//! Filesystem Cache - File-based cache storage
//!
//! Implements persistent caching using the local filesystem
//! with directory structure organized by category.

use anyhow::{Context, Result};
use async_trait::async_trait;
use chrono::Utc;
use std::collections::HashMap;
use std::path::PathBuf;
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::backend::{Cache, CacheConfig};
use super::entry::CacheEntry;
use super::key::{CacheCategory, CacheKey};
use super::stats::{AtomicCacheStats, CacheStats, CategoryStats};

/// Filesystem-based cache implementation
pub struct FilesystemCache {
    /// Base directory for cache storage
    base_path: PathBuf,
    /// Cache configuration
    config: CacheConfig,
    /// Atomic statistics
    stats: AtomicCacheStats,
}

impl FilesystemCache {
    /// Create a new filesystem cache with default path
    pub async fn new(config: CacheConfig) -> Result<Self> {
        let base_path = match &config.backend {
            super::backend::CacheBackend::Filesystem { path } => path.clone(),
            _ => super::backend::default_cache_path(),
        };

        Self::with_path(base_path, config).await
    }

    /// Create a filesystem cache with a custom path
    pub async fn with_path(base_path: PathBuf, config: CacheConfig) -> Result<Self> {
        // Create base directory structure
        fs::create_dir_all(&base_path)
            .await
            .context("Failed to create cache directory")?;

        // Create category subdirectories
        for category in CacheCategory::all() {
            let category_path = base_path.join(category.to_string());
            fs::create_dir_all(&category_path).await?;
        }

        Ok(Self {
            base_path,
            config,
            stats: AtomicCacheStats::new(),
        })
    }

    /// Get the file path for a cache key
    fn path_for_key(&self, key: &CacheKey) -> PathBuf {
        let (dir, file) = key.to_path_components();
        self.base_path.join(dir).join(file)
    }

    /// Read entry from disk
    async fn read_entry(&self, path: &PathBuf) -> Result<Option<CacheEntry>> {
        if !path.exists() {
            return Ok(None);
        }

        let mut file = fs::File::open(path).await?;
        let mut contents = Vec::new();
        file.read_to_end(&mut contents).await?;

        let entry: CacheEntry = serde_json::from_slice(&contents)?;

        // Check expiration
        if entry.is_expired() {
            // Clean up expired entry
            let _ = fs::remove_file(path).await;
            return Ok(None);
        }

        Ok(Some(entry))
    }

    /// Write entry to disk
    async fn write_entry(&self, path: &PathBuf, entry: &CacheEntry) -> Result<()> {
        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).await?;
        }

        let contents = serde_json::to_vec_pretty(entry)?;

        let mut file = fs::File::create(path).await?;
        file.write_all(&contents).await?;
        file.sync_all().await?;

        Ok(())
    }

    /// List all files in a category directory
    async fn list_category_files(&self, category: CacheCategory) -> Result<Vec<PathBuf>> {
        let category_path = self.base_path.join(category.to_string());

        if !category_path.exists() {
            return Ok(Vec::new());
        }

        let mut files = Vec::new();
        let mut entries = fs::read_dir(&category_path).await?;

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path.is_file() && path.extension().map(|e| e == "json").unwrap_or(false) {
                files.push(path);
            }
        }

        Ok(files)
    }

    /// Get cache statistics for a category
    async fn category_stats(&self, category: CacheCategory) -> Result<CategoryStats> {
        let files = self.list_category_files(category).await?;
        let mut entries = 0u64;
        let mut size_bytes = 0u64;
        let mut expired = 0u64;

        for path in files {
            if let Ok(metadata) = fs::metadata(&path).await {
                size_bytes += metadata.len();
                entries += 1;

                // Check if expired
                if let Ok(Some(entry)) = self.read_entry(&path).await {
                    if entry.is_expired() {
                        expired += 1;
                    }
                }
            }
        }

        Ok(CategoryStats::new(entries, size_bytes, expired))
    }
}

#[async_trait]
impl Cache for FilesystemCache {
    async fn get(&self, key: &CacheKey) -> Result<Option<CacheEntry>> {
        let path = self.path_for_key(key);

        match self.read_entry(&path).await? {
            Some(mut entry) => {
                self.stats.record_hit();
                entry.touch();
                // Update access time on disk (best effort)
                let _ = self.write_entry(&path, &entry).await;
                Ok(Some(entry))
            }
            None => {
                self.stats.record_miss();
                Ok(None)
            }
        }
    }

    async fn set(&self, key: &CacheKey, entry: CacheEntry) -> Result<()> {
        let path = self.path_for_key(key);
        let size = entry.size_bytes;

        self.write_entry(&path, &entry).await?;
        self.stats.record_add(size);

        Ok(())
    }

    async fn delete(&self, key: &CacheKey) -> Result<()> {
        let path = self.path_for_key(key);

        if path.exists() {
            // Get size before deletion for stats
            if let Ok(metadata) = fs::metadata(&path).await {
                self.stats.record_remove(metadata.len());
            }
            fs::remove_file(&path).await?;
        }

        Ok(())
    }

    async fn exists(&self, key: &CacheKey) -> Result<bool> {
        let path = self.path_for_key(key);

        if !path.exists() {
            return Ok(false);
        }

        // Check if expired
        if let Some(entry) = self.read_entry(&path).await? {
            Ok(!entry.is_expired())
        } else {
            Ok(false)
        }
    }

    async fn clear(&self, category: Option<CacheCategory>) -> Result<u64> {
        let categories = match category {
            Some(cat) => vec![cat],
            None => CacheCategory::all().to_vec(),
        };

        let mut cleared = 0u64;

        for cat in categories {
            let files = self.list_category_files(cat).await?;
            for path in files {
                if fs::remove_file(&path).await.is_ok() {
                    cleared += 1;
                }
            }
        }

        Ok(cleared)
    }

    async fn stats(&self) -> Result<CacheStats> {
        let mut stats = self.stats.to_stats();

        // Get per-category stats
        for category in CacheCategory::all() {
            let cat_stats = self.category_stats(*category).await?;
            stats.by_category.insert(category.to_string(), cat_stats);
        }

        // Recalculate totals from categories
        stats.total_entries = 0;
        stats.total_size_bytes = 0;
        stats.expired_entries = 0;

        for (_, cat_stats) in &stats.by_category {
            stats.total_entries += cat_stats.entries;
            stats.total_size_bytes += cat_stats.size_bytes;
            stats.expired_entries += cat_stats.expired;
        }

        // Find oldest and newest entries
        let mut oldest: Option<chrono::DateTime<Utc>> = None;
        let mut newest: Option<chrono::DateTime<Utc>> = None;

        for category in CacheCategory::all() {
            let files = self.list_category_files(*category).await?;
            for path in files {
                if let Ok(Some(entry)) = self.read_entry(&path).await {
                    match oldest {
                        Some(o) if entry.created_at < o => oldest = Some(entry.created_at),
                        None => oldest = Some(entry.created_at),
                        _ => {}
                    }
                    match newest {
                        Some(n) if entry.created_at > n => newest = Some(entry.created_at),
                        None => newest = Some(entry.created_at),
                        _ => {}
                    }
                }
            }
        }

        stats.oldest_entry = oldest;
        stats.newest_entry = newest;
        stats.calculate_hit_ratio();

        Ok(stats)
    }

    async fn prune_expired(&self) -> Result<u64> {
        let mut pruned = 0u64;

        for category in CacheCategory::all() {
            let files = self.list_category_files(*category).await?;
            for path in files {
                if let Ok(Some(entry)) = self.read_entry(&path).await {
                    if entry.is_expired() {
                        if fs::remove_file(&path).await.is_ok() {
                            pruned += 1;
                        }
                    }
                }
            }
        }

        Ok(pruned)
    }

    async fn keys(&self, category: Option<CacheCategory>) -> Result<Vec<CacheKey>> {
        let categories = match category {
            Some(cat) => vec![cat],
            None => CacheCategory::all().to_vec(),
        };

        let mut keys = Vec::new();

        for cat in categories {
            let files = self.list_category_files(cat).await?;
            for path in files {
                if let Some(stem) = path.file_stem() {
                    let identifier = stem.to_string_lossy().to_string();
                    keys.push(CacheKey::new(cat, identifier));
                }
            }
        }

        Ok(keys)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tempfile::tempdir;

    #[tokio::test]
    async fn filesystem_cache_basic_operations() {
        let dir = tempdir().unwrap();
        let config = CacheConfig::filesystem(dir.path().to_path_buf());
        let cache = FilesystemCache::with_path(dir.path().to_path_buf(), config)
            .await
            .unwrap();

        let key = CacheKey::schema("test-server");
        let entry = CacheEntry::new(b"test data".to_vec(), Duration::from_secs(3600));

        // Set
        cache.set(&key, entry.clone()).await.unwrap();

        // Exists
        assert!(cache.exists(&key).await.unwrap());

        // Get
        let retrieved = cache.get(&key).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().data, b"test data".to_vec());

        // Delete
        cache.delete(&key).await.unwrap();
        assert!(!cache.exists(&key).await.unwrap());
    }

    #[tokio::test]
    async fn filesystem_cache_stats() {
        let dir = tempdir().unwrap();
        let config = CacheConfig::filesystem(dir.path().to_path_buf());
        let cache = FilesystemCache::with_path(dir.path().to_path_buf(), config)
            .await
            .unwrap();

        // Add some entries
        for i in 0..5 {
            let key = CacheKey::schema(&format!("server-{}", i));
            let entry = CacheEntry::new(vec![0u8; 100], Duration::from_secs(3600));
            cache.set(&key, entry).await.unwrap();
        }

        let stats = cache.stats().await.unwrap();
        assert_eq!(stats.total_entries, 5);
    }

    #[tokio::test]
    async fn filesystem_cache_clear_category() {
        let dir = tempdir().unwrap();
        let config = CacheConfig::filesystem(dir.path().to_path_buf());
        let cache = FilesystemCache::with_path(dir.path().to_path_buf(), config)
            .await
            .unwrap();

        // Add entries to different categories
        let key1 = CacheKey::schema("server1");
        let key2 = CacheKey::validation("server2", "1.0");

        cache
            .set(&key1, CacheEntry::new(vec![], Duration::from_secs(3600)))
            .await
            .unwrap();
        cache
            .set(&key2, CacheEntry::new(vec![], Duration::from_secs(3600)))
            .await
            .unwrap();

        // Clear only schemas
        let cleared = cache.clear(Some(CacheCategory::Schema)).await.unwrap();
        assert_eq!(cleared, 1);

        // Validation entry should still exist
        assert!(cache.exists(&key2).await.unwrap());
    }
}
