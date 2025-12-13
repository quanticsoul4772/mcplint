//! Memory Cache - In-memory cache storage
//!
//! Implements ephemeral caching using an in-memory HashMap.
//! Suitable for CI environments or short-lived processes.

use anyhow::Result;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use super::backend::{Cache, CacheConfig};
use super::entry::CacheEntry;
use super::key::{CacheCategory, CacheKey};
use super::stats::{AtomicCacheStats, CacheStats, CategoryStats};

/// In-memory cache implementation
pub struct MemoryCache {
    /// Cache entries stored in a thread-safe HashMap
    entries: Arc<RwLock<HashMap<CacheKey, CacheEntry>>>,
    /// Cache configuration
    config: CacheConfig,
    /// Atomic statistics
    stats: AtomicCacheStats,
}

impl MemoryCache {
    /// Create a new memory cache
    pub fn new(config: CacheConfig) -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
            config,
            stats: AtomicCacheStats::new(),
        }
    }

    /// Create with pre-populated entries (useful for testing)
    pub fn with_entries(config: CacheConfig, entries: HashMap<CacheKey, CacheEntry>) -> Self {
        let stats = AtomicCacheStats::new();

        // Initialize stats from entries
        for entry in entries.values() {
            stats.record_add(entry.size_bytes);
        }

        Self {
            entries: Arc::new(RwLock::new(entries)),
            config,
            stats,
        }
    }

    /// Check if we're at capacity and need to evict
    async fn maybe_evict(&self) -> Result<()> {
        if let Some(max_size) = self.config.max_size_bytes {
            let entries = self.entries.read().await;
            let current_size: u64 = entries.values().map(|e| e.size_bytes).sum();

            if current_size > max_size {
                drop(entries);
                self.evict_lru().await?;
            }
        }
        Ok(())
    }

    /// Evict least recently used entries until under capacity
    async fn evict_lru(&self) -> Result<u64> {
        let max_size = match self.config.max_size_bytes {
            Some(size) => size,
            None => return Ok(0),
        };

        let mut entries = self.entries.write().await;
        let mut evicted = 0u64;

        // Sort by last_accessed and remove oldest until under capacity
        while !entries.is_empty() {
            let current_size: u64 = entries.values().map(|e| e.size_bytes).sum();
            if current_size <= max_size {
                break;
            }

            // Find LRU entry
            let lru_key = entries
                .iter()
                .min_by_key(|(_, e)| e.last_accessed)
                .map(|(k, _)| k.clone());

            if let Some(key) = lru_key {
                if let Some(entry) = entries.remove(&key) {
                    self.stats.record_remove(entry.size_bytes);
                    evicted += 1;
                }
            } else {
                break;
            }
        }

        Ok(evicted)
    }

    /// Remove expired entries
    async fn remove_expired(&self) -> u64 {
        let mut entries = self.entries.write().await;
        let expired_keys: Vec<CacheKey> = entries
            .iter()
            .filter(|(_, e)| e.is_expired())
            .map(|(k, _)| k.clone())
            .collect();

        let mut removed = 0u64;
        for key in expired_keys {
            if let Some(entry) = entries.remove(&key) {
                self.stats.record_remove(entry.size_bytes);
                removed += 1;
            }
        }

        removed
    }
}

#[async_trait]
impl Cache for MemoryCache {
    async fn get(&self, key: &CacheKey) -> Result<Option<CacheEntry>> {
        let mut entries = self.entries.write().await;

        if let Some(entry) = entries.get_mut(key) {
            // Check expiration
            if entry.is_expired() {
                let size = entry.size_bytes;
                entries.remove(key);
                self.stats.record_remove(size);
                self.stats.record_miss();
                return Ok(None);
            }

            entry.touch();
            self.stats.record_hit();
            Ok(Some(entry.clone()))
        } else {
            self.stats.record_miss();
            Ok(None)
        }
    }

    async fn set(&self, key: &CacheKey, entry: CacheEntry) -> Result<()> {
        // Check capacity first
        self.maybe_evict().await?;

        let size = entry.size_bytes;
        let mut entries = self.entries.write().await;

        // Remove old entry if exists
        if let Some(old) = entries.remove(key) {
            self.stats.record_remove(old.size_bytes);
        }

        entries.insert(key.clone(), entry);
        self.stats.record_add(size);

        Ok(())
    }

    async fn delete(&self, key: &CacheKey) -> Result<()> {
        let mut entries = self.entries.write().await;

        if let Some(entry) = entries.remove(key) {
            self.stats.record_remove(entry.size_bytes);
        }

        Ok(())
    }

    async fn exists(&self, key: &CacheKey) -> Result<bool> {
        let entries = self.entries.read().await;

        if let Some(entry) = entries.get(key) {
            Ok(!entry.is_expired())
        } else {
            Ok(false)
        }
    }

    async fn clear(&self, category: Option<CacheCategory>) -> Result<u64> {
        let mut entries = self.entries.write().await;
        let mut cleared = 0u64;

        match category {
            Some(cat) => {
                let keys_to_remove: Vec<CacheKey> = entries
                    .keys()
                    .filter(|k| k.category == cat)
                    .cloned()
                    .collect();

                for key in keys_to_remove {
                    if let Some(entry) = entries.remove(&key) {
                        self.stats.record_remove(entry.size_bytes);
                        cleared += 1;
                    }
                }
            }
            None => {
                cleared = entries.len() as u64;
                entries.clear();
                self.stats.reset();
            }
        }

        Ok(cleared)
    }

    async fn stats(&self) -> Result<CacheStats> {
        let entries = self.entries.read().await;
        let mut stats = self.stats.to_stats();

        // Build per-category stats
        let mut by_category: HashMap<String, CategoryStats> = HashMap::new();

        for (key, entry) in entries.iter() {
            let cat_name = key.category.to_string();
            let cat_stats = by_category.entry(cat_name).or_default();

            cat_stats.entries += 1;
            cat_stats.size_bytes += entry.size_bytes;
            if entry.is_expired() {
                cat_stats.expired += 1;
            }
        }

        stats.by_category = by_category;

        // Find oldest and newest
        if !entries.is_empty() {
            stats.oldest_entry = entries.values().map(|e| e.created_at).min();
            stats.newest_entry = entries.values().map(|e| e.created_at).max();
        }

        // Recalculate totals
        stats.total_entries = entries.len() as u64;
        stats.total_size_bytes = entries.values().map(|e| e.size_bytes).sum();
        stats.expired_entries = entries.values().filter(|e| e.is_expired()).count() as u64;

        Ok(stats)
    }

    async fn prune_expired(&self) -> Result<u64> {
        Ok(self.remove_expired().await)
    }

    async fn keys(&self, category: Option<CacheCategory>) -> Result<Vec<CacheKey>> {
        let entries = self.entries.read().await;

        let keys: Vec<CacheKey> = match category {
            Some(cat) => entries
                .keys()
                .filter(|k| k.category == cat)
                .cloned()
                .collect(),
            None => entries.keys().cloned().collect(),
        };

        Ok(keys)
    }
}

impl Default for MemoryCache {
    fn default() -> Self {
        Self::new(CacheConfig::memory())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn memory_cache_basic_operations() {
        let cache = MemoryCache::new(CacheConfig::memory());

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
    async fn memory_cache_expiration() {
        let cache = MemoryCache::new(CacheConfig::memory());

        let key = CacheKey::schema("test-server");
        // 0 TTL = immediately expired
        let entry = CacheEntry::new(b"test".to_vec(), Duration::from_secs(0));

        cache.set(&key, entry).await.unwrap();

        // Wait a bit for expiration
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Should be expired
        let retrieved = cache.get(&key).await.unwrap();
        assert!(retrieved.is_none());
    }

    #[tokio::test]
    async fn memory_cache_lru_eviction() {
        // Capacity for ~3 entries (each entry.size_bytes = 100)
        let config = CacheConfig::memory().with_max_size(250);
        let cache = MemoryCache::new(config);

        // Add entries with different access times
        for i in 0..5 {
            let key = CacheKey::schema(&format!("server-{}", i));
            let entry = CacheEntry::new(vec![0u8; 100], Duration::from_secs(3600));
            cache.set(&key, entry).await.unwrap();

            // Small delay to ensure different last_accessed times
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // Should have evicted older entries - only ~2-3 should remain
        let stats = cache.stats().await.unwrap();
        // Verify eviction occurred (not all 5 entries present)
        assert!(
            stats.total_entries < 5,
            "Expected fewer than 5 entries after eviction, got {}",
            stats.total_entries
        );
    }

    #[tokio::test]
    async fn memory_cache_clear_category() {
        let cache = MemoryCache::new(CacheConfig::memory());

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

    #[tokio::test]
    async fn memory_cache_stats() {
        let cache = MemoryCache::new(CacheConfig::memory());

        // Add some entries
        for i in 0..5 {
            let key = CacheKey::schema(&format!("server-{}", i));
            let entry = CacheEntry::new(vec![0u8; 100], Duration::from_secs(3600));
            cache.set(&key, entry).await.unwrap();
        }

        // Record some hits/misses
        cache.get(&CacheKey::schema("server-0")).await.unwrap(); // hit
        cache.get(&CacheKey::schema("nonexistent")).await.unwrap(); // miss

        let stats = cache.stats().await.unwrap();
        assert_eq!(stats.total_entries, 5);
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 1);
    }

    #[tokio::test]
    async fn memory_cache_miss_on_nonexistent() {
        let cache = MemoryCache::new(CacheConfig::memory());
        let key = CacheKey::schema("nonexistent");

        // Get non-existent key should return None
        let result = cache.get(&key).await.unwrap();
        assert!(result.is_none());

        // Stats should show a miss
        let stats = cache.stats().await.unwrap();
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.hits, 0);
    }

    #[tokio::test]
    async fn memory_cache_replace_existing() {
        let cache = MemoryCache::new(CacheConfig::memory());
        let key = CacheKey::schema("test-server");

        // Set initial value
        let entry1 = CacheEntry::new(b"data1".to_vec(), Duration::from_secs(3600));
        cache.set(&key, entry1).await.unwrap();

        // Replace with new value
        let entry2 = CacheEntry::new(b"data2".to_vec(), Duration::from_secs(3600));
        cache.set(&key, entry2).await.unwrap();

        // Should get the new value
        let retrieved = cache.get(&key).await.unwrap().unwrap();
        assert_eq!(retrieved.data, b"data2".to_vec());
    }

    #[tokio::test]
    async fn memory_cache_clear_all() {
        let cache = MemoryCache::new(CacheConfig::memory());

        // Add entries to different categories
        let key1 = CacheKey::schema("server1");
        let key2 = CacheKey::validation("server2", "1.0");
        let key3 = CacheKey::scan_result("server3", "ruleset1");

        cache
            .set(&key1, CacheEntry::new(vec![0u8; 100], Duration::from_secs(3600)))
            .await
            .unwrap();
        cache
            .set(&key2, CacheEntry::new(vec![0u8; 100], Duration::from_secs(3600)))
            .await
            .unwrap();
        cache
            .set(&key3, CacheEntry::new(vec![0u8; 100], Duration::from_secs(3600)))
            .await
            .unwrap();

        // Clear all
        let cleared = cache.clear(None).await.unwrap();
        assert_eq!(cleared, 3);

        // All entries should be gone
        assert!(!cache.exists(&key1).await.unwrap());
        assert!(!cache.exists(&key2).await.unwrap());
        assert!(!cache.exists(&key3).await.unwrap());

        // Stats should be reset
        let stats = cache.stats().await.unwrap();
        assert_eq!(stats.total_entries, 0);
    }

    #[tokio::test]
    async fn memory_cache_prune_expired() {
        let cache = MemoryCache::new(CacheConfig::memory());

        // Add mix of expired and valid entries
        let key1 = CacheKey::schema("expired1");
        let key2 = CacheKey::schema("expired2");
        let key3 = CacheKey::schema("valid");

        cache
            .set(&key1, CacheEntry::new(vec![0u8; 100], Duration::from_secs(0)))
            .await
            .unwrap();
        cache
            .set(&key2, CacheEntry::new(vec![0u8; 100], Duration::from_secs(0)))
            .await
            .unwrap();
        cache
            .set(
                &key3,
                CacheEntry::new(vec![0u8; 100], Duration::from_secs(3600)),
            )
            .await
            .unwrap();

        // Wait for expiration
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Prune expired
        let pruned = cache.prune_expired().await.unwrap();
        assert_eq!(pruned, 2);

        // Only valid entry should remain
        assert!(cache.exists(&key3).await.unwrap());
        assert!(!cache.exists(&key1).await.unwrap());
        assert!(!cache.exists(&key2).await.unwrap());
    }

    #[tokio::test]
    async fn memory_cache_keys_by_category() {
        let cache = MemoryCache::new(CacheConfig::memory());

        // Add entries to different categories
        let key1 = CacheKey::schema("server1");
        let key2 = CacheKey::schema("server2");
        let key3 = CacheKey::validation("server3", "1.0");

        cache
            .set(&key1, CacheEntry::new(vec![], Duration::from_secs(3600)))
            .await
            .unwrap();
        cache
            .set(&key2, CacheEntry::new(vec![], Duration::from_secs(3600)))
            .await
            .unwrap();
        cache
            .set(&key3, CacheEntry::new(vec![], Duration::from_secs(3600)))
            .await
            .unwrap();

        // Get only schema keys
        let schema_keys = cache.keys(Some(CacheCategory::Schema)).await.unwrap();
        assert_eq!(schema_keys.len(), 2);

        // Get all keys
        let all_keys = cache.keys(None).await.unwrap();
        assert_eq!(all_keys.len(), 3);
    }

    #[tokio::test]
    async fn memory_cache_exists_with_expired() {
        let cache = MemoryCache::new(CacheConfig::memory());
        let key = CacheKey::schema("test");

        // Add expired entry
        cache
            .set(&key, CacheEntry::new(vec![], Duration::from_secs(0)))
            .await
            .unwrap();

        // Wait for expiration
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Should return false for expired entry
        assert!(!cache.exists(&key).await.unwrap());
    }

    #[tokio::test]
    async fn memory_cache_with_entries_constructor() {
        let mut entries = HashMap::new();
        let key = CacheKey::schema("preloaded");
        let entry = CacheEntry::new(b"data".to_vec(), Duration::from_secs(3600));
        entries.insert(key.clone(), entry);

        let cache = MemoryCache::with_entries(CacheConfig::memory(), entries);

        // Should be able to retrieve pre-populated entry
        let retrieved = cache.get(&key).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().data, b"data".to_vec());

        // Stats should reflect pre-populated entry
        let stats = cache.stats().await.unwrap();
        assert_eq!(stats.total_entries, 1);
    }

    #[tokio::test]
    async fn memory_cache_default_constructor() {
        let cache = MemoryCache::default();

        // Should be able to use default cache
        let key = CacheKey::schema("test");
        let entry = CacheEntry::new(b"data".to_vec(), Duration::from_secs(3600));

        cache.set(&key, entry).await.unwrap();

        let retrieved = cache.get(&key).await.unwrap();
        assert!(retrieved.is_some());
    }

    #[tokio::test]
    async fn memory_cache_empty_cache_stats() {
        let cache = MemoryCache::new(CacheConfig::memory());

        let stats = cache.stats().await.unwrap();
        assert_eq!(stats.total_entries, 0);
        assert_eq!(stats.total_size_bytes, 0);
        assert_eq!(stats.expired_entries, 0);
        assert!(stats.oldest_entry.is_none());
        assert!(stats.newest_entry.is_none());
    }

    #[tokio::test]
    async fn memory_cache_stats_with_expired() {
        let cache = MemoryCache::new(CacheConfig::memory());

        // Add mix of expired and valid
        let key1 = CacheKey::schema("expired");
        let key2 = CacheKey::schema("valid");

        cache
            .set(&key1, CacheEntry::new(vec![0u8; 100], Duration::from_secs(0)))
            .await
            .unwrap();
        cache
            .set(
                &key2,
                CacheEntry::new(vec![0u8; 100], Duration::from_secs(3600)),
            )
            .await
            .unwrap();

        // Wait for expiration
        tokio::time::sleep(Duration::from_millis(10)).await;

        let stats = cache.stats().await.unwrap();
        assert_eq!(stats.total_entries, 2);
        assert_eq!(stats.expired_entries, 1);
    }

    #[tokio::test]
    async fn memory_cache_stats_by_category() {
        let cache = MemoryCache::new(CacheConfig::memory());

        // Add entries to different categories
        cache
            .set(
                &CacheKey::schema("server1"),
                CacheEntry::new(vec![0u8; 100], Duration::from_secs(3600)),
            )
            .await
            .unwrap();
        cache
            .set(
                &CacheKey::schema("server2"),
                CacheEntry::new(vec![0u8; 150], Duration::from_secs(3600)),
            )
            .await
            .unwrap();
        cache
            .set(
                &CacheKey::validation("server3", "1.0"),
                CacheEntry::new(vec![0u8; 200], Duration::from_secs(3600)),
            )
            .await
            .unwrap();

        let stats = cache.stats().await.unwrap();
        assert!(stats.by_category.contains_key("schemas"));
        assert!(stats.by_category.contains_key("validation"));

        let schema_stats = &stats.by_category["schemas"];
        assert_eq!(schema_stats.entries, 2);
        assert_eq!(schema_stats.size_bytes, 250);
    }

    #[tokio::test]
    async fn memory_cache_delete_nonexistent() {
        let cache = MemoryCache::new(CacheConfig::memory());
        let key = CacheKey::schema("nonexistent");

        // Deleting non-existent key should not error
        cache.delete(&key).await.unwrap();

        // Stats should remain unchanged
        let stats = cache.stats().await.unwrap();
        assert_eq!(stats.total_entries, 0);
    }

    #[tokio::test]
    async fn memory_cache_no_eviction_when_under_capacity() {
        let config = CacheConfig::memory().with_max_size(1000);
        let cache = MemoryCache::new(config);

        // Add entry well under capacity
        let key = CacheKey::schema("server1");
        cache
            .set(&key, CacheEntry::new(vec![0u8; 100], Duration::from_secs(3600)))
            .await
            .unwrap();

        // Should still exist
        assert!(cache.exists(&key).await.unwrap());

        let stats = cache.stats().await.unwrap();
        assert_eq!(stats.total_entries, 1);
    }

    #[tokio::test]
    async fn memory_cache_lru_eviction_multiple_rounds() {
        let config = CacheConfig::memory().with_max_size(150);
        let cache = MemoryCache::new(config);

        // Add first entry
        let key1 = CacheKey::schema("server1");
        cache
            .set(&key1, CacheEntry::new(vec![0u8; 100], Duration::from_secs(3600)))
            .await
            .unwrap();

        tokio::time::sleep(Duration::from_millis(10)).await;

        // Add second entry (should fit since 200 < 250 in previous test)
        let key2 = CacheKey::schema("server2");
        cache
            .set(&key2, CacheEntry::new(vec![0u8; 100], Duration::from_secs(3600)))
            .await
            .unwrap();

        tokio::time::sleep(Duration::from_millis(10)).await;

        // Add third entry (triggers eviction of oldest)
        let key3 = CacheKey::schema("server3");
        cache
            .set(&key3, CacheEntry::new(vec![0u8; 100], Duration::from_secs(3600)))
            .await
            .unwrap();

        // First entry should be evicted (LRU)
        assert!(!cache.exists(&key1).await.unwrap());
        // Second and third should remain
        assert!(cache.exists(&key2).await.unwrap());
        assert!(cache.exists(&key3).await.unwrap());
    }

    #[tokio::test]
    async fn memory_cache_touch_updates_last_accessed() {
        let cache = MemoryCache::new(CacheConfig::memory());
        let key = CacheKey::schema("test");

        cache
            .set(&key, CacheEntry::new(vec![0u8; 100], Duration::from_secs(3600)))
            .await
            .unwrap();

        // Get should update last_accessed via touch()
        let entry1 = cache.get(&key).await.unwrap().unwrap();
        let accessed1 = entry1.last_accessed;

        tokio::time::sleep(Duration::from_millis(10)).await;

        let entry2 = cache.get(&key).await.unwrap().unwrap();
        let accessed2 = entry2.last_accessed;

        // Last accessed should have been updated
        assert!(accessed2 > accessed1);
    }

    #[tokio::test]
    async fn memory_cache_expired_on_get_removes_entry() {
        let cache = MemoryCache::new(CacheConfig::memory());
        let key = CacheKey::schema("test");

        // Add expired entry
        cache
            .set(&key, CacheEntry::new(vec![0u8; 100], Duration::from_secs(0)))
            .await
            .unwrap();

        tokio::time::sleep(Duration::from_millis(10)).await;

        // Get should remove expired entry
        let result = cache.get(&key).await.unwrap();
        assert!(result.is_none());

        // Entry should no longer exist
        let keys = cache.keys(None).await.unwrap();
        assert_eq!(keys.len(), 0);
    }

    #[tokio::test]
    async fn memory_cache_prune_expired_empty_cache() {
        let cache = MemoryCache::new(CacheConfig::memory());

        // Pruning empty cache should return 0
        let pruned = cache.prune_expired().await.unwrap();
        assert_eq!(pruned, 0);
    }

    #[tokio::test]
    async fn memory_cache_clear_category_empty() {
        let cache = MemoryCache::new(CacheConfig::memory());

        // Clearing non-existent category should return 0
        let cleared = cache.clear(Some(CacheCategory::Schema)).await.unwrap();
        assert_eq!(cleared, 0);
    }
}
