//! Cache Module - Multi-backend caching system
//!
//! Provides caching infrastructure for MCPLint with support for:
//! - Filesystem storage (default, persistent)
//! - In-memory storage (ephemeral, fast)
//! - Redis storage (distributed, scalable) [optional feature]
//!
//! # Example
//!
//! ```rust,ignore
//! use mcplint::cache::{CacheConfig, CacheManager};
//!
//! // Create with default filesystem backend
//! let config = CacheConfig::default();
//! let cache = CacheManager::new(config).await?;
//!
//! // Cache a schema
//! cache.set_schema("server-hash", &tools).await?;
//!
//! // Retrieve cached schema
//! if let Some(tools) = cache.get_schema("server-hash").await? {
//!     println!("Cache hit!");
//! }
//! ```

pub mod backend;
pub mod entry;
pub mod filesystem;
pub mod key;
pub mod memory;
#[cfg(feature = "redis")]
pub mod redis;
pub mod rug_pull;
pub mod stats;

// Re-exports for convenience
pub use backend::{Cache, CacheBackend, CacheConfig};
pub use entry::CacheEntry;
pub use filesystem::FilesystemCache;
pub use key::{CacheCategory, CacheKey};
pub use memory::MemoryCache;
#[cfg(feature = "redis")]
pub use redis::RedisCache;
pub use rug_pull::{detect_rug_pull, RugPullDetection, RugPullSeverity, ToolHashRecord};
pub use stats::{CacheStats, CategoryStats};

use anyhow::Result;
use serde::{de::DeserializeOwned, Serialize};
use std::sync::Arc;
use std::time::Duration;

/// Unified cache manager that delegates to the configured backend
pub struct CacheManager {
    /// The underlying cache implementation
    backend: Arc<dyn Cache>,
    /// Cache configuration
    config: CacheConfig,
}

impl CacheManager {
    /// Create a new cache manager from configuration
    pub async fn new(config: CacheConfig) -> Result<Self> {
        let backend: Arc<dyn Cache> = match &config.backend {
            CacheBackend::Filesystem { path } => {
                Arc::new(FilesystemCache::with_path(path.clone(), config.clone()).await?)
            }
            CacheBackend::Memory => Arc::new(MemoryCache::new(config.clone())),
            #[cfg(feature = "redis")]
            CacheBackend::Redis { url, .. } => {
                Arc::new(RedisCache::new(url, config.clone()).await?)
            }
        };

        Ok(Self { backend, config })
    }

    /// Create a memory-only cache manager
    pub fn memory() -> Self {
        Self {
            backend: Arc::new(MemoryCache::new(CacheConfig::memory())),
            config: CacheConfig::memory(),
        }
    }

    /// Check if caching is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Get the current configuration
    pub fn config(&self) -> &CacheConfig {
        &self.config
    }

    // =========================================================================
    // Generic cache operations
    // =========================================================================

    /// Get a value from cache
    pub async fn get<T: DeserializeOwned>(&self, key: &CacheKey) -> Result<Option<T>> {
        if !self.config.enabled {
            return Ok(None);
        }

        if let Some(entry) = self.backend.get(key).await? {
            let value = entry.to_value()?;
            Ok(Some(value))
        } else {
            Ok(None)
        }
    }

    /// Set a value in cache with category-appropriate TTL
    pub async fn set<T: Serialize>(&self, key: &CacheKey, value: &T) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        let ttl = self.config.ttl_for_category(key.category);
        let entry = CacheEntry::from_value(value, ttl)?;
        self.backend.set(key, entry).await
    }

    /// Set a value with custom TTL
    pub async fn set_with_ttl<T: Serialize>(
        &self,
        key: &CacheKey,
        value: &T,
        ttl: Duration,
    ) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        let entry = CacheEntry::from_value(value, ttl)?;
        self.backend.set(key, entry).await
    }

    /// Delete a value from cache
    pub async fn delete(&self, key: &CacheKey) -> Result<()> {
        self.backend.delete(key).await
    }

    /// Check if a key exists
    pub async fn exists(&self, key: &CacheKey) -> Result<bool> {
        if !self.config.enabled {
            return Ok(false);
        }
        self.backend.exists(key).await
    }

    // =========================================================================
    // Schema caching
    // =========================================================================

    /// Get cached schema (tools)
    pub async fn get_schema<T: DeserializeOwned>(&self, server_hash: &str) -> Result<Option<T>> {
        let key = CacheKey::schema(server_hash);
        self.get(&key).await
    }

    /// Cache schema (tools)
    pub async fn set_schema<T: Serialize>(&self, server_hash: &str, schema: &T) -> Result<()> {
        let key = CacheKey::schema(server_hash);
        self.set(&key, schema).await
    }

    // =========================================================================
    // Scan result caching
    // =========================================================================

    /// Get cached scan result
    pub async fn get_scan_result<T: DeserializeOwned>(
        &self,
        server_hash: &str,
        ruleset_hash: &str,
    ) -> Result<Option<T>> {
        let key = CacheKey::scan_result(server_hash, ruleset_hash);
        self.get(&key).await
    }

    /// Cache scan result
    pub async fn set_scan_result<T: Serialize>(
        &self,
        server_hash: &str,
        ruleset_hash: &str,
        result: &T,
    ) -> Result<()> {
        let key = CacheKey::scan_result(server_hash, ruleset_hash);
        self.set(&key, result).await
    }

    // =========================================================================
    // Validation caching
    // =========================================================================

    /// Get cached validation result
    pub async fn get_validation<T: DeserializeOwned>(
        &self,
        server_hash: &str,
        protocol_version: &str,
    ) -> Result<Option<T>> {
        let key = CacheKey::validation(server_hash, protocol_version);
        self.get(&key).await
    }

    /// Cache validation result
    pub async fn set_validation<T: Serialize>(
        &self,
        server_hash: &str,
        protocol_version: &str,
        result: &T,
    ) -> Result<()> {
        let key = CacheKey::validation(server_hash, protocol_version);
        self.set(&key, result).await
    }

    // =========================================================================
    // Corpus caching
    // =========================================================================

    /// Get cached corpus
    pub async fn get_corpus<T: DeserializeOwned>(&self, server_id: &str) -> Result<Option<T>> {
        let key = CacheKey::corpus(server_id);
        self.get(&key).await
    }

    /// Cache corpus
    pub async fn set_corpus<T: Serialize>(&self, server_id: &str, corpus: &T) -> Result<()> {
        let key = CacheKey::corpus(server_id);
        self.set(&key, corpus).await
    }

    // =========================================================================
    // Tool hash caching (rug-pull detection)
    // =========================================================================

    /// Get cached tool hash
    pub async fn get_tool_hash<T: DeserializeOwned>(&self, server_id: &str) -> Result<Option<T>> {
        let key = CacheKey::tool_hash(server_id);
        self.get(&key).await
    }

    /// Cache tool hash
    pub async fn set_tool_hash<T: Serialize>(&self, server_id: &str, hash: &T) -> Result<()> {
        let key = CacheKey::tool_hash(server_id);
        self.set(&key, hash).await
    }

    // =========================================================================
    // Maintenance operations
    // =========================================================================

    /// Clear cache entries
    pub async fn clear(&self, category: Option<CacheCategory>) -> Result<u64> {
        self.backend.clear(category).await
    }

    /// Prune expired entries
    pub async fn prune_expired(&self) -> Result<u64> {
        self.backend.prune_expired().await
    }

    /// Get cache statistics
    pub async fn stats(&self) -> Result<CacheStats> {
        self.backend.stats().await
    }

    /// Get all keys
    pub async fn keys(&self, category: Option<CacheCategory>) -> Result<Vec<CacheKey>> {
        self.backend.keys(category).await
    }
}

/// Hash a server command for cache key generation
pub fn hash_server(server: &str, args: &[String]) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    server.hash(&mut hasher);
    for arg in args {
        arg.hash(&mut hasher);
    }
    format!("{:016x}", hasher.finish())
}

/// Hash a ruleset for cache key generation
pub fn hash_ruleset(rules: &[String]) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    for rule in rules {
        rule.hash(&mut hasher);
    }
    format!("{:016x}", hasher.finish())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn cache_manager_memory() {
        let cache = CacheManager::memory();
        assert!(cache.is_enabled());

        let key = CacheKey::schema("test");
        let data = vec!["tool1", "tool2"];

        cache.set(&key, &data).await.unwrap();

        let retrieved: Option<Vec<String>> = cache.get(&key).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap(), data);
    }

    #[tokio::test]
    async fn cache_manager_schema_helpers() {
        let cache = CacheManager::memory();

        let tools = vec!["read_file", "write_file"];
        cache.set_schema("server1", &tools).await.unwrap();

        let retrieved: Option<Vec<String>> = cache.get_schema("server1").await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap(), tools);
    }

    #[tokio::test]
    async fn cache_manager_disabled() {
        let config = CacheConfig::disabled();
        let cache = CacheManager::new(config).await.unwrap();

        assert!(!cache.is_enabled());

        // Operations should succeed but be no-ops
        let key = CacheKey::schema("test");
        cache.set(&key, &"data").await.unwrap();

        let retrieved: Option<String> = cache.get(&key).await.unwrap();
        assert!(retrieved.is_none());
    }

    #[test]
    fn hash_server_consistency() {
        let hash1 = hash_server("server", &["arg1".to_string(), "arg2".to_string()]);
        let hash2 = hash_server("server", &["arg1".to_string(), "arg2".to_string()]);
        assert_eq!(hash1, hash2);

        let hash3 = hash_server("server", &["arg1".to_string()]);
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn hash_ruleset_consistency() {
        let hash1 = hash_ruleset(&["rule1".to_string(), "rule2".to_string()]);
        let hash2 = hash_ruleset(&["rule1".to_string(), "rule2".to_string()]);
        assert_eq!(hash1, hash2);
    }
}
