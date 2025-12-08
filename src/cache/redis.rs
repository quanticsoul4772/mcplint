//! Redis Cache - Distributed cache storage
//!
//! Implements caching using Redis for distributed environments.
//! This module is only available when the `redis` feature is enabled.

#![cfg(feature = "redis")]

use anyhow::{Context, Result};
use async_trait::async_trait;
use redis::aio::MultiplexedConnection;
use redis::{AsyncCommands, Client};
use std::time::Duration;

use super::backend::{Cache, CacheConfig};
use super::entry::CacheEntry;
use super::key::{CacheCategory, CacheKey};
use super::stats::{CacheStats, CategoryStats};

/// Redis-based distributed cache implementation
pub struct RedisCache {
    /// Redis client for connection management
    client: Client,
    /// Multiplexed connection for async operations
    connection: MultiplexedConnection,
    /// Cache configuration
    config: CacheConfig,
    /// Key prefix for namespacing
    prefix: String,
    /// Default TTL in seconds
    default_ttl: u64,
}

impl RedisCache {
    /// Create a new Redis cache
    pub async fn new(url: &str, config: CacheConfig) -> Result<Self> {
        let client = Client::open(url).context("Failed to create Redis client")?;

        let connection = client
            .get_multiplexed_async_connection()
            .await
            .context("Failed to connect to Redis")?;

        let default_ttl = match &config.backend {
            super::backend::CacheBackend::Redis { ttl_secs, .. } => *ttl_secs,
            _ => 3600,
        };

        Ok(Self {
            client,
            connection,
            config,
            prefix: "mcplint".to_string(),
            default_ttl,
        })
    }

    /// Create with a custom prefix for namespacing
    pub async fn with_prefix(url: &str, prefix: &str, config: CacheConfig) -> Result<Self> {
        let mut cache = Self::new(url, config).await?;
        cache.prefix = prefix.to_string();
        Ok(cache)
    }

    /// Get the Redis key for a cache key
    fn redis_key(&self, key: &CacheKey) -> String {
        key.to_redis_key(&self.prefix)
    }

    /// Get the pattern for listing keys in a category
    fn category_pattern(&self, category: CacheCategory) -> String {
        format!("{}:{}:*", self.prefix, category)
    }

    /// Get all keys matching a pattern
    async fn scan_keys(&self, pattern: &str) -> Result<Vec<String>> {
        let mut conn = self.connection.clone();
        let keys: Vec<String> = redis::cmd("KEYS")
            .arg(pattern)
            .query_async(&mut conn)
            .await
            .context("Failed to scan keys")?;
        Ok(keys)
    }

    /// Get TTL for a category
    fn ttl_for_category(&self, category: CacheCategory) -> Duration {
        self.config.ttl_for_category(category)
    }

    /// Increment a stats counter
    async fn incr_stat(&self, stat_name: &str) -> Result<()> {
        let key = format!("{}:stats:{}", self.prefix, stat_name);
        let mut conn = self.connection.clone();
        let _: () = conn.incr(&key, 1i64).await?;
        Ok(())
    }

    /// Get a stats counter value
    async fn get_stat(&self, stat_name: &str) -> Result<u64> {
        let key = format!("{}:stats:{}", self.prefix, stat_name);
        let mut conn = self.connection.clone();
        let value: Option<u64> = conn.get(&key).await?;
        Ok(value.unwrap_or(0))
    }
}

#[async_trait]
impl Cache for RedisCache {
    async fn get(&self, key: &CacheKey) -> Result<Option<CacheEntry>> {
        let redis_key = self.redis_key(key);
        let mut conn = self.connection.clone();

        let data: Option<Vec<u8>> = conn
            .get(&redis_key)
            .await
            .context("Failed to get from Redis")?;

        match data {
            Some(bytes) => {
                let entry: CacheEntry =
                    serde_json::from_slice(&bytes).context("Failed to deserialize cache entry")?;

                // Check expiration (Redis TTL handles this, but check anyway)
                if entry.is_expired() {
                    let _: () = conn.del(&redis_key).await?;
                    self.incr_stat("misses").await?;
                    return Ok(None);
                }

                self.incr_stat("hits").await?;

                // Update last_accessed (best effort)
                let mut updated = entry.clone();
                updated.touch();
                if let Ok(bytes) = serde_json::to_vec(&updated) {
                    // Keep same TTL
                    let ttl: i64 = conn.ttl(&redis_key).await.unwrap_or(-1);
                    if ttl > 0 {
                        let _: () = conn
                            .set_ex(&redis_key, bytes, ttl as u64)
                            .await
                            .ok()
                            .unwrap_or(());
                    }
                }

                Ok(Some(entry))
            }
            None => {
                self.incr_stat("misses").await?;
                Ok(None)
            }
        }
    }

    async fn set(&self, key: &CacheKey, entry: CacheEntry) -> Result<()> {
        let redis_key = self.redis_key(key);
        let mut conn = self.connection.clone();

        let bytes = serde_json::to_vec(&entry).context("Failed to serialize cache entry")?;

        // Use entry's TTL or default
        let ttl_secs = entry.ttl_secs.max(1);

        let _: () = conn
            .set_ex(&redis_key, bytes, ttl_secs)
            .await
            .context("Failed to set in Redis")?;

        self.incr_stat("sets").await?;

        Ok(())
    }

    async fn delete(&self, key: &CacheKey) -> Result<()> {
        let redis_key = self.redis_key(key);
        let mut conn = self.connection.clone();

        let _: () = conn
            .del(&redis_key)
            .await
            .context("Failed to delete from Redis")?;

        Ok(())
    }

    async fn exists(&self, key: &CacheKey) -> Result<bool> {
        let redis_key = self.redis_key(key);
        let mut conn = self.connection.clone();

        let exists: bool = conn
            .exists(&redis_key)
            .await
            .context("Failed to check existence in Redis")?;

        Ok(exists)
    }

    async fn clear(&self, category: Option<CacheCategory>) -> Result<u64> {
        let mut conn = self.connection.clone();
        let mut cleared = 0u64;

        let categories = match category {
            Some(cat) => vec![cat],
            None => CacheCategory::all().to_vec(),
        };

        for cat in categories {
            let pattern = self.category_pattern(cat);
            let keys = self.scan_keys(&pattern).await?;

            for key in keys {
                let deleted: u64 = conn.del(&key).await?;
                cleared += deleted;
            }
        }

        Ok(cleared)
    }

    async fn stats(&self) -> Result<CacheStats> {
        let mut conn = self.connection.clone();

        let hits = self.get_stat("hits").await?;
        let misses = self.get_stat("misses").await?;

        let mut stats = CacheStats {
            hits,
            misses,
            hit_ratio: if hits + misses > 0 {
                hits as f64 / (hits + misses) as f64
            } else {
                0.0
            },
            ..Default::default()
        };

        // Get per-category stats
        for category in CacheCategory::all() {
            let pattern = self.category_pattern(*category);
            let keys = self.scan_keys(&pattern).await?;

            let mut cat_stats = CategoryStats::default();
            cat_stats.entries = keys.len() as u64;

            // Sum up sizes (approximate - we'd need to fetch each entry)
            for key in &keys {
                if let Ok(Some(len)) = conn.strlen::<_, Option<u64>>(key).await {
                    cat_stats.size_bytes += len;
                }
            }

            stats.total_entries += cat_stats.entries;
            stats.total_size_bytes += cat_stats.size_bytes;
            stats.by_category.insert(category.to_string(), cat_stats);
        }

        Ok(stats)
    }

    async fn prune_expired(&self) -> Result<u64> {
        // Redis handles TTL expiration automatically
        // This method is mostly a no-op for Redis, but we can
        // manually check for any entries that should be expired
        let mut pruned = 0u64;
        let mut conn = self.connection.clone();

        for category in CacheCategory::all() {
            let pattern = self.category_pattern(*category);
            let keys = self.scan_keys(&pattern).await?;

            for key in keys {
                // Check if entry is expired based on our logic
                if let Ok(Some(bytes)) = conn.get::<_, Option<Vec<u8>>>(&key).await {
                    if let Ok(entry) = serde_json::from_slice::<CacheEntry>(&bytes) {
                        if entry.is_expired() {
                            let _: () = conn.del(&key).await?;
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

        let mut cache_keys = Vec::new();

        for cat in categories {
            let pattern = self.category_pattern(cat);
            let redis_keys = self.scan_keys(&pattern).await?;

            for redis_key in redis_keys {
                // Parse the identifier from the Redis key
                // Format: prefix:category:identifier
                let parts: Vec<&str> = redis_key.split(':').collect();
                if parts.len() >= 3 {
                    let identifier = parts[2..].join(":");
                    cache_keys.push(CacheKey::new(cat, identifier));
                }
            }
        }

        Ok(cache_keys)
    }
}

/// Batch operations for Redis cache
impl RedisCache {
    /// Get multiple entries at once
    pub async fn mget(&self, keys: &[CacheKey]) -> Result<Vec<Option<CacheEntry>>> {
        if keys.is_empty() {
            return Ok(Vec::new());
        }

        let redis_keys: Vec<String> = keys.iter().map(|k| self.redis_key(k)).collect();
        let mut conn = self.connection.clone();

        let results: Vec<Option<Vec<u8>>> = conn.mget(&redis_keys).await?;

        let entries: Vec<Option<CacheEntry>> = results
            .into_iter()
            .map(|opt| {
                opt.and_then(|bytes| {
                    serde_json::from_slice(&bytes)
                        .ok()
                        .and_then(|entry: CacheEntry| {
                            if entry.is_expired() {
                                None
                            } else {
                                Some(entry)
                            }
                        })
                })
            })
            .collect();

        Ok(entries)
    }

    /// Set multiple entries at once using pipeline
    pub async fn mset(&self, entries: &[(CacheKey, CacheEntry)]) -> Result<()> {
        if entries.is_empty() {
            return Ok(());
        }

        let mut conn = self.connection.clone();
        let mut pipe = redis::pipe();

        for (key, entry) in entries {
            let redis_key = self.redis_key(key);
            let bytes = serde_json::to_vec(entry)?;
            let ttl = entry.ttl_secs.max(1);
            pipe.set_ex(&redis_key, bytes, ttl);
        }

        let _: () = pipe.query_async(&mut conn).await?;

        Ok(())
    }

    /// Delete multiple entries at once
    pub async fn mdel(&self, keys: &[CacheKey]) -> Result<u64> {
        if keys.is_empty() {
            return Ok(0);
        }

        let redis_keys: Vec<String> = keys.iter().map(|k| self.redis_key(k)).collect();
        let mut conn = self.connection.clone();

        let deleted: u64 = conn.del(&redis_keys).await?;

        Ok(deleted)
    }

    /// Check Redis connection health
    pub async fn ping(&self) -> Result<bool> {
        let mut conn = self.connection.clone();
        let pong: String = redis::cmd("PING").query_async(&mut conn).await?;
        Ok(pong == "PONG")
    }

    /// Get Redis server info
    pub async fn info(&self) -> Result<String> {
        let mut conn = self.connection.clone();
        let info: String = redis::cmd("INFO").query_async(&mut conn).await?;
        Ok(info)
    }
}

#[cfg(test)]
mod tests {
    // Redis tests require a running Redis server
    // Run with: cargo test --features redis -- --ignored

    use super::*;

    async fn get_test_cache() -> Option<RedisCache> {
        let url =
            std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());
        let config = CacheConfig::default();

        match RedisCache::with_prefix(&url, "mcplint_test", config).await {
            Ok(cache) => {
                // Clear test keys before starting
                let _ = cache.clear(None).await;
                Some(cache)
            }
            Err(_) => None, // Redis not available
        }
    }

    #[tokio::test]
    #[ignore] // Requires Redis server
    async fn redis_cache_basic_operations() {
        let Some(cache) = get_test_cache().await else {
            eprintln!("Skipping test: Redis not available");
            return;
        };

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
    #[ignore] // Requires Redis server
    async fn redis_cache_batch_operations() {
        let Some(cache) = get_test_cache().await else {
            eprintln!("Skipping test: Redis not available");
            return;
        };

        let entries: Vec<(CacheKey, CacheEntry)> = (0..5)
            .map(|i| {
                let key = CacheKey::schema(&format!("server-{}", i));
                let entry = CacheEntry::new(
                    format!("data-{}", i).into_bytes(),
                    Duration::from_secs(3600),
                );
                (key, entry)
            })
            .collect();

        // Batch set
        cache.mset(&entries).await.unwrap();

        // Batch get
        let keys: Vec<CacheKey> = entries.iter().map(|(k, _)| k.clone()).collect();
        let results = cache.mget(&keys).await.unwrap();

        assert_eq!(results.len(), 5);
        for result in results {
            assert!(result.is_some());
        }

        // Batch delete
        let deleted = cache.mdel(&keys).await.unwrap();
        assert_eq!(deleted, 5);
    }

    #[tokio::test]
    #[ignore] // Requires Redis server
    async fn redis_cache_ping() {
        let Some(cache) = get_test_cache().await else {
            eprintln!("Skipping test: Redis not available");
            return;
        };

        assert!(cache.ping().await.unwrap());
    }

    #[tokio::test]
    #[ignore] // Requires Redis server
    async fn redis_cache_stats() {
        let Some(cache) = get_test_cache().await else {
            eprintln!("Skipping test: Redis not available");
            return;
        };

        // Add some entries
        for i in 0..5 {
            let key = CacheKey::schema(&format!("server-{}", i));
            let entry = CacheEntry::new(vec![0u8; 100], Duration::from_secs(3600));
            cache.set(&key, entry).await.unwrap();
        }

        // Record some hits/misses
        cache.get(&CacheKey::schema("server-0")).await.unwrap();
        cache.get(&CacheKey::schema("nonexistent")).await.unwrap();

        let stats = cache.stats().await.unwrap();
        assert_eq!(stats.total_entries, 5);
    }
}
