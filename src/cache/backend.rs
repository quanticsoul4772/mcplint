//! Cache Backend - Backend trait and configuration
//!
//! Defines the Cache trait that all backends implement
//! and the backend selection enum.

use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;

use super::entry::CacheEntry;
use super::key::{CacheCategory, CacheKey};
use super::stats::CacheStats;

/// Cache backend selection
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum CacheBackend {
    /// Filesystem-based cache storage
    Filesystem {
        /// Base path for cache storage
        path: PathBuf,
    },
    /// In-memory cache (ephemeral)
    Memory,
    /// Redis-based distributed cache
    #[cfg(feature = "redis")]
    Redis {
        /// Redis connection URL
        url: String,
        /// Default TTL for entries
        #[serde(default = "default_redis_ttl")]
        ttl_secs: u64,
    },
}

#[cfg(feature = "redis")]
fn default_redis_ttl() -> u64 {
    3600 // 1 hour
}

impl Default for CacheBackend {
    fn default() -> Self {
        CacheBackend::Filesystem {
            path: default_cache_path(),
        }
    }
}

/// Get the default cache path
pub fn default_cache_path() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".mcplint")
        .join("cache")
}

/// Cache configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    /// Selected backend
    pub backend: CacheBackend,
    /// TTL for schema entries
    #[serde(default = "default_schema_ttl")]
    pub schema_ttl_secs: u64,
    /// TTL for scan results
    #[serde(default = "default_result_ttl")]
    pub result_ttl_secs: u64,
    /// TTL for validation results
    #[serde(default = "default_validation_ttl")]
    pub validation_ttl_secs: u64,
    /// Whether to persist corpus data
    #[serde(default = "default_corpus_persist")]
    pub corpus_persist: bool,
    /// Maximum cache size in bytes (optional)
    pub max_size_bytes: Option<u64>,
    /// Whether caching is enabled
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_schema_ttl() -> u64 {
    3600 // 1 hour
}
fn default_result_ttl() -> u64 {
    86400 // 24 hours
}
fn default_validation_ttl() -> u64 {
    3600 // 1 hour
}
fn default_corpus_persist() -> bool {
    true
}
fn default_enabled() -> bool {
    true
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            backend: CacheBackend::default(),
            schema_ttl_secs: default_schema_ttl(),
            result_ttl_secs: default_result_ttl(),
            validation_ttl_secs: default_validation_ttl(),
            corpus_persist: default_corpus_persist(),
            max_size_bytes: None,
            enabled: default_enabled(),
        }
    }
}

impl CacheConfig {
    /// Create a memory-only cache config
    pub fn memory() -> Self {
        Self {
            backend: CacheBackend::Memory,
            ..Default::default()
        }
    }

    /// Create a filesystem cache config with custom path
    pub fn filesystem(path: PathBuf) -> Self {
        Self {
            backend: CacheBackend::Filesystem { path },
            ..Default::default()
        }
    }

    /// Create a Redis cache config
    #[cfg(feature = "redis")]
    pub fn redis(url: &str) -> Self {
        Self {
            backend: CacheBackend::Redis {
                url: url.to_string(),
                ttl_secs: default_redis_ttl(),
            },
            ..Default::default()
        }
    }

    /// Get TTL for a specific category
    pub fn ttl_for_category(&self, category: CacheCategory) -> Duration {
        match category {
            CacheCategory::Schema => Duration::from_secs(self.schema_ttl_secs),
            CacheCategory::ScanResult => Duration::from_secs(self.result_ttl_secs),
            CacheCategory::Validation => Duration::from_secs(self.validation_ttl_secs),
            CacheCategory::Corpus => Duration::from_secs(86400 * 365), // 1 year (persistent)
            CacheCategory::ToolHash => Duration::from_secs(86400 * 365), // 1 year (persistent)
            CacheCategory::AiResponse => Duration::from_secs(3600),    // 1 hour
        }
    }

    /// Set max cache size
    pub fn with_max_size(mut self, bytes: u64) -> Self {
        self.max_size_bytes = Some(bytes);
        self
    }

    /// Disable caching
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            ..Default::default()
        }
    }
}

/// The core cache trait that all backends implement
#[async_trait]
pub trait Cache: Send + Sync {
    /// Get an entry from the cache
    async fn get(&self, key: &CacheKey) -> Result<Option<CacheEntry>>;

    /// Set an entry in the cache
    async fn set(&self, key: &CacheKey, entry: CacheEntry) -> Result<()>;

    /// Delete an entry from the cache
    async fn delete(&self, key: &CacheKey) -> Result<()>;

    /// Check if a key exists in the cache
    async fn exists(&self, key: &CacheKey) -> Result<bool>;

    /// Clear cache entries, optionally filtered by category
    /// Returns the number of entries cleared
    async fn clear(&self, category: Option<CacheCategory>) -> Result<u64>;

    /// Get cache statistics
    async fn stats(&self) -> Result<CacheStats>;

    /// Prune expired entries
    /// Returns the number of entries pruned
    async fn prune_expired(&self) -> Result<u64>;

    /// Get all keys, optionally filtered by category
    async fn keys(&self, category: Option<CacheCategory>) -> Result<Vec<CacheKey>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config() {
        let config = CacheConfig::default();
        assert!(config.enabled);
        assert!(config.corpus_persist);
        assert_eq!(config.schema_ttl_secs, 3600);
    }

    #[test]
    fn memory_config() {
        let config = CacheConfig::memory();
        assert!(matches!(config.backend, CacheBackend::Memory));
    }

    #[test]
    fn ttl_for_category() {
        let config = CacheConfig::default();

        assert_eq!(
            config.ttl_for_category(CacheCategory::Schema).as_secs(),
            3600
        );
        assert_eq!(
            config.ttl_for_category(CacheCategory::ScanResult).as_secs(),
            86400
        );
    }

    #[test]
    fn disabled_config() {
        let config = CacheConfig::disabled();
        assert!(!config.enabled);
    }
}
