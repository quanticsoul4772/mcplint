//! Cache Entry - Cached data with metadata
//!
//! Represents a cached item with TTL, timestamps,
//! and optional metadata for tracking.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

/// A cached entry with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEntry {
    /// The cached data (serialized as bytes)
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
    /// When this entry was created
    pub created_at: DateTime<Utc>,
    /// When this entry was last accessed
    pub last_accessed: DateTime<Utc>,
    /// Time-to-live in seconds
    pub ttl_secs: u64,
    /// Size in bytes
    pub size_bytes: u64,
    /// Optional metadata key-value pairs
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

impl CacheEntry {
    /// Create a new cache entry with default TTL
    pub fn new(data: Vec<u8>, ttl: Duration) -> Self {
        let now = Utc::now();
        let size = data.len() as u64;

        Self {
            data,
            created_at: now,
            last_accessed: now,
            ttl_secs: ttl.as_secs(),
            size_bytes: size,
            metadata: HashMap::new(),
        }
    }

    /// Create from serializable data
    pub fn from_value<T: Serialize>(value: &T, ttl: Duration) -> Result<Self, serde_json::Error> {
        let data = serde_json::to_vec(value)?;
        Ok(Self::new(data, ttl))
    }

    /// Deserialize the cached data
    pub fn to_value<T: for<'de> Deserialize<'de>>(&self) -> Result<T, serde_json::Error> {
        serde_json::from_slice(&self.data)
    }

    /// Check if this entry has expired
    pub fn is_expired(&self) -> bool {
        let expiry = self.created_at + chrono::Duration::seconds(self.ttl_secs as i64);
        Utc::now() > expiry
    }

    /// Get remaining TTL if not expired
    pub fn remaining_ttl(&self) -> Option<Duration> {
        let expiry = self.created_at + chrono::Duration::seconds(self.ttl_secs as i64);
        let now = Utc::now();

        if now > expiry {
            None
        } else {
            let remaining = expiry - now;
            Some(Duration::from_secs(remaining.num_seconds() as u64))
        }
    }

    /// Get the TTL as Duration
    pub fn ttl(&self) -> Duration {
        Duration::from_secs(self.ttl_secs)
    }

    /// Update last accessed time
    pub fn touch(&mut self) {
        self.last_accessed = Utc::now();
    }

    /// Add metadata
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Get metadata value
    pub fn get_metadata(&self, key: &str) -> Option<&str> {
        self.metadata.get(key).map(|s| s.as_str())
    }

    /// Get age of entry
    pub fn age(&self) -> Duration {
        let age = Utc::now() - self.created_at;
        Duration::from_secs(age.num_seconds().max(0) as u64)
    }

    /// Get time since last access
    pub fn idle_time(&self) -> Duration {
        let idle = Utc::now() - self.last_accessed;
        Duration::from_secs(idle.num_seconds().max(0) as u64)
    }
}

impl Default for CacheEntry {
    fn default() -> Self {
        Self::new(Vec::new(), Duration::from_secs(3600))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_creation() {
        let data = b"test data".to_vec();
        let entry = CacheEntry::new(data.clone(), Duration::from_secs(3600));

        assert_eq!(entry.data, data);
        assert_eq!(entry.ttl_secs, 3600);
        assert_eq!(entry.size_bytes, 9);
        assert!(!entry.is_expired());
    }

    #[test]
    fn entry_from_value() {
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct TestData {
            name: String,
            value: i32,
        }

        let original = TestData {
            name: "test".to_string(),
            value: 42,
        };

        let entry = CacheEntry::from_value(&original, Duration::from_secs(3600)).unwrap();
        let retrieved: TestData = entry.to_value().unwrap();

        assert_eq!(original, retrieved);
    }

    #[test]
    fn entry_expiration() {
        let entry = CacheEntry::new(vec![], Duration::from_secs(0));
        // With 0 TTL, should be expired immediately or very soon
        std::thread::sleep(std::time::Duration::from_millis(10));
        assert!(entry.is_expired());
    }

    #[test]
    fn remaining_ttl() {
        let entry = CacheEntry::new(vec![], Duration::from_secs(3600));
        let remaining = entry.remaining_ttl();

        assert!(remaining.is_some());
        assert!(remaining.unwrap().as_secs() > 3500); // Should be close to 3600
    }

    #[test]
    fn metadata() {
        let entry = CacheEntry::new(vec![], Duration::from_secs(3600))
            .with_metadata("server", "test-server")
            .with_metadata("version", "1.0");

        assert_eq!(entry.get_metadata("server"), Some("test-server"));
        assert_eq!(entry.get_metadata("version"), Some("1.0"));
        assert_eq!(entry.get_metadata("missing"), None);
    }

    #[test]
    fn entry_default() {
        let entry = CacheEntry::default();
        assert!(entry.data.is_empty());
        assert_eq!(entry.ttl_secs, 3600);
        assert!(!entry.is_expired());
    }

    #[test]
    fn entry_touch_updates_last_accessed() {
        let mut entry = CacheEntry::new(b"test".to_vec(), Duration::from_secs(3600));
        let original = entry.last_accessed;
        std::thread::sleep(std::time::Duration::from_millis(10));
        entry.touch();
        assert!(entry.last_accessed > original);
    }

    #[test]
    fn entry_ttl_returns_duration() {
        let entry = CacheEntry::new(vec![], Duration::from_secs(7200));
        assert_eq!(entry.ttl().as_secs(), 7200);
    }

    #[test]
    fn entry_age_returns_valid_duration() {
        let entry = CacheEntry::new(vec![], Duration::from_secs(3600));
        // Just check that age returns a valid duration (doesn't panic)
        let age = entry.age();
        // Age should be very small for a just-created entry
        assert!(age.as_secs() < 1);
    }

    #[test]
    fn entry_idle_time_returns_valid_duration() {
        let entry = CacheEntry::new(vec![], Duration::from_secs(3600));
        // Just check that idle_time returns a valid duration (doesn't panic)
        let idle = entry.idle_time();
        // Idle time should be very small for a just-created entry
        assert!(idle.as_secs() < 1);
    }

    #[test]
    fn remaining_ttl_none_when_expired() {
        let entry = CacheEntry::new(vec![], Duration::from_secs(0));
        std::thread::sleep(std::time::Duration::from_millis(10));
        assert!(entry.remaining_ttl().is_none());
    }

    #[test]
    fn from_value_with_complex_type() {
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct Complex {
            items: Vec<String>,
            count: u32,
            nested: Option<Inner>,
        }
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct Inner {
            value: i64,
        }

        let original = Complex {
            items: vec!["a".to_string(), "b".to_string()],
            count: 42,
            nested: Some(Inner { value: -100 }),
        };

        let entry = CacheEntry::from_value(&original, Duration::from_secs(3600)).unwrap();
        let retrieved: Complex = entry.to_value().unwrap();
        assert_eq!(original, retrieved);
    }

    #[test]
    fn entry_size_matches_data_length() {
        let data = vec![0u8; 1024];
        let entry = CacheEntry::new(data.clone(), Duration::from_secs(3600));
        assert_eq!(entry.size_bytes, data.len() as u64);
    }

    #[test]
    fn metadata_chaining() {
        let entry = CacheEntry::new(vec![], Duration::from_secs(3600))
            .with_metadata("key1", "val1")
            .with_metadata("key2", "val2")
            .with_metadata("key3", "val3");

        assert_eq!(entry.metadata.len(), 3);
        assert_eq!(entry.get_metadata("key1"), Some("val1"));
        assert_eq!(entry.get_metadata("key2"), Some("val2"));
        assert_eq!(entry.get_metadata("key3"), Some("val3"));
    }
}
