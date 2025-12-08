//! Cache Statistics - Usage metrics and reporting
//!
//! Tracks cache performance including hits, misses,
//! size, and per-category breakdowns.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use super::key::CacheCategory;

/// Cache usage statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CacheStats {
    /// Total number of entries
    pub total_entries: u64,
    /// Total size in bytes
    pub total_size_bytes: u64,
    /// Number of cache hits
    pub hits: u64,
    /// Number of cache misses
    pub misses: u64,
    /// Cache hit ratio (0.0 - 1.0)
    pub hit_ratio: f64,
    /// Statistics broken down by category
    pub by_category: HashMap<String, CategoryStats>,
    /// Timestamp of oldest entry
    pub oldest_entry: Option<DateTime<Utc>>,
    /// Timestamp of newest entry
    pub newest_entry: Option<DateTime<Utc>>,
    /// Number of expired entries
    pub expired_entries: u64,
}

impl CacheStats {
    /// Create empty stats
    pub fn new() -> Self {
        Self::default()
    }

    /// Calculate hit ratio from hits and misses
    pub fn calculate_hit_ratio(&mut self) {
        let total = self.hits + self.misses;
        self.hit_ratio = if total > 0 {
            self.hits as f64 / total as f64
        } else {
            0.0
        };
    }

    /// Update category stats
    pub fn update_category(&mut self, category: CacheCategory, stats: CategoryStats) {
        self.by_category.insert(category.to_string(), stats);
    }

    /// Get formatted size string
    pub fn formatted_size(&self) -> String {
        format_bytes(self.total_size_bytes)
    }

    /// Merge with another stats instance
    pub fn merge(&mut self, other: &CacheStats) {
        self.total_entries += other.total_entries;
        self.total_size_bytes += other.total_size_bytes;
        self.hits += other.hits;
        self.misses += other.misses;
        self.expired_entries += other.expired_entries;
        self.calculate_hit_ratio();

        // Update timestamps
        if let Some(oldest) = other.oldest_entry {
            match self.oldest_entry {
                Some(current) if oldest < current => self.oldest_entry = Some(oldest),
                None => self.oldest_entry = Some(oldest),
                _ => {}
            }
        }

        if let Some(newest) = other.newest_entry {
            match self.newest_entry {
                Some(current) if newest > current => self.newest_entry = Some(newest),
                None => self.newest_entry = Some(newest),
                _ => {}
            }
        }

        // Merge category stats
        for (cat, stats) in &other.by_category {
            self.by_category
                .entry(cat.clone())
                .and_modify(|e| {
                    e.entries += stats.entries;
                    e.size_bytes += stats.size_bytes;
                    e.expired += stats.expired;
                })
                .or_insert_with(|| stats.clone());
        }
    }
}

/// Statistics for a specific cache category
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CategoryStats {
    /// Number of entries in this category
    pub entries: u64,
    /// Total size in bytes for this category
    pub size_bytes: u64,
    /// Number of expired entries
    pub expired: u64,
}

impl CategoryStats {
    /// Create new category stats
    pub fn new(entries: u64, size_bytes: u64, expired: u64) -> Self {
        Self {
            entries,
            size_bytes,
            expired,
        }
    }

    /// Get formatted size string
    pub fn formatted_size(&self) -> String {
        format_bytes(self.size_bytes)
    }
}

/// Atomic cache statistics for thread-safe tracking
pub struct AtomicCacheStats {
    pub hits: AtomicU64,
    pub misses: AtomicU64,
    pub entries: AtomicU64,
    pub size_bytes: AtomicU64,
}

impl AtomicCacheStats {
    /// Create new atomic stats
    pub fn new() -> Self {
        Self {
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            entries: AtomicU64::new(0),
            size_bytes: AtomicU64::new(0),
        }
    }

    /// Record a cache hit
    pub fn record_hit(&self) {
        self.hits.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a cache miss
    pub fn record_miss(&self) {
        self.misses.fetch_add(1, Ordering::Relaxed);
    }

    /// Record an entry addition
    pub fn record_add(&self, size: u64) {
        self.entries.fetch_add(1, Ordering::Relaxed);
        self.size_bytes.fetch_add(size, Ordering::Relaxed);
    }

    /// Record an entry removal
    pub fn record_remove(&self, size: u64) {
        self.entries.fetch_sub(1, Ordering::Relaxed);
        self.size_bytes.fetch_sub(size, Ordering::Relaxed);
    }

    /// Get current stats as CacheStats
    pub fn to_stats(&self) -> CacheStats {
        let hits = self.hits.load(Ordering::Relaxed);
        let misses = self.misses.load(Ordering::Relaxed);
        let total = hits + misses;

        CacheStats {
            total_entries: self.entries.load(Ordering::Relaxed),
            total_size_bytes: self.size_bytes.load(Ordering::Relaxed),
            hits,
            misses,
            hit_ratio: if total > 0 {
                hits as f64 / total as f64
            } else {
                0.0
            },
            ..Default::default()
        }
    }

    /// Reset all counters
    pub fn reset(&self) {
        self.hits.store(0, Ordering::Relaxed);
        self.misses.store(0, Ordering::Relaxed);
        self.entries.store(0, Ordering::Relaxed);
        self.size_bytes.store(0, Ordering::Relaxed);
    }
}

impl Default for AtomicCacheStats {
    fn default() -> Self {
        Self::new()
    }
}

/// Format bytes as human-readable string
pub fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stats_creation() {
        let stats = CacheStats::new();
        assert_eq!(stats.total_entries, 0);
        assert_eq!(stats.hit_ratio, 0.0);
    }

    #[test]
    fn hit_ratio_calculation() {
        let mut stats = CacheStats {
            hits: 80,
            misses: 20,
            ..Default::default()
        };

        stats.calculate_hit_ratio();
        assert!((stats.hit_ratio - 0.8).abs() < 0.001);
    }

    #[test]
    fn atomic_stats() {
        let stats = AtomicCacheStats::new();

        stats.record_hit();
        stats.record_hit();
        stats.record_miss();
        stats.record_add(100);

        let snapshot = stats.to_stats();
        assert_eq!(snapshot.hits, 2);
        assert_eq!(snapshot.misses, 1);
        assert_eq!(snapshot.total_entries, 1);
        assert_eq!(snapshot.total_size_bytes, 100);
    }

    #[test]
    fn format_bytes_display() {
        assert_eq!(format_bytes(500), "500 B");
        assert_eq!(format_bytes(2048), "2.00 KB");
        assert_eq!(format_bytes(1048576), "1.00 MB");
        assert_eq!(format_bytes(1073741824), "1.00 GB");
    }

    #[test]
    fn stats_merge() {
        let mut stats1 = CacheStats {
            total_entries: 10,
            hits: 8,
            misses: 2,
            ..Default::default()
        };

        let stats2 = CacheStats {
            total_entries: 5,
            hits: 4,
            misses: 1,
            ..Default::default()
        };

        stats1.merge(&stats2);
        assert_eq!(stats1.total_entries, 15);
        assert_eq!(stats1.hits, 12);
        assert_eq!(stats1.misses, 3);
    }
}
