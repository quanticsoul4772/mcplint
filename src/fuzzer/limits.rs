//! Resource Limits - Safety controls for fuzzing sessions
//!
//! Provides resource monitoring and limit enforcement to prevent
//! runaway fuzzing sessions from consuming excessive resources.
//!
//! # Supported Limits
//!
//! - **Time**: Maximum execution time
//! - **Memory**: Maximum process memory usage
//! - **Executions**: Maximum number of iterations
//! - **Corpus Size**: Maximum entries in the corpus
//! - **Restarts**: Maximum server restart attempts
//!
//! # Error Handling
//!
//! This module uses comprehensive error types with `thiserror` for
//! consistent and informative error reporting.
//!
//! # Example
//!
//! ```ignore
//! use mcplint::fuzzer::limits::{ResourceLimits, ResourceMonitor};
//!
//! let limits = ResourceLimits::default()
//!     .with_max_time(Duration::from_secs(300))
//!     .with_max_memory(512 * 1024 * 1024);
//!
//! let mut monitor = ResourceMonitor::new(limits);
//!
//! loop {
//!     // ... fuzzing iteration ...
//!     if let Some(exceeded) = monitor.check(&stats) {
//!         println!("Limit exceeded: {}", exceeded);
//!         break;
//!     }
//! }
//! ```

use std::time::{Duration, Instant};

/// Resource limits for fuzzing sessions
#[derive(Debug, Clone)]
pub struct ResourceLimits {
    /// Maximum execution time (None = unlimited)
    pub max_time: Option<Duration>,
    /// Maximum memory usage in bytes (None = unlimited)
    pub max_memory: Option<u64>,
    /// Maximum number of executions/iterations (None = unlimited)
    pub max_executions: Option<u64>,
    /// Maximum corpus size in entries (None = unlimited)
    pub max_corpus_size: Option<usize>,
    /// Maximum server restart attempts (None = unlimited)
    pub max_restarts: Option<u32>,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_time: Some(Duration::from_secs(300)), // 5 minutes default
            max_memory: Some(512 * 1024 * 1024),      // 512MB default
            max_executions: None,                     // Unlimited by default
            max_corpus_size: Some(10_000),            // 10K entries default
            max_restarts: Some(10),                   // 10 restarts default
        }
    }
}

impl ResourceLimits {
    /// Create unlimited resource limits
    pub fn unlimited() -> Self {
        Self {
            max_time: None,
            max_memory: None,
            max_executions: None,
            max_corpus_size: None,
            max_restarts: None,
        }
    }

    /// Set maximum execution time
    pub fn with_max_time(mut self, duration: Duration) -> Self {
        self.max_time = Some(duration);
        self
    }

    /// Set maximum memory usage
    pub fn with_max_memory(mut self, bytes: u64) -> Self {
        self.max_memory = Some(bytes);
        self
    }

    /// Set maximum executions
    pub fn with_max_executions(mut self, count: u64) -> Self {
        self.max_executions = Some(count);
        self
    }

    /// Set maximum corpus size
    pub fn with_max_corpus_size(mut self, count: usize) -> Self {
        self.max_corpus_size = Some(count);
        self
    }

    /// Set maximum restarts
    pub fn with_max_restarts(mut self, count: u32) -> Self {
        self.max_restarts = Some(count);
        self
    }

    /// Check if any limits are configured
    pub fn has_limits(&self) -> bool {
        self.max_time.is_some()
            || self.max_memory.is_some()
            || self.max_executions.is_some()
            || self.max_corpus_size.is_some()
            || self.max_restarts.is_some()
    }

    /// Parse duration from human-readable string (e.g., "5m", "1h", "30s")
    pub fn parse_duration(s: &str) -> Result<Duration, ParseError> {
        let s = s.trim().to_lowercase();

        if s.is_empty() {
            return Err(ParseError::Empty);
        }

        // Try to find the unit suffix
        let (num_str, multiplier) = if s.ends_with("ms") {
            (&s[..s.len() - 2], 1u64)
        } else if s.ends_with('s') {
            (&s[..s.len() - 1], 1000u64)
        } else if s.ends_with('m') {
            (&s[..s.len() - 1], 60 * 1000u64)
        } else if s.ends_with('h') {
            (&s[..s.len() - 1], 60 * 60 * 1000u64)
        } else if s.ends_with('d') {
            (&s[..s.len() - 1], 24 * 60 * 60 * 1000u64)
        } else {
            // Assume seconds if no unit
            (s.as_str(), 1000u64)
        };

        let num: u64 = num_str
            .trim()
            .parse()
            .map_err(|_| ParseError::InvalidNumber(num_str.to_string()))?;

        Ok(Duration::from_millis(num * multiplier))
    }

    /// Parse byte size from human-readable string (e.g., "512MB", "1G", "100K")
    pub fn parse_bytes(s: &str) -> Result<u64, ParseError> {
        let s = s.trim().to_uppercase();

        if s.is_empty() {
            return Err(ParseError::Empty);
        }

        // Try to find the unit suffix
        let (num_str, multiplier) = if s.ends_with("GB") || s.ends_with('G') {
            let len = if s.ends_with("GB") { 2 } else { 1 };
            (&s[..s.len() - len], 1024u64 * 1024 * 1024)
        } else if s.ends_with("MB") || s.ends_with('M') {
            let len = if s.ends_with("MB") { 2 } else { 1 };
            (&s[..s.len() - len], 1024u64 * 1024)
        } else if s.ends_with("KB") || s.ends_with('K') {
            let len = if s.ends_with("KB") { 2 } else { 1 };
            (&s[..s.len() - len], 1024u64)
        } else if s.ends_with('B') {
            (&s[..s.len() - 1], 1u64)
        } else {
            // Assume bytes if no unit
            (s.as_str(), 1u64)
        };

        let num: u64 = num_str
            .trim()
            .parse()
            .map_err(|_| ParseError::InvalidNumber(num_str.to_string()))?;

        Ok(num * multiplier)
    }
}

/// Error parsing limit values
#[derive(Debug, Clone)]
pub enum ParseError {
    /// Empty input
    Empty,
    /// Invalid number
    InvalidNumber(String),
    /// Unknown unit
    UnknownUnit(String),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::Empty => write!(f, "empty value"),
            ParseError::InvalidNumber(s) => write!(f, "invalid number: '{}'", s),
            ParseError::UnknownUnit(s) => write!(f, "unknown unit: '{}'", s),
        }
    }
}

impl std::error::Error for ParseError {}

/// Comprehensive error type for fuzzer resource limits
#[derive(Debug, thiserror::Error)]
pub enum FuzzerError {
    /// Configuration parsing error
    #[error("Configuration error: {0}")]
    ConfigError(#[from] ParseError),

    /// Memory monitoring failed
    #[error("Memory monitoring failed: {0}")]
    MemoryMonitoringFailed(String),

    /// Time limit exceeded
    #[error("Time limit exceeded: {0}")]
    TimeLimitExceeded(String),

    /// Memory limit exceeded
    #[error("Memory limit exceeded: {0} bytes")]
    MemoryLimitExceeded(u64),

    /// Execution limit exceeded
    #[error("Execution limit exceeded: {0} iterations")]
    ExecutionLimitExceeded(u64),

    /// Corpus size limit exceeded
    #[error("Corpus size limit exceeded: {0} entries")]
    CorpusLimitExceeded(usize),

    /// Restart limit exceeded
    #[error("Restart limit exceeded: {0} attempts")]
    RestartLimitExceeded(u32),

    /// Platform not supported for memory monitoring
    #[error("Memory monitoring not supported on this platform")]
    PlatformNotSupported,

    /// IO error during resource monitoring
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}



/// Statistics tracked during fuzzing for limit checking
#[derive(Debug, Clone, Default)]
pub struct FuzzStats {
    /// Number of executions/iterations completed
    pub executions: u64,
    /// Current corpus size
    pub corpus_size: usize,
    /// Number of server restarts
    pub restarts: u32,
}

/// Resource monitor that tracks usage and checks limits
pub struct ResourceMonitor {
    /// Configured limits
    limits: ResourceLimits,
    /// Session start time
    start_time: Instant,
    /// Current process ID (for memory monitoring)
    pid: u32,
}

impl ResourceMonitor {
    /// Create a new resource monitor
    pub fn new(limits: ResourceLimits) -> Self {
        Self {
            limits,
            start_time: Instant::now(),
            pid: std::process::id(),
        }
    }

    /// Reset the start time (for session restarts)
    pub fn reset_timer(&mut self) {
        self.start_time = Instant::now();
    }

    /// Get elapsed time since start
    pub fn elapsed(&self) -> Duration {
        self.start_time.elapsed()
    }

    /// Check if any limits have been exceeded
    pub fn check(&self, stats: &FuzzStats) -> Option<LimitExceeded> {
        // Time limit
        if let Some(max_time) = self.limits.max_time {
            if self.start_time.elapsed() >= max_time {
                return Some(LimitExceeded::Time(max_time));
            }
        }

        // Execution limit
        if let Some(max_execs) = self.limits.max_executions {
            if stats.executions >= max_execs {
                return Some(LimitExceeded::Executions(max_execs));
            }
        }

        // Corpus size limit
        if let Some(max_corpus) = self.limits.max_corpus_size {
            if stats.corpus_size >= max_corpus {
                return Some(LimitExceeded::CorpusSize(max_corpus));
            }
        }

        // Restart limit
        if let Some(max_restarts) = self.limits.max_restarts {
            if stats.restarts >= max_restarts {
                return Some(LimitExceeded::Restarts(max_restarts));
            }
        }

        // Memory limit (most expensive check, do last)
        if let Some(max_mem) = self.limits.max_memory {
            if let Ok(current_mem) = self.get_process_memory() {
                if current_mem >= max_mem {
                    return Some(LimitExceeded::Memory(max_mem));
                }
            }
        }

        None
    }

    /// Check if a specific limit type is exceeded
    pub fn check_specific(&self, stats: &FuzzStats, limit_type: LimitType) -> bool {
        match limit_type {
            LimitType::Time => {
                if let Some(max_time) = self.limits.max_time {
                    return self.start_time.elapsed() >= max_time;
                }
            }
            LimitType::Memory => {
                if let Some(max_mem) = self.limits.max_memory {
                    if let Ok(current_mem) = self.get_process_memory() {
                        return current_mem >= max_mem;
                    }
                }
            }
            LimitType::Executions => {
                if let Some(max_execs) = self.limits.max_executions {
                    return stats.executions >= max_execs;
                }
            }
            LimitType::CorpusSize => {
                if let Some(max_corpus) = self.limits.max_corpus_size {
                    return stats.corpus_size >= max_corpus;
                }
            }
            LimitType::Restarts => {
                if let Some(max_restarts) = self.limits.max_restarts {
                    return stats.restarts >= max_restarts;
                }
            }
        }
        false
    }

    /// Get remaining time until time limit
    pub fn remaining_time(&self) -> Option<Duration> {
        self.limits.max_time.map(|max| {
            let elapsed = self.start_time.elapsed();
            if elapsed >= max {
                Duration::ZERO
            } else {
                max - elapsed
            }
        })
    }

    /// Get current process memory usage in bytes
    fn get_process_memory(&self) -> Result<u64, FuzzerError> {
        // Use a simple cross-platform approach
        #[cfg(target_os = "windows")]
        {
            self.get_memory_windows()
        }

        #[cfg(target_os = "linux")]
        {
            self.get_memory_linux()
        }

        #[cfg(target_os = "macos")]
        {
            self.get_memory_macos()
        }

        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        {
            Err(FuzzerError::PlatformNotSupported)
        }
    }

    #[cfg(target_os = "windows")]
    fn get_memory_windows(&self) -> Result<u64, FuzzerError> {
        /// Safe wrapper for Windows process memory monitoring
        fn get_process_memory_safe() -> Result<u64, FuzzerError> {
            #[repr(C)]
            struct ProcessMemoryCounters {
                cb: u32,
                page_fault_count: u32,
                peak_working_set_size: usize,
                working_set_size: usize,
                quota_peak_paged_pool_usage: usize,
                quota_paged_pool_usage: usize,
                quota_peak_non_paged_pool_usage: usize,
                quota_non_paged_pool_usage: usize,
                pagefile_usage: usize,
                peak_pagefile_usage: usize,
            }

            #[link(name = "psapi")]
            extern "system" {
                fn GetProcessMemoryInfo(
                    process: *mut std::ffi::c_void,
                    pmc: *mut ProcessMemoryCounters,
                    cb: u32,
                ) -> i32;
            }

            #[link(name = "kernel32")]
            extern "system" {
                fn GetCurrentProcess() -> *mut std::ffi::c_void;
            }

            // Safe wrapper with proper initialization and error handling
            let mut pmc = ProcessMemoryCounters {
                cb: std::mem::size_of::<ProcessMemoryCounters>() as u32,
                page_fault_count: 0,
                peak_working_set_size: 0,
                working_set_size: 0,
                quota_peak_paged_pool_usage: 0,
                quota_paged_pool_usage: 0,
                quota_peak_non_paged_pool_usage: 0,
                quota_non_paged_pool_usage: 0,
                pagefile_usage: 0,
                peak_pagefile_usage: 0,
            };

            let result = unsafe { GetProcessMemoryInfo(GetCurrentProcess(), &mut pmc, pmc.cb) };

            if result != 0 {
                Ok(pmc.working_set_size as u64)
            } else {
                Err(FuzzerError::MemoryMonitoringFailed(
                    "Windows GetProcessMemoryInfo failed".to_string(),
                ))
            }
        }

        get_process_memory_safe()
    }

    #[cfg(target_os = "linux")]
    fn get_memory_linux(&self) -> Result<u64, FuzzerError> {
        // Read from /proc/self/statm
        let contents = std::fs::read_to_string("/proc/self/statm").map_err(FuzzerError::IoError)?;

        let parts: Vec<&str> = contents.split_whitespace().collect();
        // Second field is RSS in pages
        parts
            .get(1)
            .and_then(|rss| rss.parse::<u64>().ok())
            .map(|pages| pages * 4096) // Page size is typically 4KB
            .ok_or_else(|| {
                FuzzerError::MemoryMonitoringFailed("Failed to parse /proc/self/statm".to_string())
            })
    }

    #[cfg(target_os = "macos")]
    fn get_memory_macos(&self) -> Result<u64, FuzzerError> {
        /// Safe wrapper for macOS process memory monitoring using getrusage
        fn get_memory_usage_safe() -> Result<u64, FuzzerError> {
            #[repr(C)]
            struct Rusage {
                ru_utime: [i64; 2],
                ru_stime: [i64; 2],
                ru_maxrss: i64,
                // ... other fields we don't need
                _padding: [i64; 13],
            }

            extern "C" {
                fn getrusage(who: i32, usage: *mut Rusage) -> i32;
            }

            const RUSAGE_SELF: i32 = 0;

            // Safe wrapper with proper initialization
            let mut usage = Rusage {
                ru_utime: [0, 0],
                ru_stime: [0, 0],
                ru_maxrss: 0,
                _padding: [0; 13],
            };

            let result = unsafe { getrusage(RUSAGE_SELF, &mut usage) };

            if result == 0 {
                // On macOS, ru_maxrss is in bytes
                Ok(usage.ru_maxrss as u64)
            } else {
                Err(FuzzerError::MemoryMonitoringFailed(
                    "macOS getrusage failed".to_string(),
                ))
            }
        }

        get_memory_usage_safe()
    }

    /// Get the configured limits
    pub fn limits(&self) -> &ResourceLimits {
        &self.limits
    }

    /// Get current usage summary
    pub fn usage_summary(&self, stats: &FuzzStats) -> Result<UsageSummary, FuzzerError> {
        Ok(UsageSummary {
            elapsed: self.start_time.elapsed(),
            max_time: self.limits.max_time,
            memory_used: self.get_process_memory().ok(),
            max_memory: self.limits.max_memory,
            executions: stats.executions,
            max_executions: self.limits.max_executions,
            corpus_size: stats.corpus_size,
            max_corpus_size: self.limits.max_corpus_size,
            restarts: stats.restarts,
            max_restarts: self.limits.max_restarts,
        })
    }
}

/// Types of limits that can be exceeded
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitType {
    Time,
    Memory,
    Executions,
    CorpusSize,
    Restarts,
}

/// Information about which limit was exceeded
#[derive(Debug, Clone)]
pub enum LimitExceeded {
    /// Time limit exceeded
    Time(Duration),
    /// Memory limit exceeded
    Memory(u64),
    /// Execution count limit exceeded
    Executions(u64),
    /// Corpus size limit exceeded
    CorpusSize(usize),
    /// Restart count limit exceeded
    Restarts(u32),
}

impl std::fmt::Display for LimitExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LimitExceeded::Time(d) => write!(f, "Time limit exceeded: {:?}", d),
            LimitExceeded::Memory(b) => write!(f, "Memory limit exceeded: {} bytes", b),
            LimitExceeded::Executions(n) => write!(f, "Execution limit exceeded: {} iterations", n),
            LimitExceeded::CorpusSize(n) => write!(f, "Corpus size limit exceeded: {} entries", n),
            LimitExceeded::Restarts(n) => write!(f, "Restart limit exceeded: {} restarts", n),
        }
    }
}

impl LimitExceeded {
    /// Get the limit type
    pub fn limit_type(&self) -> LimitType {
        match self {
            LimitExceeded::Time(_) => LimitType::Time,
            LimitExceeded::Memory(_) => LimitType::Memory,
            LimitExceeded::Executions(_) => LimitType::Executions,
            LimitExceeded::CorpusSize(_) => LimitType::CorpusSize,
            LimitExceeded::Restarts(_) => LimitType::Restarts,
        }
    }

    /// Check if this is a critical limit (should stop immediately)
    pub fn is_critical(&self) -> bool {
        matches!(self, LimitExceeded::Memory(_) | LimitExceeded::Restarts(_))
    }
}

/// Summary of current resource usage
#[derive(Debug, Clone)]
pub struct UsageSummary {
    pub elapsed: Duration,
    pub max_time: Option<Duration>,
    pub memory_used: Option<u64>,
    pub max_memory: Option<u64>,
    pub executions: u64,
    pub max_executions: Option<u64>,
    pub corpus_size: usize,
    pub max_corpus_size: Option<usize>,
    pub restarts: u32,
    pub max_restarts: Option<u32>,
}

impl UsageSummary {
    /// Get time usage as percentage (0.0 - 1.0), None if no limit
    pub fn time_usage(&self) -> Option<f64> {
        self.max_time.map(|max| {
            let elapsed = self.elapsed.as_secs_f64();
            let max = max.as_secs_f64();
            (elapsed / max).min(1.0)
        })
    }

    /// Get memory usage as percentage (0.0 - 1.0), None if no limit or unknown
    pub fn memory_usage(&self) -> Option<f64> {
        match (self.memory_used, self.max_memory) {
            (Some(used), Some(max)) => Some((used as f64 / max as f64).min(1.0)),
            _ => None,
        }
    }

    /// Get execution usage as percentage (0.0 - 1.0), None if no limit
    pub fn execution_usage(&self) -> Option<f64> {
        self.max_executions
            .map(|max| (self.executions as f64 / max as f64).min(1.0))
    }

    /// Get corpus usage as percentage (0.0 - 1.0), None if no limit
    pub fn corpus_usage(&self) -> Option<f64> {
        self.max_corpus_size
            .map(|max| (self.corpus_size as f64 / max as f64).min(1.0))
    }
}

/// Format bytes as human-readable string
pub fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.1}GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1}MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1}KB", bytes as f64 / KB as f64)
    } else {
        format!("{}B", bytes)
    }
}

/// Format duration as human-readable string
pub fn format_duration(duration: Duration) -> String {
    let secs = duration.as_secs();

    if secs >= 3600 {
        format!("{}h{}m", secs / 3600, (secs % 3600) / 60)
    } else if secs >= 60 {
        format!("{}m{}s", secs / 60, secs % 60)
    } else {
        format!("{}s", secs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_limits() {
        let limits = ResourceLimits::default();
        assert_eq!(limits.max_time, Some(Duration::from_secs(300)));
        assert_eq!(limits.max_memory, Some(512 * 1024 * 1024));
        assert!(limits.has_limits());
    }

    #[test]
    fn unlimited_limits() {
        let limits = ResourceLimits::unlimited();
        assert!(limits.max_time.is_none());
        assert!(limits.max_memory.is_none());
        assert!(!limits.has_limits());
    }

    #[test]
    fn parse_duration_seconds() {
        assert_eq!(
            ResourceLimits::parse_duration("30s").unwrap(),
            Duration::from_secs(30)
        );
        assert_eq!(
            ResourceLimits::parse_duration("30").unwrap(),
            Duration::from_secs(30)
        );
    }

    #[test]
    fn parse_duration_minutes() {
        assert_eq!(
            ResourceLimits::parse_duration("5m").unwrap(),
            Duration::from_secs(300)
        );
    }

    #[test]
    fn parse_duration_hours() {
        assert_eq!(
            ResourceLimits::parse_duration("1h").unwrap(),
            Duration::from_secs(3600)
        );
    }

    #[test]
    fn parse_duration_milliseconds() {
        assert_eq!(
            ResourceLimits::parse_duration("500ms").unwrap(),
            Duration::from_millis(500)
        );
    }

    #[test]
    fn parse_bytes_megabytes() {
        assert_eq!(
            ResourceLimits::parse_bytes("512MB").unwrap(),
            512 * 1024 * 1024
        );
        assert_eq!(
            ResourceLimits::parse_bytes("512M").unwrap(),
            512 * 1024 * 1024
        );
    }

    #[test]
    fn parse_bytes_gigabytes() {
        assert_eq!(
            ResourceLimits::parse_bytes("1GB").unwrap(),
            1024 * 1024 * 1024
        );
        assert_eq!(
            ResourceLimits::parse_bytes("1G").unwrap(),
            1024 * 1024 * 1024
        );
    }

    #[test]
    fn parse_bytes_kilobytes() {
        assert_eq!(ResourceLimits::parse_bytes("100KB").unwrap(), 100 * 1024);
        assert_eq!(ResourceLimits::parse_bytes("100K").unwrap(), 100 * 1024);
    }

    #[test]
    fn monitor_time_limit() {
        let limits = ResourceLimits::default().with_max_time(Duration::from_millis(1));
        let monitor = ResourceMonitor::new(limits);

        // Sleep briefly to exceed the 1ms limit
        std::thread::sleep(Duration::from_millis(10));

        let stats = FuzzStats::default();
        let result = monitor.check(&stats);

        assert!(matches!(result, Some(LimitExceeded::Time(_))));
    }

    #[test]
    fn monitor_execution_limit() {
        let limits = ResourceLimits::default().with_max_executions(100);
        let monitor = ResourceMonitor::new(limits);

        let stats_50 = FuzzStats {
            executions: 50,
            ..FuzzStats::default()
        };
        assert!(monitor.check(&stats_50).is_none());

        let stats_100 = FuzzStats {
            executions: 100,
            ..FuzzStats::default()
        };
        assert!(matches!(
            monitor.check(&stats_100),
            Some(LimitExceeded::Executions(100))
        ));
    }

    #[test]
    fn monitor_corpus_limit() {
        let limits = ResourceLimits::default().with_max_corpus_size(1000);
        let monitor = ResourceMonitor::new(limits);

        let stats_500 = FuzzStats {
            corpus_size: 500,
            ..FuzzStats::default()
        };
        assert!(monitor.check(&stats_500).is_none());

        let stats_1000 = FuzzStats {
            corpus_size: 1000,
            ..FuzzStats::default()
        };
        assert!(matches!(
            monitor.check(&stats_1000),
            Some(LimitExceeded::CorpusSize(1000))
        ));
    }

    #[test]
    fn monitor_restart_limit() {
        let limits = ResourceLimits::default().with_max_restarts(5);
        let monitor = ResourceMonitor::new(limits);

        let stats_3 = FuzzStats {
            restarts: 3,
            ..FuzzStats::default()
        };
        assert!(monitor.check(&stats_3).is_none());

        let stats_5 = FuzzStats {
            restarts: 5,
            ..FuzzStats::default()
        };
        assert!(matches!(
            monitor.check(&stats_5),
            Some(LimitExceeded::Restarts(5))
        ));
    }

    #[test]
    fn remaining_time_calculation() {
        let limits = ResourceLimits::default().with_max_time(Duration::from_secs(60));
        let monitor = ResourceMonitor::new(limits);

        let remaining = monitor.remaining_time();
        assert!(remaining.is_some());
        assert!(remaining.unwrap() <= Duration::from_secs(60));
    }

    #[test]
    fn format_bytes_display() {
        assert_eq!(format_bytes(500), "500B");
        assert_eq!(format_bytes(1024), "1.0KB");
        assert_eq!(format_bytes(1024 * 1024), "1.0MB");
        assert_eq!(format_bytes(1024 * 1024 * 1024), "1.0GB");
        assert_eq!(format_bytes(512 * 1024 * 1024), "512.0MB");
    }

    #[test]
    fn format_duration_display() {
        assert_eq!(format_duration(Duration::from_secs(30)), "30s");
        assert_eq!(format_duration(Duration::from_secs(90)), "1m30s");
        assert_eq!(format_duration(Duration::from_secs(3660)), "1h1m");
    }

    #[test]
    fn limit_exceeded_is_critical() {
        assert!(LimitExceeded::Memory(100).is_critical());
        assert!(LimitExceeded::Restarts(5).is_critical());
        assert!(!LimitExceeded::Time(Duration::from_secs(60)).is_critical());
        assert!(!LimitExceeded::Executions(100).is_critical());
    }

    #[test]
    fn usage_summary_percentages() {
        let summary = UsageSummary {
            elapsed: Duration::from_secs(30),
            max_time: Some(Duration::from_secs(60)),
            memory_used: Some(256 * 1024 * 1024),
            max_memory: Some(512 * 1024 * 1024),
            executions: 500,
            max_executions: Some(1000),
            corpus_size: 250,
            max_corpus_size: Some(1000),
            restarts: 2,
            max_restarts: Some(10),
        };

        assert!((summary.time_usage().unwrap() - 0.5).abs() < 0.01);
        assert!((summary.memory_usage().unwrap() - 0.5).abs() < 0.01);
        assert!((summary.execution_usage().unwrap() - 0.5).abs() < 0.01);
        assert!((summary.corpus_usage().unwrap() - 0.25).abs() < 0.01);
    }

    // Builder method tests
    #[test]
    fn builder_with_max_time() {
        let limits = ResourceLimits::unlimited().with_max_time(Duration::from_secs(120));
        assert_eq!(limits.max_time, Some(Duration::from_secs(120)));
    }

    #[test]
    fn builder_with_max_memory() {
        let limits = ResourceLimits::unlimited().with_max_memory(256 * 1024 * 1024);
        assert_eq!(limits.max_memory, Some(256 * 1024 * 1024));
    }

    #[test]
    fn builder_with_max_executions() {
        let limits = ResourceLimits::unlimited().with_max_executions(5000);
        assert_eq!(limits.max_executions, Some(5000));
    }

    #[test]
    fn builder_with_max_corpus_size() {
        let limits = ResourceLimits::unlimited().with_max_corpus_size(2000);
        assert_eq!(limits.max_corpus_size, Some(2000));
    }

    #[test]
    fn builder_with_max_restarts() {
        let limits = ResourceLimits::unlimited().with_max_restarts(15);
        assert_eq!(limits.max_restarts, Some(15));
    }

    #[test]
    fn builder_chaining() {
        let limits = ResourceLimits::unlimited()
            .with_max_time(Duration::from_secs(60))
            .with_max_memory(128 * 1024 * 1024)
            .with_max_executions(1000);

        assert_eq!(limits.max_time, Some(Duration::from_secs(60)));
        assert_eq!(limits.max_memory, Some(128 * 1024 * 1024));
        assert_eq!(limits.max_executions, Some(1000));
    }

    // has_limits() with partial limits
    #[test]
    fn has_limits_with_only_time() {
        let limits = ResourceLimits::unlimited().with_max_time(Duration::from_secs(60));
        assert!(limits.has_limits());
    }

    #[test]
    fn has_limits_with_only_memory() {
        let limits = ResourceLimits::unlimited().with_max_memory(512 * 1024 * 1024);
        assert!(limits.has_limits());
    }

    #[test]
    fn has_limits_with_only_executions() {
        let limits = ResourceLimits::unlimited().with_max_executions(1000);
        assert!(limits.has_limits());
    }

    #[test]
    fn has_limits_with_only_corpus_size() {
        let limits = ResourceLimits::unlimited().with_max_corpus_size(5000);
        assert!(limits.has_limits());
    }

    #[test]
    fn has_limits_with_only_restarts() {
        let limits = ResourceLimits::unlimited().with_max_restarts(3);
        assert!(limits.has_limits());
    }

    // parse_duration tests
    #[test]
    fn parse_duration_days() {
        assert_eq!(
            ResourceLimits::parse_duration("1d").unwrap(),
            Duration::from_secs(24 * 60 * 60)
        );
        assert_eq!(
            ResourceLimits::parse_duration("2d").unwrap(),
            Duration::from_secs(2 * 24 * 60 * 60)
        );
    }

    #[test]
    fn parse_duration_with_whitespace() {
        assert_eq!(
            ResourceLimits::parse_duration("  30s  ").unwrap(),
            Duration::from_secs(30)
        );
        assert_eq!(
            ResourceLimits::parse_duration("\t5m\n").unwrap(),
            Duration::from_secs(300)
        );
    }

    #[test]
    fn parse_duration_empty_string() {
        let result = ResourceLimits::parse_duration("");
        assert!(matches!(result, Err(ParseError::Empty)));
    }

    #[test]
    fn parse_duration_whitespace_only() {
        let result = ResourceLimits::parse_duration("   ");
        assert!(matches!(result, Err(ParseError::Empty)));
    }

    #[test]
    fn parse_duration_invalid_number() {
        let result = ResourceLimits::parse_duration("abc");
        assert!(matches!(result, Err(ParseError::InvalidNumber(_))));
    }

    #[test]
    fn parse_duration_invalid_suffix() {
        let result = ResourceLimits::parse_duration("10x");
        assert!(matches!(result, Err(ParseError::InvalidNumber(_))));
    }

    // parse_bytes tests
    #[test]
    fn parse_bytes_raw_bytes() {
        assert_eq!(ResourceLimits::parse_bytes("1024").unwrap(), 1024);
        assert_eq!(ResourceLimits::parse_bytes("100B").unwrap(), 100);
    }

    #[test]
    fn parse_bytes_lowercase() {
        assert_eq!(
            ResourceLimits::parse_bytes("512mb").unwrap(),
            512 * 1024 * 1024
        );
        assert_eq!(
            ResourceLimits::parse_bytes("1gb").unwrap(),
            1024 * 1024 * 1024
        );
        assert_eq!(ResourceLimits::parse_bytes("100kb").unwrap(), 100 * 1024);
    }

    #[test]
    fn parse_bytes_with_whitespace() {
        assert_eq!(
            ResourceLimits::parse_bytes("  512MB  ").unwrap(),
            512 * 1024 * 1024
        );
    }

    #[test]
    fn parse_bytes_empty_string() {
        let result = ResourceLimits::parse_bytes("");
        assert!(matches!(result, Err(ParseError::Empty)));
    }

    #[test]
    fn parse_bytes_invalid_number() {
        let result = ResourceLimits::parse_bytes("abcMB");
        assert!(matches!(result, Err(ParseError::InvalidNumber(_))));
    }

    // ParseError Display tests
    #[test]
    fn parse_error_empty_display() {
        let err = ParseError::Empty;
        assert_eq!(err.to_string(), "empty value");
    }

    #[test]
    fn parse_error_invalid_number_display() {
        let err = ParseError::InvalidNumber("abc".to_string());
        assert_eq!(err.to_string(), "invalid number: 'abc'");
    }

    #[test]
    fn parse_error_unknown_unit_display() {
        let err = ParseError::UnknownUnit("xyz".to_string());
        assert_eq!(err.to_string(), "unknown unit: 'xyz'");
    }

    // ResourceMonitor tests
    #[test]
    fn monitor_reset_timer() {
        let limits = ResourceLimits::default().with_max_time(Duration::from_secs(60));
        let mut monitor = ResourceMonitor::new(limits);

        std::thread::sleep(Duration::from_millis(10));
        let elapsed1 = monitor.elapsed();

        monitor.reset_timer();
        let elapsed2 = monitor.elapsed();

        assert!(elapsed2 < elapsed1);
    }

    #[test]
    fn monitor_elapsed() {
        let limits = ResourceLimits::default();
        let monitor = ResourceMonitor::new(limits);

        std::thread::sleep(Duration::from_millis(10));
        let elapsed = monitor.elapsed();

        assert!(elapsed >= Duration::from_millis(10));
    }

    #[test]
    fn monitor_check_no_limits_exceeded() {
        let limits = ResourceLimits::default()
            .with_max_time(Duration::from_secs(60))
            .with_max_executions(1000);
        let monitor = ResourceMonitor::new(limits);

        let stats = FuzzStats {
            executions: 50,
            corpus_size: 100,
            restarts: 1,
        };

        assert!(monitor.check(&stats).is_none());
    }

    #[test]
    fn monitor_check_specific_time() {
        let limits = ResourceLimits::default().with_max_time(Duration::from_millis(1));
        let monitor = ResourceMonitor::new(limits);

        std::thread::sleep(Duration::from_millis(10));

        let stats = FuzzStats::default();
        assert!(monitor.check_specific(&stats, LimitType::Time));
    }

    #[test]
    fn monitor_check_specific_executions() {
        let limits = ResourceLimits::default().with_max_executions(100);
        let monitor = ResourceMonitor::new(limits);

        let stats = FuzzStats {
            executions: 100,
            corpus_size: 0,
            restarts: 0,
        };

        assert!(monitor.check_specific(&stats, LimitType::Executions));
    }

    #[test]
    fn monitor_check_specific_corpus_size() {
        let limits = ResourceLimits::default().with_max_corpus_size(500);
        let monitor = ResourceMonitor::new(limits);

        let stats = FuzzStats {
            executions: 0,
            corpus_size: 500,
            restarts: 0,
        };

        assert!(monitor.check_specific(&stats, LimitType::CorpusSize));
    }

    #[test]
    fn monitor_check_specific_restarts() {
        let limits = ResourceLimits::default().with_max_restarts(5);
        let monitor = ResourceMonitor::new(limits);

        let stats = FuzzStats {
            executions: 0,
            corpus_size: 0,
            restarts: 5,
        };

        assert!(monitor.check_specific(&stats, LimitType::Restarts));
    }

    #[test]
    fn monitor_check_specific_no_limit_set() {
        let limits = ResourceLimits::unlimited();
        let monitor = ResourceMonitor::new(limits);

        let stats = FuzzStats {
            executions: 10000,
            corpus_size: 10000,
            restarts: 100,
        };

        assert!(!monitor.check_specific(&stats, LimitType::Time));
        assert!(!monitor.check_specific(&stats, LimitType::Executions));
        assert!(!monitor.check_specific(&stats, LimitType::CorpusSize));
        assert!(!monitor.check_specific(&stats, LimitType::Restarts));
    }

    #[test]
    fn monitor_remaining_time_expired() {
        let limits = ResourceLimits::default().with_max_time(Duration::from_millis(1));
        let monitor = ResourceMonitor::new(limits);

        std::thread::sleep(Duration::from_millis(10));

        let remaining = monitor.remaining_time();
        assert_eq!(remaining, Some(Duration::ZERO));
    }

    #[test]
    fn monitor_remaining_time_no_limit() {
        let limits = ResourceLimits::unlimited();
        let monitor = ResourceMonitor::new(limits);

        let remaining = monitor.remaining_time();
        assert!(remaining.is_none());
    }

    #[test]
    fn monitor_limits_accessor() {
        let limits = ResourceLimits::default().with_max_executions(500);
        let monitor = ResourceMonitor::new(limits.clone());

        assert_eq!(monitor.limits().max_executions, Some(500));
        assert_eq!(monitor.limits().max_time, limits.max_time);
    }

    #[test]
    fn monitor_usage_summary() {
        let limits = ResourceLimits::default()
            .with_max_time(Duration::from_secs(60))
            .with_max_executions(1000);
        let monitor = ResourceMonitor::new(limits);

        let stats = FuzzStats {
            executions: 500,
            corpus_size: 200,
            restarts: 2,
        };

        let summary = monitor.usage_summary(&stats).unwrap();
        assert_eq!(summary.executions, 500);
        assert_eq!(summary.max_executions, Some(1000));
        assert_eq!(summary.corpus_size, 200);
        assert_eq!(summary.restarts, 2);
    }

    // LimitType tests
    #[test]
    fn limit_type_equality() {
        assert_eq!(LimitType::Time, LimitType::Time);
        assert_ne!(LimitType::Time, LimitType::Memory);
    }

    // LimitExceeded tests
    #[test]
    fn limit_exceeded_limit_type_time() {
        let exceeded = LimitExceeded::Time(Duration::from_secs(60));
        assert_eq!(exceeded.limit_type(), LimitType::Time);
    }

    #[test]
    fn limit_exceeded_limit_type_memory() {
        let exceeded = LimitExceeded::Memory(512 * 1024 * 1024);
        assert_eq!(exceeded.limit_type(), LimitType::Memory);
    }

    #[test]
    fn limit_exceeded_limit_type_executions() {
        let exceeded = LimitExceeded::Executions(1000);
        assert_eq!(exceeded.limit_type(), LimitType::Executions);
    }

    #[test]
    fn limit_exceeded_limit_type_corpus_size() {
        let exceeded = LimitExceeded::CorpusSize(5000);
        assert_eq!(exceeded.limit_type(), LimitType::CorpusSize);
    }

    #[test]
    fn limit_exceeded_limit_type_restarts() {
        let exceeded = LimitExceeded::Restarts(10);
        assert_eq!(exceeded.limit_type(), LimitType::Restarts);
    }

    // LimitExceeded Display tests
    #[test]
    fn limit_exceeded_display_time() {
        let exceeded = LimitExceeded::Time(Duration::from_secs(60));
        let display = format!("{}", exceeded);
        assert!(display.contains("Time limit exceeded"));
    }

    #[test]
    fn limit_exceeded_display_memory() {
        let exceeded = LimitExceeded::Memory(512 * 1024 * 1024);
        let display = format!("{}", exceeded);
        assert!(display.contains("Memory limit exceeded"));
        assert!(display.contains("bytes"));
    }

    #[test]
    fn limit_exceeded_display_executions() {
        let exceeded = LimitExceeded::Executions(1000);
        let display = format!("{}", exceeded);
        assert!(display.contains("Execution limit exceeded"));
        assert!(display.contains("iterations"));
    }

    #[test]
    fn limit_exceeded_display_corpus_size() {
        let exceeded = LimitExceeded::CorpusSize(5000);
        let display = format!("{}", exceeded);
        assert!(display.contains("Corpus size limit exceeded"));
        assert!(display.contains("entries"));
    }

    #[test]
    fn limit_exceeded_display_restarts() {
        let exceeded = LimitExceeded::Restarts(10);
        let display = format!("{}", exceeded);
        assert!(display.contains("Restart limit exceeded"));
        assert!(display.contains("restarts"));
    }

    // UsageSummary percentage methods with None values
    #[test]
    fn usage_summary_time_usage_no_limit() {
        let summary = UsageSummary {
            elapsed: Duration::from_secs(30),
            max_time: None,
            memory_used: None,
            max_memory: None,
            executions: 500,
            max_executions: None,
            corpus_size: 250,
            max_corpus_size: None,
            restarts: 2,
            max_restarts: None,
        };

        assert!(summary.time_usage().is_none());
    }

    #[test]
    fn usage_summary_memory_usage_no_limit() {
        let summary = UsageSummary {
            elapsed: Duration::from_secs(30),
            max_time: None,
            memory_used: Some(256 * 1024 * 1024),
            max_memory: None,
            executions: 500,
            max_executions: None,
            corpus_size: 250,
            max_corpus_size: None,
            restarts: 2,
            max_restarts: None,
        };

        assert!(summary.memory_usage().is_none());
    }

    #[test]
    fn usage_summary_memory_usage_no_measurement() {
        let summary = UsageSummary {
            elapsed: Duration::from_secs(30),
            max_time: None,
            memory_used: None,
            max_memory: Some(512 * 1024 * 1024),
            executions: 500,
            max_executions: None,
            corpus_size: 250,
            max_corpus_size: None,
            restarts: 2,
            max_restarts: None,
        };

        assert!(summary.memory_usage().is_none());
    }

    #[test]
    fn usage_summary_execution_usage_no_limit() {
        let summary = UsageSummary {
            elapsed: Duration::from_secs(30),
            max_time: None,
            memory_used: None,
            max_memory: None,
            executions: 500,
            max_executions: None,
            corpus_size: 250,
            max_corpus_size: None,
            restarts: 2,
            max_restarts: None,
        };

        assert!(summary.execution_usage().is_none());
    }

    #[test]
    fn usage_summary_corpus_usage_no_limit() {
        let summary = UsageSummary {
            elapsed: Duration::from_secs(30),
            max_time: None,
            memory_used: None,
            max_memory: None,
            executions: 500,
            max_executions: None,
            corpus_size: 250,
            max_corpus_size: None,
            restarts: 2,
            max_restarts: None,
        };

        assert!(summary.corpus_usage().is_none());
    }

    // format_bytes edge cases
    #[test]
    fn format_bytes_exact_kb_boundary() {
        assert_eq!(format_bytes(1024), "1.0KB");
    }

    #[test]
    fn format_bytes_exact_mb_boundary() {
        assert_eq!(format_bytes(1024 * 1024), "1.0MB");
    }

    #[test]
    fn format_bytes_exact_gb_boundary() {
        assert_eq!(format_bytes(1024 * 1024 * 1024), "1.0GB");
    }

    #[test]
    fn format_bytes_zero() {
        assert_eq!(format_bytes(0), "0B");
    }

    #[test]
    fn format_bytes_fractional_kb() {
        assert_eq!(format_bytes(1536), "1.5KB");
    }

    #[test]
    fn format_bytes_fractional_mb() {
        assert_eq!(format_bytes(1536 * 1024), "1.5MB");
    }

    // format_duration edge cases
    #[test]
    fn format_duration_zero() {
        assert_eq!(format_duration(Duration::from_secs(0)), "0s");
    }

    #[test]
    fn format_duration_exact_minute() {
        assert_eq!(format_duration(Duration::from_secs(60)), "1m0s");
    }

    #[test]
    fn format_duration_exact_hour() {
        assert_eq!(format_duration(Duration::from_secs(3600)), "1h0m");
    }

    #[test]
    fn format_duration_multiple_hours() {
        assert_eq!(format_duration(Duration::from_secs(7200)), "2h0m");
    }

    #[test]
    fn format_duration_hours_and_minutes() {
        assert_eq!(format_duration(Duration::from_secs(3720)), "1h2m");
    }

    // FuzzerError tests
    #[test]
    fn fuzzer_error_display_formats() {
        let config_err = FuzzerError::ConfigError(ParseError::Empty);
        assert_eq!(format!("{}", config_err), "Configuration error: empty value");

        let mem_err = FuzzerError::MemoryMonitoringFailed("test".to_string());
        assert_eq!(format!("{}", mem_err), "Memory monitoring failed: test");

        let time_err = FuzzerError::TimeLimitExceeded("300s".to_string());
        assert_eq!(format!("{}", time_err), "Time limit exceeded: 300s");

        let memory_limit_err = FuzzerError::MemoryLimitExceeded(512 * 1024 * 1024);
        assert_eq!(format!("{}", memory_limit_err), "Memory limit exceeded: 536870912 bytes");
    }

    #[test]
    fn fuzzer_error_from_traits() {
        let parse_err = ParseError::InvalidNumber("abc".to_string());
        let fuzzer_err: FuzzerError = parse_err.into();
        
        match fuzzer_err {
            FuzzerError::ConfigError(ParseError::InvalidNumber(s)) => {
                assert_eq!(s, "abc");
            }
            _ => panic!("Expected ConfigError with InvalidNumber"),
        }
    }

    #[test]
    fn fuzzer_error_io_error_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let fuzzer_err: FuzzerError = io_err.into();
        
        match fuzzer_err {
            FuzzerError::IoError(e) => {
                assert_eq!(e.kind(), std::io::ErrorKind::NotFound);
            }
            _ => panic!("Expected IoError"),
        }
    }

    #[test]
    fn memory_monitoring_error_handling() {
        // Test that memory monitoring returns proper errors on unsupported platforms
        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        {
            let monitor = ResourceMonitor::new(ResourceLimits::unlimited());
            let result = monitor.get_process_memory();
            
            match result {
                Err(FuzzerError::PlatformNotSupported) => {},
                _ => panic!("Expected PlatformNotSupported error"),
            }
        }
    }

    #[test]
    fn usage_summary_error_handling() {
        let monitor = ResourceMonitor::new(ResourceLimits::unlimited());
        let stats = FuzzStats::default();
        
        // This should work on supported platforms, fail gracefully on unsupported
        let result = monitor.usage_summary(&stats);
        
        // On supported platforms, it should succeed (memory_used will be None if monitoring fails)
        // On unsupported platforms, it should return PlatformNotSupported
        match result {
            Ok(summary) => {
                // Summary created successfully
                assert_eq!(summary.executions, 0);
            },
            Err(FuzzerError::PlatformNotSupported) => {
                // Expected on unsupported platforms
            },
            Err(e) => panic!("Unexpected error: {}", e),
        }
    }
}
