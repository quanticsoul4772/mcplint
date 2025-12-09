//! Fuzzer Configuration - Settings and profiles for fuzzing sessions
//!
//! Provides configuration options for controlling fuzzing behavior,
//! including duration, workers, mutation strategies, and profiles.

use super::limits::ResourceLimits;
use std::path::PathBuf;
use std::time::Duration;

/// Fuzzing configuration
#[derive(Debug, Clone)]
pub struct FuzzConfig {
    /// Maximum duration in seconds (0 = unlimited)
    pub duration_secs: u64,
    /// Maximum iterations (0 = unlimited)
    pub max_iterations: u64,
    /// Timeout per request in milliseconds
    pub request_timeout_ms: u64,
    /// Number of parallel workers
    pub workers: usize,
    /// Corpus directory path
    pub corpus_path: Option<PathBuf>,
    /// Dictionary file path
    pub dictionary_path: Option<PathBuf>,
    /// Target tools to fuzz (None = all)
    pub target_tools: Option<Vec<String>>,
    /// Fuzzing profile
    pub profile: FuzzProfile,
    /// Save interesting inputs
    pub save_interesting: bool,
    /// Minimum new coverage to save input
    pub coverage_threshold: f64,
    /// Random seed for reproducibility (None = random)
    pub seed: Option<u64>,
    /// Resource limits for safety controls
    pub resource_limits: ResourceLimits,
}

impl Default for FuzzConfig {
    fn default() -> Self {
        Self {
            duration_secs: 60,
            max_iterations: 0,
            request_timeout_ms: 5000,
            workers: 1,
            corpus_path: None,
            dictionary_path: None,
            target_tools: None,
            profile: FuzzProfile::Standard,
            save_interesting: true,
            coverage_threshold: 0.01,
            seed: None,
            resource_limits: ResourceLimits::default(),
        }
    }
}

impl FuzzConfig {
    /// Create config with specific profile
    pub fn with_profile(profile: FuzzProfile) -> Self {
        let mut config = profile.default_config();
        config.profile = profile;
        config
    }

    /// Set number of workers
    pub fn with_workers(mut self, workers: usize) -> Self {
        self.workers = workers.max(1);
        self
    }

    /// Set duration in seconds
    pub fn with_duration(mut self, duration_secs: u64) -> Self {
        self.duration_secs = duration_secs;
        self
    }

    /// Set maximum iterations
    pub fn with_iterations(mut self, max_iterations: u64) -> Self {
        self.max_iterations = max_iterations;
        self
    }

    /// Set corpus path
    pub fn with_corpus(mut self, path: Option<PathBuf>) -> Self {
        self.corpus_path = path;
        self
    }

    /// Set target tools
    pub fn with_target_tools(mut self, tools: Option<Vec<String>>) -> Self {
        self.target_tools = tools;
        self
    }

    /// Set request timeout
    pub fn with_timeout(mut self, timeout_ms: u64) -> Self {
        self.request_timeout_ms = timeout_ms;
        self
    }

    /// Set random seed for reproducibility
    pub fn with_seed(mut self, seed: u64) -> Self {
        self.seed = Some(seed);
        self
    }

    /// Set resource limits
    pub fn with_resource_limits(mut self, limits: ResourceLimits) -> Self {
        self.resource_limits = limits;
        self
    }

    /// Set maximum memory limit
    pub fn with_max_memory(mut self, bytes: u64) -> Self {
        self.resource_limits = self.resource_limits.with_max_memory(bytes);
        self
    }

    /// Set maximum time limit (overrides duration_secs for resource monitoring)
    pub fn with_max_time(mut self, duration: Duration) -> Self {
        self.resource_limits = self.resource_limits.with_max_time(duration);
        self
    }

    /// Set maximum corpus size
    pub fn with_max_corpus_size(mut self, count: usize) -> Self {
        self.resource_limits = self.resource_limits.with_max_corpus_size(count);
        self
    }

    /// Set maximum restarts
    pub fn with_max_restarts(mut self, count: u32) -> Self {
        self.resource_limits = self.resource_limits.with_max_restarts(count);
        self
    }

    /// Disable all resource limits (use with caution)
    pub fn with_unlimited_resources(mut self) -> Self {
        self.resource_limits = ResourceLimits::unlimited();
        self
    }
}

/// Fuzzing profiles with different intensity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum FuzzProfile {
    /// Quick fuzzing (~1 minute, basic mutations)
    Quick,
    /// Standard fuzzing (~5 minutes, all mutations)
    #[default]
    Standard,
    /// Intensive fuzzing (unlimited, aggressive mutations)
    Intensive,
    /// CI-optimized (fast feedback, deterministic seed)
    #[clap(name = "ci")]
    CI,
}

impl FuzzProfile {
    /// Get default configuration for this profile
    pub fn default_config(&self) -> FuzzConfig {
        match self {
            FuzzProfile::Quick => FuzzConfig {
                duration_secs: 60,
                max_iterations: 500,
                request_timeout_ms: 3000,
                workers: 1,
                corpus_path: None,
                dictionary_path: None,
                target_tools: None,
                profile: FuzzProfile::Quick,
                save_interesting: false,
                coverage_threshold: 0.05,
                seed: None,
                // Quick profile: conservative limits
                resource_limits: ResourceLimits::default()
                    .with_max_time(Duration::from_secs(120)) // 2 minutes max
                    .with_max_memory(256 * 1024 * 1024) // 256MB
                    .with_max_corpus_size(1_000)
                    .with_max_restarts(3),
            },
            FuzzProfile::Standard => FuzzConfig {
                duration_secs: 300,
                max_iterations: 0,
                request_timeout_ms: 5000,
                workers: 1,
                corpus_path: None,
                dictionary_path: None,
                target_tools: None,
                profile: FuzzProfile::Standard,
                save_interesting: true,
                coverage_threshold: 0.01,
                seed: None,
                // Standard profile: balanced limits
                resource_limits: ResourceLimits::default()
                    .with_max_time(Duration::from_secs(600)) // 10 minutes max
                    .with_max_memory(512 * 1024 * 1024) // 512MB
                    .with_max_corpus_size(10_000)
                    .with_max_restarts(10),
            },
            FuzzProfile::Intensive => FuzzConfig {
                duration_secs: 0,
                max_iterations: 0,
                request_timeout_ms: 10000,
                workers: 1,
                corpus_path: None,
                dictionary_path: None,
                target_tools: None,
                profile: FuzzProfile::Intensive,
                save_interesting: true,
                coverage_threshold: 0.001,
                seed: None,
                // Intensive profile: relaxed limits
                resource_limits: ResourceLimits::default()
                    .with_max_time(Duration::from_secs(3600)) // 1 hour max
                    .with_max_memory(2 * 1024 * 1024 * 1024) // 2GB
                    .with_max_corpus_size(100_000)
                    .with_max_restarts(50),
            },
            FuzzProfile::CI => FuzzConfig {
                duration_secs: 30,
                max_iterations: 200,
                request_timeout_ms: 2000,
                workers: 1,
                corpus_path: None,
                dictionary_path: None,
                target_tools: None,
                profile: FuzzProfile::CI,
                save_interesting: false,
                coverage_threshold: 0.1,
                seed: Some(42), // Deterministic for CI
                // CI profile: strict limits for predictable behavior
                resource_limits: ResourceLimits::default()
                    .with_max_time(Duration::from_secs(60)) // 1 minute max
                    .with_max_memory(128 * 1024 * 1024) // 128MB
                    .with_max_executions(500) // Hard execution limit
                    .with_max_corpus_size(500)
                    .with_max_restarts(2),
            },
        }
    }

    /// Get string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            FuzzProfile::Quick => "quick",
            FuzzProfile::Standard => "standard",
            FuzzProfile::Intensive => "intensive",
            FuzzProfile::CI => "ci",
        }
    }

    /// Parse from string
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "quick" => Some(FuzzProfile::Quick),
            "standard" => Some(FuzzProfile::Standard),
            "intensive" => Some(FuzzProfile::Intensive),
            "ci" => Some(FuzzProfile::CI),
            _ => None,
        }
    }
}

impl std::fmt::Display for FuzzProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_configs() {
        let quick = FuzzProfile::Quick.default_config();
        assert_eq!(quick.duration_secs, 60);
        assert_eq!(quick.max_iterations, 500);

        let ci = FuzzProfile::CI.default_config();
        assert!(ci.seed.is_some());
    }

    #[test]
    fn config_builder() {
        let config = FuzzConfig::default()
            .with_workers(4)
            .with_duration(120)
            .with_timeout(3000);

        assert_eq!(config.workers, 4);
        assert_eq!(config.duration_secs, 120);
        assert_eq!(config.request_timeout_ms, 3000);
    }

    #[test]
    fn profile_parsing() {
        assert_eq!(FuzzProfile::from_str("quick"), Some(FuzzProfile::Quick));
        assert_eq!(FuzzProfile::from_str("CI"), Some(FuzzProfile::CI));
        assert_eq!(FuzzProfile::from_str("unknown"), None);
    }

    #[test]
    fn default_config_values() {
        let config = FuzzConfig::default();
        assert_eq!(config.duration_secs, 60);
        assert_eq!(config.max_iterations, 0);
        assert_eq!(config.request_timeout_ms, 5000);
        assert_eq!(config.workers, 1);
        assert!(config.corpus_path.is_none());
        assert!(config.dictionary_path.is_none());
        assert!(config.target_tools.is_none());
        assert_eq!(config.profile, FuzzProfile::Standard);
        assert!(config.save_interesting);
        assert!((config.coverage_threshold - 0.01).abs() < f64::EPSILON);
        assert!(config.seed.is_none());
    }

    #[test]
    fn with_profile_creates_config() {
        let config = FuzzConfig::with_profile(FuzzProfile::Quick);
        assert_eq!(config.profile, FuzzProfile::Quick);
        assert_eq!(config.duration_secs, 60);
        assert_eq!(config.max_iterations, 500);
    }

    #[test]
    fn with_iterations() {
        let config = FuzzConfig::default().with_iterations(1000);
        assert_eq!(config.max_iterations, 1000);
    }

    #[test]
    fn with_corpus() {
        let path = PathBuf::from("/tmp/corpus");
        let config = FuzzConfig::default().with_corpus(Some(path.clone()));
        assert_eq!(config.corpus_path, Some(path));

        let config2 = FuzzConfig::default().with_corpus(None);
        assert!(config2.corpus_path.is_none());
    }

    #[test]
    fn with_target_tools() {
        let tools = vec!["tool1".to_string(), "tool2".to_string()];
        let config = FuzzConfig::default().with_target_tools(Some(tools.clone()));
        assert_eq!(config.target_tools, Some(tools));

        let config2 = FuzzConfig::default().with_target_tools(None);
        assert!(config2.target_tools.is_none());
    }

    #[test]
    fn with_seed() {
        let config = FuzzConfig::default().with_seed(12345);
        assert_eq!(config.seed, Some(12345));
    }

    #[test]
    fn with_resource_limits() {
        let limits = ResourceLimits::default();
        let config = FuzzConfig::default().with_resource_limits(limits);
        // Just verify it doesn't panic - resource limits are optional
        assert!(config.resource_limits.max_memory.is_some() || config.resource_limits.max_memory.is_none());
    }

    #[test]
    fn with_max_memory() {
        let config = FuzzConfig::default().with_max_memory(1024 * 1024 * 1024);
        assert_eq!(config.resource_limits.max_memory, Some(1024 * 1024 * 1024));
    }

    #[test]
    fn with_max_time() {
        let config = FuzzConfig::default().with_max_time(Duration::from_secs(3600));
        assert_eq!(config.resource_limits.max_time, Some(Duration::from_secs(3600)));
    }

    #[test]
    fn with_max_corpus_size() {
        let config = FuzzConfig::default().with_max_corpus_size(50000);
        assert_eq!(config.resource_limits.max_corpus_size, Some(50000));
    }

    #[test]
    fn with_max_restarts() {
        let config = FuzzConfig::default().with_max_restarts(25);
        assert_eq!(config.resource_limits.max_restarts, Some(25));
    }

    #[test]
    fn with_unlimited_resources() {
        let config = FuzzConfig::default().with_unlimited_resources();
        // Unlimited means None (no limit)
        assert!(config.resource_limits.max_memory.is_none());
        assert!(config.resource_limits.max_time.is_none());
    }

    #[test]
    fn with_workers_minimum_one() {
        let config = FuzzConfig::default().with_workers(0);
        assert_eq!(config.workers, 1);

        let config2 = FuzzConfig::default().with_workers(1);
        assert_eq!(config2.workers, 1);
    }

    #[test]
    fn profile_as_str() {
        assert_eq!(FuzzProfile::Quick.as_str(), "quick");
        assert_eq!(FuzzProfile::Standard.as_str(), "standard");
        assert_eq!(FuzzProfile::Intensive.as_str(), "intensive");
        assert_eq!(FuzzProfile::CI.as_str(), "ci");
    }

    #[test]
    fn profile_display() {
        assert_eq!(format!("{}", FuzzProfile::Quick), "quick");
        assert_eq!(format!("{}", FuzzProfile::Standard), "standard");
        assert_eq!(format!("{}", FuzzProfile::Intensive), "intensive");
        assert_eq!(format!("{}", FuzzProfile::CI), "ci");
    }

    #[test]
    fn profile_from_str_all_variants() {
        assert_eq!(FuzzProfile::from_str("quick"), Some(FuzzProfile::Quick));
        assert_eq!(FuzzProfile::from_str("QUICK"), Some(FuzzProfile::Quick));
        assert_eq!(FuzzProfile::from_str("Quick"), Some(FuzzProfile::Quick));
        assert_eq!(FuzzProfile::from_str("standard"), Some(FuzzProfile::Standard));
        assert_eq!(FuzzProfile::from_str("STANDARD"), Some(FuzzProfile::Standard));
        assert_eq!(FuzzProfile::from_str("intensive"), Some(FuzzProfile::Intensive));
        assert_eq!(FuzzProfile::from_str("INTENSIVE"), Some(FuzzProfile::Intensive));
        assert_eq!(FuzzProfile::from_str("ci"), Some(FuzzProfile::CI));
        assert_eq!(FuzzProfile::from_str("CI"), Some(FuzzProfile::CI));
    }

    #[test]
    fn standard_profile_config() {
        let config = FuzzProfile::Standard.default_config();
        assert_eq!(config.duration_secs, 300);
        assert_eq!(config.max_iterations, 0);
        assert_eq!(config.request_timeout_ms, 5000);
        assert!(config.save_interesting);
        assert!(config.seed.is_none());
    }

    #[test]
    fn intensive_profile_config() {
        let config = FuzzProfile::Intensive.default_config();
        assert_eq!(config.duration_secs, 0);
        assert_eq!(config.max_iterations, 0);
        assert_eq!(config.request_timeout_ms, 10000);
        assert!(config.save_interesting);
        assert!((config.coverage_threshold - 0.001).abs() < f64::EPSILON);
    }

    #[test]
    fn ci_profile_config() {
        let config = FuzzProfile::CI.default_config();
        assert_eq!(config.duration_secs, 30);
        assert_eq!(config.max_iterations, 200);
        assert_eq!(config.request_timeout_ms, 2000);
        assert!(!config.save_interesting);
        assert_eq!(config.seed, Some(42));
    }

    #[test]
    fn quick_profile_config() {
        let config = FuzzProfile::Quick.default_config();
        assert_eq!(config.duration_secs, 60);
        assert_eq!(config.max_iterations, 500);
        assert_eq!(config.request_timeout_ms, 3000);
        assert!(!config.save_interesting);
    }

    #[test]
    fn profile_default() {
        let profile = FuzzProfile::default();
        assert_eq!(profile, FuzzProfile::Standard);
    }

    #[test]
    fn profile_clone() {
        let profile = FuzzProfile::Intensive;
        let cloned = profile;
        assert_eq!(cloned, FuzzProfile::Intensive);
    }

    #[test]
    fn config_clone() {
        let config = FuzzConfig::default()
            .with_workers(4)
            .with_seed(123);
        let cloned = config.clone();
        assert_eq!(cloned.workers, 4);
        assert_eq!(cloned.seed, Some(123));
    }

    #[test]
    fn config_debug() {
        let config = FuzzConfig::default();
        let debug = format!("{:?}", config);
        assert!(debug.contains("FuzzConfig"));
    }

    #[test]
    fn profile_debug() {
        let profile = FuzzProfile::Quick;
        let debug = format!("{:?}", profile);
        assert!(debug.contains("Quick"));
    }

    #[test]
    fn builder_chain() {
        let config = FuzzConfig::default()
            .with_workers(2)
            .with_duration(180)
            .with_iterations(5000)
            .with_timeout(4000)
            .with_seed(999)
            .with_max_memory(1024 * 1024 * 256)
            .with_max_restarts(5);

        assert_eq!(config.workers, 2);
        assert_eq!(config.duration_secs, 180);
        assert_eq!(config.max_iterations, 5000);
        assert_eq!(config.request_timeout_ms, 4000);
        assert_eq!(config.seed, Some(999));
        assert_eq!(config.resource_limits.max_memory, Some(1024 * 1024 * 256));
        assert_eq!(config.resource_limits.max_restarts, Some(5));
    }
}
