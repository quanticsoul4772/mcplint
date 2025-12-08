//! Fuzzer Configuration - Settings and profiles for fuzzing sessions
//!
//! Provides configuration options for controlling fuzzing behavior,
//! including duration, workers, mutation strategies, and profiles.

use std::path::PathBuf;

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
}
