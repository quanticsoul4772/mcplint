//! CLI Configuration Structs
//!
//! Provides configuration structs to reduce argument count in command functions.
//! This addresses the clippy::too_many_arguments warnings and improves maintainability.
//!
//! These structs are designed for future refactoring of command handlers.

#![allow(dead_code)] // Public API for future command refactoring

use std::path::PathBuf;

use crate::cli::commands::explain::CliAiProvider;
use crate::scanner::Severity;
use crate::ScanProfile as CliScanProfile;

/// Configuration for scan command execution
#[derive(Debug, Clone)]
pub struct ScanRunConfig {
    /// Server to scan
    pub server: String,
    /// Arguments to pass to the server
    pub args: Vec<String>,
    /// Scan profile
    pub profile: CliScanProfile,
    /// Categories to include
    pub include: Option<Vec<String>>,
    /// Categories to exclude
    pub exclude: Option<Vec<String>>,
    /// Timeout in seconds
    pub timeout: u64,
}

impl ScanRunConfig {
    pub fn new(server: impl Into<String>, profile: CliScanProfile) -> Self {
        Self {
            server: server.into(),
            args: Vec::new(),
            profile,
            include: None,
            exclude: None,
            timeout: 60,
        }
    }

    pub fn with_args(mut self, args: Vec<String>) -> Self {
        self.args = args;
        self
    }

    pub fn with_timeout(mut self, timeout: u64) -> Self {
        self.timeout = timeout;
        self
    }
}

/// Configuration for baseline comparison
#[derive(Debug, Clone, Default)]
pub struct BaselineConfig {
    /// Path to baseline file for comparison
    pub baseline_path: Option<PathBuf>,
    /// Save scan results as new baseline
    pub save_baseline: Option<PathBuf>,
    /// Update existing baseline with current findings
    pub update_baseline: bool,
    /// Show only diff summary
    pub diff_only: bool,
    /// Fail only on specified severities
    pub fail_on: Option<Vec<Severity>>,
}

impl BaselineConfig {
    pub fn with_baseline(mut self, path: PathBuf) -> Self {
        self.baseline_path = Some(path);
        self
    }

    pub fn with_save_baseline(mut self, path: PathBuf) -> Self {
        self.save_baseline = Some(path);
        self
    }

    pub fn with_update(mut self, update: bool) -> Self {
        self.update_baseline = update;
        self
    }

    pub fn with_diff_only(mut self, diff_only: bool) -> Self {
        self.diff_only = diff_only;
        self
    }

    pub fn with_fail_on(mut self, severities: Vec<Severity>) -> Self {
        self.fail_on = Some(severities);
        self
    }
}

/// Configuration for AI-powered explanations
#[derive(Debug, Clone)]
pub struct AiExplainConfig {
    /// Whether to generate AI explanations
    pub enabled: bool,
    /// AI provider
    pub provider: CliAiProvider,
    /// AI model override
    pub model: Option<String>,
}

impl Default for AiExplainConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            provider: CliAiProvider::Ollama,
            model: None,
        }
    }
}

impl AiExplainConfig {
    pub fn enabled(provider: CliAiProvider) -> Self {
        Self {
            enabled: true,
            provider,
            model: None,
        }
    }

    pub fn with_model(mut self, model: impl Into<String>) -> Self {
        self.model = Some(model.into());
        self
    }

    pub fn disabled() -> Self {
        Self::default()
    }
}

/// Combined configuration for the scan command
#[derive(Debug, Clone)]
pub struct ScanCommandConfig {
    pub run: ScanRunConfig,
    pub baseline: BaselineConfig,
    pub ai: AiExplainConfig,
}

impl ScanCommandConfig {
    pub fn new(run: ScanRunConfig) -> Self {
        Self {
            run,
            baseline: BaselineConfig::default(),
            ai: AiExplainConfig::default(),
        }
    }

    pub fn with_baseline(mut self, baseline: BaselineConfig) -> Self {
        self.baseline = baseline;
        self
    }

    pub fn with_ai(mut self, ai: AiExplainConfig) -> Self {
        self.ai = ai;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_run_config_builder() {
        let config = ScanRunConfig::new("test-server", CliScanProfile::Standard)
            .with_args(vec!["arg1".to_string()])
            .with_timeout(30);

        assert_eq!(config.server, "test-server");
        assert_eq!(config.timeout, 30);
    }

    #[test]
    fn baseline_config_builder() {
        let config = BaselineConfig::default()
            .with_baseline(PathBuf::from("baseline.json"))
            .with_diff_only(true);

        assert!(config.baseline_path.is_some());
        assert!(config.diff_only);
    }

    #[test]
    fn ai_config_enabled() {
        let config = AiExplainConfig::enabled(CliAiProvider::Anthropic)
            .with_model("claude-3-opus");

        assert!(config.enabled);
        assert!(config.model.is_some());
    }
}
