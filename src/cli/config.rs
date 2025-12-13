//! CLI Configuration Structs
//!
//! Provides configuration structs to reduce argument count in command functions.
//! This addresses the clippy::too_many_arguments warnings and improves maintainability.

use std::path::PathBuf;

use crate::cli::commands::explain::CliAiProvider;
use crate::scanner::Severity;
use crate::cli::OutputFormat;
use crate::cli::ScanProfile as CliScanProfile;

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
    /// Path to MCP config file
    pub config_path: Option<PathBuf>,
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
            config_path: None,
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

    pub fn with_config_path(mut self, path: PathBuf) -> Self {
        self.config_path = Some(path);
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

/// Output configuration
#[derive(Debug, Clone)]
pub struct OutputConfig {
    /// Output format
    pub format: OutputFormat,
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            format: OutputFormat::Text,
        }
    }
}

impl OutputConfig {
    pub fn new(format: OutputFormat) -> Self {
        Self { format }
    }
}

/// Combined configuration for the scan command
#[derive(Debug, Clone)]
pub struct ScanCommandConfig {
    pub run: ScanRunConfig,
    pub baseline: BaselineConfig,
    pub ai: AiExplainConfig,
    pub output: OutputConfig,
}

impl ScanCommandConfig {
    pub fn new(run: ScanRunConfig) -> Self {
        Self {
            run,
            baseline: BaselineConfig::default(),
            ai: AiExplainConfig::default(),
            output: OutputConfig::default(),
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

    pub fn with_output(mut self, output: OutputConfig) -> Self {
        self.output = output;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ScanRunConfig tests
    #[test]
    fn scan_run_config_builder() {
        let config = ScanRunConfig::new("test-server", CliScanProfile::Standard)
            .with_args(vec!["arg1".to_string()])
            .with_timeout(30);

        assert_eq!(config.server, "test-server");
        assert_eq!(config.timeout, 30);
    }

    #[test]
    fn scan_run_config_new_default_values() {
        let config = ScanRunConfig::new("my-server", CliScanProfile::Quick);

        assert_eq!(config.server, "my-server");
        assert!(config.args.is_empty());
        assert!(matches!(config.profile, CliScanProfile::Quick));
        assert!(config.include.is_none());
        assert!(config.exclude.is_none());
        assert_eq!(config.timeout, 60);
    }

    #[test]
    fn scan_run_config_with_args() {
        let config = ScanRunConfig::new("server", CliScanProfile::Full)
            .with_args(vec!["--flag".to_string(), "value".to_string()]);

        assert_eq!(config.args.len(), 2);
        assert_eq!(config.args[0], "--flag");
        assert_eq!(config.args[1], "value");
    }

    #[test]
    fn scan_run_config_with_timeout() {
        let config = ScanRunConfig::new("server", CliScanProfile::Standard).with_timeout(120);

        assert_eq!(config.timeout, 120);
    }

    #[test]
    fn scan_run_config_profiles() {
        let quick = ScanRunConfig::new("s", CliScanProfile::Quick);
        assert!(matches!(quick.profile, CliScanProfile::Quick));

        let standard = ScanRunConfig::new("s", CliScanProfile::Standard);
        assert!(matches!(standard.profile, CliScanProfile::Standard));

        let full = ScanRunConfig::new("s", CliScanProfile::Full);
        assert!(matches!(full.profile, CliScanProfile::Full));

        let enterprise = ScanRunConfig::new("s", CliScanProfile::Enterprise);
        assert!(matches!(enterprise.profile, CliScanProfile::Enterprise));
    }

    #[test]
    fn scan_run_config_clone() {
        let config = ScanRunConfig::new("server", CliScanProfile::Standard).with_timeout(90);
        let cloned = config.clone();

        assert_eq!(cloned.server, "server");
        assert_eq!(cloned.timeout, 90);
    }

    #[test]
    fn scan_run_config_debug() {
        let config = ScanRunConfig::new("server", CliScanProfile::Standard);
        let debug = format!("{:?}", config);
        assert!(debug.contains("ScanRunConfig"));
        assert!(debug.contains("server"));
    }

    // BaselineConfig tests
    #[test]
    fn baseline_config_builder() {
        let config = BaselineConfig::default()
            .with_baseline(PathBuf::from("baseline.json"))
            .with_diff_only(true);

        assert!(config.baseline_path.is_some());
        assert!(config.diff_only);
    }

    #[test]
    fn baseline_config_default() {
        let config = BaselineConfig::default();

        assert!(config.baseline_path.is_none());
        assert!(config.save_baseline.is_none());
        assert!(!config.update_baseline);
        assert!(!config.diff_only);
        assert!(config.fail_on.is_none());
    }

    #[test]
    fn baseline_config_with_baseline() {
        let config =
            BaselineConfig::default().with_baseline(PathBuf::from("/path/to/baseline.json"));

        assert_eq!(
            config.baseline_path,
            Some(PathBuf::from("/path/to/baseline.json"))
        );
    }

    #[test]
    fn baseline_config_with_save_baseline() {
        let config = BaselineConfig::default().with_save_baseline(PathBuf::from("output.json"));

        assert_eq!(config.save_baseline, Some(PathBuf::from("output.json")));
    }

    #[test]
    fn baseline_config_with_update() {
        let config = BaselineConfig::default().with_update(true);

        assert!(config.update_baseline);
    }

    #[test]
    fn baseline_config_with_update_false() {
        let config = BaselineConfig::default().with_update(false);

        assert!(!config.update_baseline);
    }

    #[test]
    fn baseline_config_with_diff_only() {
        let config = BaselineConfig::default().with_diff_only(true);

        assert!(config.diff_only);
    }

    #[test]
    fn baseline_config_with_fail_on() {
        let config =
            BaselineConfig::default().with_fail_on(vec![Severity::Critical, Severity::High]);

        assert!(config.fail_on.is_some());
        let severities = config.fail_on.unwrap();
        assert_eq!(severities.len(), 2);
    }

    #[test]
    fn baseline_config_chained_builders() {
        let config = BaselineConfig::default()
            .with_baseline(PathBuf::from("baseline.json"))
            .with_save_baseline(PathBuf::from("new_baseline.json"))
            .with_update(true)
            .with_diff_only(true)
            .with_fail_on(vec![Severity::Critical]);

        assert!(config.baseline_path.is_some());
        assert!(config.save_baseline.is_some());
        assert!(config.update_baseline);
        assert!(config.diff_only);
        assert!(config.fail_on.is_some());
    }

    #[test]
    fn baseline_config_clone() {
        let config = BaselineConfig::default()
            .with_baseline(PathBuf::from("test.json"))
            .with_diff_only(true);
        let cloned = config.clone();

        assert_eq!(cloned.baseline_path, Some(PathBuf::from("test.json")));
        assert!(cloned.diff_only);
    }

    #[test]
    fn baseline_config_debug() {
        let config = BaselineConfig::default();
        let debug = format!("{:?}", config);
        assert!(debug.contains("BaselineConfig"));
    }

    // AiExplainConfig tests
    #[test]
    fn ai_config_enabled() {
        let config = AiExplainConfig::enabled(CliAiProvider::Anthropic).with_model("claude-3-opus");

        assert!(config.enabled);
        assert!(config.model.is_some());
    }

    #[test]
    fn ai_config_default() {
        let config = AiExplainConfig::default();

        assert!(!config.enabled);
        assert!(matches!(config.provider, CliAiProvider::Ollama));
        assert!(config.model.is_none());
    }

    #[test]
    fn ai_config_disabled() {
        let config = AiExplainConfig::disabled();

        assert!(!config.enabled);
        assert!(config.model.is_none());
    }

    #[test]
    fn ai_config_enabled_ollama() {
        let config = AiExplainConfig::enabled(CliAiProvider::Ollama);

        assert!(config.enabled);
        assert!(matches!(config.provider, CliAiProvider::Ollama));
        assert!(config.model.is_none());
    }

    #[test]
    fn ai_config_enabled_anthropic() {
        let config = AiExplainConfig::enabled(CliAiProvider::Anthropic);

        assert!(config.enabled);
        assert!(matches!(config.provider, CliAiProvider::Anthropic));
    }

    #[test]
    fn ai_config_enabled_openai() {
        let config = AiExplainConfig::enabled(CliAiProvider::Openai);

        assert!(config.enabled);
        assert!(matches!(config.provider, CliAiProvider::Openai));
    }

    #[test]
    fn ai_config_with_model() {
        let config = AiExplainConfig::enabled(CliAiProvider::Openai).with_model("gpt-4");

        assert_eq!(config.model, Some("gpt-4".to_string()));
    }

    #[test]
    fn ai_config_with_model_string() {
        let config = AiExplainConfig::enabled(CliAiProvider::Anthropic)
            .with_model(String::from("claude-3-sonnet"));

        assert_eq!(config.model, Some("claude-3-sonnet".to_string()));
    }

    #[test]
    fn ai_config_clone() {
        let config = AiExplainConfig::enabled(CliAiProvider::Anthropic).with_model("test-model");
        let cloned = config.clone();

        assert!(cloned.enabled);
        assert_eq!(cloned.model, Some("test-model".to_string()));
    }

    #[test]
    fn ai_config_debug() {
        let config = AiExplainConfig::default();
        let debug = format!("{:?}", config);
        assert!(debug.contains("AiExplainConfig"));
    }

    // ScanCommandConfig tests
    #[test]
    fn scan_command_config_new() {
        let run_config = ScanRunConfig::new("server", CliScanProfile::Standard);
        let config = ScanCommandConfig::new(run_config);

        assert_eq!(config.run.server, "server");
        assert!(!config.ai.enabled);
        assert!(config.baseline.baseline_path.is_none());
    }

    #[test]
    fn scan_command_config_with_baseline() {
        let run_config = ScanRunConfig::new("server", CliScanProfile::Standard);
        let baseline = BaselineConfig::default().with_baseline(PathBuf::from("test.json"));
        let config = ScanCommandConfig::new(run_config).with_baseline(baseline);

        assert!(config.baseline.baseline_path.is_some());
    }

    #[test]
    fn scan_command_config_with_ai() {
        let run_config = ScanRunConfig::new("server", CliScanProfile::Standard);
        let ai = AiExplainConfig::enabled(CliAiProvider::Anthropic);
        let config = ScanCommandConfig::new(run_config).with_ai(ai);

        assert!(config.ai.enabled);
    }

    #[test]
    fn scan_command_config_full_builder() {
        let run_config = ScanRunConfig::new("my-server", CliScanProfile::Full)
            .with_args(vec!["--verbose".to_string()])
            .with_timeout(120);

        let baseline = BaselineConfig::default()
            .with_baseline(PathBuf::from("baseline.json"))
            .with_diff_only(true);

        let ai = AiExplainConfig::enabled(CliAiProvider::Anthropic).with_model("claude-3-opus");

        let config = ScanCommandConfig::new(run_config)
            .with_baseline(baseline)
            .with_ai(ai);

        assert_eq!(config.run.server, "my-server");
        assert_eq!(config.run.timeout, 120);
        assert!(config.baseline.diff_only);
        assert!(config.ai.enabled);
        assert_eq!(config.ai.model, Some("claude-3-opus".to_string()));
    }

    #[test]
    fn scan_command_config_clone() {
        let run_config = ScanRunConfig::new("server", CliScanProfile::Standard);
        let config = ScanCommandConfig::new(run_config);
        let cloned = config.clone();

        assert_eq!(cloned.run.server, "server");
    }

    #[test]
    fn scan_command_config_debug() {
        let run_config = ScanRunConfig::new("server", CliScanProfile::Standard);
        let config = ScanCommandConfig::new(run_config);
        let debug = format!("{:?}", config);
        assert!(debug.contains("ScanCommandConfig"));
    }
}
