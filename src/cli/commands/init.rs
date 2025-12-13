//! Init command - Generate configuration file

use crate::cli::interactive::InitWizardResult;
use crate::scanner::ScanProfile;
use anyhow::{bail, Result};
use colored::Colorize;
use serde::Serialize;
use std::fs;
use std::path::Path;
use tracing::info;

const DEFAULT_CONFIG: &str = r#"# MCPLint Configuration
# https://github.com/quanticsoul4772/mcplint

[general]
# Default output format: text, json, sarif
format = "text"

# Default timeout for server operations (seconds)
timeout = 30

[validate]
# Protocol features to check
features = ["lifecycle", "tools", "resources", "prompts"]

# Strict mode fails on warnings
strict = false

[scan]
# Default scan profile: quick, standard, full, enterprise
profile = "standard"

# Rule categories to include (empty = all)
include = []

# Rule categories to exclude
exclude = []

[fuzz]
# Default fuzzing duration (seconds)
duration = 300

# Number of parallel workers
workers = 4

# Path to corpus directory
corpus = ".mcplint/corpus"

# Maximum iterations (0 = unlimited)
max_iterations = 0

[rules]
# Custom rules directory
# custom_rules = ".mcplint/rules"

# Severity threshold: info, warning, error, critical
min_severity = "warning"

# AI-Assisted Vulnerability Explanation settings
[ai]
# AI provider: anthropic, openai, ollama
provider = "ollama"

# Model to use (provider-specific)
# anthropic: claude-sonnet-4-20250514, claude-3-opus-20240229
# openai: gpt-4o, gpt-4-turbo
# ollama: llama3.2, codellama, mistral
model = "llama3.2"

# Ollama base URL (for local provider)
ollama_url = "http://localhost:11434"

# Maximum tokens for response
max_tokens = 4096

# Temperature for generation (0.0 - 1.0, lower = more focused)
temperature = 0.3

# Cache AI responses (TTL in seconds, 0 = no cache)
cache_ttl = 604800  # 7 days

# Rate limiting (requests per minute)
rate_limit_rpm = 50

# Rate limiting (tokens per minute)
rate_limit_tpm = 100000

# Target audience level: beginner, intermediate, expert
audience = "intermediate"

[output]
# Enable colored output
color = true

# Show progress indicators
progress = true

# SARIF output settings
[output.sarif]
# Include code snippets in SARIF
include_snippets = true

# Schema version
schema_version = "2.1.0"
"#;

/// Configuration structs for TOML serialization
#[derive(Debug, Serialize)]
struct GeneralConfig {
    format: String,
    timeout: u32,
}

#[derive(Debug, Serialize)]
struct ValidateConfig {
    features: Vec<String>,
    strict: bool,
}

#[derive(Debug, Serialize)]
struct ScanConfig {
    profile: String,
    include: Vec<String>,
    exclude: Vec<String>,
}

#[derive(Debug, Serialize)]
struct FuzzConfig {
    duration: u32,
    workers: u32,
    corpus: String,
    max_iterations: u32,
}

#[derive(Debug, Serialize)]
struct RulesConfig {
    min_severity: String,
}

#[derive(Debug, Serialize)]
struct AiConfig {
    provider: String,
    model: String,
    ollama_url: String,
    max_tokens: u32,
    temperature: f32,
    cache_ttl: u32,
    rate_limit_rpm: u32,
    rate_limit_tpm: u32,
    audience: String,
}

#[derive(Debug, Serialize)]
struct SarifConfig {
    include_snippets: bool,
    schema_version: String,
}

#[derive(Debug, Serialize)]
struct OutputConfig {
    color: bool,
    progress: bool,
    sarif: SarifConfig,
}

#[derive(Debug, Serialize)]
struct McplintConfig {
    general: GeneralConfig,
    validate: ValidateConfig,
    scan: ScanConfig,
    fuzz: FuzzConfig,
    rules: RulesConfig,
    ai: AiConfig,
    output: OutputConfig,
}

impl Default for McplintConfig {
    fn default() -> Self {
        Self {
            general: GeneralConfig {
                format: "text".to_string(),
                timeout: 30,
            },
            validate: ValidateConfig {
                features: vec![
                    "lifecycle".to_string(),
                    "tools".to_string(),
                    "resources".to_string(),
                    "prompts".to_string(),
                ],
                strict: false,
            },
            scan: ScanConfig {
                profile: "standard".to_string(),
                include: vec![],
                exclude: vec![],
            },
            fuzz: FuzzConfig {
                duration: 300,
                workers: 4,
                corpus: ".mcplint/corpus".to_string(),
                max_iterations: 0,
            },
            rules: RulesConfig {
                min_severity: "warning".to_string(),
            },
            ai: AiConfig {
                provider: "ollama".to_string(),
                model: "llama3.2".to_string(),
                ollama_url: "http://localhost:11434".to_string(),
                max_tokens: 4096,
                temperature: 0.3,
                cache_ttl: 604800,
                rate_limit_rpm: 50,
                rate_limit_tpm: 100000,
                audience: "intermediate".to_string(),
            },
            output: OutputConfig {
                color: true,
                progress: true,
                sarif: SarifConfig {
                    include_snippets: true,
                    schema_version: "2.1.0".to_string(),
                },
            },
        }
    }
}

impl McplintConfig {
    /// Create configuration from wizard result
    fn from_wizard(wizard: &InitWizardResult) -> Self {
        let mut config = Self::default();

        // Apply wizard selections
        config.scan.profile = match wizard.default_profile {
            ScanProfile::Quick => "quick",
            ScanProfile::Standard => "standard",
            ScanProfile::Full => "full",
            ScanProfile::Enterprise => "enterprise",
        }
        .to_string();

        config
    }

    /// Generate TOML with header comments
    fn to_toml_with_header(&self) -> Result<String> {
        let header = "# MCPLint Configuration\n\
                     # https://github.com/quanticsoul4772/mcplint\n\
                     # Generated by MCPLint init wizard\n\n";

        let toml_content = toml::to_string_pretty(self)
            .map_err(|e| anyhow::anyhow!("Failed to serialize config: {}", e))?;

        Ok(format!("{}{}", header, toml_content))
    }
}

#[allow(dead_code)]
pub fn run(output: &str, force: bool) -> Result<()> {
    run_with_config(output, force, None)
}

/// Run init with optional wizard configuration
pub fn run_with_config(
    output: &str,
    force: bool,
    wizard_result: Option<InitWizardResult>,
) -> Result<()> {
    info!("Generating config file: {}", output);

    let path = Path::new(output);

    if path.exists() && !force {
        bail!(
            "Config file already exists: {}. Use --force to overwrite.",
            output
        );
    }

    // Generate config content
    let config_content = if let Some(ref wizard) = wizard_result {
        let config = McplintConfig::from_wizard(wizard);
        config.to_toml_with_header()?
    } else {
        DEFAULT_CONFIG.to_string()
    };

    fs::write(path, &config_content)?;

    println!("{}", "✓ Configuration file created".green());
    println!("  Location: {}", output.yellow());
    println!();

    if let Some(wizard) = wizard_result {
        // Show summary of wizard selections
        if !wizard.servers_to_test.is_empty() {
            println!("{}", "Servers to test:".cyan());
            for server in &wizard.servers_to_test {
                println!("  • {}", server);
            }
            println!();
        }

        // Create CI workflow if requested
        if wizard.create_ci_workflow {
            match create_github_actions_workflow() {
                Ok(()) => {}
                Err(e) => {
                    println!("  {} Failed to create workflow: {}", "✗".red(), e);
                }
            }
        }

        // Add gitignore entry
        match create_gitignore_entry() {
            Ok(()) => {}
            Err(e) => {
                println!("  {} Failed to update .gitignore: {}", "✗".red(), e);
            }
        }

        println!();

        if wizard.run_initial_scan && !wizard.servers_to_test.is_empty() {
            println!("{}", "To scan the selected servers, run:".cyan());
            for server in &wizard.servers_to_test {
                println!(
                    "  mcplint scan {} --profile {:?}",
                    server, wizard.default_profile
                );
            }
            println!();
        }

        // Next steps
        println!("{}", "═".repeat(50).cyan());
        println!("{}", "  Next Steps".cyan().bold());
        println!("{}", "═".repeat(50).cyan());
        println!("  1. Review config: {}", output.yellow());
        println!("  2. Run a scan: {}", "mcplint scan <server>".yellow());
        println!("  3. View rules: {}", "mcplint rules --details".yellow());
        println!();
    } else {
        println!("Edit {} to customize MCPLint behavior.", output.cyan());
    }

    Ok(())
}

/// Get the default configuration content
#[allow(dead_code)]
pub fn default_config() -> &'static str {
    DEFAULT_CONFIG
}

/// Create GitHub Actions workflow file
pub fn create_github_actions_workflow() -> Result<()> {
    use std::path::Path;

    let workflow_dir = Path::new(".github/workflows");
    fs::create_dir_all(workflow_dir)?;

    let workflow_path = workflow_dir.join("mcplint.yml");

    let workflow_content = r#"# MCPLint Security Scan Workflow
# Generated by: mcplint init
# https://github.com/quanticsoul4772/mcplint

name: MCPLint Security Scan

on:
  push:
    branches: [ main, master, develop ]
  pull_request:
    branches: [ main, master ]
  # Allow manual trigger
  workflow_dispatch:

jobs:
  security-scan:
    runs-on: ubuntu-latest
    name: MCP Security Scan

    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Install Rust toolchain
        uses: dtolnay/rust-action@stable

      - name: Install MCPLint
        run: cargo install mcplint

      - name: Run Security Scan
        run: |
          # Replace <server-name> with your actual MCP server
          # mcplint scan <server-name> --profile standard --format sarif --output mcplint-results.sarif
          echo "Configure your MCP servers in .mcplint.toml and update this workflow"

      # Uncomment to upload SARIF results to GitHub Security tab
      # - name: Upload SARIF results
      #   uses: github/codeql-action/upload-sarif@v3
      #   if: always()
      #   with:
      #     sarif_file: mcplint-results.sarif
"#;

    fs::write(&workflow_path, workflow_content)?;

    println!(
        "  {} GitHub Actions workflow: {}",
        "✓".green(),
        ".github/workflows/mcplint.yml".yellow()
    );

    Ok(())
}

/// Add .mcplint-cache/ to .gitignore
pub fn create_gitignore_entry() -> Result<()> {
    use std::path::Path;

    let gitignore_path = Path::new(".gitignore");
    let entry = "\n# MCPLint cache directory\n.mcplint-cache/\n";

    if gitignore_path.exists() {
        let content = fs::read_to_string(gitignore_path)?;
        if !content.contains(".mcplint-cache") {
            fs::write(gitignore_path, format!("{}{}", content, entry))?;
            println!(
                "  {} Added {} to .gitignore",
                "✓".green(),
                ".mcplint-cache/".yellow()
            );
        } else {
            println!("  {} .mcplint-cache/ already in .gitignore", "✓".green());
        }
    } else {
        fs::write(gitignore_path, entry.trim_start())?;
        println!(
            "  {} Created .gitignore with {}",
            "✓".green(),
            ".mcplint-cache/".yellow()
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn default_config_contains_sections() {
        let config = default_config();
        assert!(config.contains("[general]"));
        assert!(config.contains("[validate]"));
        assert!(config.contains("[scan]"));
        assert!(config.contains("[fuzz]"));
        assert!(config.contains("[rules]"));
        assert!(config.contains("[ai]"));
        assert!(config.contains("[output]"));
    }

    #[test]
    fn default_config_has_format_option() {
        let config = default_config();
        assert!(config.contains("format = \"text\""));
    }

    #[test]
    fn default_config_has_timeout_option() {
        let config = default_config();
        assert!(config.contains("timeout = 30"));
    }

    #[test]
    fn default_config_has_profile_option() {
        let config = default_config();
        assert!(config.contains("profile = \"standard\""));
    }

    #[test]
    fn default_config_has_ai_settings() {
        let config = default_config();
        assert!(config.contains("provider = \"ollama\""));
        assert!(config.contains("model = \"llama3.2\""));
        assert!(config.contains("max_tokens = 4096"));
    }

    #[test]
    fn run_creates_config_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(".mcplint.toml");
        let path_str = path.to_str().unwrap();

        let result = run(path_str, false);
        assert!(result.is_ok());
        assert!(path.exists());

        let contents = fs::read_to_string(&path).unwrap();
        assert!(contents.contains("[general]"));
    }

    #[test]
    fn run_fails_if_file_exists_without_force() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(".mcplint.toml");
        let path_str = path.to_str().unwrap();

        // Create the file first
        fs::write(&path, "existing content").unwrap();

        let result = run(path_str, false);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("already exists"));
    }

    #[test]
    fn run_overwrites_with_force() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(".mcplint.toml");
        let path_str = path.to_str().unwrap();

        // Create the file first
        fs::write(&path, "existing content").unwrap();

        let result = run(path_str, true);
        assert!(result.is_ok());

        let contents = fs::read_to_string(&path).unwrap();
        assert!(contents.contains("[general]"));
        assert!(!contents.contains("existing content"));
    }

    #[test]
    fn default_config_is_valid_toml() {
        let config = default_config();
        let parsed: Result<toml::Value, _> = toml::from_str(config);
        assert!(parsed.is_ok(), "DEFAULT_CONFIG should be valid TOML");
    }
}
