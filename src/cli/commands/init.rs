//! Init command - Generate configuration file

use anyhow::{bail, Result};
use colored::Colorize;
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

pub fn run(output: &str, force: bool) -> Result<()> {
    info!("Generating config file: {}", output);

    let path = Path::new(output);

    if path.exists() && !force {
        bail!(
            "Config file already exists: {}. Use --force to overwrite.",
            output
        );
    }

    fs::write(path, DEFAULT_CONFIG)?;

    println!("{}", "✓ Configuration file created".green());
    println!("  Location: {}", output.yellow());
    println!();
    println!("Edit {} to customize MCPLint behavior.", output.cyan());

    Ok(())
}

/// Get the default configuration content
#[allow(dead_code)]
pub fn default_config() -> &'static str {
    DEFAULT_CONFIG
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
