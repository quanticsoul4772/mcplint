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
