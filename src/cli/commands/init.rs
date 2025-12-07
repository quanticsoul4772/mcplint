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
