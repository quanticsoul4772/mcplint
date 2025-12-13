//! Multi-Scan command - Scan multiple MCP servers in parallel
//!
//! This command implements Phase 7-2 of the M7 milestone: Multi-Server Analysis.
//! It provides parallel scanning of multiple MCP servers with combined reporting.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use colored::Colorize;
use serde::Deserialize;

use crate::cli::OutputFormat;
use crate::scanner::multi_server::{MultiServerScanner, ServerConfig};
use crate::scanner::{ScanProfile, Severity};

#[derive(Debug, Deserialize)]
struct McpConfig {
    #[serde(rename = "mcpServers")]
    mcp_servers: HashMap<String, McpServerConfig>,
}

#[derive(Debug, Deserialize)]
struct McpServerConfig {
    command: String,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    env: HashMap<String, String>,
}

fn find_config_file() -> Option<PathBuf> {
    let home = dirs::home_dir()?;

    let locations = [
        // Claude Desktop (Windows)
        home.join("AppData/Roaming/Claude/claude_desktop_config.json"),
        // Claude Desktop (macOS)
        home.join("Library/Application Support/Claude/claude_desktop_config.json"),
        // Claude Desktop (Linux)
        home.join(".config/claude/claude_desktop_config.json"),
        // Local config
        PathBuf::from("claude_desktop_config.json"),
        PathBuf::from(".mcplint.json"),
        PathBuf::from("mcp.json"),
    ];

    locations.into_iter().find(|path| path.exists())
}

fn load_config(path: &Path) -> Result<McpConfig> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read config: {}", path.display()))?;
    let config: McpConfig = serde_json::from_str(&content)
        .with_context(|| format!("Failed to parse config: {}", path.display()))?;
    Ok(config)
}

/// Run multi-server scan command
#[allow(clippy::too_many_arguments)]
pub async fn run(
    servers: Option<Vec<String>>,
    all: bool,
    concurrency: usize,
    profile: ScanProfile,
    timeout: u64,
    config_path: Option<&Path>,
    fail_on: Option<Vec<Severity>>,
    format: OutputFormat,
) -> Result<()> {
    // Load config
    let config_file = config_path
        .map(PathBuf::from)
        .or_else(find_config_file)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "No MCP config found. Create claude_desktop_config.json or specify --config"
            )
        })?;

    println!("{} {}", "Config:".green(), config_file.display());
    let config = load_config(&config_file)?;

    if config.mcp_servers.is_empty() {
        println!("{}", "No MCP servers configured.".yellow());
        return Ok(());
    }

    // Determine which servers to scan
    let server_names: Vec<String> = if all {
        config.mcp_servers.keys().cloned().collect()
    } else if let Some(ref names) = servers {
        // Validate server names exist
        for name in names {
            if !config.mcp_servers.contains_key(name) {
                return Err(anyhow::anyhow!(
                    "Server '{}' not found in config. Available servers: {}",
                    name,
                    config
                        .mcp_servers
                        .keys()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
        }
        names.clone()
    } else {
        return Err(anyhow::anyhow!(
            "Specify servers with --servers or use --all to scan all configured servers"
        ));
    };

    if server_names.is_empty() {
        println!("{}", "No servers to scan.".yellow());
        return Ok(());
    }

    // Build server configs for the multi-server scanner
    let server_configs: Vec<ServerConfig> = server_names
        .iter()
        .filter_map(|name| {
            config.mcp_servers.get(name).map(|cfg| {
                ServerConfig::new(name, &cfg.command)
                    .with_args(cfg.args.clone())
                    .with_env(cfg.env.clone())
                    .with_timeout(timeout)
                    .with_profile(profile)
            })
        })
        .collect();

    println!();
    println!(
        "{} Scanning {} servers (concurrency: {}, profile: {:?})",
        "▶".cyan(),
        server_configs.len(),
        concurrency,
        profile
    );
    println!("{}", "─".repeat(60).dimmed());

    // Create scanner and run
    let scanner = MultiServerScanner::new(server_configs)
        .with_concurrency(concurrency)
        .with_timeout(timeout)
        .with_profile(profile);

    let results = scanner.scan_all().await?;

    // Output results based on format
    match format {
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&results).unwrap_or_default()
            );
        }
        OutputFormat::Sarif => {
            println!(
                "{}",
                serde_json::to_string_pretty(&results.to_sarif()).unwrap_or_default()
            );
        }
        OutputFormat::Text | OutputFormat::Junit | OutputFormat::Gitlab => {
            results.print_summary();
        }
    }

    // Check fail conditions
    if let Some(ref severities) = fail_on {
        for severity in severities {
            let severity_str = format!("{:?}", severity).to_lowercase();
            if let Some(&count) = results.severity_counts.get(&severity_str) {
                if count > 0 {
                    return Err(anyhow::anyhow!(
                        "Found {} {} severity finding(s)",
                        count,
                        severity_str
                    ));
                }
            }
        }
    }

    // Return error if any servers failed
    if results.failure_count > 0 {
        let failed = results.failed_servers();
        eprintln!(
            "\n{} {} server(s) failed: {}",
            "⚠".yellow(),
            results.failure_count,
            failed.join(", ")
        );
    }

    Ok(())
}
