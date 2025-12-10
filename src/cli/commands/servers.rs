//! Servers command - List available MCP servers from config

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use colored::Colorize;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct McpConfig {
    #[serde(rename = "mcpServers")]
    mcp_servers: HashMap<String, ServerConfig>,
}

#[derive(Debug, Deserialize)]
struct ServerConfig {
    command: String,
    #[serde(default)]
    args: Vec<String>,
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

    for path in locations {
        if path.exists() {
            return Some(path);
        }
    }
    None
}

fn load_config(path: &Path) -> Result<McpConfig> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read config: {}", path.display()))?;
    let config: McpConfig = serde_json::from_str(&content)
        .with_context(|| format!("Failed to parse config: {}", path.display()))?;
    Ok(config)
}

pub fn run(config_path: Option<&Path>) -> Result<()> {
    let config_file = config_path
        .map(PathBuf::from)
        .or_else(find_config_file)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "No MCP config found. Create claude_desktop_config.json or specify --config"
            )
        })?;

    println!("{} {}", "Config:".green(), config_file.display());
    println!();

    let config = load_config(&config_file)?;

    if config.mcp_servers.is_empty() {
        println!("{}", "No MCP servers configured.".yellow());
        return Ok(());
    }

    println!(
        "{} ({} servers)",
        "Available MCP Servers".cyan().bold(),
        config.mcp_servers.len()
    );
    println!("{}", "─".repeat(60).dimmed());

    let mut servers: Vec<_> = config.mcp_servers.into_iter().collect();
    servers.sort_by(|a, b| a.0.cmp(&b.0));

    for (name, cfg) in servers {
        println!("  {} {}", "•".green(), name.yellow().bold());
        println!("    Command: {}", cfg.command.dimmed());
        if !cfg.args.is_empty() {
            println!("    Args:    {}", cfg.args.join(" ").dimmed());
        }
    }

    println!();
    println!("{}", "Use: mcplint validate <server-name>".dimmed());

    Ok(())
}
