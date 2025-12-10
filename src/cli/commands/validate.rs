//! Validate command - MCP protocol compliance checking

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use colored::Colorize;
use serde::Deserialize;
use tracing::{debug, info};

use crate::validator::ProtocolValidator;
use crate::OutputFormat;

/// MCP server configuration from claude_desktop_config.json or similar
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
    #[serde(default)]
    env: HashMap<String, String>,
}

/// Find MCP config file in standard locations
fn find_config_file() -> Option<PathBuf> {
    let home = dirs::home_dir()?;

    // Check standard locations
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

/// Load MCP config from file
fn load_config(path: &Path) -> Result<McpConfig> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read config: {}", path.display()))?;
    let config: McpConfig = serde_json::from_str(&content)
        .with_context(|| format!("Failed to parse config: {}", path.display()))?;
    Ok(config)
}

/// Resolve server specification to command, args, and env vars
fn resolve_server(
    server: Option<&str>,
    config_path: Option<&Path>,
) -> Result<Vec<(String, String, Vec<String>, HashMap<String, String>)>> {
    // If server starts with @, it's an npm package
    if let Some(s) = server {
        if s.starts_with('@') || s.contains('/') && !s.contains('\\') && !Path::new(s).exists() {
            // npm package: npx @package/name
            return Ok(vec![(
                s.to_string(),
                "npx".to_string(),
                vec!["-y".to_string(), s.to_string()],
                HashMap::new(),
            )]);
        }

        // URL - use directly
        if s.starts_with("http://") || s.starts_with("https://") {
            return Ok(vec![(s.to_string(), s.to_string(), vec![], HashMap::new())]);
        }

        // File path
        let path = Path::new(s);
        if path.exists() {
            let (cmd, args) = detect_runtime_for_file(s);
            return Ok(vec![(s.to_string(), cmd, args, HashMap::new())]);
        }
    }

    // Try to load from config
    let config_file = config_path
        .map(PathBuf::from)
        .or_else(find_config_file)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "No MCP config found. Specify a server or create claude_desktop_config.json"
            )
        })?;

    println!("{} {}", "Found config:".green(), config_file.display());

    let config = load_config(&config_file)?;

    if config.mcp_servers.is_empty() {
        anyhow::bail!("No MCP servers configured in {}", config_file.display());
    }

    // If server name specified, find it in config
    if let Some(name) = server {
        let server_config = config.mcp_servers.get(name).ok_or_else(|| {
            anyhow::anyhow!(
                "Server '{}' not found in config. Available: {}",
                name,
                config
                    .mcp_servers
                    .keys()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })?;

        return Ok(vec![(
            name.to_string(),
            server_config.command.clone(),
            server_config.args.clone(),
            server_config.env.clone(),
        )]);
    }

    // No server specified - return all configured servers
    println!("{}", "Available servers:".cyan());
    for name in config.mcp_servers.keys() {
        println!("  • {}", name.yellow());
    }
    println!();

    Ok(config
        .mcp_servers
        .into_iter()
        .map(|(name, cfg)| (name, cfg.command, cfg.args, cfg.env))
        .collect())
}

/// Detect runtime for a file path
fn detect_runtime_for_file(server: &str) -> (String, Vec<String>) {
    let path = Path::new(server);

    match path.extension().and_then(|e| e.to_str()) {
        Some("js") | Some("mjs") => ("node".to_string(), vec![server.to_string()]),
        Some("ts") => (
            "npx".to_string(),
            vec!["ts-node".to_string(), server.to_string()],
        ),
        Some("py") => ("python".to_string(), vec![server.to_string()]),
        _ => (server.to_string(), vec![]),
    }
}

pub async fn run(
    server: Option<&str>,
    config: Option<&Path>,
    _features: Option<Vec<String>>,
    timeout: u64,
    format: OutputFormat,
) -> Result<()> {
    let servers = resolve_server(server, config)?;

    let mut all_passed = true;

    for (name, command, args, env) in &servers {
        info!("Validating MCP server: {} ({})", name, command);
        debug!(
            "Args: {:?}, Env: {:?}, Timeout: {}s",
            args,
            env.keys().collect::<Vec<_>>(),
            timeout
        );

        println!("{}", "━".repeat(60).dimmed());
        println!("{} {}", "Validating:".cyan(), name.yellow().bold());
        println!("  Command: {} {}", command, args.join(" ").dimmed());
        if !env.is_empty() {
            println!("  Env: {} variables", env.len());
        }
        println!();

        let validator = ProtocolValidator::new(command, args, env.clone(), timeout);
        let results = validator.validate().await?;

        match format {
            OutputFormat::Text => {
                results.print_text();
            }
            OutputFormat::Json => {
                results.print_json()?;
            }
            OutputFormat::Sarif => {
                results.print_sarif()?;
            }
            OutputFormat::Junit | OutputFormat::Gitlab => {
                results.print_json()?;
            }
        }

        if results.failed > 0 {
            all_passed = false;
        }

        println!();
    }

    if servers.len() > 1 {
        println!("{}", "━".repeat(60).dimmed());
        if all_passed {
            println!("{}", "✓ All servers passed validation".green().bold());
        } else {
            println!("{}", "✗ Some servers failed validation".red().bold());
        }
    }

    Ok(())
}
