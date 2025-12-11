//! Server Resolution Utilities
//!
//! Shared functions for resolving MCP server specifications from various sources:
//! - Claude Desktop config file
//! - Direct file paths
//! - npm packages
//! - HTTP/HTTPS URLs

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;

/// Server specification: (name, command, args, env)
pub type ServerSpec = (String, String, Vec<String>, HashMap<String, String>);

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
pub fn find_config_file() -> Option<PathBuf> {
    let home = dirs::home_dir()?;

    let locations = [
        home.join("AppData/Roaming/Claude/claude_desktop_config.json"),
        home.join("Library/Application Support/Claude/claude_desktop_config.json"),
        home.join(".config/claude/claude_desktop_config.json"),
        PathBuf::from("claude_desktop_config.json"),
        PathBuf::from(".mcplint.json"),
        PathBuf::from("mcp.json"),
    ];

    locations.into_iter().find(|path| path.exists())
}

/// Load MCP config from file
fn load_config(path: &Path) -> Result<McpConfig> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read config: {}", path.display()))?;
    let config: McpConfig = serde_json::from_str(&content)
        .with_context(|| format!("Failed to parse config: {}", path.display()))?;
    Ok(config)
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

/// Resolve server specification to command, args, and env vars
///
/// Supports multiple server specification formats:
/// - Server name from Claude Desktop config (e.g., "filesystem", "unified-thinking")
/// - npm package (e.g., "@modelcontextprotocol/server-filesystem")
/// - HTTP/HTTPS URL
/// - Local file path with auto-detected runtime
///
/// # Arguments
/// * `server` - Server identifier (name, path, URL, or npm package)
/// * `config_path` - Optional path to config file (defaults to Claude Desktop config)
///
/// # Returns
/// A tuple of (name, command, args, env) for spawning the server
pub fn resolve_server(server: &str, config_path: Option<&Path>) -> Result<ServerSpec> {
    // If server is an HTTP/HTTPS URL, return it as-is (for SSE/HTTP transport)
    if server.starts_with("http://") || server.starts_with("https://") {
        return Ok((
            server.to_string(),
            server.to_string(),
            vec![],
            HashMap::new(),
        ));
    }

    // If server starts with @, it's an npm package
    if server.starts_with('@')
        || server.contains('/') && !server.contains('\\') && !Path::new(server).exists()
    {
        return Ok((
            server.to_string(),
            "npx".to_string(),
            vec!["-y".to_string(), server.to_string()],
            HashMap::new(),
        ));
    }

    // File path
    let path = Path::new(server);
    if path.exists() {
        let (cmd, args) = detect_runtime_for_file(server);
        return Ok((server.to_string(), cmd, args, HashMap::new()));
    }

    // Try to load from config
    let config_file = config_path
        .map(PathBuf::from)
        .or_else(find_config_file)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "No MCP config found. Specify a server path or create claude_desktop_config.json"
            )
        })?;

    let config = load_config(&config_file)?;

    let server_config = config.mcp_servers.get(server).ok_or_else(|| {
        anyhow::anyhow!(
            "Server '{}' not found in config. Available: {}",
            server,
            config
                .mcp_servers
                .keys()
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        )
    })?;

    Ok((
        server.to_string(),
        server_config.command.clone(),
        server_config.args.clone(),
        server_config.env.clone(),
    ))
}

/// List available servers from config
#[allow(dead_code)]
pub fn list_servers(config_path: Option<&Path>) -> Result<Vec<String>> {
    let config_file = config_path
        .map(PathBuf::from)
        .or_else(find_config_file)
        .ok_or_else(|| anyhow::anyhow!("No MCP config found"))?;

    let config = load_config(&config_file)?;
    let mut servers: Vec<String> = config.mcp_servers.keys().cloned().collect();
    servers.sort();
    Ok(servers)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_runtime_js() {
        let (cmd, args) = detect_runtime_for_file("server.js");
        assert_eq!(cmd, "node");
        assert_eq!(args, vec!["server.js"]);
    }

    #[test]
    fn detect_runtime_mjs() {
        let (cmd, args) = detect_runtime_for_file("server.mjs");
        assert_eq!(cmd, "node");
        assert_eq!(args, vec!["server.mjs"]);
    }

    #[test]
    fn detect_runtime_ts() {
        let (cmd, args) = detect_runtime_for_file("server.ts");
        assert_eq!(cmd, "npx");
        assert_eq!(args, vec!["ts-node", "server.ts"]);
    }

    #[test]
    fn detect_runtime_py() {
        let (cmd, args) = detect_runtime_for_file("server.py");
        assert_eq!(cmd, "python");
        assert_eq!(args, vec!["server.py"]);
    }

    #[test]
    fn detect_runtime_unknown() {
        let (cmd, args) = detect_runtime_for_file("myserver");
        assert_eq!(cmd, "myserver");
        assert!(args.is_empty());
    }

    #[test]
    fn resolve_npm_package() {
        let result = resolve_server("@modelcontextprotocol/server-filesystem", None);
        assert!(result.is_ok());
        let (name, cmd, args, _) = result.unwrap();
        assert_eq!(name, "@modelcontextprotocol/server-filesystem");
        assert_eq!(cmd, "npx");
        assert!(args.contains(&"-y".to_string()));
    }

    #[test]
    fn resolve_http_url() {
        let result = resolve_server("http://localhost:8080/mcp", None);
        assert!(result.is_ok());
        let (name, cmd, args, _) = result.unwrap();
        assert_eq!(name, "http://localhost:8080/mcp");
        assert_eq!(cmd, "http://localhost:8080/mcp");
        assert!(args.is_empty());
    }

    #[test]
    fn resolve_https_url() {
        let result = resolve_server("https://api.example.com/mcp", None);
        assert!(result.is_ok());
        let (name, cmd, args, _) = result.unwrap();
        assert_eq!(name, "https://api.example.com/mcp");
        assert_eq!(cmd, "https://api.example.com/mcp");
        assert!(args.is_empty());
    }
}
