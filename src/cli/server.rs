//! Server Resolution Utilities
//!
//! Shared functions for resolving MCP server specifications from various sources:
//! - Claude Desktop config file
//! - Direct file paths
//! - npm packages
//! - HTTP/HTTPS URLs
//!
//! # Performance Targets (METRICS.md - Phase 1)
//! - Config file detection: < 50ms
//! - Server resolution: < 100ms
//! - Transport type detection: < 10ms

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::transport::{ServerTransportConfig, TransportType};

/// Server specification: (name, command, args, env, transport)
#[derive(Debug, Clone)]
pub struct ServerSpec {
    /// Server name/identifier
    pub name: String,
    /// Command to execute (or URL for remote)
    pub command: String,
    /// Arguments to pass to the command
    pub args: Vec<String>,
    /// Environment variables
    pub env: HashMap<String, String>,
    /// Detected/configured transport type
    pub transport: TransportType,
    /// Transport config for full detection algorithm (used for future phases)
    #[allow(dead_code)]
    pub transport_config: ServerTransportConfig,
}

#[allow(dead_code)]
impl ServerSpec {
    /// Create a new ServerSpec with default stdio transport
    pub fn new(name: String, command: String) -> Self {
        Self {
            name,
            command: command.clone(),
            args: Vec::new(),
            env: HashMap::new(),
            transport: TransportType::Stdio,
            transport_config: ServerTransportConfig {
                transport: None,
                command: Some(command),
            },
        }
    }

    /// Create from a legacy tuple format
    pub fn from_tuple(tuple: (String, String, Vec<String>, HashMap<String, String>)) -> Self {
        let transport = crate::transport::detect_transport_type(&tuple.1);
        Self {
            name: tuple.0,
            command: tuple.1.clone(),
            args: tuple.2,
            env: tuple.3,
            transport,
            transport_config: ServerTransportConfig {
                transport: None,
                command: Some(tuple.1),
            },
        }
    }

    /// Convert to legacy tuple format for backward compatibility
    pub fn to_tuple(&self) -> (String, String, Vec<String>, HashMap<String, String>) {
        (
            self.name.clone(),
            self.command.clone(),
            self.args.clone(),
            self.env.clone(),
        )
    }
}

/// MCP server configuration from claude_desktop_config.json or similar
#[derive(Debug, Deserialize, Clone)]
#[cfg_attr(test, derive(serde::Serialize))]
pub struct McpConfig {
    #[serde(rename = "mcpServers")]
    pub mcp_servers: HashMap<String, ServerConfig>,
}

/// Server configuration from config file
#[derive(Debug, Deserialize, Clone)]
#[cfg_attr(test, derive(serde::Serialize))]
pub struct ServerConfig {
    /// Command to execute
    pub command: String,
    /// Arguments to pass to the command
    #[serde(default)]
    pub args: Vec<String>,
    /// Environment variables
    #[serde(default)]
    pub env: HashMap<String, String>,
    /// Explicit transport type (stdio, http, sse)
    #[serde(default)]
    pub transport: Option<String>,
}

impl ServerConfig {
    /// Convert to ServerTransportConfig for transport detection
    pub fn to_transport_config(&self) -> ServerTransportConfig {
        ServerTransportConfig {
            transport: self.transport.clone(),
            command: Some(self.command.clone()),
        }
    }
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
pub fn load_config(path: &Path) -> Result<McpConfig> {
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

/// Resolve server specification to full ServerSpec
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
/// A ServerSpec containing name, command, args, env, and detected transport type
pub fn resolve_server(server: &str, config_path: Option<&Path>) -> Result<ServerSpec> {
    resolve_server_with_transport(server, config_path, None)
}

/// Resolve server specification with explicit transport override
///
/// # Arguments
/// * `server` - Server identifier (name, path, URL, or npm package)
/// * `config_path` - Optional path to config file
/// * `explicit_transport` - Explicit transport type override (--transport flag)
///
/// # Returns
/// A ServerSpec with full transport detection per ADR-001
pub fn resolve_server_with_transport(
    server: &str,
    config_path: Option<&Path>,
    explicit_transport: Option<TransportType>,
) -> Result<ServerSpec> {
    use crate::transport::detect_transport_type_full;

    // If server is an HTTP/HTTPS URL, return it as-is (for SSE/HTTP transport)
    if server.starts_with("http://") || server.starts_with("https://") {
        let transport = detect_transport_type_full(server, None, explicit_transport);
        return Ok(ServerSpec {
            name: server.to_string(),
            command: server.to_string(),
            args: vec![],
            env: HashMap::new(),
            transport,
            transport_config: ServerTransportConfig {
                transport: None,
                command: Some(server.to_string()),
            },
        });
    }

    // If server starts with @, it's an npm package
    if server.starts_with('@')
        || server.contains('/') && !server.contains('\\') && !Path::new(server).exists()
    {
        let transport = explicit_transport.unwrap_or(TransportType::Stdio);
        return Ok(ServerSpec {
            name: server.to_string(),
            command: "npx".to_string(),
            args: vec!["-y".to_string(), server.to_string()],
            env: HashMap::new(),
            transport,
            transport_config: ServerTransportConfig {
                transport: None,
                command: Some("npx".to_string()),
            },
        });
    }

    // File path
    let path = Path::new(server);
    if path.exists() {
        let (cmd, args) = detect_runtime_for_file(server);
        let transport = explicit_transport.unwrap_or(TransportType::Stdio);
        return Ok(ServerSpec {
            name: server.to_string(),
            command: cmd.clone(),
            args,
            env: HashMap::new(),
            transport,
            transport_config: ServerTransportConfig {
                transport: None,
                command: Some(cmd),
            },
        });
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
        let available: Vec<_> = config.mcp_servers.keys().cloned().collect();
        let suggestions = suggest_similar(server, &available);

        if suggestions.is_empty() {
            anyhow::anyhow!(
                "Server '{}' not found in config. Available: {}",
                server,
                available.join(", ")
            )
        } else {
            anyhow::anyhow!(
                "Server '{}' not found in config.\n\nDid you mean one of these?\n  - {}\n\nAvailable servers: {}",
                server,
                suggestions.join("\n  - "),
                available.join(", ")
            )
        }
    })?;

    // Use full transport detection algorithm (ADR-001)
    let transport_config = server_config.to_transport_config();
    let transport =
        detect_transport_type_full(&server_config.command, Some(&transport_config), explicit_transport);

    Ok(ServerSpec {
        name: server.to_string(),
        command: server_config.command.clone(),
        args: server_config.args.clone(),
        env: server_config.env.clone(),
        transport,
        transport_config,
    })
}

/// Suggest similar server names using Levenshtein distance
fn suggest_similar(input: &str, candidates: &[String]) -> Vec<String> {
    let input_lower = input.to_lowercase();
    let mut suggestions: Vec<(String, usize)> = candidates
        .iter()
        .filter_map(|candidate| {
            let candidate_lower = candidate.to_lowercase();
            let distance = levenshtein_distance(&input_lower, &candidate_lower);
            // Only suggest if distance is reasonably small (< 50% of input length)
            if distance <= (input.len() / 2).max(3) {
                Some((candidate.clone(), distance))
            } else {
                None
            }
        })
        .collect();

    suggestions.sort_by_key(|(_, d)| *d);
    suggestions.into_iter().take(3).map(|(s, _)| s).collect()
}

/// Simple Levenshtein distance implementation
fn levenshtein_distance(a: &str, b: &str) -> usize {
    let a_chars: Vec<char> = a.chars().collect();
    let b_chars: Vec<char> = b.chars().collect();
    let m = a_chars.len();
    let n = b_chars.len();

    if m == 0 {
        return n;
    }
    if n == 0 {
        return m;
    }

    let mut prev: Vec<usize> = (0..=n).collect();
    let mut curr = vec![0; n + 1];

    for i in 1..=m {
        curr[0] = i;
        for j in 1..=n {
            let cost = if a_chars[i - 1] == b_chars[j - 1] {
                0
            } else {
                1
            };
            curr[j] = (prev[j] + 1).min(curr[j - 1] + 1).min(prev[j - 1] + cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }

    prev[n]
}

/// Resolve all servers from config (for batch operations like validate --all)
///
/// When `server` is `None`, returns all configured servers.
/// When `server` is `Some`, returns only that server.
///
/// # Arguments
/// * `server` - Optional server identifier
/// * `config_path` - Optional path to config file
///
/// # Returns
/// A vector of ServerSpecs for batch processing
pub fn resolve_servers(server: Option<&str>, config_path: Option<&Path>) -> Result<Vec<ServerSpec>> {
    use crate::transport::detect_transport_type_full;
    use colored::Colorize;

    // If a server is specified, resolve just that one
    if let Some(s) = server {
        return Ok(vec![resolve_server(s, config_path)?]);
    }

    // No server specified - return all configured servers
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

    // Print available servers
    println!("{}", "Available servers:".cyan());
    for name in config.mcp_servers.keys() {
        println!("  • {}", name.yellow());
    }
    println!();

    // Convert all servers to ServerSpecs
    let specs: Vec<ServerSpec> = config
        .mcp_servers
        .into_iter()
        .map(|(name, server_config)| {
            let transport_config = server_config.to_transport_config();
            let transport = detect_transport_type_full(
                &server_config.command,
                Some(&transport_config),
                None,
            );

            ServerSpec {
                name,
                command: server_config.command,
                args: server_config.args,
                env: server_config.env,
                transport,
                transport_config,
            }
        })
        .collect();

    Ok(specs)
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

    // ==========================================================================
    // Runtime Detection Tests
    // ==========================================================================

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

    // ==========================================================================
    // Server Resolution Tests
    // ==========================================================================

    #[test]
    fn resolve_npm_package() {
        let result = resolve_server("@modelcontextprotocol/server-filesystem", None);
        assert!(result.is_ok());
        let spec = result.unwrap();
        assert_eq!(spec.name, "@modelcontextprotocol/server-filesystem");
        assert_eq!(spec.command, "npx");
        assert!(spec.args.contains(&"-y".to_string()));
        assert_eq!(spec.transport, TransportType::Stdio);
    }

    #[test]
    fn resolve_http_url() {
        let result = resolve_server("http://localhost:8080/mcp", None);
        assert!(result.is_ok());
        let spec = result.unwrap();
        assert_eq!(spec.name, "http://localhost:8080/mcp");
        assert_eq!(spec.command, "http://localhost:8080/mcp");
        assert!(spec.args.is_empty());
        assert_eq!(spec.transport, TransportType::StreamableHttp);
    }

    #[test]
    fn resolve_https_url() {
        let result = resolve_server("https://api.example.com/mcp", None);
        assert!(result.is_ok());
        let spec = result.unwrap();
        assert_eq!(spec.name, "https://api.example.com/mcp");
        assert_eq!(spec.command, "https://api.example.com/mcp");
        assert!(spec.args.is_empty());
        assert_eq!(spec.transport, TransportType::StreamableHttp);
    }

    #[test]
    fn resolve_sse_url() {
        let result = resolve_server("https://api.example.com/sse", None);
        assert!(result.is_ok());
        let spec = result.unwrap();
        assert_eq!(spec.transport, TransportType::SseLegacy);
    }

    #[test]
    fn resolve_with_explicit_transport_override() {
        let result = resolve_server_with_transport(
            "http://localhost:8080/mcp",
            None,
            Some(TransportType::SseLegacy),
        );
        assert!(result.is_ok());
        let spec = result.unwrap();
        // Explicit override should win over URL detection
        assert_eq!(spec.transport, TransportType::SseLegacy);
    }

    // ==========================================================================
    // ServerSpec Tests
    // ==========================================================================

    #[test]
    fn server_spec_new() {
        let spec = ServerSpec::new("test".to_string(), "node".to_string());
        assert_eq!(spec.name, "test");
        assert_eq!(spec.command, "node");
        assert!(spec.args.is_empty());
        assert!(spec.env.is_empty());
        assert_eq!(spec.transport, TransportType::Stdio);
    }

    #[test]
    fn server_spec_from_tuple() {
        let tuple = (
            "test".to_string(),
            "http://localhost/mcp".to_string(),
            vec![],
            HashMap::new(),
        );
        let spec = ServerSpec::from_tuple(tuple);
        assert_eq!(spec.name, "test");
        assert_eq!(spec.transport, TransportType::StreamableHttp);
    }

    #[test]
    fn server_spec_to_tuple() {
        let spec = ServerSpec::new("test".to_string(), "node".to_string());
        let (name, cmd, args, env) = spec.to_tuple();
        assert_eq!(name, "test");
        assert_eq!(cmd, "node");
        assert!(args.is_empty());
        assert!(env.is_empty());
    }

    // ==========================================================================
    // Levenshtein Distance Tests
    // ==========================================================================

    #[test]
    fn levenshtein_identical() {
        assert_eq!(levenshtein_distance("hello", "hello"), 0);
    }

    #[test]
    fn levenshtein_one_char_diff() {
        assert_eq!(levenshtein_distance("hello", "hallo"), 1);
    }

    #[test]
    fn levenshtein_empty() {
        assert_eq!(levenshtein_distance("", "hello"), 5);
        assert_eq!(levenshtein_distance("hello", ""), 5);
        assert_eq!(levenshtein_distance("", ""), 0);
    }

    #[test]
    fn levenshtein_completely_different() {
        assert_eq!(levenshtein_distance("abc", "xyz"), 3);
    }

    // ==========================================================================
    // Suggest Similar Tests
    // ==========================================================================

    #[test]
    fn suggest_similar_finds_close_matches() {
        let candidates = vec![
            "filesystem".to_string(),
            "github".to_string(),
            "slack".to_string(),
        ];
        let suggestions = suggest_similar("filesystm", &candidates);
        assert!(suggestions.contains(&"filesystem".to_string()));
    }

    #[test]
    fn suggest_similar_no_matches_for_very_different() {
        let candidates = vec![
            "filesystem".to_string(),
            "github".to_string(),
            "slack".to_string(),
        ];
        let suggestions = suggest_similar("completely_unrelated_name", &candidates);
        assert!(suggestions.is_empty());
    }

    #[test]
    fn suggest_similar_limits_to_three() {
        let candidates = vec![
            "test1".to_string(),
            "test2".to_string(),
            "test3".to_string(),
            "test4".to_string(),
            "test5".to_string(),
        ];
        let suggestions = suggest_similar("test", &candidates);
        assert!(suggestions.len() <= 3);
    }

    // ==========================================================================
    // ServerConfig Tests
    // ==========================================================================

    #[test]
    fn server_config_deserialize() {
        let json = r#"{"command": "node", "args": ["server.js"], "env": {"KEY": "VALUE"}}"#;
        let config: ServerConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.command, "node");
        assert_eq!(config.args, vec!["server.js"]);
        assert_eq!(config.env.get("KEY"), Some(&"VALUE".to_string()));
        assert!(config.transport.is_none());
    }

    #[test]
    fn server_config_deserialize_with_transport() {
        let json = r#"{"command": "node", "args": [], "transport": "sse"}"#;
        let config: ServerConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.transport, Some("sse".to_string()));
    }

    #[test]
    fn server_config_to_transport_config() {
        let config = ServerConfig {
            command: "node".to_string(),
            args: vec![],
            env: HashMap::new(),
            transport: Some("sse".to_string()),
        };
        let transport_config = config.to_transport_config();
        assert_eq!(transport_config.transport, Some("sse".to_string()));
        assert_eq!(transport_config.command, Some("node".to_string()));
    }

    // ==========================================================================
    // McpConfig Tests
    // ==========================================================================

    #[test]
    fn mcp_config_deserialize() {
        let json = r#"{
            "mcpServers": {
                "filesystem": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem"]
                },
                "remote": {
                    "command": "https://api.example.com/mcp",
                    "args": [],
                    "transport": "http"
                }
            }
        }"#;
        let config: McpConfig = serde_json::from_str(json).unwrap();
        assert!(config.mcp_servers.contains_key("filesystem"));
        assert!(config.mcp_servers.contains_key("remote"));
        assert_eq!(
            config.mcp_servers.get("remote").unwrap().transport,
            Some("http".to_string())
        );
    }

    // ==========================================================================
    // Performance / Metrics Compliance Tests (METRICS.md Phase 1)
    // ==========================================================================

    #[test]
    fn metrics_config_parsing_under_50ms() {
        // METRICS.md Phase 1: Config file detection < 50ms
        use std::time::Instant;

        // Create a config with 100 servers
        let mut servers = HashMap::new();
        for i in 0..100 {
            servers.insert(
                format!("server-{}", i),
                ServerConfig {
                    command: "node".to_string(),
                    args: vec!["server.js".to_string()],
                    env: HashMap::new(),
                    transport: None,
                },
            );
        }

        let config = McpConfig { mcp_servers: servers };
        let json = serde_json::to_string(&config).unwrap();

        let start = Instant::now();
        let parsed: McpConfig = serde_json::from_str(&json).unwrap();
        let elapsed = start.elapsed();

        assert!(
            elapsed.as_millis() < 50,
            "Config parsing took {}ms, expected < 50ms",
            elapsed.as_millis()
        );
        assert_eq!(parsed.mcp_servers.len(), 100);
    }

    #[test]
    fn metrics_transport_detection_under_10ms() {
        // METRICS.md Phase 1: Transport type detection < 10ms
        use crate::transport::detect_transport_type_full;
        use std::time::Instant;

        let test_cases = vec![
            "http://localhost:8080/mcp",
            "https://api.example.com/sse",
            "node",
            "/usr/local/bin/server",
            "@modelcontextprotocol/server-filesystem",
        ];

        for target in test_cases {
            let start = Instant::now();
            let _ = detect_transport_type_full(target, None, None);
            let elapsed = start.elapsed();

            assert!(
                elapsed.as_millis() < 10,
                "Transport detection for '{}' took {}ms, expected < 10ms",
                target,
                elapsed.as_millis()
            );
        }
    }

    #[test]
    fn metrics_server_resolution_under_100ms_for_url() {
        // METRICS.md Phase 1: Server resolution < 100ms
        use std::time::Instant;

        let start = Instant::now();
        let result = resolve_server("http://localhost:8080/mcp", None);
        let elapsed = start.elapsed();

        assert!(result.is_ok());
        assert!(
            elapsed.as_millis() < 100,
            "Server resolution took {}ms, expected < 100ms",
            elapsed.as_millis()
        );
    }

    #[test]
    fn metrics_server_resolution_under_100ms_for_npm() {
        // METRICS.md Phase 1: Server resolution < 100ms
        use std::time::Instant;

        let start = Instant::now();
        let result = resolve_server("@modelcontextprotocol/server-filesystem", None);
        let elapsed = start.elapsed();

        assert!(result.is_ok());
        assert!(
            elapsed.as_millis() < 100,
            "Server resolution took {}ms, expected < 100ms",
            elapsed.as_millis()
        );
    }

    // ==========================================================================
    // resolve_servers Tests (for batch validation)
    // ==========================================================================

    #[test]
    fn resolve_servers_single_server() {
        // When a server is specified, should return just that one
        let result = resolve_servers(Some("http://localhost:8080"), None);
        assert!(result.is_ok());
        let specs = result.unwrap();
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].name, "http://localhost:8080");
    }

    #[test]
    fn resolve_servers_npm_package() {
        let result = resolve_servers(Some("@anthropic/mcp-server"), None);
        assert!(result.is_ok());
        let specs = result.unwrap();
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].command, "npx");
    }
}
