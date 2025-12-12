//! Transport layer for MCP server communication
//!
//! Provides abstractions for communicating with MCP servers over different transports:
//! - `stdio` - Local server communication via stdin/stdout
//! - `streamable_http` - Remote server communication via HTTP (MCP 2025 spec)
//! - `sse` - Legacy SSE transport (MCP 2024-11-05 spec)
//!
//! # Transport Selection Algorithm (ADR-001)
//!
//! Transport is selected using the following priority:
//! 1. Explicit override via `--transport` flag
//! 2. URL detection (http:// or https://)
//!    - "/sse" path or "sse" query param → SSE
//!    - Otherwise → StreamableHttp
//! 3. Config-based: `transport` field in server config
//! 4. File-based: Local file paths → Stdio
//! 5. NPM packages (starts with "@") → Stdio
//! 6. Default: Stdio

#![allow(dead_code)] // Transport layer will be used in M1 (Protocol Validator)

pub mod mock;
pub mod sse;
pub mod stdio;
pub mod streamable_http;

use std::collections::HashMap;
use std::str::FromStr;

use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;

use crate::protocol::{JsonRpcMessage, JsonRpcResponse};

// Re-export transport implementations
pub use sse::SseTransport;
pub use stdio::StdioTransport;
pub use streamable_http::StreamableHttpTransport;

/// MCP transport abstraction
#[async_trait]
pub trait Transport: Send + Sync {
    /// Send a raw JSON-RPC message
    async fn send(&mut self, message: &JsonRpcMessage) -> Result<()>;

    /// Receive next message (may return None if no message available)
    async fn recv(&mut self) -> Result<Option<JsonRpcMessage>>;

    /// Send a JSON-RPC request and receive a response
    async fn request(&mut self, method: &str, params: Option<Value>) -> Result<JsonRpcResponse>;

    /// Send a notification (no response expected)
    async fn notify(&mut self, method: &str, params: Option<Value>) -> Result<()>;

    /// Close the transport
    async fn close(&mut self) -> Result<()>;

    /// Get transport type name for logging/debugging
    fn transport_type(&self) -> &'static str;
}

/// Transport configuration
#[derive(Debug, Clone)]
pub struct TransportConfig {
    /// Timeout for operations in seconds
    pub timeout_secs: u64,
    /// Maximum message size in bytes
    pub max_message_size: usize,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            timeout_secs: 30,
            max_message_size: 10 * 1024 * 1024, // 10MB
        }
    }
}

/// Detected transport type based on target
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportType {
    /// Local stdio transport (spawn child process)
    Stdio,
    /// Streamable HTTP transport (MCP 2025 spec)
    StreamableHttp,
    /// Legacy SSE transport (MCP 2024-11-05 spec)
    SseLegacy,
}

impl std::fmt::Display for TransportType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportType::Stdio => write!(f, "stdio"),
            TransportType::StreamableHttp => write!(f, "streamable_http"),
            TransportType::SseLegacy => write!(f, "sse"),
        }
    }
}

impl FromStr for TransportType {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "stdio" => Ok(TransportType::Stdio),
            "http" | "streamable_http" | "streamablehttp" => Ok(TransportType::StreamableHttp),
            "sse" | "sse_legacy" | "sselegacy" => Ok(TransportType::SseLegacy),
            _ => Err(anyhow::anyhow!(
                "Unknown transport type: '{}'. Valid options: stdio, http, sse",
                s
            )),
        }
    }
}

/// Server configuration for transport detection
#[derive(Debug, Clone, Default)]
pub struct ServerTransportConfig {
    /// Explicit transport type from config
    pub transport: Option<String>,
    /// Command to spawn (for detecting if it's a URL)
    pub command: Option<String>,
}

/// Detect appropriate transport type based on target string (simple version)
///
/// For advanced detection with config and explicit override, use `detect_transport_type_full`.
pub fn detect_transport_type(target: &str) -> TransportType {
    detect_transport_type_full(target, None, None)
}

/// Detect appropriate transport type with full ADR-001 algorithm
///
/// # Arguments
/// * `target` - Server specification (path, URL, or npm package)
/// * `config` - Optional server configuration from config file
/// * `explicit` - Explicit transport override from --transport flag
///
/// # Algorithm (ADR-001)
/// 1. Explicit override (--transport flag)
/// 2. URL detection (http:// or https://)
///    - "/sse" path or "sse" query param → SSE
///    - Otherwise → StreamableHttp
/// 3. Config-based: `transport` field in server config
/// 4. File-based: Local file paths → Stdio
/// 5. NPM packages (starts with "@") → Stdio
/// 6. Default: Stdio
pub fn detect_transport_type_full(
    target: &str,
    config: Option<&ServerTransportConfig>,
    explicit: Option<TransportType>,
) -> TransportType {
    // 1. Explicit override takes highest priority
    if let Some(t) = explicit {
        return t;
    }

    // 2. URL detection
    let target_lower = target.to_lowercase();
    if target_lower.starts_with("http://") || target_lower.starts_with("https://") {
        return detect_http_transport_type(target);
    }

    // 3. Config-based detection
    if let Some(cfg) = config {
        // Check explicit transport in config
        if let Some(ref t) = cfg.transport {
            if let Ok(transport) = t.parse::<TransportType>() {
                return transport;
            }
        }

        // Check if command is a URL
        if let Some(ref cmd) = cfg.command {
            let cmd_lower = cmd.to_lowercase();
            if cmd_lower.starts_with("http://") || cmd_lower.starts_with("https://") {
                return detect_http_transport_type(cmd);
            }
        }
    }

    // 4 & 5. File-based and NPM packages → Stdio
    // 6. Default → Stdio
    TransportType::Stdio
}

/// Detect HTTP transport type (StreamableHttp vs SSE) from URL
///
/// Uses URL patterns to determine transport:
/// - Path ends with "/sse" → SSE
/// - Query contains "sse" → SSE
/// - Otherwise → StreamableHttp (MCP 2025 spec default)
fn detect_http_transport_type(url: &str) -> TransportType {
    let url_lower = url.to_lowercase();

    // Check for SSE indicators in path
    if url_lower.contains("/sse") {
        return TransportType::SseLegacy;
    }

    // Check for SSE in query parameters
    if let Some(query_start) = url_lower.find('?') {
        let query = &url_lower[query_start..];
        if query.contains("sse") {
            return TransportType::SseLegacy;
        }
    }

    // Default to StreamableHttp (MCP 2025 spec)
    TransportType::StreamableHttp
}

/// Connect to an MCP server with auto-detection
///
/// # Arguments
/// * `target` - Server target (path for stdio, URL for HTTP)
/// * `args` - Arguments for stdio transport (ignored for HTTP)
/// * `env` - Environment variables for stdio transport (ignored for HTTP)
/// * `config` - Transport configuration
///
/// # Returns
/// A boxed transport implementation
#[allow(dead_code)]
pub async fn connect(
    target: &str,
    args: &[String],
    env: &HashMap<String, String>,
    config: TransportConfig,
) -> Result<Box<dyn Transport>> {
    let transport_type = detect_transport_type(target);
    connect_with_type(target, args, env, config, transport_type).await
}

/// Connect to an MCP server with explicit transport type
#[allow(dead_code)]
pub async fn connect_with_type(
    target: &str,
    args: &[String],
    env: &HashMap<String, String>,
    config: TransportConfig,
    transport_type: TransportType,
) -> Result<Box<dyn Transport>> {
    match transport_type {
        TransportType::Stdio => {
            let transport = StdioTransport::spawn(target, args, env, config).await?;
            Ok(Box::new(transport))
        }
        TransportType::StreamableHttp => {
            let transport = StreamableHttpTransport::new(target, config)?;
            Ok(Box::new(transport))
        }
        TransportType::SseLegacy => {
            let transport = SseTransport::new(target, config)?;
            Ok(Box::new(transport))
        }
    }
}

/// Try Streamable HTTP first, fall back to SSE legacy on failure
///
/// Per MCP spec backwards compatibility guidance:
/// 1. Attempt POST InitializeRequest with Accept header
/// 2. If succeeds (or 4xx failure) → new Streamable HTTP transport
/// 3. If fails with 4xx → Issue GET expecting `endpoint` event → old HTTP+SSE transport
#[allow(dead_code)]
pub async fn connect_http_with_fallback(
    target: &str,
    config: TransportConfig,
) -> Result<Box<dyn Transport>> {
    // Try Streamable HTTP first
    let streamable = StreamableHttpTransport::new(target, config.clone())?;

    // For now, just return Streamable HTTP - full fallback logic would require
    // attempting an actual request and checking for specific error patterns
    // This can be enhanced later if needed for compatibility with older servers

    Ok(Box::new(streamable))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==========================================================================
    // Basic Transport Detection Tests (simple version)
    // ==========================================================================

    #[test]
    fn detect_stdio_for_path() {
        assert_eq!(detect_transport_type("./server"), TransportType::Stdio);
        assert_eq!(detect_transport_type("python"), TransportType::Stdio);
        assert_eq!(detect_transport_type("npx"), TransportType::Stdio);
        assert_eq!(
            detect_transport_type("/usr/bin/mcp-server"),
            TransportType::Stdio
        );
    }

    #[test]
    fn detect_http_for_url() {
        assert_eq!(
            detect_transport_type("http://localhost:8080/mcp"),
            TransportType::StreamableHttp
        );
        assert_eq!(
            detect_transport_type("https://api.example.com/mcp"),
            TransportType::StreamableHttp
        );
        assert_eq!(
            detect_transport_type("HTTP://EXAMPLE.COM"),
            TransportType::StreamableHttp
        );
    }

    // ==========================================================================
    // SSE Detection Tests (ADR-001)
    // ==========================================================================

    #[test]
    fn detect_sse_for_sse_path() {
        assert_eq!(
            detect_transport_type("http://localhost:8080/sse"),
            TransportType::SseLegacy
        );
        assert_eq!(
            detect_transport_type("https://api.example.com/mcp/sse"),
            TransportType::SseLegacy
        );
        assert_eq!(
            detect_transport_type("http://localhost/v1/sse/events"),
            TransportType::SseLegacy
        );
    }

    #[test]
    fn detect_sse_for_sse_query_param() {
        assert_eq!(
            detect_transport_type("http://localhost:8080/mcp?transport=sse"),
            TransportType::SseLegacy
        );
        assert_eq!(
            detect_transport_type("https://api.example.com/mcp?mode=sse&version=1"),
            TransportType::SseLegacy
        );
    }

    // ==========================================================================
    // Full Transport Detection Tests (ADR-001 algorithm)
    // ==========================================================================

    #[test]
    fn detect_full_explicit_override_takes_priority() {
        // Explicit override should beat URL detection
        assert_eq!(
            detect_transport_type_full(
                "http://localhost:8080/mcp",
                None,
                Some(TransportType::Stdio)
            ),
            TransportType::Stdio
        );

        // Explicit override should beat config
        let config = ServerTransportConfig {
            transport: Some("sse".to_string()),
            command: None,
        };
        assert_eq!(
            detect_transport_type_full(
                "server.js",
                Some(&config),
                Some(TransportType::StreamableHttp)
            ),
            TransportType::StreamableHttp
        );
    }

    #[test]
    fn detect_full_url_detection() {
        assert_eq!(
            detect_transport_type_full("http://localhost/mcp", None, None),
            TransportType::StreamableHttp
        );
        assert_eq!(
            detect_transport_type_full("https://localhost/sse", None, None),
            TransportType::SseLegacy
        );
    }

    #[test]
    fn detect_full_config_transport_field() {
        let config = ServerTransportConfig {
            transport: Some("sse".to_string()),
            command: Some("node".to_string()),
        };
        assert_eq!(
            detect_transport_type_full("my-server", Some(&config), None),
            TransportType::SseLegacy
        );
    }

    #[test]
    fn detect_full_config_command_url() {
        let config = ServerTransportConfig {
            transport: None,
            command: Some("https://api.example.com/mcp".to_string()),
        };
        assert_eq!(
            detect_transport_type_full("remote-server", Some(&config), None),
            TransportType::StreamableHttp
        );
    }

    #[test]
    fn detect_full_default_stdio() {
        assert_eq!(
            detect_transport_type_full("server.js", None, None),
            TransportType::Stdio
        );
        assert_eq!(
            detect_transport_type_full("@modelcontextprotocol/server", None, None),
            TransportType::Stdio
        );
    }

    // ==========================================================================
    // FromStr Tests
    // ==========================================================================

    #[test]
    fn transport_type_from_str() {
        assert_eq!(
            "stdio".parse::<TransportType>().unwrap(),
            TransportType::Stdio
        );
        assert_eq!(
            "http".parse::<TransportType>().unwrap(),
            TransportType::StreamableHttp
        );
        assert_eq!(
            "streamable_http".parse::<TransportType>().unwrap(),
            TransportType::StreamableHttp
        );
        assert_eq!(
            "sse".parse::<TransportType>().unwrap(),
            TransportType::SseLegacy
        );
        assert_eq!(
            "sse_legacy".parse::<TransportType>().unwrap(),
            TransportType::SseLegacy
        );
    }

    #[test]
    fn transport_type_from_str_case_insensitive() {
        assert_eq!(
            "STDIO".parse::<TransportType>().unwrap(),
            TransportType::Stdio
        );
        assert_eq!(
            "HTTP".parse::<TransportType>().unwrap(),
            TransportType::StreamableHttp
        );
        assert_eq!(
            "SSE".parse::<TransportType>().unwrap(),
            TransportType::SseLegacy
        );
    }

    #[test]
    fn transport_type_from_str_invalid() {
        assert!("invalid".parse::<TransportType>().is_err());
        assert!("websocket".parse::<TransportType>().is_err());
        assert!("".parse::<TransportType>().is_err());
    }

    // ==========================================================================
    // Display Tests
    // ==========================================================================

    #[test]
    fn transport_type_display() {
        assert_eq!(format!("{}", TransportType::Stdio), "stdio");
        assert_eq!(
            format!("{}", TransportType::StreamableHttp),
            "streamable_http"
        );
        assert_eq!(format!("{}", TransportType::SseLegacy), "sse");
    }

    // ==========================================================================
    // Config Tests
    // ==========================================================================

    #[test]
    fn default_config() {
        let config = TransportConfig::default();
        assert_eq!(config.timeout_secs, 30);
        assert_eq!(config.max_message_size, 10 * 1024 * 1024);
    }

    #[test]
    fn server_transport_config_default() {
        let config = ServerTransportConfig::default();
        assert!(config.transport.is_none());
        assert!(config.command.is_none());
    }

    // ==========================================================================
    // Edge Cases
    // ==========================================================================

    #[test]
    fn detect_mixed_case_urls() {
        assert_eq!(
            detect_transport_type("HTTP://LOCALHOST/MCP"),
            TransportType::StreamableHttp
        );
        assert_eq!(
            detect_transport_type("HTTPS://LOCALHOST/SSE"),
            TransportType::SseLegacy
        );
    }

    #[test]
    fn detect_npm_packages() {
        assert_eq!(
            detect_transport_type("@modelcontextprotocol/server-filesystem"),
            TransportType::Stdio
        );
        assert_eq!(
            detect_transport_type("@anthropic/mcp-server"),
            TransportType::Stdio
        );
    }

    #[test]
    fn detect_local_paths() {
        assert_eq!(detect_transport_type("./server.js"), TransportType::Stdio);
        assert_eq!(
            detect_transport_type("../path/to/server"),
            TransportType::Stdio
        );
        assert_eq!(
            detect_transport_type("C:\\path\\to\\server.exe"),
            TransportType::Stdio
        );
    }

    // ==========================================================================
    // Additional TransportType Tests
    // ==========================================================================

    #[test]
    fn transport_type_equality() {
        assert_eq!(TransportType::Stdio, TransportType::Stdio);
        assert_eq!(TransportType::StreamableHttp, TransportType::StreamableHttp);
        assert_eq!(TransportType::SseLegacy, TransportType::SseLegacy);
        assert_ne!(TransportType::Stdio, TransportType::StreamableHttp);
        assert_ne!(TransportType::Stdio, TransportType::SseLegacy);
        assert_ne!(TransportType::StreamableHttp, TransportType::SseLegacy);
    }

    #[test]
    fn transport_type_copy_clone() {
        let t1 = TransportType::Stdio;
        let t2 = t1; // Copy
        let t3 = t1; // Copy again (type implements Copy)
        assert_eq!(t1, t2);
        assert_eq!(t1, t3);
    }

    #[test]
    fn transport_type_debug() {
        let debug_str = format!("{:?}", TransportType::Stdio);
        assert!(debug_str.contains("Stdio"));
    }

    #[test]
    fn transport_type_from_str_variants() {
        // Test all accepted variants
        assert_eq!(
            "streamablehttp".parse::<TransportType>().unwrap(),
            TransportType::StreamableHttp
        );
        assert_eq!(
            "sselegacy".parse::<TransportType>().unwrap(),
            TransportType::SseLegacy
        );
    }

    #[test]
    fn transport_type_from_str_error_message() {
        let err = "invalid_transport".parse::<TransportType>().unwrap_err();
        let msg = format!("{}", err);
        assert!(msg.contains("Unknown transport type"));
        assert!(msg.contains("invalid_transport"));
        assert!(msg.contains("stdio"));
        assert!(msg.contains("http"));
        assert!(msg.contains("sse"));
    }

    // ==========================================================================
    // TransportConfig Tests
    // ==========================================================================

    #[test]
    fn transport_config_custom() {
        let config = TransportConfig {
            timeout_secs: 60,
            max_message_size: 5 * 1024 * 1024,
        };
        assert_eq!(config.timeout_secs, 60);
        assert_eq!(config.max_message_size, 5 * 1024 * 1024);
    }

    #[test]
    fn transport_config_clone() {
        let config1 = TransportConfig::default();
        let config2 = config1.clone();
        assert_eq!(config1.timeout_secs, config2.timeout_secs);
        assert_eq!(config1.max_message_size, config2.max_message_size);
    }

    #[test]
    fn transport_config_debug() {
        let config = TransportConfig::default();
        let debug_str = format!("{:?}", config);
        assert!(debug_str.contains("timeout_secs"));
        assert!(debug_str.contains("max_message_size"));
    }

    // ==========================================================================
    // ServerTransportConfig Tests
    // ==========================================================================

    #[test]
    fn server_transport_config_with_transport() {
        let config = ServerTransportConfig {
            transport: Some("http".to_string()),
            command: None,
        };
        assert_eq!(config.transport.as_deref(), Some("http"));
        assert!(config.command.is_none());
    }

    #[test]
    fn server_transport_config_with_command() {
        let config = ServerTransportConfig {
            transport: None,
            command: Some("python server.py".to_string()),
        };
        assert!(config.transport.is_none());
        assert_eq!(config.command.as_deref(), Some("python server.py"));
    }

    #[test]
    fn server_transport_config_clone() {
        let config1 = ServerTransportConfig {
            transport: Some("sse".to_string()),
            command: Some("node server.js".to_string()),
        };
        let config2 = config1.clone();
        assert_eq!(config1.transport, config2.transport);
        assert_eq!(config1.command, config2.command);
    }

    #[test]
    fn server_transport_config_debug() {
        let config = ServerTransportConfig {
            transport: Some("stdio".to_string()),
            command: Some("test".to_string()),
        };
        let debug_str = format!("{:?}", config);
        assert!(debug_str.contains("transport"));
        assert!(debug_str.contains("command"));
    }

    // ==========================================================================
    // Advanced Detection Tests
    // ==========================================================================

    #[test]
    fn detect_full_invalid_config_transport() {
        let config = ServerTransportConfig {
            transport: Some("invalid_type".to_string()),
            command: Some("node".to_string()),
        };
        // Should fall through to default when transport parse fails
        assert_eq!(
            detect_transport_type_full("my-server", Some(&config), None),
            TransportType::Stdio
        );
    }

    #[test]
    fn detect_full_config_command_sse_url() {
        let config = ServerTransportConfig {
            transport: None,
            command: Some("https://api.example.com/mcp/sse".to_string()),
        };
        assert_eq!(
            detect_transport_type_full("remote-server", Some(&config), None),
            TransportType::SseLegacy
        );
    }

    #[test]
    fn detect_full_explicit_overrides_everything() {
        let config = ServerTransportConfig {
            transport: Some("http".to_string()),
            command: Some("https://example.com/sse".to_string()),
        };
        // Explicit should override both config and URL detection
        assert_eq!(
            detect_transport_type_full(
                "https://other.com/sse",
                Some(&config),
                Some(TransportType::Stdio)
            ),
            TransportType::Stdio
        );
    }

    #[test]
    fn detect_full_empty_config() {
        let config = ServerTransportConfig {
            transport: None,
            command: None,
        };
        assert_eq!(
            detect_transport_type_full("server.js", Some(&config), None),
            TransportType::Stdio
        );
    }

    // ==========================================================================
    // HTTP Transport Detection Edge Cases
    // ==========================================================================

    #[test]
    fn detect_http_sse_in_path_multiple_times() {
        assert_eq!(
            detect_transport_type("http://localhost/sse/v1/sse"),
            TransportType::SseLegacy
        );
    }

    #[test]
    fn detect_http_case_variations() {
        assert_eq!(
            detect_transport_type("HtTp://localhost/mcp"),
            TransportType::StreamableHttp
        );
        assert_eq!(
            detect_transport_type("HtTpS://localhost/SSE"),
            TransportType::SseLegacy
        );
    }

    #[test]
    fn detect_http_query_multiple_params() {
        assert_eq!(
            detect_transport_type("http://localhost/mcp?foo=bar&sse=true&baz=qux"),
            TransportType::SseLegacy
        );
        assert_eq!(
            detect_transport_type("http://localhost/mcp?foo=bar&baz=qux"),
            TransportType::StreamableHttp
        );
    }

    #[test]
    fn detect_http_query_sse_in_value() {
        assert_eq!(
            detect_transport_type("http://localhost/mcp?mode=sse"),
            TransportType::SseLegacy
        );
    }

    #[test]
    fn detect_http_complex_urls() {
        // Port numbers
        assert_eq!(
            detect_transport_type("http://localhost:8080/mcp"),
            TransportType::StreamableHttp
        );
        assert_eq!(
            detect_transport_type("https://api.example.com:443/sse"),
            TransportType::SseLegacy
        );

        // Subdomains
        assert_eq!(
            detect_transport_type("https://api.subdomain.example.com/mcp"),
            TransportType::StreamableHttp
        );

        // Fragment identifiers
        assert_eq!(
            detect_transport_type("http://localhost/mcp#section"),
            TransportType::StreamableHttp
        );
        assert_eq!(
            detect_transport_type("http://localhost/sse#section"),
            TransportType::SseLegacy
        );
    }

    // ==========================================================================
    // Non-URL Path Detection
    // ==========================================================================

    #[test]
    fn detect_absolute_unix_paths() {
        assert_eq!(
            detect_transport_type("/usr/local/bin/mcp-server"),
            TransportType::Stdio
        );
        assert_eq!(
            detect_transport_type("/home/user/.local/bin/server"),
            TransportType::Stdio
        );
    }

    #[test]
    fn detect_windows_paths() {
        assert_eq!(
            detect_transport_type("C:\\Program Files\\Server\\server.exe"),
            TransportType::Stdio
        );
        assert_eq!(
            detect_transport_type("D:\\servers\\mcp.exe"),
            TransportType::Stdio
        );
    }

    #[test]
    fn detect_relative_paths() {
        assert_eq!(detect_transport_type("./server"), TransportType::Stdio);
        assert_eq!(detect_transport_type("../server"), TransportType::Stdio);
        assert_eq!(
            detect_transport_type("../../bin/server"),
            TransportType::Stdio
        );
    }

    #[test]
    fn detect_bare_commands() {
        assert_eq!(detect_transport_type("node"), TransportType::Stdio);
        assert_eq!(detect_transport_type("python"), TransportType::Stdio);
        assert_eq!(detect_transport_type("npx"), TransportType::Stdio);
        assert_eq!(detect_transport_type("uvx"), TransportType::Stdio);
    }

    #[test]
    fn detect_scoped_npm_packages() {
        assert_eq!(
            detect_transport_type("@modelcontextprotocol/server-everything"),
            TransportType::Stdio
        );
        assert_eq!(
            detect_transport_type("@anthropic/sdk"),
            TransportType::Stdio
        );
    }

    // ==========================================================================
    // Edge Cases and Boundary Conditions
    // ==========================================================================

    #[test]
    fn detect_empty_string() {
        // Empty string should default to stdio
        assert_eq!(detect_transport_type(""), TransportType::Stdio);
    }

    #[test]
    fn detect_whitespace_only() {
        assert_eq!(detect_transport_type("   "), TransportType::Stdio);
        assert_eq!(detect_transport_type("\t\n"), TransportType::Stdio);
    }

    #[test]
    fn detect_url_like_but_not_http() {
        // These look like URLs but don't start with http(s)
        assert_eq!(
            detect_transport_type("ftp://example.com/mcp"),
            TransportType::Stdio
        );
        assert_eq!(
            detect_transport_type("ws://example.com/mcp"),
            TransportType::Stdio
        );
        assert_eq!(
            detect_transport_type("file:///path/to/server"),
            TransportType::Stdio
        );
    }

    #[test]
    fn detect_http_in_middle_of_string() {
        // "http://" not at start should be stdio
        assert_eq!(
            detect_transport_type("server http://example.com"),
            TransportType::Stdio
        );
    }

    #[test]
    fn detect_partial_url() {
        // URLs with http:// or https:// prefix are detected as HTTP transports
        // even if incomplete - transport creation will handle validation
        assert_eq!(
            detect_transport_type("http://"),
            TransportType::StreamableHttp
        );
        assert_eq!(
            detect_transport_type("https://"),
            TransportType::StreamableHttp
        );
        // Without :// it's not detected as URL, defaults to Stdio
        assert_eq!(detect_transport_type("http:"), TransportType::Stdio);
    }
}
