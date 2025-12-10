//! Transport layer for MCP server communication
//!
//! Provides abstractions for communicating with MCP servers over different transports:
//! - `stdio` - Local server communication via stdin/stdout
//! - `streamable_http` - Remote server communication via HTTP (MCP 2025 spec)
//! - `sse` - Legacy SSE transport (MCP 2024-11-05 spec)

#![allow(dead_code)] // Transport layer will be used in M1 (Protocol Validator)

pub mod mock;
pub mod sse;
pub mod stdio;
pub mod streamable_http;

use std::collections::HashMap;

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
            TransportType::SseLegacy => write!(f, "sse_legacy"),
        }
    }
}

/// Detect appropriate transport type based on target string
pub fn detect_transport_type(target: &str) -> TransportType {
    let target_lower = target.to_lowercase();

    if target_lower.starts_with("http://") || target_lower.starts_with("https://") {
        // HTTP URL - prefer Streamable HTTP (2025 spec)
        TransportType::StreamableHttp
    } else {
        // Assume local executable path
        TransportType::Stdio
    }
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

    #[test]
    fn default_config() {
        let config = TransportConfig::default();
        assert_eq!(config.timeout_secs, 30);
        assert_eq!(config.max_message_size, 10 * 1024 * 1024);
    }

    #[test]
    fn transport_type_display() {
        assert_eq!(format!("{}", TransportType::Stdio), "stdio");
        assert_eq!(
            format!("{}", TransportType::StreamableHttp),
            "streamable_http"
        );
        assert_eq!(format!("{}", TransportType::SseLegacy), "sse_legacy");
    }
}
