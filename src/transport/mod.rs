//! Transport layer for MCP server communication

pub mod sse;
pub mod stdio;

use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;

/// MCP transport abstraction
#[allow(dead_code)]
#[async_trait]
pub trait Transport: Send + Sync {
    /// Send a JSON-RPC request and receive a response
    async fn request(&mut self, method: &str, params: Option<Value>) -> Result<Value>;

    /// Send a notification (no response expected)
    async fn notify(&mut self, method: &str, params: Option<Value>) -> Result<()>;

    /// Close the transport
    async fn close(&mut self) -> Result<()>;
}

/// Transport configuration
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct TransportConfig {
    pub timeout_secs: u64,
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
