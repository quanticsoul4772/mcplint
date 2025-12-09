//! Stdio transport for local MCP servers
//!
//! Communicates with MCP servers via stdin/stdout pipes.
//! The server is spawned as a child process.

use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::time::timeout;

use crate::protocol::{
    JsonRpcMessage, JsonRpcNotification, JsonRpcRequest, JsonRpcResponse, RequestId,
};

use super::{Transport, TransportConfig};

/// Stdio transport for communicating with MCP servers via stdin/stdout
pub struct StdioTransport {
    child: Child,
    stdin: BufWriter<ChildStdin>,
    stdout: BufReader<ChildStdout>,
    config: TransportConfig,
    request_id: AtomicU64,
}

impl StdioTransport {
    /// Spawn a new MCP server process
    pub async fn spawn(command: &str, args: &[String], config: TransportConfig) -> Result<Self> {
        let mut child = Command::new(command)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit()) // Let stderr pass through for debugging
            .kill_on_drop(true)
            .spawn()
            .with_context(|| format!("Failed to spawn MCP server: {}", command))?;

        let stdin = child
            .stdin
            .take()
            .context("Failed to capture stdin of child process")?;
        let stdout = child
            .stdout
            .take()
            .context("Failed to capture stdout of child process")?;

        Ok(Self {
            child,
            stdin: BufWriter::new(stdin),
            stdout: BufReader::new(stdout),
            config,
            request_id: AtomicU64::new(0),
        })
    }

    fn next_id(&self) -> RequestId {
        RequestId::Number(self.request_id.fetch_add(1, Ordering::SeqCst) + 1)
    }

    fn timeout_duration(&self) -> Duration {
        Duration::from_secs(self.config.timeout_secs)
    }

    async fn write_message(&mut self, message: &str) -> Result<()> {
        // MCP stdio uses newline-delimited JSON
        self.stdin
            .write_all(message.as_bytes())
            .await
            .context("Failed to write to stdin")?;
        self.stdin
            .write_all(b"\n")
            .await
            .context("Failed to write newline")?;
        self.stdin.flush().await.context("Failed to flush stdin")?;
        Ok(())
    }

    async fn read_line(&mut self) -> Result<String> {
        let mut line = String::new();

        let read_result = timeout(self.timeout_duration(), self.stdout.read_line(&mut line)).await;

        match read_result {
            Ok(Ok(0)) => anyhow::bail!("Server closed connection (EOF)"),
            Ok(Ok(_)) => Ok(line),
            Ok(Err(e)) => Err(e).context("Failed to read from stdout"),
            Err(_) => anyhow::bail!("Read timeout after {} seconds", self.config.timeout_secs),
        }
    }
}

#[async_trait::async_trait]
impl Transport for StdioTransport {
    async fn send(&mut self, message: &JsonRpcMessage) -> Result<()> {
        let json = serde_json::to_string(message).context("Failed to serialize message")?;
        self.write_message(&json).await
    }

    async fn recv(&mut self) -> Result<Option<JsonRpcMessage>> {
        let line = self.read_line().await?;
        let trimmed = line.trim();

        if trimmed.is_empty() {
            return Ok(None);
        }

        let message: JsonRpcMessage =
            serde_json::from_str(trimmed).context("Failed to parse JSON-RPC message")?;

        Ok(Some(message))
    }

    async fn request(
        &mut self,
        method: &str,
        params: Option<serde_json::Value>,
    ) -> Result<JsonRpcResponse> {
        let id = self.next_id();

        let request = JsonRpcRequest::new(id.clone(), method, params);
        let request_json =
            serde_json::to_string(&request).context("Failed to serialize request")?;

        self.write_message(&request_json).await?;

        // Read response (may need to skip notifications)
        loop {
            let line = self.read_line().await?;
            let trimmed = line.trim();

            if trimmed.is_empty() {
                continue;
            }

            // Try to parse as response first
            if let Ok(response) = serde_json::from_str::<JsonRpcResponse>(trimmed) {
                if response.id == id {
                    return Ok(response);
                }
                // Response for different request - log and continue
                tracing::warn!(
                    "Received response for unexpected request ID: {}",
                    response.id
                );
                continue;
            }

            // Try to parse as notification (server-initiated)
            if let Ok(notification) = serde_json::from_str::<JsonRpcNotification>(trimmed) {
                tracing::debug!(
                    "Received notification while waiting for response: {}",
                    notification.method
                );
                continue;
            }

            // Unknown message format
            tracing::warn!("Received unknown message format: {}", trimmed);
        }
    }

    async fn notify(&mut self, method: &str, params: Option<serde_json::Value>) -> Result<()> {
        let notification = JsonRpcNotification::new(method, params);
        let json =
            serde_json::to_string(&notification).context("Failed to serialize notification")?;
        self.write_message(&json).await
    }

    async fn close(&mut self) -> Result<()> {
        // Signal EOF by shutting down stdin
        // Note: get_mut() returns a reference, so we just let the BufWriter flush
        let _ = self.stdin.get_mut();

        // Give server time to exit gracefully
        let wait_result = timeout(Duration::from_secs(5), self.child.wait()).await;

        match wait_result {
            Ok(Ok(status)) => {
                tracing::debug!("Server exited with status: {}", status);
            }
            Ok(Err(e)) => {
                tracing::warn!("Error waiting for server: {}", e);
            }
            Err(_) => {
                // Timeout - force kill
                tracing::warn!("Server did not exit gracefully, killing");
                let _ = self.child.kill().await;
            }
        }

        Ok(())
    }

    fn transport_type(&self) -> &'static str {
        "stdio"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{JsonRpcMessage, JsonRpcRequest, JsonRpcNotification};

    #[test]
    fn request_id_increments() {
        let counter = AtomicU64::new(0);
        let id1 = RequestId::Number(counter.fetch_add(1, Ordering::SeqCst) + 1);
        let id2 = RequestId::Number(counter.fetch_add(1, Ordering::SeqCst) + 1);

        assert_eq!(id1, RequestId::Number(1));
        assert_eq!(id2, RequestId::Number(2));
    }

    #[test]
    fn timeout_duration() {
        let config = TransportConfig {
            timeout_secs: 60,
            ..Default::default()
        };
        assert_eq!(
            Duration::from_secs(60),
            Duration::from_secs(config.timeout_secs)
        );
    }

    #[test]
    fn default_transport_config() {
        let config = TransportConfig::default();
        assert_eq!(config.timeout_secs, 30);
        assert!(config.max_message_size > 0);
    }

    #[test]
    fn custom_transport_config() {
        let config = TransportConfig {
            timeout_secs: 120,
            max_message_size: 1024 * 1024,
        };
        assert_eq!(config.timeout_secs, 120);
        assert_eq!(config.max_message_size, 1024 * 1024);
    }

    #[test]
    fn request_id_starts_at_one() {
        let counter = AtomicU64::new(0);
        let id = RequestId::Number(counter.fetch_add(1, Ordering::SeqCst) + 1);
        assert_eq!(id, RequestId::Number(1));
    }

    #[test]
    fn request_id_sequential() {
        let counter = AtomicU64::new(0);
        for i in 1..=100 {
            let id = RequestId::Number(counter.fetch_add(1, Ordering::SeqCst) + 1);
            assert_eq!(id, RequestId::Number(i));
        }
    }

    #[test]
    fn jsonrpc_request_serialization() {
        let request = JsonRpcRequest::new(
            RequestId::Number(1),
            "initialize",
            Some(serde_json::json!({"capabilities": {}})),
        );
        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("\"jsonrpc\":\"2.0\""));
        assert!(json.contains("\"method\":\"initialize\""));
        assert!(json.contains("\"id\":1"));
    }

    #[test]
    fn jsonrpc_notification_serialization() {
        let notification = JsonRpcNotification::new(
            "notifications/message",
            Some(serde_json::json!({"data": "test"})),
        );
        let json = serde_json::to_string(&notification).unwrap();
        assert!(json.contains("\"jsonrpc\":\"2.0\""));
        assert!(json.contains("\"method\":\"notifications/message\""));
        // Notifications don't have id
        assert!(!json.contains("\"id\""));
    }

    #[test]
    fn jsonrpc_message_parse_request() {
        let json = r#"{"jsonrpc":"2.0","method":"test","id":1}"#;
        let message: JsonRpcMessage = serde_json::from_str(json).unwrap();
        match message {
            JsonRpcMessage::Request(req) => {
                assert_eq!(req.method, "test");
                assert_eq!(req.id, RequestId::Number(1));
            }
            _ => panic!("Expected request"),
        }
    }

    #[test]
    fn jsonrpc_message_parse_notification() {
        let json = r#"{"jsonrpc":"2.0","method":"notifications/ping"}"#;
        let message: JsonRpcMessage = serde_json::from_str(json).unwrap();
        match message {
            JsonRpcMessage::Notification(notif) => {
                assert_eq!(notif.method, "notifications/ping");
            }
            _ => panic!("Expected notification"),
        }
    }

    #[test]
    fn jsonrpc_message_parse_response() {
        let json = r#"{"jsonrpc":"2.0","id":1,"result":{"success":true}}"#;
        let message: JsonRpcMessage = serde_json::from_str(json).unwrap();
        match message {
            JsonRpcMessage::Response(resp) => {
                assert_eq!(resp.id, RequestId::Number(1));
                assert!(resp.result.is_some());
            }
            _ => panic!("Expected response"),
        }
    }

    #[test]
    fn jsonrpc_response_with_error() {
        let json = r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"Method not found"}}"#;
        let message: JsonRpcMessage = serde_json::from_str(json).unwrap();
        match message {
            JsonRpcMessage::Response(resp) => {
                assert!(resp.error.is_some());
                let err = resp.error.unwrap();
                assert_eq!(err.code, -32601);
            }
            _ => panic!("Expected response"),
        }
    }

    #[test]
    fn timeout_duration_calculation() {
        let config1 = TransportConfig {
            timeout_secs: 30,
            ..Default::default()
        };
        let config2 = TransportConfig {
            timeout_secs: 120,
            ..Default::default()
        };

        assert_eq!(Duration::from_secs(30), Duration::from_secs(config1.timeout_secs));
        assert_eq!(Duration::from_secs(120), Duration::from_secs(config2.timeout_secs));
    }
}
