//! Stdio transport for local MCP servers

use anyhow::{Context, Result};
use serde_json::Value;
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};

use super::{Transport, TransportConfig};

/// Stdio transport for communicating with MCP servers via stdin/stdout
#[allow(dead_code)]
pub struct StdioTransport {
    child: Child,
    config: TransportConfig,
    request_id: u64,
}

#[allow(dead_code)]
impl StdioTransport {
    /// Spawn a new MCP server process
    pub async fn spawn(command: &str, args: &[String], config: TransportConfig) -> Result<Self> {
        let child = Command::new(command)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("Failed to spawn MCP server process")?;

        Ok(Self {
            child,
            config,
            request_id: 0,
        })
    }

    fn next_id(&mut self) -> u64 {
        self.request_id += 1;
        self.request_id
    }
}

#[async_trait::async_trait]
impl Transport for StdioTransport {
    async fn request(&mut self, method: &str, params: Option<Value>) -> Result<Value> {
        let id = self.next_id();

        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params.unwrap_or(Value::Null)
        });

        let stdin = self.child.stdin.as_mut().context("No stdin available")?;
        let request_str = serde_json::to_string(&request)? + "\n";
        stdin.write_all(request_str.as_bytes()).await?;
        stdin.flush().await?;

        let stdout = self.child.stdout.as_mut().context("No stdout available")?;
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();

        // TODO: Add timeout handling
        reader.read_line(&mut line).await?;

        let response: Value = serde_json::from_str(&line)?;

        if let Some(error) = response.get("error") {
            anyhow::bail!("JSON-RPC error: {}", error);
        }

        Ok(response.get("result").cloned().unwrap_or(Value::Null))
    }

    async fn notify(&mut self, method: &str, params: Option<Value>) -> Result<()> {
        let notification = serde_json::json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params.unwrap_or(Value::Null)
        });

        let stdin = self.child.stdin.as_mut().context("No stdin available")?;
        let notification_str = serde_json::to_string(&notification)? + "\n";
        stdin.write_all(notification_str.as_bytes()).await?;
        stdin.flush().await?;

        Ok(())
    }

    async fn close(&mut self) -> Result<()> {
        self.child.kill().await?;
        Ok(())
    }
}
