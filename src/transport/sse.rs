//! SSE (Server-Sent Events) transport for remote MCP servers

use anyhow::{Context, Result};
use serde_json::Value;

use super::{Transport, TransportConfig};

/// SSE transport for communicating with remote MCP servers
pub struct SseTransport {
    base_url: String,
    client: reqwest::Client,
    config: TransportConfig,
    request_id: u64,
}

impl SseTransport {
    /// Create a new SSE transport connection
    pub fn new(base_url: &str, config: TransportConfig) -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(config.timeout_secs))
            .build()
            .context("Failed to create HTTP client")?;

        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client,
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
impl Transport for SseTransport {
    async fn request(&mut self, method: &str, params: Option<Value>) -> Result<Value> {
        let id = self.next_id();

        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params.unwrap_or(Value::Null)
        });

        let response = self
            .client
            .post(&self.base_url)
            .json(&request)
            .send()
            .await
            .context("Failed to send request")?;

        let response_body: Value = response.json().await.context("Failed to parse response")?;

        if let Some(error) = response_body.get("error") {
            anyhow::bail!("JSON-RPC error: {}", error);
        }

        Ok(response_body.get("result").cloned().unwrap_or(Value::Null))
    }

    async fn notify(&mut self, method: &str, params: Option<Value>) -> Result<()> {
        let notification = serde_json::json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params.unwrap_or(Value::Null)
        });

        self.client
            .post(&self.base_url)
            .json(&notification)
            .send()
            .await
            .context("Failed to send notification")?;

        Ok(())
    }

    async fn close(&mut self) -> Result<()> {
        // HTTP is stateless, nothing to close
        Ok(())
    }
}
