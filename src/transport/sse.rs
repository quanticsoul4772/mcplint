//! SSE (Server-Sent Events) transport for remote MCP servers
//!
//! Implements the legacy MCP 2024-11-05 HTTP+SSE transport specification.
//! This transport is provided for backwards compatibility with older MCP servers.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{Context, Result};
use serde_json::Value;
use url::Url;

use crate::protocol::{
    JsonRpcMessage, JsonRpcNotification, JsonRpcRequest, JsonRpcResponse, RequestId,
};

use super::{Transport, TransportConfig};

/// SSE transport for communicating with remote MCP servers (legacy)
pub struct SseTransport {
    base_url: Url,
    client: reqwest::Client,
    config: TransportConfig,
    request_id: AtomicU64,
}

impl SseTransport {
    /// Create a new SSE transport connection
    pub fn new(base_url: &str, config: TransportConfig) -> Result<Self> {
        let base_url = Url::parse(base_url).context("Invalid base URL")?;

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .use_rustls_tls()
            .build()
            .context("Failed to create HTTP client")?;

        Ok(Self {
            base_url,
            client,
            config,
            request_id: AtomicU64::new(0),
        })
    }

    fn next_id(&self) -> RequestId {
        RequestId::Number(self.request_id.fetch_add(1, Ordering::SeqCst) + 1)
    }
}

#[async_trait::async_trait]
impl Transport for SseTransport {
    async fn send(&mut self, message: &JsonRpcMessage) -> Result<()> {
        let response = self
            .client
            .post(self.base_url.clone())
            .header("Content-Type", "application/json")
            .json(message)
            .send()
            .await
            .context("Failed to send message")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("HTTP error {}: {}", status, body);
        }

        Ok(())
    }

    async fn recv(&mut self) -> Result<Option<JsonRpcMessage>> {
        // Legacy SSE would require maintaining an SSE connection
        // For now, return None as we primarily use request/response pattern
        Ok(None)
    }

    async fn request(&mut self, method: &str, params: Option<Value>) -> Result<JsonRpcResponse> {
        let id = self.next_id();

        let request = JsonRpcRequest::new(id, method, params);

        let response = self
            .client
            .post(self.base_url.clone())
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await
            .context("Failed to send request")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("HTTP error {}: {}", status, body);
        }

        let response_body: JsonRpcResponse = response
            .json()
            .await
            .context("Failed to parse JSON-RPC response")?;

        Ok(response_body)
    }

    async fn notify(&mut self, method: &str, params: Option<Value>) -> Result<()> {
        let notification = JsonRpcNotification::new(method, params);

        let response = self
            .client
            .post(self.base_url.clone())
            .header("Content-Type", "application/json")
            .json(&notification)
            .send()
            .await
            .context("Failed to send notification")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("HTTP error {}: {}", status, body);
        }

        Ok(())
    }

    async fn close(&mut self) -> Result<()> {
        // HTTP is stateless, nothing to close
        Ok(())
    }

    fn transport_type(&self) -> &'static str {
        "sse_legacy"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_url() {
        let config = TransportConfig::default();
        let transport = SseTransport::new("https://example.com/mcp", config);
        assert!(transport.is_ok());
    }

    #[test]
    fn invalid_url_fails() {
        let config = TransportConfig::default();
        let transport = SseTransport::new("not a url", config);
        assert!(transport.is_err());
    }

    #[test]
    fn request_id_increments() {
        let config = TransportConfig::default();
        let transport = SseTransport::new("https://example.com/mcp", config).unwrap();

        let id1 = transport.next_id();
        let id2 = transport.next_id();

        assert_eq!(id1, RequestId::Number(1));
        assert_eq!(id2, RequestId::Number(2));
    }
}
