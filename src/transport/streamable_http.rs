//! Streamable HTTP transport for remote MCP servers
//!
//! Implements the MCP 2025-03-26 Streamable HTTP transport specification.
//! Supports session management, SSE response streaming, and proper header handling.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{Context, Result};
use reqwest::header::{HeaderMap, ACCEPT, CONTENT_TYPE};
use serde_json::Value;
use url::Url;

use crate::protocol::{
    JsonRpcMessage, JsonRpcNotification, JsonRpcRequest, JsonRpcResponse, RequestId,
};

use super::{Transport, TransportConfig};

/// HTTP header for MCP session ID
const MCP_SESSION_ID_HEADER: &str = "Mcp-Session-Id";

/// Streamable HTTP transport for remote MCP servers
#[derive(Debug)]
pub struct StreamableHttpTransport {
    endpoint: Url,
    #[allow(dead_code)]
    client: reqwest::Client,
    session_id: Option<String>,
    config: TransportConfig,
    request_id: AtomicU64,
}

impl StreamableHttpTransport {
    /// Create a new Streamable HTTP transport
    pub fn new(endpoint: &str, config: TransportConfig) -> Result<Self> {
        let endpoint = Url::parse(endpoint).context("Invalid endpoint URL")?;

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .use_rustls_tls()
            .build()
            .context("Failed to create HTTP client")?;

        Ok(Self {
            endpoint,
            client,
            session_id: None,
            config,
            request_id: AtomicU64::new(0),
        })
    }

    /// Create with custom reqwest client (for testing or custom TLS)
    pub fn with_client(
        endpoint: &str,
        client: reqwest::Client,
        config: TransportConfig,
    ) -> Result<Self> {
        let endpoint = Url::parse(endpoint).context("Invalid endpoint URL")?;

        Ok(Self {
            endpoint,
            client,
            session_id: None,
            config,
            request_id: AtomicU64::new(0),
        })
    }

    fn next_id(&self) -> RequestId {
        RequestId::Number(self.request_id.fetch_add(1, Ordering::SeqCst) + 1)
    }

    /// Get current session ID if established
    pub fn session_id(&self) -> Option<&str> {
        self.session_id.as_deref()
    }

    /// Build request with required headers
    fn build_request(&self) -> reqwest::RequestBuilder {
        let mut builder = self
            .client
            .post(self.endpoint.clone())
            .header(ACCEPT, "application/json, text/event-stream")
            .header(CONTENT_TYPE, "application/json");

        // Include session ID if we have one
        if let Some(ref session_id) = self.session_id {
            builder = builder.header(MCP_SESSION_ID_HEADER, session_id);
        }

        builder
    }

    /// Extract session ID from response headers
    fn extract_session_id(&mut self, headers: &HeaderMap) {
        if let Some(session_id) = headers.get(MCP_SESSION_ID_HEADER) {
            if let Ok(id) = session_id.to_str() {
                self.session_id = Some(id.to_string());
                tracing::debug!("Established session: {}", id);
            }
        }
    }

    /// Parse SSE stream for JSON-RPC response
    async fn parse_sse_response(&self, text: &str) -> Result<JsonRpcResponse> {
        for line in text.lines() {
            let line = line.trim();

            // SSE data lines start with "data: "
            if let Some(data) = line.strip_prefix("data: ") {
                // Skip empty data
                if data.is_empty() || data == "[DONE]" {
                    continue;
                }

                // Try to parse as JSON-RPC response
                if let Ok(response) = serde_json::from_str::<JsonRpcResponse>(data) {
                    return Ok(response);
                }

                // Could also be a notification or request from server - log and continue
                if let Ok(notification) = serde_json::from_str::<JsonRpcNotification>(data) {
                    tracing::debug!(
                        "Received notification in SSE stream: {}",
                        notification.method
                    );
                    continue;
                }
            }
        }

        anyhow::bail!("No valid JSON-RPC response found in SSE stream")
    }
}

#[async_trait::async_trait]
impl Transport for StreamableHttpTransport {
    async fn send(&mut self, message: &JsonRpcMessage) -> Result<()> {
        let builder = self.build_request();

        let response = builder
            .json(message)
            .send()
            .await
            .context("Failed to send message")?;

        // Check for session expiry
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            self.session_id = None;
            anyhow::bail!("Session expired (404), re-initialization required");
        }

        // Extract session ID if present
        self.extract_session_id(response.headers());

        // For notifications and pure sends, we expect 202 Accepted or similar
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("HTTP error {}: {}", status, body);
        }

        Ok(())
    }

    async fn recv(&mut self) -> Result<Option<JsonRpcMessage>> {
        // Streamable HTTP doesn't support passive receive without GET stream
        // This would require establishing a separate SSE connection
        // For now, return None as we primarily use request/response pattern
        Ok(None)
    }

    async fn request(&mut self, method: &str, params: Option<Value>) -> Result<JsonRpcResponse> {
        let id = self.next_id();
        let request = JsonRpcRequest::new(id.clone(), method, params);

        let builder = self.build_request();

        let response = builder
            .json(&request)
            .send()
            .await
            .context("Failed to send request")?;

        // Check for session expiry
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            self.session_id = None;
            anyhow::bail!("Session expired (404), re-initialization required");
        }

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("HTTP error {}: {}", status, body);
        }

        // Extract session ID (especially important for initialize response)
        self.extract_session_id(response.headers());

        // Check content type to determine response format
        let content_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        if content_type.starts_with("text/event-stream") {
            // Parse SSE stream
            let text = response.text().await.context("Failed to read SSE body")?;
            self.parse_sse_response(&text).await
        } else {
            // Direct JSON response
            response
                .json()
                .await
                .context("Failed to parse JSON response")
        }
    }

    async fn notify(&mut self, method: &str, params: Option<Value>) -> Result<()> {
        let notification = JsonRpcNotification::new(method, params);

        let builder = self.build_request();

        let response = builder
            .json(&notification)
            .send()
            .await
            .context("Failed to send notification")?;

        // Check for session expiry
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            self.session_id = None;
            anyhow::bail!("Session expired (404), re-initialization required");
        }

        // Notifications should return 202 Accepted (or 200 OK)
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("HTTP error {}: {}", status, body);
        }

        Ok(())
    }

    async fn close(&mut self) -> Result<()> {
        // If we have a session, try to terminate it with DELETE
        if let Some(ref session_id) = self.session_id {
            let result = self
                .client
                .delete(self.endpoint.clone())
                .header(MCP_SESSION_ID_HEADER, session_id)
                .send()
                .await;

            match result {
                Ok(response) => {
                    // 405 Method Not Allowed is acceptable (server doesn't support session termination)
                    if response.status() == reqwest::StatusCode::METHOD_NOT_ALLOWED {
                        tracing::debug!("Server does not support session termination");
                    } else if response.status().is_success() {
                        tracing::debug!("Session terminated successfully");
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to terminate session: {}", e);
                }
            }
        }

        self.session_id = None;
        Ok(())
    }

    fn transport_type(&self) -> &'static str {
        "streamable_http"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_endpoint_url() {
        let config = TransportConfig::default();
        let transport = StreamableHttpTransport::new("https://example.com/mcp", config);
        assert!(transport.is_ok());

        let transport = transport.unwrap();
        assert_eq!(transport.endpoint.as_str(), "https://example.com/mcp");
    }

    #[test]
    fn invalid_url_fails() {
        let config = TransportConfig::default();
        let transport = StreamableHttpTransport::new("not a url", config);
        assert!(transport.is_err());
    }

    #[test]
    fn request_id_increments() {
        let config = TransportConfig::default();
        let transport = StreamableHttpTransport::new("https://example.com/mcp", config).unwrap();

        let id1 = transport.next_id();
        let id2 = transport.next_id();

        assert_eq!(id1, RequestId::Number(1));
        assert_eq!(id2, RequestId::Number(2));
    }

    #[test]
    fn no_session_initially() {
        let config = TransportConfig::default();
        let transport = StreamableHttpTransport::new("https://example.com/mcp", config).unwrap();
        assert!(transport.session_id().is_none());
    }

    #[tokio::test]
    async fn parse_sse_response_extracts_json() {
        let config = TransportConfig::default();
        let transport = StreamableHttpTransport::new("https://example.com/mcp", config).unwrap();

        let sse_text = r#"event: message
data: {"jsonrpc":"2.0","id":1,"result":{"status":"ok"}}

"#;

        let response = transport.parse_sse_response(sse_text).await.unwrap();
        assert_eq!(response.id, RequestId::Number(1));
        assert!(response.is_success());
    }

    // ==========================================================================
    // Additional Tests for Coverage
    // ==========================================================================

    #[test]
    fn parse_endpoint_with_port() {
        let config = TransportConfig::default();
        let transport = StreamableHttpTransport::new("https://example.com:8080/mcp", config);
        assert!(transport.is_ok());
        let transport = transport.unwrap();
        assert_eq!(transport.endpoint.as_str(), "https://example.com:8080/mcp");
    }

    #[test]
    fn parse_endpoint_with_query() {
        let config = TransportConfig::default();
        let transport = StreamableHttpTransport::new("https://example.com/mcp?key=value", config);
        assert!(transport.is_ok());
        let transport = transport.unwrap();
        assert_eq!(
            transport.endpoint.as_str(),
            "https://example.com/mcp?key=value"
        );
    }

    #[test]
    fn parse_endpoint_complex_path() {
        let config = TransportConfig::default();
        let transport = StreamableHttpTransport::new("https://api.example.com/v1/mcp", config);
        assert!(transport.is_ok());
        let transport = transport.unwrap();
        assert_eq!(
            transport.endpoint.as_str(),
            "https://api.example.com/v1/mcp"
        );
    }

    #[test]
    fn invalid_url_empty() {
        let config = TransportConfig::default();
        let transport = StreamableHttpTransport::new("", config);
        assert!(transport.is_err());
    }

    #[test]
    fn invalid_url_no_scheme() {
        let config = TransportConfig::default();
        let transport = StreamableHttpTransport::new("example.com/mcp", config);
        assert!(transport.is_err());
    }

    #[test]
    fn invalid_url_malformed() {
        let config = TransportConfig::default();
        // URLs without proper scheme are invalid
        let transport = StreamableHttpTransport::new("not-a-valid-url", config);
        assert!(transport.is_err());
    }

    #[test]
    fn invalid_url_contains_context() {
        let config = TransportConfig::default();
        let result = StreamableHttpTransport::new("not a url", config);
        assert!(result.is_err());
        let err = result.unwrap_err();
        let err_msg = format!("{:#}", err);
        assert!(err_msg.contains("Invalid endpoint URL"));
    }

    #[test]
    fn request_id_sequential() {
        let config = TransportConfig::default();
        let transport = StreamableHttpTransport::new("https://example.com/mcp", config).unwrap();

        let id1 = transport.next_id();
        let id2 = transport.next_id();
        let id3 = transport.next_id();

        assert_eq!(id1, RequestId::Number(1));
        assert_eq!(id2, RequestId::Number(2));
        assert_eq!(id3, RequestId::Number(3));
    }

    #[test]
    fn request_id_starts_at_one() {
        let config = TransportConfig::default();
        let transport = StreamableHttpTransport::new("https://example.com/mcp", config).unwrap();
        let id = transport.next_id();
        assert_eq!(id, RequestId::Number(1));
    }

    #[test]
    fn request_id_many_increments() {
        let config = TransportConfig::default();
        let transport = StreamableHttpTransport::new("https://example.com/mcp", config).unwrap();

        for i in 1..=20 {
            let id = transport.next_id();
            assert_eq!(id, RequestId::Number(i));
        }
    }

    #[test]
    fn session_id_none_initially() {
        let config = TransportConfig::default();
        let transport = StreamableHttpTransport::new("https://example.com/mcp", config).unwrap();
        assert!(transport.session_id().is_none());
    }

    #[test]
    fn transport_type_name() {
        let config = TransportConfig::default();
        let transport = StreamableHttpTransport::new("https://example.com/mcp", config).unwrap();
        assert_eq!(transport.transport_type(), "streamable_http");
    }

    #[test]
    fn custom_config() {
        let config = TransportConfig {
            timeout_secs: 120,
            max_message_size: 20 * 1024 * 1024,
        };
        let transport = StreamableHttpTransport::new("https://example.com/mcp", config);
        assert!(transport.is_ok());
        let transport = transport.unwrap();
        assert_eq!(transport.config.timeout_secs, 120);
        assert_eq!(transport.config.max_message_size, 20 * 1024 * 1024);
    }

    #[test]
    fn with_client_custom() {
        let config = TransportConfig::default();
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .build()
            .unwrap();

        let transport =
            StreamableHttpTransport::with_client("https://example.com/mcp", client, config);
        assert!(transport.is_ok());
    }

    #[test]
    fn with_client_invalid_url() {
        let config = TransportConfig::default();
        let client = reqwest::Client::new();
        let transport = StreamableHttpTransport::with_client("not a url", client, config);
        assert!(transport.is_err());
    }

    #[test]
    fn parse_localhost_endpoint() {
        let config = TransportConfig::default();
        let transport = StreamableHttpTransport::new("http://localhost:8080/mcp", config);
        assert!(transport.is_ok());
    }

    #[test]
    fn parse_ipv4_endpoint() {
        let config = TransportConfig::default();
        let transport = StreamableHttpTransport::new("http://127.0.0.1:8080/mcp", config);
        assert!(transport.is_ok());
    }

    #[test]
    fn parse_ipv6_endpoint() {
        let config = TransportConfig::default();
        let transport = StreamableHttpTransport::new("http://[::1]:8080/mcp", config);
        assert!(transport.is_ok());
    }

    #[tokio::test]
    async fn parse_sse_response_empty_data() {
        let config = TransportConfig::default();
        let transport = StreamableHttpTransport::new("https://example.com/mcp", config).unwrap();

        let sse_text = r#"event: message
data:

"#;

        let result = transport.parse_sse_response(sse_text).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn parse_sse_response_done_marker() {
        let config = TransportConfig::default();
        let transport = StreamableHttpTransport::new("https://example.com/mcp", config).unwrap();

        let sse_text = r#"event: message
data: [DONE]

"#;

        let result = transport.parse_sse_response(sse_text).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn parse_sse_response_with_notification() {
        let config = TransportConfig::default();
        let transport = StreamableHttpTransport::new("https://example.com/mcp", config).unwrap();

        let sse_text = r#"event: message
data: {"jsonrpc":"2.0","method":"notification"}

data: {"jsonrpc":"2.0","id":1,"result":{"status":"ok"}}

"#;

        let response = transport.parse_sse_response(sse_text).await.unwrap();
        assert_eq!(response.id, RequestId::Number(1));
        assert!(response.is_success());
    }

    #[tokio::test]
    async fn parse_sse_response_multiple_lines() {
        let config = TransportConfig::default();
        let transport = StreamableHttpTransport::new("https://example.com/mcp", config).unwrap();

        let sse_text = r#"event: start

event: message
data: {"jsonrpc":"2.0","id":1,"result":{"status":"ok"}}

event: end

"#;

        let response = transport.parse_sse_response(sse_text).await.unwrap();
        assert_eq!(response.id, RequestId::Number(1));
    }

    #[tokio::test]
    async fn parse_sse_response_with_error() {
        let config = TransportConfig::default();
        let transport = StreamableHttpTransport::new("https://example.com/mcp", config).unwrap();

        let sse_text = r#"data: {"jsonrpc":"2.0","id":1,"error":{"code":-32600,"message":"Invalid Request"}}

"#;

        let response = transport.parse_sse_response(sse_text).await.unwrap();
        assert_eq!(response.id, RequestId::Number(1));
        assert!(response.is_error());
    }

    #[tokio::test]
    async fn parse_sse_response_no_valid_response() {
        let config = TransportConfig::default();
        let transport = StreamableHttpTransport::new("https://example.com/mcp", config).unwrap();

        let sse_text = r#"event: message
data: {"invalid": "json"}

"#;

        let result = transport.parse_sse_response(sse_text).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn parse_sse_response_empty() {
        let config = TransportConfig::default();
        let transport = StreamableHttpTransport::new("https://example.com/mcp", config).unwrap();

        let result = transport.parse_sse_response("").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn parse_sse_response_no_data_prefix() {
        let config = TransportConfig::default();
        let transport = StreamableHttpTransport::new("https://example.com/mcp", config).unwrap();

        let sse_text = r#"{"jsonrpc":"2.0","id":1,"result":{"status":"ok"}}"#;

        let result = transport.parse_sse_response(sse_text).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn parse_sse_response_whitespace_handling() {
        let config = TransportConfig::default();
        let transport = StreamableHttpTransport::new("https://example.com/mcp", config).unwrap();

        let sse_text = r#"

data: {"jsonrpc":"2.0","id":1,"result":{"status":"ok"}}

"#;

        let response = transport.parse_sse_response(sse_text).await.unwrap();
        assert_eq!(response.id, RequestId::Number(1));
    }

    #[tokio::test]
    async fn parse_sse_response_string_id() {
        let config = TransportConfig::default();
        let transport = StreamableHttpTransport::new("https://example.com/mcp", config).unwrap();

        let sse_text = r#"data: {"jsonrpc":"2.0","id":"abc-123","result":{"status":"ok"}}"#;

        let response = transport.parse_sse_response(sse_text).await.unwrap();
        assert_eq!(response.id, RequestId::String("abc-123".to_string()));
    }

    #[test]
    fn extract_session_id_from_headers() {
        let config = TransportConfig::default();
        let mut transport =
            StreamableHttpTransport::new("https://example.com/mcp", config).unwrap();

        let mut headers = HeaderMap::new();
        headers.insert("Mcp-Session-Id", "session-123".parse().unwrap());

        transport.extract_session_id(&headers);
        assert_eq!(transport.session_id(), Some("session-123"));
    }

    #[test]
    fn extract_session_id_no_header() {
        let config = TransportConfig::default();
        let mut transport =
            StreamableHttpTransport::new("https://example.com/mcp", config).unwrap();

        let headers = HeaderMap::new();
        transport.extract_session_id(&headers);
        assert!(transport.session_id().is_none());
    }

    #[test]
    fn extract_session_id_invalid_utf8() {
        let config = TransportConfig::default();
        let mut transport =
            StreamableHttpTransport::new("https://example.com/mcp", config).unwrap();

        let mut headers = HeaderMap::new();
        // Create invalid UTF-8 header value
        headers.insert(
            "Mcp-Session-Id",
            reqwest::header::HeaderValue::from_bytes(&[0xFF, 0xFF]).unwrap(),
        );

        transport.extract_session_id(&headers);
        // Should remain None when UTF-8 parsing fails
        assert!(transport.session_id().is_none());
    }

    #[test]
    fn build_request_no_session() {
        let config = TransportConfig::default();
        let transport = StreamableHttpTransport::new("https://example.com/mcp", config).unwrap();

        let builder = transport.build_request();
        // Can't easily inspect the builder, but we can verify it doesn't panic
        drop(builder);
    }

    #[test]
    fn build_request_with_session() {
        let config = TransportConfig::default();
        let mut transport =
            StreamableHttpTransport::new("https://example.com/mcp", config).unwrap();

        // Manually set session ID
        let mut headers = HeaderMap::new();
        headers.insert("Mcp-Session-Id", "test-session".parse().unwrap());
        transport.extract_session_id(&headers);

        let builder = transport.build_request();
        drop(builder);
    }

    #[tokio::test]
    async fn recv_returns_none() {
        let config = TransportConfig::default();
        let mut transport =
            StreamableHttpTransport::new("https://example.com/mcp", config).unwrap();

        let result = transport.recv().await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }
}
