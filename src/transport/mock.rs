//! Mock transport for testing
//!
//! Provides a mock implementation of the Transport trait that can be used
//! for unit testing without spawning actual MCP server processes.

use std::collections::VecDeque;
use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;
use tokio::sync::Mutex;

use crate::protocol::{JsonRpcMessage, JsonRpcResponse, RequestId};

use super::{Transport, TransportConfig, TransportType};

/// Type alias for sent notifications storage to reduce type complexity
type SentNotifications = Arc<Mutex<Vec<(String, Option<Value>)>>>;

/// Mock transport for testing
///
/// Allows pre-configuring responses and capturing sent messages for assertions.
pub struct MockTransport {
    /// Queue of responses to return for requests
    responses: Arc<Mutex<VecDeque<JsonRpcResponse>>>,
    /// Messages sent through the transport
    sent_messages: Arc<Mutex<Vec<JsonRpcMessage>>>,
    /// Notifications sent through the transport
    sent_notifications: SentNotifications,
    /// Whether the transport is closed
    closed: Arc<Mutex<bool>>,
    /// Request counter for ID generation
    request_counter: Arc<Mutex<u64>>,
}

impl MockTransport {
    /// Create a new mock transport
    pub fn new() -> Self {
        Self {
            responses: Arc::new(Mutex::new(VecDeque::new())),
            sent_messages: Arc::new(Mutex::new(Vec::new())),
            sent_notifications: Arc::new(Mutex::new(Vec::new())),
            closed: Arc::new(Mutex::new(false)),
            request_counter: Arc::new(Mutex::new(0)),
        }
    }

    /// Queue a response to be returned by the next request
    pub async fn queue_response(&self, response: JsonRpcResponse) {
        let mut responses = self.responses.lock().await;
        responses.push_back(response);
    }

    /// Queue multiple responses
    pub async fn queue_responses(&self, new_responses: Vec<JsonRpcResponse>) {
        let mut responses = self.responses.lock().await;
        for resp in new_responses {
            responses.push_back(resp);
        }
    }

    /// Create a successful response with the given result
    pub fn success_response(id: RequestId, result: Value) -> JsonRpcResponse {
        JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            id,
            result: Some(result),
            error: None,
        }
    }

    /// Create an error response
    pub fn error_response(id: RequestId, code: i32, message: &str) -> JsonRpcResponse {
        use crate::protocol::jsonrpc::JsonRpcError;
        JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            id,
            result: None,
            error: Some(JsonRpcError {
                code,
                message: message.to_string(),
                data: None,
            }),
        }
    }

    /// Get all sent messages
    pub async fn get_sent_messages(&self) -> Vec<JsonRpcMessage> {
        let messages = self.sent_messages.lock().await;
        messages.clone()
    }

    /// Get all sent notifications as (method, params) tuples
    pub async fn get_sent_notifications(&self) -> Vec<(String, Option<Value>)> {
        let notifications = self.sent_notifications.lock().await;
        notifications.clone()
    }

    /// Check if transport has been closed
    pub async fn is_closed(&self) -> bool {
        *self.closed.lock().await
    }

    /// Clear all queued responses
    pub async fn clear_responses(&self) {
        let mut responses = self.responses.lock().await;
        responses.clear();
    }

    /// Clear all sent messages
    pub async fn clear_sent(&self) {
        let mut messages = self.sent_messages.lock().await;
        messages.clear();
        let mut notifications = self.sent_notifications.lock().await;
        notifications.clear();
    }
}

impl Default for MockTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for MockTransport {
    fn clone(&self) -> Self {
        Self {
            responses: Arc::clone(&self.responses),
            sent_messages: Arc::clone(&self.sent_messages),
            sent_notifications: Arc::clone(&self.sent_notifications),
            closed: Arc::clone(&self.closed),
            request_counter: Arc::clone(&self.request_counter),
        }
    }
}

#[async_trait]
impl Transport for MockTransport {
    async fn send(&mut self, message: &JsonRpcMessage) -> Result<()> {
        let mut messages = self.sent_messages.lock().await;
        messages.push(message.clone());
        Ok(())
    }

    async fn recv(&mut self) -> Result<Option<JsonRpcMessage>> {
        // Mock doesn't receive unsolicited messages by default
        Ok(None)
    }

    async fn request(&mut self, method: &str, params: Option<Value>) -> Result<JsonRpcResponse> {
        // Generate request ID
        let mut counter = self.request_counter.lock().await;
        *counter += 1;
        let id = RequestId::Number(*counter);

        // Record the request
        let request = crate::protocol::JsonRpcRequest::new(id.clone(), method, params.clone());
        let mut messages = self.sent_messages.lock().await;
        messages.push(JsonRpcMessage::Request(request));
        drop(messages);

        // Return queued response or error
        let mut responses = self.responses.lock().await;
        match responses.pop_front() {
            Some(mut response) => {
                // Ensure response ID matches request ID
                response.id = id;
                Ok(response)
            }
            None => {
                // Return a default error if no response queued
                Ok(Self::error_response(
                    id,
                    -32603,
                    &format!("No mock response configured for method: {}", method),
                ))
            }
        }
    }

    async fn notify(&mut self, method: &str, params: Option<Value>) -> Result<()> {
        let mut notifications = self.sent_notifications.lock().await;
        notifications.push((method.to_string(), params));
        Ok(())
    }

    async fn close(&mut self) -> Result<()> {
        let mut closed = self.closed.lock().await;
        *closed = true;
        Ok(())
    }

    fn transport_type(&self) -> &'static str {
        "mock"
    }
}

/// Factory trait for creating transports
///
/// This trait enables dependency injection by abstracting transport creation.
/// Production code uses `DefaultTransportFactory`, while tests can use
/// `MockTransportFactory` to inject mock transports.
#[async_trait]
pub trait TransportFactory: Send + Sync {
    /// Create a new transport connection
    async fn create(
        &self,
        target: &str,
        args: &[String],
        config: TransportConfig,
        transport_type: TransportType,
    ) -> Result<Box<dyn Transport>>;
}

/// Default transport factory that creates real transports
pub struct DefaultTransportFactory;

impl DefaultTransportFactory {
    pub fn new() -> Self {
        Self
    }
}

impl Default for DefaultTransportFactory {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl TransportFactory for DefaultTransportFactory {
    async fn create(
        &self,
        target: &str,
        args: &[String],
        config: TransportConfig,
        transport_type: TransportType,
    ) -> Result<Box<dyn Transport>> {
        super::connect_with_type(target, args, config, transport_type).await
    }
}

/// Mock transport factory for testing
///
/// Returns a pre-configured MockTransport instead of creating real connections.
pub struct MockTransportFactory {
    /// The mock transport to return
    transport: Arc<Mutex<Option<MockTransport>>>,
}

impl MockTransportFactory {
    /// Create a factory that will return the given mock transport
    pub fn new(transport: MockTransport) -> Self {
        Self {
            transport: Arc::new(Mutex::new(Some(transport))),
        }
    }

    /// Create a factory with a fresh mock transport
    pub fn with_new_transport() -> (Self, MockTransport) {
        let transport = MockTransport::new();
        let factory = Self::new(transport.clone());
        (factory, transport)
    }
}

#[async_trait]
impl TransportFactory for MockTransportFactory {
    async fn create(
        &self,
        _target: &str,
        _args: &[String],
        _config: TransportConfig,
        _transport_type: TransportType,
    ) -> Result<Box<dyn Transport>> {
        let mut transport = self.transport.lock().await;
        match transport.take() {
            Some(t) => Ok(Box::new(t)),
            None => anyhow::bail!("MockTransportFactory: transport already consumed"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn mock_transport_queues_responses() {
        let mut transport = MockTransport::new();

        let response =
            MockTransport::success_response(RequestId::Number(1), json!({"status": "ok"}));
        transport.queue_response(response).await;

        let result = transport.request("test_method", None).await.unwrap();
        assert!(result.result.is_some());
        assert_eq!(result.result.unwrap()["status"], "ok");
    }

    #[tokio::test]
    async fn mock_transport_returns_error_when_no_response() {
        let mut transport = MockTransport::new();

        let result = transport.request("unknown_method", None).await.unwrap();
        assert!(result.error.is_some());
        assert!(result.error.unwrap().message.contains("No mock response"));
    }

    #[tokio::test]
    async fn mock_transport_tracks_sent_messages() {
        let mut transport = MockTransport::new();
        transport
            .queue_response(MockTransport::success_response(
                RequestId::Number(1),
                json!({}),
            ))
            .await;

        transport
            .request("test_method", Some(json!({"key": "value"})))
            .await
            .unwrap();

        let messages = transport.get_sent_messages().await;
        assert_eq!(messages.len(), 1);
    }

    #[tokio::test]
    async fn mock_transport_tracks_notifications() {
        let mut transport = MockTransport::new();

        transport
            .notify("notifications/test", Some(json!({"data": 123})))
            .await
            .unwrap();

        let notifications = transport.get_sent_notifications().await;
        assert_eq!(notifications.len(), 1);
        assert_eq!(notifications[0].0, "notifications/test");
    }

    #[tokio::test]
    async fn mock_transport_close() {
        let mut transport = MockTransport::new();

        assert!(!transport.is_closed().await);
        transport.close().await.unwrap();
        assert!(transport.is_closed().await);
    }

    #[tokio::test]
    async fn mock_transport_type() {
        let transport = MockTransport::new();
        assert_eq!(transport.transport_type(), "mock");
    }

    #[tokio::test]
    async fn mock_transport_multiple_responses() {
        let mut transport = MockTransport::new();

        transport
            .queue_responses(vec![
                MockTransport::success_response(RequestId::Number(1), json!({"n": 1})),
                MockTransport::success_response(RequestId::Number(2), json!({"n": 2})),
                MockTransport::success_response(RequestId::Number(3), json!({"n": 3})),
            ])
            .await;

        let r1 = transport.request("m1", None).await.unwrap();
        let r2 = transport.request("m2", None).await.unwrap();
        let r3 = transport.request("m3", None).await.unwrap();

        assert_eq!(r1.result.unwrap()["n"], 1);
        assert_eq!(r2.result.unwrap()["n"], 2);
        assert_eq!(r3.result.unwrap()["n"], 3);
    }

    #[tokio::test]
    async fn mock_transport_error_response() {
        let mut transport = MockTransport::new();

        transport
            .queue_response(MockTransport::error_response(
                RequestId::Number(1),
                -32601,
                "Method not found",
            ))
            .await;

        let result = transport.request("unknown", None).await.unwrap();
        assert!(result.error.is_some());
        let err = result.error.unwrap();
        assert_eq!(err.code, -32601);
        assert_eq!(err.message, "Method not found");
    }

    #[tokio::test]
    async fn mock_factory_returns_transport() {
        let (factory, mock) = MockTransportFactory::with_new_transport();

        // Queue a response on the mock
        mock.queue_response(MockTransport::success_response(
            RequestId::Number(1),
            json!({"test": true}),
        ))
        .await;

        // Get transport from factory
        let mut transport = factory
            .create(
                "test",
                &[],
                TransportConfig::default(),
                TransportType::Stdio,
            )
            .await
            .unwrap();

        let result = transport.request("test", None).await.unwrap();
        assert!(result.result.is_some());
    }

    #[tokio::test]
    async fn mock_factory_consumes_transport() {
        let transport = MockTransport::new();
        let factory = MockTransportFactory::new(transport);

        // First call succeeds
        let _ = factory
            .create(
                "test",
                &[],
                TransportConfig::default(),
                TransportType::Stdio,
            )
            .await
            .unwrap();

        // Second call fails
        let result = factory
            .create(
                "test",
                &[],
                TransportConfig::default(),
                TransportType::Stdio,
            )
            .await;
        assert!(result.is_err());
    }

    #[test]
    fn default_transport_factory_creation() {
        let _factory = DefaultTransportFactory::new();
        let _factory2 = DefaultTransportFactory::default();
    }

    #[test]
    fn mock_transport_clone() {
        let transport = MockTransport::new();
        let _cloned = transport.clone();
    }

    #[test]
    fn mock_transport_default() {
        let _transport = MockTransport::default();
    }
}
