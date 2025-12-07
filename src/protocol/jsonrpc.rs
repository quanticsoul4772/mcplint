//! JSON-RPC 2.0 types for MCP communication

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// JSON-RPC version constant
pub const JSONRPC_VERSION: &str = "2.0";

/// Standard JSON-RPC error codes
pub mod error_codes {
    pub const PARSE_ERROR: i32 = -32700;
    pub const INVALID_REQUEST: i32 = -32600;
    pub const METHOD_NOT_FOUND: i32 = -32601;
    pub const INVALID_PARAMS: i32 = -32602;
    pub const INTERNAL_ERROR: i32 = -32603;
}

/// Request ID - can be string or number per JSON-RPC spec
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RequestId {
    Number(u64),
    String(String),
}

impl From<u64> for RequestId {
    fn from(n: u64) -> Self {
        RequestId::Number(n)
    }
}

impl From<String> for RequestId {
    fn from(s: String) -> Self {
        RequestId::String(s)
    }
}

impl std::fmt::Display for RequestId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RequestId::Number(n) => write!(f, "{}", n),
            RequestId::String(s) => write!(f, "{}", s),
        }
    }
}

/// JSON-RPC 2.0 Request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub id: RequestId,
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

impl JsonRpcRequest {
    pub fn new(id: impl Into<RequestId>, method: impl Into<String>, params: Option<Value>) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_string(),
            id: id.into(),
            method: method.into(),
            params,
        }
    }
}

/// JSON-RPC 2.0 Response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub id: RequestId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

impl JsonRpcResponse {
    pub fn success(id: RequestId, result: Value) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_string(),
            id,
            result: Some(result),
            error: None,
        }
    }

    pub fn error(id: RequestId, error: JsonRpcError) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_string(),
            id,
            result: None,
            error: Some(error),
        }
    }

    pub fn is_success(&self) -> bool {
        self.error.is_none()
    }

    pub fn is_error(&self) -> bool {
        self.error.is_some()
    }
}

/// JSON-RPC 2.0 Notification (no id field)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcNotification {
    pub jsonrpc: String,
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

impl JsonRpcNotification {
    pub fn new(method: impl Into<String>, params: Option<Value>) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_string(),
            method: method.into(),
            params,
        }
    }
}

/// JSON-RPC 2.0 Error object
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl JsonRpcError {
    pub fn new(code: i32, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            data: None,
        }
    }

    pub fn with_data(mut self, data: Value) -> Self {
        self.data = Some(data);
        self
    }

    pub fn parse_error(message: impl Into<String>) -> Self {
        Self::new(error_codes::PARSE_ERROR, message)
    }

    pub fn invalid_request(message: impl Into<String>) -> Self {
        Self::new(error_codes::INVALID_REQUEST, message)
    }

    pub fn method_not_found(method: &str) -> Self {
        Self::new(
            error_codes::METHOD_NOT_FOUND,
            format!("Method not found: {}", method),
        )
    }

    pub fn invalid_params(message: impl Into<String>) -> Self {
        Self::new(error_codes::INVALID_PARAMS, message)
    }

    pub fn internal_error(message: impl Into<String>) -> Self {
        Self::new(error_codes::INTERNAL_ERROR, message)
    }
}

impl std::fmt::Display for JsonRpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)
    }
}

impl std::error::Error for JsonRpcError {}

/// Union type for any JSON-RPC message
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum JsonRpcMessage {
    Request(JsonRpcRequest),
    Response(JsonRpcResponse),
    Notification(JsonRpcNotification),
}

impl JsonRpcMessage {
    /// Parse a JSON string into a JSON-RPC message
    pub fn parse(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }

    /// Serialize to JSON string
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Check if this is a request (has id and method)
    pub fn is_request(&self) -> bool {
        matches!(self, JsonRpcMessage::Request(_))
    }

    /// Check if this is a response (has id, no method)
    pub fn is_response(&self) -> bool {
        matches!(self, JsonRpcMessage::Response(_))
    }

    /// Check if this is a notification (has method, no id)
    pub fn is_notification(&self) -> bool {
        matches!(self, JsonRpcMessage::Notification(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_request() {
        let json = r#"{"jsonrpc":"2.0","id":1,"method":"test","params":{"foo":"bar"}}"#;
        let msg: JsonRpcRequest = serde_json::from_str(json).unwrap();
        assert_eq!(msg.jsonrpc, "2.0");
        assert_eq!(msg.id, RequestId::Number(1));
        assert_eq!(msg.method, "test");
        assert!(msg.params.is_some());
    }

    #[test]
    fn parse_request_string_id() {
        let json = r#"{"jsonrpc":"2.0","id":"abc-123","method":"test"}"#;
        let msg: JsonRpcRequest = serde_json::from_str(json).unwrap();
        assert_eq!(msg.id, RequestId::String("abc-123".to_string()));
    }

    #[test]
    fn parse_response_with_result() {
        let json = r#"{"jsonrpc":"2.0","id":1,"result":{"status":"ok"}}"#;
        let msg: JsonRpcResponse = serde_json::from_str(json).unwrap();
        assert!(msg.is_success());
        assert!(msg.result.is_some());
        assert!(msg.error.is_none());
    }

    #[test]
    fn parse_response_with_error() {
        let json =
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32600,"message":"Invalid Request"}}"#;
        let msg: JsonRpcResponse = serde_json::from_str(json).unwrap();
        assert!(msg.is_error());
        assert!(msg.error.is_some());
        let err = msg.error.unwrap();
        assert_eq!(err.code, error_codes::INVALID_REQUEST);
    }

    #[test]
    fn parse_notification() {
        let json = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
        let msg: JsonRpcNotification = serde_json::from_str(json).unwrap();
        assert_eq!(msg.method, "notifications/initialized");
        assert!(msg.params.is_none());
    }

    #[test]
    fn serialize_request() {
        let req = JsonRpcRequest::new(1u64, "test", Some(serde_json::json!({"foo": "bar"})));
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains(r#""jsonrpc":"2.0""#));
        assert!(json.contains(r#""id":1"#));
        assert!(json.contains(r#""method":"test""#));
    }

    #[test]
    fn serialize_notification_no_params() {
        let notif = JsonRpcNotification::new("test", None);
        let json = serde_json::to_string(&notif).unwrap();
        assert!(!json.contains("params"));
    }

    #[test]
    fn error_display() {
        let err = JsonRpcError::method_not_found("unknown");
        let display = format!("{}", err);
        assert!(display.contains("-32601"));
        assert!(display.contains("unknown"));
    }
}
