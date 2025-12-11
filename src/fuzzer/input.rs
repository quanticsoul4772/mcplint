//! Fuzz Input - Represents a fuzzing input/request
//!
//! Defines the FuzzInput structure that represents a single
//! request to be sent to an MCP server during fuzzing.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::mutation::strategy::MutationStrategy;

/// A fuzzing input (request to send to server)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzInput {
    /// JSON-RPC method name
    pub method: String,
    /// Request parameters
    pub params: Option<Value>,
    /// Request ID
    pub id: Value,
    /// Strategy that generated this input (if any)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub strategy_used: Option<String>,
    /// Parent input ID for corpus tracking
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,
    /// Unique identifier for this input
    pub input_id: String,
}

impl Default for FuzzInput {
    fn default() -> Self {
        Self {
            method: String::new(),
            params: None,
            id: json!(1),
            strategy_used: None,
            parent_id: None,
            input_id: uuid::Uuid::new_v4().to_string(),
        }
    }
}

impl FuzzInput {
    /// Create a new fuzz input
    pub fn new(method: impl Into<String>, params: Option<Value>) -> Self {
        Self {
            method: method.into(),
            params,
            id: json!(1),
            strategy_used: None,
            parent_id: None,
            input_id: uuid::Uuid::new_v4().to_string(),
        }
    }

    /// Create a request input
    pub fn request(method: impl Into<String>, params: Option<Value>) -> Self {
        Self::new(method, params)
    }

    /// Create a notification input (no id expected in response)
    pub fn notification(method: impl Into<String>, params: Option<Value>) -> Self {
        Self {
            method: method.into(),
            params,
            id: Value::Null, // Notifications have null id
            strategy_used: None,
            parent_id: None,
            input_id: uuid::Uuid::new_v4().to_string(),
        }
    }

    /// Create an initialize request
    pub fn initialize() -> Self {
        Self::new(
            "initialize",
            Some(json!({
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {
                    "name": "mcplint-fuzzer",
                    "version": env!("CARGO_PKG_VERSION")
                }
            })),
        )
    }

    /// Create an initialized notification
    pub fn initialized() -> Self {
        Self::notification("notifications/initialized", None)
    }

    /// Create a tools/list request
    pub fn tools_list() -> Self {
        Self::new("tools/list", Some(json!({})))
    }

    /// Create a tools/call request
    pub fn tool_call(name: &str, arguments: Value) -> Self {
        Self::new(
            "tools/call",
            Some(json!({
                "name": name,
                "arguments": arguments
            })),
        )
    }

    /// Create a resources/list request
    pub fn resources_list() -> Self {
        Self::new("resources/list", Some(json!({})))
    }

    /// Create a resources/read request
    pub fn resources_read(uri: &str) -> Self {
        Self::new("resources/read", Some(json!({"uri": uri})))
    }

    /// Create a prompts/list request
    pub fn prompts_list() -> Self {
        Self::new("prompts/list", Some(json!({})))
    }

    /// Create a prompts/get request
    pub fn prompts_get(name: &str, arguments: Option<Value>) -> Self {
        let mut params = json!({"name": name});
        if let Some(args) = arguments {
            params["arguments"] = args;
        }
        Self::new("prompts/get", Some(params))
    }

    /// Create a ping request
    pub fn ping() -> Self {
        Self::new("ping", None)
    }

    /// Set the strategy that created this input
    pub fn with_strategy(mut self, strategy: MutationStrategy) -> Self {
        self.strategy_used = Some(strategy.to_string());
        self
    }

    /// Set the parent input ID
    pub fn with_parent(mut self, parent_id: &str) -> Self {
        self.parent_id = Some(parent_id.to_string());
        self
    }

    /// Set a custom request ID
    pub fn with_id(mut self, id: Value) -> Self {
        self.id = id;
        self
    }

    /// Convert to JSON-RPC request format
    pub fn to_json_rpc(&self) -> Value {
        let mut request = json!({
            "jsonrpc": "2.0",
            "method": self.method,
        });

        if let Some(params) = &self.params {
            request["params"] = params.clone();
        }

        if !self.id.is_null() {
            request["id"] = self.id.clone();
        }

        request
    }

    /// Convert to JSON string
    pub fn to_json_string(&self) -> String {
        serde_json::to_string(&self.to_json_rpc()).unwrap_or_default()
    }

    /// Create input with empty params
    pub fn empty_params() -> Self {
        Self::new("tools/list", Some(json!({})))
    }

    /// Create input with null id
    pub fn null_id() -> Self {
        Self::new("tools/list", Some(json!({}))).with_id(Value::Null)
    }

    /// Create input with string id
    pub fn string_id(id: &str) -> Self {
        Self::new("tools/list", Some(json!({}))).with_id(json!(id))
    }

    /// Check if this is a notification (no response expected)
    pub fn is_notification(&self) -> bool {
        self.id.is_null()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_rpc_format() {
        let input = FuzzInput::tools_list();
        let json = input.to_json_rpc();

        assert_eq!(json["jsonrpc"], "2.0");
        assert_eq!(json["method"], "tools/list");
        assert!(json.get("id").is_some());
    }

    #[test]
    fn tool_call_format() {
        let input = FuzzInput::tool_call("my_tool", json!({"arg": "value"}));
        let json = input.to_json_rpc();

        assert_eq!(json["method"], "tools/call");
        assert_eq!(json["params"]["name"], "my_tool");
        assert_eq!(json["params"]["arguments"]["arg"], "value");
    }

    #[test]
    fn notification_format() {
        let input = FuzzInput::notification("test/notify", Some(json!({"data": 1})));

        assert!(input.is_notification());
        let json = input.to_json_rpc();
        assert!(json.get("id").is_none());
    }

    #[test]
    fn initialize_format() {
        let input = FuzzInput::initialize();
        let json = input.to_json_rpc();

        assert_eq!(json["method"], "initialize");
        assert!(json["params"]["protocolVersion"].is_string());
        assert!(json["params"]["clientInfo"]["name"].is_string());
    }

    #[test]
    fn initialized_notification() {
        let input = FuzzInput::initialized();
        assert!(input.is_notification());
        assert_eq!(input.method, "notifications/initialized");
    }

    #[test]
    fn resources_list_format() {
        let input = FuzzInput::resources_list();
        let json = input.to_json_rpc();
        assert_eq!(json["method"], "resources/list");
    }

    #[test]
    fn resources_read_format() {
        let input = FuzzInput::resources_read("file:///test/path.txt");
        let json = input.to_json_rpc();
        assert_eq!(json["method"], "resources/read");
        assert_eq!(json["params"]["uri"], "file:///test/path.txt");
    }

    #[test]
    fn prompts_list_format() {
        let input = FuzzInput::prompts_list();
        let json = input.to_json_rpc();
        assert_eq!(json["method"], "prompts/list");
    }

    #[test]
    fn prompts_get_without_arguments() {
        let input = FuzzInput::prompts_get("my-prompt", None);
        let json = input.to_json_rpc();
        assert_eq!(json["method"], "prompts/get");
        assert_eq!(json["params"]["name"], "my-prompt");
        assert!(json["params"].get("arguments").is_none());
    }

    #[test]
    fn prompts_get_with_arguments() {
        let input = FuzzInput::prompts_get("my-prompt", Some(json!({"key": "value"})));
        let json = input.to_json_rpc();
        assert_eq!(json["params"]["arguments"]["key"], "value");
    }

    #[test]
    fn ping_format() {
        let input = FuzzInput::ping();
        let json = input.to_json_rpc();
        assert_eq!(json["method"], "ping");
        assert!(json.get("params").is_none());
    }

    #[test]
    fn with_strategy() {
        let input = FuzzInput::tools_list().with_strategy(MutationStrategy::TypeConfusion);
        // Strategy name is converted to snake_case by to_string()
        assert_eq!(input.strategy_used, Some("type_confusion".to_string()));
    }

    #[test]
    fn with_parent() {
        let input = FuzzInput::tools_list().with_parent("parent-id-123");
        assert_eq!(input.parent_id, Some("parent-id-123".to_string()));
    }

    #[test]
    fn with_id_custom() {
        let input = FuzzInput::tools_list().with_id(json!(42));
        assert_eq!(input.id, json!(42));
    }

    #[test]
    fn to_json_string() {
        let input = FuzzInput::ping();
        let json_str = input.to_json_string();
        assert!(json_str.contains("\"method\":\"ping\""));
        assert!(json_str.contains("\"jsonrpc\":\"2.0\""));
    }

    #[test]
    fn empty_params() {
        let input = FuzzInput::empty_params();
        assert_eq!(input.method, "tools/list");
        assert!(input.params.is_some());
    }

    #[test]
    fn null_id() {
        let input = FuzzInput::null_id();
        assert!(input.is_notification());
    }

    #[test]
    fn string_id() {
        let input = FuzzInput::string_id("my-string-id");
        assert_eq!(input.id, json!("my-string-id"));
    }

    #[test]
    fn default_creates_unique_id() {
        let input1 = FuzzInput::default();
        let input2 = FuzzInput::default();
        assert_ne!(input1.input_id, input2.input_id);
    }

    #[test]
    fn request_helper() {
        let input = FuzzInput::request("custom/method", Some(json!({"arg": 1})));
        assert_eq!(input.method, "custom/method");
        assert_eq!(input.params, Some(json!({"arg": 1})));
    }
}
