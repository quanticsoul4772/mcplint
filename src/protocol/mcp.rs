//! MCP (Model Context Protocol) message types
//! Based on MCP Specification 2025-03-26

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Supported MCP protocol versions
pub const PROTOCOL_VERSION_2024_11_05: &str = "2024-11-05";
pub const PROTOCOL_VERSION_2025_03_26: &str = "2025-03-26";
pub const LATEST_PROTOCOL_VERSION: &str = PROTOCOL_VERSION_2025_03_26;

/// Check if a protocol version is supported
pub fn is_supported_version(version: &str) -> bool {
    matches!(
        version,
        PROTOCOL_VERSION_2024_11_05 | PROTOCOL_VERSION_2025_03_26
    )
}

// ============================================================================
// Common Types
// ============================================================================

/// Implementation info (client or server)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Implementation {
    pub name: String,
    pub version: String,
}

impl Implementation {
    pub fn new(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
        }
    }
}

// ============================================================================
// Initialize
// ============================================================================

/// Initialize request parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InitializeParams {
    pub protocol_version: String,
    pub capabilities: ClientCapabilities,
    pub client_info: Implementation,
}

impl InitializeParams {
    pub fn new(client_info: Implementation, capabilities: ClientCapabilities) -> Self {
        Self {
            protocol_version: LATEST_PROTOCOL_VERSION.to_string(),
            capabilities,
            client_info,
        }
    }
}

/// Initialize result from server
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InitializeResult {
    pub protocol_version: String,
    pub capabilities: ServerCapabilities,
    pub server_info: Implementation,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instructions: Option<String>,
}

// ============================================================================
// Capabilities
// ============================================================================

/// Client capabilities advertised during initialization
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientCapabilities {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub roots: Option<RootsCapability>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sampling: Option<SamplingCapability>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub experimental: Option<Value>,
}

/// Server capabilities advertised during initialization
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerCapabilities {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompts: Option<PromptsCapability>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resources: Option<ResourcesCapability>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<ToolsCapability>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logging: Option<LoggingCapability>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completions: Option<CompletionsCapability>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub experimental: Option<Value>,
}

impl ServerCapabilities {
    pub fn has_tools(&self) -> bool {
        self.tools.is_some()
    }

    pub fn has_resources(&self) -> bool {
        self.resources.is_some()
    }

    pub fn has_prompts(&self) -> bool {
        self.prompts.is_some()
    }
}

/// Roots capability (client)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RootsCapability {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub list_changed: Option<bool>,
}

/// Sampling capability (client)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SamplingCapability {}

/// Prompts capability (server)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PromptsCapability {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub list_changed: Option<bool>,
}

/// Resources capability (server)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourcesCapability {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subscribe: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub list_changed: Option<bool>,
}

/// Tools capability (server)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolsCapability {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub list_changed: Option<bool>,
}

/// Logging capability (server)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LoggingCapability {}

/// Completions capability (server)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CompletionsCapability {}

// ============================================================================
// Tools
// ============================================================================

/// Tool definition from server
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Tool {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub input_schema: Value,
}

/// Result of tools/list
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListToolsResult {
    pub tools: Vec<Tool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// Parameters for tools/call
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallToolParams {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arguments: Option<Value>,
}

impl CallToolParams {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            arguments: None,
        }
    }

    pub fn with_arguments(mut self, arguments: Value) -> Self {
        self.arguments = Some(arguments);
        self
    }
}

/// Result of tools/call
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CallToolResult {
    pub content: Vec<Content>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_error: Option<bool>,
}

// ============================================================================
// Resources
// ============================================================================

/// Resource definition from server
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Resource {
    pub uri: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
}

/// Result of resources/list
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListResourcesResult {
    pub resources: Vec<Resource>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// Parameters for resources/read
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadResourceParams {
    pub uri: String,
}

/// Result of resources/read
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadResourceResult {
    pub contents: Vec<ResourceContent>,
}

/// Resource content
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceContent {
    pub uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blob: Option<String>,
}

// ============================================================================
// Prompts
// ============================================================================

/// Prompt definition from server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Prompt {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arguments: Option<Vec<PromptArgument>>,
}

/// Prompt argument definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptArgument {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
}

/// Result of prompts/list
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListPromptsResult {
    pub prompts: Vec<Prompt>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// Parameters for prompts/get
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetPromptParams {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arguments: Option<Value>,
}

/// Result of prompts/get
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetPromptResult {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub messages: Vec<PromptMessage>,
}

/// Message in a prompt result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptMessage {
    pub role: Role,
    pub content: Content,
}

// ============================================================================
// Content Types
// ============================================================================

/// Message role
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    User,
    Assistant,
}

/// Content in tool results and prompts
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Content {
    Text {
        text: String,
    },
    Image {
        data: String,
        #[serde(rename = "mimeType")]
        mime_type: String,
    },
    Resource {
        resource: ResourceContent,
    },
}

impl Content {
    pub fn text(text: impl Into<String>) -> Self {
        Content::Text { text: text.into() }
    }

    pub fn image(data: String, mime_type: String) -> Self {
        Content::Image { data, mime_type }
    }
}

// ============================================================================
// Pagination
// ============================================================================

/// Common pagination parameters
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PaginationParams {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

// ============================================================================
// Method Names
// ============================================================================

pub mod methods {
    // Lifecycle
    pub const INITIALIZE: &str = "initialize";
    pub const INITIALIZED: &str = "notifications/initialized";
    pub const PING: &str = "ping";

    // Tools
    pub const TOOLS_LIST: &str = "tools/list";
    pub const TOOLS_CALL: &str = "tools/call";

    // Resources
    pub const RESOURCES_LIST: &str = "resources/list";
    pub const RESOURCES_READ: &str = "resources/read";
    pub const RESOURCES_SUBSCRIBE: &str = "resources/subscribe";
    pub const RESOURCES_UNSUBSCRIBE: &str = "resources/unsubscribe";

    // Prompts
    pub const PROMPTS_LIST: &str = "prompts/list";
    pub const PROMPTS_GET: &str = "prompts/get";

    // Logging
    pub const LOGGING_SET_LEVEL: &str = "logging/setLevel";

    // Notifications
    pub const NOTIFICATION_CANCELLED: &str = "notifications/cancelled";
    pub const NOTIFICATION_PROGRESS: &str = "notifications/progress";
    pub const NOTIFICATION_RESOURCES_UPDATED: &str = "notifications/resources/updated";
    pub const NOTIFICATION_RESOURCES_LIST_CHANGED: &str = "notifications/resources/list_changed";
    pub const NOTIFICATION_TOOLS_LIST_CHANGED: &str = "notifications/tools/list_changed";
    pub const NOTIFICATION_PROMPTS_LIST_CHANGED: &str = "notifications/prompts/list_changed";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_initialize_params() {
        let params = InitializeParams::new(
            Implementation::new("test-client", "1.0.0"),
            ClientCapabilities::default(),
        );
        let json = serde_json::to_string(&params).unwrap();
        assert!(json.contains("protocolVersion"));
        assert!(json.contains("2025-03-26"));
        assert!(json.contains("test-client"));
    }

    #[test]
    fn deserialize_initialize_result() {
        let json = r#"{
            "protocolVersion": "2025-03-26",
            "capabilities": {
                "tools": {"listChanged": true},
                "resources": {"subscribe": true}
            },
            "serverInfo": {"name": "test-server", "version": "1.0.0"},
            "instructions": "Test instructions"
        }"#;

        let result: InitializeResult = serde_json::from_str(json).unwrap();
        assert_eq!(result.protocol_version, "2025-03-26");
        assert!(result.capabilities.has_tools());
        assert!(result.capabilities.has_resources());
        assert_eq!(result.server_info.name, "test-server");
        assert_eq!(result.instructions, Some("Test instructions".to_string()));
    }

    #[test]
    fn deserialize_tool() {
        let json = r#"{
            "name": "read_file",
            "description": "Read a file from disk",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"}
                },
                "required": ["path"]
            }
        }"#;

        let tool: Tool = serde_json::from_str(json).unwrap();
        assert_eq!(tool.name, "read_file");
        assert_eq!(tool.description, Some("Read a file from disk".to_string()));
        assert!(tool.input_schema.is_object());
    }

    #[test]
    fn deserialize_tool_call_result() {
        let json = r#"{
            "content": [
                {"type": "text", "text": "Hello, world!"}
            ],
            "isError": false
        }"#;

        let result: CallToolResult = serde_json::from_str(json).unwrap();
        assert_eq!(result.content.len(), 1);
        assert_eq!(result.is_error, Some(false));
    }

    #[test]
    fn content_variants() {
        let text = Content::text("Hello");
        let json = serde_json::to_string(&text).unwrap();
        assert!(json.contains(r#""type":"text""#));
        assert!(json.contains(r#""text":"Hello""#));
    }

    #[test]
    fn supported_versions() {
        assert!(is_supported_version("2024-11-05"));
        assert!(is_supported_version("2025-03-26"));
        assert!(!is_supported_version("1.0.0"));
    }

    // Implementation tests
    #[test]
    fn implementation_new_with_strings() {
        let impl_info = Implementation::new("mcplint", "1.0.0");
        assert_eq!(impl_info.name, "mcplint");
        assert_eq!(impl_info.version, "1.0.0");
    }

    #[test]
    fn implementation_new_with_string_slices() {
        let name = String::from("test-server");
        let version = String::from("2.1.0");
        let impl_info = Implementation::new(name, version);
        assert_eq!(impl_info.name, "test-server");
        assert_eq!(impl_info.version, "2.1.0");
    }

    #[test]
    fn implementation_serialization() {
        let impl_info = Implementation::new("test", "1.0");
        let json = serde_json::to_string(&impl_info).unwrap();
        assert!(json.contains(r#""name":"test""#));
        assert!(json.contains(r#""version":"1.0""#));
    }

    // InitializeParams tests
    #[test]
    fn initialize_params_new() {
        let client_info = Implementation::new("test-client", "0.1.0");
        let capabilities = ClientCapabilities::default();
        let params = InitializeParams::new(client_info.clone(), capabilities);

        assert_eq!(params.protocol_version, LATEST_PROTOCOL_VERSION);
        assert_eq!(params.client_info.name, "test-client");
        assert_eq!(params.client_info.version, "0.1.0");
    }

    #[test]
    fn initialize_params_with_custom_capabilities() {
        let client_info = Implementation::new("client", "1.0");
        let capabilities = ClientCapabilities {
            roots: Some(RootsCapability {
                list_changed: Some(true),
            }),
            ..ClientCapabilities::default()
        };
        let params = InitializeParams::new(client_info, capabilities);

        assert!(params.capabilities.roots.is_some());
    }

    // ServerCapabilities tests
    #[test]
    fn server_capabilities_has_tools_when_none() {
        let caps = ServerCapabilities::default();
        assert!(!caps.has_tools());
    }

    #[test]
    fn server_capabilities_has_tools_when_some() {
        let caps = ServerCapabilities {
            tools: Some(ToolsCapability::default()),
            ..Default::default()
        };
        assert!(caps.has_tools());
    }

    #[test]
    fn server_capabilities_has_resources_when_none() {
        let caps = ServerCapabilities::default();
        assert!(!caps.has_resources());
    }

    #[test]
    fn server_capabilities_has_resources_when_some() {
        let caps = ServerCapabilities {
            resources: Some(ResourcesCapability::default()),
            ..Default::default()
        };
        assert!(caps.has_resources());
    }

    #[test]
    fn server_capabilities_has_prompts_when_none() {
        let caps = ServerCapabilities::default();
        assert!(!caps.has_prompts());
    }

    #[test]
    fn server_capabilities_has_prompts_when_some() {
        let caps = ServerCapabilities {
            prompts: Some(PromptsCapability::default()),
            ..Default::default()
        };
        assert!(caps.has_prompts());
    }

    // CallToolParams tests
    #[test]
    fn call_tool_params_new() {
        let params = CallToolParams::new("test_tool");
        assert_eq!(params.name, "test_tool");
        assert!(params.arguments.is_none());
    }

    #[test]
    fn call_tool_params_with_arguments() {
        let args = serde_json::json!({"key": "value"});
        let params = CallToolParams::new("test_tool").with_arguments(args.clone());
        assert_eq!(params.name, "test_tool");
        assert_eq!(params.arguments, Some(args));
    }

    #[test]
    fn call_tool_params_chaining() {
        let params = CallToolParams::new("tool").with_arguments(serde_json::json!({"a": 1}));
        assert_eq!(params.name, "tool");
        assert!(params.arguments.is_some());
    }

    // Content tests
    #[test]
    fn content_image_creation() {
        let img = Content::image("base64data".to_string(), "image/png".to_string());
        match img {
            Content::Image { data, mime_type } => {
                assert_eq!(data, "base64data");
                assert_eq!(mime_type, "image/png");
            }
            _ => panic!("Expected Image variant"),
        }
    }

    #[test]
    fn content_text_serialization() {
        let text = Content::text("test text");
        let json = serde_json::to_string(&text).unwrap();
        assert!(json.contains(r#""type":"text""#));
        assert!(json.contains(r#""text":"test text""#));
    }

    #[test]
    fn content_image_serialization() {
        let img = Content::image("data123".to_string(), "image/jpeg".to_string());
        let json = serde_json::to_string(&img).unwrap();
        assert!(json.contains(r#""type":"image""#));
        assert!(json.contains(r#""data":"data123""#));
        assert!(json.contains(r#""mimeType":"image/jpeg""#));
    }

    // Resource tests
    #[test]
    fn resource_serialization() {
        let resource = Resource {
            uri: "file:///test.txt".to_string(),
            name: "test.txt".to_string(),
            description: Some("Test file".to_string()),
            mime_type: Some("text/plain".to_string()),
        };
        let json = serde_json::to_string(&resource).unwrap();
        assert!(json.contains(r#""uri":"file:///test.txt""#));
        assert!(json.contains(r#""name":"test.txt""#));
        assert!(json.contains(r#""description":"Test file""#));
        assert!(json.contains(r#""mimeType":"text/plain""#));
    }

    #[test]
    fn resource_deserialization() {
        let json = r#"{
            "uri": "http://example.com/resource",
            "name": "example",
            "description": "Example resource",
            "mimeType": "application/json"
        }"#;
        let resource: Resource = serde_json::from_str(json).unwrap();
        assert_eq!(resource.uri, "http://example.com/resource");
        assert_eq!(resource.name, "example");
        assert_eq!(resource.description, Some("Example resource".to_string()));
        assert_eq!(resource.mime_type, Some("application/json".to_string()));
    }

    // ReadResourceParams tests
    #[test]
    fn read_resource_params_serialization() {
        let params = ReadResourceParams {
            uri: "file:///data.json".to_string(),
        };
        let json = serde_json::to_string(&params).unwrap();
        assert!(json.contains(r#""uri":"file:///data.json""#));
    }

    // ReadResourceResult tests
    #[test]
    fn read_resource_result_serialization() {
        let result = ReadResourceResult {
            contents: vec![ResourceContent {
                uri: "file:///test".to_string(),
                mime_type: Some("text/plain".to_string()),
                text: Some("content".to_string()),
                blob: None,
            }],
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains(r#""contents""#));
    }

    // Prompt tests
    #[test]
    fn prompt_serialization() {
        let prompt = Prompt {
            name: "test_prompt".to_string(),
            description: Some("Test prompt".to_string()),
            arguments: Some(vec![PromptArgument {
                name: "arg1".to_string(),
                description: Some("First argument".to_string()),
                required: Some(true),
            }]),
        };
        let json = serde_json::to_string(&prompt).unwrap();
        assert!(json.contains(r#""name":"test_prompt""#));
        assert!(json.contains(r#""description":"Test prompt""#));
        assert!(json.contains(r#""arguments""#));
    }

    #[test]
    fn prompt_deserialization() {
        let json = r#"{
            "name": "my_prompt",
            "description": "My prompt",
            "arguments": [
                {"name": "input", "required": true}
            ]
        }"#;
        let prompt: Prompt = serde_json::from_str(json).unwrap();
        assert_eq!(prompt.name, "my_prompt");
        assert_eq!(prompt.arguments.as_ref().unwrap().len(), 1);
    }

    // PromptArgument tests
    #[test]
    fn prompt_argument_serialization() {
        let arg = PromptArgument {
            name: "param".to_string(),
            description: Some("Parameter description".to_string()),
            required: Some(false),
        };
        let json = serde_json::to_string(&arg).unwrap();
        assert!(json.contains(r#""name":"param""#));
        assert!(json.contains(r#""required":false"#));
    }

    #[test]
    fn prompt_argument_deserialization() {
        let json = r#"{"name": "arg", "description": "desc", "required": true}"#;
        let arg: PromptArgument = serde_json::from_str(json).unwrap();
        assert_eq!(arg.name, "arg");
        assert_eq!(arg.description, Some("desc".to_string()));
        assert_eq!(arg.required, Some(true));
    }

    // GetPromptParams tests
    #[test]
    fn get_prompt_params_serialization() {
        let params = GetPromptParams {
            name: "prompt1".to_string(),
            arguments: Some(serde_json::json!({"key": "value"})),
        };
        let json = serde_json::to_string(&params).unwrap();
        assert!(json.contains(r#""name":"prompt1""#));
        assert!(json.contains(r#""arguments""#));
    }

    // GetPromptResult tests
    #[test]
    fn get_prompt_result_serialization() {
        let result = GetPromptResult {
            description: Some("Result description".to_string()),
            messages: vec![PromptMessage {
                role: Role::User,
                content: Content::text("Hello"),
            }],
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains(r#""description":"Result description""#));
        assert!(json.contains(r#""messages""#));
    }

    // PromptMessage tests
    #[test]
    fn prompt_message_with_user_role() {
        let msg = PromptMessage {
            role: Role::User,
            content: Content::text("User message"),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains(r#""role":"user""#));
    }

    #[test]
    fn prompt_message_with_assistant_role() {
        let msg = PromptMessage {
            role: Role::Assistant,
            content: Content::text("Assistant message"),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains(r#""role":"assistant""#));
    }

    // PaginationParams tests
    #[test]
    fn pagination_params_serialization_without_cursor() {
        let params = PaginationParams::default();
        let json = serde_json::to_string(&params).unwrap();
        assert_eq!(json, "{}");
    }

    #[test]
    fn pagination_params_serialization_with_cursor() {
        let params = PaginationParams {
            cursor: Some("cursor123".to_string()),
        };
        let json = serde_json::to_string(&params).unwrap();
        assert!(json.contains(r#""cursor":"cursor123""#));
    }

    // ListToolsResult tests
    #[test]
    fn list_tools_result_with_next_cursor() {
        let result = ListToolsResult {
            tools: vec![],
            next_cursor: Some("next_page".to_string()),
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains(r#""next_cursor":"next_page""#));
    }

    #[test]
    fn list_tools_result_without_cursor() {
        let result = ListToolsResult {
            tools: vec![],
            next_cursor: None,
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(!json.contains("nextCursor"));
    }

    // ListResourcesResult tests
    #[test]
    fn list_resources_result_with_next_cursor() {
        let result = ListResourcesResult {
            resources: vec![],
            next_cursor: Some("page2".to_string()),
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains(r#""next_cursor":"page2""#));
    }

    #[test]
    fn list_resources_result_without_cursor() {
        let result = ListResourcesResult {
            resources: vec![],
            next_cursor: None,
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(!json.contains("nextCursor"));
    }

    // ListPromptsResult tests
    #[test]
    fn list_prompts_result_with_next_cursor() {
        let result = ListPromptsResult {
            prompts: vec![],
            next_cursor: Some("cursor_token".to_string()),
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains(r#""next_cursor":"cursor_token""#));
    }

    #[test]
    fn list_prompts_result_without_cursor() {
        let result = ListPromptsResult {
            prompts: vec![],
            next_cursor: None,
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(!json.contains("nextCursor"));
    }

    // ResourceContent tests
    #[test]
    fn resource_content_with_text() {
        let content = ResourceContent {
            uri: "file:///test.txt".to_string(),
            mime_type: Some("text/plain".to_string()),
            text: Some("File content here".to_string()),
            blob: None,
        };
        let json = serde_json::to_string(&content).unwrap();
        assert!(json.contains(r#""text":"File content here""#));
        assert!(!json.contains(r#""blob""#));
    }

    #[test]
    fn resource_content_with_blob() {
        let content = ResourceContent {
            uri: "file:///image.png".to_string(),
            mime_type: Some("image/png".to_string()),
            text: None,
            blob: Some("base64encodeddata".to_string()),
        };
        let json = serde_json::to_string(&content).unwrap();
        assert!(json.contains(r#""blob":"base64encodeddata""#));
        assert!(!json.contains(r#""text""#));
    }

    // Method constants tests
    #[test]
    fn method_constants_lifecycle() {
        assert_eq!(methods::INITIALIZE, "initialize");
        assert_eq!(methods::INITIALIZED, "notifications/initialized");
        assert_eq!(methods::PING, "ping");
    }

    #[test]
    fn method_constants_tools() {
        assert_eq!(methods::TOOLS_LIST, "tools/list");
        assert_eq!(methods::TOOLS_CALL, "tools/call");
    }

    #[test]
    fn method_constants_resources() {
        assert_eq!(methods::RESOURCES_LIST, "resources/list");
        assert_eq!(methods::RESOURCES_READ, "resources/read");
        assert_eq!(methods::RESOURCES_SUBSCRIBE, "resources/subscribe");
        assert_eq!(methods::RESOURCES_UNSUBSCRIBE, "resources/unsubscribe");
    }

    #[test]
    fn method_constants_prompts() {
        assert_eq!(methods::PROMPTS_LIST, "prompts/list");
        assert_eq!(methods::PROMPTS_GET, "prompts/get");
    }

    #[test]
    fn method_constants_logging() {
        assert_eq!(methods::LOGGING_SET_LEVEL, "logging/setLevel");
    }

    #[test]
    fn method_constants_notifications() {
        assert_eq!(methods::NOTIFICATION_CANCELLED, "notifications/cancelled");
        assert_eq!(methods::NOTIFICATION_PROGRESS, "notifications/progress");
        assert_eq!(
            methods::NOTIFICATION_RESOURCES_UPDATED,
            "notifications/resources/updated"
        );
        assert_eq!(
            methods::NOTIFICATION_RESOURCES_LIST_CHANGED,
            "notifications/resources/list_changed"
        );
        assert_eq!(
            methods::NOTIFICATION_TOOLS_LIST_CHANGED,
            "notifications/tools/list_changed"
        );
        assert_eq!(
            methods::NOTIFICATION_PROMPTS_LIST_CHANGED,
            "notifications/prompts/list_changed"
        );
    }

    // Role tests
    #[test]
    fn role_equality() {
        assert_eq!(Role::User, Role::User);
        assert_eq!(Role::Assistant, Role::Assistant);
        assert_ne!(Role::User, Role::Assistant);
    }

    #[test]
    fn role_serialization() {
        let user_json = serde_json::to_string(&Role::User).unwrap();
        let assistant_json = serde_json::to_string(&Role::Assistant).unwrap();
        assert_eq!(user_json, r#""user""#);
        assert_eq!(assistant_json, r#""assistant""#);
    }
}
