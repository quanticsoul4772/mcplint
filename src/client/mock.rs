//! Mock client for testing
//!
//! Provides mock implementations of McpClient for unit testing without
//! spawning actual MCP server processes.

#![allow(dead_code)] // Testing infrastructure - used by test consumers

use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;
use tokio::sync::Mutex;

use crate::protocol::mcp::{
    CallToolResult, Content, GetPromptResult, InitializeResult, ListResourcesResult,
    ListToolsResult, Prompt, PromptMessage, ReadResourceResult, Resource, ResourceContent, Role,
    Tool,
};
use crate::protocol::{ClientCapabilities, Implementation, ServerCapabilities};
use serde_json::json;

/// Trait for MCP client operations
///
/// This trait abstracts the MCP client interface to enable dependency injection
/// and testing with mock clients.
#[async_trait]
pub trait McpClientTrait: Send + Sync {
    /// Initialize the connection with the server
    async fn initialize(&mut self) -> Result<InitializeResult>;

    /// Check if the client is ready for operations
    fn is_ready(&self) -> bool;

    /// Get server capabilities (after initialization)
    fn server_capabilities(&self) -> Option<&ServerCapabilities>;

    /// Get transport type
    fn transport_type(&self) -> &'static str;

    /// List available tools from the server
    async fn list_tools(&mut self) -> Result<Vec<Tool>>;

    /// List tools with pagination support
    async fn list_tools_paginated(&mut self, cursor: Option<String>) -> Result<ListToolsResult>;

    /// Call a tool on the server
    async fn call_tool(&mut self, name: &str, arguments: Option<Value>) -> Result<CallToolResult>;

    /// List available resources from the server
    async fn list_resources(&mut self) -> Result<Vec<Resource>>;

    /// List resources with pagination support
    async fn list_resources_paginated(
        &mut self,
        cursor: Option<String>,
    ) -> Result<ListResourcesResult>;

    /// Read a resource by URI
    async fn read_resource(&mut self, uri: &str) -> Result<ReadResourceResult>;

    /// List available prompts from the server
    async fn list_prompts(&mut self) -> Result<Vec<Prompt>>;

    /// Get a prompt by name with optional arguments
    async fn get_prompt(&mut self, name: &str, arguments: Option<Value>)
        -> Result<GetPromptResult>;

    /// Ping the server to check connection
    async fn ping(&mut self) -> Result<()>;

    /// Close the connection to the server
    async fn close(&mut self) -> Result<()>;
}

/// Mock configuration for a tool response
#[derive(Clone)]
pub struct MockToolResponse {
    /// Tool name
    pub name: String,
    /// Response to return
    pub response: CallToolResult,
}

/// Mock configuration for a resource response
#[derive(Clone)]
pub struct MockResourceResponse {
    /// Resource URI
    pub uri: String,
    /// Response to return
    pub response: ReadResourceResult,
}

/// Mock configuration for a prompt response
#[derive(Clone)]
pub struct MockPromptResponse {
    /// Prompt name
    pub name: String,
    /// Response to return
    pub response: GetPromptResult,
}

/// Mock MCP client for testing
///
/// Allows pre-configuring responses for tools, resources, and prompts.
pub struct MockMcpClient {
    /// Whether initialized
    initialized: bool,
    /// Server capabilities to return
    capabilities: ServerCapabilities,
    /// Server info
    server_info: Implementation,
    /// Available tools
    tools: Arc<Mutex<Vec<Tool>>>,
    /// Tool call responses
    tool_responses: Arc<Mutex<Vec<MockToolResponse>>>,
    /// Available resources
    resources: Arc<Mutex<Vec<Resource>>>,
    /// Resource read responses
    resource_responses: Arc<Mutex<Vec<MockResourceResponse>>>,
    /// Available prompts
    prompts: Arc<Mutex<Vec<Prompt>>>,
    /// Prompt get responses
    prompt_responses: Arc<Mutex<Vec<MockPromptResponse>>>,
    /// Whether closed
    closed: bool,
    /// Error to return on next call (if set)
    next_error: Arc<Mutex<Option<String>>>,
}

impl MockMcpClient {
    /// Create a new mock client with default settings
    pub fn new() -> Self {
        Self {
            initialized: false,
            capabilities: ServerCapabilities::default(),
            server_info: Implementation::new("mock-server", "1.0.0"),
            tools: Arc::new(Mutex::new(Vec::new())),
            tool_responses: Arc::new(Mutex::new(Vec::new())),
            resources: Arc::new(Mutex::new(Vec::new())),
            resource_responses: Arc::new(Mutex::new(Vec::new())),
            prompts: Arc::new(Mutex::new(Vec::new())),
            prompt_responses: Arc::new(Mutex::new(Vec::new())),
            closed: false,
            next_error: Arc::new(Mutex::new(None)),
        }
    }

    /// Create a mock client with specific capabilities
    pub fn with_capabilities(capabilities: ServerCapabilities) -> Self {
        let mut client = Self::new();
        client.capabilities = capabilities;
        client
    }

    /// Set the tools that will be returned by list_tools
    pub async fn set_tools(&self, tools: Vec<Tool>) {
        let mut t = self.tools.lock().await;
        *t = tools;
    }

    /// Add a tool to the list
    pub async fn add_tool(&self, tool: Tool) {
        let mut tools = self.tools.lock().await;
        tools.push(tool);
    }

    /// Set a response for a specific tool call
    pub async fn set_tool_response(&self, name: &str, response: CallToolResult) {
        let mut responses = self.tool_responses.lock().await;
        responses.push(MockToolResponse {
            name: name.to_string(),
            response,
        });
    }

    /// Set the resources that will be returned by list_resources
    pub async fn set_resources(&self, resources: Vec<Resource>) {
        let mut r = self.resources.lock().await;
        *r = resources;
    }

    /// Add a resource to the list
    pub async fn add_resource(&self, resource: Resource) {
        let mut resources = self.resources.lock().await;
        resources.push(resource);
    }

    /// Set a response for a specific resource read
    pub async fn set_resource_response(&self, uri: &str, response: ReadResourceResult) {
        let mut responses = self.resource_responses.lock().await;
        responses.push(MockResourceResponse {
            uri: uri.to_string(),
            response,
        });
    }

    /// Set the prompts that will be returned by list_prompts
    pub async fn set_prompts(&self, prompts: Vec<Prompt>) {
        let mut p = self.prompts.lock().await;
        *p = prompts;
    }

    /// Add a prompt to the list
    pub async fn add_prompt(&self, prompt: Prompt) {
        let mut prompts = self.prompts.lock().await;
        prompts.push(prompt);
    }

    /// Set a response for a specific prompt get
    pub async fn set_prompt_response(&self, name: &str, response: GetPromptResult) {
        let mut responses = self.prompt_responses.lock().await;
        responses.push(MockPromptResponse {
            name: name.to_string(),
            response,
        });
    }

    /// Set an error to be returned on the next call
    pub async fn set_next_error(&self, error: &str) {
        let mut err = self.next_error.lock().await;
        *err = Some(error.to_string());
    }

    /// Check if mock is closed
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Create a simple tool for testing
    pub fn create_test_tool(name: &str, description: &str) -> Tool {
        Tool {
            name: name.to_string(),
            description: Some(description.to_string()),
            input_schema: json!({
                "type": "object",
                "properties": {}
            }),
        }
    }

    /// Create a simple resource for testing
    pub fn create_test_resource(uri: &str, name: &str) -> Resource {
        Resource {
            uri: uri.to_string(),
            name: name.to_string(),
            description: None,
            mime_type: Some("text/plain".to_string()),
        }
    }

    /// Create a simple prompt for testing
    pub fn create_test_prompt(name: &str, description: &str) -> Prompt {
        Prompt {
            name: name.to_string(),
            description: Some(description.to_string()),
            arguments: None,
        }
    }

    /// Create a success tool result
    pub fn success_tool_result(text: &str) -> CallToolResult {
        CallToolResult {
            content: vec![Content::Text {
                text: text.to_string(),
            }],
            is_error: None,
        }
    }

    /// Create an error tool result
    pub fn error_tool_result(text: &str) -> CallToolResult {
        CallToolResult {
            content: vec![Content::Text {
                text: text.to_string(),
            }],
            is_error: Some(true),
        }
    }

    /// Create a resource read result
    pub fn text_resource_result(uri: &str, text: &str) -> ReadResourceResult {
        ReadResourceResult {
            contents: vec![ResourceContent {
                uri: uri.to_string(),
                mime_type: Some("text/plain".to_string()),
                text: Some(text.to_string()),
                blob: None,
            }],
        }
    }

    /// Create a prompt get result
    pub fn prompt_result(description: &str, messages: Vec<(&str, &str)>) -> GetPromptResult {
        GetPromptResult {
            description: Some(description.to_string()),
            messages: messages
                .into_iter()
                .map(|(role, content)| PromptMessage {
                    role: match role {
                        "assistant" => Role::Assistant,
                        _ => Role::User,
                    },
                    content: Content::Text {
                        text: content.to_string(),
                    },
                })
                .collect(),
        }
    }

    /// Check for pending error and return it if set
    async fn check_error(&self) -> Result<()> {
        let mut err = self.next_error.lock().await;
        if let Some(msg) = err.take() {
            anyhow::bail!("{}", msg);
        }
        Ok(())
    }
}

impl Default for MockMcpClient {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for MockMcpClient {
    fn clone(&self) -> Self {
        Self {
            initialized: self.initialized,
            capabilities: self.capabilities.clone(),
            server_info: self.server_info.clone(),
            tools: Arc::clone(&self.tools),
            tool_responses: Arc::clone(&self.tool_responses),
            resources: Arc::clone(&self.resources),
            resource_responses: Arc::clone(&self.resource_responses),
            prompts: Arc::clone(&self.prompts),
            prompt_responses: Arc::clone(&self.prompt_responses),
            closed: self.closed,
            next_error: Arc::clone(&self.next_error),
        }
    }
}

#[async_trait]
impl McpClientTrait for MockMcpClient {
    async fn initialize(&mut self) -> Result<InitializeResult> {
        self.check_error().await?;

        self.initialized = true;
        Ok(InitializeResult {
            protocol_version: "2024-11-05".to_string(),
            capabilities: self.capabilities.clone(),
            server_info: self.server_info.clone(),
            instructions: None,
        })
    }

    fn is_ready(&self) -> bool {
        self.initialized && !self.closed
    }

    fn server_capabilities(&self) -> Option<&ServerCapabilities> {
        if self.initialized {
            Some(&self.capabilities)
        } else {
            None
        }
    }

    fn transport_type(&self) -> &'static str {
        "mock"
    }

    async fn list_tools(&mut self) -> Result<Vec<Tool>> {
        self.check_error().await?;

        if !self.initialized {
            anyhow::bail!("Client not initialized");
        }

        let tools = self.tools.lock().await;
        Ok(tools.clone())
    }

    async fn list_tools_paginated(&mut self, _cursor: Option<String>) -> Result<ListToolsResult> {
        self.check_error().await?;

        if !self.initialized {
            anyhow::bail!("Client not initialized");
        }

        let tools = self.tools.lock().await;
        Ok(ListToolsResult {
            tools: tools.clone(),
            next_cursor: None, // Mock doesn't paginate
        })
    }

    async fn call_tool(&mut self, name: &str, _arguments: Option<Value>) -> Result<CallToolResult> {
        self.check_error().await?;

        if !self.initialized {
            anyhow::bail!("Client not initialized");
        }

        let responses = self.tool_responses.lock().await;
        for resp in responses.iter() {
            if resp.name == name {
                return Ok(resp.response.clone());
            }
        }

        // Default response if no specific response configured
        Ok(Self::success_tool_result(&format!(
            "Mock response for tool: {}",
            name
        )))
    }

    async fn list_resources(&mut self) -> Result<Vec<Resource>> {
        self.check_error().await?;

        if !self.initialized {
            anyhow::bail!("Client not initialized");
        }

        let resources = self.resources.lock().await;
        Ok(resources.clone())
    }

    async fn list_resources_paginated(
        &mut self,
        _cursor: Option<String>,
    ) -> Result<ListResourcesResult> {
        self.check_error().await?;

        if !self.initialized {
            anyhow::bail!("Client not initialized");
        }

        let resources = self.resources.lock().await;
        Ok(ListResourcesResult {
            resources: resources.clone(),
            next_cursor: None, // Mock doesn't paginate
        })
    }

    async fn read_resource(&mut self, uri: &str) -> Result<ReadResourceResult> {
        self.check_error().await?;

        if !self.initialized {
            anyhow::bail!("Client not initialized");
        }

        let responses = self.resource_responses.lock().await;
        for resp in responses.iter() {
            if resp.uri == uri {
                return Ok(resp.response.clone());
            }
        }

        // Default response if no specific response configured
        Ok(Self::text_resource_result(
            uri,
            &format!("Mock content for resource: {}", uri),
        ))
    }

    async fn list_prompts(&mut self) -> Result<Vec<Prompt>> {
        self.check_error().await?;

        if !self.initialized {
            anyhow::bail!("Client not initialized");
        }

        let prompts = self.prompts.lock().await;
        Ok(prompts.clone())
    }

    async fn get_prompt(
        &mut self,
        name: &str,
        _arguments: Option<Value>,
    ) -> Result<GetPromptResult> {
        self.check_error().await?;

        if !self.initialized {
            anyhow::bail!("Client not initialized");
        }

        let responses = self.prompt_responses.lock().await;
        for resp in responses.iter() {
            if resp.name == name {
                return Ok(resp.response.clone());
            }
        }

        // Default response if no specific response configured
        Ok(Self::prompt_result(
            &format!("Mock prompt: {}", name),
            vec![("user", &format!("Mock message for prompt: {}", name))],
        ))
    }

    async fn ping(&mut self) -> Result<()> {
        self.check_error().await?;

        if !self.initialized {
            anyhow::bail!("Client not initialized");
        }

        Ok(())
    }

    async fn close(&mut self) -> Result<()> {
        self.closed = true;
        Ok(())
    }
}

/// Factory trait for creating MCP clients
///
/// This trait enables dependency injection by abstracting client creation.
/// Production code uses `DefaultClientFactory`, while tests can use
/// `MockClientFactory` to inject mock clients.
#[async_trait]
pub trait McpClientFactory: Send + Sync {
    /// Create a new MCP client connection
    async fn create(
        &self,
        target: &str,
        args: &[String],
        client_name: &str,
        client_version: &str,
        capabilities: Option<ClientCapabilities>,
    ) -> Result<Box<dyn McpClientTrait>>;
}

/// Mock client factory for testing
///
/// Returns a pre-configured MockMcpClient instead of creating real connections.
pub struct MockClientFactory {
    /// The mock client to return
    client: Arc<Mutex<Option<MockMcpClient>>>,
}

impl MockClientFactory {
    /// Create a factory that will return the given mock client
    pub fn new(client: MockMcpClient) -> Self {
        Self {
            client: Arc::new(Mutex::new(Some(client))),
        }
    }

    /// Create a factory with a fresh mock client
    pub fn with_new_client() -> (Self, MockMcpClient) {
        let client = MockMcpClient::new();
        let factory = Self::new(client.clone());
        (factory, client)
    }
}

#[async_trait]
impl McpClientFactory for MockClientFactory {
    async fn create(
        &self,
        _target: &str,
        _args: &[String],
        _client_name: &str,
        _client_version: &str,
        _capabilities: Option<ClientCapabilities>,
    ) -> Result<Box<dyn McpClientTrait>> {
        let mut client = self.client.lock().await;
        match client.take() {
            Some(c) => Ok(Box::new(c)),
            None => anyhow::bail!("MockClientFactory: client already consumed"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::mcp::{PromptsCapability, ResourcesCapability, ToolsCapability};

    #[tokio::test]
    async fn mock_client_initialize() {
        let mut client = MockMcpClient::new();
        assert!(!client.is_ready());

        let result = client.initialize().await.unwrap();
        assert!(client.is_ready());
        assert_eq!(result.protocol_version, "2024-11-05");
        assert_eq!(result.server_info.name, "mock-server");
    }

    #[tokio::test]
    async fn mock_client_with_capabilities() {
        let mut caps = ServerCapabilities::default();
        caps.tools = Some(ToolsCapability::default());

        let mut client = MockMcpClient::with_capabilities(caps);
        client.initialize().await.unwrap();

        let server_caps = client.server_capabilities().unwrap();
        assert!(server_caps.tools.is_some());
    }

    #[tokio::test]
    async fn mock_client_list_tools() {
        let mut client = MockMcpClient::new();
        client
            .set_tools(vec![
                MockMcpClient::create_test_tool("tool1", "First tool"),
                MockMcpClient::create_test_tool("tool2", "Second tool"),
            ])
            .await;

        client.initialize().await.unwrap();
        let tools = client.list_tools().await.unwrap();

        assert_eq!(tools.len(), 2);
        assert_eq!(tools[0].name, "tool1");
        assert_eq!(tools[1].name, "tool2");
    }

    #[tokio::test]
    async fn mock_client_add_tool() {
        let mut client = MockMcpClient::new();
        client
            .add_tool(MockMcpClient::create_test_tool("added_tool", "Added"))
            .await;

        client.initialize().await.unwrap();
        let tools = client.list_tools().await.unwrap();

        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name, "added_tool");
    }

    #[tokio::test]
    async fn mock_client_call_tool_default_response() {
        let mut client = MockMcpClient::new();
        client.initialize().await.unwrap();

        let result = client.call_tool("any_tool", None).await.unwrap();
        assert!(result.is_error.is_none());
        assert!(!result.content.is_empty());
    }

    #[tokio::test]
    async fn mock_client_call_tool_custom_response() {
        let mut client = MockMcpClient::new();
        client
            .set_tool_response(
                "my_tool",
                MockMcpClient::success_tool_result("custom result"),
            )
            .await;

        client.initialize().await.unwrap();
        let result = client.call_tool("my_tool", None).await.unwrap();

        if let Content::Text { text } = &result.content[0] {
            assert_eq!(text, "custom result");
        } else {
            panic!("Expected text content");
        }
    }

    #[tokio::test]
    async fn mock_client_call_tool_error_response() {
        let mut client = MockMcpClient::new();
        client
            .set_tool_response(
                "error_tool",
                MockMcpClient::error_tool_result("error message"),
            )
            .await;

        client.initialize().await.unwrap();
        let result = client.call_tool("error_tool", None).await.unwrap();

        assert_eq!(result.is_error, Some(true));
    }

    #[tokio::test]
    async fn mock_client_list_resources() {
        let mut client = MockMcpClient::new();
        client
            .set_resources(vec![MockMcpClient::create_test_resource(
                "file://test.txt",
                "test.txt",
            )])
            .await;

        client.initialize().await.unwrap();
        let resources = client.list_resources().await.unwrap();

        assert_eq!(resources.len(), 1);
        assert_eq!(resources[0].uri, "file://test.txt");
    }

    #[tokio::test]
    async fn mock_client_read_resource() {
        let mut client = MockMcpClient::new();
        client
            .set_resource_response(
                "file://test.txt",
                MockMcpClient::text_resource_result("file://test.txt", "file contents"),
            )
            .await;

        client.initialize().await.unwrap();
        let result = client.read_resource("file://test.txt").await.unwrap();

        assert_eq!(result.contents.len(), 1);
        let content = &result.contents[0];
        assert_eq!(content.text.as_deref(), Some("file contents"));
    }

    #[tokio::test]
    async fn mock_client_list_prompts() {
        let mut client = MockMcpClient::new();
        client
            .set_prompts(vec![MockMcpClient::create_test_prompt(
                "prompt1",
                "Test prompt",
            )])
            .await;

        client.initialize().await.unwrap();
        let prompts = client.list_prompts().await.unwrap();

        assert_eq!(prompts.len(), 1);
        assert_eq!(prompts[0].name, "prompt1");
    }

    #[tokio::test]
    async fn mock_client_get_prompt() {
        let mut client = MockMcpClient::new();
        client
            .set_prompt_response(
                "my_prompt",
                MockMcpClient::prompt_result("Test", vec![("user", "Hello")]),
            )
            .await;

        client.initialize().await.unwrap();
        let result = client.get_prompt("my_prompt", None).await.unwrap();

        assert_eq!(result.description, Some("Test".to_string()));
        assert_eq!(result.messages.len(), 1);
    }

    #[tokio::test]
    async fn mock_client_ping() {
        let mut client = MockMcpClient::new();
        client.initialize().await.unwrap();

        let result = client.ping().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn mock_client_close() {
        let mut client = MockMcpClient::new();
        client.initialize().await.unwrap();

        assert!(client.is_ready());
        client.close().await.unwrap();
        assert!(!client.is_ready());
        assert!(client.is_closed());
    }

    #[tokio::test]
    async fn mock_client_error_injection() {
        let mut client = MockMcpClient::new();
        client.set_next_error("Simulated error").await;

        let result = client.initialize().await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Simulated error"));
    }

    #[tokio::test]
    async fn mock_client_not_initialized_errors() {
        let mut client = MockMcpClient::new();

        let tools_result = client.list_tools().await;
        assert!(tools_result.is_err());

        let call_result = client.call_tool("test", None).await;
        assert!(call_result.is_err());

        let resources_result = client.list_resources().await;
        assert!(resources_result.is_err());

        let read_result = client.read_resource("uri").await;
        assert!(read_result.is_err());

        let prompts_result = client.list_prompts().await;
        assert!(prompts_result.is_err());

        let get_prompt_result = client.get_prompt("name", None).await;
        assert!(get_prompt_result.is_err());

        let ping_result = client.ping().await;
        assert!(ping_result.is_err());
    }

    #[tokio::test]
    async fn mock_client_transport_type() {
        let client = MockMcpClient::new();
        assert_eq!(client.transport_type(), "mock");
    }

    #[tokio::test]
    async fn mock_client_clone() {
        let client = MockMcpClient::new();
        client
            .add_tool(MockMcpClient::create_test_tool("shared", "Shared tool"))
            .await;

        let mut cloned = client.clone();
        cloned.initialize().await.unwrap();

        let tools = cloned.list_tools().await.unwrap();
        assert_eq!(tools.len(), 1);
    }

    #[tokio::test]
    async fn mock_client_default() {
        let client = MockMcpClient::default();
        assert!(!client.is_ready());
    }

    #[tokio::test]
    async fn mock_factory_returns_client() {
        let (factory, mock) = MockClientFactory::with_new_client();

        mock.add_tool(MockMcpClient::create_test_tool("test", "Test"))
            .await;

        let mut client = factory
            .create("target", &[], "client", "1.0", None)
            .await
            .unwrap();

        client.initialize().await.unwrap();
        let tools = client.list_tools().await.unwrap();
        assert_eq!(tools.len(), 1);
    }

    #[tokio::test]
    async fn mock_factory_consumes_client() {
        let client = MockMcpClient::new();
        let factory = MockClientFactory::new(client);

        // First call succeeds
        let _ = factory
            .create("target", &[], "client", "1.0", None)
            .await
            .unwrap();

        // Second call fails
        let result = factory.create("target", &[], "client", "1.0", None).await;
        assert!(result.is_err());
    }

    #[test]
    fn create_test_tool_helper() {
        let tool = MockMcpClient::create_test_tool("test", "description");
        assert_eq!(tool.name, "test");
        assert_eq!(tool.description, Some("description".to_string()));
    }

    #[test]
    fn create_test_resource_helper() {
        let resource = MockMcpClient::create_test_resource("file://test", "test");
        assert_eq!(resource.uri, "file://test");
        assert_eq!(resource.name, "test");
    }

    #[test]
    fn create_test_prompt_helper() {
        let prompt = MockMcpClient::create_test_prompt("test", "description");
        assert_eq!(prompt.name, "test");
        assert_eq!(prompt.description, Some("description".to_string()));
    }

    #[test]
    fn success_tool_result_helper() {
        let result = MockMcpClient::success_tool_result("output");
        assert!(result.is_error.is_none());
        assert_eq!(result.content.len(), 1);
    }

    #[test]
    fn error_tool_result_helper() {
        let result = MockMcpClient::error_tool_result("error");
        assert_eq!(result.is_error, Some(true));
    }

    #[test]
    fn text_resource_result_helper() {
        let result = MockMcpClient::text_resource_result("uri", "content");
        assert_eq!(result.contents.len(), 1);
    }

    #[test]
    fn prompt_result_helper() {
        let result = MockMcpClient::prompt_result("desc", vec![("user", "msg")]);
        assert_eq!(result.description, Some("desc".to_string()));
        assert_eq!(result.messages.len(), 1);
    }

    #[tokio::test]
    async fn mock_client_capabilities_access() {
        let mut caps = ServerCapabilities::default();
        caps.tools = Some(ToolsCapability::default());
        caps.resources = Some(ResourcesCapability::default());
        caps.prompts = Some(PromptsCapability::default());

        let mut client = MockMcpClient::with_capabilities(caps);

        // Before initialization, should be None
        assert!(client.server_capabilities().is_none());

        client.initialize().await.unwrap();

        // After initialization, should be Some
        let server_caps = client.server_capabilities().unwrap();
        assert!(server_caps.tools.is_some());
        assert!(server_caps.resources.is_some());
        assert!(server_caps.prompts.is_some());
    }
}
