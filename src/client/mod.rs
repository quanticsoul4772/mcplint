//! MCP Client - High-level API for interacting with MCP servers
//!
//! Provides a type-safe, ergonomic interface for:
//! - Connecting to MCP servers (stdio or HTTP)
//! - Protocol initialization and capability negotiation
//! - Tool discovery and invocation
//! - Resource and prompt access

#![allow(dead_code)] // Public API - methods will be used by consumers

pub mod mock;

// Re-export mock types for testing
pub use mock::McpClientTrait;

use anyhow::{Context, Result};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::Value;

use crate::protocol::{
    mcp::{
        self, CallToolParams, CallToolResult, GetPromptParams, GetPromptResult, InitializeParams,
        InitializeResult, ListPromptsResult, ListResourcesResult, ListToolsResult,
        PaginationParams, Prompt, ReadResourceParams, ReadResourceResult, Resource, Tool,
    },
    ClientCapabilities, ConnectionContext, ConnectionState, Implementation, ServerCapabilities,
};
use std::collections::HashMap;

use crate::transport::{connect, Transport, TransportConfig};

/// MCP Client for communicating with MCP servers
pub struct McpClient {
    transport: Box<dyn Transport>,
    context: ConnectionContext,
    client_info: Implementation,
}

impl McpClient {
    /// Create a new MCP client with the given transport
    pub fn new(transport: Box<dyn Transport>, client_info: Implementation) -> Self {
        Self {
            transport,
            context: ConnectionContext::new(),
            client_info,
        }
    }

    /// Mark the client as connected (transport is established)
    ///
    /// Call this after creating a client with `new()` when the transport
    /// has been established externally.
    pub fn mark_connected(&mut self) {
        self.context.set_connected();
    }

    /// Create a client with custom capabilities
    pub fn with_capabilities(
        transport: Box<dyn Transport>,
        client_info: Implementation,
        capabilities: ClientCapabilities,
    ) -> Self {
        Self {
            transport,
            context: ConnectionContext::with_capabilities(capabilities),
            client_info,
        }
    }

    /// Connect to an MCP server with auto-detection
    ///
    /// # Arguments
    /// * `target` - Server target (executable path or URL)
    /// * `args` - Arguments for the server (used for stdio transport)
    /// * `client_name` - Name of this client
    /// * `client_version` - Version of this client
    pub async fn connect(
        target: &str,
        args: &[String],
        client_name: &str,
        client_version: &str,
    ) -> Result<Self> {
        Self::connect_with_config(
            target,
            args,
            client_name,
            client_version,
            TransportConfig::default(),
        )
        .await
    }

    /// Connect with custom transport configuration
    pub async fn connect_with_config(
        target: &str,
        args: &[String],
        client_name: &str,
        client_version: &str,
        config: TransportConfig,
    ) -> Result<Self> {
        let transport = connect(target, args, &HashMap::new(), config).await?;
        let client_info = Implementation::new(client_name, client_version);

        let mut client = Self::new(transport, client_info);
        client.context.set_connected();

        Ok(client)
    }

    /// Initialize the connection with the server
    ///
    /// This must be called before any other operations.
    /// Performs capability negotiation and version agreement.
    pub async fn initialize(&mut self) -> Result<InitializeResult> {
        if !self.context.can_initialize() {
            anyhow::bail!(
                "Cannot initialize in current state: {}",
                self.context.state()
            );
        }

        self.context.set_initializing()?;

        let params = InitializeParams::new(
            self.client_info.clone(),
            self.context.client_capabilities().clone(),
        );

        let result: InitializeResult = self.request(mcp::methods::INITIALIZE, Some(params)).await?;

        // Validate protocol version
        if !mcp::is_supported_version(&result.protocol_version) {
            anyhow::bail!(
                "Unsupported protocol version: {} (supported: {}, {})",
                result.protocol_version,
                mcp::PROTOCOL_VERSION_2024_11_05,
                mcp::PROTOCOL_VERSION_2025_03_26
            );
        }

        // Update context with server info
        self.context.set_ready(
            result.protocol_version.clone(),
            result.capabilities.clone(),
            result.server_info.name.clone(),
            result.server_info.version.clone(),
        )?;

        // Send initialized notification
        self.notify(mcp::methods::INITIALIZED, None::<()>).await?;

        Ok(result)
    }

    // =========================================================================
    // Connection State
    // =========================================================================

    /// Check if the client is ready for operations
    pub fn is_ready(&self) -> bool {
        self.context.is_ready()
    }

    /// Get current connection state
    pub fn state(&self) -> ConnectionState {
        self.context.state()
    }

    /// Get server capabilities (after initialization)
    pub fn server_capabilities(&self) -> Option<&ServerCapabilities> {
        self.context.server_capabilities()
    }

    /// Get server info (name, version) after initialization
    pub fn server_info(&self) -> Option<(&str, &str)> {
        self.context.server_info()
    }

    /// Get negotiated protocol version
    pub fn protocol_version(&self) -> Option<&str> {
        self.context.protocol_version()
    }

    /// Get transport type
    pub fn transport_type(&self) -> &'static str {
        self.transport.transport_type()
    }

    // =========================================================================
    // Tools
    // =========================================================================

    /// List available tools from the server
    pub async fn list_tools(&mut self) -> Result<Vec<Tool>> {
        self.ensure_ready()?;

        if !self.context.server_has_tools() {
            return Ok(Vec::new());
        }

        let result: ListToolsResult = self.request(mcp::methods::TOOLS_LIST, None::<()>).await?;
        Ok(result.tools)
    }

    /// List tools with pagination
    pub async fn list_tools_paginated(
        &mut self,
        cursor: Option<String>,
    ) -> Result<ListToolsResult> {
        self.ensure_ready()?;

        if !self.context.server_has_tools() {
            return Ok(ListToolsResult {
                tools: Vec::new(),
                next_cursor: None,
            });
        }

        let params = cursor.map(|c| PaginationParams { cursor: Some(c) });
        self.request(mcp::methods::TOOLS_LIST, params).await
    }

    /// Call a tool on the server
    pub async fn call_tool(
        &mut self,
        name: &str,
        arguments: Option<Value>,
    ) -> Result<CallToolResult> {
        self.ensure_ready()?;

        if !self.context.server_has_tools() {
            anyhow::bail!("Server does not support tools");
        }

        let params = CallToolParams {
            name: name.to_string(),
            arguments,
        };

        self.request(mcp::methods::TOOLS_CALL, Some(params)).await
    }

    // =========================================================================
    // Resources
    // =========================================================================

    /// List available resources from the server
    pub async fn list_resources(&mut self) -> Result<Vec<Resource>> {
        self.ensure_ready()?;

        if !self.context.server_has_resources() {
            return Ok(Vec::new());
        }

        let result: ListResourcesResult = self
            .request(mcp::methods::RESOURCES_LIST, None::<()>)
            .await?;
        Ok(result.resources)
    }

    /// List resources with pagination
    pub async fn list_resources_paginated(
        &mut self,
        cursor: Option<String>,
    ) -> Result<ListResourcesResult> {
        self.ensure_ready()?;

        if !self.context.server_has_resources() {
            return Ok(ListResourcesResult {
                resources: Vec::new(),
                next_cursor: None,
            });
        }

        let params = cursor.map(|c| PaginationParams { cursor: Some(c) });
        self.request(mcp::methods::RESOURCES_LIST, params).await
    }

    /// Read a resource by URI
    pub async fn read_resource(&mut self, uri: &str) -> Result<ReadResourceResult> {
        self.ensure_ready()?;

        if !self.context.server_has_resources() {
            anyhow::bail!("Server does not support resources");
        }

        let params = ReadResourceParams {
            uri: uri.to_string(),
        };

        self.request(mcp::methods::RESOURCES_READ, Some(params))
            .await
    }

    // =========================================================================
    // Prompts
    // =========================================================================

    /// List available prompts from the server
    pub async fn list_prompts(&mut self) -> Result<Vec<Prompt>> {
        self.ensure_ready()?;

        if !self.context.server_has_prompts() {
            return Ok(Vec::new());
        }

        let result: ListPromptsResult =
            self.request(mcp::methods::PROMPTS_LIST, None::<()>).await?;
        Ok(result.prompts)
    }

    /// Get a prompt by name with optional arguments
    pub async fn get_prompt(
        &mut self,
        name: &str,
        arguments: Option<Value>,
    ) -> Result<GetPromptResult> {
        self.ensure_ready()?;

        if !self.context.server_has_prompts() {
            anyhow::bail!("Server does not support prompts");
        }

        let params = GetPromptParams {
            name: name.to_string(),
            arguments,
        };

        self.request(mcp::methods::PROMPTS_GET, Some(params)).await
    }

    // =========================================================================
    // Lifecycle
    // =========================================================================

    /// Close the connection to the server
    pub async fn close(&mut self) -> Result<()> {
        if self.context.is_ready() {
            self.context.set_shutting_down()?;
        }

        self.transport.close().await?;
        self.context.set_disconnected();

        Ok(())
    }

    /// Ping the server to check connection
    pub async fn ping(&mut self) -> Result<()> {
        self.ensure_ready()?;
        let _: Value = self.request(mcp::methods::PING, None::<()>).await?;
        Ok(())
    }

    // =========================================================================
    // Internal
    // =========================================================================

    fn ensure_ready(&self) -> Result<()> {
        if !self.context.is_ready() {
            anyhow::bail!(
                "Client not ready (current state: {}). Call initialize() first.",
                self.context.state()
            );
        }
        Ok(())
    }

    async fn request<P: Serialize, R: DeserializeOwned>(
        &mut self,
        method: &str,
        params: Option<P>,
    ) -> Result<R> {
        let params_value = params
            .map(|p| serde_json::to_value(p))
            .transpose()
            .context("Failed to serialize request params")?;

        let response = self.transport.request(method, params_value).await?;

        if let Some(error) = response.error {
            anyhow::bail!("RPC error [{}]: {}", error.code, error.message);
        }

        let result = response.result.unwrap_or(Value::Null);
        serde_json::from_value(result).context("Failed to deserialize response")
    }

    async fn notify<P: Serialize>(&mut self, method: &str, params: Option<P>) -> Result<()> {
        let params_value = params
            .map(|p| serde_json::to_value(p))
            .transpose()
            .context("Failed to serialize notification params")?;

        self.transport.notify(method, params_value).await
    }
}

impl Drop for McpClient {
    fn drop(&mut self) {
        // Note: We can't do async cleanup in Drop
        // Users should call close() explicitly for graceful shutdown
        if self.context.is_connected() {
            tracing::debug!("McpClient dropped without explicit close()");
        }
    }
}

/// Builder for creating MCP clients with custom configuration
pub struct McpClientBuilder {
    client_name: String,
    client_version: String,
    capabilities: ClientCapabilities,
    config: TransportConfig,
}

impl McpClientBuilder {
    pub fn new(client_name: impl Into<String>, client_version: impl Into<String>) -> Self {
        Self {
            client_name: client_name.into(),
            client_version: client_version.into(),
            capabilities: ClientCapabilities::default(),
            config: TransportConfig::default(),
        }
    }

    pub fn capabilities(mut self, capabilities: ClientCapabilities) -> Self {
        self.capabilities = capabilities;
        self
    }

    pub fn timeout_secs(mut self, secs: u64) -> Self {
        self.config.timeout_secs = secs;
        self
    }

    pub fn max_message_size(mut self, size: usize) -> Self {
        self.config.max_message_size = size;
        self
    }

    pub async fn connect(self, target: &str, args: &[String]) -> Result<McpClient> {
        let transport = connect(target, args, &HashMap::new(), self.config).await?;
        let client_info = Implementation::new(self.client_name, self.client_version);

        let mut client = McpClient::with_capabilities(transport, client_info, self.capabilities);
        client.context.set_connected();

        Ok(client)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::mcp::{PromptsCapability, ResourcesCapability, ToolsCapability};

    #[test]
    fn builder_creates_config() {
        let builder = McpClientBuilder::new("test", "1.0.0")
            .timeout_secs(60)
            .max_message_size(1024);

        assert_eq!(builder.config.timeout_secs, 60);
        assert_eq!(builder.config.max_message_size, 1024);
    }

    #[test]
    fn builder_default_values() {
        let builder = McpClientBuilder::new("mcplint", "0.1.0");

        assert_eq!(builder.client_name, "mcplint");
        assert_eq!(builder.client_version, "0.1.0");
        assert_eq!(builder.config.timeout_secs, 30); // default
    }

    #[test]
    fn builder_with_capabilities() {
        let caps = ClientCapabilities::default();
        let builder = McpClientBuilder::new("test", "1.0.0").capabilities(caps);

        assert!(builder.capabilities.roots.is_none());
    }

    #[test]
    fn default_capabilities() {
        let caps = ClientCapabilities::default();
        // Default should have no capabilities set
        assert!(caps.roots.is_none());
        assert!(caps.sampling.is_none());
    }

    #[test]
    fn server_capability_checks() {
        let mut caps = ServerCapabilities::default();
        assert!(!caps.has_tools());
        assert!(!caps.has_resources());

        caps.tools = Some(ToolsCapability::default());
        assert!(caps.has_tools());
    }

    #[test]
    fn server_capability_resources() {
        let mut caps = ServerCapabilities::default();
        assert!(!caps.has_resources());

        caps.resources = Some(ResourcesCapability::default());
        assert!(caps.has_resources());
    }

    #[test]
    fn server_capability_prompts() {
        let mut caps = ServerCapabilities::default();
        assert!(!caps.has_prompts());

        caps.prompts = Some(PromptsCapability::default());
        assert!(caps.has_prompts());
    }

    #[test]
    fn implementation_new() {
        let impl_info = Implementation::new("test-client", "1.0.0");
        assert_eq!(impl_info.name, "test-client");
        assert_eq!(impl_info.version, "1.0.0");
    }

    #[test]
    fn connection_context_initial_state() {
        let ctx = ConnectionContext::new();
        assert!(!ctx.is_ready());
        assert!(!ctx.is_connected());
        assert!(ctx.server_capabilities().is_none());
        assert!(ctx.protocol_version().is_none());
    }

    #[test]
    fn connection_context_with_capabilities() {
        let caps = ClientCapabilities::default();
        let ctx = ConnectionContext::with_capabilities(caps);
        assert!(!ctx.is_ready());
    }

    #[test]
    fn connection_context_state_transitions() {
        let mut ctx = ConnectionContext::new();

        // Initial state - Disconnected, cannot initialize yet
        assert!(!ctx.can_initialize());
        assert!(!ctx.is_connected());

        // After connecting - now in Connecting state
        ctx.set_connected();
        assert!(ctx.is_connected());
        assert!(ctx.can_initialize()); // Can initialize from Connecting state

        // After starting initialization
        assert!(ctx.set_initializing().is_ok());
        assert!(!ctx.can_initialize()); // No longer in Connecting state
    }

    #[test]
    fn connection_state_display() {
        let state = ConnectionState::Disconnected;
        assert!(!format!("{}", state).is_empty());

        let state = ConnectionState::Connecting;
        assert!(!format!("{}", state).is_empty());

        let state = ConnectionState::Ready;
        assert!(!format!("{}", state).is_empty());
    }

    #[test]
    fn transport_config_default() {
        let config = TransportConfig::default();
        assert_eq!(config.timeout_secs, 30);
        assert!(config.max_message_size > 0);
    }

    #[tokio::test]
    async fn mcp_client_new() {
        let transport = Box::new(crate::transport::mock::MockTransport::new());
        let client_info = Implementation::new("test-client", "1.0.0");
        let client = McpClient::new(transport, client_info);

        assert!(!client.is_ready());
        assert_eq!(client.state(), ConnectionState::Disconnected);
        assert!(client.server_capabilities().is_none());
        assert_eq!(client.transport_type(), "mock");
    }

    #[tokio::test]
    async fn mcp_client_mark_connected() {
        let transport = Box::new(crate::transport::mock::MockTransport::new());
        let client_info = Implementation::new("test-client", "1.0.0");
        let mut client = McpClient::new(transport, client_info);

        assert_eq!(client.state(), ConnectionState::Disconnected);
        client.mark_connected();
        assert_eq!(client.state(), ConnectionState::Connecting);
    }

    #[tokio::test]
    async fn mcp_client_with_capabilities() {
        let transport = Box::new(crate::transport::mock::MockTransport::new());
        let client_info = Implementation::new("test-client", "1.0.0");
        let caps = ClientCapabilities::default();
        let client = McpClient::with_capabilities(transport, client_info, caps);

        assert!(!client.is_ready());
        assert_eq!(client.state(), ConnectionState::Disconnected);
    }

    #[tokio::test]
    async fn mcp_client_initialize_success() {
        use crate::protocol::mcp::{InitializeResult, ToolsCapability};
        use crate::protocol::RequestId;
        use crate::transport::mock::MockTransport;
        use serde_json::json;

        let mock_transport = MockTransport::new();
        let server_caps = ServerCapabilities {
            tools: Some(ToolsCapability::default()),
            ..ServerCapabilities::default()
        };

        let init_result = InitializeResult {
            protocol_version: "2024-11-05".to_string(),
            capabilities: server_caps,
            server_info: Implementation::new("test-server", "1.0.0"),
            instructions: None,
        };

        mock_transport
            .queue_responses(vec![
                MockTransport::success_response(RequestId::Number(1), json!(init_result)),
                MockTransport::success_response(RequestId::Number(2), json!({})), // initialized notification
            ])
            .await;

        let transport = Box::new(mock_transport);
        let client_info = Implementation::new("test-client", "1.0.0");
        let mut client = McpClient::new(transport, client_info);
        client.mark_connected();

        let result = client.initialize().await.unwrap();
        assert_eq!(result.protocol_version, "2024-11-05");
        assert!(client.is_ready());
        assert_eq!(client.state(), ConnectionState::Ready);
        assert!(client.server_capabilities().is_some());
        assert_eq!(client.server_info(), Some(("test-server", "1.0.0")));
        assert_eq!(client.protocol_version(), Some("2024-11-05"));
    }

    #[tokio::test]
    async fn mcp_client_initialize_unsupported_version() {
        use crate::protocol::mcp::InitializeResult;
        use crate::protocol::RequestId;
        use crate::transport::mock::MockTransport;
        use serde_json::json;

        let mock_transport = MockTransport::new();
        let server_caps = ServerCapabilities::default();

        let init_result = InitializeResult {
            protocol_version: "1999-01-01".to_string(), // Unsupported version
            capabilities: server_caps,
            server_info: Implementation::new("test-server", "1.0.0"),
            instructions: None,
        };

        mock_transport
            .queue_response(MockTransport::success_response(
                RequestId::Number(1),
                json!(init_result),
            ))
            .await;

        let transport = Box::new(mock_transport);
        let client_info = Implementation::new("test-client", "1.0.0");
        let mut client = McpClient::new(transport, client_info);
        client.mark_connected();

        let result = client.initialize().await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Unsupported protocol version"));
    }

    #[tokio::test]
    async fn mcp_client_initialize_wrong_state() {
        let transport = Box::new(crate::transport::mock::MockTransport::new());
        let client_info = Implementation::new("test-client", "1.0.0");
        let mut client = McpClient::new(transport, client_info);

        // Try to initialize without connecting first
        let result = client.initialize().await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Cannot initialize"));
    }

    #[tokio::test]
    async fn mcp_client_ensure_ready_fails_when_not_ready() {
        use crate::transport::mock::MockTransport;

        let mock_transport = MockTransport::new();
        let transport = Box::new(mock_transport);
        let client_info = Implementation::new("test-client", "1.0.0");
        let mut client = McpClient::new(transport, client_info);

        let result = client.list_tools().await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not ready"));
    }

    #[tokio::test]
    async fn mcp_client_list_tools_no_capability() {
        use crate::protocol::mcp::InitializeResult;
        use crate::protocol::RequestId;
        use crate::transport::mock::MockTransport;
        use serde_json::json;

        let mock_transport = MockTransport::new();
        let server_caps = ServerCapabilities::default(); // No tools capability

        let init_result = InitializeResult {
            protocol_version: "2024-11-05".to_string(),
            capabilities: server_caps,
            server_info: Implementation::new("test-server", "1.0.0"),
            instructions: None,
        };

        mock_transport
            .queue_responses(vec![
                MockTransport::success_response(RequestId::Number(1), json!(init_result)),
                // notify does not consume response
            ])
            .await;

        let transport = Box::new(mock_transport);
        let client_info = Implementation::new("test-client", "1.0.0");
        let mut client = McpClient::new(transport, client_info);
        client.mark_connected();
        client.initialize().await.unwrap();

        let tools = client.list_tools().await.unwrap();
        assert!(tools.is_empty());
    }

    #[tokio::test]
    async fn mcp_client_list_tools_paginated_no_capability() {
        use crate::protocol::mcp::InitializeResult;
        use crate::protocol::RequestId;
        use crate::transport::mock::MockTransport;
        use serde_json::json;

        let mock_transport = MockTransport::new();
        let server_caps = ServerCapabilities::default();

        let init_result = InitializeResult {
            protocol_version: "2024-11-05".to_string(),
            capabilities: server_caps,
            server_info: Implementation::new("test-server", "1.0.0"),
            instructions: None,
        };

        mock_transport
            .queue_responses(vec![
                MockTransport::success_response(RequestId::Number(1), json!(init_result)),
                // notify does not consume response
            ])
            .await;

        let transport = Box::new(mock_transport);
        let client_info = Implementation::new("test-client", "1.0.0");
        let mut client = McpClient::new(transport, client_info);
        client.mark_connected();
        client.initialize().await.unwrap();

        let result = client.list_tools_paginated(None).await.unwrap();
        assert!(result.tools.is_empty());
        assert!(result.next_cursor.is_none());
    }

    #[tokio::test]
    async fn mcp_client_call_tool_no_capability() {
        use crate::protocol::mcp::InitializeResult;
        use crate::protocol::RequestId;
        use crate::transport::mock::MockTransport;
        use serde_json::json;

        let mock_transport = MockTransport::new();
        let server_caps = ServerCapabilities::default();

        let init_result = InitializeResult {
            protocol_version: "2024-11-05".to_string(),
            capabilities: server_caps,
            server_info: Implementation::new("test-server", "1.0.0"),
            instructions: None,
        };

        mock_transport
            .queue_responses(vec![
                MockTransport::success_response(RequestId::Number(1), json!(init_result)),
                // notify does not consume response
            ])
            .await;

        let transport = Box::new(mock_transport);
        let client_info = Implementation::new("test-client", "1.0.0");
        let mut client = McpClient::new(transport, client_info);
        client.mark_connected();
        client.initialize().await.unwrap();

        let result = client.call_tool("test", None).await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("does not support tools"));
    }

    #[tokio::test]
    async fn mcp_client_list_resources_no_capability() {
        use crate::protocol::mcp::InitializeResult;
        use crate::protocol::RequestId;
        use crate::transport::mock::MockTransport;
        use serde_json::json;

        let mock_transport = MockTransport::new();
        let server_caps = ServerCapabilities::default();

        let init_result = InitializeResult {
            protocol_version: "2024-11-05".to_string(),
            capabilities: server_caps,
            server_info: Implementation::new("test-server", "1.0.0"),
            instructions: None,
        };

        mock_transport
            .queue_responses(vec![
                MockTransport::success_response(RequestId::Number(1), json!(init_result)),
                // notify does not consume response
            ])
            .await;

        let transport = Box::new(mock_transport);
        let client_info = Implementation::new("test-client", "1.0.0");
        let mut client = McpClient::new(transport, client_info);
        client.mark_connected();
        client.initialize().await.unwrap();

        let resources = client.list_resources().await.unwrap();
        assert!(resources.is_empty());
    }

    #[tokio::test]
    async fn mcp_client_list_resources_paginated_no_capability() {
        use crate::protocol::mcp::InitializeResult;
        use crate::protocol::RequestId;
        use crate::transport::mock::MockTransport;
        use serde_json::json;

        let mock_transport = MockTransport::new();
        let server_caps = ServerCapabilities::default();

        let init_result = InitializeResult {
            protocol_version: "2024-11-05".to_string(),
            capabilities: server_caps,
            server_info: Implementation::new("test-server", "1.0.0"),
            instructions: None,
        };

        mock_transport
            .queue_responses(vec![
                MockTransport::success_response(RequestId::Number(1), json!(init_result)),
                // notify does not consume response
            ])
            .await;

        let transport = Box::new(mock_transport);
        let client_info = Implementation::new("test-client", "1.0.0");
        let mut client = McpClient::new(transport, client_info);
        client.mark_connected();
        client.initialize().await.unwrap();

        let result = client.list_resources_paginated(None).await.unwrap();
        assert!(result.resources.is_empty());
        assert!(result.next_cursor.is_none());
    }

    #[tokio::test]
    async fn mcp_client_read_resource_no_capability() {
        use crate::protocol::mcp::InitializeResult;
        use crate::protocol::RequestId;
        use crate::transport::mock::MockTransport;
        use serde_json::json;

        let mock_transport = MockTransport::new();
        let server_caps = ServerCapabilities::default();

        let init_result = InitializeResult {
            protocol_version: "2024-11-05".to_string(),
            capabilities: server_caps,
            server_info: Implementation::new("test-server", "1.0.0"),
            instructions: None,
        };

        mock_transport
            .queue_responses(vec![
                MockTransport::success_response(RequestId::Number(1), json!(init_result)),
                // notify does not consume response
            ])
            .await;

        let transport = Box::new(mock_transport);
        let client_info = Implementation::new("test-client", "1.0.0");
        let mut client = McpClient::new(transport, client_info);
        client.mark_connected();
        client.initialize().await.unwrap();

        let result = client.read_resource("file://test").await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("does not support resources"));
    }

    #[tokio::test]
    async fn mcp_client_list_prompts_no_capability() {
        use crate::protocol::mcp::InitializeResult;
        use crate::protocol::RequestId;
        use crate::transport::mock::MockTransport;
        use serde_json::json;

        let mock_transport = MockTransport::new();
        let server_caps = ServerCapabilities::default();

        let init_result = InitializeResult {
            protocol_version: "2024-11-05".to_string(),
            capabilities: server_caps,
            server_info: Implementation::new("test-server", "1.0.0"),
            instructions: None,
        };

        mock_transport
            .queue_responses(vec![
                MockTransport::success_response(RequestId::Number(1), json!(init_result)),
                // notify does not consume response
            ])
            .await;

        let transport = Box::new(mock_transport);
        let client_info = Implementation::new("test-client", "1.0.0");
        let mut client = McpClient::new(transport, client_info);
        client.mark_connected();
        client.initialize().await.unwrap();

        let prompts = client.list_prompts().await.unwrap();
        assert!(prompts.is_empty());
    }

    #[tokio::test]
    async fn mcp_client_get_prompt_no_capability() {
        use crate::protocol::mcp::InitializeResult;
        use crate::protocol::RequestId;
        use crate::transport::mock::MockTransport;
        use serde_json::json;

        let mock_transport = MockTransport::new();
        let server_caps = ServerCapabilities::default();

        let init_result = InitializeResult {
            protocol_version: "2024-11-05".to_string(),
            capabilities: server_caps,
            server_info: Implementation::new("test-server", "1.0.0"),
            instructions: None,
        };

        mock_transport
            .queue_responses(vec![
                MockTransport::success_response(RequestId::Number(1), json!(init_result)),
                // notify does not consume response
            ])
            .await;

        let transport = Box::new(mock_transport);
        let client_info = Implementation::new("test-client", "1.0.0");
        let mut client = McpClient::new(transport, client_info);
        client.mark_connected();
        client.initialize().await.unwrap();

        let result = client.get_prompt("test", None).await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("does not support prompts"));
    }

    #[tokio::test]
    async fn mcp_client_ping() {
        use crate::protocol::mcp::InitializeResult;
        use crate::protocol::RequestId;
        use crate::transport::mock::MockTransport;
        use serde_json::json;

        let mock_transport = MockTransport::new();
        let server_caps = ServerCapabilities::default();

        let init_result = InitializeResult {
            protocol_version: "2024-11-05".to_string(),
            capabilities: server_caps,
            server_info: Implementation::new("test-server", "1.0.0"),
            instructions: None,
        };

        mock_transport
            .queue_responses(vec![
                MockTransport::success_response(RequestId::Number(1), json!(init_result)),
                // notify does not consume response
                MockTransport::success_response(RequestId::Number(2), json!({})), // ping response
            ])
            .await;

        let transport = Box::new(mock_transport);
        let client_info = Implementation::new("test-client", "1.0.0");
        let mut client = McpClient::new(transport, client_info);
        client.mark_connected();
        client.initialize().await.unwrap();

        let result = client.ping().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn mcp_client_close() {
        use crate::protocol::mcp::InitializeResult;
        use crate::protocol::RequestId;
        use crate::transport::mock::MockTransport;
        use serde_json::json;

        let mock_transport = MockTransport::new();
        let server_caps = ServerCapabilities::default();

        let init_result = InitializeResult {
            protocol_version: "2024-11-05".to_string(),
            capabilities: server_caps,
            server_info: Implementation::new("test-server", "1.0.0"),
            instructions: None,
        };

        mock_transport
            .queue_responses(vec![
                MockTransport::success_response(RequestId::Number(1), json!(init_result)),
                // notify does not consume response
            ])
            .await;

        let transport = Box::new(mock_transport.clone());
        let client_info = Implementation::new("test-client", "1.0.0");
        let mut client = McpClient::new(transport, client_info);
        client.mark_connected();
        client.initialize().await.unwrap();

        assert!(client.is_ready());
        client.close().await.unwrap();
        assert!(!client.is_ready());
        assert_eq!(client.state(), ConnectionState::Disconnected);
        assert!(mock_transport.is_closed().await);
    }

    #[tokio::test]
    async fn mcp_client_close_without_init() {
        let mock_transport = crate::transport::mock::MockTransport::new();
        let transport = Box::new(mock_transport.clone());
        let client_info = Implementation::new("test-client", "1.0.0");
        let mut client = McpClient::new(transport, client_info);

        let result = client.close().await;
        assert!(result.is_ok());
        assert!(mock_transport.is_closed().await);
    }

    #[tokio::test]
    async fn mcp_client_drop_warns_if_connected() {
        use crate::protocol::mcp::InitializeResult;
        use crate::protocol::RequestId;
        use crate::transport::mock::MockTransport;
        use serde_json::json;

        let mock_transport = MockTransport::new();
        let server_caps = ServerCapabilities::default();

        let init_result = InitializeResult {
            protocol_version: "2024-11-05".to_string(),
            capabilities: server_caps,
            server_info: Implementation::new("test-server", "1.0.0"),
            instructions: None,
        };

        mock_transport
            .queue_responses(vec![
                MockTransport::success_response(RequestId::Number(1), json!(init_result)),
                // notify does not consume response
            ])
            .await;

        let transport = Box::new(mock_transport);
        let client_info = Implementation::new("test-client", "1.0.0");
        let mut client = McpClient::new(transport, client_info);
        client.mark_connected();
        client.initialize().await.unwrap();

        // Drop without closing - should trigger debug log
        drop(client);
    }

    #[tokio::test]
    async fn mcp_client_server_info_getter() {
        use crate::protocol::mcp::InitializeResult;
        use crate::protocol::RequestId;
        use crate::transport::mock::MockTransport;
        use serde_json::json;

        let mock_transport = MockTransport::new();
        let server_caps = ServerCapabilities::default();

        let init_result = InitializeResult {
            protocol_version: "2024-11-05".to_string(),
            capabilities: server_caps,
            server_info: Implementation::new("test-server", "2.3.4"),
            instructions: None,
        };

        mock_transport
            .queue_responses(vec![
                MockTransport::success_response(RequestId::Number(1), json!(init_result)),
                // notify does not consume response
            ])
            .await;

        let transport = Box::new(mock_transport);
        let client_info = Implementation::new("test-client", "1.0.0");
        let mut client = McpClient::new(transport, client_info);
        client.mark_connected();

        assert!(client.server_info().is_none());
        client.initialize().await.unwrap();

        let (name, version) = client.server_info().unwrap();
        assert_eq!(name, "test-server");
        assert_eq!(version, "2.3.4");
    }

    #[tokio::test]
    async fn mcp_client_protocol_version_getter() {
        use crate::protocol::mcp::InitializeResult;
        use crate::protocol::RequestId;
        use crate::transport::mock::MockTransport;
        use serde_json::json;

        let mock_transport = MockTransport::new();
        let server_caps = ServerCapabilities::default();

        let init_result = InitializeResult {
            protocol_version: "2025-03-26".to_string(),
            capabilities: server_caps,
            server_info: Implementation::new("test-server", "1.0.0"),
            instructions: None,
        };

        mock_transport
            .queue_responses(vec![
                MockTransport::success_response(RequestId::Number(1), json!(init_result)),
                // notify does not consume response
            ])
            .await;

        let transport = Box::new(mock_transport);
        let client_info = Implementation::new("test-client", "1.0.0");
        let mut client = McpClient::new(transport, client_info);
        client.mark_connected();

        assert!(client.protocol_version().is_none());
        client.initialize().await.unwrap();

        assert_eq!(client.protocol_version(), Some("2025-03-26"));
    }

    // =========================================================================
    // NEW TESTS - Client State Management
    // =========================================================================

    #[tokio::test]
    async fn client_state_connected_to_initializing() {
        use crate::transport::mock::MockTransport;

        let transport = Box::new(MockTransport::new());
        let client_info = Implementation::new("test-client", "1.0.0");
        let mut client = McpClient::new(transport, client_info);

        assert_eq!(client.state(), ConnectionState::Disconnected);

        client.mark_connected();
        assert_eq!(client.state(), ConnectionState::Connecting);
        assert!(client.context.can_initialize());
    }

    #[tokio::test]
    async fn client_state_cannot_initialize_from_disconnected() {
        use crate::transport::mock::MockTransport;

        let transport = Box::new(MockTransport::new());
        let client_info = Implementation::new("test-client", "1.0.0");
        let client = McpClient::new(transport, client_info);

        assert_eq!(client.state(), ConnectionState::Disconnected);
        assert!(!client.context.can_initialize());
    }

    #[tokio::test]
    async fn client_state_ready_to_shutting_down() {
        use crate::protocol::mcp::InitializeResult;
        use crate::protocol::RequestId;
        use crate::transport::mock::MockTransport;
        use serde_json::json;

        let mock_transport = MockTransport::new();
        let server_caps = ServerCapabilities::default();

        let init_result = InitializeResult {
            protocol_version: "2024-11-05".to_string(),
            capabilities: server_caps,
            server_info: Implementation::new("test-server", "1.0.0"),
            instructions: None,
        };

        mock_transport
            .queue_responses(vec![
                MockTransport::success_response(RequestId::Number(1), json!(init_result)),
                // notify does not consume response
            ])
            .await;

        let transport = Box::new(mock_transport.clone());
        let client_info = Implementation::new("test-client", "1.0.0");
        let mut client = McpClient::new(transport, client_info);
        client.mark_connected();
        client.initialize().await.unwrap();

        assert_eq!(client.state(), ConnectionState::Ready);

        client.close().await.unwrap();
        assert_eq!(client.state(), ConnectionState::Disconnected);
    }

    // =========================================================================
    // NEW TESTS - Request/Response Error Handling
    // =========================================================================

    #[tokio::test]
    async fn request_with_rpc_error_code() {
        use crate::protocol::RequestId;
        use crate::transport::mock::MockTransport;

        let mock_transport = MockTransport::new();
        mock_transport
            .queue_response(MockTransport::error_response(
                RequestId::Number(1),
                -32600,
                "Invalid Request",
            ))
            .await;

        let transport = Box::new(mock_transport);
        let client_info = Implementation::new("test-client", "1.0.0");
        let mut client = McpClient::new(transport, client_info);
        client.mark_connected();

        let result = client.initialize().await;
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("RPC error"));
        assert!(error_msg.contains("-32600"));
        assert!(error_msg.contains("Invalid Request"));
    }

    #[tokio::test]
    async fn request_with_custom_error_code() {
        use crate::protocol::mcp::{InitializeResult, ToolsCapability};
        use crate::protocol::RequestId;
        use crate::transport::mock::MockTransport;
        use serde_json::json;

        let mock_transport = MockTransport::new();
        let server_caps = ServerCapabilities {
            tools: Some(ToolsCapability::default()),
            ..ServerCapabilities::default()
        };

        let init_result = InitializeResult {
            protocol_version: "2024-11-05".to_string(),
            capabilities: server_caps,
            server_info: Implementation::new("test-server", "1.0.0"),
            instructions: None,
        };

        mock_transport
            .queue_responses(vec![
                MockTransport::success_response(RequestId::Number(1), json!(init_result)),
                // notify does not consume response
                MockTransport::error_response(RequestId::Number(2), -32001, "Custom error"),
            ])
            .await;

        let transport = Box::new(mock_transport);
        let client_info = Implementation::new("test-client", "1.0.0");
        let mut client = McpClient::new(transport, client_info);
        client.mark_connected();
        client.initialize().await.unwrap();

        let result = client.list_tools().await;
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Custom error"));
    }

    // =========================================================================
    // NEW TESTS - Pagination Logic
    // =========================================================================

    #[tokio::test]
    async fn list_tools_paginated_with_cursor() {
        use crate::protocol::mcp::{InitializeResult, ListToolsResult, Tool, ToolsCapability};
        use crate::protocol::RequestId;
        use crate::transport::mock::MockTransport;
        use serde_json::json;

        let mock_transport = MockTransport::new();
        let server_caps = ServerCapabilities {
            tools: Some(ToolsCapability::default()),
            ..ServerCapabilities::default()
        };

        let init_result = InitializeResult {
            protocol_version: "2024-11-05".to_string(),
            capabilities: server_caps,
            server_info: Implementation::new("test-server", "1.0.0"),
            instructions: None,
        };

        let tools_result = ListToolsResult {
            tools: vec![Tool {
                name: "test_tool".to_string(),
                description: Some("A test tool".to_string()),
                input_schema: json!({}),
            }],
            next_cursor: Some("cursor123".to_string()),
        };

        mock_transport
            .queue_responses(vec![
                MockTransport::success_response(RequestId::Number(1), json!(init_result)),
                // notify does not consume response
                MockTransport::success_response(RequestId::Number(2), json!(tools_result)),
            ])
            .await;

        let transport = Box::new(mock_transport);
        let client_info = Implementation::new("test-client", "1.0.0");
        let mut client = McpClient::new(transport, client_info);
        client.mark_connected();
        client.initialize().await.unwrap();

        let result = client
            .list_tools_paginated(Some("prev_cursor".to_string()))
            .await
            .unwrap();
        assert_eq!(result.tools.len(), 1);
        assert_eq!(result.next_cursor, Some("cursor123".to_string()));
    }

    #[tokio::test]
    async fn list_resources_paginated_with_cursor() {
        use crate::protocol::mcp::{
            InitializeResult, ListResourcesResult, Resource, ResourcesCapability,
        };
        use crate::protocol::RequestId;
        use crate::transport::mock::MockTransport;
        use serde_json::json;

        let mock_transport = MockTransport::new();
        let server_caps = ServerCapabilities {
            resources: Some(ResourcesCapability::default()),
            ..ServerCapabilities::default()
        };

        let init_result = InitializeResult {
            protocol_version: "2024-11-05".to_string(),
            capabilities: server_caps,
            server_info: Implementation::new("test-server", "1.0.0"),
            instructions: None,
        };

        let resources_result = ListResourcesResult {
            resources: vec![Resource {
                uri: "file:///test.txt".to_string(),
                name: "test.txt".to_string(),
                description: Some("A test resource".to_string()),
                mime_type: Some("text/plain".to_string()),
            }],
            next_cursor: None,
        };

        mock_transport
            .queue_responses(vec![
                MockTransport::success_response(RequestId::Number(1), json!(init_result)),
                // notify does not consume response
                MockTransport::success_response(RequestId::Number(2), json!(resources_result)),
            ])
            .await;

        let transport = Box::new(mock_transport);
        let client_info = Implementation::new("test-client", "1.0.0");
        let mut client = McpClient::new(transport, client_info);
        client.mark_connected();
        client.initialize().await.unwrap();

        let result = client
            .list_resources_paginated(Some("cursor".to_string()))
            .await
            .unwrap();
        assert_eq!(result.resources.len(), 1);
        assert_eq!(result.next_cursor, None);
    }

    // =========================================================================
    // NEW TESTS - Builder Pattern Validation
    // =========================================================================

    #[test]
    fn builder_chaining() {
        let caps = ClientCapabilities::default();
        let builder = McpClientBuilder::new("test", "1.0.0")
            .timeout_secs(120)
            .max_message_size(2048)
            .capabilities(caps);

        assert_eq!(builder.config.timeout_secs, 120);
        assert_eq!(builder.config.max_message_size, 2048);
        assert_eq!(builder.client_name, "test");
        assert_eq!(builder.client_version, "1.0.0");
    }

    #[test]
    fn builder_default_capabilities() {
        let builder = McpClientBuilder::new("test", "1.0.0");

        assert!(builder.capabilities.roots.is_none());
        assert!(builder.capabilities.sampling.is_none());
    }

    #[test]
    fn builder_timeout_override() {
        let builder1 = McpClientBuilder::new("test", "1.0.0").timeout_secs(60);
        let builder2 = builder1.timeout_secs(90);

        assert_eq!(builder2.config.timeout_secs, 90);
    }

    #[test]
    fn builder_message_size_override() {
        let builder1 = McpClientBuilder::new("test", "1.0.0").max_message_size(1024);
        let builder2 = builder1.max_message_size(4096);

        assert_eq!(builder2.config.max_message_size, 4096);
    }

    // =========================================================================
    // NEW TESTS - Connection Context Edge Cases
    // =========================================================================

    #[test]
    fn connection_context_state_display_all_variants() {
        let states = vec![
            ConnectionState::Disconnected,
            ConnectionState::Connecting,
            ConnectionState::Initializing,
            ConnectionState::Ready,
            ConnectionState::ShuttingDown,
        ];

        for state in states {
            let display = format!("{}", state);
            assert!(!display.is_empty());
        }
    }

    #[test]
    fn connection_context_multiple_set_connected() {
        let mut ctx = ConnectionContext::new();

        ctx.set_connected();
        assert!(ctx.is_connected());

        // Calling set_connected again should be idempotent
        ctx.set_connected();
        assert!(ctx.is_connected());
    }

    #[test]
    fn connection_context_set_disconnected() {
        let mut ctx = ConnectionContext::new();

        ctx.set_connected();
        assert!(ctx.is_connected());

        ctx.set_disconnected();
        assert!(!ctx.is_connected());
        assert_eq!(ctx.state(), ConnectionState::Disconnected);
    }

    // =========================================================================
    // NEW TESTS - Transport Type and Info
    // =========================================================================

    #[tokio::test]
    async fn client_transport_type_is_accessible() {
        use crate::transport::mock::MockTransport;

        let transport = Box::new(MockTransport::new());
        let client_info = Implementation::new("test-client", "1.0.0");
        let client = McpClient::new(transport, client_info);

        assert_eq!(client.transport_type(), "mock");
    }

    #[tokio::test]
    async fn client_server_info_none_before_init() {
        use crate::transport::mock::MockTransport;

        let transport = Box::new(MockTransport::new());
        let client_info = Implementation::new("test-client", "1.0.0");
        let client = McpClient::new(transport, client_info);

        assert!(client.server_info().is_none());
        assert!(client.protocol_version().is_none());
        assert!(client.server_capabilities().is_none());
    }

    // =========================================================================
    // NEW TESTS - Ensure Ready Validation
    // =========================================================================

    #[tokio::test]
    async fn ensure_ready_fails_in_disconnected_state() {
        use crate::transport::mock::MockTransport;

        let mock_transport = MockTransport::new();
        let transport = Box::new(mock_transport);
        let client_info = Implementation::new("test-client", "1.0.0");
        let mut client = McpClient::new(transport, client_info);

        let result = client.ping().await;
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("not ready"));
    }

    #[tokio::test]
    async fn ensure_ready_fails_in_connecting_state() {
        use crate::transport::mock::MockTransport;

        let mock_transport = MockTransport::new();
        let transport = Box::new(mock_transport);
        let client_info = Implementation::new("test-client", "1.0.0");
        let mut client = McpClient::new(transport, client_info);
        client.mark_connected();

        let result = client.list_tools().await;
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("not ready"));
    }

    // =========================================================================
    // NEW TESTS - Tool Operations with Capabilities
    // =========================================================================

    #[tokio::test]
    async fn call_tool_with_arguments() {
        use crate::protocol::mcp::{CallToolResult, InitializeResult, ToolsCapability};
        use crate::protocol::RequestId;
        use crate::transport::mock::MockTransport;
        use serde_json::json;

        let mock_transport = MockTransport::new();
        let server_caps = ServerCapabilities {
            tools: Some(ToolsCapability::default()),
            ..ServerCapabilities::default()
        };

        let init_result = InitializeResult {
            protocol_version: "2024-11-05".to_string(),
            capabilities: server_caps,
            server_info: Implementation::new("test-server", "1.0.0"),
            instructions: None,
        };

        let tool_result = CallToolResult {
            content: vec![],
            is_error: Some(false),
        };

        mock_transport
            .queue_responses(vec![
                MockTransport::success_response(RequestId::Number(1), json!(init_result)),
                // notify does not consume response
                MockTransport::success_response(RequestId::Number(2), json!(tool_result)),
            ])
            .await;

        let transport = Box::new(mock_transport);
        let client_info = Implementation::new("test-client", "1.0.0");
        let mut client = McpClient::new(transport, client_info);
        client.mark_connected();
        client.initialize().await.unwrap();

        let args = json!({"param": "value"});
        let result = client.call_tool("test_tool", Some(args)).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn call_tool_without_arguments() {
        use crate::protocol::mcp::{CallToolResult, InitializeResult, ToolsCapability};
        use crate::protocol::RequestId;
        use crate::transport::mock::MockTransport;
        use serde_json::json;

        let mock_transport = MockTransport::new();
        let server_caps = ServerCapabilities {
            tools: Some(ToolsCapability::default()),
            ..ServerCapabilities::default()
        };

        let init_result = InitializeResult {
            protocol_version: "2024-11-05".to_string(),
            capabilities: server_caps,
            server_info: Implementation::new("test-server", "1.0.0"),
            instructions: None,
        };

        let tool_result = CallToolResult {
            content: vec![],
            is_error: Some(false),
        };

        mock_transport
            .queue_responses(vec![
                MockTransport::success_response(RequestId::Number(1), json!(init_result)),
                // notify does not consume response
                MockTransport::success_response(RequestId::Number(2), json!(tool_result)),
            ])
            .await;

        let transport = Box::new(mock_transport);
        let client_info = Implementation::new("test-client", "1.0.0");
        let mut client = McpClient::new(transport, client_info);
        client.mark_connected();
        client.initialize().await.unwrap();

        let result = client.call_tool("test_tool", None).await;
        assert!(result.is_ok());
    }

    // =========================================================================
    // NEW TESTS - Resource Operations with Capabilities
    // =========================================================================

    #[tokio::test]
    async fn read_resource_with_uri() {
        use crate::protocol::mcp::{InitializeResult, ReadResourceResult, ResourcesCapability};
        use crate::protocol::RequestId;
        use crate::transport::mock::MockTransport;
        use serde_json::json;

        let mock_transport = MockTransport::new();
        let server_caps = ServerCapabilities {
            resources: Some(ResourcesCapability::default()),
            ..ServerCapabilities::default()
        };

        let init_result = InitializeResult {
            protocol_version: "2024-11-05".to_string(),
            capabilities: server_caps,
            server_info: Implementation::new("test-server", "1.0.0"),
            instructions: None,
        };

        let resource_result = ReadResourceResult { contents: vec![] };

        mock_transport
            .queue_responses(vec![
                MockTransport::success_response(RequestId::Number(1), json!(init_result)),
                // notify does not consume response
                MockTransport::success_response(RequestId::Number(2), json!(resource_result)),
            ])
            .await;

        let transport = Box::new(mock_transport);
        let client_info = Implementation::new("test-client", "1.0.0");
        let mut client = McpClient::new(transport, client_info);
        client.mark_connected();
        client.initialize().await.unwrap();

        let result = client.read_resource("file:///test.txt").await;
        assert!(result.is_ok());
    }

    // =========================================================================
    // NEW TESTS - Prompt Operations with Capabilities
    // =========================================================================

    #[tokio::test]
    async fn get_prompt_with_arguments() {
        use crate::protocol::mcp::{GetPromptResult, InitializeResult, PromptsCapability};
        use crate::protocol::RequestId;
        use crate::transport::mock::MockTransport;
        use serde_json::json;

        let mock_transport = MockTransport::new();
        let server_caps = ServerCapabilities {
            prompts: Some(PromptsCapability::default()),
            ..ServerCapabilities::default()
        };

        let init_result = InitializeResult {
            protocol_version: "2024-11-05".to_string(),
            capabilities: server_caps,
            server_info: Implementation::new("test-server", "1.0.0"),
            instructions: None,
        };

        let prompt_result = GetPromptResult {
            description: Some("Test prompt".to_string()),
            messages: vec![],
        };

        mock_transport
            .queue_responses(vec![
                MockTransport::success_response(RequestId::Number(1), json!(init_result)),
                // notify does not consume response
                MockTransport::success_response(RequestId::Number(2), json!(prompt_result)),
            ])
            .await;

        let transport = Box::new(mock_transport);
        let client_info = Implementation::new("test-client", "1.0.0");
        let mut client = McpClient::new(transport, client_info);
        client.mark_connected();
        client.initialize().await.unwrap();

        let args = json!({"key": "value"});
        let result = client.get_prompt("test_prompt", Some(args)).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn get_prompt_without_arguments() {
        use crate::protocol::mcp::{GetPromptResult, InitializeResult, PromptsCapability};
        use crate::protocol::RequestId;
        use crate::transport::mock::MockTransport;
        use serde_json::json;

        let mock_transport = MockTransport::new();
        let server_caps = ServerCapabilities {
            prompts: Some(PromptsCapability::default()),
            ..ServerCapabilities::default()
        };

        let init_result = InitializeResult {
            protocol_version: "2024-11-05".to_string(),
            capabilities: server_caps,
            server_info: Implementation::new("test-server", "1.0.0"),
            instructions: None,
        };

        let prompt_result = GetPromptResult {
            description: None,
            messages: vec![],
        };

        mock_transport
            .queue_responses(vec![
                MockTransport::success_response(RequestId::Number(1), json!(init_result)),
                // notify does not consume response
                MockTransport::success_response(RequestId::Number(2), json!(prompt_result)),
            ])
            .await;

        let transport = Box::new(mock_transport);
        let client_info = Implementation::new("test-client", "1.0.0");
        let mut client = McpClient::new(transport, client_info);
        client.mark_connected();
        client.initialize().await.unwrap();

        let result = client.get_prompt("test_prompt", None).await;
        assert!(result.is_ok());
    }

    // =========================================================================
    // NEW TESTS - Multiple Supported Protocol Versions
    // =========================================================================

    #[tokio::test]
    async fn initialize_with_2025_protocol_version() {
        use crate::protocol::mcp::InitializeResult;
        use crate::protocol::RequestId;
        use crate::transport::mock::MockTransport;
        use serde_json::json;

        let mock_transport = MockTransport::new();
        let server_caps = ServerCapabilities::default();

        let init_result = InitializeResult {
            protocol_version: "2025-03-26".to_string(),
            capabilities: server_caps,
            server_info: Implementation::new("test-server", "1.0.0"),
            instructions: None,
        };

        mock_transport
            .queue_responses(vec![
                MockTransport::success_response(RequestId::Number(1), json!(init_result)),
                // notify does not consume response
            ])
            .await;

        let transport = Box::new(mock_transport);
        let client_info = Implementation::new("test-client", "1.0.0");
        let mut client = McpClient::new(transport, client_info);
        client.mark_connected();

        let result = client.initialize().await;
        assert!(result.is_ok());
        assert_eq!(client.protocol_version(), Some("2025-03-26"));
    }

    #[tokio::test]
    async fn initialize_with_2024_protocol_version() {
        use crate::protocol::mcp::InitializeResult;
        use crate::protocol::RequestId;
        use crate::transport::mock::MockTransport;
        use serde_json::json;

        let mock_transport = MockTransport::new();
        let server_caps = ServerCapabilities::default();

        let init_result = InitializeResult {
            protocol_version: "2024-11-05".to_string(),
            capabilities: server_caps,
            server_info: Implementation::new("test-server", "1.0.0"),
            instructions: None,
        };

        mock_transport
            .queue_responses(vec![
                MockTransport::success_response(RequestId::Number(1), json!(init_result)),
                // notify does not consume response
            ])
            .await;

        let transport = Box::new(mock_transport);
        let client_info = Implementation::new("test-client", "1.0.0");
        let mut client = McpClient::new(transport, client_info);
        client.mark_connected();

        let result = client.initialize().await;
        assert!(result.is_ok());
        assert_eq!(client.protocol_version(), Some("2024-11-05"));
    }

    // =========================================================================
    // NEW TESTS - Client Configuration and Capabilities
    // =========================================================================

    #[tokio::test]
    async fn client_with_custom_capabilities_creation() {
        use crate::transport::mock::MockTransport;

        let transport = Box::new(MockTransport::new());
        let client_info = Implementation::new("test-client", "1.0.0");
        let caps = ClientCapabilities::default();
        let client = McpClient::with_capabilities(transport, client_info, caps);

        assert!(!client.is_ready());
        assert_eq!(client.state(), ConnectionState::Disconnected);
    }

    #[test]
    fn implementation_struct_fields() {
        let impl_info = Implementation::new("my-client", "2.0.0");
        assert_eq!(impl_info.name, "my-client");
        assert_eq!(impl_info.version, "2.0.0");
    }

    // =========================================================================
    // NEW TESTS - Drop Behavior
    // =========================================================================

    #[tokio::test]
    async fn client_drop_without_connection() {
        use crate::transport::mock::MockTransport;

        let transport = Box::new(MockTransport::new());
        let client_info = Implementation::new("test-client", "1.0.0");
        let client = McpClient::new(transport, client_info);

        // Drop without connecting - should not log warning
        assert!(!client.context.is_connected());
        drop(client);
    }
}
