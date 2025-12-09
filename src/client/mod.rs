//! MCP Client - High-level API for interacting with MCP servers
//!
//! Provides a type-safe, ergonomic interface for:
//! - Connecting to MCP servers (stdio or HTTP)
//! - Protocol initialization and capability negotiation
//! - Tool discovery and invocation
//! - Resource and prompt access

#![allow(dead_code)] // Client API will be used in M1 (Protocol Validator)

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
        let transport = connect(target, args, config).await?;
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
        let transport = connect(target, args, self.config).await?;
        let client_info = Implementation::new(self.client_name, self.client_version);

        let mut client = McpClient::with_capabilities(transport, client_info, self.capabilities);
        client.context.set_connected();

        Ok(client)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::mcp::{ToolsCapability, ResourcesCapability, PromptsCapability};

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
}
