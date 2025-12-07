//! Protocol layer for MCP communication
//!
//! This module provides:
//! - JSON-RPC 2.0 message types and parsing
//! - MCP-specific message types (initialize, tools, resources, prompts)
//! - Connection state machine for lifecycle management

pub mod jsonrpc;
pub mod mcp;
pub mod state;

// Re-export commonly used types
pub use jsonrpc::{
    JsonRpcError, JsonRpcMessage, JsonRpcNotification, JsonRpcRequest, JsonRpcResponse, RequestId,
};
pub use mcp::{
    CallToolParams, CallToolResult, ClientCapabilities, Content, Implementation, InitializeParams,
    InitializeResult, ListResourcesResult, ListToolsResult, Resource, ServerCapabilities, Tool,
};
pub use state::{ConnectionContext, ConnectionState, StateTransitionError};
