//! Protocol layer for MCP communication
//!
//! This module provides:
//! - JSON-RPC 2.0 message types and parsing
//! - MCP-specific message types (initialize, tools, resources, prompts)
//! - Connection state machine for lifecycle management
//!
//! Public library API - types are available for external library consumers.
//! CLI uses rmcp crate directly; these types exist for flexibility and testing.

// Protocol types used by client, validator, and scanner modules.
// Public API not consumed by CLI - available for library consumers.
#![allow(dead_code)]

pub mod jsonrpc;
pub mod mcp;
pub mod state;

// Re-export commonly used types
pub use jsonrpc::{
    JsonRpcMessage, JsonRpcNotification, JsonRpcRequest, JsonRpcResponse, RequestId,
};
pub use mcp::{ClientCapabilities, Implementation, ServerCapabilities};
pub use state::{ConnectionContext, ConnectionState};
