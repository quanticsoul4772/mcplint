//! Protocol layer for MCP communication
//!
//! This module provides:
//! - JSON-RPC 2.0 message types and parsing
//! - MCP-specific message types (initialize, tools, resources, prompts)
//! - Connection state machine for lifecycle management

#![allow(dead_code)] // Protocol types used by client module, will be used in M1

pub mod jsonrpc;
pub mod mcp;
pub mod state;

// Re-export commonly used types
pub use jsonrpc::{
    JsonRpcMessage, JsonRpcNotification, JsonRpcRequest, JsonRpcResponse, RequestId,
};
pub use mcp::{ClientCapabilities, Implementation, ServerCapabilities};
pub use state::{ConnectionContext, ConnectionState};
