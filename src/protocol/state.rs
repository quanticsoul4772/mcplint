//! Connection state machine for MCP protocol lifecycle

use std::collections::HashMap;
use std::time::Instant;

use super::jsonrpc::RequestId;
use super::mcp::{ClientCapabilities, ServerCapabilities};

/// Connection lifecycle states
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Not connected to server
    Disconnected,
    /// Transport connected, not yet initialized
    Connecting,
    /// Initialize request sent, awaiting response
    Initializing,
    /// Fully initialized and ready for operations
    Ready,
    /// Shutdown in progress
    ShuttingDown,
}

impl std::fmt::Display for ConnectionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectionState::Disconnected => write!(f, "Disconnected"),
            ConnectionState::Connecting => write!(f, "Connecting"),
            ConnectionState::Initializing => write!(f, "Initializing"),
            ConnectionState::Ready => write!(f, "Ready"),
            ConnectionState::ShuttingDown => write!(f, "ShuttingDown"),
        }
    }
}

/// Tracks a pending request awaiting response
#[derive(Debug)]
pub struct PendingRequest {
    pub method: String,
    pub sent_at: Instant,
}

impl PendingRequest {
    pub fn new(method: impl Into<String>) -> Self {
        Self {
            method: method.into(),
            sent_at: Instant::now(),
        }
    }

    pub fn elapsed_secs(&self) -> f64 {
        self.sent_at.elapsed().as_secs_f64()
    }
}

/// Connection context tracking state and capabilities
#[derive(Debug)]
pub struct ConnectionContext {
    state: ConnectionState,
    protocol_version: Option<String>,
    server_capabilities: Option<ServerCapabilities>,
    client_capabilities: ClientCapabilities,
    pending_requests: HashMap<RequestId, PendingRequest>,
    server_info: Option<(String, String)>, // (name, version)
}

impl Default for ConnectionContext {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectionContext {
    pub fn new() -> Self {
        Self {
            state: ConnectionState::Disconnected,
            protocol_version: None,
            server_capabilities: None,
            client_capabilities: ClientCapabilities::default(),
            pending_requests: HashMap::new(),
            server_info: None,
        }
    }

    pub fn with_capabilities(capabilities: ClientCapabilities) -> Self {
        Self {
            client_capabilities: capabilities,
            ..Self::new()
        }
    }

    // State queries

    pub fn state(&self) -> ConnectionState {
        self.state
    }

    pub fn is_ready(&self) -> bool {
        matches!(self.state, ConnectionState::Ready)
    }

    pub fn is_connected(&self) -> bool {
        !matches!(self.state, ConnectionState::Disconnected)
    }

    pub fn can_send_request(&self) -> bool {
        matches!(self.state, ConnectionState::Ready)
    }

    pub fn can_initialize(&self) -> bool {
        matches!(self.state, ConnectionState::Connecting)
    }

    // State transitions

    pub fn transition_to(
        &mut self,
        new_state: ConnectionState,
    ) -> Result<(), StateTransitionError> {
        let valid = match (self.state, new_state) {
            // Valid transitions
            (ConnectionState::Disconnected, ConnectionState::Connecting) => true,
            (ConnectionState::Connecting, ConnectionState::Initializing) => true,
            (ConnectionState::Initializing, ConnectionState::Ready) => true,
            (ConnectionState::Ready, ConnectionState::ShuttingDown) => true,
            (ConnectionState::ShuttingDown, ConnectionState::Disconnected) => true,
            // Error recovery: can go back to disconnected from any state
            (_, ConnectionState::Disconnected) => true,
            // Same state is a no-op
            (a, b) if a == b => true,
            _ => false,
        };

        if valid {
            self.state = new_state;
            Ok(())
        } else {
            Err(StateTransitionError {
                from: self.state,
                to: new_state,
            })
        }
    }

    pub fn set_connected(&mut self) {
        let _ = self.transition_to(ConnectionState::Connecting);
    }

    pub fn set_initializing(&mut self) -> Result<(), StateTransitionError> {
        self.transition_to(ConnectionState::Initializing)
    }

    pub fn set_ready(
        &mut self,
        protocol_version: String,
        server_capabilities: ServerCapabilities,
        server_name: String,
        server_version: String,
    ) -> Result<(), StateTransitionError> {
        self.transition_to(ConnectionState::Ready)?;
        self.protocol_version = Some(protocol_version);
        self.server_capabilities = Some(server_capabilities);
        self.server_info = Some((server_name, server_version));
        Ok(())
    }

    pub fn set_shutting_down(&mut self) -> Result<(), StateTransitionError> {
        self.transition_to(ConnectionState::ShuttingDown)
    }

    pub fn set_disconnected(&mut self) {
        let _ = self.transition_to(ConnectionState::Disconnected);
        self.protocol_version = None;
        self.server_capabilities = None;
        self.server_info = None;
        self.pending_requests.clear();
    }

    // Capability access

    pub fn client_capabilities(&self) -> &ClientCapabilities {
        &self.client_capabilities
    }

    pub fn server_capabilities(&self) -> Option<&ServerCapabilities> {
        self.server_capabilities.as_ref()
    }

    pub fn protocol_version(&self) -> Option<&str> {
        self.protocol_version.as_deref()
    }

    pub fn server_info(&self) -> Option<(&str, &str)> {
        self.server_info
            .as_ref()
            .map(|(n, v)| (n.as_str(), v.as_str()))
    }

    // Server capability checks

    pub fn server_has_tools(&self) -> bool {
        self.server_capabilities
            .as_ref()
            .map(|c| c.has_tools())
            .unwrap_or(false)
    }

    pub fn server_has_resources(&self) -> bool {
        self.server_capabilities
            .as_ref()
            .map(|c| c.has_resources())
            .unwrap_or(false)
    }

    pub fn server_has_prompts(&self) -> bool {
        self.server_capabilities
            .as_ref()
            .map(|c| c.has_prompts())
            .unwrap_or(false)
    }

    // Pending request tracking

    pub fn add_pending_request(&mut self, id: RequestId, method: impl Into<String>) {
        self.pending_requests
            .insert(id, PendingRequest::new(method));
    }

    pub fn remove_pending_request(&mut self, id: &RequestId) -> Option<PendingRequest> {
        self.pending_requests.remove(id)
    }

    pub fn has_pending_request(&self, id: &RequestId) -> bool {
        self.pending_requests.contains_key(id)
    }

    pub fn pending_request_count(&self) -> usize {
        self.pending_requests.len()
    }

    pub fn get_timed_out_requests(&self, timeout_secs: f64) -> Vec<RequestId> {
        self.pending_requests
            .iter()
            .filter(|(_, req)| req.elapsed_secs() > timeout_secs)
            .map(|(id, _)| id.clone())
            .collect()
    }
}

/// Error when attempting an invalid state transition
#[derive(Debug, Clone)]
pub struct StateTransitionError {
    pub from: ConnectionState,
    pub to: ConnectionState,
}

impl std::fmt::Display for StateTransitionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Invalid state transition from {} to {}",
            self.from, self.to
        )
    }
}

impl std::error::Error for StateTransitionError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_state() {
        let ctx = ConnectionContext::new();
        assert_eq!(ctx.state(), ConnectionState::Disconnected);
        assert!(!ctx.is_ready());
        assert!(!ctx.is_connected());
    }

    #[test]
    fn valid_lifecycle_transitions() {
        let mut ctx = ConnectionContext::new();

        // Disconnected -> Connecting
        assert!(ctx.transition_to(ConnectionState::Connecting).is_ok());
        assert_eq!(ctx.state(), ConnectionState::Connecting);

        // Connecting -> Initializing
        assert!(ctx.transition_to(ConnectionState::Initializing).is_ok());
        assert_eq!(ctx.state(), ConnectionState::Initializing);

        // Initializing -> Ready
        assert!(ctx.transition_to(ConnectionState::Ready).is_ok());
        assert!(ctx.is_ready());
        assert!(ctx.can_send_request());

        // Ready -> ShuttingDown
        assert!(ctx.transition_to(ConnectionState::ShuttingDown).is_ok());

        // ShuttingDown -> Disconnected
        assert!(ctx.transition_to(ConnectionState::Disconnected).is_ok());
    }

    #[test]
    fn invalid_transitions() {
        let mut ctx = ConnectionContext::new();

        // Cannot go directly to Ready
        assert!(ctx.transition_to(ConnectionState::Ready).is_err());

        // Cannot go directly to Initializing
        assert!(ctx.transition_to(ConnectionState::Initializing).is_err());
    }

    #[test]
    fn can_always_disconnect() {
        let mut ctx = ConnectionContext::new();
        ctx.transition_to(ConnectionState::Connecting).unwrap();
        ctx.transition_to(ConnectionState::Initializing).unwrap();

        // Can disconnect from any state
        assert!(ctx.transition_to(ConnectionState::Disconnected).is_ok());
    }

    #[test]
    fn pending_requests() {
        let mut ctx = ConnectionContext::new();
        let id = RequestId::Number(1);

        ctx.add_pending_request(id.clone(), "test");
        assert!(ctx.has_pending_request(&id));
        assert_eq!(ctx.pending_request_count(), 1);

        let req = ctx.remove_pending_request(&id);
        assert!(req.is_some());
        assert_eq!(req.unwrap().method, "test");
        assert!(!ctx.has_pending_request(&id));
    }

    #[test]
    fn set_ready_stores_info() {
        let mut ctx = ConnectionContext::new();
        ctx.set_connected();
        ctx.set_initializing().unwrap();
        ctx.set_ready(
            "2025-03-26".to_string(),
            ServerCapabilities {
                tools: Some(Default::default()),
                ..Default::default()
            },
            "test-server".to_string(),
            "1.0.0".to_string(),
        )
        .unwrap();

        assert!(ctx.is_ready());
        assert_eq!(ctx.protocol_version(), Some("2025-03-26"));
        assert!(ctx.server_has_tools());
        assert!(!ctx.server_has_resources());
        assert_eq!(ctx.server_info(), Some(("test-server", "1.0.0")));
    }

    #[test]
    fn disconnect_clears_state() {
        let mut ctx = ConnectionContext::new();
        ctx.set_connected();
        ctx.set_initializing().unwrap();
        ctx.set_ready(
            "2025-03-26".to_string(),
            ServerCapabilities::default(),
            "server".to_string(),
            "1.0".to_string(),
        )
        .unwrap();

        ctx.add_pending_request(RequestId::Number(1), "test");

        ctx.set_disconnected();

        assert_eq!(ctx.state(), ConnectionState::Disconnected);
        assert!(ctx.protocol_version().is_none());
        assert!(ctx.server_capabilities().is_none());
        assert_eq!(ctx.pending_request_count(), 0);
    }
}
