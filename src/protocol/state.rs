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

    // ConnectionState Display trait tests
    #[test]
    fn connection_state_display_disconnected() {
        let state = ConnectionState::Disconnected;
        assert_eq!(state.to_string(), "Disconnected");
    }

    #[test]
    fn connection_state_display_connecting() {
        let state = ConnectionState::Connecting;
        assert_eq!(state.to_string(), "Connecting");
    }

    #[test]
    fn connection_state_display_initializing() {
        let state = ConnectionState::Initializing;
        assert_eq!(state.to_string(), "Initializing");
    }

    #[test]
    fn connection_state_display_ready() {
        let state = ConnectionState::Ready;
        assert_eq!(state.to_string(), "Ready");
    }

    #[test]
    fn connection_state_display_shutting_down() {
        let state = ConnectionState::ShuttingDown;
        assert_eq!(state.to_string(), "ShuttingDown");
    }

    // StateTransitionError Display trait test
    #[test]
    fn state_transition_error_display() {
        let error = StateTransitionError {
            from: ConnectionState::Disconnected,
            to: ConnectionState::Ready,
        };
        assert_eq!(
            error.to_string(),
            "Invalid state transition from Disconnected to Ready"
        );
    }

    // PendingRequest tests
    #[test]
    fn pending_request_new() {
        let req = PendingRequest::new("test_method");
        assert_eq!(req.method, "test_method");
        assert!(req.elapsed_secs() >= 0.0);
    }

    #[test]
    fn pending_request_elapsed_secs() {
        let req = PendingRequest::new("method");
        std::thread::sleep(std::time::Duration::from_millis(10));
        let elapsed = req.elapsed_secs();
        assert!(elapsed >= 0.01); // At least 10ms
        assert!(elapsed < 1.0); // But less than 1 second
    }

    // ConnectionContext::with_capabilities test
    #[test]
    fn connection_context_with_capabilities() {
        let capabilities = ClientCapabilities {
            experimental: Some(serde_json::json!({"test": true})),
            ..Default::default()
        };
        let ctx = ConnectionContext::with_capabilities(capabilities.clone());

        assert_eq!(ctx.state(), ConnectionState::Disconnected);
        assert_eq!(
            ctx.client_capabilities().experimental,
            capabilities.experimental
        );
    }

    // State query methods tests
    #[test]
    fn state_queries_in_connecting() {
        let mut ctx = ConnectionContext::new();
        ctx.set_connected();

        assert_eq!(ctx.state(), ConnectionState::Connecting);
        assert!(!ctx.is_ready());
        assert!(ctx.is_connected());
        assert!(!ctx.can_send_request());
        assert!(ctx.can_initialize());
    }

    #[test]
    fn state_queries_in_initializing() {
        let mut ctx = ConnectionContext::new();
        ctx.set_connected();
        ctx.set_initializing().unwrap();

        assert_eq!(ctx.state(), ConnectionState::Initializing);
        assert!(!ctx.is_ready());
        assert!(ctx.is_connected());
        assert!(!ctx.can_send_request());
        assert!(!ctx.can_initialize());
    }

    #[test]
    fn state_queries_in_ready() {
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

        assert_eq!(ctx.state(), ConnectionState::Ready);
        assert!(ctx.is_ready());
        assert!(ctx.is_connected());
        assert!(ctx.can_send_request());
        assert!(!ctx.can_initialize());
    }

    #[test]
    fn state_queries_in_shutting_down() {
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
        ctx.set_shutting_down().unwrap();

        assert_eq!(ctx.state(), ConnectionState::ShuttingDown);
        assert!(!ctx.is_ready());
        assert!(ctx.is_connected());
        assert!(!ctx.can_send_request());
        assert!(!ctx.can_initialize());
    }

    // Invalid state transitions tests
    #[test]
    fn invalid_transition_connecting_to_ready() {
        let mut ctx = ConnectionContext::new();
        ctx.set_connected();

        let result = ctx.transition_to(ConnectionState::Ready);
        assert!(result.is_err());
        assert_eq!(ctx.state(), ConnectionState::Connecting);
    }

    #[test]
    fn invalid_transition_initializing_to_connecting() {
        let mut ctx = ConnectionContext::new();
        ctx.set_connected();
        ctx.set_initializing().unwrap();

        let result = ctx.transition_to(ConnectionState::Connecting);
        assert!(result.is_err());
        assert_eq!(ctx.state(), ConnectionState::Initializing);
    }

    #[test]
    fn invalid_transition_ready_to_connecting() {
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

        let result = ctx.transition_to(ConnectionState::Connecting);
        assert!(result.is_err());
        assert_eq!(ctx.state(), ConnectionState::Ready);
    }

    #[test]
    fn invalid_transition_shutting_down_to_ready() {
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
        ctx.set_shutting_down().unwrap();

        let result = ctx.transition_to(ConnectionState::Ready);
        assert!(result.is_err());
        assert_eq!(ctx.state(), ConnectionState::ShuttingDown);
    }

    // Same state transitions (should be no-op)
    #[test]
    fn same_state_transition_disconnected() {
        let mut ctx = ConnectionContext::new();

        let result = ctx.transition_to(ConnectionState::Disconnected);
        assert!(result.is_ok());
        assert_eq!(ctx.state(), ConnectionState::Disconnected);
    }

    #[test]
    fn same_state_transition_connecting() {
        let mut ctx = ConnectionContext::new();
        ctx.set_connected();

        let result = ctx.transition_to(ConnectionState::Connecting);
        assert!(result.is_ok());
        assert_eq!(ctx.state(), ConnectionState::Connecting);
    }

    #[test]
    fn same_state_transition_ready() {
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

        let result = ctx.transition_to(ConnectionState::Ready);
        assert!(result.is_ok());
        assert_eq!(ctx.state(), ConnectionState::Ready);
    }

    // set_shutting_down test
    #[test]
    fn set_shutting_down_from_ready() {
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

        let result = ctx.set_shutting_down();
        assert!(result.is_ok());
        assert_eq!(ctx.state(), ConnectionState::ShuttingDown);
    }

    #[test]
    fn set_shutting_down_from_invalid_state() {
        let mut ctx = ConnectionContext::new();
        ctx.set_connected();

        let result = ctx.set_shutting_down();
        assert!(result.is_err());
        assert_eq!(ctx.state(), ConnectionState::Connecting);
    }

    // Capability accessor tests
    #[test]
    fn client_capabilities_accessor() {
        let capabilities = ClientCapabilities {
            experimental: Some(serde_json::json!({"key": "value"})),
            ..Default::default()
        };
        let ctx = ConnectionContext::with_capabilities(capabilities.clone());

        assert_eq!(
            ctx.client_capabilities().experimental,
            capabilities.experimental
        );
    }

    #[test]
    fn server_capabilities_none_initially() {
        let ctx = ConnectionContext::new();
        assert!(ctx.server_capabilities().is_none());
    }

    #[test]
    fn server_capabilities_after_ready() {
        let mut ctx = ConnectionContext::new();
        ctx.set_connected();
        ctx.set_initializing().unwrap();

        let caps = ServerCapabilities {
            tools: Some(Default::default()),
            ..Default::default()
        };
        ctx.set_ready(
            "2025-03-26".to_string(),
            caps.clone(),
            "server".to_string(),
            "1.0".to_string(),
        )
        .unwrap();

        assert!(ctx.server_capabilities().is_some());
        assert!(ctx.server_capabilities().unwrap().tools.is_some());
    }

    #[test]
    fn protocol_version_accessor() {
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

        assert_eq!(ctx.protocol_version(), Some("2025-03-26"));
    }

    #[test]
    fn server_info_accessor() {
        let mut ctx = ConnectionContext::new();
        ctx.set_connected();
        ctx.set_initializing().unwrap();
        ctx.set_ready(
            "2025-03-26".to_string(),
            ServerCapabilities::default(),
            "test-server".to_string(),
            "2.3.4".to_string(),
        )
        .unwrap();

        assert_eq!(ctx.server_info(), Some(("test-server", "2.3.4")));
    }

    // Server capability checks when None
    #[test]
    fn server_has_tools_when_none() {
        let ctx = ConnectionContext::new();
        assert!(!ctx.server_has_tools());
    }

    #[test]
    fn server_has_resources_when_none() {
        let ctx = ConnectionContext::new();
        assert!(!ctx.server_has_resources());
    }

    #[test]
    fn server_has_prompts_when_none() {
        let ctx = ConnectionContext::new();
        assert!(!ctx.server_has_prompts());
    }

    #[test]
    fn server_has_tools_when_present() {
        let mut ctx = ConnectionContext::new();
        ctx.set_connected();
        ctx.set_initializing().unwrap();
        ctx.set_ready(
            "2025-03-26".to_string(),
            ServerCapabilities {
                tools: Some(Default::default()),
                ..Default::default()
            },
            "server".to_string(),
            "1.0".to_string(),
        )
        .unwrap();

        assert!(ctx.server_has_tools());
        assert!(!ctx.server_has_resources());
        assert!(!ctx.server_has_prompts());
    }

    #[test]
    fn server_has_resources_when_present() {
        let mut ctx = ConnectionContext::new();
        ctx.set_connected();
        ctx.set_initializing().unwrap();
        ctx.set_ready(
            "2025-03-26".to_string(),
            ServerCapabilities {
                resources: Some(Default::default()),
                ..Default::default()
            },
            "server".to_string(),
            "1.0".to_string(),
        )
        .unwrap();

        assert!(!ctx.server_has_tools());
        assert!(ctx.server_has_resources());
        assert!(!ctx.server_has_prompts());
    }

    #[test]
    fn server_has_prompts_when_present() {
        let mut ctx = ConnectionContext::new();
        ctx.set_connected();
        ctx.set_initializing().unwrap();
        ctx.set_ready(
            "2025-03-26".to_string(),
            ServerCapabilities {
                prompts: Some(Default::default()),
                ..Default::default()
            },
            "server".to_string(),
            "1.0".to_string(),
        )
        .unwrap();

        assert!(!ctx.server_has_tools());
        assert!(!ctx.server_has_resources());
        assert!(ctx.server_has_prompts());
    }

    // Timeout tests
    #[test]
    fn get_timed_out_requests_with_no_timeouts() {
        let mut ctx = ConnectionContext::new();
        ctx.add_pending_request(RequestId::Number(1), "method1");
        ctx.add_pending_request(RequestId::Number(2), "method2");

        // Very high timeout - nothing should be timed out
        let timed_out = ctx.get_timed_out_requests(1000.0);
        assert!(timed_out.is_empty());
    }

    #[test]
    fn get_timed_out_requests_with_some_timed_out() {
        let mut ctx = ConnectionContext::new();
        ctx.add_pending_request(RequestId::Number(1), "method1");

        std::thread::sleep(std::time::Duration::from_millis(50));

        ctx.add_pending_request(RequestId::Number(2), "method2");

        // First request should be timed out, second should not
        let timed_out = ctx.get_timed_out_requests(0.03);
        assert_eq!(timed_out.len(), 1);
        assert!(timed_out.contains(&RequestId::Number(1)));
    }

    // Multiple pending requests tests
    #[test]
    fn multiple_pending_requests() {
        let mut ctx = ConnectionContext::new();

        ctx.add_pending_request(RequestId::Number(1), "method1");
        ctx.add_pending_request(RequestId::Number(2), "method2");
        ctx.add_pending_request(RequestId::String("abc".to_string()), "method3");

        assert_eq!(ctx.pending_request_count(), 3);
        assert!(ctx.has_pending_request(&RequestId::Number(1)));
        assert!(ctx.has_pending_request(&RequestId::Number(2)));
        assert!(ctx.has_pending_request(&RequestId::String("abc".to_string())));

        ctx.remove_pending_request(&RequestId::Number(1));
        assert_eq!(ctx.pending_request_count(), 2);
        assert!(!ctx.has_pending_request(&RequestId::Number(1)));
    }

    // Edge case: empty pending requests
    #[test]
    fn empty_pending_requests() {
        let ctx = ConnectionContext::new();

        assert_eq!(ctx.pending_request_count(), 0);
        assert!(!ctx.has_pending_request(&RequestId::Number(1)));
        assert!(ctx.get_timed_out_requests(0.0).is_empty());
    }

    #[test]
    fn remove_nonexistent_pending_request() {
        let mut ctx = ConnectionContext::new();
        ctx.add_pending_request(RequestId::Number(1), "method");

        let removed = ctx.remove_pending_request(&RequestId::Number(999));
        assert!(removed.is_none());
        assert_eq!(ctx.pending_request_count(), 1);
    }

    #[test]
    fn connection_context_default() {
        let ctx = ConnectionContext::default();
        assert_eq!(ctx.state(), ConnectionState::Disconnected);
        assert_eq!(ctx.pending_request_count(), 0);
    }
}
