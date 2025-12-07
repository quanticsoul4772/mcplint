# M0: Foundation Implementation Plan

## Current State

**Existing code:**
- `transport/mod.rs` - Transport trait defined (request, notify, close)
- `transport/stdio.rs` - Basic stdio implementation (spawn, request, notify, close)
- `transport/sse.rs` - Basic HTTP POST implementation (misnamed, not actual SSE)
- Dependencies: tokio, reqwest (with rustls-tls), serde_json, async-trait

**Gaps:**
- No JSON-RPC types (request/response/notification/error structures)
- No MCP message types (initialize, tools/list, etc.)
- No connection lifecycle (state machine)
- No Streamable HTTP transport (2025 spec)
- No session management
- No timeout handling
- No auto-detection

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      MCP Client                              │
│  connect() → initialize() → ready() → operations → close()  │
├─────────────────────────────────────────────────────────────┤
│                    Protocol Layer                            │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │  JSON-RPC   │  │ MCP Messages│  │   State Machine     │  │
│  │  (parsing)  │  │  (types)    │  │   (lifecycle)       │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
├─────────────────────────────────────────────────────────────┤
│                    Transport Layer                           │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │    Stdio    │  │ Streamable  │  │   SSE (legacy)      │  │
│  │             │  │    HTTP     │  │                     │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

---

## Implementation Tasks

### 1. Protocol Types (`src/protocol/`)

**1.1 JSON-RPC Types** (`jsonrpc.rs`)

```rust
// Request
pub struct JsonRpcRequest {
    pub jsonrpc: String,  // always "2.0"
    pub id: RequestId,    // u64 | String
    pub method: String,
    pub params: Option<Value>,
}

// Response
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub id: RequestId,
    pub result: Option<Value>,
    pub error: Option<JsonRpcError>,
}

// Notification (no id)
pub struct JsonRpcNotification {
    pub jsonrpc: String,
    pub method: String,
    pub params: Option<Value>,
}

// Error
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    pub data: Option<Value>,
}

// Standard error codes
pub const PARSE_ERROR: i32 = -32700;
pub const INVALID_REQUEST: i32 = -32600;
pub const METHOD_NOT_FOUND: i32 = -32601;
pub const INVALID_PARAMS: i32 = -32602;
pub const INTERNAL_ERROR: i32 = -32603;
```

**1.2 MCP Types** (`mcp.rs`)

```rust
// Initialize request params
pub struct InitializeParams {
    pub protocol_version: String,
    pub capabilities: ClientCapabilities,
    pub client_info: Implementation,
}

// Initialize result
pub struct InitializeResult {
    pub protocol_version: String,
    pub capabilities: ServerCapabilities,
    pub server_info: Implementation,
    pub instructions: Option<String>,
}

// Capabilities
pub struct ClientCapabilities {
    pub roots: Option<RootsCapability>,
    pub sampling: Option<SamplingCapability>,
    pub experimental: Option<Value>,
}

pub struct ServerCapabilities {
    pub prompts: Option<PromptsCapability>,
    pub resources: Option<ResourcesCapability>,
    pub tools: Option<ToolsCapability>,
    pub logging: Option<LoggingCapability>,
    pub experimental: Option<Value>,
}

// Tool definition
pub struct Tool {
    pub name: String,
    pub description: Option<String>,
    pub input_schema: Value,  // JSON Schema
}

// Tool call
pub struct ToolCallParams {
    pub name: String,
    pub arguments: Option<Value>,
}

pub struct ToolCallResult {
    pub content: Vec<Content>,
    pub is_error: Option<bool>,
}
```

**1.3 State Machine** (`state.rs`)

```rust
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Initializing,
    Ready,
    ShuttingDown,
}

pub struct ConnectionContext {
    state: ConnectionState,
    protocol_version: Option<String>,
    server_capabilities: Option<ServerCapabilities>,
    client_capabilities: ClientCapabilities,
    pending_requests: HashMap<RequestId, PendingRequest>,
}

impl ConnectionContext {
    pub fn can_send_request(&self) -> bool {
        matches!(self.state, ConnectionState::Ready)
    }

    pub fn can_initialize(&self) -> bool {
        matches!(self.state, ConnectionState::Connecting)
    }
}
```

---

### 2. Transport Improvements (`src/transport/`)

**2.1 Refactor Transport Trait**

```rust
#[async_trait]
pub trait Transport: Send + Sync {
    /// Send raw JSON-RPC message, receive raw response
    async fn send(&mut self, message: &JsonRpcMessage) -> Result<()>;

    /// Receive next message (may block)
    async fn recv(&mut self) -> Result<Option<JsonRpcMessage>>;

    /// Send request, wait for matching response
    async fn request(&mut self, req: JsonRpcRequest) -> Result<JsonRpcResponse>;

    /// Send notification (no response expected)
    async fn notify(&mut self, notif: JsonRpcNotification) -> Result<()>;

    /// Close transport
    async fn close(&mut self) -> Result<()>;

    /// Transport type for logging/debugging
    fn transport_type(&self) -> &'static str;
}
```

**2.2 Stdio Transport Fixes**

Current issues:
- No timeout handling
- Creates new BufReader each request (loses buffered data)
- No handling of server-initiated messages

```rust
pub struct StdioTransport {
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    stderr: Option<BufReader<ChildStderr>>,
    config: TransportConfig,
    request_id: AtomicU64,
}

impl StdioTransport {
    pub async fn spawn(command: &str, args: &[String], config: TransportConfig) -> Result<Self> {
        let mut child = Command::new(command)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        let stdin = child.stdin.take().context("No stdin")?;
        let stdout = BufReader::new(child.stdout.take().context("No stdout")?);
        let stderr = child.stderr.take().map(BufReader::new);

        Ok(Self { stdin, stdout, stderr, config, request_id: AtomicU64::new(0) })
    }

    async fn read_line(&mut self) -> Result<String> {
        let timeout = Duration::from_secs(self.config.timeout_secs);
        let mut line = String::new();

        tokio::time::timeout(timeout, self.stdout.read_line(&mut line))
            .await
            .context("Read timeout")?
            .context("Read failed")?;

        Ok(line)
    }
}
```

**2.3 Streamable HTTP Transport** (`streamable_http.rs`)

Per MCP 2025-03-26 spec:

```rust
pub struct StreamableHttpTransport {
    endpoint: Url,
    client: reqwest::Client,
    session_id: Option<String>,
    config: TransportConfig,
    request_id: AtomicU64,
}

impl StreamableHttpTransport {
    pub fn new(endpoint: &str, config: TransportConfig) -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .use_rustls_tls()
            .build()?;

        Ok(Self {
            endpoint: Url::parse(endpoint)?,
            client,
            session_id: None,
            config,
            request_id: AtomicU64::new(0),
        })
    }

    pub async fn request(&mut self, req: JsonRpcRequest) -> Result<JsonRpcResponse> {
        let mut builder = self.client
            .post(self.endpoint.clone())
            .header("Accept", "application/json, text/event-stream")
            .header("Content-Type", "application/json");

        // Include session ID if we have one
        if let Some(ref session_id) = self.session_id {
            builder = builder.header("Mcp-Session-Id", session_id);
        }

        let response = builder
            .json(&req)
            .send()
            .await?;

        // Capture session ID from initialize response
        if req.method == "initialize" {
            if let Some(session_id) = response.headers().get("Mcp-Session-Id") {
                self.session_id = Some(session_id.to_str()?.to_string());
            }
        }

        // Handle 404 = session expired
        if response.status() == 404 {
            self.session_id = None;
            anyhow::bail!("Session expired, re-initialize required");
        }

        let content_type = response.headers()
            .get("Content-Type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        if content_type.starts_with("text/event-stream") {
            // Parse SSE stream for response
            self.parse_sse_response(response).await
        } else {
            // Direct JSON response
            response.json().await.context("Parse response")
        }
    }

    async fn parse_sse_response(&self, response: reqwest::Response) -> Result<JsonRpcResponse> {
        // Read SSE stream, extract JSON-RPC response
        let text = response.text().await?;

        for line in text.lines() {
            if let Some(data) = line.strip_prefix("data: ") {
                let msg: JsonRpcMessage = serde_json::from_str(data)?;
                if let JsonRpcMessage::Response(resp) = msg {
                    return Ok(resp);
                }
            }
        }

        anyhow::bail!("No response in SSE stream")
    }
}
```

**2.4 SSE Transport (Legacy)**

Rename current `sse.rs` to properly implement SSE per 2024-11-05 spec:

```rust
pub struct SseTransport {
    base_url: Url,
    sse_endpoint: Option<Url>,  // Discovered via GET
    client: reqwest::Client,
    session_id: Option<String>,
    config: TransportConfig,
    request_id: AtomicU64,
}

impl SseTransport {
    /// Connect and discover SSE endpoint
    pub async fn connect(base_url: &str, config: TransportConfig) -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .build()?;

        // GET to discover endpoint event
        let response = client.get(base_url)
            .header("Accept", "text/event-stream")
            .send()
            .await?;

        // Parse endpoint from SSE
        let sse_endpoint = Self::parse_endpoint_event(response).await?;

        Ok(Self {
            base_url: Url::parse(base_url)?,
            sse_endpoint: Some(sse_endpoint),
            client,
            session_id: None,
            config,
            request_id: AtomicU64::new(0),
        })
    }
}
```

**2.5 Auto-Detection**

```rust
pub enum TransportType {
    Stdio,
    StreamableHttp,
    SseLegacy,
}

pub fn detect_transport(target: &str) -> TransportType {
    if target.starts_with("http://") || target.starts_with("https://") {
        // Try Streamable HTTP first, fall back to SSE
        TransportType::StreamableHttp
    } else {
        TransportType::Stdio
    }
}

pub async fn connect(target: &str, args: &[String], config: TransportConfig) -> Result<Box<dyn Transport>> {
    match detect_transport(target) {
        TransportType::Stdio => {
            Ok(Box::new(StdioTransport::spawn(target, args, config).await?))
        }
        TransportType::StreamableHttp => {
            let mut transport = StreamableHttpTransport::new(target, config.clone())?;

            // Try initialize, fall back to SSE on 4xx
            match transport.request(initialize_request()).await {
                Ok(_) => Ok(Box::new(transport)),
                Err(_) => {
                    // Fall back to legacy SSE
                    Ok(Box::new(SseTransport::connect(target, config).await?))
                }
            }
        }
        TransportType::SseLegacy => {
            Ok(Box::new(SseTransport::connect(target, config).await?))
        }
    }
}
```

---

### 3. MCP Client (`src/client/`)

**3.1 Client Implementation** (`mod.rs`)

```rust
pub struct McpClient {
    transport: Box<dyn Transport>,
    context: ConnectionContext,
}

impl McpClient {
    /// Connect to MCP server
    pub async fn connect(target: &str, args: &[String], config: TransportConfig) -> Result<Self> {
        let transport = connect(target, args, config).await?;

        Ok(Self {
            transport,
            context: ConnectionContext::new(),
        })
    }

    /// Initialize connection (required before any operations)
    pub async fn initialize(&mut self, client_info: Implementation) -> Result<InitializeResult> {
        if !self.context.can_initialize() {
            anyhow::bail!("Cannot initialize in state {:?}", self.context.state);
        }

        self.context.state = ConnectionState::Initializing;

        let params = InitializeParams {
            protocol_version: "2025-03-26".to_string(),
            capabilities: self.context.client_capabilities.clone(),
            client_info,
        };

        let result: InitializeResult = self.request("initialize", Some(params)).await?;

        // Validate protocol version
        if !SUPPORTED_VERSIONS.contains(&result.protocol_version.as_str()) {
            anyhow::bail!("Unsupported protocol version: {}", result.protocol_version);
        }

        self.context.protocol_version = Some(result.protocol_version.clone());
        self.context.server_capabilities = Some(result.capabilities.clone());

        // Send initialized notification
        self.notify("notifications/initialized", None::<()>).await?;

        self.context.state = ConnectionState::Ready;

        Ok(result)
    }

    /// List available tools
    pub async fn list_tools(&mut self) -> Result<Vec<Tool>> {
        self.ensure_ready()?;

        #[derive(Deserialize)]
        struct ListToolsResult { tools: Vec<Tool> }

        let result: ListToolsResult = self.request("tools/list", None::<()>).await?;
        Ok(result.tools)
    }

    /// Call a tool
    pub async fn call_tool(&mut self, name: &str, arguments: Option<Value>) -> Result<ToolCallResult> {
        self.ensure_ready()?;

        let params = ToolCallParams {
            name: name.to_string(),
            arguments,
        };

        self.request("tools/call", Some(params)).await
    }

    /// List resources
    pub async fn list_resources(&mut self) -> Result<Vec<Resource>> {
        self.ensure_ready()?;

        #[derive(Deserialize)]
        struct ListResourcesResult { resources: Vec<Resource> }

        let result: ListResourcesResult = self.request("resources/list", None::<()>).await?;
        Ok(result.resources)
    }

    /// Close connection
    pub async fn close(&mut self) -> Result<()> {
        self.context.state = ConnectionState::ShuttingDown;
        self.transport.close().await?;
        self.context.state = ConnectionState::Disconnected;
        Ok(())
    }

    // Internal helpers

    fn ensure_ready(&self) -> Result<()> {
        if !matches!(self.context.state, ConnectionState::Ready) {
            anyhow::bail!("Not ready, current state: {:?}", self.context.state);
        }
        Ok(())
    }

    async fn request<P: Serialize, R: DeserializeOwned>(&mut self, method: &str, params: Option<P>) -> Result<R> {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: self.next_id(),
            method: method.to_string(),
            params: params.map(|p| serde_json::to_value(p)).transpose()?,
        };

        let resp = self.transport.request(req).await?;

        if let Some(error) = resp.error {
            anyhow::bail!("RPC error {}: {}", error.code, error.message);
        }

        serde_json::from_value(resp.result.unwrap_or(Value::Null))
            .context("Deserialize response")
    }

    async fn notify<P: Serialize>(&mut self, method: &str, params: Option<P>) -> Result<()> {
        let notif = JsonRpcNotification {
            jsonrpc: "2.0".to_string(),
            method: method.to_string(),
            params: params.map(|p| serde_json::to_value(p)).transpose()?,
        };

        self.transport.notify(notif).await
    }
}
```

---

### 4. File Structure

```
src/
├── client/
│   └── mod.rs              # McpClient implementation
├── protocol/
│   ├── mod.rs              # Re-exports
│   ├── jsonrpc.rs          # JSON-RPC 2.0 types
│   ├── mcp.rs              # MCP message types
│   └── state.rs            # Connection state machine
├── transport/
│   ├── mod.rs              # Transport trait, auto-detection
│   ├── stdio.rs            # Stdio transport (fixed)
│   ├── streamable_http.rs  # Streamable HTTP (new)
│   └── sse.rs              # SSE legacy (refactored)
└── ...
```

---

## Validation Criteria

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    // JSON-RPC parsing
    #[test]
    fn parse_request() { ... }
    #[test]
    fn parse_response_with_result() { ... }
    #[test]
    fn parse_response_with_error() { ... }
    #[test]
    fn parse_notification() { ... }

    // MCP types
    #[test]
    fn serialize_initialize_params() { ... }
    #[test]
    fn deserialize_initialize_result() { ... }
    #[test]
    fn deserialize_tool_definition() { ... }

    // State machine
    #[test]
    fn state_transitions() { ... }
    #[test]
    fn cannot_send_before_ready() { ... }
}
```

### Integration Tests

```rust
#[tokio::test]
async fn stdio_connect_initialize() {
    // Spawn test server, initialize, verify state
}

#[tokio::test]
async fn stdio_list_tools() {
    // Connect, initialize, list tools
}

#[tokio::test]
async fn stdio_call_tool() {
    // Connect, initialize, call tool, verify result
}

#[tokio::test]
async fn http_connect_initialize() {
    // Connect to HTTP endpoint, initialize
}

#[tokio::test]
async fn auto_detect_stdio() {
    // Verify "./server" → stdio
}

#[tokio::test]
async fn auto_detect_http() {
    // Verify "https://..." → streamable http
}
```

### Manual Testing

```bash
# Test against reference MCP server
mcplint validate npx -y @anthropic-ai/mcp-server-demo

# Test against HTTP endpoint
mcplint validate https://example.com/mcp

# Verify output
mcplint doctor npx -y @anthropic-ai/mcp-server-demo
```

---

## Dependencies to Add

```toml
# Cargo.toml additions

# For SSE parsing
eventsource-client = "0.13"  # or tokio-sse-stream

# Already have:
# reqwest with rustls-tls
# tokio
# serde_json
# async-trait
```

---

## Order of Implementation

1. **Protocol types** (`protocol/jsonrpc.rs`, `protocol/mcp.rs`)
   - Pure data types, no async, easy to test
   - Unblocks everything else

2. **State machine** (`protocol/state.rs`)
   - Simple enum + transitions
   - Validates lifecycle

3. **Fix stdio transport** (`transport/stdio.rs`)
   - Add timeout
   - Fix buffer reuse
   - Test with real server

4. **Streamable HTTP transport** (`transport/streamable_http.rs`)
   - New file
   - Session management
   - SSE response parsing

5. **Auto-detection** (`transport/mod.rs`)
   - Connect function
   - Type detection

6. **MCP Client** (`client/mod.rs`)
   - High-level API
   - Uses transport + protocol

7. **SSE legacy** (`transport/sse.rs`)
   - Refactor existing
   - Lower priority (most servers use stdio or new HTTP)

---

## Definition of Done

- [ ] `McpClient::connect()` works with stdio servers
- [ ] `McpClient::connect()` works with Streamable HTTP servers
- [ ] `McpClient::initialize()` performs handshake correctly
- [ ] `McpClient::list_tools()` returns tool definitions
- [ ] `McpClient::call_tool()` executes tools
- [ ] Auto-detection routes to correct transport
- [ ] Timeout handling works
- [ ] Session management works for HTTP
- [ ] All tests pass
- [ ] `mcplint validate <server>` uses new client internally
