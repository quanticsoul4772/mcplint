# ADR-001: Transport Selection Algorithm

## Status
Accepted

## Date
2025-12-11

## Context

MCPLint needs to connect to MCP servers using different transport mechanisms:
- **Stdio**: Local servers spawned as child processes
- **SSE (Server-Sent Events)**: Remote servers with streaming responses
- **Streamable HTTP**: MCP 2025 specification for HTTP-based transport

The CLI must automatically select the correct transport based on server specification without requiring explicit user configuration in most cases.

## Decision

### Transport Selection Algorithm

```
Input: server_spec (string)
Output: TransportType (Stdio | SSE | StreamableHttp)

1. URL Detection (highest priority):
   - If starts with "http://" or "https://":
     - If URL path ends with "/sse" → SSE
     - If URL contains "sse" in query params → SSE
     - Otherwise → StreamableHttp (default for HTTP)

2. Explicit Override:
   - If --transport flag provided → use specified transport
   - Valid values: stdio, sse, http

3. Config-Based Detection:
   - If server found in config file:
     - If config has "transport" field → use specified
     - If command starts with "http" → apply URL rules
     - Otherwise → Stdio

4. File-Based Detection:
   - If server_spec is a file path:
     - Always → Stdio (spawn with appropriate runtime)

5. NPM Package Detection:
   - If server_spec starts with "@" or looks like npm package:
     - Always → Stdio (via npx)

6. Default:
   - Stdio (safest default for local development)
```

### Implementation Location

```rust
// src/transport/mod.rs
pub fn detect_transport_type(
    server_spec: &str,
    config: Option<&ServerConfig>,
    explicit: Option<TransportType>,
) -> TransportType {
    // 1. Explicit override
    if let Some(t) = explicit {
        return t;
    }

    // 2. URL detection
    if server_spec.starts_with("http://") || server_spec.starts_with("https://") {
        return detect_http_transport(server_spec);
    }

    // 3. Config-based
    if let Some(cfg) = config {
        if let Some(t) = &cfg.transport {
            return t.parse().unwrap_or(TransportType::Stdio);
        }
    }

    // 4. Default
    TransportType::Stdio
}
```

## Consequences

### Positive
- Zero-config experience for common cases
- Explicit override available when needed
- Deterministic selection (same input = same transport)
- Backward compatible with existing configs

### Negative
- SSE vs StreamableHttp detection relies on URL patterns (may need refinement)
- Config file must be parsed before transport selection

### Risks
- Remote server without "/sse" pattern might be SSE → mitigation: --transport flag
- New transport types require algorithm update

## Alternatives Considered

### 1. Always Explicit
Require users to specify transport type explicitly.
- Rejected: Poor UX, most users don't know/care about transport

### 2. Probe-Based Detection
Connect and probe to determine transport type.
- Rejected: Slow, unreliable, security concerns with probing

### 3. Config-Only
Only support transports defined in config file.
- Rejected: Limits ad-hoc usage with URLs/paths

## References

- MCP Specification: Transport Layer
- `src/transport/mod.rs`: Current implementation
- `src/cli/server.rs`: Server resolution logic
