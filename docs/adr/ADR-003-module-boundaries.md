# ADR-003: Module Boundary Definitions

## Status
Accepted

## Date
2025-12-11

## Context

MCPLint has grown to include multiple subsystems:
- CLI command handling
- Protocol validation
- Security scanning
- Fuzzing engine
- AI-powered explanations
- Caching layer
- Transport abstraction
- Report generation

Clear module boundaries are needed to:
- Enable parallel development
- Prevent tight coupling
- Support testing in isolation
- Allow future extensibility

## Decision

### Module Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                           CLI Layer                              │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐           │
│  │ validate │ │   scan   │ │   fuzz   │ │ explain  │  ...      │
│  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘           │
└───────┼────────────┼────────────┼────────────┼──────────────────┘
        │            │            │            │
┌───────┴────────────┴────────────┴────────────┴──────────────────┐
│                         Engine Layer                             │
│  ┌────────────────┐ ┌────────────────┐ ┌────────────────┐       │
│  │ValidationEngine│ │   ScanEngine   │ │  FuzzSession   │       │
│  └───────┬────────┘ └───────┬────────┘ └───────┬────────┘       │
│          │                  │                  │                 │
│  ┌───────┴──────────────────┴──────────────────┴───────┐        │
│  │                    ExplainEngine                     │        │
│  └──────────────────────────┬──────────────────────────┘        │
└─────────────────────────────┼───────────────────────────────────┘
                              │
┌─────────────────────────────┴───────────────────────────────────┐
│                        Core Services                             │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐           │
│  │McpClient │ │  Cache   │ │ Reporter │ │ Baseline │           │
│  └────┬─────┘ └──────────┘ └──────────┘ └──────────┘           │
└───────┼─────────────────────────────────────────────────────────┘
        │
┌───────┴─────────────────────────────────────────────────────────┐
│                       Transport Layer                            │
│  ┌──────────┐ ┌──────────┐ ┌──────────────────┐                 │
│  │  Stdio   │ │   SSE    │ │ StreamableHttp   │                 │
│  └──────────┘ └──────────┘ └──────────────────┘                 │
└─────────────────────────────────────────────────────────────────┘
```

### Module Responsibilities & Boundaries

#### CLI Layer (`src/cli/`)
**Responsibility**: User interaction, argument parsing, output formatting
**Dependencies**: Engine Layer only
**Exports**: None (entry point)

```rust
// ALLOWED: CLI → Engine
use crate::scanner::ScanEngine;
use crate::validator::ValidationEngine;

// FORBIDDEN: CLI → Transport (use Engine instead)
// use crate::transport::StdioTransport; // ❌
```

#### Engine Layer (`src/scanner/`, `src/validator/`, `src/fuzzer/`, `src/ai/`)
**Responsibility**: Business logic, orchestration
**Dependencies**: Core Services, Protocol types
**Exports**: Public engine APIs

```rust
// scanner/engine.rs
pub struct ScanEngine {
    client: McpClient,      // Core Service
    cache: CacheManager,    // Core Service
    rules: Vec<Box<dyn SecurityRule>>,
}

impl ScanEngine {
    // Public API - used by CLI
    pub async fn scan(&mut self, profile: ScanProfile) -> Result<ScanResults>;

    // Internal - not exposed to CLI
    fn apply_rules(&self, context: &ServerContext) -> Vec<Finding>;
}
```

#### Core Services (`src/client/`, `src/cache/`, `src/reporter/`, `src/baseline/`)
**Responsibility**: Shared infrastructure
**Dependencies**: Transport Layer, Protocol types
**Exports**: Service interfaces

```rust
// client/mod.rs
pub struct McpClient {
    transport: Box<dyn Transport>,  // Transport abstraction
    // ...
}

// Client doesn't know about engines
// Engines don't know about transport implementation
```

#### Transport Layer (`src/transport/`)
**Responsibility**: Wire protocol, connection management
**Dependencies**: Protocol types only
**Exports**: Transport trait implementations

```rust
pub trait Transport: Send + Sync {
    async fn send(&mut self, request: JsonRpcRequest) -> Result<JsonRpcResponse>;
    async fn close(&mut self) -> Result<()>;
}

// Transport knows nothing about scanning, validation, etc.
```

#### Protocol Types (`src/protocol/`)
**Responsibility**: MCP/JSON-RPC type definitions
**Dependencies**: None (leaf module)
**Exports**: Type definitions only

```rust
// Pure data types - no behavior
pub struct Tool { pub name: String, pub description: String, ... }
pub struct Resource { pub uri: String, pub name: String, ... }
```

### Dependency Rules

```
┌─────────┐
│   CLI   │ ──────────────────────────────────────┐
└────┬────┘                                       │
     │ uses                                       │
     ▼                                            │
┌─────────┐                                       │
│ Engine  │ ──────────────────────────┐          │
└────┬────┘                           │          │
     │ uses                           │          │
     ▼                                ▼          ▼
┌─────────┐                      ┌─────────┐
│  Core   │ ─────────────────────│Protocol │
└────┬────┘                      └─────────┘
     │ uses                           ▲
     ▼                                │
┌─────────┐                           │
│Transport│ ──────────────────────────┘
└─────────┘

Rule: Arrows point DOWN or RIGHT only (no upward dependencies)
```

### Cross-Cutting Concerns

| Concern | Implementation | Location |
|---------|----------------|----------|
| Logging | `tracing` crate | All layers |
| Error Handling | `anyhow::Result` | All layers |
| Configuration | `Config` struct | Core Services |
| Metrics | `CacheMetrics`, etc. | Per-module |

### Module Interface Examples

```rust
// ✅ GOOD: Engine exposes high-level API
pub struct ScanEngine { /* private fields */ }
impl ScanEngine {
    pub fn new(client: McpClient, cache: CacheManager) -> Self;
    pub async fn scan(&mut self, profile: ScanProfile) -> Result<ScanResults>;
}

// ❌ BAD: Engine exposes internal details
pub struct ScanEngine {
    pub client: McpClient,  // Should be private
    pub rules: Vec<Box<dyn SecurityRule>>,  // Implementation detail
}
```

## Consequences

### Positive
- Clear ownership per module
- Independent testing possible
- Parallel development enabled
- Future extensibility (new transports, new rules)

### Negative
- Some indirection overhead
- Must maintain interface stability
- Cross-module changes require coordination

### Risks
- Boundary violations creep in over time → mitigation: CI lint checks
- Over-abstraction → mitigation: YAGNI principle

## Validation

### Architectural Lint Rules

```rust
// In CI or as a custom lint
#[deny(clippy::disallowed_imports)]
// cli/ cannot import from transport/
// engine/ cannot import from cli/
// transport/ cannot import from scanner/, validator/, etc.
```

### Test Organization

```
tests/
├── cli/           # CLI integration tests
├── scanner/       # Scanner unit + integration tests
├── validator/     # Validator unit tests
├── transport/     # Transport mock tests
└── integration/   # Full system tests
```

## References

- Clean Architecture (Robert C. Martin)
- Hexagonal Architecture (Alistair Cockburn)
- `src/lib.rs`: Module exports
