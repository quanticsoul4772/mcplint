# M2: Security Scanner - Implementation Plan

## Overview

**Milestone**: M2 - Security Scanner
**Goal**: Implement comprehensive security vulnerability detection for MCP servers
**Dependencies**: M1 (Protocol Validator) - Complete ✓

## Architecture Design

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          SecurityScanner                                 │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                      ScanEngine                                  │   │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐   │   │
│  │  │ RuleRegistry │  │ RuleExecutor │  │ FindingsCollector    │   │   │
│  │  │              │  │              │  │                      │   │   │
│  │  │ • load()     │  │ • execute()  │  │ • add_finding()      │   │   │
│  │  │ • filter()   │  │ • validate() │  │ • aggregate()        │   │   │
│  │  │ • by_cat()   │  │ • check()    │  │ • to_sarif()         │   │   │
│  │  └──────────────┘  └──────────────┘  └──────────────────────┘   │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                   Rule Categories                                │   │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐            │   │
│  │  │Injection │ │  Auth    │ │Transport │ │ Protocol │            │   │
│  │  │ INJ-001  │ │ AUTH-001 │ │TRANS-001 │ │PROTO-001 │            │   │
│  │  │ INJ-002  │ │ AUTH-002 │ │TRANS-002 │ │PROTO-002 │            │   │
│  │  │ INJ-003  │ │ AUTH-003 │ │          │ │PROTO-003 │            │   │
│  │  │ INJ-004  │ │          │ │          │ │          │            │   │
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘            │   │
│  │  ┌──────────┐ ┌──────────┐                                       │   │
│  │  │   Data   │ │   DoS    │                                       │   │
│  │  │ DATA-001 │ │ DOS-001  │                                       │   │
│  │  │ DATA-002 │ │ DOS-002  │                                       │   │
│  │  └──────────┘ └──────────┘                                       │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                    Scan Profiles                                 │   │
│  │  Quick      │ Standard    │ Full        │ Enterprise            │   │
│  │  ~10 rules  │ ~15 rules   │ All rules   │ All + compliance      │   │
│  │  Fast       │ Balanced    │ Thorough    │ Audit-ready           │   │
│  └─────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
```

## Component Design

### 1. ScanEngine (`src/scanner/engine.rs`)

Core scanning orchestrator that coordinates rule execution.

```rust
pub struct ScanEngine {
    config: ScanConfig,
    registry: RuleRegistry,
    client: Option<McpClient>,
}

pub struct ScanConfig {
    pub profile: ScanProfile,
    pub timeout_secs: u64,
    pub include_categories: Vec<String>,
    pub exclude_categories: Vec<String>,
    pub include_rules: Vec<String>,
    pub exclude_rules: Vec<String>,
    pub parallel_checks: bool,
}

impl ScanEngine {
    pub fn new(config: ScanConfig) -> Self;
    pub async fn scan_server(&mut self, target: &str, args: &[String]) -> Result<ScanFindings>;

    // Internal phases
    async fn connect_and_initialize(&mut self, target: &str, args: &[String]) -> Result<ServerContext>;
    async fn run_injection_checks(&self, ctx: &ServerContext) -> Vec<Finding>;
    async fn run_auth_checks(&self, ctx: &ServerContext) -> Vec<Finding>;
    async fn run_transport_checks(&self, ctx: &ServerContext) -> Vec<Finding>;
    async fn run_protocol_checks(&self, ctx: &ServerContext) -> Vec<Finding>;
    async fn run_data_checks(&self, ctx: &ServerContext) -> Vec<Finding>;
    async fn run_dos_checks(&self, ctx: &ServerContext) -> Vec<Finding>;
}
```

### 2. RuleRegistry Enhancement (`src/rules/mod.rs`)

Enhanced rule registry with execution capability.

```rust
pub struct SecurityRule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub category: RuleCategory,
    pub severity: Severity,
    pub references: Vec<Reference>,
    pub check: Box<dyn RuleCheck>,
}

pub enum RuleCategory {
    Injection,
    Auth,
    Transport,
    Protocol,
    Data,
    Dos,
}

#[async_trait]
pub trait RuleCheck: Send + Sync {
    async fn check(&self, ctx: &CheckContext) -> CheckResult;
    fn applicable(&self, ctx: &CheckContext) -> bool;
}

pub struct CheckContext<'a> {
    pub client: &'a mut McpClient,
    pub server_info: &'a ServerInfo,
    pub capabilities: &'a ServerCapabilities,
    pub tools: &'a [Tool],
    pub resources: &'a [Resource],
    pub prompts: &'a [Prompt],
}

pub enum CheckResult {
    Pass,
    Finding(Finding),
    Skip(String),
    Error(String),
}
```

### 3. Individual Rule Implementations (`src/scanner/rules/`)

Directory structure for rule implementations:

```
src/scanner/rules/
├── mod.rs              # Rule exports
├── injection/
│   ├── mod.rs
│   ├── command.rs      # MCP-INJ-001: Command injection
│   ├── sql.rs          # MCP-INJ-002: SQL injection
│   ├── path.rs         # MCP-INJ-003: Path traversal
│   └── ssrf.rs         # MCP-INJ-004: SSRF
├── auth/
│   ├── mod.rs
│   ├── missing.rs      # MCP-AUTH-001: Missing auth
│   ├── token.rs        # MCP-AUTH-002: Weak token validation
│   └── exposure.rs     # MCP-AUTH-003: Credential exposure
├── transport/
│   ├── mod.rs
│   ├── encryption.rs   # MCP-TRANS-001: Unencrypted HTTP
│   └── tls.rs          # MCP-TRANS-002: TLS validation
├── protocol/
│   ├── mod.rs
│   ├── poisoning.rs    # MCP-PROTO-001: Tool poisoning
│   ├── jsonrpc.rs      # MCP-PROTO-002: Invalid JSON-RPC
│   └── errors.rs       # MCP-PROTO-003: Missing error handling
├── data/
│   ├── mod.rs
│   ├── sensitive.rs    # MCP-DATA-001: Sensitive data exposure
│   └── excessive.rs    # MCP-DATA-002: Excessive data
└── dos/
    ├── mod.rs
    ├── resources.rs    # MCP-DOS-001: Resource consumption
    └── ratelimit.rs    # MCP-DOS-002: Rate limiting
```

### 4. Finding Structure (`src/scanner/finding.rs`)

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,           // Unique finding ID (UUID)
    pub rule_id: String,      // e.g., "MCP-INJ-001"
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub location: FindingLocation,
    pub evidence: Vec<Evidence>,
    pub remediation: String,
    pub references: Vec<Reference>,
    pub metadata: FindingMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingLocation {
    pub component: String,    // "tool", "resource", "transport", etc.
    pub identifier: String,   // Tool name, resource URI, etc.
    pub context: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub kind: EvidenceKind,
    pub data: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EvidenceKind {
    Request,
    Response,
    Configuration,
    Observation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reference {
    pub kind: ReferenceKind,
    pub id: String,
    pub url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReferenceKind {
    Cwe,
    Cve,
    McpAdvisory,
    Documentation,
}
```

### 5. SARIF Integration (`src/scanner/sarif.rs`)

```rust
impl ScanFindings {
    pub fn to_sarif(&self) -> SarifReport {
        // Convert findings to SARIF 2.1.0 format
        // - Map severity to SARIF levels
        // - Include rule definitions
        // - Format locations and evidence
    }
}
```

## Rule Implementation Details

### Injection Rules

| Rule ID | Name | Detection Strategy |
|---------|------|-------------------|
| MCP-INJ-001 | Command Injection | Analyze tool schemas for shell-unsafe patterns; test with injection payloads |
| MCP-INJ-002 | SQL Injection | Detect database tools; test with SQL injection patterns |
| MCP-INJ-003 | Path Traversal | Check file/path parameters for traversal sequences |
| MCP-INJ-004 | SSRF | Analyze URL parameters for internal network access |

### Authentication Rules

| Rule ID | Name | Detection Strategy |
|---------|------|-------------------|
| MCP-AUTH-001 | Missing Auth | Check transport for authentication requirements |
| MCP-AUTH-002 | Weak Token | Test OAuth/API key validation |
| MCP-AUTH-003 | Credential Exposure | Scan responses for credential patterns |

### Transport Rules

| Rule ID | Name | Detection Strategy |
|---------|------|-------------------|
| MCP-TRANS-001 | Unencrypted HTTP | Check if SSE/HTTP uses TLS |
| MCP-TRANS-002 | TLS Validation | Verify certificate validation |

### Protocol Rules

| Rule ID | Name | Detection Strategy |
|---------|------|-------------------|
| MCP-PROTO-001 | Tool Poisoning | Analyze tool descriptions for injection patterns |
| MCP-PROTO-002 | Invalid JSON-RPC | Send malformed requests |
| MCP-PROTO-003 | Error Handling | Test error conditions |

### Data Rules

| Rule ID | Name | Detection Strategy |
|---------|------|-------------------|
| MCP-DATA-001 | Sensitive Data | Pattern match outputs for secrets/PII |
| MCP-DATA-002 | Excessive Data | Analyze response sizes |

### DoS Rules

| Rule ID | Name | Detection Strategy |
|---------|------|-------------------|
| MCP-DOS-001 | Resource Consumption | Test resource limits |
| MCP-DOS-002 | Rate Limiting | Check for rate limit headers/behavior |

## Scan Profiles

```rust
pub fn get_profile_rules(profile: ScanProfile) -> Vec<&'static str> {
    match profile {
        ScanProfile::Quick => vec![
            "MCP-INJ-001", "MCP-INJ-003",  // Critical injection
            "MCP-AUTH-001",                 // Missing auth
            "MCP-TRANS-001",                // Encryption
            "MCP-PROTO-001",                // Tool poisoning
        ],
        ScanProfile::Standard => vec![
            // All Quick rules plus:
            "MCP-INJ-002", "MCP-INJ-004",  // More injection
            "MCP-AUTH-002", "MCP-AUTH-003", // Auth
            "MCP-PROTO-002",                // Protocol
            "MCP-DATA-001",                 // Data
        ],
        ScanProfile::Full => {
            // All rules
        },
        ScanProfile::Enterprise => {
            // All rules + compliance checks
        },
    }
}
```

## Implementation Steps

### Phase 1: Core Infrastructure (Files: 4)

1. **`src/scanner/engine.rs`** - ScanEngine implementation
   - Initialization and connection handling
   - Rule execution orchestration
   - Results aggregation

2. **`src/scanner/finding.rs`** - Finding data structures
   - Finding, Evidence, Location types
   - Severity and reference enums

3. **`src/scanner/context.rs`** - Check context
   - ServerContext with collected info
   - CheckContext for rule execution

4. **`src/scanner/mod.rs`** - Module updates
   - Export new types
   - Integrate with existing structures

### Phase 2: Rule Framework (Files: 3)

5. **`src/scanner/rules/mod.rs`** - Rule trait and registry
   - RuleCheck trait
   - Rule registration

6. **`src/rules/mod.rs`** - Enhanced RuleRegistry
   - SecurityRule with check capability
   - Category filtering

7. **`src/scanner/profiles.rs`** - Profile definitions
   - Rule sets per profile
   - Profile configuration

### Phase 3: Rule Implementations (Files: 6)

8. **`src/scanner/rules/injection/mod.rs`** - Injection rules
   - MCP-INJ-001 through MCP-INJ-004
   - Payload generation

9. **`src/scanner/rules/auth/mod.rs`** - Auth rules
   - MCP-AUTH-001 through MCP-AUTH-003

10. **`src/scanner/rules/transport/mod.rs`** - Transport rules
    - MCP-TRANS-001, MCP-TRANS-002

11. **`src/scanner/rules/protocol/mod.rs`** - Protocol rules
    - MCP-PROTO-001 through MCP-PROTO-003

12. **`src/scanner/rules/data/mod.rs`** - Data rules
    - MCP-DATA-001, MCP-DATA-002

13. **`src/scanner/rules/dos/mod.rs`** - DoS rules
    - MCP-DOS-001, MCP-DOS-002

### Phase 4: Integration (Files: 3)

14. **`src/scanner/sarif.rs`** - SARIF output
    - ScanFindings to SARIF conversion
    - GitHub Code Scanning format

15. **`src/cli/commands/scan.rs`** - CLI integration
    - Connect to ScanEngine
    - Handle include/exclude options

16. **`src/cli/commands/rules.rs`** - Rules command update
    - Show security rules with details
    - Category filtering

## Testing Strategy

### Unit Tests
- Each rule has isolated unit tests
- Mock server responses for detection testing
- Edge case coverage

### Integration Tests
- Full scan against test MCP servers
- Profile verification
- SARIF output validation

### Test Fixtures
```
tests/fixtures/
├── vulnerable_server/     # MCP server with known vulnerabilities
├── secure_server/         # Clean MCP server
└── payloads/              # Test payloads for injection tests
```

## Success Criteria

1. **Core Functionality**
   - [ ] All 15 security rules implemented
   - [ ] 4 scan profiles working
   - [ ] Include/exclude filtering works
   - [ ] SARIF output generates valid reports

2. **Quality**
   - [ ] All tests passing
   - [ ] No clippy warnings
   - [ ] Code formatted

3. **Documentation**
   - [ ] Rule documentation complete
   - [ ] API docs for public types
   - [ ] README updated with scan examples

## File Summary

| Category | Files | Lines (Est.) |
|----------|-------|--------------|
| Core Infrastructure | 4 | ~600 |
| Rule Framework | 3 | ~400 |
| Rule Implementations | 6 | ~1200 |
| Integration | 3 | ~300 |
| **Total** | **16** | **~2500** |

## Dependencies

No new dependencies required. Uses existing:
- `serde` / `serde_json` - Serialization
- `anyhow` - Error handling
- `async-trait` - Async traits
- `uuid` - Finding IDs
- `regex` - Pattern matching

## Risk Mitigation

| Risk | Mitigation |
|------|------------|
| Complex async rule execution | Use proven patterns from M1 validator |
| False positives | Conservative detection with evidence requirements |
| Performance | Parallel rule execution, caching |
| Rule maintenance | Modular structure, clear documentation |
