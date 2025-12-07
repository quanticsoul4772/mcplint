# MCPLint Technical Plan
## MCP Server Security Testing Tool - Detailed Architecture & Milestones

**Version:** 1.0  
**Date:** December 7, 2025  
**Architecture:** Independent Modules with Smart Defaults

---

## Executive Summary

MCPLint is an **AI-native** security testing tool for Model Context Protocol (MCP) servers. AI powers every operation: protocol validation with semantic understanding, context-aware vulnerability scanning, and adaptive payload generation for fuzzing.

**Key Capabilities:**
- Every finding is AI-validated before reporting
- Fuzzer generates targeted payloads based on schema understanding
- Reports include synthesized analysis and remediation guidance
- Supports Anthropic, OpenAI, or local Ollama

This plan outlines a phased development approach with clear milestones, decision points, and integrated caching strategies.

---

## Competitive Analysis

### Industry Tool Patterns

| Tool | Key Features | What MCPLint Should Adopt |
|------|-------------|---------------------------|
| **Snyk** | `snyk test`, `snyk monitor`, cloud-synced vulnerability DB, actionable fix advice | Monitoring mode, fix suggestions, severity-based filtering |
| **Semgrep** | Pattern-based rules, multiple output formats (SARIF, JUnit, GitLab), --error flag for CI, custom rule support | Rule engine architecture, output format variety, strict mode |
| **Trivy** | Multi-backend caching (fs/memory/Redis), scanner modules (vuln/misconfig/secret), --scanners flag | Modular scanners, caching strategy, scanner selection |
| **AFL++/libFuzzer** | Coverage-guided mutation, corpus management, dictionary support, persistent mode | Fuzzer architecture, corpus handling, MCP-specific dictionaries |
| **Garak** | LLM vulnerability probes, automated scanning, model-agnostic | AI payload generation concepts, probe/detector pattern |

### Gap Analysis: No Existing Tool Provides

1. **MCP Protocol Validation** - JSON-RPC 2.0 + MCP-specific message validation
2. **MCP Security Scanning** - Tool schema analysis, capability abuse detection
3. **MCP Fuzzing** - Protocol-aware mutation with MCP message understanding
4. **Transport Abstraction** - stdio and SSE support in one tool

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                         CLI Layer                            │
│  validate | scan | fuzz | check | rules | init | doctor     │
├─────────────────────────────────────────────────────────────┤
│                     Module Orchestrator                      │
│           (Independent execution, smart defaults)            │
├──────────────┬──────────────┬──────────────┬────────────────┤
│   Validator  │   Scanner    │    Fuzzer    │   Reporter     │
│      ↓       │      ↓       │      ↓       │       ↓        │
│   AI-Spec    │  AI-Validate │ AI-Generate  │  AI-Synthesize │
│   Interpret  │  Findings    │  Payloads    │  Analysis      │
├──────────────┴──────────────┴──────────────┴────────────────┤
│                    AI Engine (Required)                      │
│         Anthropic | OpenAI | Ollama | Custom Endpoint        │
├─────────────────────────────────────────────────────────────┤
│                      Protocol Layer                          │
│         JSON-RPC 2.0 | MCP Messages | State Machine          │
├─────────────────────────────────────────────────────────────┤
│                      Transport Layer                         │
│                    stdio | SSE (HTTP)                        │
├─────────────────────────────────────────────────────────────┤
│                       Cache Layer                            │
│     Schemas | Results | Corpus | AI Responses                │
│              Filesystem | Memory | Redis                     │
└─────────────────────────────────────────────────────────────┘
```

---

## Development Milestones

### Milestone 0: Foundation (Transport + Protocol Core)
**Duration:** 2-3 weeks  
**Goal:** Establish communication with MCP servers

#### Deliverables
- [ ] **stdio transport**: Spawn child process, manage stdin/stdout pipes
- [ ] **SSE transport**: HTTP client for Server-Sent Events endpoints
- [ ] **JSON-RPC 2.0 parser**: Request/response/notification/error handling
- [ ] **MCP message types**: initialize, initialized, tools/list, tools/call, resources/list, prompts/list
- [ ] **Connection lifecycle**: Connect → Initialize → Ready → Operations → Shutdown
- [ ] **Auto-detection**: URL patterns (http/https → SSE, else → stdio)

#### Technical Decisions
| Decision | Choice | Rationale |
|----------|--------|-----------|
| Async runtime | Tokio | Industry standard, SSE support |
| HTTP client | reqwest | Mature, async, SSE-capable |
| JSON parsing | serde_json | Fast, well-integrated with Rust ecosystem |
| Process spawn | tokio::process | Async child process management |

#### Decision Point: Milestone 0 → 1
**Gate:** Successfully connect to 3+ real MCP servers (stdio and SSE)
- Test against: filesystem server, fetch server, an SSE-based server
- Validate message exchange works correctly
- **If blocked:** Debug transport issues before proceeding

---

### Milestone 1: Protocol Validator
**Duration:** 2 weeks  
**Goal:** Verify MCP specification compliance

#### Deliverables
- [ ] **Required field validation**: Ensure all mandatory fields present
- [ ] **Type checking**: Validate field types match spec
- [ ] **Sequence validation**: Proper message ordering (initialize first)
- [ ] **Schema validation**: Tool definitions have valid JSON schemas
- [ ] **Version checking**: Protocol version compatibility
- [ ] **Capability validation**: Advertised vs actual capabilities

#### Validation Rules (Initial Set)
```
PROTO-001: Missing required field in initialize response
PROTO-002: Invalid JSON-RPC version (must be "2.0")
PROTO-003: Tool definition missing required 'name' field
PROTO-004: Tool inputSchema is not valid JSON Schema
PROTO-005: Message sent before initialize completed
PROTO-006: Unknown notification type received
PROTO-007: Response ID doesn't match any pending request
PROTO-008: Protocol version mismatch
```

#### Output Format
```json
{
  "valid": false,
  "violations": [
    {
      "rule": "PROTO-004",
      "severity": "error",
      "message": "Tool 'execute_sql' has invalid inputSchema",
      "location": "tools[2].inputSchema",
      "details": "Missing 'type' field in schema root"
    }
  ]
}
```

#### Decision Point: Milestone 1 → 2
**Gate:** Validator detects known protocol issues in test fixtures
- Create intentionally malformed server responses
- Verify all validation rules trigger appropriately
- **Consider:** Should we support "lenient" mode for development servers?

---

### Milestone 2: Security Scanner
**Duration:** 3-4 weeks  
**Goal:** Detect security vulnerabilities in MCP server configurations

#### Rule Categories

**Critical Severity**
| Rule ID | Name | Description |
|---------|------|-------------|
| SEC-001 | Shell Command Injection | Tool accepts untrusted input passed to shell |
| SEC-002 | Path Traversal | File operations allow escaping intended directory |
| SEC-003 | SQL Injection | Database queries with string interpolation |
| SEC-004 | Code Execution | Tool can execute arbitrary code |

**High Severity**
| Rule ID | Name | Description |
|---------|------|-------------|
| SEC-010 | Unrestricted File Read | Can read arbitrary files without allowlist |
| SEC-011 | Unrestricted File Write | Can write arbitrary files |
| SEC-012 | Network SSRF | Can make requests to internal networks |
| SEC-013 | Credential Exposure | Tool leaks credentials in responses |

**Medium Severity**
| Rule ID | Name | Description |
|---------|------|-------------|
| SEC-020 | Missing Input Validation | No schema constraints on dangerous inputs |
| SEC-021 | Overly Permissive Schema | Schema accepts any type/format |
| SEC-022 | Verbose Error Messages | Errors leak implementation details |
| SEC-023 | Resource Exhaustion | No limits on resource-intensive operations |

**Low/Info Severity**
| Rule ID | Name | Description |
|---------|------|-------------|
| SEC-030 | Missing Description | Tool lacks security-relevant documentation |
| SEC-031 | Deprecated Pattern | Uses known-problematic patterns |
| SEC-032 | Capability Mismatch | Advertises capabilities it doesn't have |

#### Detection Techniques
1. **Schema Analysis**: Examine tool inputSchema for dangerous patterns
2. **Name/Description Heuristics**: Identify risky tool names (execute, run, shell, eval)
3. **Behavioral Probing**: Send test inputs and analyze responses
4. **Capability Mapping**: Cross-reference capabilities with known CVE patterns

#### CVE Mapping (Known MCP Vulnerabilities)
```
CVE-2024-XXXX (CVSS 9.6) → SEC-001: Command injection in tool_call
CVE-2024-YYYY (CVSS 8.2) → SEC-012: SSRF via fetch tool
...
```

#### Decision Point: Milestone 2 → 3
**Gate:** Scanner + AI validation achieves >90% precision on test vulnerable servers
- Build intentionally vulnerable MCP server for testing
- Measure false positive rate (<5% target with AI validation)
- AI must successfully filter obvious false positives

---

### Milestone 3: Fuzzer (Basic)
**Duration:** 4-5 weeks  
**Goal:** Discover crashes and unexpected behaviors through input mutation

#### Components

**Mutation Engine**
```rust
enum MutationStrategy {
    // JSON-level mutations
    TypeConfusion,      // String → Number, Array → Object
    BoundaryValues,     // MAX_INT, empty string, null
    DeepNesting,        // Deeply nested objects/arrays
    UnicodeInjection,   // Null bytes, control chars, RTL markers
    
    // JSON-RPC mutations
    InvalidId,          // Missing, wrong type, null
    MalformedVersion,   // "2.1", "1.0", missing
    UnknownMethod,      // Random method names
    
    // MCP-specific mutations
    ToolNotFound,       // Call non-existent tools
    SchemaViolation,    // Invalid inputs per schema
    SequenceViolation,  // Out-of-order messages
    ResourceExhaustion, // Large payloads, many concurrent
}
```

**Corpus Management**
```
corpus/
├── seed/              # Hand-crafted initial inputs
│   ├── valid/         # Known-good messages
│   └── edge-cases/    # Boundary conditions
├── generated/         # Fuzzer-discovered inputs
│   ├── crashes/       # Inputs that caused crashes
│   ├── hangs/         # Inputs that caused timeouts
│   └── interesting/   # New coverage paths
└── dictionaries/      # Protocol-specific tokens
    └── mcp.dict       # "tools/list", "initialize", etc.
```

**MCP Dictionary (mcp.dict)**
```
# JSON-RPC
"jsonrpc"
"2.0"
"method"
"params"
"result"
"error"
"id"

# MCP Methods
"initialize"
"initialized"
"tools/list"
"tools/call"
"resources/list"
"resources/read"
"prompts/list"
"prompts/get"

# MCP Fields
"protocolVersion"
"capabilities"
"serverInfo"
"name"
"version"
"inputSchema"

# Injection payloads
"$(whoami)"
"; cat /etc/passwd"
"' OR '1'='1"
"{{constructor.constructor('return this')()}}"
```

#### Crash Detection
- Exit code non-zero
- Connection terminated unexpectedly
- Timeout (configurable, default 5s)
- Error response with stack trace
- Memory exhaustion signals

#### Decision Point: Milestone 3 → 4
**Gate:** AI-powered fuzzer discovers bugs traditional fuzzing would miss
- Run against intentionally vulnerable server
- Compare AI-generated payloads vs random mutation discovery rate
- Measure executions/second performance (target: >100 exec/s)

---

### Milestone 4: Caching Layer
**Duration:** 2 weeks  
**Goal:** Reduce redundant operations for faster repeat scans

#### Cache Architecture

```rust
enum CacheBackend {
    Filesystem {
        path: PathBuf,  // Default: ~/.mcplint/cache/
    },
    Memory,  // For CI/ephemeral environments
    Redis {
        url: String,
        ttl: Duration,
    },
}

struct CacheConfig {
    backend: CacheBackend,
    schema_ttl: Duration,      // Default: 1 hour
    result_ttl: Duration,      // Default: 24 hours  
    corpus_persist: bool,      // Default: true
}
```

#### What Gets Cached

| Cache Type | Key | Value | TTL | Invalidation |
|------------|-----|-------|-----|--------------|
| Schema | server_hash | tool definitions | 1h | Server restart, version change |
| Scan Results | (server_hash, ruleset_hash) | findings | 24h | Manual, rule update |
| Validation | (server_hash, protocol_version) | violations | 1h | Server restart |
| Corpus | server_identifier | interesting inputs | Permanent | Manual prune |

#### Cache Operations
```bash
mcplint cache stats           # Show cache usage
mcplint cache clear           # Clear all caches
mcplint cache clear --schemas # Clear only schema cache
mcplint cache export          # Export corpus for sharing
```

#### CI Optimization
```yaml
# GitHub Actions example
- uses: actions/cache@v3
  with:
    path: ~/.mcplint/cache
    key: mcplint-${{ hashFiles('mcp-config.json') }}
    
- run: mcplint check ./my-server --cache-backend=filesystem
```

---

### Milestone 5: AI Integration (Core)
**Duration:** 3-4 weeks  
**Goal:** Embed AI as a core component of all MCPLint operations

**Philosophy:** MCPLint is an AI-native security tool. Every scan uses AI for payload generation, every finding is AI-validated, every report includes AI analysis.

#### AI is Embedded Everywhere

**1. Scanner: AI-Validated Findings**
Every finding passes through AI validation before being reported. No raw rule output reaches the user.

```
Rule Engine → Finding → AI Validation → Confirmed/Rejected
                              ↓
                    - Context analysis
                    - Schema understanding  
                    - False positive detection
                    - Severity adjustment
                    - Fix generation
```

**2. Fuzzer: AI-Generated Payloads**
The fuzzer doesn't just mutate randomly. It understands what it's attacking.

```
Tool Schema → AI Analysis → Targeted Payloads → Mutation Engine
                  ↓
         - Understands tool purpose
         - Generates context-aware injections
         - Learns from crash patterns
         - Adapts based on responses
```

**3. Validator: AI-Powered Spec Interpretation**
Protocol edge cases get AI judgment with semantic understanding.

```
Message → Structural Check → AI Interpretation → Verdict
                                    ↓
                         - Ambiguous spec handling
                         - Intent vs literal compliance
                         - Security implications
```

**4. Reporter: AI-Native Output**
Every report includes synthesized analysis.

```
Findings → AI Synthesis → Report
               ↓
        - Executive summary
        - Attack chain analysis
        - Prioritized remediation
        - Risk quantification
```

#### AI Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      AI Engine (Required)                    │
├─────────────────────────────────────────────────────────────┤
│  Provider Abstraction                                        │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐       │
│  │ Anthropic│ │  OpenAI  │ │  Ollama  │ │  Custom  │       │
│  │ Claude   │ │  GPT-4   │ │  Local   │ │  Endpoint│       │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘       │
├─────────────────────────────────────────────────────────────┤
│  Prompt Templates                                            │
│  - payload_generation.txt                                    │
│  - finding_validation.txt                                    │
│  - fix_suggestion.txt                                        │
│  - report_synthesis.txt                                      │
│  - schema_analysis.txt                                       │
├─────────────────────────────────────────────────────────────┤
│  Response Cache (Mandatory)                                  │
│  - Semantic deduplication                                    │
│  - TTL: 7 days default                                       │
│  - Cost tracking                                             │
└─────────────────────────────────────────────────────────────┘
```

#### Provider Configuration (Required)
```toml
# mcplint.toml - AI configuration is REQUIRED

[ai]
provider = "anthropic"           # anthropic | openai | ollama | custom
model = "claude-sonnet-4-20250514"  # Model identifier
api_key_env = "ANTHROPIC_API_KEY"   # Environment variable name

# For local/offline use
[ai.ollama]
endpoint = "http://localhost:11434"
model = "llama3:70b"

# For enterprise/custom endpoints
[ai.custom]
endpoint = "https://ai.company.internal/v1"
api_key_env = "COMPANY_AI_KEY"

[ai.cache]
path = "~/.mcplint/ai-cache"
ttl = "7d"
max_size = "1GB"

[ai.limits]
max_tokens_per_request = 4096
max_requests_per_scan = 100
timeout = "30s"
```

#### Startup Validation
MCPLint verifies AI connectivity on startup:
```
$ mcplint check ./server

MCPLint v1.0.0
✓ AI Provider: Anthropic (claude-sonnet-4-20250514)
✓ API Key: Valid
✓ Cache: 127 entries (42MB)
✓ Transport: stdio

Scanning...
```

If AI is not configured:
```
$ mcplint check ./server

ERROR: AI provider not configured.

MCPLint requires an AI provider to function. Configure one of:
  1. Set ANTHROPIC_API_KEY and add [ai] section to mcplint.toml
  2. Set OPENAI_API_KEY and add [ai] section to mcplint.toml  
  3. Run Ollama locally and configure [ai.ollama] section

See: https://mcplint.dev/setup
```

#### Decision Point: Milestone 5 → 6
**Gate:** AI integration is seamless and performant
- Scan time with AI: <2x baseline (caching helps)
- Finding quality: >90% user agreement
- Cost per scan: <$0.10 average (with caching)

---

### Milestone 6: Advanced Features
**Duration:** 3-4 weeks  
**Goal:** Polish for production CI/CD and power user workflows

#### 6.1 Baseline/Diff Mode
```bash
# Create baseline
mcplint scan ./server --output=baseline.json

# PR workflow: only show new findings
mcplint scan ./server --baseline=baseline.json --fail-on-new

# Output only shows delta
{
  "new_findings": [...],
  "fixed_findings": [...],
  "unchanged_findings_count": 42
}
```

#### 6.2 Watch Mode
```bash
# Auto-rescan on server changes (development mode)
mcplint watch ./server-dir --on-change="mcplint check {}"

# Watch specific files
mcplint watch ./server.py --debounce=500ms
```

#### 6.3 Plugin Architecture
```rust
// Custom rule plugin interface
pub trait SecurityRule {
    fn id(&self) -> &str;
    fn name(&self) -> &str;
    fn severity(&self) -> Severity;
    fn check(&self, context: &ScanContext) -> Vec<Finding>;
}

// Plugin loading
mcplint scan ./server --plugin=./my-rules.wasm
mcplint scan ./server --plugin-dir=./company-rules/
```

#### 6.4 Additional Output Formats
```bash
mcplint scan ./server --format=junit     # JUnit XML for CI
mcplint scan ./server --format=gitlab    # GitLab SAST format
mcplint scan ./server --format=markdown  # Human-readable report
```

#### 6.5 Resource Limits (CI-Friendly)
```bash
mcplint fuzz ./server --max-time=60s --max-memory=512M --max-execs=10000
mcplint scan ./server --timeout=30s
```

#### 6.6 Exit Codes
| Code | Meaning |
|------|---------|
| 0 | Success, no findings |
| 1 | Success, findings detected |
| 2 | Error (connection failed, config invalid) |
| 3 | Partial success (some checks skipped) |
| 4 | Timeout exceeded |

---

## CLI Design

### Command Structure
```
mcplint <command> [options] <target>

Commands:
  validate   Protocol compliance validation only
  scan       Security vulnerability scanning only  
  fuzz       Fuzz testing only
  check      Combined validate + scan (recommended default)
  rules      List available security rules
  init       Create configuration file
  doctor     Diagnose environment and connectivity
  cache      Manage caching (stats, clear, export)

Target Auto-Detection:
  http(s)://...  → SSE transport
  ./path         → stdio transport (spawn process)
  server-name    → Lookup in config file
```

### Common Options
```
--config=PATH        Configuration file (default: ./mcplint.toml)
--format=FORMAT      Output format: text|json|sarif|junit (default: text)
--output=PATH        Write results to file (default: stdout)
--severity=LEVEL     Minimum severity: critical|high|medium|low|info
--quiet              Suppress progress output
--verbose            Detailed output including debug info
--color=WHEN         Colorize output: always|never|auto (default: auto)
--timeout=DURATION   Maximum time per operation (default: 30s)
--ai-provider=NAME   Override AI provider from config
--ai-model=NAME      Override AI model from config
```

### Example Workflows
```bash
# Quick check during development
mcplint check ./my-server

# CI pipeline with strict settings  
mcplint check ./my-server --format=sarif --output=results.sarif \
  --severity=high --fail-on-findings

# Deep fuzzing session (AI generates targeted payloads automatically)
mcplint fuzz ./my-server --max-time=1h \
  --corpus-dir=./corpus --output-crashes=./crashes

# Compare against baseline in PR
mcplint check ./my-server --baseline=main-baseline.json \
  --format=json --fail-on-new

# Use local AI for air-gapped environments
mcplint check ./my-server --ai-provider=ollama --ai-model=llama3:70b
```

---

## Configuration File

```toml
# mcplint.toml

[general]
severity_threshold = "medium"  # Minimum severity to report
fail_on_findings = true        # Exit code 1 if findings
timeout = "30s"

# AI CONFIGURATION (REQUIRED)
[ai]
provider = "anthropic"              # anthropic | openai | ollama | custom
model = "claude-sonnet-4-20250514"     # Model identifier
api_key_env = "ANTHROPIC_API_KEY"   # Environment variable containing key

[ai.cache]
path = "~/.mcplint/ai-cache"
ttl = "7d"
max_size = "1GB"

[ai.limits]
max_tokens_per_request = 4096
timeout = "30s"

# Alternative: Local AI (Ollama)
# [ai]
# provider = "ollama"
# [ai.ollama]
# endpoint = "http://localhost:11434"
# model = "llama3:70b"

[servers]
# Named server configurations
[servers.my-server]
command = ["python", "./server.py"]
transport = "stdio"

[servers.remote-api]
url = "https://api.example.com/mcp/sse"
transport = "sse"
headers = { Authorization = "Bearer ${MCP_TOKEN}" }

[validator]
strict = false                 # Fail on warnings too
check_sequences = true
check_schemas = true

[scanner]
custom_rules_dir = "./rules"

[fuzzer]
max_time = "5m"
max_execs = 100000
corpus_dir = "./corpus"
dictionary = "./mcp.dict"
parallel_workers = 4

[cache]
backend = "filesystem"         # or "memory", "redis://..."
path = "~/.mcplint/cache"
schema_ttl = "1h"
result_ttl = "24h"

[output]
default_format = "text"
sarif_version = "2.1.0"
include_evidence = true
```

---

## Testing Strategy

### Unit Tests
- JSON-RPC parsing edge cases
- MCP message validation
- Rule detection accuracy
- Mutation strategy coverage

### Integration Tests  
- End-to-end with mock MCP servers
- Transport reliability (stdio reconnection, SSE keepalive)
- Cache hit/miss scenarios

### Fuzzer Self-Test
- Run MCPLint's fuzzer against MCPLint's own parser
- Ensure no crashes in input handling

### Benchmark Suite
- Scan time for various server sizes
- Fuzzer executions/second
- Memory usage under load
- Cache performance impact

---

## Risk Considerations

| Risk | Mitigation |
|------|------------|
| MCP spec evolves | Version-tagged validation rules, update mechanism |
| AI provider outage | Support multiple providers, fallback to Ollama |
| AI costs per scan | Aggressive caching, semantic deduplication, cost tracking |
| AI latency in CI | Response caching, parallel requests, timeout handling |
| Fuzzer causes harm | Sandboxing recommendations, rate limiting |
| Performance too slow for CI | Bounded modes, caching, parallel execution |
| No internet access | Ollama local model support for air-gapped environments |

---

## Success Metrics

| Milestone | Key Metric | Target |
|-----------|------------|--------|
| M0 | Server connectivity | 100% success rate |
| M1 | Validation accuracy | 95% on test fixtures |
| M2 | Detection precision (with AI validation) | >95% |
| M3 | AI-payload discovery rate vs random | >3x improvement |
| M4 | Repeat scan speedup with cache | 10x |
| M5 | AI response latency (cached) | <100ms |
| M6 | CI integration time | <60s for typical server |

---

## Appendix: File Structure

```
mcplint/
├── Cargo.toml
├── src/
│   ├── main.rs
│   ├── cli/
│   │   ├── mod.rs
│   │   ├── commands/
│   │   │   ├── validate.rs
│   │   │   ├── scan.rs
│   │   │   ├── fuzz.rs
│   │   │   ├── check.rs
│   │   │   ├── rules.rs
│   │   │   ├── init.rs
│   │   │   ├── doctor.rs
│   │   │   └── cache.rs
│   │   └── output.rs
│   ├── transport/
│   │   ├── mod.rs
│   │   ├── stdio.rs
│   │   └── sse.rs
│   ├── protocol/
│   │   ├── mod.rs
│   │   ├── jsonrpc.rs
│   │   └── mcp.rs
│   ├── validator/
│   │   ├── mod.rs
│   │   └── rules/
│   ├── scanner/
│   │   ├── mod.rs
│   │   ├── engine.rs
│   │   └── rules/
│   │       ├── mod.rs
│   │       ├── injection.rs
│   │       ├── traversal.rs
│   │       └── ...
│   ├── fuzzer/
│   │   ├── mod.rs
│   │   ├── mutator.rs
│   │   ├── corpus.rs
│   │   └── coverage.rs
│   ├── reporter/
│   │   ├── mod.rs
│   │   ├── text.rs
│   │   ├── json.rs
│   │   ├── sarif.rs
│   │   └── junit.rs
│   ├── cache/
│   │   ├── mod.rs
│   │   ├── filesystem.rs
│   │   ├── memory.rs
│   │   └── redis.rs
│   └── ai/
│       ├── mod.rs
│       ├── payloads.rs
│       ├── filter.rs
│       └── summary.rs
├── tests/
│   ├── fixtures/
│   │   ├── servers/
│   │   └── messages/
│   └── integration/
├── corpus/
│   ├── seed/
│   └── dictionaries/
└── payloads/
    ├── injection/
    └── fuzzing/
```

---

*Document generated for MCPLint development planning.*
