# MCPLint Technical Plan
## MCP Server Security Testing Tool

**Version:** 1.2
**Architecture:** Independent Modules with Smart Defaults
**MCP Spec:** 2025-03-26

---

## What This Is

MCPLint is an **AI-native** security testing tool for MCP servers. AI powers every operation:
- Protocol validation with semantic understanding
- Context-aware vulnerability scanning
- Adaptive payload generation for fuzzing

**Core Features:**
- AI-validated findings (no raw rule output)
- Schema-aware payload generation
- Synthesized remediation guidance
- Multi-provider: Anthropic, OpenAI, Ollama
- Hybrid mode for air-gapped/cost-sensitive use

---

## Threat Landscape (2025)

### Documented MCP Vulnerabilities

| CVE | CVSS | Description | Impact |
|-----|------|-------------|--------|
| CVE-2025-6514 | 9.6 | Command injection in mcp-remote | 437K+ downloads affected |
| CVE-2025-49596 | 9.4 | RCE in MCP Inspector | Full system compromise |
| CVE-2025-32711 | - | "EchoLeak" prompt injection | Data exfiltration via Copilot |
| CVE-2025-53109 | 8.2 | Path traversal in file tools | Arbitrary file access |

### Attack Statistics
- **43%** of MCP servers have command injection flaws
- **92%** exploit probability with 10 MCP plugins deployed
- **5.5%** of servers exhibit tool poisoning attacks
- OAuth vulnerabilities represent the most severe attack class

### Attack Classes Requiring Detection
1. **Traditional Injection** - Command, SQL, Path Traversal, SSRF
2. **Tool Poisoning** - Malicious instructions in tool descriptions
3. **Cross-Server Shadowing** - Multi-server interference attacks
4. **Rug Pull Attacks** - Time-delayed malicious updates
5. **Full-Schema Poisoning** - Attack surface beyond descriptions
6. **OAuth Scope Abuse** - Overly broad token permissions
7. **Unicode Hidden Instructions** - Invisible prompt injection

---

## Competitive Analysis

### Industry Tool Patterns

| Tool | Key Features | What MCPLint Should Adopt |
|------|-------------|---------------------------|
| **Snyk** | `snyk test`, `snyk monitor`, cloud-synced vulnerability DB, actionable fix advice | Monitoring mode, fix suggestions, severity-based filtering |
| **Semgrep** | Pattern-based rules, multiple output formats (SARIF, JUnit, GitLab), --error flag for CI, custom rule support | Rule engine architecture, output format variety, strict mode |
| **Trivy** | Multi-backend caching (fs/memory/Redis), scanner modules (vuln/misconfig/secret), --scanners flag | Modular scanners, caching strategy, scanner selection |
| **AFL++/libFuzzer** | Coverage-guided mutation, corpus management, dictionary support, persistent mode, AddressSanitizer | Fuzzer architecture, corpus handling, MCP-specific dictionaries, ASAN integration |
| **Garak** | LLM vulnerability probes, automated scanning, model-agnostic | AI payload generation concepts, probe/detector pattern |

### MCP-Specific Competitors (Emerged 2025)

| Tool | Features | MCPLint Differentiation |
|------|----------|------------------------|
| **MCP-Scan** | Static/dynamic scanning, tool poisoning, rug pull detection, proxy mode | MCPLint: AI-native, fuzzing, SARIF output |
| **Proximity** | Tool enumeration, resource scanning, risk assessment | MCPLint: Comprehensive validate+scan+fuzz |
| **Penzzer** | MCP fuzzing, schema-aware test generation | MCPLint: AI-powered payload generation |
| **MCPSafetyScanner** | Role-based testing, auditor simulation | MCPLint: Multi-provider AI, CI/CD ready |

### Why MCPLint
- **AI-native** - Competitors use pattern matching only
- **Comprehensive** - validate + scan + fuzz in one tool
- **SARIF/CI ready** - Enterprise integration from day one
- **Multi-provider AI** - Anthropic, OpenAI, Ollama, custom
- **Hybrid mode** - Works without AI for air-gapped use

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
│               AI Engine (Required | Enhanced | Disabled)     │
│         Anthropic | OpenAI | Ollama | Custom Endpoint        │
├─────────────────────────────────────────────────────────────┤
│                      Protocol Layer                          │
│    JSON-RPC 2.0 | MCP Messages | State Machine | OAuth 2.1   │
├─────────────────────────────────────────────────────────────┤
│                      Transport Layer                         │
│              stdio | Streamable HTTP | SSE (legacy)          │
├─────────────────────────────────────────────────────────────┤
│                       Cache Layer                            │
│     Schemas | Results | Corpus | AI Responses                │
│              Filesystem | Memory | Redis                     │
└─────────────────────────────────────────────────────────────┘
```

---

## Implementation

### M0: Foundation (Transport + Protocol)

#### Deliverables
- [ ] **stdio transport**: Spawn child process, manage stdin/stdout pipes
- [ ] **Streamable HTTP transport**: Modern HTTP transport (MCP 2025 spec)
- [ ] **SSE transport (legacy)**: HTTP client for Server-Sent Events endpoints
- [ ] **JSON-RPC 2.0 parser**: Request/response/notification/error handling
- [ ] **MCP message types**: initialize, initialized, tools/list, tools/call, resources/list, prompts/list
- [ ] **Connection lifecycle**: Connect → Initialize → Ready → Operations → Shutdown
- [ ] **Auto-detection**: URL patterns (http/https → Streamable HTTP, else → stdio)
- [ ] **OAuth 2.1 support**: Token validation for remote HTTP servers (per 2025 spec)

#### Tech Stack
| Component | Choice | Why |
|-----------|--------|-----|
| Async runtime | Tokio | Standard, stable |
| HTTP client | reqwest | Async, mature |
| JSON | serde_json | Fast |
| Process spawn | tokio::process | Async child process |
| TLS | Rustls | Memory-safe, no OpenSSL |

---

### M1: Protocol Validator

#### Deliverables
- [ ] **Required field validation**: Ensure all mandatory fields present
- [ ] **Type checking**: Validate field types match spec
- [ ] **Sequence validation**: Proper message ordering (initialize first)
- [ ] **Schema validation**: Tool definitions have valid JSON schemas
- [ ] **Version checking**: Protocol version compatibility (2024-11-05, 2025-03-26)
- [ ] **Capability validation**: Advertised vs actual capabilities
- [ ] **OAuth validation**: Token scope and expiry checking

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
PROTO-009: OAuth token expired or invalid scope
PROTO-010: Streamable HTTP session management violation
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

---

### M2: Security Scanner

#### Rule Categories

**Critical Severity (SEC-001 to SEC-009)**
| Rule ID | Name | Description | CVE Reference |
|---------|------|-------------|---------------|
| SEC-001 | Shell Command Injection | Tool accepts untrusted input passed to shell | CVE-2025-6514 |
| SEC-002 | Path Traversal | File operations allow escaping intended directory | CVE-2025-53109 |
| SEC-003 | SQL Injection | Database queries with string interpolation | SQLite MCP vuln |
| SEC-004 | Code Execution | Tool can execute arbitrary code | - |
| SEC-005 | Tool Description Injection | Malicious instructions in tool descriptions | Tool poisoning |
| SEC-006 | Full-Schema Poisoning | Attack vectors in entire tool schema | CyberArk research |

**High Severity (SEC-010 to SEC-019)**
| Rule ID | Name | Description |
|---------|------|-------------|
| SEC-010 | Unrestricted File Read | Can read arbitrary files without allowlist |
| SEC-011 | Unrestricted File Write | Can write arbitrary files |
| SEC-012 | Network SSRF | Can make requests to internal networks |
| SEC-013 | Credential Exposure | Tool leaks credentials in responses |
| SEC-014 | Cross-Server Tool Shadowing | Server redefines tools from other servers |
| SEC-015 | Rug Pull Vulnerability | Tool behavior can change post-deployment |
| SEC-016 | OAuth Scope Abuse | Overly broad token permissions |

**Medium Severity (SEC-020 to SEC-029)**
| Rule ID | Name | Description |
|---------|------|-------------|
| SEC-020 | Missing Input Validation | No schema constraints on dangerous inputs |
| SEC-021 | Overly Permissive Schema | Schema accepts any type/format |
| SEC-022 | Verbose Error Messages | Errors leak implementation details |
| SEC-023 | Resource Exhaustion | No limits on resource-intensive operations |
| SEC-024 | Unicode Hidden Instructions | Invisible characters in descriptions |
| SEC-025 | Indirect Prompt Injection | External content can influence LLM |

**Low/Info Severity (SEC-030 to SEC-039)**
| Rule ID | Name | Description |
|---------|------|-------------|
| SEC-030 | Missing Description | Tool lacks security-relevant documentation |
| SEC-031 | Deprecated Pattern | Uses known-problematic patterns |
| SEC-032 | Capability Mismatch | Advertises capabilities it doesn't have |
| SEC-033 | Unencrypted Transport | HTTP used instead of HTTPS |
| SEC-034 | Missing Rate Limiting | No protection against request flooding |

#### Detection Techniques
1. **Schema Analysis**: Examine tool inputSchema for dangerous patterns
2. **Name/Description Heuristics**: Identify risky tool names (execute, run, shell, eval)
3. **Behavioral Probing**: Send test inputs and analyze responses
4. **Capability Mapping**: Cross-reference capabilities with known CVE patterns
5. **Hash Monitoring**: Detect tool definition changes (rug pull detection)
6. **Cross-Server Analysis**: Identify shadowing between connected servers
7. **Unicode Scanning**: Detect invisible/control characters

#### CVE Mapping (Known MCP Vulnerabilities)
```
CVE-2025-6514 (CVSS 9.6) → SEC-001: Command injection in mcp-remote
CVE-2025-49596 (CVSS 9.4) → SEC-004: RCE in MCP Inspector
CVE-2025-53109 (CVSS 8.2) → SEC-002: Path traversal in file tools
CVE-2025-32711 → SEC-025: EchoLeak prompt injection
```

#### Test Targets
- Anthropic SQLite MCP (archived, 5000+ forks, known SQL injection)
- mcp-remote pre-0.1.16 (CVE-2025-6514)
- Intentionally vulnerable test server

---

### M3: Fuzzer

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

    // AI-guided mutations (when AI enabled)
    SemanticInjection,  // Context-aware attack payloads
    SchemaAwarePayload, // Payloads crafted for specific tool schemas
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

# Tool poisoning payloads
"<IMPORTANT>Ignore previous instructions"
"\u200B\u200C\u200D"  # Zero-width characters
```

#### Performance (AFL++ patterns)
- Persistent mode for 5-10x speedup
- Deferred init to skip costly startup
- AddressSanitizer for memory bugs
- Parallel fuzzing coordination
- Custom mutators for MCP-aware mutation

#### Crash Detection
- Exit code non-zero
- Connection terminated unexpectedly
- Timeout (configurable, default 5s)
- Error response with stack trace
- Memory exhaustion signals
- AddressSanitizer reports

---

### M4: Caching

#### Architecture

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
| Tool Hashes | server_id | hash of tool definitions | Permanent | Rug pull detection |

#### Cache Operations
```bash
mcplint cache stats           # Show cache usage
mcplint cache clear           # Clear all caches
mcplint cache clear --schemas # Clear only schema cache
mcplint cache export          # Export corpus for sharing
```

#### CI Example
```yaml
- uses: actions/cache@v4
  with:
    path: ~/.mcplint/cache
    key: mcplint-${{ hashFiles('mcp-config.json') }}
```

---

### M5: AI Integration

MCPLint is AI-native. Every scan uses AI for payload generation, every finding is AI-validated, every report includes AI analysis.

#### AI Modes

```toml
[ai]
mode = "required"  # required | enhanced | disabled

# required  - AI powers all operations, fails without AI
# enhanced  - AI improves results, works without AI (default for adoption)
# disabled  - Traditional pattern-matching only
```

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
│               AI Engine (Required | Enhanced | Disabled)     │
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
└─────────────────────────────────────────────────────────────┘
```

#### Provider Configuration
```toml
# mcplint.toml - AI configuration

[ai]
mode = "enhanced"                   # required | enhanced | disabled
provider = "anthropic"              # anthropic | openai | ollama | custom
model = "claude-sonnet-4-20250514"  # Model identifier
api_key_env = "ANTHROPIC_API_KEY"   # Environment variable name

# For local/offline use
[ai.ollama]
endpoint = "http://localhost:11434"
model = "llama3:70b"                # Or llama3:8b for faster/cheaper

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
MCPLint verifies AI connectivity on startup (when mode != disabled):
```
$ mcplint check ./server

MCPLint v1.0.0
✓ AI Provider: Anthropic (claude-sonnet-4-20250514)
✓ API Key: Valid
✓ Cache: 127 entries (42MB)
✓ Transport: stdio

Scanning...
```

If AI is not configured but mode is "enhanced":
```
$ mcplint check ./server

MCPLint v1.0.0
⚠ AI Provider: Not configured (running in basic mode)
  Configure AI for improved accuracy. See: mcplint.dev/setup
✓ Transport: stdio

Scanning (basic mode)...
```

---

### M6: Advanced Features

#### Baseline/Diff Mode
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

#### Watch Mode
```bash
mcplint watch ./server-dir --on-change="mcplint check {}"
mcplint watch ./server.py --debounce=500ms
```

#### Plugin Architecture
```rust
pub trait SecurityRule {
    fn id(&self) -> &str;
    fn name(&self) -> &str;
    fn severity(&self) -> Severity;
    fn check(&self, context: &ScanContext) -> Vec<Finding>;
}
```
```bash
mcplint scan ./server --plugin=./my-rules.wasm
```

#### Output Formats
```bash
mcplint scan ./server --format=sarif|json|junit|gitlab|markdown
```

#### Resource Limits
```bash
mcplint fuzz ./server --max-time=60s --max-memory=512M --max-execs=10000
```

#### Exit Codes
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
  http(s)://...  → Streamable HTTP transport
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
--ai-mode=MODE       Override AI mode: required|enhanced|disabled
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

# CI pipeline without AI
mcplint check ./my-server --ai-mode=disabled --format=sarif

# Deep fuzzing session (AI generates targeted payloads automatically)
mcplint fuzz ./my-server --max-time=1h \
  --corpus-dir=./corpus --output-crashes=./crashes

# Compare against baseline in PR
mcplint check ./my-server --baseline=main-baseline.json \
  --format=json --fail-on-new

# Use local AI for air-gapped environments
mcplint check ./my-server --ai-provider=ollama --ai-model=llama3:8b
```

---

## Configuration File

```toml
# mcplint.toml

[general]
severity_threshold = "medium"  # Minimum severity to report
fail_on_findings = true        # Exit code 1 if findings
timeout = "30s"

# AI CONFIGURATION
[ai]
mode = "enhanced"                   # required | enhanced | disabled
provider = "anthropic"              # anthropic | openai | ollama | custom
model = "claude-sonnet-4-20250514"  # Model identifier
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
# mode = "enhanced"
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
url = "https://api.example.com/mcp"
transport = "streamable_http"  # or "sse" for legacy
headers = { Authorization = "Bearer ${MCP_TOKEN}" }

[validator]
strict = false                 # Fail on warnings too
check_sequences = true
check_schemas = true
check_oauth = true             # Validate OAuth tokens

[scanner]
custom_rules_dir = "./rules"
enable_tool_poisoning = true   # SEC-005, SEC-006
enable_rug_pull_detection = true  # SEC-015

[fuzzer]
max_time = "5m"
max_execs = 100000
corpus_dir = "./corpus"
dictionary = "./mcp.dict"
parallel_workers = 4
use_asan = true                # Enable AddressSanitizer

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

## Testing

**Unit:** JSON-RPC parsing, MCP validation, rule detection, mutation coverage

**Integration:** Mock MCP servers, transport reliability, cache scenarios, OAuth validation

**Self-test:** Run MCPLint fuzzer against MCPLint parser

**Benchmarks:** Scan time, fuzzer execs/sec, memory, cache impact, AI vs non-AI

**Vulnerable targets:** SQLite MCP (SQL injection), mcp-remote <0.1.16 (CVE-2025-6514)

---

## Risks & Mitigations

| Risk | Mitigation |
|------|------------|
| MCP spec evolves | Version-tagged rules, monitor spec repo |
| AI provider outage | Multi-provider, fallback modes |
| AI latency in CI | Caching, parallel requests, disabled mode |
| Fuzzer causes harm | Sandboxing, rate limiting, ASAN |
| No internet | Ollama local models |

---

## File Structure

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
│   │   ├── streamable_http.rs    # NEW: 2025 spec
│   │   └── sse.rs                # Legacy support
│   ├── protocol/
│   │   ├── mod.rs
│   │   ├── jsonrpc.rs
│   │   ├── mcp.rs
│   │   └── oauth.rs              # NEW: OAuth 2.1 support
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
│   │       ├── tool_poisoning.rs  # NEW: SEC-005, SEC-006
│   │       ├── rug_pull.rs        # NEW: SEC-015
│   │       ├── cross_server.rs    # NEW: SEC-014
│   │       └── ...
│   ├── fuzzer/
│   │   ├── mod.rs
│   │   ├── mutator.rs
│   │   ├── corpus.rs
│   │   ├── coverage.rs
│   │   └── asan.rs               # NEW: AddressSanitizer integration
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
│       ├── providers/            # NEW: Provider abstraction
│       │   ├── mod.rs
│       │   ├── anthropic.rs
│       │   ├── openai.rs
│       │   ├── ollama.rs
│       │   └── custom.rs
│       ├── payloads.rs
│       ├── filter.rs
│       └── summary.rs
├── tests/
│   ├── fixtures/
│   │   ├── servers/
│   │   │   └── vulnerable/       # NEW: Intentionally vulnerable servers
│   │   └── messages/
│   └── integration/
├── corpus/
│   ├── seed/
│   └── dictionaries/
└── payloads/
    ├── injection/
    ├── tool_poisoning/           # NEW
    └── fuzzing/
```

---

## References

### MCP Security Research
- [JFrog: CVE-2025-6514 Analysis](https://jfrog.com/blog/2025-6514-critical-mcp-remote-rce-vulnerability/)
- [Docker: MCP Security Issues](https://www.docker.com/blog/mcp-security-issues-threatening-ai-infrastructure/)
- [CyberArk: Full-Schema Poisoning](https://www.cyberark.com/resources/threat-research-blog/poison-everywhere-no-output-from-your-mcp-server-is-safe)
- [Invariant Labs: Tool Poisoning](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks)

### Protocol Specifications
- [MCP Specification 2025-03-26](https://modelcontextprotocol.io/specification/2025-03-26)
- [Streamable HTTP Transport](https://modelcontextprotocol.io/specification/2025-03-26/transports)

### Fuzzing Best Practices
- [AFL++ Documentation](https://aflplus.plus/docs/best_practices/)
- [libFuzzer Guide](https://llvm.org/docs/LibFuzzer.html)

