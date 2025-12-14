# CLAUDE.md

This file provides guidance to Claude Code when working with code in this repository.

## Project Overview

MCPLint is a Rust-based security testing tool for Model Context Protocol (MCP) servers. It provides protocol validation, security vulnerability scanning, coverage-guided fuzzing, AI-assisted vulnerability explanation, and multi-backend caching with SARIF output for CI/CD integration.

## Build and Development

```bash
# Build
cargo build              # Debug build
cargo build --release    # Release build

# Install
cargo install --path .   # Install to ~/.cargo/bin

# Test
cargo test               # Run all tests
cargo test -- --nocapture  # Show test output

# Lint and Format
cargo clippy             # Lint
cargo fmt                # Format code
```

## Running MCPLint

After installation:

```bash
mcplint servers                  # List servers from config
mcplint validate <server>        # Validate protocol compliance
mcplint scan <server>            # Security scan
mcplint fuzz <server>            # Fuzz testing
mcplint explain <server>         # AI explanations
mcplint rules --details          # List rules
mcplint doctor                   # Environment check
mcplint cache stats              # Cache statistics
mcplint fingerprint generate <s> # Generate fingerprints
mcplint watch <server>           # Watch mode
mcplint multi-scan --all         # Multi-server scanning
```

## Architecture

```
src/
  main.rs              # CLI entry point
  lib.rs               # Library exports
  cli/
    mod.rs             # CLI configuration
    config.rs          # Configuration loading
    commands/          # Subcommand implementations
      validate.rs      # Protocol validation
      scan.rs          # Security scanning
      fuzz.rs          # Fuzzing
      explain.rs       # AI explanations
      cache.rs         # Cache management
      watch.rs         # File watching
      init.rs          # Config generation
      rules.rs         # List rules
      doctor.rs        # Environment check
      servers.rs       # List servers
      multi_scan.rs    # Multi-server scanning
  ai/                  # AI provider integration
    engine.rs          # ExplainEngine
    provider/          # Provider implementations
      anthropic.rs     # Claude API
      openai.rs        # GPT API
      ollama.rs        # Local Ollama
  cache/               # Caching system
    mod.rs             # CacheManager
    memory.rs          # In-memory backend
    filesystem.rs      # Filesystem backend
    redis.rs           # Redis backend (optional)
    rug_pull.rs        # Schema change detection
  scanner/             # Security scanner
    engine.rs          # ScanEngine
    finding.rs         # Finding, Severity
    multi_server.rs    # Multi-server parallel scanning
    rules/             # Detection rules
      tool_injection.rs
      tool_shadowing.rs
      schema_poisoning.rs
      unicode_hidden.rs
      oauth_abuse.rs   # OAuth scope abuse detection
  fingerprinting/      # Tool fingerprinting
    mod.rs             # Fingerprint generation
    comparator.rs      # Fingerprint comparison
    normalizer.rs      # Schema normalization
  fuzzer/              # Fuzzing framework
    session.rs         # FuzzSession
    corpus.rs          # CorpusManager
    mutation/          # Mutation strategies
  validator/           # Protocol validator
    engine.rs          # ValidationEngine
    rules.rs           # Validation rules (56 rules)
  transport/           # Transport layer
    stdio.rs           # Stdio transport
    sse.rs             # SSE transport
    streamable_http.rs # HTTP transport
  protocol/            # Protocol types
    jsonrpc.rs         # JSON-RPC types
    mcp.rs             # MCP types
  client/              # MCP client
  baseline/            # Baseline comparison
  reporter/            # Output formatters
    sarif.rs           # SARIF output
    junit.rs           # JUnit output
    gitlab.rs          # GitLab output
```

## Key Components

### Validation Rules (validator/rules.rs)

56 rules across 7 categories:
- PROTO-001 to PROTO-015: Protocol compliance
- SCHEMA-001 to SCHEMA-005: Schema validation
- SEQ-001 to SEQ-003: Sequence validation
- TOOL-001 to TOOL-005: Tool validation
- RES-001 to RES-003: Resource validation
- SEC-001 to SEC-015: Security checks (path traversal, injection, SSRF, XXE, template injection, prompt injection, tool shadowing)
- EDGE-001 to EDGE-010: Edge cases (null bytes, deep nesting, overflow, timeouts)

### Scanner Rules (scanner/rules/)

Detection rules for:
- Tool injection (prompt injection in tool descriptions)
- Tool shadowing (impersonating standard tools)
- Schema poisoning (malicious defaults in schemas)
- Unicode hidden characters
- OAuth scope abuse

### Transport Layer

- StdioTransport: Local servers via stdin/stdout
- SseTransport: Remote servers via SSE
- StreamableHttpTransport: MCP 2025 HTTP spec

Environment variables are passed to spawned processes from the config file.

### Cache System

Multi-backend caching:
- MemoryCache: In-process
- FilesystemCache: Persistent (default)
- RedisCache: Distributed (optional feature)

Categories with different TTLs: Schema, ScanResult, Validation, Corpus, ToolHash

## Configuration

MCPLint reads server configuration from Claude Desktop config:
- Windows: %APPDATA%/Claude/claude_desktop_config.json
- macOS: ~/Library/Application Support/Claude/claude_desktop_config.json
- Linux: ~/.config/Claude/claude_desktop_config.json

Project configuration via .mcplint.toml (generate with `mcplint init`).

## Environment Variables

```
ANTHROPIC_API_KEY     # For Claude models
OPENAI_API_KEY        # For GPT models
OLLAMA_BASE_URL       # For local Ollama (default: http://localhost:11434)
MCPLINT_CACHE_DIR     # Cache directory
MCPLINT_CACHE_BACKEND # Backend: filesystem, memory, redis
```

## Exit Codes

- 0: Success, no findings
- 1: Success, findings detected
- 2: Error
- 3: Partial success
- 4: Timeout

## Dependencies

Key crates:
- rmcp: MCP SDK
- clap: CLI parsing
- tokio: Async runtime
- serde/serde_json: Serialization
- reqwest: HTTP client
- tracing: Logging

## Test Coverage

Current statistics:
- **3,068 unique tests** (2,965 unit + 103 integration)
- Integration tests use live MCP servers (filesystem, memory)
- Run time: ~80 seconds for full suite

Test breakdown:
| Suite | Tests |
|-------|-------|
| Unit tests (lib.rs) | 2,965 |
| ai_integration | 26 |
| cache_integration | 13 |
| interactive_tests | 30 |
| server_integration | 34 |

Key module coverage:
- scanner/engine.rs: 93.8%
- transport/stdio.rs: 93.5%
- validator/rules.rs: 99.5%
- validator/engine.rs: 69.4%
- scanner/multi_server.rs: 100%
- fuzzer/session.rs: comprehensive unit tests
- baseline/store.rs: comprehensive unit tests

Run tests:
```bash
cargo test                        # Run all tests
cargo test -- --test-threads=1    # Sequential execution
cargo test scanner::              # Run scanner module tests only
```

## v0.2.0 CLI Features

### Smart Context Detection
- Auto-detects TTY, CI, and plain output modes
- Respects NO_COLOR environment variable
- Unicode/ASCII fallback based on terminal capabilities

### Progress Indicators
- Real-time progress bars for scan operations
- Connection spinners with phase tracking

### Enhanced Error Handling
- Miette-based diagnostic errors with source context
- "Did you mean?" suggestions using Jaro-Winkler similarity
- Contextual help for common errors

### Shell Completions
- Dynamic completions for bash, zsh, fish, PowerShell, elvish
- Server name completion from Claude Desktop config

### Watch Mode
- Differential display showing new/fixed issues
- Debounced file watching

## Multi-Server Scanning

Scan multiple MCP servers in parallel:

```bash
mcplint multi-scan --all --profile standard
mcplint multi-scan -s server1,server2 --format sarif
mcplint multi-scan --all --fail-on critical,high
```

Features:
- Parallel execution with configurable concurrency (-j flag)
- Combined SARIF output for CI/CD
- Aggregated statistics and severity counts
- Per-server timeout configuration

## Public API Reference

MCPLint exposes a library API for programmatic use. Key public types:

### Core Engines

```rust
// Scanner - Security vulnerability detection
use mcplint::{ScanEngine, ScanConfig, ScanResults, Finding, Severity};

let engine = ScanEngine::new(config);
let results: ScanResults = engine.scan(&tools).await?;
for finding in results.findings {
    println!("{}: {}", finding.severity, finding.title);
}

// Validator - Protocol compliance checking
use mcplint::{ValidationEngine, ValidationConfig, ValidationResults};

let engine = ValidationEngine::new(config);
let results: ValidationResults = engine.validate(&client).await?;

// Fuzzer - Coverage-guided fuzzing
use mcplint::fuzzer::{FuzzEngine, FuzzSession, FuzzResults, FuzzProfile};

let session = FuzzSession::new(config).await?;
let results: FuzzResults = session.run().await?;
```

### AI Explanation

```rust
use mcplint::ai::{AiConfig, ExplainEngine, AiProvider, AudienceLevel};

let config = AiConfig {
    provider: AiProvider::Ollama,
    model: Some("llama3.2".to_string()),
    audience: AudienceLevel::Intermediate,
    ..Default::default()
};
let engine = ExplainEngine::new(config, cache).await?;
let explanation = engine.explain(&finding).await?;
```

### Caching

```rust
use mcplint::cache::{CacheManager, CacheConfig, CacheBackend};

// Memory cache
let cache = CacheManager::memory();

// Filesystem cache (persistent)
let config = CacheConfig::default();
let cache = CacheManager::new(config).await?;

// Store/retrieve
cache.set_schema("server-hash", &tools).await?;
let cached: Option<Vec<Tool>> = cache.get_schema("server-hash").await?;
```

### Baseline Comparison

```rust
use mcplint::baseline::{Baseline, DiffEngine, DiffResult};

let baseline = Baseline::load("baseline.json")?;
let diff: DiffResult = DiffEngine::compare(&baseline, &current_findings);
println!("New: {}, Fixed: {}", diff.new.len(), diff.fixed.len());
```

### Fingerprinting

```rust
use mcplint::fingerprinting::{FingerprintHasher, FingerprintComparator, ToolFingerprint};

let fingerprint: ToolFingerprint = FingerprintHasher::fingerprint(&tool)?;
let diff = FingerprintComparator::compare(&old_fp, &new_fp);
if diff.is_breaking() {
    println!("Breaking change detected!");
}
```

### Transport Layer

```rust
use mcplint::transport::{Transport, TransportType, StdioTransport, detect_transport_type};

// Auto-detect transport
let transport_type = detect_transport_type("http://localhost:8080/mcp");

// Connect to server
let mut transport = StdioTransport::spawn(
    "node",
    &["server.js".to_string()],
    &env_vars,
    TransportConfig::default()
).await?;

// Send request
let response = transport.request("tools/list", None).await?;
```

### Scanner Profiles

```rust
use mcplint::scanner::ScanProfile;

// Quick: Fast checks, ~5 seconds
// Standard: Balanced (default), ~30 seconds
// Full: Comprehensive, ~2 minutes
// Enterprise: Maximum depth, ~5 minutes
let profile = ScanProfile::Standard;
```

### Finding Severities

```rust
use mcplint::scanner::Severity;

// Critical - Immediate exploitation risk
// High - Significant security impact
// Medium - Moderate risk
// Low - Minor issues
// Info - Informational findings
match finding.severity {
    Severity::Critical | Severity::High => panic!("Security issue!"),
    _ => {}
}
```

### Output Formats

```rust
use mcplint::cli::OutputFormat;
use mcplint::reporter::{SarifReporter, JunitReporter, GitlabReporter};

// Generate SARIF for GitHub Code Scanning
let sarif = SarifReporter::new().generate(&results)?;

// Generate JUnit for test runners
let junit = JunitReporter::new().generate(&results)?;
```

## Architecture Deep Dive

### Data Flow

```
User Command
    │
    ▼
┌─────────────────────────────────────────────────────────────────────┐
│  CLI Layer (src/cli/)                                               │
│  ├── commands/  - Subcommand implementations                        │
│  ├── config.rs  - Configuration loading & validation                │
│  └── interactive/ - TUI wizards for scan/fuzz/init/explain          │
└─────────────────────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Transport Layer (src/transport/)                                   │
│  ├── stdio.rs         - Spawn & communicate with local servers      │
│  ├── sse.rs           - SSE transport (MCP 2024-11 spec)           │
│  └── streamable_http.rs - HTTP transport (MCP 2025 spec)           │
└─────────────────────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Engine Layer                                                        │
│  ├── validator/  - Protocol compliance (56 rules)                   │
│  ├── scanner/    - Security vulnerability detection (20+ rules)    │
│  ├── fuzzer/     - Coverage-guided fuzzing with mutation strategies│
│  └── ai/         - AI-powered vulnerability explanations            │
└─────────────────────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Support Layer                                                       │
│  ├── cache/         - Multi-backend caching (memory/fs/redis)       │
│  ├── baseline/      - Diff comparison for CI/CD                     │
│  ├── fingerprinting/- Tool schema change detection                  │
│  └── reporter/      - SARIF, JUnit, GitLab, HTML output             │
└─────────────────────────────────────────────────────────────────────┘
```

### Module Responsibilities

| Module | Purpose | Key Types |
|--------|---------|-----------|
| `validator` | MCP protocol compliance checking | `ValidationEngine`, `ValidationResults` |
| `scanner` | Security vulnerability detection | `ScanEngine`, `Finding`, `Severity` |
| `fuzzer` | Coverage-guided fuzzing | `FuzzSession`, `FuzzResults`, `FuzzCrash` |
| `ai` | AI-powered explanations | `ExplainEngine`, `ExplanationResponse` |
| `cache` | Multi-backend caching | `CacheManager`, `CacheConfig` |
| `baseline` | Diff comparison | `Baseline`, `DiffEngine`, `DiffResult` |
| `fingerprinting` | Schema change detection | `FingerprintHasher`, `ToolFingerprint` |
| `transport` | Server communication | `Transport`, `StdioTransport` |
| `reporter` | Output formatting | `SarifReporter`, `JunitReporter` |
| `protocol` | MCP/JSON-RPC types | `Tool`, `Resource`, `JsonRpcMessage` |

### Security Rule Categories

| Prefix | Category | Example Rules |
|--------|----------|---------------|
| `SEC-INJ-*` | Injection | Command injection, SQL injection, path traversal |
| `SEC-AUTH-*` | Authentication | Credential exposure, OAuth abuse |
| `SEC-TRANS-*` | Transport | TLS/SSL security |
| `SEC-PROTO-*` | Protocol | Tool poisoning, shadowing, rug pull |
| `SEC-DATA-*` | Data | Data exposure, leakage |
| `SEC-DOS-*` | Availability | Denial of service |

### Validation Rule Categories

| Prefix | Category | Count | Description |
|--------|----------|-------|-------------|
| `PROTO-*` | Protocol | 15 | JSON-RPC 2.0 and MCP protocol compliance |
| `SCHEMA-*` | Schema | 5 | JSON Schema validation |
| `SEQ-*` | Sequence | 3 | Method call ordering |
| `TOOL-*` | Tool | 5 | Tool definition and invocation |
| `RES-*` | Resource | 3 | Resource listing and access |
| `SEC-*` | Security | 15 | Security vulnerability checks |
| `EDGE-*` | Edge | 10 | Boundary conditions and edge cases |
