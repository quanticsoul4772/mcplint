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
- **3,540+ tests** across lib, bin, and integration test suites
- **68.7% code coverage** (8,360/12,166 lines)
- Integration tests use live MCP servers (filesystem, memory)

Key module coverage:
- scanner/engine.rs: 93.8%
- transport/stdio.rs: 93.5%
- validator/rules.rs: 99.5%
- validator/engine.rs: 69.4%

Run coverage:
```bash
cargo tarpaulin --lib --test server_integration --out Stdout
```
