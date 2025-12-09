# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

MCPLint is a Rust-based security testing tool for Model Context Protocol (MCP) servers. It provides protocol validation, security vulnerability scanning, coverage-guided fuzzing, AI-assisted vulnerability explanation, and multi-backend caching with SARIF output for CI/CD integration.

## Build and Development Commands

```bash
# Build
cargo build              # Debug build
cargo build --release    # Release build (with LTO)

# Run
cargo run -- <command>   # Run with arguments
cargo run -- validate node my-server.js
cargo run -- scan node my-server.js
cargo run -- fuzz node my-server.js --duration 60
cargo run -- explain <finding-id>
cargo run -- cache stats
cargo run -- rules --details
cargo run -- doctor --extended
cargo run -- init

# Test
cargo test               # Run all tests
cargo test <test_name>   # Run specific test
cargo test -- --nocapture  # Show test output

# Lint and Format
cargo clippy             # Lint
cargo fmt                # Format code
cargo fmt -- --check     # Check formatting without modifying
```

## Architecture

```
src/
├── main.rs              # CLI entry point, command routing
├── lib.rs               # Library exports and re-exports
├── cli/
│   ├── mod.rs           # CLI configuration
│   ├── config.rs        # Configuration loading
│   └── commands/        # Subcommand implementations
│       ├── validate.rs  # Protocol compliance validation
│       ├── scan.rs      # Security vulnerability scanning
│       ├── fuzz.rs      # Coverage-guided fuzzing
│       ├── explain.rs   # AI-assisted explanation
│       ├── cache.rs     # Cache management
│       ├── watch.rs     # File watching mode
│       ├── init.rs      # Config file generation
│       ├── rules.rs     # List security rules
│       └── doctor.rs    # Environment diagnostics
├── ai/                  # M5: AI-Assisted Explanation
│   ├── mod.rs           # Module exports
│   ├── config.rs        # AI configuration (provider, model, audience)
│   ├── engine.rs        # ExplainEngine - main orchestration
│   ├── prompt.rs        # PromptBuilder - structured prompts
│   ├── response.rs      # ExplanationResponse, VulnerabilityExplanation
│   ├── rate_limit.rs    # Token bucket rate limiter
│   ├── streaming.rs     # Streaming response handling
│   └── provider/        # AI provider implementations
│       ├── mod.rs       # AiProvider trait
│       ├── anthropic.rs # Claude API integration
│       ├── openai.rs    # GPT API integration
│       ├── ollama.rs    # Local Ollama integration
│       └── mock.rs      # Mock provider for testing
├── cache/               # M4: Caching System
│   ├── mod.rs           # CacheManager - unified interface
│   ├── backend.rs       # Cache trait and CacheConfig
│   ├── entry.rs         # CacheEntry with TTL
│   ├── key.rs           # CacheKey and CacheCategory
│   ├── memory.rs        # In-memory cache backend
│   ├── filesystem.rs    # Filesystem cache backend
│   ├── redis.rs         # Redis cache backend (optional)
│   ├── rug_pull.rs      # Tool schema change detection
│   └── stats.rs         # CacheStats tracking
├── scanner/             # M2: Security Scanner
│   ├── mod.rs           # ScanResults, output formatting
│   ├── engine.rs        # ScanEngine - main scanner
│   ├── context.rs       # ScanConfig, ScanProfile
│   ├── finding.rs       # Finding, Severity, Evidence
│   ├── results.rs       # ScanResults, ScanSummary
│   ├── helpers.rs       # Utility functions
│   ├── checks/          # Security check implementations
│   │   ├── injection.rs # Injection vulnerability checks
│   │   ├── auth.rs      # Authentication checks
│   │   ├── transport.rs # Transport security checks
│   │   ├── protocol.rs  # Protocol compliance checks
│   │   ├── data.rs      # Data handling checks
│   │   └── dos.rs       # DoS vulnerability checks
│   └── rules/           # Security rule definitions
│       ├── tool_injection.rs
│       ├── tool_shadowing.rs
│       ├── schema_poisoning.rs
│       ├── oauth_abuse.rs
│       └── unicode_hidden.rs
├── fuzzer/              # M3: Coverage-Guided Fuzzing
│   ├── mod.rs           # FuzzResults, FuzzCrash
│   ├── config.rs        # FuzzConfig, FuzzProfile
│   ├── session.rs       # FuzzSession - manages fuzzing
│   ├── corpus.rs        # CorpusManager - seed management
│   ├── coverage.rs      # CoverageStats, CoverageTracker
│   ├── detection.rs     # CrashDetector, CrashAnalysis
│   ├── input.rs         # FuzzInput generation
│   ├── limits.rs        # ResourceLimits, ResourceMonitor
│   └── mutation/        # Input mutation strategies
│       ├── mod.rs       # MutationEngine
│       ├── strategy.rs  # MutationStrategy trait
│       ├── json.rs      # JSON mutation operators
│       ├── jsonrpc.rs   # JSON-RPC specific mutations
│       ├── mcp.rs       # MCP protocol mutations
│       └── dictionary.rs # Dictionary-based mutations
├── validator/           # M1: Protocol Validator
│   ├── mod.rs           # ValidationEngine exports
│   ├── engine.rs        # ValidationEngine implementation
│   └── rules.rs         # Validation rule definitions
├── transport/           # Transport layer
│   ├── mod.rs           # Transport trait
│   ├── stdio.rs         # Stdio transport (local servers)
│   ├── sse.rs           # SSE transport (remote servers)
│   ├── streamable_http.rs # HTTP transport (MCP 2025)
│   └── mock.rs          # Mock transport for testing
├── protocol/            # Protocol definitions
│   ├── mod.rs           # Protocol exports
│   ├── jsonrpc.rs       # JSON-RPC types
│   ├── mcp.rs           # MCP protocol types
│   └── state.rs         # Protocol state machine
├── client/              # MCP client
│   ├── mod.rs           # Client exports
│   └── mock.rs          # MockMcpClient for testing
├── baseline/            # Baseline/diff mode
│   ├── mod.rs           # Baseline, DiffEngine
│   ├── store.rs         # Baseline storage
│   ├── fingerprint.rs   # Finding fingerprinting
│   └── diff.rs          # DiffResult, comparison logic
├── reporter/            # Output formatters
│   ├── mod.rs           # Reporter trait
│   ├── sarif.rs         # SARIF 2.1.0 output
│   ├── junit.rs         # JUnit XML output
│   ├── html.rs          # HTML report output
│   └── gitlab.rs        # GitLab code quality format
└── rules/
    └── mod.rs           # Security rule registry
```

## Key Abstractions

### Transport Layer (`transport/`)
Async trait for MCP server communication:
- `Transport` trait with `request()`, `notify()`, `close()` methods
- `StdioTransport` - local server via stdin/stdout
- `SseTransport` - remote server via SSE
- `StreamableHttpTransport` - MCP 2025 HTTP spec

### AI Explanation Engine (`ai/`)
Multi-provider AI integration for vulnerability explanation:
- `AiProvider` trait - common interface for all AI providers
- `AnthropicProvider` - Claude API (claude-3-haiku, claude-3-sonnet)
- `OpenAiProvider` - GPT API (gpt-4o-mini, gpt-4o)
- `OllamaProvider` - Local models (llama3.2, codellama)
- `ExplainEngine` - orchestrates explanations with caching and rate limiting

### Cache System (`cache/`)
Multi-backend caching with rug-pull detection:
- `Cache` trait - common interface for all backends
- `MemoryCache` - ephemeral, fast, in-process
- `FilesystemCache` - persistent, default backend
- `RedisCache` - distributed, scalable (optional feature)
- `CacheManager` - unified interface with category-based TTL
- `detect_rug_pull()` - detects schema changes between scans

### Scanner (`scanner/`)
Pattern-based security vulnerability detection:
- `ScanEngine` - main scanner with profile support
- `Finding` - represents a security issue
- `Severity` - Critical, High, Medium, Low, Info
- Security checks organized by category

### Fuzzer (`fuzzer/`)
Coverage-guided fuzzing framework:
- `FuzzSession` - manages fuzzing execution
- `MutationEngine` - generates mutated inputs
- `CorpusManager` - tracks seeds and crashes
- `CrashDetector` - classifies crash types
- `ResourceMonitor` - enforces resource limits

### Output Formats
All result types implement multiple output methods:
- `print_text()` - colored terminal output
- `print_json()` - JSON for programmatic use
- `print_sarif()` - SARIF 2.1.0 for CI/CD integration

## Scan Profiles

The scanner supports four profiles with increasing depth:
- `quick` - Essential rules only, fastest execution
- `standard` - Default security scan, balanced coverage
- `full` - Comprehensive including experimental rules
- `enterprise` - Compliance-focused with all checks

## Cache Categories

Cache entries are organized by category with different TTLs:
- `Schema` - Tool/resource schemas (1 hour)
- `ScanResult` - Scan findings (30 minutes)
- `Validation` - Protocol validation results (30 minutes)
- `Corpus` - Fuzzer corpus data (1 week)
- `ToolHash` - Tool hashes for rug-pull detection (24 hours)

## Dependencies

Key crates:
- `rmcp` - MCP SDK for client communication
- `clap` - CLI argument parsing with derive macros
- `tokio` - Async runtime
- `serde/serde_json` - Serialization
- `tracing` - Logging infrastructure
- `reqwest` - HTTP client for AI providers
- `colored` - Terminal output coloring

## Configuration

MCPLint uses `.mcplint.toml` for configuration. Generate a template with:

```bash
cargo run -- init
```

### Environment Variables

```bash
# AI Provider API Keys
ANTHROPIC_API_KEY=sk-ant-...  # For Claude models
OPENAI_API_KEY=sk-...         # For GPT models
OLLAMA_BASE_URL=http://localhost:11434  # For local Ollama

# Cache Configuration
MCPLINT_CACHE_DIR=~/.mcplint/cache
MCPLINT_CACHE_BACKEND=filesystem  # filesystem, memory, redis
```

## Exit Codes

- 0: Success, no findings
- 1: Success, findings detected
- 2: Error (connection failed, config invalid)
- 3: Partial success (some checks skipped)
- 4: Timeout exceeded

## Testing

```bash
# Run all tests
cargo test

# Run specific test modules
cargo test scanner::          # Scanner tests
cargo test fuzzer::           # Fuzzer tests
cargo test cache::            # Cache tests
cargo test ai::               # AI module tests

# Run integration tests
cargo test --test ai_integration    # AI provider integration
cargo test --test cache_integration # Cache backend integration

# Run with output visible
cargo test -- --nocapture
```
