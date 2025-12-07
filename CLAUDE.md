# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

MCPLint is a Rust-based security testing tool for Model Context Protocol (MCP) servers. It provides protocol validation, security vulnerability scanning, and coverage-guided fuzzing capabilities with SARIF output for CI/CD integration.

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
├── cli/
│   ├── mod.rs
│   └── commands/        # Subcommand implementations
│       ├── validate.rs  # Protocol compliance validation
│       ├── scan.rs      # Security vulnerability scanning
│       ├── fuzz.rs      # Coverage-guided fuzzing
│       ├── init.rs      # Config file generation
│       ├── rules.rs     # List security rules
│       └── doctor.rs    # Environment diagnostics
├── transport/
│   ├── mod.rs           # Transport trait definition
│   ├── stdio.rs         # stdio transport for local servers
│   └── sse.rs           # SSE transport for remote servers
├── validator/
│   └── mod.rs           # Protocol compliance checker
├── scanner/
│   └── mod.rs           # Security vulnerability scanner
├── fuzzer/
│   └── mod.rs           # Fuzz engine with coverage tracking
├── rules/
│   └── mod.rs           # Security rule registry (MCP-INJ-*, MCP-AUTH-*, etc.)
└── reporter/
    ├── mod.rs           # Report trait and wrapper
    └── sarif.rs         # SARIF 2.1.0 output format
```

### Key Abstractions

- **Transport trait** (`transport/mod.rs`): Async trait for MCP server communication with `request()`, `notify()`, and `close()` methods. Implementations handle stdio (local) and SSE (remote) transports.

- **Rule Registry** (`rules/mod.rs`): Static registry of security rules organized by category (injection, auth, transport, protocol, data, dos). Each rule has an ID pattern like `MCP-<CATEGORY>-###`.

- **Output Formats**: All result types (ValidationResults, ScanFindings, FuzzResults) implement `print_text()`, `print_json()`, and `print_sarif()` methods.

### Scan Profiles

The scanner supports four profiles with increasing depth:
- `quick` - Essential rules only
- `standard` - Default security scan
- `full` - Comprehensive including experimental rules
- `enterprise` - Compliance-focused

## Dependencies

Key crates:
- `rmcp` - MCP SDK for client communication
- `clap` - CLI argument parsing with derive macros
- `tokio` - Async runtime
- `serde/serde_json` - Serialization
- `tracing` - Logging infrastructure

## Configuration

MCPLint uses `.mcplint.toml` for configuration. Generate a template with:

```bash
cargo run -- init
```

## Exit Codes

- 0: Success, no findings
- 1: Success, findings detected
- 2: Error (connection failed, config invalid)
- 3: Partial success (some checks skipped)
- 4: Timeout exceeded
