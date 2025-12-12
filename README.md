# MCPLint

[![Crates.io](https://img.shields.io/crates/v/mcplint.svg)](https://crates.io/crates/mcplint)
[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/quanticsoul4772/mcplint/actions/workflows/ci.yml/badge.svg)](https://github.com/quanticsoul4772/mcplint/actions/workflows/ci.yml)

Security testing tool for Model Context Protocol (MCP) servers.

## Features

- Protocol validation - verify MCP compliance
- Security scanning - detect vulnerabilities
- Coverage-guided fuzzing - find crashes and edge cases
- Tool fingerprinting - detect schema changes and breaking API updates
- AI-powered explanations - understand findings with remediation guidance
- CI/CD integration - SARIF, JUnit, GitLab output formats
- Config file support - reads Claude Desktop config to find servers

## Installation

```bash
cargo install --path .
```

Or build from source:

```bash
cargo build --release
./target/release/mcplint --help
```

## Usage

```bash
# List servers from Claude Desktop config
mcplint servers

# Validate a server
mcplint validate <server>
mcplint validate filesystem
mcplint validate                    # validates all servers from config

# Security scan
mcplint scan <server>

# Fuzz a server
mcplint fuzz <server>

# AI-powered explanations
mcplint explain <server>

# Watch mode
mcplint watch <server>

# List security rules
mcplint rules
mcplint rules --details

# Environment check
mcplint doctor

# Cache management
mcplint cache stats
mcplint cache clear

# Tool fingerprinting
mcplint fingerprint generate <server>
mcplint fingerprint compare <server> --baseline baseline.json

# Generate config
mcplint init
```

## Commands

### validate

Check MCP server for protocol compliance. Runs 56 validation rules across protocol, schema, sequence, tool, resource, security, and edge case categories.

```bash
mcplint validate <server> [options]

Options:
  -t, --timeout <seconds>    Timeout for server operations [default: 30]
  -f, --format <format>      Output format: text, json, sarif, junit, gitlab
  -c, --config <path>        Path to MCP config file
```

### scan

Scan for security vulnerabilities.

```bash
mcplint scan <server> [options]

Options:
  -p, --profile <profile>    Scan profile: quick, standard, full, enterprise
  -i, --include <rules>      Include specific rule categories
  -e, --exclude <rules>      Exclude specific rule categories
  -t, --timeout <seconds>    Timeout [default: 60]
  --baseline <path>          Compare against baseline file
  --save-baseline <path>     Save results as baseline
  --fail-on <severities>     Fail only on specified severities
```

### fuzz

Coverage-guided fuzzing.

```bash
mcplint fuzz <server> [options]

Options:
  -d, --duration <seconds>   Duration to run [default: 300]
  -c, --corpus <path>        Corpus directory
  -W, --workers <count>      Parallel workers [default: 4]
  --max-memory <size>        Memory limit (e.g., 512MB)
  --max-time <time>          Time limit (e.g., 5m)
```

### explain

AI-powered explanations for security findings.

```bash
mcplint explain <server> [options]

Options:
  -P, --provider <provider>  AI provider: ollama, anthropic, openai [default: ollama]
  -m, --model <model>        Model to use
  -a, --audience <level>     Audience: beginner, intermediate, expert
  -n, --max-findings <n>     Max findings to explain
```

AI providers require environment variables:
- Anthropic: ANTHROPIC_API_KEY
- OpenAI: OPENAI_API_KEY
- Ollama: runs locally, no key needed

### fingerprint

Generate and compare tool definition fingerprints to detect schema changes.

```bash
# Generate fingerprints
mcplint fingerprint generate <server> [options]

Options:
  -o, --output <path>        Save fingerprints to file
  -t, --timeout <seconds>    Timeout [default: 30]
  -f, --format <format>      Output format: text, json

# Compare against baseline
mcplint fingerprint compare <server> --baseline <path> [options]

Options:
  -b, --baseline <path>      Baseline file for comparison (required)
  -t, --timeout <seconds>    Timeout [default: 30]
```

Exit codes for compare:
- 0: No changes or minor/patch changes
- 1: Breaking changes detected
- 2: Major changes detected

See [docs/fingerprinting.md](docs/fingerprinting.md) for detailed documentation.

### servers

List MCP servers from Claude Desktop config.

```bash
mcplint servers
```

### cache

Manage cache storage.

```bash
mcplint cache stats          # show statistics
mcplint cache clear          # clear all entries
mcplint cache prune          # remove expired entries
mcplint cache keys           # list cache keys
mcplint cache export -o f    # export to file
mcplint cache import -i f    # import from file
```

## Validation Rules

56 rules across 7 categories:

| Category | Rules | Description |
|----------|-------|-------------|
| Protocol | PROTO-001 to PROTO-015 | JSON-RPC 2.0 compliance, MCP version |
| Schema | SCHEMA-001 to SCHEMA-005 | JSON Schema validation |
| Sequence | SEQ-001 to SEQ-003 | Method call sequences |
| Tool | TOOL-001 to TOOL-005 | Tool invocation |
| Resource | RES-001 to RES-003 | Resource listing and reading |
| Security | SEC-001 to SEC-015 | Path traversal, injection, SSRF, XXE, template injection, prompt injection, tool shadowing |
| Edge | EDGE-001 to EDGE-010 | Null bytes, deep nesting, overflow, timeouts |

Run `mcplint rules --details` to see all rules.

## Security Rules (Scanner)

20+ rules for vulnerability detection:

| Category | Description |
|----------|-------------|
| injection | Command injection, SQL injection, path traversal, SSRF |
| auth | Authentication, credential exposure, OAuth scope abuse |
| transport | TLS/SSL security |
| protocol | Tool poisoning, shadowing, rug pull detection |
| data | Data exposure |
| dos | Denial of service |

## Output Formats

| Format | Flag | Use |
|--------|------|-----|
| text | --format text | Terminal output (default) |
| json | --format json | Machine-parseable |
| sarif | --format sarif | GitHub Code Scanning |
| junit | --format junit | Test runners |
| gitlab | --format gitlab | GitLab Code Quality |

## Configuration

Create `.mcplint.toml`:

```bash
mcplint init
```

Example:

```toml
[scan]
profile = "standard"
exclude = ["MCP-DOS-002"]
fail_on = ["critical", "high"]

[fuzz]
duration = 600
workers = 8

[ai]
provider = "ollama"
model = "llama3.2"
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success, no findings |
| 1 | Success, findings detected |
| 2 | Error |
| 3 | Partial success |
| 4 | Timeout |

## License

MIT
