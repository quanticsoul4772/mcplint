# MCPLint

[![Crates.io](https://img.shields.io/crates/v/mcplint.svg)](https://crates.io/crates/mcplint)
[![Rust](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/quanticsoul4772/mcplint/actions/workflows/ci.yml/badge.svg)](https://github.com/quanticsoul4772/mcplint/actions/workflows/ci.yml)
[![Tests](https://img.shields.io/badge/tests-3066%20passing-brightgreen.svg)](https://github.com/quanticsoul4772/mcplint)

Security testing tool for Model Context Protocol (MCP) servers.

## Features

- **Protocol validation** - verify MCP compliance with 56 validation rules
- **Security scanning** - detect vulnerabilities with 20+ detection rules
- **Multi-server scanning** - parallel scanning with aggregated results
- **Coverage-guided fuzzing** - find crashes and edge cases
- **Tool fingerprinting** - detect schema changes and breaking API updates
- **AI-powered explanations** - understand findings with remediation guidance
- **Advanced prompt engineering** - chain-of-thought reasoning with few-shot examples
- **Neo4j knowledge graph** - vector similarity search for related vulnerabilities (optional)
- **Watch mode** - differential display showing new/fixed issues
- **Shell completions** - bash, zsh, fish, PowerShell, elvish
- **CI/CD integration** - SARIF, JUnit, GitLab output formats
- **Smart context detection** - auto-detects TTY, CI, NO_COLOR modes
- **Config file support** - reads Claude Desktop config to find servers
- **Interactive mode** - guided wizards for scan, fuzz, and init commands

## Interactive Mode

MCPLint includes interactive wizards that guide you through common operations when running in a terminal. Interactive mode automatically activates when:

- Running in a TTY (terminal)
- Not in a CI environment
- Command arguments are omitted

### Scan Wizard

Run `mcplint scan` without arguments to launch the scan wizard:

```bash
mcplint scan
# Prompts for:
# - Server selection (from configured servers)
# - Scan profile (quick/standard/full/enterprise)
# - Categories to include
# - Output format
# - Severity threshold for failure
```

### Fuzz Wizard

Run `mcplint fuzz` without arguments:

```bash
mcplint fuzz
# Prompts for:
# - Server selection
# - Fuzz profile (quick/standard/intensive/CI)
# - Duration
# - Number of workers
# - Corpus directory
```

### Init Wizard

Run `mcplint init` to generate configuration with guidance:

```bash
mcplint init
# Prompts for:
# - Output path
# - Servers to test
# - Default scan profile
# - Create GitHub Actions workflow
# - Run initial scan
```

### Explain Wizard

Run `mcplint explain` without arguments to get AI-powered explanations:

```bash
mcplint explain
# Prompts for:
# - Server selection
# - AI provider (Ollama/Anthropic/OpenAI)
# - Audience level (beginner/intermediate/expert)
# - Severity filter (optional)
# - Max findings to explain
# - Enable interactive follow-up Q&A
```

Interactive mode is disabled in CI environments or when piping output. Use explicit arguments for non-interactive execution.

## Installation

```bash
# From crates.io
cargo install mcplint

# From source
cargo install --path .

# With optional Neo4j knowledge graph support
cargo install mcplint --features neo4j

# Or build manually
cargo build --release
./target/release/mcplint --help
```

### Optional Features

| Feature | Description | Install |
|---------|-------------|---------|
| `neo4j` | Neo4j knowledge graph for vulnerability similarity search | `--features neo4j` |
| `redis` | Redis distributed cache backend | `--features redis` |

## Quick Start

```bash
# List servers from Claude Desktop config
mcplint servers

# Validate a server
mcplint validate <server>

# Security scan
mcplint scan <server>

# Scan all servers in parallel
mcplint multi-scan --all

# Watch mode with differential display
mcplint watch <server>
```

## Commands

```bash
# Core commands
mcplint validate <server>            # Validate protocol compliance
mcplint scan <server>                # Security scan
mcplint multi-scan --all             # Parallel multi-server scan
mcplint fuzz <server>                # Coverage-guided fuzzing
mcplint explain <server>             # AI-powered explanations
mcplint watch <server>               # Watch mode with live diffs

# Utility commands
mcplint servers                      # List configured servers
mcplint rules --details              # List all security rules
mcplint doctor                       # Environment check
mcplint fingerprint generate <s>     # Generate tool fingerprints
mcplint cache stats                  # Cache statistics
mcplint completions <shell>          # Generate shell completions
mcplint how-do-i <query>             # Contextual help
mcplint init                         # Generate config file
```

## Command Reference

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
  --update-baseline          Update existing baseline
  --diff-only                Show only diff summary
  --fail-on <severities>     Fail only on specified severities
  --explain                  Generate AI-powered explanations
  --ai-provider <provider>   AI provider for explanations
```

### multi-scan

Scan multiple MCP servers in parallel.

```bash
mcplint multi-scan [options]

Options:
  -s, --servers <list>       Server names (comma-separated)
  --all                      Scan all configured servers
  -j, --concurrency <n>      Maximum concurrent scans [default: 4]
  -p, --profile <profile>    Scan profile for all servers
  -t, --timeout <seconds>    Timeout per server [default: 60]
  --fail-on <severities>     Fail only on specified severities
  -f, --format <format>      Output format (sarif for CI/CD)

# Examples
mcplint multi-scan --all --profile standard
mcplint multi-scan -s server1,server2 --format sarif
mcplint multi-scan --all --fail-on critical,high
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

### watch

Watch files and rescan on changes with differential display.

```bash
mcplint watch <server> [options]

Options:
  -w, --watch <path>         Paths to watch [default: .]
  -p, --profile <profile>    Scan profile [default: quick]
  -d, --debounce <ms>        Debounce delay [default: 500]
  -c, --clear                Clear screen before each scan

# Shows differential output:
# ❌ NEW ISSUES - newly detected vulnerabilities
# ✅ FIXED - previously detected issues now resolved
```

### completions

Generate shell completions with server name support.

```bash
mcplint completions <shell>

Shells: bash, zsh, fish, powershell, elvish

# Installation examples
mcplint completions bash >> ~/.bashrc
mcplint completions zsh >> ~/.zshrc
mcplint completions fish > ~/.config/fish/completions/mcplint.fish
mcplint completions powershell >> $PROFILE
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
| html | --format html | Rich HTML reports with charts |

### HTML Reports

Generate visual HTML reports with severity charts and detailed findings:

```bash
mcplint scan <server> --format html > report.html
```

HTML reports include:
- Severity distribution pie chart
- Finding cards with details
- Remediation guidance
- Responsive design for viewing on any device

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
