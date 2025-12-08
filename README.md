# MCPLint

MCP Server Testing, Fuzzing, and Security Scanning Platform

## Overview

MCPLint is a comprehensive security and quality assurance tool for [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) servers. It provides:

- **Protocol Validation** - Verify MCP protocol compliance
- **Security Scanning** - Detect vulnerabilities like command injection, path traversal, SSRF
- **AI-Powered Explanations** - Get detailed explanations of findings with remediation guidance
- **Coverage-Guided Fuzzing** - Find crashes and edge cases with intelligent input generation
- **Baseline Comparison** - Track security changes between scans
- **Watch Mode** - Continuous scanning during development
- **CI/CD Integration** - SARIF, JUnit, and GitLab output formats

## Installation

```bash
cargo install mcplint
```

Or build from source:

```bash
git clone https://github.com/quanticsoul4772/mcplint
cd mcplint
cargo build --release
```

## Quick Start

```bash
# Validate protocol compliance
mcplint validate node my-mcp-server.js

# Run security scan
mcplint scan node my-mcp-server.js

# Get AI-powered explanations for findings
mcplint explain node my-mcp-server.js

# Fuzz for crashes
mcplint fuzz node my-mcp-server.js --duration 300

# Watch mode for continuous scanning
mcplint watch node my-mcp-server.js --watch ./src

# Generate config file
mcplint init

# List security rules
mcplint rules --details

# Check environment
mcplint doctor --extended

# Manage cache
mcplint cache stats
```

## Commands

### `validate`

Check MCP server for protocol compliance:

```bash
mcplint validate <server> [args...] [OPTIONS]

Options:
  -f, --features <FEATURES>  Check specific protocol features only
  -t, --timeout <TIMEOUT>    Timeout for server operations [default: 30]
```

### `scan`

Scan for security vulnerabilities:

```bash
mcplint scan <server> [args...] [OPTIONS]

Options:
  -p, --profile <PROFILE>       Security scan profile [default: standard]
                                [possible values: quick, standard, full, enterprise]
  -i, --include <INCLUDE>       Include specific rule categories
  -e, --exclude <EXCLUDE>       Exclude specific rule categories
  -t, --timeout <TIMEOUT>       Timeout for server operations [default: 60]
      --explain                 Generate AI-powered explanations for findings
      --ai-provider <PROVIDER>  AI provider for explanations [default: ollama]
                                [possible values: ollama, anthropic, openai]
      --ai-model <MODEL>        AI model for explanations
      --baseline <PATH>         Path to baseline file for comparison
      --save-baseline <PATH>    Save scan results as new baseline
      --update-baseline         Update existing baseline with current findings
      --diff-only               Show only diff summary (requires --baseline)
      --fail-on <SEVERITIES>    Fail only on specified severities (e.g., critical,high)
```

### `explain`

Get AI-powered explanations for security findings:

```bash
mcplint explain <server> [args...] [OPTIONS]

Options:
  -P, --provider <PROVIDER>     AI provider [default: ollama]
                                [possible values: ollama, anthropic, openai]
  -m, --model <MODEL>           AI model to use (defaults to provider's default)
  -a, --audience <LEVEL>        Audience level for explanations [default: intermediate]
                                [possible values: beginner, intermediate, expert]
  -s, --severity <SEVERITY>     Minimum severity to explain
  -n, --max-findings <N>        Maximum number of findings to explain
      --no-cache                Disable response caching
  -i, --interactive             Interactive mode (ask follow-up questions)
  -t, --timeout <TIMEOUT>       Timeout for server operations [default: 120]
```

**AI Provider Configuration:**

| Provider | Environment Variable | Default Model |
|----------|---------------------|---------------|
| Ollama | None (local) | llama3.2 |
| Anthropic | `ANTHROPIC_API_KEY` | claude-sonnet-4-20250514 |
| OpenAI | `OPENAI_API_KEY` | gpt-4o |

### `fuzz`

Run coverage-guided fuzzing:

```bash
mcplint fuzz <server> [args...] [OPTIONS]

Options:
  -d, --duration <DURATION>      Duration to run fuzzing (seconds) [default: 300]
  -c, --corpus <CORPUS>          Path to corpus directory for inputs
  -i, --iterations <ITERATIONS>  Maximum iterations [default: unlimited]
  -W, --workers <WORKERS>        Number of parallel workers [default: 4]
      --tools <TOOLS>            Focus on specific tools
  -p, --profile <PROFILE>        Fuzzing profile [default: standard]
                                 [possible values: quick, standard, intensive, ci]
      --seed <SEED>              Random seed for reproducibility

Resource Limits:
      --max-memory <SIZE>        Maximum memory usage (e.g., "512MB", "1GB")
      --max-time <TIME>          Maximum time limit (e.g., "5m", "1h")
      --max-corpus <N>           Maximum corpus size (number of entries)
      --max-restarts <N>         Maximum server restarts
      --no-limits                Disable all resource limits (use with caution)
```

### `watch`

Watch files and rescan on changes:

```bash
mcplint watch <server> [args...] [OPTIONS]

Options:
  -w, --watch <PATHS>         Paths to watch for changes [default: .]
  -p, --profile <PROFILE>     Security scan profile [default: quick]
  -d, --debounce <MS>         Debounce delay in milliseconds [default: 500]
  -c, --clear                 Clear screen before each scan
```

### `cache`

Manage cache storage:

```bash
mcplint cache <SUBCOMMAND>

Subcommands:
  stats   Show cache statistics [--json]
  clear   Clear cache entries [--category <CAT>] [--force]
  prune   Remove expired cache entries [--json]
  export  Export cache to file [--output <PATH>] [--category <CAT>]
  import  Import cache from file [--input <PATH>] [--merge]
  keys    List cache keys [--category <CAT>] [--json]

Categories: schemas, scan_results, validation, corpus, tool_hashes
```

### `init`

Generate a configuration file:

```bash
mcplint init [OPTIONS]

Options:
  -o, --output <PATH>   Output path for config file [default: .mcplint.toml]
      --force           Overwrite existing config
```

### `rules`

List available security rules:

```bash
mcplint rules [OPTIONS]

Options:
  -c, --category <CATEGORY>   Filter by category
  -d, --details               Show rule details
```

### `doctor`

Check MCPLint version and environment:

```bash
mcplint doctor [OPTIONS]

Options:
  -e, --extended    Run extended diagnostics
```

## Output Formats

MCPLint supports multiple output formats:

| Format | Flag | Use Case |
|--------|------|----------|
| `text` | `--format text` | Human-readable terminal output (default) |
| `json` | `--format json` | Machine-parseable JSON |
| `sarif` | `--format sarif` | SARIF 2.1.0 for GitHub Code Scanning |
| `junit` | `--format junit` | JUnit XML for test runners |
| `gitlab` | `--format gitlab` | GitLab Code Quality report |

```bash
mcplint scan server.js --format sarif > results.sarif
mcplint scan server.js --format junit > results.xml
```

## GitHub Actions Integration

```yaml
- name: MCPLint Security Scan
  run: |
    mcplint scan node ${{ github.workspace }}/mcp-server.js \
      --format sarif \
      --output mcplint-results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: mcplint-results.sarif
```

## Baseline Comparison

Track security changes between scans using baselines:

```bash
# Create initial baseline
mcplint scan server.js --save-baseline baseline.json

# Compare against baseline
mcplint scan server.js --baseline baseline.json

# Show only differences
mcplint scan server.js --baseline baseline.json --diff-only

# Update baseline with new findings
mcplint scan server.js --baseline baseline.json --update-baseline
```

## Security Rules

MCPLint includes 20+ security rules across 6 categories:

| Category | Rules | Description |
|----------|-------|-------------|
| `injection` | MCP-INJ-001 to 004, MCP-SEC-040, 044, 045 | Command injection, SQL injection, path traversal, SSRF, tool poisoning |
| `auth` | MCP-AUTH-001 to 003, MCP-SEC-043 | Authentication, authorization, credential exposure, OAuth scope abuse |
| `transport` | MCP-TRANS-001, 002 | TLS/SSL and transport security |
| `protocol` | MCP-PROTO-001 to 003, MCP-SEC-041, 042 | MCP protocol compliance, tool shadowing, rug pull detection |
| `data` | MCP-DATA-001, 002 | Data exposure and leakage |
| `dos` | MCP-DOS-001, 002 | Denial of service vulnerabilities |

### Advanced Security Rules (M6)

| Rule ID | Name | Severity |
|---------|------|----------|
| MCP-SEC-040 | Tool Description Injection | Critical |
| MCP-SEC-041 | Cross-Server Tool Shadowing | High |
| MCP-SEC-042 | Rug Pull Detection | Critical |
| MCP-SEC-043 | OAuth Scope Abuse | High |
| MCP-SEC-044 | Unicode Hidden Instructions | High |
| MCP-SEC-045 | Full-Schema Poisoning | High |

Run `mcplint rules --details` to see all available rules with descriptions.

## Configuration

Create `.mcplint.toml` in your project:

```bash
mcplint init
```

Example configuration:

```toml
[scan]
profile = "standard"
exclude = ["MCP-DOS-002"]
fail_on = ["critical", "high"]

[fuzz]
duration = 600
workers = 8
profile = "standard"

[fuzz.limits]
max_memory = "1GB"
max_time = "10m"
max_corpus = 10000

[ai]
provider = "ollama"
model = "llama3.2"

[watch]
debounce = 500
clear = true
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success, no findings |
| 1 | Success, findings detected |
| 2 | Error (connection failed, config invalid) |
| 3 | Partial success (some checks skipped) |
| 4 | Timeout exceeded |

## License

MIT License - see [LICENSE](LICENSE) for details.

## Contributing

Contributions welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) first.
