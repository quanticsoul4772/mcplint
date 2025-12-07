# MCPLint

MCP Server Testing, Fuzzing, and Security Scanning Platform

## Overview

MCPLint is a comprehensive security and quality assurance tool for [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) servers. It provides:

- **Protocol Validation** - Verify MCP protocol compliance
- **Security Scanning** - Detect vulnerabilities like command injection, path traversal, SSRF
- **Coverage-Guided Fuzzing** - Find crashes and edge cases with intelligent input generation
- **CI/CD Integration** - SARIF output for GitHub Code Scanning

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

# Fuzz for crashes
mcplint fuzz node my-mcp-server.js --duration 300

# Generate config file
mcplint init

# List security rules
mcplint rules --verbose

# Check environment
mcplint doctor --extended
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
  -p, --profile <PROFILE>    Security scan profile [default: standard]
                             [possible values: quick, standard, full, enterprise]
  -i, --include <INCLUDE>    Include specific rule categories
  -e, --exclude <EXCLUDE>    Exclude specific rule categories
  -t, --timeout <TIMEOUT>    Timeout for server operations [default: 60]
```

### `fuzz`

Run coverage-guided fuzzing:

```bash
mcplint fuzz <server> [args...] [OPTIONS]

Options:
  -d, --duration <DURATION>    Duration to run fuzzing (seconds) [default: 300]
  -c, --corpus <CORPUS>        Path to corpus directory for inputs
  -i, --iterations <ITERATIONS> Maximum iterations [default: unlimited]
  -w, --workers <WORKERS>      Number of parallel workers [default: 4]
      --tools <TOOLS>          Focus on specific tools
```

## Output Formats

MCPLint supports multiple output formats:

- `text` (default) - Human-readable terminal output
- `json` - Machine-parseable JSON
- `sarif` - SARIF 2.1.0 for GitHub Code Scanning

```bash
mcplint scan server.js --format sarif > results.sarif
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

## Security Rules

MCPLint includes rules for:

| Category | Description |
|----------|-------------|
| `injection` | Command injection, SQL injection, path traversal, SSRF |
| `auth` | Authentication and authorization issues |
| `transport` | TLS/SSL and transport security |
| `protocol` | MCP protocol compliance issues |
| `data` | Data exposure and leakage |
| `dos` | Denial of service vulnerabilities |

Run `mcplint rules --verbose` to see all available rules.

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

[fuzz]
duration = 600
workers = 8
```

## License

MIT License - see [LICENSE](LICENSE) for details.

## Contributing

Contributions welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) first.
