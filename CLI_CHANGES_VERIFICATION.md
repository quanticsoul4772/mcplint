# CLI Changes Verification Plan

## Overview

This document outlines the verification plan for the new CLI features introduced in commit `0942d0a`:
- **Watch Mode Differential Display**
- **Enhanced SARIF Output**
- **CI Integration Examples**

## New Features Summary

### 1. Watch Mode Differential Display

**Key Components:**
- `ResultsDiff` struct for comparing scan results
- Fingerprint-based comparison (ignores UUID differences)
- Colored output: ❌ Red for new issues, ✅ Green for fixed issues
- Summary display showing current state

**Files Modified:**
- `src/cli/commands/watch.rs` (+484 lines)
- Added `ResultsDiff` struct with comprehensive testing
- Enhanced display logic with differential comparison

### 2. Enhanced SARIF Output

**Key Components:**
- `SarifReport::from_scan_results()` method
- SARIF 2.1.0 compliant output
- Proper severity mapping (Critical→Error, High→Error, Medium→Warning, etc.)
- Rule deduplication with help text and remediation guidance

**Files Modified:**
- `src/reporter/sarif.rs` (+224 lines)
- Added conversion from scan results to SARIF format
- Comprehensive rule and result generation

### 3. CI Integration Examples

**Files Added:**
- `examples/ci/github-actions-mcp-scan.yml` (200 lines)
- `examples/ci/github-actions-simple.yml` (40 lines)
- `examples/ci/README.md` (160 lines)

## Verification Strategy

### Phase 1: Unit Testing

**Test Coverage:**
```rust
// ResultsDiff tests (all should pass)
#[test] fn diff_empty_results_has_no_changes()
#[test] fn diff_detects_new_findings()
#[test] fn diff_detects_fixed_findings()
#[test] fn diff_detects_unchanged_findings()
#[test] fn diff_handles_mixed_changes()
#[test] fn diff_ignores_finding_id_differences()
#[test] fn diff_treats_different_locations_as_different_findings()
#[test] fn diff_treats_different_titles_as_different_findings()
#[test] fn fingerprint_is_consistent()
#[test] fn diff_multiple_findings_same_rule()
```

**Expected Results:**
- ✅ All diff tests pass
- ✅ Fingerprint consistency verified
- ✅ Edge cases handled correctly

### Phase 2: Integration Testing

**Test Scenarios:**

1. **Basic Watch Mode:**
   ```bash
   cargo run -- watch --server "test_server" --profile quick
   ```
   - Should start watch mode
   - Should trigger scan on file changes
   - Should display results

2. **Differential Display:**
   ```bash
   # First scan (baseline)
   cargo run -- watch --server "vulnerable_server"
   
   # Modify server to fix issues
   # Second scan should show:
   # - ✅ Green: Fixed findings
   # - ❌ Red: New findings  
   # - Summary: Current state
   ```

3. **SARIF Output:**
   ```bash
   cargo run -- scan --server "test_server" --format sarif --output results.sarif
   
   # Validate SARIF structure
   jq '.runs[0].tool.driver.name' results.sarif  # Should show "MCPLint"
   jq '.runs[0].results[0].level' results.sarif   # Should show "error"|"warning"|"note"
   ```

### Phase 3: CI Workflow Testing

**Validation:**
```bash
# Check YAML syntax
cd examples/ci
yaml-lint github-actions-*.yml

# Check GitHub Actions syntax
act --validate github-actions-simple.yml
act --validate github-actions-mcp-scan.yml
```

**Expected Results:**
- ✅ Valid YAML syntax
- ✅ Proper GitHub Actions structure
- ✅ All required fields present

## Test Data Preparation

### Test Servers Setup

```bash
# Create test servers with known vulnerabilities
mkdir -p test_servers/

# Server with injection vulnerability
cat > test_servers/injection_server.js << 'EOF'
const { createServer } = require('@modelcontextprotocol/server-memory');

const server = createServer({
  tools: [{
    name: "vulnerable_tool",
    description: "Tool with injection",
    execute: (params) => {
      // Vulnerable to command injection
      const result = eval(params.command);
      return { result };
    }
  }]
});

server.listen(3001);
EOF

# Server with fixed vulnerability
cat > test_servers/fixed_server.js << 'EOF'
const { createServer } = require('@modelcontextprotocol/server-memory');

const server = createServer({
  tools: [{
    name: "safe_tool",
    description: "Tool without injection",
    execute: (params) => {
      // Safe implementation
      return { result: "safe" };
    }
  }]
});

server.listen(3002);
EOF
```

### Baseline Files

```bash
# Empty baseline
echo '{"findings": [], "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}}' > baseline_empty.json

# Baseline with known issues
cp test_results.json baseline_with_issues.json
```

## Verification Checklist

### Watch Mode Differential Display

| Test | Command | Expected Result | Status |
|------|---------|-----------------|--------|
| Help text | `cargo run -- watch --help` | Shows new diff options | ❌ |
| Basic execution | `cargo run -- watch --server test_server` | Runs without errors | ❌ |
| Empty diff | First scan on clean server | No changes shown | ❌ |
| New findings | Scan server with vulnerabilities | ❌ Red output for new issues | ❌ |
| Fixed findings | Scan after fixing issues | ✅ Green output for fixed issues | ❌ |
| Unchanged findings | Scan with same issues | No color change | ❌ |
| UUID differences | Same finding, different UUID | Ignored in comparison | ❌ |
| Multiple changes | Mixed new/old/fixed | Correct categorization | ❌ |

### SARIF Output

| Test | Command | Expected Result | Status |
|------|---------|-----------------|--------|
| SARIF generation | `cargo run -- scan --format sarif` | Valid SARIF 2.1.0 | ❌ |
| Severity mapping | Check `.level` fields | Critical→error, High→error, Medium→warning | ❌ |
| Rule deduplication | Multiple same-rule findings | Single rule definition | ❌ |
| Help text | Check `.help` fields | Proper remediation guidance | ❌ |
| Schema validation | Validate against SARIF schema | Schema compliant | ❌ |

### CI Integration

| Test | Command | Expected Result | Status |
|------|---------|-----------------|--------|
| YAML syntax | `yaml-lint *.yml` | Valid YAML | ❌ |
| GH Actions syntax | `act --validate` | Valid workflow | ❌ |
| Baseline comparison | `cargo run -- scan --baseline` | Shows differences | ❌ |
| Matrix builds | Check workflow matrix | Proper server matrix | ❌ |
| SARIF upload | Check upload step | Proper SARIF artifact | ❌ |

## Expected Output Examples

### Differential Display Output

```
🔍 Watch Mode - Monitoring for changes...

📊 Changes Detected:
  ❌ NEW ISSUES (2):
    • MCP-INJ-001: Command Injection in tool_a (High)
    • MCP-INJ-002: SQL Injection in tool_b (Critical)

  ✅ FIXED ISSUES (1):
    • MCP-AUTH-001: Missing Authentication (Medium)

  ⚪️ UNCHANGED (3):
    • MCP-TRANSPORT-001: Insecure Transport
    • MCP-DATA-001: Data Validation
    • MCP-PROTOCOL-001: Protocol Compliance

────────────────────────────────────────────────────────────────────────────────
Current state: 2 critical, 1 high, 3 medium, 0 low, 0 info
```

### SARIF Output Structure

```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "MCPLint",
        "informationUri": "https://github.com/quanticsoul4772/mcplint",
        "version": "0.2.0",
        "rules": [{
          "id": "MCP-INJ-001",
          "name": "Command Injection Detection",
          "shortDescription": {"text": "Detects command injection vulnerabilities"},
          "fullDescription": {"text": "Checks for unsafe command execution..."},
          "help": {"text": "Use parameterized commands or input validation..."},
          "properties": {
            "tags": ["security", "injection", "critical"]
          }
        }]
      }
    },
    "results": [{
      "ruleId": "MCP-INJ-001",
      "ruleIndex": 0,
      "level": "error",
      "message": {"text": "Command injection vulnerability detected in tool 'vulnerable_tool'"},
      "locations": [{
        "physicalLocation": {
          "artifactLocation": {"uri": "server.js"},
          "region": {"startLine": 10}
        }
      }],
      "properties": {
        "severity": "CRITICAL",
        "fingerprint": "MCP-INJ-001:tool:vulnerable_tool:Command injection"
      }
    }]
  }]
}
```

## Performance Considerations

### Expected Performance Metrics

| Operation | Expected Time | Notes |
|-----------|---------------|-------|
| Watch mode startup | < 2s | Initial scan |
| File change detection | < 100ms | Debounce period |
| Diff computation | O(n) | Linear with finding count |
| SARIF generation | O(n) | Linear with finding count |
| Memory usage | < 50MB | For typical scans |

### Scalability Testing

```bash
# Test with large number of findings
# Generate test data with 1000+ findings
cargo run -- scan --server "large_server" --profile full

# Measure performance
time cargo run -- watch --server "large_server"
```

## Error Handling Verification

### Expected Error Cases

| Error Condition | Expected Behavior |
|-----------------|-------------------|
| Invalid server path | Clear error message with suggestions |
| Missing dependencies | Helpful installation instructions |
| Permission denied | Proper error with file path |
| Invalid profile | List of available profiles |
| Network timeout | Retry mechanism with timeout info |

### Error Message Examples

```
❌ Error: Server not found at path '/invalid/path'

Suggestions:
  • Check that the server path is correct
  • Ensure the server is installed
  • Use --server flag to specify the correct path

Available servers:
  • memory: MCP Memory Server
  • filesystem: MCP Filesystem Server
  • custom: Path to custom server
```

## Documentation Verification

### Help Text Updates

```bash
# Check that help text includes new features
cargo run -- watch --help | grep -E "diff|differential|baseline"
cargo run -- scan --help | grep -E "sarif|ci|baseline"
```

### Expected Help Output

```
USAGE:
    mcplint watch [OPTIONS] --server <SERVER> [ARGS]...

OPTIONS:
    -s, --server <SERVER>      Server to watch (path, URL, or preset)
    -p, --profile <PROFILE>    Scan profile [default: standard] [possible values: quick, standard, full, enterprise]
    -d, --debounce <MS>       Debounce time in milliseconds [default: 500]
    -c, --clear-screen        Clear screen between scans
    -b, --baseline <FILE>     Baseline file for differential comparison
    --diff-only              Show only changes from baseline
    -h, --help               Print help information
```

## CI/CD Integration Testing

### GitHub Actions Workflow Validation

```yaml
# Key components to verify in github-actions-mcp-scan.yml
name: MCP Security Scan

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]
  schedule:
    - cron: '0 0 * * 0'  # Weekly

jobs:
  security-scan:
    strategy:
      matrix:
        server: [memory, filesystem, custom]
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
      - run: npm install -g @modelcontextprotocol/server-memory
      - run: mcplint scan --server ${{ matrix.server }} --format sarif --output results.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

## Success Criteria

### Minimum Viable Verification

- ✅ All unit tests pass
- ✅ Watch mode starts without errors
- ✅ Differential display shows correct colors
- ✅ SARIF output is valid JSON
- ✅ CI workflows have valid syntax

### Comprehensive Verification

- ✅ All edge cases handled correctly
- ✅ Performance meets expectations
- ✅ Error handling is robust
- ✅ Documentation is accurate
- ✅ Integration with real servers works

## Reporting Template

```markdown
# CLI Changes Verification Report

## Summary
- **Date:** [Date]
- **Version:** 0.2.0
- **Commit:** 0942d0a

## Test Results

### ✅ Passed Tests
- [ ] diff_empty_results_has_no_changes
- [ ] diff_detects_new_findings
- [ ] diff_detects_fixed_findings
- [ ] diff_ignores_finding_id_differences
- [ ] SARIF generation and validation
- [ ] CI workflow syntax validation

### ❌ Failed Tests
- [ ] [Test Name]: [Error Description]

### 📝 Observations
- [ ] Performance metrics
- [ ] Usability improvements
- [ ] Documentation gaps

## Recommendations
- [ ] Fix any failed tests
- [ ] Improve error messages
- [ ] Add more test cases
- [ ] Update documentation

## Next Steps
- [ ] Address failed tests
- [ ] Merge to main branch
- [ ] Update release notes
- [ ] Announce new features
```

## Conclusion

This verification plan provides comprehensive coverage of the new CLI features:
- **Watch Mode Differential Display** with colored output
- **Enhanced SARIF Output** for CI/CD integration
- **CI Workflow Examples** for easy adoption

The plan includes unit tests, integration tests, performance testing, and documentation verification to ensure the features work correctly and meet user expectations.

**Status:** Ready for execution
**Next Step:** Begin testing with unit tests, then proceed to integration testing