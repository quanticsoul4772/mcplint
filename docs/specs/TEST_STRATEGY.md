# MCPLint Test Strategy

This document defines the testing approach for each phase of the MCPLint CLI implementation.

## Test Pyramid

```
                    ┌─────────┐
                    │   E2E   │  ~10%
                    │  Tests  │  (slow, high confidence)
                   ─┴─────────┴─
                  ┌─────────────┐
                  │ Integration │  ~30%
                  │    Tests    │  (medium speed)
                 ─┴─────────────┴─
                ┌─────────────────┐
                │   Unit Tests    │  ~60%
                │                 │  (fast, isolated)
               ─┴─────────────────┴─
```

## Global Testing Infrastructure

### Mock MCP Server

A configurable mock server for testing without real MCP servers:

```rust
// tests/common/mock_server.rs
pub struct MockMcpServer {
    tools: Vec<Tool>,
    resources: Vec<Resource>,
    prompts: Vec<Prompt>,
    behavior: MockBehavior,
}

pub enum MockBehavior {
    Normal,
    SlowResponse(Duration),
    FailAfter(usize),  // Fail after N requests
    InvalidJson,
    Timeout,
}

impl MockMcpServer {
    pub fn with_tools(tools: Vec<Tool>) -> Self;
    pub fn with_behavior(behavior: MockBehavior) -> Self;
    pub async fn spawn(&self) -> MockServerHandle;
}
```

### Test Fixtures

```
tests/
├── fixtures/
│   ├── servers/
│   │   ├── clean_server.json      # No vulnerabilities
│   │   ├── vuln_server.json       # Multiple findings
│   │   ├── shadow_server.json     # Tool shadowing
│   │   └── injection_server.json  # Prompt injection
│   ├── configs/
│   │   ├── valid_config.json      # Valid Claude config
│   │   ├── empty_config.json      # No servers
│   │   └── malformed_config.json  # Invalid JSON
│   └── sarif/
│       └── expected_output.sarif  # Expected SARIF format
```

---

## Phase 1: Smart Context Detection

### Unit Tests

```rust
#[cfg(test)]
mod context_detection_tests {
    // Config file detection
    #[test]
    fn finds_claude_config_in_standard_locations();

    #[test]
    fn finds_local_mcplint_config();

    #[test]
    fn prefers_local_config_over_global();

    // Server resolution
    #[test]
    fn resolves_server_by_name_from_config();

    #[test]
    fn resolves_http_url_directly();

    #[test]
    fn resolves_npm_package_via_npx();

    #[test]
    fn detects_file_extension_runtime() {
        assert_eq!(detect_runtime("server.js"), ("node", vec!["server.js"]));
        assert_eq!(detect_runtime("server.py"), ("python", vec!["server.py"]));
    }

    // Transport detection
    #[test]
    fn detects_stdio_for_local_paths();

    #[test]
    fn detects_http_for_urls();

    #[test]
    fn detects_sse_for_sse_urls();
}
```

### Integration Tests

```rust
#[tokio::test]
async fn resolves_and_connects_to_mock_server() {
    let mock = MockMcpServer::default().spawn().await;
    let (name, cmd, args, env) = resolve_server(&mock.address, None)?;
    // Verify connection works
}

#[tokio::test]
async fn handles_missing_config_gracefully() {
    // Test with no config file present
}
```

### Test Coverage Target: 90%

---

## Phase 2: Progress Indicators

### Unit Tests

```rust
#[cfg(test)]
mod progress_tests {
    // Progress bar
    #[test]
    fn progress_bar_calculates_percentage();

    #[test]
    fn progress_bar_formats_eta();

    #[test]
    fn progress_bar_handles_zero_total();

    // Spinner
    #[test]
    fn spinner_cycles_through_frames();

    #[test]
    fn spinner_stops_cleanly();

    // Multi-progress
    #[test]
    fn tracks_multiple_operations();
}
```

### Integration Tests

```rust
#[tokio::test]
async fn shows_progress_during_scan() {
    let output = capture_stderr(|| {
        scan_with_progress(&mock_server, ScanProfile::Full).await
    });
    assert!(output.contains("Scanning"));
    assert!(output.contains("100%"));
}

#[tokio::test]
async fn hides_progress_in_ci_mode() {
    std::env::set_var("CI", "true");
    let output = capture_stderr(|| {
        scan_with_progress(&mock_server, ScanProfile::Full).await
    });
    assert!(!output.contains("████")); // No progress bar
}
```

### Visual Regression Tests

Manual verification checklist for terminal output (not automated):
- [ ] Progress bar renders correctly in 80-column terminal
- [ ] Colors display properly with TERM=xterm-256color
- [ ] Spinner animation is smooth
- [ ] ETA updates correctly

### Test Coverage Target: 85%

---

## Phase 3: Interactive Mode

### Unit Tests

```rust
#[cfg(test)]
mod repl_tests {
    // Command parsing
    #[test]
    fn parses_simple_commands();

    #[test]
    fn parses_commands_with_args();

    #[test]
    fn handles_quoted_strings();

    // History
    #[test]
    fn saves_command_to_history();

    #[test]
    fn navigates_history_with_arrows();

    // Completion
    #[test]
    fn completes_command_names();

    #[test]
    fn completes_server_names();
}
```

### Integration Tests

```rust
#[tokio::test]
async fn repl_connect_and_scan() {
    let mut repl = TestRepl::new();
    repl.input("connect mock-server").await;
    assert!(repl.output().contains("Connected"));

    repl.input("scan").await;
    assert!(repl.output().contains("findings"));
}

#[tokio::test]
async fn repl_handles_invalid_commands() {
    let mut repl = TestRepl::new();
    repl.input("invalid_command").await;
    assert!(repl.output().contains("Unknown command"));
}
```

### Test Coverage Target: 80%

---

## Phase 4: Error Messages & Help

### Unit Tests

```rust
#[cfg(test)]
mod error_tests {
    // Error formatting
    #[test]
    fn formats_connection_error_with_suggestion();

    #[test]
    fn formats_server_not_found_with_alternatives();

    #[test]
    fn calculates_levenshtein_for_suggestions();

    // Help text
    #[test]
    fn all_commands_have_help();

    #[test]
    fn examples_are_valid_syntax();
}
```

### Snapshot Tests

```rust
#[test]
fn error_message_snapshots() {
    // Connection timeout
    insta::assert_snapshot!(
        format_error(McpError::ConnectionTimeout("server", 30))
    );

    // Server not found
    insta::assert_snapshot!(
        format_error(McpError::ServerNotFound("typo-server", vec!["type-server"]))
    );
}
```

### Documentation Tests

```rust
/// # Examples
///
/// ```
/// use mcplint::cli::suggest_similar;
/// let suggestions = suggest_similar("filesystm", &["filesystem", "github"]);
/// assert_eq!(suggestions, vec!["filesystem"]);
/// ```
pub fn suggest_similar(input: &str, candidates: &[&str]) -> Vec<String>;
```

### Test Coverage Target: 95%

---

## Phase 5: Shell Completions & Watch Mode

### Unit Tests

```rust
#[cfg(test)]
mod completion_tests {
    #[test]
    fn generates_bash_completions();

    #[test]
    fn generates_zsh_completions();

    #[test]
    fn generates_fish_completions();

    #[test]
    fn generates_powershell_completions();
}

#[cfg(test)]
mod watch_tests {
    #[test]
    fn should_trigger_on_file_create();

    #[test]
    fn should_not_trigger_on_hidden_files();

    #[test]
    fn should_not_trigger_on_git_directory();

    #[test]
    fn debounces_rapid_changes();
}
```

### Integration Tests

```rust
#[tokio::test]
async fn watch_mode_detects_changes() {
    let dir = tempdir()?;
    let handle = spawn_watch_mode(&dir).await;

    // Create a file
    std::fs::write(dir.path().join("server.js"), "// changed")?;

    // Wait for debounce
    tokio::time::sleep(Duration::from_millis(600)).await;

    assert!(handle.output().contains("File changed"));
    assert!(handle.output().contains("Running security scan"));
}

#[tokio::test]
async fn watch_mode_respects_file_limits() {
    let dir = tempdir()?;
    // Create 15,000 files
    for i in 0..15000 {
        std::fs::write(dir.path().join(format!("file{}.js", i)), "")?;
    }

    let result = start_watch_mode(&dir);
    assert!(result.warnings().contains("exceeds recommended limit"));
}
```

### Shell Completion Verification

```bash
# Manual verification script
#!/bin/bash
# tests/verify_completions.sh

# Test bash completions
source <(mcplint completions bash)
complete -p mcplint  # Should show completion function

# Test that completion works
COMP_WORDS=(mcplint sc)
COMP_CWORD=1
_mcplint
echo "${COMPREPLY[@]}"  # Should include 'scan'
```

### Test Coverage Target: 85%

---

## Phase 6: CI/CD Integration

### Unit Tests

```rust
#[cfg(test)]
mod sarif_tests {
    #[test]
    fn generates_valid_sarif_schema();

    #[test]
    fn maps_severity_to_sarif_level();

    #[test]
    fn includes_rule_definitions();
}

#[cfg(test)]
mod baseline_tests {
    #[test]
    fn detects_new_findings();

    #[test]
    fn detects_fixed_findings();

    #[test]
    fn handles_moved_findings();
}
```

### Integration Tests

```rust
#[tokio::test]
async fn sarif_output_validates() {
    let results = scan(&mock_server).await?;
    let sarif = SarifReporter::format(&results);

    // Validate against schema
    let schema = load_sarif_schema();
    assert!(schema.validate(&sarif).is_ok());
}

#[tokio::test]
async fn baseline_comparison_works() {
    // First scan
    let baseline = scan(&server_v1).await?;
    save_baseline(&baseline, "baseline.json")?;

    // Second scan with changes
    let current = scan(&server_v2).await?;
    let diff = compare_to_baseline(&current, "baseline.json")?;

    assert_eq!(diff.new_findings.len(), 1);
    assert_eq!(diff.fixed_findings.len(), 2);
}
```

### E2E Tests

```rust
#[tokio::test]
async fn github_actions_workflow() {
    // Simulate GitHub Actions environment
    std::env::set_var("GITHUB_ACTIONS", "true");
    std::env::set_var("GITHUB_WORKSPACE", "/workspace");

    let exit_code = run_cli(&["scan", "mock-server", "--format", "sarif"]).await;

    assert_eq!(exit_code, 1); // Findings detected
    assert!(Path::new("results.sarif").exists());
}
```

### Test Coverage Target: 90%

---

## Phase 7: Polish & Documentation

### Documentation Tests

```rust
// Ensure all public APIs have documentation
#![deny(missing_docs)]

// Ensure examples compile
#![doc(test(attr(deny(warnings))))]
```

### README Verification

```rust
#[test]
fn readme_examples_work() {
    // Extract code blocks from README
    let examples = extract_code_blocks("README.md");

    for example in examples {
        if example.language == "bash" {
            // Verify command syntax is valid
            assert!(parse_cli_args(&example.code).is_ok());
        }
    }
}
```

### Link Checker

```bash
# CI step to verify documentation links
cargo doc --no-deps
linkchecker target/doc/mcplint/index.html
```

---

## CI Pipeline Configuration

```yaml
# .github/workflows/test.yml
name: Tests

on: [push, pull_request]

jobs:
  unit-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run unit tests
        run: cargo test --lib

  integration-tests:
    runs-on: ubuntu-latest
    services:
      ollama:
        image: ollama/ollama
    steps:
      - uses: actions/checkout@v4
      - name: Run integration tests
        run: cargo test --test '*'

  e2e-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Build release
        run: cargo build --release
      - name: Run E2E tests
        run: ./tests/e2e/run_all.sh

  coverage:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Generate coverage
        run: cargo tarpaulin --out Xml
      - name: Upload coverage
        uses: codecov/codecov-action@v3

  mutation-testing:
    runs-on: ubuntu-latest
    if: github.event_name == 'pull_request'
    steps:
      - uses: actions/checkout@v4
      - name: Run mutation tests
        run: cargo mutants --in-place -- --lib
```

---

## Test Naming Convention

```rust
// Pattern: test_<module>_<scenario>_<expected>

#[test]
fn test_resolver_http_url_returns_http_transport() { }

#[test]
fn test_scanner_injection_pattern_detects_ignore_instructions() { }

#[test]
fn test_progress_zero_total_shows_indeterminate() { }
```

---

## Coverage Targets Summary

| Phase | Unit | Integration | E2E | Total Target |
|-------|------|-------------|-----|--------------|
| 1. Context Detection | 90% | 80% | - | 85% |
| 2. Progress Indicators | 85% | 70% | - | 80% |
| 3. Interactive Mode | 80% | 75% | - | 78% |
| 4. Error Messages | 95% | 80% | - | 90% |
| 5. Completions & Watch | 85% | 80% | - | 83% |
| 6. CI/CD Integration | 90% | 85% | 80% | 88% |
| 7. Polish & Docs | - | - | - | 85% |
| **Overall** | **88%** | **78%** | **80%** | **85%** |
