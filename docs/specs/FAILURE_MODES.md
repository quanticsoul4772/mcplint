# MCPLint Failure Modes & Recovery Strategies

This document defines expected behavior under failure conditions and recovery strategies for each component.

## Failure Classification

| Level | Description | User Impact | Recovery |
|-------|-------------|-------------|----------|
| **Critical** | System cannot continue | Operation fails | Immediate error, clean exit |
| **Degraded** | Feature unavailable | Partial results | Fallback + warning |
| **Warning** | Suboptimal but functional | Reduced quality | Continue + inform user |

---

## Transport Layer Failures

### Connection Timeout

**Trigger**: Server doesn't respond within timeout period

**Behavior**:
```
Error: Connection to 'my-server' timed out after 30s

Possible causes:
  1. Server process crashed or didn't start
  2. Server is waiting for input
  3. Network issue (for remote servers)

Try:
  - Run the server manually: node /path/to/server.js
  - Increase timeout: --timeout 60
  - Check server logs
```

**Exit Code**: 4 (Timeout)

**Recovery**: None - operation fails cleanly

### Server Crash During Operation

**Trigger**: Transport closed unexpectedly mid-operation

**Behavior**:
- Partial results returned if any complete
- Clear indication of incomplete scan
- Exit code 3 (Partial)

```
Warning: Connection lost during scan

Completed: 15/50 tools scanned
Findings so far: 2

Partial results saved to: results.partial.json
```

**Recovery**: Save partial results, inform user

### Invalid Server Response

**Trigger**: Server returns malformed JSON-RPC

**Behavior**:
- Log raw response for debugging
- Attempt to continue if possible
- Mark specific operation as failed

```
Warning: Invalid response from server for tools/list

Raw response (truncated): {"jsonrpc": "2.0", "result": null...

Continuing with available data...
```

**Recovery**: Skip malformed response, continue operation

---

## AI Provider Failures

### API Rate Limit (429)

**Trigger**: Too many requests to AI provider

**Behavior**:
```
Warning: AI provider rate limited. Waiting 60s before retry...
Retry 1/3...
```

**Recovery**: Exponential backoff with 3 retries

### API Timeout

**Trigger**: AI provider doesn't respond (implemented in Ollama fix)

**Current Implementation** (`src/ai/provider/ollama.rs`):
```rust
// Simplified prompt for faster response
const OLLAMA_SYSTEM_PROMPT: &str = "You are a security expert...";

// Timeout: 300s for CPU inference
let provider = OllamaProvider::new(base_url, model, Duration::from_secs(300));

// Fallback response if JSON parsing fails
fn create_fallback_response(&self, finding: &Finding, response_text: &str, ...) {
    // Use raw text as summary, truncate if needed
}
```

**Behavior**:
- Use simplified prompts for local models
- Generous timeout for CPU inference
- Fallback to raw text summary if structured parsing fails

**Recovery**: Fallback response with raw AI output

### AI Provider Unavailable

**Trigger**: Cannot reach AI provider at all

**Behavior**:
```
Warning: AI explanation unavailable (Ollama not running)

Scan results (without AI explanations):
  ⚠ TOOL-INJ-001 [HIGH] Prompt Injection Detected
    Tool: read_file
    Evidence: "Ignore previous instructions"

Tip: Start Ollama with 'ollama serve' for AI-powered explanations
```

**Recovery**: Continue without AI explanations, show raw findings

---

## Cache Failures

### Cache Backend Unavailable

**Trigger**: Redis down, filesystem full, etc.

**Behavior**:
```
Warning: Cache unavailable (Redis connection refused)
Continuing without caching (slower performance)
```

**Recovery**: Fall back to in-memory or no-op cache

### Cache Corruption

**Trigger**: Invalid data in cache

**Behavior**:
- Log corruption details
- Clear corrupted entry
- Regenerate fresh data

```
Warning: Corrupted cache entry for 'schema:my-server'
Clearing and refetching...
```

**Recovery**: Transparent re-fetch

### Cache Miss During Baseline

**Trigger**: Baseline file missing for comparison

**Behavior**:
```
Warning: No baseline found at '.mcplint-baseline.json'
All findings will be reported as new.

Tip: Create baseline with: mcplint scan <server> --save-baseline
```

**Recovery**: Treat all findings as new

---

## Watch Mode Failures

### File Watcher Overload

**Trigger**: Too many files/directories being watched

**Thresholds** (from METRICS.md):
- Warning at 10,000 files
- Warning at 100 directories

**Behavior**:
```
Warning: Watching 15,000 files exceeds recommended limit (10,000)

Performance may degrade. Consider:
  - Using --watch-filter '*.js,*.ts'
  - Excluding node_modules: --exclude node_modules
  - Watching specific directories only

Continuing with aggressive debouncing (2000ms)...
```

**Recovery**:
- Increase debounce to reduce event processing
- Warn user about performance
- Continue operating

### Watch Mode Event Storm

**Trigger**: Rapid succession of file events (e.g., git checkout)

**Behavior**:
- Aggressive debouncing kicks in
- Single scan after storm subsides

```
Detected 150 file changes in 500ms
Waiting for changes to settle...
Running scan after 2s quiet period...
```

**Recovery**: Dynamic debounce adjustment

### Server Restart Required

**Trigger**: Server file changed, needs restart

**Behavior**:
```
Server file changed: server.js
Restarting server connection...
Connecting... ✓
Running security scan...
```

**Recovery**: Automatic reconnection

---

## Scanner Failures

### Rule Execution Error

**Trigger**: Security rule throws exception

**Behavior**:
- Log error details
- Mark rule as failed
- Continue with other rules

```
Warning: Rule TOOL-INJ-003 failed: regex compilation error
Skipping rule, continuing scan...

Scan completed with 1 rule skipped.
```

**Recovery**: Skip failed rule, report issue

### Schema Analysis Failure

**Trigger**: Cannot parse tool schema

**Behavior**:
- Mark tool as unanalyzable
- Continue with other tools

```
Warning: Cannot analyze tool 'complex_tool': schema too deeply nested
Skipping tool, continuing scan...
```

**Recovery**: Skip problematic tool

---

## CLI Failures

### Invalid Arguments

**Trigger**: User provides invalid command-line arguments

**Behavior**:
```
Error: Invalid value 'super' for '--profile'

Valid values: quick, standard, full, paranoid

Usage: mcplint scan <SERVER> --profile <PROFILE>
```

**Exit Code**: 2 (Error)

### Missing Dependencies

**Trigger**: Required tool not installed (e.g., node for JS servers)

**Behavior**:
```
Error: Cannot start server - 'node' not found

The server 'my-server' requires Node.js to run.

Install Node.js:
  - macOS: brew install node
  - Ubuntu: sudo apt install nodejs
  - Windows: https://nodejs.org/

Or specify a different server runtime with --command
```

**Exit Code**: 2 (Error)

### Permission Denied

**Trigger**: Cannot read config file or write output

**Behavior**:
```
Error: Permission denied reading '/etc/claude/config.json'

Try:
  - Use a config in your home directory
  - Run with appropriate permissions
  - Specify config with --config path/to/config.json
```

**Exit Code**: 2 (Error)

---

## Memory Pressure

### High Memory Usage

**Thresholds** (from METRICS.md):
- Warning at 75% of limit
- Critical at 90% of limit

**Behavior**:
```
Warning: High memory usage (180MB / 250MB limit)
Consider reducing scope or using streaming mode.
```

**Recovery**: Continue but warn user

### Out of Memory

**Trigger**: Cannot allocate required memory

**Behavior**:
- Log memory state
- Clean exit with partial results if possible

```
Error: Out of memory during corpus analysis

Partial results saved to: results.partial.json
Consider using --streaming mode for large corpora.
```

**Exit Code**: 2 (Error)

**Recovery**: Save partial results before exit

---

## Network Failures (Remote Servers)

### DNS Resolution Failure

**Trigger**: Cannot resolve server hostname

**Behavior**:
```
Error: Cannot resolve 'mcp.example.com'

Check:
  - Hostname spelling
  - Network connectivity
  - DNS configuration
```

**Exit Code**: 2 (Error)

### TLS/SSL Errors

**Trigger**: Certificate validation fails

**Behavior**:
```
Error: TLS certificate validation failed for 'mcp.example.com'

Certificate error: self-signed certificate

Options:
  - Use a valid certificate
  - Skip validation with --insecure (not recommended)
```

**Exit Code**: 2 (Error)

---

## Failure Mode Summary Table

| Component | Failure | Level | Recovery | Exit Code |
|-----------|---------|-------|----------|-----------|
| Transport | Timeout | Critical | Clean exit | 4 |
| Transport | Mid-op crash | Degraded | Partial results | 3 |
| Transport | Invalid response | Warning | Skip + continue | 0/1 |
| AI | Rate limit | Degraded | Retry w/ backoff | 0/1 |
| AI | Timeout | Degraded | Fallback response | 0/1 |
| AI | Unavailable | Warning | No explanations | 0/1 |
| Cache | Unavailable | Warning | No caching | 0/1 |
| Cache | Corruption | Warning | Re-fetch | 0/1 |
| Watch | Overload | Warning | Aggressive debounce | 0/1 |
| Watch | Event storm | Warning | Dynamic debounce | 0/1 |
| Scanner | Rule error | Warning | Skip rule | 0/1 |
| CLI | Invalid args | Critical | Error message | 2 |
| CLI | Missing deps | Critical | Install guide | 2 |
| Memory | High usage | Warning | Continue + warn | 0/1 |
| Memory | OOM | Critical | Partial save + exit | 2 |
| Network | DNS failure | Critical | Error message | 2 |
| Network | TLS error | Critical | Error + options | 2 |

---

## Circuit Breaker Pattern

For repeated failures, implement circuit breaker:

```rust
pub struct CircuitBreaker {
    failure_count: AtomicUsize,
    last_failure: AtomicU64,
    state: AtomicU8,  // 0=Closed, 1=Open, 2=HalfOpen
}

impl CircuitBreaker {
    const FAILURE_THRESHOLD: usize = 5;
    const RECOVERY_TIMEOUT: Duration = Duration::from_secs(60);

    pub fn call<F, T>(&self, f: F) -> Result<T>
    where F: FnOnce() -> Result<T>
    {
        match self.state() {
            State::Open => Err(CircuitOpenError),
            State::HalfOpen | State::Closed => {
                match f() {
                    Ok(result) => {
                        self.record_success();
                        Ok(result)
                    }
                    Err(e) => {
                        self.record_failure();
                        Err(e)
                    }
                }
            }
        }
    }
}
```

Apply to:
- AI provider calls
- Remote server connections
- Redis cache operations

---

## Graceful Degradation Priority

When multiple failures occur, degrade in this order:

1. **AI Explanations** → Raw findings only
2. **Caching** → Fresh fetch every time
3. **Progress Indicators** → Silent operation
4. **Baseline Comparison** → All findings as new
5. **Watch Mode** → Single scan mode
6. **Full Scan** → Quick scan only
7. **Any Results** → Error + exit

Each level maintains maximum useful functionality while handling failures gracefully.
