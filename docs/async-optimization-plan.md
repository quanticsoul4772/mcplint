# Async Performance Optimization Plan

## Overview

This document outlines the implementation plan for optimizing async operations in MCPLint's scanner and validator engines to achieve 30-50% faster multi-server scanning and better CPU utilization.

## Current State Analysis

### Existing Parallel Infrastructure

MCPLint already has a solid foundation for parallel execution in `src/scanner/multi_server.rs`:

```rust
// Current pattern (lines 482-518)
let results: Vec<ServerScanResult> = stream::iter(self.configs.clone())
    .map(|config| {
        let sem = semaphore.clone();
        async move {
            let _permit = sem.acquire().await.unwrap();
            // ... scan logic
        }
    })
    .buffer_unordered(self.concurrency)
    .collect()
    .await;
```

This pattern is efficient for **inter-server** parallelism but doesn't optimize **intra-server** operations.

### Blocking Operations Identified

#### Scanner Engine (`src/scanner/engine.rs`)

| Line | Operation | Current Pattern | Optimization Potential |
|------|-----------|-----------------|----------------------|
| 232, 286, 341, 381 | Tool iteration for injection checks | Sequential `for tool in &ctx.tools` | **HIGH** - Independent checks per tool |
| 488, 607, 683, 747 | Auth/data/DOS checks per tool | Sequential iteration | **MEDIUM** - CPU-bound pattern matching |
| 573, 799-852 | Finding collection loops | Sequential aggregation | **LOW** - Fast, dependent operations |
| 991-1043 | Schema property analysis | Nested loops for patterns | **MEDIUM** - Can batch pattern matching |

#### Validator Engine (`src/validator/engine.rs`)

| Line | Operation | Current Pattern | Optimization Potential |
|------|-----------|-----------------|----------------------|
| 795, 927, 956, 990, 1026, 1074 | Tool validation rules | Sequential `for tool in tools` | **HIGH** - Independent validations |
| 827 | Resource validation | Sequential `for resource in &resources` | **HIGH** - Independent checks |
| 859 | Prompt validation | Sequential `for prompt in &prompts` | **HIGH** - Independent checks |
| 1743-1744, 1822-1823, 1953-1954, 2065-2066 | Security payload testing | Nested for loops | **CRITICAL** - I/O bound, await per call |
| 2214-2215, 2270, 2350 | More payload testing | Nested sequential | **CRITICAL** - Major bottleneck |
| 2413-2424 | Name collision checks | Nested iteration | **LOW** - Fast O(n²) but small n |

### Key Bottlenecks

1. **Security Rule Payload Testing** (Lines 1743-2279 in validator/engine.rs)
   - Each payload test involves `client.call_tool(...).await`
   - Currently executed sequentially per tool, per payload
   - Example: 5 tools × 10 payloads = 50 sequential network calls

2. **Tool Schema Analysis** (Scanner engine)
   - Pattern matching against tool schemas is CPU-bound
   - Currently uses regex matching in sequential loops

3. **Multi-Category Validation** (Validator engine)
   - Protocol, schema, sequence, tool, resource, security, edge rules
   - All categories execute sequentially, but many are independent

## Implementation Plan

### Phase 1: Intra-Scan Parallelism (High Impact)

**Target Files:**
- `src/scanner/engine.rs`
- `src/validator/engine.rs`

**Pattern to Apply:**
```rust
use futures::stream::{self, StreamExt};

// Current (blocking)
for tool in &ctx.tools {
    if let Some(finding) = self.check_command_injection_for_tool(tool) {
        results.add_finding(finding);
    }
}

// Optimized (parallel)
let findings: Vec<Option<Finding>> = stream::iter(&ctx.tools)
    .map(|tool| async move {
        self.check_command_injection_for_tool(tool)
    })
    .buffer_unordered(num_cpus::get())
    .collect()
    .await;

for finding in findings.into_iter().flatten() {
    results.add_finding(finding);
}
```

**Specific Changes:**

1. **Scanner: Injection Checks** (lines 232-400)
   ```rust
   // Parallelize: check_command_injection, check_sql_injection,
   // check_path_traversal, check_ssrf
   // These are independent per-tool checks
   ```

2. **Validator: Tool Rule Execution** (lines 795-1100)
   ```rust
   // Parallelize: TOOL-001 through TOOL-005 validations
   // Each tool can be validated independently
   ```

3. **Validator: Security Payload Testing** (lines 1743-2300)
   ```rust
   // CRITICAL: Parallelize payload testing
   // Current: O(tools × payloads) sequential awaits
   // Target: O(tools × payloads / concurrency) with buffer_unordered
   ```

### Phase 2: Category-Level Parallelism (Medium Impact)

**Current Flow (Sequential):**
```rust
self.run_protocol_rules(&ctx, &mut results);
self.run_schema_rules(&ctx, &mut results);
self.run_sequence_rules(&mut client, &ctx, &mut results).await;
self.run_tool_rules(&mut client, &ctx, &mut results).await;
self.run_resource_rules(&mut client, &ctx, &mut results).await;
self.run_security_rules(&mut client, &ctx, &mut results).await;
self.run_edge_rules(&mut client, &ctx, &mut results).await;
```

**Optimized Flow:**
```rust
// Phase A: Non-client rules (can run in parallel)
let (protocol_results, schema_results) = tokio::join!(
    async { self.run_protocol_rules(&ctx) },
    async { self.run_schema_rules(&ctx) }
);

// Phase B: Client-dependent rules (need shared client access)
// These remain sequential due to client borrowing constraints
self.run_sequence_rules(&mut client, &ctx, &mut results).await;
// ...
```

**Note:** Full category parallelism requires refactoring client to be `Arc<Mutex<McpClient>>` or using connection pooling.

### Phase 3: Connection Pooling (Advanced)

For maximum throughput, implement a connection pool:

```rust
pub struct ClientPool {
    clients: Vec<Arc<Mutex<McpClient>>>,
    semaphore: Semaphore,
}

impl ClientPool {
    pub async fn with_client<F, T>(&self, f: F) -> T
    where
        F: FnOnce(&mut McpClient) -> T,
    {
        let _permit = self.semaphore.acquire().await.unwrap();
        let client = self.clients.pop().unwrap();
        let result = f(&mut client.lock().await);
        self.clients.push(client);
        result
    }
}
```

This enables true parallel execution of client-dependent operations.

## Implementation Priority

### Immediate (Week 1)
1. Add `num_cpus` dependency to `Cargo.toml`
2. Implement parallel tool iteration in scanner injection checks
3. Implement parallel payload testing in validator security rules

### Short-term (Week 2)
4. Parallelize tool/resource/prompt validation loops
5. Add benchmarking to measure improvements
6. Update tests for parallel execution

### Medium-term (Week 3-4)
7. Evaluate connection pooling feasibility
8. Implement category-level parallelism where client sharing allows
9. Add configurable concurrency limits

## Required Dependencies

```toml
[dependencies]
# Add to Cargo.toml
num_cpus = "1.16"
futures = "0.3"  # Already present
```

## Expected Performance Gains

| Optimization | Expected Improvement | Affected Operations |
|--------------|---------------------|---------------------|
| Parallel tool checks (scanner) | 20-30% | Injection detection |
| Parallel payload testing (validator) | 40-60% | Security rules |
| Category parallelism | 10-15% | Protocol/schema rules |
| Connection pooling | 50-70% | All client operations |

**Combined Impact:** 30-50% faster overall scan time for multi-tool servers.

## Risk Mitigation

1. **Race Conditions:** Use `Arc<Mutex<_>>` for shared mutable state
2. **Resource Exhaustion:** Limit concurrency with `buffer_unordered(n)`
3. **Error Handling:** Collect all errors, don't fail fast
4. **Backward Compatibility:** Keep sequential fallback for single-threaded contexts

## Testing Strategy

1. **Unit Tests:** Verify parallel results match sequential results
2. **Integration Tests:** Benchmark against real MCP servers
3. **Stress Tests:** High concurrency with many tools/payloads
4. **Regression Tests:** Ensure no findings are missed

## Code Examples

### Example 1: Parallel Tool Injection Check

```rust
// In src/scanner/engine.rs

async fn run_injection_checks_parallel(
    &self,
    ctx: &ServerContext,
    results: &mut ScanResults,
) {
    use futures::stream::{self, StreamExt};

    let concurrency = num_cpus::get().min(ctx.tools.len()).max(1);

    // Run all injection checks in parallel per tool
    let all_findings: Vec<Vec<Finding>> = stream::iter(&ctx.tools)
        .map(|tool| async move {
            let mut findings = Vec::new();

            if let Some(f) = self.check_command_injection_for_tool(tool) {
                findings.push(f);
            }
            if let Some(f) = self.check_sql_injection_for_tool(tool) {
                findings.push(f);
            }
            if let Some(f) = self.check_path_traversal_for_tool(tool) {
                findings.push(f);
            }
            if let Some(f) = self.check_ssrf_for_tool(tool) {
                findings.push(f);
            }

            findings
        })
        .buffer_unordered(concurrency)
        .collect()
        .await;

    // Aggregate results
    for findings in all_findings {
        for finding in findings {
            results.add_finding(finding);
        }
    }
}
```

### Example 2: Parallel Security Payload Testing

```rust
// In src/validator/engine.rs

async fn run_security_payloads_parallel(
    &self,
    client: &McpClient,  // Would need Arc<Mutex<>> for true parallelism
    tools: &[Tool],
    payloads: &[&str],
) -> Vec<ValidationResult> {
    use futures::stream::{self, StreamExt};

    let tool_payload_pairs: Vec<_> = tools.iter()
        .flat_map(|tool| payloads.iter().map(move |payload| (tool, *payload)))
        .collect();

    let concurrency = num_cpus::get().min(tool_payload_pairs.len()).max(1);

    stream::iter(tool_payload_pairs)
        .map(|(tool, payload)| async move {
            // Test this tool with this payload
            self.test_payload(client, tool, payload).await
        })
        .buffer_unordered(concurrency)
        .collect()
        .await
}
```

## Conclusion

This optimization plan targets the most impactful bottlenecks in MCPLint's scanning infrastructure. By applying the `futures::stream` + `buffer_unordered` pattern to independent operations, we can achieve significant performance improvements without major architectural changes.

The phased approach allows incremental delivery of benefits while managing risk through thorough testing at each stage.
