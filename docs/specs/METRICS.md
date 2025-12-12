# MCPLint Performance Metrics & Acceptance Criteria

This document defines quantifiable success metrics for each phase of the MCPLint CLI implementation.

## Global Performance Targets

| Metric | Target | Measurement Method |
|--------|--------|-------------------|
| CLI startup time | < 100ms | `time mcplint --version` |
| Memory baseline | < 50MB | RSS at idle |
| Exit code consistency | 100% | All commands follow exit code spec |

## Phase 1: Smart Context Detection

### Response Time Targets

| Operation | Target | Conditions |
|-----------|--------|------------|
| Config file detection | < 50ms | Standard locations |
| Server resolution | < 100ms | From config name |
| Transport type detection | < 10ms | URL/path analysis |

### Accuracy Metrics

| Metric | Target |
|--------|--------|
| Correct config file detection | 100% (standard locations) |
| Server name resolution accuracy | 100% (valid config entries) |
| Transport type inference accuracy | 100% (http/https/stdio) |

### Memory Limits

| Scenario | Limit |
|----------|-------|
| Config parsing (< 100 servers) | < 10MB |
| Config parsing (100-1000 servers) | < 50MB |

## Phase 2: Progress Indicators

### Response Time Targets

| Operation | Target | Conditions |
|-----------|--------|------------|
| Progress bar initialization | < 10ms | Any operation |
| Progress update frequency | 100ms intervals | During scans |
| Spinner frame rate | 10 FPS | During connection |

### User Experience Metrics

| Metric | Target |
|--------|--------|
| Time to first visual feedback | < 500ms |
| Progress accuracy | ±5% of actual completion |
| ETA accuracy (after 25% complete) | ±20% |

### Memory Limits

| Scenario | Limit |
|----------|-------|
| Progress tracking overhead | < 5MB |
| Multi-operation progress | < 10MB |

## Phase 3: Interactive Mode

### Response Time Targets

| Operation | Target |
|-----------|--------|
| REPL prompt display | < 50ms |
| Command parsing | < 10ms |
| Tab completion response | < 100ms |
| History search | < 50ms |

### Reliability Metrics

| Metric | Target |
|--------|--------|
| Command history persistence | 100% |
| Graceful exit on Ctrl+C | 100% |
| Session state consistency | 100% |

### Memory Limits

| Scenario | Limit |
|----------|-------|
| REPL session (1 hour) | < 100MB |
| Command history (1000 entries) | < 5MB |

## Phase 4: Error Messages & Help

### Response Time Targets

| Operation | Target |
|-----------|--------|
| Help text display | < 50ms |
| Error message formatting | < 10ms |
| Suggestion generation | < 100ms |

### Quality Metrics

| Metric | Target |
|--------|--------|
| Error message actionability | 100% (include fix suggestion) |
| Help coverage | 100% (all commands documented) |
| Example accuracy | 100% (all examples work) |

## Phase 5: Shell Completions & Watch Mode

### Shell Completions

| Metric | Target |
|--------|--------|
| Completion script generation | < 100ms |
| Runtime completion response | < 200ms |
| Server name completion | < 500ms (requires config read) |

### Watch Mode

| Operation | Target | Conditions |
|-----------|--------|------------|
| File change detection | < 100ms | notify crate |
| Debounce window | 500ms default | Configurable |
| Rescan trigger | < 1s after debounce | |

### Watch Mode Limits

| Scenario | Limit | Behavior if Exceeded |
|----------|-------|---------------------|
| Watched files | 10,000 | Warning + suggest filters |
| Watched directories | 100 | Warning + suggest specific paths |
| Memory (500 files) | < 100MB | |
| Memory (5000 files) | < 250MB | |
| Events per second | 100 | Aggressive debouncing |

## Phase 6: CI/CD Integration

### Response Time Targets

| Operation | Target | Conditions |
|-----------|--------|------------|
| SARIF output generation | < 100ms | < 100 findings |
| JUnit output generation | < 100ms | < 100 findings |
| Baseline comparison | < 500ms | < 1000 findings |

### Reliability Metrics

| Metric | Target |
|--------|--------|
| Exit code correctness | 100% |
| Output format validity | 100% (parseable by tools) |
| Baseline determinism | 100% (same input = same output) |

### CI Performance

| Scenario | Target |
|----------|--------|
| Simple scan (< 10 tools) | < 5s total |
| Medium scan (10-50 tools) | < 15s total |
| Full scan (50+ tools) | < 30s total |
| Fuzz session (quick) | < 60s |

## Phase 7: Polish & Documentation

### Documentation Metrics

| Metric | Target |
|--------|--------|
| README completeness | 100% commands documented |
| Example coverage | 1+ example per command |
| API documentation | 100% public items |

## Measurement & Validation

### Automated Benchmarks

```bash
# Run performance benchmarks
cargo bench

# Run memory profiling
cargo run --release -- scan <server> &
sleep 5
ps -o rss -p $!
```

### CI Integration

```yaml
# .github/workflows/benchmarks.yml
- name: Performance regression check
  run: |
    cargo bench -- --save-baseline main
    # Fail if > 10% regression
```

### Manual Validation Checklist

- [ ] All response time targets met on CI hardware
- [ ] Memory limits verified with valgrind/heaptrack
- [ ] Exit codes match specification
- [ ] Output formats validate against schemas
