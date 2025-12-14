# Memory Optimization for Large Scans

## Design Document

**Version:** 1.0
**Date:** 2025-12-14
**Status:** Proposed

---

## 1. Problem Statement

### Current Issue
MCPLint's scanner collects all findings into memory before processing:

```rust
// Current pattern in scanner/engine.rs
pub struct ScanResults {
    pub findings: Vec<Finding>,  // All findings loaded at once
    // ...
}

impl ScanResults {
    pub fn add_finding(&mut self, finding: Finding) {
        self.findings.push(finding);  // Accumulates in memory
    }
}
```

### Impact
- **Memory pressure**: Large scans with >1000 findings consume significant memory
- **Latency**: Consumers must wait for full scan completion before processing
- **Scalability**: Multi-server scans multiply the memory problem

### Memory Profile (Current)
| Findings | Estimated Memory |
|----------|------------------|
| 100      | ~500 KB          |
| 1,000    | ~5 MB            |
| 10,000   | ~50 MB           |
| 100,000  | ~500 MB          |

Each `Finding` struct contains:
- `id`: String (~40 bytes UUID)
- `rule_id`: String (~15 bytes)
- `severity`: Enum (1 byte)
- `title`: String (~50 bytes avg)
- `description`: String (~200 bytes avg)
- `location`: FindingLocation (~100 bytes)
- `evidence`: Vec<Evidence> (~200 bytes avg)
- `remediation`: String (~100 bytes avg)
- `references`: Vec<Reference> (~100 bytes)
- `metadata`: FindingMetadata (~50 bytes)

**Total per Finding**: ~500-800 bytes + heap allocations

---

## 2. Proposed Solution

### Architecture: Streaming Results with Channels

Instead of collecting all findings, use **async channels** for streaming results:

```rust
// New streaming architecture
use tokio::sync::mpsc;

pub struct StreamingScanSession {
    finding_tx: mpsc::Sender<Finding>,
    summary_tx: mpsc::Sender<ScanSummary>,
}

pub struct StreamingScanResults {
    pub server: String,
    pub profile: String,
    pub finding_rx: mpsc::Receiver<Finding>,
    pub summary: Option<ScanSummary>,
}
```

### Why Channels Over streaming-iterator Crate?

After analysis, **tokio channels** are preferred over the `streaming-iterator` crate because:

1. **Async compatibility**: MCPLint is already async (tokio-based)
2. **Backpressure**: Bounded channels provide natural backpressure
3. **No external dependency**: Uses existing tokio infrastructure
4. **Producer-consumer decoupling**: Scanner produces, reporters/UI consume independently

---

## 3. Implementation Plan

### Phase 1: Core Streaming Infrastructure

#### 3.1 New Types (scanner/streaming.rs)

```rust
use tokio::sync::mpsc;
use crate::scanner::finding::{Finding, Severity};

/// Configuration for streaming scan
pub struct StreamingConfig {
    /// Channel buffer size (default: 100)
    pub buffer_size: usize,
    /// Whether to also collect findings (for backward compat)
    pub collect_findings: bool,
}

impl Default for StreamingConfig {
    fn default() -> Self {
        Self {
            buffer_size: 100,
            collect_findings: false,
        }
    }
}

/// Handle for receiving streaming findings
pub struct FindingStream {
    rx: mpsc::Receiver<Finding>,
    summary: ScanSummaryAccumulator,
}

impl FindingStream {
    /// Receive the next finding (async)
    pub async fn next(&mut self) -> Option<Finding> {
        let finding = self.rx.recv().await?;
        self.summary.record(&finding);
        Some(finding)
    }

    /// Process all findings with a callback
    pub async fn for_each<F, Fut>(&mut self, mut f: F)
    where
        F: FnMut(Finding) -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
        while let Some(finding) = self.next().await {
            f(finding).await;
        }
    }

    /// Collect all findings (when needed for backward compat)
    pub async fn collect_all(mut self) -> (Vec<Finding>, ScanSummary) {
        let mut findings = Vec::new();
        while let Some(finding) = self.next().await {
            findings.push(finding);
        }
        (findings, self.summary.finalize())
    }

    /// Get current summary (findings processed so far)
    pub fn current_summary(&self) -> &ScanSummary {
        self.summary.current()
    }
}

/// Internal accumulator for summary stats
struct ScanSummaryAccumulator {
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
    info: usize,
    total: usize,
}

impl ScanSummaryAccumulator {
    fn new() -> Self {
        Self {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            info: 0,
            total: 0,
        }
    }

    fn record(&mut self, finding: &Finding) {
        self.total += 1;
        match finding.severity {
            Severity::Critical => self.critical += 1,
            Severity::High => self.high += 1,
            Severity::Medium => self.medium += 1,
            Severity::Low => self.low += 1,
            Severity::Info => self.info += 1,
        }
    }

    fn current(&self) -> &ScanSummary {
        // Return current state (requires lifetime adjustment)
        todo!()
    }

    fn finalize(self) -> ScanSummary {
        ScanSummary {
            critical: self.critical,
            high: self.high,
            medium: self.medium,
            low: self.low,
            info: self.info,
        }
    }
}

/// Producer side for scan engine
pub struct FindingProducer {
    tx: mpsc::Sender<Finding>,
}

impl FindingProducer {
    /// Send a finding to the stream
    pub async fn send(&self, finding: Finding) -> Result<(), mpsc::error::SendError<Finding>> {
        self.tx.send(finding).await
    }

    /// Send a finding (non-blocking, drops if full)
    pub fn try_send(&self, finding: Finding) -> Result<(), mpsc::error::TrySendError<Finding>> {
        self.tx.try_send(finding)
    }
}

/// Create a new streaming channel pair
pub fn streaming_channel(buffer_size: usize) -> (FindingProducer, FindingStream) {
    let (tx, rx) = mpsc::channel(buffer_size);
    (
        FindingProducer { tx },
        FindingStream {
            rx,
            summary: ScanSummaryAccumulator::new(),
        },
    )
}
```

#### 3.2 Extended ScanEngine API

```rust
impl ScanEngine {
    /// Run a streaming security scan
    pub async fn scan_streaming(
        &self,
        target: &str,
        args: &[String],
        transport_type: Option<TransportType>,
    ) -> Result<FindingStream> {
        let (producer, stream) = streaming_channel(
            self.config.streaming.buffer_size
        );

        // Spawn scan task
        let config = self.config.clone();
        let target = target.to_string();
        let args = args.to_vec();

        tokio::spawn(async move {
            let engine = ScanEngine::new(config);
            // Run scan, sending findings to producer
            if let Err(e) = engine.scan_to_producer(&target, &args, transport_type, producer).await {
                tracing::error!("Streaming scan error: {}", e);
            }
        });

        Ok(stream)
    }

    /// Internal: Run scan sending findings to producer
    async fn scan_to_producer(
        &self,
        target: &str,
        args: &[String],
        transport_type: Option<TransportType>,
        producer: FindingProducer,
    ) -> Result<()> {
        // ... connect to server ...

        // Run checks, streaming findings
        self.run_injection_checks_streaming(&ctx, &mut client, &producer).await;
        self.run_auth_checks_streaming(&ctx, &producer).await;
        // ... etc

        Ok(())
    }
}
```

### Phase 2: Consumer Adaptations

#### 3.3 Streaming SARIF Reporter

```rust
impl SarifReport {
    /// Create SARIF report from streaming findings
    pub async fn from_streaming(
        mut stream: FindingStream,
        server: &str,
    ) -> Self {
        let mut report = SarifReport::new();
        let mut results = Vec::new();
        let mut seen_rules = HashSet::new();
        let mut rules = Vec::new();

        while let Some(finding) = stream.next().await {
            // Add rule if not seen
            if seen_rules.insert(finding.rule_id.clone()) {
                rules.push(SarifRule::from_finding(&finding));
            }

            // Add result
            results.push(SarifResult::from_finding(&finding));
        }

        report.runs.push(SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "MCPLint".to_string(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    information_uri: "https://github.com/quanticsoul4772/mcplint".to_string(),
                    rules,
                },
            },
            results,
        });

        report
    }
}
```

#### 3.4 Streaming CLI Output

```rust
/// Print findings as they arrive
pub async fn print_streaming_findings(
    mut stream: FindingStream,
    format: OutputFormat,
) -> Result<ScanSummary> {
    match format {
        OutputFormat::Text => {
            while let Some(finding) = stream.next().await {
                print_finding_text(&finding);
            }
        }
        OutputFormat::Json => {
            // Write JSON array incrementally
            print!("[");
            let mut first = true;
            while let Some(finding) = stream.next().await {
                if !first { print!(","); }
                first = false;
                print!("{}", serde_json::to_string(&finding)?);
            }
            println!("]");
        }
        // ... other formats
    }

    Ok(stream.current_summary().clone())
}
```

### Phase 3: Backward Compatibility Layer

```rust
impl ScanEngine {
    /// Original API - collects all findings (for backward compat)
    pub async fn scan(
        &self,
        target: &str,
        args: &[String],
        transport_type: Option<TransportType>,
    ) -> Result<ScanResults> {
        let stream = self.scan_streaming(target, args, transport_type).await?;
        let (findings, summary) = stream.collect_all().await;

        Ok(ScanResults {
            server: target.to_string(),
            profile: self.config.profile.to_string(),
            total_checks: self.config.total_checks(),
            findings,
            summary,
            duration_ms: 0, // Tracked separately
        })
    }
}
```

---

## 4. Memory Benefits Analysis

### Streaming Mode Memory Profile

| Scenario | Current | Streaming (buffer=100) | Reduction |
|----------|---------|------------------------|-----------|
| 1,000 findings | 5 MB | ~50 KB | **99%** |
| 10,000 findings | 50 MB | ~50 KB | **99.9%** |
| Multi-server (10 × 1000) | 50 MB | ~500 KB | **99%** |

### Trade-offs

| Aspect | Current | Streaming |
|--------|---------|-----------|
| Memory | O(n) | O(buffer_size) |
| Latency to first result | High (scan complete) | Low (immediate) |
| Random access | ✅ Yes | ❌ No |
| Multiple iterations | ✅ Yes | ❌ No (consume once) |
| Serialization | Simple | Requires buffering |
| Complexity | Low | Medium |

---

## 5. Implementation Priority

### High Priority (Phase 1)
1. ✅ `scanner/streaming.rs` - Core streaming types
2. ✅ `ScanEngine::scan_streaming()` - Streaming scan API
3. ✅ Backward compatibility wrapper

### Medium Priority (Phase 2)
4. CLI streaming output support
5. SARIF streaming generation
6. Multi-server streaming aggregation

### Lower Priority (Phase 3)
7. Watch mode streaming integration
8. AI explain streaming batch processing
9. Baseline diff streaming comparison

---

## 6. Testing Strategy

### Unit Tests
```rust
#[tokio::test]
async fn test_streaming_channel_basic() {
    let (producer, mut stream) = streaming_channel(10);

    producer.send(Finding::new("TEST-001", Severity::High, "Test", "Desc")).await.unwrap();

    let finding = stream.next().await.unwrap();
    assert_eq!(finding.rule_id, "TEST-001");
}

#[tokio::test]
async fn test_streaming_summary_accumulation() {
    let (producer, mut stream) = streaming_channel(10);

    for i in 0..5 {
        producer.send(Finding::new(&format!("TEST-{:03}", i), Severity::High, "T", "D")).await.unwrap();
    }
    drop(producer);  // Close channel

    let (findings, summary) = stream.collect_all().await;
    assert_eq!(findings.len(), 5);
    assert_eq!(summary.high, 5);
}

#[tokio::test]
async fn test_streaming_backpressure() {
    let (producer, stream) = streaming_channel(2);  // Small buffer

    // Fill buffer
    producer.send(Finding::new("TEST-001", Severity::High, "T", "D")).await.unwrap();
    producer.send(Finding::new("TEST-002", Severity::High, "T", "D")).await.unwrap();

    // This should block (or return error with try_send)
    assert!(producer.try_send(Finding::new("TEST-003", Severity::High, "T", "D")).is_err());
}
```

### Integration Tests
```rust
#[tokio::test]
async fn test_streaming_scan_integration() {
    let config = ScanConfig::default();
    let engine = ScanEngine::new(config);

    let mut stream = engine.scan_streaming("test-server", &[], None).await.unwrap();

    let mut count = 0;
    while let Some(finding) = stream.next().await {
        count += 1;
        // Process finding immediately
        assert!(!finding.rule_id.is_empty());
    }

    // Summary available after consumption
    let summary = stream.current_summary();
    assert_eq!(summary.total(), count);
}
```

### Memory Benchmarks
```rust
#[bench]
fn bench_current_scan_memory(b: &mut Bencher) {
    // Measure peak memory with current approach
}

#[bench]
fn bench_streaming_scan_memory(b: &mut Bencher) {
    // Measure peak memory with streaming approach
}
```

---

## 7. Migration Path

### Step 1: Add Streaming API (Non-Breaking)
- Add new `scan_streaming()` method
- Keep existing `scan()` unchanged
- Internal tests use streaming

### Step 2: Migrate Consumers (Gradual)
- Update CLI to use streaming where beneficial
- Update reporters to support streaming
- Add feature flag for streaming mode

### Step 3: Default to Streaming (Major Version)
- Make streaming the default in v1.0
- Deprecate collection-based API
- Provide migration guide

---

## 8. Alternatives Considered

### Alternative 1: streaming-iterator Crate
```rust
// Rejected: Sync-only, doesn't fit async architecture
use streaming_iterator::StreamingIterator;
```
**Rejected because**: MCPLint is async-first; streaming-iterator is sync.

### Alternative 2: Pin-based Streaming
```rust
// Rejected: Too complex for this use case
use std::pin::Pin;
use futures::Stream;

struct FindingStream {
    inner: Pin<Box<dyn Stream<Item = Finding> + Send>>,
}
```
**Rejected because**: Channels are simpler and provide backpressure.

### Alternative 3: Callback-based API
```rust
// Rejected: Harder to compose and test
engine.scan_with_callback(target, |finding| {
    println!("{}", finding.title);
});
```
**Rejected because**: Channels are more flexible and composable.

---

## 9. Success Metrics

| Metric | Target |
|--------|--------|
| Memory reduction for 10K findings | ≥95% |
| Latency to first finding | <100ms |
| API backward compatibility | 100% |
| Test coverage | ≥80% |
| Performance regression | <5% |

---

## 10. References

- [Rust Async Streams](https://doc.rust-lang.org/book/ch17-04-streams.html)
- [Tokio Channels](https://tokio.rs/tokio/tutorial/channels)
- [Efficiently Handling Large Data Sets in Rust](https://softwarepatternslexicon.com/patterns-rust/17/4/)
- [streaming-iterator Crate](https://github.com/sfackler/streaming-iterator)

---

## Appendix A: File Changes Summary

| File | Change Type | Description |
|------|-------------|-------------|
| `src/scanner/mod.rs` | Modify | Export streaming module |
| `src/scanner/streaming.rs` | **New** | Core streaming types |
| `src/scanner/engine.rs` | Modify | Add `scan_streaming()` |
| `src/reporter/sarif.rs` | Modify | Add streaming support |
| `src/cli/commands/scan.rs` | Modify | Streaming CLI output |
| `Cargo.toml` | No change | Uses existing tokio |

---

## Appendix B: API Surface

### New Public API
```rust
// scanner/streaming.rs
pub struct StreamingConfig { ... }
pub struct FindingStream { ... }
pub struct FindingProducer { ... }
pub fn streaming_channel(buffer_size: usize) -> (FindingProducer, FindingStream);

// scanner/engine.rs
impl ScanEngine {
    pub async fn scan_streaming(...) -> Result<FindingStream>;
}
```

### Unchanged Public API
```rust
// All existing APIs remain unchanged
impl ScanEngine {
    pub async fn scan(...) -> Result<ScanResults>;  // Still works
}
```
