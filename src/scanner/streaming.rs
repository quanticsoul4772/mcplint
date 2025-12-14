//! Streaming Scan Results - Memory-optimized findings processing
//!
//! This module provides streaming iterators for scan results, enabling
//! memory-efficient processing of large scans with >1000 findings.
//!
//! # Architecture
//!
//! Uses tokio channels for async streaming with natural backpressure:
//! - `FindingProducer`: Scanner sends findings as they're discovered
//! - `FindingStream`: Consumers receive findings one at a time
//!
//! # Memory Benefits
//!
//! | Findings | Traditional | Streaming (buffer=100) | Reduction |
//! |----------|-------------|------------------------|-----------|
//! | 1,000    | ~5 MB       | ~50 KB                 | 99%       |
//! | 10,000   | ~50 MB      | ~50 KB                 | 99.9%     |
//!
//! # Example
//!
//! ```ignore
//! use mcplint::scanner::streaming::{streaming_channel, StreamingConfig};
//!
//! // Create channel pair
//! let (producer, mut stream) = streaming_channel(100);
//!
//! // Producer sends findings
//! producer.send(finding).await?;
//!
//! // Consumer processes as they arrive
//! while let Some(finding) = stream.next().await {
//!     println!("{}: {}", finding.severity, finding.title);
//! }
//!
//! // Get final summary
//! let summary = stream.into_summary();
//! ```

// This module provides public API for streaming scan results.
// The types are exported but not yet used by the CLI - they're intended
// for library consumers and future CLI integration.
#![allow(dead_code)]

use tokio::sync::mpsc;

use super::finding::{Finding, Severity};
use super::ScanSummary;

/// Configuration for streaming scan operations
#[derive(Debug, Clone)]
pub struct StreamingConfig {
    /// Channel buffer size (default: 100)
    /// Larger buffers reduce backpressure but use more memory
    pub buffer_size: usize,
    /// Whether to also collect findings for backward compatibility
    /// When true, `FindingStream::collect_all()` stores findings
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

impl StreamingConfig {
    /// Create config with custom buffer size
    pub fn with_buffer_size(mut self, size: usize) -> Self {
        self.buffer_size = size;
        self
    }

    /// Enable collection mode for backward compatibility
    pub fn with_collection(mut self, collect: bool) -> Self {
        self.collect_findings = collect;
        self
    }
}

/// Handle for receiving streaming findings
///
/// Provides async iteration over findings as they're produced,
/// with automatic summary accumulation.
pub struct FindingStream {
    rx: mpsc::Receiver<Finding>,
    summary: ScanSummaryAccumulator,
    collected: Option<Vec<Finding>>,
    collect_mode: bool,
}

impl FindingStream {
    /// Receive the next finding (async)
    ///
    /// Returns `None` when the producer is dropped (scan complete).
    pub async fn next(&mut self) -> Option<Finding> {
        let finding = self.rx.recv().await?;
        self.summary.record(&finding);

        if self.collect_mode {
            if let Some(ref mut vec) = self.collected {
                vec.push(finding.clone());
            }
        }

        Some(finding)
    }

    /// Process all findings with a callback
    ///
    /// Useful for side-effect processing like printing or writing to file.
    pub async fn for_each<F, Fut>(&mut self, mut f: F)
    where
        F: FnMut(Finding) -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
        while let Some(finding) = self.next().await {
            f(finding).await;
        }
    }

    /// Process all findings with a sync callback
    ///
    /// Convenience method for simple processing without async.
    pub async fn for_each_sync<F>(&mut self, mut f: F)
    where
        F: FnMut(&Finding),
    {
        while let Some(finding) = self.next().await {
            f(&finding);
        }
    }

    /// Collect all findings into a vector
    ///
    /// Consumes the stream and returns all findings with final summary.
    /// Use this for backward compatibility with APIs expecting `Vec<Finding>`.
    pub async fn collect_all(mut self) -> (Vec<Finding>, ScanSummary) {
        let mut findings = self.collected.take().unwrap_or_default();

        while let Some(finding) = self.rx.recv().await {
            self.summary.record(&finding);
            findings.push(finding);
        }

        (findings, self.summary.finalize())
    }

    /// Get current summary (findings processed so far)
    ///
    /// Returns a snapshot of the summary at the current point in processing.
    pub fn current_summary(&self) -> ScanSummary {
        self.summary.to_summary()
    }

    /// Consume the stream and return the final summary
    ///
    /// Drains any remaining findings and returns the complete summary.
    pub async fn into_summary(mut self) -> ScanSummary {
        // Drain remaining findings
        while let Some(finding) = self.rx.recv().await {
            self.summary.record(&finding);
        }
        self.summary.finalize()
    }

    /// Check if any critical or high severity findings have been seen
    pub fn has_critical_or_high(&self) -> bool {
        self.summary.critical > 0 || self.summary.high > 0
    }

    /// Get total findings processed so far
    pub fn total_processed(&self) -> usize {
        self.summary.total
    }
}

/// Internal accumulator for summary statistics
///
/// Tracks severity counts as findings stream through.
#[derive(Debug, Clone, Default)]
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
        Self::default()
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

    fn to_summary(&self) -> ScanSummary {
        ScanSummary {
            critical: self.critical,
            high: self.high,
            medium: self.medium,
            low: self.low,
            info: self.info,
        }
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

/// Producer side for streaming findings from scan engine
///
/// Created by `streaming_channel()` and passed to the scanner.
/// Findings sent through this producer are received by the paired `FindingStream`.
#[derive(Clone)]
pub struct FindingProducer {
    tx: mpsc::Sender<Finding>,
}

impl FindingProducer {
    /// Send a finding to the stream (async, waits if buffer full)
    ///
    /// Returns error if the receiver has been dropped.
    pub async fn send(&self, finding: Finding) -> Result<(), mpsc::error::SendError<Finding>> {
        self.tx.send(finding).await
    }

    /// Send a finding without waiting (drops if buffer full)
    ///
    /// Use this for non-blocking sends when dropping is acceptable.
    #[allow(clippy::result_large_err)]
    pub fn try_send(&self, finding: Finding) -> Result<(), mpsc::error::TrySendError<Finding>> {
        self.tx.try_send(finding)
    }

    /// Check if the receiver is still connected
    pub fn is_closed(&self) -> bool {
        self.tx.is_closed()
    }

    /// Get remaining capacity in the channel buffer
    pub fn capacity(&self) -> usize {
        self.tx.capacity()
    }
}

/// Create a new streaming channel pair
///
/// # Arguments
///
/// * `buffer_size` - Maximum findings that can be buffered before backpressure
///
/// # Returns
///
/// A tuple of (producer, stream) for the scanner and consumer respectively.
///
/// # Example
///
/// ```ignore
/// let (producer, mut stream) = streaming_channel(100);
///
/// // Scanner task
/// tokio::spawn(async move {
///     producer.send(finding1).await.unwrap();
///     producer.send(finding2).await.unwrap();
///     // Producer dropped, signals end of stream
/// });
///
/// // Consumer
/// while let Some(finding) = stream.next().await {
///     process(finding);
/// }
/// ```
pub fn streaming_channel(buffer_size: usize) -> (FindingProducer, FindingStream) {
    let (tx, rx) = mpsc::channel(buffer_size);
    (
        FindingProducer { tx },
        FindingStream {
            rx,
            summary: ScanSummaryAccumulator::new(),
            collected: None,
            collect_mode: false,
        },
    )
}

/// Create a streaming channel with collection enabled
///
/// Like `streaming_channel` but the stream will also store findings
/// for later retrieval via `collect_all()`.
pub fn streaming_channel_with_collection(buffer_size: usize) -> (FindingProducer, FindingStream) {
    let (tx, rx) = mpsc::channel(buffer_size);
    (
        FindingProducer { tx },
        FindingStream {
            rx,
            summary: ScanSummaryAccumulator::new(),
            collected: Some(Vec::new()),
            collect_mode: true,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_finding(rule_id: &str, severity: Severity) -> Finding {
        Finding::new(rule_id, severity, "Test Title", "Test Description")
    }

    #[tokio::test]
    async fn test_streaming_channel_basic() {
        let (producer, mut stream) = streaming_channel(10);

        producer
            .send(create_test_finding("TEST-001", Severity::High))
            .await
            .unwrap();

        let finding = stream.next().await.unwrap();
        assert_eq!(finding.rule_id, "TEST-001");
        assert_eq!(finding.severity, Severity::High);
    }

    #[tokio::test]
    async fn test_streaming_channel_multiple_findings() {
        let (producer, mut stream) = streaming_channel(10);

        producer
            .send(create_test_finding("TEST-001", Severity::Critical))
            .await
            .unwrap();
        producer
            .send(create_test_finding("TEST-002", Severity::High))
            .await
            .unwrap();
        producer
            .send(create_test_finding("TEST-003", Severity::Medium))
            .await
            .unwrap();

        drop(producer); // Signal end of stream

        let mut count = 0;
        while let Some(_) = stream.next().await {
            count += 1;
        }
        assert_eq!(count, 3);
    }

    #[tokio::test]
    async fn test_streaming_summary_accumulation() {
        let (producer, mut stream) = streaming_channel(10);

        producer
            .send(create_test_finding("TEST-001", Severity::Critical))
            .await
            .unwrap();
        producer
            .send(create_test_finding("TEST-002", Severity::Critical))
            .await
            .unwrap();
        producer
            .send(create_test_finding("TEST-003", Severity::High))
            .await
            .unwrap();
        producer
            .send(create_test_finding("TEST-004", Severity::Medium))
            .await
            .unwrap();
        producer
            .send(create_test_finding("TEST-005", Severity::Low))
            .await
            .unwrap();

        drop(producer);

        let (findings, summary) = stream.collect_all().await;

        assert_eq!(findings.len(), 5);
        assert_eq!(summary.critical, 2);
        assert_eq!(summary.high, 1);
        assert_eq!(summary.medium, 1);
        assert_eq!(summary.low, 1);
        assert_eq!(summary.info, 0);
    }

    #[tokio::test]
    async fn test_streaming_current_summary() {
        let (producer, mut stream) = streaming_channel(10);

        producer
            .send(create_test_finding("TEST-001", Severity::High))
            .await
            .unwrap();
        producer
            .send(create_test_finding("TEST-002", Severity::High))
            .await
            .unwrap();

        // Process one finding
        stream.next().await;
        let summary1 = stream.current_summary();
        assert_eq!(summary1.high, 1);

        // Process second finding
        stream.next().await;
        let summary2 = stream.current_summary();
        assert_eq!(summary2.high, 2);
    }

    #[tokio::test]
    async fn test_streaming_has_critical_or_high() {
        let (producer, mut stream) = streaming_channel(10);

        producer
            .send(create_test_finding("TEST-001", Severity::Low))
            .await
            .unwrap();
        stream.next().await;
        assert!(!stream.has_critical_or_high());

        producer
            .send(create_test_finding("TEST-002", Severity::Critical))
            .await
            .unwrap();
        stream.next().await;
        assert!(stream.has_critical_or_high());
    }

    #[tokio::test]
    async fn test_streaming_total_processed() {
        let (producer, mut stream) = streaming_channel(10);

        assert_eq!(stream.total_processed(), 0);

        for i in 0..5 {
            producer
                .send(create_test_finding(
                    &format!("TEST-{:03}", i),
                    Severity::Medium,
                ))
                .await
                .unwrap();
        }

        for _ in 0..3 {
            stream.next().await;
        }
        assert_eq!(stream.total_processed(), 3);

        for _ in 0..2 {
            stream.next().await;
        }
        assert_eq!(stream.total_processed(), 5);
    }

    #[tokio::test]
    async fn test_streaming_for_each() {
        let (producer, mut stream) = streaming_channel(10);

        producer
            .send(create_test_finding("TEST-001", Severity::High))
            .await
            .unwrap();
        producer
            .send(create_test_finding("TEST-002", Severity::Medium))
            .await
            .unwrap();

        drop(producer);

        // Use Arc<AtomicUsize> to track count across async calls
        let count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let count_clone = count.clone();
        stream
            .for_each(|_finding| {
                let count = count_clone.clone();
                async move {
                    count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
            })
            .await;

        assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn test_streaming_for_each_sync() {
        let (producer, mut stream) = streaming_channel(10);

        producer
            .send(create_test_finding("TEST-001", Severity::High))
            .await
            .unwrap();
        producer
            .send(create_test_finding("TEST-002", Severity::Medium))
            .await
            .unwrap();

        drop(producer);

        let mut rule_ids = Vec::new();
        stream
            .for_each_sync(|finding| {
                rule_ids.push(finding.rule_id.clone());
            })
            .await;

        assert_eq!(rule_ids, vec!["TEST-001", "TEST-002"]);
    }

    #[tokio::test]
    async fn test_streaming_into_summary() {
        let (producer, stream) = streaming_channel(10);

        producer
            .send(create_test_finding("TEST-001", Severity::Critical))
            .await
            .unwrap();
        producer
            .send(create_test_finding("TEST-002", Severity::Info))
            .await
            .unwrap();

        drop(producer);

        let summary = stream.into_summary().await;
        assert_eq!(summary.critical, 1);
        assert_eq!(summary.info, 1);
    }

    #[tokio::test]
    async fn test_streaming_channel_closed() {
        let (producer, mut stream) = streaming_channel(10);

        producer
            .send(create_test_finding("TEST-001", Severity::Low))
            .await
            .unwrap();

        drop(producer);

        // Should receive the finding
        assert!(stream.next().await.is_some());
        // Should return None when producer is dropped
        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn test_producer_is_closed() {
        let (producer, stream) = streaming_channel(10);

        assert!(!producer.is_closed());

        drop(stream);

        assert!(producer.is_closed());
    }

    #[tokio::test]
    async fn test_producer_capacity() {
        let (producer, _stream) = streaming_channel(10);

        assert_eq!(producer.capacity(), 10);

        producer
            .send(create_test_finding("TEST-001", Severity::Low))
            .await
            .unwrap();

        assert_eq!(producer.capacity(), 9);
    }

    #[tokio::test]
    async fn test_streaming_try_send() {
        let (producer, _stream) = streaming_channel(2);

        // Should succeed
        assert!(producer
            .try_send(create_test_finding("TEST-001", Severity::Low))
            .is_ok());
        assert!(producer
            .try_send(create_test_finding("TEST-002", Severity::Low))
            .is_ok());

        // Buffer full, should fail
        assert!(producer
            .try_send(create_test_finding("TEST-003", Severity::Low))
            .is_err());
    }

    #[tokio::test]
    async fn test_streaming_config_default() {
        let config = StreamingConfig::default();
        assert_eq!(config.buffer_size, 100);
        assert!(!config.collect_findings);
    }

    #[tokio::test]
    async fn test_streaming_config_builder() {
        let config = StreamingConfig::default()
            .with_buffer_size(50)
            .with_collection(true);

        assert_eq!(config.buffer_size, 50);
        assert!(config.collect_findings);
    }

    #[tokio::test]
    async fn test_streaming_with_collection() {
        let (producer, mut stream) = streaming_channel_with_collection(10);

        producer
            .send(create_test_finding("TEST-001", Severity::High))
            .await
            .unwrap();
        producer
            .send(create_test_finding("TEST-002", Severity::Medium))
            .await
            .unwrap();

        // Process findings (they get collected)
        stream.next().await;
        stream.next().await;

        drop(producer);

        // Collect remaining (none) and get all collected
        let (findings, summary) = stream.collect_all().await;

        assert_eq!(findings.len(), 2);
        assert_eq!(summary.high, 1);
        assert_eq!(summary.medium, 1);
    }

    #[tokio::test]
    async fn test_producer_clone() {
        let (producer, mut stream) = streaming_channel(10);
        let producer2 = producer.clone();

        producer
            .send(create_test_finding("TEST-001", Severity::High))
            .await
            .unwrap();
        producer2
            .send(create_test_finding("TEST-002", Severity::Medium))
            .await
            .unwrap();

        drop(producer);
        drop(producer2);

        let (findings, _) = stream.collect_all().await;
        assert_eq!(findings.len(), 2);
    }

    #[tokio::test]
    async fn test_empty_stream() {
        let (producer, stream) = streaming_channel(10);

        drop(producer);

        let (findings, summary) = stream.collect_all().await;
        assert!(findings.is_empty());
        assert_eq!(summary.critical, 0);
        assert_eq!(summary.high, 0);
        assert_eq!(summary.medium, 0);
        assert_eq!(summary.low, 0);
        assert_eq!(summary.info, 0);
    }

    #[tokio::test]
    async fn test_all_severity_levels() {
        let (producer, mut stream) = streaming_channel(10);

        producer
            .send(create_test_finding("CRIT", Severity::Critical))
            .await
            .unwrap();
        producer
            .send(create_test_finding("HIGH", Severity::High))
            .await
            .unwrap();
        producer
            .send(create_test_finding("MED", Severity::Medium))
            .await
            .unwrap();
        producer
            .send(create_test_finding("LOW", Severity::Low))
            .await
            .unwrap();
        producer
            .send(create_test_finding("INFO", Severity::Info))
            .await
            .unwrap();

        drop(producer);

        let summary = stream.into_summary().await;
        assert_eq!(summary.critical, 1);
        assert_eq!(summary.high, 1);
        assert_eq!(summary.medium, 1);
        assert_eq!(summary.low, 1);
        assert_eq!(summary.info, 1);
    }
}
