//! Corpus Management - Seed corpus and crash/hang storage
//!
//! Manages the fuzzing corpus including seed inputs, discovered crashes,
//! hangs, and interesting inputs that trigger new coverage.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use super::input::FuzzInput;

/// Manages fuzzing corpus (seeds, crashes, interesting inputs)
pub struct CorpusManager {
    /// Base path for corpus storage
    base_path: Option<PathBuf>,
    /// Seed inputs
    seeds: Vec<FuzzInput>,
    /// Recorded crashes
    crashes: Vec<CrashRecord>,
    /// Recorded hangs/timeouts
    hangs: Vec<HangRecord>,
    /// Interesting inputs (new coverage)
    interesting: Vec<InterestingInput>,
    /// Current index for round-robin seed selection
    current_index: usize,
    /// Seen input hashes (for deduplication)
    seen_hashes: HashSet<u64>,
}

/// Record of a crash discovered during fuzzing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrashRecord {
    /// Unique crash ID
    pub id: String,
    /// Input that caused the crash
    pub input: FuzzInput,
    /// Type of crash
    pub crash_type: CrashType,
    /// Error message
    pub error_message: String,
    /// Stack trace if available
    pub stack_trace: Option<String>,
    /// Iteration when crash occurred
    pub iteration: u64,
    /// Timestamp
    pub timestamp: String,
}

/// Record of a hang/timeout discovered during fuzzing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HangRecord {
    /// Unique hang ID
    pub id: String,
    /// Input that caused the hang
    pub input: FuzzInput,
    /// Timeout duration in milliseconds
    pub timeout_ms: u64,
    /// Iteration when hang occurred
    pub iteration: u64,
    /// Timestamp
    pub timestamp: String,
}

/// An input that triggered new coverage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterestingInput {
    /// Unique ID
    pub id: String,
    /// The input
    pub input: FuzzInput,
    /// Why it's interesting
    pub reason: InterestingReason,
    /// Coverage hash that was new
    pub coverage_hash: u64,
    /// Iteration when discovered
    pub iteration: u64,
}

/// Types of crashes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CrashType {
    /// Process panicked
    Panic,
    /// Segmentation fault
    Segfault,
    /// Out of memory
    OutOfMemory,
    /// Connection dropped unexpectedly
    ConnectionDrop,
    /// Assertion failure
    AssertionFailure,
    /// Unknown crash type
    Unknown,
}

impl CrashType {
    pub fn as_str(&self) -> &'static str {
        match self {
            CrashType::Panic => "panic",
            CrashType::Segfault => "segfault",
            CrashType::OutOfMemory => "oom",
            CrashType::ConnectionDrop => "connection_drop",
            CrashType::AssertionFailure => "assertion",
            CrashType::Unknown => "unknown",
        }
    }
}

impl std::fmt::Display for CrashType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Why an input is interesting
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InterestingReason {
    /// Triggered new code path
    NewCoverage,
    /// Got unexpected success
    UnexpectedSuccess,
    /// Got new error code
    NewErrorCode,
    /// Protocol violation response
    ProtocolViolation,
}

impl Default for CorpusManager {
    fn default() -> Self {
        Self::new()
    }
}

impl CorpusManager {
    /// Create a new corpus manager
    pub fn new() -> Self {
        Self {
            base_path: None,
            seeds: Vec::new(),
            crashes: Vec::new(),
            hangs: Vec::new(),
            interesting: Vec::new(),
            current_index: 0,
            seen_hashes: HashSet::new(),
        }
    }

    /// Create with a base path for persistence
    pub fn with_path(path: PathBuf) -> Self {
        Self {
            base_path: Some(path),
            seeds: Vec::new(),
            crashes: Vec::new(),
            hangs: Vec::new(),
            interesting: Vec::new(),
            current_index: 0,
            seen_hashes: HashSet::new(),
        }
    }

    /// Initialize corpus with default seeds
    pub fn initialize(&mut self) -> Result<()> {
        self.generate_default_seeds();

        // Load existing corpus if path is set
        if let Some(path) = self.base_path.clone() {
            self.load_from_disk(&path)?;
        }

        Ok(())
    }

    /// Generate default seed corpus
    fn generate_default_seeds(&mut self) {
        // Valid MCP message seeds
        self.seeds.push(FuzzInput::initialize());
        self.seeds.push(FuzzInput::tools_list());
        self.seeds.push(FuzzInput::resources_list());
        self.seeds.push(FuzzInput::prompts_list());
        self.seeds.push(FuzzInput::ping());

        // Edge case seeds
        self.seeds.push(FuzzInput::empty_params());
        self.seeds.push(FuzzInput::null_id());
        self.seeds.push(FuzzInput::string_id("test-id-123"));

        // Tool call with various argument patterns
        self.seeds
            .push(FuzzInput::tool_call("test_tool", serde_json::json!({})));
        self.seeds.push(FuzzInput::tool_call(
            "test_tool",
            serde_json::json!({"key": "value"}),
        ));
        self.seeds.push(FuzzInput::tool_call(
            "test_tool",
            serde_json::json!({"nested": {"key": "value"}}),
        ));

        // Resource reads
        self.seeds
            .push(FuzzInput::resources_read("file:///test.txt"));
        self.seeds
            .push(FuzzInput::resources_read("http://example.com"));

        // Prompts
        self.seeds.push(FuzzInput::prompts_get("test_prompt", None));
        self.seeds.push(FuzzInput::prompts_get(
            "test_prompt",
            Some(serde_json::json!({"arg": "value"})),
        ));
    }

    /// Load corpus from disk
    fn load_from_disk(&mut self, path: &Path) -> Result<()> {
        // Load seeds from seeds directory
        let seeds_dir = path.join("seeds");
        if seeds_dir.exists() {
            let loaded_seeds = Self::load_inputs_from_dir(&seeds_dir)?;
            self.seeds.extend(loaded_seeds);
        }

        // Load crashes (for analysis, not re-execution)
        let crashes_dir = path.join("crashes");
        if crashes_dir.exists() {
            for entry in fs::read_dir(&crashes_dir)? {
                let entry = entry?;
                let file_path = entry.path();
                if file_path.extension().is_some_and(|e| e == "json") {
                    if let Ok(content) = fs::read_to_string(&file_path) {
                        if let Ok(record) = serde_json::from_str::<CrashRecord>(&content) {
                            self.crashes.push(record);
                        }
                    }
                }
            }
        }

        // Load hangs
        let hangs_dir = path.join("hangs");
        if hangs_dir.exists() {
            for entry in fs::read_dir(&hangs_dir)? {
                let entry = entry?;
                let file_path = entry.path();
                if file_path.extension().is_some_and(|e| e == "json") {
                    if let Ok(content) = fs::read_to_string(&file_path) {
                        if let Ok(record) = serde_json::from_str::<HangRecord>(&content) {
                            self.hangs.push(record);
                        }
                    }
                }
            }
        }

        // Load interesting inputs (add to fuzzing corpus)
        let interesting_dir = path.join("interesting");
        if interesting_dir.exists() {
            for entry in fs::read_dir(&interesting_dir)? {
                let entry = entry?;
                let file_path = entry.path();
                if file_path.extension().is_some_and(|e| e == "json") {
                    if let Ok(content) = fs::read_to_string(&file_path) {
                        if let Ok(record) = serde_json::from_str::<InterestingInput>(&content) {
                            self.seen_hashes.insert(record.coverage_hash);
                            self.interesting.push(record);
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Load FuzzInput files from a directory
    fn load_inputs_from_dir(dir: &Path) -> Result<Vec<FuzzInput>> {
        let mut inputs = Vec::new();
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let file_path = entry.path();
            if file_path.extension().is_some_and(|e| e == "json") {
                if let Ok(content) = fs::read_to_string(&file_path) {
                    if let Ok(input) = serde_json::from_str::<FuzzInput>(&content) {
                        inputs.push(input);
                    }
                }
            }
        }
        Ok(inputs)
    }

    /// Save all seeds to disk
    pub fn save_seeds(&self) -> Result<()> {
        if let Some(base) = &self.base_path {
            let seeds_dir = base.join("seeds");
            fs::create_dir_all(&seeds_dir)?;

            for (i, seed) in self.seeds.iter().enumerate() {
                let filename = format!("seed_{:04}.json", i);
                let filepath = seeds_dir.join(filename);
                let json = serde_json::to_string_pretty(seed)?;
                fs::write(filepath, json)?;
            }
        }
        Ok(())
    }

    /// Get the number of seeds
    pub fn seed_count(&self) -> usize {
        self.seeds.len()
    }

    /// Get next input to fuzz (round-robin through seeds + interesting)
    pub fn next_input(&mut self) -> &FuzzInput {
        // Combine seeds and interesting inputs
        let total = self.seeds.len() + self.interesting.len();
        if total == 0 {
            // Fallback - should not happen after initialize()
            self.seeds.push(FuzzInput::ping());
            return &self.seeds[0];
        }

        let idx = self.current_index % total;
        self.current_index = self.current_index.wrapping_add(1);

        if idx < self.seeds.len() {
            &self.seeds[idx]
        } else {
            &self.interesting[idx - self.seeds.len()].input
        }
    }

    /// Add a custom seed input
    pub fn add_seed(&mut self, input: FuzzInput) {
        self.seeds.push(input);
    }

    /// Record a crash
    pub fn record_crash(&mut self, record: CrashRecord) -> Result<()> {
        // Save to disk if path is set
        if let Some(base) = &self.base_path {
            let crashes_dir = base.join("crashes");
            fs::create_dir_all(&crashes_dir)?;

            let filename = format!("crash_{}_{}.json", record.crash_type, record.id);
            let filepath = crashes_dir.join(filename);
            let json = serde_json::to_string_pretty(&record)?;
            fs::write(filepath, json)?;
        }

        self.crashes.push(record);
        Ok(())
    }

    /// Record a hang/timeout
    pub fn record_hang(&mut self, record: HangRecord) -> Result<()> {
        // Save to disk if path is set
        if let Some(base) = &self.base_path {
            let hangs_dir = base.join("hangs");
            fs::create_dir_all(&hangs_dir)?;

            let filename = format!("hang_{}.json", record.id);
            let filepath = hangs_dir.join(filename);
            let json = serde_json::to_string_pretty(&record)?;
            fs::write(filepath, json)?;
        }

        self.hangs.push(record);
        Ok(())
    }

    /// Record an interesting input (new coverage)
    pub fn record_interesting(&mut self, record: InterestingInput) -> Result<()> {
        // Check for duplicates
        if self.seen_hashes.contains(&record.coverage_hash) {
            return Ok(());
        }
        self.seen_hashes.insert(record.coverage_hash);

        // Save to disk if path is set
        if let Some(base) = &self.base_path {
            let interesting_dir = base.join("interesting");
            fs::create_dir_all(&interesting_dir)?;

            let filename = format!("interesting_{}.json", record.id);
            let filepath = interesting_dir.join(filename);
            let json = serde_json::to_string_pretty(&record)?;
            fs::write(filepath, json)?;
        }

        self.interesting.push(record);
        Ok(())
    }

    /// Get all crashes
    pub fn crashes(&self) -> &[CrashRecord] {
        &self.crashes
    }

    /// Get all hangs
    pub fn hangs(&self) -> &[HangRecord] {
        &self.hangs
    }

    /// Get all interesting inputs
    pub fn interesting(&self) -> &[InterestingInput] {
        &self.interesting
    }

    /// Get crash count
    pub fn crash_count(&self) -> usize {
        self.crashes.len()
    }

    /// Get hang count
    pub fn hang_count(&self) -> usize {
        self.hangs.len()
    }

    /// Get interesting count
    pub fn interesting_count(&self) -> usize {
        self.interesting.len()
    }

    /// Get total corpus size (seeds + interesting inputs)
    pub fn corpus_size(&self) -> usize {
        self.seeds.len() + self.interesting.len()
    }

    /// Create a crash record
    pub fn create_crash_record(
        input: FuzzInput,
        crash_type: CrashType,
        error_message: String,
        stack_trace: Option<String>,
        iteration: u64,
    ) -> CrashRecord {
        CrashRecord {
            id: uuid::Uuid::new_v4().to_string(),
            input,
            crash_type,
            error_message,
            stack_trace,
            iteration,
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Create a hang record
    pub fn create_hang_record(input: FuzzInput, timeout_ms: u64, iteration: u64) -> HangRecord {
        HangRecord {
            id: uuid::Uuid::new_v4().to_string(),
            input,
            timeout_ms,
            iteration,
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Create an interesting input record
    pub fn create_interesting_record(
        input: FuzzInput,
        reason: InterestingReason,
        coverage_hash: u64,
        iteration: u64,
    ) -> InterestingInput {
        InterestingInput {
            id: uuid::Uuid::new_v4().to_string(),
            input,
            reason,
            coverage_hash,
            iteration,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_seeds() {
        let mut corpus = CorpusManager::new();
        corpus.initialize().unwrap();

        assert!(corpus.seed_count() > 0);
    }

    #[test]
    fn round_robin_selection() {
        let mut corpus = CorpusManager::new();
        corpus.initialize().unwrap();

        let seed_count = corpus.seed_count();
        let mut methods = std::collections::HashSet::new();

        // Get more inputs than seeds to ensure round-robin
        for _ in 0..(seed_count * 2) {
            let input = corpus.next_input();
            methods.insert(input.method.clone());
        }

        // Should have seen multiple different methods
        assert!(methods.len() > 1);
    }

    #[test]
    fn crash_recording() {
        let mut corpus = CorpusManager::new();
        corpus.initialize().unwrap();

        let crash = CorpusManager::create_crash_record(
            FuzzInput::ping(),
            CrashType::Panic,
            "test panic".to_string(),
            None,
            1,
        );

        corpus.record_crash(crash).unwrap();
        assert_eq!(corpus.crash_count(), 1);
    }

    #[test]
    fn interesting_deduplication() {
        let mut corpus = CorpusManager::new();
        corpus.initialize().unwrap();

        let record1 = CorpusManager::create_interesting_record(
            FuzzInput::ping(),
            InterestingReason::NewCoverage,
            12345,
            1,
        );

        let record2 = CorpusManager::create_interesting_record(
            FuzzInput::tools_list(),
            InterestingReason::NewCoverage,
            12345, // Same hash
            2,
        );

        corpus.record_interesting(record1).unwrap();
        corpus.record_interesting(record2).unwrap();

        // Should only have one (deduplicated by hash)
        assert_eq!(corpus.interesting_count(), 1);
    }

    #[test]
    fn corpus_manager_default() {
        let corpus = CorpusManager::default();
        assert_eq!(corpus.seed_count(), 0);
        assert_eq!(corpus.crash_count(), 0);
        assert_eq!(corpus.hang_count(), 0);
        assert_eq!(corpus.interesting_count(), 0);
    }

    #[test]
    fn corpus_manager_new() {
        let corpus = CorpusManager::new();
        assert_eq!(corpus.corpus_size(), 0);
    }

    #[test]
    fn corpus_manager_with_path() {
        let path = PathBuf::from("/tmp/test_corpus");
        let corpus = CorpusManager::with_path(path);
        assert_eq!(corpus.seed_count(), 0);
    }

    #[test]
    fn crash_type_as_str() {
        assert_eq!(CrashType::Panic.as_str(), "panic");
        assert_eq!(CrashType::Segfault.as_str(), "segfault");
        assert_eq!(CrashType::OutOfMemory.as_str(), "oom");
        assert_eq!(CrashType::ConnectionDrop.as_str(), "connection_drop");
        assert_eq!(CrashType::AssertionFailure.as_str(), "assertion");
        assert_eq!(CrashType::Unknown.as_str(), "unknown");
    }

    #[test]
    fn crash_type_display() {
        assert_eq!(format!("{}", CrashType::Panic), "panic");
        assert_eq!(format!("{}", CrashType::Segfault), "segfault");
        assert_eq!(format!("{}", CrashType::OutOfMemory), "oom");
        assert_eq!(format!("{}", CrashType::ConnectionDrop), "connection_drop");
        assert_eq!(format!("{}", CrashType::AssertionFailure), "assertion");
        assert_eq!(format!("{}", CrashType::Unknown), "unknown");
    }

    #[test]
    fn add_seed() {
        let mut corpus = CorpusManager::new();
        assert_eq!(corpus.seed_count(), 0);

        corpus.add_seed(FuzzInput::ping());
        assert_eq!(corpus.seed_count(), 1);

        corpus.add_seed(FuzzInput::tools_list());
        assert_eq!(corpus.seed_count(), 2);
    }

    #[test]
    fn hang_recording() {
        let mut corpus = CorpusManager::new();
        corpus.initialize().unwrap();

        let hang = CorpusManager::create_hang_record(FuzzInput::ping(), 5000, 1);

        corpus.record_hang(hang).unwrap();
        assert_eq!(corpus.hang_count(), 1);
        assert_eq!(corpus.hangs().len(), 1);
    }

    #[test]
    fn interesting_recording() {
        let mut corpus = CorpusManager::new();
        corpus.initialize().unwrap();

        let record = CorpusManager::create_interesting_record(
            FuzzInput::ping(),
            InterestingReason::NewErrorCode,
            99999,
            1,
        );

        corpus.record_interesting(record).unwrap();
        assert_eq!(corpus.interesting_count(), 1);
        assert_eq!(corpus.interesting().len(), 1);
    }

    #[test]
    fn crashes_accessor() {
        let mut corpus = CorpusManager::new();

        let crash = CorpusManager::create_crash_record(
            FuzzInput::ping(),
            CrashType::Unknown,
            "error".to_string(),
            Some("trace".to_string()),
            1,
        );

        corpus.record_crash(crash).unwrap();
        assert_eq!(corpus.crashes().len(), 1);
        assert_eq!(corpus.crashes()[0].error_message, "error");
    }

    #[test]
    fn corpus_size_calculation() {
        let mut corpus = CorpusManager::new();
        assert_eq!(corpus.corpus_size(), 0);

        corpus.add_seed(FuzzInput::ping());
        assert_eq!(corpus.corpus_size(), 1);

        let record = CorpusManager::create_interesting_record(
            FuzzInput::tools_list(),
            InterestingReason::UnexpectedSuccess,
            11111,
            1,
        );
        corpus.record_interesting(record).unwrap();
        assert_eq!(corpus.corpus_size(), 2);
    }

    #[test]
    fn interesting_reason_variants() {
        let reasons = [
            InterestingReason::NewCoverage,
            InterestingReason::UnexpectedSuccess,
            InterestingReason::NewErrorCode,
            InterestingReason::ProtocolViolation,
        ];

        for reason in reasons {
            let record = CorpusManager::create_interesting_record(
                FuzzInput::ping(),
                reason,
                reason as u64, // unique hash for each
                1,
            );
            assert_eq!(record.reason, reason);
        }
    }

    #[test]
    fn crash_record_with_stack_trace() {
        let crash = CorpusManager::create_crash_record(
            FuzzInput::ping(),
            CrashType::Panic,
            "test error".to_string(),
            Some("at main.rs:42".to_string()),
            100,
        );

        assert_eq!(crash.crash_type, CrashType::Panic);
        assert_eq!(crash.error_message, "test error");
        assert_eq!(crash.stack_trace, Some("at main.rs:42".to_string()));
        assert_eq!(crash.iteration, 100);
        assert!(!crash.id.is_empty());
        assert!(!crash.timestamp.is_empty());
    }

    #[test]
    fn hang_record_fields() {
        let hang = CorpusManager::create_hang_record(FuzzInput::tools_list(), 10000, 50);

        assert_eq!(hang.timeout_ms, 10000);
        assert_eq!(hang.iteration, 50);
        assert!(!hang.id.is_empty());
        assert!(!hang.timestamp.is_empty());
    }

    #[test]
    fn next_input_fallback() {
        let mut corpus = CorpusManager::new();
        // Don't initialize - corpus is empty

        // Should add a fallback and return it
        let input = corpus.next_input();
        assert!(!input.method.is_empty());
    }

    #[test]
    fn crash_type_equality() {
        assert_eq!(CrashType::Panic, CrashType::Panic);
        assert_ne!(CrashType::Panic, CrashType::Segfault);
    }

    #[test]
    fn interesting_reason_equality() {
        assert_eq!(
            InterestingReason::NewCoverage,
            InterestingReason::NewCoverage
        );
        assert_ne!(
            InterestingReason::NewCoverage,
            InterestingReason::NewErrorCode
        );
    }

    #[test]
    fn crash_record_without_stack_trace() {
        let crash = CorpusManager::create_crash_record(
            FuzzInput::empty_params(),
            CrashType::ConnectionDrop,
            "connection lost".to_string(),
            None,
            42,
        );

        assert_eq!(crash.crash_type, CrashType::ConnectionDrop);
        assert_eq!(crash.error_message, "connection lost");
        assert_eq!(crash.stack_trace, None);
        assert_eq!(crash.iteration, 42);
        assert!(!crash.id.is_empty());
        assert!(!crash.timestamp.is_empty());
    }

    #[test]
    fn crash_type_all_variants_display() {
        let types = vec![
            (CrashType::Panic, "panic"),
            (CrashType::Segfault, "segfault"),
            (CrashType::OutOfMemory, "oom"),
            (CrashType::ConnectionDrop, "connection_drop"),
            (CrashType::AssertionFailure, "assertion"),
            (CrashType::Unknown, "unknown"),
        ];

        for (crash_type, expected) in types {
            assert_eq!(format!("{}", crash_type), expected);
            assert_eq!(crash_type.as_str(), expected);
        }
    }

    #[test]
    fn interesting_record_all_fields() {
        let input = FuzzInput::resources_list();
        let reason = InterestingReason::ProtocolViolation;
        let hash = 0xDEADBEEF;
        let iteration = 999;

        let record =
            CorpusManager::create_interesting_record(input.clone(), reason, hash, iteration);

        assert!(!record.id.is_empty());
        assert_eq!(record.input.method, input.method);
        assert_eq!(record.reason, reason);
        assert_eq!(record.coverage_hash, hash);
        assert_eq!(record.iteration, iteration);
    }

    #[test]
    fn multiple_crash_recordings() {
        let mut corpus = CorpusManager::new();

        for i in 0..5 {
            let crash = CorpusManager::create_crash_record(
                FuzzInput::ping(),
                CrashType::Panic,
                format!("error {}", i),
                None,
                i,
            );
            corpus.record_crash(crash).unwrap();
        }

        assert_eq!(corpus.crash_count(), 5);
        assert_eq!(corpus.crashes().len(), 5);

        // Verify all crashes recorded
        for i in 0..5 {
            assert_eq!(corpus.crashes()[i].error_message, format!("error {}", i));
            assert_eq!(corpus.crashes()[i].iteration, i as u64);
        }
    }

    #[test]
    fn multiple_hang_recordings() {
        let mut corpus = CorpusManager::new();

        for i in 0..3 {
            let hang =
                CorpusManager::create_hang_record(FuzzInput::tools_list(), 1000 * (i + 1), i);
            corpus.record_hang(hang).unwrap();
        }

        assert_eq!(corpus.hang_count(), 3);
        assert_eq!(corpus.hangs().len(), 3);

        // Verify timeout values
        for i in 0..3 {
            assert_eq!(corpus.hangs()[i].timeout_ms, 1000 * (i as u64 + 1));
        }
    }

    #[test]
    fn interesting_with_different_hashes() {
        let mut corpus = CorpusManager::new();

        for i in 0..4 {
            let record = CorpusManager::create_interesting_record(
                FuzzInput::ping(),
                InterestingReason::NewCoverage,
                i * 1000, // Different hashes
                i,
            );
            corpus.record_interesting(record).unwrap();
        }

        assert_eq!(corpus.interesting_count(), 4);
        assert_eq!(corpus.interesting().len(), 4);
    }

    #[test]
    fn corpus_size_with_seeds_and_interesting() {
        let mut corpus = CorpusManager::new();
        corpus.initialize().unwrap();

        let initial_seeds = corpus.seed_count();
        assert_eq!(corpus.corpus_size(), initial_seeds);

        // Add interesting inputs
        for i in 0..3 {
            let record = CorpusManager::create_interesting_record(
                FuzzInput::ping(),
                InterestingReason::NewCoverage,
                i * 100,
                i,
            );
            corpus.record_interesting(record).unwrap();
        }

        assert_eq!(corpus.corpus_size(), initial_seeds + 3);
    }

    #[test]
    fn next_input_cycles_through_corpus() {
        let mut corpus = CorpusManager::new();
        corpus.add_seed(FuzzInput::ping());
        corpus.add_seed(FuzzInput::tools_list());
        corpus.add_seed(FuzzInput::resources_list());

        let total = corpus.corpus_size();
        assert_eq!(total, 3);

        // Collect methods from multiple rounds
        let mut methods = Vec::new();
        for _ in 0..9 {
            methods.push(corpus.next_input().method.clone());
        }

        // Should cycle through the same 3 methods 3 times
        assert_eq!(methods[0], methods[3]);
        assert_eq!(methods[0], methods[6]);
        assert_eq!(methods[1], methods[4]);
        assert_eq!(methods[1], methods[7]);
        assert_eq!(methods[2], methods[5]);
        assert_eq!(methods[2], methods[8]);
    }

    #[test]
    fn next_input_includes_interesting_inputs() {
        let mut corpus = CorpusManager::new();
        corpus.add_seed(FuzzInput::ping());

        let record = CorpusManager::create_interesting_record(
            FuzzInput::tools_list(),
            InterestingReason::NewCoverage,
            12345,
            1,
        );
        corpus.record_interesting(record).unwrap();

        assert_eq!(corpus.corpus_size(), 2);

        // Get both inputs
        let first = corpus.next_input().method.clone();
        let second = corpus.next_input().method.clone();

        // Should get both seed and interesting
        assert_ne!(first, second);
    }

    #[test]
    fn empty_corpus_size() {
        let corpus = CorpusManager::new();
        assert_eq!(corpus.corpus_size(), 0);
        assert_eq!(corpus.seed_count(), 0);
        assert_eq!(corpus.interesting_count(), 0);
    }

    #[test]
    fn empty_corpus_counts() {
        let corpus = CorpusManager::new();
        assert_eq!(corpus.crash_count(), 0);
        assert_eq!(corpus.hang_count(), 0);
        assert_eq!(corpus.interesting_count(), 0);
        assert_eq!(corpus.crashes().len(), 0);
        assert_eq!(corpus.hangs().len(), 0);
        assert_eq!(corpus.interesting().len(), 0);
    }

    #[test]
    fn crash_type_copy_trait() {
        let crash1 = CrashType::Panic;
        let crash2 = crash1; // Copy
        assert_eq!(crash1, crash2);
    }

    #[test]
    fn interesting_reason_copy_trait() {
        let reason1 = InterestingReason::NewCoverage;
        let reason2 = reason1; // Copy
        assert_eq!(reason1, reason2);
    }

    #[test]
    fn crash_record_clone() {
        let crash = CorpusManager::create_crash_record(
            FuzzInput::ping(),
            CrashType::Segfault,
            "segfault error".to_string(),
            Some("trace data".to_string()),
            10,
        );

        let cloned = crash.clone();
        assert_eq!(crash.id, cloned.id);
        assert_eq!(crash.crash_type, cloned.crash_type);
        assert_eq!(crash.error_message, cloned.error_message);
        assert_eq!(crash.stack_trace, cloned.stack_trace);
        assert_eq!(crash.iteration, cloned.iteration);
        assert_eq!(crash.timestamp, cloned.timestamp);
    }

    #[test]
    fn hang_record_clone() {
        let hang = CorpusManager::create_hang_record(FuzzInput::ping(), 3000, 25);

        let cloned = hang.clone();
        assert_eq!(hang.id, cloned.id);
        assert_eq!(hang.timeout_ms, cloned.timeout_ms);
        assert_eq!(hang.iteration, cloned.iteration);
        assert_eq!(hang.timestamp, cloned.timestamp);
    }

    #[test]
    fn interesting_input_clone() {
        let record = CorpusManager::create_interesting_record(
            FuzzInput::ping(),
            InterestingReason::UnexpectedSuccess,
            777,
            15,
        );

        let cloned = record.clone();
        assert_eq!(record.id, cloned.id);
        assert_eq!(record.reason, cloned.reason);
        assert_eq!(record.coverage_hash, cloned.coverage_hash);
        assert_eq!(record.iteration, cloned.iteration);
    }

    #[test]
    fn crash_type_serialize_deserialize() {
        let crash_type = CrashType::OutOfMemory;
        let serialized = serde_json::to_string(&crash_type).unwrap();
        let deserialized: CrashType = serde_json::from_str(&serialized).unwrap();
        assert_eq!(crash_type, deserialized);
    }

    #[test]
    fn interesting_reason_serialize_deserialize() {
        let reason = InterestingReason::ProtocolViolation;
        let serialized = serde_json::to_string(&reason).unwrap();
        let deserialized: InterestingReason = serde_json::from_str(&serialized).unwrap();
        assert_eq!(reason, deserialized);
    }

    #[test]
    fn hang_record_unique_ids() {
        let hang1 = CorpusManager::create_hang_record(FuzzInput::ping(), 1000, 1);
        let hang2 = CorpusManager::create_hang_record(FuzzInput::ping(), 1000, 1);

        // IDs should be unique even with same parameters
        assert_ne!(hang1.id, hang2.id);
    }

    #[test]
    fn crash_record_unique_ids() {
        let crash1 = CorpusManager::create_crash_record(
            FuzzInput::ping(),
            CrashType::Panic,
            "error".to_string(),
            None,
            1,
        );
        let crash2 = CorpusManager::create_crash_record(
            FuzzInput::ping(),
            CrashType::Panic,
            "error".to_string(),
            None,
            1,
        );

        // IDs should be unique
        assert_ne!(crash1.id, crash2.id);
    }

    #[test]
    fn interesting_input_unique_ids() {
        let record1 = CorpusManager::create_interesting_record(
            FuzzInput::ping(),
            InterestingReason::NewCoverage,
            123,
            1,
        );
        let record2 = CorpusManager::create_interesting_record(
            FuzzInput::ping(),
            InterestingReason::NewCoverage,
            456,
            1,
        );

        // IDs should be unique
        assert_ne!(record1.id, record2.id);
    }

    #[test]
    fn add_multiple_seeds() {
        let mut corpus = CorpusManager::new();
        assert_eq!(corpus.seed_count(), 0);

        let inputs = vec![
            FuzzInput::ping(),
            FuzzInput::tools_list(),
            FuzzInput::resources_list(),
            FuzzInput::prompts_list(),
            FuzzInput::initialize(),
        ];

        for input in inputs {
            corpus.add_seed(input);
        }

        assert_eq!(corpus.seed_count(), 5);
    }

    #[test]
    fn next_input_wraps_around() {
        let mut corpus = CorpusManager::new();
        corpus.add_seed(FuzzInput::ping());
        corpus.add_seed(FuzzInput::tools_list());

        // Advance many times to test wrapping
        for _ in 0..100 {
            corpus.next_input();
        }

        // Should still work after wrapping
        let input = corpus.next_input();
        assert!(!input.method.is_empty());
    }

    #[test]
    fn crash_record_debug_format() {
        let crash = CorpusManager::create_crash_record(
            FuzzInput::ping(),
            CrashType::Panic,
            "test".to_string(),
            None,
            1,
        );

        let debug_str = format!("{:?}", crash);
        assert!(debug_str.contains("CrashRecord"));
    }

    #[test]
    fn hang_record_debug_format() {
        let hang = CorpusManager::create_hang_record(FuzzInput::ping(), 1000, 1);
        let debug_str = format!("{:?}", hang);
        assert!(debug_str.contains("HangRecord"));
    }

    #[test]
    fn interesting_input_debug_format() {
        let record = CorpusManager::create_interesting_record(
            FuzzInput::ping(),
            InterestingReason::NewCoverage,
            123,
            1,
        );
        let debug_str = format!("{:?}", record);
        assert!(debug_str.contains("InterestingInput"));
    }
}
