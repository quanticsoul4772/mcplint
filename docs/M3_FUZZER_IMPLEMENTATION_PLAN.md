# M3: Fuzzer Implementation Plan

## Overview

**Milestone**: M3 - Coverage-Guided Fuzzing Engine
**Status**: Stub implementation exists, needs full build-out
**Dependencies**: M0 (Transport), M1 (Validator), M2 (Scanner) - All complete
**Estimated Scope**: ~1,500-2,000 lines of Rust code

The M3 Fuzzer provides coverage-guided fuzzing capabilities for MCP servers, detecting crashes, hangs, protocol violations, and unexpected behaviors through intelligent payload mutation.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        CLI (fuzz command)                        │
│   mcplint fuzz <server> [--duration] [--corpus] [--workers]     │
├─────────────────────────────────────────────────────────────────┤
│                         FuzzEngine                               │
│  ┌──────────────┬──────────────┬──────────────┬──────────────┐  │
│  │ FuzzConfig   │ FuzzSession  │ FuzzResults  │ FuzzReporter │  │
│  └──────────────┴──────────────┴──────────────┴──────────────┘  │
├─────────────────────────────────────────────────────────────────┤
│                       Core Components                            │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                    MutationEngine                         │   │
│  │  ┌─────────────┬────────────┬─────────────┬───────────┐  │   │
│  │  │ JSON Mutator│ RPC Mutator│ MCP Mutator │ Dict-based│  │   │
│  │  └─────────────┴────────────┴─────────────┴───────────┘  │   │
│  └──────────────────────────────────────────────────────────┘   │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                    CorpusManager                          │   │
│  │  ┌─────────────┬────────────┬─────────────┬───────────┐  │   │
│  │  │ Seed Corpus │ Crash Store│ Hang Store  │Interesting│  │   │
│  │  └─────────────┴────────────┴─────────────┴───────────┘  │   │
│  └──────────────────────────────────────────────────────────┘   │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                    CrashDetector                          │   │
│  │  ┌─────────────┬────────────┬─────────────┬───────────┐  │   │
│  │  │ Exit Code   │ Timeout    │ Error Parse │Connection │  │   │
│  │  └─────────────┴────────────┴─────────────┴───────────┘  │   │
│  └──────────────────────────────────────────────────────────┘   │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                   CoverageTracker                         │   │
│  │  ┌─────────────┬────────────┬─────────────┐              │   │
│  │  │ Path Hash   │ Edge Map   │ New Coverage│              │   │
│  │  └─────────────┴────────────┴─────────────┘              │   │
│  └──────────────────────────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────────────┤
│                     Existing Infrastructure                      │
│            McpClient | Transport | Protocol Types                │
└─────────────────────────────────────────────────────────────────┘
```

---

## File Structure

```
src/fuzzer/
├── mod.rs              # Module exports, FuzzEngine facade
├── config.rs           # FuzzConfig, FuzzProfile configurations
├── session.rs          # FuzzSession state machine
├── mutation/
│   ├── mod.rs          # MutationEngine coordinator
│   ├── strategy.rs     # MutationStrategy enum and selection
│   ├── json.rs         # JSON-level mutations
│   ├── jsonrpc.rs      # JSON-RPC specific mutations
│   ├── mcp.rs          # MCP protocol mutations
│   └── dictionary.rs   # Dictionary-based mutations
├── corpus/
│   ├── mod.rs          # CorpusManager
│   ├── seed.rs         # Seed corpus generation
│   └── store.rs        # Crash/hang/interesting storage
├── detection/
│   ├── mod.rs          # CrashDetector coordinator
│   ├── crash.rs        # Crash classification
│   └── timeout.rs      # Timeout/hang detection
├── coverage.rs         # CoverageTracker (path hashing)
└── results.rs          # FuzzResults, FuzzCrash (exists, enhance)
```

---

## Component Specifications

### 1. FuzzConfig (`config.rs`)

```rust
/// Fuzzing configuration
#[derive(Debug, Clone)]
pub struct FuzzConfig {
    /// Maximum duration in seconds (0 = unlimited)
    pub duration_secs: u64,
    /// Maximum iterations (0 = unlimited)
    pub max_iterations: u64,
    /// Timeout per request in milliseconds
    pub request_timeout_ms: u64,
    /// Number of parallel workers
    pub workers: usize,
    /// Mutation strategies to use
    pub strategies: Vec<MutationStrategy>,
    /// Corpus directory path
    pub corpus_path: Option<PathBuf>,
    /// Dictionary file path
    pub dictionary_path: Option<PathBuf>,
    /// Target tools to fuzz (None = all)
    pub target_tools: Option<Vec<String>>,
    /// Fuzzing profile
    pub profile: FuzzProfile,
    /// Save interesting inputs
    pub save_interesting: bool,
    /// Minimum new coverage to save input
    pub coverage_threshold: f64,
}

/// Fuzzing profiles with different intensity levels
#[derive(Debug, Clone, Copy, Default)]
pub enum FuzzProfile {
    /// Quick fuzzing (~1 minute, basic mutations)
    Quick,
    /// Standard fuzzing (~5 minutes, all mutations)
    #[default]
    Standard,
    /// Intensive fuzzing (unlimited, aggressive mutations)
    Intensive,
    /// CI-optimized (fast feedback, deterministic seed)
    CI,
}

impl FuzzProfile {
    pub fn default_config(&self) -> FuzzConfig { ... }
    pub fn strategies(&self) -> Vec<MutationStrategy> { ... }
}
```

### 2. MutationStrategy (`mutation/strategy.rs`)

```rust
/// Mutation strategies for fuzzing
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MutationStrategy {
    // JSON-level mutations
    TypeConfusion,       // String → Number, Array → Object, etc.
    BoundaryValues,      // MAX_INT, MIN_INT, empty, null
    DeepNesting,         // Deeply nested objects/arrays
    UnicodeInjection,    // Null bytes, control chars, RTL markers
    StringMutation,      // Bit flips, insertions, deletions

    // JSON-RPC mutations
    InvalidId,           // Missing, wrong type, null, negative
    MalformedVersion,    // "2.1", "1.0", missing, wrong type
    UnknownMethod,       // Random/invented method names
    MissingFields,       // Remove required fields
    ExtraFields,         // Add unexpected fields

    // MCP-specific mutations
    ToolNotFound,        // Call non-existent tools
    SchemaViolation,     // Invalid inputs per tool schema
    SequenceViolation,   // Out-of-order messages
    ResourceExhaustion,  // Large payloads, many nested levels
    CapabilityMismatch,  // Request unsupported capabilities
    InvalidPagination,   // Bad cursor values

    // Protocol stress
    RapidFire,           // Many requests without waiting
    ConnectionDrop,      // Disconnect mid-request
    PartialMessage,      // Incomplete JSON
}

impl MutationStrategy {
    /// Get all strategies for a profile
    pub fn for_profile(profile: FuzzProfile) -> Vec<Self> { ... }

    /// Weight for random selection (higher = more likely)
    pub fn weight(&self) -> u32 { ... }

    /// Category for this strategy
    pub fn category(&self) -> MutationCategory { ... }
}

#[derive(Debug, Clone, Copy)]
pub enum MutationCategory {
    Json,
    JsonRpc,
    Mcp,
    Stress,
}
```

### 3. MutationEngine (`mutation/mod.rs`)

```rust
/// Engine for generating mutated inputs
pub struct MutationEngine {
    strategies: Vec<MutationStrategy>,
    dictionary: Dictionary,
    rng: SmallRng,
    schema_cache: HashMap<String, JsonSchema>,
}

impl MutationEngine {
    pub fn new(strategies: Vec<MutationStrategy>) -> Self;
    pub fn with_dictionary(self, dict: Dictionary) -> Self;
    pub fn with_seed(self, seed: u64) -> Self;

    /// Generate a mutated input from a base input
    pub fn mutate(&mut self, base: &FuzzInput) -> FuzzInput;

    /// Generate a completely random input
    pub fn generate_random(&mut self) -> FuzzInput;

    /// Apply a specific strategy to an input
    pub fn apply_strategy(
        &mut self,
        strategy: MutationStrategy,
        input: &FuzzInput
    ) -> FuzzInput;

    /// Cache tool schemas for schema-aware mutation
    pub fn cache_schemas(&mut self, tools: &[Tool]);
}

/// A fuzzing input (request to send to server)
#[derive(Debug, Clone)]
pub struct FuzzInput {
    pub method: String,
    pub params: Option<Value>,
    pub id: Value,
    pub raw_json: String,
    pub strategy_used: Option<MutationStrategy>,
    pub parent_id: Option<String>,  // For corpus tracking
}
```

### 4. JSON Mutations (`mutation/json.rs`)

```rust
/// JSON-level mutation operations
pub struct JsonMutator;

impl JsonMutator {
    /// Type confusion: change value types
    pub fn type_confuse(value: &Value, rng: &mut impl Rng) -> Value {
        match value {
            Value::String(s) => {
                // String → Number, Bool, Array, Object, Null
                match rng.gen_range(0..5) {
                    0 => Value::Number(s.len().into()),
                    1 => Value::Bool(true),
                    2 => json!([s]),
                    3 => json!({"value": s}),
                    4 => Value::Null,
                    _ => unreachable!(),
                }
            }
            // ... other type confusions
        }
    }

    /// Boundary values for various types
    pub fn boundary_value(value: &Value, rng: &mut impl Rng) -> Value {
        match value {
            Value::Number(_) => {
                let boundaries = [
                    i64::MAX, i64::MIN, 0, -1, 1,
                    i32::MAX as i64, i32::MIN as i64,
                ];
                Value::Number(boundaries[rng.gen_range(0..boundaries.len())].into())
            }
            Value::String(_) => {
                let boundaries = ["", " ", "\0", "a".repeat(10000), "\n\r\t"];
                Value::String(boundaries[rng.gen_range(0..boundaries.len())].into())
            }
            // ...
        }
    }

    /// Deep nesting to stress parsers
    pub fn deep_nest(depth: usize) -> Value {
        let mut v = json!("leaf");
        for _ in 0..depth {
            v = json!({"nested": v});
        }
        v
    }

    /// Unicode injection payloads
    pub fn unicode_inject(s: &str, rng: &mut impl Rng) -> String {
        let injections = [
            "\u{0000}",     // Null byte
            "\u{200B}",     // Zero-width space
            "\u{200C}",     // Zero-width non-joiner
            "\u{200D}",     // Zero-width joiner
            "\u{FEFF}",     // BOM
            "\u{202E}",     // RTL override
            "\u{2066}",     // LTR isolate
        ];
        format!("{}{}", s, injections[rng.gen_range(0..injections.len())])
    }
}
```

### 5. MCP Mutations (`mutation/mcp.rs`)

```rust
/// MCP protocol-specific mutations
pub struct McpMutator;

impl McpMutator {
    /// Generate a call to a non-existent tool
    pub fn tool_not_found(existing_tools: &[String], rng: &mut impl Rng) -> FuzzInput {
        let fake_names = [
            "nonexistent_tool",
            "../../etc/passwd",
            "'; DROP TABLE tools; --",
            "__proto__",
            "constructor",
        ];
        FuzzInput {
            method: "tools/call".to_string(),
            params: Some(json!({
                "name": fake_names[rng.gen_range(0..fake_names.len())],
                "arguments": {}
            })),
            ..Default::default()
        }
    }

    /// Generate schema-violating input for a tool
    pub fn schema_violation(tool: &Tool, rng: &mut impl Rng) -> FuzzInput {
        // Analyze tool schema and generate violating input
        let violations = generate_schema_violations(&tool.input_schema);
        FuzzInput {
            method: "tools/call".to_string(),
            params: Some(json!({
                "name": tool.name,
                "arguments": violations[rng.gen_range(0..violations.len())]
            })),
            ..Default::default()
        }
    }

    /// Out-of-order message sequences
    pub fn sequence_violation(rng: &mut impl Rng) -> Vec<FuzzInput> {
        // Return messages in wrong order
        vec![
            // tools/call before initialize
            FuzzInput::tool_call("some_tool", json!({})),
            FuzzInput::initialize(),
        ]
    }

    /// Resource exhaustion payloads
    pub fn resource_exhaustion(rng: &mut impl Rng) -> FuzzInput {
        match rng.gen_range(0..4) {
            0 => FuzzInput::with_large_payload(1_000_000),  // 1MB payload
            1 => FuzzInput::with_deep_nesting(1000),       // 1000 levels
            2 => FuzzInput::with_many_params(10000),       // 10k params
            3 => FuzzInput::with_long_string(100_000),     // 100k string
            _ => unreachable!(),
        }
    }
}
```

### 6. Dictionary (`mutation/dictionary.rs`)

```rust
/// Protocol-aware dictionary for mutations
#[derive(Debug, Clone, Default)]
pub struct Dictionary {
    tokens: Vec<String>,
    categories: HashMap<TokenCategory, Vec<String>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TokenCategory {
    JsonRpc,
    McpMethod,
    McpField,
    Injection,
    Unicode,
}

impl Dictionary {
    /// Load the default MCP dictionary
    pub fn mcp_default() -> Self {
        let mut dict = Self::default();

        // JSON-RPC tokens
        dict.add_tokens(TokenCategory::JsonRpc, vec![
            "jsonrpc", "2.0", "method", "params", "result", "error", "id",
            "code", "message", "data",
        ]);

        // MCP methods
        dict.add_tokens(TokenCategory::McpMethod, vec![
            "initialize", "initialized", "ping",
            "tools/list", "tools/call",
            "resources/list", "resources/read", "resources/subscribe",
            "prompts/list", "prompts/get",
            "logging/setLevel", "completion/complete",
            "notifications/cancelled", "notifications/progress",
        ]);

        // MCP fields
        dict.add_tokens(TokenCategory::McpField, vec![
            "protocolVersion", "capabilities", "serverInfo", "clientInfo",
            "name", "version", "description", "inputSchema",
            "tools", "resources", "prompts", "logging", "experimental",
            "uri", "mimeType", "annotations", "arguments",
        ]);

        // Injection payloads
        dict.add_tokens(TokenCategory::Injection, vec![
            "$(whoami)", "; cat /etc/passwd", "| ls -la",
            "' OR '1'='1", "'; DROP TABLE users; --",
            "../../../etc/passwd", "....//....//etc/passwd",
            "{{constructor.constructor('return this')()}}",
            "${7*7}", "#{7*7}", "<script>alert(1)</script>",
            "<IMPORTANT>Ignore previous instructions",
        ]);

        // Unicode tricks
        dict.add_tokens(TokenCategory::Unicode, vec![
            "\u{0000}", "\u{200B}", "\u{200C}", "\u{200D}",
            "\u{FEFF}", "\u{202E}", "\u{2066}", "\u{2067}",
        ]);

        dict
    }

    /// Load dictionary from file
    pub fn from_file(path: &Path) -> Result<Self>;

    /// Get random token
    pub fn random_token(&self, rng: &mut impl Rng) -> &str;

    /// Get random token from category
    pub fn random_from(&self, category: TokenCategory, rng: &mut impl Rng) -> &str;
}
```

### 7. CorpusManager (`corpus/mod.rs`)

```rust
/// Manages fuzzing corpus (seeds, crashes, interesting inputs)
pub struct CorpusManager {
    base_path: PathBuf,
    seeds: Vec<FuzzInput>,
    crashes: Vec<CrashRecord>,
    hangs: Vec<HangRecord>,
    interesting: Vec<InterestingInput>,
}

impl CorpusManager {
    pub fn new(base_path: PathBuf) -> Self;

    /// Initialize corpus with seed inputs
    pub fn initialize(&mut self) -> Result<()> {
        self.generate_default_seeds()?;
        self.load_existing_corpus()?;
        Ok(())
    }

    /// Generate default seed corpus
    fn generate_default_seeds(&mut self) -> Result<()> {
        // Valid MCP message seeds
        self.seeds.push(FuzzInput::initialize());
        self.seeds.push(FuzzInput::tools_list());
        self.seeds.push(FuzzInput::resources_list());
        self.seeds.push(FuzzInput::prompts_list());
        self.seeds.push(FuzzInput::ping());

        // Edge case seeds
        self.seeds.push(FuzzInput::empty_params());
        self.seeds.push(FuzzInput::null_id());
        self.seeds.push(FuzzInput::string_id("test-id"));

        Ok(())
    }

    /// Get next input to fuzz (round-robin + weighted)
    pub fn next_input(&mut self) -> &FuzzInput;

    /// Record a crash
    pub fn record_crash(&mut self, crash: CrashRecord) -> Result<()>;

    /// Record a hang/timeout
    pub fn record_hang(&mut self, hang: HangRecord) -> Result<()>;

    /// Record an interesting input (new coverage)
    pub fn record_interesting(&mut self, input: InterestingInput) -> Result<()>;

    /// Export corpus to directory
    pub fn export(&self, path: &Path) -> Result<()>;

    /// Import corpus from directory
    pub fn import(&mut self, path: &Path) -> Result<()>;
}

/// Directory structure
/// corpus/
/// ├── seeds/
/// │   ├── valid/
/// │   │   ├── 001_initialize.json
/// │   │   ├── 002_tools_list.json
/// │   │   └── ...
/// │   └── edge_cases/
/// │       ├── 001_empty_params.json
/// │       └── ...
/// ├── crashes/
/// │   ├── crash_001_timeout_20241207_120000.json
/// │   └── ...
/// ├── hangs/
/// │   └── ...
/// └── interesting/
///     └── ...
```

### 8. CrashDetector (`detection/mod.rs`)

```rust
/// Detects and classifies crashes/hangs/errors
pub struct CrashDetector {
    timeout_ms: u64,
}

impl CrashDetector {
    pub fn new(timeout_ms: u64) -> Self;

    /// Analyze response for crash indicators
    pub fn analyze(&self, response: &FuzzResponse) -> CrashAnalysis {
        match &response.result {
            FuzzResponseResult::Success(_) => CrashAnalysis::None,
            FuzzResponseResult::Error(e) => self.classify_error(e),
            FuzzResponseResult::Timeout => CrashAnalysis::Hang(HangInfo {
                timeout_ms: self.timeout_ms,
                last_activity: response.last_activity,
            }),
            FuzzResponseResult::ConnectionLost(reason) => {
                CrashAnalysis::Crash(CrashInfo {
                    crash_type: CrashType::ConnectionDrop,
                    message: reason.clone(),
                    stack_trace: None,
                })
            }
            FuzzResponseResult::ProcessExit(code) => {
                CrashAnalysis::Crash(CrashInfo {
                    crash_type: if *code == 139 {
                        CrashType::Segfault
                    } else {
                        CrashType::Panic
                    },
                    message: format!("Process exited with code {}", code),
                    stack_trace: None,
                })
            }
        }
    }

    /// Classify error response
    fn classify_error(&self, error: &JsonRpcError) -> CrashAnalysis {
        // Check for stack traces in error message
        if error.message.contains("panic") || error.message.contains("stack backtrace") {
            return CrashAnalysis::Crash(CrashInfo {
                crash_type: CrashType::Panic,
                message: error.message.clone(),
                stack_trace: Self::extract_stack_trace(&error.message),
            });
        }

        // Check for memory errors
        if error.message.contains("out of memory") || error.message.contains("allocation") {
            return CrashAnalysis::Crash(CrashInfo {
                crash_type: CrashType::OutOfMemory,
                message: error.message.clone(),
                stack_trace: None,
            });
        }

        // Protocol violation (not a crash, but interesting)
        if error.code == -32600 || error.code == -32601 {
            return CrashAnalysis::Interesting(InterestingReason::ProtocolViolation);
        }

        CrashAnalysis::None
    }
}

#[derive(Debug, Clone)]
pub enum CrashAnalysis {
    None,
    Crash(CrashInfo),
    Hang(HangInfo),
    Interesting(InterestingReason),
}

#[derive(Debug, Clone)]
pub enum CrashType {
    Panic,
    Segfault,
    OutOfMemory,
    ConnectionDrop,
    AssertionFailure,
    Unknown,
}

#[derive(Debug, Clone)]
pub enum InterestingReason {
    ProtocolViolation,
    UnexpectedSuccess,
    NewErrorCode,
    NewCoverage,
}
```

### 9. CoverageTracker (`coverage.rs`)

```rust
/// Tracks execution coverage for guided fuzzing
pub struct CoverageTracker {
    /// Hash of all seen paths
    seen_paths: HashSet<u64>,
    /// Edge hit counts (simplified edge coverage)
    edge_counts: HashMap<u64, u32>,
    /// Total inputs processed
    total_inputs: u64,
    /// Inputs that found new coverage
    coverage_inputs: u64,
}

impl CoverageTracker {
    pub fn new() -> Self;

    /// Hash a response to track coverage
    /// Uses response structure, error codes, and timing patterns
    pub fn hash_response(&self, input: &FuzzInput, response: &FuzzResponse) -> u64 {
        let mut hasher = DefaultHasher::new();

        // Hash method + response type
        input.method.hash(&mut hasher);

        match &response.result {
            FuzzResponseResult::Success(v) => {
                "success".hash(&mut hasher);
                // Hash structure, not values
                self.hash_json_structure(v, &mut hasher);
            }
            FuzzResponseResult::Error(e) => {
                "error".hash(&mut hasher);
                e.code.hash(&mut hasher);
            }
            FuzzResponseResult::Timeout => "timeout".hash(&mut hasher),
            FuzzResponseResult::ConnectionLost(_) => "connection_lost".hash(&mut hasher),
            FuzzResponseResult::ProcessExit(code) => {
                "exit".hash(&mut hasher);
                code.hash(&mut hasher);
            }
        }

        hasher.finish()
    }

    /// Record execution and return whether it's new coverage
    pub fn record(&mut self, input: &FuzzInput, response: &FuzzResponse) -> bool {
        let hash = self.hash_response(input, response);
        self.total_inputs += 1;

        if self.seen_paths.insert(hash) {
            self.coverage_inputs += 1;
            *self.edge_counts.entry(hash).or_insert(0) += 1;
            true
        } else {
            *self.edge_counts.get_mut(&hash).unwrap() += 1;
            false
        }
    }

    /// Get coverage statistics
    pub fn stats(&self) -> CoverageStats {
        CoverageStats {
            paths_explored: self.seen_paths.len(),
            edge_coverage: self.edge_counts.len() as f64 / 1000.0, // Normalized
            new_coverage_rate: self.coverage_inputs as f64 / self.total_inputs.max(1) as f64,
        }
    }
}
```

### 10. FuzzSession (`session.rs`)

```rust
/// A fuzzing session managing the fuzzing loop
pub struct FuzzSession {
    config: FuzzConfig,
    engine: MutationEngine,
    corpus: CorpusManager,
    detector: CrashDetector,
    coverage: CoverageTracker,
    client: McpClient,

    // Session state
    start_time: Instant,
    iterations: u64,
    crashes: Vec<FuzzCrash>,
    hangs: Vec<FuzzHang>,
}

impl FuzzSession {
    pub async fn new(
        server: &str,
        args: &[String],
        config: FuzzConfig,
    ) -> Result<Self>;

    /// Run the fuzzing session
    pub async fn run(&mut self) -> Result<FuzzResults> {
        self.corpus.initialize()?;
        self.cache_tool_schemas().await?;

        let progress = self.create_progress_bar();

        loop {
            // Check termination conditions
            if self.should_stop() {
                break;
            }

            // Get base input from corpus
            let base = self.corpus.next_input();

            // Mutate input
            let mutated = self.engine.mutate(base);

            // Execute and measure
            let response = self.execute(&mutated).await;

            // Analyze response
            let analysis = self.detector.analyze(&response);

            // Record coverage
            let is_new = self.coverage.record(&mutated, &response);

            // Handle analysis result
            match analysis {
                CrashAnalysis::Crash(info) => {
                    self.record_crash(&mutated, info)?;
                }
                CrashAnalysis::Hang(info) => {
                    self.record_hang(&mutated, info)?;
                }
                CrashAnalysis::Interesting(reason) if is_new => {
                    self.corpus.record_interesting(InterestingInput {
                        input: mutated,
                        reason,
                        coverage_hash: self.coverage.hash_response(&mutated, &response),
                    })?;
                }
                _ => {}
            }

            self.iterations += 1;
            progress.inc(1);
        }

        progress.finish();
        self.generate_results()
    }

    /// Execute a single fuzz input
    async fn execute(&mut self, input: &FuzzInput) -> FuzzResponse {
        let timeout = Duration::from_millis(self.config.request_timeout_ms);

        match tokio::time::timeout(timeout, self.send_request(input)).await {
            Ok(Ok(result)) => FuzzResponse::success(result),
            Ok(Err(e)) => FuzzResponse::from_error(e),
            Err(_) => FuzzResponse::timeout(),
        }
    }

    /// Check if session should stop
    fn should_stop(&self) -> bool {
        // Duration limit
        if self.config.duration_secs > 0 {
            if self.start_time.elapsed().as_secs() >= self.config.duration_secs {
                return true;
            }
        }

        // Iteration limit
        if self.config.max_iterations > 0 {
            if self.iterations >= self.config.max_iterations {
                return true;
            }
        }

        false
    }
}
```

### 11. FuzzEngine Updates (`mod.rs`)

Update the existing `FuzzEngine` to use the new components:

```rust
/// Fuzzing engine for MCP servers
pub struct FuzzEngine {
    server: String,
    args: Vec<String>,
    config: FuzzConfig,
}

impl FuzzEngine {
    pub fn new(server: &str, args: &[String], workers: usize) -> Self {
        Self {
            server: server.to_string(),
            args: args.to_vec(),
            config: FuzzConfig::default().with_workers(workers),
        }
    }

    pub fn with_config(server: &str, args: &[String], config: FuzzConfig) -> Self {
        Self {
            server: server.to_string(),
            args: args.to_vec(),
            config,
        }
    }

    pub async fn run(
        &self,
        duration: u64,
        corpus: Option<String>,
        iterations: u64,
        tools: Option<Vec<String>>,
    ) -> Result<FuzzResults> {
        // Build config from parameters
        let mut config = self.config.clone();
        config.duration_secs = duration;
        config.max_iterations = iterations;
        config.target_tools = tools;
        if let Some(path) = corpus {
            config.corpus_path = Some(PathBuf::from(path));
        }

        // Create and run session
        let mut session = FuzzSession::new(&self.server, &self.args, config).await?;
        session.run().await
    }
}
```

### 12. SARIF Output (`results.rs`)

Enhance `FuzzResults` with proper SARIF support:

```rust
impl FuzzResults {
    pub fn print_sarif(&self) -> Result<()> {
        let sarif = self.to_sarif();
        println!("{}", serde_json::to_string_pretty(&sarif)?);
        Ok(())
    }

    fn to_sarif(&self) -> Value {
        let rules: Vec<Value> = self.crashes.iter()
            .map(|c| self.crash_to_sarif_rule(c))
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();

        let results: Vec<Value> = self.crashes.iter()
            .map(|c| self.crash_to_sarif_result(c))
            .collect();

        json!({
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "mcplint-fuzzer",
                        "version": env!("CARGO_PKG_VERSION"),
                        "informationUri": "https://github.com/quanticsoul4772/mcplint",
                        "rules": rules
                    }
                },
                "results": results,
                "invocations": [{
                    "executionSuccessful": true,
                    "properties": {
                        "iterations": self.iterations,
                        "duration_secs": self.duration_secs,
                        "coverage": self.coverage
                    }
                }]
            }]
        })
    }

    fn crash_to_sarif_rule(&self, crash: &FuzzCrash) -> Value {
        json!({
            "id": format!("FUZZ-{}", crash.crash_type.to_uppercase().replace(" ", "-")),
            "name": crash.crash_type,
            "shortDescription": {
                "text": format!("Fuzzer detected: {}", crash.crash_type)
            },
            "defaultConfiguration": {
                "level": "error"
            }
        })
    }
}
```

---

## CLI Integration

Update `src/cli/commands/fuzz.rs`:

```rust
pub async fn run(
    server: &str,
    args: &[String],
    duration: u64,
    corpus: Option<String>,
    iterations: u64,
    workers: usize,
    tools: Option<Vec<String>>,
    profile: Option<String>,
    format: OutputFormat,
) -> Result<()> {
    // Determine profile
    let fuzz_profile = match profile.as_deref() {
        Some("quick") => FuzzProfile::Quick,
        Some("standard") => FuzzProfile::Standard,
        Some("intensive") => FuzzProfile::Intensive,
        Some("ci") => FuzzProfile::CI,
        _ => FuzzProfile::Standard,
    };

    // Build config
    let config = fuzz_profile.default_config()
        .with_workers(workers)
        .with_duration(duration)
        .with_iterations(iterations)
        .with_corpus(corpus.map(PathBuf::from))
        .with_target_tools(tools);

    println!("{}", "Starting fuzzing session...".cyan());
    println!("  Server: {}", server.yellow());
    println!("  Profile: {}", fuzz_profile.as_str().green());
    println!("  Duration: {}", format_duration(duration));
    println!("  Workers: {}", workers);
    println!();

    let engine = FuzzEngine::with_config(server, args, config);
    let results = engine.run(duration, corpus, iterations, tools).await?;

    // Output results
    match format {
        OutputFormat::Text => results.print_text(),
        OutputFormat::Json => results.print_json()?,
        OutputFormat::Sarif => results.print_sarif()?,
    }

    // Exit code based on crashes
    if !results.crashes.is_empty() {
        std::process::exit(1);
    }

    Ok(())
}
```

---

## Implementation Order

### Phase 1: Core Infrastructure (Priority: High)
1. `config.rs` - FuzzConfig and FuzzProfile
2. `mutation/strategy.rs` - MutationStrategy enum
3. `mutation/dictionary.rs` - Dictionary loading
4. `results.rs` - Enhance existing FuzzResults

### Phase 2: Mutation Engine (Priority: High)
5. `mutation/json.rs` - JSON-level mutations
6. `mutation/jsonrpc.rs` - JSON-RPC mutations
7. `mutation/mcp.rs` - MCP-specific mutations
8. `mutation/mod.rs` - MutationEngine coordinator

### Phase 3: Corpus & Detection (Priority: Medium)
9. `corpus/seed.rs` - Seed generation
10. `corpus/store.rs` - Crash/hang storage
11. `corpus/mod.rs` - CorpusManager
12. `detection/crash.rs` - Crash classification
13. `detection/timeout.rs` - Timeout detection
14. `detection/mod.rs` - CrashDetector

### Phase 4: Session & Coverage (Priority: Medium)
15. `coverage.rs` - CoverageTracker
16. `session.rs` - FuzzSession
17. Update `mod.rs` - Integrate components

### Phase 5: CLI & Output (Priority: Low)
18. Update `fuzz.rs` command
19. SARIF output enhancement
20. Progress bar and reporting

---

## Testing Strategy

### Unit Tests
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_type_confusion() {
        let value = json!("test");
        let mutated = JsonMutator::type_confuse(&value, &mut rand::thread_rng());
        assert!(matches!(
            mutated,
            Value::Number(_) | Value::Bool(_) | Value::Array(_) | Value::Object(_) | Value::Null
        ));
    }

    #[test]
    fn dictionary_loads() {
        let dict = Dictionary::mcp_default();
        assert!(!dict.tokens.is_empty());
        assert!(dict.categories.contains_key(&TokenCategory::McpMethod));
    }

    #[test]
    fn crash_detection() {
        let detector = CrashDetector::new(5000);

        let panic_error = JsonRpcError {
            code: -32603,
            message: "thread 'main' panicked at...".to_string(),
            data: None,
        };

        let analysis = detector.classify_error(&panic_error);
        assert!(matches!(analysis, CrashAnalysis::Crash(_)));
    }

    #[test]
    fn coverage_tracking() {
        let mut tracker = CoverageTracker::new();

        let input = FuzzInput::default();
        let response1 = FuzzResponse::success(json!({"tools": []}));
        let response2 = FuzzResponse::success(json!({"tools": []}));
        let response3 = FuzzResponse::error(-32601, "Method not found");

        assert!(tracker.record(&input, &response1)); // New
        assert!(!tracker.record(&input, &response2)); // Same structure
        assert!(tracker.record(&input, &response3)); // Different (error)
    }
}
```

### Integration Tests
```rust
#[tokio::test]
async fn fuzz_test_server() {
    let engine = FuzzEngine::new("test-server", &[], 1);
    let results = engine.run(5, None, 100, None).await.unwrap();

    assert!(results.iterations >= 100);
    assert!(results.coverage.paths_explored > 0);
}
```

---

## Success Criteria

1. **Functional Requirements**
   - [ ] Fuzzer connects to MCP servers via stdio and HTTP
   - [ ] Mutation engine generates valid mutations for all strategy types
   - [ ] Corpus manager persists crashes/hangs/interesting inputs
   - [ ] Crash detector identifies panics, timeouts, connection drops
   - [ ] Coverage tracker identifies new execution paths
   - [ ] SARIF output includes all crashes with proper formatting

2. **Performance Requirements**
   - [ ] Achieves ≥50 iterations/second for stdio servers
   - [ ] Achieves ≥20 iterations/second for HTTP servers
   - [ ] Memory usage stays under 500MB for standard profile

3. **Quality Requirements**
   - [ ] All code passes `cargo clippy -- -D warnings`
   - [ ] All code passes `cargo fmt -- --check`
   - [ ] Unit test coverage ≥80% for mutation engine
   - [ ] Integration tests pass for all profiles

4. **Documentation Requirements**
   - [ ] Inline documentation for public APIs
   - [ ] Usage examples in module headers
   - [ ] CLI help text updated

---

## Dependencies

No new external dependencies required. Uses existing:
- `rand` (already available via `proptest`)
- `tokio` (existing)
- `serde/serde_json` (existing)
- `colored/indicatif` (existing)

---

## Risk Mitigation

| Risk | Mitigation |
|------|------------|
| Server crashes during fuzzing | Implement graceful reconnection with backoff |
| Corpus grows unbounded | Implement corpus minimization/deduplication |
| False positive crashes | Require reproducibility (3 attempts) before recording |
| Resource exhaustion on client | Implement memory limits and iteration caps |
| Flaky coverage measurements | Use structural hashing, not content hashing |

---

## Future Enhancements (Post-M3)

1. **Parallel Fuzzing**: Multiple worker processes with corpus sharing
2. **AI-Guided Mutations**: Use LLM to generate semantic payloads (M5 dependency)
3. **Persistent Mode**: AFL++ style fork server for 10x speedup
4. **Remote Corpus Sync**: Share corpus across team/CI via cloud storage
5. **Differential Fuzzing**: Compare behavior across server versions
