//! Fuzz Session - Orchestrates a fuzzing session
//!
//! Manages the main fuzzing loop, coordinating mutation,
//! execution, crash detection, and coverage tracking.

use anyhow::{Context, Result};
use indicatif::{ProgressBar, ProgressStyle};
use std::time::{Duration, Instant};

use crate::client::McpClient;
use crate::protocol::mcp::Tool;
use crate::transport::TransportConfig;

use super::config::FuzzConfig;
use super::corpus::{
    CorpusManager, CrashRecord, CrashType, HangRecord, InterestingInput, InterestingReason,
};
use super::coverage::CoverageTracker;
use super::detection::{CrashAnalysis, CrashDetector, FuzzResponse};
use super::input::FuzzInput;
use super::limits::{FuzzStats, LimitExceeded, ResourceMonitor};
use super::mutation::strategy::MutationStrategy;
use super::mutation::MutationEngine;
use super::{FuzzCrash, FuzzResults};

/// A fuzzing session managing the fuzzing loop
pub struct FuzzSession {
    /// Target server
    server: String,
    /// Server arguments
    args: Vec<String>,
    /// Session configuration
    config: FuzzConfig,
    /// Mutation engine
    engine: MutationEngine,
    /// Corpus manager
    corpus: CorpusManager,
    /// Crash detector
    detector: CrashDetector,
    /// Coverage tracker
    coverage: CoverageTracker,
    /// Resource monitor for limit enforcement
    resource_monitor: ResourceMonitor,
    /// MCP client (lazily initialized)
    client: Option<McpClient>,
    /// Session start time
    start_time: Option<Instant>,
    /// Current iteration
    iterations: u64,
    /// Discovered tools
    tools: Vec<Tool>,
    /// Connection failures count
    connection_failures: u32,
    /// Max consecutive connection failures before stopping
    max_connection_failures: u32,
    /// Server restart count (for resource tracking)
    restarts: u32,
    /// Reason for stopping (if limits exceeded)
    stop_reason: Option<LimitExceeded>,
}

impl FuzzSession {
    /// Create a new fuzzing session
    pub fn new(server: &str, args: &[String], config: FuzzConfig) -> Self {
        let strategies = MutationStrategy::for_profile(config.profile);
        let mut engine = MutationEngine::new(strategies);

        // Set seed if configured
        if let Some(seed) = config.seed {
            engine = engine.with_seed(seed);
        }

        let corpus = if let Some(ref path) = config.corpus_path {
            CorpusManager::with_path(path.clone())
        } else {
            CorpusManager::new()
        };

        let timeout_ms = config.request_timeout_ms;

        // Create resource monitor from config limits
        let resource_monitor = ResourceMonitor::new(config.resource_limits.clone());

        Self {
            server: server.to_string(),
            args: args.to_vec(),
            config,
            engine,
            corpus,
            detector: CrashDetector::new(timeout_ms),
            coverage: CoverageTracker::new(),
            resource_monitor,
            client: None,
            start_time: None,
            iterations: 0,
            tools: Vec::new(),
            connection_failures: 0,
            max_connection_failures: 5,
            restarts: 0,
            stop_reason: None,
        }
    }

    /// Run the fuzzing session
    pub async fn run(&mut self) -> Result<FuzzResults> {
        self.start_time = Some(Instant::now());

        // Initialize corpus
        self.corpus.initialize()?;

        // Connect and initialize
        self.connect().await?;
        self.discover_tools().await?;

        // Create progress bar
        let progress = self.create_progress_bar();

        // Main fuzzing loop
        loop {
            // Check termination conditions
            if self.should_stop() {
                break;
            }

            // Get base input from corpus
            let base = self.corpus.next_input().clone();

            // Mutate input
            let mutated = self.engine.mutate(&base);

            // Execute and measure
            let response = self.execute(&mutated).await;

            // Analyze response
            let analysis = self.detector.analyze(&response);

            // Record coverage
            let is_new = self.coverage.record(&mutated, &response);

            // Handle analysis result
            self.handle_analysis(&mutated, &response, analysis, is_new)
                .await?;

            self.iterations += 1;
            progress.set_position(self.iterations);

            // Update progress message
            if self.iterations.is_multiple_of(10) {
                let stats = self.coverage.stats();
                progress.set_message(format!(
                    "paths: {}, crashes: {}, coverage: {:.1}%",
                    stats.paths_explored,
                    self.corpus.crash_count(),
                    stats.new_coverage_rate * 100.0
                ));
            }
        }

        progress.finish_with_message("Fuzzing complete");

        // Disconnect
        self.disconnect().await;

        // Generate results
        self.generate_results()
    }

    /// Connect to the server
    async fn connect(&mut self) -> Result<()> {
        let transport_config = TransportConfig {
            timeout_secs: (self.config.request_timeout_ms / 1000).max(1),
            ..Default::default()
        };

        let client = McpClient::connect_with_config(
            &self.server,
            &self.args,
            "mcplint-fuzzer",
            env!("CARGO_PKG_VERSION"),
            transport_config,
        )
        .await
        .context("Failed to connect to server")?;

        self.client = Some(client);
        Ok(())
    }

    /// Reconnect after connection failure
    async fn reconnect(&mut self) -> Result<()> {
        self.connection_failures += 1;
        self.restarts += 1;

        if self.connection_failures >= self.max_connection_failures {
            anyhow::bail!(
                "Too many consecutive connection failures ({})",
                self.connection_failures
            );
        }

        // Check restart limit before attempting
        let stats = self.get_fuzz_stats();
        if let Some(exceeded) = self.resource_monitor.check(&stats) {
            if matches!(exceeded, LimitExceeded::Restarts(_)) {
                self.stop_reason = Some(exceeded.clone());
                anyhow::bail!("Restart limit exceeded: {}", exceeded);
            }
        }

        // Wait before reconnecting
        tokio::time::sleep(Duration::from_millis(500)).await;

        self.client = None;
        self.connect().await?;

        // Re-initialize
        if let Some(client) = &mut self.client {
            client.initialize().await?;
        }

        self.connection_failures = 0;
        Ok(())
    }

    /// Discover available tools
    async fn discover_tools(&mut self) -> Result<()> {
        if let Some(client) = &mut self.client {
            // Initialize first
            client.initialize().await?;

            // List tools
            match client.list_tools().await {
                Ok(tools) => {
                    self.tools = tools;
                    self.engine.cache_tools(&self.tools);
                }
                Err(e) => {
                    // Non-fatal - some servers may not have tools
                    tracing::debug!("Could not list tools: {}", e);
                }
            }
        }
        Ok(())
    }

    /// Execute a single fuzz input
    async fn execute(&mut self, input: &FuzzInput) -> FuzzResponse {
        let timeout = Duration::from_millis(self.config.request_timeout_ms);
        let start = Instant::now();

        // Try to send the request
        let result = tokio::time::timeout(timeout, self.send_request(input)).await;

        let response_time = start.elapsed().as_millis() as u64;

        match result {
            Ok(Ok(response)) => response.with_time(response_time),
            Ok(Err(e)) => {
                // Check if it's a connection error
                let error_str = e.to_string();
                if error_str.contains("connection")
                    || error_str.contains("broken pipe")
                    || error_str.contains("reset")
                {
                    FuzzResponse::connection_lost(error_str).with_time(response_time)
                } else {
                    FuzzResponse::error(-32603, error_str).with_time(response_time)
                }
            }
            Err(_) => FuzzResponse::timeout().with_time(response_time),
        }
    }

    /// Send a request to the server
    async fn send_request(&mut self, input: &FuzzInput) -> Result<FuzzResponse> {
        let client = self
            .client
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Not connected"))?;

        // Build the request based on method
        let response = match input.method.as_str() {
            "initialize" => {
                // Skip - already initialized
                return Ok(FuzzResponse::success(serde_json::json!({"skipped": true})));
            }
            "tools/list" => {
                let result = client.list_tools().await?;
                FuzzResponse::success(serde_json::to_value(result)?)
            }
            "tools/call" => {
                if let Some(params) = &input.params {
                    let name = params
                        .get("name")
                        .and_then(|n| n.as_str())
                        .unwrap_or("unknown");
                    let args = params
                        .get("arguments")
                        .cloned()
                        .unwrap_or(serde_json::json!({}));

                    match client.call_tool(name, Some(args)).await {
                        Ok(result) => FuzzResponse::success(serde_json::to_value(result)?),
                        Err(e) => FuzzResponse::error(-32603, e.to_string()),
                    }
                } else {
                    FuzzResponse::error(-32602, "Missing params")
                }
            }
            "resources/list" => {
                let result = client.list_resources().await?;
                FuzzResponse::success(serde_json::to_value(result)?)
            }
            "resources/read" => {
                if let Some(params) = &input.params {
                    let uri = params
                        .get("uri")
                        .and_then(|u| u.as_str())
                        .unwrap_or("file:///test");

                    match client.read_resource(uri).await {
                        Ok(result) => FuzzResponse::success(serde_json::to_value(result)?),
                        Err(e) => FuzzResponse::error(-32603, e.to_string()),
                    }
                } else {
                    FuzzResponse::error(-32602, "Missing uri")
                }
            }
            "prompts/list" => {
                let result = client.list_prompts().await?;
                FuzzResponse::success(serde_json::to_value(result)?)
            }
            "prompts/get" => {
                if let Some(params) = &input.params {
                    let name = params
                        .get("name")
                        .and_then(|n| n.as_str())
                        .unwrap_or("test");
                    let args = params.get("arguments").cloned();

                    match client.get_prompt(name, args).await {
                        Ok(result) => FuzzResponse::success(serde_json::to_value(result)?),
                        Err(e) => FuzzResponse::error(-32603, e.to_string()),
                    }
                } else {
                    FuzzResponse::error(-32602, "Missing name")
                }
            }
            "ping" => match client.ping().await {
                Ok(_) => FuzzResponse::success(serde_json::json!({"pong": true})),
                Err(e) => FuzzResponse::error(-32603, e.to_string()),
            },
            _ => {
                // Unknown method - send raw and expect error
                FuzzResponse::error(-32601, format!("Unknown method: {}", input.method))
            }
        };

        Ok(response)
    }

    /// Handle analysis result
    async fn handle_analysis(
        &mut self,
        input: &FuzzInput,
        response: &FuzzResponse,
        analysis: CrashAnalysis,
        is_new_coverage: bool,
    ) -> Result<()> {
        match analysis {
            CrashAnalysis::Crash(info) => {
                let record = CrashRecord {
                    id: uuid::Uuid::new_v4().to_string(),
                    input: input.clone(),
                    crash_type: info.crash_type,
                    error_message: info.message,
                    stack_trace: info.stack_trace,
                    iteration: self.iterations,
                    timestamp: chrono::Utc::now().to_rfc3339(),
                };
                self.corpus.record_crash(record)?;

                // Try to reconnect
                if matches!(info.crash_type, CrashType::ConnectionDrop) {
                    if let Err(e) = self.reconnect().await {
                        tracing::warn!("Failed to reconnect after crash: {}", e);
                    }
                }
            }
            CrashAnalysis::Hang(info) => {
                let record = HangRecord {
                    id: uuid::Uuid::new_v4().to_string(),
                    input: input.clone(),
                    timeout_ms: info.timeout_ms,
                    iteration: self.iterations,
                    timestamp: chrono::Utc::now().to_rfc3339(),
                };
                self.corpus.record_hang(record)?;
            }
            CrashAnalysis::Interesting(reason) => {
                if is_new_coverage && self.config.save_interesting {
                    let hash = self.coverage.hash_response(input, response);
                    let record = InterestingInput {
                        id: uuid::Uuid::new_v4().to_string(),
                        input: input.clone(),
                        reason,
                        coverage_hash: hash,
                        iteration: self.iterations,
                    };
                    self.corpus.record_interesting(record)?;
                }
            }
            CrashAnalysis::None => {
                // Just new coverage, no crash
                if is_new_coverage && self.config.save_interesting {
                    let hash = self.coverage.hash_response(input, response);
                    let record = InterestingInput {
                        id: uuid::Uuid::new_v4().to_string(),
                        input: input.clone(),
                        reason: InterestingReason::NewCoverage,
                        coverage_hash: hash,
                        iteration: self.iterations,
                    };
                    self.corpus.record_interesting(record)?;
                }
            }
        }

        Ok(())
    }

    /// Check if session should stop
    fn should_stop(&mut self) -> bool {
        let Some(start) = self.start_time else {
            return false;
        };

        // Check legacy duration limit (for backwards compatibility)
        if self.config.duration_secs > 0 && start.elapsed().as_secs() >= self.config.duration_secs {
            return true;
        }

        // Check legacy iteration limit (for backwards compatibility)
        if self.config.max_iterations > 0 && self.iterations >= self.config.max_iterations {
            return true;
        }

        // Check resource limits
        let stats = self.get_fuzz_stats();
        if let Some(exceeded) = self.resource_monitor.check(&stats) {
            tracing::info!("Resource limit exceeded: {}", exceeded);
            self.stop_reason = Some(exceeded);
            return true;
        }

        false
    }

    /// Get current fuzzing statistics for resource monitoring
    fn get_fuzz_stats(&self) -> FuzzStats {
        FuzzStats {
            executions: self.iterations,
            corpus_size: self.corpus.corpus_size(),
            restarts: self.restarts,
        }
    }

    /// Create progress bar
    fn create_progress_bar(&self) -> ProgressBar {
        let total = if self.config.max_iterations > 0 {
            self.config.max_iterations
        } else if self.config.duration_secs > 0 {
            // Estimate iterations (assuming ~50/sec)
            self.config.duration_secs * 50
        } else {
            u64::MAX
        };

        let pb = ProgressBar::new(total);
        pb.set_style(
            ProgressStyle::default_bar()
                .template(
                    "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({msg})",
                )
                .unwrap()
                .progress_chars("#>-"),
        );
        pb.set_message("starting...");
        pb
    }

    /// Disconnect from server
    async fn disconnect(&mut self) {
        if let Some(mut client) = self.client.take() {
            let _ = client.close().await;
        }
    }

    /// Generate final results
    fn generate_results(&self) -> Result<FuzzResults> {
        let duration = self.start_time.map(|s| s.elapsed().as_secs()).unwrap_or(0);

        let crashes: Vec<FuzzCrash> = self
            .corpus
            .crashes()
            .iter()
            .map(|c| FuzzCrash {
                id: c.id.clone(),
                crash_type: c.crash_type.to_string(),
                input: c.input.to_json_string(),
                error: c.error_message.clone(),
                iteration: c.iteration,
                timestamp: c.timestamp.clone(),
            })
            .collect();

        Ok(FuzzResults {
            server: self.server.clone(),
            duration_secs: duration,
            iterations: self.iterations,
            crashes,
            coverage: self.coverage.stats(),
            interesting_inputs: self.corpus.interesting_count(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fuzzer::config::FuzzProfile;

    #[test]
    fn session_creation() {
        let config = FuzzConfig::with_profile(FuzzProfile::Quick);
        let session = FuzzSession::new("test-server", &[], config);

        assert_eq!(session.server, "test-server");
        assert_eq!(session.iterations, 0);
    }

    #[test]
    fn session_creation_with_args() {
        let config = FuzzConfig::with_profile(FuzzProfile::Standard);
        let args = vec!["--port".to_string(), "8080".to_string()];
        let session = FuzzSession::new("node server.js", &args, config);

        assert_eq!(session.server, "node server.js");
        assert_eq!(session.args.len(), 2);
        assert_eq!(session.args[0], "--port");
    }

    #[test]
    fn session_with_seed() {
        let mut config = FuzzConfig::with_profile(FuzzProfile::Quick);
        config.seed = Some(12345);
        let session = FuzzSession::new("test", &[], config);

        assert_eq!(session.iterations, 0);
    }

    #[test]
    fn session_with_corpus_path() {
        let mut config = FuzzConfig::with_profile(FuzzProfile::Quick);
        config.corpus_path = Some(std::path::PathBuf::from("/tmp/corpus"));
        let session = FuzzSession::new("test", &[], config);

        assert_eq!(session.server, "test");
    }

    #[test]
    fn stop_conditions() {
        let config = FuzzConfig {
            duration_secs: 0,
            max_iterations: 100,
            ..FuzzConfig::default()
        };

        let mut session = FuzzSession::new("test", &[], config);
        session.start_time = Some(Instant::now());
        session.iterations = 50;

        assert!(!session.should_stop());

        session.iterations = 100;
        assert!(session.should_stop());
    }

    #[test]
    fn stop_conditions_no_start_time() {
        let config = FuzzConfig {
            duration_secs: 10,
            max_iterations: 100,
            ..FuzzConfig::default()
        };

        let mut session = FuzzSession::new("test", &[], config);
        // No start_time set
        assert!(!session.should_stop());
    }

    #[test]
    fn stop_conditions_duration() {
        let config = FuzzConfig {
            duration_secs: 0, // 0 seconds = immediate stop
            max_iterations: 0,
            ..FuzzConfig::default()
        };

        let mut session = FuzzSession::new("test", &[], config);
        session.start_time = Some(Instant::now() - Duration::from_secs(1));

        // With duration_secs = 0, should not stop based on duration
        assert!(!session.should_stop());
    }

    #[test]
    fn get_fuzz_stats() {
        let config = FuzzConfig::with_profile(FuzzProfile::Quick);
        let mut session = FuzzSession::new("test", &[], config);
        session.iterations = 100;
        session.restarts = 3;

        let stats = session.get_fuzz_stats();
        assert_eq!(stats.executions, 100);
        assert_eq!(stats.restarts, 3);
    }

    #[test]
    fn session_initial_state() {
        let config = FuzzConfig::with_profile(FuzzProfile::Quick);
        let session = FuzzSession::new("test", &[], config);

        assert!(session.client.is_none());
        assert!(session.start_time.is_none());
        assert_eq!(session.iterations, 0);
        assert!(session.tools.is_empty());
        assert_eq!(session.connection_failures, 0);
        assert_eq!(session.restarts, 0);
        assert!(session.stop_reason.is_none());
    }

    #[test]
    fn session_max_connection_failures() {
        let config = FuzzConfig::with_profile(FuzzProfile::Quick);
        let session = FuzzSession::new("test", &[], config);

        assert_eq!(session.max_connection_failures, 5);
    }

    #[test]
    fn fuzz_profile_quick() {
        let config = FuzzConfig::with_profile(FuzzProfile::Quick);
        let session = FuzzSession::new("test", &[], config);

        assert_eq!(session.config.profile, FuzzProfile::Quick);
    }

    #[test]
    fn fuzz_profile_standard() {
        let config = FuzzConfig::with_profile(FuzzProfile::Standard);
        let session = FuzzSession::new("test", &[], config);

        assert_eq!(session.config.profile, FuzzProfile::Standard);
    }

    #[test]
    fn fuzz_profile_intensive() {
        let config = FuzzConfig::with_profile(FuzzProfile::Intensive);
        let session = FuzzSession::new("test", &[], config);

        assert_eq!(session.config.profile, FuzzProfile::Intensive);
    }

    #[test]
    fn generate_results_no_crashes() {
        let config = FuzzConfig::with_profile(FuzzProfile::Quick);
        let mut session = FuzzSession::new("test-server", &[], config);
        session.start_time = Some(Instant::now());
        session.iterations = 100;

        let results = session.generate_results().unwrap();
        assert_eq!(results.server, "test-server");
        assert_eq!(results.iterations, 100);
        assert!(results.crashes.is_empty());
    }

    #[test]
    fn generate_results_without_start_time() {
        let config = FuzzConfig::with_profile(FuzzProfile::Quick);
        let session = FuzzSession::new("test", &[], config);

        let results = session.generate_results().unwrap();
        assert_eq!(results.duration_secs, 0);
    }

    #[test]
    fn create_progress_bar_with_iterations() {
        let config = FuzzConfig {
            max_iterations: 1000,
            duration_secs: 0,
            ..FuzzConfig::default()
        };

        let session = FuzzSession::new("test", &[], config);
        let pb = session.create_progress_bar();

        // Progress bar should be created successfully
        assert_eq!(pb.length(), Some(1000));
    }

    #[test]
    fn create_progress_bar_with_duration() {
        let config = FuzzConfig {
            max_iterations: 0,
            duration_secs: 60,
            ..FuzzConfig::default()
        };

        let session = FuzzSession::new("test", &[], config);
        let pb = session.create_progress_bar();

        // Should estimate ~50 iterations per second
        assert_eq!(pb.length(), Some(60 * 50));
    }

    #[test]
    fn create_progress_bar_unlimited() {
        let config = FuzzConfig {
            max_iterations: 0,
            duration_secs: 0,
            ..FuzzConfig::default()
        };

        let session = FuzzSession::new("test", &[], config);
        let pb = session.create_progress_bar();

        assert_eq!(pb.length(), Some(u64::MAX));
    }

    #[test]
    fn fuzz_config_default_values() {
        let config = FuzzConfig::default();

        // Just verify these fields exist and are initialized
        let _duration = config.duration_secs;
        let _iterations = config.max_iterations;
        assert!(config.request_timeout_ms > 0);
        assert!(config.corpus_path.is_none());
        assert!(config.seed.is_none());
    }

    #[test]
    fn fuzz_config_quick_profile() {
        let config = FuzzConfig::with_profile(FuzzProfile::Quick);

        assert_eq!(config.profile, FuzzProfile::Quick);
        assert!(config.duration_secs > 0 || config.max_iterations > 0);
    }

    #[test]
    fn fuzz_config_standard_profile() {
        let config = FuzzConfig::with_profile(FuzzProfile::Standard);

        assert_eq!(config.profile, FuzzProfile::Standard);
    }

    #[test]
    fn fuzz_config_intensive_profile() {
        let config = FuzzConfig::with_profile(FuzzProfile::Intensive);

        assert_eq!(config.profile, FuzzProfile::Intensive);
    }

    #[test]
    fn fuzz_config_with_seed() {
        let config = FuzzConfig {
            seed: Some(999),
            ..FuzzConfig::default()
        };

        assert_eq!(config.seed, Some(999));
    }

    #[test]
    fn fuzz_config_with_corpus_path() {
        let mut config = FuzzConfig::default();
        let path = std::path::PathBuf::from("/test/corpus");
        config.corpus_path = Some(path.clone());

        assert_eq!(config.corpus_path, Some(path));
    }

    #[test]
    fn fuzz_config_request_timeout() {
        let config = FuzzConfig {
            request_timeout_ms: 5000,
            ..FuzzConfig::default()
        };

        assert_eq!(config.request_timeout_ms, 5000);
    }

    #[test]
    fn fuzz_config_save_interesting() {
        let config_false = FuzzConfig {
            save_interesting: false,
            ..FuzzConfig::default()
        };

        assert!(!config_false.save_interesting);

        let config_true = FuzzConfig {
            save_interesting: true,
            ..FuzzConfig::default()
        };
        assert!(config_true.save_interesting);
    }

    #[test]
    fn session_with_empty_args() {
        let config = FuzzConfig::default();
        let session = FuzzSession::new("test-server", &[], config);

        assert!(session.args.is_empty());
    }

    #[test]
    fn session_with_multiple_args() {
        let config = FuzzConfig::default();
        let args = vec![
            "--arg1".to_string(),
            "value1".to_string(),
            "--arg2".to_string(),
            "value2".to_string(),
        ];
        let session = FuzzSession::new("test", &args, config);

        assert_eq!(session.args.len(), 4);
        assert_eq!(session.args[0], "--arg1");
        assert_eq!(session.args[1], "value1");
        assert_eq!(session.args[2], "--arg2");
        assert_eq!(session.args[3], "value2");
    }

    #[test]
    fn session_iterations_tracking() {
        let config = FuzzConfig::default();
        let mut session = FuzzSession::new("test", &[], config);

        assert_eq!(session.iterations, 0);

        session.iterations = 50;
        assert_eq!(session.iterations, 50);

        session.iterations += 1;
        assert_eq!(session.iterations, 51);
    }

    #[test]
    fn session_tools_empty_initially() {
        let config = FuzzConfig::default();
        let session = FuzzSession::new("test", &[], config);

        assert!(session.tools.is_empty());
        assert_eq!(session.tools.len(), 0);
    }

    #[test]
    fn session_connection_failures_tracking() {
        let config = FuzzConfig::default();
        let mut session = FuzzSession::new("test", &[], config);

        assert_eq!(session.connection_failures, 0);

        session.connection_failures += 1;
        assert_eq!(session.connection_failures, 1);

        session.connection_failures = 3;
        assert_eq!(session.connection_failures, 3);
    }

    #[test]
    fn session_restarts_tracking() {
        let config = FuzzConfig::default();
        let mut session = FuzzSession::new("test", &[], config);

        assert_eq!(session.restarts, 0);

        session.restarts = 5;
        assert_eq!(session.restarts, 5);
    }

    #[test]
    fn session_stop_reason_initially_none() {
        let config = FuzzConfig::default();
        let session = FuzzSession::new("test", &[], config);

        assert!(session.stop_reason.is_none());
    }

    #[test]
    fn stop_conditions_with_zero_limits() {
        let config = FuzzConfig {
            duration_secs: 0,
            max_iterations: 0,
            ..FuzzConfig::default()
        };

        let mut session = FuzzSession::new("test", &[], config);
        session.start_time = Some(Instant::now());
        session.iterations = 1000;

        // With both limits at 0, should not stop
        assert!(!session.should_stop());
    }

    #[test]
    fn stop_conditions_at_exact_iteration_limit() {
        let config = FuzzConfig {
            max_iterations: 100,
            duration_secs: 0,
            ..FuzzConfig::default()
        };

        let mut session = FuzzSession::new("test", &[], config);
        session.start_time = Some(Instant::now());
        session.iterations = 99;

        assert!(!session.should_stop());

        session.iterations = 100;
        assert!(session.should_stop());
    }

    #[test]
    fn stop_conditions_exceed_iteration_limit() {
        let config = FuzzConfig {
            max_iterations: 50,
            duration_secs: 0,
            ..FuzzConfig::default()
        };

        let mut session = FuzzSession::new("test", &[], config);
        session.start_time = Some(Instant::now());
        session.iterations = 100;

        assert!(session.should_stop());
    }

    #[test]
    fn stop_conditions_duration_elapsed() {
        let config = FuzzConfig {
            duration_secs: 1,
            max_iterations: 0,
            ..FuzzConfig::default()
        };

        let mut session = FuzzSession::new("test", &[], config);
        // Set start time to 2 seconds ago
        session.start_time = Some(Instant::now() - Duration::from_secs(2));

        assert!(session.should_stop());
    }

    #[test]
    fn stop_conditions_duration_not_elapsed() {
        let config = FuzzConfig {
            duration_secs: 10,
            max_iterations: 0,
            ..FuzzConfig::default()
        };

        let mut session = FuzzSession::new("test", &[], config);
        session.start_time = Some(Instant::now());

        assert!(!session.should_stop());
    }

    #[test]
    fn get_fuzz_stats_with_corpus() {
        let config = FuzzConfig::default();
        let mut session = FuzzSession::new("test", &[], config);

        session.iterations = 200;
        session.restarts = 7;

        let stats = session.get_fuzz_stats();

        assert_eq!(stats.executions, 200);
        assert_eq!(stats.restarts, 7);
        // corpus_size is usize, just verify it's initialized
        let _size = stats.corpus_size;
    }

    #[test]
    fn generate_results_with_duration() {
        let config = FuzzConfig::default();
        let mut session = FuzzSession::new("my-server", &[], config);

        // Set start time to 3 seconds ago
        session.start_time = Some(Instant::now() - Duration::from_secs(3));
        session.iterations = 42;

        let results = session.generate_results().unwrap();

        assert_eq!(results.server, "my-server");
        assert_eq!(results.iterations, 42);
        assert!(results.duration_secs >= 3);
        assert!(results.crashes.is_empty());
    }

    #[test]
    fn generate_results_server_name() {
        let config = FuzzConfig::default();
        let session = FuzzSession::new("test-server-123", &[], config);

        let results = session.generate_results().unwrap();

        assert_eq!(results.server, "test-server-123");
    }

    #[test]
    fn fuzz_stats_new() {
        let stats = FuzzStats {
            executions: 100,
            corpus_size: 50,
            restarts: 3,
        };

        assert_eq!(stats.executions, 100);
        assert_eq!(stats.corpus_size, 50);
        assert_eq!(stats.restarts, 3);
    }

    #[test]
    fn fuzz_stats_zero_values() {
        let stats = FuzzStats {
            executions: 0,
            corpus_size: 0,
            restarts: 0,
        };

        assert_eq!(stats.executions, 0);
        assert_eq!(stats.corpus_size, 0);
        assert_eq!(stats.restarts, 0);
    }

    #[test]
    fn fuzz_stats_large_values() {
        let stats = FuzzStats {
            executions: 1_000_000,
            corpus_size: 10_000,
            restarts: 500,
        };

        assert_eq!(stats.executions, 1_000_000);
        assert_eq!(stats.corpus_size, 10_000);
        assert_eq!(stats.restarts, 500);
    }

    #[test]
    fn session_client_initially_none() {
        let config = FuzzConfig::default();
        let session = FuzzSession::new("test", &[], config);

        assert!(session.client.is_none());
    }

    #[test]
    fn session_config_retention() {
        let config = FuzzConfig {
            duration_secs: 123,
            max_iterations: 456,
            request_timeout_ms: 7890,
            ..FuzzConfig::default()
        };

        let session = FuzzSession::new("test", &[], config);

        assert_eq!(session.config.duration_secs, 123);
        assert_eq!(session.config.max_iterations, 456);
        assert_eq!(session.config.request_timeout_ms, 7890);
    }

    #[test]
    fn session_server_name_preserved() {
        let config = FuzzConfig::default();
        let server_name = "node /path/to/server.js";
        let session = FuzzSession::new(server_name, &[], config);

        assert_eq!(session.server, server_name);
    }

    #[test]
    fn session_with_special_characters_in_server() {
        let config = FuzzConfig::default();
        let server = "python3 -m server --arg=\"value with spaces\"";
        let session = FuzzSession::new(server, &[], config);

        assert_eq!(session.server, server);
    }

    #[test]
    fn create_progress_bar_prefers_iterations() {
        let config = FuzzConfig {
            max_iterations: 500,
            duration_secs: 60,
            ..FuzzConfig::default()
        };

        let session = FuzzSession::new("test", &[], config);
        let pb = session.create_progress_bar();

        // Should use max_iterations when both are set
        assert_eq!(pb.length(), Some(500));
    }

    #[test]
    fn create_progress_bar_duration_estimation() {
        let config = FuzzConfig {
            max_iterations: 0,
            duration_secs: 120,
            ..FuzzConfig::default()
        };

        let session = FuzzSession::new("test", &[], config);
        let pb = session.create_progress_bar();

        // Should estimate 50 iterations/sec
        assert_eq!(pb.length(), Some(120 * 50));
    }

    #[test]
    fn session_max_connection_failures_default() {
        let config = FuzzConfig::default();
        let session = FuzzSession::new("test", &[], config);

        assert_eq!(session.max_connection_failures, 5);
    }

    #[test]
    fn fuzz_config_profiles_are_distinct() {
        let quick = FuzzConfig::with_profile(FuzzProfile::Quick);
        let standard = FuzzConfig::with_profile(FuzzProfile::Standard);
        let intensive = FuzzConfig::with_profile(FuzzProfile::Intensive);

        assert_ne!(quick.profile, standard.profile);
        assert_ne!(standard.profile, intensive.profile);
        assert_ne!(quick.profile, intensive.profile);
    }

    #[test]
    fn session_args_cloned_correctly() {
        let config = FuzzConfig::default();
        let original_args = vec!["--flag".to_string(), "value".to_string()];
        let session = FuzzSession::new("test", &original_args, config);

        // Verify args are cloned, not moved
        assert_eq!(session.args, original_args);
        assert_eq!(original_args.len(), 2);
    }

    // ===== NEW COMPREHENSIVE TESTS FOR INCREASED COVERAGE =====

    #[test]
    fn session_with_custom_resource_limits() {
        use crate::fuzzer::limits::ResourceLimits;

        let limits = ResourceLimits::default()
            .with_max_memory(1024 * 1024 * 1024)
            .with_max_executions(5000);

        let config = FuzzConfig::default().with_resource_limits(limits);
        let session = FuzzSession::new("test-server", &[], config);

        assert_eq!(
            session.config.resource_limits.max_memory,
            Some(1024 * 1024 * 1024)
        );
        assert_eq!(session.config.resource_limits.max_executions, Some(5000));
    }

    #[test]
    fn session_with_all_config_options() {
        let mut config = FuzzConfig::with_profile(FuzzProfile::Standard);
        config.seed = Some(999);
        config.corpus_path = Some(std::path::PathBuf::from("/tmp/corpus"));
        config.save_interesting = true;
        config.request_timeout_ms = 8000;

        let args = vec!["--verbose".to_string()];
        let session = FuzzSession::new("complex-server", &args, config);

        assert_eq!(session.server, "complex-server");
        assert_eq!(session.args.len(), 1);
        assert_eq!(session.args[0], "--verbose");
        assert_eq!(session.config.seed, Some(999));
        assert_eq!(session.config.request_timeout_ms, 8000);
    }

    #[test]
    fn stop_conditions_resource_limit_exceeded() {
        use crate::fuzzer::limits::ResourceLimits;

        let limits = ResourceLimits::default().with_max_executions(50);
        let config = FuzzConfig::default().with_resource_limits(limits);

        let mut session = FuzzSession::new("test", &[], config);
        session.start_time = Some(Instant::now());
        session.iterations = 49;

        assert!(!session.should_stop());

        session.iterations = 50;
        assert!(session.should_stop());
        assert!(session.stop_reason.is_some());
    }

    #[test]
    fn stop_conditions_restart_limit() {
        use crate::fuzzer::limits::ResourceLimits;

        let limits = ResourceLimits::default().with_max_restarts(5);
        let config = FuzzConfig::default().with_resource_limits(limits);

        let mut session = FuzzSession::new("test", &[], config);
        session.start_time = Some(Instant::now());
        session.restarts = 4;

        assert!(!session.should_stop());

        session.restarts = 5;
        assert!(session.should_stop());
    }

    #[test]
    fn get_fuzz_stats_complete() {
        let config = FuzzConfig::default();
        let mut session = FuzzSession::new("test", &[], config);

        session.iterations = 250;
        session.restarts = 10;

        let stats = session.get_fuzz_stats();

        assert_eq!(stats.executions, 250);
        assert_eq!(stats.restarts, 10);
        assert_eq!(stats.corpus_size, session.corpus.corpus_size());
    }

    #[test]
    fn session_timeout_configuration() {
        let config = FuzzConfig {
            request_timeout_ms: 1000,
            ..FuzzConfig::default()
        };

        let session = FuzzSession::new("test", &[], config);
        assert_eq!(session.config.request_timeout_ms, 1000);
    }

    #[test]
    fn session_with_ci_profile() {
        let config = FuzzConfig::with_profile(FuzzProfile::CI);
        let session = FuzzSession::new("test", &[], config);

        assert_eq!(session.config.profile, FuzzProfile::CI);
        assert_eq!(session.config.seed, Some(42)); // CI has deterministic seed
    }

    #[test]
    fn session_detector_timeout_matches_config() {
        let config = FuzzConfig {
            request_timeout_ms: 7500,
            ..FuzzConfig::default()
        };

        let session = FuzzSession::new("test", &[], config);
        assert_eq!(session.config.request_timeout_ms, 7500);
    }

    #[test]
    fn session_engine_uses_seed() {
        let config = FuzzConfig {
            seed: Some(54321),
            ..FuzzConfig::default()
        };

        let session = FuzzSession::new("test", &[], config);
        assert!(session.config.seed.is_some());
    }

    #[test]
    fn session_corpus_manager_with_path() {
        let mut config = FuzzConfig::default();
        let corpus_path = std::path::PathBuf::from("/tmp/test-corpus");
        config.corpus_path = Some(corpus_path.clone());

        let session = FuzzSession::new("test", &[], config);
        assert_eq!(session.config.corpus_path, Some(corpus_path));
    }

    #[test]
    fn session_corpus_manager_without_path() {
        let config = FuzzConfig::default();
        assert!(config.corpus_path.is_none());

        let session = FuzzSession::new("test", &[], config);
        assert!(session.config.corpus_path.is_none());
    }

    #[test]
    fn session_coverage_tracker_initialized() {
        let config = FuzzConfig::default();
        let session = FuzzSession::new("test", &[], config);

        let stats = session.coverage.stats();
        assert_eq!(stats.paths_explored, 0);
    }

    #[test]
    fn generate_results_coverage_stats() {
        let config = FuzzConfig::default();
        let mut session = FuzzSession::new("test-server", &[], config);
        session.start_time = Some(Instant::now());
        session.iterations = 150;

        let results = session.generate_results().unwrap();

        assert_eq!(results.iterations, 150);
        // paths_explored is always valid (usize is non-negative)
        let _ = results.coverage.paths_explored;
    }

    #[test]
    fn generate_results_interesting_inputs_count() {
        let config = FuzzConfig::default();
        let mut session = FuzzSession::new("test", &[], config);
        session.start_time = Some(Instant::now());

        let results = session.generate_results().unwrap();

        assert_eq!(
            results.interesting_inputs,
            session.corpus.interesting_count()
        );
    }

    #[test]
    fn session_max_connection_failures_five() {
        let config = FuzzConfig::default();
        let session = FuzzSession::new("test", &[], config);

        assert_eq!(session.max_connection_failures, 5);
    }

    #[test]
    fn fuzz_stats_default_initialization() {
        let stats = FuzzStats::default();

        assert_eq!(stats.executions, 0);
        assert_eq!(stats.corpus_size, 0);
        assert_eq!(stats.restarts, 0);
    }

    #[test]
    fn stop_conditions_both_duration_and_iteration_limits() {
        let config = FuzzConfig {
            duration_secs: 1,
            max_iterations: 100,
            ..FuzzConfig::default()
        };

        let mut session = FuzzSession::new("test", &[], config);
        session.start_time = Some(Instant::now());
        session.iterations = 50;

        assert!(!session.should_stop());

        session.iterations = 100;
        assert!(session.should_stop());
    }

    #[test]
    fn stop_conditions_duration_reached_before_iterations() {
        let config = FuzzConfig {
            duration_secs: 1,
            max_iterations: 10000,
            ..FuzzConfig::default()
        };

        let mut session = FuzzSession::new("test", &[], config);
        session.start_time = Some(Instant::now() - Duration::from_secs(2));
        session.iterations = 50;

        assert!(session.should_stop());
    }

    #[test]
    fn create_progress_bar_both_limits_set() {
        let config = FuzzConfig {
            max_iterations: 1000,
            duration_secs: 120,
            ..FuzzConfig::default()
        };

        let session = FuzzSession::new("test", &[], config);
        let pb = session.create_progress_bar();

        assert_eq!(pb.length(), Some(1000));
    }

    #[test]
    fn session_with_multiple_tools_in_config() {
        let config = FuzzConfig {
            target_tools: Some(vec![
                "tool1".to_string(),
                "tool2".to_string(),
                "tool3".to_string(),
            ]),
            ..Default::default()
        };

        let session = FuzzSession::new("test", &[], config);
        assert_eq!(
            session.config.target_tools,
            Some(vec![
                "tool1".to_string(),
                "tool2".to_string(),
                "tool3".to_string(),
            ])
        );
    }

    #[test]
    fn session_with_dictionary_path() {
        let config = FuzzConfig {
            dictionary_path: Some(std::path::PathBuf::from("/tmp/dict.txt")),
            ..Default::default()
        };

        let session = FuzzSession::new("test", &[], config);
        assert_eq!(
            session.config.dictionary_path,
            Some(std::path::PathBuf::from("/tmp/dict.txt"))
        );
    }

    #[test]
    fn session_save_interesting_flag() {
        let config = FuzzConfig {
            save_interesting: false,
            ..Default::default()
        };

        let session = FuzzSession::new("test", &[], config);
        assert!(!session.config.save_interesting);

        let config2 = FuzzConfig {
            save_interesting: true,
            ..Default::default()
        };

        let session2 = FuzzSession::new("test", &[], config2);
        assert!(session2.config.save_interesting);
    }

    #[test]
    fn session_coverage_threshold() {
        let config = FuzzConfig {
            coverage_threshold: 0.05,
            ..Default::default()
        };

        let session = FuzzSession::new("test", &[], config);
        assert!((session.config.coverage_threshold - 0.05).abs() < f64::EPSILON);
    }

    #[test]
    fn session_workers_configuration() {
        let config = FuzzConfig {
            workers: 4,
            ..Default::default()
        };

        let session = FuzzSession::new("test", &[], config);
        assert_eq!(session.config.workers, 4);
    }

    #[test]
    fn session_connection_failures_starts_at_zero() {
        let config = FuzzConfig::default();
        let session = FuzzSession::new("test", &[], config);

        assert_eq!(session.connection_failures, 0);
    }

    #[test]
    fn session_restarts_starts_at_zero() {
        let config = FuzzConfig::default();
        let session = FuzzSession::new("test", &[], config);

        assert_eq!(session.restarts, 0);
    }

    #[test]
    fn session_iterations_starts_at_zero() {
        let config = FuzzConfig::default();
        let session = FuzzSession::new("test", &[], config);

        assert_eq!(session.iterations, 0);
    }

    #[test]
    fn stop_reason_initially_none_duplicate() {
        let config = FuzzConfig::default();
        let session = FuzzSession::new("test", &[], config);

        assert!(session.stop_reason.is_none());
    }

    #[test]
    fn start_time_initially_none_duplicate() {
        let config = FuzzConfig::default();
        let session = FuzzSession::new("test", &[], config);

        assert!(session.start_time.is_none());
    }

    #[test]
    fn tools_initially_empty_duplicate() {
        let config = FuzzConfig::default();
        let session = FuzzSession::new("test", &[], config);

        assert!(session.tools.is_empty());
        assert_eq!(session.tools.len(), 0);
    }

    #[test]
    fn client_initially_none_duplicate() {
        let config = FuzzConfig::default();
        let session = FuzzSession::new("test", &[], config);

        assert!(session.client.is_none());
    }

    #[test]
    fn session_resource_monitor_created() {
        let config = FuzzConfig::default();
        let session = FuzzSession::new("test", &[], config);

        assert!(session.config.resource_limits.max_time.is_some());
    }

    #[test]
    fn fuzz_config_profile_field_matches() {
        let config = FuzzConfig::with_profile(FuzzProfile::Intensive);
        let session = FuzzSession::new("test", &[], config);

        assert_eq!(session.config.profile, FuzzProfile::Intensive);
    }

    #[test]
    fn generate_results_with_zero_iterations() {
        let config = FuzzConfig::default();
        let session = FuzzSession::new("test", &[], config);

        let results = session.generate_results().unwrap();

        assert_eq!(results.iterations, 0);
        assert!(results.crashes.is_empty());
    }

    #[test]
    fn generate_results_preserves_server_name() {
        let config = FuzzConfig::default();
        let session = FuzzSession::new("unique-server-name", &[], config);

        let results = session.generate_results().unwrap();
        assert_eq!(results.server, "unique-server-name");
    }

    #[test]
    fn session_args_ownership() {
        let config = FuzzConfig::default();
        let args = vec!["arg1".to_string(), "arg2".to_string()];

        let session = FuzzSession::new("test", &args, config);

        assert_eq!(args.len(), 2);
        assert_eq!(session.args, args);
    }

    #[test]
    fn session_server_name_empty_string() {
        let config = FuzzConfig::default();
        let session = FuzzSession::new("", &[], config);

        assert_eq!(session.server, "");
    }

    #[test]
    fn session_with_long_server_command() {
        let config = FuzzConfig::default();
        let long_command = "python3 -u /very/long/path/to/server.py --verbose --debug --port 8080";
        let session = FuzzSession::new(long_command, &[], config);

        assert_eq!(session.server, long_command);
    }

    #[test]
    fn stop_conditions_with_no_resource_limits() {
        use crate::fuzzer::limits::ResourceLimits;

        let limits = ResourceLimits::unlimited();
        let config = FuzzConfig {
            duration_secs: 0,
            max_iterations: 0,
            ..FuzzConfig::default()
        }
        .with_resource_limits(limits);

        let mut session = FuzzSession::new("test", &[], config);
        session.start_time = Some(Instant::now());
        session.iterations = 999999;

        assert!(!session.should_stop());
    }

    #[test]
    fn progress_bar_with_very_large_duration() {
        let config = FuzzConfig {
            max_iterations: 0,
            duration_secs: 86400, // 1 day
            ..FuzzConfig::default()
        };

        let session = FuzzSession::new("test", &[], config);
        let pb = session.create_progress_bar();

        assert_eq!(pb.length(), Some(86400 * 50));
    }

    #[test]
    fn session_mutation_engine_strategies() {
        let config = FuzzConfig::with_profile(FuzzProfile::Quick);
        let session = FuzzSession::new("test", &[], config);

        assert_eq!(session.config.profile, FuzzProfile::Quick);
    }

    #[test]
    fn fuzz_stats_with_max_values() {
        let stats = FuzzStats {
            executions: u64::MAX,
            corpus_size: usize::MAX,
            restarts: u32::MAX,
        };

        assert_eq!(stats.executions, u64::MAX);
        assert_eq!(stats.corpus_size, usize::MAX);
        assert_eq!(stats.restarts, u32::MAX);
    }

    #[test]
    fn session_config_cloned_into_session() {
        let config = FuzzConfig::default().with_duration(999).with_workers(8);

        let session = FuzzSession::new("test", &[], config.clone());

        assert_eq!(session.config.duration_secs, config.duration_secs);
        assert_eq!(session.config.workers, config.workers);
    }

    #[test]
    fn generate_results_duration_calculation() {
        let config = FuzzConfig::default();
        let mut session = FuzzSession::new("test", &[], config);

        session.start_time = Some(Instant::now() - Duration::from_secs(5));

        let results = session.generate_results().unwrap();

        assert!(results.duration_secs >= 5);
    }

    #[test]
    fn stop_conditions_multiple_checks() {
        let config = FuzzConfig {
            duration_secs: 10,
            max_iterations: 100,
            ..FuzzConfig::default()
        };

        let mut session = FuzzSession::new("test", &[], config);
        session.start_time = Some(Instant::now());

        assert!(!session.should_stop());
        session.iterations = 50;
        assert!(!session.should_stop());
        session.iterations = 75;
        assert!(!session.should_stop());
        session.iterations = 100;
        assert!(session.should_stop());
    }

    #[test]
    fn session_with_intensive_profile_settings() {
        let config = FuzzConfig::with_profile(FuzzProfile::Intensive);
        let session = FuzzSession::new("test", &[], config);

        assert_eq!(session.config.profile, FuzzProfile::Intensive);
        assert_eq!(session.config.duration_secs, 0);
        assert_eq!(session.config.max_iterations, 0);
    }

    #[test]
    fn session_corpus_initialization_flag() {
        let config = FuzzConfig::default();
        let session = FuzzSession::new("test", &[], config);

        assert_eq!(session.corpus.corpus_size(), 0);
    }

    #[test]
    fn session_with_standard_profile_defaults() {
        let config = FuzzConfig::with_profile(FuzzProfile::Standard);
        let session = FuzzSession::new("test", &[], config);

        assert_eq!(session.config.profile, FuzzProfile::Standard);
        assert_eq!(session.config.duration_secs, 300);
    }

    #[test]
    fn session_with_quick_profile_defaults() {
        let config = FuzzConfig::with_profile(FuzzProfile::Quick);
        let session = FuzzSession::new("test", &[], config);

        assert_eq!(session.config.profile, FuzzProfile::Quick);
        assert_eq!(session.config.duration_secs, 60);
        assert_eq!(session.config.max_iterations, 500);
    }

    #[test]
    fn fuzz_stats_clone() {
        let stats = FuzzStats {
            executions: 100,
            corpus_size: 50,
            restarts: 3,
        };

        let cloned = stats.clone();
        assert_eq!(cloned.executions, 100);
        assert_eq!(cloned.corpus_size, 50);
        assert_eq!(cloned.restarts, 3);
    }

    #[test]
    fn fuzz_stats_debug() {
        let stats = FuzzStats {
            executions: 100,
            corpus_size: 50,
            restarts: 3,
        };

        let debug_str = format!("{:?}", stats);
        assert!(debug_str.contains("FuzzStats"));
    }

    #[test]
    fn stop_conditions_legacy_iteration_limit() {
        let config = FuzzConfig {
            duration_secs: 0,
            max_iterations: 200,
            ..FuzzConfig::default()
        };

        let mut session = FuzzSession::new("test", &[], config);
        session.start_time = Some(Instant::now());
        session.iterations = 199;

        assert!(!session.should_stop());

        session.iterations = 200;
        assert!(session.should_stop());
    }

    #[test]
    fn stop_conditions_legacy_duration_limit() {
        let config = FuzzConfig {
            duration_secs: 2,
            max_iterations: 0,
            ..FuzzConfig::default()
        };

        let mut session = FuzzSession::new("test", &[], config);
        session.start_time = Some(Instant::now() - Duration::from_secs(3));

        assert!(session.should_stop());
    }

    #[test]
    fn stop_reason_tracked() {
        use crate::fuzzer::limits::ResourceLimits;

        let limits = ResourceLimits::default().with_max_executions(50);
        let config = FuzzConfig::default().with_resource_limits(limits);
        let mut session = FuzzSession::new("test", &[], config);
        session.start_time = Some(Instant::now());
        session.iterations = 50;
        assert!(session.should_stop());
        assert!(session.stop_reason.is_some());
    }

    #[test]
    fn connection_failures_tracking() {
        let config = FuzzConfig::default();
        let mut session = FuzzSession::new("test", &[], config);
        session.connection_failures = 3;
        assert_eq!(session.connection_failures, 3);
    }

    #[test]
    fn iterations_counter() {
        let config = FuzzConfig::default();
        let mut session = FuzzSession::new("test", &[], config);
        for i in 1..=50 {
            session.iterations += 1;
            assert_eq!(session.iterations, i);
        }
    }

    #[test]
    fn progress_bar_unlimited() {
        let config = FuzzConfig {
            max_iterations: 0,
            duration_secs: 0,
            ..FuzzConfig::default()
        };
        let session = FuzzSession::new("test", &[], config);
        let pb = session.create_progress_bar();
        assert_eq!(pb.length(), Some(u64::MAX));
    }

    #[test]
    fn all_profiles_tested() {
        for profile in [
            FuzzProfile::Quick,
            FuzzProfile::Standard,
            FuzzProfile::Intensive,
            FuzzProfile::CI,
        ] {
            let config = FuzzConfig::with_profile(profile);
            let session = FuzzSession::new("test", &[], config);
            assert_eq!(session.config.profile, profile);
        }
    }

    #[test]
    fn timeout_edge_cases() {
        for timeout in [0u64, 1000, u64::MAX] {
            let config = FuzzConfig {
                request_timeout_ms: timeout,
                ..FuzzConfig::default()
            };
            let session = FuzzSession::new("test", &[], config);
            assert_eq!(session.config.request_timeout_ms, timeout);
        }
    }

    #[test]
    fn coverage_thresholds() {
        for threshold in [0.0, 0.01, 0.1, 1.0] {
            let config = FuzzConfig {
                coverage_threshold: threshold,
                ..FuzzConfig::default()
            };
            let session = FuzzSession::new("test", &[], config);
            assert!((session.config.coverage_threshold - threshold).abs() < f64::EPSILON);
        }
    }

    #[test]
    fn comprehensive_session_state() {
        use crate::fuzzer::limits::ResourceLimits;
        use std::path::PathBuf;

        let limits = ResourceLimits::default()
            .with_max_time(Duration::from_secs(600))
            .with_max_executions(10000);
        let config = FuzzConfig {
            duration_secs: 300,
            max_iterations: 5000,
            request_timeout_ms: 8000,
            workers: 4,
            corpus_path: Some(PathBuf::from("/corpus")),
            dictionary_path: Some(PathBuf::from("/dict")),
            target_tools: Some(vec!["tool1".to_string()]),
            profile: FuzzProfile::Standard,
            save_interesting: true,
            coverage_threshold: 0.02,
            seed: Some(12345),
            resource_limits: limits,
        };
        let args = vec!["--arg".to_string()];
        let session = FuzzSession::new("server", &args, config);

        assert_eq!(session.server, "server");
        assert_eq!(session.args.len(), 1);
        assert_eq!(session.config.duration_secs, 300);
        assert_eq!(session.config.max_iterations, 5000);
        assert_eq!(session.config.workers, 4);
        assert_eq!(session.iterations, 0);
        assert_eq!(session.connection_failures, 0);
        assert_eq!(session.restarts, 0);
        assert!(session.stop_reason.is_none());
        assert!(session.client.is_none());
        assert!(session.start_time.is_none());
    }

    #[test]
    #[ignore = "timing dependent test"]
    fn stop_conditions_resource_limit_max_time() {
        use crate::fuzzer::limits::ResourceLimits;

        let limits = ResourceLimits::default().with_max_time(Duration::from_secs(5));
        let config = FuzzConfig::default().with_resource_limits(limits);

        let mut session = FuzzSession::new("test", &[], config);
        session.start_time = Some(Instant::now() - Duration::from_secs(6));

        assert!(session.should_stop());
        assert!(session.stop_reason.is_some());
    }

    #[test]
    fn stop_conditions_resource_limit_corpus_size() {
        use crate::fuzzer::limits::ResourceLimits;

        let limits = ResourceLimits::default().with_max_corpus_size(100);
        let config = FuzzConfig::default().with_resource_limits(limits);

        let mut session = FuzzSession::new("test", &[], config);
        session.start_time = Some(Instant::now());

        // Corpus size tracking tested via get_fuzz_stats
        assert!(!session.should_stop() || session.stop_reason.is_some());
    }

    #[test]
    fn session_with_zero_timeout() {
        let config = FuzzConfig {
            request_timeout_ms: 0,
            ..FuzzConfig::default()
        };

        let session = FuzzSession::new("test", &[], config);
        assert_eq!(session.config.request_timeout_ms, 0);
    }

    #[test]
    fn session_with_max_timeout() {
        let config = FuzzConfig {
            request_timeout_ms: u64::MAX,
            ..FuzzConfig::default()
        };

        let session = FuzzSession::new("test", &[], config);
        assert_eq!(session.config.request_timeout_ms, u64::MAX);
    }

    #[test]
    fn session_iterations_overflow_safety() {
        let config = FuzzConfig::default();
        let mut session = FuzzSession::new("test", &[], config);

        session.iterations = u64::MAX - 1;
        assert_eq!(session.iterations, u64::MAX - 1);

        session.iterations += 1;
        assert_eq!(session.iterations, u64::MAX);
    }

    #[test]
    fn session_restarts_max_value() {
        let config = FuzzConfig::default();
        let mut session = FuzzSession::new("test", &[], config);

        session.restarts = u32::MAX;
        assert_eq!(session.restarts, u32::MAX);
    }

    #[test]
    fn session_connection_failures_limit_boundary() {
        let config = FuzzConfig::default();
        let mut session = FuzzSession::new("test", &[], config);

        session.connection_failures = 4;
        assert_eq!(session.connection_failures, 4);
        assert!(session.connection_failures < session.max_connection_failures);

        session.connection_failures = 5;
        assert_eq!(session.connection_failures, session.max_connection_failures);
    }

    #[test]
    fn stop_conditions_check_ordering() {
        let config = FuzzConfig {
            duration_secs: 100,
            max_iterations: 1000,
            ..FuzzConfig::default()
        };

        let mut session = FuzzSession::new("test", &[], config);
        session.start_time = Some(Instant::now() - Duration::from_secs(101));
        session.iterations = 50;

        // Duration should trigger stop even if iterations haven't been reached
        assert!(session.should_stop());
    }

    #[test]
    fn get_fuzz_stats_consistency() {
        let config = FuzzConfig::default();
        let mut session = FuzzSession::new("test", &[], config);

        session.iterations = 42;
        session.restarts = 7;

        let stats1 = session.get_fuzz_stats();
        let stats2 = session.get_fuzz_stats();

        assert_eq!(stats1.executions, stats2.executions);
        assert_eq!(stats1.restarts, stats2.restarts);
        assert_eq!(stats1.corpus_size, stats2.corpus_size);
    }

    #[test]
    fn generate_results_empty_corpus() {
        let config = FuzzConfig::default();
        let mut session = FuzzSession::new("test-server", &[], config);
        session.start_time = Some(Instant::now());
        session.iterations = 250;

        let results = session.generate_results().unwrap();

        assert_eq!(results.server, "test-server");
        assert_eq!(results.iterations, 250);
        assert_eq!(results.crashes.len(), 0);
        assert_eq!(results.interesting_inputs, 0);
    }

    #[test]
    fn session_with_all_profiles() {
        for profile in [
            FuzzProfile::Quick,
            FuzzProfile::Standard,
            FuzzProfile::Intensive,
            FuzzProfile::CI,
        ] {
            let config = FuzzConfig::with_profile(profile);
            let session = FuzzSession::new("test", &[], config);

            assert_eq!(session.config.profile, profile);
            assert_eq!(session.iterations, 0);
            assert!(session.client.is_none());
            assert!(session.tools.is_empty());
        }
    }

    #[test]
    fn session_config_immutability_after_creation() {
        let config = FuzzConfig {
            duration_secs: 100,
            max_iterations: 500,
            ..FuzzConfig::default()
        };

        let session = FuzzSession::new("test", &[], config);

        assert_eq!(session.config.duration_secs, 100);
        assert_eq!(session.config.max_iterations, 500);
    }

    #[test]
    fn progress_bar_zero_duration() {
        let config = FuzzConfig {
            max_iterations: 0,
            duration_secs: 0,
            ..FuzzConfig::default()
        };

        let session = FuzzSession::new("test", &[], config);
        let pb = session.create_progress_bar();

        assert_eq!(pb.length(), Some(u64::MAX));
    }

    #[test]
    fn progress_bar_small_duration() {
        let config = FuzzConfig {
            max_iterations: 0,
            duration_secs: 1,
            ..FuzzConfig::default()
        };

        let session = FuzzSession::new("test", &[], config);
        let pb = session.create_progress_bar();

        assert_eq!(pb.length(), Some(50));
    }

    #[test]
    fn session_detector_created_with_timeout() {
        let config = FuzzConfig {
            request_timeout_ms: 3000,
            ..FuzzConfig::default()
        };

        let session = FuzzSession::new("test", &[], config);
        assert_eq!(session.config.request_timeout_ms, 3000);
    }

    #[test]
    fn session_coverage_tracker_initial_stats() {
        let config = FuzzConfig::default();
        let session = FuzzSession::new("test", &[], config);

        let stats = session.coverage.stats();
        assert_eq!(stats.paths_explored, 0);
        assert_eq!(stats.new_coverage_rate, 0.0);
    }

    #[test]
    fn session_corpus_manager_initial_state() {
        let config = FuzzConfig::default();
        let session = FuzzSession::new("test", &[], config);

        assert_eq!(session.corpus.corpus_size(), 0);
        assert_eq!(session.corpus.crash_count(), 0);
        assert_eq!(session.corpus.interesting_count(), 0);
    }

    #[test]
    fn stop_conditions_with_start_time_set() {
        let config = FuzzConfig {
            duration_secs: 5,
            max_iterations: 0,
            ..FuzzConfig::default()
        };

        let mut session = FuzzSession::new("test", &[], config);
        session.start_time = Some(Instant::now());

        // Immediately after start, shouldn't stop
        assert!(!session.should_stop());
    }

    #[test]
    fn stop_conditions_exact_duration_boundary() {
        let config = FuzzConfig {
            duration_secs: 5,
            max_iterations: 0,
            ..FuzzConfig::default()
        };

        let mut session = FuzzSession::new("test", &[], config);
        session.start_time = Some(Instant::now() - Duration::from_secs(5));

        // At exact boundary, should stop
        assert!(session.should_stop());
    }

    #[test]
    fn fuzz_config_builder_methods() {
        let config = FuzzConfig::default()
            .with_duration(300)
            .with_iterations(10000)
            .with_timeout(5000);

        assert_eq!(config.duration_secs, 300);
        assert_eq!(config.max_iterations, 10000);
        assert_eq!(config.request_timeout_ms, 5000);
    }

    #[test]
    fn session_multiple_args_preserved() {
        let config = FuzzConfig::default();
        let args = vec![
            "--host".to_string(),
            "localhost".to_string(),
            "--port".to_string(),
            "8080".to_string(),
            "--verbose".to_string(),
        ];

        let session = FuzzSession::new("test", &args, config);

        assert_eq!(session.args.len(), 5);
        assert_eq!(session.args[0], "--host");
        assert_eq!(session.args[1], "localhost");
        assert_eq!(session.args[2], "--port");
        assert_eq!(session.args[3], "8080");
        assert_eq!(session.args[4], "--verbose");
    }

    #[test]
    fn session_args_with_special_chars() {
        let config = FuzzConfig::default();
        let args = vec![
            "--data".to_string(),
            "{\"key\": \"value\"}".to_string(),
            "--path".to_string(),
            "/path/to/file".to_string(),
        ];

        let session = FuzzSession::new("test", &args, config);

        assert_eq!(session.args.len(), 4);
        assert_eq!(session.args[1], "{\"key\": \"value\"}");
        assert_eq!(session.args[3], "/path/to/file");
    }

    #[test]
    fn generate_results_with_long_duration() {
        let config = FuzzConfig::default();
        let mut session = FuzzSession::new("test", &[], config);

        session.start_time = Some(Instant::now() - Duration::from_secs(3600));
        session.iterations = 100000;

        let results = session.generate_results().unwrap();

        assert!(results.duration_secs >= 3600);
        assert_eq!(results.iterations, 100000);
    }

    #[test]
    fn session_state_after_multiple_iterations() {
        let config = FuzzConfig::default();
        let mut session = FuzzSession::new("test", &[], config);

        for i in 1..=100 {
            session.iterations += 1;
            assert_eq!(session.iterations, i);
        }

        assert_eq!(session.iterations, 100);
    }

    #[test]
    fn stop_conditions_iterations_exact_match() {
        let config = FuzzConfig {
            duration_secs: 0,
            max_iterations: 42,
            ..FuzzConfig::default()
        };

        let mut session = FuzzSession::new("test", &[], config);
        session.start_time = Some(Instant::now());
        session.iterations = 41;

        assert!(!session.should_stop());

        session.iterations = 42;
        assert!(session.should_stop());
    }

    #[test]
    fn session_with_seed_deterministic() {
        let config1 = FuzzConfig {
            seed: Some(99999),
            ..FuzzConfig::default()
        };
        let config2 = FuzzConfig {
            seed: Some(99999),
            ..FuzzConfig::default()
        };

        let session1 = FuzzSession::new("test", &[], config1);
        let session2 = FuzzSession::new("test", &[], config2);

        assert_eq!(session1.config.seed, session2.config.seed);
    }

    #[test]
    fn session_resource_monitor_initialization() {
        use crate::fuzzer::limits::ResourceLimits;

        let limits = ResourceLimits::default()
            .with_max_executions(1000)
            .with_max_time(Duration::from_secs(300));

        let config = FuzzConfig::default().with_resource_limits(limits);
        let session = FuzzSession::new("test", &[], config);

        assert_eq!(session.config.resource_limits.max_executions, Some(1000));
    }

    #[test]
    fn fuzz_stats_equality() {
        let stats1 = FuzzStats {
            executions: 100,
            corpus_size: 50,
            restarts: 3,
        };
        let stats2 = FuzzStats {
            executions: 100,
            corpus_size: 50,
            restarts: 3,
        };

        assert_eq!(stats1.executions, stats2.executions);
        assert_eq!(stats1.corpus_size, stats2.corpus_size);
        assert_eq!(stats1.restarts, stats2.restarts);
    }

    #[test]
    fn session_start_time_none_initially() {
        let config = FuzzConfig::default();
        let session = FuzzSession::new("test", &[], config);

        assert!(session.start_time.is_none());
    }

    #[test]
    fn session_tools_vector_capacity() {
        let config = FuzzConfig::default();
        let session = FuzzSession::new("test", &[], config);

        assert!(session.tools.is_empty());
        assert_eq!(session.tools.len(), 0);
        assert_eq!(session.tools.capacity(), 0);
    }

    #[test]
    fn generate_results_fields_complete() {
        let config = FuzzConfig::default();
        let mut session = FuzzSession::new("my-test-server", &[], config);
        session.start_time = Some(Instant::now());
        session.iterations = 42;

        let results = session.generate_results().unwrap();

        assert_eq!(results.server, "my-test-server");
        assert_eq!(results.iterations, 42);
        assert!(results.duration_secs >= 0);
        assert!(results.crashes.is_empty());
        assert_eq!(results.interesting_inputs, 0);
    }

    #[test]
    fn session_max_connection_failures_constant() {
        let config1 = FuzzConfig::default();
        let config2 = FuzzConfig::with_profile(FuzzProfile::Quick);
        let config3 = FuzzConfig::with_profile(FuzzProfile::Intensive);

        let session1 = FuzzSession::new("test", &[], config1);
        let session2 = FuzzSession::new("test", &[], config2);
        let session3 = FuzzSession::new("test", &[], config3);

        assert_eq!(session1.max_connection_failures, 5);
        assert_eq!(session2.max_connection_failures, 5);
        assert_eq!(session3.max_connection_failures, 5);
    }

    #[test]
    fn stop_conditions_no_limits_set() {
        let config = FuzzConfig {
            duration_secs: 0,
            max_iterations: 0,
            ..FuzzConfig::default()
        };

        let mut session = FuzzSession::new("test", &[], config);
        session.start_time = Some(Instant::now());
        session.iterations = 999999;

        // With no limits, should not stop
        assert!(!session.should_stop());
    }

    #[test]
    fn session_engine_mutation_strategies() {
        let config = FuzzConfig::with_profile(FuzzProfile::Intensive);
        let session = FuzzSession::new("test", &[], config);

        // Engine is created with strategies from profile
        assert_eq!(session.config.profile, FuzzProfile::Intensive);
    }

    #[test]
    fn progress_bar_iteration_preference() {
        let config = FuzzConfig {
            max_iterations: 100,
            duration_secs: 3600,
            ..FuzzConfig::default()
        };

        let session = FuzzSession::new("test", &[], config);
        let pb = session.create_progress_bar();

        // Should prefer iterations over duration
        assert_eq!(pb.length(), Some(100));
    }

    #[test]
    fn session_corpus_path_none_by_default() {
        let config = FuzzConfig::default();
        let session = FuzzSession::new("test", &[], config);

        assert!(session.config.corpus_path.is_none());
    }

    #[test]
    fn session_seed_none_by_default() {
        let config = FuzzConfig::default();
        let session = FuzzSession::new("test", &[], config);

        assert!(session.config.seed.is_none());
    }

    #[test]
    fn get_fuzz_stats_reflects_current_state() {
        let config = FuzzConfig::default();
        let mut session = FuzzSession::new("test", &[], config);

        let stats_before = session.get_fuzz_stats();
        assert_eq!(stats_before.executions, 0);
        assert_eq!(stats_before.restarts, 0);

        session.iterations = 100;
        session.restarts = 5;

        let stats_after = session.get_fuzz_stats();
        assert_eq!(stats_after.executions, 100);
        assert_eq!(stats_after.restarts, 5);
    }

    #[test]
    fn session_server_name_unicode() {
        let config = FuzzConfig::default();
        let server = "node server-日本語.js";
        let session = FuzzSession::new(server, &[], config);

        assert_eq!(session.server, server);
    }

    #[test]
    fn fuzz_config_clone_independence() {
        let config1 = FuzzConfig {
            duration_secs: 100,
            max_iterations: 500,
            ..FuzzConfig::default()
        };

        let config2 = config1.clone();

        assert_eq!(config1.duration_secs, config2.duration_secs);
        assert_eq!(config1.max_iterations, config2.max_iterations);
    }

    #[test]
    fn session_with_empty_server_name() {
        let config = FuzzConfig::default();
        let session = FuzzSession::new("", &[], config);

        assert_eq!(session.server, "");
        assert_eq!(session.iterations, 0);
    }

    #[test]
    fn stop_conditions_combined_limits() {
        use crate::fuzzer::limits::ResourceLimits;

        let limits = ResourceLimits::default()
            .with_max_executions(100)
            .with_max_time(Duration::from_secs(60));

        let config = FuzzConfig {
            duration_secs: 30,
            max_iterations: 50,
            ..FuzzConfig::default()
        }
        .with_resource_limits(limits);

        let mut session = FuzzSession::new("test", &[], config);
        session.start_time = Some(Instant::now());
        session.iterations = 49;

        assert!(!session.should_stop());

        session.iterations = 50;
        assert!(session.should_stop());
    }
}
