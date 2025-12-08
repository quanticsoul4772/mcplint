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
    fn stop_conditions() {
        let mut config = FuzzConfig::default();
        config.duration_secs = 0;
        config.max_iterations = 100;

        let mut session = FuzzSession::new("test", &[], config);
        session.start_time = Some(Instant::now());
        session.iterations = 50;

        assert!(!session.should_stop());

        session.iterations = 100;
        assert!(session.should_stop());
    }
}
