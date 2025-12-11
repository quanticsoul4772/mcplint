//! Fuzz Engine - Coverage-guided fuzzing for MCP servers
//!
//! This module implements the M3 milestone: Security Fuzzer.
//! It provides coverage-guided fuzzing to discover crashes, hangs,
//! and unexpected behaviors in MCP servers.
//!
//! # Components
//!
//! - **FuzzEngine**: Main entry point for fuzzing operations
//! - **FuzzSession**: Manages a single fuzzing session
//! - **MutationEngine**: Generates mutated inputs
//! - **CorpusManager**: Manages seed inputs and discovered crashes
//! - **CoverageTracker**: Tracks execution coverage for guided fuzzing
//! - **CrashDetector**: Detects and classifies crashes and hangs
//!
//! # Example
//!
//! ```ignore
//! use mcplint::fuzzer::{FuzzEngine, FuzzConfig, FuzzProfile};
//!
//! let config = FuzzConfig::with_profile(FuzzProfile::Standard);
//! let engine = FuzzEngine::with_config("./my-server", &[], config);
//! let results = engine.run(60, None, 0, None).await?;
//!
//! if !results.crashes.is_empty() {
//!     println!("Found {} crashes!", results.crashes.len());
//! }
//! ```

// Allow dead_code for library functions that are part of the public API
// but not yet used by the CLI
#![allow(dead_code)]

pub mod config;
pub mod corpus;
pub mod coverage;
pub mod detection;
pub mod input;
pub mod limits;
pub mod mutation;
pub mod session;

pub use config::{FuzzConfig, FuzzProfile};
// Re-exports for external API - allow unused since they're library exports
#[allow(unused_imports)]
pub use corpus::{CorpusManager, CrashRecord, CrashType, HangRecord, InterestingReason};
pub use coverage::CoverageStats;
#[allow(unused_imports)]
pub use detection::{CrashAnalysis, CrashDetector, FuzzResponse};
#[allow(unused_imports)]
pub use input::FuzzInput;
#[allow(unused_imports)]
pub use limits::{
    format_bytes, format_duration, FuzzStats, LimitExceeded, LimitType, ResourceLimits,
    ResourceMonitor, UsageSummary,
};
#[allow(unused_imports)]
pub use mutation::MutationEngine;
pub use session::FuzzSession;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Fuzzing session results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzResults {
    /// Server that was fuzzed
    pub server: String,
    /// Duration of the fuzzing session in seconds
    pub duration_secs: u64,
    /// Number of iterations executed
    pub iterations: u64,
    /// Crashes discovered
    pub crashes: Vec<FuzzCrash>,
    /// Coverage statistics
    pub coverage: CoverageStats,
    /// Number of interesting inputs discovered
    pub interesting_inputs: usize,
}

/// A crash discovered during fuzzing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzCrash {
    /// Unique crash ID
    pub id: String,
    /// Type of crash
    pub crash_type: String,
    /// Input that caused the crash (JSON string)
    pub input: String,
    /// Error message
    pub error: String,
    /// Iteration when crash occurred
    pub iteration: u64,
    /// Timestamp
    pub timestamp: String,
}

impl FuzzResults {
    /// Print results as formatted text
    pub fn print_text(&self) {
        use colored::Colorize;

        println!("{}", "Fuzzing Results".cyan().bold());
        println!("{}", "=".repeat(50));
        println!();

        println!("  Server: {}", self.server.yellow());
        println!("  Duration: {}s", self.duration_secs);
        println!("  Iterations: {}", self.iterations);
        println!("  Interesting inputs: {}", self.interesting_inputs);
        println!();

        println!("{}", "Coverage:".yellow());
        println!("  Paths explored: {}", self.coverage.paths_explored);
        println!(
            "  Edge coverage: {:.1}%",
            self.coverage.edge_coverage * 100.0
        );
        println!(
            "  New coverage rate: {:.2}%",
            self.coverage.new_coverage_rate * 100.0
        );
        println!();

        if self.crashes.is_empty() {
            println!("{}", "No crashes found ✓".green().bold());
        } else {
            println!(
                "{}",
                format!("Crashes found: {}", self.crashes.len())
                    .red()
                    .bold()
            );
            for crash in &self.crashes {
                println!();
                println!(
                    "  {} {} (iteration {})",
                    "[CRASH]".red().bold(),
                    crash.crash_type.red(),
                    crash.iteration
                );
                // Truncate input for display
                let input_display = if crash.input.len() > 100 {
                    format!("{}...", &crash.input[..100])
                } else {
                    crash.input.clone()
                };
                println!("  Input: {}", input_display.dimmed());
                println!("  Error: {}", crash.error);
            }
        }

        println!();
        println!("{}", "─".repeat(50));

        if !self.crashes.is_empty() {
            println!(
                "\n{}",
                format!(
                    "Server has {} crash(es) - review recommended!",
                    self.crashes.len()
                )
                .red()
                .bold()
            );
        } else if self.coverage.paths_explored > 0 {
            println!(
                "\n{}",
                format!(
                    "Explored {} unique paths with no crashes.",
                    self.coverage.paths_explored
                )
                .green()
            );
        }
    }

    /// Print results as JSON
    pub fn print_json(&self) -> Result<()> {
        println!("{}", serde_json::to_string_pretty(self)?);
        Ok(())
    }

    /// Print results as SARIF format
    pub fn print_sarif(&self) -> Result<()> {
        let sarif = self.to_sarif();
        println!("{}", serde_json::to_string_pretty(&sarif)?);
        Ok(())
    }

    /// Convert to SARIF format
    fn to_sarif(&self) -> serde_json::Value {
        use std::collections::HashSet;

        // Collect unique rules
        let mut seen_types: HashSet<String> = HashSet::new();
        let mut rules = Vec::new();

        for crash in &self.crashes {
            if !seen_types.contains(&crash.crash_type) {
                seen_types.insert(crash.crash_type.clone());
                rules.push(serde_json::json!({
                    "id": format!("FUZZ-{}", crash.crash_type.to_uppercase().replace(' ', "-")),
                    "name": crash.crash_type,
                    "shortDescription": {
                        "text": format!("Fuzzer detected: {}", crash.crash_type)
                    },
                    "defaultConfiguration": {
                        "level": "error"
                    }
                }));
            }
        }

        // Convert crashes to SARIF results
        let results: Vec<serde_json::Value> = self
            .crashes
            .iter()
            .map(|c| {
                serde_json::json!({
                    "ruleId": format!("FUZZ-{}", c.crash_type.to_uppercase().replace(' ', "-")),
                    "level": "error",
                    "message": {
                        "text": format!("{}: {}", c.crash_type, c.error)
                    },
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": self.server.clone()
                            }
                        }
                    }],
                    "properties": {
                        "iteration": c.iteration,
                        "timestamp": c.timestamp,
                        "input": c.input
                    }
                })
            })
            .collect();

        serde_json::json!({
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
                        "paths_explored": self.coverage.paths_explored,
                        "interesting_inputs": self.interesting_inputs
                    }
                }]
            }]
        })
    }

    /// Check if any crashes were found
    pub fn has_crashes(&self) -> bool {
        !self.crashes.is_empty()
    }

    /// Get crash count
    pub fn crash_count(&self) -> usize {
        self.crashes.len()
    }
}

/// Fuzzing engine for MCP servers
pub struct FuzzEngine {
    /// Target server (path or URL)
    server: String,
    /// Server arguments
    args: Vec<String>,
    /// Fuzzing configuration
    config: FuzzConfig,
}

impl FuzzEngine {
    /// Create a new fuzzing engine with default configuration
    pub fn new(server: &str, args: &[String], workers: usize) -> Self {
        Self {
            server: server.to_string(),
            args: args.to_vec(),
            config: FuzzConfig::default().with_workers(workers),
        }
    }

    /// Create with custom configuration
    pub fn with_config(server: &str, args: &[String], config: FuzzConfig) -> Self {
        Self {
            server: server.to_string(),
            args: args.to_vec(),
            config,
        }
    }

    /// Run the fuzzing session
    pub async fn run(
        &self,
        duration: u64,
        corpus: Option<String>,
        iterations: u64,
        tools: Option<Vec<String>>,
    ) -> Result<FuzzResults> {
        // Build config from parameters
        let mut config = self.config.clone();

        if duration > 0 {
            config.duration_secs = duration;
        }
        if iterations > 0 {
            config.max_iterations = iterations;
        }
        if let Some(path) = corpus {
            config.corpus_path = Some(PathBuf::from(path));
        }
        if tools.is_some() {
            config.target_tools = tools;
        }

        // Create and run session
        let mut session = FuzzSession::new(&self.server, &self.args, config);
        session.run().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engine_creation() {
        let engine = FuzzEngine::new("test-server", &[], 1);
        assert_eq!(engine.server, "test-server");
    }

    #[test]
    fn results_has_crashes() {
        let results = FuzzResults {
            server: "test".to_string(),
            duration_secs: 10,
            iterations: 100,
            crashes: vec![],
            coverage: CoverageStats::default(),
            interesting_inputs: 0,
        };

        assert!(!results.has_crashes());
        assert_eq!(results.crash_count(), 0);
    }

    #[test]
    fn results_to_sarif() {
        let results = FuzzResults {
            server: "test".to_string(),
            duration_secs: 10,
            iterations: 100,
            crashes: vec![FuzzCrash {
                id: "test-id".to_string(),
                crash_type: "panic".to_string(),
                input: "{}".to_string(),
                error: "test error".to_string(),
                iteration: 50,
                timestamp: "2024-01-01T00:00:00Z".to_string(),
            }],
            coverage: CoverageStats::default(),
            interesting_inputs: 5,
        };

        let sarif = results.to_sarif();
        assert_eq!(sarif["version"], "2.1.0");
        assert!(!sarif["runs"][0]["results"].as_array().unwrap().is_empty());
    }

    #[test]
    fn engine_with_config() {
        let config = FuzzConfig::with_profile(FuzzProfile::Quick);
        let engine = FuzzEngine::with_config("test-server", &[], config);
        assert_eq!(engine.server, "test-server");
        assert_eq!(engine.config.profile, FuzzProfile::Quick);
    }

    #[test]
    fn engine_with_args() {
        let args = vec!["--port".to_string(), "8080".to_string()];
        let engine = FuzzEngine::new("node server.js", &args, 2);
        assert_eq!(engine.server, "node server.js");
        assert_eq!(engine.args.len(), 2);
        assert_eq!(engine.config.workers, 2);
    }

    #[test]
    fn results_with_crashes() {
        let results = FuzzResults {
            server: "test".to_string(),
            duration_secs: 10,
            iterations: 100,
            crashes: vec![
                FuzzCrash {
                    id: "crash-1".to_string(),
                    crash_type: "panic".to_string(),
                    input: "{}".to_string(),
                    error: "panic error".to_string(),
                    iteration: 10,
                    timestamp: "2024-01-01T00:00:00Z".to_string(),
                },
                FuzzCrash {
                    id: "crash-2".to_string(),
                    crash_type: "segfault".to_string(),
                    input: "{\"test\": 1}".to_string(),
                    error: "segfault error".to_string(),
                    iteration: 50,
                    timestamp: "2024-01-01T00:01:00Z".to_string(),
                },
            ],
            coverage: CoverageStats::default(),
            interesting_inputs: 3,
        };

        assert!(results.has_crashes());
        assert_eq!(results.crash_count(), 2);
    }

    #[test]
    fn results_json_format() {
        let results = FuzzResults {
            server: "test-server".to_string(),
            duration_secs: 30,
            iterations: 500,
            crashes: vec![],
            coverage: CoverageStats::default(),
            interesting_inputs: 10,
        };

        let json_result = results.print_json();
        assert!(json_result.is_ok());
    }

    #[test]
    fn results_sarif_format() {
        let results = FuzzResults {
            server: "test-server".to_string(),
            duration_secs: 30,
            iterations: 500,
            crashes: vec![],
            coverage: CoverageStats::default(),
            interesting_inputs: 10,
        };

        let sarif_result = results.print_sarif();
        assert!(sarif_result.is_ok());
    }

    #[test]
    fn fuzz_crash_structure() {
        let crash = FuzzCrash {
            id: "unique-id".to_string(),
            crash_type: "connection_drop".to_string(),
            input: "{\"method\": \"test\"}".to_string(),
            error: "Connection lost".to_string(),
            iteration: 123,
            timestamp: "2024-12-11T10:00:00Z".to_string(),
        };

        assert_eq!(crash.id, "unique-id");
        assert_eq!(crash.crash_type, "connection_drop");
        assert_eq!(crash.iteration, 123);
    }

    #[test]
    fn results_sarif_with_multiple_crashes() {
        let results = FuzzResults {
            server: "test".to_string(),
            duration_secs: 60,
            iterations: 1000,
            crashes: vec![
                FuzzCrash {
                    id: "1".to_string(),
                    crash_type: "panic".to_string(),
                    input: "{}".to_string(),
                    error: "error 1".to_string(),
                    iteration: 10,
                    timestamp: "2024-01-01T00:00:00Z".to_string(),
                },
                FuzzCrash {
                    id: "2".to_string(),
                    crash_type: "panic".to_string(),
                    input: "{}".to_string(),
                    error: "error 2".to_string(),
                    iteration: 20,
                    timestamp: "2024-01-01T00:01:00Z".to_string(),
                },
                FuzzCrash {
                    id: "3".to_string(),
                    crash_type: "timeout".to_string(),
                    input: "{}".to_string(),
                    error: "timeout error".to_string(),
                    iteration: 30,
                    timestamp: "2024-01-01T00:02:00Z".to_string(),
                },
            ],
            coverage: CoverageStats::default(),
            interesting_inputs: 5,
        };

        let sarif = results.to_sarif();

        // Should have 2 unique rules (panic and timeout)
        let rules = sarif["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap();
        assert_eq!(rules.len(), 2);

        // Should have 3 results
        let sarif_results = sarif["runs"][0]["results"].as_array().unwrap();
        assert_eq!(sarif_results.len(), 3);
    }

    #[test]
    fn results_sarif_rule_deduplication() {
        let results = FuzzResults {
            server: "test".to_string(),
            duration_secs: 10,
            iterations: 100,
            crashes: vec![
                FuzzCrash {
                    id: "1".to_string(),
                    crash_type: "panic".to_string(),
                    input: "{}".to_string(),
                    error: "error 1".to_string(),
                    iteration: 1,
                    timestamp: "2024-01-01T00:00:00Z".to_string(),
                },
                FuzzCrash {
                    id: "2".to_string(),
                    crash_type: "panic".to_string(),
                    input: "{}".to_string(),
                    error: "error 2".to_string(),
                    iteration: 2,
                    timestamp: "2024-01-01T00:00:01Z".to_string(),
                },
            ],
            coverage: CoverageStats::default(),
            interesting_inputs: 0,
        };

        let sarif = results.to_sarif();

        // Should only have 1 unique rule despite 2 crashes of same type
        let rules = sarif["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0]["id"], "FUZZ-PANIC");
    }

    #[test]
    fn results_sarif_invocations() {
        let results = FuzzResults {
            server: "test".to_string(),
            duration_secs: 120,
            iterations: 5000,
            crashes: vec![],
            coverage: CoverageStats::default(),
            interesting_inputs: 25,
        };

        let sarif = results.to_sarif();
        let invocations = &sarif["runs"][0]["invocations"][0];

        assert_eq!(invocations["executionSuccessful"], true);
        assert_eq!(invocations["properties"]["iterations"], 5000);
        assert_eq!(invocations["properties"]["duration_secs"], 120);
        assert_eq!(invocations["properties"]["interesting_inputs"], 25);
    }

    #[test]
    fn results_sarif_schema_version() {
        let results = FuzzResults {
            server: "test".to_string(),
            duration_secs: 1,
            iterations: 1,
            crashes: vec![],
            coverage: CoverageStats::default(),
            interesting_inputs: 0,
        };

        let sarif = results.to_sarif();
        assert_eq!(sarif["$schema"], "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json");
        assert_eq!(sarif["version"], "2.1.0");
    }

    #[test]
    fn results_sarif_tool_driver() {
        let results = FuzzResults {
            server: "test".to_string(),
            duration_secs: 1,
            iterations: 1,
            crashes: vec![],
            coverage: CoverageStats::default(),
            interesting_inputs: 0,
        };

        let sarif = results.to_sarif();
        let driver = &sarif["runs"][0]["tool"]["driver"];

        assert_eq!(driver["name"], "mcplint-fuzzer");
        assert!(driver["version"].is_string());
        assert_eq!(
            driver["informationUri"],
            "https://github.com/quanticsoul4772/mcplint"
        );
    }

    #[test]
    fn fuzz_crash_clone() {
        let crash = FuzzCrash {
            id: "id".to_string(),
            crash_type: "panic".to_string(),
            input: "{}".to_string(),
            error: "error".to_string(),
            iteration: 1,
            timestamp: "2024-01-01T00:00:00Z".to_string(),
        };

        let cloned = crash.clone();
        assert_eq!(crash.id, cloned.id);
        assert_eq!(crash.crash_type, cloned.crash_type);
        assert_eq!(crash.iteration, cloned.iteration);
    }

    #[test]
    fn fuzz_results_clone() {
        let results = FuzzResults {
            server: "test".to_string(),
            duration_secs: 10,
            iterations: 100,
            crashes: vec![],
            coverage: CoverageStats::default(),
            interesting_inputs: 5,
        };

        let cloned = results.clone();
        assert_eq!(results.server, cloned.server);
        assert_eq!(results.duration_secs, cloned.duration_secs);
        assert_eq!(results.iterations, cloned.iterations);
    }

    #[test]
    fn engine_default_workers() {
        let engine = FuzzEngine::new("test", &[], 1);
        assert_eq!(engine.config.workers, 1);
    }

    #[test]
    fn engine_multiple_workers() {
        let engine = FuzzEngine::new("test", &[], 4);
        assert_eq!(engine.config.workers, 4);
    }

    #[test]
    fn results_empty_crashes() {
        let results = FuzzResults {
            server: "test".to_string(),
            duration_secs: 10,
            iterations: 100,
            crashes: vec![],
            coverage: CoverageStats::default(),
            interesting_inputs: 0,
        };

        assert!(!results.has_crashes());
        assert_eq!(results.crash_count(), 0);
        assert!(results.crashes.is_empty());
    }

    #[test]
    fn results_server_name() {
        let results = FuzzResults {
            server: "my-test-server".to_string(),
            duration_secs: 1,
            iterations: 1,
            crashes: vec![],
            coverage: CoverageStats::default(),
            interesting_inputs: 0,
        };

        assert_eq!(results.server, "my-test-server");
    }

    #[test]
    fn results_duration_and_iterations() {
        let results = FuzzResults {
            server: "test".to_string(),
            duration_secs: 300,
            iterations: 5000,
            crashes: vec![],
            coverage: CoverageStats::default(),
            interesting_inputs: 15,
        };

        assert_eq!(results.duration_secs, 300);
        assert_eq!(results.iterations, 5000);
        assert_eq!(results.interesting_inputs, 15);
    }

    #[test]
    fn crash_input_truncation_display() {
        // Test that long inputs would be truncated in display
        let long_input = "x".repeat(150);
        let crash = FuzzCrash {
            id: "id".to_string(),
            crash_type: "panic".to_string(),
            input: long_input.clone(),
            error: "error".to_string(),
            iteration: 1,
            timestamp: "2024-01-01T00:00:00Z".to_string(),
        };

        // The input is stored fully
        assert_eq!(crash.input.len(), 150);
    }

    #[test]
    fn sarif_result_properties() {
        let results = FuzzResults {
            server: "test".to_string(),
            duration_secs: 10,
            iterations: 100,
            crashes: vec![FuzzCrash {
                id: "test-id".to_string(),
                crash_type: "panic".to_string(),
                input: "{\"test\": true}".to_string(),
                error: "test error".to_string(),
                iteration: 42,
                timestamp: "2024-01-01T00:00:00Z".to_string(),
            }],
            coverage: CoverageStats::default(),
            interesting_inputs: 5,
        };

        let sarif = results.to_sarif();
        let result = &sarif["runs"][0]["results"][0];

        assert_eq!(result["properties"]["iteration"], 42);
        assert_eq!(result["properties"]["timestamp"], "2024-01-01T00:00:00Z");
        assert_eq!(result["properties"]["input"], "{\"test\": true}");
    }

    #[test]
    fn engine_empty_args() {
        let engine = FuzzEngine::new("test-server", &[], 1);
        assert!(engine.args.is_empty());
    }

    #[test]
    fn engine_config_preserved() {
        let config = FuzzConfig {
            duration_secs: 999,
            max_iterations: 777,
            ..FuzzConfig::default()
        };

        let engine = FuzzEngine::with_config("test", &[], config);
        assert_eq!(engine.config.duration_secs, 999);
        assert_eq!(engine.config.max_iterations, 777);
    }
}
