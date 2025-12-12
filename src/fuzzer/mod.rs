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

use crate::ui::{OutputMode, Printer};

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
    /// Print results as formatted text (uses auto-detected output mode)
    pub fn print_text(&self) {
        self.print_text_with_mode(OutputMode::detect());
    }

    /// Print results as formatted text with specific output mode
    pub fn print_text_with_mode(&self, mode: OutputMode) {
        use colored::Colorize;

        let printer = Printer::with_mode(mode);

        printer.header("Fuzzing Results");
        printer.separator();
        printer.newline();

        printer.kv("Server", &self.server);
        printer.kv("Duration", &format!("{}s", self.duration_secs));
        printer.kv("Iterations", &self.iterations.to_string());
        printer.kv("Interesting inputs", &self.interesting_inputs.to_string());
        printer.newline();

        // Coverage section
        if mode.colors_enabled() {
            println!("{}", "Coverage:".yellow());
        } else {
            println!("Coverage:");
        }
        println!("  Paths explored: {}", self.coverage.paths_explored);
        println!(
            "  Edge coverage: {:.1}%",
            self.coverage.edge_coverage * 100.0
        );
        println!(
            "  New coverage rate: {:.2}%",
            self.coverage.new_coverage_rate * 100.0
        );
        printer.newline();

        if self.crashes.is_empty() {
            let msg = if mode.unicode_enabled() {
                "No crashes found ✓"
            } else {
                "No crashes found [OK]"
            };
            printer.success(msg);
        } else {
            let crash_msg = format!("Crashes found: {}", self.crashes.len());
            if mode.colors_enabled() {
                println!("{}", crash_msg.red().bold());
            } else {
                println!("{}", crash_msg);
            }
            for crash in &self.crashes {
                printer.newline();
                let crash_label = if mode.colors_enabled() {
                    "[CRASH]".red().bold().to_string()
                } else {
                    "[CRASH]".to_string()
                };
                let crash_type = if mode.colors_enabled() {
                    crash.crash_type.red().to_string()
                } else {
                    crash.crash_type.clone()
                };
                println!(
                    "  {} {} (iteration {})",
                    crash_label, crash_type, crash.iteration
                );
                // Truncate input for display
                let input_display = if crash.input.len() > 100 {
                    format!("{}...", &crash.input[..100])
                } else {
                    crash.input.clone()
                };
                if mode.colors_enabled() {
                    println!("  Input: {}", input_display.dimmed());
                } else {
                    println!("  Input: {}", input_display);
                }
                println!("  Error: {}", crash.error);
            }
        }

        printer.newline();
        printer.separator();

        // Final status message
        if !self.crashes.is_empty() {
            printer.error(&format!(
                "Server has {} crash(es) - review recommended!",
                self.crashes.len()
            ));
        } else if self.coverage.paths_explored > 0 {
            printer.success(&format!(
                "Explored {} unique paths with no crashes.",
                self.coverage.paths_explored
            ));
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

    #[test]
    fn fuzz_results_serialization() {
        let results = FuzzResults {
            server: "test-server".to_string(),
            duration_secs: 30,
            iterations: 500,
            crashes: vec![FuzzCrash {
                id: "crash-1".to_string(),
                crash_type: "panic".to_string(),
                input: "{}".to_string(),
                error: "test error".to_string(),
                iteration: 10,
                timestamp: "2024-01-01T00:00:00Z".to_string(),
            }],
            coverage: CoverageStats::default(),
            interesting_inputs: 10,
        };

        let json = serde_json::to_string(&results).unwrap();
        let deserialized: FuzzResults = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.server, results.server);
        assert_eq!(deserialized.duration_secs, results.duration_secs);
        assert_eq!(deserialized.iterations, results.iterations);
        assert_eq!(deserialized.crashes.len(), results.crashes.len());
        assert_eq!(deserialized.interesting_inputs, results.interesting_inputs);
    }

    #[test]
    fn fuzz_crash_serialization() {
        let crash = FuzzCrash {
            id: "test-id".to_string(),
            crash_type: "timeout".to_string(),
            input: "{\"method\": \"test\"}".to_string(),
            error: "timeout error".to_string(),
            iteration: 42,
            timestamp: "2024-12-11T10:00:00Z".to_string(),
        };

        let json = serde_json::to_string(&crash).unwrap();
        let deserialized: FuzzCrash = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.id, crash.id);
        assert_eq!(deserialized.crash_type, crash.crash_type);
        assert_eq!(deserialized.input, crash.input);
        assert_eq!(deserialized.error, crash.error);
        assert_eq!(deserialized.iteration, crash.iteration);
        assert_eq!(deserialized.timestamp, crash.timestamp);
    }

    #[test]
    fn results_debug_format() {
        let results = FuzzResults {
            server: "test".to_string(),
            duration_secs: 10,
            iterations: 100,
            crashes: vec![],
            coverage: CoverageStats::default(),
            interesting_inputs: 0,
        };

        let debug = format!("{:?}", results);
        assert!(debug.contains("FuzzResults"));
        assert!(debug.contains("test"));
    }

    #[test]
    fn crash_debug_format() {
        let crash = FuzzCrash {
            id: "id".to_string(),
            crash_type: "panic".to_string(),
            input: "{}".to_string(),
            error: "error".to_string(),
            iteration: 1,
            timestamp: "2024-01-01T00:00:00Z".to_string(),
        };

        let debug = format!("{:?}", crash);
        assert!(debug.contains("FuzzCrash"));
        assert!(debug.contains("panic"));
    }

    #[test]
    fn sarif_crash_type_formatting() {
        let results = FuzzResults {
            server: "test".to_string(),
            duration_secs: 10,
            iterations: 100,
            crashes: vec![FuzzCrash {
                id: "1".to_string(),
                crash_type: "connection drop".to_string(),
                input: "{}".to_string(),
                error: "error".to_string(),
                iteration: 1,
                timestamp: "2024-01-01T00:00:00Z".to_string(),
            }],
            coverage: CoverageStats::default(),
            interesting_inputs: 0,
        };

        let sarif = results.to_sarif();
        let rules = sarif["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap();

        // Check that spaces in crash_type are replaced with hyphens
        assert_eq!(rules[0]["id"], "FUZZ-CONNECTION-DROP");
    }

    #[test]
    fn sarif_with_empty_crashes() {
        let results = FuzzResults {
            server: "test".to_string(),
            duration_secs: 10,
            iterations: 100,
            crashes: vec![],
            coverage: CoverageStats::default(),
            interesting_inputs: 0,
        };

        let sarif = results.to_sarif();
        let rules = sarif["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap();
        let sarif_results = sarif["runs"][0]["results"].as_array().unwrap();

        assert!(rules.is_empty());
        assert!(sarif_results.is_empty());
    }

    #[test]
    fn sarif_message_format() {
        let results = FuzzResults {
            server: "test".to_string(),
            duration_secs: 10,
            iterations: 100,
            crashes: vec![FuzzCrash {
                id: "1".to_string(),
                crash_type: "panic".to_string(),
                input: "{}".to_string(),
                error: "null pointer dereference".to_string(),
                iteration: 50,
                timestamp: "2024-01-01T00:00:00Z".to_string(),
            }],
            coverage: CoverageStats::default(),
            interesting_inputs: 5,
        };

        let sarif = results.to_sarif();
        let result = &sarif["runs"][0]["results"][0];

        assert_eq!(result["message"]["text"], "panic: null pointer dereference");
    }

    #[test]
    fn sarif_artifact_location() {
        let results = FuzzResults {
            server: "path/to/server".to_string(),
            duration_secs: 10,
            iterations: 100,
            crashes: vec![FuzzCrash {
                id: "1".to_string(),
                crash_type: "panic".to_string(),
                input: "{}".to_string(),
                error: "error".to_string(),
                iteration: 1,
                timestamp: "2024-01-01T00:00:00Z".to_string(),
            }],
            coverage: CoverageStats::default(),
            interesting_inputs: 0,
        };

        let sarif = results.to_sarif();
        let location =
            &sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"];

        assert_eq!(location["uri"], "path/to/server");
    }

    #[test]
    fn sarif_rule_description() {
        let results = FuzzResults {
            server: "test".to_string(),
            duration_secs: 10,
            iterations: 100,
            crashes: vec![FuzzCrash {
                id: "1".to_string(),
                crash_type: "segfault".to_string(),
                input: "{}".to_string(),
                error: "error".to_string(),
                iteration: 1,
                timestamp: "2024-01-01T00:00:00Z".to_string(),
            }],
            coverage: CoverageStats::default(),
            interesting_inputs: 0,
        };

        let sarif = results.to_sarif();
        let rule = &sarif["runs"][0]["tool"]["driver"]["rules"][0];

        assert_eq!(rule["id"], "FUZZ-SEGFAULT");
        assert_eq!(rule["name"], "segfault");
        assert_eq!(
            rule["shortDescription"]["text"],
            "Fuzzer detected: segfault"
        );
        assert_eq!(rule["defaultConfiguration"]["level"], "error");
    }

    #[test]
    fn coverage_stats_serialization() {
        let stats = CoverageStats {
            paths_explored: 100,
            edge_coverage: 0.75,
            new_coverage_rate: 0.25,
        };

        let json = serde_json::to_string(&stats).unwrap();
        let deserialized: CoverageStats = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.paths_explored, stats.paths_explored);
        assert_eq!(deserialized.edge_coverage, stats.edge_coverage);
        assert_eq!(deserialized.new_coverage_rate, stats.new_coverage_rate);
    }

    #[test]
    fn engine_with_config_profile() {
        let config = FuzzConfig::with_profile(FuzzProfile::Intensive);
        let engine = FuzzEngine::with_config("test-server", &[], config);

        assert_eq!(engine.config.profile, FuzzProfile::Intensive);
        assert_eq!(engine.config.duration_secs, 0); // Intensive has unlimited duration
    }

    #[test]
    fn engine_with_config_and_custom_workers() {
        let config = FuzzConfig::with_profile(FuzzProfile::Standard).with_workers(8);
        let engine = FuzzEngine::with_config("test-server", &[], config);

        assert_eq!(engine.config.workers, 8);
        assert_eq!(engine.config.profile, FuzzProfile::Standard);
    }

    #[test]
    fn results_with_zero_iterations() {
        let results = FuzzResults {
            server: "test".to_string(),
            duration_secs: 0,
            iterations: 0,
            crashes: vec![],
            coverage: CoverageStats::default(),
            interesting_inputs: 0,
        };

        assert_eq!(results.iterations, 0);
        assert_eq!(results.duration_secs, 0);
        assert!(!results.has_crashes());
    }

    #[test]
    fn results_with_large_number_of_crashes() {
        let crashes: Vec<FuzzCrash> = (0..100)
            .map(|i| FuzzCrash {
                id: format!("crash-{}", i),
                crash_type: "panic".to_string(),
                input: "{}".to_string(),
                error: format!("error {}", i),
                iteration: i,
                timestamp: "2024-01-01T00:00:00Z".to_string(),
            })
            .collect();

        let results = FuzzResults {
            server: "test".to_string(),
            duration_secs: 10,
            iterations: 100,
            crashes,
            coverage: CoverageStats::default(),
            interesting_inputs: 0,
        };

        assert_eq!(results.crash_count(), 100);
        assert!(results.has_crashes());
    }

    #[test]
    fn crash_with_empty_fields() {
        let crash = FuzzCrash {
            id: String::new(),
            crash_type: String::new(),
            input: String::new(),
            error: String::new(),
            iteration: 0,
            timestamp: String::new(),
        };

        assert_eq!(crash.id, "");
        assert_eq!(crash.crash_type, "");
        assert_eq!(crash.input, "");
        assert_eq!(crash.error, "");
    }

    #[test]
    fn results_coverage_stats_access() {
        let coverage = CoverageStats {
            paths_explored: 42,
            edge_coverage: 0.5,
            new_coverage_rate: 0.1,
        };

        let results = FuzzResults {
            server: "test".to_string(),
            duration_secs: 10,
            iterations: 100,
            crashes: vec![],
            coverage: coverage.clone(),
            interesting_inputs: 5,
        };

        assert_eq!(results.coverage.paths_explored, 42);
        assert_eq!(results.coverage.edge_coverage, 0.5);
        assert_eq!(results.coverage.new_coverage_rate, 0.1);
    }

    #[test]
    fn engine_new_with_zero_workers() {
        // Engine should enforce minimum of 1 worker via config
        let engine = FuzzEngine::new("test", &[], 0);
        // FuzzConfig::with_workers enforces minimum of 1
        assert_eq!(engine.config.workers, 1);
    }

    #[test]
    fn sarif_multiple_crash_types() {
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
                    crash_type: "timeout".to_string(),
                    input: "{}".to_string(),
                    error: "timeout".to_string(),
                    iteration: 20,
                    timestamp: "2024-01-01T00:01:00Z".to_string(),
                },
                FuzzCrash {
                    id: "3".to_string(),
                    crash_type: "segfault".to_string(),
                    input: "{}".to_string(),
                    error: "segfault".to_string(),
                    iteration: 30,
                    timestamp: "2024-01-01T00:02:00Z".to_string(),
                },
            ],
            coverage: CoverageStats::default(),
            interesting_inputs: 5,
        };

        let sarif = results.to_sarif();
        let rules = sarif["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap();

        // Should have 3 unique rules
        assert_eq!(rules.len(), 3);

        let rule_ids: Vec<String> = rules
            .iter()
            .map(|r| r["id"].as_str().unwrap().to_string())
            .collect();

        assert!(rule_ids.contains(&"FUZZ-PANIC".to_string()));
        assert!(rule_ids.contains(&"FUZZ-TIMEOUT".to_string()));
        assert!(rule_ids.contains(&"FUZZ-SEGFAULT".to_string()));
    }

    #[test]
    fn crash_with_special_characters_in_input() {
        let crash = FuzzCrash {
            id: "id".to_string(),
            crash_type: "panic".to_string(),
            input: "{\"test\": \"\\n\\t\\r\\u0000\"}".to_string(),
            error: "error".to_string(),
            iteration: 1,
            timestamp: "2024-01-01T00:00:00Z".to_string(),
        };

        // Should handle special characters without panicking
        let json = serde_json::to_string(&crash).unwrap();
        assert!(json.contains("test"));
    }

    #[test]
    fn results_with_high_coverage() {
        let coverage = CoverageStats {
            paths_explored: 10000,
            edge_coverage: 1.0,
            new_coverage_rate: 0.99,
        };

        let results = FuzzResults {
            server: "test".to_string(),
            duration_secs: 3600,
            iterations: 50000,
            crashes: vec![],
            coverage,
            interesting_inputs: 5000,
        };

        assert_eq!(results.coverage.edge_coverage, 1.0);
        assert_eq!(results.coverage.paths_explored, 10000);
    }

    #[test]
    fn fuzz_crash_with_very_long_error() {
        let long_error = "e".repeat(10000);
        let crash = FuzzCrash {
            id: "id".to_string(),
            crash_type: "panic".to_string(),
            input: "{}".to_string(),
            error: long_error.clone(),
            iteration: 1,
            timestamp: "2024-01-01T00:00:00Z".to_string(),
        };

        assert_eq!(crash.error.len(), 10000);
        assert_eq!(crash.error, long_error);
    }

    #[test]
    fn coverage_stats_clone() {
        let stats = CoverageStats {
            paths_explored: 100,
            edge_coverage: 0.5,
            new_coverage_rate: 0.25,
        };

        let cloned = stats.clone();
        assert_eq!(cloned.paths_explored, stats.paths_explored);
        assert_eq!(cloned.edge_coverage, stats.edge_coverage);
        assert_eq!(cloned.new_coverage_rate, stats.new_coverage_rate);
    }

    #[test]
    fn coverage_stats_debug() {
        let stats = CoverageStats {
            paths_explored: 100,
            edge_coverage: 0.5,
            new_coverage_rate: 0.25,
        };

        let debug = format!("{:?}", stats);
        assert!(debug.contains("CoverageStats"));
        assert!(debug.contains("100"));
    }

    #[test]
    fn engine_server_name_preserved() {
        let server = "my-custom-server-name";
        let engine = FuzzEngine::new(server, &[], 1);
        assert_eq!(engine.server, server);
    }

    #[test]
    fn engine_args_preserved() {
        let args = vec![
            "--arg1".to_string(),
            "value1".to_string(),
            "--arg2".to_string(),
            "value2".to_string(),
        ];
        let engine = FuzzEngine::new("test", &args, 1);
        assert_eq!(engine.args, args);
    }

    #[test]
    fn results_interesting_inputs_count() {
        let results = FuzzResults {
            server: "test".to_string(),
            duration_secs: 10,
            iterations: 100,
            crashes: vec![],
            coverage: CoverageStats::default(),
            interesting_inputs: 42,
        };

        assert_eq!(results.interesting_inputs, 42);
    }
}
