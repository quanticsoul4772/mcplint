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
        assert!(sarif["runs"][0]["results"].as_array().unwrap().len() > 0);
    }
}
