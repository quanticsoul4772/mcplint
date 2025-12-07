//! Protocol Validator - MCP protocol compliance checking
//!
//! This module implements the M1 milestone: Protocol Validator
//! It validates MCP servers against the protocol specification.

mod engine;
mod rules;

pub use engine::{
    ValidationConfig, ValidationEngine, ValidationResult, ValidationResults, ValidationSeverity,
};

use anyhow::Result;
use colored::Colorize;
use serde::{Deserialize, Serialize};

use crate::transport::TransportType;

/// Protocol validation results (legacy structure for compatibility)
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationCheck {
    pub name: String,
    pub category: String,
    pub status: CheckStatus,
    pub message: Option<String>,
    pub duration_ms: u64,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CheckStatus {
    Passed,
    Failed,
    Warning,
    Skipped,
}

/// Protocol validator for MCP servers
pub struct ProtocolValidator {
    server: String,
    args: Vec<String>,
    timeout: u64,
    transport_type: Option<TransportType>,
}

impl ProtocolValidator {
    pub fn new(server: &str, args: &[String], timeout: u64) -> Self {
        Self {
            server: server.to_string(),
            args: args.to_vec(),
            timeout,
            transport_type: None,
        }
    }

    #[allow(dead_code)]
    pub fn with_transport_type(mut self, transport_type: TransportType) -> Self {
        self.transport_type = Some(transport_type);
        self
    }

    /// Run full protocol validation
    pub async fn validate(&self) -> Result<ValidationResults> {
        // Create validation config
        let config = ValidationConfig {
            timeout_secs: self.timeout,
            skip_categories: Vec::new(),
            skip_rules: Vec::new(),
            strict_mode: false,
        };

        // Create and run validation engine
        let mut engine = ValidationEngine::new(config);

        // Connect to server and run validation
        let results = engine
            .validate_server(&self.server, &self.args, self.transport_type)
            .await?;

        tracing::info!(
            "Validation completed: {} passed, {} failed, {} warnings",
            results.passed,
            results.failed,
            results.warnings
        );

        Ok(results)
    }
}

impl ValidationResults {
    pub fn print_text(&self) {
        println!("{}", "Validation Results".cyan().bold());
        println!("{}", "=".repeat(60));
        println!();

        // Group by category
        let mut by_category: std::collections::HashMap<&str, Vec<&ValidationResult>> =
            std::collections::HashMap::new();
        for result in &self.results {
            by_category
                .entry(result.category.as_str())
                .or_default()
                .push(result);
        }

        for (category, results) in by_category.iter() {
            println!("  {} {}", "▸".cyan(), category.to_uppercase().bold());

            for result in results {
                let status = match result.severity {
                    ValidationSeverity::Pass => "✓ PASS".green(),
                    ValidationSeverity::Fail => "✗ FAIL".red(),
                    ValidationSeverity::Warning => "⚠ WARN".yellow(),
                    ValidationSeverity::Info => "ℹ INFO".blue(),
                    ValidationSeverity::Skip => "- SKIP".dimmed(),
                };

                let duration = format!("({}ms)", result.duration_ms).dimmed();
                println!("    {} {} {}", status, result.rule_id, duration);

                if let Some(ref msg) = result.message {
                    println!("      {}", msg.dimmed());
                }

                if !result.details.is_empty() {
                    for detail in &result.details {
                        println!("      • {}", detail.dimmed());
                    }
                }
            }
            println!();
        }

        println!("{}", "─".repeat(60));
        println!(
            "Summary: {} passed, {} failed, {} warnings",
            self.passed.to_string().green(),
            self.failed.to_string().red(),
            self.warnings.to_string().yellow()
        );

        if self.failed > 0 {
            println!("\n{}", "Server failed protocol validation.".red().bold());
        } else if self.warnings > 0 {
            println!("\n{}", "Server passed with warnings.".yellow());
        } else {
            println!(
                "\n{}",
                "Server passed all validation checks.".green().bold()
            );
        }
    }

    pub fn print_json(&self) -> Result<()> {
        println!("{}", serde_json::to_string_pretty(self)?);
        Ok(())
    }

    pub fn print_sarif(&self) -> Result<()> {
        let sarif = crate::reporter::sarif::SarifReport::from_validation_results(self);
        println!("{}", serde_json::to_string_pretty(&sarif)?);
        Ok(())
    }
}
