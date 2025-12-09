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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_check_creation() {
        let check = ValidationCheck {
            name: "test-check".to_string(),
            category: "protocol".to_string(),
            status: CheckStatus::Passed,
            message: Some("Test passed".to_string()),
            duration_ms: 100,
        };

        assert_eq!(check.name, "test-check");
        assert_eq!(check.category, "protocol");
        assert!(matches!(check.status, CheckStatus::Passed));
        assert_eq!(check.message.unwrap(), "Test passed");
        assert_eq!(check.duration_ms, 100);
    }

    #[test]
    fn validation_check_no_message() {
        let check = ValidationCheck {
            name: "check".to_string(),
            category: "auth".to_string(),
            status: CheckStatus::Skipped,
            message: None,
            duration_ms: 0,
        };

        assert!(check.message.is_none());
    }

    #[test]
    fn check_status_variants() {
        let passed = CheckStatus::Passed;
        let failed = CheckStatus::Failed;
        let warning = CheckStatus::Warning;
        let skipped = CheckStatus::Skipped;

        assert!(matches!(passed, CheckStatus::Passed));
        assert!(matches!(failed, CheckStatus::Failed));
        assert!(matches!(warning, CheckStatus::Warning));
        assert!(matches!(skipped, CheckStatus::Skipped));
    }

    #[test]
    fn protocol_validator_new() {
        let args = vec!["--port".to_string(), "3000".to_string()];
        let validator = ProtocolValidator::new("node server.js", &args, 30);

        assert_eq!(validator.server, "node server.js");
        assert_eq!(validator.args, args);
        assert_eq!(validator.timeout, 30);
        assert!(validator.transport_type.is_none());
    }

    #[test]
    fn protocol_validator_with_transport_type_stdio() {
        let validator =
            ProtocolValidator::new("server", &[], 60).with_transport_type(TransportType::Stdio);

        assert!(matches!(
            validator.transport_type,
            Some(TransportType::Stdio)
        ));
    }

    #[test]
    fn protocol_validator_with_transport_type_streamable_http() {
        let validator = ProtocolValidator::new("http://localhost:3000", &[], 60)
            .with_transport_type(TransportType::StreamableHttp);

        assert!(matches!(
            validator.transport_type,
            Some(TransportType::StreamableHttp)
        ));
    }

    #[test]
    fn protocol_validator_with_transport_type_sse_legacy() {
        let validator = ProtocolValidator::new("http://localhost:3000/sse", &[], 60)
            .with_transport_type(TransportType::SseLegacy);

        assert!(matches!(
            validator.transport_type,
            Some(TransportType::SseLegacy)
        ));
    }

    #[test]
    fn validation_check_serialization() {
        let check = ValidationCheck {
            name: "test".to_string(),
            category: "protocol".to_string(),
            status: CheckStatus::Passed,
            message: Some("ok".to_string()),
            duration_ms: 10,
        };

        let json = serde_json::to_string(&check).unwrap();
        assert!(json.contains("\"name\":\"test\""));
        assert!(json.contains("\"status\":\"Passed\""));
    }

    #[test]
    fn validation_check_deserialization() {
        let json = r#"{"name":"test","category":"auth","status":"Failed","message":"error","duration_ms":50}"#;
        let check: ValidationCheck = serde_json::from_str(json).unwrap();

        assert_eq!(check.name, "test");
        assert_eq!(check.category, "auth");
        assert!(matches!(check.status, CheckStatus::Failed));
        assert_eq!(check.message, Some("error".to_string()));
        assert_eq!(check.duration_ms, 50);
    }

    #[test]
    fn check_status_serialization() {
        let passed = CheckStatus::Passed;
        let failed = CheckStatus::Failed;
        let warning = CheckStatus::Warning;
        let skipped = CheckStatus::Skipped;

        assert_eq!(serde_json::to_string(&passed).unwrap(), "\"Passed\"");
        assert_eq!(serde_json::to_string(&failed).unwrap(), "\"Failed\"");
        assert_eq!(serde_json::to_string(&warning).unwrap(), "\"Warning\"");
        assert_eq!(serde_json::to_string(&skipped).unwrap(), "\"Skipped\"");
    }

    #[test]
    fn check_status_deserialization() {
        let passed: CheckStatus = serde_json::from_str("\"Passed\"").unwrap();
        let failed: CheckStatus = serde_json::from_str("\"Failed\"").unwrap();
        let warning: CheckStatus = serde_json::from_str("\"Warning\"").unwrap();
        let skipped: CheckStatus = serde_json::from_str("\"Skipped\"").unwrap();

        assert!(matches!(passed, CheckStatus::Passed));
        assert!(matches!(failed, CheckStatus::Failed));
        assert!(matches!(warning, CheckStatus::Warning));
        assert!(matches!(skipped, CheckStatus::Skipped));
    }

    #[test]
    fn validation_results_print_json_empty() {
        let results = ValidationResults {
            server: "test-server".to_string(),
            protocol_version: None,
            capabilities: None,
            results: Vec::new(),
            passed: 0,
            failed: 0,
            warnings: 0,
            total_duration_ms: 0,
        };

        // Should not error
        let json_result = results.print_json();
        assert!(json_result.is_ok());
    }

    #[test]
    fn validation_results_print_text_no_failures() {
        let results = ValidationResults {
            server: "test".to_string(),
            protocol_version: None,
            capabilities: None,
            results: vec![ValidationResult {
                rule_id: "MCP-PROTO-001".to_string(),
                rule_name: "Protocol Version Check".to_string(),
                category: "protocol".to_string(),
                severity: ValidationSeverity::Pass,
                message: Some("Passed".to_string()),
                details: Vec::new(),
                duration_ms: 10,
            }],
            passed: 1,
            failed: 0,
            warnings: 0,
            total_duration_ms: 10,
        };

        // Should not panic
        results.print_text();
    }

    #[test]
    fn validation_results_print_text_with_failures() {
        let results = ValidationResults {
            server: "test".to_string(),
            protocol_version: None,
            capabilities: None,
            results: vec![ValidationResult {
                rule_id: "MCP-PROTO-002".to_string(),
                rule_name: "Test Rule".to_string(),
                category: "protocol".to_string(),
                severity: ValidationSeverity::Fail,
                message: Some("Test failed".to_string()),
                details: vec!["detail1".to_string(), "detail2".to_string()],
                duration_ms: 20,
            }],
            passed: 0,
            failed: 1,
            warnings: 0,
            total_duration_ms: 20,
        };

        // Should not panic
        results.print_text();
    }

    #[test]
    fn validation_results_print_text_with_warnings() {
        let results = ValidationResults {
            server: "test".to_string(),
            protocol_version: None,
            capabilities: None,
            results: vec![ValidationResult {
                rule_id: "MCP-AUTH-001".to_string(),
                rule_name: "Auth Check".to_string(),
                category: "auth".to_string(),
                severity: ValidationSeverity::Warning,
                message: Some("Warning message".to_string()),
                details: Vec::new(),
                duration_ms: 5,
            }],
            passed: 0,
            failed: 0,
            warnings: 1,
            total_duration_ms: 5,
        };

        // Should not panic
        results.print_text();
    }

    #[test]
    fn validation_results_print_sarif() {
        let results = ValidationResults {
            server: "test".to_string(),
            protocol_version: None,
            capabilities: None,
            results: vec![ValidationResult {
                rule_id: "MCP-PROTO-001".to_string(),
                rule_name: "Test".to_string(),
                category: "protocol".to_string(),
                severity: ValidationSeverity::Pass,
                message: Some("Test".to_string()),
                details: Vec::new(),
                duration_ms: 10,
            }],
            passed: 1,
            failed: 0,
            warnings: 0,
            total_duration_ms: 10,
        };

        let sarif_result = results.print_sarif();
        assert!(sarif_result.is_ok());
    }

    #[test]
    fn validation_results_multiple_categories() {
        let results = ValidationResults {
            server: "test".to_string(),
            protocol_version: Some("2024-11-05".to_string()),
            capabilities: None,
            results: vec![
                ValidationResult {
                    rule_id: "MCP-PROTO-001".to_string(),
                    rule_name: "Rule 1".to_string(),
                    category: "protocol".to_string(),
                    severity: ValidationSeverity::Pass,
                    message: None,
                    details: Vec::new(),
                    duration_ms: 10,
                },
                ValidationResult {
                    rule_id: "MCP-AUTH-001".to_string(),
                    rule_name: "Rule 2".to_string(),
                    category: "auth".to_string(),
                    severity: ValidationSeverity::Pass,
                    message: None,
                    details: Vec::new(),
                    duration_ms: 15,
                },
                ValidationResult {
                    rule_id: "MCP-PROTO-002".to_string(),
                    rule_name: "Rule 3".to_string(),
                    category: "protocol".to_string(),
                    severity: ValidationSeverity::Info,
                    message: Some("Info message".to_string()),
                    details: Vec::new(),
                    duration_ms: 5,
                },
            ],
            passed: 2,
            failed: 0,
            warnings: 0,
            total_duration_ms: 30,
        };

        // Should not panic - tests grouping by category
        results.print_text();
    }

    #[test]
    fn validation_results_all_severities() {
        let results = ValidationResults {
            server: "test".to_string(),
            protocol_version: None,
            capabilities: None,
            results: vec![
                ValidationResult {
                    rule_id: "R1".to_string(),
                    rule_name: "Pass Rule".to_string(),
                    category: "test".to_string(),
                    severity: ValidationSeverity::Pass,
                    message: None,
                    details: Vec::new(),
                    duration_ms: 1,
                },
                ValidationResult {
                    rule_id: "R2".to_string(),
                    rule_name: "Fail Rule".to_string(),
                    category: "test".to_string(),
                    severity: ValidationSeverity::Fail,
                    message: None,
                    details: Vec::new(),
                    duration_ms: 1,
                },
                ValidationResult {
                    rule_id: "R3".to_string(),
                    rule_name: "Warn Rule".to_string(),
                    category: "test".to_string(),
                    severity: ValidationSeverity::Warning,
                    message: None,
                    details: Vec::new(),
                    duration_ms: 1,
                },
                ValidationResult {
                    rule_id: "R4".to_string(),
                    rule_name: "Info Rule".to_string(),
                    category: "test".to_string(),
                    severity: ValidationSeverity::Info,
                    message: None,
                    details: Vec::new(),
                    duration_ms: 1,
                },
                ValidationResult {
                    rule_id: "R5".to_string(),
                    rule_name: "Skip Rule".to_string(),
                    category: "test".to_string(),
                    severity: ValidationSeverity::Skip,
                    message: None,
                    details: Vec::new(),
                    duration_ms: 1,
                },
            ],
            passed: 1,
            failed: 1,
            warnings: 1,
            total_duration_ms: 5,
        };

        // Should not panic - tests all severity color branches
        results.print_text();
    }

    #[test]
    fn validation_check_clone() {
        let check = ValidationCheck {
            name: "test".to_string(),
            category: "proto".to_string(),
            status: CheckStatus::Passed,
            message: Some("msg".to_string()),
            duration_ms: 10,
        };

        let cloned = check.clone();
        assert_eq!(cloned.name, check.name);
        assert_eq!(cloned.category, check.category);
    }

    #[test]
    fn check_status_clone() {
        let status = CheckStatus::Warning;
        let cloned = status.clone();
        assert!(matches!(cloned, CheckStatus::Warning));
    }

    #[test]
    fn validation_check_debug() {
        let check = ValidationCheck {
            name: "test".to_string(),
            category: "test".to_string(),
            status: CheckStatus::Passed,
            message: None,
            duration_ms: 0,
        };

        let debug = format!("{:?}", check);
        assert!(debug.contains("ValidationCheck"));
        assert!(debug.contains("test"));
    }

    #[test]
    fn check_status_debug() {
        let status = CheckStatus::Failed;
        let debug = format!("{:?}", status);
        assert!(debug.contains("Failed"));
    }

    #[test]
    fn validation_results_new() {
        let results = ValidationResults::new("my-server");
        assert_eq!(results.server, "my-server");
        assert!(results.protocol_version.is_none());
        assert!(results.capabilities.is_none());
        assert!(results.results.is_empty());
        assert_eq!(results.passed, 0);
        assert_eq!(results.failed, 0);
        assert_eq!(results.warnings, 0);
        assert_eq!(results.total_duration_ms, 0);
    }

    #[test]
    fn validation_results_add_result_pass() {
        let mut results = ValidationResults::new("test");
        let result = ValidationResult {
            rule_id: "R1".to_string(),
            rule_name: "Test".to_string(),
            category: "test".to_string(),
            severity: ValidationSeverity::Pass,
            message: None,
            details: Vec::new(),
            duration_ms: 10,
        };

        results.add_result(result);

        assert_eq!(results.passed, 1);
        assert_eq!(results.failed, 0);
        assert_eq!(results.warnings, 0);
        assert_eq!(results.total_duration_ms, 10);
        assert_eq!(results.results.len(), 1);
    }

    #[test]
    fn validation_results_add_result_fail() {
        let mut results = ValidationResults::new("test");
        let result = ValidationResult {
            rule_id: "R1".to_string(),
            rule_name: "Test".to_string(),
            category: "test".to_string(),
            severity: ValidationSeverity::Fail,
            message: None,
            details: Vec::new(),
            duration_ms: 20,
        };

        results.add_result(result);

        assert_eq!(results.passed, 0);
        assert_eq!(results.failed, 1);
        assert_eq!(results.warnings, 0);
    }

    #[test]
    fn validation_results_add_result_warning() {
        let mut results = ValidationResults::new("test");
        let result = ValidationResult {
            rule_id: "R1".to_string(),
            rule_name: "Test".to_string(),
            category: "test".to_string(),
            severity: ValidationSeverity::Warning,
            message: None,
            details: Vec::new(),
            duration_ms: 5,
        };

        results.add_result(result);

        assert_eq!(results.passed, 0);
        assert_eq!(results.failed, 0);
        assert_eq!(results.warnings, 1);
    }

    #[test]
    fn validation_results_add_result_info() {
        let mut results = ValidationResults::new("test");
        let result = ValidationResult {
            rule_id: "R1".to_string(),
            rule_name: "Test".to_string(),
            category: "test".to_string(),
            severity: ValidationSeverity::Info,
            message: None,
            details: Vec::new(),
            duration_ms: 3,
        };

        results.add_result(result);

        // Info doesn't increment any counter
        assert_eq!(results.passed, 0);
        assert_eq!(results.failed, 0);
        assert_eq!(results.warnings, 0);
        assert_eq!(results.total_duration_ms, 3);
    }

    #[test]
    fn validation_results_add_result_skip() {
        let mut results = ValidationResults::new("test");
        let result = ValidationResult {
            rule_id: "R1".to_string(),
            rule_name: "Test".to_string(),
            category: "test".to_string(),
            severity: ValidationSeverity::Skip,
            message: None,
            details: Vec::new(),
            duration_ms: 0,
        };

        results.add_result(result);

        // Skip doesn't increment any counter
        assert_eq!(results.passed, 0);
        assert_eq!(results.failed, 0);
        assert_eq!(results.warnings, 0);
    }

    #[test]
    fn validation_results_has_failures() {
        let mut results = ValidationResults::new("test");
        assert!(!results.has_failures());

        let result = ValidationResult {
            rule_id: "R1".to_string(),
            rule_name: "Test".to_string(),
            category: "test".to_string(),
            severity: ValidationSeverity::Fail,
            message: None,
            details: Vec::new(),
            duration_ms: 10,
        };
        results.add_result(result);

        assert!(results.has_failures());
    }

    #[test]
    fn validation_config_default() {
        let config = ValidationConfig::default();
        assert_eq!(config.timeout_secs, 30);
        assert!(config.skip_categories.is_empty());
        assert!(config.skip_rules.is_empty());
        assert!(!config.strict_mode);
    }

    #[test]
    fn validation_severity_equality() {
        assert_eq!(ValidationSeverity::Pass, ValidationSeverity::Pass);
        assert_eq!(ValidationSeverity::Fail, ValidationSeverity::Fail);
        assert_ne!(ValidationSeverity::Pass, ValidationSeverity::Fail);
    }

    #[test]
    fn validation_result_with_details() {
        let result = ValidationResult {
            rule_id: "R1".to_string(),
            rule_name: "Test".to_string(),
            category: "test".to_string(),
            severity: ValidationSeverity::Pass,
            message: None,
            details: Vec::new(),
            duration_ms: 0,
        };

        let with_details = result.with_details(vec!["detail1".to_string(), "detail2".to_string()]);
        assert_eq!(with_details.details.len(), 2);
        assert_eq!(with_details.details[0], "detail1");
    }
}
