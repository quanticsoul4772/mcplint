//! Protocol Validator - MCP protocol compliance checking
//!
//! This module implements the M1 milestone: Protocol Validator
//! It validates MCP servers against the protocol specification.

mod engine;
pub mod rules;

pub use engine::{
    ValidationConfig, ValidationEngine, ValidationResult, ValidationResults, ValidationSeverity,
};

use std::collections::HashMap;

use anyhow::Result;
use colored::Colorize;
use serde::{Deserialize, Serialize};

use crate::transport::TransportType;
use crate::ui::{OutputMode, Printer};

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
    env: HashMap<String, String>,
    timeout: u64,
    transport_type: Option<TransportType>,
}

impl ProtocolValidator {
    pub fn new(server: &str, args: &[String], env: HashMap<String, String>, timeout: u64) -> Self {
        Self {
            server: server.to_string(),
            args: args.to_vec(),
            env,
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
            .validate_server(&self.server, &self.args, &self.env, self.transport_type)
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
    /// Print results as formatted text (uses auto-detected output mode)
    pub fn print_text(&self) {
        self.print_text_with_mode(OutputMode::detect());
    }

    /// Print results as formatted text with specific output mode
    pub fn print_text_with_mode(&self, mode: OutputMode) {
        let printer = Printer::with_mode(mode);

        // Get rule definitions for remediation lookup
        let all_rules = rules::get_all_rules();
        let rule_map: std::collections::HashMap<String, &rules::ValidationRule> =
            all_rules.iter().map(|r| (r.id.to_string(), r)).collect();

        // Separate issues from passing tests
        let failures: Vec<_> = self
            .results
            .iter()
            .filter(|r| r.severity == ValidationSeverity::Fail)
            .collect();
        let warnings: Vec<_> = self
            .results
            .iter()
            .filter(|r| r.severity == ValidationSeverity::Warning)
            .collect();
        let passing: Vec<_> = self
            .results
            .iter()
            .filter(|r| r.severity == ValidationSeverity::Pass)
            .collect();

        // Show summary first
        printer.newline();
        printer.separator();

        if self.failed > 0 {
            if mode.colors_enabled() {
                println!(
                    "  {} {} failures, {} warnings, {} passed",
                    "VALIDATION FAILED:".red().bold(),
                    self.failed.to_string().red().bold(),
                    self.warnings.to_string().yellow(),
                    self.passed.to_string().green()
                );
            } else {
                println!(
                    "  VALIDATION FAILED: {} failures, {} warnings, {} passed",
                    self.failed, self.warnings, self.passed
                );
            }
        } else if self.warnings > 0 {
            if mode.colors_enabled() {
                println!(
                    "  {} {} warnings, {} passed",
                    "VALIDATION PASSED WITH WARNINGS:".yellow().bold(),
                    self.warnings.to_string().yellow().bold(),
                    self.passed.to_string().green()
                );
            } else {
                println!(
                    "  VALIDATION PASSED WITH WARNINGS: {} warnings, {} passed",
                    self.warnings, self.passed
                );
            }
        } else if mode.colors_enabled() {
            println!(
                "  {} All {} checks passed",
                "VALIDATION PASSED:".green().bold(),
                self.passed.to_string().green().bold()
            );
        } else {
            println!("  VALIDATION PASSED: All {} checks passed", self.passed);
        }
        printer.separator();

        // Show failures first (most important)
        if !failures.is_empty() {
            printer.newline();
            let fail_header = if mode.unicode_enabled() {
                "  ✗ FAILURES"
            } else {
                "  [X] FAILURES"
            };
            if mode.colors_enabled() {
                println!("{}", fail_header.red().bold());
                println!("{}", "  ─".repeat(34).red());
            } else {
                println!("{}", fail_header);
                println!("{}", "  -".repeat(34));
            }
            for result in &failures {
                self.print_issue_with_mode(result, &rule_map, true, mode);
            }
        }

        // Show warnings next
        if !warnings.is_empty() {
            printer.newline();
            let warn_header = if mode.unicode_enabled() {
                "  ⚠ WARNINGS"
            } else {
                "  [!] WARNINGS"
            };
            if mode.colors_enabled() {
                println!("{}", warn_header.yellow().bold());
                println!("{}", "  ─".repeat(34).yellow());
            } else {
                println!("{}", warn_header);
                println!("{}", "  -".repeat(34));
            }
            for result in &warnings {
                self.print_issue_with_mode(result, &rule_map, false, mode);
            }
        }

        // Show passing tests (collapsed summary)
        if !passing.is_empty() && (self.failed > 0 || self.warnings > 0) {
            printer.newline();
            let check_mark = if mode.unicode_enabled() {
                "✓"
            } else {
                "[OK]"
            };
            if mode.colors_enabled() {
                println!(
                    "  {} {} checks passed",
                    check_mark.green(),
                    passing.len().to_string().green()
                );
            } else {
                println!("  {} {} checks passed", check_mark, passing.len());
            }

            // Group by category for compact display
            let mut by_cat: std::collections::HashMap<&str, Vec<&ValidationResult>> =
                std::collections::HashMap::new();
            for r in &passing {
                by_cat.entry(r.category.as_str()).or_default().push(r);
            }
            for (cat, results) in by_cat.iter() {
                let ids: Vec<_> = results.iter().map(|r| r.rule_id.as_str()).collect();
                if mode.colors_enabled() {
                    println!("    {}: {}", cat.dimmed(), ids.join(", ").dimmed());
                } else {
                    println!("    {}: {}", cat, ids.join(", "));
                }
            }
        } else if passing.is_empty() && failures.is_empty() && warnings.is_empty() {
            printer.newline();
            if mode.colors_enabled() {
                println!("  {}", "No validation checks were run.".dimmed());
            } else {
                println!("  No validation checks were run.");
            }
        } else if failures.is_empty() && warnings.is_empty() {
            // All passed - show brief summary
            printer.newline();
            let check_mark = if mode.unicode_enabled() {
                "✓"
            } else {
                "[OK]"
            };
            if mode.colors_enabled() {
                println!(
                    "  {} All {} protocol checks passed",
                    check_mark.green().bold(),
                    self.passed
                );
            } else {
                println!(
                    "  {} All {} protocol checks passed",
                    check_mark, self.passed
                );
            }
        }

        printer.newline();
    }

    fn print_issue_with_mode(
        &self,
        result: &ValidationResult,
        rule_map: &std::collections::HashMap<String, &rules::ValidationRule>,
        is_failure: bool,
        mode: OutputMode,
    ) {
        let (icon, icon_plain) = if is_failure {
            ("✗", "[X]")
        } else {
            ("⚠", "[!]")
        };

        // Rule ID and name
        println!();
        if mode.colors_enabled() {
            let icon_display = if mode.unicode_enabled() {
                icon
            } else {
                icon_plain
            };
            let icon_colored = if is_failure {
                icon_display.red()
            } else {
                icon_display.yellow()
            };
            let rule_id_colored = if is_failure {
                result.rule_id.red().bold()
            } else {
                result.rule_id.yellow().bold()
            };
            println!(
                "  {} {} - {}",
                icon_colored,
                rule_id_colored,
                result.rule_name.bold()
            );
        } else {
            let icon_display = if mode.unicode_enabled() {
                icon
            } else {
                icon_plain
            };
            println!(
                "  {} {} - {}",
                icon_display, result.rule_id, result.rule_name
            );
        }

        // What happened
        if let Some(ref msg) = result.message {
            if mode.colors_enabled() {
                println!("    {}: {}", "Issue".white().bold(), msg);
            } else {
                println!("    Issue: {}", msg);
            }
        }

        // Details
        if !result.details.is_empty() {
            let bullet = if mode.unicode_enabled() { "•" } else { "-" };
            for detail in &result.details {
                println!("    {} {}", bullet, detail);
            }
        }

        // How to fix (from rule definition)
        if let Some(rule) = rule_map.get(&result.rule_id) {
            if mode.colors_enabled() {
                println!("    {}: {}", "Fix".cyan().bold(), rule.remediation);
            } else {
                println!("    Fix: {}", rule.remediation);
            }
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
        let validator = ProtocolValidator::new("node server.js", &args, HashMap::new(), 30);

        assert_eq!(validator.server, "node server.js");
        assert_eq!(validator.args, args);
        assert_eq!(validator.timeout, 30);
        assert!(validator.transport_type.is_none());
    }

    #[test]
    fn protocol_validator_with_transport_type_stdio() {
        let validator = ProtocolValidator::new("server", &[], HashMap::new(), 60)
            .with_transport_type(TransportType::Stdio);

        assert!(matches!(
            validator.transport_type,
            Some(TransportType::Stdio)
        ));
    }

    #[test]
    fn protocol_validator_with_transport_type_streamable_http() {
        let validator = ProtocolValidator::new("http://localhost:3000", &[], HashMap::new(), 60)
            .with_transport_type(TransportType::StreamableHttp);

        assert!(matches!(
            validator.transport_type,
            Some(TransportType::StreamableHttp)
        ));
    }

    #[test]
    fn protocol_validator_with_transport_type_sse_legacy() {
        let validator =
            ProtocolValidator::new("http://localhost:3000/sse", &[], HashMap::new(), 60)
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
