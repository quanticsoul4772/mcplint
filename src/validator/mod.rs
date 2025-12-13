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

    #[test]
    fn validation_check_with_all_status_types() {
        // Test all CheckStatus variants
        let passed = ValidationCheck {
            name: "passed".to_string(),
            category: "test".to_string(),
            status: CheckStatus::Passed,
            message: None,
            duration_ms: 10,
        };
        let failed = ValidationCheck {
            name: "failed".to_string(),
            category: "test".to_string(),
            status: CheckStatus::Failed,
            message: Some("error".to_string()),
            duration_ms: 20,
        };
        let warning = ValidationCheck {
            name: "warning".to_string(),
            category: "test".to_string(),
            status: CheckStatus::Warning,
            message: Some("warn".to_string()),
            duration_ms: 15,
        };
        let skipped = ValidationCheck {
            name: "skipped".to_string(),
            category: "test".to_string(),
            status: CheckStatus::Skipped,
            message: Some("skipped".to_string()),
            duration_ms: 0,
        };

        assert!(matches!(passed.status, CheckStatus::Passed));
        assert!(matches!(failed.status, CheckStatus::Failed));
        assert!(matches!(warning.status, CheckStatus::Warning));
        assert!(matches!(skipped.status, CheckStatus::Skipped));
    }

    #[test]
    fn validation_check_serialization_roundtrip() {
        let original = ValidationCheck {
            name: "roundtrip-test".to_string(),
            category: "integration".to_string(),
            status: CheckStatus::Warning,
            message: Some("test message".to_string()),
            duration_ms: 42,
        };

        let json = serde_json::to_string(&original).unwrap();
        let deserialized: ValidationCheck = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.name, original.name);
        assert_eq!(deserialized.category, original.category);
        assert_eq!(deserialized.message, original.message);
        assert_eq!(deserialized.duration_ms, original.duration_ms);
        assert!(matches!(deserialized.status, CheckStatus::Warning));
    }

    #[test]
    fn validation_check_serialization_with_null_message() {
        let json = r#"{"name":"test","category":"proto","status":"Passed","message":null,"duration_ms":10}"#;
        let check: ValidationCheck = serde_json::from_str(json).unwrap();
        assert!(check.message.is_none());
    }

    #[test]
    fn check_status_serialization_all_variants() {
        assert_eq!(
            serde_json::to_string(&CheckStatus::Passed).unwrap(),
            "\"Passed\""
        );
        assert_eq!(
            serde_json::to_string(&CheckStatus::Failed).unwrap(),
            "\"Failed\""
        );
        assert_eq!(
            serde_json::to_string(&CheckStatus::Warning).unwrap(),
            "\"Warning\""
        );
        assert_eq!(
            serde_json::to_string(&CheckStatus::Skipped).unwrap(),
            "\"Skipped\""
        );
    }

    #[test]
    fn protocol_validator_with_env_vars() {
        let mut env = HashMap::new();
        env.insert("API_KEY".to_string(), "secret123".to_string());
        env.insert("DEBUG".to_string(), "true".to_string());

        let validator = ProtocolValidator::new("server", &[], env.clone(), 30);

        assert_eq!(validator.env.get("API_KEY").unwrap(), "secret123");
        assert_eq!(validator.env.get("DEBUG").unwrap(), "true");
        assert_eq!(validator.env.len(), 2);
    }

    #[test]
    fn protocol_validator_with_args() {
        let args = vec![
            "--config".to_string(),
            "config.json".to_string(),
            "--verbose".to_string(),
        ];
        let validator = ProtocolValidator::new("node server.js", &args, HashMap::new(), 60);

        assert_eq!(validator.args.len(), 3);
        assert_eq!(validator.args[0], "--config");
        assert_eq!(validator.args[1], "config.json");
        assert_eq!(validator.args[2], "--verbose");
    }

    #[test]
    fn protocol_validator_timeout_values() {
        let v1 = ProtocolValidator::new("server", &[], HashMap::new(), 10);
        let v2 = ProtocolValidator::new("server", &[], HashMap::new(), 120);
        let v3 = ProtocolValidator::new("server", &[], HashMap::new(), 0);

        assert_eq!(v1.timeout, 10);
        assert_eq!(v2.timeout, 120);
        assert_eq!(v3.timeout, 0);
    }

    #[test]
    fn validation_results_empty_state() {
        let results = ValidationResults::new("empty-server");
        assert_eq!(results.server, "empty-server");
        assert_eq!(results.passed, 0);
        assert_eq!(results.failed, 0);
        assert_eq!(results.warnings, 0);
        assert_eq!(results.total_duration_ms, 0);
        assert!(results.results.is_empty());
        assert!(results.protocol_version.is_none());
        assert!(results.capabilities.is_none());
    }

    #[test]
    fn validation_results_mixed_results() {
        let mut results = ValidationResults::new("test");

        results.add_result(ValidationResult {
            rule_id: "R1".to_string(),
            rule_name: "Pass".to_string(),
            category: "test".to_string(),
            severity: ValidationSeverity::Pass,
            message: None,
            details: Vec::new(),
            duration_ms: 10,
        });

        results.add_result(ValidationResult {
            rule_id: "R2".to_string(),
            rule_name: "Fail".to_string(),
            category: "test".to_string(),
            severity: ValidationSeverity::Fail,
            message: Some("failed".to_string()),
            details: Vec::new(),
            duration_ms: 20,
        });

        results.add_result(ValidationResult {
            rule_id: "R3".to_string(),
            rule_name: "Warn".to_string(),
            category: "test".to_string(),
            severity: ValidationSeverity::Warning,
            message: Some("warning".to_string()),
            details: Vec::new(),
            duration_ms: 15,
        });

        assert_eq!(results.passed, 1);
        assert_eq!(results.failed, 1);
        assert_eq!(results.warnings, 1);
        assert_eq!(results.total_duration_ms, 45);
        assert_eq!(results.results.len(), 3);
    }

    #[test]
    fn validation_results_duration_accumulation() {
        let mut results = ValidationResults::new("test");

        for i in 1..=5 {
            results.add_result(ValidationResult {
                rule_id: format!("R{}", i),
                rule_name: "Test".to_string(),
                category: "test".to_string(),
                severity: ValidationSeverity::Pass,
                message: None,
                details: Vec::new(),
                duration_ms: 10,
            });
        }

        assert_eq!(results.total_duration_ms, 50);
        assert_eq!(results.passed, 5);
    }

    #[test]
    fn validation_results_print_text_with_mode_no_color() {
        let results = ValidationResults {
            server: "test".to_string(),
            protocol_version: None,
            capabilities: None,
            results: vec![ValidationResult {
                rule_id: "R1".to_string(),
                rule_name: "Test".to_string(),
                category: "test".to_string(),
                severity: ValidationSeverity::Pass,
                message: None,
                details: Vec::new(),
                duration_ms: 10,
            }],
            passed: 1,
            failed: 0,
            warnings: 0,
            total_duration_ms: 10,
        };

        // Should not panic with CI mode (no color)
        results.print_text_with_mode(OutputMode::CI);
    }

    #[test]
    fn validation_results_print_text_with_mode_plain() {
        let results = ValidationResults {
            server: "test".to_string(),
            protocol_version: None,
            capabilities: None,
            results: vec![ValidationResult {
                rule_id: "R1".to_string(),
                rule_name: "Test".to_string(),
                category: "test".to_string(),
                severity: ValidationSeverity::Fail,
                message: Some("failure".to_string()),
                details: vec!["detail".to_string()],
                duration_ms: 10,
            }],
            passed: 0,
            failed: 1,
            warnings: 0,
            total_duration_ms: 10,
        };

        // Should not panic with Plain mode (no unicode)
        results.print_text_with_mode(OutputMode::Plain);
    }

    #[test]
    fn validation_results_print_text_with_mode_interactive() {
        let results = ValidationResults {
            server: "test".to_string(),
            protocol_version: None,
            capabilities: None,
            results: vec![ValidationResult {
                rule_id: "R1".to_string(),
                rule_name: "Test".to_string(),
                category: "test".to_string(),
                severity: ValidationSeverity::Warning,
                message: Some("warning".to_string()),
                details: Vec::new(),
                duration_ms: 5,
            }],
            passed: 0,
            failed: 0,
            warnings: 1,
            total_duration_ms: 5,
        };

        // Should not panic with Interactive mode (colors and unicode enabled)
        results.print_text_with_mode(OutputMode::Interactive);
    }

    #[test]
    fn validation_results_print_text_empty_results() {
        let results = ValidationResults {
            server: "test".to_string(),
            protocol_version: None,
            capabilities: None,
            results: Vec::new(),
            passed: 0,
            failed: 0,
            warnings: 0,
            total_duration_ms: 0,
        };

        // Should not panic with empty results
        results.print_text();
    }

    #[test]
    fn validation_results_print_text_only_failures() {
        let results = ValidationResults {
            server: "test".to_string(),
            protocol_version: None,
            capabilities: None,
            results: vec![
                ValidationResult {
                    rule_id: "R1".to_string(),
                    rule_name: "Fail 1".to_string(),
                    category: "test".to_string(),
                    severity: ValidationSeverity::Fail,
                    message: Some("error 1".to_string()),
                    details: Vec::new(),
                    duration_ms: 10,
                },
                ValidationResult {
                    rule_id: "R2".to_string(),
                    rule_name: "Fail 2".to_string(),
                    category: "test".to_string(),
                    severity: ValidationSeverity::Fail,
                    message: Some("error 2".to_string()),
                    details: Vec::new(),
                    duration_ms: 20,
                },
            ],
            passed: 0,
            failed: 2,
            warnings: 0,
            total_duration_ms: 30,
        };

        // Should not panic with only failures
        results.print_text();
    }

    #[test]
    fn validation_results_print_text_only_warnings() {
        let results = ValidationResults {
            server: "test".to_string(),
            protocol_version: None,
            capabilities: None,
            results: vec![ValidationResult {
                rule_id: "W1".to_string(),
                rule_name: "Warning".to_string(),
                category: "test".to_string(),
                severity: ValidationSeverity::Warning,
                message: Some("warning message".to_string()),
                details: Vec::new(),
                duration_ms: 5,
            }],
            passed: 0,
            failed: 0,
            warnings: 1,
            total_duration_ms: 5,
        };

        // Should not panic with only warnings
        results.print_text();
    }

    #[test]
    fn validation_results_print_text_with_details() {
        let results = ValidationResults {
            server: "test".to_string(),
            protocol_version: None,
            capabilities: None,
            results: vec![ValidationResult {
                rule_id: "R1".to_string(),
                rule_name: "Test".to_string(),
                category: "test".to_string(),
                severity: ValidationSeverity::Fail,
                message: Some("failure".to_string()),
                details: vec![
                    "Detail line 1".to_string(),
                    "Detail line 2".to_string(),
                    "Detail line 3".to_string(),
                ],
                duration_ms: 10,
            }],
            passed: 0,
            failed: 1,
            warnings: 0,
            total_duration_ms: 10,
        };

        // Should not panic with multiple details
        results.print_text();
    }

    #[test]
    fn validation_results_print_text_mixed_with_passing() {
        let results = ValidationResults {
            server: "test".to_string(),
            protocol_version: Some("2024-11-05".to_string()),
            capabilities: None,
            results: vec![
                ValidationResult {
                    rule_id: "P1".to_string(),
                    rule_name: "Pass".to_string(),
                    category: "protocol".to_string(),
                    severity: ValidationSeverity::Pass,
                    message: None,
                    details: Vec::new(),
                    duration_ms: 5,
                },
                ValidationResult {
                    rule_id: "F1".to_string(),
                    rule_name: "Fail".to_string(),
                    category: "security".to_string(),
                    severity: ValidationSeverity::Fail,
                    message: Some("Security issue".to_string()),
                    details: Vec::new(),
                    duration_ms: 10,
                },
                ValidationResult {
                    rule_id: "W1".to_string(),
                    rule_name: "Warn".to_string(),
                    category: "schema".to_string(),
                    severity: ValidationSeverity::Warning,
                    message: Some("Schema warning".to_string()),
                    details: Vec::new(),
                    duration_ms: 3,
                },
            ],
            passed: 1,
            failed: 1,
            warnings: 1,
            total_duration_ms: 18,
        };

        // Should display all sections correctly
        results.print_text();
    }

    #[test]
    fn validation_config_custom_values() {
        let config = ValidationConfig {
            timeout_secs: 120,
            skip_categories: vec![],
            skip_rules: vec![],
            strict_mode: true,
        };

        assert_eq!(config.timeout_secs, 120);
        assert!(config.strict_mode);
    }

    #[test]
    fn validation_severity_serialization() {
        assert_eq!(
            serde_json::to_string(&ValidationSeverity::Pass).unwrap(),
            "\"pass\""
        );
        assert_eq!(
            serde_json::to_string(&ValidationSeverity::Fail).unwrap(),
            "\"fail\""
        );
        assert_eq!(
            serde_json::to_string(&ValidationSeverity::Warning).unwrap(),
            "\"warning\""
        );
        assert_eq!(
            serde_json::to_string(&ValidationSeverity::Info).unwrap(),
            "\"info\""
        );
        assert_eq!(
            serde_json::to_string(&ValidationSeverity::Skip).unwrap(),
            "\"skip\""
        );
    }

    #[test]
    fn validation_severity_deserialization() {
        let pass: ValidationSeverity = serde_json::from_str("\"pass\"").unwrap();
        let fail: ValidationSeverity = serde_json::from_str("\"fail\"").unwrap();
        let warning: ValidationSeverity = serde_json::from_str("\"warning\"").unwrap();
        let info: ValidationSeverity = serde_json::from_str("\"info\"").unwrap();
        let skip: ValidationSeverity = serde_json::from_str("\"skip\"").unwrap();

        assert_eq!(pass, ValidationSeverity::Pass);
        assert_eq!(fail, ValidationSeverity::Fail);
        assert_eq!(warning, ValidationSeverity::Warning);
        assert_eq!(info, ValidationSeverity::Info);
        assert_eq!(skip, ValidationSeverity::Skip);
    }

    #[test]
    fn validation_result_serialization() {
        let result = ValidationResult {
            rule_id: "TEST-001".to_string(),
            rule_name: "Test Rule".to_string(),
            category: "testing".to_string(),
            severity: ValidationSeverity::Pass,
            message: Some("Test message".to_string()),
            details: vec!["detail1".to_string()],
            duration_ms: 42,
        };

        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"rule_id\":\"TEST-001\""));
        assert!(json.contains("\"severity\":\"pass\""));
        assert!(json.contains("\"duration_ms\":42"));
    }

    #[test]
    fn validation_result_deserialization() {
        let json = r#"{
            "rule_id": "TEST-002",
            "rule_name": "Another Test",
            "category": "test",
            "severity": "fail",
            "message": "Failed test",
            "details": ["d1", "d2"],
            "duration_ms": 100
        }"#;

        let result: ValidationResult = serde_json::from_str(json).unwrap();
        assert_eq!(result.rule_id, "TEST-002");
        assert_eq!(result.severity, ValidationSeverity::Fail);
        assert_eq!(result.details.len(), 2);
        assert_eq!(result.duration_ms, 100);
    }

    #[test]
    fn validation_results_serialization() {
        let results = ValidationResults {
            server: "test-server".to_string(),
            protocol_version: Some("2024-11-05".to_string()),
            capabilities: None,
            results: vec![],
            passed: 5,
            failed: 2,
            warnings: 1,
            total_duration_ms: 1000,
        };

        let json = serde_json::to_string(&results).unwrap();
        assert!(json.contains("\"server\":\"test-server\""));
        assert!(json.contains("\"passed\":5"));
        assert!(json.contains("\"failed\":2"));
        assert!(json.contains("\"warnings\":1"));
    }

    #[test]
    fn validation_results_deserialization() {
        let json = r#"{
            "server": "my-server",
            "protocol_version": null,
            "capabilities": null,
            "results": [],
            "passed": 10,
            "failed": 0,
            "warnings": 3,
            "total_duration_ms": 500
        }"#;

        let results: ValidationResults = serde_json::from_str(json).unwrap();
        assert_eq!(results.server, "my-server");
        assert_eq!(results.passed, 10);
        assert_eq!(results.failed, 0);
        assert_eq!(results.warnings, 3);
        assert!(results.protocol_version.is_none());
    }

    #[test]
    fn validation_severity_copy_clone() {
        let original = ValidationSeverity::Pass;
        let cloned = original.clone();
        let copied = original;

        assert_eq!(original, cloned);
        assert_eq!(original, copied);
    }

    #[test]
    fn validation_result_clone() {
        let result = ValidationResult {
            rule_id: "R1".to_string(),
            rule_name: "Test".to_string(),
            category: "test".to_string(),
            severity: ValidationSeverity::Pass,
            message: Some("msg".to_string()),
            details: vec!["d1".to_string()],
            duration_ms: 10,
        };

        let cloned = result.clone();
        assert_eq!(cloned.rule_id, result.rule_id);
        assert_eq!(cloned.severity, result.severity);
        assert_eq!(cloned.details, result.details);
    }

    #[test]
    fn validation_results_clone() {
        let results = ValidationResults {
            server: "test".to_string(),
            protocol_version: None,
            capabilities: None,
            results: vec![],
            passed: 1,
            failed: 0,
            warnings: 0,
            total_duration_ms: 10,
        };

        let cloned = results.clone();
        assert_eq!(cloned.server, results.server);
        assert_eq!(cloned.passed, results.passed);
    }
}
