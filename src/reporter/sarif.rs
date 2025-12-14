//! SARIF output format for GitHub Code Scanning integration
//!
//! SARIF (Static Analysis Results Interchange Format) 2.1.0 types
//! for CI/CD integration with GitHub, GitLab, and other platforms.

#![allow(dead_code)] // Types are defined for future SARIF output implementation

use serde::{Deserialize, Serialize};

/// SARIF 2.1.0 compatible report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifReport {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub version: String,
    pub runs: Vec<SarifRun>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifRun {
    pub tool: SarifTool,
    pub results: Vec<SarifResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifTool {
    pub driver: SarifDriver,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifDriver {
    pub name: String,
    pub version: String,
    #[serde(rename = "informationUri")]
    pub information_uri: String,
    pub rules: Vec<SarifRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifRule {
    pub id: String,
    pub name: String,
    #[serde(rename = "shortDescription")]
    pub short_description: SarifMessage,
    #[serde(rename = "fullDescription")]
    pub full_description: SarifMessage,
    #[serde(rename = "defaultConfiguration")]
    pub default_configuration: SarifConfiguration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifMessage {
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifConfiguration {
    pub level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifResult {
    #[serde(rename = "ruleId")]
    pub rule_id: String,
    pub level: String,
    pub message: SarifMessage,
    pub locations: Vec<SarifLocation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifLocation {
    #[serde(rename = "physicalLocation")]
    pub physical_location: SarifPhysicalLocation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifPhysicalLocation {
    #[serde(rename = "artifactLocation")]
    pub artifact_location: SarifArtifactLocation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifArtifactLocation {
    pub uri: String,
}

impl SarifReport {
    pub fn new() -> Self {
        Self {
            schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json".to_string(),
            version: "2.1.0".to_string(),
            runs: vec![],
        }
    }

    /// Create a SARIF report from security scan results
    pub fn from_scan_results(results: &crate::scanner::ScanResults) -> Self {
        // Collect unique rules from findings
        let mut rules: Vec<SarifRule> = Vec::new();
        let mut seen_rules: std::collections::HashSet<String> = std::collections::HashSet::new();

        for finding in &results.findings {
            if !seen_rules.contains(&finding.rule_id) {
                seen_rules.insert(finding.rule_id.clone());
                rules.push(SarifRule {
                    id: finding.rule_id.clone(),
                    name: finding.title.clone(),
                    short_description: SarifMessage {
                        text: finding.title.clone(),
                    },
                    full_description: SarifMessage {
                        text: finding.description.clone(),
                    },
                    default_configuration: SarifConfiguration {
                        level: finding.severity.sarif_level().to_string(),
                    },
                });
            }
        }

        // Convert findings to SARIF results
        let sarif_results: Vec<SarifResult> = results
            .findings
            .iter()
            .map(|f| {
                // Build location URI from finding location
                let uri = if f.location.identifier.is_empty() {
                    format!("{}/{}", f.location.component, results.server)
                } else {
                    format!("{}/{}", f.location.component, f.location.identifier)
                };

                SarifResult {
                    rule_id: f.rule_id.clone(),
                    level: f.severity.sarif_level().to_string(),
                    message: SarifMessage {
                        text: format!(
                            "{}: {}{}",
                            f.title,
                            f.description,
                            if f.remediation.is_empty() {
                                String::new()
                            } else {
                                format!(" Remediation: {}", f.remediation)
                            }
                        ),
                    },
                    locations: vec![SarifLocation {
                        physical_location: SarifPhysicalLocation {
                            artifact_location: SarifArtifactLocation { uri },
                        },
                    }],
                }
            })
            .collect();

        Self {
            schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json".to_string(),
            version: "2.1.0".to_string(),
            runs: vec![SarifRun {
                tool: SarifTool {
                    driver: SarifDriver {
                        name: "mcplint".to_string(),
                        version: env!("CARGO_PKG_VERSION").to_string(),
                        information_uri: "https://github.com/quanticsoul4772/mcplint".to_string(),
                        rules,
                    },
                },
                results: sarif_results,
            }],
        }
    }

    /// Create a SARIF report from validation results
    pub fn from_validation_results(results: &crate::validator::ValidationResults) -> Self {
        use crate::validator::ValidationSeverity;

        // Collect unique rules from results
        let mut rules: Vec<SarifRule> = Vec::new();
        let mut seen_rules: std::collections::HashSet<String> = std::collections::HashSet::new();

        for result in &results.results {
            if !seen_rules.contains(&result.rule_id) {
                seen_rules.insert(result.rule_id.clone());
                rules.push(SarifRule {
                    id: result.rule_id.clone(),
                    name: result.rule_name.clone(),
                    short_description: SarifMessage {
                        text: result.rule_name.clone(),
                    },
                    full_description: SarifMessage {
                        text: result
                            .message
                            .clone()
                            .unwrap_or_else(|| result.rule_name.clone()),
                    },
                    default_configuration: SarifConfiguration {
                        level: match result.severity {
                            ValidationSeverity::Fail => "error".to_string(),
                            ValidationSeverity::Warning => "warning".to_string(),
                            _ => "note".to_string(),
                        },
                    },
                });
            }
        }

        // Convert results to SARIF results (only failures and warnings)
        let sarif_results: Vec<SarifResult> = results
            .results
            .iter()
            .filter(|r| {
                matches!(
                    r.severity,
                    ValidationSeverity::Fail | ValidationSeverity::Warning
                )
            })
            .map(|r| SarifResult {
                rule_id: r.rule_id.clone(),
                level: match r.severity {
                    ValidationSeverity::Fail => "error".to_string(),
                    ValidationSeverity::Warning => "warning".to_string(),
                    _ => "note".to_string(),
                },
                message: SarifMessage {
                    text: format!("{}: {}", r.rule_name, r.message.clone().unwrap_or_default()),
                },
                locations: vec![SarifLocation {
                    physical_location: SarifPhysicalLocation {
                        artifact_location: SarifArtifactLocation {
                            uri: results.server.clone(),
                        },
                    },
                }],
            })
            .collect();

        Self {
            schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json".to_string(),
            version: "2.1.0".to_string(),
            runs: vec![SarifRun {
                tool: SarifTool {
                    driver: SarifDriver {
                        name: "mcplint".to_string(),
                        version: env!("CARGO_PKG_VERSION").to_string(),
                        information_uri: "https://github.com/quanticsoul4772/mcplint".to_string(),
                        rules,
                    },
                },
                results: sarif_results,
            }],
        }
    }
}

impl Default for SarifReport {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::{Finding, FindingLocation, ScanProfile, ScanResults, Severity};
    use crate::validator::{ValidationResult, ValidationResults, ValidationSeverity};

    #[test]
    fn sarif_report_new() {
        let report = SarifReport::new();
        assert_eq!(report.version, "2.1.0");
        assert!(report.schema.contains("sarif-schema-2.1.0"));
        assert!(report.runs.is_empty());
    }

    #[test]
    fn sarif_report_default() {
        let report = SarifReport::default();
        assert_eq!(report.version, "2.1.0");
    }

    #[test]
    fn sarif_message_creation() {
        let msg = SarifMessage {
            text: "Test message".to_string(),
        };
        assert_eq!(msg.text, "Test message");
    }

    #[test]
    fn sarif_configuration_creation() {
        let config = SarifConfiguration {
            level: "error".to_string(),
        };
        assert_eq!(config.level, "error");
    }

    #[test]
    fn sarif_rule_creation() {
        let rule = SarifRule {
            id: "TEST-001".to_string(),
            name: "Test Rule".to_string(),
            short_description: SarifMessage {
                text: "Short desc".to_string(),
            },
            full_description: SarifMessage {
                text: "Full description".to_string(),
            },
            default_configuration: SarifConfiguration {
                level: "warning".to_string(),
            },
        };
        assert_eq!(rule.id, "TEST-001");
        assert_eq!(rule.name, "Test Rule");
    }

    #[test]
    fn sarif_location_creation() {
        let location = SarifLocation {
            physical_location: SarifPhysicalLocation {
                artifact_location: SarifArtifactLocation {
                    uri: "file:///test.js".to_string(),
                },
            },
        };
        assert_eq!(
            location.physical_location.artifact_location.uri,
            "file:///test.js"
        );
    }

    #[test]
    fn sarif_result_creation() {
        let result = SarifResult {
            rule_id: "TEST-001".to_string(),
            level: "error".to_string(),
            message: SarifMessage {
                text: "Test finding".to_string(),
            },
            locations: vec![SarifLocation {
                physical_location: SarifPhysicalLocation {
                    artifact_location: SarifArtifactLocation {
                        uri: "test.js".to_string(),
                    },
                },
            }],
        };
        assert_eq!(result.rule_id, "TEST-001");
        assert_eq!(result.level, "error");
    }

    fn make_validation_result(
        rule_id: &str,
        rule_name: &str,
        severity: ValidationSeverity,
        message: Option<&str>,
    ) -> ValidationResult {
        ValidationResult {
            rule_id: rule_id.to_string(),
            rule_name: rule_name.to_string(),
            category: "protocol".to_string(),
            severity,
            message: message.map(|s| s.to_string()),
            details: vec![],
            duration_ms: 100,
        }
    }

    fn make_empty_results() -> ValidationResults {
        ValidationResults {
            server: "test-server".to_string(),
            protocol_version: Some("2024-11-05".to_string()),
            capabilities: None,
            results: vec![],
            passed: 0,
            failed: 0,
            warnings: 0,
            total_duration_ms: 0,
        }
    }

    #[test]
    fn sarif_from_validation_results_empty() {
        let results = make_empty_results();
        let sarif = SarifReport::from_validation_results(&results);
        assert_eq!(sarif.runs.len(), 1);
        assert!(sarif.runs[0].results.is_empty());
    }

    #[test]
    fn sarif_from_validation_results_with_failures() {
        let mut results = make_empty_results();
        results.results = vec![
            make_validation_result(
                "PROTO-001",
                "Test Rule",
                ValidationSeverity::Fail,
                Some("Failed validation"),
            ),
            make_validation_result(
                "PROTO-002",
                "Warning Rule",
                ValidationSeverity::Warning,
                Some("Warning message"),
            ),
        ];
        results.failed = 1;
        results.warnings = 1;

        let sarif = SarifReport::from_validation_results(&results);
        assert_eq!(sarif.runs.len(), 1);
        assert_eq!(sarif.runs[0].results.len(), 2);
        assert_eq!(sarif.runs[0].tool.driver.rules.len(), 2);
    }

    #[test]
    fn sarif_from_validation_results_filters_pass() {
        let mut results = make_empty_results();
        results.results = vec![
            make_validation_result("PROTO-001", "Pass Rule", ValidationSeverity::Pass, None),
            make_validation_result(
                "PROTO-002",
                "Fail Rule",
                ValidationSeverity::Fail,
                Some("Error"),
            ),
        ];
        results.passed = 1;
        results.failed = 1;

        let sarif = SarifReport::from_validation_results(&results);
        // Only failures and warnings should be in results
        assert_eq!(sarif.runs[0].results.len(), 1);
        assert_eq!(sarif.runs[0].results[0].rule_id, "PROTO-002");
    }

    #[test]
    fn sarif_serialization() {
        let report = SarifReport::new();
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("2.1.0"));
        assert!(json.contains("$schema"));
    }

    #[test]
    fn sarif_deserialization() {
        let json = r#"{
            "$schema": "https://example.com/schema.json",
            "version": "2.1.0",
            "runs": []
        }"#;
        let report: SarifReport = serde_json::from_str(json).unwrap();
        assert_eq!(report.version, "2.1.0");
    }

    #[test]
    fn sarif_driver_info() {
        let results = make_empty_results();
        let sarif = SarifReport::from_validation_results(&results);
        assert_eq!(sarif.runs[0].tool.driver.name, "mcplint");
        assert!(sarif.runs[0].tool.driver.information_uri.contains("github"));
    }

    // =========================================================================
    // Tests for from_scan_results()
    // =========================================================================

    fn make_scan_finding(
        rule_id: &str,
        severity: Severity,
        title: &str,
        description: &str,
        component: &str,
        identifier: &str,
    ) -> Finding {
        Finding::new(rule_id, severity, title, description).with_location(FindingLocation {
            component: component.to_string(),
            identifier: identifier.to_string(),
            context: None,
        })
    }

    fn make_empty_scan_results() -> ScanResults {
        ScanResults::new("test-server", ScanProfile::Standard)
    }

    #[test]
    fn sarif_from_scan_results_empty() {
        let results = make_empty_scan_results();
        let sarif = SarifReport::from_scan_results(&results);

        assert_eq!(sarif.version, "2.1.0");
        assert_eq!(sarif.runs.len(), 1);
        assert!(sarif.runs[0].results.is_empty());
        assert!(sarif.runs[0].tool.driver.rules.is_empty());
    }

    #[test]
    fn sarif_from_scan_results_with_findings() {
        let mut results = make_empty_scan_results();
        results.add_finding(make_scan_finding(
            "MCP-INJ-001",
            Severity::Critical,
            "Command Injection",
            "Detected command injection vulnerability",
            "tool",
            "shell_exec",
        ));

        let sarif = SarifReport::from_scan_results(&results);

        assert_eq!(sarif.runs.len(), 1);
        assert_eq!(sarif.runs[0].results.len(), 1);
        assert_eq!(sarif.runs[0].tool.driver.rules.len(), 1);

        // Check the result
        let result = &sarif.runs[0].results[0];
        assert_eq!(result.rule_id, "MCP-INJ-001");
        assert_eq!(result.level, "error"); // Critical maps to error
        assert!(result.message.text.contains("Command Injection"));

        // Check the rule
        let rule = &sarif.runs[0].tool.driver.rules[0];
        assert_eq!(rule.id, "MCP-INJ-001");
        assert_eq!(rule.name, "Command Injection");
    }

    #[test]
    fn sarif_from_scan_results_severity_mapping() {
        let mut results = make_empty_scan_results();

        // Add findings with different severities
        results.add_finding(make_scan_finding(
            "TEST-001",
            Severity::Critical,
            "Critical Issue",
            "Desc",
            "tool",
            "t1",
        ));
        results.add_finding(make_scan_finding(
            "TEST-002",
            Severity::High,
            "High Issue",
            "Desc",
            "tool",
            "t2",
        ));
        results.add_finding(make_scan_finding(
            "TEST-003",
            Severity::Medium,
            "Medium Issue",
            "Desc",
            "tool",
            "t3",
        ));
        results.add_finding(make_scan_finding(
            "TEST-004",
            Severity::Low,
            "Low Issue",
            "Desc",
            "tool",
            "t4",
        ));
        results.add_finding(make_scan_finding(
            "TEST-005",
            Severity::Info,
            "Info Issue",
            "Desc",
            "tool",
            "t5",
        ));

        let sarif = SarifReport::from_scan_results(&results);

        // Verify SARIF levels
        assert_eq!(sarif.runs[0].results[0].level, "error"); // Critical
        assert_eq!(sarif.runs[0].results[1].level, "error"); // High
        assert_eq!(sarif.runs[0].results[2].level, "warning"); // Medium
        assert_eq!(sarif.runs[0].results[3].level, "note"); // Low
        assert_eq!(sarif.runs[0].results[4].level, "note"); // Info
    }

    #[test]
    fn sarif_from_scan_results_deduplicates_rules() {
        let mut results = make_empty_scan_results();

        // Add multiple findings with the same rule_id
        results.add_finding(make_scan_finding(
            "MCP-INJ-001",
            Severity::High,
            "Injection",
            "Desc",
            "tool",
            "tool_a",
        ));
        results.add_finding(make_scan_finding(
            "MCP-INJ-001",
            Severity::High,
            "Injection",
            "Desc",
            "tool",
            "tool_b",
        ));
        results.add_finding(make_scan_finding(
            "MCP-INJ-001",
            Severity::High,
            "Injection",
            "Desc",
            "tool",
            "tool_c",
        ));

        let sarif = SarifReport::from_scan_results(&results);

        // Should have 3 results but only 1 rule
        assert_eq!(sarif.runs[0].results.len(), 3);
        assert_eq!(sarif.runs[0].tool.driver.rules.len(), 1);
    }

    #[test]
    fn sarif_from_scan_results_location_uri() {
        let mut results = make_empty_scan_results();
        results.add_finding(make_scan_finding(
            "TEST-001",
            Severity::High,
            "Issue",
            "Desc",
            "tool",
            "dangerous_tool",
        ));

        let sarif = SarifReport::from_scan_results(&results);

        let location = &sarif.runs[0].results[0].locations[0];
        assert_eq!(
            location.physical_location.artifact_location.uri,
            "tool/dangerous_tool"
        );
    }

    #[test]
    fn sarif_from_scan_results_includes_remediation() {
        let mut results = make_empty_scan_results();
        let finding = Finding::new("TEST-001", Severity::High, "Issue", "Description of issue")
            .with_location(FindingLocation::tool("test_tool"))
            .with_remediation("Sanitize all user inputs");
        results.add_finding(finding);

        let sarif = SarifReport::from_scan_results(&results);

        let message = &sarif.runs[0].results[0].message.text;
        assert!(message.contains("Remediation: Sanitize all user inputs"));
    }

    #[test]
    fn sarif_from_scan_results_serializes_correctly() {
        let mut results = make_empty_scan_results();
        results.add_finding(make_scan_finding(
            "MCP-INJ-001",
            Severity::Critical,
            "Test Issue",
            "Test Description",
            "tool",
            "test_tool",
        ));

        let sarif = SarifReport::from_scan_results(&results);
        let json = serde_json::to_string_pretty(&sarif).unwrap();

        // Verify the JSON contains expected fields
        assert!(json.contains("\"$schema\""));
        assert!(json.contains("\"version\": \"2.1.0\""));
        assert!(json.contains("\"ruleId\": \"MCP-INJ-001\""));
        assert!(json.contains("\"level\": \"error\""));
        assert!(json.contains("\"mcplint\""));
    }

    #[test]
    fn sarif_from_scan_results_empty_identifier() {
        let mut results = make_empty_scan_results();
        results.add_finding(
            Finding::new("TEST-001", Severity::Medium, "Issue", "Desc").with_location(
                FindingLocation {
                    component: "server".to_string(),
                    identifier: String::new(),
                    context: None,
                },
            ),
        );

        let sarif = SarifReport::from_scan_results(&results);

        // Should fall back to server name in URI
        let location = &sarif.runs[0].results[0].locations[0];
        assert_eq!(
            location.physical_location.artifact_location.uri,
            "server/test-server"
        );
    }

    #[test]
    fn sarif_from_validation_results_with_info_and_skip() {
        let mut results = make_empty_results();
        results.results = vec![
            make_validation_result(
                "PROTO-001",
                "Info Rule",
                ValidationSeverity::Info,
                Some("Informational message"),
            ),
            make_validation_result(
                "PROTO-002",
                "Skip Rule",
                ValidationSeverity::Skip,
                Some("Skipped validation"),
            ),
        ];

        let sarif = SarifReport::from_validation_results(&results);

        // Info and Skip should be filtered out (not included in results)
        assert_eq!(sarif.runs[0].results.len(), 0);
        // But rules should still be created with "note" level
        assert_eq!(sarif.runs[0].tool.driver.rules.len(), 2);
        assert_eq!(
            sarif.runs[0].tool.driver.rules[0]
                .default_configuration
                .level,
            "note"
        );
        assert_eq!(
            sarif.runs[0].tool.driver.rules[1]
                .default_configuration
                .level,
            "note"
        );
    }
}
