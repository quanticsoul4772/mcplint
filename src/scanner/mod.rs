//! Security Scanner - Vulnerability detection for MCP servers
//!
//! This module implements the M2 milestone: Security Scanner
//! It scans MCP servers for security vulnerabilities using pattern-based detection.

mod checks;
pub mod context;
mod engine;
mod finding;
mod helpers;
mod results;
pub mod rules;

pub use context::{ScanConfig, ScanProfile, ServerContext};
// Re-exports for public API - used by external consumers and tests
#[allow(unused_imports)]
pub use engine::{ScanEngine, ScanResults, ScanSummary};
#[allow(unused_imports)]
pub use finding::{Evidence, EvidenceKind, Finding, FindingLocation, ReferenceKind, Severity};

use anyhow::Result;
use colored::Colorize;

impl ScanResults {
    pub fn print_text(&self) {
        println!("{}", "Security Scan Results".cyan().bold());
        println!("{}", "=".repeat(60));
        println!();

        println!("  Server: {}", self.server.yellow());
        println!("  Profile: {}", self.profile.green());
        println!("  Checks: {}", self.total_checks);
        println!("  Duration: {}ms", self.duration_ms);
        println!();

        if self.findings.is_empty() {
            println!("{}", "  No vulnerabilities found ✓".green().bold());
        } else {
            println!(
                "  {} {} found:",
                self.findings.len(),
                if self.findings.len() == 1 {
                    "vulnerability"
                } else {
                    "vulnerabilities"
                }
            );
            println!();

            for finding in &self.findings {
                println!(
                    "  [{}] {} ({})",
                    finding.severity.colored_display(),
                    finding.title,
                    finding.rule_id.dimmed()
                );
                println!("    {}", finding.description);

                if !finding.location.component.is_empty() {
                    println!(
                        "    Location: {}: {}",
                        finding.location.component.cyan(),
                        finding.location.identifier
                    );
                }

                if !finding.remediation.is_empty() {
                    println!("    Fix: {}", finding.remediation.green());
                }

                if !finding.references.is_empty() {
                    let refs: Vec<String> =
                        finding.references.iter().map(|r| r.id.clone()).collect();
                    println!("    References: {}", refs.join(", ").dimmed());
                }

                println!();
            }
        }

        println!("{}", "─".repeat(60));
        println!(
            "Summary: {} critical, {} high, {} medium, {} low, {} info",
            self.summary.critical.to_string().red(),
            self.summary.high.to_string().red(),
            self.summary.medium.to_string().yellow(),
            self.summary.low.to_string().blue(),
            self.summary.info.to_string().dimmed()
        );

        if self.has_critical_or_high() {
            println!(
                "\n{}",
                "Server has critical/high severity vulnerabilities!"
                    .red()
                    .bold()
            );
        } else if self.total_findings() > 0 {
            println!("\n{}", "Server has security issues to address.".yellow());
        } else {
            println!("\n{}", "No security issues detected.".green().bold());
        }
    }

    pub fn print_json(&self) -> Result<()> {
        println!("{}", serde_json::to_string_pretty(self)?);
        Ok(())
    }

    pub fn print_sarif(&self) -> Result<()> {
        let sarif = to_sarif_report(self);
        println!("{}", serde_json::to_string_pretty(&sarif)?);
        Ok(())
    }
}

/// Convert scan results to SARIF format for CI/CD integration
fn to_sarif_report(results: &ScanResults) -> serde_json::Value {
    use std::collections::HashSet;

    // Collect unique rules
    let mut seen_rules: HashSet<String> = HashSet::new();
    let mut rules = Vec::new();

    for finding in &results.findings {
        if !seen_rules.contains(&finding.rule_id) {
            seen_rules.insert(finding.rule_id.clone());
            rules.push(serde_json::json!({
                "id": finding.rule_id,
                "name": finding.title,
                "shortDescription": {
                    "text": finding.title
                },
                "fullDescription": {
                    "text": finding.description
                },
                "defaultConfiguration": {
                    "level": finding.severity.sarif_level()
                },
                "helpUri": finding.references.first().and_then(|r| r.url.clone())
            }));
        }
    }

    // Convert findings to SARIF results
    let sarif_results: Vec<serde_json::Value> = results
        .findings
        .iter()
        .map(|f| {
            serde_json::json!({
                "ruleId": f.rule_id,
                "level": f.severity.sarif_level(),
                "message": {
                    "text": format!("{}: {}", f.title, f.description)
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": results.server.clone()
                        }
                    },
                    "logicalLocations": [{
                        "name": f.location.identifier.clone(),
                        "kind": f.location.component.clone()
                    }]
                }]
            })
        })
        .collect();

    serde_json::json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "mcplint",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/quanticsoul4772/mcplint",
                    "rules": rules
                }
            },
            "results": sarif_results
        }]
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use engine::{ScanResults, ScanSummary};
    use finding::{Finding, Severity};

    fn create_test_results(findings: Vec<Finding>) -> ScanResults {
        let summary = ScanSummary {
            critical: findings
                .iter()
                .filter(|f| f.severity == Severity::Critical)
                .count(),
            high: findings
                .iter()
                .filter(|f| f.severity == Severity::High)
                .count(),
            medium: findings
                .iter()
                .filter(|f| f.severity == Severity::Medium)
                .count(),
            low: findings
                .iter()
                .filter(|f| f.severity == Severity::Low)
                .count(),
            info: findings
                .iter()
                .filter(|f| f.severity == Severity::Info)
                .count(),
        };
        ScanResults {
            server: "test-server".to_string(),
            profile: "standard".to_string(),
            total_checks: 10,
            duration_ms: 100,
            findings,
            summary,
        }
    }

    fn create_finding(severity: Severity, rule_id: &str, title: &str) -> Finding {
        Finding::new(rule_id, severity, title, "Test description")
    }

    #[test]
    fn to_sarif_report_empty_results() {
        let results = create_test_results(vec![]);
        let sarif = to_sarif_report(&results);

        assert_eq!(sarif["version"], "2.1.0");
        assert!(sarif["$schema"].as_str().unwrap().contains("sarif-schema"));
        assert_eq!(sarif["runs"][0]["tool"]["driver"]["name"], "mcplint");
        assert!(sarif["runs"][0]["results"].as_array().unwrap().is_empty());
    }

    #[test]
    fn to_sarif_report_with_findings() {
        let findings = vec![
            create_finding(Severity::Critical, "TEST-001", "Critical Issue"),
            create_finding(Severity::High, "TEST-002", "High Issue"),
        ];
        let results = create_test_results(findings);
        let sarif = to_sarif_report(&results);

        let sarif_results = sarif["runs"][0]["results"].as_array().unwrap();
        assert_eq!(sarif_results.len(), 2);
        assert_eq!(sarif_results[0]["ruleId"], "TEST-001");
        assert_eq!(sarif_results[1]["ruleId"], "TEST-002");
    }

    #[test]
    fn to_sarif_report_deduplicates_rules() {
        let findings = vec![
            create_finding(Severity::High, "TEST-001", "Issue 1"),
            create_finding(Severity::High, "TEST-001", "Issue 1 again"),
            create_finding(Severity::Medium, "TEST-002", "Issue 2"),
        ];
        let results = create_test_results(findings);
        let sarif = to_sarif_report(&results);

        let rules = sarif["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap();
        // Should only have 2 unique rules even though we have 3 findings
        assert_eq!(rules.len(), 2);
    }

    #[test]
    fn to_sarif_report_severity_levels() {
        let findings = vec![
            create_finding(Severity::Critical, "CRIT-001", "Critical"),
            create_finding(Severity::High, "HIGH-001", "High"),
            create_finding(Severity::Medium, "MED-001", "Medium"),
            create_finding(Severity::Low, "LOW-001", "Low"),
            create_finding(Severity::Info, "INFO-001", "Info"),
        ];
        let results = create_test_results(findings);
        let sarif = to_sarif_report(&results);

        let sarif_results = sarif["runs"][0]["results"].as_array().unwrap();
        assert_eq!(sarif_results[0]["level"], "error"); // Critical
        assert_eq!(sarif_results[1]["level"], "error"); // High
        assert_eq!(sarif_results[2]["level"], "warning"); // Medium
        assert_eq!(sarif_results[3]["level"], "note"); // Low
        assert_eq!(sarif_results[4]["level"], "note"); // Info (also maps to note)
    }

    #[test]
    fn to_sarif_report_includes_server_uri() {
        let results =
            create_test_results(vec![create_finding(Severity::Medium, "TEST-001", "Test")]);
        let sarif = to_sarif_report(&results);

        let location = &sarif["runs"][0]["results"][0]["locations"][0];
        assert_eq!(
            location["physicalLocation"]["artifactLocation"]["uri"],
            "test-server"
        );
    }

    #[test]
    fn scan_results_has_critical_or_high() {
        let critical_results = create_test_results(vec![create_finding(
            Severity::Critical,
            "TEST-001",
            "Critical",
        )]);
        assert!(critical_results.has_critical_or_high());

        let high_results =
            create_test_results(vec![create_finding(Severity::High, "TEST-001", "High")]);
        assert!(high_results.has_critical_or_high());

        let medium_results =
            create_test_results(vec![create_finding(Severity::Medium, "TEST-001", "Medium")]);
        assert!(!medium_results.has_critical_or_high());

        let empty_results = create_test_results(vec![]);
        assert!(!empty_results.has_critical_or_high());
    }

    #[test]
    fn scan_results_total_findings() {
        let results = create_test_results(vec![
            create_finding(Severity::High, "TEST-001", "Finding 1"),
            create_finding(Severity::Medium, "TEST-002", "Finding 2"),
            create_finding(Severity::Low, "TEST-003", "Finding 3"),
        ]);
        assert_eq!(results.total_findings(), 3);

        let empty = create_test_results(vec![]);
        assert_eq!(empty.total_findings(), 0);
    }

    #[test]
    fn print_text_no_findings() {
        let results = create_test_results(vec![]);
        // Should not panic
        results.print_text();
    }

    #[test]
    fn print_text_with_critical_finding() {
        let results = create_test_results(vec![create_finding(
            Severity::Critical,
            "CRIT-001",
            "Critical Issue",
        )]);
        // Should not panic - tests the critical/high branch
        results.print_text();
    }

    #[test]
    fn print_text_with_medium_finding() {
        let results = create_test_results(vec![create_finding(
            Severity::Medium,
            "MED-001",
            "Medium Issue",
        )]);
        // Should not panic - tests the "has issues to address" branch
        results.print_text();
    }

    #[test]
    fn print_text_single_finding() {
        let results = create_test_results(vec![create_finding(
            Severity::Low,
            "LOW-001",
            "Single Finding",
        )]);
        // Tests the "1 vulnerability" vs "vulnerabilities" logic
        results.print_text();
    }

    #[test]
    fn print_text_multiple_findings() {
        let results = create_test_results(vec![
            create_finding(Severity::High, "HIGH-001", "Finding 1"),
            create_finding(Severity::Medium, "MED-001", "Finding 2"),
        ]);
        // Tests the "vulnerabilities" plural branch
        results.print_text();
    }

    #[test]
    fn print_text_with_location() {
        let mut finding = create_finding(Severity::High, "TEST-001", "Test");
        finding.location.component = "tool".to_string();
        finding.location.identifier = "dangerous_exec".to_string();
        let results = create_test_results(vec![finding]);
        results.print_text();
    }

    #[test]
    fn print_text_with_remediation() {
        let mut finding = create_finding(Severity::Medium, "TEST-001", "Test");
        finding.remediation = "Fix this by doing X".to_string();
        let results = create_test_results(vec![finding]);
        results.print_text();
    }

    #[test]
    fn print_text_with_references() {
        let mut finding = create_finding(Severity::Low, "TEST-001", "Test");
        finding.references = vec![
            crate::scanner::finding::Reference {
                kind: ReferenceKind::Cwe,
                id: "CWE-78".to_string(),
                url: Some("https://cwe.mitre.org/data/definitions/78.html".to_string()),
            },
            crate::scanner::finding::Reference {
                kind: ReferenceKind::Documentation,
                id: "MCP-SEC-001".to_string(),
                url: None,
            },
        ];
        let results = create_test_results(vec![finding]);
        results.print_text();
    }

    #[test]
    fn print_json_success() {
        let results = create_test_results(vec![create_finding(
            Severity::High,
            "TEST-001",
            "Test Finding",
        )]);
        let result = results.print_json();
        assert!(result.is_ok());
    }

    #[test]
    fn print_json_empty() {
        let results = create_test_results(vec![]);
        let result = results.print_json();
        assert!(result.is_ok());
    }

    #[test]
    fn print_sarif_success() {
        let results = create_test_results(vec![create_finding(
            Severity::Critical,
            "TEST-001",
            "Test Finding",
        )]);
        let result = results.print_sarif();
        assert!(result.is_ok());
    }

    #[test]
    fn print_sarif_empty() {
        let results = create_test_results(vec![]);
        let result = results.print_sarif();
        assert!(result.is_ok());
    }

    #[test]
    fn scan_summary_counts() {
        let findings = vec![
            create_finding(Severity::Critical, "C1", "Critical 1"),
            create_finding(Severity::Critical, "C2", "Critical 2"),
            create_finding(Severity::High, "H1", "High 1"),
            create_finding(Severity::Medium, "M1", "Medium 1"),
            create_finding(Severity::Medium, "M2", "Medium 2"),
            create_finding(Severity::Medium, "M3", "Medium 3"),
            create_finding(Severity::Low, "L1", "Low 1"),
            create_finding(Severity::Info, "I1", "Info 1"),
            create_finding(Severity::Info, "I2", "Info 2"),
        ];
        let results = create_test_results(findings);

        assert_eq!(results.summary.critical, 2);
        assert_eq!(results.summary.high, 1);
        assert_eq!(results.summary.medium, 3);
        assert_eq!(results.summary.low, 1);
        assert_eq!(results.summary.info, 2);
    }

    #[test]
    fn sarif_report_has_required_fields() {
        let results = create_test_results(vec![]);
        let sarif = to_sarif_report(&results);

        assert!(sarif["$schema"].is_string());
        assert_eq!(sarif["version"], "2.1.0");
        assert!(sarif["runs"].is_array());
        assert!(sarif["runs"][0]["tool"]["driver"]["name"].is_string());
        assert!(sarif["runs"][0]["tool"]["driver"]["version"].is_string());
        assert!(sarif["runs"][0]["tool"]["driver"]["informationUri"].is_string());
    }

    #[test]
    fn sarif_results_have_logical_locations() {
        let mut finding = create_finding(Severity::Medium, "TEST-001", "Test");
        finding.location.component = "resource".to_string();
        finding.location.identifier = "config://data".to_string();
        let results = create_test_results(vec![finding]);
        let sarif = to_sarif_report(&results);

        let loc = &sarif["runs"][0]["results"][0]["locations"][0]["logicalLocations"][0];
        assert_eq!(loc["name"], "config://data");
        assert_eq!(loc["kind"], "resource");
    }

    #[test]
    fn sarif_rule_includes_help_uri_when_present() {
        let mut finding = create_finding(Severity::High, "TEST-001", "Test");
        finding.references = vec![crate::scanner::finding::Reference {
            kind: ReferenceKind::Cwe,
            id: "CWE-78".to_string(),
            url: Some("https://example.com/help".to_string()),
        }];
        let results = create_test_results(vec![finding]);
        let sarif = to_sarif_report(&results);

        let rules = sarif["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap();
        assert_eq!(rules[0]["helpUri"], "https://example.com/help");
    }

    #[test]
    fn sarif_rule_no_help_uri_when_absent() {
        let finding = create_finding(Severity::Low, "TEST-001", "Test");
        let results = create_test_results(vec![finding]);
        let sarif = to_sarif_report(&results);

        let rules = sarif["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap();
        assert!(rules[0]["helpUri"].is_null());
    }

    #[test]
    fn print_text_all_severity_levels() {
        let findings = vec![
            create_finding(Severity::Critical, "CRIT-001", "Critical"),
            create_finding(Severity::High, "HIGH-001", "High"),
            create_finding(Severity::Medium, "MED-001", "Medium"),
            create_finding(Severity::Low, "LOW-001", "Low"),
            create_finding(Severity::Info, "INFO-001", "Info"),
        ];
        let results = create_test_results(findings);
        // Tests all severity coloring branches
        results.print_text();
    }

    #[test]
    fn print_text_empty_component_skips_location() {
        let mut finding = create_finding(Severity::Medium, "TEST-001", "Test");
        finding.location.component = "".to_string(); // Empty component
        finding.location.identifier = "something".to_string();
        let results = create_test_results(vec![finding]);
        // Should not print location line
        results.print_text();
    }

    #[test]
    fn print_text_empty_remediation_skips_fix() {
        let mut finding = create_finding(Severity::Medium, "TEST-001", "Test");
        finding.remediation = "".to_string(); // Empty remediation
        let results = create_test_results(vec![finding]);
        // Should not print fix line
        results.print_text();
    }

    #[test]
    fn print_text_empty_references_skips_refs() {
        let finding = create_finding(Severity::Medium, "TEST-001", "Test");
        // finding.references is empty by default
        let results = create_test_results(vec![finding]);
        // Should not print references line
        results.print_text();
    }
}
