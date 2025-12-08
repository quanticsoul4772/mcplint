//! JUnit XML Reporter
//!
//! Generates JUnit XML output format for CI/CD integration.
//! Compatible with Jenkins, CircleCI, Azure DevOps, and other CI systems.

use crate::scanner::{ScanResults, Severity};

/// Generate JUnit XML output from scan results
pub fn generate_junit(results: &ScanResults) -> String {
    let mut xml = String::new();

    xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    xml.push_str(&format!(
        "<testsuite name=\"mcplint\" tests=\"{}\" failures=\"{}\" errors=\"0\" time=\"{:.3}\">\n",
        if results.findings.is_empty() {
            1
        } else {
            results.findings.len()
        },
        results.findings.len(),
        results.duration_ms as f64 / 1000.0
    ));

    if results.findings.is_empty() {
        // Add a passing test case when no findings
        xml.push_str(
            "  <testcase name=\"Security Scan\" classname=\"mcplint.scan\" time=\"0.000\"/>\n",
        );
    } else {
        for finding in &results.findings {
            xml.push_str(&format!(
                "  <testcase name=\"{}\" classname=\"mcplint.{}\" time=\"0.000\">\n",
                escape_xml(&finding.title),
                finding.rule_id.replace('-', ".")
            ));

            xml.push_str(&format!(
                "    <failure message=\"{}\" type=\"{}\">\n",
                escape_xml(&truncate(&finding.description, 200)),
                severity_type(finding.severity)
            ));

            // Detailed failure content
            xml.push_str(&format!("Rule: {}\n", finding.rule_id));
            xml.push_str(&format!("Severity: {}\n", finding.severity));
            xml.push_str(&format!(
                "Location: {}:{}\n",
                finding.location.component, finding.location.identifier
            ));
            xml.push_str(&format!("Description: {}\n", finding.description));

            if !finding.evidence.is_empty() {
                xml.push_str("\nEvidence:\n");
                for evidence in &finding.evidence {
                    xml.push_str(&format!(
                        "- {}: {}\n",
                        evidence.kind_str(),
                        evidence.description
                    ));
                }
            }

            if !finding.remediation.is_empty() {
                xml.push_str(&format!("\nRemediation: {}\n", finding.remediation));
            }

            if !finding.references.is_empty() {
                xml.push_str("\nReferences:\n");
                for reference in &finding.references {
                    xml.push_str(&format!("- {}", reference.id));
                    if let Some(url) = &reference.url {
                        xml.push_str(&format!(": {}", url));
                    }
                    xml.push('\n');
                }
            }

            xml.push_str("    </failure>\n");
            xml.push_str("  </testcase>\n");
        }
    }

    xml.push_str("</testsuite>\n");
    xml
}

/// Escape XML special characters
fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// Truncate string to max length with ellipsis
fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len.saturating_sub(3)])
    }
}

/// Map severity to JUnit failure type
fn severity_type(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "Critical",
        Severity::High => "High",
        Severity::Medium => "Medium",
        Severity::Low => "Low",
        Severity::Info => "Info",
    }
}

// Helper trait to get evidence kind as string
trait EvidenceKindStr {
    fn kind_str(&self) -> &'static str;
}

impl EvidenceKindStr for crate::scanner::Evidence {
    fn kind_str(&self) -> &'static str {
        match self.kind {
            crate::scanner::EvidenceKind::Request => "Request",
            crate::scanner::EvidenceKind::Response => "Response",
            crate::scanner::EvidenceKind::Configuration => "Configuration",
            crate::scanner::EvidenceKind::Observation => "Observation",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::{Finding, FindingLocation, ScanSummary};

    fn create_test_results() -> ScanResults {
        let mut results = ScanResults {
            server: "test-server".to_string(),
            profile: "standard".to_string(),
            total_checks: 10,
            findings: Vec::new(),
            summary: ScanSummary::default(),
            duration_ms: 1500,
        };

        results.add_finding(
            Finding::new(
                "MCP-INJ-001",
                Severity::Critical,
                "Command Injection",
                "Tool accepts shell commands without sanitization",
            )
            .with_location(FindingLocation::tool("exec_command")),
        );

        results
    }

    #[test]
    fn generates_valid_xml() {
        let results = create_test_results();
        let xml = generate_junit(&results);

        assert!(xml.starts_with("<?xml"));
        assert!(xml.contains("<testsuite"));
        assert!(xml.contains("</testsuite>"));
        assert!(xml.contains("mcplint"));
    }

    #[test]
    fn empty_results_has_passing_test() {
        let results = ScanResults {
            server: "test-server".to_string(),
            profile: "standard".to_string(),
            total_checks: 10,
            findings: Vec::new(),
            summary: ScanSummary::default(),
            duration_ms: 100,
        };

        let xml = generate_junit(&results);

        assert!(xml.contains("failures=\"0\""));
        assert!(xml.contains("Security Scan"));
        assert!(!xml.contains("<failure"));
    }

    #[test]
    fn escapes_xml_entities() {
        assert_eq!(escape_xml("<test>"), "&lt;test&gt;");
        assert_eq!(escape_xml("a & b"), "a &amp; b");
        assert_eq!(escape_xml("\"quoted\""), "&quot;quoted&quot;");
    }

    #[test]
    fn truncates_long_strings() {
        let long = "a".repeat(300);
        let truncated = truncate(&long, 100);
        assert!(truncated.len() <= 100);
        assert!(truncated.ends_with("..."));
    }
}
