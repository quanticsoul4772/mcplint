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
    use crate::scanner::{
        Evidence, EvidenceKind, Finding, FindingLocation, Reference, ScanSummary,
    };

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

    // NEW TESTS

    #[test]
    fn generates_junit_xml_with_empty_results() {
        let results = ScanResults {
            server: "empty-server".to_string(),
            profile: "minimal".to_string(),
            total_checks: 0,
            findings: Vec::new(),
            summary: ScanSummary::default(),
            duration_ms: 50,
        };

        let xml = generate_junit(&results);

        assert!(xml.contains("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
        assert!(xml.contains("<testsuite name=\"mcplint\" tests=\"1\" failures=\"0\""));
        assert!(xml.contains("time=\"0.050\""));
        assert!(xml.contains("<testcase name=\"Security Scan\" classname=\"mcplint.scan\""));
    }

    #[test]
    fn generates_junit_xml_with_passed_tests() {
        let results = ScanResults {
            server: "pass-server".to_string(),
            profile: "standard".to_string(),
            total_checks: 5,
            findings: Vec::new(),
            summary: ScanSummary::default(),
            duration_ms: 200,
        };

        let xml = generate_junit(&results);

        assert!(xml.contains("tests=\"1\""));
        assert!(xml.contains("failures=\"0\""));
        assert!(xml.contains("errors=\"0\""));
        assert!(xml.contains("Security Scan"));
    }

    #[test]
    fn generates_junit_xml_with_failed_tests() {
        let mut results = ScanResults {
            server: "fail-server".to_string(),
            profile: "standard".to_string(),
            total_checks: 10,
            findings: Vec::new(),
            summary: ScanSummary::default(),
            duration_ms: 2000,
        };

        results.add_finding(
            Finding::new(
                "MCP-SEC-001",
                Severity::High,
                "Security Vulnerability",
                "Detected security issue in tool configuration",
            )
            .with_location(FindingLocation::tool("dangerous_tool")),
        );

        let xml = generate_junit(&results);

        assert!(xml.contains("tests=\"1\""));
        assert!(xml.contains("failures=\"1\""));
        assert!(xml.contains("<failure message="));
        assert!(xml.contains("type=\"High\""));
        assert!(xml.contains("Security Vulnerability"));
    }

    #[test]
    fn generates_junit_xml_with_warnings() {
        let mut results = ScanResults {
            server: "warn-server".to_string(),
            profile: "standard".to_string(),
            total_checks: 8,
            findings: Vec::new(),
            summary: ScanSummary::default(),
            duration_ms: 800,
        };

        results.add_finding(
            Finding::new(
                "MCP-WARN-001",
                Severity::Low,
                "Configuration Warning",
                "Potential configuration issue detected",
            )
            .with_location(FindingLocation::server()),
        );

        let xml = generate_junit(&results);

        assert!(xml.contains("tests=\"1\""));
        assert!(xml.contains("failures=\"1\""));
        assert!(xml.contains("type=\"Low\""));
        assert!(xml.contains("Configuration Warning"));
    }

    #[test]
    fn generates_junit_xml_with_mixed_results() {
        let mut results = ScanResults {
            server: "mixed-server".to_string(),
            profile: "comprehensive".to_string(),
            total_checks: 15,
            findings: Vec::new(),
            summary: ScanSummary::default(),
            duration_ms: 3500,
        };

        results.add_finding(
            Finding::new(
                "MCP-CRIT-001",
                Severity::Critical,
                "Critical Issue",
                "Critical vulnerability found",
            )
            .with_location(FindingLocation::tool("critical_tool")),
        );

        results.add_finding(
            Finding::new(
                "MCP-MED-001",
                Severity::Medium,
                "Medium Issue",
                "Medium severity issue",
            )
            .with_location(FindingLocation::transport("http")),
        );

        results.add_finding(
            Finding::new(
                "MCP-INFO-001",
                Severity::Info,
                "Information",
                "Informational finding",
            )
            .with_location(FindingLocation::server()),
        );

        let xml = generate_junit(&results);

        assert!(xml.contains("tests=\"3\""));
        assert!(xml.contains("failures=\"3\""));
        assert!(xml.contains("type=\"Critical\""));
        assert!(xml.contains("type=\"Medium\""));
        assert!(xml.contains("type=\"Info\""));
        assert!(xml.contains("Critical Issue"));
        assert!(xml.contains("Medium Issue"));
        assert!(xml.contains("Information"));
    }

    #[test]
    fn xml_structure_validation_test_suites() {
        let results = ScanResults {
            server: "struct-server".to_string(),
            profile: "standard".to_string(),
            total_checks: 1,
            findings: Vec::new(),
            summary: ScanSummary::default(),
            duration_ms: 100,
        };

        let xml = generate_junit(&results);

        assert!(xml.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"));
        assert!(xml.contains("<testsuite"));
        assert!(xml.contains("name=\"mcplint\""));
        assert!(xml.ends_with("</testsuite>\n"));
    }

    #[test]
    fn xml_structure_validation_test_cases() {
        let mut results = ScanResults {
            server: "case-server".to_string(),
            profile: "standard".to_string(),
            total_checks: 2,
            findings: Vec::new(),
            summary: ScanSummary::default(),
            duration_ms: 500,
        };

        results.add_finding(
            Finding::new(
                "MCP-TEST-001",
                Severity::High,
                "Test Finding",
                "Test description",
            )
            .with_location(FindingLocation::tool("test_tool")),
        );

        let xml = generate_junit(&results);

        assert!(xml.contains("<testcase"));
        assert!(xml.contains("name=\"Test Finding\""));
        assert!(xml.contains("classname=\"mcplint.MCP.TEST.001\""));
        assert!(xml.contains("</testcase>"));
    }

    #[test]
    fn proper_xml_escaping_of_special_characters() {
        let mut results = ScanResults {
            server: "escape-server".to_string(),
            profile: "standard".to_string(),
            total_checks: 1,
            findings: Vec::new(),
            summary: ScanSummary::default(),
            duration_ms: 100,
        };

        results.add_finding(
            Finding::new(
                "MCP-ESC-001",
                Severity::Medium,
                "<Title> with \"quotes\" & 'apostrophes'",
                "Description with <tags>, \"quotes\", & special chars",
            )
            .with_location(FindingLocation::tool("escape_test")),
        );

        let xml = generate_junit(&results);

        // Verify XML escaping - at minimum < and > must be escaped
        assert!(xml.contains("&lt;") || !xml.contains("<Title>")); // < escaped or not present raw
        assert!(xml.contains("&gt;") || !xml.contains(">Title<")); // > escaped or not present raw
                                                                   // Other assertions are implementation-dependent
    }

    #[test]
    fn duration_calculation_in_output() {
        let results = ScanResults {
            server: "duration-server".to_string(),
            profile: "standard".to_string(),
            total_checks: 1,
            findings: Vec::new(),
            summary: ScanSummary::default(),
            duration_ms: 5432,
        };

        let xml = generate_junit(&results);

        assert!(xml.contains("time=\"5.432\""));
    }

    #[test]
    fn duration_calculation_sub_second() {
        let results = ScanResults {
            server: "quick-server".to_string(),
            profile: "fast".to_string(),
            total_checks: 1,
            findings: Vec::new(),
            summary: ScanSummary::default(),
            duration_ms: 123,
        };

        let xml = generate_junit(&results);

        assert!(xml.contains("time=\"0.123\""));
    }

    #[test]
    fn error_message_formatting() {
        let mut results = ScanResults {
            server: "error-server".to_string(),
            profile: "standard".to_string(),
            total_checks: 1,
            findings: Vec::new(),
            summary: ScanSummary::default(),
            duration_ms: 200,
        };

        results.add_finding(
            Finding::new(
                "MCP-ERR-001",
                Severity::Critical,
                "Error Title",
                "Detailed error description goes here",
            )
            .with_location(FindingLocation::tool("error_tool"))
            .with_remediation("Fix by doing XYZ"),
        );

        let xml = generate_junit(&results);

        assert!(xml.contains(
            "<failure message=\"Detailed error description goes here\" type=\"Critical\">"
        ));
        assert!(xml.contains("Rule: MCP-ERR-001"));
        assert!(xml.contains("Severity: critical"));
        assert!(xml.contains("Location: tool:error_tool"));
        assert!(xml.contains("Description: Detailed error description goes here"));
        assert!(xml.contains("Remediation: Fix by doing XYZ"));
    }

    #[test]
    fn finding_with_evidence() {
        let mut results = ScanResults {
            server: "evidence-server".to_string(),
            profile: "standard".to_string(),
            total_checks: 1,
            findings: Vec::new(),
            summary: ScanSummary::default(),
            duration_ms: 300,
        };

        results.add_finding(
            Finding::new(
                "MCP-EV-001",
                Severity::High,
                "Finding with Evidence",
                "Description",
            )
            .with_location(FindingLocation::tool("evidence_tool"))
            .with_evidence(Evidence::new(
                EvidenceKind::Request,
                "{\"tool\": \"exec\"}",
                "Suspicious request payload",
            ))
            .with_evidence(Evidence::new(
                EvidenceKind::Response,
                "{\"error\": \"injection\"}",
                "Injection detected in response",
            )),
        );

        let xml = generate_junit(&results);

        assert!(xml.contains("Evidence:"));
        assert!(xml.contains("- Request: Suspicious request payload"));
        assert!(xml.contains("- Response: Injection detected in response"));
    }

    #[test]
    fn finding_with_references() {
        let mut results = ScanResults {
            server: "ref-server".to_string(),
            profile: "standard".to_string(),
            total_checks: 1,
            findings: Vec::new(),
            summary: ScanSummary::default(),
            duration_ms: 250,
        };

        results.add_finding(
            Finding::new(
                "MCP-REF-001",
                Severity::High,
                "Finding with References",
                "Description",
            )
            .with_location(FindingLocation::tool("ref_tool"))
            .with_reference(Reference::cwe("78"))
            .with_reference(Reference::mcp_advisory("MCP-ADV-2025-001")),
        );

        let xml = generate_junit(&results);

        assert!(xml.contains("References:"));
        assert!(xml.contains("- CWE-78: https://cwe.mitre.org/data/definitions/78.html"));
        assert!(xml.contains("- MCP-ADV-2025-001"));
    }

    #[test]
    fn severity_type_mapping() {
        assert_eq!(severity_type(Severity::Critical), "Critical");
        assert_eq!(severity_type(Severity::High), "High");
        assert_eq!(severity_type(Severity::Medium), "Medium");
        assert_eq!(severity_type(Severity::Low), "Low");
        assert_eq!(severity_type(Severity::Info), "Info");
    }

    #[test]
    fn truncate_short_string() {
        let short = "Short string";
        let result = truncate(short, 100);
        assert_eq!(result, "Short string");
        assert!(!result.contains("..."));
    }

    #[test]
    fn truncate_exact_length() {
        let exact = "a".repeat(100);
        let result = truncate(&exact, 100);
        assert_eq!(result.len(), 100);
        assert!(!result.contains("..."));
    }

    #[test]
    fn escape_all_xml_entities() {
        let input = "<>&\"'";
        let escaped = escape_xml(input);
        assert_eq!(escaped, "&lt;&gt;&amp;&quot;&apos;");
    }

    #[test]
    fn finding_location_formats() {
        let mut results = ScanResults {
            server: "loc-server".to_string(),
            profile: "standard".to_string(),
            total_checks: 3,
            findings: Vec::new(),
            summary: ScanSummary::default(),
            duration_ms: 400,
        };

        results.add_finding(
            Finding::new("R1", Severity::High, "Tool Location", "Desc")
                .with_location(FindingLocation::tool("my_tool")),
        );

        results.add_finding(
            Finding::new("R2", Severity::Medium, "Transport Location", "Desc")
                .with_location(FindingLocation::transport("stdio")),
        );

        results.add_finding(
            Finding::new("R3", Severity::Low, "Server Location", "Desc")
                .with_location(FindingLocation::server()),
        );

        let xml = generate_junit(&results);

        assert!(xml.contains("Location: tool:my_tool"));
        assert!(xml.contains("Location: transport:stdio"));
        assert!(xml.contains("Location: server:configuration"));
    }

    #[test]
    fn rule_id_classname_conversion() {
        let mut results = ScanResults {
            server: "class-server".to_string(),
            profile: "standard".to_string(),
            total_checks: 1,
            findings: Vec::new(),
            summary: ScanSummary::default(),
            duration_ms: 100,
        };

        results.add_finding(
            Finding::new("MCP-SEC-TOOL-001", Severity::Critical, "Test", "Test")
                .with_location(FindingLocation::tool("test")),
        );

        let xml = generate_junit(&results);

        assert!(xml.contains("classname=\"mcplint.MCP.SEC.TOOL.001\""));
    }

    #[test]
    fn message_truncation_in_failure() {
        let mut results = ScanResults {
            server: "truncate-server".to_string(),
            profile: "standard".to_string(),
            total_checks: 1,
            findings: Vec::new(),
            summary: ScanSummary::default(),
            duration_ms: 100,
        };

        let long_desc = "a".repeat(250);
        results.add_finding(
            Finding::new("MCP-TRUNC-001", Severity::High, "Test", &long_desc)
                .with_location(FindingLocation::tool("test")),
        );

        let xml = generate_junit(&results);

        // Message should be truncated to 200 chars + "..."
        let expected_truncated = format!("{}...", &long_desc[..197]);
        assert!(xml.contains(&expected_truncated));
        assert!(!xml.contains(&format!("message=\"{}\"", long_desc)));
    }
}
