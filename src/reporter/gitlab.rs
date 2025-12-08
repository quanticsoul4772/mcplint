//! GitLab Code Quality Reporter
//!
//! Generates GitLab Code Quality JSON format for merge request integration.
//! See: https://docs.gitlab.com/ee/ci/testing/code_quality.html

use serde::{Deserialize, Serialize};

use crate::baseline::FindingFingerprint;
use crate::scanner::{ScanResults, Severity};

/// GitLab Code Quality issue
#[derive(Debug, Clone, Serialize, Deserialize)]
struct GitLabIssue {
    description: String,
    check_name: String,
    fingerprint: String,
    severity: String,
    location: GitLabLocation,
}

/// GitLab location information
#[derive(Debug, Clone, Serialize, Deserialize)]
struct GitLabLocation {
    path: String,
    lines: GitLabLines,
}

/// GitLab line information
#[derive(Debug, Clone, Serialize, Deserialize)]
struct GitLabLines {
    begin: u32,
}

/// Generate GitLab Code Quality JSON output from scan results
pub fn generate_gitlab(results: &ScanResults) -> String {
    let issues: Vec<GitLabIssue> = results
        .findings
        .iter()
        .map(|f| {
            GitLabIssue {
                description: format!(
                    "[{}] {}: {}",
                    f.rule_id, f.title, f.description
                ),
                check_name: f.rule_id.clone(),
                fingerprint: FindingFingerprint::from_finding(f),
                severity: map_severity(f.severity).to_string(),
                location: GitLabLocation {
                    // Use the component:identifier as path
                    path: format!("{}:{}", f.location.component, f.location.identifier),
                    lines: GitLabLines { begin: 1 },
                },
            }
        })
        .collect();

    serde_json::to_string_pretty(&issues).unwrap_or_else(|_| "[]".to_string())
}

/// Map mcplint severity to GitLab Code Quality severity
///
/// GitLab supports: info, minor, major, critical, blocker
fn map_severity(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "blocker",
        Severity::High => "critical",
        Severity::Medium => "major",
        Severity::Low => "minor",
        Severity::Info => "info",
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
            duration_ms: 1000,
        };

        results.add_finding(
            Finding::new(
                "MCP-INJ-001",
                Severity::Critical,
                "Command Injection",
                "Tool accepts shell commands",
            )
            .with_location(FindingLocation::tool("exec_command")),
        );

        results.add_finding(
            Finding::new(
                "MCP-AUTH-001",
                Severity::High,
                "Missing Authentication",
                "Server lacks authentication",
            )
            .with_location(FindingLocation::server()),
        );

        results
    }

    #[test]
    fn generates_valid_json() {
        let results = create_test_results();
        let json = generate_gitlab(&results);

        // Parse to verify it's valid JSON
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.len(), 2);
    }

    #[test]
    fn includes_required_fields() {
        let results = create_test_results();
        let json = generate_gitlab(&results);

        let parsed: Vec<GitLabIssue> = serde_json::from_str(&json).unwrap();
        let issue = &parsed[0];

        assert!(!issue.description.is_empty());
        assert!(!issue.check_name.is_empty());
        assert!(!issue.fingerprint.is_empty());
        assert!(!issue.severity.is_empty());
        assert!(!issue.location.path.is_empty());
    }

    #[test]
    fn maps_severity_correctly() {
        assert_eq!(map_severity(Severity::Critical), "blocker");
        assert_eq!(map_severity(Severity::High), "critical");
        assert_eq!(map_severity(Severity::Medium), "major");
        assert_eq!(map_severity(Severity::Low), "minor");
        assert_eq!(map_severity(Severity::Info), "info");
    }

    #[test]
    fn empty_results_returns_empty_array() {
        let results = ScanResults {
            server: "test-server".to_string(),
            profile: "standard".to_string(),
            total_checks: 10,
            findings: Vec::new(),
            summary: ScanSummary::default(),
            duration_ms: 100,
        };

        let json = generate_gitlab(&results);
        assert_eq!(json.trim(), "[]");
    }

    #[test]
    fn fingerprint_is_stable() {
        let results = create_test_results();
        let json1 = generate_gitlab(&results);
        let json2 = generate_gitlab(&results);

        let parsed1: Vec<GitLabIssue> = serde_json::from_str(&json1).unwrap();
        let parsed2: Vec<GitLabIssue> = serde_json::from_str(&json2).unwrap();

        assert_eq!(parsed1[0].fingerprint, parsed2[0].fingerprint);
    }
}
