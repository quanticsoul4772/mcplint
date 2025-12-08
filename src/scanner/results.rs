//! Scan Results - Data structures for scan output
//!
//! Contains the results and summary types returned from security scans.
//! These types are prepared for future migration from engine.rs.

#![allow(dead_code)] // Prepared for future migration

use super::finding::{Finding, Severity};
use super::context::ScanProfile;

/// Results from a security scan
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ScanResults {
    /// Server that was scanned
    pub server: String,
    /// Profile used for scanning
    pub profile: String,
    /// Total checks performed
    pub total_checks: usize,
    /// Findings from the scan
    pub findings: Vec<Finding>,
    /// Summary of findings by severity
    pub summary: ScanSummary,
    /// Total scan duration in milliseconds
    pub duration_ms: u64,
}

/// Summary of scan findings by severity
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ScanSummary {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

impl ScanResults {
    pub fn new(server: &str, profile: ScanProfile) -> Self {
        Self {
            server: server.to_string(),
            profile: profile.to_string(),
            total_checks: 0,
            findings: Vec::new(),
            summary: ScanSummary::default(),
            duration_ms: 0,
        }
    }

    pub fn add_finding(&mut self, finding: Finding) {
        match finding.severity {
            Severity::Critical => self.summary.critical += 1,
            Severity::High => self.summary.high += 1,
            Severity::Medium => self.summary.medium += 1,
            Severity::Low => self.summary.low += 1,
            Severity::Info => self.summary.info += 1,
        }
        self.findings.push(finding);
    }

    pub fn has_critical_or_high(&self) -> bool {
        self.summary.critical > 0 || self.summary.high > 0
    }

    pub fn total_findings(&self) -> usize {
        self.findings.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_results_counting() {
        let mut results = ScanResults::new("test", ScanProfile::Standard);

        results.add_finding(Finding::new("TEST-001", Severity::Critical, "Test", "Test"));
        results.add_finding(Finding::new("TEST-002", Severity::High, "Test", "Test"));
        results.add_finding(Finding::new("TEST-003", Severity::Medium, "Test", "Test"));

        assert_eq!(results.summary.critical, 1);
        assert_eq!(results.summary.high, 1);
        assert_eq!(results.summary.medium, 1);
        assert!(results.has_critical_or_high());
        assert_eq!(results.total_findings(), 3);
    }
}
