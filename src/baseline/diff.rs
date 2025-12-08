//! Diff Engine - Compare baseline against current scan
//!
//! Provides diff capabilities for incremental vulnerability detection,
//! identifying new, fixed, and unchanged findings.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::scanner::{Finding, ScanResults, Severity};

use super::{Baseline, BaselineFinding, FindingFingerprint};

/// Engine for comparing baseline against current scan results
pub struct DiffEngine;

impl DiffEngine {
    /// Compare current scan results against baseline
    pub fn diff(baseline: &Baseline, current: &ScanResults) -> DiffResult {
        // Build set of baseline fingerprints
        let baseline_set: HashSet<_> = baseline
            .findings
            .iter()
            .map(|f| f.evidence_hash.as_str())
            .collect();

        // Compute fingerprints for current findings
        let current_fingerprints: Vec<_> = current
            .findings
            .iter()
            .map(|f| (FindingFingerprint::from_finding(f), f))
            .collect();

        let mut new_findings = Vec::new();
        let mut unchanged_count = 0;

        for (fingerprint, finding) in &current_fingerprints {
            if baseline_set.contains(fingerprint.as_str()) {
                unchanged_count += 1;
            } else {
                new_findings.push((*finding).clone());
            }
        }

        // Find fixed findings (in baseline but not in current)
        let current_set: HashSet<_> = current_fingerprints
            .iter()
            .map(|(fp, _)| fp.as_str())
            .collect();

        let fixed_findings: Vec<_> = baseline
            .findings
            .iter()
            .filter(|f| !current_set.contains(f.evidence_hash.as_str()))
            .cloned()
            .collect();

        // Compute severity counts for new findings
        let (new_critical, new_high) = new_findings.iter().fold((0, 0), |(crit, high), f| {
            match f.severity {
                Severity::Critical => (crit + 1, high),
                Severity::High => (crit, high + 1),
                _ => (crit, high),
            }
        });

        DiffResult {
            new_findings,
            fixed_findings,
            unchanged_count,
            summary: DiffSummary {
                total_baseline: baseline.findings.len(),
                total_current: current.findings.len(),
                new_count: current.findings.len() - unchanged_count,
                fixed_count: baseline.findings.len()
                    - baseline
                        .findings
                        .iter()
                        .filter(|f| current_set.contains(f.evidence_hash.as_str()))
                        .count(),
                unchanged_count,
                new_critical,
                new_high,
            },
        }
    }
}

/// Result of diffing baseline against current scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffResult {
    /// Newly introduced findings (not in baseline)
    pub new_findings: Vec<Finding>,
    /// Findings that were fixed (in baseline but not current)
    pub fixed_findings: Vec<BaselineFinding>,
    /// Count of findings unchanged from baseline
    pub unchanged_count: usize,
    /// Summary statistics
    pub summary: DiffSummary,
}

impl DiffResult {
    /// Check if there are any new critical or high severity findings
    pub fn has_new_critical_or_high(&self) -> bool {
        self.summary.new_critical > 0 || self.summary.new_high > 0
    }

    /// Check if there are any new findings at all
    #[allow(dead_code)] // Public API method
    pub fn has_new_findings(&self) -> bool {
        !self.new_findings.is_empty()
    }

    /// Get the count of new findings
    pub fn new_count(&self) -> usize {
        self.new_findings.len()
    }

    /// Get the count of fixed findings
    pub fn fixed_count(&self) -> usize {
        self.fixed_findings.len()
    }
}

/// Summary statistics for baseline diff
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffSummary {
    /// Total findings in baseline
    pub total_baseline: usize,
    /// Total findings in current scan
    pub total_current: usize,
    /// Number of new findings
    pub new_count: usize,
    /// Number of fixed findings
    pub fixed_count: usize,
    /// Number of unchanged findings
    pub unchanged_count: usize,
    /// New findings with Critical severity
    pub new_critical: usize,
    /// New findings with High severity
    pub new_high: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::{FindingLocation, ScanSummary};

    fn create_finding(rule_id: &str, tool: &str) -> Finding {
        Finding::new(rule_id, Severity::High, "Test Finding", "Description")
            .with_location(FindingLocation::tool(tool))
    }

    fn create_results(findings: Vec<Finding>) -> ScanResults {
        let mut results = ScanResults {
            server: "test-server".to_string(),
            profile: "standard".to_string(),
            total_checks: 10,
            findings: Vec::new(),
            summary: ScanSummary::default(),
            duration_ms: 1000,
        };

        for finding in findings {
            results.add_finding(finding);
        }

        results
    }

    #[test]
    fn diff_detects_new_findings() {
        let finding_a = create_finding("MCP-INJ-001", "tool_a");
        let finding_b = create_finding("MCP-INJ-002", "tool_b");

        let baseline_results = create_results(vec![finding_a.clone()]);
        let baseline = Baseline::from_results(&baseline_results);

        let current = create_results(vec![finding_a.clone(), finding_b.clone()]);

        let diff = DiffEngine::diff(&baseline, &current);

        assert_eq!(diff.new_findings.len(), 1);
        assert_eq!(diff.unchanged_count, 1);
        assert_eq!(diff.fixed_findings.len(), 0);
    }

    #[test]
    fn diff_detects_fixed_findings() {
        let finding_a = create_finding("MCP-INJ-001", "tool_a");
        let finding_b = create_finding("MCP-INJ-002", "tool_b");

        let baseline_results = create_results(vec![finding_a.clone(), finding_b.clone()]);
        let baseline = Baseline::from_results(&baseline_results);

        let current = create_results(vec![finding_a.clone()]);

        let diff = DiffEngine::diff(&baseline, &current);

        assert_eq!(diff.new_findings.len(), 0);
        assert_eq!(diff.unchanged_count, 1);
        assert_eq!(diff.fixed_findings.len(), 1);
    }

    #[test]
    fn diff_unchanged_findings() {
        let finding_a = create_finding("MCP-INJ-001", "tool_a");

        let baseline_results = create_results(vec![finding_a.clone()]);
        let baseline = Baseline::from_results(&baseline_results);

        let current = create_results(vec![finding_a.clone()]);

        let diff = DiffEngine::diff(&baseline, &current);

        assert_eq!(diff.new_findings.len(), 0);
        assert_eq!(diff.unchanged_count, 1);
        assert_eq!(diff.fixed_findings.len(), 0);
        assert!(!diff.has_new_findings());
    }

    #[test]
    fn diff_counts_critical_high() {
        let finding_crit =
            Finding::new("MCP-INJ-001", Severity::Critical, "Critical", "Desc")
                .with_location(FindingLocation::tool("tool_crit"));
        let finding_high = Finding::new("MCP-INJ-002", Severity::High, "High", "Desc")
            .with_location(FindingLocation::tool("tool_high"));
        let finding_med = Finding::new("MCP-INJ-003", Severity::Medium, "Medium", "Desc")
            .with_location(FindingLocation::tool("tool_med"));

        let baseline_results = create_results(vec![]);
        let baseline = Baseline::from_results(&baseline_results);

        let current =
            create_results(vec![finding_crit.clone(), finding_high.clone(), finding_med.clone()]);

        let diff = DiffEngine::diff(&baseline, &current);

        assert_eq!(diff.summary.new_critical, 1);
        assert_eq!(diff.summary.new_high, 1);
        assert!(diff.has_new_critical_or_high());
    }
}
