//! Baseline Store - Persistence for baseline data
//!
//! Provides storage and retrieval of baseline data for incremental
//! vulnerability detection in CI/CD workflows.

use std::fs;
use std::path::Path;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::scanner::{ScanResults, Severity};

use super::FindingFingerprint;

/// Baseline storage format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Baseline {
    /// Version for forward compatibility
    pub version: String,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Server identifier (name or path hash)
    pub server_id: String,
    /// Fingerprinted findings
    pub findings: Vec<BaselineFinding>,
    /// Scan configuration used
    pub config: BaselineConfig,
}

impl Baseline {
    /// Current baseline format version
    pub const VERSION: &'static str = "1.0";

    /// Create a new baseline from scan results
    pub fn from_results(results: &ScanResults) -> Self {
        let findings = results
            .findings
            .iter()
            .map(|f| BaselineFinding {
                rule_id: f.rule_id.clone(),
                location_fingerprint: format!("{}:{}", f.location.component, f.location.identifier),
                evidence_hash: FindingFingerprint::from_finding(f),
                severity: f.severity,
            })
            .collect();

        Self {
            version: Self::VERSION.to_string(),
            created_at: Utc::now(),
            server_id: results.server.clone(),
            findings,
            config: BaselineConfig {
                profile: Some(results.profile.clone()),
                ..Default::default()
            },
        }
    }

    /// Load baseline from a JSON file
    pub fn load(path: impl AsRef<Path>) -> Result<Self, BaselineError> {
        let content = fs::read_to_string(path.as_ref()).map_err(|e| BaselineError::IoError {
            path: path.as_ref().display().to_string(),
            source: e,
        })?;

        let baseline: Self =
            serde_json::from_str(&content).map_err(|e| BaselineError::ParseError {
                path: path.as_ref().display().to_string(),
                source: e,
            })?;

        // Version compatibility check
        if !baseline.version.starts_with("1.") {
            return Err(BaselineError::VersionMismatch {
                expected: Self::VERSION.to_string(),
                found: baseline.version,
            });
        }

        Ok(baseline)
    }

    /// Save baseline to a JSON file
    pub fn save(&self, path: impl AsRef<Path>) -> Result<(), BaselineError> {
        let content = serde_json::to_string_pretty(self)
            .map_err(|e| BaselineError::SerializeError { source: e })?;

        fs::write(path.as_ref(), content).map_err(|e| BaselineError::IoError {
            path: path.as_ref().display().to_string(),
            source: e,
        })?;

        Ok(())
    }

    /// Get the number of findings by severity
    #[allow(dead_code)] // Public API method
    pub fn severity_counts(&self) -> SeverityCounts {
        let mut counts = SeverityCounts::default();
        for finding in &self.findings {
            match finding.severity {
                Severity::Critical => counts.critical += 1,
                Severity::High => counts.high += 1,
                Severity::Medium => counts.medium += 1,
                Severity::Low => counts.low += 1,
                Severity::Info => counts.info += 1,
            }
        }
        counts
    }
}

/// Fingerprinted finding for stable comparison
#[derive(Debug, Clone, Serialize, Deserialize, Hash, Eq, PartialEq)]
pub struct BaselineFinding {
    /// Rule ID (e.g., "MCP-INJ-001")
    pub rule_id: String,
    /// Location fingerprint (component:identifier)
    pub location_fingerprint: String,
    /// Evidence hash for deduplication
    pub evidence_hash: String,
    /// Severity at time of baseline
    pub severity: Severity,
}

/// Configuration stored with baseline
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BaselineConfig {
    /// Scan profile used
    pub profile: Option<String>,
    /// Categories included
    pub include_categories: Vec<String>,
    /// Categories excluded
    pub exclude_categories: Vec<String>,
}

/// Severity counts for summary
#[derive(Debug, Clone, Default)]
#[allow(dead_code)] // Public API struct
pub struct SeverityCounts {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

/// Errors that can occur with baseline operations
#[derive(Debug, thiserror::Error)]
pub enum BaselineError {
    #[error("Failed to read baseline file '{path}': {source}")]
    IoError {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("Failed to parse baseline file '{path}': {source}")]
    ParseError {
        path: String,
        #[source]
        source: serde_json::Error,
    },

    #[error("Failed to serialize baseline: {source}")]
    SerializeError {
        #[source]
        source: serde_json::Error,
    },

    #[error("Baseline version mismatch: expected {expected}, found {found}")]
    VersionMismatch { expected: String, found: String },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::{Finding, FindingLocation, ScanSummary};
    use tempfile::tempdir;

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
                "Critical Finding",
                "Description",
            )
            .with_location(FindingLocation::tool("tool1")),
        );
        results.add_finding(
            Finding::new(
                "MCP-AUTH-001",
                Severity::High,
                "High Finding",
                "Description",
            )
            .with_location(FindingLocation::tool("tool2")),
        );

        results
    }

    #[test]
    fn baseline_from_results() {
        let results = create_test_results();
        let baseline = Baseline::from_results(&results);

        assert_eq!(baseline.version, Baseline::VERSION);
        assert_eq!(baseline.findings.len(), 2);
        assert_eq!(baseline.server_id, "test-server");
    }

    #[test]
    fn baseline_save_and_load() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("baseline.json");

        let results = create_test_results();
        let baseline = Baseline::from_results(&results);

        // Save
        baseline.save(&path).unwrap();
        assert!(path.exists());

        // Load
        let loaded = Baseline::load(&path).unwrap();
        assert_eq!(loaded.findings.len(), baseline.findings.len());
        assert_eq!(loaded.server_id, baseline.server_id);
    }

    #[test]
    fn severity_counts() {
        let results = create_test_results();
        let baseline = Baseline::from_results(&results);
        let counts = baseline.severity_counts();

        assert_eq!(counts.critical, 1);
        assert_eq!(counts.high, 1);
        assert_eq!(counts.medium, 0);
    }
}
