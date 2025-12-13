//! Baseline Store - Persistence for baseline data
//!
//! Provides storage and retrieval of baseline data for incremental
//! vulnerability detection in CI/CD workflows.

use std::fs;
use std::path::Path;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::fingerprinting::ToolFingerprint;
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
    /// Tool definition fingerprints for schema change detection
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_fingerprints: Option<Vec<ToolFingerprint>>,
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
            tool_fingerprints: None,
        }
    }

    /// Create a new baseline from scan results with tool fingerprints
    #[allow(dead_code)]
    pub fn from_results_with_fingerprints(
        results: &ScanResults,
        fingerprints: Vec<ToolFingerprint>,
    ) -> Self {
        let mut baseline = Self::from_results(results);
        baseline.tool_fingerprints = Some(fingerprints);
        baseline
    }

    /// Add tool fingerprints to an existing baseline
    #[allow(dead_code)]
    pub fn with_fingerprints(mut self, fingerprints: Vec<ToolFingerprint>) -> Self {
        self.tool_fingerprints = Some(fingerprints);
        self
    }

    /// Set tool fingerprints
    #[allow(dead_code)]
    pub fn set_fingerprints(&mut self, fingerprints: Vec<ToolFingerprint>) {
        self.tool_fingerprints = Some(fingerprints);
    }

    /// Check if baseline has tool fingerprints
    #[allow(dead_code)]
    pub fn has_fingerprints(&self) -> bool {
        self.tool_fingerprints
            .as_ref()
            .is_some_and(|f| !f.is_empty())
    }

    /// Get the number of fingerprints
    #[allow(dead_code)]
    pub fn fingerprint_count(&self) -> usize {
        self.tool_fingerprints
            .as_ref()
            .map(|f| f.len())
            .unwrap_or(0)
    }

    /// Get a specific tool's fingerprint by name
    #[allow(dead_code)]
    pub fn get_fingerprint(&self, tool_name: &str) -> Option<&ToolFingerprint> {
        self.tool_fingerprints
            .as_ref()
            .and_then(|fps| fps.iter().find(|fp| fp.tool_name == tool_name))
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

    #[test]
    fn test_empty_baseline() {
        let results = ScanResults {
            server: "empty-server".to_string(),
            profile: "standard".to_string(),
            total_checks: 0,
            findings: Vec::new(),
            summary: ScanSummary::default(),
            duration_ms: 100,
        };

        let baseline = Baseline::from_results(&results);
        assert_eq!(baseline.findings.len(), 0);
        assert_eq!(baseline.server_id, "empty-server");
        assert_eq!(baseline.version, Baseline::VERSION);
    }

    #[test]
    fn test_severity_counts_all_types() {
        let mut results = ScanResults {
            server: "test-server".to_string(),
            profile: "standard".to_string(),
            total_checks: 10,
            findings: Vec::new(),
            summary: ScanSummary::default(),
            duration_ms: 1000,
        };

        // Add one of each severity
        results.add_finding(
            Finding::new("CRIT-1", Severity::Critical, "Critical", "Desc")
                .with_location(FindingLocation::tool("t1")),
        );
        results.add_finding(
            Finding::new("HIGH-1", Severity::High, "High", "Desc")
                .with_location(FindingLocation::tool("t2")),
        );
        results.add_finding(
            Finding::new("MED-1", Severity::Medium, "Medium", "Desc")
                .with_location(FindingLocation::tool("t3")),
        );
        results.add_finding(
            Finding::new("LOW-1", Severity::Low, "Low", "Desc")
                .with_location(FindingLocation::tool("t4")),
        );
        results.add_finding(
            Finding::new("INFO-1", Severity::Info, "Info", "Desc")
                .with_location(FindingLocation::tool("t5")),
        );

        let baseline = Baseline::from_results(&results);
        let counts = baseline.severity_counts();

        assert_eq!(counts.critical, 1);
        assert_eq!(counts.high, 1);
        assert_eq!(counts.medium, 1);
        assert_eq!(counts.low, 1);
        assert_eq!(counts.info, 1);
    }

    #[test]
    fn test_baseline_with_fingerprints() {
        use crate::fingerprinting::ToolFingerprint;

        let results = create_test_results();
        let fp1 = ToolFingerprint::new("tool1", "semantic_hash1", "full_hash1");
        let fp2 = ToolFingerprint::new("tool2", "semantic_hash2", "full_hash2");

        let baseline = Baseline::from_results_with_fingerprints(&results, vec![fp1, fp2]);

        assert!(baseline.has_fingerprints());
        assert_eq!(baseline.fingerprint_count(), 2);
        assert!(baseline.get_fingerprint("tool1").is_some());
        assert!(baseline.get_fingerprint("tool2").is_some());
        assert!(baseline.get_fingerprint("tool3").is_none());
    }

    #[test]
    fn test_baseline_set_fingerprints() {
        use crate::fingerprinting::ToolFingerprint;

        let results = create_test_results();
        let mut baseline = Baseline::from_results(&results);

        assert!(!baseline.has_fingerprints());
        assert_eq!(baseline.fingerprint_count(), 0);

        let fp = ToolFingerprint::new("tool1", "hash1", "hash2");
        baseline.set_fingerprints(vec![fp]);

        assert!(baseline.has_fingerprints());
        assert_eq!(baseline.fingerprint_count(), 1);
    }

    #[test]
    fn test_baseline_with_fingerprints_builder() {
        use crate::fingerprinting::ToolFingerprint;

        let results = create_test_results();
        let fp = ToolFingerprint::new("tool1", "hash1", "hash2");

        let baseline = Baseline::from_results(&results).with_fingerprints(vec![fp]);

        assert!(baseline.has_fingerprints());
        assert_eq!(baseline.fingerprint_count(), 1);
    }

    #[test]
    fn test_baseline_empty_fingerprints() {
        let results = create_test_results();
        let baseline = Baseline::from_results(&results).with_fingerprints(vec![]);

        assert!(!baseline.has_fingerprints());
        assert_eq!(baseline.fingerprint_count(), 0);
    }

    #[test]
    fn test_baseline_get_specific_fingerprint() {
        use crate::fingerprinting::ToolFingerprint;

        let results = create_test_results();
        let fp1 = ToolFingerprint::new("alpha", "hash_a", "hash_full_a");
        let fp2 = ToolFingerprint::new("beta", "hash_b", "hash_full_b");

        let baseline = Baseline::from_results(&results).with_fingerprints(vec![fp1, fp2]);

        let alpha_fp = baseline.get_fingerprint("alpha");
        assert!(alpha_fp.is_some());
        assert_eq!(alpha_fp.unwrap().tool_name, "alpha");

        let beta_fp = baseline.get_fingerprint("beta");
        assert!(beta_fp.is_some());
        assert_eq!(beta_fp.unwrap().tool_name, "beta");

        let missing_fp = baseline.get_fingerprint("gamma");
        assert!(missing_fp.is_none());
    }

    #[test]
    fn test_baseline_serialization_roundtrip() {
        let results = create_test_results();
        let baseline = Baseline::from_results(&results);

        let json = serde_json::to_string(&baseline).unwrap();
        let deserialized: Baseline = serde_json::from_str(&json).unwrap();

        assert_eq!(baseline.version, deserialized.version);
        assert_eq!(baseline.server_id, deserialized.server_id);
        assert_eq!(baseline.findings.len(), deserialized.findings.len());
        assert_eq!(
            baseline.config.profile.as_ref().unwrap(),
            deserialized.config.profile.as_ref().unwrap()
        );
    }

    #[test]
    fn test_baseline_serialization_with_fingerprints() {
        use crate::fingerprinting::ToolFingerprint;

        let results = create_test_results();
        let fp = ToolFingerprint::new("tool1", "semantic", "full");
        let baseline = Baseline::from_results(&results).with_fingerprints(vec![fp]);

        let json = serde_json::to_string(&baseline).unwrap();
        let deserialized: Baseline = serde_json::from_str(&json).unwrap();

        assert!(deserialized.has_fingerprints());
        assert_eq!(deserialized.fingerprint_count(), 1);
    }

    #[test]
    fn test_baseline_version_check() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("baseline.json");

        // Create a baseline with an incompatible version
        let content = r#"{
            "version": "2.0",
            "created_at": "2025-01-01T00:00:00Z",
            "server_id": "test",
            "findings": [],
            "config": {
                "profile": "standard",
                "include_categories": [],
                "exclude_categories": []
            }
        }"#;
        fs::write(&path, content).unwrap();

        let result = Baseline::load(&path);
        assert!(result.is_err());
        match result {
            Err(BaselineError::VersionMismatch { expected, found }) => {
                assert_eq!(expected, Baseline::VERSION);
                assert_eq!(found, "2.0");
            }
            _ => panic!("Expected VersionMismatch error"),
        }
    }

    #[test]
    fn test_baseline_load_invalid_json() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("invalid.json");
        fs::write(&path, "{ invalid json }").unwrap();

        let result = Baseline::load(&path);
        assert!(result.is_err());
        assert!(matches!(result, Err(BaselineError::ParseError { .. })));
    }

    #[test]
    fn test_baseline_load_nonexistent_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("nonexistent.json");

        let result = Baseline::load(&path);
        assert!(result.is_err());
        assert!(matches!(result, Err(BaselineError::IoError { .. })));
    }

    #[test]
    fn test_baseline_finding_equality() {
        let finding1 = BaselineFinding {
            rule_id: "MCP-INJ-001".to_string(),
            location_fingerprint: "tool:test_tool".to_string(),
            evidence_hash: "hash123".to_string(),
            severity: Severity::Critical,
        };

        let finding2 = BaselineFinding {
            rule_id: "MCP-INJ-001".to_string(),
            location_fingerprint: "tool:test_tool".to_string(),
            evidence_hash: "hash123".to_string(),
            severity: Severity::Critical,
        };

        let finding3 = BaselineFinding {
            rule_id: "MCP-INJ-002".to_string(),
            location_fingerprint: "tool:test_tool".to_string(),
            evidence_hash: "hash123".to_string(),
            severity: Severity::Critical,
        };

        assert_eq!(finding1, finding2);
        assert_ne!(finding1, finding3);
    }

    #[test]
    fn test_baseline_config_default() {
        let config = BaselineConfig::default();
        assert!(config.profile.is_none());
        assert!(config.include_categories.is_empty());
        assert!(config.exclude_categories.is_empty());
    }

    #[test]
    fn test_baseline_location_fingerprint_format() {
        let results = create_test_results();
        let baseline = Baseline::from_results(&results);

        // Check that location fingerprints have the correct format
        for finding in &baseline.findings {
            assert!(finding.location_fingerprint.contains(':'));
            let parts: Vec<&str> = finding.location_fingerprint.split(':').collect();
            assert_eq!(parts.len(), 2);
        }
    }

    #[test]
    fn test_severity_counts_empty() {
        let results = ScanResults {
            server: "test-server".to_string(),
            profile: "standard".to_string(),
            total_checks: 0,
            findings: Vec::new(),
            summary: ScanSummary::default(),
            duration_ms: 100,
        };

        let baseline = Baseline::from_results(&results);
        let counts = baseline.severity_counts();

        assert_eq!(counts.critical, 0);
        assert_eq!(counts.high, 0);
        assert_eq!(counts.medium, 0);
        assert_eq!(counts.low, 0);
        assert_eq!(counts.info, 0);
    }

    #[test]
    fn test_baseline_preserves_profile() {
        let results = ScanResults {
            server: "test-server".to_string(),
            profile: "custom-profile".to_string(),
            total_checks: 0,
            findings: Vec::new(),
            summary: ScanSummary::default(),
            duration_ms: 100,
        };

        let baseline = Baseline::from_results(&results);
        assert_eq!(baseline.config.profile, Some("custom-profile".to_string()));
    }

    #[test]
    fn test_baseline_finding_serialization() {
        let finding = BaselineFinding {
            rule_id: "MCP-INJ-001".to_string(),
            location_fingerprint: "tool:test_tool".to_string(),
            evidence_hash: "hash123".to_string(),
            severity: Severity::High,
        };

        let json = serde_json::to_string(&finding).unwrap();
        let deserialized: BaselineFinding = serde_json::from_str(&json).unwrap();

        assert_eq!(finding, deserialized);
    }

    #[test]
    fn test_baseline_config_serialization() {
        let config = BaselineConfig {
            profile: Some("standard".to_string()),
            include_categories: vec!["security".to_string()],
            exclude_categories: vec!["performance".to_string()],
        };

        let json = serde_json::to_string(&config).unwrap();
        let deserialized: BaselineConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(config.profile, deserialized.profile);
        assert_eq!(config.include_categories, deserialized.include_categories);
        assert_eq!(config.exclude_categories, deserialized.exclude_categories);
    }

    #[test]
    fn test_baseline_multiple_findings_same_severity() {
        let mut results = ScanResults {
            server: "test-server".to_string(),
            profile: "standard".to_string(),
            total_checks: 10,
            findings: Vec::new(),
            summary: ScanSummary::default(),
            duration_ms: 1000,
        };

        // Add multiple critical findings
        for i in 0..3 {
            results.add_finding(
                Finding::new(
                    format!("CRIT-{}", i),
                    Severity::Critical,
                    "Critical Finding",
                    "Description",
                )
                .with_location(FindingLocation::tool(format!("tool{}", i))),
            );
        }

        let baseline = Baseline::from_results(&results);
        let counts = baseline.severity_counts();

        assert_eq!(counts.critical, 3);
        assert_eq!(counts.high, 0);
    }

    #[test]
    fn test_baseline_version_compatibility_1_1() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("baseline.json");

        // Create a baseline with version 1.1 (should be compatible)
        let content = r#"{
            "version": "1.1",
            "created_at": "2025-01-01T00:00:00Z",
            "server_id": "test",
            "findings": [],
            "config": {
                "profile": "standard",
                "include_categories": [],
                "exclude_categories": []
            }
        }"#;
        fs::write(&path, content).unwrap();

        let result = Baseline::load(&path);
        assert!(result.is_ok());
        let baseline = result.unwrap();
        assert_eq!(baseline.version, "1.1");
    }

    #[test]
    fn test_baseline_fingerprints_optional_serialization() {
        let results = create_test_results();
        let baseline = Baseline::from_results(&results);

        let json = serde_json::to_string(&baseline).unwrap();
        // Verify that tool_fingerprints is not included when None
        assert!(!json.contains("tool_fingerprints"));
    }
}
