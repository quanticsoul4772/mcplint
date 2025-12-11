//! Fingerprinting Data Types
//!
//! Core data structures for tool definition fingerprinting.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Complete fingerprint for a tool definition
///
/// Contains both semantic and full content hashes for flexible comparison
/// and audit trail capabilities.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolFingerprint {
    /// Tool name from the definition
    pub tool_name: String,

    /// Semantic fingerprint for comparison
    ///
    /// SHA-256 hash of normalized semantic properties (types, constraints,
    /// required fields). Ignores non-semantic changes like whitespace or
    /// property ordering.
    pub semantic_hash: String,

    /// Full content fingerprint for audit trail
    ///
    /// SHA-256 hash of complete normalized schema including all metadata.
    /// Useful for detecting any changes, including descriptions and examples.
    pub full_hash: String,

    /// Schema version from tool definition (if specified)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema_version: Option<String>,

    /// Timestamp of fingerprint generation
    pub created_at: DateTime<Utc>,

    /// MCPLint version that generated this fingerprint
    pub mcplint_version: String,

    /// Metadata for debugging and analysis
    #[serde(default)]
    pub metadata: FingerprintMetadata,
}

impl ToolFingerprint {
    /// Create a new fingerprint with the current timestamp
    pub fn new(
        tool_name: impl Into<String>,
        semantic_hash: impl Into<String>,
        full_hash: impl Into<String>,
    ) -> Self {
        Self {
            tool_name: tool_name.into(),
            semantic_hash: semantic_hash.into(),
            full_hash: full_hash.into(),
            schema_version: None,
            created_at: Utc::now(),
            mcplint_version: env!("CARGO_PKG_VERSION").to_string(),
            metadata: FingerprintMetadata::default(),
        }
    }

    /// Set the schema version
    pub fn with_schema_version(mut self, version: impl Into<String>) -> Self {
        self.schema_version = Some(version.into());
        self
    }

    /// Set the metadata
    pub fn with_metadata(mut self, metadata: FingerprintMetadata) -> Self {
        self.metadata = metadata;
        self
    }

    /// Check if semantic hash matches another fingerprint
    #[allow(dead_code)]
    pub fn semantic_matches(&self, other: &Self) -> bool {
        self.semantic_hash == other.semantic_hash
    }

    /// Check if full hash matches another fingerprint
    #[allow(dead_code)]
    pub fn full_matches(&self, other: &Self) -> bool {
        self.full_hash == other.full_hash
    }

    /// Get a short hash (first 16 characters) for display
    #[allow(dead_code)]
    pub fn short_semantic_hash(&self) -> &str {
        &self.semantic_hash[..16.min(self.semantic_hash.len())]
    }

    /// Get a short full hash (first 16 characters) for display
    #[allow(dead_code)]
    pub fn short_full_hash(&self) -> &str {
        &self.full_hash[..16.min(self.full_hash.len())]
    }
}

/// Metadata about the fingerprinted schema
///
/// Provides debugging information and quick insights about the tool's schema
/// without requiring full schema analysis.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct FingerprintMetadata {
    /// Number of parameters in the input schema
    pub parameter_count: usize,

    /// Names of required parameters (sorted)
    pub required_params: Vec<String>,

    /// Top-level parameter types (name -> canonical type)
    pub param_types: HashMap<String, String>,

    /// Schema complexity score (for performance hints)
    ///
    /// Calculated based on:
    /// - Number of properties
    /// - Nesting depth
    /// - Number of constraints
    pub complexity_score: u32,
}

impl FingerprintMetadata {
    /// Create new metadata
    pub fn new(
        parameter_count: usize,
        required_params: Vec<String>,
        param_types: HashMap<String, String>,
        complexity_score: u32,
    ) -> Self {
        Self {
            parameter_count,
            required_params,
            param_types,
            complexity_score,
        }
    }

    /// Check if a parameter is required
    #[allow(dead_code)]
    pub fn is_required(&self, param: &str) -> bool {
        self.required_params.iter().any(|p| p == param)
    }

    /// Get the type of a parameter
    #[allow(dead_code)]
    pub fn get_param_type(&self, param: &str) -> Option<&str> {
        self.param_types.get(param).map(|s| s.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fingerprint_creation() {
        let fp = ToolFingerprint::new("test_tool", "semantic123", "full456");

        assert_eq!(fp.tool_name, "test_tool");
        assert_eq!(fp.semantic_hash, "semantic123");
        assert_eq!(fp.full_hash, "full456");
        assert!(fp.schema_version.is_none());
        assert_eq!(fp.mcplint_version, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn test_fingerprint_with_version() {
        let fp = ToolFingerprint::new("test_tool", "semantic123", "full456")
            .with_schema_version("1.0.0");

        assert_eq!(fp.schema_version, Some("1.0.0".to_string()));
    }

    #[test]
    fn test_fingerprint_matching() {
        let fp1 = ToolFingerprint::new("tool", "semantic_same", "full_same");
        let fp2 = ToolFingerprint::new("tool", "semantic_same", "full_diff");
        let fp3 = ToolFingerprint::new("tool", "semantic_diff", "full_same");

        assert!(fp1.semantic_matches(&fp2));
        assert!(!fp1.semantic_matches(&fp3));
        assert!(fp1.full_matches(&fp3));
        assert!(!fp1.full_matches(&fp2));
    }

    #[test]
    fn test_short_hash() {
        let fp = ToolFingerprint::new("tool", "a1b2c3d4e5f6g7h8i9j0", "z9y8x7w6v5u4t3s2r1q0");

        assert_eq!(fp.short_semantic_hash(), "a1b2c3d4e5f6g7h8");
        assert_eq!(fp.short_full_hash(), "z9y8x7w6v5u4t3s2");
    }

    #[test]
    fn test_metadata() {
        let mut types = HashMap::new();
        types.insert("name".to_string(), "string".to_string());
        types.insert("count".to_string(), "integer".to_string());

        let metadata = FingerprintMetadata::new(2, vec!["name".to_string()], types, 10);

        assert_eq!(metadata.parameter_count, 2);
        assert!(metadata.is_required("name"));
        assert!(!metadata.is_required("count"));
        assert_eq!(metadata.get_param_type("name"), Some("string"));
        assert_eq!(metadata.get_param_type("count"), Some("integer"));
        assert_eq!(metadata.get_param_type("missing"), None);
    }

    #[test]
    fn test_fingerprint_serialization() {
        let fp = ToolFingerprint::new("test_tool", "semantic123", "full456")
            .with_schema_version("1.0.0");

        let json = serde_json::to_string(&fp).unwrap();
        let deserialized: ToolFingerprint = serde_json::from_str(&json).unwrap();

        assert_eq!(fp.tool_name, deserialized.tool_name);
        assert_eq!(fp.semantic_hash, deserialized.semantic_hash);
        assert_eq!(fp.full_hash, deserialized.full_hash);
        assert_eq!(fp.schema_version, deserialized.schema_version);
    }
}
