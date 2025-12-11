//! Fingerprint Hasher
//!
//! Generates SHA-256 hashes from normalized schemas for tool fingerprinting.

use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::protocol::mcp::Tool;

use super::normalizer::{SchemaMetadata, SchemaNormalizer};
use super::types::{FingerprintMetadata, ToolFingerprint};

/// Errors that can occur during fingerprint generation
#[derive(Debug, Error)]
#[allow(dead_code)] // Public API error variants for future use
pub enum FingerprintError {
    #[error("Tool has no input schema")]
    MissingInputSchema,

    #[error("Failed to normalize schema: {0}")]
    NormalizationError(String),

    #[error("Schema is invalid: {0}")]
    InvalidSchema(String),
}

/// Generates fingerprints from tool definitions
pub struct FingerprintHasher;

impl FingerprintHasher {
    /// Generate a complete fingerprint for a tool
    ///
    /// Creates both semantic and full hashes for the tool's input schema.
    pub fn fingerprint(tool: &Tool) -> Result<ToolFingerprint, FingerprintError> {
        let schema = &tool.input_schema;

        // Validate schema is an object
        if !schema.is_object() && !schema.is_null() {
            return Err(FingerprintError::InvalidSchema(
                "Input schema must be an object".to_string(),
            ));
        }

        // Generate semantic hash (for comparison)
        let semantic_normalized = SchemaNormalizer::normalize_semantic(schema);
        let semantic_hash = Self::hash_string(&semantic_normalized.canonical_json);

        // Generate full hash (for audit trail)
        let full_normalized = SchemaNormalizer::normalize_full(schema);
        let full_hash = Self::hash_string(&full_normalized.canonical_json);

        // Build metadata from normalization results
        let metadata = Self::build_metadata(&semantic_normalized.metadata);

        // Create fingerprint
        let mut fingerprint = ToolFingerprint::new(tool.name.clone(), semantic_hash, full_hash)
            .with_metadata(metadata);

        // Extract schema version if present
        if let Some(version) = schema
            .get("$schema")
            .or_else(|| schema.get("version"))
            .and_then(|v| v.as_str())
        {
            fingerprint = fingerprint.with_schema_version(version);
        }

        Ok(fingerprint)
    }

    /// Generate a semantic hash from a normalized schema
    #[allow(dead_code)]
    pub fn semantic_hash(schema: &serde_json::Value) -> String {
        let normalized = SchemaNormalizer::normalize_semantic(schema);
        Self::hash_string(&normalized.canonical_json)
    }

    /// Generate a full hash from a normalized schema
    #[allow(dead_code)]
    pub fn full_hash(schema: &serde_json::Value) -> String {
        let normalized = SchemaNormalizer::normalize_full(schema);
        Self::hash_string(&normalized.canonical_json)
    }

    /// Generate a SHA-256 hash of a string
    ///
    /// Returns a 64-character hex string.
    pub fn hash_string(input: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(input.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    /// Generate a short hash (first 16 chars) of a string
    #[allow(dead_code)]
    pub fn short_hash(input: &str) -> String {
        let full = Self::hash_string(input);
        full[..16].to_string()
    }

    /// Generate fingerprints for multiple tools
    ///
    /// Returns a vector of results, one for each tool.
    #[allow(dead_code)]
    pub fn fingerprint_all(tools: &[Tool]) -> Vec<Result<ToolFingerprint, FingerprintError>> {
        tools.iter().map(Self::fingerprint).collect()
    }

    /// Generate fingerprints for multiple tools, skipping errors
    ///
    /// Returns only successful fingerprints.
    #[allow(dead_code)]
    pub fn fingerprint_all_ok(tools: &[Tool]) -> Vec<ToolFingerprint> {
        tools
            .iter()
            .filter_map(|t| Self::fingerprint(t).ok())
            .collect()
    }

    /// Build fingerprint metadata from schema metadata
    fn build_metadata(schema_meta: &SchemaMetadata) -> FingerprintMetadata {
        FingerprintMetadata::new(
            schema_meta.property_count,
            schema_meta.required.clone(),
            schema_meta.property_types.clone(),
            schema_meta.complexity,
        )
    }

    /// Create a combined hash of tool name and schema
    ///
    /// Useful for unique identification when tool name matters.
    #[allow(dead_code)]
    pub fn combined_hash(tool: &Tool) -> String {
        let normalized_name = SchemaNormalizer::normalize_tool_name(&tool.name);
        let schema_normalized = SchemaNormalizer::normalize_semantic(&tool.input_schema);

        let combined = format!("{}:{}", normalized_name, schema_normalized.canonical_json);
        Self::hash_string(&combined)
    }

    /// Hash a tool's description (normalized)
    #[allow(dead_code)]
    pub fn description_hash(tool: &Tool) -> Option<String> {
        tool.description.as_ref().map(|desc| {
            let normalized = SchemaNormalizer::normalize_description(desc);
            Self::hash_string(&normalized)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn create_test_tool(name: &str, schema: serde_json::Value) -> Tool {
        Tool {
            name: name.to_string(),
            description: Some("A test tool".to_string()),
            input_schema: schema,
        }
    }

    #[test]
    fn test_fingerprint_basic() {
        let tool = create_test_tool(
            "test_tool",
            json!({
                "type": "object",
                "properties": {
                    "query": { "type": "string" }
                },
                "required": ["query"]
            }),
        );

        let fp = FingerprintHasher::fingerprint(&tool).unwrap();

        assert_eq!(fp.tool_name, "test_tool");
        assert_eq!(fp.semantic_hash.len(), 64);
        assert_eq!(fp.full_hash.len(), 64);
        assert_eq!(fp.metadata.parameter_count, 1);
        assert!(fp.metadata.required_params.contains(&"query".to_string()));
    }

    #[test]
    fn test_fingerprint_determinism() {
        let tool = create_test_tool(
            "test_tool",
            json!({
                "type": "object",
                "properties": {
                    "a": { "type": "string" },
                    "b": { "type": "number" }
                }
            }),
        );

        // Generate fingerprints multiple times
        let fingerprints: Vec<_> = (0..100)
            .map(|_| FingerprintHasher::fingerprint(&tool).unwrap())
            .collect();

        // All semantic hashes should be identical
        let first_semantic = &fingerprints[0].semantic_hash;
        assert!(fingerprints
            .iter()
            .all(|fp| &fp.semantic_hash == first_semantic));

        // All full hashes should be identical
        let first_full = &fingerprints[0].full_hash;
        assert!(fingerprints.iter().all(|fp| &fp.full_hash == first_full));
    }

    #[test]
    fn test_fingerprint_ordering_independence() {
        let tool1 = create_test_tool(
            "tool",
            json!({
                "type": "object",
                "properties": {
                    "a": { "type": "string" },
                    "b": { "type": "number" },
                    "c": { "type": "boolean" }
                }
            }),
        );

        let tool2 = create_test_tool(
            "tool",
            json!({
                "type": "object",
                "properties": {
                    "c": { "type": "boolean" },
                    "a": { "type": "string" },
                    "b": { "type": "number" }
                }
            }),
        );

        let fp1 = FingerprintHasher::fingerprint(&tool1).unwrap();
        let fp2 = FingerprintHasher::fingerprint(&tool2).unwrap();

        assert_eq!(fp1.semantic_hash, fp2.semantic_hash);
    }

    #[test]
    fn test_semantic_ignores_description_changes() {
        let tool1 = create_test_tool(
            "tool",
            json!({
                "type": "object",
                "description": "Original description",
                "properties": {
                    "query": { "type": "string" }
                }
            }),
        );

        let tool2 = create_test_tool(
            "tool",
            json!({
                "type": "object",
                "description": "Different description",
                "properties": {
                    "query": { "type": "string" }
                }
            }),
        );

        let fp1 = FingerprintHasher::fingerprint(&tool1).unwrap();
        let fp2 = FingerprintHasher::fingerprint(&tool2).unwrap();

        // Semantic hashes should match (description ignored)
        assert_eq!(fp1.semantic_hash, fp2.semantic_hash);

        // Full hashes should differ (description included)
        assert_ne!(fp1.full_hash, fp2.full_hash);
    }

    #[test]
    fn test_full_hash_normalizes_description() {
        let tool1 = create_test_tool(
            "tool",
            json!({
                "type": "object",
                "description": "  Fetch   Data  ",
                "properties": { "x": { "type": "string" } }
            }),
        );

        let tool2 = create_test_tool(
            "tool",
            json!({
                "type": "object",
                "description": "fetch data",
                "properties": { "x": { "type": "string" } }
            }),
        );

        let fp1 = FingerprintHasher::fingerprint(&tool1).unwrap();
        let fp2 = FingerprintHasher::fingerprint(&tool2).unwrap();

        // Full hashes should match after description normalization
        assert_eq!(fp1.full_hash, fp2.full_hash);
    }

    #[test]
    fn test_semantic_detects_type_changes() {
        let tool1 = create_test_tool(
            "tool",
            json!({
                "type": "object",
                "properties": {
                    "count": { "type": "string" }
                }
            }),
        );

        let tool2 = create_test_tool(
            "tool",
            json!({
                "type": "object",
                "properties": {
                    "count": { "type": "number" }
                }
            }),
        );

        let fp1 = FingerprintHasher::fingerprint(&tool1).unwrap();
        let fp2 = FingerprintHasher::fingerprint(&tool2).unwrap();

        // Hashes should differ when types change
        assert_ne!(fp1.semantic_hash, fp2.semantic_hash);
    }

    #[test]
    fn test_hash_string() {
        let hash = FingerprintHasher::hash_string("test input");

        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_short_hash() {
        let hash = FingerprintHasher::short_hash("test input");

        assert_eq!(hash.len(), 16);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_empty_schema() {
        let tool = create_test_tool("empty_tool", json!({}));

        let fp = FingerprintHasher::fingerprint(&tool).unwrap();

        assert_eq!(fp.metadata.parameter_count, 0);
        assert!(fp.metadata.required_params.is_empty());
    }

    #[test]
    fn test_null_schema() {
        let tool = create_test_tool("null_tool", serde_json::Value::Null);

        let result = FingerprintHasher::fingerprint(&tool);
        assert!(result.is_ok());
    }

    #[test]
    fn test_invalid_schema() {
        let tool = create_test_tool("invalid_tool", json!("not an object"));

        let result = FingerprintHasher::fingerprint(&tool);
        assert!(result.is_err());
    }
}
