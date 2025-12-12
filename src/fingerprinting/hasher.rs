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

    #[test]
    fn test_hash_string_consistency() {
        let input = "consistent input";
        let hash1 = FingerprintHasher::hash_string(input);
        let hash2 = FingerprintHasher::hash_string(input);

        assert_eq!(hash1, hash2, "Same input should produce same hash");
    }

    #[test]
    fn test_hash_string_different_inputs() {
        let hash1 = FingerprintHasher::hash_string("input1");
        let hash2 = FingerprintHasher::hash_string("input2");

        assert_ne!(
            hash1, hash2,
            "Different inputs should produce different hashes"
        );
    }

    #[test]
    fn test_hash_string_empty() {
        let hash = FingerprintHasher::hash_string("");

        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_hash_string_special_chars() {
        let hash1 = FingerprintHasher::hash_string("test@#$%^&*()");
        let hash2 = FingerprintHasher::hash_string("test\n\t\r");
        let hash3 = FingerprintHasher::hash_string("тест"); // Unicode

        assert_eq!(hash1.len(), 64);
        assert_eq!(hash2.len(), 64);
        assert_eq!(hash3.len(), 64);
        assert_ne!(hash1, hash2);
        assert_ne!(hash2, hash3);
    }

    #[test]
    fn test_short_hash_length() {
        let short = FingerprintHasher::short_hash("test");
        assert_eq!(short.len(), 16);
    }

    #[test]
    fn test_short_hash_consistency() {
        let input = "test input";
        let short1 = FingerprintHasher::short_hash(input);
        let short2 = FingerprintHasher::short_hash(input);

        assert_eq!(short1, short2);
    }

    #[test]
    fn test_short_hash_is_prefix() {
        let input = "test input";
        let full = FingerprintHasher::hash_string(input);
        let short = FingerprintHasher::short_hash(input);

        assert_eq!(&full[..16], short);
    }

    #[test]
    fn test_semantic_hash_direct() {
        let schema = json!({
            "type": "object",
            "properties": {
                "name": { "type": "string" }
            }
        });

        let hash = FingerprintHasher::semantic_hash(&schema);
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_full_hash_direct() {
        let schema = json!({
            "type": "object",
            "properties": {
                "name": { "type": "string" }
            }
        });

        let hash = FingerprintHasher::full_hash(&schema);
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_combined_hash() {
        let tool = create_test_tool(
            "test_tool",
            json!({
                "type": "object",
                "properties": {
                    "query": { "type": "string" }
                }
            }),
        );

        let hash = FingerprintHasher::combined_hash(&tool);
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_combined_hash_consistency() {
        let tool = create_test_tool(
            "test_tool",
            json!({
                "type": "object",
                "properties": {
                    "query": { "type": "string" }
                }
            }),
        );

        let hash1 = FingerprintHasher::combined_hash(&tool);
        let hash2 = FingerprintHasher::combined_hash(&tool);

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_combined_hash_differs_on_name_change() {
        let tool1 = create_test_tool(
            "tool_name_1",
            json!({
                "type": "object",
                "properties": {
                    "query": { "type": "string" }
                }
            }),
        );

        let tool2 = create_test_tool(
            "tool_name_2",
            json!({
                "type": "object",
                "properties": {
                    "query": { "type": "string" }
                }
            }),
        );

        let hash1 = FingerprintHasher::combined_hash(&tool1);
        let hash2 = FingerprintHasher::combined_hash(&tool2);

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_description_hash_some() {
        let tool = create_test_tool(
            "tool",
            json!({
                "type": "object",
                "properties": {
                    "query": { "type": "string" }
                }
            }),
        );

        let hash = FingerprintHasher::description_hash(&tool);
        assert!(hash.is_some());
        let hash_value = hash.unwrap();
        assert_eq!(hash_value.len(), 64);
        assert!(hash_value.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_description_hash_none() {
        let tool = Tool {
            name: "tool".to_string(),
            description: None,
            input_schema: json!({
                "type": "object",
                "properties": {
                    "query": { "type": "string" }
                }
            }),
        };

        let hash = FingerprintHasher::description_hash(&tool);
        assert!(hash.is_none());
    }

    #[test]
    fn test_description_hash_consistency() {
        let tool = create_test_tool(
            "tool",
            json!({
                "type": "object",
                "properties": {
                    "query": { "type": "string" }
                }
            }),
        );

        let hash1 = FingerprintHasher::description_hash(&tool);
        let hash2 = FingerprintHasher::description_hash(&tool);

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_fingerprint_all() {
        let tools = vec![
            create_test_tool(
                "tool1",
                json!({
                    "type": "object",
                    "properties": {
                        "a": { "type": "string" }
                    }
                }),
            ),
            create_test_tool(
                "tool2",
                json!({
                    "type": "object",
                    "properties": {
                        "b": { "type": "number" }
                    }
                }),
            ),
            create_test_tool("tool3", json!("invalid")), // This will error
        ];

        let results = FingerprintHasher::fingerprint_all(&tools);

        assert_eq!(results.len(), 3);
        assert!(results[0].is_ok());
        assert!(results[1].is_ok());
        assert!(results[2].is_err());
    }

    #[test]
    fn test_fingerprint_all_ok() {
        let tools = vec![
            create_test_tool(
                "tool1",
                json!({
                    "type": "object",
                    "properties": {
                        "a": { "type": "string" }
                    }
                }),
            ),
            create_test_tool(
                "tool2",
                json!({
                    "type": "object",
                    "properties": {
                        "b": { "type": "number" }
                    }
                }),
            ),
            create_test_tool("tool3", json!("invalid")), // This will be filtered out
        ];

        let results = FingerprintHasher::fingerprint_all_ok(&tools);

        assert_eq!(results.len(), 2);
        assert_eq!(results[0].tool_name, "tool1");
        assert_eq!(results[1].tool_name, "tool2");
    }

    #[test]
    fn test_fingerprint_all_ok_empty() {
        let tools: Vec<Tool> = vec![];
        let results = FingerprintHasher::fingerprint_all_ok(&tools);
        assert!(results.is_empty());
    }

    #[test]
    fn test_fingerprint_with_schema_version() {
        let tool = create_test_tool(
            "versioned_tool",
            json!({
                "type": "object",
                "$schema": "http://json-schema.org/draft-07/schema#",
                "properties": {
                    "query": { "type": "string" }
                }
            }),
        );

        let fp = FingerprintHasher::fingerprint(&tool).unwrap();

        assert_eq!(
            fp.schema_version,
            Some("http://json-schema.org/draft-07/schema#".to_string())
        );
    }

    #[test]
    fn test_fingerprint_with_version_field() {
        let tool = create_test_tool(
            "versioned_tool",
            json!({
                "type": "object",
                "version": "1.0.0",
                "properties": {
                    "query": { "type": "string" }
                }
            }),
        );

        let fp = FingerprintHasher::fingerprint(&tool).unwrap();

        assert_eq!(fp.schema_version, Some("1.0.0".to_string()));
    }

    #[test]
    fn test_fingerprint_without_version() {
        let tool = create_test_tool(
            "unversioned_tool",
            json!({
                "type": "object",
                "properties": {
                    "query": { "type": "string" }
                }
            }),
        );

        let fp = FingerprintHasher::fingerprint(&tool).unwrap();

        assert!(fp.schema_version.is_none());
    }

    #[test]
    fn test_fingerprint_metadata_population() {
        let tool = create_test_tool(
            "test_tool",
            json!({
                "type": "object",
                "properties": {
                    "name": { "type": "string" },
                    "age": { "type": "integer" },
                    "active": { "type": "boolean" }
                },
                "required": ["name", "age"]
            }),
        );

        let fp = FingerprintHasher::fingerprint(&tool).unwrap();

        assert_eq!(fp.metadata.parameter_count, 3);
        assert_eq!(fp.metadata.required_params.len(), 2);
        assert!(fp.metadata.required_params.contains(&"name".to_string()));
        assert!(fp.metadata.required_params.contains(&"age".to_string()));
        assert_eq!(fp.metadata.param_types.len(), 3);
    }

    #[test]
    fn test_invalid_schema_array() {
        let tool = create_test_tool("invalid", json!([]));
        let result = FingerprintHasher::fingerprint(&tool);
        assert!(result.is_err());
        match result {
            Err(FingerprintError::InvalidSchema(_)) => (),
            _ => panic!("Expected InvalidSchema error"),
        }
    }

    #[test]
    fn test_invalid_schema_number() {
        let tool = create_test_tool("invalid", json!(42));
        let result = FingerprintHasher::fingerprint(&tool);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_schema_boolean() {
        let tool = create_test_tool("invalid", json!(true));
        let result = FingerprintHasher::fingerprint(&tool);
        assert!(result.is_err());
    }

    #[test]
    fn test_semantic_and_full_hash_differ_when_metadata_present() {
        let tool = create_test_tool(
            "tool",
            json!({
                "type": "object",
                "title": "My Tool",
                "description": "Does something",
                "examples": [{"name": "test"}],
                "properties": {
                    "query": { "type": "string" }
                }
            }),
        );

        let fp = FingerprintHasher::fingerprint(&tool).unwrap();

        // Semantic and full should differ when there's metadata
        assert_ne!(fp.semantic_hash, fp.full_hash);
    }

    #[test]
    fn test_build_metadata() {
        use super::super::normalizer::SchemaMetadata;
        use std::collections::HashMap;

        let mut property_types = HashMap::new();
        property_types.insert("field1".to_string(), "string".to_string());
        property_types.insert("field2".to_string(), "number".to_string());

        let schema_meta = SchemaMetadata {
            property_count: 2,
            required: vec!["field1".to_string()],
            property_types: property_types.clone(),
            max_depth: 2,
            complexity: 5,
        };

        let fp_meta = FingerprintHasher::build_metadata(&schema_meta);

        assert_eq!(fp_meta.parameter_count, 2);
        assert_eq!(fp_meta.required_params, vec!["field1".to_string()]);
        assert_eq!(fp_meta.param_types, property_types);
        assert_eq!(fp_meta.complexity_score, 5);
    }

    #[test]
    fn test_complex_schema_fingerprint() {
        let tool = create_test_tool(
            "complex_tool",
            json!({
                "type": "object",
                "properties": {
                    "user": {
                        "type": "object",
                        "properties": {
                            "name": { "type": "string" },
                            "email": { "type": "string", "format": "email" }
                        },
                        "required": ["name"]
                    },
                    "options": {
                        "type": "array",
                        "items": { "type": "string" }
                    },
                    "count": {
                        "type": "integer",
                        "minimum": 0,
                        "maximum": 100
                    }
                },
                "required": ["user"]
            }),
        );

        let fp = FingerprintHasher::fingerprint(&tool).unwrap();

        assert_eq!(fp.tool_name, "complex_tool");
        assert!(fp.metadata.complexity_score > 0);
        assert!(fp.semantic_hash.len() == 64);
        assert!(fp.full_hash.len() == 64);
    }
}
