//! Schema Normalizer
//!
//! Provides canonicalization of JSON schemas for consistent fingerprinting.
//! Normalization ensures that semantically equivalent schemas produce
//! identical fingerprints regardless of formatting or property ordering.

use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Normalized schema representation
///
/// Contains canonicalized schema properties suitable for hashing.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NormalizedSchema {
    /// Canonicalized schema as JSON string
    pub canonical_json: String,

    /// Whether this is a semantic normalization (excludes descriptions, examples)
    pub is_semantic: bool,

    /// Extracted metadata
    pub metadata: SchemaMetadata,
}

/// Metadata extracted during normalization
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SchemaMetadata {
    /// Number of properties
    pub property_count: usize,

    /// Required property names (sorted)
    pub required: Vec<String>,

    /// Property name to type mapping
    pub property_types: HashMap<String, String>,

    /// Maximum nesting depth
    pub max_depth: usize,

    /// Complexity score
    pub complexity: u32,
}

/// Schema normalizer for consistent fingerprinting
pub struct SchemaNormalizer;

impl SchemaNormalizer {
    /// Normalize a schema for semantic fingerprinting
    ///
    /// Extracts and canonicalizes semantic properties:
    /// - Property names (alphabetically sorted)
    /// - Property types (canonicalized)
    /// - Required vs optional status
    /// - Constraints (min, max, pattern, enum)
    ///
    /// Excludes:
    /// - Descriptions (normalized separately if needed)
    /// - Examples
    /// - Titles
    /// - Default values
    /// - Non-semantic metadata
    pub fn normalize_semantic(schema: &Value) -> NormalizedSchema {
        let mut metadata = SchemaMetadata::default();
        let normalized = Self::normalize_value_semantic(schema, 0, &mut metadata);

        NormalizedSchema {
            canonical_json: serde_json::to_string(&normalized).unwrap_or_default(),
            is_semantic: true,
            metadata,
        }
    }

    /// Normalize a schema for full content fingerprinting
    ///
    /// Includes all properties but canonicalizes ordering and formatting.
    /// Descriptions are normalized (lowercased, trimmed, single spaces).
    pub fn normalize_full(schema: &Value) -> NormalizedSchema {
        let mut metadata = SchemaMetadata::default();
        let normalized = Self::normalize_value_full(schema, 0, &mut metadata);

        NormalizedSchema {
            canonical_json: serde_json::to_string(&normalized).unwrap_or_default(),
            is_semantic: false,
            metadata,
        }
    }

    /// Normalize tool name for fingerprinting
    #[allow(dead_code)]
    pub fn normalize_tool_name(name: &str) -> String {
        name.trim().to_lowercase()
    }

    /// Normalize description for fingerprinting
    ///
    /// - Trim whitespace
    /// - Convert to lowercase
    /// - Collapse multiple spaces to single space
    pub fn normalize_description(desc: &str) -> String {
        desc.split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .to_lowercase()
    }

    /// Canonicalize a type string
    pub fn canonicalize_type(type_str: &str) -> String {
        match type_str.to_lowercase().as_str() {
            "string" | "str" | "text" => "string".to_string(),
            "number" | "float" | "double" | "decimal" => "number".to_string(),
            "integer" | "int" | "long" => "integer".to_string(),
            "boolean" | "bool" => "boolean".to_string(),
            "object" | "map" | "dict" => "object".to_string(),
            "array" | "list" | "vec" => "array".to_string(),
            "null" | "nil" | "none" => "null".to_string(),
            other => other.to_lowercase(),
        }
    }

    /// Normalize a JSON value for semantic fingerprinting (recursive)
    fn normalize_value_semantic(
        value: &Value,
        depth: usize,
        metadata: &mut SchemaMetadata,
    ) -> Value {
        metadata.max_depth = metadata.max_depth.max(depth);

        match value {
            Value::Object(obj) => {
                let mut normalized: BTreeMap<String, Value> = BTreeMap::new();

                // Handle type
                if let Some(type_val) = obj.get("type") {
                    normalized.insert("type".to_string(), Self::normalize_type(type_val));
                }

                // Handle properties (for object schemas)
                if let Some(Value::Object(props)) = obj.get("properties") {
                    metadata.property_count = props.len();
                    let mut norm_props: BTreeMap<String, Value> = BTreeMap::new();

                    for (key, val) in props {
                        let prop_type = Self::extract_type(val);
                        metadata
                            .property_types
                            .insert(key.clone(), prop_type.clone());
                        norm_props.insert(
                            key.clone(),
                            Self::normalize_value_semantic(val, depth + 1, metadata),
                        );
                        metadata.complexity += 1;
                    }

                    normalized.insert(
                        "properties".to_string(),
                        Value::Object(norm_props.into_iter().collect()),
                    );
                }

                // Handle required fields
                if let Some(Value::Array(req)) = obj.get("required") {
                    let mut required: Vec<String> = req
                        .iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect();
                    required.sort();
                    metadata.required = required.clone();
                    normalized.insert(
                        "required".to_string(),
                        Value::Array(required.into_iter().map(Value::String).collect()),
                    );
                    metadata.complexity += 2;
                }

                // Handle items (for array schemas)
                if let Some(items) = obj.get("items") {
                    normalized.insert(
                        "items".to_string(),
                        Self::normalize_value_semantic(items, depth + 1, metadata),
                    );
                    metadata.complexity += 1;
                }

                // Handle additionalProperties
                if let Some(ap) = obj.get("additionalProperties") {
                    match ap {
                        Value::Bool(b) => {
                            normalized.insert("additionalProperties".to_string(), Value::Bool(*b));
                        }
                        Value::Object(_) => {
                            normalized.insert(
                                "additionalProperties".to_string(),
                                Self::normalize_value_semantic(ap, depth + 1, metadata),
                            );
                        }
                        _ => {}
                    }
                }

                // Handle enum values (sorted)
                if let Some(Value::Array(enum_vals)) = obj.get("enum") {
                    let mut sorted_enum: Vec<Value> = enum_vals.clone();
                    sorted_enum.sort_by(|a, b| {
                        serde_json::to_string(a)
                            .unwrap_or_default()
                            .cmp(&serde_json::to_string(b).unwrap_or_default())
                    });
                    normalized.insert("enum".to_string(), Value::Array(sorted_enum));
                    metadata.complexity += 3;
                }

                // Handle numeric constraints
                for constraint in &[
                    "minimum",
                    "maximum",
                    "exclusiveMinimum",
                    "exclusiveMaximum",
                    "multipleOf",
                ] {
                    if let Some(v) = obj.get(*constraint) {
                        if v.is_number() {
                            normalized.insert(constraint.to_string(), v.clone());
                            metadata.complexity += 1;
                        }
                    }
                }

                // Handle string constraints
                for constraint in &["minLength", "maxLength", "pattern", "format"] {
                    if let Some(v) = obj.get(*constraint) {
                        normalized.insert(constraint.to_string(), v.clone());
                        metadata.complexity += 1;
                    }
                }

                // Handle array constraints
                for constraint in &["minItems", "maxItems", "uniqueItems"] {
                    if let Some(v) = obj.get(*constraint) {
                        normalized.insert(constraint.to_string(), v.clone());
                        metadata.complexity += 1;
                    }
                }

                // Handle oneOf, anyOf, allOf
                for combiner in &["oneOf", "anyOf", "allOf"] {
                    if let Some(Value::Array(schemas)) = obj.get(*combiner) {
                        let normalized_schemas: Vec<Value> = schemas
                            .iter()
                            .map(|s| Self::normalize_value_semantic(s, depth + 1, metadata))
                            .collect();
                        normalized.insert(combiner.to_string(), Value::Array(normalized_schemas));
                        metadata.complexity += 5;
                    }
                }

                // Handle const
                if let Some(v) = obj.get("const") {
                    normalized.insert("const".to_string(), v.clone());
                    metadata.complexity += 2;
                }

                Value::Object(normalized.into_iter().collect())
            }
            Value::Array(arr) => Value::Array(
                arr.iter()
                    .map(|v| Self::normalize_value_semantic(v, depth + 1, metadata))
                    .collect(),
            ),
            // Primitives pass through unchanged
            other => other.clone(),
        }
    }

    /// Normalize a JSON value for full content fingerprinting (recursive)
    fn normalize_value_full(value: &Value, depth: usize, metadata: &mut SchemaMetadata) -> Value {
        metadata.max_depth = metadata.max_depth.max(depth);

        match value {
            Value::Object(obj) => {
                let mut normalized: BTreeMap<String, Value> = BTreeMap::new();

                // Process all keys in sorted order
                let mut keys: Vec<_> = obj.keys().collect();
                keys.sort();

                for key in keys {
                    if let Some(val) = obj.get(key) {
                        let normalized_val = match key.as_str() {
                            // Normalize descriptions
                            "description" | "title" => {
                                if let Some(s) = val.as_str() {
                                    Value::String(Self::normalize_description(s))
                                } else {
                                    Self::normalize_value_full(val, depth + 1, metadata)
                                }
                            }
                            // Normalize type
                            "type" => Self::normalize_type(val),
                            // Sort required arrays
                            "required" => {
                                if let Value::Array(arr) = val {
                                    let mut sorted: Vec<String> = arr
                                        .iter()
                                        .filter_map(|v| v.as_str().map(String::from))
                                        .collect();
                                    sorted.sort();
                                    metadata.required = sorted.clone();
                                    Value::Array(sorted.into_iter().map(Value::String).collect())
                                } else {
                                    val.clone()
                                }
                            }
                            // Sort enum arrays
                            "enum" => {
                                if let Value::Array(arr) = val {
                                    let mut sorted = arr.clone();
                                    sorted.sort_by(|a, b| {
                                        serde_json::to_string(a)
                                            .unwrap_or_default()
                                            .cmp(&serde_json::to_string(b).unwrap_or_default())
                                    });
                                    Value::Array(sorted)
                                } else {
                                    val.clone()
                                }
                            }
                            // Track properties
                            "properties" => {
                                if let Value::Object(props) = val {
                                    metadata.property_count = props.len();
                                    for (k, v) in props {
                                        metadata
                                            .property_types
                                            .insert(k.clone(), Self::extract_type(v));
                                    }
                                }
                                Self::normalize_value_full(val, depth + 1, metadata)
                            }
                            // Recurse for other values
                            _ => Self::normalize_value_full(val, depth + 1, metadata),
                        };

                        normalized.insert(key.clone(), normalized_val);
                        metadata.complexity += 1;
                    }
                }

                Value::Object(normalized.into_iter().collect())
            }
            Value::Array(arr) => Value::Array(
                arr.iter()
                    .map(|v| Self::normalize_value_full(v, depth + 1, metadata))
                    .collect(),
            ),
            Value::String(s) => Value::String(s.clone()),
            other => other.clone(),
        }
    }

    /// Normalize a type value
    fn normalize_type(type_val: &Value) -> Value {
        match type_val {
            Value::String(s) => Value::String(Self::canonicalize_type(s)),
            Value::Array(arr) => {
                let mut types: Vec<String> = arr
                    .iter()
                    .filter_map(|v| v.as_str())
                    .map(Self::canonicalize_type)
                    .collect();
                types.sort();
                Value::String(types.join("|"))
            }
            other => other.clone(),
        }
    }

    /// Extract type from a schema value
    fn extract_type(value: &Value) -> String {
        if let Some(obj) = value.as_object() {
            if let Some(type_val) = obj.get("type") {
                return match type_val {
                    Value::String(s) => Self::canonicalize_type(s),
                    Value::Array(arr) => {
                        let types: Vec<String> = arr
                            .iter()
                            .filter_map(|v| v.as_str())
                            .map(Self::canonicalize_type)
                            .collect();
                        types.join("|")
                    }
                    _ => "unknown".to_string(),
                };
            }

            // Check for common patterns
            if obj.contains_key("properties") {
                return "object".to_string();
            }
            if obj.contains_key("items") {
                return "array".to_string();
            }
            if obj.contains_key("enum") {
                return "enum".to_string();
            }
            if obj.contains_key("oneOf") || obj.contains_key("anyOf") {
                return "union".to_string();
            }
        }

        "unknown".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_normalize_tool_name() {
        assert_eq!(
            SchemaNormalizer::normalize_tool_name("  Test_Tool  "),
            "test_tool"
        );
        assert_eq!(
            SchemaNormalizer::normalize_tool_name("UPPERCASE"),
            "uppercase"
        );
    }

    #[test]
    fn test_normalize_description() {
        assert_eq!(
            SchemaNormalizer::normalize_description("  Fetch   User   Data  "),
            "fetch user data"
        );
        assert_eq!(
            SchemaNormalizer::normalize_description("UPPERCASE TEXT"),
            "uppercase text"
        );
    }

    #[test]
    fn test_canonicalize_type() {
        assert_eq!(SchemaNormalizer::canonicalize_type("String"), "string");
        assert_eq!(SchemaNormalizer::canonicalize_type("INTEGER"), "integer");
        assert_eq!(SchemaNormalizer::canonicalize_type("bool"), "boolean");
        assert_eq!(SchemaNormalizer::canonicalize_type("float"), "number");
    }

    #[test]
    fn test_property_ordering_independence() {
        let schema1 = json!({
            "type": "object",
            "properties": {
                "a": { "type": "string" },
                "b": { "type": "number" }
            }
        });

        let schema2 = json!({
            "type": "object",
            "properties": {
                "b": { "type": "number" },
                "a": { "type": "string" }
            }
        });

        let norm1 = SchemaNormalizer::normalize_semantic(&schema1);
        let norm2 = SchemaNormalizer::normalize_semantic(&schema2);

        assert_eq!(norm1.canonical_json, norm2.canonical_json);
    }

    #[test]
    fn test_required_sorting() {
        let schema1 = json!({
            "type": "object",
            "required": ["z", "a", "m"]
        });

        let schema2 = json!({
            "type": "object",
            "required": ["a", "m", "z"]
        });

        let norm1 = SchemaNormalizer::normalize_semantic(&schema1);
        let norm2 = SchemaNormalizer::normalize_semantic(&schema2);

        assert_eq!(norm1.canonical_json, norm2.canonical_json);
        assert_eq!(norm1.metadata.required, vec!["a", "m", "z"]);
    }

    #[test]
    fn test_semantic_excludes_description() {
        let schema1 = json!({
            "type": "string",
            "description": "A short description"
        });

        let schema2 = json!({
            "type": "string",
            "description": "A different description"
        });

        let norm1 = SchemaNormalizer::normalize_semantic(&schema1);
        let norm2 = SchemaNormalizer::normalize_semantic(&schema2);

        // Semantic normalization should produce identical results
        assert_eq!(norm1.canonical_json, norm2.canonical_json);
    }

    #[test]
    fn test_full_includes_description() {
        let schema1 = json!({
            "type": "string",
            "description": "A short description"
        });

        let schema2 = json!({
            "type": "string",
            "description": "A different description"
        });

        let norm1 = SchemaNormalizer::normalize_full(&schema1);
        let norm2 = SchemaNormalizer::normalize_full(&schema2);

        // Full normalization should produce different results
        assert_ne!(norm1.canonical_json, norm2.canonical_json);
    }

    #[test]
    fn test_full_normalizes_description() {
        let schema1 = json!({
            "type": "string",
            "description": "  Fetch   Data  "
        });

        let schema2 = json!({
            "type": "string",
            "description": "fetch data"
        });

        let norm1 = SchemaNormalizer::normalize_full(&schema1);
        let norm2 = SchemaNormalizer::normalize_full(&schema2);

        // Description normalization should make them equal
        assert_eq!(norm1.canonical_json, norm2.canonical_json);
    }

    #[test]
    fn test_determinism() {
        let schema = json!({
            "type": "object",
            "properties": {
                "z": { "type": "string" },
                "a": { "type": "number" },
                "m": { "type": "boolean" }
            },
            "required": ["z", "a"]
        });

        // Run normalization multiple times
        let results: Vec<String> = (0..10)
            .map(|_| SchemaNormalizer::normalize_semantic(&schema).canonical_json)
            .collect();

        // All results should be identical
        let first = &results[0];
        assert!(results.iter().all(|r| r == first));
    }
}
