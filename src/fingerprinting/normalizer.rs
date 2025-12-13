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

    #[test]
    fn test_canonicalize_type_variants() {
        assert_eq!(SchemaNormalizer::canonicalize_type("str"), "string");
        assert_eq!(SchemaNormalizer::canonicalize_type("text"), "string");
        assert_eq!(SchemaNormalizer::canonicalize_type("double"), "number");
        assert_eq!(SchemaNormalizer::canonicalize_type("decimal"), "number");
        assert_eq!(SchemaNormalizer::canonicalize_type("int"), "integer");
        assert_eq!(SchemaNormalizer::canonicalize_type("long"), "integer");
        assert_eq!(SchemaNormalizer::canonicalize_type("bool"), "boolean");
        assert_eq!(SchemaNormalizer::canonicalize_type("map"), "object");
        assert_eq!(SchemaNormalizer::canonicalize_type("dict"), "object");
        assert_eq!(SchemaNormalizer::canonicalize_type("list"), "array");
        assert_eq!(SchemaNormalizer::canonicalize_type("vec"), "array");
        assert_eq!(SchemaNormalizer::canonicalize_type("nil"), "null");
        assert_eq!(SchemaNormalizer::canonicalize_type("none"), "null");
        assert_eq!(SchemaNormalizer::canonicalize_type("custom"), "custom");
    }

    #[test]
    fn test_normalize_empty_schema() {
        let schema = json!({});
        let normalized = SchemaNormalizer::normalize_semantic(&schema);

        assert!(normalized.canonical_json.contains("{}"));
        assert_eq!(normalized.metadata.property_count, 0);
    }

    #[test]
    fn test_normalize_simple_string_type() {
        let schema = json!({
            "type": "string"
        });
        let normalized = SchemaNormalizer::normalize_semantic(&schema);

        assert!(normalized.canonical_json.contains("string"));
        assert_eq!(normalized.metadata.property_count, 0);
    }

    #[test]
    fn test_normalize_array_schema() {
        let schema = json!({
            "type": "array",
            "items": {
                "type": "string"
            }
        });
        let normalized = SchemaNormalizer::normalize_semantic(&schema);

        assert!(normalized.canonical_json.contains("array"));
        assert!(normalized.canonical_json.contains("items"));
    }

    #[test]
    fn test_normalize_additional_properties_bool() {
        let schema = json!({
            "type": "object",
            "additionalProperties": false
        });
        let normalized = SchemaNormalizer::normalize_semantic(&schema);

        assert!(normalized.canonical_json.contains("additionalProperties"));
    }

    #[test]
    fn test_normalize_additional_properties_object() {
        let schema = json!({
            "type": "object",
            "additionalProperties": {
                "type": "string"
            }
        });
        let normalized = SchemaNormalizer::normalize_semantic(&schema);

        assert!(normalized.canonical_json.contains("additionalProperties"));
    }

    #[test]
    fn test_normalize_enum_sorting() {
        let schema1 = json!({
            "type": "string",
            "enum": ["z", "a", "m"]
        });
        let schema2 = json!({
            "type": "string",
            "enum": ["a", "m", "z"]
        });

        let norm1 = SchemaNormalizer::normalize_semantic(&schema1);
        let norm2 = SchemaNormalizer::normalize_semantic(&schema2);

        assert_eq!(norm1.canonical_json, norm2.canonical_json);
    }

    #[test]
    fn test_normalize_numeric_constraints() {
        let schema = json!({
            "type": "number",
            "minimum": 0,
            "maximum": 100,
            "exclusiveMinimum": 0,
            "exclusiveMaximum": 100,
            "multipleOf": 5
        });
        let normalized = SchemaNormalizer::normalize_semantic(&schema);

        assert!(normalized.canonical_json.contains("minimum"));
        assert!(normalized.canonical_json.contains("maximum"));
        assert!(normalized.canonical_json.contains("multipleOf"));
    }

    #[test]
    fn test_normalize_string_constraints() {
        let schema = json!({
            "type": "string",
            "minLength": 1,
            "maxLength": 100,
            "pattern": "^[a-z]+$",
            "format": "email"
        });
        let normalized = SchemaNormalizer::normalize_semantic(&schema);

        assert!(normalized.canonical_json.contains("minLength"));
        assert!(normalized.canonical_json.contains("maxLength"));
        assert!(normalized.canonical_json.contains("pattern"));
        assert!(normalized.canonical_json.contains("format"));
    }

    #[test]
    fn test_normalize_array_constraints() {
        let schema = json!({
            "type": "array",
            "minItems": 1,
            "maxItems": 10,
            "uniqueItems": true
        });
        let normalized = SchemaNormalizer::normalize_semantic(&schema);

        assert!(normalized.canonical_json.contains("minItems"));
        assert!(normalized.canonical_json.contains("maxItems"));
        assert!(normalized.canonical_json.contains("uniqueItems"));
    }

    #[test]
    fn test_normalize_oneof() {
        let schema = json!({
            "oneOf": [
                {"type": "string"},
                {"type": "number"}
            ]
        });
        let normalized = SchemaNormalizer::normalize_semantic(&schema);

        assert!(normalized.canonical_json.contains("oneOf"));
        assert!(normalized.metadata.complexity > 0);
    }

    #[test]
    fn test_normalize_anyof() {
        let schema = json!({
            "anyOf": [
                {"type": "string"},
                {"type": "number"}
            ]
        });
        let normalized = SchemaNormalizer::normalize_semantic(&schema);

        assert!(normalized.canonical_json.contains("anyOf"));
    }

    #[test]
    fn test_normalize_allof() {
        let schema = json!({
            "allOf": [
                {"type": "object", "properties": {"a": {"type": "string"}}},
                {"type": "object", "properties": {"b": {"type": "number"}}}
            ]
        });
        let normalized = SchemaNormalizer::normalize_semantic(&schema);

        assert!(normalized.canonical_json.contains("allOf"));
    }

    #[test]
    fn test_normalize_const() {
        let schema = json!({
            "const": "fixed_value"
        });
        let normalized = SchemaNormalizer::normalize_semantic(&schema);

        assert!(normalized.canonical_json.contains("const"));
        assert!(normalized.metadata.complexity > 0);
    }

    #[test]
    fn test_metadata_property_count() {
        let schema = json!({
            "type": "object",
            "properties": {
                "a": {"type": "string"},
                "b": {"type": "number"},
                "c": {"type": "boolean"}
            }
        });
        let normalized = SchemaNormalizer::normalize_semantic(&schema);

        assert_eq!(normalized.metadata.property_count, 3);
    }

    #[test]
    fn test_metadata_required_fields() {
        let schema = json!({
            "type": "object",
            "properties": {
                "a": {"type": "string"},
                "b": {"type": "number"}
            },
            "required": ["a"]
        });
        let normalized = SchemaNormalizer::normalize_semantic(&schema);

        assert_eq!(normalized.metadata.required, vec!["a"]);
    }

    #[test]
    fn test_metadata_property_types() {
        let schema = json!({
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "age": {"type": "number"}
            }
        });
        let normalized = SchemaNormalizer::normalize_semantic(&schema);

        assert_eq!(
            normalized.metadata.property_types.get("name"),
            Some(&"string".to_string())
        );
        assert_eq!(
            normalized.metadata.property_types.get("age"),
            Some(&"number".to_string())
        );
    }

    #[test]
    fn test_metadata_max_depth() {
        let schema = json!({
            "type": "object",
            "properties": {
                "level1": {
                    "type": "object",
                    "properties": {
                        "level2": {
                            "type": "object",
                            "properties": {
                                "level3": {"type": "string"}
                            }
                        }
                    }
                }
            }
        });
        let normalized = SchemaNormalizer::normalize_semantic(&schema);

        assert!(normalized.metadata.max_depth > 2);
    }

    #[test]
    fn test_metadata_complexity_score() {
        let schema = json!({
            "type": "object",
            "properties": {
                "a": {"type": "string"},
                "b": {"type": "number"}
            },
            "required": ["a"]
        });
        let normalized = SchemaNormalizer::normalize_semantic(&schema);

        assert!(normalized.metadata.complexity > 0);
    }

    #[test]
    fn test_normalize_type_array() {
        let schema = json!({
            "type": ["string", "null"]
        });
        let normalized = SchemaNormalizer::normalize_semantic(&schema);

        // Array types should be normalized to a unified format
        assert!(normalized.canonical_json.contains("type"));
    }

    #[test]
    fn test_extract_type_from_object_schema() {
        let value = json!({
            "type": "object",
            "properties": {}
        });

        let schema_type = SchemaNormalizer::normalize_semantic(&value);
        assert!(
            schema_type.metadata.property_types.is_empty()
                || schema_type.metadata.property_count == 0
        );
    }

    #[test]
    fn test_extract_type_from_array_schema() {
        let value = json!({
            "type": "array",
            "items": {"type": "string"}
        });

        let normalized = SchemaNormalizer::normalize_semantic(&value);
        assert!(normalized.canonical_json.contains("array"));
    }

    #[test]
    fn test_full_normalization_preserves_all_fields() {
        let schema = json!({
            "type": "object",
            "title": "Test Schema",
            "description": "A test schema",
            "properties": {
                "name": {
                    "type": "string",
                    "description": "User name"
                }
            }
        });
        let normalized = SchemaNormalizer::normalize_full(&schema);

        assert!(normalized.canonical_json.contains("title"));
        assert!(normalized.canonical_json.contains("description"));
    }

    #[test]
    fn test_full_normalization_key_ordering() {
        let schema1 = json!({
            "type": "object",
            "description": "Test",
            "properties": {}
        });
        let schema2 = json!({
            "properties": {},
            "type": "object",
            "description": "Test"
        });

        let norm1 = SchemaNormalizer::normalize_full(&schema1);
        let norm2 = SchemaNormalizer::normalize_full(&schema2);

        // Full normalization should produce same result regardless of key order
        assert_eq!(norm1.canonical_json, norm2.canonical_json);
    }

    #[test]
    fn test_is_semantic_flag() {
        let schema = json!({"type": "string"});

        let semantic = SchemaNormalizer::normalize_semantic(&schema);
        assert!(semantic.is_semantic);

        let full = SchemaNormalizer::normalize_full(&schema);
        assert!(!full.is_semantic);
    }

    #[test]
    fn test_normalize_nested_arrays() {
        let schema = json!({
            "type": "array",
            "items": {
                "type": "array",
                "items": {"type": "string"}
            }
        });
        let normalized = SchemaNormalizer::normalize_semantic(&schema);

        assert!(normalized.canonical_json.contains("array"));
        assert!(normalized.metadata.max_depth > 1);
    }

    #[test]
    fn test_normalize_primitives_pass_through() {
        let schema = json!("string_value");
        let normalized = SchemaNormalizer::normalize_semantic(&schema);

        assert!(normalized.canonical_json.contains("string_value"));
    }

    #[test]
    fn test_normalize_description_whitespace() {
        assert_eq!(
            SchemaNormalizer::normalize_description("   spaces   everywhere   "),
            "spaces everywhere"
        );
        assert_eq!(
            SchemaNormalizer::normalize_description("\t\ntabs\nand\nnewlines\t"),
            "tabs and newlines"
        );
    }

    #[test]
    fn test_normalize_tool_name_empty() {
        assert_eq!(SchemaNormalizer::normalize_tool_name(""), "");
        assert_eq!(SchemaNormalizer::normalize_tool_name("   "), "");
    }

    #[test]
    fn test_complexity_increases_with_constraints() {
        let simple = json!({"type": "string"});
        let complex = json!({
            "type": "string",
            "minLength": 1,
            "maxLength": 100,
            "pattern": "^[a-z]+$"
        });

        let simple_norm = SchemaNormalizer::normalize_semantic(&simple);
        let complex_norm = SchemaNormalizer::normalize_semantic(&complex);

        assert!(complex_norm.metadata.complexity > simple_norm.metadata.complexity);
    }

    // NEW TESTS FOR INCREASED COVERAGE

    #[test]
    fn test_normalize_type_with_union_types() {
        let schema = json!({
            "type": ["string", "number", "null"]
        });
        let normalized = SchemaNormalizer::normalize_semantic(&schema);

        // Union types should be sorted and joined
        assert!(normalized.canonical_json.contains("type"));
        assert!(normalized.canonical_json.contains("null|number|string"));
    }

    #[test]
    fn test_normalize_type_with_empty_array() {
        let type_val = json!([]);
        let result = SchemaNormalizer::normalize_type(&type_val);

        // Empty array should produce empty string
        assert_eq!(result, Value::String("".to_string()));
    }

    #[test]
    fn test_normalize_type_with_non_string_non_array() {
        let type_val = json!(123);
        let result = SchemaNormalizer::normalize_type(&type_val);

        // Non-string, non-array should pass through
        assert_eq!(result, json!(123));
    }

    #[test]
    fn test_extract_type_without_type_field_but_properties() {
        let schema = json!({
            "properties": {
                "name": {"type": "string"}
            }
        });

        let extracted = SchemaNormalizer::normalize_semantic(&schema);
        // Should infer object type from properties
        assert!(extracted.canonical_json.contains("properties"));
    }

    #[test]
    fn test_extract_type_without_type_field_but_items() {
        let value = json!({
            "items": {"type": "string"}
        });

        let normalized = SchemaNormalizer::normalize_semantic(&value);
        // Should infer array type from items
        assert!(normalized.canonical_json.contains("items"));
    }

    #[test]
    fn test_extract_type_with_enum() {
        let value = json!({
            "enum": ["option1", "option2"]
        });

        let normalized = SchemaNormalizer::normalize_semantic(&value);
        // Should recognize enum pattern
        assert!(normalized.canonical_json.contains("enum"));
    }

    #[test]
    fn test_extract_type_with_oneof_union() {
        let value = json!({
            "oneOf": [
                {"type": "string"},
                {"type": "number"}
            ]
        });

        let normalized = SchemaNormalizer::normalize_semantic(&value);
        // Should recognize union pattern
        assert!(normalized.canonical_json.contains("oneOf"));
    }

    #[test]
    fn test_extract_type_with_anyof_union() {
        let value = json!({
            "anyOf": [
                {"type": "string"},
                {"type": "number"}
            ]
        });

        let normalized = SchemaNormalizer::normalize_semantic(&value);
        // Should recognize union pattern
        assert!(normalized.canonical_json.contains("anyOf"));
    }

    #[test]
    fn test_extract_type_with_type_array() {
        let value = json!({
            "type": ["string", "integer"]
        });

        let normalized = SchemaNormalizer::normalize_semantic(&value);
        // Should handle array types
        assert!(normalized.canonical_json.contains("type"));
    }

    #[test]
    fn test_extract_type_with_unknown_schema() {
        let value = json!({
            "customField": "value"
        });

        let normalized = SchemaNormalizer::normalize_semantic(&value);
        // Unknown schema should still normalize
        assert!(!normalized.canonical_json.is_empty());
    }

    #[test]
    fn test_full_normalization_with_title() {
        let schema = json!({
            "type": "string",
            "title": "  Test   Title  "
        });

        let normalized = SchemaNormalizer::normalize_full(&schema);

        // Title should be normalized
        assert!(normalized.canonical_json.contains("test title"));
    }

    #[test]
    fn test_full_normalization_with_non_string_description() {
        let schema = json!({
            "type": "string",
            "description": 123
        });

        let normalized = SchemaNormalizer::normalize_full(&schema);

        // Non-string description should be processed
        assert!(!normalized.canonical_json.is_empty());
    }

    #[test]
    fn test_full_normalization_enum_sorting() {
        let schema1 = json!({
            "enum": [3, 1, 2]
        });
        let schema2 = json!({
            "enum": [1, 2, 3]
        });

        let norm1 = SchemaNormalizer::normalize_full(&schema1);
        let norm2 = SchemaNormalizer::normalize_full(&schema2);

        // Enum should be sorted regardless of order
        assert_eq!(norm1.canonical_json, norm2.canonical_json);
    }

    #[test]
    fn test_full_normalization_required_non_array() {
        let schema = json!({
            "type": "object",
            "required": "not_an_array"
        });

        let normalized = SchemaNormalizer::normalize_full(&schema);

        // Non-array required should pass through
        assert!(normalized.canonical_json.contains("required"));
    }

    #[test]
    fn test_semantic_normalization_excludes_title() {
        let schema1 = json!({
            "type": "string",
            "title": "First Title"
        });
        let schema2 = json!({
            "type": "string",
            "title": "Second Title"
        });

        let norm1 = SchemaNormalizer::normalize_semantic(&schema1);
        let norm2 = SchemaNormalizer::normalize_semantic(&schema2);

        // Semantic normalization should exclude titles
        assert_eq!(norm1.canonical_json, norm2.canonical_json);
    }

    #[test]
    fn test_semantic_normalization_excludes_examples() {
        let schema1 = json!({
            "type": "string",
            "examples": ["example1"]
        });
        let schema2 = json!({
            "type": "string",
            "examples": ["example2"]
        });

        let norm1 = SchemaNormalizer::normalize_semantic(&schema1);
        let norm2 = SchemaNormalizer::normalize_semantic(&schema2);

        // Semantic normalization should exclude examples
        assert_eq!(norm1.canonical_json, norm2.canonical_json);
    }

    #[test]
    fn test_semantic_normalization_excludes_default() {
        let schema1 = json!({
            "type": "string",
            "default": "value1"
        });
        let schema2 = json!({
            "type": "string",
            "default": "value2"
        });

        let norm1 = SchemaNormalizer::normalize_semantic(&schema1);
        let norm2 = SchemaNormalizer::normalize_semantic(&schema2);

        // Semantic normalization should exclude defaults
        assert_eq!(norm1.canonical_json, norm2.canonical_json);
    }

    #[test]
    fn test_additional_properties_non_bool_non_object() {
        let schema = json!({
            "type": "object",
            "additionalProperties": "invalid"
        });

        let normalized = SchemaNormalizer::normalize_semantic(&schema);

        // Invalid additionalProperties should be ignored
        assert!(!normalized.canonical_json.contains("additionalProperties"));
    }

    #[test]
    fn test_numeric_constraint_with_non_number() {
        let schema = json!({
            "type": "number",
            "minimum": "not_a_number"
        });

        let normalized = SchemaNormalizer::normalize_semantic(&schema);

        // Non-numeric constraint should be ignored
        assert!(!normalized.canonical_json.contains("minimum"));
    }

    #[test]
    fn test_complex_nested_schema() {
        let schema = json!({
            "type": "object",
            "properties": {
                "user": {
                    "type": "object",
                    "properties": {
                        "profile": {
                            "type": "object",
                            "properties": {
                                "address": {
                                    "type": "object",
                                    "properties": {
                                        "street": {"type": "string"}
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });

        let normalized = SchemaNormalizer::normalize_semantic(&schema);

        assert!(normalized.metadata.max_depth >= 4);
        assert!(normalized.metadata.complexity > 0);
    }

    #[test]
    fn test_schema_with_all_constraint_types() {
        let schema = json!({
            "type": "object",
            "properties": {
                "num": {
                    "type": "number",
                    "minimum": 0,
                    "maximum": 100,
                    "multipleOf": 5
                },
                "str": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 50,
                    "pattern": "^[a-z]+$",
                    "format": "email"
                },
                "arr": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 10,
                    "uniqueItems": true
                }
            },
            "required": ["num", "str"],
            "additionalProperties": false
        });

        let normalized = SchemaNormalizer::normalize_semantic(&schema);

        assert_eq!(normalized.metadata.property_count, 3);
        assert_eq!(normalized.metadata.required.len(), 2);
        assert!(normalized.metadata.complexity > 10);
    }

    #[test]
    fn test_empty_object_array_normalization() {
        let schema = json!({
            "type": "object",
            "properties": {}
        });

        let normalized = SchemaNormalizer::normalize_semantic(&schema);

        assert_eq!(normalized.metadata.property_count, 0);
        assert!(normalized.canonical_json.contains("properties"));
    }

    #[test]
    fn test_array_with_complex_items() {
        let schema = json!({
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "id": {"type": "integer"},
                    "name": {"type": "string"}
                },
                "required": ["id"]
            }
        });

        let normalized = SchemaNormalizer::normalize_semantic(&schema);

        assert!(normalized.canonical_json.contains("items"));
        assert!(normalized.metadata.max_depth >= 2);
    }

    #[test]
    fn test_enum_with_mixed_types() {
        let schema = json!({
            "enum": [1, "two", true, null]
        });

        let normalized = SchemaNormalizer::normalize_semantic(&schema);

        assert!(normalized.canonical_json.contains("enum"));
        assert!(normalized.metadata.complexity > 0);
    }

    #[test]
    fn test_multiple_combiners() {
        let schema = json!({
            "allOf": [
                {"type": "object", "properties": {"a": {"type": "string"}}},
                {"type": "object", "properties": {"b": {"type": "number"}}}
            ],
            "oneOf": [
                {"required": ["a"]},
                {"required": ["b"]}
            ]
        });

        let normalized = SchemaNormalizer::normalize_semantic(&schema);

        assert!(normalized.canonical_json.contains("allOf"));
        assert!(normalized.canonical_json.contains("oneOf"));
        assert!(normalized.metadata.complexity > 5);
    }

    #[test]
    fn test_deeply_nested_combiners() {
        let schema = json!({
            "oneOf": [
                {
                    "anyOf": [
                        {"type": "string"},
                        {
                            "allOf": [
                                {"type": "number"},
                                {"minimum": 0}
                            ]
                        }
                    ]
                },
                {"type": "boolean"}
            ]
        });

        let normalized = SchemaNormalizer::normalize_semantic(&schema);

        assert!(normalized.metadata.max_depth > 2);
        assert!(normalized.metadata.complexity > 10);
    }

    #[test]
    fn test_normalization_determinism_with_complex_schema() {
        let schema = json!({
            "type": "object",
            "properties": {
                "z": {
                    "type": "array",
                    "items": {
                        "oneOf": [
                            {"type": "string"},
                            {"type": "number"}
                        ]
                    }
                },
                "a": {
                    "type": "object",
                    "properties": {
                        "nested": {"type": "boolean"}
                    }
                }
            },
            "required": ["z", "a"]
        });

        let results: Vec<String> = (0..5)
            .map(|_| SchemaNormalizer::normalize_semantic(&schema).canonical_json)
            .collect();

        let first = &results[0];
        assert!(results.iter().all(|r| r == first));
    }

    #[test]
    fn test_full_normalization_preserves_custom_fields() {
        let schema = json!({
            "type": "object",
            "x-custom-field": "custom_value",
            "properties": {
                "name": {"type": "string"}
            }
        });

        let normalized = SchemaNormalizer::normalize_full(&schema);

        // Custom fields should be preserved in full normalization
        assert!(normalized.canonical_json.contains("x-custom-field"));
    }

    #[test]
    fn test_metadata_property_types_with_complex_schemas() {
        let schema = json!({
            "type": "object",
            "properties": {
                "simple": {"type": "string"},
                "inferred_object": {"properties": {"nested": {"type": "number"}}},
                "inferred_array": {"items": {"type": "boolean"}},
                "enum_field": {"enum": ["a", "b"]},
                "union_field": {"oneOf": [{"type": "string"}, {"type": "number"}]}
            }
        });

        let normalized = SchemaNormalizer::normalize_semantic(&schema);

        // Check that properties are tracked
        assert!(normalized.metadata.property_count > 0);
        assert_eq!(
            normalized.metadata.property_types.get("simple"),
            Some(&"string".to_string())
        );
        assert_eq!(
            normalized.metadata.property_types.get("inferred_object"),
            Some(&"object".to_string())
        );
        assert_eq!(
            normalized.metadata.property_types.get("inferred_array"),
            Some(&"array".to_string())
        );
        assert_eq!(
            normalized.metadata.property_types.get("enum_field"),
            Some(&"enum".to_string())
        );
        assert_eq!(
            normalized.metadata.property_types.get("union_field"),
            Some(&"union".to_string())
        );
    }

    #[test]
    fn test_required_field_with_non_string_values() {
        let schema = json!({
            "type": "object",
            "required": ["field1", 123, true, "field2"]
        });

        let normalized = SchemaNormalizer::normalize_semantic(&schema);

        // Only string values should be extracted
        assert_eq!(normalized.metadata.required, vec!["field1", "field2"]);
    }

    #[test]
    fn test_primitive_number_normalization() {
        let schema = json!(42);
        let normalized = SchemaNormalizer::normalize_semantic(&schema);

        assert!(normalized.canonical_json.contains("42"));
    }

    #[test]
    fn test_primitive_boolean_normalization() {
        let schema = json!(true);
        let normalized = SchemaNormalizer::normalize_semantic(&schema);

        assert!(normalized.canonical_json.contains("true"));
    }

    #[test]
    fn test_primitive_null_normalization() {
        let schema = json!(null);
        let normalized = SchemaNormalizer::normalize_semantic(&schema);

        assert!(normalized.canonical_json.contains("null"));
    }

    #[test]
    fn test_array_of_primitives() {
        let schema = json!([1, 2, 3]);
        let normalized = SchemaNormalizer::normalize_semantic(&schema);

        assert!(normalized.canonical_json.contains("1"));
        assert!(normalized.canonical_json.contains("2"));
        assert!(normalized.canonical_json.contains("3"));
    }

    #[test]
    fn test_normalization_with_all_numeric_constraints() {
        let schema = json!({
            "type": "number",
            "minimum": 0,
            "maximum": 100,
            "exclusiveMinimum": 0,
            "exclusiveMaximum": 100,
            "multipleOf": 0.5
        });

        let normalized = SchemaNormalizer::normalize_semantic(&schema);

        assert!(normalized.canonical_json.contains("minimum"));
        assert!(normalized.canonical_json.contains("maximum"));
        assert!(normalized.canonical_json.contains("exclusiveMinimum"));
        assert!(normalized.canonical_json.contains("exclusiveMaximum"));
        assert!(normalized.canonical_json.contains("multipleOf"));
    }

    #[test]
    fn test_normalization_with_all_string_constraints() {
        let schema = json!({
            "type": "string",
            "minLength": 5,
            "maxLength": 100,
            "pattern": "^[A-Z]",
            "format": "uri"
        });

        let normalized = SchemaNormalizer::normalize_semantic(&schema);

        assert!(normalized.canonical_json.contains("minLength"));
        assert!(normalized.canonical_json.contains("maxLength"));
        assert!(normalized.canonical_json.contains("pattern"));
        assert!(normalized.canonical_json.contains("format"));
    }

    #[test]
    fn test_const_with_object_value() {
        let schema = json!({
            "const": {"fixed": "value"}
        });

        let normalized = SchemaNormalizer::normalize_semantic(&schema);

        assert!(normalized.canonical_json.contains("const"));
        assert!(normalized.metadata.complexity > 0);
    }

    #[test]
    fn test_const_with_array_value() {
        let schema = json!({
            "const": [1, 2, 3]
        });

        let normalized = SchemaNormalizer::normalize_semantic(&schema);

        assert!(normalized.canonical_json.contains("const"));
    }

    #[test]
    fn test_description_with_unicode() {
        let desc = "Unicode: 日本語 🎉 Ñoño";
        let normalized = SchemaNormalizer::normalize_description(desc);

        assert_eq!(normalized, "unicode: 日本語 🎉 ñoño");
    }

    #[test]
    fn test_empty_description() {
        assert_eq!(SchemaNormalizer::normalize_description(""), "");
        assert_eq!(SchemaNormalizer::normalize_description("   "), "");
    }

    #[test]
    fn test_canonicalize_type_case_insensitive() {
        assert_eq!(SchemaNormalizer::canonicalize_type("STRING"), "string");
        assert_eq!(SchemaNormalizer::canonicalize_type("Number"), "number");
        assert_eq!(SchemaNormalizer::canonicalize_type("BOOLEAN"), "boolean");
    }
}
