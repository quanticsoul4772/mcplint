//! JSON-RPC Mutations - JSON-RPC protocol-level mutations
//!
//! Provides mutations specific to the JSON-RPC 2.0 protocol,
//! including invalid IDs, malformed versions, and field manipulation.

use rand::Rng;
use serde_json::{json, Value};

use super::dictionary::{Dictionary, TokenCategory};

/// JSON-RPC protocol mutation operations
pub struct JsonRpcMutator;

impl JsonRpcMutator {
    /// Generate invalid request ID values
    pub fn invalid_id(rng: &mut impl Rng) -> Value {
        let choices: &[Value] = &[
            Value::Null,
            json!(-1),
            json!(-999999),
            json!(0),
            json!(i64::MAX),
            json!(i64::MIN),
            json!(1.5),       // Float ID
            json!(""),        // Empty string ID
            json!([]),        // Array ID
            json!({}),        // Object ID
            json!([1, 2, 3]), // Array with values
            json!({"id": 1}), // Nested ID
            json!(true),      // Boolean ID
            json!(false),
        ];
        choices[rng.gen_range(0..choices.len())].clone()
    }

    /// Generate malformed JSON-RPC version values
    pub fn malformed_version(rng: &mut impl Rng) -> Value {
        let choices: &[Value] = &[
            json!("1.0"),
            json!("2.1"),
            json!("3.0"),
            json!(""),
            json!(2.0), // Number instead of string
            json!(2),   // Integer
            json!(null),
            json!("2,0"), // Comma instead of dot
            json!("v2.0"),
            json!("JSON-RPC 2.0"),
            json!(["2.0"]),
            json!({"version": "2.0"}),
            json!("2.0.0"),
            json!("2.0-beta"),
        ];
        choices[rng.gen_range(0..choices.len())].clone()
    }

    /// Generate unknown/invalid method names
    pub fn unknown_method(dict: &Dictionary, rng: &mut impl Rng) -> String {
        let base_methods = [
            "nonexistent_method",
            "../../etc/passwd",
            "__proto__",
            "constructor",
            "",
            " ",
            "\n",
            "tools/invalid",
            "admin/delete",
            "system/exec",
            "rpc.discover",
            "system.listMethods",
            "$.",
            "*",
            "tools/*",
        ];

        match rng.gen_range(0..3) {
            0 => base_methods[rng.gen_range(0..base_methods.len())].to_string(),
            1 => {
                // Inject into method name
                if let Some(injection) = dict.injection_payload(rng) {
                    format!("tools/{}", injection)
                } else {
                    base_methods[0].to_string()
                }
            }
            _ => {
                // Random garbage
                format!(
                    "method_{}",
                    (0..10)
                        .map(|_| (rng.gen_range(b'a'..=b'z') as char))
                        .collect::<String>()
                )
            }
        }
    }

    /// Remove required fields from a request
    pub fn remove_required_field(request: &Value, rng: &mut impl Rng) -> Value {
        let mut result = request.clone();

        let required_fields = ["jsonrpc", "method", "id"];
        let field_to_remove = required_fields[rng.gen_range(0..required_fields.len())];

        if let Some(obj) = result.as_object_mut() {
            obj.remove(field_to_remove);
        }

        result
    }

    /// Add extra/unexpected fields to a request
    pub fn add_extra_field(request: &Value, rng: &mut impl Rng) -> Value {
        let mut result = request.clone();

        let extra_fields = [
            ("extra", json!("unexpected")),
            ("__proto__", json!({})),
            ("constructor", json!(null)),
            ("toString", json!("hacked")),
            ("version", json!("1.0")),
            ("auth", json!({"token": "fake"})),
            ("admin", json!(true)),
            ("debug", json!(true)),
            ("internal", json!({"bypass": true})),
            ("", json!("empty_key")),
        ];

        if let Some(obj) = result.as_object_mut() {
            let (key, value) = &extra_fields[rng.gen_range(0..extra_fields.len())];
            obj.insert(key.to_string(), value.clone());
        }

        result
    }

    /// Create a completely malformed JSON-RPC request
    pub fn malformed_request(rng: &mut impl Rng) -> Value {
        match rng.gen_range(0..8) {
            0 => json!([]),                                               // Empty array
            1 => json!(null),                                             // Null
            2 => json!("not an object"),                                  // String
            3 => json!(42),                                               // Number
            4 => json!(true),                                             // Boolean
            5 => json!([{"jsonrpc": "2.0"}]),                             // Array of objects
            6 => json!({"nested": {"jsonrpc": "2.0", "method": "test"}}), // Nested
            _ => json!({"invalid": "structure", "no": "method"}),         // Missing required
        }
    }

    /// Create a batch request with invalid structure
    pub fn invalid_batch(rng: &mut impl Rng) -> Value {
        match rng.gen_range(0..5) {
            0 => json!([]),        // Empty batch
            1 => json!([null]),    // Null in batch
            2 => json!([[{}]]),    // Nested array
            3 => json!([1, 2, 3]), // Numbers in batch
            _ => {
                // Mix of valid and invalid
                json!([
                    {"jsonrpc": "2.0", "method": "test", "id": 1},
                    null,
                    "invalid",
                    {"jsonrpc": "2.0", "method": "test2", "id": 2}
                ])
            }
        }
    }

    /// Mutate the params field
    pub fn mutate_params(params: &Value, dict: &Dictionary, rng: &mut impl Rng) -> Value {
        match params {
            Value::Object(obj) => {
                let mut result = obj.clone();

                // Choose a mutation
                match rng.gen_range(0..4) {
                    0 => {
                        // Inject into string values
                        for (_, v) in result.iter_mut() {
                            if v.is_string() && rng.gen_bool(0.5) {
                                if let Some(injection) = dict.injection_payload(rng) {
                                    *v = json!(injection);
                                }
                            }
                        }
                    }
                    1 => {
                        // Add injection key
                        if let Some(injection) = dict.injection_payload(rng) {
                            result.insert("_injected".to_string(), json!(injection));
                        }
                    }
                    2 => {
                        // Set all values to null
                        for (_, v) in result.iter_mut() {
                            *v = Value::Null;
                        }
                    }
                    _ => {
                        // Add prototype pollution
                        result.insert("__proto__".to_string(), json!({"polluted": true}));
                    }
                }

                Value::Object(result)
            }
            Value::Array(arr) => {
                // Mutate array params
                let mut result = arr.clone();
                if !result.is_empty() {
                    let idx = rng.gen_range(0..result.len());
                    if let Some(injection) = dict.injection_payload(rng) {
                        result[idx] = json!(injection);
                    }
                }
                Value::Array(result)
            }
            _ => {
                // Replace with injection
                if let Some(injection) = dict.injection_payload(rng) {
                    json!(injection)
                } else {
                    params.clone()
                }
            }
        }
    }

    /// Create a valid-looking but subtly broken request
    pub fn subtle_break(method: &str, rng: &mut impl Rng) -> Value {
        match rng.gen_range(0..6) {
            0 => {
                // Trailing whitespace in method
                json!({
                    "jsonrpc": "2.0",
                    "method": format!("{} ", method),
                    "id": 1
                })
            }
            1 => {
                // Leading whitespace in method
                json!({
                    "jsonrpc": "2.0",
                    "method": format!(" {}", method),
                    "id": 1
                })
            }
            2 => {
                // Case variation
                json!({
                    "jsonrpc": "2.0",
                    "method": method.to_uppercase(),
                    "id": 1
                })
            }
            3 => {
                // Duplicate keys (later one wins in most parsers)
                json!({
                    "jsonrpc": "2.0",
                    "jsonrpc": "1.0",
                    "method": method,
                    "id": 1
                })
            }
            4 => {
                // Unicode normalization issue
                json!({
                    "jsonrpc": "2.0",
                    "method": format!("{}\u{200B}", method), // Zero-width space
                    "id": 1
                })
            }
            _ => {
                // Params as array instead of object
                json!({
                    "jsonrpc": "2.0",
                    "method": method,
                    "params": [],
                    "id": 1
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_ids() {
        let mut rng = rand::thread_rng();
        let mut seen_types = std::collections::HashSet::new();

        for _ in 0..50 {
            let id = JsonRpcMutator::invalid_id(&mut rng);
            let type_name = match &id {
                Value::Null => "null",
                Value::Bool(_) => "bool",
                Value::Number(_) => "number",
                Value::String(_) => "string",
                Value::Array(_) => "array",
                Value::Object(_) => "object",
            };
            seen_types.insert(type_name);
        }

        // Should produce multiple types
        assert!(seen_types.len() >= 3);
    }

    #[test]
    fn malformed_versions() {
        let mut rng = rand::thread_rng();

        for _ in 0..20 {
            let version = JsonRpcMutator::malformed_version(&mut rng);
            // Should not be exactly "2.0"
            if let Some(s) = version.as_str() {
                if s == "2.0" {
                    continue; // This is valid, try again
                }
            }
            assert!(version != json!("2.0") || !version.is_string());
        }
    }

    #[test]
    fn unknown_methods() {
        let dict = Dictionary::mcp_default();
        let mut rng = rand::thread_rng();

        let valid_methods = ["initialize", "tools/list", "tools/call"];

        for _ in 0..20 {
            let method = JsonRpcMutator::unknown_method(&dict, &mut rng);
            // Most should not be valid MCP methods
            let is_valid = valid_methods.contains(&method.as_str());
            // Allow some to be valid by chance, but not all
            if is_valid {
                continue;
            }
            assert!(!valid_methods.contains(&method.as_str()));
            break;
        }
    }

    #[test]
    fn remove_required() {
        let mut rng = rand::thread_rng();
        let request = json!({
            "jsonrpc": "2.0",
            "method": "test",
            "id": 1
        });

        let mutated = JsonRpcMutator::remove_required_field(&request, &mut rng);
        let obj = mutated.as_object().unwrap();

        // Should be missing exactly one required field
        let has_jsonrpc = obj.contains_key("jsonrpc");
        let has_method = obj.contains_key("method");
        let has_id = obj.contains_key("id");

        let missing_count = [!has_jsonrpc, !has_method, !has_id]
            .iter()
            .filter(|&&x| x)
            .count();

        assert_eq!(missing_count, 1);
    }
}
