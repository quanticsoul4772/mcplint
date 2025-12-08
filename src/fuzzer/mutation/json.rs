//! JSON Mutations - JSON-level mutation operations
//!
//! Provides mutations that operate at the JSON value level,
//! including type confusion, boundary values, deep nesting, and unicode injection.

use rand::Rng;
use serde_json::{json, Map, Value};

use super::dictionary::{Dictionary, TokenCategory};

/// JSON-level mutation operations
pub struct JsonMutator;

impl JsonMutator {
    /// Type confusion: change value types randomly
    pub fn type_confuse(value: &Value, rng: &mut impl Rng) -> Value {
        match value {
            Value::String(s) => match rng.gen_range(0..6) {
                0 => Value::Number(s.len().into()),
                1 => Value::Bool(!s.is_empty()),
                2 => json!([s]),
                3 => json!({"value": s}),
                4 => Value::Null,
                _ => Value::Number((-1_i64).into()),
            },
            Value::Number(n) => match rng.gen_range(0..5) {
                0 => Value::String(n.to_string()),
                1 => Value::Bool(n.as_f64().unwrap_or(0.0) != 0.0),
                2 => json!([n]),
                3 => Value::Null,
                _ => Value::String(format!("{}x", n)),
            },
            Value::Bool(b) => match rng.gen_range(0..5) {
                0 => Value::String(b.to_string()),
                1 => Value::Number(if *b { 1 } else { 0 }.into()),
                2 => json!([b]),
                3 => Value::Null,
                _ => Value::String(if *b { "yes" } else { "no" }.to_string()),
            },
            Value::Array(arr) => match rng.gen_range(0..4) {
                0 => Value::String(format!("{:?}", arr)),
                1 => json!({"array": arr}),
                2 => Value::Null,
                _ => {
                    if arr.is_empty() {
                        json!([null])
                    } else {
                        arr.first().cloned().unwrap_or(Value::Null)
                    }
                }
            },
            Value::Object(obj) => match rng.gen_range(0..4) {
                0 => Value::String(serde_json::to_string(obj).unwrap_or_default()),
                1 => json!([obj]),
                2 => Value::Null,
                _ => {
                    if obj.is_empty() {
                        json!({"key": "value"})
                    } else {
                        obj.values().next().cloned().unwrap_or(Value::Null)
                    }
                }
            },
            Value::Null => match rng.gen_range(0..5) {
                0 => Value::String("null".to_string()),
                1 => Value::Number(0.into()),
                2 => Value::Bool(false),
                3 => json!([]),
                _ => json!({}),
            },
        }
    }

    /// Boundary values for various types
    pub fn boundary_value(value: &Value, rng: &mut impl Rng) -> Value {
        match value {
            Value::Number(_) => {
                let boundaries: &[i64] = &[
                    i64::MAX,
                    i64::MIN,
                    i32::MAX as i64,
                    i32::MIN as i64,
                    0,
                    -1,
                    1,
                    -0,
                    i16::MAX as i64,
                    i16::MIN as i64,
                    255,
                    256,
                    -128,
                    127,
                ];
                Value::Number(boundaries[rng.gen_range(0..boundaries.len())].into())
            }
            Value::String(_) => {
                let boundaries = [
                    "",
                    " ",
                    "\0",
                    "\n",
                    "\r\n",
                    "\t",
                    &"a".repeat(10000),
                    &"A".repeat(65536),
                    "null",
                    "undefined",
                    "NaN",
                    "Infinity",
                    "-Infinity",
                    "true",
                    "false",
                    "0",
                    "-1",
                ];
                Value::String(boundaries[rng.gen_range(0..boundaries.len())].to_string())
            }
            Value::Array(_) => {
                let idx = rng.gen_range(0..6);
                match idx {
                    0 => json!([]),
                    1 => json!([null]),
                    2 => json!([[]]),
                    3 => Value::Array(vec![Value::Array(vec![Value::Array(vec![])]); 5]),
                    4 => Value::Array(vec![Value::Null; 1000]),
                    _ => json!([0, 1, 2, 3, 4, 5, 6, 7, 8, 9]),
                }
            }
            Value::Object(_) => {
                let choices: &[Value] = &[
                    json!({}),
                    json!({"": ""}),
                    json!({"null": null}),
                    json!({"__proto__": {}}),
                    json!({"constructor": {}}),
                    json!({"toString": null}),
                ];
                choices[rng.gen_range(0..choices.len())].clone()
            }
            Value::Bool(_) => {
                // Bools only have two values, but we can return unexpected types
                if rng.gen_bool(0.5) {
                    Value::Bool(rng.gen_bool(0.5))
                } else {
                    Value::String(if rng.gen_bool(0.5) { "true" } else { "false" }.to_string())
                }
            }
            Value::Null => {
                let choices: &[Value] = &[
                    Value::Null,
                    Value::String("null".to_string()),
                    Value::String("".to_string()),
                    Value::Number(0.into()),
                    Value::Bool(false),
                ];
                choices[rng.gen_range(0..choices.len())].clone()
            }
        }
    }

    /// Deep nesting to stress parsers
    pub fn deep_nest(depth: usize, array_mode: bool) -> Value {
        let mut v = json!("leaf");
        for _ in 0..depth {
            if array_mode {
                v = json!([v]);
            } else {
                v = json!({"nested": v});
            }
        }
        v
    }

    /// Unicode injection payloads
    pub fn unicode_inject(s: &str, dict: &Dictionary, rng: &mut impl Rng) -> String {
        let injection = dict
            .random_from(TokenCategory::Unicode, rng)
            .unwrap_or("\u{0000}");

        match rng.gen_range(0..4) {
            0 => format!("{}{}", injection, s),              // Prepend
            1 => format!("{}{}", s, injection),              // Append
            2 => format!("{}{}{}", s, injection, s),         // Middle
            _ => format!("{}{}{}", injection, s, injection), // Surround
        }
    }

    /// String mutation: bit flips, insertions, deletions
    pub fn mutate_string(s: &str, rng: &mut impl Rng) -> String {
        if s.is_empty() {
            return "a".to_string();
        }

        let mut chars: Vec<char> = s.chars().collect();

        match rng.gen_range(0..6) {
            0 => {
                // Delete random character
                if !chars.is_empty() {
                    let idx = rng.gen_range(0..chars.len());
                    chars.remove(idx);
                }
            }
            1 => {
                // Insert random character
                let idx = rng.gen_range(0..=chars.len());
                let c = (rng.gen_range(32u8..127u8)) as char;
                chars.insert(idx, c);
            }
            2 => {
                // Replace random character
                if !chars.is_empty() {
                    let idx = rng.gen_range(0..chars.len());
                    chars[idx] = (rng.gen_range(32u8..127u8)) as char;
                }
            }
            3 => {
                // Duplicate string
                let s: String = chars.iter().collect();
                return format!("{}{}", s, s);
            }
            4 => {
                // Reverse string
                chars.reverse();
            }
            _ => {
                // Uppercase/lowercase flip
                for c in &mut chars {
                    if c.is_uppercase() {
                        *c = c.to_lowercase().next().unwrap_or(*c);
                    } else if c.is_lowercase() {
                        *c = c.to_uppercase().next().unwrap_or(*c);
                    }
                }
            }
        }

        chars.into_iter().collect()
    }

    /// Mutate a JSON object by modifying its structure
    pub fn mutate_object(obj: &Map<String, Value>, rng: &mut impl Rng) -> Map<String, Value> {
        let mut result = obj.clone();

        match rng.gen_range(0..5) {
            0 => {
                // Remove random key
                if !result.is_empty() {
                    let keys: Vec<String> = result.keys().cloned().collect();
                    let key = &keys[rng.gen_range(0..keys.len())];
                    result.remove(key);
                }
            }
            1 => {
                // Add random key
                let key = format!("fuzz_{}", rng.gen_range(0..1000));
                result.insert(key, json!("fuzzed"));
            }
            2 => {
                // Duplicate a key's value to another key
                if !result.is_empty() {
                    let keys: Vec<String> = result.keys().cloned().collect();
                    let key = &keys[rng.gen_range(0..keys.len())];
                    if let Some(value) = result.get(key).cloned() {
                        result.insert(format!("{}_dup", key), value);
                    }
                }
            }
            3 => {
                // Set a value to null
                if !result.is_empty() {
                    let keys: Vec<String> = result.keys().cloned().collect();
                    let key = &keys[rng.gen_range(0..keys.len())];
                    result.insert(key.clone(), Value::Null);
                }
            }
            _ => {
                // Add prototype pollution attempt
                result.insert("__proto__".to_string(), json!({"polluted": true}));
            }
        }

        result
    }

    /// Mutate a JSON array by modifying its structure
    pub fn mutate_array(arr: &[Value], rng: &mut impl Rng) -> Vec<Value> {
        let mut result = arr.to_vec();

        match rng.gen_range(0..5) {
            0 => {
                // Remove random element
                if !result.is_empty() {
                    let idx = rng.gen_range(0..result.len());
                    result.remove(idx);
                }
            }
            1 => {
                // Add random element
                result.push(json!("fuzzed"));
            }
            2 => {
                // Duplicate array
                let copy = result.clone();
                result.extend(copy);
            }
            3 => {
                // Reverse array
                result.reverse();
            }
            _ => {
                // Insert null at random position
                if result.is_empty() {
                    result.push(Value::Null);
                } else {
                    let idx = rng.gen_range(0..=result.len());
                    result.insert(idx, Value::Null);
                }
            }
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn type_confusion_string() {
        let value = json!("test");
        let mut rng = rand::thread_rng();

        for _ in 0..10 {
            let mutated = JsonMutator::type_confuse(&value, &mut rng);
            assert!(!matches!(mutated, Value::String(s) if s == "test"));
        }
    }

    #[test]
    fn boundary_values() {
        let mut rng = rand::thread_rng();

        let num = json!(42);
        let boundary = JsonMutator::boundary_value(&num, &mut rng);
        assert!(boundary.is_number());

        let str = json!("hello");
        let boundary = JsonMutator::boundary_value(&str, &mut rng);
        assert!(boundary.is_string());
    }

    #[test]
    fn deep_nesting() {
        let nested_obj = JsonMutator::deep_nest(10, false);
        let json_str = serde_json::to_string(&nested_obj).unwrap();
        assert!(json_str.contains("nested"));

        let nested_arr = JsonMutator::deep_nest(10, true);
        let json_str = serde_json::to_string(&nested_arr).unwrap();
        assert!(json_str.starts_with('['));
    }

    #[test]
    fn string_mutation() {
        let mut rng = rand::thread_rng();
        let original = "hello world";

        for _ in 0..10 {
            let mutated = JsonMutator::mutate_string(original, &mut rng);
            // Should produce some variation
            assert!(!mutated.is_empty() || original.is_empty());
        }
    }

    #[test]
    fn object_mutation() {
        let mut rng = rand::thread_rng();
        let obj: Map<String, Value> =
            serde_json::from_str(r#"{"key": "value", "num": 42}"#).unwrap();

        for _ in 0..10 {
            let mutated = JsonMutator::mutate_object(&obj, &mut rng);
            // Should have some difference
            assert!(mutated.len() != obj.len() || mutated != obj);
        }
    }
}
