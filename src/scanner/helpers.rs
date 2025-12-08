//! Schema Analysis Helpers
//!
//! Helper functions for analyzing JSON Schema structures in tool definitions.
//! These functions are prepared for future migration from engine.rs.

#![allow(dead_code)] // Prepared for future migration

/// Check if a schema has string parameters
pub fn has_string_parameters(schema: &serde_json::Value) -> bool {
    if let Some(props) = schema.get("properties").and_then(|p| p.as_object()) {
        for prop in props.values() {
            if let Some(t) = prop.get("type").and_then(|t| t.as_str()) {
                if t == "string" {
                    return true;
                }
            }
        }
    }
    false
}

/// Check if a schema has path-related parameters
pub fn has_path_parameters(schema: &serde_json::Value) -> bool {
    let path_names = ["path", "file", "filename", "filepath", "directory", "dir"];

    if let Some(props) = schema.get("properties").and_then(|p| p.as_object()) {
        for name in props.keys() {
            let name_lower = name.to_lowercase();
            for pattern in &path_names {
                if name_lower.contains(pattern) {
                    return true;
                }
            }
        }
    }
    false
}

/// Check if a schema has URL-related parameters
pub fn has_url_parameters(schema: &serde_json::Value) -> bool {
    let url_names = ["url", "uri", "href", "link", "endpoint"];

    if let Some(props) = schema.get("properties").and_then(|p| p.as_object()) {
        for name in props.keys() {
            let name_lower = name.to_lowercase();
            for pattern in &url_names {
                if name_lower.contains(pattern) {
                    return true;
                }
            }
        }
    }
    false
}

/// Check if a schema has limit/pagination parameters
pub fn has_limit_parameters(schema: &serde_json::Value) -> bool {
    let limit_names = ["limit", "max", "size", "count", "page_size", "per_page"];

    if let Some(props) = schema.get("properties").and_then(|p| p.as_object()) {
        for name in props.keys() {
            let name_lower = name.to_lowercase();
            for pattern in &limit_names {
                if name_lower.contains(pattern) {
                    return true;
                }
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_analysis() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "query": { "type": "string" },
                "count": { "type": "integer" }
            }
        });

        assert!(has_string_parameters(&schema));
        assert!(!has_path_parameters(&schema));

        let path_schema = serde_json::json!({
            "type": "object",
            "properties": {
                "file_path": { "type": "string" }
            }
        });

        assert!(has_path_parameters(&path_schema));
    }

    #[test]
    fn url_parameter_detection() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "target_url": { "type": "string" }
            }
        });

        assert!(has_url_parameters(&schema));
    }

    #[test]
    fn limit_parameter_detection() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "max_results": { "type": "integer" }
            }
        });

        assert!(has_limit_parameters(&schema));
    }
}
