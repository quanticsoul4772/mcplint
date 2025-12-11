//! Cache Key - Type-safe cache key definitions
//!
//! Provides strongly-typed cache keys with categories
//! for organizing cached data.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::hash::{Hash, Hasher};

/// Cache key categories for organizing cached data
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheCategory {
    /// Tool/resource schemas from servers
    Schema,
    /// Scan results from security analysis
    ScanResult,
    /// Protocol validation results
    Validation,
    /// Fuzzer corpus data
    Corpus,
    /// Tool hashes for rug-pull detection
    ToolHash,
    /// AI response cache (future: M5)
    AiResponse,
}

impl fmt::Display for CacheCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CacheCategory::Schema => write!(f, "schemas"),
            CacheCategory::ScanResult => write!(f, "scan_results"),
            CacheCategory::Validation => write!(f, "validation"),
            CacheCategory::Corpus => write!(f, "corpus"),
            CacheCategory::ToolHash => write!(f, "tool_hashes"),
            CacheCategory::AiResponse => write!(f, "ai_responses"),
        }
    }
}

impl CacheCategory {
    /// Get all categories
    pub fn all() -> &'static [CacheCategory] {
        &[
            CacheCategory::Schema,
            CacheCategory::ScanResult,
            CacheCategory::Validation,
            CacheCategory::Corpus,
            CacheCategory::ToolHash,
            CacheCategory::AiResponse,
        ]
    }

    /// Parse from string
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "schema" | "schemas" => Some(CacheCategory::Schema),
            "scan_result" | "scan_results" | "scanresult" => Some(CacheCategory::ScanResult),
            "validation" => Some(CacheCategory::Validation),
            "corpus" => Some(CacheCategory::Corpus),
            "tool_hash" | "tool_hashes" | "toolhash" => Some(CacheCategory::ToolHash),
            "ai_response" | "ai_responses" | "airesponse" => Some(CacheCategory::AiResponse),
            _ => None,
        }
    }
}

/// Type-safe cache key with category and identifier
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheKey {
    /// The category this key belongs to
    pub category: CacheCategory,
    /// Unique identifier within the category
    pub identifier: String,
}

impl Hash for CacheKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.category.hash(state);
        self.identifier.hash(state);
    }
}

impl fmt::Display for CacheKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.category, self.identifier)
    }
}

impl CacheKey {
    /// Create a new cache key
    pub fn new(category: CacheCategory, identifier: impl Into<String>) -> Self {
        Self {
            category,
            identifier: identifier.into(),
        }
    }

    /// Create a schema cache key from server hash
    pub fn schema(server_hash: &str) -> Self {
        Self::new(CacheCategory::Schema, server_hash)
    }

    /// Create a scan result cache key from server and ruleset hashes
    pub fn scan_result(server_hash: &str, ruleset_hash: &str) -> Self {
        Self::new(
            CacheCategory::ScanResult,
            format!("{}_{}", server_hash, ruleset_hash),
        )
    }

    /// Create a validation cache key from server hash and protocol version
    pub fn validation(server_hash: &str, protocol_version: &str) -> Self {
        Self::new(
            CacheCategory::Validation,
            format!("{}_{}", server_hash, protocol_version),
        )
    }

    /// Create a corpus cache key from server identifier
    pub fn corpus(server_id: &str) -> Self {
        Self::new(CacheCategory::Corpus, server_id)
    }

    /// Create a tool hash cache key for rug-pull detection
    pub fn tool_hash(server_id: &str) -> Self {
        Self::new(CacheCategory::ToolHash, server_id)
    }

    /// Create an AI response cache key
    pub fn ai_response(query_hash: &str) -> Self {
        Self::new(CacheCategory::AiResponse, query_hash)
    }

    /// Get the Redis key representation with prefix
    pub fn to_redis_key(&self, prefix: &str) -> String {
        format!("{}:{}:{}", prefix, self.category, self.identifier)
    }

    /// Get the filesystem path components
    ///
    /// Sanitizes the identifier to be safe for use as a filename on all platforms.
    /// Replaces characters that are invalid in Windows filenames: < > : " / \ | ? *
    pub fn to_path_components(&self) -> (String, String) {
        // Replace characters invalid in Windows/Unix filenames
        let safe_identifier = self
            .identifier
            .replace(':', "_")
            .replace('<', "_")
            .replace('>', "_")
            .replace('"', "_")
            .replace('/', "_")
            .replace('\\', "_")
            .replace('|', "_")
            .replace('?', "_")
            .replace('*', "_");

        (
            self.category.to_string(),
            format!("{}.json", safe_identifier),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_key_creation() {
        let key = CacheKey::schema("abc123");
        assert_eq!(key.category, CacheCategory::Schema);
        assert_eq!(key.identifier, "abc123");
    }

    #[test]
    fn cache_key_display() {
        let key = CacheKey::scan_result("server1", "rules1");
        assert_eq!(key.to_string(), "scan_results:server1_rules1");
    }

    #[test]
    fn redis_key_format() {
        let key = CacheKey::schema("test");
        assert_eq!(key.to_redis_key("mcplint"), "mcplint:schemas:test");
    }

    #[test]
    fn path_components() {
        let key = CacheKey::validation("server", "2024-11-05");
        let (dir, file) = key.to_path_components();
        assert_eq!(dir, "validation");
        assert_eq!(file, "server_2024-11-05.json");
    }

    #[test]
    fn path_components_sanitizes_colons() {
        // Test that colons (invalid on Windows) are replaced with underscores
        let key = CacheKey::new(CacheCategory::AiResponse, "1:model:uuid:rule:audience");
        let (dir, file) = key.to_path_components();
        assert_eq!(dir, "ai_responses");
        assert_eq!(file, "1_model_uuid_rule_audience.json");
    }

    #[test]
    fn path_components_sanitizes_all_invalid_chars() {
        // Test all Windows-invalid characters: < > : " / \ | ? *
        let key = CacheKey::new(CacheCategory::Schema, "a<b>c:d\"e/f\\g|h?i*j");
        let (_, file) = key.to_path_components();
        assert_eq!(file, "a_b_c_d_e_f_g_h_i_j.json");
    }

    #[test]
    fn category_parsing() {
        assert_eq!(
            CacheCategory::from_str("schemas"),
            Some(CacheCategory::Schema)
        );
        assert_eq!(
            CacheCategory::from_str("VALIDATION"),
            Some(CacheCategory::Validation)
        );
        assert_eq!(CacheCategory::from_str("invalid"), None);
    }

    #[test]
    fn category_parsing_all_variants() {
        assert_eq!(
            CacheCategory::from_str("schema"),
            Some(CacheCategory::Schema)
        );
        assert_eq!(
            CacheCategory::from_str("scan_result"),
            Some(CacheCategory::ScanResult)
        );
        assert_eq!(
            CacheCategory::from_str("scan_results"),
            Some(CacheCategory::ScanResult)
        );
        assert_eq!(
            CacheCategory::from_str("scanresult"),
            Some(CacheCategory::ScanResult)
        );
        assert_eq!(
            CacheCategory::from_str("corpus"),
            Some(CacheCategory::Corpus)
        );
        assert_eq!(
            CacheCategory::from_str("tool_hash"),
            Some(CacheCategory::ToolHash)
        );
        assert_eq!(
            CacheCategory::from_str("tool_hashes"),
            Some(CacheCategory::ToolHash)
        );
        assert_eq!(
            CacheCategory::from_str("toolhash"),
            Some(CacheCategory::ToolHash)
        );
        assert_eq!(
            CacheCategory::from_str("ai_response"),
            Some(CacheCategory::AiResponse)
        );
        assert_eq!(
            CacheCategory::from_str("ai_responses"),
            Some(CacheCategory::AiResponse)
        );
        assert_eq!(
            CacheCategory::from_str("airesponse"),
            Some(CacheCategory::AiResponse)
        );
    }

    #[test]
    fn category_all() {
        let all = CacheCategory::all();
        assert_eq!(all.len(), 6);
        assert!(all.contains(&CacheCategory::Schema));
        assert!(all.contains(&CacheCategory::ScanResult));
        assert!(all.contains(&CacheCategory::Validation));
        assert!(all.contains(&CacheCategory::Corpus));
        assert!(all.contains(&CacheCategory::ToolHash));
        assert!(all.contains(&CacheCategory::AiResponse));
    }

    #[test]
    fn category_display() {
        assert_eq!(CacheCategory::Schema.to_string(), "schemas");
        assert_eq!(CacheCategory::ScanResult.to_string(), "scan_results");
        assert_eq!(CacheCategory::Validation.to_string(), "validation");
        assert_eq!(CacheCategory::Corpus.to_string(), "corpus");
        assert_eq!(CacheCategory::ToolHash.to_string(), "tool_hashes");
        assert_eq!(CacheCategory::AiResponse.to_string(), "ai_responses");
    }

    #[test]
    fn cache_key_new() {
        let key = CacheKey::new(CacheCategory::Schema, "test-identifier");
        assert_eq!(key.category, CacheCategory::Schema);
        assert_eq!(key.identifier, "test-identifier");
    }

    #[test]
    fn cache_key_corpus() {
        let key = CacheKey::corpus("my-server");
        assert_eq!(key.category, CacheCategory::Corpus);
        assert_eq!(key.identifier, "my-server");
    }

    #[test]
    fn cache_key_tool_hash() {
        let key = CacheKey::tool_hash("server-id");
        assert_eq!(key.category, CacheCategory::ToolHash);
        assert_eq!(key.identifier, "server-id");
    }

    #[test]
    fn cache_key_ai_response() {
        let key = CacheKey::ai_response("query-hash-123");
        assert_eq!(key.category, CacheCategory::AiResponse);
        assert_eq!(key.identifier, "query-hash-123");
    }

    #[test]
    fn cache_key_hash_equality() {
        use std::collections::HashSet;
        let key1 = CacheKey::schema("abc");
        let key2 = CacheKey::schema("abc");
        let key3 = CacheKey::schema("xyz");

        let mut set = HashSet::new();
        set.insert(key1.clone());
        assert!(set.contains(&key2));
        assert!(!set.contains(&key3));
    }

    #[test]
    fn cache_key_display_all_categories() {
        assert_eq!(CacheKey::schema("test").to_string(), "schemas:test");
        assert_eq!(CacheKey::corpus("test").to_string(), "corpus:test");
        assert_eq!(CacheKey::tool_hash("test").to_string(), "tool_hashes:test");
        assert_eq!(
            CacheKey::ai_response("test").to_string(),
            "ai_responses:test"
        );
    }
}
