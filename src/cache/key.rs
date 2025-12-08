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
    pub fn to_path_components(&self) -> (String, String) {
        (
            self.category.to_string(),
            format!("{}.json", self.identifier),
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
}
