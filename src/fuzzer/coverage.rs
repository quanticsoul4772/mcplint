//! Coverage Tracker - Track execution coverage for guided fuzzing
//!
//! Tracks unique execution paths based on response characteristics
//! to guide the fuzzer toward new code paths.

use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::detection::{FuzzResponse, FuzzResponseResult};
use super::input::FuzzInput;

/// Tracks execution coverage for guided fuzzing
pub struct CoverageTracker {
    /// Hash of all seen paths
    seen_paths: HashSet<u64>,
    /// Edge hit counts (path -> count)
    edge_counts: HashMap<u64, u32>,
    /// Total inputs processed
    total_inputs: u64,
    /// Inputs that found new coverage
    coverage_inputs: u64,
    /// Method-specific coverage
    method_coverage: HashMap<String, HashSet<u64>>,
}

impl Default for CoverageTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl CoverageTracker {
    /// Create a new coverage tracker
    pub fn new() -> Self {
        Self {
            seen_paths: HashSet::new(),
            edge_counts: HashMap::new(),
            total_inputs: 0,
            coverage_inputs: 0,
            method_coverage: HashMap::new(),
        }
    }

    /// Hash a response to track coverage
    /// Uses response structure, error codes, and method
    pub fn hash_response(&self, input: &FuzzInput, response: &FuzzResponse) -> u64 {
        let mut hasher = DefaultHasher::new();

        // Include method in hash
        input.method.hash(&mut hasher);

        // Hash response type and characteristics
        match &response.result {
            FuzzResponseResult::Success(v) => {
                "success".hash(&mut hasher);
                // Hash structure, not values (for coverage tracking)
                self.hash_json_structure(v, &mut hasher);
            }
            FuzzResponseResult::Error(e) => {
                "error".hash(&mut hasher);
                e.code.hash(&mut hasher);
                // Hash message pattern (first 50 chars)
                e.message
                    .chars()
                    .take(50)
                    .collect::<String>()
                    .hash(&mut hasher);
            }
            FuzzResponseResult::Timeout => {
                "timeout".hash(&mut hasher);
            }
            FuzzResponseResult::ConnectionLost(reason) => {
                "connection_lost".hash(&mut hasher);
                reason
                    .chars()
                    .take(20)
                    .collect::<String>()
                    .hash(&mut hasher);
            }
            FuzzResponseResult::ProcessExit(code) => {
                "exit".hash(&mut hasher);
                code.hash(&mut hasher);
            }
        }

        // Include response time bucket (for timing-based coverage)
        let time_bucket = response.response_time_ms / 100; // 100ms buckets
        time_bucket.hash(&mut hasher);

        hasher.finish()
    }

    /// Hash JSON structure (types and keys, not values)
    fn hash_json_structure(&self, value: &Value, hasher: &mut impl Hasher) {
        match value {
            Value::Null => "null".hash(hasher),
            Value::Bool(_) => "bool".hash(hasher),
            Value::Number(_) => "number".hash(hasher),
            Value::String(_) => "string".hash(hasher),
            Value::Array(arr) => {
                "array".hash(hasher);
                arr.len().hash(hasher);
                // Hash structure of first few elements
                for item in arr.iter().take(3) {
                    self.hash_json_structure(item, hasher);
                }
            }
            Value::Object(obj) => {
                "object".hash(hasher);
                obj.len().hash(hasher);
                // Hash keys (sorted for consistency)
                let mut keys: Vec<_> = obj.keys().collect();
                keys.sort();
                for key in keys.iter().take(10) {
                    key.hash(hasher);
                    if let Some(v) = obj.get(*key) {
                        self.hash_json_structure(v, hasher);
                    }
                }
            }
        }
    }

    /// Record execution and return whether it's new coverage
    pub fn record(&mut self, input: &FuzzInput, response: &FuzzResponse) -> bool {
        let hash = self.hash_response(input, response);
        self.total_inputs += 1;

        // Track method-specific coverage
        let method_paths = self
            .method_coverage
            .entry(input.method.clone())
            .or_default();
        method_paths.insert(hash);

        // Check if this is new global coverage
        if self.seen_paths.insert(hash) {
            self.coverage_inputs += 1;
            *self.edge_counts.entry(hash).or_insert(0) += 1;
            true
        } else {
            *self.edge_counts.get_mut(&hash).unwrap() += 1;
            false
        }
    }

    /// Get coverage statistics
    pub fn stats(&self) -> CoverageStats {
        let total_edges = self.edge_counts.len();
        let edge_coverage = if total_edges > 0 {
            // Normalize to a reasonable scale
            (total_edges as f64 / 100.0).min(1.0)
        } else {
            0.0
        };

        let new_coverage_rate = if self.total_inputs > 0 {
            self.coverage_inputs as f64 / self.total_inputs as f64
        } else {
            0.0
        };

        CoverageStats {
            paths_explored: self.seen_paths.len(),
            edge_coverage,
            new_coverage_rate,
        }
    }

    /// Get the number of unique paths seen
    pub fn unique_paths(&self) -> usize {
        self.seen_paths.len()
    }

    /// Get the number of total inputs processed
    pub fn total_inputs(&self) -> u64 {
        self.total_inputs
    }

    /// Get coverage by method
    pub fn method_coverage(&self) -> &HashMap<String, HashSet<u64>> {
        &self.method_coverage
    }

    /// Get the hit count for a specific path
    pub fn hit_count(&self, hash: u64) -> u32 {
        self.edge_counts.get(&hash).copied().unwrap_or(0)
    }

    /// Check if a path has been seen
    pub fn has_seen(&self, hash: u64) -> bool {
        self.seen_paths.contains(&hash)
    }

    /// Reset coverage tracking
    pub fn reset(&mut self) {
        self.seen_paths.clear();
        self.edge_counts.clear();
        self.total_inputs = 0;
        self.coverage_inputs = 0;
        self.method_coverage.clear();
    }
}

/// Coverage statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageStats {
    /// Number of unique paths explored
    pub paths_explored: usize,
    /// Edge coverage ratio (0.0 to 1.0)
    pub edge_coverage: f64,
    /// Rate of inputs finding new coverage
    pub new_coverage_rate: f64,
}

impl Default for CoverageStats {
    fn default() -> Self {
        Self {
            paths_explored: 0,
            edge_coverage: 0.0,
            new_coverage_rate: 0.0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_tracker() {
        let tracker = CoverageTracker::new();
        assert_eq!(tracker.unique_paths(), 0);
        assert_eq!(tracker.total_inputs(), 0);
    }

    #[test]
    fn record_new_coverage() {
        let mut tracker = CoverageTracker::new();

        let input = FuzzInput::tools_list();
        let response = FuzzResponse::success(serde_json::json!({"tools": []}));

        let is_new = tracker.record(&input, &response);
        assert!(is_new);
        assert_eq!(tracker.unique_paths(), 1);
    }

    #[test]
    fn duplicate_not_new() {
        let mut tracker = CoverageTracker::new();

        let input = FuzzInput::tools_list();
        let response1 = FuzzResponse::success(serde_json::json!({"tools": []}));
        let response2 = FuzzResponse::success(serde_json::json!({"tools": []}));

        tracker.record(&input, &response1);
        let is_new = tracker.record(&input, &response2);

        assert!(!is_new);
        assert_eq!(tracker.unique_paths(), 1);
        assert_eq!(tracker.total_inputs(), 2);
    }

    #[test]
    fn different_responses_different_coverage() {
        let mut tracker = CoverageTracker::new();

        let input = FuzzInput::tools_list();
        let success = FuzzResponse::success(serde_json::json!({"tools": []}));
        let error = FuzzResponse::error(-32601, "Method not found");

        tracker.record(&input, &success);
        tracker.record(&input, &error);

        assert_eq!(tracker.unique_paths(), 2);
    }

    #[test]
    fn different_methods_different_coverage() {
        let mut tracker = CoverageTracker::new();

        let input1 = FuzzInput::tools_list();
        let input2 = FuzzInput::resources_list();
        let response = FuzzResponse::success(serde_json::json!({}));

        tracker.record(&input1, &response);
        tracker.record(&input2, &response);

        assert_eq!(tracker.unique_paths(), 2);
    }

    #[test]
    fn coverage_stats() {
        let mut tracker = CoverageTracker::new();

        let input = FuzzInput::tools_list();
        let response1 = FuzzResponse::success(serde_json::json!({"a": 1}));
        let response2 = FuzzResponse::success(serde_json::json!({"b": 2}));
        let response3 = FuzzResponse::success(serde_json::json!({"a": 1})); // Duplicate structure

        tracker.record(&input, &response1);
        tracker.record(&input, &response2);
        tracker.record(&input, &response3);

        let stats = tracker.stats();
        assert_eq!(stats.paths_explored, 2);
        assert!(stats.new_coverage_rate > 0.0);
        assert!(stats.new_coverage_rate <= 1.0);
    }

    #[test]
    fn method_coverage_tracking() {
        let mut tracker = CoverageTracker::new();

        let tools = FuzzInput::tools_list();
        let resources = FuzzInput::resources_list();
        let response = FuzzResponse::success(serde_json::json!({}));

        tracker.record(&tools, &response);
        tracker.record(&tools, &response);
        tracker.record(&resources, &response);

        let method_cov = tracker.method_coverage();
        assert!(method_cov.contains_key("tools/list"));
        assert!(method_cov.contains_key("resources/list"));
    }
}
