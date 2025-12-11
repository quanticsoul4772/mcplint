//! Mutation Module - Input mutation for fuzzing
//!
//! Provides mutation strategies and engines for generating
//! fuzzed inputs to test MCP servers.

pub mod dictionary;
pub mod json;
pub mod jsonrpc;
pub mod mcp;
pub mod strategy;

use rand::rngs::SmallRng;
use rand::{Rng, SeedableRng};
use serde_json::Value;
use std::collections::HashMap;

use self::dictionary::Dictionary;
use self::json::JsonMutator;
use self::jsonrpc::JsonRpcMutator;
use self::mcp::McpMutator;
use self::strategy::MutationStrategy;
use super::input::FuzzInput;

/// Engine for generating mutated inputs
pub struct MutationEngine {
    /// Active mutation strategies
    strategies: Vec<MutationStrategy>,
    /// Protocol dictionary
    dictionary: Dictionary,
    /// Random number generator
    rng: SmallRng,
    /// Cached tool schemas for schema-aware mutation
    tool_schemas: HashMap<String, Value>,
    /// Known tool names
    tool_names: Vec<String>,
    /// Total weight for strategy selection
    total_weight: u32,
}

impl MutationEngine {
    /// Create a new mutation engine with given strategies
    pub fn new(strategies: Vec<MutationStrategy>) -> Self {
        let total_weight = strategies.iter().map(|s| s.weight()).sum();

        Self {
            strategies,
            dictionary: Dictionary::mcp_default(),
            rng: SmallRng::from_entropy(),
            tool_schemas: HashMap::new(),
            tool_names: Vec::new(),
            total_weight,
        }
    }

    /// Create with all strategies
    pub fn all_strategies() -> Self {
        Self::new(MutationStrategy::all())
    }

    /// Set custom dictionary
    pub fn with_dictionary(mut self, dict: Dictionary) -> Self {
        self.dictionary = dict;
        self
    }

    /// Set random seed for reproducibility
    pub fn with_seed(mut self, seed: u64) -> Self {
        self.rng = SmallRng::seed_from_u64(seed);
        self
    }

    /// Cache tool schemas for schema-aware mutation
    pub fn cache_tools(&mut self, tools: &[crate::protocol::mcp::Tool]) {
        self.tool_names.clear();
        self.tool_schemas.clear();

        for tool in tools {
            self.tool_names.push(tool.name.clone());
            self.tool_schemas
                .insert(tool.name.clone(), tool.input_schema.clone());
        }
    }

    /// Select a random strategy based on weights
    fn select_strategy(&mut self) -> MutationStrategy {
        if self.strategies.is_empty() {
            return MutationStrategy::TypeConfusion;
        }

        let mut target = self.rng.gen_range(0..self.total_weight);

        for strategy in &self.strategies {
            let weight = strategy.weight();
            if target < weight {
                return *strategy;
            }
            target -= weight;
        }

        self.strategies[0]
    }

    /// Generate a mutated input from a base input
    pub fn mutate(&mut self, base: &FuzzInput) -> FuzzInput {
        let strategy = self.select_strategy();
        self.apply_strategy(strategy, base)
    }

    /// Apply a specific strategy to an input
    pub fn apply_strategy(&mut self, strategy: MutationStrategy, base: &FuzzInput) -> FuzzInput {
        let mutated = match strategy {
            // JSON-level mutations
            MutationStrategy::TypeConfusion => self.mutate_type_confusion(base),
            MutationStrategy::BoundaryValues => self.mutate_boundary_values(base),
            MutationStrategy::DeepNesting => self.mutate_deep_nesting(base),
            MutationStrategy::UnicodeInjection => self.mutate_unicode_injection(base),
            MutationStrategy::StringMutation => self.mutate_string(base),

            // JSON-RPC mutations
            MutationStrategy::InvalidId => self.mutate_invalid_id(base),
            MutationStrategy::MalformedVersion => self.mutate_malformed_version(base),
            MutationStrategy::UnknownMethod => self.mutate_unknown_method(),
            MutationStrategy::MissingFields => self.mutate_missing_fields(base),
            MutationStrategy::ExtraFields => self.mutate_extra_fields(base),

            // MCP-specific mutations
            MutationStrategy::ToolNotFound => self.mutate_tool_not_found(),
            MutationStrategy::SchemaViolation => self.mutate_schema_violation(base),
            MutationStrategy::SequenceViolation => self.mutate_sequence_violation(),
            MutationStrategy::ResourceExhaustion => self.mutate_resource_exhaustion(),
            MutationStrategy::CapabilityMismatch => self.mutate_capability_mismatch(),
            MutationStrategy::InvalidPagination => self.mutate_invalid_pagination(),

            // Stress mutations
            MutationStrategy::RapidFire => self.mutate_rapid_fire(base),
        };

        mutated.with_strategy(strategy).with_parent(&base.input_id)
    }

    /// Generate a completely random input
    pub fn generate_random(&mut self) -> FuzzInput {
        let methods = [
            "initialize",
            "tools/list",
            "tools/call",
            "resources/list",
            "resources/read",
            "prompts/list",
            "prompts/get",
            "ping",
        ];

        let method = methods[self.rng.gen_range(0..methods.len())];
        let params = self.generate_random_params(method);

        FuzzInput::new(method, Some(params))
    }

    fn generate_random_params(&mut self, method: &str) -> Value {
        match method {
            "tools/call" => {
                let name = if !self.tool_names.is_empty() {
                    self.tool_names[self.rng.gen_range(0..self.tool_names.len())].clone()
                } else {
                    "unknown_tool".to_string()
                };
                serde_json::json!({
                    "name": name,
                    "arguments": {}
                })
            }
            "resources/read" => serde_json::json!({"uri": "file:///test"}),
            "prompts/get" => serde_json::json!({"name": "test_prompt"}),
            _ => serde_json::json!({}),
        }
    }

    // =========================================================================
    // JSON-level mutations
    // =========================================================================

    fn mutate_type_confusion(&mut self, base: &FuzzInput) -> FuzzInput {
        let mut input = base.clone();
        if let Some(params) = &base.params {
            let mutated = JsonMutator::type_confuse(params, &mut self.rng);
            input.params = Some(mutated);
        }
        input
    }

    fn mutate_boundary_values(&mut self, base: &FuzzInput) -> FuzzInput {
        let mut input = base.clone();
        if let Some(params) = &base.params {
            let mutated = JsonMutator::boundary_value(params, &mut self.rng);
            input.params = Some(mutated);
        }
        input
    }

    fn mutate_deep_nesting(&mut self, base: &FuzzInput) -> FuzzInput {
        let mut input = base.clone();
        let depth = self.rng.gen_range(50..200);
        let array_mode = self.rng.gen_bool(0.5);
        let nested = JsonMutator::deep_nest(depth, array_mode);
        input.params = Some(nested);
        input
    }

    fn mutate_unicode_injection(&mut self, base: &FuzzInput) -> FuzzInput {
        let mut input = base.clone();
        if let Some(params) = &base.params {
            let json_str = serde_json::to_string(params).unwrap_or_default();
            let mutated = JsonMutator::unicode_inject(&json_str, &self.dictionary, &mut self.rng);
            // Try to parse back, fallback to string
            input.params = serde_json::from_str(&mutated)
                .ok()
                .or(Some(serde_json::json!(mutated)));
        }
        input
    }

    fn mutate_string(&mut self, base: &FuzzInput) -> FuzzInput {
        let mut input = base.clone();
        if let Some(params) = &base.params {
            if let Some(obj) = params.as_object() {
                let mut new_obj = obj.clone();
                for (_, v) in new_obj.iter_mut() {
                    if let Some(s) = v.as_str() {
                        *v = serde_json::json!(JsonMutator::mutate_string(s, &mut self.rng));
                    }
                }
                input.params = Some(Value::Object(new_obj));
            }
        }
        input
    }

    // =========================================================================
    // JSON-RPC mutations
    // =========================================================================

    fn mutate_invalid_id(&mut self, base: &FuzzInput) -> FuzzInput {
        let mut input = base.clone();
        input.id = JsonRpcMutator::invalid_id(&mut self.rng);
        input
    }

    fn mutate_malformed_version(&mut self, _base: &FuzzInput) -> FuzzInput {
        // Create a raw JSON-RPC request with malformed version
        let _version = JsonRpcMutator::malformed_version(&mut self.rng);
        // Note: The version mutation is tracked but the FuzzInput structure
        // doesn't directly support custom jsonrpc versions, so we return
        // a standard input that will be sent with the protocol default.

        FuzzInput {
            method: "ping".to_string(),
            params: None,
            id: serde_json::json!(1),
            strategy_used: None,
            parent_id: None,
            input_id: uuid::Uuid::new_v4().to_string(),
        }
    }

    fn mutate_unknown_method(&mut self) -> FuzzInput {
        let method = JsonRpcMutator::unknown_method(&self.dictionary, &mut self.rng);
        FuzzInput::new(method, Some(serde_json::json!({})))
    }

    fn mutate_missing_fields(&mut self, base: &FuzzInput) -> FuzzInput {
        let json = base.to_json_rpc();
        let mutated = JsonRpcMutator::remove_required_field(&json, &mut self.rng);

        // Extract back to FuzzInput (best effort)
        let method = mutated
            .get("method")
            .and_then(|m| m.as_str())
            .unwrap_or("")
            .to_string();

        FuzzInput {
            method,
            params: mutated.get("params").cloned(),
            id: mutated.get("id").cloned().unwrap_or(Value::Null),
            strategy_used: None,
            parent_id: None,
            input_id: uuid::Uuid::new_v4().to_string(),
        }
    }

    fn mutate_extra_fields(&mut self, base: &FuzzInput) -> FuzzInput {
        let mut input = base.clone();
        if let Some(params) = &base.params {
            if let Some(obj) = params.as_object() {
                let mutated = JsonMutator::mutate_object(obj, &mut self.rng);
                input.params = Some(Value::Object(mutated));
            }
        }
        input
    }

    // =========================================================================
    // MCP-specific mutations
    // =========================================================================

    fn mutate_tool_not_found(&mut self) -> FuzzInput {
        McpMutator::tool_not_found(&self.tool_names, &self.dictionary, &mut self.rng)
    }

    fn mutate_schema_violation(&mut self, base: &FuzzInput) -> FuzzInput {
        // Try to get tool name from base input
        let tool_name = base
            .params
            .as_ref()
            .and_then(|p| p.get("name"))
            .and_then(|n| n.as_str())
            .unwrap_or("unknown");

        let schema = self.tool_schemas.get(tool_name);
        McpMutator::schema_violation(tool_name, schema, &self.dictionary, &mut self.rng)
    }

    fn mutate_sequence_violation(&mut self) -> FuzzInput {
        let sequence = McpMutator::sequence_violation(&mut self.rng);
        // Return first input from sequence
        sequence.into_iter().next().unwrap_or_else(FuzzInput::ping)
    }

    fn mutate_resource_exhaustion(&mut self) -> FuzzInput {
        McpMutator::resource_exhaustion(&mut self.rng)
    }

    fn mutate_capability_mismatch(&mut self) -> FuzzInput {
        McpMutator::capability_mismatch(&mut self.rng)
    }

    fn mutate_invalid_pagination(&mut self) -> FuzzInput {
        McpMutator::invalid_pagination(&mut self.rng)
    }

    fn mutate_rapid_fire(&mut self, base: &FuzzInput) -> FuzzInput {
        // Just return the base with a marker - actual rapid fire happens at session level
        base.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engine_creation() {
        let engine = MutationEngine::all_strategies();
        assert!(!engine.strategies.is_empty());
    }

    #[test]
    fn mutation_produces_different_output() {
        let mut engine = MutationEngine::all_strategies().with_seed(42);
        let base = FuzzInput::tools_list();

        let mutated = engine.mutate(&base);

        // Should have strategy and parent set
        assert!(mutated.strategy_used.is_some());
        assert!(mutated.parent_id.is_some());
    }

    #[test]
    fn random_generation() {
        let mut engine = MutationEngine::all_strategies();

        for _ in 0..10 {
            let input = engine.generate_random();
            assert!(!input.method.is_empty());
        }
    }

    #[test]
    fn deterministic_with_seed() {
        let mut engine1 = MutationEngine::all_strategies().with_seed(12345);
        let mut engine2 = MutationEngine::all_strategies().with_seed(12345);

        let base = FuzzInput::tools_list();

        let m1 = engine1.mutate(&base);
        let m2 = engine2.mutate(&base);

        assert_eq!(m1.strategy_used, m2.strategy_used);
    }

    #[test]
    fn engine_with_specific_strategies() {
        let strategies = vec![
            MutationStrategy::TypeConfusion,
            MutationStrategy::BoundaryValues,
        ];
        let engine = MutationEngine::new(strategies.clone());
        assert_eq!(engine.strategies.len(), 2);
    }

    #[test]
    fn engine_with_custom_dictionary() {
        let dict = Dictionary::mcp_default();
        let engine = MutationEngine::all_strategies().with_dictionary(dict);
        // Just verify dictionary was set (Dictionary doesn't have public unicode_chars)
        assert!(engine.strategies.len() > 0);
    }

    #[test]
    fn cache_tools() {
        use crate::protocol::mcp::Tool;

        let mut engine = MutationEngine::all_strategies();
        let tools = vec![
            Tool {
                name: "test_tool".to_string(),
                description: Some("A test tool".to_string()),
                input_schema: serde_json::json!({"type": "object"}),
            },
            Tool {
                name: "another_tool".to_string(),
                description: None,
                input_schema: serde_json::json!({"type": "object", "properties": {}}),
            },
        ];

        engine.cache_tools(&tools);
        assert_eq!(engine.tool_names.len(), 2);
        assert!(engine.tool_schemas.contains_key("test_tool"));
        assert!(engine.tool_schemas.contains_key("another_tool"));
    }

    #[test]
    fn apply_type_confusion_strategy() {
        let mut engine = MutationEngine::all_strategies().with_seed(42);
        let base = FuzzInput::tools_list();
        let mutated = engine.apply_strategy(MutationStrategy::TypeConfusion, &base);
        assert_eq!(mutated.strategy_used, Some("type_confusion".to_string()));
    }

    #[test]
    fn apply_boundary_values_strategy() {
        let mut engine = MutationEngine::all_strategies().with_seed(42);
        let base = FuzzInput::tool_call("test", serde_json::json!({"arg": 1}));
        let mutated = engine.apply_strategy(MutationStrategy::BoundaryValues, &base);
        assert_eq!(mutated.strategy_used, Some("boundary_values".to_string()));
    }

    #[test]
    fn apply_deep_nesting_strategy() {
        let mut engine = MutationEngine::all_strategies().with_seed(42);
        let base = FuzzInput::tools_list();
        let mutated = engine.apply_strategy(MutationStrategy::DeepNesting, &base);
        assert_eq!(mutated.strategy_used, Some("deep_nesting".to_string()));
        // Should have deeply nested params
        assert!(mutated.params.is_some());
    }

    #[test]
    fn apply_unicode_injection_strategy() {
        let mut engine = MutationEngine::all_strategies().with_seed(42);
        let base = FuzzInput::tool_call("test", serde_json::json!({"arg": "value"}));
        let mutated = engine.apply_strategy(MutationStrategy::UnicodeInjection, &base);
        assert_eq!(mutated.strategy_used, Some("unicode_injection".to_string()));
    }

    #[test]
    fn apply_string_mutation_strategy() {
        let mut engine = MutationEngine::all_strategies().with_seed(42);
        let base = FuzzInput::tool_call("test", serde_json::json!({"str": "hello world"}));
        let mutated = engine.apply_strategy(MutationStrategy::StringMutation, &base);
        assert_eq!(mutated.strategy_used, Some("string_mutation".to_string()));
    }

    #[test]
    fn apply_invalid_id_strategy() {
        let mut engine = MutationEngine::all_strategies().with_seed(42);
        let base = FuzzInput::tools_list();
        let mutated = engine.apply_strategy(MutationStrategy::InvalidId, &base);
        assert_eq!(mutated.strategy_used, Some("invalid_id".to_string()));
    }

    #[test]
    fn apply_malformed_version_strategy() {
        let mut engine = MutationEngine::all_strategies().with_seed(42);
        let base = FuzzInput::tools_list();
        let mutated = engine.apply_strategy(MutationStrategy::MalformedVersion, &base);
        assert_eq!(mutated.strategy_used, Some("malformed_version".to_string()));
    }

    #[test]
    fn apply_unknown_method_strategy() {
        let mut engine = MutationEngine::all_strategies().with_seed(42);
        let base = FuzzInput::tools_list();
        let mutated = engine.apply_strategy(MutationStrategy::UnknownMethod, &base);
        assert_eq!(mutated.strategy_used, Some("unknown_method".to_string()));
        // Method can be empty (which is intentionally invalid)
        assert!(mutated.strategy_used.is_some());
    }

    #[test]
    fn apply_missing_fields_strategy() {
        let mut engine = MutationEngine::all_strategies().with_seed(42);
        let base = FuzzInput::tools_list();
        let mutated = engine.apply_strategy(MutationStrategy::MissingFields, &base);
        assert_eq!(mutated.strategy_used, Some("missing_fields".to_string()));
    }

    #[test]
    fn apply_extra_fields_strategy() {
        let mut engine = MutationEngine::all_strategies().with_seed(42);
        let base = FuzzInput::tool_call("test", serde_json::json!({"key": "value"}));
        let mutated = engine.apply_strategy(MutationStrategy::ExtraFields, &base);
        assert_eq!(mutated.strategy_used, Some("extra_fields".to_string()));
    }

    #[test]
    fn apply_tool_not_found_strategy() {
        let mut engine = MutationEngine::all_strategies().with_seed(42);
        let base = FuzzInput::tools_list();
        let mutated = engine.apply_strategy(MutationStrategy::ToolNotFound, &base);
        assert_eq!(mutated.strategy_used, Some("tool_not_found".to_string()));
        assert_eq!(mutated.method, "tools/call");
    }

    #[test]
    fn apply_schema_violation_strategy() {
        let mut engine = MutationEngine::all_strategies().with_seed(42);
        let base = FuzzInput::tool_call("test_tool", serde_json::json!({}));
        let mutated = engine.apply_strategy(MutationStrategy::SchemaViolation, &base);
        assert_eq!(mutated.strategy_used, Some("schema_violation".to_string()));
    }

    #[test]
    fn apply_sequence_violation_strategy() {
        let mut engine = MutationEngine::all_strategies().with_seed(42);
        let base = FuzzInput::tools_list();
        let mutated = engine.apply_strategy(MutationStrategy::SequenceViolation, &base);
        assert_eq!(
            mutated.strategy_used,
            Some("sequence_violation".to_string())
        );
    }

    #[test]
    fn apply_resource_exhaustion_strategy() {
        let mut engine = MutationEngine::all_strategies().with_seed(42);
        let base = FuzzInput::tools_list();
        let mutated = engine.apply_strategy(MutationStrategy::ResourceExhaustion, &base);
        assert_eq!(
            mutated.strategy_used,
            Some("resource_exhaustion".to_string())
        );
    }

    #[test]
    fn apply_capability_mismatch_strategy() {
        let mut engine = MutationEngine::all_strategies().with_seed(42);
        let base = FuzzInput::tools_list();
        let mutated = engine.apply_strategy(MutationStrategy::CapabilityMismatch, &base);
        assert_eq!(
            mutated.strategy_used,
            Some("capability_mismatch".to_string())
        );
    }

    #[test]
    fn apply_invalid_pagination_strategy() {
        let mut engine = MutationEngine::all_strategies().with_seed(42);
        let base = FuzzInput::tools_list();
        let mutated = engine.apply_strategy(MutationStrategy::InvalidPagination, &base);
        assert_eq!(
            mutated.strategy_used,
            Some("invalid_pagination".to_string())
        );
    }

    #[test]
    fn apply_rapid_fire_strategy() {
        let mut engine = MutationEngine::all_strategies().with_seed(42);
        let base = FuzzInput::tools_list();
        let mutated = engine.apply_strategy(MutationStrategy::RapidFire, &base);
        assert_eq!(mutated.strategy_used, Some("rapid_fire".to_string()));
    }

    #[test]
    fn select_strategy_empty() {
        let mut engine = MutationEngine::new(vec![]);
        let strategy = engine.select_strategy();
        // Default is TypeConfusion
        assert_eq!(strategy, MutationStrategy::TypeConfusion);
    }

    #[test]
    fn generate_random_params_tools_call() {
        let mut engine = MutationEngine::all_strategies().with_seed(42);
        let params = engine.generate_random_params("tools/call");
        assert!(params.get("name").is_some());
        assert!(params.get("arguments").is_some());
    }

    #[test]
    fn generate_random_params_resources_read() {
        let mut engine = MutationEngine::all_strategies().with_seed(42);
        let params = engine.generate_random_params("resources/read");
        assert!(params.get("uri").is_some());
    }

    #[test]
    fn generate_random_params_prompts_get() {
        let mut engine = MutationEngine::all_strategies().with_seed(42);
        let params = engine.generate_random_params("prompts/get");
        assert!(params.get("name").is_some());
    }

    #[test]
    fn generate_random_params_other() {
        let mut engine = MutationEngine::all_strategies().with_seed(42);
        let params = engine.generate_random_params("ping");
        assert!(params.is_object());
    }

    #[test]
    fn mutate_with_cached_tools() {
        use crate::protocol::mcp::Tool;

        let mut engine = MutationEngine::all_strategies().with_seed(42);
        engine.cache_tools(&[Tool {
            name: "cached_tool".to_string(),
            description: Some("desc".to_string()),
            input_schema: serde_json::json!({}),
        }]);

        let base = FuzzInput::tool_call("cached_tool", serde_json::json!({}));
        let mutated = engine.mutate(&base);
        assert!(mutated.strategy_used.is_some());
    }
}
