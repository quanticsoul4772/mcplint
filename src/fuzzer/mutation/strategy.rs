//! Mutation Strategy - Types of mutations for fuzzing
//!
//! Defines the various mutation strategies used by the fuzzer
//! to generate test inputs for MCP servers.

use crate::fuzzer::config::FuzzProfile;

/// Mutation strategies for fuzzing
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MutationStrategy {
    // JSON-level mutations
    /// Change value types (String → Number, Array → Object, etc.)
    TypeConfusion,
    /// Use boundary values (MAX_INT, MIN_INT, empty, null)
    BoundaryValues,
    /// Create deeply nested objects/arrays
    DeepNesting,
    /// Inject unicode control characters, null bytes, RTL markers
    UnicodeInjection,
    /// Bit flips, insertions, deletions in strings
    StringMutation,

    // JSON-RPC mutations
    /// Missing, wrong type, null, negative IDs
    InvalidId,
    /// Wrong JSON-RPC version ("2.1", "1.0", missing)
    MalformedVersion,
    /// Random/invented method names
    UnknownMethod,
    /// Remove required fields
    MissingFields,
    /// Add unexpected fields
    ExtraFields,

    // MCP-specific mutations
    /// Call non-existent tools
    ToolNotFound,
    /// Invalid inputs per tool schema
    SchemaViolation,
    /// Out-of-order messages
    SequenceViolation,
    /// Large payloads, deep nesting
    ResourceExhaustion,
    /// Request unsupported capabilities
    CapabilityMismatch,
    /// Bad cursor/pagination values
    InvalidPagination,

    // Protocol stress
    /// Many requests without waiting
    RapidFire,
}

impl MutationStrategy {
    /// Get all strategies
    pub fn all() -> Vec<Self> {
        vec![
            Self::TypeConfusion,
            Self::BoundaryValues,
            Self::DeepNesting,
            Self::UnicodeInjection,
            Self::StringMutation,
            Self::InvalidId,
            Self::MalformedVersion,
            Self::UnknownMethod,
            Self::MissingFields,
            Self::ExtraFields,
            Self::ToolNotFound,
            Self::SchemaViolation,
            Self::SequenceViolation,
            Self::ResourceExhaustion,
            Self::CapabilityMismatch,
            Self::InvalidPagination,
            Self::RapidFire,
        ]
    }

    /// Get strategies for a profile
    pub fn for_profile(profile: FuzzProfile) -> Vec<Self> {
        match profile {
            FuzzProfile::Quick => vec![
                Self::TypeConfusion,
                Self::BoundaryValues,
                Self::InvalidId,
                Self::ToolNotFound,
                Self::MissingFields,
            ],
            FuzzProfile::Standard => vec![
                Self::TypeConfusion,
                Self::BoundaryValues,
                Self::DeepNesting,
                Self::UnicodeInjection,
                Self::InvalidId,
                Self::MalformedVersion,
                Self::UnknownMethod,
                Self::MissingFields,
                Self::ExtraFields,
                Self::ToolNotFound,
                Self::SchemaViolation,
            ],
            FuzzProfile::Intensive | FuzzProfile::CI => Self::all(),
        }
    }

    /// Weight for random selection (higher = more likely)
    pub fn weight(&self) -> u32 {
        match self {
            // High-value mutations
            Self::TypeConfusion => 10,
            Self::BoundaryValues => 10,
            Self::SchemaViolation => 10,
            Self::ToolNotFound => 8,

            // Medium-value mutations
            Self::DeepNesting => 5,
            Self::UnicodeInjection => 5,
            Self::InvalidId => 5,
            Self::MissingFields => 5,
            Self::ExtraFields => 5,
            Self::UnknownMethod => 5,

            // Lower-value mutations
            Self::StringMutation => 3,
            Self::MalformedVersion => 3,
            Self::SequenceViolation => 3,
            Self::CapabilityMismatch => 3,
            Self::InvalidPagination => 3,

            // Stress mutations (use sparingly)
            Self::ResourceExhaustion => 2,
            Self::RapidFire => 1,
        }
    }

    /// Category for this strategy
    pub fn category(&self) -> MutationCategory {
        match self {
            Self::TypeConfusion
            | Self::BoundaryValues
            | Self::DeepNesting
            | Self::UnicodeInjection
            | Self::StringMutation => MutationCategory::Json,

            Self::InvalidId
            | Self::MalformedVersion
            | Self::UnknownMethod
            | Self::MissingFields
            | Self::ExtraFields => MutationCategory::JsonRpc,

            Self::ToolNotFound
            | Self::SchemaViolation
            | Self::SequenceViolation
            | Self::CapabilityMismatch
            | Self::InvalidPagination => MutationCategory::Mcp,

            Self::ResourceExhaustion | Self::RapidFire => MutationCategory::Stress,
        }
    }

    /// Get string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::TypeConfusion => "type_confusion",
            Self::BoundaryValues => "boundary_values",
            Self::DeepNesting => "deep_nesting",
            Self::UnicodeInjection => "unicode_injection",
            Self::StringMutation => "string_mutation",
            Self::InvalidId => "invalid_id",
            Self::MalformedVersion => "malformed_version",
            Self::UnknownMethod => "unknown_method",
            Self::MissingFields => "missing_fields",
            Self::ExtraFields => "extra_fields",
            Self::ToolNotFound => "tool_not_found",
            Self::SchemaViolation => "schema_violation",
            Self::SequenceViolation => "sequence_violation",
            Self::ResourceExhaustion => "resource_exhaustion",
            Self::CapabilityMismatch => "capability_mismatch",
            Self::InvalidPagination => "invalid_pagination",
            Self::RapidFire => "rapid_fire",
        }
    }
}

impl std::fmt::Display for MutationStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Category of mutation strategies
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MutationCategory {
    /// JSON-level mutations
    Json,
    /// JSON-RPC protocol mutations
    JsonRpc,
    /// MCP-specific mutations
    Mcp,
    /// Stress/resource mutations
    Stress,
}

impl MutationCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::JsonRpc => "jsonrpc",
            Self::Mcp => "mcp",
            Self::Stress => "stress",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_strategies() {
        let all = MutationStrategy::all();
        assert_eq!(all.len(), 17);
    }

    #[test]
    fn profile_strategies() {
        let quick = MutationStrategy::for_profile(FuzzProfile::Quick);
        let standard = MutationStrategy::for_profile(FuzzProfile::Standard);
        let intensive = MutationStrategy::for_profile(FuzzProfile::Intensive);

        assert!(quick.len() < standard.len());
        assert!(standard.len() < intensive.len());
    }

    #[test]
    fn strategy_weights() {
        let high_value = MutationStrategy::TypeConfusion;
        let low_value = MutationStrategy::RapidFire;

        assert!(high_value.weight() > low_value.weight());
    }

    #[test]
    fn strategy_categories() {
        assert_eq!(
            MutationStrategy::TypeConfusion.category(),
            MutationCategory::Json
        );
        assert_eq!(
            MutationStrategy::InvalidId.category(),
            MutationCategory::JsonRpc
        );
        assert_eq!(
            MutationStrategy::ToolNotFound.category(),
            MutationCategory::Mcp
        );
        assert_eq!(
            MutationStrategy::RapidFire.category(),
            MutationCategory::Stress
        );
    }
}
