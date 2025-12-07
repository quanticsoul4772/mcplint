//! Validation Rules - Protocol compliance rule definitions
//!
//! Defines all validation rules for MCP protocol compliance checking.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Validation rule identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ValidationRuleId {
    // Protocol rules (PROTO-001 to PROTO-010)
    #[serde(rename = "PROTO-001")]
    Proto001,
    #[serde(rename = "PROTO-002")]
    Proto002,
    #[serde(rename = "PROTO-003")]
    Proto003,
    #[serde(rename = "PROTO-004")]
    Proto004,
    #[serde(rename = "PROTO-005")]
    Proto005,
    #[serde(rename = "PROTO-006")]
    Proto006,
    #[serde(rename = "PROTO-007")]
    Proto007,
    #[serde(rename = "PROTO-008")]
    Proto008,
    #[serde(rename = "PROTO-009")]
    Proto009,
    #[serde(rename = "PROTO-010")]
    Proto010,

    // Schema rules (SCHEMA-001 to SCHEMA-005)
    #[serde(rename = "SCHEMA-001")]
    Schema001,
    #[serde(rename = "SCHEMA-002")]
    Schema002,
    #[serde(rename = "SCHEMA-003")]
    Schema003,
    #[serde(rename = "SCHEMA-004")]
    Schema004,
    #[serde(rename = "SCHEMA-005")]
    Schema005,

    // Sequence rules (SEQ-001 to SEQ-003)
    #[serde(rename = "SEQ-001")]
    Seq001,
    #[serde(rename = "SEQ-002")]
    Seq002,
    #[serde(rename = "SEQ-003")]
    Seq003,
}

impl fmt::Display for ValidationRuleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValidationRuleId::Proto001 => write!(f, "PROTO-001"),
            ValidationRuleId::Proto002 => write!(f, "PROTO-002"),
            ValidationRuleId::Proto003 => write!(f, "PROTO-003"),
            ValidationRuleId::Proto004 => write!(f, "PROTO-004"),
            ValidationRuleId::Proto005 => write!(f, "PROTO-005"),
            ValidationRuleId::Proto006 => write!(f, "PROTO-006"),
            ValidationRuleId::Proto007 => write!(f, "PROTO-007"),
            ValidationRuleId::Proto008 => write!(f, "PROTO-008"),
            ValidationRuleId::Proto009 => write!(f, "PROTO-009"),
            ValidationRuleId::Proto010 => write!(f, "PROTO-010"),
            ValidationRuleId::Schema001 => write!(f, "SCHEMA-001"),
            ValidationRuleId::Schema002 => write!(f, "SCHEMA-002"),
            ValidationRuleId::Schema003 => write!(f, "SCHEMA-003"),
            ValidationRuleId::Schema004 => write!(f, "SCHEMA-004"),
            ValidationRuleId::Schema005 => write!(f, "SCHEMA-005"),
            ValidationRuleId::Seq001 => write!(f, "SEQ-001"),
            ValidationRuleId::Seq002 => write!(f, "SEQ-002"),
            ValidationRuleId::Seq003 => write!(f, "SEQ-003"),
        }
    }
}

/// Validation rule category
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ValidationCategory {
    /// Protocol compliance rules
    Protocol,
    /// JSON Schema validation rules
    Schema,
    /// Message sequence rules
    Sequence,
}

impl fmt::Display for ValidationCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValidationCategory::Protocol => write!(f, "protocol"),
            ValidationCategory::Schema => write!(f, "schema"),
            ValidationCategory::Sequence => write!(f, "sequence"),
        }
    }
}

/// A validation rule definition
#[derive(Debug, Clone)]
pub struct ValidationRule {
    pub id: ValidationRuleId,
    pub name: String,
    pub description: String,
    pub category: ValidationCategory,
}

/// Get all validation rules
pub fn get_all_rules() -> Vec<ValidationRule> {
    vec![
        // Protocol rules
        ValidationRule {
            id: ValidationRuleId::Proto001,
            name: "JSON-RPC 2.0 Compliance".to_string(),
            description: "Server must respond with valid JSON-RPC 2.0 messages".to_string(),
            category: ValidationCategory::Protocol,
        },
        ValidationRule {
            id: ValidationRuleId::Proto002,
            name: "Valid Protocol Version".to_string(),
            description: "Server must return a supported MCP protocol version".to_string(),
            category: ValidationCategory::Protocol,
        },
        ValidationRule {
            id: ValidationRuleId::Proto003,
            name: "Valid Server Info".to_string(),
            description: "Server must provide valid name and version in serverInfo".to_string(),
            category: ValidationCategory::Protocol,
        },
        ValidationRule {
            id: ValidationRuleId::Proto004,
            name: "Valid Capabilities Object".to_string(),
            description: "Server capabilities must be a valid object".to_string(),
            category: ValidationCategory::Protocol,
        },
        ValidationRule {
            id: ValidationRuleId::Proto005,
            name: "Valid Tool Definitions".to_string(),
            description: "All tools must have valid name and inputSchema".to_string(),
            category: ValidationCategory::Protocol,
        },
        ValidationRule {
            id: ValidationRuleId::Proto006,
            name: "Valid Resource Definitions".to_string(),
            description: "All resources must have valid URI and name".to_string(),
            category: ValidationCategory::Protocol,
        },
        ValidationRule {
            id: ValidationRuleId::Proto007,
            name: "Valid Prompt Definitions".to_string(),
            description: "All prompts must have valid name".to_string(),
            category: ValidationCategory::Protocol,
        },
        ValidationRule {
            id: ValidationRuleId::Proto008,
            name: "Capabilities Consistency".to_string(),
            description: "Advertised capabilities must match actual functionality".to_string(),
            category: ValidationCategory::Protocol,
        },
        ValidationRule {
            id: ValidationRuleId::Proto009,
            name: "Error Code Compliance".to_string(),
            description: "Errors must use standard JSON-RPC error codes".to_string(),
            category: ValidationCategory::Protocol,
        },
        ValidationRule {
            id: ValidationRuleId::Proto010,
            name: "Content Type Handling".to_string(),
            description: "Server must handle content types correctly".to_string(),
            category: ValidationCategory::Protocol,
        },
        // Schema rules
        ValidationRule {
            id: ValidationRuleId::Schema001,
            name: "Valid JSON Schema".to_string(),
            description: "Tool inputSchema must be valid JSON Schema".to_string(),
            category: ValidationCategory::Schema,
        },
        ValidationRule {
            id: ValidationRuleId::Schema002,
            name: "Schema Type Field".to_string(),
            description: "Schema should include a type field".to_string(),
            category: ValidationCategory::Schema,
        },
        ValidationRule {
            id: ValidationRuleId::Schema003,
            name: "Object Properties".to_string(),
            description: "Object schemas should define properties".to_string(),
            category: ValidationCategory::Schema,
        },
        ValidationRule {
            id: ValidationRuleId::Schema004,
            name: "Required Array Valid".to_string(),
            description: "Required fields must exist in properties".to_string(),
            category: ValidationCategory::Schema,
        },
        ValidationRule {
            id: ValidationRuleId::Schema005,
            name: "Description Fields".to_string(),
            description: "Tools should include descriptions for clarity".to_string(),
            category: ValidationCategory::Schema,
        },
        // Sequence rules
        ValidationRule {
            id: ValidationRuleId::Seq001,
            name: "Ping Response".to_string(),
            description: "Server must respond to ping requests".to_string(),
            category: ValidationCategory::Sequence,
        },
        ValidationRule {
            id: ValidationRuleId::Seq002,
            name: "Unknown Method Handling".to_string(),
            description: "Server must properly handle unknown methods".to_string(),
            category: ValidationCategory::Sequence,
        },
        ValidationRule {
            id: ValidationRuleId::Seq003,
            name: "Error Response Format".to_string(),
            description: "Error responses must follow JSON-RPC format".to_string(),
            category: ValidationCategory::Sequence,
        },
    ]
}

/// Get rules by category
pub fn get_rules_by_category(category: ValidationCategory) -> Vec<ValidationRule> {
    get_all_rules()
        .into_iter()
        .filter(|r| r.category == category)
        .collect()
}

/// Get a rule by ID
pub fn get_rule_by_id(id: ValidationRuleId) -> Option<ValidationRule> {
    get_all_rules().into_iter().find(|r| r.id == id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_rules_have_unique_ids() {
        let rules = get_all_rules();
        let mut ids: std::collections::HashSet<ValidationRuleId> = std::collections::HashSet::new();

        for rule in &rules {
            assert!(ids.insert(rule.id), "Duplicate rule ID: {:?}", rule.id);
        }
    }

    #[test]
    fn rule_id_display() {
        assert_eq!(ValidationRuleId::Proto001.to_string(), "PROTO-001");
        assert_eq!(ValidationRuleId::Schema001.to_string(), "SCHEMA-001");
        assert_eq!(ValidationRuleId::Seq001.to_string(), "SEQ-001");
    }

    #[test]
    fn category_display() {
        assert_eq!(ValidationCategory::Protocol.to_string(), "protocol");
        assert_eq!(ValidationCategory::Schema.to_string(), "schema");
        assert_eq!(ValidationCategory::Sequence.to_string(), "sequence");
    }

    #[test]
    fn get_protocol_rules() {
        let rules = get_rules_by_category(ValidationCategory::Protocol);
        assert!(!rules.is_empty());
        assert!(rules
            .iter()
            .all(|r| r.category == ValidationCategory::Protocol));
    }

    #[test]
    fn get_schema_rules() {
        let rules = get_rules_by_category(ValidationCategory::Schema);
        assert!(!rules.is_empty());
        assert!(rules
            .iter()
            .all(|r| r.category == ValidationCategory::Schema));
    }

    #[test]
    fn get_sequence_rules() {
        let rules = get_rules_by_category(ValidationCategory::Sequence);
        assert!(!rules.is_empty());
        assert!(rules
            .iter()
            .all(|r| r.category == ValidationCategory::Sequence));
    }
}
