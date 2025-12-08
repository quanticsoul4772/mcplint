//! Data Exposure Checks
//!
//! MCP-DATA-001 to MCP-DATA-002: Sensitive data exposure, excessive data exposure

use crate::scanner::context::ServerContext;
use crate::scanner::finding::{Finding, FindingLocation, Severity};

/// Trait for data exposure checks
pub trait DataChecks {
    /// Check for sensitive data exposure (MCP-DATA-001)
    fn check_sensitive_data_exposure(&self, ctx: &ServerContext) -> Option<Finding>;
}

/// Default implementation of data exposure checks
pub struct DefaultDataChecks;

impl DataChecks for DefaultDataChecks {
    fn check_sensitive_data_exposure(&self, ctx: &ServerContext) -> Option<Finding> {
        // Check for tools that might return sensitive data
        let sensitive_patterns = [
            "user",
            "profile",
            "account",
            "credential",
            "config",
            "setting",
            "env",
            "environment",
            "secret",
        ];

        for tool in &ctx.tools {
            let name_lower = tool.name.to_lowercase();
            let desc_lower = tool
                .description
                .as_ref()
                .map(|d| d.to_lowercase())
                .unwrap_or_default();

            for pattern in &sensitive_patterns {
                if (name_lower.contains(pattern) || desc_lower.contains(pattern))
                    && (name_lower.contains("get")
                        || name_lower.contains("read")
                        || name_lower.contains("list")
                        || name_lower.contains("fetch"))
                {
                    return Some(
                        Finding::new(
                            "MCP-DATA-001",
                            Severity::Medium,
                            "Potential Sensitive Data Exposure",
                            format!(
                                "Tool '{}' may return sensitive information. \
                                 Ensure appropriate access controls and data filtering are in place.",
                                tool.name
                            ),
                        )
                        .with_location(FindingLocation::tool(&tool.name))
                        .with_remediation(
                            "Implement field-level access controls. \
                             Filter sensitive fields from responses. \
                             Apply data masking for PII and credentials.",
                        )
                        .with_cwe("200"),
                    );
                }
            }
        }

        None
    }
}
