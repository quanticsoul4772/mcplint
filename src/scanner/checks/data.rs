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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::mcp::Tool;

    fn make_tool(name: &str, description: Option<&str>) -> Tool {
        Tool {
            name: name.to_string(),
            description: description.map(|s| s.to_string()),
            input_schema: serde_json::json!({}),
        }
    }

    #[test]
    fn detect_get_user_exposure() {
        let checker = DefaultDataChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools.push(make_tool("get_user_profile", None));

        let finding = checker.check_sensitive_data_exposure(&ctx);
        assert!(finding.is_some());
        let f = finding.unwrap();
        assert_eq!(f.rule_id, "MCP-DATA-001");
        assert_eq!(f.severity, Severity::Medium);
    }

    #[test]
    fn detect_read_credentials() {
        let checker = DefaultDataChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools.push(make_tool("read_credentials", None));

        let finding = checker.check_sensitive_data_exposure(&ctx);
        assert!(finding.is_some());
    }

    #[test]
    fn detect_list_secrets() {
        let checker = DefaultDataChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools.push(make_tool("list_secrets", None));

        let finding = checker.check_sensitive_data_exposure(&ctx);
        assert!(finding.is_some());
    }

    #[test]
    fn detect_fetch_config() {
        let checker = DefaultDataChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools.push(make_tool("fetch_config", None));

        let finding = checker.check_sensitive_data_exposure(&ctx);
        assert!(finding.is_some());
    }

    #[test]
    fn detect_env_in_description() {
        let checker = DefaultDataChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools.push(make_tool(
            "get_data",
            Some("Retrieves environment variables"),
        ));

        let finding = checker.check_sensitive_data_exposure(&ctx);
        assert!(finding.is_some());
    }

    #[test]
    fn no_finding_without_access_verb() {
        let checker = DefaultDataChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools.push(make_tool("user_settings", None));

        let finding = checker.check_sensitive_data_exposure(&ctx);
        assert!(finding.is_none());
    }

    #[test]
    fn no_finding_safe_tool() {
        let checker = DefaultDataChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools.push(make_tool("calculate_sum", None));

        let finding = checker.check_sensitive_data_exposure(&ctx);
        assert!(finding.is_none());
    }

    #[test]
    fn empty_tools_no_findings() {
        let checker = DefaultDataChecks;
        let ctx = ServerContext::for_test("test");

        assert!(checker.check_sensitive_data_exposure(&ctx).is_none());
    }
}
