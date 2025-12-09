//! Denial of Service Checks
//!
//! MCP-DOS-001 to MCP-DOS-002: Resource consumption, rate limiting

use crate::scanner::context::ServerContext;
use crate::scanner::finding::{Finding, FindingLocation, Severity};
use crate::scanner::helpers::has_limit_parameters;

/// Trait for DoS vulnerability checks
pub trait DosChecks {
    /// Check for unbounded resource consumption (MCP-DOS-001)
    fn check_resource_consumption(&self, ctx: &ServerContext) -> Option<Finding>;
}

/// Default implementation of DoS checks
pub struct DefaultDosChecks;

impl DosChecks for DefaultDosChecks {
    fn check_resource_consumption(&self, ctx: &ServerContext) -> Option<Finding> {
        // Check for tools that might consume unbounded resources
        let resource_patterns = [
            "download", "upload", "stream", "bulk", "batch", "all", "export", "import",
        ];

        for tool in &ctx.tools {
            let name_lower = tool.name.to_lowercase();

            for pattern in &resource_patterns {
                if name_lower.contains(pattern) {
                    // Check if there's no apparent limit parameter
                    if !has_limit_parameters(&tool.input_schema) {
                        return Some(
                            Finding::new(
                                "MCP-DOS-001",
                                Severity::Medium,
                                "Potential Unbounded Resource Consumption",
                                format!(
                                    "Tool '{}' may process large amounts of data without apparent limits. \
                                     This could be exploited for denial of service.",
                                    tool.name
                                ),
                            )
                            .with_location(FindingLocation::tool(&tool.name))
                            .with_remediation(
                                "Implement resource limits (max size, timeout, pagination). \
                                 Add rate limiting and request throttling. \
                                 Monitor resource usage and implement circuit breakers.",
                            )
                            .with_cwe("400"),
                        );
                    }
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

    fn make_tool(name: &str, schema: serde_json::Value) -> Tool {
        Tool {
            name: name.to_string(),
            description: None,
            input_schema: schema,
        }
    }

    fn make_empty_schema() -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {}
        })
    }

    fn make_limit_schema() -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "max_items": { "type": "integer" }
            }
        })
    }

    #[test]
    fn detect_download_no_limit() {
        let checker = DefaultDosChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools
            .push(make_tool("download_files", make_empty_schema()));

        let finding = checker.check_resource_consumption(&ctx);
        assert!(finding.is_some());
        let f = finding.unwrap();
        assert_eq!(f.rule_id, "MCP-DOS-001");
        assert_eq!(f.severity, Severity::Medium);
    }

    #[test]
    fn detect_bulk_no_limit() {
        let checker = DefaultDosChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools
            .push(make_tool("bulk_process", make_empty_schema()));

        let finding = checker.check_resource_consumption(&ctx);
        assert!(finding.is_some());
    }

    #[test]
    fn detect_export_no_limit() {
        let checker = DefaultDosChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools
            .push(make_tool("export_data", make_empty_schema()));

        let finding = checker.check_resource_consumption(&ctx);
        assert!(finding.is_some());
    }

    #[test]
    fn detect_stream_no_limit() {
        let checker = DefaultDosChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools
            .push(make_tool("stream_data", make_empty_schema()));

        let finding = checker.check_resource_consumption(&ctx);
        assert!(finding.is_some());
    }

    #[test]
    fn no_finding_with_limit_param() {
        let checker = DefaultDosChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools
            .push(make_tool("download_files", make_limit_schema()));

        let finding = checker.check_resource_consumption(&ctx);
        assert!(finding.is_none());
    }

    #[test]
    fn no_finding_safe_tool() {
        let checker = DefaultDosChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools.push(make_tool("get_status", make_empty_schema()));

        let finding = checker.check_resource_consumption(&ctx);
        assert!(finding.is_none());
    }

    #[test]
    fn empty_tools_no_findings() {
        let checker = DefaultDosChecks;
        let ctx = ServerContext::for_test("test");

        assert!(checker.check_resource_consumption(&ctx).is_none());
    }

    #[test]
    fn detect_upload_no_limit() {
        let checker = DefaultDosChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools
            .push(make_tool("upload_batch", make_empty_schema()));

        let finding = checker.check_resource_consumption(&ctx);
        assert!(finding.is_some());
    }

    #[test]
    fn detect_import_no_limit() {
        let checker = DefaultDosChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools.push(make_tool("import_all", make_empty_schema()));

        let finding = checker.check_resource_consumption(&ctx);
        assert!(finding.is_some());
    }
}
