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
