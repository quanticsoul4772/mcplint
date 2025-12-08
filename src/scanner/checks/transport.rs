//! Transport Security Checks
//!
//! MCP-TRANS-001 to MCP-TRANS-002: Unencrypted HTTP, TLS validation

use crate::scanner::context::ServerContext;
use crate::scanner::finding::{Evidence, Finding, FindingLocation, Severity};

/// Trait for transport security checks
pub trait TransportChecks {
    /// Check for unencrypted transport (MCP-TRANS-001)
    fn check_unencrypted_transport(&self, ctx: &ServerContext) -> Option<Finding>;
}

/// Default implementation of transport checks
pub struct DefaultTransportChecks;

impl TransportChecks for DefaultTransportChecks {
    fn check_unencrypted_transport(&self, ctx: &ServerContext) -> Option<Finding> {
        if ctx.uses_http() && ctx.target.starts_with("http://") {
            // Exclude localhost
            if !ctx.target.contains("localhost") && !ctx.target.contains("127.0.0.1") {
                return Some(
                    Finding::new(
                        "MCP-TRANS-001",
                        Severity::High,
                        "Unencrypted HTTP Transport",
                        format!(
                            "Server uses unencrypted HTTP at '{}'. \
                             All communications including tool calls and responses can be intercepted.",
                            ctx.target
                        ),
                    )
                    .with_location(FindingLocation::transport(&ctx.transport_type))
                    .with_evidence(Evidence::configuration(
                        &ctx.target,
                        "Target URL uses http:// scheme",
                    ))
                    .with_remediation(
                        "Use HTTPS with valid TLS certificates for all remote MCP servers. \
                         Configure TLS 1.2 or higher with strong cipher suites.",
                    )
                    .with_cwe("319"),
                );
            }
        }

        None
    }
}
