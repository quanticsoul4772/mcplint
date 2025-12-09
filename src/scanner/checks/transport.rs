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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_unencrypted_remote_http() {
        let checker = DefaultTransportChecks;
        let mut ctx = ServerContext::for_test("http://api.example.com/mcp");
        ctx.set_transport_type("sse");

        let finding = checker.check_unencrypted_transport(&ctx);
        assert!(finding.is_some());
        let f = finding.unwrap();
        assert_eq!(f.rule_id, "MCP-TRANS-001");
        assert_eq!(f.severity, Severity::High);
    }

    #[test]
    fn detect_unencrypted_streamable_http() {
        let checker = DefaultTransportChecks;
        let mut ctx = ServerContext::for_test("http://remote-server.com:8080/mcp");
        ctx.set_transport_type("streamable_http");

        let finding = checker.check_unencrypted_transport(&ctx);
        assert!(finding.is_some());
    }

    #[test]
    fn no_finding_localhost_http() {
        let checker = DefaultTransportChecks;
        let mut ctx = ServerContext::for_test("http://localhost:8080/mcp");
        ctx.set_transport_type("sse");

        let finding = checker.check_unencrypted_transport(&ctx);
        assert!(finding.is_none());
    }

    #[test]
    fn no_finding_127_0_0_1_http() {
        let checker = DefaultTransportChecks;
        let mut ctx = ServerContext::for_test("http://127.0.0.1:8080/mcp");
        ctx.set_transport_type("sse");

        let finding = checker.check_unencrypted_transport(&ctx);
        assert!(finding.is_none());
    }

    #[test]
    fn no_finding_https() {
        let checker = DefaultTransportChecks;
        let mut ctx = ServerContext::for_test("https://api.example.com/mcp");
        ctx.set_transport_type("sse");

        let finding = checker.check_unencrypted_transport(&ctx);
        assert!(finding.is_none());
    }

    #[test]
    fn no_finding_stdio_transport() {
        let checker = DefaultTransportChecks;
        let ctx = ServerContext::for_test("node server.js");
        // Default transport is stdio, which is not HTTP

        let finding = checker.check_unencrypted_transport(&ctx);
        assert!(finding.is_none());
    }

    #[test]
    fn finding_has_evidence() {
        let checker = DefaultTransportChecks;
        let mut ctx = ServerContext::for_test("http://api.example.com/mcp");
        ctx.set_transport_type("sse");

        let finding = checker.check_unencrypted_transport(&ctx).unwrap();
        assert!(!finding.evidence.is_empty());
    }

    #[test]
    fn finding_has_cwe() {
        let checker = DefaultTransportChecks;
        let mut ctx = ServerContext::for_test("http://remote.example.org/mcp");
        ctx.set_transport_type("sse");

        let finding = checker.check_unencrypted_transport(&ctx).unwrap();
        assert!(!finding.references.is_empty());
        assert!(finding.references.iter().any(|r| r.id.contains("CWE-319")));
    }
}
