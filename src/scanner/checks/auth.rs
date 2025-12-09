//! Authentication Vulnerability Checks
//!
//! MCP-AUTH-001 to MCP-AUTH-003: Missing auth, weak tokens, credential exposure

use crate::scanner::context::ServerContext;
use crate::scanner::finding::{Finding, FindingLocation, Severity};

/// Trait for authentication vulnerability checks
pub trait AuthChecks {
    /// Check for missing authentication (MCP-AUTH-001)
    fn check_missing_auth(&self, ctx: &ServerContext) -> Option<Finding>;

    /// Check for credential exposure (MCP-AUTH-003)
    fn check_credential_exposure(&self, ctx: &ServerContext) -> Option<Finding>;
}

/// Default implementation of authentication checks
pub struct DefaultAuthChecks;

impl AuthChecks for DefaultAuthChecks {
    fn check_missing_auth(&self, ctx: &ServerContext) -> Option<Finding> {
        // Check if HTTP transport without apparent authentication
        if ctx.uses_http() && !ctx.target.contains("localhost") && !ctx.target.contains("127.0.0.1")
        {
            // Check if the target URL doesn't seem to have auth tokens
            if !ctx.target.contains("token")
                && !ctx.target.contains("key")
                && !ctx.target.contains("auth")
            {
                return Some(
                    Finding::new(
                        "MCP-AUTH-001",
                        Severity::High,
                        "Potentially Missing Authentication",
                        format!(
                            "Server at '{}' is accessible via HTTP transport without apparent authentication. \
                             Remote MCP servers should require authentication to prevent unauthorized access.",
                            ctx.target
                        ),
                    )
                    .with_location(FindingLocation::server())
                    .with_remediation(
                        "Implement authentication for remote MCP servers. \
                         Use OAuth 2.0, API keys, or other authentication mechanisms. \
                         Consider using mTLS for transport-level security.",
                    )
                    .with_cwe("306"),
                );
            }
        }

        None
    }

    fn check_credential_exposure(&self, ctx: &ServerContext) -> Option<Finding> {
        // Check tool descriptions and names for credential-related patterns
        let credential_patterns = [
            "password",
            "secret",
            "api_key",
            "apikey",
            "token",
            "credential",
            "auth",
            "private_key",
        ];

        for tool in &ctx.tools {
            if let Some(ref desc) = tool.description {
                let desc_lower = desc.to_lowercase();
                for pattern in &credential_patterns {
                    if desc_lower.contains(pattern) && desc_lower.contains("log") {
                        return Some(
                            Finding::new(
                                "MCP-AUTH-003",
                                Severity::Medium,
                                "Potential Credential Exposure in Logs",
                                format!(
                                    "Tool '{}' description mentions credentials and logging. \
                                     Ensure credentials are not written to logs.",
                                    tool.name
                                ),
                            )
                            .with_location(FindingLocation::tool(&tool.name))
                            .with_remediation(
                                "Implement credential masking in logs. \
                                 Use structured logging that excludes sensitive fields.",
                            )
                            .with_cwe("532"),
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

    fn make_tool(name: &str, description: Option<&str>) -> Tool {
        Tool {
            name: name.to_string(),
            description: description.map(|s| s.to_string()),
            input_schema: serde_json::json!({}),
        }
    }

    #[test]
    fn detect_missing_auth_remote_http() {
        let checker = DefaultAuthChecks;
        let mut ctx = ServerContext::for_test("https://api.example.com/mcp");
        ctx.set_transport_type("sse");

        let finding = checker.check_missing_auth(&ctx);
        assert!(finding.is_some());
        let f = finding.unwrap();
        assert_eq!(f.rule_id, "MCP-AUTH-001");
        assert_eq!(f.severity, Severity::High);
    }

    #[test]
    fn no_missing_auth_localhost() {
        let checker = DefaultAuthChecks;
        let mut ctx = ServerContext::for_test("http://localhost:8080/mcp");
        ctx.set_transport_type("sse");

        let finding = checker.check_missing_auth(&ctx);
        assert!(finding.is_none());
    }

    #[test]
    fn no_missing_auth_127_0_0_1() {
        let checker = DefaultAuthChecks;
        let mut ctx = ServerContext::for_test("http://127.0.0.1:8080/mcp");
        ctx.set_transport_type("sse");

        let finding = checker.check_missing_auth(&ctx);
        assert!(finding.is_none());
    }

    #[test]
    fn no_missing_auth_with_token_in_url() {
        let checker = DefaultAuthChecks;
        let mut ctx = ServerContext::for_test("https://api.example.com/mcp?token=abc123");
        ctx.set_transport_type("sse");

        let finding = checker.check_missing_auth(&ctx);
        assert!(finding.is_none());
    }

    #[test]
    fn no_missing_auth_with_key_in_url() {
        let checker = DefaultAuthChecks;
        let mut ctx = ServerContext::for_test("https://api.example.com/mcp?api_key=abc123");
        ctx.set_transport_type("sse");

        let finding = checker.check_missing_auth(&ctx);
        assert!(finding.is_none());
    }

    #[test]
    fn no_missing_auth_stdio() {
        let checker = DefaultAuthChecks;
        let ctx = ServerContext::for_test("node server.js");
        // Default transport is stdio, not http

        let finding = checker.check_missing_auth(&ctx);
        assert!(finding.is_none());
    }

    #[test]
    fn detect_credential_exposure_password_log() {
        let checker = DefaultAuthChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools.push(make_tool(
            "process_auth",
            Some("Handles password authentication and logs attempts"),
        ));

        let finding = checker.check_credential_exposure(&ctx);
        assert!(finding.is_some());
        let f = finding.unwrap();
        assert_eq!(f.rule_id, "MCP-AUTH-003");
        assert_eq!(f.severity, Severity::Medium);
    }

    #[test]
    fn detect_credential_exposure_token_log() {
        let checker = DefaultAuthChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools.push(make_tool(
            "auth_handler",
            Some("Validates token and writes to log file"),
        ));

        let finding = checker.check_credential_exposure(&ctx);
        assert!(finding.is_some());
    }

    #[test]
    fn detect_credential_exposure_apikey_log() {
        let checker = DefaultAuthChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools.push(make_tool(
            "verify",
            Some("Checks apikey validity, logs results"),
        ));

        let finding = checker.check_credential_exposure(&ctx);
        assert!(finding.is_some());
    }

    #[test]
    fn no_credential_exposure_no_log() {
        let checker = DefaultAuthChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools.push(make_tool(
            "auth_handler",
            Some("Validates password securely"),
        ));

        let finding = checker.check_credential_exposure(&ctx);
        assert!(finding.is_none());
    }

    #[test]
    fn no_credential_exposure_no_credentials() {
        let checker = DefaultAuthChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools.push(make_tool(
            "data_processor",
            Some("Processes data and logs results"),
        ));

        let finding = checker.check_credential_exposure(&ctx);
        assert!(finding.is_none());
    }

    #[test]
    fn no_credential_exposure_no_description() {
        let checker = DefaultAuthChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools.push(make_tool("password_handler", None));

        let finding = checker.check_credential_exposure(&ctx);
        assert!(finding.is_none());
    }

    #[test]
    fn empty_tools_no_findings() {
        let checker = DefaultAuthChecks;
        let ctx = ServerContext::for_test("test");

        assert!(checker.check_credential_exposure(&ctx).is_none());
    }
}
