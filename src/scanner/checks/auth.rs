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
