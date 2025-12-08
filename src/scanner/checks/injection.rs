//! Injection Vulnerability Checks
//!
//! MCP-INJ-001 to MCP-INJ-004: Command injection, SQL injection, path traversal, SSRF

use crate::client::McpClient;
use crate::scanner::context::ServerContext;
use crate::scanner::finding::{Evidence, Finding, FindingLocation, Severity};
use crate::scanner::helpers::{has_path_parameters, has_string_parameters, has_url_parameters};

/// Trait for injection vulnerability checks
pub trait InjectionChecks {
    /// Check for command injection vulnerabilities (MCP-INJ-001)
    fn check_command_injection(&self, ctx: &ServerContext) -> Option<Finding>;

    /// Check for SQL injection vulnerabilities (MCP-INJ-002)
    fn check_sql_injection(&self, ctx: &ServerContext) -> Option<Finding>;

    /// Check for path traversal vulnerabilities (MCP-INJ-003)
    fn check_path_traversal(&self, ctx: &ServerContext) -> Option<Finding>;

    /// Check for SSRF vulnerabilities (MCP-INJ-004)
    fn check_ssrf(
        &self,
        ctx: &ServerContext,
        client: &mut McpClient,
    ) -> impl std::future::Future<Output = Option<Finding>> + Send;
}

/// Default implementation of injection checks
pub struct DefaultInjectionChecks;

impl InjectionChecks for DefaultInjectionChecks {
    fn check_command_injection(&self, ctx: &ServerContext) -> Option<Finding> {
        // Look for tools that might execute shell commands
        let shell_patterns = [
            "exec",
            "shell",
            "command",
            "run",
            "system",
            "spawn",
            "popen",
            "bash",
            "sh",
            "cmd",
            "powershell",
        ];

        for tool in &ctx.tools {
            let name_lower = tool.name.to_lowercase();
            let desc_lower = tool
                .description
                .as_ref()
                .map(|d| d.to_lowercase())
                .unwrap_or_default();

            for pattern in &shell_patterns {
                if (name_lower.contains(pattern) || desc_lower.contains(pattern))
                    && has_string_parameters(&tool.input_schema)
                {
                    return Some(
                        Finding::new(
                            "MCP-INJ-001",
                            Severity::Critical,
                            "Potential Command Injection",
                            format!(
                                "Tool '{}' appears to execute shell commands and accepts string parameters. \
                                 User-controlled input may be passed to system commands without sanitization.",
                                tool.name
                            ),
                        )
                        .with_location(FindingLocation::tool(&tool.name))
                        .with_evidence(Evidence::observation(
                            format!("Tool name/description contains '{}' pattern", pattern),
                            "Indicates shell command execution capability",
                        ))
                        .with_remediation(
                            "Implement strict input validation and use parameterized commands. \
                             Avoid passing user input directly to shell interpreters.",
                        )
                        .with_cwe("78"),
                    );
                }
            }
        }

        None
    }

    fn check_sql_injection(&self, ctx: &ServerContext) -> Option<Finding> {
        let db_patterns = [
            "sql",
            "query",
            "database",
            "db",
            "mysql",
            "postgres",
            "sqlite",
            "mongodb",
            "execute_query",
        ];

        for tool in &ctx.tools {
            let name_lower = tool.name.to_lowercase();
            let desc_lower = tool
                .description
                .as_ref()
                .map(|d| d.to_lowercase())
                .unwrap_or_default();

            for pattern in &db_patterns {
                if (name_lower.contains(pattern) || desc_lower.contains(pattern))
                    && has_string_parameters(&tool.input_schema)
                {
                    return Some(
                        Finding::new(
                            "MCP-INJ-002",
                            Severity::Critical,
                            "Potential SQL Injection",
                            format!(
                                "Tool '{}' appears to execute database queries and accepts string parameters. \
                                 SQL injection may be possible if input is not properly sanitized.",
                                tool.name
                            ),
                        )
                        .with_location(FindingLocation::tool(&tool.name))
                        .with_evidence(Evidence::observation(
                            format!("Tool name/description contains '{}' pattern", pattern),
                            "Indicates database query capability",
                        ))
                        .with_remediation(
                            "Use parameterized queries or prepared statements. \
                             Never concatenate user input into SQL strings.",
                        )
                        .with_cwe("89"),
                    );
                }
            }
        }

        None
    }

    fn check_path_traversal(&self, ctx: &ServerContext) -> Option<Finding> {
        let file_patterns = [
            "file",
            "path",
            "read",
            "write",
            "load",
            "save",
            "open",
            "directory",
            "folder",
            "fs",
        ];

        for tool in &ctx.tools {
            let name_lower = tool.name.to_lowercase();

            for pattern in &file_patterns {
                if name_lower.contains(pattern) && has_path_parameters(&tool.input_schema) {
                    return Some(
                        Finding::new(
                            "MCP-INJ-003",
                            Severity::High,
                            "Potential Path Traversal",
                            format!(
                                "Tool '{}' performs file operations with user-controlled paths. \
                                 Path traversal attacks (../) may allow access to unauthorized files.",
                                tool.name
                            ),
                        )
                        .with_location(FindingLocation::tool(&tool.name))
                        .with_evidence(Evidence::observation(
                            format!(
                                "Tool '{}' has file-related name and accepts path parameters",
                                tool.name
                            ),
                            "File operation with user-controlled path",
                        ))
                        .with_remediation(
                            "Validate and sanitize file paths. Use allowlists for permitted directories. \
                             Resolve paths and verify they remain within allowed boundaries.",
                        )
                        .with_cwe("22"),
                    );
                }
            }
        }

        None
    }

    async fn check_ssrf(&self, ctx: &ServerContext, _client: &mut McpClient) -> Option<Finding> {
        let url_patterns = ["url", "uri", "fetch", "request", "http", "api", "endpoint"];

        for tool in &ctx.tools {
            let name_lower = tool.name.to_lowercase();

            for pattern in &url_patterns {
                if name_lower.contains(pattern) && has_url_parameters(&tool.input_schema) {
                    return Some(
                        Finding::new(
                            "MCP-INJ-004",
                            Severity::High,
                            "Potential SSRF Vulnerability",
                            format!(
                                "Tool '{}' accepts URL parameters that may allow Server-Side Request Forgery. \
                                 Attackers could use this to access internal services or cloud metadata.",
                                tool.name
                            ),
                        )
                        .with_location(FindingLocation::tool(&tool.name))
                        .with_evidence(Evidence::observation(
                            format!("Tool '{}' accepts URL/URI parameters", tool.name),
                            "Potential for server-side requests with user-controlled URLs",
                        ))
                        .with_remediation(
                            "Implement URL allowlisting. Block access to internal IP ranges \
                             (10.x.x.x, 172.16-31.x.x, 192.168.x.x) and cloud metadata endpoints. \
                             Validate URL schemes (allow only http/https).",
                        )
                        .with_cwe("918"),
                    );
                }
            }
        }

        None
    }
}
