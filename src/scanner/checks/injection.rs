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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::mcp::Tool;

    fn make_tool(name: &str, description: Option<&str>, schema: serde_json::Value) -> Tool {
        Tool {
            name: name.to_string(),
            description: description.map(|s| s.to_string()),
            input_schema: schema,
        }
    }

    fn make_string_schema() -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "input": { "type": "string" }
            }
        })
    }

    fn make_path_schema() -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "file_path": { "type": "string" }
            }
        })
    }

    fn make_url_schema() -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "target_url": { "type": "string" }
            }
        })
    }

    fn make_empty_schema() -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {}
        })
    }

    #[test]
    fn detect_command_injection_exec() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools
            .push(make_tool("exec_command", None, make_string_schema()));

        let finding = checker.check_command_injection(&ctx);
        assert!(finding.is_some());
        let f = finding.unwrap();
        assert_eq!(f.rule_id, "MCP-INJ-001");
        assert_eq!(f.severity, Severity::Critical);
    }

    #[test]
    fn detect_command_injection_shell() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools
            .push(make_tool("run_shell", None, make_string_schema()));

        let finding = checker.check_command_injection(&ctx);
        assert!(finding.is_some());
    }

    #[test]
    fn detect_command_injection_in_description() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools.push(make_tool(
            "process",
            Some("Executes a bash command"),
            make_string_schema(),
        ));

        let finding = checker.check_command_injection(&ctx);
        assert!(finding.is_some());
    }

    #[test]
    fn no_command_injection_safe_tool() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools
            .push(make_tool("get_data", None, make_string_schema()));

        let finding = checker.check_command_injection(&ctx);
        assert!(finding.is_none());
    }

    #[test]
    fn no_command_injection_no_string_params() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools
            .push(make_tool("exec_command", None, make_empty_schema()));

        let finding = checker.check_command_injection(&ctx);
        assert!(finding.is_none());
    }

    #[test]
    fn detect_sql_injection() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools
            .push(make_tool("execute_query", None, make_string_schema()));

        let finding = checker.check_sql_injection(&ctx);
        assert!(finding.is_some());
        let f = finding.unwrap();
        assert_eq!(f.rule_id, "MCP-INJ-002");
    }

    #[test]
    fn detect_sql_injection_database() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools
            .push(make_tool("database_search", None, make_string_schema()));

        let finding = checker.check_sql_injection(&ctx);
        assert!(finding.is_some());
    }

    #[test]
    fn no_sql_injection_safe_tool() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools
            .push(make_tool("search_files", None, make_string_schema()));

        let finding = checker.check_sql_injection(&ctx);
        assert!(finding.is_none());
    }

    #[test]
    fn detect_path_traversal() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools
            .push(make_tool("read_file", None, make_path_schema()));

        let finding = checker.check_path_traversal(&ctx);
        assert!(finding.is_some());
        let f = finding.unwrap();
        assert_eq!(f.rule_id, "MCP-INJ-003");
        assert_eq!(f.severity, Severity::High);
    }

    #[test]
    fn detect_path_traversal_directory() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools
            .push(make_tool("list_directory", None, make_path_schema()));

        let finding = checker.check_path_traversal(&ctx);
        assert!(finding.is_some());
    }

    #[test]
    fn no_path_traversal_no_path_params() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools
            .push(make_tool("read_file", None, make_string_schema()));

        let finding = checker.check_path_traversal(&ctx);
        assert!(finding.is_none());
    }

    #[test]
    fn ssrf_url_detection() {
        let mut ctx = ServerContext::for_test("test");
        ctx.tools
            .push(make_tool("fetch_url", None, make_url_schema()));

        // Test the synchronous pattern matching logic
        let tool = &ctx.tools[0];
        let has_url = has_url_parameters(&tool.input_schema);
        assert!(has_url);
        assert!(tool.name.to_lowercase().contains("url"));
    }

    #[test]
    fn ssrf_url_patterns() {
        let mut ctx = ServerContext::for_test("test");

        // Test various URL-related tool names
        for name in &["http_get", "api_call", "fetch_endpoint"] {
            ctx.tools.clear();
            ctx.tools.push(make_tool(name, None, make_url_schema()));

            // The pattern detection should work for these names
            let name_lower = name.to_lowercase();
            let url_patterns = ["url", "uri", "fetch", "request", "http", "api", "endpoint"];
            let matches = url_patterns.iter().any(|p| name_lower.contains(p));
            assert!(matches, "Pattern should match for {}", name);
        }
    }

    #[test]
    fn empty_tools_no_findings() {
        let checker = DefaultInjectionChecks;
        let ctx = ServerContext::for_test("test");

        assert!(checker.check_command_injection(&ctx).is_none());
        assert!(checker.check_sql_injection(&ctx).is_none());
        assert!(checker.check_path_traversal(&ctx).is_none());
    }
}
