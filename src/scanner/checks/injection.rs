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

    // Additional comprehensive tests

    #[test]
    fn detect_command_injection_powershell() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools
            .push(make_tool("run_powershell", None, make_string_schema()));

        let finding = checker.check_command_injection(&ctx);
        assert!(finding.is_some());
        let f = finding.unwrap();
        assert_eq!(f.rule_id, "MCP-INJ-001");
        assert!(f.description.contains("run_powershell"));
    }

    #[test]
    fn detect_command_injection_spawn() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools
            .push(make_tool("spawn_process", None, make_string_schema()));

        let finding = checker.check_command_injection(&ctx);
        assert!(finding.is_some());
    }

    #[test]
    fn detect_command_injection_system() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools
            .push(make_tool("system_call", None, make_string_schema()));

        let finding = checker.check_command_injection(&ctx);
        assert!(finding.is_some());
    }

    #[test]
    fn detect_command_injection_popen() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools
            .push(make_tool("popen_command", None, make_string_schema()));

        let finding = checker.check_command_injection(&ctx);
        assert!(finding.is_some());
    }

    #[test]
    fn detect_command_injection_case_insensitive() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools
            .push(make_tool("RUN_SHELL", None, make_string_schema()));

        let finding = checker.check_command_injection(&ctx);
        assert!(finding.is_some());
    }

    #[test]
    fn detect_command_injection_description_only() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools.push(make_tool(
            "process_data",
            Some("Uses system commands to process data"),
            make_string_schema(),
        ));

        let finding = checker.check_command_injection(&ctx);
        assert!(finding.is_some());
    }

    #[test]
    fn command_injection_finding_has_remediation() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools
            .push(make_tool("exec_command", None, make_string_schema()));

        let finding = checker.check_command_injection(&ctx).unwrap();
        assert!(!finding.remediation.is_empty());
        assert!(finding.remediation.contains("parameterized commands"));
    }

    #[test]
    fn command_injection_finding_has_cwe() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools
            .push(make_tool("exec_command", None, make_string_schema()));

        let finding = checker.check_command_injection(&ctx).unwrap();
        assert!(finding.references.iter().any(|r| r.id == "CWE-78"));
    }

    #[test]
    fn detect_sql_injection_mysql() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools
            .push(make_tool("mysql_query", None, make_string_schema()));

        let finding = checker.check_sql_injection(&ctx);
        assert!(finding.is_some());
    }

    #[test]
    fn detect_sql_injection_postgres() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools
            .push(make_tool("postgres_execute", None, make_string_schema()));

        let finding = checker.check_sql_injection(&ctx);
        assert!(finding.is_some());
    }

    #[test]
    fn detect_sql_injection_sqlite() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools
            .push(make_tool("sqlite_query", None, make_string_schema()));

        let finding = checker.check_sql_injection(&ctx);
        assert!(finding.is_some());
    }

    #[test]
    fn detect_sql_injection_mongodb() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools
            .push(make_tool("mongodb_find", None, make_string_schema()));

        let finding = checker.check_sql_injection(&ctx);
        assert!(finding.is_some());
    }

    #[test]
    fn detect_sql_injection_in_description() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools.push(make_tool(
            "search",
            Some("Executes SQL queries to search database"),
            make_string_schema(),
        ));

        let finding = checker.check_sql_injection(&ctx);
        assert!(finding.is_some());
    }

    #[test]
    fn sql_injection_finding_has_remediation() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools
            .push(make_tool("execute_query", None, make_string_schema()));

        let finding = checker.check_sql_injection(&ctx).unwrap();
        assert!(!finding.remediation.is_empty());
        assert!(finding.remediation.contains("parameterized queries"));
    }

    #[test]
    fn sql_injection_finding_has_cwe() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools
            .push(make_tool("execute_query", None, make_string_schema()));

        let finding = checker.check_sql_injection(&ctx).unwrap();
        assert!(finding.references.iter().any(|r| r.id == "CWE-89"));
    }

    #[test]
    fn detect_path_traversal_write() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools
            .push(make_tool("write_file", None, make_path_schema()));

        let finding = checker.check_path_traversal(&ctx);
        assert!(finding.is_some());
    }

    #[test]
    fn detect_path_traversal_load() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools
            .push(make_tool("load_config", None, make_path_schema()));

        let finding = checker.check_path_traversal(&ctx);
        assert!(finding.is_some());
    }

    #[test]
    fn detect_path_traversal_save() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools
            .push(make_tool("save_data", None, make_path_schema()));

        let finding = checker.check_path_traversal(&ctx);
        assert!(finding.is_some());
    }

    #[test]
    fn detect_path_traversal_open() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools
            .push(make_tool("open_document", None, make_path_schema()));

        let finding = checker.check_path_traversal(&ctx);
        assert!(finding.is_some());
    }

    #[test]
    fn detect_path_traversal_folder() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools
            .push(make_tool("list_folder", None, make_path_schema()));

        let finding = checker.check_path_traversal(&ctx);
        assert!(finding.is_some());
    }

    #[test]
    fn detect_path_traversal_fs() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools
            .push(make_tool("fs_operations", None, make_path_schema()));

        let finding = checker.check_path_traversal(&ctx);
        assert!(finding.is_some());
    }

    #[test]
    fn path_traversal_finding_has_remediation() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools
            .push(make_tool("read_file", None, make_path_schema()));

        let finding = checker.check_path_traversal(&ctx).unwrap();
        assert!(!finding.remediation.is_empty());
        assert!(finding.remediation.contains("allowlists"));
    }

    #[test]
    fn path_traversal_finding_has_cwe() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools
            .push(make_tool("read_file", None, make_path_schema()));

        let finding = checker.check_path_traversal(&ctx).unwrap();
        assert!(finding.references.iter().any(|r| r.id == "CWE-22"));
    }

    #[test]
    fn no_path_traversal_safe_name() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools
            .push(make_tool("calculate_result", None, make_path_schema()));

        let finding = checker.check_path_traversal(&ctx);
        assert!(finding.is_none());
    }

    #[test]
    fn ssrf_http_detection() {
        let mut ctx = ServerContext::for_test("test");
        ctx.tools
            .push(make_tool("http_request", None, make_url_schema()));

        let tool = &ctx.tools[0];
        let has_url = has_url_parameters(&tool.input_schema);
        assert!(has_url);
        assert!(tool.name.to_lowercase().contains("http"));
    }

    #[test]
    fn ssrf_api_detection() {
        let mut ctx = ServerContext::for_test("test");
        ctx.tools
            .push(make_tool("call_api", None, make_url_schema()));

        let tool = &ctx.tools[0];
        let has_url = has_url_parameters(&tool.input_schema);
        assert!(has_url);
        assert!(tool.name.to_lowercase().contains("api"));
    }

    #[test]
    fn ssrf_endpoint_detection() {
        let mut ctx = ServerContext::for_test("test");
        ctx.tools
            .push(make_tool("query_endpoint", None, make_url_schema()));

        let tool = &ctx.tools[0];
        let has_url = has_url_parameters(&tool.input_schema);
        assert!(has_url);
        assert!(tool.name.to_lowercase().contains("endpoint"));
    }

    #[test]
    fn multiple_tools_first_match() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools
            .push(make_tool("safe_tool", None, make_string_schema()));
        ctx.tools
            .push(make_tool("exec_command", None, make_string_schema()));
        ctx.tools
            .push(make_tool("another_exec", None, make_string_schema()));

        let finding = checker.check_command_injection(&ctx);
        assert!(finding.is_some());
        let f = finding.unwrap();
        assert!(f.description.contains("exec_command"));
    }

    #[test]
    fn complex_schema_with_string_params() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "command": { "type": "string" },
                "args": { "type": "array", "items": { "type": "string" } },
                "timeout": { "type": "number" }
            }
        });
        ctx.tools.push(make_tool("exec", None, schema));

        let finding = checker.check_command_injection(&ctx);
        assert!(finding.is_some());
    }

    #[test]
    fn tool_with_empty_description() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools
            .push(make_tool("shell_runner", Some(""), make_string_schema()));

        let finding = checker.check_command_injection(&ctx);
        assert!(finding.is_some());
    }

    #[test]
    fn pattern_matching_partial_words() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        // "shell" should match within "shellcode"
        ctx.tools
            .push(make_tool("shellcode_generator", None, make_string_schema()));

        let finding = checker.check_command_injection(&ctx);
        assert!(finding.is_some());
    }

    #[test]
    fn no_sql_injection_without_string_params() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "id": { "type": "number" }
            }
        });
        ctx.tools.push(make_tool("execute_query", None, schema));

        let finding = checker.check_sql_injection(&ctx);
        assert!(finding.is_none());
    }

    #[test]
    fn finding_location_is_tool() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools
            .push(make_tool("exec_command", None, make_string_schema()));

        let finding = checker.check_command_injection(&ctx).unwrap();
        assert_eq!(finding.location.component, "tool");
        assert_eq!(finding.location.identifier, "exec_command");
    }

    #[test]
    fn finding_has_evidence() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools
            .push(make_tool("exec_command", None, make_string_schema()));

        let finding = checker.check_command_injection(&ctx).unwrap();
        assert!(!finding.evidence.is_empty());
    }

    // Additional edge case tests for command injection
    #[test]
    fn command_injection_run_pattern() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools
            .push(make_tool("run_script", None, make_string_schema()));

        let finding = checker.check_command_injection(&ctx);
        assert!(finding.is_some());
    }

    #[test]
    fn command_injection_multiple_patterns_in_name() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools
            .push(make_tool("shell_exec_command", None, make_string_schema()));

        let finding = checker.check_command_injection(&ctx);
        assert!(finding.is_some());
    }

    #[test]
    fn command_injection_description_with_no_pattern_in_name() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools.push(make_tool(
            "process_data",
            Some("Execute shell commands"),
            make_string_schema(),
        ));

        let finding = checker.check_command_injection(&ctx);
        assert!(finding.is_some());
    }

    // SQL injection edge cases
    #[test]
    fn sql_injection_query_pattern() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools
            .push(make_tool("query_database", None, make_string_schema()));

        let finding = checker.check_sql_injection(&ctx);
        assert!(finding.is_some());
    }

    #[test]
    fn sql_injection_sql_pattern() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools
            .push(make_tool("sql_runner", None, make_string_schema()));

        let finding = checker.check_sql_injection(&ctx);
        assert!(finding.is_some());
    }

    #[test]
    fn sql_injection_description_pattern() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools.push(make_tool(
            "data_fetcher",
            Some("Runs database queries"),
            make_string_schema(),
        ));

        let finding = checker.check_sql_injection(&ctx);
        assert!(finding.is_some());
    }

    // Path traversal edge cases
    #[test]
    fn path_traversal_path_pattern() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools
            .push(make_tool("path_reader", None, make_path_schema()));

        let finding = checker.check_path_traversal(&ctx);
        assert!(finding.is_some());
    }

    #[test]
    fn path_traversal_read_pattern() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools
            .push(make_tool("read_data", None, make_path_schema()));

        let finding = checker.check_path_traversal(&ctx);
        assert!(finding.is_some());
    }

    // Schema edge cases
    #[test]
    fn empty_schema_no_findings() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools
            .push(make_tool("exec_command", None, serde_json::json!({})));

        let finding = checker.check_command_injection(&ctx);
        assert!(finding.is_none());
    }

    #[test]
    fn schema_with_non_string_properties() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "count": { "type": "integer" },
                "enabled": { "type": "boolean" }
            }
        });
        ctx.tools.push(make_tool("exec_command", None, schema));

        let finding = checker.check_command_injection(&ctx);
        assert!(finding.is_none());
    }

    // Multiple tools edge cases
    #[test]
    fn first_unsafe_tool_detected() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools
            .push(make_tool("safe_tool1", None, make_string_schema()));
        ctx.tools
            .push(make_tool("safe_tool2", None, make_string_schema()));
        ctx.tools
            .push(make_tool("exec_dangerous", None, make_string_schema()));
        ctx.tools
            .push(make_tool("exec_also_dangerous", None, make_string_schema()));

        let finding = checker.check_command_injection(&ctx);
        assert!(finding.is_some());
        let f = finding.unwrap();
        assert!(f.description.contains("exec_dangerous"));
    }

    // Description case sensitivity
    #[test]
    fn command_injection_case_insensitive_description() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools.push(make_tool(
            "processor",
            Some("Executes SHELL Commands"),
            make_string_schema(),
        ));

        let finding = checker.check_command_injection(&ctx);
        assert!(finding.is_some());
    }

    // Complex schemas
    #[test]
    fn command_injection_nested_schema_properties() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "config": {
                    "type": "object",
                    "properties": {
                        "command": { "type": "string" }
                    }
                },
                "options": { "type": "string" }
            }
        });
        ctx.tools.push(make_tool("shell_runner", None, schema));

        let finding = checker.check_command_injection(&ctx);
        assert!(finding.is_some());
    }

    // Pattern matching comprehensive
    #[test]
    fn all_command_injection_patterns() {
        let checker = DefaultInjectionChecks;
        let patterns = vec![
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

        for pattern in patterns {
            let mut ctx = ServerContext::for_test("test");
            ctx.tools
                .push(make_tool(pattern, None, make_string_schema()));

            let finding = checker.check_command_injection(&ctx);
            assert!(
                finding.is_some(),
                "Pattern '{}' should trigger finding",
                pattern
            );
        }
    }

    #[test]
    fn all_sql_injection_patterns() {
        let checker = DefaultInjectionChecks;
        let patterns = vec![
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

        for pattern in patterns {
            let mut ctx = ServerContext::for_test("test");
            ctx.tools
                .push(make_tool(pattern, None, make_string_schema()));

            let finding = checker.check_sql_injection(&ctx);
            assert!(
                finding.is_some(),
                "Pattern '{}' should trigger finding",
                pattern
            );
        }
    }

    #[test]
    fn all_path_traversal_patterns() {
        let checker = DefaultInjectionChecks;
        let patterns = vec![
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

        for pattern in patterns {
            let mut ctx = ServerContext::for_test("test");
            ctx.tools.push(make_tool(pattern, None, make_path_schema()));

            let finding = checker.check_path_traversal(&ctx);
            assert!(
                finding.is_some(),
                "Pattern '{}' should trigger finding",
                pattern
            );
        }
    }

    // SSRF edge cases with synchronous checks
    #[test]
    fn ssrf_uri_pattern_in_schema() {
        let mut ctx = ServerContext::for_test("test");
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "uri": { "type": "string" }
            }
        });
        ctx.tools.push(make_tool("fetch_resource", None, schema));

        let tool = &ctx.tools[0];
        assert!(has_url_parameters(&tool.input_schema));
    }

    #[test]
    fn ssrf_href_pattern_in_schema() {
        let mut ctx = ServerContext::for_test("test");
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "href": { "type": "string" }
            }
        });
        ctx.tools.push(make_tool("http_get", None, schema));

        let tool = &ctx.tools[0];
        assert!(has_url_parameters(&tool.input_schema));
    }

    #[test]
    fn ssrf_link_pattern_in_schema() {
        let mut ctx = ServerContext::for_test("test");
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "link": { "type": "string" }
            }
        });
        ctx.tools.push(make_tool("fetch_link", None, schema));

        let tool = &ctx.tools[0];
        assert!(has_url_parameters(&tool.input_schema));
    }

    #[test]
    fn ssrf_endpoint_pattern_in_schema() {
        let mut ctx = ServerContext::for_test("test");
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "endpoint": { "type": "string" }
            }
        });
        ctx.tools.push(make_tool("call_endpoint", None, schema));

        let tool = &ctx.tools[0];
        assert!(has_url_parameters(&tool.input_schema));
    }

    // Tool name variations
    #[test]
    fn tool_name_with_underscores() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools.push(make_tool(
            "execute_shell_command",
            None,
            make_string_schema(),
        ));

        let finding = checker.check_command_injection(&ctx);
        assert!(finding.is_some());
    }

    #[test]
    fn tool_name_with_mixed_case() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools
            .push(make_tool("ExecuteShellCommand", None, make_string_schema()));

        let finding = checker.check_command_injection(&ctx);
        assert!(finding.is_some());
    }

    // Empty description edge case
    #[test]
    fn tool_with_none_description() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools
            .push(make_tool("exec", None, make_string_schema()));

        let finding = checker.check_command_injection(&ctx);
        assert!(finding.is_some());
    }

    // Finding structure validation
    #[test]
    fn command_injection_finding_structure() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools
            .push(make_tool("exec_command", None, make_string_schema()));

        let finding = checker.check_command_injection(&ctx).unwrap();

        assert_eq!(finding.rule_id, "MCP-INJ-001");
        assert_eq!(finding.severity, Severity::Critical);
        assert_eq!(finding.title, "Potential Command Injection");
        assert!(!finding.description.is_empty());
        assert!(!finding.remediation.is_empty());
        assert!(!finding.evidence.is_empty());
        assert_eq!(finding.location.component, "tool");
        assert_eq!(finding.location.identifier, "exec_command");
    }

    #[test]
    fn sql_injection_finding_structure() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools
            .push(make_tool("execute_query", None, make_string_schema()));

        let finding = checker.check_sql_injection(&ctx).unwrap();

        assert_eq!(finding.rule_id, "MCP-INJ-002");
        assert_eq!(finding.severity, Severity::Critical);
        assert_eq!(finding.title, "Potential SQL Injection");
    }

    #[test]
    fn path_traversal_finding_structure() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools
            .push(make_tool("read_file", None, make_path_schema()));

        let finding = checker.check_path_traversal(&ctx).unwrap();

        assert_eq!(finding.rule_id, "MCP-INJ-003");
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(finding.title, "Potential Path Traversal");
    }

    // Multiple pattern matches should stop at first
    #[test]
    fn stops_at_first_pattern_match() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        // Tool has multiple patterns but should match on first
        ctx.tools.push(make_tool(
            "exec",
            Some("shell command runner"),
            make_string_schema(),
        ));

        let finding = checker.check_command_injection(&ctx);
        assert!(finding.is_some());
    }

    // Schema helper validation
    #[test]
    fn has_string_parameters_mixed_types() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "id": { "type": "integer" },
                "name": { "type": "string" },
                "enabled": { "type": "boolean" }
            }
        });
        assert!(has_string_parameters(&schema));
    }

    #[test]
    fn has_path_parameters_dir_variant() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "dir": { "type": "string" }
            }
        });
        assert!(has_path_parameters(&schema));
    }

    // Context coverage
    #[test]
    fn server_context_empty_tools() {
        let checker = DefaultInjectionChecks;
        let ctx = ServerContext::for_test("test");

        assert!(checker.check_command_injection(&ctx).is_none());
        assert!(checker.check_sql_injection(&ctx).is_none());
        assert!(checker.check_path_traversal(&ctx).is_none());
    }

    // Case sensitivity edge cases
    #[test]
    fn pattern_matching_uppercase_name() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools
            .push(make_tool("EXEC_COMMAND", None, make_string_schema()));

        let finding = checker.check_command_injection(&ctx);
        assert!(finding.is_some());
    }

    #[test]
    fn pattern_matching_uppercase_description() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools.push(make_tool(
            "processor",
            Some("EXECUTES SHELL COMMANDS"),
            make_string_schema(),
        ));

        let finding = checker.check_command_injection(&ctx);
        assert!(finding.is_some());
    }

    // Additional edge cases for better coverage

    #[test]
    fn command_injection_cmd_pattern() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools
            .push(make_tool("cmd_runner", None, make_string_schema()));

        let finding = checker.check_command_injection(&ctx);
        assert!(finding.is_some());
        let f = finding.unwrap();
        assert_eq!(f.rule_id, "MCP-INJ-001");
    }

    #[test]
    fn command_injection_bash_pattern() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools
            .push(make_tool("bash_executor", None, make_string_schema()));

        let finding = checker.check_command_injection(&ctx);
        assert!(finding.is_some());
    }

    #[test]
    fn command_injection_sh_pattern() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools
            .push(make_tool("sh_script", None, make_string_schema()));

        let finding = checker.check_command_injection(&ctx);
        assert!(finding.is_some());
    }

    #[test]
    fn sql_injection_db_pattern() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools
            .push(make_tool("db_operation", None, make_string_schema()));

        let finding = checker.check_sql_injection(&ctx);
        assert!(finding.is_some());
    }

    #[test]
    fn path_traversal_file_pattern() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools
            .push(make_tool("file_handler", None, make_path_schema()));

        let finding = checker.check_path_traversal(&ctx);
        assert!(finding.is_some());
    }

    #[test]
    fn command_injection_description_uppercase_exec() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools.push(make_tool(
            "processor",
            Some("EXEC operations"),
            make_string_schema(),
        ));

        let finding = checker.check_command_injection(&ctx);
        assert!(finding.is_some());
    }

    #[test]
    fn sql_injection_description_uppercase_sql() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools.push(make_tool(
            "data_handler",
            Some("EXECUTE SQL QUERY"),
            make_string_schema(),
        ));

        let finding = checker.check_sql_injection(&ctx);
        assert!(finding.is_some());
    }

    // Test special characters and edge cases in tool names
    #[test]
    fn command_injection_special_chars_in_name() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools
            .push(make_tool("exec-command", None, make_string_schema()));

        let finding = checker.check_command_injection(&ctx);
        assert!(finding.is_some());
    }

    #[test]
    fn empty_string_description_with_pattern_in_name() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools
            .push(make_tool("shell_exec", Some(""), make_string_schema()));

        let finding = checker.check_command_injection(&ctx);
        assert!(finding.is_some());
    }

    // Test schema edge cases
    #[test]
    fn schema_without_properties_field() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        let schema = serde_json::json!({
            "type": "object"
        });
        ctx.tools.push(make_tool("exec_command", None, schema));

        let finding = checker.check_command_injection(&ctx);
        assert!(finding.is_none());
    }

    #[test]
    fn schema_with_null_properties() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        let schema = serde_json::json!({
            "type": "object",
            "properties": null
        });
        ctx.tools.push(make_tool("exec_command", None, schema));

        let finding = checker.check_command_injection(&ctx);
        assert!(finding.is_none());
    }

    #[test]
    fn schema_with_array_type() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "items": {
                    "type": "array",
                    "items": { "type": "string" }
                }
            }
        });
        ctx.tools.push(make_tool("shell_runner", None, schema));

        // Should not trigger because top-level properties don't have string type
        let finding = checker.check_command_injection(&ctx);
        assert!(finding.is_none());
    }

    #[test]
    fn path_traversal_description_ignored() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools.push(make_tool(
            "data_processor",
            Some("reads file content"),
            make_path_schema(),
        ));

        // Path traversal only checks name, not description
        let finding = checker.check_path_traversal(&ctx);
        assert!(finding.is_none());
    }

    #[test]
    fn ssrf_fetch_pattern() {
        let mut ctx = ServerContext::for_test("test");
        ctx.tools
            .push(make_tool("fetch_resource", None, make_url_schema()));

        let tool = &ctx.tools[0];
        assert!(has_url_parameters(&tool.input_schema));
        assert!(tool.name.to_lowercase().contains("fetch"));
    }

    #[test]
    fn ssrf_request_pattern() {
        let mut ctx = ServerContext::for_test("test");
        ctx.tools
            .push(make_tool("make_request", None, make_url_schema()));

        let tool = &ctx.tools[0];
        assert!(has_url_parameters(&tool.input_schema));
        assert!(tool.name.to_lowercase().contains("request"));
    }

    #[test]
    fn ssrf_uri_pattern() {
        let mut ctx = ServerContext::for_test("test");
        ctx.tools
            .push(make_tool("uri_handler", None, make_url_schema()));

        let tool = &ctx.tools[0];
        assert!(has_url_parameters(&tool.input_schema));
        assert!(tool.name.to_lowercase().contains("uri"));
    }

    // Test multiple tools with different findings
    #[test]
    fn multiple_tools_sql_injection_first_match() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools
            .push(make_tool("safe_processor", None, make_string_schema()));
        ctx.tools
            .push(make_tool("sql_executor", None, make_string_schema()));
        ctx.tools
            .push(make_tool("another_query", None, make_string_schema()));

        let finding = checker.check_sql_injection(&ctx);
        assert!(finding.is_some());
        let f = finding.unwrap();
        assert!(f.description.contains("sql_executor"));
    }

    #[test]
    fn multiple_tools_path_traversal_first_match() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools
            .push(make_tool("calculator", None, make_path_schema()));
        ctx.tools
            .push(make_tool("read_file", None, make_path_schema()));
        ctx.tools
            .push(make_tool("write_file", None, make_path_schema()));

        let finding = checker.check_path_traversal(&ctx);
        assert!(finding.is_some());
        let f = finding.unwrap();
        assert!(f.description.contains("read_file"));
    }

    // Test evidence field content
    #[test]
    fn command_injection_evidence_contains_pattern() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools
            .push(make_tool("exec_command", None, make_string_schema()));

        let finding = checker.check_command_injection(&ctx).unwrap();
        assert!(finding.evidence.len() > 0);
        let evidence_text = format!("{:?}", finding.evidence);
        assert!(evidence_text.contains("exec"));
    }

    #[test]
    fn sql_injection_evidence_contains_pattern() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools
            .push(make_tool("sql_query", None, make_string_schema()));

        let finding = checker.check_sql_injection(&ctx).unwrap();
        assert!(finding.evidence.len() > 0);
        let evidence_text = format!("{:?}", finding.evidence);
        assert!(evidence_text.contains("sql"));
    }

    // Test pattern matching behavior with contains() - these DO trigger
    #[test]
    fn pattern_matching_helper_contains_shell() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        // "helper" does NOT contain "shell" pattern
        ctx.tools
            .push(make_tool("data_helper", None, make_string_schema()));

        let finding = checker.check_command_injection(&ctx);
        assert!(finding.is_none());
    }

    #[test]
    fn pattern_matching_sequel_no_match() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        // "sequel" does NOT contain "sql" pattern - no match
        ctx.tools
            .push(make_tool("sequel_story", None, make_string_schema()));

        let finding = checker.check_sql_injection(&ctx);
        assert!(finding.is_none()); // "sequel" doesn't contain "sql"
    }

    #[test]
    fn pattern_matching_refill_no_match() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        // "refill" does NOT contain "file" pattern - no match
        ctx.tools
            .push(make_tool("refill_cache", None, make_path_schema()));

        let finding = checker.check_path_traversal(&ctx);
        assert!(finding.is_none()); // "refill" doesn't contain "file"
    }

    // Test tool name patterns with numbers
    #[test]
    fn command_injection_name_with_numbers() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools
            .push(make_tool("exec2000", None, make_string_schema()));

        let finding = checker.check_command_injection(&ctx);
        assert!(finding.is_some());
    }

    // Test description with whitespace variations
    #[test]
    fn command_injection_description_with_tabs() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools.push(make_tool(
            "processor",
            Some("Runs\tshell\tcommands"),
            make_string_schema(),
        ));

        let finding = checker.check_command_injection(&ctx);
        assert!(finding.is_some());
    }

    #[test]
    fn command_injection_description_with_newlines() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools.push(make_tool(
            "processor",
            Some("Runs\nshell\ncommands"),
            make_string_schema(),
        ));

        let finding = checker.check_command_injection(&ctx);
        assert!(finding.is_some());
    }

    // Test remediation content
    #[test]
    fn sql_injection_remediation_mentions_prepared_statements() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools
            .push(make_tool("execute_query", None, make_string_schema()));

        let finding = checker.check_sql_injection(&ctx).unwrap();
        assert!(finding.remediation.to_lowercase().contains("prepared"));
    }

    #[test]
    fn path_traversal_remediation_mentions_validation() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools
            .push(make_tool("read_file", None, make_path_schema()));

        let finding = checker.check_path_traversal(&ctx).unwrap();
        assert!(
            finding.remediation.to_lowercase().contains("validate")
                || finding.remediation.to_lowercase().contains("sanitize")
        );
    }

    // Test all URL patterns for SSRF
    #[test]
    fn all_ssrf_url_patterns() {
        let patterns = vec!["url", "uri", "fetch", "request", "http", "api", "endpoint"];

        for pattern in patterns {
            let mut ctx = ServerContext::for_test("test");
            let tool_name = format!("{}_handler", pattern);
            ctx.tools.push(make_tool(&tool_name, None, make_url_schema()));

            let tool = &ctx.tools[0];
            let has_url = has_url_parameters(&tool.input_schema);
            let name_matches = tool.name.to_lowercase().contains(pattern);

            assert!(
                has_url && name_matches,
                "Pattern '{}' should match for SSRF detection",
                pattern
            );
        }
    }

    // Test pattern at different positions in name
    #[test]
    fn command_injection_pattern_at_start() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools
            .push(make_tool("exec_something", None, make_string_schema()));

        let finding = checker.check_command_injection(&ctx);
        assert!(finding.is_some());
    }

    #[test]
    fn command_injection_pattern_at_end() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools
            .push(make_tool("something_exec", None, make_string_schema()));

        let finding = checker.check_command_injection(&ctx);
        assert!(finding.is_some());
    }

    #[test]
    fn command_injection_pattern_in_middle() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools
            .push(make_tool("run_exec_now", None, make_string_schema()));

        let finding = checker.check_command_injection(&ctx);
        assert!(finding.is_some());
    }

    // Test complex nested schemas
    #[test]
    fn command_injection_deeply_nested_schema() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "level1": {
                    "type": "object",
                    "properties": {
                        "level2": {
                            "type": "object",
                            "properties": {
                                "command": { "type": "string" }
                            }
                        }
                    }
                }
            }
        });
        ctx.tools.push(make_tool("exec_tool", None, schema));

        // Current implementation only checks top-level properties
        let finding = checker.check_command_injection(&ctx);
        assert!(finding.is_none());
    }

    // Test array of strings in schema
    #[test]
    fn command_injection_array_of_strings_schema() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "commands": {
                    "type": "array",
                    "items": { "type": "string" }
                }
            }
        });
        ctx.tools.push(make_tool("exec_multiple", None, schema));

        // Current implementation checks for direct string type, not array items
        let finding = checker.check_command_injection(&ctx);
        assert!(finding.is_none());
    }

    // Test schema with mixed property types including string
    #[test]
    fn sql_injection_schema_with_multiple_strings() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "query": { "type": "string" },
                "database": { "type": "string" },
                "timeout": { "type": "number" }
            }
        });
        ctx.tools.push(make_tool("sql_execute", None, schema));

        let finding = checker.check_sql_injection(&ctx);
        assert!(finding.is_some());
    }

    // Test that only first matching tool is reported
    #[test]
    fn only_first_vulnerable_tool_reported() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools
            .push(make_tool("exec_first", None, make_string_schema()));
        ctx.tools
            .push(make_tool("shell_second", None, make_string_schema()));

        let finding = checker.check_command_injection(&ctx);
        assert!(finding.is_some());
        let f = finding.unwrap();
        // Should report the first one found
        assert!(f.description.contains("exec_first"));
    }

    // Test location information
    #[test]
    fn sql_injection_location_information() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools
            .push(make_tool("sql_query", None, make_string_schema()));

        let finding = checker.check_sql_injection(&ctx).unwrap();
        assert_eq!(finding.location.component, "tool");
        assert_eq!(finding.location.identifier, "sql_query");
    }

    #[test]
    fn path_traversal_location_information() {
        let checker = DefaultInjectionChecks;
        let mut ctx = ServerContext::for_test("test");
        ctx.tools
            .push(make_tool("file_reader", None, make_path_schema()));

        let finding = checker.check_path_traversal(&ctx).unwrap();
        assert_eq!(finding.location.component, "tool");
        assert_eq!(finding.location.identifier, "file_reader");
    }
}
