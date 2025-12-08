//! Scan Engine - Core security scanning orchestration
//!
//! Coordinates security rule execution and findings collection.

use std::time::Instant;

use anyhow::{Context, Result};
use regex::Regex;

use crate::client::McpClient;
use crate::protocol::mcp::Tool;
use crate::protocol::Implementation;
use crate::transport::{connect_with_type, TransportConfig, TransportType};

use super::context::{ScanConfig, ScanProfile, ServerContext};
use super::finding::{Evidence, Finding, FindingLocation, Reference, Severity};

/// Results from a security scan
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ScanResults {
    /// Server that was scanned
    pub server: String,
    /// Profile used for scanning
    pub profile: String,
    /// Total checks performed
    pub total_checks: usize,
    /// Findings from the scan
    pub findings: Vec<Finding>,
    /// Summary of findings by severity
    pub summary: ScanSummary,
    /// Total scan duration in milliseconds
    pub duration_ms: u64,
}

/// Summary of scan findings by severity
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ScanSummary {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

impl ScanResults {
    pub fn new(server: &str, profile: ScanProfile) -> Self {
        Self {
            server: server.to_string(),
            profile: profile.to_string(),
            total_checks: 0,
            findings: Vec::new(),
            summary: ScanSummary::default(),
            duration_ms: 0,
        }
    }

    pub fn add_finding(&mut self, finding: Finding) {
        match finding.severity {
            Severity::Critical => self.summary.critical += 1,
            Severity::High => self.summary.high += 1,
            Severity::Medium => self.summary.medium += 1,
            Severity::Low => self.summary.low += 1,
            Severity::Info => self.summary.info += 1,
        }
        self.findings.push(finding);
    }

    pub fn has_critical_or_high(&self) -> bool {
        self.summary.critical > 0 || self.summary.high > 0
    }

    pub fn total_findings(&self) -> usize {
        self.findings.len()
    }
}

/// Security scan engine
pub struct ScanEngine {
    config: ScanConfig,
}

impl ScanEngine {
    pub fn new(config: ScanConfig) -> Self {
        Self { config }
    }

    /// Run a security scan against the specified server
    pub async fn scan(
        &self,
        target: &str,
        args: &[String],
        transport_type: Option<TransportType>,
    ) -> Result<ScanResults> {
        let start = Instant::now();
        let mut results = ScanResults::new(target, self.config.profile);

        // Connect to server
        let transport =
            transport_type.unwrap_or_else(|| crate::transport::detect_transport_type(target));

        let transport_config = TransportConfig {
            timeout_secs: self.config.timeout_secs,
            ..Default::default()
        };

        tracing::info!("Connecting to server: {} via {:?}", target, transport);
        let transport_box = connect_with_type(target, args, transport_config, transport)
            .await
            .context("Failed to connect to server")?;

        // Create and initialize client
        let client_info = Implementation::new("mcplint-scanner", env!("CARGO_PKG_VERSION"));
        let mut client = McpClient::new(transport_box, client_info);

        let init_result = client.initialize().await?;

        // Build server context
        let mut ctx = ServerContext::new(
            &init_result.server_info.name,
            &init_result.server_info.version,
            &init_result.protocol_version,
            init_result.capabilities.clone(),
        )
        .with_transport(transport.as_str())
        .with_target(target);

        // Collect tools, resources, prompts
        if init_result.capabilities.has_tools() {
            if let Ok(tools) = client.list_tools().await {
                ctx = ctx.with_tools(tools);
            }
        }

        if init_result.capabilities.has_resources() {
            if let Ok(resources) = client.list_resources().await {
                ctx = ctx.with_resources(resources);
            }
        }

        if init_result.capabilities.has_prompts() {
            if let Ok(prompts) = client.list_prompts().await {
                ctx = ctx.with_prompts(prompts);
            }
        }

        // Run security checks
        self.run_injection_checks(&ctx, &mut client, &mut results)
            .await;
        self.run_auth_checks(&ctx, &mut results);
        self.run_transport_checks(&ctx, &mut results);
        self.run_protocol_checks(&ctx, &mut results);
        self.run_data_checks(&ctx, &mut results);
        self.run_dos_checks(&ctx, &mut results);

        // Cleanup
        let _ = client.close().await;

        results.duration_ms = start.elapsed().as_millis() as u64;
        Ok(results)
    }

    /// MCP-INJ-001 to MCP-INJ-004: Injection vulnerability checks
    async fn run_injection_checks(
        &self,
        ctx: &ServerContext,
        client: &mut McpClient,
        results: &mut ScanResults,
    ) {
        // MCP-INJ-001: Command injection via tool arguments
        if self.should_run("MCP-INJ-001", "injection") {
            results.total_checks += 1;
            if let Some(finding) = self.check_command_injection(ctx) {
                results.add_finding(finding);
            }
        }

        // MCP-INJ-002: SQL injection in database tools
        if self.should_run("MCP-INJ-002", "injection") {
            results.total_checks += 1;
            if let Some(finding) = self.check_sql_injection(ctx) {
                results.add_finding(finding);
            }
        }

        // MCP-INJ-003: Path traversal
        if self.should_run("MCP-INJ-003", "injection") {
            results.total_checks += 1;
            if let Some(finding) = self.check_path_traversal(ctx) {
                results.add_finding(finding);
            }
        }

        // MCP-INJ-004: SSRF
        if self.should_run("MCP-INJ-004", "injection") {
            results.total_checks += 1;
            if let Some(finding) = self.check_ssrf(ctx, client).await {
                results.add_finding(finding);
            }
        }
    }

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
                if name_lower.contains(pattern) || desc_lower.contains(pattern) {
                    // Check if input schema has string parameters (potential injection points)
                    if has_string_parameters(&tool.input_schema) {
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
                if name_lower.contains(pattern) || desc_lower.contains(pattern) {
                    if has_string_parameters(&tool.input_schema) {
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
                if name_lower.contains(pattern) {
                    // Check for path-like parameters
                    if has_path_parameters(&tool.input_schema) {
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
        }

        None
    }

    async fn check_ssrf(&self, ctx: &ServerContext, _client: &mut McpClient) -> Option<Finding> {
        let url_patterns = ["url", "uri", "fetch", "request", "http", "api", "endpoint"];

        for tool in &ctx.tools {
            let name_lower = tool.name.to_lowercase();

            for pattern in &url_patterns {
                if name_lower.contains(pattern) {
                    if has_url_parameters(&tool.input_schema) {
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
                                format!(
                                    "Tool '{}' accepts URL/URI parameters",
                                    tool.name
                                ),
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
        }

        None
    }

    /// MCP-AUTH-001 to MCP-AUTH-003: Authentication checks
    fn run_auth_checks(&self, ctx: &ServerContext, results: &mut ScanResults) {
        // MCP-AUTH-001: Missing authentication
        if self.should_run("MCP-AUTH-001", "auth") {
            results.total_checks += 1;
            if let Some(finding) = self.check_missing_auth(ctx) {
                results.add_finding(finding);
            }
        }

        // MCP-AUTH-002: Weak token validation
        if self.should_run("MCP-AUTH-002", "auth") {
            results.total_checks += 1;
            // This requires runtime testing, mark as info for now
        }

        // MCP-AUTH-003: Credential exposure
        if self.should_run("MCP-AUTH-003", "auth") {
            results.total_checks += 1;
            if let Some(finding) = self.check_credential_exposure(ctx) {
                results.add_finding(finding);
            }
        }
    }

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

    /// MCP-TRANS-001 to MCP-TRANS-002: Transport security checks
    fn run_transport_checks(&self, ctx: &ServerContext, results: &mut ScanResults) {
        // MCP-TRANS-001: Unencrypted HTTP
        if self.should_run("MCP-TRANS-001", "transport") {
            results.total_checks += 1;
            if let Some(finding) = self.check_unencrypted_transport(ctx) {
                results.add_finding(finding);
            }
        }

        // MCP-TRANS-002: TLS validation
        if self.should_run("MCP-TRANS-002", "transport") {
            results.total_checks += 1;
            // Requires runtime TLS inspection
        }
    }

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

    /// MCP-PROTO-001 to MCP-PROTO-003: Protocol security checks
    fn run_protocol_checks(&self, ctx: &ServerContext, results: &mut ScanResults) {
        // MCP-PROTO-001: Tool poisoning
        if self.should_run("MCP-PROTO-001", "protocol") {
            results.total_checks += 1;
            for finding in self.check_tool_poisoning(ctx) {
                results.add_finding(finding);
            }
        }

        // MCP-PROTO-002: Invalid JSON-RPC
        if self.should_run("MCP-PROTO-002", "protocol") {
            results.total_checks += 1;
            // Covered by M1 validator
        }

        // MCP-PROTO-003: Error handling
        if self.should_run("MCP-PROTO-003", "protocol") {
            results.total_checks += 1;
            // Covered by M1 validator
        }
    }

    fn check_tool_poisoning(&self, ctx: &ServerContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Patterns that might indicate instruction injection in tool descriptions
        let suspicious_patterns = [
            r"ignore\s+(previous|all|prior)",
            r"disregard\s+(previous|all|prior)",
            r"forget\s+(previous|all|prior)",
            r"instead\s*,?\s*(do|perform|execute)",
            r"actually\s*,?\s*(do|perform|execute)",
            r"system\s*prompt",
            r"you\s+are\s+now",
            r"new\s+instructions?",
            r"override",
        ];

        for tool in &ctx.tools {
            if let Some(ref desc) = tool.description {
                let desc_lower = desc.to_lowercase();

                for pattern in &suspicious_patterns {
                    if let Ok(re) = Regex::new(pattern) {
                        if re.is_match(&desc_lower) {
                            findings.push(
                                Finding::new(
                                    "MCP-PROTO-001",
                                    Severity::High,
                                    "Potential Tool Poisoning",
                                    format!(
                                        "Tool '{}' description contains suspicious patterns that may \
                                         attempt to manipulate AI behavior through prompt injection.",
                                        tool.name
                                    ),
                                )
                                .with_location(
                                    FindingLocation::tool(&tool.name)
                                        .with_context("description field"),
                                )
                                .with_evidence(Evidence::observation(
                                    format!("Matched pattern: {}", pattern),
                                    "Suspicious instruction-like content in tool description",
                                ))
                                .with_remediation(
                                    "Review tool descriptions for injection attempts. \
                                     Sanitize descriptions before displaying to users. \
                                     Consider implementing content security policies for tool metadata.",
                                )
                                .with_reference(Reference::mcp_advisory(
                                    "MCP-Security-Advisory-2025-01",
                                )),
                            );
                            break; // One finding per tool is enough
                        }
                    }
                }
            }
        }

        findings
    }

    /// MCP-DATA-001 to MCP-DATA-002: Data exposure checks
    fn run_data_checks(&self, ctx: &ServerContext, results: &mut ScanResults) {
        // MCP-DATA-001: Sensitive data exposure
        if self.should_run("MCP-DATA-001", "data") {
            results.total_checks += 1;
            if let Some(finding) = self.check_sensitive_data_exposure(ctx) {
                results.add_finding(finding);
            }
        }

        // MCP-DATA-002: Excessive data exposure
        if self.should_run("MCP-DATA-002", "data") {
            results.total_checks += 1;
            // Requires runtime analysis of actual responses
        }
    }

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

    /// MCP-DOS-001 to MCP-DOS-002: DoS vulnerability checks
    fn run_dos_checks(&self, ctx: &ServerContext, results: &mut ScanResults) {
        // MCP-DOS-001: Resource consumption
        if self.should_run("MCP-DOS-001", "dos") {
            results.total_checks += 1;
            if let Some(finding) = self.check_resource_consumption(ctx) {
                results.add_finding(finding);
            }
        }

        // MCP-DOS-002: Rate limiting
        if self.should_run("MCP-DOS-002", "dos") {
            results.total_checks += 1;
            // Requires runtime testing
        }
    }

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

    /// Check if a rule should be run based on config and profile
    fn should_run(&self, rule_id: &str, category: &str) -> bool {
        // Check profile first
        if !self.config.profile.includes_rule(rule_id) {
            return false;
        }

        // Then check config filters
        self.config.should_run_rule(rule_id, category)
    }
}

// Helper functions for schema analysis

fn has_string_parameters(schema: &serde_json::Value) -> bool {
    if let Some(props) = schema.get("properties").and_then(|p| p.as_object()) {
        for prop in props.values() {
            if let Some(t) = prop.get("type").and_then(|t| t.as_str()) {
                if t == "string" {
                    return true;
                }
            }
        }
    }
    false
}

fn has_path_parameters(schema: &serde_json::Value) -> bool {
    let path_names = ["path", "file", "filename", "filepath", "directory", "dir"];

    if let Some(props) = schema.get("properties").and_then(|p| p.as_object()) {
        for name in props.keys() {
            let name_lower = name.to_lowercase();
            for pattern in &path_names {
                if name_lower.contains(pattern) {
                    return true;
                }
            }
        }
    }
    false
}

fn has_url_parameters(schema: &serde_json::Value) -> bool {
    let url_names = ["url", "uri", "href", "link", "endpoint"];

    if let Some(props) = schema.get("properties").and_then(|p| p.as_object()) {
        for name in props.keys() {
            let name_lower = name.to_lowercase();
            for pattern in &url_names {
                if name_lower.contains(pattern) {
                    return true;
                }
            }
        }
    }
    false
}

fn has_limit_parameters(schema: &serde_json::Value) -> bool {
    let limit_names = ["limit", "max", "size", "count", "page_size", "per_page"];

    if let Some(props) = schema.get("properties").and_then(|p| p.as_object()) {
        for name in props.keys() {
            let name_lower = name.to_lowercase();
            for pattern in &limit_names {
                if name_lower.contains(pattern) {
                    return true;
                }
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_results_counting() {
        let mut results = ScanResults::new("test", ScanProfile::Standard);

        results.add_finding(Finding::new("TEST-001", Severity::Critical, "Test", "Test"));
        results.add_finding(Finding::new("TEST-002", Severity::High, "Test", "Test"));
        results.add_finding(Finding::new("TEST-003", Severity::Medium, "Test", "Test"));

        assert_eq!(results.summary.critical, 1);
        assert_eq!(results.summary.high, 1);
        assert_eq!(results.summary.medium, 1);
        assert!(results.has_critical_or_high());
        assert_eq!(results.total_findings(), 3);
    }

    #[test]
    fn schema_analysis() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "query": { "type": "string" },
                "count": { "type": "integer" }
            }
        });

        assert!(has_string_parameters(&schema));
        assert!(!has_path_parameters(&schema));

        let path_schema = serde_json::json!({
            "type": "object",
            "properties": {
                "file_path": { "type": "string" }
            }
        });

        assert!(has_path_parameters(&path_schema));
    }
}
