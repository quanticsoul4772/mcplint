//! Scan Context - Server information collected for security checks
//!
//! Provides the context needed by security rules to perform their checks.
//!
//! Many helper methods are marked as public API for external consumers
//! and plugin authors, even if not used internally.

use crate::protocol::mcp::{Prompt, Resource, ServerCapabilities, Tool};

/// Server context collected during scanning
#[derive(Debug, Clone)]
pub struct ServerContext {
    /// Server name
    #[allow(dead_code)]
    pub server_name: String,
    /// Server version
    #[allow(dead_code)]
    pub server_version: String,
    /// Negotiated protocol version
    #[allow(dead_code)]
    pub protocol_version: String,
    /// Server capabilities
    #[allow(dead_code)]
    pub capabilities: ServerCapabilities,
    /// Transport type used
    pub transport_type: String,
    /// Target (path or URL)
    pub target: String,
    /// Available tools
    pub tools: Vec<Tool>,
    /// Available resources
    pub resources: Vec<Resource>,
    /// Available prompts
    pub prompts: Vec<Prompt>,
}

impl ServerContext {
    pub fn new(
        server_name: impl Into<String>,
        server_version: impl Into<String>,
        protocol_version: impl Into<String>,
        capabilities: ServerCapabilities,
    ) -> Self {
        Self {
            server_name: server_name.into(),
            server_version: server_version.into(),
            protocol_version: protocol_version.into(),
            capabilities,
            transport_type: String::new(),
            target: String::new(),
            tools: Vec::new(),
            resources: Vec::new(),
            prompts: Vec::new(),
        }
    }

    /// Create a minimal context for testing with just a target
    #[cfg(test)]
    pub fn for_test(target: impl Into<String>) -> Self {
        Self {
            server_name: "test-server".to_string(),
            server_version: "1.0.0".to_string(),
            protocol_version: "2024-11-05".to_string(),
            capabilities: ServerCapabilities::default(),
            transport_type: "stdio".to_string(),
            target: target.into(),
            tools: Vec::new(),
            resources: Vec::new(),
            prompts: Vec::new(),
        }
    }

    /// Set transport type (for testing)
    #[cfg(test)]
    pub fn set_transport_type(&mut self, transport: impl Into<String>) {
        self.transport_type = transport.into();
    }

    pub fn with_transport(mut self, transport_type: impl Into<String>) -> Self {
        self.transport_type = transport_type.into();
        self
    }

    pub fn with_target(mut self, target: impl Into<String>) -> Self {
        self.target = target.into();
        self
    }

    pub fn with_tools(mut self, tools: Vec<Tool>) -> Self {
        self.tools = tools;
        self
    }

    pub fn with_resources(mut self, resources: Vec<Resource>) -> Self {
        self.resources = resources;
        self
    }

    pub fn with_prompts(mut self, prompts: Vec<Prompt>) -> Self {
        self.prompts = prompts;
        self
    }

    /// Check if the server uses HTTP transport
    pub fn uses_http(&self) -> bool {
        self.transport_type == "sse" || self.transport_type == "streamable_http"
    }

    /// Check if the target appears to use HTTPS
    #[allow(dead_code)]
    pub fn uses_https(&self) -> bool {
        self.target.starts_with("https://")
    }

    /// Check if the server has any tools
    #[allow(dead_code)]
    pub fn has_tools(&self) -> bool {
        !self.tools.is_empty()
    }

    /// Check if the server has any resources
    #[allow(dead_code)]
    pub fn has_resources(&self) -> bool {
        !self.resources.is_empty()
    }

    /// Check if the server has any prompts
    #[allow(dead_code)]
    pub fn has_prompts(&self) -> bool {
        !self.prompts.is_empty()
    }
}

/// Configuration for security scans
#[derive(Debug, Clone)]
pub struct ScanConfig {
    /// Scan profile to use
    pub profile: ScanProfile,
    /// Timeout for operations in seconds
    pub timeout_secs: u64,
    /// Categories to include (empty = all)
    pub include_categories: Vec<String>,
    /// Categories to exclude
    pub exclude_categories: Vec<String>,
    /// Specific rules to include
    pub include_rules: Vec<String>,
    /// Specific rules to exclude
    pub exclude_rules: Vec<String>,
    /// Run checks in parallel where possible
    #[allow(dead_code)]
    pub parallel_checks: bool,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            profile: ScanProfile::Standard,
            timeout_secs: 60,
            include_categories: Vec::new(),
            exclude_categories: Vec::new(),
            include_rules: Vec::new(),
            exclude_rules: Vec::new(),
            parallel_checks: true,
        }
    }
}

impl ScanConfig {
    pub fn with_profile(mut self, profile: ScanProfile) -> Self {
        self.profile = profile;
        self
    }

    pub fn with_timeout(mut self, timeout_secs: u64) -> Self {
        self.timeout_secs = timeout_secs;
        self
    }

    #[allow(dead_code)]
    pub fn with_include_categories(mut self, categories: Vec<String>) -> Self {
        self.include_categories = categories;
        self
    }

    #[allow(dead_code)]
    pub fn with_exclude_categories(mut self, categories: Vec<String>) -> Self {
        self.exclude_categories = categories;
        self
    }

    #[allow(dead_code)]
    pub fn with_include_rules(mut self, rules: Vec<String>) -> Self {
        self.include_rules = rules;
        self
    }

    #[allow(dead_code)]
    pub fn with_exclude_rules(mut self, rules: Vec<String>) -> Self {
        self.exclude_rules = rules;
        self
    }

    /// Check if a rule should be executed based on configuration
    #[allow(dead_code)] // Public API method for library consumers
    pub fn should_run_rule(&self, rule_id: &str, category: &str) -> bool {
        // Check explicit exclusions first
        if self.exclude_rules.iter().any(|r| r == rule_id) {
            return false;
        }

        if self
            .exclude_categories
            .iter()
            .any(|c| c.eq_ignore_ascii_case(category))
        {
            return false;
        }

        // Check explicit inclusions
        if !self.include_rules.is_empty() {
            return self.include_rules.iter().any(|r| r == rule_id);
        }

        if !self.include_categories.is_empty() {
            return self
                .include_categories
                .iter()
                .any(|c| c.eq_ignore_ascii_case(category));
        }

        // Default: run the rule
        true
    }
}

/// Scan profile determining which rules to run
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ScanProfile {
    /// Quick scan with essential rules only (~5 rules)
    Quick,
    /// Standard security scan (~10 rules)
    #[default]
    Standard,
    /// Full scan with all rules
    Full,
    /// Enterprise compliance-focused scan
    Enterprise,
}

impl ScanProfile {
    /// Get the rule IDs included in this profile
    #[allow(dead_code)] // Public API method for library consumers
    pub fn included_rules(&self) -> Vec<&'static str> {
        match self {
            ScanProfile::Quick => vec![
                "MCP-INJ-001",   // Command injection
                "MCP-INJ-003",   // Path traversal
                "MCP-AUTH-001",  // Missing auth
                "MCP-TRANS-001", // Unencrypted HTTP
                "MCP-PROTO-001", // Tool poisoning
            ],
            ScanProfile::Standard => vec![
                "MCP-INJ-001",
                "MCP-INJ-002",
                "MCP-INJ-003",
                "MCP-INJ-004",
                "MCP-AUTH-001",
                "MCP-AUTH-002",
                "MCP-AUTH-003",
                "MCP-TRANS-001",
                "MCP-PROTO-001",
                "MCP-DATA-001",
                // M6 Advanced rules
                "MCP-SEC-040", // Tool Description Injection
                "MCP-SEC-044", // Unicode Hidden Instructions
            ],
            ScanProfile::Full | ScanProfile::Enterprise => vec![
                "MCP-INJ-001",
                "MCP-INJ-002",
                "MCP-INJ-003",
                "MCP-INJ-004",
                "MCP-AUTH-001",
                "MCP-AUTH-002",
                "MCP-AUTH-003",
                "MCP-TRANS-001",
                "MCP-TRANS-002",
                "MCP-PROTO-001",
                "MCP-PROTO-002",
                "MCP-PROTO-003",
                "MCP-DATA-001",
                "MCP-DATA-002",
                "MCP-DOS-001",
                "MCP-DOS-002",
                // M6 Advanced rules
                "MCP-SEC-040", // Tool Description Injection
                "MCP-SEC-041", // Cross-Server Tool Shadowing
                "MCP-SEC-042", // Rug Pull Detection
                "MCP-SEC-043", // OAuth Scope Abuse
                "MCP-SEC-044", // Unicode Hidden Instructions
                "MCP-SEC-045", // Schema Poisoning
            ],
        }
    }

    /// Check if a rule is included in this profile
    #[allow(dead_code)] // Public API method for library consumers
    pub fn includes_rule(&self, rule_id: &str) -> bool {
        self.included_rules().contains(&rule_id)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            ScanProfile::Quick => "quick",
            ScanProfile::Standard => "standard",
            ScanProfile::Full => "full",
            ScanProfile::Enterprise => "enterprise",
        }
    }
}

impl std::fmt::Display for ScanProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // Helper to create a test tool
    fn test_tool(name: &str, desc: &str) -> Tool {
        Tool {
            name: name.to_string(),
            description: Some(desc.to_string()),
            input_schema: json!({"type": "object"}),
        }
    }

    // Helper to create a test resource
    fn test_resource(uri: &str, name: &str) -> Resource {
        Resource {
            uri: uri.to_string(),
            name: name.to_string(),
            description: None,
            mime_type: Some("text/plain".to_string()),
        }
    }

    // Helper to create a test prompt
    fn test_prompt(name: &str, desc: &str) -> Prompt {
        Prompt {
            name: name.to_string(),
            description: Some(desc.to_string()),
            arguments: None,
        }
    }

    #[test]
    fn profile_rules() {
        let quick = ScanProfile::Quick;
        assert!(quick.includes_rule("MCP-INJ-001"));
        assert!(!quick.includes_rule("MCP-DOS-001"));

        let full = ScanProfile::Full;
        assert!(full.includes_rule("MCP-DOS-001"));
    }

    #[test]
    fn config_filtering() {
        let config = ScanConfig::default().with_exclude_rules(vec!["MCP-INJ-001".to_string()]);

        assert!(!config.should_run_rule("MCP-INJ-001", "injection"));
        assert!(config.should_run_rule("MCP-INJ-002", "injection"));
    }

    #[test]
    fn category_filtering() {
        let config = ScanConfig::default().with_include_categories(vec!["injection".to_string()]);

        assert!(config.should_run_rule("MCP-INJ-001", "injection"));
        assert!(!config.should_run_rule("MCP-AUTH-001", "auth"));
    }

    // ServerContext tests
    #[test]
    fn server_context_new() {
        let ctx = ServerContext::new(
            "test-server",
            "1.0.0",
            "2024-11-05",
            ServerCapabilities::default(),
        );

        assert_eq!(ctx.server_name, "test-server");
        assert_eq!(ctx.server_version, "1.0.0");
        assert_eq!(ctx.protocol_version, "2024-11-05");
        assert!(ctx.transport_type.is_empty());
        assert!(ctx.target.is_empty());
        assert!(ctx.tools.is_empty());
        assert!(ctx.resources.is_empty());
        assert!(ctx.prompts.is_empty());
    }

    #[test]
    fn server_context_for_test() {
        let ctx = ServerContext::for_test("/path/to/server");

        assert_eq!(ctx.server_name, "test-server");
        assert_eq!(ctx.server_version, "1.0.0");
        assert_eq!(ctx.target, "/path/to/server");
        assert_eq!(ctx.transport_type, "stdio");
    }

    #[test]
    fn server_context_with_transport() {
        let ctx =
            ServerContext::new("s", "v", "p", ServerCapabilities::default()).with_transport("sse");

        assert_eq!(ctx.transport_type, "sse");
    }

    #[test]
    fn server_context_with_target() {
        let ctx = ServerContext::new("s", "v", "p", ServerCapabilities::default())
            .with_target("https://example.com/mcp");

        assert_eq!(ctx.target, "https://example.com/mcp");
    }

    #[test]
    fn server_context_with_tools() {
        let tools = vec![test_tool("tool1", "desc1"), test_tool("tool2", "desc2")];
        let ctx =
            ServerContext::new("s", "v", "p", ServerCapabilities::default()).with_tools(tools);

        assert_eq!(ctx.tools.len(), 2);
        assert!(ctx.has_tools());
    }

    #[test]
    fn server_context_with_resources() {
        let resources = vec![test_resource("file:///a.txt", "a")];
        let ctx = ServerContext::new("s", "v", "p", ServerCapabilities::default())
            .with_resources(resources);

        assert_eq!(ctx.resources.len(), 1);
        assert!(ctx.has_resources());
    }

    #[test]
    fn server_context_with_prompts() {
        let prompts = vec![test_prompt("p1", "desc1"), test_prompt("p2", "desc2")];
        let ctx =
            ServerContext::new("s", "v", "p", ServerCapabilities::default()).with_prompts(prompts);

        assert_eq!(ctx.prompts.len(), 2);
        assert!(ctx.has_prompts());
    }

    #[test]
    fn server_context_uses_http() {
        let ctx_sse = ServerContext::for_test("http://example.com");
        let mut ctx_sse = ctx_sse;
        ctx_sse.set_transport_type("sse");
        assert!(ctx_sse.uses_http());

        let ctx_http = ServerContext::for_test("http://example.com");
        let mut ctx_http = ctx_http;
        ctx_http.set_transport_type("streamable_http");
        assert!(ctx_http.uses_http());

        let ctx_stdio = ServerContext::for_test("/path/to/server");
        assert!(!ctx_stdio.uses_http());
    }

    #[test]
    fn server_context_uses_https() {
        let ctx_https = ServerContext::new("s", "v", "p", ServerCapabilities::default())
            .with_target("https://example.com/mcp");
        assert!(ctx_https.uses_https());

        let ctx_http = ServerContext::new("s", "v", "p", ServerCapabilities::default())
            .with_target("http://example.com/mcp");
        assert!(!ctx_http.uses_https());

        let ctx_local = ServerContext::for_test("/path/to/server");
        assert!(!ctx_local.uses_https());
    }

    #[test]
    fn server_context_has_methods_empty() {
        let ctx = ServerContext::new("s", "v", "p", ServerCapabilities::default());

        assert!(!ctx.has_tools());
        assert!(!ctx.has_resources());
        assert!(!ctx.has_prompts());
    }

    #[test]
    fn server_context_builder_chain() {
        let ctx = ServerContext::new("server", "1.0", "2024-11-05", ServerCapabilities::default())
            .with_transport("sse")
            .with_target("https://example.com")
            .with_tools(vec![test_tool("t", "d")])
            .with_resources(vec![test_resource("file:///f", "f")])
            .with_prompts(vec![test_prompt("p", "d")]);

        assert_eq!(ctx.transport_type, "sse");
        assert_eq!(ctx.target, "https://example.com");
        assert!(ctx.has_tools());
        assert!(ctx.has_resources());
        assert!(ctx.has_prompts());
    }

    // ScanConfig tests
    #[test]
    fn scan_config_default() {
        let config = ScanConfig::default();

        assert_eq!(config.profile, ScanProfile::Standard);
        assert_eq!(config.timeout_secs, 60);
        assert!(config.include_categories.is_empty());
        assert!(config.exclude_categories.is_empty());
        assert!(config.include_rules.is_empty());
        assert!(config.exclude_rules.is_empty());
        assert!(config.parallel_checks);
    }

    #[test]
    fn scan_config_with_profile() {
        let config = ScanConfig::default().with_profile(ScanProfile::Full);
        assert_eq!(config.profile, ScanProfile::Full);
    }

    #[test]
    fn scan_config_with_timeout() {
        let config = ScanConfig::default().with_timeout(120);
        assert_eq!(config.timeout_secs, 120);
    }

    #[test]
    fn scan_config_with_include_categories() {
        let config = ScanConfig::default()
            .with_include_categories(vec!["injection".to_string(), "auth".to_string()]);

        assert_eq!(config.include_categories.len(), 2);
        assert!(config.should_run_rule("MCP-INJ-001", "injection"));
        assert!(config.should_run_rule("MCP-AUTH-001", "auth"));
        assert!(!config.should_run_rule("MCP-DOS-001", "dos"));
    }

    #[test]
    fn scan_config_with_exclude_categories() {
        let config = ScanConfig::default().with_exclude_categories(vec!["dos".to_string()]);

        assert!(!config.should_run_rule("MCP-DOS-001", "dos"));
        assert!(config.should_run_rule("MCP-INJ-001", "injection"));
    }

    #[test]
    fn scan_config_with_include_rules() {
        let config = ScanConfig::default().with_include_rules(vec!["MCP-INJ-001".to_string()]);

        assert!(config.should_run_rule("MCP-INJ-001", "injection"));
        assert!(!config.should_run_rule("MCP-INJ-002", "injection"));
    }

    #[test]
    fn scan_config_with_exclude_rules() {
        let config = ScanConfig::default().with_exclude_rules(vec!["MCP-INJ-001".to_string()]);

        assert!(!config.should_run_rule("MCP-INJ-001", "injection"));
        assert!(config.should_run_rule("MCP-INJ-002", "injection"));
    }

    #[test]
    fn scan_config_exclude_takes_precedence() {
        // Exclude takes precedence over include
        let config = ScanConfig::default()
            .with_include_categories(vec!["injection".to_string()])
            .with_exclude_rules(vec!["MCP-INJ-001".to_string()]);

        assert!(!config.should_run_rule("MCP-INJ-001", "injection"));
        assert!(config.should_run_rule("MCP-INJ-002", "injection"));
    }

    #[test]
    fn scan_config_category_exclude_precedence() {
        let config = ScanConfig::default()
            .with_include_rules(vec!["MCP-INJ-001".to_string()])
            .with_exclude_categories(vec!["injection".to_string()]);

        // Category exclusion takes precedence
        assert!(!config.should_run_rule("MCP-INJ-001", "injection"));
    }

    #[test]
    fn scan_config_case_insensitive_categories() {
        let config = ScanConfig::default().with_include_categories(vec!["INJECTION".to_string()]);

        assert!(config.should_run_rule("MCP-INJ-001", "injection"));
        assert!(config.should_run_rule("MCP-INJ-001", "Injection"));
        assert!(config.should_run_rule("MCP-INJ-001", "INJECTION"));
    }

    #[test]
    fn scan_config_builder_chain() {
        let config = ScanConfig::default()
            .with_profile(ScanProfile::Full)
            .with_timeout(120)
            .with_include_categories(vec!["injection".to_string()])
            .with_exclude_rules(vec!["MCP-INJ-001".to_string()]);

        assert_eq!(config.profile, ScanProfile::Full);
        assert_eq!(config.timeout_secs, 120);
        assert_eq!(config.include_categories.len(), 1);
        assert_eq!(config.exclude_rules.len(), 1);
    }

    // ScanProfile tests
    #[test]
    fn scan_profile_quick_rules() {
        let profile = ScanProfile::Quick;
        let rules = profile.included_rules();

        assert_eq!(rules.len(), 5);
        assert!(rules.contains(&"MCP-INJ-001"));
        assert!(rules.contains(&"MCP-TRANS-001"));
        assert!(!rules.contains(&"MCP-DOS-001"));
    }

    #[test]
    fn scan_profile_standard_rules() {
        let profile = ScanProfile::Standard;
        let rules = profile.included_rules();

        assert!(rules.len() > 5);
        assert!(rules.contains(&"MCP-INJ-001"));
        assert!(rules.contains(&"MCP-SEC-040"));
        assert!(!rules.contains(&"MCP-DOS-001"));
    }

    #[test]
    fn scan_profile_full_rules() {
        let profile = ScanProfile::Full;
        let rules = profile.included_rules();

        assert!(rules.len() > 15);
        assert!(rules.contains(&"MCP-DOS-001"));
        assert!(rules.contains(&"MCP-SEC-045"));
    }

    #[test]
    fn scan_profile_enterprise_same_as_full() {
        let full = ScanProfile::Full;
        let enterprise = ScanProfile::Enterprise;

        assert_eq!(full.included_rules(), enterprise.included_rules());
    }

    #[test]
    fn scan_profile_as_str() {
        assert_eq!(ScanProfile::Quick.as_str(), "quick");
        assert_eq!(ScanProfile::Standard.as_str(), "standard");
        assert_eq!(ScanProfile::Full.as_str(), "full");
        assert_eq!(ScanProfile::Enterprise.as_str(), "enterprise");
    }

    #[test]
    fn scan_profile_display() {
        assert_eq!(format!("{}", ScanProfile::Quick), "quick");
        assert_eq!(format!("{}", ScanProfile::Standard), "standard");
        assert_eq!(format!("{}", ScanProfile::Full), "full");
        assert_eq!(format!("{}", ScanProfile::Enterprise), "enterprise");
    }

    #[test]
    fn scan_profile_default() {
        let profile = ScanProfile::default();
        assert_eq!(profile, ScanProfile::Standard);
    }

    #[test]
    fn scan_profile_includes_rule() {
        let quick = ScanProfile::Quick;
        assert!(quick.includes_rule("MCP-INJ-001"));
        assert!(!quick.includes_rule("NONEXISTENT-RULE"));

        let full = ScanProfile::Full;
        assert!(full.includes_rule("MCP-DOS-001"));
        assert!(full.includes_rule("MCP-SEC-045"));
    }

    #[test]
    fn scan_profile_equality() {
        assert_eq!(ScanProfile::Quick, ScanProfile::Quick);
        assert_ne!(ScanProfile::Quick, ScanProfile::Full);
    }
}
