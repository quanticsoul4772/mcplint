//! Scan Context - Server information collected for security checks
//!
//! Provides the context needed by security rules to perform their checks.

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

    pub fn with_include_categories(mut self, categories: Vec<String>) -> Self {
        self.include_categories = categories;
        self
    }

    pub fn with_exclude_categories(mut self, categories: Vec<String>) -> Self {
        self.exclude_categories = categories;
        self
    }

    /// Check if a rule should be executed based on configuration
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
            ],
        }
    }

    /// Check if a rule is included in this profile
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
}
