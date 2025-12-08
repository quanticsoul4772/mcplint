//! Security Rules Registry
//!
//! Defines the security rules that the scanner uses to detect vulnerabilities.

use serde::{Deserialize, Serialize};

/// A security rule definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub category: String,
    pub severity: String,
    pub references: Vec<String>,
}

/// Registry of security rules
pub struct RuleRegistry {
    rules: Vec<Rule>,
}

impl Default for RuleRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl RuleRegistry {
    pub fn new() -> Self {
        let rules = vec![
            // Injection rules
            Rule {
                id: "MCP-INJ-001".to_string(),
                name: "Command Injection via Tool Arguments".to_string(),
                description:
                    "Detects potential command injection vulnerabilities in tool argument handling. \
                     Tools that execute shell commands with user-provided input may allow attackers \
                     to execute arbitrary commands on the server."
                        .to_string(),
                category: "injection".to_string(),
                severity: "critical".to_string(),
                references: vec!["CWE-78".to_string()],
            },
            Rule {
                id: "MCP-INJ-002".to_string(),
                name: "SQL Injection in Database Tools".to_string(),
                description: "Detects SQL injection risks in database-related MCP tools. \
                     User input concatenated into SQL queries can allow data theft or modification."
                    .to_string(),
                category: "injection".to_string(),
                severity: "critical".to_string(),
                references: vec!["CWE-89".to_string()],
            },
            Rule {
                id: "MCP-INJ-003".to_string(),
                name: "Path Traversal in File Operations".to_string(),
                description: "Detects path traversal vulnerabilities in file system tools. \
                     Attackers may use ../ sequences to access files outside intended directories."
                    .to_string(),
                category: "injection".to_string(),
                severity: "high".to_string(),
                references: vec!["CWE-22".to_string()],
            },
            Rule {
                id: "MCP-INJ-004".to_string(),
                name: "SSRF via URL Parameters".to_string(),
                description: "Detects server-side request forgery risks in URL handling. \
                     Attackers may access internal services or cloud metadata endpoints."
                    .to_string(),
                category: "injection".to_string(),
                severity: "high".to_string(),
                references: vec!["CWE-918".to_string()],
            },
            // Authentication rules
            Rule {
                id: "MCP-AUTH-001".to_string(),
                name: "Missing Authentication".to_string(),
                description: "Server accepts connections without authentication. \
                     Remote MCP servers should require authentication to prevent unauthorized access."
                    .to_string(),
                category: "auth".to_string(),
                severity: "high".to_string(),
                references: vec!["CWE-306".to_string()],
            },
            Rule {
                id: "MCP-AUTH-002".to_string(),
                name: "Weak Token Validation".to_string(),
                description: "OAuth tokens or API keys not properly validated. \
                     Weak validation may allow token forgery or replay attacks."
                    .to_string(),
                category: "auth".to_string(),
                severity: "high".to_string(),
                references: vec!["CWE-287".to_string()],
            },
            Rule {
                id: "MCP-AUTH-003".to_string(),
                name: "Credential Exposure in Logs".to_string(),
                description: "Credentials or tokens may be logged or exposed in output. \
                     Sensitive data in logs can be accessed by unauthorized parties."
                    .to_string(),
                category: "auth".to_string(),
                severity: "medium".to_string(),
                references: vec!["CWE-532".to_string()],
            },
            // Transport rules
            Rule {
                id: "MCP-TRANS-001".to_string(),
                name: "Unencrypted HTTP Transport".to_string(),
                description: "Server uses HTTP instead of HTTPS for SSE transport. \
                     All communications can be intercepted and modified by attackers."
                    .to_string(),
                category: "transport".to_string(),
                severity: "high".to_string(),
                references: vec!["CWE-319".to_string()],
            },
            Rule {
                id: "MCP-TRANS-002".to_string(),
                name: "Missing TLS Certificate Validation".to_string(),
                description: "TLS certificates not properly validated. \
                     Man-in-the-middle attacks possible with invalid certificates."
                    .to_string(),
                category: "transport".to_string(),
                severity: "medium".to_string(),
                references: vec!["CWE-295".to_string()],
            },
            // Protocol rules
            Rule {
                id: "MCP-PROTO-001".to_string(),
                name: "Tool Poisoning Vulnerability".to_string(),
                description: "Tool descriptions may contain malicious instructions. \
                     Prompt injection in tool metadata can manipulate AI behavior."
                    .to_string(),
                category: "protocol".to_string(),
                severity: "high".to_string(),
                references: vec!["MCP-Security-Advisory-2025-01".to_string()],
            },
            Rule {
                id: "MCP-PROTO-002".to_string(),
                name: "Invalid JSON-RPC Response".to_string(),
                description: "Server returns malformed JSON-RPC responses. \
                     Protocol violations may cause client crashes or undefined behavior."
                    .to_string(),
                category: "protocol".to_string(),
                severity: "medium".to_string(),
                references: vec!["JSON-RPC-2.0-Spec".to_string()],
            },
            Rule {
                id: "MCP-PROTO-003".to_string(),
                name: "Missing Error Handling".to_string(),
                description: "Server does not properly handle error conditions. \
                     Poor error handling may expose sensitive information or cause instability."
                    .to_string(),
                category: "protocol".to_string(),
                severity: "low".to_string(),
                references: vec!["CWE-755".to_string()],
            },
            // Data exposure rules
            Rule {
                id: "MCP-DATA-001".to_string(),
                name: "Sensitive Data in Tool Output".to_string(),
                description: "Tool responses may contain sensitive information. \
                     PII, credentials, or internal data may be exposed through tool outputs."
                    .to_string(),
                category: "data".to_string(),
                severity: "medium".to_string(),
                references: vec!["CWE-200".to_string()],
            },
            Rule {
                id: "MCP-DATA-002".to_string(),
                name: "Excessive Data Exposure".to_string(),
                description: "Tools return more data than necessary. \
                     Over-fetching data increases attack surface and privacy risks."
                    .to_string(),
                category: "data".to_string(),
                severity: "low".to_string(),
                references: vec!["CWE-213".to_string()],
            },
            // DoS rules
            Rule {
                id: "MCP-DOS-001".to_string(),
                name: "Unbounded Resource Consumption".to_string(),
                description: "No limits on resource consumption in tool execution. \
                     Attackers may cause denial of service by exhausting server resources."
                    .to_string(),
                category: "dos".to_string(),
                severity: "medium".to_string(),
                references: vec!["CWE-400".to_string()],
            },
            Rule {
                id: "MCP-DOS-002".to_string(),
                name: "Missing Rate Limiting".to_string(),
                description: "Server does not implement rate limiting. \
                     Excessive requests may overwhelm the server or enable brute-force attacks."
                    .to_string(),
                category: "dos".to_string(),
                severity: "low".to_string(),
                references: vec!["CWE-770".to_string()],
            },
            // Advanced security rules (M6)
            Rule {
                id: "MCP-SEC-040".to_string(),
                name: "Tool Description Injection".to_string(),
                description: "Tool descriptions contain suspicious patterns that could manipulate AI behavior. \
                     Hidden instructions like 'ignore previous instructions' or encoded directives in tool \
                     descriptions may trick AI assistants into performing unintended actions."
                    .to_string(),
                category: "injection".to_string(),
                severity: "critical".to_string(),
                references: vec![
                    "CWE-94".to_string(),
                    "OWASP-LLM-PI".to_string(),
                    "MCP-Security-Advisory-2025-02".to_string(),
                ],
            },
            Rule {
                id: "MCP-SEC-041".to_string(),
                name: "Cross-Server Tool Shadowing".to_string(),
                description: "Server registers tools with names that shadow commonly-used tools from other servers. \
                     Tool shadowing can intercept calls intended for legitimate tools, enabling data theft or \
                     manipulation of AI assistant behavior."
                    .to_string(),
                category: "protocol".to_string(),
                severity: "high".to_string(),
                references: vec![
                    "CWE-706".to_string(),
                    "MCP-Security-Advisory-2025-03".to_string(),
                ],
            },
            Rule {
                id: "MCP-SEC-042".to_string(),
                name: "Rug Pull Detection".to_string(),
                description: "Server tool definitions have changed significantly since baseline scan. \
                     Changes to tool names, descriptions, or schemas after initial trust establishment \
                     may indicate a supply-chain attack where a previously trusted server becomes malicious."
                    .to_string(),
                category: "protocol".to_string(),
                severity: "critical".to_string(),
                references: vec![
                    "CWE-494".to_string(),
                    "MCP-Security-Advisory-2025-04".to_string(),
                ],
            },
            Rule {
                id: "MCP-SEC-043".to_string(),
                name: "OAuth Scope Abuse".to_string(),
                description: "Server requests OAuth scopes that exceed its stated functionality. \
                     Excessive permission requests may indicate malicious intent or poor security hygiene. \
                     Tools should request minimum necessary scopes."
                    .to_string(),
                category: "auth".to_string(),
                severity: "high".to_string(),
                references: vec![
                    "CWE-250".to_string(),
                    "CWE-269".to_string(),
                    "OAuth-Best-Practice".to_string(),
                ],
            },
            Rule {
                id: "MCP-SEC-044".to_string(),
                name: "Unicode Hidden Instructions".to_string(),
                description: "Tool descriptions or responses contain hidden Unicode characters. \
                     Zero-width characters, RTL overrides, or homoglyphs may hide malicious instructions \
                     that are invisible to users but processed by AI assistants."
                    .to_string(),
                category: "injection".to_string(),
                severity: "high".to_string(),
                references: vec![
                    "CWE-116".to_string(),
                    "Unicode-Security-TR36".to_string(),
                ],
            },
            Rule {
                id: "MCP-SEC-045".to_string(),
                name: "Full-Schema Poisoning".to_string(),
                description: "Tool input schema contains suspicious default values or enum constraints. \
                     Malicious schemas may include default values that execute commands, or restrict \
                     valid inputs to dangerous values disguised as safe options."
                    .to_string(),
                category: "injection".to_string(),
                severity: "high".to_string(),
                references: vec![
                    "CWE-1321".to_string(),
                    "JSON-Schema-Security".to_string(),
                ],
            },
        ];

        Self { rules }
    }

    pub fn list_rules(&self, category: Option<&str>) -> Vec<&Rule> {
        match category {
            Some(cat) => self
                .rules
                .iter()
                .filter(|r| r.category.eq_ignore_ascii_case(cat))
                .collect(),
            None => self.rules.iter().collect(),
        }
    }

    #[allow(dead_code)]
    pub fn get_rule(&self, id: &str) -> Option<&Rule> {
        self.rules.iter().find(|r| r.id == id)
    }

    #[allow(dead_code)]
    pub fn categories(&self) -> Vec<&str> {
        vec!["injection", "auth", "transport", "protocol", "data", "dos", "security"]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_has_rules() {
        let registry = RuleRegistry::new();
        assert!(!registry.list_rules(None).is_empty());
    }

    #[test]
    fn filter_by_category() {
        let registry = RuleRegistry::new();
        let injection = registry.list_rules(Some("injection"));
        assert!(injection.iter().all(|r| r.category == "injection"));
        assert!(!injection.is_empty());
    }

    #[test]
    fn get_rule_by_id() {
        let registry = RuleRegistry::new();
        let rule = registry.get_rule("MCP-INJ-001");
        assert!(rule.is_some());
        assert_eq!(rule.unwrap().name, "Command Injection via Tool Arguments");
    }

    #[test]
    fn m6_security_rules_exist() {
        let registry = RuleRegistry::new();

        // SEC-040: Tool Description Injection
        let rule = registry.get_rule("MCP-SEC-040");
        assert!(rule.is_some());
        assert_eq!(rule.unwrap().severity, "critical");

        // SEC-041: Cross-Server Tool Shadowing
        let rule = registry.get_rule("MCP-SEC-041");
        assert!(rule.is_some());
        assert_eq!(rule.unwrap().category, "protocol");

        // SEC-042: Rug Pull Detection
        let rule = registry.get_rule("MCP-SEC-042");
        assert!(rule.is_some());
        assert_eq!(rule.unwrap().severity, "critical");

        // SEC-043: OAuth Scope Abuse
        let rule = registry.get_rule("MCP-SEC-043");
        assert!(rule.is_some());
        assert_eq!(rule.unwrap().category, "auth");

        // SEC-044: Unicode Hidden Instructions
        let rule = registry.get_rule("MCP-SEC-044");
        assert!(rule.is_some());

        // SEC-045: Full-Schema Poisoning
        let rule = registry.get_rule("MCP-SEC-045");
        assert!(rule.is_some());
    }
}
