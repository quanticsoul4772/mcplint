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

    pub fn get_rule(&self, id: &str) -> Option<&Rule> {
        self.rules.iter().find(|r| r.id == id)
    }

    pub fn categories(&self) -> Vec<&str> {
        vec!["injection", "auth", "transport", "protocol", "data", "dos"]
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
}
