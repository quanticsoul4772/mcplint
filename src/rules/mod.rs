//! Security Rules Registry

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
                description: "Detects potential command injection vulnerabilities in tool argument handling".to_string(),
                category: "injection".to_string(),
                severity: "critical".to_string(),
                references: vec!["CWE-78".to_string(), "CVE-2025-6514".to_string()],
            },
            Rule {
                id: "MCP-INJ-002".to_string(),
                name: "SQL Injection in Database Tools".to_string(),
                description: "Detects SQL injection risks in database-related MCP tools".to_string(),
                category: "injection".to_string(),
                severity: "critical".to_string(),
                references: vec!["CWE-89".to_string()],
            },
            Rule {
                id: "MCP-INJ-003".to_string(),
                name: "Path Traversal in File Operations".to_string(),
                description: "Detects path traversal vulnerabilities in file system tools".to_string(),
                category: "injection".to_string(),
                severity: "high".to_string(),
                references: vec!["CWE-22".to_string(), "CVE-2025-53109".to_string()],
            },
            Rule {
                id: "MCP-INJ-004".to_string(),
                name: "SSRF via URL Parameters".to_string(),
                description: "Detects server-side request forgery risks in URL handling".to_string(),
                category: "injection".to_string(),
                severity: "high".to_string(),
                references: vec!["CWE-918".to_string()],
            },
            
            // Authentication rules
            Rule {
                id: "MCP-AUTH-001".to_string(),
                name: "Missing Authentication".to_string(),
                description: "Server accepts connections without authentication".to_string(),
                category: "auth".to_string(),
                severity: "high".to_string(),
                references: vec!["CWE-306".to_string()],
            },
            Rule {
                id: "MCP-AUTH-002".to_string(),
                name: "Weak Token Validation".to_string(),
                description: "OAuth tokens not properly validated".to_string(),
                category: "auth".to_string(),
                severity: "high".to_string(),
                references: vec!["CWE-287".to_string()],
            },
            Rule {
                id: "MCP-AUTH-003".to_string(),
                name: "Credential Exposure in Logs".to_string(),
                description: "Credentials or tokens may be logged".to_string(),
                category: "auth".to_string(),
                severity: "medium".to_string(),
                references: vec!["CWE-532".to_string()],
            },
            
            // Transport rules
            Rule {
                id: "MCP-TRANS-001".to_string(),
                name: "Unencrypted HTTP Transport".to_string(),
                description: "Server uses HTTP instead of HTTPS for SSE transport".to_string(),
                category: "transport".to_string(),
                severity: "high".to_string(),
                references: vec!["CWE-319".to_string()],
            },
            Rule {
                id: "MCP-TRANS-002".to_string(),
                name: "Missing TLS Certificate Validation".to_string(),
                description: "TLS certificates not properly validated".to_string(),
                category: "transport".to_string(),
                severity: "medium".to_string(),
                references: vec!["CWE-295".to_string()],
            },
            
            // Protocol rules
            Rule {
                id: "MCP-PROTO-001".to_string(),
                name: "Tool Poisoning Vulnerability".to_string(),
                description: "Tool descriptions may contain malicious instructions".to_string(),
                category: "protocol".to_string(),
                severity: "high".to_string(),
                references: vec!["MCP-Security-Advisory-2025-01".to_string()],
            },
            Rule {
                id: "MCP-PROTO-002".to_string(),
                name: "Invalid JSON-RPC Response".to_string(),
                description: "Server returns malformed JSON-RPC responses".to_string(),
                category: "protocol".to_string(),
                severity: "medium".to_string(),
                references: vec!["JSON-RPC-2.0-Spec".to_string()],
            },
            Rule {
                id: "MCP-PROTO-003".to_string(),
                name: "Missing Error Handling".to_string(),
                description: "Server does not properly handle error conditions".to_string(),
                category: "protocol".to_string(),
                severity: "low".to_string(),
                references: vec![],
            },
            
            // Data exposure rules
            Rule {
                id: "MCP-DATA-001".to_string(),
                name: "Sensitive Data in Tool Output".to_string(),
                description: "Tool responses may contain sensitive information".to_string(),
                category: "data".to_string(),
                severity: "medium".to_string(),
                references: vec!["CWE-200".to_string()],
            },
            Rule {
                id: "MCP-DATA-002".to_string(),
                name: "Excessive Data Exposure".to_string(),
                description: "Tools return more data than necessary".to_string(),
                category: "data".to_string(),
                severity: "low".to_string(),
                references: vec!["CWE-213".to_string()],
            },
            
            // DoS rules
            Rule {
                id: "MCP-DOS-001".to_string(),
                name: "Unbounded Resource Consumption".to_string(),
                description: "No limits on resource consumption in tool execution".to_string(),
                category: "dos".to_string(),
                severity: "medium".to_string(),
                references: vec!["CWE-400".to_string()],
            },
            Rule {
                id: "MCP-DOS-002".to_string(),
                name: "Missing Rate Limiting".to_string(),
                description: "Server does not implement rate limiting".to_string(),
                category: "dos".to_string(),
                severity: "low".to_string(),
                references: vec!["CWE-770".to_string()],
            },
        ];
        
        Self { rules }
    }
    
    pub fn list_rules(&self, category: Option<&str>) -> Vec<&Rule> {
        match category {
            Some(cat) => self.rules.iter().filter(|r| r.category == cat).collect(),
            None => self.rules.iter().collect(),
        }
    }
    
    pub fn get_rule(&self, id: &str) -> Option<&Rule> {
        self.rules.iter().find(|r| r.id == id)
    }
}
