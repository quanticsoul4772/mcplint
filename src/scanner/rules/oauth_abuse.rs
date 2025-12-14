//! SEC-043: OAuth Scope Abuse Detection
//!
//! Detects when an MCP server requests OAuth scopes that exceed its stated functionality,
//! or when tools request dangerous permissions without justification.

use crate::protocol::mcp::Tool;
use crate::scanner::finding::{Evidence, Finding, FindingLocation, Reference, Severity};
use regex::Regex;
use std::collections::HashSet;

/// Detector for OAuth scope abuse and excessive permission requests
pub struct OAuthAbuseDetector {
    /// Known OAuth scope patterns and their risk levels
    scope_patterns: Vec<ScopePattern>,
    /// Dangerous scope combinations
    dangerous_combinations: Vec<ScopeCombination>,
}

/// A known OAuth scope pattern
struct ScopePattern {
    pattern: Regex,
    provider: &'static str,
    risk_level: RiskLevel,
    description: &'static str,
    required_functionality: Vec<&'static str>,
}

/// Dangerous combination of scopes
struct ScopeCombination {
    scopes: Vec<&'static str>,
    risk_level: RiskLevel,
    description: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RiskLevel {
    /// Low risk - read-only access to non-sensitive data
    Low,
    /// Medium risk - read access to potentially sensitive data
    Medium,
    /// High risk - write access or access to sensitive data
    High,
    /// Critical risk - administrative or destructive capabilities
    Critical,
}

impl OAuthAbuseDetector {
    /// Create a new detector with comprehensive scope patterns
    pub fn new() -> Self {
        let mut scope_patterns = Vec::new();

        // === GitHub OAuth Scopes ===
        Self::add_pattern(
            &mut scope_patterns,
            r"(?i)^repo$",
            "github",
            RiskLevel::Critical,
            "Full repository access (read, write, delete)",
            vec!["git", "commit", "push", "repository", "code"],
        );
        Self::add_pattern(
            &mut scope_patterns,
            r"(?i)^repo:status$",
            "github",
            RiskLevel::Low,
            "Repository status access",
            vec!["status", "commit", "check"],
        );
        Self::add_pattern(
            &mut scope_patterns,
            r"(?i)^delete_repo$",
            "github",
            RiskLevel::Critical,
            "Delete repositories",
            vec!["delete", "repository", "remove"],
        );
        Self::add_pattern(
            &mut scope_patterns,
            r"(?i)^admin:org$",
            "github",
            RiskLevel::Critical,
            "Full organization admin access",
            vec!["organization", "admin", "manage"],
        );
        Self::add_pattern(
            &mut scope_patterns,
            r"(?i)^write:org$",
            "github",
            RiskLevel::High,
            "Write access to organization",
            vec!["organization", "team", "member"],
        );
        Self::add_pattern(
            &mut scope_patterns,
            r"(?i)^read:org$",
            "github",
            RiskLevel::Medium,
            "Read organization data",
            vec!["organization", "list", "member"],
        );
        Self::add_pattern(
            &mut scope_patterns,
            r"(?i)^user$",
            "github",
            RiskLevel::High,
            "Full user profile access",
            vec!["user", "profile", "email"],
        );
        Self::add_pattern(
            &mut scope_patterns,
            r"(?i)^user:email$",
            "github",
            RiskLevel::Medium,
            "User email access",
            vec!["email", "user"],
        );
        Self::add_pattern(
            &mut scope_patterns,
            r"(?i)^gist$",
            "github",
            RiskLevel::High,
            "Create and modify gists",
            vec!["gist", "snippet", "paste"],
        );
        Self::add_pattern(
            &mut scope_patterns,
            r"(?i)^workflow$",
            "github",
            RiskLevel::Critical,
            "Modify GitHub Actions workflows",
            vec!["workflow", "action", "ci", "pipeline"],
        );

        // === Google OAuth Scopes ===
        Self::add_pattern(
            &mut scope_patterns,
            r"(?i)googleapis\.com/auth/drive$",
            "google",
            RiskLevel::Critical,
            "Full Google Drive access",
            vec!["drive", "file", "document", "storage"],
        );
        Self::add_pattern(
            &mut scope_patterns,
            r"(?i)googleapis\.com/auth/drive\.readonly$",
            "google",
            RiskLevel::Medium,
            "Read-only Google Drive access",
            vec!["drive", "read", "file", "list"],
        );
        Self::add_pattern(
            &mut scope_patterns,
            r"(?i)googleapis\.com/auth/gmail\.(readonly|modify|compose|send)$",
            "google",
            RiskLevel::Critical,
            "Gmail access",
            vec!["email", "gmail", "mail", "send"],
        );
        Self::add_pattern(
            &mut scope_patterns,
            r"(?i)googleapis\.com/auth/calendar$",
            "google",
            RiskLevel::High,
            "Full Google Calendar access",
            vec!["calendar", "event", "schedule"],
        );
        Self::add_pattern(
            &mut scope_patterns,
            r"(?i)googleapis\.com/auth/contacts$",
            "google",
            RiskLevel::High,
            "Full contacts access",
            vec!["contact", "address", "people"],
        );
        Self::add_pattern(
            &mut scope_patterns,
            r"(?i)googleapis\.com/auth/cloud-platform$",
            "google",
            RiskLevel::Critical,
            "Full Google Cloud Platform access",
            vec!["cloud", "gcp", "compute", "storage"],
        );

        // === Microsoft/Azure OAuth Scopes ===
        Self::add_pattern(
            &mut scope_patterns,
            r"(?i)\.default$",
            "microsoft",
            RiskLevel::Critical,
            "All default permissions",
            vec![],
        );
        Self::add_pattern(
            &mut scope_patterns,
            r"(?i)Files\.ReadWrite\.All$",
            "microsoft",
            RiskLevel::Critical,
            "Full OneDrive/SharePoint access",
            vec!["file", "drive", "document"],
        );
        Self::add_pattern(
            &mut scope_patterns,
            r"(?i)Mail\.ReadWrite$",
            "microsoft",
            RiskLevel::Critical,
            "Full email access",
            vec!["mail", "email", "outlook"],
        );
        Self::add_pattern(
            &mut scope_patterns,
            r"(?i)User\.ReadWrite\.All$",
            "microsoft",
            RiskLevel::Critical,
            "Modify all user profiles",
            vec!["user", "profile", "admin"],
        );
        Self::add_pattern(
            &mut scope_patterns,
            r"(?i)Directory\.ReadWrite\.All$",
            "microsoft",
            RiskLevel::Critical,
            "Full Azure AD directory access",
            vec!["directory", "ad", "admin"],
        );

        // === Slack OAuth Scopes ===
        Self::add_pattern(
            &mut scope_patterns,
            r"(?i)^admin$",
            "slack",
            RiskLevel::Critical,
            "Full Slack admin access",
            vec!["admin", "workspace", "manage"],
        );
        Self::add_pattern(
            &mut scope_patterns,
            r"(?i)^chat:write$",
            "slack",
            RiskLevel::High,
            "Send messages as the app",
            vec!["message", "chat", "send"],
        );
        Self::add_pattern(
            &mut scope_patterns,
            r"(?i)^users:read\.email$",
            "slack",
            RiskLevel::Medium,
            "Access user emails",
            vec!["email", "user"],
        );
        Self::add_pattern(
            &mut scope_patterns,
            r"(?i)^files:write$",
            "slack",
            RiskLevel::High,
            "Upload and modify files",
            vec!["file", "upload"],
        );

        // === Generic dangerous patterns ===
        Self::add_pattern(
            &mut scope_patterns,
            r"(?i)(admin|root|superuser)",
            "generic",
            RiskLevel::Critical,
            "Administrative access",
            vec!["admin", "manage", "configure"],
        );
        Self::add_pattern(
            &mut scope_patterns,
            r"(?i)(write|modify|delete|remove).*all",
            "generic",
            RiskLevel::Critical,
            "Write access to all resources",
            vec![],
        );
        Self::add_pattern(
            &mut scope_patterns,
            r"(?i)offline.?access",
            "generic",
            RiskLevel::High,
            "Offline/persistent access",
            vec![],
        );

        let dangerous_combinations = vec![
            ScopeCombination {
                scopes: vec!["repo", "delete_repo"],
                risk_level: RiskLevel::Critical,
                description: "Can read and delete all repositories",
            },
            ScopeCombination {
                scopes: vec!["user", "admin:org"],
                risk_level: RiskLevel::Critical,
                description: "Full user and organization control",
            },
            ScopeCombination {
                scopes: vec!["Mail.ReadWrite", "offline_access"],
                risk_level: RiskLevel::Critical,
                description: "Persistent email access",
            },
        ];

        Self {
            scope_patterns,
            dangerous_combinations,
        }
    }

    fn add_pattern(
        patterns: &mut Vec<ScopePattern>,
        pattern: &str,
        provider: &'static str,
        risk_level: RiskLevel,
        description: &'static str,
        required_functionality: Vec<&'static str>,
    ) {
        if let Ok(regex) = Regex::new(pattern) {
            patterns.push(ScopePattern {
                pattern: regex,
                provider,
                risk_level,
                description,
                required_functionality,
            });
        }
    }

    /// Check tools and server metadata for OAuth scope abuse
    pub fn check_tools(&self, tools: &[Tool]) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Collect all scopes mentioned in tool descriptions and schemas
        let mut detected_scopes: Vec<(String, String)> = Vec::new(); // (scope, tool_name)

        for tool in tools {
            // Check tool descriptions for scope mentions
            if let Some(ref desc) = tool.description {
                for scope in self.extract_scopes(desc) {
                    detected_scopes.push((scope, tool.name.clone()));
                }
            }

            // Check schema for scope requirements
            let schema_str = tool.input_schema.to_string();
            for scope in self.extract_scopes(&schema_str) {
                detected_scopes.push((scope, tool.name.clone()));
            }

            // Check for excessive permission patterns in tool names/descriptions
            findings.extend(self.check_permission_patterns(tool));
        }

        // Analyze detected scopes
        for (scope, tool_name) in &detected_scopes {
            findings.extend(self.analyze_scope(scope, tool_name, tools));
        }

        // Check for dangerous scope combinations
        let all_scopes: HashSet<_> = detected_scopes.iter().map(|(s, _)| s.clone()).collect();
        findings.extend(self.check_dangerous_combinations(&all_scopes));

        // Deduplicate findings by rule_id + tool
        findings.sort_by(|a, b| {
            (&a.rule_id, &a.location.identifier).cmp(&(&b.rule_id, &b.location.identifier))
        });
        findings.dedup_by(|a, b| {
            a.rule_id == b.rule_id && a.location.identifier == b.location.identifier
        });

        findings
    }

    /// Extract potential OAuth scopes from text
    fn extract_scopes(&self, text: &str) -> Vec<String> {
        let mut scopes = Vec::new();

        // Common scope patterns
        let scope_regexes = [
            // GitHub style: repo, user:email, admin:org
            r"\b(repo|user|gist|admin|write|read|delete)[:\.]?(\w+)?\b",
            // Google style: https://www.googleapis.com/auth/...
            r"googleapis\.com/auth/[\w\.]+",
            // Microsoft style: Files.ReadWrite.All, Mail.Read, User.ReadWrite.All
            r"[A-Z][a-z]+\.[A-Z][a-zA-Z]+(?:\.[A-Z][a-z]+)?",
            // Slack style: chat:write, users:read
            r"\b(chat|users|files|channels|admin)[:\.](\w+)\b",
            // Generic patterns - match scope= or scopes: followed by value
            r#"\bscope[s]?\s*[:=]\s*["']?([^"'\s]+)["']?"#,
        ];

        for pattern in &scope_regexes {
            if let Ok(re) = Regex::new(pattern) {
                for cap in re.find_iter(text) {
                    let scope = cap.as_str().to_string();
                    if scope.len() >= 3 {
                        scopes.push(scope);
                    }
                }
            }
        }

        scopes
    }

    /// Analyze a single scope for potential abuse
    fn analyze_scope(&self, scope: &str, tool_name: &str, tools: &[Tool]) -> Vec<Finding> {
        let mut findings = Vec::new();

        for pattern in &self.scope_patterns {
            if pattern.pattern.is_match(scope) {
                // Check if tools provide functionality that justifies this scope
                let has_justification =
                    self.scope_justified_by_tools(tools, &pattern.required_functionality);

                if pattern.risk_level == RiskLevel::Critical
                    || (pattern.risk_level == RiskLevel::High && !has_justification)
                {
                    let severity = match pattern.risk_level {
                        RiskLevel::Critical => Severity::Critical,
                        RiskLevel::High => Severity::High,
                        RiskLevel::Medium => Severity::Medium,
                        RiskLevel::Low => Severity::Low,
                    };

                    let justification_text = if has_justification {
                        "Tool functionality may justify this scope, but review is recommended."
                    } else {
                        "No tool functionality appears to justify this scope level."
                    };

                    findings.push(
                        Finding::new(
                            "MCP-SEC-043",
                            severity,
                            "Excessive OAuth Scope Detected",
                            format!(
                                "Tool '{}' references OAuth scope '{}' ({}): {}. {}",
                                tool_name,
                                scope,
                                pattern.provider,
                                pattern.description,
                                justification_text
                            ),
                        )
                        .with_location(FindingLocation::tool(tool_name))
                        .with_evidence(Evidence::observation(
                            format!("OAuth scope: {} ({})", scope, pattern.provider),
                            format!("Risk level: {:?}", pattern.risk_level),
                        ))
                        .with_remediation(
                            "Request only the minimum OAuth scopes necessary for functionality. \
                             Use read-only scopes when write access is not required. \
                             Consider using more granular scopes instead of broad permissions.",
                        )
                        .with_cwe("250")
                        .with_reference(Reference::documentation(
                            "OAuth-Best-Practice",
                            "https://oauth.net/2/scope/",
                        )),
                    );
                }
            }
        }

        findings
    }

    /// Check if scope is justified by tool functionality
    fn scope_justified_by_tools(&self, tools: &[Tool], required_keywords: &[&str]) -> bool {
        if required_keywords.is_empty() {
            return false; // No justification possible
        }

        for tool in tools {
            let tool_text = format!(
                "{} {}",
                tool.name,
                tool.description.as_deref().unwrap_or("")
            )
            .to_lowercase();

            for keyword in required_keywords {
                if tool_text.contains(*keyword) {
                    return true;
                }
            }
        }

        false
    }

    /// Check for dangerous permission patterns in tools
    fn check_permission_patterns(&self, tool: &Tool) -> Vec<Finding> {
        let mut findings = Vec::new();

        let dangerous_patterns = [
            (
                r"(?i)full\s+access",
                "Full access permission",
                Severity::High,
            ),
            (
                r"(?i)all\s+permissions?",
                "All permissions requested",
                Severity::High,
            ),
            (
                r"(?i)admin(istrat(or|ive))?\s+(access|permission|right)",
                "Administrative access",
                Severity::Critical,
            ),
            (
                r"(?i)root\s+access",
                "Root/superuser access",
                Severity::Critical,
            ),
            (
                r"(?i)unlimited\s+(access|permission)",
                "Unlimited access",
                Severity::Critical,
            ),
            (
                r"(?i)bypass\s+(security|auth)",
                "Security bypass",
                Severity::Critical,
            ),
        ];

        let text = format!(
            "{} {}",
            tool.name,
            tool.description.as_deref().unwrap_or("")
        );

        for (pattern, description, severity) in &dangerous_patterns {
            if let Ok(re) = Regex::new(pattern) {
                if re.is_match(&text) {
                    findings.push(
                        Finding::new(
                            "MCP-SEC-043",
                            *severity,
                            "Dangerous Permission Pattern",
                            format!(
                                "Tool '{}' mentions '{}' which may indicate excessive permissions.",
                                tool.name, description
                            ),
                        )
                        .with_location(FindingLocation::tool(&tool.name))
                        .with_evidence(Evidence::observation(
                            description.to_string(),
                            format!("Found in: \"{}\"", truncate(&text, 100)),
                        ))
                        .with_remediation(
                            "Review the actual permissions required and request only minimum necessary access. \
                             Document why elevated permissions are required if they are legitimate.",
                        )
                        .with_cwe("269"),
                    );
                }
            }
        }

        findings
    }

    /// Check for dangerous scope combinations
    fn check_dangerous_combinations(&self, scopes: &HashSet<String>) -> Vec<Finding> {
        let mut findings = Vec::new();

        for combo in &self.dangerous_combinations {
            let scopes_lower: HashSet<String> = scopes.iter().map(|s| s.to_lowercase()).collect();
            let matches: Vec<_> = combo
                .scopes
                .iter()
                .filter(|s| {
                    scopes_lower
                        .iter()
                        .any(|scope| scope.contains(&s.to_lowercase()))
                })
                .collect();

            if matches.len() >= 2 {
                let severity = match combo.risk_level {
                    RiskLevel::Critical => Severity::Critical,
                    RiskLevel::High => Severity::High,
                    RiskLevel::Medium => Severity::Medium,
                    RiskLevel::Low => Severity::Low,
                };

                findings.push(
                    Finding::new(
                        "MCP-SEC-043",
                        severity,
                        "Dangerous OAuth Scope Combination",
                        format!(
                            "Detected dangerous combination of OAuth scopes: {}. {}",
                            combo.scopes.join(" + "),
                            combo.description
                        ),
                    )
                    .with_location(FindingLocation::server())
                    .with_evidence(Evidence::observation(
                        format!("Scope combination: {:?}", combo.scopes),
                        format!("Matched scopes: {:?}", matches),
                    ))
                    .with_remediation(
                        "Avoid requesting multiple high-privilege scopes together. \
                         Consider splitting functionality across separate, more focused integrations.",
                    )
                    .with_cwe("269"),
                );
            }
        }

        findings
    }
}

impl Default for OAuthAbuseDetector {
    fn default() -> Self {
        Self::new()
    }
}

fn truncate(s: &str, max_len: usize) -> String {
    if s.len() > max_len {
        format!("{}...", &s[..max_len])
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_tool(name: &str, description: Option<&str>) -> Tool {
        Tool {
            name: name.to_string(),
            description: description.map(|s| s.to_string()),
            input_schema: json!({"type": "object"}),
        }
    }

    #[test]
    fn detect_excessive_github_scope() {
        let detector = OAuthAbuseDetector::new();
        let tools = vec![make_tool(
            "simple_reader",
            Some("Reads files. Requires OAuth scope: repo"),
        )];

        let findings = detector.check_tools(&tools);
        assert!(!findings.is_empty());
        assert!(findings
            .iter()
            .any(|f| f.description.contains("repo") && f.description.contains("OAuth")));
    }

    #[test]
    fn detect_admin_scope() {
        let detector = OAuthAbuseDetector::new();
        let tools = vec![make_tool(
            "org_tool",
            Some("Manages organization. Requires admin:org scope."),
        )];

        let findings = detector.check_tools(&tools);
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn detect_dangerous_permission_pattern() {
        let detector = OAuthAbuseDetector::new();
        let tools = vec![make_tool(
            "super_tool",
            Some("This tool requires full access to all resources."),
        )];

        let findings = detector.check_tools(&tools);
        assert!(!findings.is_empty());
        assert!(findings
            .iter()
            .any(|f| f.title.contains("Dangerous Permission")));
    }

    #[test]
    fn allow_justified_scope() {
        let detector = OAuthAbuseDetector::new();
        let tools = vec![
            make_tool("git_commit", Some("Creates git commits in repository")),
            make_tool(
                "git_push",
                Some("Pushes commits to remote. Requires repo scope."),
            ),
        ];

        let findings = detector.check_tools(&tools);
        // Should still flag but with justification note
        let repo_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.description.contains("repo"))
            .collect();
        // The finding should exist but acknowledge justification
        if !repo_findings.is_empty() {
            assert!(repo_findings[0].description.contains("justify"));
        }
    }

    #[test]
    fn extract_scopes_from_text() {
        let detector = OAuthAbuseDetector::new();

        let text1 = "Requires repo:status and user:email scopes";
        let scopes1 = detector.extract_scopes(text1);
        assert!(!scopes1.is_empty());

        let text2 = "Uses https://www.googleapis.com/auth/drive.readonly";
        let scopes2 = detector.extract_scopes(text2);
        assert!(scopes2.iter().any(|s| s.contains("drive")));

        let text3 = "Needs Files.ReadWrite.All permission";
        let scopes3 = detector.extract_scopes(text3);
        assert!(scopes3.iter().any(|s| s.contains("ReadWrite")));
    }

    #[test]
    fn detect_google_scope() {
        let detector = OAuthAbuseDetector::new();
        let tools = vec![make_tool(
            "email_tool",
            Some("Access Gmail via googleapis.com/auth/gmail.modify"),
        )];

        let findings = detector.check_tools(&tools);
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn detect_microsoft_default_scope() {
        let detector = OAuthAbuseDetector::new();
        let tools = vec![make_tool(
            "azure_tool",
            Some("Uses Microsoft Graph API scope: https://graph.microsoft.com/.default"),
        )];

        let findings = detector.check_tools(&tools);
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.severity == Severity::Critical));
        assert!(findings.iter().any(|f| f.description.contains("microsoft")));
    }

    #[test]
    fn detect_microsoft_files_scope() {
        let detector = OAuthAbuseDetector::new();
        let tools = vec![make_tool(
            "file_access",
            Some("OneDrive access scope: Files.ReadWrite.All"),
        )];

        let findings = detector.check_tools(&tools);
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn detect_microsoft_mail_scope() {
        let detector = OAuthAbuseDetector::new();
        let tools = vec![make_tool(
            "outlook_tool",
            Some("Email access scope: Mail.ReadWrite"),
        )];

        let findings = detector.check_tools(&tools);
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn detect_microsoft_user_scope() {
        let detector = OAuthAbuseDetector::new();
        let tools = vec![make_tool(
            "user_manager",
            Some("User management scope: User.ReadWrite.All"),
        )];

        let findings = detector.check_tools(&tools);
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn detect_microsoft_directory_scope() {
        let detector = OAuthAbuseDetector::new();
        let tools = vec![make_tool(
            "ad_tool",
            Some("Azure AD scope: Directory.ReadWrite.All"),
        )];

        let findings = detector.check_tools(&tools);
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn detect_slack_admin_scope() {
        let detector = OAuthAbuseDetector::new();
        let tools = vec![make_tool(
            "slack_admin",
            Some("Slack workspace scope: admin"),
        )];

        let findings = detector.check_tools(&tools);
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn detect_generic_admin_pattern() {
        let detector = OAuthAbuseDetector::new();
        let tools = vec![make_tool(
            "management_tool",
            Some("Needs superuser access for system administration"),
        )];

        let findings = detector.check_tools(&tools);
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn detect_generic_write_all_pattern() {
        let detector = OAuthAbuseDetector::new();
        let tools = vec![make_tool(
            "bulk_modifier",
            Some("write all access required for resource modification - scope: write_all"),
        )];

        let findings = detector.check_tools(&tools);
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn detect_offline_access_scope() {
        let detector = OAuthAbuseDetector::new();
        let tools = vec![make_tool(
            "background_sync",
            Some("Persistent token scope: offline_access"),
        )];

        let findings = detector.check_tools(&tools);
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.severity == Severity::High));
    }

    #[test]
    fn detect_dangerous_scope_combination_repo_delete() {
        let detector = OAuthAbuseDetector::new();
        let tools = vec![
            make_tool("repo_reader", Some("Reads repositories with repo scope")),
            make_tool(
                "repo_deleter",
                Some("Deletes repos using delete_repo scope"),
            ),
        ];

        let findings = detector.check_tools(&tools);
        assert!(findings
            .iter()
            .any(|f| f.title.contains("Dangerous OAuth Scope Combination")));
        assert!(findings.iter().any(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn detect_dangerous_scope_combination_user_org() {
        let detector = OAuthAbuseDetector::new();
        let tools = vec![
            make_tool("user_manager", Some("Manages users with user scope")),
            make_tool("org_admin", Some("Organization admin via admin:org scope")),
        ];

        let findings = detector.check_tools(&tools);
        assert!(findings
            .iter()
            .any(|f| f.title.contains("Dangerous OAuth Scope Combination")));
    }

    #[test]
    fn detect_all_permissions_pattern() {
        let detector = OAuthAbuseDetector::new();
        let tools = vec![make_tool(
            "super_admin",
            Some("This tool needs all permissions to function"),
        )];

        let findings = detector.check_tools(&tools);
        assert!(findings
            .iter()
            .any(|f| f.title.contains("Dangerous Permission")));
    }

    #[test]
    fn detect_admin_access_pattern() {
        let detector = OAuthAbuseDetector::new();
        let tools = vec![make_tool(
            "system_config",
            Some("Requires administrative access to configure system"),
        )];

        let findings = detector.check_tools(&tools);
        assert!(findings
            .iter()
            .any(|f| f.title.contains("Dangerous Permission")));
    }

    #[test]
    fn detect_root_access_pattern() {
        let detector = OAuthAbuseDetector::new();
        let tools = vec![make_tool(
            "system_control",
            Some("Needs root access for system modifications"),
        )];

        let findings = detector.check_tools(&tools);
        assert!(findings
            .iter()
            .any(|f| f.title.contains("Dangerous Permission")));
        assert!(findings.iter().any(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn detect_unlimited_access_pattern() {
        let detector = OAuthAbuseDetector::new();
        let tools = vec![make_tool(
            "unrestricted_tool",
            Some("Provides unlimited access to all data"),
        )];

        let findings = detector.check_tools(&tools);
        assert!(findings
            .iter()
            .any(|f| f.title.contains("Dangerous Permission")));
    }

    #[test]
    fn detect_bypass_security_pattern() {
        let detector = OAuthAbuseDetector::new();
        let tools = vec![make_tool(
            "security_override",
            Some("Can bypass security checks when needed"),
        )];

        let findings = detector.check_tools(&tools);
        assert!(findings
            .iter()
            .any(|f| f.title.contains("Dangerous Permission")));
        assert!(findings.iter().any(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn detect_bypass_auth_pattern() {
        let detector = OAuthAbuseDetector::new();
        let tools = vec![make_tool(
            "auth_skip",
            Some("Tool can bypass auth for administrative tasks"),
        )];

        let findings = detector.check_tools(&tools);
        assert!(findings
            .iter()
            .any(|f| f.title.contains("Dangerous Permission")));
    }

    #[test]
    fn detect_github_delete_repo_scope() {
        let detector = OAuthAbuseDetector::new();
        let tools = vec![make_tool(
            "repo_cleanup",
            Some("Deletes repositories with delete_repo scope"),
        )];

        let findings = detector.check_tools(&tools);
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn detect_github_repo_status_scope() {
        let detector = OAuthAbuseDetector::new();
        let tools = vec![make_tool(
            "status_checker",
            Some("Checks commit status with repo:status scope"),
        )];

        let findings = detector.check_tools(&tools);
        // This is a low-risk scope, so it might not generate findings
        // unless there's no justification
        assert!(findings
            .iter()
            .all(|f| f.severity == Severity::Low || f.severity == Severity::Medium));
    }

    #[test]
    fn detect_google_drive_scope() {
        let detector = OAuthAbuseDetector::new();
        let tools = vec![make_tool(
            "drive_manager",
            Some("Full Drive access via googleapis.com/auth/drive"),
        )];

        let findings = detector.check_tools(&tools);
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn extract_scopes_slack_pattern() {
        let detector = OAuthAbuseDetector::new();
        let text = "Requires chat:write and channels:read scopes";
        let scopes = detector.extract_scopes(text);
        assert!(scopes.iter().any(|s| s.contains("chat")));
        assert!(scopes.iter().any(|s| s.contains("channels")));
    }

    #[test]
    fn extract_scopes_with_scope_equals() {
        let detector = OAuthAbuseDetector::new();
        let text = "Configure with scope=repo or scopes: user,admin:org";
        let scopes = detector.extract_scopes(text);
        assert!(!scopes.is_empty());
    }

    #[test]
    fn no_findings_for_safe_tool() {
        let detector = OAuthAbuseDetector::new();
        let tools = vec![make_tool(
            "calculator",
            Some("Performs basic math operations"),
        )];

        let findings = detector.check_tools(&tools);
        assert!(findings.is_empty());
    }

    #[test]
    fn deduplication_of_findings() {
        let detector = OAuthAbuseDetector::new();
        let tools = vec![make_tool(
            "multi_mention",
            Some("Uses repo scope and repo scope and repo scope"),
        )];

        let findings = detector.check_tools(&tools);
        // Findings should be deduplicated
        let repo_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.description.contains("repo"))
            .collect();
        assert!(repo_findings.len() <= 2); // Should not have excessive duplicates
    }

    #[test]
    fn scope_in_schema() {
        let detector = OAuthAbuseDetector::new();
        let mut tool = make_tool("schema_tool", Some("Tool with scope in schema"));
        tool.input_schema = json!({
            "type": "object",
            "properties": {
                "oauth_scope": {
                    "type": "string",
                    "default": "admin:org",
                    "description": "OAuth scope for API access"
                }
            }
        });

        let findings = detector.check_tools(&[tool]);
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn test_default_implementation() {
        let detector1 = OAuthAbuseDetector::new();
        let detector2 = OAuthAbuseDetector::default();

        // Both should have the same number of patterns
        assert_eq!(
            detector1.scope_patterns.len(),
            detector2.scope_patterns.len()
        );
        assert_eq!(
            detector1.dangerous_combinations.len(),
            detector2.dangerous_combinations.len()
        );
    }

    #[test]
    fn test_truncate_short_string() {
        let short = "short text";
        assert_eq!(truncate(short, 100), "short text");
    }

    #[test]
    fn test_truncate_long_string() {
        let long = "a".repeat(200);
        let result = truncate(&long, 100);
        assert_eq!(result.len(), 103); // 100 chars + "..."
        assert!(result.ends_with("..."));
    }

    #[test]
    fn multiple_tools_with_various_scopes() {
        let detector = OAuthAbuseDetector::new();
        let tools = vec![
            make_tool("github_tool", Some("Uses repo scope")),
            make_tool("google_tool", Some("Uses googleapis.com/auth/drive")),
            make_tool("slack_tool", Some("Uses admin scope")),
            make_tool("safe_tool", Some("No special permissions needed")),
        ];

        let findings = detector.check_tools(&tools);
        assert!(findings.len() >= 3); // At least one finding per dangerous tool
    }

    #[test]
    fn tool_with_no_description() {
        let detector = OAuthAbuseDetector::new();
        let tools = vec![make_tool("no_desc_tool", None)];

        let findings = detector.check_tools(&tools);
        assert!(findings.is_empty());
    }

    #[test]
    fn tool_with_empty_description() {
        let detector = OAuthAbuseDetector::new();
        let tools = vec![make_tool("empty_desc", Some(""))];

        let findings = detector.check_tools(&tools);
        assert!(findings.is_empty());
    }

    #[test]
    fn github_gmail_variants() {
        let detector = OAuthAbuseDetector::new();
        let tools = vec![
            make_tool(
                "gmail_readonly",
                Some("Read emails via googleapis.com/auth/gmail.readonly"),
            ),
            make_tool(
                "gmail_compose",
                Some("Compose emails via googleapis.com/auth/gmail.compose"),
            ),
            make_tool(
                "gmail_send",
                Some("Send emails via googleapis.com/auth/gmail.send"),
            ),
        ];

        let findings = detector.check_tools(&tools);
        assert!(!findings.is_empty());
        // All Gmail scopes should be flagged as critical
        assert!(findings.iter().any(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn check_cwe_and_references() {
        let detector = OAuthAbuseDetector::new();
        let tools = vec![make_tool("admin_tool", Some("Uses admin scope"))];

        let findings = detector.check_tools(&tools);
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| !f.references.is_empty()));
    }

    #[test]
    fn check_remediation_present() {
        let detector = OAuthAbuseDetector::new();
        let tools = vec![make_tool("scope_tool", Some("Uses repo scope"))];

        let findings = detector.check_tools(&tools);
        assert!(!findings.is_empty());
        assert!(findings.iter().all(|f| !f.remediation.is_empty()));
    }

    #[test]
    fn check_evidence_present() {
        let detector = OAuthAbuseDetector::new();
        let tools = vec![make_tool("evidence_tool", Some("Uses admin:org scope"))];

        let findings = detector.check_tools(&tools);
        assert!(!findings.is_empty());
        assert!(findings.iter().all(|f| !f.evidence.is_empty()));
    }

    #[test]
    fn scope_justified_with_empty_keywords() {
        let detector = OAuthAbuseDetector::new();
        let tools = vec![make_tool("test_tool", Some("Does testing"))];

        // Scopes with empty required_functionality should return false
        let justified = detector.scope_justified_by_tools(&tools, &[]);
        assert!(!justified);
    }
}
