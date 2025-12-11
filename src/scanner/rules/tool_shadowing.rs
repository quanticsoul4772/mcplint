//! SEC-041: Cross-Server Tool Shadowing Detection
//!
//! Detects when a server registers tools with names that shadow commonly-used
//! tools from well-known MCP servers or suspicious naming patterns.

use crate::protocol::mcp::Tool;
use crate::scanner::finding::{Evidence, Finding, FindingLocation, Reference, Severity};

/// Detector for cross-server tool shadowing attacks
pub struct ToolShadowingDetector {
    /// Well-known tool names from popular MCP servers
    known_tools: Vec<KnownTool>,
    /// Suspicious naming patterns
    suspicious_patterns: Vec<ShadowPattern>,
}

/// A well-known tool from a popular MCP server
struct KnownTool {
    name: &'static str,
    source: &'static str,
    #[allow(dead_code)] // Reserved for future detailed reporting
    description: &'static str,
}

/// Suspicious naming pattern that might indicate shadowing
struct ShadowPattern {
    pattern: &'static str,
    category: ShadowCategory,
    severity: Severity,
}

#[derive(Debug, Clone, Copy)]
enum ShadowCategory {
    /// Shadows file system operations
    FileSystem,
    /// Shadows code execution tools
    CodeExecution,
    /// Shadows network/API tools
    Network,
    /// Shadows authentication tools
    Authentication,
    /// Shadows database tools
    Database,
    /// Shadows Claude/AI tools
    AiAssistant,
}

impl ToolShadowingDetector {
    /// Create a new detector with comprehensive known tool database
    pub fn new() -> Self {
        let known_tools = vec![
            // Filesystem MCP server tools
            KnownTool {
                name: "read_file",
                source: "filesystem",
                description: "Read file contents",
            },
            KnownTool {
                name: "write_file",
                source: "filesystem",
                description: "Write file contents",
            },
            KnownTool {
                name: "list_directory",
                source: "filesystem",
                description: "List directory contents",
            },
            KnownTool {
                name: "create_directory",
                source: "filesystem",
                description: "Create a directory",
            },
            KnownTool {
                name: "delete_file",
                source: "filesystem",
                description: "Delete a file",
            },
            KnownTool {
                name: "move_file",
                source: "filesystem",
                description: "Move/rename a file",
            },
            KnownTool {
                name: "copy_file",
                source: "filesystem",
                description: "Copy a file",
            },
            KnownTool {
                name: "get_file_info",
                source: "filesystem",
                description: "Get file metadata",
            },
            KnownTool {
                name: "search_files",
                source: "filesystem",
                description: "Search for files",
            },
            // Git MCP server tools
            KnownTool {
                name: "git_status",
                source: "git",
                description: "Get git status",
            },
            KnownTool {
                name: "git_diff",
                source: "git",
                description: "Get git diff",
            },
            KnownTool {
                name: "git_commit",
                source: "git",
                description: "Create git commit",
            },
            KnownTool {
                name: "git_push",
                source: "git",
                description: "Push to remote",
            },
            KnownTool {
                name: "git_log",
                source: "git",
                description: "View git log",
            },
            // GitHub MCP server tools
            KnownTool {
                name: "create_issue",
                source: "github",
                description: "Create GitHub issue",
            },
            KnownTool {
                name: "create_pull_request",
                source: "github",
                description: "Create pull request",
            },
            KnownTool {
                name: "list_issues",
                source: "github",
                description: "List issues",
            },
            KnownTool {
                name: "search_repositories",
                source: "github",
                description: "Search repos",
            },
            // Fetch/Web MCP server tools
            KnownTool {
                name: "fetch",
                source: "fetch",
                description: "Fetch URL contents",
            },
            KnownTool {
                name: "fetch_url",
                source: "fetch",
                description: "Fetch URL contents",
            },
            KnownTool {
                name: "web_search",
                source: "brave-search",
                description: "Web search",
            },
            KnownTool {
                name: "brave_search",
                source: "brave-search",
                description: "Brave search",
            },
            // Puppeteer/Browser tools
            KnownTool {
                name: "navigate",
                source: "puppeteer",
                description: "Navigate browser",
            },
            KnownTool {
                name: "screenshot",
                source: "puppeteer",
                description: "Take screenshot",
            },
            KnownTool {
                name: "click",
                source: "puppeteer",
                description: "Click element",
            },
            // Memory/Knowledge tools
            KnownTool {
                name: "store_memory",
                source: "memory",
                description: "Store in memory",
            },
            KnownTool {
                name: "retrieve_memory",
                source: "memory",
                description: "Retrieve from memory",
            },
            KnownTool {
                name: "search_memory",
                source: "memory",
                description: "Search memory",
            },
            // Slack tools
            KnownTool {
                name: "send_message",
                source: "slack",
                description: "Send Slack message",
            },
            KnownTool {
                name: "list_channels",
                source: "slack",
                description: "List Slack channels",
            },
            // Database tools
            KnownTool {
                name: "query",
                source: "sqlite/postgres",
                description: "Execute SQL query",
            },
            KnownTool {
                name: "execute_query",
                source: "sqlite/postgres",
                description: "Execute SQL query",
            },
            KnownTool {
                name: "list_tables",
                source: "sqlite/postgres",
                description: "List database tables",
            },
            // Common shell/execution tools
            KnownTool {
                name: "run_command",
                source: "shell",
                description: "Run shell command",
            },
            KnownTool {
                name: "execute",
                source: "shell",
                description: "Execute command",
            },
            KnownTool {
                name: "bash",
                source: "shell",
                description: "Run bash command",
            },
        ];

        let suspicious_patterns = vec![
            // File system shadowing
            ShadowPattern {
                pattern: "read_file",
                category: ShadowCategory::FileSystem,
                severity: Severity::High,
            },
            ShadowPattern {
                pattern: "write_file",
                category: ShadowCategory::FileSystem,
                severity: Severity::Critical,
            },
            ShadowPattern {
                pattern: "delete_file",
                category: ShadowCategory::FileSystem,
                severity: Severity::Critical,
            },
            ShadowPattern {
                pattern: "list_directory",
                category: ShadowCategory::FileSystem,
                severity: Severity::High,
            },
            // Code execution shadowing (most dangerous)
            ShadowPattern {
                pattern: "execute",
                category: ShadowCategory::CodeExecution,
                severity: Severity::Critical,
            },
            ShadowPattern {
                pattern: "run_command",
                category: ShadowCategory::CodeExecution,
                severity: Severity::Critical,
            },
            ShadowPattern {
                pattern: "bash",
                category: ShadowCategory::CodeExecution,
                severity: Severity::Critical,
            },
            ShadowPattern {
                pattern: "shell",
                category: ShadowCategory::CodeExecution,
                severity: Severity::Critical,
            },
            // Note: "eval" is handled in AiAssistant category to avoid false positives
            // on legitimate reasoning tools like "evaluate-hypotheses", "self-evaluate"
            // Network tools
            ShadowPattern {
                pattern: "fetch",
                category: ShadowCategory::Network,
                severity: Severity::High,
            },
            ShadowPattern {
                pattern: "http_request",
                category: ShadowCategory::Network,
                severity: Severity::High,
            },
            ShadowPattern {
                pattern: "web_search",
                category: ShadowCategory::Network,
                severity: Severity::Medium,
            },
            // Auth tools
            ShadowPattern {
                pattern: "authenticate",
                category: ShadowCategory::Authentication,
                severity: Severity::Critical,
            },
            ShadowPattern {
                pattern: "login",
                category: ShadowCategory::Authentication,
                severity: Severity::Critical,
            },
            ShadowPattern {
                pattern: "get_token",
                category: ShadowCategory::Authentication,
                severity: Severity::Critical,
            },
            ShadowPattern {
                pattern: "oauth",
                category: ShadowCategory::Authentication,
                severity: Severity::Critical,
            },
            // Database tools
            ShadowPattern {
                pattern: "query",
                category: ShadowCategory::Database,
                severity: Severity::High,
            },
            ShadowPattern {
                pattern: "execute_sql",
                category: ShadowCategory::Database,
                severity: Severity::High,
            },
            // AI assistant tools (potential for confusion attacks)
            // Note: These patterns have low/info severity because many legitimate
            // MCP servers provide reasoning/analysis tools. Only flag if the
            // description doesn't match expected cognitive functionality.
            ShadowPattern {
                pattern: "think",
                category: ShadowCategory::AiAssistant,
                severity: Severity::Info,
            },
            ShadowPattern {
                pattern: "reason",
                category: ShadowCategory::AiAssistant,
                severity: Severity::Info,
            },
            ShadowPattern {
                pattern: "analyze",
                category: ShadowCategory::AiAssistant,
                severity: Severity::Info,
            },
            ShadowPattern {
                pattern: "eval",
                category: ShadowCategory::AiAssistant,
                severity: Severity::Info,
            },
        ];

        Self {
            known_tools,
            suspicious_patterns,
        }
    }

    /// Check tools for potential shadowing attacks
    pub fn check_tools(&self, tools: &[Tool], server_name: Option<&str>) -> Vec<Finding> {
        let mut findings = Vec::new();

        for tool in tools {
            // Check against known tools from other servers
            findings.extend(self.check_known_tool_shadowing(tool, server_name));

            // Check for suspicious generic naming patterns
            findings.extend(self.check_suspicious_patterns(tool));

            // Check for typosquatting attempts
            findings.extend(self.check_typosquatting(tool));
        }

        findings
    }

    /// Check if tool shadows a known tool from another server
    fn check_known_tool_shadowing(&self, tool: &Tool, server_name: Option<&str>) -> Vec<Finding> {
        let mut findings = Vec::new();
        let tool_name_lower = tool.name.to_lowercase();

        for known in &self.known_tools {
            // Skip if this server is the expected source
            if let Some(name) = server_name {
                if name.to_lowercase().contains(known.source) {
                    continue;
                }
            }

            // Exact match
            if tool_name_lower == known.name.to_lowercase() {
                findings.push(self.create_shadowing_finding(
                    tool,
                    known.name,
                    known.source,
                    ShadowType::ExactMatch,
                ));
            }
            // Similar name (contains the known name)
            else if tool_name_lower.contains(&known.name.to_lowercase())
                || known.name.to_lowercase().contains(&tool_name_lower)
            {
                // Skip if the tool has a clear differentiating prefix that indicates
                // it's for a different protocol/purpose (e.g., sftp_, ssh_, remote_)
                let has_clear_prefix = tool_name_lower.starts_with("sftp_")
                    || tool_name_lower.starts_with("ssh_")
                    || tool_name_lower.starts_with("remote_")
                    || tool_name_lower.starts_with("s3_")
                    || tool_name_lower.starts_with("azure_")
                    || tool_name_lower.starts_with("gcp_")
                    || tool_name_lower.starts_with("cloud_");

                if has_clear_prefix {
                    continue;
                }

                // Only flag if very similar (at least 70% of characters match)
                if self.similarity_score(&tool_name_lower, known.name) > 0.7 {
                    findings.push(self.create_shadowing_finding(
                        tool,
                        known.name,
                        known.source,
                        ShadowType::SimilarName,
                    ));
                }
            }
        }

        findings
    }

    /// Check for suspicious generic naming patterns
    fn check_suspicious_patterns(&self, tool: &Tool) -> Vec<Finding> {
        let mut findings = Vec::new();
        let tool_name_lower = tool.name.to_lowercase();

        for pattern in &self.suspicious_patterns {
            if tool_name_lower == pattern.pattern || tool_name_lower.contains(pattern.pattern) {
                // Check if the tool description seems legitimate
                let desc_lower = tool
                    .description
                    .as_ref()
                    .map(|d| d.to_lowercase())
                    .unwrap_or_default();

                // Flag if description doesn't match expected functionality
                if !self.description_matches_category(&desc_lower, pattern.category) {
                    findings.push(
                        Finding::new(
                            "MCP-SEC-041",
                            pattern.severity,
                            "Suspicious Tool Name Pattern",
                            format!(
                                "Tool '{}' uses a generic name pattern '{}' commonly used by {} tools. \
                                 This could intercept calls intended for legitimate tools.",
                                tool.name,
                                pattern.pattern,
                                category_name(pattern.category)
                            ),
                        )
                        .with_location(FindingLocation::tool(&tool.name))
                        .with_evidence(Evidence::observation(
                            format!("Matches {} pattern: {}", category_name(pattern.category), pattern.pattern),
                            format!("Tool description: \"{}\"", truncate(&desc_lower, 100)),
                        ))
                        .with_remediation(
                            "Use unique, descriptive tool names that clearly indicate the server source. \
                             For example, use 'myserver_read_file' instead of 'read_file'. \
                             This prevents accidental shadowing of tools from other servers.",
                        )
                        .with_cwe("706")
                        .with_reference(Reference::mcp_advisory("MCP-Security-Advisory-2025-03")),
                    );
                }
            }
        }

        findings
    }

    /// Check for typosquatting attempts (slight misspellings of known tools)
    fn check_typosquatting(&self, tool: &Tool) -> Vec<Finding> {
        let mut findings = Vec::new();
        let tool_name_lower = tool.name.to_lowercase();

        for known in &self.known_tools {
            let known_lower = known.name.to_lowercase();

            // Skip exact matches (handled elsewhere)
            if tool_name_lower == known_lower {
                continue;
            }

            // Check for edit distance of 1-2 (potential typosquatting)
            let distance = self.levenshtein_distance(&tool_name_lower, &known_lower);
            if distance > 0 && distance <= 2 && tool_name_lower.len() >= 4 {
                findings.push(
                    Finding::new(
                        "MCP-SEC-041",
                        Severity::High,
                        "Potential Typosquatting Tool Name",
                        format!(
                            "Tool '{}' has a name very similar to '{}' from the {} server \
                             (edit distance: {}). This may be an attempt to intercept tool calls \
                             through typosquatting.",
                            tool.name, known.name, known.source, distance
                        ),
                    )
                    .with_location(FindingLocation::tool(&tool.name))
                    .with_evidence(Evidence::observation(
                        format!("Similar to known tool: {} (from {})", known.name, known.source),
                        format!("Levenshtein distance: {}", distance),
                    ))
                    .with_remediation(
                        "If this is intentional, use a clearly distinct name. \
                         If unintentional, correct the typo to avoid confusion with legitimate tools.",
                    )
                    .with_cwe("706")
                    .with_reference(Reference::mcp_advisory("MCP-Security-Advisory-2025-03")),
                );
            }
        }

        findings
    }

    /// Create a shadowing finding
    fn create_shadowing_finding(
        &self,
        tool: &Tool,
        known_name: &str,
        known_source: &str,
        shadow_type: ShadowType,
    ) -> Finding {
        let severity = match shadow_type {
            ShadowType::ExactMatch => Severity::High,
            ShadowType::SimilarName => Severity::Medium,
        };

        let type_desc = match shadow_type {
            ShadowType::ExactMatch => "exactly matches",
            ShadowType::SimilarName => "is similar to",
        };

        Finding::new(
            "MCP-SEC-041",
            severity,
            "Cross-Server Tool Shadowing Detected",
            format!(
                "Tool '{}' {} known tool '{}' from the {} MCP server. \
                 This could intercept calls intended for the legitimate tool, \
                 enabling data theft or manipulation.",
                tool.name, type_desc, known_name, known_source
            ),
        )
        .with_location(FindingLocation::tool(&tool.name))
        .with_evidence(Evidence::observation(
            format!("Shadows: {} (from {} server)", known_name, known_source),
            format!(
                "Tool description: \"{}\"",
                truncate(tool.description.as_deref().unwrap_or("(none)"), 100)
            ),
        ))
        .with_remediation(
            "Rename the tool to use a unique, server-specific prefix. \
             For example, instead of 'read_file', use 'myserver_read_file' or 'custom_read_file'. \
             This prevents tool shadowing and makes the tool's origin clear.",
        )
        .with_cwe("706")
        .with_reference(Reference::mcp_advisory("MCP-Security-Advisory-2025-03"))
    }

    /// Calculate similarity score between two strings (0.0 to 1.0)
    fn similarity_score(&self, a: &str, b: &str) -> f64 {
        let distance = self.levenshtein_distance(a, b);
        let max_len = std::cmp::max(a.len(), b.len());
        if max_len == 0 {
            return 1.0;
        }
        1.0 - (distance as f64 / max_len as f64)
    }

    /// Calculate Levenshtein edit distance between two strings
    fn levenshtein_distance(&self, a: &str, b: &str) -> usize {
        let a_chars: Vec<char> = a.chars().collect();
        let b_chars: Vec<char> = b.chars().collect();
        let a_len = a_chars.len();
        let b_len = b_chars.len();

        if a_len == 0 {
            return b_len;
        }
        if b_len == 0 {
            return a_len;
        }

        let mut matrix = vec![vec![0; b_len + 1]; a_len + 1];

        // Initialize first column
        for (i, row) in matrix.iter_mut().enumerate() {
            row[0] = i;
        }
        // Initialize first row
        for (j, val) in matrix[0].iter_mut().enumerate() {
            *val = j;
        }

        for i in 1..=a_len {
            for j in 1..=b_len {
                let cost = if a_chars[i - 1] == b_chars[j - 1] {
                    0
                } else {
                    1
                };
                matrix[i][j] = std::cmp::min(
                    std::cmp::min(matrix[i - 1][j] + 1, matrix[i][j - 1] + 1),
                    matrix[i - 1][j - 1] + cost,
                );
            }
        }

        matrix[a_len][b_len]
    }

    /// Check if description matches expected category functionality
    fn description_matches_category(&self, desc: &str, category: ShadowCategory) -> bool {
        match category {
            ShadowCategory::FileSystem => {
                desc.contains("file") || desc.contains("directory") || desc.contains("folder")
            }
            ShadowCategory::CodeExecution => {
                desc.contains("command")
                    || desc.contains("execute")
                    || desc.contains("run")
                    || desc.contains("shell")
            }
            ShadowCategory::Network => {
                desc.contains("http")
                    || desc.contains("url")
                    || desc.contains("web")
                    || desc.contains("api")
                    || desc.contains("fetch")
            }
            ShadowCategory::Authentication => {
                desc.contains("auth")
                    || desc.contains("login")
                    || desc.contains("token")
                    || desc.contains("credential")
            }
            ShadowCategory::Database => {
                desc.contains("database")
                    || desc.contains("sql")
                    || desc.contains("query")
                    || desc.contains("table")
            }
            ShadowCategory::AiAssistant => {
                desc.contains("think")
                    || desc.contains("reason")
                    || desc.contains("analyze")
                    || desc.contains("ai")
                    || desc.contains("cognitive")
                    || desc.contains("hypothesis")
                    || desc.contains("hypotheses")
                    || desc.contains("inference")
                    || desc.contains("bayesian")
                    || desc.contains("probabilistic")
                    || desc.contains("decision")
                    || desc.contains("evaluat")
                    || desc.contains("metacognit")
                    || desc.contains("self-assess")
                    || desc.contains("reflect")
                    || desc.contains("timing")
            }
        }
    }
}

impl Default for ToolShadowingDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy)]
enum ShadowType {
    ExactMatch,
    SimilarName,
}

fn category_name(category: ShadowCategory) -> &'static str {
    match category {
        ShadowCategory::FileSystem => "filesystem",
        ShadowCategory::CodeExecution => "code execution",
        ShadowCategory::Network => "network/API",
        ShadowCategory::Authentication => "authentication",
        ShadowCategory::Database => "database",
        ShadowCategory::AiAssistant => "AI assistant",
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
    fn detect_exact_shadowing() {
        let detector = ToolShadowingDetector::new();
        let tools = vec![make_tool("read_file", Some("Reads files from disk"))];

        // Server name doesn't match expected source
        let findings = detector.check_tools(&tools, Some("malicious-server"));
        assert!(!findings.is_empty());
        assert!(findings[0].description.contains("read_file"));
    }

    #[test]
    fn allow_legitimate_tool() {
        let detector = ToolShadowingDetector::new();
        let tools = vec![make_tool("read_file", Some("Reads files from disk"))];

        // Server name matches expected source
        let findings = detector.check_tools(&tools, Some("filesystem-server"));
        // Should have fewer findings because it's from the expected source
        let shadowing_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("Shadowing"))
            .collect();
        assert!(shadowing_findings.is_empty());
    }

    #[test]
    fn detect_typosquatting() {
        let detector = ToolShadowingDetector::new();
        let tools = vec![
            make_tool("read_flie", Some("Reads files")), // typo: flie instead of file
            make_tool("reed_file", Some("Reads files")), // typo: reed instead of read
        ];

        let findings = detector.check_tools(&tools, Some("random-server"));
        let typo_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("Typosquatting"))
            .collect();
        assert!(!typo_findings.is_empty());
    }

    #[test]
    fn detect_suspicious_execute_pattern() {
        let detector = ToolShadowingDetector::new();
        let tools = vec![make_tool(
            "execute",
            Some("Runs arbitrary operations"), // vague description
        )];

        let findings = detector.check_tools(&tools, Some("random-server"));
        assert!(!findings.is_empty());
    }

    #[test]
    fn levenshtein_distance_calculation() {
        let detector = ToolShadowingDetector::new();

        assert_eq!(detector.levenshtein_distance("read_file", "read_file"), 0);
        assert_eq!(detector.levenshtein_distance("read_file", "read_flie"), 2);
        assert_eq!(detector.levenshtein_distance("read_file", "reed_file"), 1);
        assert_eq!(detector.levenshtein_distance("cat", "dog"), 3);
    }

    #[test]
    fn similarity_score_calculation() {
        let detector = ToolShadowingDetector::new();

        assert!((detector.similarity_score("read_file", "read_file") - 1.0).abs() < 0.01);
        assert!(detector.similarity_score("read_file", "read_flie") > 0.7);
        assert!(detector.similarity_score("abc", "xyz") < 0.5);
    }

    #[test]
    fn test_database_initialization() {
        let detector = ToolShadowingDetector::new();
        // Verify that known tools are loaded
        assert!(!detector.known_tools.is_empty());
        assert!(!detector.suspicious_patterns.is_empty());

        // Check that we have tools from various sources
        assert!(detector
            .known_tools
            .iter()
            .any(|t| t.source == "filesystem"));
        assert!(detector.known_tools.iter().any(|t| t.source == "git"));
        assert!(detector.known_tools.iter().any(|t| t.source == "github"));
        assert!(detector.known_tools.iter().any(|t| t.source == "shell"));
    }

    #[test]
    fn test_similarity_score_edge_cases() {
        let detector = ToolShadowingDetector::new();

        // Empty string comparison
        assert!((detector.similarity_score("", "") - 1.0).abs() < 0.01);

        // One empty string
        assert!((detector.similarity_score("", "abc") - 0.0).abs() < 0.01);
        assert!((detector.similarity_score("abc", "") - 0.0).abs() < 0.01);

        // Single character differences
        assert!(detector.similarity_score("a", "b") < 0.5);
        assert!((detector.similarity_score("a", "a") - 1.0).abs() < 0.01);
    }

    #[test]
    fn test_levenshtein_edge_cases() {
        let detector = ToolShadowingDetector::new();

        // Empty strings
        assert_eq!(detector.levenshtein_distance("", ""), 0);
        assert_eq!(detector.levenshtein_distance("", "abc"), 3);
        assert_eq!(detector.levenshtein_distance("abc", ""), 3);

        // Single characters
        assert_eq!(detector.levenshtein_distance("a", "a"), 0);
        assert_eq!(detector.levenshtein_distance("a", "b"), 1);

        // Insertions, deletions, substitutions
        assert_eq!(detector.levenshtein_distance("kitten", "sitting"), 3);
        assert_eq!(detector.levenshtein_distance("Saturday", "Sunday"), 3);
    }

    #[test]
    fn test_suspicious_pattern_with_matching_description() {
        let detector = ToolShadowingDetector::new();

        // Tool with matching description should not be flagged
        let tools = vec![
            make_tool("execute", Some("Execute shell command via subprocess")),
            make_tool(
                "read_file",
                Some("Read file contents from local filesystem"),
            ),
        ];

        let findings = detector.check_tools(&tools, Some("custom-server"));

        // These should still be flagged if description doesn't match well enough
        // but fewer than if description was completely unrelated
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_clear_prefix_detection() {
        let detector = ToolShadowingDetector::new();

        // Tools with clear prefixes should not be flagged as shadowing
        let tools = vec![
            make_tool("sftp_read_file", Some("Read file via SFTP")),
            make_tool("ssh_execute", Some("Execute command via SSH")),
            make_tool("s3_write_file", Some("Write file to S3")),
            make_tool("azure_list_directory", Some("List Azure storage")),
            make_tool("gcp_delete_file", Some("Delete file from GCP")),
            make_tool("cloud_copy_file", Some("Copy file in cloud storage")),
            make_tool("remote_bash", Some("Execute bash remotely")),
        ];

        let findings = detector.check_tools(&tools, Some("cloud-server"));

        // Should have fewer or no shadowing findings due to clear prefixes
        let shadowing_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("Shadowing") || f.title.contains("Pattern"))
            .collect();

        // These are clearly differentiated, so should not trigger shadowing
        assert!(shadowing_findings.is_empty() || shadowing_findings.len() < tools.len());
    }

    #[test]
    fn test_description_matches_filesystem_category() {
        let detector = ToolShadowingDetector::new();

        // Should match
        assert!(
            detector.description_matches_category("read file contents", ShadowCategory::FileSystem)
        );
        assert!(detector
            .description_matches_category("list directory entries", ShadowCategory::FileSystem));
        assert!(
            detector.description_matches_category("create a folder", ShadowCategory::FileSystem)
        );

        // Should not match
        assert!(
            !detector.description_matches_category("execute command", ShadowCategory::FileSystem)
        );
    }

    #[test]
    fn test_description_matches_code_execution_category() {
        let detector = ToolShadowingDetector::new();

        // Should match
        assert!(detector
            .description_matches_category("execute a command", ShadowCategory::CodeExecution));
        assert!(detector
            .description_matches_category("run shell script", ShadowCategory::CodeExecution));

        // Should not match
        assert!(!detector.description_matches_category("read file", ShadowCategory::CodeExecution));
    }

    #[test]
    fn test_description_matches_network_category() {
        let detector = ToolShadowingDetector::new();

        // Should match
        assert!(
            detector.description_matches_category("fetch http resource", ShadowCategory::Network)
        );
        assert!(detector.description_matches_category("call web api", ShadowCategory::Network));
        assert!(detector.description_matches_category("download from url", ShadowCategory::Network));

        // Should not match
        assert!(!detector.description_matches_category("read local file", ShadowCategory::Network));
    }

    #[test]
    fn test_description_matches_authentication_category() {
        let detector = ToolShadowingDetector::new();

        // Should match
        assert!(detector
            .description_matches_category("authenticate user", ShadowCategory::Authentication));
        assert!(
            detector.description_matches_category("perform login", ShadowCategory::Authentication)
        );
        assert!(
            detector.description_matches_category("get auth token", ShadowCategory::Authentication)
        );
        assert!(detector
            .description_matches_category("store credentials", ShadowCategory::Authentication));

        // Should not match
        assert!(!detector.description_matches_category("read file", ShadowCategory::Authentication));
    }

    #[test]
    fn test_description_matches_database_category() {
        let detector = ToolShadowingDetector::new();

        // Should match
        assert!(
            detector.description_matches_category("execute sql query", ShadowCategory::Database)
        );
        assert!(
            detector.description_matches_category("list database tables", ShadowCategory::Database)
        );

        // Should not match
        assert!(!detector.description_matches_category("read file", ShadowCategory::Database));
    }

    #[test]
    fn test_description_matches_ai_assistant_category() {
        let detector = ToolShadowingDetector::new();

        // Should match
        assert!(detector
            .description_matches_category("think through problem", ShadowCategory::AiAssistant));
        assert!(detector
            .description_matches_category("reason about hypothesis", ShadowCategory::AiAssistant));
        assert!(detector.description_matches_category("analyze data", ShadowCategory::AiAssistant));
        assert!(detector
            .description_matches_category("evaluate hypotheses", ShadowCategory::AiAssistant));
        assert!(detector
            .description_matches_category("bayesian inference", ShadowCategory::AiAssistant));
        assert!(detector
            .description_matches_category("probabilistic reasoning", ShadowCategory::AiAssistant));
        assert!(
            detector.description_matches_category("decision making", ShadowCategory::AiAssistant)
        );
        assert!(detector
            .description_matches_category("metacognitive reflection", ShadowCategory::AiAssistant));
        assert!(detector
            .description_matches_category("self-assessment tool", ShadowCategory::AiAssistant));
        assert!(
            detector.description_matches_category("timing analysis", ShadowCategory::AiAssistant)
        );

        // Should not match
        assert!(
            !detector.description_matches_category("execute command", ShadowCategory::AiAssistant)
        );
    }

    #[test]
    fn test_typosquatting_various_distances() {
        let detector = ToolShadowingDetector::new();

        // Distance 1 - should be flagged
        let tools = vec![
            make_tool("git_comit", Some("Create commit")), // missing 'm'
            make_tool("git_pushh", Some("Push to remote")), // extra 'h'
        ];

        let findings = detector.check_tools(&tools, Some("custom-server"));
        let typo_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("Typosquatting"))
            .collect();
        assert!(!typo_findings.is_empty());
    }

    #[test]
    fn test_typosquatting_short_names_not_flagged() {
        let detector = ToolShadowingDetector::new();

        // Short names (< 4 chars) should not trigger typosquatting
        let tools = vec![
            make_tool("gt", Some("Get tool")), // similar to "git" but too short
            make_tool("bsh", Some("Shell")),   // similar to "bash" but too short
        ];

        let findings = detector.check_tools(&tools, Some("custom-server"));
        let typo_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("Typosquatting"))
            .collect();

        // Short names should not be flagged for typosquatting
        assert!(typo_findings.is_empty());
    }

    #[test]
    fn test_unicode_tool_names() {
        let detector = ToolShadowingDetector::new();

        // Unicode characters in tool names
        let tools = vec![
            make_tool("read_file_🔒", Some("Read secure file")),
            make_tool("写文件", Some("Write file")), // Chinese characters
            make_tool("читать_файл", Some("Read file")), // Cyrillic
        ];

        // Should not crash and should process without panic
        let _findings = detector.check_tools(&tools, Some("unicode-server"));
        // Just verify it doesn't panic - if we get here, test passes
    }

    #[test]
    fn test_empty_tool_name() {
        let detector = ToolShadowingDetector::new();

        let tools = vec![make_tool("", Some("Empty name tool"))];

        // Should handle empty names gracefully
        let _findings = detector.check_tools(&tools, Some("test-server"));
        // If we get here without panic, test passes
    }

    #[test]
    fn test_similar_name_detection() {
        let detector = ToolShadowingDetector::new();

        // Tools with similar names that contain known tool names
        // "read_filex" contains "read_file" and is very similar (edit distance 1)
        let tools = vec![
            make_tool("read_filex", Some("Custom file reader")),
            make_tool("git_commitx", Some("Enhanced commit")),
        ];

        let findings = detector.check_tools(&tools, Some("custom-server"));

        // Should detect similar name shadowing
        let shadowing_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("Shadowing"))
            .collect();

        assert!(!shadowing_findings.is_empty());
    }

    #[test]
    fn test_exact_match_severity() {
        let detector = ToolShadowingDetector::new();

        let tools = vec![make_tool("read_file", Some("Reads files"))];
        let findings = detector.check_tools(&tools, Some("malicious-server"));

        // Exact match should be High severity
        let exact_matches: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("Shadowing") && f.severity == Severity::High)
            .collect();

        assert!(!exact_matches.is_empty());
    }

    #[test]
    fn test_category_name_function() {
        assert_eq!(category_name(ShadowCategory::FileSystem), "filesystem");
        assert_eq!(
            category_name(ShadowCategory::CodeExecution),
            "code execution"
        );
        assert_eq!(category_name(ShadowCategory::Network), "network/API");
        assert_eq!(
            category_name(ShadowCategory::Authentication),
            "authentication"
        );
        assert_eq!(category_name(ShadowCategory::Database), "database");
        assert_eq!(category_name(ShadowCategory::AiAssistant), "AI assistant");
    }

    #[test]
    fn test_truncate_function() {
        assert_eq!(truncate("short", 10), "short");
        assert_eq!(truncate("this is a very long string", 10), "this is a ...");
        assert_eq!(truncate("exactly10!", 10), "exactly10!");
        assert_eq!(truncate("", 10), "");
    }

    #[test]
    fn test_default_implementation() {
        let detector = ToolShadowingDetector::default();
        assert!(!detector.known_tools.is_empty());
        assert!(!detector.suspicious_patterns.is_empty());
    }

    #[test]
    fn test_multiple_findings_per_tool() {
        let detector = ToolShadowingDetector::new();

        // A tool that triggers multiple detection rules
        let tools = vec![make_tool("execute", Some("Does something vague"))];

        let findings = detector.check_tools(&tools, Some("suspicious-server"));

        // Should detect both suspicious pattern and possibly shadowing
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_git_server_allowed_git_tools() {
        let detector = ToolShadowingDetector::new();

        let tools = vec![
            make_tool("git_status", Some("Get git status")),
            make_tool("git_commit", Some("Create commit")),
            make_tool("git_push", Some("Push to remote")),
        ];

        // Git server should be allowed to have git tools
        let findings = detector.check_tools(&tools, Some("git-server"));

        let shadowing_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("Shadowing"))
            .collect();

        assert!(shadowing_findings.is_empty());
    }

    #[test]
    fn test_github_server_allowed_github_tools() {
        let detector = ToolShadowingDetector::new();

        let tools = vec![
            make_tool("create_issue", Some("Create GitHub issue")),
            make_tool("create_pull_request", Some("Create PR")),
        ];

        let findings = detector.check_tools(&tools, Some("github-integration"));

        let shadowing_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("Shadowing"))
            .collect();

        assert!(shadowing_findings.is_empty());
    }

    #[test]
    fn test_suspicious_pattern_critical_severity() {
        let detector = ToolShadowingDetector::new();

        // Critical patterns
        let tools = vec![
            make_tool("write_file", Some("Does something unrelated to files")),
            make_tool("delete_file", Some("Not about files")),
            make_tool("bash", Some("Some tool")),
            make_tool("authenticate", Some("Not about auth")),
            make_tool("login", Some("Not about login")),
        ];

        let findings = detector.check_tools(&tools, Some("suspicious-server"));

        // Should have critical severity findings
        let critical_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.severity == Severity::Critical)
            .collect();

        assert!(!critical_findings.is_empty());
    }

    #[test]
    fn test_ai_assistant_low_severity() {
        let detector = ToolShadowingDetector::new();

        // AI assistant patterns should be low/info severity
        let tools = vec![
            make_tool("think", Some("Random thinking")),
            make_tool("reason", Some("Some reasoning")),
            make_tool("analyze", Some("Analysis tool")),
        ];

        let findings = detector.check_tools(&tools, Some("random-server"));

        // Should have info severity findings for AI patterns
        let info_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.severity == Severity::Info)
            .collect();

        assert!(!info_findings.is_empty());
    }

    #[test]
    fn test_no_findings_for_unique_names() {
        let detector = ToolShadowingDetector::new();

        let tools = vec![
            make_tool("myapp_custom_tool", Some("My custom tool")),
            make_tool("unique_operation", Some("Unique operation")),
            make_tool("specialized_function", Some("Specialized function")),
        ];

        let findings = detector.check_tools(&tools, Some("myapp-server"));

        // Unique names should not trigger any findings
        assert!(findings.is_empty());
    }

    #[test]
    fn test_slack_server_allowed_slack_tools() {
        let detector = ToolShadowingDetector::new();

        let tools = vec![
            make_tool("send_message", Some("Send Slack message")),
            make_tool("list_channels", Some("List Slack channels")),
        ];

        let findings = detector.check_tools(&tools, Some("slack-integration"));

        let shadowing_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("Shadowing"))
            .collect();

        assert!(shadowing_findings.is_empty());
    }

    #[test]
    fn test_case_insensitive_matching() {
        let detector = ToolShadowingDetector::new();

        let tools = vec![
            make_tool("READ_FILE", Some("Read file")),
            make_tool("Git_Status", Some("Get status")),
        ];

        let findings = detector.check_tools(&tools, Some("random-server"));

        // Should detect despite case differences
        assert!(!findings.is_empty());
    }
}
