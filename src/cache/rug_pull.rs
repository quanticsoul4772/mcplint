//! Rug-Pull Detection - Detect changes in tool definitions
//!
//! Monitors tool definitions across scans to detect unexpected
//! changes that could indicate malicious behavior ("rug pulls").

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

use crate::protocol::mcp::Tool;

/// Record of tool hashes for a server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolHashRecord {
    /// Server identifier
    pub server_id: String,
    /// When this record was created
    pub created_at: DateTime<Utc>,
    /// When this record was last updated
    pub updated_at: DateTime<Utc>,
    /// Hash of the overall tool configuration
    pub config_hash: String,
    /// Individual tool hashes for comparison
    pub tool_hashes: HashMap<String, ToolHash>,
    /// Number of times this configuration has been seen
    pub seen_count: u64,
}

/// Hash information for a single tool
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolHash {
    /// Tool name
    pub name: String,
    /// Hash of tool description
    pub description_hash: String,
    /// Hash of input schema
    pub schema_hash: String,
    /// Combined hash
    pub combined_hash: String,
}

impl ToolHash {
    /// Create a hash record from a tool
    pub fn from_tool(tool: &Tool) -> Self {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut desc_hasher = DefaultHasher::new();
        tool.description.hash(&mut desc_hasher);
        let description_hash = format!("{:016x}", desc_hasher.finish());

        let mut schema_hasher = DefaultHasher::new();
        tool.input_schema.to_string().hash(&mut schema_hasher);
        let schema_hash = format!("{:016x}", schema_hasher.finish());

        let mut combined_hasher = DefaultHasher::new();
        tool.name.hash(&mut combined_hasher);
        tool.description.hash(&mut combined_hasher);
        tool.input_schema.to_string().hash(&mut combined_hasher);
        let combined_hash = format!("{:016x}", combined_hasher.finish());

        Self {
            name: tool.name.clone(),
            description_hash,
            schema_hash,
            combined_hash,
        }
    }
}

impl ToolHashRecord {
    /// Create a new record from a list of tools
    pub fn from_tools(server_id: &str, tools: &[Tool]) -> Self {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let now = Utc::now();
        let mut tool_hashes = HashMap::new();

        // Create individual tool hashes
        for tool in tools {
            let hash = ToolHash::from_tool(tool);
            tool_hashes.insert(tool.name.clone(), hash);
        }

        // Create overall config hash
        let mut config_hasher = DefaultHasher::new();
        let mut sorted_names: Vec<_> = tool_hashes.keys().collect();
        sorted_names.sort();
        for name in sorted_names {
            name.hash(&mut config_hasher);
            tool_hashes[name].combined_hash.hash(&mut config_hasher);
        }
        let config_hash = format!("{:016x}", config_hasher.finish());

        Self {
            server_id: server_id.to_string(),
            created_at: now,
            updated_at: now,
            config_hash,
            tool_hashes,
            seen_count: 1,
        }
    }

    /// Update the seen count and timestamp
    pub fn mark_seen(&mut self) {
        self.seen_count += 1;
        self.updated_at = Utc::now();
    }
}

/// Result of rug-pull detection comparison
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RugPullDetection {
    /// Server identifier
    pub server_id: String,
    /// Tools that were added
    pub added: Vec<String>,
    /// Tools that were removed
    pub removed: Vec<String>,
    /// Tools with modified definitions
    pub modified: Vec<ToolModification>,
    /// Severity assessment
    pub severity: RugPullSeverity,
    /// Human-readable summary
    pub summary: String,
    /// Previous config hash
    pub previous_hash: String,
    /// Current config hash
    pub current_hash: String,
    /// When the previous record was created
    pub previous_seen: DateTime<Utc>,
}

/// Details of a modified tool
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolModification {
    /// Tool name
    pub name: String,
    /// Whether description changed
    pub description_changed: bool,
    /// Whether schema changed
    pub schema_changed: bool,
    /// Previous hash
    pub previous_hash: String,
    /// Current hash
    pub current_hash: String,
}

/// Severity of detected changes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RugPullSeverity {
    /// Informational changes (metadata only)
    Info,
    /// Low severity (minor additions)
    Low,
    /// Medium severity (significant changes)
    Medium,
    /// High severity (suspicious changes)
    High,
    /// Critical severity (likely malicious)
    Critical,
}

impl std::fmt::Display for RugPullSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RugPullSeverity::Info => write!(f, "info"),
            RugPullSeverity::Low => write!(f, "low"),
            RugPullSeverity::Medium => write!(f, "medium"),
            RugPullSeverity::High => write!(f, "high"),
            RugPullSeverity::Critical => write!(f, "critical"),
        }
    }
}

/// Compare tool configurations and detect changes
pub fn detect_rug_pull(
    server_id: &str,
    previous: &ToolHashRecord,
    current_tools: &[Tool],
) -> Option<RugPullDetection> {
    let current = ToolHashRecord::from_tools(server_id, current_tools);

    // Quick check - if hashes match, no changes
    if previous.config_hash == current.config_hash {
        return None;
    }

    let previous_names: HashSet<_> = previous.tool_hashes.keys().collect();
    let current_names: HashSet<_> = current.tool_hashes.keys().collect();

    // Find added tools
    let added: Vec<String> = current_names
        .difference(&previous_names)
        .map(|s| (*s).clone())
        .collect();

    // Find removed tools
    let removed: Vec<String> = previous_names
        .difference(&current_names)
        .map(|s| (*s).clone())
        .collect();

    // Find modified tools
    let mut modified = Vec::new();
    for name in previous_names.intersection(&current_names) {
        let prev_hash = &previous.tool_hashes[*name];
        let curr_hash = &current.tool_hashes[*name];

        if prev_hash.combined_hash != curr_hash.combined_hash {
            modified.push(ToolModification {
                name: (*name).clone(),
                description_changed: prev_hash.description_hash != curr_hash.description_hash,
                schema_changed: prev_hash.schema_hash != curr_hash.schema_hash,
                previous_hash: prev_hash.combined_hash.clone(),
                current_hash: curr_hash.combined_hash.clone(),
            });
        }
    }

    // No changes detected
    if added.is_empty() && removed.is_empty() && modified.is_empty() {
        return None;
    }

    // Assess severity
    let severity = assess_severity(&added, &removed, &modified);

    // Generate summary
    let summary = generate_summary(&added, &removed, &modified);

    Some(RugPullDetection {
        server_id: server_id.to_string(),
        added,
        removed,
        modified,
        severity,
        summary,
        previous_hash: previous.config_hash.clone(),
        current_hash: current.config_hash,
        previous_seen: previous.updated_at,
    })
}

/// Assess the severity of detected changes
fn assess_severity(
    added: &[String],
    removed: &[String],
    modified: &[ToolModification],
) -> RugPullSeverity {
    // Critical: Tools removed or schemas changed significantly
    if !removed.is_empty() {
        return RugPullSeverity::High;
    }

    // Check for suspicious tool names in added tools
    let suspicious_names = [
        "exec", "shell", "system", "eval", "run", "execute", "command", "admin", "sudo", "root",
    ];

    for tool_name in added {
        let lower = tool_name.to_lowercase();
        for suspicious in &suspicious_names {
            if lower.contains(suspicious) {
                return RugPullSeverity::Critical;
            }
        }
    }

    // Schema changes are more concerning than description changes
    let schema_changes = modified.iter().filter(|m| m.schema_changed).count();

    if schema_changes > 0 {
        if schema_changes >= 3 {
            return RugPullSeverity::High;
        }
        return RugPullSeverity::Medium;
    }

    // Description-only changes
    if !modified.is_empty() {
        return RugPullSeverity::Low;
    }

    // Only additions
    if !added.is_empty() {
        if added.len() >= 5 {
            return RugPullSeverity::Medium;
        }
        return RugPullSeverity::Low;
    }

    RugPullSeverity::Info
}

/// Generate a human-readable summary
fn generate_summary(added: &[String], removed: &[String], modified: &[ToolModification]) -> String {
    let mut parts = Vec::new();

    if !added.is_empty() {
        parts.push(format!("{} tools added", added.len()));
    }

    if !removed.is_empty() {
        parts.push(format!("{} tools removed", removed.len()));
    }

    if !modified.is_empty() {
        let schema_changes = modified.iter().filter(|m| m.schema_changed).count();
        let desc_changes = modified.len() - schema_changes;

        if schema_changes > 0 {
            parts.push(format!("{} schema changes", schema_changes));
        }
        if desc_changes > 0 {
            parts.push(format!("{} description changes", desc_changes));
        }
    }

    if parts.is_empty() {
        "No changes detected".to_string()
    } else {
        format!("Tool changes detected: {}", parts.join(", "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_tool(name: &str, description: &str) -> Tool {
        Tool {
            name: name.to_string(),
            description: Some(description.to_string()),
            input_schema: json!({"type": "object"}),
        }
    }

    fn make_tool_with_schema(name: &str, description: &str, schema: serde_json::Value) -> Tool {
        Tool {
            name: name.to_string(),
            description: Some(description.to_string()),
            input_schema: schema,
        }
    }

    #[test]
    fn tool_hash_creation() {
        let tool = make_tool("test_tool", "A test tool");
        let hash = ToolHash::from_tool(&tool);

        assert_eq!(hash.name, "test_tool");
        assert!(!hash.description_hash.is_empty());
        assert!(!hash.schema_hash.is_empty());
        assert!(!hash.combined_hash.is_empty());
    }

    #[test]
    fn tool_hash_record_creation() {
        let tools = vec![
            make_tool("tool1", "First tool"),
            make_tool("tool2", "Second tool"),
        ];

        let record = ToolHashRecord::from_tools("test-server", &tools);

        assert_eq!(record.server_id, "test-server");
        assert_eq!(record.tool_hashes.len(), 2);
        assert!(record.tool_hashes.contains_key("tool1"));
        assert!(record.tool_hashes.contains_key("tool2"));
    }

    #[test]
    fn no_changes_detected() {
        let tools = vec![make_tool("tool1", "First tool")];
        let record = ToolHashRecord::from_tools("server", &tools);

        let detection = detect_rug_pull("server", &record, &tools);
        assert!(detection.is_none());
    }

    #[test]
    fn detect_added_tools() {
        let tools_v1 = vec![make_tool("tool1", "First tool")];
        let tools_v2 = vec![
            make_tool("tool1", "First tool"),
            make_tool("tool2", "New tool"),
        ];

        let record = ToolHashRecord::from_tools("server", &tools_v1);
        let detection = detect_rug_pull("server", &record, &tools_v2);

        assert!(detection.is_some());
        let d = detection.unwrap();
        assert_eq!(d.added, vec!["tool2".to_string()]);
        assert!(d.removed.is_empty());
    }

    #[test]
    fn detect_removed_tools() {
        let tools_v1 = vec![
            make_tool("tool1", "First tool"),
            make_tool("tool2", "Second tool"),
        ];
        let tools_v2 = vec![make_tool("tool1", "First tool")];

        let record = ToolHashRecord::from_tools("server", &tools_v1);
        let detection = detect_rug_pull("server", &record, &tools_v2);

        assert!(detection.is_some());
        let d = detection.unwrap();
        assert!(d.added.is_empty());
        assert_eq!(d.removed, vec!["tool2".to_string()]);
        assert_eq!(d.severity, RugPullSeverity::High);
    }

    #[test]
    fn detect_modified_tools() {
        let tools_v1 = vec![make_tool("tool1", "Original description")];
        let tools_v2 = vec![make_tool("tool1", "Changed description")];

        let record = ToolHashRecord::from_tools("server", &tools_v1);
        let detection = detect_rug_pull("server", &record, &tools_v2);

        assert!(detection.is_some());
        let d = detection.unwrap();
        assert_eq!(d.modified.len(), 1);
        assert!(d.modified[0].description_changed);
    }

    #[test]
    fn suspicious_tool_name_detection() {
        let tools_v1 = vec![make_tool("tool1", "Safe tool")];
        let tools_v2 = vec![
            make_tool("tool1", "Safe tool"),
            make_tool("execute_shell", "New suspicious tool"),
        ];

        let record = ToolHashRecord::from_tools("server", &tools_v1);
        let detection = detect_rug_pull("server", &record, &tools_v2);

        assert!(detection.is_some());
        let d = detection.unwrap();
        assert_eq!(d.severity, RugPullSeverity::Critical);
    }

    // New comprehensive tests

    #[test]
    fn tool_hash_consistency() {
        let tool = make_tool("test", "description");
        let hash1 = ToolHash::from_tool(&tool);
        let hash2 = ToolHash::from_tool(&tool);

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn tool_hash_different_description() {
        let tool1 = make_tool("test", "desc1");
        let tool2 = make_tool("test", "desc2");

        let hash1 = ToolHash::from_tool(&tool1);
        let hash2 = ToolHash::from_tool(&tool2);

        assert_ne!(hash1.description_hash, hash2.description_hash);
        assert_eq!(hash1.schema_hash, hash2.schema_hash);
        assert_ne!(hash1.combined_hash, hash2.combined_hash);
    }

    #[test]
    fn tool_hash_different_schema() {
        let tool1 = make_tool_with_schema("test", "desc", json!({"type": "object"}));
        let tool2 = make_tool_with_schema("test", "desc", json!({"type": "string"}));

        let hash1 = ToolHash::from_tool(&tool1);
        let hash2 = ToolHash::from_tool(&tool2);

        assert_eq!(hash1.description_hash, hash2.description_hash);
        assert_ne!(hash1.schema_hash, hash2.schema_hash);
        assert_ne!(hash1.combined_hash, hash2.combined_hash);
    }

    #[test]
    fn tool_hash_record_seen_count() {
        let tools = vec![make_tool("tool1", "First tool")];
        let record = ToolHashRecord::from_tools("server", &tools);

        assert_eq!(record.seen_count, 1);
    }

    #[test]
    fn tool_hash_record_mark_seen() {
        let tools = vec![make_tool("tool1", "First tool")];
        let mut record = ToolHashRecord::from_tools("server", &tools);

        let original_count = record.seen_count;
        let original_updated = record.updated_at;

        std::thread::sleep(std::time::Duration::from_millis(10));
        record.mark_seen();

        assert_eq!(record.seen_count, original_count + 1);
        assert!(record.updated_at > original_updated);
    }

    #[test]
    fn tool_hash_record_config_hash_consistency() {
        let tools = vec![make_tool("tool1", "First"), make_tool("tool2", "Second")];
        let record1 = ToolHashRecord::from_tools("server", &tools);
        let record2 = ToolHashRecord::from_tools("server", &tools);

        assert_eq!(record1.config_hash, record2.config_hash);
    }

    #[test]
    fn detect_schema_changes() {
        let tools_v1 = vec![make_tool_with_schema(
            "tool1",
            "desc",
            json!({"type": "object"}),
        )];
        let tools_v2 = vec![make_tool_with_schema(
            "tool1",
            "desc",
            json!({"type": "string"}),
        )];

        let record = ToolHashRecord::from_tools("server", &tools_v1);
        let detection = detect_rug_pull("server", &record, &tools_v2);

        assert!(detection.is_some());
        let d = detection.unwrap();
        assert_eq!(d.modified.len(), 1);
        assert!(d.modified[0].schema_changed);
        assert!(!d.modified[0].description_changed);
    }

    #[test]
    fn detect_both_description_and_schema_changes() {
        let tools_v1 = vec![make_tool_with_schema(
            "tool1",
            "old",
            json!({"type": "object"}),
        )];
        let tools_v2 = vec![make_tool_with_schema(
            "tool1",
            "new",
            json!({"type": "string"}),
        )];

        let record = ToolHashRecord::from_tools("server", &tools_v1);
        let detection = detect_rug_pull("server", &record, &tools_v2);

        assert!(detection.is_some());
        let d = detection.unwrap();
        assert_eq!(d.modified.len(), 1);
        assert!(d.modified[0].schema_changed);
        assert!(d.modified[0].description_changed);
    }

    #[test]
    fn severity_info_for_metadata_only() {
        // Info severity is the default fallback
        let severity = assess_severity(&[], &[], &[]);
        assert_eq!(severity, RugPullSeverity::Info);
    }

    #[test]
    fn severity_low_for_few_additions() {
        let added = vec!["tool1".to_string(), "tool2".to_string()];
        let severity = assess_severity(&added, &[], &[]);
        assert_eq!(severity, RugPullSeverity::Low);
    }

    #[test]
    fn severity_medium_for_many_additions() {
        let added = vec![
            "tool1".to_string(),
            "tool2".to_string(),
            "tool3".to_string(),
            "tool4".to_string(),
            "tool5".to_string(),
        ];
        let severity = assess_severity(&added, &[], &[]);
        assert_eq!(severity, RugPullSeverity::Medium);
    }

    #[test]
    fn severity_high_for_removals() {
        let removed = vec!["tool1".to_string()];
        let severity = assess_severity(&[], &removed, &[]);
        assert_eq!(severity, RugPullSeverity::High);
    }

    #[test]
    fn severity_low_for_description_only_changes() {
        let modified = vec![ToolModification {
            name: "tool1".to_string(),
            description_changed: true,
            schema_changed: false,
            previous_hash: "old".to_string(),
            current_hash: "new".to_string(),
        }];
        let severity = assess_severity(&[], &[], &modified);
        assert_eq!(severity, RugPullSeverity::Low);
    }

    #[test]
    fn severity_medium_for_single_schema_change() {
        let modified = vec![ToolModification {
            name: "tool1".to_string(),
            description_changed: false,
            schema_changed: true,
            previous_hash: "old".to_string(),
            current_hash: "new".to_string(),
        }];
        let severity = assess_severity(&[], &[], &modified);
        assert_eq!(severity, RugPullSeverity::Medium);
    }

    #[test]
    fn severity_high_for_multiple_schema_changes() {
        let modified = vec![
            ToolModification {
                name: "tool1".to_string(),
                description_changed: false,
                schema_changed: true,
                previous_hash: "old1".to_string(),
                current_hash: "new1".to_string(),
            },
            ToolModification {
                name: "tool2".to_string(),
                description_changed: false,
                schema_changed: true,
                previous_hash: "old2".to_string(),
                current_hash: "new2".to_string(),
            },
            ToolModification {
                name: "tool3".to_string(),
                description_changed: false,
                schema_changed: true,
                previous_hash: "old3".to_string(),
                current_hash: "new3".to_string(),
            },
        ];
        let severity = assess_severity(&[], &[], &modified);
        assert_eq!(severity, RugPullSeverity::High);
    }

    #[test]
    fn severity_critical_for_suspicious_names() {
        let suspicious_names = vec![
            "exec", "shell", "system", "eval", "run", "execute", "command", "admin", "sudo", "root",
        ];

        for name in suspicious_names {
            let added = vec![format!("tool_{}", name)];
            let severity = assess_severity(&added, &[], &[]);
            assert_eq!(
                severity,
                RugPullSeverity::Critical,
                "Expected critical for tool with name containing '{}'",
                name
            );
        }
    }

    #[test]
    fn summary_no_changes() {
        let summary = generate_summary(&[], &[], &[]);
        assert_eq!(summary, "No changes detected");
    }

    #[test]
    fn summary_additions_only() {
        let added = vec!["tool1".to_string(), "tool2".to_string()];
        let summary = generate_summary(&added, &[], &[]);
        assert!(summary.contains("2 tools added"));
    }

    #[test]
    fn summary_removals_only() {
        let removed = vec!["tool1".to_string()];
        let summary = generate_summary(&[], &removed, &[]);
        assert!(summary.contains("1 tools removed"));
    }

    #[test]
    fn summary_modifications_only() {
        let modified = vec![
            ToolModification {
                name: "tool1".to_string(),
                description_changed: true,
                schema_changed: false,
                previous_hash: "old".to_string(),
                current_hash: "new".to_string(),
            },
            ToolModification {
                name: "tool2".to_string(),
                description_changed: false,
                schema_changed: true,
                previous_hash: "old".to_string(),
                current_hash: "new".to_string(),
            },
        ];
        let summary = generate_summary(&[], &[], &modified);
        assert!(summary.contains("1 schema changes"));
        assert!(summary.contains("1 description changes"));
    }

    #[test]
    fn summary_combined_changes() {
        let added = vec!["tool3".to_string()];
        let removed = vec!["tool1".to_string()];
        let modified = vec![ToolModification {
            name: "tool2".to_string(),
            description_changed: true,
            schema_changed: true,
            previous_hash: "old".to_string(),
            current_hash: "new".to_string(),
        }];
        let summary = generate_summary(&added, &removed, &modified);

        assert!(summary.contains("1 tools added"));
        assert!(summary.contains("1 tools removed"));
        assert!(summary.contains("1 schema changes"));
    }

    #[test]
    fn rug_pull_severity_display() {
        assert_eq!(RugPullSeverity::Info.to_string(), "info");
        assert_eq!(RugPullSeverity::Low.to_string(), "low");
        assert_eq!(RugPullSeverity::Medium.to_string(), "medium");
        assert_eq!(RugPullSeverity::High.to_string(), "high");
        assert_eq!(RugPullSeverity::Critical.to_string(), "critical");
    }

    #[test]
    fn rug_pull_detection_includes_timestamps() {
        let tools_v1 = vec![make_tool("tool1", "First tool")];
        let tools_v2 = vec![
            make_tool("tool1", "First tool"),
            make_tool("tool2", "New tool"),
        ];

        let record = ToolHashRecord::from_tools("server", &tools_v1);
        let detection = detect_rug_pull("server", &record, &tools_v2).unwrap();

        assert_eq!(detection.previous_seen, record.updated_at);
        assert_ne!(detection.previous_hash, detection.current_hash);
    }

    #[test]
    fn rug_pull_detection_includes_server_id() {
        let tools_v1 = vec![make_tool("tool1", "First tool")];
        let tools_v2 = vec![make_tool("tool1", "Changed tool")];

        let record = ToolHashRecord::from_tools("my-server", &tools_v1);
        let detection = detect_rug_pull("my-server", &record, &tools_v2).unwrap();

        assert_eq!(detection.server_id, "my-server");
    }

    #[test]
    fn detect_multiple_tools_added_and_removed() {
        let tools_v1 = vec![
            make_tool("tool1", "First"),
            make_tool("tool2", "Second"),
            make_tool("tool3", "Third"),
        ];
        let tools_v2 = vec![
            make_tool("tool1", "First"),
            make_tool("tool4", "Fourth"),
            make_tool("tool5", "Fifth"),
        ];

        let record = ToolHashRecord::from_tools("server", &tools_v1);
        let detection = detect_rug_pull("server", &record, &tools_v2).unwrap();

        assert_eq!(detection.added.len(), 2);
        assert_eq!(detection.removed.len(), 2);
        assert!(detection.added.contains(&"tool4".to_string()));
        assert!(detection.added.contains(&"tool5".to_string()));
        assert!(detection.removed.contains(&"tool2".to_string()));
        assert!(detection.removed.contains(&"tool3".to_string()));
    }

    #[test]
    fn tool_modification_tracks_hash_changes() {
        let tools_v1 = vec![make_tool("tool1", "Old description")];
        let tools_v2 = vec![make_tool("tool1", "New description")];

        let record = ToolHashRecord::from_tools("server", &tools_v1);
        let detection = detect_rug_pull("server", &record, &tools_v2).unwrap();

        assert_eq!(detection.modified.len(), 1);
        assert_ne!(
            detection.modified[0].previous_hash,
            detection.modified[0].current_hash
        );
    }

    #[test]
    fn empty_tools_list_detected() {
        let tools_v1 = vec![make_tool("tool1", "First")];
        let tools_v2 = vec![];

        let record = ToolHashRecord::from_tools("server", &tools_v1);
        let detection = detect_rug_pull("server", &record, &tools_v2).unwrap();

        assert_eq!(detection.removed.len(), 1);
        assert_eq!(detection.severity, RugPullSeverity::High);
    }

    #[test]
    fn case_sensitive_suspicious_names() {
        let added = vec!["EXECUTE_COMMAND".to_string()];
        let severity = assess_severity(&added, &[], &[]);
        assert_eq!(severity, RugPullSeverity::Critical);
    }
}
