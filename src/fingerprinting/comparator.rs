//! Fingerprint Comparator
//!
//! Compares tool fingerprints and generates detailed diff reports
//! with severity analysis and actionable recommendations.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use super::types::ToolFingerprint;

/// Types of changes detected between fingerprints
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ChangeType {
    /// A new parameter was added
    ParameterAdded {
        name: String,
        param_type: String,
        required: bool,
    },

    /// An existing parameter was removed
    ParameterRemoved {
        name: String,
        param_type: String,
        required: bool,
    },

    /// A parameter's type changed
    TypeChanged {
        param: String,
        old_type: String,
        new_type: String,
    },

    /// A parameter's required status changed
    RequiredChanged { param: String, now_required: bool },

    /// A constraint was added to a parameter
    ConstraintAdded {
        param: String,
        constraint: String,
        value: String,
    },

    /// A constraint was removed from a parameter
    ConstraintRemoved {
        param: String,
        constraint: String,
        value: String,
    },

    /// A constraint value changed
    ConstraintChanged {
        param: String,
        constraint: String,
        old_value: String,
        new_value: String,
    },

    /// The tool description changed
    DescriptionChanged { old: String, new: String },

    /// A new tool was added
    ToolAdded { tool_name: String },

    /// A tool was removed
    ToolRemoved { tool_name: String },

    /// Schema structure changed significantly
    SchemaStructureChanged { detail: String },
}

impl ChangeType {
    /// Get a human-readable description of the change
    #[allow(dead_code)]
    pub fn description(&self) -> String {
        match self {
            ChangeType::ParameterAdded { name, required, .. } => {
                let req = if *required { "required " } else { "optional " };
                format!("Added {} parameter '{}'", req, name)
            }
            ChangeType::ParameterRemoved { name, required, .. } => {
                let req = if *required { "required " } else { "optional " };
                format!("Removed {} parameter '{}'", req, name)
            }
            ChangeType::TypeChanged {
                param,
                old_type,
                new_type,
            } => {
                format!(
                    "Type of '{}' changed from '{}' to '{}'",
                    param, old_type, new_type
                )
            }
            ChangeType::RequiredChanged {
                param,
                now_required,
            } => {
                if *now_required {
                    format!("Parameter '{}' is now required", param)
                } else {
                    format!("Parameter '{}' is now optional", param)
                }
            }
            ChangeType::ConstraintAdded {
                param,
                constraint,
                value,
            } => {
                format!(
                    "Added constraint '{}={}' to parameter '{}'",
                    constraint, value, param
                )
            }
            ChangeType::ConstraintRemoved {
                param,
                constraint,
                value,
            } => {
                format!(
                    "Removed constraint '{}={}' from parameter '{}'",
                    constraint, value, param
                )
            }
            ChangeType::ConstraintChanged {
                param,
                constraint,
                old_value,
                new_value,
            } => {
                format!(
                    "Constraint '{}' on '{}' changed from '{}' to '{}'",
                    constraint, param, old_value, new_value
                )
            }
            ChangeType::DescriptionChanged { .. } => "Tool description changed".to_string(),
            ChangeType::ToolAdded { tool_name } => format!("New tool '{}' added", tool_name),
            ChangeType::ToolRemoved { tool_name } => format!("Tool '{}' removed", tool_name),
            ChangeType::SchemaStructureChanged { detail } => {
                format!("Schema structure changed: {}", detail)
            }
        }
    }

    /// Check if this is a breaking change
    #[allow(dead_code)]
    pub fn is_breaking(&self) -> bool {
        matches!(
            self,
            ChangeType::ParameterRemoved { required: true, .. }
                | ChangeType::TypeChanged { .. }
                | ChangeType::RequiredChanged {
                    now_required: true,
                    ..
                }
                | ChangeType::ToolRemoved { .. }
        )
    }
}

/// Severity level of changes
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChangeSeverity {
    /// No changes detected
    None,

    /// Description or metadata only changes
    Patch,

    /// New optional parameters or relaxed constraints
    Minor,

    /// New required parameters or tightened constraints
    Major,

    /// Removed required parameters, type incompatibilities
    Breaking,
}

impl ChangeSeverity {
    /// Get a display string for the severity
    #[allow(dead_code)]
    pub fn as_str(&self) -> &'static str {
        match self {
            ChangeSeverity::None => "none",
            ChangeSeverity::Patch => "patch",
            ChangeSeverity::Minor => "minor",
            ChangeSeverity::Major => "major",
            ChangeSeverity::Breaking => "breaking",
        }
    }

    /// Get a colored indicator for terminal output
    #[allow(dead_code)]
    pub fn indicator(&self) -> &'static str {
        match self {
            ChangeSeverity::None => "✓",
            ChangeSeverity::Patch => "~",
            ChangeSeverity::Minor => "+",
            ChangeSeverity::Major => "!",
            ChangeSeverity::Breaking => "✗",
        }
    }

    /// Parse from string
    #[allow(dead_code)]
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "none" => Some(ChangeSeverity::None),
            "patch" => Some(ChangeSeverity::Patch),
            "minor" => Some(ChangeSeverity::Minor),
            "major" => Some(ChangeSeverity::Major),
            "breaking" => Some(ChangeSeverity::Breaking),
            _ => None,
        }
    }
}

impl std::fmt::Display for ChangeSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Result of comparing two fingerprints
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintDiff {
    /// Tool name
    pub tool_name: String,

    /// Old semantic hash (empty if tool is new)
    pub old_semantic_hash: String,

    /// New semantic hash (empty if tool was removed)
    pub new_semantic_hash: String,

    /// Old full hash
    pub old_full_hash: String,

    /// New full hash
    pub new_full_hash: String,

    /// List of detected changes
    pub changes: Vec<ChangeType>,

    /// Overall severity of changes
    pub severity: ChangeSeverity,

    /// Human-readable summary
    pub summary: String,

    /// Actionable recommendations
    pub recommendations: Vec<String>,
}

impl FingerprintDiff {
    /// Create a new diff for unchanged tool
    #[allow(dead_code)]
    fn unchanged(fingerprint: &ToolFingerprint) -> Self {
        Self {
            tool_name: fingerprint.tool_name.clone(),
            old_semantic_hash: fingerprint.semantic_hash.clone(),
            new_semantic_hash: fingerprint.semantic_hash.clone(),
            old_full_hash: fingerprint.full_hash.clone(),
            new_full_hash: fingerprint.full_hash.clone(),
            changes: vec![],
            severity: ChangeSeverity::None,
            summary: "No changes detected".to_string(),
            recommendations: vec![],
        }
    }

    /// Create a diff for a new tool
    #[allow(dead_code)]
    fn new_tool(fingerprint: &ToolFingerprint) -> Self {
        Self {
            tool_name: fingerprint.tool_name.clone(),
            old_semantic_hash: String::new(),
            new_semantic_hash: fingerprint.semantic_hash.clone(),
            old_full_hash: String::new(),
            new_full_hash: fingerprint.full_hash.clone(),
            changes: vec![ChangeType::ToolAdded {
                tool_name: fingerprint.tool_name.clone(),
            }],
            severity: ChangeSeverity::Minor,
            summary: format!("New tool '{}' added", fingerprint.tool_name),
            recommendations: vec![
                "Review the new tool's capabilities and permissions".to_string(),
                "Update documentation to include the new tool".to_string(),
            ],
        }
    }

    /// Create a diff for a removed tool
    #[allow(dead_code)]
    fn removed_tool(fingerprint: &ToolFingerprint) -> Self {
        Self {
            tool_name: fingerprint.tool_name.clone(),
            old_semantic_hash: fingerprint.semantic_hash.clone(),
            new_semantic_hash: String::new(),
            old_full_hash: fingerprint.full_hash.clone(),
            new_full_hash: String::new(),
            changes: vec![ChangeType::ToolRemoved {
                tool_name: fingerprint.tool_name.clone(),
            }],
            severity: ChangeSeverity::Breaking,
            summary: format!("Tool '{}' was removed", fingerprint.tool_name),
            recommendations: vec![
                "Update clients that depend on this tool".to_string(),
                "Consider providing a migration path or deprecation notice".to_string(),
            ],
        }
    }

    /// Check if there are any changes
    #[allow(dead_code)]
    pub fn has_changes(&self) -> bool {
        !self.changes.is_empty()
    }

    /// Check if changes are breaking
    #[allow(dead_code)]
    pub fn is_breaking(&self) -> bool {
        self.severity == ChangeSeverity::Breaking
    }

    /// Get count of changes by type
    #[allow(dead_code)]
    pub fn change_count(&self) -> usize {
        self.changes.len()
    }
}

/// Compares fingerprints and generates diff reports
#[allow(dead_code)]
pub struct FingerprintComparator;

impl FingerprintComparator {
    /// Compare two individual fingerprints
    #[allow(dead_code)]
    pub fn compare(old: &ToolFingerprint, new: &ToolFingerprint) -> FingerprintDiff {
        // Quick check: if semantic hashes match, there are no semantic changes
        if old.semantic_hash == new.semantic_hash {
            if old.full_hash == new.full_hash {
                return FingerprintDiff::unchanged(old);
            } else {
                // Only non-semantic changes (like description)
                return Self::build_patch_diff(old, new);
            }
        }

        // Detailed comparison needed
        Self::build_semantic_diff(old, new)
    }

    /// Analyze severity of a set of changes
    #[allow(dead_code)]
    pub fn analyze_severity(changes: &[ChangeType]) -> ChangeSeverity {
        if changes.is_empty() {
            return ChangeSeverity::None;
        }

        let mut max_severity = ChangeSeverity::None;

        for change in changes {
            let severity = match change {
                // Breaking changes
                ChangeType::ParameterRemoved { required: true, .. } => ChangeSeverity::Breaking,
                ChangeType::TypeChanged { .. } => ChangeSeverity::Breaking,
                ChangeType::ToolRemoved { .. } => ChangeSeverity::Breaking,
                ChangeType::RequiredChanged {
                    now_required: true, ..
                } => ChangeSeverity::Major,

                // Major changes
                ChangeType::ParameterAdded { required: true, .. } => ChangeSeverity::Major,
                ChangeType::ConstraintAdded { .. } => ChangeSeverity::Major,
                ChangeType::ConstraintChanged { .. } => ChangeSeverity::Major,
                ChangeType::SchemaStructureChanged { .. } => ChangeSeverity::Major,

                // Minor changes
                ChangeType::ParameterAdded {
                    required: false, ..
                } => ChangeSeverity::Minor,
                ChangeType::ParameterRemoved {
                    required: false, ..
                } => ChangeSeverity::Minor,
                ChangeType::RequiredChanged {
                    now_required: false,
                    ..
                } => ChangeSeverity::Minor,
                ChangeType::ConstraintRemoved { .. } => ChangeSeverity::Minor,
                ChangeType::ToolAdded { .. } => ChangeSeverity::Minor,

                // Patch changes
                ChangeType::DescriptionChanged { .. } => ChangeSeverity::Patch,
            };

            if severity > max_severity {
                max_severity = severity;
            }
        }

        max_severity
    }

    /// Build a diff for patch-level changes (non-semantic)
    fn build_patch_diff(old: &ToolFingerprint, new: &ToolFingerprint) -> FingerprintDiff {
        FingerprintDiff {
            tool_name: old.tool_name.clone(),
            old_semantic_hash: old.semantic_hash.clone(),
            new_semantic_hash: new.semantic_hash.clone(),
            old_full_hash: old.full_hash.clone(),
            new_full_hash: new.full_hash.clone(),
            changes: vec![ChangeType::DescriptionChanged {
                old: "".to_string(), // We don't store original descriptions
                new: "".to_string(),
            }],
            severity: ChangeSeverity::Patch,
            summary: "Description or metadata changed (no semantic impact)".to_string(),
            recommendations: vec![
                "Review description changes for accuracy".to_string(),
                "Update documentation if needed".to_string(),
            ],
        }
    }

    /// Build a diff for semantic changes
    fn build_semantic_diff(old: &ToolFingerprint, new: &ToolFingerprint) -> FingerprintDiff {
        let mut changes = Vec::new();

        // Compare parameters
        let old_params: HashSet<_> = old.metadata.param_types.keys().collect();
        let new_params: HashSet<_> = new.metadata.param_types.keys().collect();

        // Added parameters
        for param in new_params.difference(&old_params) {
            let param_type = new
                .metadata
                .param_types
                .get(*param)
                .cloned()
                .unwrap_or_default();
            let required = new.metadata.required_params.contains(*param);

            changes.push(ChangeType::ParameterAdded {
                name: (*param).clone(),
                param_type,
                required,
            });
        }

        // Removed parameters
        for param in old_params.difference(&new_params) {
            let param_type = old
                .metadata
                .param_types
                .get(*param)
                .cloned()
                .unwrap_or_default();
            let required = old.metadata.required_params.contains(*param);

            changes.push(ChangeType::ParameterRemoved {
                name: (*param).clone(),
                param_type,
                required,
            });
        }

        // Check for type changes in common parameters
        for param in old_params.intersection(&new_params) {
            let old_type = old.metadata.param_types.get(*param);
            let new_type = new.metadata.param_types.get(*param);

            if old_type != new_type {
                changes.push(ChangeType::TypeChanged {
                    param: (*param).clone(),
                    old_type: old_type.cloned().unwrap_or_default(),
                    new_type: new_type.cloned().unwrap_or_default(),
                });
            }
        }

        // Check for required status changes
        let old_required: HashSet<_> = old.metadata.required_params.iter().collect();
        let new_required: HashSet<_> = new.metadata.required_params.iter().collect();

        for param in new_required.difference(&old_required) {
            if old_params.contains(*param) {
                changes.push(ChangeType::RequiredChanged {
                    param: (*param).clone(),
                    now_required: true,
                });
            }
        }

        for param in old_required.difference(&new_required) {
            if new_params.contains(*param) {
                changes.push(ChangeType::RequiredChanged {
                    param: (*param).clone(),
                    now_required: false,
                });
            }
        }

        let severity = Self::analyze_severity(&changes);
        let summary = Self::generate_summary(&changes, severity);
        let recommendations = Self::generate_recommendations(&changes, severity);

        FingerprintDiff {
            tool_name: old.tool_name.clone(),
            old_semantic_hash: old.semantic_hash.clone(),
            new_semantic_hash: new.semantic_hash.clone(),
            old_full_hash: old.full_hash.clone(),
            new_full_hash: new.full_hash.clone(),
            changes,
            severity,
            summary,
            recommendations,
        }
    }

    /// Generate a human-readable summary
    fn generate_summary(changes: &[ChangeType], severity: ChangeSeverity) -> String {
        if changes.is_empty() {
            return "No changes detected".to_string();
        }

        let change_count = changes.len();
        let breaking_count = changes.iter().filter(|c| c.is_breaking()).count();

        if breaking_count > 0 {
            format!(
                "{} change(s) detected ({} breaking) - {} severity",
                change_count, breaking_count, severity
            )
        } else {
            format!(
                "{} change(s) detected - {} severity",
                change_count, severity
            )
        }
    }

    /// Generate actionable recommendations
    fn generate_recommendations(changes: &[ChangeType], severity: ChangeSeverity) -> Vec<String> {
        let mut recommendations = Vec::new();

        match severity {
            ChangeSeverity::Breaking => {
                recommendations.push(
                    "CRITICAL: This is a breaking change. Update all clients before deploying."
                        .to_string(),
                );
                recommendations.push(
                    "Consider versioning your API or providing a migration period.".to_string(),
                );
            }
            ChangeSeverity::Major => {
                recommendations.push(
                    "This change may require client updates. Review compatibility.".to_string(),
                );
            }
            ChangeSeverity::Minor => {
                recommendations.push("New features added. Update documentation.".to_string());
            }
            ChangeSeverity::Patch => {
                recommendations
                    .push("Documentation changes only. Review for accuracy.".to_string());
            }
            ChangeSeverity::None => {}
        }

        // Add specific recommendations based on change types
        for change in changes {
            match change {
                ChangeType::ParameterRemoved {
                    name,
                    required: true,
                    ..
                } => {
                    recommendations.push(format!(
                        "Required parameter '{}' was removed. Clients using this will break.",
                        name
                    ));
                }
                ChangeType::TypeChanged {
                    param,
                    old_type,
                    new_type,
                } => {
                    recommendations.push(format!(
                        "Type of '{}' changed from '{}' to '{}'. Verify data compatibility.",
                        param, old_type, new_type
                    ));
                }
                ChangeType::RequiredChanged {
                    param,
                    now_required: true,
                } => {
                    recommendations.push(format!(
                        "Parameter '{}' is now required. Ensure all clients provide this value.",
                        param
                    ));
                }
                _ => {}
            }
        }

        recommendations
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fingerprinting::types::FingerprintMetadata;
    use std::collections::HashMap;

    fn create_fingerprint(
        name: &str,
        semantic: &str,
        full: &str,
        params: &[(&str, &str)],
        required: &[&str],
    ) -> ToolFingerprint {
        let mut param_types = HashMap::new();
        for (k, v) in params {
            param_types.insert(k.to_string(), v.to_string());
        }

        let metadata = FingerprintMetadata {
            parameter_count: params.len(),
            required_params: required.iter().map(|s| s.to_string()).collect(),
            param_types,
            complexity_score: 0,
        };

        ToolFingerprint::new(name, semantic, full).with_metadata(metadata)
    }

    #[test]
    fn test_unchanged_fingerprints() {
        let fp = create_fingerprint("tool", "hash1", "hash2", &[("a", "string")], &["a"]);

        let diff = FingerprintComparator::compare(&fp, &fp);

        assert_eq!(diff.severity, ChangeSeverity::None);
        assert!(!diff.has_changes());
    }

    #[test]
    fn test_patch_level_change() {
        let fp1 = create_fingerprint("tool", "semantic", "full1", &[("a", "string")], &[]);
        let fp2 = create_fingerprint("tool", "semantic", "full2", &[("a", "string")], &[]);

        let diff = FingerprintComparator::compare(&fp1, &fp2);

        assert_eq!(diff.severity, ChangeSeverity::Patch);
        assert!(diff.has_changes());
    }

    #[test]
    fn test_parameter_added_optional() {
        let fp1 = create_fingerprint("tool", "hash1", "full1", &[("a", "string")], &[]);
        let fp2 = create_fingerprint(
            "tool",
            "hash2",
            "full2",
            &[("a", "string"), ("b", "number")],
            &[],
        );

        let diff = FingerprintComparator::compare(&fp1, &fp2);

        assert_eq!(diff.severity, ChangeSeverity::Minor);
        assert!(diff.changes.iter().any(|c| matches!(
            c,
            ChangeType::ParameterAdded { name, required: false, .. } if name == "b"
        )));
    }

    #[test]
    fn test_parameter_added_required() {
        let fp1 = create_fingerprint("tool", "hash1", "full1", &[("a", "string")], &["a"]);
        let fp2 = create_fingerprint(
            "tool",
            "hash2",
            "full2",
            &[("a", "string"), ("b", "number")],
            &["a", "b"],
        );

        let diff = FingerprintComparator::compare(&fp1, &fp2);

        assert_eq!(diff.severity, ChangeSeverity::Major);
        assert!(diff.changes.iter().any(|c| matches!(
            c,
            ChangeType::ParameterAdded { name, required: true, .. } if name == "b"
        )));
    }

    #[test]
    fn test_parameter_removed_required() {
        let fp1 = create_fingerprint(
            "tool",
            "hash1",
            "full1",
            &[("a", "string"), ("b", "number")],
            &["a", "b"],
        );
        let fp2 = create_fingerprint("tool", "hash2", "full2", &[("a", "string")], &["a"]);

        let diff = FingerprintComparator::compare(&fp1, &fp2);

        assert_eq!(diff.severity, ChangeSeverity::Breaking);
        assert!(diff.is_breaking());
        assert!(diff.changes.iter().any(|c| matches!(
            c,
            ChangeType::ParameterRemoved { name, required: true, .. } if name == "b"
        )));
    }

    #[test]
    fn test_type_changed() {
        let fp1 = create_fingerprint("tool", "hash1", "full1", &[("count", "string")], &[]);
        let fp2 = create_fingerprint("tool", "hash2", "full2", &[("count", "number")], &[]);

        let diff = FingerprintComparator::compare(&fp1, &fp2);

        assert_eq!(diff.severity, ChangeSeverity::Breaking);
        assert!(diff.changes.iter().any(|c| matches!(
            c,
            ChangeType::TypeChanged { param, old_type, new_type }
                if param == "count" && old_type == "string" && new_type == "number"
        )));
    }

    #[test]
    fn test_required_changed() {
        let fp1 = create_fingerprint("tool", "hash1", "full1", &[("a", "string")], &[]);
        let fp2 = create_fingerprint("tool", "hash2", "full2", &[("a", "string")], &["a"]);

        let diff = FingerprintComparator::compare(&fp1, &fp2);

        assert_eq!(diff.severity, ChangeSeverity::Major);
        assert!(diff.changes.iter().any(|c| matches!(
            c,
            ChangeType::RequiredChanged { param, now_required: true } if param == "a"
        )));
    }

    #[test]
    fn test_severity_analysis() {
        let changes = vec![ChangeType::ParameterAdded {
            name: "x".to_string(),
            param_type: "string".to_string(),
            required: false,
        }];

        assert_eq!(
            FingerprintComparator::analyze_severity(&changes),
            ChangeSeverity::Minor
        );

        let changes = vec![ChangeType::ParameterRemoved {
            name: "x".to_string(),
            param_type: "string".to_string(),
            required: true,
        }];

        assert_eq!(
            FingerprintComparator::analyze_severity(&changes),
            ChangeSeverity::Breaking
        );
    }

    #[test]
    fn test_change_type_description() {
        let change = ChangeType::ParameterAdded {
            name: "query".to_string(),
            param_type: "string".to_string(),
            required: true,
        };

        assert!(change.description().contains("query"));
        assert!(change.description().contains("required"));
    }

    #[test]
    fn test_severity_display() {
        assert_eq!(ChangeSeverity::Breaking.as_str(), "breaking");
        assert_eq!(format!("{}", ChangeSeverity::Major), "major");
    }

    #[test]
    fn test_severity_ordering() {
        assert!(ChangeSeverity::Breaking > ChangeSeverity::Major);
        assert!(ChangeSeverity::Major > ChangeSeverity::Minor);
        assert!(ChangeSeverity::Minor > ChangeSeverity::Patch);
        assert!(ChangeSeverity::Patch > ChangeSeverity::None);
    }

    #[test]
    fn test_severity_parse() {
        assert_eq!(
            ChangeSeverity::parse("breaking"),
            Some(ChangeSeverity::Breaking)
        );
        assert_eq!(ChangeSeverity::parse("MAJOR"), Some(ChangeSeverity::Major));
        assert_eq!(ChangeSeverity::parse("invalid"), None);
    }

    #[test]
    fn test_recommendations_generated() {
        let fp1 = create_fingerprint(
            "tool",
            "hash1",
            "full1",
            &[("a", "string"), ("b", "number")],
            &["a", "b"],
        );
        let fp2 = create_fingerprint("tool", "hash2", "full2", &[("a", "string")], &["a"]);

        let diff = FingerprintComparator::compare(&fp1, &fp2);

        assert!(!diff.recommendations.is_empty());
        assert!(diff
            .recommendations
            .iter()
            .any(|r| r.to_lowercase().contains("breaking")));
    }
}
