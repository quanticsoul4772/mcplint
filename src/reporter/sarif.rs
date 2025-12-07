//! SARIF output format for GitHub Code Scanning integration
//!
//! SARIF (Static Analysis Results Interchange Format) 2.1.0 types
//! for CI/CD integration with GitHub, GitLab, and other platforms.

#![allow(dead_code)] // Types are defined for future SARIF output implementation

use serde::{Deserialize, Serialize};

/// SARIF 2.1.0 compatible report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifReport {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub version: String,
    pub runs: Vec<SarifRun>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifRun {
    pub tool: SarifTool,
    pub results: Vec<SarifResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifTool {
    pub driver: SarifDriver,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifDriver {
    pub name: String,
    pub version: String,
    #[serde(rename = "informationUri")]
    pub information_uri: String,
    pub rules: Vec<SarifRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifRule {
    pub id: String,
    pub name: String,
    #[serde(rename = "shortDescription")]
    pub short_description: SarifMessage,
    #[serde(rename = "fullDescription")]
    pub full_description: SarifMessage,
    #[serde(rename = "defaultConfiguration")]
    pub default_configuration: SarifConfiguration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifMessage {
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifConfiguration {
    pub level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifResult {
    #[serde(rename = "ruleId")]
    pub rule_id: String,
    pub level: String,
    pub message: SarifMessage,
    pub locations: Vec<SarifLocation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifLocation {
    #[serde(rename = "physicalLocation")]
    pub physical_location: SarifPhysicalLocation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifPhysicalLocation {
    #[serde(rename = "artifactLocation")]
    pub artifact_location: SarifArtifactLocation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifArtifactLocation {
    pub uri: String,
}

impl SarifReport {
    pub fn new() -> Self {
        Self {
            schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json".to_string(),
            version: "2.1.0".to_string(),
            runs: vec![],
        }
    }

    /// Create a SARIF report from validation results
    pub fn from_validation_results(results: &crate::validator::ValidationResults) -> Self {
        use crate::validator::ValidationSeverity;

        // Collect unique rules from results
        let mut rules: Vec<SarifRule> = Vec::new();
        let mut seen_rules: std::collections::HashSet<String> = std::collections::HashSet::new();

        for result in &results.results {
            if !seen_rules.contains(&result.rule_id) {
                seen_rules.insert(result.rule_id.clone());
                rules.push(SarifRule {
                    id: result.rule_id.clone(),
                    name: result.rule_name.clone(),
                    short_description: SarifMessage {
                        text: result.rule_name.clone(),
                    },
                    full_description: SarifMessage {
                        text: result
                            .message
                            .clone()
                            .unwrap_or_else(|| result.rule_name.clone()),
                    },
                    default_configuration: SarifConfiguration {
                        level: match result.severity {
                            ValidationSeverity::Fail => "error".to_string(),
                            ValidationSeverity::Warning => "warning".to_string(),
                            _ => "note".to_string(),
                        },
                    },
                });
            }
        }

        // Convert results to SARIF results (only failures and warnings)
        let sarif_results: Vec<SarifResult> = results
            .results
            .iter()
            .filter(|r| {
                matches!(
                    r.severity,
                    ValidationSeverity::Fail | ValidationSeverity::Warning
                )
            })
            .map(|r| SarifResult {
                rule_id: r.rule_id.clone(),
                level: match r.severity {
                    ValidationSeverity::Fail => "error".to_string(),
                    ValidationSeverity::Warning => "warning".to_string(),
                    _ => "note".to_string(),
                },
                message: SarifMessage {
                    text: format!("{}: {}", r.rule_name, r.message.clone().unwrap_or_default()),
                },
                locations: vec![SarifLocation {
                    physical_location: SarifPhysicalLocation {
                        artifact_location: SarifArtifactLocation {
                            uri: results.server.clone(),
                        },
                    },
                }],
            })
            .collect();

        Self {
            schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json".to_string(),
            version: "2.1.0".to_string(),
            runs: vec![SarifRun {
                tool: SarifTool {
                    driver: SarifDriver {
                        name: "mcplint".to_string(),
                        version: env!("CARGO_PKG_VERSION").to_string(),
                        information_uri: "https://github.com/quanticsoul4772/mcplint".to_string(),
                        rules,
                    },
                },
                results: sarif_results,
            }],
        }
    }
}

impl Default for SarifReport {
    fn default() -> Self {
        Self::new()
    }
}
