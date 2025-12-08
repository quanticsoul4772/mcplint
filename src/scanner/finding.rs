//! Security Finding - Vulnerability data structures
//!
//! Defines the structures for representing security findings from scans.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Severity level for security findings
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    pub fn sarif_level(self) -> &'static str {
        match self {
            Severity::Critical | Severity::High => "error",
            Severity::Medium => "warning",
            Severity::Low | Severity::Info => "note",
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// A security finding representing a detected vulnerability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Unique finding ID
    pub id: String,
    /// Rule ID that detected this finding (e.g., "MCP-INJ-001")
    pub rule_id: String,
    /// Severity level
    pub severity: Severity,
    /// Short title describing the vulnerability
    pub title: String,
    /// Detailed description
    pub description: String,
    /// Location where the vulnerability was found
    pub location: FindingLocation,
    /// Evidence supporting the finding
    pub evidence: Vec<Evidence>,
    /// Recommended remediation
    pub remediation: String,
    /// External references (CWE, CVE, etc.)
    pub references: Vec<Reference>,
    /// Additional metadata
    pub metadata: FindingMetadata,
}

impl Finding {
    pub fn new(
        rule_id: impl Into<String>,
        severity: Severity,
        title: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            rule_id: rule_id.into(),
            severity,
            title: title.into(),
            description: description.into(),
            location: FindingLocation::default(),
            evidence: Vec::new(),
            remediation: String::new(),
            references: Vec::new(),
            metadata: FindingMetadata::default(),
        }
    }

    pub fn with_location(mut self, location: FindingLocation) -> Self {
        self.location = location;
        self
    }

    pub fn with_evidence(mut self, evidence: Evidence) -> Self {
        self.evidence.push(evidence);
        self
    }

    pub fn with_remediation(mut self, remediation: impl Into<String>) -> Self {
        self.remediation = remediation.into();
        self
    }

    pub fn with_reference(mut self, reference: Reference) -> Self {
        self.references.push(reference);
        self
    }

    pub fn with_cwe(mut self, cwe_id: impl Into<String>) -> Self {
        self.references.push(Reference::cwe(cwe_id));
        self
    }
}

/// Location where a vulnerability was found
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FindingLocation {
    /// Component type (tool, resource, transport, etc.)
    pub component: String,
    /// Specific identifier (tool name, resource URI, etc.)
    pub identifier: String,
    /// Additional context about the location
    pub context: Option<String>,
}

impl FindingLocation {
    pub fn tool(name: impl Into<String>) -> Self {
        Self {
            component: "tool".to_string(),
            identifier: name.into(),
            context: None,
        }
    }

    #[allow(dead_code)]
    pub fn resource(uri: impl Into<String>) -> Self {
        Self {
            component: "resource".to_string(),
            identifier: uri.into(),
            context: None,
        }
    }

    pub fn transport(kind: impl Into<String>) -> Self {
        Self {
            component: "transport".to_string(),
            identifier: kind.into(),
            context: None,
        }
    }

    pub fn server() -> Self {
        Self {
            component: "server".to_string(),
            identifier: "configuration".to_string(),
            context: None,
        }
    }

    pub fn with_context(mut self, context: impl Into<String>) -> Self {
        self.context = Some(context.into());
        self
    }
}

/// Evidence supporting a security finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    /// Type of evidence
    pub kind: EvidenceKind,
    /// The evidence data
    pub data: String,
    /// Description of what this evidence shows
    pub description: String,
}

impl Evidence {
    pub fn new(
        kind: EvidenceKind,
        data: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            data: data.into(),
            description: description.into(),
        }
    }

    #[allow(dead_code)]
    pub fn request(data: impl Into<String>, description: impl Into<String>) -> Self {
        Self::new(EvidenceKind::Request, data, description)
    }

    #[allow(dead_code)]
    pub fn response(data: impl Into<String>, description: impl Into<String>) -> Self {
        Self::new(EvidenceKind::Response, data, description)
    }

    pub fn configuration(data: impl Into<String>, description: impl Into<String>) -> Self {
        Self::new(EvidenceKind::Configuration, data, description)
    }

    pub fn observation(data: impl Into<String>, description: impl Into<String>) -> Self {
        Self::new(EvidenceKind::Observation, data, description)
    }
}

/// Kind of evidence
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EvidenceKind {
    Request,
    Response,
    Configuration,
    Observation,
}

/// External reference for a finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reference {
    /// Type of reference
    pub kind: ReferenceKind,
    /// Reference ID (e.g., "CWE-78", "CVE-2025-1234")
    pub id: String,
    /// URL for more information
    pub url: Option<String>,
}

impl Reference {
    pub fn cwe(id: impl Into<String>) -> Self {
        let id_str = id.into();
        let cwe_num = id_str.trim_start_matches("CWE-");
        Self {
            kind: ReferenceKind::Cwe,
            id: format!("CWE-{}", cwe_num),
            url: Some(format!(
                "https://cwe.mitre.org/data/definitions/{}.html",
                cwe_num
            )),
        }
    }

    #[allow(dead_code)]
    pub fn cve(id: impl Into<String>) -> Self {
        let id_str = id.into();
        Self {
            kind: ReferenceKind::Cve,
            id: id_str.clone(),
            url: Some(format!("https://nvd.nist.gov/vuln/detail/{}", id_str)),
        }
    }

    pub fn mcp_advisory(id: impl Into<String>) -> Self {
        Self {
            kind: ReferenceKind::McpAdvisory,
            id: id.into(),
            url: None,
        }
    }

    #[allow(dead_code)]
    pub fn documentation(id: impl Into<String>, url: impl Into<String>) -> Self {
        Self {
            kind: ReferenceKind::Documentation,
            id: id.into(),
            url: Some(url.into()),
        }
    }
}

/// Kind of external reference
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReferenceKind {
    Cwe,
    Cve,
    McpAdvisory,
    Documentation,
}

/// Additional metadata for a finding
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FindingMetadata {
    /// Time the finding was detected
    pub detected_at: Option<String>,
    /// Scanner version
    pub scanner_version: Option<String>,
    /// Additional tags
    pub tags: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Info);
    }

    #[test]
    fn finding_builder() {
        let finding = Finding::new(
            "MCP-INJ-001",
            Severity::Critical,
            "Command Injection",
            "Detected command injection vulnerability",
        )
        .with_location(FindingLocation::tool("shell_exec"))
        .with_cwe("78")
        .with_remediation("Sanitize user input before shell execution");

        assert_eq!(finding.rule_id, "MCP-INJ-001");
        assert_eq!(finding.severity, Severity::Critical);
        assert_eq!(finding.location.component, "tool");
        assert_eq!(finding.references.len(), 1);
        assert!(finding.references[0].id.contains("CWE-78"));
    }

    #[test]
    fn cwe_reference_url() {
        let ref1 = Reference::cwe("78");
        assert_eq!(ref1.id, "CWE-78");
        assert!(ref1.url.unwrap().contains("78"));

        let ref2 = Reference::cwe("CWE-89");
        assert_eq!(ref2.id, "CWE-89");
    }
}
