//! Security Finding - Vulnerability data structures
//!
//! Defines the structures for representing security findings from scans.

use colored::{Color, ColoredString, Colorize};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::ui::OutputMode;

/// Severity level for security findings
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    clap::ValueEnum,
)]
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

    /// Parse a severity string (case-insensitive)
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "info" => Some(Severity::Info),
            "low" => Some(Severity::Low),
            "medium" => Some(Severity::Medium),
            "high" => Some(Severity::High),
            "critical" => Some(Severity::Critical),
            _ => None,
        }
    }

    pub fn sarif_level(self) -> &'static str {
        match self {
            Severity::Critical | Severity::High => "error",
            Severity::Medium => "warning",
            Severity::Low | Severity::Info => "note",
        }
    }

    /// Return a colorized display string for terminal output
    pub fn colored_display(&self) -> ColoredString {
        match self {
            Severity::Critical => "CRITICAL".red().bold(),
            Severity::High => "HIGH".red(),
            Severity::Medium => "MEDIUM".yellow(),
            Severity::Low => "LOW".blue(),
            Severity::Info => "INFO".dimmed(),
        }
    }

    /// Return a colorized display from a severity string
    /// Useful for displaying severity from string-based sources like Rule.severity
    pub fn colored_from_str(s: &str) -> ColoredString {
        Self::parse(s)
            .map(|sev| sev.colored_display())
            .unwrap_or_else(|| s.normal())
    }

    /// Get the color associated with this severity
    #[allow(dead_code)]
    pub fn color(&self) -> Color {
        match self {
            Severity::Info => Color::BrightBlack,
            Severity::Low => Color::Blue,
            Severity::Medium => Color::Yellow,
            Severity::High => Color::Red,
            Severity::Critical => Color::Red,
        }
    }

    /// Get icon for this severity (unicode or ASCII based on mode)
    #[allow(dead_code)]
    pub fn icon(&self, mode: OutputMode) -> &'static str {
        if mode.unicode_enabled() {
            match self {
                Severity::Info => "⚪",
                Severity::Low => "🔵",
                Severity::Medium => "🟡",
                Severity::High => "🟠",
                Severity::Critical => "🔴",
            }
        } else {
            match self {
                Severity::Info => "[INFO]",
                Severity::Low => "[LOW]",
                Severity::Medium => "[MEDIUM]",
                Severity::High => "[HIGH]",
                Severity::Critical => "[CRITICAL]",
            }
        }
    }

    /// Return a mode-aware display string for terminal output
    pub fn display(&self, mode: OutputMode) -> String {
        if mode.colors_enabled() {
            self.colored_display().to_string()
        } else {
            match self {
                Severity::Critical => "CRITICAL".to_string(),
                Severity::High => "HIGH".to_string(),
                Severity::Medium => "MEDIUM".to_string(),
                Severity::Low => "LOW".to_string(),
                Severity::Info => "INFO".to_string(),
            }
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

    // Severity::as_str() tests
    #[test]
    fn severity_as_str_info() {
        assert_eq!(Severity::Info.as_str(), "info");
    }

    #[test]
    fn severity_as_str_low() {
        assert_eq!(Severity::Low.as_str(), "low");
    }

    #[test]
    fn severity_as_str_medium() {
        assert_eq!(Severity::Medium.as_str(), "medium");
    }

    #[test]
    fn severity_as_str_high() {
        assert_eq!(Severity::High.as_str(), "high");
    }

    #[test]
    fn severity_as_str_critical() {
        assert_eq!(Severity::Critical.as_str(), "critical");
    }

    // Severity::parse() tests
    #[test]
    fn severity_parse_info() {
        assert_eq!(Severity::parse("info"), Some(Severity::Info));
    }

    #[test]
    fn severity_parse_low() {
        assert_eq!(Severity::parse("low"), Some(Severity::Low));
    }

    #[test]
    fn severity_parse_medium() {
        assert_eq!(Severity::parse("medium"), Some(Severity::Medium));
    }

    #[test]
    fn severity_parse_high() {
        assert_eq!(Severity::parse("high"), Some(Severity::High));
    }

    #[test]
    fn severity_parse_critical() {
        assert_eq!(Severity::parse("critical"), Some(Severity::Critical));
    }

    #[test]
    fn severity_parse_case_insensitive() {
        assert_eq!(Severity::parse("INFO"), Some(Severity::Info));
        assert_eq!(Severity::parse("Low"), Some(Severity::Low));
        assert_eq!(Severity::parse("MEDIUM"), Some(Severity::Medium));
        assert_eq!(Severity::parse("HiGh"), Some(Severity::High));
        assert_eq!(Severity::parse("CRITICAL"), Some(Severity::Critical));
    }

    #[test]
    fn severity_parse_invalid() {
        assert_eq!(Severity::parse("unknown"), None);
        assert_eq!(Severity::parse(""), None);
        assert_eq!(Severity::parse("severe"), None);
        assert_eq!(Severity::parse("warning"), None);
    }

    // Severity::sarif_level() tests
    #[test]
    fn severity_sarif_level_critical() {
        assert_eq!(Severity::Critical.sarif_level(), "error");
    }

    #[test]
    fn severity_sarif_level_high() {
        assert_eq!(Severity::High.sarif_level(), "error");
    }

    #[test]
    fn severity_sarif_level_medium() {
        assert_eq!(Severity::Medium.sarif_level(), "warning");
    }

    #[test]
    fn severity_sarif_level_low() {
        assert_eq!(Severity::Low.sarif_level(), "note");
    }

    #[test]
    fn severity_sarif_level_info() {
        assert_eq!(Severity::Info.sarif_level(), "note");
    }

    // Severity::colored_display() tests
    #[test]
    fn severity_colored_display_all_variants() {
        // Just ensure they don't panic and return something
        let _ = Severity::Critical.colored_display();
        let _ = Severity::High.colored_display();
        let _ = Severity::Medium.colored_display();
        let _ = Severity::Low.colored_display();
        let _ = Severity::Info.colored_display();
    }

    // Severity::colored_from_str() tests
    #[test]
    fn severity_colored_from_str_valid() {
        let _ = Severity::colored_from_str("critical");
        let _ = Severity::colored_from_str("high");
        let _ = Severity::colored_from_str("medium");
        let _ = Severity::colored_from_str("low");
        let _ = Severity::colored_from_str("info");
    }

    #[test]
    fn severity_colored_from_str_invalid() {
        // Should return normal colored string for invalid input
        let result = Severity::colored_from_str("invalid");
        assert_eq!(result.to_string(), "invalid");
    }

    // Severity Display trait test
    #[test]
    fn severity_display_trait() {
        assert_eq!(format!("{}", Severity::Info), "info");
        assert_eq!(format!("{}", Severity::Low), "low");
        assert_eq!(format!("{}", Severity::Medium), "medium");
        assert_eq!(format!("{}", Severity::High), "high");
        assert_eq!(format!("{}", Severity::Critical), "critical");
    }

    // Severity ordering tests (additional)
    #[test]
    fn severity_ordering_comprehensive() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::Critical > Severity::Medium);
        assert!(Severity::Critical > Severity::Low);
        assert!(Severity::Critical > Severity::Info);

        assert!(Severity::High > Severity::Medium);
        assert!(Severity::High > Severity::Low);
        assert!(Severity::High > Severity::Info);

        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Medium > Severity::Info);

        assert!(Severity::Low > Severity::Info);
    }

    #[test]
    fn severity_equality() {
        assert_eq!(Severity::Critical, Severity::Critical);
        assert_ne!(Severity::Critical, Severity::High);
    }

    // Finding::new() tests
    #[test]
    fn finding_new_creates_valid_finding() {
        let finding = Finding::new("TEST-001", Severity::High, "Test Title", "Test Description");

        assert!(!finding.id.is_empty());
        assert_eq!(finding.rule_id, "TEST-001");
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(finding.title, "Test Title");
        assert_eq!(finding.description, "Test Description");
        assert!(finding.evidence.is_empty());
        assert!(finding.remediation.is_empty());
        assert!(finding.references.is_empty());
    }

    #[test]
    fn finding_new_generates_unique_ids() {
        let finding1 = Finding::new("TEST-001", Severity::High, "Title", "Description");
        let finding2 = Finding::new("TEST-001", Severity::High, "Title", "Description");

        assert_ne!(finding1.id, finding2.id);
    }

    // Finding builder methods tests
    #[test]
    fn finding_with_location() {
        let location = FindingLocation::tool("test_tool");
        let finding = Finding::new("TEST-001", Severity::Medium, "Title", "Description")
            .with_location(location.clone());

        assert_eq!(finding.location.component, "tool");
        assert_eq!(finding.location.identifier, "test_tool");
    }

    #[test]
    fn finding_with_evidence() {
        let evidence = Evidence::observation("test data", "test description");
        let finding = Finding::new("TEST-001", Severity::Medium, "Title", "Description")
            .with_evidence(evidence);

        assert_eq!(finding.evidence.len(), 1);
        assert_eq!(finding.evidence[0].data, "test data");
    }

    #[test]
    fn finding_with_multiple_evidence() {
        let finding = Finding::new("TEST-001", Severity::Medium, "Title", "Description")
            .with_evidence(Evidence::observation("data1", "desc1"))
            .with_evidence(Evidence::observation("data2", "desc2"));

        assert_eq!(finding.evidence.len(), 2);
    }

    #[test]
    fn finding_with_remediation() {
        let finding = Finding::new("TEST-001", Severity::Medium, "Title", "Description")
            .with_remediation("Apply this fix");

        assert_eq!(finding.remediation, "Apply this fix");
    }

    #[test]
    fn finding_with_cwe() {
        let finding =
            Finding::new("TEST-001", Severity::High, "Title", "Description").with_cwe("78");

        assert_eq!(finding.references.len(), 1);
        assert_eq!(finding.references[0].id, "CWE-78");
        assert_eq!(finding.references[0].kind, ReferenceKind::Cwe);
    }

    #[test]
    fn finding_with_reference() {
        let reference = Reference::mcp_advisory("MCP-ADV-001");
        let finding = Finding::new("TEST-001", Severity::High, "Title", "Description")
            .with_reference(reference);

        assert_eq!(finding.references.len(), 1);
        assert_eq!(finding.references[0].id, "MCP-ADV-001");
    }

    #[test]
    fn finding_with_multiple_references() {
        let finding = Finding::new("TEST-001", Severity::Critical, "Title", "Description")
            .with_cwe("78")
            .with_reference(Reference::mcp_advisory("MCP-ADV-001"));

        assert_eq!(finding.references.len(), 2);
    }

    #[test]
    fn finding_builder_chain() {
        let finding = Finding::new("TEST-001", Severity::Critical, "Title", "Description")
            .with_location(FindingLocation::tool("test_tool"))
            .with_evidence(Evidence::observation("test", "test"))
            .with_remediation("Fix it")
            .with_cwe("78");

        assert_eq!(finding.location.component, "tool");
        assert_eq!(finding.evidence.len(), 1);
        assert_eq!(finding.remediation, "Fix it");
        assert_eq!(finding.references.len(), 1);
    }

    // FindingLocation tests
    #[test]
    fn finding_location_tool() {
        let location = FindingLocation::tool("my_tool");
        assert_eq!(location.component, "tool");
        assert_eq!(location.identifier, "my_tool");
        assert_eq!(location.context, None);
    }

    #[test]
    fn finding_location_resource() {
        let location = FindingLocation::resource("file:///path/to/resource");
        assert_eq!(location.component, "resource");
        assert_eq!(location.identifier, "file:///path/to/resource");
        assert_eq!(location.context, None);
    }

    #[test]
    fn finding_location_transport() {
        let location = FindingLocation::transport("stdio");
        assert_eq!(location.component, "transport");
        assert_eq!(location.identifier, "stdio");
        assert_eq!(location.context, None);
    }

    #[test]
    fn finding_location_server() {
        let location = FindingLocation::server();
        assert_eq!(location.component, "server");
        assert_eq!(location.identifier, "configuration");
        assert_eq!(location.context, None);
    }

    #[test]
    fn finding_location_with_context() {
        let location = FindingLocation::tool("test_tool").with_context("in description field");

        assert_eq!(location.component, "tool");
        assert_eq!(location.identifier, "test_tool");
        assert_eq!(location.context, Some("in description field".to_string()));
    }

    // Evidence tests
    #[test]
    fn evidence_observation_creation() {
        let evidence = Evidence::observation("observed data", "what was observed");
        assert_eq!(evidence.kind, EvidenceKind::Observation);
        assert_eq!(evidence.data, "observed data");
        assert_eq!(evidence.description, "what was observed");
    }

    #[test]
    fn evidence_request_creation() {
        let evidence = Evidence::request("request payload", "malicious request");
        assert_eq!(evidence.kind, EvidenceKind::Request);
        assert_eq!(evidence.data, "request payload");
        assert_eq!(evidence.description, "malicious request");
    }

    #[test]
    fn evidence_response_creation() {
        let evidence = Evidence::response("response data", "suspicious response");
        assert_eq!(evidence.kind, EvidenceKind::Response);
        assert_eq!(evidence.data, "response data");
        assert_eq!(evidence.description, "suspicious response");
    }

    #[test]
    fn evidence_configuration_creation() {
        let evidence = Evidence::configuration("config value", "insecure config");
        assert_eq!(evidence.kind, EvidenceKind::Configuration);
        assert_eq!(evidence.data, "config value");
        assert_eq!(evidence.description, "insecure config");
    }

    // Reference tests
    #[test]
    fn reference_cwe_formatting() {
        let ref1 = Reference::cwe("78");
        assert_eq!(ref1.kind, ReferenceKind::Cwe);
        assert_eq!(ref1.id, "CWE-78");
        assert!(ref1.url.is_some());
        assert!(ref1.url.unwrap().contains("cwe.mitre.org"));
    }

    #[test]
    fn reference_cwe_with_prefix() {
        let reference = Reference::cwe("CWE-89");
        assert_eq!(reference.id, "CWE-89");
        assert!(reference.url.unwrap().contains("89.html"));
    }

    #[test]
    fn reference_cve() {
        let reference = Reference::cve("CVE-2025-1234");
        assert_eq!(reference.kind, ReferenceKind::Cve);
        assert_eq!(reference.id, "CVE-2025-1234");
        assert!(reference.url.is_some());
        assert!(reference.url.unwrap().contains("nvd.nist.gov"));
    }

    #[test]
    fn reference_mcp_advisory() {
        let reference = Reference::mcp_advisory("MCP-ADV-001");
        assert_eq!(reference.kind, ReferenceKind::McpAdvisory);
        assert_eq!(reference.id, "MCP-ADV-001");
        assert_eq!(reference.url, None);
    }

    #[test]
    fn reference_documentation() {
        let reference =
            Reference::documentation("MCP Spec", "https://spec.modelcontextprotocol.io");
        assert_eq!(reference.kind, ReferenceKind::Documentation);
        assert_eq!(reference.id, "MCP Spec");
        assert_eq!(
            reference.url,
            Some("https://spec.modelcontextprotocol.io".to_string())
        );
    }

    // Serialization/Deserialization tests
    #[test]
    fn severity_serialization() {
        let severity = Severity::Critical;
        let json = serde_json::to_string(&severity).unwrap();
        assert_eq!(json, "\"critical\"");
    }

    #[test]
    fn severity_deserialization() {
        let json = "\"high\"";
        let severity: Severity = serde_json::from_str(json).unwrap();
        assert_eq!(severity, Severity::High);
    }

    #[test]
    fn finding_serialization_roundtrip() {
        let finding = Finding::new("TEST-001", Severity::High, "Title", "Description")
            .with_location(FindingLocation::tool("test"))
            .with_remediation("Fix");

        let json = serde_json::to_string(&finding).unwrap();
        let deserialized: Finding = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.rule_id, finding.rule_id);
        assert_eq!(deserialized.severity, finding.severity);
        assert_eq!(deserialized.title, finding.title);
    }

    #[test]
    fn evidence_kind_serialization() {
        let kind = EvidenceKind::Observation;
        let json = serde_json::to_string(&kind).unwrap();
        assert_eq!(json, "\"observation\"");
    }

    #[test]
    fn reference_kind_serialization() {
        let kind = ReferenceKind::Cwe;
        let json = serde_json::to_string(&kind).unwrap();
        assert_eq!(json, "\"cwe\"");
    }

    // Additional Severity tests
    #[test]
    fn severity_color_critical() {
        assert_eq!(Severity::Critical.color(), Color::Red);
    }

    #[test]
    fn severity_color_high() {
        assert_eq!(Severity::High.color(), Color::Red);
    }

    #[test]
    fn severity_color_medium() {
        assert_eq!(Severity::Medium.color(), Color::Yellow);
    }

    #[test]
    fn severity_color_low() {
        assert_eq!(Severity::Low.color(), Color::Blue);
    }

    #[test]
    fn severity_color_info() {
        assert_eq!(Severity::Info.color(), Color::BrightBlack);
    }

    #[test]
    fn severity_icon_unicode_critical() {
        assert_eq!(Severity::Critical.icon(OutputMode::Interactive), "🔴");
    }

    #[test]
    fn severity_icon_unicode_high() {
        assert_eq!(Severity::High.icon(OutputMode::Interactive), "🟠");
    }

    #[test]
    fn severity_icon_unicode_medium() {
        assert_eq!(Severity::Medium.icon(OutputMode::Interactive), "🟡");
    }

    #[test]
    fn severity_icon_unicode_low() {
        assert_eq!(Severity::Low.icon(OutputMode::Interactive), "🔵");
    }

    #[test]
    fn severity_icon_unicode_info() {
        assert_eq!(Severity::Info.icon(OutputMode::Interactive), "⚪");
    }

    #[test]
    fn severity_icon_ascii_critical() {
        assert_eq!(Severity::Critical.icon(OutputMode::CI), "[CRITICAL]");
    }

    #[test]
    fn severity_icon_ascii_high() {
        assert_eq!(Severity::High.icon(OutputMode::CI), "[HIGH]");
    }

    #[test]
    fn severity_icon_ascii_medium() {
        assert_eq!(Severity::Medium.icon(OutputMode::CI), "[MEDIUM]");
    }

    #[test]
    fn severity_icon_ascii_low() {
        assert_eq!(Severity::Low.icon(OutputMode::CI), "[LOW]");
    }

    #[test]
    fn severity_icon_ascii_info() {
        assert_eq!(Severity::Info.icon(OutputMode::CI), "[INFO]");
    }

    #[test]
    fn severity_display_with_colors() {
        let display = Severity::Critical.display(OutputMode::Interactive);
        assert!(display.contains("CRITICAL"));
    }

    #[test]
    fn severity_display_without_colors() {
        let display = Severity::Critical.display(OutputMode::CI);
        assert_eq!(display, "CRITICAL");
    }

    #[test]
    fn severity_display_high() {
        let display = Severity::High.display(OutputMode::CI);
        assert_eq!(display, "HIGH");
    }

    #[test]
    fn severity_display_medium() {
        let display = Severity::Medium.display(OutputMode::CI);
        assert_eq!(display, "MEDIUM");
    }

    #[test]
    fn severity_display_low() {
        let display = Severity::Low.display(OutputMode::CI);
        assert_eq!(display, "LOW");
    }

    #[test]
    fn severity_display_info() {
        let display = Severity::Info.display(OutputMode::CI);
        assert_eq!(display, "INFO");
    }

    // FindingMetadata tests
    #[test]
    fn finding_metadata_default() {
        let metadata = FindingMetadata::default();
        assert!(metadata.detected_at.is_none());
        assert!(metadata.scanner_version.is_none());
        assert!(metadata.tags.is_empty());
    }

    #[test]
    fn finding_metadata_with_values() {
        let mut metadata = FindingMetadata::default();
        metadata.detected_at = Some("2025-12-12T00:00:00Z".to_string());
        metadata.scanner_version = Some("1.0.0".to_string());
        metadata.tags.push("test".to_string());

        assert_eq!(
            metadata.detected_at,
            Some("2025-12-12T00:00:00Z".to_string())
        );
        assert_eq!(metadata.scanner_version, Some("1.0.0".to_string()));
        assert_eq!(metadata.tags.len(), 1);
    }

    // FindingLocation default test
    #[test]
    fn finding_location_default() {
        let location = FindingLocation::default();
        assert!(location.component.is_empty());
        assert!(location.identifier.is_empty());
        assert!(location.context.is_none());
    }

    // Evidence::new tests
    #[test]
    fn evidence_new() {
        let evidence = Evidence::new(EvidenceKind::Request, "test data", "test description");
        assert_eq!(evidence.kind, EvidenceKind::Request);
        assert_eq!(evidence.data, "test data");
        assert_eq!(evidence.description, "test description");
    }

    // EvidenceKind serialization tests
    #[test]
    fn evidence_kind_request_serialization() {
        let kind = EvidenceKind::Request;
        let json = serde_json::to_string(&kind).unwrap();
        assert_eq!(json, "\"request\"");
    }

    #[test]
    fn evidence_kind_response_serialization() {
        let kind = EvidenceKind::Response;
        let json = serde_json::to_string(&kind).unwrap();
        assert_eq!(json, "\"response\"");
    }

    #[test]
    fn evidence_kind_configuration_serialization() {
        let kind = EvidenceKind::Configuration;
        let json = serde_json::to_string(&kind).unwrap();
        assert_eq!(json, "\"configuration\"");
    }

    #[test]
    fn evidence_kind_observation_serialization() {
        let kind = EvidenceKind::Observation;
        let json = serde_json::to_string(&kind).unwrap();
        assert_eq!(json, "\"observation\"");
    }

    // ReferenceKind serialization tests
    #[test]
    fn reference_kind_cve_serialization() {
        let kind = ReferenceKind::Cve;
        let json = serde_json::to_string(&kind).unwrap();
        assert_eq!(json, "\"cve\"");
    }

    #[test]
    fn reference_kind_mcp_advisory_serialization() {
        let kind = ReferenceKind::McpAdvisory;
        let json = serde_json::to_string(&kind).unwrap();
        assert_eq!(json, "\"mcpadvisory\"");
    }

    #[test]
    fn reference_kind_documentation_serialization() {
        let kind = ReferenceKind::Documentation;
        let json = serde_json::to_string(&kind).unwrap();
        assert_eq!(json, "\"documentation\"");
    }

    // Additional Finding builder tests
    #[test]
    fn finding_with_all_severities() {
        let critical = Finding::new("TEST-001", Severity::Critical, "Title", "Desc");
        let high = Finding::new("TEST-002", Severity::High, "Title", "Desc");
        let medium = Finding::new("TEST-003", Severity::Medium, "Title", "Desc");
        let low = Finding::new("TEST-004", Severity::Low, "Title", "Desc");
        let info = Finding::new("TEST-005", Severity::Info, "Title", "Desc");

        assert_eq!(critical.severity, Severity::Critical);
        assert_eq!(high.severity, Severity::High);
        assert_eq!(medium.severity, Severity::Medium);
        assert_eq!(low.severity, Severity::Low);
        assert_eq!(info.severity, Severity::Info);
    }

    #[test]
    fn finding_complex_builder_chain() {
        let finding = Finding::new(
            "TEST-001",
            Severity::High,
            "Complex Test",
            "Test Description",
        )
        .with_location(FindingLocation::tool("test_tool").with_context("field"))
        .with_evidence(Evidence::request("req1", "desc1"))
        .with_evidence(Evidence::response("resp1", "desc2"))
        .with_evidence(Evidence::configuration("conf1", "desc3"))
        .with_remediation("Fix all issues")
        .with_cwe("78")
        .with_reference(Reference::mcp_advisory("MCP-ADV-001"));

        assert_eq!(finding.evidence.len(), 3);
        assert_eq!(finding.references.len(), 2);
        assert_eq!(finding.location.context, Some("field".to_string()));
    }

    // Reference URL generation tests
    #[test]
    fn reference_cwe_url_format() {
        let reference = Reference::cwe("123");
        assert_eq!(
            reference.url,
            Some("https://cwe.mitre.org/data/definitions/123.html".to_string())
        );
    }

    #[test]
    fn reference_cwe_strips_prefix() {
        let reference = Reference::cwe("CWE-456");
        assert_eq!(reference.id, "CWE-456");
        assert!(reference.url.unwrap().contains("456.html"));
    }

    #[test]
    fn reference_cve_url_format() {
        let reference = Reference::cve("CVE-2025-9999");
        assert_eq!(
            reference.url,
            Some("https://nvd.nist.gov/vuln/detail/CVE-2025-9999".to_string())
        );
    }

    #[test]
    fn reference_mcp_advisory_no_url() {
        let reference = Reference::mcp_advisory("MCP-ADV-123");
        assert_eq!(reference.id, "MCP-ADV-123");
        assert_eq!(reference.url, None);
    }

    #[test]
    fn reference_documentation_with_url() {
        let reference = Reference::documentation("Test Doc", "https://example.com/docs");
        assert_eq!(reference.id, "Test Doc");
        assert_eq!(reference.url, Some("https://example.com/docs".to_string()));
    }

    // Severity hash test
    #[test]
    fn severity_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(Severity::Critical);
        set.insert(Severity::High);
        set.insert(Severity::Critical); // duplicate

        assert_eq!(set.len(), 2);
        assert!(set.contains(&Severity::Critical));
        assert!(set.contains(&Severity::High));
    }

    // Severity copy and clone tests
    #[test]
    fn severity_copy_clone() {
        let s1 = Severity::High;
        let s2 = s1; // copy
        let s3 = s1.clone(); // clone

        assert_eq!(s1, s2);
        assert_eq!(s1, s3);
    }

    // EvidenceKind equality tests
    #[test]
    fn evidence_kind_equality() {
        assert_eq!(EvidenceKind::Request, EvidenceKind::Request);
        assert_ne!(EvidenceKind::Request, EvidenceKind::Response);
    }

    // ReferenceKind equality tests
    #[test]
    fn reference_kind_equality() {
        assert_eq!(ReferenceKind::Cwe, ReferenceKind::Cwe);
        assert_ne!(ReferenceKind::Cwe, ReferenceKind::Cve);
    }

    // Finding serialization edge cases
    #[test]
    fn finding_serialization_with_empty_fields() {
        let finding = Finding::new("TEST-001", Severity::Info, "Title", "Description");
        let json = serde_json::to_string(&finding).unwrap();
        let deserialized: Finding = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.rule_id, "TEST-001");
        assert!(deserialized.evidence.is_empty());
        assert!(deserialized.references.is_empty());
    }

    #[test]
    fn finding_serialization_with_all_fields() {
        let finding = Finding::new("TEST-001", Severity::Critical, "Title", "Description")
            .with_location(FindingLocation::tool("test"))
            .with_evidence(Evidence::observation("data", "desc"))
            .with_remediation("Fix it")
            .with_cwe("78");

        let json = serde_json::to_string(&finding).unwrap();
        let deserialized: Finding = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.rule_id, "TEST-001");
        assert_eq!(deserialized.evidence.len(), 1);
        assert_eq!(deserialized.references.len(), 1);
    }

    // Severity deserialization tests
    #[test]
    fn severity_deserialization_all() {
        let severities = vec!["info", "low", "medium", "high", "critical"];
        let expected = vec![
            Severity::Info,
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ];

        for (json_str, expected_severity) in severities.iter().zip(expected.iter()) {
            let json = format!("\"{}\"", json_str);
            let severity: Severity = serde_json::from_str(&json).unwrap();
            assert_eq!(severity, *expected_severity);
        }
    }

    // Severity ordering comprehensive
    #[test]
    fn severity_partial_ord() {
        use std::cmp::Ordering;

        assert_eq!(
            Severity::Critical.partial_cmp(&Severity::High),
            Some(Ordering::Greater)
        );
        assert_eq!(
            Severity::Low.partial_cmp(&Severity::High),
            Some(Ordering::Less)
        );
        assert_eq!(
            Severity::Medium.partial_cmp(&Severity::Medium),
            Some(Ordering::Equal)
        );
    }

    // Finding location variants
    #[test]
    fn finding_location_all_variants() {
        let tool_loc = FindingLocation::tool("my_tool");
        assert_eq!(tool_loc.component, "tool");

        let resource_loc = FindingLocation::resource("resource://path");
        assert_eq!(resource_loc.component, "resource");

        let transport_loc = FindingLocation::transport("stdio");
        assert_eq!(transport_loc.component, "transport");

        let server_loc = FindingLocation::server();
        assert_eq!(server_loc.component, "server");
    }

    // Evidence all kinds
    #[test]
    fn evidence_all_kinds() {
        let req = Evidence::request("req", "desc");
        assert_eq!(req.kind, EvidenceKind::Request);

        let resp = Evidence::response("resp", "desc");
        assert_eq!(resp.kind, EvidenceKind::Response);

        let conf = Evidence::configuration("conf", "desc");
        assert_eq!(conf.kind, EvidenceKind::Configuration);

        let obs = Evidence::observation("obs", "desc");
        assert_eq!(obs.kind, EvidenceKind::Observation);
    }

    // Multiple CWE references
    #[test]
    fn finding_with_multiple_cwes() {
        let finding = Finding::new("TEST-001", Severity::High, "Title", "Description")
            .with_cwe("78")
            .with_cwe("89")
            .with_cwe("22");

        assert_eq!(finding.references.len(), 3);
        assert!(finding.references.iter().any(|r| r.id == "CWE-78"));
        assert!(finding.references.iter().any(|r| r.id == "CWE-89"));
        assert!(finding.references.iter().any(|r| r.id == "CWE-22"));
    }

    // Severity colored_from_str edge cases
    #[test]
    fn severity_colored_from_str_empty() {
        let result = Severity::colored_from_str("");
        assert_eq!(result.to_string(), "");
    }

    #[test]
    fn severity_colored_from_str_whitespace() {
        let result = Severity::colored_from_str("   ");
        assert_eq!(result.to_string(), "   ");
    }

    // Metadata serialization
    #[test]
    fn finding_metadata_serialization() {
        let mut metadata = FindingMetadata::default();
        metadata.detected_at = Some("2025-12-12T00:00:00Z".to_string());
        metadata.scanner_version = Some("1.0.0".to_string());
        metadata.tags = vec!["test".to_string(), "security".to_string()];

        let json = serde_json::to_string(&metadata).unwrap();
        let deserialized: FindingMetadata = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.detected_at, metadata.detected_at);
        assert_eq!(deserialized.scanner_version, metadata.scanner_version);
        assert_eq!(deserialized.tags, metadata.tags);
    }
}
