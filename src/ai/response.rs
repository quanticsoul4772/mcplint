//! AI Response Types - Structured explanation responses
//!
//! Defines the data structures for AI-generated explanations
//! including vulnerability details, remediation guidance, and educational context.

use serde::{Deserialize, Serialize};

/// Complete AI-generated explanation for a security finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExplanationResponse {
    /// Finding ID this explanation is for
    pub finding_id: String,
    /// Rule ID (e.g., "MCP-INJ-001")
    pub rule_id: String,
    /// Human-readable vulnerability explanation
    pub explanation: VulnerabilityExplanation,
    /// Remediation guidance
    pub remediation: RemediationGuide,
    /// Educational context
    pub education: Option<EducationalContext>,
    /// Provider and model metadata
    pub metadata: ExplanationMetadata,
}

impl ExplanationResponse {
    /// Create a new explanation response
    pub fn new(finding_id: impl Into<String>, rule_id: impl Into<String>) -> Self {
        Self {
            finding_id: finding_id.into(),
            rule_id: rule_id.into(),
            explanation: VulnerabilityExplanation::default(),
            remediation: RemediationGuide::default(),
            education: None,
            metadata: ExplanationMetadata::default(),
        }
    }

    /// Set the explanation
    pub fn with_explanation(mut self, explanation: VulnerabilityExplanation) -> Self {
        self.explanation = explanation;
        self
    }

    /// Set remediation
    pub fn with_remediation(mut self, remediation: RemediationGuide) -> Self {
        self.remediation = remediation;
        self
    }

    /// Set educational context
    pub fn with_education(mut self, education: EducationalContext) -> Self {
        self.education = Some(education);
        self
    }

    /// Set metadata
    pub fn with_metadata(mut self, metadata: ExplanationMetadata) -> Self {
        self.metadata = metadata;
        self
    }

    /// Get a brief summary
    pub fn summary(&self) -> &str {
        &self.explanation.summary
    }

    /// Check if this was a cached response
    pub fn is_cached(&self) -> bool {
        self.metadata.cached
    }
}

/// Detailed vulnerability explanation
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VulnerabilityExplanation {
    /// Plain-language summary (1-2 sentences)
    pub summary: String,
    /// Technical deep-dive (markdown)
    pub technical_details: String,
    /// Attack scenario description
    pub attack_scenario: String,
    /// Real-world impact assessment
    pub impact: String,
    /// Likelihood rating
    pub likelihood: Likelihood,
}

impl VulnerabilityExplanation {
    pub fn new(summary: impl Into<String>) -> Self {
        Self {
            summary: summary.into(),
            ..Default::default()
        }
    }

    pub fn with_technical_details(mut self, details: impl Into<String>) -> Self {
        self.technical_details = details.into();
        self
    }

    pub fn with_attack_scenario(mut self, scenario: impl Into<String>) -> Self {
        self.attack_scenario = scenario.into();
        self
    }

    pub fn with_impact(mut self, impact: impl Into<String>) -> Self {
        self.impact = impact.into();
        self
    }

    pub fn with_likelihood(mut self, likelihood: Likelihood) -> Self {
        self.likelihood = likelihood;
        self
    }
}

/// Likelihood rating for vulnerability exploitation
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Likelihood {
    Low,
    #[default]
    Medium,
    High,
}

impl Likelihood {
    pub fn as_str(&self) -> &'static str {
        match self {
            Likelihood::Low => "low",
            Likelihood::Medium => "medium",
            Likelihood::High => "high",
        }
    }
}

impl std::str::FromStr for Likelihood {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "low" => Ok(Likelihood::Low),
            "medium" => Ok(Likelihood::Medium),
            "high" => Ok(Likelihood::High),
            _ => Err(()),
        }
    }
}

impl std::fmt::Display for Likelihood {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Remediation guidance for fixing the vulnerability
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RemediationGuide {
    /// Immediate mitigation steps
    pub immediate_actions: Vec<String>,
    /// Long-term fix recommendation
    pub permanent_fix: String,
    /// Code example (if applicable)
    pub code_example: Option<CodeExample>,
    /// Verification steps
    pub verification: Vec<String>,
    /// Estimated effort level
    pub effort: EffortLevel,
}

impl RemediationGuide {
    pub fn new(permanent_fix: impl Into<String>) -> Self {
        Self {
            permanent_fix: permanent_fix.into(),
            ..Default::default()
        }
    }

    pub fn with_immediate_actions(mut self, actions: Vec<String>) -> Self {
        self.immediate_actions = actions;
        self
    }

    pub fn add_immediate_action(mut self, action: impl Into<String>) -> Self {
        self.immediate_actions.push(action.into());
        self
    }

    pub fn with_code_example(mut self, example: CodeExample) -> Self {
        self.code_example = Some(example);
        self
    }

    pub fn with_verification(mut self, steps: Vec<String>) -> Self {
        self.verification = steps;
        self
    }

    pub fn add_verification_step(mut self, step: impl Into<String>) -> Self {
        self.verification.push(step.into());
        self
    }

    pub fn with_effort(mut self, effort: EffortLevel) -> Self {
        self.effort = effort;
        self
    }
}

/// Effort level for remediation
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EffortLevel {
    /// Quick fix (minutes)
    Trivial,
    /// Small change (hours)
    #[default]
    Low,
    /// Moderate work (days)
    Medium,
    /// Significant effort (weeks)
    High,
}

impl EffortLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            EffortLevel::Trivial => "trivial",
            EffortLevel::Low => "low",
            EffortLevel::Medium => "medium",
            EffortLevel::High => "high",
        }
    }
}

/// Code example showing vulnerable and fixed versions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeExample {
    /// Programming language
    pub language: String,
    /// Vulnerable code
    pub before: String,
    /// Fixed code
    pub after: String,
    /// Explanation of changes
    pub explanation: String,
}

impl CodeExample {
    pub fn new(
        language: impl Into<String>,
        before: impl Into<String>,
        after: impl Into<String>,
    ) -> Self {
        Self {
            language: language.into(),
            before: before.into(),
            after: after.into(),
            explanation: String::new(),
        }
    }

    pub fn with_explanation(mut self, explanation: impl Into<String>) -> Self {
        self.explanation = explanation.into();
        self
    }
}

/// Educational context about the vulnerability class
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EducationalContext {
    /// Related CWEs with descriptions
    pub related_weaknesses: Vec<WeaknessInfo>,
    /// Similar vulnerability patterns
    pub similar_patterns: Vec<String>,
    /// Security best practices
    pub best_practices: Vec<String>,
    /// Further reading resources
    pub resources: Vec<ResourceLink>,
}

impl EducationalContext {
    pub fn add_weakness(mut self, weakness: WeaknessInfo) -> Self {
        self.related_weaknesses.push(weakness);
        self
    }

    pub fn add_pattern(mut self, pattern: impl Into<String>) -> Self {
        self.similar_patterns.push(pattern.into());
        self
    }

    pub fn add_best_practice(mut self, practice: impl Into<String>) -> Self {
        self.best_practices.push(practice.into());
        self
    }

    pub fn add_resource(mut self, resource: ResourceLink) -> Self {
        self.resources.push(resource);
        self
    }
}

/// Information about a related CWE weakness
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WeaknessInfo {
    /// CWE ID (e.g., "CWE-78")
    pub cwe_id: String,
    /// Weakness name
    pub name: String,
    /// Brief description
    pub description: String,
}

impl WeaknessInfo {
    pub fn new(
        cwe_id: impl Into<String>,
        name: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            cwe_id: cwe_id.into(),
            name: name.into(),
            description: description.into(),
        }
    }

    pub fn url(&self) -> String {
        let id = self.cwe_id.trim_start_matches("CWE-");
        format!("https://cwe.mitre.org/data/definitions/{}.html", id)
    }
}

/// External resource link
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLink {
    /// Resource title
    pub title: String,
    /// URL
    pub url: String,
    /// Category
    pub category: ResourceCategory,
}

impl ResourceLink {
    pub fn documentation(title: impl Into<String>, url: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            url: url.into(),
            category: ResourceCategory::Documentation,
        }
    }

    pub fn article(title: impl Into<String>, url: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            url: url.into(),
            category: ResourceCategory::Article,
        }
    }

    pub fn tool(title: impl Into<String>, url: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            url: url.into(),
            category: ResourceCategory::Tool,
        }
    }
}

/// Resource category
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ResourceCategory {
    Documentation,
    Article,
    Tool,
    Video,
    Course,
}

/// Metadata about the explanation generation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExplanationMetadata {
    /// Provider used
    pub provider: String,
    /// Model used
    pub model: String,
    /// Generation timestamp
    pub generated_at: String,
    /// Prompt template version
    pub prompt_version: String,
    /// Tokens used
    pub tokens_used: u32,
    /// Whether this was from cache
    pub cached: bool,
    /// Response time in milliseconds
    pub response_time_ms: u64,
}

impl Default for ExplanationMetadata {
    fn default() -> Self {
        Self {
            provider: "unknown".to_string(),
            model: "unknown".to_string(),
            generated_at: chrono::Utc::now().to_rfc3339(),
            prompt_version: "1.0".to_string(),
            tokens_used: 0,
            cached: false,
            response_time_ms: 0,
        }
    }
}

impl ExplanationMetadata {
    pub fn new(provider: impl Into<String>, model: impl Into<String>) -> Self {
        Self {
            provider: provider.into(),
            model: model.into(),
            ..Default::default()
        }
    }

    pub fn with_tokens(mut self, tokens: u32) -> Self {
        self.tokens_used = tokens;
        self
    }

    pub fn with_response_time(mut self, ms: u64) -> Self {
        self.response_time_ms = ms;
        self
    }

    pub fn mark_cached(mut self) -> Self {
        self.cached = true;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explanation_response_builder() {
        let response = ExplanationResponse::new("finding-123", "MCP-INJ-001")
            .with_explanation(VulnerabilityExplanation::new("Test summary"))
            .with_remediation(RemediationGuide::new("Fix the issue"));

        assert_eq!(response.finding_id, "finding-123");
        assert_eq!(response.rule_id, "MCP-INJ-001");
        assert_eq!(response.summary(), "Test summary");
    }

    #[test]
    fn code_example_creation() {
        let example = CodeExample::new("rust", "let x = unsafe { ... }", "let x = safe_fn()")
            .with_explanation("Replaced unsafe block with safe alternative");

        assert_eq!(example.language, "rust");
        assert!(!example.explanation.is_empty());
    }

    #[test]
    fn weakness_info_url() {
        let weakness = WeaknessInfo::new("CWE-78", "OS Command Injection", "Description");
        assert!(weakness.url().contains("78"));

        let weakness2 = WeaknessInfo::new("78", "OS Command Injection", "Description");
        assert!(weakness2.url().contains("78"));
    }

    #[test]
    fn likelihood_parsing() {
        assert_eq!("high".parse::<Likelihood>(), Ok(Likelihood::High));
        assert_eq!("LOW".parse::<Likelihood>(), Ok(Likelihood::Low));
        assert!("invalid".parse::<Likelihood>().is_err());
    }
}
