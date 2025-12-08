//! Prompt Templates - Security-focused prompt engineering
//!
//! Provides templates and builders for constructing prompts
//! that generate high-quality vulnerability explanations.

use crate::scanner::Finding;

use super::config::{AudienceLevel, ExplanationContext};

/// Current prompt template version (for cache invalidation)
pub const PROMPT_VERSION: &str = "1.0";

/// System prompt for security analysis
pub const SYSTEM_PROMPT: &str = r#"You are a senior security researcher specializing in MCP (Model Context Protocol) server security. Your role is to analyze security findings and provide clear, actionable explanations.

Key responsibilities:
1. Explain vulnerabilities in terms appropriate for the target audience
2. Provide realistic attack scenarios that demonstrate the risk
3. Offer specific, implementable remediation guidance
4. Include educational context about related security concepts

Always be:
- Accurate and technically precise
- Clear and well-structured in explanations
- Practical in remediation advice
- Educational without being condescending

Response format: You MUST respond with valid JSON matching the specified schema."#;

/// Prompt builder for generating explanation requests
pub struct PromptBuilder {
    finding: Option<Finding>,
    context: ExplanationContext,
}

impl Default for PromptBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl PromptBuilder {
    /// Create a new prompt builder
    pub fn new() -> Self {
        Self {
            finding: None,
            context: ExplanationContext::default(),
        }
    }

    /// Set the finding to explain
    pub fn with_finding(mut self, finding: Finding) -> Self {
        self.finding = Some(finding);
        self
    }

    /// Set the explanation context
    pub fn with_context(mut self, context: ExplanationContext) -> Self {
        self.context = context;
        self
    }

    /// Build the user prompt for a single finding
    pub fn build_finding_prompt(&self) -> String {
        let finding = self.finding.as_ref().expect("Finding is required");

        let cwe_refs = finding
            .references
            .iter()
            .filter(|r| r.kind == crate::scanner::ReferenceKind::Cwe)
            .map(|r| r.id.as_str())
            .collect::<Vec<_>>()
            .join(", ");

        let evidence_text = finding
            .evidence
            .iter()
            .map(|e| format!("- {}: {}", e.description, e.data))
            .collect::<Vec<_>>()
            .join("\n");

        let tech_stack = if self.context.tech_stack.is_empty() {
            "Not specified".to_string()
        } else {
            self.context.tech_stack.join(", ")
        };

        let code_lang = self
            .context
            .code_language
            .as_deref()
            .unwrap_or("TypeScript");

        format!(
            r#"Analyze the following MCP server security finding and provide a comprehensive explanation.

## Finding Details
- **Rule ID**: {rule_id}
- **Severity**: {severity}
- **Title**: {title}
- **Description**: {description}
- **Location**: {component} - {identifier}
- **CWE References**: {cwe_refs}

## Evidence
{evidence}

## Server Context
- **Server Name**: {server_name}
- **Technology Stack**: {tech_stack}

## Target Audience
{audience_desc}

## Required Response Format
Respond with a JSON object matching this exact structure:
```json
{{
  "explanation": {{
    "summary": "One or two sentence plain-language summary of the vulnerability",
    "technical_details": "Detailed technical explanation in markdown format",
    "attack_scenario": "Realistic attack scenario showing how this could be exploited",
    "impact": "Business and technical impact assessment",
    "likelihood": "low|medium|high"
  }},
  "remediation": {{
    "immediate_actions": ["Step 1", "Step 2", "Step 3"],
    "permanent_fix": "Description of the proper long-term fix",
    "code_example": {{
      "language": "{code_lang}",
      "before": "// Vulnerable code example",
      "after": "// Fixed code example",
      "explanation": "What changed and why it's more secure"
    }},
    "verification": ["How to verify the fix was applied correctly"]
  }},
  "education": {{
    "related_weaknesses": [
      {{"cwe_id": "CWE-XXX", "name": "Weakness Name", "description": "Brief description"}}
    ],
    "similar_patterns": ["Related vulnerability pattern 1", "Related pattern 2"],
    "best_practices": ["Security best practice 1", "Best practice 2"],
    "resources": [
      {{"title": "Resource Title", "url": "https://example.com", "category": "documentation|article|tool"}}
    ]
  }}
}}
```

Provide your analysis now:"#,
            rule_id = finding.rule_id,
            severity = finding.severity,
            title = finding.title,
            description = finding.description,
            component = finding.location.component,
            identifier = finding.location.identifier,
            cwe_refs = if cwe_refs.is_empty() {
                "None specified"
            } else {
                &cwe_refs
            },
            evidence = if evidence_text.is_empty() {
                "No specific evidence provided".to_string()
            } else {
                evidence_text
            },
            server_name = self.context.server_name,
            tech_stack = tech_stack,
            audience_desc = self.context.audience.description(),
            code_lang = code_lang,
        )
    }

    /// Build a follow-up question prompt
    pub fn build_followup_prompt(
        finding: &Finding,
        previous_explanation: &str,
        question: &str,
    ) -> String {
        format!(
            r#"Based on our previous analysis of the security finding:

## Original Finding
- **Rule ID**: {rule_id}
- **Title**: {title}

## Previous Explanation Summary
{previous}

## Follow-up Question
{question}

Please provide a clear, focused answer to this follow-up question. If the question requires code examples, provide them. If it asks for clarification, be specific and detailed."#,
            rule_id = finding.rule_id,
            title = finding.title,
            previous = previous_explanation,
            question = question
        )
    }

    /// Build a batch prompt for multiple findings
    pub fn build_batch_prompt(findings: &[Finding], context: &ExplanationContext) -> String {
        let findings_text = findings
            .iter()
            .enumerate()
            .map(|(i, f)| {
                format!(
                    "### Finding {}\n- Rule ID: {}\n- Severity: {}\n- Title: {}\n- Description: {}",
                    i + 1,
                    f.rule_id,
                    f.severity,
                    f.title,
                    f.description
                )
            })
            .collect::<Vec<_>>()
            .join("\n\n");

        format!(
            r#"Analyze the following {} MCP server security findings and provide brief explanations.

## Server Context
- Server Name: {}
- Target Audience: {}

## Findings
{}

For each finding, provide a JSON array with objects containing:
- finding_index: The finding number (1-based)
- summary: Brief explanation (1-2 sentences)
- immediate_action: Single most important remediation step
- severity_justification: Why this severity level is appropriate

Respond with a JSON array."#,
            findings.len(),
            context.server_name,
            context.audience.description(),
            findings_text
        )
    }
}

/// Format a finding for inclusion in prompts
pub fn format_finding_for_prompt(finding: &Finding) -> String {
    format!(
        "Rule: {} | Severity: {} | {} - {}",
        finding.rule_id, finding.severity, finding.title, finding.description
    )
}

/// Get the appropriate detail level based on audience
pub fn detail_level_for_audience(audience: AudienceLevel) -> &'static str {
    match audience {
        AudienceLevel::Beginner => {
            "Use simple language, avoid jargon, explain security concepts from first principles"
        }
        AudienceLevel::Intermediate => {
            "Assume familiarity with basic security concepts, can use technical terms with brief explanations"
        }
        AudienceLevel::Expert => {
            "Use precise technical language, reference industry standards and frameworks, focus on advanced techniques"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::{Finding, FindingLocation, Severity};

    fn sample_finding() -> Finding {
        Finding::new(
            "MCP-INJ-001",
            Severity::Critical,
            "Command Injection",
            "Tool accepts unsanitized user input",
        )
        .with_location(FindingLocation::tool("execute_command"))
        .with_cwe("78")
    }

    #[test]
    fn prompt_builder_creates_valid_prompt() {
        let finding = sample_finding();
        let context = ExplanationContext::new("test-server").with_audience(AudienceLevel::Expert);

        let prompt = PromptBuilder::new()
            .with_finding(finding)
            .with_context(context)
            .build_finding_prompt();

        assert!(prompt.contains("MCP-INJ-001"));
        assert!(prompt.contains("Command Injection"));
        assert!(prompt.contains("CWE-78"));
        assert!(prompt.contains("security professional"));
    }

    #[test]
    fn followup_prompt_includes_context() {
        let finding = sample_finding();
        let prompt = PromptBuilder::build_followup_prompt(
            &finding,
            "Previous explanation here",
            "How can I test for this vulnerability?",
        );

        assert!(prompt.contains("MCP-INJ-001"));
        assert!(prompt.contains("Previous explanation"));
        assert!(prompt.contains("test for this vulnerability"));
    }

    #[test]
    fn batch_prompt_includes_all_findings() {
        let findings = vec![sample_finding(), sample_finding()];
        let context = ExplanationContext::default();

        let prompt = PromptBuilder::build_batch_prompt(&findings, &context);

        assert!(prompt.contains("Finding 1"));
        assert!(prompt.contains("Finding 2"));
        assert!(prompt.contains("2 MCP server security findings"));
    }
}
