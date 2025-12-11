//! Ollama Provider - Local model integration
//!
//! Implements the AiProvider trait for locally-running Ollama models.
//! Supports air-gapped environments and offline use.

use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::scanner::Finding;

use super::super::config::ExplanationContext;
use super::super::prompt::{PromptBuilder, SYSTEM_PROMPT};
use super::super::response::{
    CodeExample, EducationalContext, ExplanationMetadata, ExplanationResponse, Likelihood,
    RemediationGuide, ResourceCategory, ResourceLink, VulnerabilityExplanation, WeaknessInfo,
};
use super::{AiProvider, AiProviderError};

/// Ollama local model provider
pub struct OllamaProvider {
    base_url: String,
    model: String,
    timeout: Duration,
    client: reqwest::Client,
}

impl OllamaProvider {
    /// Create a new Ollama provider
    pub fn new(base_url: String, model: String, timeout: Duration) -> Self {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .expect("Failed to create HTTP client");

        Self {
            base_url,
            model,
            timeout,
            client,
        }
    }

    /// Get the API endpoint URL
    fn api_url(&self) -> String {
        format!("{}/api/generate", self.base_url.trim_end_matches('/'))
    }

    /// Get the chat API endpoint URL
    fn chat_url(&self) -> String {
        format!("{}/api/chat", self.base_url.trim_end_matches('/'))
    }

    /// Make a request to the Ollama API
    async fn make_request(&self, prompt: &str, system: Option<&str>) -> Result<GenerateResponse> {
        // Note: We intentionally do NOT use format: "json" here.
        // Ollama's JSON format mode uses constrained decoding which can be
        // extremely slow (10-100x slower) on resource-limited environments.
        // Instead, we ask for JSON in the prompt and parse what we can from
        // the response. This is more reliable for local models.
        let request = GenerateRequest {
            model: self.model.clone(),
            prompt: prompt.to_string(),
            system: system.map(|s| s.to_string()),
            stream: Some(false),
            format: None, // Disabled - constrained decoding too slow on CI
            options: Some(GenerateOptions {
                temperature: Some(0.3),
                num_predict: Some(2048),
            }),
        };

        let response = self
            .client
            .post(self.api_url())
            .json(&request)
            .send()
            .await
            .context("Failed to send request to Ollama API")?;

        let status = response.status();

        if !status.is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(AiProviderError::ApiError {
                provider: "Ollama".to_string(),
                message: format!("HTTP {}: {}", status, error_text),
            }
            .into());
        }

        let api_response: GenerateResponse = response
            .json()
            .await
            .context("Failed to parse Ollama API response")?;

        Ok(api_response)
    }

    /// Parse the AI response into structured format
    fn parse_response(
        &self,
        finding: &Finding,
        response_text: &str,
        response_time_ms: u64,
    ) -> Result<ExplanationResponse> {
        // Try to extract JSON from the response
        let json_str = extract_json(response_text)?;

        // Try to parse as structured JSON first
        let parsed: ParsedExplanation = match serde_json::from_str(&json_str) {
            Ok(p) => p,
            Err(_) => {
                // Fallback: create a minimal response from the raw text
                // This handles cases where local models don't produce perfect JSON
                return Ok(self.create_fallback_response(finding, response_text, response_time_ms));
            }
        };

        let explanation = VulnerabilityExplanation {
            summary: parsed.explanation.summary,
            technical_details: parsed.explanation.technical_details,
            attack_scenario: parsed.explanation.attack_scenario,
            impact: parsed.explanation.impact,
            likelihood: parsed
                .explanation
                .likelihood
                .parse()
                .unwrap_or(Likelihood::Medium),
        };

        let code_example = parsed.remediation.code_example.map(|ce| {
            CodeExample::new(ce.language, ce.before, ce.after).with_explanation(ce.explanation)
        });

        let remediation = RemediationGuide {
            immediate_actions: parsed.remediation.immediate_actions,
            permanent_fix: parsed.remediation.permanent_fix,
            code_example,
            verification: parsed.remediation.verification,
            ..Default::default()
        };

        let education = parsed.education.map(|edu| {
            let related_weaknesses = edu
                .related_weaknesses
                .into_iter()
                .map(|w| WeaknessInfo::new(w.cwe_id, w.name, w.description))
                .collect();

            let resources = edu
                .resources
                .into_iter()
                .map(|r| ResourceLink {
                    title: r.title,
                    url: r.url,
                    category: match r.category.as_str() {
                        "article" => ResourceCategory::Article,
                        "tool" => ResourceCategory::Tool,
                        "video" => ResourceCategory::Video,
                        "course" => ResourceCategory::Course,
                        _ => ResourceCategory::Documentation,
                    },
                })
                .collect();

            EducationalContext {
                related_weaknesses,
                similar_patterns: edu.similar_patterns,
                best_practices: edu.best_practices,
                resources,
            }
        });

        let metadata =
            ExplanationMetadata::new("ollama", &self.model).with_response_time(response_time_ms);

        let mut response = ExplanationResponse::new(&finding.id, &finding.rule_id)
            .with_explanation(explanation)
            .with_remediation(remediation)
            .with_metadata(metadata);

        if let Some(edu) = education {
            response = response.with_education(edu);
        }

        Ok(response)
    }

    /// Create a fallback response when JSON parsing fails
    /// Extracts what we can from free-form text
    fn create_fallback_response(
        &self,
        finding: &Finding,
        response_text: &str,
        response_time_ms: u64,
    ) -> ExplanationResponse {
        // Use the raw response as the summary, truncating if too long
        let summary = if response_text.len() > 500 {
            format!("{}...", &response_text[..500])
        } else {
            response_text.to_string()
        };

        let explanation = VulnerabilityExplanation {
            summary,
            technical_details: String::new(),
            attack_scenario: String::new(),
            impact: String::new(),
            likelihood: Likelihood::Medium,
        };

        let metadata =
            ExplanationMetadata::new("ollama", &self.model).with_response_time(response_time_ms);

        ExplanationResponse::new(&finding.id, &finding.rule_id)
            .with_explanation(explanation)
            .with_metadata(metadata)
    }
}

#[async_trait]
impl AiProvider for OllamaProvider {
    fn name(&self) -> &'static str {
        "Ollama"
    }

    fn model(&self) -> &str {
        &self.model
    }

    async fn explain_finding(
        &self,
        finding: &Finding,
        context: &ExplanationContext,
    ) -> Result<ExplanationResponse> {
        let start = Instant::now();

        let prompt = PromptBuilder::new()
            .with_finding(finding.clone())
            .with_context(context.clone())
            .build_finding_prompt();

        let response = self.make_request(&prompt, Some(SYSTEM_PROMPT)).await?;
        let response_time_ms = start.elapsed().as_millis() as u64;

        self.parse_response(finding, &response.response, response_time_ms)
    }

    async fn ask_followup(
        &self,
        explanation: &ExplanationResponse,
        question: &str,
    ) -> Result<String> {
        let finding = Finding::new(
            &explanation.rule_id,
            crate::scanner::Severity::Medium,
            &explanation.explanation.summary,
            "",
        );

        let prompt = PromptBuilder::build_followup_prompt(
            &finding,
            &explanation.explanation.summary,
            question,
        );

        let response = self.make_request(&prompt, Some(SYSTEM_PROMPT)).await?;

        Ok(response.response)
    }

    async fn health_check(&self) -> Result<bool> {
        // Check if Ollama is running by hitting the version endpoint
        let url = format!("{}/api/version", self.base_url.trim_end_matches('/'));

        match self.client.get(&url).send().await {
            Ok(response) => Ok(response.status().is_success()),
            Err(_) => Ok(false),
        }
    }
}

/// Sanitize JSON string by properly escaping control characters within string values
fn sanitize_json(text: &str) -> String {
    let mut result = String::with_capacity(text.len());
    let mut in_string = false;
    let mut escape_next = false;

    for c in text.chars() {
        if escape_next {
            // Previous char was backslash, this char is escaped
            result.push(c);
            escape_next = false;
            continue;
        }

        match c {
            '\\' if in_string => {
                result.push(c);
                escape_next = true;
            }
            '"' => {
                in_string = !in_string;
                result.push(c);
            }
            '\n' | '\r' if in_string => {
                result.push_str("\\n");
            }
            '\t' if in_string => {
                result.push_str("\\t");
            }
            c if c.is_control() => {
                result.push(' ');
            }
            _ => {
                result.push(c);
            }
        }
    }
    result
}

/// Extract JSON from a response that might have extra text
fn extract_json(text: &str) -> Result<String> {
    // Sanitize the text first
    let text = sanitize_json(text);

    // Try to find JSON object
    if let Some(start) = text.find('{') {
        if let Some(end) = text.rfind('}') {
            if start < end {
                return Ok(text[start..=end].to_string());
            }
        }
    }

    // Return the whole text if no JSON found
    Ok(text.to_string())
}

// API Request/Response types

#[derive(Serialize)]
struct GenerateRequest {
    model: String,
    prompt: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    system: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stream: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    format: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    options: Option<GenerateOptions>,
}

#[derive(Serialize)]
struct GenerateOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    num_predict: Option<u32>,
}

#[derive(Deserialize)]
struct GenerateResponse {
    response: String,
}

// Parsed response structure (same as other providers)

#[derive(Deserialize)]
struct ParsedExplanation {
    explanation: ParsedVulnerability,
    #[serde(default)]
    remediation: ParsedRemediation,
    education: Option<ParsedEducation>,
}

#[derive(Deserialize)]
struct ParsedVulnerability {
    summary: String,
    #[serde(default)]
    technical_details: String,
    #[serde(default)]
    attack_scenario: String,
    #[serde(default)]
    impact: String,
    #[serde(default = "default_likelihood")]
    likelihood: String,
}

fn default_likelihood() -> String {
    "medium".to_string()
}

#[derive(Deserialize, Default)]
struct ParsedRemediation {
    #[serde(default)]
    immediate_actions: Vec<String>,
    #[serde(default)]
    permanent_fix: String,
    code_example: Option<ParsedCodeExample>,
    #[serde(default)]
    verification: Vec<String>,
}

#[derive(Deserialize)]
struct ParsedCodeExample {
    language: String,
    before: String,
    after: String,
    explanation: String,
}

#[derive(Deserialize)]
struct ParsedEducation {
    related_weaknesses: Vec<ParsedWeakness>,
    similar_patterns: Vec<String>,
    best_practices: Vec<String>,
    resources: Vec<ParsedResource>,
}

#[derive(Deserialize)]
struct ParsedWeakness {
    cwe_id: String,
    name: String,
    description: String,
}

#[derive(Deserialize)]
struct ParsedResource {
    title: String,
    url: String,
    category: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_json_finds_object() {
        let text = r#"Here is the analysis: {"key": "value"} as requested"#;
        let result = extract_json(text).unwrap();
        assert_eq!(result, r#"{"key": "value"}"#);
    }

    #[test]
    fn api_url_construction() {
        let provider = OllamaProvider::new(
            "http://localhost:11434".to_string(),
            "llama3.2".to_string(),
            Duration::from_secs(120),
        );
        assert_eq!(provider.api_url(), "http://localhost:11434/api/generate");

        let provider2 = OllamaProvider::new(
            "http://localhost:11434/".to_string(),
            "llama3.2".to_string(),
            Duration::from_secs(120),
        );
        assert_eq!(provider2.api_url(), "http://localhost:11434/api/generate");
    }
}
