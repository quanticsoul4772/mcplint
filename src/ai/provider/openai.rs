//! OpenAI Provider - GPT API integration
//!
//! Implements the AiProvider trait for OpenAI's GPT models.

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

/// OpenAI GPT API provider
pub struct OpenAiProvider {
    api_key: String,
    model: String,
    max_tokens: u32,
    temperature: f32,
    timeout: Duration,
    client: reqwest::Client,
}

impl OpenAiProvider {
    const API_URL: &'static str = "https://api.openai.com/v1/chat/completions";

    /// Create a new OpenAI provider
    pub fn new(
        api_key: String,
        model: String,
        max_tokens: u32,
        temperature: f32,
        timeout: Duration,
    ) -> Self {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .expect("Failed to create HTTP client");

        Self {
            api_key,
            model,
            max_tokens,
            temperature,
            timeout,
            client,
        }
    }

    /// Make a request to the OpenAI API
    async fn make_request(&self, messages: Vec<ChatMessage>) -> Result<ChatResponse> {
        let request = ChatRequest {
            model: self.model.clone(),
            messages,
            max_tokens: Some(self.max_tokens),
            temperature: Some(self.temperature),
            response_format: Some(ResponseFormat {
                type_field: "json_object".to_string(),
            }),
        };

        let response = self
            .client
            .post(Self::API_URL)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await
            .context("Failed to send request to OpenAI API")?;

        let status = response.status();

        if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            return Err(AiProviderError::RateLimitExceeded {
                message: "OpenAI API rate limit exceeded".to_string(),
            }
            .into());
        }

        if !status.is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(AiProviderError::ApiError {
                provider: "OpenAI".to_string(),
                message: format!("HTTP {}: {}", status, error_text),
            }
            .into());
        }

        let api_response: ChatResponse = response
            .json()
            .await
            .context("Failed to parse OpenAI API response")?;

        Ok(api_response)
    }

    /// Parse the AI response into structured format
    fn parse_response(
        &self,
        finding: &Finding,
        response_text: &str,
        response_time_ms: u64,
        tokens_used: u32,
    ) -> Result<ExplanationResponse> {
        // Sanitize the response to handle control characters
        let sanitized = sanitize_json(response_text);

        let parsed: ParsedExplanation =
            serde_json::from_str(&sanitized).map_err(|e| AiProviderError::ParseError {
                message: format!("Failed to parse AI response: {}", e),
            })?;

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

        let metadata = ExplanationMetadata::new("openai", &self.model)
            .with_tokens(tokens_used)
            .with_response_time(response_time_ms);

        let mut response = ExplanationResponse::new(&finding.id, &finding.rule_id)
            .with_explanation(explanation)
            .with_remediation(remediation)
            .with_metadata(metadata);

        if let Some(edu) = education {
            response = response.with_education(edu);
        }

        Ok(response)
    }
}

#[async_trait]
impl AiProvider for OpenAiProvider {
    fn name(&self) -> &'static str {
        "OpenAI"
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

        let messages = vec![
            ChatMessage {
                role: "system".to_string(),
                content: SYSTEM_PROMPT.to_string(),
            },
            ChatMessage {
                role: "user".to_string(),
                content: prompt,
            },
        ];

        let response = self.make_request(messages).await?;

        let response_text = response
            .choices
            .first()
            .map(|c| c.message.content.as_str())
            .unwrap_or("");

        let tokens_used = response.usage.map(|u| u.total_tokens).unwrap_or(0);
        let response_time_ms = start.elapsed().as_millis() as u64;

        self.parse_response(finding, response_text, response_time_ms, tokens_used)
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

        let messages = vec![
            ChatMessage {
                role: "system".to_string(),
                content: SYSTEM_PROMPT.to_string(),
            },
            ChatMessage {
                role: "user".to_string(),
                content: prompt,
            },
        ];

        let response = self.make_request(messages).await?;

        Ok(response
            .choices
            .first()
            .map(|c| c.message.content.clone())
            .unwrap_or_default())
    }

    async fn health_check(&self) -> Result<bool> {
        let messages = vec![
            ChatMessage {
                role: "system".to_string(),
                content: "You are a helpful assistant.".to_string(),
            },
            ChatMessage {
                role: "user".to_string(),
                content: "Respond with just the word 'ok'".to_string(),
            },
        ];

        let request = ChatRequest {
            model: self.model.clone(),
            messages,
            max_tokens: Some(10),
            temperature: Some(0.0),
            response_format: None,
        };

        let response = self
            .client
            .post(Self::API_URL)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await?;

        Ok(response.status().is_success())
    }
}

// API Request/Response types

#[derive(Serialize)]
struct ChatRequest {
    model: String,
    messages: Vec<ChatMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_format: Option<ResponseFormat>,
}

#[derive(Serialize)]
struct ResponseFormat {
    #[serde(rename = "type")]
    type_field: String,
}

#[derive(Serialize, Deserialize)]
struct ChatMessage {
    role: String,
    content: String,
}

#[derive(Deserialize)]
struct ChatResponse {
    choices: Vec<Choice>,
    usage: Option<TokenUsage>,
}

#[derive(Deserialize)]
struct Choice {
    message: ChatMessage,
}

#[derive(Deserialize)]
struct TokenUsage {
    total_tokens: u32,
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

// Parsed response structure (same as Anthropic)

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
