//! Anthropic Provider - Claude API integration
//!
//! Implements the AiProvider trait for Anthropic's Claude models.

use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use async_trait::async_trait;
use futures::StreamExt;
use serde::{Deserialize, Serialize};

use crate::scanner::Finding;

use super::super::config::ExplanationContext;
use super::super::prompt::{PromptBuilder, SYSTEM_PROMPT};
use super::super::response::{
    CodeExample, EducationalContext, ExplanationMetadata, ExplanationResponse, Likelihood,
    RemediationGuide, ResourceCategory, ResourceLink, VulnerabilityExplanation, WeaknessInfo,
};
use super::super::streaming::{ChunkSender, StreamChunk};
use super::{AiProvider, AiProviderError};

/// Anthropic Claude API provider
pub struct AnthropicProvider {
    api_key: String,
    model: String,
    max_tokens: u32,
    temperature: f32,
    timeout: Duration,
    client: reqwest::Client,
}

impl AnthropicProvider {
    const API_URL: &'static str = "https://api.anthropic.com/v1/messages";
    const API_VERSION: &'static str = "2023-06-01";

    /// Create a new Anthropic provider
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

    /// Make a request to the Anthropic API
    async fn make_request(&self, messages: Vec<Message>) -> Result<ApiResponse> {
        let request = ApiRequest {
            model: self.model.clone(),
            max_tokens: self.max_tokens,
            temperature: Some(self.temperature),
            system: Some(SYSTEM_PROMPT.to_string()),
            messages,
        };

        let response = self
            .client
            .post(Self::API_URL)
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", Self::API_VERSION)
            .header("content-type", "application/json")
            .json(&request)
            .send()
            .await
            .context("Failed to send request to Anthropic API")?;

        let status = response.status();

        if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            return Err(AiProviderError::RateLimitExceeded {
                message: "Anthropic API rate limit exceeded".to_string(),
            }
            .into());
        }

        if !status.is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(AiProviderError::ApiError {
                provider: "Anthropic".to_string(),
                message: format!("HTTP {}: {}", status, error_text),
            }
            .into());
        }

        let api_response: ApiResponse = response
            .json()
            .await
            .context("Failed to parse Anthropic API response")?;

        Ok(api_response)
    }

    /// Make a streaming request to the Anthropic API
    async fn make_streaming_request(
        &self,
        messages: Vec<Message>,
        sender: ChunkSender,
    ) -> Result<(String, u32)> {
        let request = StreamingApiRequest {
            model: self.model.clone(),
            max_tokens: self.max_tokens,
            temperature: Some(self.temperature),
            system: Some(SYSTEM_PROMPT.to_string()),
            messages,
            stream: true,
        };

        let response = self
            .client
            .post(Self::API_URL)
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", Self::API_VERSION)
            .header("content-type", "application/json")
            .json(&request)
            .send()
            .await
            .context("Failed to send streaming request to Anthropic API")?;

        let status = response.status();

        if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            let _ = sender.send(StreamChunk::error("Rate limit exceeded")).await;
            return Err(AiProviderError::RateLimitExceeded {
                message: "Anthropic API rate limit exceeded".to_string(),
            }
            .into());
        }

        if !status.is_success() {
            let error_text = response.text().await.unwrap_or_default();
            let _ = sender
                .send(StreamChunk::error(format!(
                    "HTTP {}: {}",
                    status, error_text
                )))
                .await;
            return Err(AiProviderError::ApiError {
                provider: "Anthropic".to_string(),
                message: format!("HTTP {}: {}", status, error_text),
            }
            .into());
        }

        // Process the SSE stream
        let mut stream = response.bytes_stream();
        let mut accumulated_text = String::new();
        let mut total_tokens = 0u32;
        let mut buffer = String::new();

        while let Some(chunk_result) = stream.next().await {
            match chunk_result {
                Ok(bytes) => {
                    let text = String::from_utf8_lossy(&bytes);
                    buffer.push_str(&text);

                    // Process complete SSE events from buffer
                    while let Some(event_end) = buffer.find("\n\n") {
                        let event = buffer[..event_end].to_string();
                        buffer = buffer[event_end + 2..].to_string();

                        // Parse SSE event
                        if let Some(data_line) = event.lines().find(|l| l.starts_with("data: ")) {
                            let json_str = &data_line[6..];

                            // Skip [DONE] marker
                            if json_str.trim() == "[DONE]" {
                                continue;
                            }

                            // Parse the streaming event
                            if let Ok(sse_event) = serde_json::from_str::<StreamEvent>(json_str) {
                                match sse_event.event_type.as_str() {
                                    "content_block_delta" => {
                                        if let Some(delta) = sse_event.delta {
                                            if let Some(text) = delta.text {
                                                accumulated_text.push_str(&text);
                                                let _ = sender.send(StreamChunk::text(&text)).await;
                                            }
                                        }
                                    }
                                    "message_delta" => {
                                        if let Some(usage) = sse_event.usage {
                                            total_tokens = usage.input_tokens + usage.output_tokens;
                                            let _ = sender
                                                .send(StreamChunk::TokenUpdate {
                                                    input: usage.input_tokens,
                                                    output: usage.output_tokens,
                                                })
                                                .await;
                                        }
                                    }
                                    "message_stop" => {
                                        // Stream complete
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    let _ = sender
                        .send(StreamChunk::error(format!("Stream error: {}", e)))
                        .await;
                    return Err(anyhow::anyhow!("Stream error: {}", e));
                }
            }
        }

        let _ = sender.send(StreamChunk::Done).await;
        Ok((accumulated_text, total_tokens))
    }

    /// Parse the AI response into structured format
    fn parse_response(
        &self,
        finding: &Finding,
        response_text: &str,
        response_time_ms: u64,
        tokens_used: u32,
    ) -> Result<ExplanationResponse> {
        // Try to extract JSON from the response
        let json_str = extract_json(response_text)?;

        let parsed: ParsedExplanation =
            serde_json::from_str(&json_str).map_err(|e| AiProviderError::ParseError {
                message: format!("Failed to parse AI response: {}", e),
            })?;

        // Convert to our response type
        let explanation = VulnerabilityExplanation {
            summary: parsed.explanation.summary,
            technical_details: parsed.explanation.technical_details,
            attack_scenario: parsed.explanation.attack_scenario,
            impact: parsed.explanation.impact,
            likelihood: Likelihood::from_str(&parsed.explanation.likelihood)
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

        let metadata = ExplanationMetadata::new("anthropic", &self.model)
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
impl AiProvider for AnthropicProvider {
    fn name(&self) -> &'static str {
        "Anthropic"
    }

    fn model(&self) -> &str {
        &self.model
    }

    fn supports_streaming(&self) -> bool {
        true
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

        let messages = vec![Message {
            role: "user".to_string(),
            content: prompt,
        }];

        let response = self.make_request(messages).await?;

        let response_text = response
            .content
            .first()
            .map(|c| c.text.as_str())
            .unwrap_or("");

        let tokens_used = response.usage.output_tokens + response.usage.input_tokens;
        let response_time_ms = start.elapsed().as_millis() as u64;

        self.parse_response(finding, response_text, response_time_ms, tokens_used)
    }

    async fn explain_finding_streaming(
        &self,
        finding: &Finding,
        context: &ExplanationContext,
        sender: ChunkSender,
    ) -> Result<ExplanationResponse> {
        let start = Instant::now();

        let prompt = PromptBuilder::new()
            .with_finding(finding.clone())
            .with_context(context.clone())
            .build_finding_prompt();

        let messages = vec![Message {
            role: "user".to_string(),
            content: prompt,
        }];

        let (response_text, tokens_used) = self.make_streaming_request(messages, sender).await?;

        let response_time_ms = start.elapsed().as_millis() as u64;

        self.parse_response(finding, &response_text, response_time_ms, tokens_used)
    }

    async fn ask_followup(
        &self,
        explanation: &ExplanationResponse,
        question: &str,
    ) -> Result<String> {
        // Create a minimal finding for context
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

        let messages = vec![Message {
            role: "user".to_string(),
            content: prompt,
        }];

        let response = self.make_request(messages).await?;

        Ok(response
            .content
            .first()
            .map(|c| c.text.clone())
            .unwrap_or_default())
    }

    async fn health_check(&self) -> Result<bool> {
        // Simple health check - try to make a minimal request
        let messages = vec![Message {
            role: "user".to_string(),
            content: "Respond with just the word 'ok'".to_string(),
        }];

        let request = ApiRequest {
            model: self.model.clone(),
            max_tokens: 10,
            temperature: Some(0.0),
            system: None,
            messages,
        };

        let response = self
            .client
            .post(Self::API_URL)
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", Self::API_VERSION)
            .header("content-type", "application/json")
            .json(&request)
            .send()
            .await?;

        Ok(response.status().is_success())
    }
}

/// Extract JSON from a response that might have markdown code blocks
fn extract_json(text: &str) -> Result<String> {
    // Try to find JSON in code blocks
    if let Some(start) = text.find("```json") {
        if let Some(end) = text[start..]
            .find("```\n")
            .or_else(|| text[start..].rfind("```"))
        {
            let json_start = start + 7; // Skip "```json"
            let json_end = start + end;
            if json_start < json_end {
                return Ok(text[json_start..json_end].trim().to_string());
            }
        }
    }

    // Try to find JSON in regular code blocks
    if let Some(start) = text.find("```") {
        if let Some(end) = text[start + 3..].find("```") {
            let json_start = start + 3;
            let json_end = start + 3 + end;
            let content = text[json_start..json_end].trim();
            // Skip language identifier if present
            if let Some(newline) = content.find('\n') {
                return Ok(content[newline..].trim().to_string());
            }
        }
    }

    // Try to find raw JSON (starts with { and ends with })
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
struct ApiRequest {
    model: String,
    max_tokens: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    system: Option<String>,
    messages: Vec<Message>,
}

#[derive(Serialize)]
struct StreamingApiRequest {
    model: String,
    max_tokens: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    system: Option<String>,
    messages: Vec<Message>,
    stream: bool,
}

// Streaming event types
#[derive(Deserialize)]
struct StreamEvent {
    #[serde(rename = "type")]
    event_type: String,
    #[serde(default)]
    delta: Option<StreamDelta>,
    #[serde(default)]
    usage: Option<StreamUsage>,
}

#[derive(Deserialize)]
struct StreamDelta {
    #[serde(default)]
    text: Option<String>,
}

#[derive(Deserialize)]
struct StreamUsage {
    #[serde(default)]
    input_tokens: u32,
    #[serde(default)]
    output_tokens: u32,
}

#[derive(Serialize, Deserialize)]
struct Message {
    role: String,
    content: String,
}

#[derive(Deserialize)]
struct ApiResponse {
    content: Vec<ContentBlock>,
    usage: Usage,
}

#[derive(Deserialize)]
struct ContentBlock {
    text: String,
}

#[derive(Deserialize)]
struct Usage {
    input_tokens: u32,
    output_tokens: u32,
}

// Parsed response structure

#[derive(Deserialize)]
struct ParsedExplanation {
    explanation: ParsedVulnerability,
    remediation: ParsedRemediation,
    education: Option<ParsedEducation>,
}

#[derive(Deserialize)]
struct ParsedVulnerability {
    summary: String,
    technical_details: String,
    attack_scenario: String,
    impact: String,
    likelihood: String,
}

#[derive(Deserialize)]
struct ParsedRemediation {
    immediate_actions: Vec<String>,
    permanent_fix: String,
    code_example: Option<ParsedCodeExample>,
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
    fn extract_json_from_code_block() {
        let text = r#"Here's my analysis:
```json
{"key": "value"}
```
"#;
        let result = extract_json(text).unwrap();
        assert!(result.contains("key"));
    }

    #[test]
    fn extract_raw_json() {
        let text = r#"The response is {"key": "value"} as shown."#;
        let result = extract_json(text).unwrap();
        assert_eq!(result, r#"{"key": "value"}"#);
    }
}
