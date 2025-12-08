//! AI Provider - Provider trait and implementations
//!
//! Defines the trait for AI providers and provides implementations
//! for Anthropic, OpenAI, Ollama, and a Mock provider for testing.

pub mod anthropic;
pub mod mock;
pub mod ollama;
pub mod openai;

use anyhow::Result;
use async_trait::async_trait;

use crate::scanner::Finding;

use super::config::ExplanationContext;
use super::response::ExplanationResponse;
use super::streaming::ChunkSender;

// Re-exports
pub use anthropic::AnthropicProvider;
pub use mock::MockProvider;
pub use ollama::OllamaProvider;
pub use openai::OpenAiProvider;

/// Trait for AI providers that can generate vulnerability explanations
#[async_trait]
pub trait AiProvider: Send + Sync {
    /// Provider name
    fn name(&self) -> &'static str;

    /// Model being used
    fn model(&self) -> &str;

    /// Check if this provider supports streaming
    fn supports_streaming(&self) -> bool {
        false
    }

    /// Generate explanation for a single finding
    async fn explain_finding(
        &self,
        finding: &Finding,
        context: &ExplanationContext,
    ) -> Result<ExplanationResponse>;

    /// Generate explanation with streaming output
    ///
    /// Sends chunks through the provided sender as they arrive.
    /// Returns the final complete response.
    async fn explain_finding_streaming(
        &self,
        finding: &Finding,
        context: &ExplanationContext,
        sender: ChunkSender,
    ) -> Result<ExplanationResponse> {
        // Default implementation: fall back to non-streaming
        use super::streaming::StreamChunk;

        let response = self.explain_finding(finding, context).await?;

        // Send the complete response as a single chunk
        let _ = sender.send(StreamChunk::text(&response.explanation.summary)).await;
        let _ = sender.send(StreamChunk::Done).await;

        Ok(response)
    }

    /// Generate explanations for multiple findings (batch)
    async fn explain_batch(
        &self,
        findings: &[Finding],
        context: &ExplanationContext,
    ) -> Result<Vec<ExplanationResponse>> {
        // Default implementation: sequential processing
        let mut results = Vec::with_capacity(findings.len());
        for finding in findings {
            let explanation = self.explain_finding(finding, context).await?;
            results.push(explanation);
        }
        Ok(results)
    }

    /// Interactive follow-up question
    async fn ask_followup(
        &self,
        explanation: &ExplanationResponse,
        question: &str,
    ) -> Result<String>;

    /// Interactive follow-up with streaming
    async fn ask_followup_streaming(
        &self,
        explanation: &ExplanationResponse,
        question: &str,
        sender: ChunkSender,
    ) -> Result<String> {
        // Default implementation: fall back to non-streaming
        use super::streaming::StreamChunk;

        let response = self.ask_followup(explanation, question).await?;

        // Send the complete response as a single chunk
        let _ = sender.send(StreamChunk::text(&response)).await;
        let _ = sender.send(StreamChunk::Done).await;

        Ok(response)
    }

    /// Check if provider is available and configured correctly
    async fn health_check(&self) -> Result<bool>;
}

/// Error types for AI providers
#[derive(Debug, thiserror::Error)]
pub enum AiProviderError {
    #[error("API key not configured for {provider}")]
    MissingApiKey { provider: String },

    #[error("Rate limit exceeded: {message}")]
    RateLimitExceeded { message: String },

    #[error("API error from {provider}: {message}")]
    ApiError { provider: String, message: String },

    #[error("Invalid response from {provider}: {message}")]
    InvalidResponse { provider: String, message: String },

    #[error("Request timeout after {seconds}s")]
    Timeout { seconds: u64 },

    #[error("Provider {provider} is not available: {reason}")]
    Unavailable { provider: String, reason: String },

    #[error("Failed to parse AI response: {message}")]
    ParseError { message: String },
}

/// Create a provider based on configuration
pub fn create_provider(config: &super::config::AiConfig) -> Result<Box<dyn AiProvider>> {
    match config.provider {
        super::config::AiProvider::Anthropic => {
            let api_key = config
                .api_key
                .clone()
                .or_else(|| std::env::var("ANTHROPIC_API_KEY").ok())
                .ok_or_else(|| AiProviderError::MissingApiKey {
                    provider: "Anthropic".to_string(),
                })?;

            Ok(Box::new(AnthropicProvider::new(
                api_key,
                config.model.clone(),
                config.max_tokens,
                config.temperature,
                config.timeout(),
            )))
        }
        super::config::AiProvider::OpenAI => {
            let api_key = config
                .api_key
                .clone()
                .or_else(|| std::env::var("OPENAI_API_KEY").ok())
                .ok_or_else(|| AiProviderError::MissingApiKey {
                    provider: "OpenAI".to_string(),
                })?;

            Ok(Box::new(OpenAiProvider::new(
                api_key,
                config.model.clone(),
                config.max_tokens,
                config.temperature,
                config.timeout(),
            )))
        }
        super::config::AiProvider::Ollama => Ok(Box::new(OllamaProvider::new(
            config.ollama_url.clone(),
            config.model.clone(),
            config.timeout(),
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display() {
        let err = AiProviderError::MissingApiKey {
            provider: "Anthropic".to_string(),
        };
        assert!(err.to_string().contains("Anthropic"));

        let err = AiProviderError::RateLimitExceeded {
            message: "Too many requests".to_string(),
        };
        assert!(err.to_string().contains("Rate limit"));
    }
}
