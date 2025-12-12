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
        let _ = sender
            .send(StreamChunk::text(&response.explanation.summary))
            .await;
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
    use crate::scanner::Severity;

    fn sample_finding() -> Finding {
        Finding::new(
            "MCP-TEST-001",
            Severity::High,
            "Test Finding",
            "This is a test finding for unit tests",
        )
    }

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

    #[test]
    fn all_error_variants_display() {
        let errors = vec![
            AiProviderError::MissingApiKey {
                provider: "TestProvider".to_string(),
            },
            AiProviderError::RateLimitExceeded {
                message: "Limit exceeded".to_string(),
            },
            AiProviderError::ApiError {
                provider: "TestProvider".to_string(),
                message: "API failed".to_string(),
            },
            AiProviderError::InvalidResponse {
                provider: "TestProvider".to_string(),
                message: "Bad JSON".to_string(),
            },
            AiProviderError::Timeout { seconds: 30 },
            AiProviderError::Unavailable {
                provider: "TestProvider".to_string(),
                reason: "Service down".to_string(),
            },
            AiProviderError::ParseError {
                message: "Parse failed".to_string(),
            },
        ];

        for error in errors {
            let display = error.to_string();
            assert!(!display.is_empty(), "Error should have non-empty display");
        }
    }

    #[test]
    fn create_provider_ollama_success() {
        let config = super::super::config::AiConfig::builder()
            .provider(super::super::config::AiProvider::Ollama)
            .model("llama3.2")
            .build();

        let result = create_provider(&config);
        assert!(result.is_ok());

        let provider = result.unwrap();
        assert_eq!(provider.name(), "Ollama");
        assert_eq!(provider.model(), "llama3.2");
    }

    #[test]
    fn create_provider_anthropic_missing_key() {
        // Clear env var to ensure it's not set
        std::env::remove_var("ANTHROPIC_API_KEY");

        let config = super::super::config::AiConfig::builder()
            .provider(super::super::config::AiProvider::Anthropic)
            .model("claude-3-5-sonnet-20241022")
            .build();

        let result = create_provider(&config);
        assert!(result.is_err(), "Should fail without API key");
    }

    #[test]
    fn create_provider_anthropic_with_config_key() {
        let config = super::super::config::AiConfig::builder()
            .provider(super::super::config::AiProvider::Anthropic)
            .model("claude-3-5-sonnet-20241022")
            .api_key("test-key")
            .build();

        let result = create_provider(&config);
        assert!(result.is_ok());

        let provider = result.unwrap();
        assert_eq!(provider.name(), "Anthropic");
        assert_eq!(provider.model(), "claude-3-5-sonnet-20241022");
    }

    #[test]
    fn create_provider_openai_missing_key() {
        // Clear env var to ensure it's not set
        std::env::remove_var("OPENAI_API_KEY");

        let config = super::super::config::AiConfig::builder()
            .provider(super::super::config::AiProvider::OpenAI)
            .model("gpt-4")
            .build();

        let result = create_provider(&config);
        assert!(result.is_err(), "Should fail without API key");
    }

    #[test]
    fn create_provider_openai_with_config_key() {
        let config = super::super::config::AiConfig::builder()
            .provider(super::super::config::AiProvider::OpenAI)
            .model("gpt-4")
            .api_key("test-key")
            .build();

        let result = create_provider(&config);
        assert!(result.is_ok());

        let provider = result.unwrap();
        assert_eq!(provider.name(), "OpenAI");
        assert_eq!(provider.model(), "gpt-4");
    }

    #[tokio::test]
    async fn provider_trait_default_streaming() {
        let provider = MockProvider::new();
        let finding = sample_finding();
        let context = ExplanationContext::default();

        let (sender, mut receiver) = super::super::streaming::stream_channel(32);

        // Test that default implementation falls back to non-streaming
        let result = provider
            .explain_finding_streaming(&finding, &context, sender)
            .await;
        assert!(result.is_ok());

        // Should get at least a Done chunk
        let mut got_chunk = false;
        while let Ok(chunk) = receiver.try_recv() {
            got_chunk = true;
            if chunk.is_terminal() {
                break;
            }
        }
        assert!(got_chunk);
    }

    #[tokio::test]
    async fn provider_trait_default_batch() {
        let provider = MockProvider::new();
        let findings = vec![
            sample_finding(),
            Finding::new(
                "MCP-TEST-002",
                Severity::Medium,
                "Second Finding",
                "Another test",
            ),
        ];
        let context = ExplanationContext::default();

        // Default batch implementation should process sequentially
        let result = provider.explain_batch(&findings, &context).await;
        assert!(result.is_ok());

        let responses = result.unwrap();
        assert_eq!(responses.len(), 2);
        assert_eq!(responses[0].finding_id, findings[0].id);
        assert_eq!(responses[1].finding_id, findings[1].id);
    }

    #[tokio::test]
    async fn provider_trait_default_followup_streaming() {
        let provider = MockProvider::new();
        let explanation = ExplanationResponse::new("test", "TEST-001");

        let (sender, mut receiver) = super::super::streaming::stream_channel(32);

        // Test default implementation
        let result = provider
            .ask_followup_streaming(&explanation, "How to fix?", sender)
            .await;
        assert!(result.is_ok());

        // Should get at least a Done chunk
        let mut got_chunk = false;
        while let Ok(chunk) = receiver.try_recv() {
            got_chunk = true;
            if chunk.is_terminal() {
                break;
            }
        }
        assert!(got_chunk);
    }

    #[test]
    fn provider_trait_default_supports_streaming() {
        // Create a minimal provider to test default trait method
        struct MinimalProvider;

        #[async_trait::async_trait]
        impl AiProvider for MinimalProvider {
            fn name(&self) -> &'static str {
                "Minimal"
            }
            fn model(&self) -> &str {
                "test"
            }
            async fn explain_finding(
                &self,
                _: &Finding,
                _: &ExplanationContext,
            ) -> Result<ExplanationResponse> {
                Ok(ExplanationResponse::new("test", "TEST"))
            }
            async fn ask_followup(&self, _: &ExplanationResponse, _: &str) -> Result<String> {
                Ok("test".to_string())
            }
            async fn health_check(&self) -> Result<bool> {
                Ok(true)
            }
        }

        let provider = MinimalProvider;
        // Default implementation should return false
        assert!(!provider.supports_streaming());
    }
}
