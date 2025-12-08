//! Mock Provider - Testing implementation
//!
//! Provides a mock AI provider for unit testing without network calls.

use anyhow::Result;
use async_trait::async_trait;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::scanner::Finding;

use super::super::config::ExplanationContext;
use super::super::response::{
    CodeExample, EducationalContext, ExplanationMetadata, ExplanationResponse, Likelihood,
    RemediationGuide, ResourceLink, VulnerabilityExplanation, WeaknessInfo,
};
use super::super::streaming::{ChunkSender, StreamChunk};
use super::AiProvider;

/// Mock AI provider for testing
pub struct MockProvider {
    /// Model name to report
    model: String,
    /// Simulated response delay in milliseconds
    delay_ms: u64,
    /// Track number of calls
    call_count: AtomicU32,
    /// Custom responses (if set)
    custom_responses: Arc<Mutex<Vec<ExplanationResponse>>>,
    /// Whether to simulate errors
    should_fail: Arc<Mutex<bool>>,
    /// Error message to return when failing
    error_message: Arc<Mutex<String>>,
}

impl MockProvider {
    /// Create a new mock provider
    pub fn new() -> Self {
        Self {
            model: "mock-model-v1".to_string(),
            delay_ms: 0,
            call_count: AtomicU32::new(0),
            custom_responses: Arc::new(Mutex::new(Vec::new())),
            should_fail: Arc::new(Mutex::new(false)),
            error_message: Arc::new(Mutex::new("Mock error".to_string())),
        }
    }

    /// Set the model name
    pub fn with_model(mut self, model: impl Into<String>) -> Self {
        self.model = model.into();
        self
    }

    /// Set simulated delay
    pub fn with_delay(mut self, delay_ms: u64) -> Self {
        self.delay_ms = delay_ms;
        self
    }

    /// Add a custom response to return
    pub async fn add_response(&self, response: ExplanationResponse) {
        let mut responses = self.custom_responses.lock().await;
        responses.push(response);
    }

    /// Set the provider to fail on next call
    pub async fn set_should_fail(&self, should_fail: bool, message: &str) {
        *self.should_fail.lock().await = should_fail;
        *self.error_message.lock().await = message.to_string();
    }

    /// Get the number of calls made
    pub fn call_count(&self) -> u32 {
        self.call_count.load(Ordering::SeqCst)
    }

    /// Reset call count
    pub fn reset_call_count(&self) {
        self.call_count.store(0, Ordering::SeqCst);
    }

    /// Generate a default mock explanation for a finding
    fn generate_mock_explanation(&self, finding: &Finding) -> ExplanationResponse {
        ExplanationResponse::new(&finding.id, &finding.rule_id)
            .with_explanation(
                VulnerabilityExplanation::new(format!(
                    "This is a mock explanation for {} vulnerability.",
                    finding.title
                ))
                .with_technical_details(format!(
                    "The {} vulnerability was detected with {} severity. \
                    This is simulated technical analysis for testing purposes.",
                    finding.rule_id, finding.severity
                ))
                .with_attack_scenario(
                    "An attacker could potentially exploit this vulnerability \
                    in a testing scenario. This is mock content."
                        .to_string(),
                )
                .with_impact(
                    "Mock impact assessment: This could affect system security \
                    if this were a real finding."
                        .to_string(),
                )
                .with_likelihood(Likelihood::Medium),
            )
            .with_remediation(
                RemediationGuide::new("Apply the recommended security fix for this vulnerability type.")
                    .with_immediate_actions(vec![
                        "Review the affected code".to_string(),
                        "Apply input validation".to_string(),
                        "Test the fix thoroughly".to_string(),
                    ])
                    .with_code_example(CodeExample::new(
                        "rust",
                        "// Vulnerable code\nlet input = user_data;",
                        "// Fixed code\nlet input = sanitize(user_data);",
                    ).with_explanation("Added input sanitization to prevent the vulnerability."))
                    .with_verification(vec![
                        "Run the security scanner again".to_string(),
                        "Verify the fix in staging environment".to_string(),
                    ]),
            )
            .with_education(
                EducationalContext::default()
                    .add_weakness(WeaknessInfo::new(
                        "CWE-20",
                        "Improper Input Validation",
                        "The software does not validate or incorrectly validates input.",
                    ))
                    .add_best_practice("Always validate and sanitize user input".to_string())
                    .add_best_practice("Use allowlists rather than blocklists".to_string())
                    .add_resource(ResourceLink::documentation(
                        "OWASP Input Validation Cheat Sheet",
                        "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html",
                    )),
            )
            .with_metadata(
                ExplanationMetadata::new("Mock", &self.model)
                    .with_tokens(500)
                    .with_response_time(self.delay_ms),
            )
    }
}

impl Default for MockProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl AiProvider for MockProvider {
    fn name(&self) -> &'static str {
        "Mock"
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
        _context: &ExplanationContext,
    ) -> Result<ExplanationResponse> {
        // Increment call count
        self.call_count.fetch_add(1, Ordering::SeqCst);

        // Check if we should fail
        if *self.should_fail.lock().await {
            let message = self.error_message.lock().await.clone();
            anyhow::bail!("{}", message);
        }

        // Simulate delay if configured
        if self.delay_ms > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(self.delay_ms)).await;
        }

        // Check for custom response
        let mut responses = self.custom_responses.lock().await;
        if !responses.is_empty() {
            return Ok(responses.remove(0));
        }

        // Generate default mock response
        Ok(self.generate_mock_explanation(finding))
    }

    async fn explain_finding_streaming(
        &self,
        finding: &Finding,
        context: &ExplanationContext,
        sender: ChunkSender,
    ) -> Result<ExplanationResponse> {
        // Get the non-streaming response
        let response = self.explain_finding(finding, context).await?;

        // Simulate streaming by sending chunks of the summary
        let summary = &response.explanation.summary;
        let words: Vec<&str> = summary.split_whitespace().collect();

        for word in words {
            let _ = sender.send(StreamChunk::text(format!("{} ", word))).await;
            // Small delay to simulate streaming
            if self.delay_ms > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        }

        let _ = sender
            .send(StreamChunk::TokenUpdate {
                input: 100,
                output: 400,
            })
            .await;
        let _ = sender.send(StreamChunk::Done).await;

        Ok(response)
    }

    async fn ask_followup(
        &self,
        _explanation: &ExplanationResponse,
        question: &str,
    ) -> Result<String> {
        self.call_count.fetch_add(1, Ordering::SeqCst);

        if *self.should_fail.lock().await {
            let message = self.error_message.lock().await.clone();
            anyhow::bail!("{}", message);
        }

        if self.delay_ms > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(self.delay_ms)).await;
        }

        Ok(format!(
            "Mock follow-up response to your question: '{}'\n\n\
            This is a simulated response for testing purposes. In a real scenario, \
            the AI would provide detailed answers based on the context of the \
            previous explanation.",
            question
        ))
    }

    async fn health_check(&self) -> Result<bool> {
        // Mock provider is always available
        Ok(true)
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
            "Test Vulnerability",
            "This is a test finding for unit tests",
        )
    }

    #[tokio::test]
    async fn mock_provider_generates_response() {
        let provider = MockProvider::new();
        let finding = sample_finding();
        let context = ExplanationContext::default();

        let result = provider.explain_finding(&finding, &context).await;
        assert!(result.is_ok());

        let explanation = result.unwrap();
        assert_eq!(explanation.finding_id, finding.id);
        assert_eq!(explanation.rule_id, finding.rule_id);
        assert!(!explanation.explanation.summary.is_empty());
    }

    #[tokio::test]
    async fn mock_provider_tracks_calls() {
        let provider = MockProvider::new();
        let finding = sample_finding();
        let context = ExplanationContext::default();

        assert_eq!(provider.call_count(), 0);

        provider.explain_finding(&finding, &context).await.unwrap();
        assert_eq!(provider.call_count(), 1);

        provider.explain_finding(&finding, &context).await.unwrap();
        assert_eq!(provider.call_count(), 2);

        provider.reset_call_count();
        assert_eq!(provider.call_count(), 0);
    }

    #[tokio::test]
    async fn mock_provider_can_fail() {
        let provider = MockProvider::new();
        provider.set_should_fail(true, "Simulated API error").await;

        let finding = sample_finding();
        let context = ExplanationContext::default();

        let result = provider.explain_finding(&finding, &context).await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Simulated API error"));
    }

    #[tokio::test]
    async fn mock_provider_returns_custom_response() {
        let provider = MockProvider::new();
        let finding = sample_finding();
        let context = ExplanationContext::default();

        // Add custom response
        let custom = ExplanationResponse::new("custom-id", "CUSTOM-001")
            .with_explanation(VulnerabilityExplanation::new("Custom summary"));
        provider.add_response(custom).await;

        let result = provider.explain_finding(&finding, &context).await.unwrap();
        assert_eq!(result.finding_id, "custom-id");
        assert_eq!(result.rule_id, "CUSTOM-001");
    }

    #[tokio::test]
    async fn mock_provider_followup() {
        let provider = MockProvider::new();
        let explanation = ExplanationResponse::new("test", "TEST-001");

        let result = provider
            .ask_followup(&explanation, "How do I fix this?")
            .await;
        assert!(result.is_ok());
        assert!(result.unwrap().contains("How do I fix this?"));
    }

    #[tokio::test]
    async fn mock_provider_health_check() {
        let provider = MockProvider::new();
        let result = provider.health_check().await;
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn mock_provider_name_and_model() {
        let provider = MockProvider::new().with_model("test-model-v2");
        assert_eq!(provider.name(), "Mock");
        assert_eq!(provider.model(), "test-model-v2");
    }

    #[tokio::test]
    async fn mock_provider_streaming() {
        use super::super::super::streaming::stream_channel;

        let provider = MockProvider::new();
        let finding = sample_finding();
        let context = ExplanationContext::default();

        let (sender, mut receiver) = stream_channel(32);

        // Spawn the streaming task
        let provider_clone = MockProvider::new();
        let finding_clone = finding.clone();
        let context_clone = context.clone();
        let handle = tokio::spawn(async move {
            provider_clone
                .explain_finding_streaming(&finding_clone, &context_clone, sender)
                .await
        });

        // Collect streamed chunks
        let mut chunks = Vec::new();
        while let Some(chunk) = receiver.recv().await {
            let is_terminal = chunk.is_terminal();
            chunks.push(chunk);
            if is_terminal {
                break;
            }
        }

        // Verify we got some chunks and a Done marker
        assert!(!chunks.is_empty());
        assert!(matches!(chunks.last(), Some(StreamChunk::Done)));

        // Verify the result
        let result = handle.await.unwrap();
        assert!(result.is_ok());
    }

    #[test]
    fn mock_provider_supports_streaming() {
        let provider = MockProvider::new();
        assert!(provider.supports_streaming());
    }
}
