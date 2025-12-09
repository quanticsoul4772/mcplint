//! AI Module Integration Tests
//!
//! Tests for the AI-assisted vulnerability explanation system.
//! Includes real API integration tests that require valid API keys.
//!
//! Note: These tests call real AI APIs and may occasionally fail due to
//! LLM response variability. Tests include retry logic to handle this.

use std::future::Future;
use std::time::Duration;

use mcplint::ai::provider::{AiProvider, AnthropicProvider, OllamaProvider, OpenAiProvider};
use mcplint::ai::{
    AiConfig, AiProviderType, AudienceLevel, ExplainEngine, ExplanationContext, Likelihood,
    VulnerabilityExplanation,
};
use mcplint::scanner::{Evidence, Finding, Severity};

/// Retry helper for flaky LLM API calls
/// LLMs sometimes return malformed JSON - retry up to 3 times
async fn with_retry<F, Fut, T, E>(max_retries: usize, mut operation: F) -> Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, E>>,
    E: std::fmt::Debug,
{
    let mut last_error = None;
    for attempt in 0..max_retries {
        match operation().await {
            Ok(result) => return Ok(result),
            Err(e) => {
                eprintln!("Attempt {} failed: {:?}", attempt + 1, e);
                last_error = Some(e);
                if attempt < max_retries - 1 {
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            }
        }
    }
    Err(last_error.unwrap())
}

/// Create a sample finding for testing
fn sample_finding() -> Finding {
    Finding::new(
        "MCP-INJ-001",
        Severity::Critical,
        "Command Injection Vulnerability",
        "The tool 'execute_command' accepts user input without proper sanitization",
    )
    .with_location(mcplint::scanner::FindingLocation::tool("execute_command"))
    .with_cwe("78")
    .with_evidence(Evidence::observation(
        "execute_command",
        "User input flows directly to shell execution",
    ))
}

#[test]
fn test_ai_config_defaults() {
    let config = AiConfig::default();

    assert_eq!(config.provider, AiProviderType::Anthropic);
    assert!(!config.model.is_empty());
    assert!(config.max_tokens > 0);
    assert!(config.temperature >= 0.0 && config.temperature <= 1.0);
}

#[test]
fn test_ai_config_builder() {
    let config = AiConfig::builder()
        .provider(AiProviderType::Ollama)
        .model("llama3.2")
        .timeout(60)
        .build();

    assert_eq!(config.provider, AiProviderType::Ollama);
    assert_eq!(config.model, "llama3.2");
    assert_eq!(config.timeout_secs, 60);
}

#[test]
fn test_ai_config_providers() {
    // Anthropic config
    let anthropic = AiConfig::anthropic();
    assert_eq!(anthropic.provider, AiProviderType::Anthropic);
    assert!(anthropic.model.contains("claude"));

    // OpenAI config
    let openai = AiConfig::openai();
    assert_eq!(openai.provider, AiProviderType::OpenAI);
    assert!(openai.model.contains("gpt"));

    // Ollama config
    let ollama = AiConfig::ollama();
    assert_eq!(ollama.provider, AiProviderType::Ollama);
    assert!(ollama.model.contains("llama"));
}

#[test]
fn test_provider_default_models() {
    assert!(!AiProviderType::Anthropic.default_model().is_empty());
    assert!(!AiProviderType::OpenAI.default_model().is_empty());
    assert!(!AiProviderType::Ollama.default_model().is_empty());
}

#[test]
fn test_provider_env_keys() {
    assert_eq!(
        AiProviderType::Anthropic.env_key_name(),
        "ANTHROPIC_API_KEY"
    );
    assert_eq!(AiProviderType::OpenAI.env_key_name(), "OPENAI_API_KEY");
    assert_eq!(AiProviderType::Ollama.env_key_name(), "OLLAMA_BASE_URL");
}

#[test]
fn test_explanation_context_builder() {
    let context = ExplanationContext::new("test-server")
        .with_audience(AudienceLevel::Expert)
        .with_tech_stack(vec!["Node.js".to_string(), "TypeScript".to_string()])
        .with_code_language("typescript");

    assert_eq!(context.server_name, "test-server");
    assert_eq!(context.audience, AudienceLevel::Expert);
    assert_eq!(context.tech_stack.len(), 2);
    assert_eq!(context.code_language, Some("typescript".to_string()));
}

#[test]
fn test_audience_levels() {
    assert_eq!(AudienceLevel::Beginner.as_str(), "beginner");
    assert_eq!(AudienceLevel::Intermediate.as_str(), "intermediate");
    assert_eq!(AudienceLevel::Expert.as_str(), "expert");

    // Check descriptions are non-empty
    assert!(!AudienceLevel::Beginner.description().is_empty());
    assert!(!AudienceLevel::Intermediate.description().is_empty());
    assert!(!AudienceLevel::Expert.description().is_empty());
}

#[test]
fn test_likelihood_parsing() {
    assert_eq!("high".parse::<Likelihood>(), Ok(Likelihood::High));
    assert_eq!("medium".parse::<Likelihood>(), Ok(Likelihood::Medium));
    assert_eq!("low".parse::<Likelihood>(), Ok(Likelihood::Low));
    assert!("invalid".parse::<Likelihood>().is_err());
}

#[test]
fn test_explanation_response_structure() {
    let explanation = VulnerabilityExplanation {
        summary: "Test summary".to_string(),
        technical_details: "Technical details here".to_string(),
        attack_scenario: "Attack scenario description".to_string(),
        impact: "Impact assessment".to_string(),
        likelihood: Likelihood::High,
    };

    assert!(!explanation.summary.is_empty());
    assert!(!explanation.technical_details.is_empty());
    assert_eq!(explanation.likelihood, Likelihood::High);
}

#[test]
fn test_finding_for_ai() {
    let finding = sample_finding();

    assert_eq!(finding.rule_id, "MCP-INJ-001");
    assert_eq!(finding.severity, Severity::Critical);
    assert!(finding.title.contains("Command Injection"));
    assert!(!finding.evidence.is_empty());
}

#[tokio::test]
async fn test_engine_creation_with_ollama() {
    // Ollama doesn't require API key, so we can test engine creation
    let config = AiConfig::ollama();
    let result = ExplainEngine::new(config);

    // Should succeed even without a running Ollama instance
    // (the actual connection only happens on API calls)
    assert!(result.is_ok());

    let engine = result.unwrap();
    assert_eq!(engine.provider_name(), "Ollama");
}

#[tokio::test]
async fn test_engine_stats_initial() {
    let config = AiConfig::ollama();
    let engine = ExplainEngine::new(config).unwrap();
    let stats = engine.stats().await;

    assert_eq!(stats.total_explanations, 0);
    assert_eq!(stats.cache_hits, 0);
    assert_eq!(stats.cache_misses, 0);
    assert_eq!(stats.api_calls, 0);
    assert_eq!(stats.cache_hit_rate(), 0.0);
}

#[test]
fn test_config_validation() {
    // Ollama config should always validate (no API key needed)
    let ollama = AiConfig::ollama();
    assert!(ollama.validate().is_ok());

    // Anthropic without key should fail validation
    let anthropic = AiConfig::anthropic();
    assert!(anthropic.validate().is_err());

    // Anthropic with key should pass
    let with_key = AiConfig::anthropic().with_api_key("test-key");
    assert!(with_key.validate().is_ok());
}

#[test]
fn test_provider_from_string() {
    assert_eq!(
        "anthropic".parse::<AiProviderType>(),
        Ok(AiProviderType::Anthropic)
    );
    assert_eq!(
        "claude".parse::<AiProviderType>(),
        Ok(AiProviderType::Anthropic)
    );
    assert_eq!(
        "openai".parse::<AiProviderType>(),
        Ok(AiProviderType::OpenAI)
    );
    assert_eq!("gpt".parse::<AiProviderType>(), Ok(AiProviderType::OpenAI));
    assert_eq!(
        "ollama".parse::<AiProviderType>(),
        Ok(AiProviderType::Ollama)
    );
    assert_eq!(
        "local".parse::<AiProviderType>(),
        Ok(AiProviderType::Ollama)
    );
    assert!("invalid".parse::<AiProviderType>().is_err());
}

// =============================================================================
// REAL API INTEGRATION TESTS
// =============================================================================
// These tests make actual API calls and require valid credentials.
// They will FAIL if API keys are not set or if the APIs are unreachable.

/// Helper to get required env var or panic with clear message
fn require_env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| {
        panic!(
            "Required environment variable {} is not set. \
            Set it to run integration tests.",
            name
        )
    })
}

/// Create a simple finding for API testing (smaller than sample_finding for faster responses)
fn simple_test_finding() -> Finding {
    Finding::new(
        "MCP-INJ-001",
        Severity::High,
        "SQL Injection",
        "User input passed directly to database query",
    )
    .with_cwe("89")
}

// -----------------------------------------------------------------------------
// Anthropic Provider Tests
// -----------------------------------------------------------------------------

#[tokio::test]
async fn test_anthropic_health_check() {
    let api_key = require_env("ANTHROPIC_API_KEY");

    let provider = AnthropicProvider::new(
        api_key,
        "claude-3-haiku-20240307".to_string(), // Use haiku for speed/cost
        1024,
        0.3,
        Duration::from_secs(30),
    );

    let healthy = provider
        .health_check()
        .await
        .expect("Anthropic health check request failed");

    assert!(
        healthy,
        "Anthropic API health check returned false - API may be down or key invalid"
    );
}

#[tokio::test]
async fn test_anthropic_provider_name_and_model() {
    let api_key = require_env("ANTHROPIC_API_KEY");

    let provider = AnthropicProvider::new(
        api_key,
        "claude-3-haiku-20240307".to_string(),
        1024,
        0.3,
        Duration::from_secs(30),
    );

    assert_eq!(provider.name(), "Anthropic");
    assert_eq!(provider.model(), "claude-3-haiku-20240307");
    assert!(provider.supports_streaming());
}

#[tokio::test]
async fn test_anthropic_explain_finding() {
    let api_key = require_env("ANTHROPIC_API_KEY");

    let provider = AnthropicProvider::new(
        api_key,
        "claude-3-haiku-20240307".to_string(),
        2048,
        0.3,
        Duration::from_secs(60),
    );

    let finding = simple_test_finding();
    let context = ExplanationContext::new("test-server").with_audience(AudienceLevel::Intermediate);

    // Use retry logic to handle occasional LLM response parsing failures
    let response = with_retry(3, || async {
        provider.explain_finding(&finding, &context).await
    })
    .await
    .expect("Anthropic explain_finding failed after 3 retries");

    // Verify we got a real response
    assert!(
        !response.explanation.summary.is_empty(),
        "Summary should not be empty"
    );
    // Note: LLM responses may not always include all fields
    assert_eq!(response.metadata.provider, "anthropic");
}

// -----------------------------------------------------------------------------
// OpenAI Provider Tests
// -----------------------------------------------------------------------------

#[tokio::test]
async fn test_openai_health_check() {
    let api_key = require_env("OPENAI_API_KEY");

    let provider = OpenAiProvider::new(
        api_key,
        "gpt-4o-mini".to_string(), // Use mini for speed/cost
        1024,
        0.3,
        Duration::from_secs(30),
    );

    let healthy = provider
        .health_check()
        .await
        .expect("OpenAI health check request failed");

    assert!(
        healthy,
        "OpenAI API health check returned false - API may be down or key invalid"
    );
}

#[tokio::test]
async fn test_openai_provider_name_and_model() {
    let api_key = require_env("OPENAI_API_KEY");

    let provider = OpenAiProvider::new(
        api_key,
        "gpt-4o-mini".to_string(),
        1024,
        0.3,
        Duration::from_secs(30),
    );

    assert_eq!(provider.name(), "OpenAI");
    assert_eq!(provider.model(), "gpt-4o-mini");
}

#[tokio::test]
async fn test_openai_explain_finding() {
    let api_key = require_env("OPENAI_API_KEY");

    let provider = OpenAiProvider::new(
        api_key,
        "gpt-4o-mini".to_string(),
        2048,
        0.3,
        Duration::from_secs(60),
    );

    let finding = simple_test_finding();
    let context = ExplanationContext::new("test-server").with_audience(AudienceLevel::Intermediate);

    // Use retry logic to handle occasional LLM response parsing failures
    let response = with_retry(3, || async {
        provider.explain_finding(&finding, &context).await
    })
    .await
    .expect("OpenAI explain_finding failed after 3 retries");

    // Verify we got a real response
    assert!(
        !response.explanation.summary.is_empty(),
        "Summary should not be empty"
    );
    // Note: LLM responses may not always include all fields
    assert_eq!(response.metadata.provider, "openai");
}

// -----------------------------------------------------------------------------
// Ollama Provider Tests
// -----------------------------------------------------------------------------

#[tokio::test]
async fn test_ollama_health_check() {
    let base_url =
        std::env::var("OLLAMA_BASE_URL").unwrap_or_else(|_| "http://localhost:11434".to_string());

    let provider = OllamaProvider::new(
        base_url.clone(),
        "llama3.2".to_string(),
        Duration::from_secs(30),
    );

    let healthy = provider
        .health_check()
        .await
        .expect("Ollama health check request failed");

    assert!(
        healthy,
        "Ollama health check returned false - is Ollama running at {}?",
        base_url
    );
}

#[tokio::test]
async fn test_ollama_provider_name_and_model() {
    let base_url =
        std::env::var("OLLAMA_BASE_URL").unwrap_or_else(|_| "http://localhost:11434".to_string());

    let provider = OllamaProvider::new(base_url, "llama3.2".to_string(), Duration::from_secs(30));

    assert_eq!(provider.name(), "Ollama");
    assert_eq!(provider.model(), "llama3.2");
}

#[tokio::test]
async fn test_ollama_explain_finding() {
    let base_url =
        std::env::var("OLLAMA_BASE_URL").unwrap_or_else(|_| "http://localhost:11434".to_string());

    let provider = OllamaProvider::new(
        base_url,
        "llama3.2".to_string(),
        Duration::from_secs(120), // Ollama can be slower
    );

    // First check if Ollama is available
    let healthy = provider.health_check().await.unwrap_or(false);
    if !healthy {
        panic!("Ollama is not available - ensure it's running with llama3.2 model pulled");
    }

    let finding = simple_test_finding();
    let context = ExplanationContext::new("test-server").with_audience(AudienceLevel::Intermediate);

    // Use retry logic to handle occasional LLM response parsing failures
    let response = with_retry(3, || async {
        provider.explain_finding(&finding, &context).await
    })
    .await
    .expect("Ollama explain_finding failed after 3 retries");

    // Verify we got a real response
    assert!(
        !response.explanation.summary.is_empty(),
        "Summary should not be empty"
    );
    // Note: LLM responses may not always include all fields
    assert_eq!(response.metadata.provider, "ollama");
}

// -----------------------------------------------------------------------------
// ExplainEngine Integration Tests
// -----------------------------------------------------------------------------

#[tokio::test]
async fn test_explain_engine_with_anthropic() {
    let _api_key = require_env("ANTHROPIC_API_KEY"); // Ensure key exists

    let config = AiConfig::anthropic();
    let engine = ExplainEngine::new(config).expect("Failed to create ExplainEngine with Anthropic");

    assert_eq!(engine.provider_name(), "Anthropic");

    let finding = simple_test_finding();

    let response = engine
        .explain(&finding)
        .await
        .expect("ExplainEngine explain failed with Anthropic");

    assert!(!response.explanation.summary.is_empty());
}

#[tokio::test]
async fn test_explain_engine_with_openai() {
    let _api_key = require_env("OPENAI_API_KEY"); // Ensure key exists

    let config = AiConfig::openai();
    let engine = ExplainEngine::new(config).expect("Failed to create ExplainEngine with OpenAI");

    assert_eq!(engine.provider_name(), "OpenAI");

    let finding = simple_test_finding();

    let response = engine
        .explain(&finding)
        .await
        .expect("ExplainEngine explain failed with OpenAI");

    assert!(!response.explanation.summary.is_empty());
}

// -----------------------------------------------------------------------------
// Cross-Provider Comparison Test
// -----------------------------------------------------------------------------

#[tokio::test]
async fn test_all_providers_explain_same_finding() {
    // This test ensures all providers can handle the same finding
    // Useful for catching provider-specific parsing issues

    let finding = simple_test_finding();
    let context = ExplanationContext::new("test-server")
        .with_audience(AudienceLevel::Expert)
        .with_tech_stack(vec!["Rust".to_string(), "PostgreSQL".to_string()]);

    // Anthropic - use Sonnet for combined test as it handles complex JSON more reliably
    if let Ok(api_key) = std::env::var("ANTHROPIC_API_KEY") {
        let provider = AnthropicProvider::new(
            api_key,
            "claude-sonnet-4-20250514".to_string(),
            4096,
            0.3,
            Duration::from_secs(90),
        );

        // Use retry logic to handle occasional LLM response parsing failures
        let response = with_retry(3, || async {
            provider.explain_finding(&finding, &context).await
        })
        .await
        .expect("Anthropic failed to explain finding after 3 retries");
        assert!(
            !response.explanation.summary.is_empty(),
            "Anthropic: empty summary"
        );
        println!(
            "Anthropic response OK: {} chars",
            response.explanation.summary.len()
        );
    } else {
        panic!("ANTHROPIC_API_KEY not set");
    }

    // OpenAI
    if let Ok(api_key) = std::env::var("OPENAI_API_KEY") {
        let provider = OpenAiProvider::new(
            api_key,
            "gpt-4o-mini".to_string(),
            2048,
            0.3,
            Duration::from_secs(60),
        );

        // Use retry logic to handle occasional LLM response parsing failures
        let response = with_retry(3, || async {
            provider.explain_finding(&finding, &context).await
        })
        .await
        .expect("OpenAI failed to explain finding after 3 retries");
        assert!(
            !response.explanation.summary.is_empty(),
            "OpenAI: empty summary"
        );
        println!(
            "OpenAI response OK: {} chars",
            response.explanation.summary.len()
        );
    } else {
        panic!("OPENAI_API_KEY not set");
    }

    // Ollama (if available - skip if not running)
    let base_url =
        std::env::var("OLLAMA_BASE_URL").unwrap_or_else(|_| "http://localhost:11434".to_string());
    let ollama = OllamaProvider::new(
        base_url.clone(),
        "llama3.2".to_string(),
        Duration::from_secs(120),
    );

    if ollama.health_check().await.unwrap_or(false) {
        // Use retry logic to handle occasional LLM response parsing failures
        let response = with_retry(3, || async {
            ollama.explain_finding(&finding, &context).await
        })
        .await
        .expect("Ollama failed to explain finding after 3 retries");
        assert!(
            !response.explanation.summary.is_empty(),
            "Ollama: empty summary"
        );
        println!(
            "Ollama response OK: {} chars",
            response.explanation.summary.len()
        );
    } else {
        println!(
            "Ollama not available at {} - skipping (not an error if cloud-only CI)",
            base_url
        );
    }
}
