//! AI Module Integration Tests
//!
//! Tests for the AI-assisted vulnerability explanation system.
//! Note: Most tests use mocked responses to avoid API dependencies.

use mcplint::ai::{
    AiConfig, AiProviderType, AudienceLevel, ExplainEngine, ExplanationContext, Likelihood,
    VulnerabilityExplanation,
};
use mcplint::scanner::{Evidence, Finding, Severity};

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
    assert_eq!(Likelihood::from_str("high"), Some(Likelihood::High));
    assert_eq!(Likelihood::from_str("medium"), Some(Likelihood::Medium));
    assert_eq!(Likelihood::from_str("low"), Some(Likelihood::Low));
    assert_eq!(Likelihood::from_str("invalid"), None);
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
        AiProviderType::from_str("anthropic"),
        Some(AiProviderType::Anthropic)
    );
    assert_eq!(
        AiProviderType::from_str("claude"),
        Some(AiProviderType::Anthropic)
    );
    assert_eq!(
        AiProviderType::from_str("openai"),
        Some(AiProviderType::OpenAI)
    );
    assert_eq!(
        AiProviderType::from_str("gpt"),
        Some(AiProviderType::OpenAI)
    );
    assert_eq!(
        AiProviderType::from_str("ollama"),
        Some(AiProviderType::Ollama)
    );
    assert_eq!(
        AiProviderType::from_str("local"),
        Some(AiProviderType::Ollama)
    );
    assert_eq!(AiProviderType::from_str("invalid"), None);
}
