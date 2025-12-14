//! Explain Engine - Orchestrates AI-powered vulnerability explanations
//!
//! Provides the main interface for generating explanations with:
//! - Multi-provider support
//! - Response caching
//! - Rate limiting
//! - Batch processing

use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::sync::RwLock;

use crate::cache::{CacheCategory, CacheKey, CacheManager};
use crate::scanner::Finding;

use super::config::{AiConfig, ExplanationContext};
use super::prompt::PROMPT_VERSION;
use super::provider::{create_provider, AiProvider};
use super::rate_limit::RateLimiter;
use super::response::ExplanationResponse;

/// Engine for generating AI-powered vulnerability explanations
pub struct ExplainEngine {
    /// AI provider instance
    provider: Arc<dyn AiProvider>,
    /// Cache manager for response caching
    cache: Option<Arc<CacheManager>>,
    /// Rate limiter for API calls
    rate_limiter: Arc<RateLimiter>,
    /// Default explanation context
    default_context: ExplanationContext,
    /// Statistics tracking
    stats: Arc<RwLock<EngineStats>>,
}

/// Statistics for the explain engine
#[derive(Debug, Default, Clone)]
pub struct EngineStats {
    /// Total explanations generated
    pub total_explanations: u64,
    /// Cache hits
    pub cache_hits: u64,
    /// Cache misses
    pub cache_misses: u64,
    /// API calls made
    pub api_calls: u64,
    /// Total tokens used
    pub tokens_used: u64,
    /// Total response time in milliseconds
    pub total_response_time_ms: u64,
}

impl EngineStats {
    /// Calculate cache hit rate as percentage
    pub fn cache_hit_rate(&self) -> f64 {
        let total = self.cache_hits + self.cache_misses;
        if total == 0 {
            0.0
        } else {
            (self.cache_hits as f64 / total as f64) * 100.0
        }
    }

    /// Calculate average response time
    pub fn avg_response_time_ms(&self) -> u64 {
        if self.api_calls == 0 {
            0
        } else {
            self.total_response_time_ms / self.api_calls
        }
    }
}

impl ExplainEngine {
    /// Create a new explain engine with the given configuration
    pub fn new(config: AiConfig) -> Result<Self> {
        let provider = create_provider(&config)?;

        let rate_limiter = Arc::new(RateLimiter::new(
            config.rate_limit_rpm,
            config.rate_limit_tpm,
        ));

        Ok(Self {
            provider: Arc::from(provider),
            cache: None,
            rate_limiter,
            default_context: ExplanationContext::default(),
            stats: Arc::new(RwLock::new(EngineStats::default())),
        })
    }

    /// Create an engine with cache support
    pub fn with_cache(mut self, cache: Arc<CacheManager>) -> Self {
        self.cache = Some(cache);
        self
    }

    /// Set the default explanation context
    pub fn with_default_context(mut self, context: ExplanationContext) -> Self {
        self.default_context = context;
        self
    }

    /// Set a custom rate limiter
    pub fn with_rate_limiter(mut self, rate_limiter: Arc<RateLimiter>) -> Self {
        self.rate_limiter = rate_limiter;
        self
    }

    /// Get the provider name
    pub fn provider_name(&self) -> &'static str {
        self.provider.name()
    }

    /// Get the model name
    pub fn model_name(&self) -> &str {
        self.provider.model()
    }

    /// Generate a cache key for a finding
    fn cache_key(&self, finding: &Finding, context: &ExplanationContext) -> CacheKey {
        // Include prompt version in cache key for invalidation
        let key_data = format!(
            "{}:{}:{}:{}:{}",
            PROMPT_VERSION,
            self.provider.model(),
            finding.id,
            finding.rule_id,
            context.audience.description()
        );

        CacheKey::new(CacheCategory::AiResponse, &key_data)
    }

    /// Try to get an explanation from cache
    async fn get_cached(
        &self,
        finding: &Finding,
        context: &ExplanationContext,
    ) -> Option<ExplanationResponse> {
        let cache = self.cache.as_ref()?;
        let key = self.cache_key(finding, context);

        match cache.get::<ExplanationResponse>(&key).await {
            Ok(Some(response)) => {
                let mut stats = self.stats.write().await;
                stats.cache_hits += 1;
                Some(response)
            }
            _ => {
                let mut stats = self.stats.write().await;
                stats.cache_misses += 1;
                None
            }
        }
    }

    /// Store an explanation in cache
    async fn store_cached(
        &self,
        finding: &Finding,
        context: &ExplanationContext,
        response: &ExplanationResponse,
    ) {
        if let Some(cache) = &self.cache {
            let key = self.cache_key(finding, context);
            if let Err(e) = cache.set(&key, response).await {
                tracing::warn!("Failed to cache explanation: {}", e);
            }
        }
    }

    /// Explain a single finding
    pub async fn explain(&self, finding: &Finding) -> Result<ExplanationResponse> {
        self.explain_with_context(finding, &self.default_context)
            .await
    }

    /// Explain a finding with custom context
    pub async fn explain_with_context(
        &self,
        finding: &Finding,
        context: &ExplanationContext,
    ) -> Result<ExplanationResponse> {
        // Check cache first
        if let Some(cached) = self.get_cached(finding, context).await {
            tracing::debug!("Cache hit for finding {}", finding.id);
            return Ok(cached);
        }

        // Estimate tokens for rate limiting (rough estimate)
        let estimated_tokens = estimate_tokens(finding);

        // Acquire rate limit
        self.rate_limiter
            .acquire(estimated_tokens)
            .await
            .context("Rate limit acquisition failed")?;

        // Make API call
        tracing::debug!("Generating explanation for finding {}", finding.id);
        let response = self
            .provider
            .explain_finding(finding, context)
            .await
            .context("Failed to generate explanation")?;

        // Update statistics
        {
            let mut stats = self.stats.write().await;
            stats.total_explanations += 1;
            stats.api_calls += 1;

            // Track token usage if available
            if response.metadata.tokens_used > 0 {
                stats.tokens_used += response.metadata.tokens_used as u64;
                // Adjust rate limiter with actual usage
                self.rate_limiter
                    .record_tokens(response.metadata.tokens_used, estimated_tokens)
                    .await;
            }

            // Track response time if available
            if response.metadata.response_time_ms > 0 {
                stats.total_response_time_ms += response.metadata.response_time_ms;
            }
        }

        // Store in cache
        self.store_cached(finding, context, &response).await;

        Ok(response)
    }

    /// Explain multiple findings in batch
    pub async fn explain_batch(
        &self,
        findings: &[Finding],
        context: Option<&ExplanationContext>,
    ) -> Result<Vec<ExplanationResponse>> {
        let ctx = context.unwrap_or(&self.default_context);
        let mut results = Vec::with_capacity(findings.len());
        let mut uncached_findings = Vec::new();
        let mut uncached_indices = Vec::new();

        // Check cache for each finding
        for (idx, finding) in findings.iter().enumerate() {
            if let Some(cached) = self.get_cached(finding, ctx).await {
                results.push((idx, cached));
            } else {
                uncached_findings.push(finding.clone());
                uncached_indices.push(idx);
            }
        }

        // Generate explanations for uncached findings
        if !uncached_findings.is_empty() {
            tracing::info!(
                "Generating {} explanations ({} cached)",
                uncached_findings.len(),
                results.len()
            );

            // Process uncached findings one at a time with rate limiting
            for (i, finding) in uncached_findings.iter().enumerate() {
                let response = self.explain_with_context(finding, ctx).await?;
                results.push((uncached_indices[i], response));
            }
        }

        // Sort by original index and extract responses
        results.sort_by_key(|(idx, _)| *idx);
        Ok(results.into_iter().map(|(_, r)| r).collect())
    }

    /// Ask a follow-up question about an explanation
    pub async fn ask_followup(
        &self,
        explanation: &ExplanationResponse,
        question: &str,
    ) -> Result<String> {
        // Estimate tokens for rate limiting
        let estimated_tokens = 500 + (question.len() as u32 / 4);

        self.rate_limiter
            .acquire(estimated_tokens)
            .await
            .context("Rate limit acquisition failed")?;

        let response = self
            .provider
            .ask_followup(explanation, question)
            .await
            .context("Failed to get follow-up response")?;

        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.api_calls += 1;
        }

        Ok(response)
    }

    /// Check if the AI provider is available
    pub async fn health_check(&self) -> Result<bool> {
        self.provider.health_check().await
    }

    /// Get current engine statistics
    pub async fn stats(&self) -> EngineStats {
        self.stats.read().await.clone()
    }

    /// Get rate limiter statistics
    pub async fn rate_limit_stats(&self) -> super::rate_limit::RateLimitStats {
        self.rate_limiter.stats().await
    }

    /// Check if rate limit would be exceeded
    pub async fn would_exceed_rate_limit(&self, estimated_tokens: u32) -> bool {
        self.rate_limiter.would_exceed(estimated_tokens).await
    }
}

/// Estimate tokens for a finding (rough calculation)
fn estimate_tokens(finding: &Finding) -> u32 {
    // Base tokens for prompt template
    let base = 500;

    // Add tokens for finding content
    let finding_tokens = (finding.title.len()
        + finding.description.len()
        + finding.evidence.iter().map(|e| e.data.len()).sum::<usize>())
        / 4; // Rough char-to-token ratio

    // Add tokens for expected response
    let response_estimate = 2000;

    base + finding_tokens as u32 + response_estimate
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ai::config::AiProvider as AiProviderType;
    use crate::ai::provider::MockProvider;
    use crate::scanner::Severity;
    use std::sync::Arc;

    fn sample_finding() -> Finding {
        Finding::new(
            "MCP-TEST-001",
            Severity::High,
            "Test Finding",
            "This is a test finding for unit tests",
        )
    }

    fn sample_finding_with_evidence() -> Finding {
        use crate::scanner::{Evidence, EvidenceKind};

        sample_finding()
            .with_evidence(Evidence::new(
                EvidenceKind::Observation,
                "let x = user_input;",
                "Vulnerable code pattern",
            ))
            .with_evidence(Evidence::new(
                EvidenceKind::Observation,
                "src/main.rs:42",
                "Location of issue",
            ))
    }

    #[test]
    fn engine_stats_calculations() {
        let mut stats = EngineStats::default();

        // Test cache hit rate calculation
        assert_eq!(stats.cache_hit_rate(), 0.0);

        stats.cache_hits = 3;
        stats.cache_misses = 7;
        assert!((stats.cache_hit_rate() - 30.0).abs() < 0.01);

        // Test average response time
        assert_eq!(stats.avg_response_time_ms(), 0);

        stats.api_calls = 5;
        stats.total_response_time_ms = 1000;
        assert_eq!(stats.avg_response_time_ms(), 200);
    }

    #[test]
    fn engine_stats_edge_cases() {
        let stats = EngineStats::default();

        // Zero division safety
        assert_eq!(stats.cache_hit_rate(), 0.0);
        assert_eq!(stats.avg_response_time_ms(), 0);

        // 100% cache hit rate
        let stats = EngineStats {
            cache_hits: 10,
            cache_misses: 0,
            ..Default::default()
        };
        assert_eq!(stats.cache_hit_rate(), 100.0);

        // 0% cache hit rate
        let stats = EngineStats {
            cache_hits: 0,
            cache_misses: 10,
            ..Default::default()
        };
        assert_eq!(stats.cache_hit_rate(), 0.0);
    }

    #[test]
    fn token_estimation() {
        let finding = sample_finding();
        let tokens = estimate_tokens(&finding);

        // Should have base + content + response estimate
        assert!(tokens > 500);
        assert!(tokens < 10000);
    }

    #[test]
    fn token_estimation_with_evidence() {
        let finding = sample_finding_with_evidence();
        let tokens = estimate_tokens(&finding);

        // Should be more than base finding due to evidence
        let base_tokens = estimate_tokens(&sample_finding());
        assert!(tokens >= base_tokens);
    }

    #[test]
    fn token_estimation_scales_with_content() {
        let small_finding = Finding::new("ID1", Severity::Low, "Short", "Brief");
        let large_finding = Finding::new(
            "ID2",
            Severity::High,
            "Very Long Title That Contains Many Words And Details",
            "This is a much longer description that contains significantly more text \
            and detailed information about the vulnerability, including technical details, \
            impact assessment, and comprehensive analysis of the security issue.",
        );

        let small_tokens = estimate_tokens(&small_finding);
        let large_tokens = estimate_tokens(&large_finding);

        assert!(large_tokens > small_tokens);
    }

    #[tokio::test]
    async fn engine_creation_with_ollama() {
        // Test with Ollama (doesn't require API key)
        let config = AiConfig::builder()
            .provider(AiProviderType::Ollama)
            .model("llama3.2")
            .build();

        let engine = ExplainEngine::new(config);
        assert!(engine.is_ok());

        let engine = engine.unwrap();
        assert_eq!(engine.provider_name(), "Ollama");
        assert_eq!(engine.model_name(), "llama3.2");
    }

    #[tokio::test]
    async fn engine_builder_pattern() {
        use crate::cache::{CacheBackend, CacheConfig};

        let config = AiConfig::builder()
            .provider(AiProviderType::Ollama)
            .model("llama3.2")
            .build();

        let cache_config = CacheConfig {
            backend: CacheBackend::Memory,
            schema_ttl_secs: 3600,
            result_ttl_secs: 86400,
            validation_ttl_secs: 3600,
            corpus_persist: false,
            max_size_bytes: None,
            enabled: true,
        };
        let cache_manager = Arc::new(CacheManager::new(cache_config).await.unwrap());
        let custom_context = ExplanationContext::default();
        let rate_limiter = Arc::new(RateLimiter::new(100, 10000));

        let engine = ExplainEngine::new(config)
            .unwrap()
            .with_cache(cache_manager)
            .with_default_context(custom_context)
            .with_rate_limiter(rate_limiter);

        assert_eq!(engine.provider_name(), "Ollama");
    }

    #[tokio::test]
    async fn engine_stats_tracking() {
        let config = AiConfig::builder()
            .provider(AiProviderType::Ollama)
            .model("llama3.2")
            .build();

        let engine = ExplainEngine::new(config).unwrap();

        let stats = engine.stats().await;
        assert_eq!(stats.total_explanations, 0);
        assert_eq!(stats.api_calls, 0);
        assert_eq!(stats.tokens_used, 0);
    }

    #[test]
    fn cache_key_generation() {
        let config = AiConfig::builder()
            .provider(AiProviderType::Ollama)
            .model("llama3.2")
            .build();

        let engine = ExplainEngine::new(config).unwrap();
        let finding = sample_finding();
        let context = ExplanationContext::default();

        let key = engine.cache_key(&finding, &context);
        assert!(key.to_string().contains("llama3.2"));
        assert!(key.to_string().contains(&finding.id));
    }

    #[test]
    fn cache_key_differs_for_different_findings() {
        let config = AiConfig::builder()
            .provider(AiProviderType::Ollama)
            .model("llama3.2")
            .build();

        let engine = ExplainEngine::new(config).unwrap();
        let finding1 = sample_finding();
        let finding2 = Finding::new(
            "MCP-TEST-002",
            Severity::Medium,
            "Different Finding",
            "Different description",
        );
        let context = ExplanationContext::default();

        let key1 = engine.cache_key(&finding1, &context);
        let key2 = engine.cache_key(&finding2, &context);

        assert_ne!(key1, key2);
    }

    #[test]
    fn cache_key_includes_prompt_version() {
        let config = AiConfig::builder()
            .provider(AiProviderType::Ollama)
            .model("llama3.2")
            .build();

        let engine = ExplainEngine::new(config).unwrap();
        let finding = sample_finding();
        let context = ExplanationContext::default();

        let key = engine.cache_key(&finding, &context);
        assert!(key.to_string().contains(PROMPT_VERSION));
    }

    #[tokio::test]
    async fn rate_limit_stats() {
        let config = AiConfig::builder()
            .provider(AiProviderType::Ollama)
            .model("llama3.2")
            .build();

        let engine = ExplainEngine::new(config).unwrap();

        let stats = engine.rate_limit_stats().await;
        // Should have default limits from config
        assert!(stats.requests_limit > 0);
        assert_eq!(stats.requests_used, 0);
    }

    #[tokio::test]
    async fn would_exceed_rate_limit() {
        // Create an engine with low limits using a direct rate limiter
        let config = AiConfig::builder()
            .provider(AiProviderType::Ollama)
            .model("llama3.2")
            .build();

        let rate_limiter = Arc::new(RateLimiter::new(10, 1000));
        let engine = ExplainEngine::new(config)
            .unwrap()
            .with_rate_limiter(rate_limiter);

        // Should not exceed with small token count
        let would_exceed = engine.would_exceed_rate_limit(100).await;
        assert!(!would_exceed);

        // Very large token count might exceed
        let would_exceed = engine.would_exceed_rate_limit(1_000_000).await;
        assert!(would_exceed);
    }

    #[tokio::test]
    async fn engine_getters() {
        let config = AiConfig::builder()
            .provider(AiProviderType::Ollama)
            .model("test-model")
            .build();

        let engine = ExplainEngine::new(config).unwrap();

        assert_eq!(engine.provider_name(), "Ollama");
        assert_eq!(engine.model_name(), "test-model");
    }

    // Integration-style tests using MockProvider (no real API calls)
    #[tokio::test]
    async fn explain_with_mock_provider() {
        // Create engine with mock provider directly
        let provider = Arc::new(MockProvider::new()) as Arc<dyn AiProvider>;
        let rate_limiter = Arc::new(RateLimiter::new(1000, 100000));

        let engine = ExplainEngine {
            provider,
            cache: None,
            rate_limiter,
            default_context: ExplanationContext::default(),
            stats: Arc::new(RwLock::new(EngineStats::default())),
        };

        let finding = sample_finding();
        let result = engine.explain(&finding).await;

        assert!(result.is_ok());
        let explanation = result.unwrap();
        assert_eq!(explanation.finding_id, finding.id);

        // Check stats were updated
        let stats = engine.stats().await;
        assert_eq!(stats.total_explanations, 1);
        assert_eq!(stats.api_calls, 1);
    }

    #[tokio::test]
    async fn explain_batch_ordering() {
        let provider = Arc::new(MockProvider::new()) as Arc<dyn AiProvider>;
        let rate_limiter = Arc::new(RateLimiter::new(1000, 100000));

        let engine = ExplainEngine {
            provider,
            cache: None,
            rate_limiter,
            default_context: ExplanationContext::default(),
            stats: Arc::new(RwLock::new(EngineStats::default())),
        };

        let finding1 = Finding::new("RULE-1", Severity::High, "First", "First finding");
        let finding2 = Finding::new("RULE-2", Severity::Medium, "Second", "Second finding");
        let finding3 = Finding::new("RULE-3", Severity::Low, "Third", "Third finding");

        let findings = vec![finding1.clone(), finding2.clone(), finding3.clone()];

        let result = engine.explain_batch(&findings, None).await;
        assert!(result.is_ok());

        let responses = result.unwrap();
        assert_eq!(responses.len(), 3);
        // Verify ordering is preserved by checking finding IDs match in order
        assert_eq!(responses[0].finding_id, finding1.id);
        assert_eq!(responses[1].finding_id, finding2.id);
        assert_eq!(responses[2].finding_id, finding3.id);
    }

    #[tokio::test]
    async fn explain_with_custom_context() {
        let provider = Arc::new(MockProvider::new()) as Arc<dyn AiProvider>;
        let rate_limiter = Arc::new(RateLimiter::new(1000, 100000));

        let engine = ExplainEngine {
            provider,
            cache: None,
            rate_limiter,
            default_context: ExplanationContext::default(),
            stats: Arc::new(RwLock::new(EngineStats::default())),
        };

        let finding = sample_finding();
        let custom_context = ExplanationContext::default();

        let result = engine.explain_with_context(&finding, &custom_context).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn ask_followup_updates_stats() {
        let provider = Arc::new(MockProvider::new()) as Arc<dyn AiProvider>;
        let rate_limiter = Arc::new(RateLimiter::new(1000, 100000));

        let engine = ExplainEngine {
            provider,
            cache: None,
            rate_limiter,
            default_context: ExplanationContext::default(),
            stats: Arc::new(RwLock::new(EngineStats::default())),
        };

        let explanation = ExplanationResponse::new("test", "TEST-001");
        let result = engine.ask_followup(&explanation, "How to fix?").await;

        assert!(result.is_ok());

        let stats = engine.stats().await;
        assert_eq!(stats.api_calls, 1);
    }

    #[tokio::test]
    async fn health_check() {
        let provider = Arc::new(MockProvider::new()) as Arc<dyn AiProvider>;
        let rate_limiter = Arc::new(RateLimiter::new(1000, 100000));

        let engine = ExplainEngine {
            provider,
            cache: None,
            rate_limiter,
            default_context: ExplanationContext::default(),
            stats: Arc::new(RwLock::new(EngineStats::default())),
        };

        let result = engine.health_check().await;
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    // Additional comprehensive tests for increased coverage

    #[test]
    fn engine_stats_clone_trait() {
        let stats = EngineStats {
            total_explanations: 10,
            cache_hits: 5,
            cache_misses: 5,
            api_calls: 5,
            tokens_used: 1000,
            total_response_time_ms: 5000,
        };

        let cloned = stats.clone();
        assert_eq!(cloned.total_explanations, 10);
        assert_eq!(cloned.cache_hits, 5);
        assert_eq!(cloned.cache_misses, 5);
        assert_eq!(cloned.api_calls, 5);
        assert_eq!(cloned.tokens_used, 1000);
        assert_eq!(cloned.total_response_time_ms, 5000);
    }

    #[test]
    fn engine_stats_debug_trait() {
        let stats = EngineStats {
            total_explanations: 1,
            cache_hits: 2,
            cache_misses: 3,
            api_calls: 4,
            tokens_used: 5,
            total_response_time_ms: 6,
        };

        let debug_str = format!("{:?}", stats);
        assert!(debug_str.contains("total_explanations"));
        assert!(debug_str.contains("cache_hits"));
    }

    #[test]
    fn engine_stats_cache_hit_rate_precision() {
        let stats = EngineStats {
            cache_hits: 1,
            cache_misses: 2,
            ..Default::default()
        };
        let rate = stats.cache_hit_rate();
        assert!((rate - 33.333333333333).abs() < 0.0001);
    }

    #[test]
    fn engine_stats_avg_response_single_call() {
        let stats = EngineStats {
            api_calls: 1,
            total_response_time_ms: 500,
            ..Default::default()
        };
        assert_eq!(stats.avg_response_time_ms(), 500);
    }

    #[test]
    fn engine_stats_avg_response_multiple_calls() {
        let stats = EngineStats {
            api_calls: 4,
            total_response_time_ms: 1000,
            ..Default::default()
        };
        assert_eq!(stats.avg_response_time_ms(), 250);
    }

    #[test]
    fn engine_stats_cache_rate_with_only_hits() {
        let stats = EngineStats {
            cache_hits: 100,
            cache_misses: 0,
            ..Default::default()
        };
        assert_eq!(stats.cache_hit_rate(), 100.0);
    }

    #[test]
    fn engine_stats_cache_rate_with_only_misses() {
        let stats = EngineStats {
            cache_hits: 0,
            cache_misses: 50,
            ..Default::default()
        };
        assert_eq!(stats.cache_hit_rate(), 0.0);
    }

    #[test]
    fn engine_stats_large_values() {
        let stats = EngineStats {
            total_explanations: u64::MAX / 2,
            cache_hits: 1000000,
            cache_misses: 1000000,
            api_calls: 500000,
            tokens_used: u64::MAX / 4,
            total_response_time_ms: 10000000,
        };

        assert_eq!(stats.cache_hit_rate(), 50.0);
        assert_eq!(stats.avg_response_time_ms(), 20);
    }

    #[test]
    fn token_estimation_empty_finding() {
        let finding = Finding::new("ID", Severity::Info, "", "");
        let tokens = estimate_tokens(&finding);
        assert!(tokens >= 2500);
    }

    #[test]
    fn token_estimation_minimum_value() {
        let minimal_finding = Finding::new("", Severity::Info, "", "");
        let tokens = estimate_tokens(&minimal_finding);
        assert_eq!(tokens, 2500);
    }

    #[test]
    fn token_estimation_char_to_token_ratio() {
        let text_1000_chars = "a".repeat(1000);
        let finding = Finding::new("ID", Severity::Medium, &text_1000_chars, &text_1000_chars);

        let tokens = estimate_tokens(&finding);
        assert_eq!(tokens, 3000);
    }

    #[test]
    fn token_estimation_with_multiple_evidence() {
        use crate::scanner::{Evidence, EvidenceKind};

        let mut finding = sample_finding();
        for i in 0..5 {
            finding = finding.with_evidence(Evidence::new(
                EvidenceKind::Observation,
                &format!("Evidence data {}", i),
                &format!("Description {}", i),
            ));
        }

        let tokens = estimate_tokens(&finding);
        let base_tokens = estimate_tokens(&sample_finding());
        assert!(tokens > base_tokens);
    }

    #[test]
    fn token_estimation_with_very_long_evidence() {
        use crate::scanner::{Evidence, EvidenceKind};

        let long_data = "x".repeat(10000);
        let finding = sample_finding().with_evidence(Evidence::new(
            EvidenceKind::Observation,
            &long_data,
            "Long evidence",
        ));

        let tokens = estimate_tokens(&finding);
        let base_tokens = estimate_tokens(&sample_finding());
        assert!(tokens > base_tokens + 2000);
    }

    #[tokio::test]
    async fn engine_creation_with_anthropic() {
        let config = AiConfig::builder()
            .provider(AiProviderType::Anthropic)
            .model("claude-3-5-sonnet-20241022")
            .build();

        let result = ExplainEngine::new(config);
        if let Err(e) = result {
            assert!(e.to_string().contains("API key") || e.to_string().contains("ANTHROPIC"));
        }
    }

    #[tokio::test]
    async fn engine_creation_with_openai() {
        let config = AiConfig::builder()
            .provider(AiProviderType::OpenAI)
            .model("gpt-4")
            .build();

        let result = ExplainEngine::new(config);
        if let Err(e) = result {
            assert!(e.to_string().contains("API key") || e.to_string().contains("OPENAI"));
        }
    }

    #[tokio::test]
    async fn engine_provider_and_model_getters() {
        let config = AiConfig::builder()
            .provider(AiProviderType::Ollama)
            .model("custom-model-name")
            .build();

        let engine = ExplainEngine::new(config).unwrap();
        assert_eq!(engine.provider_name(), "Ollama");
        assert_eq!(engine.model_name(), "custom-model-name");
    }

    #[tokio::test]
    async fn engine_without_cache() {
        let config = AiConfig::builder()
            .provider(AiProviderType::Ollama)
            .model("llama3.2")
            .build();

        let engine = ExplainEngine::new(config).unwrap();
        assert!(engine.cache.is_none());
    }

    #[tokio::test]
    async fn engine_with_all_builder_methods() {
        use crate::cache::{CacheBackend, CacheConfig};

        let config = AiConfig::builder()
            .provider(AiProviderType::Ollama)
            .model("llama3.2")
            .build();

        let cache_config = CacheConfig {
            backend: CacheBackend::Memory,
            schema_ttl_secs: 3600,
            result_ttl_secs: 86400,
            validation_ttl_secs: 3600,
            corpus_persist: false,
            max_size_bytes: None,
            enabled: true,
        };
        let cache_manager = Arc::new(CacheManager::new(cache_config).await.unwrap());
        let custom_context = ExplanationContext::default();
        let custom_rate_limiter = Arc::new(RateLimiter::new(200, 20000));

        let engine = ExplainEngine::new(config)
            .unwrap()
            .with_cache(Arc::clone(&cache_manager))
            .with_default_context(custom_context.clone())
            .with_rate_limiter(Arc::clone(&custom_rate_limiter));

        assert!(engine.cache.is_some());
        let stats = engine.rate_limit_stats().await;
        assert_eq!(stats.requests_limit, 200);
    }

    #[test]
    fn cache_key_differs_for_different_models() {
        let config1 = AiConfig::builder()
            .provider(AiProviderType::Ollama)
            .model("llama3.2")
            .build();
        let config2 = AiConfig::builder()
            .provider(AiProviderType::Ollama)
            .model("mistral")
            .build();

        let engine1 = ExplainEngine::new(config1).unwrap();
        let engine2 = ExplainEngine::new(config2).unwrap();

        let finding = sample_finding();
        let context = ExplanationContext::default();

        let key1 = engine1.cache_key(&finding, &context);
        let key2 = engine2.cache_key(&finding, &context);

        assert_ne!(key1, key2);
    }

    #[test]
    fn cache_key_differs_for_different_audience() {
        use crate::ai::config::AudienceLevel;

        let config = AiConfig::builder()
            .provider(AiProviderType::Ollama)
            .model("llama3.2")
            .build();

        let engine = ExplainEngine::new(config).unwrap();
        let finding = sample_finding();

        let mut context1 = ExplanationContext::default();
        context1.audience = AudienceLevel::Beginner;

        let mut context2 = ExplanationContext::default();
        context2.audience = AudienceLevel::Expert;

        let key1 = engine.cache_key(&finding, &context1);
        let key2 = engine.cache_key(&finding, &context2);

        assert_ne!(key1, key2);
    }

    #[test]
    fn cache_key_includes_rule_id() {
        let config = AiConfig::builder()
            .provider(AiProviderType::Ollama)
            .model("llama3.2")
            .build();

        let engine = ExplainEngine::new(config).unwrap();
        let finding = sample_finding();
        let context = ExplanationContext::default();

        let key = engine.cache_key(&finding, &context);
        assert!(key.to_string().contains(&finding.rule_id));
    }

    #[test]
    fn cache_key_format_contains_all_components() {
        let config = AiConfig::builder()
            .provider(AiProviderType::Ollama)
            .model("llama3.2")
            .build();

        let engine = ExplainEngine::new(config).unwrap();
        let finding = Finding::new(
            "TEST-RULE-123",
            Severity::Critical,
            "Test Title",
            "Test Description",
        );
        let context = ExplanationContext::default();

        let key = engine.cache_key(&finding, &context);
        let key_str = key.to_string();

        assert!(key_str.contains(PROMPT_VERSION));
        assert!(key_str.contains("llama3.2"));
        assert!(key_str.contains(&finding.id));
        assert!(key_str.contains("TEST-RULE-123"));
    }

    #[test]
    fn cache_key_consistency() {
        let config = AiConfig::builder()
            .provider(AiProviderType::Ollama)
            .model("llama3.2")
            .build();

        let engine = ExplainEngine::new(config).unwrap();
        let finding = sample_finding();
        let context = ExplanationContext::default();

        let key1 = engine.cache_key(&finding, &context);
        let key2 = engine.cache_key(&finding, &context);
        assert_eq!(key1, key2);
    }

    #[tokio::test]
    async fn explain_batch_empty() {
        let provider = Arc::new(MockProvider::new()) as Arc<dyn AiProvider>;
        let rate_limiter = Arc::new(RateLimiter::new(1000, 100000));

        let engine = ExplainEngine {
            provider,
            cache: None,
            rate_limiter,
            default_context: ExplanationContext::default(),
            stats: Arc::new(RwLock::new(EngineStats::default())),
        };

        let findings = vec![];
        let result = engine.explain_batch(&findings, None).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 0);
    }

    #[tokio::test]
    async fn explain_batch_single_item() {
        let provider = Arc::new(MockProvider::new()) as Arc<dyn AiProvider>;
        let rate_limiter = Arc::new(RateLimiter::new(1000, 100000));

        let engine = ExplainEngine {
            provider,
            cache: None,
            rate_limiter,
            default_context: ExplanationContext::default(),
            stats: Arc::new(RwLock::new(EngineStats::default())),
        };

        let finding = sample_finding();
        let findings = vec![finding.clone()];

        let result = engine.explain_batch(&findings, None).await;
        assert!(result.is_ok());

        let responses = result.unwrap();
        assert_eq!(responses.len(), 1);
        assert_eq!(responses[0].finding_id, finding.id);
    }

    #[tokio::test]
    async fn explain_batch_with_custom_context() {
        let provider = Arc::new(MockProvider::new()) as Arc<dyn AiProvider>;
        let rate_limiter = Arc::new(RateLimiter::new(1000, 100000));

        let engine = ExplainEngine {
            provider,
            cache: None,
            rate_limiter,
            default_context: ExplanationContext::default(),
            stats: Arc::new(RwLock::new(EngineStats::default())),
        };

        let finding = sample_finding();
        let findings = vec![finding];
        let custom_context = ExplanationContext::default();

        let result = engine.explain_batch(&findings, Some(&custom_context)).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn explain_batch_stats_tracking() {
        let provider = Arc::new(MockProvider::new()) as Arc<dyn AiProvider>;
        let rate_limiter = Arc::new(RateLimiter::new(1000, 100000));

        let engine = ExplainEngine {
            provider,
            cache: None,
            rate_limiter,
            default_context: ExplanationContext::default(),
            stats: Arc::new(RwLock::new(EngineStats::default())),
        };

        let findings = vec![
            Finding::new("R1", Severity::High, "F1", "D1"),
            Finding::new("R2", Severity::Medium, "F2", "D2"),
            Finding::new("R3", Severity::Low, "F3", "D3"),
        ];

        let result = engine.explain_batch(&findings, None).await;
        assert!(result.is_ok());

        let stats = engine.stats().await;
        assert_eq!(stats.total_explanations, 3);
        assert_eq!(stats.api_calls, 3);
    }

    #[tokio::test]
    async fn explain_uses_default_context() {
        use crate::ai::config::AudienceLevel;

        let provider = Arc::new(MockProvider::new()) as Arc<dyn AiProvider>;
        let rate_limiter = Arc::new(RateLimiter::new(1000, 100000));

        let mut default_context = ExplanationContext::default();
        default_context.audience = AudienceLevel::Expert;

        let engine = ExplainEngine {
            provider,
            cache: None,
            rate_limiter,
            default_context,
            stats: Arc::new(RwLock::new(EngineStats::default())),
        };

        let finding = sample_finding();
        let result = engine.explain(&finding).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn rate_limit_would_not_exceed_small_tokens() {
        let config = AiConfig::builder()
            .provider(AiProviderType::Ollama)
            .model("llama3.2")
            .build();

        let engine = ExplainEngine::new(config).unwrap();
        let would_exceed = engine.would_exceed_rate_limit(10).await;
        assert!(!would_exceed);
    }
}
