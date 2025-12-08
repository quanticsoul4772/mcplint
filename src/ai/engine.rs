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
    async fn get_cached(&self, finding: &Finding, context: &ExplanationContext) -> Option<ExplanationResponse> {
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
    async fn store_cached(&self, finding: &Finding, context: &ExplanationContext, response: &ExplanationResponse) {
        if let Some(cache) = &self.cache {
            let key = self.cache_key(finding, context);
            if let Err(e) = cache.set(&key, response).await {
                tracing::warn!("Failed to cache explanation: {}", e);
            }
        }
    }

    /// Explain a single finding
    pub async fn explain(&self, finding: &Finding) -> Result<ExplanationResponse> {
        self.explain_with_context(finding, &self.default_context).await
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
    fn token_estimation() {
        let finding = sample_finding();
        let tokens = estimate_tokens(&finding);

        // Should have base + content + response estimate
        assert!(tokens > 500);
        assert!(tokens < 10000);
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
}
