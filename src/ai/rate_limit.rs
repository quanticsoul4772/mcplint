//! Rate Limiting - API call throttling
//!
//! Provides rate limiting to prevent excessive API costs
//! and respect provider rate limits.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;

/// Rate limiter for API calls
pub struct RateLimiter {
    /// Requests per minute limit
    rpm_limit: u32,
    /// Tokens per minute limit
    tpm_limit: u32,
    /// State tracking
    state: Arc<Mutex<RateLimitState>>,
}

struct RateLimitState {
    /// Window start time
    window_start: Instant,
    /// Requests in current window
    requests: u32,
    /// Tokens in current window
    tokens: u32,
}

impl RateLimiter {
    /// Create a new rate limiter
    pub fn new(rpm_limit: u32, tpm_limit: u32) -> Self {
        Self {
            rpm_limit,
            tpm_limit,
            state: Arc::new(Mutex::new(RateLimitState {
                window_start: Instant::now(),
                requests: 0,
                tokens: 0,
            })),
        }
    }

    /// Create an unlimited rate limiter (for local models)
    pub fn unlimited() -> Self {
        Self::new(u32::MAX, u32::MAX)
    }

    /// Wait if necessary and record a request
    pub async fn acquire(&self, estimated_tokens: u32) -> Result<(), RateLimitError> {
        loop {
            let mut state = self.state.lock().await;

            // Reset window if expired
            if state.window_start.elapsed() > Duration::from_secs(60) {
                state.window_start = Instant::now();
                state.requests = 0;
                state.tokens = 0;
            }

            // Check if we need to wait for requests limit
            if state.requests >= self.rpm_limit {
                let wait_time = Duration::from_secs(60) - state.window_start.elapsed();
                drop(state);
                tokio::time::sleep(wait_time).await;
                continue;
            }

            // Check if we need to wait for tokens limit
            if state.tokens + estimated_tokens > self.tpm_limit {
                let wait_time = Duration::from_secs(60) - state.window_start.elapsed();
                drop(state);
                tokio::time::sleep(wait_time).await;
                continue;
            }

            // Record the request
            state.requests += 1;
            state.tokens += estimated_tokens;

            return Ok(());
        }
    }

    /// Record actual tokens used after a request completes
    pub async fn record_tokens(&self, actual_tokens: u32, estimated_tokens: u32) {
        let mut state = self.state.lock().await;

        // Adjust token count based on actual usage
        if actual_tokens > estimated_tokens {
            state.tokens += actual_tokens - estimated_tokens;
        }
    }

    /// Get current usage stats
    pub async fn stats(&self) -> RateLimitStats {
        let state = self.state.lock().await;
        let elapsed = state.window_start.elapsed();

        RateLimitStats {
            requests_used: state.requests,
            requests_limit: self.rpm_limit,
            tokens_used: state.tokens,
            tokens_limit: self.tpm_limit,
            window_remaining_secs: if elapsed < Duration::from_secs(60) {
                60 - elapsed.as_secs()
            } else {
                60
            },
        }
    }

    /// Check if rate limit would be exceeded
    pub async fn would_exceed(&self, estimated_tokens: u32) -> bool {
        let state = self.state.lock().await;

        // Check if window needs reset
        if state.window_start.elapsed() > Duration::from_secs(60) {
            return false;
        }

        state.requests >= self.rpm_limit || state.tokens + estimated_tokens > self.tpm_limit
    }
}

/// Rate limit statistics
#[derive(Debug, Clone)]
pub struct RateLimitStats {
    pub requests_used: u32,
    pub requests_limit: u32,
    pub tokens_used: u32,
    pub tokens_limit: u32,
    pub window_remaining_secs: u64,
}

impl RateLimitStats {
    pub fn requests_remaining(&self) -> u32 {
        self.requests_limit.saturating_sub(self.requests_used)
    }

    pub fn tokens_remaining(&self) -> u32 {
        self.tokens_limit.saturating_sub(self.tokens_used)
    }

    pub fn is_at_limit(&self) -> bool {
        self.requests_remaining() == 0 || self.tokens_remaining() == 0
    }
}

/// Rate limit error
#[derive(Debug, thiserror::Error)]
pub enum RateLimitError {
    #[error("Rate limit exceeded, retry after {wait_secs}s")]
    Exceeded { wait_secs: u64 },
}

/// Simple retry with exponential backoff
pub struct RetryConfig {
    /// Maximum number of retries
    pub max_retries: u32,
    /// Initial delay between retries
    pub initial_delay: Duration,
    /// Maximum delay between retries
    pub max_delay: Duration,
    /// Multiplier for exponential backoff
    pub backoff_factor: f64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            initial_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(60),
            backoff_factor: 2.0,
        }
    }
}

impl RetryConfig {
    /// Calculate delay for a given attempt
    pub fn delay_for_attempt(&self, attempt: u32) -> Duration {
        let delay = self.initial_delay.as_secs_f64() * self.backoff_factor.powi(attempt as i32);
        let delay = delay.min(self.max_delay.as_secs_f64());
        Duration::from_secs_f64(delay)
    }

    /// Execute an async operation with retries
    pub async fn execute<F, Fut, T, E>(&self, mut operation: F) -> Result<T, E>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = Result<T, E>>,
        E: std::fmt::Debug,
    {
        let mut attempt = 0;
        loop {
            match operation().await {
                Ok(result) => return Ok(result),
                Err(e) => {
                    if attempt >= self.max_retries {
                        return Err(e);
                    }

                    let delay = self.delay_for_attempt(attempt);
                    tracing::warn!(
                        "Attempt {} failed, retrying in {:?}: {:?}",
                        attempt + 1,
                        delay,
                        e
                    );

                    tokio::time::sleep(delay).await;
                    attempt += 1;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn rate_limiter_allows_under_limit() {
        let limiter = RateLimiter::new(10, 1000);

        // Should allow first few requests
        assert!(limiter.acquire(100).await.is_ok());
        assert!(limiter.acquire(100).await.is_ok());

        let stats = limiter.stats().await;
        assert_eq!(stats.requests_used, 2);
        assert_eq!(stats.tokens_used, 200);
    }

    #[tokio::test]
    async fn rate_limiter_tracks_tokens() {
        let limiter = RateLimiter::new(100, 500);

        limiter.acquire(100).await.unwrap();
        limiter.acquire(100).await.unwrap();

        // Should detect that we would exceed
        assert!(limiter.would_exceed(400).await);
        assert!(!limiter.would_exceed(200).await);
    }

    #[test]
    fn retry_delay_calculation() {
        let config = RetryConfig::default();

        assert_eq!(config.delay_for_attempt(0), Duration::from_secs(1));
        assert_eq!(config.delay_for_attempt(1), Duration::from_secs(2));
        assert_eq!(config.delay_for_attempt(2), Duration::from_secs(4));
    }

    #[test]
    fn retry_delay_respects_max() {
        let config = RetryConfig {
            max_delay: Duration::from_secs(5),
            ..Default::default()
        };

        // After enough retries, should hit max
        assert!(config.delay_for_attempt(10) <= Duration::from_secs(5));
    }
}
