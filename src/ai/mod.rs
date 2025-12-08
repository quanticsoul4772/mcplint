//! AI Module - AI-Assisted Vulnerability Explanation
//!
//! Provides AI-powered explanations for security findings using
//! multiple provider backends (Anthropic, OpenAI, Ollama).
//!
//! # Example
//!
//! ```rust,ignore
//! use mcplint::ai::{AiConfig, ExplainEngine};
//! use mcplint::scanner::Finding;
//!
//! let config = AiConfig::default();
//! let engine = ExplainEngine::new(config, cache).await?;
//!
//! let explanation = engine.explain(&finding).await?;
//! println!("{}", explanation.summary);
//! ```

// Allow dead_code for library functions that are part of the public API
#![allow(dead_code)]

pub mod config;
pub mod engine;
pub mod prompt;
pub mod provider;
pub mod rate_limit;
pub mod response;
pub mod streaming;

// Re-exports for convenience - these are public API exports used by external consumers
#[allow(unused_imports)]
pub use config::{AiConfig, AiProvider as AiProviderType, AudienceLevel, ExplanationContext};
#[allow(unused_imports)]
pub use engine::{EngineStats, ExplainEngine};
#[allow(unused_imports)]
pub use prompt::PromptBuilder;
#[allow(unused_imports)]
pub use provider::{AiProvider, MockProvider};
#[allow(unused_imports)]
pub use rate_limit::RateLimiter;
#[allow(unused_imports)]
pub use response::{
    CodeExample, EducationalContext, ExplanationMetadata, ExplanationResponse, Likelihood,
    RemediationGuide, ResourceLink, VulnerabilityExplanation, WeaknessInfo,
};
#[allow(unused_imports)]
pub use streaming::{
    stream_channel, ChunkReceiver, ChunkSender, CollectCallback, PrintCallback, StreamAccumulator,
    StreamCallback, StreamChunk,
};
