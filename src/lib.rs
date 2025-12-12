//! MCPLint - MCP Server Testing, Fuzzing, and Security Scanning Platform
//!
//! A comprehensive security and quality assurance library for Model Context Protocol servers.
//! Provides protocol validation, security scanning, coverage-guided fuzzing, and AI-assisted
//! vulnerability explanation.
//!
//! # Modules
//!
//! - `ai` - AI-powered vulnerability explanation engine
//! - `baseline` - Baseline/diff mode for incremental vulnerability detection
//! - `cache` - Multi-backend caching system with rug-pull detection
//! - `protocol` - MCP protocol definitions and JSON-RPC handling
//! - `scanner` - Security vulnerability scanning engine
//! - `validator` - Protocol compliance validation
//! - `fuzzer` - Coverage-guided fuzzing framework
//!
//! # Example
//!
//! ```rust,ignore
//! use mcplint::cache::{CacheConfig, CacheManager};
//! use mcplint::ai::{AiConfig, ExplainEngine};
//!
//! // Create a memory-only cache
//! let cache = CacheManager::memory();
//!
//! // Create an AI explanation engine
//! let config = AiConfig::default();
//! let engine = ExplainEngine::new(config)?;
//!
//! // Explain a finding
//! let explanation = engine.explain(&finding).await?;
//! println!("{}", explanation.explanation.summary);
//! ```

pub mod ai;
pub mod baseline;
pub mod cache;
pub mod client;
pub mod fingerprinting;
pub mod fuzzer;
pub mod protocol;
pub mod reporter;
pub mod rules;
pub mod scanner;
pub mod transport;
pub mod ui;
pub mod validator;

// Re-export commonly used types
pub use ai::{AiConfig, ExplainEngine, ExplanationResponse};
pub use baseline::{Baseline, DiffEngine, DiffResult};
pub use cache::{CacheConfig, CacheManager};
pub use fingerprinting::{
    ChangeSeverity, ChangeType, FingerprintComparator, FingerprintDiff, FingerprintHasher,
    FingerprintMetadata, NormalizedSchema, SchemaNormalizer, ToolFingerprint,
};
pub use scanner::{ScanEngine, ScanResults, Severity};
pub use ui::{OutputMode, Printer, ProgressStyle, ScanProgress, SecurityTheme, Theme};
pub use validator::ValidationEngine;
