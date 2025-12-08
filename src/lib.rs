//! MCPLint - MCP Server Testing, Fuzzing, and Security Scanning Platform
//!
//! A comprehensive security and quality assurance library for Model Context Protocol servers.
//! Provides protocol validation, security scanning, and coverage-guided fuzzing.
//!
//! # Modules
//!
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
//!
//! // Create a memory-only cache
//! let cache = CacheManager::memory();
//!
//! // Cache some data
//! cache.set_schema("server-id", &tools).await?;
//!
//! // Retrieve cached data
//! if let Some(tools) = cache.get_schema("server-id").await? {
//!     println!("Cache hit!");
//! }
//! ```

pub mod cache;
pub mod client;
pub mod fuzzer;
pub mod protocol;
pub mod reporter;
pub mod rules;
pub mod scanner;
pub mod transport;
pub mod validator;

// Re-export commonly used types
pub use cache::{CacheConfig, CacheManager};
pub use scanner::{ScanEngine, ScanResults};
pub use validator::ValidationEngine;
