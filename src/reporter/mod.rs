//! Reporter - Output formatting and reporting
//!
//! Provides output formatting for scan results in various formats:
//! - Text (human-readable console output)
//! - JSON (machine-readable)
//! - SARIF (GitHub/GitLab CI integration)
//! - JUnit XML (Jenkins, CircleCI, Azure DevOps)
//! - GitLab Code Quality (GitLab MR integration)
//! - HTML (rich visual reports)

#![allow(dead_code)] // Generic reporter types for future use

pub mod gitlab;
pub mod html;
pub mod junit;
pub mod sarif;

pub use gitlab::generate_gitlab;
pub use html::generate_html;
pub use junit::generate_junit;

use serde::Serialize;

/// Trait for types that can be reported in multiple formats
pub trait Reportable {
    fn to_text(&self) -> String;
    fn to_json(&self) -> anyhow::Result<String>;
    fn to_sarif(&self) -> anyhow::Result<String>;
}

/// Generic report wrapper with metadata
#[derive(Debug, Clone, Serialize)]
pub struct Report<T: Serialize> {
    pub tool: String,
    pub version: String,
    pub timestamp: String,
    pub data: T,
}

impl<T: Serialize> Report<T> {
    pub fn new(data: T) -> Self {
        Self {
            tool: "mcplint".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            data,
        }
    }
}
