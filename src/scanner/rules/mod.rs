//! Advanced Security Rules - M6 Detection Implementations
//!
//! Implements detection logic for advanced security rules SEC-040 through SEC-045.

pub mod oauth_abuse;
pub mod schema_poisoning;
pub mod tool_injection;
pub mod tool_shadowing;
pub mod unicode_hidden;

pub use oauth_abuse::OAuthAbuseDetector;
pub use schema_poisoning::SchemaPoisoningDetector;
pub use tool_injection::ToolInjectionDetector;
pub use tool_shadowing::ToolShadowingDetector;
pub use unicode_hidden::UnicodeHiddenDetector;
