//! Tool Definition Fingerprinting Module
//!
//! Provides dual-tier fingerprinting for MCP tool definitions:
//! - **Semantic Hash**: Tracks meaningful schema changes (types, constraints, required fields)
//! - **Full Content Hash**: Provides audit trail and tamper detection
//!
//! # Architecture
//!
//! The fingerprinting system consists of three main components:
//! - `SchemaNormalizer`: Canonicalizes JSON schemas for consistent comparison
//! - `FingerprintHasher`: Generates SHA-256 hashes from normalized schemas
//! - `FingerprintComparator`: Compares fingerprints and generates diff reports
//!
//! # Example
//!
//! ```rust,ignore
//! use mcplint::fingerprinting::{ToolFingerprint, FingerprintHasher};
//! use mcplint::protocol::mcp::Tool;
//!
//! // Generate a fingerprint from a tool definition
//! let fingerprint = FingerprintHasher::fingerprint(&tool)?;
//!
//! // Compare two fingerprints
//! let diff = FingerprintComparator::compare(&old_fingerprint, &new_fingerprint);
//! println!("Severity: {:?}", diff.severity);
//! ```

mod comparator;
mod hasher;
mod normalizer;
mod types;

// Re-export public API (allow unused - these are intentional public exports)
#[allow(unused_imports)]
pub use comparator::{ChangeSeverity, ChangeType, FingerprintComparator, FingerprintDiff};
pub use hasher::FingerprintHasher;
#[allow(unused_imports)]
pub use normalizer::{NormalizedSchema, SchemaNormalizer};
#[allow(unused_imports)]
pub use types::{FingerprintMetadata, ToolFingerprint};
