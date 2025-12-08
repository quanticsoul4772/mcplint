//! Baseline Module - Incremental vulnerability detection
//!
//! Provides baseline/diff capabilities for CI/CD workflows, enabling
//! teams to track security posture changes and fail only on new findings.

mod diff;
mod fingerprint;
mod store;

// Re-exports for public API - used by external consumers and library users
#[allow(unused_imports)]
pub use diff::{DiffEngine, DiffResult, DiffSummary};
pub use fingerprint::FindingFingerprint;
#[allow(unused_imports)]
pub use store::{Baseline, BaselineConfig, BaselineFinding};
