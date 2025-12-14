//! Security Check Modules
//!
//! Individual security check implementations organized by category.
//! These modules provide modular, trait-based security checks with comprehensive tests.
//! Used internally by scanner and available for library consumers.
//!
//! Public library API - traits enable custom check implementations.
//! Scanner uses inline checks; traits exist for extensibility and testing.

// Public API not consumed by CLI - available for library consumers.
#![allow(dead_code)]

pub mod auth;
pub mod data;
pub mod dos;
pub mod injection;
pub mod protocol;
pub mod transport;

// Re-export check traits/functions for convenience
#[allow(unused_imports)]
pub use auth::AuthChecks;
#[allow(unused_imports)]
pub use data::DataChecks;
#[allow(unused_imports)]
pub use dos::DosChecks;
#[allow(unused_imports)]
pub use injection::InjectionChecks;
#[allow(unused_imports)]
pub use protocol::ProtocolChecks;
#[allow(unused_imports)]
pub use transport::TransportChecks;
