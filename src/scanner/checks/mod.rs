//! Security Check Modules
//!
//! Individual security check implementations organized by category.
//! These modules provide a modular structure for security checks,
//! allowing future migration of checks from engine.rs.

#![allow(dead_code)] // Modules prepared for future migration

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
