//! Core iOS code signing library (WASM-compatible).
//!
//! This crate contains pure computation modules for iOS code signing.
//! No filesystem, no threads — safe for `wasm32-unknown-unknown`.

pub mod bundle;
pub mod codesign;
pub mod crypto;
pub mod error;
pub mod macho;
pub mod provisioning;

pub use bundle::CodeResourcesBuilder;
pub use crypto::SigningCredentials;
pub use error::Error;
pub use provisioning::extract_entitlements_from_profile;

/// Convenience result type for zsign-core operations.
pub type Result<T> = std::result::Result<T, Error>;
