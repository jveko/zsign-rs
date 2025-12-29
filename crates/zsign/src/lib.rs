//! iOS code signing library.
//!
//! This crate provides functionality to sign Mach-O binaries, app bundles, and IPA files
//! for iOS and macOS. It supports PKCS#12 and PEM certificate formats, provisioning profiles,
//! and generates valid code signatures compatible with Apple's codesign tool.
//!
//! # Quick Start
//!
//! ```no_run
//! use zsign::{ZSign, SigningCredentials};
//!
//! // Load credentials from a PKCS#12 file
//! let p12_data = std::fs::read("certificate.p12").unwrap();
//! let credentials = SigningCredentials::from_p12(&p12_data, "password").unwrap();
//!
//! // Sign an IPA file
//! ZSign::new()
//!     .credentials(credentials)
//!     .provisioning_profile("app.mobileprovision")
//!     .sign_ipa("input.ipa", "output.ipa")
//!     .unwrap();
//! ```
//!
//! # Modules
//!
//! - [`builder`] - High-level builder API for signing operations
//! - [`bundle`] - App bundle handling and CodeResources generation
//! - [`codesign`] - Code signature blob generation
//! - [`crypto`] - Certificate and key handling
//! - [`error`] - Error types
//! - [`ipa`] - IPA archive operations
//! - [`macho`] - Mach-O binary parsing and signing
//!
//! # See Also
//!
//! - [`ZSign`] - Main entry point for signing operations
//! - [`SigningCredentials`] - Certificate and key management
//! - [`Error`] - All possible error conditions

pub mod builder;
pub mod bundle;
pub mod codesign;
pub mod crypto;
pub mod error;
pub mod ipa;
pub mod macho;

pub use builder::ZSign;
pub use bundle::CodeResourcesBuilder;
pub use crypto::SigningCredentials;
pub use error::Error;
pub use ipa::{create_ipa, extract_ipa, validate_ipa, CompressionLevel, IpaSigner};

/// Convenience result type for zsign operations.
///
/// This is a type alias for [`std::result::Result<T, Error>`] using the crate's [`Error`] type.
pub type Result<T> = std::result::Result<T, Error>;
