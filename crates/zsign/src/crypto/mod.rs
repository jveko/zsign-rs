//! Cryptographic operations for iOS code signing.
//!
//! This module provides the core cryptographic primitives needed for signing
//! iOS applications and frameworks.
//!
//! # Overview
//!
//! - [`SigningCredentials`] - Load certificates and private keys from PEM or PKCS#12 files
//! - [`SigningKeyType`] - RSA or ECDSA private key for signing operations
//! - [`assets`] - Embedded Apple CA certificates for signature chain verification
//! - [`cms`] - CMS/PKCS#7 signature generation with Apple CDHash attributes
//!
//! # Examples
//!
//! ```no_run
//! use zsign::crypto::SigningCredentials;
//!
//! // Load from PKCS#12 file
//! let p12_data = std::fs::read("certificate.p12")?;
//! let credentials = SigningCredentials::from_p12(&p12_data, "password")?;
//!
//! // Access extracted team ID
//! if let Some(team_id) = &credentials.team_id {
//!     println!("Team ID: {}", team_id);
//! }
//! # Ok::<(), zsign::Error>(())
//! ```

pub mod assets;
pub mod cert;
pub mod cms;

pub use cert::SigningCredentials;
pub use cert::SigningKeyType;
