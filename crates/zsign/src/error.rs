//! Error types for zsign operations.
//!
//! This module defines the [`enum@Error`] enum covering all failure cases
//! in code signing operations, including I/O, parsing, cryptography,
//! and configuration errors.
//!
//! # See Also
//!
//! - [`crate::Result`] - Convenience type alias using this error

use thiserror::Error;

/// Error type for zsign operations.
///
/// All public functions in this crate return [`crate::Result<T>`], which uses this error type.
/// Match on variants to handle specific failure cases.
///
/// # Examples
///
/// ```no_run
/// use zsign::{ZSign, Error};
///
/// let result = ZSign::new().sign_ipa("input.ipa", "output.ipa");
/// match result {
///     Ok(()) => println!("Signed successfully"),
///     Err(Error::MissingCredentials(msg)) => eprintln!("Need credentials: {msg}"),
///     Err(Error::Io(e)) => eprintln!("IO error: {e}"),
///     Err(e) => eprintln!("Other error: {e}"),
/// }
/// ```
#[derive(Debug, Error)]
pub enum Error {
    /// I/O operation failed.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Invalid or unsupported Mach-O binary format.
    #[error("Invalid Mach-O: {0}")]
    MachO(String),

    /// Code signing operation failed.
    #[error("Signing failed: {0}")]
    Signing(String),

    /// Invalid or malformed certificate.
    #[error("Invalid certificate: {0}")]
    Certificate(String),

    /// Incorrect password for private key or PKCS#12 file.
    #[error("Invalid password for private key or PKCS#12")]
    InvalidPassword,

    /// Required credentials not configured.
    #[error("Missing credentials: {0}")]
    MissingCredentials(String),

    /// Invalid builder configuration.
    #[error("Configuration error: {0}")]
    Config(String),

    /// Invalid or malformed provisioning profile.
    #[error("Invalid provisioning profile: {0}")]
    ProvisioningProfile(String),

    /// Property list parsing failed.
    #[error("Plist error: {0}")]
    Plist(#[from] plist::Error),

    /// ZIP archive operation failed.
    #[error("Zip error: {0}")]
    Zip(#[from] zip::result::ZipError),

    /// Mach-O binary parsing failed.
    #[error("Binary parsing error: {0}")]
    Goblin(String),

    /// Symlinks not supported on this platform.
    #[error("Symlink handling not supported on this platform")]
    SymlinkNotSupported,
}

impl From<zsign_core::Error> for Error {
    fn from(e: zsign_core::Error) -> Self {
        match e {
            zsign_core::Error::MachO(s) => Error::MachO(s),
            zsign_core::Error::Signing(s) => Error::Signing(s),
            zsign_core::Error::Certificate(s) => Error::Certificate(s),
            zsign_core::Error::InvalidPassword => Error::InvalidPassword,
            zsign_core::Error::MissingCredentials(s) => Error::MissingCredentials(s),
            zsign_core::Error::Config(s) => Error::Config(s),
            zsign_core::Error::ProvisioningProfile(s) => Error::ProvisioningProfile(s),
            zsign_core::Error::Plist(e) => Error::Plist(e),
            zsign_core::Error::Goblin(s) => Error::Goblin(s),
        }
    }
}
