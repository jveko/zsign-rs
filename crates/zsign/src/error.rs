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
    ///
    /// Occurs when reading input files, writing output files, or accessing
    /// the filesystem during signing operations.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Invalid or unsupported Mach-O binary format.
    ///
    /// The input file is not a valid Mach-O binary or uses an unsupported
    /// architecture or format.
    #[error("Invalid Mach-O: {0}")]
    MachO(String),

    /// Code signing operation failed.
    ///
    /// A general signing failure occurred during signature generation
    /// or embedding.
    #[error("Signing failed: {0}")]
    Signing(String),

    /// Invalid or malformed certificate.
    ///
    /// The provided certificate could not be parsed or is not suitable
    /// for code signing. See [`crate::SigningCredentials`] for valid formats.
    #[error("Invalid certificate: {0}")]
    Certificate(String),

    /// Incorrect password for private key or PKCS#12 file.
    ///
    /// The password provided to [`crate::SigningCredentials::from_p12`] or
    /// [`crate::SigningCredentials::from_pem`] is incorrect.
    #[error("Invalid password for private key or PKCS#12")]
    InvalidPassword,

    /// Required credentials not configured.
    ///
    /// Signing was attempted without first calling [`crate::ZSign::credentials`].
    #[error("Missing credentials: {0}")]
    MissingCredentials(String),

    /// Invalid builder configuration.
    ///
    /// A configuration value is invalid or conflicting options were specified.
    #[error("Configuration error: {0}")]
    Config(String),

    /// Invalid or malformed provisioning profile.
    ///
    /// The `.mobileprovision` file could not be parsed or does not contain
    /// required entitlements.
    #[error("Invalid provisioning profile: {0}")]
    ProvisioningProfile(String),

    /// Property list parsing failed.
    ///
    /// Failed to parse `Info.plist`, entitlements, or other plist data.
    #[error("Plist error: {0}")]
    Plist(#[from] plist::Error),

    /// ZIP archive operation failed.
    ///
    /// Occurs during IPA extraction or creation. See [`crate::ipa`] module.
    #[error("Zip error: {0}")]
    Zip(#[from] zip::result::ZipError),

    /// Mach-O binary parsing failed.
    ///
    /// Low-level binary parsing error from the goblin library.
    #[error("Binary parsing error: {0}")]
    Goblin(String),

    /// Symlinks not supported on this platform.
    ///
    /// Some platforms do not support symbolic links in app bundles.
    #[error("Symlink handling not supported on this platform")]
    SymlinkNotSupported,
}
