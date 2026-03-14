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
/// use zsign_rs::{ZSign, Error};
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

    /// Required credentials not configured.
    #[error("Missing credentials: {0}")]
    MissingCredentials(String),

    /// Property list parsing failed.
    #[error("Plist error: {0}")]
    Plist(#[from] plist::Error),

    /// ZIP archive operation failed.
    #[error("Zip error: {0}")]
    Zip(#[from] zip::result::ZipError),

    /// Symlinks not supported on this platform.
    #[error("Symlink handling not supported on this platform")]
    SymlinkNotSupported,

    /// Core library error (forwarded from zsign-core).
    #[error(transparent)]
    Core(zsign_core::Error),
}

impl From<zsign_core::Error> for Error {
    fn from(e: zsign_core::Error) -> Self {
        match e {
            zsign_core::Error::Plist(e) => Error::Plist(e),
            other => Error::Core(other),
        }
    }
}
