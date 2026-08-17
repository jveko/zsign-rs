//! Error types for zsign-core operations.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Invalid Mach-O: {0}")]
    MachO(String),

    #[error("Signing failed: {0}")]
    Signing(String),

    #[error("Invalid certificate: {0}")]
    Certificate(String),

    #[error("Invalid password for private key or PKCS#12")]
    InvalidPassword,

    #[error("Missing credentials: {0}")]
    MissingCredentials(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Invalid provisioning profile: {0}")]
    ProvisioningProfile(String),

    #[error("Plist error: {0}")]
    Plist(#[from] plist::Error),

    #[error("Binary parsing error: {0}")]
    Goblin(String),

    #[error("DER encoding error: {0}")]
    DerEncoding(String),

    #[error("Verification failed: {0}")]
    Verification(String),
}
