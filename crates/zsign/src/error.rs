use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

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

    #[cfg(feature = "openssl-backend")]
    #[error("OpenSSL error: {0}")]
    OpenSsl(#[from] openssl::error::ErrorStack),

    #[error("Plist error: {0}")]
    Plist(#[from] plist::Error),

    #[error("Zip error: {0}")]
    Zip(#[from] zip::result::ZipError),

    #[error("Binary parsing error: {0}")]
    Goblin(String),

    #[error("Symlink handling not supported on this platform")]
    SymlinkNotSupported,
}
