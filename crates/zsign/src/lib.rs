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

pub type Result<T> = std::result::Result<T, Error>;
