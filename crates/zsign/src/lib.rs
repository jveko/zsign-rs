pub mod builder;
pub mod bundle;
pub mod codesign;
pub mod crypto;
pub mod error;
pub mod ipa;
pub mod macho;

#[cfg(feature = "openssl-backend")]
pub use builder::ZSign;
pub use bundle::CodeResourcesBuilder;
pub use error::Error;
#[cfg(feature = "openssl-backend")]
pub use ipa::IpaSigner;
pub use ipa::{extract_ipa, create_ipa, validate_ipa, CompressionLevel};

pub type Result<T> = std::result::Result<T, Error>;
