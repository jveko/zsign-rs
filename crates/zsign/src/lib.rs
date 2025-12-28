pub mod builder;
#[cfg(feature = "pure-rust")]
pub mod builder_pure;
pub mod bundle;
pub mod codesign;
pub mod crypto;
pub mod error;
pub mod ipa;
pub mod macho;

#[cfg(feature = "openssl-backend")]
pub use builder::ZSign;
#[cfg(feature = "pure-rust")]
pub use builder_pure::ZSignPure;
pub use bundle::CodeResourcesBuilder;
pub use error::Error;
#[cfg(feature = "openssl-backend")]
pub use ipa::IpaSigner;
#[cfg(feature = "pure-rust")]
pub use ipa::IpaSignerPure;
pub use ipa::{extract_ipa, create_ipa, validate_ipa, CompressionLevel};
#[cfg(feature = "pure-rust")]
pub use crypto::PureRustCredentials;

pub type Result<T> = std::result::Result<T, Error>;
