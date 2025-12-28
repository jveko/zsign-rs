pub mod assets;

#[cfg(feature = "openssl-backend")]
pub mod cms;
#[cfg(feature = "openssl-backend")]
pub mod cms_ffi;

#[cfg(feature = "pure-rust")]
pub mod cert;
#[cfg(feature = "pure-rust")]
pub mod cms_pure;

#[cfg(feature = "openssl-backend")]
pub use assets::SigningAssets;

#[cfg(feature = "pure-rust")]
pub use cert::PureRustCredentials;
