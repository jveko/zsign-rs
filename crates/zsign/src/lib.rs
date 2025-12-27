pub mod codesign;
pub mod crypto;
pub mod error;
pub mod macho;

pub use error::Error;

pub type Result<T> = std::result::Result<T, Error>;
