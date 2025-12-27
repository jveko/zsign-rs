pub mod builder;
pub mod codesign;
pub mod crypto;
pub mod error;
pub mod macho;

pub use builder::ZSign;
pub use error::Error;

pub type Result<T> = std::result::Result<T, Error>;
