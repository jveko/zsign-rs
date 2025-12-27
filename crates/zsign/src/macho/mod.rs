pub mod parser;
pub mod signer;
pub mod writer;

pub use parser::MachOFile;
pub use signer::sign_macho;
pub use writer::{embed_signature, write_signed_macho, write_signed_macho_in_place};
