pub mod parser;
pub mod signer;

pub use parser::MachOFile;
pub use signer::sign_macho;
