pub mod parser;
pub mod signer;
pub mod writer;

pub use parser::MachOFile;
pub use signer::{sign_macho, sign_macho_all_slices, SignedSlice};
pub use writer::{embed_signature, embed_signature_fat, write_signed_macho, write_signed_macho_in_place};
