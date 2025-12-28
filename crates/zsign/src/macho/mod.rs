pub mod parser;
pub mod signer;
pub mod writer;

pub use parser::MachOFile;
pub use signer::{sign_macho, sign_macho_all_slices, SignedSlice};
pub use writer::{
    align_to, embed_signature, embed_signature_fat, prepare_code_for_signing,
    prepare_code_for_signing_slice, write_signed_macho, write_signed_macho_in_place,
};
