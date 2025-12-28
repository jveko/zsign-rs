pub mod parser;
pub mod signer;
#[cfg(feature = "pure-rust")]
pub mod signer_pure;
pub mod writer;

pub use parser::MachOFile;
#[cfg(feature = "openssl-backend")]
pub use signer::{sign_macho, sign_macho_all_slices};
pub use signer::SignedSlice;
#[cfg(feature = "pure-rust")]
pub use signer_pure::{sign_macho_pure, sign_macho_all_slices_pure};
pub use writer::{
    align_to, embed_signature, embed_signature_fat, prepare_code_for_signing,
    prepare_code_for_signing_slice, write_signed_macho, write_signed_macho_in_place,
};
