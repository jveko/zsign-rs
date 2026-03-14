//! Mach-O binary parsing, signing, and writing.
//!
//! This module provides functionality for working with Apple Mach-O binaries:
//!
//! - [`parser`] - Parse single-architecture and FAT/Universal Mach-O binaries
//! - [`signer`] - Build and embed code signatures
//! - [`writer`] - Modify binaries to include code signatures

pub mod parser;
pub mod signer;
pub mod writer;

pub use parser::{ArchSlice, MachOFile};
pub use writer::SignedSlice;
pub use signer::{sign_macho, sign_macho_all_slices, sign_any_macho, EMPTY_ENTITLEMENTS};
pub use writer::{
    align_to, embed_signature, embed_signature_fat, calculate_signature_space,
    prepare_code_for_signing, prepare_code_for_signing_slice,
};
