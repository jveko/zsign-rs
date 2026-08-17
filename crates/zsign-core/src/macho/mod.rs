//! Mach-O binary parsing, signing, and writing.
//!
//! This module provides functionality for working with Apple Mach-O binaries:
//!
//! - [`parser`] - Parse single-architecture and FAT/Universal Mach-O binaries
//! - [`signer`] - Build and embed code signatures
//! - [`writer`] - Modify binaries to include code signatures

pub mod parser;
pub mod signer;
pub mod verify;
pub mod writer;

#[cfg(test)]
pub(crate) mod fixtures;

pub use parser::{ArchSlice, EncryptionInfo, MachOFile, MachOMetadata};
pub use signer::{
    sign_any_macho, sign_macho, sign_macho_adhoc, sign_macho_all_slices, sign_macho_sha256_only,
    EMPTY_ENTITLEMENTS,
};
pub use verify::{verify_macho, MachOVerifyReport, SliceVerifyReport};
pub use writer::SignedSlice;
pub use writer::{
    align_to, calculate_signature_space, embed_signature, embed_signature_fat,
    prepare_code_for_signing, prepare_code_for_signing_slice,
};
