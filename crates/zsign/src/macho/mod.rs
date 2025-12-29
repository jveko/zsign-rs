//! Mach-O binary parsing, signing, and writing.
//!
//! This module provides functionality for working with Apple Mach-O binaries:
//!
//! - [`parser`] - Parse single-architecture and FAT/Universal Mach-O binaries
//! - [`signer`] - Build and embed code signatures
//! - [`writer`] - Modify binaries to include code signatures
//!
//! # Overview
//!
//! The typical workflow for signing a Mach-O binary:
//!
//! 1. Parse the binary with [`MachOFile::open`] or [`MachOFile::parse`]
//! 2. Sign with [`sign_macho`] (single-arch) or [`sign_macho_all_slices`] (FAT)
//! 3. Write using [`write_signed_macho`] or embed with [`embed_signature_fat`]
//!
//! # Examples
//!
//! ```no_run
//! use zsign::macho::{MachOFile, sign_macho};
//!
//! let macho = MachOFile::open("path/to/binary")?;
//! println!("Is FAT binary: {}", macho.is_fat());
//! println!("Number of slices: {}", macho.slices().len());
//! # Ok::<(), zsign::Error>(())
//! ```

pub mod parser;
pub mod signer;
pub mod writer;

pub use parser::MachOFile;
pub use signer::{sign_macho, sign_macho_all_slices, SignedSlice};
pub use writer::{
    align_to, embed_signature, embed_signature_fat, prepare_code_for_signing,
    prepare_code_for_signing_slice, write_signed_macho, write_signed_macho_in_place,
};
