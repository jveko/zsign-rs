//! Mach-O binary parsing, signing, and writing.
//!
//! This module provides functionality for working with Apple Mach-O binaries:
//!
//! - [`parser`] - Parse single-architecture and FAT/Universal Mach-O binaries
//! - Signing via `zsign_core` (sign_macho, sign_macho_all_slices)
//! - Writing via `zsign_core` (embed_signature, embed_signature_fat)
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
//! use zsign_rs::macho::{MachOFile, sign_macho};
//!
//! let macho = MachOFile::open("path/to/binary")?;
//! println!("Is FAT binary: {}", macho.is_fat());
//! println!("Number of slices: {}", macho.slices().len());
//! # Ok::<(), zsign_rs::Error>(())
//! ```

pub mod parser;

pub use parser::{ArchSlice, MachOFile};
pub use zsign_core::macho::writer::{
    align_to, calculate_signature_space, embed_signature, embed_signature_fat,
    prepare_code_for_signing, prepare_code_for_signing_slice, SignedSlice,
};

/// Write signed Mach-O to file (native-only).
pub fn write_signed_macho(
    input_path: impl AsRef<std::path::Path>,
    output_path: impl AsRef<std::path::Path>,
    signature: &[u8],
) -> crate::Result<()> {
    let data = std::fs::read(input_path.as_ref())?;
    let output = embed_signature(&data, signature)?;
    std::fs::write(output_path.as_ref(), output)?;
    Ok(())
}

/// Write signed Mach-O in place (native-only).
pub fn write_signed_macho_in_place(
    binary_path: impl AsRef<std::path::Path>,
    signature: &[u8],
) -> crate::Result<()> {
    let data = std::fs::read(binary_path.as_ref())?;
    let output = embed_signature(&data, signature)?;
    std::fs::write(binary_path.as_ref(), output)?;
    Ok(())
}

/// Signs a single-architecture Mach-O binary.
///
/// Builds a complete code signature and embeds it into the binary.
/// For FAT binaries, use [`sign_macho_all_slices`] instead.
pub fn sign_macho(
    macho: &MachOFile,
    identifier: &str,
    entitlements: Option<&[u8]>,
    credentials: &zsign_core::crypto::SigningCredentials,
    info_plist: Option<&[u8]>,
    code_resources: Option<&[u8]>,
    allow_encrypted: bool,
) -> crate::Result<Vec<u8>> {
    Ok(zsign_core::macho::sign_macho(
        macho.as_core(),
        identifier,
        entitlements,
        credentials,
        info_plist,
        code_resources,
        allow_encrypted,
    )?)
}

/// Signs all architecture slices of a Mach-O binary.
///
/// Returns a [`SignedSlice`] for each architecture, suitable for reassembly
/// into a FAT binary using [`embed_signature_fat`].
pub fn sign_macho_all_slices(
    macho: &MachOFile,
    identifier: &str,
    entitlements: Option<&[u8]>,
    credentials: &zsign_core::crypto::SigningCredentials,
    info_plist: Option<&[u8]>,
    code_resources: Option<&[u8]>,
    allow_encrypted: bool,
) -> crate::Result<Vec<SignedSlice>> {
    Ok(zsign_core::macho::sign_macho_all_slices(
        macho.as_core(),
        identifier,
        entitlements,
        credentials,
        info_plist,
        code_resources,
        allow_encrypted,
    )?)
}

/// Signs a single-architecture Mach-O with no identity (ad-hoc).
pub fn sign_macho_adhoc(
    macho: &MachOFile,
    identifier: &str,
    entitlements: Option<&[u8]>,
    info_plist: Option<&[u8]>,
    code_resources: Option<&[u8]>,
    allow_encrypted: bool,
) -> crate::Result<Vec<u8>> {
    Ok(zsign_core::macho::sign_macho_adhoc(
        macho.as_core(),
        identifier,
        entitlements,
        info_plist,
        code_resources,
        allow_encrypted,
    )?)
}

/// Signs a single-architecture Mach-O emitting only the SHA-256 code
/// directory (no SHA-1 code directory slot).
pub fn sign_macho_sha256_only(
    macho: &MachOFile,
    identifier: &str,
    entitlements: Option<&[u8]>,
    credentials: &zsign_core::crypto::SigningCredentials,
    info_plist: Option<&[u8]>,
    code_resources: Option<&[u8]>,
    allow_encrypted: bool,
) -> crate::Result<Vec<u8>> {
    Ok(zsign_core::macho::sign_macho_sha256_only(
        macho.as_core(),
        identifier,
        entitlements,
        credentials,
        info_plist,
        code_resources,
        allow_encrypted,
    )?)
}

/// Signs any Mach-O binary (single-arch or FAT), returns signed bytes.
///
/// Automatically selects entitlements based on executable type:
/// - Executables use the provided entitlements
/// - Non-executables (dylibs, frameworks) use empty entitlements
pub fn sign_any_macho(
    macho: &MachOFile,
    identifier: &str,
    entitlements: Option<&[u8]>,
    credentials: &zsign_core::crypto::SigningCredentials,
    info_plist: Option<&[u8]>,
    code_resources: Option<&[u8]>,
    allow_encrypted: bool,
) -> crate::Result<Vec<u8>> {
    Ok(zsign_core::macho::sign_any_macho(
        macho.as_core(),
        identifier,
        entitlements,
        credentials,
        info_plist,
        code_resources,
        allow_encrypted,
    )?)
}

#[cfg(test)]
mod tests {}
