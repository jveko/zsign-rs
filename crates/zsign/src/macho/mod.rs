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
) -> crate::Result<Vec<u8>> {
    Ok(zsign_core::macho::sign_macho(
        macho.as_core(),
        identifier,
        entitlements,
        credentials,
        info_plist,
        code_resources,
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
) -> crate::Result<Vec<SignedSlice>> {
    Ok(zsign_core::macho::sign_macho_all_slices(
        macho.as_core(),
        identifier,
        entitlements,
        credentials,
        info_plist,
        code_resources,
    )?)
}

/// Signs a single-architecture Mach-O with no identity (ad-hoc).
pub fn sign_macho_adhoc(
    macho: &MachOFile,
    identifier: &str,
    entitlements: Option<&[u8]>,
    info_plist: Option<&[u8]>,
    code_resources: Option<&[u8]>,
) -> crate::Result<Vec<u8>> {
    Ok(zsign_core::macho::sign_macho_adhoc(
        macho.as_core(),
        identifier,
        entitlements,
        info_plist,
        code_resources,
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
) -> crate::Result<Vec<u8>> {
    Ok(zsign_core::macho::sign_macho_sha256_only(
        macho.as_core(),
        identifier,
        entitlements,
        credentials,
        info_plist,
        code_resources,
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
) -> crate::Result<Vec<u8>> {
    Ok(zsign_core::macho::sign_any_macho(
        macho.as_core(),
        identifier,
        entitlements,
        credentials,
        info_plist,
        code_resources,
    )?)
}

/// Read-only report of a Mach-O binary's embedded code signature.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CheckReport {
    /// Whether an embedded signature SuperBlob was found.
    pub signed: bool,
    /// Bundle identifier recorded in a CodeDirectory, if present.
    pub identifier: Option<String>,
    /// Number of SHA-1 code pages from the SHA-1 CodeDirectory, if present.
    pub sha1_pages: Option<usize>,
    /// Number of SHA-256 code pages from the SHA-256 CodeDirectory, if present.
    pub sha256_pages: Option<usize>,
    /// Whether a CMS signature slot is present.
    pub cms_present: bool,
    /// Whether any CodeDirectory's stored code-page hashes match hashes
    /// recomputed over the binary's code region.
    pub hashes_match: bool,
}

/// Checks the embedded code signature of a single-architecture Mach-O binary.
///
/// Reads the file, locates the `LC_CODE_SIGNATURE` superblob, and verifies its
/// structure: the presence of a SHA-1/SHA-256 CodeDirectory, the recorded
/// identifier, whether stored code-page hashes match freshly computed ones,
/// and whether a CMS signature blob is present.
///
/// # Errors
///
/// Returns [`crate::Error`] if the file cannot be read, is not a valid Mach-O,
/// or is a FAT/Universal binary (unsupported).
pub fn check_signature(path: impl AsRef<std::path::Path>) -> crate::Result<CheckReport> {
    use zsign_core::codesign::constants::{
        CSMAGIC_BLOBWRAPPER, CSMAGIC_EMBEDDED_SIGNATURE, CSSLOT_ALTERNATE_CODEDIRECTORIES,
        CSSLOT_CODEDIRECTORY, CSSLOT_SIGNATURESLOT, CS_HASHTYPE_SHA1, CS_HASHTYPE_SHA256,
        CS_SHA1_LEN, CS_SHA256_LEN,
    };
    use zsign_core::codesign::hash_code_pages_dual;

    let data = std::fs::read(path.as_ref())?;
    let macho = zsign_core::macho::MachOFile::parse(data.clone())?;

    if macho.is_fat() {
        return Err(crate::Error::Core(zsign_core::Error::MachO(
            "fat binaries not supported by check".into(),
        )));
    }

    let slice = &macho.slices()[0];
    let (sig_off, sig_size) = match (slice.code_sig_offset, slice.code_sig_size) {
        (Some(off), Some(size)) => (off as usize, size as usize),
        _ => return Ok(CheckReport::default()),
    };

    let Some(blob) = data.get(sig_off..sig_off.saturating_add(sig_size)) else {
        return Ok(CheckReport::default());
    };

    // SuperBlob magic, big-endian (0xfa de 0c c0).
    if blob.len() < 8 || blob[0..4] != CSMAGIC_EMBEDDED_SIGNATURE.to_be_bytes() {
        return Ok(CheckReport::default());
    }

    let mut report = CheckReport {
        signed: true,
        ..CheckReport::default()
    };

    let count = u32::from_be_bytes(blob[8..12].try_into().unwrap()) as usize;
    let code = macho.code_bytes(slice).to_vec();
    let dual = hash_code_pages_dual(&code);

    for i in 0..count {
        let entry_off = 12 + i * 8;
        let Some(entry) = blob.get(entry_off..entry_off + 8) else {
            break;
        };
        let typ = u32::from_be_bytes(entry[0..4].try_into().unwrap());
        let offset = u32::from_be_bytes(entry[4..8].try_into().unwrap()) as usize;

        match typ {
            CSSLOT_CODEDIRECTORY | CSSLOT_ALTERNATE_CODEDIRECTORIES => {
                let Some(cd) = blob.get(offset..) else {
                    continue;
                };
                if cd.len() < 40 {
                    continue;
                }
                let hash_offset = u32::from_be_bytes(cd[16..20].try_into().unwrap()) as usize;
                let ident_offset = u32::from_be_bytes(cd[20..24].try_into().unwrap()) as usize;
                let n_code_slots = u32::from_be_bytes(cd[28..32].try_into().unwrap()) as usize;
                let hash_size = cd[36] as usize;
                let hash_type = cd[37];

                if report.identifier.is_none() && ident_offset < cd.len() {
                    if let Some(ident) = cd[ident_offset..]
                        .split(|&b| b == 0)
                        .next()
                        .filter(|s| !s.is_empty())
                        .and_then(|s| std::str::from_utf8(s).ok())
                    {
                        report.identifier = Some(ident.to_string());
                    }
                }

                match (hash_size, hash_type) {
                    (CS_SHA1_LEN, CS_HASHTYPE_SHA1) => {
                        report.sha1_pages = Some(n_code_slots);
                        if n_code_slots * CS_SHA1_LEN <= dual.sha1.len() {
                            if let Some(stored) =
                                cd.get(hash_offset..hash_offset + n_code_slots * CS_SHA1_LEN)
                            {
                                if stored == &dual.sha1[..n_code_slots * CS_SHA1_LEN] {
                                    report.hashes_match = true;
                                }
                            }
                        }
                    }
                    (CS_SHA256_LEN, CS_HASHTYPE_SHA256) => {
                        report.sha256_pages = Some(n_code_slots);
                        if n_code_slots * CS_SHA256_LEN <= dual.sha256.len() {
                            if let Some(stored) =
                                cd.get(hash_offset..hash_offset + n_code_slots * CS_SHA256_LEN)
                            {
                                if stored == &dual.sha256[..n_code_slots * CS_SHA256_LEN] {
                                    report.hashes_match = true;
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
            CSSLOT_SIGNATURESLOT => {
                let Some(sig) = blob.get(offset..) else {
                    continue;
                };
                if sig.len() >= 8 && sig[0..4] == CSMAGIC_BLOBWRAPPER.to_be_bytes() {
                    let length = u32::from_be_bytes(sig[4..8].try_into().unwrap()) as usize;
                    if length > 100 {
                        report.cms_present = true;
                    }
                }
            }
            _ => {}
        }
    }

    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{minimal_macho, test_credentials};

    #[test]
    fn check_signature_reports_unsigned_binary() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("unsigned");
        std::fs::write(&path, minimal_macho()).unwrap();

        let report = check_signature(&path).unwrap();
        assert!(!report.signed);
        assert_eq!(report.identifier, None);
        assert!(!report.cms_present);
        assert!(!report.hashes_match);
    }

    #[test]
    fn check_signature_reports_signed_binary() {
        let creds = test_credentials();
        let macho = MachOFile::parse(minimal_macho()).unwrap();
        let signed = sign_macho(&macho, "com.check.test", None, &creds, None, None)
            .expect("signing must succeed");

        let code_length = macho.slices()[0].code_length;
        let expected_pages = code_length.div_ceil(4096);

        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("signed");
        std::fs::write(&path, &signed).unwrap();

        let report = check_signature(&path).unwrap();
        assert!(report.signed, "signed binary must be reported as signed");
        assert_eq!(report.identifier.as_deref(), Some("com.check.test"));
        assert!(report.hashes_match, "recomputed page hashes must match");
        assert!(report.cms_present, "CMS signature slot must be present");
        assert_eq!(report.sha1_pages, Some(expected_pages));
        assert_eq!(report.sha256_pages, Some(expected_pages));
    }
}
