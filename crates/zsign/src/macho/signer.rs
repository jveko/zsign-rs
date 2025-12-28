//! Mach-O signing implementation
//!
//! This module provides the core signing functionality for Mach-O binaries,
//! building CodeDirectory structures with page hashes and assembling them
//! into a SuperBlob with all required signature components.
//!
//! ## Signing Flow
//!
//! The signing process uses a two-pass approach to ensure page hashes are correct:
//!
//! 1. **Pass 1**: Build preliminary signature to measure its size
//! 2. **Pass 2**: Prepare code with actual signature size (updating load commands),
//!    rebuild signature with correct hashes, and embed into the prepared code
//!
//! This is necessary because page 0 contains the Mach-O header and load commands,
//! which must reflect the final signature offset and size.

use crate::codesign::code_directory::{
    compute_cdhash_sha1, compute_cdhash_sha256, CodeDirectoryBuilder,
};
use crate::codesign::constants::{CS_EXECSEG_ALLOW_UNSIGNED, CS_EXECSEG_MAIN_BINARY};
use crate::codesign::der::plist_to_der;
use crate::codesign::superblob::{
    build_der_entitlements_blob, build_entitlements_blob, build_requirements_blob_full,
    build_signature_blob, SuperBlobBuilder,
};
use crate::crypto::cms;
use crate::Result;
use openssl::nid::Nid;
use openssl::pkey::{PKeyRef, Private};
use openssl::x509::{X509, X509Ref};
use rayon::prelude::*;
use sha1::{Digest, Sha1};
use sha2::Sha256;

use super::parser::{ArchSlice, MachOFile};
use super::writer::{has_enough_signature_space, prepare_code_for_signing_slice, realloc_code_sign_space_slice};

/// Represents a signed architecture slice with its complete binary data.
#[derive(Debug, Clone)]
pub struct SignedSlice {
    /// Index of the slice in the original Mach-O file
    pub slice_index: usize,
    /// Offset of the slice in the original file
    pub offset: usize,
    /// Size of the original slice (before signature)
    pub original_size: usize,
    /// The complete signed binary data (code + embedded signature)
    pub signed_data: Vec<u8>,
}

/// Sign a Mach-O binary and return the complete signed binary data.
///
/// This function builds a complete code signature and embeds it into the binary.
/// Returns the complete signed binary ready to be written to disk.
///
/// # Arguments
///
/// * `macho` - The parsed Mach-O file to sign
/// * `identifier` - Bundle identifier (e.g., "com.example.app")
/// * `team_id` - Team identifier (None for ad-hoc signing)
/// * `entitlements` - Optional entitlements plist data (XML format)
/// * `cert` - X.509 signing certificate
/// * `pkey` - Private key corresponding to the certificate
/// * `cert_chain` - Certificate chain (intermediate CAs)
/// * `info_plist` - Optional Info.plist data for hashing
/// * `code_resources` - Optional CodeResources data for hashing
///
/// # Returns
///
/// A `Vec<u8>` containing the complete signed binary.
pub fn sign_macho(
    macho: &MachOFile,
    identifier: &str,
    team_id: Option<&str>,
    entitlements: Option<&[u8]>,
    cert: &X509Ref,
    pkey: &PKeyRef<Private>,
    cert_chain: &[X509],
    info_plist: Option<&[u8]>,
    code_resources: Option<&[u8]>,
) -> Result<Vec<u8>> {
    let slice = &macho.slices()[0];
    let slice_data = macho.slice_data(slice);

    let signed = sign_slice_complete(
        slice_data,
        slice,
        identifier,
        team_id,
        entitlements,
        cert,
        pkey,
        cert_chain,
        info_plist,
        code_resources,
    )?;

    Ok(signed.signed_data)
}

/// Sign all slices of a Mach-O binary (including FAT/Universal binaries).
///
/// Returns a `SignedSlice` for each architecture containing the complete
/// signed binary data ready for reassembly.
pub fn sign_macho_all_slices(
    macho: &MachOFile,
    identifier: &str,
    team_id: Option<&str>,
    entitlements: Option<&[u8]>,
    cert: &X509Ref,
    pkey: &PKeyRef<Private>,
    cert_chain: &[X509],
    info_plist: Option<&[u8]>,
    code_resources: Option<&[u8]>,
) -> Result<Vec<SignedSlice>> {
    let mut signed_slices = Vec::with_capacity(macho.slices().len());

    for (index, slice) in macho.slices().iter().enumerate() {
        let slice_data = macho.slice_data(slice);

        let mut signed = sign_slice_complete(
            slice_data,
            slice,
            identifier,
            team_id,
            entitlements,
            cert,
            pkey,
            cert_chain,
            info_plist,
            code_resources,
        )?;

        signed.slice_index = index;
        signed_slices.push(signed);
    }

    Ok(signed_slices)
}

/// Sign a single slice and return complete signed binary data.
fn sign_slice_complete(
    slice_data: &[u8],
    slice: &ArchSlice,
    identifier: &str,
    team_id: Option<&str>,
    entitlements: Option<&[u8]>,
    cert: &X509Ref,
    pkey: &PKeyRef<Private>,
    cert_chain: &[X509],
    info_plist: Option<&[u8]>,
    code_resources: Option<&[u8]>,
) -> Result<SignedSlice> {
    // Pre-compute hashes that don't depend on code (same for both passes)
    // Extract subject CN from certificate for requirements blob
    let subject_cn = extract_subject_cn(cert).unwrap_or_default();
    let requirements = build_requirements_blob_full(identifier, &subject_cn);
    let requirements_hash_sha1 = sha1_hash(&requirements);
    let requirements_hash_sha256 = sha256_hash(&requirements);

    let (entitlements_blob, ent_hash_sha1, ent_hash_sha256) = if let Some(ent) = entitlements {
        let blob = build_entitlements_blob(ent);
        (Some(blob.clone()), Some(sha1_hash(&blob)), Some(sha256_hash(&blob)))
    } else {
        (None, None, None)
    };

    // Build DER entitlements only for executables (slot -7)
    // Non-executables should not have DER entitlements (only 5 special slots)
    let (der_entitlements_blob, der_ent_hash_sha1, der_ent_hash_sha256) =
        if slice.is_executable {
            if let Some(ent) = entitlements {
                if let Some(der_data) = plist_to_der(ent) {
                    let blob = build_der_entitlements_blob(&der_data);
                    (Some(blob.clone()), Some(sha1_hash(&blob)), Some(sha256_hash(&blob)))
                } else {
                    (None, None, None)
                }
            } else {
                (None, None, None)
            }
        } else {
            (None, None, None)
        };

    let (info_hash_sha1, info_hash_sha256) = if let Some(info) = info_plist {
        (Some(sha1_hash(info)), Some(sha256_hash(info)))
    } else {
        (None, None)
    };

    let (res_hash_sha1, res_hash_sha256) = if let Some(res) = code_resources {
        (Some(sha1_hash(res)), Some(sha256_hash(res)))
    } else {
        (None, None)
    };

    // === PASS 1: Build preliminary signature to measure size ===
    let preliminary_code = &slice_data[..slice.code_length];
    let preliminary_sig = build_superblob(
        preliminary_code,
        slice,
        identifier,
        team_id,
        entitlements,
        &requirements,
        &requirements_hash_sha1,
        &requirements_hash_sha256,
        &entitlements_blob,
        &ent_hash_sha1,
        &ent_hash_sha256,
        &der_entitlements_blob,
        &der_ent_hash_sha1,
        &der_ent_hash_sha256,
        &info_hash_sha1,
        &info_hash_sha256,
        &res_hash_sha1,
        &res_hash_sha256,
        cert,
        pkey,
        cert_chain,
    )?;

    // === Check if reallocation is needed ===
    // If there's not enough space in the current binary, reallocate
    let (working_slice_data, working_slice, preserve_original_size) = if !has_enough_signature_space(slice_data, slice.code_length, preliminary_sig.len()) {
        // Reallocate the binary with more signature space
        let reallocated = realloc_code_sign_space_slice(slice_data, slice.code_length)?;

        // Create a new slice descriptor for the reallocated binary
        let new_slice = ArchSlice {
            offset: slice.offset,
            size: reallocated.len(),
            cpu_type: slice.cpu_type,
            is_64: slice.is_64,
            is_executable: slice.is_executable,
            code_sig_offset: Some(slice.code_length as u32),
            code_sig_size: Some((reallocated.len() - slice.code_length) as u32),
            text_segment_size: slice.text_segment_size,
            code_length: slice.code_length,
        };

        // When reallocating, use the new size (don't preserve old size)
        (reallocated, new_slice, false)
    } else {
        // Original binary has enough space - preserve its size
        (slice_data.to_vec(), slice.clone(), true)
    };

    // Determine the target binary size
    // When reallocated: use the reallocated size (formula-based padding)
    // When not reallocated: use original size (preserve existing space)
    // C++ zsign always pads to formula-based size when reallocating (archo.cpp:629)
    let target_binary_size = Some(working_slice_data.len());

    // === PASS 2: Prepare code with actual size and rebuild ===
    // When preserving original size, pass the original signature space size
    let sig_space_size = if preserve_original_size {
        // Use the original reserved space size if it's larger
        let original_sig_space = slice_data.len().saturating_sub(slice.code_length);
        original_sig_space.max(preliminary_sig.len())
    } else {
        preliminary_sig.len()
    };
    let (prepared_code, sig_offset, _) = prepare_code_for_signing_slice(&working_slice_data, sig_space_size)?;

    // Pad prepared_code to sig_offset so CodeDirectory hashes all bytes up to signature
    // This is critical: codeLimit must equal sig_offset, and we need hashes for all pages
    let mut code_for_hashing = prepared_code.clone();
    code_for_hashing.resize(sig_offset, 0);

    let final_sig = build_superblob(
        &code_for_hashing,
        &working_slice,
        identifier,
        team_id,
        entitlements,
        &requirements,
        &requirements_hash_sha1,
        &requirements_hash_sha256,
        &entitlements_blob,
        &ent_hash_sha1,
        &ent_hash_sha256,
        &der_entitlements_blob,
        &der_ent_hash_sha1,
        &der_ent_hash_sha256,
        &info_hash_sha1,
        &info_hash_sha256,
        &res_hash_sha1,
        &res_hash_sha256,
        cert,
        pkey,
        cert_chain,
    )?;

    // === Embed signature into prepared code ===
    let signed_data = embed_signature_into_prepared(&prepared_code, &final_sig, sig_offset, target_binary_size);

    Ok(SignedSlice {
        slice_index: 0,
        offset: slice.offset,
        original_size: slice.size,
        signed_data,
    })
}

/// Embed signature into already-prepared code bytes.
///
/// If `original_binary_size` is provided and is larger than the signed output,
/// the output will be padded with zeros to preserve the original size.
/// This is important for preserving reserved signature space in the binary.
fn embed_signature_into_prepared(
    prepared_code: &[u8],
    signature: &[u8],
    sig_offset: usize,
    original_binary_size: Option<usize>,
) -> Vec<u8> {
    let min_size = sig_offset + signature.len();
    let final_size = original_binary_size.map(|orig| orig.max(min_size)).unwrap_or(min_size);
    let mut output = Vec::with_capacity(final_size);

    // Copy prepared code (already has updated load commands)
    output.extend_from_slice(prepared_code);

    // Pad to signature offset if needed
    while output.len() < sig_offset {
        output.push(0);
    }

    // Append signature
    output.extend_from_slice(signature);

    // Preserve original binary size if it was larger (maintain reserved signature space)
    if output.len() < final_size {
        output.resize(final_size, 0);
    }

    output
}

/// Build a complete SuperBlob signature from code and hashes.
#[allow(clippy::too_many_arguments)]
fn build_superblob(
    code: &[u8],
    slice: &ArchSlice,
    identifier: &str,
    team_id: Option<&str>,
    entitlements: Option<&[u8]>,
    requirements: &[u8],
    requirements_hash_sha1: &[u8],
    requirements_hash_sha256: &[u8],
    entitlements_blob: &Option<Vec<u8>>,
    ent_hash_sha1: &Option<Vec<u8>>,
    ent_hash_sha256: &Option<Vec<u8>>,
    der_entitlements_blob: &Option<Vec<u8>>,
    der_ent_hash_sha1: &Option<Vec<u8>>,
    der_ent_hash_sha256: &Option<Vec<u8>>,
    info_hash_sha1: &Option<Vec<u8>>,
    info_hash_sha256: &Option<Vec<u8>>,
    res_hash_sha1: &Option<Vec<u8>>,
    res_hash_sha256: &Option<Vec<u8>>,
    cert: &X509Ref,
    pkey: &PKeyRef<Private>,
    cert_chain: &[X509],
) -> Result<Vec<u8>> {
    // Build CodeDirectory (SHA-1) and (SHA-256) in parallel
    let (cd_sha1, cd_sha256) = rayon::join(
        || build_code_directory(
            identifier, team_id, code, slice, entitlements,
            requirements_hash_sha1, info_hash_sha1, res_hash_sha1, ent_hash_sha1, der_ent_hash_sha1, true,
        ),
        || build_code_directory(
            identifier, team_id, code, slice, entitlements,
            requirements_hash_sha256, info_hash_sha256, res_hash_sha256, ent_hash_sha256, der_ent_hash_sha256, false,
        ),
    );

    // Generate CMS signature
    // Note: CMS signs the SHA-1 CodeDirectory (for compatibility), not SHA-256
    // The CDHashes in attributes reference both CDs
    let cdhash_sha1: [u8; 20] = compute_cdhash_sha1(&cd_sha1);
    let cdhash_sha256: [u8; 32] = compute_cdhash_sha256(&cd_sha256);
    let cms_data = cms::sign_with_apple_attrs(&cd_sha1, cert, pkey, cert_chain, &cdhash_sha1, &cdhash_sha256)?;
    let signature_blob = build_signature_blob(&cms_data);

    // Assemble SuperBlob
    let mut builder = SuperBlobBuilder::new()
        .code_directory_sha1(cd_sha1)
        .code_directory_sha256(cd_sha256)
        .requirements(requirements.to_vec())
        .cms_signature(signature_blob);

    if let Some(ent_blob) = entitlements_blob {
        builder = builder.entitlements(ent_blob.clone());
    }

    // Add DER entitlements only for executables (slot -7)
    if let Some(der_ent_blob) = der_entitlements_blob {
        builder = builder.der_entitlements(der_ent_blob.clone());
    }

    Ok(builder.build())
}

/// Build a CodeDirectory blob with the specified hash type.
fn build_code_directory(
    identifier: &str,
    team_id: Option<&str>,
    code: &[u8],
    slice: &ArchSlice,
    entitlements: Option<&[u8]>,
    requirements_hash: &[u8],
    info_hash: &Option<Vec<u8>>,
    resources_hash: &Option<Vec<u8>>,
    entitlements_hash: &Option<Vec<u8>>,
    der_entitlements_hash: &Option<Vec<u8>>,
    is_sha1: bool,
) -> Vec<u8> {
    // Compute exec_seg_flags based on binary type and entitlements
    // C++ zsign sets CS_EXECSEG_MAIN_BINARY for executable binaries
    // and adds CS_EXECSEG_ALLOW_UNSIGNED if get-task-allow entitlement is present
    let mut exec_seg_flags: u64 = 0;

    if slice.is_executable {
        exec_seg_flags = CS_EXECSEG_MAIN_BINARY;
    }

    // Check for get-task-allow entitlement (C++ reference: archo.cpp:387-390)
    // If entitlements contain <key>get-task-allow</key>, add both flags
    if let Some(ent_data) = entitlements {
        if let Ok(ent_str) = std::str::from_utf8(ent_data) {
            if ent_str.contains("<key>get-task-allow</key>") {
                exec_seg_flags |= CS_EXECSEG_MAIN_BINARY | CS_EXECSEG_ALLOW_UNSIGNED;
            }
        }
    }

    let mut builder = CodeDirectoryBuilder::new(identifier, code)
        .requirements_hash(requirements_hash.to_vec())
        .exec_seg_limit(slice.text_segment_size)
        .exec_seg_flags(exec_seg_flags);

    if let Some(team) = team_id {
        builder = builder.team_id(team);
    }
    if let Some(hash) = info_hash {
        builder = builder.info_hash(hash.clone());
    }
    if let Some(hash) = resources_hash {
        builder = builder.resources_hash(hash.clone());
    }
    if let Some(hash) = entitlements_hash {
        builder = builder.entitlements_hash(hash.clone());
    }
    // Add DER entitlements hash for slot -7 (executables only)
    if let Some(hash) = der_entitlements_hash {
        builder = builder.der_entitlements_hash(hash.clone());
    }

    if is_sha1 {
        builder.build_sha1()
    } else {
        builder.build_sha256()
    }
}

fn sha1_hash(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha1::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

fn sha256_hash(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Extract the Common Name (CN) from a certificate's subject.
///
/// Returns the CN value if found, or None if not present.
fn extract_subject_cn(cert: &X509Ref) -> Option<String> {
    cert.subject_name()
        .entries_by_nid(Nid::COMMONNAME)
        .next()
        .and_then(|entry| entry.data().as_utf8().ok())
        .map(|s| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha1_hash() {
        let data = b"hello world";
        let hash = sha1_hash(data);
        assert_eq!(hash.len(), 20);
    }

    #[test]
    fn test_sha256_hash() {
        let data = b"hello world";
        let hash = sha256_hash(data);
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_sha1_hash_deterministic() {
        let data = b"test data for hashing";
        let hash1 = sha1_hash(data);
        let hash2 = sha1_hash(data);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_sha256_hash_deterministic() {
        let data = b"test data for hashing";
        let hash1 = sha256_hash(data);
        let hash2 = sha256_hash(data);
        assert_eq!(hash1, hash2);
    }
}
