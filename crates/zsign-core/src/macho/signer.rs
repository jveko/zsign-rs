//! Mach-O code signing implementation.
//!
//! Builds complete code signatures for Mach-O binaries including:
//! - Code directories (SHA-1 and SHA-256)
//! - Requirements blobs
//! - Entitlements (XML and DER formats)
//! - CMS signatures with Apple-specific attributes
//!
//! Supports both single-architecture and FAT/Universal binaries.
//!
//! # Key Functions
//!
//! - [`sign_macho`] - Sign a single-architecture binary
//! - [`sign_macho_all_slices`] - Sign all slices of a FAT binary
//!
//! # Workflow
//!
//! 1. Parse binary with [`MachOFile`]
//! 2. Sign with [`sign_macho`] or [`sign_macho_all_slices`]
//! 3. For FAT binaries, reassemble with [`embed_signature_fat`](super::writer::embed_signature_fat)

use crate::codesign::code_directory::{
    compute_cdhash_sha1, compute_cdhash_sha256, hash_code_pages_dual, CodeDirectoryBuilder,
};
use crate::codesign::constants::{CS_EXECSEG_ALLOW_UNSIGNED, CS_EXECSEG_MAIN_BINARY, CS_SHA1_LEN, CS_SHA256_LEN, PAGE_SIZE};
use crate::codesign::der::plist_to_der;
use crate::codesign::superblob::{
    build_der_entitlements_blob, build_entitlements_blob, build_requirements_blob_full,
    build_signature_blob, SuperBlobBuilder,
};
use crate::crypto::cert::extract_subject_cn;
use crate::crypto::cms;
use crate::crypto::SigningCredentials;
use crate::Result;
use sha1::{Digest, Sha1};
use sha2::Sha256;

use super::parser::{ArchSlice, MachOFile};
use super::writer::SignedSlice;
use super::writer::{align_to, calculate_signature_space, checked_u32, has_enough_signature_space, prepare_code_in_place, realloc_code_sign_space_with_metadata};

/// Pre-computed signing inputs that are invariant across all slices of a binary.
///
/// Avoids recomputing requirements, entitlements, hashes, and subject CN
/// for each architecture slice in a FAT binary.
pub(crate) struct SigningContext {
    pub(crate) team_id: Option<String>,
    pub(crate) requirements: Vec<u8>,
    pub(crate) entitlements_blob: Option<Vec<u8>>,
    pub(crate) der_entitlements_blob: Option<Vec<u8>>,
    pub(crate) hashes: SpecialSlotHashes,
    pub(crate) has_get_task_allow: bool,
    pub(crate) cms_reserve: usize,
}

impl SigningContext {
    /// Build a SigningContext from signing parameters.
    ///
    /// Parses entitlements once, builds all blobs, and computes dual hashes
    /// of all special slots.
    pub(crate) fn new(
        identifier: &str,
        credentials: &SigningCredentials,
        entitlements: Option<&[u8]>,
        is_executable: bool,
        info_plist: Option<&[u8]>,
        code_resources: Option<&[u8]>,
    ) -> Result<Self> {
        let subject_cn = extract_subject_cn(&credentials.certificate).unwrap_or_default();
        let requirements = build_requirements_blob_full(identifier, &subject_cn);

        let entitlements_blob = entitlements.map(build_entitlements_blob);

        let der_entitlements_blob: Option<Vec<u8>> = if is_executable {
            entitlements.map(|ent| {
                let der_data = plist_to_der(ent)?;
                Ok::<_, crate::Error>(build_der_entitlements_blob(&der_data))
            }).transpose()?
        } else {
            None
        };

        let mut has_get_task_allow = false;
        if let Some(ent_data) = entitlements {
            if let Ok(plist_val) = plist::from_bytes::<plist::Value>(ent_data) {
                if let Some(dict) = plist_val.as_dictionary() {
                    if dict.get("get-task-allow").and_then(|v| v.as_boolean()) == Some(true) {
                        has_get_task_allow = true;
                    }
                }
            }
        }

        let hashes = SpecialSlotHashes {
            requirements: dual_hash(&requirements),
            entitlements: entitlements_blob.as_ref().map(|b| dual_hash(b)),
            der_entitlements: der_entitlements_blob.as_ref().map(|b| dual_hash(b)),
            info: info_plist.map(dual_hash),
            resources: code_resources.map(dual_hash),
        };

        let cms_reserve = cms::estimate_cms_size(credentials);

        Ok(Self {
            team_id: credentials.team_id.clone(),
            requirements,
            entitlements_blob,
            der_entitlements_blob,
            hashes,
            has_get_task_allow,
            cms_reserve,
        })
    }
}

/// Empty entitlements plist for non-executable binaries (dylibs, frameworks).
pub const EMPTY_ENTITLEMENTS: &[u8] = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict/>\n</plist>\n";

/// Signs any Mach-O binary (single-arch or FAT), returns signed bytes.
///
/// Automatically selects entitlements based on executable type:
/// - Executables use the provided entitlements
/// - Non-executables (dylibs, frameworks) use empty entitlements
pub fn sign_any_macho(
    macho: &MachOFile,
    identifier: &str,
    entitlements: Option<&[u8]>,
    credentials: &SigningCredentials,
    info_plist: Option<&[u8]>,
    code_resources: Option<&[u8]>,
) -> Result<Vec<u8>> {
    let is_executable = macho.slices().first().map(|s| s.is_executable).unwrap_or(false);
    let ent = if is_executable { entitlements } else { Some(EMPTY_ENTITLEMENTS) };

    if macho.slices().len() == 1 {
        sign_macho(macho, identifier, ent, credentials, info_plist, code_resources)
    } else {
        let signed_slices = sign_macho_all_slices(
            macho, identifier, ent, credentials, info_plist, code_resources,
        )?;
        super::writer::embed_signature_fat(macho.data(), &signed_slices)
    }
}

/// Signs a single-architecture Mach-O binary.
///
/// Builds a complete code signature and embeds it into the binary.
/// For FAT binaries, use [`sign_macho_all_slices`] instead.
///
/// # Arguments
///
/// * `macho` - Parsed Mach-O file (uses first slice)
/// * `identifier` - Bundle identifier (e.g., `com.example.app`)
/// * `entitlements` - Optional entitlements plist (XML format)
/// * `credentials` - Signing certificate and key from [`SigningCredentials`]
/// * `info_plist` - Optional Info.plist data for hashing
/// * `code_resources` - Optional CodeResources data for hashing
///
/// # Returns
///
/// The complete signed binary as a byte vector.
///
/// # Errors
///
/// Returns an error if signing fails due to invalid credentials or binary format.
///
/// # Examples
///
/// ```ignore
/// use zsign_core::macho::{MachOFile, sign_macho};
/// use zsign_core::crypto::SigningCredentials;
///
/// let macho = MachOFile::open("path/to/binary")?;
/// let credentials = SigningCredentials::from_p12("cert.p12", "password")?;
///
/// let signed = sign_macho(
///     &macho,
///     "com.example.app",
///     None,  // entitlements
///     &credentials,
///     None,  // info_plist
///     None,  // code_resources
/// )?;
/// # Ok::<(), zsign_core::Error>(())
/// ```
pub fn sign_macho(
    macho: &MachOFile,
    identifier: &str,
    entitlements: Option<&[u8]>,
    credentials: &SigningCredentials,
    info_plist: Option<&[u8]>,
    code_resources: Option<&[u8]>,
) -> Result<Vec<u8>> {
    if macho.slices().len() != 1 {
        return Err(crate::Error::MachO(
            "sign_macho only supports single-arch Mach-O; use sign_macho_all_slices for FAT binaries".into()
        ));
    }
    let slice = &macho.slices()[0];
    let slice_data = macho.slice_data(slice);

    let ctx = SigningContext::new(
        identifier, credentials, entitlements, slice.is_executable, info_plist, code_resources,
    )?;

    let signed = sign_slice_complete(
        slice_data, slice, identifier, &ctx, credentials,
    )?;

    Ok(signed.signed_data)
}

/// Signs all architecture slices of a Mach-O binary.
///
/// Returns a [`SignedSlice`] for each architecture, suitable for reassembly
/// into a FAT binary using [`embed_signature_fat`](super::writer::embed_signature_fat).
///
/// For single-architecture binaries, prefer [`sign_macho`] which returns the
/// signed binary directly.
///
/// # Errors
///
/// Returns an error if signing fails for any slice.
pub fn sign_macho_all_slices(
    macho: &MachOFile,
    identifier: &str,
    entitlements: Option<&[u8]>,
    credentials: &SigningCredentials,
    info_plist: Option<&[u8]>,
    code_resources: Option<&[u8]>,
) -> Result<Vec<SignedSlice>> {
    let is_executable = macho.slices().first().map(|s| s.is_executable).unwrap_or(false);
    let ctx = SigningContext::new(
        identifier, credentials, entitlements, is_executable, info_plist, code_resources,
    )?;

    use rayon::prelude::*;

    let signed_slices: Vec<SignedSlice> = macho.slices()
        .par_iter()
        .enumerate()
        .map(|(index, slice)| -> Result<SignedSlice> {
            let slice_data = macho.slice_data(slice);

            let mut signed = sign_slice_complete(
                slice_data, slice, identifier, &ctx, credentials,
            )?;

            signed.slice_index = index;
            Ok(signed)
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(signed_slices)
}

fn sign_slice_complete(
    slice_data: &[u8],
    slice: &ArchSlice,
    identifier: &str,
    ctx: &SigningContext,
    credentials: &SigningCredentials,
) -> Result<SignedSlice> {
    // Step 1: Estimate superblob size instead of building a preliminary one
    let estimated_sig_size = compute_superblob_reserved_size(slice.code_length, identifier, ctx);

    // Step 2: Check if we need to reallocate space
    let (mut buf, working_metadata, working_slice, preserve_original_size) = if !has_enough_signature_space(slice_data, slice.code_length, estimated_sig_size) {
        let (reallocated, updated_metadata) = realloc_code_sign_space_with_metadata(slice_data, &slice.metadata, slice.code_length)?;

        let new_slice = ArchSlice {
            offset: slice.offset,
            size: reallocated.len(),
            cpu_type: slice.cpu_type,
            is_64: slice.is_64,
            is_executable: slice.is_executable,
            code_sig_offset: Some(checked_u32(slice.code_length, "code_length")?),
                code_sig_size: Some(checked_u32(reallocated.len() - slice.code_length, "sig_size")?),
                text_segment_size: slice.text_segment_size,
                code_length: slice.code_length,
                metadata: updated_metadata.clone(),
            };

        (reallocated, updated_metadata, new_slice, false)
    } else {
        (slice_data.to_vec(), slice.metadata.clone(), slice.clone(), true)
    };

    let target_binary_size = Some(buf.len());

    // Step 3: Prepare code for signing in-place (update load commands, truncate to code_length)
    let sig_space_size = if preserve_original_size {
        let original_sig_space = slice_data.len().saturating_sub(slice.code_length);
        original_sig_space.max(estimated_sig_size)
    } else {
        estimated_sig_size
    };
    let (sig_offset, _) = prepare_code_in_place(&mut buf, &working_metadata, working_slice.code_length, sig_space_size)?;

    // Step 4: Hash code pages ONCE with both SHA-1 and SHA-256
    // buf now contains exactly the code bytes (code_length) with updated load commands
    let dual_hashes = hash_code_pages_dual(&buf);

    // Step 5: Build both code directories from pre-computed hashes
    let cd_sha1 = build_code_directory_from_hashes(
        identifier, &buf, &working_slice, ctx, &dual_hashes.sha1, true,
    );
    let cd_sha256 = build_code_directory_from_hashes(
        identifier, &buf, &working_slice, ctx, &dual_hashes.sha256, false,
    );

    // Step 6: CMS sign ONCE
    let cdhash_sha1: [u8; 20] = compute_cdhash_sha1(&cd_sha1);
    let cdhash_sha256: [u8; 32] = compute_cdhash_sha256(&cd_sha256);

    let cms_data = cms::sign_code_directory(
        &cd_sha1,
        credentials,
        &cdhash_sha1,
        &cdhash_sha256,
    )?;
    let signature_blob = build_signature_blob(&cms_data);

    // Step 7: Assemble superblob ONCE
    let mut builder = SuperBlobBuilder::new()
        .code_directory_sha1(cd_sha1)
        .code_directory_sha256(cd_sha256)
        .requirements(ctx.requirements.clone())
        .cms_signature(signature_blob);

    if let Some(ref ent_blob) = ctx.entitlements_blob {
        builder = builder.entitlements(ent_blob.clone());
    }

    if let Some(ref der_ent_blob) = ctx.der_entitlements_blob {
        builder = builder.der_entitlements(der_ent_blob.clone());
    }

    let final_sig = builder.build();

    if final_sig.len() > sig_space_size {
        // Retry with larger reserve based on actual signature size
        let padded_sig_size = align_to(final_sig.len() + 256, PAGE_SIZE);

        // Re-prepare from the original slice data
        let (mut buf2, working_metadata2, working_slice2) = if !has_enough_signature_space(slice_data, slice.code_length, padded_sig_size) {
            let (reallocated, updated_metadata) = realloc_code_sign_space_with_metadata(slice_data, &slice.metadata, slice.code_length)?;
            let new_slice = ArchSlice {
                offset: slice.offset,
                size: reallocated.len(),
                cpu_type: slice.cpu_type,
                is_64: slice.is_64,
                is_executable: slice.is_executable,
                code_sig_offset: Some(checked_u32(slice.code_length, "code_length")?),
                code_sig_size: Some(checked_u32(reallocated.len() - slice.code_length, "sig_size")?),
                text_segment_size: slice.text_segment_size,
                code_length: slice.code_length,
                metadata: updated_metadata.clone(),
            };
            (reallocated, updated_metadata, new_slice)
        } else {
            (slice_data.to_vec(), slice.metadata.clone(), slice.clone())
        };

        let target2 = Some(buf2.len());
        let (sig_offset2, _) = prepare_code_in_place(&mut buf2, &working_metadata2, working_slice2.code_length, padded_sig_size)?;

        // Re-hash and re-sign with new offsets
        let dual2 = hash_code_pages_dual(&buf2);
        let cd_sha1_2 = build_code_directory_from_hashes(identifier, &buf2, &working_slice2, ctx, &dual2.sha1, true);
        let cd_sha256_2 = build_code_directory_from_hashes(identifier, &buf2, &working_slice2, ctx, &dual2.sha256, false);

        let cdhash_sha1_2: [u8; 20] = compute_cdhash_sha1(&cd_sha1_2);
        let cdhash_sha256_2: [u8; 32] = compute_cdhash_sha256(&cd_sha256_2);

        let cms_data2 = cms::sign_code_directory(&cd_sha1_2, credentials, &cdhash_sha1_2, &cdhash_sha256_2)?;
        let sig_blob2 = build_signature_blob(&cms_data2);

        let mut builder2 = SuperBlobBuilder::new()
            .code_directory_sha1(cd_sha1_2)
            .code_directory_sha256(cd_sha256_2)
            .requirements(ctx.requirements.clone())
            .cms_signature(sig_blob2);
        if let Some(ref ent_blob) = ctx.entitlements_blob {
            builder2 = builder2.entitlements(ent_blob.clone());
        }
        if let Some(ref der_ent_blob) = ctx.der_entitlements_blob {
            builder2 = builder2.der_entitlements(der_ent_blob.clone());
        }

        let final_sig2 = builder2.build();
        if final_sig2.len() > padded_sig_size {
            return Err(crate::Error::MachO(format!(
                "signature exceeded reserved size after retry: reserved={}, actual={}",
                padded_sig_size, final_sig2.len()
            )));
        }

        embed_signature_in_place(&mut buf2, &final_sig2, sig_offset2, target2);
        return Ok(SignedSlice {
            slice_index: 0,
            offset: slice.offset,
            original_size: slice.size,
            signed_data: buf2,
        });
    }

    // Step 8: Embed signature in-place
    embed_signature_in_place(&mut buf, &final_sig, sig_offset, target_binary_size);

    Ok(SignedSlice {
        slice_index: 0,
        offset: slice.offset,
        original_size: slice.size,
        signed_data: buf,
    })
}

pub(crate) struct SpecialSlotHashes {
    pub(crate) requirements: DualHash,
    pub(crate) entitlements: Option<DualHash>,
    pub(crate) der_entitlements: Option<DualHash>,
    pub(crate) info: Option<DualHash>,
    pub(crate) resources: Option<DualHash>,
}

#[allow(dead_code)]
fn embed_signature_into_prepared(
    prepared_code: &[u8],
    signature: &[u8],
    sig_offset: usize,
    original_binary_size: Option<usize>,
) -> Vec<u8> {
    let min_size = sig_offset + signature.len();
    let final_size = original_binary_size.map(|orig| orig.max(min_size)).unwrap_or(min_size);
    let mut output = Vec::with_capacity(final_size);

    output.extend_from_slice(prepared_code);

    while output.len() < sig_offset {
        output.push(0);
    }

    output.extend_from_slice(signature);

    if output.len() < final_size {
        output.resize(final_size, 0);
    }

    output
}

fn embed_signature_in_place(
    buf: &mut Vec<u8>,
    signature: &[u8],
    sig_offset: usize,
    target_size: Option<usize>,
) {
    if buf.len() < sig_offset {
        buf.resize(sig_offset, 0);
    }

    let needed = sig_offset + signature.len();
    if buf.len() < needed {
        buf.resize(needed, 0);
    }
    buf[sig_offset..sig_offset + signature.len()].copy_from_slice(signature);

    if let Some(target) = target_size {
        if buf.len() < target {
            buf.resize(target, 0);
        }
    }
}

fn compute_superblob_reserved_size(
    code_length: usize,
    identifier: &str,
    ctx: &SigningContext,
) -> usize {
    let writer_reserved = calculate_signature_space(code_length) - code_length;

    let pages = code_length.div_ceil(PAGE_SIZE);
    let id_len = identifier.len() + 1;
    let team_len = ctx.team_id.as_ref().map(|t| t.len() + 1).unwrap_or(0);
    let special_slots = 7;

    let cd_sha1 = 88 + id_len + team_len + special_slots * CS_SHA1_LEN + pages * CS_SHA1_LEN;
    let cd_sha256 = 88 + id_len + team_len + special_slots * CS_SHA256_LEN + pages * CS_SHA256_LEN;
    let req_size = ctx.requirements.len();
    let ent_size = ctx.entitlements_blob.as_ref().map(|b| b.len()).unwrap_or(0);
    let der_ent_size = ctx.der_entitlements_blob.as_ref().map(|b| b.len()).unwrap_or(0);
    let cms_reserve = ctx.cms_reserve;
    let header = 12 + 7 * 8;

    let tight = header + cd_sha1 + cd_sha256 + req_size + ent_size + der_ent_size + cms_reserve;

    writer_reserved.max(tight)
}

fn build_code_directory_from_hashes(
    identifier: &str,
    code: &[u8],
    slice: &ArchSlice,
    ctx: &SigningContext,
    page_hashes: &[u8],
    is_sha1: bool,
) -> Vec<u8> {
    let mut exec_seg_flags: u64 = 0;

    if slice.is_executable {
        exec_seg_flags = CS_EXECSEG_MAIN_BINARY;
        if ctx.has_get_task_allow {
            exec_seg_flags |= CS_EXECSEG_ALLOW_UNSIGNED;
        }
    }

    let hashes = &ctx.hashes;
    let requirements_hash: &[u8] = if is_sha1 { &hashes.requirements.sha1 } else { &hashes.requirements.sha256 };
    let info_hash: Option<&[u8]> = if is_sha1 { hashes.info.as_ref().map(|h| h.sha1.as_slice()) } else { hashes.info.as_ref().map(|h| h.sha256.as_slice()) };
    let resources_hash: Option<&[u8]> = if is_sha1 { hashes.resources.as_ref().map(|h| h.sha1.as_slice()) } else { hashes.resources.as_ref().map(|h| h.sha256.as_slice()) };
    let entitlements_hash: Option<&[u8]> = if is_sha1 { hashes.entitlements.as_ref().map(|h| h.sha1.as_slice()) } else { hashes.entitlements.as_ref().map(|h| h.sha256.as_slice()) };
    let der_entitlements_hash: Option<&[u8]> = if is_sha1 { hashes.der_entitlements.as_ref().map(|h| h.sha1.as_slice()) } else { hashes.der_entitlements.as_ref().map(|h| h.sha256.as_slice()) };

    let mut builder = CodeDirectoryBuilder::new(identifier, code)
        .requirements_hash(requirements_hash.to_vec())
        .exec_seg_limit(slice.text_segment_size)
        .exec_seg_flags(exec_seg_flags);

    if let Some(ref team) = ctx.team_id {
        builder = builder.team_id(team.as_str());
    }
    if let Some(hash) = info_hash {
        builder = builder.info_hash(hash.to_vec());
    }
    if let Some(hash) = resources_hash {
        builder = builder.resources_hash(hash.to_vec());
    }
    if let Some(hash) = entitlements_hash {
        builder = builder.entitlements_hash(hash.to_vec());
    }
    if let Some(hash) = der_entitlements_hash {
        builder = builder.der_entitlements_hash(hash.to_vec());
    }

    if is_sha1 {
        builder.build_sha1_from_hashes(page_hashes)
    } else {
        builder.build_sha256_from_hashes(page_hashes)
    }
}

pub(crate) struct DualHash {
    pub(crate) sha1: [u8; 20],
    pub(crate) sha256: [u8; 32],
}

pub(crate) fn dual_hash(data: &[u8]) -> DualHash {
    DualHash {
        sha1: sha1_hash(data),
        sha256: sha256_hash(data),
    }
}

fn sha1_hash(data: &[u8]) -> [u8; 20] {
    let mut hasher = Sha1::new();
    hasher.update(data);
    hasher.finalize().into()
}

fn sha256_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
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
