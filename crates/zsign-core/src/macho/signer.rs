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
use crate::codesign::constants::{
    CS_ADHOC, CS_EXECSEG_ALLOW_UNSIGNED, CS_EXECSEG_MAIN_BINARY, CS_SHA1_LEN, CS_SHA256_LEN,
    PAGE_SIZE,
};
use crate::codesign::der::plist_to_der;
use crate::codesign::superblob::{
    build_adhoc_signature_blob, build_der_entitlements_blob, build_entitlements_blob,
    build_requirements_blob, build_signature_blob, SuperBlobBuilder,
};
use crate::crypto::cms;
use crate::crypto::SigningCredentials;
use crate::Result;
use sha1::{Digest, Sha1};
use sha2::Sha256;

use super::parser::{ArchSlice, MachOFile};
use super::writer::SignedSlice;
use super::writer::{
    align_to, calculate_signature_space, checked_u32, has_enough_signature_space,
    prepare_code_in_place, realloc_code_sign_space_with_metadata,
};

/// Pre-computed signing inputs that are invariant across all slices of a binary.
///
/// Avoids recomputing requirements, entitlements, hashes, and subject CN
/// for each architecture slice in a FAT binary.
pub(crate) struct SigningContext {
    pub(crate) adhoc: bool,
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
        _identifier: &str,
        credentials: Option<&SigningCredentials>,
        entitlements: Option<&[u8]>,
        is_executable: bool,
        info_plist: Option<&[u8]>,
        code_resources: Option<&[u8]>,
    ) -> Result<Self> {
        let adhoc = credentials.is_none();
        // Apple's baseline is an empty requirements blob: codesign and the
        // device synthesize the designated requirement from the embedded
        // certificate chain at verification time. Writing an explicit DR
        // (especially one pinned to `anchor apple generic`) fails
        // verification for certificates that do not chain to Apple.
        let requirements = build_requirements_blob();

        let entitlements_blob = entitlements.map(build_entitlements_blob);

        let der_entitlements_blob: Option<Vec<u8>> = if is_executable {
            entitlements
                .map(|ent| {
                    let der_data = plist_to_der(ent)?;
                    Ok::<_, crate::Error>(build_der_entitlements_blob(&der_data))
                })
                .transpose()?
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

        let cms_reserve = credentials.map(cms::estimate_cms_size).unwrap_or(0);

        Ok(Self {
            adhoc,
            team_id: credentials.and_then(|c| c.team_id.clone()),
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
    let is_executable = macho
        .slices()
        .first()
        .map(|s| s.is_executable)
        .unwrap_or(false);
    let ent = if is_executable {
        entitlements
    } else {
        Some(EMPTY_ENTITLEMENTS)
    };

    if macho.slices().len() == 1 {
        sign_macho(
            macho,
            identifier,
            ent,
            credentials,
            info_plist,
            code_resources,
        )
    } else {
        let signed_slices = sign_macho_all_slices(
            macho,
            identifier,
            ent,
            credentials,
            info_plist,
            code_resources,
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
        identifier,
        Some(credentials),
        entitlements,
        slice.is_executable,
        info_plist,
        code_resources,
    )?;

    let signed = sign_slice_complete(
        slice_data,
        slice,
        identifier,
        &ctx,
        Some(credentials),
        false,
    )?;

    Ok(signed.signed_data)
}

/// Signs a single-architecture Mach-O with no identity (ad-hoc).
///
/// The superblob carries an empty CMS wrapper and the code directories are
/// flagged `CS_ADHOC`. No certificate or private key is required.
pub fn sign_macho_adhoc(
    macho: &MachOFile,
    identifier: &str,
    entitlements: Option<&[u8]>,
    info_plist: Option<&[u8]>,
    code_resources: Option<&[u8]>,
) -> Result<Vec<u8>> {
    if macho.slices().len() != 1 {
        return Err(crate::Error::MachO(
            "sign_macho_adhoc only supports single-arch Mach-O".into(),
        ));
    }
    let slice = &macho.slices()[0];
    let slice_data = macho.slice_data(slice);
    let ctx = SigningContext::new(
        identifier,
        None,
        entitlements,
        slice.is_executable,
        info_plist,
        code_resources,
    )?;
    let signed = sign_slice_complete(slice_data, slice, identifier, &ctx, None, false)?;
    Ok(signed.signed_data)
}

/// Signs a single-architecture Mach-O emitting only the SHA-256 code
/// directory (no SHA-1 code directory slot).
pub fn sign_macho_sha256_only(
    macho: &MachOFile,
    identifier: &str,
    entitlements: Option<&[u8]>,
    credentials: &SigningCredentials,
    info_plist: Option<&[u8]>,
    code_resources: Option<&[u8]>,
) -> Result<Vec<u8>> {
    if macho.slices().len() != 1 {
        return Err(crate::Error::MachO(
            "sign_macho_sha256_only only supports single-arch Mach-O".into(),
        ));
    }
    let slice = &macho.slices()[0];
    let slice_data = macho.slice_data(slice);
    let ctx = SigningContext::new(
        identifier,
        Some(credentials),
        entitlements,
        slice.is_executable,
        info_plist,
        code_resources,
    )?;
    let signed = sign_slice_complete(slice_data, slice, identifier, &ctx, Some(credentials), true)?;
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
    let is_executable = macho
        .slices()
        .first()
        .map(|s| s.is_executable)
        .unwrap_or(false);
    let ctx = SigningContext::new(
        identifier,
        Some(credentials),
        entitlements,
        is_executable,
        info_plist,
        code_resources,
    )?;

    use rayon::prelude::*;

    let signed_slices: Vec<SignedSlice> = macho
        .slices()
        .par_iter()
        .enumerate()
        .map(|(index, slice)| -> Result<SignedSlice> {
            let slice_data = macho.slice_data(slice);

            let mut signed = sign_slice_complete(
                slice_data,
                slice,
                identifier,
                &ctx,
                Some(credentials),
                false,
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
    credentials: Option<&SigningCredentials>,
    sha256_only: bool,
) -> Result<SignedSlice> {
    // Step 1: Estimate superblob size instead of building a preliminary one
    let estimated_sig_size = compute_superblob_reserved_size(slice.code_length, identifier, ctx);

    // Step 2: Check if we need to reallocate space
    let (mut buf, working_metadata, working_slice, preserve_original_size) =
        if !has_enough_signature_space(slice_data, slice.code_length, estimated_sig_size) {
            let (reallocated, updated_metadata) = realloc_code_sign_space_with_metadata(
                slice_data,
                &slice.metadata,
                slice.code_length,
            )?;

            let new_slice = ArchSlice {
                offset: slice.offset,
                size: reallocated.len(),
                cpu_type: slice.cpu_type,
                is_64: slice.is_64,
                is_executable: slice.is_executable,
                code_sig_offset: Some(checked_u32(slice.code_length, "code_length")?),
                code_sig_size: Some(checked_u32(
                    reallocated.len() - slice.code_length,
                    "sig_size",
                )?),
                text_segment_size: slice.text_segment_size,
                text_segment_base: slice.text_segment_base,
                code_length: slice.code_length,
                metadata: updated_metadata.clone(),
            };

            (reallocated, updated_metadata, new_slice, false)
        } else {
            (
                slice_data.to_vec(),
                slice.metadata.clone(),
                slice.clone(),
                true,
            )
        };

    let target_binary_size = Some(buf.len());

    // Step 3: Prepare code for signing in-place (update load commands, truncate to code_length)
    let sig_space_size = if preserve_original_size {
        let original_sig_space = slice_data.len().saturating_sub(slice.code_length);
        original_sig_space.max(estimated_sig_size)
    } else {
        estimated_sig_size
    };
    let (sig_offset, _) = prepare_code_in_place(
        &mut buf,
        &working_metadata,
        working_slice.code_length,
        sig_space_size,
    )?;

    // Step 4: Hash code pages ONCE with both SHA-1 and SHA-256
    // buf now contains exactly the code bytes (code_length) with updated load commands
    let dual_hashes = hash_code_pages_dual(&buf);

    // Step 5: Build code directories from pre-computed hashes
    let cd_sha1 = if sha256_only {
        Vec::new()
    } else {
        build_code_directory_from_hashes(
            identifier,
            &buf,
            &working_slice,
            ctx,
            &dual_hashes.sha1,
            true,
        )
    };
    let cd_sha256 = build_code_directory_from_hashes(
        identifier,
        &buf,
        &working_slice,
        ctx,
        &dual_hashes.sha256,
        false,
    );

    // Step 6: CMS sign ONCE (in sha256-only mode the SHA-1 cdhash is
    // unused because no SHA-1 code directory slot is emitted)
    let cdhash_sha1: [u8; 20] = if cd_sha1.is_empty() {
        [0; 20]
    } else {
        compute_cdhash_sha1(&cd_sha1)
    };
    let cdhash_sha256: [u8; 32] = compute_cdhash_sha256(&cd_sha256);

    let signature_blob = match credentials {
        Some(creds) => {
            // The CMS must sign the CodeDirectory that is actually emitted as
            // primary. In sha256-only mode cd_sha1 is empty — signing it would
            // bind the signature to zero bytes and macOS verify would fail
            // with "invalid signature (code or signature have been modified)".
            let signed_cd = if sha256_only { &cd_sha256 } else { &cd_sha1 };
            let cms_data = cms::sign_code_directory(
                signed_cd,
                creds,
                if sha256_only {
                    None
                } else {
                    Some(&cdhash_sha1)
                },
                &cdhash_sha256,
            )?;
            build_signature_blob(&cms_data)
        }
        None => build_adhoc_signature_blob(),
    };

    // Step 7: Assemble superblob ONCE
    let mut builder = SuperBlobBuilder::new()
        .code_directory_sha256(cd_sha256)
        .requirements(ctx.requirements.clone())
        .cms_signature(signature_blob);
    if !sha256_only {
        builder = builder.code_directory_sha1(cd_sha1);
    }

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
        let (mut buf2, working_metadata2, working_slice2) =
            if !has_enough_signature_space(slice_data, slice.code_length, padded_sig_size) {
                let (reallocated, updated_metadata) = realloc_code_sign_space_with_metadata(
                    slice_data,
                    &slice.metadata,
                    slice.code_length,
                )?;
                let new_slice = ArchSlice {
                    offset: slice.offset,
                    size: reallocated.len(),
                    cpu_type: slice.cpu_type,
                    is_64: slice.is_64,
                    is_executable: slice.is_executable,
                    code_sig_offset: Some(checked_u32(slice.code_length, "code_length")?),
                    code_sig_size: Some(checked_u32(
                        reallocated.len() - slice.code_length,
                        "sig_size",
                    )?),
                    text_segment_size: slice.text_segment_size,
                    text_segment_base: slice.text_segment_base,
                    code_length: slice.code_length,
                    metadata: updated_metadata.clone(),
                };
                (reallocated, updated_metadata, new_slice)
            } else {
                (slice_data.to_vec(), slice.metadata.clone(), slice.clone())
            };

        let target2 = Some(buf2.len());
        let (sig_offset2, _) = prepare_code_in_place(
            &mut buf2,
            &working_metadata2,
            working_slice2.code_length,
            padded_sig_size,
        )?;

        // Re-hash and re-sign with new offsets
        let dual2 = hash_code_pages_dual(&buf2);
        let cd_sha1_2 = if sha256_only {
            Vec::new()
        } else {
            build_code_directory_from_hashes(
                identifier,
                &buf2,
                &working_slice2,
                ctx,
                &dual2.sha1,
                true,
            )
        };
        let cd_sha256_2 = build_code_directory_from_hashes(
            identifier,
            &buf2,
            &working_slice2,
            ctx,
            &dual2.sha256,
            false,
        );

        let cdhash_sha1_2: [u8; 20] = if cd_sha1_2.is_empty() {
            [0; 20]
        } else {
            compute_cdhash_sha1(&cd_sha1_2)
        };
        let cdhash_sha256_2: [u8; 32] = compute_cdhash_sha256(&cd_sha256_2);

        let sig_blob2 = match credentials {
            Some(creds) => {
                let signed_cd2 = if sha256_only {
                    &cd_sha256_2
                } else {
                    &cd_sha1_2
                };
                let cms_data2 = cms::sign_code_directory(
                    signed_cd2,
                    creds,
                    if sha256_only {
                        None
                    } else {
                        Some(&cdhash_sha1_2)
                    },
                    &cdhash_sha256_2,
                )?;
                build_signature_blob(&cms_data2)
            }
            None => build_adhoc_signature_blob(),
        };

        let mut builder2 = SuperBlobBuilder::new()
            .code_directory_sha256(cd_sha256_2)
            .requirements(ctx.requirements.clone())
            .cms_signature(sig_blob2);
        if !sha256_only {
            builder2 = builder2.code_directory_sha1(cd_sha1_2);
        }
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
                padded_sig_size,
                final_sig2.len()
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
    let final_size = original_binary_size
        .map(|orig| orig.max(min_size))
        .unwrap_or(min_size);
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
    let der_ent_size = ctx
        .der_entitlements_blob
        .as_ref()
        .map(|b| b.len())
        .unwrap_or(0);
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
    let requirements_hash: &[u8] = if is_sha1 {
        &hashes.requirements.sha1
    } else {
        &hashes.requirements.sha256
    };
    let info_hash: Option<&[u8]> = if is_sha1 {
        hashes.info.as_ref().map(|h| h.sha1.as_slice())
    } else {
        hashes.info.as_ref().map(|h| h.sha256.as_slice())
    };
    let resources_hash: Option<&[u8]> = if is_sha1 {
        hashes.resources.as_ref().map(|h| h.sha1.as_slice())
    } else {
        hashes.resources.as_ref().map(|h| h.sha256.as_slice())
    };
    let entitlements_hash: Option<&[u8]> = if is_sha1 {
        hashes.entitlements.as_ref().map(|h| h.sha1.as_slice())
    } else {
        hashes.entitlements.as_ref().map(|h| h.sha256.as_slice())
    };
    let der_entitlements_hash: Option<&[u8]> = if is_sha1 {
        hashes.der_entitlements.as_ref().map(|h| h.sha1.as_slice())
    } else {
        hashes
            .der_entitlements
            .as_ref()
            .map(|h| h.sha256.as_slice())
    };

    let mut builder = CodeDirectoryBuilder::new(identifier, code)
        .requirements_hash(requirements_hash.to_vec())
        .flags(if ctx.adhoc { CS_ADHOC } else { 0 })
        .exec_seg_base(slice.text_segment_base)
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

    /// A minimal, valid thin arm64 `MH_EXECUTE` Mach-O: header, a `__TEXT`
    /// segment with a 4-byte `__text` section, a `__LINKEDIT` segment for the
    /// signature, and a build version command. No `LC_CODE_SIGNATURE` — an
    /// unsigned input for signing tests.
    fn make_minimal_macho() -> Vec<u8> {
        let mut b = Vec::new();
        macro_rules! u32 {
            ($v:expr) => {
                b.extend_from_slice(&($v as u32).to_le_bytes())
            };
        }
        macro_rules! u64 {
            ($v:expr) => {
                b.extend_from_slice(&($v as u64).to_le_bytes())
            };
        }
        macro_rules! name {
            ($s:expr, $len:expr) => {
                let mut n = [0u8; 16];
                n[..$s.len()].copy_from_slice($s.as_bytes());
                b.extend_from_slice(&n[..$len]);
            };
        }

        // mach_header_64
        u32!(0xfeedfacf); // MH_MAGIC_64
        u32!(0x0100_000c); // CPU_TYPE_ARM64
        u32!(0x0000_0000); // CPU_SUBTYPE_ARM64_ALL
        u32!(2); // MH_EXECUTE
        u32!(3); // ncmds
        u32!(152 + 72 + 24); // sizeofcmds
        u32!(0x1); // MH_NOUNDEFS
        u32!(0); // reserved

        // LC_SEGMENT_64 "__TEXT" (152 bytes, one section)
        u32!(0x19);
        u32!(152);
        name!("__TEXT", 16);
        u64!(0x1_0000_0000); // vmaddr
        u64!(0x1000); // vmsize
        u64!(0x1000); // fileoff: leaves room for load commands
        u64!(0x1000); // filesize
        u32!(7); // maxprot
        u32!(7); // initprot
        u32!(1); // nsects
        u32!(0); // flags
        name!("__text", 16);
        name!("__TEXT", 16);
        u64!(0x1_0000_0000); // addr
        u64!(4); // size
        u32!(0x1000); // absolute file offset of the code
        u32!(0); // align
        u32!(0); // reloff
        u32!(0); // nreloc
        u32!(0); // flags
        u32!(0); // reserved1
        u32!(0); // reserved2
        u32!(0); // reserved3

        // LC_SEGMENT_64 "__LINKEDIT" (72 bytes, no sections) — the signature
        // is appended after this segment.
        u32!(0x19);
        u32!(72);
        name!("__LINKEDIT", 16);
        u64!(0x1_0000_1000); // vmaddr
        u64!(0x1000); // vmsize
        u64!(0x2000); // fileoff
        u64!(0); // filesize
        u32!(1); // maxprot (read-only)
        u32!(1); // initprot
        u32!(0); // nsects
        u32!(0); // flags

        // LC_BUILD_VERSION (24 bytes)
        u32!(0x32);
        u32!(24);
        u32!(1); // macOS
        u32!(0x000f_0000); // minos 15.0
        u32!(0x000f_0000); // sdk 15.0
        u32!(0); // ntools

        // Zero-fill the first page (load-command area, alignment), place the
        // 4-byte __text code at 0x1000, then pad through the __LINKEDIT page.
        b.resize(0x1000, 0);
        b.extend_from_slice(&[0x1f, 0x20, 0x03, 0xd5]);
        b.resize(0x2000, 0);
        b
    }

    /// Self-signed RSA-2048 credentials with `team_id=Some("TESTTEAM")`.
    fn test_credentials() -> crate::crypto::SigningCredentials {
        use crate::crypto::cert::{SigningCredentials, SigningKeyType};
        use der::Decode;
        use rsa::RsaPrivateKey;
        use sha2::Sha256;
        use spki::{EncodePublicKey, SubjectPublicKeyInfoOwned};
        use std::str::FromStr;
        use std::time::Duration;
        use x509_cert::builder::{Builder, CertificateBuilder, Profile};
        use x509_cert::name::Name;
        use x509_cert::serial_number::SerialNumber;
        use x509_cert::time::Validity;

        let mut rng = rand::thread_rng();
        let rsa_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let signing_key = rsa::pkcs1v15::SigningKey::<Sha256>::new(rsa_key.clone());

        let subject = Name::from_str("CN=zsign roundtrip,OU=TESTTEAM").unwrap();
        let serial = SerialNumber::from(7u32);
        let validity = Validity::from_now(Duration::from_secs(3600)).unwrap();
        let pub_key_der = rsa_key.to_public_key().to_public_key_der().unwrap();
        let pub_key = SubjectPublicKeyInfoOwned::from_der(pub_key_der.as_ref()).unwrap();

        let cert = CertificateBuilder::new(
            Profile::Root,
            serial,
            validity,
            subject,
            pub_key,
            &signing_key,
        )
        .unwrap()
        .build::<rsa::pkcs1v15::Signature>()
        .unwrap();

        SigningCredentials {
            certificate: cert,
            signing_key: SigningKeyType::Rsa(rsa::pkcs1v15::SigningKey::<Sha256>::new(rsa_key)),
            cert_chain: vec![],
            team_id: Some("TESTTEAM".to_string()),
        }
    }

    #[test]
    fn test_sha256_only_signature_omits_sha1_code_directory() {
        use crate::codesign::constants::{
            CSMAGIC_BLOBWRAPPER, CSMAGIC_EMBEDDED_SIGNATURE, CSSLOT_ALTERNATE_CODEDIRECTORIES,
            CSSLOT_CODEDIRECTORY, CSSLOT_SIGNATURESLOT,
        };

        let macho = MachOFile::parse(make_minimal_macho()).unwrap();
        let credentials = test_credentials();
        let signed = sign_macho_sha256_only(
            &macho,
            "com.zsign.sha256only",
            None,
            &credentials,
            None,
            None,
        )
        .expect("sha256-only signing must succeed");

        let signed_macho = crate::macho::MachOFile::parse(signed.clone()).unwrap();
        let slice = &signed_macho.slices()[0];
        let off = slice.code_sig_offset.unwrap() as usize;
        let size = slice.code_sig_size.unwrap() as usize;
        let blob = &signed[off..off + size];
        assert_eq!(
            read_u32(blob, 0),
            CSMAGIC_EMBEDDED_SIGNATURE,
            "must be a superblob"
        );
        let count = read_u32(blob, 8) as usize;
        let mut saw_sha256 = false;
        let mut saw_sha1 = false;
        let mut saw_cms = false;
        for i in 0..count {
            let typ = read_u32(blob, 12 + i * 8);
            let eoff = read_u32(blob, 16 + i * 8) as usize;
            match typ {
                CSSLOT_CODEDIRECTORY => saw_sha256 = true,
                CSSLOT_ALTERNATE_CODEDIRECTORIES => saw_sha1 = true,
                CSSLOT_SIGNATURESLOT => {
                    saw_cms = read_u32(blob, eoff) == CSMAGIC_BLOBWRAPPER;
                }
                _ => {}
            }
        }
        assert!(
            saw_sha256,
            "sha256 code directory must be present in the primary slot"
        );
        assert!(!saw_sha1, "sha1 code directory must be omitted");
        assert!(saw_cms, "cms signature must be present");
    }

    #[test]
    fn test_adhoc_signature_has_cs_adhoc_flag_and_empty_wrapper() {
        use crate::codesign::constants::{
            CSMAGIC_BLOBWRAPPER, CSMAGIC_EMBEDDED_SIGNATURE, CSSLOT_ALTERNATE_CODEDIRECTORIES,
            CSSLOT_CODEDIRECTORY, CSSLOT_SIGNATURESLOT,
        };

        let macho = MachOFile::parse(make_minimal_macho()).unwrap();
        let signed = sign_macho_adhoc(&macho, "com.zsign.adhoc", None, None, None)
            .expect("adhoc signing must succeed");

        let sm = crate::macho::MachOFile::parse(signed.clone()).unwrap();
        let slice = &sm.slices()[0];
        let off = slice.code_sig_offset.unwrap() as usize;
        let size = slice.code_sig_size.unwrap() as usize;
        let blob = &signed[off..off + size];
        assert_eq!(read_u32(blob, 0), CSMAGIC_EMBEDDED_SIGNATURE);

        let count = read_u32(blob, 8) as usize;
        let mut saw_adhoc_flag = false;
        let mut saw_empty_wrapper = false;
        for i in 0..count {
            let typ = read_u32(blob, 12 + i * 8);
            let eoff = read_u32(blob, 16 + i * 8) as usize;
            match typ {
                CSSLOT_CODEDIRECTORY | CSSLOT_ALTERNATE_CODEDIRECTORIES => {
                    let flags = read_u32(blob, eoff + 12);
                    if flags & CS_ADHOC != 0 {
                        saw_adhoc_flag = true;
                    }
                }
                CSSLOT_SIGNATURESLOT => {
                    let magic = read_u32(blob, eoff);
                    let len = read_u32(blob, eoff + 4) as usize;
                    if magic == CSMAGIC_BLOBWRAPPER && len == 8 {
                        saw_empty_wrapper = true;
                    }
                }
                _ => {}
            }
        }
        assert!(
            saw_adhoc_flag,
            "code directories must carry the CS_ADHOC flag"
        );
        assert!(
            saw_empty_wrapper,
            "signature slot must be the empty ad-hoc wrapper"
        );
    }

    #[test]
    fn test_minimal_macho_is_parseable() {
        let data = make_minimal_macho();
        assert_eq!(data.len(), 0x2000);
        let macho = MachOFile::parse(data).expect("minimal mach-o must parse");
        assert!(!macho.is_fat());
        assert_eq!(macho.slices().len(), 1);
        assert!(macho.slices()[0].is_executable);
        assert_eq!(macho.slices()[0].text_segment_size, 0x1000);
        assert_eq!(macho.slices()[0].text_segment_base, 0x1_0000_0000);
        assert_eq!(macho.code_bytes(&macho.slices()[0]).len(), 0x2000);
    }

    #[test]
    fn test_sign_then_verify_roundtrip() {
        use goblin::mach::load_command::CommandVariant;
        use goblin::mach::Mach;

        let identifier = "com.zsign.roundtrip";
        let macho = MachOFile::parse(make_minimal_macho()).unwrap();
        let credentials = test_credentials();

        let signed = sign_macho(
            &macho,
            identifier,
            Some(b"<plist><dict><key>get-task-allow</key><true/></dict></plist>"),
            &credentials,
            Some(b"<plist><dict><key>CFBundleIdentifier</key><string>com.zsign.roundtrip</string></dict></plist>"),
            Some(b"<plist><dict><key>files</key><dict/></dict></plist>"),
        )
        .expect("signing must succeed");

        // The signed binary must still parse with the same code region.
        let signed_macho = MachOFile::parse(signed.clone()).unwrap();
        let slice = &signed_macho.slices()[0];
        let code = signed_macho.code_bytes(slice);
        assert_eq!(code.len(), 0x2000, "signing must not alter the code region");

        // Locate the embedded code signature through goblin.
        let Mach::Binary(binary) = Mach::parse(&signed).unwrap() else {
            panic!("signed binary must be a single-arch Mach-O");
        };
        let lc = binary
            .load_commands
            .iter()
            .find_map(|cmd| match cmd.command {
                CommandVariant::CodeSignature(cs) => Some(cs),
                _ => None,
            })
            .expect("signed binary must carry LC_CODE_SIGNATURE");
        let blob = &signed[lc.dataoff as usize..(lc.dataoff + lc.datasize) as usize];

        assert_eq!(
            read_u32(blob, 0),
            crate::codesign::constants::CSMAGIC_EMBEDDED_SIGNATURE,
            "embedded signature must be a SuperBlob"
        );
        let count = read_u32(blob, 8) as usize;
        assert!(count >= 3, "superblob needs code directories + CMS");

        // Collect blob entries.
        let mut cms_found = false;
        let mut hash_size_seen = 0usize;
        for i in 0..count {
            let typ = read_u32(blob, 12 + i * 8);
            let off = read_u32(blob, 12 + i * 8 + 4) as usize;
            let entry = &blob[off..];
            match typ {
                crate::codesign::constants::CSSLOT_SIGNATURESLOT => {
                    assert_eq!(
                        read_u32(entry, 0),
                        crate::codesign::constants::CSMAGIC_BLOBWRAPPER,
                        "CMS slot must be a blob wrapper"
                    );
                    let len = read_u32(entry, 4) as usize;
                    assert!(len > 100, "CMS signature must be non-trivial");
                    cms_found = true;
                }
                crate::codesign::constants::CSSLOT_CODEDIRECTORY
                | crate::codesign::constants::CSSLOT_ALTERNATE_CODEDIRECTORIES => {
                    hash_size_seen = verify_code_directory(
                        entry,
                        code,
                        identifier,
                        &credentials,
                        hash_size_seen,
                    );
                }
                _ => {}
            }
        }
        assert!(cms_found, "superblob must contain a CMS signature");
        assert!(
            (hash_size_seen & (20 | 32)) == (20 | 32),
            "both SHA-1 and SHA-256 code directories must be present"
        );
    }

    /// Code-signing blobs are stored big-endian (`0xfade0cc0` is written as
    /// `fa de 0c c0`), matching the in-file byte order of Apple's CS blobs.
    fn read_u32(s: &[u8], off: usize) -> u32 {
        u32::from_be_bytes(s[off..off + 4].try_into().unwrap())
    }

    /// Independently recomputes the code-page hashes and checks every
    /// important CodeDirectory field. Returns the hash size seen (20 or 32).
    fn verify_code_directory(
        cd: &[u8],
        code: &[u8],
        identifier: &str,
        credentials: &crate::crypto::SigningCredentials,
        mut seen: usize,
    ) -> usize {
        use crate::codesign::constants::CSMAGIC_CODEDIRECTORY;

        assert_eq!(
            read_u32(cd, 0),
            CSMAGIC_CODEDIRECTORY,
            "code directory magic"
        );
        let version = read_u32(cd, 8);
        assert!(version >= 0x20400, "code directory must be v0x20400+");
        let hash_offset = read_u32(cd, 16) as usize;
        let ident_offset = read_u32(cd, 20) as usize;
        let n_special = read_u32(cd, 24) as usize;
        let n_code = read_u32(cd, 28) as usize;
        let code_limit = read_u32(cd, 32) as usize;
        let hash_size = cd[36] as usize;
        let hash_type = cd[37];
        let page_size_log2 = cd[39];
        seen |= hash_size;

        assert_eq!(page_size_log2, 12, "page size must be 4096");
        assert_eq!(
            code_limit,
            code.len(),
            "codeLimit must cover exactly the unsigned code region"
        );
        assert_eq!(
            n_code,
            code.len().div_ceil(4096),
            "code slot count must match the page count"
        );

        let hash_type_expected: u8 = if hash_size == 20 { 1 } else { 2 };
        assert_eq!(
            hash_type, hash_type_expected,
            "hash type must match hash size"
        );

        let ident_end = cd[ident_offset..]
            .iter()
            .position(|&b| b == 0)
            .expect("identifier must be NUL-terminated");
        assert_eq!(
            std::str::from_utf8(&cd[ident_offset..ident_offset + ident_end]).unwrap(),
            identifier,
            "code directory identifier must match the signing identifier"
        );

        // Executable segment fields (v0x20400).
        let exec_seg_base = u64::from_be_bytes(cd[64..72].try_into().unwrap());
        let exec_seg_limit = u64::from_be_bytes(cd[72..80].try_into().unwrap());
        assert_eq!(exec_seg_base, 0x1_0000_0000, "exec segment base");
        assert_eq!(exec_seg_limit, 0x1000, "exec segment limit");

        // Team identifier (v0x20200+).
        let team_off = read_u32(cd, 48) as usize;
        let team_end = cd[team_off..]
            .iter()
            .position(|&b| b == 0)
            .expect("team id must be NUL-terminated");
        assert_eq!(
            std::str::from_utf8(&cd[team_off..team_off + team_end]).unwrap(),
            credentials.team_id.as_deref().unwrap(),
            "team id must round-trip through the code directory"
        );

        // The stored `hashOffset` points at the first code slot (the
        // special-slot hashes precede it), matching zsign's layout.
        let hashes = &cd[hash_offset..hash_offset + n_code * hash_size];
        let _ = (n_special, seen);
        let mut manual = Vec::with_capacity(hashes.len());
        for page in code.chunks(4096) {
            if hash_size == 20 {
                let mut h = Sha1::new();
                h.update(page);
                manual.extend_from_slice(&h.finalize());
            } else {
                let mut h = Sha256::new();
                h.update(page);
                manual.extend_from_slice(&h.finalize());
            }
        }
        assert_eq!(hashes, manual, "code-page hashes must verify");
        seen
    }
}
