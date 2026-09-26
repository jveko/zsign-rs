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

        // Non-executables (dylibs, frameworks) carry no entitlements: an absent
        // entitlements slot is the codesign baseline, and unallocated special
        // slots are presumed absent rather than being an error.
        let entitlements = if is_executable { entitlements } else { None };

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

/// Refuse to sign if any slice is FairPlay-encrypted (unless overridden).
fn reject_encrypted(macho: &MachOFile, identifier: &str, allow_encrypted: bool) -> Result<()> {
    if allow_encrypted {
        return Ok(());
    }
    for (index, slice) in macho.slices().iter().enumerate() {
        if slice.is_encrypted() {
            let enc = slice
                .encryption
                .as_ref()
                .expect("is_encrypted() implies encryption is Some");
            return Err(crate::Error::EncryptedBinary(format!(
                "identifier \"{identifier}\", slice {index} (cpu 0x{:x}): cryptid={}, cryptoff=0x{:x}, cryptsize=0x{:x}: decrypt the binary first (frida-ios-dump / bagbak / Clutch / bfdecrypt), then re-sign. Pass allow_encrypted=true (-f/--force) to override.",
                slice.cpu_type, enc.cryptid, enc.cryptoff, enc.cryptsize
            )));
        }
    }
    Ok(())
}

/// Signs any Mach-O binary (single-arch or FAT), returns signed bytes.
///
/// Dispatch follows the container kind: a FAT/Universal container is signed
/// slice-by-slice and reassembled (even when it holds a single architecture),
/// while a thin binary is signed in place.
/// * Entitlements are ignored for non-executables: no entitlements slot is
///   emitted (an absent slot is the codesign baseline).
pub fn sign_any_macho(
    macho: &MachOFile,
    identifier: &str,
    entitlements: Option<&[u8]>,
    credentials: &SigningCredentials,
    info_plist: Option<&[u8]>,
    code_resources: Option<&[u8]>,
    allow_encrypted: bool,
) -> Result<Vec<u8>> {
    reject_encrypted(macho, identifier, allow_encrypted)?;

    if !macho.is_fat() {
        sign_macho(
            macho,
            identifier,
            entitlements,
            credentials,
            info_plist,
            code_resources,
            allow_encrypted,
        )
    } else {
        let signed_slices = sign_macho_all_slices(
            macho,
            identifier,
            entitlements,
            credentials,
            info_plist,
            code_resources,
            allow_encrypted,
        )?;
        super::writer::embed_signature_fat(macho.data(), &signed_slices)
    }
}

/// Signs a single-architecture Mach-O binary.
///
/// Builds a complete code signature and embeds it into the binary.
/// For FAT binaries, use [`sign_any_macho`] instead.
///
/// # Arguments
///
/// * `macho` - Parsed Mach-O file (uses first slice)
/// * `identifier` - Bundle identifier (e.g., `com.example.app`)
/// * `entitlements` - Optional entitlements plist (XML format)
/// * `credentials` - Signing certificate and key from [`SigningCredentials`]
/// * `info_plist` - Optional Info.plist data for hashing
/// * `code_resources` - Optional CodeResources data for hashing
/// * `allow_encrypted` - Override the FairPlay-encryption refusal and sign
///   encrypted binaries anyway (for already-decrypted input only)
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
///     false, // allow_encrypted
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
    allow_encrypted: bool,
) -> Result<Vec<u8>> {
    if macho.is_fat() {
        return Err(crate::Error::MachO(
            "sign_macho signs thin Mach-O only; use sign_any_macho for FAT/Universal binaries"
                .into(),
        ));
    }
    reject_encrypted(macho, identifier, allow_encrypted)?;
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
    allow_encrypted: bool,
) -> Result<Vec<u8>> {
    if macho.is_fat() {
        return Err(crate::Error::MachO(
            "sign_macho_adhoc signs thin Mach-O only; use sign_any_macho for FAT/Universal binaries"
                .into(),
        ));
    }
    reject_encrypted(macho, identifier, allow_encrypted)?;
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

/// Signs a Mach-O emitting only the SHA-256 code directory (no SHA-1 code
/// directory slot).
///
/// Every slice of a FAT/Universal binary is signed with SHA-256-only code
/// directories and the container is reassembled; a thin binary is signed in
/// place.
pub fn sign_macho_sha256_only(
    macho: &MachOFile,
    identifier: &str,
    entitlements: Option<&[u8]>,
    credentials: &SigningCredentials,
    info_plist: Option<&[u8]>,
    code_resources: Option<&[u8]>,
    allow_encrypted: bool,
) -> Result<Vec<u8>> {
    if macho.is_fat() {
        reject_encrypted(macho, identifier, allow_encrypted)?;
        let signed = sign_all_slices_impl(
            macho,
            identifier,
            entitlements,
            credentials,
            info_plist,
            code_resources,
            allow_encrypted,
            true,
        )?;
        return super::writer::embed_signature_fat(macho.data(), &signed);
    }
    reject_encrypted(macho, identifier, allow_encrypted)?;
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
    allow_encrypted: bool,
) -> Result<Vec<SignedSlice>> {
    sign_all_slices_impl(
        macho,
        identifier,
        entitlements,
        credentials,
        info_plist,
        code_resources,
        allow_encrypted,
        false,
    )
}

/// Shared per-slice signing engine behind [`sign_macho_all_slices`] and
/// [`sign_macho_sha256_only`].
///
/// `sha256_only` selects whether each slice gets a SHA-256-only code
/// directory (no SHA-1 slot) or the default SHA-1 + SHA-256 set.
// Mirrors the frozen 7-argument public sibling plus the sha256_only mode
// flag; a wrapper struct for a private two-caller helper would add
// indirection without shrinking the public surface.
#[allow(clippy::too_many_arguments)]
fn sign_all_slices_impl(
    macho: &MachOFile,
    identifier: &str,
    entitlements: Option<&[u8]>,
    credentials: &SigningCredentials,
    info_plist: Option<&[u8]>,
    code_resources: Option<&[u8]>,
    allow_encrypted: bool,
    sha256_only: bool,
) -> Result<Vec<SignedSlice>> {
    let is_executable = macho
        .slices()
        .first()
        .map(|s| s.is_executable)
        .unwrap_or(false);
    reject_encrypted(macho, identifier, allow_encrypted)?;
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
                sha256_only,
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
                estimated_sig_size,
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
                text_segment_fileoff: slice.text_segment_fileoff,
                code_length: slice.code_length,
                metadata: updated_metadata.clone(),
                encryption: slice.encryption,
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
                    padded_sig_size,
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
                    text_segment_fileoff: slice.text_segment_fileoff,
                    code_length: slice.code_length,
                    metadata: updated_metadata.clone(),
                    encryption: slice.encryption,
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
            cpu_type: slice.cpu_type,
            signed_data: buf2,
        });
    }

    // Step 8: Embed signature in-place
    embed_signature_in_place(&mut buf, &final_sig, sig_offset, target_binary_size);

    Ok(SignedSlice {
        slice_index: 0,
        offset: slice.offset,
        original_size: slice.size,
        cpu_type: slice.cpu_type,
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
        .exec_seg_base(slice.text_segment_fileoff)
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
    use crate::macho::fixtures::{
        make_fat_macho, make_minimal_macho, make_minimal_macho_encrypted,
    };

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

    /// RFC 6979 A.2.5 P-256 scalar, quoted from
    /// <https://www.rfc-editor.org/rfc/rfc6979.txt#appendix-A.2.5>.
    const RFC6979_P256_SCALAR: [u8; 32] = [
        0xc9, 0xaf, 0xa9, 0xd8, 0x45, 0xba, 0x75, 0x16, 0x6b, 0x5c, 0x21, 0x57, 0x67, 0xb1, 0xd6,
        0x93, 0x4e, 0x50, 0xc3, 0xdb, 0x36, 0xe8, 0x9b, 0x12, 0x7b, 0x8a, 0x62, 0x2b, 0x12, 0x0f,
        0x67, 0x21,
    ];

    /// codeSigning EKU: `1.3.6.1.5.5.7.3.3`.
    const OID_CODE_SIGNING: const_oid::ObjectIdentifier =
        const_oid::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.3");

    fn fixed_unix_time(unix: u64) -> x509_cert::time::Time {
        x509_cert::time::Time::try_from(
            std::time::UNIX_EPOCH + std::time::Duration::from_secs(unix),
        )
        .unwrap()
    }

    /// Fixed-scalar ECDSA credentials with a pinned validity window, so the whole
    /// signed binary is a pure function of its inputs. Mirrors
    /// `cms.rs`'s `build_fixed_ecdsa_credentials`; test-only helpers are duplicated
    /// across these modules rather than widening a `#[cfg(test)]` surface.
    fn ecdsa_credentials_for_determinism() -> crate::crypto::SigningCredentials {
        use crate::crypto::cert::{SigningCredentials, SigningKeyType};
        use der::Decode;
        use p256::ecdsa::SigningKey;
        use spki::{EncodePublicKey, SubjectPublicKeyInfoOwned};
        use std::str::FromStr;
        use x509_cert::builder::{Builder, CertificateBuilder, Profile};
        use x509_cert::ext::pkix::ExtendedKeyUsage;
        use x509_cert::name::Name;
        use x509_cert::serial_number::SerialNumber;
        use x509_cert::time::Validity;

        let ecdsa_key = SigningKey::from_slice(&RFC6979_P256_SCALAR).expect("fixed scalar");
        let subject = Name::from_str("CN=ECDSA Determinism Signer,OU=TESTTEAM").unwrap();
        let validity = Validity {
            not_before: fixed_unix_time(1_700_000_000),
            not_after: fixed_unix_time(4_000_000_000),
        };
        let pub_key = SubjectPublicKeyInfoOwned::from_der(
            p256::ecdsa::VerifyingKey::from(&ecdsa_key)
                .to_public_key_der()
                .unwrap()
                .as_ref(),
        )
        .unwrap();
        let mut builder = CertificateBuilder::new(
            Profile::Leaf {
                issuer: subject.clone(),
                enable_key_agreement: false,
                enable_key_encipherment: false,
            },
            SerialNumber::from(442u32),
            validity,
            subject,
            pub_key,
            &ecdsa_key,
        )
        .unwrap();
        builder
            .add_extension(&ExtendedKeyUsage(vec![OID_CODE_SIGNING]))
            .unwrap();
        let cert = builder.build::<p256::ecdsa::DerSignature>().unwrap();

        SigningCredentials {
            certificate: cert,
            signing_key: SigningKeyType::Ecdsa(ecdsa_key),
            cert_chain: vec![],
            team_id: Some("TESTTEAM".to_string()),
        }
    }

    #[test]
    fn sign_macho_ecdsa_is_byte_identical_twice() {
        let credentials = ecdsa_credentials_for_determinism();
        let macho = MachOFile::parse(crate::macho::fixtures::make_minimal_macho()).unwrap();
        let identifier = "com.zsign.ecdsa.determinism";
        let entitlements = Some(b"<plist><dict/></plist>".as_slice());

        let first = sign_macho(
            &macho,
            identifier,
            entitlements,
            &credentials,
            None,
            None,
            false,
        )
        .expect("first ECDSA sign");
        let second = sign_macho(
            &macho,
            identifier,
            entitlements,
            &credentials,
            None,
            None,
            false,
        )
        .expect("second ECDSA sign");
        assert_eq!(
            first, second,
            "embedding a P-256 signature twice must reproduce the binary byte for byte"
        );
        // Reparsing proves the bytes are a real signature, not identical garbage.
        let reparsed = MachOFile::parse(second).expect("signed output must reparse");
        assert!(!reparsed.slices().is_empty());
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
            false,
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
    fn test_sha256_only_signs_two_arch_fat_container() {
        use crate::codesign::constants::{
            CSMAGIC_CODEDIRECTORY, CSMAGIC_EMBEDDED_SIGNATURE, CSSLOT_ALTERNATE_CODEDIRECTORIES,
            CSSLOT_CODEDIRECTORY, CS_HASHTYPE_SHA1, CS_HASHTYPE_SHA256,
        };

        let mut second = make_minimal_macho();
        second[4..8].copy_from_slice(&0x0100_0007u32.to_le_bytes()); // x86_64-headed
        let fat = make_fat_macho(&[make_minimal_macho(), second], &[12, 12]);
        let macho = MachOFile::parse(fat).unwrap();
        assert!(macho.is_fat(), "fixture must parse as a FAT container");
        assert_eq!(macho.slices().len(), 2, "fixture must hold two slices");

        let creds = test_credentials();
        // This is exactly the call the default IpaSigner (sha256_only=true) makes.
        let signed =
            sign_macho_sha256_only(&macho, "com.zsign.fatsha", None, &creds, None, None, false)
                .expect("default sha256-only path must sign a two-arch FAT executable");

        let m = MachOFile::parse(signed.clone()).unwrap();
        assert!(m.is_fat(), "FAT container must survive sha256-only signing");
        assert_eq!(m.slices().len(), 2, "both architectures must be preserved");
        let cpus: Vec<u32> = m.slices().iter().map(|s| s.cpu_type).collect();
        assert_eq!(
            cpus,
            vec![0x0100_000c, 0x0100_0007],
            "architecture order must be preserved"
        );
        for slice in m.slices() {
            let sig = slice
                .code_sig_offset
                .expect("each slice must carry a signature");
            let sig_len = slice
                .code_sig_size
                .expect("each slice must size its signature") as usize;
            let start = slice.offset + sig as usize;
            let blob = &signed[start..start + sig_len];
            assert_eq!(
                read_u32(blob, 0),
                CSMAGIC_EMBEDDED_SIGNATURE,
                "slice cpu_type {:#x}: signature must be a superblob",
                slice.cpu_type
            );
            // SuperBlob layout: magic(4) + count(4, BE) + count * 8-byte
            // (type, offset) BE entries starting at offset 8.
            let count = read_u32(blob, 8) as usize;
            let mut saw_cd = false;
            for i in 0..count {
                let typ = read_u32(blob, 12 + i * 8);
                let eoff = read_u32(blob, 16 + i * 8) as usize;
                let is_cd_slot = typ == CSSLOT_CODEDIRECTORY
                    || (CSSLOT_ALTERNATE_CODEDIRECTORIES..CSSLOT_ALTERNATE_CODEDIRECTORIES + 5)
                        .contains(&typ);
                if !is_cd_slot {
                    continue;
                }
                assert_eq!(
                    read_u32(blob, eoff),
                    CSMAGIC_CODEDIRECTORY,
                    "slot {typ:#x} must point at a CodeDirectory blob"
                );
                // CodeDirectory header: magic 4 + version 4 + flags 4 +
                // hashOffset 2 + identOffset 2 + nSpecialSlots 4 +
                // nCodeSlots 4 + codeLimit 4 + hashSize 1 => hashType is
                // the single byte at offset 37 (CS_HASHTYPE_SHA256 == 2).
                let hash_type = blob[eoff + 37];
                saw_cd = true;
                assert_ne!(
                    hash_type, CS_HASHTYPE_SHA1,
                    "slice cpu_type {:#x}: no SHA-1 CodeDirectory may exist",
                    slice.cpu_type
                );
                assert_eq!(
                    hash_type, CS_HASHTYPE_SHA256,
                    "slice cpu_type {:#x}: every CodeDirectory must be SHA-256",
                    slice.cpu_type
                );
            }
            assert!(
                saw_cd,
                "slice cpu_type {:#x}: at least one CodeDirectory must be emitted",
                slice.cpu_type
            );
        }
    }

    #[test]
    fn test_sign_any_macho_preserves_one_arch_fat_container() {
        let fat = make_fat_macho(&[make_minimal_macho()], &[12]);
        let macho = MachOFile::parse(fat).unwrap();
        assert!(macho.is_fat() && macho.slices().len() == 1);
        let creds = test_credentials();
        let signed = sign_any_macho(&macho, "com.zsign.onefat", None, &creds, None, None, false)
            .expect("one-arch FAT must sign through the FAT-capable path");
        assert_eq!(
            &signed[0..4],
            &[0xca, 0xfe, 0xba, 0xbe],
            "one-arch FAT output must keep the fat_header, not be stripped to thin"
        );
        let m = MachOFile::parse(signed).unwrap();
        assert!(m.is_fat(), "output must reparse as a FAT container");
        assert_eq!(m.slices().len(), 1);
        assert!(
            m.slices()[0].code_sig_offset.is_some(),
            "embedded slice must be signed"
        );
    }

    #[test]
    fn test_sign_preserves_fat_slice_trailing_bytes() {
        let mut a = make_minimal_macho();
        let tail_start = a.len();
        // Bytes past the last file-backed segment, inside the declared
        // fat_arch size: the signature must start after them, and they must
        // survive verbatim in the signed output.
        a.extend(std::iter::repeat_n(0xAB, 0x400));
        let mut b = make_minimal_macho();
        b[4..8].copy_from_slice(&0x0100_0007u32.to_le_bytes()); // x86_64-headed
        let fat = make_fat_macho(&[a, b], &[12, 12]);
        let macho = MachOFile::parse(fat).unwrap();
        let creds = test_credentials();
        let signed = sign_any_macho(&macho, "com.zsign.tail", None, &creds, None, None, false)
            .expect("FAT signing must succeed");
        let m = MachOFile::parse(signed.clone()).expect("signed output reparses");
        let s = &m.slices()[0];
        let end = s.offset + s.code_sig_offset.expect("signed slice") as usize;
        let got = &signed[s.offset + tail_start..end];
        assert_eq!(
            got.len(),
            0x400,
            "signature must start after the full 0x400-byte tail, got 0x{:x}-byte range",
            got.len()
        );
        assert!(
            got.iter().all(|byte| *byte == 0xAB),
            "trailing bytes must be preserved before the signature; got {:02x?}",
            &got[..8.min(got.len())]
        );
    }

    #[test]
    fn test_thin_only_signers_reject_fat_containers() {
        let fat = make_fat_macho(&[make_minimal_macho()], &[12]);
        let macho = MachOFile::parse(fat).unwrap();
        let creds = test_credentials();
        let err = sign_macho(&macho, "com.zsign.no", None, &creds, None, None, false)
            .expect_err("thin-only signer must reject a container, never strip it");
        assert!(
            err.to_string().contains("sign_any_macho"),
            "error must point at the FAT-capable entry: {err}"
        );
        let err = sign_macho_adhoc(&macho, "com.zsign.no", None, None, None, false)
            .expect_err("adhoc thin-only signer must reject a container");
        assert!(
            err.to_string().contains("sign_any_macho"),
            "error must point at the FAT-capable entry: {err}"
        );
    }

    #[test]
    fn test_adhoc_signature_has_cs_adhoc_flag_and_empty_wrapper() {
        use crate::codesign::constants::{
            CSMAGIC_BLOBWRAPPER, CSMAGIC_EMBEDDED_SIGNATURE, CSSLOT_ALTERNATE_CODEDIRECTORIES,
            CSSLOT_CODEDIRECTORY, CSSLOT_SIGNATURESLOT,
        };

        let macho = MachOFile::parse(make_minimal_macho()).unwrap();
        let signed = sign_macho_adhoc(&macho, "com.zsign.adhoc", None, None, None, false)
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
    fn test_sign_with_large_entitlements_fits_reserve() {
        // A ~20 KiB entitlements plist pushes the signer's own tight estimate
        // past the writer's formula reserve, so the expansion must be sized from
        // the estimate the signer actually hands to prepare. Re-signing the
        // output covers the window where the declared reserve is already there.
        let mut ent = String::from(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n",
        );
        for i in 0..400 {
            ent.push_str(&format!(
                "<key>com.example.pad{i}</key><string>{}</string>\n",
                "x".repeat(30)
            ));
        }
        ent.push_str("</dict>\n</plist>\n");
        assert!(
            ent.len() > 16_000,
            "fixture must exceed the formula reserve headroom: {}",
            ent.len()
        );

        let macho = MachOFile::parse(make_minimal_macho()).unwrap();
        let creds = test_credentials();
        let first = sign_macho(
            &macho,
            "com.zsign.bigents",
            Some(ent.as_bytes()),
            &creds,
            None,
            None,
            false,
        )
        .expect("tight-heavy estimate must be covered by realloc");

        let m = MachOFile::parse(first.clone()).expect("signed output must reparse");
        sign_macho(
            &m,
            "com.zsign.bigents",
            Some(ent.as_bytes()),
            &creds,
            None,
            None,
            false,
        )
        .expect("re-sign of the signed output must succeed with the reserve flowing into realloc");
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
            false,
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

    #[test]
    fn test_sign_refuses_encrypted_binary() {
        // cryptsize=0x2000 (distinct from the fixture's hardcoded cryptoff=0x1000)
        // so the message assertion proves both fields are serialized.
        let macho = MachOFile::parse(make_minimal_macho_encrypted(1, 0x2000)).unwrap();
        let credentials = test_credentials();
        let err = sign_macho(
            &macho,
            "com.zsign.encrypted",
            None,
            &credentials,
            None,
            None,
            false, // allow_encrypted
        )
        .expect_err("signing an encrypted binary must refuse");
        match err {
            crate::Error::EncryptedBinary(msg) => {
                assert!(
                    msg.contains("com.zsign.encrypted"),
                    "message must name the identifier: {msg}"
                );
                assert!(
                    msg.contains("cpu 0x100000c"),
                    "message must show the cpu type: {msg}"
                );
                assert!(
                    msg.contains("cryptid=1"),
                    "message must show cryptid: {msg}"
                );
                assert!(
                    msg.contains("cryptoff=0x1000"),
                    "message must show cryptoff: {msg}"
                );
                assert!(
                    msg.contains("cryptsize=0x2000"),
                    "message must show cryptsize: {msg}"
                );
                assert!(
                    msg.contains("decrypt"),
                    "message must tell the user to decrypt: {msg}"
                );
            }
            other => panic!("expected EncryptedBinary, got {other:?}"),
        }
    }

    #[test]
    fn test_sign_any_macho_refuses_encrypted() {
        // sign_any_macho single-arch path must enforce the guard and forward
        // allow_encrypted through to sign_macho.
        let macho = MachOFile::parse(make_minimal_macho_encrypted(1, 0x1000)).unwrap();
        let credentials = test_credentials();
        let err = sign_any_macho(
            &macho,
            "com.zsign.encrypted",
            None,
            &credentials,
            None,
            None,
            false,
        )
        .expect_err("sign_any_macho must refuse encrypted input");
        assert!(
            matches!(err, crate::Error::EncryptedBinary(_)),
            "expected EncryptedBinary, got {err:?}"
        );
    }

    /// Builds a FAT binary: plain arm64 slice at offset 0x1000 and an
    /// encrypted arm64 slice at offset 0x3000 (per-slice load commands).
    fn make_fat_with_encrypted_second_slice() -> Vec<u8> {
        let plain = make_minimal_macho();
        let encrypted = make_minimal_macho_encrypted(1, 0x1000);
        assert_eq!(plain.len(), encrypted.len());

        let mut b = Vec::with_capacity(0x3000 + plain.len());
        // FAT header (big-endian): magic, nfat_arch
        b.extend_from_slice(&0xcafebabeu32.to_be_bytes());
        b.extend_from_slice(&2u32.to_be_bytes());
        // fat_arch[0]: cputype, cpusubtype, offset, size, align (BE)
        b.extend_from_slice(&0x0100_000cu32.to_be_bytes());
        b.extend_from_slice(&0u32.to_be_bytes());
        b.extend_from_slice(&0x1000u32.to_be_bytes());
        b.extend_from_slice(&(plain.len() as u32).to_be_bytes());
        b.extend_from_slice(&12u32.to_be_bytes());
        // fat_arch[1]
        b.extend_from_slice(&0x0100_000cu32.to_be_bytes());
        b.extend_from_slice(&0u32.to_be_bytes());
        b.extend_from_slice(&0x3000u32.to_be_bytes());
        b.extend_from_slice(&(encrypted.len() as u32).to_be_bytes());
        b.extend_from_slice(&12u32.to_be_bytes());
        // slice data
        b.resize(0x1000, 0);
        b.extend_from_slice(&plain);
        b.resize(0x3000, 0);
        b.extend_from_slice(&encrypted);
        b
    }

    #[test]
    fn test_sign_refuses_fat_with_encrypted_slice() {
        let macho = MachOFile::parse(make_fat_with_encrypted_second_slice())
            .expect("FAT binary must parse");
        assert!(macho.is_fat());
        assert_eq!(macho.slices().len(), 2);
        assert!(
            !macho.slices()[0].is_encrypted(),
            "first slice must be plain"
        );
        assert!(
            macho.slices()[1].is_encrypted(),
            "second slice must be encrypted"
        );

        let credentials = test_credentials();
        let err = sign_any_macho(
            &macho,
            "com.zsign.fat",
            None,
            &credentials,
            None,
            None,
            false,
        )
        .expect_err("FAT with an encrypted slice must refuse");
        match err {
            crate::Error::EncryptedBinary(msg) => {
                assert!(
                    msg.contains("slice 1"),
                    "message must name the encrypted slice: {msg}"
                );
                assert!(
                    msg.contains("cryptid=1"),
                    "message must show cryptid: {msg}"
                );
            }
            other => panic!("expected EncryptedBinary, got {other:?}"),
        }

        // allow_encrypted=true must sign a FAT binary with an encrypted slice.
        let signed = sign_any_macho(
            &macho,
            "com.zsign.fat",
            None,
            &credentials,
            None,
            None,
            true,
        )
        .expect("allow_encrypted=true must sign the FAT binary");
        assert!(
            signed.len() > macho.data().len(),
            "signed FAT must include the embedded signature"
        );
    }

    #[test]
    fn test_sign_allow_encrypted_override() {
        let macho = MachOFile::parse(make_minimal_macho_encrypted(1, 0x1000)).unwrap();
        let credentials = test_credentials();
        let signed = sign_macho(
            &macho,
            "com.zsign.encrypted",
            None,
            &credentials,
            None,
            None,
            true, // allow_encrypted
        )
        .expect("allow_encrypted=true must sign");
        assert!(
            signed.len() > 0x2000,
            "signed output must append the embedded signature (got {} bytes)",
            signed.len()
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
        // Apple emits __TEXT.fileoff, not vmaddr
        assert_eq!(exec_seg_base, 0x1000, "exec segment base");
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

    /// Returns the raw bytes of the primary (first) CodeDirectory in an
    /// embedded superblob: `CSSLOT_CODEDIRECTORY` is type 0 in the entry table.
    fn primary_code_directory(blob: &[u8]) -> Vec<u8> {
        let count = read_u32(blob, 8) as usize;
        for e in 0..count {
            let typ = read_u32(blob, 12 + e * 8);
            let off = read_u32(blob, 12 + e * 8 + 4) as usize;
            if typ == crate::codesign::constants::CSSLOT_CODEDIRECTORY {
                return blob[off..].to_vec();
            }
        }
        panic!("primary CodeDirectory present");
    }

    #[test]
    fn test_exec_seg_main_binary_and_fileoff_base_on_every_fat_slice() {
        let mut b = make_minimal_macho();
        b[4..8].copy_from_slice(&0x0100_0007u32.to_le_bytes());
        let fat = make_fat_macho(&[make_minimal_macho(), b], &[12, 12]);
        let macho = MachOFile::parse(fat).unwrap();
        let creds = test_credentials();
        let signed =
            sign_any_macho(&macho, "com.zsign.execseg", None, &creds, None, None, false).unwrap();
        let m = MachOFile::parse(signed.clone()).unwrap();
        assert_eq!(m.slices().len(), 2);
        for (i, slice) in m.slices().iter().enumerate() {
            let sig = slice.code_sig_offset.expect("signed") as usize;
            let size = slice.code_sig_size.expect("signed size") as usize;
            let blob = &signed[slice.offset + sig..slice.offset + sig + size];
            let cd = primary_code_directory(blob);
            let base = u64::from_be_bytes(cd[64..72].try_into().unwrap());
            let limit = u64::from_be_bytes(cd[72..80].try_into().unwrap());
            let flags = u64::from_be_bytes(cd[80..88].try_into().unwrap());
            assert_eq!(
                base, slice.text_segment_fileoff,
                "slice {i}: execSegBase must be __TEXT fileoff (Apple convention), got {base:#x}"
            );
            assert_eq!(
                limit, slice.text_segment_size,
                "slice {i}: execSegLimit stays __TEXT.filesize"
            );
            assert_ne!(
                flags & 0x1,
                0,
                "slice {i}: CS_EXECSEG_MAIN_BINARY must be set on every MH_EXECUTE slice"
            );
        }
    }

    #[test]
    fn test_exec_seg_flags_zero_for_non_executable() {
        let macho = MachOFile::parse(crate::macho::fixtures::make_minimal_dylib()).unwrap();
        let signed = sign_macho_adhoc(&macho, "com.zsign.dylib", None, None, None, false).unwrap();
        let m = MachOFile::parse(signed.clone()).unwrap();
        let sl = &m.slices()[0];
        let sig = sl.code_sig_offset.expect("signed") as usize;
        let blob = &signed[sig..sig + sl.code_sig_size.expect("size") as usize];
        let cd = primary_code_directory(blob);
        let flags = u64::from_be_bytes(cd[80..88].try_into().unwrap());
        assert_eq!(
            flags, 0,
            "non-executables must not claim CS_EXECSEG_MAIN_BINARY"
        ); // contract lock
    }

    #[test]
    fn test_non_executable_signing_carries_no_entitlements() {
        const ENT: &[u8] = br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>com.example.ent</key><string>yes</string></dict></plist>"#;

        fn assert_no_entitlements(signed: &[u8], via: &str) {
            let m = MachOFile::parse(signed.to_vec()).unwrap();
            let sl = &m.slices()[0];
            let sig_off = sl.code_sig_offset.unwrap() as usize;
            let sig_len = sl.code_sig_size.unwrap() as usize;
            let sb = crate::codesign::verify::parse_superblob(&signed[sig_off..sig_off + sig_len])
                .unwrap_or_else(|e| panic!("{via}: superblob must parse: {e}"));
            assert!(
                sb.entries.iter().all(|e| e.slot != 0x0005),
                "{via}: entitlements blob (slot -5) must not be emitted for a dylib"
            );
            assert!(
                sb.entries.iter().all(|e| e.slot != 0x0007),
                "{via}: DER entitlements blob must not be emitted for a dylib"
            );
            let cd = sb
                .code_directory
                .as_ref()
                .unwrap_or_else(|| panic!("{via}: primary CodeDirectory must be present"));
            match cd.special_slot_hash(5) {
                None => {}
                Some(h) => assert!(
                    h.iter().all(|&b| b == 0),
                    "{via}: slot -5 must be unbound, got {h:02x?}"
                ),
            }
        }

        fn verify(signed: &[u8]) -> crate::macho::MachOVerifyReport {
            crate::macho::verify_macho(signed, &crate::codesign::verify::SignatureInputs::none())
                .unwrap_or_else(|e| panic!("verify must accept the signed dylib: {e}"))
        }

        let macho = MachOFile::parse(crate::macho::fixtures::make_minimal_dylib()).unwrap();
        // Leaf + codeSigning EKU fixture (macho/fixtures.rs:360-399) — the
        // shared macho-test credentials. EKU is required for the identity
        // entries to reach the anchor gate the dual-pin pattern below pins.
        let creds = crate::macho::fixtures::test_signing_credentials();

        // Adhoc entry: strict verify leg — adhoc output carries no certificate,
        // so "still verifies via the existing verify path" means report.is_valid()
        // with zero errors (empirically confirmed for this fixture shape).
        let signed =
            sign_macho_adhoc(&macho, "com.zsign.dylib", Some(ENT), None, None, false).unwrap();
        assert_no_entitlements(&signed, "sign_macho_adhoc");
        let report = verify(&signed);
        assert!(
            report.is_valid(),
            "sign_macho_adhoc: dylib must verify clean: {:?}",
            report.slices[0].errors
        );

        // Identity-signed entries: copy verify_signed_binary_round_trip
        // (macho/verify.rs:948-980) verbatim — signed + !adhoc + identifier +
        // pages Matched + cms signature/message_digest/cdhash/chain each ok,
        // with the ONLY allowed error being the anchor message.
        let gated: [(&str, Vec<u8>); 3] = [
            (
                "sign_macho",
                sign_macho(
                    &macho,
                    "com.zsign.dylib",
                    Some(ENT),
                    &creds,
                    None,
                    None,
                    false,
                )
                .unwrap(),
            ),
            (
                "sign_macho_sha256_only",
                sign_macho_sha256_only(
                    &macho,
                    "com.zsign.dylib",
                    Some(ENT),
                    &creds,
                    None,
                    None,
                    false,
                )
                .unwrap(),
            ),
            (
                "sign_any_macho",
                sign_any_macho(
                    &macho,
                    "com.zsign.dylib",
                    Some(ENT),
                    &creds,
                    None,
                    None,
                    false,
                )
                .unwrap(),
            ),
        ];
        for (via, signed) in gated {
            assert_no_entitlements(&signed, via);
            let report = verify(&signed);
            assert!(!report.is_valid(), "{via}: fixture must stay anchor-gated");
            let slice = &report.slices[0];
            assert!(slice.signed, "{via}: output must carry a signature");
            assert!(
                !slice.adhoc,
                "{via}: credential-signed output must not be ad-hoc"
            );
            assert_eq!(
                slice.identifier.as_deref(),
                Some("com.zsign.dylib"),
                "{via}"
            );
            assert_eq!(
                slice.pages,
                crate::codesign::verify::PageCheck::Matched,
                "{via}: page hashes must match"
            );
            assert_eq!(
                slice.errors.len(),
                1,
                "{via}: only the anchor gate may fail, got {:?}",
                slice.errors
            );
            assert!(
                slice.errors[0].contains("not anchored to a trusted root"),
                "{via}: unexpected gate: {}",
                slice.errors[0]
            );
            let cms = slice.cms.as_ref().expect("CMS report");
            assert!(
                cms.signature_ok
                    && cms.message_digest_ok
                    && cms.cdhash_v1_ok
                    && cms.cdhash_v2_ok
                    && cms.chain_ok,
                "{via}: cms: {cms:?}"
            );
            assert!(
                !cms.anchored,
                "{via}: not anchored without an injected root"
            );
        }
    }
}
