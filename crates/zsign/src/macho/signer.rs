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
    compute_cdhash_sha1, compute_cdhash_sha256, CodeDirectoryBuilder,
};
use crate::codesign::constants::{CS_EXECSEG_ALLOW_UNSIGNED, CS_EXECSEG_MAIN_BINARY};
use crate::codesign::der::plist_to_der;
use crate::codesign::superblob::{
    build_der_entitlements_blob, build_entitlements_blob, build_requirements_blob_full,
    build_signature_blob, SuperBlobBuilder,
};
use crate::crypto::cms;
use crate::crypto::{SigningCredentials, cert::SigningKeyType};
use crate::Result;
use sha1::{Digest, Sha1};
use sha2::Sha256;
use x509_certificate::{CapturedX509Certificate, signing::InMemorySigningKeyPair};

use super::parser::{ArchSlice, MachOFile};
use super::writer::{has_enough_signature_space, prepare_code_for_signing_slice, realloc_code_sign_space_slice};

/// A signed architecture slice with its metadata.
///
/// Contains the complete signed binary data for a single architecture,
/// ready for embedding into a FAT binary using [`embed_signature_fat`](super::writer::embed_signature_fat)
/// or writing directly to disk.
///
/// See [`sign_macho_all_slices`] for generating these from a FAT binary.
#[derive(Debug, Clone)]
pub struct SignedSlice {
    /// Index of this slice within the FAT binary (0 for single-arch).
    pub slice_index: usize,
    /// Original byte offset within the FAT binary.
    pub offset: usize,
    /// Original size before signing.
    pub original_size: usize,
    /// Complete signed binary data for this slice.
    pub signed_data: Vec<u8>,
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
/// ```no_run
/// use zsign::macho::{MachOFile, sign_macho};
/// use zsign::crypto::SigningCredentials;
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
/// # Ok::<(), zsign::Error>(())
/// ```
pub fn sign_macho(
    macho: &MachOFile,
    identifier: &str,
    entitlements: Option<&[u8]>,
    credentials: &SigningCredentials,
    info_plist: Option<&[u8]>,
    code_resources: Option<&[u8]>,
) -> Result<Vec<u8>> {
    let slice = &macho.slices()[0];
    let slice_data = macho.slice_data(slice);

    let signed = sign_slice_complete(
        slice_data,
        slice,
        identifier,
        entitlements,
        credentials,
        info_plist,
        code_resources,
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
    let mut signed_slices = Vec::with_capacity(macho.slices().len());

    for (index, slice) in macho.slices().iter().enumerate() {
        let slice_data = macho.slice_data(slice);

        let mut signed = sign_slice_complete(
            slice_data,
            slice,
            identifier,
            entitlements,
            credentials,
            info_plist,
            code_resources,
        )?;

        signed.slice_index = index;
        signed_slices.push(signed);
    }

    Ok(signed_slices)
}

fn sign_slice_complete(
    slice_data: &[u8],
    slice: &ArchSlice,
    identifier: &str,
    entitlements: Option<&[u8]>,
    credentials: &SigningCredentials,
    info_plist: Option<&[u8]>,
    code_resources: Option<&[u8]>,
) -> Result<SignedSlice> {
    let team_id = credentials.team_id.as_deref();

    let subject_cn = extract_subject_cn(&credentials.certificate).unwrap_or_default();
    let requirements = build_requirements_blob_full(identifier, &subject_cn);
    let requirements_hash_sha1 = sha1_hash(&requirements);
    let requirements_hash_sha256 = sha256_hash(&requirements);

    let (entitlements_blob, ent_hash_sha1, ent_hash_sha256) = if let Some(ent) = entitlements {
        let blob = build_entitlements_blob(ent);
        (Some(blob.clone()), Some(sha1_hash(&blob)), Some(sha256_hash(&blob)))
    } else {
        (None, None, None)
    };

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
        credentials,
    )?;

    let (working_slice_data, working_slice, preserve_original_size) = if !has_enough_signature_space(slice_data, slice.code_length, preliminary_sig.len()) {
        let reallocated = realloc_code_sign_space_slice(slice_data, slice.code_length)?;

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

        (reallocated, new_slice, false)
    } else {
        (slice_data.to_vec(), slice.clone(), true)
    };

    let target_binary_size = Some(working_slice_data.len());

    let sig_space_size = if preserve_original_size {
        let original_sig_space = slice_data.len().saturating_sub(slice.code_length);
        original_sig_space.max(preliminary_sig.len())
    } else {
        preliminary_sig.len()
    };
    let (prepared_code, sig_offset, _) = prepare_code_for_signing_slice(&working_slice_data, sig_space_size)?;

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
        credentials,
    )?;

    let signed_data = embed_signature_into_prepared(&prepared_code, &final_sig, sig_offset, target_binary_size);

    Ok(SignedSlice {
        slice_index: 0,
        offset: slice.offset,
        original_size: slice.size,
        signed_data,
    })
}

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
    credentials: &SigningCredentials,
) -> Result<Vec<u8>> {
    let cd_sha1 = build_code_directory(
        identifier, team_id, code, slice, entitlements,
        requirements_hash_sha1, info_hash_sha1, res_hash_sha1, ent_hash_sha1, der_ent_hash_sha1, true,
    );
    let cd_sha256 = build_code_directory(
        identifier, team_id, code, slice, entitlements,
        requirements_hash_sha256, info_hash_sha256, res_hash_sha256, ent_hash_sha256, der_ent_hash_sha256, false,
    );

    let cdhash_sha1: [u8; 20] = compute_cdhash_sha1(&cd_sha1);
    let cdhash_sha256: [u8; 32] = compute_cdhash_sha256(&cd_sha256);

    let (signing_key, signing_cert, cert_chain) = convert_credentials_for_cms(credentials)?;

    let cms_data = cms::sign_with_apple_attrs(
        &cd_sha1,
        &signing_key,
        &signing_cert,
        &cert_chain,
        &cdhash_sha1,
        &cdhash_sha256,
    )?;
    let signature_blob = build_signature_blob(&cms_data);

    let mut builder = SuperBlobBuilder::new()
        .code_directory_sha1(cd_sha1)
        .code_directory_sha256(cd_sha256)
        .requirements(requirements.to_vec())
        .cms_signature(signature_blob);

    if let Some(ent_blob) = entitlements_blob {
        builder = builder.entitlements(ent_blob.clone());
    }

    if let Some(der_ent_blob) = der_entitlements_blob {
        builder = builder.der_entitlements(der_ent_blob.clone());
    }

    Ok(builder.build())
}

#[allow(clippy::too_many_arguments)]
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
    let mut exec_seg_flags: u64 = 0;

    if slice.is_executable {
        exec_seg_flags = CS_EXECSEG_MAIN_BINARY;
    }

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
    if let Some(hash) = der_entitlements_hash {
        builder = builder.der_entitlements_hash(hash.clone());
    }

    if is_sha1 {
        builder.build_sha1()
    } else {
        builder.build_sha256()
    }
}

fn convert_credentials_for_cms(
    credentials: &SigningCredentials,
) -> Result<(InMemorySigningKeyPair, CapturedX509Certificate, Vec<CapturedX509Certificate>)> {
    use crate::Error;

    let cert_der = credentials.certificate.encode_der()
        .map_err(|e| Error::Certificate(format!("Failed to encode certificate to DER: {}", e)))?;

    let signing_cert = CapturedX509Certificate::from_der(cert_der)
        .map_err(|e| Error::Certificate(format!("Failed to parse certificate for CMS: {}", e)))?;

    let signing_key = match &credentials.signing_key {
        SigningKeyType::Rsa(rsa_key) => {
            use pkcs8::EncodePrivateKey;
            let key_der = rsa_key.to_pkcs8_der()
                .map_err(|e| Error::Certificate(format!("Failed to encode RSA key to PKCS8: {}", e)))?;
            InMemorySigningKeyPair::from_pkcs8_der(key_der.as_bytes())
                .map_err(|e| Error::Certificate(format!("Failed to create signing key pair from RSA: {}", e)))?
        }
        SigningKeyType::Ecdsa(ecdsa_key) => {
            use pkcs8::EncodePrivateKey;
            let key_der = ecdsa_key.to_pkcs8_der()
                .map_err(|e| Error::Certificate(format!("Failed to encode ECDSA key to PKCS8: {}", e)))?;
            InMemorySigningKeyPair::from_pkcs8_der(key_der.as_bytes())
                .map_err(|e| Error::Certificate(format!("Failed to create signing key pair from ECDSA: {}", e)))?
        }
    };

    let cert_chain: Vec<CapturedX509Certificate> = credentials
        .cert_chain
        .iter()
        .filter_map(|cert| {
            cert.encode_der().ok().and_then(|der| {
                CapturedX509Certificate::from_der(der).ok()
            })
        })
        .collect();

    Ok((signing_key, signing_cert, cert_chain))
}

fn extract_subject_cn(cert: &x509_certificate::X509Certificate) -> Option<String> {
    let subject = cert.subject_name();
    for atav in subject.iter_common_name() {
        if let Ok(value) = atav.to_string() {
            return Some(value);
        }
    }
    None
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
