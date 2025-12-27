//! Mach-O signing implementation
//!
//! This module provides the core signing functionality for Mach-O binaries,
//! building CodeDirectory structures with page hashes and assembling them
//! into a SuperBlob with all required signature components.
//!
//! Supports both single-architecture and FAT/Universal binaries by signing
//! each architecture slice independently.

use crate::codesign::code_directory::{
    compute_cdhash_sha1, compute_cdhash_sha256, CodeDirectoryBuilder,
};
use crate::codesign::superblob::{
    build_entitlements_blob, build_requirements_blob, build_signature_blob, SuperBlobBuilder,
};
use crate::crypto::cms;
use crate::Result;
use openssl::pkey::{PKeyRef, Private};
use openssl::x509::X509Ref;
use sha1::{Digest, Sha1};
use sha2::Sha256;

use super::parser::{ArchSlice, MachOFile};

/// Represents a signed architecture slice with its signature data.
#[derive(Debug, Clone)]
pub struct SignedSlice {
    /// Index of the slice in the original Mach-O file
    pub slice_index: usize,
    /// Offset of the slice in the original file
    pub offset: usize,
    /// Size of the original slice (before signature)
    pub original_size: usize,
    /// The SuperBlob signature data for this slice
    pub signature: Vec<u8>,
}

/// Sign a Mach-O binary and return the complete signature blob.
///
/// This function builds a complete code signature for a Mach-O binary, including:
/// - CodeDirectory with SHA-1 hashes (for legacy compatibility)
/// - CodeDirectory with SHA-256 hashes (required for iOS 12+)
/// - Requirements blob (minimal empty requirements if none provided)
/// - Entitlements blob (if provided)
/// - CMS signature with Apple CDHash attributes
///
/// For single-architecture binaries, returns a single signature blob.
/// For FAT/Universal binaries, returns the signature for the first slice only.
/// Use `sign_macho_all_slices` for FAT binaries to get signatures for all architectures.
///
/// # Arguments
///
/// * `macho` - The parsed Mach-O file to sign
/// * `identifier` - Bundle identifier (e.g., "com.example.app")
/// * `team_id` - Team identifier (None for ad-hoc signing)
/// * `entitlements` - Optional entitlements plist data (XML format)
/// * `cert` - X.509 signing certificate
/// * `pkey` - Private key corresponding to the certificate
/// * `info_plist` - Optional Info.plist data for hashing
/// * `code_resources` - Optional CodeResources data for hashing
///
/// # Returns
///
/// A `Vec<u8>` containing the complete SuperBlob signature data ready to be
/// embedded in the Mach-O binary.
///
/// # Errors
///
/// Returns an error if CMS signing fails.
pub fn sign_macho(
    macho: &MachOFile,
    identifier: &str,
    team_id: Option<&str>,
    entitlements: Option<&[u8]>,
    cert: &X509Ref,
    pkey: &PKeyRef<Private>,
    info_plist: Option<&[u8]>,
    code_resources: Option<&[u8]>,
) -> Result<Vec<u8>> {
    let slice = &macho.slices()[0];
    let code = macho.code_bytes(slice).to_vec();

    sign_slice(
        &code,
        slice,
        identifier,
        team_id,
        entitlements,
        cert,
        pkey,
        info_plist,
        code_resources,
    )
}

/// Sign all slices of a Mach-O binary (including FAT/Universal binaries).
///
/// For single-architecture binaries, returns a single `SignedSlice`.
/// For FAT/Universal binaries, returns a `SignedSlice` for each architecture.
///
/// # Arguments
///
/// * `macho` - The parsed Mach-O file to sign
/// * `identifier` - Bundle identifier (e.g., "com.example.app")
/// * `team_id` - Team identifier (None for ad-hoc signing)
/// * `entitlements` - Optional entitlements plist data (XML format)
/// * `cert` - X.509 signing certificate
/// * `pkey` - Private key corresponding to the certificate
/// * `info_plist` - Optional Info.plist data for hashing
/// * `code_resources` - Optional CodeResources data for hashing
///
/// # Returns
///
/// A `Vec<SignedSlice>` containing signature data for each architecture slice.
pub fn sign_macho_all_slices(
    macho: &MachOFile,
    identifier: &str,
    team_id: Option<&str>,
    entitlements: Option<&[u8]>,
    cert: &X509Ref,
    pkey: &PKeyRef<Private>,
    info_plist: Option<&[u8]>,
    code_resources: Option<&[u8]>,
) -> Result<Vec<SignedSlice>> {
    let mut signed_slices = Vec::with_capacity(macho.slices().len());

    for (index, slice) in macho.slices().iter().enumerate() {
        let code = macho.code_bytes(slice).to_vec();

        let signature = sign_slice(
            &code,
            slice,
            identifier,
            team_id,
            entitlements,
            cert,
            pkey,
            info_plist,
            code_resources,
        )?;

        signed_slices.push(SignedSlice {
            slice_index: index,
            offset: slice.offset,
            original_size: slice.size,
            signature,
        });
    }

    Ok(signed_slices)
}

/// Sign a single architecture slice and return its signature blob.
fn sign_slice(
    code: &[u8],
    slice: &ArchSlice,
    identifier: &str,
    team_id: Option<&str>,
    entitlements: Option<&[u8]>,
    cert: &X509Ref,
    pkey: &PKeyRef<Private>,
    info_plist: Option<&[u8]>,
    code_resources: Option<&[u8]>,
) -> Result<Vec<u8>> {
    // Build requirements blob
    let requirements = build_requirements_blob();
    let requirements_hash_sha1 = sha1_hash(&requirements);
    let requirements_hash_sha256 = sha256_hash(&requirements);

    // Build entitlements blob if provided
    let (entitlements_blob, ent_hash_sha1, ent_hash_sha256) =
        if let Some(ent) = entitlements {
            let blob = build_entitlements_blob(ent);
            (
                Some(blob.clone()),
                Some(sha1_hash(&blob)),
                Some(sha256_hash(&blob)),
            )
        } else {
            (None, None, None)
        };

    // Hash info.plist
    let (info_hash_sha1, info_hash_sha256) = if let Some(info) = info_plist {
        (Some(sha1_hash(info)), Some(sha256_hash(info)))
    } else {
        (None, None)
    };

    // Hash CodeResources
    let (res_hash_sha1, res_hash_sha256) = if let Some(res) = code_resources {
        (Some(sha1_hash(res)), Some(sha256_hash(res)))
    } else {
        (None, None)
    };

    // Build CodeDirectory (SHA-1)
    let cd_sha1 = build_code_directory(
        identifier,
        team_id,
        code,
        slice,
        &requirements_hash_sha1,
        &info_hash_sha1,
        &res_hash_sha1,
        &ent_hash_sha1,
        true, // is_sha1
    );

    // Build CodeDirectory (SHA-256)
    let cd_sha256 = build_code_directory(
        identifier,
        team_id,
        code,
        slice,
        &requirements_hash_sha256,
        &info_hash_sha256,
        &res_hash_sha256,
        &ent_hash_sha256,
        false, // is_sha1
    );

    // Hash CodeDirectories for CMS
    let cdhash_sha1: [u8; 20] = compute_cdhash_sha1(&cd_sha1);
    let cdhash_sha256: [u8; 32] = compute_cdhash_sha256(&cd_sha256);

    // Generate CMS signature
    let cms_data = cms::sign_with_apple_attrs(&cd_sha256, cert, pkey, &cdhash_sha1, &cdhash_sha256)?;

    let signature_blob = build_signature_blob(&cms_data);

    // Assemble SuperBlob using the builder
    let mut builder = SuperBlobBuilder::new()
        .code_directory_sha1(cd_sha1)
        .code_directory_sha256(cd_sha256)
        .requirements(requirements)
        .cms_signature(signature_blob);

    if let Some(ent_blob) = entitlements_blob {
        builder = builder.entitlements(ent_blob);
    }

    let superblob = builder.build();

    Ok(superblob)
}

/// Build a CodeDirectory blob with the specified hash type.
fn build_code_directory(
    identifier: &str,
    team_id: Option<&str>,
    code: &[u8],
    slice: &ArchSlice,
    requirements_hash: &[u8],
    info_hash: &Option<Vec<u8>>,
    resources_hash: &Option<Vec<u8>>,
    entitlements_hash: &Option<Vec<u8>>,
    is_sha1: bool,
) -> Vec<u8> {
    let mut builder = CodeDirectoryBuilder::new(identifier, code.to_vec())
        .requirements_hash(requirements_hash.to_vec())
        .exec_seg_limit(slice.text_segment_size)
        .is_executable(slice.is_executable);

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

    if is_sha1 {
        builder.build_sha1()
    } else {
        builder.build_sha256()
    }
}

/// Compute SHA-1 hash of data.
fn sha1_hash(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha1::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Compute SHA-256 hash of data.
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
