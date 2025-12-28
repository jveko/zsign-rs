//! SuperBlob assembly for Apple code signatures
//!
//! The SuperBlob is the top-level container for all code signature components.
//! It contains a header followed by an index of blob entries, each pointing
//! to embedded blobs (CodeDirectory, requirements, entitlements, CMS signature, etc.)
//!
//! ## Structure
//!
//! ```text
//! ┌────────────────────────────────────┐
//! │ SuperBlob Header (12 bytes)        │
//! │  - magic: 0xfade0cc0 (4 bytes)     │
//! │  - length: total size (4 bytes)    │
//! │  - count: number of blobs (4 bytes)│
//! ├────────────────────────────────────┤
//! │ Index Entry 0 (8 bytes)            │
//! │  - slot_type (4 bytes)             │
//! │  - offset (4 bytes)                │
//! ├────────────────────────────────────┤
//! │ Index Entry 1 (8 bytes)            │
//! │  - slot_type (4 bytes)             │
//! │  - offset (4 bytes)                │
//! ├────────────────────────────────────┤
//! │ ... more index entries             │
//! ├────────────────────────────────────┤
//! │ Blob 0 data                        │
//! ├────────────────────────────────────┤
//! │ Blob 1 data                        │
//! ├────────────────────────────────────┤
//! │ ... more blob data                 │
//! └────────────────────────────────────┘
//! ```
//!
//! ## Slot Types
//!
//! - `CSSLOT_CODEDIRECTORY` (0x0000): SHA-1 CodeDirectory
//! - `CSSLOT_REQUIREMENTS` (0x0002): Code requirements
//! - `CSSLOT_ENTITLEMENTS` (0x0005): XML entitlements
//! - `CSSLOT_DER_ENTITLEMENTS` (0x0007): DER entitlements
//! - `CSSLOT_ALTERNATE_CODEDIRECTORIES` (0x1000): SHA-256 CodeDirectory
//! - `CSSLOT_SIGNATURESLOT` (0x10000): CMS signature

use super::constants::*;

/// Size of the SuperBlob header in bytes (magic + length + count)
const SUPERBLOB_HEADER_SIZE: u32 = 12;

/// Size of each index entry in bytes (slot_type + offset)
const INDEX_ENTRY_SIZE: u32 = 8;

/// A blob entry for inclusion in a SuperBlob.
///
/// Each entry represents a component of the code signature,
/// identified by its slot type and containing the raw blob data.
#[derive(Debug, Clone)]
pub struct BlobEntry {
    /// The slot type identifying this blob's purpose.
    /// See `CSSLOT_*` constants for standard slot types.
    pub slot_type: u32,
    /// The raw blob data, including its own magic and length header.
    pub data: Vec<u8>,
}

impl BlobEntry {
    /// Create a new blob entry.
    ///
    /// # Arguments
    ///
    /// * `slot_type` - The slot type (e.g., `CSSLOT_CODEDIRECTORY`)
    /// * `data` - The raw blob data including magic and length header
    pub fn new(slot_type: u32, data: Vec<u8>) -> Self {
        Self { slot_type, data }
    }
}

/// Build a SuperBlob containing all signature components.
///
/// The SuperBlob is the top-level container for iOS/macOS code signatures.
/// It contains multiple embedded blobs, each identified by a slot type.
///
/// # Arguments
///
/// * `entries` - A vector of `BlobEntry` items to include in the SuperBlob
///
/// # Returns
///
/// A `Vec<u8>` containing the serialized SuperBlob with all embedded blobs.
///
/// # Example
///
/// ```ignore
/// use zsign::codesign::superblob::{build_superblob, BlobEntry};
/// use zsign::codesign::constants::*;
///
/// let entries = vec![
///     BlobEntry::new(CSSLOT_CODEDIRECTORY, code_directory_sha1),
///     BlobEntry::new(CSSLOT_REQUIREMENTS, requirements),
///     BlobEntry::new(CSSLOT_ENTITLEMENTS, entitlements),
///     BlobEntry::new(CSSLOT_ALTERNATE_CODEDIRECTORIES, code_directory_sha256),
///     BlobEntry::new(CSSLOT_SIGNATURESLOT, cms_signature),
/// ];
///
/// let superblob = build_superblob(entries);
/// ```
pub fn build_superblob(entries: Vec<BlobEntry>) -> Vec<u8> {
    let count = entries.len() as u32;

    // Header: magic(4) + length(4) + count(4) = 12 bytes
    // Index: count * (type(4) + offset(4)) = count * 8 bytes
    let header_size = SUPERBLOB_HEADER_SIZE + (count * INDEX_ENTRY_SIZE);

    // Calculate offsets for each blob with 4-byte alignment
    let mut offsets = Vec::with_capacity(entries.len());
    let mut current_offset = header_size;

    for entry in &entries {
        offsets.push(current_offset);
        current_offset += entry.data.len() as u32;
        
        // Pad to 4-byte alignment for next blob
        let remainder = current_offset % 4;
        if remainder != 0 {
            current_offset += 4 - remainder;
        }
    }

    let total_length = current_offset;

    // Build the SuperBlob
    let mut buf = Vec::with_capacity(total_length as usize);

    // Header (big-endian)
    buf.extend(&CSMAGIC_EMBEDDED_SIGNATURE.to_be_bytes());
    buf.extend(&total_length.to_be_bytes());
    buf.extend(&count.to_be_bytes());

    // Index entries
    for (i, entry) in entries.iter().enumerate() {
        buf.extend(&entry.slot_type.to_be_bytes());
        buf.extend(&offsets[i].to_be_bytes());
    }

    // Blob data with padding
    for (i, entry) in entries.iter().enumerate() {
        buf.extend(&entry.data);
        
        // Add padding to reach the next offset (or total length for last entry)
        let next_offset = if i + 1 < entries.len() {
            offsets[i + 1]
        } else {
            total_length
        };
        
        let current_pos = buf.len() as u32;
        if next_offset > current_pos {
            let padding = (next_offset - current_pos) as usize;
            buf.extend(std::iter::repeat(0u8).take(padding));
        }
    }

    buf
}

/// Build an entitlements blob from XML plist data.
///
/// Wraps the plist data with a standard blob header.
///
/// # Arguments
///
/// * `plist_data` - The XML plist entitlements data
///
/// # Returns
///
/// A `Vec<u8>` containing the entitlements blob with magic and length header.
pub fn build_entitlements_blob(plist_data: &[u8]) -> Vec<u8> {
    let total_len = 8 + plist_data.len() as u32;
    let mut buf = Vec::with_capacity(total_len as usize);

    buf.extend(&CSMAGIC_EMBEDDED_ENTITLEMENTS.to_be_bytes());
    buf.extend(&total_len.to_be_bytes());
    buf.extend(plist_data);

    buf
}

/// Build a DER entitlements blob.
///
/// Wraps the DER-encoded entitlements with a standard blob header.
///
/// # Arguments
///
/// * `der_data` - The DER-encoded entitlements data
///
/// # Returns
///
/// A `Vec<u8>` containing the DER entitlements blob with magic and length header.
pub fn build_der_entitlements_blob(der_data: &[u8]) -> Vec<u8> {
    let total_len = 8 + der_data.len() as u32;
    let mut buf = Vec::with_capacity(total_len as usize);

    buf.extend(&CSMAGIC_EMBEDDED_DER_ENTITLEMENTS.to_be_bytes());
    buf.extend(&total_len.to_be_bytes());
    buf.extend(der_data);

    buf
}

/// Pad a byte slice to 4-byte alignment.
///
/// Returns a new Vec with the original data padded with null bytes
/// to reach a 4-byte boundary.
fn pad_to_alignment(data: &[u8], alignment: usize) -> Vec<u8> {
    let mut padded = data.to_vec();
    let remainder = data.len() % alignment;
    if remainder != 0 {
        let padding_needed = alignment - remainder;
        padded.extend(std::iter::repeat(0u8).take(padding_needed));
    }
    padded
}

/// Build a minimal empty requirements blob.
///
/// This creates the simplest valid requirements blob with no requirements.
/// Used when no specific code signing requirements are needed.
///
/// # Returns
///
/// A `Vec<u8>` containing an empty requirements blob (12 bytes).
pub fn build_requirements_blob() -> Vec<u8> {
    // Minimal requirements: just a wrapper with count=0
    let mut buf = Vec::with_capacity(12);

    buf.extend(&CSMAGIC_REQUIREMENTS.to_be_bytes());
    buf.extend(&12u32.to_be_bytes()); // length = 12 (header only)
    buf.extend(&0u32.to_be_bytes()); // count = 0

    buf
}

/// Build a full requirements blob with bundle ID and certificate subject CN.
///
/// This generates a designated requirement expression matching the C++ zsign
/// implementation (SlotBuildRequirements in signing.cpp). The expression
/// validates:
/// 1. The bundle identifier matches
/// 2. The signing certificate subject CN matches
/// 3. The certificate chain is anchored to Apple
///
/// # Arguments
///
/// * `bundle_id` - The bundle identifier (e.g., "com.example.app")
/// * `subject_cn` - The certificate subject Common Name (e.g., "iPhone Distribution: ...")
///
/// # Returns
///
/// A `Vec<u8>` containing the complete requirements blob.
///
/// # Structure
///
/// The blob structure follows Apple's requirements format:
/// ```text
/// Requirements blob (0xfade0c01):
///   - magic (4) + length (4) + count (4) = 12 bytes header
///   - index entry: type (4) + offset (4) = 8 bytes
///
/// Embedded Requirement (0xfade0c00):
///   - Expression: identifier "bundle_id" and
///                 certificate leaf[subject.CN] = "subject_cn" and
///                 anchor apple generic (OID 1.2.840.113635.100.6.2.1)
/// ```
pub fn build_requirements_blob_full(bundle_id: &str, subject_cn: &str) -> Vec<u8> {
    // If either is empty, fall back to the empty requirements blob (like ldid)
    if bundle_id.is_empty() || subject_cn.is_empty() {
        return build_requirements_blob();
    }

    // Pad strings to 4-byte alignment
    let padded_bundle_id = pad_to_alignment(bundle_id.as_bytes(), 4);
    let padded_subject_cn = pad_to_alignment(subject_cn.as_bytes(), 4);

    // Fixed byte arrays matching C++ implementation
    // pack1: count=1, type=designated(3), offset=0x14
    let pack1: [u8; 12] = [
        0x00, 0x00, 0x00, 0x01, // count = 1
        0x00, 0x00, 0x00, 0x03, // type = designated requirement
        0x00, 0x00, 0x00, 0x14, // offset = 20 (header + index)
    ];

    // pack2: expression start - op_and(6), op_ident(2)
    let pack2: [u8; 12] = [
        0x00, 0x00, 0x00, 0x01, // expression version = 1
        0x00, 0x00, 0x00, 0x06, // op = OP_AND
        0x00, 0x00, 0x00, 0x02, // op = OP_IDENT (identifier check)
    ];

    // pack3: nested and with cert field check
    // op_and(6), op_apple_generic_anchor(15), op_and(6), op_cert_field(11),
    // cert_slot=0 (leaf), field_name "subject.CN", match_equal(1)
    let pack3: [u8; 40] = [
        0x00, 0x00, 0x00, 0x06, // op = OP_AND
        0x00, 0x00, 0x00, 0x0f, // op = OP_APPLE_GENERIC_ANCHOR
        0x00, 0x00, 0x00, 0x06, // op = OP_AND
        0x00, 0x00, 0x00, 0x0b, // op = OP_CERT_FIELD
        0x00, 0x00, 0x00, 0x00, // cert slot = 0 (leaf certificate)
        0x00, 0x00, 0x00, 0x0a, // field name length = 10
        0x73, 0x75, 0x62, 0x6a, // "subj"
        0x65, 0x63, 0x74, 0x2e, // "ect."
        0x43, 0x4e, 0x00, 0x00, // "CN" + 2 bytes padding
        0x00, 0x00, 0x00, 0x01, // match = MATCH_EQUAL
    ];

    // pack4: certificate generic OID for Apple anchor check
    // op_cert_generic(14), cert_slot=1 (intermediate), OID length=10,
    // OID: 1.2.840.113635.100.6.2.1 (Apple WWDR intermediate)
    let pack4: [u8; 28] = [
        0x00, 0x00, 0x00, 0x0e, // op = OP_CERT_GENERIC
        0x00, 0x00, 0x00, 0x01, // cert slot = 1 (intermediate)
        0x00, 0x00, 0x00, 0x0a, // OID length = 10
        0x2a, 0x86, 0x48, 0x86, // OID bytes: 1.2.840.113635.100.6.2.1
        0xf7, 0x63, 0x64, 0x06,
        0x02, 0x01, 0x00, 0x00, // + 2 bytes padding
        0x00, 0x00, 0x00, 0x00, // match = MATCH_EXISTS
    ];

    // Calculate inner requirement length (magic2 + length2 + pack2 + bundle_id + pack3 + subject_cn + pack4)
    let inner_length: u32 = 4 // magic
        + 4 // length
        + pack2.len() as u32
        + 4 // bundle ID length field
        + padded_bundle_id.len() as u32
        + pack3.len() as u32
        + 4 // subject CN length field
        + padded_subject_cn.len() as u32
        + pack4.len() as u32;

    // Calculate outer requirements length (magic1 + length1 + pack1 + inner_length)
    let outer_length: u32 = 4 // magic
        + 4 // length
        + pack1.len() as u32
        + inner_length;

    // Build the blob
    let mut buf = Vec::with_capacity(outer_length as usize);

    // Outer requirements blob header
    buf.extend(&CSMAGIC_REQUIREMENTS.to_be_bytes()); // 0xfade0c01
    buf.extend(&outer_length.to_be_bytes());
    buf.extend(&pack1);

    // Inner requirement blob header
    buf.extend(&CSMAGIC_REQUIREMENT.to_be_bytes()); // 0xfade0c00
    buf.extend(&inner_length.to_be_bytes());
    buf.extend(&pack2);

    // Bundle ID (length + padded string)
    buf.extend(&(bundle_id.len() as u32).to_be_bytes());
    buf.extend(&padded_bundle_id);

    // Certificate field check
    buf.extend(&pack3);

    // Subject CN (length + padded string)
    buf.extend(&(subject_cn.len() as u32).to_be_bytes());
    buf.extend(&padded_subject_cn);

    // Apple anchor OID check
    buf.extend(&pack4);

    buf
}

/// Build a CMS signature wrapper blob.
///
/// Wraps the CMS signature data with a standard blob header.
///
/// # Arguments
///
/// * `cms_data` - The DER-encoded CMS signature data
///
/// # Returns
///
/// A `Vec<u8>` containing the signature blob with magic and length header.
pub fn build_signature_blob(cms_data: &[u8]) -> Vec<u8> {
    let total_len = 8 + cms_data.len() as u32;
    let mut buf = Vec::with_capacity(total_len as usize);

    buf.extend(&CSMAGIC_BLOBWRAPPER.to_be_bytes());
    buf.extend(&total_len.to_be_bytes());
    buf.extend(cms_data);

    buf
}

/// Build an empty signature blob for ad-hoc signing.
///
/// Ad-hoc signed binaries don't have a CMS signature,
/// so this creates an empty wrapper blob.
///
/// # Returns
///
/// A `Vec<u8>` containing an empty signature blob (8 bytes, header only).
pub fn build_adhoc_signature_blob() -> Vec<u8> {
    let mut buf = Vec::with_capacity(8);

    buf.extend(&CSMAGIC_BLOBWRAPPER.to_be_bytes());
    buf.extend(&8u32.to_be_bytes()); // just header, no data

    buf
}

/// Builder for constructing SuperBlobs in a structured way.
///
/// This provides a more ergonomic API for building SuperBlobs
/// with the standard components for iOS code signing.
///
/// # Example
///
/// ```ignore
/// let superblob = SuperBlobBuilder::new()
///     .code_directory_sha1(cd_sha1)
///     .code_directory_sha256(cd_sha256)
///     .requirements(requirements)
///     .entitlements(entitlements_plist)
///     .cms_signature(cms_data)
///     .build();
/// ```
#[derive(Debug, Default)]
pub struct SuperBlobBuilder {
    /// SHA-1 CodeDirectory (slot 0x0000) - primary, CMS signs this
    code_directory_sha1: Option<Vec<u8>>,
    /// SHA-256 CodeDirectory (slot 0x1000) - alternate for iOS 11+
    code_directory_sha256: Option<Vec<u8>>,
    /// Requirements blob (slot 0x0002)
    requirements: Option<Vec<u8>>,
    /// XML entitlements blob (slot 0x0005)
    entitlements: Option<Vec<u8>>,
    /// DER entitlements blob (slot 0x0007)
    der_entitlements: Option<Vec<u8>>,
    /// CMS signature blob (slot 0x10000)
    cms_signature: Option<Vec<u8>>,
    /// Bundle identifier for requirements blob generation
    bundle_id: Option<String>,
    /// Certificate subject CN for requirements blob generation
    subject_cn: Option<String>,
}

impl SuperBlobBuilder {
    /// Create a new SuperBlobBuilder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the SHA-1 CodeDirectory blob.
    ///
    /// SHA-1 is the primary CodeDirectory in slot `CSSLOT_CODEDIRECTORY` (0x0000).
    /// The CMS signature signs this CodeDirectory.
    pub fn code_directory_sha1(mut self, cd: Vec<u8>) -> Self {
        self.code_directory_sha1 = Some(cd);
        self
    }

    /// Set the SHA-256 CodeDirectory blob.
    ///
    /// SHA-256 goes in the alternate slot `CSSLOT_ALTERNATE_CODEDIRECTORIES` (0x1000).
    /// This is used by iOS 11+ for verification.
    pub fn code_directory_sha256(mut self, cd: Vec<u8>) -> Self {
        self.code_directory_sha256 = Some(cd);
        self
    }

    /// Set the requirements blob.
    ///
    /// This goes in slot `CSSLOT_REQUIREMENTS` (0x0002).
    /// If not provided, an empty requirements blob will be generated.
    pub fn requirements(mut self, req: Vec<u8>) -> Self {
        self.requirements = Some(req);
        self
    }

    /// Set the XML entitlements blob.
    ///
    /// This goes in slot `CSSLOT_ENTITLEMENTS` (0x0005).
    pub fn entitlements(mut self, ent: Vec<u8>) -> Self {
        self.entitlements = Some(ent);
        self
    }

    /// Set the DER entitlements blob.
    ///
    /// This goes in slot `CSSLOT_DER_ENTITLEMENTS` (0x0007).
    pub fn der_entitlements(mut self, der_ent: Vec<u8>) -> Self {
        self.der_entitlements = Some(der_ent);
        self
    }

    /// Set the CMS signature blob.
    ///
    /// This goes in slot `CSSLOT_SIGNATURESLOT` (0x10000).
    /// If not provided for non-adhoc signing, the signature will be missing.
    pub fn cms_signature(mut self, sig: Vec<u8>) -> Self {
        self.cms_signature = Some(sig);
        self
    }

    /// Set the bundle identifier for requirements blob generation.
    ///
    /// When both `bundle_id` and `subject_cn` are provided, a full requirements
    /// blob will be generated that validates the bundle identifier and signing
    /// certificate, matching the C++ zsign implementation.
    ///
    /// If only `bundle_id` is set (without `subject_cn`), an empty requirements
    /// blob will be used instead.
    pub fn bundle_id(mut self, id: impl Into<String>) -> Self {
        self.bundle_id = Some(id.into());
        self
    }

    /// Set the certificate subject CN for requirements blob generation.
    ///
    /// When both `bundle_id` and `subject_cn` are provided, a full requirements
    /// blob will be generated that validates the bundle identifier and signing
    /// certificate, matching the C++ zsign implementation.
    ///
    /// If only `subject_cn` is set (without `bundle_id`), an empty requirements
    /// blob will be used instead.
    pub fn subject_cn(mut self, cn: impl Into<String>) -> Self {
        self.subject_cn = Some(cn.into());
        self
    }

    /// Build the SuperBlob with all configured components.
    ///
    /// Components are ordered by slot type (matching Apple codesign/zsign):
    /// 1. CodeDirectory SHA-1 (0x0000) - primary slot, CMS signs this
    /// 2. Requirements (0x0002)
    /// 3. Entitlements (0x0005) - if present
    /// 4. DER Entitlements (0x0007) - if present
    /// 5. CodeDirectory SHA-256 (0x1000) - alternate slot for iOS 11+
    /// 6. CMS Signature (0x10000) - if present
    ///
    /// # Returns
    ///
    /// A `Vec<u8>` containing the complete serialized SuperBlob.
    pub fn build(self) -> Vec<u8> {
        let mut entries = Vec::new();

        // Slot 0x0000: CodeDirectory SHA-1 (primary - CMS signs this one)
        if let Some(cd_sha1) = self.code_directory_sha1 {
            entries.push(BlobEntry::new(CSSLOT_CODEDIRECTORY, cd_sha1));
        }

        // Slot 0x0002: Requirements
        // Priority: explicit requirements > generated from bundle_id/subject_cn > empty
        let requirements = if let Some(req) = self.requirements {
            req
        } else if let (Some(bundle_id), Some(subject_cn)) = (&self.bundle_id, &self.subject_cn) {
            build_requirements_blob_full(bundle_id, subject_cn)
        } else {
            build_requirements_blob()
        };
        entries.push(BlobEntry::new(CSSLOT_REQUIREMENTS, requirements));

        // Slot 0x0005: Entitlements (optional)
        if let Some(ent) = self.entitlements {
            entries.push(BlobEntry::new(CSSLOT_ENTITLEMENTS, ent));
        }

        // Slot 0x0007: DER Entitlements (optional)
        if let Some(der_ent) = self.der_entitlements {
            entries.push(BlobEntry::new(CSSLOT_DER_ENTITLEMENTS, der_ent));
        }

        // Slot 0x1000: CodeDirectory SHA-256 (alternate for iOS 11+)
        if let Some(cd_sha256) = self.code_directory_sha256 {
            entries.push(BlobEntry::new(CSSLOT_ALTERNATE_CODEDIRECTORIES, cd_sha256));
        }

        // Slot 0x10000: CMS Signature (optional for adhoc)
        if let Some(sig) = self.cms_signature {
            entries.push(BlobEntry::new(CSSLOT_SIGNATURESLOT, sig));
        }

        build_superblob(entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_superblob_structure() {
        let entries = vec![
            BlobEntry::new(CSSLOT_CODEDIRECTORY, vec![0xab; 100]),
            BlobEntry::new(CSSLOT_REQUIREMENTS, vec![0xcd; 12]),
        ];

        let blob = build_superblob(entries);

        // Check magic
        assert_eq!(&blob[0..4], &CSMAGIC_EMBEDDED_SIGNATURE.to_be_bytes());

        // Check count
        assert_eq!(&blob[8..12], &2u32.to_be_bytes());

        // Verify total length
        // Header: 12 + Index: 2*8 = 28 + Data: 100+12 = 140
        let expected_len = 12 + 16 + 100 + 12;
        let actual_len = u32::from_be_bytes([blob[4], blob[5], blob[6], blob[7]]);
        assert_eq!(actual_len, expected_len);
    }

    #[test]
    fn test_superblob_offsets() {
        let entries = vec![
            BlobEntry::new(CSSLOT_CODEDIRECTORY, vec![0; 50]),
            BlobEntry::new(CSSLOT_REQUIREMENTS, vec![1; 30]),
            BlobEntry::new(CSSLOT_ENTITLEMENTS, vec![2; 20]),
        ];

        let blob = build_superblob(entries);

        // Header size: 12, Index entries: 3*8 = 24, so first blob starts at offset 36
        // First entry offset
        let offset1 = u32::from_be_bytes([blob[16], blob[17], blob[18], blob[19]]);
        assert_eq!(offset1, 36);

        // Second entry offset = 36 + 50 + 2 padding = 88 (4-byte aligned)
        let offset2 = u32::from_be_bytes([blob[24], blob[25], blob[26], blob[27]]);
        assert_eq!(offset2, 88);

        // Third entry offset = 88 + 30 + 2 padding = 120 (4-byte aligned)
        let offset3 = u32::from_be_bytes([blob[32], blob[33], blob[34], blob[35]]);
        assert_eq!(offset3, 120);
    }

    #[test]
    fn test_superblob_slot_types() {
        let entries = vec![
            BlobEntry::new(CSSLOT_CODEDIRECTORY, vec![0; 10]),
            BlobEntry::new(CSSLOT_ALTERNATE_CODEDIRECTORIES, vec![0; 10]),
            BlobEntry::new(CSSLOT_SIGNATURESLOT, vec![0; 10]),
        ];

        let blob = build_superblob(entries);

        // Check slot types in index
        let slot1 = u32::from_be_bytes([blob[12], blob[13], blob[14], blob[15]]);
        assert_eq!(slot1, CSSLOT_CODEDIRECTORY);

        let slot2 = u32::from_be_bytes([blob[20], blob[21], blob[22], blob[23]]);
        assert_eq!(slot2, CSSLOT_ALTERNATE_CODEDIRECTORIES);

        let slot3 = u32::from_be_bytes([blob[28], blob[29], blob[30], blob[31]]);
        assert_eq!(slot3, CSSLOT_SIGNATURESLOT);
    }

    #[test]
    fn test_requirements_blob() {
        let req = build_requirements_blob();

        // Check magic
        assert_eq!(&req[0..4], &CSMAGIC_REQUIREMENTS.to_be_bytes());

        // Check length
        assert_eq!(req.len(), 12);
        let len = u32::from_be_bytes([req[4], req[5], req[6], req[7]]);
        assert_eq!(len, 12);

        // Check count = 0
        let count = u32::from_be_bytes([req[8], req[9], req[10], req[11]]);
        assert_eq!(count, 0);
    }

    #[test]
    fn test_entitlements_blob() {
        let plist = b"<?xml version=\"1.0\"?><plist><dict></dict></plist>";
        let blob = build_entitlements_blob(plist);

        // Check magic
        assert_eq!(&blob[0..4], &CSMAGIC_EMBEDDED_ENTITLEMENTS.to_be_bytes());

        // Check length
        let len = u32::from_be_bytes([blob[4], blob[5], blob[6], blob[7]]);
        assert_eq!(len as usize, 8 + plist.len());

        // Check data starts at offset 8
        assert_eq!(&blob[8..], plist);
    }

    #[test]
    fn test_der_entitlements_blob() {
        let der = vec![0x30, 0x10, 0x06, 0x08]; // Example DER data
        let blob = build_der_entitlements_blob(&der);

        // Check magic
        assert_eq!(
            &blob[0..4],
            &CSMAGIC_EMBEDDED_DER_ENTITLEMENTS.to_be_bytes()
        );

        // Check length
        let len = u32::from_be_bytes([blob[4], blob[5], blob[6], blob[7]]);
        assert_eq!(len as usize, 8 + der.len());

        // Check data
        assert_eq!(&blob[8..], &der);
    }

    #[test]
    fn test_signature_blob() {
        let cms = vec![0x30, 0x82, 0x01, 0x00]; // Example CMS data
        let blob = build_signature_blob(&cms);

        // Check magic
        assert_eq!(&blob[0..4], &CSMAGIC_BLOBWRAPPER.to_be_bytes());

        // Check length
        let len = u32::from_be_bytes([blob[4], blob[5], blob[6], blob[7]]);
        assert_eq!(len as usize, 8 + cms.len());

        // Check data
        assert_eq!(&blob[8..], &cms);
    }

    #[test]
    fn test_adhoc_signature_blob() {
        let blob = build_adhoc_signature_blob();

        // Check magic
        assert_eq!(&blob[0..4], &CSMAGIC_BLOBWRAPPER.to_be_bytes());

        // Check length = 8 (header only)
        let len = u32::from_be_bytes([blob[4], blob[5], blob[6], blob[7]]);
        assert_eq!(len, 8);
        assert_eq!(blob.len(), 8);
    }

    #[test]
    fn test_superblob_builder() {
        let cd_sha1 = vec![0x11; 100];
        let cd_sha256 = vec![0x22; 150];
        let ent = build_entitlements_blob(b"<plist></plist>");
        let sig = build_signature_blob(&[0x30, 0x00]);

        let superblob = SuperBlobBuilder::new()
            .code_directory_sha1(cd_sha1)
            .code_directory_sha256(cd_sha256)
            .entitlements(ent)
            .cms_signature(sig)
            .build();

        // Check magic
        assert_eq!(
            &superblob[0..4],
            &CSMAGIC_EMBEDDED_SIGNATURE.to_be_bytes()
        );

        // Should have 5 entries: CD SHA-1, requirements, entitlements, CD SHA-256, signature
        let count = u32::from_be_bytes([superblob[8], superblob[9], superblob[10], superblob[11]]);
        assert_eq!(count, 5);
    }

    #[test]
    fn test_superblob_builder_minimal() {
        // Build with just SHA-256 CodeDirectory (minimum viable)
        let cd_sha256 = vec![0xaa; 80];

        let superblob = SuperBlobBuilder::new()
            .code_directory_sha256(cd_sha256)
            .build();

        // Should have 2 entries: requirements (auto-generated), CD SHA-256
        let count = u32::from_be_bytes([superblob[8], superblob[9], superblob[10], superblob[11]]);
        assert_eq!(count, 2);
    }

    #[test]
    fn test_superblob_builder_with_der_entitlements() {
        let cd_sha1 = vec![0x11; 100];
        let ent = build_entitlements_blob(b"<plist></plist>");
        let der_ent = build_der_entitlements_blob(&[0x30, 0x00]);

        let superblob = SuperBlobBuilder::new()
            .code_directory_sha1(cd_sha1)
            .entitlements(ent)
            .der_entitlements(der_ent)
            .build();

        // Should have 4 entries: CD SHA-1, requirements, entitlements, DER entitlements
        let count = u32::from_be_bytes([superblob[8], superblob[9], superblob[10], superblob[11]]);
        assert_eq!(count, 4);
    }

    #[test]
    fn test_superblob_empty_entries() {
        let superblob = build_superblob(vec![]);

        // Check magic
        assert_eq!(
            &superblob[0..4],
            &CSMAGIC_EMBEDDED_SIGNATURE.to_be_bytes()
        );

        // Check count = 0
        let count = u32::from_be_bytes([superblob[8], superblob[9], superblob[10], superblob[11]]);
        assert_eq!(count, 0);

        // Total length should be just the header
        let len = u32::from_be_bytes([superblob[4], superblob[5], superblob[6], superblob[7]]);
        assert_eq!(len, 12);
    }

    #[test]
    fn test_blob_entry_new() {
        let entry = BlobEntry::new(CSSLOT_CODEDIRECTORY, vec![1, 2, 3]);
        assert_eq!(entry.slot_type, CSSLOT_CODEDIRECTORY);
        assert_eq!(entry.data, vec![1, 2, 3]);
    }

    #[test]
    fn test_superblob_builder_slot_ordering() {
        // Verify slots are added in correct order regardless of method call order
        let cd_sha1 = vec![0x01; 10];
        let cd_sha256 = vec![0x02; 10];
        let ent = build_entitlements_blob(b"");
        let der_ent = build_der_entitlements_blob(&[]);
        let sig = build_signature_blob(&[]);

        let superblob = SuperBlobBuilder::new()
            .code_directory_sha256(cd_sha256) // SHA-256 → slot 0x1000 (alternate)
            .cms_signature(sig) // CMS → slot 0x10000
            .code_directory_sha1(cd_sha1) // SHA-1 → slot 0x0000 (primary)
            .der_entitlements(der_ent) // DER ent → slot 0x0007
            .entitlements(ent) // Ent → slot 0x0005
            .build();

        // Regardless of insertion order, slots should be ordered:
        // 0x0000 (SHA-1), 0x0002, 0x0005, 0x0007, 0x1000 (SHA-256), 0x10000
        let slot0 = u32::from_be_bytes([superblob[12], superblob[13], superblob[14], superblob[15]]);
        assert_eq!(slot0, CSSLOT_CODEDIRECTORY); // 0x0000

        let slot1 = u32::from_be_bytes([superblob[20], superblob[21], superblob[22], superblob[23]]);
        assert_eq!(slot1, CSSLOT_REQUIREMENTS); // 0x0002

        let slot2 = u32::from_be_bytes([superblob[28], superblob[29], superblob[30], superblob[31]]);
        assert_eq!(slot2, CSSLOT_ENTITLEMENTS); // 0x0005

        let slot3 = u32::from_be_bytes([superblob[36], superblob[37], superblob[38], superblob[39]]);
        assert_eq!(slot3, CSSLOT_DER_ENTITLEMENTS); // 0x0007

        let slot4 = u32::from_be_bytes([superblob[44], superblob[45], superblob[46], superblob[47]]);
        assert_eq!(slot4, CSSLOT_ALTERNATE_CODEDIRECTORIES); // 0x1000

        let slot5 = u32::from_be_bytes([superblob[52], superblob[53], superblob[54], superblob[55]]);
        assert_eq!(slot5, CSSLOT_SIGNATURESLOT); // 0x10000
    }

    #[test]
    fn test_pad_to_alignment() {
        // Already aligned (4 bytes)
        let data = b"test";
        let padded = pad_to_alignment(data, 4);
        assert_eq!(padded.len(), 4);
        assert_eq!(&padded, data);

        // Needs 1 byte padding (5 -> 8)
        let data = b"hello";
        let padded = pad_to_alignment(data, 4);
        assert_eq!(padded.len(), 8);
        assert_eq!(&padded[..5], data);
        assert_eq!(&padded[5..], &[0, 0, 0]);

        // Needs 2 bytes padding (6 -> 8)
        let data = b"foobar";
        let padded = pad_to_alignment(data, 4);
        assert_eq!(padded.len(), 8);
        assert_eq!(&padded[..6], data);
        assert_eq!(&padded[6..], &[0, 0]);

        // Empty stays empty
        let data = b"";
        let padded = pad_to_alignment(data, 4);
        assert_eq!(padded.len(), 0);
    }

    #[test]
    fn test_requirements_blob_full_empty_inputs() {
        // Empty bundle_id should fall back to empty requirements
        let blob = build_requirements_blob_full("", "iPhone Distribution: Test");
        assert_eq!(blob.len(), 12);
        assert_eq!(&blob[0..4], &CSMAGIC_REQUIREMENTS.to_be_bytes());

        // Empty subject_cn should fall back to empty requirements
        let blob = build_requirements_blob_full("com.example.app", "");
        assert_eq!(blob.len(), 12);

        // Both empty should fall back to empty requirements
        let blob = build_requirements_blob_full("", "");
        assert_eq!(blob.len(), 12);
    }

    #[test]
    fn test_requirements_blob_full_structure() {
        let bundle_id = "com.example.app";
        let subject_cn = "iPhone Distribution: Test Company";
        let blob = build_requirements_blob_full(bundle_id, subject_cn);

        // Check outer magic (requirements blob)
        assert_eq!(&blob[0..4], &CSMAGIC_REQUIREMENTS.to_be_bytes());

        // Check length matches blob size
        let outer_len = u32::from_be_bytes([blob[4], blob[5], blob[6], blob[7]]) as usize;
        assert_eq!(outer_len, blob.len());

        // Check count = 1
        let count = u32::from_be_bytes([blob[8], blob[9], blob[10], blob[11]]);
        assert_eq!(count, 1);

        // Check type = designated requirement (3)
        let req_type = u32::from_be_bytes([blob[12], blob[13], blob[14], blob[15]]);
        assert_eq!(req_type, CSREQ_DESIGNATED);

        // Check inner offset = 20 (0x14)
        let offset = u32::from_be_bytes([blob[16], blob[17], blob[18], blob[19]]);
        assert_eq!(offset, 0x14);

        // Check inner magic (single requirement)
        assert_eq!(&blob[20..24], &CSMAGIC_REQUIREMENT.to_be_bytes());

        // Verify bundle ID is embedded
        let bundle_id_bytes = bundle_id.as_bytes();
        assert!(blob
            .windows(bundle_id_bytes.len())
            .any(|w| w == bundle_id_bytes));

        // Verify subject CN is embedded
        let subject_cn_bytes = subject_cn.as_bytes();
        assert!(blob
            .windows(subject_cn_bytes.len())
            .any(|w| w == subject_cn_bytes));

        // Verify "subject.CN" field name is in the blob
        let field_name = b"subject.CN";
        assert!(blob.windows(field_name.len()).any(|w| w == field_name));
    }

    #[test]
    fn test_requirements_blob_full_alignment() {
        // Test with bundle_id that needs padding (7 bytes -> 8)
        let bundle_id = "com.abc";
        let subject_cn = "Test";
        let blob = build_requirements_blob_full(bundle_id, subject_cn);

        // Verify the blob is well-formed (outer length matches)
        let outer_len = u32::from_be_bytes([blob[4], blob[5], blob[6], blob[7]]) as usize;
        assert_eq!(outer_len, blob.len());

        // Test with bundle_id that's already aligned (8 bytes)
        let bundle_id = "com.abcd";
        let blob = build_requirements_blob_full(bundle_id, subject_cn);
        let outer_len = u32::from_be_bytes([blob[4], blob[5], blob[6], blob[7]]) as usize;
        assert_eq!(outer_len, blob.len());
    }

    #[test]
    fn test_superblob_builder_with_bundle_id_and_subject_cn() {
        let cd_sha1 = vec![0x11; 100];

        let superblob = SuperBlobBuilder::new()
            .code_directory_sha1(cd_sha1)
            .bundle_id("com.example.app")
            .subject_cn("iPhone Distribution: Test")
            .build();

        // Check magic
        assert_eq!(
            &superblob[0..4],
            &CSMAGIC_EMBEDDED_SIGNATURE.to_be_bytes()
        );

        // Should have 2 entries: CD SHA-1, requirements
        let count = u32::from_be_bytes([superblob[8], superblob[9], superblob[10], superblob[11]]);
        assert_eq!(count, 2);

        // The requirements blob should be larger than 12 bytes (not the empty one)
        // Find the requirements offset and check its size
        let req_offset =
            u32::from_be_bytes([superblob[24], superblob[25], superblob[26], superblob[27]])
                as usize;
        let req_magic = u32::from_be_bytes([
            superblob[req_offset],
            superblob[req_offset + 1],
            superblob[req_offset + 2],
            superblob[req_offset + 3],
        ]);
        assert_eq!(req_magic, CSMAGIC_REQUIREMENTS);

        let req_len = u32::from_be_bytes([
            superblob[req_offset + 4],
            superblob[req_offset + 5],
            superblob[req_offset + 6],
            superblob[req_offset + 7],
        ]);
        // Full requirements should be > 12 bytes
        assert!(req_len > 12);
    }

    #[test]
    fn test_superblob_builder_explicit_requirements_takes_precedence() {
        let cd_sha1 = vec![0x11; 100];
        let explicit_req = build_requirements_blob(); // Empty requirements (12 bytes)

        let superblob = SuperBlobBuilder::new()
            .code_directory_sha1(cd_sha1)
            .bundle_id("com.example.app")
            .subject_cn("iPhone Distribution: Test")
            .requirements(explicit_req.clone()) // Explicit takes precedence
            .build();

        // Find the requirements offset
        let req_offset =
            u32::from_be_bytes([superblob[24], superblob[25], superblob[26], superblob[27]])
                as usize;
        let req_len = u32::from_be_bytes([
            superblob[req_offset + 4],
            superblob[req_offset + 5],
            superblob[req_offset + 6],
            superblob[req_offset + 7],
        ]);
        // Explicit empty requirements should be 12 bytes (not full requirements)
        assert_eq!(req_len, 12);
    }

    #[test]
    fn test_superblob_builder_missing_subject_cn_uses_empty_requirements() {
        let cd_sha1 = vec![0x11; 100];

        // Only bundle_id, no subject_cn
        let superblob = SuperBlobBuilder::new()
            .code_directory_sha1(cd_sha1)
            .bundle_id("com.example.app")
            .build();

        // Find the requirements offset
        let req_offset =
            u32::from_be_bytes([superblob[24], superblob[25], superblob[26], superblob[27]])
                as usize;
        let req_len = u32::from_be_bytes([
            superblob[req_offset + 4],
            superblob[req_offset + 5],
            superblob[req_offset + 6],
            superblob[req_offset + 7],
        ]);
        // Should fall back to empty requirements (12 bytes)
        assert_eq!(req_len, 12);
    }

    #[test]
    fn test_superblob_4byte_alignment() {
        // Create blobs with odd sizes to test alignment
        let entries = vec![
            BlobEntry::new(CSSLOT_CODEDIRECTORY, vec![0xab; 101]),  // 101 bytes (odd)
            BlobEntry::new(CSSLOT_REQUIREMENTS, vec![0xcd; 13]),     // 13 bytes (odd)
            BlobEntry::new(CSSLOT_ENTITLEMENTS, vec![0xef; 50]),     // 50 bytes (even but not aligned)
        ];

        let blob = build_superblob(entries);

        // Header: 12 bytes, Index: 3*8 = 24 bytes, total header = 36 bytes
        // Offset of first blob = 36 (aligned)
        // Offset of second blob = 36 + 101 + padding = 36 + 104 = 140 (must be 4-byte aligned)
        // Offset of third blob = 140 + 13 + padding = 140 + 16 = 156 (must be 4-byte aligned)
        
        // Check second entry offset is 4-byte aligned
        let offset2 = u32::from_be_bytes([blob[24], blob[25], blob[26], blob[27]]);
        assert_eq!(offset2 % 4, 0, "Second blob offset {} not 4-byte aligned", offset2);

        // Check third entry offset is 4-byte aligned  
        let offset3 = u32::from_be_bytes([blob[32], blob[33], blob[34], blob[35]]);
        assert_eq!(offset3 % 4, 0, "Third blob offset {} not 4-byte aligned", offset3);
    }

    #[test]
    fn test_superblob_alignment_padding_bytes() {
        // Verify padding bytes are zeros
        let entries = vec![
            BlobEntry::new(CSSLOT_CODEDIRECTORY, vec![0xAB; 5]),  // 5 bytes, needs 3 padding
            BlobEntry::new(CSSLOT_REQUIREMENTS, vec![0xCD; 4]),   // 4 bytes, aligned
        ];

        let blob = build_superblob(entries);
        
        // Header: 12 + 2*8 = 28 bytes
        // First blob at 28, length 5
        // Padding: 3 bytes at offsets 33, 34, 35
        // Second blob at 36
        
        // Check padding bytes are zero
        assert_eq!(blob[33], 0x00, "Padding byte 1 should be zero");
        assert_eq!(blob[34], 0x00, "Padding byte 2 should be zero");
        assert_eq!(blob[35], 0x00, "Padding byte 3 should be zero");
        
        // Check second blob starts correctly
        assert_eq!(blob[36], 0xCD, "Second blob data should start at aligned offset");
    }
}
