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

    // Calculate offsets for each blob
    let mut offsets = Vec::with_capacity(entries.len());
    let mut current_offset = header_size;

    for entry in &entries {
        offsets.push(current_offset);
        current_offset += entry.data.len() as u32;
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

    // Blob data
    for entry in entries {
        buf.extend(&entry.data);
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

        // Slot 0x0002: Requirements (use empty if not provided)
        let requirements = self.requirements.unwrap_or_else(build_requirements_blob);
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

        // Second entry offset = 36 + 50 = 86
        let offset2 = u32::from_be_bytes([blob[24], blob[25], blob[26], blob[27]]);
        assert_eq!(offset2, 86);

        // Third entry offset = 86 + 30 = 116
        let offset3 = u32::from_be_bytes([blob[32], blob[33], blob[34], blob[35]]);
        assert_eq!(offset3, 116);
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
}
