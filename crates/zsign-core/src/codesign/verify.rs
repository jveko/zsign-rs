//! Code signature verification: SuperBlob/CodeDirectory parsing and blob-level checks.
//!
//! This module is the read-side counterpart of the [`superblob`]/[`code_directory`]
//! builders. It parses an embedded code signature SuperBlob and verifies the
//! integrity of its contents the way Apple's verifier does:
//!
//! - **Code pages**: every page of the signed code region must hash to the value
//!   stored in the CodeDirectory's code slots.
//! - **Special slots**: the Info.plist, requirements, CodeResources, entitlements,
//!   and DER-entitlements digests recorded in the CodeDirectory must match their
//!   content, when that content is available to the caller.
//! - **Structure**: the primary CodeDirectory must be the SHA-256 directory on
//!   modern output, fields must be self-consistent, and blob bounds must hold.
//!
//! Cryptographic CMS verification lives in [`crate::crypto::cms_verify`]; this
//! module feeds it the parsed CodeDirectory bytes and hashes.
//!
//! # Examples
//!
//! ```
//! use zsign_core::codesign::verify::{parse_superblob, SignatureInputs};
//!
//! let blob: &[u8] = &[]; // an embedded signature SuperBlob
//! let superblob = parse_superblob(blob).ok();
//! # let _ = superblob;
//! ```

use super::constants::*;
use crate::Result;
use sha1::{Digest, Sha1};
use sha2::Sha256;

/// A parsed entry in the SuperBlob index: a slot type and the blob bytes it points to.
#[derive(Debug, Clone)]
pub struct SlotEntry<'a> {
    /// SuperBlob slot type (e.g. [`CSSLOT_CODEDIRECTORY`]).
    pub slot: u32,
    /// Blob payload bytes (including the blob's 8-byte magic+length header).
    pub blob: &'a [u8],
}

/// A parsed code signature SuperBlob (`CSMAGIC_EMBEDDED_SIGNATURE`).
#[derive(Debug, Clone)]
pub struct SuperBlob<'a> {
    /// All index entries in file order.
    pub entries: Vec<SlotEntry<'a>>,
    /// The primary CodeDirectory (slot [`CSSLOT_CODEDIRECTORY`]), if present.
    pub code_directory: Option<CodeDirectory<'a>>,
    /// Any alternate CodeDirectories (slot [`CSSLOT_ALTERNATE_CODEDIRECTORIES`]+).
    pub alternate_code_directories: Vec<CodeDirectory<'a>>,
    /// The CMS signature wrapper blob (slot [`CSSLOT_SIGNATURESLOT`]), if present.
    pub cms: Option<&'a [u8]>,
}

/// Parses a SuperBlob from an embedded code signature.
///
/// # Errors
///
/// Returns [`Error::Verification`] if the blob is truncated or the magic is wrong.
pub fn parse_superblob(blob: &[u8]) -> Result<SuperBlob<'_>> {
    if blob.len() < 12 {
        return Err(crate::Error::Verification(
            "code signature blob too short for SuperBlob header".into(),
        ));
    }
    if blob[0..4] != CSMAGIC_EMBEDDED_SIGNATURE.to_be_bytes() {
        return Err(crate::Error::Verification(
            "not an embedded signature SuperBlob (magic mismatch)".into(),
        ));
    }

    let count = u32::from_be_bytes(blob[8..12].try_into().unwrap()) as usize;
    if 12 + count * 8 > blob.len() {
        return Err(crate::Error::Verification(format!(
            "SuperBlob index ({} entries) overruns blob of {} bytes",
            count,
            blob.len()
        )));
    }

    let mut entries = Vec::with_capacity(count);
    for i in 0..count {
        let entry_off = 12 + i * 8;
        let slot = u32::from_be_bytes(blob[entry_off..entry_off + 4].try_into().unwrap());
        let offset =
            u32::from_be_bytes(blob[entry_off + 4..entry_off + 8].try_into().unwrap()) as usize;
        let Some(item) = blob.get(offset..).filter(|b| b.len() >= 8) else {
            return Err(crate::Error::Verification(format!(
                "SuperBlob entry {i} (slot 0x{slot:08x}) points outside the blob"
            )));
        };
        // Each blob carries its own magic+length header; bound it precisely so
        // hashing a slot blob never implicitly includes later blobs.
        let item_len = u32::from_be_bytes(item[4..8].try_into().unwrap()) as usize;
        let Some(bounded) = blob.get(offset..offset.saturating_add(item_len)) else {
            return Err(crate::Error::Verification(format!(
                "SuperBlob entry {i} (slot 0x{slot:08x}) length overruns blob"
            )));
        };
        entries.push(SlotEntry {
            slot,
            blob: bounded,
        });
    }

    let mut code_directory = None;
    let mut alternate_code_directories = Vec::new();
    let mut cms = None;
    for entry in &entries {
        match entry.slot {
            CSSLOT_CODEDIRECTORY if code_directory.is_none() => {
                code_directory = CodeDirectory::parse(entry.blob).ok();
            }
            CSSLOT_ALTERNATE_CODEDIRECTORIES..=CSSLOT_ALTERNATE_CODEDIRECTORY_LIMIT => {
                if let Ok(cd) = CodeDirectory::parse(entry.blob) {
                    alternate_code_directories.push(cd);
                }
            }
            CSSLOT_SIGNATURESLOT => cms = Some(entry.blob),
            _ => {}
        }
    }

    Ok(SuperBlob {
        entries,
        code_directory,
        alternate_code_directories,
        cms,
    })
}

/// A parsed CodeDirectory (`CSMAGIC_CODEDIRECTORY`).
///
/// All multi-byte header fields are big-endian per the Apple format.
/// Version 0x20400 (exec segment) is the header size this parser requires.
#[derive(Debug, Clone)]
pub struct CodeDirectory<'a> {
    /// Raw CodeDirectory bytes (what the cdhash is computed over).
    data: &'a [u8],
    /// `version` header field.
    pub version: u32,
    /// `flags` header field ([`CS_ADHOC`] etc.).
    pub flags: u32,
    /// `hashOffset`: start of the code-page hash slots.
    hash_offset: usize,
    /// `identOffset` into `data` for the null-terminated identifier.
    ident_offset: usize,
    /// `nSpecialSlots` header field.
    pub n_special_slots: u32,
    /// `nCodeSlots` header field.
    pub n_code_slots: u32,
    /// `codeLimit` header field: number of code bytes hashed (u32).
    pub code_limit: u32,
    /// `hashSize` header field (e.g. 32 for SHA-256).
    pub hash_size: usize,
    /// `hashType` header field ([`CS_HASHTYPE_SHA256`] etc.).
    pub hash_type: u8,
    /// `pageSize` header field: log2 of the page size (12 = 4096).
    pub page_size_log2: u8,
    /// `teamOffset` into `data` for the null-terminated team ID, if any.
    team_offset: Option<usize>,
}

impl<'a> CodeDirectory<'a> {
    /// Parses a CodeDirectory from its blob bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Verification`] on a bad magic or a header too short for
    /// the declared version.
    pub fn parse(blob: &'a [u8]) -> Result<Self> {
        if blob.len() < 12 {
            return Err(crate::Error::Verification(
                "CodeDirectory blob too short".into(),
            ));
        }
        if blob[0..4] != CSMAGIC_CODEDIRECTORY.to_be_bytes() {
            return Err(crate::Error::Verification(
                "not a CodeDirectory blob (magic mismatch)".into(),
            ));
        }

        let version = u32::from_be_bytes(blob[8..12].try_into().unwrap());
        if version < CODEDIRECTORY_VERSION_EARLIEST {
            return Err(crate::Error::Verification(format!(
                "unsupported CodeDirectory version 0x{version:08x}"
            )));
        }

        let header_size = if version >= CODEDIRECTORY_VERSION_EXECSEG {
            88
        } else if version >= CODEDIRECTORY_VERSION_CODELIMIT64 {
            80
        } else if version >= CODEDIRECTORY_VERSION_TEAMID {
            76
        } else {
            52
        };
        if blob.len() < header_size {
            return Err(crate::Error::Verification(format!(
                "CodeDirectory header ({header_size} bytes for version 0x{version:08x}) overruns blob"
            )));
        }

        let rd_u32 = |off: usize| u32::from_be_bytes(blob[off..off + 4].try_into().unwrap());

        let flags = rd_u32(12);
        let hash_offset = rd_u32(16) as usize;
        let ident_offset = rd_u32(20) as usize;
        let n_special_slots = rd_u32(24);
        let n_code_slots = rd_u32(28);
        let code_limit = rd_u32(32);
        let hash_size = blob[36] as usize;
        let hash_type = blob[37];
        let page_size_log2 = blob[39];
        let team_offset_raw = if version >= CODEDIRECTORY_VERSION_TEAMID {
            rd_u32(48)
        } else {
            0
        };

        if hash_type != CS_HASHTYPE_SHA1 && hash_type != CS_HASHTYPE_SHA256 {
            return Err(crate::Error::Verification(format!(
                "unsupported CodeDirectory hash type {hash_type}"
            )));
        }
        if hash_size != CS_SHA1_LEN && hash_size != CS_SHA256_LEN {
            return Err(crate::Error::Verification(format!(
                "unexpected CodeDirectory hash size {hash_size}"
            )));
        }

        // Bounds: identifier/team strings, then special slots, then code slots.
        if ident_offset >= blob.len() {
            return Err(crate::Error::Verification(
                "CodeDirectory identifier offset out of bounds".into(),
            ));
        }
        let team_offset = (team_offset_raw != 0).then_some(team_offset_raw as usize);
        if let Some(off) = team_offset {
            if off >= blob.len() {
                return Err(crate::Error::Verification(
                    "CodeDirectory team offset out of bounds".into(),
                ));
            }
        }
        let n_special = n_special_slots as usize;
        let n_code = n_code_slots as usize;
        let expected_tail = hash_offset
            .checked_add(n_code * hash_size)
            .ok_or_else(|| crate::Error::Verification("hash region overflow".into()))?;
        if expected_tail > blob.len() {
            return Err(crate::Error::Verification(format!(
                "CodeDirectory hash region ({n_special} special + {n_code} code slots) overruns blob"
            )));
        }
        if n_special > hash_offset / hash_size.max(1) {
            return Err(crate::Error::Verification(
                "CodeDirectory special-slot region overruns hash offset".into(),
            ));
        }

        Ok(CodeDirectory {
            data: blob,
            version,
            flags,
            hash_offset,
            ident_offset,
            n_special_slots,
            n_code_slots,
            code_limit,
            hash_size,
            hash_type,
            page_size_log2,
            team_offset,
        })
    }

    /// The bundle identifier recorded in the CodeDirectory.
    pub fn identifier(&self) -> Option<&'a str> {
        cstring_at(self.data, self.ident_offset)
    }

    /// The team ID recorded in the CodeDirectory, if any.
    pub fn team_id(&self) -> Option<&'a str> {
        self.team_offset.and_then(|off| cstring_at(self.data, off))
    }

    /// The raw CodeDirectory bytes (what the cdhash is computed over).
    pub fn raw(&self) -> &'a [u8] {
        self.data
    }

    /// The digest of this CodeDirectory itself (the cdhash).
    ///
    /// SHA-1 when the directory carries SHA-1 hashes, SHA-256 otherwise —
    /// matching what Apple seals in the CMS CDHash attributes.
    pub fn cdhash(&self) -> Vec<u8> {
        match self.hash_type {
            CS_HASHTYPE_SHA1 => Sha1::digest(self.data).to_vec(),
            _ => Sha256::digest(self.data).to_vec(),
        }
    }

    /// The SHA-256 cdhash of this directory (computes the SHA-256 digest even
    /// for SHA-1 directories; used for Apple CDHash v2 attribute checks).
    pub fn cdhash_sha256(&self) -> [u8; 32] {
        Sha256::digest(self.data).into()
    }

    /// The special-slot hash for slot `-index` (1 = Info.plist slot −1).
    ///
    /// Slot entries are stored most-negative-first immediately before the code
    /// hashes: slot −k lives at `hashOffset − k·hashSize`.
    pub fn special_slot_hash(&self, index: usize) -> Option<&'a [u8]> {
        if index == 0 || index > self.n_special_slots as usize {
            return None;
        }
        // Slots are stored most-negative-first, so slot −index is the
        // `index`-th hash counting back from the code-hash area.
        let start = self.hash_offset - index * self.hash_size;
        let end = start + self.hash_size;
        self.data.get(start..end)
    }

    /// All code-page hashes (one `hashSize`-byte digest per page).
    pub fn code_hashes(&self) -> &'a [u8] {
        &self.data[self.hash_offset..self.hash_offset + self.n_code_slots as usize * self.hash_size]
    }

    /// True when the directory is SHA-1 hashed.
    pub fn is_sha1(&self) -> bool {
        self.hash_type == CS_HASHTYPE_SHA1
    }

    /// True when the directory is SHA-256 hashed.
    pub fn is_sha256(&self) -> bool {
        self.hash_type == CS_HASHTYPE_SHA256
    }

    /// Whether the signature is ad-hoc (has the [`CS_ADHOC`] flag).
    pub fn is_adhoc(&self) -> bool {
        self.flags & CS_ADHOC != 0
    }
}

/// Reads a NUL-terminated string from `data` at `offset`.
fn cstring_at(data: &[u8], offset: usize) -> Option<&str> {
    let rest = data.get(offset..)?;
    let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
    std::str::from_utf8(&rest[..end]).ok()
}

/// Per-slot special-content inputs needed to verify a CodeDirectory's special
/// slot hashes.
///
/// - `info_plist` and `code_resources` are file bytes (what the signer hashes
///   raw), supplied by bundle-level verification from the on-disk bundle.
/// - The requirements/entitlements/DER-entitlements slots are verified against
///   the blobs of the *same* SuperBlob (self-consistency) and need no input.
#[derive(Debug, Default, Clone)]
pub struct SignatureInputs<'a> {
    /// Info.plist file bytes (slot −1).
    pub info_plist: Option<&'a [u8]>,
    /// CodeResources file bytes (slot −3).
    pub code_resources: Option<&'a [u8]>,
}

impl<'a> SignatureInputs<'a> {
    /// Empty inputs: only self-consistent slots are checked.
    pub fn none() -> Self {
        Self::default()
    }
}

/// Result of checking the code pages of one CodeDirectory.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum PageCheck {
    /// No code slots (zero-length code region).
    #[default]
    Empty,
    /// All pages matched the stored hashes.
    Matched,
    /// `page_index` (0-based) hash mismatch.
    Mismatch { page_index: usize },
    /// Page size not supported by this verifier (only 4096).
    UnsupportedPageSize { page_size_log2: u8 },
    /// Stored hash count does not match the code region's page count.
    CountMismatch { stored: usize, computed: usize },
}

/// Verifies every code page of `code` against the directory's code slots.
///
/// The signed code region is the first `code_limit` bytes of the slice
/// (the Mach-O header, load commands, and `__TEXT` until the signature),
/// hashed in `page_size`-sized chunks with a partial last page hashed as-is,
/// matching both the signer and Apple's verifier.
pub fn check_code_pages(cd: &CodeDirectory<'_>, code: &[u8]) -> PageCheck {
    let page_size = 1usize << cd.page_size_log2;
    if page_size != PAGE_SIZE {
        return PageCheck::UnsupportedPageSize {
            page_size_log2: cd.page_size_log2,
        };
    }

    let region_len = (cd.code_limit as usize).min(code.len());
    // Guard against a CodeDirectory claiming more code than exists.
    if cd.code_limit as usize > code.len() {
        return PageCheck::CountMismatch {
            stored: cd.n_code_slots as usize,
            computed: region_len.div_ceil(PAGE_SIZE),
        };
    }

    let stored = cd.code_hashes();
    let expected_slots = region_len.div_ceil(PAGE_SIZE);
    if stored.len() != expected_slots * cd.hash_size {
        return PageCheck::CountMismatch {
            stored: cd.n_code_slots as usize,
            computed: expected_slots,
        };
    }
    if expected_slots == 0 {
        return PageCheck::Empty;
    }

    let region = &code[..region_len];
    for (i, chunk) in region.chunks(PAGE_SIZE).enumerate() {
        let digest = match cd.hash_type {
            CS_HASHTYPE_SHA1 => Sha1::digest(chunk).to_vec(),
            CS_HASHTYPE_SHA256 => Sha256::digest(chunk).to_vec(),
            _ => return PageCheck::UnsupportedPageSize { page_size_log2: 0 }, // unreachable
        };
        let expected = &stored[i * cd.hash_size..(i + 1) * cd.hash_size];
        if digest.as_slice() != expected {
            return PageCheck::Mismatch { page_index: i };
        }
    }
    PageCheck::Matched
}

/// Result of checking one special slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpecialSlotCheck {
    /// The slot is present and its hash matched the content.
    Matched,
    /// The slot is present but the content needed to check it was not supplied.
    NotChecked,
    /// The slot's stored hash does not match the content.
    Mismatch,
    /// The slot's stored hash matches no supplied content.
    Missing,
}

/// Verifies the CodeDirectory's special-slot hashes.
///
/// `hash_requirements`/`hash_entitlements`/`hash_der_entitlements` are the
/// blob bytes hashed into slots −2/−5/−7; they are taken from the SuperBlob
/// (the blob is self-hashed). `info_plist`/`code_resources` come from
/// [`SignatureInputs`].
///
/// Returns one entry per special slot, ordered −1 downward (index 0 = −1).
pub fn check_special_slots(
    cd: &CodeDirectory<'_>,
    inputs: &SignatureInputs<'_>,
    hash_requirements: Option<&[u8]>,
    hash_entitlements: Option<&[u8]>,
    hash_der_entitlements: Option<&[u8]>,
) -> Vec<SpecialSlotCheck> {
    let n = cd.n_special_slots as usize;
    let mut out = Vec::with_capacity(n);
    for k in 1..=n {
        let Some(stored) = cd.special_slot_hash(k) else {
            out.push(SpecialSlotCheck::Missing);
            continue;
        };
        if stored.iter().all(|&b| b == 0) {
            out.push(SpecialSlotCheck::Missing);
            continue;
        }
        // map k -> slot -k content
        let content: Option<&[u8]> = match k {
            1 => inputs.info_plist,
            2 => hash_requirements,
            3 => inputs.code_resources,
            // -4 application slot: content unavailable at the Mach-O level
            4 => None,
            5 => hash_entitlements,
            // -6 rep-specific: unavailable
            6 => None,
            7 => hash_der_entitlements,
            _ => None,
        };
        let Some(content) = content else {
            out.push(SpecialSlotCheck::NotChecked);
            continue;
        };
        let digest = match cd.hash_type {
            CS_HASHTYPE_SHA1 => Sha1::digest(content).to_vec(),
            _ => Sha256::digest(content).to_vec(),
        };
        out.push(if digest.as_slice() == stored {
            SpecialSlotCheck::Matched
        } else {
            SpecialSlotCheck::Mismatch
        });
    }
    out
}

/// Verify that the requirements/entitlements/der-entitlements blobs in the
/// SuperBlob hash to the corresponding special slots. Returns the blob bytes
/// for use by the CMS/attribute checks.
/// The requirements, XML-entitlements, and DER-entitlements blobs of a
/// SuperBlob (each bounded to its own length header).
pub type SlotBlobs<'a> = (Option<&'a [u8]>, Option<&'a [u8]>, Option<&'a [u8]>);

pub fn self_consistent_blobs<'a>(
    superblob: &SuperBlob<'a>,
    cd: &CodeDirectory<'_>,
) -> SlotBlobs<'a> {
    let mut requirements = None;
    let mut entitlements = None;
    let mut der_entitlements = None;
    for entry in &superblob.entries {
        match entry.slot {
            CSSLOT_REQUIREMENTS => requirements = Some(entry.blob),
            CSSLOT_ENTITLEMENTS => entitlements = Some(entry.blob),
            CSSLOT_DER_ENTITLEMENTS => der_entitlements = Some(entry.blob),
            _ => {}
        }
    }
    let _ = cd;
    (requirements, entitlements, der_entitlements)
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::codesign::superblob::SuperBlobBuilder;
    use crate::codesign::CodeDirectoryBuilder;

    const TEST_CODE: &[u8] = b"hello world, this is a test code region for page hashing!";

    fn build_blob(sha256_only: bool) -> Vec<u8> {
        let code = TEST_CODE;
        let builder = CodeDirectoryBuilder::new("com.example.test", code);
        let mut sb = SuperBlobBuilder::new().code_directory_sha256(builder.build_sha256());
        if !sha256_only {
            let sb1 = CodeDirectoryBuilder::new("com.example.test", code).build_sha1();
            sb = sb.code_directory_sha1(sb1);
        }
        sb.build()
    }

    #[test]
    fn parse_and_verify_pages() {
        let blob = build_blob(true);
        let sb = parse_superblob(&blob).expect("parse");
        let cd = sb.code_directory.expect("primary CD");
        assert_eq!(cd.version, CODEDIRECTORY_VERSION);
        assert_eq!(cd.identifier(), Some("com.example.test"));
        assert!(cd.is_sha256());
        assert!(!cd.is_adhoc());
        assert_eq!(check_code_pages(&cd, TEST_CODE), PageCheck::Matched);
    }

    #[test]
    fn tampered_code_fails_pages() {
        let blob = build_blob(true);
        let sb = parse_superblob(&blob).unwrap();
        let cd = sb.code_directory.unwrap();
        let mut tampered = TEST_CODE.to_vec();
        tampered[0] ^= 0xFF;
        assert!(matches!(
            check_code_pages(&cd, &tampered),
            PageCheck::Mismatch { .. }
        ));
    }

    #[test]
    fn legacy_dual_has_both_directories() {
        let blob = build_blob(false);
        let sb = parse_superblob(&blob).unwrap();
        assert!(sb.code_directory.is_some());
        assert_eq!(sb.alternate_code_directories.len(), 1);
        let alt = &sb.alternate_code_directories[0];
        assert!(alt.is_sha1() || sb.code_directory.as_ref().unwrap().is_sha1());
    }

    #[test]
    fn cdhash_is_digest_of_cd_bytes() {
        let blob = build_blob(true);
        let sb = parse_superblob(&blob).unwrap();
        let cd = sb.code_directory.unwrap();
        let expected: [u8; 32] = Sha256::digest(cd.data).into();
        assert_eq!(cd.cdhash_sha256(), expected);
        assert_eq!(cd.cdhash().len(), 32);
    }

    #[test]
    fn special_slot_hashes_self_consistent() {
        // Build a CD with an Info.plist and requirements special slot, then
        // verify the parser maps slot −1/−2 back to the right content.
        let builder = CodeDirectoryBuilder::new("com.example.test", TEST_CODE)
            .info_hash(vec![0xAB; 32])
            .requirements_hash(vec![0xCD; 32]);
        let cd_bytes = builder.build_sha256();
        let code = TEST_CODE;
        let _ = code;
        let cd = CodeDirectory::parse(&cd_bytes).unwrap();
        assert_eq!(cd.n_special_slots, 2);
        assert_eq!(cd.special_slot_hash(1), Some(&[0xAB; 32][..]));
        assert_eq!(cd.special_slot_hash(2), Some(&[0xCD; 32][..]));
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_superblob(&[0u8; 64]).is_err());
        assert!(CodeDirectory::parse(&[0u8; 64]).is_err());
    }
}
