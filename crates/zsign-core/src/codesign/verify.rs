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

fn expected_magic(slot: u32) -> Option<u32> {
    Some(match slot {
        CSSLOT_CODEDIRECTORY
        | CSSLOT_ALTERNATE_CODEDIRECTORIES..=CSSLOT_ALTERNATE_CODEDIRECTORY_LIMIT => {
            CSMAGIC_CODEDIRECTORY
        }
        CSSLOT_SIGNATURESLOT => CSMAGIC_BLOBWRAPPER,
        CSSLOT_REQUIREMENTS => CSMAGIC_REQUIREMENTS,
        CSSLOT_ENTITLEMENTS => CSMAGIC_EMBEDDED_ENTITLEMENTS,
        CSSLOT_DER_ENTITLEMENTS => CSMAGIC_EMBEDDED_DER_ENTITLEMENTS,
        _ => return None,
    })
}

/// A parsed entry in the SuperBlob index: a slot type and the blob bytes it points to.
#[derive(Debug, Clone)]
pub struct SlotEntry<'a> {
    /// SuperBlob slot type (e.g. [`CSSLOT_CODEDIRECTORY`]).
    pub slot: u32,
    /// Blob payload bytes (including the blob's 8-byte magic+length header).
    pub blob: &'a [u8],
}

impl<'a> SlotEntry<'a> {
    /// The child's payload: its declared bytes AFTER the 8-byte magic+length
    /// header. Semantic parsers (plist, DER) need this; the special-slot
    /// hashes cover the FULL blob including the header.
    pub fn payload(&self) -> &'a [u8] {
        &self.blob[8..]
    }
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
/// Returns [`Error::Verification`] if the blob is truncated, the magic is wrong,
/// the declared length or index extent is invalid, or any child is shorter than
/// eight bytes, aliases the header/index, lies out of bounds, or overlaps another
/// child.
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

    // The declared total length bounds every subsequent read; trailing bytes
    // in the LC window beyond it are tolerated (own writer reserves the LC
    // window larger than the SuperBlob) but never parsed. `count` is read
    // from blob[8..12], safe because blob.len() >= 12 was checked above;
    // index_end >= 12 then rejects any declared length below the header
    // *before* slicing, so `&blob[..declared]` can never panic.
    let declared = u32::from_be_bytes(blob[4..8].try_into().unwrap()) as usize;
    if declared > blob.len() {
        return Err(crate::Error::Verification(format!(
            "SuperBlob declared length ({declared}) overruns blob of {} bytes",
            blob.len()
        )));
    }
    let count = u32::from_be_bytes(blob[8..12].try_into().unwrap()) as usize;
    let index_end = count
        .checked_mul(8)
        .and_then(|e| e.checked_add(12))
        .ok_or_else(|| crate::Error::Verification("SuperBlob index extent overflow".into()))?;
    if index_end > declared {
        return Err(crate::Error::Verification(format!(
            "SuperBlob index ({count} entries) overruns declared length of {declared} bytes"
        )));
    }
    let sb = &blob[..declared];

    let mut entries = Vec::with_capacity(count.min(declared / 8));
    let mut ranges: Vec<(usize, usize)> = Vec::with_capacity(count.min(declared / 8));
    let mut seen: std::collections::HashSet<u32> = std::collections::HashSet::new();
    for i in 0..count {
        let entry_off = 12 + i * 8;
        let slot = u32::from_be_bytes(sb[entry_off..entry_off + 4].try_into().unwrap());
        let offset =
            u32::from_be_bytes(sb[entry_off + 4..entry_off + 8].try_into().unwrap()) as usize;
        if offset < index_end {
            return Err(crate::Error::Verification(format!(
                "SuperBlob entry {i} (slot 0x{slot:08x}) points inside the header/index"
            )));
        }
        let Some(item) = sb.get(offset..).filter(|b| b.len() >= 8) else {
            return Err(crate::Error::Verification(format!(
                "SuperBlob entry {i} (slot 0x{slot:08x}) points outside the blob"
            )));
        };
        // Each blob carries its own magic+length header; bound it precisely so
        // hashing a slot blob never implicitly includes later blobs.
        let item_len = u32::from_be_bytes(item[4..8].try_into().unwrap()) as usize;
        if item_len < 8 {
            return Err(crate::Error::Verification(format!(
                "SuperBlob entry {i} (slot 0x{slot:08x}) declares a {item_len}-byte blob"
            )));
        }
        let end = offset
            .checked_add(item_len)
            .filter(|end| *end <= declared)
            .ok_or_else(|| {
                crate::Error::Verification(format!(
                    "SuperBlob entry {i} (slot 0x{slot:08x}) length overruns blob"
                ))
            })?;
        if let Some(want) = expected_magic(slot) {
            let magic = u32::from_be_bytes(item[0..4].try_into().unwrap());
            if magic != want {
                return Err(crate::Error::Verification(format!(
                    "SuperBlob entry {i} (slot 0x{slot:08x}): blob magic 0x{magic:08x}, expected 0x{want:08x}"
                )));
            }
            if !seen.insert(slot) {
                return Err(crate::Error::Verification(format!(
                    "duplicate SuperBlob slot 0x{slot:08x}"
                )));
            }
        }
        ranges.push((offset, end));
        entries.push(SlotEntry {
            slot,
            blob: &sb[offset..end],
        });
    }

    // Children must be pairwise disjoint (duplicates overlap identically).
    ranges.sort_unstable();
    for pair in ranges.windows(2) {
        if pair[1].0 < pair[0].1 {
            return Err(crate::Error::Verification(format!(
                "SuperBlob entries at {} and {} overlap",
                pair[0].0, pair[1].0
            )));
        }
    }

    let mut code_directory = None;
    let mut alternate_code_directories = Vec::new();
    let mut cms = None;
    for entry in &entries {
        match entry.slot {
            CSSLOT_CODEDIRECTORY if code_directory.is_none() => {
                code_directory = Some(CodeDirectory::parse(entry.blob).map_err(|e| {
                    crate::Error::Verification(format!("primary CodeDirectory: {e}"))
                })?);
            }
            CSSLOT_ALTERNATE_CODEDIRECTORIES..=CSSLOT_ALTERNATE_CODEDIRECTORY_LIMIT => {
                let cd = CodeDirectory::parse(entry.blob).map_err(|e| {
                    crate::Error::Verification(format!(
                        "alternate CodeDirectory (slot 0x{:08x}): {e}",
                        entry.slot
                    ))
                })?;
                alternate_code_directories.push(cd);
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
    /// `execSegBase` header field (version >= 0x20400); 0 when unset/older.
    pub exec_seg_base: u64,
    /// `execSegLimit` header field (version >= 0x20400); 0 when unset/older.
    pub exec_seg_limit: u64,
    /// `execSegFlags` header field (version >= 0x20400); 0 when unset/older.
    pub exec_seg_flags: u64,
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
        let declared = u32::from_be_bytes(blob[4..8].try_into().unwrap()) as usize;
        if declared < 12 || declared > blob.len() {
            return Err(crate::Error::Verification(format!(
                "CodeDirectory declared length ({declared}) is invalid for blob of {} bytes",
                blob.len()
            )));
        }
        let data = &blob[..declared];
        if data[0..4] != CSMAGIC_CODEDIRECTORY.to_be_bytes() {
            return Err(crate::Error::Verification(
                "not a CodeDirectory blob (magic mismatch)".into(),
            ));
        }

        let version = u32::from_be_bytes(data[8..12].try_into().unwrap());
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
        if data.len() < header_size {
            return Err(crate::Error::Verification(format!(
                "CodeDirectory header ({header_size} bytes for version 0x{version:08x}) overruns blob"
            )));
        }

        let rd_u32 = |off: usize| u32::from_be_bytes(data[off..off + 4].try_into().unwrap());
        let rd_u64 = |off: usize| u64::from_be_bytes(data[off..off + 8].try_into().unwrap());

        let flags = rd_u32(12);
        let hash_offset = rd_u32(16) as usize;
        let ident_offset = rd_u32(20) as usize;
        let n_special_slots = rd_u32(24);
        let n_code_slots = rd_u32(28);
        let code_limit = rd_u32(32);
        let hash_size = data[36] as usize;
        let hash_type = data[37];
        let page_size_log2 = data[39];
        let team_offset_raw = if version >= CODEDIRECTORY_VERSION_TEAMID {
            rd_u32(48)
        } else {
            0
        };
        let (exec_seg_base, exec_seg_limit, exec_seg_flags) =
            if version >= CODEDIRECTORY_VERSION_EXECSEG {
                (rd_u64(64), rd_u64(72), rd_u64(80))
            } else {
                (0, 0, 0)
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
        if ident_offset >= data.len() {
            return Err(crate::Error::Verification(
                "CodeDirectory identifier offset out of bounds".into(),
            ));
        }
        let team_offset = (team_offset_raw != 0).then_some(team_offset_raw as usize);
        if let Some(off) = team_offset {
            if off >= data.len() {
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
        if expected_tail > data.len() {
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
            data,
            version,
            flags,
            exec_seg_base,
            exec_seg_limit,
            exec_seg_flags,
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
    // Page size comes from the CodeDirectory (log2): 4096 on iOS, 16384 on
    // modern macOS system binaries.
    let page_size = 1usize << cd.page_size_log2;

    let region_len = (cd.code_limit as usize).min(code.len());
    // Guard against a CodeDirectory claiming more code than exists.
    if cd.code_limit as usize > code.len() {
        return PageCheck::CountMismatch {
            stored: cd.n_code_slots as usize,
            computed: region_len.div_ceil(page_size),
        };
    }

    let stored = cd.code_hashes();
    let expected_slots = region_len.div_ceil(page_size);
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
    for (i, chunk) in region.chunks(page_size).enumerate() {
        let digest = match cd.hash_type {
            CS_HASHTYPE_SHA1 => Sha1::digest(chunk).to_vec(),
            CS_HASHTYPE_SHA256 => Sha256::digest(chunk).to_vec(),
            _ => {
                return PageCheck::CountMismatch {
                    stored: 0,
                    computed: 0,
                }
            } // unreachable
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

/// Verifies the CodeDirectory's special-slot hashes against caller inputs and
/// SuperBlob children.
///
/// Returns one entry per special slot, ordered −1 downward (index 0 = −1).
pub fn check_special_slots(
    cd: &CodeDirectory<'_>,
    inputs: &SignatureInputs<'_>,
    superblob: &SuperBlob<'_>,
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
        let slot_child = |slot: u32| {
            superblob
                .entries
                .iter()
                .find(|e| e.slot == slot)
                .map(|e| e.blob)
        };
        let content: Option<&[u8]> = match k {
            1 => inputs.info_plist,
            3 => inputs.code_resources,
            2 => slot_child(CSSLOT_REQUIREMENTS),
            5 => slot_child(CSSLOT_ENTITLEMENTS),
            7 => slot_child(CSSLOT_DER_ENTITLEMENTS),
            8 => slot_child(CSSLOT_LAUNCH_CONSTRAINT_SELF),
            9 => slot_child(CSSLOT_LAUNCH_CONSTRAINT_PARENT),
            10 => slot_child(CSSLOT_LAUNCH_CONSTRAINT_RESPONSIBLE),
            11 => slot_child(CSSLOT_LIBRARY_CONSTRAINT),
            4 | 6 => None,
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

const DER_ENTRIES_CONTAINERS: [u8; 5] = [0xb0, 0x31, 0x30, 0x60, 0xa0];

fn der_error(message: impl Into<String>) -> crate::Error {
    crate::Error::DerEncoding(message.into())
}

fn read_der_tlv(bytes: &[u8]) -> Result<(u8, &[u8], &[u8])> {
    if bytes.len() < 2 {
        return Err(der_error("truncated DER tag or length"));
    }
    let tag = bytes[0];
    let first = bytes[1];
    let (content_len, content_start) = if first < 0x80 {
        (first as usize, 2)
    } else {
        let count = (first & 0x7f) as usize;
        if count == 0 {
            return Err(der_error("indefinite DER lengths are not supported"));
        }
        if count > std::mem::size_of::<usize>() {
            return Err(der_error("DER length is too large"));
        }
        let length_end = 2usize
            .checked_add(count)
            .ok_or_else(|| der_error("DER length extent overflow"))?;
        let length_bytes = bytes
            .get(2..length_end)
            .ok_or_else(|| der_error("truncated DER long-form length"))?;
        let mut content_len = 0usize;
        for &byte in length_bytes {
            content_len = (content_len << 8) | byte as usize;
        }
        (content_len, length_end)
    };
    let end = content_start
        .checked_add(content_len)
        .ok_or_else(|| der_error("DER value extent overflow"))?;
    let content = bytes
        .get(content_start..end)
        .ok_or_else(|| der_error("DER value length overruns input"))?;
    Ok((tag, content, bytes.get(end..).unwrap_or_default()))
}

fn der_integer(content: &[u8]) -> Result<plist::Value> {
    let (&first, prefix) = content
        .split_first()
        .ok_or_else(|| der_error("empty DER INTEGER"))?;
    let negative = first & 0x80 != 0;
    let significant = if negative {
        prefix.iter().skip_while(|&&byte| byte == 0xff).count()
    } else {
        prefix.iter().skip_while(|&&byte| byte == 0x00).count()
    };
    if prefix.len() - significant > 1 || content.len() > 8 {
        return Err(der_error("non-minimal or oversized DER INTEGER"));
    }
    let mut value = if negative {
        -1i128 << (8 * content.len())
    } else {
        0
    };
    for &byte in content {
        value = (value << 8) | byte as i128;
    }
    let value = i64::try_from(value).map_err(|_| der_error("DER INTEGER does not fit i64"))?;
    Ok(plist::Value::Integer(value.into()))
}

fn der_string(tag: u8, content: &[u8]) -> Result<plist::Value> {
    let string = match tag {
        0x0c => std::str::from_utf8(content)
            .map_err(|_| der_error("invalid DER UTF8String"))?
            .to_owned(),
        0x16 => {
            if !content.is_ascii() {
                return Err(der_error("invalid DER IA5String"));
            }
            // SAFETY: `is_ascii` proves every byte is below 0x80.
            unsafe { std::str::from_utf8_unchecked(content) }.to_owned()
        }
        0x1e => {
            if content.len() % 2 != 0 {
                return Err(der_error("invalid DER BMPString length"));
            }
            let units = content
                .chunks_exact(2)
                .map(|pair| u16::from_be_bytes([pair[0], pair[1]]));
            let utf16 = units.collect::<Vec<_>>();
            String::from_utf16(&utf16)
                .map_err(|_| der_error("invalid DER BMPString surrogate pair"))?
        }
        _ => return Err(der_error(format!("unsupported DER string tag 0x{tag:02x}"))),
    };
    Ok(plist::Value::String(string))
}

fn der_time(tag: u8, content: &[u8]) -> Result<plist::Value> {
    let text = std::str::from_utf8(content).map_err(|_| der_error("invalid DER time encoding"))?;
    let digits = text
        .strip_suffix('Z')
        .ok_or_else(|| der_error("DER time must use UTC 'Z' offset"))?;
    let (fraction, digits) = match digits.find(['.', ',']) {
        Some(index) => (digits[index..].replace(',', "."), &digits[..index]),
        None => (String::new(), digits),
    };
    let expected = match tag {
        0x17 => 12,
        0x18 => 14,
        _ => return Err(der_error("invalid DER time tag")),
    };
    if digits.len() != expected || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(der_error("invalid DER time digits"));
    }
    let year = if tag == 0x17 {
        let yy: i32 = digits[0..2].parse().unwrap();
        if yy < 50 {
            2000 + yy
        } else {
            1900 + yy
        }
    } else {
        digits[0..4].parse().unwrap()
    };
    let date_start = if tag == 0x17 { 2 } else { 4 };
    let rfc3339 = format!(
        "{year:04}-{}-{}T{}:{}:{}{fraction}Z",
        &digits[date_start..date_start + 2],
        &digits[date_start + 2..date_start + 4],
        &digits[date_start + 4..date_start + 6],
        &digits[date_start + 6..date_start + 8],
        &digits[date_start + 8..date_start + 10]
    );
    let date =
        plist::Date::from_xml_format(&rfc3339).map_err(|_| der_error("invalid DER time value"))?;
    Ok(plist::Value::Date(date))
}

fn decode_der_entries(content: &[u8], depth: u32) -> Result<plist::Value> {
    if depth > 32 {
        return Err(der_error("DER nesting depth exceeds 32"));
    }
    let mut dictionary = plist::Dictionary::new();
    let mut remaining = content;
    while !remaining.is_empty() {
        let (tag, pair, rest) = read_der_tlv(remaining)?;
        if tag != 0x30 {
            return Err(der_error("DER entitlement entry is not a SEQUENCE"));
        }
        let (key_tag, key, key_rest) = read_der_tlv(pair)?;
        if key_tag != 0x0c || key_rest.is_empty() {
            return Err(der_error("DER entitlement entry has an invalid key"));
        }
        let key = std::str::from_utf8(key)
            .map_err(|_| der_error("invalid DER entitlement key"))?
            .to_owned();
        let (value_tag, value_bytes, value_rest) = read_der_tlv(key_rest)?;
        if !value_rest.is_empty() {
            return Err(der_error("DER entitlement entry has extra values"));
        }
        dictionary.insert(key, decode_der_value(value_tag, value_bytes, depth + 1)?);
        remaining = rest;
    }
    Ok(plist::Value::Dictionary(dictionary))
}

fn parse_tlv(bytes: &[u8], depth: u32) -> Result<plist::Value> {
    if depth > 32 {
        return Err(der_error("DER nesting depth exceeds 32"));
    }
    let (tag, content, remaining) = read_der_tlv(bytes)?;
    if !remaining.is_empty() {
        return Err(der_error("trailing bytes after DER value"));
    }
    decode_der_value(tag, content, depth)
}

fn decode_der_value(tag: u8, content: &[u8], depth: u32) -> Result<plist::Value> {
    if depth > 32 {
        return Err(der_error("DER nesting depth exceeds 32"));
    }
    match tag {
        0x01 => match content {
            [0x00] => Ok(plist::Value::Boolean(false)),
            [0xff] => Ok(plist::Value::Boolean(true)),
            _ => Err(der_error("invalid DER BOOLEAN value")),
        },
        0x02 => der_integer(content),
        0x0c | 0x16 | 0x1e => der_string(tag, content),
        0x04 => Ok(plist::Value::Data(content.to_vec())),
        0x17 | 0x18 => der_time(tag, content),
        0x30 => {
            let mut values = Vec::new();
            let mut remaining = content;
            while !remaining.is_empty() {
                let (child_tag, child_content, rest) = read_der_tlv(remaining)?;
                values.push(decode_der_value(child_tag, child_content, depth + 1)?);
                remaining = rest;
            }
            Ok(plist::Value::Array(values))
        }
        0x70 => {
            let (version_tag, _version, rest) = read_der_tlv(content)?;
            if version_tag != 0x02 {
                return Err(der_error("DER entitlements envelope lacks INTEGER version"));
            }
            let (entries_tag, entries, entries_rest) = read_der_tlv(rest)?;
            if !entries_rest.is_empty() || !DER_ENTRIES_CONTAINERS.contains(&entries_tag) {
                return Err(der_error("invalid DER entitlements entries container"));
            }
            decode_der_entries(entries, depth + 1)
        }
        0x31 | 0x60 | 0xa0 | 0xb0 => decode_der_entries(content, depth + 1),
        0x05 => Err(der_error("DER NULL is not a supported plist value")),
        _ => Err(der_error(format!("unsupported DER tag 0x{tag:02x}"))),
    }
}

pub(crate) fn der_entitlements_to_plist(der: &[u8]) -> Result<plist::Value> {
    let (tag, content, remaining) = read_der_tlv(der)?;
    if !remaining.is_empty() {
        return Err(der_error("trailing bytes after DER entitlements"));
    }
    let value = if DER_ENTRIES_CONTAINERS.contains(&tag) {
        decode_der_entries(content, 0)?
    } else {
        parse_tlv(der, 0)?
    };
    if !matches!(value, plist::Value::Dictionary(_)) {
        return Err(der_error("DER entitlements root is not a dictionary"));
    }
    Ok(value)
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

    /// Minimal SuperBlob: header + index + zero-filled tail to `total`.
    /// `entries` are `(slot, offset)` index pairs; the caller writes each
    /// child's magic+length header bytes at its `offset` afterwards.
    fn synth_superblob(total: u32, entries: &[(u32, u32)]) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&CSMAGIC_EMBEDDED_SIGNATURE.to_be_bytes());
        b.extend_from_slice(&total.to_be_bytes());
        b.extend_from_slice(&(entries.len() as u32).to_be_bytes());
        for (slot, off) in entries {
            b.extend_from_slice(&slot.to_be_bytes());
            b.extend_from_slice(&off.to_be_bytes());
        }
        b.resize(total as usize, 0);
        b
    }

    #[test]
    fn superblob_shorter_declared_length_is_rejected() {
        // Declared total below the index extent: pre-fix this parses
        // because bytes 4..8 are never read.
        let mut b = build_blob(true);
        b[4..8].copy_from_slice(&4u32.to_be_bytes());
        assert!(
            parse_superblob(&b).is_err(),
            "declared length below index extent"
        );

        // Declared length past the actual buffer.
        let mut b = build_blob(true);
        let len = b.len() as u32;
        b[4..8].copy_from_slice(&(len + 64).to_be_bytes());
        assert!(
            parse_superblob(&b).is_err(),
            "declared length overruns buffer"
        );

        // Declared length inside the index but with children beyond it:
        // bound all reads to blob[..declared].
        let mut b = build_blob(true);
        let count = u32::from_be_bytes(b[8..12].try_into().unwrap());
        let index_end = 12 + count * 8;
        b[4..8].copy_from_slice(&(index_end + 4).to_be_bytes());
        assert!(
            parse_superblob(&b).is_err(),
            "children outside declared length"
        );
    }

    #[test]
    fn superblob_entry_inside_header_is_rejected() {
        // Child offset 0 aliases the SuperBlob header itself.
        let b = synth_superblob(40, &[(0, 0)]);
        assert!(parse_superblob(&b).is_err(), "entry inside header/index");
    }

    #[test]
    fn superblob_short_child_is_rejected() {
        // Valid index (12 + 8 = 20), child at 20 declares item_len 4 (< 8).
        let mut b = synth_superblob(28, &[(0, 20)]);
        b[20..24].copy_from_slice(&0xfade0c00u32.to_be_bytes());
        b[24..28].copy_from_slice(&4u32.to_be_bytes());
        assert!(parse_superblob(&b).is_err(), "item_len < 8");
    }

    #[test]
    fn superblob_overlapping_children_are_rejected() {
        // Index ends at 28. Child A [28,44), child B [36,44) — B sits
        // inside A; duplicates would overlap identically.
        let mut b = synth_superblob(44, &[(0, 28), (1, 36)]);
        b[28..32].copy_from_slice(&0xfade0c00u32.to_be_bytes());
        b[32..36].copy_from_slice(&16u32.to_be_bytes());
        b[36..40].copy_from_slice(&0xfade0c01u32.to_be_bytes());
        b[40..44].copy_from_slice(&8u32.to_be_bytes());
        assert!(parse_superblob(&b).is_err(), "overlapping children");
    }

    #[test]
    fn slot_magic_mismatch_is_rejected() {
        let mut b = build_blob(true);
        // locate the requirements child (slot 0x0002) via its index entry
        let count = u32::from_be_bytes(b[8..12].try_into().unwrap()) as usize;
        let mut off = 0usize;
        for i in 0..count {
            let e = 12 + i * 8;
            if u32::from_be_bytes(b[e..e + 4].try_into().unwrap()) == CSSLOT_REQUIREMENTS {
                off = u32::from_be_bytes(b[e + 4..e + 8].try_into().unwrap()) as usize;
            }
        }
        assert!(off > 0, "fixture must carry a requirements child");
        b[off..off + 4].copy_from_slice(&0u32.to_be_bytes());
        assert!(parse_superblob(&b).is_err(), "wrong magic must be rejected");
    }

    #[test]
    fn distinct_duplicate_slot_is_rejected() {
        // Two DIFFERENT children both claiming slot 0x0002 (distinct ranges, so the
        // pairwise-overlap check passes): today last-wins Ok.
        let mut b = synth_superblob(60, &[(CSSLOT_REQUIREMENTS, 28), (CSSLOT_REQUIREMENTS, 44)]);
        b[28..32].copy_from_slice(&CSMAGIC_REQUIREMENTS.to_be_bytes());
        b[32..36].copy_from_slice(&16u32.to_be_bytes());
        b[44..48].copy_from_slice(&CSMAGIC_REQUIREMENTS.to_be_bytes());
        b[48..52].copy_from_slice(&16u32.to_be_bytes());
        assert!(
            parse_superblob(&b).is_err(),
            "duplicate slot must be rejected"
        );
    }

    #[test]
    fn duplicate_code_directory_slot_is_rejected() {
        // Two DIFFERENT valid CodeDirectory children both claiming slot 0x0000:
        // today the second is silently ignored by the is_none() guard.
        let a = CodeDirectoryBuilder::new("com.example.a", TEST_CODE).build_sha256();
        let c = CodeDirectoryBuilder::new("com.example.bbbb", TEST_CODE).build_sha256();
        let a_off = 28u32; // index = 12 + 2*8
        let c_off = a_off + a.len() as u32;
        let total = c_off + c.len() as u32;
        let mut b = synth_superblob(
            total,
            &[(CSSLOT_CODEDIRECTORY, a_off), (CSSLOT_CODEDIRECTORY, c_off)],
        );
        b[a_off as usize..a_off as usize + a.len()].copy_from_slice(&a);
        b[c_off as usize..c_off as usize + c.len()].copy_from_slice(&c);
        assert!(
            parse_superblob(&b).is_err(),
            "duplicate slot 0 must be rejected"
        );
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
    fn parse_reads_exec_segment_fields() {
        let cd_bytes = CodeDirectoryBuilder::new("com.example.exec", TEST_CODE)
            .exec_seg_base(0x1_0000_0000)
            .exec_seg_limit(0x1000)
            .exec_seg_flags(CS_EXECSEG_MAIN_BINARY)
            .build_sha256();
        let cd = CodeDirectory::parse(&cd_bytes).unwrap();
        assert_eq!(cd.exec_seg_base, 0x1_0000_0000);
        assert_eq!(cd.exec_seg_limit, 0x1000);
        assert_eq!(cd.exec_seg_flags, CS_EXECSEG_MAIN_BINARY);
    }

    #[test]
    fn der_entitlements_round_trip() {
        let xml = br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>com.example.flag</key><true/>
<key>com.example.count</key><integer>7</integer>
<key>com.example.name</key><string>demo</string>
<key>com.example.list</key><array><string>a</string><integer>2</integer></array>
<key>com.example.nested</key><dict><key>inner</key><string>v</string></dict>
</dict></plist>"#;
        let der = crate::codesign::der::plist_to_der(xml).unwrap();
        let decoded = der_entitlements_to_plist(&der).unwrap();
        let expected = plist::from_bytes::<plist::Value>(xml.as_slice()).unwrap();
        assert_eq!(decoded, expected);
    }

    #[test]
    fn der_v0_and_v1_shapes_parse() {
        // v1 as the repo encoder emits (der.rs:258-276):
        //   0x70 { INTEGER 1, 0xb0 { SEQUENCE{ UTF8String "k", UTF8String "v" } } }
        let v1 = [
            0x70u8, 0x0d, 0x02, 0x01, 0x01, 0xb0, 0x08, 0x30, 0x06, 0x0c, 0x01, b'k', 0x0c, 0x01,
            b'v',
        ];
        // v0: the bare entries SET with no envelope (older Apple blobs)
        let v0 = [0x31u8, 0x08, 0x30, 0x06, 0x0c, 0x01, b'k', 0x0c, 0x01, b'v'];
        for bytes in [v1.as_slice(), v0.as_slice()] {
            let v = der_entitlements_to_plist(bytes).unwrap();
            assert_eq!(
                v.as_dictionary().unwrap().get("k").unwrap().as_string(),
                Some("v")
            );
        }
    }

    #[test]
    fn der_malformed_is_error() {
        assert!(der_entitlements_to_plist(&[0x31, 0x02, 0xff, 0xff]).is_err()); // length overrun
        assert!(der_entitlements_to_plist(&[]).is_err());
        assert!(der_entitlements_to_plist(&[0x70, 0x02, 0x05, 0x00]).is_err()); // no INTEGER version
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_superblob(&[0u8; 64]).is_err());
        assert!(CodeDirectory::parse(&[0u8; 64]).is_err());
    }

    fn synth_cd_with_slot8(child: &[u8]) -> Vec<u8> {
        // 0x20400 layout: 88-byte header + ident + 8 special slots + 0 code slots.
        let ident = b"com.example.lc\0";
        let n_special = 8usize;
        let hash_size = 32usize;
        let hash_offset = 88 + ident.len() + n_special * hash_size;
        let mut cd = vec![0u8; hash_offset];
        cd[0..4].copy_from_slice(&CSMAGIC_CODEDIRECTORY.to_be_bytes());
        cd[4..8].copy_from_slice(&(hash_offset as u32).to_be_bytes());
        cd[8..12].copy_from_slice(&CODEDIRECTORY_VERSION.to_be_bytes());
        cd[16..20].copy_from_slice(&(hash_offset as u32).to_be_bytes()); // hashOffset
        cd[20..24].copy_from_slice(&88u32.to_be_bytes()); // identOffset
        cd[24..28].copy_from_slice(&(n_special as u32).to_be_bytes());
        cd[36] = hash_size as u8;
        cd[37] = CS_HASHTYPE_SHA256;
        cd[39] = 12; // pageSize log2
        cd[88..88 + ident.len()].copy_from_slice(ident);
        let digest = Sha256::digest(child);
        cd[hash_offset - 8 * hash_size..hash_offset - 7 * hash_size].copy_from_slice(&digest);
        cd
    }

    #[test]
    fn launch_constraint_content_comes_from_superblob_slot_8() {
        let child: Vec<u8> = [
            0xfade8181u32.to_be_bytes(), // CSMAGIC_LAUNCH_CONSTRAINT
            12u32.to_be_bytes(),
            [0u8; 4],
        ]
        .concat();
        let cd_bytes = synth_cd_with_slot8(&child);
        let cd = CodeDirectory::parse(&cd_bytes).unwrap();
        assert_eq!(cd.n_special_slots, 8);

        let total = (12 + 8 + child.len()) as u32;
        let mut sb = synth_superblob(total, &[(CSSLOT_LAUNCH_CONSTRAINT_SELF, 20)]);
        sb[20..20 + child.len()].copy_from_slice(&child);
        let parsed = parse_superblob(&sb).expect("slot 0x0008 child parses");
        let checks = check_special_slots(&cd, &SignatureInputs::none(), &parsed);
        assert_eq!(checks[7], SpecialSlotCheck::Matched); // k=8 verified against 0x0008

        let empty = synth_superblob(20, &[]);
        let parsed_empty = parse_superblob(&empty).unwrap();
        let checks2 = check_special_slots(&cd, &SignatureInputs::none(), &parsed_empty);
        assert_eq!(checks2[7], SpecialSlotCheck::NotChecked);
    }
}
