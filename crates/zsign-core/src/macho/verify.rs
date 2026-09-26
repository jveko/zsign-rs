//! Mach-O-level code signature verification.
//!
//! Orchestrates the blob-level checks ([`codesign::verify`](super::super::codesign::verify))
//! and the CMS verifier ([`crypto::cms_verify`](super::super::crypto::cms_verify))
//! across every architecture slice of a Mach-O binary (single-arch or FAT).
//!
//! This is the "verify one binary" entry point used by the CLI and by
//! bundle-level verification; it never touches the filesystem.

use crate::codesign::constants::*;
use crate::codesign::verify::{
    check_code_pages, check_special_slots, der_entitlements_to_plist, parse_requirements,
    parse_superblob, CodeDirectory, PageCheck, RequirementContext, RequirementVerdict,
    SignatureInputs, SpecialSlotCheck, SuperBlob,
};
use crate::Result;
use sha1::Sha1;
use sha2::{Digest, Sha256};

// -1/-3 need caller-supplied content: elevate ONLY when the caller demonstrated
// bundle context (any SignatureInputs field present). SignatureInputs::none()
// means "standalone: caller cannot supply these" - the zsign facade reports them.
const CONTEXT_SLOTS: [i32; 2] = [CSSLOT_SPECIAL_INFOSLOT, CSSLOT_SPECIAL_RESOURCEDIR];

// -2/-5/-7 and the launch-constraint slots are SuperBlob-sourced: their content
// needs no caller context, so NotChecked there is ALWAYS a core failure.
const SUPERBLOB_SLOTS: [i32; 7] = [
    CSSLOT_SPECIAL_REQUIREMENTS,
    CSSLOT_SPECIAL_ENTITLEMENTS,
    CSSLOT_SPECIAL_DER_ENTITLEMENTS,
    CSSLOT_SPECIAL_LAUNCH_CONSTRAINT_SELF,
    CSSLOT_SPECIAL_LAUNCH_CONSTRAINT_PARENT,
    CSSLOT_SPECIAL_LAUNCH_CONSTRAINT_RESPONSIBLE,
    CSSLOT_SPECIAL_LIBRARY_CONSTRAINT,
];

/// Report of the verification of one architecture slice.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SliceVerifyReport {
    /// Human-readable architecture name (e.g. `arm64`, `x86_64`).
    pub arch: String,
    /// Whether an embedded signature SuperBlob was found.
    pub signed: bool,
    /// Bundle identifier recorded in the primary CodeDirectory.
    pub identifier: Option<String>,
    /// Whether the slice is ad-hoc signed (no CMS identity).
    pub adhoc: bool,
    /// Result of the code-page hash check.
    pub pages: PageCheck,
    /// Special-slot checks, ordered slot −1 downward.
    pub special_slots: Vec<SpecialSlotCheck>,
    /// CMS verification, when a signature slot is present.
    pub cms: Option<crate::crypto::cms_verify::CmsVerifyReport>,
    /// Human-readable failures (empty when the slice verifies).
    pub errors: Vec<String>,
    /// Non-fatal notes (e.g. unsupported page size).
    pub warnings: Vec<String>,
}

impl SliceVerifyReport {
    /// True when every check that applies to this slice passed.
    pub fn is_valid(&self) -> bool {
        self.errors.is_empty()
    }
}

/// Report of the verification of a whole Mach-O binary.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MachOVerifyReport {
    /// Whether the binary is FAT/Universal.
    pub fat: bool,
    /// Per-slice reports in file order.
    pub slices: Vec<SliceVerifyReport>,
}

impl MachOVerifyReport {
    /// True when every slice verifies.
    pub fn is_valid(&self) -> bool {
        !self.slices.is_empty() && self.slices.iter().all(|s| s.is_valid())
    }

    /// Total number of failures across all slices.
    pub fn error_count(&self) -> usize {
        self.slices.iter().map(|s| s.errors.len()).sum()
    }
}

/// Verifies every architecture slice of an in-memory Mach-O binary.
///
/// `inputs` supplies the Info.plist and CodeResources file bytes whose digests
/// are bound into the signature's special slots (they are independent of the
/// binary); pass [`SignatureInputs::none`] when verifying a bare binary that
/// has no bundle context.
///
/// # Errors
///
/// Returns [`Error::MachO`] when the bytes are not a parseable Mach-O and
/// [`Error::Verification`] for structurally broken embedded signatures.
pub fn verify_macho(data: &[u8], inputs: &SignatureInputs<'_>) -> Result<MachOVerifyReport> {
    let macho = crate::macho::MachOFile::parse(data.to_vec())?;
    let fat = macho.is_fat();
    let mut slices = Vec::with_capacity(macho.slices().len());

    for slice in macho.slices() {
        let report = verify_slice(data, slice, inputs)?;
        slices.push(report);
    }

    Ok(MachOVerifyReport { fat, slices })
}

fn push_page_errors(report: &mut SliceVerifyReport, label: &str, pages: &PageCheck) {
    match pages {
        PageCheck::Empty => report
            .errors
            .push(format!("{label}code directory covers zero code bytes")),
        PageCheck::Mismatch { page_index } => report.errors.push(format!(
            "{label}code page {page_index} hash mismatch (code region modified?)"
        )),
        PageCheck::CountMismatch { stored, computed } => report.errors.push(format!(
            "{label}code slot count mismatch: {stored} stored vs {computed} pages computed"
        )),
        PageCheck::Matched => {}
    }
}

fn verify_slice(
    data: &[u8],
    slice: &crate::macho::ArchSlice,
    inputs: &SignatureInputs<'_>,
) -> Result<SliceVerifyReport> {
    let mut report = SliceVerifyReport {
        arch: slice.arch_name(),
        ..SliceVerifyReport::default()
    };

    let (sig_off, sig_size) = match (slice.code_sig_offset, slice.code_sig_size) {
        (Some(off), Some(size)) => (off as usize, size as usize),
        _ => {
            report
                .errors
                .push("no LC_CODE_SIGNATURE load command".into());
            return Ok(report);
        }
    };
    // Load-command offsets are slice-relative; FAT slices sit at an arch
    // offset within the file.
    let sig_file_off = slice.offset.saturating_add(sig_off);

    let Some(sig) = data.get(sig_file_off..sig_file_off.saturating_add(sig_size)) else {
        report
            .errors
            .push("code signature region is out of file bounds".into());
        return Ok(report);
    };

    let superblob = match parse_superblob(sig) {
        Ok(superblob) => superblob,
        Err(e) => {
            report.errors.push(format!(
                "embedded code signature is not a valid SuperBlob: {e}"
            ));
            return Ok(report);
        }
    };

    let Some(primary) = superblob.code_directory.as_ref() else {
        report
            .errors
            .push("no primary CodeDirectory (slot 0x0)".into());
        return Ok(report);
    };

    let cds = emitted_cds(&superblob);
    let strongest = cds
        .iter()
        .copied()
        .max_by_key(|cd| cd.hash_size)
        .unwrap_or(primary);

    report.signed = true;
    report.adhoc = primary.is_adhoc();
    report.identifier = primary.identifier().map(str::to_owned);

    for cd in &cds {
        let pages = check_code_pages_in_file(cd, data, slice);
        let label = if std::ptr::eq(*cd, primary) {
            String::new()
        } else {
            format!(
                "alternate {} ",
                if cd.is_sha1() { "SHA-1" } else { "SHA-256" }
            )
        };
        push_page_errors(&mut report, &label, &pages);
    }

    let mut pairs: Vec<(String, Vec<SpecialSlotCheck>)> = Vec::with_capacity(cds.len());
    let mut strongest_slots = None;
    for cd in &cds {
        let checks = check_special_slots(cd, inputs, &superblob);
        let is_primary = std::ptr::eq(*cd, primary);
        if std::ptr::eq(*cd, strongest) {
            strongest_slots = Some(checks.clone());
        }
        pairs.push((
            if is_primary {
                String::new()
            } else {
                format!(
                    "alternate {} ",
                    if cd.is_sha1() { "SHA-1" } else { "SHA-256" }
                )
            },
            checks,
        ));
    }
    let context_supplied = inputs.info_plist.is_some() || inputs.code_resources.is_some();
    for (label, checks) in &pairs {
        for (i, check) in checks.iter().enumerate() {
            let k = i + 1;
            let slot = -(k as i32);
            match check {
                SpecialSlotCheck::Mismatch => report
                    .errors
                    .push(format!("{label}special slot -{k} hash mismatch")),
                SpecialSlotCheck::NotChecked
                    if SUPERBLOB_SLOTS.contains(&slot)
                        || (context_supplied && CONTEXT_SLOTS.contains(&slot)) =>
                {
                    report.errors.push(format!(
                        "{label}special slot -{k} is bound but its content was not supplied"
                    ));
                }
                _ => {}
            }
        }
    }
    report.pages = check_code_pages_in_file(strongest, data, slice);
    report.special_slots = strongest_slots.unwrap_or_default();
    let child = |slot: u32| superblob.entries.iter().find(|e| e.slot == slot);
    let xml_bound = primary
        .special_slot_hash(5)
        .map(|h| h.iter().any(|&b| b != 0))
        .unwrap_or(false);
    let der_bound = primary
        .special_slot_hash(7)
        .map(|h| h.iter().any(|&b| b != 0))
        .unwrap_or(false);
    if let Some(xml_entry) = child(CSSLOT_ENTITLEMENTS) {
        let xml_val = match plist::from_bytes::<plist::Value>(xml_entry.payload()) {
            Ok(v) => Some(v),
            Err(e) => {
                report
                    .errors
                    .push(format!("XML entitlements do not parse: {e}"));
                None
            }
        };
        if let Some(der_entry) = child(CSSLOT_DER_ENTITLEMENTS) {
            match der_entitlements_to_plist(der_entry.payload()) {
                Ok(der_val) => {
                    if let Some(xml_val) = &xml_val {
                        if &der_val != xml_val {
                            report
                                .errors
                                .push("XML and DER entitlements dictionaries differ".to_string());
                        }
                    }
                }
                Err(e) => report
                    .errors
                    .push(format!("DER entitlements do not parse: {e}")),
            }
        }
    }
    // Binding rule: a bound -5 on a modern main executable requires a BOUND -7 child.
    if xml_bound
        && slice.is_executable
        && primary.version >= CODEDIRECTORY_VERSION_EXECSEG
        && !(der_bound && child(CSSLOT_DER_ENTITLEMENTS).is_some())
    {
        report.errors.push(
            "XML entitlements bound (slot -5) without bound DER entitlements (slot -7)".to_string(),
        );
    }

    if primary.version >= CODEDIRECTORY_VERSION_EXECSEG {
        let (base, limit, flags) = (
            primary.exec_seg_base,
            primary.exec_seg_limit,
            primary.exec_seg_flags,
        );
        if base != 0 || limit != 0 {
            // Our signer uses exact virtual-address base/limit pairs.
            let vm_matches = base == slice.text_segment_base && limit == slice.text_segment_size;
            // Apple's file-convention range remains a plausibility fallback
            // because __TEXT fileoff/filesize is not exposed by this parser.
            let file_space_ok = base <= slice.size as u64
                && limit >= 0x1000
                && limit <= slice.text_segment_size
                && base.saturating_add(limit) <= slice.size as u64;
            if !vm_matches && !file_space_ok {
                report.errors.push(format!(
                    "executable segment range 0x{base:x}+0x{limit:x} does not match __TEXT"
                ));
            }
        }
        const KNOWN_EXECSEG_FLAGS: u64 = 0x1 | 0x10 | 0x20 | 0x40 | 0x80 | 0x100 | 0x200;
        if flags & !KNOWN_EXECSEG_FLAGS != 0 {
            report.errors.push(format!(
                "unknown exec segment flags bits {:#x}",
                flags & !KNOWN_EXECSEG_FLAGS
            ));
        }
        if (flags & CS_EXECSEG_MAIN_BINARY != 0) != slice.is_executable {
            report.errors.push(if slice.is_executable {
                "exec segment flags missing CS_EXECSEG_MAIN_BINARY".to_string()
            } else {
                "CS_EXECSEG_MAIN_BINARY set on a non-executable slice".to_string()
            });
        }
        const CROSS_CHECK_FLAGS: u64 =
            CS_EXECSEG_ALLOW_UNSIGNED | CS_EXECSEG_JIT | CS_EXECSEG_DEBUGGER | CS_EXECSEG_SKIP_LV;
        if flags & CROSS_CHECK_FLAGS != 0 {
            let ent_dict = child(CSSLOT_ENTITLEMENTS)
                .and_then(|e| plist::from_bytes::<plist::Dictionary>(e.payload()).ok());
            match ent_dict {
                Some(dict) => {
                    let has = |k: &str| dict.get(k).is_some();
                    if flags & CS_EXECSEG_ALLOW_UNSIGNED != 0
                        && !(has("get-task-allow") || has("run-unsigned-code"))
                    {
                        report.errors.push(
                            "CS_EXECSEG_ALLOW_UNSIGNED requires get-task-allow or run-unsigned-code"
                                .to_string(),
                        );
                    }
                    if flags & CS_EXECSEG_JIT != 0 && !has("dynamic-codesigning") {
                        report
                            .errors
                            .push("CS_EXECSEG_JIT requires dynamic-codesigning".to_string());
                    }
                    if flags & CS_EXECSEG_DEBUGGER != 0 && !has("com.apple.private.cs.debugger") {
                        report.errors.push(
                            "CS_EXECSEG_DEBUGGER requires com.apple.private.cs.debugger"
                                .to_string(),
                        );
                    }
                    if flags & CS_EXECSEG_SKIP_LV != 0
                        && !has("com.apple.private.skip-library-validation")
                    {
                        report.errors.push(
                            "CS_EXECSEG_SKIP_LV requires com.apple.private.skip-library-validation"
                                .to_string(),
                        );
                    }
                }
                None => report.warnings.push(format!(
                    "exec segment flags {:#x} cannot be cross-checked without entitlements",
                    flags
                )),
            }
        }
    }

    // CMS signature. An exact 8-byte CSMAGIC_BLOBWRAPPER header is what
    // codesign emits for ad-hoc output; the shortcut also requires CS_ADHOC.
    if let Some(cms_blob) = superblob.cms {
        let empty_wrapper =
            cms_blob.len() == 8 && cms_blob[0..4] == CSMAGIC_BLOBWRAPPER.to_be_bytes();
        if empty_wrapper {
            if primary.is_adhoc() {
                report.cms = Some(crate::crypto::cms_verify::adhoc_report());
            } else {
                report
                    .errors
                    .push("empty CMS wrapper but not ad-hoc flagged".into());
            }
        } else {
            let (cd_sha1, cd_sha256_opt) = cdhash_pair(&cds);
            match cd_sha256_opt {
                None => report.errors.push(
                    "CMS signature present but no SHA-256 CodeDirectory to bind CDHash v2"
                        .to_string(),
                ),
                Some(cd_sha256) => {
                    match crate::crypto::cms_verify::verify_code_signature(
                        cms_blob,
                        primary.raw(),
                        cd_sha1.as_ref(),
                        &cd_sha256,
                    ) {
                        Ok(cms_report) => {
                            if !cms_report.valid {
                                report.errors.extend(cms_report.errors.clone());
                            }
                            report.cms = Some(cms_report);
                        }
                        Err(e) => report.errors.push(format!("CMS verification error: {e}")),
                    }
                }
            }
        }
    } else if primary.is_adhoc() {
        report.cms = Some(crate::crypto::cms_verify::adhoc_report());
    } else {
        report
            .errors
            .push("no CMS signature slot but not ad-hoc flagged".into());
    }

    if let Some(req) = superblob
        .entries
        .iter()
        .find(|entry| entry.slot == CSSLOT_REQUIREMENTS)
    {
        match parse_requirements(req.blob) {
            Err(e) => report
                .errors
                .push(format!("malformed requirements blob: {e}")),
            Ok(set) => {
                if let Some(dr) = set.designated() {
                    let cdhashes: Vec<Vec<u8>> = cds
                        .iter()
                        .map(|cd| {
                            let digest: Vec<u8> = match cd.hash_type {
                                1 => Sha1::digest(cd.raw()).to_vec(),
                                _ => Sha256::digest(cd.raw()).to_vec(),
                            };
                            digest[..digest.len().min(20)].to_vec()
                        })
                        .collect();
                    let refs: Vec<&[u8]> = cdhashes.iter().map(Vec::as_slice).collect();
                    let anchored = report
                        .cms
                        .as_ref()
                        .filter(|cms| !cms.no_signature)
                        .map(|cms| cms.anchored);
                    let context = RequirementContext {
                        identifier: primary.identifier(),
                        cdhashes: &refs,
                        anchored,
                    };
                    match dr.evaluate(&context) {
                        RequirementVerdict::Violated => report
                            .errors
                            .push("designated requirement not satisfied".to_string()),
                        RequirementVerdict::Unsupported(why) => report
                            .warnings
                            .push(format!("designated requirement not fully evaluated: {why}")),
                        RequirementVerdict::Satisfied => {}
                    }
                }
            }
        }
    }

    Ok(report)
}

/// Every emitted CodeDirectory: primary first, then alternates, in slot order.
fn emitted_cds<'a>(superblob: &'a SuperBlob<'a>) -> Vec<&'a CodeDirectory<'a>> {
    let mut cds = Vec::with_capacity(1 + superblob.alternate_code_directories.len());
    if let Some(p) = superblob.code_directory.as_ref() {
        cds.push(p);
    }
    cds.extend(superblob.alternate_code_directories.iter());
    cds
}

/// The CDHash pair bound into the CMS attributes, selected BY EMITTED TYPE:
/// v1's first entry hashes the SHA-1 CD, v1's second entry and v2 hash the
/// SHA-256 CD. `None` when that type is not emitted.
fn cdhash_pair(cds: &[&CodeDirectory<'_>]) -> (Option<[u8; 20]>, Option<[u8; 32]>) {
    let sha1 = cds.iter().find(|cd| cd.is_sha1()).map(|cd| {
        let d: [u8; 20] = Sha1::digest(cd.raw()).into();
        d
    });
    let sha256 = cds.iter().find(|cd| cd.is_sha256()).map(|cd| {
        let d: [u8; 32] = Sha256::digest(cd.raw()).into();
        d
    });
    (sha1, sha256)
}

/// Page check variant that reads exactly the slice's byte range from the
/// file, using the effective code limit — `codeLimit64` when the 0x20300+
/// CodeDirectory binds it, else `codeLimit` — as authoritative. A limit
/// beyond the slice therefore overruns the bounded region and reports
/// `CountMismatch` instead of hashing the next architecture.
fn check_code_pages_in_file(
    cd: &CodeDirectory<'_>,
    data: &[u8],
    slice: &crate::macho::ArchSlice,
) -> PageCheck {
    let Some(range) = slice
        .offset
        .checked_add(slice.size)
        .and_then(|end| data.get(slice.offset..end))
    else {
        return PageCheck::CountMismatch {
            stored: cd.n_code_slots as usize,
            computed: 0,
        };
    };
    check_code_pages(cd, range)
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::codesign::constants::{
        CSMAGIC_EMBEDDED_SIGNATURE, CSMAGIC_REQUIREMENT, CSMAGIC_REQUIREMENTS,
        CSSLOT_ALTERNATE_CODEDIRECTORIES, CSSLOT_CODEDIRECTORY, CSSLOT_DER_ENTITLEMENTS,
        CSSLOT_REQUIREMENTS, CSSLOT_SIGNATURESLOT,
    };
    use crate::crypto::SigningCredentials;
    use crate::macho::fixtures::{make_fat_macho, make_minimal_macho};
    use crate::macho::{
        sign_any_macho, sign_macho, sign_macho_adhoc, sign_macho_sha256_only, MachOFile,
    };
    use sha2::{Digest, Sha256};

    fn sign_round_trip(creds: &SigningCredentials, ident: &str) -> Vec<u8> {
        let macho = MachOFile::parse(make_minimal_macho()).unwrap();
        sign_macho_sha256_only(&macho, ident, None, creds, None, None, false).unwrap()
    }

    fn signed_superblob(data: &[u8]) -> Vec<u8> {
        let macho = MachOFile::parse(data.to_vec()).unwrap();
        let slice = &macho.slices()[0];
        let (off, size) = (
            slice.code_sig_offset.unwrap() as usize,
            slice.code_sig_size.unwrap() as usize,
        );
        data[off..off + size].to_vec()
    }

    /// Offset of the child blob whose header carries `slot`, relative to the
    /// SuperBlob start.
    fn entry_offset(sb: &[u8], slot: u32) -> Option<usize> {
        let count = u32::from_be_bytes(sb[8..12].try_into().unwrap()) as usize;
        (0..count).find_map(|i| {
            let e = 12 + i * 8;
            let s = u32::from_be_bytes(sb[e..e + 4].try_into().unwrap());
            (s == slot).then(|| u32::from_be_bytes(sb[e + 4..e + 8].try_into().unwrap()) as usize)
        })
    }

    const ENT_PLIST: &[u8] = br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>com.example.ent</key><string>same</string></dict></plist>"#;

    fn adhoc_ent_fixture() -> Vec<u8> {
        let macho = MachOFile::parse(make_minimal_macho()).unwrap();
        sign_macho_adhoc(
            &macho,
            "com.example.ent",
            Some(ENT_PLIST),
            None,
            None,
            false,
        )
        .unwrap()
    }

    /// File offset of a SuperBlob child inside `signed` (slice 0 only).
    fn child_off_in_signed(signed: &[u8], slot: u32) -> usize {
        let m = MachOFile::parse(signed.to_vec()).unwrap();
        let sl = &m.slices()[0];
        let sig_off = sl.code_sig_offset.unwrap() as usize;
        let sig_len = sl.code_sig_size.unwrap() as usize;
        sig_off + entry_offset(&signed[sig_off..sig_off + sig_len], slot).unwrap()
    }

    /// Rewrite stored special slot `k` (1-based) in BOTH CodeDirectories:
    /// digest of `content` under each CD's own hash type, or all-zero when `None`.
    fn bind_special_slot(signed: &mut [u8], k: usize, content: Option<&[u8]>) {
        let m = MachOFile::parse(signed.to_vec()).unwrap();
        let sl = &m.slices()[0];
        let sig_off = sl.code_sig_offset.unwrap() as usize;
        let sig_len = sl.code_sig_size.unwrap() as usize;
        let cds: Vec<usize> = [CSSLOT_CODEDIRECTORY, CSSLOT_ALTERNATE_CODEDIRECTORIES]
            .iter()
            .map(|s| sig_off + entry_offset(&signed[sig_off..sig_off + sig_len], *s).unwrap())
            .collect();
        for cd in cds {
            let hash_offset =
                u32::from_be_bytes(signed[cd + 16..cd + 20].try_into().unwrap()) as usize;
            let hash_size = signed[cd + 36] as usize;
            let hash_type = signed[cd + 37];
            let start = cd + hash_offset - k * hash_size;
            let bytes: Vec<u8> = match content {
                None => vec![0; hash_size],
                Some(c) => match hash_type {
                    1 => Sha1::digest(c).to_vec(),
                    _ => Sha256::digest(c).to_vec(),
                },
            };
            assert_eq!(bytes.len(), hash_size);
            signed[start..start + hash_size].copy_from_slice(&bytes);
        }
    }

    fn ident_dr_blob(name: &str) -> Vec<u8> {
        let mut expr = 2u32.to_be_bytes().to_vec(); // opIdent
        expr.extend_from_slice(&(name.len() as u32).to_be_bytes());
        expr.extend_from_slice(name.as_bytes());
        while !expr.len().is_multiple_of(4) {
            expr.push(0);
        }
        let child_len = 12 + expr.len();
        let total = 0x14 + child_len;
        let mut b = Vec::with_capacity(total);
        b.extend_from_slice(&CSMAGIC_REQUIREMENTS.to_be_bytes());
        b.extend_from_slice(&(total as u32).to_be_bytes());
        b.extend_from_slice(&1u32.to_be_bytes());
        b.extend_from_slice(&3u32.to_be_bytes()); // CSREQ_DESIGNATED
        b.extend_from_slice(&0x14u32.to_be_bytes());
        b.extend_from_slice(&CSMAGIC_REQUIREMENT.to_be_bytes());
        b.extend_from_slice(&(child_len as u32).to_be_bytes());
        b.extend_from_slice(&1u32.to_be_bytes()); // exprForm
        b.extend_from_slice(&expr);
        b
    }

    /// Replace the requirements child of `signed`'s SuperBlob with `new_child`
    /// (shifting later children, fixing declared length + index offsets), then
    /// rebind stored special slot -2 in BOTH CDs to the new child.
    fn replace_requirements_child(signed: &mut [u8], new_child: &[u8]) {
        use std::collections::HashMap;
        let m = MachOFile::parse(signed.to_vec()).unwrap();
        let sl = &m.slices()[0];
        let sig_off = sl.code_sig_offset.unwrap() as usize;
        let sig_len = sl.code_sig_size.unwrap() as usize;
        let sb = &signed[sig_off..sig_off + sig_len];
        let declared = u32::from_be_bytes(sb[4..8].try_into().unwrap()) as usize;
        let count = u32::from_be_bytes(sb[8..12].try_into().unwrap()) as usize;
        let index_end = 12 + count * 8;
        let mut entries: Vec<(u32, usize, usize)> = Vec::with_capacity(count);
        for i in 0..count {
            let e = 12 + i * 8;
            let slot = u32::from_be_bytes(sb[e..e + 4].try_into().unwrap());
            let off = u32::from_be_bytes(sb[e + 4..e + 8].try_into().unwrap()) as usize;
            let len = u32::from_be_bytes(sb[off + 4..off + 8].try_into().unwrap()) as usize;
            entries.push((slot, off, len));
        }
        let (req_off, req_len) = entries
            .iter()
            .find(|(s, _, _)| *s == CSSLOT_REQUIREMENTS)
            .map(|(_, o, l)| (*o, *l))
            .expect("requirements child");
        let delta = new_child.len() as isize - req_len as isize;
        assert!(
            declared as isize + delta <= sig_len as isize,
            "LC window slack too small for the DR blob"
        );
        entries.sort_by_key(|(_, off, _)| *off);
        let mut out: Vec<u8> = Vec::with_capacity((declared as isize + delta) as usize);
        out.extend_from_slice(&sb[0..index_end]); // header (length fixed below) + index
        let mut new_off = HashMap::new();
        for (slot, off, len) in &entries {
            new_off.insert(*slot, out.len());
            if *off == req_off {
                out.extend_from_slice(new_child);
            } else {
                out.extend_from_slice(&sb[*off..*off + *len]);
            }
        }
        let new_declared = out.len() as u32;
        out[4..8].copy_from_slice(&new_declared.to_be_bytes());
        for i in 0..count {
            let e = 12 + i * 8;
            let slot = u32::from_be_bytes(out[e..e + 4].try_into().unwrap());
            let off = new_off[&slot] as u32;
            out[e + 4..e + 8].copy_from_slice(&off.to_be_bytes());
        }
        signed[sig_off..sig_off + out.len()].copy_from_slice(&out);
        bind_special_slot(signed, 2, Some(new_child)); // task 5 helper
    }

    #[test]
    fn designated_requirement_is_enforced_end_to_end() {
        let macho = MachOFile::parse(make_minimal_macho()).unwrap();
        // Satisfied: DR demanding this fixture's own identifier -> no DR finding.
        let mut ok_signed =
            sign_macho_adhoc(&macho, "com.example.dr", None, None, None, false).unwrap();
        replace_requirements_child(&mut ok_signed, &ident_dr_blob("com.example.dr"));
        let ok_report = verify_macho(&ok_signed, &SignatureInputs::none()).unwrap();
        assert!(
            ok_report.is_valid(),
            "satisfied DR must verify: {:?}",
            ok_report.slices[0].errors
        );
        // Violated: DR demanding a different identifier -> hard error.
        let mut bad_signed =
            sign_macho_adhoc(&macho, "com.example.dr", None, None, None, false).unwrap();
        replace_requirements_child(&mut bad_signed, &ident_dr_blob("com.evil"));
        let report = verify_macho(&bad_signed, &SignatureInputs::none()).unwrap();
        assert!(
            report.slices[0]
                .errors
                .iter()
                .any(|e| e.contains("designated requirement not satisfied")),
            "errors: {:?}",
            report.slices[0].errors
        );
    }

    #[test]
    fn fat_code_limit_beyond_slice_is_rejected() {
        let fat = make_fat_macho(&[make_minimal_macho(), make_minimal_macho()], &[12, 12]);
        let macho = MachOFile::parse(fat).unwrap();
        assert_eq!(macho.slices().len(), 2);
        let creds = crate::macho::fixtures::test_signing_credentials();
        let mut signed =
            sign_any_macho(&macho, "com.example.fat", None, &creds, None, None, false).unwrap();

        // Trailing pad is load-bearing: without it the second slice's tail
        // equals its slice size, and pre-fix would take the same guard path
        // as post-fix (no observable difference).
        signed.extend_from_slice(&[0u8; 0x1000]);

        let m = MachOFile::parse(signed.clone()).unwrap();
        let s = &m.slices()[1];
        let slice_off = s.offset as usize;
        let slice_size = s.size as usize;
        let tail_len = signed.len() - slice_off;
        let sig_off = slice_off + s.code_sig_offset.unwrap() as usize;
        let sig_len = s.code_sig_size.unwrap() as usize;

        // Patch only the primary CD's codeLimit (slot 0x0000, SHA-1 in dual
        // mode — no hash rewrites, no page-size change, no CMS edits).
        let cd = entry_offset(&signed[sig_off..sig_off + sig_len], CSSLOT_CODEDIRECTORY)
            .expect("primary CD entry")
            + sig_off;
        let n_slots = u32::from_be_bytes(signed[cd + 28..cd + 32].try_into().unwrap()) as usize;
        let page_size = 1usize << signed[cd + 39];

        let c_prime = (slice_size + 0x100) as u32;
        assert!(
            (c_prime as usize) <= tail_len,
            "C' must fit the padded tail"
        );
        assert!(
            (c_prime as usize).div_ceil(page_size) != slice_size.div_ceil(page_size),
            "fixture precondition: C' must cross a page boundary of the slice"
        );
        signed[cd + 32..cd + 36].copy_from_slice(&c_prime.to_be_bytes());

        let report = verify_macho(&signed, &SignatureInputs::none()).unwrap();
        // Pre-fix the check runs over the tail, so the slot-count guard is
        // never reached and expected_slots = ceil(C'/page) mismatches the
        // stored count. Post-fix the slice-bounded region makes
        // code_limit > len fire the guard, which reports ceil(slice_size/page).
        // Metadata now reports the strongest (unpatched SHA-256 alternate) CD;
        // the patched primary's exact numbers are pinned through the error string.
        assert!(
            report.slices[1].errors.iter().any(|e| e.contains(&format!(
                "code slot count mismatch: {n_slots} stored vs {} pages computed",
                slice_size.div_ceil(page_size)
            ))),
            "errors: {:?}",
            report.slices[1].errors
        );
        assert!(
            report.slices[1]
                .errors
                .iter()
                .any(|e| e.contains("code slot count mismatch")),
            "oversized codeLimit must be reported, got {:?}",
            report.slices[1].errors
        );
    }

    #[test]
    fn zero_code_coverage_is_rejected() {
        let macho = MachOFile::parse(make_minimal_macho()).unwrap();
        let mut signed =
            sign_macho_adhoc(&macho, "com.example.zero", None, None, None, false).unwrap();

        // Collapse the primary CD to zero coverage: nCodeSlots = 0,
        // codeLimit = 0.
        let m = MachOFile::parse(signed.clone()).unwrap();
        let sl = &m.slices()[0];
        let sig_off = sl.code_sig_offset.unwrap() as usize;
        let sig_len = sl.code_sig_size.unwrap() as usize;
        let cd = entry_offset(&signed[sig_off..sig_off + sig_len], CSSLOT_CODEDIRECTORY)
            .expect("primary CD entry");
        let sb = &mut signed[sig_off..sig_off + sig_len];
        sb[cd + 28..cd + 32].copy_from_slice(&0u32.to_be_bytes()); // nCodeSlots
        sb[cd + 32..cd + 36].copy_from_slice(&0u32.to_be_bytes()); // codeLimit

        let report = verify_macho(&signed, &SignatureInputs::none()).unwrap();
        let slice = &report.slices[0];
        assert!(
            slice.errors.iter().any(|e| e.contains("zero code bytes")),
            "zero-coverage CD must be rejected, got {:?}",
            slice.errors
        );
        assert!(!report.is_valid());
    }

    fn cms_report_with_test_anchor(
        bin: &[u8],
        creds: &SigningCredentials,
    ) -> crate::crypto::cms_verify::CmsVerifyReport {
        let macho = MachOFile::parse(bin.to_vec()).unwrap();
        let slice = &macho.slices()[0];
        let (off, size) = (
            slice.code_sig_offset.unwrap() as usize,
            slice.code_sig_size.unwrap() as usize,
        );
        let sb = parse_superblob(&bin[off..off + size]).unwrap();
        let cds = emitted_cds(&sb);
        let (cd_sha1, cd_sha256) = cdhash_pair(&cds);
        let cd_sha256 = cd_sha256.expect("emitted SHA-256 CodeDirectory");
        crate::crypto::cms_verify::verify_code_signature_with_anchors(
            sb.cms.expect("signed superblob carries a CMS slot"),
            sb.code_directory.as_ref().expect("primary").raw(),
            cd_sha1.as_ref(),
            &cd_sha256,
            &crate::crypto::cms_verify::TrustAnchors::from_certificates(vec![creds
                .certificate
                .clone()]),
        )
        .unwrap()
    }

    #[test]
    fn verify_unsigned_binary_fails() {
        let report = verify_macho(&make_minimal_macho(), &SignatureInputs::none()).unwrap();
        assert!(!report.is_valid());
        assert!(report.slices[0]
            .errors
            .iter()
            .any(|e| e.contains("LC_CODE_SIGNATURE")));
    }

    #[test]
    fn verify_signed_binary_round_trip() {
        let creds = crate::macho::fixtures::test_signing_credentials();
        let signed = sign_round_trip(&creds, "com.example");
        let report = verify_macho(&signed, &SignatureInputs::none()).unwrap();
        // Production anchors to Apple's roots, so the self-signed fixture is
        // rejected for anchoring and nothing else; the injected root proves
        // full round-trip validity.
        assert!(
            !report.is_valid(),
            "errors: {:?}",
            report.slices.iter().map(|s| &s.errors).collect::<Vec<_>>()
        );
        let slice = &report.slices[0];
        assert!(slice.signed);
        assert!(!slice.adhoc);
        assert_eq!(slice.identifier.as_deref(), Some("com.example"));
        assert_eq!(slice.pages, PageCheck::Matched);
        let cms = slice.cms.as_ref().unwrap();
        assert_eq!(slice.errors.len(), 1);
        assert!(slice.errors[0].contains("not anchored to a trusted root"));
        assert!(
            cms.signature_ok
                && cms.message_digest_ok
                && cms.cdhash_v1_ok
                && cms.cdhash_v2_ok
                && cms.chain_ok
        );
        assert!(!cms.anchored);
        let injected = cms_report_with_test_anchor(&signed, &creds);
        assert!(injected.valid, "cms errors: {:?}", injected.errors);
        assert!(injected.anchored);
    }

    #[test]
    fn verify_signed_32bit_armv7_round_trip() {
        let creds = crate::macho::fixtures::test_signing_credentials();
        let macho = MachOFile::parse(crate::macho::fixtures::make_minimal_macho_32()).unwrap();
        assert!(!macho.slices()[0].is_64, "fixture must be 32-bit");
        let signed = sign_macho(&macho, "com.example", None, &creds, None, None, false).unwrap();
        assert_eq!(
            &signed[..4],
            &0xfeedfaceu32.to_le_bytes(),
            "32-bit magic must survive signing"
        );
        let report = verify_macho(&signed, &SignatureInputs::none()).unwrap();
        let slice = &report.slices[0];
        assert!(slice.signed, "32-bit slice must carry a signature");
        assert!(!slice.adhoc);
        assert_eq!(slice.pages, PageCheck::Matched, "{:?}", slice.errors);
        assert_eq!(
            slice.errors.len(),
            1,
            "self-signed fixture may fail anchoring only: {:?}",
            slice.errors
        );
        assert!(slice.errors[0].contains("not anchored to a trusted root"));
        let cms = slice.cms.as_ref().expect("cms report");
        assert!(
            cms.signature_ok
                && cms.message_digest_ok
                && cms.cdhash_v1_ok
                && cms.cdhash_v2_ok
                && cms.chain_ok
        );
        let injected = cms_report_with_test_anchor(&signed, &creds);
        assert!(injected.valid, "cms errors: {:?}", injected.errors);
    }

    #[test]
    fn verify_signed_fat_armv7_arm64_round_trip() {
        let creds = crate::macho::fixtures::test_signing_credentials();
        let fat = make_fat_macho(
            &[
                crate::macho::fixtures::make_minimal_macho_32(),
                make_minimal_macho(),
            ],
            &[12, 12],
        );
        let macho = MachOFile::parse(fat).unwrap();
        assert!(macho.is_fat() && macho.slices().len() == 2);
        let signed =
            sign_any_macho(&macho, "com.example.fat", None, &creds, None, None, false).unwrap();
        let report = verify_macho(&signed, &SignatureInputs::none()).unwrap();
        assert!(report.fat);
        assert_eq!(report.slices.len(), 2, "both slices must report");
        for (i, slice) in report.slices.iter().enumerate() {
            assert!(slice.signed, "slice {i} must be signed");
            assert_eq!(
                slice.pages,
                PageCheck::Matched,
                "slice {i}: {:?}",
                slice.errors
            );
            assert!(
                slice
                    .errors
                    .iter()
                    .all(|e| e.contains("not anchored to a trusted root")),
                "slice {i}: unexpected errors {:?}",
                slice.errors
            );
        }
        let cms = report.slices[0].cms.as_ref().expect("32-bit slice cms");
        assert!(
            cms.signature_ok
                && cms.message_digest_ok
                && cms.cdhash_v1_ok
                && cms.cdhash_v2_ok
                && cms.chain_ok,
            "32-bit slice cms: {:?}",
            cms
        );
    }

    #[test]
    fn sign_rejects_big_endian_32bit_with_typed_error() {
        let data = crate::macho::fixtures::make_minimal_macho_32_be();
        let macho = MachOFile::parse(data).expect("big-endian 32-bit fixture parses");
        let slice = &macho.slices()[0];
        assert!(!slice.is_64, "fixture must be 32-bit");
        let creds = crate::macho::fixtures::test_signing_credentials();
        let res = sign_any_macho(&macho, "com.example.be32", None, &creds, None, None, false);
        assert!(
            matches!(&res, Err(crate::Error::MachO(m)) if m.contains("big-endian")),
            "typed big-endian rejection required, got {:?}",
            res.as_ref().err()
        );
    }

    #[test]
    fn tampered_code_bytes_fail_page_hash() {
        let creds = crate::macho::fixtures::test_signing_credentials();
        let mut signed = sign_round_trip(&creds, "com.example");
        // Flip a byte inside the __text code region (file offset 0x1000).
        signed[0x1000] ^= 0x01;
        let report = verify_macho(&signed, &SignatureInputs::none()).unwrap();
        assert!(!report.is_valid());
        assert!(matches!(report.slices[0].pages, PageCheck::Mismatch { .. }));
    }

    #[test]
    fn tampered_signature_bytes_fail_cms() {
        let creds = crate::macho::fixtures::test_signing_credentials();
        let mut signed = sign_round_trip(&creds, "com.example");
        // Flip a bit inside the CMS signature slot (file offset = signature
        // region offset + superblob-relative blob offset).
        let macho = MachOFile::parse(signed.clone()).unwrap();
        let sig_off = macho.slices()[0].code_sig_offset.unwrap() as usize;
        let sb = signed_superblob(&signed);
        let cms_off = {
            let count = u32::from_be_bytes(sb[8..12].try_into().unwrap()) as usize;
            let mut found = None;
            for i in 0..count {
                let e = 12 + i * 8;
                let slot = u32::from_be_bytes(sb[e..e + 4].try_into().unwrap());
                if slot == CSSLOT_SIGNATURESLOT {
                    found = Some(u32::from_be_bytes(sb[e + 4..e + 8].try_into().unwrap()) as usize);
                }
            }
            found.expect("signature slot")
        };
        // Signature slot content starts with the 8-byte wrapper; flip the last byte of CMS.
        let cms_len = u32::from_be_bytes(sb[cms_off + 4..cms_off + 8].try_into().unwrap()) as usize;
        let last = sig_off + cms_off + cms_len - 1;
        assert_ne!(signed[last], 0xFF);
        signed[last] ^= 0x01;
        let report = verify_macho(&signed, &SignatureInputs::none()).unwrap();
        assert!(!report.is_valid());
        let slice = &report.slices[0];
        assert!(
            slice.errors.iter().any(|e| e.contains("CMS")) || !slice.cms.as_ref().unwrap().valid
        );
    }

    #[test]
    fn non_adhoc_truncated_cms_is_rejected() {
        let creds = crate::macho::fixtures::test_signing_credentials();
        let mut signed = sign_round_trip(&creds, "com.example.trunc");
        let m = MachOFile::parse(signed.clone()).unwrap();
        let sl = &m.slices()[0];
        let sig_off = sl.code_sig_offset.unwrap() as usize;
        let sig_len = sl.code_sig_size.unwrap() as usize;

        // Truncate the CMS child to its 8-byte blob-wrapper header, leaving
        // everything else intact.
        let sb = &mut signed[sig_off..sig_off + sig_len];
        let cms_off = entry_offset(sb, CSSLOT_SIGNATURESLOT).expect("CMS entry");
        sb[cms_off + 4..cms_off + 8].copy_from_slice(&8u32.to_be_bytes());

        let report = verify_macho(&signed, &SignatureInputs::none()).unwrap();
        let slice = &report.slices[0];
        assert!(!slice.adhoc, "credential-signed CD must stay non-ad-hoc");
        assert!(
            !report.is_valid(),
            "8-byte CMS wrapper on a non-ad-hoc CD must not verify: {:?}",
            slice.errors
        );
        assert!(
            slice.errors.iter().any(|e| e.contains("empty CMS wrapper")),
            "expected the empty-wrapper rejection, got {:?}",
            slice.errors
        );
    }

    #[test]
    fn special_slots_bind_info_and_resources() {
        let creds = crate::macho::fixtures::test_signing_credentials();
        let info = b"<?xml version=\"1.0\"?><plist><dict><key>CFBundleIdentifier</key><string>com.example</string></dict></plist>";
        let resources =
            b"<?xml version=\"1.0\"?><plist><dict><key>files2</key><dict/></dict></plist>";
        let macho = MachOFile::parse(make_minimal_macho()).unwrap();
        let signed = sign_macho_sha256_only(
            &macho,
            "com.example",
            None,
            &creds,
            Some(info),
            Some(resources),
            false,
        )
        .unwrap();

        // Correct contents verify.
        let inputs = SignatureInputs {
            info_plist: Some(info),
            code_resources: Some(resources),
        };
        let report = verify_macho(&signed, &inputs).unwrap();
        assert!(
            !report.is_valid(),
            "errors: {:?}",
            report.slices.iter().map(|s| &s.errors).collect::<Vec<_>>()
        );
        let slice = &report.slices[0];
        assert_eq!(slice.errors.len(), 1);
        assert!(slice.errors[0].contains("not anchored to a trusted root"));
        let cms = slice.cms.as_ref().unwrap();
        assert!(
            cms.signature_ok
                && cms.message_digest_ok
                && cms.cdhash_v1_ok
                && cms.cdhash_v2_ok
                && cms.chain_ok
        );
        assert!(!cms.anchored);
        let injected = cms_report_with_test_anchor(&signed, &creds);
        assert!(injected.valid, "cms errors: {:?}", injected.errors);
        assert!(injected.anchored);
        assert!(report.slices[0]
            .special_slots
            .iter()
            .all(|c| *c == SpecialSlotCheck::Matched));

        // A tampered Info.plist fails the -1 slot.
        let bad_inputs = SignatureInputs {
            info_plist: Some(b"tampered".as_slice()),
            code_resources: Some(resources),
        };
        let report = verify_macho(&signed, &bad_inputs).unwrap();
        assert!(!report.is_valid());
        assert!(report.slices[0]
            .errors
            .iter()
            .any(|e| e.contains("special slot -1")));
    }

    #[test]
    fn embedded_superblob_parses() {
        let creds = crate::macho::fixtures::test_signing_credentials();
        let signed = sign_round_trip(&creds, "com.example");
        let sb = signed_superblob(&signed);
        assert_eq!(&sb[0..4], &CSMAGIC_EMBEDDED_SIGNATURE.to_be_bytes());
        let parsed = parse_superblob(&sb).unwrap();
        assert!(parsed.code_directory.is_some());
        assert!(parsed.cms.is_some());
    }
    #[test]
    fn dual_signing_binds_cdhash_pair() {
        let creds = crate::macho::fixtures::test_signing_credentials();
        let macho = MachOFile::parse(make_minimal_macho()).unwrap();
        // sign_macho signs in DUAL mode (sha256_only=false): SHA-1 primary at slot 0,
        // SHA-256 alternate at 0x1000, CMS over the primary.
        let signed =
            sign_macho(&macho, "com.example.dual", None, &creds, None, None, false).unwrap();
        let report = verify_macho(&signed, &SignatureInputs::none()).unwrap();
        assert!(!report.is_valid());
        let slice = &report.slices[0];
        assert!(slice.signed && !slice.adhoc);
        // Pre-fix: cdhash v1/v2 errors inflate this beyond 1.
        assert_eq!(slice.errors.len(), 1, "errors: {:?}", slice.errors);
        assert!(slice.errors[0].contains("not anchored to a trusted root"));
        assert_eq!(slice.pages, PageCheck::Matched);
        let cms = slice.cms.as_ref().unwrap();
        assert!(cms.signature_ok && cms.message_digest_ok && cms.chain_ok);
        assert!(cms.cdhash_v1_ok, "v1 errors: {:?}", cms.errors);
        assert!(cms.cdhash_v2_ok, "v2 errors: {:?}", cms.errors);
        let injected = cms_report_with_test_anchor(&signed, &creds);
        assert!(injected.valid, "cms errors: {:?}", injected.errors);
        assert!(injected.anchored);
    }
    #[test]
    fn corrupt_alternate_cd_is_rejected_with_detail() {
        let macho = MachOFile::parse(make_minimal_macho()).unwrap();
        let mut signed =
            sign_macho_adhoc(&macho, "com.example.alt", None, None, None, false).unwrap();
        let m = MachOFile::parse(signed.clone()).unwrap();
        let sl = &m.slices()[0];
        let sig_off = sl.code_sig_offset.unwrap() as usize;
        let sig_len = sl.code_sig_size.unwrap() as usize;
        let cd = sig_off
            + entry_offset(
                &signed[sig_off..sig_off + sig_len],
                CSSLOT_ALTERNATE_CODEDIRECTORIES,
            )
            .unwrap();
        // Corrupt the child's hashType (byte 37) while preserving its magic.
        signed[cd + 37] = 0x07;
        // Pre-fix: the parse failure is silently dropped and this binary verifies.
        let report = verify_macho(&signed, &SignatureInputs::none()).unwrap();
        assert!(!report.is_valid());
        assert!(
            report.slices[0]
                .errors
                .iter()
                .any(|e| e.contains("unsupported CodeDirectory hash type 7")),
            "errors: {:?}",
            report.slices[0].errors
        );
    }

    #[test]
    fn tampered_alternate_page_hash_is_rejected() {
        let macho = MachOFile::parse(make_minimal_macho()).unwrap();
        let mut signed =
            sign_macho_adhoc(&macho, "com.example.alt2", None, None, None, false).unwrap();
        let m = MachOFile::parse(signed.clone()).unwrap();
        let sl = &m.slices()[0];
        let sig_off = sl.code_sig_offset.unwrap() as usize;
        let sig_len = sl.code_sig_size.unwrap() as usize;
        let cd = sig_off
            + entry_offset(
                &signed[sig_off..sig_off + sig_len],
                CSSLOT_ALTERNATE_CODEDIRECTORIES,
            )
            .unwrap();
        let hash_offset = u32::from_be_bytes(signed[cd + 16..cd + 20].try_into().unwrap()) as usize;
        signed[cd + hash_offset] ^= 0xFF; // first stored code hash of the SHA-256 alternate
        let report = verify_macho(&signed, &SignatureInputs::none()).unwrap();
        assert!(!report.is_valid());
        assert!(
            report.slices[0].errors.iter().any(|e| e
                .contains("alternate SHA-256 code page 0 hash mismatch (code region modified?)")),
            "errors: {:?}",
            report.slices[0].errors
        );
        // Metadata = strongest CD (the tampered SHA-256 alternate), so the field
        // itself now reflects the tamper:
        assert_eq!(
            report.slices[0].pages,
            PageCheck::Mismatch { page_index: 0 }
        );
    }

    #[test]
    fn bound_slots_fail_when_context_is_supplied() {
        let resources =
            b"<?xml version=\"1.0\"?><plist><dict><key>files2</key><dict/></dict></plist>";
        let macho = MachOFile::parse(make_minimal_macho()).unwrap();
        let signed =
            sign_macho_adhoc(&macho, "com.example", None, None, Some(resources), false).unwrap();
        // Context supplied (any SignatureInputs field present) but the bound -3 content
        // is not -> core-level failure, on primary and alternate alike:
        let inputs = SignatureInputs {
            info_plist: Some(b"not-the-fixture".as_slice()),
            code_resources: None,
        };
        let report = verify_macho(&signed, &inputs).unwrap();
        assert!(!report.is_valid());
        let errors = &report.slices[0].errors;
        assert!(
            errors
                .iter()
                .any(|e| e.contains("special slot -3 is bound but its content was not supplied")),
            "primary: {:?}",
            errors
        );
        // Dual output's alternate is the SHA-256 CD; its unavailable slot elevates tagged:
        assert!(
            errors.iter().any(|e| e.contains(
                "alternate SHA-256 special slot -3 is bound but its content was not supplied"
            )),
            "alternate: {:?}",
            errors
        );
        // With BOTH contents supplied the same binary has no slot finding:
        let ok = verify_macho(
            &signed,
            &SignatureInputs {
                info_plist: None,
                code_resources: Some(resources),
            },
        )
        .unwrap();
        assert!(ok.slices[0].errors.is_empty(), "{:?}", ok.slices[0].errors);
    }

    #[test]
    fn standalone_without_context_stays_silent() {
        // SignatureInputs::none() means "caller cannot supply -1/-3" (standalone
        // verification): bound-but-unavailable -1 stays NotChecked, the facade
        // (zsign verify_macho_file) reports it - core must not fail here.
        let info = b"<?xml version=\"1.0\"?><plist><dict><key>CFBundleIdentifier</key><string>com.example</string></dict></plist>";
        let macho = MachOFile::parse(make_minimal_macho()).unwrap();
        let signed =
            sign_macho_adhoc(&macho, "com.example", None, Some(info), None, false).unwrap();
        let report = verify_macho(&signed, &SignatureInputs::none()).unwrap();
        assert!(report.is_valid(), "{:?}", report.slices[0].errors);
        assert!(report.slices[0]
            .errors
            .iter()
            .all(|e| !e.contains("bound but")));
    }

    #[test]
    fn requirements_slot_failure_needs_no_context() {
        // SuperBlob-sourced slots (-2 here) need NO caller context: drop the 0x0002
        // child by renaming its index entry to an unknown slot and keep the nonzero
        // -2 hash -> unconditional core failure, even with SignatureInputs::none().
        let macho = MachOFile::parse(make_minimal_macho()).unwrap();
        let mut signed =
            sign_macho_adhoc(&macho, "com.example.bare", None, None, None, false).unwrap();
        let m = MachOFile::parse(signed.clone()).unwrap();
        let sl = &m.slices()[0];
        let sig_off = sl.code_sig_offset.unwrap() as usize;
        let count =
            u32::from_be_bytes(signed[sig_off + 8..sig_off + 12].try_into().unwrap()) as usize;
        for i in 0..count {
            let e = sig_off + 12 + i * 8;
            if u32::from_be_bytes(signed[e..e + 4].try_into().unwrap()) == CSSLOT_REQUIREMENTS {
                signed[e..e + 4].copy_from_slice(&0x0040u32.to_be_bytes());
            }
        }
        let report = verify_macho(&signed, &SignatureInputs::none()).unwrap();
        assert!(!report.is_valid());
        assert!(
            report.slices[0]
                .errors
                .iter()
                .any(|e| e.contains("special slot -2 is bound but its content was not supplied")),
            "errors: {:?}",
            report.slices[0].errors
        );
    }
    #[test]
    fn differing_xml_der_entitlements_are_rejected() {
        let mut signed = adhoc_ent_fixture();
        // Flip ONE character inside the DER child's value: same length -> still valid
        // DER, semantically different dictionary ("same" -> "sane").
        let der_off = child_off_in_signed(&signed, CSSLOT_DER_ENTITLEMENTS);
        let der_len =
            u32::from_be_bytes(signed[der_off + 4..der_off + 8].try_into().unwrap()) as usize;
        let pos = signed[der_off..der_off + der_len]
            .windows(4)
            .position(|w| w == b"same")
            .expect("value bytes in DER");
        signed[der_off + pos + 2] = b'n'; // "same" -> "sane", same length
                                          // Rebind -7 in both CDs so the integrity check stays green and the compare runs:
        let der_bytes = signed[der_off..der_off + der_len].to_vec();
        bind_special_slot(&mut signed, 7, Some(&der_bytes));
        let report = verify_macho(&signed, &SignatureInputs::none()).unwrap();
        assert!(
            report.slices[0]
                .errors
                .iter()
                .any(|e| e.contains("XML and DER entitlements dictionaries differ")),
            "errors: {:?}",
            report.slices[0].errors
        );
    }

    #[test]
    fn missing_der_for_modern_main_executable_is_rejected() {
        let mut signed = adhoc_ent_fixture();
        // Unbind -7 in both CDs (zero the stored hash): present-but-unbound must fail.
        bind_special_slot(&mut signed, 7, None);
        // Drop the 0x0007 index entry by renaming its slot type to an unknown value
        // (routing and the magic table ignore unknown slots; offsets stay valid).
        let m = MachOFile::parse(signed.clone()).unwrap();
        let sl = &m.slices()[0];
        let sig_off = sl.code_sig_offset.unwrap() as usize;
        let count =
            u32::from_be_bytes(signed[sig_off + 8..sig_off + 12].try_into().unwrap()) as usize;
        for i in 0..count {
            let e = sig_off + 12 + i * 8;
            if u32::from_be_bytes(signed[e..e + 4].try_into().unwrap()) == CSSLOT_DER_ENTITLEMENTS {
                signed[e..e + 4].copy_from_slice(&0x0040u32.to_be_bytes());
            }
        }
        let report = verify_macho(&signed, &SignatureInputs::none()).unwrap();
        assert!(
            report.slices[0].errors.iter().any(|e| e.contains(
                "XML entitlements bound (slot -5) without bound DER entitlements (slot -7)"
            )),
            "errors: {:?}",
            report.slices[0].errors
        );
    }
    #[test]
    fn bound_launch_constraint_without_blob_is_rejected() {
        let macho = MachOFile::parse(make_minimal_macho()).unwrap();
        let mut signed =
            sign_macho_adhoc(&macho, "com.example.lc", Some(ENT_PLIST), None, None, false).unwrap();
        // Grow the special-slot window 7 -> 8 on the primary CD. The new -8 region
        // [hashOffset-160, hashOffset-140) overlaps exec-seg header/ident bytes, which
        // are deterministically nonzero for this fixture => stored hash "bound";
        // no 0x0008 child exists => content unavailable => elevation must fire.
        let cd = child_off_in_signed(&signed, CSSLOT_CODEDIRECTORY);
        let n_special = u32::from_be_bytes(signed[cd + 24..cd + 28].try_into().unwrap());
        assert_eq!(
            n_special, 7,
            "fixture precondition: main + entitlements binds 7 slots"
        );
        signed[cd + 24..cd + 28].copy_from_slice(&8u32.to_be_bytes());
        let report = verify_macho(&signed, &SignatureInputs::none()).unwrap();
        assert!(
            report.slices[0]
                .errors
                .iter()
                .any(|e| e.contains("special slot -8 is bound but its content was not supplied")),
            "errors: {:?}",
            report.slices[0].errors
        );
    }

    /// Ad-hoc dual fixture with `__TEXT` vm exec-seg values; returns bytes with the
    /// PRIMARY CD's exec-seg header already patched by `f(base, limit, flags)`.
    fn adhoc_with_patched_execseg(f: impl FnOnce(u64, u64, u64) -> (u64, u64, u64)) -> Vec<u8> {
        let macho = MachOFile::parse(make_minimal_macho()).unwrap();
        let mut signed =
            sign_macho_adhoc(&macho, "com.example.xseg", None, None, None, false).unwrap();
        let cd = child_off_in_signed(&signed, CSSLOT_CODEDIRECTORY);
        let base = u64::from_be_bytes(signed[cd + 64..cd + 72].try_into().unwrap());
        let limit = u64::from_be_bytes(signed[cd + 72..cd + 80].try_into().unwrap());
        let flags = u64::from_be_bytes(signed[cd + 80..cd + 88].try_into().unwrap());
        let (b, l, g) = f(base, limit, flags);
        signed[cd + 64..cd + 72].copy_from_slice(&b.to_be_bytes());
        signed[cd + 72..cd + 80].copy_from_slice(&l.to_be_bytes());
        signed[cd + 80..cd + 88].copy_from_slice(&g.to_be_bytes());
        signed
    }

    #[test]
    fn exec_segment_range_mismatch_is_rejected() {
        let signed = adhoc_with_patched_execseg(|_, _, g| (0xDEAD_0000_0000_0000u64, 0x1000, g));
        let report = verify_macho(&signed, &SignatureInputs::none()).unwrap();
        assert!(
            report.slices[0]
                .errors
                .iter()
                .any(|e| e.contains("does not match __TEXT")),
            "errors: {:?}",
            report.slices[0].errors
        );
    }

    #[test]
    fn unknown_exec_segment_flag_bits_are_rejected() {
        let signed = adhoc_with_patched_execseg(|b, l, g| (b, l, g | 0x800));
        let report = verify_macho(&signed, &SignatureInputs::none()).unwrap();
        assert!(
            report.slices[0]
                .errors
                .iter()
                .any(|e| e.contains("unknown exec segment flags bits 0x800")),
            "errors: {:?}",
            report.slices[0].errors
        );
    }

    #[test]
    fn main_binary_flag_is_required_for_executables() {
        let signed = adhoc_with_patched_execseg(|b, l, _| (b, l, 0));
        let report = verify_macho(&signed, &SignatureInputs::none()).unwrap();
        assert!(
            report.slices[0]
                .errors
                .iter()
                .any(|e| e.contains("exec segment flags missing CS_EXECSEG_MAIN_BINARY")),
            "errors: {:?}",
            report.slices[0].errors
        );
    }

    #[test]
    fn jit_flag_without_entitlements_warns() {
        let signed = adhoc_with_patched_execseg(|b, l, g| (b, l, g | 0x40)); // CS_EXECSEG_JIT
        let report = verify_macho(&signed, &SignatureInputs::none()).unwrap();
        assert!(
            report.slices[0]
                .warnings
                .iter()
                .any(|w| w.contains("cannot be cross-checked without entitlements")),
            "warnings: {:?}",
            report.slices[0].warnings
        );
        assert!(
            report.is_valid(),
            "a warning must not invalidate: {:?}",
            report.slices[0].errors
        );
    }
}
