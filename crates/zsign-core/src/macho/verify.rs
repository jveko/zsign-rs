//! Mach-O-level code signature verification.
//!
//! Orchestrates the blob-level checks ([`codesign::verify`](super::super::codesign::verify))
//! and the CMS verifier ([`crypto::cms_verify`](super::super::crypto::cms_verify))
//! across every architecture slice of a Mach-O binary (single-arch or FAT).
//!
//! This is the "verify one binary" entry point used by the CLI and by
//! bundle-level verification; it never touches the filesystem.

use crate::codesign::constants::CSMAGIC_BLOBWRAPPER;
use crate::codesign::verify::{
    check_code_pages, check_special_slots, parse_superblob, self_consistent_blobs, CodeDirectory,
    PageCheck, SignatureInputs, SpecialSlotCheck, SuperBlob,
};
use crate::Result;
use sha1::Sha1;
use sha2::{Digest, Sha256};

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
        let (req_blob, ent_blob, der_blob) = self_consistent_blobs(&superblob, cd);
        let checks = check_special_slots(cd, inputs, req_blob, ent_blob, der_blob);
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
    // A follow-up will elevate NotChecked across every collected pair here.
    for (label, checks) in &pairs {
        for (i, check) in checks.iter().enumerate() {
            if *check == SpecialSlotCheck::Mismatch {
                report
                    .errors
                    .push(format!("{label}special slot -{} hash mismatch", i + 1));
            }
        }
    }
    report.pages = check_code_pages_in_file(strongest, data, slice);
    report.special_slots = strongest_slots.unwrap_or_default();

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
            return Ok(report);
        }

        let (cd_sha1, cd_sha256_opt) = cdhash_pair(&cds);
        match cd_sha256_opt {
            None => report.errors.push(
                "CMS signature present but no SHA-256 CodeDirectory to bind CDHash v2".to_string(),
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
    } else if primary.is_adhoc() {
        report.cms = Some(crate::crypto::cms_verify::adhoc_report());
    } else {
        report
            .errors
            .push("no CMS signature slot but not ad-hoc flagged".into());
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
/// file, using the CodeDirectory `codeLimit` as authoritative. A codeLimit
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
    #[test]
    fn debug_req_slot() {
        let creds = rsa_credentials();
        let macho = MachOFile::parse(make_minimal_macho()).unwrap();
        let signed =
            sign_macho_sha256_only(&macho, "com.example", None, &creds, None, None, false).unwrap();
        let m = MachOFile::parse(signed.clone()).unwrap();
        let sl = &m.slices()[0];
        let (off, sz) = (
            sl.code_sig_offset.unwrap() as usize,
            sl.code_sig_size.unwrap() as usize,
        );
        let sb = parse_superblob(&signed[off..off + sz]).unwrap();
        let cd = sb.code_directory.as_ref().unwrap();
        println!("n_special={}", cd.n_special_slots);
        for (idx, e) in sb.entries.iter().enumerate() {
            println!(
                "entry {idx}: slot 0x{:08x} blob_len={}",
                e.slot,
                e.blob.len()
            );
        }
        for k in 1..=cd.n_special_slots as usize {
            println!("slot -{k}: {}", hex(cd.special_slot_hash(k).unwrap_or(&[])));
        }
        for e in &sb.entries {
            if e.slot == 2 {
                println!(
                    "req blob: {} bytes sha256={}",
                    e.blob.len(),
                    hex(&sha2::Sha256::digest(e.blob))
                );
            }
        }
        fn hex(b: &[u8]) -> String {
            b.iter().map(|x| format!("{x:02x}")).collect()
        }
    }

    use super::*;
    use crate::codesign::constants::{
        CSMAGIC_EMBEDDED_SIGNATURE, CSSLOT_ALTERNATE_CODEDIRECTORIES, CSSLOT_CODEDIRECTORY,
        CSSLOT_SIGNATURESLOT,
    };
    use crate::crypto::cert::SigningKeyType;
    use crate::crypto::SigningCredentials;
    use crate::macho::fixtures::make_minimal_macho;
    use crate::macho::{
        sign_any_macho, sign_macho, sign_macho_adhoc, sign_macho_sha256_only, MachOFile,
    };
    use der::Decode;
    use sha2::{Digest, Sha256};
    use spki::{EncodePublicKey, SubjectPublicKeyInfoOwned};
    use std::str::FromStr;
    use std::time::Duration;
    use x509_cert::builder::{Builder, CertificateBuilder, Profile};
    use x509_cert::name::Name;
    use x509_cert::serial_number::SerialNumber;
    use x509_cert::time::Validity;

    fn rsa_credentials() -> SigningCredentials {
        let mut rng = rand::thread_rng();
        let key = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let signing_key = rsa::pkcs1v15::SigningKey::<Sha256>::new(key.clone());
        let subject = Name::from_str("CN=zsign verify test").unwrap();
        let serial = SerialNumber::from(7u32);
        let validity = Validity::from_now(Duration::from_secs(3600)).unwrap();
        let pub_der = key.to_public_key().to_public_key_der().unwrap();
        let pub_key = SubjectPublicKeyInfoOwned::from_der(pub_der.as_ref()).unwrap();
        let mut builder = CertificateBuilder::new(
            Profile::Leaf {
                issuer: subject.clone(),
                enable_key_agreement: false,
                enable_key_encipherment: false,
            },
            serial,
            validity,
            subject,
            pub_key,
            &signing_key,
        )
        .unwrap();
        builder
            .add_extension(&x509_cert::ext::pkix::ExtendedKeyUsage(vec![
                const_oid::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.3"),
            ]))
            .unwrap();
        let cert = builder.build::<rsa::pkcs1v15::Signature>().unwrap();
        SigningCredentials {
            certificate: cert,
            signing_key: SigningKeyType::Rsa(signing_key),
            cert_chain: vec![],
            team_id: Some("TESTTEAM".to_string()),
        }
    }

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

    fn build_two_slice_fat() -> Vec<u8> {
        let a = make_minimal_macho();
        let b = make_minimal_macho();
        let mut out = Vec::new();
        out.extend_from_slice(&0xcafebabeu32.to_be_bytes()); // FAT_MAGIC
        out.extend_from_slice(&2u32.to_be_bytes());
        for (offset, size) in [(0x1000u32, a.len() as u32), (0x3000u32, b.len() as u32)] {
            out.extend_from_slice(&0x0100_000cu32.to_be_bytes()); // CPU_TYPE_ARM64
            out.extend_from_slice(&0u32.to_be_bytes());
            out.extend_from_slice(&offset.to_be_bytes());
            out.extend_from_slice(&size.to_be_bytes());
            out.extend_from_slice(&12u32.to_be_bytes()); // align 2^12
        }
        out.resize(0x1000, 0);
        out.extend_from_slice(&a);
        out.resize(0x3000, 0);
        out.extend_from_slice(&b);
        out
    }

    #[test]
    fn fat_code_limit_beyond_slice_is_rejected() {
        let fat = build_two_slice_fat();
        let macho = MachOFile::parse(fat).unwrap();
        assert_eq!(macho.slices().len(), 2);
        let creds = rsa_credentials();
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
        let creds = rsa_credentials();
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
    fn tampered_code_bytes_fail_page_hash() {
        let creds = rsa_credentials();
        let mut signed = sign_round_trip(&creds, "com.example");
        // Flip a byte inside the __text code region (file offset 0x1000).
        signed[0x1000] ^= 0x01;
        let report = verify_macho(&signed, &SignatureInputs::none()).unwrap();
        assert!(!report.is_valid());
        assert!(matches!(report.slices[0].pages, PageCheck::Mismatch { .. }));
    }

    #[test]
    fn tampered_signature_bytes_fail_cms() {
        let creds = rsa_credentials();
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
        let creds = rsa_credentials();
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
        let creds = rsa_credentials();
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
        let creds = rsa_credentials();
        let signed = sign_round_trip(&creds, "com.example");
        let sb = signed_superblob(&signed);
        assert_eq!(&sb[0..4], &CSMAGIC_EMBEDDED_SIGNATURE.to_be_bytes());
        let parsed = parse_superblob(&sb).unwrap();
        assert!(parsed.code_directory.is_some());
        assert!(parsed.cms.is_some());
    }
    #[test]
    fn dual_signing_binds_cdhash_pair() {
        let creds = rsa_credentials();
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
        // Corrupt the child's hashType (byte 37) — the magic at [0..4) stays intact so
        // task 4's slot-magic table does not change this assertion's message.
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
}
