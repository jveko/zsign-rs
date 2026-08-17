//! Mach-O-level code signature verification.
//!
//! Orchestrates the blob-level checks ([`codesign::verify`](super::super::codesign::verify))
//! and the CMS verifier ([`crypto::cms_verify`](super::super::crypto::cms_verify))
//! across every architecture slice of a Mach-O binary (single-arch or FAT).
//!
//! This is the "verify one binary" entry point used by the CLI and by
//! bundle-level verification; it never touches the filesystem.

use crate::codesign::verify::{
    check_code_pages, check_special_slots, parse_superblob, self_consistent_blobs, CodeDirectory,
    PageCheck, SignatureInputs, SpecialSlotCheck, SuperBlob,
};
use crate::Result;
use sha1::{Digest, Sha1};

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

    let Some(sig) = data.get(sig_off..sig_off.saturating_add(sig_size)) else {
        report
            .errors
            .push("code signature region is out of file bounds".into());
        return Ok(report);
    };

    let Ok(superblob) = parse_superblob(sig) else {
        report
            .errors
            .push("embedded code signature is not a valid SuperBlob".into());
        return Ok(report);
    };

    let Some(primary) = superblob.code_directory.as_ref() else {
        report
            .errors
            .push("no primary CodeDirectory (slot 0x0)".into());
        return Ok(report);
    };

    report.signed = true;
    report.adhoc = primary.is_adhoc();
    report.identifier = primary.identifier().map(str::to_owned);

    // Code pages: hash the declared code region.
    report.pages = check_code_pages_in_file(primary, data, slice.offset);
    match &report.pages {
        PageCheck::Matched | PageCheck::Empty => {}
        PageCheck::Mismatch { page_index } => {
            report.errors.push(format!(
                "code page {page_index} hash mismatch (code region modified?)"
            ));
        }
        PageCheck::CountMismatch { stored, computed } => {
            report.errors.push(format!(
                "code slot count mismatch: {stored} stored vs {computed} pages computed"
            ));
        }
        PageCheck::UnsupportedPageSize { page_size_log2 } => {
            report.warnings.push(format!(
                "page size 2^{page_size_log2} is not 4096; code pages not checked"
            ));
        }
    }

    // Special slots: self-consistent blobs + caller-supplied file contents.
    let (req_blob, ent_blob, der_blob) = self_consistent_blobs(&superblob, primary);
    let slot_checks = check_special_slots(primary, inputs, req_blob, ent_blob, der_blob);
    report.special_slots = slot_checks.clone();
    for (i, check) in slot_checks.iter().enumerate() {
        if *check == SpecialSlotCheck::Mismatch {
            report
                .errors
                .push(format!("special slot -{} hash mismatch", i + 1));
        }
    }

    // CMS signature.
    if let Some(cms_blob) = superblob.cms {
        let cd_sha256: [u8; 32] = primary.cdhash_sha256();
        let cd_sha1 = alternate_sha1(&superblob);
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
    } else if primary.is_adhoc() {
        report.cms = Some(crate::crypto::cms_verify::adhoc_report());
    } else {
        report
            .errors
            .push("no CMS signature slot but not ad-hoc flagged".into());
    }

    Ok(report)
}

/// Page check variant that reads the region straight from the file at the
/// slice's offset, using the CodeDirectory `codeLimit` as authoritative.
fn check_code_pages_in_file(cd: &CodeDirectory<'_>, data: &[u8], offset: usize) -> PageCheck {
    let Some(tail) = data.get(offset..) else {
        return PageCheck::CountMismatch {
            stored: cd.n_code_slots as usize,
            computed: 0,
        };
    };
    check_code_pages(cd, tail)
}

/// SHA-1 digest of the alternate (SHA-1) CodeDirectory, for the CDHash v1
/// attribute binding — `Some` only for legacy dual output.
fn alternate_sha1(superblob: &SuperBlob<'_>) -> Option<[u8; 20]> {
    for cd in &superblob.alternate_code_directories {
        if cd.is_sha1() {
            return Some(Sha1::digest(cd.raw()).into());
        }
    }
    // A single-slot SHA-1 primary without an alternate (ancient output) — not
    // something we emit, but match the digest shape if encountered.
    if let Some(primary) = &superblob.code_directory {
        if primary.is_sha1() && superblob.alternate_code_directories.is_empty() {
            return Some(Sha1::digest(primary.raw()).into());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    #[test]
    fn debug_req_slot() {
        let creds = rsa_credentials();
        let macho = MachOFile::parse(make_minimal_macho()).unwrap();
        let signed =
            sign_macho_sha256_only(&macho, "com.example", None, &creds, None, None).unwrap();
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
    use crate::codesign::constants::{CSMAGIC_EMBEDDED_SIGNATURE, CSSLOT_SIGNATURESLOT};
    use crate::crypto::cert::SigningKeyType;
    use crate::crypto::SigningCredentials;
    use crate::macho::fixtures::make_minimal_macho;
    use crate::macho::{sign_macho_sha256_only, MachOFile};
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
            signing_key: SigningKeyType::Rsa(signing_key),
            cert_chain: vec![],
            team_id: Some("TESTTEAM".to_string()),
        }
    }

    fn sign_round_trip(creds: &SigningCredentials, ident: &str) -> Vec<u8> {
        let macho = MachOFile::parse(make_minimal_macho()).unwrap();
        sign_macho_sha256_only(&macho, ident, None, creds, None, None).unwrap()
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
        assert!(
            report.is_valid(),
            "errors: {:?}",
            report.slices.iter().map(|s| &s.errors).collect::<Vec<_>>()
        );
        let slice = &report.slices[0];
        assert!(slice.signed);
        assert!(!slice.adhoc);
        assert_eq!(slice.identifier.as_deref(), Some("com.example"));
        assert_eq!(slice.pages, PageCheck::Matched);
        let cms = slice.cms.as_ref().unwrap();
        assert!(cms.valid, "cms errors: {:?}", cms.errors);
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
        )
        .unwrap();

        // Correct contents verify.
        let inputs = SignatureInputs {
            info_plist: Some(info),
            code_resources: Some(resources),
        };
        let report = verify_macho(&signed, &inputs).unwrap();
        assert!(
            report.is_valid(),
            "errors: {:?}",
            report.slices.iter().map(|s| &s.errors).collect::<Vec<_>>()
        );
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
}
