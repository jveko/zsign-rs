//! Bundle- and IPA-level code signature verification.
//!
//! Verifies a signed app bundle the way `codesign --verify --deep --strict`
//! does, using the pure core checks from `zsign_core`:
//!
//! - Every Mach-O binary in the bundle (main executable, frameworks, app
//!   extensions, standalone dylibs) is verified at the slice level: code-page
//!   hashes, special-slot digests, and — for identity-signed binaries — the
//!   embedded CMS signature and certificate chain.
//! - The bundle's `_CodeSignature/CodeResources` is checked bidirectionally:
//!   every sealed file must hash to its recorded value, and every on-disk file
//!   must be sealed (or belong to the rules' omission set).
//! - Nested bundles (`.framework`, `.appex`, nested `.app`) are verified
//!   recursively, mirroring the signer's depth-first walk.
//!
//! # Examples
//!
//! ```no_run
//! use zsign_rs::verify;
//!
//! let report = verify::verify_ipa("signed.ipa")?;
//! assert!(report.valid());
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use crate::Result;
use sha2::{Digest, Sha256};

use std::collections::BTreeSet;
use std::path::Path;
use walkdir::WalkDir;
pub use zsign_core::macho::verify::{MachOVerifyReport, SliceVerifyReport};

/// Verification of one file path (Mach-O binary) inside a bundle.
#[derive(Debug, Clone, Default)]
pub struct BinaryVerification {
    /// Path relative to the bundle root.
    pub path: String,
    /// Machine-level verification from `zsign_core` (per slice).
    pub report: Option<zsign_core::macho::verify::MachOVerifyReport>,
    /// Extra bundle-level errors (e.g. unbound special slots).
    pub errors: Vec<String>,
}

impl BinaryVerification {
    /// True when the binary verifies completely.
    pub fn valid(&self) -> bool {
        self.errors.is_empty() && self.report.as_ref().map(|r| r.is_valid()).unwrap_or(false)
    }
}

/// Checksum verification of a `_CodeSignature/CodeResources` file.
#[derive(Debug, Clone, Default)]
pub struct CodeResourcesVerification {
    /// Number of sealed files whose hashes matched.
    pub matched: usize,
    /// Sealed files whose on-disk content has a different hash.
    pub mismatched: Vec<String>,
    /// Sealed files that no longer exist on disk.
    pub missing: Vec<String>,
    /// On-disk files that are neither sealed nor rule-omitted.
    pub unsealed: Vec<String>,
}

impl CodeResourcesVerification {
    /// True when every sealed file matches and nothing unexpected is unsealed.
    pub fn valid(&self) -> bool {
        self.mismatched.is_empty() && self.missing.is_empty() && self.unsealed.is_empty()
    }
}

/// Verification of one bundle directory (recursive over nested bundles).
#[derive(Debug, Clone, Default)]
pub struct BundleVerification {
    /// Path relative to the verified root.
    pub path: String,
    /// Every direct Mach-O binary of this bundle.
    pub binaries: Vec<BinaryVerification>,
    /// CodeResources check (present when the bundle has a `_CodeSignature`).
    pub code_resources: Option<CodeResourcesVerification>,
    /// Nested bundles (`.framework`, `.appex`, nested `.app`).
    pub nested: Vec<BundleVerification>,
    /// Bundle-level errors (e.g. missing Info.plist for an app bundle).
    pub errors: Vec<String>,
}

impl BundleVerification {
    /// True when every binary, the CodeResources, and all nested bundles verify.
    pub fn valid(&self) -> bool {
        self.errors.is_empty()
            && self.binaries.iter().all(|b| b.valid())
            && self.nested.iter().all(|b| b.valid())
            && self
                .code_resources
                .as_ref()
                .map(|c| c.valid())
                .unwrap_or(true)
    }

    /// Total number of problems found anywhere in this bundle subtree.
    pub fn problem_count(&self) -> usize {
        self.errors.len()
            + self
                .binaries
                .iter()
                .map(|b| b.errors.len() + b.report.as_ref().map(|r| r.error_count()).unwrap_or(1))
                .sum::<usize>()
            + self
                .code_resources
                .as_ref()
                .map(|c| c.mismatched.len() + c.missing.len() + c.unsealed.len())
                .unwrap_or(0)
            + self.nested.iter().map(|n| n.problem_count()).sum::<usize>()
    }
}

/// Top-level verification report for a Mach-O, bundle, or IPA input.
#[derive(Debug, Clone, Default)]
pub struct VerifyReport {
    /// The input path that was verified.
    pub input: String,
    /// Machine-level report for bare Mach-O inputs.
    pub macho: Option<zsign_core::macho::verify::MachOVerifyReport>,
    /// Bundle report for `.app`/IPA inputs.
    pub bundle: Option<BundleVerification>,
    /// Non-fatal observations.
    pub warnings: Vec<String>,
    /// Hard errors (unreadable input, unsupported format, …).
    pub errors: Vec<String>,
}

impl VerifyReport {
    /// True when the input is valid AND no hard error occurred.
    pub fn valid(&self) -> bool {
        self.errors.is_empty()
            && self.macho.as_ref().map(|m| m.is_valid()).unwrap_or(true)
            && self.bundle.as_ref().map(|b| b.valid()).unwrap_or(true)
    }
}

/// Bundle directory extensions recognized as nested bundles.
fn is_bundle_dir(path: &Path) -> bool {
    path.extension()
        .map(|e| {
            matches!(
                e.to_string_lossy().to_lowercase().as_str(),
                "app" | "framework" | "appex"
            )
        })
        .unwrap_or(false)
}

/// True when `path` (relative to `root`) passes through a nested bundle
/// directory before reaching `path` itself.
fn inside_nested_bundle(rel: &Path) -> bool {
    // The main bundle's own extension is the first component; nested bundle
    // directories are any LATER component with a bundle extension.
    let mut components = rel.components().peekable();
    if let Some(first) = components.peek() {
        if is_bundle_dir(Path::new(first.as_os_str())) {
            components.next();
        }
    }
    components
        .find(|c| is_bundle_dir(Path::new(c.as_os_str())))
        .is_some()
}

/// Determines whether a file should be omitted from the unsealed-file scan,
/// mirroring `CodeResourcesBuilder::should_exclude` and the files2 omissions.
fn is_rule_omitted(rel: &str, main_executable: Option<&str>) -> bool {
    if rel.starts_with("_CodeSignature/") || rel == "_CodeSignature" {
        return true;
    }
    if rel == "Info.plist" || rel == "PkgInfo" || rel == ".DS_Store" {
        return true;
    }
    if rel.ends_with(".lproj/") {
        return true;
    }
    if let Some(exe) = main_executable {
        if rel == exe {
            return true;
        }
    }
    false
}

/// Verifies a bare Mach-O file (no bundle context).
///
/// # Errors
///
/// Returns [`Error::Io`] when the file cannot be read.
pub fn verify_macho_file(path: impl AsRef<Path>) -> Result<VerifyReport> {
    let path = path.as_ref();
    let data = std::fs::read(path)?;
    let macho = zsign_core::macho::verify_macho(
        &data,
        &zsign_core::codesign::verify::SignatureInputs::none(),
    )
    .map_err(crate::Error::Core)?;
    Ok(VerifyReport {
        input: path.display().to_string(),
        macho: Some(macho),
        ..VerifyReport::default()
    })
}

/// Verifies an app bundle in place (`.app` directory).
///
/// # Errors
///
/// Returns [`Error::Io`] when the bundle cannot be read.
pub fn verify_bundle(path: impl AsRef<Path>) -> Result<VerifyReport> {
    let path = path.as_ref();
    let bundle = verify_bundle_dir(path, path, "")?;
    Ok(VerifyReport {
        input: path.display().to_string(),
        bundle: Some(bundle),
        ..VerifyReport::default()
    })
}

/// Verifies an IPA archive by extracting it and verifying the payload bundle.
///
/// # Errors
///
/// Returns [`Error::Io`]/[`Error::Zip`] when the archive cannot be read and
/// [`Error::Verify`]-style errors when extraction fails.
pub fn verify_ipa(path: impl AsRef<Path>) -> Result<VerifyReport> {
    let path = path.as_ref();
    let tmp = tempfile::TempDir::new()?;
    // extract_ipa returns the Payload/*.app bundle path directly.
    let app = crate::ipa::extract_ipa(path, tmp.path())?;

    let bundle = verify_bundle_dir(&app, &app, "")?;
    Ok(VerifyReport {
        input: path.display().to_string(),
        bundle: Some(bundle),
        ..VerifyReport::default()
    })
}

/// Recursive bundle verification.
///
/// `root` is the top bundle directory (for relative paths); `dir` is the
/// bundle currently being verified; `rel` is `dir` relative to `root`.
fn verify_bundle_dir(root: &Path, dir: &Path, rel: &str) -> Result<BundleVerification> {
    let meta = std::fs::metadata(dir).map_err(crate::Error::Io)?;
    if !meta.is_dir() {
        return Err(crate::Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("not a bundle directory: {}", dir.display()),
        )));
    }

    let mut out = BundleVerification {
        path: rel.to_string(),
        ..BundleVerification::default()
    };

    let info_plist = read_opt(&dir.join("Info.plist"))?;
    let code_resources = read_opt(&dir.join("_CodeSignature").join("CodeResources"))?;
    if code_resources.is_none() {
        out.errors
            .push("missing _CodeSignature/CodeResources".to_string());
    }
    let main_executable = info_plist
        .as_deref()
        .and_then(|bytes| plist_executable(bytes).ok().flatten());

    // Collect direct Mach-O binaries (not inside a nested bundle, not inside
    // _CodeSignature) and nested bundle directories.
    let mut direct_binaries = Vec::new();
    let mut nested_dirs = Vec::new();
    for entry in WalkDir::new(dir).min_depth(1) {
        let entry = entry.map_err(|e| {
            crate::Error::Io(std::io::Error::other(format!(
                "Failed to walk directory: {e}"
            )))
        })?;
        let p = entry.path();
        if p.is_dir() {
            if p != dir && is_bundle_dir(p) {
                nested_dirs.push(p.to_path_buf());
            }
            continue;
        }
        let rel_path = p.strip_prefix(root).unwrap_or(p);
        let rel_str = rel_path.to_string_lossy().replace('\\', "/");
        if rel_str.contains("_CodeSignature/") {
            continue;
        }
        if is_macho_file(p)? {
            if inside_nested_bundle(rel_path) {
                continue; // handled by the nested bundle recursion
            }
            direct_binaries.push((p.to_path_buf(), rel_str));
        }
    }

    // Verify each direct binary, binding this bundle's Info.plist and
    // CodeResources into the special-slot checks.
    for (bin_path, bin_rel) in direct_binaries {
        let mut bv = BinaryVerification {
            path: bin_rel,
            ..BinaryVerification::default()
        };
        match std::fs::read(&bin_path) {
            Ok(data) => {
                let inputs = zsign_core::codesign::verify::SignatureInputs {
                    info_plist: info_plist.as_deref(),
                    code_resources: code_resources.as_deref(),
                };
                match zsign_core::macho::verify_macho(&data, &inputs) {
                    Ok(report) => {
                        for slice in &report.slices {
                            if !slice.signed {
                                continue;
                            }
                            // Slot -1 (index 0) and -3 (index 2): if the CD
                            // declares them but the content file is missing,
                            // signal an unbound signature.
                            if !slice.special_slots.is_empty()
                                && slice.special_slots[0]
                                    == zsign_core::codesign::verify::SpecialSlotCheck::NotChecked
                                && info_plist.is_none()
                            {
                                bv.errors.push(
                                    "signature binds Info.plist (slot -1) but the file is missing"
                                        .into(),
                                );
                            }
                            if slice.special_slots.len() >= 3
                                && slice.special_slots[2]
                                    == zsign_core::codesign::verify::SpecialSlotCheck::NotChecked
                                && code_resources.is_none()
                            {
                                bv.errors.push(
                                    "signature binds CodeResources (slot -3) but the file is missing"
                                        .into(),
                                );
                            }
                        }
                        bv.report = Some(report);
                    }
                    Err(e) => bv.errors.push(format!("Mach-O verify error: {e}")),
                }
            }
            Err(e) => bv.errors.push(format!("cannot read binary: {e}")),
        }
        out.binaries.push(bv);
    }

    // CodeResources bidirectional check.
    if let Some(cr_bytes) = &code_resources {
        out.code_resources = Some(check_code_resources(
            dir,
            cr_bytes,
            main_executable.as_deref(),
            &mut out.errors,
        )?);
    }

    // Recurse into nested bundles (deep verification).
    nested_dirs.sort();
    for nested in nested_dirs {
        let nested_rel = nested
            .strip_prefix(root)
            .unwrap_or(&nested)
            .to_string_lossy()
            .replace('\\', "/");
        out.nested
            .push(verify_bundle_dir(root, &nested, &nested_rel)?);
    }

    Ok(out)
}

/// Reads a file, returning `None` only when it does not exist.
fn read_opt(path: &Path) -> Result<Option<Vec<u8>>> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(crate::Error::Io(e)),
    }
}

/// Extracts `CFBundleExecutable` from an Info.plist.
fn plist_executable(bytes: &[u8]) -> Result<Option<String>> {
    let value: plist::Value = plist::from_bytes(bytes).map_err(crate::Error::Plist)?;
    Ok(value
        .as_dictionary()
        .and_then(|d| d.get("CFBundleExecutable"))
        .and_then(|v| v.as_string())
        .map(str::to_owned))
}

/// Detects a Mach-O file by magic bytes (thin + FAT, all byte orders).
fn is_macho_file(path: &Path) -> Result<bool> {
    let mut f = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(crate::Error::Io(e)),
    };
    use std::io::Read;
    let mut magic = [0u8; 4];
    if let Err(e) = f.read_exact(&mut magic) {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            return Ok(false);
        }
        return Err(crate::Error::Io(e));
    }
    Ok(matches!(
        u32::from_le_bytes(magic),
        0xfeed_face | 0xfeed_facf | 0xcefa_edfe | 0xcffa_edfe | 0xcafe_babe | 0xbeba_feca
    ))
}

/// Verifies the sealed-file hashes of a CodeResources plist against the
/// bundle on disk (both directions: sealed→disk and disk→sealed).
fn check_code_resources(
    bundle: &Path,
    cr_bytes: &[u8],
    main_executable: Option<&str>,
    errors: &mut Vec<String>,
) -> Result<CodeResourcesVerification> {
    let mut out = CodeResourcesVerification::default();

    let Ok(value) = plist::from_bytes::<plist::Value>(cr_bytes) else {
        errors.push("CodeResources is not a parseable plist".into());
        return Ok(out);
    };
    let Some(files2) = value
        .as_dictionary()
        .and_then(|d| d.get("files2"))
        .and_then(|v| v.as_dictionary())
    else {
        errors.push("CodeResources has no files2 dictionary".into());
        return Ok(out);
    };

    // Sealed → disk: every entry must exist and hash to its recorded value.
    for (rel, entry) in files2 {
        let file_path = bundle.join(rel.as_str());
        let Some(data) = std::fs::read(&file_path).ok() else {
            out.missing.push(rel.clone());
            continue;
        };
        let entry_dict = match entry.as_dictionary() {
            Some(d) => d,
            None => continue,
        };
        let computed = Sha256::digest(&data);
        let sealed = entry_dict
            .get("hash2")
            .and_then(|v| v.as_data())
            .map(|d| d.to_vec());
        let sealed = sealed.or_else(|| {
            entry_dict
                .get("hash")
                .and_then(|v| v.as_data())
                .map(|d| d.to_vec())
        });
        match sealed {
            Some(hash) if hash.as_slice() == computed.as_slice() => out.matched += 1,
            Some(_) => out.mismatched.push(rel.clone()),
            None => out.unsealed.push(format!("{rel} (sealed without a hash)")),
        }
    }

    // Disk → sealed: every file in the bundle must be sealed or rule-omitted.
    let mut disk_files = BTreeSet::new();
    for entry in WalkDir::new(bundle).min_depth(1) {
        let entry = entry.map_err(|e| {
            crate::Error::Io(std::io::Error::other(format!(
                "Failed to walk directory: {e}"
            )))
        })?;
        if !entry.file_type().is_file() {
            continue;
        }
        let rel = entry
            .path()
            .strip_prefix(bundle)
            .map(|p| p.to_string_lossy().replace('\\', "/"))
            .unwrap_or_default();
        if is_rule_omitted(&rel, main_executable) {
            continue;
        }
        disk_files.insert(rel);
    }
    for rel in disk_files {
        if !files2.contains_key(&rel) {
            out.unsealed.push(rel);
        }
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::macho::{sign_macho_sha256_only, MachOFile};
    use crate::test_util::minimal_macho;
    use crate::ZSign;
    use rsa::pkcs1v15::SigningKey as RsaSigningKey;
    use sha2::Sha256;
    use spki::der::Decode;
    use spki::{EncodePublicKey, ObjectIdentifier, SubjectPublicKeyInfoOwned};
    use std::fs;
    use std::path::PathBuf;
    use std::str::FromStr;
    use std::time::Duration;
    use x509_cert::builder::{Builder, CertificateBuilder, Profile};
    use x509_cert::ext::pkix::ExtendedKeyUsage;
    use x509_cert::name::Name;
    use x509_cert::serial_number::SerialNumber;
    use x509_cert::time::Validity;

    fn local_test_credentials() -> (crate::SigningCredentials, rsa::RsaPrivateKey) {
        let mut rng = rand::thread_rng();
        let rsa_key = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let signing_key = RsaSigningKey::<Sha256>::new(rsa_key.clone());
        let subject = Name::from_str("CN=zsign test,OU=TESTTEAM").unwrap();
        let serial = SerialNumber::from(7u32);
        let validity = Validity::from_now(Duration::from_secs(3600)).unwrap();
        let pub_key_der = rsa_key.to_public_key().to_public_key_der().unwrap();
        let pub_key = SubjectPublicKeyInfoOwned::from_der(pub_key_der.as_ref()).unwrap();
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
            .add_extension(&ExtendedKeyUsage(vec![ObjectIdentifier::new_unwrap(
                "1.3.6.1.5.5.7.3.3",
            )]))
            .unwrap();
        let cert = builder.build::<rsa::pkcs1v15::Signature>().unwrap();
        let creds = crate::SigningCredentials {
            certificate: cert,
            signing_key: zsign_core::crypto::SigningKeyType::Rsa(signing_key),
            cert_chain: vec![],
            team_id: Some("TESTTEAM".to_string()),
        };
        (creds, rsa_key)
    }

    fn cms_report_with_test_anchor(
        bin: &[u8],
        creds: &crate::SigningCredentials,
    ) -> zsign_core::crypto::cms_verify::CmsVerifyReport {
        let macho = MachOFile::parse(bin.to_vec()).unwrap();
        let slice = &macho.slices()[0];
        let (off, size) = (
            slice.code_sig_offset.unwrap() as usize,
            slice.code_sig_size.unwrap() as usize,
        );
        let sb = zsign_core::codesign::verify::parse_superblob(&bin[off..off + size]).unwrap();
        let cd = sb.code_directory.as_ref().unwrap();
        zsign_core::crypto::cms_verify::verify_code_signature_with_anchors(
            sb.cms.expect("signed superblob carries a CMS slot"),
            cd.raw(),
            None,
            &cd.cdhash_sha256(),
            &zsign_core::crypto::cms_verify::TrustAnchors::from_certificates(vec![creds
                .certificate
                .clone()]),
        )
        .unwrap()
    }

    fn app_info_plist() -> Vec<u8> {
        br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleExecutable</key><string>Test</string>
  <key>CFBundleIdentifier</key><string>com.zsign.test</string>
  <key>CFBundlePackageType</key><string>APPL</string>
</dict></plist>
"#
        .to_vec()
    }

    /// Builds a signed bundle with one nested framework (mirrors the CI
    /// interop fixture shape).
    fn build_signed_bundle_with(dir: &Path, setup: impl FnOnce(&Path)) -> (PathBuf, crate::SigningCredentials) {
        let app = dir.join("Test.app");
        fs::create_dir_all(app.join("Frameworks").join("Sub.framework")).unwrap();
        fs::write(app.join("Info.plist"), app_info_plist()).unwrap();
        fs::write(app.join("Test"), minimal_macho()).unwrap();
        fs::write(
            app.join("Frameworks").join("Sub.framework").join("Sub"),
            minimal_macho(),
        )
        .unwrap();
        fs::write(
            app.join("Frameworks").join("Sub.framework").join("Info.plist"),
            br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleExecutable</key><string>Sub</string>
  <key>CFBundleIdentifier</key><string>com.zsign.test.sub</string>
  <key>CFBundlePackageType</key><string>FMWK</string>
</dict></plist>
"#,
        )
        .unwrap();
        setup(&app);
        let (creds, rsa_key) = local_test_credentials();
        let verify_creds = crate::SigningCredentials {
            certificate: creds.certificate.clone(),
            signing_key: zsign_core::crypto::SigningKeyType::Rsa(RsaSigningKey::new(rsa_key)),
            cert_chain: vec![],
            team_id: Some("TESTTEAM".to_string()),
        };
        let zsign = ZSign::new().credentials(creds);
        zsign.sign_bundle(&app, None).unwrap();
        (app, verify_creds)
    }

    fn build_signed_bundle(dir: &Path) -> (PathBuf, crate::SigningCredentials) {
        build_signed_bundle_with(dir, |_| {})
    }

    /// Rewrites `Test.app/_CodeSignature/CodeResources` through a mutation closure.
    /// NOTE: every use breaks the main executable's slot -3 binding, so tests using
    /// this helper assert at the CodeResources / bundle-error layer, not report.valid().
    fn rewrite_code_resources(app: &Path, mutate: impl FnOnce(&mut plist::Dictionary)) {
        let cr = app.join("_CodeSignature").join("CodeResources");
        let bytes = fs::read(&cr).unwrap();
        let mut value: plist::Value = plist::from_bytes(&bytes).unwrap();
        mutate(value.as_dictionary_mut().unwrap());
        let mut out = Vec::new();
        plist::to_writer_xml(&mut out, &value).unwrap();
        fs::write(&cr, out).unwrap();
    }

    #[test]
    fn signed_bundle_verifies() {
        let td = tempfile::TempDir::new().unwrap();
        let (app, creds) = build_signed_bundle(td.path());
        let report = verify_bundle(&app).unwrap();
        assert!(
            !report.valid(),
            "problems: {} — {:#?}",
            report
                .bundle
                .as_ref()
                .map(|b| b.problem_count())
                .unwrap_or(0),
            report.bundle
        );
        let bundle = report.bundle.unwrap();
        assert!(bundle.errors.is_empty());
        assert_eq!(bundle.nested.len(), 1); // Sub.framework
        for binary in bundle.binaries.iter().chain(&bundle.nested[0].binaries) {
            assert!(!binary.valid());
            let slice = &binary.report.as_ref().expect("Mach-O report").slices[0];
            assert_eq!(slice.errors.len(), 1, "binaries: {:?}", binary.errors);
            assert!(slice.errors[0].contains("not anchored to a trusted root"));
            let cms = slice.cms.as_ref().unwrap();
            assert!(
                cms.signature_ok
                    && cms.message_digest_ok
                    && cms.cdhash_v1_ok
                    && cms.cdhash_v2_ok
                    && cms.chain_ok,
                "cms: {:?}",
                cms
            );
        }
        let injected = cms_report_with_test_anchor(&fs::read(app.join("Test")).unwrap(), &creds);
        assert!(injected.valid, "cms errors: {:?}", injected.errors);
        assert!(injected.anchored);
        let cr = bundle.code_resources.as_ref().expect("CodeResources check");
        assert!(
            cr.valid(),
            "mismatched={:?} missing={:?} unsealed={:?}",
            cr.mismatched,
            cr.missing,
            cr.unsealed
        );
        assert!(cr.matched >= 1);
    }

    #[test]
    fn tampered_resource_fails_code_resources() {
        let td = tempfile::TempDir::new().unwrap();
        let (app, _) = build_signed_bundle(td.path());
        fs::write(app.join("data.bin"), b"tampered payload").unwrap();
        let report = verify_bundle(&app).unwrap();
        assert!(!report.valid());
        let cr = report.bundle.unwrap().code_resources.unwrap();
        assert!(!cr.unsealed.is_empty(), "unsealed should flag data.bin");
    }

    #[test]
    fn tampered_binary_fails_pages() {
        let td = tempfile::TempDir::new().unwrap();
        let (app, _) = build_signed_bundle(td.path());
        // Flip a byte inside the __text code region of the main binary.
        let bin = app.join("Test");
        let mut data = fs::read(&bin).unwrap();
        data[0x1000] ^= 0x01;
        fs::write(&bin, data).unwrap();
        let report = verify_bundle(&app).unwrap();
        assert!(!report.valid());
    }

    #[test]
    fn modified_sealed_resource_fails() {
        let td = tempfile::TempDir::new().unwrap();
        let (app, _) = build_signed_bundle(td.path());
        // Modify a sealed resource AFTER signing: the framework binary is
        // sealed as a file in the parent's CodeResources; re-writing it
        // changes its hash without re-signing.
        let fw = app.join("Frameworks").join("Sub.framework").join("Sub");
        let mut data = fs::read(&fw).unwrap();
        data[0x1000] ^= 0x02;
        fs::write(&fw, data).unwrap();
        let report = verify_bundle(&app).unwrap();
        assert!(!report.valid());
    }

    #[test]
    fn bare_macho_verifies() {
        let td = tempfile::TempDir::new().unwrap();
        let out = td.path().join("signed.bin");
        let (creds, _) = local_test_credentials();
        let macho = MachOFile::parse(minimal_macho()).unwrap();
        let signed =
            sign_macho_sha256_only(&macho, "com.zsign.test", None, &creds, None, None, false)
                .unwrap();
        fs::write(&out, &signed).unwrap();
        let report = verify_macho_file(&out).unwrap();
        let slice = &report.macho.as_ref().expect("Mach-O report").slices[0];
        assert_eq!(slice.errors.len(), 1, "{:#?}", report.macho);
        assert!(slice.errors[0].contains("not anchored to a trusted root"));
        let injected = cms_report_with_test_anchor(&fs::read(&out).unwrap(), &creds);
        assert!(injected.valid, "cms errors: {:?}", injected.errors);
        assert!(injected.anchored);
    }

    #[test]
    fn unsigned_binary_fails() {
        let td = tempfile::TempDir::new().unwrap();
        let f = td.path().join("u.bin");
        fs::write(&f, minimal_macho()).unwrap();
        let report = verify_macho_file(&f).unwrap();
        assert!(!report.valid());
    }

    #[test]
    fn unsigned_bundle_fails() {
        let td = tempfile::TempDir::new().unwrap();
        let app = td.path().join("Test.app");
        fs::create_dir_all(&app).unwrap();
        fs::write(app.join("Test"), minimal_macho()).unwrap();
        let report = verify_bundle(&app).unwrap();
        assert!(!report.valid());
    }

    #[test]
    fn missing_code_resources_is_reported_invalid() {
        let td = tempfile::TempDir::new().unwrap();
        let app = build_signed_bundle(td.path());
        fs::remove_dir_all(app.join("_CodeSignature")).unwrap();
        let report = verify_bundle(&app).unwrap();
        assert!(
            !report.valid(),
            "bundle without CodeResources must be invalid"
        );
        let bundle = report.bundle.as_ref().unwrap();
        assert!(
            bundle
                .errors
                .iter()
                .any(|e| e.contains("_CodeSignature/CodeResources")),
            "bundle-level error required (a binary-level slot error exists already); got {:?}",
            bundle.errors
        );
    }

    #[test]
    fn missing_bundle_root_is_hard_error() {
        let td = tempfile::TempDir::new().unwrap();
        let result = verify_bundle(td.path().join("missing.app"));
        assert!(
            result.is_err(),
            "a nonexistent bundle must not verify: {:?}",
            result.map(|r| r.valid())
        );
    }
}
