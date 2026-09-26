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
//! - Nested-code bundles recognized by
//!   [`crate::bundle::is_nested_bundle_dir`] are verified recursively,
//!   mirroring the signer's depth-first walk.
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
use sha1::Sha1;
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
    /// Number of sealed entries verified (hash match or symlink target match).
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
    /// Nested-code bundles recognized by [`crate::bundle::is_nested_bundle_dir`].
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

/// True when any ancestor component of `rel` (relative to the bundle dir
/// `dir` currently being verified) names a nested-code bundle directory.
/// With `ignore_last` the final component is exempt, which lets a
/// directory entry itself be the bundle while its ancestors must not be.
fn has_nested_bundle_component(dir: &Path, rel: &Path, ignore_last: bool) -> bool {
    let mut components: Vec<_> = rel.components().collect();
    if ignore_last {
        components.pop();
    }
    let mut prefix = dir.to_path_buf();
    components.iter().any(|c| {
        prefix.push(c);
        crate::bundle::is_nested_bundle_dir(&prefix)
    })
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RuleAction {
    Include,
    Omit,
    Optional,
}
enum RulePattern {
    Always,
    Contains(&'static str),
    Locversion,
    Prefix(&'static str),
    Exact(&'static str),
    Dsym,
    DsStore,
}
struct Rule {
    pattern: RulePattern,
    action: RuleAction,
    weight: f64,
}

fn compile_pattern(pattern: &str) -> Option<RulePattern> {
    Some(match pattern {
        "^.*" => RulePattern::Always,
        "^.*\\.lproj/" => RulePattern::Contains(".lproj/"),
        "^.*\\.lproj/locversion.plist$" => RulePattern::Locversion,
        "^Base\\.lproj/" => RulePattern::Prefix("Base.lproj/"),
        "^version\\.plist$" => RulePattern::Exact("version.plist"),
        ".*\\.dSYM($|/)" => RulePattern::Dsym,
        "^(.*/)?\\.DS_Store$" => RulePattern::DsStore,
        "^Info\\.plist$" => RulePattern::Exact("Info.plist"),
        "^PkgInfo$" => RulePattern::Exact("PkgInfo"),
        "^embedded\\.provisionprofile$" => RulePattern::Exact("embedded.provisionprofile"),
        _ => return None,
    })
}

fn pattern_matches(pattern: &RulePattern, rel: &str) -> bool {
    match pattern {
        RulePattern::Always => true,
        RulePattern::Contains(needle) => rel.contains(needle),
        RulePattern::Locversion => {
            // ^.*\.lproj/locversion.plist$: the dot before "plist" is
            // unescaped in the builder's emitted pattern, so it stands for
            // exactly one arbitrary character (regex ".", newline excluded).
            // Never narrow it to a literal dot.
            rel.match_indices(".lproj/locversion").any(|(idx, _)| {
                let rest = &rel[idx + ".lproj/locversion".len()..];
                let mut chars = rest.chars();
                matches!(chars.next(), Some(c) if c != '\n') && chars.as_str() == "plist"
            })
        }
        RulePattern::Prefix(prefix) => rel.starts_with(prefix),
        RulePattern::Exact(text) => rel == *text,
        RulePattern::Dsym => rel.ends_with(".dSYM") || rel.contains(".dSYM/"),
        RulePattern::DsStore => rel == ".DS_Store" || rel.ends_with("/.DS_Store"),
    }
}

// Tie-break on equal weight, strictest first: Include beats Omit beats
// Optional. Never derive PartialOrd on RuleAction — derived order would
// make Optional outrank Include on a tie.
fn tie_rank(action: RuleAction) -> u8 {
    match action {
        RuleAction::Include => 0,
        RuleAction::Omit => 1,
        RuleAction::Optional => 2,
    }
}

fn compile_rules(dict: &plist::Dictionary, errors: &mut Vec<String>) -> Vec<Rule> {
    let mut out = Vec::new();
    for (pattern_str, spec) in dict {
        let Some(pattern) = compile_pattern(pattern_str) else {
            errors.push(format!("unsupported CodeResources rule: {pattern_str}"));
            continue;
        };
        let (action, weight) = match spec {
            plist::Value::Boolean(true) => (RuleAction::Include, 1.0),
            plist::Value::Boolean(false) => (RuleAction::Omit, 1.0),
            plist::Value::Dictionary(d) => {
                let bad_key = d
                    .keys()
                    .any(|k| !matches!(k.as_str(), "omit" | "optional" | "weight"));
                let bad_type = matches!(d.get("omit"), Some(v) if !matches!(v, plist::Value::Boolean(_)))
                    || matches!(d.get("optional"), Some(v) if !matches!(v, plist::Value::Boolean(_)))
                    || matches!(d.get("weight"), Some(v)
                        if !matches!(v, plist::Value::Real(_) | plist::Value::Integer(_)));
                let omit = matches!(d.get("omit"), Some(plist::Value::Boolean(true)));
                let optional = matches!(d.get("optional"), Some(plist::Value::Boolean(true)));
                let weight = match d.get("weight") {
                    None => 1.0,
                    // plist::Integer is a struct, not a primitive: convert
                    // through as_signed/as_unsigned and fail closed on
                    // out-of-range values via the is_finite() check below.
                    // Map each Option to f64 BEFORE combining — or_else
                    // requires the same T, and the arms differ (i64/u64).
                    Some(plist::Value::Integer(w)) => w
                        .as_signed()
                        .map(|v| v as f64)
                        .or_else(|| w.as_unsigned().map(|v| v as f64))
                        .unwrap_or(f64::NAN),
                    Some(plist::Value::Real(w)) => *w,
                    _ => 1.0,
                };
                if bad_key || bad_type || (omit && optional) || !weight.is_finite() {
                    errors.push(format!(
                        "unsupported CodeResources rule: {pattern_str}: invalid spec"
                    ));
                    continue;
                }
                // Weight-only dictionaries (e.g. ^Base\.lproj/ {weight: 1010})
                // resolve to Include here.
                let action = if omit {
                    RuleAction::Omit
                } else if optional {
                    RuleAction::Optional
                } else {
                    RuleAction::Include
                };
                (action, weight)
            }
            _ => {
                errors.push(format!(
                    "unsupported CodeResources rule: {pattern_str}: invalid spec"
                ));
                continue;
            }
        };
        out.push(Rule {
            pattern,
            action,
            weight,
        });
    }
    out
}

fn rule_action(rules: &[Rule], rel: &str) -> Option<RuleAction> {
    let mut best: Option<&Rule> = None;
    for rule in rules {
        if !pattern_matches(&rule.pattern, rel) {
            continue;
        }
        best = Some(match best {
            None => rule,
            Some(b) => match rule.weight.total_cmp(&b.weight) {
                std::cmp::Ordering::Greater => rule,
                std::cmp::Ordering::Equal if tie_rank(rule.action) < tie_rank(b.action) => rule,
                _ => b,
            },
        });
    }
    best.map(|r| r.action)
}

/// Determines whether a path is structurally omitted before rule evaluation.
fn is_rule_omitted(rel: &str, main_executable: Option<&str>) -> bool {
    if rel.starts_with("_CodeSignature/") || rel == "_CodeSignature" {
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
    let mut slot_errors: Vec<String> = Vec::new();
    for slice in &macho.slices {
        if !slice.signed {
            continue;
        }
        if slice.special_slots.first()
            == Some(&zsign_core::codesign::verify::SpecialSlotCheck::NotChecked)
        {
            slot_errors.push(
                "cannot verify special slot -1 (Info.plist) without bundle context".to_string(),
            );
        }
        if slice.special_slots.get(2)
            == Some(&zsign_core::codesign::verify::SpecialSlotCheck::NotChecked)
        {
            slot_errors.push(
                "cannot verify special slot -3 (CodeResources) without bundle context".to_string(),
            );
        }
    }
    Ok(VerifyReport {
        input: path.display().to_string(),
        macho: Some(macho),
        errors: slot_errors,
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
        if entry.file_type().is_symlink() {
            continue;
        }
        let rel_dir = p.strip_prefix(dir).unwrap_or(p);
        if entry.file_type().is_dir() {
            if crate::bundle::is_nested_bundle_dir(p)
                && !has_nested_bundle_component(dir, rel_dir, true)
            {
                nested_dirs.push(p.to_path_buf());
            }
            continue;
        }
        let rel_path = p.strip_prefix(root).unwrap_or(p);
        let rel_str = rel_path.to_string_lossy().replace('\\', "/");
        if rel_str.contains("_CodeSignature/") {
            continue;
        }
        if has_nested_bundle_component(dir, rel_dir, false) {
            continue;
        }
        if is_macho_file(p)? {
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
                            // Slot -1 (index 0) and -3 (index 2): if verification
                            // cannot check a declared binding, signal an unbound
                            // signature.
                            if slice.special_slots.first()
                                == Some(&zsign_core::codesign::verify::SpecialSlotCheck::NotChecked)
                            {
                                bv.errors.push(
                                    "signature binds Info.plist (slot -1) but the file is missing"
                                        .into(),
                                );
                            }
                            if slice.special_slots.get(2)
                                == Some(&zsign_core::codesign::verify::SpecialSlotCheck::NotChecked)
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

/// A sealed key may only address files strictly inside the bundle: every
/// path component must be a plain name (no `..`, no absolute prefix, no `.`).
fn is_safe_bundle_key(key: &str) -> bool {
    let path = Path::new(key);
    path.components().next().is_some()
        && path
            .components()
            .all(|c| matches!(c, std::path::Component::Normal(_)))
}

/// Verifies one CodeResources entry against the bundle on disk.
fn verify_code_resource_entry(
    bundle: &Path,
    bundle_real: &Path,
    rel: &str,
    entry: &plist::Value,
    out: &mut CodeResourcesVerification,
    rules: &[Rule],
    errors: &mut Vec<String>,
) -> Result<()> {
    if !is_safe_bundle_key(rel) {
        errors.push(format!(
            "CodeResources entry path escapes the bundle: {rel}"
        ));
        return Ok(());
    }
    let entry_dict = match entry.as_dictionary() {
        Some(d) => d,
        None => {
            errors.push(format!("malformed CodeResources entry: {rel}"));
            return Ok(());
        }
    };

    let symlink = entry_dict.get("symlink");
    let has_hash = entry_dict.get("hash").is_some();
    let has_hash2 = entry_dict.get("hash2").is_some();
    let malformed = (symlink.is_some() && (has_hash || has_hash2))
        || (has_hash
            && entry_dict
                .get("hash")
                .is_some_and(|value| value.as_data().is_none()))
        || (has_hash2
            && entry_dict
                .get("hash2")
                .is_some_and(|value| value.as_data().is_none()))
        || (symlink.is_some() && symlink.is_some_and(|value| value.as_string().is_none()))
        || (symlink.is_none() && !has_hash && !has_hash2);
    if malformed {
        errors.push(format!("malformed CodeResources entry: {rel}"));
        return Ok(());
    }

    let file_path = bundle.join(rel);
    let parent = file_path
        .parent()
        .ok_or_else(|| crate::Error::Io(std::io::Error::other("invalid resource path")))?;
    match std::fs::canonicalize(parent) {
        Ok(resolved) if resolved.starts_with(bundle_real) => {}
        Ok(_) => {
            errors.push(format!(
                "CodeResources entry path escapes the bundle: {rel}"
            ));
            return Ok(());
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if !matches!(
                rule_action(rules, rel),
                Some(RuleAction::Optional) | Some(RuleAction::Omit)
            ) {
                out.missing.push(rel.to_string());
            }
            return Ok(());
        }
        Err(e) => return Err(crate::Error::Io(e)),
    }
    if let Some(sealed_target) = symlink.and_then(|value| value.as_string()) {
        let metadata = match std::fs::symlink_metadata(&file_path) {
            Ok(metadata) => metadata,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if !matches!(
                    rule_action(rules, rel),
                    Some(RuleAction::Optional) | Some(RuleAction::Omit)
                ) {
                    out.missing.push(rel.to_string());
                }
                return Ok(());
            }
            Err(e) => return Err(crate::Error::Io(e)),
        };
        if !metadata.is_symlink() {
            out.mismatched.push(rel.to_string());
            return Ok(());
        }
        match std::fs::read_link(&file_path) {
            Ok(actual) => {
                if actual.to_string_lossy() == sealed_target {
                    out.matched += 1;
                } else {
                    out.mismatched.push(rel.to_string());
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if !matches!(
                    rule_action(rules, rel),
                    Some(RuleAction::Optional) | Some(RuleAction::Omit)
                ) {
                    out.missing.push(rel.to_string());
                }
            }
            Err(e) => return Err(crate::Error::Io(e)),
        }
        return Ok(());
    }

    let metadata = match std::fs::symlink_metadata(&file_path) {
        Ok(metadata) => metadata,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if !matches!(
                rule_action(rules, rel),
                Some(RuleAction::Optional) | Some(RuleAction::Omit)
            ) {
                out.missing.push(rel.to_string());
            }
            return Ok(());
        }
        Err(e) => return Err(crate::Error::Io(e)),
    };
    if metadata.is_symlink() {
        out.mismatched.push(rel.to_string());
        return Ok(());
    }
    let data = match std::fs::read(&file_path) {
        Ok(data) => data,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if !matches!(
                rule_action(rules, rel),
                Some(RuleAction::Optional) | Some(RuleAction::Omit)
            ) {
                out.missing.push(rel.to_string());
            }
            return Ok(());
        }
        Err(e) => return Err(crate::Error::Io(e)),
    };

    let mut matched = true;
    if let Some(sealed_hash) = entry_dict.get("hash2").and_then(|value| value.as_data()) {
        matched &= sealed_hash == Sha256::digest(&data).as_slice();
    }
    if let Some(sealed_hash) = entry_dict.get("hash").and_then(|value| value.as_data()) {
        matched &= sealed_hash == Sha1::digest(&data).as_slice();
    }
    if matched {
        out.matched += 1;
    } else {
        out.mismatched.push(rel.to_string());
    }
    Ok(())
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
    let Some(root) = value.as_dictionary() else {
        errors.push("CodeResources has no files2 dictionary".into());
        return Ok(out);
    };
    let rules_dict = match root.get("rules2") {
        Some(value) => match value.as_dictionary() {
            Some(dict) => Some(dict),
            None => {
                errors.push("CodeResources rules2 is not a dictionary".into());
                None
            }
        },
        None => match root.get("rules") {
            Some(value) => match value.as_dictionary() {
                Some(dict) => Some(dict),
                None => {
                    errors.push("CodeResources rules is not a dictionary".into());
                    None
                }
            },
            None => {
                errors.push("CodeResources has no rules dictionary".into());
                None
            }
        },
    };
    let rules = rules_dict
        .map(|dict| compile_rules(dict, errors))
        .unwrap_or_default();
    let bundle_real = std::fs::canonicalize(bundle).map_err(crate::Error::Io)?;
    let Some(files2_value) = root.get("files2") else {
        errors.push("CodeResources has no files2 dictionary".into());
        return Ok(out);
    };
    let files2 = match files2_value.as_dictionary() {
        Some(files2) => Some(files2),
        None => {
            errors.push("CodeResources files2 is not a dictionary".into());
            None
        }
    };
    let files = match root.get("files") {
        Some(files) => match files.as_dictionary() {
            Some(files) => Some(files),
            None => {
                errors.push("CodeResources files is not a dictionary".into());
                None
            }
        },
        None => None,
    };

    let mut sealed_set = BTreeSet::new();
    if let Some(files2) = files2 {
        sealed_set.extend(files2.keys().cloned());
    }
    if let Some(files) = files {
        sealed_set.extend(files.keys().cloned());
    }

    // Sealed → disk: every entry must exist and match its recorded seal.
    if let Some(files2) = files2 {
        for (rel, entry) in files2 {
            if entry.as_dictionary().is_none() {
                errors.push(format!("malformed CodeResources entry: {rel}"));
                continue;
            }
            verify_code_resource_entry(bundle, &bundle_real, rel, entry, &mut out, &rules, errors)?;
        }
    }
    if let Some(files) = files {
        for (rel, entry) in files {
            if files2.is_some_and(|files2| files2.contains_key(rel)) {
                continue;
            }
            if let Some(sealed_hash) = entry.as_data() {
                if !is_safe_bundle_key(rel.as_str()) {
                    errors.push(format!(
                        "CodeResources entry path escapes the bundle: {rel}"
                    ));
                    continue;
                }
                let file_path = bundle.join(rel.as_str());
                let parent = file_path.parent().ok_or_else(|| {
                    crate::Error::Io(std::io::Error::other("invalid resource path"))
                })?;
                match std::fs::canonicalize(parent) {
                    Ok(resolved) if resolved.starts_with(&bundle_real) => {}
                    Ok(_) => {
                        errors.push(format!(
                            "CodeResources entry path escapes the bundle: {rel}"
                        ));
                        continue;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        if !matches!(
                            rule_action(&rules, rel),
                            Some(RuleAction::Optional) | Some(RuleAction::Omit)
                        ) {
                            out.missing.push(rel.clone());
                        }
                        continue;
                    }
                    Err(e) => return Err(crate::Error::Io(e)),
                }
                let data = match std::fs::read(&file_path) {
                    Ok(data) => data,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        if !matches!(
                            rule_action(&rules, rel),
                            Some(RuleAction::Optional) | Some(RuleAction::Omit)
                        ) {
                            out.missing.push(rel.clone());
                        }
                        continue;
                    }
                    Err(e) => return Err(crate::Error::Io(e)),
                };
                if sealed_hash == Sha1::digest(&data).as_slice() {
                    out.matched += 1;
                } else {
                    out.mismatched.push(rel.clone());
                }
            } else {
                verify_code_resource_entry(
                    bundle,
                    &bundle_real,
                    rel,
                    entry,
                    &mut out,
                    &rules,
                    errors,
                )?;
            }
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
        if !entry.file_type().is_file() && !entry.file_type().is_symlink() {
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
        if sealed_set.contains(&rel) {
            continue;
        }
        if rule_action(&rules, &rel) == Some(RuleAction::Omit) {
            continue;
        }
        out.unsealed.push(rel);
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::macho::{sign_macho_sha256_only, MachOFile};
    use crate::ZSign;
    use rsa::pkcs1v15::SigningKey as RsaSigningKey;
    use std::fs;
    use std::path::PathBuf;
    use zsign_core::macho::fixtures;

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
    fn build_signed_bundle_with(
        dir: &Path,
        setup: impl FnOnce(&Path),
    ) -> (PathBuf, crate::SigningCredentials) {
        let app = dir.join("Test.app");
        fs::create_dir_all(app.join("Frameworks").join("Sub.framework")).unwrap();
        fs::write(app.join("Info.plist"), app_info_plist()).unwrap();
        fs::write(app.join("Test"), fixtures::make_minimal_macho()).unwrap();
        fs::write(
            app.join("Frameworks").join("Sub.framework").join("Sub"),
            fixtures::make_minimal_macho(),
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
        let (creds, rsa_key) = crate::test_util::test_credentials_with_key();
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
    fn bare_verify_of_bundle_binary_reports_unchecked_slots() {
        let td = tempfile::TempDir::new().unwrap();
        let (app, _) = build_signed_bundle(td.path());
        let extracted = td.path().join("extracted-bin");
        fs::write(&extracted, fs::read(app.join("Test")).unwrap()).unwrap();
        let report = verify_macho_file(&extracted).unwrap();
        assert!(
            !report.valid(),
            "a binary binding bundle resources cannot verify bare"
        );
        assert!(
            report
                .errors
                .iter()
                .any(|e| e.contains("without bundle context")),
            "got {:?}",
            report.errors
        );
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
    #[cfg(unix)]
    #[test]
    fn signed_bundle_with_framework_symlink_verifies() {
        use std::os::unix::fs::symlink;
        let td = tempfile::TempDir::new().unwrap();
        // Target a plain resource, never a Mach-O: the signer's binary walk follows
        // links (ipa/mod.rs:598-620) and would re-sign a linked executable through
        // the symlink, which is out of this test's scope.
        let (app, creds) = build_signed_bundle_with(td.path(), |app| {
            let framework = app.join("Frameworks").join("Sub.framework");
            fs::write(framework.join("resource.bin"), b"framework resource").unwrap();
            symlink("resource.bin", framework.join("reslink")).unwrap();
        });
        let report = verify_bundle(&app).unwrap();
        // Dual-pin contract: without injected anchors report.valid() is false,
        // so "verifies clean end-to-end" = every problem is the anchoring gate
        // and the CMS verifies anchored against the test root.
        let bundle = report.bundle.as_ref().unwrap();
        assert!(bundle.errors.is_empty(), "errors: {:?}", bundle.errors);
        assert_eq!(bundle.nested.len(), 1);
        for binary in bundle.binaries.iter().chain(&bundle.nested[0].binaries) {
            let slice = &binary.report.as_ref().expect("Mach-O report").slices[0];
            assert_eq!(slice.errors.len(), 1, "binaries: {:?}", binary.errors);
            assert!(slice.errors[0].contains("not anchored to a trusted root"));
        }
        let injected = cms_report_with_test_anchor(&fs::read(app.join("Test")).unwrap(), &creds);
        assert!(injected.valid, "cms errors: {:?}", injected.errors);
        assert!(injected.anchored);
        let cr = bundle.code_resources.as_ref().expect("CodeResources check");
        assert!(
            cr.valid(),
            "sealed symlink verified: mismatched={:?} missing={:?} unsealed={:?}",
            cr.mismatched,
            cr.missing,
            cr.unsealed
        );
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
        let (creds, _) = crate::test_util::test_credentials_with_key();
        let macho = MachOFile::parse(fixtures::make_minimal_macho()).unwrap();
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
        fs::write(&f, fixtures::make_minimal_macho()).unwrap();
        let report = verify_macho_file(&f).unwrap();
        assert!(!report.valid());
    }

    #[test]
    fn unsigned_bundle_fails() {
        let td = tempfile::TempDir::new().unwrap();
        let app = td.path().join("Test.app");
        fs::create_dir_all(&app).unwrap();
        fs::write(app.join("Test"), fixtures::make_minimal_macho()).unwrap();
        let report = verify_bundle(&app).unwrap();
        assert!(!report.valid());
    }

    #[test]
    fn missing_code_resources_is_reported_invalid() {
        let td = tempfile::TempDir::new().unwrap();
        let (app, _) = build_signed_bundle(td.path());
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
    fn tampered_nested_binary_is_detected_by_nested_frame() {
        let td = tempfile::TempDir::new().unwrap();
        let (app, _) = build_signed_bundle(td.path());
        let sub = app.join("Frameworks").join("Sub.framework").join("Sub");
        let mut data = fs::read(&sub).unwrap();
        data[0x1000] ^= 0x04;
        fs::write(&sub, data).unwrap();

        let report = verify_bundle(&app).unwrap();
        let bundle = report.bundle.as_ref().unwrap();
        assert_eq!(bundle.nested.len(), 1);
        let frame = &bundle.nested[0];
        assert!(
            !frame.binaries.is_empty(),
            "nested frame binaries must be Mach-O verified, got none"
        );
        let sub_bin = frame
            .binaries
            .iter()
            .find(|b| b.path.ends_with("/Sub") || b.path == "Sub")
            .expect("Sub binary reported by the nested frame");
        assert!(!sub_bin.valid(), "tampered nested binary must not verify");
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

    #[test]
    fn nested_ds_store_is_not_flagged_unsealed() {
        // Builder emission: any *.DS_Store is dropped from files2 at build, kept in
        // the legacy files dict, and omitted by rules2 (weight 2000).
        let td = tempfile::TempDir::new().unwrap();
        let (app, creds) = build_signed_bundle_with(td.path(), |app| {
            fs::write(app.join("Frameworks").join(".DS_Store"), b"junk").unwrap();
        });
        let report = verify_bundle(&app).unwrap();
        // Dual-pin: report.valid() is anchor-gated; this rule defends
        // files-only sealing, asserted at the CodeResources layer.
        let cr = report
            .bundle
            .as_ref()
            .unwrap()
            .code_resources
            .as_ref()
            .unwrap();
        assert!(cr.valid(), "files-only keys are sealed: {:?}", cr);
        let cms = cms_report_with_test_anchor(&fs::read(app.join("Test")).unwrap(), &creds);
        assert!(cms.valid, "cms errors: {:?}", cms.errors);
        assert!(cms.anchored);
    }

    #[test]
    fn legacy_sha1_only_entry_verifies() {
        let td = tempfile::TempDir::new().unwrap();
        let (app, _) = build_signed_bundle(td.path());
        let key = "Frameworks/Sub.framework/Info.plist";
        rewrite_code_resources(&app, |dict| {
            let files2 = dict.get_mut("files2").unwrap().as_dictionary_mut().unwrap();
            let entry = files2.get_mut(key).unwrap().as_dictionary_mut().unwrap();
            let sha1_hash = entry.get("hash").unwrap().clone();
            let mut legacy = plist::Dictionary::new();
            legacy.insert("hash".to_string(), sha1_hash);
            files2.insert(key.to_string(), plist::Value::Dictionary(legacy));
        });
        let report = verify_bundle(&app).unwrap();
        let cr = report
            .bundle
            .as_ref()
            .unwrap()
            .code_resources
            .as_ref()
            .unwrap();
        // Deliberately CR-layer only: rewriting CodeResources also breaks the main
        // executable's slot -3 binding, which is outside this test's unit.
        assert!(cr.valid(), "SHA-1-only entries must verify: {:?}", cr);
    }

    #[test]
    fn partial_reseal_with_updated_hash2_is_detected() {
        let td = tempfile::TempDir::new().unwrap();
        let (app, _) = build_signed_bundle(td.path());
        let target = app
            .join("Frameworks")
            .join("Sub.framework")
            .join("Info.plist");
        let original = fs::read(&target).unwrap();
        let mut modified = original.clone();
        modified.extend_from_slice(b"\n<!-- tampered -->\n");
        fs::write(&target, &modified).unwrap();
        rewrite_code_resources(&app, |dict| {
            let files2 = dict.get_mut("files2").unwrap().as_dictionary_mut().unwrap();
            let key = "Frameworks/Sub.framework/Info.plist";
            let entry = files2.get_mut(key).unwrap().as_dictionary_mut().unwrap();
            use sha2::{Digest, Sha256};
            entry.insert(
                "hash2".to_string(),
                plist::Value::Data(Sha256::digest(&modified).to_vec()),
            );
            // "hash" (SHA-1) intentionally left stale: every declared field is verified.
        });
        let report = verify_bundle(&app).unwrap();
        let cr = report
            .bundle
            .as_ref()
            .unwrap()
            .code_resources
            .as_ref()
            .unwrap();
        assert!(!cr.valid(), "a partial re-seal must be detected: {:?}", cr);
        assert!(
            cr.mismatched.iter().any(|m| m.contains("Info.plist")),
            "{:?}",
            cr.mismatched
        );
    }

    #[test]
    fn optional_lproj_deletion_after_signing_stays_valid() {
        let td = tempfile::TempDir::new().unwrap();
        let (app, creds) = build_signed_bundle_with(td.path(), |app| {
            fs::create_dir_all(app.join("en.lproj")).unwrap();
            fs::write(app.join("en.lproj").join("Localizable.strings"), b"hi").unwrap();
        });
        fs::remove_dir_all(app.join("en.lproj")).unwrap();
        let report = verify_bundle(&app).unwrap();
        // Dual-pin: report.valid() is anchor-gated; this rule defends the
        // optional tolerance, asserted at the CodeResources layer.
        let cr = report
            .bundle
            .as_ref()
            .unwrap()
            .code_resources
            .as_ref()
            .unwrap();
        assert!(cr.valid(), "rules2 marks .lproj optional: {:?}", cr);
        let cms = cms_report_with_test_anchor(&fs::read(app.join("Test")).unwrap(), &creds);
        assert!(cms.valid, "cms errors: {:?}", cms.errors);
        assert!(cms.anchored);
    }

    #[test]
    fn base_lproj_deletion_is_not_optional() {
        // Guard for weight precedence: ^Base\.lproj/ (1010, include) must beat
        // ^.*\.lproj/ (1000, optional), so a sealed Base.lproj file may not vanish.
        let td = tempfile::TempDir::new().unwrap();
        let (app, _) = build_signed_bundle_with(td.path(), |app| {
            fs::create_dir_all(app.join("Base.lproj")).unwrap();
            fs::write(app.join("Base.lproj").join("Notes.strings"), b"x").unwrap();
        });
        fs::remove_dir_all(app.join("Base.lproj")).unwrap();
        let report = verify_bundle(&app).unwrap();
        assert!(
            !report.valid(),
            "Base.lproj is required by weight precedence"
        );
        let cr = report
            .bundle
            .as_ref()
            .unwrap()
            .code_resources
            .as_ref()
            .unwrap();
        assert!(!cr.missing.is_empty(), "{:?}", cr);
    }

    #[test]
    fn omitted_locversion_deletion_stays_valid() {
        // Omit must tolerate absence: the builder seals *.lproj/locversion.plist
        // (its files2 drop list is only Info.plist/PkgInfo/*.DS_Store) while the
        // rules declare it omit at weight 1100.
        let td = tempfile::TempDir::new().unwrap();
        let (app, creds) = build_signed_bundle_with(td.path(), |app| {
            fs::create_dir_all(app.join("en.lproj")).unwrap();
            fs::write(app.join("en.lproj").join("locversion.plist"), b"x").unwrap();
        });
        fs::remove_file(app.join("en.lproj").join("locversion.plist")).unwrap();
        let report = verify_bundle(&app).unwrap();
        // Dual-pin: report.valid() is anchor-gated; this rule defends Omit
        // tolerance, asserted at the CodeResources layer.
        let cr = report
            .bundle
            .as_ref()
            .unwrap()
            .code_resources
            .as_ref()
            .unwrap();
        assert!(
            cr.valid(),
            "an omitted-but-sealed entry may vanish: {:?}",
            cr
        );
        let cms = cms_report_with_test_anchor(&fs::read(app.join("Test")).unwrap(), &creds);
        assert!(cms.valid, "cms errors: {:?}", cms.errors);
        assert!(cms.anchored);
    }

    #[test]
    fn unsupported_rule_is_reported() {
        let td = tempfile::TempDir::new().unwrap();
        let (app, _) = build_signed_bundle(td.path());
        rewrite_code_resources(&app, |dict| {
            let rules2 = dict.get_mut("rules2").unwrap().as_dictionary_mut().unwrap();
            rules2.insert("^secret\\.bin$".into(), plist::Value::Boolean(true));
        });
        let report = verify_bundle(&app).unwrap();
        assert!(!report.valid());
        assert!(
            report
                .bundle
                .as_ref()
                .unwrap()
                .errors
                .iter()
                .any(|e| e.contains("unsupported CodeResources rule")),
            "got {:?}",
            report.bundle.as_ref().unwrap().errors
        );
    }

    #[test]
    fn malformed_entry_is_reported() {
        let td = tempfile::TempDir::new().unwrap();
        let (app, _) = build_signed_bundle(td.path());
        rewrite_code_resources(&app, |dict| {
            let files2 = dict.get_mut("files2").unwrap().as_dictionary_mut().unwrap();
            files2.insert(
                "Frameworks/Sub.framework/Info.plist".to_string(),
                plist::Value::String("garbage".into()),
            );
        });
        let report = verify_bundle(&app).unwrap();
        assert!(!report.valid());
        let bundle = report.bundle.as_ref().unwrap();
        assert!(
            bundle
                .errors
                .iter()
                .any(|e| e.contains("malformed CodeResources entry")),
            "got {:?}",
            bundle.errors
        );
    }
    #[test]
    fn path_traversal_keys_are_rejected() {
        let td = tempfile::TempDir::new().unwrap();
        let (app, _) = build_signed_bundle(td.path());
        rewrite_code_resources(&app, |dict| {
            let files2 = dict.get_mut("files2").unwrap().as_dictionary_mut().unwrap();
            for key in ["../../../../etc/passwd", "/etc/passwd"] {
                let mut entry = plist::Dictionary::new();
                entry.insert("hash2".to_string(), plist::Value::Data(vec![0u8; 32]));
                files2.insert(key.to_string(), plist::Value::Dictionary(entry));
            }
        });
        let report = verify_bundle(&app).unwrap();
        assert!(!report.valid());
        let bundle = report.bundle.as_ref().unwrap();
        for key in ["../../../../etc/passwd", "/etc/passwd"] {
            assert!(
                bundle
                    .errors
                    .iter()
                    .any(|e| { e.contains("escapes the bundle") && e.contains(key) }),
                "key {key:?} must be rejected; got {:?}",
                bundle.errors
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn symlink_parent_traversal_is_rejected() {
        use sha2::{Digest, Sha256};
        use std::os::unix::fs::symlink;
        let td = tempfile::TempDir::new().unwrap();
        let outside = td.path().join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("secret.txt"), b"outside content").unwrap();
        // A legitimately sealed symlink pointing out of the bundle: the builder
        // hashes whatever read_link returns, so this signs cleanly.
        let (app, _) = build_signed_bundle_with(td.path(), |app| {
            symlink(&outside, app.join("Escape")).unwrap();
        });
        // Lexical-clean key whose intermediate component is that symlink; the
        // attacker-chosen hash2 even matches the real outside content.
        rewrite_code_resources(&app, |dict| {
            let files2 = dict.get_mut("files2").unwrap().as_dictionary_mut().unwrap();
            let mut entry = plist::Dictionary::new();
            entry.insert(
                "hash2".to_string(),
                plist::Value::Data(Sha256::digest(b"outside content").to_vec()),
            );
            files2.insert(
                "Escape/secret.txt".to_string(),
                plist::Value::Dictionary(entry),
            );
        });
        let report = verify_bundle(&app).unwrap();
        assert!(!report.valid());
        let bundle = report.bundle.as_ref().unwrap();
        assert!(
            bundle
                .errors
                .iter()
                .any(|e| e.contains("escapes the bundle") && e.contains("Escape/secret.txt")),
            "symlink-parent key must be rejected before any read; got {:?}",
            bundle.errors
        );
    }
}
