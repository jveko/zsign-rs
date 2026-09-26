//! Command-line interface for zsign iOS code signing tool.
//!
//! Provides a CLI for signing Mach-O binaries, app bundles, and IPA files
//! using PKCS#12 or PEM-format certificates.

use clap::Parser;
use std::path::PathBuf;
use std::process::ExitCode;
use zsign_rs::codesign::verify::{PageCheck, SpecialSlotCheck};
use zsign_rs::verify::MachOVerifyReport;
use zsign_rs::{SigningCredentials, ZSign};

#[derive(Parser)]
#[command(name = "zsign")]
#[command(about = "iOS code signing tool")]
#[command(after_help = "upstream users: -p/-k now match upstream; --pkcs12 is long-only")]
// mandatory: non-multiple groups auto-conflict their members in clap 4.6.7
// (validator.rs:509-515), which would reject the legitimate -c + -k pairing
#[command(group = clap::ArgGroup::new("credentials")
    .args(["pkcs12", "certificate", "private_key"])
    .multiple(true))]
struct Cli {
    /// Input file (IPA, Mach-O, or app bundle)
    input: PathBuf,

    /// Output file
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Certificate file (PEM format)
    #[arg(short = 'c', long, requires = "private_key")]
    certificate: Option<PathBuf>,

    /// Private key or PKCS#12 file: format detected by content
    /// (PEM `-----BEGIN` key, DER key, or PKCS#12 — use `-k` alone for PKCS#12)
    #[arg(short = 'k', long, required_unless_present_any = ["adhoc", "verify", "credentials"])]
    private_key: Option<PathBuf>,

    /// PKCS#12 file (.p12)
    #[arg(
        long,
        conflicts_with_all = ["certificate", "private_key"],
        required_unless_present_any = ["adhoc", "verify", "credentials"]
    )]
    pkcs12: Option<PathBuf>,

    /// Provisioning profile
    #[arg(short = 'm', long)]
    profile: Option<PathBuf>,

    /// Per-bundle provisioning profile as bundle-id=profile-path (repeatable).
    /// Applies to app bundles only; ignored when signing a bare Mach-O.
    #[arg(
        long = "profile-map",
        value_name = "BUNDLE_ID=PATH",
        value_parser = parse_profile_map
    )]
    profile_map: Vec<(String, PathBuf)>,

    /// Remove embedded.mobileprovision from every bundle before signing, so the
    /// output's CodeResources never references it. The result carries no
    /// provisioning profile, so it installs only where profile validation is
    /// bypassed.
    /// Applies to app bundles and IPAs; ignored for bare Mach-O input.
    #[arg(short = 'R', long)]
    remove_profile: bool,

    /// Custom entitlements file (replaces the profile's entitlements)
    #[arg(short = 'e', long)]
    entitlements: Option<PathBuf>,

    /// Directory of per-bundle-id entitlements files (`<dir>/<bundle-id>.plist`).
    /// Applies to every bundle; falls back to the profile when no file matches.
    #[arg(long)]
    entitlements_dir: Option<PathBuf>,

    /// Password for the PKCS#12 or key material (empty password is valid).
    /// Precedence: this flag beats the ZSIGN_PASSWORD environment variable.
    /// Values passed on the command line are visible to other users in
    /// process listings; prefer ZSIGN_PASSWORD where possible.
    #[arg(short = 'p', long, env = "ZSIGN_PASSWORD", hide_env_values = true)]
    password: Option<String>,

    /// ZIP compression level (0-9, default: 6)
    /// 0 = no compression (fastest, matches C++ zsign default)
    /// 9 = maximum compression (slowest, smallest file)
    #[arg(
        short = 'z',
        long,
        default_value = "6",
        value_parser = clap::value_parser!(u32).range(0..=9)
    )]
    zip_level: u32,

    /// New bundle identifier to set in Info.plist
    #[arg(short = 'b', long)]
    bundle_id: Option<String>,

    /// New display name to set in Info.plist (CFBundleDisplayName)
    #[arg(short = 'n', long)]
    bundle_name: Option<String>,

    /// New bundle version to set in Info.plist (CFBundleShortVersionString)
    #[arg(short = 'r', long)]
    bundle_version: Option<String>,

    /// Emit only the SHA-256 code directory (no SHA-1 code directory).
    /// This is the modern default; SHA-1 dual directories are rejected by
    /// current macOS verification and only needed for iOS <= 10 targets.
    #[arg(short = '2', long)]
    sha256_only: bool,

    /// Legacy SHA-1 + SHA-256 dual code directories (iOS <= 10 only).
    /// Emitting a SHA-1 primary directory makes output fail
    /// `codesign --verify` on modern macOS.
    #[arg(short = 'L', long, conflicts_with_all = ["sha256_only"])]
    legacy_sha1: bool,

    /// Force signing: override the FairPlay-encryption refusal and sign
    /// encrypted binaries anyway (for already-decrypted input only).
    #[arg(short = 'f', long)]
    force: bool,

    /// Sign without an identity (ad-hoc)
    #[arg(short = 'a', long, conflicts_with_all = ["profile"])]
    adhoc: bool,

    /// Dylib load path to inject (repeatable)
    #[arg(short = 'l', long)]
    dylibs: Vec<String>,

    /// Inject dylibs as LC_LOAD_WEAK_DYLIB
    #[arg(short = 'w', long)]
    weak: bool,

    /// Verify a signed Mach-O, app bundle, or IPA the way
    /// `codesign --verify --deep --strict` does: code-page hashes, special
    /// slots, CodeResources, and the CMS signature + certificate chain.
    /// Exit 0 = valid, 1 = invalid, 2 = hard error.
    #[arg(
        short = 'V',
        long,
        conflicts_with_all = [
            "output",
            "certificate",
            "private_key",
            "pkcs12",
            "profile",
            "profile_map",
            "remove_profile",
            "entitlements",
            "entitlements_dir",
            "zip_level",
            "bundle_id",
            "bundle_name",
            "bundle_version",
            "sha256_only",
            "legacy_sha1",
            "force",
            "adhoc",
            "dylibs",
            "weak"
        ]
    )]
    verify: bool,
    /// Emit a machine-readable JSON document on stdout; failures become JSON
    /// objects on stderr. Human-readable output stays the default.
    #[arg(long)]
    json: bool,
}

/// Parses one `--profile-map bundle-id=path` pair.
fn parse_profile_map(s: &str) -> std::result::Result<(String, PathBuf), String> {
    match s.split_once('=') {
        Some((id, path)) if !id.is_empty() && !path.is_empty() => {
            Ok((id.to_string(), PathBuf::from(path)))
        }
        _ => Err(format!("expected bundle-id=path, got '{s}'")),
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let json = cli.json;
    match run(cli) {
        Ok(code) => code,
        Err(err) => {
            emit_error(json, &err.to_string());
            // signing/credential failures: unchanged contract (design, item 1)
            ExitCode::from(1)
        }
    }
}

/// Runs the CLI from parsed arguments (testable without argv).
fn run(cli: Cli) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let json = cli.json;
    if cli.verify {
        return Ok(run_verify(&cli.input, json));
    }

    let mut signer = if cli.adhoc {
        ZSign::new().adhoc(true)
    } else {
        let credentials = load_credentials(&cli)?;
        ZSign::new().credentials(credentials)
    }
    .compression_level(cli.zip_level);

    if let Some(profile) = cli.profile {
        signer = signer.provisioning_profile(profile);
    }

    if let Some(entitlements) = cli.entitlements {
        signer = signer.entitlements(entitlements);
    }

    if let Some(entitlements_dir) = cli.entitlements_dir {
        signer = signer.entitlements_dir(entitlements_dir);
    }

    if !cli.profile_map.is_empty() {
        signer = signer.bundle_profiles(cli.profile_map.clone());
    }

    if cli.remove_profile {
        signer = signer.remove_embedded_profile(true);
    }

    if let Some(bundle_id) = cli.bundle_id {
        signer = signer.bundle_id(bundle_id);
    }
    if let Some(name) = cli.bundle_name {
        signer = signer.bundle_name(name);
    }
    if let Some(version) = cli.bundle_version {
        signer = signer.bundle_version(version);
    }
    if cli.sha256_only {
        signer = signer.sha256_only(true);
    }
    if cli.legacy_sha1 {
        signer = signer.sha256_only(false);
    }
    if !cli.dylibs.is_empty() {
        signer = signer.dylib_injection(cli.dylibs.clone(), cli.weak);
    }
    if cli.force {
        signer = signer.allow_encrypted(true);
    }

    let ext = cli.input.extension().and_then(|e| e.to_str()).unwrap_or("");

    match ext.to_lowercase().as_str() {
        "ipa" => {
            let output = cli.output.unwrap_or_else(|| {
                let mut out = cli.input.clone();
                out.set_extension("signed");
                out
            });
            signer.sign_ipa(&cli.input, &output)?;
            report_sign(json, false, &output.display().to_string());
        }
        "app" => {
            // Folder signing: with -o ending in .ipa, repack; otherwise in place.
            signer.sign_bundle(&cli.input, cli.output.as_deref())?;
            match &cli.output {
                Some(ipa) => report_sign(json, false, &ipa.display().to_string()),
                None => report_sign(json, true, &cli.input.display().to_string()),
            }
        }
        _ => {
            let output = cli.output.unwrap_or_else(|| {
                let mut out = cli.input.clone();
                out.set_extension("signed");
                out
            });
            signer.sign_macho(&cli.input, &output)?;
            report_sign(json, false, &output.display().to_string());
        }
    }

    Ok(ExitCode::from(0))
}

/// Maps verification to the exit-code contract: 0 valid, 1 invalid,
/// 2 could-not-complete (unreadable/unsupported input or a report with
/// top-level errors).
fn run_verify(input: &std::path::Path, json: bool) -> ExitCode {
    let report = match input
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_lowercase())
        .as_deref()
    {
        Some("ipa") => zsign_rs::verify::verify_ipa(input),
        Some("app") => zsign_rs::verify::verify_bundle(input),
        _ => zsign_rs::verify::verify_macho_file(input),
    };
    let report = match report {
        Ok(report) => report,
        Err(err) => {
            emit_error(json, &err.to_string());
            return ExitCode::from(2);
        }
    };

    if json {
        let status = if report.valid() {
            VerifyStatus::Valid
        } else if report.errors.is_empty() {
            VerifyStatus::Invalid
        } else {
            VerifyStatus::Error
        };
        emit_line(&VerifyDoc {
            status,
            input: input.display().to_string(),
            report: ReportDto::from(&report),
        });
    } else {
        print_report(&report);
    }

    if report.valid() {
        ExitCode::from(0)
    } else if report.errors.is_empty() {
        ExitCode::from(1)
    } else {
        emit_error(json, "verification could not complete");
        ExitCode::from(2)
    }
}

fn print_report(report: &zsign_rs::VerifyReport) {
    println!("verified: {}", if report.valid() { "yes" } else { "no" });
    println!("input: {}", report.input);

    if let Some(macho) = &report.macho {
        print_macho(macho);
    }
    if let Some(bundle) = &report.bundle {
        print_bundle(bundle, 0);
    }
    if !report.errors.is_empty() {
        for e in &report.errors {
            println!("error: {e}");
        }
    }
}

fn print_macho(macho: &MachOVerifyReport) {
    for slice in &macho.slices {
        println!(
            "slice: {} {} (identifier: {:?}, ad-hoc: {})",
            slice.arch,
            if slice.is_valid() { "ok" } else { "INVALID" },
            slice.identifier,
            slice.adhoc
        );
        match &slice.pages {
            PageCheck::Matched => {}
            PageCheck::Empty => println!("  pages: empty code region"),
            PageCheck::Mismatch { page_index } => {
                println!("  pages: MISMATCH at page {page_index}")
            }
            PageCheck::CountMismatch { stored, computed } => {
                println!("  pages: slot count {stored} != computed {computed}")
            }
        }
        if let Some(cms) = &slice.cms {
            if cms.no_signature {
                println!("  cms: ad-hoc (no signature)");
            } else {
                println!(
                    "  cms: {} (chain: {}, anchor: {})",
                    if cms.valid { "valid" } else { "INVALID" },
                    if cms.chain.is_empty() {
                        "n/a".to_string()
                    } else {
                        cms.chain.join(" <- ")
                    },
                    cms.anchored
                );
                if let Some(subject) = &cms.signer_subject {
                    println!("  signer: {subject}");
                }
            }
        }
        // Index special slots -1..-n (index 0 = -1 Info.plist).
        for (i, check) in slice.special_slots.iter().enumerate() {
            let label = slot_label(i);
            match check {
                SpecialSlotCheck::Matched => {}
                SpecialSlotCheck::NotChecked => {}
                SpecialSlotCheck::Mismatch => println!("  slot -{} ({label}): MISMATCH", i + 1),
                // Zeroed/unbound slots are normal (e.g. no Info.plist binding).
                SpecialSlotCheck::Missing => {}
            }
        }
        for e in &slice.errors {
            println!("  error: {e}");
        }
        for w in &slice.warnings {
            println!("  warning: {w}");
        }
    }
}

fn print_bundle(bundle: &zsign_rs::verify::BundleVerification, depth: usize) {
    let indent = "  ".repeat(depth);
    let label = if depth == 0 {
        "bundle".to_string()
    } else {
        "nested".to_string()
    };
    println!(
        "{indent}{label}: {} ({})",
        display_path(&bundle.path),
        if bundle.valid() { "ok" } else { "INVALID" }
    );

    for b in &bundle.binaries {
        let status = if b.valid() { "ok" } else { "INVALID" };
        println!("{indent}  binary: {} ({status})", display_path(&b.path));
        if let Some(m) = &b.report {
            for slice in &m.slices {
                let cms = slice
                    .cms
                    .as_ref()
                    .map(|c| {
                        if c.no_signature {
                            "ad-hoc".to_string()
                        } else if c.valid {
                            "CMS valid".to_string()
                        } else {
                            "CMS INVALID".to_string()
                        }
                    })
                    .unwrap_or_else(|| "no CMS".to_string());
                println!(
                    "{indent}    {}: pages {}, {cms}",
                    slice.arch,
                    match &slice.pages {
                        PageCheck::Matched => "ok".to_string(),
                        PageCheck::Empty => "empty".to_string(),
                        PageCheck::Mismatch { page_index } => {
                            format!("MISMATCH page {page_index}")
                        }
                        PageCheck::CountMismatch { stored, computed } => {
                            format!("count {stored} != {computed}")
                        }
                    }
                );
            }
        }
        for e in &b.errors {
            println!("{indent}    error: {e}");
        }
    }
    if let Some(cr) = &bundle.code_resources {
        let cr_status = if cr.valid() { "ok" } else { "INVALID" };
        println!(
            "{indent}  code resources: {cr_status} ({} sealed)",
            cr.matched
        );
        for f in &cr.mismatched {
            println!("{indent}    mismatch: {f}");
        }
        for f in &cr.missing {
            println!("{indent}    missing: {f}");
        }
        for f in &cr.unsealed {
            println!("{indent}    unsealed: {f}");
        }
    }
    for e in &bundle.errors {
        println!("{indent}  error: {e}");
    }
    for nested in &bundle.nested {
        print_bundle(nested, depth + 1);
    }
}

fn display_path(path: &str) -> &str {
    if path.is_empty() {
        "."
    } else {
        path
    }
}

/// Human label for special slot `index` (0 = slot -1, Info.plist).
fn slot_label(index: usize) -> &'static str {
    const LABELS: [&str; 7] = [
        "Info.plist",
        "requirements",
        "CodeResources",
        "application",
        "entitlements",
        "rep-specific",
        "der entitlements",
    ];
    LABELS.get(index).copied().unwrap_or("?")
}

/// Prints one sign success line: the JSON document under `--json`, else the
/// byte-stable human text the interop script pins.
fn report_sign(json: bool, in_place: bool, output: &str) {
    if json {
        emit_line(&SignDoc {
            status: SignStatus::Signed,
            output: output.to_string(),
        });
    } else if in_place {
        println!("Signed in place: {output}");
    } else {
        println!("Signed: {output}");
    }
}

/// Writes a serializable document to stdout as a single line.
fn emit_line<T: serde::Serialize>(doc: &T) {
    println!(
        "{}",
        serde_json::to_string(doc).expect("JSON document must serialize")
    );
}

/// Renders a failure: one JSON object on stderr under `--json`, else the
/// human `error: …` line.
fn emit_error(json: bool, message: &str) {
    if json {
        eprintln!(
            "{}",
            serde_json::to_string(&ErrorDoc {
                status: ErrorStatus::Error,
                error: message.to_string(),
            })
            .expect("error document must serialize")
        );
    } else {
        eprintln!("error: {message}");
    }
}

// --- JSON schema v1 ---------------------------------------------------------
//
// CLI-local mirror DTOs of the verification report graph: the library structs
// carry no serde derives, and every field they need to expose is public, so
// the conversions below are pure copies. Field names and enum spellings here
// are the stable v1 schema; renaming or removing one is a breaking change.

#[derive(serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum VerifyStatus {
    Valid,
    Invalid,
    Error,
}

#[derive(serde::Serialize)]
struct SignDoc {
    status: SignStatus,
    output: String,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum SignStatus {
    Signed,
}

#[derive(serde::Serialize)]
struct ErrorDoc {
    status: ErrorStatus,
    error: String,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum ErrorStatus {
    Error,
}

#[derive(serde::Serialize)]
struct VerifyDoc {
    status: VerifyStatus,
    input: String,
    report: ReportDto,
}

#[derive(serde::Serialize)]
struct ReportDto {
    valid: bool,
    macho: Option<MachoDto>,
    bundle: Option<BundleDto>,
    errors: Vec<String>,
}

impl From<&zsign_rs::VerifyReport> for ReportDto {
    fn from(report: &zsign_rs::VerifyReport) -> Self {
        Self {
            valid: report.valid(),
            macho: report.macho.as_ref().map(MachoDto::from),
            bundle: report.bundle.as_ref().map(BundleDto::from),
            errors: report.errors.clone(),
        }
    }
}

#[derive(serde::Serialize)]
struct MachoDto {
    fat: bool,
    slices: Vec<SliceDto>,
}

impl From<&MachOVerifyReport> for MachoDto {
    fn from(macho: &MachOVerifyReport) -> Self {
        Self {
            fat: macho.fat,
            slices: macho.slices.iter().map(SliceDto::from).collect(),
        }
    }
}

#[derive(serde::Serialize)]
struct SliceDto {
    arch: String,
    signed: bool,
    identifier: Option<String>,
    adhoc: bool,
    valid: bool,
    pages: PagesDto,
    special_slots: Vec<SlotDto>,
    cms: Option<CmsDto>,
    errors: Vec<String>,
    warnings: Vec<String>,
}

impl From<&zsign_rs::verify::SliceVerifyReport> for SliceDto {
    fn from(slice: &zsign_rs::verify::SliceVerifyReport) -> Self {
        Self {
            arch: slice.arch.clone(),
            signed: slice.signed,
            identifier: slice.identifier.clone(),
            adhoc: slice.adhoc,
            valid: slice.is_valid(),
            pages: PagesDto::from(&slice.pages),
            special_slots: slice
                .special_slots
                .iter()
                .enumerate()
                .map(|(i, check)| SlotDto {
                    slot: -((i + 1) as i32),
                    name: slot_label(i).to_string(),
                    check: SlotCheckDto::from(check),
                })
                .collect(),
            cms: slice.cms.as_ref().map(CmsDto::from),
            errors: slice.errors.clone(),
            warnings: slice.warnings.clone(),
        }
    }
}

#[derive(serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum PagesDto {
    Matched,
    Empty,
    Mismatch { page_index: usize },
    CountMismatch { stored: usize, computed: usize },
}

impl From<&PageCheck> for PagesDto {
    fn from(pages: &PageCheck) -> Self {
        match pages {
            PageCheck::Matched => Self::Matched,
            PageCheck::Empty => Self::Empty,
            PageCheck::Mismatch { page_index } => Self::Mismatch {
                page_index: *page_index,
            },
            PageCheck::CountMismatch { stored, computed } => Self::CountMismatch {
                stored: *stored,
                computed: *computed,
            },
        }
    }
}

#[derive(serde::Serialize)]
struct SlotDto {
    slot: i32,
    name: String,
    check: SlotCheckDto,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum SlotCheckDto {
    Matched,
    NotChecked,
    Mismatch,
    Missing,
}

impl From<&SpecialSlotCheck> for SlotCheckDto {
    fn from(check: &SpecialSlotCheck) -> Self {
        match check {
            SpecialSlotCheck::Matched => Self::Matched,
            SpecialSlotCheck::NotChecked => Self::NotChecked,
            SpecialSlotCheck::Mismatch => Self::Mismatch,
            SpecialSlotCheck::Missing => Self::Missing,
        }
    }
}

#[derive(serde::Serialize)]
struct CmsDto {
    valid: bool,
    no_signature: bool,
    signer_subject: Option<String>,
    signer_serial: Option<String>,
    message_digest_ok: bool,
    cdhash_v1_ok: bool,
    cdhash_v2_ok: bool,
    signature_ok: bool,
    chain_ok: bool,
    anchored: bool,
    chain_reason: Option<String>,
    chain: Vec<String>,
    errors: Vec<String>,
    warnings: Vec<String>,
}

impl From<&zsign_rs::crypto::cms_verify::CmsVerifyReport> for CmsDto {
    fn from(cms: &zsign_rs::crypto::cms_verify::CmsVerifyReport) -> Self {
        Self {
            valid: cms.valid,
            no_signature: cms.no_signature,
            signer_subject: cms.signer_subject.clone(),
            signer_serial: cms.signer_serial.clone(),
            message_digest_ok: cms.message_digest_ok,
            cdhash_v1_ok: cms.cdhash_v1_ok,
            cdhash_v2_ok: cms.cdhash_v2_ok,
            signature_ok: cms.signature_ok,
            chain_ok: cms.chain_ok,
            anchored: cms.anchored,
            chain_reason: cms.chain_reason.clone(),
            chain: cms.chain.clone(),
            errors: cms.errors.clone(),
            warnings: cms.warnings.clone(),
        }
    }
}

#[derive(serde::Serialize)]
struct BundleDto {
    path: String,
    valid: bool,
    binaries: Vec<BinaryDto>,
    code_resources: Option<CrDto>,
    errors: Vec<String>,
    nested: Vec<BundleDto>,
}

impl From<&zsign_rs::verify::BundleVerification> for BundleDto {
    fn from(bundle: &zsign_rs::verify::BundleVerification) -> Self {
        Self {
            path: bundle.path.clone(),
            valid: bundle.valid(),
            binaries: bundle.binaries.iter().map(BinaryDto::from).collect(),
            code_resources: bundle.code_resources.as_ref().map(CrDto::from),
            errors: bundle.errors.clone(),
            nested: bundle.nested.iter().map(BundleDto::from).collect(),
        }
    }
}

#[derive(serde::Serialize)]
struct BinaryDto {
    path: String,
    valid: bool,
    report: Option<MachoDto>,
    errors: Vec<String>,
}

impl From<&zsign_rs::verify::BinaryVerification> for BinaryDto {
    fn from(binary: &zsign_rs::verify::BinaryVerification) -> Self {
        Self {
            path: binary.path.clone(),
            valid: binary.valid(),
            report: binary.report.as_ref().map(MachoDto::from),
            errors: binary.errors.clone(),
        }
    }
}

#[derive(serde::Serialize)]
struct CrDto {
    valid: bool,
    matched: usize,
    mismatched: Vec<String>,
    missing: Vec<String>,
    unsealed: Vec<String>,
}

impl From<&zsign_rs::verify::CodeResourcesVerification> for CrDto {
    fn from(cr: &zsign_rs::verify::CodeResourcesVerification) -> Self {
        Self {
            valid: cr.valid(),
            matched: cr.matched,
            mismatched: cr.mismatched.clone(),
            missing: cr.missing.clone(),
            unsealed: cr.unsealed.clone(),
        }
    }
}

/// Reads a credential file, labeling io failures with the flag that named it:
/// a bare `No such file or directory` never says which of the three paths
/// was wrong.
fn read_credential_file(
    path: &std::path::Path,
    label: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    std::fs::read(path)
        .map_err(|e| format!("failed to read {label} '{}': {e}", path.display()).into())
}

fn load_credentials(cli: &Cli) -> Result<SigningCredentials, Box<dyn std::error::Error>> {
    if let Some(p12_path) = &cli.pkcs12 {
        let p12_data = read_credential_file(p12_path, "pkcs12")?;
        let password = resolve_p12_password(cli, &p12_data)?;
        let creds = SigningCredentials::from_p12(&p12_data, &password)?;
        return Ok(creds);
    }

    let Some(key_path) = &cli.private_key else {
        // Defense in depth: clap's required credential group already rejects
        // invocations that reach this point.
        return Err("--pkcs12 or --private-key is required".into());
    };
    let key_data = read_credential_file(key_path, "private key")?;
    if key_data.starts_with(b"-----BEGIN") {
        let Some(cert_path) = &cli.certificate else {
            return Err("--certificate <FILE> is required with a PEM private key".into());
        };
        let cert_data = read_credential_file(cert_path, "certificate")?;
        let creds = SigningCredentials::from_pem(&cert_data, &key_data, cli.password.as_deref())?;
        return Ok(creds);
    }

    match &cli.certificate {
        // no PEM marker + certificate present: PKCS#12 content here is a
        // flag-combination mistake, not a key file — detect it before the
        // certificate loader misdiagnoses the ASN.1 as a broken certificate
        Some(cert_path) => {
            // A PKCS#12 authSafe ContentInfo carries pkcs7-data (…1.7.1) or, for
            // encrypted-shroud containers, pkcs7-encryptedData (…1.7.6) — the only
            // two OIDs our parser accepts for authSafe; a PKCS#8 key has neither.
            const P12_PKCS7_DATA_OID: &[u8] = &[
                0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01,
            ];
            const P12_PKCS7_ENCRYPTED_DATA_OID: &[u8] = &[
                0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x06,
            ];
            if key_data
                .windows(P12_PKCS7_DATA_OID.len())
                .any(|w| w == P12_PKCS7_DATA_OID)
                || key_data
                    .windows(P12_PKCS7_ENCRYPTED_DATA_OID.len())
                    .any(|w| w == P12_PKCS7_ENCRYPTED_DATA_OID)
            {
                return Err("--private-key contains a PKCS#12 file, which cannot be \
                    combined with --certificate; pass -k alone (password via -p) or \
                    use --pkcs12"
                    .into());
            }
            let cert_data = read_credential_file(cert_path, "certificate")?;
            let wrapped = pem_wrap_der(&key_data);
            let creds = SigningCredentials::from_pem(
                &cert_data,
                wrapped.as_bytes(),
                cli.password.as_deref(),
            )?;
            Ok(creds)
        }
        // no PEM marker + no certificate => PKCS#12 content
        None => {
            let password = resolve_p12_password(cli, &key_data)?;
            let creds = SigningCredentials::from_p12(&key_data, &password)?;
            Ok(creds)
        }
    }
}

/// Resolves the PKCS#12 password: flag/env first; otherwise the historical
/// empty-password attempt, and only a *password-shaped* trial failure may
/// prompt (TTY) or name the password channels (non-TTY). Other failures
/// (policy rejection, corruption) surface verbatim — they are not password
/// problems and must not be reported as "no password supplied".
fn resolve_p12_password(cli: &Cli, data: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
    if let Some(pw) = &cli.password {
        return Ok(pw.clone());
    }
    let trial_err = match SigningCredentials::from_p12(data, "") {
        Ok(_) => return Ok(String::new()), // empty-password containers never prompt
        Err(e) => e.to_string(),
    };
    // Same two markers the wasm adapter sniffs for "wrong/needed password"
    let password_shaped = trial_err.contains("invalid PKCS#12 password (MAC mismatch)")
        || trial_err.contains("PKCS#12 decryption failed");
    if !password_shaped {
        return Err(trial_err.into());
    }
    if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        // one prompt, no pre-validation: the call site's from_p12 is the
        // single retry (a wrong prompt surfaces its loader error there)
        let prompted = rpassword::prompt_password("PKCS#12 password: ")
            .map_err(|e| format!("password prompt failed: {e}"))?;
        Ok(prompted)
    } else {
        Err(format!(
            "{trial_err}; no password supplied: pass -p/--password or set \
             ZSIGN_PASSWORD (stdin is not a terminal, cannot prompt)"
        )
        .into())
    }
}

/// Wraps raw DER key bytes in a PEM envelope so the PEM-only loader can
/// decode them (the library exposes no public DER entry point).
fn pem_wrap_der(der: &[u8]) -> String {
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = String::with_capacity(b64.len() + b64.len() / 64 + 64);
    out.push_str(concat!("-----BEGIN ", "PRIVATE KEY-----", "\n"));
    for line in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).expect("base64 is ascii"));
        out.push('\n');
    }
    out.push_str(concat!("-----END ", "PRIVATE KEY-----", "\n"));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;
    use std::path::Path;
    use tempfile::TempDir;

    /// Minimal arm64 MH_EXECUTE with an injected LC_ENCRYPTION_INFO_64 (cryptid=1, cryptsize=0x1000).
    fn encrypted_macho() -> Vec<u8> {
        let mut b = Vec::with_capacity(0x2000);
        macro_rules! u32 {
            ($v:expr) => {
                b.extend_from_slice(&($v as u32).to_le_bytes())
            };
        }
        macro_rules! u64 {
            ($v:expr) => {
                b.extend_from_slice(&($v as u64).to_le_bytes())
            };
        }
        macro_rules! name {
            ($s:expr) => {
                let mut n = [0u8; 16];
                n[..$s.len()].copy_from_slice($s.as_bytes());
                b.extend_from_slice(&n);
            };
        }

        u32!(0xfeedfacf); // MH_MAGIC_64
        u32!(0x0100_000c); // CPU_TYPE_ARM64
        u32!(0x0000_0000);
        u32!(2); // MH_EXECUTE
        u32!(4); // ncmds
        u32!(152 + 72 + 24 + 24); // sizeofcmds
        u32!(0x1); // MH_NOUNDEFS
        u32!(0); // reserved
        u32!(0x19);
        u32!(152);
        name!("__TEXT");
        u64!(0x1_0000_0000);
        u64!(0x1000);
        u64!(0x1000);
        u64!(0x1000);
        u32!(7);
        u32!(7);
        u32!(1);
        u32!(0);
        name!("__text");
        name!("__TEXT");
        u64!(0x1_0000_0000);
        u64!(4);
        u32!(0x1000);
        u32!(0);
        u32!(0);
        u32!(0);
        u32!(0);
        u32!(0);
        u32!(0);
        u32!(0);
        u32!(0x19);
        u32!(72);
        name!("__LINKEDIT");
        u64!(0x1_0000_1000);
        u64!(0x1000);
        u64!(0x2000);
        u64!(0);
        u32!(1);
        u32!(1);
        u32!(0);
        u32!(0);
        u32!(0x32);
        u32!(24);
        u32!(1);
        u32!(0x000f_0000);
        u32!(0x000f_0000);
        u32!(0);
        u32!(0x2c);
        u32!(24);
        u32!(0x1000);
        u32!(0x1000);
        u32!(1);
        u32!(0);
        b.resize(0x1000, 0);
        b.extend_from_slice(&[0x1f, 0x20, 0x03, 0xd5]);
        b.resize(0x2000, 0);
        b
    }

    /// Builds `dir/Enc.app` containing the encrypted executable.
    fn make_encrypted_app(dir: &Path) -> std::path::PathBuf {
        let app = dir.join("Enc.app");
        std::fs::create_dir_all(&app).unwrap();
        std::fs::write(
            app.join("Info.plist"),
            br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleExecutable</key><string>Enc</string>
  <key>CFBundleIdentifier</key><string>com.zsign.enc</string>
</dict></plist>"#,
        )
        .unwrap();
        std::fs::write(app.join("Enc"), encrypted_macho()).unwrap();
        std::fs::write(app.join("data.bin"), [0xAB; 2048]).unwrap();
        app
    }

    /// Path to the freshly built zsign-cli binary, building it once per test process.
    /// Cargo does not build the bin target for unit tests (no tests/ dir), so the child
    /// `cargo build` is what makes the executable exist and be current. The child
    /// mirrors this test binary's profile: CI also runs `cargo test --workspace
    /// --release` (ci.yml:62), and a release test run resolves target/release/zsign-cli
    /// — a debug-only build would leave that path missing at merge.
    fn zsign_bin() -> &'static std::path::Path {
        static BIN: std::sync::LazyLock<std::path::PathBuf> = std::sync::LazyLock::new(|| {
            let exe = std::env::current_exe().expect("test executable path");
            let profile_dir = exe
                .parent()
                .expect("deps dir")
                .parent()
                .expect("profile dir");
            let mut build = std::process::Command::new("cargo");
            build.args(["build", "-p", "zsign-cli", "-q"]);
            if !cfg!(debug_assertions) {
                build.arg("--release");
            }
            let out = build.output().expect("spawn cargo build for zsign-cli");
            assert!(
                out.status.success(),
                "cargo build -p zsign-cli failed:\n{}",
                String::from_utf8_lossy(&out.stderr)
            );
            profile_dir.join(format!("zsign-cli{}", std::env::consts::EXE_SUFFIX))
        });
        &BIN
    }

    struct CliRun {
        code: i32,
        stdout: String,
        stderr: String,
    }

    /// Runs the built binary with `args`, scrubbing any inherited ZSIGN_PASSWORD
    /// before applying `envs`, and captures its exit code and streams.
    fn run_cli(args: &[&OsStr], envs: &[(&str, &str)]) -> CliRun {
        let out = std::process::Command::new(zsign_bin())
            .args(args)
            .env_remove("ZSIGN_PASSWORD")
            .envs(envs.iter().copied())
            .output()
            .expect("spawn zsign-cli");
        CliRun {
            code: out.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        }
    }

    const MINIMAL_MACHO: &[u8] = include_bytes!("../../zsign/src/ipa/fixtures/minimal_macho.bin");

    const IDENTITY_P12: &[u8] =
        include_bytes!("../../zsign-core/src/crypto/fixtures/identity_single.p12");

    const EMPTY_PASSWORD_P12: &[u8] =
        include_bytes!("../../zsign-core/src/crypto/fixtures/empty_password.p12");

    // Encrypted-key fixtures are committed as base64 blobs of byte-exact OpenSSL output: the
    // repository's private-key commit gate refuses every private-key PEM file, PBES2 included.
    // The certificate is committed readable, because a certificate is not a key.
    const RSA_CERT: &[u8] = include_bytes!("../../zsign-core/src/crypto/fixtures/pem_rsa_cert.pem");
    const ENC_TRAD_RSA: &str =
        include_str!("../../zsign-core/src/crypto/fixtures/pem_rsa_key_dekinfo_aes256.pem.b64");
    const ENC_PKCS8_RSA: &str =
        include_str!("../../zsign-core/src/crypto/fixtures/pem_rsa_key_pbes2_sha256.pem.b64");

    /// Decodes one committed encrypted-key fixture back to its PEM text.
    fn pem_fixture(blob: &str) -> String {
        use base64::Engine as _;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(blob.trim())
            .expect("fixture must be valid base64");
        String::from_utf8(bytes).expect("fixture must be UTF-8 PEM text")
    }

    #[test]
    fn verify_valid_input_exits_zero() {
        let dir = TempDir::new().unwrap();
        let input = dir.path().join("in.bin");
        std::fs::write(&input, MINIMAL_MACHO).unwrap();
        let signed = dir.path().join("signed.bin");
        let sign = run_cli(
            &[
                OsStr::new("-a"),
                OsStr::new("-o"),
                signed.as_os_str(),
                input.as_os_str(),
            ],
            &[],
        );
        assert_eq!(sign.code, 0, "adhoc sign failed: {}", sign.stderr);
        let v = run_cli(&[OsStr::new("-V"), signed.as_os_str()], &[]);
        assert_eq!(v.code, 0, "expected 0, stderr: {}", v.stderr);
        assert!(v.stdout.contains("verified: yes"), "stdout: {}", v.stdout);
    }

    #[test]
    fn verify_invalid_input_exits_one() {
        // unsigned minimal macho: slice error (no LC_CODE_SIGNATURE), top-level errors empty
        let dir = TempDir::new().unwrap();
        let input = dir.path().join("in.bin");
        std::fs::write(&input, MINIMAL_MACHO).unwrap();
        let v = run_cli(&[OsStr::new("-V"), input.as_os_str()], &[]);
        assert_eq!(v.code, 1, "expected 1, stderr: {}", v.stderr);
        assert!(v.stdout.contains("verified: no"), "stdout: {}", v.stdout);
    }

    #[test]
    fn verify_missing_file_exits_two() {
        let dir = TempDir::new().unwrap();
        let v = run_cli(
            &[OsStr::new("-V"), dir.path().join("nope.bin").as_os_str()],
            &[],
        );
        assert_eq!(v.code, 2, "expected 2, stderr: {}", v.stderr);
        assert!(v.stderr.starts_with("error: "), "stderr: {}", v.stderr);
        // regression pin: Rust's Result-termination prefix must not come back
        assert!(!v.stderr.starts_with("Error:"), "stderr: {}", v.stderr);
    }

    #[test]
    fn verify_invalid_zip_exits_two() {
        let dir = TempDir::new().unwrap();
        let input = dir.path().join("garbage.ipa");
        std::fs::write(&input, b"this is not a zip archive").unwrap();
        let v = run_cli(&[OsStr::new("-V"), input.as_os_str()], &[]);
        assert_eq!(v.code, 2, "expected 2, stderr: {}", v.stderr);
    }

    #[test]
    fn verify_non_macho_input_exits_two() {
        let dir = TempDir::new().unwrap();
        let input = dir.path().join("plain.bin");
        std::fs::write(&input, b"#!/bin/sh\necho hi\n").unwrap();
        let v = run_cli(&[OsStr::new("-V"), input.as_os_str()], &[]);
        assert_eq!(v.code, 2, "expected 2, stderr: {}", v.stderr);
    }

    #[test]
    fn verify_bound_slot_without_bundle_context_exits_two() {
        // bundle signing binds slot content on its main executable (IpaSigner's
        // adhoc path passes info_data/code_resources, ipa/mod.rs:1029-1035);
        // verifying that executable loose (no bundle context) makes
        // verify_macho_file populate top-level report errors => exit 2
        let dir = TempDir::new().unwrap();
        let app = make_encrypted_app(dir.path());
        let sign = run_cli(&[OsStr::new("-a"), OsStr::new("-f"), app.as_os_str()], &[]);
        assert_eq!(sign.code, 0, "bundle sign failed: {}", sign.stderr);
        let loose = dir.path().join("loose.bin");
        std::fs::copy(app.join("Enc"), &loose).unwrap();
        let v = run_cli(&[OsStr::new("-V"), loose.as_os_str()], &[]);
        assert_eq!(v.code, 2, "expected 2, stderr: {}", v.stderr);
        assert!(v.stdout.contains("verified: no"), "stdout: {}", v.stdout);
    }

    #[test]
    fn cli_refuses_encrypted_without_force() {
        let dir = TempDir::new().unwrap();
        let app = make_encrypted_app(dir.path());
        let out = dir.path().join("out.ipa");
        let cli = Cli::parse_from([
            "zsign",
            "-a",
            "-o",
            out.to_str().unwrap(),
            app.to_str().unwrap(),
        ]);
        let err = run(cli).expect_err("encrypted app without --force must refuse");
        assert!(
            err.to_string().contains("decrypt"),
            "must tell the user to decrypt: {err}"
        );
    }

    #[test]
    fn cli_signing_encrypted_with_force_succeeds() {
        let dir = TempDir::new().unwrap();
        let app = make_encrypted_app(dir.path());
        let out = dir.path().join("out.ipa");
        let cli = Cli::parse_from([
            "zsign",
            "-a",
            "-f",
            "-o",
            out.to_str().unwrap(),
            app.to_str().unwrap(),
        ]);
        run(cli).expect("--force must sign the encrypted app");
        assert!(out.exists());
    }

    fn parse_json(s: &str) -> serde_json::Value {
        serde_json::from_str(s).unwrap_or_else(|e| panic!("invalid JSON {e}: {s}"))
    }

    #[test]
    fn json_sign_reports_output() {
        let dir = TempDir::new().unwrap();
        let input = dir.path().join("in.bin");
        std::fs::write(&input, MINIMAL_MACHO).unwrap();
        let signed = dir.path().join("signed.bin");
        let r = run_cli(
            &[
                OsStr::new("--json"),
                OsStr::new("-a"),
                OsStr::new("-o"),
                signed.as_os_str(),
                input.as_os_str(),
            ],
            &[],
        );
        assert_eq!(r.code, 0, "{}", r.stderr);
        let doc = parse_json(&r.stdout);
        assert_eq!(doc["status"], "signed");
        assert_eq!(doc["output"], signed.to_str().unwrap());
        assert!(signed.exists());
    }

    #[test]
    fn json_verify_valid_and_invalid_documents() {
        let dir = TempDir::new().unwrap();
        let input = dir.path().join("in.bin");
        std::fs::write(&input, MINIMAL_MACHO).unwrap();
        let signed = dir.path().join("signed.bin");
        assert_eq!(
            run_cli(
                &[
                    OsStr::new("-a"),
                    OsStr::new("-o"),
                    signed.as_os_str(),
                    input.as_os_str()
                ],
                &[]
            )
            .code,
            0
        );

        let ok = run_cli(
            &[OsStr::new("--json"), OsStr::new("-V"), signed.as_os_str()],
            &[],
        );
        assert_eq!(ok.code, 0, "{}", ok.stderr);
        let doc = parse_json(&ok.stdout);
        assert_eq!(doc["status"], "valid");
        assert_eq!(doc["report"]["valid"], true);
        assert_eq!(doc["report"]["macho"]["slices"][0]["arch"], "arm64");
        assert_eq!(
            doc["report"]["macho"]["slices"][0]["pages"]["kind"],
            "matched"
        );
        assert_eq!(
            doc["report"]["macho"]["slices"][0]["cms"]["no_signature"],
            true
        );

        let bad = run_cli(
            &[OsStr::new("--json"), OsStr::new("-V"), input.as_os_str()],
            &[],
        );
        assert_eq!(bad.code, 1, "{}", bad.stderr);
        let doc = parse_json(&bad.stdout);
        assert_eq!(doc["status"], "invalid");
        assert_eq!(doc["report"]["valid"], false);
    }

    #[test]
    fn json_error_is_a_single_stderr_object() {
        let dir = TempDir::new().unwrap();
        let r = run_cli(
            &[
                OsStr::new("--json"),
                OsStr::new("-V"),
                dir.path().join("nope.bin").as_os_str(),
            ],
            &[],
        );
        assert_eq!(r.code, 2, "{}", r.stderr);
        assert!(r.stdout.is_empty(), "stdout must stay empty: {}", r.stdout);
        let doc = parse_json(&r.stderr);
        assert_eq!(doc["status"], "error");
        assert!(!doc["error"].as_str().unwrap().is_empty());
    }

    #[test]
    fn human_output_is_unchanged_without_json_flag() {
        // guard for the interop script's pinned stdout lines
        let dir = TempDir::new().unwrap();
        let input = dir.path().join("in.bin");
        std::fs::write(&input, MINIMAL_MACHO).unwrap();
        let r = run_cli(&[OsStr::new("-V"), input.as_os_str()], &[]);
        assert!(
            r.stdout.starts_with("verified: no\n"),
            "stdout: {}",
            r.stdout
        );
        assert!(r.stdout.contains("slice: arm64"), "stdout: {}", r.stdout);
    }

    #[test]
    fn short_p_is_password_and_pkcs12_is_long_only() {
        let cli = Cli::parse_from(["zsign", "-a", "-p", "secret", "in.bin"]);
        assert_eq!(cli.password.as_deref(), Some("secret"));
        assert!(cli.pkcs12.is_none());
        // old -p <path> invocations now parse as a password string, not a path
        let cli = Cli::parse_from(["zsign", "-a", "-p", "some/path.p12", "in.bin"]);
        assert_eq!(cli.password.as_deref(), Some("some/path.p12"));
        // pkcs12 remains reachable, long-only
        let cli = Cli::parse_from(["zsign", "-a", "--pkcs12", "some/path.p12", "in.bin"]);
        assert_eq!(
            cli.pkcs12.as_deref(),
            Some(std::path::Path::new("some/path.p12"))
        );
    }

    #[test]
    fn help_carries_upstream_migration_note() {
        let r = run_cli(&[OsStr::new("--help")], &[]);
        assert_eq!(r.code, 0);
        assert!(
            r.stdout
                .contains("upstream users: -p/-k now match upstream; --pkcs12 is long-only"),
            "stdout: {}",
            r.stdout
        );
    }

    #[test]
    fn key_route_pkcs12_content_loads_with_password() {
        // `-k` carrying p12 bytes + `-p` password signs a bare Mach-O to exit 0:
        // proves content routing (p12 branch) and that -p feeds from_p12.
        let dir = TempDir::new().unwrap();
        let key = dir.path().join("identity.p12");
        std::fs::write(&key, IDENTITY_P12).unwrap();
        let input = dir.path().join("in.bin");
        std::fs::write(&input, MINIMAL_MACHO).unwrap();
        let out = dir.path().join("out.bin");
        let r = run_cli(
            &[
                OsStr::new("-k"),
                key.as_os_str(),
                OsStr::new("-p"),
                OsStr::new("testpassword"),
                OsStr::new("-o"),
                out.as_os_str(),
                input.as_os_str(),
            ],
            &[],
        );
        assert_eq!(r.code, 0, "expected signed output, stderr: {}", r.stderr);
        assert!(out.exists());
    }

    #[test]
    fn pkcs12_content_with_certificate_names_the_conflict() {
        let dir = TempDir::new().unwrap();
        let key = dir.path().join("identity.p12");
        std::fs::write(&key, IDENTITY_P12).unwrap();
        let input = dir.path().join("in.bin");
        std::fs::write(&input, MINIMAL_MACHO).unwrap();
        // the OID check runs before the certificate is read, so a nonexistent
        // -c path proves the misuse error fires first
        let r = run_cli(
            &[
                OsStr::new("-k"),
                key.as_os_str(),
                OsStr::new("-c"),
                dir.path().join("absent.pem").as_os_str(),
                OsStr::new("-o"),
                dir.path().join("o.bin").as_os_str(),
                input.as_os_str(),
            ],
            &[],
        );
        assert_eq!(r.code, 1, "stderr: {}", r.stderr);
        assert!(r.stderr.contains("PKCS#12"), "stderr: {}", r.stderr);
        assert!(r.stderr.contains("--certificate"), "stderr: {}", r.stderr);
    }

    #[test]
    fn pem_key_without_certificate_names_the_missing_flag() {
        let dir = TempDir::new().unwrap();
        let key = dir.path().join("key.pem");
        std::fs::write(&key, concat!("-----BEGIN ", "PRIVATE KEY-----", "\n")).unwrap();
        let input = dir.path().join("in.bin");
        std::fs::write(&input, MINIMAL_MACHO).unwrap();
        let out = dir.path().join("o.bin");
        let r = run_cli(
            &[
                OsStr::new("-k"),
                key.as_os_str(),
                OsStr::new("-o"),
                out.as_os_str(),
                input.as_os_str(),
            ],
            &[],
        );
        assert_eq!(r.code, 1, "stderr: {}", r.stderr);
        assert!(r.stderr.contains("--certificate"), "stderr: {}", r.stderr);
        // the generic "provide both" fallthrough also contains the substring
        // "--certificate", so require the missing flag to be named on its own
        assert!(
            !r.stderr.contains("--pkcs12 or both"),
            "error must name the missing flag, not the generic fallthrough: {}",
            r.stderr
        );
    }

    #[test]
    fn env_password_signs_p12_without_flag() {
        let dir = TempDir::new().unwrap();
        let key = dir.path().join("identity.p12");
        std::fs::write(&key, IDENTITY_P12).unwrap();
        let input = dir.path().join("in.bin");
        std::fs::write(&input, MINIMAL_MACHO).unwrap();
        let out = dir.path().join("out.bin");
        let r = run_cli(
            &[
                OsStr::new("-k"),
                key.as_os_str(),
                OsStr::new("-o"),
                out.as_os_str(),
                input.as_os_str(),
            ],
            &[("ZSIGN_PASSWORD", "testpassword")],
        );
        assert_eq!(r.code, 0, "env password must work, stderr: {}", r.stderr);
        assert!(out.exists());
    }

    #[test]
    fn argv_password_beats_env_password() {
        // env-only wrong password must FAIL first (proves the env value is read
        // at all), then flag+wrong-env must succeed (proves the flag wins) —
        // either case alone cannot distinguish precedence from env being ignored
        let dir = TempDir::new().unwrap();
        let key = dir.path().join("identity.p12");
        std::fs::write(&key, IDENTITY_P12).unwrap();
        let input = dir.path().join("in.bin");
        std::fs::write(&input, MINIMAL_MACHO).unwrap();

        let env_only = run_cli(
            &[
                OsStr::new("-k"),
                key.as_os_str(),
                OsStr::new("-o"),
                dir.path().join("o1.bin").as_os_str(),
                input.as_os_str(),
            ],
            &[("ZSIGN_PASSWORD", "wrong-password")],
        );
        assert_eq!(
            env_only.code, 1,
            "env value must be read: {}",
            env_only.stderr
        );
        assert!(
            env_only.stderr.contains("MAC mismatch"),
            "stderr: {}",
            env_only.stderr
        );

        let out = dir.path().join("o2.bin");
        let r = run_cli(
            &[
                OsStr::new("-k"),
                key.as_os_str(),
                OsStr::new("-p"),
                OsStr::new("testpassword"),
                OsStr::new("-o"),
                out.as_os_str(),
                input.as_os_str(),
            ],
            &[("ZSIGN_PASSWORD", "wrong-password")],
        );
        assert_eq!(r.code, 0, "flag must win over env, stderr: {}", r.stderr);
        assert!(out.exists());
    }

    #[test]
    fn missing_password_on_non_tty_degrades_to_clear_error() {
        // no flag, no env, piped stdin: "" trial fails (MAC mismatch) and the
        // error must name both password channels instead of prompting
        let dir = TempDir::new().unwrap();
        let key = dir.path().join("identity.p12");
        std::fs::write(&key, IDENTITY_P12).unwrap();
        let input = dir.path().join("in.bin");
        std::fs::write(&input, MINIMAL_MACHO).unwrap();
        let r = run_cli(
            &[
                OsStr::new("-k"),
                key.as_os_str(),
                OsStr::new("-o"),
                dir.path().join("o.bin").as_os_str(),
                input.as_os_str(),
            ],
            &[],
        );
        assert_eq!(r.code, 1, "stderr: {}", r.stderr);
        assert!(r.stderr.contains("--password"), "stderr: {}", r.stderr);
        assert!(r.stderr.contains("ZSIGN_PASSWORD"), "stderr: {}", r.stderr);
        assert!(
            r.stderr.contains("MAC mismatch"),
            "must surface the real cause: {}",
            r.stderr
        );
    }

    #[test]
    fn empty_password_container_is_never_treated_as_missing() {
        // no flag, no env: this fixture's `""` trial fails at the certificate
        // policy gate (not MAC), and a non-password failure must surface verbatim —
        // never the "no password supplied" channel hint, and never a prompt
        // (stdin is piped here, and a prompt would hang a CI job)
        let dir = TempDir::new().unwrap();
        let key = dir.path().join("empty.p12");
        std::fs::write(&key, EMPTY_PASSWORD_P12).unwrap();
        let input = dir.path().join("in.bin");
        std::fs::write(&input, MINIMAL_MACHO).unwrap();
        let r = run_cli(
            &[
                OsStr::new("-k"),
                key.as_os_str(),
                OsStr::new("-o"),
                dir.path().join("o.bin").as_os_str(),
                input.as_os_str(),
            ],
            &[],
        );
        assert!(
            !r.stderr.contains("MAC mismatch"),
            "not a password failure: {}",
            r.stderr
        );
        assert!(
            !r.stderr.contains("ZSIGN_PASSWORD"),
            "must not demand a password: {}",
            r.stderr
        );
        assert!(
            !r.stderr.contains("no password supplied"),
            "verbatim surface: {}",
            r.stderr
        );
    }

    #[test]
    fn help_does_not_leak_env_password_value() {
        let r = run_cli(
            &[OsStr::new("--help")],
            &[("ZSIGN_PASSWORD", "s3cret-value")],
        );
        assert_eq!(r.code, 0);
        assert!(!r.stdout.contains("s3cret-value"), "leaked: {}", r.stdout);
        assert!(
            r.stdout.contains("[env: ZSIGN_PASSWORD]"),
            "stdout: {}",
            r.stdout
        );
    }

    /// Parse-level helper: these args must be rejected by clap itself, with the
    /// failure surfaced as a typed `clap::error::Error` (never a runtime check).
    /// `match` rather than `expect_err` because `Cli` deliberately has no
    /// `Debug` impl and the production struct is frozen in this lane.
    fn parse_err(args: &[&str]) -> clap::error::Error {
        match Cli::try_parse_from(args) {
            Ok(_) => panic!("must be rejected"),
            Err(e) => e,
        }
    }

    #[test]
    fn verify_conflicts_with_sign_only_flags() {
        for extra in [
            vec!["zsign", "-V", "-o", "x.ipa", "in.ipa"],
            vec!["zsign", "-V", "-m", "p.mobileprovision", "in.ipa"],
            vec!["zsign", "-V", "-z", "5", "in.ipa"],
            vec!["zsign", "-V", "-a", "in.ipa"],
            vec!["zsign", "-V", "-c", "c.pem", "-k", "k.pem", "in.ipa"],
            vec!["zsign", "-V", "--pkcs12", "x.p12", "in.ipa"],
            vec!["zsign", "-V", "-2", "in.ipa"],
        ] {
            assert_eq!(
                parse_err(&extra).kind(),
                clap::error::ErrorKind::ArgumentConflict
            );
        }
        // verify itself stays valid, and ZSIGN_PASSWORD must NOT conflict (env presentness)
        assert!(Cli::try_parse_from(["zsign", "-V", "in.ipa"]).is_ok());
    }

    #[test]
    fn entitlements_flag_parses_short_and_long() {
        for args in [
            ["zsign", "-a", "-e", "x.plist", "in.bin"],
            ["zsign", "-a", "--entitlements", "x.plist", "in.bin"],
        ] {
            let cli = Cli::try_parse_from(args).expect("must parse");
            assert_eq!(cli.entitlements, Some(PathBuf::from("x.plist")));
        }
    }

    #[test]
    fn verify_conflicts_with_entitlements() {
        for extra in [
            vec!["zsign", "-V", "-e", "x.plist", "in.ipa"],
            vec!["zsign", "-V", "--entitlements", "x.plist", "in.ipa"],
        ] {
            assert_eq!(
                parse_err(&extra).kind(),
                clap::error::ErrorKind::ArgumentConflict
            );
        }
        // entitlements alone (and alongside adhoc) stays valid
        assert!(Cli::try_parse_from(["zsign", "-V", "in.ipa"]).is_ok());
        assert!(Cli::try_parse_from(["zsign", "-a", "-e", "x.plist", "in.bin"]).is_ok());
    }

    #[test]
    fn entitlements_dir_flag_parses() {
        let cli = Cli::try_parse_from(["zsign", "-a", "--entitlements-dir", "ents", "in.ipa"])
            .expect("must parse");
        assert_eq!(cli.entitlements_dir, Some(PathBuf::from("ents")));
    }

    #[test]
    fn verify_conflicts_with_entitlements_dir() {
        for extra in [
            vec!["zsign", "-V", "--entitlements-dir", "ents", "in.ipa"],
            vec!["zsign", "--entitlements-dir", "ents", "-V", "in.ipa"],
        ] {
            assert_eq!(
                parse_err(&extra).kind(),
                clap::error::ErrorKind::ArgumentConflict
            );
        }
        // alone-valid controls
        assert!(Cli::try_parse_from(["zsign", "-V", "in.ipa"]).is_ok());
        assert!(
            Cli::try_parse_from(["zsign", "-a", "--entitlements-dir", "ents", "in.ipa"]).is_ok()
        );
    }

    #[test]
    fn profile_map_parses_repeated_pairs() {
        let cli = Cli::try_parse_from([
            "zsign",
            "-a",
            "--profile-map",
            "com.test.app.ext=ext.mobileprovision",
            "--profile-map",
            "com.test.app.fwk=fwk.mobileprovision",
            "in.ipa",
        ])
        .expect("must parse");
        assert_eq!(
            cli.profile_map,
            vec![
                (
                    "com.test.app.ext".to_string(),
                    PathBuf::from("ext.mobileprovision")
                ),
                (
                    "com.test.app.fwk".to_string(),
                    PathBuf::from("fwk.mobileprovision")
                ),
            ]
        );
    }

    #[test]
    fn profile_map_rejects_malformed_at_parse() {
        for bad in ["nopath", "=x", "a="] {
            assert_eq!(
                parse_err(&["zsign", "-a", "--profile-map", bad, "in.ipa"]).kind(),
                clap::error::ErrorKind::ValueValidation,
                "{bad:?} must be rejected at parse time"
            );
        }
        assert!(Cli::try_parse_from([
            "zsign",
            "-a",
            "--profile-map",
            "com.test.app.ext=ext.mobileprovision",
            "in.ipa"
        ])
        .is_ok());
    }

    #[test]
    fn verify_conflicts_with_profile_map() {
        for extra in [
            vec!["zsign", "-V", "--profile-map", "a=b", "in.ipa"],
            vec!["zsign", "--profile-map", "a=b", "-V", "in.ipa"],
        ] {
            assert_eq!(
                parse_err(&extra).kind(),
                clap::error::ErrorKind::ArgumentConflict
            );
        }
        assert!(Cli::try_parse_from(["zsign", "-V", "in.ipa"]).is_ok());
        assert!(Cli::try_parse_from(["zsign", "-a", "--profile-map", "a=b", "in.ipa"]).is_ok());
    }

    #[test]
    fn remove_profile_flag_parses_short_and_long() {
        for args in [
            ["zsign", "-a", "-R", "in.ipa"],
            ["zsign", "-a", "--remove-profile", "in.ipa"],
        ] {
            let cli = Cli::try_parse_from(args).expect("must parse");
            assert!(cli.remove_profile);
        }
        // The flag is a bool: it must be absent (false) by default.
        let cli = Cli::try_parse_from(["zsign", "-a", "in.ipa"]).expect("must parse");
        assert!(!cli.remove_profile);
    }

    #[test]
    fn verify_conflicts_with_remove_profile() {
        for extra in [
            vec!["zsign", "-V", "-R", "in.ipa"],
            vec!["zsign", "-R", "-V", "in.ipa"],
        ] {
            assert_eq!(
                parse_err(&extra).kind(),
                clap::error::ErrorKind::ArgumentConflict
            );
        }
        // alone-valid controls
        assert!(Cli::try_parse_from(["zsign", "-V", "in.ipa"]).is_ok());
        assert!(Cli::try_parse_from(["zsign", "-a", "-R", "in.ipa"]).is_ok());
    }

    #[test]
    fn sha256_only_conflicts_with_legacy_sha1_at_parse() {
        assert_eq!(
            parse_err(&["zsign", "-2", "-L", "in.ipa"]).kind(),
            clap::error::ErrorKind::ArgumentConflict
        );
        assert_eq!(
            parse_err(&["zsign", "-L", "-2", "in.ipa"]).kind(),
            clap::error::ErrorKind::ArgumentConflict
        );
        // each flag alone stays valid (adhoc supplies the credentials exemption)
        assert!(Cli::try_parse_from(["zsign", "-a", "-2", "in.ipa"]).is_ok());
        assert!(Cli::try_parse_from(["zsign", "-a", "-L", "in.ipa"]).is_ok());
    }

    #[test]
    fn adhoc_conflicts_with_profile_at_parse() {
        assert_eq!(
            parse_err(&["zsign", "-a", "-m", "p.mobileprovision", "in.ipa"]).kind(),
            clap::error::ErrorKind::ArgumentConflict
        );
        assert_eq!(
            parse_err(&["zsign", "-m", "p.mobileprovision", "-a", "in.ipa"]).kind(),
            clap::error::ErrorKind::ArgumentConflict
        );
        // profile stays valid with credentials and without adhoc
        assert!(Cli::try_parse_from([
            "zsign",
            "--pkcs12",
            "x.p12",
            "-p",
            "pw",
            "-m",
            "p.mobileprovision",
            "in.ipa"
        ])
        .is_ok());
        // adhoc without a profile stays valid
        assert!(Cli::try_parse_from(["zsign", "-a", "in.ipa"]).is_ok());
    }

    #[test]
    fn credentials_group_required_unless_adhoc_or_verify() {
        assert_eq!(
            parse_err(&["zsign", "in.ipa"]).kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );
        assert!(Cli::try_parse_from(["zsign", "-a", "in.ipa"]).is_ok());
        assert!(Cli::try_parse_from(["zsign", "-V", "in.ipa"]).is_ok());
        assert!(Cli::try_parse_from(["zsign", "--pkcs12", "x.p12", "in.ipa"]).is_ok());
        assert!(Cli::try_parse_from(["zsign", "-k", "x.p12", "in.ipa"]).is_ok());
        assert!(Cli::try_parse_from(["zsign", "-c", "c.pem", "-k", "k.pem", "in.ipa"]).is_ok());
        // certificate without private key
        assert_eq!(
            parse_err(&["zsign", "-c", "c.pem", "in.ipa"]).kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );
        // pkcs12 conflicts with the certificate/key pair
        assert_eq!(
            parse_err(&["zsign", "--pkcs12", "x.p12", "-c", "c.pem", "-k", "k.pem", "in.ipa"])
                .kind(),
            clap::error::ErrorKind::ArgumentConflict
        );
    }

    #[test]
    fn zip_level_range_is_enforced_at_parse() {
        assert_eq!(
            parse_err(&["zsign", "-a", "-z", "99", "in.ipa"]).kind(),
            clap::error::ErrorKind::ValueValidation
        );
        assert!(Cli::try_parse_from(["zsign", "-a", "-z", "9", "in.ipa"]).is_ok());
        assert!(Cli::try_parse_from(["zsign", "-a", "-z", "0", "in.ipa"]).is_ok());
    }

    #[test]
    fn encrypted_pem_routes_through_the_password_flow() {
        let dir = TempDir::new().unwrap();
        let input = dir.path().join("in.bin");
        std::fs::write(&input, MINIMAL_MACHO).unwrap();
        let key = dir.path().join("key.pem");
        let cert = dir.path().join("cert.pem");
        std::fs::write(&key, pem_fixture(ENC_TRAD_RSA)).unwrap();
        std::fs::write(&cert, RSA_CERT).unwrap();
        let out = dir.path().join("o.bin");

        // No password: the loader says exactly what it needs.
        let r = run_cli(
            &[
                OsStr::new("-k"),
                key.as_os_str(),
                OsStr::new("-c"),
                cert.as_os_str(),
                OsStr::new("-o"),
                out.as_os_str(),
                input.as_os_str(),
            ],
            &[],
        );
        assert_eq!(r.code, 1, "stderr: {}", r.stderr);
        assert!(
            r.stderr.contains("requires a password"),
            "stderr: {}",
            r.stderr
        );

        // Wrong password: an explicit password failure, not a generic parse error.
        let r = run_cli(
            &[
                OsStr::new("-k"),
                key.as_os_str(),
                OsStr::new("-c"),
                cert.as_os_str(),
                OsStr::new("-p"),
                OsStr::new("nope"),
                OsStr::new("-o"),
                out.as_os_str(),
                input.as_os_str(),
            ],
            &[],
        );
        assert_eq!(r.code, 1, "stderr: {}", r.stderr);
        assert!(
            r.stderr.contains("Invalid password"),
            "stderr: {}",
            r.stderr
        );

        // Correct password: the key loads and the binary signs.
        let r = run_cli(
            &[
                OsStr::new("-k"),
                key.as_os_str(),
                OsStr::new("-c"),
                cert.as_os_str(),
                OsStr::new("-p"),
                OsStr::new("testpassword"),
                OsStr::new("-o"),
                out.as_os_str(),
                input.as_os_str(),
            ],
            &[],
        );
        assert_eq!(r.code, 0, "stderr: {}", r.stderr);
        assert!(out.exists(), "signed output missing");
    }

    #[test]
    fn pbes2_pem_wrong_password_is_a_password_error_at_the_cli_too() {
        let dir = TempDir::new().unwrap();
        let input = dir.path().join("in.bin");
        std::fs::write(&input, MINIMAL_MACHO).unwrap();
        let key = dir.path().join("key.pem");
        let cert = dir.path().join("cert.pem");
        std::fs::write(&key, pem_fixture(ENC_PKCS8_RSA)).unwrap();
        std::fs::write(&cert, RSA_CERT).unwrap();
        let r = run_cli(
            &[
                OsStr::new("-k"),
                key.as_os_str(),
                OsStr::new("-c"),
                cert.as_os_str(),
                OsStr::new("-p"),
                OsStr::new("nope"),
                OsStr::new("-o"),
                dir.path().join("o.bin").as_os_str(),
                input.as_os_str(),
            ],
            &[],
        );
        assert_eq!(r.code, 1, "stderr: {}", r.stderr);
        assert!(
            r.stderr.contains("Invalid password"),
            "a PBES2 wrong password must be explicit at the CLI too, stderr: {}",
            r.stderr
        );
    }

    #[test]
    fn password_on_an_unencrypted_pem_key_is_now_accepted() {
        // The deleted reject path failed *any* password on the key route before looking at the
        // key at all. A well-formed but undecodable plaintext PEM now reaches the loader, so the
        // only failures left are the ordinary parse/pairing ones. The label is split so no
        // source line carries a private-key header.
        let dir = TempDir::new().unwrap();
        let input = dir.path().join("in.bin");
        std::fs::write(&input, MINIMAL_MACHO).unwrap();
        let key = dir.path().join("key.pem");
        let cert = dir.path().join("cert.pem");
        std::fs::write(
            &key,
            concat!(
                "-----BEGIN ",
                "PRIVATE KEY-----\n",
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n",
                "-----END ",
                "PRIVATE KEY-----\n"
            ),
        )
        .unwrap();
        std::fs::write(&cert, RSA_CERT).unwrap();
        let r = run_cli(
            &[
                OsStr::new("-k"),
                key.as_os_str(),
                OsStr::new("-c"),
                cert.as_os_str(),
                OsStr::new("-p"),
                OsStr::new("irrelevant"),
                OsStr::new("-o"),
                dir.path().join("o.bin").as_os_str(),
                input.as_os_str(),
            ],
            &[],
        );
        assert_eq!(r.code, 1, "stderr: {}", r.stderr);
        assert!(
            !r.stderr.contains("encrypted PEM keys are unsupported"),
            "the old reject path must be gone, stderr: {}",
            r.stderr
        );
        assert!(
            r.stderr.contains("Failed to parse private key"),
            "a password on an unencrypted key must be ignored, not rejected, stderr: {}",
            r.stderr
        );
    }

    #[test]
    fn credential_io_errors_name_the_file() {
        let dir = TempDir::new().unwrap();
        let input = dir.path().join("in.bin");
        std::fs::write(&input, MINIMAL_MACHO).unwrap();
        let missing_key = dir.path().join("absent.key");
        let r = run_cli(
            &[
                OsStr::new("-k"),
                missing_key.as_os_str(),
                OsStr::new("-o"),
                dir.path().join("o.bin").as_os_str(),
                input.as_os_str(),
            ],
            &[],
        );
        assert_eq!(r.code, 1);
        assert!(r.stderr.contains("absent.key"), "stderr: {}", r.stderr);
        assert!(
            r.stderr.contains("private key"),
            "label the flag: {}",
            r.stderr
        );
    }

    #[test]
    fn missing_profile_error_names_the_file() {
        let dir = TempDir::new().unwrap();
        let key = dir.path().join("identity.p12");
        std::fs::write(&key, IDENTITY_P12).unwrap();
        let input = dir.path().join("in.bin");
        std::fs::write(&input, MINIMAL_MACHO).unwrap();
        let out = dir.path().join("out.bin");
        let profile = dir.path().join("absent.mobileprovision");
        let r = run_cli(
            &[
                OsStr::new("-k"),
                key.as_os_str(),
                OsStr::new("-p"),
                OsStr::new("testpassword"),
                OsStr::new("-m"),
                profile.as_os_str(),
                OsStr::new("-o"),
                out.as_os_str(),
                input.as_os_str(),
            ],
            &[],
        );
        assert_eq!(r.code, 1, "expected 1, stderr: {}", r.stderr);
        assert!(
            r.stderr.contains("absent.mobileprovision"),
            "stderr must name the profile file: {}",
            r.stderr
        );
        assert!(
            r.stderr.contains("provisioning profile"),
            "stderr must name the label: {}",
            r.stderr
        );
    }
}
