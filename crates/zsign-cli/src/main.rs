//! Command-line interface for zsign iOS code signing tool.
//!
//! Provides a CLI for signing Mach-O binaries, app bundles, and IPA files
//! using PKCS#12 or PEM-format certificates.

use clap::Parser;
use std::path::PathBuf;
use zsign_rs::codesign::verify::{PageCheck, SpecialSlotCheck};
use zsign_rs::verify::MachOVerifyReport;
use zsign_rs::{SigningCredentials, ZSign};

#[derive(Parser)]
#[command(name = "zsign")]
#[command(about = "iOS code signing tool")]
struct Cli {
    /// Input file (IPA, Mach-O, or app bundle)
    input: PathBuf,

    /// Output file
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Certificate file (PEM format)
    #[arg(short = 'c', long)]
    certificate: Option<PathBuf>,

    /// Private key file (PEM format)
    #[arg(short = 'k', long)]
    private_key: Option<PathBuf>,

    /// PKCS#12 file (.p12)
    #[arg(short = 'p', long)]
    pkcs12: Option<PathBuf>,

    /// Provisioning profile
    #[arg(short = 'm', long)]
    profile: Option<PathBuf>,

    /// Password for private key or PKCS#12
    #[arg(long)]
    password: Option<String>,

    /// ZIP compression level (0-9, default: 6)
    /// 0 = no compression (fastest, matches C++ zsign default)
    /// 9 = maximum compression (slowest, smallest file)
    #[arg(short = 'z', long, default_value = "6")]
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
    #[arg(short = 'L', long)]
    legacy_sha1: bool,

    /// Force signing: override the FairPlay-encryption refusal and sign
    /// encrypted binaries anyway (for already-decrypted input only).
    #[arg(short = 'f', long)]
    force: bool,

    /// Sign without an identity (ad-hoc)
    #[arg(short = 'a', long)]
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
    #[arg(short = 'V', long)]
    verify: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    run(Cli::parse())
}

/// Runs the CLI from parsed arguments (testable without argv).
fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    if cli.verify {
        return run_verify(&cli.input);
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
            println!("Signed: {}", output.display());
        }
        "app" => {
            // Folder signing: with -o ending in .ipa, repack; otherwise in place.
            signer.sign_bundle(&cli.input, cli.output.as_deref())?;
            match &cli.output {
                Some(ipa) => println!("Signed: {}", ipa.display()),
                None => println!("Signed in place: {}", cli.input.display()),
            }
        }
        _ => {
            let output = cli.output.unwrap_or_else(|| {
                let mut out = cli.input.clone();
                out.set_extension("signed");
                out
            });
            signer.sign_macho(&cli.input, &output)?;
            println!("Signed: {}", output.display());
        }
    }

    Ok(())
}

/// Runs the deep verifier and maps the report to the exit-code contract:
/// 0 valid, 1 invalid, 2 hard error.
fn run_verify(input: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    let report = match input
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_lowercase())
        .as_deref()
    {
        Some("ipa") => zsign_rs::verify::verify_ipa(input)?,
        Some("app") => zsign_rs::verify::verify_bundle(input)?,
        _ => zsign_rs::verify::verify_macho_file(input)?,
    };

    print_report(&report);

    if report.valid() {
        Ok(())
    } else if report.errors.is_empty() {
        std::process::exit(1)
    } else {
        eprintln!("error: verification could not complete");
        for e in &report.errors {
            eprintln!("  {e}");
        }
        std::process::exit(2)
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
    for w in &report.warnings {
        println!("warning: {w}");
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
        let labels = [
            "Info.plist",
            "requirements",
            "CodeResources",
            "application",
            "entitlements",
            "rep-specific",
            "der entitlements",
        ];
        for (i, check) in slice.special_slots.iter().enumerate() {
            let label = labels.get(i).copied().unwrap_or("?");
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

fn load_credentials(cli: &Cli) -> Result<SigningCredentials, Box<dyn std::error::Error>> {
    if let Some(ref p12_path) = cli.pkcs12 {
        let p12_data = std::fs::read(p12_path)?;
        let password = cli.password.as_deref().unwrap_or("");
        let creds = SigningCredentials::from_p12(&p12_data, password)?;
        return Ok(creds);
    }

    if let (Some(ref cert_path), Some(ref key_path)) = (&cli.certificate, &cli.private_key) {
        let cert_data = std::fs::read(cert_path)?;
        let key_data = std::fs::read(key_path)?;
        let creds = SigningCredentials::from_pem(&cert_data, &key_data, None)?;
        return Ok(creds);
    }

    Err("Must provide either --pkcs12 or both --certificate and --private-key".into())
}

#[cfg(test)]
mod tests {
    use super::*;
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
}
