//! Command-line interface for zsign iOS code signing tool.
//!
//! Provides a CLI for signing Mach-O binaries, app bundles, and IPA files
//! using PKCS#12 or PEM-format certificates.

use clap::Parser;
use std::path::PathBuf;
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

    /// Check whether the input Mach-O is signed and its hashes verify
    #[arg(short = 'C', long)]
    check: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    run(Cli::parse())
}

/// Runs the CLI from parsed arguments (testable without argv).
fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    if cli.check {
        let report = zsign_rs::macho::check_signature(&cli.input)?;
        println!("signed: {}", report.signed);
        println!("identifier: {:?}", report.identifier);
        println!("sha1 pages: {:?}", report.sha1_pages);
        println!("sha256 pages: {:?}", report.sha256_pages);
        println!("cms present: {}", report.cms_present);
        println!("hashes match: {}", report.hashes_match);
        if !report.hashes_match {
            std::process::exit(1);
        }
        return Ok(());
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
