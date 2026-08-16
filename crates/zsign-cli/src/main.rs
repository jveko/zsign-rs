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

    /// Emit only the SHA-256 code directory (no SHA-1 code directory)
    #[arg(short = '2', long)]
    sha256_only: bool,

    /// Force re-signing (accepted for compatibility; no cache is kept)
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
    let cli = Cli::parse();

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
    if !cli.dylibs.is_empty() {
        signer = signer.dylib_injection(cli.dylibs.clone(), cli.weak);
    }
    let _ = cli.force; // accepted for compatibility; no signing cache is kept

    let ext = cli
        .input
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");

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
