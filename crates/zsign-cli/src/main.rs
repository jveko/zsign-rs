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
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    let credentials = load_credentials(&cli)?;

    let mut signer = ZSign::new()
        .credentials(credentials)
        .compression_level(cli.zip_level);

    if let Some(profile) = cli.profile {
        signer = signer.provisioning_profile(profile);
    }

    let output = cli.output.unwrap_or_else(|| {
        let mut out = cli.input.clone();
        out.set_extension("signed");
        out
    });

    let ext = cli
        .input
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");

    match ext.to_lowercase().as_str() {
        "ipa" => {
            signer.sign_ipa(&cli.input, &output)?;
        }
        "app" => {
            signer.sign_bundle(&cli.input)?;
        }
        _ => {
            signer.sign_macho(&cli.input, &output)?;
        }
    }

    println!("Signed: {}", output.display());
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
