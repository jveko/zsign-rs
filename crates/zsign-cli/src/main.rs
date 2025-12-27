use clap::Parser;
use std::path::PathBuf;
use zsign::ZSign;

#[derive(Parser)]
#[command(name = "zsign")]
#[command(about = "iOS code signing tool")]
struct Cli {
    /// Input file (IPA, Mach-O, or app bundle)
    input: PathBuf,

    /// Output file
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Certificate file (PEM or DER)
    #[arg(short = 'c', long)]
    certificate: Option<PathBuf>,

    /// Private key file (PEM or DER)
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
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    let mut signer = ZSign::new();

    if let Some(cert) = cli.certificate {
        signer = signer.certificate(cert);
    }
    if let Some(key) = cli.private_key {
        signer = signer.private_key(key);
    }
    if let Some(p12) = cli.pkcs12 {
        signer = signer.pkcs12(p12);
    }
    if let Some(profile) = cli.profile {
        signer = signer.provisioning_profile(profile);
    }
    if let Some(password) = cli.password {
        signer = signer.password(password);
    }

    let output = cli.output.unwrap_or_else(|| {
        let mut out = cli.input.clone();
        out.set_extension("signed");
        out
    });

    // Detect input type and sign
    let ext = cli.input.extension()
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
            // Assume Mach-O
            signer.sign_macho(&cli.input, &output)?;
        }
    }

    println!("Signed: {}", output.display());
    Ok(())
}
