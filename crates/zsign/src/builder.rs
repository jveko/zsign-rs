//! ZSign builder API
//!
//! Provides a builder pattern interface for iOS code signing operations.
//! Supports signing Mach-O binaries, IPA files, and app bundles.

use crate::crypto::SigningAssets;
use crate::ipa::{CompressionLevel, IpaSigner};
use crate::macho::{sign_macho, MachOFile};
use crate::{Error, Result};
use secrecy::SecretString;
use std::path::{Path, PathBuf};

/// iOS code signing tool with builder pattern API.
///
/// # Example
///
/// ```ignore
/// use zsign::ZSign;
///
/// ZSign::new()
///     .pkcs12("certificate.p12")
///     .password("secret")
///     .provisioning_profile("profile.mobileprovision")
///     .sign_macho("input", "output")?;
/// ```
#[derive(Clone)]
pub struct ZSign {
    certificate: Option<PathBuf>,
    private_key: Option<PathBuf>,
    pkcs12: Option<PathBuf>,
    provisioning_profile: Option<PathBuf>,
    password: Option<SecretString>,
    compression_level: CompressionLevel,
}

impl ZSign {
    /// Create a new ZSign builder.
    pub fn new() -> Self {
        Self {
            certificate: None,
            private_key: None,
            pkcs12: None,
            provisioning_profile: None,
            password: None,
            compression_level: CompressionLevel::DEFAULT,
        }
    }

    /// Set certificate file path (PEM or DER format).
    ///
    /// Use together with `private_key()` for PEM-based signing.
    /// Alternatively, use `pkcs12()` for PKCS#12 files that contain both.
    pub fn certificate(mut self, path: impl AsRef<Path>) -> Self {
        self.certificate = Some(path.as_ref().to_path_buf());
        self
    }

    /// Set private key file path (PEM or DER format).
    ///
    /// Use together with `certificate()` for PEM-based signing.
    /// Alternatively, use `pkcs12()` for PKCS#12 files that contain both.
    pub fn private_key(mut self, path: impl AsRef<Path>) -> Self {
        self.private_key = Some(path.as_ref().to_path_buf());
        self
    }

    /// Set PKCS#12 file path (.p12 format).
    ///
    /// PKCS#12 files contain both the certificate and private key.
    /// Use `password()` to set the decryption password.
    pub fn pkcs12(mut self, path: impl AsRef<Path>) -> Self {
        self.pkcs12 = Some(path.as_ref().to_path_buf());
        self
    }

    /// Set provisioning profile path (.mobileprovision format).
    ///
    /// The provisioning profile contains entitlements that will be
    /// embedded in the signed binary.
    pub fn provisioning_profile(mut self, path: impl AsRef<Path>) -> Self {
        self.provisioning_profile = Some(path.as_ref().to_path_buf());
        self
    }

    /// Set password for private key or PKCS#12 file.
    ///
    /// The password is stored securely and will be zeroized when dropped.
    pub fn password(mut self, password: impl Into<String>) -> Self {
        self.password = Some(SecretString::new(password.into()));
        self
    }

    /// Set ZIP compression level for IPA output (0-9).
    ///
    /// 0 = no compression (fastest), 9 = maximum compression (smallest).
    /// Default is 6 (balanced).
    pub fn compression_level(mut self, level: u32) -> Self {
        self.compression_level = CompressionLevel::new(level);
        self
    }

    /// Validate the builder configuration.
    ///
    /// Returns an error if:
    /// - Both PKCS#12 and PEM credentials are specified
    /// - Neither PKCS#12 nor PEM credentials are specified
    /// - Only one of certificate/private_key is specified (need both)
    pub fn validate(&self) -> Result<()> {
        let has_p12 = self.pkcs12.is_some();
        let has_pem = self.certificate.is_some() || self.private_key.is_some();

        if has_p12 && has_pem {
            return Err(Error::Config(
                "Cannot specify both PKCS#12 and PEM certificate/key".into(),
            ));
        }

        if !has_p12 && !has_pem {
            return Err(Error::MissingCredentials(
                "Must specify either PKCS#12 or certificate/key pair".into(),
            ));
        }

        if has_pem && (self.certificate.is_none() || self.private_key.is_none()) {
            return Err(Error::MissingCredentials(
                "Both certificate and private key must be specified".into(),
            ));
        }

        Ok(())
    }

    /// Load signing assets from configured paths.
    ///
    /// Uses PKCS#12 if configured, otherwise uses separate certificate and private key.
    /// Optionally loads provisioning profile for entitlements.
    fn load_assets(&self) -> Result<SigningAssets> {
        self.validate()?;

        let mut assets = if let Some(ref p12) = self.pkcs12 {
            SigningAssets::from_p12(p12, self.password.as_ref())?
        } else {
            let cert = self
                .certificate
                .as_ref()
                .ok_or_else(|| Error::Certificate("No certificate configured".into()))?;
            let key = self
                .private_key
                .as_ref()
                .ok_or_else(|| Error::Certificate("No private key configured".into()))?;
            SigningAssets::from_pem(cert, key, self.password.as_ref())?
        };

        if let Some(ref profile) = self.provisioning_profile {
            assets = assets.with_provisioning_profile(profile)?;
        }

        Ok(assets)
    }

    /// Sign a Mach-O binary.
    ///
    /// Loads signing assets, parses the Mach-O binary, generates a code signature,
    /// and writes a complete signed binary to the output path.
    ///
    /// # Arguments
    ///
    /// * `input` - Path to the input Mach-O binary
    /// * `output` - Path for the signed output binary
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Signing assets cannot be loaded
    /// - Input file cannot be parsed as Mach-O
    /// - Signing fails
    /// - Output file cannot be written
    pub fn sign_macho(&self, input: impl AsRef<Path>, output: impl AsRef<Path>) -> Result<()> {
        let assets = self.load_assets()?;
        let macho = MachOFile::open(input.as_ref())?;

        // Get bundle ID from file name as fallback
        let identifier = input
            .as_ref()
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown");

        let signed_binary = sign_macho(
            &macho,
            identifier,
            assets.team_id.as_deref(),
            assets.entitlements.as_deref(),
            &assets.certificate,
            &assets.private_key,
            &assets.cert_chain,
            None, // info_plist
            None, // code_resources
        )?;

        // Write the complete signed binary
        std::fs::write(output.as_ref(), signed_binary)?;

        Ok(())
    }

    /// Sign an IPA file.
    ///
    /// Extracts the IPA, signs all Mach-O binaries in the bundle,
    /// generates CodeResources, and repacks into a new IPA.
    ///
    /// # Arguments
    ///
    /// * `input` - Path to the input IPA file
    /// * `output` - Path for the signed output IPA
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Signing assets cannot be loaded
    /// - IPA extraction fails
    /// - Bundle signing fails
    /// - IPA repacking fails
    pub fn sign_ipa(
        &self,
        input: impl AsRef<Path>,
        output: impl AsRef<Path>,
    ) -> Result<()> {
        let assets = self.load_assets()?;
        let mut signer = IpaSigner::new(assets)
            .compression_level(self.compression_level);

        // Pass provisioning profile path to IpaSigner for embedding as embedded.mobileprovision
        if let Some(ref profile_path) = self.provisioning_profile {
            signer = signer.provisioning_profile(profile_path);
        }

        signer.sign(input, output)
    }

    /// Sign an app bundle.
    ///
    /// Not yet implemented.
    pub fn sign_bundle(&self, _bundle_path: impl AsRef<Path>) -> Result<()> {
        Err(Error::Signing("Bundle signing not yet implemented".into()))
    }
}

impl Default for ZSign {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    #[test]
    fn test_zsign_builder_default() {
        let zsign = ZSign::default();
        assert!(zsign.certificate.is_none());
        assert!(zsign.private_key.is_none());
        assert!(zsign.pkcs12.is_none());
        assert!(zsign.provisioning_profile.is_none());
        assert!(zsign.password.is_none());
    }

    #[test]
    fn test_zsign_builder_chain() {
        let zsign = ZSign::new()
            .certificate("/path/to/cert.pem")
            .private_key("/path/to/key.pem")
            .password("secret");

        assert_eq!(
            zsign.certificate,
            Some(PathBuf::from("/path/to/cert.pem"))
        );
        assert_eq!(
            zsign.private_key,
            Some(PathBuf::from("/path/to/key.pem"))
        );
        assert!(zsign.password.is_some());
        assert_eq!(zsign.password.as_ref().unwrap().expose_secret(), "secret");
    }

    #[test]
    fn test_zsign_builder_pkcs12() {
        let zsign = ZSign::new()
            .pkcs12("/path/to/cert.p12")
            .password("p12secret")
            .provisioning_profile("/path/to/profile.mobileprovision");

        assert_eq!(zsign.pkcs12, Some(PathBuf::from("/path/to/cert.p12")));
        assert!(zsign.password.is_some());
        assert_eq!(zsign.password.as_ref().unwrap().expose_secret(), "p12secret");
        assert_eq!(
            zsign.provisioning_profile,
            Some(PathBuf::from("/path/to/profile.mobileprovision"))
        );
    }

    #[test]
    fn test_load_assets_no_credentials() {
        let zsign = ZSign::new();
        let result = zsign.load_assets();
        assert!(result.is_err());
    }

    #[test]
    fn test_sign_ipa_requires_credentials() {
        let zsign = ZSign::new();
        let result = zsign.sign_ipa("input.ipa", "output.ipa");
        assert!(result.is_err());
        if let Err(Error::MissingCredentials(msg)) = result {
            assert!(msg.contains("Must specify either PKCS#12 or certificate/key pair"));
        }
    }

    #[test]
    fn test_compression_level_builder() {
        let zsign = ZSign::new().compression_level(9);
        assert_eq!(zsign.compression_level.level(), 9);
    }

    #[test]
    fn test_sign_bundle_not_implemented() {
        let zsign = ZSign::new();
        let result = zsign.sign_bundle("MyApp.app");
        assert!(result.is_err());
        if let Err(Error::Signing(msg)) = result {
            assert!(msg.contains("not yet implemented"));
        }
    }

    #[test]
    fn test_validate_both_p12_and_pem() {
        let zsign = ZSign::new()
            .pkcs12("/path/to/cert.p12")
            .certificate("/path/to/cert.pem");

        let result = zsign.validate();
        assert!(result.is_err());
        if let Err(Error::Config(msg)) = result {
            assert!(msg.contains("Cannot specify both"));
        }
    }

    #[test]
    fn test_validate_missing_private_key() {
        let zsign = ZSign::new().certificate("/path/to/cert.pem");

        let result = zsign.validate();
        assert!(result.is_err());
        if let Err(Error::MissingCredentials(msg)) = result {
            assert!(msg.contains("Both certificate and private key"));
        }
    }
}
