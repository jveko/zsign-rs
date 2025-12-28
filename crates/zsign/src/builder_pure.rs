//! Pure Rust ZSign builder API
//!
//! Provides a builder pattern interface for iOS code signing operations
//! using pure Rust cryptography (no OpenSSL dependency).

#[cfg(feature = "pure-rust")]
use crate::crypto::PureRustCredentials;
#[cfg(feature = "pure-rust")]
use crate::ipa::{CompressionLevel, IpaSignerPure};
#[cfg(feature = "pure-rust")]
use crate::macho::{sign_macho_pure, MachOFile};
#[cfg(feature = "pure-rust")]
use crate::{Error, Result};
#[cfg(feature = "pure-rust")]
use std::path::{Path, PathBuf};

/// iOS code signing tool with builder pattern API (pure Rust implementation).
///
/// # Example
///
/// ```ignore
/// use zsign::{ZSignPure, PureRustCredentials};
///
/// let credentials = PureRustCredentials::from_p12(&p12_data, "password")?;
///
/// ZSignPure::new()
///     .credentials(credentials)
///     .provisioning_profile("profile.mobileprovision")
///     .sign_macho("input", "output")?;
/// ```
#[cfg(feature = "pure-rust")]
pub struct ZSignPure {
    credentials: Option<PureRustCredentials>,
    provisioning_profile: Option<PathBuf>,
    compression_level: CompressionLevel,
}

#[cfg(feature = "pure-rust")]
impl ZSignPure {
    /// Create a new ZSignPure builder.
    pub fn new() -> Self {
        Self {
            credentials: None,
            provisioning_profile: None,
            compression_level: CompressionLevel::DEFAULT,
        }
    }

    /// Set signing credentials (certificate, private key, cert chain).
    ///
    /// Use `PureRustCredentials::from_p12()` or `PureRustCredentials::from_pem()`
    /// to create credentials from certificate files.
    pub fn credentials(mut self, credentials: PureRustCredentials) -> Self {
        self.credentials = Some(credentials);
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
    /// Returns an error if credentials are not set.
    pub fn validate(&self) -> Result<()> {
        if self.credentials.is_none() {
            return Err(Error::MissingCredentials(
                "Credentials must be set using .credentials()".into(),
            ));
        }
        Ok(())
    }

    /// Get a reference to the credentials, loading entitlements from provisioning profile if set.
    fn get_credentials_with_entitlements(&self) -> Result<&PureRustCredentials> {
        self.validate()?;
        self.credentials
            .as_ref()
            .ok_or_else(|| Error::MissingCredentials("No credentials configured".into()))
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
    /// - Credentials are not set
    /// - Input file cannot be parsed as Mach-O
    /// - Signing fails
    /// - Output file cannot be written
    pub fn sign_macho(&self, input: impl AsRef<Path>, output: impl AsRef<Path>) -> Result<()> {
        let credentials = self.get_credentials_with_entitlements()?;
        let macho = MachOFile::open(input.as_ref())?;

        let identifier = input
            .as_ref()
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown");

        let entitlements = self.load_entitlements_from_profile()?;

        let signed_binary = sign_macho_pure(
            &macho,
            identifier,
            entitlements.as_deref(),
            credentials,
            None,
            None,
        )?;

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
    /// - Credentials are not set
    /// - IPA extraction fails
    /// - Bundle signing fails
    /// - IPA repacking fails
    pub fn sign_ipa(&self, input: impl AsRef<Path>, output: impl AsRef<Path>) -> Result<()> {
        self.validate()?;

        let credentials = self
            .credentials
            .as_ref()
            .ok_or_else(|| Error::MissingCredentials("No credentials configured".into()))?;

        let mut signer =
            IpaSignerPure::new(credentials).compression_level(self.compression_level);

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

    /// Load entitlements from provisioning profile if set.
    fn load_entitlements_from_profile(&self) -> Result<Option<Vec<u8>>> {
        if let Some(ref profile_path) = self.provisioning_profile {
            let profile_data = std::fs::read(profile_path)?;
            if let Some(entitlements) = extract_entitlements_from_profile(&profile_data) {
                return Ok(Some(entitlements));
            }
        }
        Ok(None)
    }
}

#[cfg(feature = "pure-rust")]
impl Default for ZSignPure {
    fn default() -> Self {
        Self::new()
    }
}

/// Extract entitlements from a provisioning profile (mobileprovision file).
///
/// Provisioning profiles are CMS-signed XML plists. This extracts the
/// Entitlements dictionary and converts it back to XML plist format.
#[cfg(feature = "pure-rust")]
fn extract_entitlements_from_profile(profile_data: &[u8]) -> Option<Vec<u8>> {
    let plist_start = profile_data
        .windows(6)
        .position(|w| w == b"<?xml ")?;

    let plist_end = profile_data
        .windows(8)
        .rposition(|w| w == b"</plist>")?
        + 8;

    if plist_start >= plist_end {
        return None;
    }

    let plist_slice = &profile_data[plist_start..plist_end];

    let plist: plist::Value = plist::from_bytes(plist_slice).ok()?;
    let dict = plist.as_dictionary()?;
    let entitlements = dict.get("Entitlements")?;

    let mut buf = Vec::new();
    plist::to_writer_xml(&mut buf, entitlements).ok()?;
    Some(buf)
}

#[cfg(all(test, feature = "pure-rust"))]
mod tests {
    use super::*;

    #[test]
    fn test_zsign_pure_builder_default() {
        let zsign = ZSignPure::default();
        assert!(zsign.credentials.is_none());
        assert!(zsign.provisioning_profile.is_none());
    }

    #[test]
    fn test_zsign_pure_builder_chain() {
        let zsign = ZSignPure::new()
            .provisioning_profile("/path/to/profile.mobileprovision")
            .compression_level(9);

        assert_eq!(
            zsign.provisioning_profile,
            Some(PathBuf::from("/path/to/profile.mobileprovision"))
        );
        assert_eq!(zsign.compression_level.level(), 9);
    }

    #[test]
    fn test_validate_no_credentials() {
        let zsign = ZSignPure::new();
        let result = zsign.validate();
        assert!(result.is_err());
        if let Err(Error::MissingCredentials(msg)) = result {
            assert!(msg.contains("Credentials must be set"));
        }
    }

    #[test]
    fn test_sign_ipa_requires_credentials() {
        let zsign = ZSignPure::new();
        let result = zsign.sign_ipa("input.ipa", "output.ipa");
        assert!(result.is_err());
        if let Err(Error::MissingCredentials(msg)) = result {
            assert!(msg.contains("Credentials must be set"));
        }
    }

    #[test]
    fn test_sign_bundle_not_implemented() {
        let zsign = ZSignPure::new();
        let result = zsign.sign_bundle("MyApp.app");
        assert!(result.is_err());
        if let Err(Error::Signing(msg)) = result {
            assert!(msg.contains("not yet implemented"));
        }
    }
}
