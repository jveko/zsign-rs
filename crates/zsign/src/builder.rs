//! High-level builder API for iOS code signing.
//!
//! This module provides a fluent builder pattern for signing Mach-O binaries,
//! app bundles, and IPA files. Configure credentials, provisioning profiles,
//! and compression settings before invoking signing operations.
//!
//! # Examples
//!
//! ```no_run
//! use zsign::{ZSign, SigningCredentials};
//!
//! let p12_data = std::fs::read("certificate.p12").unwrap();
//! let credentials = SigningCredentials::from_p12(&p12_data, "password").unwrap();
//!
//! ZSign::new()
//!     .credentials(credentials)
//!     .provisioning_profile("app.mobileprovision")
//!     .compression_level(6)
//!     .sign_ipa("input.ipa", "output.ipa")
//!     .unwrap();
//! ```
//!
//! # See Also
//!
//! - [`SigningCredentials`] - Certificate and key loading
//! - [`crate::ipa::IpaSigner`] - Lower-level IPA signing API

use crate::crypto::SigningCredentials;
use crate::ipa::{CompressionLevel, IpaSigner};
use crate::macho::{sign_macho, MachOFile};
use crate::{Error, Result};
use std::path::{Path, PathBuf};

/// iOS code signing tool with builder pattern API.
///
/// [`ZSign`] provides a fluent interface for configuring and executing code signing
/// operations. Create a new instance with [`ZSign::new`], configure it with the
/// builder methods, then call a signing method.
///
/// # Examples
///
/// Sign a Mach-O binary:
///
/// ```no_run
/// use zsign::{ZSign, SigningCredentials};
///
/// let p12_data = std::fs::read("cert.p12").unwrap();
/// let credentials = SigningCredentials::from_p12(&p12_data, "password").unwrap();
///
/// ZSign::new()
///     .credentials(credentials)
///     .sign_macho("input", "output")
///     .unwrap();
/// ```
///
/// Sign an IPA with a provisioning profile:
///
/// ```no_run
/// use zsign::{ZSign, SigningCredentials};
///
/// let p12_data = std::fs::read("cert.p12").unwrap();
/// let credentials = SigningCredentials::from_p12(&p12_data, "password").unwrap();
///
/// ZSign::new()
///     .credentials(credentials)
///     .provisioning_profile("profile.mobileprovision")
///     .compression_level(9)
///     .sign_ipa("input.ipa", "output.ipa")
///     .unwrap();
/// ```
///
/// # See Also
///
/// - [`SigningCredentials`] - How to load certificates
/// - [`crate::ipa::IpaSigner`] - Alternative low-level API for IPA signing
pub struct ZSign {
    credentials: Option<SigningCredentials>,
    provisioning_profile: Option<PathBuf>,
    compression_level: CompressionLevel,
}

impl ZSign {
    /// Creates a new [`ZSign`] builder with default settings.
    ///
    /// # Examples
    ///
    /// ```
    /// use zsign::ZSign;
    ///
    /// let zsign = ZSign::new();
    /// ```
    pub fn new() -> Self {
        Self {
            credentials: None,
            provisioning_profile: None,
            compression_level: CompressionLevel::DEFAULT,
        }
    }

    /// Sets the signing credentials (certificate, private key, and optional chain).
    ///
    /// Credentials are required before calling any signing method.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use zsign::{ZSign, SigningCredentials};
    ///
    /// let p12_data = std::fs::read("cert.p12").unwrap();
    /// let credentials = SigningCredentials::from_p12(&p12_data, "password").unwrap();
    ///
    /// let zsign = ZSign::new().credentials(credentials);
    /// ```
    ///
    /// # See Also
    ///
    /// - [`SigningCredentials::from_p12`] - Load from PKCS#12 file
    /// - [`SigningCredentials::from_pem`] - Load from PEM files
    pub fn credentials(mut self, credentials: SigningCredentials) -> Self {
        self.credentials = Some(credentials);
        self
    }

    /// Sets the provisioning profile path.
    ///
    /// The provisioning profile (`.mobileprovision` file) contains entitlements
    /// that will be embedded in the signed binary. Required for most iOS app signing.
    ///
    /// # Examples
    ///
    /// ```
    /// use zsign::ZSign;
    ///
    /// let zsign = ZSign::new()
    ///     .provisioning_profile("app.mobileprovision");
    /// ```
    pub fn provisioning_profile(mut self, path: impl AsRef<Path>) -> Self {
        self.provisioning_profile = Some(path.as_ref().to_path_buf());
        self
    }

    /// Sets the ZIP compression level for IPA output.
    ///
    /// Valid values are 0-9:
    /// - `0` - No compression (fastest, largest file)
    /// - `6` - Default (balanced)
    /// - `9` - Maximum compression (slowest, smallest file)
    ///
    /// # Examples
    ///
    /// ```
    /// use zsign::ZSign;
    ///
    /// let zsign = ZSign::new().compression_level(9);
    /// ```
    pub fn compression_level(mut self, level: u32) -> Self {
        self.compression_level = CompressionLevel::new(level);
        self
    }

    /// Validates the builder configuration.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MissingCredentials`] if credentials have not been set.
    ///
    /// # Examples
    ///
    /// ```
    /// use zsign::ZSign;
    ///
    /// let result = ZSign::new().validate();
    /// assert!(result.is_err()); // No credentials set
    /// ```
    pub fn validate(&self) -> Result<()> {
        if self.credentials.is_none() {
            return Err(Error::MissingCredentials(
                "Credentials must be set using .credentials()".into(),
            ));
        }
        Ok(())
    }

    /// Gets a reference to the credentials after validation.
    fn get_credentials_with_entitlements(&self) -> Result<&SigningCredentials> {
        self.validate()?;
        self.credentials
            .as_ref()
            .ok_or_else(|| Error::MissingCredentials("No credentials configured".into()))
    }

    /// Signs a Mach-O binary.
    ///
    /// Loads signing assets, parses the Mach-O binary, generates a code signature,
    /// and writes a complete signed binary to the output path.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - [`Error::MissingCredentials`] - Credentials not set
    /// - [`Error::MachO`] - Input file is not a valid Mach-O binary
    /// - [`Error::Signing`] - Signature generation failed
    /// - [`Error::Io`] - File read/write failed
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use zsign::{ZSign, SigningCredentials};
    ///
    /// let p12_data = std::fs::read("cert.p12").unwrap();
    /// let credentials = SigningCredentials::from_p12(&p12_data, "password").unwrap();
    ///
    /// ZSign::new()
    ///     .credentials(credentials)
    ///     .sign_macho("input_binary", "output_binary")
    ///     .unwrap();
    /// ```
    pub fn sign_macho(&self, input: impl AsRef<Path>, output: impl AsRef<Path>) -> Result<()> {
        let credentials = self.get_credentials_with_entitlements()?;
        let macho = MachOFile::open(input.as_ref())?;

        let identifier = input
            .as_ref()
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown");

        let entitlements = self.load_entitlements_from_profile()?;

        let signed_binary = sign_macho(
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

    /// Signs an IPA file.
    ///
    /// Extracts the IPA, signs all Mach-O binaries in the bundle,
    /// generates CodeResources, and repacks into a new IPA.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - [`Error::MissingCredentials`] - Credentials not set
    /// - [`Error::Zip`] - IPA extraction or creation failed
    /// - [`Error::Signing`] - Bundle signing failed
    /// - [`Error::ProvisioningProfile`] - Invalid provisioning profile
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use zsign::{ZSign, SigningCredentials};
    ///
    /// let p12_data = std::fs::read("cert.p12").unwrap();
    /// let credentials = SigningCredentials::from_p12(&p12_data, "password").unwrap();
    ///
    /// ZSign::new()
    ///     .credentials(credentials)
    ///     .provisioning_profile("app.mobileprovision")
    ///     .sign_ipa("input.ipa", "output.ipa")
    ///     .unwrap();
    /// ```
    ///
    /// # See Also
    ///
    /// - [`crate::ipa::IpaSigner`] - Lower-level IPA signing with more control
    pub fn sign_ipa(&self, input: impl AsRef<Path>, output: impl AsRef<Path>) -> Result<()> {
        self.validate()?;

        let credentials = self
            .credentials
            .as_ref()
            .ok_or_else(|| Error::MissingCredentials("No credentials configured".into()))?;

        let mut signer =
            IpaSigner::new(credentials).compression_level(self.compression_level);

        if let Some(ref profile_path) = self.provisioning_profile {
            signer = signer.provisioning_profile(profile_path);
        }

        signer.sign(input, output)
    }

    /// Signs an app bundle directory.
    ///
    /// # Errors
    ///
    /// Currently returns [`Error::Signing`] as this feature is not yet implemented.
    pub fn sign_bundle(&self, _bundle_path: impl AsRef<Path>) -> Result<()> {
        Err(Error::Signing("Bundle signing not implemented".into()))
    }

    /// Loads entitlements from the provisioning profile if set.
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

impl Default for ZSign {
    fn default() -> Self {
        Self::new()
    }
}

/// Extracts entitlements from a provisioning profile.
///
/// Provisioning profiles are CMS-signed XML plists. This extracts the
/// `Entitlements` dictionary and converts it back to XML plist format
/// suitable for embedding in a code signature.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zsign_builder_default() {
        let zsign = ZSign::default();
        assert!(zsign.credentials.is_none());
        assert!(zsign.provisioning_profile.is_none());
    }

    #[test]
    fn test_zsign_builder_chain() {
        let zsign = ZSign::new()
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
        let zsign = ZSign::new();
        let result = zsign.validate();
        assert!(result.is_err());
        if let Err(Error::MissingCredentials(msg)) = result {
            assert!(msg.contains("Credentials must be set"));
        }
    }

    #[test]
    fn test_sign_ipa_requires_credentials() {
        let zsign = ZSign::new();
        let result = zsign.sign_ipa("input.ipa", "output.ipa");
        assert!(result.is_err());
        if let Err(Error::MissingCredentials(msg)) = result {
            assert!(msg.contains("Credentials must be set"));
        }
    }

    #[test]
    fn test_sign_bundle_not_implemented() {
        let zsign = ZSign::new();
        let result = zsign.sign_bundle("MyApp.app");
        assert!(result.is_err());
        if let Err(Error::Signing(msg)) = result {
            assert!(msg.contains("not implemented"));
        }
    }
}
