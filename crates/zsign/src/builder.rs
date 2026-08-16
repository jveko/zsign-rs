//! High-level builder API for iOS code signing.
//!
//! This module provides a fluent builder pattern for signing Mach-O binaries,
//! app bundles, and IPA files. Configure credentials, provisioning profiles,
//! and compression settings before invoking signing operations.
//!
//! # Examples
//!
//! ```no_run
//! use zsign_rs::{ZSign, SigningCredentials};
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
use crate::extract_entitlements_from_profile;
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
/// use zsign_rs::{ZSign, SigningCredentials};
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
/// use zsign_rs::{ZSign, SigningCredentials};
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
    bundle_id: Option<String>,
    bundle_name: Option<String>,
    bundle_version: Option<String>,
    sha256_only: bool,
    adhoc: bool,
}

impl ZSign {
    /// Creates a new [`ZSign`] builder with default settings.
    ///
    /// # Examples
    ///
    /// ```
    /// use zsign_rs::ZSign;
    ///
    /// let zsign = ZSign::new();
    /// ```
    pub fn new() -> Self {
        Self {
            credentials: None,
            provisioning_profile: None,
            compression_level: CompressionLevel::DEFAULT,
            bundle_id: None,
            bundle_name: None,
            bundle_version: None,
            sha256_only: false,
            adhoc: false,
        }
    }

    /// Sets the signing credentials (certificate, private key, and optional chain).
    ///
    /// Credentials are required before calling any signing method.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use zsign_rs::{ZSign, SigningCredentials};
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
    /// use zsign_rs::ZSign;
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
    /// use zsign_rs::ZSign;
    ///
    /// let zsign = ZSign::new().compression_level(9);
    /// ```
    pub fn compression_level(mut self, level: u32) -> Self {
        self.compression_level = CompressionLevel::new(level);
        self
    }

    /// Sets the bundle identifier to rewrite in the main app's `Info.plist`.
    ///
    /// When set, the `CFBundleIdentifier` will be changed to this value before signing.
    pub fn bundle_id(mut self, id: impl Into<String>) -> Self {
        self.bundle_id = Some(id.into());
        self
    }

    /// Rewrites `CFBundleDisplayName` in the main app's `Info.plist`.
    pub fn bundle_name(mut self, name: impl Into<String>) -> Self {
        self.bundle_name = Some(name.into());
        self
    }

    /// Rewrites `CFBundleShortVersionString` in the main app's `Info.plist`.
    pub fn bundle_version(mut self, version: impl Into<String>) -> Self {
        self.bundle_version = Some(version.into());
        self
    }

    /// Emits only the SHA-256 code directory (no SHA-1 code directory).
    pub fn sha256_only(mut self, only: bool) -> Self {
        self.sha256_only = only;
        self
    }

    /// Signs without an identity (ad-hoc), like the reference tool's `-a`.
    ///
    /// No credentials are required; code directories are flagged `CS_ADHOC`.
    pub fn adhoc(mut self, adhoc: bool) -> Self {
        self.adhoc = adhoc;
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
    /// use zsign_rs::ZSign;
    ///
    /// let result = ZSign::new().validate();
    /// assert!(result.is_err()); // No credentials set
    /// ```
    pub fn validate(&self) -> Result<()> {
        if self.credentials.is_none() && !self.adhoc {
            return Err(Error::MissingCredentials(
                "Credentials must be set using .credentials()".into(),
            ));
        }
        Ok(())
    }

    /// Gets a reference to the credentials after validation.
    fn get_credentials(&self) -> Result<&SigningCredentials> {
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
    /// use zsign_rs::{ZSign, SigningCredentials};
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
        let credentials = self.get_credentials()?;
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
    /// use zsign_rs::{ZSign, SigningCredentials};
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

        let mut signer = if self.adhoc {
            IpaSigner::new_adhoc().compression_level(self.compression_level)
        } else {
            let credentials = self
                .credentials
                .as_ref()
                .ok_or_else(|| Error::MissingCredentials("No credentials configured".into()))?;
            IpaSigner::new(credentials).compression_level(self.compression_level)
        };

        if let Some(ref profile_path) = self.provisioning_profile {
            signer = signer.provisioning_profile(profile_path);
        }

        if let Some(ref id) = self.bundle_id {
            signer = signer.bundle_id(id);
        }

        signer.sign(input, output)
    }

    /// Signs an app bundle directory.
    ///
    /// # Errors
    ///
    /// Signs an app bundle (`.app` folder) in place.
    ///
    /// When `output_ipa` is `Some`, the signed bundle is first produced in
    /// place and then repacked into an IPA archive; when `None`, the bundle
    /// is signed in place only.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MissingCredentials`] when no credentials are set,
    /// or a signing error if the bundle cannot be processed.
    pub fn sign_bundle(
        &self,
        bundle_path: impl AsRef<Path>,
        output_ipa: Option<&Path>,
    ) -> Result<()> {
        self.validate()?;

        let mut signer = if self.adhoc {
            crate::ipa::IpaSigner::new_adhoc().sha256_only(self.sha256_only)
        } else {
            let credentials = self.get_credentials()?;
            crate::ipa::IpaSigner::new(credentials).sha256_only(self.sha256_only)
        };
        if let Some(ref profile) = self.provisioning_profile {
            signer = signer.provisioning_profile(profile);
        }
        if let Some(ref bundle_id) = self.bundle_id {
            signer = signer.bundle_id(bundle_id.as_str());
        }
        if let Some(ref name) = self.bundle_name {
            signer = signer.bundle_name(name.as_str());
        }
        if let Some(ref version) = self.bundle_version {
            signer = signer.bundle_version(version.as_str());
        }

        match output_ipa {
            Some(ipa) if ipa.extension().map(|e| e.eq_ignore_ascii_case("ipa")).unwrap_or(false) => {
                signer.sign_folder_to_ipa(&bundle_path, ipa)?
            }
            Some(other) => {
                return Err(Error::Core(zsign_core::Error::Signing(format!(
                    "app bundle output must end in .ipa, got: {}",
                    other.display()
                ))))
            }
            None => signer.sign_folder_in_place(&bundle_path)?,
        }
        Ok(())
    }

    /// Loads entitlements from the provisioning profile if set.
    fn load_entitlements_from_profile(&self) -> Result<Option<Vec<u8>>> {
        if let Some(ref profile_path) = self.provisioning_profile {
            let profile_data = std::fs::read(profile_path)?;
            match extract_entitlements_from_profile(&profile_data)? {
                Some(entitlements) => return Ok(Some(entitlements)),
                None => return Ok(None),
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
    fn test_sign_bundle_requires_credentials() {
        let zsign = ZSign::new();
        let result = zsign.sign_bundle("MyApp.app", None);
        assert!(matches!(result, Err(Error::MissingCredentials(_))));
    }

    #[test]
    fn test_sign_bundle_missing_path() {
        let zsign = ZSign::new().credentials(crate::test_util::test_credentials());
        let result = zsign.sign_bundle("/nonexistent/MyApp.app", None);
        assert!(result.is_err());
    }

    #[test]
    fn test_sign_bundle_rejects_non_ipa_output() {
        let dir = tempfile::TempDir::new().unwrap();
        let app = dir.path().join("Test.app");
        std::fs::create_dir_all(&app).unwrap();
        let zsign = ZSign::new().credentials(crate::test_util::test_credentials());
        let result = zsign.sign_bundle(&app, Some(&dir.path().join("out.zip")));
        assert!(result.is_err());
    }

    #[test]
    fn test_sign_bundle_folder_in_place() {
        use crate::test_util::{minimal_macho, test_credentials};
        use std::io::Write;

        let dir = tempfile::TempDir::new().unwrap();
        let app = dir.path().join("Test.app");
        std::fs::create_dir_all(&app).unwrap();
        std::fs::write(
            app.join("Info.plist"),
            br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleExecutable</key><string>Test</string>
  <key>CFBundleIdentifier</key><string>com.zsign.test</string>
</dict></plist>"#,
        )
        .unwrap();
        std::fs::write(app.join("Test"), minimal_macho()).unwrap();
        let mut f = std::fs::File::create(app.join("data.bin")).unwrap();
        f.write_all(&[0xCD; 2048]).unwrap();

        ZSign::new()
            .credentials(test_credentials())
            .bundle_id("com.zsign.changed")
            .bundle_name("Renamed")
            .bundle_version("2.0")
            .sign_bundle(&app, None)
            .expect("folder signing must succeed");

        assert!(app.join("_CodeSignature/CodeResources").exists());
        let plist: plist::Value =
            plist::from_bytes(&std::fs::read(app.join("Info.plist")).unwrap()).unwrap();
        let dict = plist.as_dictionary().unwrap();
        assert_eq!(
            dict.get("CFBundleIdentifier").unwrap().as_string().unwrap(),
            "com.zsign.changed"
        );
        assert_eq!(
            dict.get("CFBundleDisplayName").unwrap().as_string().unwrap(),
            "Renamed"
        );
        assert_eq!(
            dict.get("CFBundleShortVersionString").unwrap().as_string().unwrap(),
            "2.0"
        );

        // Repack into an IPA too.
        let ipa = dir.path().join("out.ipa");
        ZSign::new()
            .credentials(test_credentials())
            .sign_bundle(&app, Some(&ipa))
            .expect("folder to ipa must succeed");
        assert!(ipa.exists());
    }
}
