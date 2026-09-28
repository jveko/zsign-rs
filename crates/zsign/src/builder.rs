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
    dylibs: Vec<String>,
    weak_dylibs: bool,
    allow_encrypted: bool,
    /// Custom entitlements file: replaces profile-derived entitlements
    entitlements: Option<PathBuf>,
    /// Entitlements directory keyed by bundle id (`<dir>/<bundle-id>.plist`)
    entitlements_dir: Option<PathBuf>,
    /// Per-nested-bundle provisioning profiles keyed by bundle id
    bundle_profiles: Vec<(String, PathBuf)>,
    /// Strip `embedded.mobileprovision` from every bundle before sealing
    remove_embedded_profile: bool,
    /// Skip CMS/expiry/team/App-ID validation of provisioning profiles (explicit opt-in)
    allow_unsafe_profile: bool,
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
            sha256_only: true,
            adhoc: false,
            dylibs: Vec::new(),
            weak_dylibs: false,
            allow_encrypted: false,
            entitlements: None,
            entitlements_dir: None,
            bundle_profiles: Vec::new(),
            remove_embedded_profile: false,
            allow_unsafe_profile: false,
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

    /// Sets a custom entitlements file.
    ///
    /// The file must be an XML or binary plist with a top-level dictionary
    /// whose values the signer can encode to DER; it replaces the
    /// entitlements extracted from the provisioning profile. A rejected file
    /// fails the sign instead of silently falling back to the profile.
    ///
    /// # Examples
    ///
    /// ```
    /// use zsign_rs::ZSign;
    ///
    /// let zsign = ZSign::new().entitlements("custom.entitlements");
    /// ```
    pub fn entitlements(mut self, path: impl AsRef<Path>) -> Self {
        self.entitlements = Some(path.as_ref().to_path_buf());
        self
    }

    /// Sets a directory of per-bundle-id entitlements files.
    ///
    /// For every bundle the file `<dir>/<bundle-id>.plist` — for the root, the
    /// id *after* any configured [`Self::bundle_id`] rewrite — is used in place
    /// of that bundle's profile-derived entitlements. A missing *entry* falls
    /// back to the profile, while a symlinked entry or a configured directory
    /// that does not exist is a hard error. Precedence for the root is
    /// [`Self::entitlements`] > this directory > profile-derived
    /// entitlements; for a nested bundle the directory beats the entitlements
    /// derived from its [`Self::bundle_profiles`] entry. Not consulted by
    /// [`Self::sign_macho`], which has no bundle identity.
    ///
    /// # Examples
    ///
    /// ```
    /// use zsign_rs::ZSign;
    ///
    /// let zsign = ZSign::new().entitlements_dir("entitlements");
    /// ```
    pub fn entitlements_dir(mut self, dir: impl AsRef<Path>) -> Self {
        self.entitlements_dir = Some(dir.as_ref().to_path_buf());
        self
    }

    /// Replaces the per-nested-bundle provisioning profiles with
    /// `(bundle-id, path)` pairs.
    ///
    /// Each key must match a nested bundle's `CFBundleIdentifier` exactly; the
    /// matched profile is embedded as that bundle's `embedded.mobileprovision`
    /// and its extracted entitlements are signed into that bundle. A key that
    /// matches no bundle, a duplicate key, or the root bundle's own id is an
    /// error — the root profile belongs in [`Self::provisioning_profile`].
    /// Not consulted by [`Self::sign_macho`], which has no bundle identity.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use zsign_rs::ZSign;
    ///
    /// let zsign = ZSign::new().bundle_profiles(vec![(
    ///     "com.example.app.ext".to_string(),
    ///     "ext.mobileprovision".into(),
    /// )]);
    /// ```
    pub fn bundle_profiles(mut self, profiles: Vec<(String, PathBuf)>) -> Self {
        self.bundle_profiles = profiles;
        self
    }

    /// Strips `embedded.mobileprovision` from every bundle before sealing.
    ///
    /// A pre-existing profile is removed from the tree and no resolved profile
    /// is embedded, at the root and in every nested bundle alike. Entitlements
    /// are unaffected: they are still derived from whatever profiles were
    /// configured, only the embedded file is withheld.
    ///
    /// The result carries no provisioning profile, so it installs only where
    /// profile validation is bypassed (jailbroken devices, enterprise
    /// re-signing flows); a stock device rejects it at install time.
    ///
    /// # Examples
    ///
    /// ```
    /// use zsign_rs::ZSign;
    ///
    /// let zsign = ZSign::new().remove_embedded_profile(true);
    /// ```
    pub fn remove_embedded_profile(mut self, remove: bool) -> Self {
        self.remove_embedded_profile = remove;
        self
    }

    /// Skips CMS, expiry, team and App-ID validation of every provisioning
    /// profile this builder loads.
    ///
    /// Profiles are validated by default; the opt-in falls back to the
    /// historical raw byte scan, so a forged, expired or foreign profile is
    /// signed and embedded verbatim. Only useful for fixtures and for
    /// re-signing flows that install where validation is bypassed.
    pub fn allow_unsafe_profile(mut self, allow: bool) -> Self {
        self.allow_unsafe_profile = allow;
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
    ///
    /// This is the modern default: current macOS verification rejects
    /// SHA-1-primary dual directories, and SHA-1 is only needed for
    /// iOS <= 10 targets (see [`Self::legacy_sha1`]).
    pub fn sha256_only(mut self, only: bool) -> Self {
        self.sha256_only = only;
        self
    }

    /// Opts back into the legacy SHA-1 + SHA-256 dual code directories.
    ///
    /// Dual output is only needed for iOS <= 10 targets and is rejected by
    /// `codesign --verify` on current macOS.
    pub fn legacy_sha1(mut self, legacy: bool) -> Self {
        self.sha256_only = !legacy;
        self
    }

    /// Signs without an identity (ad-hoc), like the reference tool's `-a`.
    ///
    /// No credentials are required; code directories are flagged `CS_ADHOC`.
    pub fn adhoc(mut self, adhoc: bool) -> Self {
        self.adhoc = adhoc;
        self
    }

    /// Injects dylib load paths into every signed executable.
    ///
    /// `weak` selects `LC_LOAD_WEAK_DYLIB`.
    pub fn dylib_injection(mut self, dylibs: Vec<String>, weak: bool) -> Self {
        self.dylibs = dylibs;
        self.weak_dylibs = weak;
        self
    }

    /// Overrides the FairPlay-encryption refusal (`-f/--force` on the CLI).
    pub fn allow_encrypted(mut self, allow: bool) -> Self {
        self.allow_encrypted = allow;
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
    /// FAT/Universal containers are supported in both credentialed modes: the
    /// default dual-digest mode and `sha256_only` route containers through
    /// [`crate::macho::sign_any_macho`], which signs every slice. Adhoc mode
    /// rejects containers and fails closed.
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
        self.validate()?;
        let mut bytes = std::fs::read(input.as_ref())?;
        for dylib in &self.dylibs {
            bytes =
                zsign_core::macho::writer::inject_dylib_command(&bytes, dylib, self.weak_dylibs)?;
        }
        let macho = MachOFile::parse(bytes)?;

        let identifier = match &self.bundle_id {
            Some(id) => id.as_str(),
            None => input
                .as_ref()
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("unknown"),
        };

        let entitlements = self
            .load_entitlements_override()?
            .or(self.load_entitlements_from_profile()?);
        let signed_binary = if self.adhoc {
            crate::macho::sign_macho_adhoc(
                &macho,
                identifier,
                entitlements.as_deref(),
                None,
                None,
                self.allow_encrypted,
            )?
        } else {
            let credentials = self.get_credentials()?;
            if self.sha256_only {
                crate::macho::sign_macho_sha256_only(
                    &macho,
                    identifier,
                    entitlements.as_deref(),
                    credentials,
                    None,
                    None,
                    self.allow_encrypted,
                )?
            } else if macho.is_fat() {
                crate::macho::sign_any_macho(
                    &macho,
                    identifier,
                    entitlements.as_deref(),
                    credentials,
                    None,
                    None,
                    self.allow_encrypted,
                )?
            } else {
                sign_macho(
                    &macho,
                    identifier,
                    entitlements.as_deref(),
                    credentials,
                    None,
                    None,
                    self.allow_encrypted,
                )?
            }
        };

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
            IpaSigner::new_adhoc()
                .compression_level(self.compression_level)
                .sha256_only(self.sha256_only)
        } else {
            let credentials = self
                .credentials
                .as_ref()
                .ok_or_else(|| Error::MissingCredentials("No credentials configured".into()))?;
            IpaSigner::new(credentials)
                .compression_level(self.compression_level)
                .sha256_only(self.sha256_only)
        };
        if !self.dylibs.is_empty() {
            signer = signer.dylib_injection(self.dylibs.clone(), self.weak_dylibs);
        }
        signer = signer.allow_encrypted(self.allow_encrypted);
        signer = signer.remove_embedded_profile(self.remove_embedded_profile);
        if self.allow_unsafe_profile {
            signer = signer.allow_unsafe_profile(true);
        }

        if let Some(ref profile_path) = self.provisioning_profile {
            signer = signer.provisioning_profile(profile_path);
        }

        if let Some(entitlements) = &self.entitlements {
            signer = signer.entitlements(entitlements);
        }

        if let Some(entitlements_dir) = &self.entitlements_dir {
            signer = signer.entitlements_dir(entitlements_dir);
        }
        if !self.bundle_profiles.is_empty() {
            signer = signer.bundle_profiles(self.bundle_profiles.clone());
        }

        if let Some(ref id) = self.bundle_id {
            signer = signer.bundle_id(id);
        }

        if let Some(ref name) = self.bundle_name {
            signer = signer.bundle_name(name.as_str());
        }
        if let Some(ref version) = self.bundle_version {
            signer = signer.bundle_version(version.as_str());
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
            crate::ipa::IpaSigner::new_adhoc()
                .compression_level(self.compression_level)
                .sha256_only(self.sha256_only)
        } else {
            let credentials = self.get_credentials()?;
            crate::ipa::IpaSigner::new(credentials)
                .compression_level(self.compression_level)
                .sha256_only(self.sha256_only)
        };
        if !self.dylibs.is_empty() {
            signer = signer.dylib_injection(self.dylibs.clone(), self.weak_dylibs);
        }
        signer = signer.allow_encrypted(self.allow_encrypted);
        signer = signer.remove_embedded_profile(self.remove_embedded_profile);
        if self.allow_unsafe_profile {
            signer = signer.allow_unsafe_profile(true);
        }
        if let Some(ref profile) = self.provisioning_profile {
            signer = signer.provisioning_profile(profile);
        }
        if let Some(entitlements) = &self.entitlements {
            signer = signer.entitlements(entitlements);
        }
        if let Some(entitlements_dir) = &self.entitlements_dir {
            signer = signer.entitlements_dir(entitlements_dir);
        }
        if !self.bundle_profiles.is_empty() {
            signer = signer.bundle_profiles(self.bundle_profiles.clone());
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
            Some(ipa)
                if ipa
                    .extension()
                    .map(|e| e.eq_ignore_ascii_case("ipa"))
                    .unwrap_or(false) =>
            {
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
            let profile_data = read_profile_file(profile_path, None)?;
            let request = zsign_core::ProfileRequest {
                now: None,
                anchors: None,
                expected_team_id: self.credentials.as_ref().and_then(|c| c.team_id.clone()),
                target_bundle_id: self.bundle_id.clone(),
                target_device_udid: None,
            };
            match zsign_core::extract_entitlements_checked(
                &profile_data,
                &request,
                self.allow_unsafe_profile,
            )
            .map_err(|e| profile_validation_error(e, profile_path, None))?
            {
                Some(entitlements) => return Ok(Some(entitlements)),
                None => return Ok(None),
            }
        }
        Ok(None)
    }

    /// Reads and validates a custom entitlements file. Every rejection is a
    /// hard error naming the path — silently falling back to the profile is
    /// the upstream failure mode this port deliberately does not reproduce.
    fn load_entitlements_override(&self) -> Result<Option<Vec<u8>>> {
        read_entitlements_file(self.entitlements.as_deref())
    }
}

/// Reads and validates an entitlements file. `Ok(None)` when no path is given.
///
/// Every rejection is a hard error naming the path — silently falling back to
/// the profile is the upstream failure mode this port deliberately does not
/// reproduce.
pub(crate) fn read_entitlements_file(path: Option<&Path>) -> Result<Option<Vec<u8>>> {
    let Some(path) = path else {
        return Ok(None);
    };
    let data = std::fs::read(path).map_err(|e| entitlements_read_error(path, e))?;
    validate_entitlements_blob(&data, path)?;
    Ok(Some(data))
}

/// Single owner of the "failed to read entitlements file" text, shared by the
/// builder override loader and the signer's entitlements-directory lookup.
pub(crate) fn entitlements_read_error(path: &Path, e: std::io::Error) -> Error {
    Error::Io(std::io::Error::new(
        e.kind(),
        format!("failed to read entitlements file '{}': {e}", path.display()),
    ))
}

/// Source label for a provisioning-profile failure: the path is always named,
/// and a mapped entry also names the bundle id whose lookup selected it.
fn profile_source(path: &Path, bundle_id: Option<&str>) -> String {
    match bundle_id {
        Some(id) => format!(
            "provisioning profile for bundle '{id}' at '{}'",
            path.display()
        ),
        None => format!("provisioning profile '{}'", path.display()),
    }
}

/// Single owner of the "failed to read provisioning profile" text, shared by
/// every profile-loading site so a read failure always names the file. A site
/// must pass the same `bundle_id` here and to [`profile_validation_error`], so
/// its read and validation failures name the same source.
pub(crate) fn read_profile_file(path: &Path, bundle_id: Option<&str>) -> Result<Vec<u8>> {
    std::fs::read(path).map_err(|e| {
        let source = profile_source(path, bundle_id);
        Error::Io(std::io::Error::new(
            e.kind(),
            format!("failed to read {source}: {e}"),
        ))
    })
}

/// Single owner of the profile-validation context wrap. The offending profile
/// is always named; the failure keeps the class its own validator produced, so
/// a malformed profile, a failed CMS verification, and a size rejection stay
/// distinguishable after the wrap.
/// Callers must pass the same `bundle_id` they gave [`read_profile_file`], so
/// read and validation failures for one profile name the same source.
pub(crate) fn profile_validation_error(
    e: zsign_core::Error,
    path: &Path,
    bundle_id: Option<&str>,
) -> Error {
    let source = profile_source(path, bundle_id);
    match e {
        zsign_core::Error::ProvisioningProfile(detail) => Error::Core(
            zsign_core::Error::ProvisioningProfile(format!("{detail} ({source})")),
        ),
        zsign_core::Error::Verification(detail) => Error::Core(zsign_core::Error::Verification(
            format!("{detail} ({source})"),
        )),
        zsign_core::Error::InputTooLarge(detail) => {
            Error::InputTooLarge(format!("{detail} ({source})"))
        }
        other => Error::Core(other),
    }
}

/// Validates entitlements bytes against the blob contract: XML-or-binary
/// plist, dictionary root, and DER-encodable by the signer's encoder —
/// the same three checks the wasm setter runs before accepting an override.
pub(crate) fn validate_entitlements_blob(data: &[u8], source: &Path) -> crate::Result<()> {
    let value: plist::Value = plist::from_bytes(data).map_err(|e| {
        Error::Core(zsign_core::Error::Config(format!(
            "entitlements file '{}' is not a valid plist: {e}",
            source.display()
        )))
    })?;
    if value.as_dictionary().is_none() {
        return Err(Error::Core(zsign_core::Error::Config(format!(
            "entitlements file '{}' must contain a top-level dictionary",
            source.display()
        ))));
    }
    zsign_core::codesign::der::plist_to_der(data).map_err(|e| {
        Error::Core(zsign_core::Error::DerEncoding(format!(
            "entitlements in '{}' contain types the signer cannot encode: {e}",
            source.display()
        )))
    })?;
    Ok(())
}

impl Default for ZSign {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zsign_core::macho::fixtures;

    #[test]
    fn test_zsign_builder_default() {
        let zsign = ZSign::default();
        assert!(zsign.credentials.is_none());
        assert!(zsign.provisioning_profile.is_none());
        assert!(zsign.entitlements.is_none());
        assert!(zsign.entitlements_dir.is_none());
        assert!(zsign.bundle_profiles.is_empty());
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

        assert!(!zsign.allow_encrypted);
        let zsign = ZSign::new().allow_encrypted(true);
        assert!(zsign.allow_encrypted);
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
        use crate::test_util::test_credentials;
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
        std::fs::write(app.join("Test"), fixtures::make_minimal_macho()).unwrap();
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
            dict.get("CFBundleDisplayName")
                .unwrap()
                .as_string()
                .unwrap(),
            "Renamed"
        );
        assert_eq!(
            dict.get("CFBundleShortVersionString")
                .unwrap()
                .as_string()
                .unwrap(),
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

    /// Writes a two-architecture (arm64 + x86_64) universal binary into `dir`.
    fn write_two_arch_fat_fixture(dir: &std::path::Path) -> std::path::PathBuf {
        let mut x86 = fixtures::make_minimal_macho();
        x86[4..8].copy_from_slice(&0x0100_0007u32.to_le_bytes());
        let slices = [fixtures::make_minimal_macho(), x86];
        // One align exponent per slice: both are padded to a 2^12 boundary.
        let aligns = [12u32; 2];
        let input = dir.join("universal_bin");
        std::fs::write(&input, fixtures::make_fat_macho(&slices, &aligns)).expect("write fixture");
        input
    }

    #[test]
    fn test_sign_macho_fat_default_sha256_only_routes_through_fat_path() {
        let dir = tempfile::tempdir().unwrap();
        let input = write_two_arch_fat_fixture(dir.path());
        let output = dir.path().join("universal_signed");

        ZSign::new()
            .credentials(crate::test_util::test_credentials())
            .sign_macho(&input, &output)
            .expect("default direct-sign (sha256_only=true) must handle FAT");

        let signed = std::fs::read(&output).unwrap();
        assert_eq!(
            &signed[0..4],
            &[0xca, 0xfe, 0xba, 0xbe],
            "signed output must stay FAT"
        );
        let m = crate::macho::MachOFile::parse(signed).unwrap();
        assert!(m.is_fat() && m.slices().len() == 2);
        assert!(
            m.slices().iter().all(|s| s.code_sig_offset.is_some()),
            "both slices must be signed"
        );

        // Dual-pin: without injected anchors the report is anchor-gated, so
        // "signed and verifiable" = every slice verifies with the anchoring
        // gate as its only problem, and its code pages match.
        let report = crate::verify::verify_macho_file(&output).unwrap();
        let macho = report.macho.as_ref().expect("Mach-O report");
        assert!(macho.fat, "verify must see a FAT container");
        assert_eq!(macho.slices.len(), 2);
        for (i, slice) in macho.slices.iter().enumerate() {
            assert!(slice.signed, "slice {i} must verify as signed");
            assert_eq!(
                slice.pages,
                zsign_core::codesign::verify::PageCheck::Matched,
                "slice {i}: {:?}",
                slice.errors
            );
            assert!(
                slice
                    .errors
                    .iter()
                    .all(|e| e.contains("not anchored to a trusted root")),
                "slice {i}: {:?}",
                slice.errors
            );
        }
    }

    #[test]
    fn test_sign_macho_fat_verify_detects_tampered_second_slice() {
        // Power check for the per-slice verify assertions above: tamper only
        // slice 1's code region (the container offsets stay valid, so the
        // container still parses and both slices still carry a signature) and
        // require exactly that slice to be reported as a page mismatch. A
        // verifier that ignored per-slice page state, or that only checked the
        // first slice, would pass this file off as clean.
        let dir = tempfile::tempdir().unwrap();
        let input = write_two_arch_fat_fixture(dir.path());
        let output = dir.path().join("universal_signed");
        ZSign::new()
            .credentials(crate::test_util::test_credentials())
            .sign_macho(&input, &output)
            .expect("sign FAT");

        let container = crate::macho::MachOFile::parse(std::fs::read(&output).unwrap()).unwrap();
        let victim = &container.slices()[1];
        // Land past the load commands but inside the region the CodeDirectory
        // actually hashes: `check_code_pages` covers the first `code_limit`
        // bytes of the slice, and the signer sets codeLimit to the __TEXT
        // segment size. A byte beyond that would report CountMismatch (or
        // nothing) instead of the page mismatch this test is pinning.
        let code_limit = victim.text_segment_size as usize;
        let page_covered = 0x100usize;
        assert!(
            page_covered < code_limit,
            "tamper point {page_covered} must lie below codeLimit {code_limit}"
        );

        let mut bytes = std::fs::read(&output).unwrap();
        bytes[victim.offset as usize + page_covered] ^= 0x01;
        let tampered = dir.path().join("universal_tampered");
        std::fs::write(&tampered, &bytes).unwrap();

        let report = crate::verify::verify_macho_file(&tampered).unwrap();
        let macho = report.macho.as_ref().expect("Mach-O report");
        assert!(macho.fat, "the container must still parse as FAT");
        assert_eq!(macho.slices.len(), 2);
        // Exact page index: 0x100 falls in the first 4096-byte page. A verifier
        // that walked the wrong page size, or attributed the mismatch to the
        // wrong architecture, cannot produce this value.
        assert_eq!(
            macho.slices[1].pages,
            zsign_core::codesign::verify::PageCheck::Mismatch { page_index: 0 },
            "slice 1 must be reported as a page mismatch"
        );
        // Control: the untouched architecture must stay clean, so the report
        // attributes the damage to the tampered slice alone.
        assert_eq!(
            macho.slices[0].pages,
            zsign_core::codesign::verify::PageCheck::Matched,
            "the untampered slice must still verify"
        );
    }

    #[test]
    fn test_sign_macho_fat_dual_digest_routes_through_sign_any() {
        let dir = tempfile::tempdir().unwrap();
        let input = write_two_arch_fat_fixture(dir.path());
        let output = dir.path().join("universal_signed");

        ZSign::new()
            .credentials(crate::test_util::test_credentials())
            .sha256_only(false)
            .sign_macho(&input, &output)
            .expect("dual-digest direct-sign must route FAT through sign_any_macho");

        let signed = std::fs::read(&output).unwrap();
        assert_eq!(&signed[0..4], &[0xca, 0xfe, 0xba, 0xbe]);
        let m = crate::macho::MachOFile::parse(signed).unwrap();
        assert!(m.is_fat() && m.slices().len() == 2);
        assert!(
            m.slices().iter().all(|s| s.code_sig_offset.is_some()),
            "both slices must be signed"
        );
    }

    #[test]
    fn test_sign_macho_adhoc_rejects_fat() {
        let dir = tempfile::tempdir().unwrap();
        let input = write_two_arch_fat_fixture(dir.path());
        let output = dir.path().join("universal_signed");

        let err = ZSign::new()
            .adhoc(true)
            .sign_macho(&input, &output)
            .expect_err("adhoc direct-sign must fail closed on FAT (documented limitation)");
        assert!(err.to_string().contains("sign_any_macho"), "{err}");
    }
    /// Minimal `Info.plist` for the IPA fixture (has no name/version keys, so a
    /// rewrite of either key is observable in the signed output).
    const FIXTURE_PLIST: &[u8] = br#"<?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
    <plist version="1.0"><dict>
      <key>CFBundleExecutable</key><string>Test</string>
      <key>CFBundleIdentifier</key><string>com.zsign.test</string>
    </dict></plist>"#;

    /// Writes a one-app IPA (Info.plist + thin Mach-O + a data blob) to `path`.
    fn write_ipa_fixture(path: &std::path::Path) {
        use std::io::Write;
        use zip::write::SimpleFileOptions;
        let file = std::fs::File::create(path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let opts =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        zip.start_file("Payload/Test.app/Info.plist", opts).unwrap();
        zip.write_all(FIXTURE_PLIST).unwrap();
        zip.start_file("Payload/Test.app/Test", opts).unwrap();
        zip.write_all(&fixtures::make_minimal_macho()).unwrap();
        zip.start_file("Payload/Test.app/data.bin", opts).unwrap();
        zip.write_all(&[0xCD; 4096]).unwrap();
        zip.finish().unwrap();
    }

    /// Read one entry's bytes back out of an IPA.
    fn ipa_entry(path: &std::path::Path, name: &str) -> Vec<u8> {
        use std::io::Read;
        let f = std::fs::File::open(path).unwrap();
        let mut zip = zip::ZipArchive::new(f).unwrap();
        let mut buf = Vec::new();
        zip.by_name(name).unwrap().read_to_end(&mut buf).unwrap();
        buf
    }

    /// Every entry name in an IPA.
    fn ipa_entry_names(path: &std::path::Path) -> Vec<String> {
        let f = std::fs::File::open(path).unwrap();
        let mut zip = zip::ZipArchive::new(f).unwrap();
        (0..zip.len())
            .map(|i| zip.by_index(i).unwrap().name().to_string())
            .collect()
    }

    /// Locate the code signature of a thin Mach-O and parse its SuperBlob.
    /// LC_CODE_SIGNATURE lookup follows the repo idiom at
    /// zsign-core/src/macho/signer.rs:1364-1376 (goblin 0.10 MachO has no
    /// `code_signature` field — only the `CommandVariant::CodeSignature` variant).
    fn thin_code_signature(bytes: &[u8]) -> crate::codesign::verify::SuperBlob<'_> {
        use goblin::mach::load_command::CommandVariant;
        let mach = goblin::mach::Mach::parse(bytes).unwrap();
        let macho = match mach {
            goblin::mach::Mach::Binary(b) => b,
            goblin::mach::Mach::Fat(_) => panic!("thin binary expected"),
        };
        let lc = macho
            .load_commands
            .iter()
            .find_map(|cmd| match cmd.command {
                CommandVariant::CodeSignature(cs) => Some(cs),
                _ => None,
            })
            .expect("LC_CODE_SIGNATURE");
        let start = lc.dataoff as usize;
        let end = start + lc.datasize as usize;
        crate::codesign::verify::parse_superblob(&bytes[start..end]).unwrap()
    }

    /// True when any emitted CodeDirectory (primary or alternate) is SHA-1.
    fn has_sha1_directory(sb: &crate::codesign::verify::SuperBlob<'_>) -> bool {
        sb.code_directory.as_ref().is_some_and(|cd| cd.is_sha1())
            || sb.alternate_code_directories.iter().any(|cd| cd.is_sha1())
    }

    #[test]
    fn test_sign_ipa_forwards_bundle_options() {
        use crate::test_util::test_credentials;
        let dir = tempfile::TempDir::new().unwrap();
        let input = dir.path().join("in.ipa");
        write_ipa_fixture(&input);

        // Control: ZSign defaults — sha256_only=true, no name/version rewrites.
        let control = dir.path().join("control.ipa");
        ZSign::new()
            .credentials(test_credentials())
            .sign_ipa(&input, &control)
            .expect("control sign");

        // Treatment: forwarded options must reach the output.
        let out = dir.path().join("out.ipa");
        ZSign::new()
            .credentials(test_credentials())
            .bundle_name("Renamed")
            .bundle_version("9.9")
            .sha256_only(false)
            .sign_ipa(&input, &out)
            .expect("treatment sign");

        let plist: plist::Value =
            plist::from_bytes(&ipa_entry(&out, "Payload/Test.app/Info.plist")).unwrap();
        let dict = plist.as_dictionary().unwrap();
        assert_eq!(
            dict.get("CFBundleDisplayName")
                .unwrap()
                .as_string()
                .unwrap(),
            "Renamed"
        );
        assert_eq!(
            dict.get("CFBundleShortVersionString")
                .unwrap()
                .as_string()
                .unwrap(),
            "9.9"
        );

        let control_exe = ipa_entry(&control, "Payload/Test.app/Test");
        let treatment_exe = ipa_entry(&out, "Payload/Test.app/Test");
        assert!(
            !has_sha1_directory(&thin_code_signature(&control_exe)),
            "default sha256_only must emit no SHA-1 directory"
        );
        assert!(
            has_sha1_directory(&thin_code_signature(&treatment_exe)),
            "sha256_only(false) must be forwarded as a dual directory"
        );
    }
    #[test]
    fn test_sign_bundle_forwards_compression_level() {
        use crate::test_util::test_credentials;
        use std::io::Write;

        let dir = tempfile::TempDir::new().unwrap();
        let app = dir.path().join("Test.app");
        std::fs::create_dir_all(&app).unwrap();
        std::fs::write(app.join("Info.plist"), FIXTURE_PLIST).unwrap();
        std::fs::write(app.join("Test"), fixtures::make_minimal_macho()).unwrap();
        let mut f = std::fs::File::create(app.join("data.bin")).unwrap();
        f.write_all(&[0xCD; 2048]).unwrap();

        let out = dir.path().join("out.ipa");
        ZSign::new()
            .credentials(test_credentials())
            .compression_level(0)
            .sign_bundle(&app, Some(&out))
            .expect("folder to ipa must succeed");

        let f = std::fs::File::open(&out).unwrap();
        let mut zip = zip::ZipArchive::new(f).unwrap();
        let entry = zip.by_name("Payload/Test.app/Info.plist").unwrap();
        assert_eq!(
            entry.compression(),
            zip::CompressionMethod::Stored,
            "compression_level(0) must reach the repack as Stored"
        );
    }

    #[test]
    fn test_sign_macho_applies_dylibs_and_bundle_id() {
        use crate::test_util::test_credentials;

        let dir = tempfile::TempDir::new().unwrap();
        let input = dir.path().join("app.bin");
        std::fs::write(&input, fixtures::make_minimal_macho()).unwrap();
        let out = dir.path().join("signed.bin");

        ZSign::new()
            .credentials(test_credentials())
            .dylib_injection(vec!["/usr/lib/libzsn.dylib".to_string()], false)
            .bundle_id("com.zsign.forwarded")
            .sign_macho(&input, &out)
            .expect("sign");

        let signed = std::fs::read(&out).unwrap();

        // the injected dylib appears as a load command in the SIGNED output
        let mach = goblin::mach::Mach::parse(&signed).unwrap();
        let macho = match mach {
            goblin::mach::Mach::Binary(b) => b,
            goblin::mach::Mach::Fat(_) => panic!("thin binary expected"),
        };
        assert!(
            macho.libs.contains(&"/usr/lib/libzsn.dylib"),
            "injected dylib missing from signed load commands: {:?}",
            macho.libs
        );

        // bundle_id becomes the code-signing identifier
        let sb = thin_code_signature(&signed);
        let cd = sb.code_directory.as_ref().expect("code directory");
        assert_eq!(
            cd.identifier(),
            Some("com.zsign.forwarded"),
            "configured bundle_id must replace the file-stem identifier"
        );
    }
    const PROFILE_FIXTURE: &[u8] = br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Entitlements</key>
  <dict>
    <key>application-identifier</key>
    <string>TESTTEAM.com.zsign.test.entitlement</string>
  </dict>
  <key>ExpirationDate</key>
  <date>2099-01-01T00:00:00Z</date>
</dict></plist>"#;

    #[test]
    fn test_sign_macho_adhoc_applies_profile_entitlements() {
        use crate::codesign::constants::CSSLOT_ENTITLEMENTS;

        let dir = tempfile::TempDir::new().unwrap();
        let profile = dir.path().join("test.mobileprovision");
        std::fs::write(&profile, PROFILE_FIXTURE).unwrap();
        let input = dir.path().join("app.bin");
        std::fs::write(&input, fixtures::make_minimal_macho()).unwrap();

        // Control: adhoc without a profile must not carry an entitlements slot.
        let control = dir.path().join("control.bin");
        ZSign::new()
            .adhoc(true)
            .sign_macho(&input, &control)
            .expect("control");
        let control_bytes = std::fs::read(&control).unwrap();
        let control_sb = thin_code_signature(&control_bytes);
        assert!(
            !control_sb
                .entries
                .iter()
                .any(|e| e.slot == CSSLOT_ENTITLEMENTS),
            "control must not carry an entitlements slot"
        );

        // Treatment: the profile's entitlements must reach the signed output.
        let out = dir.path().join("signed.bin");
        ZSign::new()
            .adhoc(true)
            .provisioning_profile(&profile)
            .allow_unsafe_profile(true)
            .sign_macho(&input, &out)
            .expect("adhoc sign with profile");
        let signed_bytes = std::fs::read(&out).unwrap();
        let sb = thin_code_signature(&signed_bytes);
        let ent = sb
            .entries
            .iter()
            .find(|e| e.slot == CSSLOT_ENTITLEMENTS)
            .expect("entitlements slot must be present");
        assert!(
            String::from_utf8_lossy(ent.blob).contains("com.zsign.test.entitlement"),
            "entitlements slot must carry the profile's entitlements"
        );
    }
    #[test]
    fn validate_failure_leaves_input_tree_untouched() {
        let dir = tempfile::TempDir::new().unwrap();

        // .app: abort before any bundle mutation
        let app = dir.path().join("Test.app");
        std::fs::create_dir_all(&app).unwrap();
        std::fs::write(app.join("Info.plist"), FIXTURE_PLIST).unwrap();
        std::fs::write(app.join("Test"), fixtures::make_minimal_macho()).unwrap();
        let plist_before = std::fs::read(app.join("Info.plist")).unwrap();
        let result = ZSign::new().sign_bundle(&app, None);
        assert!(matches!(result, Err(Error::MissingCredentials(_))));
        assert!(!app.join("_CodeSignature").exists());
        assert_eq!(std::fs::read(app.join("Info.plist")).unwrap(), plist_before);

        // .ipa: output must never be created, input bytes unchanged
        let ipa = dir.path().join("in.ipa");
        write_ipa_fixture(&ipa);
        let ipa_before = std::fs::read(&ipa).unwrap();
        let out = dir.path().join("out.ipa");
        let result = ZSign::new().sign_ipa(&ipa, &out);
        assert!(matches!(result, Err(Error::MissingCredentials(_))));
        assert!(!out.exists());
        assert_eq!(std::fs::read(&ipa).unwrap(), ipa_before);

        // bare macho: output must never be created
        let input = dir.path().join("app.bin");
        std::fs::write(&input, fixtures::make_minimal_macho()).unwrap();
        let out_bin = dir.path().join("signed.bin");
        let result = ZSign::new().sign_macho(&input, &out_bin);
        assert!(matches!(result, Err(Error::MissingCredentials(_))));
        assert!(!out_bin.exists());
    }

    const OVERRIDE_ENTITLEMENTS: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>application-identifier</key>
    <string>TESTTEAM.com.override.app</string>
    <key>com.zsign.override.ent</key>
    <true/>
</dict>
</plist>"#;

    /// Slot blob of the signed output's primary CodeDirectory, if any.
    fn entitlements_slot_blob(signed: &[u8]) -> Option<String> {
        use crate::codesign::constants::CSSLOT_ENTITLEMENTS;

        let sb = thin_code_signature(signed);
        sb.entries
            .iter()
            .find(|e| e.slot == CSSLOT_ENTITLEMENTS)
            .map(|e| String::from_utf8_lossy(e.blob).into_owned())
    }

    #[test]
    fn test_sign_macho_entitlements_override_replaces_profile() {
        let dir = tempfile::TempDir::new().unwrap();
        let profile = dir.path().join("test.mobileprovision");
        std::fs::write(&profile, PROFILE_FIXTURE).unwrap();
        let ents = dir.path().join("custom.entitlements");
        std::fs::write(&ents, OVERRIDE_ENTITLEMENTS).unwrap();
        let input = dir.path().join("app.bin");
        std::fs::write(&input, fixtures::make_minimal_macho()).unwrap();

        let out = dir.path().join("signed.bin");
        ZSign::new()
            .adhoc(true)
            .provisioning_profile(&profile)
            .allow_unsafe_profile(true)
            .entitlements(&ents)
            .sign_macho(&input, &out)
            .expect("adhoc sign with entitlements override");

        let blob = entitlements_slot_blob(&std::fs::read(&out).unwrap())
            .expect("entitlements slot must be present");
        assert!(
            blob.contains("com.zsign.override.ent"),
            "override entitlements must be signed: {blob}"
        );
        assert!(
            !blob.contains("com.zsign.test.entitlement"),
            "the profile's entitlements must be fully replaced: {blob}"
        );
    }

    #[test]
    fn test_sign_macho_entitlements_override_with_credentials() {
        let dir = tempfile::TempDir::new().unwrap();
        let profile = dir.path().join("test.mobileprovision");
        std::fs::write(&profile, PROFILE_FIXTURE).unwrap();
        let ents = dir.path().join("custom.entitlements");
        std::fs::write(&ents, OVERRIDE_ENTITLEMENTS).unwrap();
        let input = dir.path().join("app.bin");
        std::fs::write(&input, fixtures::make_minimal_macho()).unwrap();

        let out = dir.path().join("signed.bin");
        ZSign::new()
            .credentials(crate::test_util::test_credentials())
            .provisioning_profile(&profile)
            .allow_unsafe_profile(true)
            .entitlements(&ents)
            .sign_macho(&input, &out)
            .expect("certificate sign with entitlements override");

        let blob = entitlements_slot_blob(&std::fs::read(&out).unwrap())
            .expect("entitlements slot must be present");
        assert!(
            blob.contains("com.zsign.override.ent"),
            "override entitlements must be signed: {blob}"
        );
        assert!(
            !blob.contains("com.zsign.test.entitlement"),
            "the profile's entitlements must be fully replaced: {blob}"
        );
    }

    #[test]
    fn test_sign_macho_adhoc_entitlements_override_without_profile() {
        let dir = tempfile::TempDir::new().unwrap();
        let ents = dir.path().join("custom.entitlements");
        std::fs::write(&ents, OVERRIDE_ENTITLEMENTS).unwrap();
        let input = dir.path().join("app.bin");
        std::fs::write(&input, fixtures::make_minimal_macho()).unwrap();

        let out = dir.path().join("signed.bin");
        ZSign::new()
            .adhoc(true)
            .entitlements(&ents)
            .sign_macho(&input, &out)
            .expect("adhoc sign with entitlements only");

        let blob = entitlements_slot_blob(&std::fs::read(&out).unwrap())
            .expect("entitlements slot must be present without a profile");
        assert!(
            blob.contains("com.zsign.override.ent"),
            "override entitlements must be signed: {blob}"
        );
    }

    #[test]
    fn test_entitlements_override_missing_file_names_path() {
        let dir = tempfile::TempDir::new().unwrap();
        let missing = dir.path().join("absent.entitlements");
        let input = dir.path().join("app.bin");
        std::fs::write(&input, fixtures::make_minimal_macho()).unwrap();
        let out = dir.path().join("signed.bin");

        let err = ZSign::new()
            .adhoc(true)
            .entitlements(&missing)
            .sign_macho(&input, &out)
            .expect_err("a missing entitlements file must fail the sign");
        let message = err.to_string();
        assert!(
            message.contains("entitlements file"),
            "the error must name the failure: {message}"
        );
        assert!(
            message.contains("absent.entitlements"),
            "the error must name the path: {message}"
        );
        assert!(
            !out.exists(),
            "no output may be written for a rejected override"
        );
    }

    #[test]
    fn test_entitlements_override_rejects_non_dictionary() {
        let dir = tempfile::TempDir::new().unwrap();
        let ents = dir.path().join("array.entitlements");
        std::fs::write(
            &ents,
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<array>
    <string>nope</string>
</array>
</plist>"#,
        )
        .unwrap();
        let input = dir.path().join("app.bin");
        std::fs::write(&input, fixtures::make_minimal_macho()).unwrap();

        let err = ZSign::new()
            .adhoc(true)
            .entitlements(&ents)
            .sign_macho(&input, dir.path().join("signed.bin"))
            .expect_err("a top-level array must be rejected");
        let message = err.to_string();
        assert!(
            message.contains("dictionary"),
            "the error must name the required shape: {message}"
        );
    }

    #[test]
    fn test_entitlements_override_rejects_unencodable_values() {
        let dir = tempfile::TempDir::new().unwrap();
        let ents = dir.path().join("real.entitlements");
        std::fs::write(
            &ents,
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.zsign.override.real</key>
    <real>1.5</real>
</dict>
</plist>"#,
        )
        .unwrap();
        let input = dir.path().join("app.bin");
        std::fs::write(&input, fixtures::make_minimal_macho()).unwrap();

        let err = ZSign::new()
            .adhoc(true)
            .entitlements(&ents)
            .sign_macho(&input, dir.path().join("signed.bin"))
            .expect_err("Real values cannot be DER-encoded and must be rejected up front");
        let message = err.to_string();
        assert!(
            message.contains("cannot encode") && message.contains("real.entitlements"),
            "the DER gate must reject Real and name the file: {message}"
        );
    }

    #[test]
    fn test_sign_ipa_forwards_entitlements_override() {
        let dir = tempfile::TempDir::new().unwrap();
        let input = dir.path().join("in.ipa");
        write_ipa_fixture(&input);
        let ents = dir.path().join("custom.entitlements");
        std::fs::write(&ents, OVERRIDE_ENTITLEMENTS).unwrap();
        let out = dir.path().join("out.ipa");

        ZSign::new()
            .adhoc(true)
            .entitlements(&ents)
            .sign_ipa(&input, &out)
            .expect("sign_ipa must forward the entitlements override");

        let exe = ipa_entry(&out, "Payload/Test.app/Test");
        let blob = entitlements_slot_blob(&exe)
            .expect("the root binary must carry the forwarded override");
        assert!(
            blob.contains("com.zsign.override.ent"),
            "sign_ipa must forward the override to IpaSigner: {blob}"
        );

        // The control path (no override) must not carry the slot at all.
        let control = dir.path().join("control.ipa");
        ZSign::new()
            .adhoc(true)
            .sign_ipa(&input, &control)
            .expect("control sign");
        assert!(
            entitlements_slot_blob(&ipa_entry(&control, "Payload/Test.app/Test")).is_none(),
            "without an override no entitlements slot may be emitted"
        );
    }

    #[test]
    fn test_sign_bundle_forwards_entitlements_override() {
        let dir = tempfile::TempDir::new().unwrap();
        let app = dir.path().join("Test.app");
        std::fs::create_dir_all(&app).unwrap();
        std::fs::write(app.join("Info.plist"), FIXTURE_PLIST).unwrap();
        std::fs::write(app.join("Test"), fixtures::make_minimal_macho()).unwrap();
        let ents = dir.path().join("custom.entitlements");
        std::fs::write(&ents, OVERRIDE_ENTITLEMENTS).unwrap();

        ZSign::new()
            .adhoc(true)
            .entitlements(&ents)
            .sign_bundle(&app, None)
            .expect("sign_bundle must forward the entitlements override");

        let blob = entitlements_slot_blob(&std::fs::read(app.join("Test")).unwrap())
            .expect("the root binary must carry the forwarded override");
        assert!(
            blob.contains("com.zsign.override.ent"),
            "sign_bundle must forward the override to IpaSigner: {blob}"
        );
    }

    /// An entitlements directory holding a single `<key>.plist` with `marker`.
    fn write_entitlements_dir(dir: &Path, key: &str, marker: &str) -> PathBuf {
        std::fs::create_dir_all(dir).unwrap();
        let path = dir.join(format!("{key}.plist"));
        std::fs::write(
            &path,
            format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>{marker}</key>
    <true/>
</dict>
</plist>"#
            ),
        )
        .unwrap();
        path
    }

    #[test]
    fn test_sign_ipa_forwards_entitlements_dir() {
        let dir = tempfile::TempDir::new().unwrap();
        let input = dir.path().join("in.ipa");
        write_ipa_fixture(&input);
        // FIXTURE_PLIST declares com.zsign.test as CFBundleIdentifier.
        let ents_dir = dir.path().join("ents");
        write_entitlements_dir(&ents_dir, "com.zsign.test", "com.zsign.dir.ent");
        let out = dir.path().join("out.ipa");

        ZSign::new()
            .adhoc(true)
            .entitlements_dir(&ents_dir)
            .sign_ipa(&input, &out)
            .expect("sign_ipa must forward the entitlements directory");

        let blob = entitlements_slot_blob(&ipa_entry(&out, "Payload/Test.app/Test"))
            .expect("the root binary must carry the directory entitlements");
        assert!(
            blob.contains("com.zsign.dir.ent"),
            "sign_ipa must forward entitlements_dir to IpaSigner: {blob}"
        );
    }

    #[test]
    fn test_sign_bundle_forwards_entitlements_dir() {
        let dir = tempfile::TempDir::new().unwrap();
        let app = dir.path().join("Test.app");
        std::fs::create_dir_all(&app).unwrap();
        std::fs::write(app.join("Info.plist"), FIXTURE_PLIST).unwrap();
        std::fs::write(app.join("Test"), fixtures::make_minimal_macho()).unwrap();
        let ents_dir = dir.path().join("ents");
        write_entitlements_dir(&ents_dir, "com.zsign.test", "com.zsign.dir.ent");

        ZSign::new()
            .adhoc(true)
            .entitlements_dir(&ents_dir)
            .sign_bundle(&app, None)
            .expect("sign_bundle must forward the entitlements directory");

        let blob = entitlements_slot_blob(&std::fs::read(app.join("Test")).unwrap())
            .expect("the root binary must carry the directory entitlements");
        assert!(
            blob.contains("com.zsign.dir.ent"),
            "sign_bundle must forward entitlements_dir to IpaSigner: {blob}"
        );
    }

    #[test]
    fn test_entitlements_dir_uses_post_rewrite_bundle_id() {
        let dir = tempfile::TempDir::new().unwrap();
        let app = dir.path().join("Test.app");
        std::fs::create_dir_all(&app).unwrap();
        std::fs::write(app.join("Info.plist"), FIXTURE_PLIST).unwrap();
        std::fs::write(app.join("Test"), fixtures::make_minimal_macho()).unwrap();
        // Only the REWRITTEN id has a file; the pre-rewrite one must not be used.
        let ents_dir = dir.path().join("ents");
        write_entitlements_dir(&ents_dir, "com.zsign.rewritten", "com.zsign.dir.ent");
        write_entitlements_dir(&ents_dir, "com.zsign.test", "com.zsign.stale.ent");

        ZSign::new()
            .adhoc(true)
            .bundle_id("com.zsign.rewritten")
            .entitlements_dir(&ents_dir)
            .sign_bundle(&app, None)
            .expect("signing with a rewrite must succeed");

        let blob = entitlements_slot_blob(&std::fs::read(app.join("Test")).unwrap())
            .expect("the root binary must carry the directory entitlements");
        assert!(
            blob.contains("com.zsign.dir.ent"),
            "the directory must be keyed by the post-rewrite id: {blob}"
        );
        assert!(
            !blob.contains("com.zsign.stale.ent"),
            "the pre-rewrite id must not be used as a directory key: {blob}"
        );
    }

    #[test]
    fn test_sign_macho_ignores_entitlements_dir() {
        let dir = tempfile::TempDir::new().unwrap();
        let ents_dir = dir.path().join("ents");
        write_entitlements_dir(&ents_dir, "app", "com.zsign.dir.ent");
        let input = dir.path().join("app.bin");
        std::fs::write(&input, fixtures::make_minimal_macho()).unwrap();
        let out = dir.path().join("signed.bin");

        // A bare Mach-O has no bundle identity, so the directory must not apply.
        ZSign::new()
            .adhoc(true)
            .entitlements_dir(&ents_dir)
            .sign_macho(&input, &out)
            .expect("sign_macho must not consult the directory");

        assert!(
            entitlements_slot_blob(&std::fs::read(&out).unwrap()).is_none(),
            "sign_macho has no bundle identity and must not sign with directory entitlements"
        );
    }

    /// Root app `com.zsign.test` with `PlugIns/Ext.appex` (`com.zsign.test.ext`).
    fn create_bundle_with_appex(dir: &Path) -> (PathBuf, PathBuf) {
        let app = dir.join("App.app");
        std::fs::create_dir_all(&app).unwrap();
        std::fs::write(app.join("Info.plist"), FIXTURE_PLIST).unwrap();
        std::fs::write(app.join("Test"), fixtures::make_minimal_macho()).unwrap();
        let appex = app.join("PlugIns").join("Ext.appex");
        std::fs::create_dir_all(&appex).unwrap();
        std::fs::write(appex.join("Info.plist"), EXT_APPLE_INFO_PLIST).unwrap();
        std::fs::write(appex.join("Ext"), fixtures::make_minimal_macho()).unwrap();
        (app, appex)
    }

    /// Info.plist for the `Ext.appex` fixture, shared by the folder and IPA
    /// builders so both declare the same nested bundle id.
    const EXT_APPLE_INFO_PLIST: &[u8] = br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
    <key>CFBundleIdentifier</key><string>com.zsign.test.ext</string>
    <key>CFBundleExecutable</key><string>Ext</string>
    <key>CFBundlePackageType</key><string>XPC!</string>
</dict></plist>"#;

    /// A development profile whose entitlements carry `marker`.
    fn write_ext_profile(path: &Path, marker: &str) {
        std::fs::write(
            path,
            format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Entitlements</key>
  <dict>
    <key>application-identifier</key>
    <string>TESTTEAM.com.zsign.test.ext</string>
    <key>{marker}</key>
    <true/>
  </dict>
  <key>TeamIdentifier</key>
  <array><string>TESTTEAM</string></array>
  <key>ProvisionedDevices</key>
  <array><string>00008030-000000000000001E</string></array>
  <key>ExpirationDate</key>
  <date>2099-01-01T00:00:00Z</date>
</dict></plist>"#
            ),
        )
        .unwrap();
    }

    /// Writes an IPA carrying the same `Ext.appex` fixture as the folder builder.
    fn write_ipa_with_appex(path: &Path) {
        use std::io::Write;
        use zip::write::SimpleFileOptions;
        let file = std::fs::File::create(path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let opts =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        zip.start_file("Payload/App.app/Info.plist", opts).unwrap();
        zip.write_all(FIXTURE_PLIST).unwrap();
        zip.start_file("Payload/App.app/Test", opts).unwrap();
        zip.write_all(&fixtures::make_minimal_macho()).unwrap();
        zip.start_file("Payload/App.app/PlugIns/Ext.appex/Info.plist", opts)
            .unwrap();
        zip.write_all(EXT_APPLE_INFO_PLIST).unwrap();
        zip.start_file("Payload/App.app/PlugIns/Ext.appex/Ext", opts)
            .unwrap();
        zip.write_all(&fixtures::make_minimal_macho()).unwrap();
        zip.finish().unwrap();
    }

    #[test]
    fn test_sign_bundle_forwards_bundle_profiles() {
        let dir = tempfile::TempDir::new().unwrap();
        let (app, appex) = create_bundle_with_appex(dir.path());
        let ext_profile = dir.path().join("ext.mobileprovision");
        write_ext_profile(&ext_profile, "com.zsign.ext.ent");

        ZSign::new()
            .adhoc(true)
            .allow_unsafe_profile(true)
            .bundle_profiles(vec![(
                "com.zsign.test.ext".to_string(),
                ext_profile.clone(),
            )])
            .sign_bundle(&app, None)
            .expect("sign_bundle must forward the profile map");

        assert_eq!(
            std::fs::read(appex.join("embedded.mobileprovision")).unwrap(),
            std::fs::read(&ext_profile).unwrap(),
            "the forwarded map must embed the appex's profile"
        );
        let blob = entitlements_slot_blob(&std::fs::read(appex.join("Ext")).unwrap())
            .expect("the appex binary must carry its mapped entitlements");
        assert!(
            blob.contains("com.zsign.ext.ent"),
            "sign_bundle must forward bundle_profiles to IpaSigner: {blob}"
        );
    }

    #[test]
    fn test_sign_ipa_forwards_bundle_profiles() {
        let dir = tempfile::TempDir::new().unwrap();
        let ext_profile = dir.path().join("ext.mobileprovision");
        write_ext_profile(&ext_profile, "com.zsign.ext.ent");
        let ipa = dir.path().join("in.ipa");
        write_ipa_with_appex(&ipa);
        let out = dir.path().join("out.ipa");

        // An unused key fails the whole sign, so a successful sign with a map
        // entry is itself the evidence that the forward happened.
        ZSign::new()
            .adhoc(true)
            .allow_unsafe_profile(true)
            .bundle_profiles(vec![(
                "com.zsign.test.ext".to_string(),
                ext_profile.clone(),
            )])
            .sign_ipa(&ipa, &out)
            .expect("sign_ipa must forward the profile map");

        assert_eq!(
            ipa_entry(
                &out,
                "Payload/App.app/PlugIns/Ext.appex/embedded.mobileprovision"
            ),
            std::fs::read(&ext_profile).unwrap(),
            "the mapped profile must be embedded in the signed IPA's appex"
        );
    }

    #[test]
    fn test_sign_bundle_forwards_remove_embedded_profile() {
        let dir = tempfile::TempDir::new().unwrap();
        let app = dir.path().join("Test.app");
        std::fs::create_dir_all(&app).unwrap();
        std::fs::write(app.join("Info.plist"), FIXTURE_PLIST).unwrap();
        std::fs::write(app.join("Test"), fixtures::make_minimal_macho()).unwrap();
        // Pre-seeded junk profile: it survives a sign that does NOT forward -R.
        std::fs::write(app.join("embedded.mobileprovision"), b"junk").unwrap();

        ZSign::new()
            .adhoc(true)
            .remove_embedded_profile(true)
            .sign_bundle(&app, None)
            .expect("sign_bundle must forward -R");

        assert!(
            !app.join("embedded.mobileprovision").exists(),
            "sign_bundle must forward remove_embedded_profile to IpaSigner"
        );
    }

    #[test]
    fn test_sign_ipa_forwards_remove_embedded_profile() {
        use std::io::Write;
        use zip::write::SimpleFileOptions;

        let dir = tempfile::TempDir::new().unwrap();
        let input = dir.path().join("in.ipa");
        {
            let file = std::fs::File::create(&input).unwrap();
            let mut zip = zip::ZipWriter::new(file);
            let opts =
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
            zip.start_file("Payload/Test.app/Info.plist", opts).unwrap();
            zip.write_all(FIXTURE_PLIST).unwrap();
            zip.start_file("Payload/Test.app/Test", opts).unwrap();
            zip.write_all(&fixtures::make_minimal_macho()).unwrap();
            zip.start_file("Payload/Test.app/embedded.mobileprovision", opts)
                .unwrap();
            zip.write_all(b"junk").unwrap();
            zip.finish().unwrap();
        }
        let out = dir.path().join("out.ipa");

        ZSign::new()
            .adhoc(true)
            .remove_embedded_profile(true)
            .sign_ipa(&input, &out)
            .expect("sign_ipa must forward -R");

        // `ipa_entry` unwraps, so the absence itself is the assertion: a
        // forwarded -R leaves no such entry in the repacked archive.
        let names = ipa_entry_names(&out);
        assert!(
            !names
                .iter()
                .any(|n| n.ends_with("embedded.mobileprovision")),
            "sign_ipa must forward remove_embedded_profile to IpaSigner: {names:?}"
        );
    }

    /// The brief's forgery: no CMS envelope, foreign team, another app id,
    /// long expired, `get-task-allow` and a wildcard keychain group.
    const FORGED_PROFILE_XML: &[u8] = br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Name</key>
    <string>Forged Profile</string>
    <key>CreationDate</key>
    <date>2001-01-01T00:00:00Z</date>
    <key>ExpirationDate</key>
    <date>2001-01-02T00:00:00Z</date>
    <key>TeamIdentifier</key>
    <array>
        <string>EVILTEAM</string>
    </array>
    <key>Entitlements</key>
    <dict>
        <key>application-identifier</key>
        <string>EVILTEAM.com.other.app</string>
        <key>get-task-allow</key>
        <true/>
        <key>keychain-access-groups</key>
        <array>
            <string>*</string>
        </array>
    </dict>
</dict>
</plist>"#;

    /// Writes the forged profile and a minimal Mach-O into `dir`, returning
    /// the two paths both sign_macho tests use.
    fn forged_profile_sign_paths(dir: &Path) -> (PathBuf, PathBuf) {
        let profile = dir.join("forged.mobileprovision");
        std::fs::write(&profile, FORGED_PROFILE_XML).unwrap();
        let input = dir.join("app.bin");
        std::fs::write(&input, fixtures::make_minimal_macho()).unwrap();
        (profile, input)
    }

    #[test]
    fn sign_macho_rejects_forged_profile() {
        let dir = tempfile::TempDir::new().unwrap();
        let (profile, input) = forged_profile_sign_paths(dir.path());
        let out = dir.path().join("signed.bin");
        let err = ZSign::new()
            .credentials(crate::test_util::test_credentials())
            .provisioning_profile(&profile)
            .sign_macho(&input, &out)
            .expect_err("a CMS-less profile must not sign a Mach-O");
        assert!(
            matches!(err, Error::Core(zsign_core::Error::Verification(_))),
            "a profile without a CMS envelope must fail verification, got: {err}"
        );
    }

    /// A failed profile validation must name the file that failed, not just
    /// the class: the caller pointed at a path and needs it echoed back.
    #[test]
    fn sign_macho_forged_profile_names_the_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let (profile, input) = forged_profile_sign_paths(dir.path());
        let out = dir.path().join("signed.bin");
        let err = ZSign::new()
            .credentials(crate::test_util::test_credentials())
            .provisioning_profile(&profile)
            .sign_macho(&input, &out)
            .expect_err("a CMS-less profile must not sign a Mach-O");
        assert!(
            matches!(&err, Error::Core(zsign_core::Error::Verification(_))),
            "class pin: {err:?}"
        );
        let file_name = profile.file_name().unwrap().to_str().unwrap();
        assert!(
            err.to_string().contains(file_name),
            "the validation failure must name the profile file: {err}"
        );
    }

    /// A profile path that does not exist is an I/O failure, and it must name
    /// the path it could not read.
    #[test]
    fn sign_macho_missing_profile_names_the_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let (_profile, input) = forged_profile_sign_paths(dir.path());
        let out = dir.path().join("signed.bin");
        let missing = dir.path().join("absent.mobileprovision");
        let err = ZSign::new()
            .credentials(crate::test_util::test_credentials())
            .provisioning_profile(&missing)
            .sign_macho(&input, &out)
            .expect_err("an unreadable profile must not sign a Mach-O");
        assert!(matches!(&err, Error::Io(_)), "got: {err:?}");
        let message = err.to_string();
        assert!(
            message.contains("provisioning profile"),
            "the read failure must name what it was reading: {message}"
        );
        assert!(
            message.contains("absent.mobileprovision"),
            "the read failure must name the path: {message}"
        );
    }

    #[test]
    fn sign_macho_accepts_forged_profile_with_explicit_bypass() {
        let dir = tempfile::TempDir::new().unwrap();
        let (profile, input) = forged_profile_sign_paths(dir.path());
        let out = dir.path().join("signed.bin");
        ZSign::new()
            .credentials(crate::test_util::test_credentials())
            .provisioning_profile(&profile)
            .allow_unsafe_profile(true)
            .sign_macho(&input, &out)
            .expect("the explicit bypass signs the same forged bytes");
    }
}
