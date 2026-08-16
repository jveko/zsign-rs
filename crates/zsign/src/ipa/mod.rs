//! IPA file handling for iOS app signing.
//!
//! This module provides functionality for working with IPA (iOS App Store Package) files:
//!
//! - **Extraction**: Unpacking IPA archives via [`extract_ipa`] and validation with [`validate_ipa`]
//! - **Signing**: Signing all Mach-O binaries with [`IpaSigner`]
//! - **Archiving**: Repacking signed bundles via [`create_ipa`] with configurable [`CompressionLevel`]
//!
//! # IPA Structure
//!
//! An IPA file is a ZIP archive containing:
//! ```text
//! Payload/
//!   └── AppName.app/
//!       ├── Info.plist
//!       ├── AppName (main executable)
//!       ├── embedded.mobileprovision
//!       ├── _CodeSignature/
//!       │   └── CodeResources
//!       └── Frameworks/
//!           └── *.framework/
//! ```
//!
//! # Examples
//!
//! ## Complete signing workflow
//!
//! ```no_run
//! use zsign_rs::ipa::IpaSigner;
//! use zsign_rs::crypto::SigningCredentials;
//!
//! let p12_data = std::fs::read("cert.p12").unwrap();
//! let credentials = SigningCredentials::from_p12(&p12_data, "password")?;
//! let signer = IpaSigner::new(&credentials)
//!     .provisioning_profile("profile.mobileprovision");
//!
//! signer.sign("input.ipa", "output.ipa")?;
//! # Ok::<(), zsign_rs::Error>(())
//! ```
//!
//! ## Manual extraction and repacking
//!
//! ```no_run
//! use zsign_rs::ipa::{extract_ipa, create_ipa, CompressionLevel};
//!
//! // Extract IPA to inspect or modify contents
//! let app_bundle = extract_ipa("input.ipa", "output_dir")?;
//!
//! // Repack into a new IPA with maximum compression
//! create_ipa(&app_bundle, "output.ipa", CompressionLevel::MAX)?;
//! # Ok::<(), zsign_rs::Error>(())
//! ```

pub mod archive;
pub mod extract;

pub use archive::{create_ipa, CompressionLevel};
pub use extract::{extract_ipa, validate_ipa};

use crate::bundle::CodeResourcesBuilder;
use crate::crypto::SigningCredentials;
use crate::macho::{sign_any_macho, sign_macho, MachOFile};
use crate::{Error, Result};
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;
use rayon::prelude::*;
use walkdir::WalkDir;

/// High-level IPA signing workflow.
///
/// Provides a builder-style interface for signing IPA files, handling
/// extraction, bundle signing, and repacking automatically.
///
/// # Examples
///
/// ```no_run
/// use zsign_rs::ipa::IpaSigner;
/// use zsign_rs::crypto::SigningCredentials;
///
/// let p12_data = std::fs::read("cert.p12").unwrap();
/// let credentials = SigningCredentials::from_p12(&p12_data, "password")?;
///
/// // Basic signing
/// IpaSigner::new(&credentials)
///     .sign("input.ipa", "output.ipa")?;
///
/// // With provisioning profile and custom compression
/// use zsign_rs::ipa::CompressionLevel;
/// IpaSigner::new(&credentials)
///     .provisioning_profile("dev.mobileprovision")
///     .compression_level(CompressionLevel::MAX)
///     .sign("input.ipa", "output.ipa")?;
/// # Ok::<(), zsign_rs::Error>(())
/// ```
///
/// # Workflow
///
/// The signing process involves these steps:
/// 1. Extract IPA via [`extract_ipa`]
/// 2. Sign all Mach-O binaries in the `.app` bundle
/// 3. Embed provisioning profile (if provided)
/// 4. Generate `_CodeSignature/CodeResources`
/// 5. Repack via [`create_ipa`]
///
/// For manual control over extraction/repacking, use [`extract_ipa`] and
/// [`create_ipa`] directly.
pub struct IpaSigner<'a> {
    /// Reference to signing credentials; `None` signs ad-hoc
    credentials: Option<&'a SigningCredentials>,
    /// Compression level for output IPA
    compression_level: CompressionLevel,
    /// Path to provisioning profile to embed as embedded.mobileprovision
    provisioning_profile_path: Option<PathBuf>,
    /// Override bundle identifier for the main app bundle
    bundle_id: Option<String>,
    /// Override display name for the main app bundle
    bundle_name: Option<String>,
    /// Override bundle version for the main app bundle
    bundle_version: Option<String>,
    /// Emit only the SHA-256 code directory (no SHA-1 code directory)
    sha256_only: bool,
}

impl<'a> IpaSigner<'a> {
    /// Creates a new IPA signer with the given signing credentials.
    ///
    /// Uses [`CompressionLevel::DEFAULT`] for output compression.
    /// Configure with [`Self::compression_level`] and [`Self::provisioning_profile`]
    /// before calling [`Self::sign`].
    pub fn new(credentials: &'a SigningCredentials) -> Self {
        Self {
            credentials: Some(credentials),
            compression_level: CompressionLevel::DEFAULT,
            provisioning_profile_path: None,
            bundle_id: None,
            bundle_name: None,
            bundle_version: None,
            sha256_only: false,
        }
    }

    /// Creates an ad-hoc signer (no certificate or private key).
    pub fn new_adhoc() -> Self {
        Self {
            credentials: None,
            compression_level: CompressionLevel::DEFAULT,
            provisioning_profile_path: None,
            bundle_id: None,
            bundle_name: None,
            bundle_version: None,
            sha256_only: false,
        }
    }

    /// Returns the signing credentials if identity signing was configured.
    fn credentials_or_err(&self) -> Option<&'a SigningCredentials> {
        self.credentials
    }

    /// Sets the compression level for the output IPA.
    ///
    /// See [`CompressionLevel`] for available options.
    pub fn compression_level(mut self, level: CompressionLevel) -> Self {
        self.compression_level = level;
        self
    }

    /// Sets the provisioning profile to embed as `embedded.mobileprovision`.
    ///
    /// iOS apps require a provisioning profile to launch on device.
    /// The profile is read and entitlements are extracted during [`Self::sign`],
    /// where errors can be properly propagated.
    pub fn provisioning_profile(mut self, path: impl AsRef<Path>) -> Self {
        self.provisioning_profile_path = Some(path.as_ref().to_path_buf());
        self
    }

    /// Sets a new bundle identifier for the main app bundle.
    ///
    /// When set, the `CFBundleIdentifier` in the main app's `Info.plist` will be
    /// rewritten to this value before signing.
    pub fn bundle_id(mut self, id: impl Into<String>) -> Self {
        self.bundle_id = Some(id.into());
        self
    }

    /// Sets a new display name for the main app bundle.
    ///
    /// When set, `CFBundleDisplayName` in the main app's `Info.plist` is
    /// rewritten before signing.
    pub fn bundle_name(mut self, name: impl Into<String>) -> Self {
        self.bundle_name = Some(name.into());
        self
    }

    /// Sets a new bundle version for the main app bundle.
    ///
    /// When set, `CFBundleShortVersionString` in the main app's `Info.plist`
    /// is rewritten before signing.
    pub fn bundle_version(mut self, version: impl Into<String>) -> Self {
        self.bundle_version = Some(version.into());
        self
    }

    /// Emits only the SHA-256 code directory (`-2` behaviour).
    ///
    /// The SHA-1 code directory slot and its page hashes are omitted from
    /// the superblob, matching the reference tool's single-code-directory
    /// mode.
    pub fn sha256_only(mut self, only: bool) -> Self {
        self.sha256_only = only;
        self
    }

    /// Signs an IPA file.
    ///
    /// This performs the complete signing workflow:
    /// 1. Extract IPA to a temporary directory via [`extract_ipa`]
    /// 2. Find the `.app` bundle in `Payload/`
    /// 3. Sign all Mach-O binaries in-place
    /// 4. Copy provisioning profile to bundle (if set via [`Self::provisioning_profile`])
    /// 5. Generate `CodeResources` (hashes include signed binaries and profile)
    /// 6. Repack into a new IPA via [`create_ipa`]
    ///
    /// # Arguments
    ///
    /// * `input_ipa` - Path to the input IPA file
    /// * `output_ipa` - Path for the signed output IPA
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if files cannot be read or written.
    /// Returns [`Error::Zip`] if the IPA archive is invalid.
    /// Returns [`Error::Signing`] if code signing fails.
    pub fn sign(&self, input_ipa: impl AsRef<Path>, output_ipa: impl AsRef<Path>) -> Result<()> {
        let input_ipa = input_ipa.as_ref();
        let output_ipa = output_ipa.as_ref();

        validate_ipa(input_ipa)?;

        let temp_dir = TempDir::new().map_err(|e| {
            Error::Io(std::io::Error::other(
                format!("Failed to create temp directory: {}", e),
            ))
        })?;

        let app_bundle = extract_ipa(input_ipa, temp_dir.path())?;
        self.sign_bundle_from_options(&app_bundle)?;

        create_ipa(&app_bundle, output_ipa, self.compression_level)?;

        Ok(())
    }

    /// Loads the provisioning profile and its entitlements.
    fn load_profile(&self) -> Result<(Option<Vec<u8>>, Option<Vec<u8>>)> {
        match &self.provisioning_profile_path {
            Some(path) => {
                let data = fs::read(path)?;
                let ent = zsign_core::extract_entitlements_from_profile(&data)?;
                Ok((Some(data), ent))
            }
            None => Ok((None, None)),
        }
    }

    /// Signs an app bundle in place (`.app` folder signing).
    ///
    /// All Mach-O binaries are signed in place, the provisioning profile is
    /// embedded (if set), and `_CodeSignature/CodeResources` is generated.
    pub fn sign_folder_in_place(&self, bundle_path: impl AsRef<Path>) -> Result<()> {
        let bundle_path = bundle_path.as_ref();
        if !bundle_path.is_dir() {
            return Err(Error::Io(std::io::Error::other(format!(
                "Not a directory: {}",
                bundle_path.display()
            ))));
        }
        self.sign_bundle_from_options(bundle_path)
    }

    /// Signs an app bundle and repacks it as an IPA.
    pub fn sign_folder_to_ipa(
        &self,
        bundle_path: impl AsRef<Path>,
        output_ipa: impl AsRef<Path>,
    ) -> Result<()> {
        self.sign_folder_in_place(&bundle_path)?;
        create_ipa(bundle_path.as_ref(), output_ipa.as_ref(), self.compression_level)
    }

    /// Loads profile options and applies bundle rewrites before signing.
    fn sign_bundle_from_options(&self, bundle_path: &Path) -> Result<()> {
        let (profile_data, entitlements) = self.load_profile()?;
        self.sign_bundle(bundle_path, entitlements.as_deref(), profile_data.as_deref())
    }

    /// Sign an app bundle in place.
    ///
    /// Signs all Mach-O binaries and generates CodeResources.
    ///
    /// The signing workflow follows C++ zsign order:
    /// 1. Find and sign ALL standalone .dylib files first (with empty params)
    /// 2. Collect all bundles (main app, frameworks, plugins) with their depths
    /// 3. Sort by depth (deepest first)
    /// 4. Sign each bundle in order so nested bundles are fully signed before
    ///    their parent includes them in CodeResources
    ///
    /// For each bundle, the signing order is:
    /// 1. Sign all Mach-O binaries in-place (modifies binary content)
    /// 2. Copy provisioning profile to bundle (main app only)
    /// 3. Generate CodeResources (hashes all files including signed binaries)
    fn sign_bundle(&self, bundle_path: &Path, entitlements: Option<&[u8]>, profile_data: Option<&[u8]>) -> Result<()> {
        if let Some(ref new_id) = self.bundle_id {
            self.rewrite_plist_string(bundle_path, "CFBundleIdentifier", new_id)?;
        }
        if let Some(ref name) = self.bundle_name {
            self.rewrite_plist_string(bundle_path, "CFBundleDisplayName", name)?;
        }
        if let Some(ref version) = self.bundle_version {
            self.rewrite_plist_string(bundle_path, "CFBundleShortVersionString", version)?;
        }

        let dylibs = self.find_standalone_dylibs(bundle_path)?;
        dylibs.par_iter()
            .try_for_each(|dylib_path| self.sign_standalone_dylib(dylib_path))?;

        let mut bundles = self.collect_nested_bundles(bundle_path)?;

        bundles.sort_by(|a, b| b.1.cmp(&a.1));

        for (nested_bundle_path, _depth) in &bundles {
            let is_main_bundle = nested_bundle_path == bundle_path;
            self.sign_single_bundle(
                nested_bundle_path,
                is_main_bundle,
                if is_main_bundle { entitlements } else { None },
                if is_main_bundle { profile_data } else { None },
            )?;
        }

        Ok(())
    }

    /// Collect all nested bundles (.app, .framework, .appex) with their depths.
    ///
    /// Returns a vector of (path, depth) tuples where depth is the nesting level.
    fn collect_nested_bundles(&self, bundle_path: &Path) -> Result<Vec<(PathBuf, usize)>> {
        let mut bundles = Vec::new();

        bundles.push((bundle_path.to_path_buf(), 0));

        for entry in WalkDir::new(bundle_path)
            .min_depth(1)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let path = entry.path();

            if path.is_dir() && Self::is_bundle_directory(path) {
                let depth = self.calculate_bundle_depth(path, bundle_path);
                bundles.push((path.to_path_buf(), depth));
            }
        }

        Ok(bundles)
    }

    /// Check if a directory is an iOS bundle.
    fn is_bundle_directory(path: &Path) -> bool {
        if let Some(ext) = path.extension() {
            let ext_str = ext.to_string_lossy().to_lowercase();
            matches!(ext_str.as_str(), "app" | "framework" | "appex")
        } else {
            false
        }
    }

    /// Calculate the nesting depth of a bundle relative to the root bundle.
    ///
    /// Depth is based on how many bundle directories are in the path.
    fn calculate_bundle_depth(&self, bundle_path: &Path, root_bundle: &Path) -> usize {
        let relative = bundle_path.strip_prefix(root_bundle).unwrap_or(bundle_path);

        let mut depth = 0;
        for component in relative.iter() {
            let component_str = component.to_string_lossy();
            if component_str.ends_with(".app")
                || component_str.ends_with(".framework")
                || component_str.ends_with(".appex")
            {
                depth += 1;
            }
        }

        depth
    }

    /// Find all standalone .dylib files recursively in the bundle.
    ///
    /// This matches C++ zsign behavior: find ALL .dylib files and sign them
    /// BEFORE processing bundle folders. These are signed with empty parameters
    /// (no bundleId, no InfoPlist hash, no CodeResources).
    fn find_standalone_dylibs(&self, bundle_path: &Path) -> Result<Vec<PathBuf>> {
        let mut dylibs = Vec::new();

        for entry in WalkDir::new(bundle_path)
            .min_depth(1)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let path = entry.path();

            if !path.is_file() {
                continue;
            }

            if let Some(ext) = path.extension() {
                if ext == "dylib"
                    && !path
                        .components()
                        .any(|c| c.as_os_str() == "_CodeSignature")
                {
                    dylibs.push(path.to_path_buf());
                }
            }
        }

        Ok(dylibs)
    }

    /// Sign a standalone .dylib file with empty parameters.
    ///
    /// C++ zsign signs dylibs with: macho.Sign(asset, force, "", "", "", "")
    /// This means: no bundleId, no InfoPlist hash, no CodeResources.
    fn sign_standalone_dylib(&self, dylib_path: &Path) -> Result<()> {
        let macho = MachOFile::open(dylib_path)?;

        let identifier = dylib_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("dylib")
            .to_string();

        let signed_binary = match self.credentials {
            Some(creds) => sign_macho(&macho, &identifier, None, creds, None, None)?,
            None => crate::macho::sign_macho_adhoc(&macho, &identifier, None, None, None)?,
        };

        fs::write(dylib_path, signed_binary)?;

        Ok(())
    }

    /// Sign a single bundle (binaries + CodeResources).
    ///
    /// This handles one bundle at a time. Called in depth-first order.
    ///
    /// The correct signing order is:
    /// 1. Sign all binaries EXCEPT the main executable (no CodeResources yet)
    /// 2. Generate CodeResources (which hashes the signed binaries)
    /// 3. Sign the main executable WITH the CodeResources hash
    fn sign_single_bundle(&self, bundle_path: &Path, copy_provisioning_profile: bool, entitlements: Option<&[u8]>, profile_data: Option<&[u8]>) -> Result<()> {
        let identifier = self.get_bundle_identifier(bundle_path)?;
        let main_executable = self.get_main_executable(bundle_path)?;

        let binaries = self.find_immediate_macho_binaries(bundle_path)?;

        let non_main_binaries: Vec<_> = binaries.iter()
            .filter(|p| *p != &main_executable)
            .collect();

        non_main_binaries.par_iter()
            .try_for_each(|binary_path| {
                let binary_identifier = binary_path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or(&identifier);
                self.sign_binary(binary_path, binary_identifier, None, entitlements)
            })?;

        if copy_provisioning_profile {
            if let Some(data) = profile_data {
                let embedded_path = bundle_path.join("embedded.mobileprovision");
                fs::write(&embedded_path, data).map_err(|e| {
                    Error::Core(zsign_core::Error::Signing(format!(
                        "Failed to write provisioning profile to {}: {}",
                        embedded_path.display(),
                        e
                    )))
                })?;
            }
        }

        self.generate_code_resources(bundle_path)?;

        let code_resources_path = bundle_path.join("_CodeSignature/CodeResources");
        let code_resources_data = if code_resources_path.exists() {
            Some(fs::read(&code_resources_path)?)
        } else {
            None
        };

        if main_executable.exists() {
            self.sign_binary(&main_executable, &identifier, code_resources_data.as_deref(), entitlements)?;
        }

        Ok(())
    }

    /// Find Mach-O binaries that belong directly to this bundle (not nested bundles).
    ///
    /// This excludes binaries inside nested .framework or .appex directories.
    fn find_immediate_macho_binaries(&self, bundle_path: &Path) -> Result<Vec<PathBuf>> {
        let mut binaries = Vec::new();

        let main_executable = self.get_main_executable(bundle_path)?;
        if main_executable.exists() {
            binaries.push(main_executable.clone());
        }

        for entry in WalkDir::new(bundle_path)
            .min_depth(1)
            .into_iter()
            .filter_entry(|e| {
                let path = e.path();
                if path != bundle_path && path.is_dir() && Self::is_bundle_directory(path) {
                    return false;
                }
                true
            })
            .filter_map(|e| e.ok())
        {
            let path = entry.path();

            if !path.is_file() {
                continue;
            }

            if path
                .components()
                .any(|c| c.as_os_str() == "_CodeSignature")
            {
                continue;
            }

            if path != main_executable && self.is_macho_binary(path)? {
                binaries.push(path.to_path_buf());
            }
        }

        Ok(binaries)
    }

    /// Rewrites a string key in the main app's `Info.plist`.
    fn rewrite_plist_string(&self, bundle_path: &Path, key: &str, value: &str) -> Result<()> {
        let info_plist_path = bundle_path.join("Info.plist");

        if !info_plist_path.exists() {
            return Err(Error::Core(zsign_core::Error::Signing(format!(
                "Info.plist not found in bundle: {}",
                bundle_path.display()
            ))));
        }

        let plist_data = fs::read(&info_plist_path)?;
        let mut plist: plist::Value = plist::from_bytes(&plist_data)
            .map_err(|e| Error::Core(zsign_core::Error::Signing(format!("Failed to parse Info.plist: {}", e))))?;

        if let Some(dict) = plist.as_dictionary_mut() {
            dict.insert(key.to_string(), plist::Value::String(value.to_string()));
        }

        let mut buf = Vec::new();
        plist::to_writer_xml(&mut buf, &plist)
            .map_err(|e| Error::Core(zsign_core::Error::Signing(format!("Failed to serialize Info.plist: {}", e))))?;

        fs::write(&info_plist_path, &buf)?;

        Ok(())
    }

    /// Get the bundle identifier from Info.plist.
    fn get_bundle_identifier(&self, bundle_path: &Path) -> Result<String> {
        let info_plist_path = bundle_path.join("Info.plist");

        if !info_plist_path.exists() {
            return Err(Error::Core(zsign_core::Error::Signing(format!(
                "Info.plist not found in bundle: {}",
                bundle_path.display()
            ))));
        }

        let plist_data = fs::read(&info_plist_path)?;
        let plist: plist::Value = plist::from_bytes(&plist_data)
            .map_err(|e| Error::Core(zsign_core::Error::Signing(format!("Failed to parse Info.plist: {}", e))))?;

        let identifier = plist
            .as_dictionary()
            .and_then(|d| d.get("CFBundleIdentifier"))
            .and_then(|v| v.as_string())
            .map(|s| s.to_string())
            .unwrap_or_else(|| {
                bundle_path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("unknown")
                    .to_string()
            });

        Ok(identifier)
    }

    /// Get the main executable path from Info.plist.
    fn get_main_executable(&self, bundle_path: &Path) -> Result<PathBuf> {
        let info_plist_path = bundle_path.join("Info.plist");

        if !info_plist_path.exists() {
            let bundle_name = bundle_path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("unknown");
            return Ok(bundle_path.join(bundle_name));
        }

        let plist_data = fs::read(&info_plist_path)?;
        let plist: plist::Value = plist::from_bytes(&plist_data)
            .map_err(|e| Error::Core(zsign_core::Error::Signing(format!("Failed to parse Info.plist: {}", e))))?;

        let executable_name = plist
            .as_dictionary()
            .and_then(|d| d.get("CFBundleExecutable"))
            .and_then(|v| v.as_string())
            .map(|s| s.to_string())
            .unwrap_or_else(|| {
                bundle_path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("unknown")
                    .to_string()
            });

        Ok(bundle_path.join(executable_name))
    }

    /// Check if a file is a Mach-O binary by reading its magic bytes.
    fn is_macho_binary(&self, path: &Path) -> Result<bool> {
        use std::io::Read;

        let mut file = match fs::File::open(path) {
            Ok(f) => f,
            Err(_) => return Ok(false),
        };

        let mut magic = [0u8; 4];
        if file.read_exact(&mut magic).is_err() {
            return Ok(false);
        }

        let is_macho = matches!(
            magic,
            [0xfe, 0xed, 0xfa, 0xce]
                | [0xfe, 0xed, 0xfa, 0xcf]
                | [0xce, 0xfa, 0xed, 0xfe]
                | [0xcf, 0xfa, 0xed, 0xfe]
                | [0xca, 0xfe, 0xba, 0xbe]
                | [0xbe, 0xba, 0xfe, 0xca]
        );

        Ok(is_macho)
    }

    /// Sign a single Mach-O binary.
    ///
    /// Generates a code signature and embeds it directly into the binary,
    /// modifying the LC_CODE_SIGNATURE load command and appending the
    /// SuperBlob signature data.
    ///
    /// For non-executable binaries (dylibs, frameworks), empty entitlements are used
    /// instead of the full entitlements. This matches the behavior of the C++ zsign.
    fn sign_binary(
        &self,
        binary_path: &Path,
        identifier: &str,
        code_resources: Option<&[u8]>,
        entitlements: Option<&[u8]>,
    ) -> Result<()> {
        let macho = MachOFile::open(binary_path)?;

        let is_executable = macho
            .slices()
            .first()
            .map(|s| s.is_executable)
            .unwrap_or(false);

        // Only the main executable gets Info.plist in its CodeDirectory.
        // Dylibs/frameworks must NOT include Info.plist or AMFI rejects them
        // with "has entitlements but is not a main binary".
        let info_data = if is_executable && code_resources.is_some() {
            let bundle_path = binary_path
                .parent()
                .ok_or_else(|| Error::Core(zsign_core::Error::Signing("Binary has no parent directory".into())))?;
            let info_plist = bundle_path.join("Info.plist");
            if info_plist.exists() {
                Some(fs::read(&info_plist)?)
            } else {
                None
            }
        } else {
            None
        };

        let signed_binary = match self.credentials {
            Some(creds) => {
                if self.sha256_only {
                    crate::macho::sign_macho_sha256_only(
                        &macho,
                        identifier,
                        entitlements,
                        creds,
                        info_data.as_deref(),
                        code_resources,
                    )?
                } else {
                    sign_any_macho(
                        &macho,
                        identifier,
                        entitlements,
                        creds,
                        info_data.as_deref(),
                        code_resources,
                    )?
                }
            }
            None => crate::macho::sign_macho_adhoc(
                &macho,
                identifier,
                entitlements,
                info_data.as_deref(),
                code_resources,
            )?,
        };

        fs::write(binary_path, signed_binary)?;

        Ok(())
    }

    /// Generate CodeResources plist for the bundle.
    fn generate_code_resources(&self, bundle_path: &Path) -> Result<()> {
        let code_resources = CodeResourcesBuilder::new(bundle_path)?.scan()?.build()?;

        let codesig_dir = bundle_path.join("_CodeSignature");
        fs::create_dir_all(&codesig_dir)?;

        let resources_path = codesig_dir.join("CodeResources");
        fs::write(&resources_path, &code_resources)?;

        Ok(())
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use std::path::{Path, PathBuf};
    use tempfile::TempDir;
    use zip::write::SimpleFileOptions;
    use zip::ZipWriter;

    /// Create a minimal test IPA file.
    fn create_test_ipa(dir: &Path) -> PathBuf {
        let ipa_path = dir.join("test.ipa");
        let file = fs::File::create(&ipa_path).unwrap();
        let mut zip = ZipWriter::new(file);

        let options = SimpleFileOptions::default();

        zip.add_directory("Payload/", options).unwrap();
        zip.add_directory("Payload/Test.app/", options).unwrap();

        zip.start_file("Payload/Test.app/Info.plist", options)
            .unwrap();
        zip.write_all(
            br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>com.test.app</string>
    <key>CFBundleExecutable</key>
    <string>Test</string>
</dict>
</plist>"#,
        )
        .unwrap();

        zip.start_file("Payload/Test.app/Test", options).unwrap();
        zip.write_all(include_bytes!("fixtures/minimal_macho.bin"))
            .unwrap();

        zip.start_file("Payload/Test.app/data.bin", options).unwrap();
        zip.write_all(&[0xAB; 4096]).unwrap();

        zip.finish().unwrap();

        ipa_path
    }

    #[test]
    fn test_extract_and_repack_ipa() {
        let temp_dir = TempDir::new().unwrap();
        let ipa_path = create_test_ipa(temp_dir.path());

        let extract_dir = temp_dir.path().join("extracted");
        let app_bundle = extract_ipa(&ipa_path, &extract_dir).unwrap();

        assert!(app_bundle.exists());
        assert!(app_bundle.join("Info.plist").exists());

        let output_ipa = temp_dir.path().join("repacked.ipa");
        create_ipa(&app_bundle, &output_ipa, CompressionLevel::DEFAULT).unwrap();

        assert!(output_ipa.exists());

        let verify_dir = temp_dir.path().join("verify");
        let verified_bundle = extract_ipa(&output_ipa, &verify_dir).unwrap();

        assert!(verified_bundle.exists());
        assert!(verified_bundle.join("Info.plist").exists());
    }

    #[test]
    fn test_ipa_signer_workflow() {
        let temp_dir = TempDir::new().unwrap();
        let ipa_path = create_test_ipa(temp_dir.path());

        let credentials = crate::test_util::test_credentials();
        let output_ipa = temp_dir.path().join("signed.ipa");

        IpaSigner::new(&credentials)
            .bundle_id("com.zsign.changed")
            .sign(&ipa_path, &output_ipa)
            .expect("ipa signing must succeed");

        assert!(output_ipa.exists());

        // Unpack and assert the signed bundle structure.
        let verify_dir = temp_dir.path().join("signed");
        let bundle = extract_ipa(&output_ipa, &verify_dir).unwrap();

        // The bundle identifier must be rewritten before signing.
        let plist_data = fs::read(bundle.join("Info.plist")).unwrap();
        let plist: plist::Value = plist::from_bytes(&plist_data).unwrap();
        let identifier = plist
            .as_dictionary()
            .and_then(|d| d.get("CFBundleIdentifier"))
            .and_then(|v| v.as_string())
            .unwrap();
        assert_eq!(identifier, "com.zsign.changed");

        // CodeResources must exist and hash every non-excluded file.
        let cr = fs::read(bundle.join("_CodeSignature/CodeResources")).unwrap();
        let cr_plist: plist::Value = plist::from_bytes(&cr).unwrap();
        let files = cr_plist
            .as_dictionary()
            .and_then(|d| d.get("files"))
            .and_then(|v| v.as_dictionary())
            .expect("CodeResources must have a files dict");
        assert!(
            files.get("data.bin").is_some(),
            "CodeResources must hash the resource file"
        );

        // The main executable must carry an embedded code signature that
        // parses as a SuperBlob containing code directories and a CMS blob.
        let main_data = fs::read(bundle.join("Test")).unwrap();
        let macho = zsign_core::macho::MachOFile::parse(main_data.clone())
            .expect("signed binary must parse");
        let slice = &macho.slices()[0];
        let sig_off = slice.code_sig_offset.expect("binary must be signed");
        let sig_size = slice.code_sig_size.expect("binary must be signed");
        let blob = &main_data[sig_off as usize..(sig_off + sig_size) as usize];

        let magic = u32::from_be_bytes(blob[0..4].try_into().unwrap());
        assert_eq!(magic, 0xfade_0cc0, "embedded signature must be a SuperBlob");
        let count = u32::from_be_bytes(blob[8..12].try_into().unwrap()) as usize;
        let mut saw_cms = false;
        for i in 0..count {
            let typ = u32::from_be_bytes(blob[12 + i * 8..16 + i * 8].try_into().unwrap());
            if typ == 0x10000 {
                let off = u32::from_be_bytes(blob[16 + i * 8..20 + i * 8].try_into().unwrap()) as usize;
                let cms_magic = u32::from_be_bytes(blob[off..off + 4].try_into().unwrap());
                assert_eq!(cms_magic, 0xfade_0b01, "CMS slot must be a blob wrapper");
                saw_cms = true;
            }
        }
        assert!(saw_cms, "SuperBlob must contain a CMS signature");
    }
}
