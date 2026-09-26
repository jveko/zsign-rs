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

use archive::create_ipa_from_root;
pub use archive::{create_ipa, CompressionLevel};
pub use extract::{extract_ipa, validate_ipa};

use crate::bundle::CodeResourcesBuilder;
use crate::crypto::SigningCredentials;
use crate::macho::{sign_any_macho, sign_macho, MachOFile};
use crate::{Error, Result};
use rayon::prelude::*;
use std::collections::HashSet;
use std::fs;
use std::path::{Component, Path, PathBuf};
use tempfile::TempDir;
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
/// 5. Repack the extraction root via `create_ipa_from_root` (keeps
///    non-`Payload` entries such as `SwiftSupport/` and `iTunesMetadata.plist`)
///
/// For manual control over extraction/repacking, use [`extract_ipa`] and
/// [`create_ipa`] directly.
/// Provisioning profile bytes and their extracted entitlements.
type ProfilePayload = (Option<Vec<u8>>, Option<Vec<u8>>);

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
    /// Dylib load paths to inject into signed binaries
    dylibs: Vec<String>,
    /// Inject with LC_LOAD_WEAK_DYLIB instead of LC_LOAD_DYLIB
    weak_dylibs: bool,
    /// Override the FairPlay-encryption refusal (sign an encrypted binary anyway).
    allow_encrypted: bool,
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
            sha256_only: true,
            dylibs: Vec::new(),
            weak_dylibs: false,
            allow_encrypted: false,
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
            sha256_only: true,
            dylibs: Vec::new(),
            weak_dylibs: false,
            allow_encrypted: false,
        }
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

    /// Injects the given dylib load paths into every signed bundle binary.
    ///
    /// `weak` selects `LC_LOAD_WEAK_DYLIB`; otherwise `LC_LOAD_DYLIB` is used.
    pub fn dylib_injection(mut self, dylibs: Vec<String>, weak: bool) -> Self {
        self.dylibs = dylibs;
        self.weak_dylibs = weak;
        self
    }

    /// Overrides the FairPlay-encryption refusal and signs encrypted binaries anyway.
    ///
    /// Use only on binaries you have already decrypted; otherwise the output
    /// dies on-device with an AMFI kill at launch.
    pub fn allow_encrypted(mut self, allow: bool) -> Self {
        self.allow_encrypted = allow;
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
    /// 6. Repack the extraction root via `create_ipa_from_root` (keeps
    ///    non-`Payload` entries such as `SwiftSupport/` and `iTunesMetadata.plist`)
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
            Error::Io(std::io::Error::other(format!(
                "Failed to create temp directory: {}",
                e
            )))
        })?;

        let app_bundle = extract_ipa(input_ipa, temp_dir.path())?;
        // Components between the extraction root and the bundle root come
        // from the archive: none of them may be a symlink.
        Self::resolve_within(temp_dir.path(), &app_bundle)?;
        Self::ensure_single_app_bundle(&temp_dir.path().join("Payload"))?;
        self.sign_bundle_from_options(&app_bundle)?;

        create_ipa_from_root(temp_dir.path(), output_ipa, self.compression_level)?;

        Ok(())
    }

    /// Loads the provisioning profile and its entitlements.
    fn load_profile(&self) -> Result<ProfilePayload> {
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
        create_ipa(
            bundle_path.as_ref(),
            output_ipa.as_ref(),
            self.compression_level,
        )
    }

    /// Loads profile options and applies bundle rewrites before signing.
    fn sign_bundle_from_options(&self, bundle_path: &Path) -> Result<()> {
        // A trailing separator makes lstat follow a final symlink, so check
        // the component-rebuilt path; ancestors of the root stay trusted.
        let plain_root: PathBuf = bundle_path.components().collect();
        let root_metadata = fs::symlink_metadata(&plain_root)?;
        if root_metadata.file_type().is_symlink() {
            return Err(Error::Core(zsign_core::Error::Signing(format!(
                "Bundle root must not be a symlink: {}",
                bundle_path.display()
            ))));
        }
        let (profile_data, entitlements) = self.load_profile()?;
        self.sign_bundle(
            bundle_path,
            entitlements.as_deref(),
            profile_data.as_deref(),
        )
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
    fn sign_bundle(
        &self,
        bundle_path: &Path,
        entitlements: Option<&[u8]>,
        profile_data: Option<&[u8]>,
    ) -> Result<()> {
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
        dylibs
            .par_iter()
            .try_for_each(|dylib_path| self.sign_standalone_dylib(bundle_path, dylib_path))?;
        let already_signed: HashSet<PathBuf> = dylibs.iter().cloned().collect();

        let mut bundles = self.collect_nested_bundles(bundle_path)?;

        bundles.sort_by_key(|b| std::cmp::Reverse(b.1));

        for (nested_bundle_path, _depth) in &bundles {
            let is_main_bundle = nested_bundle_path == bundle_path;
            self.sign_single_bundle(
                nested_bundle_path,
                is_main_bundle,
                if is_main_bundle { entitlements } else { None },
                if is_main_bundle { profile_data } else { None },
                &already_signed,
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

            if entry.file_type().is_dir() && Self::is_bundle_directory(path) {
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

    /// Resolve `rel` — a root-relative name (raw plist value or literal) —
    /// under `root`.
    ///
    /// Never reinterprets `rel` as already root-prefixed: a value that
    /// starts with the root's own name still joins below the root. The
    /// spelling must be plain — no `..`, no absolute prefix, no `.`, no
    /// redundant separators — and no existing component may be a symlink.
    /// Returns `root.join(rel)`, the lexical shape WalkDir produces.
    fn resolve_relative(root: &Path, rel: &str) -> Result<PathBuf> {
        let rel_path = Path::new(rel);
        if rel_path.components().any(|c| {
            matches!(
                c,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        }) {
            return Err(Error::Core(zsign_core::Error::Signing(format!(
                "Path {} escapes the bundle root {}",
                rel,
                root.display()
            ))));
        }
        let separator = |c: char| c == '/' || (cfg!(windows) && c == '\\');
        if rel.split(separator).any(|s| s.is_empty() || s == ".") {
            return Err(Error::Core(zsign_core::Error::Signing(format!(
                "Path {} is not a plain relative path under {}",
                rel,
                root.display()
            ))));
        }
        Self::check_no_symlink_components(root, rel_path)?;
        Ok(root.join(rel))
    }

    /// Resolve `path` — already root-prefixed (discovery-walk output or a
    /// previously joined target) — under `root`.
    ///
    /// `strip_prefix` must succeed; the remainder must be plain; no
    /// existing component may be a symlink. Returns `root.join(relative)`,
    /// the lexical shape WalkDir produces.
    fn resolve_within(root: &Path, path: &Path) -> Result<PathBuf> {
        let relative = path.strip_prefix(root).map_err(|_| {
            Error::Core(zsign_core::Error::Signing(format!(
                "Path {} is not under root {}",
                path.display(),
                root.display()
            )))
        })?;
        if relative.components().any(|c| {
            matches!(
                c,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        }) {
            return Err(Error::Core(zsign_core::Error::Signing(format!(
                "Path {} escapes the bundle root {}",
                relative.display(),
                root.display()
            ))));
        }
        // The remainder must contain no empty segments (redundant or
        // trailing separators) and no "." segments — a PathBuf rebuild
        // would join with the native separator and reject plain
        // '/'-spelled values on Windows. CodeResources' main-executable
        // exclusion compares the raw CFBundleExecutable string against
        // WalkDir-relative paths, so only plain raw values keep that
        // invariant intact.
        let raw = relative.to_string_lossy();
        let separator = |c: char| c == '/' || (cfg!(windows) && c == '\\');
        if raw.split(separator).any(|s| s.is_empty() || s == ".") {
            return Err(Error::Core(zsign_core::Error::Signing(format!(
                "Path {} is not a plain relative path under {}",
                relative.display(),
                root.display()
            ))));
        }
        Self::check_no_symlink_components(root, relative)?;
        Ok(root.join(relative))
    }

    /// Rejects archives whose `Payload/` holds more than one `.app` bundle.
    ///
    /// `extract_ipa` selects the first `Payload/*.app` it meets in `read_dir`
    /// order, so a multi-candidate archive would be signed and repacked from
    /// an arbitrary pick. Failing here names every candidate instead.
    fn ensure_single_app_bundle(payload_dir: &Path) -> Result<()> {
        let mut candidates: Vec<String> = Vec::new();
        for entry in fs::read_dir(payload_dir)? {
            let path = entry?.path();
            if path.is_dir() && path.extension().is_some_and(|ext| ext == "app") {
                if let Some(name) = path.file_name() {
                    candidates.push(name.to_string_lossy().into_owned());
                }
            }
        }
        candidates.sort();
        if candidates.len() > 1 {
            return Err(Error::Zip(zip::result::ZipError::InvalidArchive(
                std::borrow::Cow::Owned(format!(
                    "multiple .app bundles in Payload/: {}",
                    candidates.join(", ")
                )),
            )));
        }
        Ok(())
    }

    /// Walk `relative` below `root`: reject symlink components, stop at the
    /// first missing component (a fresh tail is safe), and turn any other
    /// metadata failure into a hard error instead of treating it as absence.
    fn check_no_symlink_components(root: &Path, relative: &Path) -> Result<()> {
        let mut current = root.to_path_buf();
        for component in relative.components() {
            current.push(component);
            match fs::symlink_metadata(&current) {
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    return Err(Error::Core(zsign_core::Error::Signing(format!(
                        "Pre-existing symlink in signing path: {}",
                        current.display()
                    ))));
                }
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => break,
                Err(e) => {
                    return Err(Error::Core(zsign_core::Error::Signing(format!(
                        "Failed to inspect signing path {}: {}",
                        current.display(),
                        e
                    ))))
                }
            }
        }
        Ok(())
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

            if !entry.file_type().is_file() {
                continue;
            }

            if let Some(ext) = path.extension() {
                if ext == "dylib" && !path.components().any(|c| c.as_os_str() == "_CodeSignature") {
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
    fn sign_standalone_dylib(&self, root: &Path, dylib_path: &Path) -> Result<()> {
        let validated = Self::resolve_within(root, dylib_path)?;
        let dylib_path = validated.as_path();
        let macho = MachOFile::open(dylib_path)?;

        let identifier = dylib_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("dylib")
            .to_string();

        if !self.allow_encrypted {
            for slice in macho.slices() {
                if slice.is_encrypted() {
                    return Err(self.encrypted_error(
                        &dylib_path.display().to_string(),
                        &identifier,
                        slice,
                    ));
                }
            }
        }

        let signed_binary = match self.credentials {
            Some(creds) => sign_macho(
                &macho,
                &identifier,
                None,
                creds,
                None,
                None,
                self.allow_encrypted,
            )?,
            None => crate::macho::sign_macho_adhoc(
                &macho,
                &identifier,
                None,
                None,
                None,
                self.allow_encrypted,
            )?,
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
    fn sign_single_bundle(
        &self,
        bundle_path: &Path,
        copy_provisioning_profile: bool,
        entitlements: Option<&[u8]>,
        profile_data: Option<&[u8]>,
        already_signed: &HashSet<PathBuf>,
    ) -> Result<()> {
        let identifier = self.get_bundle_identifier(bundle_path)?;
        let main_executable = self.get_main_executable(bundle_path)?;

        let binaries = self.find_immediate_macho_binaries(bundle_path, already_signed)?;

        let non_main_binaries: Vec<_> =
            binaries.iter().filter(|p| *p != &main_executable).collect();

        non_main_binaries.par_iter().try_for_each(|binary_path| {
            let binary_identifier = binary_path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or(&identifier);
            self.sign_binary(
                bundle_path,
                binary_path,
                binary_identifier,
                None,
                entitlements,
            )
        })?;

        if copy_provisioning_profile {
            if let Some(data) = profile_data {
                let embedded_path =
                    Self::resolve_relative(bundle_path, "embedded.mobileprovision")?;
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
            self.sign_binary(
                bundle_path,
                &main_executable,
                &identifier,
                code_resources_data.as_deref(),
                entitlements,
            )?;
        }

        Ok(())
    }

    /// Find Mach-O binaries that belong directly to this bundle (not nested bundles).
    ///
    /// This excludes binaries inside nested .framework or .appex directories.
    fn find_immediate_macho_binaries(
        &self,
        bundle_path: &Path,
        already_signed: &HashSet<PathBuf>,
    ) -> Result<Vec<PathBuf>> {
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
                if path != bundle_path && e.file_type().is_dir() && Self::is_bundle_directory(path)
                {
                    return false;
                }
                true
            })
            .filter_map(|e| e.ok())
        {
            let path = entry.path();

            if !entry.file_type().is_file() {
                continue;
            }

            if path.components().any(|c| c.as_os_str() == "_CodeSignature") {
                continue;
            }

            if path != main_executable
                && !already_signed.contains(&path.to_path_buf())
                && self.is_macho_binary(path)?
            {
                binaries.push(path.to_path_buf());
            }
        }

        Ok(binaries)
    }

    /// Rewrites a string key in the main app's `Info.plist`.
    fn rewrite_plist_string(&self, bundle_path: &Path, key: &str, value: &str) -> Result<()> {
        let info_plist_path = Self::resolve_relative(bundle_path, "Info.plist")?;

        if !info_plist_path.exists() {
            return Err(Error::Core(zsign_core::Error::Signing(format!(
                "Info.plist not found in bundle: {}",
                bundle_path.display()
            ))));
        }

        let plist_data = fs::read(&info_plist_path)?;
        let mut plist: plist::Value = plist::from_bytes(&plist_data).map_err(|e| {
            Error::Core(zsign_core::Error::Signing(format!(
                "Failed to parse Info.plist: {}",
                e
            )))
        })?;

        if let Some(dict) = plist.as_dictionary_mut() {
            dict.insert(key.to_string(), plist::Value::String(value.to_string()));
        }

        let mut buf = Vec::new();
        plist::to_writer_xml(&mut buf, &plist).map_err(|e| {
            Error::Core(zsign_core::Error::Signing(format!(
                "Failed to serialize Info.plist: {}",
                e
            )))
        })?;

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
        let plist: plist::Value = plist::from_bytes(&plist_data).map_err(|e| {
            Error::Core(zsign_core::Error::Signing(format!(
                "Failed to parse Info.plist: {}",
                e
            )))
        })?;

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
    ///
    /// A present `CFBundleExecutable` must be a string naming a relative
    /// path to an existing regular file inside the bundle; non-string
    /// values, absolute values, non-plain spellings, traversal, and
    /// symlinked components are rejected. The file-stem fallback applies
    /// only when the key is absent.
    fn get_main_executable(&self, bundle_path: &Path) -> Result<PathBuf> {
        let info_plist_path = bundle_path.join("Info.plist");

        if !info_plist_path.exists() {
            return Err(Error::Core(zsign_core::Error::Signing(format!(
                "Info.plist not found in bundle: {}",
                bundle_path.display()
            ))));
        }

        let plist_data = fs::read(&info_plist_path)?;
        let plist: plist::Value = plist::from_bytes(&plist_data).map_err(|e| {
            Error::Core(zsign_core::Error::Signing(format!(
                "Failed to parse Info.plist: {}",
                e
            )))
        })?;

        let executable_value = match plist
            .as_dictionary()
            .and_then(|d| d.get("CFBundleExecutable"))
        {
            None => bundle_path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("unknown")
                .to_string(),
            Some(value) => {
                let value = value.as_string().ok_or_else(|| {
                    Error::Core(zsign_core::Error::Signing(format!(
                        "CFBundleExecutable in {} must be a string",
                        bundle_path.display()
                    )))
                })?;
                if Path::new(value).is_absolute() {
                    return Err(Error::Core(zsign_core::Error::Signing(format!(
                        "CFBundleExecutable \"{}\" must be a relative path inside the bundle {}",
                        value,
                        bundle_path.display()
                    ))));
                }
                let executable = Self::resolve_relative(bundle_path, value)?;
                match fs::symlink_metadata(&executable) {
                    Ok(metadata) if metadata.is_file() => return Ok(executable),
                    Ok(_) => {
                        return Err(Error::Core(zsign_core::Error::Signing(format!(
                            "CFBundleExecutable \"{}\" does not name a regular file in {}",
                            value,
                            bundle_path.display()
                        ))))
                    }
                    Err(e) => {
                        return Err(Error::Core(zsign_core::Error::Signing(format!(
                            "CFBundleExecutable \"{}\" in {} is not an existing regular file: {}",
                            value,
                            bundle_path.display(),
                            e
                        ))))
                    }
                }
            }
        };

        Self::resolve_relative(bundle_path, &executable_value)
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
    /// Entitlements are emitted only for executables: non-executables
    /// (dylibs, frameworks) are signed with no entitlements slot at all
    /// (enforced in `zsign-core`'s signing context; the C++ upstream
    /// instead emits an empty-dict slot, which this port deliberately
    /// does not reproduce).
    fn sign_binary(
        &self,
        root: &Path,
        binary_path: &Path,
        identifier: &str,
        code_resources: Option<&[u8]>,
        entitlements: Option<&[u8]>,
    ) -> Result<()> {
        let validated = Self::resolve_within(root, binary_path)?;
        let binary_path = validated.as_path();
        let binary_data = fs::read(binary_path)?;
        let executable_probe = MachOFile::parse(binary_data.clone())?;
        let is_executable = executable_probe
            .slices()
            .first()
            .map(|s| s.is_executable)
            .unwrap_or(false);

        // Refuse to sign encrypted binaries before any on-disk mutation
        // (dylib injection below rewrites the file first). executable_probe
        // holds the same original bytes parsed at the top of the function.
        if !self.allow_encrypted {
            for slice in executable_probe.slices() {
                if slice.is_encrypted() {
                    return Err(self.encrypted_error(
                        &binary_path.display().to_string(),
                        identifier,
                        slice,
                    ));
                }
            }
        }

        // Dylib injection applies to executables, before they are signed.
        let mut binary_data = binary_data;
        if !self.dylibs.is_empty() && is_executable {
            for name in &self.dylibs {
                binary_data = zsign_core::macho::writer::inject_dylib_command(
                    &binary_data,
                    name,
                    self.weak_dylibs,
                )?;
            }
            fs::write(binary_path, &binary_data)?;
        }
        let macho = MachOFile::parse(binary_data)?;

        // Only the main executable gets Info.plist in its CodeDirectory.
        // The Info.plist hash arrives with the bundle's CodeResources,
        // which only the main-executable path receives.
        let info_data = if is_executable && code_resources.is_some() {
            let bundle_path = binary_path.parent().ok_or_else(|| {
                Error::Core(zsign_core::Error::Signing(
                    "Binary has no parent directory".into(),
                ))
            })?;
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
                        self.allow_encrypted,
                    )?
                } else {
                    sign_any_macho(
                        &macho,
                        identifier,
                        entitlements,
                        creds,
                        info_data.as_deref(),
                        code_resources,
                        self.allow_encrypted,
                    )?
                }
            }
            None => crate::macho::sign_macho_adhoc(
                &macho,
                identifier,
                entitlements,
                info_data.as_deref(),
                code_resources,
                self.allow_encrypted,
            )?,
        };

        fs::write(binary_path, signed_binary)?;

        Ok(())
    }

    /// Builds a path-qualified EncryptedBinary error for one slice.
    fn encrypted_error(
        &self,
        path: &str,
        identifier: &str,
        slice: &zsign_core::macho::ArchSlice,
    ) -> Error {
        let enc = slice
            .encryption
            .as_ref()
            .expect("is_encrypted() implies encryption is Some");
        Error::Core(zsign_core::Error::EncryptedBinary(format!(
            "{path}: identifier \"{identifier}\", cpu 0x{:x}: cryptid={}, cryptoff=0x{:x}, cryptsize=0x{:x}: decrypt the binary first (frida-ios-dump / bagbak / Clutch / bfdecrypt), then re-sign. Pass allow_encrypted(true) / -f/--force to override.",
            slice.cpu_type, enc.cryptid, enc.cryptoff, enc.cryptsize
        )))
    }

    /// Generate CodeResources plist for the bundle.
    fn generate_code_resources(&self, bundle_path: &Path) -> Result<()> {
        let code_resources = CodeResourcesBuilder::new(bundle_path)?.scan()?.build()?;

        let codesig_dir = Self::resolve_relative(bundle_path, "_CodeSignature")?;
        fs::create_dir_all(&codesig_dir)?;

        let resources_path = Self::resolve_relative(bundle_path, "_CodeSignature/CodeResources")?;
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
    use zip::{ZipArchive, ZipWriter};

    #[test]
    fn test_ipa_signing_is_deterministic() {
        let temp_dir = TempDir::new().unwrap();
        let ipa_path = create_test_ipa(temp_dir.path());
        let credentials = crate::test_util::test_credentials();

        let out_a = temp_dir.path().join("a.ipa");
        let out_b = temp_dir.path().join("b.ipa");
        IpaSigner::new(&credentials)
            .sign(&ipa_path, &out_a)
            .unwrap();
        IpaSigner::new(&credentials)
            .sign(&ipa_path, &out_b)
            .unwrap();

        assert_eq!(
            fs::read(&out_a).unwrap(),
            fs::read(&out_b).unwrap(),
            "re-signing the same IPA must produce byte-identical output"
        );
    }

    #[test]
    fn test_sign_preserves_non_payload_entries() {
        let temp = TempDir::new().unwrap();
        let ipa_path = write_test_ipa(
            &temp.path().join("test.ipa"),
            &[
                (
                    "SwiftSupport/iphoneos/libswiftCore.dylib",
                    b"swift-support-bytes".as_slice(),
                ),
                ("iTunesMetadata.plist", b"<plist></plist>".as_slice()),
                (
                    "META-INF/com.apple.ZipMetadata.plist",
                    b"<plist></plist>".as_slice(),
                ),
            ],
        );
        let output = temp.path().join("signed.ipa");
        IpaSigner::new(&crate::test_util::test_credentials())
            .sign(&ipa_path, &output)
            .expect("signing must succeed");

        let file = fs::File::open(&output).unwrap();
        let mut archive = ZipArchive::new(file).unwrap();
        let names: Vec<String> = (0..archive.len())
            .map(|i| archive.by_index(i).unwrap().name().to_string())
            .collect();
        for expected in [
            "Payload/Test.app/Info.plist",
            "Payload/Test.app/data.bin",
            "SwiftSupport/iphoneos/libswiftCore.dylib",
            "iTunesMetadata.plist",
            "META-INF/com.apple.ZipMetadata.plist",
        ] {
            assert!(
                names.iter().any(|n| n == expected),
                "entry {expected} must survive re-signing; got {names:?}"
            );
        }

        let extracted = temp.path().join("extracted");
        extract_ipa(&output, &extracted).unwrap();
        assert!(
            extracted
                .join("SwiftSupport/iphoneos/libswiftCore.dylib")
                .exists(),
            "carried entries must re-extract"
        );
    }

    /// Create a minimal test IPA file.
    fn create_test_ipa(dir: &Path) -> PathBuf {
        write_test_ipa(&dir.join("test.ipa"), &[])
    }

    /// Write a minimal test IPA to `ipa_path`, appending `extras` as extra
    /// root-level entries after the bundle payload.
    fn write_test_ipa(ipa_path: &Path, extras: &[(&str, &[u8])]) -> PathBuf {
        let file = fs::File::create(ipa_path).unwrap();
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

        zip.start_file("Payload/Test.app/data.bin", options)
            .unwrap();
        zip.write_all(&[0xAB; 4096]).unwrap();

        for (name, bytes) in extras {
            zip.start_file(*name, options).unwrap();
            zip.write_all(bytes).unwrap();
        }

        zip.finish().unwrap();

        ipa_path.to_path_buf()
    }

    /// XML for an Info.plist declaring `cf_bundle_executable_entry`
    /// (already XML) as CFBundleExecutable.
    fn info_plist_xml(cf_bundle_executable_entry: &str) -> String {
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>com.test.app</string>
    <key>CFBundleExecutable</key>
    {cf_bundle_executable_entry}
</dict>
</plist>"#
        )
    }

    /// Serializes the tests that mutate the process working directory.
    static CWD_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Build a minimal `.app` folder whose Info.plist declares
    /// `executable_value` as CFBundleExecutable.
    fn create_folder_bundle(dir: &Path, executable_value: &str, write_executable: bool) -> PathBuf {
        let app = dir.join("App.app");
        std::fs::create_dir_all(&app).unwrap();
        std::fs::write(
            app.join("Info.plist"),
            info_plist_xml(&format!("<string>{executable_value}</string>")),
        )
        .unwrap();
        if write_executable {
            std::fs::write(app.join("Test"), crate::test_util::minimal_macho()).unwrap();
        }
        app
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
                let off =
                    u32::from_be_bytes(blob[16 + i * 8..20 + i * 8].try_into().unwrap()) as usize;
                let cms_magic = u32::from_be_bytes(blob[off..off + 4].try_into().unwrap());
                assert_eq!(cms_magic, 0xfade_0b01, "CMS slot must be a blob wrapper");
                saw_cms = true;
            }
        }
        assert!(saw_cms, "SuperBlob must contain a CMS signature");
    }

    #[test]
    fn test_ipa_signer_refuses_encrypted_bundle() {
        let temp_dir = TempDir::new().unwrap();
        let app = temp_dir.path().join("Enc.app");
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
        std::fs::write(app.join("Enc"), crate::test_util::minimal_macho_encrypted()).unwrap();
        std::fs::write(app.join("data.bin"), [0xAB; 2048]).unwrap();

        let credentials = crate::test_util::test_credentials();
        let before = std::fs::read(app.join("Enc")).unwrap();
        let signer =
            IpaSigner::new(&credentials).dylib_injection(vec!["lib.dylib".to_string()], false);
        let err = signer
            .sign_folder_in_place(&app)
            .expect_err("encrypted main executable must refuse");
        let msg = err.to_string();
        assert!(msg.contains("Enc"), "error must name the file: {msg}");
        assert!(msg.contains("cryptid"), "error must show cryptid: {msg}");
        assert!(
            msg.contains("decrypt"),
            "error must tell the user to decrypt: {msg}"
        );
        let after = std::fs::read(app.join("Enc")).unwrap();
        assert_eq!(
            after, before,
            "refused signing must not mutate the encrypted binary"
        );
    }

    #[test]
    fn test_ipa_signer_allow_encrypted_override() {
        let temp_dir = TempDir::new().unwrap();
        let app = temp_dir.path().join("Enc.app");
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
        std::fs::write(app.join("Enc"), crate::test_util::minimal_macho_encrypted()).unwrap();
        std::fs::write(app.join("data.bin"), [0xAB; 2048]).unwrap();

        IpaSigner::new(&crate::test_util::test_credentials())
            .allow_encrypted(true)
            .sign_folder_in_place(&app)
            .expect("allow_encrypted=true must sign");
        assert!(app.join("_CodeSignature/CodeResources").exists());
    }

    #[test]
    fn test_sign_rejects_executable_path_outside_bundle() {
        let temp = TempDir::new().unwrap();
        let outside = temp.path().join("outside_macho");
        std::fs::write(&outside, crate::test_util::minimal_macho()).unwrap();
        let app = create_folder_bundle(temp.path(), "../outside_macho", true);
        let before = std::fs::read(&outside).unwrap();

        let error = IpaSigner::new_adhoc()
            .sign_folder_in_place(&app)
            .expect_err("parent traversal in CFBundleExecutable must be rejected");
        let message = error.to_string();
        assert!(
            message.contains("outside_macho") && message.contains("escapes"),
            "error must name the escaping value: {message}"
        );
        assert_eq!(
            std::fs::read(&outside).unwrap(),
            before,
            "outside file must stay untouched"
        );
    }

    #[test]
    fn test_sign_rejects_absolute_executable_path() {
        let temp = TempDir::new().unwrap();
        let outside = temp.path().join("outside_macho");
        std::fs::write(&outside, crate::test_util::minimal_macho()).unwrap();
        let app = create_folder_bundle(temp.path(), outside.to_str().unwrap(), true);
        let before = std::fs::read(&outside).unwrap();

        let error = IpaSigner::new_adhoc()
            .sign_folder_in_place(&app)
            .expect_err("absolute CFBundleExecutable must be rejected");
        let message = error.to_string();
        assert!(
            message.contains("must be a relative path"),
            "error must reject the absolute value: {message}"
        );
        assert_eq!(
            std::fs::read(&outside).unwrap(),
            before,
            "outside file must stay untouched"
        );
    }

    #[test]
    fn test_sign_rejects_absolute_executable_path_inside_bundle() {
        let temp = TempDir::new().unwrap();
        let in_bundle = temp.path().join("App.app").join("Test");
        let app = create_folder_bundle(temp.path(), in_bundle.to_str().unwrap(), true);

        let error = IpaSigner::new_adhoc()
            .sign_folder_in_place(&app)
            .expect_err("absolute CFBundleExecutable must be rejected even inside the bundle");
        let message = error.to_string();
        assert!(
            message.contains("must be a relative path"),
            "error must reject the absolute value: {message}"
        );
    }

    #[test]
    fn test_sign_rejects_non_string_executable_value() {
        let temp = TempDir::new().unwrap();
        let app = temp.path().join("App.app");
        std::fs::create_dir_all(&app).unwrap();
        std::fs::write(
            app.join("Info.plist"),
            info_plist_xml("<integer>42</integer>"),
        )
        .unwrap();
        std::fs::write(app.join("Test"), crate::test_util::minimal_macho()).unwrap();

        let error = IpaSigner::new_adhoc()
            .sign_folder_in_place(&app)
            .expect_err("a non-string CFBundleExecutable must be rejected");
        let message = error.to_string();
        assert!(
            message.contains("CFBundleExecutable") && message.contains("must be a string"),
            "error must name the wrong-typed value: {message}"
        );
    }

    #[test]
    fn test_sign_rejects_nonplain_executable_value() {
        let temp = TempDir::new().unwrap();
        let app = create_folder_bundle(temp.path(), "./Test", true);

        let error = IpaSigner::new_adhoc()
            .sign_folder_in_place(&app)
            .expect_err("a non-plain CFBundleExecutable value must be rejected");
        let message = error.to_string();
        assert!(
            message.contains("not a plain relative path"),
            "error must name the spelling problem: {message}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_sign_rejects_symlinked_main_executable() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().unwrap();
        let app = create_folder_bundle(temp.path(), "Test", false);
        let real = app.join("RealTest");
        std::fs::write(&real, crate::test_util::minimal_macho()).unwrap();
        // Flattened versioned-framework layout: the declared executable
        // is the root link, RealTest the real binary.
        symlink(&real, app.join("Test")).unwrap();
        let before = std::fs::read(&real).unwrap();

        let error = IpaSigner::new_adhoc()
            .sign_folder_in_place(&app)
            .expect_err("a symlinked main executable must be rejected");
        let message = error.to_string();
        assert!(
            message.contains("Pre-existing symlink"),
            "error must name the cause: {message}"
        );
        assert_eq!(
            std::fs::read(&real).unwrap(),
            before,
            "the symlink target must stay untouched"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_sign_errors_on_unreadable_path_component() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new().unwrap();
        let app = create_folder_bundle(temp.path(), "locked/tool", true);
        let locked = app.join("locked");
        std::fs::create_dir_all(&locked).unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();

        // Environments that bypass DAC checks (e.g. running as root) cannot
        // exercise the metadata-error arm; skip the assertions there.
        match std::fs::metadata(locked.join("tool")) {
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {}
            _ => {
                std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();
                return;
            }
        }

        let result = IpaSigner::new_adhoc().sign_folder_in_place(&app);
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();

        let error = result.expect_err("an unreadable path component must be a hard error");
        let message = error.to_string();
        assert!(
            message.contains("Failed to inspect signing path"),
            "error must surface the metadata failure: {message}"
        );
    }

    #[test]
    fn test_sign_rejects_root_shaped_value_with_relative_root() {
        let _guard = CWD_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let temp = TempDir::new().unwrap();
        let app = create_folder_bundle(temp.path(), "App.app/Test", true);
        let before = std::fs::read(app.join("Test")).unwrap();
        let previous = std::env::current_dir().unwrap();
        std::env::set_current_dir(temp.path()).unwrap();
        let result = IpaSigner::new_adhoc().sign_folder_in_place("App.app");
        std::env::set_current_dir(previous).unwrap();

        let error =
            result.expect_err("a root-relative CFBundleExecutable must not strip the root prefix");
        let message = error.to_string();
        assert!(
            message.contains("App.app/Test") && message.contains("not an existing regular file"),
            "error must name the misresolved target: {message}"
        );
        assert_eq!(
            std::fs::read(app.join("Test")).unwrap(),
            before,
            "nothing may be signed when the declared target does not resolve"
        );
    }

    #[test]
    fn test_sign_rejects_nonplain_value_under_dot_root() {
        let _guard = CWD_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let temp = TempDir::new().unwrap();
        std::fs::write(
            temp.path().join("Info.plist"),
            info_plist_xml("<string>./Test</string>"),
        )
        .unwrap();
        std::fs::write(temp.path().join("Test"), crate::test_util::minimal_macho()).unwrap();
        let previous = std::env::current_dir().unwrap();
        std::env::set_current_dir(temp.path()).unwrap();
        let result = IpaSigner::new_adhoc().sign_folder_in_place(".");
        std::env::set_current_dir(previous).unwrap();

        let error = result.expect_err("a '.'-spelled CFBundleExecutable must be rejected");
        let message = error.to_string();
        assert!(
            message.contains("not a plain relative path"),
            "error must name the spelling problem: {message}"
        );
    }

    #[test]
    fn test_sign_tolerates_missing_executable_key() {
        let temp = TempDir::new().unwrap();
        let app = temp.path().join("App.app");
        std::fs::create_dir_all(&app).unwrap();
        std::fs::write(
            app.join("Info.plist"),
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>com.test.app</string>
</dict>
</plist>"#,
        )
        .unwrap();
        // Named after the bundle's file stem so the fallback target is the
        // file that actually gets signed.
        std::fs::write(app.join("App"), crate::test_util::minimal_macho()).unwrap();

        IpaSigner::new(&crate::test_util::test_credentials())
            .sign_folder_in_place(&app)
            .expect("key-absent bundle must still sign via the file-stem fallback");
        assert!(
            app.join("_CodeSignature/CodeResources").exists(),
            "signing must complete through the fallback path"
        );
    }
    #[cfg(unix)]
    #[test]
    fn test_symlinked_dylib_is_skipped_and_target_untouched() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().unwrap();
        let outside = temp.path().join("outside.dylib");
        std::fs::write(&outside, crate::test_util::minimal_macho()).unwrap();
        let app = create_folder_bundle(temp.path(), "Test", true);
        std::fs::write(app.join("real.dylib"), crate::test_util::minimal_macho()).unwrap();
        let link = app.join("lib.dylib");
        symlink(&outside, &link).unwrap();
        let before = std::fs::read(&outside).unwrap();

        let signer = IpaSigner::new_adhoc();
        let dylibs = signer.find_standalone_dylibs(&app).unwrap();
        assert!(
            dylibs.contains(&app.join("real.dylib")),
            "a real dylib must still be discovered: {dylibs:?}"
        );
        assert!(
            !dylibs.contains(&link),
            "a symlinked dylib must not be discovered: {dylibs:?}"
        );
        let processed: std::collections::HashSet<_> = dylibs.iter().cloned().collect();
        let binaries = signer
            .find_immediate_macho_binaries(&app, &processed)
            .unwrap();
        assert!(
            !binaries.contains(&link),
            "a symlinked dylib must not be a signing target: {binaries:?}"
        );
        assert!(
            !binaries.contains(&app.join("real.dylib")),
            "a standalone-signed dylib must not be re-offered by the immediate walk: {binaries:?}"
        );

        IpaSigner::new(&crate::test_util::test_credentials())
            .sign_folder_in_place(&app)
            .unwrap();
        assert_eq!(
            std::fs::read(&outside).unwrap(),
            before,
            "external dylib target must stay untouched"
        );
    }

    #[test]
    fn test_standalone_dylib_signed_exactly_once() {
        use zsign_core::codesign::verify::parse_superblob;

        let temp = TempDir::new().unwrap();
        let app = create_folder_bundle(temp.path(), "Test", true);
        std::fs::create_dir_all(app.join("Frameworks")).unwrap();
        std::fs::write(
            app.join("Frameworks").join("libfoo.dylib"),
            crate::test_util::minimal_dylib(),
        )
        .unwrap();

        let creds = crate::test_util::test_credentials();
        IpaSigner::new(&creds)
            .sign_folder_in_place(&app)
            .expect("folder containing a Frameworks dylib must sign");

        let data = std::fs::read(app.join("Frameworks").join("libfoo.dylib")).unwrap();
        let m = crate::macho::MachOFile::parse(data.clone()).unwrap();
        let sl = &m.slices()[0];
        let sig_off = sl.code_sig_offset.unwrap() as usize;
        let sig_len = sl.code_sig_size.unwrap() as usize;
        let sb = parse_superblob(&data[sig_off..sig_off + sig_len]).unwrap();
        let cd = sb
            .code_directory
            .as_ref()
            .expect("primary CodeDirectory must be present");

        assert_eq!(
            cd.identifier(),
            Some("libfoo"),
            "the standalone pass's file-stem identifier must be the on-disk identifier"
        );
        assert!(
            sb.entries.iter().any(|e| e.slot == 0x1000),
            "the standalone pass's dual code directories must survive: a second \
             sha256-only pass over the same file would leave a single SHA-256 CD"
        );
        assert!(
            sb.entries.iter().all(|e| e.slot != 0x0005),
            "no entitlements blob may be applied to a dylib"
        );

        // Per-binary pins, one level up from verify_signed_binary_round_trip
        // (macho/verify.rs:948-980): identity-signed output is anchor-gated, so
        // "sign→verify passes" = each binary's ONLY failure is the anchor
        // message, with signed + pages Matched + cms signature/message_digest/
        // cdhash/chain each ok — any structural defect (pages, slots, sealing)
        // would add a second error or flip these pins. No report-level
        // valid() assertion (supervisor AMEND refinement); bundle-level pins
        // stay structural: no bundle errors and a sealed CodeResources.
        let report = crate::verify::verify_bundle(&app).expect("verify must run");
        let bundle = report.bundle.as_ref().expect("bundle verification");
        assert!(
            bundle.errors.is_empty(),
            "bundle-level errors must be empty: {:?}",
            bundle.errors
        );
        let cr = bundle
            .code_resources
            .as_ref()
            .expect("bundle CodeResources verification");
        assert!(
            cr.valid(),
            "sealed CodeResources must verify: mismatched={:?} missing={:?} unsealed={:?}",
            cr.mismatched,
            cr.missing,
            cr.unsealed
        );
        for binary in &bundle.binaries {
            let slice = &binary
                .report
                .as_ref()
                .unwrap_or_else(|| panic!("Mach-O report for {}", binary.path))
                .slices[0];
            assert!(
                slice.signed,
                "{}: output must carry a signature",
                binary.path
            );
            assert!(
                !slice.adhoc,
                "{}: credential-signed output must not be ad-hoc",
                binary.path
            );
            assert_eq!(
                slice.pages,
                zsign_core::codesign::verify::PageCheck::Matched,
                "{}: page hashes must match",
                binary.path
            );
            assert_eq!(
                slice.errors.len(),
                1,
                "{}: only the anchor gate may fail, got {:?}",
                binary.path,
                slice.errors
            );
            assert!(
                slice.errors[0].contains("not anchored to a trusted root"),
                "{}: unexpected gate: {}",
                binary.path,
                slice.errors[0]
            );
            let cms = slice.cms.as_ref().expect("CMS report");
            assert!(
                cms.signature_ok
                    && cms.message_digest_ok
                    && cms.cdhash_v1_ok
                    && cms.cdhash_v2_ok
                    && cms.chain_ok,
                "{}: cms: {cms:?}",
                binary.path
            );
            assert!(
                !cms.anchored,
                "{}: not anchored without an injected root",
                binary.path
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn test_symlinked_framework_is_not_collected_and_target_untouched() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().unwrap();
        let evil = temp.path().join("EvilTarget.framework");
        std::fs::create_dir_all(&evil).unwrap();
        std::fs::write(
            evil.join("Info.plist"),
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>com.test.evil</string>
    <key>CFBundleExecutable</key>
    <string>Evil</string>
</dict>
</plist>"#,
        )
        .unwrap();
        std::fs::write(evil.join("Evil"), crate::test_util::minimal_macho()).unwrap();

        let app = create_folder_bundle(temp.path(), "Test", true);
        symlink(&evil, app.join("Evil.framework")).unwrap();
        let before = std::fs::read(evil.join("Evil")).unwrap();

        let bundles = IpaSigner::new_adhoc().collect_nested_bundles(&app).unwrap();
        assert!(
            bundles
                .iter()
                .all(|(path, _)| path != &app.join("Evil.framework")),
            "a symlinked framework must not be collected: {bundles:?}"
        );
        assert!(
            bundles.iter().any(|(path, _)| path == &app),
            "the root bundle must still be collected: {bundles:?}"
        );

        IpaSigner::new(&crate::test_util::test_credentials())
            .sign_folder_in_place(&app)
            .unwrap();
        assert_eq!(
            std::fs::read(evil.join("Evil")).unwrap(),
            before,
            "external framework binary must stay untouched"
        );
        assert!(
            !evil.join("_CodeSignature").exists(),
            "no signature may be written outside the bundle"
        );
    }
    #[cfg(unix)]
    #[test]
    fn test_sign_rejects_symlinked_info_plist_rewrite() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().unwrap();
        let app = create_folder_bundle(temp.path(), "Test", true);
        let outside_plist = temp.path().join("outside.plist");
        std::fs::copy(app.join("Info.plist"), &outside_plist).unwrap();
        std::fs::remove_file(app.join("Info.plist")).unwrap();
        symlink(&outside_plist, app.join("Info.plist")).unwrap();
        let before = std::fs::read(&outside_plist).unwrap();

        let error = IpaSigner::new_adhoc()
            .bundle_id("com.test.changed")
            .sign_folder_in_place(&app)
            .expect_err("a symlinked Info.plist must be rejected before the rewrite");
        let message = error.to_string();
        assert!(
            message.contains("Pre-existing symlink"),
            "error must name the cause: {message}"
        );
        assert_eq!(
            std::fs::read(&outside_plist).unwrap(),
            before,
            "external plist must stay untouched"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_sign_rejects_symlinked_bundle_root() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().unwrap();
        let app = create_folder_bundle(temp.path(), "Test", true);
        let outside = temp.path().join("Outside.app");
        std::fs::rename(&app, &outside).unwrap();
        symlink(&outside, &app).unwrap();
        let before = std::fs::read(outside.join("Test")).unwrap();

        let error = IpaSigner::new_adhoc()
            .sign_folder_in_place(&app)
            .expect_err("a symlinked bundle root must be rejected");
        assert!(
            error.to_string().contains("must not be a symlink"),
            "error must name the cause: {error}"
        );

        let with_slash = format!("{}/", app.display());
        IpaSigner::new_adhoc()
            .sign_folder_in_place(&with_slash)
            .expect_err("a trailing separator must not bypass the root check");

        assert_eq!(
            std::fs::read(outside.join("Test")).unwrap(),
            before,
            "the symlink target must stay untouched"
        );
        assert!(
            !outside.join("_CodeSignature").exists(),
            "no signature may be written outside the bundle"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_sign_trusts_operator_root_ancestors() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().unwrap();
        let real = temp.path().join("real");
        std::fs::create_dir_all(&real).unwrap();
        let app = create_folder_bundle(&real, "Test", true);
        let link = temp.path().join("link");
        symlink(&real, &link).unwrap();
        let through_link = link.join("App.app");

        IpaSigner::new(&crate::test_util::test_credentials())
            .sign_folder_in_place(&through_link)
            .unwrap();
        assert!(
            app.join("_CodeSignature/CodeResources").exists(),
            "writes land at the resolved location of the operator-supplied root"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_sign_rejects_aliased_payload_root() {
        let temp = TempDir::new().unwrap();
        let ipa = temp.path().join("aliased.ipa");

        let file = std::fs::File::create(&ipa).unwrap();
        let mut zip = ZipWriter::new(file);
        let options = SimpleFileOptions::default();
        zip.add_directory("Payload2/", options).unwrap();
        zip.add_directory("Payload2/App.app/", options).unwrap();
        zip.start_file("Payload2/App.app/Info.plist", options)
            .unwrap();
        zip.write_all(info_plist_xml("<string>Test</string>").as_bytes())
            .unwrap();
        zip.start_file("Payload2/App.app/Test", options).unwrap();
        zip.write_all(&crate::test_util::minimal_macho()).unwrap();
        zip.add_symlink("Payload", "Payload2", options).unwrap();
        zip.finish().unwrap();

        let output = temp.path().join("out.ipa");
        let error = IpaSigner::new_adhoc()
            .sign(&ipa, &output)
            .expect_err("an archive-created symlink above the bundle root must be rejected");
        let message = error.to_string();
        assert!(
            message.contains("Pre-existing symlink"),
            "error must name the cause: {message}"
        );
    }

    #[test]
    fn test_sign_rejects_multiple_app_bundles() {
        let temp = TempDir::new().unwrap();
        let ipa_path = temp.path().join("multi.ipa");
        let file = fs::File::create(&ipa_path).unwrap();
        let mut zip = ZipWriter::new(file);
        let options = SimpleFileOptions::default();
        zip.add_directory("Payload/", options).unwrap();
        zip.add_directory("Payload/First.app/", options).unwrap();
        zip.add_directory("Payload/Second.app/", options).unwrap();
        zip.finish().unwrap();

        let output = temp.path().join("signed.ipa");
        let err = IpaSigner::new(&crate::test_util::test_credentials())
            .sign(&ipa_path, &output)
            .expect_err("two .app bundles must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("multiple .app bundles"),
            "actionable message: {msg}"
        );
        assert!(
            msg.contains("First.app") && msg.contains("Second.app"),
            "candidates named: {msg}"
        );
        assert!(
            !output.exists(),
            "no output may be written for an ambiguous archive"
        );
    }
}
