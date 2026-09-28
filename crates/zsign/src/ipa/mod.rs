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
//!       ├── Frameworks/
//!       │   └── *.framework/
//!       └── XPCServices/
//!           └── *.xpc/
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

mod mem_store;
use archive::create_ipa_from_root;
use archive::create_ipa_from_store;
pub use archive::{create_ipa, CompressionLevel};
pub use extract::{extract_ipa, validate_ipa};
use extract::{extract_ipa_into_store, ExtractionLimits};
use mem_store::MemStore;

use crate::bundle::CodeResourcesBuilder;
use crate::crypto::SigningCredentials;
use crate::macho::{sign_any_macho, sign_macho, MachOFile};
use crate::store::{FsStore, Store, StoreKind};
use crate::{Error, Result};
#[cfg(not(target_arch = "wasm32"))]
use rayon::prelude::*;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Component, Path, PathBuf};
use tempfile::TempDir;

/// Provisioning profile bytes and their extracted entitlements.
type ProfilePayload = (Option<Vec<u8>>, Option<Vec<u8>>);

/// One entry of the read-only signing plan: the bundle path, the entitlements
/// resolved for it, and the profile bytes to embed (absent when it resolves none).
type BundlePlan = (PathBuf, Option<Vec<u8>>, Option<Vec<u8>>);

/// Rewrites `value` when it IS the old id or a sub-id of it
/// (`old.<suffix>`); never a bare substring (com.a must not match com.ab).
fn replace_id_prefix(value: &str, old: &str, new: &str) -> Option<String> {
    if value == old {
        return Some(new.to_string());
    }
    let rest = value.strip_prefix(old)?.strip_prefix('.')?;
    Some(format!("{new}.{rest}"))
}

/// `replace_id_prefix` on a present top-level string key; returns whether
/// it rewrote.
fn rewrite_string_key(dict: &mut plist::Dictionary, key: &str, old: &str, new: &str) -> bool {
    let Some(current) = dict.get(key).and_then(|v| v.as_string()).map(str::to_owned) else {
        return false;
    };
    match replace_id_prefix(&current, old, new) {
        Some(rewritten) => {
            dict.insert(key.to_string(), plist::Value::String(rewritten));
            true
        }
        None => false,
    }
}

/// Aligns signature entitlements with a changed bundle id (design §3.5
/// stage 2). Keys outside the documented rewrite set — including
/// `com.apple.security.application-groups` — are byte-preserved; bundles
/// with no entitlements never reach here and none are invented.
fn rewrite_entitlements_for_id(
    ents: &[u8],
    old_id: &str,
    new_id: &str,
    prefix: Option<&str>,
    drop_get_task_allow: bool,
) -> Result<Vec<u8>> {
    let mut value: plist::Value = plist::from_bytes(ents).map_err(|e| {
        Error::Core(zsign_core::Error::Config(format!(
            "resolved entitlements are not a valid plist: {e}"
        )))
    })?;
    let dict = value.as_dictionary_mut().ok_or_else(|| {
        Error::Core(zsign_core::Error::Config(
            "resolved entitlements must be a dictionary".into(),
        ))
    })?;
    // iOS uses `application-identifier`, macOS the legacy
    // `com.apple.application-identifier`. Only a key that is already present is
    // rewritten, and it is rewritten under its OWN name — creating the
    // canonical key for a legacy-only profile is out of scope.
    let app_id_key = if dict.contains_key("application-identifier") {
        "application-identifier"
    } else if dict.contains_key("com.apple.application-identifier") {
        "com.apple.application-identifier"
    } else {
        ""
    };
    let existing_prefix = dict
        .get(app_id_key)
        .and_then(|v| v.as_string())
        .and_then(|s| s.split('.').next())
        .map(str::to_owned);
    if !app_id_key.is_empty() {
        if let Some(prefix) = prefix.map(str::to_owned).or(existing_prefix) {
            dict.insert(
                app_id_key.to_string(),
                plist::Value::String(format!("{prefix}.{new_id}")),
            );
            if let Some(groups) = dict
                .get_mut("keychain-access-groups")
                .and_then(|v| v.as_array_mut())
            {
                for group in groups.iter_mut() {
                    let Some(text) = group.as_string().map(str::to_owned) else {
                        continue;
                    };
                    let Some(dot) = text.find('.') else {
                        continue;
                    };
                    let suffix = &text[dot + 1..];
                    let suffix = replace_id_prefix(suffix, old_id, new_id)
                        .unwrap_or_else(|| suffix.to_owned());
                    *group = plist::Value::String(format!("{prefix}.{suffix}"));
                }
            }
        }
    }
    if drop_get_task_allow {
        dict.remove("get-task-allow");
    }
    let mut buf = Vec::new();
    plist::to_writer_xml(&mut buf, &value).map_err(|e| {
        Error::Core(zsign_core::Error::Config(format!(
            "failed to serialize rewritten entitlements: {e}"
        )))
    })?;
    Ok(buf)
}

/// App-ID prefix chain (design §3.5/D7): own profile's Entitlements app-id
/// prefix, then the root profile's, then either profile's
/// `TeamIdentifier[0]`, then `None` (transform falls back to the resolved
/// entitlements' own prefix). Never assumes prefix == TeamID (TN2415:461).
fn app_id_prefix(own: Option<&[u8]>, root: Option<&[u8]>) -> Option<String> {
    fn document(profile: &[u8]) -> Option<plist::Value> {
        zsign_core::provisioning::profile_document(profile).ok()
    }
    for profile in own.iter().chain(root.iter()) {
        let Some(doc) = document(profile) else {
            continue;
        };
        let app_id = doc
            .as_dictionary()
            .and_then(|d| d.get("Entitlements"))
            // plist 1.7 has no `Value::get`, so the nested dict is taken first.
            .and_then(|e| e.as_dictionary())
            .and_then(|d| {
                d.get("application-identifier")
                    .or_else(|| d.get("com.apple.application-identifier"))
            })
            .and_then(|v| v.as_string())
            .and_then(|s| s.split('.').next())
            .map(str::to_owned);
        if app_id.is_some() {
            return app_id;
        }
    }
    for profile in own.iter().chain(root.iter()) {
        let Some(doc) = document(profile) else {
            continue;
        };
        let team = doc
            .as_dictionary()
            .and_then(|d| d.get("TeamIdentifier"))
            .and_then(|v| v.as_array())
            .and_then(|a| a.first())
            .and_then(|v| v.as_string())
            .map(str::to_owned);
        if team.is_some() {
            return team;
        }
    }
    None
}

/// Distribution detection (design D7): a resolved profile that lacks
/// `ProvisionedDevices`. No resolved profile ⇒ never drop get-task-allow.
fn profile_is_distribution(profile_data: Option<&[u8]>) -> bool {
    let Some(profile) = profile_data else {
        return false;
    };
    match zsign_core::provisioning::profile_document(profile) {
        Ok(doc) => doc
            .as_dictionary()
            .is_some_and(|d| !d.contains_key("ProvisionedDevices")),
        Err(_) => false,
    }
}

/// Where a blob input comes from: a native path (resolved at the same flow
/// point as today) or caller-provided bytes (wasm surface, no IO).
enum BlobSource {
    Path(PathBuf),
    Bytes(Vec<u8>),
}

/// Label naming the bytes form in a validation rejection: there is no file to
/// name, but the message must still say where the offending bytes came from.
const IN_MEMORY_ENTS: &str = "<in-memory entitlements>";

/// Reads and validates a blob input. `Ok(None)` when no source is set.
///
/// The `Path` arm keeps the native flow exactly as it is — the read, its
/// wrapped I/O error, and the shared validation — so plan-build error timing
/// and text are unchanged. The `Bytes` arm performs no IO and runs the same
/// three checks over the supplied bytes.
fn read_entitlements(source: Option<&BlobSource>) -> Result<Option<Vec<u8>>> {
    let Some(source) = source else {
        return Ok(None);
    };
    match source {
        BlobSource::Path(path) => crate::builder::read_entitlements_file(Some(path)),
        BlobSource::Bytes(data) => {
            crate::builder::validate_entitlements_blob(data, Path::new(IN_MEMORY_ENTS))?;
            Ok(Some(data.clone()))
        }
    }
}

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
/// 3. Resolve each bundle's entitlements and embed the provisioning profile
///    it resolved (the root profile, or a `--profile-map` entry for a nested
///    bundle), if any
/// 4. Generate `_CodeSignature/CodeResources`
/// 5. Repack the extraction root via `create_ipa_from_root` (keeps
///    non-`Payload` entries such as `SwiftSupport/` and `iTunesMetadata.plist`)
///
/// For manual control over extraction/repacking, use [`extract_ipa`] and
/// [`create_ipa`] directly.
pub struct IpaSigner<'a> {
    /// Reference to signing credentials; `None` signs ad-hoc
    credentials: Option<&'a SigningCredentials>,
    /// Compression level for output IPA
    compression_level: CompressionLevel,
    /// Provisioning profile to embed as embedded.mobileprovision
    provisioning_profile: Option<BlobSource>,
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
    /// Custom entitlements replacing the profile-derived entitlements
    entitlements_override: Option<BlobSource>,
    /// Directory of per-bundle-id entitlements files, applied per bundle
    entitlements_dir: Option<PathBuf>,
    /// Per-nested-bundle provisioning profiles keyed by bundle id
    bundle_profiles: Vec<(String, PathBuf)>,
    /// Strip `embedded.mobileprovision` from every bundle before sealing
    remove_embedded_profile: bool,
    /// Skip CMS/expiry/team/App-ID validation of provisioning profiles (explicit opt-in)
    allow_unsafe_profile: bool,
    /// Injected trust anchors for profile CMS verification; `None` anchors to Apple's root
    profile_anchors: Option<zsign_core::crypto::cms_verify::TrustAnchors>,
    /// Explicit verification instant for profile validation; `None` uses the wall
    /// clock on native and errors on wasm32
    profile_now: Option<time::OffsetDateTime>,
}

/// Two-byte `PK` check over an IPA held in memory, the bytes analogue of
/// [`validate_ipa`]: the path-existence branch has no bytes form, so only
/// the magic check is reproduced.
fn validate_ipa_bytes(input: &[u8]) -> Result<()> {
    let mut magic = [0u8; 4];
    let mut reader = input;
    std::io::Read::read_exact(&mut reader, &mut magic)?;

    // ZIP magic: PK\x03\x04 or PK\x05\x06 (empty) or PK\x07\x08 (spanned)
    if &magic[0..2] != b"PK" {
        return Err(Error::Zip(zip::result::ZipError::InvalidArchive(
            std::borrow::Cow::Borrowed("Not a valid ZIP/IPA file"),
        )));
    }

    Ok(())
}

impl ExtractionLimits {
    /// Browser-oriented caps for the in-memory bytes pipeline: 512 MiB per
    /// entry, 2 GiB total — matching the whole-IPA input cap the wasm
    /// surface enforces before the call. The native [`ExtractionLimits::
    /// Default`] is deliberately wider and stays unchanged; these are
    /// tighter for a wasm32 heap.
    fn wasm_default() -> Self {
        ExtractionLimits {
            max_entry_bytes: 512 * 1024 * 1024,
            max_total_bytes: 2 * 1024 * 1024 * 1024,
        }
    }
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
            provisioning_profile: None,
            bundle_id: None,
            bundle_name: None,
            bundle_version: None,
            sha256_only: true,
            dylibs: Vec::new(),
            weak_dylibs: false,
            allow_encrypted: false,
            entitlements_override: None,
            entitlements_dir: None,
            bundle_profiles: Vec::new(),
            remove_embedded_profile: false,
            allow_unsafe_profile: false,
            profile_anchors: None,
            profile_now: None,
        }
    }

    /// Creates an ad-hoc signer (no certificate or private key).
    pub fn new_adhoc() -> Self {
        Self {
            credentials: None,
            compression_level: CompressionLevel::DEFAULT,
            provisioning_profile: None,
            bundle_id: None,
            bundle_name: None,
            bundle_version: None,
            sha256_only: true,
            dylibs: Vec::new(),
            weak_dylibs: false,
            allow_encrypted: false,
            entitlements_override: None,
            entitlements_dir: None,
            bundle_profiles: Vec::new(),
            remove_embedded_profile: false,
            allow_unsafe_profile: false,
            profile_anchors: None,
            profile_now: None,
        }
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
    pub fn remove_embedded_profile(mut self, remove: bool) -> Self {
        self.remove_embedded_profile = remove;
        self
    }

    /// Skips CMS, expiry, team and App-ID validation of every provisioning
    /// profile this signer loads.
    ///
    /// Profiles are validated by default; the opt-in falls back to the
    /// historical raw byte scan, so a forged, expired or foreign profile is
    /// signed and embedded verbatim. Only useful for fixtures and for
    /// re-signing flows that install where validation is bypassed.
    pub fn allow_unsafe_profile(mut self, allow: bool) -> Self {
        self.allow_unsafe_profile = allow;
        self
    }

    /// Anchors profile CMS verification to the given trust anchors instead of
    /// Apple's roots.
    ///
    /// The default (`None`) verifies against the Apple root store; injected
    /// anchors exist for test fixtures signed by a private root.
    pub fn profile_anchors(
        mut self,
        anchors: zsign_core::crypto::cms_verify::TrustAnchors,
    ) -> Self {
        self.profile_anchors = Some(anchors);
        self
    }

    /// Sets the instant used as "now" when validating provisioning profiles.
    ///
    /// The default (`None`) uses the wall clock on native targets and fails
    /// validation on wasm32, where no clock is available.
    pub fn profile_now(mut self, now: time::OffsetDateTime) -> Self {
        self.profile_now = Some(now);
        self
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
        self.provisioning_profile = Some(BlobSource::Path(path.as_ref().to_path_buf()));
        self
    }

    /// Uses the given provisioning profile bytes instead of reading a path.
    /// The bytes are validated during plan build, mirroring the path form.
    pub fn provisioning_profile_bytes(mut self, data: Vec<u8>) -> Self {
        self.provisioning_profile = Some(BlobSource::Bytes(data));
        self
    }

    /// Sets a custom entitlements file.
    ///
    /// The file must be an XML or binary plist with a top-level dictionary
    /// whose values the signer can encode to DER; it replaces the
    /// entitlements extracted from the provisioning profile and applies only
    /// to the root app bundle. A rejected file fails the sign.
    pub fn entitlements(mut self, path: impl AsRef<Path>) -> Self {
        self.entitlements_override = Some(BlobSource::Path(path.as_ref().to_path_buf()));
        self
    }

    /// Uses the given entitlements bytes instead of reading a file. They are
    /// validated exactly like the path form — XML-or-binary plist,
    /// dictionary root, DER-encodable values — during plan build, so a
    /// rejected blob fails the sign.
    pub fn entitlements_bytes(mut self, data: Vec<u8>) -> Self {
        self.entitlements_override = Some(BlobSource::Bytes(data));
        self
    }

    /// Sets a directory of per-bundle-id entitlements files.
    ///
    /// For every bundle the file `<dir>/<bundle-id>.plist` — for the root, the
    /// id *after* any [`Self::bundle_id`] rewrite — replaces that bundle's
    /// profile-derived entitlements. A missing *entry* falls back to the
    /// profile, but a symlinked entry is refused and a configured directory
    /// that does not exist is a hard error, so a typo cannot silently sign
    /// with the profile's entitlements. An entry that exists but is invalid
    /// also fails the sign. For a bundle with a [`Self::bundle_profiles`] entry
    /// the directory still wins; for the root, [`Self::entitlements`] wins over
    /// both. The file override applies to the root bundle only.
    pub fn entitlements_dir(mut self, dir: impl AsRef<Path>) -> Self {
        self.entitlements_dir = Some(dir.as_ref().to_path_buf());
        self
    }

    /// Replaces the nested-bundle provisioning profiles with `(bundle-id, path)`
    /// pairs.
    ///
    /// Each key must match a nested bundle's `CFBundleIdentifier` exactly; the
    /// matched profile is embedded as that bundle's `embedded.mobileprovision`
    /// and its extracted entitlements are signed into that bundle. A key that
    /// matches no bundle, a duplicate key, or the root bundle's own id is an
    /// error — the root profile belongs in [`Self::provisioning_profile`].
    /// For a nested bundle, [`Self::entitlements_dir`] beats the mapped
    /// profile's derived entitlements.
    /// Not consulted when signing a bare Mach-O, which has no bundle identity.
    pub fn bundle_profiles(mut self, profiles: Vec<(String, PathBuf)>) -> Self {
        self.bundle_profiles = profiles;
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
        let store = FsStore;
        // Components between the extraction root and the bundle root come
        // from the archive: none of them may be a symlink.
        Self::resolve_within(&store, temp_dir.path(), &app_bundle)?;
        Self::ensure_single_app_bundle(&store, &temp_dir.path().join("Payload"))?;
        self.sign_bundle_from_options(&store, &app_bundle)?;

        create_ipa_from_root(temp_dir.path(), output_ipa, self.compression_level)?;

        Ok(())
    }

    /// Signs a complete IPA held in memory and returns the signed IPA
    /// bytes. Same stages as [`Self::sign`], running over an in-memory
    /// store: no filesystem access, deterministic output.
    ///
    /// Limits: input ≤ 512 MiB (enforced by the wasm surface), declared
    /// per-entry uncompressed ≤ 512 MiB and total ≤ 2 GiB (enforced here).
    pub fn sign_ipa_bytes(&self, input: &[u8]) -> Result<Vec<u8>> {
        validate_ipa_bytes(input)?;

        let store = MemStore::new();
        let app_bundle = extract_ipa_into_store(
            std::io::Cursor::new(input),
            &store,
            Path::new(""),
            ExtractionLimits::wasm_default(),
        )?;
        Self::resolve_within(&store, Path::new(""), &app_bundle)?;
        Self::ensure_single_app_bundle(&store, Path::new("Payload"))?;
        self.sign_bundle_from_options(&store, &app_bundle)?;

        create_ipa_from_store(&store, Path::new(""), self.compression_level)
    }

    /// The validation request both profile loaders share, targeting the given
    /// bundle id.
    fn profile_request(&self, target_bundle_id: Option<String>) -> zsign_core::ProfileRequest {
        zsign_core::ProfileRequest {
            now: self.profile_now,
            anchors: self.profile_anchors.clone(),
            expected_team_id: self.credentials.and_then(|c| c.team_id.clone()),
            target_bundle_id,
            target_device_udid: None,
        }
    }

    /// Loads the provisioning profile and its entitlements, validating it
    /// against `root_id` — the bundle's post-rewrite identifier.
    fn load_profile(&self, root_id: &str) -> Result<ProfilePayload> {
        let request = self.profile_request(Some(root_id.to_string()));
        match &self.provisioning_profile {
            Some(BlobSource::Path(path)) => {
                let data = crate::builder::read_profile_file(path, None)?;
                let ent = zsign_core::extract_entitlements_checked(
                    &data,
                    &request,
                    self.allow_unsafe_profile,
                )
                .map_err(|e| crate::builder::profile_validation_error(e, path, None))?;
                Ok((Some(data), ent))
            }
            Some(BlobSource::Bytes(data)) => {
                let ent = zsign_core::extract_entitlements_checked(
                    data,
                    &request,
                    self.allow_unsafe_profile,
                )?;
                Ok((Some(data.clone()), ent))
            }
            None => Ok((None, None)),
        }
    }

    /// Loads the exact-key nested-profile map. Root-id keys are rejected (the
    /// root profile belongs in `provisioning_profile`), as are ids that could
    /// escape the precedence lookup; every entry's bytes + derived
    /// entitlements load during plan build, before the first sign write.
    fn load_bundle_profiles(&self, root_id: &str) -> Result<HashMap<String, ProfilePayload>> {
        let mut map = HashMap::new();
        for (id, path) in &self.bundle_profiles {
            if id.is_empty()
                || id.contains('/')
                || id.contains('\\')
                || id.contains('\0')
                || id.contains("..")
            {
                return Err(Error::Core(zsign_core::Error::Config(format!(
                    "invalid bundle id '{id}' in provisioning profile map"
                ))));
            }
            if id == root_id {
                return Err(Error::Core(zsign_core::Error::Config(format!(
                    "profile map key '{id}' is the main bundle; the root profile belongs in --profile"
                ))));
            }
            if map.contains_key(id) {
                return Err(Error::Core(zsign_core::Error::Config(format!(
                    "duplicate profile map key '{id}'"
                ))));
            }
            let data = crate::builder::read_profile_file(path, Some(id))?;
            // Bare propagation would report only "No XML plist found in profile
            // data", which cannot say which entry of a multi-entry map is at
            // fault. The shared wrap adds that context while keeping the class
            // the validator produced, so a malformed profile, a failed CMS
            // verification, and a size rejection stay distinguishable.
            let request = self.profile_request(Some(id.clone()));
            let ent = zsign_core::extract_entitlements_checked(
                &data,
                &request,
                self.allow_unsafe_profile,
            )
            .map_err(|e| crate::builder::profile_validation_error(e, path, Some(id)))?;
            map.insert(id.clone(), (Some(data), ent));
        }
        Ok(map)
    }

    /// Reads and validates the custom entitlements, if one is set.
    fn load_entitlements_override(&self) -> Result<Option<Vec<u8>>> {
        read_entitlements(self.entitlements_override.as_ref())
    }

    /// Exact-key entitlements directory hit: `<dir>/<bundle-id>.plist`.
    ///
    /// `Ok(None)` means "no hit, fall back to the profile": no directory
    /// configured, a bundle id whose file name carries a prefix / root / parent
    /// component (a malformed identity must never read a file through the
    /// directory — this is the escape, and on Windows `join` would clear the
    /// base for a drive-prefixed id), or a non-regular entry. A symlinked entry
    /// is refused outright — the resolved path must stay inside the directory
    /// (design D4 §3.3), so a planted link cannot get outside bytes signed.
    /// A configured directory that is missing or is not a directory is a hard
    /// error, not a silent fallback.
    fn dir_hit(&self, bundle_id: &str) -> Result<Option<Vec<u8>>> {
        let Some(dir) = &self.entitlements_dir else {
            return Ok(None);
        };
        if !dir.exists() {
            return Err(Error::Core(zsign_core::Error::Config(format!(
                "entitlements directory does not exist: {}",
                dir.display()
            ))));
        }
        if !dir.is_dir() {
            return Err(Error::Core(zsign_core::Error::Config(format!(
                "entitlements directory is not a directory: {}",
                dir.display()
            ))));
        }
        let name = format!("{bundle_id}.plist");
        // Component-based guard, matching this file's own `resolve_relative`:
        // reject any prefix, root or parent component rather than a character
        // blacklist, so no platform's `join` can redirect the lookup.
        if bundle_id.is_empty()
            || Path::new(&name).components().any(|c| {
                matches!(
                    c,
                    std::path::Component::Prefix(_)
                        | std::path::Component::RootDir
                        | std::path::Component::ParentDir
                )
            })
        {
            return Ok(None);
        }
        let path = dir.join(&name);
        // symlink_metadata does NOT follow links, so a planted link is
        // classified here instead of resolving to an outside file.
        match fs::symlink_metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(crate::builder::entitlements_read_error(&path, e)),
            Ok(m) if m.file_type().is_symlink() => Err(Error::Core(zsign_core::Error::Signing(
                format!("Refusing symlinked entitlements file: {}", path.display()),
            ))),
            Ok(m) if !m.is_file() => Ok(None),
            Ok(_) => match crate::builder::read_entitlements_file(Some(&path)) {
                // The entry can vanish between the probe and the read; a miss
                // stays a miss. `Error::Io` preserves the `ErrorKind`.
                Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
                result => result,
            },
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
        self.sign_bundle_from_options(&FsStore, bundle_path)
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

    /// Rejects a symlinked bundle root, then delegates to [`Self::sign_bundle`]
    /// which applies the plist rewrites, resolves the root entitlements, and
    /// signs the bundle tree.
    fn sign_bundle_from_options<S: Store>(&self, store: &S, bundle_path: &Path) -> Result<()> {
        // A trailing separator makes lstat follow a final symlink, so check
        // the component-rebuilt path; ancestors of the root stay trusted.
        let plain_root: PathBuf = bundle_path.components().collect();
        let root_metadata = store.metadata(&plain_root)?;
        if root_metadata.is_symlink() {
            return Err(Error::Core(zsign_core::Error::Signing(format!(
                "Bundle root must not be a symlink: {}",
                bundle_path.display()
            ))));
        }
        self.sign_bundle(store, bundle_path)
    }

    /// Sign an app bundle in place.
    ///
    /// Signs all Mach-O binaries and generates CodeResources.
    ///
    /// The signing workflow:
    /// 1. Apply the requested `Info.plist` rewrites (the only pre-existing
    ///    mutation) — entitlements are keyed by the rewritten bundle id
    /// 2. Collect all bundles (main app, frameworks, plugins) with their depths
    ///    and sort by depth (deepest first)
    /// 3. Build the read-only signing plan: resolve each bundle's entitlements
    ///    and provisioning profile (root profile, `--entitlements` file,
    ///    `--entitlements-dir` entry, or its `--profile-map` entry). Every
    ///    rejection surfaces here, before any binary is written
    /// 4. Sign ALL standalone .dylib files (with empty params)
    /// 5. Sign each bundle in order so nested bundles are fully signed before
    ///    their parent includes them in CodeResources
    ///
    /// For each bundle, the signing order is:
    /// 1. Sign all Mach-O binaries in-place (modifies binary content)
    /// 2. Embed the resolved provisioning profile as
    ///    `embedded.mobileprovision` (whichever bundles resolved one)
    /// 3. Generate CodeResources (hashes all files including signed binaries)
    fn sign_bundle<S: Store>(&self, store: &S, bundle_path: &Path) -> Result<()> {
        // --- read-only resolution: nothing below this line has written yet ---
        let old_root_id = self.get_bundle_identifier(store, bundle_path)?;
        // The root's FINAL id is knowable without writing the plist, so the
        // plan build can key on the post-rewrite id (design §3.5 stage 3).
        let root_id_final = self
            .bundle_id
            .clone()
            .unwrap_or_else(|| old_root_id.clone());

        // `collect_nested_bundles` is a pure read, so it runs before the dylib
        // pass: plan build must precede the first sign write.
        let mut bundles = self.collect_nested_bundles(store, bundle_path)?;
        bundles.sort_by_key(|b| std::cmp::Reverse(b.1));

        // Stage 1 (design §3.5): compute each nested bundle's FINAL id in
        // memory. Nothing is written here; the cascade's writes happen in the
        // requested-rewrite phase below, so an option rejection above leaves
        // every plist byte-untouched.
        let mut id_pairs: HashMap<PathBuf, (String, String)> = HashMap::new();
        if let Some(ref new_root) = self.bundle_id {
            for (path, _depth) in &bundles {
                if path == bundle_path {
                    continue; // root rewritten by the existing requested rewrite
                }
                let old = match self.read_bundle_identifier(store, path) {
                    Some(id) => id,
                    None => continue, // plist-less extension arm: nothing to cascade
                };
                if let Some(new) = replace_id_prefix(&old, &old_root_id, new_root) {
                    id_pairs.insert(path.clone(), (old, new));
                }
            }
        }

        // --- plan build: read-only; every rejection lands here ---
        let (root_profile_data, root_profile_ent) = self.load_profile(&root_id_final)?;
        let root_entitlements = match self.load_entitlements_override()? {
            // The directory is consulted only when the explicit override did
            // not win — §3.2 precedence must not let a losing tier fail the sign.
            Some(override_ents) => Some(override_ents),
            None => self.dir_hit(&root_id_final)?.or(root_profile_ent),
        };
        let profile_map = self.load_bundle_profiles(&root_id_final)?;
        let mut plan: Vec<BundlePlan> = Vec::with_capacity(bundles.len());
        let mut nested_ids: Vec<String> = Vec::new();
        for (path, _depth) in &bundles {
            let (old_id, final_id, mut entitlements, profile_bytes) = if path == bundle_path {
                (
                    old_root_id.clone(),
                    root_id_final.clone(),
                    root_entitlements.clone(),
                    root_profile_data.clone(),
                )
            } else {
                // No pair: a bundle whose id does not follow the old root keeps
                // its own. The tolerant read is deliberately NOT used here —
                // plan build must keep HEAD's semantics, where a plist-less
                // nested bundle is a hard error and a key-less plist falls back
                // to the file stem.
                let final_id = match id_pairs.get(path) {
                    Some((_, new)) => new.clone(),
                    None => self.get_bundle_identifier(store, path)?,
                };
                nested_ids.push(final_id.clone());
                let mapped = profile_map.get(&final_id);
                let old_id = id_pairs
                    .get(path)
                    .map(|(old, _)| old.clone())
                    .unwrap_or_else(|| final_id.clone());
                (
                    old_id,
                    final_id.clone(),
                    self.dir_hit(&final_id)?
                        .or_else(|| mapped.and_then(|(_, ent)| ent.clone())),
                    // `ProfilePayload`'s profile bytes are always `Some` for a
                    // mapped key, so flatten rather than nest an empty option.
                    mapped.and_then(|(data, _)| data.clone()),
                )
            };
            if self.bundle_id.is_some() {
                if let Some(ents) = entitlements.take() {
                    let root_profile = root_profile_data.as_deref();
                    entitlements = Some(rewrite_entitlements_for_id(
                        &ents,
                        &old_id,
                        &final_id,
                        app_id_prefix(profile_bytes.as_deref(), root_profile).as_deref(),
                        profile_is_distribution(profile_bytes.as_deref().or(root_profile)),
                    )?);
                }
            }
            plan.push((path.clone(), entitlements, profile_bytes));
        }
        let mut unused: Vec<&String> = profile_map
            .keys()
            .filter(|key| !nested_ids.iter().any(|id| id == *key))
            .collect();
        if !unused.is_empty() {
            unused.sort();
            nested_ids.sort();
            return Err(Error::Core(zsign_core::Error::Config(format!(
                "provisioning profile map keys matched no bundle: {unused:?}; nested bundle ids: {nested_ids:?}"
            ))));
        }

        // --- requested-rewrite phase: the first writes of this sign. Root
        // first, then nested, so a failure can at worst leave the root
        // rewritten -- the same exposure HEAD has for a broken root. ---
        if let Some(ref new_id) = self.bundle_id {
            self.rewrite_plist_string(store, bundle_path, "CFBundleIdentifier", new_id)?;
        }
        if let Some(ref name) = self.bundle_name {
            self.rewrite_plist_string(store, bundle_path, "CFBundleDisplayName", name)?;
        }
        if let Some(ref version) = self.bundle_version {
            self.rewrite_plist_string(store, bundle_path, "CFBundleShortVersionString", version)?;
        }
        if let Some(ref new_root) = self.bundle_id {
            self.rewrite_nested_identifiers(store, &bundles, bundle_path, &old_root_id, new_root)?;
        }

        let dylibs = self.find_standalone_dylibs(store, bundle_path)?;
        let already_signed: HashSet<PathBuf> = dylibs.iter().cloned().collect();

        // --- only now does anything mutate ---
        #[cfg(not(target_arch = "wasm32"))]
        dylibs.par_iter().try_for_each(|dylib_path| {
            self.sign_standalone_dylib(store, bundle_path, dylib_path)
        })?;
        // rayon's thread pool cannot run on wasm32; each dylib is signed
        // independently, so sequential iteration yields the same tree.
        #[cfg(target_arch = "wasm32")]
        for dylib_path in &dylibs {
            self.sign_standalone_dylib(store, bundle_path, dylib_path)?;
        }
        for (path, entitlements, profile_data) in &plan {
            self.sign_single_bundle(
                store,
                path,
                entitlements.as_deref(),
                profile_data.as_deref(),
                &already_signed,
            )?;
        }

        Ok(())
    }

    /// Reads a nested bundle's `CFBundleIdentifier` without writing anything.
    ///
    /// `is_nested_bundle_dir` also matches plist-less `.framework`/`.appex`
    /// directories, so absence is a legitimate `None` here rather than an
    /// error: such a bundle simply has no id to cascade from.
    fn read_bundle_identifier<S: Store>(&self, store: &S, bundle_path: &Path) -> Option<String> {
        let info_plist = Self::resolve_relative(store, bundle_path, "Info.plist").ok()?;
        let data = store.read(&info_plist).ok()?;
        let value: plist::Value = plist::from_bytes(&data).ok()?;
        let dict = value.as_dictionary()?;
        dict.get("CFBundleIdentifier")
            .and_then(|v| v.as_string())
            .map(str::to_owned)
    }

    /// Cascades a bundle-id change into nested identity plists (design §3.5
    /// stage 1): `CFBundleIdentifier`, `WKCompanionAppBundleIdentifier`,
    /// top-level and `NSExtension→NSExtensionAttributes`
    /// `WKAppBundleIdentifier`. Runs in the requested-rewrite phase, after
    /// every option rejection has already surfaced.
    fn rewrite_nested_identifiers<S: Store>(
        &self,
        store: &S,
        bundles: &[(PathBuf, usize)],
        root: &Path,
        old: &str,
        new: &str,
    ) -> Result<()> {
        for (path, _depth) in bundles {
            if path == root {
                continue; // root rewritten by the existing requested rewrite
            }
            let info_plist = Self::resolve_relative(store, path, "Info.plist")?;
            // A plist-less extension-arm directory has no id to cascade from.
            let Ok(data) = store.read(&info_plist) else {
                continue;
            };
            let mut value: plist::Value = plist::from_bytes(&data).map_err(|e| {
                Error::Core(zsign_core::Error::Signing(format!(
                    "Failed to parse Info.plist for {}: {e}",
                    info_plist.display()
                )))
            })?;
            let dict = match value.as_dictionary_mut() {
                Some(dict) => dict,
                None => continue,
            };
            let mut modified = false;
            if let Some(current) = dict
                .get("CFBundleIdentifier")
                .and_then(|v| v.as_string())
                .map(str::to_owned)
            {
                if let Some(rewritten) = replace_id_prefix(&current, old, new) {
                    dict.insert(
                        "CFBundleIdentifier".to_string(),
                        plist::Value::String(rewritten),
                    );
                    modified = true;
                }
            }
            modified |= rewrite_string_key(dict, "WKCompanionAppBundleIdentifier", old, new);
            modified |= rewrite_string_key(dict, "WKAppBundleIdentifier", old, new);
            if let Some(attrs) = dict
                .get_mut("NSExtension")
                .and_then(|v| v.as_dictionary_mut())
                .and_then(|d| d.get_mut("NSExtensionAttributes"))
                .and_then(|v| v.as_dictionary_mut())
            {
                modified |= rewrite_string_key(attrs, "WKAppBundleIdentifier", old, new);
            }
            if modified {
                let mut buf = Vec::new();
                plist::to_writer_xml(&mut buf, &value).map_err(|e| {
                    Error::Core(zsign_core::Error::Signing(format!(
                        "failed to serialize Info.plist for {}: {e}",
                        path.display()
                    )))
                })?;
                store.write(&info_plist, &buf)?;
            }
        }
        Ok(())
    }

    /// Collect all nested-code bundle directories with their depths.
    ///
    /// See [`crate::bundle::is_nested_bundle_dir`] for what qualifies.
    ///
    /// Returns a vector of (path, depth) tuples where depth is the nesting level.
    fn collect_nested_bundles<S: Store>(
        &self,
        store: &S,
        bundle_path: &Path,
    ) -> Result<Vec<(PathBuf, usize)>> {
        let mut bundles = Vec::new();

        bundles.push((bundle_path.to_path_buf(), 0));

        for entry in store.walk(bundle_path)? {
            let Ok((path, kind)) = entry else {
                continue;
            };
            // `walk` yields the root first; it is pushed above at depth 0, so
            // the historical `min_depth(1)` guard stands in here.
            if path == bundle_path {
                continue;
            }

            if kind == StoreKind::Dir && crate::bundle::is_nested_bundle_dir(&path) {
                let depth = self.calculate_bundle_depth(&path, bundle_path);
                bundles.push((path, depth));
            }
        }

        Ok(bundles)
    }

    /// Resolve `rel` — a root-relative name (raw plist value or literal) —
    /// under `root`.
    ///
    /// Never reinterprets `rel` as already root-prefixed: a value that
    /// starts with the root's own name still joins below the root. The
    /// spelling must be plain — no `..`, no absolute prefix, no `.`, no
    /// redundant separators — and no existing component may be a symlink.
    /// Returns `root.join(rel)`, the lexical shape WalkDir produces.
    fn resolve_relative<S: Store>(store: &S, root: &Path, rel: &str) -> Result<PathBuf> {
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
        Self::check_no_symlink_components(store, root, rel_path)?;
        Ok(root.join(rel))
    }

    /// Resolve `path` — already root-prefixed (discovery-walk output or a
    /// previously joined target) — under `root`.
    ///
    /// `strip_prefix` must succeed; the remainder must be plain; no
    /// existing component may be a symlink. Returns `root.join(relative)`,
    /// the lexical shape WalkDir produces.
    fn resolve_within<S: Store>(store: &S, root: &Path, path: &Path) -> Result<PathBuf> {
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
        Self::check_no_symlink_components(store, root, relative)?;
        Ok(root.join(relative))
    }

    /// Rejects archives whose `Payload/` holds more than one `.app` bundle.
    ///
    /// `extract_ipa` selects the first `Payload/*.app` it meets in `read_dir`
    /// order, so a multi-candidate archive would be signed and repacked from
    /// an arbitrary pick. Failing here names every candidate instead.
    fn ensure_single_app_bundle<S: Store>(store: &S, payload_dir: &Path) -> Result<()> {
        let mut candidates: Vec<String> = Vec::new();
        for (name, kind) in store.list(payload_dir)? {
            if kind == StoreKind::Dir
                && Path::new(&name).extension().is_some_and(|ext| ext == "app")
            {
                candidates.push(name);
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
    fn check_no_symlink_components<S: Store>(
        store: &S,
        root: &Path,
        relative: &Path,
    ) -> Result<()> {
        let mut current = root.to_path_buf();
        for component in relative.components() {
            current.push(component);
            match store.metadata(&current) {
                Ok(metadata) if metadata.is_symlink() => {
                    return Err(Error::Core(zsign_core::Error::Signing(format!(
                        "Pre-existing symlink in signing path: {}",
                        current.display()
                    ))));
                }
                Ok(_) => {}
                Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => break,
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
        let Ok(relative) = bundle_path.strip_prefix(root_bundle) else {
            return 0;
        };

        let mut depth = 0;
        let mut prefix = root_bundle.to_path_buf();
        for component in relative.components() {
            prefix.push(component);
            if crate::bundle::is_nested_bundle_dir(&prefix) {
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
    fn find_standalone_dylibs<S: Store>(
        &self,
        store: &S,
        bundle_path: &Path,
    ) -> Result<Vec<PathBuf>> {
        let mut dylibs = Vec::new();

        for entry in store.walk(bundle_path)? {
            let Ok((path, kind)) = entry else {
                continue;
            };
            // `walk` yields the root first, and it is a directory, so the
            // `!is_file` test below drops it — the historical `min_depth(1)`
            // guard needs no separate check here.

            if !matches!(kind, StoreKind::File) {
                continue;
            }

            if let Some(ext) = path.extension() {
                if ext == "dylib" && !path.components().any(|c| c.as_os_str() == "_CodeSignature") {
                    dylibs.push(path);
                }
            }
        }

        Ok(dylibs)
    }

    /// Sign a standalone .dylib file with empty parameters.
    ///
    /// C++ zsign signs dylibs with: macho.Sign(asset, force, "", "", "", "")
    /// This means: no bundleId, no InfoPlist hash, no CodeResources.
    fn sign_standalone_dylib<S: Store>(
        &self,
        store: &S,
        root: &Path,
        dylib_path: &Path,
    ) -> Result<()> {
        let validated = Self::resolve_within(store, root, dylib_path)?;
        let dylib_path = validated.as_path();
        let macho = MachOFile::parse(store.read(dylib_path)?)?;

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

        store.write(dylib_path, &signed_binary)?;

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
    fn sign_single_bundle<S: Store>(
        &self,
        store: &S,
        bundle_path: &Path,
        entitlements: Option<&[u8]>,
        profile_data: Option<&[u8]>,
        already_signed: &HashSet<PathBuf>,
    ) -> Result<()> {
        // Strip first: the removal must be visible to the CodeResources scan
        // below, or the seal would record a file that is no longer there.
        if self.remove_embedded_profile {
            let embedded_path =
                Self::resolve_relative(store, bundle_path, "embedded.mobileprovision")?;
            match store.remove_file(&embedded_path) {
                Ok(()) => {}
                Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    let kind = match &e {
                        Error::Io(e) => e.kind(),
                        _ => std::io::ErrorKind::Other,
                    };
                    return Err(Error::Io(std::io::Error::new(
                        kind,
                        format!(
                            "failed to remove embedded provisioning profile '{}' (-R): {e}",
                            embedded_path.display()
                        ),
                    )));
                }
            }
        }
        let identifier = self.get_bundle_identifier(store, bundle_path)?;
        let main_executable = self.get_main_executable(store, bundle_path)?;

        let binaries = self.find_immediate_macho_binaries(store, bundle_path, already_signed)?;

        let non_main_binaries: Vec<_> =
            binaries.iter().filter(|p| *p != &main_executable).collect();

        #[cfg(not(target_arch = "wasm32"))]
        non_main_binaries.par_iter().try_for_each(|binary_path| {
            self.sign_one_binary(store, bundle_path, binary_path, &identifier, entitlements)
        })?;
        // rayon's thread pool cannot run on wasm32; each binary is signed
        // independently, so sequential iteration yields the same tree.
        #[cfg(target_arch = "wasm32")]
        for binary_path in &non_main_binaries {
            self.sign_one_binary(store, bundle_path, binary_path, &identifier, entitlements)?;
        }

        // The plan build hands this bundle the profile it resolved, so embedding
        // is decided by presence rather than by a separate main-app flag.
        if let Some(data) = profile_data.filter(|_| !self.remove_embedded_profile) {
            let embedded_path =
                Self::resolve_relative(store, bundle_path, "embedded.mobileprovision")?;
            store.write(&embedded_path, data).map_err(|e| {
                Error::Core(zsign_core::Error::Signing(format!(
                    "Failed to write provisioning profile to {}: {}",
                    embedded_path.display(),
                    e
                )))
            })?;
        }

        self.generate_code_resources(store, bundle_path)?;

        let code_resources_path = bundle_path.join("_CodeSignature/CodeResources");
        let code_resources_data = if store.exists(&code_resources_path) {
            Some(store.read(&code_resources_path)?)
        } else {
            None
        };

        if store.exists(&main_executable) {
            self.sign_binary(
                store,
                bundle_path,
                &main_executable,
                &identifier,
                code_resources_data.as_deref(),
                entitlements,
            )?;
        }

        Ok(())
    }

    /// Signs one non-main binary of the bundle; shared verbatim by the
    /// parallel and sequential arms above so they cannot drift.
    fn sign_one_binary<S: Store>(
        &self,
        store: &S,
        bundle_path: &Path,
        binary_path: &Path,
        identifier: &str,
        entitlements: Option<&[u8]>,
    ) -> Result<()> {
        let binary_identifier = binary_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or(identifier);
        self.sign_binary(
            store,
            bundle_path,
            binary_path,
            binary_identifier,
            None,
            entitlements,
        )
    }

    /// Find Mach-O binaries that belong directly to this bundle (not nested bundles).
    ///
    /// This excludes binaries inside nested-code bundle directories.
    fn find_immediate_macho_binaries<S: Store>(
        &self,
        store: &S,
        bundle_path: &Path,
        already_signed: &HashSet<PathBuf>,
    ) -> Result<Vec<PathBuf>> {
        let mut binaries = Vec::new();

        let main_executable = self.get_main_executable(store, bundle_path)?;
        if store.exists(&main_executable) {
            binaries.push(main_executable.clone());
        }

        // `walk_pruned` reproduces the `filter_entry` chain exactly: a
        // nested-bundle directory is never descended into, so nothing below
        // it (nor an error inside it) is ever seen.
        let prune = |path: &Path, kind: StoreKind| {
            if path != bundle_path
                && kind == StoreKind::Dir
                && crate::bundle::is_nested_bundle_dir(path)
            {
                return false;
            }
            true
        };
        for entry in store.walk_pruned(bundle_path, &prune)? {
            let Ok((path, kind)) = entry else {
                continue;
            };

            if !matches!(kind, StoreKind::File) {
                continue;
            }

            if path.components().any(|c| c.as_os_str() == "_CodeSignature") {
                continue;
            }

            if path != main_executable
                && !already_signed.contains(&path)
                && self.is_macho_binary(store, &path)?
            {
                binaries.push(path);
            }
        }

        Ok(binaries)
    }

    /// Rewrites a string key in the main app's `Info.plist`.
    fn rewrite_plist_string<S: Store>(
        &self,
        store: &S,
        bundle_path: &Path,
        key: &str,
        value: &str,
    ) -> Result<()> {
        let info_plist_path = Self::resolve_relative(store, bundle_path, "Info.plist")?;

        if !store.exists(&info_plist_path) {
            return Err(Error::Core(zsign_core::Error::Signing(format!(
                "Info.plist not found in bundle: {}",
                bundle_path.display()
            ))));
        }

        let plist_data = store.read(&info_plist_path)?;
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

        store.write(&info_plist_path, &buf)?;

        Ok(())
    }

    /// Get the bundle identifier from Info.plist.
    fn get_bundle_identifier<S: Store>(&self, store: &S, bundle_path: &Path) -> Result<String> {
        let info_plist_path = bundle_path.join("Info.plist");

        if !store.exists(&info_plist_path) {
            return Err(Error::Core(zsign_core::Error::Signing(format!(
                "Info.plist not found in bundle: {}",
                bundle_path.display()
            ))));
        }

        let plist_data = store.read(&info_plist_path)?;
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
    fn get_main_executable<S: Store>(&self, store: &S, bundle_path: &Path) -> Result<PathBuf> {
        let info_plist_path = bundle_path.join("Info.plist");

        if !store.exists(&info_plist_path) {
            return Err(Error::Core(zsign_core::Error::Signing(format!(
                "Info.plist not found in bundle: {}",
                bundle_path.display()
            ))));
        }

        let plist_data = store.read(&info_plist_path)?;
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
                let executable = Self::resolve_relative(store, bundle_path, value)?;
                match store.metadata(&executable) {
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

        Self::resolve_relative(store, bundle_path, &executable_value)
    }

    /// Check if a file is a Mach-O binary by reading its magic bytes.
    fn is_macho_binary<S: Store>(&self, store: &S, path: &Path) -> Result<bool> {
        use std::io::Read;

        let mut file = match store.open(path) {
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
    fn sign_binary<S: Store>(
        &self,
        store: &S,
        root: &Path,
        binary_path: &Path,
        identifier: &str,
        code_resources: Option<&[u8]>,
        entitlements: Option<&[u8]>,
    ) -> Result<()> {
        let validated = Self::resolve_within(store, root, binary_path)?;
        let binary_path = validated.as_path();
        let binary_data = store.read(binary_path)?;
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
            store.write(binary_path, &binary_data)?;
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
            if store.exists(&info_plist) {
                Some(store.read(&info_plist)?)
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

        store.write(binary_path, &signed_binary)?;

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
    fn generate_code_resources<S: Store>(&self, store: &S, bundle_path: &Path) -> Result<()> {
        let code_resources = CodeResourcesBuilder::with_store(store, bundle_path)?
            .scan()?
            .build()?;

        let codesig_dir = Self::resolve_relative(store, bundle_path, "_CodeSignature")?;
        store.create_dir_all(&codesig_dir)?;

        let resources_path =
            Self::resolve_relative(store, bundle_path, "_CodeSignature/CodeResources")?;
        store.write(&resources_path, &code_resources)?;

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
    use zsign_core::macho::fixtures;

    // ---- CMS-signed provisioning-profile fixtures ----
    //
    // Generated by a throwaway test in zsign-core's provisioning.rs (a single
    // RSA root/leaf chain valid 2020-01-01..2099-01-01, so the profiles
    // validate at any wall clock). All four profiles anchor to the SAME root,
    // so an injected `profile_anchors` is the only trust source they need.
    const VALID_PROFILE_B64: &str = "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";
    const EXPIRED_PROFILE_B64: &str = "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";
    const WRONG_TEAM_PROFILE_B64: &str = "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";
    const WRONG_APP_PROFILE_B64: &str = "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";
    const PROFILE_TEST_ROOT_DER_B64: &str = "MIIC+zCCAeOgAwIBAgIBKTANBgkqhkiG9w0BAQsFADAeMRwwGgYDVQQDDBN6c24xMTggZml4dHVyZSByb290MCAXDTIwMDEwMTAwMDAwMFoYDzIwOTgxMjMwMDI0MDAwWjAeMRwwGgYDVQQDDBN6c24xMTggZml4dHVyZSByb290MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtAb2duMuJ01mRhSGvrrfwQ9tWRDYnMAlMFW4DaJL1F5iaJlwkxhP/0Q3Tbwm9AOEgeJkFxregL+He4HEMPnbR+bmWUia4yeHBUtsLK/YT36WdQeJOHgKY/7q9LeS0YkRN+3IRNUcaDQEtY5x8DrXtxQeDT0UEkiSYuIn4uMXzmPDm1r8iRsy1N4qSCcvv1EfxJHSD9Ra1857EME1G/+PdOT37TsRETgtTLe+D/6KuulXZf93d59QDthcecc3dswKFvZ3aHbMLXPdJR8gyvCuJDdd5KPifTCLPc0RZ5adaPCipgBirhRGlk0Iqk6Bs8tXpR0ekYW6tHWH7AV0NrN0HwIDAQABo0IwQDAdBgNVHQ4EFgQUMNeWKNo7q6eGih28ddNfBndEUakwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwDQYJKoZIhvcNAQELBQADggEBAGu11AnnrmRr/IRLjPya73dW4BJLaisgKB98Z4DNdsJ487YyvDXVwes+zqeGSY5w5/bTTwMhYFVzMII6CYyw41Rn6Tk8QmT7AT5aEfE+bKzrGr++h2njAtYD16SgaY1dB0KKkspRZOhLVD1+kflypq6/07eZ956ZY55hPeAm8t1u8wDYHrKVVOxHj1afV1WDJEOzH0jxABDzdQRlFTfhQjNoJQddR5tRpAFRluCLSybpAvK6d0u81Jdvu3LKQUIqqz5iwBw9NK0qVxb4/jL5+kTCoe1uiVk1LRx1+55VxnchXCZov5lbzbeTAVad4cC1sAFLkD462ttBfYLVJcFyGXE=";

    /// The brief's forgery: no CMS envelope, a foreign team, another app id,
    /// long expired, and the dangerous entitlements.
    const FORGED_PROFILE_XML: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
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

    /// STANDARD base64 engine, named for the fixture decode helper below.
    fn base64_engine() -> base64::engine::general_purpose::GeneralPurpose {
        base64::engine::general_purpose::STANDARD
    }

    /// The fixture root certificate, parsed for `TrustAnchors` injection.
    fn profile_fixture_anchors() -> zsign_core::crypto::cms_verify::TrustAnchors {
        use base64::Engine as _;
        use spki::der::Decode as _;
        let root = x509_cert::Certificate::from_der(
            &base64_engine().decode(PROFILE_TEST_ROOT_DER_B64).unwrap(),
        )
        .expect("root fixture must be a certificate");
        zsign_core::crypto::cms_verify::TrustAnchors::from_certificates(vec![root])
    }

    /// The raw profile bytes behind one of the embedded base64 fixtures.
    fn profile_fixture_bytes(b64: &str) -> Vec<u8> {
        use base64::Engine as _;
        base64_engine().decode(b64).expect("fixture must be base64")
    }

    #[test]
    fn valid_fixture_validates_against_injected_root() {
        let profile = profile_fixture_bytes(VALID_PROFILE_B64);
        let info = zsign_core::validate_and_extract_profile(
            &profile,
            &zsign_core::ProfileRequest {
                anchors: Some(profile_fixture_anchors()),
                expected_team_id: Some("TESTTEAM".into()),
                target_bundle_id: Some("com.test.app".into()),
                ..Default::default()
            },
        )
        .expect("valid fixture must validate at the wall clock");
        assert!(
            info.entitlements_xml.is_some(),
            "the valid fixture must carry entitlements"
        );
        assert!(
            String::from_utf8(info.entitlements_xml.unwrap())
                .unwrap()
                .contains("get-task-allow"),
            "fixture entitlements round-trip"
        );
    }

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
        zip.write_all(&fixtures::make_minimal_macho()).unwrap();

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

    /// The bytes form of [`write_test_ipa`]: the same fixture assembled in
    /// memory over a `Cursor`, so the bytes pipeline never touches disk.
    fn test_ipa_bytes(extras: &[(&str, &[u8])]) -> Vec<u8> {
        let mut buf = std::io::Cursor::new(Vec::new());
        let mut zip = ZipWriter::new(&mut buf);

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
        zip.write_all(&fixtures::make_minimal_macho()).unwrap();

        zip.start_file("Payload/Test.app/data.bin", options)
            .unwrap();
        zip.write_all(&[0xAB; 4096]).unwrap();

        for (name, bytes) in extras {
            zip.start_file(*name, options).unwrap();
            zip.write_all(bytes).unwrap();
        }

        zip.finish().unwrap();

        buf.into_inner()
    }

    /// Entry names of the zip in `bytes`.
    fn zip_entry_names(bytes: &[u8]) -> Vec<String> {
        let mut archive = ZipArchive::new(std::io::Cursor::new(bytes)).unwrap();
        (0..archive.len())
            .map(|i| archive.by_index(i).unwrap().name().to_string())
            .collect()
    }

    /// The bytes of `name` inside the zip `bytes`.
    fn zip_entry(bytes: &[u8], name: &str) -> Vec<u8> {
        use std::io::Read;

        let mut archive = ZipArchive::new(std::io::Cursor::new(bytes)).unwrap();
        let mut file = archive.by_name(name).expect("entry must exist");
        let mut out = Vec::new();
        file.read_to_end(&mut out).unwrap();
        out
    }

    /// Permission bits recorded in the zip for `name`.
    fn zip_entry_mode(bytes: &[u8], name: &str) -> u32 {
        let mut archive = ZipArchive::new(std::io::Cursor::new(bytes)).unwrap();
        let entry = archive.by_name(name).expect("entry must exist");
        entry
            .unix_mode()
            .unwrap_or_else(|| panic!("entry {name} carries no unix mode"))
    }

    /// A zip whose `Payload/Test.app/Test` is 0o755, the mode a real IPA
    /// has for its main executable. `patch_central_dir_unix_mode`-style
    /// rewriting is avoided here: the bytes fixture is built with the
    /// permission-bearing `FileOptions` directly.
    fn test_ipa_bytes_exec_mode(mode: u32) -> Vec<u8> {
        let mut buf = std::io::Cursor::new(Vec::new());
        let mut zip = ZipWriter::new(&mut buf);
        let dir_options = SimpleFileOptions::default();
        zip.add_directory("Payload/", dir_options).unwrap();
        zip.add_directory("Payload/Test.app/", dir_options).unwrap();
        zip.start_file("Payload/Test.app/Info.plist", dir_options)
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
        let exec_options = SimpleFileOptions::default().unix_permissions(mode);
        zip.start_file("Payload/Test.app/Test", exec_options)
            .unwrap();
        zip.write_all(&fixtures::make_minimal_macho()).unwrap();
        zip.start_file("Payload/Test.app/data.bin", dir_options)
            .unwrap();
        zip.write_all(&[0xAB; 4096]).unwrap();
        zip.finish().unwrap();
        buf.into_inner()
    }

    #[test]
    fn test_sign_ipa_bytes_round_trip() {
        let input = test_ipa_bytes(&[(
            "SwiftSupport/iphoneos/libswiftCore.dylib",
            b"swift-support-bytes".as_slice(),
        )]);
        let credentials = crate::test_util::test_credentials();

        let signed = IpaSigner::new(&credentials)
            .sign_ipa_bytes(&input)
            .expect("bytes signing must succeed");

        // The result must be a readable zip carrying the seal, the signed
        // main executable, and the carried root entry.
        let names = zip_entry_names(&signed);
        assert!(
            names
                .iter()
                .any(|n| n == "Payload/Test.app/_CodeSignature/CodeResources"),
            "the seal must be written; got {names:?}"
        );

        let cr = zip_entry(&signed, "Payload/Test.app/_CodeSignature/CodeResources");
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

        let main_data = zip_entry(&signed, "Payload/Test.app/Test");
        let macho =
            zsign_core::macho::MachOFile::parse(main_data).expect("signed binary must parse");
        let slice = &macho.slices()[0];
        let sig_off = slice.code_sig_offset.expect("binary must be signed") as usize;
        let sig_size = slice.code_sig_size.expect("binary must be signed") as usize;
        let sig = &macho.data()[sig_off..sig_off + sig_size];
        assert_eq!(
            u32::from_be_bytes(sig.get(0..4).expect("superblob magic").try_into().unwrap()),
            0xfade_0cc0,
            "embedded signature must be a SuperBlob"
        );
        let sb = zsign_core::codesign::verify::parse_superblob(sig)
            .expect("the embedded signature must parse as a SuperBlob");
        let cms = sb
            .entries
            .iter()
            .find(|e| e.slot == 0x10000)
            .expect("SuperBlob must contain a CMS signature");
        assert_eq!(
            u32::from_be_bytes(cms.blob.get(0..4).expect("CMS magic").try_into().unwrap()),
            0xfade_0b01,
            "CMS slot must be a blob wrapper"
        );

        assert!(
            names
                .iter()
                .any(|n| n == "SwiftSupport/iphoneos/libswiftCore.dylib"),
            "the carried root entry must survive; got {names:?}"
        );
    }

    #[test]
    fn test_sign_ipa_bytes_preserves_executable_mode() {
        // The reviewer-proven divergence: a 0o755 executable came out 0o644
        // through the bytes path because the store dropped the mode on rewrite.
        let input = test_ipa_bytes_exec_mode(0o755);
        assert_eq!(
            zip_entry_mode(&input, "Payload/Test.app/Test") & 0o777,
            0o755
        );

        let signed = IpaSigner::new(&crate::test_util::test_credentials())
            .sign_ipa_bytes(&input)
            .expect("bytes signing must succeed");
        assert_eq!(
            zip_entry_mode(&signed, "Payload/Test.app/Test") & 0o777,
            0o755,
            "signing must not downgrade the main executable to the zip default"
        );

        // Stronger form: both paths must agree on the mode, not merely match
        // the fixture's own 0o755.
        let temp = TempDir::new().unwrap();
        let input_path = temp.path().join("in.ipa");
        fs::write(&input_path, &input).unwrap();
        let native_out = temp.path().join("out.ipa");
        IpaSigner::new(&crate::test_util::test_credentials())
            .sign(&input_path, &native_out)
            .expect("native signing must succeed");
        let native = fs::read(&native_out).unwrap();
        assert_eq!(
            zip_entry_mode(&native, "Payload/Test.app/Test") & 0o777,
            zip_entry_mode(&signed, "Payload/Test.app/Test") & 0o777,
            "the bytes path must match the native path's executable mode"
        );
    }

    #[test]
    fn test_sign_ipa_bytes_is_deterministic() {
        let input = test_ipa_bytes(&[]);
        let credentials = crate::test_util::test_credentials();

        let a = IpaSigner::new(&credentials).sign_ipa_bytes(&input).unwrap();
        let b = IpaSigner::new(&credentials).sign_ipa_bytes(&input).unwrap();
        assert_eq!(a, b, "two signs of the same input must be byte-identical");

        let again = IpaSigner::new(&credentials)
            .sign_ipa_bytes(&a)
            .expect("re-signing signed bytes must succeed");
        assert_eq!(a, again, "re-signing signed bytes must be byte-identical");
    }

    #[test]
    fn test_sign_ipa_bytes_rejects_oversize_declared_entries() {
        // The fixture's data.bin declares 4096 uncompressed bytes; a 100-byte
        // per-entry budget must reject it before anything is materialized.
        let input = test_ipa_bytes(&[]);
        let store = MemStore::new();
        let err = extract_ipa_into_store(
            std::io::Cursor::new(input),
            &store,
            Path::new(""),
            ExtractionLimits {
                max_entry_bytes: 100,
                max_total_bytes: 100_000,
            },
        )
        .expect_err("an entry over the budget must be rejected");
        assert!(
            matches!(err, Error::InputTooLarge(_)),
            "the size breach must be reported as InputTooLarge; got {err:?}"
        );
    }

    #[test]
    fn test_sign_ipa_bytes_rejects_hostile_entry_names() {
        for hostile in ["../evil", "Payload/../../evil", "/abs/evil", "C:/abs/evil"] {
            let input = test_ipa_bytes(&[(hostile, b"evil content".as_slice())]);
            let err = IpaSigner::new(&crate::test_util::test_credentials())
                .sign_ipa_bytes(&input)
                .expect_err("a hostile entry name must fail the sign");
            // The shared collect pass rejects the name before any materializing
            // — `Error::Io(InvalidInput)`, not `Error::Zip`.
            assert!(
                matches!(&err, Error::Io(e) if e.kind() == std::io::ErrorKind::InvalidInput),
                "a hostile entry name must be an InvalidInput io error; got {err:?}"
            );
            let msg = err.to_string();
            assert!(
                msg.contains("Unsafe entry name in IPA") && msg.contains(hostile),
                "the collect pass must reject {hostile} by name: {msg}"
            );
        }
    }

    #[test]
    fn test_sign_ipa_bytes_entitlements_bytes_override() {
        let input = test_ipa_bytes(&[]);
        let signed = IpaSigner::new(&crate::test_util::test_credentials())
            .allow_unsafe_profile(true)
            .provisioning_profile_bytes(OVERRIDE_TEST_PROFILE.to_vec())
            .entitlements_bytes(OVERRIDE_TEST_ENTITLEMENTS.as_bytes().to_vec())
            .sign_ipa_bytes(&input)
            .expect("signing with an entitlements override must succeed");

        let main = zip_entry(&signed, "Payload/Test.app/Test");
        let macho = zsign_core::macho::MachOFile::parse(main.clone()).unwrap();
        let slice = &macho.slices()[0];
        let off = slice.code_sig_offset.unwrap() as usize;
        let len = slice.code_sig_size.unwrap() as usize;
        let sb = zsign_core::codesign::verify::parse_superblob(&main[off..off + len]).unwrap();
        let ents = sb
            .entries
            .iter()
            .find(|e| e.slot == zsign_core::codesign::constants::CSSLOT_ENTITLEMENTS)
            .map(|e| String::from_utf8_lossy(e.blob).into_owned())
            .expect("the main executable must carry an entitlements slot");
        assert!(
            ents.contains("com.zsign.bundle.override.ent"),
            "the override must reach the signed slot: {ents}"
        );
        assert!(
            !ents.contains("com.zsign.profile.entitlement"),
            "the override must replace, not merge with, the profile's entitlements: {ents}"
        );
    }

    #[test]
    fn test_sign_ipa_bytes_rejects_malformed_input() {
        let err = IpaSigner::new(&crate::test_util::test_credentials())
            .sign_ipa_bytes(b"not a zip")
            .expect_err("non-zip bytes must be rejected");
        assert!(
            matches!(err, Error::Zip(_)),
            "a bad PK prefix must map to Error::Zip; got {err:?}"
        );
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
            std::fs::write(app.join("Test"), fixtures::make_minimal_macho()).unwrap();
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
        std::fs::write(
            app.join("Enc"),
            fixtures::make_minimal_macho_encrypted(1, 0x1000),
        )
        .unwrap();
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
        std::fs::write(
            app.join("Enc"),
            fixtures::make_minimal_macho_encrypted(1, 0x1000),
        )
        .unwrap();
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
        std::fs::write(&outside, fixtures::make_minimal_macho()).unwrap();
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
        std::fs::write(&outside, fixtures::make_minimal_macho()).unwrap();
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
        std::fs::write(app.join("Test"), fixtures::make_minimal_macho()).unwrap();

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
        std::fs::write(&real, fixtures::make_minimal_macho()).unwrap();
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
        std::fs::write(temp.path().join("Test"), fixtures::make_minimal_macho()).unwrap();
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
        std::fs::write(app.join("App"), fixtures::make_minimal_macho()).unwrap();

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
        std::fs::write(&outside, fixtures::make_minimal_macho()).unwrap();
        let app = create_folder_bundle(temp.path(), "Test", true);
        std::fs::write(app.join("real.dylib"), fixtures::make_minimal_macho()).unwrap();
        let link = app.join("lib.dylib");
        symlink(&outside, &link).unwrap();
        let before = std::fs::read(&outside).unwrap();

        let signer = IpaSigner::new_adhoc();
        let dylibs = signer.find_standalone_dylibs(&FsStore, &app).unwrap();
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
            .find_immediate_macho_binaries(&FsStore, &app, &processed)
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
            fixtures::make_minimal_dylib(),
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
        std::fs::write(evil.join("Evil"), fixtures::make_minimal_macho()).unwrap();

        let app = create_folder_bundle(temp.path(), "Test", true);
        symlink(&evil, app.join("Evil.framework")).unwrap();
        let before = std::fs::read(evil.join("Evil")).unwrap();

        let bundles = IpaSigner::new_adhoc()
            .collect_nested_bundles(&FsStore, &app)
            .unwrap();
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
        zip.write_all(&fixtures::make_minimal_macho()).unwrap();
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

    #[test]
    fn test_xpc_service_is_discovered_and_signed_as_nested_bundle() {
        use zsign_core::codesign::verify::parse_superblob;

        let temp = TempDir::new().unwrap();
        let app = create_folder_bundle(temp.path(), "Test", true);
        let xpc = app.join("XPCServices").join("Foo.xpc");
        std::fs::create_dir_all(&xpc).unwrap();
        std::fs::write(
            xpc.join("Info.plist"),
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
    <key>CFBundleIdentifier</key><string>com.test.foo.xpc</string>
    <key>CFBundleExecutable</key><string>Foo</string>
    <key>CFBundlePackageType</key><string>XPC!</string>
</dict></plist>"#,
        )
        .unwrap();
        std::fs::write(xpc.join("Foo"), fixtures::make_minimal_macho()).unwrap();

        // `.xpc` is not in the {app, framework, appex} whitelist: only the
        // Info.plist/location arms can discover this bundle.
        let bundles = IpaSigner::new_adhoc()
            .collect_nested_bundles(&FsStore, &app)
            .unwrap();
        assert!(
            bundles.iter().any(|(p, d)| p == &xpc && *d == 1),
            "the XPC service must be collected as a depth-1 nested bundle: {bundles:?}"
        );

        IpaSigner::new_adhoc()
            .sign_folder_in_place(&app)
            .expect("a folder containing an XPC service must sign");
        assert!(
            xpc.join("_CodeSignature/CodeResources").exists(),
            "the XPC bundle must be sealed with its own CodeResources"
        );

        let foo = std::fs::read(xpc.join("Foo")).unwrap();
        let m = crate::macho::MachOFile::parse(foo.clone()).unwrap();
        let sl = &m.slices()[0];
        let sig_off = sl.code_sig_offset.unwrap() as usize;
        let sig_len = sl.code_sig_size.unwrap() as usize;
        let sb = parse_superblob(&foo[sig_off..sig_off + sig_len]).unwrap();
        let cd = sb
            .code_directory
            .as_ref()
            .expect("primary CodeDirectory must be present");
        assert_eq!(
            cd.identifier(),
            Some("com.test.foo.xpc"),
            "the XPC binary must carry its bundle identifier, not its file stem"
        );
        let info_hash = cd
            .special_slot_hash(1)
            .expect("nested bundle main executable must bind its Info.plist slot -1");
        assert!(
            info_hash.iter().any(|&b| b != 0),
            "slot -1 must hold a real Info.plist hash"
        );
        assert!(
            sb.entries.iter().all(|e| e.slot != 0x0005),
            "a nested bundle binary must be signed without entitlements"
        );

        let vreport = crate::verify::verify_bundle(&app).expect("verify must run");
        assert!(
            vreport.valid(),
            "ipa sign→verify must pass: {:?}",
            vreport.bundle.as_ref().map(|b| &b.errors)
        );
        let bundle = vreport.bundle.as_ref().unwrap();
        assert_eq!(bundle.nested.len(), 1, "exactly the XPC service is nested");
        assert_eq!(
            bundle.nested[0].path, "XPCServices/Foo.xpc",
            "the verifier must recognize the XPC bundle by the same predicate"
        );
    }
    /// Provisioning profile whose entitlements differ from any override, so
    /// precedence between the two is observable in the signed slot.
    const OVERRIDE_TEST_PROFILE: &[u8] = br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Entitlements</key>
  <dict>
    <key>application-identifier</key>
    <string>TESTTEAM.com.zsign.profile.entitlement</string>
  </dict>
  <key>ExpirationDate</key>
  <date>2099-01-01T00:00:00Z</date>
</dict></plist>"#;

    const OVERRIDE_TEST_ENTITLEMENTS: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.zsign.bundle.override.ent</key>
    <true/>
</dict>
</plist>"#;

    /// Blob of slot `slot` in `binary`'s superblob, if bound.
    fn signature_slot_blob(binary: &Path, slot: u32) -> Option<Vec<u8>> {
        use zsign_core::codesign::verify::parse_superblob;

        let m = crate::macho::MachOFile::open(binary).unwrap();
        let sl = &m.slices()[0];
        let off = sl.code_sig_offset? as usize;
        let len = sl.code_sig_size? as usize;
        let sb = parse_superblob(&m.data()[off..off + len]).unwrap();
        sb.entries
            .iter()
            .find(|e| e.slot == slot)
            .map(|e| e.blob.to_vec())
    }

    /// An `.app` with an XPC service nested under `XPCServices/`, used to prove
    /// the root-only scope of the entitlements override.
    fn create_bundle_with_xpc(dir: &Path) -> PathBuf {
        let app = create_folder_bundle(dir, "Test", true);
        let xpc = app.join("XPCServices").join("Foo.xpc");
        std::fs::create_dir_all(&xpc).unwrap();
        std::fs::write(
            xpc.join("Info.plist"),
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
    <key>CFBundleIdentifier</key><string>com.test.foo.xpc</string>
    <key>CFBundleExecutable</key><string>Foo</string>
    <key>CFBundlePackageType</key><string>XPC!</string>
</dict></plist>"#,
        )
        .unwrap();
        std::fs::write(xpc.join("Foo"), fixtures::make_minimal_macho()).unwrap();
        app
    }

    #[test]
    fn test_entitlements_override_applies_to_root_bundle() {
        let temp = TempDir::new().unwrap();
        let app = create_folder_bundle(temp.path(), "Test", true);
        let profile = temp.path().join("test.mobileprovision");
        std::fs::write(&profile, OVERRIDE_TEST_PROFILE).unwrap();
        let ents = temp.path().join("custom.entitlements");
        std::fs::write(&ents, OVERRIDE_TEST_ENTITLEMENTS).unwrap();

        IpaSigner::new_adhoc()
            .allow_unsafe_profile(true)
            .provisioning_profile(&profile)
            .entitlements(&ents)
            .sign_folder_in_place(&app)
            .expect("signing with an entitlements override must succeed");

        let blob = signature_slot_blob(
            &app.join("Test"),
            zsign_core::codesign::constants::CSSLOT_ENTITLEMENTS,
        )
        .expect("the root main binary must carry the override entitlements");
        assert!(
            String::from_utf8_lossy(&blob).contains("com.zsign.bundle.override.ent"),
            "the override must reach the root binary's entitlements slot"
        );
        assert!(
            !String::from_utf8_lossy(&blob).contains("com.zsign.profile.entitlement"),
            "the override must replace, not merge with, the profile's entitlements"
        );
    }

    #[test]
    fn test_blob_source_bytes_setters_match_path_form() {
        let temp = TempDir::new().unwrap();
        let app = create_folder_bundle(temp.path(), "Test", true);
        let profile = temp.path().join("test.mobileprovision");
        std::fs::write(&profile, OVERRIDE_TEST_PROFILE).unwrap();

        // The bytes form must sign exactly as the path form does: the profile
        // is embedded, and the supplied entitlements reach the root binary.
        IpaSigner::new_adhoc()
            .allow_unsafe_profile(true)
            .provisioning_profile_bytes(std::fs::read(&profile).unwrap())
            .entitlements_bytes(OVERRIDE_TEST_ENTITLEMENTS.as_bytes().to_vec())
            .sign_folder_in_place(&app)
            .expect("signing from bytes must succeed");
        assert!(
            app.join("embedded.mobileprovision").exists(),
            "profile bytes must be embedded, not skipped"
        );
        let blob = signature_slot_blob(
            &app.join("Test"),
            zsign_core::codesign::constants::CSSLOT_ENTITLEMENTS,
        )
        .expect("the root main binary must carry the supplied entitlements");
        assert!(
            String::from_utf8_lossy(&blob).contains("com.zsign.bundle.override.ent"),
            "entitlements bytes must reach the root binary's entitlements slot"
        );
        assert!(
            !String::from_utf8_lossy(&blob).contains("com.zsign.profile.entitlement"),
            "the override must replace, not merge with, the profile's entitlements"
        );

        // The same three blob checks apply to supplied bytes: a non-dictionary
        // root is a hard error, never a silent fallback to the profile.
        let other = create_folder_bundle(temp.path(), "Other", true);
        let err = IpaSigner::new_adhoc()
            .entitlements_bytes(
                br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<array>
    <string>nope</string>
</array>
</plist>"#
                .to_vec(),
            )
            .sign_folder_in_place(&other)
            .expect_err("a non-dictionary override must fail the sign");
        assert!(
            err.to_string()
                .contains("must contain a top-level dictionary"),
            "the rejection must name the violated check: {err}"
        );
        assert!(
            err.to_string().contains(IN_MEMORY_ENTS),
            "a rejection from supplied bytes must name the bytes source: {err}"
        );
    }

    #[test]
    fn test_entitlements_override_not_inherited_by_nested() {
        let temp = TempDir::new().unwrap();
        let app = create_bundle_with_xpc(temp.path());
        let ents = temp.path().join("custom.entitlements");
        std::fs::write(&ents, OVERRIDE_TEST_ENTITLEMENTS).unwrap();

        IpaSigner::new_adhoc()
            .entitlements(&ents)
            .sign_folder_in_place(&app)
            .expect("signing with an entitlements override must succeed");

        let nested = app.join("XPCServices/Foo.xpc/Foo");
        assert!(
            crate::macho::MachOFile::open(&nested).unwrap().slices()[0]
                .code_sig_offset
                .is_some(),
            "the nested binary must be signed, or an absent entitlements slot proves nothing"
        );
        assert!(
            signature_slot_blob(
                &nested,
                zsign_core::codesign::constants::CSSLOT_ENTITLEMENTS,
            )
            .is_none(),
            "a nested bundle must not inherit the root's entitlements override"
        );
    }

    /// An entitlements plist carrying a single marker key.
    fn dir_entitlements(marker: &str) -> String {
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>{marker}</key>
    <true/>
</dict>
</plist>"#
        )
    }

    /// Root bundle whose Info.plist declares `bundle_id` as CFBundleIdentifier.
    fn create_bundle_with_id(dir: &Path, bundle_id: &str) -> PathBuf {
        let app = create_folder_bundle(dir, "Test", true);
        std::fs::write(
            app.join("Info.plist"),
            format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key><string>Test</string>
    <key>CFBundleIdentifier</key><string>{bundle_id}</string>
</dict>
</plist>"#
            ),
        )
        .unwrap();
        app
    }

    #[test]
    fn test_entitlements_dir_hit_replaces_profile() {
        let temp = TempDir::new().unwrap();
        let app = create_folder_bundle(temp.path(), "Test", true);
        let profile = temp.path().join("test.mobileprovision");
        std::fs::write(&profile, OVERRIDE_TEST_PROFILE).unwrap();
        let dir = temp.path().join("ents");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("com.test.app.plist"),
            dir_entitlements("com.zsign.dir.ent"),
        )
        .unwrap();

        IpaSigner::new_adhoc()
            .allow_unsafe_profile(true)
            .provisioning_profile(&profile)
            .entitlements_dir(&dir)
            .sign_folder_in_place(&app)
            .expect("a directory hit must sign");

        let blob = signature_slot_blob(
            &app.join("Test"),
            zsign_core::codesign::constants::CSSLOT_ENTITLEMENTS,
        )
        .expect("the root main binary must carry the directory entitlements");
        assert!(
            String::from_utf8_lossy(&blob).contains("com.zsign.dir.ent"),
            "the directory hit must reach the root slot: {blob:?}"
        );
        assert!(
            !String::from_utf8_lossy(&blob).contains("com.zsign.profile.entitlement"),
            "a directory hit must replace the profile's entitlements, not merge"
        );
    }

    #[test]
    fn test_entitlements_dir_miss_falls_back_to_profile() {
        let temp = TempDir::new().unwrap();
        let app = create_folder_bundle(temp.path(), "Test", true);
        let profile = temp.path().join("test.mobileprovision");
        std::fs::write(&profile, OVERRIDE_TEST_PROFILE).unwrap();
        // The directory exists but holds no file for this bundle id.
        let dir = temp.path().join("ents");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("com.other.app.plist"),
            dir_entitlements("com.zsign.dir.ent"),
        )
        .unwrap();

        IpaSigner::new_adhoc()
            .allow_unsafe_profile(true)
            .provisioning_profile(&profile)
            .entitlements_dir(&dir)
            .sign_folder_in_place(&app)
            .expect("a directory miss must fall back and still sign");

        let blob = signature_slot_blob(
            &app.join("Test"),
            zsign_core::codesign::constants::CSSLOT_ENTITLEMENTS,
        )
        .expect("the profile entitlements must still be signed");
        assert!(
            String::from_utf8_lossy(&blob).contains("com.zsign.profile.entitlement"),
            "a directory miss must fall back to the profile: {blob:?}"
        );
        assert!(
            !String::from_utf8_lossy(&blob).contains("com.zsign.dir.ent"),
            "another app's entitlements must never be used"
        );
    }

    #[test]
    fn test_entitlements_dir_traversal_id_never_reads_outside() {
        let temp = TempDir::new().unwrap();
        let app = create_bundle_with_id(temp.path(), "../evil");
        let profile = temp.path().join("test.mobileprovision");
        std::fs::write(&profile, OVERRIDE_TEST_PROFILE).unwrap();
        let dir = temp.path().join("ents");
        std::fs::create_dir_all(&dir).unwrap();
        // One level ABOVE the directory: reachable only by escaping it.
        std::fs::write(
            temp.path().join("evil.plist"),
            dir_entitlements("com.zsign.evil"),
        )
        .unwrap();

        IpaSigner::new_adhoc()
            .allow_unsafe_profile(true)
            .provisioning_profile(&profile)
            .entitlements_dir(&dir)
            .sign_folder_in_place(&app)
            .expect("a traversal-shaped id must fall back, not fail");

        let blob = signature_slot_blob(
            &app.join("Test"),
            zsign_core::codesign::constants::CSSLOT_ENTITLEMENTS,
        )
        .expect("the profile entitlements must be signed");
        assert!(
            String::from_utf8_lossy(&blob).contains("com.zsign.profile.entitlement"),
            "a traversal id must fall back to the profile: {blob:?}"
        );
        assert!(
            !String::from_utf8_lossy(&blob).contains("com.zsign.evil"),
            "a bundle id must never escape the entitlements directory"
        );
    }

    #[test]
    fn test_entitlements_dir_invalid_file_names_path() {
        let temp = TempDir::new().unwrap();
        let app = create_folder_bundle(temp.path(), "Test", true);
        let dir = temp.path().join("ents");
        std::fs::create_dir_all(&dir).unwrap();
        let bad = dir.join("com.test.app.plist");
        std::fs::write(&bad, b"not a plist at all").unwrap();

        let err = IpaSigner::new_adhoc()
            .entitlements_dir(&dir)
            .sign_folder_in_place(&app)
            .expect_err("an unparsable directory entry must fail the sign");
        let message = err.to_string();
        assert!(
            message.contains("com.test.app.plist"),
            "the error must name the offending file: {message}"
        );
        assert!(
            !app.join("_CodeSignature").exists(),
            "a rejected directory entry must not seal the bundle"
        );
        assert!(
            signature_slot_blob(
                &app.join("Test"),
                zsign_core::codesign::constants::CSSLOT_ENTITLEMENTS
            )
            .is_none(),
            "a rejected directory entry must leave the main binary unsigned"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_entitlements_dir_symlink_key_rejected() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().unwrap();
        let app = create_folder_bundle(temp.path(), "Test", true);
        let outside = temp.path().join("outside.plist");
        std::fs::write(&outside, dir_entitlements("com.zsign.outside")).unwrap();
        let dir = temp.path().join("ents");
        std::fs::create_dir_all(&dir).unwrap();
        symlink(&outside, dir.join("com.test.app.plist")).unwrap();

        let err = IpaSigner::new_adhoc()
            .entitlements_dir(&dir)
            .sign_folder_in_place(&app)
            .expect_err("a symlinked directory entry must be refused");
        let message = err.to_string();
        assert!(
            message.contains("com.test.app.plist") && message.contains("symlink"),
            "the error must name the symlinked entry: {message}"
        );
        assert!(
            !app.join("_CodeSignature").exists(),
            "a refused symlinked entry must not seal the bundle"
        );
        assert!(
            signature_slot_blob(
                &app.join("Test"),
                zsign_core::codesign::constants::CSSLOT_ENTITLEMENTS
            )
            .is_none(),
            "a refused symlinked entry must leave the main binary unsigned"
        );
    }

    #[test]
    fn test_entitlements_dir_missing_directory_names_path() {
        let temp = TempDir::new().unwrap();
        let app = create_folder_bundle(temp.path(), "Test", true);
        let dir = temp.path().join("absent-ents");

        let err = IpaSigner::new_adhoc()
            .entitlements_dir(&dir)
            .sign_folder_in_place(&app)
            .expect_err("a configured but absent directory must fail the sign");
        let message = err.to_string();
        assert!(
            message.contains("absent-ents"),
            "the error must name the configured directory: {message}"
        );
        assert!(
            !app.join("_CodeSignature").exists(),
            "a rejected directory must not seal the bundle"
        );
    }

    #[test]
    fn test_entitlements_file_beats_entitlements_dir() {
        let temp = TempDir::new().unwrap();
        let app = create_folder_bundle(temp.path(), "Test", true);
        let dir = temp.path().join("ents");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("com.test.app.plist"),
            dir_entitlements("com.zsign.dir.ent"),
        )
        .unwrap();
        let file = temp.path().join("custom.entitlements");
        std::fs::write(&file, OVERRIDE_TEST_ENTITLEMENTS).unwrap();

        IpaSigner::new_adhoc()
            .entitlements(&file)
            .entitlements_dir(&dir)
            .sign_folder_in_place(&app)
            .expect("both sources set must sign");

        let blob = signature_slot_blob(
            &app.join("Test"),
            zsign_core::codesign::constants::CSSLOT_ENTITLEMENTS,
        )
        .expect("the root binary must carry entitlements");
        assert!(
            String::from_utf8_lossy(&blob).contains("com.zsign.bundle.override.ent"),
            "the -e file must win over a directory hit: {blob:?}"
        );
        assert!(
            !String::from_utf8_lossy(&blob).contains("com.zsign.dir.ent"),
            "the directory tier must not be consulted once -e is set: {blob:?}"
        );
    }

    #[test]
    fn test_entitlements_dir_regular_file_reports_not_a_directory() {
        let temp = TempDir::new().unwrap();
        let app = create_folder_bundle(temp.path(), "Test", true);
        // A regular file where the directory was configured.
        let dir = temp.path().join("ents");
        std::fs::write(&dir, b"not a directory").unwrap();

        let err = IpaSigner::new_adhoc()
            .entitlements_dir(&dir)
            .sign_folder_in_place(&app)
            .expect_err("a file used as the entitlements directory must fail the sign");
        let message = err.to_string();
        assert!(
            message.contains("not a directory"),
            "a regular file must be reported as such, not as missing: {message}"
        );
        assert!(
            !message.contains("does not exist"),
            "an existing path must not be reported as missing: {message}"
        );
    }

    #[test]
    fn test_entitlements_dir_rejects_drive_prefixed_id() {
        let temp = TempDir::new().unwrap();
        let dir = temp.path().join("ents");
        std::fs::create_dir_all(&dir).unwrap();
        // Planted one level ABOVE the directory: reachable only by escaping it.
        std::fs::write(
            temp.path().join("evil.plist"),
            dir_entitlements("com.zsign.evil"),
        )
        .unwrap();
        // A Windows drive-prefixed id would make `dir.join(name)` clear the base
        // on Windows; the component guard must reject it on every platform.
        for id in ["C:foo", "C:\\foo", "..", "../evil", "", "a/b", "a\\b"] {
            assert!(
                IpaSigner::new_adhoc()
                    .entitlements_dir(&dir)
                    .dir_hit(id)
                    .expect("a malformed id must be a miss, not an error")
                    .is_none(),
                "id {id:?} must not resolve to a file through the directory"
            );
        }
    }

    #[test]
    fn test_entitlements_dir_non_regular_entry_falls_back() {
        let temp = TempDir::new().unwrap();
        let app = create_folder_bundle(temp.path(), "Test", true);
        let profile = temp.path().join("test.mobileprovision");
        std::fs::write(&profile, OVERRIDE_TEST_PROFILE).unwrap();
        let dir = temp.path().join("ents");
        // A directory planted where the bundle's entry file is expected.
        std::fs::create_dir_all(dir.join("com.test.app.plist")).unwrap();

        IpaSigner::new_adhoc()
            .allow_unsafe_profile(true)
            .provisioning_profile(&profile)
            .entitlements_dir(&dir)
            .sign_folder_in_place(&app)
            .expect("a non-regular entry must fall back, not fail");

        let blob = signature_slot_blob(
            &app.join("Test"),
            zsign_core::codesign::constants::CSSLOT_ENTITLEMENTS,
        )
        .expect("the profile entitlements must be signed");
        assert!(
            String::from_utf8_lossy(&blob).contains("com.zsign.profile.entitlement"),
            "a non-regular entry must fall back to the profile: {blob:?}"
        );
    }

    /// Extension bundle profile: its own marker and app-identifier, plus the
    /// team/device fields a development profile carries.
    const EXT_PROFILE_FIXTURE: &[u8] = br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Entitlements</key>
  <dict>
    <key>application-identifier</key>
    <string>TESTTEAM.com.test.app.ext</string>
    <key>com.zsign.ext.ent</key>
    <true/>
  </dict>
  <key>TeamIdentifier</key>
  <array><string>TESTTEAM</string></array>
  <key>ProvisionedDevices</key>
  <array><string>00008030-000000000000001E</string></array>
  <key>ExpirationDate</key>
  <date>2099-01-01T00:00:00Z</date>
</dict></plist>"#;

    /// Root app `com.test.app` with `PlugIns/Ext.appex` (`com.test.app.ext`).
    fn create_bundle_with_appex(dir: &Path) -> (PathBuf, PathBuf) {
        let app = create_folder_bundle(dir, "Test", true);
        let appex = app.join("PlugIns").join("Ext.appex");
        std::fs::create_dir_all(&appex).unwrap();
        std::fs::write(
            appex.join("Info.plist"),
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
    <key>CFBundleIdentifier</key><string>com.test.app.ext</string>
    <key>CFBundleExecutable</key><string>Ext</string>
    <key>CFBundlePackageType</key><string>XPC!</string>
</dict></plist>"#,
        )
        .unwrap();
        std::fs::write(appex.join("Ext"), fixtures::make_minimal_macho()).unwrap();
        (app, appex)
    }

    #[test]
    fn test_profile_map_embeds_and_derives_for_nested() {
        let temp = TempDir::new().unwrap();
        let (app, appex) = create_bundle_with_appex(temp.path());
        let root_profile = temp.path().join("root.mobileprovision");
        std::fs::write(&root_profile, OVERRIDE_TEST_PROFILE).unwrap();
        let ext_profile = temp.path().join("ext.mobileprovision");
        std::fs::write(&ext_profile, EXT_PROFILE_FIXTURE).unwrap();

        IpaSigner::new_adhoc()
            .allow_unsafe_profile(true)
            .provisioning_profile(&root_profile)
            .bundle_profiles(vec![("com.test.app.ext".to_string(), ext_profile.clone())])
            .sign_folder_in_place(&app)
            .expect("a mapped nested profile must sign");

        assert_eq!(
            std::fs::read(appex.join("embedded.mobileprovision")).unwrap(),
            std::fs::read(&ext_profile).unwrap(),
            "the appex must embed exactly the mapped profile bytes"
        );
        let appex_blob = signature_slot_blob(
            &appex.join("Ext"),
            zsign_core::codesign::constants::CSSLOT_ENTITLEMENTS,
        )
        .expect("the appex binary must carry its mapped entitlements");
        assert!(
            String::from_utf8_lossy(&appex_blob).contains("com.zsign.ext.ent"),
            "the appex must be signed with entitlements derived from its mapped profile: {appex_blob:?}"
        );
        // No bleed in either direction: the root keeps its own entitlements.
        let root_blob = signature_slot_blob(
            &app.join("Test"),
            zsign_core::codesign::constants::CSSLOT_ENTITLEMENTS,
        )
        .expect("the root binary must keep its own entitlements");
        assert!(
            String::from_utf8_lossy(&root_blob).contains("com.zsign.profile.entitlement"),
            "the root must keep the root profile's entitlements: {root_blob:?}"
        );
        assert!(
            !String::from_utf8_lossy(&root_blob).contains("com.zsign.ext.ent"),
            "the appex's entitlements must not bleed into the root: {root_blob:?}"
        );
    }

    #[test]
    fn test_entitlements_dir_beats_mapped_profile_for_nested() {
        let temp = TempDir::new().unwrap();
        let (app, appex) = create_bundle_with_appex(temp.path());
        let ext_profile = temp.path().join("ext.mobileprovision");
        std::fs::write(&ext_profile, EXT_PROFILE_FIXTURE).unwrap();
        // A directory entry for the appex id must win over the map's derived
        // entitlements — the map still supplies the embedded profile bytes.
        let dir = temp.path().join("ents");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("com.test.app.ext.plist"),
            dir_entitlements("com.zsign.dir.ent"),
        )
        .unwrap();

        IpaSigner::new_adhoc()
            .allow_unsafe_profile(true)
            .entitlements_dir(&dir)
            .bundle_profiles(vec![("com.test.app.ext".to_string(), ext_profile.clone())])
            .sign_folder_in_place(&app)
            .expect("a directory entry plus a mapped profile must sign");

        let blob = signature_slot_blob(
            &appex.join("Ext"),
            zsign_core::codesign::constants::CSSLOT_ENTITLEMENTS,
        )
        .expect("the appex binary must carry entitlements");
        assert!(
            String::from_utf8_lossy(&blob).contains("com.zsign.dir.ent"),
            "the directory tier must beat the map's derived entitlements: {blob:?}"
        );
        assert!(
            !String::from_utf8_lossy(&blob).contains("com.zsign.ext.ent"),
            "the map's entitlements must not be used when the directory hits: {blob:?}"
        );
        assert_eq!(
            std::fs::read(appex.join("embedded.mobileprovision")).unwrap(),
            std::fs::read(&ext_profile).unwrap(),
            "the directory supplies entitlements only; the map must still supply \
             the embedded profile bytes"
        );
    }

    #[test]
    fn test_profile_map_unused_key_errors() {
        let temp = TempDir::new().unwrap();
        let (app, _appex) = create_bundle_with_appex(temp.path());
        // Plan build is read-only and precedes EVERY sign mutation, the dylib
        // pass included, so an untouched dylib proves the rejection landed
        // before any write.
        let frameworks = app.join("Frameworks");
        std::fs::create_dir_all(&frameworks).unwrap();
        let dylib = frameworks.join("libHelper.dylib");
        std::fs::write(&dylib, fixtures::make_minimal_dylib()).unwrap();
        let ext_profile = temp.path().join("ext.mobileprovision");
        std::fs::write(&ext_profile, EXT_PROFILE_FIXTURE).unwrap();

        let err = IpaSigner::new_adhoc()
            .allow_unsafe_profile(true)
            .bundle_profiles(vec![("com.test.app.nope".to_string(), ext_profile)])
            .sign_folder_in_place(&app)
            .expect_err("a map key matching no bundle must fail the sign");
        // Assert the untouched state first: if the dylib pass ran before the
        // plan build, these fail on their own terms rather than on expect_err.
        assert!(
            crate::macho::MachOFile::open(&dylib).unwrap().slices()[0]
                .code_sig_offset
                .is_none(),
            "the dylib pass is the first mutation, so it must not have run: {}",
            dylib.display()
        );
        assert!(
            !app.join("_CodeSignature").exists(),
            "plan build precedes every mutation, so nothing may be sealed: {}",
            app.display()
        );
        let message = err.to_string();
        assert!(
            message.contains("com.test.app.nope"),
            "the error must name the unused key: {message}"
        );
    }

    #[test]
    fn test_profile_map_invalid_profile_names_bundle() {
        let temp = TempDir::new().unwrap();
        let (app, _appex) = create_bundle_with_appex(temp.path());
        let good = temp.path().join("ext.mobileprovision");
        std::fs::write(&good, EXT_PROFILE_FIXTURE).unwrap();
        let bad = temp.path().join("broken.mobileprovision");
        std::fs::write(&bad, b"not a provisioning profile at all").unwrap();

        let err = IpaSigner::new_adhoc()
            .allow_unsafe_profile(true)
            .bundle_profiles(vec![
                ("com.test.app.ext".to_string(), good),
                ("com.test.app.bad".to_string(), bad.clone()),
            ])
            .sign_folder_in_place(&app)
            .expect_err("a mapped profile that is not a profile must fail the sign");
        let message = err.to_string();
        assert!(
            message.contains("com.test.app.bad"),
            "with several entries the error must name the offending bundle: {message}"
        );
        assert!(
            message.contains("broken.mobileprovision"),
            "the error must name the offending file: {message}"
        );
    }

    /// Pins that an oversized root provisioning profile is rejected by the
    /// documented size cap and surfaces to the caller as `Error::InputTooLarge`
    /// naming both the offending length and the limit — never as a generic
    /// forwarded core error.
    #[test]
    fn oversized_root_profile_surfaces_as_input_too_large() {
        let temp = TempDir::new().unwrap();
        let (app, _appex) = create_bundle_with_appex(temp.path());
        let big = temp.path().join("huge.mobileprovision");
        std::fs::write(&big, vec![0u8; 17 * 1024 * 1024]).unwrap();

        let err = IpaSigner::new_adhoc()
            .provisioning_profile(&big)
            .sign_folder_in_place(&app)
            .expect_err("a 17 MiB root profile must fail the sign");
        assert!(
            matches!(&err, Error::InputTooLarge(m) if m.contains("17825792") && m.contains("16777216")),
            "oversized root profile must surface as InputTooLarge with lengths named, got {err:?}"
        );
        assert!(
            err.to_string().contains("huge.mobileprovision"),
            "the size rejection must name the offending root profile file, got {err:?}"
        );
    }

    /// Pins that an oversized profile in the bundle map keeps its
    /// `Error::InputTooLarge` variant through the per-bundle context wrap, and
    /// that the wrap still names the offending bundle id and file path.
    #[test]
    fn oversized_profile_map_entry_surfaces_as_input_too_large_naming_bundle() {
        let temp = TempDir::new().unwrap();
        let (app, _appex) = create_bundle_with_appex(temp.path());
        let big = temp.path().join("huge-ext.mobileprovision");
        std::fs::write(&big, vec![0u8; 17 * 1024 * 1024]).unwrap();

        let err = IpaSigner::new_adhoc()
            .bundle_profiles(vec![("com.test.app.ext".to_string(), big.clone())])
            .sign_folder_in_place(&app)
            .expect_err("a 17 MiB mapped profile must fail the sign");
        assert!(
            matches!(&err, Error::InputTooLarge(_)),
            "the size rejection must keep its variant through the map context wrap, got {err:?}"
        );
        let message = err.to_string();
        assert!(
            message.contains("com.test.app.ext") && message.contains("huge-ext.mobileprovision"),
            "the error must still name the offending bundle and file: {message}"
        );
        // The context appends detail; it must never add a second prefix.
        assert!(
            message.starts_with("Input too large: "),
            "the size rejection keeps a single prefix: {message}"
        );
        assert_eq!(
            message.matches("Input too large:").count(),
            1,
            "the prefix must never double: {message}"
        );
    }

    /// Pins that a malformed map entry keeps the class its own validator
    /// produced and gains the offending entry's name from the context wrap.
    /// Preserving the class is what lets the wrap name the entry without
    /// hiding whether this was a configuration mistake or a failed
    /// validation.
    #[test]
    fn malformed_profile_map_entry_keeps_the_validation_class() {
        let temp = TempDir::new().unwrap();
        let (app, _appex) = create_bundle_with_appex(temp.path());
        let bad = temp.path().join("broken.mobileprovision");
        std::fs::write(&bad, b"not a provisioning profile at all").unwrap();

        let err = IpaSigner::new_adhoc()
            .allow_unsafe_profile(true)
            .bundle_profiles(vec![("com.test.app.bad".to_string(), bad.clone())])
            .sign_folder_in_place(&app)
            .expect_err("a malformed mapped profile must fail the sign");
        assert!(
            matches!(&err, Error::Core(zsign_core::Error::ProvisioningProfile(_))),
            "a malformed map entry must keep its validation class, got: {err:?}"
        );
        let message = err.to_string();
        assert!(
            message.contains("com.test.app.bad"),
            "the wrap must name the offending entry: {message}"
        );
        assert!(
            message.contains("broken.mobileprovision"),
            "the wrap must name the offending file: {message}"
        );
    }

    /// A mapped profile that parses but carries no CMS envelope is a
    /// verification failure; the per-entry context wrap must not reclassify
    /// it as a configuration error.
    #[test]
    fn nested_cms_less_profile_keeps_verification_class() {
        let temp = TempDir::new().unwrap();
        let (app, _appex) = create_bundle_with_appex(temp.path());
        let forged = temp.path().join("forged.mobileprovision");
        std::fs::write(&forged, FORGED_PROFILE_XML).unwrap();

        let err = IpaSigner::new_adhoc()
            .bundle_profiles(vec![("com.test.app.bad".to_string(), forged.clone())])
            .sign_folder_in_place(&app)
            .expect_err("a CMS-less mapped profile must fail the sign");
        assert!(
            matches!(&err, Error::Core(zsign_core::Error::Verification(_))),
            "a CMS-less map entry is a verification failure, got: {err:?}"
        );
        let message = err.to_string();
        assert!(
            message.contains("com.test.app.bad"),
            "the wrap must name the offending entry: {message}"
        );
        assert!(
            message.contains("forged.mobileprovision"),
            "the wrap must name the offending file: {message}"
        );
    }

    /// An unreadable root profile names the path it failed to read, the same
    /// way a mapped entry already does — the root arm is not exempt.
    #[test]
    fn missing_root_profile_read_names_the_path() {
        let temp = TempDir::new().unwrap();
        let (app, _appex) = create_bundle_with_appex(temp.path());
        let missing = temp.path().join("nope.mobileprovision");

        let err = IpaSigner::new_adhoc()
            .provisioning_profile(&missing)
            .sign_folder_in_place(&app)
            .expect_err("an unreadable root profile must fail the sign");
        assert!(matches!(&err, Error::Io(_)), "got: {err:?}");
        let message = err.to_string();
        assert!(
            message.contains("provisioning profile"),
            "the read failure must name what it was reading: {message}"
        );
        assert!(
            message.contains("nope.mobileprovision"),
            "the read failure must name the path: {message}"
        );
    }

    #[test]
    fn test_profile_map_root_id_rejected() {
        let temp = TempDir::new().unwrap();
        let (app, _appex) = create_bundle_with_appex(temp.path());
        let ext_profile = temp.path().join("ext.mobileprovision");
        std::fs::write(&ext_profile, EXT_PROFILE_FIXTURE).unwrap();

        let err = IpaSigner::new_adhoc()
            .bundle_profiles(vec![("com.test.app".to_string(), ext_profile)])
            .sign_folder_in_place(&app)
            .expect_err("the root id must be rejected as a map key");
        assert!(
            matches!(&err, Error::Core(zsign_core::Error::Config(_))),
            "a map-key rejection is a config error, got: {err:?}"
        );
        let message = err.to_string();
        assert!(
            message.contains("--profile"),
            "the error must point at the root profile flag: {message}"
        );
    }

    #[test]
    fn test_profile_map_duplicate_key_errors() {
        let temp = TempDir::new().unwrap();
        let (app, _appex) = create_bundle_with_appex(temp.path());
        let ext_profile = temp.path().join("ext.mobileprovision");
        std::fs::write(&ext_profile, EXT_PROFILE_FIXTURE).unwrap();

        let err = IpaSigner::new_adhoc()
            .allow_unsafe_profile(true)
            .bundle_profiles(vec![
                ("com.test.app.ext".to_string(), ext_profile.clone()),
                ("com.test.app.ext".to_string(), ext_profile),
            ])
            .sign_folder_in_place(&app)
            .expect_err("a duplicate map key must fail the sign");
        assert!(
            matches!(&err, Error::Core(zsign_core::Error::Config(_))),
            "a map-key rejection is a config error, got: {err:?}"
        );
        let message = err.to_string();
        assert!(
            message.contains("com.test.app.ext") && message.contains("duplicate"),
            "the error must name the duplicated key: {message}"
        );
    }

    /// A map key that could escape the exact-key lookup is a malformed
    /// configuration, not a profile that failed validation.
    #[test]
    fn profile_map_invalid_bundle_id_is_config() {
        let temp = TempDir::new().unwrap();
        let (app, _appex) = create_bundle_with_appex(temp.path());
        let ext_profile = temp.path().join("ext.mobileprovision");
        std::fs::write(&ext_profile, EXT_PROFILE_FIXTURE).unwrap();

        let err = IpaSigner::new_adhoc()
            .allow_unsafe_profile(true)
            .bundle_profiles(vec![("com.test.app/../escape".to_string(), ext_profile)])
            .sign_folder_in_place(&app)
            .expect_err("a traversing map key must be rejected");
        assert!(
            matches!(&err, Error::Core(zsign_core::Error::Config(_))),
            "a map-key rejection is a config error, got: {err:?}"
        );
        let message = err.to_string();
        assert!(
            message.contains("com.test.app/../escape"),
            "the error must name the offending bundle id: {message}"
        );
    }

    #[test]
    fn test_profile_map_missing_profile_file_names_path() {
        let temp = TempDir::new().unwrap();
        let (app, _appex) = create_bundle_with_appex(temp.path());
        let missing = temp.path().join("nope.mobileprovision");

        let err = IpaSigner::new_adhoc()
            .bundle_profiles(vec![("com.test.app.ext".to_string(), missing)])
            .sign_folder_in_place(&app)
            .expect_err("an unreadable mapped profile must fail the sign");
        let message = err.to_string();
        assert!(
            message.contains("nope.mobileprovision") && message.contains("com.test.app.ext"),
            "the error must name both the bundle and the path: {message}"
        );
    }

    /// A development profile: `TESTTEAM` prefix, a keychain group carrying the
    /// bundle id, and `ProvisionedDevices` (the development marker).
    const DEV_PROFILE_FIXTURE: &[u8] = br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Entitlements</key>
  <dict>
    <key>application-identifier</key>
    <string>TESTTEAM.com.test.app</string>
    <key>keychain-access-groups</key>
    <array>
      <string>TESTTEAM.com.test.app</string>
      <string>TESTTEAM.sharedgroup</string>
    </array>
    <key>get-task-allow</key>
    <true/>
    <key>com.apple.security.application-groups</key>
    <array><string>group.com.test.shared</string></array>
  </dict>
  <key>TeamIdentifier</key>
  <array><string>TESTTEAM</string></array>
  <key>ProvisionedDevices</key>
  <array><string>00008030-000000000000001E</string></array>
  <key>ExpirationDate</key>
  <date>2099-01-01T00:00:00Z</date>
</dict></plist>"#;

    /// The same profile without `ProvisionedDevices`: a distribution profile.
    const DIST_PROFILE_FIXTURE: &[u8] = br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Entitlements</key>
  <dict>
    <key>application-identifier</key>
    <string>TESTTEAM.com.test.app</string>
    <key>get-task-allow</key>
    <true/>
  </dict>
  <key>TeamIdentifier</key>
  <array><string>TESTTEAM</string></array>
  <key>ExpirationDate</key>
  <date>2099-01-01T00:00:00Z</date>
</dict></plist>"#;

    /// Root `com.test.app` + `PlugIns/Ext.appex` (`com.test.app.ext`) +
    /// `Watch/1/Companion.app` carrying a `WKCompanionAppBundleIdentifier`, plus
    /// an `NSExtension → NSExtensionAttributes → WKAppBundleIdentifier` chain.
    fn create_bundle_with_watch(dir: &Path) -> PathBuf {
        let (app, _appex) = create_bundle_with_appex(dir);
        let watch = app.join("Watch").join("1").join("Companion.app");
        std::fs::create_dir_all(&watch).unwrap();
        std::fs::write(
            watch.join("Info.plist"),
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
    <key>CFBundleIdentifier</key><string>com.test.app.watch</string>
    <key>CFBundleExecutable</key><string>Companion</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>WKCompanionAppBundleIdentifier</key><string>com.test.app</string>
    <key>NSExtension</key>
    <dict>
        <key>NSExtensionPointIdentifier</key><string>com.apple.watchkit</string>
        <key>NSExtensionAttributes</key>
        <dict>
            <key>WKAppBundleIdentifier</key><string>com.test.app.watch</string>
            <key>WKWatchOnly</key><true/>
        </dict>
    </dict>
</dict></plist>"#,
        )
        .unwrap();
        std::fs::write(watch.join("Companion"), fixtures::make_minimal_macho()).unwrap();
        app
    }

    /// The watch app's `WKCompanionAppBundleIdentifier` after signing.
    fn watch_companion_id(app: &Path) -> String {
        let data = std::fs::read(app.join("Watch/1/Companion.app/Info.plist")).unwrap();
        let value: plist::Value = plist::from_bytes(&data).unwrap();
        value
            .as_dictionary()
            .unwrap()
            .get("WKCompanionAppBundleIdentifier")
            .unwrap()
            .as_string()
            .unwrap()
            .to_string()
    }

    /// The watch companion's `NSExtensionAttributes.WKAppBundleIdentifier`.
    fn watch_wk_app_bundle_id(app: &Path) -> String {
        let data = std::fs::read(app.join("Watch/1/Companion.app/Info.plist")).unwrap();
        let value: plist::Value = plist::from_bytes(&data).unwrap();
        value
            .as_dictionary()
            .unwrap()
            .get("NSExtension")
            .unwrap()
            .as_dictionary()
            .unwrap()
            .get("NSExtensionAttributes")
            .unwrap()
            .as_dictionary()
            .unwrap()
            .get("WKAppBundleIdentifier")
            .unwrap()
            .as_string()
            .unwrap()
            .to_string()
    }

    /// A sibling bundle whose id merely STARTS WITH the root id
    /// (`com.test.app` vs `com.test.appprefixguard`) but is not a sub-id of it.
    fn plant_prefix_guard_sibling(app: &Path) -> PathBuf {
        let sibling = app.join("PlugIns").join("Guard.appex");
        std::fs::create_dir_all(&sibling).unwrap();
        std::fs::write(
            sibling.join("Info.plist"),
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
    <key>CFBundleIdentifier</key><string>com.test.appprefixguard</string>
    <key>CFBundleExecutable</key><string>Guard</string>
    <key>CFBundlePackageType</key><string>XPC!</string>
</dict></plist>"#,
        )
        .unwrap();
        std::fs::write(sibling.join("Guard"), fixtures::make_minimal_macho()).unwrap();
        sibling
    }

    #[test]
    fn test_without_bundle_id_change_entitlements_not_reserialized() {
        let temp = TempDir::new().unwrap();
        let app = create_bundle_with_appex(temp.path()).0;
        let profile = temp.path().join("dev.mobileprovision");
        std::fs::write(&profile, DEV_PROFILE_FIXTURE).unwrap();
        let ent_xml = zsign_core::extract_entitlements_from_profile(DEV_PROFILE_FIXTURE)
            .unwrap()
            .unwrap();
        let dir = temp.path().join("ents");
        std::fs::create_dir_all(&dir).unwrap();
        // The directory entry is stored as a BINARY plist. Canonical XML
        // round-trips byte-identically through the transform's re-
        // serialization, so only a differently-encoded input makes "the
        // transform never ran" observable: the transform would emit XML,
        // while the untouched pass forwards these exact bytes into the slot.
        let ent_value: plist::Value = plist::from_bytes(&ent_xml).unwrap();
        let mut churned = Vec::new();
        plist::to_writer_binary(&mut churned, &ent_value).expect("binary plist encodes");
        std::fs::write(dir.join("com.test.app.plist"), &churned).unwrap();

        IpaSigner::new_adhoc()
            .allow_unsafe_profile(true)
            .provisioning_profile(&profile)
            .entitlements_dir(&dir)
            .sign_folder_in_place(&app)
            .expect("signing without a bundle-id change must succeed");

        let blob = signature_slot_blob(
            &app.join("Test"),
            zsign_core::codesign::constants::CSSLOT_ENTITLEMENTS,
        )
        .expect("entitlements slot must exist");
        assert_eq!(
            &blob[8..],
            churned.as_slice(),
            "with no -b the signed slot must carry the directory entry's exact bytes, not a re-serialization"
        );
        let ents = plist::Value::from_reader(std::io::Cursor::new(&blob[8..]))
            .unwrap()
            .into_dictionary()
            .unwrap();
        assert_eq!(
            ents.get("application-identifier")
                .unwrap()
                .as_string()
                .unwrap(),
            "TESTTEAM.com.test.app",
            "with no -b the app id keeps the directory entry's value"
        );
        assert!(
            ents.contains_key("get-task-allow"),
            "with no -b a development-shaped directory entry keeps get-task-allow"
        );
    }

    /// Legacy-only app-id entitlements: `com.apple.application-identifier`
    /// with no canonical `application-identifier` key.
    const LEGACY_APPID_PROFILE_FIXTURE: &[u8] = br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Entitlements</key>
  <dict>
    <key>com.apple.application-identifier</key>
    <string>TESTTEAM.com.test.app</string>
  </dict>
  <key>TeamIdentifier</key>
  <array><string>TESTTEAM</string></array>
  <key>ExpirationDate</key>
  <date>2099-01-01T00:00:00Z</date>
</dict></plist>"#;

    #[test]
    fn test_bundle_id_change_rewrites_legacy_app_id_key() {
        let temp = TempDir::new().unwrap();
        let app = create_bundle_with_appex(temp.path()).0;
        let profile = temp.path().join("legacy.mobileprovision");
        std::fs::write(&profile, LEGACY_APPID_PROFILE_FIXTURE).unwrap();

        IpaSigner::new_adhoc()
            .allow_unsafe_profile(true)
            .provisioning_profile(&profile)
            .bundle_id("com.new.app")
            .sign_folder_in_place(&app)
            .expect("a bundle-id change must sign");

        let ents = entitlements_slot_dict(&app.join("Test"))
            .expect("the root binary must carry entitlements");
        assert_eq!(
            ents.get("com.apple.application-identifier")
                .unwrap()
                .as_string()
                .unwrap(),
            "TESTTEAM.com.new.app",
            "the legacy key must be updated in place"
        );
        assert!(
            !ents.contains_key("application-identifier"),
            "creating the canonical key is out of scope for a legacy-only profile"
        );
        // The 8-byte slot header is binary, so only the payload is scanned.
        let blob = signature_slot_blob(
            &app.join("Test"),
            zsign_core::codesign::constants::CSSLOT_ENTITLEMENTS,
        )
        .unwrap();
        let payload = String::from_utf8_lossy(&blob[8..]);
        assert!(
            !payload.contains("com.test.app"),
            "no stale old id may survive anywhere in the entitlements: {payload}"
        );
    }

    #[test]
    fn test_plistless_extension_errors_like_head() {
        // A plist-less `.appex` matches the extension arm of
        // is_nested_bundle_dir, so the sign loop reaches it and HEAD's
        // get_bundle_identifier error surfaces. The tolerant skip belongs ONLY
        // to the cascade preview, which runs earlier — if the preview errored
        // instead, the message would be a bare IO error, not this one.
        for bundle_id in [None, Some("com.new.app")] {
            let temp = TempDir::new().unwrap();
            let app = create_bundle_with_appex(temp.path()).0;
            std::fs::create_dir_all(app.join("PlugIns").join("Empty.appex")).unwrap();

            let mut signer = IpaSigner::new_adhoc();
            if let Some(id) = bundle_id {
                signer = signer.bundle_id(id);
            }
            let err = signer
                .sign_folder_in_place(&app)
                .expect_err("a nested bundle with no Info.plist must fail the sign");
            assert!(
                err.to_string().contains("Info.plist not found in bundle"),
                "the error must be HEAD's, and independent of the trigger: {err}"
            );
        }
    }

    #[test]
    fn test_rewrite_nested_identifiers_tolerates_plistless_bundle() {
        // Pinned at the method itself: through the sign path this bundle is
        // already rejected by plan build, so the cascade's tolerant skip would
        // otherwise be unobservable.
        let temp = TempDir::new().unwrap();
        let (app, appex) = create_bundle_with_appex(temp.path());
        let empty = app.join("PlugIns").join("Empty.appex");
        std::fs::create_dir_all(&empty).unwrap();

        IpaSigner::new_adhoc()
            .rewrite_nested_identifiers(
                &FsStore,
                &[(app.clone(), 0), (appex.clone(), 1), (empty.clone(), 1)],
                &app,
                "com.test.app",
                "com.new.app",
            )
            .expect("a plist-less extension must be skipped, not error");

        let value: plist::Value =
            plist::from_bytes(&std::fs::read(appex.join("Info.plist")).unwrap()).unwrap();
        assert_eq!(
            value
                .as_dictionary()
                .unwrap()
                .get("CFBundleIdentifier")
                .unwrap()
                .as_string()
                .unwrap(),
            "com.new.app.ext",
            "the sibling bundle must still be cascaded"
        );
    }

    #[test]
    fn test_entitlements_override_shields_invalid_dir_file() {
        let temp = TempDir::new().unwrap();
        let app = create_folder_bundle(temp.path(), "Test", true);
        std::fs::write(app.join("Info.plist"), FIXTURE_PLIST_FOR_OVERRIDE).unwrap();
        std::fs::write(app.join("Test"), fixtures::make_minimal_macho()).unwrap();

        // The directory holds a GARBAGE entry for this very bundle id, so a
        // losing tier is able to fail the sign unless the winning override
        // short-circuits the lookup (design §3.2 precedence).
        let dir = temp.path().join("ents");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("com.test.app.plist"), b"not a plist").unwrap();
        let override_ents = temp.path().join("custom.entitlements");
        std::fs::write(
            &override_ents,
            r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
    <key>com.zsign.override.wins</key><true/>
</dict></plist>"#,
        )
        .unwrap();

        IpaSigner::new_adhoc()
            .entitlements(&override_ents)
            .entitlements_dir(&dir)
            .sign_folder_in_place(&app)
            .expect("a winning -e override must shield the directory tier");

        let blob = signature_slot_blob(
            &app.join("Test"),
            zsign_core::codesign::constants::CSSLOT_ENTITLEMENTS,
        )
        .expect("the root binary must carry the override");
        assert!(
            String::from_utf8_lossy(&blob).contains("com.zsign.override.wins"),
            "the override must be the signed entitlements: {blob:?}"
        );
    }

    /// Info.plist declaring `com.test.app`, for the override-shielding test.
    const FIXTURE_PLIST_FOR_OVERRIDE: &[u8] = br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleExecutable</key><string>Test</string>
  <key>CFBundleIdentifier</key><string>com.test.app</string>
</dict></plist>"#;

    #[test]
    fn test_bundle_id_change_rejection_leaves_every_plist_untouched() {
        let temp = TempDir::new().unwrap();
        let (app, _appex) = create_bundle_with_appex(temp.path());
        let root_before = std::fs::read(app.join("Info.plist")).unwrap();
        let appex_before = std::fs::read(app.join("PlugIns/Ext.appex/Info.plist")).unwrap();
        let profile = temp.path().join("ext.mobileprovision");
        std::fs::write(&profile, EXT_PROFILE_FIXTURE).unwrap();

        // A map entry naming the appex's NEW id plus one bogus key: the bogus
        // key must be rejected before ANY plist is written.
        let err = IpaSigner::new_adhoc()
            .allow_unsafe_profile(true)
            .bundle_profiles(vec![
                ("com.new.app.ext".to_string(), profile.clone()),
                ("com.new.app.nope".to_string(), profile),
            ])
            .bundle_id("com.new.app")
            .sign_folder_in_place(&app)
            .expect_err("an unused map key must fail the sign");
        assert!(
            err.to_string().contains("com.new.app.nope"),
            "the error must still name the unused key: {err}"
        );
        assert_eq!(
            std::fs::read(app.join("Info.plist")).unwrap(),
            root_before,
            "an option rejection must leave the root plist byte-untouched"
        );
        assert_eq!(
            std::fs::read(app.join("PlugIns/Ext.appex/Info.plist")).unwrap(),
            appex_before,
            "an option rejection must leave nested plists byte-untouched"
        );
    }

    #[test]
    fn test_bundle_id_change_never_rewrites_prefix_lookalike_sibling() {
        let temp = TempDir::new().unwrap();
        let app = create_bundle_with_appex(temp.path()).0;
        let sibling = plant_prefix_guard_sibling(&app);

        IpaSigner::new_adhoc()
            .bundle_id("com.new.app")
            .sign_folder_in_place(&app)
            .expect("signing must succeed");

        let data = std::fs::read(sibling.join("Info.plist")).unwrap();
        let value: plist::Value = plist::from_bytes(&data).unwrap();
        assert_eq!(
            value
                .as_dictionary()
                .unwrap()
                .get("CFBundleIdentifier")
                .unwrap()
                .as_string()
                .unwrap(),
            "com.test.appprefixguard",
            "an id that merely starts with the old root is not a sub-id and must not move"
        );
    }

    #[test]
    fn test_without_bundle_id_change_nested_identifiers_untouched() {
        let temp = TempDir::new().unwrap();
        let app = create_bundle_with_appex(temp.path()).0;
        let before = std::fs::read(app.join("PlugIns/Ext.appex/Info.plist")).unwrap();

        IpaSigner::new_adhoc()
            .sign_folder_in_place(&app)
            .expect("signing without a bundle-id change must succeed");

        assert_eq!(
            std::fs::read(app.join("PlugIns/Ext.appex/Info.plist")).unwrap(),
            before,
            "with no -b a nested Info.plist must not be re-serialized at all"
        );
    }

    #[test]
    fn test_bundle_id_change_rewrites_nested_identifiers() {
        let temp = TempDir::new().unwrap();
        let app = create_bundle_with_watch(temp.path());
        // The Watch companion must be discovered as a nested bundle, or the
        // cascade would legitimately never see it.
        let bundles = IpaSigner::new_adhoc()
            .collect_nested_bundles(&FsStore, &app)
            .unwrap();
        assert!(
            bundles
                .iter()
                .any(|(p, _)| p.ends_with("Watch/1/Companion.app")),
            "the watch companion must be a discovered nested bundle: {bundles:?}"
        );

        IpaSigner::new_adhoc()
            .bundle_id("com.new.app")
            .sign_folder_in_place(&app)
            .expect("a bundle-id change must sign");

        let appex: plist::Value =
            plist::from_bytes(&std::fs::read(app.join("PlugIns/Ext.appex/Info.plist")).unwrap())
                .unwrap();
        assert_eq!(
            appex
                .as_dictionary()
                .unwrap()
                .get("CFBundleIdentifier")
                .unwrap()
                .as_string()
                .unwrap(),
            "com.new.app.ext",
            "a sub-id of the old root must follow the new prefix"
        );
        assert_eq!(
            watch_companion_id(&app),
            "com.new.app",
            "WKCompanionAppBundleIdentifier must cascade"
        );
        assert_eq!(
            watch_wk_app_bundle_id(&app),
            "com.new.app.watch",
            "the nested NSExtensionAttributes WKAppBundleIdentifier must cascade"
        );
        // A key that was absent must not be invented by the rewrite.
        let watch: plist::Value = plist::from_bytes(
            &std::fs::read(app.join("Watch/1/Companion.app/Info.plist")).unwrap(),
        )
        .unwrap();
        assert!(
            watch
                .as_dictionary()
                .unwrap()
                .get("WKAppBundleIdentifier")
                .is_none(),
            "a top-level WKAppBundleIdentifier that never existed must stay absent"
        );
    }

    #[test]
    fn test_bundle_id_change_rewrites_entitlements_identifiers() {
        let temp = TempDir::new().unwrap();
        let app = create_bundle_with_appex(temp.path()).0;
        let profile = temp.path().join("dev.mobileprovision");
        std::fs::write(&profile, DEV_PROFILE_FIXTURE).unwrap();

        IpaSigner::new_adhoc()
            .allow_unsafe_profile(true)
            .provisioning_profile(&profile)
            .bundle_id("com.new.app")
            .sign_folder_in_place(&app)
            .expect("a bundle-id change must sign");

        let ents = entitlements_slot_dict(&app.join("Test"))
            .expect("the root binary must carry entitlements");
        assert_eq!(
            ents.get("application-identifier")
                .unwrap()
                .as_string()
                .unwrap(),
            "TESTTEAM.com.new.app",
            "the app id must follow the new bundle id"
        );
        let groups: Vec<String> = ents
            .get("keychain-access-groups")
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_string().unwrap().to_string())
            .collect();
        assert_eq!(
            groups,
            vec![
                "TESTTEAM.com.new.app".to_string(),
                "TESTTEAM.sharedgroup".to_string()
            ],
            "only the group carrying the old id is rewritten; the shared one is kept"
        );
        assert!(
            ents.contains_key("get-task-allow"),
            "a development profile keeps get-task-allow"
        );
    }

    #[test]
    fn test_distribution_profile_drops_get_task_allow() {
        let temp = TempDir::new().unwrap();
        let app = create_bundle_with_appex(temp.path()).0;
        let profile = temp.path().join("dist.mobileprovision");
        std::fs::write(&profile, DIST_PROFILE_FIXTURE).unwrap();

        IpaSigner::new_adhoc()
            .allow_unsafe_profile(true)
            .provisioning_profile(&profile)
            .bundle_id("com.new.app")
            .sign_folder_in_place(&app)
            .expect("a bundle-id change must sign");

        let ents = entitlements_slot_dict(&app.join("Test"))
            .expect("the root binary must carry entitlements");
        assert_eq!(
            ents.get("application-identifier")
                .unwrap()
                .as_string()
                .unwrap(),
            "TESTTEAM.com.new.app",
            "the app id must still be rewritten"
        );
        assert!(
            !ents.contains_key("get-task-allow"),
            "a distribution profile must not carry get-task-allow"
        );
    }

    #[test]
    fn test_app_groups_never_rewritten() {
        let temp = TempDir::new().unwrap();
        let app = create_bundle_with_appex(temp.path()).0;
        let profile = temp.path().join("dev.mobileprovision");
        std::fs::write(&profile, DEV_PROFILE_FIXTURE).unwrap();

        IpaSigner::new_adhoc()
            .allow_unsafe_profile(true)
            .provisioning_profile(&profile)
            .bundle_id("com.new.app")
            .sign_folder_in_place(&app)
            .expect("a bundle-id change must sign");

        let ents = entitlements_slot_dict(&app.join("Test"))
            .expect("the root binary must carry entitlements");
        let groups: Vec<String> = ents
            .get("com.apple.security.application-groups")
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_string().unwrap().to_string())
            .collect();
        assert_eq!(
            groups,
            vec!["group.com.test.shared".to_string()],
            "app groups are outside the rewrite set and must be byte-preserved"
        );
    }

    #[test]
    fn test_nested_app_id_uses_own_profile_prefix() {
        let temp = TempDir::new().unwrap();
        let (app, appex) = create_bundle_with_appex(temp.path());
        // The appex's mapped profile carries a DIFFERENT prefix than the root's,
        // so the own-profile tier must win over the root tier.
        let ext_profile = temp.path().join("ext.mobileprovision");
        std::fs::write(
            &ext_profile,
            br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Entitlements</key>
  <dict>
    <key>application-identifier</key>
    <string>TESTTEAM2.com.test.app.ext</string>
    <key>get-task-allow</key>
    <true/>
  </dict>
  <key>TeamIdentifier</key>
  <array><string>TESTTEAM2</string></array>
  <key>ProvisionedDevices</key>
  <array><string>00008030-000000000000001E</string></array>
  <key>ExpirationDate</key>
  <date>2099-01-01T00:00:00Z</date>
</dict></plist>"#,
        )
        .unwrap();
        let root_profile = temp.path().join("root.mobileprovision");
        std::fs::write(&root_profile, OVERRIDE_TEST_PROFILE).unwrap();

        IpaSigner::new_adhoc()
            .provisioning_profile(&root_profile)
            .allow_unsafe_profile(true)
            // The map is keyed by the post-rewrite id, exactly as the sibling
            // integration test pins.
            .bundle_profiles(vec![("com.new.app.ext".to_string(), ext_profile)])
            .bundle_id("com.new.app")
            .sign_folder_in_place(&app)
            .expect("a bundle-id change must sign");

        let ents =
            entitlements_slot_dict(&appex.join("Ext")).expect("the appex must carry entitlements");
        assert_eq!(
            ents.get("application-identifier")
                .unwrap()
                .as_string()
                .unwrap(),
            "TESTTEAM2.com.new.app.ext",
            "a nested bundle's app id must use ITS OWN profile's prefix"
        );
    }

    #[test]
    fn test_bundle_id_change_child_profile_resolves_by_rewritten_id() {
        let temp = TempDir::new().unwrap();
        let (app, appex) = create_bundle_with_appex(temp.path());
        let ext_profile = temp.path().join("ext.mobileprovision");
        std::fs::write(&ext_profile, EXT_PROFILE_FIXTURE).unwrap();

        // The map key is the POST-rewrite id, so the cascade must run before
        // plan build for this to resolve at all.
        IpaSigner::new_adhoc()
            .allow_unsafe_profile(true)
            .bundle_profiles(vec![("com.new.app.ext".to_string(), ext_profile.clone())])
            .bundle_id("com.new.app")
            .sign_folder_in_place(&app)
            .expect("the mapped profile must resolve by the rewritten id");

        assert_eq!(
            std::fs::read(appex.join("embedded.mobileprovision")).unwrap(),
            std::fs::read(&ext_profile).unwrap(),
            "the appex must embed the profile mapped to its rewritten id"
        );
    }

    /// The entitlements blob of `binary` parsed as a plist dictionary. A
    /// superblob slot entry carries an 8-byte magic+length header ahead of the
    /// payload, so it is stripped before parsing.
    fn entitlements_slot_dict(binary: &Path) -> Option<plist::Dictionary> {
        let blob =
            signature_slot_blob(binary, zsign_core::codesign::constants::CSSLOT_ENTITLEMENTS)?;
        let value: plist::Value = plist::from_bytes(&blob[8..]).ok()?;
        value.as_dictionary().cloned()
    }

    #[test]
    fn test_without_bundle_id_change_entitlements_verbatim() {
        let temp = TempDir::new().unwrap();
        let app = create_bundle_with_appex(temp.path()).0;
        let profile = temp.path().join("dev.mobileprovision");
        std::fs::write(&profile, DEV_PROFILE_FIXTURE).unwrap();
        let before = std::fs::read(&profile).unwrap();

        IpaSigner::new_adhoc()
            .allow_unsafe_profile(true)
            .provisioning_profile(&profile)
            .sign_folder_in_place(&app)
            .expect("signing without a bundle-id change must succeed");

        let ents = entitlements_slot_dict(&app.join("Test"))
            .expect("the root binary must carry entitlements");
        assert_eq!(
            ents.get("application-identifier")
                .unwrap()
                .as_string()
                .unwrap(),
            "TESTTEAM.com.test.app",
            "with no -b the app id must be left exactly as the profile has it"
        );
        assert!(
            ents.contains_key("get-task-allow"),
            "with no -b get-task-allow must be left alone"
        );
        assert_eq!(
            std::fs::read(&profile).unwrap(),
            before,
            "the profile bytes on disk are never modified"
        );
    }

    #[test]
    fn test_remove_embedded_profile_strips_every_bundle() {
        let temp = TempDir::new().unwrap();
        let (app, appex) = create_bundle_with_appex(temp.path());
        // Source-shipped profiles: junk bytes at the root and in the appex.
        let root_profile = app.join("embedded.mobileprovision");
        let appex_profile = appex.join("embedded.mobileprovision");
        std::fs::write(&root_profile, b"junk root profile").unwrap();
        std::fs::write(&appex_profile, b"junk appex profile").unwrap();

        IpaSigner::new_adhoc()
            .remove_embedded_profile(true)
            .sign_folder_in_place(&app)
            .expect("signing with -R must succeed");

        assert!(
            !root_profile.exists(),
            "the root embedded.mobileprovision must be stripped"
        );
        assert!(
            !appex_profile.exists(),
            "a nested embedded.mobileprovision must be stripped too"
        );

        // The result self-seals: CodeResources is computed after the strip, so
        // no missing/mismatched entry may name the removed file. The walk
        // covers the ROOT and every nested bundle — signing is deepest-first,
        // so a strip-after-seal regression would poison the APPEX's own
        // CodeResources, which a root-only check cannot see. Only this
        // dimension is asserted: the self-signed test certificate is not
        // anchored to a trusted root, so full `valid()` fails by construction.
        let report = crate::verify::verify_bundle(&app).expect("verify must run");
        let bundle = report
            .bundle
            .as_ref()
            .expect("verify must report the bundle");
        let sealed: Vec<&crate::verify::BundleVerification> = std::iter::once(bundle)
            .chain(bundle.nested.iter())
            .collect();
        assert!(
            sealed.iter().any(|b| b.path.contains("Ext.appex")),
            "the appex must be among the verified nested bundles, or this walk \
             proves nothing about it: {:?}",
            sealed.iter().map(|b| &b.path).collect::<Vec<_>>()
        );
        let mut findings: Vec<String> = Vec::new();
        for b in &sealed {
            let Some(resources) = b.code_resources.as_ref() else {
                continue;
            };
            findings.extend(
                resources
                    .missing
                    .iter()
                    .chain(resources.mismatched.iter())
                    .chain(resources.unsealed.iter())
                    .map(|f| format!("{}: {f}", b.path)),
            );
        }
        assert!(
            !findings
                .iter()
                .any(|f| f.contains("embedded.mobileprovision")),
            "the stripped profile must not appear in any bundle's CodeResources \
             findings: {findings:?}"
        );
    }

    #[test]
    fn test_remove_embedded_profile_failure_names_the_path() {
        let temp = TempDir::new().unwrap();
        let (app, _appex) = create_bundle_with_appex(temp.path());
        // A DIRECTORY at the profile path: `fs::remove_file` answers
        // IsADirectory, which is neither Ok nor NotFound, so this reaches the
        // strip's error arm deterministically and without depending on DAC or
        // on the test not running as root (the same idiom as the Task 2
        // non-regular-entry pin).
        let stuck = app.join("embedded.mobileprovision");
        std::fs::create_dir(&stuck).unwrap();

        let err = IpaSigner::new_adhoc()
            .remove_embedded_profile(true)
            .sign_folder_in_place(&app)
            .expect_err("an unremovable profile must fail the sign");

        let message = err.to_string();
        assert!(
            message.contains("failed to remove embedded provisioning profile"),
            "the error must name the failure: {message}"
        );
        assert!(
            message.contains("embedded.mobileprovision"),
            "the error must name the offending file: {message}"
        );
        assert!(
            message.contains("-R"),
            "the error must say which option produced it: {message}"
        );
    }

    #[test]
    fn test_remove_embedded_profile_skips_embed_but_keeps_derived_entitlements() {
        let temp = TempDir::new().unwrap();
        let (app, appex) = create_bundle_with_appex(temp.path());
        let root_profile = temp.path().join("root.mobileprovision");
        std::fs::write(&root_profile, OVERRIDE_TEST_PROFILE).unwrap();
        let ext_profile = temp.path().join("ext.mobileprovision");
        std::fs::write(&ext_profile, EXT_PROFILE_FIXTURE).unwrap();

        // Derive-but-don't-embed: entitlements still come from the profiles, but
        // no profile bytes are written and none are left behind.
        IpaSigner::new_adhoc()
            .allow_unsafe_profile(true)
            .provisioning_profile(&root_profile)
            .bundle_profiles(vec![("com.test.app.ext".to_string(), ext_profile)])
            .remove_embedded_profile(true)
            .sign_folder_in_place(&app)
            .expect("signing with profiles and -R must succeed");

        assert!(
            !app.join("embedded.mobileprovision").exists(),
            "the root profile must not be embedded under -R"
        );
        assert!(
            !appex.join("embedded.mobileprovision").exists(),
            "the mapped profile must not be embedded under -R"
        );

        let root_blob = signature_slot_blob(
            &app.join("Test"),
            zsign_core::codesign::constants::CSSLOT_ENTITLEMENTS,
        )
        .expect("the root binary must still carry derived entitlements");
        assert!(
            String::from_utf8_lossy(&root_blob).contains("com.zsign.profile.entitlement"),
            "the root entitlements are still derived from the profile: {root_blob:?}"
        );
        let appex_blob = signature_slot_blob(
            &appex.join("Ext"),
            zsign_core::codesign::constants::CSSLOT_ENTITLEMENTS,
        )
        .expect("the appex binary must still carry derived entitlements");
        assert!(
            String::from_utf8_lossy(&appex_blob).contains("com.zsign.ext.ent"),
            "the appex entitlements are still derived from its mapped profile: {appex_blob:?}"
        );
    }

    /// A profile with no CMS envelope is never signed, whatever its fields.
    #[test]
    fn sign_ipa_bytes_rejects_forged_profile() {
        let err = IpaSigner::new(&crate::test_util::test_credentials())
            .provisioning_profile_bytes(FORGED_PROFILE_XML.as_bytes().to_vec())
            .sign_ipa_bytes(&test_ipa_bytes(&[]))
            .expect_err("a CMS-less profile must not sign");
        assert!(
            matches!(err, Error::Core(zsign_core::Error::Verification(_))),
            "a profile without a CMS envelope must fail verification, got: {err}"
        );
    }

    /// The path arm of the root profile must behave like the bytes arm: a
    /// CMS-less profile keeps the verification class, and the failure names
    /// the file the signer actually read.
    #[test]
    fn sign_ipa_path_profile_forged_keeps_verification_class_and_names_path() {
        let temp = TempDir::new().unwrap();
        let forged = temp.path().join("forged.mobileprovision");
        std::fs::write(&forged, FORGED_PROFILE_XML).unwrap();

        let err = IpaSigner::new(&crate::test_util::test_credentials())
            .provisioning_profile(&forged)
            .sign_ipa_bytes(&test_ipa_bytes(&[]))
            .expect_err("a CMS-less profile must not sign");
        assert!(
            matches!(&err, Error::Core(zsign_core::Error::Verification(_))),
            "the path arm must keep the verification class, got: {err:?}"
        );
        assert!(
            err.to_string().contains("forged.mobileprovision"),
            "the validation failure must name the profile file: {err}"
        );
    }

    /// The bypass is the only way the same forged bytes sign.
    #[test]
    fn sign_ipa_bytes_accepts_forged_profile_with_explicit_bypass() {
        IpaSigner::new(&crate::test_util::test_credentials())
            .provisioning_profile_bytes(FORGED_PROFILE_XML.as_bytes().to_vec())
            .allow_unsafe_profile(true)
            .sign_ipa_bytes(&test_ipa_bytes(&[]))
            .expect("the explicit bypass signs the same forged bytes");
    }

    /// A CMS-valid profile whose chain is anchored by an injected root signs
    /// and is embedded in the output bundle.
    #[test]
    fn sign_ipa_bytes_accepts_valid_profile_with_injected_anchors() {
        let signed = IpaSigner::new(&crate::test_util::test_credentials())
            .provisioning_profile_bytes(profile_fixture_bytes(VALID_PROFILE_B64))
            .profile_anchors(profile_fixture_anchors())
            .sign_ipa_bytes(&test_ipa_bytes(&[]))
            .expect("a CMS-valid profile with injected anchors must sign");
        assert!(
            zip_entry_names(&signed).contains(&"Payload/Test.app/embedded.mobileprovision".into()),
            "the validated profile must be embedded in the root bundle, got: {:?}",
            zip_entry_names(&signed)
        );
    }

    /// Each rejected profile must name the gate that rejected it, so an
    /// unrelated failure (CMS, parsing) can never satisfy these tests.
    #[test]
    fn sign_ipa_bytes_rejects_expired_profile() {
        let err = sign_with_fixture_profile(EXPIRED_PROFILE_B64);
        assert!(
            matches!(err, Error::Core(zsign_core::Error::ProvisioningProfile(_))),
            "an expired profile must fail the profile gate, got: {err}"
        );
        let msg = err.to_string();
        for expected in ["\"Valid Fixture\"", "expired"] {
            assert!(
                msg.contains(expected),
                "the expiry gate must name the profile and the gate, got: {msg}"
            );
        }
    }

    #[test]
    fn sign_ipa_bytes_rejects_wrong_team_profile() {
        let err = sign_with_fixture_profile(WRONG_TEAM_PROFILE_B64);
        assert!(
            matches!(err, Error::Core(zsign_core::Error::ProvisioningProfile(_))),
            "a foreign-team profile must fail the profile gate, got: {err}"
        );
        let msg = err.to_string();
        for expected in ["\"Wrong Team Fixture\"", "not the signing team TESTTEAM"] {
            assert!(
                msg.contains(expected),
                "the team gate must name the profile and the gate, got: {msg}"
            );
        }
    }

    #[test]
    fn sign_ipa_bytes_rejects_wrong_app_id_profile() {
        let err = sign_with_fixture_profile(WRONG_APP_PROFILE_B64);
        assert!(
            matches!(err, Error::Core(zsign_core::Error::ProvisioningProfile(_))),
            "a profile for another app id must fail the profile gate, got: {err}"
        );
        let msg = err.to_string();
        for expected in [
            "\"Wrong App Fixture\"",
            "App ID TESTTEAM.com.other.app does not cover bundle identifier com.test.app",
        ] {
            assert!(
                msg.contains(expected),
                "the App-ID gate must name the profile and the gate, got: {msg}"
            );
        }
    }

    /// Signs the fixture IPA with one CMS fixture profile, anchored to the
    /// fixture root; returns the error so each test can pin its own gate.
    fn sign_with_fixture_profile(b64: &str) -> Error {
        IpaSigner::new(&crate::test_util::test_credentials())
            .provisioning_profile_bytes(profile_fixture_bytes(b64))
            .profile_anchors(profile_fixture_anchors())
            .sign_ipa_bytes(&test_ipa_bytes(&[]))
            .expect_err("this profile must be rejected")
    }
}
