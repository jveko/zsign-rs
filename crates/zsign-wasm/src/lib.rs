//! WASM bindings for zsign iOS code signing.
//!
//! This crate provides WASM-compatible utilities for iOS app bundle signing:
//! - Certificate and credential loading from PKCS#12 (.p12) files
//! - Provisioning profile entitlement extraction
//! - Mach-O binary signing (SHA-256-only default for thin input; dual SHA-1+SHA-256 via `sign_macho_fat`, incl. FAT/Universal)
//! - CodeResources hash computation (including streaming for large files)
//! - Mach-O binary parsing and metadata inspection
//! - Whole-IPA bytes-to-bytes signing (`sign_ipa`)
//!
//! All cryptographic operations use pure-Rust RustCrypto implementations,
//! making this crate fully compatible with `wasm32-unknown-unknown`.
//!
//! ## Error codes
//!
//! Every thrown error is a real JavaScript `Error` carrying a stable string
//! `error.code` property. Match on `error.code`; `error.message` is human-facing
//! and may change.
//!
//! | Code | When it occurs |
//! | --- | --- |
//! | `ZSIGN_INVALID_MACHO` | Mach-O parsing or binary-format validation fails. |
//! | `ZSIGN_ENCRYPTED_BINARY` | FairPlay-encrypted binaries are rejected. |
//! | `ZSIGN_SIGNING_FAILED` | Signing cannot be completed. |
//! | `ZSIGN_INVALID_CERTIFICATE` | The signing certificate is invalid. |
//! | `ZSIGN_INVALID_PASSWORD` | A PKCS#12 or private-key password is incorrect. |
//! | `ZSIGN_MISSING_CREDENTIALS` | Required signing credentials are missing. |
//! | `ZSIGN_CONFIG` | Signing configuration is invalid. |
//! | `ZSIGN_INVALID_PROFILE` | The provisioning profile is invalid. |
//! | `ZSIGN_INVALID_PLIST` | An Info.plist is malformed or is not a dictionary. |
//! | `ZSIGN_DER_ENCODING` | A value cannot be DER-encoded. |
//! | `ZSIGN_VERIFICATION` | Signature verification fails. |
//! | `ZSIGN_INPUT_TOO_LARGE` | An input exceeds its surface-specific size limit. |
//! | `ZSIGN_INVALID_ENTITLEMENTS` | Entitlements are malformed or unsupported. |
//! | `ZSIGN_UNFINISHED_HASHES` | CodeResources are built with unfinished streams. |
//! | `ZSIGN_PATH_ALREADY_FINALIZED` | A finalized resource path is reused before reset. |
//! | `ZSIGN_PATH_IN_PROGRESS` | A streamed resource path is hashed directly. |
//! | `ZSIGN_FAT_UNSUPPORTED` | FAT input is passed to thin signing. |
//! | `ZSIGN_INTERNAL` | An internal JavaScript object operation fails. |
//! | `ZSIGN_SIGNING_FAILED` / `ZSIGN_INPUT_TOO_LARGE` | `sign_ipa` archive and size failures map to `ZSIGN_SIGNING_FAILED` (malformed archive) and `ZSIGN_INPUT_TOO_LARGE` (the IPA, per-entry, and total-uncompressed caps); profile validation during plan build can surface `ZSIGN_VERIFICATION` or `ZSIGN_INVALID_PROFILE`. |

use sha1::{Digest as _, Sha1};
use sha2::Sha256;
use std::collections::{HashMap, HashSet};
use time::OffsetDateTime;
use wasm_bindgen::prelude::*;
use zsign_core::bundle::CodeResourcesBuilder;
use zsign_core::crypto::SigningCredentials;
use zsign_core::extract_entitlements_checked;
use zsign_core::provisioning::ProfileRequest;

/// Verification instant for profile validation: the browser clock on wasm32
/// (the core resolver hard-errors on an omitted instant there), and `None` on
/// native targets, where the resolver falls back to the wall clock.
fn host_now() -> Option<OffsetDateTime> {
    #[cfg(target_arch = "wasm32")]
    {
        let ms = js_sys::Date::now();
        OffsetDateTime::from_unix_timestamp_nanos((ms as i128) * 1_000_000).ok()
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        None
    }
}

/// Maximum size of a single Mach-O input (parse/sign): the wasm32 address
/// space is 4 GiB and signing peaks at roughly 2-3x the input.
const MAX_MACHO_BYTES: usize = 512 * 1024 * 1024;
/// Maximum size of one `hash_file` buffer or one `hash_file_chunk` chunk.
/// Larger content must be streamed chunk-wise.
const MAX_HASH_BYTES: usize = 128 * 1024 * 1024;
/// Maximum size of plist inputs (Info.plist, CodeResources, entitlements).
const MAX_PLIST_BYTES: usize = 16 * 1024 * 1024;
/// Maximum size of a provisioning profile.
const MAX_PROFILE_BYTES: usize = 16 * 1024 * 1024;
/// Maximum size of a PKCS#12 file.
const MAX_P12_BYTES: usize = 4 * 1024 * 1024;
/// Maximum size of a whole IPA input to `sign_ipa` (compressed bytes).
/// Matches `MAX_MACHO_BYTES`; the uncompressed entry budget is enforced
/// inside the pipeline (512 MiB per entry, 2 GiB total).
const MAX_IPA_BYTES: usize = 512 * 1024 * 1024;

/// Stable, machine-readable error categories exposed as `Error.code`.
/// This is a public contract and changes only across major versions; message
/// text is intended for humans and may change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WasmErrorCode {
    InvalidMachO,
    EncryptedBinary,
    SigningFailed,
    InvalidCertificate,
    InvalidPassword,
    MissingCredentials,
    Config,
    InvalidProfile,
    InvalidPlist,
    DerEncoding,
    Verification,
    InputTooLarge,
    InvalidEntitlements,
    UnfinishedHashes,
    PathAlreadyFinalized,
    PathInProgress,
    FatUnsupported,
    Internal,
}

impl WasmErrorCode {
    fn as_str(self) -> &'static str {
        match self {
            Self::InvalidMachO => "ZSIGN_INVALID_MACHO",
            Self::EncryptedBinary => "ZSIGN_ENCRYPTED_BINARY",
            Self::SigningFailed => "ZSIGN_SIGNING_FAILED",
            Self::InvalidCertificate => "ZSIGN_INVALID_CERTIFICATE",
            Self::InvalidPassword => "ZSIGN_INVALID_PASSWORD",
            Self::MissingCredentials => "ZSIGN_MISSING_CREDENTIALS",
            Self::Config => "ZSIGN_CONFIG",
            Self::InvalidProfile => "ZSIGN_INVALID_PROFILE",
            Self::InvalidPlist => "ZSIGN_INVALID_PLIST",
            Self::DerEncoding => "ZSIGN_DER_ENCODING",
            Self::Verification => "ZSIGN_VERIFICATION",
            Self::InputTooLarge => "ZSIGN_INPUT_TOO_LARGE",
            Self::InvalidEntitlements => "ZSIGN_INVALID_ENTITLEMENTS",
            Self::UnfinishedHashes => "ZSIGN_UNFINISHED_HASHES",
            Self::PathAlreadyFinalized => "ZSIGN_PATH_ALREADY_FINALIZED",
            Self::PathInProgress => "ZSIGN_PATH_IN_PROGRESS",
            Self::FatUnsupported => "ZSIGN_FAT_UNSUPPORTED",
            Self::Internal => "ZSIGN_INTERNAL",
        }
    }
}

/// Categorizes core errors exhaustively by design: a new
/// `zsign_core::Error` variant must fail to compile until it is assigned a
/// stable public code.
fn code_for_core_error(e: &zsign_core::Error) -> WasmErrorCode {
    match e {
        zsign_core::Error::MachO(_) | zsign_core::Error::Goblin(_) => WasmErrorCode::InvalidMachO,
        zsign_core::Error::EncryptedBinary(_) => WasmErrorCode::EncryptedBinary,
        zsign_core::Error::Signing(_) => WasmErrorCode::SigningFailed,
        zsign_core::Error::Certificate(_) => WasmErrorCode::InvalidCertificate,
        zsign_core::Error::InvalidPassword => WasmErrorCode::InvalidPassword,
        zsign_core::Error::MissingCredentials(_) => WasmErrorCode::MissingCredentials,
        zsign_core::Error::Config(_) => WasmErrorCode::Config,
        zsign_core::Error::ProvisioningProfile(_) => WasmErrorCode::InvalidProfile,
        zsign_core::Error::Plist(_) => WasmErrorCode::InvalidPlist,
        zsign_core::Error::DerEncoding(_) => WasmErrorCode::DerEncoding,
        zsign_core::Error::Verification(_) => WasmErrorCode::Verification,
        zsign_core::Error::InputTooLarge(_) => WasmErrorCode::InputTooLarge,
    }
}

/// Maps the native crate's error enum onto the stable public codes.
/// Exhaustive by construction: a new `zsign_rs::Error` variant must fail to
/// compile until it is assigned a code.
fn code_for_zsign_error(e: &zsign_rs::Error) -> WasmErrorCode {
    match e {
        zsign_rs::Error::Core(inner) => code_for_core_error(inner),
        zsign_rs::Error::Plist(_) => WasmErrorCode::InvalidPlist,
        zsign_rs::Error::MissingCredentials(_) => WasmErrorCode::MissingCredentials,
        zsign_rs::Error::InputTooLarge(_) => WasmErrorCode::InputTooLarge,
        zsign_rs::Error::Zip(_) => WasmErrorCode::SigningFailed,
        zsign_rs::Error::Io(_) => WasmErrorCode::SigningFailed,
        zsign_rs::Error::SymlinkNotSupported => WasmErrorCode::SigningFailed,
    }
}

fn js_err(code: WasmErrorCode, message: impl std::fmt::Display) -> JsValue {
    let err = js_sys::Error::new(&message.to_string());
    let _ = js_sys::Reflect::set(
        &err,
        &JsValue::from_str("code"),
        &JsValue::from_str(code.as_str()),
    );
    err.into()
}

fn core_err(e: zsign_core::Error) -> JsValue {
    let code = code_for_core_error(&e);
    js_err(code, e)
}

/// `from_p12` wraps every PKCS#12 failure as `Error::Certificate`. A MAC
/// mismatch is a password-layer outcome for the standard unencrypted-authSafe
/// flow, proven across all nine core fixtures; a decryption failure is the
/// corresponding password-layer outcome for encrypted-authSafe or no-MAC
/// files. A wrong password that degenerates into a malformed-ASN.1 parse error
/// carries no password signal and degrades to the generic certificate code.
fn p12_err(e: zsign_core::Error) -> JsValue {
    let code = if [
        "invalid PKCS#12 password (MAC mismatch)",
        "PKCS#12 decryption failed",
    ]
    .iter()
    .any(|marker| e.to_string().contains(marker))
    {
        WasmErrorCode::InvalidPassword
    } else {
        code_for_core_error(&e)
    };
    js_err(code, e)
}

fn ensure_size(len: usize, max: usize, surface: &str, remedy: &str) -> Result<(), JsValue> {
    if len <= max {
        return Ok(());
    }
    Err(js_err(
        WasmErrorCode::InputTooLarge,
        format!("{surface} input too large: {len} bytes exceeds the {max}-byte limit; {remedy}"),
    ))
}

/// In-progress streaming hash state for a single file.
struct StreamingHashState {
    sha1: Sha1,
    sha256: Sha256,
}

/// Metadata extracted from a parsed Mach-O binary.
#[wasm_bindgen]
pub struct MachOInfo {
    is_fat: bool,
    slices_count: usize,
}

#[wasm_bindgen]
impl MachOInfo {
    #[wasm_bindgen(getter)]
    pub fn is_fat(&self) -> bool {
        self.is_fat
    }

    #[wasm_bindgen(getter)]
    pub fn slices_count(&self) -> usize {
        self.slices_count
    }
}

#[wasm_bindgen]
pub struct WasmSigner {
    credentials: SigningCredentials,
    profile_entitlements: Option<Vec<u8>>,
    profile_bytes: Option<Vec<u8>>,
    entitlements_override: Option<Vec<u8>>,
    /// Whether CMS/expiry/team validation of the profile is bypassed; `true`
    /// keeps the historical raw byte scan. Defaults to `false`, so a forged or
    /// expired profile is rejected rather than parsed. App-ID coverage is not
    /// checkable here: the bundle id is unknown at construction, and the IPA
    /// path checks it at plan build.
    allow_unsafe_profile: bool,
    resource_builder: CodeResourcesBuilder,
    streaming_hashes: HashMap<String, StreamingHashState>,
    main_executable: Option<String>,
    finalized_paths: HashSet<String>,
}

#[wasm_bindgen]
impl WasmSigner {
    /// Create a new signer from a PKCS#12 (.p12) file, optionally extracting entitlements from a provisioning profile.
    ///
    /// `allow_unsafe_profile` skips CMS/expiry/team validation of the profile
    /// and keeps the historical raw byte scan. It defaults to `false`, so a
    /// forged or expired profile is rejected rather than parsed.
    #[wasm_bindgen(constructor)]
    pub fn new(
        p12_bytes: &[u8],
        p12_password: &str,
        profile_bytes: Option<Vec<u8>>,
        allow_unsafe_profile: Option<bool>,
    ) -> Result<WasmSigner, JsValue> {
        ensure_size(
            p12_bytes.len(),
            MAX_P12_BYTES,
            "WasmSigner constructor (p12_bytes)",
            "supply a smaller PKCS#12",
        )?;
        if let Some(profile) = &profile_bytes {
            ensure_size(
                profile.len(),
                MAX_PROFILE_BYTES,
                "WasmSigner constructor (profile_bytes)",
                "supply a smaller provisioning profile",
            )?;
        }

        let credentials = SigningCredentials::from_p12(p12_bytes, p12_password).map_err(p12_err)?;

        let allow = allow_unsafe_profile.unwrap_or(false);
        let entitlements = match profile_bytes.as_deref() {
            Some(data) => {
                let request = ProfileRequest {
                    now: host_now(),
                    anchors: None,
                    expected_team_id: credentials.team_id.clone(),
                    target_bundle_id: None,
                    target_device_udid: None,
                };
                extract_entitlements_checked(data, &request, allow).map_err(core_err)?
            }
            None => None,
        };

        Ok(WasmSigner {
            credentials,
            profile_bytes,
            allow_unsafe_profile: allow,
            profile_entitlements: entitlements,
            entitlements_override: None,
            main_executable: None,
            resource_builder: CodeResourcesBuilder::new(),
            streaming_hashes: HashMap::new(),
            finalized_paths: HashSet::new(),
        })
    }

    /// Get the effective entitlements: the override when set, otherwise the
    /// profile-derived entitlements (if any).
    pub fn entitlements(&self) -> Option<Vec<u8>> {
        self.effective_entitlements().map(<[u8]>::to_vec)
    }

    /// Override the entitlements used for signing.
    ///
    /// `Some(bytes)` must be an XML or binary plist dictionary whose values
    /// the signer can encode to DER (strings, booleans, integers, arrays,
    /// dictionaries, data, dates — Real is rejected here rather than at sign
    /// time) — it replaces the profile-derived entitlements until cleared.
    /// `None` clears the override, falling back to the profile-derived
    /// entitlements. To sign with no entitlements while holding a profile,
    /// construct the signer without profile bytes instead.
    pub fn set_entitlements(&mut self, data: Option<Vec<u8>>) -> Result<(), JsValue> {
        match data {
            Some(bytes) => {
                ensure_size(
                    bytes.len(),
                    MAX_PLIST_BYTES,
                    "set_entitlements",
                    "entitlements must be a compact plist dictionary",
                )?;

                let value: plist::Value = plist::from_bytes(&bytes).map_err(|e| {
                    js_err(
                        WasmErrorCode::InvalidEntitlements,
                        format!("entitlements must be a valid XML or binary plist dictionary: {e}"),
                    )
                })?;
                if value.as_dictionary().is_none() {
                    return Err(js_err(
                        WasmErrorCode::InvalidEntitlements,
                        "entitlements plist must contain a top-level dictionary",
                    ));
                }
                zsign_core::codesign::der::plist_to_der(&bytes).map_err(|e| {
                    js_err(
                        WasmErrorCode::InvalidEntitlements,
                        format!("entitlements contain types the signer cannot encode: {e}"),
                    )
                })?;
                self.entitlements_override = Some(bytes);
            }
            None => self.entitlements_override = None,
        }
        Ok(())
    }

    fn effective_entitlements(&self) -> Option<&[u8]> {
        self.entitlements_override
            .as_deref()
            .or(self.profile_entitlements.as_deref())
    }

    /// Set the main executable name for CodeResources exclusion.
    pub fn set_main_executable(&mut self, name: &str) {
        self.main_executable = Some(name.to_string());
        self.resource_builder.set_main_executable(name);
    }

    /// Hash a complete file for CodeResources (small files).
    ///
    /// Returns `true` if the file was added, `false` if it was excluded.
    /// Throws when the buffer exceeds 128 MiB; stream large files with
    /// `hash_file_chunk` instead. Throws when the path has an unfinished
    /// streaming hash or was already finalized in this resources round.
    pub fn hash_file(&mut self, relative_path: &str, data: &[u8]) -> Result<bool, JsValue> {
        ensure_size(
            data.len(),
            MAX_HASH_BYTES,
            "hash_file",
            "stream large files with hash_file_chunk(...)",
        )?;
        if self.streaming_hashes.contains_key(relative_path) {
            return Err(js_err(
                WasmErrorCode::PathInProgress,
                format!(
                    "path \"{relative_path}\" has an unfinished streaming hash; finalize it with hash_file_chunk(..., true) before hashing it directly"
                ),
            ));
        }
        if self.finalized_paths.contains(relative_path) {
            return Err(js_err(
                WasmErrorCode::PathAlreadyFinalized,
                format!(
                    "path \"{relative_path}\" was already finalized in this resources round; call reset_resources() before hashing it again"
                ),
            ));
        }
        let (sha1, sha256) = CodeResourcesBuilder::hash_data(data);
        let added = self.resource_builder.add_file(relative_path, sha1, sha256);
        if added {
            self.finalized_paths.insert(relative_path.to_string());
        }
        Ok(added)
    }

    /// Start or continue streaming hash for a large file.
    ///
    /// There may be one stream per path in each resources round. A final call
    /// seals a stored path, after which all further calls for it throw until
    /// `reset_resources()` starts a new round. Setting `is_final` on the first
    /// call is a legal single-chunk stream. Excluded paths are never stored or
    /// sealed and remain re-callable. Two non-final streams for the same path
    /// cannot be distinguished and merge, so callers must use one stream per
    /// path. Throws when a chunk exceeds 128 MiB; send smaller chunks instead.
    ///
    pub fn hash_file_chunk(
        &mut self,
        relative_path: &str,
        chunk: &[u8],
        is_final: bool,
    ) -> Result<(), JsValue> {
        ensure_size(
            chunk.len(),
            MAX_HASH_BYTES,
            "hash_file_chunk",
            "send smaller chunks",
        )?;
        if self.finalized_paths.contains(relative_path) {
            return Err(js_err(
                WasmErrorCode::PathAlreadyFinalized,
                format!(
                    "path \"{relative_path}\" was already finalized in this resources round; call reset_resources() before hashing it again"
                ),
            ));
        }
        let state = self
            .streaming_hashes
            .entry(relative_path.to_string())
            .or_insert_with(|| StreamingHashState {
                sha1: Sha1::new(),
                sha256: Sha256::new(),
            });

        state.sha1.update(chunk);
        state.sha256.update(chunk);

        if is_final {
            if let Some(state) = self.streaming_hashes.remove(relative_path) {
                let sha1_result = state.sha1.finalize();
                let sha256_result = state.sha256.finalize();

                let mut sha1 = [0u8; 20];
                let mut sha256 = [0u8; 32];
                sha1.copy_from_slice(&sha1_result);
                sha256.copy_from_slice(&sha256_result);

                if self.resource_builder.add_file(relative_path, sha1, sha256) {
                    self.finalized_paths.insert(relative_path.to_string());
                }
            }
        }
        Ok(())
    }

    /// Register a symlink in CodeResources.
    ///
    /// Returns `true` if the symlink was added, `false` if it was excluded.
    /// Duplicate symlink paths retain last-wins semantics; symlink registration
    /// is outside the file-path sealing state machine.
    pub fn add_symlink(&mut self, relative_path: &str, target: &str) -> bool {
        let target_bytes = target.as_bytes();
        let (sha1, sha256) = CodeResourcesBuilder::hash_data(target_bytes);
        self.resource_builder
            .add_symlink(relative_path, target, sha1, sha256)
    }

    /// Build and return the CodeResources plist bytes.
    pub fn build_code_resources(&self) -> Result<Vec<u8>, JsValue> {
        if !self.streaming_hashes.is_empty() {
            let pending: Vec<_> = self.streaming_hashes.keys().collect();
            return Err(js_err(
                WasmErrorCode::UnfinishedHashes,
                format!(
                    "Cannot build CodeResources: {} unfinished streaming hashes: {:?}",
                    pending.len(),
                    pending
                ),
            ));
        }
        self.resource_builder.build().map_err(core_err)
    }

    /// Start a new resources round, clearing the builder, active streams, and
    /// finalized-path seals. The main-executable exclusion is a bundle-layout
    /// property and is preserved across resets; call `set_main_executable`
    /// again to point at a different executable.
    pub fn reset_resources(&mut self) {
        self.resource_builder = CodeResourcesBuilder::new();
        if let Some(name) = self.main_executable.clone() {
            self.resource_builder.set_main_executable(name);
        }
        self.streaming_hashes.clear();
        self.finalized_paths.clear();
    }

    /// Extract entitlements from a provisioning profile.
    ///
    /// `allow_unsafe_profile` skips CMS/expiry validation and keeps the
    /// historical raw byte scan. It defaults to `false`; the team is never
    /// checked here because this static surface holds no credentials, and
    /// App-ID coverage is not checkable either — the caller has no bundle id.
    pub fn extract_entitlements(
        profile_data: &[u8],
        allow_unsafe_profile: Option<bool>,
    ) -> Result<Option<Vec<u8>>, JsValue> {
        ensure_size(
            profile_data.len(),
            MAX_PROFILE_BYTES,
            "extract_entitlements",
            "supply a smaller provisioning profile",
        )?;

        let request = ProfileRequest {
            now: host_now(),
            anchors: None,
            expected_team_id: None,
            target_bundle_id: None,
            target_device_udid: None,
        };
        extract_entitlements_checked(
            profile_data,
            &request,
            allow_unsafe_profile.unwrap_or(false),
        )
        .map_err(core_err)
    }

    /// Parse a Mach-O binary and return metadata.
    pub fn parse_macho(data: Vec<u8>) -> Result<MachOInfo, JsValue> {
        ensure_size(
            data.len(),
            MAX_MACHO_BYTES,
            "parse_macho",
            "use the native zsign CLI for larger binaries",
        )?;

        let macho = zsign_core::macho::MachOFile::parse(data).map_err(core_err)?;
        Ok(MachOInfo {
            is_fat: macho.is_fat(),
            slices_count: macho.slices().len(),
        })
    }

    /// Get the team ID extracted from the signing certificate.
    pub fn team_id(&self) -> Option<String> {
        self.credentials.team_id.clone()
    }

    /// Sign a thin (single-arch) Mach-O binary with a SHA-256-only code directory. FAT/Universal input is rejected — call `sign_macho_fat` to opt into dual SHA-1+SHA-256 signing. Returns the signed binary bytes.
    pub fn sign_macho(
        &self,
        data: Vec<u8>,
        identifier: &str,
        info_plist: Option<Vec<u8>>,
        code_resources: Option<Vec<u8>>,
    ) -> Result<Vec<u8>, JsValue> {
        ensure_size(
            data.len(),
            MAX_MACHO_BYTES,
            "sign_macho",
            "use the native zsign CLI for larger binaries",
        )?;
        if let Some(pl) = &info_plist {
            ensure_size(
                pl.len(),
                MAX_PLIST_BYTES,
                "sign_macho (info_plist)",
                "supply a smaller Info.plist",
            )?;
        }
        if let Some(cr) = &code_resources {
            ensure_size(
                cr.len(),
                MAX_PLIST_BYTES,
                "sign_macho (code_resources)",
                "supply smaller CodeResources",
            )?;
        }

        let macho = zsign_core::macho::MachOFile::parse(data).map_err(core_err)?;
        if macho.is_fat() {
            return Err(js_err(
                WasmErrorCode::FatUnsupported,
                "FAT/Universal input is not supported by SHA-256-only signing; call sign_macho_fat() to opt into dual SHA-1+SHA-256 signing explicitly",
            ));
        }
        let entitlements: Option<&[u8]> = self.effective_entitlements();
        zsign_core::macho::sign_macho_sha256_only(
            &macho,
            identifier,
            entitlements,
            &self.credentials,
            info_plist.as_deref(),
            code_resources.as_deref(),
            false,
        )
        .map_err(core_err)
    }

    /// Sign a Mach-O binary (thin or FAT/Universal) with dual SHA-1+SHA-256 code directories. Returns the signed binary bytes.
    pub fn sign_macho_fat(
        &self,
        data: Vec<u8>,
        identifier: &str,
        info_plist: Option<Vec<u8>>,
        code_resources: Option<Vec<u8>>,
    ) -> Result<Vec<u8>, JsValue> {
        ensure_size(
            data.len(),
            MAX_MACHO_BYTES,
            "sign_macho_fat",
            "use the native zsign CLI for larger binaries",
        )?;
        if let Some(pl) = &info_plist {
            ensure_size(
                pl.len(),
                MAX_PLIST_BYTES,
                "sign_macho_fat (info_plist)",
                "supply a smaller Info.plist",
            )?;
        }
        if let Some(cr) = &code_resources {
            ensure_size(
                cr.len(),
                MAX_PLIST_BYTES,
                "sign_macho_fat (code_resources)",
                "supply smaller CodeResources",
            )?;
        }

        let macho = zsign_core::macho::MachOFile::parse(data).map_err(core_err)?;
        zsign_core::macho::sign_any_macho(
            &macho,
            identifier,
            self.effective_entitlements(),
            &self.credentials,
            info_plist.as_deref(),
            code_resources.as_deref(),
            false,
        )
        .map_err(core_err)
    }

    /// Parse an Info.plist (XML or binary) and return bundle ID and executable name.
    ///
    /// Returns a JS object with string fields `bundle_id` and `executable`; each
    /// defaults to the empty string when the key is absent.
    pub fn parse_info_plist(data: &[u8]) -> Result<JsValue, JsValue> {
        ensure_size(
            data.len(),
            MAX_PLIST_BYTES,
            "parse_info_plist",
            "supply a smaller Info.plist",
        )?;

        let plist_value: plist::Value = plist::from_bytes(data).map_err(|e| {
            js_err(
                WasmErrorCode::InvalidPlist,
                format!("Failed to parse Info.plist: {}", e),
            )
        })?;

        let dict = plist_value.as_dictionary().ok_or_else(|| {
            js_err(
                WasmErrorCode::InvalidPlist,
                "Info.plist is not a dictionary",
            )
        })?;

        let bundle_id = dict
            .get("CFBundleIdentifier")
            .and_then(|v| v.as_string())
            .unwrap_or("");

        let executable = dict
            .get("CFBundleExecutable")
            .and_then(|v| v.as_string())
            .unwrap_or("");

        let js_obj = js_sys::Object::new();
        js_sys::Reflect::set(&js_obj, &"bundle_id".into(), &bundle_id.into())
            .map_err(|_| js_err(WasmErrorCode::Internal, "Failed to set bundle_id"))?;
        js_sys::Reflect::set(&js_obj, &"executable".into(), &executable.into())
            .map_err(|_| js_err(WasmErrorCode::Internal, "Failed to set executable"))?;

        Ok(js_obj.into())
    }

    /// Signs a complete IPA in memory and returns the signed IPA bytes —
    /// no JS-side zip handling needed.
    ///
    /// Options: `bundle_id`/`bundle_name`/`bundle_version` rewrite the root
    /// bundle's Info.plist keys before signing; `compression_level` (0-9,
    /// default 6) selects the output zip compression.
    ///
    /// Limits: input ≤ 512 MiB; declared uncompressed total ≤ 2 GiB
    /// (`ZSIGN_INPUT_TOO_LARGE`). Peak memory ≈ input + uncompressed tree +
    /// output plus per-file signing working set, with one ABI copy of the
    /// input and one of the output; linear memory never shrinks, so large
    /// signs leave a per-tab watermark. Desktop-class browsers are
    /// recommended above ~100 MiB inputs.
    ///
    /// Errors: stable codes per the module table; malformed archives map to
    /// `ZSIGN_SIGNING_FAILED`.
    pub fn sign_ipa(
        &self,
        input: &[u8],
        bundle_id: Option<String>,
        bundle_name: Option<String>,
        bundle_version: Option<String>,
        compression_level: Option<u8>,
    ) -> Result<Vec<u8>, JsValue> {
        ensure_size(
            input.len(),
            MAX_IPA_BYTES,
            "IPA input",
            "split or reduce the archive before signing",
        )?;

        let mut signer = zsign_rs::ipa::IpaSigner::new(&self.credentials);
        if let Some(data) = &self.profile_bytes {
            signer = signer.provisioning_profile_bytes(data.clone());
        }
        if self.allow_unsafe_profile {
            signer = signer.allow_unsafe_profile(true);
        }
        if let Some(now) = host_now() {
            signer = signer.profile_now(now);
        }
        if let Some(data) = &self.entitlements_override {
            signer = signer.entitlements_bytes(data.clone());
        }
        if let Some(id) = bundle_id {
            signer = signer.bundle_id(id);
        }
        if let Some(name) = bundle_name {
            signer = signer.bundle_name(name);
        }
        if let Some(version) = bundle_version {
            signer = signer.bundle_version(version);
        }
        if let Some(level) = compression_level {
            signer = signer.compression_level(zsign_rs::CompressionLevel::new(level.into()));
        }
        signer
            .sign_ipa_bytes(input)
            .map_err(|e| js_err(code_for_zsign_error(&e), format!("sign_ipa failed: {e}")))
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use sha1::Sha1;
    use sha2::Sha256;
    use wasm_bindgen_test::*;
    use zsign_core::macho::fixtures;

    // Self-issued code-signing leaf generated with openssl: RSA-2048, CA:FALSE,
    // digitalSignature, codeSigning EKU, validity 2026-09-25 to 2036-09-22,
    // packed as an AES-256-CBC p12 (SHA-256 mac) with password `test`. RSA
    // rather than EC on purpose: the CMS verifier parses ECDSA signatures as
    // fixed-width r||s, so the DER-encoded EC signatures that openssl and the
    // CMS builder emit never verify and the anchored round-trip assertions
    // below could never go green.
    const LEAF_P12_B64: &str = concat!(
        "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",
        "UH6cwlIqKIM1AgIIAA==",
    );

    const PROFILE_XML: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Entitlements</key>
    <dict>
        <key>get-task-allow</key>
        <true/>
        <key>application-identifier</key>
        <string>ZSN40TEST.com.zsign.test</string>
    </dict>
</dict>
</plist>
"#;

    /// Bare plist carrying a plausible but unsigned profile: no CMS envelope,
    /// an unknown team, an expired window and a foreign App ID.
    const FORGED_PROFILE_XML: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>TeamIdentifier</key>
    <array>
        <string>EVILTEAM</string>
    </array>
    <key>ExpirationDate</key>
    <date>2001-01-02T00:00:00Z</date>
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
</plist>
"#;

    fn decode_base64(s: &str) -> Vec<u8> {
        fn value(byte: u8) -> Option<u8> {
            match byte {
                b'A'..=b'Z' => Some(byte - b'A'),
                b'a'..=b'z' => Some(byte - b'a' + 26),
                b'0'..=b'9' => Some(byte - b'0' + 52),
                b'+' => Some(62),
                b'/' => Some(63),
                _ => None,
            }
        }

        let mut output = Vec::new();
        let mut accumulator = 0u32;
        let mut bits = 0u32;
        for byte in s
            .bytes()
            .filter(|byte| !byte.is_ascii_whitespace() && *byte != b'=')
        {
            let byte = value(byte).unwrap_or_else(|| panic!("invalid base64 byte {byte:#x}"));
            accumulator = (accumulator << 6) | u32::from(byte);
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                output.push((accumulator >> bits) as u8);
            }
        }
        output
    }

    fn new_signer() -> WasmSigner {
        WasmSigner::new(&decode_base64(LEAF_P12_B64), "test", None, None)
            .expect("fixture p12 loads")
    }

    /// The fixture profile is a bare plist with no CMS envelope, so it only
    /// loads under the explicit unsafe-profile opt-in.
    fn new_signer_with_profile() -> WasmSigner {
        WasmSigner::new(
            &decode_base64(LEAF_P12_B64),
            "test",
            Some(PROFILE_XML.as_bytes().to_vec()),
            Some(true),
        )
        .expect("fixture p12 + profile load")
    }

    fn err_message(err: impl Into<JsValue>) -> String {
        let value: JsValue = err.into();
        value.unchecked_into::<js_sys::Error>().message().into()
    }

    /// XML for a minimal signable Info.plist: the sign flow only reads
    /// CFBundleIdentifier and CFBundleExecutable.
    fn info_plist_xml(cf_bundle_executable: &str) -> String {
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>com.zsign.test</string>
    <key>CFBundleExecutable</key>
    {cf_bundle_executable}
</dict>
</plist>"#
        )
    }

    /// Builds a minimal IPA in-test, signs it through the bytes-to-bytes
    /// surface, and verifies the output structurally: archive shape,
    /// CodeResources presence, a verifying main-executable signature,
    /// root-entry pass-through, and re-sign determinism.
    #[wasm_bindgen_test(unsupported = test)]
    fn sign_ipa_round_trip_signs_and_verifies_structurally() {
        use std::io::Read as _;

        let input = build_test_ipa_bytes();
        let signer = new_signer();

        let output = signer
            .sign_ipa(&input, None, None, None, None)
            .expect("bytes-to-bytes IPA signing must succeed");

        // The output is a zip with Payload/ and a signed CodeResources.
        let mut archive =
            zip::ZipArchive::new(std::io::Cursor::new(&output)).expect("output must be a zip");
        let mut code_resources = Vec::new();
        {
            let mut entry = archive
                .by_name("Payload/Test.app/_CodeSignature/CodeResources")
                .expect("CodeResources must be present");
            entry.read_to_end(&mut code_resources).unwrap();
        }
        archive
            .by_name("SwiftSupport/keep.txt")
            .expect("non-Payload root entries must pass through");

        // ... and it actually seals content: parse the plist and require a
        // known non-excluded path in the legacy `files` dict (Info.plist is
        // rule-omitted from `files2`, so `files` is the honest map here).
        let cr: plist::Value =
            plist::from_bytes(&code_resources).expect("CodeResources must be a plist");
        let files = cr
            .as_dictionary()
            .and_then(|d| d.get("files"))
            .and_then(|v| v.as_dictionary())
            .expect("CodeResources must have a files dict");
        assert!(
            files.contains_key("Info.plist"),
            "CodeResources must seal Info.plist; keys: {:?}",
            files.keys().collect::<Vec<_>>()
        );

        // The main executable carries a signature that verifies against the
        // fixture credential's certificate.
        let main = {
            let mut entry = archive
                .by_name("Payload/Test.app/Test")
                .expect("main executable must be present");
            let mut buf = Vec::new();
            entry.read_to_end(&mut buf).unwrap();
            buf
        };
        let report = anchored_verify_slice(&main, 0, &signer.credentials);
        assert!(report.valid, "main executable must verify: {:?}", report);

        // Re-signing the output is byte-identical (determinism).
        let resigned = signer
            .sign_ipa(&output, None, None, None, None)
            .expect("re-sign must succeed");
        assert_eq!(output, resigned, "re-sign must be byte-identical");
    }

    /// Minimal signable IPA: Payload/Test.app with Info.plist, the
    /// minimal mach-o executable, plus a root-level pass-through entry.
    fn build_test_ipa_bytes() -> Vec<u8> {
        use std::io::Write as _;

        let mut cursor = std::io::Cursor::new(Vec::new());
        let mut zip = zip::ZipWriter::new(&mut cursor);
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        zip.start_file("Payload/Test.app/Info.plist", opts).unwrap();
        zip.write_all(info_plist_xml("<string>Test</string>").as_bytes())
            .unwrap();
        zip.start_file("Payload/Test.app/Test", opts).unwrap();
        zip.write_all(&fixtures::make_minimal_macho()).unwrap();
        zip.start_file("SwiftSupport/keep.txt", opts).unwrap();
        zip.write_all(b"pass-through").unwrap();
        zip.finish().unwrap();
        cursor.into_inner()
    }

    fn cd_layout(signed: &[u8]) -> (bool, bool) {
        let macho =
            zsign_core::macho::MachOFile::parse(signed.to_vec()).expect("signed Mach-O parses");
        let slice = &macho.slices()[0];
        let offset = slice.offset + slice.code_sig_offset.expect("code signature offset") as usize;
        let size = slice.code_sig_size.expect("code signature size") as usize;
        let superblob =
            zsign_core::codesign::verify::parse_superblob(&signed[offset..offset + size])
                .expect("embedded signature parses");
        let mut has_sha1 = superblob
            .code_directory
            .as_ref()
            .is_some_and(|cd| cd.is_sha1());
        let mut has_sha256 = superblob
            .code_directory
            .as_ref()
            .is_some_and(|cd| !cd.is_sha1());
        for cd in &superblob.alternate_code_directories {
            if cd.is_sha1() {
                has_sha1 = true;
            } else {
                has_sha256 = true;
            }
        }
        (has_sha1, has_sha256)
    }

    fn entitlements_slot(signed: &[u8]) -> Option<Vec<u8>> {
        let macho =
            zsign_core::macho::MachOFile::parse(signed.to_vec()).expect("signed Mach-O parses");
        let slice = &macho.slices()[0];
        let offset = slice.offset + slice.code_sig_offset.expect("code signature offset") as usize;
        let size = slice.code_sig_size.expect("code signature size") as usize;
        let superblob =
            zsign_core::codesign::verify::parse_superblob(&signed[offset..offset + size])
                .expect("embedded signature parses");
        superblob
            .code_directory
            .as_ref()?
            .special_slot_hash(5)
            .map(<[u8]>::to_vec)
    }

    fn anchored_verify(
        signed: &[u8],
        creds: &SigningCredentials,
    ) -> zsign_core::crypto::cms_verify::CmsVerifyReport {
        anchored_verify_slice(signed, 0, creds)
    }

    fn anchored_verify_slice(
        signed: &[u8],
        slice_idx: usize,
        creds: &SigningCredentials,
    ) -> zsign_core::crypto::cms_verify::CmsVerifyReport {
        let macho =
            zsign_core::macho::MachOFile::parse(signed.to_vec()).expect("signed Mach-O parses");
        let slice = &macho.slices()[slice_idx];
        let offset = slice.offset + slice.code_sig_offset.expect("code signature offset") as usize;
        let size = slice.code_sig_size.expect("code signature size") as usize;
        let superblob =
            zsign_core::codesign::verify::parse_superblob(&signed[offset..offset + size])
                .expect("embedded signature parses");
        let primary = superblob
            .code_directory
            .as_ref()
            .expect("primary CodeDirectory present");
        let sha1_cd = if primary.is_sha1() {
            Some(primary)
        } else {
            superblob
                .alternate_code_directories
                .iter()
                .find(|cd| cd.is_sha1())
        };
        let sha256_cd = if primary.is_sha1() {
            superblob
                .alternate_code_directories
                .iter()
                .find(|cd| !cd.is_sha1())
        } else {
            Some(primary)
        };
        let cd_sha1 = sha1_cd.map(|cd| <[u8; 20]>::from(Sha1::digest(cd.raw())));
        let cd_sha256: [u8; 32] =
            Sha256::digest(sha256_cd.expect("sha256 CodeDirectory present").raw()).into();
        let anchors = zsign_core::crypto::cms_verify::TrustAnchors::from_certificates(vec![creds
            .certificate
            .clone()]);
        zsign_core::crypto::cms_verify::verify_code_signature_with_anchors(
            superblob.cms.expect("CMS slot present"),
            primary.raw(),
            cd_sha1.as_ref(),
            &cd_sha256,
            &anchors,
        )
        .expect("cms verify runs")
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn sign_macho_default_emits_sha256_only_for_thin_input() {
        let signed = new_signer()
            .sign_macho(fixtures::make_minimal_macho(), "com.zsign.test", None, None)
            .expect("thin sign succeeds");
        assert_eq!(
            zsign_core::macho::MachOFile::parse(signed.clone())
                .expect("signed Mach-O parses")
                .slices()
                .len(),
            1
        );
        let (has_sha1, has_sha256) = cd_layout(&signed);
        assert!(
            !has_sha1,
            "default output must carry no SHA-1 CodeDirectory"
        );
        assert!(
            has_sha256,
            "default output must carry the SHA-256 CodeDirectory"
        );
        let report = anchored_verify(&signed, &new_signer().credentials);
        assert!(
            report.valid,
            "sha256-only signature must verify: {:?}",
            report.errors
        );
    }

    #[wasm_bindgen_test]
    fn sign_macho_rejects_fat_input() {
        let fat = fixtures::make_fat_macho(
            &[
                fixtures::make_minimal_macho(),
                fixtures::make_minimal_macho(),
            ],
            &[12, 12],
        );
        let err = new_signer()
            .sign_macho(fat, "com.zsign.test", None, None)
            .expect_err("FAT rejected by default");
        assert_eq!(error_code(&err), Some("ZSIGN_FAT_UNSUPPORTED".into()));
        let msg = err_message(err);
        assert!(
            msg.contains("sign_macho_fat"),
            "error must name the dual opt-in: {msg}"
        );

        let err2 = new_signer()
            .sign_macho(
                fixtures::make_fat_macho(&[fixtures::make_minimal_macho()], &[12]),
                "com.zsign.test",
                None,
                None,
            )
            .expect_err("one-slice FAT rejected by default");
        assert_eq!(error_code(&err2), Some("ZSIGN_FAT_UNSUPPORTED".into()));
        assert!(err_message(err2).contains("sign_macho_fat"));
    }

    #[wasm_bindgen_test]
    fn p12_classifier_maps_password_layer_failures() {
        let mac = zsign_core::Error::Certificate(
            "Failed to parse PKCS#12: invalid PKCS#12 password (MAC mismatch)".into(),
        );
        assert_eq!(
            error_code(&p12_err(mac)),
            Some("ZSIGN_INVALID_PASSWORD".into())
        );
        let dec = zsign_core::Error::Certificate(
            "Failed to parse PKCS#12: PKCS#12 decryption failed: bad padding".into(),
        );
        assert_eq!(
            error_code(&p12_err(dec)),
            Some("ZSIGN_INVALID_PASSWORD".into())
        );
        let other = zsign_core::Error::Certificate(
            "Failed to parse PKCS#12: malformed PKCS#12: value length exceeds input".into(),
        );
        assert_eq!(
            error_code(&p12_err(other)),
            Some("ZSIGN_INVALID_CERTIFICATE".into())
        );
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn sign_macho_fat_keeps_dual_behavior_for_thin_and_fat() {
        let signer = new_signer();
        let thin = signer
            .sign_macho_fat(fixtures::make_minimal_macho(), "com.zsign.test", None, None)
            .expect("thin dual sign");
        let (has_sha1, has_sha256) = cd_layout(&thin);
        assert!(
            has_sha1 && has_sha256,
            "dual output carries both CodeDirectories"
        );
        let report = anchored_verify(&thin, &signer.credentials);
        assert!(
            report.valid,
            "thin signature must verify: {:?}",
            report.errors
        );

        let fat = signer
            .sign_macho_fat(
                fixtures::make_fat_macho(
                    &[
                        fixtures::make_minimal_macho(),
                        fixtures::make_minimal_macho(),
                    ],
                    &[12, 12],
                ),
                "com.zsign.test",
                None,
                None,
            )
            .expect("FAT dual sign");
        assert_eq!(
            zsign_core::macho::MachOFile::parse(fat.clone())
                .expect("signed FAT Mach-O parses")
                .slices()
                .len(),
            2
        );
        for idx in 0..2 {
            assert!(
                anchored_verify_slice(&fat, idx, &signer.credentials).valid,
                "FAT slice {idx} must verify under the injected anchor"
            );
        }
    }

    /// Pins the executable/non-executable entitlements policy: non-executable
    /// input must ignore profile entitlements entirely (no entitlements slot
    /// either way), executable input must not. The non-executable assertion
    /// goes red if any entitlements slot is ever emitted for non-executables
    /// again (the pre-change state); the executable assertions go red if
    /// profile entitlements stop being applied.
    #[wasm_bindgen_test(unsupported = test)]
    fn non_executable_input_ignores_profile_entitlements() {
        let mut dylib = fixtures::make_minimal_macho();
        dylib[12..16].copy_from_slice(&6u32.to_le_bytes());
        let with = new_signer_with_profile();
        let without = new_signer();

        let a = with
            .sign_macho(dylib.clone(), "com.zsign.test", None, None)
            .expect("sign");
        let b = without
            .sign_macho(dylib.clone(), "com.zsign.test", None, None)
            .expect("sign");
        assert!(
            entitlements_slot(&a).is_none(),
            "non-executable input must emit no entitlements slot at all"
        );
        assert_eq!(
            entitlements_slot(&a),
            entitlements_slot(&b),
            "non-executable input must ignore profile entitlements"
        );

        let c = with
            .sign_macho(fixtures::make_minimal_macho(), "com.zsign.test", None, None)
            .expect("sign");
        let d = without
            .sign_macho(fixtures::make_minimal_macho(), "com.zsign.test", None, None)
            .expect("sign");
        assert_ne!(
            entitlements_slot(&c),
            entitlements_slot(&d),
            "executable input must carry the profile entitlements when loaded"
        );
    }

    fn parse_dict(xml: &[u8]) -> plist::Dictionary {
        let v: plist::Value = plist::from_bytes(xml).expect("fixture plist parses");
        v.as_dictionary().expect("top-level dict").clone()
    }

    const OVERRIDE_XML: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>com.example.override</key><true/>
</dict></plist>
"#;

    #[wasm_bindgen_test(unsupported = test)]
    fn entitlements_setter_overrides_then_reverts_to_profile() {
        let mut signer = new_signer_with_profile();
        let derived = signer
            .entitlements()
            .expect("profile-derived entitlements exist");
        assert!(parse_dict(&derived).contains_key("application-identifier"));

        signer
            .set_entitlements(Some(OVERRIDE_XML.as_bytes().to_vec()))
            .expect("valid dictionary accepted");
        assert_eq!(
            parse_dict(&signer.entitlements().expect("override is effective")),
            parse_dict(OVERRIDE_XML.as_bytes())
        );

        signer.set_entitlements(None).expect("clear succeeds");
        assert_eq!(
            parse_dict(&signer.entitlements().expect("profile fallback returns")),
            parse_dict(&derived)
        );
    }

    #[wasm_bindgen_test]
    fn entitlements_setter_rejects_invalid_input() {
        let mut signer = new_signer();
        let e1 = signer
            .set_entitlements(Some(b"not a plist".to_vec()))
            .expect_err("garbage rejected");
        assert_eq!(error_code(&e1), Some("ZSIGN_INVALID_ENTITLEMENTS".into()));
        assert!(err_message(e1).contains("plist dictionary"));

        let arr = br#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><array><string>x</string></array></plist>"#;
        let e2 = signer
            .set_entitlements(Some(arr.to_vec()))
            .expect_err("non-dictionary rejected");
        assert!(err_message(e2).contains("dictionary"));

        // Data and Date are encodable (OCTET STRING / GeneralizedTime), so
        // they pass eagerly and round-trip; only Real is still refused by the
        // DER encoder, and it must fail at set time rather than at sign time.
        let with_data = br#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>k</key><data>AA==</data></dict></plist>"#;
        signer
            .set_entitlements(Some(with_data.to_vec()))
            .expect("data values are DER-encodable and accepted");
        assert_eq!(
            parse_dict(&signer.entitlements().expect("data override is effective")),
            parse_dict(with_data),
            "an accepted data entitlements value must round-trip unchanged"
        );

        let with_real = br#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>k</key><real>1.5</real></dict></plist>"#;
        let e3 = signer
            .set_entitlements(Some(with_real.to_vec()))
            .expect_err("Real rejected");
        assert_eq!(error_code(&e3), Some("ZSIGN_INVALID_ENTITLEMENTS".into()));
        let m3 = err_message(e3);
        assert!(m3.contains("cannot encode"), "got: {m3}");
        assert!(m3.contains("Real"), "got: {m3}");
    }

    // ensure_size boundaries: `len` is a plain parameter, so every constant
    // is pinned without large allocations (the 513 MiB Mach-O case is never
    // allocated in CI by design — design doc item 3).
    #[wasm_bindgen_test(unsupported = test)]
    fn ensure_size_accepts_exactly_at_limit() {
        for max in [
            MAX_P12_BYTES,
            MAX_HASH_BYTES,
            MAX_PLIST_BYTES,
            MAX_PROFILE_BYTES,
            MAX_MACHO_BYTES,
        ] {
            assert!(
                ensure_size(max, max, "surface", "remedy").is_ok(),
                "at limit {max}"
            );
        }
    }

    #[wasm_bindgen_test]
    fn ensure_size_rejects_one_byte_over_every_limit() {
        for max in [
            MAX_P12_BYTES,
            MAX_HASH_BYTES,
            MAX_PLIST_BYTES,
            MAX_PROFILE_BYTES,
            MAX_MACHO_BYTES,
        ] {
            let e = ensure_size(max + 1, max, "surface", "remedy").expect_err("over limit");
            assert_eq!(error_code(&e), Some("ZSIGN_INPUT_TOO_LARGE".into()));
            let msg = err_message(e);
            assert!(
                msg.contains("too large") && msg.contains("surface"),
                "{msg}"
            );
        }
    }

    // Wiring: exactly at the limit passes the guard (and fails later at p12
    // parsing); one byte over fails with the size error. 4 MiB allocations.
    #[wasm_bindgen_test]
    fn p12_size_boundary_is_enforced() {
        let at_limit = vec![0u8; MAX_P12_BYTES];
        let e = match WasmSigner::new(&at_limit, "test", None, None) {
            Err(e) => e,
            Ok(_) => panic!("garbage still fails parsing"),
        };
        let m = err_message(e);
        assert!(
            !m.contains("too large"),
            "exactly-at-limit input must pass the size guard: {m}"
        );

        let over = vec![0u8; MAX_P12_BYTES + 1];
        let e = match WasmSigner::new(&over, "test", None, None) {
            Err(e) => e,
            Ok(_) => panic!("oversize rejected"),
        };
        let msg = err_message(e);
        assert!(
            msg.contains("too large") && msg.contains("4194304"),
            "{msg}"
        );
    }

    #[wasm_bindgen_test]
    fn hash_and_plist_surfaces_reject_oversize_input() {
        let mut signer = new_signer();
        // 129 MiB — the largest allocation kept in CI (one transient chunk)
        let e = signer
            .hash_file("big.bin", &vec![0u8; MAX_HASH_BYTES + 1])
            .expect_err("hash guard");
        assert!(
            err_message(e).contains("hash_file_chunk"),
            "remedy must name the streaming API"
        );

        let e = signer
            .hash_file_chunk("big.bin", &vec![0u8; MAX_HASH_BYTES + 1], true)
            .expect_err("chunk guard");
        assert!(err_message(e).contains("too large"));

        let e =
            WasmSigner::parse_info_plist(&vec![0u8; MAX_PLIST_BYTES + 1]).expect_err("plist guard");
        assert!(err_message(e).contains("16777216"));

        let e = WasmSigner::extract_entitlements(&vec![0u8; MAX_PROFILE_BYTES + 1], None)
            .expect_err("profile guard");
        assert!(err_message(e).contains("too large"));
    }

    // Plain #[wasm_bindgen_test] (NOT `unsupported = test`): ensure_size's
    // error path constructs the JsValue through js_err → js_sys::Error,
    // whose import shim panics on non-wasm targets. Mirrors the existing
    // error-path test ensure_size_rejects_one_byte_over_every_limit
    // (lib.rs:1222), which is also plain; the Ok-path test at lib.rs:1206
    // is the one that carries `unsupported = test`.
    #[wasm_bindgen_test]
    fn sign_ipa_size_guard_rejects_one_byte_over() {
        // Mirrors ensure_size_rejects_one_byte_over_every_limit (lib.rs:1222):
        // the guard is exercised directly rather than allocating a 513 MiB
        // input; sign_ipa applies it to input.len() as its first statement.
        ensure_size(
            MAX_IPA_BYTES,
            MAX_IPA_BYTES,
            "IPA input",
            "reduce the archive",
        )
        .expect("exactly-at-limit must pass");
        let e = ensure_size(
            MAX_IPA_BYTES + 1,
            MAX_IPA_BYTES,
            "IPA input",
            "reduce the archive",
        )
        .expect_err("one byte over the IPA limit must be rejected");
        assert_eq!(error_code(&e), Some("ZSIGN_INPUT_TOO_LARGE".into()));
    }

    // Plain #[wasm_bindgen_test] (NOT `unsupported = test`): the assertion
    // goes through js_err → js_sys::Error + Reflect, whose import shims
    // panic on non-wasm targets. This matches the crate's existing
    // js_err-touching tests and runs only under `wasm-pack test --node`.
    #[wasm_bindgen_test]
    fn sign_ipa_maps_malformed_archive_to_stable_code() {
        let signer = new_signer();
        let e = signer
            .sign_ipa(b"not a zip", None, None, None, None)
            .expect_err("malformed input must be rejected");
        assert_eq!(error_code(&e), Some("ZSIGN_SIGNING_FAILED".into()));
    }
    /// Reads the stored digests for `rel` from built CodeResources:
    /// legacy `files` maps ordinary paths to raw SHA-1 Data; `files2` maps
    /// them to a dict with `hash` (SHA-1) and `hash2` (SHA-256) Data
    /// (code_resources.rs:412-452). Returns (sha1, sha256) bytes.
    fn resource_digests(built: &[u8], rel: &str) -> (Vec<u8>, Vec<u8>) {
        let root: plist::Value = plist::from_bytes(built).expect("CodeResources is a plist");
        let dict = root.as_dictionary().expect("root dict");
        let files = dict
            .get("files")
            .and_then(|v| v.as_dictionary())
            .expect("files dict");
        let legacy = files
            .get(rel)
            .and_then(|v| v.as_data())
            .expect("legacy files maps ordinary paths to SHA-1 Data")
            .to_vec();
        let files2 = dict
            .get("files2")
            .and_then(|v| v.as_dictionary())
            .expect("files2 dict");
        let entry = files2
            .get(rel)
            .and_then(|v| v.as_dictionary())
            .expect("files2 entry dict");
        let modern = entry
            .get("hash2")
            .and_then(|v| v.as_data())
            .expect("files2 entry carries hash2 Data")
            .to_vec();
        (legacy, modern)
    }

    const CHUNK_A: &[u8] = b"first chunk of a large file ";
    const CHUNK_B: &[u8] = b"second chunk of a large file";

    #[wasm_bindgen_test(unsupported = test)]
    fn chunked_stream_hashes_full_content_once_finalized() {
        let mut signer = new_signer();
        signer
            .hash_file_chunk("stream.bin", CHUNK_A, false)
            .expect("first chunk");
        signer
            .hash_file_chunk("stream.bin", CHUNK_B, true)
            .expect("final chunk");
        let built = signer
            .build_code_resources()
            .expect("build with no pending streams");
        let mut full = CHUNK_A.to_vec();
        full.extend_from_slice(CHUNK_B);
        let (h1, h2) = resource_digests(&built, "stream.bin");
        assert_eq!(h1, Sha1::digest(&full).to_vec());
        assert_eq!(h2, Sha256::digest(&full).to_vec());
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn single_call_finalize_and_interleaved_paths_stay_correct() {
        let mut signer = new_signer();
        // single-call stream (is_final on the first call) stays legal
        signer
            .hash_file_chunk("one.bin", b"whole file", true)
            .expect("single finalize");
        // two paths interleaved across their streams
        signer.hash_file_chunk("a.bin", b"A1", false).expect("a1");
        signer.hash_file_chunk("b.bin", b"B1", false).expect("b1");
        signer
            .hash_file_chunk("a.bin", b"A2", true)
            .expect("a2 final");
        signer
            .hash_file_chunk("b.bin", b"B2", true)
            .expect("b2 final");
        let built = signer.build_code_resources().expect("build");
        let (a1, a2) = resource_digests(&built, "a.bin");
        assert_eq!(a1, Sha1::digest(b"A1A2").to_vec());
        assert_eq!(a2, Sha256::digest(b"A1A2").to_vec());
        let (b1, b2) = resource_digests(&built, "b.bin");
        assert_eq!(b1, Sha1::digest(b"B1B2").to_vec());
        assert_eq!(b2, Sha256::digest(b"B1B2").to_vec());
    }

    #[wasm_bindgen_test]
    fn double_finalize_and_post_finalize_chunks_are_rejected() {
        let mut signer = new_signer();
        signer
            .hash_file_chunk("x.bin", b"data", true)
            .expect("first finalize");

        // double finalize (previously silently re-hashed just the 2nd call)
        let e = signer
            .hash_file_chunk("x.bin", b"more", true)
            .expect_err("double finalize");
        assert_eq!(error_code(&e), Some("ZSIGN_PATH_ALREADY_FINALIZED".into()));
        assert!(err_message(e).contains("reset_resources"));

        // post-finalize chunk (previously seeded a fresh digest = silent partial hash)
        let e = signer
            .hash_file_chunk("x.bin", b"more", false)
            .expect_err("post-finalize chunk");
        let msg = err_message(e);
        assert!(
            msg.contains("already finalized") && msg.contains("reset_resources"),
            "{msg}"
        );

        // build must not contain the corrupted partial content: only "data" was sealed
        let built = signer
            .build_code_resources()
            .expect("sealed state still builds");
        let (h1, _) = resource_digests(&built, "x.bin");
        assert_eq!(h1, Sha1::digest(b"data").to_vec());
    }

    #[wasm_bindgen_test]
    fn hash_file_conflicts_with_active_or_sealed_paths() {
        let mut signer = new_signer();
        signer
            .hash_file_chunk("y.bin", b"part", false)
            .expect("stream open");
        let e = signer
            .hash_file("y.bin", b"direct")
            .expect_err("active stream conflict");
        assert_eq!(error_code(&e), Some("ZSIGN_PATH_IN_PROGRESS".into()));
        assert!(err_message(e).contains("unfinished streaming hash"));

        signer
            .hash_file_chunk("y.bin", b" rest", true)
            .expect("finalize");
        let e = signer
            .hash_file("y.bin", b"direct")
            .expect_err("sealed conflict");
        let msg = err_message(e);
        assert!(
            msg.contains("already finalized") && msg.contains("reset_resources"),
            "{msg}"
        );

        // unfinished-stream guard on build stays (stream z.bin never finalized)
        signer
            .hash_file_chunk("z.bin", b"open", false)
            .expect("open");
        let e = signer
            .build_code_resources()
            .expect_err("pending streams block build");
        assert!(err_message(e).contains("unfinished streaming hashes"));

        // reset_resources is the documented round boundary
        signer.reset_resources();
        signer
            .hash_file("y.bin", b"direct")
            .expect("sealed path reusable after reset");
        let built = signer.build_code_resources().expect("clean build");
        let (h1, _) = resource_digests(&built, "y.bin");
        assert_eq!(h1, Sha1::digest(b"direct").to_vec());
    }

    /// Excluded paths (the main executable) are never stored and never
    /// sealed: repeated `hash_file` calls keep returning `false` without
    /// throwing — the pre-lane no-op behavior is preserved.
    #[wasm_bindgen_test(unsupported = test)]
    fn excluded_paths_stay_recallable_noops() {
        let mut signer = new_signer();
        signer.set_main_executable("App");
        assert!(!signer
            .hash_file("App", b"binary bytes")
            .expect("first call ok"));
        assert!(!signer
            .hash_file("App", b"binary bytes")
            .expect("second call ok, not sealed"));
        signer.reset_resources();
        assert!(!signer
            .hash_file("App", b"binary bytes")
            .expect("still excluded after reset"));
    }

    fn error_code(err: &JsValue) -> Option<String> {
        js_sys::Reflect::get(err, &JsValue::from_str("code"))
            .ok()
            .and_then(|v| v.as_string())
    }

    #[wasm_bindgen_test]
    fn errors_carry_stable_zsign_codes_and_real_error_instances() {
        let e = match WasmSigner::new(&decode_base64(LEAF_P12_B64), "wrong-password", None, None) {
            Err(e) => e,
            Ok(_) => panic!("bad password"),
        };
        assert_eq!(error_code(&e), Some("ZSIGN_INVALID_PASSWORD".into()));

        let e = new_signer()
            .sign_macho(
                fixtures::make_fat_macho(
                    &[
                        fixtures::make_minimal_macho(),
                        fixtures::make_minimal_macho(),
                    ],
                    &[12, 12],
                ),
                "com.zsign.test",
                None,
                None,
            )
            .expect_err("fat input");
        assert_eq!(error_code(&e), Some("ZSIGN_FAT_UNSUPPORTED".into()));

        let e = match WasmSigner::new(&vec![0u8; MAX_P12_BYTES + 1], "test", None, None) {
            Err(e) => e,
            Ok(_) => panic!("oversize"),
        };
        assert_eq!(error_code(&e), Some("ZSIGN_INPUT_TOO_LARGE".into()));

        let mut signer = new_signer();
        signer.hash_file_chunk("c.bin", b"x", true).unwrap();
        let e = signer
            .hash_file_chunk("c.bin", b"y", true)
            .expect_err("sealed path");
        assert_eq!(error_code(&e), Some("ZSIGN_PATH_ALREADY_FINALIZED".into()));

        let mut signer = new_signer();
        let e = signer
            .set_entitlements(Some(b"junk".to_vec()))
            .expect_err("invalid entitlements");
        assert_eq!(error_code(&e), Some("ZSIGN_INVALID_ENTITLEMENTS".into()));

        let e = WasmSigner::parse_info_plist(b"not a plist").expect_err("bad plist");
        assert_eq!(error_code(&e), Some("ZSIGN_INVALID_PLIST".into()));

        // the thrown value is a real Error with a non-empty message
        assert!(e.is_instance_of::<js_sys::Error>());
        assert!(!err_message(e).is_empty());
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn constructor_extracts_profile_entitlements_and_team_id() {
        let signer = new_signer_with_profile();
        assert_eq!(signer.team_id().as_deref(), Some("ZSN40TEST"));
        let ents = signer.entitlements().expect("profile entitlements");
        let dict = parse_dict(&ents);
        assert_eq!(
            dict.get("application-identifier")
                .and_then(|v| v.as_string()),
            Some("ZSN40TEST.com.zsign.test")
        );
    }

    #[wasm_bindgen_test]
    fn constructor_rejects_bad_profile() {
        let e = match WasmSigner::new(
            &decode_base64(LEAF_P12_B64),
            "test",
            Some(b"<not a profile".to_vec()),
            None,
        ) {
            Ok(_) => panic!("bad profile must be rejected"),
            Err(e) => e,
        };
        // The raw-scan parse error is now a CMS-envelope verification failure.
        assert_eq!(error_code(&e), Some("ZSIGN_VERIFICATION".into()));
    }

    #[wasm_bindgen_test]
    fn constructor_rejects_forged_profile() {
        let e = match WasmSigner::new(
            &decode_base64(LEAF_P12_B64),
            "test",
            Some(FORGED_PROFILE_XML.as_bytes().to_vec()),
            None,
        ) {
            Ok(_) => panic!("an unsigned profile must be rejected"),
            Err(e) => e,
        };
        assert_eq!(error_code(&e), Some("ZSIGN_VERIFICATION".into()));
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn constructor_accepts_forged_profile_with_explicit_bypass() {
        let signer = WasmSigner::new(
            &decode_base64(LEAF_P12_B64),
            "test",
            Some(FORGED_PROFILE_XML.as_bytes().to_vec()),
            Some(true),
        )
        .expect("explicit bypass keeps the raw byte scan");
        let ents = String::from_utf8(signer.entitlements().expect("profile entitlements"))
            .expect("entitlements are utf-8");
        assert!(
            ents.contains("get-task-allow"),
            "bypassed profile entitlements must load, got: {ents}"
        );
    }

    #[wasm_bindgen_test]
    fn extract_entitlements_rejects_forged_profile() {
        let forged = FORGED_PROFILE_XML.as_bytes();
        let e = WasmSigner::extract_entitlements(forged, None).expect_err("unsigned profile");
        assert_eq!(error_code(&e), Some("ZSIGN_VERIFICATION".into()));
        let bypassed = WasmSigner::extract_entitlements(forged, Some(true))
            .expect("explicit bypass keeps the raw byte scan")
            .expect("entitlements present");
        assert!(
            String::from_utf8_lossy(&bypassed).contains("get-task-allow"),
            "bypassed extraction must return the raw-scan entitlements"
        );
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn adhoc_sign_round_trip_verifies_without_credentials() {
        let signed = zsign_core::macho::sign_macho_adhoc(
            &zsign_core::macho::MachOFile::parse(fixtures::make_minimal_macho()).unwrap(),
            "com.zsign.test",
            None,
            None,
            None,
            false,
        )
        .expect("adhoc sign");
        let report = zsign_core::macho::verify::verify_macho(
            &signed,
            &zsign_core::codesign::verify::SignatureInputs::none(),
        )
        .expect("verify report");
        let slice = &report.slices[0];
        assert!(slice.signed && slice.adhoc);
        assert_eq!(
            slice.pages,
            zsign_core::codesign::verify::PageCheck::Matched
        );
        assert!(
            report.is_valid(),
            "adhoc round-trip must verify: {:?}",
            slice.errors
        );
    }

    #[wasm_bindgen_test]
    fn parse_info_plist_handles_xml_binary_absent_keys_and_bad_input() {
        let xml = br#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
  <key>CFBundleIdentifier</key><string>com.zsign.test</string>
  <key>CFBundleExecutable</key><string>Test</string>
</dict></plist>"#;
        let v = WasmSigner::parse_info_plist(xml).expect("xml parses");
        assert_eq!(
            js_sys::Reflect::get(&v, &"bundle_id".into())
                .unwrap()
                .as_string()
                .as_deref(),
            Some("com.zsign.test")
        );
        assert_eq!(
            js_sys::Reflect::get(&v, &"executable".into())
                .unwrap()
                .as_string()
                .as_deref(),
            Some("Test")
        );

        // binary plist round-trip
        let mut dict = plist::Dictionary::new();
        dict.insert("CFBundleIdentifier".into(), "com.zsign.binary".into());
        let value = plist::Value::Dictionary(dict);
        let mut buf = Vec::new();
        plist::to_writer_binary(&mut buf, &value).expect("serialize binary plist");
        assert!(buf.starts_with(b"bplist00"));
        let v = WasmSigner::parse_info_plist(&buf).expect("binary parses");
        assert_eq!(
            js_sys::Reflect::get(&v, &"bundle_id".into())
                .unwrap()
                .as_string()
                .as_deref(),
            Some("com.zsign.binary")
        );

        // absent keys default to empty strings (matches the method docs)
        let v = WasmSigner::parse_info_plist(br#"<plist version="1.0"><dict/></plist>"#)
            .expect("empty dict");
        assert_eq!(
            js_sys::Reflect::get(&v, &"bundle_id".into())
                .unwrap()
                .as_string()
                .as_deref(),
            Some("")
        );

        // non-dictionary plist → coded error
        let e = WasmSigner::parse_info_plist(
            br#"<plist version="1.0"><array><string>x</string></array></plist>"#,
        )
        .expect_err("not a dictionary");
        assert_eq!(error_code(&e), Some("ZSIGN_INVALID_PLIST".into()));
    }
}
