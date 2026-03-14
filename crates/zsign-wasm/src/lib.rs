//! WASM bindings for zsign iOS code signing.
//!
//! This crate provides WASM-compatible utilities for iOS app bundle signing:
//! - Certificate and credential loading from PKCS#12 (.p12) files
//! - Provisioning profile entitlement extraction
//! - Mach-O binary signing (single-arch and FAT/Universal)
//! - CodeResources hash computation (including streaming for large files)
//! - Mach-O binary parsing and metadata inspection
//!
//! All cryptographic operations use pure-Rust RustCrypto implementations,
//! making this crate fully compatible with `wasm32-unknown-unknown`.

use std::collections::HashMap;
use wasm_bindgen::prelude::*;
use zsign_core::bundle::CodeResourcesBuilder;
use zsign_core::crypto::SigningCredentials;
use zsign_core::provisioning::extract_entitlements_from_profile;
use sha1::{Digest as _, Sha1};
use sha2::Sha256;

const EMPTY_ENTITLEMENTS: &[u8] = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict/>\n</plist>\n";

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
    pub fn is_fat(&self) -> bool { self.is_fat }

    #[wasm_bindgen(getter)]
    pub fn slices_count(&self) -> usize { self.slices_count }
}

#[wasm_bindgen]
pub struct WasmSigner {
    credentials: SigningCredentials,
    entitlements: Option<Vec<u8>>,
    resource_builder: CodeResourcesBuilder,
    streaming_hashes: HashMap<String, StreamingHashState>,
}

#[wasm_bindgen]
impl WasmSigner {
    /// Create a new signer from a PKCS#12 (.p12) file, optionally extracting entitlements from a provisioning profile.
    #[wasm_bindgen(constructor)]
    pub fn new(
        p12_bytes: &[u8],
        p12_password: &str,
        profile_bytes: Option<Vec<u8>>,
    ) -> Result<WasmSigner, JsError> {
        let credentials = SigningCredentials::from_p12(p12_bytes, p12_password)
            .map_err(|e| JsError::new(&e.to_string()))?;

        let entitlements = profile_bytes
            .as_deref()
            .and_then(extract_entitlements_from_profile);

        Ok(WasmSigner {
            credentials,
            entitlements,
            resource_builder: CodeResourcesBuilder::new(),
            streaming_hashes: HashMap::new(),
        })
    }

    /// Get the extracted entitlements (if any).
    pub fn entitlements(&self) -> Option<Vec<u8>> {
        self.entitlements.clone()
    }

    /// Set the main executable name for CodeResources exclusion.
    pub fn set_main_executable(&mut self, name: &str) {
        self.resource_builder.set_main_executable(name);
    }

    /// Hash a complete file for CodeResources (small files).
    ///
    /// Returns `true` if the file was added, `false` if it was excluded.
    pub fn hash_file(&mut self, relative_path: &str, data: &[u8]) -> bool {
        let (sha1, sha256) = CodeResourcesBuilder::hash_data(data);
        self.resource_builder.add_file(relative_path, sha1, sha256)
    }

    /// Start or continue streaming hash for a large file.
    pub fn hash_file_chunk(&mut self, relative_path: &str, chunk: &[u8], is_final: bool) {
        let state = self.streaming_hashes
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

                self.resource_builder.add_file(relative_path, sha1, sha256);
            }
        }
    }

    /// Register a symlink in CodeResources.
    ///
    /// Returns `true` if the symlink was added, `false` if it was excluded.
    pub fn add_symlink(&mut self, relative_path: &str, target: &str) -> bool {
        let target_bytes = target.as_bytes();
        let (sha1, sha256) = CodeResourcesBuilder::hash_data(target_bytes);
        self.resource_builder.add_symlink(relative_path, target, sha1, sha256)
    }

    /// Build and return the CodeResources plist bytes.
    pub fn build_code_resources(&self) -> Result<Vec<u8>, JsError> {
        if !self.streaming_hashes.is_empty() {
            let pending: Vec<_> = self.streaming_hashes.keys().collect();
            return Err(JsError::new(&format!(
                "Cannot build CodeResources: {} unfinished streaming hashes: {:?}",
                pending.len(), pending
            )));
        }
        self.resource_builder
            .build()
            .map_err(|e| JsError::new(&e.to_string()))
    }

    /// Reset the CodeResources builder for signing the next bundle.
    pub fn reset_resources(&mut self) {
        self.resource_builder = CodeResourcesBuilder::new();
        self.streaming_hashes.clear();
    }

    /// Extract entitlements from a provisioning profile.
    pub fn extract_entitlements(profile_data: &[u8]) -> Option<Vec<u8>> {
        extract_entitlements_from_profile(profile_data)
    }

    /// Parse a Mach-O binary and return metadata.
    pub fn parse_macho(data: Vec<u8>) -> Result<MachOInfo, JsError> {
        let macho = zsign_core::macho::MachOFile::parse(data)
            .map_err(|e| JsError::new(&e.to_string()))?;
        Ok(MachOInfo {
            is_fat: macho.is_fat(),
            slices_count: macho.slices().len(),
        })
    }

    /// Get the team ID extracted from the signing certificate.
    pub fn team_id(&self) -> Option<String> {
        self.credentials.team_id.clone()
    }

    /// Sign a Mach-O binary. Returns the signed binary bytes.
    pub fn sign_macho(
        &self,
        data: Vec<u8>,
        identifier: &str,
        info_plist: Option<Vec<u8>>,
        code_resources: Option<Vec<u8>>,
    ) -> Result<Vec<u8>, JsError> {
        let macho = zsign_core::macho::MachOFile::parse(data)
            .map_err(|e| JsError::new(&e.to_string()))?;

        let is_executable = macho.slices().first().map(|s| s.is_executable).unwrap_or(false);
        let entitlements = if is_executable {
            self.entitlements.as_deref()
        } else {
            Some(EMPTY_ENTITLEMENTS)
        };

        zsign_core::macho::sign_macho(
            &macho,
            identifier,
            entitlements,
            &self.credentials,
            info_plist.as_deref(),
            code_resources.as_deref(),
        )
        .map_err(|e| JsError::new(&e.to_string()))
    }

    /// Sign a FAT/Universal Mach-O binary. Returns the signed binary bytes.
    pub fn sign_macho_fat(
        &self,
        data: Vec<u8>,
        identifier: &str,
        info_plist: Option<Vec<u8>>,
        code_resources: Option<Vec<u8>>,
    ) -> Result<Vec<u8>, JsError> {
        let macho = zsign_core::macho::MachOFile::parse(data)
            .map_err(|e| JsError::new(&e.to_string()))?;

        let is_executable = macho.slices().first().map(|s| s.is_executable).unwrap_or(false);
        let entitlements = if is_executable {
            self.entitlements.as_deref()
        } else {
            Some(EMPTY_ENTITLEMENTS)
        };

        if macho.slices().len() == 1 {
            return zsign_core::macho::sign_macho(
                &macho,
                identifier,
                entitlements,
                &self.credentials,
                info_plist.as_deref(),
                code_resources.as_deref(),
            )
            .map_err(|e| JsError::new(&e.to_string()));
        }

        let signed_slices = zsign_core::macho::sign_macho_all_slices(
            &macho,
            identifier,
            entitlements,
            &self.credentials,
            info_plist.as_deref(),
            code_resources.as_deref(),
        )
        .map_err(|e| JsError::new(&e.to_string()))?;

        zsign_core::macho::embed_signature_fat(macho.data(), &signed_slices)
            .map_err(|e| JsError::new(&e.to_string()))
    }

    /// Parse an Info.plist (XML or binary) and return bundle ID and executable name.
    ///
    /// Returns a JS object with `bundle_id` and `executable` fields (both optional strings).
    pub fn parse_info_plist(data: &[u8]) -> Result<JsValue, JsError> {
        let plist_value: plist::Value = plist::from_bytes(data)
            .map_err(|e| JsError::new(&format!("Failed to parse Info.plist: {}", e)))?;

        let dict = plist_value.as_dictionary()
            .ok_or_else(|| JsError::new("Info.plist is not a dictionary"))?;

        let bundle_id = dict.get("CFBundleIdentifier")
            .and_then(|v| v.as_string())
            .unwrap_or("");

        let executable = dict.get("CFBundleExecutable")
            .and_then(|v| v.as_string())
            .unwrap_or("");

        let js_obj = js_sys::Object::new();
        js_sys::Reflect::set(&js_obj, &"bundle_id".into(), &bundle_id.into())
            .map_err(|_| JsError::new("Failed to set bundle_id"))?;
        js_sys::Reflect::set(&js_obj, &"executable".into(), &executable.into())
            .map_err(|_| JsError::new("Failed to set executable"))?;

        Ok(js_obj.into())
    }
}
