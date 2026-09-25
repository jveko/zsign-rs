//! WASM bindings for zsign iOS code signing.
//!
//! This crate provides WASM-compatible utilities for iOS app bundle signing:
//! - Certificate and credential loading from PKCS#12 (.p12) files
//! - Provisioning profile entitlement extraction
//! - Mach-O binary signing (SHA-256-only default for thin input; dual SHA-1+SHA-256 via `sign_macho_fat`, incl. FAT/Universal)
//! - CodeResources hash computation (including streaming for large files)
//! - Mach-O binary parsing and metadata inspection
//!
//! All cryptographic operations use pure-Rust RustCrypto implementations,
//! making this crate fully compatible with `wasm32-unknown-unknown`.

use sha1::{Digest as _, Sha1};
use sha2::Sha256;
use std::collections::HashMap;
use wasm_bindgen::prelude::*;
use zsign_core::bundle::CodeResourcesBuilder;
use zsign_core::crypto::SigningCredentials;
use zsign_core::provisioning::extract_entitlements_from_profile;

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
    entitlements_override: Option<Vec<u8>>,
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

        let entitlements = match profile_bytes.as_deref() {
            Some(data) => {
                extract_entitlements_from_profile(data).map_err(|e| JsError::new(&e.to_string()))?
            }
            None => None,
        };

        Ok(WasmSigner {
            credentials,
            profile_entitlements: entitlements,
            entitlements_override: None,
            resource_builder: CodeResourcesBuilder::new(),
            streaming_hashes: HashMap::new(),
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
    /// dictionaries — Data/Date/Real are rejected here rather than at sign
    /// time) — it replaces the profile-derived entitlements until cleared.
    /// `None` clears the override, falling back to the profile-derived
    /// entitlements. To sign with no entitlements while holding a profile,
    /// construct the signer without profile bytes instead.
    pub fn set_entitlements(&mut self, data: Option<Vec<u8>>) -> Result<(), JsError> {
        match data {
            Some(bytes) => {
                let value: plist::Value = plist::from_bytes(&bytes).map_err(|e| {
                    JsError::new(&format!(
                        "entitlements must be a valid XML or binary plist dictionary: {e}"
                    ))
                })?;
                if value.as_dictionary().is_none() {
                    return Err(JsError::new(
                        "entitlements plist must contain a top-level dictionary",
                    ));
                }
                zsign_core::codesign::der::plist_to_der(&bytes).map_err(|e| {
                    JsError::new(&format!(
                        "entitlements contain types the signer cannot encode: {e}"
                    ))
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
        self.resource_builder
            .add_symlink(relative_path, target, sha1, sha256)
    }

    /// Build and return the CodeResources plist bytes.
    pub fn build_code_resources(&self) -> Result<Vec<u8>, JsError> {
        if !self.streaming_hashes.is_empty() {
            let pending: Vec<_> = self.streaming_hashes.keys().collect();
            return Err(JsError::new(&format!(
                "Cannot build CodeResources: {} unfinished streaming hashes: {:?}",
                pending.len(),
                pending
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
    pub fn extract_entitlements(profile_data: &[u8]) -> Result<Option<Vec<u8>>, JsError> {
        extract_entitlements_from_profile(profile_data).map_err(|e| JsError::new(&e.to_string()))
    }

    /// Parse a Mach-O binary and return metadata.
    pub fn parse_macho(data: Vec<u8>) -> Result<MachOInfo, JsError> {
        let macho =
            zsign_core::macho::MachOFile::parse(data).map_err(|e| JsError::new(&e.to_string()))?;
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
    ) -> Result<Vec<u8>, JsError> {
        let macho =
            zsign_core::macho::MachOFile::parse(data).map_err(|e| JsError::new(&e.to_string()))?;
        if macho.slices().len() > 1 {
            return Err(JsError::new(
                "FAT/Universal input is not supported by SHA-256-only signing; call sign_macho_fat() to opt into dual SHA-1+SHA-256 signing explicitly",
            ));
        }
        let is_executable = macho
            .slices()
            .first()
            .map(|s| s.is_executable)
            .unwrap_or(false);
        let entitlements: Option<&[u8]> = if is_executable {
            self.effective_entitlements()
        } else {
            Some(zsign_core::macho::EMPTY_ENTITLEMENTS)
        };
        zsign_core::macho::sign_macho_sha256_only(
            &macho,
            identifier,
            entitlements,
            &self.credentials,
            info_plist.as_deref(),
            code_resources.as_deref(),
            false,
        )
        .map_err(|e| JsError::new(&e.to_string()))
    }

    /// Sign a Mach-O binary (thin or FAT/Universal) with dual SHA-1+SHA-256 code directories. Returns the signed binary bytes.
    pub fn sign_macho_fat(
        &self,
        data: Vec<u8>,
        identifier: &str,
        info_plist: Option<Vec<u8>>,
        code_resources: Option<Vec<u8>>,
    ) -> Result<Vec<u8>, JsError> {
        let macho =
            zsign_core::macho::MachOFile::parse(data).map_err(|e| JsError::new(&e.to_string()))?;
        zsign_core::macho::sign_any_macho(
            &macho,
            identifier,
            self.effective_entitlements(),
            &self.credentials,
            info_plist.as_deref(),
            code_resources.as_deref(),
            false,
        )
        .map_err(|e| JsError::new(&e.to_string()))
    }

    /// Parse an Info.plist (XML or binary) and return bundle ID and executable name.
    ///
    /// Returns a JS object with `bundle_id` and `executable` fields (both optional strings).
    pub fn parse_info_plist(data: &[u8]) -> Result<JsValue, JsError> {
        let plist_value: plist::Value = plist::from_bytes(data)
            .map_err(|e| JsError::new(&format!("Failed to parse Info.plist: {}", e)))?;

        let dict = plist_value
            .as_dictionary()
            .ok_or_else(|| JsError::new("Info.plist is not a dictionary"))?;

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
            .map_err(|_| JsError::new("Failed to set bundle_id"))?;
        js_sys::Reflect::set(&js_obj, &"executable".into(), &executable.into())
            .map_err(|_| JsError::new("Failed to set executable"))?;

        Ok(js_obj.into())
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use sha1::Sha1;
    use sha2::Sha256;
    use wasm_bindgen_test::*;

    // Self-issued code-signing leaf generated with openssl: RSA-2048, CA:FALSE,
    // digitalSignature, codeSigning EKU, validity 2026-09-25 to 2036-09-22,
    // packed as an AES-256-CBC p12 (SHA-256 mac) with password `test`. RSA
    // rather than EC on purpose: the CMS verifier parses ECDSA signatures as
    // fixed-width r||s, so the DER-encoded EC signatures that openssl and the
    // CMS builder emit never verify and the anchored round-trip assertions
    // below could never go green.
    const LEAF_P12_B64: &str = concat!(
        "MIIKRwIBAzCCCfUGCSqGSIb3DQEHAaCCCeYEggniMIIJ3jCCBEoGCSqGSIb3DQEHBqCCBDswggQ3",
        "AgEAMIIEMAYJKoZIhvcNAQcBMF8GCSqGSIb3DQEFDTBSMDEGCSqGSIb3DQEFDDAkBBCCvX4/MMl2",
        "F+Jm2FDdaDvCAgIIADAMBggqhkiG9w0CCQUAMB0GCWCGSAFlAwQBKgQQPKCCe3Yj1ZMq0Yg7+mKu",
        "uoCCA8BhaKDWJrHoNkZgo01vefTHrdQVo4s1zFzewGbpdR8kp5SWx+NgIJHGJdNRan823mq7CN/t",
        "yHjVAMxV+8DyvpcTinVynLADgTq9P746LRRTDo31Sri+qm5ivbv4f0tbN61E5o3Chm4aK4cTPi48",
        "3XMiqTAYSQhZxL9ZYj8+cjkLT49wTWkwEw66nxrZNr+kC2u5CVskPwHiPCIJ0fpI66SSUmnzstGM",
        "HOwL6mGZVQ69MofvammwUzPtIwx6tWwOnzL1jqweQdwbaVTHN8uhqvXFoslgM8CsJaPUHNMfuAcG",
        "DTGNsSGVkMfYC74EMwppeRANtbAFtb+Uw2u2Yb9gn7kGOf4ImZ2zjAXNCx63MsjQ79kOlxSGHOMf",
        "TjKp4kWPM7QwuaI7bmaYycDz7xpMUn19dXI2IhIXVP8Bvv4cG1vhSl6uH9SGc+n6ImqTmK8zpMzH",
        "C+9sK1FQf4CPn4CAkYoTv7fvdrY1DOLp+9LFsCRV8daQBV2KmTBkgyWBSnyNRanvqXo3l7TTDYgY",
        "Iid6LRF3bY9efZ8LRH9rEP8ww5EGJFFUyssABkVALFkkbIcHQYs/VbPw3tpZFWVeyRfWGNK+ILEl",
        "6AC39RaK0lOvqvy+QW8zaLj6y3hs0KJVqE6C55EWOgyZJzqdRs89UNt5PKQbaOwDJ0vMJtoUhZhP",
        "CVn66ttY87rmz5eREg3H7uyCIw0vdN4B9qYHWwVkS+ixXOtaXZFJKyyI+KL8O4RcmxHvbkLf3K8z",
        "0My0al031ekRpCHgcRSHzjZ6L0cEzi5zLwM3fRw07UDIOmtejLkIzprbdJA+k6zCKNW7UNjdT2jR",
        "KxAv8MGkmyR45U7tS7x4y1ZWAjEyHqreEkCblF8POfb/fplZJ2tYVZKq4PwVMCRqT0P0LsSn1M3z",
        "Zjc/TBmXtbbI+rgILvzxMw3nnrtRC+y4wbEv0TcaT/lnEH8/p7OJdBn7nlkxvtMcxk4uiKx3v2Mi",
        "3rPhw58zxSqBoT92pQ3rjRm1zNqLgPUFPTcb6xSzXu8gvdKsKcgNT8sH+zX4Lnwqx27Irwv1Cnxv",
        "4qgU3lEp5XIpqo8QBCOslHjVGUQ5shAPBDLj1w4CypAa7AX+Re6NjMHNyboJ9JOddSGBKzoyETk/",
        "UvB0odQB3YZEHMbgCgS1gxrnVvn5JTRfacXFuGeits5cYwmOsdgv42arZHueLibyg+xH+VkV/50N",
        "v/2GaLyZZ4MJ3idmLHK2nsmckG3xTN0OAUUmDwkdAQaiz+SllkT8b+A8Ye19J8IgJN/sR3wwggWM",
        "BgkqhkiG9w0BBwGgggV9BIIFeTCCBXUwggVxBgsqhkiG9w0BDAoBAqCCBTkwggU1MF8GCSqGSIb3",
        "DQEFDTBSMDEGCSqGSIb3DQEFDDAkBBCuX83Xha5ib/ewhjXXSd6/AgIIADAMBggqhkiG9w0CCQUA",
        "MB0GCWCGSAFlAwQBKgQQ4bE+4+olo0nXvwxKnVoRSgSCBNC2OLojmKPP1COwsJeK3sy8cXtZ6eJy",
        "LJQxFTN4/P3aU30lUcKUlYXjo/E/F5YuBip+OudpB7Ye/8gBMw8CJ1rMnGx9/6W0qzjzX+jhxw5N",
        "4Mr0fftr8Mh4t5DXN0uon+6Cn2zbb3rb5IJMsZjutDyPdq3TxcsSPiPLQ4WlaAUuOMYN8Y10t9vG",
        "hKjnqTttPeHaaIc9NV8wcHS6RMeBBBCKZEDODRd8yaRCk3eQB7imTKLqUyRZleJhN0lj21FwUB6r",
        "mEfEDbCBMP5zVTn0faIiBSpEmT6XiFxS+IwqUrPPMdonBg62v3CcrX7igfyJJVDcO0N3iiM2JXgY",
        "dKZ9q8PX/RPDxz0w08VrpNEB9CZ/mCVWkeT0dLRyYHDnhe7pvNc1h1pHV1PtLTbrLSeA6k5MEe35",
        "3D/WK/lnG2ysjl6FyH3EZocUfbapG6O6xyIZRAv2QNbeiuOjQPFSMFhFOoChpI7+Af0OHxC9Ipkz",
        "ejkauZKaXZ1Phsa3BhIve5sAygwapvgy8NyLFIml1ECJQ0tPiSGBE2wI5zI80lYtt6gr37qFdEYP",
        "+j+nr92dn/vcpenDtZvTj/WIdAE47PGyV4Lxw2bVJ8JLqkvyiXAd+baw09b6UDnVnmQpyQ8eA6a0",
        "vc4o2I/10Ap0XHoLIVuN5k866yHqYNx5sQCwALlBJYPKTuAcA2uaG/X7odOYFr8ziBfkv0lzerhM",
        "zEtD9LSxX8w+mLVNKUxdYmKZVH2Rvje1rHoFXyQbK3B6wC7sD36GupyGZGXgX75mzMNTHUFZula0",
        "zTW4YpEoS3b+PHDdGsMUp598kG7ya9W38oYV8Lo1G5C46w79Ia5f0Mbg8DRVzF0KXBry6zL5fHKU",
        "G3JAGPHZrggsccoQLgbw/DbPs0EsJ9wpvXI7YIbe9ZTNrR84yrqyWS8GxPPf2JZs0sDsOiFN4ufd",
        "5VyCG7mlw/Nk3pyM38eCyxA2L7G2XMebhUbXLogbS6UzUa+25hWTk9sOXM7Ji6bmJDUc/P0HdYZz",
        "IiqU7Olt4ZrS3UryyghYx7EMNccPwEy53m3hqyCTXBxTBzU8o8ZWl6Il0jwlu/+4NOpCEVfwTOp7",
        "ug6pXGcZTSYTPMorjyizNaRuGxgIrEguM3So+vtUXWEYOKntafF4lom7egyIvQdtttxc0oxAhMNo",
        "gbt3kA0I9Ed+R3vTp7AUwuajArXDMJ4n3HmARPwY8jSVde8Bt9TaSNP57X9+B7d39QNb2Fi+TrhA",
        "NP2D/5DIRp6IxnAFhDWk/ialN9ESA6ZO3S4LON/mkMglpahkI4Kn/lX2Z8wDJjoI6WMRXRYXwp7S",
        "7IwTJTRRwuIMZSP8idym2SIIU8ytafYfeqwmIWBE/hxxcDmqtltHcx/HoH5M3v0XplcR/CGc34IA",
        "vFyhzcQoCEttvU8ndavs+DD5Le2uLfXXYBep5Q8E54Bt0E8RtFl/HXpTRPEneIbcQSe8Tkk2sZ/F",
        "6IrDoBZin0BAamXjGqFkX19qT09ckDecED6UdVx2oujCoC3vwSE8I9tC6AtxBh7ku8xE5bj2vzTf",
        "hlO14cDnLjH7f7sAlcC3Rrvq+lh3vDwTStiAQ0JTMnhPq7AtQgYFyAWk6r1Tqxspf6TymSl0qiWT",
        "KBqr0H/KxlwNhHyQdDElMCMGCSqGSIb3DQEJFTEWBBTYyAME10IV1rhPjotKeZMLmOI7IjBJMDEw",
        "DQYJYIZIAWUDBAIBBQAEINAqV8nM/KQFqB2FOMqJQo72ryE09t4IiDjnl4VfBWg4BBCrgwQLJGTJ",
        "UH6cwlIqKIM1AgIIAA==",
    );

    const MINIMAL_MACHO: &[u8] = include_bytes!("../../zsign/src/ipa/fixtures/minimal_macho.bin");

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
        WasmSigner::new(&decode_base64(LEAF_P12_B64), "test", None).expect("fixture p12 loads")
    }

    fn new_signer_with_profile() -> WasmSigner {
        WasmSigner::new(
            &decode_base64(LEAF_P12_B64),
            "test",
            Some(PROFILE_XML.as_bytes().to_vec()),
        )
        .expect("fixture p12 + profile load")
    }

    fn err_message(err: impl Into<JsValue>) -> String {
        let value: JsValue = err.into();
        value.unchecked_into::<js_sys::Error>().message().into()
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

    fn build_fat_macho() -> Vec<u8> {
        let mut fat = vec![0u8; 20_480];
        fat[0..4].copy_from_slice(&0xcafebabeu32.to_be_bytes());
        fat[4..8].copy_from_slice(&2u32.to_be_bytes());
        for (index, (offset, size)) in [(4_096usize, 8_192usize), (12_288, 8_192)]
            .into_iter()
            .enumerate()
        {
            let start = 8 + index * 20;
            fat[start..start + 4].copy_from_slice(&0x0100_000cu32.to_be_bytes());
            fat[start + 4..start + 8].copy_from_slice(&0u32.to_be_bytes());
            fat[start + 8..start + 12].copy_from_slice(&(offset as u32).to_be_bytes());
            fat[start + 12..start + 16].copy_from_slice(&(size as u32).to_be_bytes());
            fat[start + 16..start + 20].copy_from_slice(&12u32.to_be_bytes());
            fat[offset..offset + MINIMAL_MACHO.len()].copy_from_slice(MINIMAL_MACHO);
        }
        fat
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn sign_macho_default_emits_sha256_only_for_thin_input() {
        let signed = new_signer()
            .sign_macho(MINIMAL_MACHO.to_vec(), "com.zsign.test", None, None)
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
        let fat = build_fat_macho();
        let err = new_signer()
            .sign_macho(fat, "com.zsign.test", None, None)
            .expect_err("FAT rejected by default");
        let msg = err_message(err);
        assert!(
            msg.contains("sign_macho_fat"),
            "error must name the dual opt-in: {msg}"
        );
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn sign_macho_fat_keeps_dual_behavior_for_thin_and_fat() {
        let signer = new_signer();
        let thin = signer
            .sign_macho_fat(MINIMAL_MACHO.to_vec(), "com.zsign.test", None, None)
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
            .sign_macho_fat(build_fat_macho(), "com.zsign.test", None, None)
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

    /// Pins the executable/non-executable entitlements replication in sign_macho:
    /// non-executable input must ignore profile entitlements (EMPTY_ENTITLEMENTS
    /// both times), executable input must not. Passes on the pre-change
    /// delegation; goes red if the replication is dropped.
    #[wasm_bindgen_test(unsupported = test)]
    fn non_executable_input_ignores_profile_entitlements() {
        let mut dylib = MINIMAL_MACHO.to_vec();
        dylib[12..16].copy_from_slice(&6u32.to_le_bytes());
        let with = new_signer_with_profile();
        let without = new_signer();

        let a = with
            .sign_macho(dylib.clone(), "com.zsign.test", None, None)
            .expect("sign");
        let b = without
            .sign_macho(dylib.clone(), "com.zsign.test", None, None)
            .expect("sign");
        assert_eq!(
            entitlements_slot(&a),
            entitlements_slot(&b),
            "non-executable input must ignore profile entitlements"
        );

        let c = with
            .sign_macho(MINIMAL_MACHO.to_vec(), "com.zsign.test", None, None)
            .expect("sign");
        let d = without
            .sign_macho(MINIMAL_MACHO.to_vec(), "com.zsign.test", None, None)
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
        assert!(err_message(e1).contains("plist dictionary"));

        let arr = br#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><array><string>x</string></array></plist>"#;
        let e2 = signer
            .set_entitlements(Some(arr.to_vec()))
            .expect_err("non-dictionary rejected");
        assert!(err_message(e2).contains("dictionary"));

        // values the signer's DER encoder refuses (Data/Date/Real, der.rs:176-188)
        // must fail at set time, not at sign time
        let with_data = br#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>k</key><data>AA==</data></dict></plist>"#;
        let e3 = signer
            .set_entitlements(Some(with_data.to_vec()))
            .expect_err("DER-unsupported value rejected");
        let m3 = err_message(e3);
        assert!(m3.contains("cannot encode"), "got: {m3}");
    }
}
