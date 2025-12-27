//! IPA handling module.
//!
//! Provides functionality for extracting, signing, and repacking IPA files.
//! IPA files are standard ZIP archives containing iOS app bundles in a Payload/ directory.

pub mod archive;
pub mod extract;

pub use archive::{create_ipa, CompressionLevel};
pub use extract::{extract_ipa, validate_ipa};

use crate::bundle::CodeResourcesBuilder;
use crate::crypto::SigningAssets;
use crate::macho::{sign_macho, write_signed_macho_in_place, MachOFile};
use crate::{Error, Result};
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;
use walkdir::WalkDir;

/// IPA signing workflow that combines extract, sign, and repack operations.
///
/// This struct provides a high-level interface for signing IPA files,
/// handling the complete workflow of extraction, bundle signing, and repacking.
pub struct IpaSigner {
    /// Signing assets (certificate, private key, entitlements)
    assets: SigningAssets,
    /// Compression level for output IPA
    compression_level: CompressionLevel,
    /// Path to provisioning profile to embed as embedded.mobileprovision
    provisioning_profile_path: Option<PathBuf>,
}

impl IpaSigner {
    /// Create a new IPA signer with the given signing assets.
    pub fn new(assets: SigningAssets) -> Self {
        Self {
            assets,
            compression_level: CompressionLevel::DEFAULT,
            provisioning_profile_path: None,
        }
    }

    /// Set the compression level for the output IPA.
    pub fn compression_level(mut self, level: CompressionLevel) -> Self {
        self.compression_level = level;
        self
    }

    /// Set the provisioning profile path to embed as embedded.mobileprovision.
    ///
    /// iOS apps require a provisioning profile to launch on device.
    /// This copies the profile to the bundle as `embedded.mobileprovision`.
    pub fn provisioning_profile(mut self, path: impl AsRef<Path>) -> Self {
        self.provisioning_profile_path = Some(path.as_ref().to_path_buf());
        self
    }

    /// Sign an IPA file.
    ///
    /// This performs the complete signing workflow:
    /// 1. Extract IPA to a temporary directory
    /// 2. Find the .app bundle in Payload/
    /// 3. Sign all Mach-O binaries in-place
    /// 4. Copy provisioning profile to bundle
    /// 5. Generate CodeResources (hashes include signed binaries and profile)
    /// 6. Repack into a new IPA
    ///
    /// # Arguments
    ///
    /// * `input_ipa` - Path to the input IPA file
    /// * `output_ipa` - Path for the signed output IPA
    ///
    /// # Errors
    ///
    /// Returns an error if any step of the signing workflow fails.
    pub fn sign(&self, input_ipa: impl AsRef<Path>, output_ipa: impl AsRef<Path>) -> Result<()> {
        let input_ipa = input_ipa.as_ref();
        let output_ipa = output_ipa.as_ref();

        // Validate input IPA
        validate_ipa(input_ipa)?;

        // Create temporary directory for extraction
        let temp_dir = TempDir::new().map_err(|e| {
            Error::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Failed to create temp directory: {}", e),
            ))
        })?;

        // Extract IPA
        let app_bundle = extract_ipa(input_ipa, temp_dir.path())?;

        // Sign the bundle
        self.sign_bundle(&app_bundle)?;

        // Repack as IPA
        create_ipa(&app_bundle, output_ipa, self.compression_level)?;

        Ok(())
    }

    /// Sign an app bundle in place.
    ///
    /// Signs all Mach-O binaries and generates CodeResources.
    ///
    /// The signing workflow order is critical:
    /// 1. First: Sign all binaries in-place (modifies binary content)
    /// 2. Then: Copy provisioning profile to bundle
    /// 3. Finally: Generate CodeResources (hashes all files including signed binaries and profile)
    fn sign_bundle(&self, bundle_path: &Path) -> Result<()> {
        // Get bundle identifier from Info.plist
        let identifier = self.get_bundle_identifier(bundle_path)?;

        // Step 1: Find and sign all Mach-O binaries in-place
        // This must happen BEFORE CodeResources generation so hashes are correct
        let binaries = self.find_macho_binaries(bundle_path)?;

        for binary_path in binaries {
            self.sign_binary(&binary_path, &identifier)?;
        }

        // Step 2: Copy provisioning profile to bundle as embedded.mobileprovision
        // This must happen BEFORE CodeResources generation so profile is included in hashes
        if let Some(ref profile_path) = self.provisioning_profile_path {
            let embedded_path = bundle_path.join("embedded.mobileprovision");
            fs::copy(profile_path, &embedded_path).map_err(|e| {
                Error::Signing(format!(
                    "Failed to copy provisioning profile to {}: {}",
                    embedded_path.display(),
                    e
                ))
            })?;
        }

        // Step 3: Generate CodeResources
        // This must happen LAST so all file hashes (signed binaries + profile) are correct
        self.generate_code_resources(bundle_path)?;

        Ok(())
    }

    /// Get the bundle identifier from Info.plist.
    fn get_bundle_identifier(&self, bundle_path: &Path) -> Result<String> {
        let info_plist_path = bundle_path.join("Info.plist");

        if !info_plist_path.exists() {
            return Err(Error::Signing(format!(
                "Info.plist not found in bundle: {}",
                bundle_path.display()
            )));
        }

        let plist_data = fs::read(&info_plist_path)?;
        let plist: plist::Value = plist::from_bytes(&plist_data).map_err(|e| {
            Error::Signing(format!("Failed to parse Info.plist: {}", e))
        })?;

        let identifier = plist
            .as_dictionary()
            .and_then(|d| d.get("CFBundleIdentifier"))
            .and_then(|v| v.as_string())
            .map(|s| s.to_string())
            .unwrap_or_else(|| {
                // Fallback to bundle directory name
                bundle_path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("unknown")
                    .to_string()
            });

        Ok(identifier)
    }

    /// Find all Mach-O binaries in the bundle.
    fn find_macho_binaries(&self, bundle_path: &Path) -> Result<Vec<PathBuf>> {
        let mut binaries = Vec::new();

        // The main executable is named in Info.plist as CFBundleExecutable
        let main_executable = self.get_main_executable(bundle_path)?;
        if main_executable.exists() {
            binaries.push(main_executable);
        }

        // Find frameworks and their binaries
        let frameworks_dir = bundle_path.join("Frameworks");
        if frameworks_dir.exists() {
            for entry in WalkDir::new(&frameworks_dir)
                .min_depth(1)
                .max_depth(2)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                let path = entry.path();
                if path.is_file() && self.is_macho_binary(path)? {
                    binaries.push(path.to_path_buf());
                }
            }
        }

        // Find plugin binaries
        let plugins_dir = bundle_path.join("PlugIns");
        if plugins_dir.exists() {
            for entry in WalkDir::new(&plugins_dir)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                let path = entry.path();
                if path.is_file() && self.is_macho_binary(path)? {
                    binaries.push(path.to_path_buf());
                }
            }
        }

        Ok(binaries)
    }

    /// Get the main executable path from Info.plist.
    fn get_main_executable(&self, bundle_path: &Path) -> Result<PathBuf> {
        let info_plist_path = bundle_path.join("Info.plist");

        if !info_plist_path.exists() {
            // Fallback: assume executable has same name as bundle
            let bundle_name = bundle_path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("unknown");
            return Ok(bundle_path.join(bundle_name));
        }

        let plist_data = fs::read(&info_plist_path)?;
        let plist: plist::Value = plist::from_bytes(&plist_data).map_err(|e| {
            Error::Signing(format!("Failed to parse Info.plist: {}", e))
        })?;

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

        // Mach-O magic numbers
        let is_macho = matches!(
            magic,
            [0xfe, 0xed, 0xfa, 0xce] | // MH_MAGIC (32-bit)
            [0xfe, 0xed, 0xfa, 0xcf] | // MH_MAGIC_64 (64-bit)
            [0xce, 0xfa, 0xed, 0xfe] | // MH_CIGAM (32-bit, swapped)
            [0xcf, 0xfa, 0xed, 0xfe] | // MH_CIGAM_64 (64-bit, swapped)
            [0xca, 0xfe, 0xba, 0xbe] | // FAT_MAGIC
            [0xbe, 0xba, 0xfe, 0xca]   // FAT_CIGAM
        );

        Ok(is_macho)
    }

    /// Sign a single Mach-O binary.
    ///
    /// Generates a code signature and embeds it directly into the binary,
    /// modifying the LC_CODE_SIGNATURE load command and appending the
    /// SuperBlob signature data.
    fn sign_binary(&self, binary_path: &Path, identifier: &str) -> Result<()> {
        let macho = MachOFile::open(binary_path)?;

        // Read Info.plist for the bundle containing this binary
        let bundle_path = binary_path.parent().ok_or_else(|| {
            Error::Signing("Binary has no parent directory".into())
        })?;

        let info_plist = bundle_path.join("Info.plist");
        let info_data = if info_plist.exists() {
            Some(fs::read(&info_plist)?)
        } else {
            None
        };

        // Generate code signature
        let signature = sign_macho(
            &macho,
            identifier,
            self.assets.team_id.as_deref(),
            self.assets.entitlements.as_deref(),
            &self.assets.certificate,
            &self.assets.private_key,
            info_data.as_deref(),
            None, // CodeResources hash will be added later
        )?;

        // Embed signature directly into the binary
        write_signed_macho_in_place(binary_path, &signature)?;

        Ok(())
    }

    /// Generate CodeResources plist for the bundle.
    fn generate_code_resources(&self, bundle_path: &Path) -> Result<()> {
        let code_resources = CodeResourcesBuilder::new(bundle_path).build()?;

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
    use std::io::Write;
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

        // Create Info.plist
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

        // Create dummy executable
        zip.start_file("Payload/Test.app/Test", options).unwrap();
        zip.write_all(b"MACHO_PLACEHOLDER").unwrap();

        zip.finish().unwrap();

        ipa_path
    }

    #[test]
    fn test_extract_and_repack_ipa() {
        let temp_dir = TempDir::new().unwrap();
        let ipa_path = create_test_ipa(temp_dir.path());

        // Extract
        let extract_dir = temp_dir.path().join("extracted");
        let app_bundle = extract_ipa(&ipa_path, &extract_dir).unwrap();

        assert!(app_bundle.exists());
        assert!(app_bundle.join("Info.plist").exists());

        // Repack
        let output_ipa = temp_dir.path().join("repacked.ipa");
        create_ipa(&app_bundle, &output_ipa, CompressionLevel::DEFAULT).unwrap();

        assert!(output_ipa.exists());

        // Verify repacked IPA can be extracted
        let verify_dir = temp_dir.path().join("verify");
        let verified_bundle = extract_ipa(&output_ipa, &verify_dir).unwrap();

        assert!(verified_bundle.exists());
        assert!(verified_bundle.join("Info.plist").exists());
    }

    #[test]
    fn test_ipa_signer_workflow() {
        // This test validates the IpaSigner structure compiles correctly
        // Full signing requires valid certificates which we don't have in tests
    }
}
