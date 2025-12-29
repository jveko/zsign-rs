//! IPA handling module.
//!
//! Provides functionality for extracting, signing, and repacking IPA files.

pub mod archive;
pub mod extract;

pub use archive::{create_ipa, CompressionLevel};
pub use extract::{extract_ipa, validate_ipa};

use crate::bundle::CodeResourcesBuilder;
use crate::crypto::SigningCredentials;
use crate::macho::{sign_macho, MachOFile};
use crate::{Error, Result};
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;
use walkdir::WalkDir;

/// IPA signing workflow.
///
/// This struct provides a high-level interface for signing IPA files,
/// handling the complete workflow of extraction, bundle signing, and repacking.
pub struct IpaSigner<'a> {
    /// Reference to signing credentials
    credentials: &'a SigningCredentials,
    /// Compression level for output IPA
    compression_level: CompressionLevel,
    /// Path to provisioning profile to embed as embedded.mobileprovision
    provisioning_profile_path: Option<PathBuf>,
    /// Cached entitlements from provisioning profile
    entitlements: Option<Vec<u8>>,
}

impl<'a> IpaSigner<'a> {
    /// Create a new IPA signer with the given signing credentials.
    pub fn new(credentials: &'a SigningCredentials) -> Self {
        Self {
            credentials,
            compression_level: CompressionLevel::DEFAULT,
            provisioning_profile_path: None,
            entitlements: None,
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
    /// This copies the profile to the bundle as `embedded.mobileprovision`
    /// and extracts entitlements from the profile for signing.
    pub fn provisioning_profile(mut self, path: impl AsRef<Path>) -> Self {
        let path = path.as_ref();
        self.provisioning_profile_path = Some(path.to_path_buf());

        if let Ok(profile_data) = fs::read(path) {
            if let Some(entitlements) = Self::extract_entitlements_from_profile(&profile_data) {
                self.entitlements = Some(entitlements);
            }
        }

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

        validate_ipa(input_ipa)?;

        let temp_dir = TempDir::new().map_err(|e| {
            Error::Io(std::io::Error::other(
                format!("Failed to create temp directory: {}", e),
            ))
        })?;

        let app_bundle = extract_ipa(input_ipa, temp_dir.path())?;

        self.sign_bundle(&app_bundle)?;

        create_ipa(&app_bundle, output_ipa, self.compression_level)?;

        Ok(())
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
    fn sign_bundle(&self, bundle_path: &Path) -> Result<()> {
        let dylibs = self.find_standalone_dylibs(bundle_path)?;
        for dylib_path in &dylibs {
            self.sign_standalone_dylib(dylib_path)?;
        }

        let mut bundles = self.collect_nested_bundles(bundle_path)?;

        bundles.sort_by(|a, b| b.1.cmp(&a.1));

        for (nested_bundle_path, _depth) in &bundles {
            let is_main_bundle = nested_bundle_path == bundle_path;
            self.sign_single_bundle(nested_bundle_path, is_main_bundle)?;
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

        let signed_binary = sign_macho(
            &macho,
            &identifier,
            None,
            self.credentials,
            None,
            None,
        )?;

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
    fn sign_single_bundle(&self, bundle_path: &Path, copy_provisioning_profile: bool) -> Result<()> {
        let identifier = self.get_bundle_identifier(bundle_path)?;
        let main_executable = self.get_main_executable(bundle_path)?;

        let binaries = self.find_immediate_macho_binaries(bundle_path)?;

        for binary_path in &binaries {
            if binary_path != &main_executable {
                self.sign_binary(binary_path, &identifier, None)?;
            }
        }

        if copy_provisioning_profile {
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
        }

        self.generate_code_resources(bundle_path)?;

        let code_resources_path = bundle_path.join("_CodeSignature/CodeResources");
        let code_resources_data = if code_resources_path.exists() {
            Some(fs::read(&code_resources_path)?)
        } else {
            None
        };

        if main_executable.exists() {
            self.sign_binary(&main_executable, &identifier, code_resources_data.as_deref())?;
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

            if path != self.get_main_executable(bundle_path)? && self.is_macho_binary(path)? {
                binaries.push(path.to_path_buf());
            }
        }

        Ok(binaries)
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
        let plist: plist::Value = plist::from_bytes(&plist_data)
            .map_err(|e| Error::Signing(format!("Failed to parse Info.plist: {}", e)))?;

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
            .map_err(|e| Error::Signing(format!("Failed to parse Info.plist: {}", e)))?;

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

    /// Empty entitlements plist for non-executable binaries (dylibs, frameworks).
    /// C++ zsign uses this for non-executables instead of full entitlements.
    const EMPTY_ENTITLEMENTS: &'static [u8] = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict/>\n</plist>\n";

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
    ) -> Result<()> {
        let macho = MachOFile::open(binary_path)?;

        let bundle_path = binary_path
            .parent()
            .ok_or_else(|| Error::Signing("Binary has no parent directory".into()))?;

        let info_plist = bundle_path.join("Info.plist");
        let info_data = if info_plist.exists() {
            Some(fs::read(&info_plist)?)
        } else {
            None
        };

        let is_executable = macho
            .slices()
            .first()
            .map(|s| s.is_executable)
            .unwrap_or(false);
        let entitlements_to_use: Option<&[u8]> = if is_executable {
            self.entitlements.as_deref()
        } else {
            Some(Self::EMPTY_ENTITLEMENTS)
        };

        let signed_binary = sign_macho(
            &macho,
            identifier,
            entitlements_to_use,
            self.credentials,
            info_data.as_deref(),
            code_resources,
        )?;

        fs::write(binary_path, signed_binary)?;

        Ok(())
    }

    /// Generate CodeResources plist for the bundle.
    fn generate_code_resources(&self, bundle_path: &Path) -> Result<()> {
        let code_resources = CodeResourcesBuilder::new(bundle_path).scan()?.build()?;

        let codesig_dir = bundle_path.join("_CodeSignature");
        fs::create_dir_all(&codesig_dir)?;

        let resources_path = codesig_dir.join("CodeResources");
        fs::write(&resources_path, &code_resources)?;

        Ok(())
    }

    /// Extract entitlements from a provisioning profile (mobileprovision file).
    ///
    /// Provisioning profiles are CMS-signed XML plists. This extracts the
    /// Entitlements dictionary and converts it back to XML plist format.
    fn extract_entitlements_from_profile(profile_data: &[u8]) -> Option<Vec<u8>> {
        let plist_start = profile_data.windows(6).position(|w| w == b"<?xml ")?;

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
        zip.write_all(b"MACHO_PLACEHOLDER").unwrap();

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
    }
}
