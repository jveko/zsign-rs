//! IPA archive creation.
//!
//! Creates IPA (ZIP) archives from `.app` bundles with the standard `Payload/` structure.
//!
//! For the reverse operation, see the [`extract`](super::extract) module.
//!
//! # Features
//!
//! - Configurable compression via [`CompressionLevel`]
//! - Preserves Unix file permissions and symlinks
//! - Creates proper directory structure for iOS deployment
//!
//! # Examples
//!
//! ```no_run
//! use zsign::ipa::{create_ipa, CompressionLevel};
//! use std::path::Path;
//!
//! let app_bundle = Path::new("Payload/MyApp.app");
//! create_ipa(app_bundle, "output.ipa", CompressionLevel::DEFAULT)?;
//! # Ok::<(), zsign::Error>(())
//! ```

use crate::{Error, Result};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::Path;
use walkdir::WalkDir;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

/// ZIP compression level for IPA creation.
///
/// Controls the trade-off between compression speed and output file size.
/// Use the provided constants for common use cases, or [`CompressionLevel::new`]
/// for custom levels.
///
/// # Examples
///
/// ```
/// use zsign::ipa::CompressionLevel;
///
/// // Use predefined levels
/// let fast = CompressionLevel::NONE;      // No compression
/// let balanced = CompressionLevel::DEFAULT; // Level 6
/// let small = CompressionLevel::MAX;      // Maximum compression
///
/// // Or create a custom level (clamped to 0-9)
/// let custom = CompressionLevel::new(3);
/// assert_eq!(custom.level(), 3);
/// ```
#[derive(Debug, Clone, Copy)]
pub struct CompressionLevel(u32);

impl CompressionLevel {
    /// No compression (level 0).
    ///
    /// Fastest creation, largest file size. Useful when the IPA will be
    /// recompressed or when speed is critical.
    pub const NONE: CompressionLevel = CompressionLevel(0);

    /// Default compression (level 6).
    ///
    /// Balanced trade-off between compression speed and output size.
    /// Recommended for most use cases.
    pub const DEFAULT: CompressionLevel = CompressionLevel(6);

    /// Maximum compression (level 9).
    ///
    /// Smallest file size, slowest creation. Use when minimizing
    /// file size is important.
    pub const MAX: CompressionLevel = CompressionLevel(9);

    /// Creates a compression level from 0-9.
    ///
    /// Values greater than 9 are clamped to 9.
    #[must_use]
    pub fn new(level: u32) -> Self {
        CompressionLevel(level.min(9))
    }

    /// Returns the compression level value (0-9).
    #[must_use]
    pub fn level(&self) -> u32 {
        self.0
    }
}

impl Default for CompressionLevel {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl From<u32> for CompressionLevel {
    fn from(level: u32) -> Self {
        CompressionLevel::new(level)
    }
}

/// Creates an IPA file from a signed `.app` bundle.
///
/// The app bundle is placed inside a `Payload/` directory in the archive,
/// following the standard IPA structure expected by iOS.
///
/// For the reverse operation, see [`extract_ipa`](super::extract_ipa).
///
/// # Arguments
///
/// * `app_bundle_path` - Path to the `.app` bundle directory
/// * `output_path` - Path for the output IPA file
/// * `compression_level` - ZIP compression level (see [`CompressionLevel`])
///
/// # Examples
///
/// ```no_run
/// use zsign::ipa::{create_ipa, CompressionLevel};
///
/// // Create with default compression
/// create_ipa("MyApp.app", "output.ipa", CompressionLevel::DEFAULT)?;
///
/// // Create with no compression for faster processing
/// create_ipa("MyApp.app", "fast.ipa", CompressionLevel::NONE)?;
/// # Ok::<(), zsign::Error>(())
/// ```
///
/// # Errors
///
/// Returns [`Error::Io`] if:
/// - The app bundle doesn't exist or is not a directory
/// - The output file cannot be created
/// - Any file cannot be read during archiving
///
/// Returns [`Error::Zip`] if the ZIP archive cannot be written.
pub fn create_ipa(
    app_bundle_path: impl AsRef<Path>,
    output_path: impl AsRef<Path>,
    compression_level: CompressionLevel,
) -> Result<()> {
    let app_bundle_path = app_bundle_path.as_ref();
    let output_path = output_path.as_ref();

    // Validate app bundle exists
    if !app_bundle_path.exists() {
        return Err(Error::Io(io::Error::new(
            io::ErrorKind::NotFound,
            format!("App bundle not found: {}", app_bundle_path.display()),
        )));
    }

    if !app_bundle_path.is_dir() {
        return Err(Error::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Not a directory: {}", app_bundle_path.display()),
        )));
    }

    // Get the app bundle name (e.g., "MyApp.app")
    let app_name = app_bundle_path
        .file_name()
        .ok_or_else(|| {
            Error::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Invalid app bundle path",
            ))
        })?
        .to_string_lossy();

    // Create parent directories for output if needed
    if let Some(parent) = output_path.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent)?;
        }
    }

    // Create ZIP file
    let file = File::create(output_path)?;
    let mut zip = ZipWriter::new(file);

    // Configure compression options
    let options = if compression_level.level() == 0 {
        // For stored (no compression), don't set compression level
        SimpleFileOptions::default()
            .compression_method(CompressionMethod::Stored)
    } else {
        // For deflate, set the compression level
        SimpleFileOptions::default()
            .compression_method(CompressionMethod::Deflated)
            .compression_level(Some(compression_level.level() as i64))
    };

    // Add Payload/ directory
    zip.add_directory("Payload/", options)
        .map_err(Error::Zip)?;

    // Walk the app bundle and add all files - don't follow symlinks
    for entry in WalkDir::new(app_bundle_path).follow_links(false) {
        let entry = entry.map_err(|e| {
            Error::Io(io::Error::other(
                format!("Failed to walk directory: {}", e),
            ))
        })?;

        let path = entry.path();
        let relative_path = path
            .strip_prefix(app_bundle_path)
            .map_err(|_| {
                Error::Io(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Failed to compute relative path",
                ))
            })?;

        // Build archive path: Payload/AppName.app/relative_path
        let archive_path = if relative_path.as_os_str().is_empty() {
            format!("Payload/{}/", app_name)
        } else {
            format!("Payload/{}/{}", app_name, relative_path.display())
        };

        // Use symlink_metadata to check the entry type without following links
        let metadata = fs::symlink_metadata(path)?;

        if metadata.is_dir() {
            // Add directory entry
            let dir_path = if archive_path.ends_with('/') {
                archive_path
            } else {
                format!("{}/", archive_path)
            };
            zip.add_directory(&dir_path, options)
                .map_err(Error::Zip)?;
        } else if metadata.file_type().is_symlink() {
            // Handle symlink using the zip crate's add_symlink method
            let target = fs::read_link(path)?;
            let target_str = target.to_string_lossy();

            zip.add_symlink(&archive_path, target_str, options)
                .map_err(Error::Zip)?;
        } else {
            // Regular file
            #[cfg(unix)]
            let options = {
                use std::os::unix::fs::PermissionsExt;
                let mode = metadata.permissions().mode();
                options.unix_permissions(mode)
            };

            zip.start_file(&archive_path, options)
                .map_err(Error::Zip)?;

            let mut file = File::open(path)?;
            let mut buffer = Vec::new();
            file.read_to_end(&mut buffer)?;
            zip.write_all(&buffer)?;
        }
    }

    // Finalize the archive
    zip.finish().map_err(Error::Zip)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::TempDir;
    use zip::ZipArchive;

    /// Create a test app bundle directory structure.
    fn create_test_app_bundle(dir: &Path) -> PathBuf {
        let app_dir = dir.join("Test.app");
        fs::create_dir_all(&app_dir).unwrap();

        // Create Info.plist
        let info_plist = app_dir.join("Info.plist");
        fs::write(
            &info_plist,
            b"<?xml version=\"1.0\"?><plist><dict></dict></plist>",
        )
        .unwrap();

        // Create executable
        let executable = app_dir.join("Test");
        fs::write(&executable, b"MACHO_PLACEHOLDER").unwrap();

        // Create _CodeSignature directory
        let codesig_dir = app_dir.join("_CodeSignature");
        fs::create_dir_all(&codesig_dir).unwrap();
        let code_resources = codesig_dir.join("CodeResources");
        fs::write(&code_resources, b"<plist></plist>").unwrap();

        // Create a subdirectory with files
        let resources_dir = app_dir.join("Resources");
        fs::create_dir_all(&resources_dir).unwrap();
        fs::write(resources_dir.join("icon.png"), b"PNG_DATA").unwrap();

        app_dir
    }

    #[test]
    fn test_create_ipa() {
        let temp_dir = TempDir::new().unwrap();
        let app_bundle = create_test_app_bundle(temp_dir.path());
        let output_ipa = temp_dir.path().join("output.ipa");

        let result = create_ipa(&app_bundle, &output_ipa, CompressionLevel::DEFAULT);
        assert!(result.is_ok());
        assert!(output_ipa.exists());

        // Verify the IPA structure
        let file = File::open(&output_ipa).unwrap();
        let mut archive = ZipArchive::new(file).unwrap();

        // Check for expected entries
        let mut found_payload = false;
        let mut found_info_plist = false;
        let mut found_executable = false;

        for i in 0..archive.len() {
            let entry = archive.by_index(i).unwrap();
            let name = entry.name();

            if name == "Payload/" || name == "Payload" {
                found_payload = true;
            }
            if name.ends_with("Info.plist") {
                found_info_plist = true;
            }
            if name.ends_with("/Test") {
                found_executable = true;
            }
        }

        assert!(found_payload, "Payload directory not found");
        assert!(found_info_plist, "Info.plist not found");
        assert!(found_executable, "Executable not found");
    }

    #[test]
    fn test_create_ipa_no_compression() {
        let temp_dir = TempDir::new().unwrap();
        let app_bundle = create_test_app_bundle(temp_dir.path());
        let output_ipa = temp_dir.path().join("output_stored.ipa");

        let result = create_ipa(&app_bundle, &output_ipa, CompressionLevel::NONE);
        assert!(result.is_ok(), "Failed: {:?}", result.err());
        assert!(output_ipa.exists());
    }

    #[test]
    fn test_create_ipa_max_compression() {
        let temp_dir = TempDir::new().unwrap();
        let app_bundle = create_test_app_bundle(temp_dir.path());
        let output_ipa = temp_dir.path().join("output_max.ipa");

        let result = create_ipa(&app_bundle, &output_ipa, CompressionLevel::MAX);
        assert!(result.is_ok());
        assert!(output_ipa.exists());
    }

    #[test]
    fn test_create_ipa_not_found() {
        let temp_dir = TempDir::new().unwrap();
        let output_ipa = temp_dir.path().join("output.ipa");

        let result = create_ipa("/nonexistent/Test.app", &output_ipa, CompressionLevel::DEFAULT);
        assert!(result.is_err());
    }

    #[test]
    fn test_create_ipa_not_directory() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("not_a_dir.app");
        fs::write(&file_path, b"not a directory").unwrap();
        let output_ipa = temp_dir.path().join("output.ipa");

        let result = create_ipa(&file_path, &output_ipa, CompressionLevel::DEFAULT);
        assert!(result.is_err());
    }

    #[test]
    fn test_compression_level() {
        assert_eq!(CompressionLevel::NONE.level(), 0);
        assert_eq!(CompressionLevel::DEFAULT.level(), 6);
        assert_eq!(CompressionLevel::MAX.level(), 9);
        assert_eq!(CompressionLevel::new(15).level(), 9); // Clamped
        assert_eq!(CompressionLevel::from(5).level(), 5);
    }

    #[test]
    #[cfg(unix)]
    fn test_create_ipa_preserves_symlinks() {
        use std::os::unix::fs::symlink;

        let temp_dir = TempDir::new().unwrap();
        let app_dir = temp_dir.path().join("Test.app");
        fs::create_dir_all(&app_dir).unwrap();

        // Create framework structure with symlinks
        let framework_versions = app_dir.join("Frameworks/Test.framework/Versions/A");
        fs::create_dir_all(&framework_versions).unwrap();
        fs::write(framework_versions.join("Test"), b"binary").unwrap();

        // Create symlinks
        let versions_dir = app_dir.join("Frameworks/Test.framework/Versions");
        symlink("A", versions_dir.join("Current")).unwrap();
        symlink(
            "Versions/Current/Test",
            app_dir.join("Frameworks/Test.framework/Test"),
        )
        .unwrap();

        fs::write(app_dir.join("Info.plist"), b"<plist></plist>").unwrap();

        // Create IPA
        let output_ipa = temp_dir.path().join("output.ipa");
        let result = create_ipa(&app_dir, &output_ipa, CompressionLevel::DEFAULT);
        assert!(result.is_ok(), "Failed: {:?}", result.err());

        // Verify symlinks in archive
        let file = File::open(&output_ipa).unwrap();
        let mut archive = ZipArchive::new(file).unwrap();

        let mut found_symlink = false;
        for i in 0..archive.len() {
            let entry = archive.by_index(i).unwrap();
            if entry.name().contains("Versions/Current") {
                if let Some(mode) = entry.unix_mode() {
                    // Check if S_IFLNK bit is set
                    if (mode & 0o170000) == 0o120000 {
                        found_symlink = true;
                    }
                }
            }
        }

        assert!(found_symlink, "Symlink should be preserved in ZIP");
    }
}
