//! IPA extraction functionality.
//!
//! Extracts IPA archives to temporary directories and locates the .app bundle.

use crate::{Error, Result};
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use zip::ZipArchive;

/// Extract an IPA file to a destination directory.
///
/// IPA files are ZIP archives containing a Payload/ directory with the .app bundle.
/// This function extracts all contents and returns the path to the .app bundle.
///
/// # Arguments
///
/// * `ipa_path` - Path to the IPA file
/// * `dest_dir` - Destination directory for extraction
///
/// # Returns
///
/// Returns the path to the extracted .app bundle inside Payload/.
///
/// # Errors
///
/// Returns an error if:
/// - The IPA file cannot be opened or read
/// - The IPA is not a valid ZIP archive
/// - No .app bundle is found in Payload/
/// - Extraction fails due to I/O errors
pub fn extract_ipa(ipa_path: impl AsRef<Path>, dest_dir: impl AsRef<Path>) -> Result<PathBuf> {
    let ipa_path = ipa_path.as_ref();
    let dest_dir = dest_dir.as_ref();

    // Validate IPA file exists
    if !ipa_path.exists() {
        return Err(Error::Io(io::Error::new(
            io::ErrorKind::NotFound,
            format!("IPA file not found: {}", ipa_path.display()),
        )));
    }

    // Open ZIP archive
    let file = File::open(ipa_path)?;
    let mut archive = ZipArchive::new(file)
        .map_err(|e| Error::Zip(e))?;

    // Create destination directory if it doesn't exist
    fs::create_dir_all(dest_dir)?;

    // Extract all files
    for i in 0..archive.len() {
        let mut file = archive.by_index(i)
            .map_err(|e| Error::Zip(e))?;

        let outpath = match file.enclosed_name() {
            Some(path) => dest_dir.join(path),
            None => continue, // Skip files with invalid names
        };

        if file.is_dir() {
            fs::create_dir_all(&outpath)?;
        } else {
            // Create parent directories if needed
            if let Some(parent) = outpath.parent() {
                if !parent.exists() {
                    fs::create_dir_all(parent)?;
                }
            }

            // Extract file
            let mut outfile = File::create(&outpath)?;
            io::copy(&mut file, &mut outfile)?;

            // Set file permissions on Unix
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Some(mode) = file.unix_mode() {
                    fs::set_permissions(&outpath, fs::Permissions::from_mode(mode))?;
                }
            }
        }
    }

    // Find .app bundle in Payload/
    find_app_bundle(dest_dir)
}

/// Find the .app bundle inside a Payload/ directory.
///
/// Searches for a directory with .app extension in the Payload/ subdirectory.
fn find_app_bundle(dest_dir: impl AsRef<Path>) -> Result<PathBuf> {
    let payload_dir = dest_dir.as_ref().join("Payload");

    if !payload_dir.exists() {
        return Err(Error::Zip(zip::result::ZipError::InvalidArchive(
            "No Payload directory found in IPA",
        )));
    }

    // Find .app directory
    for entry in fs::read_dir(&payload_dir)? {
        let entry = entry?;
        let path = entry.path();

        if path.is_dir() {
            if let Some(ext) = path.extension() {
                if ext == "app" {
                    return Ok(path);
                }
            }
        }
    }

    Err(Error::Zip(zip::result::ZipError::InvalidArchive(
        "No .app bundle found in Payload/",
    )))
}

/// Validate that a path is a valid IPA file.
///
/// Checks that the file exists and has a ZIP signature.
pub fn validate_ipa(ipa_path: impl AsRef<Path>) -> Result<()> {
    let ipa_path = ipa_path.as_ref();

    if !ipa_path.exists() {
        return Err(Error::Io(io::Error::new(
            io::ErrorKind::NotFound,
            format!("IPA file not found: {}", ipa_path.display()),
        )));
    }

    // Check ZIP magic bytes (PK)
    let mut file = File::open(ipa_path)?;
    let mut magic = [0u8; 4];
    file.read_exact(&mut magic)?;

    // ZIP magic: PK\x03\x04 or PK\x05\x06 (empty) or PK\x07\x08 (spanned)
    if &magic[0..2] != b"PK" {
        return Err(Error::Zip(zip::result::ZipError::InvalidArchive(
            "Not a valid ZIP/IPA file",
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;
    use zip::write::SimpleFileOptions;
    use zip::ZipWriter;

    /// Create a minimal test IPA file with a Payload/Test.app structure.
    fn create_test_ipa(dir: &Path) -> PathBuf {
        let ipa_path = dir.join("test.ipa");
        let file = File::create(&ipa_path).unwrap();
        let mut zip = ZipWriter::new(file);

        let options = SimpleFileOptions::default();

        // Create Payload/ directory entry
        zip.add_directory("Payload/", options).unwrap();

        // Create Payload/Test.app/ directory entry
        zip.add_directory("Payload/Test.app/", options).unwrap();

        // Create a minimal Info.plist inside the app
        zip.start_file("Payload/Test.app/Info.plist", options).unwrap();
        zip.write_all(b"<?xml version=\"1.0\"?><plist><dict></dict></plist>")
            .unwrap();

        // Create a dummy executable
        zip.start_file("Payload/Test.app/Test", options).unwrap();
        zip.write_all(b"MACHO_PLACEHOLDER").unwrap();

        zip.finish().unwrap();

        ipa_path
    }

    #[test]
    fn test_validate_ipa_valid() {
        let temp_dir = TempDir::new().unwrap();
        let ipa_path = create_test_ipa(temp_dir.path());

        let result = validate_ipa(&ipa_path);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_ipa_not_found() {
        let result = validate_ipa("/nonexistent/file.ipa");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_ipa_invalid_format() {
        let temp_dir = TempDir::new().unwrap();
        let invalid_path = temp_dir.path().join("invalid.ipa");
        fs::write(&invalid_path, b"not a zip file").unwrap();

        let result = validate_ipa(&invalid_path);
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_ipa() {
        let temp_dir = TempDir::new().unwrap();
        let ipa_path = create_test_ipa(temp_dir.path());

        let extract_dir = temp_dir.path().join("extracted");
        let result = extract_ipa(&ipa_path, &extract_dir);

        assert!(result.is_ok());
        let app_path = result.unwrap();
        assert!(app_path.ends_with("Test.app"));
        assert!(app_path.exists());
        assert!(app_path.join("Info.plist").exists());
    }

    #[test]
    fn test_extract_ipa_not_found() {
        let temp_dir = TempDir::new().unwrap();
        let result = extract_ipa("/nonexistent/file.ipa", temp_dir.path());
        assert!(result.is_err());
    }

    #[test]
    fn test_find_app_bundle_no_payload() {
        let temp_dir = TempDir::new().unwrap();
        let result = find_app_bundle(temp_dir.path());
        assert!(result.is_err());
    }

    #[test]
    fn test_find_app_bundle_empty_payload() {
        let temp_dir = TempDir::new().unwrap();
        let payload_dir = temp_dir.path().join("Payload");
        fs::create_dir(&payload_dir).unwrap();

        let result = find_app_bundle(temp_dir.path());
        assert!(result.is_err());
    }
}
