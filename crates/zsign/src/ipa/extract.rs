//! IPA extraction functionality.
//!
//! Extracts IPA archives to temporary directories and locates the .app bundle.

use crate::{Error, Result};
use memmap2::Mmap;
use rayon::prelude::*;
use std::fs::{self, File};
use std::io::{self, Cursor, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use zip::ZipArchive;

/// Entry metadata for parallel extraction
struct ExtractEntry {
    index: usize,
    outpath: PathBuf,
    is_dir: bool,
    is_symlink: bool,
    #[cfg(unix)]
    unix_mode: Option<u32>,
}

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

    // Memory-map the IPA file for faster reading
    let file = File::open(ipa_path)?;
    let mmap = unsafe { Mmap::map(&file)? };
    let mmap = Arc::new(mmap);

    // Open ZIP archive from memory-mapped data
    let cursor = Cursor::new(&mmap[..]);
    let mut archive = ZipArchive::new(cursor).map_err(Error::Zip)?;

    // Create destination directory if it doesn't exist
    fs::create_dir_all(dest_dir)?;

    // First pass: collect entry metadata and create directories
    let mut entries: Vec<ExtractEntry> = Vec::with_capacity(archive.len());
    let mut dirs_to_create: Vec<PathBuf> = Vec::new();

    for i in 0..archive.len() {
        let file = archive.by_index(i).map_err(Error::Zip)?;

        let outpath = match file.enclosed_name() {
            Some(path) => dest_dir.join(path),
            None => continue,
        };

        #[cfg(unix)]
        let unix_mode = file.unix_mode();

        #[cfg(unix)]
        let is_symlink = unix_mode
            .map(|mode| (mode & 0o170000) == 0o120000)
            .unwrap_or(false);

        #[cfg(not(unix))]
        let is_symlink = false;

        if file.is_dir() {
            dirs_to_create.push(outpath.clone());
            entries.push(ExtractEntry {
                index: i,
                outpath,
                is_dir: true,
                is_symlink: false,
                #[cfg(unix)]
                unix_mode,
            });
        } else {
            // Collect parent directories
            if let Some(parent) = outpath.parent() {
                if !dirs_to_create.contains(&parent.to_path_buf()) {
                    dirs_to_create.push(parent.to_path_buf());
                }
            }
            entries.push(ExtractEntry {
                index: i,
                outpath,
                is_dir: false,
                is_symlink,
                #[cfg(unix)]
                unix_mode,
            });
        }
    }

    // Create all directories first (sequential, fast)
    for dir in &dirs_to_create {
        fs::create_dir_all(dir)?;
    }

    // Filter to only files (not directories)
    let file_entries: Vec<_> = entries.into_iter().filter(|e| !e.is_dir).collect();

    // Parallel extraction of files
    file_entries
        .par_iter()
        .try_for_each(|entry| -> Result<()> {
            // Each thread gets its own cursor into the mmap
            let cursor = Cursor::new(&mmap[..]);
            let mut archive = ZipArchive::new(cursor).map_err(Error::Zip)?;
            let mut file = archive.by_index(entry.index).map_err(Error::Zip)?;

            #[cfg(unix)]
            if entry.is_symlink {
                // Handle symlink
                let mut target = String::new();
                file.read_to_string(&mut target)?;

                if entry.outpath.exists() || entry.outpath.symlink_metadata().is_ok() {
                    let _ = fs::remove_file(&entry.outpath);
                }

                use std::os::unix::fs::symlink;
                symlink(&target, &entry.outpath)?;
                return Ok(());
            }

            // Regular file extraction
            let mut outfile = File::create(&entry.outpath)?;
            io::copy(&mut file, &mut outfile)?;

            // Set file permissions on Unix
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Some(mode) = entry.unix_mode {
                    let perms = mode & 0o7777;
                    fs::set_permissions(&entry.outpath, fs::Permissions::from_mode(perms))?;
                }
            }

            Ok(())
        })?;

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

    #[test]
    #[cfg(unix)]
    fn test_extract_ipa_with_symlinks() {
        let temp_dir = TempDir::new().unwrap();
        let ipa_path = temp_dir.path().join("symlink_test.ipa");
        
        // Create IPA with symlinks
        let file = File::create(&ipa_path).unwrap();
        let mut zip = ZipWriter::new(file);
        let options = SimpleFileOptions::default();
        
        // Add directories
        zip.add_directory("Payload/", options).unwrap();
        zip.add_directory("Payload/Test.app/", options).unwrap();
        zip.add_directory("Payload/Test.app/Frameworks/", options).unwrap();
        zip.add_directory("Payload/Test.app/Frameworks/Test.framework/", options).unwrap();
        zip.add_directory("Payload/Test.app/Frameworks/Test.framework/Versions/", options).unwrap();
        zip.add_directory("Payload/Test.app/Frameworks/Test.framework/Versions/A/", options).unwrap();
        
        // Real file
        zip.start_file("Payload/Test.app/Frameworks/Test.framework/Versions/A/Test", options).unwrap();
        zip.write_all(b"binary content").unwrap();
        
        // Symlink: Versions/Current -> A (use add_symlink to properly set file type)
        zip.add_symlink(
            "Payload/Test.app/Frameworks/Test.framework/Versions/Current",
            "A",
            options,
        ).unwrap();
        
        zip.start_file("Payload/Test.app/Info.plist", options).unwrap();
        zip.write_all(b"<?xml version=\"1.0\"?><plist><dict></dict></plist>").unwrap();
        
        zip.finish().unwrap();
        
        // Extract and verify
        let extract_dir = temp_dir.path().join("extracted");
        let result = extract_ipa(&ipa_path, &extract_dir);
        assert!(result.is_ok(), "Extraction failed: {:?}", result.err());
        
        // Check if symlink was preserved
        let symlink_path = extract_dir.join("Payload/Test.app/Frameworks/Test.framework/Versions/Current");
        let metadata = std::fs::symlink_metadata(&symlink_path);
        
        if let Ok(meta) = metadata {
            assert!(meta.file_type().is_symlink(), "Current should be a symlink");
            let target = std::fs::read_link(&symlink_path).unwrap();
            assert_eq!(target.to_str().unwrap(), "A");
        }
    }
}
