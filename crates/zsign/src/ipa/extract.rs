//! IPA archive extraction.
//!
//! Extracts IPA (ZIP) archives and locates the `.app` bundle inside `Payload/`.
//!
//! For the reverse operation, see the [`archive`](super::archive) module.
//!
//! # Features
//!
//! - Memory-mapped file access for performance
//! - Parallel file extraction using rayon
//! - Preserves Unix symlinks and file permissions
//!
//! # Examples
//!
//! ```no_run
//! use zsign_rs::ipa::{extract_ipa, validate_ipa};
//!
//! // Validate before extracting
//! validate_ipa("app.ipa")?;
//!
//! // Extract and get the path to the .app bundle
//! let app_bundle = extract_ipa("app.ipa", "output_dir")?;
//! println!("Extracted to: {}", app_bundle.display());
//! # Ok::<(), zsign_rs::Error>(())
//! ```

use crate::{Error, Result};
use memmap2::Mmap;
use rayon::prelude::*;
use std::collections::HashSet;
use std::fs::{self, File};
use std::borrow::Cow;
use std::io::{self, BufWriter, Cursor, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use zip::ZipArchive;

/// Metadata for a ZIP entry during parallel extraction.
struct ExtractEntry {
    index: usize,
    outpath: PathBuf,
    is_dir: bool,
    is_symlink: bool,
    #[cfg(unix)]
    unix_mode: Option<u32>,
}

/// Validates that a symlink target is safe (not absolute, no `..` traversal).
fn is_safe_symlink_target(target: &str) -> bool {
    if target.starts_with('/') {
        return false;
    }
    target.split('/').all(|component| component != "..")
}

/// Validates that no pre-existing symlink exists in the path from root to the target.
///
/// Walks from `root` downward toward `path`, checking each existing component.
/// If a pre-existing symlink is found, returns an error (prevents symlink attacks).
/// Stops checking at the first non-existent component (will be created fresh).
fn validate_output_path(root: &Path, path: &Path) -> Result<()> {
    let relative = path.strip_prefix(root).map_err(|_| {
        Error::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Path {} is not under root {}", path.display(), root.display()),
        ))
    })?;

    let mut current = root.to_path_buf();
    for component in relative.components() {
        current.push(component);
        // Only check components that already exist
        if let Ok(meta) = fs::symlink_metadata(&current) {
            if meta.file_type().is_symlink() {
                return Err(Error::Io(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "Pre-existing symlink in extraction path: {}",
                        current.display()
                    ),
                )));
            }
        } else {
            // Path doesn't exist yet — safe, stop checking deeper components
            break;
        }
    }
    Ok(())
}

/// Extracts an IPA file to a destination directory.
///
/// IPA files are ZIP archives containing a `Payload/` directory with the `.app` bundle.
/// This function extracts all contents and returns the path to the `.app` bundle.
///
/// For the reverse operation, see [`create_ipa`](super::create_ipa).
///
/// # Arguments
///
/// * `ipa_path` - Path to the IPA file
/// * `dest_dir` - Destination directory for extraction
///
/// # Returns
///
/// Returns the path to the extracted `.app` bundle inside `Payload/`.
///
/// # Examples
///
/// ```no_run
/// use zsign_rs::ipa::extract_ipa;
///
/// let app_bundle = extract_ipa("MyApp.ipa", "extracted")?;
/// assert!(app_bundle.join("Info.plist").exists());
/// # Ok::<(), zsign_rs::Error>(())
/// ```
///
/// # Errors
///
/// Returns [`Error::Io`] if:
/// - The IPA file cannot be opened or read
/// - Extraction fails due to I/O errors
///
/// Returns [`Error::Zip`] if:
/// - The IPA is not a valid ZIP archive
/// - No `.app` bundle is found in `Payload/`
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

    // Verify destination is a real directory (not a symlink)
    let dest_metadata = fs::symlink_metadata(dest_dir)?;
    if dest_metadata.file_type().is_symlink() {
        return Err(Error::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Extraction destination is a symlink: {}", dest_dir.display()),
        )));
    }

    // First pass: collect entry metadata and create directories
    let mut entries: Vec<ExtractEntry> = Vec::with_capacity(archive.len());
    let mut dirs_to_create: HashSet<PathBuf> = HashSet::new();

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
            dirs_to_create.insert(outpath.clone());
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
                    dirs_to_create.insert(parent.to_path_buf());
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
        validate_output_path(dest_dir, dir)?;
        fs::create_dir_all(dir)?;
    }

    // Filter to only files (not directories)
    let file_entries: Vec<_> = entries.into_iter().filter(|e| !e.is_dir).collect();

    // Split into regular files and symlinks
    let (symlink_entries, regular_entries): (Vec<_>, Vec<_>) =
        file_entries.into_iter().partition(|e| e.is_symlink);

    // Phase 1: Parallel extraction of regular files
    let dest_dir_ref = dest_dir;
    let chunk_size = (regular_entries.len() / rayon::current_num_threads()).max(1);
    regular_entries
        .par_chunks(chunk_size)
        .try_for_each(|chunk| -> Result<()> {
            let cursor = Cursor::new(&mmap[..]);
            let mut archive = ZipArchive::new(cursor).map_err(Error::Zip)?;

            for entry in chunk {
                let mut file = archive.by_index(entry.index).map_err(Error::Zip)?;
                validate_output_path(dest_dir_ref, &entry.outpath)?;
                let outfile = File::create(&entry.outpath)?;
                let mut outfile = BufWriter::new(outfile);
                io::copy(&mut file, &mut outfile)?;

                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if let Some(mode) = entry.unix_mode {
                        let perms = mode & 0o7777;
                        fs::set_permissions(&entry.outpath, fs::Permissions::from_mode(perms))?;
                    }
                }
            }
            Ok(())
        })?;

    // Phase 2: Sequential symlink creation (after all files exist)
    #[cfg(unix)]
    {
        let cursor = Cursor::new(&mmap[..]);
        let mut archive = ZipArchive::new(cursor).map_err(Error::Zip)?;

        for entry in &symlink_entries {
            let mut file = archive.by_index(entry.index).map_err(Error::Zip)?;
            let mut target = String::new();
            file.read_to_string(&mut target)?;

            if !is_safe_symlink_target(&target) {
                return Err(Error::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "Unsafe symlink target in IPA: {} -> {}",
                        entry.outpath.display(),
                        target
                    ),
                )));
            }

            if entry.outpath.exists() || entry.outpath.symlink_metadata().is_ok() {
                let _ = fs::remove_file(&entry.outpath);
            }

            use std::os::unix::fs::symlink;
            symlink(&target, &entry.outpath)?;
        }
    }

    // Find .app bundle in Payload/
    find_app_bundle(dest_dir)
}

/// Finds the `.app` bundle inside a `Payload/` directory.
///
/// Searches for a directory with `.app` extension in the `Payload/` subdirectory.
fn find_app_bundle(dest_dir: impl AsRef<Path>) -> Result<PathBuf> {
    let payload_dir = dest_dir.as_ref().join("Payload");

    if !payload_dir.exists() {
        return Err(Error::Zip(zip::result::ZipError::InvalidArchive(
            Cow::Borrowed("No Payload directory found in IPA"),
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
        Cow::Borrowed("No .app bundle found in Payload/"),
    )))
}

/// Validates that a path is a valid IPA file.
///
/// Performs a quick check that the file exists and has a ZIP signature.
/// Use before [`extract_ipa`] to fail fast on invalid files.
///
/// # Examples
///
/// ```no_run
/// use zsign_rs::ipa::validate_ipa;
///
/// validate_ipa("app.ipa")?;
/// println!("IPA is valid");
/// # Ok::<(), zsign_rs::Error>(())
/// ```
///
/// # Errors
///
/// Returns [`Error::Io`] if the file doesn't exist or cannot be read.
/// Returns [`Error::Zip`] if the file is not a valid ZIP archive.
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
            Cow::Borrowed("Not a valid ZIP/IPA file"),
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

    #[test]
    fn test_is_safe_symlink_target() {
        assert!(is_safe_symlink_target("A"));
        assert!(is_safe_symlink_target("Versions/Current/Test"));
        assert!(!is_safe_symlink_target("/etc/passwd"));
        assert!(!is_safe_symlink_target("../../../etc/passwd"));
        assert!(!is_safe_symlink_target("foo/../../bar"));
    }

    #[test]
    #[cfg(unix)]
    fn test_extract_ipa_rejects_malicious_symlink() {
        let temp_dir = TempDir::new().unwrap();
        let ipa_path = temp_dir.path().join("malicious.ipa");

        // Create IPA with a malicious symlink pointing outside
        let file = File::create(&ipa_path).unwrap();
        let mut zip = ZipWriter::new(file);
        let options = SimpleFileOptions::default();

        zip.add_directory("Payload/", options).unwrap();
        zip.add_directory("Payload/Evil.app/", options).unwrap();

        zip.start_file("Payload/Evil.app/Info.plist", options).unwrap();
        zip.write_all(b"<?xml version=\"1.0\"?><plist><dict></dict></plist>")
            .unwrap();

        // Malicious symlink pointing outside extraction dir
        zip.add_symlink(
            "Payload/Evil.app/escape",
            "../../../etc/passwd",
            options,
        )
        .unwrap();

        zip.finish().unwrap();

        let extract_dir = temp_dir.path().join("extracted");
        let result = extract_ipa(&ipa_path, &extract_dir);
        assert!(result.is_err(), "Should reject IPA with malicious symlink");
    }

    #[test]
    #[cfg(unix)]
    fn test_extract_ipa_rejects_symlink_dest() {
        let temp_dir = TempDir::new().unwrap();
        let ipa_path = create_test_ipa(temp_dir.path());

        // Create a symlink as the destination
        let real_dir = temp_dir.path().join("real");
        fs::create_dir(&real_dir).unwrap();
        let symlink_dest = temp_dir.path().join("symlink_dest");
        std::os::unix::fs::symlink(&real_dir, &symlink_dest).unwrap();

        let result = extract_ipa(&ipa_path, &symlink_dest);
        assert!(result.is_err(), "Should reject symlink destination");
    }

    #[test]
    #[cfg(unix)]
    fn test_extract_ipa_rejects_descendant_symlink() {
        let temp_dir = TempDir::new().unwrap();
        let ipa_path = create_test_ipa(temp_dir.path());

        // Create dest with a pre-existing symlink at Payload/
        let extract_dir = temp_dir.path().join("extracted");
        fs::create_dir(&extract_dir).unwrap();
        let evil_dir = temp_dir.path().join("evil");
        fs::create_dir(&evil_dir).unwrap();
        std::os::unix::fs::symlink(&evil_dir, extract_dir.join("Payload")).unwrap();

        let result = extract_ipa(&ipa_path, &extract_dir);
        assert!(result.is_err(), "Should reject pre-existing symlink in extraction path");
    }
}
