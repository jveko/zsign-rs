//! IPA archive extraction.
//!
//! Extracts IPA (ZIP) archives and locates the `.app` bundle inside `Payload/`.
//!
//! For the reverse operation, see the [`archive`](super::archive) module.
//!
//! # Features
//!
//! - Buffered file reads with bounded memory use
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
use rayon::prelude::*;
use std::borrow::Cow;
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
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

/// Wraps the extraction output and enforces byte budgets before any data
/// reaches the underlying writer.
///
/// Every buffer is checked against the entry cap and reserved from the
/// shared total first, so parallel workers cannot overshoot either cap: what
/// reaches disk stays within budget.
struct BudgetedWriter<'a, W> {
    inner: W,
    relative: &'a Path,
    entry_written: u64,
    max_entry_bytes: u64,
    total: &'a AtomicU64,
    max_total_bytes: u64,
}

impl<W: io::Write> io::Write for BudgetedWriter<'_, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = buf.len() as u64;
        if self.entry_written + n > self.max_entry_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Archive exceeds extraction limit: entry '{}' exceeds {} bytes",
                    self.relative.display(),
                    self.max_entry_bytes
                ),
            ));
        }
        let total = self.total.fetch_add(n, Ordering::Relaxed) + n;
        if total > self.max_total_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Archive exceeds extraction limit: total extracted size exceeds {} bytes",
                    self.max_total_bytes
                ),
            ));
        }
        let written = self.inner.write(buf)?;
        self.entry_written += written as u64;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Validates that a symlink target is safe (not absolute, no `..` traversal).
fn is_safe_symlink_target(target: &str) -> bool {
    if target.starts_with('/') {
        return false;
    }
    target.split('/').all(|component| component != "..")
}

/// Maximum symlink target length accepted during extraction.
///
/// Matches Linux `PATH_MAX`: longer targets can never be created by
/// `symlink(2)`, and bounding the read keeps a hostile entry from buffering
/// gigabytes before validation. Unix-only, like the symlink pass that uses it.
#[cfg(unix)]
const MAX_SYMLINK_TARGET_BYTES: usize = 4096;

/// Returns true if an archive entry name is absolute, uses `..` traversal,
/// or has no substantive component.
///
/// Both separator spellings are checked because the zip reader
/// componentizes names with Windows-path semantics (`Utf8WindowsPath`):
/// `C:/evil` and `\evil` would otherwise be silently relocated inside the
/// destination instead of rejected. Empty and dot-only names (the empty string,
/// `.`, and `./`) are rejected too: zip encloses them as an empty path that resolves
/// to the destination directory itself.
fn is_unsafe_entry_name(name: &str) -> bool {
    if name.starts_with('/') || name.starts_with('\\') {
        return true;
    }
    let bytes = name.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        return true;
    }
    let mut substantive = false;
    for segment in name.split(['/', '\\']) {
        if segment == ".." {
            return true;
        }
        if !segment.is_empty() && segment != "." {
            substantive = true;
        }
    }
    !substantive
}

/// Returns an ancestor of `path` strictly below `dest_dir` that is already
/// registered as a file entry, if any.
///
/// Walks the whole parent chain: a file `Payload/a` must also reject
/// `Payload/a/b/c`, whose immediate parent is not itself registered. The
/// walk stops at `dest_dir` and never proceeds above it.
fn file_ancestor<'a>(
    path: &Path,
    dest_dir: &Path,
    file_paths: &'a HashSet<PathBuf>,
) -> Option<&'a PathBuf> {
    let mut ancestor = path.parent();
    while let Some(dir) = ancestor {
        if dir == dest_dir || !dir.starts_with(dest_dir) {
            return None;
        }
        if let Some(hit) = file_paths.get(dir) {
            return Some(hit);
        }
        ancestor = dir.parent();
    }
    None
}

/// Registers every ancestor of `path` strictly below `dest_dir` as a path
/// that must exist as a directory.
///
/// Claims are recorded when each entry is seen so conflict detection is
/// order-independent: an archive listing `Payload/a/b/c` before
/// `Payload/a` is rejected the same way as the reverse order. The walk
/// stops at `dest_dir` and never claims the destination or anything above
/// it, even if a name encloses to the destination itself.
fn register_ancestor_dirs(path: &Path, dest_dir: &Path, dirs: &mut HashSet<PathBuf>) {
    let mut ancestor = path.parent();
    while let Some(dir) = ancestor {
        if dir == dest_dir || !dir.starts_with(dest_dir) {
            break;
        }
        if !dirs.contains(dir) {
            dirs.insert(dir.to_path_buf());
        }
        ancestor = dir.parent();
    }
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
            format!(
                "Path {} is not under root {}",
                path.display(),
                root.display()
            ),
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

/// Byte budgets enforced while writing extracted archive contents.
///
/// Defaults (used by [`extract_ipa`]): 2 GiB per entry, 8 GiB total.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtractionLimits {
    /// Maximum uncompressed size of a single archive entry, in bytes.
    pub max_entry_bytes: u64,
    /// Maximum total uncompressed size across all entries, in bytes.
    pub max_total_bytes: u64,
}

impl Default for ExtractionLimits {
    fn default() -> Self {
        ExtractionLimits {
            max_entry_bytes: 2 * 1024 * 1024 * 1024,
            max_total_bytes: 8 * 1024 * 1024 * 1024,
        }
    }
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
/// - Returns [`Error::Io`] if an archive entry name is unsafe (traversal or absolute)
/// - Returns [`Error::Io`] if an archive entry or the archive total exceeds the default extraction limits (2 GiB per entry, 8 GiB total)
///
/// Returns [`Error::Zip`] if:
/// - The IPA is not a valid ZIP archive
/// - No `.app` bundle is found in `Payload/`
pub fn extract_ipa(ipa_path: impl AsRef<Path>, dest_dir: impl AsRef<Path>) -> Result<PathBuf> {
    extract_ipa_with_limits(ipa_path, dest_dir, ExtractionLimits::default())
}

/// Extracts an IPA file with explicit extraction byte budgets.
///
/// Same as [`extract_ipa`], but the caller chooses the zip-bomb limits.
/// Extraction fails with [`Error::Io`] (`InvalidData`) as soon as an entry
/// or the archive total exceeds its budget — the check runs before each
/// buffer is written, so no unbudgeted bytes reach disk.
///
/// # Examples
///
/// ```no_run
/// use zsign_rs::ipa::extract::{extract_ipa_with_limits, ExtractionLimits};
///
/// let limits = ExtractionLimits {
///     max_entry_bytes: 512 * 1024 * 1024,
///     max_total_bytes: 2 * 1024 * 1024 * 1024,
/// };
/// let app_bundle = extract_ipa_with_limits("MyApp.ipa", "extracted", limits)?;
/// println!("Extracted to: {}", app_bundle.display());
/// # Ok::<(), zsign_rs::Error>(())
/// ```
///
/// # Errors
///
/// Returns [`Error::Io`] if the IPA is missing, an entry name is unsafe, a
/// path is a pre-existing symlink, or an extraction byte budget is exceeded.
/// Returns [`Error::Zip`] if the file is not a valid ZIP archive or no
/// `.app` bundle is found in `Payload/`.
pub fn extract_ipa_with_limits(
    ipa_path: impl AsRef<Path>,
    dest_dir: impl AsRef<Path>,
    limits: ExtractionLimits,
) -> Result<PathBuf> {
    let ipa_path = ipa_path.as_ref();
    let dest_dir = dest_dir.as_ref();

    // Validate IPA file exists
    if !ipa_path.exists() {
        return Err(Error::Io(io::Error::new(
            io::ErrorKind::NotFound,
            format!("IPA file not found: {}", ipa_path.display()),
        )));
    }

    // Buffered reads; rayon already parallelizes across entries, so
    // re-opening the archive per pass keeps memory bounded without mmap.
    let file = File::open(ipa_path)?;
    let mut archive = ZipArchive::new(BufReader::new(file)).map_err(Error::Zip)?;

    // Create destination directory if it doesn't exist
    fs::create_dir_all(dest_dir)?;

    // Verify destination is a real directory (not a symlink)
    let dest_metadata = fs::symlink_metadata(dest_dir)?;
    if dest_metadata.file_type().is_symlink() {
        return Err(Error::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "Extraction destination is a symlink: {}",
                dest_dir.display()
            ),
        )));
    }

    // First pass: collect entry metadata and create directories
    let mut entries: Vec<ExtractEntry> = Vec::with_capacity(archive.len());
    let mut dirs_to_create: HashSet<PathBuf> = HashSet::new();
    let mut file_paths: HashSet<PathBuf> = HashSet::new();

    for i in 0..archive.len() {
        let file = archive.by_index(i).map_err(Error::Zip)?;

        let name = file.name();
        if is_unsafe_entry_name(name) {
            return Err(Error::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Unsafe entry name in IPA: {}", name),
            )));
        }

        let outpath = match file.enclosed_name() {
            Some(path) if !path.as_os_str().is_empty() => dest_dir.join(path),
            _ => {
                return Err(Error::Io(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("Unsafe entry name in IPA: {}", name),
                )))
            }
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
            if file_paths.contains(&outpath) {
                let relative = outpath.strip_prefix(dest_dir).unwrap_or(&outpath);
                return Err(Error::Io(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("Conflicting entry path in IPA: {}", relative.display()),
                )));
            }
            if let Some(hit) = file_ancestor(&outpath, dest_dir, &file_paths) {
                let relative = hit.strip_prefix(dest_dir).unwrap_or(hit);
                return Err(Error::Io(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("Conflicting entry path in IPA: {}", relative.display()),
                )));
            }
            dirs_to_create.insert(outpath.clone());
            // Claim every implied ancestor as a must-be-directory so a
            // later file at the same path is rejected in the collect pass,
            // whichever order the archive lists them. A dir entry that
            // contains registered files stays legal — claims add no new
            // rejection here.
            register_ancestor_dirs(&outpath, dest_dir, &mut dirs_to_create);
            entries.push(ExtractEntry {
                index: i,
                outpath,
                is_dir: true,
                is_symlink: false,
                #[cfg(unix)]
                unix_mode,
            });
        } else {
            if file_paths.contains(&outpath) {
                let relative = outpath.strip_prefix(dest_dir).unwrap_or(&outpath);
                return Err(Error::Io(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("Duplicate entry path in IPA: {}", relative.display()),
                )));
            }
            if dirs_to_create.contains(&outpath) {
                let relative = outpath.strip_prefix(dest_dir).unwrap_or(&outpath);
                return Err(Error::Io(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("Conflicting entry path in IPA: {}", relative.display()),
                )));
            }
            if let Some(hit) = file_ancestor(&outpath, dest_dir, &file_paths) {
                let relative = hit.strip_prefix(dest_dir).unwrap_or(hit);
                return Err(Error::Io(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("Conflicting entry path in IPA: {}", relative.display()),
                )));
            }
            // Claim this entry's ancestor chain as must-be-directories; the
            // walk above already rejected file ancestors, and a later file
            // at any claimed path conflicts below.
            register_ancestor_dirs(&outpath, dest_dir, &mut dirs_to_create);
            file_paths.insert(outpath.clone());
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
    let total_written = AtomicU64::new(0);
    let chunk_size = (regular_entries.len() / rayon::current_num_threads()).max(1);
    regular_entries
        .par_chunks(chunk_size)
        .try_for_each(|chunk| -> Result<()> {
            let file = File::open(ipa_path)?;
            let mut archive = ZipArchive::new(BufReader::new(file)).map_err(Error::Zip)?;

            for entry in chunk {
                let mut file = archive.by_index(entry.index).map_err(Error::Zip)?;
                validate_output_path(dest_dir_ref, &entry.outpath)?;
                let outfile = File::create(&entry.outpath)?;
                let relative = entry
                    .outpath
                    .strip_prefix(dest_dir_ref)
                    .unwrap_or(&entry.outpath);
                let mut budgeted = BudgetedWriter {
                    inner: BufWriter::new(outfile),
                    relative,
                    entry_written: 0,
                    max_entry_bytes: limits.max_entry_bytes,
                    total: &total_written,
                    max_total_bytes: limits.max_total_bytes,
                };
                io::copy(&mut file, &mut budgeted)?;

                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if let Some(mode) = entry.unix_mode {
                        let perms = mode & 0o777;
                        fs::set_permissions(&entry.outpath, fs::Permissions::from_mode(perms))?;
                    }
                }
            }
            Ok(())
        })?;

    // Phase 2: Sequential symlink creation (after all files exist)
    #[cfg(unix)]
    {
        let file = File::open(ipa_path)?;
        let mut archive = ZipArchive::new(BufReader::new(file)).map_err(Error::Zip)?;

        for entry in &symlink_entries {
            let file = archive.by_index(entry.index).map_err(Error::Zip)?;
            // Bound the read before validation: a hostile symlink entry must
            // never buffer more than the limit into memory.
            let mut target = String::new();
            file.take(MAX_SYMLINK_TARGET_BYTES as u64 + 1)
                .read_to_string(&mut target)?;
            if target.len() > MAX_SYMLINK_TARGET_BYTES {
                return Err(Error::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "Symlink target too long in IPA: {} ({} bytes, limit {})",
                        entry.outpath.display(),
                        target.len(),
                        MAX_SYMLINK_TARGET_BYTES
                    ),
                )));
            }

            // Symlink targets count toward both budgets, reserved before
            // the link is created.
            if target.len() as u64 > limits.max_entry_bytes {
                let relative = entry
                    .outpath
                    .strip_prefix(dest_dir)
                    .unwrap_or(&entry.outpath);
                return Err(Error::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "Archive exceeds extraction limit: entry '{}' exceeds {} bytes",
                        relative.display(),
                        limits.max_entry_bytes
                    ),
                )));
            }
            let target_bytes = target.len() as u64;
            let total = total_written.fetch_add(target_bytes, Ordering::Relaxed) + target_bytes;
            if total > limits.max_total_bytes {
                return Err(Error::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "Archive exceeds extraction limit: total extracted size exceeds {} bytes",
                        limits.max_total_bytes
                    ),
                )));
            }

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
        zip.start_file("Payload/Test.app/Info.plist", options)
            .unwrap();
        zip.write_all(b"<?xml version=\"1.0\"?><plist><dict></dict></plist>")
            .unwrap();

        // Create a dummy executable
        zip.start_file("Payload/Test.app/Test", options).unwrap();
        zip.write_all(b"MACHO_PLACEHOLDER").unwrap();

        zip.finish().unwrap();

        ipa_path
    }
    /// Build an otherwise-valid IPA that additionally contains `hostile_name`.
    fn create_ipa_with_hostile_entry(dir: &Path, hostile_name: &str) -> PathBuf {
        let ipa_path = dir.join("hostile.ipa");
        let file = File::create(&ipa_path).unwrap();
        let mut zip = ZipWriter::new(file);
        let options = SimpleFileOptions::default();

        zip.add_directory("Payload/", options).unwrap();
        zip.add_directory("Payload/Test.app/", options).unwrap();
        zip.start_file("Payload/Test.app/Info.plist", options)
            .unwrap();
        zip.write_all(b"<?xml version=\"1.0\"?><plist><dict></dict></plist>")
            .unwrap();

        zip.start_file(hostile_name, options).unwrap();
        zip.write_all(b"evil content").unwrap();

        zip.finish().unwrap();
        ipa_path
    }

    fn assert_rejects_hostile_entry(hostile_name: &str) {
        let temp_dir = TempDir::new().unwrap();
        let ipa_path = create_ipa_with_hostile_entry(temp_dir.path(), hostile_name);
        let extract_dir = temp_dir.path().join("extracted");
        let err = extract_ipa(&ipa_path, &extract_dir)
            .expect_err("hostile entry name must fail the extraction");
        let msg = err.to_string();
        assert!(
            msg.contains("Unsafe entry name in IPA"),
            "unexpected error: {msg}"
        );
        assert!(
            msg.contains(hostile_name),
            "error must name the entry: {msg}"
        );
    }

    #[test]
    fn test_extract_ipa_rejects_parent_traversal_entry() {
        assert_rejects_hostile_entry("../evil");
    }

    #[test]
    fn test_extract_ipa_rejects_nested_traversal_entry() {
        assert_rejects_hostile_entry("Payload/../../evil");
        // Spelling that enclosed_name() silently normalizes instead of
        // rejecting — the raw-name check must still fail closed.
        assert_rejects_hostile_entry("Payload/../evil");
    }

    #[test]
    fn test_extract_ipa_rejects_absolute_entry_name() {
        assert_rejects_hostile_entry("/abs/evil");
        // Names with no real component: zip encloses these as an empty path
        // resolving to the destination itself.
        assert_rejects_hostile_entry("");
        assert_rejects_hostile_entry(".");
        assert_rejects_hostile_entry("./");
        // A NUL name is the one form that reaches the `enclosed_name()`
        // non-`Some` arm (the raw check passes) — this pins that arm.
        assert_rejects_hostile_entry("Payload/\0evil");
    }

    #[test]
    fn test_extract_ipa_rejects_windows_style_absolute_entry_name() {
        assert_rejects_hostile_entry("C:/abs/evil");
        assert_rejects_hostile_entry("\\abs\\evil");
        // Backslash traversal that Windows-path componentization pops
        // instead of rejecting.
        assert_rejects_hostile_entry("Payload\\sub\\..\\evil");
    }

    #[test]
    fn test_extract_ipa_rejects_oversized_entry() {
        let temp_dir = TempDir::new().unwrap();
        let ipa_path = temp_dir.path().join("entry_bomb.ipa");
        let file = File::create(&ipa_path).unwrap();
        let mut zip = ZipWriter::new(file);
        let options = SimpleFileOptions::default();
        zip.add_directory("Payload/", options).unwrap();
        zip.add_directory("Payload/Test.app/", options).unwrap();
        zip.start_file("Payload/Test.app/Info.plist", options)
            .unwrap();
        zip.write_all(&vec![b'A'; 2048]).unwrap();
        zip.finish().unwrap();

        let limits = ExtractionLimits {
            max_entry_bytes: 100,
            max_total_bytes: 100_000,
        };
        let extract_dir = temp_dir.path().join("extracted");
        let err = extract_ipa_with_limits(&ipa_path, &extract_dir, limits)
            .expect_err("oversized entry must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("Archive exceeds extraction limit"),
            "unexpected error: {msg}"
        );
        assert!(
            msg.contains("Payload/Test.app/Info.plist"),
            "error must name the entry: {msg}"
        );
    }

    #[test]
    fn test_extract_ipa_rejects_oversized_total() {
        let temp_dir = TempDir::new().unwrap();
        let ipa_path = temp_dir.path().join("total_bomb.ipa");
        let file = File::create(&ipa_path).unwrap();
        let mut zip = ZipWriter::new(file);
        let options = SimpleFileOptions::default();
        zip.add_directory("Payload/", options).unwrap();
        zip.add_directory("Payload/Test.app/", options).unwrap();
        zip.start_file("Payload/Test.app/Info.plist", options)
            .unwrap();
        zip.write_all(&vec![b'A'; 600]).unwrap();
        zip.start_file("Payload/Test.app/Test", options).unwrap();
        zip.write_all(&vec![b'B'; 600]).unwrap();
        zip.finish().unwrap();

        let limits = ExtractionLimits {
            max_entry_bytes: 1_000,
            max_total_bytes: 1_000,
        };
        let extract_dir = temp_dir.path().join("extracted");
        let err = extract_ipa_with_limits(&ipa_path, &extract_dir, limits)
            .expect_err("total size over budget must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("Archive exceeds extraction limit"),
            "unexpected error: {msg}"
        );
        assert!(msg.contains("total"), "error must mention the total: {msg}");
    }

    #[test]
    #[cfg(unix)]
    fn test_extract_ipa_rejects_total_overflow_from_symlinks() {
        let temp_dir = TempDir::new().unwrap();
        let ipa_path = temp_dir.path().join("symlink_budget.ipa");
        let file = File::create(&ipa_path).unwrap();
        let mut zip = ZipWriter::new(file);
        let options = SimpleFileOptions::default();
        zip.add_directory("Payload/", options).unwrap();
        zip.add_directory("Payload/Test.app/", options).unwrap();
        zip.start_file("Payload/Test.app/Info.plist", options)
            .unwrap();
        zip.write_all(b"<?xml version=\"1.0\"?><plist><dict></dict></plist>")
            .unwrap();
        zip.add_symlink("Payload/Test.app/link1", "a".repeat(4090), options)
            .unwrap();
        zip.add_symlink("Payload/Test.app/link2", "a".repeat(4090), options)
            .unwrap();
        zip.finish().unwrap();

        let limits = ExtractionLimits {
            max_entry_bytes: 1_000_000,
            max_total_bytes: 5_000,
        };
        let extract_dir = temp_dir.path().join("extracted");
        let err = extract_ipa_with_limits(&ipa_path, &extract_dir, limits)
            .expect_err("symlink bytes over the total budget must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("Archive exceeds extraction limit"),
            "unexpected error: {msg}"
        );
        assert!(msg.contains("total"), "error must mention the total: {msg}");
    }

    #[test]
    #[cfg(unix)]
    fn test_extract_ipa_rejects_long_symlink_target() {
        let temp_dir = TempDir::new().unwrap();
        let ipa_path = temp_dir.path().join("long_target.ipa");
        let file = File::create(&ipa_path).unwrap();
        let mut zip = ZipWriter::new(file);
        let options = SimpleFileOptions::default();
        zip.add_directory("Payload/", options).unwrap();
        zip.add_directory("Payload/Test.app/", options).unwrap();
        zip.start_file("Payload/Test.app/Info.plist", options)
            .unwrap();
        zip.write_all(b"<?xml version=\"1.0\"?><plist><dict></dict></plist>")
            .unwrap();
        zip.add_symlink("Payload/Test.app/link", "a".repeat(5000), options)
            .unwrap();
        zip.finish().unwrap();

        let extract_dir = temp_dir.path().join("extracted");
        let err = extract_ipa(&ipa_path, &extract_dir)
            .expect_err("oversized symlink target must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("Symlink target too long in IPA"),
            "unexpected error: {msg}"
        );
    }

    /// Overwrite one central-directory entry's unix mode.
    ///
    /// The zip write API masks modes through `unix_permissions(0o777)`, so a
    /// setuid fixture has to patch the central-directory record directly.
    /// `external_file_attributes` (offset 38) stores the mode in its high 16
    /// bits; the low 16 bits hold DOS attributes and are preserved.
    #[cfg(unix)]
    fn patch_central_dir_unix_mode(archive_path: &Path, entry_name: &str, mode: u32) {
        let mut bytes = fs::read(archive_path).unwrap();

        let eocd = bytes
            .windows(4)
            .rposition(|w| w == [0x50, 0x4b, 0x05, 0x06])
            .expect("end-of-central-directory record not found");
        let entry_count = u16::from_le_bytes([bytes[eocd + 10], bytes[eocd + 11]]) as usize;
        let mut pos = u32::from_le_bytes([
            bytes[eocd + 16],
            bytes[eocd + 17],
            bytes[eocd + 18],
            bytes[eocd + 19],
        ]) as usize;

        for _ in 0..entry_count {
            assert_eq!(
                &bytes[pos..pos + 4],
                b"PK\x01\x02",
                "bad central directory entry"
            );
            let name_len = u16::from_le_bytes([bytes[pos + 28], bytes[pos + 29]]) as usize;
            let extra_len = u16::from_le_bytes([bytes[pos + 30], bytes[pos + 31]]) as usize;
            let comment_len = u16::from_le_bytes([bytes[pos + 32], bytes[pos + 33]]) as usize;
            let name = std::str::from_utf8(&bytes[pos + 46..pos + 46 + name_len]).unwrap();
            if name == entry_name {
                let attr_pos = pos + 38;
                let mut attr = [0u8; 4];
                attr.copy_from_slice(&bytes[attr_pos..attr_pos + 4]);
                let old = u32::from_le_bytes(attr);
                let patched = (mode << 16) | (old & 0xffff);
                bytes[attr_pos..attr_pos + 4].copy_from_slice(&patched.to_le_bytes());
                fs::write(archive_path, &bytes).unwrap();
                return;
            }
            pos += 46 + name_len + extra_len + comment_len;
        }
        panic!("entry {entry_name} not found in central directory");
    }

    #[test]
    #[cfg(unix)]
    fn test_extract_ipa_strips_setuid_bit() {
        let temp_dir = TempDir::new().unwrap();
        let ipa_path = temp_dir.path().join("setuid.ipa");
        let file = File::create(&ipa_path).unwrap();
        let mut zip = ZipWriter::new(file);
        let options = SimpleFileOptions::default();
        zip.add_directory("Payload/", options).unwrap();
        zip.add_directory("Payload/Test.app/", options).unwrap();
        // Empty content on purpose: the kernel strips setuid/setgid on any
        // write, and production chmods before the BufWriter's final flush.
        // With zero bytes the permission restore is the last filesystem
        // operation, so a surviving setuid bit stays observable — otherwise
        // the post-chmod flush would clear it and this test would false-green.
        zip.start_file("Payload/Test.app/Info.plist", options)
            .unwrap();
        zip.finish().unwrap();

        // 0o104755 = S_IFREG | setuid | rwxr-xr-x
        patch_central_dir_unix_mode(&ipa_path, "Payload/Test.app/Info.plist", 0o104755);

        let extract_dir = temp_dir.path().join("extracted");
        let app = extract_ipa(&ipa_path, &extract_dir).unwrap();

        use std::os::unix::fs::PermissionsExt;
        let mode = app
            .join("Info.plist")
            .metadata()
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o7777,
            0o755,
            "setuid must not survive extraction, got {mode:o}"
        );
    }

    /// Build an IPA from `build`, extract it, and assert a collect-pass
    /// type conflict naming `expected` with no payload content written.
    fn assert_type_conflict(
        expected: &str,
        build: impl FnOnce(&mut ZipWriter<File>, SimpleFileOptions),
    ) {
        let temp_dir = TempDir::new().unwrap();
        let ipa_path = temp_dir.path().join("conflict.ipa");
        let file = File::create(&ipa_path).unwrap();
        let mut zip = ZipWriter::new(file);
        let options = SimpleFileOptions::default();
        zip.add_directory("Payload/", options).unwrap();
        build(&mut zip, options);
        zip.finish().unwrap();

        let extract_dir = temp_dir.path().join("extracted");
        let err = extract_ipa(&ipa_path, &extract_dir)
            .expect_err("type conflict must be rejected in the collect pass");
        let msg = err.to_string();
        assert!(
            msg.contains("Conflicting entry path in IPA"),
            "unexpected error: {msg}"
        );
        assert!(msg.contains(expected), "error must name {expected}: {msg}");
        assert!(
            !extract_dir.join("Payload").exists(),
            "collect-pass rejection must write no payload content"
        );
    }

    #[test]
    fn test_extract_ipa_rejects_duplicate_normalized_paths() {
        let temp_dir = TempDir::new().unwrap();
        let ipa_path = temp_dir.path().join("duplicate.ipa");
        let file = File::create(&ipa_path).unwrap();
        let mut zip = ZipWriter::new(file);
        let options = SimpleFileOptions::default();
        zip.add_directory("Payload/", options).unwrap();
        zip.add_directory("Payload/Test.app/", options).unwrap();
        zip.start_file("Payload/Test.app/Info.plist", options)
            .unwrap();
        zip.write_all(b"<?xml version=\"1.0\"?><plist><dict></dict></plist>")
            .unwrap();
        // Textually distinct raw name, identical path once normalized.
        zip.start_file("./Payload/Test.app/Info.plist", options)
            .unwrap();
        zip.write_all(b"second copy").unwrap();
        zip.finish().unwrap();

        let extract_dir = temp_dir.path().join("extracted");
        let err = extract_ipa(&ipa_path, &extract_dir)
            .expect_err("duplicate normalized path must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("Duplicate entry path in IPA"),
            "unexpected error: {msg}"
        );
        assert!(
            msg.contains("Payload/Test.app/Info.plist"),
            "error must name the path: {msg}"
        );
    }

    #[test]
    fn test_extract_ipa_rejects_type_conflicting_entries() {
        // Same path, directory entry first.
        assert_type_conflict("Payload/D", |zip, options| {
            zip.add_directory("Payload/D", options).unwrap();
            zip.start_file("Payload/D", options).unwrap();
            zip.write_all(b"file where a directory is").unwrap();
        });
        // Same path, file entry first — the dir branch's same-path check.
        assert_type_conflict("Payload/D", |zip, options| {
            zip.start_file("Payload/D", options).unwrap();
            zip.write_all(b"file where a directory will be").unwrap();
            zip.add_directory("Payload/D", options).unwrap();
        });
        // Directory entry under an already-registered file — the dir
        // branch's ancestor walk.
        assert_type_conflict("Payload/a", |zip, options| {
            zip.start_file("Payload/a", options).unwrap();
            zip.write_all(b"i am a file").unwrap();
            zip.add_directory("Payload/a/b", options).unwrap();
        });
        // File entry after a directory chain claimed its path — the
        // ancestor claim registered by the dir branch.
        assert_type_conflict("Payload/a", |zip, options| {
            zip.add_directory("Payload/a/b", options).unwrap();
            zip.start_file("Payload/a", options).unwrap();
            zip.write_all(b"i am a file").unwrap();
        });
    }

    #[test]
    fn test_extract_ipa_rejects_descendant_of_file_entry() {
        // Order 1: file ancestor first, then its descendant.
        let temp_dir = TempDir::new().unwrap();
        let ipa_path = temp_dir.path().join("descendant.ipa");
        let file = File::create(&ipa_path).unwrap();
        let mut zip = ZipWriter::new(file);
        let options = SimpleFileOptions::default();
        zip.add_directory("Payload/", options).unwrap();
        zip.start_file("Payload/a", options).unwrap();
        zip.write_all(b"i am a file").unwrap();
        zip.start_file("Payload/a/b/c", options).unwrap();
        zip.write_all(b"descendant of a file").unwrap();
        zip.finish().unwrap();

        let extract_dir = temp_dir.path().join("extracted");
        let err = extract_ipa(&ipa_path, &extract_dir)
            .expect_err("entry under a file must be rejected in the collect pass");
        let msg = err.to_string();
        assert!(
            msg.contains("Conflicting entry path in IPA"),
            "unexpected error: {msg}"
        );
        assert!(msg.contains("Payload/a"), "error must name the path: {msg}");

        // Order 2: descendant registered first — the later ancestor file
        // must hit the same collect-pass conflict, not an OS error after
        // directories have been created.
        let temp_dir = TempDir::new().unwrap();
        let ipa_path = temp_dir.path().join("descendant_first.ipa");
        let file = File::create(&ipa_path).unwrap();
        let mut zip = ZipWriter::new(file);
        zip.add_directory("Payload/", options).unwrap();
        zip.start_file("Payload/a/b/c", options).unwrap();
        zip.write_all(b"descendant of a file").unwrap();
        zip.start_file("Payload/a", options).unwrap();
        zip.write_all(b"i am a file").unwrap();
        zip.finish().unwrap();

        let extract_dir = temp_dir.path().join("extracted");
        let err = extract_ipa(&ipa_path, &extract_dir)
            .expect_err("ancestor file after its descendant must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("Conflicting entry path in IPA"),
            "unexpected error: {msg}"
        );
        assert!(msg.contains("Payload/a"), "error must name the path: {msg}");
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
        zip.add_directory("Payload/Test.app/Frameworks/", options)
            .unwrap();
        zip.add_directory("Payload/Test.app/Frameworks/Test.framework/", options)
            .unwrap();
        zip.add_directory(
            "Payload/Test.app/Frameworks/Test.framework/Versions/",
            options,
        )
        .unwrap();
        zip.add_directory(
            "Payload/Test.app/Frameworks/Test.framework/Versions/A/",
            options,
        )
        .unwrap();

        // Real file
        zip.start_file(
            "Payload/Test.app/Frameworks/Test.framework/Versions/A/Test",
            options,
        )
        .unwrap();
        zip.write_all(b"binary content").unwrap();

        // Symlink: Versions/Current -> A (use add_symlink to properly set file type)
        zip.add_symlink(
            "Payload/Test.app/Frameworks/Test.framework/Versions/Current",
            "A",
            options,
        )
        .unwrap();

        zip.start_file("Payload/Test.app/Info.plist", options)
            .unwrap();
        zip.write_all(b"<?xml version=\"1.0\"?><plist><dict></dict></plist>")
            .unwrap();

        zip.finish().unwrap();

        // Extract and verify
        let extract_dir = temp_dir.path().join("extracted");
        let result = extract_ipa(&ipa_path, &extract_dir);
        assert!(result.is_ok(), "Extraction failed: {:?}", result.err());

        // Check if symlink was preserved
        let symlink_path =
            extract_dir.join("Payload/Test.app/Frameworks/Test.framework/Versions/Current");
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

        zip.start_file("Payload/Evil.app/Info.plist", options)
            .unwrap();
        zip.write_all(b"<?xml version=\"1.0\"?><plist><dict></dict></plist>")
            .unwrap();

        // Malicious symlink pointing outside extraction dir
        zip.add_symlink("Payload/Evil.app/escape", "../../../etc/passwd", options)
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
        assert!(
            result.is_err(),
            "Should reject pre-existing symlink in extraction path"
        );
    }
}
