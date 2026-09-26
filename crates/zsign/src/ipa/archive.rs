//! IPA archive creation.
//!
//! Creates IPA (ZIP) archives from `.app` bundles with the standard `Payload/` structure.
//!
//! For the reverse operation, see the [`extract`](super::extract) module.
//!
//! # Features
//!
//! - Configurable compression via [`CompressionLevel`]
//! - Preserves Unix file permissions and symlinks whose targets satisfy the extractor's policy (absolute, escaping, non-UTF-8, or over-long targets are rejected at creation)
//! - Creates proper directory structure for iOS deployment
//!
//! # Examples
//!
//! ```no_run
//! use zsign_rs::ipa::{create_ipa, CompressionLevel};
//! use std::path::Path;
//!
//! let app_bundle = Path::new("Payload/MyApp.app");
//! create_ipa(app_bundle, "output.ipa", CompressionLevel::DEFAULT)?;
//! # Ok::<(), zsign_rs::Error>(())
//! ```

use crate::store::{FsStore, Store};
use crate::{Error, Result};
use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};
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
/// use zsign_rs::ipa::CompressionLevel;
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

/// File extensions that are already compressed or incompressible.
/// Using `Stored` mode for these avoids wasting CPU on deflate
/// with negligible size reduction.
const PRECOMPRESSED_EXTENSIONS: &[&str] = &[
    // Images
    "png", "jpg", "jpeg", "gif", "webp", "heic", "heif",
    // Audio/Video (compressed containers only)
    "mp3", "m4a", "aac", "mp4", "mov", "m4v",
    // iOS assets
    "car", // Assets.car (compiled asset catalog)
    // Archives
    "zip", "gz", "bz2", "xz", "zst",
];

/// Returns true if the file extension indicates pre-compressed content.
fn is_precompressed(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| {
            let lower = ext.to_ascii_lowercase();
            PRECOMPRESSED_EXTENSIONS.contains(&lower.as_str())
        })
        .unwrap_or(false)
}

/// Uncompressed-size gate for opting a member into ZIP64 extended fields.
///
/// Sits 1 MiB below the 32-bit size ceiling, so no compressed size derived
/// from a member at or below the gate can cross `0xFFFFFFFF`; members below
/// the gate keep byte-identical headers.
const ZIP64_SIZE_GATE: u64 = u32::MAX as u64 - (1 << 20);

/// True when a member of `uncompressed_len` bytes must carry ZIP64
/// extended information extra fields to be written without error.
fn needs_zip64(uncompressed_len: u64) -> bool {
    uncompressed_len > ZIP64_SIZE_GATE
}

/// Largest symlink target the extractor will read back for a written
/// archive; mirrors `MAX_SYMLINK_TARGET_BYTES` in the extract module,
/// which is not editable from this lane.
const MAX_SYMLINK_TARGET_BYTES: usize = 4096;

/// Validates a symlink target against the extractor's target policy before
/// it is written, so every archive the writer accepts re-extracts through
/// `extract_ipa` with its targets byte-identical. Returns the target.
///
/// Takes the target as raw bytes because that is what [`Store::read_link`]
/// hands back; on unix a non-UTF-8 target is still rejected rather than
/// lossily rewritten.
fn checked_symlink_target(entry_name: &str, target: &[u8]) -> Result<String> {
    let target = std::str::from_utf8(target).map_err(|_| {
        Error::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Non-UTF-8 symlink target for archive entry: {entry_name}"),
        ))
    })?;
    if target.starts_with('/') || target.split('/').any(|component| component == "..") {
        return Err(Error::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Unsafe symlink target for archive entry {entry_name}: {target}"),
        )));
    }
    if target.len() > MAX_SYMLINK_TARGET_BYTES {
        return Err(Error::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Symlink target too long for archive entry {entry_name}: {} bytes",
                target.len()
            ),
        )));
    }
    Ok(target.to_string())
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
/// use zsign_rs::ipa::{create_ipa, CompressionLevel};
///
/// // Create with default compression
/// create_ipa("MyApp.app", "output.ipa", CompressionLevel::DEFAULT)?;
///
/// // Create with no compression for faster processing
/// create_ipa("MyApp.app", "fast.ipa", CompressionLevel::NONE)?;
/// # Ok::<(), zsign_rs::Error>(())
/// ```
///
/// # Errors
///
/// Returns [`Error::Io`] if:
/// - The app bundle doesn't exist or is not a directory
/// - The output file cannot be created
/// - Any file cannot be read during archiving
/// - symlink targets that are absolute, escaping (`..`), non-UTF-8, or
///   longer than 4096 bytes
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
    let mut zip = ZipWriter::new(std::io::BufWriter::new(file));

    let options = archive_options(compression_level);

    // Add Payload/ directory
    zip.add_directory("Payload/", options).map_err(Error::Zip)?;

    // Walk the app bundle and add all files - don't follow symlinks
    let name_prefix = format!("Payload/{}", app_name);
    write_tree(
        &mut zip,
        &FsStore,
        app_bundle_path,
        options,
        &|relative_path| {
            if relative_path.as_os_str().is_empty() {
                Some(name_prefix.clone())
            } else {
                Some(format!("{}/{}", name_prefix, zip_entry_name(relative_path)))
            }
        },
    )?;

    // Finalize the archive
    zip.finish().map_err(Error::Zip)?;

    Ok(())
}

/// Creates an IPA from a whole extraction root: every top-level entry of the
/// root (`Payload/…` plus any siblings such as `SwiftSupport/` or
/// `iTunesMetadata.plist`) is archived verbatim under its relative name.
///
/// This is the repack half of [`extract_ipa`](crate::ipa::extract_ipa); unlike
/// [`create_ipa`] it does not synthesize a `Payload/` structure.
pub(crate) fn create_ipa_from_root(
    extraction_root: impl AsRef<Path>,
    output_path: impl AsRef<Path>,
    compression_level: CompressionLevel,
) -> Result<()> {
    let extraction_root = extraction_root.as_ref();
    let output_path = output_path.as_ref();

    if !extraction_root.is_dir() {
        return Err(Error::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Not a directory: {}", extraction_root.display()),
        )));
    }

    if let Some(parent) = output_path.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent)?;
        }
    }

    let file = File::create(output_path)?;
    let mut zip = ZipWriter::new(std::io::BufWriter::new(file));
    let options = archive_options(compression_level);

    write_tree(
        &mut zip,
        &FsStore,
        extraction_root,
        options,
        &|relative_path| {
            if relative_path.as_os_str().is_empty() {
                None
            } else {
                Some(zip_entry_name(relative_path))
            }
        },
    )?;

    zip.finish().map_err(Error::Zip)?;

    Ok(())
}

/// [`create_ipa_from_root`]'s store-backed twin: the same archive, built
/// from any [`Store`] medium into memory instead of onto a file, so the
/// bytes-to-bytes sign flow never touches a filesystem.
///
/// No `Payload/` directory entry is synthesized: `create_ipa_from_root` does
/// not make one either, and the `Payload/` entry in the output comes from
/// the actual `Payload` directory node in the tree. Adding one here would
/// duplicate it and break byte identity with the native twin.
pub(crate) fn create_ipa_from_store<S: Store>(
    store: &S,
    root: &Path,
    level: CompressionLevel,
) -> Result<Vec<u8>> {
    let mut cursor = io::Cursor::new(Vec::new());
    let mut zip = ZipWriter::new(&mut cursor);
    let options = archive_options(level);
    // The `name_of` closure is `create_ipa_from_root`'s, verbatim: the
    // extraction root's empty relative path maps to `None`, which is what
    // skips the root itself.
    write_tree(&mut zip, store, root, options, &|relative_path| {
        if relative_path.as_os_str().is_empty() {
            None
        } else {
            Some(zip_entry_name(relative_path))
        }
    })?;
    // `finish` flushes the central directory into the cursor; its error is
    // a write failure and must not be dropped, so it propagates here and
    // only the `Ok` payload is discarded.
    let _ = zip.finish().map_err(Error::Zip)?;
    Ok(cursor.into_inner())
}

/// Configures compression options. A fixed timestamp keeps the archive
/// reproducible: outputs are byte-identical across runs.
fn archive_options(compression_level: CompressionLevel) -> SimpleFileOptions {
    if compression_level.level() == 0 {
        // For stored (no compression), don't set compression level
        SimpleFileOptions::default()
            .compression_method(CompressionMethod::Stored)
            .last_modified_time(zip::DateTime::default())
    } else {
        // For deflate, set the compression level
        SimpleFileOptions::default()
            .compression_method(CompressionMethod::Deflated)
            .compression_level(Some(compression_level.level() as i64))
            .last_modified_time(zip::DateTime::default())
    }
}

/// Walks `walk_root` and writes every entry into `zip`, mapping each
/// strip-prefix-relative path to an archive name through `name_of`
/// (`None` skips the entry). Directories get their trailing separator here.
///
/// Entries are written in bytewise archive-name order so archive output
/// never depends on filesystem readdir order: identical inputs produce
/// byte-identical archives.
fn write_tree<S: Store, W: io::Write + io::Seek>(
    zip: &mut ZipWriter<W>,
    store: &S,
    walk_root: &Path,
    options: SimpleFileOptions,
    name_of: &dyn Fn(&Path) -> Option<String>,
) -> Result<()> {
    // Collect: map every walked entry to its archive name (None skips it).
    // `store.walk` is root-inclusive, exactly as `WalkDir` is, so the root
    // still reaches `name_of` (which is what skips it for
    // `create_ipa_from_root` and renames it for `create_ipa`).
    let mut entries: Vec<(String, PathBuf)> = Vec::new();
    for e in store.walk(walk_root)? {
        // Per-entry results keep the walk's own error, which already
        // carries the "Failed to walk directory" message.
        let (path, _kind) = e?;

        let relative_path = path.strip_prefix(walk_root).map_err(|_| {
            Error::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Failed to compute relative path",
            ))
        })?;

        if let Some(archive_path) = name_of(relative_path) {
            entries.push((archive_path, path));
        }
    }

    // Sort: bytewise order of the archive name ('/'-joined relative path),
    // which is platform-stable and keeps every directory before its children
    // (a child's name carries its directory's name as a byte prefix).
    entries.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));

    // Write: the per-entry body is unchanged from the previous walk loop,
    // with the store primitives swapped in for the `std::fs` ones.
    for (mut archive_path, path) in entries {
        // lstat through the store: the entry type is read without following
        // links, and on unix the mode rides along on the same call.
        let metadata = store.metadata(&path)?;

        if metadata.is_dir() {
            archive_path.push('/');
            zip.add_directory(&archive_path, options)
                .map_err(Error::Zip)?;
        } else if metadata.is_symlink() {
            let target = store.read_link(&path)?;
            let target = checked_symlink_target(&archive_path, &target)?;
            zip.add_symlink(&archive_path, &target, options)
                .map_err(Error::Zip)?;
        } else {
            // Regular file — use Stored for pre-compressed formats
            let file_options = if is_precompressed(&path) {
                options
                    .compression_method(CompressionMethod::Stored)
                    .compression_level(None)
            } else {
                options
            };

            let file_options = if let Some(mode) = metadata.unix_mode {
                file_options.unix_permissions(mode)
            } else {
                file_options
            };

            let file_options = if needs_zip64(metadata.len) {
                file_options.large_file(true)
            } else {
                file_options
            };

            zip.start_file(&archive_path, file_options)
                .map_err(Error::Zip)?;

            // Stream the entry through without loading it into memory
            let mut file = store.open(&path)?;
            io::copy(&mut file, &mut *zip)?;
        }
    }

    Ok(())
}

/// Builds a ZIP entry name by joining `relative`'s path components with `/`.
///
/// `Path::components()` splits on both separators on Windows, so the result
/// never carries the platform separator into the archive.
fn zip_entry_name(relative: &Path) -> String {
    relative
        .components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipa::extract_ipa;
    use std::io::Read;
    use std::path::PathBuf;
    use tempfile::TempDir;
    use zip::ZipArchive;

    #[test]
    fn test_needs_zip64_boundaries() {
        assert!(!needs_zip64(0), "empty member is never zip64");
        assert!(!needs_zip64(4096), "typical member is never zip64");
        assert!(
            !needs_zip64(ZIP64_SIZE_GATE),
            "the gate itself is still 32-bit"
        );
        assert!(
            needs_zip64(ZIP64_SIZE_GATE + 1),
            "one byte past the gate opts in"
        );
        assert!(
            needs_zip64(u64::from(u32::MAX)),
            "u32::MAX is not reachable safely"
        );
        assert!(needs_zip64(u64::from(u32::MAX) + 1), "beyond 32 bits");
    }

    /// End-to-end proof that an oversized member is written instead of
    /// aborting mid-copy: a 4 GiB+1 sparse file of zeros compresses to a
    /// few MiB but crosses the size guard that zip only clears with
    /// `large_file(true)`. Ignored so the routine suite never streams four
    /// gigabytes through deflate; run explicitly with
    /// `cargo test -p zsign-rs zip64_oversized -- --ignored`.
    #[test]
    #[ignore = "streams more than 4 GiB through deflate"]
    fn test_create_ipa_zip64_oversized_member() {
        let temp = TempDir::new().unwrap();
        let app_dir = temp.path().join("Big.app");
        fs::create_dir_all(&app_dir).unwrap();
        let big = app_dir.join("big.bin");
        let file = File::create(&big).unwrap();
        file.set_len(u64::from(u32::MAX) + 1).unwrap();
        drop(file);

        let out = temp.path().join("big.ipa");
        create_ipa(&app_dir, &out, CompressionLevel::DEFAULT)
            .expect("oversized member must be written with zip64 enabled");

        let reader = File::open(&out).unwrap();
        let mut archive = ZipArchive::new(reader).unwrap();
        let mut entry = archive
            .by_name("Payload/Big.app/big.bin")
            .expect("member present");
        // zip 7.2.0 patches the local header with the true 64-bit length,
        // then clamps the struct the central directory is derived from to
        // the 0xFFFFFFFF sentinel, so the recorded size saturates at
        // `ZIP64_BYTES_THR`. What this proves is that the write completed
        // without the mid-write guard aborting the entry.
        assert!(
            entry.size() >= zip::ZIP64_BYTES_THR,
            "recorded size must reach the zip64 threshold, got {}",
            entry.size()
        );
        let mut probe = [0u8; 16];
        entry
            .read_exact(&mut probe)
            .expect("oversized member reads back");
    }

    #[test]
    fn test_zip_entry_name_joins_components_with_forward_slash() {
        assert_eq!(
            zip_entry_name(Path::new("dir/sub/file.bin")),
            "dir/sub/file.bin",
            "nested paths join with '/'"
        );
        assert_eq!(zip_entry_name(Path::new("file.bin")), "file.bin");
        assert_eq!(zip_entry_name(Path::new("")), "", "root relative path");
    }

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

        let mut names: Vec<String> = Vec::new();
        for i in 0..archive.len() {
            let entry = archive.by_index(i).unwrap();
            names.push(entry.name().to_string());

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

        assert!(
            names
                .iter()
                .any(|n| n == "Payload/Test.app/Resources/icon.png"),
            "nested entry names are '/'-joined, got {names:?}"
        );
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

        let result = create_ipa(
            "/nonexistent/Test.app",
            &output_ipa,
            CompressionLevel::DEFAULT,
        );
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

    #[test]
    fn test_is_precompressed() {
        use std::path::Path;
        assert!(is_precompressed(Path::new("image.png")));
        assert!(is_precompressed(Path::new("image.PNG")));
        assert!(is_precompressed(Path::new("photo.jpg")));
        assert!(is_precompressed(Path::new("video.mp4")));
        assert!(is_precompressed(Path::new("Assets.car")));
        assert!(!is_precompressed(Path::new("Info.plist")));
        assert!(!is_precompressed(Path::new("binary")));
        assert!(!is_precompressed(Path::new("data.json")));
    }

    #[test]
    fn test_create_ipa_stored_for_precompressed() {
        let temp_dir = TempDir::new().unwrap();
        let app_dir = temp_dir.path().join("Test.app");
        fs::create_dir_all(&app_dir).unwrap();

        fs::write(
            app_dir.join("Info.plist"),
            b"<?xml version=\"1.0\"?><plist><dict></dict></plist>",
        )
        .unwrap();
        fs::write(app_dir.join("icon.png"), b"fake png data").unwrap();

        let output_ipa = temp_dir.path().join("output.ipa");
        create_ipa(&app_dir, &output_ipa, CompressionLevel::DEFAULT).unwrap();

        // Verify compression methods in the archive
        let file = File::open(&output_ipa).unwrap();
        let mut archive = ZipArchive::new(file).unwrap();

        for i in 0..archive.len() {
            let entry = archive.by_index(i).unwrap();
            if entry.name().ends_with("icon.png") {
                assert_eq!(
                    entry.compression(),
                    CompressionMethod::Stored,
                    "PNG should use Stored compression"
                );
            } else if entry.name().ends_with("Info.plist") {
                assert_eq!(
                    entry.compression(),
                    CompressionMethod::Deflated,
                    "plist should use Deflated compression"
                );
            }
        }
    }

    #[test]
    fn test_checked_symlink_target_boundaries() {
        assert_eq!(
            checked_symlink_target("e", b"Versions/Current/x").unwrap(),
            "Versions/Current/x",
            "framework-style relative targets pass verbatim"
        );
        let max = "a".repeat(MAX_SYMLINK_TARGET_BYTES);
        assert!(
            checked_symlink_target("e", max.as_bytes()).is_ok(),
            "a target of exactly the extractor's limit is accepted"
        );
        let too_long = "a".repeat(MAX_SYMLINK_TARGET_BYTES + 1);
        let err = checked_symlink_target("e", too_long.as_bytes())
            .expect_err("targets above the extractor's limit are rejected");
        assert!(err.to_string().contains("too long"), "{err}");
        {
            assert!(
                checked_symlink_target("e", b"bad\xfftarget").is_err(),
                "non-UTF-8 targets are rejected rather than lossily rewritten"
            );
        }
    }

    #[test]
    #[cfg(unix)]
    fn test_create_ipa_rejects_unsafe_symlink_targets() {
        for target in ["/etc/passwd", "../escape", "sub/../../escape"] {
            let temp = TempDir::new().unwrap();
            let app = create_test_app_bundle(temp.path());
            std::os::unix::fs::symlink(target, app.join("BadLink")).unwrap();
            let out = temp.path().join("out.ipa");
            let err = create_ipa(&app, &out, CompressionLevel::DEFAULT)
                .expect_err("unsafe symlink target must fail at creation");
            let msg = err.to_string();
            assert!(
                msg.contains("Unsafe symlink target"),
                "target {target}: {msg}"
            );
            assert!(msg.contains("BadLink"), "entry named: {msg}");
        }
    }

    #[test]
    #[cfg(unix)]
    fn test_create_ipa_framework_symlink_round_trips() {
        let temp = TempDir::new().unwrap();
        let app = create_test_app_bundle(temp.path());
        let versions = app
            .join("Frameworks")
            .join("Extra.framework")
            .join("Versions");
        fs::create_dir_all(versions.join("A")).unwrap();
        fs::write(versions.join("A").join("resource.txt"), b"payload").unwrap();
        std::os::unix::fs::symlink("A", versions.join("Current")).unwrap();
        std::os::unix::fs::symlink(
            "Versions/Current/resource.txt",
            app.join("Frameworks").join("Extra.framework").join("Extra"),
        )
        .unwrap();

        let out = temp.path().join("framework.ipa");
        create_ipa(&app, &out, CompressionLevel::DEFAULT).expect("creation succeeds");

        let extracted = temp.path().join("extracted");
        extract_ipa(&out, &extracted).unwrap();
        let root = extracted
            .join("Payload")
            .join("Test.app")
            .join("Frameworks")
            .join("Extra.framework");
        assert_eq!(
            std::fs::read_link(root.join("Versions").join("Current")).unwrap(),
            std::path::Path::new("A"),
            "targets round-trip verbatim"
        );
        assert_eq!(
            std::fs::read_link(root.join("Extra")).unwrap(),
            std::path::Path::new("Versions/Current/resource.txt"),
            "targets round-trip verbatim"
        );
    }
    #[test]
    fn test_create_ipa_writes_entries_in_sorted_order() {
        let temp_dir = TempDir::new().unwrap();
        let src = temp_dir.path().join("Demo.app");
        // Created in an order that differs from bytewise sorted order.
        fs::create_dir_all(src.join("zdir")).unwrap();
        fs::create_dir_all(src.join("adir")).unwrap();
        fs::write(src.join("zdir/b.txt"), b"b").unwrap();
        fs::write(src.join("adir/a.txt"), b"a").unwrap();
        fs::write(src.join("Info.plist"), b"info").unwrap();
        fs::write(src.join("zz.txt"), b"zz").unwrap();

        let out = temp_dir.path().join("out.ipa");
        create_ipa(&src, &out, CompressionLevel::NONE).unwrap();

        let mut reader = ZipArchive::new(File::open(&out).unwrap()).unwrap();
        let mut names = Vec::with_capacity(reader.len());
        for i in 0..reader.len() {
            let entry = reader.by_index(i).unwrap();
            assert_eq!(
                entry.last_modified(),
                Some(zip::DateTime::default()),
                "entry {} must carry the pinned 1980-01-01 timestamp",
                entry.name()
            );
            names.push(entry.name().to_string());
        }
        assert_eq!(
            names,
            [
                "Payload/",
                "Payload/Demo.app/",
                "Payload/Demo.app/Info.plist",
                "Payload/Demo.app/adir/",
                "Payload/Demo.app/adir/a.txt",
                "Payload/Demo.app/zdir/",
                "Payload/Demo.app/zdir/b.txt",
                "Payload/Demo.app/zz.txt",
            ],
            "entries must be in bytewise archive-name order with directories \
             before their children"
        );
    }

    #[test]
    fn test_create_ipa_from_root_is_byte_identical_across_creation_order() {
        // Same content, two extraction roots, opposite file-creation order —
        // including pass-through siblings such as SwiftSupport/.
        fn build_root(root: &Path, forward: bool) {
            let app = root.join("Payload").join("Demo.app");
            let mut files: Vec<(PathBuf, Vec<u8>)> = vec![
                (app.join("Info.plist"), b"info".to_vec()),
                (root.join("iTunesMetadata.plist"), b"meta".to_vec()),
                (
                    root.join("SwiftSupport")
                        .join("iphoneos")
                        .join("libswiftCore.dylib"),
                    b"swift".to_vec(),
                ),
            ];
            for i in 0..24u8 {
                files.push((app.join("res").join(format!("f{i:02}.bin")), vec![i; 8]));
            }
            if !forward {
                files.reverse();
            }
            for (path, bytes) in files {
                fs::create_dir_all(path.parent().unwrap()).unwrap();
                fs::write(path, bytes).unwrap();
            }
        }

        let temp_dir = TempDir::new().unwrap();
        let root_fwd = temp_dir.path().join("fwd");
        let root_rev = temp_dir.path().join("rev");
        build_root(&root_fwd, true);
        build_root(&root_rev, false);

        let out_fwd = temp_dir.path().join("fwd.ipa");
        let out_rev = temp_dir.path().join("rev.ipa");
        create_ipa_from_root(&root_fwd, &out_fwd, CompressionLevel::DEFAULT).unwrap();
        create_ipa_from_root(&root_rev, &out_rev, CompressionLevel::DEFAULT).unwrap();

        assert_eq!(
            fs::read(&out_fwd).unwrap(),
            fs::read(&out_rev).unwrap(),
            "identical content must produce byte-identical archives regardless \
             of filesystem creation order"
        );
    }

    /// The store-backed repack must be byte-identical to the native one: the
    /// bytes-to-bytes sign flow's output is compared against the native
    /// output, so any divergence in entry order, names, modes or compression
    /// would show up as a different IPA rather than a same-app resign.
    ///
    /// Covers a 0o755 executable (a mode that only survives if the store
    /// carries it), a pass-through root sibling, and framework-style
    /// symlinks (which the mem path classifies from the recorded mode rather
    /// than from the native pass's `cfg(unix)` branch).
    #[test]
    #[cfg(unix)]
    fn test_store_repack_is_byte_identical_to_native_repack() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let temp = TempDir::new().unwrap();
        let src = temp.path().join("src");
        let app = create_test_app_bundle(&src);
        fs::set_permissions(app.join("Test"), fs::Permissions::from_mode(0o755)).unwrap();
        fs::create_dir_all(src.join("SwiftSupport").join("iphoneos")).unwrap();
        fs::write(
            src.join("SwiftSupport")
                .join("iphoneos")
                .join("libswiftCore.dylib"),
            b"swift",
        )
        .unwrap();
        let versions = app
            .join("Frameworks")
            .join("Extra.framework")
            .join("Versions");
        fs::create_dir_all(versions.join("A")).unwrap();
        fs::write(versions.join("A").join("resource.txt"), b"payload").unwrap();
        symlink("A", versions.join("Current")).unwrap();
        symlink(
            "Versions/Current/resource.txt",
            app.join("Frameworks").join("Extra.framework").join("Extra"),
        )
        .unwrap();

        // (a) native: create -> extract -> repack from root.
        let native_in = temp.path().join("native.ipa");
        create_ipa(&app, &native_in, CompressionLevel::DEFAULT).unwrap();
        let extracted = temp.path().join("extracted");
        extract_ipa(&native_in, &extracted).unwrap();
        let native_out = temp.path().join("native-repacked.ipa");
        create_ipa_from_root(&extracted, &native_out, CompressionLevel::DEFAULT).unwrap();
        let native_bytes = fs::read(&native_out).unwrap();

        // (b) bytes: the same archive straight into a MemStore and back out.
        let store = crate::ipa::mem_store::MemStore::new();
        let bundle = crate::ipa::extract::extract_ipa_into_store(
            io::Cursor::new(fs::read(&native_in).unwrap()),
            &store,
            Path::new(""),
            crate::ipa::extract::ExtractionLimits::default(),
        )
        .unwrap();
        assert_eq!(bundle, Path::new("Payload/Test.app"), "bundle lookup");
        let mem_bytes =
            create_ipa_from_store(&store, Path::new(""), CompressionLevel::DEFAULT).unwrap();

        assert_eq!(
            native_bytes, mem_bytes,
            "the store-backed repack must be byte-identical to the native one"
        );

        // And the mem archive is a real IPA: it re-extracts to the same tree,
        // symlinks and modes included.
        let mem_out = temp.path().join("mem.ipa");
        fs::write(&mem_out, &mem_bytes).unwrap();
        let re_extracted = temp.path().join("re_extracted");
        extract_ipa(&mem_out, &re_extracted).unwrap();
        for (rel, want) in [
            (
                "Payload/Test.app/Info.plist",
                &b"<?xml version=\"1.0\"?><plist><dict></dict></plist>"[..],
            ),
            ("Payload/Test.app/Test", &b"MACHO_PLACEHOLDER"[..]),
            (
                "Payload/Test.app/Frameworks/Extra.framework/Versions/A/resource.txt",
                &b"payload"[..],
            ),
        ] {
            assert_eq!(
                fs::read(re_extracted.join(rel)).unwrap(),
                want,
                "{rel} survives the bytes round trip"
            );
        }
        assert_eq!(
            fs::read_link(
                re_extracted.join("Payload/Test.app/Frameworks/Extra.framework/Versions/Current")
            )
            .unwrap(),
            Path::new("A"),
            "symlinks survive the bytes round trip"
        );
        assert_eq!(
            fs::symlink_metadata(re_extracted.join("Payload/Test.app/Test"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o755,
            "the executable's mode survives the bytes round trip"
        );
    }
}
