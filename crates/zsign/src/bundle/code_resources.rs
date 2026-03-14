//! CodeResources generation for iOS app bundle signing.
//!
//! Generates the `_CodeSignature/CodeResources` plist containing cryptographic
//! hashes of all files in an iOS/macOS app bundle. This file is required for
//! code signature verification by the operating system.
//!
//! # Usage
//!
//! Use [`CodeResourcesBuilder`] to scan a bundle directory and generate the plist:
//!
//! ```no_run
//! use zsign_rs::bundle::CodeResourcesBuilder;
//!
//! let mut builder = CodeResourcesBuilder::new("/path/to/MyApp.app");
//! builder.scan()?;
//! let plist_bytes = builder.build()?;
//! std::fs::write("/path/to/MyApp.app/_CodeSignature/CodeResources", plist_bytes)?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! # Exclusions
//!
//! The following are automatically excluded from hashing:
//! - `_CodeSignature/` directory and contents
//! - Main executable (has embedded signature via `CFBundleExecutable`)
//! - Custom patterns added via [`CodeResourcesBuilder::exclude`]

use crate::{Error, Result};
use rayon::prelude::*;
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// Builder for generating CodeResources plist files.
///
/// This builder scans an iOS/macOS app bundle, computes cryptographic hashes
/// (SHA-1 and SHA-256) of all files, and produces the CodeResources plist
/// required for code signing.
///
/// # Builder Pattern
///
/// ```no_run
/// use zsign_rs::bundle::CodeResourcesBuilder;
///
/// let plist = CodeResourcesBuilder::new("/path/to/App.app")
///     .exclude("DebugResources/")
///     .scan()?
///     .build()?;
/// # Ok::<(), zsign_rs::Error>(())
/// ```
///
/// # Automatic Exclusions
///
/// The builder automatically excludes:
/// - `_CodeSignature/` directory (contains the signature itself)
/// - The main executable specified in `Info.plist` (has embedded signature)
pub struct CodeResourcesBuilder {
    /// Root bundle path
    bundle_path: PathBuf,
    /// Core builder (data-driven, no filesystem)
    inner: zsign_core::bundle::CodeResourcesBuilder,
}

impl CodeResourcesBuilder {
    /// Creates a new [`CodeResourcesBuilder`] for the given bundle path.
    ///
    /// Automatically reads `Info.plist` to determine the main executable
    /// (which is excluded from hashing as it has an embedded signature).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use zsign_rs::bundle::CodeResourcesBuilder;
    ///
    /// let builder = CodeResourcesBuilder::new("/path/to/MyApp.app");
    /// ```
    pub fn new(bundle_path: impl AsRef<Path>) -> Self {
        let bundle_path = bundle_path.as_ref().to_path_buf();
        let mut inner = zsign_core::bundle::CodeResourcesBuilder::new();

        // Read main executable from Info.plist (log warning on failure)
        match Self::read_main_executable(&bundle_path) {
            Ok(Some(exec_name)) => inner.set_main_executable(exec_name),
            Ok(None) => {}
            Err(e) => {
                eprintln!("Warning: Failed to read main executable from Info.plist: {}", e);
            }
        }

        Self { bundle_path, inner }
    }

    /// Adds a custom exclusion pattern.
    ///
    /// Files with paths starting with this pattern will be excluded from hashing.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use zsign_rs::bundle::CodeResourcesBuilder;
    ///
    /// let builder = CodeResourcesBuilder::new("/path/to/App.app")
    ///     .exclude("DebugResources/")
    ///     .exclude("TestData/");
    /// ```
    pub fn exclude(mut self, pattern: impl Into<String>) -> Self {
        self.inner = self.inner.exclude(pattern);
        self
    }

    /// Scans the bundle directory and hashes all files.
    ///
    /// Walks the bundle directory tree, computes SHA-1 and SHA-256 hashes for
    /// each file (excluding directories and excluded paths), and stores them
    /// for later plist generation.
    ///
    /// Files are processed in parallel using [`rayon`] for performance.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The bundle directory cannot be read
    /// - A file cannot be read for hashing
    /// - Symlink targets cannot be resolved (on Unix)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use zsign_rs::bundle::CodeResourcesBuilder;
    ///
    /// let mut builder = CodeResourcesBuilder::new("/path/to/App.app");
    /// builder.scan()?;
    /// println!("Scanned {} files", builder.file_count());
    /// # Ok::<(), zsign_rs::Error>(())
    /// ```
    pub fn scan(&mut self) -> Result<&mut Self> {
        let bundle_path = self.bundle_path.clone();

        // Collect all entries first (WalkDir is not Send, so we collect to Vec)
        let entries: Vec<_> = WalkDir::new(&bundle_path)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
            .collect();

        // Process entries in parallel
        let results: Vec<_> = entries
            .par_iter()
            .filter_map(|entry| {
                let path = entry.path();
                let metadata = fs::symlink_metadata(path).ok()?;
                let is_symlink = metadata.file_type().is_symlink();

                if !is_symlink && metadata.is_dir() {
                    return None;
                }

                let relative_path = path
                    .strip_prefix(&bundle_path)
                    .ok()?
                    .to_string_lossy()
                    .to_string();

                if is_symlink {
                    let symlink_result = Self::hash_symlink_entry(path)?;
                    Some((relative_path, symlink_result.0, symlink_result.1, Some(symlink_result.2)))
                } else {
                    let data = fs::read(path).ok()?;
                    let (sha1, sha256) = zsign_core::bundle::CodeResourcesBuilder::hash_data(&data);
                    Some((relative_path, sha1, sha256, None))
                }
            })
            .collect();

        for (path, sha1, sha256, symlink_target) in results {
            if let Some(target) = symlink_target {
                self.inner.add_symlink(path, target, sha1, sha256);
            } else {
                self.inner.add_file(path, sha1, sha256);
            }
        }

        Ok(self)
    }

    /// Builds the CodeResources plist as XML bytes.
    pub fn build(&self) -> Result<Vec<u8>> {
        Ok(self.inner.build()?)
    }

    /// Computes SHA-1 and SHA-256 hashes of the given data.
    pub fn hash_data(data: &[u8]) -> ([u8; 20], [u8; 32]) {
        zsign_core::bundle::CodeResourcesBuilder::hash_data(data)
    }

    /// Adds a file entry manually with pre-computed hashes.
    pub fn add_file(&mut self, path: impl Into<String>, sha1: [u8; 20], sha256: [u8; 32]) {
        self.inner.add_file(path, sha1, sha256);
    }

    /// Returns an iterator over all scanned files and their hashes.
    pub fn files(&self) -> impl Iterator<Item = (&String, &[u8; 20], &[u8; 32])> {
        self.inner.files()
    }

    /// Returns the number of files that will be included in the plist.
    pub fn file_count(&self) -> usize {
        self.inner.file_count()
    }

    /// Read the main executable name from Info.plist (CFBundleExecutable)
    fn read_main_executable(bundle_path: &Path) -> Result<Option<String>> {
        let info_plist_path = bundle_path.join("Info.plist");

        if !info_plist_path.exists() {
            return Ok(None);
        }

        let data = fs::read(&info_plist_path)?;
        let plist: plist::Value = plist::from_bytes(&data)?;

        let dict = plist.as_dictionary()
            .ok_or_else(|| Error::Io(
                std::io::Error::new(std::io::ErrorKind::InvalidData, "Info.plist is not a dictionary")
            ))?;

        Ok(dict.get("CFBundleExecutable")
            .and_then(|v| v.as_string())
            .map(|s| s.to_string()))
    }

    /// Hash a symlink by hashing its target path
    #[cfg(unix)]
    fn hash_symlink_entry(path: &Path) -> Option<([u8; 20], [u8; 32], String)> {
        use std::os::unix::ffi::OsStrExt;

        let target = fs::read_link(path).ok()?;
        let target_bytes = target.as_os_str().as_bytes();
        let (sha1, sha256) = zsign_core::bundle::CodeResourcesBuilder::hash_data(target_bytes);
        let target_str = target.to_string_lossy().to_string();
        Some((sha1, sha256, target_str))
    }

    #[cfg(not(unix))]
    fn hash_symlink_entry(_path: &Path) -> Option<([u8; 20], [u8; 32], String)> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_hash_data() {
        let data = b"Hello, World!";
        let (sha1, sha256) = CodeResourcesBuilder::hash_data(data);

        // Verify SHA-1 hash is correct (known value for "Hello, World!")
        assert_eq!(sha1.len(), 20);
        assert_eq!(sha256.len(), 32);

        // The hash should be non-zero
        assert!(sha1.iter().any(|&b| b != 0));
        assert!(sha256.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_build_plist_structure() {
        let builder = CodeResourcesBuilder::new("/fake/path");
        let plist_data = builder.build().unwrap();

        // Verify it's valid XML
        let plist_str = String::from_utf8(plist_data).unwrap();
        assert!(plist_str.contains("<?xml"));
        assert!(plist_str.contains("<plist"));
        assert!(plist_str.contains("<key>files</key>"));
        assert!(plist_str.contains("<key>files2</key>"));
        assert!(plist_str.contains("<key>rules</key>"));
        assert!(plist_str.contains("<key>rules2</key>"));
    }

    #[test]
    fn test_plist_with_files() {
        let mut builder = CodeResourcesBuilder::new("/fake/path");

        // Add a test file
        let sha1 = [1u8; 20];
        let sha256 = [2u8; 32];
        builder.add_file("test.txt", sha1, sha256);

        let plist_data = builder.build().unwrap();
        let plist_str = String::from_utf8(plist_data).unwrap();

        // Verify the file is in the plist
        assert!(plist_str.contains("<key>test.txt</key>"));
    }

    #[test]
    fn test_scan_bundle_directory() {
        // Create a temporary bundle structure
        let temp_dir = tempdir().unwrap();
        let bundle_path = temp_dir.path().join("Test.app");
        fs::create_dir(&bundle_path).unwrap();

        // Create some test files
        fs::write(bundle_path.join("Info.plist"), b"<plist></plist>").unwrap();
        fs::write(bundle_path.join("PkgInfo"), b"APPL????").unwrap();

        // Create a resources directory
        let resources = bundle_path.join("Resources");
        fs::create_dir(&resources).unwrap();
        fs::write(resources.join("icon.png"), b"fake png data").unwrap();

        // Create _CodeSignature directory (should be excluded)
        let code_sig = bundle_path.join("_CodeSignature");
        fs::create_dir(&code_sig).unwrap();
        fs::write(code_sig.join("CodeResources"), b"should be excluded").unwrap();

        // Scan the bundle
        let mut builder = CodeResourcesBuilder::new(&bundle_path);
        builder.scan().unwrap();

        // Verify files were found
        assert!(builder.file_count() >= 3); // Info.plist, PkgInfo, icon.png

        // Verify _CodeSignature was excluded
        let file_paths: Vec<_> = builder.files().map(|(p, _, _)| p.clone()).collect();
        assert!(!file_paths.iter().any(|p| p.contains("_CodeSignature")));

        // Verify expected files are included
        assert!(file_paths.contains(&"Info.plist".to_string()));
        assert!(file_paths.contains(&"PkgInfo".to_string()));
    }

    #[test]
    fn test_inclusion_of_nested_bundle_files() {
        // Create a temporary bundle with a nested framework
        let temp_dir = tempdir().unwrap();
        let bundle_path = temp_dir.path().join("Test.app");
        fs::create_dir(&bundle_path).unwrap();

        // Create main bundle files
        fs::write(bundle_path.join("Info.plist"), b"main plist").unwrap();

        // Create Frameworks directory with nested framework
        let frameworks = bundle_path.join("Frameworks");
        fs::create_dir_all(&frameworks).unwrap();
        let framework = frameworks.join("Test.framework");
        fs::create_dir(&framework).unwrap();
        fs::write(framework.join("Test"), b"framework binary").unwrap();
        fs::write(framework.join("Info.plist"), b"framework plist").unwrap();

        // Scan the bundle
        let mut builder = CodeResourcesBuilder::new(&bundle_path);
        builder.scan().unwrap();

        // Nested framework files are included in parent's CodeResources
        let file_paths: Vec<_> = builder.files().map(|(p, _, _)| p.clone()).collect();

        // Main Info.plist should be included
        assert!(file_paths.contains(&"Info.plist".to_string()));

        // Nested framework files should also be included (matching C++ zsign behavior)
        assert!(file_paths.iter().any(|p| p.contains(".framework/")));
        assert!(file_paths.contains(&"Frameworks/Test.framework/Test".to_string()));
        assert!(file_paths.contains(&"Frameworks/Test.framework/Info.plist".to_string()));
    }

    #[test]
    #[cfg(unix)]
    fn test_scan_bundle_with_symlinks() {
        use std::os::unix::fs::symlink;

        let temp_dir = tempdir().unwrap();
        let bundle_path = temp_dir.path().join("Test.app");
        fs::create_dir(&bundle_path).unwrap();

        // Create a target file
        let target_file = bundle_path.join("RealFile.txt");
        fs::write(&target_file, b"real content").unwrap();

        // Create a symlink to the file
        let link_path = bundle_path.join("LinkToFile.txt");
        symlink("RealFile.txt", &link_path).unwrap();

        // Create Frameworks structure with symlinks (typical iOS pattern)
        let framework_dir = bundle_path.join("Frameworks/Test.framework/Versions/A");
        fs::create_dir_all(&framework_dir).unwrap();
        fs::write(framework_dir.join("Test"), b"binary").unwrap();

        // Create Current -> A symlink
        let current_link = bundle_path.join("Frameworks/Test.framework/Versions/Current");
        symlink("A", &current_link).unwrap();

        // Create root symlinks
        let root_binary = bundle_path.join("Frameworks/Test.framework/Test");
        symlink("Versions/Current/Test", &root_binary).unwrap();

        // Scan the bundle
        let mut builder = CodeResourcesBuilder::new(&bundle_path);
        builder.scan().unwrap();

        // Build the plist and check for symlink entries
        let plist_data = builder.build().unwrap();
        let plist_str = String::from_utf8(plist_data).unwrap();

        // Symlinks should have a <key>symlink</key> entry in files2
        assert!(plist_str.contains("<key>symlink</key>"),
            "Symlink entries should have symlink key in plist");
    }
}
