//! CodeResources generation for iOS app bundle signing.
//!
//! Generates the `_CodeSignature/CodeResources` plist containing cryptographic
//! hashes of all files in an iOS/macOS app bundle. This file is required for
//! code signature verification by the operating system.
//!
//! # Usage
//!
//! Use [`CodeResourcesBuilder`] to generate the plist from pre-computed hashes:
//!
//! ```
//! use zsign_core::bundle::CodeResourcesBuilder;
//!
//! let mut builder = CodeResourcesBuilder::new();
//! builder.set_main_executable("MyApp");
//! let (sha1, sha256) = CodeResourcesBuilder::hash_data(b"file content");
//! builder.add_file("Resources/icon.png", sha1, sha256);
//! let plist_bytes = builder.build().unwrap();
//! ```
//!
//! # Exclusions
//!
//! The following are automatically excluded from hashing:
//! - `_CodeSignature/` directory and contents
//! - Main executable (has embedded signature via `CFBundleExecutable`)
//! - Custom patterns added via [`CodeResourcesBuilder::exclude`]

use crate::{Error, Result};
use plist::{Dictionary, Value};
use sha1::{Digest, Sha1};
use sha2::Sha256;
use std::collections::BTreeMap;

/// Builder for generating CodeResources plist files.
///
/// This builder collects pre-computed cryptographic hashes (SHA-1 and SHA-256)
/// of all files in an iOS/macOS app bundle and produces the CodeResources plist
/// required for code signing.
///
/// This is a data-driven builder — callers provide file data directly rather
/// than scanning the filesystem. This enables WASM usage where the host
/// orchestrates I/O and passes data to the builder.
///
/// # Builder Pattern
///
/// ```
/// use zsign_core::bundle::CodeResourcesBuilder;
///
/// let mut builder = CodeResourcesBuilder::new();
/// builder.set_main_executable("MyApp");
/// let (sha1, sha256) = CodeResourcesBuilder::hash_data(b"content");
/// builder.add_file("Resources/data.bin", sha1, sha256);
/// let plist = builder.build().unwrap();
/// ```
///
/// # Automatic Exclusions
///
/// The builder automatically excludes:
/// - `_CodeSignature/` directory (contains the signature itself)
/// - The main executable (has embedded signature)
pub struct CodeResourcesBuilder {
    /// Files to include with their hashes
    files: BTreeMap<String, FileEntry>,
    /// Custom exclusion patterns
    exclusions: Vec<String>,
    /// Main executable name (excluded from CodeResources as it has embedded signature)
    main_executable: Option<String>,
}

/// Entry for a file in CodeResources
struct FileEntry {
    /// SHA-1 hash (20 bytes) - for files, hash of content; for symlinks, hash of target path
    sha1: [u8; 20],
    /// SHA-256 hash (32 bytes) - for files, hash of content; for symlinks, hash of target path
    sha256: [u8; 32],
    /// If this is a symlink, contains the target path
    symlink_target: Option<String>,
}

/// Standard exclusion rules for CodeResources (legacy format).
///
/// Defines patterns for file inclusion, optional files, and omitted files.
fn standard_rules() -> Dictionary {
    let mut rules = Dictionary::new();

    // Everything else is included by default
    rules.insert("^.*".to_string(), Value::Boolean(true));

    // .lproj directories are optional
    let mut lproj = Dictionary::new();
    lproj.insert("optional".to_string(), Value::Boolean(true));
    lproj.insert("weight".to_string(), Value::Real(1000.0));
    rules.insert("^.*\\.lproj/".to_string(), Value::Dictionary(lproj));

    // locversion.plist is omitted
    let mut locversion = Dictionary::new();
    locversion.insert("omit".to_string(), Value::Boolean(true));
    locversion.insert("weight".to_string(), Value::Real(1100.0));
    rules.insert("^.*\\.lproj/locversion.plist$".to_string(), Value::Dictionary(locversion));

    // Base.lproj has higher weight
    let mut base_lproj = Dictionary::new();
    base_lproj.insert("weight".to_string(), Value::Real(1010.0));
    rules.insert("^Base\\.lproj/".to_string(), Value::Dictionary(base_lproj));

    // version.plist is included
    rules.insert("^version.plist$".to_string(), Value::Boolean(true));

    rules
}

/// Modern rules2 for CodeResources.
///
/// Defines patterns for file inclusion with extended rules including
/// .dSYM, .DS_Store, and embedded provisioning profile handling.
fn standard_rules2() -> Dictionary {
    let mut rules2 = Dictionary::new();

    // Default rule for everything else
    rules2.insert("^.*".to_string(), Value::Boolean(true));

    // .dSYM directories
    let mut dsym = Dictionary::new();
    dsym.insert("weight".to_string(), Value::Real(11.0));
    rules2.insert(".*\\.dSYM($|/)".to_string(), Value::Dictionary(dsym));

    // .DS_Store files are omitted
    let mut ds_store = Dictionary::new();
    ds_store.insert("omit".to_string(), Value::Boolean(true));
    ds_store.insert("weight".to_string(), Value::Real(2000.0));
    rules2.insert("^(.*/)?\\.DS_Store$".to_string(), Value::Dictionary(ds_store));

    // .lproj directories are optional
    let mut lproj = Dictionary::new();
    lproj.insert("optional".to_string(), Value::Boolean(true));
    lproj.insert("weight".to_string(), Value::Real(1000.0));
    rules2.insert("^.*\\.lproj/".to_string(), Value::Dictionary(lproj));

    // locversion.plist is omitted
    let mut locversion = Dictionary::new();
    locversion.insert("omit".to_string(), Value::Boolean(true));
    locversion.insert("weight".to_string(), Value::Real(1100.0));
    rules2.insert("^.*\\.lproj/locversion.plist$".to_string(), Value::Dictionary(locversion));

    // Base.lproj has higher weight
    let mut base_lproj = Dictionary::new();
    base_lproj.insert("weight".to_string(), Value::Real(1010.0));
    rules2.insert("^Base\\.lproj/".to_string(), Value::Dictionary(base_lproj));

    // Info.plist is omitted from files2
    let mut info_plist = Dictionary::new();
    info_plist.insert("omit".to_string(), Value::Boolean(true));
    info_plist.insert("weight".to_string(), Value::Real(20.0));
    rules2.insert("^Info\\.plist$".to_string(), Value::Dictionary(info_plist));

    // PkgInfo is omitted from files2
    let mut pkg_info = Dictionary::new();
    pkg_info.insert("omit".to_string(), Value::Boolean(true));
    pkg_info.insert("weight".to_string(), Value::Real(20.0));
    rules2.insert("^PkgInfo$".to_string(), Value::Dictionary(pkg_info));

    // embedded.provisionprofile (note: different from mobileprovision)
    let mut provision = Dictionary::new();
    provision.insert("weight".to_string(), Value::Real(20.0));
    rules2.insert("^embedded\\.provisionprofile$".to_string(), Value::Dictionary(provision));

    // version.plist
    let mut version_plist = Dictionary::new();
    version_plist.insert("weight".to_string(), Value::Real(20.0));
    rules2.insert("^version\\.plist$".to_string(), Value::Dictionary(version_plist));

    rules2
}

impl CodeResourcesBuilder {
    /// Creates a new [`CodeResourcesBuilder`].
    ///
    /// The builder starts empty. Use [`set_main_executable`](Self::set_main_executable)
    /// to specify the main executable name (which will be excluded from hashing),
    /// and [`add_file`](Self::add_file) / [`add_symlink`](Self::add_symlink) to add
    /// file entries with pre-computed hashes.
    ///
    /// # Examples
    ///
    /// ```
    /// use zsign_core::bundle::CodeResourcesBuilder;
    ///
    /// let builder = CodeResourcesBuilder::new();
    /// ```
    pub fn new() -> Self {
        Self {
            files: BTreeMap::new(),
            exclusions: Vec::new(),
            main_executable: None,
        }
    }

    /// Sets the main executable name.
    ///
    /// The main executable is excluded from CodeResources as it has its own
    /// embedded signature.
    ///
    /// # Examples
    ///
    /// ```
    /// use zsign_core::bundle::CodeResourcesBuilder;
    ///
    /// let mut builder = CodeResourcesBuilder::new();
    /// builder.set_main_executable("MyApp");
    /// ```
    pub fn set_main_executable(&mut self, name: impl Into<String>) {
        self.main_executable = Some(name.into());
    }

    /// Adds a custom exclusion pattern.
    ///
    /// Files with paths starting with this pattern will be excluded from hashing.
    ///
    /// # Examples
    ///
    /// ```
    /// use zsign_core::bundle::CodeResourcesBuilder;
    ///
    /// let mut builder = CodeResourcesBuilder::new();
    /// builder.exclude("DebugResources/");
    /// builder.exclude("TestData/");
    /// ```
    pub fn exclude(&mut self, pattern: impl Into<String>) -> &mut Self {
        self.exclusions.push(pattern.into());
        self
    }

    /// Checks if a path should be excluded from hashing.
    ///
    /// Returns `true` if the path matches any exclusion pattern, including
    /// the `_CodeSignature/` directory and the main executable.
    pub fn should_exclude(&self, relative_path: &str) -> bool {
        // Always exclude _CodeSignature directory
        if relative_path.starts_with("_CodeSignature/") || relative_path == "_CodeSignature" {
            return true;
        }

        // Exclude CodeResources file itself
        if relative_path == "_CodeSignature/CodeResources" {
            return true;
        }

        // Exclude the main executable (it has its own embedded signature)
        if let Some(ref main_exec) = self.main_executable {
            if relative_path == main_exec {
                return true;
            }
        }

        // Nested bundle files (Frameworks/*.framework/*, PlugIns/*.appex/*) are included
        // in the parent's CodeResources. Nested bundles have separate signatures.

        // Check custom exclusions
        for pattern in &self.exclusions {
            if relative_path.starts_with(pattern) {
                return true;
            }
        }

        false
    }

    /// Computes SHA-1 and SHA-256 hashes of the given data.
    ///
    /// Utility method for hashing arbitrary byte slices.
    ///
    /// # Examples
    ///
    /// ```
    /// use zsign_core::bundle::CodeResourcesBuilder;
    ///
    /// let (sha1, sha256) = CodeResourcesBuilder::hash_data(b"Hello, World!");
    /// assert_eq!(sha1.len(), 20);
    /// assert_eq!(sha256.len(), 32);
    /// ```
    pub fn hash_data(data: &[u8]) -> ([u8; 20], [u8; 32]) {
        let mut sha1_hasher = Sha1::new();
        sha1_hasher.update(data);
        let sha1_result = sha1_hasher.finalize();

        let mut sha256_hasher = Sha256::new();
        sha256_hasher.update(data);
        let sha256_result = sha256_hasher.finalize();

        let mut sha1 = [0u8; 20];
        let mut sha256 = [0u8; 32];
        sha1.copy_from_slice(&sha1_result);
        sha256.copy_from_slice(&sha256_result);

        (sha1, sha256)
    }

    /// Adds a file entry with pre-computed hashes.
    ///
    /// Returns `true` if the file was added, `false` if it was excluded by
    /// the current exclusion rules.
    ///
    /// # Examples
    ///
    /// ```
    /// use zsign_core::bundle::CodeResourcesBuilder;
    ///
    /// let mut builder = CodeResourcesBuilder::new();
    /// let (sha1, sha256) = CodeResourcesBuilder::hash_data(b"file content");
    /// assert!(builder.add_file("Resources/data.bin", sha1, sha256));
    /// ```
    pub fn add_file(
        &mut self,
        relative_path: impl Into<String>,
        sha1: [u8; 20],
        sha256: [u8; 32],
    ) -> bool {
        let path = relative_path.into();
        if self.should_exclude(&path) {
            return false;
        }
        self.files.insert(path, FileEntry { sha1, sha256, symlink_target: None });
        true
    }

    /// Adds a symlink entry with pre-computed hashes.
    ///
    /// Returns `true` if the symlink was added, `false` if it was excluded by
    /// the current exclusion rules.
    ///
    /// # Examples
    ///
    /// ```
    /// use zsign_core::bundle::CodeResourcesBuilder;
    ///
    /// let mut builder = CodeResourcesBuilder::new();
    /// let (sha1, sha256) = CodeResourcesBuilder::hash_data(b"Versions/Current/Test");
    /// assert!(builder.add_symlink("Frameworks/Test.framework/Test", "Versions/Current/Test", sha1, sha256));
    /// ```
    pub fn add_symlink(
        &mut self,
        relative_path: impl Into<String>,
        target: impl Into<String>,
        sha1: [u8; 20],
        sha256: [u8; 32],
    ) -> bool {
        let path = relative_path.into();
        if self.should_exclude(&path) {
            return false;
        }
        self.files.insert(
            path,
            FileEntry {
                sha1,
                sha256,
                symlink_target: Some(target.into()),
            },
        );
        true
    }

    /// Builds the CodeResources plist as XML bytes.
    ///
    /// Generates the complete `_CodeSignature/CodeResources` plist containing:
    /// - `files`: Legacy SHA-1 hashes for older iOS versions
    /// - `files2`: Modern SHA-1 + SHA-256 hashes with metadata
    /// - `rules` / `rules2`: Standard Apple inclusion/exclusion patterns
    ///
    /// # Errors
    ///
    /// Returns an error if plist serialization fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use zsign_core::bundle::CodeResourcesBuilder;
    ///
    /// let mut builder = CodeResourcesBuilder::new();
    /// let (sha1, sha256) = CodeResourcesBuilder::hash_data(b"content");
    /// builder.add_file("test.txt", sha1, sha256);
    /// let plist_bytes = builder.build().unwrap();
    /// ```
    pub fn build(&self) -> Result<Vec<u8>> {
        let mut root = Dictionary::new();

        // Build "files" dictionary (legacy, SHA-1 only)
        // C++ Reference: bundle.cpp:177-184
        // For .lproj files, use dict with hash+optional; for others, use plain hash
        let mut files = Dictionary::new();
        for (path, entry) in &self.files {
            // Skip symlinks in legacy files dict (they weren't supported in old format)
            if entry.symlink_target.is_some() {
                continue;
            }

            if path.contains(".lproj/") {
                // .lproj files get a dict with hash and optional flag
                let mut file_dict = Dictionary::new();
                file_dict.insert("hash".to_string(), Value::Data(entry.sha1.to_vec()));
                file_dict.insert("optional".to_string(), Value::Boolean(true));
                files.insert(path.clone(), Value::Dictionary(file_dict));
            } else {
                // Other files just get the hash directly
                files.insert(path.clone(), Value::Data(entry.sha1.to_vec()));
            }
        }
        root.insert("files".to_string(), Value::Dictionary(files));

        // Build "files2" dictionary (modern, SHA-1 + SHA-256)
        // C++ Reference: bundle.cpp:186-192
        // Omits .DS_Store, Info.plist, PkgInfo from files2
        // Adds optional flag for .lproj files
        let mut files2 = Dictionary::new();
        for (path, entry) in &self.files {
            // Omit these from files2 (they are included in files)
            if path == "Info.plist" || path == "PkgInfo" || path.ends_with(".DS_Store") {
                continue;
            }

            let mut file_dict = Dictionary::new();

            // If this is a symlink, add symlink target instead of hashes
            if let Some(ref target) = entry.symlink_target {
                file_dict.insert("symlink".to_string(), Value::String(target.clone()));
            } else {
                // Add SHA-1 hash
                file_dict.insert("hash".to_string(), Value::Data(entry.sha1.to_vec()));

                // Add SHA-256 hash
                file_dict.insert("hash2".to_string(), Value::Data(entry.sha256.to_vec()));
            }

            // Mark .lproj files as optional
            if path.contains(".lproj/") {
                file_dict.insert("optional".to_string(), Value::Boolean(true));
            }

            files2.insert(path.clone(), Value::Dictionary(file_dict));
        }
        root.insert("files2".to_string(), Value::Dictionary(files2));

        // Add rules (legacy)
        root.insert("rules".to_string(), Value::Dictionary(standard_rules()));

        // Add rules2 (modern)
        root.insert("rules2".to_string(), Value::Dictionary(standard_rules2()));

        // Serialize to XML plist
        let mut buf = Vec::new();
        plist::to_writer_xml(&mut buf, &Value::Dictionary(root))
            .map_err(Error::Plist)?;

        Ok(buf)
    }

    /// Returns an iterator over all scanned files and their hashes.
    ///
    /// Each item contains the relative path, SHA-1 hash, and SHA-256 hash.
    pub fn files(&self) -> impl Iterator<Item = (&String, &[u8; 20], &[u8; 32])> {
        self.files
            .iter()
            .map(|(path, entry)| (path, &entry.sha1, &entry.sha256))
    }

    /// Returns the number of files that will be included in the plist.
    pub fn file_count(&self) -> usize {
        self.files.len()
    }
}

impl Default for CodeResourcesBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let builder = CodeResourcesBuilder::new();
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
        let mut builder = CodeResourcesBuilder::new();

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
    fn test_rules_structure() {
        let rules = standard_rules();

        // Verify expected rules exist
        assert!(rules.contains_key("^.*"));
        assert!(rules.contains_key("^.*\\.lproj/"));
        assert!(rules.contains_key("^.*\\.lproj/locversion.plist$"));
        assert!(rules.contains_key("^Base\\.lproj/"));
        assert!(rules.contains_key("^version.plist$"));
    }

    #[test]
    fn test_rules2_structure() {
        let rules2 = standard_rules2();

        // Verify expected rules2 exist
        assert!(rules2.contains_key("^.*"));
        assert!(rules2.contains_key(".*\\.dSYM($|/)"));
        assert!(rules2.contains_key("^(.*/)?\\.DS_Store$"));
        assert!(rules2.contains_key("^.*\\.lproj/"));
        assert!(rules2.contains_key("^Info\\.plist$"));
        assert!(rules2.contains_key("^PkgInfo$"));
    }
}
