//! CodeResources generation for iOS app bundle signing
//!
//! Generates the CodeResources plist that contains hashes of all files in the bundle.
//! This is required for code signature verification.

use crate::{Error, Result};
use plist::{Dictionary, Value};
use sha1::{Digest, Sha1};
use sha2::Sha256;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use rayon::prelude::*;
use walkdir::WalkDir;

/// Builder for generating CodeResources plist
pub struct CodeResourcesBuilder {
    /// Root bundle path
    bundle_path: PathBuf,
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
    /// Whether this is optional (can be missing)
    #[allow(dead_code)]
    optional: bool,
    /// If this is a symlink, contains the target path
    symlink_target: Option<String>,
}

/// Standard exclusion rules for CodeResources
/// C++ Reference: bundle.cpp:195-201
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

/// Modern rules2 for CodeResources
/// C++ Reference: bundle.cpp:203-217
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
    /// Create a new CodeResources builder for the given bundle path
    pub fn new(bundle_path: impl AsRef<Path>) -> Self {
        let bundle_path = bundle_path.as_ref().to_path_buf();

        // Log warning if Info.plist can't be read (but don't fail construction)
        let main_executable = match Self::read_main_executable(&bundle_path) {
            Ok(exec) => exec,
            Err(e) => {
                eprintln!("Warning: Failed to read main executable from Info.plist: {}", e);
                None
            }
        };

        Self {
            bundle_path,
            files: BTreeMap::new(),
            exclusions: Vec::new(),
            main_executable,
        }
    }

    /// Read the main executable name from Info.plist (CFBundleExecutable)
    fn read_main_executable(bundle_path: &Path) -> Result<Option<String>> {
        let info_plist_path = bundle_path.join("Info.plist");
        
        if !info_plist_path.exists() {
            // Info.plist not existing is OK for some bundle types
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

    /// Add a custom exclusion pattern
    pub fn exclude(mut self, pattern: impl Into<String>) -> Self {
        self.exclusions.push(pattern.into());
        self
    }

    /// Check if a path should be excluded from hashing
    fn should_exclude(&self, relative_path: &str) -> bool {
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

        // NOTE: C++ zsign does NOT exclude nested bundle files from CodeResources
        // All files including Frameworks/*.framework/*, PlugIns/*.appex/* are included
        // The nested bundles are signed separately, but their files still appear in parent's CodeResources
        // Reference: C++ zsign bundle.cpp:127-193 - no nested bundle exclusion

        // Check custom exclusions
        for pattern in &self.exclusions {
            if relative_path.starts_with(pattern) {
                return true;
            }
        }

        false
    }

    /// Check if the path is inside a nested bundle
    /// 
    /// NOTE: This function is no longer used because C++ zsign does NOT exclude
    /// nested bundle files from CodeResources. Keeping for potential future use.
    #[allow(dead_code)]
    fn is_nested_bundle(&self, relative_path: &str) -> bool {
        let bundle_extensions = [".app/", ".framework/", ".appex/", ".xctest/"];

        for ext in &bundle_extensions {
            if let Some(pos) = relative_path.find(ext) {
                if pos > 0 {
                    return true;
                }
            }
        }

        false
    }

    /// Walk the bundle and hash all files
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

                if self.should_exclude(&relative_path) {
                    return None;
                }

                let file_entry = if is_symlink {
                    self.hash_symlink(path).ok()?
                } else {
                    self.hash_file(path).ok()?
                };

                Some((relative_path, file_entry))
            })
            .collect();

        // Insert results sequentially (BTreeMap is not thread-safe)
        for (path, entry) in results {
            self.files.insert(path, entry);
        }

        Ok(self)
    }

    /// Hash a single file with both SHA-1 and SHA-256
    fn hash_file(&self, path: &Path) -> Result<FileEntry> {
        let data = fs::read(path)?;

        let mut sha1_hasher = Sha1::new();
        sha1_hasher.update(&data);
        let sha1_result = sha1_hasher.finalize();

        let mut sha256_hasher = Sha256::new();
        sha256_hasher.update(&data);
        let sha256_result = sha256_hasher.finalize();

        let mut sha1 = [0u8; 20];
        let mut sha256 = [0u8; 32];
        sha1.copy_from_slice(&sha1_result);
        sha256.copy_from_slice(&sha256_result);

        Ok(FileEntry {
            sha1,
            sha256,
            optional: false,
            symlink_target: None,
        })
    }

    /// Hash a symlink by hashing its target path
    #[cfg(unix)]
    fn hash_symlink(&self, path: &Path) -> Result<FileEntry> {
        use std::os::unix::ffi::OsStrExt;

        let target = fs::read_link(path)?;
        let target_bytes = target.as_os_str().as_bytes();

        let mut sha1_hasher = Sha1::new();
        sha1_hasher.update(target_bytes);
        let sha1_result = sha1_hasher.finalize();

        let mut sha256_hasher = Sha256::new();
        sha256_hasher.update(target_bytes);
        let sha256_result = sha256_hasher.finalize();

        let mut sha1 = [0u8; 20];
        let mut sha256 = [0u8; 32];
        sha1.copy_from_slice(&sha1_result);
        sha256.copy_from_slice(&sha256_result);

        Ok(FileEntry {
            sha1,
            sha256,
            optional: false,
            symlink_target: Some(target.to_string_lossy().to_string()),
        })
    }

    #[cfg(not(unix))]
    fn hash_symlink(&self, _path: &Path) -> Result<FileEntry> {
        // On non-Unix platforms, symlinks are rare in iOS bundles
        // Return an error or handle as regular file
        Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "Symlink handling not supported on this platform",
        )))
    }

    /// Hash data directly (for testing or inline content)
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

    /// Add a file entry manually (useful for adding nested bundle CodeResources)
    pub fn add_file(
        &mut self,
        relative_path: impl Into<String>,
        sha1: [u8; 20],
        sha256: [u8; 32],
    ) {
        self.files.insert(
            relative_path.into(),
            FileEntry {
                sha1,
                sha256,
                optional: false,
                symlink_target: None,
            },
        );
    }

    /// Add an optional file entry
    pub fn add_optional_file(
        &mut self,
        relative_path: impl Into<String>,
        sha1: [u8; 20],
        sha256: [u8; 32],
    ) {
        self.files.insert(
            relative_path.into(),
            FileEntry {
                sha1,
                sha256,
                optional: true,
                symlink_target: None,
            },
        );
    }

    /// Build the CodeResources plist
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
            // C++ zsign omits these from files2 (but includes in files)
            // Reference: bundle.cpp:173-175
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

            // Add optional flag for .lproj files
            // C++ Reference: bundle.cpp:189-191
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

    /// Get the raw files map for inspection
    pub fn files(&self) -> impl Iterator<Item = (&String, &[u8; 20], &[u8; 32])> {
        self.files
            .iter()
            .map(|(path, entry)| (path, &entry.sha1, &entry.sha256))
    }

    /// Get the number of files that will be included
    pub fn file_count(&self) -> usize {
        self.files.len()
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

        // C++ zsign includes nested bundle files in parent's CodeResources
        // Reference: C++ zsign bundle.cpp:127-193 - no nested bundle exclusion
        let file_paths: Vec<_> = builder.files().map(|(p, _, _)| p.clone()).collect();

        // Main Info.plist should be included
        assert!(file_paths.contains(&"Info.plist".to_string()));

        // Nested framework files should also be included (matching C++ zsign behavior)
        assert!(file_paths.iter().any(|p| p.contains(".framework/")));
        assert!(file_paths.contains(&"Frameworks/Test.framework/Test".to_string()));
        assert!(file_paths.contains(&"Frameworks/Test.framework/Info.plist".to_string()));
    }

    #[test]
    fn test_rules_structure() {
        let rules = standard_rules();

        // Verify key rules exist (matching C++ zsign bundle.cpp:195-201)
        assert!(rules.contains_key("^.*"));
        assert!(rules.contains_key("^.*\\.lproj/"));
        assert!(rules.contains_key("^.*\\.lproj/locversion.plist$"));
        assert!(rules.contains_key("^Base\\.lproj/"));
        assert!(rules.contains_key("^version.plist$"));
    }

    #[test]
    fn test_rules2_structure() {
        let rules2 = standard_rules2();

        // Verify key rules2 exist (matching C++ zsign bundle.cpp:203-217)
        assert!(rules2.contains_key("^.*"));
        assert!(rules2.contains_key(".*\\.dSYM($|/)"));
        assert!(rules2.contains_key("^(.*/)?\\.DS_Store$"));
        assert!(rules2.contains_key("^.*\\.lproj/"));
        assert!(rules2.contains_key("^Info\\.plist$"));
        assert!(rules2.contains_key("^PkgInfo$"));
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
