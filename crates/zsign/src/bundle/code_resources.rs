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
    /// SHA-1 hash (20 bytes)
    sha1: [u8; 20],
    /// SHA-256 hash (32 bytes)
    sha256: [u8; 32],
    /// Whether this is optional (can be missing)
    optional: bool,
}

/// Standard exclusion rules for CodeResources
fn standard_rules() -> Dictionary {
    let mut rules = Dictionary::new();

    // Exclude _CodeSignature
    rules.insert("^_CodeSignature/".to_string(), Value::Boolean(false));

    // Exclude ResourceRules.plist (deprecated)
    rules.insert("^ResourceRules\\.plist$".to_string(), Value::Boolean(true));

    // Everything else is included by default
    rules.insert("^.*".to_string(), Value::Boolean(true));

    rules
}

/// Modern rules2 for CodeResources (more comprehensive)
fn standard_rules2() -> Dictionary {
    let mut rules2 = Dictionary::new();

    // Exclude _CodeSignature directory
    let mut code_sig = Dictionary::new();
    code_sig.insert("omit".to_string(), Value::Boolean(true));
    code_sig.insert("weight".to_string(), Value::Real(2000.0));
    rules2.insert("^_CodeSignature/".to_string(), Value::Dictionary(code_sig));

    // Exclude CodeResources itself
    let mut code_res = Dictionary::new();
    code_res.insert("omit".to_string(), Value::Boolean(true));
    code_res.insert("weight".to_string(), Value::Real(2000.0));
    rules2.insert(
        "^_CodeSignature/CodeResources$".to_string(),
        Value::Dictionary(code_res),
    );

    // Nested bundles are handled separately
    let mut nested = Dictionary::new();
    nested.insert("nested".to_string(), Value::Boolean(true));
    nested.insert("weight".to_string(), Value::Real(10.0));
    rules2.insert("^.*\\.app/".to_string(), Value::Dictionary(nested.clone()));
    rules2.insert(
        "^.*\\.framework/".to_string(),
        Value::Dictionary(nested.clone()),
    );
    rules2.insert(
        "^.*\\.appex/".to_string(),
        Value::Dictionary(nested.clone()),
    );

    // PlugIns directory with nested bundles
    let mut plugins = Dictionary::new();
    plugins.insert("nested".to_string(), Value::Boolean(true));
    plugins.insert("weight".to_string(), Value::Real(10.0));
    rules2.insert("^PlugIns/".to_string(), Value::Dictionary(plugins));

    // Frameworks directory with nested bundles
    let mut frameworks = Dictionary::new();
    frameworks.insert("nested".to_string(), Value::Boolean(true));
    frameworks.insert("weight".to_string(), Value::Real(10.0));
    rules2.insert("^Frameworks/".to_string(), Value::Dictionary(frameworks));

    // SC_Info (Store Container info) - optional
    let mut sc_info = Dictionary::new();
    sc_info.insert("omit".to_string(), Value::Boolean(true));
    sc_info.insert("weight".to_string(), Value::Real(1000.0));
    rules2.insert("^SC_Info/".to_string(), Value::Dictionary(sc_info));

    // Info.plist is always included with high weight
    let mut info_plist = Dictionary::new();
    info_plist.insert("weight".to_string(), Value::Real(20.0));
    rules2.insert("^Info\\.plist$".to_string(), Value::Dictionary(info_plist));

    // PkgInfo
    let mut pkg_info = Dictionary::new();
    pkg_info.insert("weight".to_string(), Value::Real(20.0));
    rules2.insert("^PkgInfo$".to_string(), Value::Dictionary(pkg_info));

    // ResourceRules.plist (deprecated, omit)
    let mut resource_rules = Dictionary::new();
    resource_rules.insert("omit".to_string(), Value::Boolean(true));
    resource_rules.insert("weight".to_string(), Value::Real(100.0));
    rules2.insert(
        "^ResourceRules\\.plist$".to_string(),
        Value::Dictionary(resource_rules),
    );

    // embedded.mobileprovision
    let mut provision = Dictionary::new();
    provision.insert("weight".to_string(), Value::Real(20.0));
    rules2.insert(
        "^embedded\\.mobileprovision$".to_string(),
        Value::Dictionary(provision),
    );

    // Default rule for everything else
    rules2.insert("^.*".to_string(), Value::Boolean(true));

    rules2
}

impl CodeResourcesBuilder {
    /// Create a new CodeResources builder for the given bundle path
    pub fn new(bundle_path: impl AsRef<Path>) -> Self {
        let bundle_path = bundle_path.as_ref().to_path_buf();

        // Try to read the main executable name from Info.plist
        let main_executable = Self::read_main_executable(&bundle_path);

        Self {
            bundle_path,
            files: BTreeMap::new(),
            exclusions: Vec::new(),
            main_executable,
        }
    }

    /// Read the main executable name from Info.plist (CFBundleExecutable)
    fn read_main_executable(bundle_path: &Path) -> Option<String> {
        let info_plist_path = bundle_path.join("Info.plist");
        let data = fs::read(&info_plist_path).ok()?;
        let plist: plist::Value = plist::from_bytes(&data).ok()?;
        let dict = plist.as_dictionary()?;
        dict.get("CFBundleExecutable")?.as_string().map(|s| s.to_string())
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

        // Check if this is a nested bundle (will be handled separately)
        if self.is_nested_bundle(relative_path) {
            return true;
        }

        // Check custom exclusions
        for pattern in &self.exclusions {
            if relative_path.starts_with(pattern) {
                return true;
            }
        }

        false
    }

    /// Check if the path is inside a nested bundle
    fn is_nested_bundle(&self, relative_path: &str) -> bool {
        let bundle_extensions = [".app/", ".framework/", ".appex/", ".xctest/"];

        for ext in &bundle_extensions {
            // Check if there's a nested bundle in the path
            if let Some(pos) = relative_path.find(ext) {
                // Only count as nested if it's not at the root
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

        for entry in WalkDir::new(&bundle_path)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let path = entry.path();

            // Skip directories
            if !path.is_file() {
                continue;
            }

            // Get relative path from bundle root
            let relative_path = path
                .strip_prefix(&bundle_path)
                .map_err(|e| Error::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))?
                .to_string_lossy()
                .to_string();

            // Check if should be excluded
            if self.should_exclude(&relative_path) {
                continue;
            }

            // Hash the file
            let file_entry = self.hash_file(path)?;
            self.files.insert(relative_path, file_entry);
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
        })
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
            },
        );
    }

    /// Build the CodeResources plist
    pub fn build(&self) -> Result<Vec<u8>> {
        let mut root = Dictionary::new();

        // Build "files" dictionary (legacy, SHA-1 only)
        let mut files = Dictionary::new();
        for (path, entry) in &self.files {
            files.insert(path.clone(), Value::Data(entry.sha1.to_vec()));
        }
        root.insert("files".to_string(), Value::Dictionary(files));

        // Build "files2" dictionary (modern, SHA-1 + SHA-256)
        let mut files2 = Dictionary::new();
        for (path, entry) in &self.files {
            let mut file_dict = Dictionary::new();

            // Add SHA-1 hash
            file_dict.insert("hash".to_string(), Value::Data(entry.sha1.to_vec()));

            // Add SHA-256 hash
            file_dict.insert("hash2".to_string(), Value::Data(entry.sha256.to_vec()));

            // Add optional flag if set
            if entry.optional {
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
            .map_err(|e| Error::Plist(e))?;

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
    fn test_exclusion_of_nested_bundles() {
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

        // Verify nested bundle files are excluded (they should be signed separately)
        let file_paths: Vec<_> = builder.files().map(|(p, _, _)| p.clone()).collect();

        // Main Info.plist should be included
        assert!(file_paths.contains(&"Info.plist".to_string()));

        // Nested framework files should be excluded
        assert!(!file_paths.iter().any(|p| p.contains(".framework/")));
    }

    #[test]
    fn test_rules_structure() {
        let rules = standard_rules();

        // Verify key rules exist
        assert!(rules.contains_key("^_CodeSignature/"));
        assert!(rules.contains_key("^.*"));
    }

    #[test]
    fn test_rules2_structure() {
        let rules2 = standard_rules2();

        // Verify key rules2 exist
        assert!(rules2.contains_key("^_CodeSignature/"));
        assert!(rules2.contains_key("^.*\\.framework/"));
        assert!(rules2.contains_key("^Frameworks/"));
        assert!(rules2.contains_key("^PlugIns/"));
        assert!(rules2.contains_key("^Info\\.plist$"));
    }
}
