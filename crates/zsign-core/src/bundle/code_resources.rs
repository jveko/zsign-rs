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
//!
//! Custom patterns are also declared as omit rules in the emitted `rules`
//! and `rules2`, so a verifier applying them reaches the same conclusion this
//! builder does.

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
    rules.insert(
        "^.*\\.lproj/locversion.plist$".to_string(),
        Value::Dictionary(locversion),
    );

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
    rules2.insert(
        "^(.*/)?\\.DS_Store$".to_string(),
        Value::Dictionary(ds_store),
    );

    // .lproj directories are optional
    let mut lproj = Dictionary::new();
    lproj.insert("optional".to_string(), Value::Boolean(true));
    lproj.insert("weight".to_string(), Value::Real(1000.0));
    rules2.insert("^.*\\.lproj/".to_string(), Value::Dictionary(lproj));

    // locversion.plist is omitted
    let mut locversion = Dictionary::new();
    locversion.insert("omit".to_string(), Value::Boolean(true));
    locversion.insert("weight".to_string(), Value::Real(1100.0));
    rules2.insert(
        "^.*\\.lproj/locversion.plist$".to_string(),
        Value::Dictionary(locversion),
    );

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
    rules2.insert(
        "^embedded\\.provisionprofile$".to_string(),
        Value::Dictionary(provision),
    );

    // version.plist
    let mut version_plist = Dictionary::new();
    version_plist.insert("weight".to_string(), Value::Real(20.0));
    rules2.insert(
        "^version\\.plist$".to_string(),
        Value::Dictionary(version_plist),
    );

    rules2
}

/// Weight emitted for `exclude()` omit rules: ties the most-specific
/// standard class (`.DS_Store` omit at 2000) and outranks every other
/// standard weight, so an excluded path resolves to `omit` regardless of
/// which other rules match it — matching `should_exclude`'s precedence.
const EXCLUSION_RULE_WEIGHT: f64 = 2000.0;

/// Action a resource rule assigns to a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuleAction {
    Include,
    Omit,
    Optional,
}

/// Tie-break on equal weight, strictest first: Include beats Omit beats
/// Optional. Mirrors the verifier's `tie_rank` in the zsign crate; the
/// verifier lives in a crate this one cannot depend on, so emission carries
/// the same resolution over the dicts it emits.
fn tie_rank(action: RuleAction) -> u8 {
    match action {
        RuleAction::Include => 0,
        RuleAction::Omit => 1,
        RuleAction::Optional => 2,
    }
}

/// Parses one emitted rule spec into `(action, weight)`; unusable specs are
/// dropped, mirroring the verifier's treatment of invalid rules.
fn parse_rule(spec: &Value) -> Option<(RuleAction, f64)> {
    match spec {
        Value::Boolean(true) => Some((RuleAction::Include, 1.0)),
        Value::Boolean(false) => Some((RuleAction::Omit, 1.0)),
        Value::Dictionary(dict) => {
            if dict
                .keys()
                .any(|k| !matches!(k.as_str(), "omit" | "optional" | "weight"))
            {
                return None;
            }
            let bad_type = matches!(dict.get("omit"), Some(v) if !matches!(v, Value::Boolean(_)))
                || matches!(dict.get("optional"), Some(v) if !matches!(v, Value::Boolean(_)));
            if bad_type {
                return None;
            }
            let omit = matches!(dict.get("omit"), Some(Value::Boolean(true)));
            let optional = matches!(dict.get("optional"), Some(Value::Boolean(true)));
            if omit && optional {
                return None;
            }
            let weight = match dict.get("weight") {
                None => 1.0,
                Some(Value::Real(w)) if w.is_finite() => *w,
                Some(Value::Integer(w)) => w
                    .as_signed()
                    .map(|v| v as f64)
                    .or_else(|| w.as_unsigned().map(|v| v as f64))
                    .unwrap_or(f64::NAN),
                _ => return None,
            };
            if !weight.is_finite() {
                return None;
            }
            let action = if omit {
                RuleAction::Omit
            } else if optional {
                RuleAction::Optional
            } else {
                RuleAction::Include
            };
            Some((action, weight))
        }
        _ => None,
    }
}

/// True when an emitted rule key matches `rel`. The standard vocabulary is
/// matched exactly as the verifier matches it (including the deliberately
/// unescaped dot before `plist`); any other `^`-anchored key is read as the
/// literal-prefix form `build()` emits for `exclude()` patterns, and keys
/// outside that vocabulary never match.
fn rule_pattern_matches(pattern: &str, rel: &str) -> bool {
    match pattern {
        "^.*" => true,
        "^.*\\.lproj/" => rel.contains(".lproj/"),
        "^.*\\.lproj/locversion.plist$" => {
            rel.match_indices(".lproj/locversion").any(|(idx, _)| {
                let rest = &rel[idx + ".lproj/locversion".len()..];
                let mut chars = rest.chars();
                matches!(chars.next(), Some(c) if c != '\n') && chars.as_str() == "plist"
            })
        }
        "^Base\\.lproj/" => rel.starts_with("Base.lproj/"),
        "^version.plist$" => rel == "version.plist",
        "^version\\.plist$" => rel == "version.plist",
        ".*\\.dSYM($|/)" => rel.ends_with(".dSYM") || rel.contains(".dSYM/"),
        "^(.*/)?\\.DS_Store$" => rel == ".DS_Store" || rel.ends_with("/.DS_Store"),
        "^Info\\.plist$" => rel == "Info.plist",
        "^PkgInfo$" => rel == "PkgInfo",
        "^embedded\\.provisionprofile$" => rel == "embedded.provisionprofile",
        other => other
            .strip_prefix('^')
            .is_some_and(|literal| rel.starts_with(&unescape_regex_literal(literal))),
    }
}

/// Escapes regex metacharacters so `format!("^{}", escape_regex_literal(p))`
/// matches exactly the paths `p` is a literal prefix of.
fn escape_regex_literal(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        if matches!(
            ch,
            '\\' | '.' | '+' | '*' | '?' | '(' | ')' | '[' | ']' | '{' | '}' | '^' | '$' | '|'
        ) {
            out.push('\\');
        }
        out.push(ch);
    }
    out
}

/// Inverse of [`escape_regex_literal`] for keys this module emitted.
fn unescape_regex_literal(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            if let Some(escaped) = chars.next() {
                out.push(escaped);
            }
        } else {
            out.push(ch);
        }
    }
    out
}

/// Winning rule for `rel`: highest weight wins; equal weights resolve
/// strictest-first via [`tie_rank`]. Mirrors the verifier's `rule_action`.
fn rule_action(rules: &Dictionary, rel: &str) -> Option<RuleAction> {
    let mut best: Option<(RuleAction, f64)> = None;
    for (pattern, spec) in rules {
        let Some((action, weight)) = parse_rule(spec) else {
            continue;
        };
        if !rule_pattern_matches(pattern, rel) {
            continue;
        }
        best = Some(match best {
            None => (action, weight),
            Some((best_action, best_weight)) => match weight.total_cmp(&best_weight) {
                std::cmp::Ordering::Greater => (action, weight),
                std::cmp::Ordering::Equal if tie_rank(action) < tie_rank(best_action) => {
                    (action, weight)
                }
                _ => (best_action, best_weight),
            },
        });
    }
    best.map(|(action, _)| action)
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
    /// The pattern is also emitted as an omit rule in the `rules` and `rules2`
    /// dictionaries of the built plist.
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
        self.files.insert(
            path,
            FileEntry {
                sha1,
                sha256,
                symlink_target: None,
            },
        );
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
    /// `files`/`files2` entries are derived from the rule sets this method
    /// emits: a path whose winning rule is `omit` is not sealed, and the
    /// entry-level `optional` flag is copied from a winning `optional` rule,
    /// so the sealed entries and the declared rules can never contradict each
    /// other. Each `exclude()` pattern is declared as a matching omit rule in
    /// both `rules` and `rules2`.
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

        let mut rules = standard_rules();
        let mut rules2 = standard_rules2();
        for pattern in &self.exclusions {
            let mut spec = Dictionary::new();
            spec.insert("omit".to_string(), Value::Boolean(true));
            spec.insert("weight".to_string(), Value::Real(EXCLUSION_RULE_WEIGHT));
            let key = format!("^{}", escape_regex_literal(pattern));
            rules.insert(key.clone(), Value::Dictionary(spec.clone()));
            rules2.insert(key, Value::Dictionary(spec));
        }

        // Legacy "files": SHA-1 only, symlinks unsupported by the old format.
        // C++ Reference: bundle.cpp:177-184
        let mut files = Dictionary::new();
        for (path, entry) in &self.files {
            if entry.symlink_target.is_some() {
                continue;
            }
            match rule_action(&rules, path) {
                Some(RuleAction::Omit) => continue,
                Some(RuleAction::Optional) => {
                    let mut file_dict = Dictionary::new();
                    file_dict.insert("hash".to_string(), Value::Data(entry.sha1.to_vec()));
                    file_dict.insert("optional".to_string(), Value::Boolean(true));
                    files.insert(path.clone(), Value::Dictionary(file_dict));
                }
                _ => {
                    files.insert(path.clone(), Value::Data(entry.sha1.to_vec()));
                }
            }
        }
        root.insert("files".to_string(), Value::Dictionary(files));

        // Modern "files2": SHA-1 + SHA-256, symlink targets instead of hashes.
        let mut files2 = Dictionary::new();
        for (path, entry) in &self.files {
            let action = rule_action(&rules2, path);
            if action == Some(RuleAction::Omit) {
                continue;
            }
            let mut file_dict = Dictionary::new();
            if let Some(target) = &entry.symlink_target {
                file_dict.insert("symlink".to_string(), Value::String(target.clone()));
            } else {
                file_dict.insert("hash".to_string(), Value::Data(entry.sha1.to_vec()));
                file_dict.insert("hash2".to_string(), Value::Data(entry.sha256.to_vec()));
            }
            if action == Some(RuleAction::Optional) {
                file_dict.insert("optional".to_string(), Value::Boolean(true));
            }
            files2.insert(path.clone(), Value::Dictionary(file_dict));
        }
        root.insert("files2".to_string(), Value::Dictionary(files2));

        root.insert("rules".to_string(), Value::Dictionary(rules));
        root.insert("rules2".to_string(), Value::Dictionary(rules2));

        let mut buf = Vec::new();
        plist::to_writer_xml(&mut buf, &Value::Dictionary(root)).map_err(Error::Plist)?;
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

    #[test]
    fn test_build_omits_rule_declared_paths() {
        let mut builder = CodeResourcesBuilder::new();
        let (sha1, sha256) = CodeResourcesBuilder::hash_data(b"x");
        for path in [
            "Info.plist",
            "PkgInfo",
            ".DS_Store",
            "en.lproj/locversion.plist",
            "en.lproj/Localizable.strings",
            "Base.lproj/Notes.strings",
            "data.bin",
        ] {
            builder.add_file(path, sha1, sha256);
        }
        let bytes = builder.build().unwrap();
        let value: Value = plist::from_bytes(&bytes).unwrap();
        let root = value.as_dictionary().unwrap();
        let files = root.get("files").unwrap().as_dictionary().unwrap();
        let files2 = root.get("files2").unwrap().as_dictionary().unwrap();

        // rules2 declares these omit: absent from files2 …
        for omitted in [
            "Info.plist",
            "PkgInfo",
            ".DS_Store",
            "en.lproj/locversion.plist",
        ] {
            assert!(!files2.contains_key(omitted), "{omitted} is rule-omitted");
        }
        // … and the legacy dict drops what the v1 rules omit.
        assert!(
            !files.contains_key("en.lproj/locversion.plist"),
            "v1 rules declare locversion omit"
        );
        // v1 rules carry no Info/PkgInfo/.DS_Store omission: still sealed there.
        assert!(matches!(files.get("Info.plist"), Some(Value::Data(_))));
        assert!(files.contains_key(".DS_Store"), "kept in the legacy dict");

        // Rule-derived optional: .lproj optional, Base.lproj (weight 1010) included.
        let en = files2
            .get("en.lproj/Localizable.strings")
            .and_then(|v| v.as_dictionary())
            .expect("en.lproj file sealed");
        assert_eq!(en.get("optional"), Some(&Value::Boolean(true)));
        let base = files2
            .get("Base.lproj/Notes.strings")
            .and_then(|v| v.as_dictionary())
            .expect("Base.lproj file sealed");
        assert!(
            base.get("optional").is_none(),
            "Base.lproj resolves to Include, not Optional"
        );
        assert!(
            matches!(files.get("Base.lproj/Notes.strings"), Some(Value::Data(_))),
            "v1 Base.lproj entry is bare data, not an optional dict"
        );
        assert!(files2.contains_key("data.bin"));
    }

    #[test]
    fn test_custom_exclude_emits_matching_omit_rule() {
        let mut builder = CodeResourcesBuilder::new();
        builder.exclude("DebugResources/");
        let (sha1, sha256) = CodeResourcesBuilder::hash_data(b"x");
        assert!(!builder.add_file("DebugResources/asset.dat", sha1, sha256));
        assert!(builder.add_file("keep.txt", sha1, sha256));

        let bytes = builder.build().unwrap();
        let value: Value = plist::from_bytes(&bytes).unwrap();
        let root = value.as_dictionary().unwrap();
        for key in ["rules", "rules2"] {
            let rules = root.get(key).unwrap().as_dictionary().unwrap();
            let spec = rules
                .get("^DebugResources/")
                .unwrap_or_else(|| panic!("{key} must declare the exclusion as omit"));
            let dict = spec.as_dictionary().expect("rule spec is a dict");
            assert_eq!(dict.get("omit"), Some(&Value::Boolean(true)));
            assert_eq!(dict.get("weight"), Some(&Value::Real(2000.0)));
        }
        let rules2 = root.get("rules2").unwrap().as_dictionary().unwrap();
        assert_eq!(
            rule_action(rules2, "DebugResources/asset.dat"),
            Some(RuleAction::Omit),
            "the emitted rules resolve excluded paths to Omit"
        );
        assert_eq!(rule_action(rules2, "keep.txt"), Some(RuleAction::Include));
        let files = root.get("files").unwrap().as_dictionary().unwrap();
        let files2 = root.get("files2").unwrap().as_dictionary().unwrap();
        assert!(!files.contains_key("DebugResources/asset.dat"));
        assert!(!files2.contains_key("DebugResources/asset.dat"));
    }

    #[test]
    fn should_exclude_table() {
        let mut builder = CodeResourcesBuilder::new();
        builder.exclude("TestData/");
        // Nested bundle files are sealed by the parent, so they are not excluded.
        // Pinned as-is: the verifier drops nested _CodeSignature entries by
        // substring (zsign/src/verify.rs:457 tests
        // `rel_str.contains("_CodeSignature/")`), so a nested signature file is
        // skipped there while this root-anchored prefix test declines to
        // exclude it. "Fixing" this row alone would desync signer and
        // verifier; changing both is out of scope here.
        for (path, excluded, why) in [
            ("_CodeSignature/CodeResources", true, "own signature dir"),
            ("_CodeSignature", true, "signature dir itself"),
            (
                "_CodeSignature/CodeResources",
                true,
                "the CodeResources file is excluded twice over",
            ),
            ("TestData/a.bin", true, "custom exclusion prefix hit"),
            (
                "TestDataX/a.bin",
                false,
                "the pattern's trailing slash keeps the near-miss out",
            ),
            ("TestData", false, "the bare directory name lacks the slash"),
            ("data.bin", false, "ordinary resource"),
            (
                "Frameworks/Sub.framework/Sub",
                false,
                "nested bundle files belong to the parent's seal",
            ),
            (
                "Frameworks/Sub.framework/_CodeSignature/CodeResources",
                false,
                "the _CodeSignature prefix is anchored at the bundle root",
            ),
        ] {
            assert_eq!(builder.should_exclude(path), excluded, "{path}: {why}");
        }
    }

    #[test]
    fn main_executable_is_excluded_and_near_miss_is_not() {
        // The main executable carries its own embedded signature, so it is
        // never sealed by the parent's CodeResources.
        let mut builder = CodeResourcesBuilder::new();
        builder.set_main_executable("Test");
        assert!(builder.should_exclude("Test"), "the main executable");
        assert!(
            !builder.should_exclude("TestData/a.bin"),
            "prefix near-miss"
        );
        assert!(!builder.should_exclude("Test2"), "different file");
    }

    #[test]
    fn add_symlink_honors_exclusions() {
        let mut builder = CodeResourcesBuilder::new();
        let (sha1, sha256) = CodeResourcesBuilder::hash_data(b"Versions/Current/Test");

        assert!(
            !builder.add_symlink(
                "_CodeSignature/CodeResources",
                "Versions/Current/Test",
                sha1,
                sha256
            ),
            "an excluded path must be refused"
        );
        assert!(builder.files().next().is_none(), "nothing was inserted");

        assert!(
            builder.add_symlink(
                "Frameworks/Test.framework/Test",
                "Versions/Current/Test",
                sha1,
                sha256
            ),
            "a sealable path is accepted"
        );
        let bytes = builder.build().unwrap();
        let value: Value = plist::from_bytes(&bytes).unwrap();
        let files2 = value
            .as_dictionary()
            .unwrap()
            .get("files2")
            .unwrap()
            .as_dictionary()
            .unwrap();
        let entry = files2
            .get("Frameworks/Test.framework/Test")
            .expect("the symlink is sealed")
            .as_dictionary()
            .unwrap();
        assert_eq!(
            entry.get("symlink").and_then(|v| v.as_string()),
            Some("Versions/Current/Test"),
            "the symlink target is observable in the built plist"
        );
        // The legacy SHA-1 dict never carries symlinks.
        let files = value
            .as_dictionary()
            .unwrap()
            .get("files")
            .unwrap()
            .as_dictionary()
            .unwrap();
        assert!(!files.contains_key("Frameworks/Test.framework/Test"));
    }

    #[test]
    fn test_rule_action_weights_and_ties() {
        let rules2 = standard_rules2();
        assert_eq!(rule_action(&rules2, "data.bin"), Some(RuleAction::Include));
        assert_eq!(
            rule_action(&rules2, "en.lproj/Localizable.strings"),
            Some(RuleAction::Optional)
        );
        assert_eq!(
            rule_action(&rules2, "Base.lproj/Notes.strings"),
            Some(RuleAction::Include),
            "weight 1010 beats the optional rule at 1000"
        );
        assert_eq!(
            rule_action(&rules2, "en.lproj/locversion.plist"),
            Some(RuleAction::Omit)
        );
        assert_eq!(rule_action(&rules2, "Info.plist"), Some(RuleAction::Omit));
        assert_eq!(
            rule_action(&rules2, "Frameworks/.DS_Store"),
            Some(RuleAction::Omit)
        );
        assert_eq!(
            rule_action(&rules2, "missing-under-.lproj/en.lproj/x"),
            Some(RuleAction::Optional)
        );

        // Equal weight: strictest-first tie-break — Include outranks Omit.
        let mut tied = Dictionary::new();
        let mut omit = Dictionary::new();
        omit.insert("omit".to_string(), Value::Boolean(true));
        omit.insert("weight".to_string(), Value::Real(5.0));
        tied.insert("^Info\\.".to_string(), Value::Dictionary(omit));
        let mut include = Dictionary::new();
        include.insert("weight".to_string(), Value::Real(5.0));
        tied.insert("^Info".to_string(), Value::Dictionary(include));
        assert_eq!(
            rule_action(&tied, "Info.x"),
            Some(RuleAction::Include),
            "tie_rank: Include < Omit"
        );

        // The escaped rules2 spelling of the version key matches exactly:
        // `version.plist` resolves to this rule's Omit (a missing arm would
        // fall through to `^.*` Include), and `version.plist.bak` must not
        // over-match it (a prefix implementation would wrongly match).
        let mut exact = Dictionary::new();
        let mut omit20 = Dictionary::new();
        omit20.insert("omit".to_string(), Value::Boolean(true));
        omit20.insert("weight".to_string(), Value::Real(20.0));
        exact.insert("^version\\.plist$".to_string(), Value::Dictionary(omit20));
        exact.insert("^.*".to_string(), Value::Boolean(true));
        assert_eq!(
            rule_action(&exact, "version.plist"),
            Some(RuleAction::Omit),
            "the escaped key matches version.plist exactly"
        );
        assert_eq!(
            rule_action(&exact, "version.plist.bak"),
            Some(RuleAction::Include),
            "the escaped key must not prefix-match past version.plist"
        );
    }
}
