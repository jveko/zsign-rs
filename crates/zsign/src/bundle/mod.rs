//! App bundle handling for iOS code signing.
//!
//! This module provides functionality to:
//! - Walk bundle directories and hash files
//! - Generate CodeResources plist with file hashes
//! - Handle nested bundles (frameworks, plugins)
//!
//! # Overview
//!
//! iOS app bundles require a `_CodeSignature/CodeResources` file containing
//! cryptographic hashes of all bundle contents. This module generates that file
//! using [`CodeResourcesBuilder`].
//!
//! # CodeResources Plist Structure
//!
//! The generated plist contains four top-level keys:
//!
//! | Key | Description |
//! |-----|-------------|
//! | `files` | Legacy SHA-1 hashes (for older iOS versions) |
//! | `files2` | Modern SHA-1 + SHA-256 hashes with metadata |
//! | `rules` | Legacy inclusion/exclusion patterns |
//! | `rules2` | Modern inclusion/exclusion patterns |
//!
//! # Examples
//!
//! ```no_run
//! use zsign_rs::bundle::CodeResourcesBuilder;
//!
//! let mut builder = CodeResourcesBuilder::new("/path/to/MyApp.app")?;
//! builder.scan()?;
//! let plist_bytes = builder.build()?;
//! # Ok::<(), zsign_rs::Error>(())
//! ```

pub mod code_resources;

pub use code_resources::CodeResourcesBuilder;

use std::path::Path;

/// Directories that Apple documents as nested-code locations
/// ("Placing content in a bundle"; TN2206 "Nested Code" Table 3).
/// `Extensions` is not Apple-documented; it is kept because upstream
/// zsign treats it as an app-extension location.
const NESTED_CODE_LOCATIONS: [&str; 7] = [
    "Frameworks",
    "SharedFrameworks",
    "PlugIns",
    "XPCServices",
    "Watch",
    "AppClips",
    "Extensions",
];

/// `CFBundlePackageType` values that identify a bundle container
/// (Bundle Programming Guide: `APPL`, `FMWK`; "Creating XPC Services":
/// `XPC!`). `BNDL` is excluded: it is CFBundle's fallback default.
const BUNDLE_PACKAGE_TYPES: [&str; 3] = ["APPL", "FMWK", "XPC!"];

/// True when `path` is a nested-code bundle directory.
///
/// A directory qualifies when it carries a legacy bundle extension
/// (`.app`, `.framework`, `.appex`), or when its child `Info.plist`
/// declares bundle markers (`CFBundleIdentifier` + `CFBundleExecutable`)
/// and it sits in a documented nested-code location or declares a
/// recognized `CFBundlePackageType`. Detection is best-effort: an
/// unreadable or unparseable `Info.plist` just means "not a bundle".
pub fn is_nested_bundle_dir(path: &Path) -> bool {
    if let Some(ext) = path.extension() {
        if matches!(
            ext.to_string_lossy().to_lowercase().as_str(),
            "app" | "framework" | "appex"
        ) {
            return true;
        }
    }

    let Some(markers) = bundle_markers(path) else {
        return false;
    };
    if !markers.0 || !markers.1 {
        return false;
    }

    let parent_is_location = path
        .parent()
        .and_then(|p| p.file_name())
        .map(|n| {
            let parent = n.to_string_lossy();
            NESTED_CODE_LOCATIONS
                .iter()
                .any(|location| location.eq_ignore_ascii_case(parent.as_ref()))
        })
        .unwrap_or(false);
    if parent_is_location {
        return true;
    }

    markers
        .2
        .is_some_and(|package_type| BUNDLE_PACKAGE_TYPES.contains(&package_type.as_str()))
}

/// `(has non-empty CFBundleIdentifier, has non-empty CFBundleExecutable,
/// CFBundlePackageType)` from `path/Info.plist`, or `None` when the file is
/// missing or unparseable.
fn bundle_markers(path: &Path) -> Option<(bool, bool, Option<String>)> {
    let data = std::fs::read(path.join("Info.plist")).ok()?;
    let value = plist::from_bytes::<plist::Value>(&data).ok()?;
    let dict = value.as_dictionary()?;
    let non_empty = |key: &str| {
        dict.get(key)
            .and_then(|v| v.as_string())
            .is_some_and(|s| !s.is_empty())
    };
    Some((
        non_empty("CFBundleIdentifier"),
        non_empty("CFBundleExecutable"),
        dict.get("CFBundlePackageType")
            .and_then(|v| v.as_string())
            .map(str::to_owned),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;

    fn write_info_plist(dir: &Path, body: &str) {
        fs::write(
            dir.join("Info.plist"),
            format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>{body}</dict></plist>"#
            ),
        )
        .unwrap();
    }

    const MARKERS: &str = "<key>CFBundleIdentifier</key><string>com.test.x</string>\
         <key>CFBundleExecutable</key><string>X</string>";

    #[test]
    fn nested_bundle_dir_matches_every_arm_and_no_more() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();

        // Legacy extension arm: matches with no Info.plist at all.
        let fw = root.join("Loose.framework");
        fs::create_dir_all(&fw).unwrap();
        assert!(is_nested_bundle_dir(&fw));

        // Location arm: a plain directory under Frameworks/ is not code…
        let plain = root.join("Frameworks").join("Plain");
        fs::create_dir_all(&plain).unwrap();
        assert!(!is_nested_bundle_dir(&plain));
        // …but a marker-complete container there is.
        write_info_plist(&plain, MARKERS);
        assert!(is_nested_bundle_dir(&plain));

        // Markers alone, outside documented locations, without a
        // recognized package type: not nested code.
        let widget = root.join("Resources").join("Widget");
        fs::create_dir_all(&widget).unwrap();
        write_info_plist(&widget, MARKERS);
        assert!(!is_nested_bundle_dir(&widget));

        // Package-type arm: a renamed XPC container is recognized anywhere.
        let renamed = root.join("Whatever");
        fs::create_dir_all(&renamed).unwrap();
        write_info_plist(
            &renamed,
            &format!("{MARKERS}<key>CFBundlePackageType</key><string>XPC!</string>"),
        );
        assert!(is_nested_bundle_dir(&renamed));

        // BNDL is CFBundle's fallback default: never a nested-code signal.
        let bndl = root.join("Fallback");
        fs::create_dir_all(&bndl).unwrap();
        write_info_plist(
            &bndl,
            &format!("{MARKERS}<key>CFBundlePackageType</key><string>BNDL</string>"),
        );
        assert!(!is_nested_bundle_dir(&bndl));

        // Markers gated: location without Info.plist is not nested code.
        let no_plist = root.join("PlugIns").join("Thing");
        fs::create_dir_all(&no_plist).unwrap();
        assert!(!is_nested_bundle_dir(&no_plist));
    }
}
