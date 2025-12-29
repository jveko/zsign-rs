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
//! use zsign::bundle::CodeResourcesBuilder;
//!
//! let mut builder = CodeResourcesBuilder::new("/path/to/MyApp.app");
//! builder.scan()?;
//! let plist_bytes = builder.build()?;
//! # Ok::<(), zsign::Error>(())
//! ```

pub mod code_resources;

pub use code_resources::CodeResourcesBuilder;
