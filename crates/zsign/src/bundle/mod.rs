//! App bundle handling for iOS code signing
//!
//! This module provides functionality to:
//! - Walk bundle directories and hash files
//! - Generate CodeResources plist with file hashes
//! - Handle nested bundles (frameworks, plugins)

pub mod code_resources;

pub use code_resources::CodeResourcesBuilder;
