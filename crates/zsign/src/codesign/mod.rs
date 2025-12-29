//! Code signing structures and constants for iOS/macOS binaries.
//!
//! This module provides the core building blocks for creating Apple code signatures:
//!
//! - [`CodeDirectoryBuilder`] - Builds CodeDirectory blobs containing code page hashes
//! - [`SuperBlobBuilder`] - Assembles the top-level signature container
//! - [`der`] - DER encoding for entitlements
//! - [`constants`] - Magic numbers, slot types, and flags
//!
//! ## Code Signature Structure
//!
//! Apple code signatures use a hierarchical blob format:
//!
//! ```text
//! SuperBlob (0xfade0cc0)
//! ├── CodeDirectory SHA-1 (slot 0x0000)
//! ├── Requirements (slot 0x0002)
//! ├── Entitlements XML (slot 0x0005)
//! ├── Entitlements DER (slot 0x0007)
//! ├── CodeDirectory SHA-256 (slot 0x1000)
//! └── CMS Signature (slot 0x10000)
//! ```
//!
//! # Examples
//!
//! ```no_run
//! use zsign::codesign::{CodeDirectoryBuilder, SuperBlobBuilder};
//!
//! let code_bytes = vec![0u8; 8192]; // executable code
//!
//! // Build CodeDirectories for the executable
//! let cd_sha1 = CodeDirectoryBuilder::new("com.example.app", &code_bytes)
//!     .team_id("TEAM123456")
//!     .build_sha1();
//! let cd_sha256 = CodeDirectoryBuilder::new("com.example.app", &code_bytes)
//!     .team_id("TEAM123456")
//!     .build_sha256();
//!
//! // Assemble the SuperBlob
//! let superblob = SuperBlobBuilder::new()
//!     .code_directory_sha1(cd_sha1)
//!     .code_directory_sha256(cd_sha256)
//!     .build();
//! ```

pub mod code_directory;
pub mod constants;
pub mod der;
pub mod superblob;

pub use code_directory::CodeDirectoryBuilder;
pub use superblob::{
    build_der_entitlements_blob, build_entitlements_blob, build_requirements_blob,
    build_signature_blob, build_superblob, BlobEntry, SuperBlobBuilder,
};
