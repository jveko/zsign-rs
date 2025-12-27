//! Code signing structures and constants for iOS/macOS binaries

pub mod code_directory;
pub mod constants;
pub mod superblob;

pub use code_directory::CodeDirectoryBuilder;
pub use superblob::{
    build_adhoc_signature_blob, build_der_entitlements_blob, build_entitlements_blob,
    build_requirements_blob, build_signature_blob, build_superblob, BlobEntry, SuperBlobBuilder,
};
