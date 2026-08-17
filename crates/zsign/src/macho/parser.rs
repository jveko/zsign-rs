//! Mach-O binary parsing.
//!
//! Provides types and functions for parsing single-architecture and FAT/Universal
//! Mach-O binaries from files or in-memory data.
//!
//! # Examples
//!
//! ```no_run
//! use zsign_rs::macho::MachOFile;
//!
//! let macho = MachOFile::open("path/to/binary")?;
//! for slice in macho.slices() {
//!     println!("CPU type: {}, 64-bit: {}", slice.cpu_type, slice.is_64);
//! }
//! # Ok::<(), zsign_rs::Error>(())
//! ```

use crate::Result;
use std::path::Path;

pub use zsign_core::macho::parser::ArchSlice;

/// A parsed Mach-O binary with filesystem support.
pub struct MachOFile {
    inner: zsign_core::macho::MachOFile,
}

impl MachOFile {
    /// Opens and parses a Mach-O file.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let data = std::fs::read(path.as_ref())?;
        Self::parse(data)
    }

    /// Parses a Mach-O binary from in-memory data.
    pub fn parse(data: Vec<u8>) -> Result<Self> {
        Ok(Self {
            inner: zsign_core::macho::MachOFile::parse(data)?,
        })
    }

    /// Returns a reference to the underlying core MachOFile.
    pub fn as_core(&self) -> &zsign_core::macho::MachOFile {
        &self.inner
    }

    pub fn data(&self) -> &[u8] {
        self.inner.data()
    }
    pub fn is_fat(&self) -> bool {
        self.inner.is_fat()
    }
    pub fn slices(&self) -> &[ArchSlice] {
        self.inner.slices()
    }
    pub fn code_bytes(&self, slice: &ArchSlice) -> &[u8] {
        self.inner.code_bytes(slice)
    }
    pub fn slice_data(&self, slice: &ArchSlice) -> &[u8] {
        self.inner.slice_data(slice)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_minimal() {
        let result = MachOFile::parse(vec![0; 100]);
        assert!(result.is_err());
    }
}
