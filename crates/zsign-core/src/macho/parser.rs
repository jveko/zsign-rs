//! Mach-O binary parsing using goblin.
//!
//! Provides types and functions for parsing single-architecture and FAT/Universal
//! Mach-O binaries from in-memory data.
//!
//! # Key Types
//!
//! - [`MachOFile`] - Main entry point for parsing Mach-O binaries
//! - [`ArchSlice`] - Represents a single architecture within a binary
//!
//! # Examples
//!
//! ```ignore
//! use zsign_core::macho::MachOFile;
//!
//! let data = std::fs::read("path/to/binary")?;
//! let macho = MachOFile::parse(data)?;
//!
//! // Iterate architecture slices
//! for slice in macho.slices() {
//!     println!("CPU type: {}, 64-bit: {}", slice.cpu_type, slice.is_64);
//! }
//! # Ok::<(), zsign_core::Error>(())
//! ```

use crate::{Error, Result};
use goblin::mach::header::{MH_CIGAM_64, MH_EXECUTE, MH_MAGIC_64};
use goblin::mach::load_command::CommandVariant;
use goblin::mach::{Mach, MachO};

/// Pre-parsed Mach-O load command metadata.
///
/// Caches the offsets and values that writer functions need,
/// avoiding redundant `goblin::Mach::parse()` calls.
#[derive(Clone)]
pub struct MachOMetadata {
    /// Offset and data of the LC_CODE_SIGNATURE command, if present.
    /// `(offset, dataoff, datasize)`
    pub code_sig_cmd: Option<(usize, u32, u32)>,
    /// Offset and data of the __LINKEDIT segment command.
    /// `(offset, fileoff, vmsize, filesize)`
    pub linkedit_cmd: Option<(usize, u64, u64, u64)>,
    /// Byte offset after the last load command.
    pub max_load_cmd_end: usize,
    /// Byte offset of the first segment's file data.
    pub first_segment_offset: usize,
    /// Whether the binary is big-endian.
    pub is_big_endian: bool,
    /// Whether this is a 64-bit binary.
    pub is_64: bool,
}

/// A parsed Mach-O binary.
///
/// Handles both single-architecture and FAT/Universal binaries. For FAT binaries,
/// each architecture slice is accessible via [`slices()`](Self::slices).
///
/// # Creating a MachOFile
///
/// - [`MachOFile::parse`] - Parse from in-memory data
///
/// # Accessing Data
///
/// - [`data()`](Self::data) - Raw binary bytes
/// - [`slices()`](Self::slices) - Architecture slices
/// - [`code_bytes()`](Self::code_bytes) - Code region for signing
/// - [`slice_data()`](Self::slice_data) - Complete slice including signature area
pub struct MachOFile {
    data: Vec<u8>,
    is_fat: bool,
    slices: Vec<ArchSlice>,
}

/// A single architecture slice within a Mach-O binary.
///
/// For single-architecture binaries, offset is 0 and size is the file size.
/// For FAT binaries, offset and size describe the slice's position within the FAT container.
#[derive(Clone)]
pub struct ArchSlice {
    /// Byte offset of this slice within the file.
    pub offset: usize,
    /// Size of the slice in bytes.
    pub size: usize,
    /// Mach-O CPU type constant (e.g., `CPU_TYPE_ARM64`).
    pub cpu_type: u32,
    /// Whether this is a 64-bit architecture.
    pub is_64: bool,
    /// Whether this is an executable (`MH_EXECUTE`).
    pub is_executable: bool,
    /// File offset of the existing code signature, if present.
    pub code_sig_offset: Option<u32>,
    /// Size of the existing code signature, if present.
    pub code_sig_size: Option<u32>,
    /// Size of the `__TEXT` segment (used for `execSegLimit` in code signing).
    pub text_segment_size: u64,
    /// Length of code to be signed (excludes existing signature).
    pub code_length: usize,
    /// Cached load command metadata for writer functions.
    pub metadata: MachOMetadata,
}

impl MachOFile {
    /// Parses a Mach-O binary from in-memory data.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MachO`] if the binary format is invalid.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use zsign_core::macho::MachOFile;
    ///
    /// let data = std::fs::read("/path/to/binary")?;
    /// let macho = MachOFile::parse(data)?;
    /// # Ok::<(), zsign_core::Error>(())
    /// ```
    pub fn parse(data: Vec<u8>) -> Result<Self> {
        let bytes = &data[..];
        let mach = Mach::parse(bytes)
            .map_err(|e| Error::MachO(format!("Failed to parse: {}", e)))?;

        let (is_fat, slices) = match mach {
            Mach::Binary(macho) => {
                let slice = Self::parse_single(bytes, &macho, 0)?;
                (false, vec![slice])
            }
            Mach::Fat(fat) => {
                let mut slices = Vec::new();
                for (i, arch) in fat.iter_arches().enumerate() {
                    let arch = arch.map_err(|e| Error::MachO(format!("Fat arch {}: {}", i, e)))?;
                    let offset = arch.offset as usize;
                    let size = arch.size as usize;
                    let end = offset.checked_add(size)
                        .ok_or_else(|| Error::MachO(format!("FAT slice {}: offset overflow", i)))?;
                    if end > bytes.len() {
                        return Err(Error::MachO(format!("FAT slice {}: extends beyond file (offset={}, size={}, file_len={})", i, offset, size, bytes.len())));
                    }
                    let slice_data = &bytes[offset..end];

                    let macho = MachO::parse(slice_data, 0)
                        .map_err(|e| Error::MachO(format!("Slice {}: {}", i, e)))?;

                    let mut slice = Self::parse_single(bytes, &macho, offset)?;
                    slice.offset = offset;
                    slice.size = size;
                    slices.push(slice);
                }
                (true, slices)
            }
        };

        Ok(Self { data, is_fat, slices })
    }

    fn parse_single(data: &[u8], macho: &MachO, base_offset: usize) -> Result<ArchSlice> {
        let is_executable = macho.header.filetype == MH_EXECUTE;
        let is_64 = macho.header.magic == MH_MAGIC_64 || macho.header.magic == MH_CIGAM_64;
        let cpu_type = macho.header.cputype;

        let mut code_sig_offset = None;
        let mut code_sig_size = None;
        let mut text_segment_size = 0u64;

        let mut meta_code_sig_cmd = None;
        let mut meta_linkedit_cmd = None;
        let mut max_load_cmd_end: usize = 0;
        let mut first_segment_offset: u64 = u64::MAX;

        for lc in &macho.load_commands {
            let lc_end = lc.offset + lc.command.cmdsize();
            if lc_end > max_load_cmd_end {
                max_load_cmd_end = lc_end;
            }

            match lc.command {
                CommandVariant::CodeSignature(cs) => {
                    code_sig_offset = Some(cs.dataoff);
                    code_sig_size = Some(cs.datasize);
                    meta_code_sig_cmd = Some((lc.offset, cs.dataoff, cs.datasize));
                }
                CommandVariant::Segment64(ref seg) => {
                    if seg.segname.starts_with(b"__TEXT") {
                        text_segment_size = seg.vmsize;
                    }
                    if seg.segname.starts_with(b"__LINKEDIT") {
                        meta_linkedit_cmd = Some((lc.offset, seg.fileoff, seg.vmsize, seg.filesize));
                    }
                    if seg.fileoff > 0 && seg.fileoff < first_segment_offset {
                        first_segment_offset = seg.fileoff;
                    }
                }
                CommandVariant::Segment32(ref seg) => {
                    if seg.segname.starts_with(b"__TEXT") {
                        text_segment_size = seg.vmsize as u64;
                    }
                    if seg.fileoff > 0 && (seg.fileoff as u64) < first_segment_offset {
                        first_segment_offset = seg.fileoff as u64;
                    }
                }
                _ => {}
            }
        }

        let computed_first_segment_offset = if first_segment_offset == u64::MAX {
            4096
        } else {
            first_segment_offset as usize
        };

        let is_big_endian = data.len() >= 4
            && (data[base_offset..base_offset + 4] == [0xfe, 0xed, 0xfa, 0xce]
                || data[base_offset..base_offset + 4] == [0xfe, 0xed, 0xfa, 0xcf]
                || data[base_offset..base_offset + 4] == [0xca, 0xfe, 0xba, 0xbe]);

        let slice_data = if base_offset == 0 {
            data
        } else {
            let end = macho.load_commands.iter()
                .filter_map(|lc| {
                    match &lc.command {
                        CommandVariant::Segment64(seg) => {
                            Some((seg.fileoff + seg.filesize) as usize)
                        }
                        CommandVariant::Segment32(seg) => {
                            Some((seg.fileoff + seg.filesize) as usize)
                        }
                        _ => None
                    }
                })
                .max()
                .unwrap_or(data.len());
            let slice_end = base_offset.checked_add(end)
                .ok_or_else(|| Error::MachO(format!("parse_single: offset {} + size {} overflow", base_offset, end)))?;
            if slice_end > data.len() {
                return Err(Error::MachO(format!("parse_single: slice extends beyond data (offset={}, size={}, data_len={})", base_offset, end, data.len())));
            }
            &data[base_offset..slice_end]
        };

        let code_length = code_sig_offset
            .map(|o| o as usize)
            .unwrap_or(slice_data.len());

        Ok(ArchSlice {
            offset: 0,
            size: slice_data.len(),
            cpu_type,
            is_64,
            is_executable,
            code_sig_offset,
            code_sig_size,
            text_segment_size,
            code_length,
            metadata: MachOMetadata {
                code_sig_cmd: meta_code_sig_cmd,
                linkedit_cmd: meta_linkedit_cmd,
                max_load_cmd_end,
                first_segment_offset: computed_first_segment_offset,
                is_big_endian,
                is_64,
            },
        })
    }

    /// Returns the raw binary data.
    ///
    /// For FAT binaries, this includes all architecture slices.
    /// Use [`slice_data()`](Self::slice_data) to access individual slices.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Returns whether this is a FAT/Universal binary.
    ///
    /// FAT binaries contain multiple architecture slices (e.g., arm64 + x86_64).
    /// Use [`slices()`](Self::slices) to iterate over them.
    pub fn is_fat(&self) -> bool {
        self.is_fat
    }

    /// Returns the architecture slices.
    ///
    /// For single-architecture binaries, returns a single [`ArchSlice`].
    /// For FAT binaries, returns one slice per architecture.
    pub fn slices(&self) -> &[ArchSlice] {
        &self.slices
    }

    /// Returns the code bytes for a slice (excluding any existing signature).
    ///
    /// This is the portion of the binary that gets hashed during code signing.
    /// The returned bytes include the Mach-O header and load commands.
    ///
    /// See also: [`slice_data()`](Self::slice_data) for full slice including signature.
    pub fn code_bytes(&self, slice: &ArchSlice) -> &[u8] {
        let start = slice.offset;
        let end = start + slice.code_length;
        &self.data[start..end]
    }

    /// Returns the full slice data including any existing signature area.
    ///
    /// Use this when preparing a slice for re-signing.
    ///
    /// See also: [`code_bytes()`](Self::code_bytes) for code region only.
    pub fn slice_data(&self, slice: &ArchSlice) -> &[u8] {
        let start = slice.offset;
        let end = start + slice.size;
        &self.data[start..end]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_minimal() {
        // This will fail without a real Mach-O, but validates the API compiles
        let result = MachOFile::parse(vec![0; 100]);
        assert!(result.is_err()); // Expected: not a valid Mach-O
    }
}
