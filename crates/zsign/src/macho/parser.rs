//! Mach-O file parsing and manipulation using goblin

use crate::{Error, Result};
use goblin::mach::{Mach, MachO};
use goblin::mach::header::{MH_EXECUTE, MH_MAGIC_64, MH_CIGAM_64};
use goblin::mach::load_command::CommandVariant;
use std::path::Path;

/// Represents a parsed Mach-O file
pub struct MachOFile {
    /// Raw file data
    data: Vec<u8>,
    /// Is FAT binary
    is_fat: bool,
    /// Architecture slices
    slices: Vec<ArchSlice>,
}

/// A single architecture slice
pub struct ArchSlice {
    /// Offset in file
    pub offset: usize,
    /// Size of slice
    pub size: usize,
    /// CPU type
    pub cpu_type: u32,
    /// Is 64-bit
    pub is_64: bool,
    /// Is executable (MH_EXECUTE)
    pub is_executable: bool,
    /// Code signature offset (if exists)
    pub code_sig_offset: Option<u32>,
    /// Code signature size
    pub code_sig_size: Option<u32>,
    /// __TEXT segment size (for execSegLimit)
    pub text_segment_size: u64,
    /// Code length (to signature or end)
    pub code_length: usize,
}

impl MachOFile {
    /// Open and parse a Mach-O file
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let data = std::fs::read(path.as_ref())?;
        Self::parse(data)
    }

    /// Parse Mach-O from bytes
    pub fn parse(data: Vec<u8>) -> Result<Self> {
        let mach = Mach::parse(&data)
            .map_err(|e| Error::MachO(format!("Failed to parse: {}", e)))?;

        let (is_fat, slices) = match mach {
            Mach::Binary(macho) => {
                let slice = Self::parse_single(&data, &macho, 0)?;
                (false, vec![slice])
            }
            Mach::Fat(fat) => {
                let mut slices = Vec::new();
                for (i, arch) in fat.iter_arches().enumerate() {
                    let arch = arch.map_err(|e| Error::MachO(format!("Fat arch {}: {}", i, e)))?;
                    let offset = arch.offset as usize;
                    let size = arch.size as usize;
                    let slice_data = &data[offset..offset + size];

                    let macho = MachO::parse(slice_data, 0)
                        .map_err(|e| Error::MachO(format!("Slice {}: {}", i, e)))?;

                    let mut slice = Self::parse_single(&data, &macho, offset)?;
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
        let cpu_type = macho.header.cputype as u32;

        let mut code_sig_offset = None;
        let mut code_sig_size = None;
        let mut text_segment_size = 0u64;

        for lc in &macho.load_commands {
            match lc.command {
                CommandVariant::CodeSignature(cs) => {
                    code_sig_offset = Some(cs.dataoff);
                    code_sig_size = Some(cs.datasize);
                }
                CommandVariant::Segment64(ref seg) => {
                    if seg.segname.starts_with(b"__TEXT") {
                        text_segment_size = seg.vmsize;
                    }
                }
                CommandVariant::Segment32(ref seg) => {
                    if seg.segname.starts_with(b"__TEXT") {
                        text_segment_size = seg.vmsize as u64;
                    }
                }
                _ => {}
            }
        }

        // Code length is up to signature or end of slice
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
            &data[base_offset..base_offset + end]
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
        })
    }

    /// Get raw data
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Is FAT binary
    pub fn is_fat(&self) -> bool {
        self.is_fat
    }

    /// Get architecture slices
    pub fn slices(&self) -> &[ArchSlice] {
        &self.slices
    }

    /// Get code bytes for a slice (up to signature)
    pub fn code_bytes(&self, slice: &ArchSlice) -> &[u8] {
        let start = slice.offset;
        let end = start + slice.code_length;
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
