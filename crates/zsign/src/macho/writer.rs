//! Mach-O binary writer for embedding code signatures.
//!
//! This module provides functionality to modify Mach-O binaries and embed
//! code signatures. It handles:
//! - Finding or creating LC_CODE_SIGNATURE load command
//! - Updating __LINKEDIT segment to include the signature
//! - Appending the SuperBlob signature to the binary
//! - FAT/Universal binary support with per-architecture signing

use crate::{Error, Result};
use goblin::mach::fat::FatArch;
use goblin::mach::header::{MH_CIGAM_64, MH_MAGIC_64};
use goblin::mach::load_command::{CommandVariant, LinkeditDataCommand, SegmentCommand64};
use goblin::mach::{Mach, MachO, MultiArch};
use std::fs;
use std::path::Path;

use super::signer::SignedSlice;

/// Load command type for LC_CODE_SIGNATURE
const LC_CODE_SIGNATURE: u32 = 0x1d;

/// Size of LC_CODE_SIGNATURE command
const LINKEDIT_DATA_COMMAND_SIZE: u32 = 16;

/// Writes a signed Mach-O binary with the signature embedded.
///
/// This function takes the original binary data and a signature blob,
/// then produces a new binary with:
/// 1. Updated LC_CODE_SIGNATURE load command pointing to the signature
/// 2. Updated __LINKEDIT segment to include the signature
/// 3. The signature appended at the end of the file
///
/// Supports both single-architecture and FAT/Universal binaries.
///
/// # Arguments
///
/// * `input_path` - Path to the input Mach-O binary
/// * `output_path` - Path for the output signed binary
/// * `signature` - The SuperBlob signature data to embed
///
/// # Errors
///
/// Returns an error if:
/// - The input file cannot be read
/// - The binary is not a valid Mach-O
/// - There is no space for LC_CODE_SIGNATURE in the load commands
/// - The output file cannot be written
pub fn write_signed_macho(
    input_path: impl AsRef<Path>,
    output_path: impl AsRef<Path>,
    signature: &[u8],
) -> Result<()> {
    let data = fs::read(input_path.as_ref())?;
    let output = embed_signature(&data, signature)?;
    fs::write(output_path.as_ref(), output)?;
    Ok(())
}

/// Writes a signed Mach-O binary in place.
///
/// This is a convenience function that reads a binary, embeds the signature,
/// and writes it back to the same path.
///
/// # Arguments
///
/// * `binary_path` - Path to the Mach-O binary to sign in place
/// * `signature` - The SuperBlob signature data to embed
pub fn write_signed_macho_in_place(binary_path: impl AsRef<Path>, signature: &[u8]) -> Result<()> {
    let data = fs::read(binary_path.as_ref())?;
    let output = embed_signature(&data, signature)?;
    fs::write(binary_path.as_ref(), output)?;
    Ok(())
}

/// Embeds a code signature into Mach-O binary data.
///
/// For single-architecture binaries, embeds the signature directly.
/// For FAT/Universal binaries, this function requires the signature for the first
/// slice only. Use `embed_signature_fat` for full FAT binary support.
///
/// Returns a new Vec<u8> containing the modified binary with the signature embedded.
pub fn embed_signature(data: &[u8], signature: &[u8]) -> Result<Vec<u8>> {
    let mach =
        Mach::parse(data).map_err(|e| Error::MachO(format!("Failed to parse Mach-O: {}", e)))?;

    match mach {
        Mach::Binary(macho) => embed_signature_single(data, &macho, signature),
        Mach::Fat(fat) => {
            // For backwards compatibility, sign only the first slice
            let first_arch = fat
                .iter_arches()
                .next()
                .ok_or_else(|| Error::MachO("Empty FAT binary".into()))?
                .map_err(|e| Error::MachO(format!("Failed to read FAT arch: {}", e)))?;

            let signed_slice = SignedSlice {
                slice_index: 0,
                offset: first_arch.offset as usize,
                original_size: first_arch.size as usize,
                signature: signature.to_vec(),
            };

            embed_signature_fat_impl(data, &fat, &[signed_slice])
        }
    }
}

/// Embeds code signatures into a FAT/Universal binary for all architecture slices.
///
/// Each slice in the FAT binary is signed independently. The FAT header offsets
/// are recalculated to account for size changes due to embedded signatures.
///
/// # Arguments
///
/// * `data` - The original FAT binary data
/// * `signed_slices` - Signatures for each architecture slice (from `sign_macho_all_slices`)
///
/// # Returns
///
/// A new `Vec<u8>` containing the modified FAT binary with all signatures embedded.
pub fn embed_signature_fat(data: &[u8], signed_slices: &[SignedSlice]) -> Result<Vec<u8>> {
    let mach =
        Mach::parse(data).map_err(|e| Error::MachO(format!("Failed to parse Mach-O: {}", e)))?;

    match mach {
        Mach::Binary(macho) => {
            if signed_slices.is_empty() {
                return Err(Error::MachO("No signed slices provided".into()));
            }
            embed_signature_single(data, &macho, &signed_slices[0].signature)
        }
        Mach::Fat(fat) => embed_signature_fat_impl(data, &fat, signed_slices),
    }
}

/// Implementation of FAT binary signature embedding.
fn embed_signature_fat_impl(
    data: &[u8],
    fat: &MultiArch,
    signed_slices: &[SignedSlice],
) -> Result<Vec<u8>> {
    // Collect architecture information
    let arches: Vec<FatArch> = fat
        .iter_arches()
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| Error::MachO(format!("Failed to read FAT arches: {}", e)))?;

    if arches.is_empty() {
        return Err(Error::MachO("Empty FAT binary".into()));
    }

    // Sign each slice and collect the results
    let mut signed_slice_data: Vec<Vec<u8>> = Vec::with_capacity(arches.len());

    for (i, arch) in arches.iter().enumerate() {
        let offset = arch.offset as usize;
        let size = arch.size as usize;
        let slice_data = &data[offset..offset + size];

        // Find the corresponding signed slice
        let signature = signed_slices
            .iter()
            .find(|s| s.slice_index == i)
            .map(|s| s.signature.as_slice())
            .unwrap_or(&[]);

        if signature.is_empty() {
            // No signature for this slice, keep it as-is
            signed_slice_data.push(slice_data.to_vec());
        } else {
            // Parse and sign this slice
            let macho = MachO::parse(slice_data, 0)
                .map_err(|e| Error::MachO(format!("Failed to parse slice {}: {}", i, e)))?;

            let signed = embed_signature_single(slice_data, &macho, signature)?;
            signed_slice_data.push(signed);
        }
    }

    // Calculate new offsets with proper alignment
    // FAT header: 8 bytes + (20 bytes per arch)
    let fat_header_size = 8 + (arches.len() * 20);

    // Start slices after header, aligned to page boundary
    let mut current_offset = align_to(fat_header_size, 0x4000);
    let mut new_offsets: Vec<(u32, u32)> = Vec::with_capacity(arches.len());

    for (i, signed_data) in signed_slice_data.iter().enumerate() {
        // Align to the arch's specified alignment (usually page size)
        let alignment = 1u32 << arches[i].align;
        current_offset = align_to(current_offset, alignment as usize);

        new_offsets.push((current_offset as u32, signed_data.len() as u32));
        current_offset += signed_data.len();
    }

    // Build the new FAT binary
    let total_size = current_offset;
    let mut output = vec![0u8; total_size];

    // Write FAT header (always big-endian)
    // Magic: 0xCAFEBABE
    output[0..4].copy_from_slice(&0xCAFEBABEu32.to_be_bytes());
    // Number of architectures
    output[4..8].copy_from_slice(&(arches.len() as u32).to_be_bytes());

    // Write fat_arch entries
    for (i, arch) in arches.iter().enumerate() {
        let entry_offset = 8 + (i * 20);
        let (new_offset, new_size) = new_offsets[i];

        // cputype
        write_u32_be(&mut output, entry_offset, arch.cputype as u32);
        // cpusubtype
        write_u32_be(&mut output, entry_offset + 4, arch.cpusubtype as u32);
        // offset (new)
        write_u32_be(&mut output, entry_offset + 8, new_offset);
        // size (new)
        write_u32_be(&mut output, entry_offset + 12, new_size);
        // align
        write_u32_be(&mut output, entry_offset + 16, arch.align);
    }

    // Write each signed slice at its new offset
    for (i, signed_data) in signed_slice_data.iter().enumerate() {
        let (offset, _) = new_offsets[i];
        output[offset as usize..offset as usize + signed_data.len()].copy_from_slice(signed_data);
    }

    Ok(output)
}

/// Writes a u32 in big-endian format.
fn write_u32_be(data: &mut [u8], offset: usize, value: u32) {
    data[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
}

/// Embeds signature into a single-architecture Mach-O binary.
fn embed_signature_single(data: &[u8], macho: &MachO, signature: &[u8]) -> Result<Vec<u8>> {
    let is_64 = macho.header.magic == MH_MAGIC_64 || macho.header.magic == MH_CIGAM_64;
    if !is_64 {
        return Err(Error::MachO(
            "32-bit Mach-O binaries not supported".into(),
        ));
    }

    // Find existing LC_CODE_SIGNATURE and __LINKEDIT segment
    let mut code_sig_cmd: Option<(usize, LinkeditDataCommand)> = None;
    let mut linkedit_cmd: Option<(usize, SegmentCommand64)> = None;
    let mut max_load_cmd_end: usize = 0;

    for lc in &macho.load_commands {
        let lc_end = lc.offset + lc.command.cmdsize();
        if lc_end > max_load_cmd_end {
            max_load_cmd_end = lc_end;
        }

        match &lc.command {
            CommandVariant::CodeSignature(cs) => {
                code_sig_cmd = Some((lc.offset, *cs));
            }
            CommandVariant::Segment64(seg) => {
                if seg.segname.starts_with(b"__LINKEDIT") {
                    linkedit_cmd = Some((lc.offset, *seg));
                }
            }
            _ => {}
        }
    }

    // Calculate the code length (everything before signature)
    let code_length = if let Some((_, cs)) = code_sig_cmd {
        cs.dataoff as usize
    } else {
        // Find the end of __LINKEDIT or end of last segment
        find_code_end(macho, data.len())
    };

    // Align signature offset to 16-byte boundary
    let sig_offset = align_to(code_length, 16);
    let sig_size = signature.len() as u32;

    // Create output buffer: code + padding + signature
    let mut output = Vec::with_capacity(sig_offset + signature.len());
    output.extend_from_slice(&data[..code_length]);

    // Add padding if needed
    while output.len() < sig_offset {
        output.push(0);
    }

    // Append signature
    output.extend_from_slice(signature);

    // Now we need to update the load commands in the output buffer
    if let Some((offset, _)) = code_sig_cmd {
        // Update existing LC_CODE_SIGNATURE
        update_linkedit_data_command(&mut output, offset, sig_offset as u32, sig_size)?;
    } else {
        // Need to add LC_CODE_SIGNATURE command
        add_code_signature_command(
            &mut output,
            macho,
            max_load_cmd_end,
            sig_offset as u32,
            sig_size,
        )?;
    }

    // Update __LINKEDIT segment to include the signature
    if let Some((offset, seg)) = linkedit_cmd {
        let linkedit_end = seg.fileoff + seg.filesize;
        let new_filesize = (sig_offset + signature.len()) as u64 - seg.fileoff;

        // Only update if signature extends beyond current __LINKEDIT
        if (sig_offset + signature.len()) as u64 > linkedit_end {
            update_linkedit_segment(&mut output, offset, new_filesize)?;
        }
    }

    Ok(output)
}

/// Finds the end of code (where signature should start) in a Mach-O binary.
fn find_code_end(macho: &MachO, file_size: usize) -> usize {
    let mut max_end: u64 = 0;

    for lc in &macho.load_commands {
        match &lc.command {
            CommandVariant::Segment64(seg) => {
                let seg_end = seg.fileoff + seg.filesize;
                if seg_end > max_end {
                    max_end = seg_end;
                }
            }
            CommandVariant::Segment32(seg) => {
                let seg_end = (seg.fileoff + seg.filesize) as u64;
                if seg_end > max_end {
                    max_end = seg_end;
                }
            }
            _ => {}
        }
    }

    if max_end == 0 {
        file_size
    } else {
        max_end as usize
    }
}

/// Updates an existing LC_CODE_SIGNATURE command with new offset and size.
fn update_linkedit_data_command(
    data: &mut [u8],
    offset: usize,
    dataoff: u32,
    datasize: u32,
) -> Result<()> {
    // LinkeditDataCommand structure:
    // u32 cmd
    // u32 cmdsize
    // u32 dataoff
    // u32 datasize

    let dataoff_offset = offset + 8;
    let datasize_offset = offset + 12;

    // Determine endianness from magic
    let is_big_endian = data.len() >= 4
        && (data[0..4] == [0xfe, 0xed, 0xfa, 0xce]
            || data[0..4] == [0xfe, 0xed, 0xfa, 0xcf]
            || data[0..4] == [0xca, 0xfe, 0xba, 0xbe]);

    write_u32(data, dataoff_offset, dataoff, is_big_endian);
    write_u32(data, datasize_offset, datasize, is_big_endian);

    Ok(())
}

/// Adds a new LC_CODE_SIGNATURE command to the Mach-O header.
fn add_code_signature_command(
    data: &mut [u8],
    macho: &MachO,
    load_commands_end: usize,
    dataoff: u32,
    datasize: u32,
) -> Result<()> {
    // Check if there's space for the new command
    // The load commands must fit within the first segment's file offset
    let first_segment_offset = find_first_segment_offset(macho);

    let new_cmd_size = LINKEDIT_DATA_COMMAND_SIZE as usize;
    let new_load_commands_end = load_commands_end + new_cmd_size;

    if new_load_commands_end > first_segment_offset {
        return Err(Error::MachO(
            "No space for LC_CODE_SIGNATURE in load commands area".into(),
        ));
    }

    // Determine endianness
    let is_big_endian = data.len() >= 4
        && (data[0..4] == [0xfe, 0xed, 0xfa, 0xce]
            || data[0..4] == [0xfe, 0xed, 0xfa, 0xcf]
            || data[0..4] == [0xca, 0xfe, 0xba, 0xbe]);

    // Write the new LC_CODE_SIGNATURE command at load_commands_end
    write_u32(data, load_commands_end, LC_CODE_SIGNATURE, is_big_endian);
    write_u32(
        data,
        load_commands_end + 4,
        LINKEDIT_DATA_COMMAND_SIZE,
        is_big_endian,
    );
    write_u32(data, load_commands_end + 8, dataoff, is_big_endian);
    write_u32(data, load_commands_end + 12, datasize, is_big_endian);

    // Update header's ncmds and sizeofcmds
    // For 64-bit: ncmds at offset 16, sizeofcmds at offset 20
    let ncmds_offset = 16;
    let sizeofcmds_offset = 20;

    let current_ncmds = read_u32(data, ncmds_offset, is_big_endian);
    let current_sizeofcmds = read_u32(data, sizeofcmds_offset, is_big_endian);

    write_u32(data, ncmds_offset, current_ncmds + 1, is_big_endian);
    write_u32(
        data,
        sizeofcmds_offset,
        current_sizeofcmds + LINKEDIT_DATA_COMMAND_SIZE,
        is_big_endian,
    );

    Ok(())
}

/// Finds the file offset of the first segment (where load commands must end).
fn find_first_segment_offset(macho: &MachO) -> usize {
    let mut min_offset: u64 = u64::MAX;

    for lc in &macho.load_commands {
        match &lc.command {
            CommandVariant::Segment64(seg) => {
                if seg.fileoff > 0 && seg.fileoff < min_offset {
                    min_offset = seg.fileoff;
                }
            }
            CommandVariant::Segment32(seg) => {
                if seg.fileoff > 0 && (seg.fileoff as u64) < min_offset {
                    min_offset = seg.fileoff as u64;
                }
            }
            _ => {}
        }
    }

    if min_offset == u64::MAX {
        // Default to 4KB if no segments found
        4096
    } else {
        min_offset as usize
    }
}

/// Updates the __LINKEDIT segment's filesize to include the signature.
fn update_linkedit_segment(data: &mut [u8], offset: usize, new_filesize: u64) -> Result<()> {
    // Segment64 structure:
    // u32 cmd (0)
    // u32 cmdsize (4)
    // char[16] segname (8)
    // u64 vmaddr (24)
    // u64 vmsize (32)
    // u64 fileoff (40)
    // u64 filesize (48)
    // ...

    let filesize_offset = offset + 48;
    let vmsize_offset = offset + 32;

    let is_big_endian = data.len() >= 4
        && (data[0..4] == [0xfe, 0xed, 0xfa, 0xce]
            || data[0..4] == [0xfe, 0xed, 0xfa, 0xcf]
            || data[0..4] == [0xca, 0xfe, 0xba, 0xbe]);

    write_u64(data, filesize_offset, new_filesize, is_big_endian);

    // Also update vmsize to match (page-aligned)
    let aligned_vmsize = align_to(new_filesize as usize, 0x4000) as u64;
    write_u64(data, vmsize_offset, aligned_vmsize, is_big_endian);

    Ok(())
}

/// Aligns a value up to the specified alignment.
fn align_to(value: usize, alignment: usize) -> usize {
    (value + alignment - 1) & !(alignment - 1)
}

/// Reads a u32 from a byte slice at the given offset.
fn read_u32(data: &[u8], offset: usize, big_endian: bool) -> u32 {
    let bytes: [u8; 4] = data[offset..offset + 4].try_into().unwrap();
    if big_endian {
        u32::from_be_bytes(bytes)
    } else {
        u32::from_le_bytes(bytes)
    }
}

/// Writes a u32 to a byte slice at the given offset.
fn write_u32(data: &mut [u8], offset: usize, value: u32, big_endian: bool) {
    let bytes = if big_endian {
        value.to_be_bytes()
    } else {
        value.to_le_bytes()
    };
    data[offset..offset + 4].copy_from_slice(&bytes);
}

/// Writes a u64 to a byte slice at the given offset.
fn write_u64(data: &mut [u8], offset: usize, value: u64, big_endian: bool) {
    let bytes = if big_endian {
        value.to_be_bytes()
    } else {
        value.to_le_bytes()
    };
    data[offset..offset + 8].copy_from_slice(&bytes);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_align_to() {
        assert_eq!(align_to(0, 16), 0);
        assert_eq!(align_to(1, 16), 16);
        assert_eq!(align_to(15, 16), 16);
        assert_eq!(align_to(16, 16), 16);
        assert_eq!(align_to(17, 16), 32);
        assert_eq!(align_to(100, 0x4000), 0x4000);
    }

    #[test]
    fn test_read_write_u32_le() {
        let mut data = vec![0u8; 8];
        write_u32(&mut data, 0, 0x12345678, false);
        assert_eq!(read_u32(&data, 0, false), 0x12345678);
        assert_eq!(&data[0..4], &[0x78, 0x56, 0x34, 0x12]);
    }

    #[test]
    fn test_read_write_u32_be() {
        let mut data = vec![0u8; 8];
        write_u32(&mut data, 0, 0x12345678, true);
        assert_eq!(read_u32(&data, 0, true), 0x12345678);
        assert_eq!(&data[0..4], &[0x12, 0x34, 0x56, 0x78]);
    }

    #[test]
    fn test_embed_signature_invalid_data() {
        let data = vec![0u8; 100];
        let signature = vec![0u8; 1000];
        let result = embed_signature(&data, &signature);
        assert!(result.is_err());
    }
}
