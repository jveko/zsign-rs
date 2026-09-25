//! Mach-O binary modification for embedding code signatures.
//!
//! Provides functionality to:
//! - Find or add `LC_CODE_SIGNATURE` load commands
//! - Update `__LINKEDIT` segment to include signature data
//! - Append SuperBlob signatures to binaries
//! - Handle FAT/Universal binaries with per-architecture signing
//!
//! # Key Functions
//!
//! - [`write_signed_macho`] - Write signed binary to a new file
//! - [`embed_signature`] - Embed signature into single-arch binary
//! - [`embed_signature_fat`] - Embed signatures into FAT binary
//! - [`prepare_code_for_signing`] - Prepare binary for hash computation

use crate::{Error, Result};
use goblin::mach::fat::FatArch;
use goblin::mach::header::{MH_CIGAM_64, MH_MAGIC_64};
use goblin::mach::load_command::{
    CommandVariant, LinkeditDataCommand, SegmentCommand64, LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB,
    LC_SEGMENT, LC_SEGMENT_64,
};
use goblin::mach::{Mach, MachO, MultiArch};

/// A signed architecture slice with its metadata.
///
/// Contains the complete signed binary data for a single architecture,
/// ready for embedding into a FAT binary using [`embed_signature_fat`]
/// or writing directly to disk.
#[derive(Debug, Clone)]
pub struct SignedSlice {
    /// Index of this slice within the FAT binary (0 for single-arch).
    pub slice_index: usize,
    /// Original byte offset within the FAT binary.
    pub offset: usize,
    /// Original size before signing.
    pub original_size: usize,
    /// Complete signed binary data for this slice.
    pub signed_data: Vec<u8>,
}

const LC_CODE_SIGNATURE: u32 = 0x1d;
const LINKEDIT_DATA_COMMAND_SIZE: u32 = 16;
const PAGE_SIZE: usize = 4096;
const CODE_SIGN_PADDING: usize = 16384;

/// End of the signature range currently declared by the LC_CODE_SIGNATURE
/// command, read from the buffer's own bytes at the command offset.
fn declared_signature_end(
    data: &[u8],
    lc_offset: usize,
    is_big_endian: bool,
) -> Result<Option<usize>> {
    let cmd_end = lc_offset
        .checked_add(16)
        .ok_or_else(|| Error::MachO("LC_CODE_SIGNATURE offset overflow".into()))?;
    if cmd_end > data.len() {
        return Err(Error::MachO(format!(
            "LC_CODE_SIGNATURE at {lc_offset} extends past the {}-byte buffer",
            data.len()
        )));
    }
    let dataoff = read_u32(data, lc_offset + 8, is_big_endian)? as usize;
    let datasize = read_u32(data, lc_offset + 12, is_big_endian)? as usize;
    Ok(Some(dataoff.checked_add(datasize).ok_or_else(|| {
        Error::MachO("LC_CODE_SIGNATURE: offset + size overflow".into())
    })?))
}

/// Calculates the binary length needed to accommodate a code signature.
///
/// Computes space for code hashes (SHA-1 and SHA-256) plus padding.
/// Used by [`realloc_code_sign_space`] to determine expansion size.
pub fn calculate_signature_space(code_length: usize) -> usize {
    let pages = code_length.div_ceil(PAGE_SIZE);
    let hash_slot_size = 20 + 32;
    let sig_space = align_to((pages + 1) * hash_slot_size, PAGE_SIZE);
    code_length + sig_space + CODE_SIGN_PADDING
}

/// Expands a Mach-O binary to accommodate a code signature.
///
/// Creates a new binary with an expanded `__LINKEDIT` segment and
/// updated `LC_CODE_SIGNATURE` load command.
///
/// For FAT binaries, use [`realloc_code_sign_space_slice`] on each slice.
///
/// # Errors
///
/// Returns [`Error::MachO`] if:
/// - The binary format is invalid
/// - The binary is 32-bit (not supported)
/// - No `__LINKEDIT` segment exists
/// - No space for `LC_CODE_SIGNATURE` in load commands area
pub fn realloc_code_sign_space(data: &[u8], code_length: usize) -> Result<Vec<u8>> {
    let mach =
        Mach::parse(data).map_err(|e| Error::MachO(format!("Failed to parse Mach-O: {}", e)))?;

    match mach {
        Mach::Binary(macho) => realloc_code_sign_space_single(data, &macho, code_length),
        Mach::Fat(_) => Err(Error::MachO(
            "Use realloc_code_sign_space_slice for FAT binaries".into(),
        )),
    }
}

/// Expands a single architecture slice to accommodate a code signature.
///
/// Use this for FAT binary slices. For single-arch binaries, use [`realloc_code_sign_space`].
///
/// # Errors
///
/// Returns [`Error::MachO`] if the slice is not a valid single-arch Mach-O.
pub fn realloc_code_sign_space_slice(slice_data: &[u8], code_length: usize) -> Result<Vec<u8>> {
    let mach = Mach::parse(slice_data)
        .map_err(|e| Error::MachO(format!("Failed to parse Mach-O slice: {}", e)))?;

    match mach {
        Mach::Binary(macho) => realloc_code_sign_space_single(slice_data, &macho, code_length),
        Mach::Fat(_) => Err(Error::MachO("Expected single-arch binary, got FAT".into())),
    }
}

fn realloc_code_sign_space_single(
    data: &[u8],
    macho: &MachO,
    code_length: usize,
) -> Result<Vec<u8>> {
    let is_64 = macho.header.magic == MH_MAGIC_64 || macho.header.magic == MH_CIGAM_64;
    let is_big_endian = super::parser::is_big_endian_macho(data, 0);

    if !is_64 {
        return Err(Error::MachO("32-bit Mach-O binaries not supported".into()));
    }

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
            CommandVariant::Segment64(seg) if seg.segname.starts_with(b"__LINKEDIT") => {
                linkedit_cmd = Some((lc.offset, *seg));
            }
            _ => {}
        }
    }
    if code_length > data.len() {
        return Err(Error::MachO(format!(
            "code_length {code_length} exceeds the {}-byte buffer",
            data.len()
        )));
    }
    let sig_offset = align_to(code_length, 16);
    let reserve = calculate_signature_space(code_length)
        .checked_sub(code_length)
        .ok_or_else(|| Error::MachO("signature space smaller than code length".into()))?;
    let formula_end = sig_offset
        .checked_add(reserve)
        .ok_or_else(|| Error::MachO("signature space overflow".into()))?;
    let declared_end = match code_sig_cmd {
        Some((lc_offset, _)) => declared_signature_end(data, lc_offset, is_big_endian)?,
        None => None,
    };
    let required = declared_end.map_or(formula_end, |end| end.max(formula_end));
    if required <= data.len() {
        return Ok(data.to_vec());
    }

    let mut output = data[..code_length].to_vec();

    if let Some((offset, seg)) = linkedit_cmd {
        let linkedit_fileoff = seg.fileoff as usize;
        let old_vmsize = seg.vmsize;
        let size_increase = required - data.len();
        let new_vmsize = align_to(old_vmsize as usize + size_increase, PAGE_SIZE) as u64;
        let new_filesize = required
            .checked_sub(linkedit_fileoff)
            .ok_or_else(|| Error::MachO("__LINKEDIT fileoff exceeds required length".into()))?
            as u64;

        write_u64(&mut output, offset + 32, new_vmsize, is_big_endian)?;
        write_u64(&mut output, offset + 48, new_filesize, is_big_endian)?;
    } else {
        return Err(Error::MachO("No __LINKEDIT segment found".into()));
    }

    let sig_datasize = checked_u32(required - code_length, "sig_datasize")?;

    if let Some((offset, _)) = code_sig_cmd {
        write_u32(
            &mut output,
            offset + 8,
            checked_u32(code_length, "code_length")?,
            is_big_endian,
        )?;
        write_u32(&mut output, offset + 12, sig_datasize, is_big_endian)?;
    } else {
        let first_segment_offset = find_first_segment_offset(macho);
        let new_cmd_size = LINKEDIT_DATA_COMMAND_SIZE as usize;
        let header_size = if is_64 { 32 } else { 28 };
        let sizeofcmds = read_u32(&output, 20, is_big_endian)? as usize;
        let insert_end = max_load_cmd_end
            .max(header_size + sizeofcmds)
            .checked_add(new_cmd_size)
            .ok_or_else(|| Error::MachO("load command end overflow".into()))?;
        if insert_end > first_segment_offset || insert_end > output.len() {
            return Err(Error::MachO(
                "No space for LC_CODE_SIGNATURE in load commands area".into(),
            ));
        }

        write_u32(
            &mut output,
            max_load_cmd_end,
            LC_CODE_SIGNATURE,
            is_big_endian,
        )?;
        write_u32(
            &mut output,
            max_load_cmd_end + 4,
            LINKEDIT_DATA_COMMAND_SIZE,
            is_big_endian,
        )?;
        write_u32(
            &mut output,
            max_load_cmd_end + 8,
            checked_u32(code_length, "code_length")?,
            is_big_endian,
        )?;
        write_u32(
            &mut output,
            max_load_cmd_end + 12,
            sig_datasize,
            is_big_endian,
        )?;

        let current_ncmds = read_u32(&output, 16, is_big_endian)?;
        let current_sizeofcmds = read_u32(&output, 20, is_big_endian)?;
        write_u32(&mut output, 16, current_ncmds + 1, is_big_endian)?;
        write_u32(
            &mut output,
            20,
            current_sizeofcmds + LINKEDIT_DATA_COMMAND_SIZE,
            is_big_endian,
        )?;
    }

    output.resize(required, 0);

    Ok(output)
}

/// Returns whether the binary has space for the signature without reallocation.
///
/// Check this before calling [`embed_signature`] to avoid unnecessary reallocation.
pub fn has_enough_signature_space(data: &[u8], code_length: usize, signature_size: usize) -> bool {
    let available_space = data.len().saturating_sub(code_length);
    available_space >= signature_size
}

/// Embeds a code signature into a Mach-O binary.
///
/// For FAT binaries with multiple architectures, use [`embed_signature_fat`].
///
/// # Errors
///
/// Returns [`Error::MachO`] if the binary format is invalid.
pub fn embed_signature(data: &[u8], signature: &[u8]) -> Result<Vec<u8>> {
    let mach =
        Mach::parse(data).map_err(|e| Error::MachO(format!("Failed to parse Mach-O: {}", e)))?;

    match mach {
        Mach::Binary(macho) => embed_signature_single(data, &macho, signature),
        Mach::Fat(fat) => {
            let first_arch = fat
                .iter_arches()
                .next()
                .ok_or_else(|| Error::MachO("Empty FAT binary".into()))?
                .map_err(|e| Error::MachO(format!("Failed to read FAT arch: {}", e)))?;

            let offset = first_arch.offset as usize;
            let size = first_arch.size as usize;
            let slice_data = &data[offset..offset + size];

            let first_macho = MachO::parse(slice_data, 0)
                .map_err(|e| Error::MachO(format!("Failed to parse first slice: {}", e)))?;

            let signed_slice = SignedSlice {
                slice_index: 0,
                offset: first_arch.offset as usize,
                original_size: first_arch.size as usize,
                signed_data: embed_signature_single(slice_data, &first_macho, signature)?,
            };

            embed_fat_from_signed_slices(data, &fat, &[signed_slice])
        }
    }
}

/// Embeds code signatures into a FAT/Universal binary.
///
/// Recalculates FAT header offsets to accommodate size changes from signatures.
/// Use [`sign_macho_all_slices`](super::signer::sign_macho_all_slices) to generate
/// the [`SignedSlice`] array.
///
/// # Errors
///
/// Returns [`Error::MachO`] if the binary format is invalid or slices are empty.
pub fn embed_signature_fat(data: &[u8], signed_slices: &[SignedSlice]) -> Result<Vec<u8>> {
    let mach =
        Mach::parse(data).map_err(|e| Error::MachO(format!("Failed to parse Mach-O: {}", e)))?;

    match mach {
        Mach::Binary(_) => {
            if signed_slices.is_empty() {
                return Err(Error::MachO("No signed slices provided".into()));
            }
            Ok(signed_slices[0].signed_data.clone())
        }
        Mach::Fat(fat) => embed_fat_from_signed_slices(data, &fat, signed_slices),
    }
}

fn embed_fat_from_signed_slices(
    data: &[u8],
    fat: &MultiArch,
    signed_slices: &[SignedSlice],
) -> Result<Vec<u8>> {
    let arches: Vec<FatArch> = fat
        .iter_arches()
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| Error::MachO(format!("Failed to read FAT arches: {}", e)))?;

    if arches.is_empty() {
        return Err(Error::MachO("Empty FAT binary".into()));
    }

    let mut slice_data_vec: Vec<Vec<u8>> = Vec::with_capacity(arches.len());

    for (i, arch) in arches.iter().enumerate() {
        if let Some(signed) = signed_slices.iter().find(|s| s.slice_index == i) {
            slice_data_vec.push(signed.signed_data.clone());
        } else {
            let offset = arch.offset as usize;
            let size = arch.size as usize;
            slice_data_vec.push(data[offset..offset + size].to_vec());
        }
    }

    let header_size = 8 + arches.len() * 20;
    let mut new_offsets: Vec<(u32, u32)> = Vec::with_capacity(arches.len());
    let mut current_offset = align_to(header_size, 0x4000) as u32;

    for slice_data in &slice_data_vec {
        let size = slice_data.len() as u32;
        new_offsets.push((current_offset, size));
        current_offset = align_to((current_offset + size) as usize, 0x4000) as u32;
    }

    let total_size = new_offsets.last().map(|(o, s)| *o + *s).unwrap_or(0) as usize;
    let mut output = vec![0u8; total_size];

    output[0..4].copy_from_slice(&0xCAFEBABEu32.to_be_bytes());
    output[4..8].copy_from_slice(&(arches.len() as u32).to_be_bytes());

    for (i, arch) in arches.iter().enumerate() {
        let entry_offset = 8 + (i * 20);
        let (new_offset, new_size) = new_offsets[i];

        write_u32_be(&mut output, entry_offset, arch.cputype);
        write_u32_be(&mut output, entry_offset + 4, arch.cpusubtype);
        write_u32_be(&mut output, entry_offset + 8, new_offset);
        write_u32_be(&mut output, entry_offset + 12, new_size);
        write_u32_be(&mut output, entry_offset + 16, arch.align);
    }

    for (i, slice_data) in slice_data_vec.iter().enumerate() {
        let (offset, _) = new_offsets[i];
        output[offset as usize..offset as usize + slice_data.len()].copy_from_slice(slice_data);
    }

    Ok(output)
}

fn write_u32_be(data: &mut [u8], offset: usize, value: u32) {
    data[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
}

fn embed_signature_single(data: &[u8], macho: &MachO, signature: &[u8]) -> Result<Vec<u8>> {
    let is_64 = macho.header.magic == MH_MAGIC_64 || macho.header.magic == MH_CIGAM_64;
    if !is_64 {
        return Err(Error::MachO("32-bit Mach-O binaries not supported".into()));
    }

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
            CommandVariant::Segment64(seg) if seg.segname.starts_with(b"__LINKEDIT") => {
                linkedit_cmd = Some((lc.offset, *seg));
            }
            _ => {}
        }
    }

    let code_length = if let Some((_, cs)) = code_sig_cmd {
        cs.dataoff as usize
    } else {
        find_code_end(macho, data.len())
    };

    let sig_offset = align_to(code_length, 16);
    let sig_size = checked_u32(signature.len(), "sig_size")?;

    let mut output = Vec::with_capacity(sig_offset + signature.len());
    output.extend_from_slice(&data[..code_length]);

    while output.len() < sig_offset {
        output.push(0);
    }

    output.extend_from_slice(signature);

    if let Some((offset, _)) = code_sig_cmd {
        update_linkedit_data_command(
            &mut output,
            offset,
            checked_u32(sig_offset, "sig_offset")?,
            sig_size,
        )?;
    } else {
        add_code_signature_command(
            &mut output,
            macho,
            max_load_cmd_end,
            checked_u32(sig_offset, "sig_offset")?,
            sig_size,
        )?;
    }

    if let Some((offset, seg)) = linkedit_cmd {
        let linkedit_end = seg.fileoff + seg.filesize;
        let new_filesize = (sig_offset + signature.len()) as u64 - seg.fileoff;

        if (sig_offset + signature.len()) as u64 > linkedit_end {
            update_linkedit_segment(&mut output, offset, new_filesize)?;
        }
    }

    Ok(output)
}

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

fn update_linkedit_data_command(
    data: &mut [u8],
    offset: usize,
    dataoff: u32,
    datasize: u32,
) -> Result<()> {
    let dataoff_offset = offset + 8;
    let datasize_offset = offset + 12;

    let is_big_endian = super::parser::is_big_endian_macho(data, 0);

    write_u32(data, dataoff_offset, dataoff, is_big_endian)?;
    write_u32(data, datasize_offset, datasize, is_big_endian)?;

    Ok(())
}

fn add_code_signature_command(
    data: &mut [u8],
    macho: &MachO,
    load_commands_end: usize,
    dataoff: u32,
    datasize: u32,
) -> Result<()> {
    let first_segment_offset = find_first_segment_offset(macho);

    let new_cmd_size = LINKEDIT_DATA_COMMAND_SIZE as usize;
    let new_load_commands_end = load_commands_end
        .checked_add(new_cmd_size)
        .ok_or_else(|| Error::MachO("load command end overflow".into()))?;
    if new_load_commands_end > first_segment_offset || new_load_commands_end > data.len() {
        return Err(Error::MachO(
            "No space for LC_CODE_SIGNATURE in load commands area".into(),
        ));
    }

    let is_big_endian = super::parser::is_big_endian_macho(data, 0);

    write_u32(data, load_commands_end, LC_CODE_SIGNATURE, is_big_endian)?;
    write_u32(
        data,
        load_commands_end + 4,
        LINKEDIT_DATA_COMMAND_SIZE,
        is_big_endian,
    )?;
    write_u32(data, load_commands_end + 8, dataoff, is_big_endian)?;
    write_u32(data, load_commands_end + 12, datasize, is_big_endian)?;

    let ncmds_offset = 16;
    let sizeofcmds_offset = 20;

    let current_ncmds = read_u32(data, ncmds_offset, is_big_endian)?;
    let current_sizeofcmds = read_u32(data, sizeofcmds_offset, is_big_endian)?;

    write_u32(data, ncmds_offset, current_ncmds + 1, is_big_endian)?;
    write_u32(
        data,
        sizeofcmds_offset,
        current_sizeofcmds + LINKEDIT_DATA_COMMAND_SIZE,
        is_big_endian,
    )?;

    Ok(())
}

/// Injects an `LC_LOAD_DYLIB` (or `LC_LOAD_WEAK_DYLIB` when `weak`) command into
/// a 64-bit Mach-O, returning a new binary with the command appended to the
/// load-command region.
///
/// # Errors
///
/// Returns [`Error::MachO`] if the input is not a 64-bit Mach-O or there is no
/// room for the command between the last load command and the first segment.
pub fn inject_dylib_command(input: &[u8], dylib_name: &str, weak: bool) -> Result<Vec<u8>> {
    const HEADER_SIZE: usize = 32;
    const DYLIB_FIXED_SIZE: usize = 24;
    const DEFAULT_FIRST_SEGMENT_OFFSET: usize = 4096;

    if input.len() < HEADER_SIZE {
        return Err(Error::MachO(
            "binary too short for a 64-bit Mach-O header".into(),
        ));
    }

    let magic = read_u32(input, 0, false)?;
    if magic != MH_MAGIC_64 && magic != MH_CIGAM_64 {
        return Err(Error::MachO("not a 64-bit Mach-O binary".into()));
    }
    let is_big_endian = super::parser::is_big_endian_macho(input, 0);

    let ncmds = read_u32(input, 16, is_big_endian)? as usize;

    // Walk the load commands to find the end of the region and the smallest
    // segment fileoff, which bounds where a new command may be inserted.
    let mut offset = HEADER_SIZE;
    let mut max_load_cmd_end = HEADER_SIZE;
    let mut first_segment_offset = usize::MAX;

    for _ in 0..ncmds {
        let cmd = read_u32(input, offset, is_big_endian)?;
        let cmdsize = read_u32(input, offset + 4, is_big_endian)? as usize;
        if cmdsize < 8 {
            return Err(Error::MachO(format!(
                "invalid load command cmdsize {} at offset {}",
                cmdsize, offset
            )));
        }
        let end = offset.checked_add(cmdsize).ok_or_else(|| {
            Error::MachO(format!(
                "load command cmdsize overflow at offset {}",
                offset
            ))
        })?;
        if end > input.len() {
            return Err(Error::MachO(format!(
                "load command at offset {} extends past end of binary",
                offset
            )));
        }

        match cmd {
            LC_SEGMENT_64 => {
                let fileoff = read_u64(input, offset + 40, is_big_endian)? as usize;
                let filesize = read_u64(input, offset + 48, is_big_endian)?;
                if fileoff > 0 && filesize > 0 && fileoff < first_segment_offset {
                    first_segment_offset = fileoff;
                }
                let nsects = read_u32(input, offset + 64, is_big_endian)? as usize;
                let sects_bytes = nsects
                    .checked_mul(80)
                    .ok_or_else(|| Error::MachO("section count overflow".into()))?;
                let sects_start = offset
                    .checked_add(72)
                    .ok_or_else(|| Error::MachO("section table overflow".into()))?;
                let sects_end = sects_start
                    .checked_add(sects_bytes)
                    .ok_or_else(|| Error::MachO("section table overflow".into()))?;
                let lc_end = offset
                    .checked_add(cmdsize)
                    .ok_or_else(|| Error::MachO("load command size overflow".into()))?;
                if sects_end > lc_end || sects_end > input.len() {
                    return Err(Error::MachO("section table exceeds load command".into()));
                }
                for i in 0..nsects {
                    let sect = sects_start
                        .checked_add(
                            i.checked_mul(80)
                                .ok_or_else(|| Error::MachO("section count overflow".into()))?,
                        )
                        .ok_or_else(|| Error::MachO("section table overflow".into()))?;
                    let size = read_u64(input, sect + 40, is_big_endian)?;
                    let soff = read_u32(input, sect + 48, is_big_endian)? as usize;
                    if size > 0 && soff > 0 && soff < first_segment_offset {
                        first_segment_offset = soff;
                    }
                }
            }
            LC_SEGMENT => {
                let fileoff = read_u32(input, offset + 32, is_big_endian)? as usize;
                let filesize = read_u32(input, offset + 36, is_big_endian)?;
                if fileoff > 0 && filesize > 0 && fileoff < first_segment_offset {
                    first_segment_offset = fileoff;
                }
                let nsects = read_u32(input, offset + 48, is_big_endian)? as usize;
                let sects_bytes = nsects
                    .checked_mul(68)
                    .ok_or_else(|| Error::MachO("section count overflow".into()))?;
                let sects_start = offset
                    .checked_add(56)
                    .ok_or_else(|| Error::MachO("section table overflow".into()))?;
                let sects_end = sects_start
                    .checked_add(sects_bytes)
                    .ok_or_else(|| Error::MachO("section table overflow".into()))?;
                let lc_end = offset
                    .checked_add(cmdsize)
                    .ok_or_else(|| Error::MachO("load command size overflow".into()))?;
                if sects_end > lc_end || sects_end > input.len() {
                    return Err(Error::MachO("section table exceeds load command".into()));
                }
                for i in 0..nsects {
                    let sect = sects_start
                        .checked_add(
                            i.checked_mul(68)
                                .ok_or_else(|| Error::MachO("section count overflow".into()))?,
                        )
                        .ok_or_else(|| Error::MachO("section table overflow".into()))?;
                    let size = read_u32(input, sect + 36, is_big_endian)?;
                    let soff = read_u32(input, sect + 40, is_big_endian)? as usize;
                    if size > 0 && soff > 0 && soff < first_segment_offset {
                        first_segment_offset = soff;
                    }
                }
            }
            _ => {}
        }

        offset = end;
        if end > max_load_cmd_end {
            max_load_cmd_end = end;
        }
    }

    if first_segment_offset == usize::MAX {
        first_segment_offset = DEFAULT_FIRST_SEGMENT_OFFSET;
    }

    let name_len_with_nul = dylib_name.len() + 1;
    let new_cmdsize = checked_u32(align_to(DYLIB_FIXED_SIZE + name_len_with_nul, 8), "cmdsize")?;
    let new_cmd_end = max_load_cmd_end
        .checked_add(new_cmdsize as usize)
        .ok_or_else(|| Error::MachO("dylib command size overflow".into()))?;

    if new_cmd_end > first_segment_offset {
        return Err(Error::MachO(
            "no space for dylib command in load commands area".into(),
        ));
    }

    let mut output = input.to_vec();
    if new_cmd_end > output.len() {
        return Err(Error::MachO("binary too short for dylib command".into()));
    }

    output[max_load_cmd_end..new_cmd_end].fill(0);

    let cmd_value = if weak {
        LC_LOAD_WEAK_DYLIB
    } else {
        LC_LOAD_DYLIB
    };
    write_u32(&mut output, max_load_cmd_end, cmd_value, is_big_endian)?;
    write_u32(
        &mut output,
        max_load_cmd_end + 4,
        new_cmdsize,
        is_big_endian,
    )?;
    write_u32(
        &mut output,
        max_load_cmd_end + 8,
        DYLIB_FIXED_SIZE as u32,
        is_big_endian,
    )?;
    write_u32(&mut output, max_load_cmd_end + 12, 0, is_big_endian)?;
    write_u32(&mut output, max_load_cmd_end + 16, 0, is_big_endian)?;
    write_u32(&mut output, max_load_cmd_end + 20, 0, is_big_endian)?;

    let name_start = max_load_cmd_end + DYLIB_FIXED_SIZE;
    output[name_start..name_start + dylib_name.len()].copy_from_slice(dylib_name.as_bytes());
    output[name_start + dylib_name.len()] = 0;

    let current_ncmds = read_u32(input, 16, is_big_endian)?;
    let current_sizeofcmds = read_u32(input, 20, is_big_endian)?;
    write_u32(&mut output, 16, current_ncmds + 1, is_big_endian)?;
    write_u32(
        &mut output,
        20,
        current_sizeofcmds + new_cmdsize,
        is_big_endian,
    )?;

    Ok(output)
}

fn find_first_segment_offset(macho: &MachO) -> usize {
    let mut min_offset: u64 = u64::MAX;

    for segment in &macho.segments {
        if let Ok(sections) = segment.sections() {
            for (section, _) in sections {
                if section.size > 0 && section.offset > 0 {
                    min_offset = min_offset.min(section.offset as u64);
                }
            }
        }
    }
    for lc in &macho.load_commands {
        match &lc.command {
            CommandVariant::Segment64(seg) if seg.fileoff > 0 && seg.filesize > 0 => {
                min_offset = min_offset.min(seg.fileoff);
            }
            CommandVariant::Segment32(seg) if seg.fileoff > 0 && seg.filesize > 0 => {
                min_offset = min_offset.min(seg.fileoff as u64);
            }
            _ => {}
        }
    }
    if min_offset == u64::MAX {
        4096
    } else {
        min_offset as usize
    }
}

fn update_linkedit_segment(data: &mut [u8], offset: usize, new_filesize: u64) -> Result<()> {
    let filesize_offset = offset + 48;
    let vmsize_offset = offset + 32;

    let is_big_endian = super::parser::is_big_endian_macho(data, 0);

    write_u64(data, filesize_offset, new_filesize, is_big_endian)?;

    let original_vmsize = read_u64(data, vmsize_offset, is_big_endian)?;
    let aligned_vmsize = align_to(new_filesize as usize, 0x4000) as u64;
    write_u64(
        data,
        vmsize_offset,
        aligned_vmsize.max(original_vmsize),
        is_big_endian,
    )?;

    Ok(())
}

/// Aligns a value up to the specified alignment boundary.
///
/// # Examples
///
/// ```
/// use zsign_core::macho::align_to;
///
/// assert_eq!(align_to(100, 16), 112);
/// assert_eq!(align_to(16, 16), 16);
/// ```
pub fn align_to(value: usize, alignment: usize) -> usize {
    (value + alignment - 1) & !(alignment - 1)
}

/// Converts a `usize` to `u32`, returning an error if the value exceeds `u32::MAX`.
///
/// Used for Mach-O fields that are defined as u32 (e.g., `LC_CODE_SIGNATURE` offsets).
pub(crate) fn checked_u32(value: usize, field_name: &str) -> Result<u32> {
    u32::try_from(value)
        .map_err(|_| Error::MachO(format!("{} exceeds u32::MAX: {}", field_name, value)))
}

/// Prepares code bytes for signing by updating load commands.
///
/// Must be called before hashing, as the hash includes the Mach-O header
/// and load commands. Updates `LC_CODE_SIGNATURE` and `__LINKEDIT` in-place.
///
/// For FAT binaries, use [`prepare_code_for_signing_slice`].
///
/// # Returns
///
/// Returns `(prepared_code, signature_offset, code_length)`.
///
/// # Errors
///
/// Returns [`Error::MachO`] if the binary is invalid or 32-bit.
pub fn prepare_code_for_signing(
    data: &[u8],
    estimated_signature_size: usize,
) -> Result<(Vec<u8>, usize, usize)> {
    let mach =
        Mach::parse(data).map_err(|e| Error::MachO(format!("Failed to parse Mach-O: {}", e)))?;

    match mach {
        Mach::Binary(macho) => prepare_code_single(data, &macho, estimated_signature_size),
        Mach::Fat(_) => Err(Error::MachO(
            "Use prepare_code_for_signing_slice for FAT binaries".into(),
        )),
    }
}

/// Prepares a single slice of a FAT binary for signing.
///
/// Use this for FAT binary slices. For single-arch binaries, use [`prepare_code_for_signing`].
///
/// # Returns
///
/// Returns `(prepared_code, signature_offset, code_length)`.
///
/// # Errors
///
/// Returns [`Error::MachO`] if the slice is not a valid single-arch Mach-O.
pub fn prepare_code_for_signing_slice(
    slice_data: &[u8],
    estimated_signature_size: usize,
) -> Result<(Vec<u8>, usize, usize)> {
    let mach = Mach::parse(slice_data)
        .map_err(|e| Error::MachO(format!("Failed to parse Mach-O slice: {}", e)))?;

    match mach {
        Mach::Binary(macho) => prepare_code_single(slice_data, &macho, estimated_signature_size),
        Mach::Fat(_) => Err(Error::MachO("Expected single-arch binary, got FAT".into())),
    }
}

fn prepare_code_single(
    data: &[u8],
    macho: &MachO,
    estimated_signature_size: usize,
) -> Result<(Vec<u8>, usize, usize)> {
    let is_64 = macho.header.magic == MH_MAGIC_64 || macho.header.magic == MH_CIGAM_64;
    if !is_64 {
        return Err(Error::MachO("32-bit Mach-O binaries not supported".into()));
    }

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
            CommandVariant::Segment64(seg) if seg.segname.starts_with(b"__LINKEDIT") => {
                linkedit_cmd = Some((lc.offset, *seg));
            }
            _ => {}
        }
    }

    let code_length = if let Some((_, cs)) = code_sig_cmd {
        cs.dataoff as usize
    } else {
        find_code_end(macho, data.len())
    };

    let sig_offset = align_to(code_length, 16);
    let sig_size = checked_u32(estimated_signature_size, "estimated_signature_size")?;

    let mut prepared = data[..code_length].to_vec();

    if let Some((offset, _)) = code_sig_cmd {
        update_linkedit_data_command(
            &mut prepared,
            offset,
            checked_u32(sig_offset, "sig_offset")?,
            sig_size,
        )?;
    } else {
        add_code_signature_command(
            &mut prepared,
            macho,
            max_load_cmd_end,
            checked_u32(sig_offset, "sig_offset")?,
            sig_size,
        )?;
    }

    if let Some((offset, seg)) = linkedit_cmd {
        let new_filesize = (sig_offset + estimated_signature_size) as u64 - seg.fileoff;
        update_linkedit_segment(&mut prepared, offset, new_filesize)?;
    } else {
        return Err(Error::MachO("No __LINKEDIT segment found".into()));
    }

    Ok((prepared, sig_offset, code_length))
}

use super::parser::MachOMetadata;

/// Expands a Mach-O binary to accommodate a code signature using cached metadata.
///
/// Returns the expanded binary and updated metadata reflecting any changes made
/// (e.g., new LC_CODE_SIGNATURE command or updated __LINKEDIT).
///
/// # Errors
///
/// Returns [`Error::MachO`] if:
/// - The binary is 32-bit (not supported)
/// - No `__LINKEDIT` segment exists
/// - No space for `LC_CODE_SIGNATURE` in load commands area
pub fn realloc_code_sign_space_with_metadata(
    data: &[u8],
    metadata: &MachOMetadata,
    code_length: usize,
) -> Result<(Vec<u8>, MachOMetadata)> {
    if !metadata.is_64 {
        return Err(Error::MachO("32-bit Mach-O binaries not supported".into()));
    }

    if code_length > data.len() {
        return Err(Error::MachO(format!(
            "code_length {code_length} exceeds the {}-byte buffer",
            data.len()
        )));
    }
    let is_big_endian = metadata.is_big_endian;
    let sig_offset = align_to(code_length, 16);
    let reserve = calculate_signature_space(code_length)
        .checked_sub(code_length)
        .ok_or_else(|| Error::MachO("signature space smaller than code length".into()))?;
    let formula_end = sig_offset
        .checked_add(reserve)
        .ok_or_else(|| Error::MachO("signature space overflow".into()))?;
    let declared_end = match metadata.code_sig_cmd {
        Some((lc_offset, _, _)) => declared_signature_end(data, lc_offset, is_big_endian)?,
        None => None,
    };
    let required = declared_end.map_or(formula_end, |end| end.max(formula_end));
    if required <= data.len() {
        return Ok((data.to_vec(), metadata.clone()));
    }

    let mut output = data[..code_length].to_vec();

    let mut updated_metadata = metadata.clone();

    if let Some((offset, fileoff, vmsize, _filesize)) = metadata.linkedit_cmd {
        let linkedit_fileoff = fileoff as usize;
        let size_increase = required - data.len();
        let new_vmsize = align_to(vmsize as usize + size_increase, PAGE_SIZE) as u64;
        let new_filesize = required
            .checked_sub(linkedit_fileoff)
            .ok_or_else(|| Error::MachO("__LINKEDIT fileoff exceeds required length".into()))?
            as u64;

        write_u64(&mut output, offset + 32, new_vmsize, is_big_endian)?;
        write_u64(&mut output, offset + 48, new_filesize, is_big_endian)?;

        updated_metadata.linkedit_cmd = Some((offset, fileoff, new_vmsize, new_filesize));
    } else {
        return Err(Error::MachO("No __LINKEDIT segment found".into()));
    }

    let sig_datasize = checked_u32(required - code_length, "sig_datasize")?;

    if let Some((offset, _dataoff, _datasize)) = metadata.code_sig_cmd {
        write_u32(
            &mut output,
            offset + 8,
            checked_u32(code_length, "code_length")?,
            is_big_endian,
        )?;
        write_u32(&mut output, offset + 12, sig_datasize, is_big_endian)?;

        updated_metadata.code_sig_cmd = Some((
            offset,
            checked_u32(code_length, "code_length")?,
            sig_datasize,
        ));
    } else {
        let new_cmd_size = LINKEDIT_DATA_COMMAND_SIZE as usize;
        let header_size = if metadata.is_64 { 32 } else { 28 };
        let sizeofcmds = read_u32(&output, 20, is_big_endian)? as usize;
        let insert_end = metadata
            .max_load_cmd_end
            .max(header_size + sizeofcmds)
            .checked_add(new_cmd_size)
            .ok_or_else(|| Error::MachO("load command end overflow".into()))?;
        if insert_end > metadata.first_segment_offset || insert_end > output.len() {
            return Err(Error::MachO(
                "No space for LC_CODE_SIGNATURE in load commands area".into(),
            ));
        }

        let cmd_offset = metadata.max_load_cmd_end;
        write_u32(&mut output, cmd_offset, LC_CODE_SIGNATURE, is_big_endian)?;
        write_u32(
            &mut output,
            cmd_offset + 4,
            LINKEDIT_DATA_COMMAND_SIZE,
            is_big_endian,
        )?;
        write_u32(
            &mut output,
            cmd_offset + 8,
            checked_u32(code_length, "code_length")?,
            is_big_endian,
        )?;
        write_u32(&mut output, cmd_offset + 12, sig_datasize, is_big_endian)?;

        let current_ncmds = read_u32(&output, 16, is_big_endian)?;
        let current_sizeofcmds = read_u32(&output, 20, is_big_endian)?;
        write_u32(&mut output, 16, current_ncmds + 1, is_big_endian)?;
        write_u32(
            &mut output,
            20,
            current_sizeofcmds + LINKEDIT_DATA_COMMAND_SIZE,
            is_big_endian,
        )?;

        updated_metadata.code_sig_cmd = Some((
            cmd_offset,
            checked_u32(code_length, "code_length")?,
            sig_datasize,
        ));
        updated_metadata.max_load_cmd_end = insert_end;
    }

    output.resize(required, 0);

    Ok((output, updated_metadata))
}

/// Prepares code bytes for signing using cached metadata.
///
/// Updates `LC_CODE_SIGNATURE` and `__LINKEDIT` in-place.
///
/// # Returns
///
/// Returns `(prepared_code, signature_offset, code_length)`.
///
/// # Errors
///
/// Returns [`Error::MachO`] if the binary is 32-bit or missing `__LINKEDIT`.
pub fn prepare_code_with_metadata(
    data: &[u8],
    metadata: &MachOMetadata,
    estimated_signature_size: usize,
) -> Result<(Vec<u8>, usize, usize)> {
    if !metadata.is_64 {
        return Err(Error::MachO("32-bit Mach-O binaries not supported".into()));
    }

    let code_length = if let Some((_offset, dataoff, _datasize)) = metadata.code_sig_cmd {
        dataoff as usize
    } else {
        data.len()
    };

    let sig_offset = align_to(code_length, 16);
    let sig_size = checked_u32(estimated_signature_size, "estimated_signature_size")?;
    let declared_end = sig_offset
        .checked_add(sig_size as usize)
        .ok_or_else(|| Error::MachO("signature reserve overflows the buffer index".into()))?;
    if declared_end > data.len() {
        return Err(Error::MachO(format!(
            "signature reserve of {sig_size} bytes at offset {sig_offset} exceeds the {}-byte buffer",
            data.len()
        )));
    }

    let mut prepared = data[..code_length].to_vec();

    if let Some((offset, _dataoff, _datasize)) = metadata.code_sig_cmd {
        update_linkedit_data_command(
            &mut prepared,
            offset,
            checked_u32(sig_offset, "sig_offset")?,
            sig_size,
        )?;
    } else {
        add_code_signature_command_with_metadata(
            &mut prepared,
            metadata,
            checked_u32(sig_offset, "sig_offset")?,
            sig_size,
        )?;
    }

    if let Some((offset, fileoff, _vmsize, _filesize)) = metadata.linkedit_cmd {
        let new_filesize = (sig_offset + estimated_signature_size) as u64 - fileoff;
        update_linkedit_segment(&mut prepared, offset, new_filesize)?;
    } else {
        return Err(Error::MachO("No __LINKEDIT segment found".into()));
    }

    Ok((prepared, sig_offset, code_length))
}

fn add_code_signature_command_with_metadata(
    data: &mut [u8],
    metadata: &MachOMetadata,
    dataoff: u32,
    datasize: u32,
) -> Result<()> {
    let new_cmd_size = LINKEDIT_DATA_COMMAND_SIZE as usize;
    let new_load_commands_end = metadata
        .max_load_cmd_end
        .checked_add(new_cmd_size)
        .ok_or_else(|| Error::MachO("load command end overflow".into()))?;
    if new_load_commands_end > metadata.first_segment_offset || new_load_commands_end > data.len() {
        return Err(Error::MachO(
            "No space for LC_CODE_SIGNATURE in load commands area".into(),
        ));
    }

    let is_big_endian = metadata.is_big_endian;
    let load_commands_end = metadata.max_load_cmd_end;

    write_u32(data, load_commands_end, LC_CODE_SIGNATURE, is_big_endian)?;
    write_u32(
        data,
        load_commands_end + 4,
        LINKEDIT_DATA_COMMAND_SIZE,
        is_big_endian,
    )?;
    write_u32(data, load_commands_end + 8, dataoff, is_big_endian)?;
    write_u32(data, load_commands_end + 12, datasize, is_big_endian)?;

    let current_ncmds = read_u32(data, 16, is_big_endian)?;
    let current_sizeofcmds = read_u32(data, 20, is_big_endian)?;

    write_u32(data, 16, current_ncmds + 1, is_big_endian)?;
    write_u32(
        data,
        20,
        current_sizeofcmds + LINKEDIT_DATA_COMMAND_SIZE,
        is_big_endian,
    )?;

    Ok(())
}

/// Prepares code for signing in-place, avoiding extra allocations.
///
/// Truncates `buf` to `code_length`, updates load commands, and returns
/// `(sig_offset, code_length)`.
///
/// # Errors
///
/// Returns [`Error::MachO`] if `__LINKEDIT` is missing or the binary is 32-bit.
pub fn prepare_code_in_place(
    buf: &mut Vec<u8>,
    metadata: &MachOMetadata,
    code_length: usize,
    estimated_signature_size: usize,
) -> Result<(usize, usize)> {
    if !metadata.is_64 {
        return Err(Error::MachO("32-bit Mach-O binaries not supported".into()));
    }

    let sig_offset = align_to(code_length, 16);
    let sig_size = checked_u32(estimated_signature_size, "estimated_signature_size")?;
    let declared_end = sig_offset
        .checked_add(sig_size as usize)
        .ok_or_else(|| Error::MachO("signature reserve overflows the buffer index".into()))?;
    if declared_end > buf.len() {
        return Err(Error::MachO(format!(
            "signature reserve of {sig_size} bytes at offset {sig_offset} exceeds the {}-byte buffer",
            buf.len()
        )));
    }

    buf.truncate(code_length);

    if let Some((offset, _dataoff, _datasize)) = metadata.code_sig_cmd {
        update_linkedit_data_command(
            buf,
            offset,
            checked_u32(sig_offset, "sig_offset")?,
            sig_size,
        )?;
    } else {
        add_code_signature_command_with_metadata(
            buf,
            metadata,
            checked_u32(sig_offset, "sig_offset")?,
            sig_size,
        )?;
    }

    if let Some((offset, fileoff, _vmsize, _filesize)) = metadata.linkedit_cmd {
        let new_filesize = (sig_offset + estimated_signature_size) as u64 - fileoff;
        update_linkedit_segment(buf, offset, new_filesize)?;
    } else {
        return Err(Error::MachO("No __LINKEDIT segment found".into()));
    }

    Ok((sig_offset, code_length))
}

fn read_u32(data: &[u8], offset: usize, big_endian: bool) -> Result<u32> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| Error::MachO(format!("read_u32: offset {} overflow", offset)))?;
    let bytes: [u8; 4] = data
        .get(offset..end)
        .ok_or_else(|| {
            Error::MachO(format!(
                "read_u32: offset {} out of bounds (len={})",
                offset,
                data.len()
            ))
        })?
        .try_into()
        .map_err(|_| Error::MachO("read_u32: slice conversion failed".into()))?;
    Ok(if big_endian {
        u32::from_be_bytes(bytes)
    } else {
        u32::from_le_bytes(bytes)
    })
}

fn read_u64(data: &[u8], offset: usize, big_endian: bool) -> Result<u64> {
    let end = offset
        .checked_add(8)
        .ok_or_else(|| Error::MachO(format!("read_u64: offset {} overflow", offset)))?;
    let bytes: [u8; 8] = data
        .get(offset..end)
        .ok_or_else(|| {
            Error::MachO(format!(
                "read_u64: offset {} out of bounds (len={})",
                offset,
                data.len()
            ))
        })?
        .try_into()
        .map_err(|_| Error::MachO("read_u64: slice conversion failed".into()))?;
    Ok(if big_endian {
        u64::from_be_bytes(bytes)
    } else {
        u64::from_le_bytes(bytes)
    })
}

fn write_u32(data: &mut [u8], offset: usize, value: u32, big_endian: bool) -> Result<()> {
    let bytes = if big_endian {
        value.to_be_bytes()
    } else {
        value.to_le_bytes()
    };
    let end = offset
        .checked_add(4)
        .ok_or_else(|| Error::MachO(format!("write_u32: offset {} overflow", offset)))?;
    let data_len = data.len();
    data.get_mut(offset..end)
        .ok_or_else(|| {
            Error::MachO(format!(
                "write_u32: offset {} out of bounds (len={})",
                offset, data_len
            ))
        })?
        .copy_from_slice(&bytes);
    Ok(())
}

fn write_u64(data: &mut [u8], offset: usize, value: u64, big_endian: bool) -> Result<()> {
    let bytes = if big_endian {
        value.to_be_bytes()
    } else {
        value.to_le_bytes()
    };
    let end = offset
        .checked_add(8)
        .ok_or_else(|| Error::MachO(format!("write_u64: offset {} overflow", offset)))?;
    let data_len = data.len();
    data.get_mut(offset..end)
        .ok_or_else(|| {
            Error::MachO(format!(
                "write_u64: offset {} out of bounds (len={})",
                offset, data_len
            ))
        })?
        .copy_from_slice(&bytes);
    Ok(())
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
        write_u32(&mut data, 0, 0x12345678, false).unwrap();
        assert_eq!(read_u32(&data, 0, false).unwrap(), 0x12345678);
        assert_eq!(&data[0..4], &[0x78, 0x56, 0x34, 0x12]);
    }

    #[test]
    fn test_read_write_u32_be() {
        let mut data = vec![0u8; 8];
        write_u32(&mut data, 0, 0x12345678, true).unwrap();
        assert_eq!(read_u32(&data, 0, true).unwrap(), 0x12345678);
        assert_eq!(&data[0..4], &[0x12, 0x34, 0x56, 0x78]);
    }

    #[test]
    fn test_read_u32_out_of_bounds() {
        let data = vec![0u8; 2];
        assert!(read_u32(&data, 0, false).is_err());
    }

    #[test]
    fn test_write_u32_out_of_bounds() {
        let mut data = vec![0u8; 2];
        assert!(write_u32(&mut data, 0, 42, false).is_err());
    }

    #[test]
    fn test_write_u64_out_of_bounds() {
        let mut data = vec![0u8; 4];
        assert!(write_u64(&mut data, 0, 42, false).is_err());
    }

    #[test]
    fn test_embed_signature_invalid_data() {
        let data = vec![0u8; 100];
        let signature = vec![0u8; 1000];
        let result = embed_signature(&data, &signature);
        assert!(result.is_err());
    }

    #[test]
    fn test_calculate_signature_space() {
        // Test with various code lengths
        // Formula: code_length + align_to((pages+1)*52, 4096) + 16384

        // 4KB code (1 page)
        let code_length = 4096;
        let result = calculate_signature_space(code_length);
        // pages = 1, (1+1)*52 = 104 -> align to 4096 = 4096
        // total = 4096 + 4096 + 16384 = 24576
        assert_eq!(result, 24576);

        // 1MB code (256 pages)
        let code_length = 1024 * 1024;
        let result = calculate_signature_space(code_length);
        // pages = 256, (256+1)*52 = 13364 -> align to 4096 = 16384
        // total = 1MB + 16384 + 16384 = 1081344
        assert_eq!(result, 1081344);

        // 10MB code
        let code_length = 10 * 1024 * 1024;
        let result = calculate_signature_space(code_length);
        // pages = 2560, (2560+1)*52 = 133172 -> align to 4096 = 135168
        // total = 10MB + 135168 + 16384 = 10637312
        assert_eq!(result, 10637312);
    }

    #[test]
    fn test_calculate_signature_space_non_aligned() {
        // 4097 bytes = 2 pages (partial page counts as full page)
        let code_length = 4097;
        let result = calculate_signature_space(code_length);
        // pages = 2 (div_ceil), (2+1)*52 = 156 -> align to 4096 = 4096
        // total = 4097 + 4096 + 16384 = 24577
        assert_eq!(result, 24577);
    }

    #[test]
    fn test_has_enough_signature_space() {
        // Data has 1000 bytes after code_length
        assert!(has_enough_signature_space(&[0u8; 2000], 1000, 500));
        assert!(has_enough_signature_space(&[0u8; 2000], 1000, 1000));
        assert!(!has_enough_signature_space(&[0u8; 2000], 1000, 1001));
        assert!(!has_enough_signature_space(&[0u8; 2000], 1000, 2000));

        // Edge case: code_length equals data length
        assert!(!has_enough_signature_space(&[0u8; 1000], 1000, 1));
        assert!(has_enough_signature_space(&[0u8; 1000], 1000, 0));
    }

    /// Builds a tiny 64-bit LE Mach-O: header plus one `LC_SEGMENT_64` __TEXT
    /// command (72 bytes), padded to 0x1004 bytes. The segment's `fileoff` is
    /// given by `segment_fileoff`.
    fn build_test_binary(segment_fileoff: u64) -> Vec<u8> {
        // 32-byte header + one 72-byte LC_SEGMENT_64 command
        let mut data = vec![0u8; 104];
        write_u32(&mut data, 0, 0xfeed_facf, false).unwrap(); // MH_MAGIC_64
        write_u32(&mut data, 4, 0x0100_000c, false).unwrap(); // CPU_TYPE_ARM64
        write_u32(&mut data, 8, 0, false).unwrap(); // cpusubtype
        write_u32(&mut data, 12, 2, false).unwrap(); // MH_EXECUTE
        write_u32(&mut data, 16, 1, false).unwrap(); // ncmds
        write_u32(&mut data, 20, 72, false).unwrap(); // sizeofcmds
        write_u32(&mut data, 24, 0, false).unwrap(); // flags
        write_u32(&mut data, 28, 0, false).unwrap(); // reserved

        let seg_off = 32usize;
        write_u32(&mut data, seg_off, 0x19, false).unwrap(); // LC_SEGMENT_64
        write_u32(&mut data, seg_off + 4, 72, false).unwrap();
        data[seg_off + 8..seg_off + 15].copy_from_slice(b"__TEXT\0"); // segname
        write_u64(&mut data, seg_off + 24, 0, false).unwrap(); // vmaddr
        write_u64(&mut data, seg_off + 32, 0x1000, false).unwrap(); // vmsize
        write_u64(&mut data, seg_off + 40, segment_fileoff, false).unwrap(); // fileoff
        write_u64(&mut data, seg_off + 48, 0x1000, false).unwrap(); // filesize
        write_u32(&mut data, seg_off + 56, 7, false).unwrap(); // maxprot
        write_u32(&mut data, seg_off + 60, 7, false).unwrap(); // initprot
        write_u32(&mut data, seg_off + 64, 0, false).unwrap(); // nsects
        write_u32(&mut data, seg_off + 68, 0, false).unwrap(); // flags

        data.resize(0x1004, 0xCC);
        data
    }

    #[test]
    fn test_inject_dylib_command() {
        let input = build_test_binary(0x1000);
        let insertion_point = 32 + 72; // end of the single load command

        let name = "libtest.dylib"; // 13 bytes + NUL = 14
        let expected_cmdsize = align_to(24 + name.len() + 1, 8); // 40

        let output = inject_dylib_command(&input, name, false).unwrap();
        assert_eq!(read_u32(&output, 16, false).unwrap(), 2); // ncmds
        assert_eq!(
            read_u32(&output, 20, false).unwrap(),
            72 + expected_cmdsize as u32
        ); // sizeofcmds

        assert_eq!(read_u32(&output, insertion_point, false).unwrap(), 0xc); // LC_LOAD_DYLIB
        assert_eq!(
            read_u32(&output, insertion_point + 4, false).unwrap(),
            expected_cmdsize as u32
        );
        assert_eq!(read_u32(&output, insertion_point + 8, false).unwrap(), 24); // name_offset
        assert_eq!(read_u32(&output, insertion_point + 12, false).unwrap(), 0); // timestamp
        assert_eq!(read_u32(&output, insertion_point + 16, false).unwrap(), 0); // current_version
        assert_eq!(read_u32(&output, insertion_point + 20, false).unwrap(), 0); // compatibility_version

        let name_start = insertion_point + 24;
        assert_eq!(
            &output[name_start..name_start + name.len()],
            name.as_bytes()
        );
        assert_eq!(output[name_start + name.len()], 0);

        // Nothing before the insertion point changed apart from the header
        // ncmds/sizeofcmds bumps.
        let mut expected_prefix = input[..insertion_point].to_vec();
        write_u32(&mut expected_prefix, 16, 2, false).unwrap();
        write_u32(
            &mut expected_prefix,
            20,
            72 + expected_cmdsize as u32,
            false,
        )
        .unwrap();
        assert_eq!(&output[..insertion_point], &expected_prefix[..]);

        // The weak variant uses LC_LOAD_WEAK_DYLIB and the same layout.
        let weak = inject_dylib_command(&input, name, true).unwrap();
        assert_eq!(read_u32(&weak, 16, false).unwrap(), 2);
        assert_eq!(
            read_u32(&weak, insertion_point, false).unwrap(),
            0x8000_0018
        );
        assert_eq!(
            read_u32(&weak, insertion_point + 4, false).unwrap(),
            expected_cmdsize as u32
        );
        let mut expected_weak_prefix = input[..insertion_point].to_vec();
        write_u32(&mut expected_weak_prefix, 16, 2, false).unwrap();
        write_u32(
            &mut expected_weak_prefix,
            20,
            72 + expected_cmdsize as u32,
            false,
        )
        .unwrap();
        assert_eq!(&weak[..insertion_point], &expected_weak_prefix[..]);
    }

    #[test]
    fn test_inject_dylib_command_no_slack() {
        // The segment starts exactly where the load-command region ends: no
        // room for another command.
        let input = build_test_binary(104);
        match inject_dylib_command(&input, "libtest.dylib", false) {
            Err(Error::MachO(msg)) => {
                assert!(msg.contains("no space"), "unexpected error: {}", msg);
            }
            other => panic!("expected no-space error, got {:?}", other),
        }
    }

    #[test]
    fn test_inject_dylib_command_cmdsize_alignment() {
        let input = build_test_binary(0x1000);
        let name = "abc1234"; // 7 bytes + NUL = 8
        let output = inject_dylib_command(&input, name, false).unwrap();

        let cmdsize = read_u32(&output, 32 + 72 + 4, false).unwrap() as usize;
        assert_eq!(cmdsize % 8, 0);
        assert_eq!(cmdsize, 24 + 8); // 32
        assert_eq!(read_u32(&output, 20, false).unwrap(), 72 + 32);
    }

    #[test]
    fn test_inject_dylib_refuses_section_clobber_with_fileoff0_text() {
        let data = crate::macho::fixtures::make_text_fileoff0_macho(true);
        let err = inject_dylib_command(&data, "@rpath/libtest.dylib", false)
            .expect_err("8-byte gap before the first section must refuse a new load command");
        let msg = match err {
            crate::Error::MachO(m) => m,
            other => panic!("expected MachO error, got {other:?}"),
        };
        assert!(
            msg.contains("no space"),
            "message must explain missing room: {msg}"
        );
    }

    #[test]
    fn test_inject_dylib_keeps_section_bytes_with_fileoff0_text() {
        let data = crate::macho::fixtures::make_text_fileoff0_macho(false);
        let section_off = 0x400;
        let before = data[section_off..section_off + 4].to_vec();
        let output = inject_dylib_command(&data, "@rpath/libtest.dylib", false)
            .expect("comfortable gap must accept the new load command");
        assert_eq!(
            &output[section_off..section_off + 4],
            &before[..],
            "section bytes must be preserved"
        );
        assert_eq!(read_u32(&output, 16, false).unwrap(), 4, "ncmds must grow");
    }

    #[test]
    fn test_metadata_first_segment_offset_sees_fileoff0_sections() {
        let data = crate::macho::fixtures::make_text_fileoff0_macho(false);
        let macho = crate::macho::MachOFile::parse(data).expect("fixture must parse");
        let meta = &macho.slices()[0].metadata;
        assert_eq!(
            meta.first_segment_offset, 0x400,
            "insertion bound must be the first section offset, not a later segment fileoff"
        );
    }

    #[test]
    fn test_realloc_refuses_insertion_across_first_section() {
        let data = crate::macho::fixtures::make_text_fileoff0_macho(true);
        let macho = crate::macho::MachOFile::parse(data.clone()).expect("fixture must parse");
        let meta = macho.slices()[0].metadata.clone();
        let result = realloc_code_sign_space_with_metadata(&data, &meta, data.len());
        let err = match result {
            Err(err) => err,
            Ok(_) => panic!("adding LC_CODE_SIGNATURE into an 8-byte gap must be refused"),
        };
        let msg = match err {
            crate::Error::MachO(m) => m,
            other => panic!("expected MachO error, got {other:?}"),
        };
        assert!(
            msg.contains("No space"),
            "message must explain missing room: {msg}"
        );
    }

    #[test]
    fn test_sign_refuses_tight_fileoff0_fixture() {
        let data = crate::macho::fixtures::make_text_fileoff0_macho(true);
        let macho = crate::macho::MachOFile::parse(data).expect("fixture must parse");
        assert!(
            crate::macho::sign_macho_adhoc(&macho, "com.example.tight", None, None, None, false)
                .is_err(),
            "signing must not overwrite __text by appending LC_CODE_SIGNATURE"
        );
    }

    #[test]
    fn test_big_endian_sign_parse_roundtrip() {
        let data = crate::macho::fixtures::make_minimal_macho_be();
        assert_eq!(
            &data[0..4],
            &[0xfe, 0xed, 0xfa, 0xcf],
            "fixture must be a real big-endian image"
        );
        let macho = crate::macho::MachOFile::parse(data).expect("big-endian Mach-O must parse");
        let slice = &macho.slices()[0];
        assert!(
            slice.metadata.is_big_endian,
            "parser must classify the slice as big-endian"
        );

        let signed =
            crate::macho::sign_macho_adhoc(&macho, "com.example.be", None, None, None, false)
                .expect("big-endian signing must succeed");
        let reparsed = crate::macho::MachOFile::parse(signed.clone())
            .expect("signed big-endian output must reparse");
        let out = &reparsed.slices()[0];
        assert!(
            out.metadata.is_big_endian,
            "signed output must still be big-endian"
        );

        // __LINKEDIT.filesize must have been rewritten big-endian: decode raw bytes both ways.
        let (lc_off, _, _, _) = out
            .metadata
            .linkedit_cmd
            .expect("signed output keeps __LINKEDIT");
        let raw = u64::from_be_bytes(signed[lc_off + 48..lc_off + 56].try_into().unwrap());
        assert_eq!(
            raw,
            out.metadata.linkedit_cmd.unwrap().3,
            "__LINKEDIT filesize must be encoded big-endian"
        );
        assert_ne!(
            raw,
            u64::from_le_bytes(signed[lc_off + 48..lc_off + 56].try_into().unwrap()),
            "little-endian decoding must not yield the filesize value"
        );
        assert!(
            raw > 0,
            "signing must have given __LINKEDIT a nonzero filesize"
        );

        // LC_CODE_SIGNATURE.dataoff must also be big-endian on the wire.
        let (cmd_off, _, _) = out
            .metadata
            .code_sig_cmd
            .expect("signed output carries LC_CODE_SIGNATURE");
        let dataoff_be = u32::from_be_bytes(signed[cmd_off + 8..cmd_off + 12].try_into().unwrap());
        let dataoff_le = u32::from_le_bytes(signed[cmd_off + 8..cmd_off + 12].try_into().unwrap());
        assert_eq!(
            dataoff_be,
            out.code_sig_offset.expect("parsed dataoff"),
            "LC_CODE_SIGNATURE.dataoff must be encoded big-endian"
        );
        assert_ne!(
            dataoff_be, dataoff_le,
            "little-endian decoding must not yield the dataoff"
        );

        // Verify leg: the embedded superblob and its CodeDirectory must round-trip.
        let sig_off = out
            .code_sig_offset
            .expect("signed output carries LC_CODE_SIGNATURE") as usize;
        let sig_size = out
            .code_sig_size
            .expect("signed output carries LC_CODE_SIGNATURE") as usize;
        let superblob =
            crate::codesign::verify::parse_superblob(&signed[sig_off..sig_off + sig_size])
                .expect("big-endian signed output must carry a parseable superblob");
        let cd = superblob
            .code_directory
            .as_ref()
            .expect("superblob carries a code directory");
        let cd_raw = cd.raw();
        assert_eq!(
            u64::from_be_bytes(cd_raw[72..80].try_into().unwrap()),
            0x1000,
            "CodeDirectory execSegLimit must round-trip for a big-endian image"
        );
    }
    fn big_signed_buffer() -> Vec<u8> {
        let mut data = crate::macho::fixtures::make_minimal_macho();
        data.resize(0x8000, 0);
        let ncmds = u32::from_le_bytes(data[16..20].try_into().unwrap());
        let sizeofcmds = u32::from_le_bytes(data[20..24].try_into().unwrap());
        data[16..20].copy_from_slice(&(ncmds + 1).to_le_bytes());
        data[20..24].copy_from_slice(&(sizeofcmds + 16).to_le_bytes());
        let lc = 32 + sizeofcmds as usize; // 280
        data[lc..lc + 4].copy_from_slice(&0x1du32.to_le_bytes()); // LC_CODE_SIGNATURE
        data[lc + 4..lc + 8].copy_from_slice(&16u32.to_le_bytes()); // cmdsize
        data[lc + 8..lc + 12].copy_from_slice(&0x3000u32.to_le_bytes()); // dataoff
        data[lc + 12..lc + 16].copy_from_slice(&0x6000u32.to_le_bytes()); // datasize
        data
    }

    #[test]
    fn test_realloc_expands_to_cover_declared_reserve() {
        let data = big_signed_buffer();
        // goblin parses the input without bounds-checking the declared range;
        // MachOFile::parse would (correctly) reject it, which is the bug's symptom.
        let out = realloc_code_sign_space(&data, 0x3000).expect("expansion must succeed");
        let reparsed = crate::macho::MachOFile::parse(out.clone())
            .expect("expanded output must reparse: the declared reserve has to fit");
        let slice = &reparsed.slices()[0];
        let dataoff = slice
            .code_sig_offset
            .expect("output carries LC_CODE_SIGNATURE") as usize;
        let datasize = slice
            .code_sig_size
            .expect("output carries LC_CODE_SIGNATURE") as usize;
        assert!(
            dataoff + datasize <= out.len(),
            "declared signature range {dataoff:#x}+{datasize:#x} must fit in {:#x}-byte output",
            out.len()
        );
        assert_eq!(
            slice.code_length, 0x3000,
            "code region must end at the existing dataoff"
        );
    }

    #[test]
    fn test_realloc_with_metadata_expands_to_cover_declared_reserve() {
        use crate::macho::parser::MachOMetadata;
        let data = big_signed_buffer();
        let metadata = MachOMetadata {
            code_sig_cmd: Some((280, 0x3000, 0x6000)),
            linkedit_cmd: Some((184, 0x2000, 0x1000, 0)),
            max_load_cmd_end: 296,
            first_segment_offset: 0x1000,
            is_big_endian: false,
            is_64: true,
        };
        let (out, meta) = realloc_code_sign_space_with_metadata(&data, &metadata, 0x3000)
            .expect("expansion must succeed");
        let (_, dataoff, datasize) = meta.code_sig_cmd.expect("metadata echoes the command");
        assert!(
            (dataoff as usize) + (datasize as usize) <= out.len(),
            "declared range {dataoff:#x}+{datasize:#x} must fit in {:#x}-byte output",
            out.len()
        );
    }

    #[test]
    fn test_prepare_rejects_reserve_exceeding_buffer_capacity() {
        let data = crate::macho::fixtures::make_minimal_macho(); // 0x2000, unsigned
        let macho = crate::macho::MachOFile::parse(data.clone()).expect("fixture must parse");
        let meta = macho.slices()[0].metadata.clone();
        let mut buf = data;
        let err = prepare_code_in_place(&mut buf, &meta, 0x2000, 0x3000)
            .expect_err("declaring 0x3000 bytes of reserve in a 0x2000 buffer must be refused");
        let msg = match err {
            crate::Error::MachO(m) => m,
            other => panic!("expected MachO error, got {other:?}"),
        };
        assert!(
            msg.contains("reserve"),
            "message must name the reserve: {msg}"
        );
        assert_eq!(buf.len(), 0x2000, "buffer must be untouched on refusal");
    }

    #[test]
    fn test_prepare_capacity_guard_counts_alignment_pad_for_odd_dataoff() {
        // Odd dataoff 0x2001: the signature starts at 0x2010, so a 0x400 reserve
        // ends at 0x2410 — 15 bytes past the 0x2401-byte input the caller passed.
        let signed = crate::macho::fixtures::make_signed_minimal_macho_at(0x2001, 0x400);
        let macho = crate::macho::MachOFile::parse(signed.clone()).expect("odd input must parse");
        let slice = &macho.slices()[0];
        assert_eq!(
            slice.code_length, 0x2001,
            "fixture precondition: odd dataoff"
        );
        let mut buf = signed;
        let err = prepare_code_in_place(&mut buf, &slice.metadata, slice.code_length, 0x400)
            .expect_err("reserve plus the 15-byte alignment pad exceeds the caller's buffer");
        let msg = match err {
            crate::Error::MachO(m) => m,
            other => panic!("expected MachO error, got {other:?}"),
        };
        assert!(
            msg.contains("exceeds"),
            "message must explain the overflow: {msg}"
        );
    }

    #[test]
    fn test_aligned_resign_roundtrip() {
        let first = crate::macho::sign_macho_adhoc(
            &crate::macho::MachOFile::parse(crate::macho::fixtures::make_minimal_macho())
                .expect("fixture parses"),
            "com.example.first",
            None,
            None,
            None,
            false,
        )
        .expect("first sign");
        let second = crate::macho::sign_macho_adhoc(
            &crate::macho::MachOFile::parse(first).expect("first output parses"),
            "com.example.second",
            None,
            None,
            None,
            false,
        )
        .expect("aligned re-sign must succeed");
        crate::macho::MachOFile::parse(second).expect("re-signed output parses");
    }
}
