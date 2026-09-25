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

/// FairPlay encryption state from `LC_ENCRYPTION_INFO` / `LC_ENCRYPTION_INFO_64`.
///
/// `cryptid != 0 && cryptsize != 0` marks an encrypted slice: at exec the
/// kernel decrypts the `[cryptoff, cryptoff+cryptsize)` range of `__TEXT`,
/// so re-signing the on-disk ciphertext yields a signature that no longer
/// matches the decrypted pages (AMFI kill / install abort).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncryptionInfo {
    /// File offset of the encrypted range.
    pub cryptoff: u32,
    /// File size of the encrypted range.
    pub cryptsize: u32,
    /// Encryption system: 0 = not encrypted, 1 = FairPlay, 0x10 = NULL.
    pub cryptid: u32,
}

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
    /// Lowest file offset of file-backed content (nonzero sections and nonzero fileoff/filesize segments), bounding load-command insertion; 4096 when none exists.
    pub first_segment_offset: usize,
    /// Whether the binary is big-endian.
    pub is_big_endian: bool,
    /// Whether this is a 64-bit binary.
    pub is_64: bool,
}

/// True when the Mach-O image starting at byte `base` is big-endian. Detection
/// keys on the byte-swapped magic constants (CIGAM == on-disk big-endian),
/// which is exactly equivalent to comparing the raw prefix against the
/// big-endian magic byte patterns.
pub(crate) fn is_big_endian_macho(data: &[u8], base: usize) -> bool {
    base.checked_add(4)
        .and_then(|end| data.get(base..end))
        .map(|raw| {
            let magic = u32::from_le_bytes(raw.try_into().expect("4-byte slice"));
            matches!(
                magic,
                goblin::mach::header::MH_CIGAM
                    | goblin::mach::header::MH_CIGAM_64
                    | goblin::mach::fat::FAT_CIGAM
            )
        })
        .unwrap_or(false)
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
    /// File-backed size of the `__TEXT` segment (`filesize`, excluding
    /// zero-fill) — the `execSegLimit` value and the `text_segment_filesize`
    /// member of the fileoff/filesize rider pair.
    pub text_segment_size: u64,
    /// Base virtual address of `__TEXT` (vmaddr — consumed by the verifier's
    /// exact-match arm; NOT emitted as execSegBase).
    pub text_segment_base: u64,
    /// File offset of the `__TEXT` segment (slice-relative). Emitted as
    /// `execSegBase` per Apple convention (`machorep.cpp`: `__TEXT.fileoff`).
    pub text_segment_fileoff: u64,
    /// Length of code to be signed: the existing signature start
    /// (`LC_CODE_SIGNATURE.dataoff`), or the full declared size for unsigned
    /// slices (thin: whole file).
    pub code_length: usize,
    /// Cached load command metadata for writer functions.
    pub metadata: MachOMetadata,
    /// FairPlay encryption info from `LC_ENCRYPTION_INFO(_64)`, if present.
    pub encryption: Option<EncryptionInfo>,
}

impl ArchSlice {
    /// Returns the readable architecture name for this slice's CPU type
    /// (e.g. `arm64`, `x86_64`), for reports and diagnostics.
    pub fn arch_name(&self) -> String {
        match self.cpu_type {
            0x0100_000C => "arm64".to_string(),    // CPU_TYPE_ARM64
            0x0200_000C => "arm64_32".to_string(), // CPU_TYPE_ARM64_32
            0x0000_000C => "arm".to_string(),      // CPU_TYPE_ARM
            0x0100_0007 => "x86_64".to_string(),   // CPU_TYPE_X86_64
            0x0000_0007 => "i386".to_string(),     // CPU_TYPE_X86
            other => format!("cpu:{other:#010x}"),
        }
    }
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
        let mach =
            Mach::parse(bytes).map_err(|e| Error::MachO(format!("Failed to parse: {}", e)))?;

        let (is_fat, slices) = match mach {
            Mach::Binary(macho) => {
                let slice = Self::parse_single(bytes, &macho, 0, bytes.len())?;
                (false, vec![slice])
            }
            Mach::Fat(fat) => {
                let mut slices = Vec::new();
                for (i, arch) in fat.iter_arches().enumerate() {
                    let arch = arch.map_err(|e| Error::MachO(format!("Fat arch {}: {}", i, e)))?;
                    let offset = arch.offset as usize;
                    let size = arch.size as usize;
                    let end = offset
                        .checked_add(size)
                        .ok_or_else(|| Error::MachO(format!("FAT slice {}: offset overflow", i)))?;
                    if end > bytes.len() {
                        return Err(Error::MachO(format!(
                            "FAT slice {}: extends beyond file (offset={}, size={}, file_len={})",
                            i,
                            offset,
                            size,
                            bytes.len()
                        )));
                    }
                    let slice_data = &bytes[offset..end];

                    let macho = MachO::parse(slice_data, 0)
                        .map_err(|e| Error::MachO(format!("Slice {}: {}", i, e)))?;

                    let mut slice = Self::parse_single(bytes, &macho, offset, size)?;
                    slice.offset = offset;
                    slice.size = size;
                    slices.push(slice);
                }
                (true, slices)
            }
        };

        Ok(Self {
            data,
            is_fat,
            slices,
        })
    }

    fn parse_single(
        data: &[u8],
        macho: &MachO,
        base_offset: usize,
        declared_size: usize,
    ) -> Result<ArchSlice> {
        let is_executable = macho.header.filetype == MH_EXECUTE;
        let is_64 = macho.header.magic == MH_MAGIC_64 || macho.header.magic == MH_CIGAM_64;
        let cpu_type = macho.header.cputype;

        let mut code_sig_offset = None;
        let mut code_sig_size = None;
        let mut text_segment_size = 0u64;
        let mut text_segment_base = 0u64;
        let mut text_segment_fileoff = 0u64;
        let mut encryption = None;

        let mut meta_code_sig_cmd = None;
        let mut meta_linkedit_cmd = None;
        let mut max_load_cmd_end: usize = 0;
        let mut first_segment_offset: u64 = u64::MAX;

        for segment in &macho.segments {
            if let Ok(sections) = segment.sections() {
                for (section, _) in sections {
                    if section.size > 0 && section.offset > 0 {
                        let section_offset = section.offset as u64;
                        if section_offset < first_segment_offset {
                            first_segment_offset = section_offset;
                        }
                    }
                }
            }
        }

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
                        text_segment_size = seg.filesize;
                        text_segment_base = seg.vmaddr;
                        text_segment_fileoff = seg.fileoff;
                    }
                    if seg.segname.starts_with(b"__LINKEDIT") {
                        meta_linkedit_cmd =
                            Some((lc.offset, seg.fileoff, seg.vmsize, seg.filesize));
                    }
                    if seg.fileoff > 0 && seg.filesize > 0 && seg.fileoff < first_segment_offset {
                        first_segment_offset = seg.fileoff;
                    }
                }
                CommandVariant::Segment32(ref seg) => {
                    if seg.segname.starts_with(b"__TEXT") {
                        text_segment_size = seg.filesize as u64;
                        text_segment_base = seg.vmaddr as u64;
                        text_segment_fileoff = seg.fileoff as u64;
                    }
                    if seg.fileoff > 0
                        && seg.filesize > 0
                        && (seg.fileoff as u64) < first_segment_offset
                    {
                        first_segment_offset = seg.fileoff as u64;
                    }
                }
                CommandVariant::EncryptionInfo32(ref enc) => {
                    record_encryption(&mut encryption, enc.cryptoff, enc.cryptsize, enc.cryptid);
                }
                CommandVariant::EncryptionInfo64(ref enc) => {
                    record_encryption(&mut encryption, enc.cryptoff, enc.cryptsize, enc.cryptid);
                }
                _ => {}
            }
        }

        // Validate code signature bounds
        if let (Some(dataoff), Some(datasize)) = (code_sig_offset, code_sig_size) {
            let sig_end = (dataoff as usize)
                .checked_add(datasize as usize)
                .ok_or_else(|| Error::MachO("LC_CODE_SIGNATURE: offset + size overflow".into()))?;
            if sig_end > declared_size {
                return Err(Error::MachO(format!(
                    "LC_CODE_SIGNATURE extends beyond slice: offset={}, size={}, slice_len={}",
                    dataoff, datasize, declared_size
                )));
            }
        }

        // Validate __LINKEDIT bounds
        if let Some((_, fileoff, _, filesize)) = meta_linkedit_cmd {
            let linkedit_end = (fileoff as usize)
                .checked_add(filesize as usize)
                .ok_or_else(|| Error::MachO("__LINKEDIT: fileoff + filesize overflow".into()))?;
            if linkedit_end > declared_size {
                return Err(Error::MachO(format!(
                    "__LINKEDIT extends beyond slice: fileoff={}, filesize={}, slice_len={}",
                    fileoff, filesize, declared_size
                )));
            }
        }

        let computed_first_segment_offset = if first_segment_offset == u64::MAX {
            4096
        } else {
            first_segment_offset as usize
        };

        let is_big_endian = is_big_endian_macho(data, base_offset);

        let code_length = code_sig_offset.map(|o| o as usize).unwrap_or(declared_size);

        if code_length > declared_size {
            return Err(Error::MachO(format!(
                "code_length exceeds declared slice size: code_length={}, declared_size={}",
                code_length, declared_size
            )));
        }

        Ok(ArchSlice {
            offset: 0,
            size: declared_size,
            cpu_type,
            is_64,
            is_executable,
            code_sig_offset,
            code_sig_size,
            text_segment_size,
            text_segment_base,
            text_segment_fileoff,
            code_length,
            metadata: MachOMetadata {
                code_sig_cmd: meta_code_sig_cmd,
                linkedit_cmd: meta_linkedit_cmd,
                max_load_cmd_end,
                first_segment_offset: computed_first_segment_offset,
                is_big_endian,
                is_64,
            },
            encryption,
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

impl ArchSlice {
    /// Whether the kernel will attempt FairPlay decryption of this slice.
    ///
    /// Matches xnu: `cryptid != 0` selects a decrypter, but the kernel
    /// ignores the entire command when `cryptsize == 0`.
    pub fn is_encrypted(&self) -> bool {
        match &self.encryption {
            Some(e) => e.cryptid != 0 && e.cryptsize != 0,
            None => false,
        }
    }
}

/// Records encryption info from an `LC_ENCRYPTION_INFO(_64)` load command.
///
/// Shared by the 32-bit and 64-bit match arms (goblin types differ, so the
/// or-pattern cannot bind both); field remapping lives in one place.
fn record_encryption(
    encryption: &mut Option<EncryptionInfo>,
    cryptoff: u32,
    cryptsize: u32,
    cryptid: u32,
) {
    *encryption = Some(EncryptionInfo {
        cryptoff,
        cryptsize,
        cryptid,
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_rejects_garbage() {
        let result = MachOFile::parse(vec![0xFF; 1000]);
        assert!(result.is_err());
    }

    /// Build a minimal arm64 MH_EXECUTE with an injected LC_ENCRYPTION_INFO_64.
    /// `cryptsize == 0` is the kernel-ignored (decrypted) form.
    fn minimal_macho_with_encryption(cryptid: u32, cryptsize: u32) -> Vec<u8> {
        let mut b = Vec::with_capacity(0x2000);

        macro_rules! u32 {
            ($v:expr) => {
                b.extend_from_slice(&($v as u32).to_le_bytes())
            };
        }
        macro_rules! u64 {
            ($v:expr) => {
                b.extend_from_slice(&($v as u64).to_le_bytes())
            };
        }
        macro_rules! name {
            ($s:expr, $len:expr) => {
                let mut n = [0u8; 16];
                n[..$s.len()].copy_from_slice($s.as_bytes());
                b.extend_from_slice(&n[..$len]);
            };
        }

        // mach_header_64
        u32!(0xfeedfacf); // MH_MAGIC_64
        u32!(0x0100_000c); // CPU_TYPE_ARM64
        u32!(0x0000_0000); // CPU_SUBTYPE_ARM64_ALL
        u32!(2); // MH_EXECUTE
        u32!(4); // ncmds: __TEXT, __LINKEDIT, build version, encryption info
        u32!(152 + 72 + 24 + 24); // sizeofcmds
        u32!(0x1); // MH_NOUNDEFS
        u32!(0); // reserved

        // LC_SEGMENT_64 "__TEXT" (152 bytes, one section)
        u32!(0x19);
        u32!(152);
        name!("__TEXT", 16);
        u64!(0x1_0000_0000); // vmaddr
        u64!(0x1000); // vmsize
        u64!(0x1000); // fileoff
        u64!(0x1000); // filesize
        u32!(7); // maxprot
        u32!(7); // initprot
        u32!(1); // nsects
        u32!(0); // flags
        name!("__text", 16);
        name!("__TEXT", 16);
        u64!(0x1_0000_0000); // addr
        u64!(4); // size
        u32!(0x1000); // file offset of code
        u32!(0); // align
        u32!(0); // reloff
        u32!(0); // nreloc
        u32!(0); // flags
        u32!(0); // reserved1
        u32!(0); // reserved2
        u32!(0); // reserved3

        // LC_SEGMENT_64 "__LINKEDIT" (72 bytes, no sections)
        u32!(0x19);
        u32!(72);
        name!("__LINKEDIT", 16);
        u64!(0x1_0000_1000); // vmaddr
        u64!(0x1000); // vmsize
        u64!(0x2000); // fileoff
        u64!(0); // filesize
        u32!(1); // maxprot
        u32!(1); // initprot
        u32!(0); // nsects
        u32!(0); // flags

        // LC_BUILD_VERSION (24 bytes)
        u32!(0x32);
        u32!(24);
        u32!(1); // macOS
        u32!(0x000f_0000); // minos 15.0
        u32!(0x000f_0000); // sdk 15.0
        u32!(0); // ntools

        // LC_ENCRYPTION_INFO_64 (24 bytes)
        u32!(0x2c);
        u32!(24);
        u32!(0x1000); // cryptoff
        u32!(cryptsize);
        u32!(cryptid);
        u32!(0); // pad

        // Zero-fill first page, code at 0x1000, pad through __LINKEDIT page
        b.resize(0x1000, 0);
        b.extend_from_slice(&[0x1f, 0x20, 0x03, 0xd5]);
        b.resize(0x2000, 0);
        b
    }

    #[test]
    fn test_parse_records_encryption_info() {
        let data = minimal_macho_with_encryption(1, 0x1000);
        let macho = MachOFile::parse(data).expect("encrypted mach-o must parse");
        let slice = &macho.slices()[0];
        assert!(slice.is_64, "arm64 slice must be 64-bit");
        let enc = slice.encryption.as_ref().expect("encryption info recorded");
        assert_eq!(enc.cryptoff, 0x1000);
        assert_eq!(enc.cryptsize, 0x1000);
        assert_eq!(enc.cryptid, 1);
        assert!(
            slice.is_encrypted(),
            "cryptid=1 + cryptsize>0 must be encrypted"
        );
    }

    #[test]
    fn test_parse_plain_macho_is_not_encrypted() {
        let data = minimal_macho_with_encryption(0, 0x1000);
        let macho = MachOFile::parse(data).unwrap();
        assert_eq!(
            macho.slices()[0].encryption.as_ref().map(|e| e.cryptid),
            Some(0)
        );
        assert!(
            !macho.slices()[0].is_encrypted(),
            "cryptid=0 must not be encrypted"
        );
    }

    #[test]
    fn test_parse_cryptsize_zero_is_not_encrypted() {
        // Kernel ignores cryptid when cryptsize == 0 (cleaned binary runs fine).
        let data = minimal_macho_with_encryption(1, 0);
        let macho = MachOFile::parse(data).unwrap();
        assert!(
            !macho.slices()[0].is_encrypted(),
            "cryptsize=0 must not be treated as encrypted"
        );
    }

    /// Build a minimal arm64 MH_EXECUTE with NO encryption load command.
    /// Mirrors [`minimal_macho_with_encryption`] minus the
    /// `LC_ENCRYPTION_INFO_64` (ncmds 4→3, sizeofcmds −24).
    fn minimal_macho_plain() -> Vec<u8> {
        let mut b = Vec::with_capacity(0x2000);

        macro_rules! u32 {
            ($v:expr) => {
                b.extend_from_slice(&($v as u32).to_le_bytes())
            };
        }
        macro_rules! u64 {
            ($v:expr) => {
                b.extend_from_slice(&($v as u64).to_le_bytes())
            };
        }
        macro_rules! name {
            ($s:expr, $len:expr) => {
                let mut n = [0u8; 16];
                n[..$s.len()].copy_from_slice($s.as_bytes());
                b.extend_from_slice(&n[..$len]);
            };
        }

        // mach_header_64
        u32!(0xfeedfacf); // MH_MAGIC_64
        u32!(0x0100_000c); // CPU_TYPE_ARM64
        u32!(0x0000_0000); // CPU_SUBTYPE_ARM64_ALL
        u32!(2); // MH_EXECUTE
        u32!(3); // ncmds: __TEXT, __LINKEDIT, build version
        u32!(152 + 72 + 24); // sizeofcmds
        u32!(0x1); // MH_NOUNDEFS
        u32!(0); // reserved

        // LC_SEGMENT_64 "__TEXT" (152 bytes, one section)
        u32!(0x19);
        u32!(152);
        name!("__TEXT", 16);
        u64!(0x1_0000_0000); // vmaddr
        u64!(0x1000); // vmsize
        u64!(0x1000); // fileoff
        u64!(0x1000); // filesize
        u32!(7); // maxprot
        u32!(7); // initprot
        u32!(1); // nsects
        u32!(0); // flags
        name!("__text", 16);
        name!("__TEXT", 16);
        u64!(0x1_0000_0000); // addr
        u64!(4); // size
        u32!(0x1000); // file offset of code
        u32!(0); // align
        u32!(0); // reloff
        u32!(0); // nreloc
        u32!(0); // flags
        u32!(0); // reserved1
        u32!(0); // reserved2
        u32!(0); // reserved3

        // LC_SEGMENT_64 "__LINKEDIT" (72 bytes, no sections)
        u32!(0x19);
        u32!(72);
        name!("__LINKEDIT", 16);
        u64!(0x1_0000_1000); // vmaddr
        u64!(0x1000); // vmsize
        u64!(0x2000); // fileoff
        u64!(0); // filesize
        u32!(1); // maxprot
        u32!(1); // initprot
        u32!(0); // nsects
        u32!(0); // flags

        // LC_BUILD_VERSION (24 bytes)
        u32!(0x32);
        u32!(24);
        u32!(1); // macOS
        u32!(0x000f_0000); // minos 15.0
        u32!(0x000f_0000); // sdk 15.0
        u32!(0); // ntools

        // Zero-fill first page, code at 0x1000, pad through __LINKEDIT page
        b.resize(0x1000, 0);
        b.extend_from_slice(&[0x1f, 0x20, 0x03, 0xd5]);
        b.resize(0x2000, 0);
        b
    }

    #[test]
    fn test_parse_no_encryption_command_is_none() {
        // A binary without any LC_ENCRYPTION_INFO(_64) — the common case.
        let data = minimal_macho_plain();
        assert_eq!(data.len(), 0x2000);
        let macho = MachOFile::parse(data).unwrap();
        let slice = &macho.slices()[0];
        assert!(slice.encryption.is_none(), "no command means None");
        assert!(!slice.is_encrypted(), "None means not encrypted");
    }

    /// Build a minimal 32-bit (armv7) MH_EXECUTE with LC_ENCRYPTION_INFO
    /// (cmd 0x21, 20 bytes) — exercises the EncryptionInfo32 parse arm.
    fn minimal_macho_32_with_encryption() -> Vec<u8> {
        let mut b = Vec::with_capacity(0x80);
        macro_rules! u32 {
            ($v:expr) => {
                b.extend_from_slice(&($v as u32).to_le_bytes())
            };
        }

        // mach_header (28 bytes)
        u32!(0xfeedface); // MH_MAGIC
        u32!(0x0000_000c); // CPU_TYPE_ARM
        u32!(0x0000_0009); // CPU_SUBTYPE_ARM_V7
        u32!(2); // MH_EXECUTE
        u32!(1); // ncmds
        u32!(20); // sizeofcmds
        u32!(0x1); // MH_NOUNDEFS

        // LC_ENCRYPTION_INFO (20 bytes)
        u32!(0x21);
        u32!(20);
        u32!(0x1000); // cryptoff
        u32!(0x2000); // cryptsize
        u32!(1); // cryptid

        b.resize(0x80, 0);
        b
    }

    #[test]
    fn test_parse_32bit_encryption_info() {
        let data = minimal_macho_32_with_encryption();
        let macho = MachOFile::parse(data).expect("32-bit encrypted mach-o must parse");
        let slice = &macho.slices()[0];
        assert!(!slice.is_64, "armv7 slice must be 32-bit");
        let enc = slice.encryption.as_ref().expect("encryption info recorded");
        assert_eq!(enc.cryptid, 1);
        assert_eq!(enc.cryptoff, 0x1000);
        assert_eq!(enc.cryptsize, 0x2000);
        assert!(slice.is_encrypted(), "32-bit cryptid=1 must be encrypted");
    }

    #[test]
    fn test_fileoff0_metadata_bound_is_first_section() {
        let data = crate::macho::fixtures::make_text_fileoff0_macho(false);
        let macho = super::MachOFile::parse(data).expect("fixture must parse");
        let meta = &macho.slices()[0].metadata;
        assert_eq!(
            meta.first_segment_offset, 0x400,
            "metadata insertion bound must come from the first file-backed section"
        );
    }

    #[test]
    fn test_text_segment_size_is_file_backed_extent() {
        let data = crate::macho::fixtures::make_minimal_macho_text_vmsize_pad();
        let macho = super::MachOFile::parse(data).expect("fixture must parse");
        let slice = &macho.slices()[0];
        assert_eq!(
            slice.text_segment_size, 0x1000,
            "execSegLimit input must be __TEXT.filesize, not vmsize (zero-fill excluded)"
        );
        assert_eq!(
            slice.text_segment_base, 0x1_0000_0000,
            "execSegBase input stays the segment base"
        );
    }

    #[test]
    fn test_exec_seg_limit_written_from_filesize() {
        let data = crate::macho::fixtures::make_minimal_macho_text_vmsize_pad();
        let macho = super::MachOFile::parse(data).expect("fixture must parse");
        let signed =
            crate::macho::sign_macho_adhoc(&macho, "com.example.textpad", None, None, None, false)
                .expect("sign must succeed");
        let reparsed = super::MachOFile::parse(signed.clone()).expect("signed output parses");
        let slice = &reparsed.slices()[0];
        let off = slice.code_sig_offset.expect("signed") as usize;
        let size = slice.code_sig_size.expect("signed") as usize;
        let superblob = crate::codesign::verify::parse_superblob(&signed[off..off + size])
            .expect("embedded superblob parses");
        let cd = superblob
            .code_directory
            .as_ref()
            .expect("code directory present");
        let exec_seg_limit = u64::from_be_bytes(cd.raw()[72..80].try_into().unwrap());
        assert_eq!(exec_seg_limit, 0x1000,
            "CodeDirectory execSegLimit must equal __TEXT.filesize (byte offsets as in signer.rs:1400-1403)");
    }

    #[test]
    fn test_unsigned_fat_code_length_covers_declared_size() {
        use crate::macho::fixtures::{make_fat_macho, make_minimal_macho};

        let mut a = make_minimal_macho();
        let declared = a.len() + 0x400;
        // Trailing bytes past the last file-backed segment, still inside the
        // arch's declared fat_arch size: they are code and must be hashed.
        a.extend(std::iter::repeat(0xAB).take(0x400));
        let fat = make_fat_macho(&[a, make_minimal_macho()], &[12, 12]);
        let macho = MachOFile::parse(fat).expect("fixture must parse");
        let slice = &macho.slices()[0];
        assert_eq!(
            slice.code_length, declared,
            "unsigned FAT slices must hash up to the declared arch size, not the last segment end"
        );
        assert_eq!(
            slice.size, declared,
            "declared arch size must include the tail"
        );
    }

    #[test]
    fn test_text_segment_fileoff_is_exposed() {
        let macho = MachOFile::parse(crate::macho::fixtures::make_minimal_macho()).unwrap();
        let slice = &macho.slices()[0];
        assert_eq!(
            slice.text_segment_fileoff, 0x1000,
            "__TEXT fileoff of the fixture"
        );
        assert_eq!(
            slice.text_segment_base, 0x1_0000_0000,
            "vmaddr arm stays for the verifier"
        );
        assert_eq!(
            slice.text_segment_size, 0x1000,
            "file-backed size (the filesize rider field)"
        );
    }
}
