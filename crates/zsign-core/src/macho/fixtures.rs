//! Shared in-memory Mach-O fixtures for zsign-core tests (test builds only).

/// Minimal thin-arm64 Mach-O bytes: `__TEXT` with a tiny `__text` section and
/// a `__LINKEDIT` segment sized for signature insertion. No `LC_CODE_SIGNATURE`
/// — an unsigned input for signing/verification tests.
pub(crate) fn make_minimal_macho() -> Vec<u8> {
    let mut b = Vec::new();
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
    u32!(3); // ncmds
    u32!(152 + 72 + 24); // sizeofcmds
    u32!(0x1); // MH_NOUNDEFS
    u32!(0); // reserved

    // LC_SEGMENT_64 "__TEXT" (152 bytes, one section)
    u32!(0x19);
    u32!(152);
    name!("__TEXT", 16);
    u64!(0x1_0000_0000); // vmaddr
    u64!(0x1000); // vmsize
    u64!(0x1000); // fileoff: leaves room for load commands
    u64!(0x1000); // filesize
    u32!(7); // maxprot
    u32!(7); // initprot
    u32!(1); // nsects
    u32!(0); // flags
    name!("__text", 16);
    name!("__TEXT", 16);
    u64!(0x1_0000_0000); // addr
    u64!(4); // size
    u32!(0x1000); // absolute file offset of the code
    u32!(0); // align
    u32!(0); // reloff
    u32!(0); // nreloc
    u32!(0); // flags
    u32!(0); // reserved1
    u32!(0); // reserved2
    u32!(0); // reserved3

    // LC_SEGMENT_64 "__LINKEDIT" (72 bytes, no sections) — the signature
    // is appended after this segment.
    u32!(0x19);
    u32!(72);
    name!("__LINKEDIT", 16);
    u64!(0x1_0000_1000); // vmaddr
    u64!(0x1000); // vmsize
    u64!(0x2000); // fileoff
    u64!(0); // filesize
    u32!(1); // maxprot (read-only)
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

    // Zero-fill the first page (load-command area, alignment), place the
    // 4-byte __text code at 0x1000, then pad through the __LINKEDIT page.
    b.resize(0x1000, 0);
    b.extend_from_slice(&[0x1f, 0x20, 0x03, 0xd5]);
    b.resize(0x2000, 0);
    b
}
/// `make_minimal_macho` extended with an existing LC_CODE_SIGNATURE whose
/// `slot_len`-byte slot begins at 0x2000 (inside `__LINKEDIT`, whose filesize
/// covers the slot), filled with 0xAA. Builds a parseable already-signed image.
pub(crate) fn make_signed_minimal_macho(slot_len: u32) -> Vec<u8> {
    make_signed_minimal_macho_at(0x2000, slot_len)
}

/// As `make_signed_minimal_macho`, but the signature starts at an arbitrary
/// (possibly unaligned) `dataoff`.
pub(crate) fn make_signed_minimal_macho_at(dataoff: u32, slot_len: u32) -> Vec<u8> {
    let mut b = make_minimal_macho();
    let ncmds = u32::from_le_bytes(b[16..20].try_into().unwrap());
    let sizeofcmds = u32::from_le_bytes(b[20..24].try_into().unwrap());
    b[16..20].copy_from_slice(&(ncmds + 1).to_le_bytes());
    b[20..24].copy_from_slice(&(sizeofcmds + 16).to_le_bytes());
    let lc = 32 + sizeofcmds as usize; // 280
    b[lc..lc + 4].copy_from_slice(&0x1du32.to_le_bytes());
    b[lc + 4..lc + 8].copy_from_slice(&16u32.to_le_bytes());
    b[lc + 8..lc + 12].copy_from_slice(&dataoff.to_le_bytes());
    b[lc + 12..lc + 16].copy_from_slice(&slot_len.to_le_bytes());
    // __LINKEDIT filesize (LC at 184, field at +48) covers the slot tail.
    let linkedit_end = dataoff as u64 + slot_len as u64;
    b[232..240].copy_from_slice(&(linkedit_end - 0x2000).to_le_bytes());
    b.resize(linkedit_end as usize, 0);
    for byte in &mut b[dataoff as usize..] {
        *byte = 0xAA;
    }
    b
}

/// Byte-for-byte layout of [`make_minimal_macho`], with every integer encoded
/// big-endian.
pub(crate) fn make_minimal_macho_be() -> Vec<u8> {
    let mut b = Vec::new();
    macro_rules! u32 {
        ($v:expr) => {
            b.extend_from_slice(&($v as u32).to_be_bytes())
        };
    }
    macro_rules! u64 {
        ($v:expr) => {
            b.extend_from_slice(&($v as u64).to_be_bytes())
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
    u32!(3); // ncmds
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
    u32!(0x1000); // absolute file offset of the code
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

    b.resize(0x1000, 0);
    b.extend_from_slice(&[0x1f, 0x20, 0x03, 0xd5]);
    b.resize(0x2000, 0);
    assert_eq!(&b[0..4], &[0xfe, 0xed, 0xfa, 0xcf], "BE fixture prefix");
    assert_eq!(b.len(), 0x2000, "BE fixture length");
    b
}

/// [`make_minimal_macho`] with an appended `LC_ENCRYPTION_INFO_64` load
/// command (FairPlay-encrypted binary shape), for refusal/verify tests.
pub(crate) fn make_minimal_macho_encrypted(cryptid: u32, cryptsize: u32) -> Vec<u8> {
    let mut data = make_minimal_macho();
    // ncmds (offset 16) and sizeofcmds (offset 20) live in mach_header_64.
    let ncmds = u32::from_le_bytes(data[16..20].try_into().unwrap());
    let sizeofcmds = u32::from_le_bytes(data[20..24].try_into().unwrap());
    data[16..20].copy_from_slice(&(ncmds + 1).to_le_bytes());
    data[20..24].copy_from_slice(&(sizeofcmds + 24).to_le_bytes());
    // Append LC_ENCRYPTION_INFO_64 right after the last load command.
    let off = 32 + sizeofcmds as usize;
    let lc: [u32; 6] = [0x2c, 24, 0x1000, cryptsize, cryptid, 0];
    for (i, v) in lc.iter().enumerate() {
        data[off + i * 4..off + i * 4 + 4].copy_from_slice(&v.to_le_bytes());
    }
    data
}

/// Realistic two-segment arm64 Mach-O with `__TEXT.fileoff == 0` (the layout
/// produced by the linker) and a `__text` section inside `__TEXT`.
/// With `tight_gap`, the section starts only 8 bytes after the last load
/// command, i.e. there is no room to append a 16-byte load command.
pub(crate) fn make_text_fileoff0_macho(tight_gap: bool) -> Vec<u8> {
    let mut b = Vec::new();
    macro_rules! u32w {
        ($v:expr) => {
            b.extend_from_slice(&($v as u32).to_le_bytes())
        };
    }
    macro_rules! u64w {
        ($v:expr) => {
            b.extend_from_slice(&($v as u64).to_le_bytes())
        };
    }
    macro_rules! name {
        ($s:expr, $len:expr) => {{
            let mut n = [0u8; 16];
            n[..$s.len()].copy_from_slice($s.as_bytes());
            b.extend_from_slice(&n[..$len]);
        }};
    }
    u32w!(0xfeedfacf); // MH_MAGIC_64
    u32w!(0x0100_000c); // CPU_TYPE_ARM64
    u32w!(0);
    u32w!(2); // MH_EXECUTE
    u32w!(3); // ncmds
    u32w!(152 + 72 + 24); // sizeofcmds = 248
    u32w!(1); // MH_NOUNDEFS
    u32w!(0);
    // LC_SEGMENT_64 "__TEXT": fileoff 0, filesize 0x1000, one __text section
    u32w!(0x19);
    u32w!(152);
    name!("__TEXT", 16);
    u64w!(0x1_0000_0000);
    u64w!(0x1000);
    u64w!(0);
    u64w!(0x1000);
    u32w!(7);
    u32w!(7);
    u32w!(1);
    u32w!(0);
    name!("__text", 16);
    name!("__TEXT", 16);
    u64w!(0x1_0000_0000); // addr
    u64w!(4); // size
    u32w!(if tight_gap { 32 + 248 + 8 } else { 0x400 }); // section file offset
    u32w!(0);
    u32w!(0);
    u32w!(0);
    u32w!(0x8000_0400); // S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS
    u32w!(0);
    u32w!(0);
    u32w!(0);
    // LC_SEGMENT_64 "__LINKEDIT": fileoff 0x1000, filesize 0 (signature home)
    u32w!(0x19);
    u32w!(72);
    name!("__LINKEDIT", 16);
    u64w!(0x1_0000_1000);
    u64w!(0x1000);
    u64w!(0x1000);
    u64w!(0);
    u32w!(1);
    u32w!(1);
    u32w!(0);
    u32w!(0);
    // LC_BUILD_VERSION (24 bytes)
    u32w!(0x32);
    u32w!(24);
    u32w!(1);
    u32w!(0x000f_0000);
    u32w!(0x000f_0000);
    u32w!(0);
    assert_eq!(b.len(), 280, "load commands end at 32 + 248");
    b.resize(0x1000, 0);
    b.extend_from_slice(&[0x1f, 0x20, 0x03, 0xd5]); // __text at 0x1000
    b.resize(0x2000, 0);
    b
}
