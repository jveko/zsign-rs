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
