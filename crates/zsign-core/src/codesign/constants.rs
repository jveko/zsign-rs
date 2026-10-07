//! Apple code signing constants and magic numbers.
//!
//! These constants define the binary format for Apple code signatures,
//! including [`SuperBlob`](super::SuperBlobBuilder) structures, CodeDirectory formats, and hash types.
//!
//! # Magic Numbers
//!
//! All Apple code signature blobs start with a 4-byte magic number in big-endian format.
//! The magic numbers all begin with `0xfade`:
//!
//! - [`CSMAGIC_EMBEDDED_SIGNATURE`] (`0xfade0cc0`): SuperBlob container
//! - [`CSMAGIC_CODEDIRECTORY`] (`0xfade0c02`): CodeDirectory blob
//! - [`CSMAGIC_REQUIREMENTS`] (`0xfade0c01`): Requirements blob
//! - [`CSMAGIC_EMBEDDED_ENTITLEMENTS`] (`0xfade7171`): XML entitlements
//! - [`CSMAGIC_EMBEDDED_DER_ENTITLEMENTS`] (`0xfade7172`): DER entitlements
//! - [`CSMAGIC_EMBEDDED_SIGNATURE_OLD`] (`0xfade0b02`): Legacy embedded signature magic
//! - [`CSMAGIC_LAUNCH_CONSTRAINT`] (`0xfade8181`): All launch-constraint blobs
//!
//! # Slot Types
//!
//! Slot types identify components within a SuperBlob:
//!
//! - [`CSSLOT_CODEDIRECTORY`] (`0x0000`): Primary SHA-1 CodeDirectory
//! - [`CSSLOT_REQUIREMENTS`] (`0x0002`): Code requirements
//! - [`CSSLOT_ENTITLEMENTS`] (`0x0005`): XML entitlements
//! - [`CSSLOT_DER_ENTITLEMENTS`] (`0x0007`): DER entitlements
//! - [`CSSLOT_LAUNCH_CONSTRAINT_SELF`] (`0x0008`) through [`CSSLOT_LIBRARY_CONSTRAINT`]
//!   (`0x000b`): Self, parent, responsible, and library launch constraints
//! - [`CSSLOT_ALTERNATE_CODEDIRECTORIES`] (`0x1000`): SHA-256 CodeDirectory
//! - [`CSSLOT_SIGNATURESLOT`] (`0x10000`): CMS signature
//! - [`CSSLOT_TICKETSLOT`] (`0x10002`): Ticket/notarization slot
//! - [`CSSLOT_SPECIAL_LAUNCH_CONSTRAINT_SELF`] (`-8`) through
//!   [`CSSLOT_SPECIAL_LIBRARY_CONSTRAINT`] (`-11`): corresponding CodeDirectory
//!   special slots for launch constraints

// =============================================================================
// SuperBlob Magic Numbers
// =============================================================================

/// SuperBlob containing all signature components (embedded signature)
pub const CSMAGIC_EMBEDDED_SIGNATURE: u32 = 0xfade0cc0;

/// Legacy embedded signature magic from Apple's headers. Its purpose is
/// undocumented there; this is used only to distinguish the diagnostic case.
pub const CSMAGIC_EMBEDDED_SIGNATURE_OLD: u32 = 0xfade0b02;

/// Magic shared by all four launch-constraint blobs: self, parent,
/// responsible, and library constraints.
pub const CSMAGIC_LAUNCH_CONSTRAINT: u32 = 0xfade8181;

/// CodeDirectory blob magic
pub const CSMAGIC_CODEDIRECTORY: u32 = 0xfade0c02;

/// Requirements blob magic
pub const CSMAGIC_REQUIREMENTS: u32 = 0xfade0c01;

/// Single requirement blob magic
pub const CSMAGIC_REQUIREMENT: u32 = 0xfade0c00;

/// Embedded entitlements (XML plist format)
pub const CSMAGIC_EMBEDDED_ENTITLEMENTS: u32 = 0xfade7171;

/// Embedded DER entitlements (ASN.1 DER format)
pub const CSMAGIC_EMBEDDED_DER_ENTITLEMENTS: u32 = 0xfade7172;

/// CMS signature wrapper blob
pub const CSMAGIC_BLOBWRAPPER: u32 = 0xfade0b01;

// =============================================================================
// Slot Types (for SuperBlob index)
// =============================================================================

/// Main code directory slot (SHA-1)
pub const CSSLOT_CODEDIRECTORY: u32 = 0x0000;

/// Code requirements slot
pub const CSSLOT_REQUIREMENTS: u32 = 0x0002;

/// Entitlements slot (XML format)
pub const CSSLOT_ENTITLEMENTS: u32 = 0x0005;

/// DER entitlements slot
pub const CSSLOT_DER_ENTITLEMENTS: u32 = 0x0007;

/// Launch constraints (self)
pub const CSSLOT_LAUNCH_CONSTRAINT_SELF: u32 = 0x0008;

/// Launch constraints (parent)
pub const CSSLOT_LAUNCH_CONSTRAINT_PARENT: u32 = 0x0009;

/// Launch constraints (responsible)
pub const CSSLOT_LAUNCH_CONSTRAINT_RESPONSIBLE: u32 = 0x000a;

/// Library constraints
pub const CSSLOT_LIBRARY_CONSTRAINT: u32 = 0x000b;

/// Alternate code directories start (SHA-256, SHA-384, etc.)
pub const CSSLOT_ALTERNATE_CODEDIRECTORIES: u32 = 0x1000;

/// Maximum number of alternate code directories
pub const CSSLOT_ALTERNATE_CODEDIRECTORY_MAX: u32 = 5;

/// Limit for alternate code directory slots
pub const CSSLOT_ALTERNATE_CODEDIRECTORY_LIMIT: u32 =
    CSSLOT_ALTERNATE_CODEDIRECTORIES + CSSLOT_ALTERNATE_CODEDIRECTORY_MAX;

/// CMS signature slot
pub const CSSLOT_SIGNATURESLOT: u32 = 0x10000;

/// Ticket/notarization slot. `0x10001` is the CodeDirectory-identification
/// slot used only by detached signatures.
pub const CSSLOT_TICKETSLOT: u32 = 0x10002;

// =============================================================================
// Special Slot Indices (negative, for CodeDirectory)
// =============================================================================

/// Info.plist special slot index
pub const CSSLOT_SPECIAL_INFOSLOT: i32 = -1;

/// Requirements special slot index
pub const CSSLOT_SPECIAL_REQUIREMENTS: i32 = -2;

/// CodeResources special slot index
pub const CSSLOT_SPECIAL_RESOURCEDIR: i32 = -3;

/// Entitlements special slot index
pub const CSSLOT_SPECIAL_ENTITLEMENTS: i32 = -5;

/// DER entitlements special slot index
pub const CSSLOT_SPECIAL_DER_ENTITLEMENTS: i32 = -7;

/// Launch-constraint (self) special slot index
pub const CSSLOT_SPECIAL_LAUNCH_CONSTRAINT_SELF: i32 = -8;

/// Launch-constraint (parent) special slot index
pub const CSSLOT_SPECIAL_LAUNCH_CONSTRAINT_PARENT: i32 = -9;

/// Launch-constraint (responsible) special slot index
pub const CSSLOT_SPECIAL_LAUNCH_CONSTRAINT_RESPONSIBLE: i32 = -10;

/// Library-constraint special slot index
pub const CSSLOT_SPECIAL_LIBRARY_CONSTRAINT: i32 = -11;

// =============================================================================
// Hash Types
// =============================================================================

/// SHA-1 hash (160-bit / 20 bytes)
pub const CS_HASHTYPE_SHA1: u8 = 1;

/// SHA-256 hash (256-bit / 32 bytes)
pub const CS_HASHTYPE_SHA256: u8 = 2;

// =============================================================================
// Hash Sizes
// =============================================================================

/// SHA-1 hash size in bytes
pub const CS_SHA1_LEN: usize = 20;

/// SHA-256 hash size in bytes
pub const CS_SHA256_LEN: usize = 32;

/// SHA-384 hash size in bytes
pub const CS_SHA384_LEN: usize = 48;

/// SHA-512 hash size in bytes
pub const CS_SHA512_LEN: usize = 64;

// =============================================================================
// Code Signature Flags
// =============================================================================

/// Ad-hoc signed (no identity)
pub const CS_ADHOC: u32 = 0x00000002;

/// Code runs with amfi in test mode
pub const CS_RUNTIME: u32 = 0x00010000;

// =============================================================================
// Exec Segment Flags
// =============================================================================

/// Executable segment is main binary
pub const CS_EXECSEG_MAIN_BINARY: u64 = 0x0001;

/// Allow unsigned executable memory
pub const CS_EXECSEG_ALLOW_UNSIGNED: u64 = 0x0010;

/// Process may have debugger attached
pub const CS_EXECSEG_DEBUGGER: u64 = 0x0020;

/// Has JIT entitlement
pub const CS_EXECSEG_JIT: u64 = 0x0040;

/// Skip library validation
pub const CS_EXECSEG_SKIP_LV: u64 = 0x0080;

// =============================================================================
// CodeDirectory Version
// =============================================================================

/// Earliest supported CodeDirectory version
pub const CODEDIRECTORY_VERSION_EARLIEST: u32 = 0x20001;

/// Version with scatter support
pub const CODEDIRECTORY_VERSION_SCATTER: u32 = 0x20100;

/// Version with team ID support
pub const CODEDIRECTORY_VERSION_TEAMID: u32 = 0x20200;

/// Version with code limit 64 support
pub const CODEDIRECTORY_VERSION_CODELIMIT64: u32 = 0x20300;

/// Version with exec segment support (current/latest)
pub const CODEDIRECTORY_VERSION_EXECSEG: u32 = 0x20400;

/// `supportsPreEncrypt` gate for both the runtime and pre-encryption fields.
pub const CODEDIRECTORY_VERSION_PREENCRYPT: u32 = 0x20500;

/// `CS_SUPPORTSRUNTIME` gate for both the runtime and pre-encryption fields.
pub const CODEDIRECTORY_VERSION_RUNTIME: u32 = 0x20500;

/// `CS_SUPPORTSLINKAGE`; the newest CodeDirectory version supported here.
pub const CODEDIRECTORY_VERSION_LINKAGE: u32 = 0x20600;

/// Current/latest version we generate (exec segment support)
pub const CODEDIRECTORY_VERSION: u32 = CODEDIRECTORY_VERSION_EXECSEG;

// =============================================================================
// Page Size
// =============================================================================

/// Standard code signing page size (4KB)
pub const PAGE_SIZE: usize = 4096;

/// Log2 of page size (for CodeDirectory header)
pub const PAGE_SIZE_LOG2: u8 = 12;

// =============================================================================
// Requirements Types
// =============================================================================

/// Requirement type: designated requirement
pub const CSREQ_DESIGNATED: u32 = 0x0003;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_magic_numbers() {
        // Verify magic numbers match Apple's specifications
        assert_eq!(CSMAGIC_EMBEDDED_SIGNATURE, 0xfade0cc0);
        assert_eq!(CSMAGIC_CODEDIRECTORY, 0xfade0c02);
        assert_eq!(CSMAGIC_REQUIREMENTS, 0xfade0c01);
        assert_eq!(CSMAGIC_EMBEDDED_ENTITLEMENTS, 0xfade7171);
        assert_eq!(CSMAGIC_EMBEDDED_DER_ENTITLEMENTS, 0xfade7172);
        assert_eq!(CSMAGIC_BLOBWRAPPER, 0xfade0b01);
    }

    #[test]
    fn test_hash_sizes() {
        assert_eq!(CS_SHA1_LEN, 20);
        assert_eq!(CS_SHA256_LEN, 32);
        assert_eq!(CS_SHA384_LEN, 48);
        assert_eq!(CS_SHA512_LEN, 64);
    }

    #[test]
    fn test_page_size() {
        assert_eq!(PAGE_SIZE, 4096);
        assert_eq!(1 << PAGE_SIZE_LOG2, PAGE_SIZE);
    }

    #[test]
    fn test_codedirectory_version() {
        // Current version should be 0x20400 (exec segment support)
        assert_eq!(CODEDIRECTORY_VERSION, 0x20400);
    }

    #[test]
    fn test_slot_types() {
        assert_eq!(CSSLOT_CODEDIRECTORY, 0x0000);
        assert_eq!(CSSLOT_REQUIREMENTS, 0x0002);
        assert_eq!(CSSLOT_ENTITLEMENTS, 0x0005);
        assert_eq!(CSSLOT_DER_ENTITLEMENTS, 0x0007);
        assert_eq!(CSSLOT_ALTERNATE_CODEDIRECTORIES, 0x1000);
        assert_eq!(CSSLOT_SIGNATURESLOT, 0x10000);
    }

    #[test]
    fn ticket_slot_is_the_notarization_slot() {
        assert_eq!(CSSLOT_TICKETSLOT, 0x10002); // Apple blob.h: 0x10001 is the cd-identification slot
    }

    #[test]
    fn version_gate_values_match_apple() {
        assert_eq!(CODEDIRECTORY_VERSION_SCATTER, 0x20100);
        assert_eq!(CODEDIRECTORY_VERSION_TEAMID, 0x20200);
        assert_eq!(CODEDIRECTORY_VERSION_CODELIMIT64, 0x20300);
        assert_eq!(CODEDIRECTORY_VERSION_EXECSEG, 0x20400);
        assert_eq!(CODEDIRECTORY_VERSION_RUNTIME, 0x20500);
        assert_eq!(CODEDIRECTORY_VERSION_LINKAGE, 0x20600);
        assert_eq!(CODEDIRECTORY_VERSION, 0x20400); // unchanged alias target
    }
}
