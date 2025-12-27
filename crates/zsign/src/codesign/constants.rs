//! Apple code signing constants and magic numbers
//!
//! These constants define the binary format for Apple code signatures,
//! including SuperBlob structures, CodeDirectory formats, and hash types.

// =============================================================================
// SuperBlob Magic Numbers
// =============================================================================

/// SuperBlob containing all signature components (embedded signature)
pub const CSMAGIC_EMBEDDED_SIGNATURE: u32 = 0xfade0cc0;

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

/// Detached signature magic
pub const CSMAGIC_DETACHED_SIGNATURE: u32 = 0xfade0cc1;

// =============================================================================
// Slot Types (for SuperBlob index)
// =============================================================================

/// Main code directory slot (SHA-1)
pub const CSSLOT_CODEDIRECTORY: u32 = 0x0000;

/// Info.plist slot
pub const CSSLOT_INFOSLOT: u32 = 0x0001;

/// Code requirements slot
pub const CSSLOT_REQUIREMENTS: u32 = 0x0002;

/// Resource directory (CodeResources) slot
pub const CSSLOT_RESOURCEDIR: u32 = 0x0003;

/// Application-specific slot
pub const CSSLOT_APPLICATION: u32 = 0x0004;

/// Entitlements slot (XML format)
pub const CSSLOT_ENTITLEMENTS: u32 = 0x0005;

/// Rep-specific slot
pub const CSSLOT_REP_SPECIFIC: u32 = 0x0006;

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

/// Ticket/notarization slot
pub const CSSLOT_TICKETSLOT: u32 = 0x10001;

// =============================================================================
// Special Slot Indices (negative, for CodeDirectory)
// =============================================================================

/// Info.plist special slot index
pub const CSSLOT_SPECIAL_INFOSLOT: i32 = -1;

/// Requirements special slot index
pub const CSSLOT_SPECIAL_REQUIREMENTS: i32 = -2;

/// CodeResources special slot index
pub const CSSLOT_SPECIAL_RESOURCEDIR: i32 = -3;

/// Application special slot index
pub const CSSLOT_SPECIAL_APPLICATION: i32 = -4;

/// Entitlements special slot index
pub const CSSLOT_SPECIAL_ENTITLEMENTS: i32 = -5;

/// Rep-specific special slot index
pub const CSSLOT_SPECIAL_REP_SPECIFIC: i32 = -6;

/// DER entitlements special slot index
pub const CSSLOT_SPECIAL_DER_ENTITLEMENTS: i32 = -7;

// =============================================================================
// Hash Types
// =============================================================================

/// No hash (placeholder)
pub const CS_HASHTYPE_NOHASH: u8 = 0;

/// SHA-1 hash (160-bit / 20 bytes)
pub const CS_HASHTYPE_SHA1: u8 = 1;

/// SHA-256 hash (256-bit / 32 bytes)
pub const CS_HASHTYPE_SHA256: u8 = 2;

/// SHA-256 truncated to 20 bytes (legacy compatibility)
pub const CS_HASHTYPE_SHA256_TRUNCATED: u8 = 3;

/// SHA-384 hash (384-bit / 48 bytes)
pub const CS_HASHTYPE_SHA384: u8 = 4;

/// SHA-512 hash (512-bit / 64 bytes)
pub const CS_HASHTYPE_SHA512: u8 = 5;

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

/// Maximum hash size we support
pub const CS_MAX_HASH_LEN: usize = 64;

// =============================================================================
// Code Signature Flags
// =============================================================================

/// Code is valid (verified)
pub const CS_VALID: u32 = 0x00000001;

/// Ad-hoc signed (no identity)
pub const CS_ADHOC: u32 = 0x00000002;

/// Force hard page validation
pub const CS_HARD: u32 = 0x00000100;

/// Force kill on page validation failure
pub const CS_KILL: u32 = 0x00000200;

/// Restrict memory protections
pub const CS_RESTRICT: u32 = 0x00000800;

/// Allow amfi to check if dyld is loaded
pub const CS_ENFORCEMENT: u32 = 0x00001000;

/// Require library validation
pub const CS_REQUIRE_LV: u32 = 0x00002000;

/// Entitlements were validated
pub const CS_ENTITLEMENTS_VALIDATED: u32 = 0x00004000;

/// Never modify code
pub const CS_NVRAM_UNRESTRICTED: u32 = 0x00008000;

/// Code runs with amfi in test mode
pub const CS_RUNTIME: u32 = 0x00010000;

/// Linked for encryption
pub const CS_LINKER_SIGNED: u32 = 0x00020000;

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

/// Can load any library
pub const CS_EXECSEG_CAN_LOAD_CDHASH: u64 = 0x0100;

/// Can execute with dyld simulator
pub const CS_EXECSEG_CAN_EXEC_CDHASH: u64 = 0x0200;

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

/// Version with pre-encrypt hashes
pub const CODEDIRECTORY_VERSION_PREENCRYPT: u32 = 0x20500;

/// Version with runtime version
pub const CODEDIRECTORY_VERSION_RUNTIME: u32 = 0x20600;

/// Version with linkage hashes
pub const CODEDIRECTORY_VERSION_LINKAGE: u32 = 0x20700;

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
// Requirements Opcodes
// =============================================================================

/// Requirement expression: always false
pub const OP_FALSE: u32 = 0;

/// Requirement expression: always true
pub const OP_TRUE: u32 = 1;

/// Requirement expression: check identifier
pub const OP_IDENT: u32 = 2;

/// Requirement expression: Apple anchor
pub const OP_APPLE_ANCHOR: u32 = 3;

/// Requirement expression: anchor hash
pub const OP_ANCHOR_HASH: u32 = 4;

/// Requirement expression: info key value
pub const OP_INFO_KEY_VALUE: u32 = 5;

/// Requirement expression: logical AND
pub const OP_AND: u32 = 6;

/// Requirement expression: logical OR
pub const OP_OR: u32 = 7;

/// Requirement expression: CDHash
pub const OP_CDHASH: u32 = 8;

/// Requirement expression: logical NOT
pub const OP_NOT: u32 = 9;

/// Requirement expression: info key field
pub const OP_INFO_KEY_FIELD: u32 = 10;

/// Requirement expression: certificate field
pub const OP_CERT_FIELD: u32 = 11;

/// Requirement expression: trusted certificate
pub const OP_TRUSTED_CERT: u32 = 12;

/// Requirement expression: trusted certificates
pub const OP_TRUSTED_CERTS: u32 = 13;

/// Requirement expression: certificate generic
pub const OP_CERT_GENERIC: u32 = 14;

/// Requirement expression: Apple generic anchor
pub const OP_APPLE_GENERIC_ANCHOR: u32 = 15;

/// Requirement expression: entitlement field
pub const OP_ENTITLEMENT_FIELD: u32 = 16;

/// Requirement expression: certificate policy
pub const OP_CERT_POLICY: u32 = 17;

/// Requirement expression: named anchor
pub const OP_NAMED_ANCHOR: u32 = 18;

/// Requirement expression: named code
pub const OP_NAMED_CODE: u32 = 19;

/// Requirement expression: platform
pub const OP_PLATFORM: u32 = 20;

/// Requirement expression: notarized
pub const OP_NOTARIZED: u32 = 21;

/// Requirement expression: certificate field (date)
pub const OP_CERT_FIELD_DATE: u32 = 22;

/// Requirement expression: legacy development ID
pub const OP_LEGACY_DEV_ID: u32 = 23;

// =============================================================================
// Requirements Types
// =============================================================================

/// Requirement type: host requirement
pub const CSREQ_HOST: u32 = 0x0001;

/// Requirement type: guest requirement
pub const CSREQ_GUEST: u32 = 0x0002;

/// Requirement type: designated requirement
pub const CSREQ_DESIGNATED: u32 = 0x0003;

/// Requirement type: library requirement
pub const CSREQ_LIBRARY: u32 = 0x0004;

/// Requirement type: plugin requirement
pub const CSREQ_PLUGIN: u32 = 0x0005;

// =============================================================================
// Match Operations (for requirements expressions)
// =============================================================================

/// Match: exists
pub const MATCH_EXISTS: u32 = 0;

/// Match: equal
pub const MATCH_EQUAL: u32 = 1;

/// Match: contains
pub const MATCH_CONTAINS: u32 = 2;

/// Match: begins with
pub const MATCH_BEGINS_WITH: u32 = 3;

/// Match: ends with
pub const MATCH_ENDS_WITH: u32 = 4;

/// Match: less than
pub const MATCH_LESS_THAN: u32 = 5;

/// Match: greater than
pub const MATCH_GREATER_THAN: u32 = 6;

/// Match: less than or equal
pub const MATCH_LESS_THAN_OR_EQUAL: u32 = 7;

/// Match: greater than or equal
pub const MATCH_GREATER_THAN_OR_EQUAL: u32 = 8;

/// Match: on (for dates)
pub const MATCH_ON: u32 = 9;

/// Match: before (for dates)
pub const MATCH_BEFORE: u32 = 10;

/// Match: after (for dates)
pub const MATCH_AFTER: u32 = 11;

/// Match: on or before (for dates)
pub const MATCH_ON_OR_BEFORE: u32 = 12;

/// Match: on or after (for dates)
pub const MATCH_ON_OR_AFTER: u32 = 13;

/// Match: absent
pub const MATCH_ABSENT: u32 = 14;

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
}
