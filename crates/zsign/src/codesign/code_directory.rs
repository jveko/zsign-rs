//! CodeDirectory blob builder for Apple code signing
//!
//! The CodeDirectory is the core data structure for iOS/macOS code signatures.
//! It contains hashes of the code pages and special slots (Info.plist, entitlements, etc.)
//!
//! This module implements dual hashing with both SHA-1 and SHA-256 for compatibility
//! with all iOS versions (iOS 12+ requires SHA-256, but SHA-1 is kept for legacy support).

use super::constants::*;
use sha1::{Digest, Sha1};
use sha2::Sha256;

// Special slot indices (negative, stored in reverse order)
// Slot -1: Info.plist
// Slot -2: Requirements
// Slot -3: CodeResources
// Slot -4: Application-specific (unused)
// Slot -5: XML Entitlements
// Slot -6: Rep-specific (unused, but included when -7 is present)
// Slot -7: DER Entitlements (only for executable binaries)

/// CodeDirectory header size for version 0x20400 (with exec segment fields)
const CODEDIRECTORY_HEADER_SIZE: u32 = 88;

/// Builder for creating CodeDirectory blobs.
///
/// The CodeDirectory contains:
/// - Magic number and version
/// - Hash of the binary's code pages (4KB each)
/// - Special slot hashes (Info.plist, requirements, resources, entitlements)
/// - Bundle identifier and team ID
/// - Exec segment information for iOS 12+
///
/// # Example
///
/// ```ignore
/// let code_data = vec![0u8; 8192]; // 2 pages of code
/// let cd = CodeDirectoryBuilder::new("com.example.app", code_data)
///     .team_id("TEAMID1234")
///     .exec_seg_limit(65536)
///     .exec_seg_flags(CS_EXECSEG_MAIN_BINARY)
///     .build_sha256();
/// ```
pub struct CodeDirectoryBuilder {
    /// Bundle identifier (e.g., "com.example.app")
    identifier: String,
    /// Team identifier (None for adhoc signing)
    team_id: Option<String>,
    /// Code bytes to hash (executable content)
    code: Vec<u8>,
    /// Info.plist hash (special slot -1)
    info_hash: Option<Vec<u8>>,
    /// CodeResources hash (special slot -3)
    resources_hash: Option<Vec<u8>>,
    /// Entitlements blob hash (special slot -5)
    entitlements_hash: Option<Vec<u8>>,
    /// DER entitlements blob hash (special slot -7)
    der_entitlements_hash: Option<Vec<u8>>,
    /// Requirements blob hash (special slot -2)
    requirements_hash: Option<Vec<u8>>,
    /// Executable segment limit (__TEXT segment size)
    exec_seg_limit: u64,
    /// Executable segment flags (raw value, e.g., CS_EXECSEG_MAIN_BINARY | CS_EXECSEG_ALLOW_UNSIGNED)
    exec_seg_flags: u64,
    /// Code signature flags (e.g., CS_ADHOC)
    flags: u32,
}

impl CodeDirectoryBuilder {
    /// Create a new CodeDirectory builder.
    ///
    /// # Arguments
    ///
    /// * `identifier` - Bundle identifier (e.g., "com.example.app")
    /// * `code` - The executable code bytes to hash
    pub fn new(identifier: impl Into<String>, code: Vec<u8>) -> Self {
        Self {
            identifier: identifier.into(),
            team_id: None,
            code,
            info_hash: None,
            resources_hash: None,
            entitlements_hash: None,
            der_entitlements_hash: None,
            requirements_hash: None,
            exec_seg_limit: 0,
            exec_seg_flags: 0,
            flags: 0,
        }
    }

    /// Set the team identifier.
    ///
    /// Required for non-adhoc signing. This is typically a 10-character
    /// alphanumeric string from the Apple Developer account.
    pub fn team_id(mut self, team_id: impl Into<String>) -> Self {
        self.team_id = Some(team_id.into());
        self
    }

    /// Set the Info.plist hash (special slot -1).
    ///
    /// The hash should match the hash type being built (SHA-1 or SHA-256).
    pub fn info_hash(mut self, hash: Vec<u8>) -> Self {
        self.info_hash = Some(hash);
        self
    }

    /// Set the CodeResources hash (special slot -3).
    ///
    /// CodeResources is a plist containing hashes of all bundle resources.
    pub fn resources_hash(mut self, hash: Vec<u8>) -> Self {
        self.resources_hash = Some(hash);
        self
    }

    /// Set the entitlements blob hash (special slot -5).
    ///
    /// This is the hash of the XML entitlements blob.
    pub fn entitlements_hash(mut self, hash: Vec<u8>) -> Self {
        self.entitlements_hash = Some(hash);
        self
    }

    /// Set the DER entitlements blob hash (special slot -7).
    ///
    /// This is the hash of the DER-encoded entitlements blob.
    pub fn der_entitlements_hash(mut self, hash: Vec<u8>) -> Self {
        self.der_entitlements_hash = Some(hash);
        self
    }

    /// Set the requirements blob hash (special slot -2).
    ///
    /// Requirements specify code signing requirements for the binary.
    pub fn requirements_hash(mut self, hash: Vec<u8>) -> Self {
        self.requirements_hash = Some(hash);
        self
    }

    /// Set the executable segment limit.
    ///
    /// This is typically the __TEXT segment size from the Mach-O header.
    pub fn exec_seg_limit(mut self, limit: u64) -> Self {
        self.exec_seg_limit = limit;
        self
    }

    /// Set the raw executable segment flags.
    ///
    /// This value is written directly to the execSegFlags field in the CodeDirectory.
    /// Common flag combinations:
    /// - `CS_EXECSEG_MAIN_BINARY` for main executables
    /// - `CS_EXECSEG_MAIN_BINARY | CS_EXECSEG_ALLOW_UNSIGNED` for executables with get-task-allow
    pub fn exec_seg_flags(mut self, flags: u64) -> Self {
        self.exec_seg_flags = flags;
        self
    }

    /// Check if this is a main executable binary.
    ///
    /// Returns true if CS_EXECSEG_MAIN_BINARY is set in exec_seg_flags.
    /// Used internally for determining special slot counts.
    fn is_main_executable(&self) -> bool {
        self.exec_seg_flags & CS_EXECSEG_MAIN_BINARY != 0
    }

    /// Set the code signature flags.
    ///
    /// Common flags include CS_ADHOC for adhoc signing.
    pub fn flags(mut self, flags: u32) -> Self {
        self.flags = flags;
        self
    }

    /// Build a SHA-1 CodeDirectory blob.
    ///
    /// SHA-1 is used for legacy compatibility with older iOS versions.
    pub fn build_sha1(&self) -> Vec<u8> {
        self.build_internal(CS_HASHTYPE_SHA1, CS_SHA1_LEN)
    }

    /// Build a SHA-256 CodeDirectory blob.
    ///
    /// SHA-256 is required for iOS 12+ and is the primary CodeDirectory.
    pub fn build_sha256(&self) -> Vec<u8> {
        self.build_internal(CS_HASHTYPE_SHA256, CS_SHA256_LEN)
    }

    /// Internal build function that handles both hash types.
    fn build_internal(&self, hash_type: u8, hash_size: usize) -> Vec<u8> {
        // Calculate number of code slots (pages)
        let code_limit = self.code.len() as u32;
        let n_code_slots = if code_limit == 0 {
            0
        } else {
            (code_limit as usize + PAGE_SIZE - 1) / PAGE_SIZE
        };

        // Determine number of special slots based on what's provided
        let n_special_slots = self.count_special_slots();

        // Calculate string offsets
        let ident_offset = CODEDIRECTORY_HEADER_SIZE;
        let ident_len = self.identifier.len() as u32 + 1; // null-terminated

        let team_offset = if self.team_id.is_some() {
            ident_offset + ident_len
        } else {
            0
        };
        let team_len = self
            .team_id
            .as_ref()
            .map(|t| t.len() as u32 + 1)
            .unwrap_or(0);

        // Hash offset is after header, identifier, team ID, and special slots
        let hash_offset = ident_offset + ident_len + team_len + (n_special_slots as u32 * hash_size as u32);

        // Total length includes header, strings, special slots, and code slots
        let total_len = hash_offset + (n_code_slots as u32 * hash_size as u32);

        // Build the blob
        let mut buf = Vec::with_capacity(total_len as usize);

        // Header (all fields are big-endian)
        buf.extend(&CSMAGIC_CODEDIRECTORY.to_be_bytes()); // magic
        buf.extend(&total_len.to_be_bytes()); // length
        buf.extend(&CODEDIRECTORY_VERSION.to_be_bytes()); // version
        buf.extend(&self.flags.to_be_bytes()); // flags
        buf.extend(&hash_offset.to_be_bytes()); // hashOffset
        buf.extend(&ident_offset.to_be_bytes()); // identOffset
        buf.extend(&(n_special_slots as u32).to_be_bytes()); // nSpecialSlots
        buf.extend(&(n_code_slots as u32).to_be_bytes()); // nCodeSlots
        buf.extend(&code_limit.to_be_bytes()); // codeLimit
        buf.push(hash_size as u8); // hashSize
        buf.push(hash_type); // hashType
        buf.push(0); // spare1
        buf.push(PAGE_SIZE_LOG2); // pageSize (log2)
        buf.extend(&0u32.to_be_bytes()); // spare2
        buf.extend(&0u32.to_be_bytes()); // scatterOffset (unused)
        buf.extend(&team_offset.to_be_bytes()); // teamOffset
        buf.extend(&0u32.to_be_bytes()); // spare3
        buf.extend(&0u64.to_be_bytes()); // codeLimit64 (unused, codeLimit is sufficient)
        buf.extend(&0u64.to_be_bytes()); // execSegBase (always 0)
        buf.extend(&self.exec_seg_limit.to_be_bytes()); // execSegLimit

        // execSegFlags - use raw value directly
        buf.extend(&self.exec_seg_flags.to_be_bytes());

        // Identifier (null-terminated)
        buf.extend(self.identifier.as_bytes());
        buf.push(0);

        // Team ID (null-terminated) if present
        if let Some(ref team) = self.team_id {
            buf.extend(team.as_bytes());
            buf.push(0);
        }

        // Special slots (stored in reverse order: -7, -6, -5, -4, -3, -2, -1)
        let special_slots = self.build_special_slots(hash_size);
        buf.extend(&special_slots);

        // Code slots (hash of each 4KB page)
        let code_hashes = self.hash_code_pages(hash_type);
        buf.extend(&code_hashes);

        buf
    }

    /// Count the number of special slots needed.
    ///
    /// This implements the C++ zsign behavior of trimming trailing empty special slots.
    /// Special slots are stored in reverse order (-7, -6, -5, -4, -3, -2, -1), so
    /// trailing empty slots are those with higher negative indices.
    ///
    /// The logic:
    /// - Slots -7 and -6 are only added for main executable binaries (CS_EXECSEG_MAIN_BINARY set)
    /// - Trailing empty slots are trimmed from the count
    /// - Common results: 7 (DER ent), 5 (XML ent only), 3 (minimal)
    fn count_special_slots(&self) -> usize {
        // Build the logical slots array in reverse order (-7 to -1)
        // Each entry is true if the slot has content, false if empty
        let mut slots: Vec<bool> = Vec::new();

        // Slots -7 and -6 are only included for main executable binaries
        if self.is_main_executable() {
            // Slot -7: DER entitlements (has content if DER hash is present)
            slots.push(self.der_entitlements_hash.is_some());
            // Slot -6: Rep-specific (always empty)
            slots.push(false);
        }

        // Slot -5: XML entitlements
        slots.push(self.entitlements_hash.is_some());
        // Slot -4: Application-specific (always empty)
        slots.push(false);
        // Slot -3: CodeResources (has content if resources hash is present)
        slots.push(self.resources_hash.is_some());
        // Slot -2: Requirements (has content if requirements hash is present)
        slots.push(self.requirements_hash.is_some());
        // Slot -1: Info.plist (has content if info hash is present)
        slots.push(self.info_hash.is_some());

        // Find the first non-empty slot from the front (highest negative index)
        // and trim all empty slots before it
        let first_non_empty = slots.iter().position(|&has_content| has_content);

        match first_non_empty {
            Some(idx) => slots.len() - idx,
            // All slots are empty - return minimum 3 slots (info, requirements, resources)
            // This matches C++ behavior which always includes at least slots -1, -2, -3
            None => 3,
        }
    }

    /// Build the special slots array.
    ///
    /// Special slots are stored in reverse order from -n to -1.
    /// Each slot is either the provided hash or zeros if not present.
    fn build_special_slots(&self, hash_size: usize) -> Vec<u8> {
        let empty = vec![0u8; hash_size];
        let mut slots = Vec::new();

        let n_slots = self.count_special_slots();

        // Build in reverse order (-7 to -1)
        if n_slots >= 7 {
            // Slot -7: DER entitlements
            slots.extend(self.der_entitlements_hash.as_ref().unwrap_or(&empty));
        }
        if n_slots >= 6 {
            // Slot -6: rep-specific (unused)
            slots.extend(&empty);
        }
        if n_slots >= 5 {
            // Slot -5: XML entitlements
            slots.extend(self.entitlements_hash.as_ref().unwrap_or(&empty));
        }
        if n_slots >= 4 {
            // Slot -4: application (unused)
            slots.extend(&empty);
        }
        // Slot -3: resources
        slots.extend(self.resources_hash.as_ref().unwrap_or(&empty));
        // Slot -2: requirements
        slots.extend(self.requirements_hash.as_ref().unwrap_or(&empty));
        // Slot -1: info.plist
        slots.extend(self.info_hash.as_ref().unwrap_or(&empty));

        slots
    }

    /// Hash all code pages.
    ///
    /// The code is divided into 4KB pages, and each page is hashed
    /// with the specified hash algorithm.
    fn hash_code_pages(&self, hash_type: u8) -> Vec<u8> {
        let mut result = Vec::new();

        if self.code.is_empty() {
            return result;
        }

        for chunk in self.code.chunks(PAGE_SIZE) {
            let hash = match hash_type {
                CS_HASHTYPE_SHA1 => {
                    let mut hasher = Sha1::new();
                    hasher.update(chunk);
                    hasher.finalize().to_vec()
                }
                CS_HASHTYPE_SHA256 => {
                    let mut hasher = Sha256::new();
                    hasher.update(chunk);
                    hasher.finalize().to_vec()
                }
                _ => panic!("Unsupported hash type: {}", hash_type),
            };
            result.extend(&hash);
        }

        result
    }
}

/// Compute the CDHash (hash of the CodeDirectory blob).
///
/// The CDHash is used in CMS signatures to bind the signature to the code.
pub fn compute_cdhash_sha1(code_directory: &[u8]) -> [u8; 20] {
    let mut hasher = Sha1::new();
    hasher.update(code_directory);
    hasher.finalize().into()
}

/// Compute the CDHash (hash of the CodeDirectory blob) using SHA-256.
pub fn compute_cdhash_sha256(code_directory: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(code_directory);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    // CodeDirectory header field offsets (version 0x20400):
    // magic: 0, length: 4, version: 8, flags: 12
    // hashOffset: 16, identOffset: 20, nSpecialSlots: 24, nCodeSlots: 28
    // codeLimit: 32, hashSize: 36, hashType: 37, spare1: 38, pageSize: 39
    // spare2: 40, scatterOffset: 44, teamOffset: 48, spare3: 52
    // codeLimit64: 56, execSegBase: 64, execSegLimit: 72, execSegFlags: 80
    const OFF_HASH_SIZE: usize = 36;
    const OFF_HASH_TYPE: usize = 37;
    const OFF_TEAM_OFFSET: usize = 48;

    #[test]
    fn test_code_directory_header_sha256() {
        let code = vec![0u8; 8192]; // 2 pages
        let cd = CodeDirectoryBuilder::new("com.example.app", code).build_sha256();

        // Check magic
        assert_eq!(&cd[0..4], &CSMAGIC_CODEDIRECTORY.to_be_bytes());
        // Check version
        assert_eq!(&cd[8..12], &CODEDIRECTORY_VERSION.to_be_bytes());
        // Check hash size (offset 36)
        assert_eq!(cd[OFF_HASH_SIZE], CS_SHA256_LEN as u8);
        // Check hash type (offset 37)
        assert_eq!(cd[OFF_HASH_TYPE], CS_HASHTYPE_SHA256);
    }

    #[test]
    fn test_code_directory_header_sha1() {
        let code = vec![0u8; 8192]; // 2 pages
        let cd = CodeDirectoryBuilder::new("com.example.app", code).build_sha1();

        // Check magic
        assert_eq!(&cd[0..4], &CSMAGIC_CODEDIRECTORY.to_be_bytes());
        // Check version
        assert_eq!(&cd[8..12], &CODEDIRECTORY_VERSION.to_be_bytes());
        // Check hash size
        assert_eq!(cd[OFF_HASH_SIZE], CS_SHA1_LEN as u8);
        // Check hash type
        assert_eq!(cd[OFF_HASH_TYPE], CS_HASHTYPE_SHA1);
    }

    #[test]
    fn test_code_directory_with_team_id() {
        let code = vec![0u8; 4096]; // 1 page
        let cd = CodeDirectoryBuilder::new("com.example.app", code)
            .team_id("TEAM123456")
            .build_sha256();

        // Verify team offset is non-zero (offset 48-51)
        let team_offset = u32::from_be_bytes([
            cd[OFF_TEAM_OFFSET],
            cd[OFF_TEAM_OFFSET + 1],
            cd[OFF_TEAM_OFFSET + 2],
            cd[OFF_TEAM_OFFSET + 3],
        ]);
        assert!(team_offset > 0);

        // Find team ID in the blob
        let cd_str = String::from_utf8_lossy(&cd);
        assert!(cd_str.contains("TEAM123456"));
    }

    #[test]
    fn test_code_directory_identifier() {
        let code = vec![0u8; 4096];
        let identifier = "com.example.myapp";
        let cd = CodeDirectoryBuilder::new(identifier, code).build_sha256();

        // Find identifier in the blob
        let cd_str = String::from_utf8_lossy(&cd);
        assert!(cd_str.contains(identifier));
    }

    #[test]
    fn test_code_directory_page_count() {
        // Test with exactly 2 pages
        let code = vec![0u8; 8192];
        let cd = CodeDirectoryBuilder::new("test", code).build_sha256();

        // nCodeSlots is at offset 28
        let n_code_slots = u32::from_be_bytes([cd[28], cd[29], cd[30], cd[31]]);
        assert_eq!(n_code_slots, 2);
    }

    #[test]
    fn test_code_directory_partial_page() {
        // Test with 1.5 pages (should round up to 2 code slots)
        let code = vec![0u8; 6144]; // 4096 + 2048
        let cd = CodeDirectoryBuilder::new("test", code).build_sha256();

        let n_code_slots = u32::from_be_bytes([cd[28], cd[29], cd[30], cd[31]]);
        assert_eq!(n_code_slots, 2);
    }

    #[test]
    fn test_code_directory_code_limit() {
        let code = vec![0u8; 12345];
        let cd = CodeDirectoryBuilder::new("test", code).build_sha256();

        // codeLimit is at offset 32
        let code_limit = u32::from_be_bytes([cd[32], cd[33], cd[34], cd[35]]);
        assert_eq!(code_limit, 12345);
    }

    #[test]
    fn test_code_directory_exec_seg() {
        let code = vec![0u8; 4096];
        let cd = CodeDirectoryBuilder::new("test", code)
            .exec_seg_limit(65536)
            .exec_seg_flags(CS_EXECSEG_MAIN_BINARY)
            .build_sha256();

        // execSegLimit is at offset 72 (u64)
        let exec_seg_limit = u64::from_be_bytes([
            cd[72], cd[73], cd[74], cd[75], cd[76], cd[77], cd[78], cd[79],
        ]);
        assert_eq!(exec_seg_limit, 65536);

        // execSegFlags is at offset 80 (u64)
        let exec_seg_flags = u64::from_be_bytes([
            cd[80], cd[81], cd[82], cd[83], cd[84], cd[85], cd[86], cd[87],
        ]);
        assert_eq!(exec_seg_flags, CS_EXECSEG_MAIN_BINARY);
    }

    #[test]
    fn test_code_directory_special_slots_minimal() {
        let code = vec![0u8; 4096];
        let cd = CodeDirectoryBuilder::new("test", code).build_sha256();

        // nSpecialSlots is at offset 24
        let n_special_slots = u32::from_be_bytes([cd[24], cd[25], cd[26], cd[27]]);
        assert_eq!(n_special_slots, 3); // info, requirements, resources
    }

    #[test]
    fn test_code_directory_special_slots_with_entitlements() {
        let code = vec![0u8; 4096];
        let cd = CodeDirectoryBuilder::new("test", code)
            .entitlements_hash(vec![0u8; 32])
            .build_sha256();

        let n_special_slots = u32::from_be_bytes([cd[24], cd[25], cd[26], cd[27]]);
        assert_eq!(n_special_slots, 5);
    }

    #[test]
    fn test_code_directory_special_slots_with_der_entitlements() {
        let code = vec![0u8; 4096];
        // DER entitlements slots -6/-7 are only included for executables (CS_EXECSEG_MAIN_BINARY set)
        let cd = CodeDirectoryBuilder::new("test", code)
            .entitlements_hash(vec![0u8; 32])
            .der_entitlements_hash(vec![0u8; 32])
            .exec_seg_flags(CS_EXECSEG_MAIN_BINARY)
            .build_sha256();

        let n_special_slots = u32::from_be_bytes([cd[24], cd[25], cd[26], cd[27]]);
        assert_eq!(n_special_slots, 7);
    }

    #[test]
    fn test_non_executable_ignores_der_entitlements_slots() {
        // Dylibs/frameworks should NOT have slots -6/-7 even if DER entitlements hash is set
        // (exec_seg_flags does not have CS_EXECSEG_MAIN_BINARY set)
        let code = vec![0u8; 4096];
        let cd = CodeDirectoryBuilder::new("test", code)
            .entitlements_hash(vec![0u8; 32])
            .der_entitlements_hash(vec![0u8; 32])
            .exec_seg_flags(0) // Not an executable
            .build_sha256();

        let n_special_slots = u32::from_be_bytes([cd[24], cd[25], cd[26], cd[27]]);
        // Non-executables max out at 5 slots (-5 through -1), not 7
        assert_eq!(n_special_slots, 5);
    }

    #[test]
    fn test_code_directory_flags() {
        let code = vec![0u8; 4096];
        let cd = CodeDirectoryBuilder::new("test", code)
            .flags(CS_ADHOC)
            .build_sha256();

        // flags is at offset 12
        let flags = u32::from_be_bytes([cd[12], cd[13], cd[14], cd[15]]);
        assert_eq!(flags, CS_ADHOC);
    }

    #[test]
    fn test_cdhash_computation() {
        let code = vec![0u8; 4096];
        let cd = CodeDirectoryBuilder::new("test", code).build_sha256();

        let cdhash = compute_cdhash_sha256(&cd);
        assert_eq!(cdhash.len(), 32);

        // Verify the hash is deterministic
        let cdhash2 = compute_cdhash_sha256(&cd);
        assert_eq!(cdhash, cdhash2);
    }

    #[test]
    fn test_code_directory_empty_code() {
        let code = vec![];
        let cd = CodeDirectoryBuilder::new("test", code).build_sha256();

        // Should still have valid header
        assert_eq!(&cd[0..4], &CSMAGIC_CODEDIRECTORY.to_be_bytes());

        // nCodeSlots should be 0
        let n_code_slots = u32::from_be_bytes([cd[28], cd[29], cd[30], cd[31]]);
        assert_eq!(n_code_slots, 0);

        // codeLimit should be 0
        let code_limit = u32::from_be_bytes([cd[32], cd[33], cd[34], cd[35]]);
        assert_eq!(code_limit, 0);
    }

    #[test]
    fn test_dual_hashing() {
        // Verify that SHA-1 and SHA-256 produce different but valid results
        let code = vec![0xab; 8192];
        let cd_sha1 = CodeDirectoryBuilder::new("test", code.clone()).build_sha1();
        let cd_sha256 = CodeDirectoryBuilder::new("test", code).build_sha256();

        // Both should have same magic
        assert_eq!(&cd_sha1[0..4], &cd_sha256[0..4]);

        // Hash types should differ (offset 37)
        assert_eq!(cd_sha1[OFF_HASH_TYPE], CS_HASHTYPE_SHA1);
        assert_eq!(cd_sha256[OFF_HASH_TYPE], CS_HASHTYPE_SHA256);

        // SHA-256 blob should be larger due to larger hashes
        assert!(cd_sha256.len() > cd_sha1.len());
    }
}
