//! Integration tests comparing Rust zsign output with C++ zsign output for parity verification.
//!
//! These tests perform detailed comparison of code signing outputs to ensure
//! the Rust implementation matches the C++ zsign behavior, including:
//! - Output file sizes
//! - Binary signature sizes
//! - CodeDirectory structure (special slots, hash counts, etc.)
//!
//! The tests are marked as `#[ignore]` because they require:
//! - External test files (IPA, certificates, provisioning profile)
//! - C++ zsign binary at /Users/dimaz/workspace/projects/zsign/bin/zsign
//!
//! Run with: cargo test -p zsign --test cpp_parity -- --ignored

use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;
use zip::ZipArchive;

/// Path to the C++ zsign binary
const CPP_ZSIGN_PATH: &str = "/Users/dimaz/workspace/projects/zsign/bin/zsign";

/// Directory containing test files (IPA, certs, etc.)
const TEST_FILES_DIR: &str = "/Users/dimaz/workspace/projects/zsign-rust/tmp";

// Magic numbers for code signing blobs (kept for documentation/future use)
#[allow(dead_code)]
const CSMAGIC_EMBEDDED_SIGNATURE: u32 = 0xfade0cc0;
#[allow(dead_code)]
const CSMAGIC_CODEDIRECTORY: u32 = 0xfade0c02;
#[allow(dead_code)]
const CSMAGIC_REQUIREMENTS: u32 = 0xfade0c01;
#[allow(dead_code)]
const CSMAGIC_EMBEDDED_ENTITLEMENTS: u32 = 0xfade7171;
#[allow(dead_code)]
const CSMAGIC_EMBEDDED_DER_ENTITLEMENTS: u32 = 0xfade7172;
#[allow(dead_code)]
const CSMAGIC_BLOBWRAPPER: u32 = 0xfade0b01;

/// Slot types
const CSSLOT_CODEDIRECTORY: u32 = 0x0000;
const CSSLOT_REQUIREMENTS: u32 = 0x0002;
const CSSLOT_ENTITLEMENTS: u32 = 0x0005;
const CSSLOT_DER_ENTITLEMENTS: u32 = 0x0007;
const CSSLOT_ALTERNATE_CODEDIRECTORIES: u32 = 0x1000;
const CSSLOT_SIGNATURESLOT: u32 = 0x10000;

/// Mach-O load command types
const LC_CODE_SIGNATURE: u32 = 0x1d;

/// FAT binary magic numbers
const FAT_MAGIC: u32 = 0xcafebabe;
const FAT_CIGAM: u32 = 0xbebafeca;

/// Mach-O magic numbers
const MH_MAGIC: u32 = 0xfeedface;
const MH_MAGIC_64: u32 = 0xfeedfacf;
const MH_CIGAM: u32 = 0xcefaedfe;
const MH_CIGAM_64: u32 = 0xcffaedfe;

/// CodeDirectory header information parsed from a binary
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct CodeDirectoryInfo {
    magic: u32,
    length: u32,
    version: u32,
    flags: u32,
    hash_offset: u32,
    ident_offset: u32,
    n_special_slots: u32,
    n_code_slots: u32,
    code_limit: u32,
    hash_size: u8,
    hash_type: u8,
    page_size_log2: u8,
    exec_seg_base: u64,
    exec_seg_limit: u64,
    exec_seg_flags: u64,
    identifier: String,
}

/// SuperBlob information
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct SuperBlobInfo {
    magic: u32,
    length: u32,
    count: u32,
    entries: Vec<BlobIndexEntry>,
}

/// Blob index entry within a SuperBlob
#[derive(Debug, Clone)]
struct BlobIndexEntry {
    slot_type: u32,
    offset: u32,
}

/// Signature information extracted from a Mach-O binary
#[derive(Debug)]
struct SignatureInfo {
    /// Total size of the code signature
    signature_size: u32,
    /// Offset to the code signature in the binary
    signature_offset: u32,
    /// SuperBlob information
    superblob: Option<SuperBlobInfo>,
    /// Primary CodeDirectory (SHA-1, slot 0x0000)
    code_directory_sha1: Option<CodeDirectoryInfo>,
    /// Alternate CodeDirectory (SHA-256, slot 0x1000)
    code_directory_sha256: Option<CodeDirectoryInfo>,
    /// Requirements blob size
    requirements_size: Option<u32>,
    /// Entitlements blob size
    entitlements_size: Option<u32>,
    /// DER entitlements blob size
    der_entitlements_size: Option<u32>,
    /// CMS signature blob size
    cms_signature_size: Option<u32>,
}

/// Check if test prerequisites exist
fn prerequisites_exist() -> bool {
    Path::new(CPP_ZSIGN_PATH).exists()
        && Path::new(TEST_FILES_DIR).join("Empty.ipa").exists()
        && Path::new(TEST_FILES_DIR).join("cert.pem").exists()
        && Path::new(TEST_FILES_DIR).join("key.pem").exists()
}

/// Find provisioning profile
fn find_provisioning_profile() -> Option<PathBuf> {
    let test_files = PathBuf::from(TEST_FILES_DIR);
    test_files
        .join("00008150-00065C1C0C0A401C")
        .read_dir()
        .ok()
        .and_then(|mut entries| {
            entries.find_map(|e| {
                e.ok().and_then(|entry| {
                    let path = entry.path();
                    if path.extension().map_or(false, |ext| ext == "mobileprovision") {
                        Some(path)
                    } else {
                        None
                    }
                })
            })
        })
}

/// Sign an IPA using C++ zsign
fn sign_with_cpp_zsign(
    input_ipa: &Path,
    output_ipa: &Path,
    cert_path: &Path,
    key_path: &Path,
    provisioning_profile: Option<&Path>,
) -> Result<(), String> {
    let mut cmd = Command::new(CPP_ZSIGN_PATH);
    cmd.arg("-c").arg(cert_path);
    cmd.arg("-k").arg(key_path);

    if let Some(prov) = provisioning_profile {
        cmd.arg("-m").arg(prov);
    }

    cmd.arg("-o").arg(output_ipa);
    cmd.arg(input_ipa);

    let output = cmd.output().map_err(|e| format!("Failed to run C++ zsign: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "C++ zsign failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    Ok(())
}

/// Sign an IPA using Rust zsign
fn sign_with_rust_zsign(
    input_ipa: &Path,
    output_ipa: &Path,
    cert_path: &Path,
    key_path: &Path,
    provisioning_profile: Option<&Path>,
) -> Result<(), String> {
    use zsign::{crypto::SigningAssets, IpaSigner};

    let assets = SigningAssets::from_pem(cert_path, key_path, None)
        .map_err(|e| format!("Failed to load signing assets: {}", e))?;

    let mut signer = IpaSigner::new(assets);

    if let Some(prov) = provisioning_profile {
        signer = signer.provisioning_profile(prov);
    }

    signer
        .sign(input_ipa, output_ipa)
        .map_err(|e| format!("Failed to sign with Rust zsign: {}", e))
}

/// Parse a u32 from big-endian bytes
fn read_be_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}

/// Parse a u64 from big-endian bytes
fn read_be_u64(data: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ])
}

/// Parse a u32 from little-endian bytes
fn read_le_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}

/// Parse a CodeDirectory blob
fn parse_code_directory(data: &[u8]) -> Option<CodeDirectoryInfo> {
    if data.len() < 88 {
        return None;
    }

    let magic = read_be_u32(data, 0);
    if magic != CSMAGIC_CODEDIRECTORY {
        return None;
    }

    let length = read_be_u32(data, 4);
    let version = read_be_u32(data, 8);
    let flags = read_be_u32(data, 12);
    let hash_offset = read_be_u32(data, 16);
    let ident_offset = read_be_u32(data, 20);
    let n_special_slots = read_be_u32(data, 24);
    let n_code_slots = read_be_u32(data, 28);
    let code_limit = read_be_u32(data, 32);
    let hash_size = data[36];
    let hash_type = data[37];
    let page_size_log2 = data[39];

    // Version 0x20400 and later have exec segment fields at offset 64
    let (exec_seg_base, exec_seg_limit, exec_seg_flags) = if version >= 0x20400 && data.len() >= 88
    {
        (
            read_be_u64(data, 64),
            read_be_u64(data, 72),
            read_be_u64(data, 80),
        )
    } else {
        (0, 0, 0)
    };

    // Extract identifier (null-terminated string at ident_offset)
    let identifier = if (ident_offset as usize) < data.len() {
        let id_start = ident_offset as usize;
        let id_end = data[id_start..]
            .iter()
            .position(|&b| b == 0)
            .map(|pos| id_start + pos)
            .unwrap_or(data.len());
        String::from_utf8_lossy(&data[id_start..id_end]).to_string()
    } else {
        String::new()
    };

    Some(CodeDirectoryInfo {
        magic,
        length,
        version,
        flags,
        hash_offset,
        ident_offset,
        n_special_slots,
        n_code_slots,
        code_limit,
        hash_size,
        hash_type,
        page_size_log2,
        exec_seg_base,
        exec_seg_limit,
        exec_seg_flags,
        identifier,
    })
}

/// Parse a SuperBlob
fn parse_superblob(data: &[u8]) -> Option<SuperBlobInfo> {
    if data.len() < 12 {
        return None;
    }

    let magic = read_be_u32(data, 0);
    if magic != CSMAGIC_EMBEDDED_SIGNATURE {
        return None;
    }

    let length = read_be_u32(data, 4);
    let count = read_be_u32(data, 8);

    let mut entries = Vec::with_capacity(count as usize);
    for i in 0..count as usize {
        let idx_offset = 12 + i * 8;
        if idx_offset + 8 > data.len() {
            break;
        }
        entries.push(BlobIndexEntry {
            slot_type: read_be_u32(data, idx_offset),
            offset: read_be_u32(data, idx_offset + 4),
        });
    }

    Some(SuperBlobInfo {
        magic,
        length,
        count,
        entries,
    })
}

/// Get blob size from a blob at the given offset
fn get_blob_size(data: &[u8], offset: usize) -> Option<u32> {
    if offset + 8 > data.len() {
        return None;
    }
    Some(read_be_u32(data, offset + 4))
}

/// Find code signature in a single-arch Mach-O binary
fn find_code_signature_single(data: &[u8], is_64: bool, is_swap: bool) -> Option<(u32, u32)> {
    let header_size = if is_64 { 32 } else { 28 };
    if data.len() < header_size {
        return None;
    }

    let ncmds = if is_swap {
        read_le_u32(data, 16).swap_bytes()
    } else {
        read_le_u32(data, 16)
    };

    let mut offset = header_size;
    for _ in 0..ncmds {
        if offset + 8 > data.len() {
            break;
        }

        let cmd = if is_swap {
            read_le_u32(data, offset).swap_bytes()
        } else {
            read_le_u32(data, offset)
        };
        let cmdsize = if is_swap {
            read_le_u32(data, offset + 4).swap_bytes()
        } else {
            read_le_u32(data, offset + 4)
        };

        if cmd == LC_CODE_SIGNATURE {
            if offset + 16 > data.len() {
                break;
            }
            let sig_offset = if is_swap {
                read_le_u32(data, offset + 8).swap_bytes()
            } else {
                read_le_u32(data, offset + 8)
            };
            let sig_size = if is_swap {
                read_le_u32(data, offset + 12).swap_bytes()
            } else {
                read_le_u32(data, offset + 12)
            };
            return Some((sig_offset, sig_size));
        }

        offset += cmdsize as usize;
    }

    None
}

/// Extract signature information from a Mach-O binary
fn extract_signature_info(data: &[u8]) -> Option<SignatureInfo> {
    if data.len() < 4 {
        return None;
    }

    let magic = read_le_u32(data, 0);

    // Handle FAT binaries - use the first architecture
    let (slice_data, slice_offset) = match magic {
        FAT_MAGIC | FAT_CIGAM => {
            if data.len() < 8 {
                return None;
            }
            let nfat = if magic == FAT_CIGAM {
                read_be_u32(data, 4).swap_bytes()
            } else {
                read_be_u32(data, 4)
            };
            if nfat == 0 || data.len() < 8 + 20 {
                return None;
            }
            // First arch at offset 8
            let arch_offset = if magic == FAT_CIGAM {
                read_be_u32(data, 16).swap_bytes()
            } else {
                read_be_u32(data, 16)
            };
            let arch_size = if magic == FAT_CIGAM {
                read_be_u32(data, 20).swap_bytes()
            } else {
                read_be_u32(data, 20)
            };

            if arch_offset as usize + arch_size as usize > data.len() {
                return None;
            }
            (
                &data[arch_offset as usize..(arch_offset + arch_size) as usize],
                arch_offset,
            )
        }
        _ => (data, 0),
    };

    if slice_data.len() < 4 {
        return None;
    }

    let slice_magic = read_le_u32(slice_data, 0);
    let (is_64, is_swap) = match slice_magic {
        MH_MAGIC => (false, false),
        MH_MAGIC_64 => (true, false),
        MH_CIGAM => (false, true),
        MH_CIGAM_64 => (true, true),
        _ => return None,
    };

    let (sig_offset, sig_size) = find_code_signature_single(slice_data, is_64, is_swap)?;

    // Signature offset is relative to slice
    let abs_sig_offset = slice_offset + sig_offset;

    if abs_sig_offset as usize + sig_size as usize > data.len() {
        return None;
    }

    let sig_data = &data[abs_sig_offset as usize..(abs_sig_offset + sig_size) as usize];
    let superblob = parse_superblob(sig_data);

    let mut info = SignatureInfo {
        signature_size: sig_size,
        signature_offset: abs_sig_offset,
        superblob: superblob.clone(),
        code_directory_sha1: None,
        code_directory_sha256: None,
        requirements_size: None,
        entitlements_size: None,
        der_entitlements_size: None,
        cms_signature_size: None,
    };

    if let Some(ref sb) = superblob {
        for entry in &sb.entries {
            let blob_offset = entry.offset as usize;
            if blob_offset >= sig_data.len() {
                continue;
            }

            let blob_data = &sig_data[blob_offset..];

            match entry.slot_type {
                CSSLOT_CODEDIRECTORY => {
                    info.code_directory_sha1 = parse_code_directory(blob_data);
                }
                CSSLOT_ALTERNATE_CODEDIRECTORIES => {
                    info.code_directory_sha256 = parse_code_directory(blob_data);
                }
                CSSLOT_REQUIREMENTS => {
                    info.requirements_size = get_blob_size(sig_data, blob_offset);
                }
                CSSLOT_ENTITLEMENTS => {
                    info.entitlements_size = get_blob_size(sig_data, blob_offset);
                }
                CSSLOT_DER_ENTITLEMENTS => {
                    info.der_entitlements_size = get_blob_size(sig_data, blob_offset);
                }
                CSSLOT_SIGNATURESLOT => {
                    info.cms_signature_size = get_blob_size(sig_data, blob_offset);
                }
                _ => {}
            }
        }
    }

    Some(info)
}

/// Extract a binary from an IPA and get its signature info
fn get_binary_signature_from_ipa(ipa_path: &Path) -> Vec<(String, SignatureInfo)> {
    let file = File::open(ipa_path).expect("Failed to open IPA");
    let mut archive = ZipArchive::new(file).expect("Failed to read ZIP");

    let mut results = Vec::new();

    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).expect("Failed to read entry");
        let name = entry.name().to_string();

        // Look for Mach-O binaries in the .app directory
        if name.contains(".app/") && !name.ends_with('/') {
            let mut data = Vec::new();
            if entry.read_to_end(&mut data).is_err() {
                continue;
            }

            // Check for Mach-O magic
            if data.len() < 4 {
                continue;
            }

            let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
            if matches!(
                magic,
                MH_MAGIC | MH_MAGIC_64 | MH_CIGAM | MH_CIGAM_64 | FAT_MAGIC | FAT_CIGAM
            ) {
                if let Some(info) = extract_signature_info(&data) {
                    results.push((name, info));
                }
            }
        }
    }

    results
}

/// Compare CodeDirectory structures and report differences
fn compare_code_directories(
    name: &str,
    cpp_cd: &CodeDirectoryInfo,
    rust_cd: &CodeDirectoryInfo,
) -> Vec<String> {
    let mut diffs = Vec::new();

    if cpp_cd.version != rust_cd.version {
        diffs.push(format!(
            "{}: version differs: C++={:#x} Rust={:#x}",
            name, cpp_cd.version, rust_cd.version
        ));
    }

    if cpp_cd.flags != rust_cd.flags {
        diffs.push(format!(
            "{}: flags differs: C++={:#x} Rust={:#x}",
            name, cpp_cd.flags, rust_cd.flags
        ));
    }

    if cpp_cd.n_special_slots != rust_cd.n_special_slots {
        diffs.push(format!(
            "{}: n_special_slots differs: C++={} Rust={}",
            name, cpp_cd.n_special_slots, rust_cd.n_special_slots
        ));
    }

    if cpp_cd.n_code_slots != rust_cd.n_code_slots {
        diffs.push(format!(
            "{}: n_code_slots differs: C++={} Rust={}",
            name, cpp_cd.n_code_slots, rust_cd.n_code_slots
        ));
    }

    if cpp_cd.code_limit != rust_cd.code_limit {
        diffs.push(format!(
            "{}: code_limit differs: C++={} Rust={}",
            name, cpp_cd.code_limit, rust_cd.code_limit
        ));
    }

    if cpp_cd.hash_size != rust_cd.hash_size {
        diffs.push(format!(
            "{}: hash_size differs: C++={} Rust={}",
            name, cpp_cd.hash_size, rust_cd.hash_size
        ));
    }

    if cpp_cd.hash_type != rust_cd.hash_type {
        diffs.push(format!(
            "{}: hash_type differs: C++={} Rust={}",
            name, cpp_cd.hash_type, rust_cd.hash_type
        ));
    }

    if cpp_cd.page_size_log2 != rust_cd.page_size_log2 {
        diffs.push(format!(
            "{}: page_size_log2 differs: C++={} Rust={}",
            name, cpp_cd.page_size_log2, rust_cd.page_size_log2
        ));
    }

    if cpp_cd.exec_seg_flags != rust_cd.exec_seg_flags {
        diffs.push(format!(
            "{}: exec_seg_flags differs: C++={:#x} Rust={:#x}",
            name, cpp_cd.exec_seg_flags, rust_cd.exec_seg_flags
        ));
    }

    if cpp_cd.exec_seg_limit != rust_cd.exec_seg_limit {
        diffs.push(format!(
            "{}: exec_seg_limit differs: C++={} Rust={}",
            name, cpp_cd.exec_seg_limit, rust_cd.exec_seg_limit
        ));
    }

    if cpp_cd.identifier != rust_cd.identifier {
        diffs.push(format!(
            "{}: identifier differs: C++='{}' Rust='{}'",
            name, cpp_cd.identifier, rust_cd.identifier
        ));
    }

    diffs
}

/// Compare signature information and return differences
fn compare_signatures(
    binary_name: &str,
    cpp_sig: &SignatureInfo,
    rust_sig: &SignatureInfo,
) -> Vec<String> {
    let mut diffs = Vec::new();

    // Compare overall signature size
    if cpp_sig.signature_size != rust_sig.signature_size {
        diffs.push(format!(
            "{}: signature_size differs: C++={} Rust={} (diff={})",
            binary_name,
            cpp_sig.signature_size,
            rust_sig.signature_size,
            (cpp_sig.signature_size as i64 - rust_sig.signature_size as i64).abs()
        ));
    }

    // Compare requirements size
    match (&cpp_sig.requirements_size, &rust_sig.requirements_size) {
        (Some(cpp), Some(rust)) if cpp != rust => {
            diffs.push(format!(
                "{}: requirements_size differs: C++={} Rust={}",
                binary_name, cpp, rust
            ));
        }
        (Some(cpp), None) => {
            diffs.push(format!(
                "{}: requirements missing in Rust (C++ has {} bytes)",
                binary_name, cpp
            ));
        }
        (None, Some(rust)) => {
            diffs.push(format!(
                "{}: requirements missing in C++ (Rust has {} bytes)",
                binary_name, rust
            ));
        }
        _ => {}
    }

    // Compare CMS signature size
    match (&cpp_sig.cms_signature_size, &rust_sig.cms_signature_size) {
        (Some(cpp), Some(rust)) if cpp != rust => {
            diffs.push(format!(
                "{}: cms_signature_size differs: C++={} Rust={}",
                binary_name, cpp, rust
            ));
        }
        _ => {}
    }

    // Compare SHA-1 CodeDirectory
    match (&cpp_sig.code_directory_sha1, &rust_sig.code_directory_sha1) {
        (Some(cpp_cd), Some(rust_cd)) => {
            diffs.extend(compare_code_directories(
                &format!("{} (SHA1 CD)", binary_name),
                cpp_cd,
                rust_cd,
            ));
        }
        (Some(_), None) => {
            diffs.push(format!("{}: SHA-1 CodeDirectory missing in Rust", binary_name));
        }
        (None, Some(_)) => {
            diffs.push(format!("{}: SHA-1 CodeDirectory missing in C++", binary_name));
        }
        _ => {}
    }

    // Compare SHA-256 CodeDirectory
    match (
        &cpp_sig.code_directory_sha256,
        &rust_sig.code_directory_sha256,
    ) {
        (Some(cpp_cd), Some(rust_cd)) => {
            diffs.extend(compare_code_directories(
                &format!("{} (SHA256 CD)", binary_name),
                cpp_cd,
                rust_cd,
            ));
        }
        (Some(_), None) => {
            diffs.push(format!(
                "{}: SHA-256 CodeDirectory missing in Rust",
                binary_name
            ));
        }
        (None, Some(_)) => {
            diffs.push(format!(
                "{}: SHA-256 CodeDirectory missing in C++",
                binary_name
            ));
        }
        _ => {}
    }

    diffs
}

#[test]
#[ignore = "Requires external test files and C++ zsign binary"]
fn test_cpp_parity_empty_ipa() {
    if !prerequisites_exist() {
        eprintln!("Skipping test: prerequisites not found");
        eprintln!("Required files:");
        eprintln!("  - C++ zsign: {}", CPP_ZSIGN_PATH);
        eprintln!("  - Test IPA: {}/Empty.ipa", TEST_FILES_DIR);
        eprintln!("  - Certificate: {}/cert.pem", TEST_FILES_DIR);
        eprintln!("  - Private key: {}/key.pem", TEST_FILES_DIR);
        return;
    }

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let test_files = PathBuf::from(TEST_FILES_DIR);

    let input_ipa = test_files.join("Empty.ipa");
    let cert_path = test_files.join("cert.pem");
    let key_path = test_files.join("key.pem");
    let prov_profile = find_provisioning_profile();

    let cpp_output = temp_dir.path().join("cpp_signed.ipa");
    let rust_output = temp_dir.path().join("rust_signed.ipa");

    // Sign with both implementations
    sign_with_cpp_zsign(
        &input_ipa,
        &cpp_output,
        &cert_path,
        &key_path,
        prov_profile.as_deref(),
    )
    .expect("C++ zsign signing failed");

    sign_with_rust_zsign(
        &input_ipa,
        &rust_output,
        &cert_path,
        &key_path,
        prov_profile.as_deref(),
    )
    .expect("Rust zsign signing failed");

    // Compare output file sizes
    let cpp_size = fs::metadata(&cpp_output).expect("Failed to get C++ output size").len();
    let rust_size = fs::metadata(&rust_output).expect("Failed to get Rust output size").len();

    println!("=== Empty IPA Parity Test ===\n");
    println!("Output File Sizes:");
    println!("  C++ zsign:  {} bytes ({:.2} KB)", cpp_size, cpp_size as f64 / 1024.0);
    println!("  Rust zsign: {} bytes ({:.2} KB)", rust_size, rust_size as f64 / 1024.0);
    println!("  Difference: {} bytes", (cpp_size as i64 - rust_size as i64).abs());
    println!();

    // Extract and compare binary signatures
    let cpp_sigs = get_binary_signature_from_ipa(&cpp_output);
    let rust_sigs = get_binary_signature_from_ipa(&rust_output);

    println!("Binary Signatures Found:");
    println!("  C++:  {} binaries", cpp_sigs.len());
    println!("  Rust: {} binaries", rust_sigs.len());
    println!();

    let mut all_diffs = Vec::new();

    for (cpp_name, cpp_sig) in &cpp_sigs {
        println!("=== {} ===", cpp_name);
        println!("C++ signature: {} bytes at offset {}", cpp_sig.signature_size, cpp_sig.signature_offset);

        if let Some(ref sb) = cpp_sig.superblob {
            println!("  SuperBlob: {} entries", sb.count);
        }
        if let Some(ref cd) = cpp_sig.code_directory_sha1 {
            println!("  SHA-1 CodeDirectory:");
            println!("    n_special_slots: {}", cd.n_special_slots);
            println!("    n_code_slots: {}", cd.n_code_slots);
            println!("    code_limit: {}", cd.code_limit);
            println!("    exec_seg_flags: {:#x}", cd.exec_seg_flags);
            println!("    identifier: {}", cd.identifier);
        }
        if let Some(size) = cpp_sig.requirements_size {
            println!("  Requirements: {} bytes", size);
        }
        if let Some(size) = cpp_sig.cms_signature_size {
            println!("  CMS Signature: {} bytes", size);
        }
        println!();

        // Find matching Rust signature
        if let Some((_, rust_sig)) = rust_sigs.iter().find(|(n, _)| n == cpp_name) {
            println!("Rust signature: {} bytes at offset {}", rust_sig.signature_size, rust_sig.signature_offset);

            if let Some(ref sb) = rust_sig.superblob {
                println!("  SuperBlob: {} entries", sb.count);
            }
            if let Some(ref cd) = rust_sig.code_directory_sha1 {
                println!("  SHA-1 CodeDirectory:");
                println!("    n_special_slots: {}", cd.n_special_slots);
                println!("    n_code_slots: {}", cd.n_code_slots);
                println!("    code_limit: {}", cd.code_limit);
                println!("    exec_seg_flags: {:#x}", cd.exec_seg_flags);
                println!("    identifier: {}", cd.identifier);
            }
            if let Some(size) = rust_sig.requirements_size {
                println!("  Requirements: {} bytes", size);
            }
            if let Some(size) = rust_sig.cms_signature_size {
                println!("  CMS Signature: {} bytes", size);
            }
            println!();

            // Compare and collect differences
            let diffs = compare_signatures(cpp_name, cpp_sig, rust_sig);
            if diffs.is_empty() {
                println!("  ✓ Signatures match!");
            } else {
                println!("  ✗ Differences found:");
                for diff in &diffs {
                    println!("    - {}", diff);
                }
                all_diffs.extend(diffs);
            }
            println!();
        } else {
            all_diffs.push(format!("{}: not found in Rust output", cpp_name));
        }
    }

    // Print summary
    println!("=== Summary ===");
    if all_diffs.is_empty() {
        println!("All signatures match between C++ and Rust implementations!");
    } else {
        println!("Differences found ({} total):", all_diffs.len());
        for diff in &all_diffs {
            println!("  - {}", diff);
        }
    }

    // Warn but don't fail on differences (informational test)
    if !all_diffs.is_empty() {
        println!("\nNote: Differences detected. Review the above output for parity issues.");
    }
}

#[test]
#[ignore = "Requires external test files and C++ zsign binary"]
fn test_cpp_parity_code_directory_structure() {
    //! This test specifically compares CodeDirectory structure between implementations.

    if !prerequisites_exist() {
        eprintln!("Skipping test: prerequisites not found");
        return;
    }

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let test_files = PathBuf::from(TEST_FILES_DIR);

    let input_ipa = test_files.join("Empty.ipa");
    let cert_path = test_files.join("cert.pem");
    let key_path = test_files.join("key.pem");
    let prov_profile = find_provisioning_profile();

    let cpp_output = temp_dir.path().join("cpp_signed.ipa");
    let rust_output = temp_dir.path().join("rust_signed.ipa");

    sign_with_cpp_zsign(
        &input_ipa,
        &cpp_output,
        &cert_path,
        &key_path,
        prov_profile.as_deref(),
    )
    .expect("C++ zsign signing failed");

    sign_with_rust_zsign(
        &input_ipa,
        &rust_output,
        &cert_path,
        &key_path,
        prov_profile.as_deref(),
    )
    .expect("Rust zsign signing failed");

    let cpp_sigs = get_binary_signature_from_ipa(&cpp_output);
    let rust_sigs = get_binary_signature_from_ipa(&rust_output);

    println!("=== CodeDirectory Structure Comparison ===\n");

    let mut has_cd_diffs = false;

    for (cpp_name, cpp_sig) in &cpp_sigs {
        let rust_sig = rust_sigs.iter().find(|(n, _)| n == cpp_name).map(|(_, s)| s);

        if let Some(rust_sig) = rust_sig {
            // Compare SHA-1 CodeDirectory
            if let (Some(cpp_cd), Some(rust_cd)) =
                (&cpp_sig.code_directory_sha1, &rust_sig.code_directory_sha1)
            {
                let diffs = compare_code_directories(&format!("{} SHA-1", cpp_name), cpp_cd, rust_cd);
                if !diffs.is_empty() {
                    has_cd_diffs = true;
                    println!("SHA-1 CodeDirectory differences for {}:", cpp_name);
                    for diff in diffs {
                        println!("  {}", diff);
                    }
                }
            }

            // Compare SHA-256 CodeDirectory
            if let (Some(cpp_cd), Some(rust_cd)) = (
                &cpp_sig.code_directory_sha256,
                &rust_sig.code_directory_sha256,
            ) {
                let diffs = compare_code_directories(&format!("{} SHA-256", cpp_name), cpp_cd, rust_cd);
                if !diffs.is_empty() {
                    has_cd_diffs = true;
                    println!("SHA-256 CodeDirectory differences for {}:", cpp_name);
                    for diff in diffs {
                        println!("  {}", diff);
                    }
                }
            }
        }
    }

    if !has_cd_diffs {
        println!("All CodeDirectory structures match!");
    }
}

#[test]
#[ignore = "Requires external test files and C++ zsign binary"]
fn test_cpp_parity_signature_sizes() {
    //! This test focuses on comparing signature blob sizes.

    if !prerequisites_exist() {
        eprintln!("Skipping test: prerequisites not found");
        return;
    }

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let test_files = PathBuf::from(TEST_FILES_DIR);

    let input_ipa = test_files.join("Empty.ipa");
    let cert_path = test_files.join("cert.pem");
    let key_path = test_files.join("key.pem");
    let prov_profile = find_provisioning_profile();

    let cpp_output = temp_dir.path().join("cpp_signed.ipa");
    let rust_output = temp_dir.path().join("rust_signed.ipa");

    sign_with_cpp_zsign(
        &input_ipa,
        &cpp_output,
        &cert_path,
        &key_path,
        prov_profile.as_deref(),
    )
    .expect("C++ zsign signing failed");

    sign_with_rust_zsign(
        &input_ipa,
        &rust_output,
        &cert_path,
        &key_path,
        prov_profile.as_deref(),
    )
    .expect("Rust zsign signing failed");

    let cpp_sigs = get_binary_signature_from_ipa(&cpp_output);
    let rust_sigs = get_binary_signature_from_ipa(&rust_output);

    println!("=== Signature Size Comparison ===\n");
    println!(
        "{:<50} {:>12} {:>12} {:>12}",
        "Binary", "C++ Size", "Rust Size", "Diff"
    );
    println!("{}", "-".repeat(86));

    for (cpp_name, cpp_sig) in &cpp_sigs {
        if let Some((_, rust_sig)) = rust_sigs.iter().find(|(n, _)| n == cpp_name) {
            let diff = cpp_sig.signature_size as i64 - rust_sig.signature_size as i64;
            let diff_str = if diff == 0 {
                "0".to_string()
            } else if diff > 0 {
                format!("+{}", diff)
            } else {
                format!("{}", diff)
            };

            println!(
                "{:<50} {:>12} {:>12} {:>12}",
                cpp_name, cpp_sig.signature_size, rust_sig.signature_size, diff_str
            );
        }
    }

    println!();
    println!("Component sizes:");
    println!(
        "{:<50} {:>12} {:>12}",
        "Component", "C++ Size", "Rust Size"
    );
    println!("{}", "-".repeat(74));

    for (cpp_name, cpp_sig) in &cpp_sigs {
        if let Some((_, rust_sig)) = rust_sigs.iter().find(|(n, _)| n == cpp_name) {
            println!("{}:", cpp_name);

            if let (Some(cpp_req), Some(rust_req)) =
                (cpp_sig.requirements_size, rust_sig.requirements_size)
            {
                println!("  {:<48} {:>12} {:>12}", "Requirements", cpp_req, rust_req);
            }

            if let (Some(cpp_cd), Some(rust_cd)) =
                (&cpp_sig.code_directory_sha1, &rust_sig.code_directory_sha1)
            {
                println!(
                    "  {:<48} {:>12} {:>12}",
                    "CodeDirectory SHA-1", cpp_cd.length, rust_cd.length
                );
            }

            if let (Some(cpp_cd), Some(rust_cd)) = (
                &cpp_sig.code_directory_sha256,
                &rust_sig.code_directory_sha256,
            ) {
                println!(
                    "  {:<48} {:>12} {:>12}",
                    "CodeDirectory SHA-256", cpp_cd.length, rust_cd.length
                );
            }

            if let (Some(cpp_cms), Some(rust_cms)) =
                (cpp_sig.cms_signature_size, rust_sig.cms_signature_size)
            {
                println!("  {:<48} {:>12} {:>12}", "CMS Signature", cpp_cms, rust_cms);
            }
        }
    }
}

#[test]
#[ignore = "Requires external test files and C++ zsign binary"]
fn test_cpp_parity_requirements_blob() {
    //! This test specifically checks if requirements blob generation matches C++.

    if !prerequisites_exist() {
        eprintln!("Skipping test: prerequisites not found");
        return;
    }

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let test_files = PathBuf::from(TEST_FILES_DIR);

    let input_ipa = test_files.join("Empty.ipa");
    let cert_path = test_files.join("cert.pem");
    let key_path = test_files.join("key.pem");
    let prov_profile = find_provisioning_profile();

    let cpp_output = temp_dir.path().join("cpp_signed.ipa");
    let rust_output = temp_dir.path().join("rust_signed.ipa");

    sign_with_cpp_zsign(
        &input_ipa,
        &cpp_output,
        &cert_path,
        &key_path,
        prov_profile.as_deref(),
    )
    .expect("C++ zsign signing failed");

    sign_with_rust_zsign(
        &input_ipa,
        &rust_output,
        &cert_path,
        &key_path,
        prov_profile.as_deref(),
    )
    .expect("Rust zsign signing failed");

    let cpp_sigs = get_binary_signature_from_ipa(&cpp_output);
    let rust_sigs = get_binary_signature_from_ipa(&rust_output);

    println!("=== Requirements Blob Comparison ===\n");

    for (cpp_name, cpp_sig) in &cpp_sigs {
        if let Some((_, rust_sig)) = rust_sigs.iter().find(|(n, _)| n == cpp_name) {
            println!("{}:", cpp_name);

            match (cpp_sig.requirements_size, rust_sig.requirements_size) {
                (Some(cpp_size), Some(rust_size)) => {
                    if cpp_size == rust_size {
                        println!("  ✓ Requirements size matches: {} bytes", cpp_size);
                    } else {
                        println!("  ✗ Requirements size differs:");
                        println!("    C++:  {} bytes", cpp_size);
                        println!("    Rust: {} bytes", rust_size);

                        // The minimal requirements blob is 12 bytes
                        // Full requirements with bundle ID + cert CN is larger
                        if rust_size == 12 && cpp_size > 12 {
                            println!(
                                "    Note: Rust is using empty requirements (12 bytes) while C++ has full requirements"
                            );
                        }
                    }
                }
                (Some(cpp_size), None) => {
                    println!("  ✗ Requirements missing in Rust (C++ has {} bytes)", cpp_size);
                }
                (None, Some(rust_size)) => {
                    println!("  ✗ Requirements missing in C++ (Rust has {} bytes)", rust_size);
                }
                (None, None) => {
                    println!("  - No requirements blob in either");
                }
            }
            println!();
        }
    }
}
