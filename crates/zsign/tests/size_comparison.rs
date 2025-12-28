//! Integration tests comparing Rust zsign output with C++ zsign output.
//!
//! These tests verify that the Rust implementation produces similar output sizes
//! to the C++ implementation, which is a key indicator that binary expansion
//! (ReallocCodeSignSpace) is working correctly.
//!
//! The tests are marked as `#[ignore]` because they require:
//! - External test files (IPA, certificates, provisioning profile)
//! - C++ zsign binary at /Users/dimaz/workspace/projects/zsign/bin/zsign
//!
//! Run with: cargo test --test size_comparison -- --ignored

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

/// Path to the C++ zsign binary
const CPP_ZSIGN_PATH: &str = "/Users/dimaz/workspace/projects/zsign/bin/zsign";

/// Directory containing test files (IPA, certs, etc.)
const TEST_FILES_DIR: &str = "/Users/dimaz/workspace/projects/zsign-rust/tmp";

/// Tolerance for size comparison (5% difference allowed)
const SIZE_TOLERANCE_PERCENT: f64 = 5.0;

/// Check if test prerequisites exist
fn prerequisites_exist() -> bool {
    Path::new(CPP_ZSIGN_PATH).exists()
        && Path::new(TEST_FILES_DIR).join("Empty.ipa").exists()
        && Path::new(TEST_FILES_DIR).join("cert.pem").exists()
        && Path::new(TEST_FILES_DIR).join("key.pem").exists()
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
    use zsign::{IpaSigner, crypto::SigningAssets};

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

/// Get file size in bytes
fn get_file_size(path: &Path) -> std::io::Result<u64> {
    fs::metadata(path).map(|m| m.len())
}

/// Compare two file sizes and check if they're within tolerance
fn sizes_within_tolerance(size1: u64, size2: u64, tolerance_percent: f64) -> bool {
    let larger = size1.max(size2) as f64;
    let smaller = size1.min(size2) as f64;
    let diff_percent = ((larger - smaller) / larger) * 100.0;
    diff_percent <= tolerance_percent
}

/// Calculate percentage difference between two sizes
fn size_difference_percent(size1: u64, size2: u64) -> f64 {
    let larger = size1.max(size2) as f64;
    let smaller = size1.min(size2) as f64;
    ((larger - smaller) / larger) * 100.0
}

#[test]
#[ignore = "Requires external test files and C++ zsign binary"]
fn test_empty_ipa_size_comparison() {
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

    // Find provisioning profile if available
    let prov_profile = test_files
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
        });

    let cpp_output = temp_dir.path().join("cpp_signed.ipa");
    let rust_output = temp_dir.path().join("rust_signed.ipa");

    // Sign with C++ zsign
    sign_with_cpp_zsign(
        &input_ipa,
        &cpp_output,
        &cert_path,
        &key_path,
        prov_profile.as_deref(),
    )
    .expect("C++ zsign signing failed");

    // Sign with Rust zsign
    sign_with_rust_zsign(
        &input_ipa,
        &rust_output,
        &cert_path,
        &key_path,
        prov_profile.as_deref(),
    )
    .expect("Rust zsign signing failed");

    // Compare file sizes
    let cpp_size = get_file_size(&cpp_output).expect("Failed to get C++ output size");
    let rust_size = get_file_size(&rust_output).expect("Failed to get Rust output size");

    println!("=== IPA Size Comparison ===");
    println!("Input IPA: {:?}", input_ipa);
    println!("C++ zsign output:  {} bytes ({:.2} KB)", cpp_size, cpp_size as f64 / 1024.0);
    println!("Rust zsign output: {} bytes ({:.2} KB)", rust_size, rust_size as f64 / 1024.0);
    println!(
        "Size difference: {:.2}%",
        size_difference_percent(cpp_size, rust_size)
    );
    println!("Tolerance: {}%", SIZE_TOLERANCE_PERCENT);

    // Primary assertion: sizes should be within tolerance
    assert!(
        sizes_within_tolerance(cpp_size, rust_size, SIZE_TOLERANCE_PERCENT),
        "Output sizes differ by more than {}%: C++={} bytes, Rust={} bytes (diff: {:.2}%)",
        SIZE_TOLERANCE_PERCENT,
        cpp_size,
        rust_size,
        size_difference_percent(cpp_size, rust_size)
    );
}

#[test]
#[ignore = "Requires external test files and C++ zsign binary"]
fn test_surge_ipa_size_comparison() {
    let test_files = PathBuf::from(TEST_FILES_DIR);
    let surge_ipa = test_files.join("Surge_5_16_0iOS15专用JumoBaBa已注入MacKedV2_blatant_patched.ipa");

    if !surge_ipa.exists() {
        eprintln!("Skipping Surge IPA test: file not found");
        return;
    }

    if !prerequisites_exist() {
        eprintln!("Skipping test: prerequisites not found");
        return;
    }

    let temp_dir = TempDir::new().expect("Failed to create temp dir");

    let cert_path = test_files.join("cert.pem");
    let key_path = test_files.join("key.pem");

    // Find provisioning profile
    let prov_profile = test_files
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
        });

    let cpp_output = temp_dir.path().join("surge_cpp_signed.ipa");
    let rust_output = temp_dir.path().join("surge_rust_signed.ipa");

    // Sign with C++ zsign
    sign_with_cpp_zsign(
        &surge_ipa,
        &cpp_output,
        &cert_path,
        &key_path,
        prov_profile.as_deref(),
    )
    .expect("C++ zsign signing failed");

    // Sign with Rust zsign
    sign_with_rust_zsign(
        &surge_ipa,
        &rust_output,
        &cert_path,
        &key_path,
        prov_profile.as_deref(),
    )
    .expect("Rust zsign signing failed");

    // Compare file sizes
    let cpp_size = get_file_size(&cpp_output).expect("Failed to get C++ output size");
    let rust_size = get_file_size(&rust_output).expect("Failed to get Rust output size");

    println!("=== Surge IPA Size Comparison ===");
    println!("Input IPA: {:?}", surge_ipa);
    println!(
        "C++ zsign output:  {} bytes ({:.2} MB)",
        cpp_size,
        cpp_size as f64 / 1024.0 / 1024.0
    );
    println!(
        "Rust zsign output: {} bytes ({:.2} MB)",
        rust_size,
        rust_size as f64 / 1024.0 / 1024.0
    );
    println!(
        "Size difference: {:.2}%",
        size_difference_percent(cpp_size, rust_size)
    );

    // This test is informational - it shows the current size difference
    // The main purpose is to track progress on binary expansion
    let within_tolerance = sizes_within_tolerance(cpp_size, rust_size, SIZE_TOLERANCE_PERCENT);
    if within_tolerance {
        println!("✓ Sizes are within {}% tolerance", SIZE_TOLERANCE_PERCENT);
    } else {
        println!(
            "✗ Sizes differ by {:.2}% (exceeds {}% tolerance)",
            size_difference_percent(cpp_size, rust_size),
            SIZE_TOLERANCE_PERCENT
        );
    }

    // Assert that Rust output is at least close to C++ output
    // This is the key metric: if ReallocCodeSignSpace is working,
    // Rust output should be similar to C++ output
    assert!(
        within_tolerance,
        "Rust output ({:.2} MB) differs significantly from C++ output ({:.2} MB). \
         This suggests ReallocCodeSignSpace may not be working correctly.",
        rust_size as f64 / 1024.0 / 1024.0,
        cpp_size as f64 / 1024.0 / 1024.0
    );
}

#[test]
#[ignore = "Requires external test files and C++ zsign binary"]
fn test_binary_expansion_verification() {
    //! This test verifies that binaries are properly expanded during signing.
    //! The key indicator is that signed output should be larger than input
    //! because code signatures require additional space in the binary.

    if !prerequisites_exist() {
        eprintln!("Skipping test: prerequisites not found");
        return;
    }

    let test_files = PathBuf::from(TEST_FILES_DIR);
    let input_ipa = test_files.join("Empty.ipa");
    let cert_path = test_files.join("cert.pem");
    let key_path = test_files.join("key.pem");

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let rust_output = temp_dir.path().join("rust_signed.ipa");

    // Get original input size
    let input_size = get_file_size(&input_ipa).expect("Failed to get input size");

    // Sign with Rust zsign
    sign_with_rust_zsign(&input_ipa, &rust_output, &cert_path, &key_path, None)
        .expect("Rust zsign signing failed");

    let output_size = get_file_size(&rust_output).expect("Failed to get output size");

    println!("=== Binary Expansion Verification ===");
    println!("Input IPA:  {} bytes ({:.2} KB)", input_size, input_size as f64 / 1024.0);
    println!("Output IPA: {} bytes ({:.2} KB)", output_size, output_size as f64 / 1024.0);

    if output_size > input_size {
        println!(
            "✓ Binary expanded by {} bytes ({:.2}%)",
            output_size - input_size,
            ((output_size - input_size) as f64 / input_size as f64) * 100.0
        );
    } else {
        println!(
            "✗ Binary did not expand (shrunk by {} bytes)",
            input_size - output_size
        );
    }

    // Note: It's valid for signed IPA to be smaller if compression differs,
    // but we expect the Mach-O binaries inside to be larger.
    // This test is mainly informational.
}

/// Test helper to extract and compare individual binary sizes
#[test]
#[ignore = "Requires external test files and C++ zsign binary"]
fn test_macho_binary_size_comparison() {
    //! Compares individual Mach-O binary sizes between C++ and Rust signed IPAs.
    //! This is the most accurate test for ReallocCodeSignSpace because
    //! it directly measures binary sizes, not IPA sizes (which include compression).

    use std::io::Read;
    use zip::ZipArchive;

    if !prerequisites_exist() {
        eprintln!("Skipping test: prerequisites not found");
        return;
    }

    let test_files = PathBuf::from(TEST_FILES_DIR);
    let input_ipa = test_files.join("Empty.ipa");
    let cert_path = test_files.join("cert.pem");
    let key_path = test_files.join("key.pem");

    // Find provisioning profile
    let prov_profile = test_files
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
        });

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let cpp_output = temp_dir.path().join("cpp_signed.ipa");
    let rust_output = temp_dir.path().join("rust_signed.ipa");

    // Sign with both tools
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

    // Extract and compare Mach-O binaries
    fn get_binary_sizes(ipa_path: &Path) -> Vec<(String, u64)> {
        let file = fs::File::open(ipa_path).expect("Failed to open IPA");
        let mut archive = ZipArchive::new(file).expect("Failed to read ZIP");

        let mut binaries = Vec::new();

        for i in 0..archive.len() {
            let mut entry = archive.by_index(i).expect("Failed to read entry");
            let name = entry.name().to_string();

            // Check if this looks like a Mach-O binary
            // (in the .app directory, no extension, or .dylib extension)
            if name.contains(".app/") && !name.ends_with('/') {
                // Read first 4 bytes to check for Mach-O magic
                let mut magic = [0u8; 4];
                if entry.read_exact(&mut magic).is_ok() {
                    // Check for Mach-O magic numbers
                    let magic_u32 = u32::from_le_bytes(magic);
                    if matches!(
                        magic_u32,
                        0xFEEDFACE | 0xFEEDFACF | 0xCAFEBABE | 0xBEBAFECA
                    ) {
                        binaries.push((name, entry.size()));
                    }
                }
            }
        }

        binaries
    }

    let cpp_binaries = get_binary_sizes(&cpp_output);
    let rust_binaries = get_binary_sizes(&rust_output);

    println!("=== Mach-O Binary Size Comparison ===");
    println!();
    println!("C++ signed binaries:");
    for (name, size) in &cpp_binaries {
        println!("  {}: {} bytes", name, size);
    }

    println!();
    println!("Rust signed binaries:");
    for (name, size) in &rust_binaries {
        println!("  {}: {} bytes", name, size);
    }

    // Compare matching binaries
    println!();
    println!("Comparison:");
    let mut all_match = true;

    for (cpp_name, cpp_size) in &cpp_binaries {
        if let Some((_, rust_size)) = rust_binaries.iter().find(|(n, _)| n == cpp_name) {
            let diff_percent = size_difference_percent(*cpp_size, *rust_size);
            let within_tolerance = sizes_within_tolerance(*cpp_size, *rust_size, SIZE_TOLERANCE_PERCENT);

            if within_tolerance {
                println!("  ✓ {}: C++={}, Rust={} ({:.2}% diff)", cpp_name, cpp_size, rust_size, diff_percent);
            } else {
                println!("  ✗ {}: C++={}, Rust={} ({:.2}% diff - EXCEEDS TOLERANCE)", cpp_name, cpp_size, rust_size, diff_percent);
                all_match = false;
            }
        } else {
            println!("  ? {}: not found in Rust output", cpp_name);
        }
    }

    assert!(
        all_match,
        "Some binary sizes differ by more than {}%",
        SIZE_TOLERANCE_PERCENT
    );
}
