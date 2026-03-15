//! Benchmarks for Mach-O signing pipeline.
//!
//! Measures the hot paths optimized by the perf-stability improvements:
//! - MachOMetadata caching (eliminates redundant goblin re-parses)
//! - In-place buffer operations (reduces 3 copies to 1)
//! - Pre-built SigningKey (avoids RSA key clone per CMS call)
//!
//! # Running
//!
//! ```sh
//! cargo bench -p zsign-core
//! ```
//!
//! For before/after comparison, use git stash or branches:
//! ```sh
//! cargo bench -p zsign-core -- --save-baseline before
//! # switch to new code
//! cargo bench -p zsign-core -- --baseline before
//! ```

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use zsign_core::crypto::cert::{SigningCredentials, SigningKeyType};
use zsign_core::macho::{sign_macho, MachOFile};

/// Build a minimal valid Mach-O arm64 binary of the given code size.
///
/// Creates a single-segment __TEXT binary with a valid header
/// and load commands, padded to the requested size.
fn build_synthetic_macho(code_size: usize) -> Vec<u8> {
    assert!(code_size >= 4096, "code_size must be at least one page");

    // arm64 little-endian Mach-O
    let mut buf = vec![0u8; code_size];

    // MH_MAGIC_64
    buf[0..4].copy_from_slice(&0xFEEDFACFu32.to_le_bytes());
    // CPU_TYPE_ARM64 = 0x0100000C
    buf[4..8].copy_from_slice(&0x0100000Cu32.to_le_bytes());
    // CPU_SUBTYPE_ARM64_ALL = 0
    buf[8..12].copy_from_slice(&0u32.to_le_bytes());
    // MH_EXECUTE = 2
    buf[12..16].copy_from_slice(&2u32.to_le_bytes());
    // ncmds = 2 (__TEXT + __LINKEDIT)
    buf[16..20].copy_from_slice(&2u32.to_le_bytes());

    let header_size: usize = 32; // mach_header_64

    // --- LC_SEGMENT_64 for __TEXT ---
    let text_cmd_offset = header_size;
    let text_cmd_size: u32 = 72; // sizeof(segment_command_64)

    // LC_SEGMENT_64 = 0x19
    buf[text_cmd_offset..text_cmd_offset + 4].copy_from_slice(&0x19u32.to_le_bytes());
    // cmdsize
    buf[text_cmd_offset + 4..text_cmd_offset + 8].copy_from_slice(&text_cmd_size.to_le_bytes());
    // segname: "__TEXT\0..."
    buf[text_cmd_offset + 8..text_cmd_offset + 14].copy_from_slice(b"__TEXT");
    // vmaddr = 0x100000000
    buf[text_cmd_offset + 24..text_cmd_offset + 32]
        .copy_from_slice(&0x100000000u64.to_le_bytes());
    // vmsize = 4096
    buf[text_cmd_offset + 32..text_cmd_offset + 40].copy_from_slice(&4096u64.to_le_bytes());
    // fileoff = 0
    buf[text_cmd_offset + 40..text_cmd_offset + 48].copy_from_slice(&0u64.to_le_bytes());
    // filesize = 4096
    buf[text_cmd_offset + 48..text_cmd_offset + 56].copy_from_slice(&4096u64.to_le_bytes());

    // --- LC_SEGMENT_64 for __LINKEDIT ---
    let linkedit_cmd_offset = text_cmd_offset + text_cmd_size as usize;
    let linkedit_cmd_size: u32 = 72;

    let linkedit_fileoff = 4096u64;
    let linkedit_filesize = (code_size - 4096) as u64;

    buf[linkedit_cmd_offset..linkedit_cmd_offset + 4].copy_from_slice(&0x19u32.to_le_bytes());
    buf[linkedit_cmd_offset + 4..linkedit_cmd_offset + 8]
        .copy_from_slice(&linkedit_cmd_size.to_le_bytes());
    buf[linkedit_cmd_offset + 8..linkedit_cmd_offset + 18].copy_from_slice(b"__LINKEDIT");
    // vmaddr
    buf[linkedit_cmd_offset + 24..linkedit_cmd_offset + 32]
        .copy_from_slice(&(0x100000000u64 + linkedit_fileoff).to_le_bytes());
    // vmsize
    let linkedit_vmsize = ((linkedit_filesize as usize + 0x3FFF) & !0x3FFF) as u64;
    buf[linkedit_cmd_offset + 32..linkedit_cmd_offset + 40]
        .copy_from_slice(&linkedit_vmsize.to_le_bytes());
    // fileoff
    buf[linkedit_cmd_offset + 40..linkedit_cmd_offset + 48]
        .copy_from_slice(&linkedit_fileoff.to_le_bytes());
    // filesize
    buf[linkedit_cmd_offset + 48..linkedit_cmd_offset + 56]
        .copy_from_slice(&linkedit_filesize.to_le_bytes());

    // sizeofcmds
    let sizeofcmds = text_cmd_size + linkedit_cmd_size;
    buf[20..24].copy_from_slice(&sizeofcmds.to_le_bytes());

    buf
}

/// Create test signing credentials (self-signed RSA 2048).
fn test_credentials() -> SigningCredentials {
    use der::Decode;
    use rsa::RsaPrivateKey;
    use spki::{EncodePublicKey, SubjectPublicKeyInfoOwned};
    use std::str::FromStr;
    use std::time::Duration;
    use x509_cert::builder::{Builder, CertificateBuilder, Profile};
    use x509_cert::name::Name;
    use x509_cert::serial_number::SerialNumber;
    use x509_cert::time::Validity;

    let mut rng = rand::thread_rng();
    let rsa_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let signing_key = rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(rsa_key.clone());

    let subject = Name::from_str("CN=Bench Signer,OU=BENCHTEAM").unwrap();
    let serial = SerialNumber::from(99u32);
    let validity = Validity::from_now(Duration::from_secs(3600)).unwrap();
    let pub_key_der = rsa_key.to_public_key().to_public_key_der().unwrap();
    let pub_key = SubjectPublicKeyInfoOwned::from_der(pub_key_der.as_ref()).unwrap();

    let cert = CertificateBuilder::new(Profile::Root, serial, validity, subject, pub_key, &signing_key)
        .unwrap()
        .build::<rsa::pkcs1v15::Signature>()
        .unwrap();

    SigningCredentials {
        certificate: cert,
        signing_key: SigningKeyType::Rsa(signing_key),
        cert_chain: vec![],
        team_id: Some("BENCHTEAM".to_string()),
    }
}

fn bench_sign_macho(c: &mut Criterion) {
    let credentials = test_credentials();

    let sizes: &[(usize, &str)] = &[
        (64 * 1024, "64KB"),
        (1024 * 1024, "1MB"),
        (10 * 1024 * 1024, "10MB"),
    ];

    let mut group = c.benchmark_group("sign_macho");

    for &(size, label) in sizes {
        let macho_data = build_synthetic_macho(size);
        let macho = MachOFile::parse(macho_data).unwrap();

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(label), &macho, |b, macho| {
            b.iter(|| {
                sign_macho(
                    macho,
                    "com.bench.test",
                    None,
                    &credentials,
                    None,
                    None,
                )
                .unwrap()
            });
        });
    }

    group.finish();
}

fn bench_parse_macho(c: &mut Criterion) {
    let sizes: &[(usize, &str)] = &[
        (64 * 1024, "64KB"),
        (1024 * 1024, "1MB"),
        (10 * 1024 * 1024, "10MB"),
    ];

    let mut group = c.benchmark_group("parse_macho");

    for &(size, label) in sizes {
        let macho_data = build_synthetic_macho(size);

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(label), &macho_data, |b, data| {
            b.iter_batched(
                || data.clone(),
                |cloned| MachOFile::parse(cloned).unwrap(),
                criterion::BatchSize::LargeInput,
            );
        });
    }

    group.finish();
}

criterion_group!(benches, bench_sign_macho, bench_parse_macho);
criterion_main!(benches);
