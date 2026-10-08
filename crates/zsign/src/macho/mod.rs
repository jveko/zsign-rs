//! Mach-O binary parsing, signing, and writing.
//!
//! This module provides functionality for working with Apple Mach-O binaries:
//!
//! - [`parser`] - Parse single-architecture and FAT/Universal Mach-O binaries
//! - Signing via `zsign_core` (sign_macho, sign_macho_all_slices)
//! - Writing via `zsign_core` (embed_signature, embed_signature_fat)
//!
//! # Overview
//!
//! The typical workflow for signing a Mach-O binary:
//!
//! 1. Parse the binary with [`MachOFile::open`] or [`MachOFile::parse`]
//! 2. Sign with [`sign_macho`] (single-arch) or [`sign_macho_all_slices`] (FAT)
//! 3. Write using [`write_signed_macho`] or embed with [`embed_signature_fat`]
//!
//! # Examples
//!
//! ```no_run
//! use zsign_rs::macho::{MachOFile, sign_macho};
//!
//! let macho = MachOFile::open("path/to/binary")?;
//! println!("Is FAT binary: {}", macho.is_fat());
//! println!("Number of slices: {}", macho.slices().len());
//! # Ok::<(), zsign_rs::Error>(())
//! ```

use std::io::Write;

pub mod parser;

pub use parser::{ArchSlice, MachOFile};
pub use zsign_core::macho::writer::{
    align_to, calculate_signature_space, embed_signature, embed_signature_fat,
    prepare_code_for_signing, prepare_code_for_signing_slice, SignedSlice,
};

/// Write signed Mach-O to file (native-only).
pub fn write_signed_macho(
    input_path: impl AsRef<std::path::Path>,
    output_path: impl AsRef<std::path::Path>,
    signature: &[u8],
) -> crate::Result<()> {
    let data = std::fs::read(input_path.as_ref())?;
    let output = embed_signature(&data, signature)?;
    std::fs::write(output_path.as_ref(), output)?;
    Ok(())
}

/// Write signed Mach-O in place (native-only).
///
/// The signed image is written to a temp file in the same directory, synced,
/// given the original file's permissions, then renamed over the path. A failure
/// before the rename leaves the original untouched; readers see old-or-new.
pub fn write_signed_macho_in_place(
    binary_path: impl AsRef<std::path::Path>,
    signature: &[u8],
) -> crate::Result<()> {
    let data = std::fs::read(binary_path.as_ref())?;
    let output = embed_signature(&data, signature)?;
    let target = std::fs::canonicalize(binary_path.as_ref())?;
    let perms = std::fs::metadata(&target)?.permissions();
    let parent = target.parent().ok_or_else(|| {
        std::io::Error::other(format!("{} has no parent directory", target.display()))
    })?;
    let mut temp = tempfile::NamedTempFile::new_in(parent)?;
    temp.as_file_mut().write_all(&output)?;
    temp.as_file().sync_all()?;
    std::fs::set_permissions(temp.path(), perms)?;
    temp.persist(&target).map_err(|pe| pe.error)?;
    let _ = std::fs::File::open(parent).and_then(|dir| dir.sync_all());
    Ok(())
}

/// Signs a single-architecture Mach-O binary.
///
/// Builds a complete code signature and embeds it into the binary.
/// For FAT binaries, use [`sign_macho_all_slices`] instead.
pub fn sign_macho(
    macho: &MachOFile,
    identifier: &str,
    entitlements: Option<&[u8]>,
    credentials: &zsign_core::crypto::SigningCredentials,
    info_plist: Option<&[u8]>,
    code_resources: Option<&[u8]>,
    allow_encrypted: bool,
) -> crate::Result<Vec<u8>> {
    Ok(zsign_core::macho::sign_macho(
        macho.as_core(),
        identifier,
        entitlements,
        credentials,
        info_plist,
        code_resources,
        allow_encrypted,
    )?)
}

/// Signs all architecture slices of a Mach-O binary.
///
/// Returns a [`SignedSlice`] for each architecture, suitable for reassembly
/// into a FAT binary using [`embed_signature_fat`].
pub fn sign_macho_all_slices(
    macho: &MachOFile,
    identifier: &str,
    entitlements: Option<&[u8]>,
    credentials: &zsign_core::crypto::SigningCredentials,
    info_plist: Option<&[u8]>,
    code_resources: Option<&[u8]>,
    allow_encrypted: bool,
) -> crate::Result<Vec<SignedSlice>> {
    Ok(zsign_core::macho::sign_macho_all_slices(
        macho.as_core(),
        identifier,
        entitlements,
        credentials,
        info_plist,
        code_resources,
        allow_encrypted,
    )?)
}

/// Signs a Mach-O with no identity (ad-hoc).
///
/// Every slice of a FAT/Universal binary is signed ad-hoc and the container
/// is reassembled; a thin binary is signed in place.
pub fn sign_macho_adhoc(
    macho: &MachOFile,
    identifier: &str,
    entitlements: Option<&[u8]>,
    info_plist: Option<&[u8]>,
    code_resources: Option<&[u8]>,
    allow_encrypted: bool,
) -> crate::Result<Vec<u8>> {
    Ok(zsign_core::macho::sign_macho_adhoc(
        macho.as_core(),
        identifier,
        entitlements,
        info_plist,
        code_resources,
        allow_encrypted,
    )?)
}

/// Signs a single-architecture Mach-O emitting only the SHA-256 code
/// directory (no SHA-1 code directory slot).
pub fn sign_macho_sha256_only(
    macho: &MachOFile,
    identifier: &str,
    entitlements: Option<&[u8]>,
    credentials: &zsign_core::crypto::SigningCredentials,
    info_plist: Option<&[u8]>,
    code_resources: Option<&[u8]>,
    allow_encrypted: bool,
) -> crate::Result<Vec<u8>> {
    Ok(zsign_core::macho::sign_macho_sha256_only(
        macho.as_core(),
        identifier,
        entitlements,
        credentials,
        info_plist,
        code_resources,
        allow_encrypted,
    )?)
}

/// Signs any Mach-O binary (single-arch or FAT), returns signed bytes.
///
/// * Entitlements are ignored for non-executables: no entitlements slot is
///   emitted (an absent slot is the codesign baseline).
pub fn sign_any_macho(
    macho: &MachOFile,
    identifier: &str,
    entitlements: Option<&[u8]>,
    credentials: &zsign_core::crypto::SigningCredentials,
    info_plist: Option<&[u8]>,
    code_resources: Option<&[u8]>,
    allow_encrypted: bool,
) -> crate::Result<Vec<u8>> {
    Ok(zsign_core::macho::sign_any_macho(
        macho.as_core(),
        identifier,
        entitlements,
        credentials,
        info_plist,
        code_resources,
        allow_encrypted,
    )?)
}
#[cfg(test)]
mod tests {
    use std::fs;
    use std::process::Command;

    use zsign_core::macho::fixtures;

    use super::{sign_macho_adhoc, write_signed_macho, write_signed_macho_in_place, MachOFile};

    /// A real signature payload: sign a thin fixture ad-hoc and extract its
    /// LC_CODE_SIGNATURE blob. Mirrors `signature_bytes` in zsign-core's
    /// writer tests (crates/zsign-core/src/macho/writer.rs:2524-2535).
    fn signature_bytes() -> Vec<u8> {
        let macho = MachOFile::parse(fixtures::make_minimal_macho()).expect("fixture parses");
        let signed = sign_macho_adhoc(&macho, "com.zsign.blobsrc", None, None, None, false)
            .expect("adhoc sign of minimal fixture");
        let m = MachOFile::parse(signed.clone()).expect("signed parses");
        let sl = &m.slices()[0];
        let sig = sl.code_sig_offset.expect("signature present") as usize;
        let len = sl.code_sig_size.expect("signature size present") as usize;
        signed[sig..sig + len].to_vec()
    }

    #[test]
    #[cfg(unix)]
    fn mid_write_failure_leaves_original_intact() {
        const CHILD_TARGET_ENV: &str = "ZSIGN_IN_PLACE_WRITE_TARGET";
        const MARKER: &str = "in-place-write-attempted";

        if let Ok(target) = std::env::var(CHILD_TARGET_ENV) {
            println!("{MARKER}");
            let res = write_signed_macho_in_place(target, &signature_bytes());
            assert!(
                res.is_err(),
                "write must fail under a file-size limit, got {res:?}"
            );
            return;
        }

        let td = tempfile::tempdir().expect("tempdir");
        let target = td.path().join("app.bin");
        let original = fixtures::make_minimal_macho();
        assert_eq!(original.len(), 0x2000);
        fs::write(&target, &original).expect("write fixture");

        let exe = std::env::current_exe().unwrap();
        let out = Command::new("sh")
            .arg("-c")
            .arg(r#"ulimit -f 1; exec "$0" "$@""#)
            .arg(&exe)
            .arg("mid_write_failure_leaves_original_intact") // substring filter, runs only this test
            .arg("--nocapture") // marker must reach stdout
            .env(CHILD_TARGET_ENV, &target)
            .output()
            .unwrap();

        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.contains(MARKER),
            "child never reached the write; stdout={stdout:?} stderr={:?}",
            String::from_utf8_lossy(&out.stderr)
        );
        let after = fs::read(&target).expect("read target after child");
        assert_eq!(
            after, original,
            "mid-write failure must leave the original bytes intact"
        );
    }

    #[test]
    #[cfg(unix)]
    fn in_place_write_matches_two_path_output_and_preserves_mode() {
        use std::os::unix::fs::PermissionsExt;

        let td = tempfile::tempdir().expect("tempdir");
        let input = td.path().join("in.bin");
        let out = td.path().join("out.bin");
        let path_b = td.path().join("b.bin");
        let fixture = fixtures::make_minimal_macho();
        fs::write(&input, &fixture).expect("write input");
        fs::write(&path_b, &fixture).expect("write b");

        let sig = signature_bytes();
        write_signed_macho(&input, &out, &sig).expect("two-path write");
        fs::set_permissions(&path_b, fs::Permissions::from_mode(0o755)).expect("chmod");
        write_signed_macho_in_place(&path_b, &sig).expect("in-place write");

        assert_eq!(
            fs::read(&path_b).expect("read b"),
            fs::read(&out).expect("read out"),
            "in-place output must be byte-identical to the two-path write"
        );
        let mode = fs::metadata(&path_b)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o755, "in-place write must preserve mode");
    }

    #[test]
    #[cfg(unix)]
    fn in_place_write_through_symlink_replaces_target_not_link() {
        use std::os::unix::fs::symlink;

        let td = tempfile::tempdir().expect("tempdir");
        let real = td.path().join("real.bin");
        let link = td.path().join("link.bin");
        let original = fixtures::make_minimal_macho();
        fs::write(&real, &original).expect("write real");
        symlink(&real, &link).expect("symlink");

        let sig = signature_bytes();
        write_signed_macho_in_place(&link, &sig).expect("in-place write via symlink");

        assert!(
            fs::symlink_metadata(&link)
                .expect("link metadata")
                .file_type()
                .is_symlink(),
            "in-place write must not replace the symlink itself"
        );
        let via_link = fs::read(&link).expect("read link");
        assert_ne!(via_link, original, "target must carry the signed image");
        let input2 = td.path().join("in2.bin");
        let out2 = td.path().join("out2.bin");
        fs::write(&input2, &original).expect("write in2");
        write_signed_macho(&input2, &out2, &sig).expect("two-path write");
        assert_eq!(
            via_link,
            fs::read(&out2).expect("read out2"),
            "target must equal the two-path output"
        );
    }
}
