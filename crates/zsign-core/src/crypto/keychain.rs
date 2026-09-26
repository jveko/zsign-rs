//! Load a code signing identity straight from the macOS keychain.
//!
//! # Flow
//!
//! 1. [`parse_find_identity`] lists the codesigning identities
//!    (`security find-identity -v -p codesigning`), pairing each certificate's
//!    SHA-1 with the identity's name.
//! 2. [`select_identity_line`] resolves the user-supplied name or 40-hex
//!    certificate hash to exactly one identity, with actionable errors for an
//!    empty, ambiguous or unknown keychain.
//! 3. The identities are exported to a PKCS#12 file
//!    (`security export -t identities -f pkcs12`) and loaded through
//!    `SigningCredentials::from_p12_with_leaf_sha1`, so a
//!    keychain identity passes exactly the same load-time checks as any other
//!    PKCS#12 source: key strength, code-signing policy, chain assembly and
//!    team ID extraction.
//!
//! # Targets
//!
//! The parser and the selector are pure and compile on every native target.
//! The live `/usr/bin/security` execution is `cfg(target_os = "macos")`; on any
//! other platform [`load`] returns [`KeychainError::MacOsOnly`] and points at
//! the portable credential flags. The module is excluded from `wasm32` builds.

/// Everything that can go wrong while resolving or exporting a keychain
/// identity.
#[derive(Debug, thiserror::Error)]
pub enum KeychainError {
    /// The current platform has no `/usr/bin/security` keychain.
    #[error("--keychain-identity is only available on macOS; use --pkcs12, -k/--private-key, or -c/--certificate on this platform")]
    MacOsOnly,
    /// The keychain holds no valid codesigning identity.
    #[error("no valid codesigning identities found in the keychain (security find-identity -v -p codesigning returned none)")]
    NoIdentities,
    /// The requested name matched several identities.
    #[error("keychain identity '{requested}' matched {count} identities: {candidates}; pass the 40-hex hash instead")]
    Ambiguous {
        /// The name the user asked for.
        requested: String,
        /// How many identities carry that exact name.
        count: usize,
        /// `HASH "name"` for each match, separated by `"; "`.
        candidates: String,
    },
    /// No identity matched the requested name or hash.
    #[error("keychain identity '{requested}' not found; available identities: {available}")]
    NotFound {
        /// The name or hash the user asked for.
        requested: String,
        /// Every available identity name, separated by `"; "`.
        available: String,
    },
    /// `/usr/bin/security` could not be run, or exited non-zero.
    #[error("`security {tool}` failed with status {status}: {stderr}")]
    CommandFailed {
        /// The `security` subcommand that failed.
        tool: &'static str,
        /// Exit status, or the spawn error's display form.
        status: String,
        /// Captured standard error, empty when the process could not be spawned.
        stderr: String,
    },
    /// The temporary PKCS#12 export could not be read or written.
    #[error("keychain export file error: {0}")]
    ExportFile(String),
    /// Resolving, exporting or loading the identity failed; the inner error
    /// is reported verbatim.
    #[error(transparent)]
    Credential(#[from] crate::Error),
}

/// One line of `security find-identity` output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityLine {
    /// SHA-1 of the identity's certificate, as printed by `security`.
    pub hash: [u8; 20],
    /// The identity's display name, without surrounding quotes or trailing
    /// markers such as ` [REVOKED]`.
    pub name: String,
}

/// Parses `security find-identity -v -p codesigning` output into identities.
///
/// Lines look like `  1) 50034388646913B117AF1D6E51D9E045B77EA916 "Apple
/// Development: alice@example.com (LVGBSLUQB4)"`. The SHA-1 follows the
/// closing parenthesis of the one-based index. Every other line — the
/// `N valid identities found` summary included — and every line that does not
/// fit the shape is skipped, so a policy message can never become an
/// identity and parsing never panics.
pub fn parse_find_identity(stdout: &str) -> Vec<IdentityLine> {
    let mut out = Vec::new();
    for line in stdout.lines() {
        let Some((prefix, rest)) = line.split_once(')') else {
            continue;
        };
        let prefix = prefix.trim();
        if prefix.is_empty() || !prefix.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let rest = rest.trim_start();
        if rest.len() < 41 {
            continue;
        }
        let Some(hash) = decode_hex20(&rest.as_bytes()[..40]) else {
            continue;
        };
        let tail = rest[40..].trim_start();
        if !tail.starts_with('"') {
            continue;
        }
        // The name is everything between the first and the last quote, so
        // quotes inside the name survive and trailing markers fall off.
        let Some(last) = tail.rfind('"') else {
            continue;
        };
        if last == 0 {
            continue;
        }
        out.push(IdentityLine {
            hash,
            name: tail[1..last].to_string(),
        });
    }
    out
}

/// Resolves `name_or_hash` against the identities `security` listed.
///
/// A 40-character ASCII-hex input is treated as a certificate SHA-1 and
/// matched case-insensitively; anything else is matched as an exact identity
/// name. An empty listing is [`KeychainError::NoIdentities`], a name shared by
/// several identities is [`KeychainError::Ambiguous`] (with the hashes to use
/// instead), and anything unmatched is [`KeychainError::NotFound`] listing the
/// available names.
pub fn select_identity_line(
    lines: &[IdentityLine],
    name_or_hash: &str,
) -> Result<IdentityLine, KeychainError> {
    if lines.is_empty() {
        return Err(KeychainError::NoIdentities);
    }
    let available = || {
        lines
            .iter()
            .map(|l| l.name.clone())
            .collect::<Vec<_>>()
            .join("; ")
    };

    if name_or_hash.len() == 40 && name_or_hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        let wanted = decode_hex20(name_or_hash.as_bytes())
            .expect("40 ASCII hex digits decode; checked above");
        return match lines.iter().find(|l| l.hash == wanted) {
            Some(found) => Ok(found.clone()),
            None => Err(KeychainError::NotFound {
                requested: name_or_hash.to_string(),
                available: available(),
            }),
        };
    }

    let matched: Vec<&IdentityLine> = lines.iter().filter(|l| l.name == name_or_hash).collect();
    match matched.as_slice() {
        [] => Err(KeychainError::NotFound {
            requested: name_or_hash.to_string(),
            available: available(),
        }),
        [only] => Ok((*only).clone()),
        many => Err(KeychainError::Ambiguous {
            requested: name_or_hash.to_string(),
            count: many.len(),
            candidates: many
                .iter()
                .map(|l| format!("{} \"{}\"", hex_upper(&l.hash), l.name))
                .collect::<Vec<_>>()
                .join("; "),
        }),
    }
}

/// The `/usr/bin/security` operations this module needs.
///
/// A trait so the selection, export and load pipeline can be exercised without
/// a keychain; the live implementation is `cfg(target_os = "macos")`.
pub trait SecurityRunner {
    /// Runs `security find-identity -v -p codesigning` and returns its stdout.
    fn find_identity(&self) -> Result<String, KeychainError>;
    /// Runs `security export -t identities -f pkcs12` writing to `out`.
    fn export_identities(&self, out: &std::path::Path) -> Result<(), KeychainError>;
}

/// Resolves `name_or_hash`, exports the keychain identities and loads the
/// selected one, removing the temporary export whether or not loading
/// succeeded.
pub fn load_with(
    name_or_hash: &str,
    runner: &dyn SecurityRunner,
) -> Result<crate::crypto::SigningCredentials, KeychainError> {
    let stdout = runner.find_identity()?;
    let lines = parse_find_identity(&stdout);
    let selected = select_identity_line(&lines, name_or_hash)?;

    let path = std::env::temp_dir().join(format!(
        "zsign-identity-{}-{}.p12",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    let result = (|| {
        runner.export_identities(&path)?;
        let data = std::fs::read(&path)
            .map_err(|e| KeychainError::ExportFile(format!("{}: {e}", path.display())))?;
        crate::crypto::cert::SigningCredentials::from_p12_with_leaf_sha1(&data, "", &selected.hash)
            .map_err(KeychainError::Credential)
    })();
    let _ = std::fs::remove_file(&path);
    result
}

/// Runs the real `/usr/bin/security` keychain.
#[cfg(target_os = "macos")]
struct LiveSecurity;

#[cfg(target_os = "macos")]
impl SecurityRunner for LiveSecurity {
    fn find_identity(&self) -> Result<String, KeychainError> {
        let out = std::process::Command::new("/usr/bin/security")
            .args(["find-identity", "-v", "-p", "codesigning"])
            .output()
            .map_err(|e| KeychainError::CommandFailed {
                tool: "find-identity",
                status: e.to_string(),
                stderr: String::new(),
            })?;
        if !out.status.success() {
            return Err(KeychainError::CommandFailed {
                tool: "find-identity",
                status: out.status.to_string(),
                stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
            });
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    fn export_identities(&self, out: &std::path::Path) -> Result<(), KeychainError> {
        let res = std::process::Command::new("/usr/bin/security")
            .args(["export", "-t", "identities", "-f", "pkcs12", "-P", "", "-o"])
            .arg(out)
            .output()
            .map_err(|e| KeychainError::CommandFailed {
                tool: "export",
                status: e.to_string(),
                stderr: String::new(),
            })?;
        if !res.status.success() {
            return Err(KeychainError::CommandFailed {
                tool: "export",
                status: res.status.to_string(),
                stderr: String::from_utf8_lossy(&res.stderr).into_owned(),
            });
        }
        Ok(())
    }
}

/// Loads the keychain codesigning identity `name_or_hash` (exact display name
/// or 40-hex certificate SHA-1) as [`crate::crypto::SigningCredentials`].
#[cfg(target_os = "macos")]
pub fn load(name_or_hash: &str) -> Result<crate::crypto::SigningCredentials, KeychainError> {
    load_with(name_or_hash, &LiveSecurity)
}

/// Stands in for the keychain on a platform that has none, so the selection
/// and export pipeline has the same shape everywhere and fails at the first
/// `security` call with an actionable message instead of a bare "unsupported".
#[cfg(not(target_os = "macos"))]
struct UnavailableSecurity;

#[cfg(not(target_os = "macos"))]
impl SecurityRunner for UnavailableSecurity {
    fn find_identity(&self) -> Result<String, KeychainError> {
        Err(KeychainError::MacOsOnly)
    }

    fn export_identities(&self, _out: &std::path::Path) -> Result<(), KeychainError> {
        Err(KeychainError::MacOsOnly)
    }
}

/// Keychain identities are a macOS facility; on every other platform this
/// always fails with [`KeychainError::MacOsOnly`], which points the caller at
/// `--pkcs12`, `-k/--private-key` and `-c/--certificate`.
#[cfg(not(target_os = "macos"))]
pub fn load(name_or_hash: &str) -> Result<crate::crypto::SigningCredentials, KeychainError> {
    load_with(name_or_hash, &UnavailableSecurity)
}

/// Decodes exactly 20 bytes of hex, or `None` for any other input.
fn decode_hex20(bytes: &[u8]) -> Option<[u8; 20]> {
    if bytes.len() != 40 {
        return None;
    }
    let mut out = [0u8; 20];
    for (i, slot) in out.iter_mut().enumerate() {
        let hi = (bytes[i * 2] as char).to_digit(16)?;
        let lo = (bytes[i * 2 + 1] as char).to_digit(16)?;
        *slot = ((hi << 4) | lo) as u8;
    }
    Some(out)
}

/// Formats a SHA-1 digest as uppercase hex, as `security` prints it.
fn hex_upper(bytes: &[u8; 20]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const TWO: &str = include_str!("fixtures/find-identity-two.txt");
    const ZERO: &str = include_str!("fixtures/find-identity-zero.txt");
    const AMBIGUOUS: &str = include_str!("fixtures/find-identity-ambiguous.txt");
    const RAGGED: &str = include_str!("fixtures/find-identity-ragged.txt");

    /// A hand-built stand-in for a `security export -t identities -f pkcs12
    /// -P ""` container: the two self-issued codesigning certificates and the
    /// single key from the `identity_duplicate_certs.p12` fixture, re-encrypted
    /// under the empty password such an export produces, so the keychain
    /// pipeline can be driven without a keychain.
    const DUAL_EXPORT: &[u8] =
        include_bytes!("fixtures/keychain_identities_dual_empty_password.p12");

    /// Lowercase hex of a digest, for byte-level assertions.
    fn hex_lower(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Uppercase hex of a digest, as `security` prints it.
    fn hex_upper(bytes: &[u8; 20]) -> String {
        bytes.iter().map(|b| format!("{b:02X}")).collect()
    }

    /// SHA-1 of a DER blob, the value `security find-identity` prints.
    fn sha1_of(der: &[u8]) -> [u8; 20] {
        use sha1::{Digest, Sha1};
        Sha1::digest(der).into()
    }

    #[test]
    fn parse_find_identity_extracts_hash_and_name() {
        let lines = parse_find_identity(TWO);
        assert_eq!(lines.len(), 2, "summary line must not parse: {lines:?}");
        assert_eq!(
            hex_lower(&lines[0].hash),
            "50034388646913b117af1d6e51d9e045b77ea916"
        );
        assert_eq!(
            lines[0].name,
            "Apple Development: alice@example.com (LVGBSLUQB4)"
        );
        assert_eq!(
            hex_lower(&lines[1].hash),
            "0123456789abcdef0123456789abcdef01234567"
        );
        assert_eq!(
            lines[1].name,
            "iPhone Distribution: Example Corp (ABCDE12345)"
        );
    }

    #[test]
    fn parse_find_identity_handles_summary_noise_and_trailing_markers() {
        assert!(
            parse_find_identity(ZERO).is_empty(),
            "a zero-identity summary is not an identity"
        );
        let lines = parse_find_identity(RAGGED);
        assert_eq!(lines.len(), 1, "noise lines must be skipped: {lines:?}");
        assert_eq!(
            lines[0].name,
            "Apple Development: carol@example.com (TEAM999999)"
        );
    }

    #[test]
    fn select_identity_line_matches_hash_case_insensitively_and_name_exactly() {
        let lines = parse_find_identity(TWO);
        let by_hash = select_identity_line(&lines, "0123456789abcdef0123456789abcdef01234567")
            .expect("hash matches case-insensitively");
        assert_eq!(
            by_hash.name,
            "iPhone Distribution: Example Corp (ABCDE12345)"
        );
        let by_name =
            select_identity_line(&lines, "Apple Development: alice@example.com (LVGBSLUQB4)")
                .expect("exact name matches");
        assert_eq!(by_name.hash[0], 0x50);
        assert!(
            select_identity_line(&lines, "Apple Development: alice").is_err(),
            "a name prefix is not an exact match"
        );
    }

    struct FakeSecurity {
        listing: String,
        export: Vec<u8>,
    }

    impl SecurityRunner for FakeSecurity {
        fn find_identity(&self) -> Result<String, KeychainError> {
            Ok(self.listing.clone())
        }

        fn export_identities(&self, out: &std::path::Path) -> Result<(), KeychainError> {
            std::fs::write(out, &self.export)
                .map_err(|e| KeychainError::ExportFile(format!("{}: {e}", out.display())))
        }
    }

    #[test]
    fn select_identity_line_reports_ambiguity_and_not_found() {
        let lines = parse_find_identity(AMBIGUOUS);
        let res = select_identity_line(&lines, "Apple Development: bob@example.com (TEAM000001)");
        assert!(
            matches!(&res, Err(KeychainError::Ambiguous { count, candidates, .. })
                if count == &2
                    && candidates.contains(&hex_upper(&decode_hex20(b"1111111111111111111111111111111111111111").unwrap()))
                    && candidates.contains(&hex_upper(&decode_hex20(b"2222222222222222222222222222222222222222").unwrap()))),
            "ambiguous name must list both hashes, got {:?}",
            res.as_ref().err()
        );

        let res =
            select_identity_line(&lines, "Apple Development: nobody@example.com (TEAM000009)");
        assert!(
            matches!(&res, Err(KeychainError::NotFound { available, .. })
                if available.contains("TEAM000001")),
            "unknown name must list what is available, got {:?}",
            res.as_ref().err()
        );

        let res = select_identity_line(&parse_find_identity(ZERO), "whatever");
        assert!(
            matches!(&res, Err(KeychainError::NoIdentities)),
            "an empty keychain is its own error, got {:?}",
            res.as_ref().err()
        );
    }

    /// Every `zsign-identity-*` file currently in the temp directory.
    fn temp_exports() -> Vec<std::path::PathBuf> {
        let dir = std::env::temp_dir();
        let Ok(entries) = std::fs::read_dir(&dir) else {
            return Vec::new();
        };
        entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with("zsign-identity-"))
            })
            .collect()
    }

    #[test]
    fn load_with_selects_one_identity_from_multi_identity_export() {
        use crate::crypto::pkcs12::extract_p12;

        let contents = extract_p12(DUAL_EXPORT, "").expect("fixture parses");
        assert!(contents.certs.len() >= 2, "fixture holds both identities");
        let hashes: Vec<[u8; 20]> = contents.certs.iter().map(|c| sha1_of(c)).collect();
        let listing = format!(
            "  1) {} \"Apple Development: alpha (TESTTEAM)\"\n  2) {} \"Apple Development: beta (TESTTEAM)\"\n     2 valid identities found\n",
            hex_upper(&hashes[0]),
            hex_upper(&hashes[1]),
        );

        let before = temp_exports();
        let fake = FakeSecurity {
            listing,
            export: DUAL_EXPORT.to_vec(),
        };
        let creds = load_with("Apple Development: beta (TESTTEAM)", &fake)
            .expect("the named identity must load out of a multi-identity export");

        use der::Encode;
        let leaf = creds.certificate.to_der().expect("leaf DER");
        assert_eq!(
            sha1_of(&leaf),
            hashes[1],
            "the selected identity, not the first one, must be the leaf"
        );
        assert_eq!(
            temp_exports(),
            before,
            "the temporary PKCS#12 export must be removed"
        );
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn load_rejects_on_non_macos() {
        let res = super::load("Apple Development: alice@example.com (LVGBSLUQB4)");
        assert!(
            matches!(&res, Err(KeychainError::MacOsOnly)),
            "non-macOS must refuse with MacOsOnly, got {:?}",
            res.as_ref().err()
        );
        let msg = res.err().expect("macOS-only error").to_string();
        assert!(
            msg.contains("macOS"),
            "the message must name the platform, got {msg}"
        );
    }

    /// Exercises the real `/usr/bin/security` against the host keychain, so the
    /// spawn, listing, parsing and full load chain run on macOS CI hosts.
    #[cfg(target_os = "macos")]
    #[test]
    fn live_security_find_identity_round_trip() {
        let listing = super::LiveSecurity
            .find_identity()
            .expect("security find-identity must be present at /usr/bin/security");
        let lines = super::parse_find_identity(&listing);
        if let Some(first) = lines.first() {
            let creds = super::load(&hex_upper(&first.hash))
                .expect("an exportable identity must load through the full check chain");
            assert!(!creds.certificate.tbs_certificate.subject.is_empty());
        }
        // Zero identities is a valid CI state: listing + parsing still ran.
    }
}
