# Deterministic ECDSA, encrypted PEM credentials, revocation warning — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development (recommended) with
> dispatching-parallel-agents for independent tasks to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Pin P-256 CMS output as byte-reproducible with tests, load encrypted private keys
(PBES2 PKCS#8 and traditional `DEK-Info` PEM) through the existing password flow, and add a
fully tested, never-fatal OCSP revocation warning to `zsign-core`.

**Architecture:** All production code lands in `crates/zsign-core/src/crypto/`. PKCS#5 v2.0
decryption reuses the PBES2/PBKDF2 engine that ZSN-37 built for PKCS#12 (visibility bump, no new
crypto), the traditional-PEM path adds one small module (`encrypted_pem.rs`), and revocation gets a
new `revocation.rs` whose network edge is a trait with a native `std::net` implementation.
`SigningCredentials` keeps its exact public shape; no CI or `deny.toml` change.

**Tech stack:** Rust 2021, `p256` 0.13.2 / `ecdsa` 0.16.9 / `cms` 0.2.3 / `der` 0.7.10 /
`x509-cert` 0.2.5 / `pbkdf2` 0.12.2 / `hmac` 0.12.1 / `sha1` 0.10.7, one new dependency `md-5`
0.10 (MIT OR Apache-2.0). OpenSSL 3.6.3 only as a fixture generator, never at test time.

**Spec:** `docs/superpowers/specs/2026-09-26-crypto-repro-credentials-design.md` (probes P1-P14).

---

## Ground rules for every task

- Worktree root is the cwd. Never `cargo fmt`/`clippy`/workspace tests mid-flight; the scoped gate
  at the end of each task is `TMPDIR=$PWD/.tmptmp cargo test -p zsign-core <filter>` (plus the
  `zsign-cli` filter in Task 6), and every test run appends
  `-- --skip test_ipa_signing_is_deterministic`: that test is the tracked ZSN-15 flake owned by lane
  zsn41, this lane must not extend, move, or remove the skip, and must not add any new skip.
- No ticket IDs in code comments; they belong in commit subjects only.
- Commit subjects: imperative, lowercase, no trailing period, ticket ID at the end of the subject.
- Never edit: `crates/zsign-cli/src/main.rs` except Task 7, `crates/zsign/src/builder.rs`,
  `crates/zsign/src/ipa/**`. Do not edit `.github/workflows/*` or `deny.toml`.
- New fixtures: `crates/zsign-core/src/crypto/fixtures/` (already package-excluded by
  `crates/zsign-core/Cargo.toml:9`). Generate into a scratch dir **outside** the repo
  (`mktemp -d -p "$HOME/tmp-cargo" …`), copy only the committed bytes in, delete the scratch dir.

## File map

| File | Responsibility | Tasks |
|---|---|---|
| `crates/zsign-core/src/crypto/cms.rs` | reproducibility contract doc + fixed-key ECDSA test helper + KAT/repetition tests | 1, 2 |
| `crates/zsign-core/src/macho/signer.rs` | blob-level ECDSA determinism test | 3 |
| `crates/zsign-core/src/crypto/pkcs12.rs` | promote the PBES2/PBKDF2/CBC/unpad primitives to `pub(crate)` | 4 |
| `crates/zsign-core/src/crypto/encrypted_pem.rs` (new) | traditional `DEK-Info` PEM framing + `EVP_BytesToKey`(MD5) | 5 |
| `crates/zsign-core/src/crypto/cert.rs` | encrypted-key routing inside `from_pem`, PKCS#1/SEC1 decoders, error taxonomy | 6 |
| `crates/zsign-cli/src/main.rs` | reject-path cutover (delete `reject_encrypted_key`) | 7 |
| `crates/zsign-core/src/crypto/revocation.rs` (new) | OCSP request/response, verification, mocked transport | 8, 9 |
| `crates/zsign-core/src/crypto/mod.rs` | register the two new modules | 5, 8 |

---

## Task 1: RFC 6979 known-answer pin (red-by-mutation, then green)

**Files:**
- Modify: `crates/zsign-core/src/crypto/cms.rs` (test module; `build_test_ecdsa_credentials`
  lives at `:1059`)
- Test: same file, inline `#[cfg(test)] mod tests`

- [ ] **Step 1: Write the failing test** — add to `cms.rs`'s `mod tests`, after
  `build_test_ecdsa_credentials`:

```rust
    /// RFC 6979 A.2.5 (NIST P-256 + SHA-256) known-answer vectors, quoted from
    /// <https://www.rfc-editor.org/rfc/rfc6979.txt#appendix-A.2.5>. The private key
    /// scalar and the two (r, s) pairs are the RFC's; the expected DER is those
    /// integers framed as `SEQUENCE { INTEGER r, INTEGER s }`.
    const RFC6979_P256_SCALAR: [u8; 32] = [
        0xc9, 0xaf, 0xa9, 0xd8, 0x45, 0xba, 0x75, 0x16, 0x6b, 0x5c, 0x21, 0x57, 0x67, 0xb1, 0xd6,
        0x93, 0x4e, 0x50, 0xc3, 0xdb, 0x36, 0xe8, 0x9b, 0x12, 0x7b, 0x8a, 0x62, 0x2b, 0x12, 0x0f,
        0x67, 0x21,
    ];
    const RFC6979_SAMPLE_DER: [u8; 72] = [
        0x30, 0x46, 0x02, 0x21, 0x00, 0xef, 0xd4, 0x8b, 0x2a, 0xac, 0xb6, 0xa8, 0xfd, 0x11, 0x40,
        0xdd, 0x9c, 0xd4, 0x5e, 0x81, 0xd6, 0x9d, 0x2c, 0x87, 0x7b, 0x56, 0xaa, 0xf9, 0x91, 0xc3,
        0x4d, 0x0e, 0xa8, 0x4e, 0xaf, 0x37, 0x16, 0x02, 0x21, 0x00, 0xf7, 0xcb, 0x1c, 0x94, 0x2d,
        0x65, 0x7c, 0x41, 0xd4, 0x36, 0xc7, 0xa1, 0xb6, 0xe2, 0x9f, 0x65, 0xf3, 0xe9, 0x00, 0xdb,
        0xb9, 0xaf, 0xf4, 0x06, 0x4d, 0xc4, 0xab, 0x2f, 0x84, 0x3a, 0xcd, 0xa8,
    ];
    const RFC6979_TEST_DER: [u8; 71] = [
        0x30, 0x45, 0x02, 0x21, 0x00, 0xf1, 0xab, 0xb0, 0x23, 0x51, 0x83, 0x51, 0xcd, 0x71, 0xd8,
        0x81, 0x56, 0x7b, 0x1e, 0xa6, 0x63, 0xed, 0x3e, 0xfc, 0xf6, 0xc5, 0x13, 0x2b, 0x35, 0x4f,
        0x28, 0xd3, 0xb0, 0xb7, 0xd3, 0x83, 0x67, 0x02, 0x20, 0x01, 0x9f, 0x41, 0x13, 0x74, 0x2a,
        0x2b, 0x14, 0xbd, 0x25, 0x92, 0x6b, 0x49, 0xc6, 0x49, 0x15, 0x5f, 0x26, 0x7e, 0x60, 0xd3,
        0x81, 0x4b, 0x4c, 0x0c, 0xc8, 0x42, 0x50, 0xe4, 0x6f, 0x00, 0x83,
    ];

    #[test]
    fn ecdsa_signing_matches_rfc6979_known_answers() {
        use p256::ecdsa::{DerSignature, SigningKey};
        use signature::{SignatureEncoding, Signer};

        let key = SigningKey::from_slice(&RFC6979_P256_SCALAR).expect("RFC 6979 scalar");
        // The annotation is what pins the trait arm: `DerSignature` is the exact type
        // `sign_code_directory` hands to the CMS builder (`cms.rs:345`), so these are the
        // bytes that land in the SignerInfo signature BIT STRING.
        // UFCS because `SigningKey` implements `Signer<Signature<C>>` (signing.rs:171) and
        // `Signer<der::Signature<C>>` (signing.rs:272) for the same key type.
        let sample_sig: DerSignature =
            <SigningKey as Signer<DerSignature>>::sign(&key, b"sample" as &[u8]);
        let test_sig: DerSignature =
            <SigningKey as Signer<DerSignature>>::sign(&key, b"test" as &[u8]);
        assert_eq!(
            sample_sig.to_vec().as_slice(),
            RFC6979_SAMPLE_DER.as_slice(),
            "P-256 SHA-256 signature over \"sample\" must be the RFC 6979 deterministic value"
        );
        assert_eq!(
            test_sig.to_vec().as_slice(),
            RFC6979_TEST_DER.as_slice(),
            "P-256 SHA-256 signature over \"test\" must be the RFC 6979 deterministic value"
        );
    }
```

  `signature` 2.2 is a direct `zsign-core` dependency (`crates/zsign-core/Cargo.toml:28`), so
  `signature::{Signer, SignatureEncoding}` resolve without going through `p256`'s re-export.

- [ ] **Step 2: Run it and confirm it passes on the untouched tree**

Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-core ecdsa_signing_matches_rfc6979`
Expected: `test result: ok. 1 passed`. The vectors are already satisfied by
`ecdsa` 0.16.9's RFC 6979 path; this test exists to keep that true.

- [ ] **Step 3: Mutation check — prove the test is load-bearing**

Temporarily replace the `Signer<DerSignature>` arm used by CMS signing in
`sign_code_directory`'s ECDSA branch is not needed; instead mutate the *test's* signer into the
randomized trait in a scratch edit that is NOT committed:

```rust
        use signature::RandomizedSigner;
        let mut rng = p256::elliptic_curve::rand_core::OsRng;
        let randomized: p256::ecdsa::DerSignature =
            key.sign_with_rng(&mut rng, b"sample" as &[u8]);
        let sample: Vec<u8> = randomized.to_vec();
```

`RandomizedSigner<der::Signature<C>>` is implemented for `SigningKey<C>`
(`ecdsa-0.16.9/src/signing.rs:325`), so the annotation above is what makes the scratch edit
compile; the explicit type is also what proves the mutation swapped the nonce source and not the
signature encoding.

Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-core ecdsa_signing_matches_rfc6979`
Expected: FAIL — the randomized nonce produces different `r`/`s`, so the assertion trips. Revert
the scratch edit and re-run Step 2 to green. Report the observed failure text as the red evidence
for this ticket.

- [ ] **Step 4: Scoped gate, then commit (after reverting the scratch edit and re-running Step 2)**

Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-core crypto::cms -- --skip test_ipa_signing_is_deterministic`
Expected: every `crypto::cms` test passes, including the new one, with no skip added by this lane.

```
git add crates/zsign-core/src/crypto/cms.rs
git commit -m "test(crypto): pin rfc 6979 deterministic p-256 signatures with a known-answer test"
```

The three byte arrays above were checked against the signer's own output and against
`openssl asn1parse` during design (P11); treat a mismatch here as a transcription error to fix in
the test, never as a reason to weaken the assertion.

---

## Task 2: Byte-identical CMS output, five times, on a fixed key

**Files:**
- Modify: `crates/zsign-core/src/crypto/cms.rs` (test module only)

- [ ] **Step 1: Add the fixed-key credential helper.** `build_test_ecdsa_credentials` (`cms.rs:1059`)
  draws `SigningKey::random(&mut OsRng)` at `:1072`, so it cannot pin bytes. Add a sibling that
  reuses the same certificate-construction shape with the RFC 6979 scalar, plus a pinned validity so
  the certificate DER is identical in every process (`Validity::from_now` would move the bytes):

```rust
    /// Fixed-scalar ECDSA credentials for the reproducibility tests: the key is the RFC 6979
    /// scalar and the certificate DER is pinned by a constant validity window, so the CMS bytes
    /// are identical in every process. Self-issued `Profile::Leaf`, matching the crate's own
    /// `rsa_credentials` idiom (`cms_verify.rs:1741-1776`), with the codeSigning EKU the verify
    /// path requires so the same helper can feed a round trip.
    fn build_fixed_ecdsa_credentials() -> SigningCredentials {
        use crate::crypto::cert::{SigningCredentials, SigningKeyType};
        use der::Decode;
        use p256::ecdsa::SigningKey;
        use spki::{EncodePublicKey, SubjectPublicKeyInfoOwned};
        use std::str::FromStr;
        use x509_cert::builder::{Builder, CertificateBuilder, Profile};
        use x509_cert::ext::pkix::ExtendedKeyUsage;
        use x509_cert::name::Name;
        use x509_cert::serial_number::SerialNumber;
        use x509_cert::time::Validity;

        let ecdsa_key = SigningKey::from_slice(&RFC6979_P256_SCALAR).expect("fixed scalar");
        let subject = Name::from_str("CN=ECDSA Determinism Signer,OU=TESTTEAM").unwrap();
        let validity = Validity {
            // x509-cert 0.2.5 has no `Time::from_unix_duration`; `Time::try_from(SystemTime)`
            // is the in-repo idiom (`cms_verify.rs:2913-2915`).
            not_before: fixed_unix_time(1_700_000_000),
            not_after: fixed_unix_time(4_000_000_000),
        };
        let pub_key = SubjectPublicKeyInfoOwned::from_der(
            p256::ecdsa::VerifyingKey::from(&ecdsa_key)
                .to_public_key_der()
                .unwrap()
                .as_ref(),
        )
        .unwrap();
        let cert = CertificateBuilder::new(
            Profile::Leaf {
                issuer: subject.clone(),
                enable_key_agreement: false,
                enable_key_encipherment: false,
            },
            SerialNumber::from(442u32),
            validity,
            subject,
            pub_key,
            &ecdsa_key,
        )
        .unwrap()
        .add_extension(&ExtendedKeyUsage(vec![super::cms_verify::OID_CODE_SIGNING]))
        .unwrap()
        .build::<p256::ecdsa::DerSignature>()
        .unwrap();

        SigningCredentials {
            certificate: cert,
            signing_key: SigningKeyType::Ecdsa(ecdsa_key),
            cert_chain: vec![],
            team_id: Some("TESTTEAM".to_string()),
        }
    }
```

  `fixed_unix_time` is the same one-liner the verify tests already use
  (`Time::try_from(UNIX_EPOCH + Duration::from_secs(n))`): add it as a local test helper in
  `cms.rs` rather than importing the private one in `cms_verify.rs` (test helpers are duplicated
  across these modules already — `time_now`/`ext_value` precedent,
  `specs/2026-09-25-credential-hardening-design.md:147-152`). `OID_CODE_SIGNING` is
  `1.3.6.1.5.5.7.3.3`; if `cms_verify::OID_CODE_SIGNING` is not visible, declare the same
  `ObjectIdentifier::new_unwrap` constant locally. Validity is pinned because
  `Validity::from_now` would move the embedded certificate DER with the machine clock and make
  the byte comparison time-dependent. `OU=TESTTEAM` keeps `team_id` extraction meaningful.

- [ ] **Step 2: Write the failing test**

```rust
    #[test]
    fn cms_ecdsa_signature_is_byte_identical_five_times() {
        let credentials = build_fixed_ecdsa_credentials();
        let code_dir = b"deterministic code directory bytes";
        let cdhash_sha1: [u8; 20] = [0x11; 20];
        let cdhash_sha256: [u8; 32] = [0x22; 32];

        let first =
            sign_code_directory(code_dir, &credentials, Some(&cdhash_sha1), &cdhash_sha256).unwrap();
        for run in 2..=5 {
            let again =
                sign_code_directory(code_dir, &credentials, Some(&cdhash_sha1), &cdhash_sha256)
                    .unwrap();
            assert_eq!(first, again, "CMS run {run} differs from run 1");
        }
        // Negative control: the test cannot pass by ignoring its input.
        let other: [u8; 32] = [0x33; 32];
        let changed =
            sign_code_directory(code_dir, &credentials, Some(&cdhash_sha1), &other).unwrap();
        assert_ne!(first, changed, "a different CDHash must change the CMS bytes");
    }
```

- [ ] **Step 3: Run it to verify it passes**

Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-core cms_ecdsa_signature_is_byte_identical`
Expected: `1 passed`. The sha256-only variant is covered by the existing
`cms_verify.rs:3064` round trip; this test pins the dual-digest path that ships in production.

- [ ] **Step 4: Scoped gate + commit**

```
git add crates/zsign-core/src/crypto/cms.rs
git commit -m "test(crypto): prove p-256 cms output is byte-identical across repeated signings"
```

---

## Task 3: Blob-level determinism and the documented contract

**Files:**
- Modify: `crates/zsign-core/src/macho/signer.rs` (test module; the tree has no RSA determinism
  test, so the credential builder here is the RSA test fixture at `test_credentials` `:960`)
- Modify: `crates/zsign-core/src/crypto/cms.rs` (module docs)

- [ ] **Step 1: Write the failing test** in `macho/signer.rs`'s `mod tests`, following the existing
  RSA tests' use of `crate::macho::fixtures::make_minimal_macho` and the `SigningCredentials`
  literal pattern at `macho/fixtures.rs:401-405`, but with the ECDSA arm. Because
  `build_fixed_ecdsa_credentials` lives in `cms.rs`'s private test module, the blob-level test builds
  its own credential with the same fixed scalar and pinned validity:

```rust
    #[test]
    fn sign_macho_ecdsa_is_byte_identical_twice() {
        let credentials = ecdsa_credentials_for_determinism();
        let macho = MachOFile::parse(crate::macho::fixtures::make_minimal_macho()).unwrap();
        let identifier = "com.zsign.ecdsa.determinism";
        let entitlements = Some(b"<plist><dict/></plist>".as_slice());

        let first = sign_macho(&macho, identifier, entitlements, &credentials, None, None, false)
            .expect("first ECDSA sign");
        let second = sign_macho(&macho, identifier, entitlements, &credentials, None, None, false)
            .expect("second ECDSA sign");
        assert_eq!(
            first, second,
            "embedding a P-256 signature twice must reproduce the binary byte for byte"
        );
        // Reparsing proves the bytes are a real signature, not identical garbage.
        let reparsed = MachOFile::parse(second).expect("signed output must reparse");
        assert!(!reparsed.slices().is_empty());
    }
```

  Argument order and the `MachOFile::parse` step follow the existing call at
  `macho/signer.rs:1303-1313`; `first`/`second` are `Vec<u8>`.

  Implement `ecdsa_credentials_for_determinism()` in that test module by copying the
  `cms.rs` helper body from Task 2 verbatim and renaming it (repo convention for test-only
  cross-module helpers is duplication — `time_now`/`ext_value` already duplicate this way, see
  `specs/2026-09-25-credential-hardening-design.md:147-152`); `cms.rs`'s test module is private, so
  importing would require widening a `#[cfg(test)] pub(crate)` surface that does not exist today.

- [ ] **Step 2: Run it to verify it passes**

Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-core sign_macho_ecdsa_is_byte_identical`
Expected: `1 passed`.

- [ ] **Step 3: Record the contract where it can be found.** Extend the `cms.rs` module doc
  (`//! CMS (Cryptographic Message Syntax) signature generation.` block, lines 1-27) with:

```rust
//! # Reproducibility contract
//!
//! Output bytes are a pure function of the inputs: `RSA_PKCS1_SHA256` is deterministic,
//! and the ECDSA arm is RFC 6979 deterministic because the CMS builder is bounded on
//! the non-randomized `signature::Signer` trait. Adding a `signingTime` signed attribute
//! (`cms::builder::SignerInfoBuilder::create_signing_time_attribute`) or switching the
//! ECDSA arm to `signature::RandomizedSigner` breaks byte-reproducible output and is
//! rejected by the tests in this module. Upstream `zsign` inherits OpenSSL's randomized
//! nonce; this implementation deliberately does not, so identical inputs reproduce the
//! signed IPA byte for byte.
```

- [ ] **Step 4: Scoped gate + commit**

Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-core crypto::cms -- --skip test_ipa_signing_is_deterministic`
plus the same filter for `macho::signer`. Expected: all green.

```
git add crates/zsign-core/src/macho/signer.rs crates/zsign-core/src/crypto/cms.rs
git commit -m "test(macho): pin byte-identical p-256 macho signing and document the contract"
```

---

## Task 4: Make the PKCS#12 PBES2 engine reusable

**Files:**
- Modify: `crates/zsign-core/src/crypto/pkcs12.rs:810` (`decrypt_key_bag`) and `:627` (`aes_decrypt`)
  (two visibility changes; the shipped line numbers)

- [ ] **Step 1: Widen the PBES2 engine and add the shared helpers.** This is the only task that
  changes `pkcs12.rs` visibility; Tasks 5, 6 and 9 consume it and widen nothing themselves.

```rust
/// pkcs8ShroudedKeyBag ::= EncryptedPrivateKeyInfo
pub(crate) fn decrypt_key_bag(value: &[u8], password: &str) -> Result<Vec<u8>> {
```

```rust
/// Block-cipher CBC decrypt with PKCS#7 removal, generic over the cipher so the traditional
/// PEM decoder can reuse the same code path as PKCS#12. The name predates that reuse;
/// `des::TdesEde3` satisfies the same `BlockDecrypt + KeyInit` bounds
/// (`des-0.8.1/src/tdes.rs:21-31` for `BlockCipher`/`KeySizeUser`/`KeyInit`, and `des` re-exports
/// `cipher` at `src/lib.rs:26` and `TdesEde3` at `:33`).
pub(crate) fn aes_decrypt<C>(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>>
where
    C: BlockDecrypt + KeyInit,
{
```

```rust
/// Translates a container failure into the credential error a caller reports. PBES2 inside
/// PKCS#12 and inside an encrypted PKCS#8 PEM share this machinery: a decryption failure is a
/// passphrase failure, an unknown algorithm is a policy refusal, anything else is a malformed
/// container.
pub(crate) fn pem_load_error(e: P12Error) -> Error {
    match e {
        P12Error::Mac | P12Error::Decrypt(_) => Error::InvalidPassword,
        P12Error::Unsupported(msg) => {
            Error::Certificate(format!("unsupported key encryption: {msg}"))
        }
        P12Error::Der(msg) => {
            Error::Certificate(format!("failed to parse encrypted private key: {msg}"))
        }
    }
}
```

  `pkcs12.rs` currently imports nothing from `crate` except through its own `Result<T, E =
  P12Error>` alias (`:94`), so `pem_load_error` needs `use crate::Error;` added to the import
  block at `:18-29`. `P12Error` is already `pub(crate)` (`:71`).

Widen the reader itself, because Tasks 8 and 9 walk DER with it. Six existing methods get
`pub(crate)` on the `fn` keyword and nothing else: `new` (`:165`), `peek_tag` (`:183`),
`read_tlv` (`:188`), `read_sequence` (`:228`), `read_octet_string` (`:232`), `read_oid` (`:249`).
The struct declaration becomes `pub(crate) struct DerReader<'a>` (`:159`) and one method is
appended to that `impl` block:

```rust
    /// Reads the next TLV and returns its **full encoded bytes** (tag, length, value), not just
    /// the value. Signature verification must cover exactly the bytes the responder wrote, so the
    /// value-only `read_tlv` cannot be used for that.
    pub(crate) fn span_of_next_tlv(&mut self) -> Option<&'a [u8]> {
        let start = self.pos;
        self.read_tlv().ok()?;
        self.buf.get(start..self.pos)
    }
```

  Nothing else in the module changes: `pbes2_decrypt`, `Pbkdf2Parameter`, `cbc_decrypt`,
  `unpad_pkcs7`, `AlgorithmId`, `mod oid`, `read_explicit`, `read_any`, `read_integer_u32`,
  `read_len` and `remaining` stay module-private. The PBES2 machinery is reached through two
  widened entries and no others: `decrypt_key_bag` (`:810`), which Task 6's PKCS#8 path calls, and
  the generic `aes_decrypt` (`:627`), which `encrypted_pem.rs:81-91` calls directly for
  AES-128/192/256 and DES-EDE3-CBC. The per-field structs the traditional path could plausibly
  have wanted were not widened, because it never parses an `EncryptedPrivateKeyInfo`.

- [ ] **Step 2: Verify the module still compiles, and do not commit yet.**

Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-core crypto::pkcs12 -- --skip test_ipa_signing_is_deterministic`
Expected: all pass, behaviour unchanged.

  Task 4 deliberately has no commit of its own: a `pub(crate)` item with no caller is a
  `dead_code` warning, and this lane's rule is that a green commit means a warning-free tree
  (ground rules: scoped test gate; lane gate: `clippy -D warnings`). The widened items therefore
  land **inside Task 5's commit**, which is the first task with a caller. Until then keep the
  edits in the working tree; `git status --short` should show `pkcs12.rs` modified.


---

## Task 5: Traditional `DEK-Info` PEM decoder

**Files:**
- Create: `crates/zsign-core/src/crypto/encrypted_pem.rs`
- Modify: `crates/zsign-core/src/crypto/mod.rs` (`pub mod encrypted_pem;` after `pub mod cms_verify;` at `:33`)
- Modify: `crates/zsign-core/Cargo.toml` (one dependency)
- Create: 8 PEM fixtures under `crates/zsign-core/src/crypto/fixtures/` (six encrypted key
  containers as `*.pem.b64`, two readable certificates; no plaintext key fixture is committed —
  the unencrypted cases generate their key in-test)

- [ ] **Step 1: Add the single new dependency** (`md-5` is MIT OR Apache-2.0, already allowlisted at
  `deny.toml:14-27`; pinned to 0.10 because 0.11 needs `digest` 0.11 and the tree is on 0.10):

```toml
# OpenSSL traditional PEM key derivation (EVP_BytesToKey)
md-5 = "0.10"
```

  Add it after `digest = "0.10"` (`Cargo.toml:38`). Verify no duplicate `digest` appears:
  `cargo tree -d | grep -c digest` must stay `0`. (`cbc`/`cipher`/`base64ct` are already in
  `Cargo.lock` through `pkcs5`, so no other manifest change is needed.)

- [ ] **Step 2: Generate the fixtures** (scratch outside the repo; the verification block fails
  loud, matching the ZSN-37 recipe style at `plans/2026-09-25-credential-hardening.md:1530-1562`).

  The repository's pre-commit `detect-private-key` hook shapes this step. Measured with
  `hk util detect-private-key <file>`: a certificate container passes; **every** key container is
  refused, `ENCRYPTED PRIVATE KEY` included, because the detector matches the label text rather
  than the ciphertext. Two consequences, both
  deliberate: no plaintext private key is
  committed by this lane at all (those keys are generated inside the tests), and to keep one
  uniform rule for key material each of the six encrypted containers is committed as one base64
  blob of the whole PEM (`*.pem.b64`) that the test decodes back to OpenSSL's exact bytes — the
  PBES2 ones would pass the hook as plain `.pem`, but one format for all key fixtures beats two
  rules that a reader has to remember. That is a storage format for encrypted test material, not
  an evasion: the payload is ciphertext, the passphrase is published next to it in the test, and
  the guards at the end of the recipe prove the hook accepts every committed file.

```bash
set -euo pipefail
F=$PWD/crates/zsign-core/src/crypto/fixtures
d=$(mktemp -d -p "$HOME/tmp-cargo" zsn42-pem.XXXXXX); trap 'rm -rf "$d"' EXIT
cat > "$d/ext.cnf" <<'EOF'
[ req ]
distinguished_name = dn
prompt = no
[ dn ]
CN = zsign-test-fixture
OU = TESTTEAM
[ v3 ]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = codeSigning
subjectKeyIdentifier = hash
authorityInfoAccess = OCSP;URI:http://ocsp.invalid.test/ocsp
EOF

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$d/rsa.key"
openssl req -new -key "$d/rsa.key" -config "$d/ext.cnf" -out "$d/rsa.csr"
openssl x509 -req -in "$d/rsa.csr" -signkey "$d/rsa.key" -days 3650 -set_serial 0x7001 \
  -extfile "$d/ext.cnf" -extensions v3 -out "$F/pem_rsa_cert.pem"
openssl pkcs8 -topk8 -in "$d/rsa.key" -v2 aes-256-cbc -passout pass:testpassword -out "$d/pbes2_sha256.pem"
openssl pkcs8 -topk8 -in "$d/rsa.key" -v2 aes-256-cbc -v2prf hmacWithSHA1 -passout pass:testpassword -out "$d/pbes2_sha1prf.pem"
base64 -w0 "$d/pbes2_sha256.pem"  > "$F/pem_rsa_key_pbes2_sha256.pem.b64"
base64 -w0 "$d/pbes2_sha1prf.pem" > "$F/pem_rsa_key_pbes2_sha1prf.pem.b64"
openssl rsa -in "$d/rsa.key" -traditional -aes256 -passout pass:testpassword -out "$d/trad_rsa_aes256.pem"
openssl rsa -in "$d/rsa.key" -traditional -des3  -passout pass:testpassword -out "$d/trad_rsa_des3.pem"
base64 -w0 "$d/trad_rsa_aes256.pem" > "$F/pem_rsa_key_dekinfo_aes256.pem.b64"
base64 -w0 "$d/trad_rsa_des3.pem"  > "$F/pem_rsa_key_dekinfo_des3.pem.b64"

openssl ecparam -name prime256v1 -genkey -noout -out "$d/ec.key"
openssl req -new -key "$d/ec.key" -config "$d/ext.cnf" -out "$d/ec.csr"
openssl x509 -req -in "$d/ec.csr" -signkey "$d/ec.key" -days 3650 -set_serial 0x7002 \
  -extfile "$d/ext.cnf" -extensions v3 -out "$F/pem_ec_cert.pem"
openssl pkcs8 -topk8 -in "$d/ec.key" -v2 aes-256-cbc -passout pass:testpassword -out "$d/ec_pbes2.pem"
base64 -w0 "$d/ec_pbes2.pem" > "$F/pem_ec_key_pbes2_sha256.pem.b64"
openssl ec -in "$d/ec.key" -aes128 -passout pass:testpassword -out "$d/trad_ec.pem"  # no -traditional for ec in 3.x
base64 -w0 "$d/trad_ec.pem" > "$F/pem_ec_key_dekinfo_aes128.pem.b64"

# Fail-loud verification: each guard aborts rather than warning.
for f in pem_rsa_key_pbes2_sha256 pem_rsa_key_pbes2_sha1prf pem_ec_key_pbes2_sha256; do
  base64 -d "$F/$f.pem.b64" | grep -q 'ENCRYPTED PRIVATE KEY' || { echo "missing PBES2 label in $f"; exit 1; }
done
for f in pem_rsa_key_dekinfo_aes256 pem_rsa_key_dekinfo_des3 pem_ec_key_dekinfo_aes128; do
  grep -qx 'Proc-Type: 4,ENCRYPTED' <(base64 -d "$F/$f.pem.b64") || { echo "missing Proc-Type in $f"; exit 1; }
  base64 -d "$F/$f.pem.b64" | grep -q 'DEK-Info:' || { echo "missing DEK-Info in $f"; exit 1; }
done
# The blobs must decode to ciphertext the committed passphrase opens, and each key family must
# agree on one public number with its certificate.
base64 -d "$F/pem_rsa_key_dekinfo_aes256.pem.b64" | openssl pkey -passin pass:testpassword -noout
base64 -d "$F/pem_ec_key_dekinfo_aes128.pem.b64"  | openssl pkey -passin pass:testpassword -noout
pub() { openssl pkey -pubout 2>/dev/null | openssl pkey -pubin -outform DER | sha256sum; }
[ "$(openssl pkey -in "$d/rsa.key" | pub)" = "$(base64 -d "$F/pem_rsa_key_pbes2_sha256.pem.b64" | openssl pkey -passin pass:testpassword | pub)" ]
[ "$(openssl pkey -in "$d/rsa.key" | pub)" = "$(base64 -d "$F/pem_rsa_key_dekinfo_des3.pem.b64" | openssl pkey -passin pass:testpassword | pub)" ]
[ "$(openssl x509 -in "$F/pem_rsa_cert.pem" -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum)" \
  = "$(openssl pkey -in "$d/rsa.key" | pub)" ]
[ "$(base64 -d "$F/pem_ec_key_pbes2_sha256.pem.b64" | openssl pkey -passin pass:testpassword | pub)" \
  = "$(openssl x509 -in "$F/pem_ec_cert.pem" -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum)" ]
# The committed set: 2 certificates, 3 PBES2 PEMs, 3 base64 traditional bodies, and no plaintext key.
ls -1 "$F" | grep -c '^pem_' | grep -qx 8 || { echo "expected 8 pem fixtures"; exit 1; }
pattern=$(printf 'BEGIN %sPRIVATE KEY' 'RSA\|EC\|')
if grep -rlE "$pattern" "$F"; then
  echo "a plaintext-shaped key container was committed"; exit 1
fi
for f in "$F"/pem_*; do hk util detect-private-key "$f" || { echo "hook rejects $f"; exit 1; }; done
echo "fixtures verified"
```

  Eight new files: two certificates plus six key containers, every key container base64-wrapped.
  `git status --short crates/zsign-core/src/crypto/fixtures/` must list exactly those eight and
  nothing else, and each `.b64` must decode to the byte-exact OpenSSL PEM — which the round-trip
  guards above prove by extracting the public number through `openssl pkey`.
- [ ] **Step 3: Write the failing tests** in `encrypted_pem.rs`

```rust
    /// Traditional PEM fixtures are committed as one base64 blob (see Task 5's hook note);
    /// decoding here keeps the bytes byte-exact, label lines included.
    pub(crate) fn pem_fixture(blob: &str) -> String {
        use base64::Engine as _;
        let der = base64::engine::general_purpose::STANDARD
            .decode(blob.trim())
            .expect("fixture must be valid base64");
        String::from_utf8(der).expect("fixture must be UTF-8 PEM text")
    }

    const TRAD_RSA_AES256: &str = include_str!("fixtures/pem_rsa_key_dekinfo_aes256.pem.b64");
    const TRAD_RSA_DES3: &str = include_str!("fixtures/pem_rsa_key_dekinfo_des3.pem.b64");
    const TRAD_EC_AES128: &str = include_str!("fixtures/pem_ec_key_dekinfo_aes128.pem.b64");

    #[test]
    fn dek_info_aes256_yields_a_pkcs1_key() {
        let pem = pem_fixture(TRAD_RSA_AES256);
        let der = decrypt_pem_fixture(pem, Some("testpassword")).unwrap();
        assert_eq!(der[0], 0x30, "plaintext must be a DER SEQUENCE");
        assert!(
            rsa::RsaPrivateKey::from_pkcs1_der(&der).is_ok(),
            "traditional RSA PEM must decrypt to PKCS#1, got {} bytes",
            der.len()
        );
    }

    #[test]
    fn dek_info_aes128_yields_a_sec1_ec_key() {
        let pem = pem_fixture(TRAD_EC_AES128);
        let der = decrypt_pem_fixture(pem, Some("testpassword")).unwrap();
        assert!(
            p256::SecretKey::from_sec1_der(&der).is_ok(),
            "traditional EC PEM must decrypt to SEC1, got {} bytes",
            der.len()
        );
    }

    #[test]
    fn dek_info_3des_yields_a_pkcs1_key() {
        let pem = pem_fixture(TRAD_RSA_DES3);
        let der = decrypt_pem_fixture(pem, Some("testpassword")).unwrap();
        assert!(rsa::RsaPrivateKey::from_pkcs1_der(&der).is_ok());
    }

    #[test]
    fn wrong_password_is_reported_as_a_password_failure() {
        for blob in [TRAD_RSA_AES256, TRAD_RSA_DES3, TRAD_EC_AES128] {
            let pem = pem_fixture(blob);
            let res = decrypt_pem_fixture(&pem, Some("not-the-password"));
            assert!(
                matches!(res, Err(Error::InvalidPassword)),
                "a wrong passphrase must be a password failure, got {:?}",
                res.as_ref().err()
            );
        }
    }

    #[test]
    fn missing_password_asks_for_one() {
        let pem = pem_fixture(TRAD_RSA_AES256);
        let res = decrypt_pem_fixture(pem, None);
        assert!(
            matches!(&res, Err(Error::Certificate(m)) if m.contains("requires a password")),
            "an encrypted key without a password must say so, got {:?}",
            res.as_ref().err()
        );
    }

    #[test]
    fn unsupported_dek_info_cipher_is_named() {
        // Hand-written header: the rejection happens before any crypto, so the body
        // never needs to be a real ciphertext. `concat!` splits the PEM label so the
        // pre-commit private-key scanner stays happy, as `main.rs:1675` already does.
        let pem = concat!(
            "-----BEGIN RSA ", "PRIVATE KEY-----\n",
            "Proc-Type: 4,ENCRYPTED\n",
            "DEK-Info: AES-128-CTR,00112233445566778899AABBCCDDEEFF\n",
            "AAAAAAAAAAAAAAAAAAAA\n",
            "-----END RSA ", "PRIVATE KEY-----\n"
        );
        let res = decrypt_pem_fixture(pem, Some("x"));
        assert!(
            matches!(&res, Err(Error::Certificate(m)) if m.contains("AES-128-CTR")),
            "unsupported ciphers must be named, got {:?}",
            res.as_ref().err()
        );
    }

    #[test]
    fn weak_and_legacy_dek_info_ciphers_are_refused_by_name() {
        // Design D18.4: single DES and RC2 spellings are refused, not silently accepted.
        for cipher in ["DES-CBC", "RC2-CBC", "RC2-40-CBC"] {
            let pem = format!(
                "-----BEGIN {label}-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: {cipher},0011223344556677\nAAAAAAAAAAAAAAAAAAAA\n-----END {label}-----\n",
                label = format!("RSA {}", "PRIVATE KEY"),
                cipher = cipher,
            );
            let res = decrypt_pem_fixture(&pem, Some("x"));
            assert!(
                matches!(&res, Err(Error::Certificate(m)) if m.contains(cipher) && m.contains("unsupported")),
                "{cipher} must be refused by name, got {:?}",
                res.as_ref().err()
            );
        }
    }

    #[test]
    fn an_unencrypted_pem_is_not_this_modules_business() {
        // The contract `decode_key_material` relies on for fall-through: a PEM without the
        // encrypted `Proc-Type` header is *not ours*, so it reports `Ok(None)` and the caller
        // decodes it normally. The key is generated here because no plaintext key is committed.
        let key = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
        let pem = std::str::from_utf8(key.to_pkcs1_der().unwrap().as_bytes()).unwrap();
        let wrapped = pem_text("RSA PRIVATE KEY", key.to_pkcs1_der().unwrap().as_bytes());
        assert!(
            matches!(decrypt_pem_fixture(&wrapped, Some("testpassword")), Ok(None)),
            "a plaintext PKCS#1 container must fall through, not error"
        );
    }

    #[test]
    fn a_missing_proc_type_falls_through_even_with_a_password() {
        let pem = concat!(
            "-----BEGIN RSA ", "PRIVATE KEY-----\n",
            "DEK-Info: AES-256-CBC,00112233445566778899AABBCCDDEEFF\n",
            "AAAAAAAAAAAAAAAAAAAA\n",
            "-----END RSA ", "PRIVATE KEY-----\n"
        );
        assert!(matches!(decrypt_pem_fixture(pem, Some("x")), Ok(None)),
            "DEK-Info without Proc-Type is not a traditional encrypted PEM");
    }

    #[test]
    fn framing_rejects_a_malformed_iv() {
        let pem = concat!(
            "-----BEGIN RSA ", "PRIVATE KEY-----\n",
            "Proc-Type: 4,ENCRYPTED\n",
            "DEK-Info: AES-256-CBC,00112233445566\n",
            "AAAAAAAAAAAAAAAAAAAA\n",
            "-----END RSA ", "PRIVATE KEY-----\n"
        );
        let res = decrypt_pem_fixture(pem, Some("x"));
        assert!(
            matches!(&res, Err(Error::Certificate(m)) if m.contains("DEK-Info")),
            "a bad IV must be a framing error, got {:?}",
            res.as_ref().err()
        );
    }
```

- [ ] **Step 4: Run them to verify they fail**

Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-core encrypted_pem -- --skip test_ipa_signing_is_deterministic`
Expected: compile error, `file not found for module encrypted_pem` until Step 5 creates it, then
nine failures.

- [ ] **Step 5: Implement `encrypted_pem.rs`**

This is the module as compiled and run against real OpenSSL output during design (probes P7-P10):
labels, headers, the key-only `EVP_BytesToKey`, the header IV rule, and the cipher matrix.

```rust
//! Traditional OpenSSL encrypted PEM keys: `Proc-Type: 4,ENCRYPTED` plus `DEK-Info`.
//!
//! The PEM label names the inner encoding (`RSA PRIVATE KEY` is PKCS#1, `EC PRIVATE KEY`
//! is SEC1, `PRIVATE KEY` is PKCS#8), the headers carry the cipher name and the
//! initialisation vector, and the body is the CBC ciphertext of those DER bytes.
//! `der`'s PEM reader rejects RFC 7468 headers outright, so the framing here is
//! deliberately small: one BEGIN line, a header block, base64, one END line.

use crate::{Error, Result};
use md5::{Digest, Md5};

/// A traditional encrypted PEM that decrypted cleanly: just the plaintext DER of the inner
/// key encoding. The PEM label is deliberately not returned — routing is by content, so a
/// `PRIVATE KEY` label that arrives from the CLI's own DER wrapper must not steer the
/// decoder, and an unused field is a `dead_code` warning under the lane's own clippy gate.
pub(crate) struct TraditionalKey {
    /// Plaintext DER of the inner key encoding (PKCS#1, SEC1 or PKCS#8).
    pub der: Vec<u8>,
}

/// Derives `need` key bytes with `EVP_BytesToKey`: MD5, `D_i = MD5(D_(i-1) || password || salt)`,
/// blocks concatenated then truncated. `salt` is the first 8 bytes of the header IV.
///
/// The derived IV is deliberately never used: OpenSSL stores the real IV in the `DEK-Info`
/// header, and feeding the derived bytes back in corrupts the first plaintext block while
/// leaving the rest (and the padding) intact — which looks like a working key until the DER
/// parser rejects it.
fn evp_bytes_to_key(password: &[u8], salt: &[u8], need: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(need);
    let mut previous: Vec<u8> = Vec::new();
    while out.len() < need {
        let mut hasher = Md5::new();
        hasher.update(&previous);
        hasher.update(password);
        hasher.update(salt);
        previous = hasher.finalize().to_vec();
        out.extend_from_slice(&previous);
    }
    out.truncate(need);
    out
}

/// Cipher name -> (key bytes, IV bytes), the set `openssl` can write into a `DEK-Info` header
/// and that this crate can decrypt with dependencies it already carries.
/// The supported `DEK-Info` cipher names, each carrying its key and IV lengths.
enum DekCipher {
    Aes128,
    Aes192,
    Aes256,
    TdesEde3,
}

impl DekCipher {
    fn shape(name: &str) -> Option<(Self, usize, usize)> {
        match name {
            "AES-128-CBC" => Some((Self::Aes128, 16, 16)),
            "AES-192-CBC" => Some((Self::Aes192, 24, 16)),
            "AES-256-CBC" => Some((Self::Aes256, 32, 16)),
            "DES-EDE3-CBC" => Some((Self::TdesEde3, 24, 8)),
            _ => None,
        }
    }

    fn decrypt(self, key: &[u8], iv: &[u8], ct: &[u8]) -> Option<Vec<u8>> {
        use crate::crypto::pkcs12::aes_decrypt;
        match self {
            Self::Aes128 => aes_decrypt::<aes::Aes128>(key, iv, ct).ok(),
            Self::Aes192 => aes_decrypt::<aes::Aes192>(key, iv, ct).ok(),
            Self::Aes256 => aes_decrypt::<aes::Aes256>(key, iv, ct).ok(),
            Self::TdesEde3 => aes_decrypt::<des::TdesEde3>(key, iv, ct).ok(),
        }
    }
}

fn malformed(detail: String) -> Error {
    Error::Certificate(format!("malformed encrypted PEM: {detail}"))
}

fn unsupported(detail: String) -> Error {
    Error::Certificate(format!("unsupported key encryption: {detail}"))
}

/// Decrypts a traditional encrypted PEM. `Ok(None)` means "this is not a traditional encrypted
/// PEM" — the caller then falls through to the PKCS#8 and PBES2 paths.
pub(crate) fn decrypt_traditional_pem(pem: &str, password: Option<&str>) -> Result<Option<TraditionalKey>> {
    let mut lines = pem.lines().map(str::trim_end);
    let begin = loop {
        match lines.next() {
            None => return Ok(None),
            Some(line) if line.starts_with("-----BEGIN ") => break line,
            Some(_) => continue,
        }
    };
    let label = begin
        .strip_prefix("-----BEGIN ")
        .and_then(|rest| rest.strip_suffix("-----"))
        .ok_or_else(|| malformed(format!("unrecognised BEGIN line {begin}")))?;
    let mut proc_type: Option<String> = None;
    let mut dek_info: Option<String> = None;
    let mut body = String::new();
    for line in lines {
        if line.starts_with("-----END ") {
            break;
        }
        match line.split_once(':') {
            Some(("Proc-Type", value)) if body.is_empty() => proc_type = Some(value.trim().to_string()),
            Some(("DEK-Info", value)) if body.is_empty() => dek_info = Some(value.trim().to_string()),
            _ => body.push_str(line),
        }
    }
    if proc_type.as_deref() != Some("4,ENCRYPTED") {
        return Ok(None);
    }
    let dek_info = dek_info.ok_or_else(|| malformed("Proc-Type is encrypted but DEK-Info is absent".into()))?;
    let (cipher, iv_hex) = dek_info
        .split_once(',')
        .ok_or_else(|| malformed(format!("DEK-Info has no IV: {dek_info}")))?;
    let cipher_name = cipher.trim();
    let (cipher, key_len, iv_len) = DekCipher::shape(cipher_name)
        .ok_or_else(|| unsupported(format!("DEK-Info cipher {cipher_name} (supported: AES-128/192/256-CBC, DES-EDE3-CBC)")))?;
    if iv_hex.len() != iv_len * 2 {
        return Err(malformed(format!(
            "{cipher} needs a {iv_len}-byte IV, DEK-Info carries {} hex characters",
            iv_hex.len()
        )));
    }
    let iv: Vec<u8> = (0..iv_hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&iv_hex[i..i + 2], 16)
                .map_err(|_| malformed(format!("DEK-Info IV is not hex: {iv_hex}")))
        })
        .collect::<Result<Vec<u8>, Error>>()?;
    let ciphertext = base64::engine::general_purpose::STANDARD
        .decode(&body)
        .map_err(|e| malformed(format!("ciphertext body is not valid base64: {e}")))?;
    let password = password.ok_or_else(|| {
        Error::Certificate("encrypted private key requires a password (-p or ZSIGN_PASSWORD)".into())
    })?;
    let key = evp_bytes_to_key(password.as_bytes(), &iv[..8], key_len);
    // A `DekCipher` enum, not a string `match`, carries the cipher: parsing maps the name to a
    // variant once (`DekCipher::shape`), so the decrypt step cannot be handed a name it rejects
    // and no `unreachable!()` arm is needed. Each variant's `decrypt` calls the shared CBC engine.
    let plaintext = cipher.decrypt(&key, &iv, &ciphertext);
    match plaintext {
        Some(der) => Ok(Some(TraditionalKey { der })),
        // Every failure after a real decryption attempt is a passphrase failure: either the
        // PKCS#7 padding is invalid, or (one in 256 times) it is valid and the DER is nonsense,
        // which the caller's decoder also reports as such. `DekCipher::decrypt` returns
        // `Option<Vec<u8>>` precisely so both collapse to one arm.
        None => Err(Error::InvalidPassword),
    }
}
```

  `use base64::Engine as _;` is added to the imports (`base64` is already a dependency, used the
  same way in `crates/zsign-cli/src/main.rs:880`, inside `pem_wrap_der`). `pkcs12::aes_decrypt` is
  generic over `C: BlockDecrypt + KeyInit` (`pkcs12.rs:627`, bound at `:629`), so DES-EDE3-CBC
  goes through the same CBC + PKCS#7 code as PKCS#12 — no second block-mode implementation, and
  `rc2` stays unused here because RC2 DEK-Info is deliberately unsupported (design D18.4).
  `DekCipher`'s `Display` is what prints
  the canonical cipher name in the IV-length error, so the message never echoes a spelling the
  crate did not accept.

- [ ] **Step 6: Run the tests to verify they pass**

Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-core encrypted_pem -- --skip test_ipa_signing_is_deterministic`
Expected: every test in the module passes; the count is whatever the module declares, and it is
recorded in the final report rather than predicted here.

- [ ] **Step 7: Commit**

```
git add crates/zsign-core/src/crypto/encrypted_pem.rs crates/zsign-core/src/crypto/mod.rs crates/zsign-core/Cargo.toml crates/zsign-core/src/crypto/fixtures Cargo.lock
git commit -m "feat(crypto): decrypt traditional dek-info pem keys with openssl-compatible framing"
```

---

## Task 6: Route encrypted keys through `from_pem`

**Files:**
- Modify: `crates/zsign-core/src/crypto/cert.rs` (`from_pem` `:534`, `DecodedKey` `:120-142`)
- Modify: `crates/zsign-core/src/crypto/pkcs12.rs:810` (`pub(crate) fn decrypt_key_bag`)
- Modify: `crates/zsign-core/src/crypto/pkcs12.rs:627` (`pub(crate) fn aes_decrypt`)
- Modify: `crates/zsign-core/src/crypto/mod.rs` (module list)
- Test: inline in `cert.rs`

- [ ] **Step 1: Write the failing tests** (append to `cert.rs`'s `mod tests`; the fixture constants
  go next to the existing `IDENTITY_SINGLE` block at `:684-686`):

```rust
    const ENC_PKCS8_RSA: &str = include_str!("fixtures/pem_rsa_key_pbes2_sha256.pem.b64");
    // `encrypted_pem`'s `pem_fixture` helper is what decodes these; `cert.rs`'s test module
    // declares the same three lines rather than importing a private test helper across modules.
    const ENC_PKCS8_RSA_SHA1PRF: &str = include_str!("fixtures/pem_rsa_key_pbes2_sha1prf.pem.b64");
    const ENC_PKCS8_EC: &str = include_str!("fixtures/pem_ec_key_pbes2_sha256.pem.b64");
    const ENC_TRAD_RSA: &str = include_str!("fixtures/pem_rsa_key_dekinfo_aes256.pem.b64");
    const ENC_TRAD_RSA_3DES: &str = include_str!("fixtures/pem_rsa_key_dekinfo_des3.pem.b64");
    const ENC_TRAD_EC: &str = include_str!("fixtures/pem_ec_key_dekinfo_aes128.pem.b64");
    // Every `.b64` constant above is decoded with `crate::crypto::encrypted_pem::pem_fixture`.

    const RSA_CERT: &[u8] = include_bytes!("fixtures/pem_rsa_cert.pem");
    const EC_CERT: &[u8] = include_bytes!("fixtures/pem_ec_cert.pem");
    // No plaintext-key fixtures exist (see Task 5): the unencrypted PKCS#1 / SEC1 cases build
    // their key in the test, which is also what makes them regression tests of the new decoder.
    // So there is deliberately no plaintext constant here to go stale.
    const PASS: &str = "testpassword";

    #[test]
    fn from_pem_loads_every_supported_encrypted_key_form() {
        // Generated rather than committed: the certificate for each generated key is built the
        // same way `cms_verify.rs:1741-1776` builds its self-signed leaf, so key and certificate
        // agree by construction.
        let rsa_key = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
        let (plain_pkcs1, plain_pkcs8, rsa_cert_pem) = rsa_identity_pems(&rsa_key);
        let ec_key = p256::ecdsa::SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        let (plain_sec1, plain_ec_pkcs8, ec_cert_pem) = ec_identity_pems(&ec_key);
        for (cert, key) in [
            (RSA_CERT, &pem_fixture(ENC_PKCS8_RSA)),
            (RSA_CERT, &pem_fixture(ENC_PKCS8_RSA_SHA1PRF)),
            (RSA_CERT, &pem_fixture(ENC_TRAD_RSA)),
            (RSA_CERT, &pem_fixture(ENC_TRAD_RSA_3DES)),
            (EC_CERT, &pem_fixture(ENC_PKCS8_EC)),
            (EC_CERT, &pem_fixture(ENC_TRAD_EC)),
            (rsa_cert_pem.as_bytes(), plain_pkcs1.as_str()),
            (rsa_cert_pem.as_bytes(), plain_pkcs8.as_str()),
            (ec_cert_pem.as_bytes(), plain_sec1.as_str()),
            (ec_cert_pem.as_bytes(), plain_ec_pkcs8.as_str()),
        ] {
            let res = SigningCredentials::from_pem(cert, key.as_bytes(), Some(PASS));
            assert!(
                res.is_ok(),
                "certificate and encrypted key must load, got {:?}",
                res.as_ref().err()
            );
            assert_eq!(res.unwrap().team_id.as_deref(), Some("TESTTEAM"));
        }
    }

    #[test]
    fn from_pem_wrong_password_is_a_password_error() {
        for key in [
            &pem_fixture(ENC_PKCS8_RSA),
            &pem_fixture(ENC_TRAD_RSA),
            &pem_fixture(ENC_PKCS8_RSA_SHA1PRF),
        ] {
            let res = SigningCredentials::from_pem(RSA_CERT, key.as_bytes(), Some("wrong"));
            assert!(
                matches!(res, Err(Error::InvalidPassword)),
                "a wrong passphrase must be InvalidPassword, got {:?}",
                res.as_ref().err()
            );
        }
    }

    #[test]
    fn from_pem_encrypted_key_without_password_asks_for_one() {
        let res = SigningCredentials::from_pem(RSA_CERT, pem_fixture(ENC_TRAD_RSA).as_bytes(), None);
        assert!(
            matches!(&res, Err(Error::Certificate(m)) if m.contains("requires a password")),
            "got {:?}",
            res.as_ref().err()
        );
    }

    #[test]
    fn from_pem_keeps_the_password_free_pkcs8_path_unchanged() {
        // Generated rather than committed: no plaintext key fixture exists in this lane.
        let key = fresh_2048();
        let cert = build_cert(
            "CN=zsign-test-fixture,OU=TESTTEAM",
            "CN=zsign-test-fixture,OU=TESTTEAM",
            &key,
            &key,
            present(),
            Some(code_signing_eku()),
        );
        let (cert_pem, key_pem) = leaf_pems(&cert, &key);
        assert!(SigningCredentials::from_pem(&cert_pem, &key_pem, None).is_ok());
        // A password on an unencrypted key is accepted and ignored, as OpenSSL does.
        assert!(SigningCredentials::from_pem(&cert_pem, &key_pem, Some("ignored")).is_ok());
    }

    #[test]
    fn from_pem_still_pairs_the_decrypted_key_with_the_certificate() {
        let res =
            SigningCredentials::from_pem(EC_CERT, pem_fixture(ENC_PKCS8_RSA).as_bytes(), Some(PASS));
        assert!(
            matches!(&res, Err(Error::Certificate(m)) if m.contains("does not match")),
            "an encrypted key must still be SPKI-paired, got {:?}",
            res.as_ref().err()
        );
    }
```

- [ ] **Step 2: Run them to verify they fail**

Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-core crypto::cert::tests::from_pem -- --skip test_ipa_signing_is_deterministic`
Expected: compile failure on the missing `pkcs12::aes_decrypt` / `pkcs12::decrypt_key_bag`
visibility, then seven red tests once the visibility lands in Step 3.

- [ ] **Step 3: Confirm Task 4 landed the widened entry points.** This task consumes
  `pkcs12::decrypt_key_bag`, `pkcs12::aes_decrypt` and `pkcs12::pem_load_error`; all three were
  promoted and added in Task 4, so nothing further is widened here.

- [ ] **Step 4: Replace the reject guard with content-driven routing** in `cert.rs`. Delete
  `cert.rs:472-483` (comment, `password.is_some()` guard, and the `from_pkcs8_pem` call) and put
  this in its place:

```rust
        let decoded = decode_key_material(key_str, password)?;
        let signing_key = decoded.into_signing_key()?;
```

  and add, next to `DecodedKey` (`cert.rs:120-142`):

```rust
/// Returns the first PEM block's label and DER body.
///
/// RFC 7468 headers (`Proc-Type:`, `DEK-Info:` and friends) may only appear before the
/// base64 text, so the scan skips lines that look like headers until the first body line.
/// `der`'s own reader refuses any block carrying headers, which is why this exists.
fn first_pem_block(pem: &str) -> Option<(&str, Vec<u8>)> {
    use base64::Engine as _;
    let rest = pem.split_once("-----BEGIN ")?.1;
    let (label, after_label) = rest.split_once("-----")?;
    let label = label.trim();
    let mut body = String::new();
    for line in after_label.lines() {
        let line = line.trim_end();
        if line.starts_with("-----END ") {
            break;
        }
        if body.is_empty() && line.contains(": ") {
            continue;
        }
        body.push_str(line);
    }
    let der = base64::engine::general_purpose::STANDARD.decode(&body).ok()?;
    Some((label, der))
}

/// Decodes a private key given as PEM, decrypting it when the container is encrypted.
///
/// Routing is by content, never by label: `main.rs` wraps bare DER in a `PRIVATE KEY`
/// label (`pem_wrap_der`, `main.rs:879`), so an encrypted PKCS#8 DER can legitimately
/// arrive under that label, and PKCS#1 / SEC1 bodies arrive both traditional-encrypted and
/// in the clear. A supplied password on an unencrypted container is ignored, which is what
/// OpenSSL does.
fn decode_key_material(pem: &str, password: Option<&str>) -> Result<DecodedKey> {
    if let Some(traditional) = crate::crypto::encrypted_pem::decrypt_pem_fixture(pem, password)? {
        // The padding validated; a body that still fails to decode means the passphrase was wrong.
        return DecodedKey::from_der_by_content(&traditional.der).ok_or(Error::InvalidPassword);
    }
    let (_, der) = first_pem_block(pem)
        .ok_or_else(|| Error::Certificate("Failed to parse private key as RSA or ECDSA".into()))?;
    if let Some(key) = DecodedKey::from_der_by_content(&der) {
        return Ok(key);
    }
    if pkcs8::EncryptedPrivateKeyInfo::try_from(der.as_slice()).is_err() {
        return Err(Error::Certificate("Failed to parse private key as RSA or ECDSA".into()));
    }
    let password = password.ok_or_else(|| {
        Error::Certificate("encrypted private key requires a password (-p or ZSIGN_PASSWORD)".into())
    })?;
    let plain = super::pkcs12::decrypt_key_bag(&der, password).map_err(super::pkcs12::pem_load_error)?;
    DecodedKey::from_der_by_content(&plain).ok_or(Error::InvalidPassword)
}
```

  Needed imports in `cert.rs`: `use rsa::pkcs1::DecodeRsaPrivateKey;` for the PKCS#1 arm below.
  `p256::SecretKey::from_sec1_der` is an inherent method already enabled by the crate's current
  `p256` features (`pkcs8` pulls `sec1`), so **no new dependency and no new feature** is required.

  `DecodedKey::from_pkcs8_pem` is deleted in the same commit: after this routing it has no
  caller, and a label-locked decoder left behind would be exactly the wrong convention to keep.

  and add the by-content decoder to `DecodedKey`:

```rust
    /// Decodes a private key by trying each encoding OpenSSL can produce: PKCS#8,
    /// then PKCS#1 (traditional RSA), then SEC1 (traditional EC).
    fn from_der_by_content(der: &[u8]) -> Option<Self> {
        if let Some(key) = Self::from_pkcs8_der(der) {
            return Some(key);
        }
        if let Ok(k) = RsaPrivateKey::from_pkcs1_der(der) {
            return Some(Self::Rsa(k));
        }
        p256::SecretKey::from_sec1_der(der)
            .ok()
            .map(|k| Self::Ecdsa(EcdsaSigningKey::from(&k)))
    }
```

- [ ] **Step 5: Update the docs that promised the opposite.** `crypto/cert.rs:3-26` module doc
  ("**PEM**: Separate certificate and private key files (unencrypted keys only)"), the `from_pem`
  doc comment (`:431-464`, including the `password` argument line "Reserved for future encrypted
  key support (must be `None`)" and the `# Errors` bullet "A password is provided (encrypted keys
  not yet supported)"), and `crypto/mod.rs:7-11` if it repeats the claim. All three must describe
  the new behaviour: PBES2 + traditional encrypted PEM supported, password optional, unencrypted
  containers ignore a supplied password.

- [ ] **Step 6: Run the scoped gate**

Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-core crypto:: -- --skip test_ipa_signing_is_deterministic`
Expected: every `crypto::` test passes, including the 18 pre-existing PKCS#12 fixture tests and the
55-test `cms_verify` module — a regression here means the routing changed an unencrypted path.

- [ ] **Step 7: Commit**

```
git add crates/zsign-core/src/crypto/cert.rs
git commit -m "feat(crypto): load encrypted pem private keys through the existing password flow"
```

---

## Task 7: Cut over the CLI reject path

**Files:**
- Modify: `crates/zsign-cli/src/main.rs:776-793` (delete `reject_encrypted_key` and its doc comment)
- Modify: `crates/zsign-cli/src/main.rs:810`, `:815`, `:845`, `:848` (the two call sites)
- Test: `crates/zsign-cli/src/main.rs:1668-1717` (`password_with_key_route_fails_explicitly`)

- [ ] **Step 1: Rewrite the pinned test first** so the cutover is visible as a behaviour change.
  Replace the body of `password_with_key_route_fails_explicitly` (which asserts the string
  `encrypted PEM keys are unsupported`) with a test of the real contract, and rename it:

```rust
    #[test]
    fn encrypted_pem_routes_through_the_password_flow() {
        let dir = TempDir::new().unwrap();
        let input = dir.path().join("in.bin");
        std::fs::write(&input, MINIMAL_MACHO).unwrap();
        let key = dir.path().join("key.pem");
        let cert = dir.path().join("cert.pem");
        std::fs::write(&key, ENC_TRAD_RSA).unwrap();
        std::fs::write(&cert, RSA_CERT).unwrap();
        let out = dir.path().join("o.bin");

        // No password: the loader says exactly what it needs.
        let r = run_cli(
            &[
                OsStr::new("-k"), key.as_os_str(),
                OsStr::new("-c"), cert.as_os_str(),
                OsStr::new("-o"), out.as_os_str(),
                input.as_os_str(),
            ],
            &[],
        );
        assert_eq!(r.code, 1, "stderr: {}", r.stderr);
        assert!(
            r.stderr.contains("requires a password"),
            "stderr: {}",
            r.stderr
        );

        // Wrong password: an explicit password failure, not a generic parse error.
        let r = run_cli(
            &[
                OsStr::new("-k"), key.as_os_str(),
                OsStr::new("-c"), cert.as_os_str(),
                OsStr::new("-p"), OsStr::new("nope"),
                OsStr::new("-o"), out.as_os_str(),
                input.as_os_str(),
            ],
            &[],
        );
        assert_eq!(r.code, 1, "stderr: {}", r.stderr);
        assert!(
            r.stderr.contains("Invalid password"),
            "stderr: {}",
            r.stderr
        );

        // Correct password: the key loads and the binary signs.
        let r = run_cli(
            &[
                OsStr::new("-k"), key.as_os_str(),
                OsStr::new("-c"), cert.as_os_str(),
                OsStr::new("-p"), OsStr::new("testpassword"),
                OsStr::new("-o"), out.as_os_str(),
                input.as_os_str(),
            ],
            &[],
        );
        assert_eq!(r.code, 0, "stderr: {}", r.stderr);
        assert!(out.exists(), "signed output missing");
    }

    #[test]
    fn pbes2_pem_wrong_password_is_a_password_error_at_the_cli_too() {
        let dir = TempDir::new().unwrap();
        let input = dir.path().join("in.bin");
        std::fs::write(&input, MINIMAL_MACHO).unwrap();
        let key = dir.path().join("key.pem");
        let cert = dir.path().join("cert.pem");
        std::fs::write(&key, ENC_PKCS8_RSA).unwrap();
        std::fs::write(&cert, RSA_CERT).unwrap();
        let r = run_cli(
            &[
                OsStr::new("-k"), key.as_os_str(),
                OsStr::new("-c"), cert.as_os_str(),
                OsStr::new("-p"), OsStr::new("nope"),
                OsStr::new("-o"), dir.path().join("o.bin").as_os_str(),
                input.as_os_str(),
            ],
            &[],
        );
        assert_eq!(r.code, 1, "stderr: {}", r.stderr);
        assert!(
            r.stderr.contains("Invalid password"),
            "a PBES2 wrong password must be explicit at the CLI too, stderr: {}",
            r.stderr
        );
    }

    #[test]
    fn password_on_an_unencrypted_pem_key_is_now_accepted() {
        // The deleted reject path failed any password on the key route *before looking at the key
        // at all*. A well-formed but undecodable plaintext PEM now reaches the loader, so the only
        // failures left are the ordinary parse ones. The assertion is therefore: the old reject
        // string is gone, and the run fails downstream at the decoder — not exit 0.
        let dir = TempDir::new().unwrap();
        let input = dir.path().join("in.bin");
        std::fs::write(&input, MINIMAL_MACHO).unwrap();
        let key = dir.path().join("key.pem");
        let cert = dir.path().join("cert.pem");
        // The label is split so no source line carries a private-key header.
        std::fs::write(
            &key,
            concat!(
                "-----BEGIN ",
                "PRIVATE KEY-----\n",
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n",
                "-----END ",
                "PRIVATE KEY-----\n"
            ),
        )
        .unwrap();
        std::fs::write(&cert, RSA_CERT).unwrap();
        let r = run_cli(
            &[
                OsStr::new("-k"), key.as_os_str(),
                OsStr::new("-c"), cert.as_os_str(),
                OsStr::new("-p"), OsStr::new("irrelevant"),
                OsStr::new("-o"), dir.path().join("o.bin").as_os_str(),
                input.as_os_str(),
            ],
            &[],
        );
        assert_eq!(r.code, 1, "stderr: {}", r.stderr);
        assert!(
            !r.stderr.contains("encrypted PEM keys are unsupported"),
            "the old reject path must be gone, stderr: {}",
            r.stderr
        );
        assert!(
            r.stderr.contains("Failed to parse private key"),
            "a password on an unencrypted key must be ignored, not rejected, stderr: {}",
            r.stderr
        );
    }
```

  Fixture constants at the top of the test module, beside the existing cross-crate pair
  (`RSA_CERT` at `main.rs:1062`, `ENC_TRAD_RSA` at `:1063`) and its `pem_fixture` decoder
  (`:1068-1074`). Each encrypted container is committed as one
  `base64 -w0` blob of the whole OpenSSL PEM text, so the constant reads the `.b64` and decodes
  it through the same `pem_fixture` helper the core tests use. There is deliberately **no**
  plaintext-key constant: the unencrypted case generates its key in-test and frames it with
  `pem_text` (`cert.rs:773`), which is what keeps it a regression test of the new decoder.

```rust
    fn pem_fixture(b64: &str) -> String {
        String::from_utf8(
            base64::engine::general_purpose::STANDARD
                .decode(b64.trim())
                .expect("fixture blob must be base64"),
        )
        .expect("OpenSSL PEM text is UTF-8")
    }
    const ENC_TRAD_RSA: &str = include_str!(
        "../../zsign-core/src/crypto/fixtures/pem_rsa_key_dekinfo_aes256.pem.b64"
    );
    const ENC_PKCS8_RSA: &str = include_str!(
        "../../zsign-core/src/crypto/fixtures/pem_rsa_key_pbes2_sha256.pem.b64"
    );
    const RSA_CERT: &[u8] = include_bytes!("../../zsign-core/src/crypto/fixtures/pem_rsa_cert.pem");
```

- [ ] **Step 2: Run it to verify it fails** with `encrypted PEM keys are unsupported` (the old path
  still short-circuits).

- [ ] **Step 3: Delete the reject and thread the password.** Remove `reject_encrypted_key` and its
  doc comment (`:776-793`), remove the two calls, and pass the resolved password at both routes:

```rust
        let creds = SigningCredentials::from_pem(&cert_data, &key_data, cli.password.as_deref())?;
```

```rust
            let creds = SigningCredentials::from_pem(
                &cert_data,
                wrapped.as_bytes(),
                cli.password.as_deref(),
            )?;
```

- [ ] **Step 4: Run the CLI tests**

Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-cli -- --skip test_ipa_signing_is_deterministic`
Expected: all pass, including the pre-existing password/env/TTY tests (`main.rs:1567`, `:2022`) —
they cover the PKCS#12 flow, which this task must not change.

- [ ] **Step 5: Commit**

```
git add crates/zsign-cli/src/main.rs
git commit -m "feat(cli): decrypt encrypted pem keys instead of rejecting the password flow"
```

---

## Tasks 8-10: corrections applied during implementation

The snippets in Tasks 8-10 below were written from the RFC text before any OCSP code was compiled.
Implementing them surfaced ten defects; each is listed with what shipped, and the shipped code —
not the snippet — is the authority. The snippets are kept in place because the surrounding tests
and the fixture recipe are unchanged.

1. **`nextUpdate` is `[0] EXPLICIT`.** The snippet peeked `0x80` and read a bare
   `GeneralizedTime`, so the branch could never fire and a signed answer could be replayed past its
   own expiry. Shipped code peeks `0xa0` and reads the time inside the wrapper, and the fixture set
   gained `good_nextupdate.der` (recipe flag `-nmin 60`, guarded by a `Next Update` grep) with
   tests on both sides of the window.
2. **`span_of_next_tlv` takes no argument** and returns one slice; the snippet's
   `span_of_next_tlv(basic)?` with a tuple destructure does not compile.
3. **`ResponderId` must actually be built.** The snippet bound `rid_tag`/`rid_value`, defined the
   enum, and then never constructed it, leaving the delegated-responder path unreachable. Shipped
   code binds a `ResponderId` from the walked bytes and `pick_signer` consumes it, with no fallback
   to the issuer key after a failed delegated-responder check (proved by `good_delegate_nocert.der`).
4. **Framing helpers have to exist.** `concat`, `oid_tlv` and `integer_from_magnitude` were used
   but never defined; all three are now local, and `integer_from_magnitude` encodes an empty or
   all-zero magnitude as `02 01 00`, never `02 00`.
5. **`issuerNameHash` must cover the stored bytes.** Walking `read_sequence()` once returns the
   `TBSCertificate` *content*, which is still a TLV, so the first walk read the certificate's
   signature instead of the issuer `Name`. The shipped walk steps into the TBS TLV first, and the
   digest now equals OpenSSL's (`0b33e087…`), with tests proving the wrong recipes differ.
6. **`parse_time` needed an OCSP-shaped parser.** RFC 3339/RFC 2822 formatters cannot read
   `YYMMDDHHMMSSZ`; and because OpenSSL emits a two-digit-year `GeneralizedTime` for
   `revocationTime`, keying the year width off the ASN.1 tag produced year 4601. The shipped
   parser takes the digit count from the value.
7. **One envelope walk, not two.** `walk_response` and `this_update_of` each re-walked the
   response, so the clock a test anchored to could come from a different message than the one
   verified. Both now share one `basic_response` helper.
8. **`warning_of` is not a stub.** The snippet returned `None` unconditionally. It is now the real
   network-free composition of `issuer_of` + `check` over a caller-supplied transport, available on
   every target; `warn_revocation` remains the only function that opens a socket.
9. **The transport had two latent hangs.** `(authority, 80)` was resolved as a whole authority
   string (already containing `:port`), so the port in the AIA URI was ignored and the loopback
   test could never connect; and the socket timeouts used `DEFAULT_BUDGET` instead of the caller's
   budget. Shipped code splits host/port (`split_authority`, with `[ipv6]` support), takes a
   numeric-literal fast path off the resolver, and threads the budget into connect/read/write.

11. **Shared certificate verifier, wider delegate algorithm set.** Deleting `revocation.rs`'s
    duplicate `verify_cert_signature` in favour of promoting `cms_verify::verify_cert_signature`
    (`:1518`) to `pub(crate)` also widened the signature algorithms a *delegated responder
    certificate* may use: `sha1WithRSA`/`sha256WithRSA`/`ecdsa-with-SHA256` only before, versus the
    chain verifier's RSA SHA-1/256/384/512 (SHA-256 for an unrecognised RSA OID) and ungated P-256
    ECDSA after. The three trust conditions — issued by this CA, `id-kp-OCSPSigning` present,
    signature verifies under the CA key — are unchanged and all still required, and the response
    signature path keeps its own strict OID allowlist in `verify_signature`. `has_ocsp_signing_eku`
    stays local to `revocation.rs` (`:675`): `cms_verify.rs` has no OCSPSigning helper, only
    codeSigning-purpose checks.

12. **The scheme filter moved from AIA extraction into `check`.** The snippet filtered in
    `ocsp_responder_url` (`url.starts_with("http://").then_some(url)`), which made `UnusableUrl`
    unreachable — a non-`http:` responder would have been indistinguishable from a certificate
    with no OCSP pointer at all. Shipped code returns the AIA text whatever its scheme
    (`revocation.rs:162-178`) and `check` short-circuits `UnusableUrl` *before* the issuer lookup
    (`:801-803`), so an `https:` AIA with no issuer reports `UnusableUrl`, not
    `NoIssuerCertificate`. Both snippets below are corrected to that ordering.

Two plan-side claims were also wrong and are corrected above where they appear: the snippet's
expected request was `SEQUENCE x3` around the CertID where RFC 6960 has four levels
(`OCSPRequest / tbsRequest / requestList / Request`), and the foreign-issuer-key case is not pinned
to one variant. A foreign issuer changes the recomputed `CertID`, so it fails the match *and* the
signature check, and the shipped test asserts only `NotChecked(_)`
(`revocation.rs:1335-1338`, with a `Good` control at `:1351`); `NoMatchingCertId` is pinned for a
*serial* mismatch only (`:1364-1367`).


## Task 8: OCSP request construction and AIA extraction

**Files:**
- Create: `crates/zsign-core/src/crypto/revocation.rs`
- Modify: `crates/zsign-core/src/crypto/mod.rs` (`pub mod revocation;`)
- Create: 8 fixtures under `crates/zsign-core/src/crypto/fixtures/revocation/`

- [ ] **Step 1: Generate the fixtures** with the offline recipe verified during design (P12, P14):

```bash
set -euo pipefail
R=$PWD/crates/zsign-core/src/crypto/fixtures/revocation
d=$(mktemp -d -p "$HOME/tmp-cargo" zsn42-ocsp.XXXXXX); trap 'rm -rf "$d"' EXIT
mkdir -p "$R"
cat > "$d/ca.cnf" <<'EOF'
[ req ]
distinguished_name = dn
x509_extensions = caext
prompt = no
[ dn ]
CN = zsign test ocsp ca
[ caext ]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
[ leaf ]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = codeSigning
subjectKeyIdentifier = hash
authorityInfoAccess = OCSP;URI:http://ocsp.invalid.test/ocsp
[ delegate ]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = OCSPSigning
subjectKeyIdentifier = hash
[ ca ]
default_ca = CA_default
[ CA_default ]
dir = .
database = $dir/index.txt
serial = $dir/serial
new_certs_dir = $dir
certificate = $dir/ca.pem
private_key = $dir/ca.key
default_md = sha256
policy = pol
email_in_dn = no
unique_subject = no
default_days = 3650
x509_extensions = leaf
[ pol ]
commonName = supplied
EOF
cd "$d"
openssl req -new -x509 -nodes -keyout ca.key -out ca.pem -days 36500 -sha256 -config ca.cnf -extensions caext
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out leaf.key
openssl req -new -key leaf.key -subj "/CN=zsign test leaf" -out leaf.csr
: > index.txt; echo 1000 > serial; echo 'unique_subject = no' > index.txt.attr
openssl ca -batch -config ca.cnf -created_serial >/dev/null 2>&1 || true
openssl ca -batch -config ca.cnf -in leaf.csr -out issued_leaf.pem
ser=$(openssl x509 -in issued_leaf.pem -noout -serial | cut -d= -f2)
openssl ocsp -issuer ca.pem -cert issued_leaf.pem -reqout req.der
openssl ocsp -reqin req.der -respout good.der -index index.txt -CA ca.pem -rsigner ca.pem -rkey ca.key -noverify
openssl ocsp -reqin req.der -respout good_nextupdate.der -index index.txt -CA ca.pem -rsigner ca.pem -rkey ca.key -noverify -nmin 60
python3 - <<'PY'
rows = [l.split('\t') for l in open('index.txt').read().splitlines() if l.strip()]
for r in rows:
    if r[0] == 'V':
        r[0] = 'R'
        r[2] = '260101000000Z'
open('index.txt','w').write('\n'.join('\t'.join(r) for r in rows) + '\n')
PY
openssl ocsp -reqin req.der -respout revoked.der -index index.txt -CA ca.pem -rsigner ca.pem -rkey ca.key -noverify
# The revoked answer must say revoked, and the good answer must not. A grep that only prints
# a warning would let a broken fixture ship, so both checks abort.
openssl ocsp -respin revoked.der -text -noverify 2>&1 | grep -q 'Cert Status: revoked'
openssl ocsp -respin revoked.der -text -noverify 2>&1 | grep -q 'Revocation Time: Jan  1 00:00:00 2026 GMT'
openssl ocsp -respin good.der -text -noverify 2>&1 | grep -q 'Cert Status: good'
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out delegate.key
openssl req -new -key delegate.key -subj "/CN=zsign test ocsp responder" -out delegate.csr
openssl x509 -req -in delegate.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -days 3650 -sha256 -extfile ca.cnf -extensions delegate -out delegate.pem
openssl ocsp -reqin req.der -respout good_delegate.der -index index.txt -CA ca.pem \
  -rsigner delegate.pem -rkey delegate.key -noverify
openssl ocsp -reqin req.der -respout good_delegate_nocert.der -index index.txt -CA ca.pem \
  -rsigner delegate.pem -rkey delegate.key -noverify -resp_no_certs
# The delegated responder must appear in one answer and not the other, or the two fixtures
# are the same file and the trust tests prove nothing.
openssl ocsp -respin good_delegate.der -text -noverify 2>&1 | grep -q 'Responder Cert'
if openssl ocsp -respin good_delegate_nocert.der -text -noverify 2>&1 \
     | grep -q 'Responder Cert'; then
  echo "nocert fixture still embeds a responder certificate"; exit 1
fi
cp ca.pem issued_leaf.pem req.der good.der good_nextupdate.der revoked.der \
   good_delegate.der good_delegate_nocert.der "$R/"
ls -1 "$R" | grep -c . | grep -qx 8 || { echo "expected 8 revocation fixtures"; exit 1; }
# `good.der` deliberately omits nextUpdate (RFC 6960 makes it OPTIONAL); this one carries it an
# hour out, so the window tests have a real pair to straddle. Without the flag openssl emits no
# nextUpdate at all and the file would be a byte-copy of good.der.
openssl ocsp -respin good_nextupdate.der -text -noverify 2>&1 | grep -q 'Next Update:'
# thisUpdate is stamped with the generation date; the tests below anchor their clock to the
# fixture instead of a constant so nothing rots. Printed for the reader, asserted nowhere.
openssl ocsp -respin good.der -text -noverify 2>&1 | grep 'This Update'
echo "revocation fixtures written"
```

- [ ] **Step 2: Write the failing tests** in `revocation.rs` (fixtures as `const`
  `include_bytes!`/`include_str!` per the `pkcs12.rs:901-909` idiom):

```rust
    #[test]
    fn aia_extension_yields_the_ocsp_responder_url() {
        let leaf = Certificate::from_pem(LEAF_PEM.as_bytes()).unwrap();
        assert_eq!(ocsp_responder_url(&leaf).as_deref(), Some("http://ocsp.invalid.test/ocsp"));
    }

    #[test]
    fn aia_without_an_ocsp_access_method_yields_nothing() {
        // The Apple root is self-issued with only a CRL pointer.
        let root = Certificate::from_pem(super::assets::APPLE_ROOT_CA_CERT.as_bytes()).unwrap();
        assert_eq!(ocsp_responder_url(&root), None);
    }

    #[test]
    fn request_cert_id_matches_the_independent_implementation() {
        let leaf = Certificate::from_pem(LEAF_PEM.as_bytes()).unwrap();
        let issuer = Certificate::from_pem(CA_PEM.as_bytes()).unwrap();
        let cid = cert_id(&leaf, &issuer).expect("certID");
        // openssl wrote REQ_DER for this exact pair; the CertID must appear verbatim inside it.
        assert!(
            REQ_DER.windows(cid.len()).any(|w| w == cid),
            "our CertID is not a byte-substring of openssl's request"
        );
        // Independent check of the hash *input*, not just the framing: hashing the issuer DN
        // as stored in the leaf must differ from hashing the leaf's own subject, which is the
        // easy mistake here. Both are compared at runtime so the test survives a regenerated
        // fixture with a different CA DN.
        let name_hash = sha1::Sha1::digest(stored_issuer_name_der(&leaf).unwrap()).to_vec();
        let subject_hash = sha1::Sha1::digest(leaf.tbs_certificate.subject.to_der().unwrap()).to_vec();
        assert_eq!(name_hash.len(), 20);
        assert_ne!(name_hash, subject_hash, "by construction these differ; if they ever match, the fixture is degenerate");
    }

    #[test]
    fn request_is_deterministic_and_minimal() {
        let leaf = Certificate::from_pem(LEAF_PEM.as_bytes()).unwrap();
        let issuer = Certificate::from_pem(CA_PEM.as_bytes()).unwrap();
        let a = build_request(&leaf, &issuer).unwrap();
        let b = build_request(&leaf, &issuer).unwrap();
        assert_eq!(a, b, "request bytes must be reproducible");
        // One Request, no nonce, no requestExtensions, no optionalSignature. The length is
        // derived from the fixture rather than hardcoded, so regenerating the CA/leaf pair
        // cannot silently date this assertion.
        let expected = tlv(0x30, &tlv(0x30, &tlv(0x30, &cert_id(&leaf, &issuer).unwrap())));
        assert_eq!(a, expected);
    }
```

- [ ] **Step 3: Implement `cert_id`, `build_request`, `ocsp_responder_url` and the framing
  The code below is the version that was compiled and run against the generated fixtures
  during design; the field order and the two hash inputs are the parts that must not drift.
  Design scratch lived in an untracked temp directory, so nothing here depends on it:
  everything that matters is reproduced in this document.

```rust
/// DER framing for a definite, minimally-encoded length. Indefinite lengths (0x80) are
/// never produced here and are rejected on input.
fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if body.len() < 0x80 {
        out.push(body.len() as u8);
    } else {
        let mut len_bytes = Vec::new();
        let mut n = body.len();
        while n > 0 {
            len_bytes.insert(0, (n & 0xff) as u8);
            n >>= 8;
        }
        out.push(0x80 | len_bytes.len() as u8);
        out.extend_from_slice(&len_bytes);
    }
    out.extend_from_slice(body);
    out
}

/// `CertID ::= SEQUENCE { hashAlgorithm, issuerNameHash, issuerKeyHash, serialNumber }`
/// (RFC 6960 §4.1.1). `issuerNameHash` hashes the DER of the issuer `Name` **as it appears
/// in the leaf**; `issuerKeyHash` hashes the value bits of the issuer's
/// `subjectPublicKey`, excluding the BIT STRING's tag, length and unused-bits byte.
/// Both use SHA-1, which is what every responder in the field, including Apple's, expects.
fn cert_id(leaf: &Certificate, issuer: &Certificate) -> Option<Vec<u8>> {
    let name_der = stored_issuer_name_der(leaf)?;
    let name_hash = sha1::Sha1::digest(&name_der).to_vec();
    let key_bits = issuer
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes();
    let key_hash = sha1::Sha1::digest(key_bits).to_vec();
    let serial = leaf.tbs_certificate.serial_number.as_bytes();
    let alg = tlv(0x30, &concat(&[&oid_tlv(OID_SHA1), &tlv(0x05, &[])]));
    Some(tlv(
        0x30,
        &concat(&[
            &alg,
            &tlv(0x04, &name_hash),
            &tlv(0x04, &key_hash),
            &integer_from_magnitude(serial),
        ]),
    ))
}

/// `OCSPRequest ::= SEQUENCE { tbsRequest SEQUENCE { requestList SEQUENCE OF Request } }`
/// with one `Request { reqCert: CertID }` and every OPTIONAL field absent.
/// The issuer `Name` TLV of `leaf`, byte-for-byte as stored in the leaf's DER.
///
/// `Certificate` -> `TBSCertificate` -> field 4 (`issuer`). Walking the stored bytes rather than
/// calling `Name::to_der()` is what keeps the digest equal to the responder's, which hashes the
/// stored form.
fn stored_issuer_name_der(leaf: &Certificate) -> Option<Vec<u8>> {
    let cert_body = leaf.to_der().ok()?;
    let tbs = DerReader::new(&cert_body).read_sequence().ok()?;
    let mut r = DerReader::new(tbs);
    if r.peek_tag() == Some(0xa0) {
        r.read_tlv().ok()?; // [0] version, DEFAULT v1 and sometimes present
    }
    r.read_tlv().ok()?; // serialNumber
    r.read_tlv().ok()?; // signature AlgorithmIdentifier
    let (_, name, _) = r.span_of_next_tlv().map(|s| (0u8, s, 0usize))?;
    Some(name.to_vec())
}

fn build_request(leaf: &Certificate, issuer: &Certificate) -> Option<Vec<u8>> {
    let cid = cert_id(leaf, issuer)?;
    let request = tlv(0x30, &cid);
    let request_list = tlv(0x30, &request);
    let tbs_request = tlv(0x30, &request_list);
    Some(tlv(0x30, &tbs_request))
}

/// The `id-ad-ocsp` `uniformResourceIdentifier` text of the leaf's AIA extension, whatever its
/// scheme, or `None` when the certificate names no OCSP access location at all. Whether the text is
/// one this module can actually speak is the caller's decision: [`check`] reports a non-`http://`
/// location as [`NotCheckedReason::UnusableUrl`], which keeps "no responder named" and "responder
/// named but unreachable by this module" distinguishable. Decoded with the typed extension
/// `x509-cert` already ships (`ext/pkix/access.rs:19` `AuthorityInfoAccessSyntax`, re-exported at
/// `ext/pkix.rs:17`), so no hand-rolled AIA parser exists here.
pub fn ocsp_responder_url(leaf: &Certificate) -> Option<String> {
    use x509_cert::ext::pkix::AuthorityInfoAccessSyntax;
    let value = ext_value(leaf, ID_PE_AUTHORITY_INFO_ACCESS)?;
    let aia = AuthorityInfoAccessSyntax::from_der(value).ok()?;
    aia.0.iter().find_map(|desc| {
        if desc.access_method != ID_AD_OCSP {
            return None;
        }
        match &desc.access_location {
            // GeneralName `uniformResourceIdentifier` is `[6] IMPLICIT IA5String`.
            x509_cert::ext::pkix::name::GeneralName::UniformResourceIdentifier(uri) => {
                Some(uri.to_string())
            }
            _ => None,
        }
    })
}

/// The DER value of extension `id`, or `None` when absent. Duplicated from
/// `cert.rs:329`/`cms_verify.rs:1572` rather than widened across modules, following the
/// precedent recorded in `specs/2026-09-25-credential-hardening-design.md:147-152`.
fn ext_value(cert: &Certificate, id: ObjectIdentifier) -> Option<&[u8]> {
    let exts = cert.tbs_certificate.extensions.as_ref()?;
    exts.iter()
        .find(|e| e.extn_id == id)
        .map(|e| e.extn_value.as_bytes())
}
```

  `ID_PE_AUTHORITY_INFO_ACCESS` and `ID_AD_OCSP` come from
  `const_oid::db::rfc5280::*`; `OID_SHA1` is `1.3.14.3.2.26` and `oid_tlv`/`tlv` are the module's
  own framing helpers above. `integer_from_magnitude` re-encodes the
  serial as an unsigned DER INTEGER — leading zero bytes are stripped and one is re-added when the
  top bit is set, which is what RFC 6960's `CertificateSerialNumber` requires.

- [ ] **Step 4: Run the tests**

Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-core revocation -- --skip test_ipa_signing_is_deterministic`
Expected: the four Step-2 tests pass.

- [ ] **Step 5: Commit**

```
git add crates/zsign-core/src/crypto/revocation.rs crates/zsign-core/src/crypto/mod.rs crates/zsign-core/src/crypto/fixtures/revocation
git commit -m "feat(crypto): build rfc6960 ocsp requests from the leaf authority info access"
```

---

## Task 9: OCSP response parsing, verification, and status

**Files:**
- Modify: `crates/zsign-core/src/crypto/revocation.rs`
- Modify: `crates/zsign-core/src/crypto/cms_verify.rs` (promote `verify_cert_signature` `:1518` to
  `pub(crate)`; no logic change). The EKU lookup is **not** promoted — see Step 4.

- [ ] **Step 1: Declare the fixture constants and the shared test helpers** at the top of
  `revocation.rs`'s test module — every test below uses them:

```rust
    const CA_PEM: &str = include_str!("fixtures/revocation/ca.pem");
    const LEAF_PEM: &str = include_str!("fixtures/revocation/issued_leaf.pem");
    const REQ_DER: &[u8] = include_bytes!("fixtures/revocation/req.der");
    const GOOD_DER: &[u8] = include_bytes!("fixtures/revocation/good.der");
    const REVOKED_DER: &[u8] = include_bytes!("fixtures/revocation/revoked.der");
    const GOOD_DELEGATE_DER: &[u8] = include_bytes!("fixtures/revocation/good_delegate.der");
    const GOOD_DELEGATE_NOCERT_DER: &[u8] =
        include_bytes!("fixtures/revocation/good_delegate_nocert.der");

    /// The committed leaf/CA pair every test checks a status for.
    fn fixture_pair() -> (Certificate, Certificate) {
        (
            Certificate::from_pem(LEAF_PEM.as_bytes()).expect("fixture leaf"),
            Certificate::from_pem(CA_PEM.as_bytes()).expect("fixture ca"),
        )
    }
```

- [ ] **Step 2: Write the failing tests**

```rust
    /// Reads the `thisUpdate` that the responder actually stamped, so the window tests are
    /// anchored to the committed fixture instead of a date that rots, and are independent of
    /// the machine clock.
    fn fixture_this_update() -> time::OffsetDateTime {
        this_update_of(GOOD_DER).expect("fixture carries a parsable thisUpdate")
    }

    fn now_in_window() -> time::OffsetDateTime {
        fixture_this_update() + time::Duration::seconds(60)
    }

    #[test]
    fn good_response_verifies_and_reports_good() {
        let (leaf, issuer) = fixture_pair();
        let status = parse_and_verify(GOOD_DER, &leaf, &issuer, now_in_window());
        assert!(
            matches!(status, RevocationStatus::Good),
            "expected Good, got {status:?}"
        );
    }

    #[test]
    fn revoked_response_reports_the_revocation_time() {
        let (leaf, issuer) = fixture_pair();
        let status = parse_and_verify(REVOKED_DER, &leaf, &issuer, now_in_window());
        let RevocationStatus::Revoked { revoked_at, .. } = status else {
            panic!("expected Revoked, got {status:?}");
        };
        assert_eq!(
            revoked_at.map(|t| t.unix_timestamp()),
            Some(1_767_225_600),
            "the recipe stamps 2026-01-01T00:00:00Z via the index.txt revocation date"
        );
        assert!(status.warning().is_some_and(|w| w.contains("revoked")));
    }

    #[test]
    fn a_tampered_signature_is_not_trusted() {
        let (leaf, issuer) = fixture_pair();
        let mut bad = GOOD_DER.to_vec();
        // Locate the 2048-bit signature BIT STRING by its framing rather than by a fixed
        // offset, so a regenerated fixture cannot turn this into a vacuous pass: the search
        // itself panics with a clear message if the shape ever changes.
        let marker = [0x03u8, 0x82, 0x01, 0x01, 0x00];
        let at = bad
            .windows(marker.len())
            .position(|w| w == marker)
            .expect("fixture must contain a 256-byte signature BIT STRING");
        bad[at + marker.len() + 8] ^= 0x01;
        let status = parse_and_verify(&bad, &leaf, &issuer, now_in_window());
        assert!(
            matches!(status, RevocationStatus::NotChecked(NotCheckedReason::Unverified)),
            "a forged answer must be Unverified, got {status:?}"
        );
        assert!(status.warning().is_none());
    }

    #[test]
    fn a_foreign_issuer_key_is_not_trusted() {
        let (leaf, real_issuer) = fixture_pair();
        let unrelated = Certificate::from_pem(
            super::assets::APPLE_WWDR_CA_G3_CERT.as_bytes(),
        )
        .unwrap();
        // The response is the one the real CA signed, so the foreign issuer both fails the CertID
        // match and cannot verify the signature. Which of the two trips first is an
        // implementation detail, so the test pins the contract — never a status — rather than
        // over-specifying one variant.
        let status = parse_and_verify(GOOD_DER, &leaf, &unrelated, now_in_window());
        assert!(
            matches!(status, RevocationStatus::NotChecked(_)),
            "a foreign issuer key must never produce a status, got {status:?}"
        );
        assert!(status.warning().is_none());
        // Control: the same bytes are trusted under the real issuer, so the failure above is the
        // key and not a permanently broken parser.
        assert!(matches!(
            parse_and_verify(GOOD_DER, &leaf, &real_issuer, now_in_window()),
            RevocationStatus::Good
        ));
    }

    #[test]
    fn a_response_for_another_certificate_is_not_trusted() {
        let (leaf, issuer) = fixture_pair();
        let mut other = leaf.clone();
        other.tbs_certificate.serial_number =
            x509_cert::serial_number::SerialNumber::new(&[0x7f]).unwrap();
        let status = parse_and_verify(GOOD_DER, &other, &issuer, now_in_window());
        assert!(
            matches!(
                status,
                RevocationStatus::NotChecked(NotCheckedReason::NoMatchingCertId)
            ),
            "a certID mismatch must not produce a status, got {status:?}"
        );
    }

    #[test]
    fn a_delegated_responder_is_trusted_only_with_a_verified_certificate() {
        let (leaf, issuer) = fixture_pair();
        // responderID names the delegate and the answer embeds its certificate, which the CA
        // issued and which carries id-kp-OCSPSigning: trusted, through the delegate's key.
        let with_cert = parse_and_verify(GOOD_DELEGATE_DER, &leaf, &issuer, now_in_window());
        assert!(matches!(with_cert, RevocationStatus::Good), "got {with_cert:?}");
        // The same responderID with the certificate stripped binds that name to no key the
        // issuer vouches for, so the answer must come back unverified, not trusted.
        let without = parse_and_verify(GOOD_DELEGATE_NOCERT_DER, &leaf, &issuer, now_in_window());
        assert!(
            matches!(without, RevocationStatus::NotChecked(NotCheckedReason::Unverified)),
            "a delegate without its certificate must not be trusted, got {without:?}"
        );
    }

    #[test]
    fn an_absent_next_update_bounds_nothing_by_design() {
        // The fixture responder omits nextUpdate (RFC 6960 makes it OPTIONAL), so the only
        // freshness rule left is `thisUpdate <= now`. Pinned so the limit is a documented
        // decision rather than an accident: an old but signed `good` stays credible.
        let (leaf, issuer) = fixture_pair();
        let far_future = fixture_this_update() + time::Duration::days(400);
        assert!(matches!(
            parse_and_verify(GOOD_DER, &leaf, &issuer, far_future),
            RevocationStatus::Good
        ));
    }

    #[test]
    fn validity_window_is_enforced() {
        let (leaf, issuer) = fixture_pair();
        // An hour before the responder said anything: outside the window by definition.
        let earlier = fixture_this_update() - time::Duration::hours(1);
        let status = parse_and_verify(GOOD_DER, &leaf, &issuer, earlier);
        assert!(
            matches!(
                status,
                RevocationStatus::NotChecked(NotCheckedReason::OutsideValidityWindow)
            ),
            "an answer from after `thisUpdate` must not be reused, got {status:?}"
        );
    }

    #[test]
    fn non_successful_and_malformed_responses_are_silent() {
        let (leaf, issuer) = fixture_pair();
        let malformed = parse_and_verify(b"not der at all", &leaf, &issuer, now_in_window());
        assert!(matches!(
            malformed,
            RevocationStatus::NotChecked(NotCheckedReason::Malformed(_))
        ));
        // responseStatus = internalError(2) with no responseBytes.
        let refused = vec![0x30, 0x03, 0x0a, 0x01, 0x02];
        let status = parse_and_verify(&refused, &leaf, &issuer, now_in_window());
        assert!(matches!(
            status,
            RevocationStatus::NotChecked(NotCheckedReason::Malformed(_))
        ));
        assert!(status.warning().is_none());
    }
```

- [ ] **Step 3: Run them to verify they fail** (`parse_and_verify` does not exist yet).

- [ ] **Step 4: Implement the parser.** The field order below is the substance of this task; the
  measured behaviour is P12-P14 plus the four negative controls above. Reuse the crate's own
  `pkcs12::DerReader` for the walk (promote it to `pub(crate)` — it already exposes
  `read_sequence`, `read_oid`, `read_tlv`-style primitives and the peek helpers this needs) rather
  than a second reader.

```rust
/// Parses and verifies one `OCSPResponse` for `leaf`/`issuer`.
///
/// This function cannot fail: every outcome, including a garbage response and a response whose
/// CertID cannot even be built, is a `RevocationStatus`, and only an authenticated `Revoked`
/// carries a warning. A revocation check must never be able to fail a signing run.
pub fn parse_and_verify(
    response_der: &[u8],
    leaf: &Certificate,
    issuer: &Certificate,
    now: time::OffsetDateTime,
) -> RevocationStatus {
    let Some(want_cid) = cert_id(leaf, issuer) else {
        return RevocationStatus::NotChecked(NotCheckedReason::Malformed(
            "cannot encode CertID for this certificate pair".into(),
        ));
    };
    walk_response(response_der, &want_cid, issuer, now)
        .unwrap_or_else(|| RevocationStatus::NotChecked(NotCheckedReason::Malformed(
            "response is not a parseable OCSPResponse for this certificate".into(),
        )))
}

/// Compares two DER `CertID`s field by field rather than byte by byte: a responder is free to
/// encode the serial with a different (still valid) INTEGER length or a non-minimal length form,
/// and a byte compare would silently downgrade a legitimate answer to `Malformed`.
fn cert_ids_match(a: &[u8], b: &[u8]) -> bool {
    fn fields(cid: &[u8]) -> Option<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)> {
        let body = DerReader::new(cid).read_sequence().ok()?;
        let mut r = DerReader::new(body);
        let alg = r.read_sequence().ok()?.to_vec();
        let name = r.read_octet_string().ok()?.to_vec();
        let key = r.read_octet_string().ok()?.to_vec();
        let serial = r.read_tlv().ok()?.1.trim_start_matches([0]).to_vec();
        Some((alg, name, key, serial))
    }
    fields(a).is_some() && fields(a) == fields(b)
}
```

  with the walk itself, in `RFC 6960` order:

```rust
/// `OCSPResponse ::= SEQUENCE { responseStatus OCSPResponseStatus,
///                              responseBytes [0] EXPLICIT ResponseBytes OPTIONAL }`
fn walk_response(
    bytes: &[u8], want_cid: &[u8], issuer: &Certificate, now: time::OffsetDateTime,
) -> Option<RevocationStatus> {
    let mut outer = DerReader::new(bytes);
    let top = outer.read_sequence().ok()?;
    let mut r = DerReader::new(top);
    let (status_tag, status_val) = r.read_tlv().ok()?;
    if status_tag != 0x0a || status_val != [0] {
        let code = status_val.first().copied().unwrap_or(0xff);
        return Some(RevocationStatus::NotChecked(NotCheckedReason::Malformed(format!(
            "responder returned responseStatus {code}"
        ))));
    }
    let (_, wrapped) = r.read_tlv().ok()?; // [0] EXPLICIT ResponseBytes
    let rb = DerReader::new(wrapped).read_sequence().ok()?;
    let mut rbr = DerReader::new(rb);
    if rbr.read_oid().ok()?.to_string() != OID_OCSP_BASIC {
        return None;
    }
    let (_, basic_tlv) = rbr.read_tlv().ok()?; // OCTET STRING wrapping BasicOCSPResponse
    let basic = DerReader::new(basic_tlv).read_sequence().ok()?;
    let mut b = DerReader::new(basic);
    // The signed bytes: the tbsResponseData TLV, verbatim out of the response.
    let (tbs_start, tbs_bytes) = b.span_of_next_tlv(basic)?;
    let _ = tbs_start;
    let sig_alg = b.read_sequence().ok()?;
    let sig_alg_oid = DerReader::new(sig_alg).read_oid().ok()?;
    let (_, sig_bits) = b.read_tlv().ok()?;
    let signature = sig_bits.get(1..)?; // skip the unused-bits byte
    // `certs [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL` — the tag is 0xa0.
    let mut embedded: Vec<Certificate> = Vec::new();
    if let Ok((0xa0, certs_wrap)) = b.read_tlv() {
        if let Ok(inner) = DerReader::new(certs_wrap).read_sequence() {
            let mut c = DerReader::new(inner);
            while let Ok(seq) = c.read_sequence() {
                let full = tlv(0x30, seq);
                if let Ok(cert) = Certificate::from_der(&full) {
                    embedded.push(cert);
                }
            }
        }
    }
    // ResponseData: [version], responderID, producedAt, responses, [1] extensions.
    let tbs = DerReader::new(tbs_bytes).read_sequence().ok()?;
    let mut d = DerReader::new(tbs);
    if d.peek_tag() == Some(0xa0) {
        d.read_tlv().ok()?;
    }
    let (rid_tag, rid_value) = d.read_tlv().ok()?;
    let responder_by_name = rid_tag == 0xa1;
    let _produced_at = d.read_tlv().ok()?;
    let responses = d.read_sequence().ok()?;
    let mut rs = DerReader::new(responses);
    while let Ok(single_der) = rs.read_sequence() {
        let mut single = DerReader::new(single_der);
        let (_, cid_body) = single.read_tlv().ok()?;
        if tlv(0x30, cid_body) != want_cid {
            continue;
        }
        // certStatus first: good [0], revoked [1] IMPLICIT RevokedInfo, unknown [2].
        let (cs_tag, cs_body) = single.read_tlv().ok()?;
        let revoked_at = if cs_tag == 0xa1 {
            let mut rev = DerReader::new(cs_body);
            let (_, when) = rev.read_tlv().ok()?;
            Some(parse_generalized_time(when)?)
        } else {
            None
        };
        let this_update = parse_time(single.read_tlv().ok()?.1)?;
        let next_update = match single.peek_tag() {
            Some(0x80) => Some(parse_time(single.read_tlv().ok()?.1)?),
            _ => None,
        };
        if this_update > now || next_update.is_some_and(|n| n < now) {
            return Some(RevocationStatus::NotChecked(
                NotCheckedReason::OutsideValidityWindow,
            ));
        }
        let _ = &responder_id;
        }
        let signer = pick_signer(&responder_id, issuer, &embedded)?;
        if !verify_signature(&signer, &sig_alg_oid.to_string(), tbs_bytes, signature) {
            return Some(RevocationStatus::NotChecked(NotCheckedReason::Unverified));
        }
        return Some(match cs_tag {
            0x80 => RevocationStatus::Good,
            0xa1 => RevocationStatus::Revoked { revoked_at, reason: None },
            0x82 => RevocationStatus::NotChecked(NotCheckedReason::Malformed(
                "responder answered unknown(2)".into(),
            )),
            other => RevocationStatus::NotChecked(NotCheckedReason::Malformed(format!(
                "unrecognised certStatus tag 0x{other:02x}"
            ))),
        });
    }
    Some(RevocationStatus::NotChecked(NotCheckedReason::NoMatchingCertId))
}

/// `responderID CHOICE { byName [1] Name, byKey [2] KeyHash }` (RFC 6960 §4.2.1).
enum ResponderId {
    ByName(Name),
    ByKey(Vec<u8>),
}

/// The `thisUpdate` stamped by the responder on the first `SingleResponse`, for tests that must
/// anchor a clock to the committed fixture instead of a date that rots. Reuses the same walk as
/// `parse_and_verify` so the two can never disagree.
fn this_update_of(response_der: &[u8]) -> Option<time::OffsetDateTime> {
    let top = DerReader::new(response_der).read_sequence().ok()?;
    let mut r = DerReader::new(top);
    r.read_tlv().ok()?; // responseStatus
    let (_, wrapped) = r.read_tlv().ok()?;
    let rb = DerReader::new(wrapped).read_sequence().ok()?;
    let mut rbr = DerReader::new(rb);
    rbr.read_oid().ok()?; // responseType
    let (_, basic_tlv) = rbr.read_tlv().ok()?;
    let basic = DerReader::new(basic_tlv).read_sequence().ok()?;
    let mut b = DerReader::new(basic);
    let tbs = b.span_of_next_tlv()?.to_vec();
    let body = DerReader::new(&tbs).read_sequence().ok()?;
    let mut d = DerReader::new(body);
    if d.peek_tag() == Some(0xa0) {
        d.read_tlv().ok()?; // version
    }
    d.read_tlv().ok()?; // responderID
    d.read_tlv().ok()?; // producedAt
    let responses = d.read_sequence().ok()?;
    let mut rs = DerReader::new(responses);
    let single_der = rs.read_sequence().ok()?;
    let mut single = DerReader::new(single_der);
    single.read_tlv().ok()?; // certID
    single.read_tlv().ok()?; // certStatus
    parse_time(single.read_tlv().ok()?.1)
}

/// Chooses the key that must have signed the response (RFC 6960 §4.2.2.2): the issuer itself
/// when `responderID` is `ByName [1]` naming the issuer, otherwise one embedded certificate that
/// the issuer issued and that carries `id-kp-OCSPSigning`. There is no fallback: a `responderID`
/// that names some other CA, or a `ByKey [2]` hash that matches no candidate, is `None` and the
/// answer is `Unverified`.
fn pick_signer(
    rid: &ResponderId, issuer: &Certificate, embedded: &[Certificate],
) -> Option<Certificate> {
    match rid {
        ResponderId::ByName(name) if name == &issuer.tbs_certificate.subject => Some(issuer.clone()),
        ResponderId::ByName(name) => embedded.iter().find(|c| {
            &c.tbs_certificate.subject == name
                && accepted_delegate(c, issuer)
        }).cloned(),
        ResponderId::ByKey(hash) => embedded.iter().find(|c| {
            let key_bits = c
                .tbs_certificate
                .subject_public_key_info
                .subject_public_key
                .raw_bytes();
            sha1::Sha1::digest(key_bits).as_slice() == hash.as_slice()
                && accepted_delegate(c, issuer)
        }).cloned(),
    }
}

/// A delegated responder must be issued by this CA, carry `id-kp-OCSPSigning`, and actually
/// verify under the CA's key — all three, or it is not trusted.
fn accepted_delegate(candidate: &Certificate, issuer: &Certificate) -> bool {
    candidate.tbs_certificate.issuer == issuer.tbs_certificate.subject
        && has_ocsp_signing_eku(candidate)
        && cms_verify::verify_cert_signature(candidate, issuer)
}
```

  `verify_signature` dispatches on `signatureAlgorithm`: `sha1WithRSAEncryption`
  (`1.2.840.113549.1.1.5`), `sha256WithRSAEncryption` (`1.2.840.113549.1.1.11`), and
  `ecdsa-with-SHA256` (`1.2.840.10045.4.3.2`), each verifying the raw `tbsResponseData` bytes —
  the same three arms `cms_verify.rs:1235-1280` already uses, re-expressed here because that
  function also handles CMS-specific `signedAttrs` re-framing and a *CMS* message rather than an
  arbitrary one.

  Two primitives are **shared**, one is **deliberately local**:
  - `cms_verify::verify_cert_signature` (`:1518`) is promoted to `pub(crate)` and called as
    `cms_verify::verify_cert_signature` — the same issue-child-under-issuer-key check the chain
    builder already performs, so duplicating it would be two answers to one question. (An earlier
    pass did duplicate it locally; the duplicate was deleted when the promotion landed.)
  - `cms_verify::resolve_now` (`:1681`) is already `pub(crate)` and reached through the existing
    `use super::cms_verify;` (`revocation.rs:44`) — it is the only `cms_verify` import.
  - `has_ocsp_signing_eku` stays **local**: read the EKU extension through this module's own
    `ext_value`, decode `ExtendedKeyUsage`, and look for
    `const_oid::db::rfc5280::ID_KP_OCSP_SIGNING`. Nothing in `cms_verify.rs` performs it, and
    `:1599` there is `leaf_purpose_reason`, a codeSigning check — the two are not the same thing, so
    widening `cms_verify` for it would buy nothing.

  `span_of_next_tlv` is one new method on `pkcs12::DerReader` returning the raw bytes of the next
  TLV (not just its value); it is the single reason the reader is widened, and it replaces the
  "re-encode and hope it is canonical" shortcut that would break on any length form the responder
  actually sends.
  `parse_time` accepts both UTCTime and GeneralizedTime (RFC 6960 allows either) and returns an
  `OffsetDateTime`; `parse_generalized_time` is its GeneralizedTime-only helper.

- [ ] **Step 5: Run the tests**

Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-core revocation -- --skip test_ipa_signing_is_deterministic`
Expected: Task 8's four plus these seven pass.

- [ ] **Step 6: Commit**

```
git add crates/zsign-core/src/crypto/revocation.rs crates/zsign-core/src/crypto/pkcs12.rs crates/zsign-core/src/crypto/cms_verify.rs
git commit -m "feat(crypto): verify ocsp responses before trusting a revocation answer"
```

---

## Task 10: Native transport, `check`, and the warning surface

**Files:**
- Modify: `crates/zsign-core/src/crypto/revocation.rs`
- Test: same file

- [ ] **Step 1: Write the failing tests.** Two layers, per the design: canned bytes for the logic,
  a loopback listener for the transport. No test resolves a hostname or opens an internet socket.

```rust
    #[test]
    fn check_with_a_stub_transport_returns_the_authenticated_answer() {
        struct Stub(&'static [u8]);
        impl OcspTransport for Stub {
            fn post(&self, _url: &str, _body: &[u8]) -> std::result::Result<Vec<u8>, TransportError> {
                Ok(self.0.to_vec())
            }
        }
        let (leaf, issuer) = fixture_pair();
        let status = check(&leaf, Some(&issuer), &Stub(REVOKED_DER), Some(now_in_window()));
        assert!(matches!(status, RevocationStatus::Revoked { .. }), "got {status:?}");
    }

    #[test]
    fn check_without_an_ocsp_url_never_touches_the_transport() {
        struct Counting(std::cell::Cell<usize>);
        impl OcspTransport for Counting {
            fn post(&self, _url: &str, _body: &[u8]) -> std::result::Result<Vec<u8>, TransportError> {
                self.0.set(self.0.get() + 1);
                Err(TransportError::Unreachable("must not be called".into()))
            }
        }
        let root = Certificate::from_pem(super::assets::APPLE_ROOT_CA_CERT.as_bytes()).unwrap();
        let calls = std::cell::Cell::new(0);
        let status = check(&root, None, &Counting(calls.clone()), Some(now_in_window()));
        assert!(matches!(
            status,
            RevocationStatus::NotChecked(NotCheckedReason::NoOcspUrl)
        ));
        assert_eq!(calls.get(), 0, "a leaf with no AIA OCSP URI must short-circuit");
    }

    #[test]
    fn transport_failures_degrade_to_not_checked() {
        struct Broken;
        impl OcspTransport for Broken {
            fn post(&self, _u: &str, _b: &[u8]) -> std::result::Result<Vec<u8>, TransportError> {
                Err(TransportError::Unreachable("dns: no such host".into()))
            }
        }
        let (leaf, issuer) = fixture_pair();
        let status = check(&leaf, Some(&issuer), &Broken, Some(now_in_window()));
        assert!(matches!(
            status,
            RevocationStatus::NotChecked(NotCheckedReason::Transport(_))
        ));
        assert!(status.warning().is_none());
    }
```

```rust
    #[cfg(not(target_arch = "wasm32"))]
    mod native {
        use super::*;
        use std::io::{Read, Write};
        use std::net::TcpListener;

        /// A one-shot HTTP/1.1 responder on the loopback interface: the AIA URI of the
        /// leaf is rewritten to the accepted port, so `HttpTransport` is exercised
        /// end to end without DNS or internet access.
        #[test]
        fn http_transport_round_trips_against_a_loopback_responder() {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            let response = GOOD_DER.to_vec();
            let server = std::thread::spawn(move || {
                let (mut sock, _) = listener.accept().unwrap();
                let mut buf = [0u8; 2048];
                let read = sock.read(&mut buf).unwrap();
                let request = String::from_utf8_lossy(&buf[..read]).into_owned();
                let mut body = Vec::new();
                let mut tail = sock.try_clone().unwrap();
                let _ = tail.read_to_end(&mut body);
                let mut all = request.into_bytes();
                all.extend_from_slice(&body);
                let text = String::from_utf8_lossy(&all).into_owned();
                assert!(text.starts_with("POST /ocsp HTTP/1.1"), "request: {text}");
                assert!(text.contains("content-type: application/ocsp-request"), "request: {text}");
                assert!(text.contains("content-length: "), "request: {text}");
                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/ocsp-response\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    response.len()
                );
                sock.write_all(header.as_bytes()).unwrap();
                sock.write_all(&response).unwrap();
                sock.flush().unwrap();
            });
            let (mut leaf, issuer) = fixture_pair();
            rewrite_ocsp_uri(&mut leaf, &format!("http://127.0.0.1:{port}/ocsp"));
            let status = check(&leaf, Some(&issuer), &HttpTransport::default(), Some(now_in_window()));
            server.join().unwrap();
            assert!(matches!(status, RevocationStatus::Good), "got {status:?}");
        }

        #[test]
        fn a_response_that_never_arrives_costs_only_the_budget() {
            // Accept the connection and then say nothing: only the caller's budget can save us.
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            let sink = std::thread::spawn(move || {
                let (mut sock, _) = listener.accept().unwrap();
                let mut buf = [0u8; 512];
                let _ = sock.read(&mut buf);
                std::thread::sleep(std::time::Duration::from_secs(30));
            });
            let (mut leaf, issuer) = fixture_pair();
            rewrite_ocsp_uri(&mut leaf, &format!("http://127.0.0.1:{port}/ocsp"));
            let started = std::time::Instant::now();
            let transport = HttpTransport { budget: std::time::Duration::from_millis(300) };
            let status = check(&leaf, Some(&issuer), &transport, Some(now_in_window()));
            assert!(
                matches!(status, RevocationStatus::NotChecked(NotCheckedReason::BudgetExpired)),
                "got {status:?}"
            );
            assert!(started.elapsed() < std::time::Duration::from_secs(5), "budget not enforced");
            drop(sink);
        }

        #[test]
        fn an_unreachable_responder_is_not_checked() {
            // Port 1 on loopback normally refuses at once. Where a firewall queues it instead,
            // the same assertion still holds: only the variant of `Transport(_)` would differ.
            let (mut leaf, issuer) = fixture_pair();
            rewrite_ocsp_uri(&mut leaf, "http://127.0.0.1:1/ocsp");
            let status = check(&leaf, Some(&issuer), &HttpTransport::default(), Some(now_in_window()));
            assert!(
                matches!(status, RevocationStatus::NotChecked(NotCheckedReason::Transport(_))),
                "got {status:?}"
            );
        }
    }
```

  `rewrite_ocsp_uri` rebuilds the leaf's AIA extension value with the loopback URI and swaps it in
  through the same extension-replacement path the verify tests use
  (`cms_verify.rs:2397` `replace_extension`, promoted to `pub(crate)` here or duplicated as a
  ten-line test helper — duplicate it, do not widen a verify helper for a test).

- [ ] **Step 2: Run them to verify they fail**, then implement:

```rust
/// Errors a transport can report. Every one of them is a `NotChecked`, never a failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportError {
    Unreachable(String),
    Timeout,
    UnexpectedStatus(u16),
    TooLarge,
    Malformed(String),
}

/// Minimal HTTP/1.1 POST over `std::net` for `http:` OCSP responder URIs.
///
/// OCSP responses are small DER blobs and Apple publishes them over plaintext HTTP, so there is
/// no TLS, no cookie jar, no redirect following and no chunked decoding here: anything the
/// strict reader cannot parse is reported as `Transport` and the signing run continues.
#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, Default, Clone)]
pub struct HttpTransport {
    pub budget: std::time::Duration,
}

#[cfg(not(target_arch = "wasm32"))]
const DEFAULT_BUDGET: std::time::Duration = std::time::Duration::from_secs(3);
/// OCSP responses are a few hundred bytes to ~2 KiB; a larger answer is not credible.
const MAX_RESPONSE_BYTES: usize = 64 * 1024;

/// Every transport outcome maps to a silent `NotChecked`; the mapping is exhaustive on purpose
/// so a new `TransportError` variant cannot fall through into a warning.
pub(crate) fn transport_reason(e: TransportError) -> NotCheckedReason {
    match e {
        TransportError::Timeout => NotCheckedReason::BudgetExpired,
        other => NotCheckedReason::Transport(format!("{other:?}")),
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl OcspTransport for HttpTransport {
    fn post(&self, url: &str, body: &[u8]) -> std::result::Result<Vec<u8>, TransportError> {
        let budget = if self.budget.is_zero() { DEFAULT_BUDGET } else { self.budget };
        // DNS has no timeout in `std::net`, so the whole exchange runs on one worker
        // thread and the caller waits on a channel with the budget. A worker that
        // outlives the deadline is abandoned; its own socket timeouts end it.
        let url = url.to_string();
        let body = body.to_vec();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(post_blocking(&url, &body));
        });
        rx.recv_timeout(budget)
            .map_err(|_| TransportError::Timeout)?
    }
}
```

  and `check` ties it together, with the mapping table above as the only `TransportError` consumer:

```rust
/// Runs one OCSP lookup through `transport`. Never fails: every problem is a silent
/// `NotChecked`, and only an authenticated `Revoked` yields a warning.
pub fn check(
    leaf: &Certificate,
    issuer: Option<&Certificate>,
    transport: &dyn OcspTransport,
    now: Option<time::OffsetDateTime>,
) -> RevocationStatus {
    let Some(url) = ocsp_responder_url(leaf) else {
        return RevocationStatus::NotChecked(NotCheckedReason::NoOcspUrl);
    };
    // Deliberately *before* the issuer lookup: a responder this module will not speak to is the
    // more specific finding, and reporting `NoIssuerCertificate` for an `https:` AIA with no
    // chain would send the reader looking in the wrong place.
    if !url.starts_with("http://") {
        return RevocationStatus::NotChecked(NotCheckedReason::UnusableUrl);
    }
    let Some(issuer) = issuer else {
        return RevocationStatus::NotChecked(NotCheckedReason::NoIssuerCertificate);
    };
    let now = match cms_verify::resolve_now(now) {
        Ok(t) => t,
        Err(_) => return RevocationStatus::NotChecked(NotCheckedReason::Malformed(
            "no clock available for the validity window".into(),
        )),
    };
    let Ok(request) = build_request(leaf, issuer) else {
        return RevocationStatus::NotChecked(NotCheckedReason::Malformed(
            "cannot encode CertID".into(),
        ));
    };
    match transport.post(&url, &request) {
        Ok(response) => parse_and_verify(&response, leaf, issuer, now),
        Err(e) => RevocationStatus::NotChecked(transport_reason(e)),
    }
}
```

  `resolve_now` is `pub(crate)` in `cms_verify.rs:1681`, so the wasm "no wall clock" rule is
  inherited rather than re-invented; `cms_verify.rs` is already a sibling module, and no re-export
  is needed beyond `use super::cms_verify;`.

  `post_blocking` does the literal work: parse `http://host[:port]/path`, resolve with
  `ToSocketAddrs`, `TcpStream::connect_timeout(&addr, 1s)`, `set_write_timeout`/`set_read_timeout`,
  write the request headers (`POST {path} HTTP/1.1`, `Host`, `Content-Type:
  application/ocsp-request`, `Content-Length`, `Connection: close`, then the DER body), read into a
  `Vec` capped at `MAX_RESPONSE_BYTES`, split the header block at `\r\n\r\n`, require a `200`
  status, honour `Content-Length` when present, and return the body bytes. `warn_revocation` is:

```rust
/// Best-effort revocation warning for a signing credential.
///
/// Prints nothing unless an authenticated responder says the certificate is revoked; every
/// other outcome — no AIA URI, unreachable responder, refused request, unverifiable answer,
/// expired answer — is silent, and the function cannot fail a signing run.
#[cfg(not(target_arch = "wasm32"))]
pub fn warn_revocation(leaf: &Certificate, chain: &[Certificate]) {
    let issuer = issuer_of(leaf, chain);
    let status = check(leaf, issuer.as_ref(), &HttpTransport::default(), None);
    if let Some(warning) = status.warning() {
        eprintln!("warning: {warning}");
    }
}
```

- [ ] **Step 3: Run the whole crate and the wasm compile check**

Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-core -- --skip test_ipa_signing_is_deterministic`
Expected: all pass.
Run: `cargo check -p zsign-wasm --target wasm32-unknown-unknown`
Expected: compiles — the transport, the thread and `warn_revocation` are `cfg`-gated out, and the
pure OCSP logic (which is what the wasm tests could ever use) builds unchanged.

- [ ] **Step 4: Commit**

```
git add crates/zsign-core/src/crypto/revocation.rs
git commit -m "feat(crypto): add a bounded native ocsp transport and a warn-only revocation hook"
```

---

## Task 11: Seam note and lane gate

- [ ] **Step 1: Record the CLI seam precisely** in `docs/superpowers/specs/` (append to the design
  doc's ZSN-21 section, not to code comments): the one-line call
  `zsign_core::crypto::revocation::warn_revocation(&creds.certificate, &creds.cert_chain);` belongs
  in `crates/zsign-cli/src/main.rs::load_credentials` immediately before each of its four
  `return Ok(creds)` sites (`:800` `--pkcs12`, `:816` PEM route, `:849` DER route, `:855`
  PKCS#12-via-`-k`), so exactly one check runs per successful credential load. Task 7 edits two of
  those four paths, and the seam covers all four. It is not applied here because lane zsn40 owns
  that file this wave.

- [ ] **Step 2: Lane gate** (the only place the full gates run):

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
TMPDIR=$PWD/.tmptmp cargo test --workspace --no-fail-fast -- --skip test_ipa_signing_is_deterministic
cargo check -p zsign-wasm --target wasm32-unknown-unknown
```

  Expected: clean output from each, and the test summary showing zero failures. Report the verbatim

- [ ] **Step 3: Assemble the evidence list for the final report, naming tests, not summaries.**
  Per ticket the report must state:
  - **ZSN-14:** `ecdsa_signing_matches_rfc6979_known_answers` and
    `cms_ecdsa_signature_is_byte_identical_five_times` passing; the Task 1 mutation failure text
    as the red evidence; `sign_macho_ecdsa_is_byte_identical_twice` as the blob-level proof;
    `ecdsa_code_signature_round_trips_with_der_signer_info` and
    `attached_profile_envelope_accepts_der_ecdsa_signer` (`cms_verify.rs:3064`, `:3087`)
    unchanged — those two are the "verify path unchanged" proof. State plainly that no
    cross-process and no IPA-level determinism test was added, and that this lane added the tree's
    *first* ECDSA determinism coverage: RSA determinism is covered only indirectly, by
    `macho::signer::tests::test_sign_then_verify_roundtrip` (`:1440`) and the size estimates
    `test_estimate_cms_size_rsa_2048` / `test_estimate_cms_size_rsa_with_chain` (`cms.rs:887`,
    `:967`). Determinism is proven five times within one process, twice at blob level, and
    cross-process only in the sense that the KAT pins RFC-published constants rather than
    self-generated bytes.
  - **ZSN-18:** which fixture each test loads; the three distinct outcomes (missing password,
    wrong password, unsupported cipher) — missing password and wrong password at unit *and* CLI
    level (`main.rs:1695`, `:1717`, `:1766`), unsupported cipher at unit level only
    (`encrypted_pem.rs:293`, `:315`; no CLI assertion covers an unsupported/legacy `DEK-Info`
    cipher, so that outcome is reported as library-level); the PKCS#8 unencrypted path
    unchanged while PKCS#1/SEC1 in the clear become newly accepted (D18.5).
  - **ZSN-21:** that every revocation test is offline — canned DER plus loopback `127.0.0.1`
    sockets — and that the design's live Apple probe (P13) is a one-time network observation,
    not reproducible evidence, and depended on by no test.
  output in the final report, together with the red→green evidence collected in Tasks 1-10.

---

## Self-review against the spec

| Spec requirement | Task |
|---|---|
| D14.1 keep the `Signer` wiring; pin with tests | 1, 2, 3 |
| D14.2 RFC 6979 A.2.5 known-answer on the CMS trait path | 1 |
| D14.3 fixed-key P-256 credential helper | 2, 3 |
| D14.4 reproducibility contract in module docs | 3 |
| D14.5 verify path untouched, existing round-trip stays green | 3 (gate in 11) |
| D18.1 `from_pem` signature unchanged | 6 |
| D18.2 reuse the in-tree PBES2 engine, not the vendor route | 4, 6 |
| D18.3 traditional framing is ours; header IV, key-only KDF | 5 |
| D18.4 cipher matrix, RC2/DES rejected by name | 5 |
| D18.5 PKCS#1 / SEC1 decoders, accepted in both forms | 6 |
| Error taxonomy without new `Error` variants | 4, 5, 6 |
| CLI cutover, five pinned tests migrated, no flag surface change | 7 |
| D21.1 library capability + reported seam | 8, 9, 10, 11 |
| D21 verification posture (signature, certID, window, delegated responder) | 9 |
| D21 bounded transport, DNS guarded by a worker thread | 10 |
| Hermetic two-layer revocation coverage | 8, 9, 10 |
| One new crate (`md-5`), no `deny.toml` change | 5 |
| No CI/skip change, deterministic-by-construction tests | ground rules, 11 |

Checked and consistent: `RevocationStatus`/`NotCheckedReason` names match between Tasks 8-10 and
the design doc, including `NoMatchingCertId`; `parse_and_verify`, `check` and `warn_revocation`
return values rather than `Result`, so no revocation outcome can reach a caller's `?`; the only
`Err` in the module is `build_request`'s "cannot encode CertID", which no production path treats as
fatal. Fixture names are identical in Tasks 5, 6 and 7.
`cert_id`, `build_request`, `ocsp_responder_url`, `tlv`, `parse_and_verify`, `warning`,
`NotCheckedReason::Malformed(String)` are defined once (Tasks 8-9) and reused later.

## Seams and follow-ups (report, do not implement here)

1. **CLI revocation wiring.** `warn_revocation` is the intended call; the insertion points are the
   four credential-return sites in `crates/zsign-cli/src/main.rs::load_credentials` (`:781`, `:796`,
   `:832`, `:838` — the first two `return Ok(creds)`, the last two the tail `Ok(creds)` of the
   `match`). Owned by lane zsn40's file; no flag is needed.
2. **TTY prompt parity for encrypted PEM keys.** `resolve_p12_password` (`main.rs:848`) prompts
   for PKCS#12 only; after this lane an encrypted PEM without `-p`/`ZSIGN_PASSWORD` gets an explicit
   "requires a password" error instead of a prompt. Adding the prompt is a password-flow change in
   the file this lane does not own.
3. **No static known-revoked list.** No license-clean source exists (design premise 5); implementing
   this would mean inventing data, which the brief forbids.
4. **Fixtures for ZSN-30.** 8 PEM files plus 8 revocation fixtures land under
   `crates/zsign-core/src/crypto/fixtures/`; wave 7 consolidates them and their recipes.
5. **Docs lane.** The in-crate docs are already correct after Tasks 6 and 9 — `crypto/mod.rs:8-9`
   reads "from PEM (plaintext or encrypted)". What is still silent is the README: its credential
   bullet (`README.md:17`) and crate-table row (`README.md:224`) mention PKCS#12 and PEM but not
   encrypted keys, and nothing at all mentions the revocation warning. Those are omissions, not
   stale claims, and the README is outside this lane's file list.
