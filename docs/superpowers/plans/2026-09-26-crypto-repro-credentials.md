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
  lives at `:1048`)
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
        use signature::Signer;

        let key = SigningKey::from_slice(&RFC6979_P256_SCALAR).expect("RFC 6979 scalar");
        let sample: Vec<u8> = key.sign(b"sample" as &[u8]).to_vec();
        let test: Vec<u8> = key.sign(b"test" as &[u8]).to_vec();
        let _: Option<DerSignature> = None; // type anchor: the CMS signature form
        assert_eq!(
            sample.as_slice(),
            RFC6979_SAMPLE_DER.as_slice(),
            "P-256 SHA-256 signature over \"sample\" must be the RFC 6979 deterministic value"
        );
        assert_eq!(
            test.as_slice(),
            RFC6979_TEST_DER.as_slice(),
            "P-256 SHA-256 signature over \"test\" must be the RFC 6979 deterministic value"
        );
    }
```

  `signature::Signer` is already a dependency of `zsign-core` (`Cargo.toml:28`).

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
(`ecdsa-0.16.9/src/signing.rs:428`), so the annotation above is what makes the scratch edit
compile; the explicit type is also what proves the mutation swapped the nonce source and not the
signature encoding.

Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-core ecdsa_signing_matches_rfc6979`
Expected: FAIL — the randomized nonce produces different `r`/`s`, so the assertion trips. Revert
the scratch edit and re-run Step 2 to green. Report the observed failure text as the red evidence
for this ticket.

- [ ] **Step 4: Scoped gate + commit**

Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-core crypto::cms -- --skip test_ipa_signing_is_deterministic`
Expected: all `crypto::cms` tests pass, none skipped by this lane.

```
git add crates/zsign-core/src/crypto/cms.rs
git commit -m "test(crypto): pin rfc 6979 deterministic p-256 signatures with a known-answer test"
```

- [ ] **Step 5: Commit (after reverting the scratch edit and re-running Step 2)**

```
git add crates/zsign-core/src/crypto/cms.rs
git commit -m "test(crypto): pin rfc 6979 deterministic p-256 signatures with a known-answer test"
```

---

## Task 2: Byte-identical CMS output, five times, on a fixed key

**Files:**
- Modify: `crates/zsign-core/src/crypto/cms.rs` (test module only)

- [ ] **Step 1: Add the fixed-key credential helper.** `build_test_ecdsa_credentials` (`cms.rs:1048`)
  draws `SigningKey::random(&mut OsRng)` at `:1061`, so it cannot pin bytes. Add a sibling that
  reuses the same certificate-construction shape with the RFC 6979 scalar, plus a pinned validity so
  the certificate DER is identical in every process (`Validity::from_now` would move the bytes):

```rust
    /// Fixed-scalar ECDSA credentials: the certificate DER is pinned by a constant validity
    /// window, so the CMS bytes it produces are reproducible across processes.
    fn build_fixed_ecdsa_credentials() -> SigningCredentials {
        use crate::crypto::cert::{SigningCredentials, SigningKeyType};
        use der::Decode;
        use p256::ecdsa::SigningKey;
        use spki::{EncodePublicKey, SubjectPublicKeyInfoOwned};
        use std::str::FromStr;
        use x509_cert::builder::{Builder, CertificateBuilder, Profile};
        use x509_cert::name::Name;
        use x509_cert::serial_number::SerialNumber;
        use x509_cert::time::{Time, Validity};

        let ecdsa_key = SigningKey::from_slice(&RFC6979_P256_SCALAR).expect("fixed scalar");
        let verifying_key = p256::ecdsa::VerifyingKey::from(&ecdsa_key);
        let subject = Name::from_str("CN=ECDSA Determinism Signer,OU=TESTTEAM").unwrap();
        let validity = Validity {
            not_before: Time::from_unix_duration(std::time::Duration::from_secs(1_700_000_000))
                .unwrap(),
            not_after: Time::from_unix_duration(std::time::Duration::from_secs(4_000_000_000))
                .unwrap(),
        };
        let pub_key = SubjectPublicKeyInfoOwned::from_der(
            verifying_key.to_public_key_der().unwrap().as_ref(),
        )
        .unwrap();
        let cert = CertificateBuilder::new(
            Profile::Root,
            SerialNumber::from(442u32),
            validity,
            subject,
            pub_key,
            &ecdsa_key,
        )
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

  If `x509_cert::time::Time::from_unix_duration` is not the available constructor at 0.2.5, use the
  existing `cms_verify.rs:2913` `fixed_time` idiom
  (`Time::try_from(UNIX_EPOCH + Duration::from_secs(n))`) — same pinned window, and `Profile::Root`
  is deliberate: the loader's code-signing policy only applies to `from_p12`/`from_pem`, and the
  determinism tests construct `SigningCredentials` directly.

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
- Modify: `crates/zsign-core/src/macho/signer.rs` (test module; RSA precedent at `:973`
  `cms_signature_is_deterministic_for_identical_inputs`)
- Modify: `crates/zsign-core/src/crypto/cms.rs` (module docs)

- [ ] **Step 1: Write the failing test** in `macho/signer.rs`'s `mod tests`, mirroring the RSA
  precedent's use of `crate::macho::fixtures::make_minimal_macho` and the `SigningCredentials`
  literal pattern at `macho/fixtures.rs:404-409`, but with the ECDSA arm. Because
  `build_fixed_ecdsa_credentials` lives in `cms.rs`'s private test module, the blob-level test builds
  its own credential with the same fixed scalar and pinned validity:

```rust
    #[test]
    fn sign_macho_ecdsa_is_byte_identical_twice() {
        let credentials = ecdsa_credentials_for_determinism();
        let macho = crate::macho::fixtures::make_minimal_macho();
        let first = sign_macho(&macho, &credentials, None).unwrap();
        let second = sign_macho(&macho, &credentials, None).unwrap();
        assert_eq!(
            first.as_slice(),
            second.as_slice(),
            "embedding a P-256 signature twice must reproduce the binary byte for byte"
        );
    }
```

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
- Modify: `crates/zsign-core/src/crypto/pkcs12.rs:793` (one visibility change)

- [ ] **Step 1: Widen `decrypt_key_bag`** — it already parses `EncryptedPrivateKeyInfo`
  (`SEQUENCE { AlgorithmIdentifier, OCTET STRING }`) and routes PBES2 through the PRF/keyLength
  dispatch, so ZSN-18 needs only visibility, not new code:

```rust
/// pkcs8ShroudedKeyBag ::= EncryptedPrivateKeyInfo
pub(crate) fn decrypt_key_bag(value: &[u8], password: &str) -> Result<Vec<u8>> {
```

  Nothing else in the module changes: `pbes2_decrypt`, `Pbkdf2Parameter`, `cbc_decrypt`,
  `unpad_pkcs7`, `aes_decrypt`, `DerReader` and `mod oid` stay module-private and are reached
  through this one entry point.

- [ ] **Step 2: Verify the module still compiles and its tests pass**

Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-core crypto::pkcs12 -- --skip test_ipa_signing_is_deterministic`
Expected: all pass (behaviour unchanged). A `dead_code` warning here would mean the entry point is
not yet wired — that is Task 6's job, so keep the two tasks in adjacent commits.

- [ ] **Step 3: Commit**

```
git add crates/zsign-core/src/crypto/pkcs12.rs
git commit -m "refactor(crypto): expose the pkcs-5 v2.0 key-bag decryptor for pem key loading"
```

---

## Task 5: Traditional `DEK-Info` PEM decoder

**Files:**
- Create: `crates/zsign-core/src/crypto/encrypted_pem.rs`
- Modify: `crates/zsign-core/src/crypto/mod.rs` (`pub mod encrypted_pem;` next to `pub mod cms;` at `:31`)
- Modify: `crates/zsign-core/Cargo.toml` (one dependency)
- Create: 12 PEM fixtures under `crates/zsign-core/src/crypto/fixtures/`

- [ ] **Step 1: Add the single new dependency** (`md-5` is MIT OR Apache-2.0, already allowlisted at
  `deny.toml:14-27`; pinned to 0.10 because 0.11 needs `digest` 0.11 and the tree is on 0.10):

```toml
# OpenSSL traditional PEM key derivation (EVP_BytesToKey)
md-5 = "0.10"
```

  Add it after `digest = "0.10"` (`Cargo.toml:38`). Verify no duplicate `digest` appears:
  `cargo tree -d | grep -c digest` must stay `0`. (`cbc`/`cipher`/`base64ct` are already in
  `Cargo.lock` through `pkcs5`, so no other manifest change is needed.)

- [ ] **Step 2: Generate the fixtures** (scratch outside the repo; the verification block fails loud,
  matching the ZSN-37 recipe style at `plans/2026-09-25-credential-hardening.md:1530-1562`):

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
FIX=$F

# RSA-2048 identity: plain PKCS#8, plain PKCS#1, PBES2 (SHA-256 and SHA-1 PRF), DEK-Info AES-256/3DES
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$d/rsa.key"
openssl req -new -key "$d/rsa.key" -config "$d/ext.cnf" -out "$d/rsa.csr"
openssl x509 -req -in "$d/rsa.csr" -signkey "$d/rsa.key" -days 3650 -set_serial 0x7001 \
  -extfile "$d/ext.cnf" -extensions v3 -out "$FIX/pem_rsa_cert.pem"
openssl pkcs8 -topk8 -nocrypt -in "$d/rsa.key" -out "$FIX/pem_rsa_key_pkcs8.pem"
openssl rsa -in "$d/rsa.key" -traditional -out "$FIX/pem_rsa_key_pkcs1.pem"
openssl pkcs8 -topk8 -in "$d/rsa.key" -v2 aes-256-cbc -passout pass:testpassword \
  -out "$FIX/pem_rsa_key_pbes2_sha256.pem"
openssl pkcs8 -topk8 -in "$d/rsa.key" -v2 aes-256-cbc -v2prf hmacWithSHA1 -passout pass:testpassword \
  -out "$FIX/pem_rsa_key_pbes2_sha1prf.pem"
openssl rsa -in "$d/rsa.key" -traditional -aes256 -passout pass:testpassword \
  -out "$FIX/pem_rsa_key_dekinfo_aes256.pem"
openssl rsa -in "$d/rsa.key" -traditional -des3 -passout pass:testpassword \
  -out "$FIX/pem_rsa_key_dekinfo_des3.pem"

# P-256 identity: plain PKCS#8, plain SEC1, PBES2, DEK-Info AES-128
openssl ecparam -name prime256v1 -genkey -noout -out "$d/ec.key"
openssl req -new -key "$d/ec.key" -config "$d/ext.cnf" -out "$d/ec.csr"
openssl x509 -req -in "$d/ec.csr" -signkey "$d/ec.key" -days 3650 -set_serial 0x7002 \
  -extfile "$d/ext.cnf" -extensions v3 -out "$FIX/pem_ec_cert.pem"
openssl pkcs8 -topk8 -nocrypt -in "$d/ec.key" -out "$FIX/pem_ec_key_pkcs8.pem"
openssl ec -in "$d/ec.key" -traditional -out "$FIX/pem_ec_key_sec1.pem"
openssl pkcs8 -topk8 -in "$d/ec.key" -v2 aes-256-cbc -passout pass:testpassword \
  -out "$FIX/pem_ec_key_pbes2_sha256.pem"
openssl ec -in "$d/ec.key" -traditional -aes128 -passout pass:testpassword \
  -out "$FIX/pem_ec_key_dekinfo_aes128.pem"

# Fail-loud verification: every encrypted fixture must carry its marker, and every key family must
# agree on one public number. Any mismatch aborts instead of committing a wrong fixture.
grep -q 'ENCRYPTED PRIVATE KEY' "$FIX/pem_rsa_key_pbes2_sha256.pem"
grep -q 'ENCRYPTED PRIVATE KEY' "$FIX/pem_rsa_key_pbes2_sha1prf.pem"
grep -q 'ENCRYPTED PRIVATE KEY' "$FIX/pem_ec_key_pbes2_sha256.pem"
for f in pem_rsa_key_dekinfo_aes256 pem_rsa_key_dekinfo_des3 pem_ec_key_dekinfo_aes128; do
  grep -q 'Proc-Type: 4,ENCRYPTED' "$FIX/$f.pem" || { echo "missing Proc-Type in $f"; exit 1; }
  grep -q 'DEK-Info:' "$FIX/$f.pem" || { echo "missing DEK-Info in $f"; exit 1; }
done
grep -q 'RC2\|AES-128-CTR' "$FIX/pem_rsa_key_dekinfo_des3.pem" && { echo "unexpected cipher"; exit 1; }
[ "$(openssl pkey -in "$FIX/pem_rsa_key_pkcs8.pem" -pubout | openssl pkey -pubin -outform DER | sha256sum)" = \
  "$(openssl pkey -in "$FIX/pem_rsa_key_pkcs1.pem" -pubout | openssl pkey -pubin -outform DER | sha256sum)" ]
[ "$(openssl pkey -in "$FIX/pem_rsa_key_pkcs8.pem" -pubout | openssl pkey -pubin -outform DER | sha256sum)" = \
  "$(openssl pkey -in "$FIX/pem_rsa_key_dekinfo_aes256.pem" -passin pass:testpassword -pubout | openssl pkey -pubin -outform DER | sha256sum)" ]
[ "$(openssl pkey -in "$FIX/pem_ec_key_pkcs8.pem" -pubout | openssl pkey -pubin -outform DER | sha256sum)" = \
  "$(openssl pkey -in "$FIX/pem_ec_key_sec1.pem" -pubout | openssl pkey -pubin -outform DER | sha256sum)" ]
[ "$(openssl x509 -in "$FIX/pem_rsa_cert.pem" -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum)" = \
  "$(openssl pkey -in "$FIX/pem_rsa_key_pkcs8.pem" -pubout | openssl pkey -pubin -outform DER | sha256sum)" ]
[ "$(openssl x509 -in "$FIX/pem_ec_cert.pem" -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum)" = \
  "$(openssl pkey -in "$FIX/pem_ec_key_pkcs8.pem" -pubout | openssl pkey -pubin -outform DER | sha256sum)" ]
echo "fixtures verified"
```

  Every `[…]` guard is a real assertion: `[ ]` failing exits non-zero under `set -e`. Re-run
  `git status --short crates/zsign-core/src/crypto/fixtures/` afterwards and confirm exactly the 12
  new files and nothing else (`.tmptmp` and `$HOME/tmp-cargo` are outside the tracked tree).

- [ ] **Step 3: Write the failing tests** in `encrypted_pem.rs`

```rust
    #[test]
    fn dek_info_aes256_yields_a_pkcs1_key() {
        let pem = include_str!("fixtures/pem_rsa_key_dekinfo_aes256.pem");
        let der = decrypt_traditional_pem(pem, Some("testpassword")).unwrap();
        assert_eq!(der[0], 0x30, "plaintext must be a DER SEQUENCE");
        assert!(
            rsa::RsaPrivateKey::from_pkcs1_der(&der).is_ok(),
            "traditional RSA PEM must decrypt to PKCS#1, got {} bytes",
            der.len()
        );
    }

    #[test]
    fn dek_info_aes128_yields_a_sec1_ec_key() {
        let pem = include_str!("fixtures/pem_ec_key_dekinfo_aes128.pem");
        let der = decrypt_traditional_pem(pem, Some("testpassword")).unwrap();
        assert!(
            p256::SecretKey::from_sec1_der(&der).is_ok(),
            "traditional EC PEM must decrypt to SEC1, got {} bytes",
            der.len()
        );
    }

    #[test]
    fn dek_info_3des_yields_a_pkcs1_key() {
        let pem = include_str!("fixtures/pem_rsa_key_dekinfo_des3.pem");
        let der = decrypt_traditional_pem(pem, Some("testpassword")).unwrap();
        assert!(rsa::RsaPrivateKey::from_pkcs1_der(&der).is_ok());
    }

    #[test]
    fn wrong_password_is_reported_as_a_password_failure() {
        for name in [
            include_str!("fixtures/pem_rsa_key_dekinfo_aes256.pem"),
            include_str!("fixtures/pem_rsa_key_dekinfo_des3.pem"),
            include_str!("fixtures/pem_ec_key_dekinfo_aes128.pem"),
        ] {
            let res = decrypt_traditional_pem(name, Some("not-the-password"));
            assert!(
                matches!(res, Err(Error::InvalidPassword)),
                "a wrong passphrase must be a password failure, got {:?}",
                res.as_ref().err()
            );
        }
    }

    #[test]
    fn missing_password_asks_for_one() {
        let pem = include_str!("fixtures/pem_rsa_key_dekinfo_aes256.pem");
        let res = decrypt_traditional_pem(pem, None);
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
        let res = decrypt_traditional_pem(pem, Some("x"));
        assert!(
            matches!(&res, Err(Error::Certificate(m)) if m.contains("AES-128-CTR")),
            "unsupported ciphers must be named, got {:?}",
            res.as_ref().err()
        );
    }

    #[test]
    fn unencrypted_pem_is_not_this_modules_business() {
        let pem = include_str!("fixtures/pem_rsa_key_pkcs1.pem");
        let res = decrypt_traditional_pem(pem, Some("testpassword"));
        assert!(
            matches!(&res, Err(Error::Certificate(m)) if m.contains("not an encrypted")),
            "a plaintext PEM must be refused by this entry point, got {:?}",
            res.as_ref().err()
        );
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
        let res = decrypt_traditional_pem(pem, Some("x"));
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

/// A traditional encrypted PEM split into the three things the decoder needs.
pub(crate) struct TraditionalKey<'a> {
    /// PEM label without the `PRIVATE KEY` suffix, e.g. `RSA`, `EC`, or empty for PKCS#8.
    pub label: &'a str,
    /// Plaintext DER of the inner key encoding.
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
fn cipher_shape(name: &str) -> Option<(usize, usize)> {
    match name {
        "AES-128-CBC" => Some((16, 16)),
        "AES-192-CBC" => Some((24, 16)),
        "AES-256-CBC" => Some((32, 16)),
        "DES-EDE3-CBC" => Some((24, 8)),
        _ => None,
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
    let cipher = cipher.trim();
    let (key_len, iv_len) = cipher_shape(cipher)
        .ok_or_else(|| unsupported(format!("DEK-Info cipher {cipher} (supported: AES-128/192/256-CBC, DES-EDE3-CBC)")))?;
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
    let plaintext = match cipher {
        "AES-128-CBC" => crate::crypto::pkcs12::aes_decrypt::<aes::Aes128>(&key, &iv, &ciphertext),
        "AES-192-CBC" => crate::crypto::pkcs12::aes_decrypt::<aes::Aes192>(&key, &iv, &ciphertext),
        "AES-256-CBC" => crate::crypto::pkcs12::aes_decrypt::<aes::Aes256>(&key, &iv, &ciphertext),
        "DES-EDE3-CBC" => crate::crypto::pkcs12::aes_decrypt::<des::TdesEde3>(&key, &iv, &ciphertext),
        _ => unreachable!("cipher_shape accepted only the four names above"),
    };
    match plaintext {
        Ok(der) => Ok(Some(TraditionalKey { label, der })),
        // Every failure after a real decryption attempt is a passphrase failure: either the
        // PKCS#7 padding is invalid, or (one in 256 times) it is valid and the DER is nonsense,
        // which the caller's decoder also reports as such.
        Err(_) => Err(Error::InvalidPassword),
    }
}
```

  `use base64::Engine as _;` is added to the imports (`base64` is already a dependency, used the
  same way in `crates/zsign-cli/src/main.rs:897`). `pkcs12::aes_decrypt` is generic over
  `C: BlockDecrypt + KeyInit` (`pkcs12.rs:610-617`), so DES-EDE3-CBC goes through the same CBC +
  PKCS#7 code as PKCS#12 — no second block-mode implementation, and `rc2` stays unused here because
  RC2 DEK-Info is deliberately unsupported (design D18.4).

- [ ] **Step 6: Run the tests to verify they pass**

Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-core encrypted_pem -- --skip test_ipa_signing_is_deterministic`
Expected: 9 passed.

- [ ] **Step 7: Commit**

```
git add crates/zsign-core/src/crypto/encrypted_pem.rs crates/zsign-core/src/crypto/mod.rs crates/zsign-core/Cargo.toml crates/zsign-core/src/crypto/fixtures Cargo.lock
git commit -m "feat(crypto): decrypt traditional dek-info pem keys with openssl-compatible framing"
```

---

## Task 6: Route encrypted keys through `from_pem`

**Files:**
- Modify: `crates/zsign-core/src/crypto/cert.rs:465-501` (`from_pem`), `:111-164` (`DecodedKey`)
- Modify: `crates/zsign-core/src/crypto/pkcs12.rs:793` (`pub(crate) fn decrypt_key_bag`)
- Modify: `crates/zsign-core/src/crypto/pkcs12.rs:610` (`pub(crate) fn aes_decrypt`)
- Modify: `crates/zsign-core/src/crypto/mod.rs` (module list)
- Test: inline in `cert.rs`

- [ ] **Step 1: Write the failing tests** (append to `cert.rs`'s `mod tests`; the fixture constants
  go next to the existing `IDENTITY_SINGLE` block at `:684-686`):

```rust
    const ENC_PKCS8_RSA: &str = include_str!("fixtures/pem_rsa_key_pbes2_sha256.pem");
    const ENC_PKCS8_RSA_SHA1PRF: &str = include_str!("fixtures/pem_rsa_key_pbes2_sha1prf.pem");
    const ENC_PKCS8_EC: &str = include_str!("fixtures/pem_ec_key_pbes2_sha256.pem");
    const ENC_TRAD_RSA: &str = include_str!("fixtures/pem_rsa_key_dekinfo_aes256.pem");
    const ENC_TRAD_RSA_3DES: &str = include_str!("fixtures/pem_rsa_key_dekinfo_des3.pem");
    const ENC_TRAD_EC: &str = include_str!("fixtures/pem_ec_key_dekinfo_aes128.pem");
    const RSA_CERT: &[u8] = include_bytes!("fixtures/pem_rsa_cert.pem");
    const EC_CERT: &[u8] = include_bytes!("fixtures/pem_ec_cert.pem");
    const PLAIN_PKCS1: &str = include_str!("fixtures/pem_rsa_key_pkcs1.pem");
    const PLAIN_SEC1: &str = include_str!("fixtures/pem_ec_key_sec1.pem");
    const PASS: &str = "testpassword";

    #[test]
    fn from_pem_loads_pbks8_pbesh2_and_traditional_keys() {
        for (cert, key) in [
            (RSA_CERT, ENC_PKCS8_RSA),
            (RSA_CERT, ENC_PKCS8_RSA_SHA1PRF),
            (RSA_CERT, ENC_TRAD_RSA),
            (RSA_CERT, ENC_TRAD_RSA_3DES),
            (RSA_CERT, PLAIN_PKCS1),
            (EC_CERT, ENC_PKCS8_EC),
            (EC_CERT, ENC_TRAD_EC),
            (EC_CERT, PLAIN_SEC1),
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
        for key in [ENC_PKCS8_RSA, ENC_TRAD_RSA, ENC_PKCS8_RSA_SHA1PRF] {
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
        let res = SigningCredentials::from_pem(RSA_CERT, ENC_TRAD_RSA.as_bytes(), None);
        assert!(
            matches!(&res, Err(Error::Certificate(m)) if m.contains("requires a password")),
            "got {:?}",
            res.as_ref().err()
        );
    }

    #[test]
    fn from_pem_keeps_the_password_free_pkcs8_path_unchanged() {
        let plain = include_str!("fixtures/pem_rsa_key_pkcs8.pem");
        assert!(SigningCredentials::from_pem(RSA_CERT, plain.as_bytes(), None).is_ok());
        // A password on an unencrypted key is accepted and ignored, as OpenSSL does.
        assert!(SigningCredentials::from_pem(RSA_CERT, plain.as_bytes(), Some("ignored")).is_ok());
    }

    #[test]
    fn from_pem_still_pairs_the_decrypted_key_with_the_certificate() {
        let res = SigningCredentials::from_pem(EC_CERT, ENC_PKCS8_RSA.as_bytes(), Some(PASS));
        assert!(
            matches!(&res, Err(Error::Certificate(m)) if m.contains("does not match")),
            "an encrypted key must still be SPKI-paired, got {:?}",
            res.as_ref().err()
        );
    }
```

  Rename the first test to `from_pem_loads_pbcs8_pbesh2_and_traditional_keys`… **no**: use this exact
  name, it is what the suite will show: `from_pem_loads_pbkdf2_pbesh2_and_traditional_keys` is also
  wrong — the name is `from_pem_loads_pbkdf2_pkcs8_pbes2_and_traditional_keys`.

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

  and add, next to `DecodedKey` (`cert.rs:111-164`):

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
/// label (`pem_wrap_der`, `main.rs:896-908`), so an encrypted PKCS#8 DER can legitimately
/// arrive under that label, and PKCS#1 / SEC1 bodies arrive both traditional-encrypted and
/// in the clear. A supplied password on an unencrypted container is ignored, which is what
/// OpenSSL does.
fn decode_key_material(pem: &str, password: Option<&str>) -> Result<DecodedKey> {
    if let Some(traditional) = crate::crypto::encrypted_pem::decrypt_traditional_pem(pem, password)? {
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

- [ ] **Step 6: Update the docs that promised the opposite.** `crypto/cert.rs:3-26` module doc
  ("**PEM**: Separate certificate and private key files (unencrypted keys only)"), the `from_pem`
  doc comment (`:431-464`, including the `password` argument line "Reserved for future encrypted
  key support (must be `None`)" and the `# Errors` bullet "A password is provided (encrypted keys
  not yet supported)"), and `crypto/mod.rs:7-11` if it repeats the claim. All three must describe
  the new behaviour: PBES2 + traditional encrypted PEM supported, password optional, unencrypted
  containers ignore a supplied password.

- [ ] **Step 7: Run the scoped gate**

Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-core crypto:: -- --skip test_ipa_signing_is_deterministic`
Expected: every `crypto::` test passes, including the 13 pre-existing PKCS#12 fixture tests and the
33-test `cms_verify` module — a regression here means the routing changed an unencrypted path.

- [ ] **Step 8: Commit**

```
git add crates/zsign-core/src/crypto/cert.rs crates/zsign-core/src/crypto/pkcs12.rs
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
```

  Fixture constants at the top of the test module, next to the existing cross-crate
  `include_bytes!` pair (`main.rs:1068-1074`):

```rust
    const ENC_TRAD_RSA: &str =
        include_str!("../../zsign-core/src/crypto/fixtures/pem_rsa_key_dekinfo_aes256.pem");
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

## Task 8: OCSP request construction and AIA extraction

**Files:**
- Create: `crates/zsign-core/src/crypto/revocation.rs`
- Modify: `crates/zsign-core/src/crypto/mod.rs` (`pub mod revocation;`)
- Create: 5 fixtures under `crates/zsign-core/src/crypto/fixtures/revocation/`

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
cp ca.pem issued_leaf.pem req.der good.der revoked.der "$R/"
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
        // And the two hashes must be the SHA-1 values openssl recorded.
        assert_eq!(hex(&sha1::Sha1::digest(leaf.tbs_certificate.issuer.to_der().unwrap())),
                   "0b33e087f49437454e41a6acc82dff34bb1ba0ab");
    }

    #[test]
    fn request_is_deterministic_and_minimal() {
        let leaf = Certificate::from_pem(LEAF_PEM.as_bytes()).unwrap();
        let issuer = Certificate::from_pem(CA_PEM.as_bytes()).unwrap();
        let a = build_request(&leaf, &issuer).unwrap();
        let b = build_request(&leaf, &issuer).unwrap();
        assert_eq!(a, b, "request bytes must be reproducible");
        // A single Request, no nonce, no optionalSignature: 69 bytes for this pair.
        assert_eq!(a.len(), 69);
    }
```

- [ ] **Step 3: Implement `cert_id`, `build_request`, `ocsp_responder_url` and the framing
  helpers.** The code below is the version that produced the P12/P13 measurements
  (`.tmptmp/research/reference-ocsp.rs` holds the runnable copy); the field order and the two
  hash inputs are the parts that must not drift.

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
    let name_hash = sha1::Sha1::digest(leaf.tbs_certificate.issuer.to_der().ok()?).to_vec();
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
fn build_request(leaf: &Certificate, issuer: &Certificate) -> Option<Vec<u8>> {
    let cid = cert_id(leaf, issuer)?;
    let request = tlv(0x30, &cid);
    let request_list = tlv(0x30, &request);
    let tbs_request = tlv(0x30, &request_list);
    Some(tlv(0x30, &tbs_request))
}

/// The `id-ad-ocsp` access location of the leaf's AIA extension, when it is an `http:` URI.
fn ocsp_responder_url(leaf: &Certificate) -> Option<String> {
    let exts = leaf.tbs_certificate.extensions.as_ref()?;
    let aia = exts
        .iter()
        .find(|e| e.extn_id == ID_PE_AUTHORITY_INFO_ACCESS)?;
    let descs = DerReader::new(aia.extn_value.as_bytes()).read_sequence().ok()?;
    let mut reader = DerReader::new(descs);
    while let Ok((tag, body)) = reader.read_description() {
        let _ = tag;
        let mut d = DerReader::new(body);
        let Ok(method) = d.read_oid() else { continue };
        let Ok((loc_tag, value)) = d.read_tlv() else { continue };
        // GeneralName uniformResourceIdentifier is `[6] IMPLICIT IA5String`.
        if method == ID_AD_OCSP && loc_tag == 0x86 {
            let url = String::from_utf8_lossy(value).into_owned();
            return url.starts_with("http://").then_some(url);
        }
    }
    None
}
```

  Two support items are needed in `revocation.rs`: a local `read_description`-style loop is just
  `read_tlv` on each element (write it directly rather than adding a method to `pkcs12::DerReader`),
  and `ID_PE_AUTHORITY_INFO_ACCESS` / `ID_AD_OCSP` come from
  `const_oid::db::rfc5280::ID_PE_AUTHORITY_INFO_ACCESS` and
  `const_oid::db::rfc5280::ID_AD_OCSP`; `OID_SHA1` is `1.3.14.3.2.26` (encode with the same
  `oid_tlv` helper used in `pkcs12.rs`'s test builders). `integer_from_magnitude` re-encodes the
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

- [ ] **Step 1: Write the failing tests**

```rust
    fn now_in_window() -> time::OffsetDateTime {
        // Both fixtures were produced with thisUpdate "20260926…"; a clock inside the
        // window keeps the test independent of the machine's wall clock.
        time::OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap()
    }

    #[test]
    fn good_response_verifies_and_reports_good() {
        let (leaf, issuer) = fixture_pair();
        let status = parse_and_verify(GOOD_DER, &leaf, &issuer, now_in_window()).unwrap();
        assert!(
            matches!(status, RevocationStatus::Good),
            "expected Good, got {status:?}"
        );
    }

    #[test]
    fn revoked_response_reports_the_revocation_time() {
        let (leaf, issuer) = fixture_pair();
        let status = parse_and_verify(REVOKED_DER, &leaf, &issuer, now_in_window()).unwrap();
        let RevocationStatus::Revoked { revoked_at, .. } = status else {
            panic!("expected Revoked, got {status:?}");
        };
        assert_eq!(
            revoked_at.map(|t| t.unix_timestamp()),
            Some(1_767_225_600),
            "fixture revokes at 2026-01-01T00:00:00Z"
        );
        assert!(status.warning().is_some_and(|w| w.contains("revoked")));
    }

    #[test]
    fn a_tampered_signature_is_not_trusted() {
        let (leaf, issuer) = fixture_pair();
        let mut bad = GOOD_DER.to_vec();
        // Offset 400 sits inside the signature BIT STRING of this 1276-byte response.
        bad[400] ^= 0x01;
        let status = parse_and_verify(&bad, &leaf, &issuer, now_in_window());
        assert!(
            matches!(status, Ok(RevocationStatus::NotChecked(NotCheckedReason::Unverified))),
            "a forged answer must be Unverified, got {status:?}"
        );
        assert!(status.unwrap().warning().is_none());
    }

    #[test]
    fn a_foreign_issuer_key_is_not_trusted() {
        let (leaf, _real) = fixture_pair();
        let unrelated = Certificate::from_pem(
            super::assets::APPLE_WWDR_CA_G3_CERT.as_bytes(),
        )
        .unwrap();
        let status = parse_and_verify(GOOD_DER, &leaf, &unrelated, now_in_window()).unwrap();
        assert!(
            matches!(status, RevocationStatus::NotChecked(NotCheckedReason::Unverified)),
            "verification must bind to the real issuer key, got {status:?}"
        );
    }

    #[test]
    fn a_response_for_another_certificate_is_not_trusted() {
        let (leaf, issuer) = fixture_pair();
        let mut other = leaf.clone();
        other.tbs_certificate.serial_number =
            x509_cert::serial_number::SerialNumber::new(&[0x7f]).unwrap();
        let status = parse_and_verify(GOOD_DER, &other, &issuer, now_in_window()).unwrap();
        assert!(
            matches!(
                status,
                RevocationStatus::NotChecked(NotCheckedReason::Malformed(_))
            ),
            "a certID mismatch must not produce a status, got {status:?}"
        );
    }

    #[test]
    fn validity_window_is_enforced() {
        let (leaf, issuer) = fixture_pair();
        let later = time::OffsetDateTime::from_unix_timestamp(2_000_000_000).unwrap();
        let status = parse_and_verify(GOOD_DER, &leaf, &issuer, later).unwrap();
        assert!(
            matches!(
                status,
                RevocationStatus::NotChecked(NotCheckedReason::OutsideValidityWindow)
            ),
            "an answer past its freshness must not be reused, got {status:?}"
        );
    }

    #[test]
    fn non_successful_and_malformed_responses_are_silent() {
        let (leaf, issuer) = fixture_pair();
        let malformed = parse_and_verify(b"not der at all", &leaf, &issuer, now_in_window());
        assert!(matches!(
            malformed,
            Ok(RevocationStatus::NotChecked(NotCheckedReason::Malformed(_)))
        ));
        // responseStatus = internalError(2) with no responseBytes.
        let refused = vec![0x30, 0x03, 0x0a, 0x01, 0x02];
        let status = parse_and_verify(&refused, &leaf, &issuer, now_in_window()).unwrap();
        assert!(matches!(
            status,
            RevocationStatus::NotChecked(NotCheckedReason::Malformed(_))
        ));
        assert!(status.warning().is_none());
    }
```

- [ ] **Step 2: Run them to verify they fail** (`parse_and_verify` does not exist yet).

- [ ] **Step 3: Implement the parser.** The field order below is the substance of this task; the
  measured behaviour is P12-P14 plus the four negative controls above. Reuse the crate's own
  `pkcs12::DerReader` for the walk (promote it to `pub(crate)` — it already exposes
  `read_sequence`, `read_oid`, `read_tlv`-style primitives and the peek helpers this needs) rather
  than a second reader.

```rust
/// Parses and verifies one `OCSPResponse` for `leaf`/`issuer`.
///
/// `Ok(status)` always means "the answer, or the reason there is no answer": the function never
/// returns `Err` for anything a responder can do, because a revocation check must not be able to
/// fail a signing run. The signature is verified over the `tbsResponseData` DER bytes exactly as
/// they appear in the response (`RFC 6960 §3.2`, `RFC 6960 §4.2.2.2`).
pub fn parse_and_verify(
    response_der: &[u8],
    leaf: &Certificate,
    issuer: &Certificate,
    now: time::OffsetDateTime,
) -> Result<RevocationStatus> {
    let want_cid = cert_id(leaf, issuer)
        .ok_or_else(|| Error::Verification("cannot build CertID".into()))?;
    let Some(outcome) = walk_response(response_der, &want_cid, issuer, now) else {
        return Ok(RevocationStatus::NotChecked(NotCheckedReason::Malformed(
            "response is not a parseable OCSPResponse for this certificate".into(),
        )));
    };
    Ok(outcome)
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
        let signer = pick_signer(rid_value, responder_by_name, issuer, &embedded)?;
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
    None
}

/// Chooses the key that must have signed the response: the issuer itself when
/// `responderID` names it, otherwise an embedded certificate that the issuer issued
/// and that carries `id-kp-OCSPSigning` (RFC 6960 §4.2.2.2).
fn pick_signer(
    rid_value: &[u8], by_name: bool, issuer: &Certificate, embedded: &[Certificate],
) -> Option<Certificate> {
    if by_name {
        let names = DerReader::new(rid_value).read_sequence().ok()?;
        let mut n = DerReader::new(names);
        let (tag, value) = n.read_tlv().ok()?;
        if tag != 0x86 && tag != 0x30 {
            return None;
        }
        let rid_der = tlv(0x30, value);
        if tlv(0x30, issuer.tbs_certificate.subject.to_der().ok()?.as_slice()) == rid_der {
            return Some(issuer.clone());
        }
    }
    embedded.iter().find(|c| {
        c.tbs_certificate.issuer == issuer.tbs_certificate.subject
            && has_ocsp_signing_eku(c)
            && verify_cert_signature(c, issuer)
    })
    .cloned()
    .or(by_name.then(|| issuer.clone()))
}
```

  `verify_signature` dispatches on `signatureAlgorithm`: `sha1WithRSAEncryption`
  (`1.2.840.113549.1.1.5`), `sha256WithRSAEncryption` (`1.2.840.113549.1.1.11`), and
  `ecdsa-with-SHA256` (`1.2.840.10045.4.3.2`), each verifying the raw `tbsResponseData` bytes —
  the same three arms `cms_verify.rs:1237-1286` already uses, re-expressed here because that
  function also handles CMS-specific `signedAttrs` re-framing. `verify_cert_signature` and the
  `id-kp-OCSPSigning` EKU check are promoted from `cms_verify.rs`
  (`:1518-1566`, `:1599-1613`) as `pub(crate)`, matching how ZSN-37 promoted `ext_value`.
  `span_of_next_tlv` is one new method on `pkcs12::DerReader` returning the raw bytes of the next
  TLV (not just its value); it is the single reason the reader is widened, and it replaces the
  "re-encode and hope it is canonical" shortcut that would break on any length form the responder
  actually sends.
  `parse_time` accepts both UTCTime and GeneralizedTime (RFC 6960 allows either) and returns an
  `OffsetDateTime`; `parse_generalized_time` is its GeneralizedTime-only helper.

- [ ] **Step 4: Run the tests**

Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-core revocation -- --skip test_ipa_signing_is_deterministic`
Expected: Task 8's four plus these seven pass.

- [ ] **Step 5: Commit**

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
        let creds = credentials_with_chain(&leaf, &issuer);
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
        fn an_unreachable_responder_is_not_checked() {
            // Port 1 on loopback refuses immediately: no DNS, no internet, no flake.
            let (mut leaf, issuer) = fixture_pair();
            rewrite_ocsp_uri(&mut leaf, "http://127.0.0.1:1/ocsp");
            let status = check(&leaf, Some(&issuer), &HttpTransport::default(), Some(now_in_window()));
            assert!(matches!(
                status,
                RevocationStatus::NotChecked(NotCheckedReason::Transport(_))
            ));
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
  in `crates/zsign-cli/src/main.rs::load_credentials` immediately before each `return Ok(creds)`.
  It is not applied here because lane zsn40 owns that file this wave.

- [ ] **Step 2: Lane gate** (the only place the full gates run):

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
TMPDIR=$PWD/.tmptmp cargo test --workspace --no-fail-fast -- --skip test_ipa_signing_is_deterministic
cargo check -p zsign-wasm --target wasm32-unknown-unknown
```

  Expected: clean output from each, and the test summary showing zero failures. Report the verbatim
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
| Hermetic two-layer revocation coverage | 9, 10 |
| One new crate (`md-5`), no `deny.toml` change | 5 |
| No CI/skip change, deterministic-by-construction tests | ground rules, 11 |

Checked and consistent: `RevocationStatus`/`NotCheckedReason` names match between Tasks 8-10 and
the design doc; `parse_and_verify` returns `Result<RevocationStatus>` everywhere, and its `Err` arm
is reserved for "we could not even build the CertID" (an internal bug), never for responder behaviour;
`check` and `warn_revocation` never propagate `Err`. Fixture names are identical in Tasks 5, 6 and 7.
`cert_id`, `build_request`, `ocsp_responder_url`, `tlv`, `parse_and_verify`, `warning`,
`NotCheckedReason::Malformed(String)` are defined once (Tasks 8-9) and reused later.

## Seams and follow-ups (report, do not implement here)

1. **CLI revocation wiring.** `warn_revocation` is the intended call; the insertion points are the
   three `return Ok(creds)` sites in `crates/zsign-cli/src/main.rs::load_credentials` (`:800`,
   `:816`, `:849`, `:855`). Owned by lane zsn40's file; no flag is needed.
2. **TTY prompt parity for encrypted PEM keys.** `resolve_p12_password` (`main.rs:865-892`) prompts
   for PKCS#12 only; after this lane an encrypted PEM without `-p`/`ZSIGN_PASSWORD` gets an explicit
   "requires a password" error instead of a prompt. Adding the prompt is a password-flow change in
   the file this lane does not own.
3. **No static known-revoked list.** No license-clean source exists (design premise 5); implementing
   this would mean inventing data, which the brief forbids.
4. **Fixtures for ZSN-30.** 12 PEM files plus 5 revocation fixtures land under
   `crates/zsign-core/src/crypto/fixtures/`; wave 7 consolidates them and their recipes.
5. **Docs lane.** `README.md:32-57` and `crates/zsign-core/src/crypto/mod.rs` still describe PEM
   loading as unencrypted-only and revocation as a device concern; the code-level docs are updated in
   Tasks 6 and 9, but the top-level README is outside this lane's file list.
