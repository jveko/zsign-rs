# Duplicate-certificate dedupe at CMS signing — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development with dispatching-parallel-agents for independent tasks to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `sign_code_directory` return a typed result (never panic) when the caller supplies a `cert_chain` containing byte-identical duplicates, by deduplicating the certificate set before it reaches the cms 0.2.3 builder.

**Architecture:** One private helper `deduped_certificates(signing_cert, cert_chain) -> Result<Vec<&Certificate>>` in `crates/zsign-core/src/crypto/cms.rs` performs order-preserving first-wins dedupe keyed on DER bytes; both certificate-adding loops (production `build_cms_signed_data` and test-only `build_test_cms`) collapse into a single loop over its output. The cms crate's internal `.unwrap()` becomes unreachable from our inputs.

**Tech Stack:** Rust, edition 2021, MSRV 1.88; `cms` 0.2.3 / `der` 0.7.10; `x509-cert` certificate builder for fixtures.

**Spec:** `docs/superpowers/specs/2026-09-28-dup-cert-dedupe-design.md`

## Global Constraints

- Zero-warning gate: `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, final `TMPDIR=$PWD/target/tmp cargo test --workspace` green (baseline 779 passed / 1+12 ignored) and `TMPDIR=$PWD/target/tmp wasm-pack test --node crates/zsign-wasm` (28 passed).
- No ticket IDs in code comments (ZSN-99 only in commit subjects); no `println!`/`eprintln!` in `src/`; no TODOs/placeholders; no new shims.
- Do NOT touch: `require_anchored_chain` / anchoring code, `build_chain_from_leaf`, `verify_key_matches_cert`, loaders in `cert.rs`, `zsign-cli`, `zsign-wasm`, facade `crates/zsign/`, `verify.rs`, Mach-O.
- Tests run with `TMPDIR=$PWD/target/tmp` (in-tree tmp).
- Commit style: conventional, imperative, lowercase, no trailing period; subject may carry `(ZSN-99)`. NEVER merge, NEVER push.
- Research agents/subagents skip formatters/linters/project-wide tests; the controller runs the gate between tasks.

## Review Focus

- Duplicate of the signer's certificate *only* (`cert_chain = vec![certificate.clone()]`): expected — sign succeeds, emitted `SignedData` holds exactly one certificate, sid still resolves. Owner: Task 1 regression A.
- Signer's certificate repeated *mid-chain* in a 3-element chain: expected — sign succeeds, emitted set equals the deduplicated set (signer first), full verify reports `valid`. Owner: Task 1 regression B.
- Chain with no duplicates (the common path): expected — byte-for-byte behavior unchanged; existing round-trip and chain tests keep passing. Owner: Task 2 gate (existing suite) plus Task 1's tests which run the untouched path too.
- `to_der()` failure inside the helper: expected — typed `Error` via `signing_err`, never a panic. Owner: Task 2 (error propagates with `?`; no test possible for a parsed cert, code inspection).
- Test-only builder `build_test_cms` left undeduped while production is fixed: expected — both loops collapse onto the same helper so the convention has exactly one home. Owner: Task 2 diff review.

---

### Task 1: Red regression tests for duplicate certificates

**Files:**
- Modify: `crates/zsign-core/src/crypto/cms_verify.rs` (test module; insert after `sign_code_directory_rejects_mismatched_key_and_certificate`, currently ending ~line 1863)

**Interfaces:**
- Consumes: `sign_code_directory(content, &creds, None, &cd_sha256) -> Result<Vec<u8>>`; `wrap(&cms) -> Vec<u8>` (cms_verify.rs:1801); `verify_code_signature_with_anchors(&wrapped, content, None, &cd_sha256, &anchors) -> Result<CmsVerifyReport>` (cms_verify.rs:333); `fresh_rsa_credentials() -> (SigningCredentials, rsa::RsaPrivateKey)` (cms_verify.rs:1756); `build_subca(cn, path_len) -> (Certificate, SigningKey)` (cms_verify.rs:2386); `build_subca_issued_by(cn, issuer_name, issuer_signing) -> (Certificate, SigningKey)` (cms_verify.rs:2415); struct-literal `SigningCredentials` construction (pattern: cms_verify.rs:1840-1845).
- Produces: two `#[test]` fns that FAIL (red) today with a panic — Task 2 greens them. Tests must use struct literals / unanchored fixtures only, never anchored public constructors, and must pair the signer's own key with its own certificate so the ZSN-98 guard at `cms.rs:296` passes first.

- [ ] **Step 1: Write regression test A (duplicate = signer cert only)**

Insert into the `cms_verify.rs` test module:

```rust
#[test]
fn sign_code_directory_dedupes_repeated_signing_certificate() {
    let (identity, _key) = fresh_rsa_credentials();
    let creds = SigningCredentials {
        certificate: identity.certificate.clone(),
        signing_key: identity.signing_key.clone(),
        cert_chain: vec![identity.certificate.clone()],
        team_id: identity.team_id.clone(),
    };
    let content: &[u8] = b"the code directory bytes";
    let cd_sha256: [u8; 32] = Sha256::digest(content).into();

    let cms = sign_code_directory(content, &creds, None, &cd_sha256)
        .expect("a duplicated signing certificate must not panic or fail");
    // Parse idiom mirrors cms.rs:760-761.
    let content_info = ContentInfo::from_der(&cms).expect("emitted CMS parses as ContentInfo");
    let signed_data =
        SignedData::from_der(&content_info.content.to_der().expect("content re-encodes"))
            .expect("emitted CMS parses as SignedData");
    let certs = signed_data.certificates.expect("certificate set present");
    assert_eq!(
        certs.0.len(),
        1,
        "signing certificate repeated in chain must be carried exactly once"
    );

    let report = verify_code_signature_with_anchors(
        &wrap(&cms),
        content,
        None,
        &cd_sha256,
        &anchors_for(&creds),
    )
    .expect("verification of deduplicated CMS");
    assert!(report.valid, "errors: {:?}", report.errors);
    assert!(report.signature_ok);
}
```

If imports are missing in the test module, add them to the existing `use` block (lines 1729-1745): `use cms::{ContentInfo, SignedData};` and `der::Decode` is already in scope via `use super::*` (cms_verify.rs:48). Match the file's import style.

- [ ] **Step 2: Write regression test B (signer cert repeated mid-chain)**

```rust
#[test]
fn sign_code_directory_dedupes_signer_certificate_repeated_mid_chain() {
    let (identity, _key) = fresh_rsa_credentials();
    let (inter, _inter_signing) = build_subca("CN=zsign dup int", None);
    let (root, _root_signing) = build_subca("CN=zsign dup root", None);
    let creds = SigningCredentials {
        certificate: identity.certificate.clone(),
        signing_key: identity.signing_key.clone(),
        cert_chain: vec![
            inter.clone(),
            identity.certificate.clone(),
            root.clone(),
        ],
        team_id: identity.team_id.clone(),
    };
    let content: &[u8] = b"the code directory bytes";
    let cd_sha256: [u8; 32] = Sha256::digest(content).into();

    let cms = sign_code_directory(content, &creds, None, &cd_sha256)
        .expect("signer certificate repeated mid-chain must not panic or fail");
    // Parse idiom mirrors cms.rs:760-761.
    let content_info = ContentInfo::from_der(&cms).expect("emitted CMS parses as ContentInfo");
    let signed_data =
        SignedData::from_der(&content_info.content.to_der().expect("content re-encodes"))
            .expect("emitted CMS parses as SignedData");
    let certs = signed_data.certificates.expect("certificate set present");
    let members: Vec<Vec<u8>> = certs
        .0
        .iter()
        .map(|c| c.to_der().expect("member re-encodes"))
        .collect();
    let signer_der = identity.certificate.to_der().unwrap();
    assert_eq!(
        members.iter().filter(|m| **m == signer_der).count(),
        1,
        "signing certificate must appear exactly once in the emitted set"
    );
    assert_eq!(
        members.len(),
        3,
        "deduplicated set is signer + inter + root, got {}",
        members.len()
    );

    let report = verify_code_signature_with_anchors(
        &wrap(&cms),
        content,
        None,
        &cd_sha256,
        &anchors_for(&creds),
    )
    .expect("verification of deduplicated CMS");
    assert!(report.valid, "errors: {:?}", report.errors);
    assert!(report.signature_ok);
}
```

Note: `anchors_for(&creds)` anchors on the signer's certificate (self-signed test leaf), so `chain_ok`/`anchored` do not depend on inter/root links — the assertion targets the dedup + signature contract, not chain building. Do not weaken `report.valid`.

- [ ] **Step 3: Run the two tests to verify they fail by panic (red)**

Run: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-core sign_code_directory_dedup`
Expected: both tests FAIL with a panic `Error { kind: SetDuplicate }` (or "SET OF contains duplicate") from `SignedDataBuilder::build`. Paste the failure output.

- [ ] **Step 4: Commit the red tests**

Run: `cargo fmt --all && git add crates/zsign-core/src/crypto/cms_verify.rs && git commit -m "test: pin duplicate certificate handling at cms signing (ZSN-99)"`
Expected: commit created; pre-commit hook passes.

---

### Task 2: Dedupe helper and wire both builder loops

**Files:**
- Modify: `crates/zsign-core/src/crypto/cms.rs` (helper near `build_cms_signed_data` ~line 368; loops at `cms.rs:393-401` and test helper `cms.rs:223-230`)

**Interfaces:**
- Consumes: `signing_err(msg, e)` helper (already used throughout cms.rs); `Certificate::to_der()` via the `der::Encode` trait already imported in this file.
- Produces: `fn deduped_certificates<'a>(signing_cert: &'a Certificate, cert_chain: &'a [Certificate]) -> Result<Vec<&'a Certificate>>` — private to the module; Task 1's tests consume it only through `sign_code_directory`.

- [ ] **Step 1: Add the helper**

Place above `build_cms_signed_data` (module-private, `///` doc comment describing first-wins order-preserving dedupe and the cms `SetDuplicate` panic it makes unreachable — no ticket IDs):

```rust
fn deduped_certificates<'a>(
    signing_cert: &'a Certificate,
    cert_chain: &'a [Certificate],
) -> Result<Vec<&'a Certificate>> {
    let mut seen: HashSet<Vec<u8>> = HashSet::new();
    let mut out = Vec::with_capacity(1 + cert_chain.len());
    for cert in std::iter::once(signing_cert).chain(cert_chain) {
        let der = cert
            .to_der()
            .map_err(|e| signing_err("Failed to encode certificate", e))?;
        if seen.insert(der) {
            out.push(cert);
        }
    }
    Ok(out)
}
```

Add `use std::collections::HashSet;` to the file's import block, matching its std/external grouping style.

- [ ] **Step 2: Collapse the production loop**

In `build_cms_signed_data`, replace the signing-cert `add_certificate` call and the chain `for` loop (`cms.rs:393-401`) with a single loop:

```rust
for cert in deduped_certificates(ctx.signing_cert, ctx.cert_chain)? {
    builder
        .add_certificate(CertificateChoices::Certificate(cert.clone()))
        .map_err(|e| signing_err("Failed to add certificate", e))?;
}
```

- [ ] **Step 3: Collapse the test-helper loop**

Apply the identical replacement in `build_test_cms` (`cms.rs:223-230`), using its `signing_cert` and `cert_chain` parameters.

- [ ] **Step 4: Green the regression tests**

Run: `TMPDIR=$PWD/target/tmp cargo test -p zsign-core sign_code_directory_dedup`
Expected: both Task 1 tests PASS.

- [ ] **Step 5: Scoped gate**

Run: `cargo fmt --all -- --check && cargo clippy -p zsign-core --all-targets -- -D warnings && TMPDIR=$PWD/target/tmp cargo test -p zsign-core`
Expected: clean fmt, zero clippy warnings, all `zsign-core` tests pass (baseline count for the crate preserved — no existing test may change).

- [ ] **Step 6: Commit**

Run: `git add crates/zsign-core/src/crypto/cms.rs && git commit -m "fix: dedupe certificate set before cms signing (ZSN-99)"`
Expected: commit created.

---

### Task 3: Full workspace verification

**Files:** none (verification only).

- [ ] **Step 1: Zero-warning gate + full test suite**

Run: `cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings && TMPDIR=$PWD/target/tmp cargo test --workspace`
Expected: fmt clean, clippy clean, 779+2 passed / 1+12 ignored (779 baseline + the 2 new tests).

- [ ] **Step 2: wasm suite**

Run: `TMPDIR=$PWD/target/tmp wasm-pack test --node crates/zsign-wasm`
Expected: 28 passed.

- [ ] **Step 3: Confirm no out-of-scope files changed**

Run: `git diff --name-only main...HEAD`
Expected: exactly `crates/zsign-core/src/crypto/cms.rs`, `crates/zsign-core/src/crypto/cms_verify.rs`, plus the two `docs/superpowers/` files.
