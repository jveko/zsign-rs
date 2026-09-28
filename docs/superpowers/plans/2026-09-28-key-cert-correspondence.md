# Key↔Certificate Correspondence at CMS Signing — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development (recommended) with dispatching-parallel-agents for independent tasks to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A mismatched `signing_key`/`certificate` pair errors with a typed `Error::Certificate` at the top of `sign_code_directory`, before any CMS byte exists; matched pairs sign and verify unchanged.

**Architecture:** One enforced choke-point guard: `sign_code_directory` (`crates/zsign-core/src/crypto/cms.rs:292`) is the single production CMS producer, so it calls the existing private SPKI-comparison helper `verify_key_matches_cert` (widened `fn` → `pub(crate) fn` in `cert.rs`) as its first statement. No new public API, no new dependencies, no wasm/CLI/facade changes (mapping evidence: spec §4.3).

**Tech Stack:** Rust (edition 2021, MSRV 1.88), thiserror, RustCrypto/x509-cert; tests inline `#[cfg(test)] mod tests`.

**Spec:** `docs/superpowers/specs/2026-09-28-key-cert-correspondence-design.md` — the plan argues from the spec; executors read both.

## Global Constraints

- Zero-warning gate: `cargo fmt --all -- --check` and `cargo clippy --workspace --all-targets -- -D warnings` must pass; scoped tests while iterating; final `TMPDIR=$PWD/target/tmp cargo test --workspace` (baseline 778 passed / 1+12 ignored) and `TMPDIR=$PWD/target/tmp wasm-pack test --node crates/zsign-wasm` (28 passed).
- Fail-closed: a mismatched key/cert must ERROR at sign time, typed (`Error::Certificate`), never warn, never produce a CMS blob.
- Fixtures: self-issued material must load through `from_p12_unanchored`/`from_pem_unanchored` (`cfg(any(test, feature = "test-fixtures"))`) or struct literals — the public `from_p12`/`from_pem` are Apple-root anchored in every build and will reject them.
- Reuse `verify_key_matches_cert`; no new dependencies; do not modify ZSN-96's anchoring code; do not touch `zsign/src/builder.rs`, `zsign/src/ipa/` (ZSN-143), or the duplicate-cert code at `cms.rs:390` (crypto-4).
- No ticket IDs in code comments (ZSN-98 allowed in commit subjects only); no `println!`/`eprintln!` in `src/`; no placeholders/TODOs.
- Test assertion convention: `assert!(matches!(&res, Err(Error::Variant(m)) if m.contains("…")), "…, got {:?}", res.as_ref().err());`
- Implementers never commit; the controller commits per task after review. Never merge, never push.

## Review Focus

1. **Guard placement:** the check must run before any CMS construction and before `match &credentials.signing_key` (`cms.rs:342`), as one call, not duplicated per key arm. The regression's negative assertion pins "errors, no bytes"; a reviewer must confirm the placement is the function's first statement (ECDSA mismatches are caught by the same pre-dispatch check).
2. **Chain non-interference:** only `certificate` vs `signing_key` is compared — never `cert_chain` members (they legitimately hold unrelated issuer keys). The existing `test_estimate_cms_size_rsa_with_chain` (`cms.rs:967`) must stay green; it is the tripwire for a naive fix that compares chain entries.
3. **Error-shape assertion:** the test asserts the typed variant plus the payload substring `does not match`, NOT the full Display string (`Invalid certificate: …`) — full-string pins would break message tuning and duplicate the Display layer.
4. **Positive control completeness:** the matched pair must not merely sign — its CMS must verify (`report.valid` AND `report.signature_ok` via `verify_code_signature_with_anchors` + `anchors_for`), otherwise a guard that rejects everything still passes the negative half.
5. **Fail-closed, no fallback:** no `unwrap_or`, warn-path, or best-effort signing may exist beside the guard; on error the function returns `Err` with zero output bytes.

---

### Task 1: Regression test (red) — authored by the Tester agent

**Files:**
- Modify: `crates/zsign-core/src/crypto/cms_verify.rs` (inline `mod tests`; place next to `round_trip_rsa_signs_and_verifies` at `:1810`)

**Interfaces:**
- Consumes: `sign_code_directory(data, credentials, cdhash_sha1, cdhash_sha256) -> Result<Vec<u8>>` (`cms.rs:292`); `fresh_rsa_credentials() -> (SigningCredentials, rsa::RsaPrivateKey)` (`cms_verify.rs:1756`, fresh identity per call); `anchors_for(&creds) -> TrustAnchors` (`cms_verify.rs:1797`); `wrap(&cms) -> Vec<u8>` (`cms_verify.rs:1801`); `verify_code_signature_with_anchors(&wrap(&cms), content, None, &cd_sha256, &anchors_for(&creds)) -> Result<report>` (`cms_verify.rs:333`); `SigningCredentials` literal fields `certificate`, `signing_key`, `cert_chain`, `team_id` (`cert.rs:107-127`); `Error::Certificate(String)` (`error.rs:16`).
- Produces: test name `sign_code_directory_rejects_mismatched_key_and_certificate` (Task 2 must make it pass unchanged).

- [ ] **Step 1: Write the failing test**

Insert into `crates/zsign-core/src/crypto/cms_verify.rs` tests, following the surrounding import conventions (`sign_code_directory` is already imported at `:1731`; `SigningCredentials` is already in scope at `:1735` and `Error` arrives via the module's `use super::*` at `:44` — no import changes needed):

```rust
#[test]
fn sign_code_directory_rejects_mismatched_key_and_certificate() {
    let (identity_a, _) = fresh_rsa_credentials();
    let (identity_b, _) = fresh_rsa_credentials();
    let mismatched = SigningCredentials {
        certificate: identity_a.certificate.clone(),
        signing_key: identity_b.signing_key.clone(),
        cert_chain: vec![],
        team_id: identity_a.team_id.clone(),
    };
    let content: &[u8] = b"the code directory bytes";
    let cd_sha256: [u8; 32] = Sha256::digest(content).into();

    let res = sign_code_directory(content, &mismatched, None, &cd_sha256);
    assert!(
        matches!(&res, Err(Error::Certificate(m)) if m.contains("does not match")),
        "mismatched key and certificate must fail closed at sign time, got {:?}",
        res.as_ref().err()
    );

    let cms = sign_code_directory(content, &identity_a, None, &cd_sha256).unwrap();
    let report = verify_code_signature_with_anchors(
        &wrap(&cms),
        content,
        None,
        &cd_sha256,
        &anchors_for(&identity_a),
    )
    .unwrap();
    assert!(report.valid, "errors: {:?}", report.errors);
    assert!(report.signature_ok);
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-core sign_code_directory_rejects_mismatched_key_and_certificate`
Expected: compile OK, test FAILS with `mismatched key and certificate must fail closed at sign time, got None` (today the mismatched pair happily returns `Ok(bytes)`).

- [ ] **Step 3: Report**

Report status, exact file paths modified, the verbatim failing output, and concerns. Do not commit.

---

### Task 2: Choke-point guard (green)

**Files:**
- Modify: `crates/zsign-core/src/crypto/cert.rs:882` — visibility only
- Modify: `crates/zsign-core/src/crypto/cms.rs` — guard (first statement of `sign_code_directory`, `:298` after the signature) + `# Errors` doc (`:290-291`)

**Interfaces:**
- Consumes: `verify_key_matches_cert(key: &SigningKeyType, cert: &Certificate) -> Result<()>` (`cert.rs:882`), which already returns `Error::Certificate("Private key does not match certificate's public key")` on mismatch.
- Produces: `sign_code_directory` now also returns `Error::Certificate` (documented); `verify_key_matches_cert` becomes `pub(crate)`.

- [ ] **Step 1: Widen the helper's visibility**

In `crates/zsign-core/src/crypto/cert.rs:882`, change `fn verify_key_matches_cert` to `pub(crate) fn verify_key_matches_cert`. No body change; this is the sanctioned `cert.rs` reuse — it must not touch any anchoring code.

- [ ] **Step 2: Insert the guard as the first statement of `sign_code_directory`**

In `crates/zsign-core/src/crypto/cms.rs`, immediately after the function's opening brace (before `build_cdhash_plist`):

```rust
verify_key_matches_cert(&credentials.signing_key, &credentials.certificate)?;
```

Add `verify_key_matches_cert` to the file's existing `cert` import (match the file's import style; no new use block).

- [ ] **Step 3: Update the `# Errors` doc**

Extend the `# Errors` section of `sign_code_directory` (`cms.rs:290-291`) with:

```rust
/// Returns [`Error::Certificate`] if `credentials.signing_key` does not
/// match the public key in `credentials.certificate`.
```

- [ ] **Step 4: Run the regression test to verify it passes**

Run: `TMPDIR=$PWD/target/tmp cargo test -p zsign-core sign_code_directory_rejects_mismatched_key_and_certificate`
Expected: PASS (1 passed).

- [ ] **Step 5: Run the scoped gate**

Run: `cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings && TMPDIR=$PWD/target/tmp cargo test -p zsign-core`
Expected: no diff, no warnings, all `zsign-core` tests pass (the chain test `test_estimate_cms_size_rsa_with_chain` among them).

- [ ] **Step 6: Run the full gates**

Run: `TMPDIR=$PWD/target/tmp cargo test --workspace`
Expected: all workspace tests pass (baseline 778 passed / 1+12 ignored, plus the new regression test — 779 passed).

Run: `TMPDIR=$PWD/target/tmp wasm-pack test --node crates/zsign-wasm`
Expected: 28 passed.

These two are the ticket's shipping gates: they exercise the P12→sign paths outside `zsign-core` (CLI `IDENTITY_P12` fixture test at `crates/zsign-cli/src/main.rs:1466-1486`, wasm `new_signer`→`sign_macho` round trip at `crates/zsign-wasm/src/lib.rs:919-923`) where the PKCS#12 pairing encoder (`DecodedKey::spki_der`, `cert.rs:165`) and the new sign-time guard encoder must agree byte-for-byte.

- [ ] **Step 7: Report**

Report status, exact file paths modified, verbatim test/clippy output including both full-gate runs, and concerns. Do not commit.
