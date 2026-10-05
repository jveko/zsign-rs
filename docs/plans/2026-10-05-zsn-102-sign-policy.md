# ZSN-102 Sign-Time Policy Gate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development (recommended) with dispatching-parallel-agents for independent tasks to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reject policy-violating signing leaves (CA=true, missing digitalSignature, expired/not-yet-valid) at sign time by calling the existing `code_signing_policy_violation` from the top of `sign_code_directory`.

**Architecture:** One enforcement point in `crates/zsign-core/src/crypto/cms.rs`, reusing the load-path policy function and `time_now()` from `cert.rs` (both bumped to `pub(crate)`), mapping violations to `Error::Certificate`. Tests live in the `cms_verify.rs` test module; existing wrong-pinning fixtures move from `Profile::Root` signer certs to valid end-entity certs.

**Tech Stack:** Rust 2021, x509-cert 0.2.5, `time`, thiserror; `cargo test -p zsign-core`, `cargo clippy -p zsign-core --all-targets -- -D warnings`.

**Spec:** `docs/plans/2026-10-05-zsn-102-sign-policy-design.md`

## Global Constraints

- Zero-warning gate: `cargo fmt --all -- --check` and `cargo clippy -p zsign-core --all-targets -- -D warnings` clean (full `hk check --all` runs once at the end).
- No new error variants; policy violations are `Error::Certificate(String)` with the existing `signing certificate "<subject>": …` message shape.
- No ticket IDs in code comments; no stubs/TODOs/placeholders; no scope beyond this plan.
- Test assertion pattern: `assert!(matches!(&res, Err(Error::Certificate(m)) if m.contains("…")), "…, got {:?}", res.as_ref().err());`
- Imports matched to each file's existing style; `crate::Result<T>` throughout.
- Tests: inline `#[cfg(test)] mod tests` per file; keep `TMPDIR` inside the repo (`mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test …`).
- Do not touch the verify engine, wasm, CLI, or bundle beyond the fixture adjustments named below.

## Review Focus

- **Root-as-signer fixtures:** five `cms.rs` tests sign with `Profile::Root` (CA=true, no EKU, no digitalSignature) — after the gate they must fail closed; their signer fixtures must become valid end-entity certs while any chain/anchor roles keep the root.
- **Message pinning:** test (a) must assert `"CA=true"`, so its fixture needs codeSigning EKU present — otherwise the mandatory-EKU check fires first and the CA assertion never matches.
- **Time-rot:** expired/not-yet-valid fixtures must be computed relative to now, not against the `T_2025..T_2030` constants, or the tests rot as wall time crosses those bounds.
- **Order of checks:** policy runs before `verify_key_matches_cert`; the ZSN-98 mismatched-key test (`cms_verify.rs:1851`) must still see `"does not match"`.
- **Fallout outside zsign-core:** research found no `sign_code_directory` callers outside `crates/zsign-core` and no Root-signer fixtures elsewhere; `macho/fixtures.rs:686` `test_signing_credentials()` is the drop-in signer fixture, and `benches/signing.rs:99` still needs its own fix. Anything `hk check --all` proves failing gets the same fixture rule, recorded in the final report.

---

### Task 1: Adjust wrong-pinning signer fixtures to valid end-entity certs

**Files:**
- Modify: `crates/zsign-core/src/crypto/cms.rs` (test module only: tests at ~719, ~836, ~905, ~925, ~985)
- Modify: `crates/zsign-core/src/macho/signer.rs` (tests signing with `test_root_credentials()`)
- Modify: `crates/zsign-core/benches/signing.rs` (`test_credentials` at ~99)

**Interfaces:**
- Consumes: `build_test_rsa_credentials(bits: usize)` (`cms.rs:944`, `Profile::Root` hard-coded today), `build_test_ecdsa_credentials()` (`cms.rs:1077`), the inline builder in the test at `cms.rs:719`, and `test_signing_credentials()` (`macho/fixtures.rs:686`, `Profile::Leaf` + codeSigning EKU + `team_id = Some("TESTTEAM")`).
- Produces: every sign-site fixture is a self-consistent end-entity cert with codeSigning EKU inside the current validity window; roots remain only in chain/anchor roles; `test_root_credentials()` (`macho/fixtures.rs:702`) itself is NOT modified.

- [ ] **Step 1:** Run `cargo test -p zsign-core` on the untouched tree; record pass baseline.
- [ ] **Step 2:** For each fixture, switch the **signer** certificate to `Profile::Leaf` and add the EKU before `.build()` with `builder.add_extension(&ExtendedKeyUsage(vec![OID_CODE_SIGNING]))` (the exact idiom at `cms_verify.rs:1786-1788`; `Profile::Leaf` already emits `basicConstraints ca:false` and `keyUsage DigitalSignature|NonRepudiation`, x509-cert 0.2.5 `builder.rs:177,199`), keeping key/cert pairing consistent. For `macho/signer.rs`: swap **every `test_root_credentials()` call site in any test that ever expects signing to succeed** to the existing `test_signing_credentials()` instead of mutating the root helper — must-swaps include the `allow_encrypted=true` success arm at `signer.rs:1658` inside `test_sign_refuses_fat_with_encrypted_slice` (creds at `signer.rs:1632`) and `test_sign_allow_encrypted_override` (`signer.rs:1677-1687`); tests that only fail before signing (e.g. `signer.rs:1283`, and the `EncryptedBinary` refusal arm that fires pre-sign) keep the root fixture untouched. Where the root is also a chain member or trust anchor, leave that role a root. Adjust only assertions that pin the old signer identity (subject/serial) **if they fail**, keeping their semantics.
- [ ] **Step 3:** Run `TMPDIR=$PWD/target/tmp cargo test -p zsign-core` — all green (behavior is unchanged today; these fixtures sign fine both before and after the gate). Commit.

### Task 2: Add the required sign-time rejection tests (expected RED)

**Files:**
- Modify: `crates/zsign-core/src/crypto/cms_verify.rs` (test module, near the ZSN-98 test at ~1851)

**Interfaces:**
- Consumes: `fresh_rsa_credentials` (`cms_verify.rs:1758`), `replace_extension` (`cms_verify.rs:2606`, composition precedent `leaf_asserting_ca_fails` at `cms_verify.rs:2735`), `fixed_validity_chain(not_before_unix: u64, not_after_unix: u64, eku: Option<ExtendedKeyUsage>)` (`cms_verify.rs:3310`), `SigningCredentials` struct literal, `sign_code_directory`.
- Produces: tests `sign_rejects_ca_true_leaf`, `sign_rejects_expired_leaf`, `sign_rejects_not_yet_valid_leaf` (names may follow file convention).

- [ ] **Step 1:** Write three tests following the repo assertion pattern:
  - CA=true: `fresh_rsa_credentials()`, destructure the `SigningCredentials`, flip `basicConstraints` to `CA=true` on the certificate clone via `replace_extension` (validity is an X.509 field, not an extension — `replace_extension` is only for this CA flip), reassemble as a `SigningCredentials` struct literal; assert `Err(Error::Certificate(m))` with `m.contains("CA=true")`.
  - Expired: `fixed_validity_chain(now - 172_800, now - 86_400, Some(ExtendedKeyUsage(vec![OID_CODE_SIGNING])))` with `now = SystemTime::now()` unix seconds; wrap `(leaf, leaf_key)` in a struct-literal `SigningCredentials` (`cert_chain: vec![]`, `team_id: None`); assert `m.contains("expired")`.
  - Not-yet-valid: same helper with `(now + 86_400, now + 172_800, …)`; assert `m.contains("not yet valid")`.
  - The EKU argument is mandatory in both validity tests: policy checks EKU before validity, so without it the named violation would be the EKU one.
- [ ] **Step 2:** Run `TMPDIR=$PWD/target/tmp cargo test -p zsign-core crypto::cms_verify` — the three tests FAIL (signing succeeds today), existing tests PASS. Record output.

### Task 3: Implement the sign-time policy gate (GREEN)

**Files:**
- Modify: `crates/zsign-core/src/crypto/cert.rs` (`code_signing_policy_violation` ~480, `time_now` ~463: `fn` → `pub(crate) fn`)
- Modify: `crates/zsign-core/src/crypto/cms.rs` (`sign_code_directory` ~291-297, import block starting `cms.rs:38`, `# Errors` doc)

**Interfaces:**
- Consumes: `code_signing_policy_violation(&Certificate, time::OffsetDateTime) -> Option<String>`, `time_now() -> time::OffsetDateTime`.
- Produces: `sign_code_directory` returns `Err(Error::Certificate(msg))` for any policy violation at the signing instant.

- [ ] **Step 1:** Bump both `cert.rs` items to `pub(crate)`; import them in `cms.rs` matching the file's import style.
- [ ] **Step 2:** Insert as the first statement of `sign_code_directory`:

```rust
if let Some(violation) = code_signing_policy_violation(&credentials.certificate, time_now()) {
    return Err(Error::Certificate(violation));
}
```

  before `verify_key_matches_cert`; extend `# Errors` to document the policy rejection via `Error::Certificate`.
- [ ] **Step 3:** Run `TMPDIR=$PWD/target/tmp cargo test -p zsign-core` — Task 2 tests and the whole crate green (incl. ZSN-98 `"does not match"` test). Run `cargo fmt --all -- --check` and `cargo clippy -p zsign-core --all-targets -- -D warnings` — clean. Commit tests + implementation together.

### Task 4: Full verification sweep

**Files:**
- Modify **only if `hk check --all` proves a failure**: signing fixtures elsewhere in the workspace (same rule: signer becomes a valid end-entity; record every adjustment). Research found no `sign_code_directory` callers outside `crates/zsign-core` (`macho/signer.rs:569/684` only), so the expected outcome is no changes here.

- [ ] **Step 1:** Run `hk check --all` (fallback: `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`).
- [ ] **Step 2:** If and only if a gate failure traces to a Root/invalid signer fixture, fix it with Task 1's fixture rule; re-run until clean; commit. No failure → no code change in this task.
- [ ] **Step 3:** Report evidence: verbatim gate output, commit list, and the full list of fixture adjustments.
