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
- **Fallout outside zsign-core:** `macho/fixtures.rs:702` signer usage, `benches/signing.rs:100`, and any signing tests in `zsign-rs`/`zsign-cli`/`zsign-wasm` surfaces only at `hk check --all` — each gets the same fixture rule and is recorded in the final report.

---

### Task 1: Adjust wrong-pinning signer fixtures to valid end-entity certs

**Files:**
- Modify: `crates/zsign-core/src/crypto/cms.rs` (test module only: tests at ~719, ~836, ~905-934, ~985)
- Modify: `crates/zsign-core/src/macho/fixtures.rs` (`test_root_credentials` usage at ~702)
- Modify: `crates/zsign-core/src/macho/signer.rs` (tests using the root fixture as signer)
- Modify: `crates/zsign-core/benches/signing.rs` (`test_credentials` at ~100)

**Interfaces:**
- Consumes: existing credential builders in `cms.rs` tests (`build_test_rsa_credentials(Profile, …)`, `build_test_ecdsa_credentials`) and `macho/fixtures.rs`.
- Produces: every sign-site fixture is a self-consistent end-entity cert with codeSigning EKU inside the current validity window; roots remain only in chain/anchor roles.

- [ ] **Step 1:** Run `cargo test -p zsign-core` on the untouched tree; record pass baseline.
- [ ] **Step 2:** For each fixture above, switch the **signer** certificate from `Profile::Root` to an end-entity (`Profile::Leaf`) carrying the codeSigning EKU, keeping key/cert pairing consistent. Where the root is also a chain member or trust anchor, leave that role a root. Adjust only assertions that pin the old signer identity (subject/serial), keeping their semantics.
- [ ] **Step 3:** Run `TMPDIR=$PWD/target/tmp cargo test -p zsign-core` — all green (behavior is unchanged today; these fixtures sign fine both before and after the gate). Commit.

### Task 2: Add the required sign-time rejection tests (expected RED)

**Files:**
- Modify: `crates/zsign-core/src/crypto/cms_verify.rs` (test module, near the ZSN-98 test at ~1851)

**Interfaces:**
- Consumes: `fresh_rsa_credentials` (~1757), `replace_extension` (~2606, precedent at ~2741-2748), `SigningCredentials` struct literal, `sign_code_directory`.
- Produces: tests `sign_rejects_ca_true_leaf`, `sign_rejects_expired_leaf`, `sign_rejects_not_yet_valid_leaf` (names may follow file convention).

- [ ] **Step 1:** Write three tests following the repo assertion pattern:
  - CA=true: struct-literal `SigningCredentials` whose `.certificate` is a policy-clean leaf with `basicConstraints` flipped to `CA=true` via `replace_extension`; assert `Err(Error::Certificate(m))` with `m.contains("CA=true")`.
  - Expired: leaf with `not_after` in the past (computed from current time); assert `m.contains("expired")`.
  - Not-yet-valid: leaf with `not_before` in the future; assert `m.contains("not yet valid")`.
- [ ] **Step 2:** Run `TMPDIR=$PWD/target/tmp cargo test -p zsign-core crypto::cms_verify` — the three tests FAIL (signing succeeds today), existing tests PASS. Record output.

### Task 3: Implement the sign-time policy gate (GREEN)

**Files:**
- Modify: `crates/zsign-core/src/crypto/cert.rs` (`code_signing_policy_violation` ~480, `time_now` ~463: `fn` → `pub(crate) fn`)
- Modify: `crates/zsign-core/src/crypto/cms.rs` (`sign_code_directory` ~291-297, imports ~38-49, `# Errors` doc)

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
- Modify only if fallout appears: signing fixtures in `zsign-rs`/`zsign-cli`/`zsign-wasm` tests (same rule: signer becomes a valid end-entity; record every adjustment).

- [ ] **Step 1:** Run `hk check --all` (fallback: `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`).
- [ ] **Step 2:** Fix any fallout with Task 1's fixture rule; re-run until clean; commit.
- [ ] **Step 3:** Report evidence: verbatim gate output, commit list, and the full list of fixture adjustments.
