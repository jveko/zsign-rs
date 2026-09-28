# Typed PKCS#12 Password Signal (ZSN-230) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development (recommended) with dispatching-parallel-agents for independent tasks to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace cross-crate substring-sniffing of PKCS#12 failure messages with a typed `Error::InvalidPassword` signal from core through wasm and the CLI, deleting every sniffer literal.

**Architecture:** Two core flatten sites route `P12Error` through a new `p12_load_error` (mirror of the existing `pem_load_error`) so `Mac|Decrypt → Error::InvalidPassword`; wasm's `p12_err` and the CLI's `resolve_p12_password` branch on the typed variant instead of Display text; both substring sniffers are deleted. Classification parity with the old sniffer is the contract — see the spec's §2 table.

**Tech Stack:** Rust 2021 / MSRV 1.88, thiserror, wasm-bindgen + wasm-pack, clap.

**Spec:** `docs/superpowers/specs/2026-09-28-typed-p12-error-design.md` — the plan argues from the spec; executors read both.

## Global Constraints

- Zero-warning gate: `cargo fmt --all -- --check` AND `cargo clippy --workspace --all-targets -- -D warnings` — both clean.
- Tests: `TMPDIR=$PWD/target/tmp cargo test --workspace` must end **785 passed / 1+12 ignored** baseline (new tests add to 785); wasm: `TMPDIR=$PWD/target/tmp wasm-pack test --node crates/zsign-wasm` baseline **29 passed** (counts may only grow).
- Fail-closed: wrong password still fails everywhere; only classification changes.
- Anchor/ordering (ZSN-96), key↔cert guard (ZSN-98), profile-error unification (ZSN-143): untouched — their pinned texts byte-identical.
- No ticket IDs in code comments (ZSN-230 in commit subjects only); no `println!`/`eprintln!` in `src/`; no placeholders/TODOs.
- Conventional commits, imperative, lowercase, no trailing period. NEVER merge, NEVER push.
- Stay inside the hunks named in the spec §4; do not reformat neighboring `time_now`/anchoring/zeroize regions.

## Review Focus

1. **CLI non-TTY hint flow** (`missing_password_on_non_tty_degrades_to_clear_error`): after the variant change the trial error must still be classified password-shaped, or users stop being told `-p/--password`/`ZSIGN_PASSWORD` exists. Pinned by Task 3 C1; the `--password`/`ZSIGN_PASSWORD` assertions in that test are untouched and must pass.
2. **CLI TTY prompt path** — CI has no TTY; the prompt branch is untestable there. Its correctness rests on `password_shaped` being computed before the branch (Task 3's code review focus); do not reorder.
3. **Corrupt container class**: `b"not valid p12 data"` must stay `Certificate` → `ZSIGN_INVALID_CERTIFICATE`, never `InvalidPassword` (crypto-11's concern). Pinned by Task 1 N3 and Task 2 W3.
4. **Anchoring/policy/identity/weak-key messages** through `from_p12` must stay byte-identical — the existing suites R1–R6 run **unmodified**; any edit to them is a failure, not a fix.
5. **Sniffer literal absence**: neither `invalid PKCS#12 password (MAC mismatch)` nor `PKCS#12 decryption failed` may exist anywhere under `crates/zsign-wasm/src` or `crates/zsign-cli/src`. Pinned by Task 2 W4 (grep step) and Task 3's equivalent grep step.

---

### Task 1: Core — typed `p12_load_error` at both flatten sites

**Files:**
- Modify: `crates/zsign-core/src/crypto/pkcs12.rs` (insert directly after `pem_load_error`, ends `:833`)
- Modify: `crates/zsign-core/src/crypto/cert.rs:709-710` (`load_p12` flatten) and `:771-772` (`from_p12_with_leaf_sha1_impl` flatten)
- Test: `crates/zsign-core/src/crypto/cert.rs` inline tests (beside `test_from_p12_invalid_data` `:1367` and the `from_p12_with_leaf_sha1` tests `:1470+`)

**Interfaces:**
- Consumes: `P12Error` (`pkcs12.rs:72-93`), `Error::InvalidPassword` / `Error::Certificate(String)` (`crates/zsign-core/src/error.rs`).
- Produces: `pub(crate) fn p12_load_error(e: P12Error) -> Error` — Tasks 2/3 depend on the resulting *behavior* (wrong p12 password → `Err(Error::InvalidPassword)`), not on the name; nothing outside `zsign-core` calls it.

- [ ] **Step 1: Write the failing tests**

Add to `crates/zsign-core/src/crypto/cert.rs` inline tests:

```rust
#[test]
fn from_p12_wrong_password_is_invalid_password() {
    let res = SigningCredentials::from_p12(IDENTITY_DUP, "wrong-password");
    assert!(
        matches!(&res, Err(Error::InvalidPassword)),
        "a wrong p12 password must be InvalidPassword, got {:?}",
        res.as_ref().err()
    );
}

#[test]
fn from_p12_with_leaf_sha1_wrong_password_is_invalid_password() {
    let res = SigningCredentials::from_p12_with_leaf_sha1(
        IDENTITY_DUP,
        "wrong-password",
        &[0u8; 20],
    );
    assert!(
        matches!(&res, Err(Error::InvalidPassword)),
        "the leaf selector must not change the password class, got {:?}",
        res.as_ref().err()
    );
}
```

Upgrade the existing corrupt-container test (its meaning — reject garbage — is preserved; the assertion gains the class pin):

```rust
// was: assert!(result.is_err());
assert!(
    matches!(&result, Err(Error::Certificate(m)) if m.contains("Failed to parse PKCS#12")),
    "a corrupt container must keep its certificate class, got {:?}",
    result.as_ref().err()
);
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-core wrong_password_is_invalid_password test_from_p12_invalid_data`
Expected: the two new tests FAIL (`InvalidPassword` vs `Certificate` mismatch) and `test_from_p12_invalid_data` FAILS (bare `is_err()` upgrade passes only if the class is right — it is `Certificate` today so this specific one may PASS at this step; the two new tests are the red set). Record actual output.

- [ ] **Step 3: Implement `p12_load_error` in `pkcs12.rs`**

Insert after `pem_load_error` (`pkcs12.rs:833`):

```rust
/// Translates a container failure into the credential error a caller
/// reports. MAC verification failure and password-derived decryption
/// failure are passphrase outcomes; malformed or unsupported containers
/// keep their certificate class with the same wrapper text the PKCS#12
/// loaders have always produced.
pub(crate) fn p12_load_error(e: P12Error) -> Error {
    match e {
        P12Error::Mac | P12Error::Decrypt(_) => Error::InvalidPassword,
        other => Error::Certificate(format!("Failed to parse PKCS#12: {other}")),
    }
}
```

- [ ] **Step 4: Rewire both flatten sites**

Replace each `.map_err(|e| Error::Certificate(format!("Failed to parse PKCS#12: {}", e)))` with `.map_err(super::pkcs12::p12_load_error)` — exactly two sites (`cert.rs:709-710`, `:771-772`). Touch nothing else in those functions.

- [ ] **Step 5: Run scoped tests to verify they pass**

Run: `TMPDIR=$PWD/target/tmp cargo test -p zsign-core`
Expected: PASS (all core tests; baseline core count grows by the two new tests).

- [ ] **Step 6: Commit**

Run: `git add crates/zsign-core/src/crypto/pkcs12.rs crates/zsign-core/src/crypto/cert.rs && git commit -m "fix(core): classify p12 mac and decrypt failures as invalid password"`

---

### Task 2: Wasm — typed `p12_err`, delete the substring sniffer

**Files:**
- Modify: `crates/zsign-wasm/src/lib.rs:182-199` (`p12_err` doc comment + body)
- Test: `crates/zsign-wasm/src/lib.rs:1202-1225` (`p12_classifier_maps_password_layer_failures`, rewritten)

**Interfaces:**
- Consumes: Task 1's behavior (wrong p12 password → `zsign_core::Error::InvalidPassword`); `code_for_core_error` `lib.rs:135-154` (arm at `:141` already exists — do not touch).
- Produces: `fn p12_err(e: zsign_core::Error) -> JsValue` with unchanged signature (caller at `:286` untouched).

- [ ] **Step 1: Rewrite the classifier test with typed inputs**

Replace the three hand-built `Error::Certificate` cases in
`p12_classifier_maps_password_layer_failures` (`lib.rs:1202-1225`):

```rust
#[wasm_bindgen_test]
fn p12_classifier_maps_password_layer_failures() {
    let pw = zsign_core::Error::InvalidPassword;
    assert_eq!(
        error_code(&p12_err(pw)),
        Some("ZSIGN_INVALID_PASSWORD".into())
    );
    let other = zsign_core::Error::Certificate(
        "Failed to parse PKCS#12: malformed PKCS#12: value length exceeds input".into(),
    );
    assert_eq!(
        error_code(&p12_err(other)),
        Some("ZSIGN_INVALID_CERTIFICATE".into())
    );
}
```

- [ ] **Step 2: Run wasm native tests to verify red**

Run: `TMPDIR=$PWD/target/tmp cargo test -p zsign-wasm`
Expected: FAIL — `p12_err(Error::InvalidPassword)` currently falls through to `code_for_core_error`… note for the implementer: if this PASSES already (the `:141` arm means the typed input may map correctly even before the rewrite), the red evidence for this task is instead **the deleted literals**: the old test body still *constructs* the marker strings, which the design forbids. Record which of the two you observed.

- [ ] **Step 3: Replace `p12_err` doc comment and body**

New comment + body exactly as in spec §4.3: typed match on
`zsign_core::Error::InvalidPassword` → `WasmErrorCode::InvalidPassword`,
`other => code_for_core_error(&other)`, then `js_err(code, e)`. The two
substring literals at `:190-191` disappear with the old body.

- [ ] **Step 4: Run wasm native tests to verify green**

Run: `TMPDIR=$PWD/target/tmp cargo test -p zsign-wasm`
Expected: PASS.

- [ ] **Step 5: Run wasm-pack suite**

Run: `TMPDIR=$PWD/target/tmp wasm-pack test --node crates/zsign-wasm`
Expected: 29 passed (count unchanged — this task adds no tests).

- [ ] **Step 6: Verify sniffer literals are gone**

Run: `grep -rn "invalid PKCS#12 password\|PKCS#12 decryption failed" crates/zsign-wasm/src`
Expected: no output (exit 1). If anything matches, delete it — the literals must end up gone.

- [ ] **Step 7: Commit**

Run: `git add crates/zsign-wasm/src/lib.rs && git commit -m "fix(wasm): branch p12 error mapping on typed invalid password"`

---

### Task 3: CLI — typed `resolve_p12_password`, delete its sniffer

**Files:**
- Modify: `crates/zsign-cli/Cargo.toml` (`[dependencies]`)
- Modify: `crates/zsign-cli/src/main.rs:958-985` (`resolve_p12_password`)
- Test: `crates/zsign-cli/src/main.rs:1577` and `:1628-1632` (two adapted assertions; everything else unmodified)

**Interfaces:**
- Consumes: Task 1's behavior; `zsign_core::Error::InvalidPassword` (new direct dependency).
- Produces: unchanged `fn resolve_p12_password(cli: &Cli, data: &[u8]) -> Result<String, Box<dyn std::error::Error>>` signature; the prompt/hint/verbatim dispatch behavior is the contract.

- [ ] **Step 1: Add the direct dependency**

In `crates/zsign-cli/Cargo.toml` `[dependencies]`, add (the dev-dependency with `test-fixtures` stays as-is — mirrors `zsign-wasm`'s arrangement):

```toml
zsign-core = { path = "../zsign-core", version = "0.1.0" }
```

- [ ] **Step 2: Adapt the two message assertions (red first)**

`argv_password_beats_env_password` (`main.rs:1577`):

```rust
assert!(
    env_only.stderr.contains("Invalid password for private key or PKCS#12"),
    "stderr: {}",
    env_only.stderr
);
```

`missing_password_on_non_tty_degrades_to_clear_error` (`main.rs:1628-1632`) — substitute the same
substring in the real-cause assertion; the `--password` and `ZSIGN_PASSWORD` assertions in that
test stay byte-identical:

```rust
assert!(
    r.stderr.contains("Invalid password for private key or PKCS#12"),
    "must surface the real cause: {}",
    r.stderr
);
```

- [ ] **Step 3: Run CLI tests to verify red**

Run: `TMPDIR=$PWD/target/tmp cargo test -p zsign-cli`
Expected: FAIL — `missing_password_on_non_tty_degrades_to_clear_error` fails on the hint assertions (sniffer no longer fires: current code still sniffs the old markers), `argv_password_beats_env_password` fails on the adapted substring. Record actual output.

- [ ] **Step 4: Rewrite `resolve_p12_password`**

Replace `main.rs:961-970` with the spec §4.4 shape: keep the trial `Result`, compute
`let password_shaped = matches!(&trial, Err(zsign_core::Error::InvalidPassword));` **before**
consuming `trial` for its text, return `Ok("")` on `Ok`, surface `Err(e.to_string())` verbatim
when not password-shaped. TTY-prompt and non-TTY-hint arms below (`:972-984`) stay untouched,
including their `trial_err` text usage. Update the comment at `:966` (it references "the same two
markers the wasm adapter sniffs" — now false) and the doc comment `:953-957` ("password-shaped"
now means the typed variant; keep the behavioral promises wording aligned: prompt only on a
password failure, other failures verbatim).

- [ ] **Step 5: Run CLI tests to verify green**

Run: `TMPDIR=$PWD/target/tmp cargo test -p zsign-cli`
Expected: PASS (count unchanged).

- [ ] **Step 6: Verify CLI sniffer literals are gone**

Run: `grep -rn "invalid PKCS#12 password\|PKCS#12 decryption failed" crates/zsign-cli/src`
Expected: no output (exit 1).

- [ ] **Step 7: Commit**

Run: `git add crates/zsign-cli/Cargo.toml crates/zsign-cli/src/main.rs && git commit -m "fix(cli): classify p12 password failures by variant not message"`

---

### Task 4: Full gates

**Files:** none (verification only; fix-forward in the owning task if red).

- [ ] **Step 1: Format + clippy**

Run: `cargo fmt --all -- --check` then `cargo clippy --workspace --all-targets -- -D warnings`
Expected: both clean (zero-warning gate).

- [ ] **Step 2: Workspace suite**

Run: `TMPDIR=$PWD/target/tmp cargo test --workspace`
Expected: all pass; baseline 785 + 2 new core tests = **787 passed / 1+12 ignored** (adjust to actual if the baseline drifted; report the number, never drop tests).

- [ ] **Step 3: wasm-pack suite**

Run: `TMPDIR=$PWD/target/tmp wasm-pack test --node crates/zsign-wasm`
Expected: 29 passed.

- [ ] **Step 4: Report**

Paste verbatim gate output in the final report. No commit unless Step 1-3 required fixes.
