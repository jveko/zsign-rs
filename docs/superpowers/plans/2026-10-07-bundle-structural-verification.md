# Bundle Structural Verification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development (recommended) with dispatching-parallel-agents for independent tasks to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make bundle verification reject a deleted declared main executable, a
zero-Mach-O bundle, and a CodeResources that seals nothing — by pushing three
structural errors, following the existing `missing _CodeSignature/CodeResources`
convention.

**Architecture:** All three checks live in the one shared recursion:
`verify_bundle_dir` gains a walk-time flag for the declared executable plus two
post-walk error pushes; `check_code_resources` gains an empty-`sealed_set` push.
`valid()`, `problem_count`, CLI output, `--json` DTOs, and `verify_ipa` need no
changes.

**Tech Stack:** Rust 2021, inline `#[cfg(test)]` tests in
`crates/zsign/src/verify.rs`, existing helpers `build_signed_bundle`,
`app_info_plist`, `fixtures::make_minimal_macho`, `ZSign`, `plist` XML writer.

**Spec:** `docs/superpowers/specs/2026-10-07-bundle-structural-verification-design.md`

## Global Constraints

- Single file of record: `crates/zsign/src/verify.rs`. No other file may change.
- Exact error strings (pinned): `declared main executable "<exe>" not found in
  the bundle` (formatted), `bundle contains no Mach-O binaries`,
  `CodeResources seals no files`.
- Executable match is exact bundle-relative path equality
  (`rel_dir.to_string_lossy().replace('\\', "/") == exe`), never stem matching.
- Sealed-set emptiness is evaluated on `files2 ∪ files`, after both dicts are
  folded into `sealed_set`, and only on the path where `files2` was present.
- No ticket IDs in code, comments, docs, or tests. No new dependencies. No
  stubs/TODOs. Repo AGENTS.md applies (error-assert footer prints the actual
  failure; `TMPDIR=$PWD/target/tmp` for tests).

## Review Focus

- Deleting the executable must produce a report (exit 1), not a hard `Err` —
  pinned by `deleted_main_executable_is_invalid` asserting `!report.valid()`
  on an `Ok` report.
- The empty-seal check must not fire on legitimate minimal signed bundles whose
  `files2` is empty but legacy `files` seals `Info.plist` — pinned by
  `minimal_signed_bundle_verifies`.
- The disk pass must stay clean for the hand-built fixture (no accidental
  `unsealed` noise masking which check fired) — the zero-Mach-O test asserts
  the two new error strings specifically.
- The declared-executable check must not false-positive at nested levels
  (`Sub.framework` declares `Sub`) — covered by existing
  `signed_bundle_verifies` / `tampered_nested_binary_is_detected_by_nested_frame`
  staying green.
- No existing test may regress toward exit 2: pushes go to
  `BundleVerification.errors`, never `VerifyReport.errors`.

---

### Task 1: Failing regression tests

**Files:**
- Modify: `crates/zsign/src/verify.rs` (tests `mod tests`, appended after
  `verify_ipa_rejects_unsigned_bundle`)

**Interfaces:**
- Consumes: `build_signed_bundle(dir) -> (PathBuf, SigningCredentials)`,
  `app_info_plist() -> Vec<u8>` (declares `CFBundleExecutable` = `Test`),
  `crate::test_util::test_credentials_with_key()`,
  `fixtures::make_minimal_macho()`, `ZSign::new().credentials(..).sign_bundle(&app, None)`,
  `verify_bundle(&app) -> Result<VerifyReport>` (`report.valid()`,
  `report.bundle.errors`).
- Produces: three tests that Task 2's error pushes must satisfy; no production
  code changes.

- [ ] **Step 1: Write the three failing/guard tests**

Append to `crates/zsign/src/verify.rs` `mod tests`:

```rust
#[test]
fn deleted_main_executable_is_invalid() {
    let td = tempfile::TempDir::new().unwrap();
    let (app, _) = build_signed_bundle(td.path());
    // Dual-pin at the bundle layer: report.valid() is anchor-gated for test
    // credentials, so it cannot express the precondition.
    let before = verify_bundle(&app).unwrap();
    let bb = before.bundle.as_ref().unwrap();
    assert!(bb.errors.is_empty(), "precondition: bundle errors: {:?}", bb.errors);
    assert!(!bb.binaries.is_empty(), "precondition: signed bundle has binaries");
    assert!(
        bb.code_resources.as_ref().is_some_and(|c| c.valid()),
        "precondition: code resources: {:?}", bb.code_resources
    );
    fs::remove_file(app.join("Test")).unwrap();
    let report = verify_bundle(&app).unwrap();
    let bundle = report.bundle.as_ref().unwrap();
    assert!(
        bundle.errors.iter().any(|e| e.contains("declared main executable") && e.contains("\"Test\"")),
        "missing-executable error expected, got {:?}", bundle.errors
    );
}

#[test]
fn zero_macho_empty_seal_bundle_is_invalid() {
    let td = tempfile::TempDir::new().unwrap();
    let app = td.path().join("Hand.app");
    fs::create_dir_all(app.join("_CodeSignature")).unwrap();
    fs::write(
        app.join("Info.plist"),
        br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleIdentifier</key><string>com.zsign.hand</string>
</dict></plist>
"#,
    )
    .unwrap();
    let mut info_omit = plist::Dictionary::new();
    info_omit.insert("omit".to_string(), plist::Value::Boolean(true));
    info_omit.insert("weight".to_string(), plist::Value::Real(20.0));
    let mut rules2 = plist::Dictionary::new();
    rules2.insert("^.*".to_string(), plist::Value::Boolean(true));
    rules2.insert("^Info\\.plist$".to_string(), plist::Value::Dictionary(info_omit));
    let mut rules = plist::Dictionary::new();
    rules.insert("^.*".to_string(), plist::Value::Boolean(true));
    let mut cr = plist::Dictionary::new();
    cr.insert("files".to_string(), plist::Value::Dictionary(plist::Dictionary::new()));
    cr.insert("files2".to_string(), plist::Value::Dictionary(plist::Dictionary::new()));
    cr.insert("rules".to_string(), plist::Value::Dictionary(rules));
    cr.insert("rules2".to_string(), plist::Value::Dictionary(rules2));
    let mut buf = Vec::new();
    plist::to_writer_xml(&mut buf, &plist::Value::Dictionary(cr)).unwrap();
    fs::write(app.join("_CodeSignature").join("CodeResources"), buf).unwrap();

    let report = verify_bundle(&app).unwrap();
    assert!(!report.valid(), "zero-Mach-O empty-seal bundle must be invalid, got {:?}", report.bundle);
    let bundle = report.bundle.as_ref().unwrap();
    assert!(
        bundle.errors.iter().any(|e| e.contains("no Mach-O binaries")),
        "empty-binaries error expected, got {:?}", bundle.errors
    );
    assert!(
        bundle.errors.iter().any(|e| e.contains("seals no files")),
        "empty-seal error expected, got {:?}", bundle.errors
    );
}

#[test]
fn minimal_signed_bundle_verifies() {
    let td = tempfile::TempDir::new().unwrap();
    let app = td.path().join("Min.app");
    fs::create_dir_all(&app).unwrap();
    fs::write(app.join("Info.plist"), app_info_plist()).unwrap();
    fs::write(app.join("Test"), fixtures::make_minimal_macho()).unwrap();
    let (creds, _rsa_key) = crate::test_util::test_credentials_with_key();
    ZSign::new().credentials(creds).sign_bundle(&app, None).unwrap();
    // Dual-pin: report.valid() is anchor-gated for test credentials.
    let report = verify_bundle(&app).unwrap();
    let bundle = report.bundle.as_ref().unwrap();
    assert!(bundle.errors.is_empty(), "minimal signed bundle must stay free of structural errors: {:?}", bundle.errors);
    assert!(!bundle.binaries.is_empty(), "the executable must be verified");
    let cr = bundle.code_resources.as_ref().expect("CodeResources check");
    assert!(cr.valid(), "mismatched={:?} missing={:?} unsealed={:?}", cr.mismatched, cr.missing, cr.unsealed);
}
```

- [ ] **Step 2: Run the tests to confirm fail-before/pass-before split**

Run: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-rs verify::tests`
Expected: `deleted_main_executable_is_invalid` FAIL ("missing-executable
error expected" — no error is pushed yet),
`zero_macho_empty_seal_bundle_is_invalid` FAIL ("must be invalid"),
`minimal_signed_bundle_verifies` PASS under its bundle-layer pins, all
pre-existing tests PASS. If any
pre-existing test fails at this step, stop and report — the fixture assumption
is wrong.

---

### Task 2: Structural error pushes

**Files:**
- Modify: `crates/zsign/src/verify.rs` (`verify_bundle_dir`, `check_code_resources`)

**Interfaces:**
- Consumes: `main_executable: Option<String>` (already resolved at
  `verify.rs:428-430`), `rel_dir` (bundle-relative path already computed at the
  top of the walk body), `direct_binaries: Vec<(PathBuf, String)>`,
  `sealed_set: BTreeSet<String>` (built immediately before the sealed→disk
  pass), `out.errors` / `errors: &mut Vec<String>`.
- Produces: the three pinned error strings Task 1 asserts; no type or
  signature changes.

- [ ] **Step 1: Track the declared executable during the walk**

In `verify_bundle_dir`, before its collection walk — the `for entry in
WalkDir…` loop that pushes onto `direct_binaries` (verify.rs ~436-466), **not**
the `check_code_resources` disk walk — add:

```rust
let mut found_main_executable = false;
```

Inside the walk's file arm, in the `if is_macho_file(p)? { … }` block that pushes
onto `direct_binaries`, add before/alongside the push:

```rust
if let Some(exe) = &main_executable {
    if rel_dir.to_string_lossy().replace('\\', "/") == *exe {
        found_main_executable = true;
    }
}
```

- [ ] **Step 2: Push the two post-walk bundle errors**

Immediately after the walk loop (before the "Verify each direct binary"
comment block):

```rust
if let Some(exe) = &main_executable {
    if !found_main_executable {
        out.errors
            .push(format!("declared main executable \"{exe}\" not found in the bundle"));
    }
}
if direct_binaries.is_empty() {
    out.errors.push("bundle contains no Mach-O binaries".to_string());
}
```

- [ ] **Step 3: Push the empty-seal error**

In `check_code_resources`, immediately after the two `sealed_set.extend(...)`
blocks:

```rust
if sealed_set.is_empty() {
    errors.push("CodeResources seals no files".to_string());
}
```

- [ ] **Step 4: Green the regression tests**

Run: `TMPDIR=$PWD/target/tmp cargo test -p zsign-rs verify::tests`
Expected: all tests in the module PASS, including Task 1's two formerly
failing tests and `minimal_signed_bundle_verifies`.

- [ ] **Step 5: Run the broader crate suite for false rejections**

Run: `TMPDIR=$PWD/target/tmp cargo test -p zsign-rs`
Expected: PASS — signed fixtures, IPA end-to-end, nested/framework/symlink
cases all stay green (every zsign-signed level has its executable at exactly
`bundle/<exe>` and a non-empty `files2 ∪ files`).

---

### Task 3: Zero-warning gate

**Files:** none modified; verification only.

- [ ] **Step 1: Formatting**

Run: `cargo fmt --all -- --check`
Expected: no output, exit 0.

- [ ] **Step 2: Clippy**

Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: no warnings, exit 0.

- [ ] **Step 3: Workspace tests**

Run: `TMPDIR=$PWD/target/tmp cargo test --workspace`
Expected: all PASS (wasm crate's native unit tests included;
`wasm-pack test` is not part of this gate).

---

## Self-review

- Spec coverage: all three checks, both gaps, the signer-asymmetry mirror, and
  the `verify_ipa` path (shared recursion) each map to Task 1 assertions and
  Task 2 steps; acceptance = Task 1 Step 2 split + Task 3 gate.
- Step scan: every step is one action with a checkable result; the only code
  bodies are the three pushes, which the pinned strings and Task 1 assertions
  fully determine.
- Type consistency: `found_main_executable: bool`, `main_executable:
  Option<String>`, `exe: &String` via `&main_executable`; matches existing
  bindings in scope.
- Review Focus: each line maps to a test — exit-1 report (Task 1 test 1), union
  emptiness (Task 1 test 3), clean disk pass (Task 1 test 2 error-specific
  assertions), nested-level no-false-positive (existing suite, Task 2 Step 5),
  no exit-2 drift (errors pushed to `out.errors`, Task 3 Step 3).
- Proportion: plan length tracks the spec; no task repeats bodies the
  assertions already pin.
