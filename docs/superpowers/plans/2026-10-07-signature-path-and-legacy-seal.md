# Signature-Path Skip and Legacy-Seal Symlink Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development (recommended) with dispatching-parallel-agents for independent tasks to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop the bundle walk from skipping lookalike `_CodeSignature`
paths, and route legacy `files` raw-hash entries through the hardened entry
verifier so final-component symlinks are `mismatched` instead of followed.

**Architecture:** One line in the walk swap a substring test for a
component-exact test on the root-relative `rel_path`; the `files` loop's
raw-Data branch synthesizes a `{"hash": …}` dict and delegates to
`verify_code_resource_entry`, deleting the inline canonicalize/read/compare
block. Two fail-first tests in the same file.

**Tech Stack:** Rust 2021, inline `#[cfg(test)]` tests reusing
`build_signed_bundle_with`, `rewrite_code_resources`, `fixtures::make_minimal_macho`.

**Spec:** `docs/superpowers/specs/2026-10-07-signature-path-and-legacy-seal-design.md`

## Global Constraints

- Single file of record: `crates/zsign/src/verify.rs`. No other file may
  change.
- Walk skip becomes exactly
  `rel_path.components().any(|c| c.as_os_str() == "_CodeSignature")` — on
  `rel_path` (root-relative `&Path`), never `rel_dir`, never a substring or
  bare `starts_with`.
- Legacy delegation: raw-Data entries become
  `{"hash": <bytes>}` dicts passed to `verify_code_resource_entry` with the
  same `bundle`, `bundle_real`, `rel`, `out`, `rules`, `errors` arguments;
  the entire inline branch (safe-key check through SHA-1 compare) is deleted;
  the existing non-Data delegate call becomes the single unified call.
- New error/outcome vocabulary: symlink-sealed-path → `out.mismatched`
  (from the helper, not newly written); no new error strings, no new
  top-level `errors` pushes.
- No ticket IDs anywhere; no new deps; no stubs/TODOs; module docs
  unchanged (they already promise this behavior); repo AGENTS.md assertion
  footer convention (`got {:?}` / actual values).

## Review Focus

- Delegation equivalence: for a raw SHA-1 entry the helper must reproduce
  containment (same escapes text), rule-gated `missing` on NotFound parent
  or file, Io-error propagation, and SHA-1-only matching — the ds_store
  files-only test and optional/missing rule tests are the existing sentinels;
  any of them turning red means an equivalence line in the spec is wrong.
- The skip must remain skip-on-component-at-any-depth: nested signature dirs
  (`Frameworks/Sub.framework/_CodeSignature/…`) were skipped before and must
  still be skipped — a regression here silently verifies no signatures; no
  existing test covers it, so the judgment lives in the exact one-line form
  pinned above.
- Test 1 must fail only on the walk skip (not on Item-1 structural errors):
  the planted binary is sealed by the pre-sign setup, so no
  `seals no files`/`unsealed` noise appears; assert membership plus a
  present Mach-O report, not `report.valid()` (anchor-gated).
- Test 2 must fail only on the missing guard: the rewrite breaks slot -3, so
  assert at the CodeResources layer (`cr.mismatched`), never `report.valid()`.
- Lookalike collision in the other direction: `X_CodeSignature` components
  must NOT be treated as `_CodeSignature` (exact component equality, no
  prefix matching).

---

### Task 1: Failing regression tests

**Files:**
- Modify: `crates/zsign/src/verify.rs` (tests `mod tests`, appended after
  `symlink_parent_traversal_is_rejected`)

**Interfaces:**
- Consumes: `build_signed_bundle_with(dir, setup)`, `rewrite_code_resources(app, mutate)`,
  `verify_bundle(&app)`, `fixtures::make_minimal_macho()`, top-level
  `sha1::Sha1` + `sha2` `Digest` imports, `std::os::unix::fs::symlink`.
- Produces: two tests Task 2 must turn GREEN without touching them.

- [ ] **Step 1: Write the two failing tests**

```rust
#[test]
fn macho_under_x_codesign_directory_is_verified() {
    let td = tempfile::TempDir::new().unwrap();
    let (app, _) = build_signed_bundle_with(td.path(), |app| {
        fs::create_dir_all(app.join("X_CodeSignature")).unwrap();
        fs::write(
            app.join("X_CodeSignature").join("App"),
            fixtures::make_minimal_macho(),
        )
        .unwrap();
    });
    let report = verify_bundle(&app).unwrap();
    let bundle = report.bundle.as_ref().unwrap();
    let planted = bundle
        .binaries
        .iter()
        .find(|b| b.path.starts_with("X_CodeSignature/"));
    let planted = planted.unwrap_or_else(|| {
        panic!(
            "lookalike signature dir must not hide binaries; binaries: {:?}",
            bundle
                .binaries
                .iter()
                .map(|b| b.path.as_str())
                .collect::<Vec<_>>()
        )
    });
    assert!(
        planted.report.is_some(),
        "planted Mach-O must be slice-verified, got {:?}",
        planted
    );
}

#[cfg(unix)]
#[test]
fn legacy_files_symlink_is_mismatched() {
    use std::os::unix::fs::symlink;
    let td = tempfile::TempDir::new().unwrap();
    let outside = td.path().join("outside");
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("secret.txt"), b"outside content").unwrap();
    // The builder seals symlinks only in files2 (legacy format has no
    // symlink shape), so this signs cleanly.
    let (app, _) = build_signed_bundle_with(td.path(), |app| {
        symlink(outside.join("secret.txt"), app.join("Leak")).unwrap();
    });
    // Attacker rewrites the seal: raw SHA-1 in legacy `files` (the inline
    // arm), key absent from files2 so the legacy arm processes it.
    rewrite_code_resources(&app, |dict| {
        let files2 = dict.get_mut("files2").unwrap().as_dictionary_mut().unwrap();
        let _ = files2.remove("Leak");
        let files = dict.get_mut("files").unwrap().as_dictionary_mut().unwrap();
        files.insert(
            "Leak".to_string(),
            plist::Value::Data(Sha1::digest(b"outside content").to_vec()),
        );
    });
    let report = verify_bundle(&app).unwrap();
    let cr = report
        .bundle
        .as_ref()
        .unwrap()
        .code_resources
        .as_ref()
        .unwrap();
    assert!(
        cr.mismatched.iter().any(|m| m == "Leak"),
        "legacy symlink must be mismatched, never hashed through; \
         mismatched={:?} missing={:?} matched={}",
        cr.mismatched,
        cr.missing,
        cr.matched
    );
}
```

- [ ] **Step 2: Run the tests to confirm both fail for their own reasons**

Run: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-rs verify::tests`
Expected: `macho_under_x_codesign_directory_is_verified` FAIL
("lookalike signature dir must not hide binaries"), `legacy_files_symlink_is_mismatched`
FAIL ("legacy symlink must be mismatched" — it reports `matched` instead),
every other `verify::tests` test PASS. Any other failure: STOP and report.

---

### Task 2: Component-exact skip + legacy delegation

**Files:**
- Modify: `crates/zsign/src/verify.rs`

**Interfaces:**
- Consumes: `rel_path` (`&Path`, root-relative) in the walk; the existing
  `verify_code_resource_entry(bundle, &bundle_real, rel, entry, &mut out,
  &rules, errors)` delegate call; `entry.as_data()` raw-Data detection;
  Task 1's two tests.
- Produces: no signature changes anywhere; both Task 1 tests GREEN.

- [ ] **Step 1: Replace the substring skip**

In `verify_bundle_dir`'s walk, replace

```rust
if rel_str.contains("_CodeSignature/") {
    continue;
}
```

with

```rust
if rel_path.components().any(|c| c.as_os_str() == "_CodeSignature") {
    continue;
}
```

(`rel_path` is the root-relative `&Path` computed two lines above; `rel_str`
keeps its other uses — do not reorder them.)

- [ ] **Step 2: Delegate raw-Data legacy entries; delete the inline arm**

In `check_code_resources`'s `files` loop, replace the whole
`if let Some(sealed_hash) = entry.as_data() { … inline canonicalize/read/SHA-1 … }
else { verify_code_resource_entry(…) }` pair with one unified call:

```rust
let synthesized;
let entry_value = match entry.as_data() {
    Some(sealed_hash) => {
        let mut legacy = plist::Dictionary::new();
        legacy.insert("hash".to_string(), plist::Value::Data(sealed_hash.to_vec()));
        synthesized = plist::Value::Dictionary(legacy);
        &synthesized
    }
    None => entry,
};
verify_code_resource_entry(
    bundle, &bundle_real, rel, entry_value, &mut out, &rules, errors,
)?;
```

The entire inline block (safe-key check, `file_path`/`parent` construction,
canonicalize-parent match, `std::fs::read` match, SHA-1 compare) is deleted —
the helper already contains the same containment text, rule-gated `missing`
handling, and Io propagation, plus the `symlink_metadata` guard this fix
adds. Keep the existing `files2`-contains-key skip above unchanged.

- [ ] **Step 3: Green the regression tests**

Run: `TMPDIR=$PWD/target/tmp cargo test -p zsign-rs verify::tests`
Expected: all pass, including both Task 1 tests (planted binary collected
with a report; `Leak` in `cr.mismatched`).

- [ ] **Step 4: Run the broader crate suite for equivalence**

Run: `TMPDIR=$PWD/target/tmp cargo test -p zsign-rs`
Expected: full crate green — the delegation-equivalence sentinels
(`nested_ds_store_is_not_flagged_unsealed`,
`legacy_sha1_only_entry_verifies`, `optional_lproj_deletion_after_signing_stays_valid`,
`base_lproj_deletion_is_not_optional`, `omitted_locversion_deletion_stays_valid`,
`symlink_parent_traversal_is_rejected`, nested/framework/IPA suites) all
stay green. Any failure means an equivalence claim in the spec is wrong —
STOP and report it with the failing output.

---

### Task 3: Zero-warning gate

**Files:** none modified; verification only.

- [ ] **Step 1: Formatting**

Run: `cargo fmt --all -- --check`
Expected: no output, exit 0. If new code is unformatted, `cargo fmt --all`
(reformats only this change) and re-check.

- [ ] **Step 2: Clippy**

Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: no warnings, exit 0.

- [ ] **Step 3: Workspace tests**

Run: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test --workspace`
Expected: all PASS.

---

## Self-review

- Spec coverage: gap 1 → Task 2 Step 1 (+ test 1); gap 2 → Task 2 Step 2
  (+ test 2); delegation equivalence → Task 2 Step 4 sentinel list; acceptance
  → Tasks 1-3 verification steps.
- Step scan: each step one checkable action; the only body the signature and
  assertions do not fix is the synthesized-dict match, shown verbatim.
- Type consistency: `entry_value: &plist::Value` both arms;
  `verify_code_resource_entry` argument list matches its definition
  (`verify.rs:610-617`); `rel_path.components()` valid on `&Path`.
- Review Focus: each line maps to a step — equivalence (Step 4 sentinels +
  spec table), nested-skip preservation (exact pinned one-liner, Step 1),
  test-1 isolation to the walk skip (pre-sign sealing + membership-only
  assertion, Task 1 Step 1), test-2 CR-layer assertion (Task 1 Step 1),
  lookalike non-collision (exact component equality, Step 1).
- Proportion: plan shorter than spec; no step restates a fixed body.
