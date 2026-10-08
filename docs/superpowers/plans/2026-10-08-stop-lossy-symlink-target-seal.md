# Stop Lossy Symlink Targets in the Seal — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development (recommended) with dispatching-parallel-agents for independent tasks to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the seal record a symlink target byte-identical to disk by failing the scan with a typed error when the target is not valid UTF-8, instead of recording a lossy string.

**Architecture:** All changes live in `crates/zsign/src/bundle/code_resources.rs`. `hash_symlink_entry` validates the raw target bytes with `String::from_utf8` before recording; failure propagates through the existing `Result` chain as `Error::Core(zsign_core::Error::Signing(String))`. The core plist writer, the verifier, the wasm surface, and the store layer are untouched — the plist value stays a `<string>`, which is the Apple-compatible shape.

**Tech Stack:** Rust (edition 2021), `plist` crate for test parsing, `tempfile` fixtures, unix-only symlink fixtures via `std::os::unix::fs::symlink`.

**Spec:** `docs/superpowers/specs/2026-10-08-stop-lossy-symlink-target-seal-design.md`

## Global Constraints

- Only `crates/zsign/src/bundle/code_resources.rs` may change. No edits to `crates/zsign/src/error.rs`, `crates/zsign/src/verify.rs`, `crates/zsign/src/store.rs`, `crates/zsign-wasm/`, `crates/zsign-core/`, or `crates/zsign/src/ipa/`.
- No ticket IDs anywhere: not in code, comments, doc text, commit subjects, or commit bodies.
- Error shape is fixed: `Error::Core(zsign_core::Error::Signing(String))` with message exactly prefixed `Symlink target is not valid UTF-8: ` followed by `path.display()`.
- The plist value for `symlink` must remain `Value::String` (no `<data>`).
- No symlink containment/escape logic, no file-name encoding changes, no FIFO/kind handling, no archive or extraction changes — those are other workstreams.
- Tests that touch the filesystem must use `#[cfg(unix)]` and raw-byte symlink fixtures created with `std::os::unix::fs::symlink` over `OsStr::from_bytes`, bypassing `FsStore::symlink`'s own UTF-8 gate.
- Every test run uses `TMPDIR=$PWD/target/tmp` (create with `mkdir -p target/tmp` first; `/tmp` is a small tmpfs).
- Zero-warning gate before completion: `cargo fmt --all -- --check` and `cargo clippy --workspace --all-targets -- -D warnings`, plus the crate's tests and `hk check --all`.
- Commit message convention: `fix(bundle): <imperative lowercase subject, no trailing period>`; never push.

## Review Focus

1. **Invalid-UTF-8 target at scan time** (`real\xFFtarget` bytes): `scan()` must return the pinned typed error and no plist can be built — pinned by `test_scan_bundle_rejects_non_utf8_symlink_target` (Task 1, Step 1).
2. **Same invalid bytes under an excluded path**: `scan()` must succeed — validation applies to sealed entries only, preserving `should_exclude` precedence at `code_resources.rs:228` — pinned by `test_scan_bundle_ignores_excluded_non_utf8_symlink_target` (Task 1, Step 5).
3. **Valid-UTF-8 non-ASCII target containing a literal U+FFFD**: the built plist's `files2` entry must hold a string byte-identical to the on-disk target (no mangling in either direction) — pinned by `test_scan_bundle_records_exact_utf8_symlink_target` (Task 1, Step 5).
4. **Error-text drift**: consumers and tests match on the message, so the rejection test asserts the exact substring `Symlink target is not valid UTF-8` (Task 1, Step 1).
5. **Regression of ordinary symlink sealing**: ASCII/UTF-8 targets must keep sealing exactly as before — pinned by requiring the pre-existing `test_scan_bundle_with_symlinks` to stay green in the full-crate run (Task 1, Step 6).

---

### Task 1: Fail-closed symlink target validation

**Files:**
- Modify: `crates/zsign/src/bundle/code_resources.rs` — `hash_symlink_entry` (~lines 300-308), the `SymlinkHashes` doc comment (~lines 34-36), and the test module (append three tests after `test_scan_bundle_with_symlinks`, ~line 502).

**Interfaces:**
- Consumes: `Store::read_link(&self, path: &Path) -> Result<Vec<u8>>` (`crates/zsign/src/store.rs:84`, raw bytes); `zsign_core::bundle::CodeResourcesBuilder::hash_data(&[u8]) -> ([u8; 20], [u8; 32])`; `crate::Error` / `crate::Result` already imported at the top of the file; the existing `should_exclude` filtering in `hash_entry`.
- Produces: unchanged signature `fn hash_symlink_entry(store: &dyn Store, path: &Path) -> Result<SymlinkHashes>` — the `SymlinkHashes` tuple type stays `([u8; 20], [u8; 32], String)`, with the invariant that the `String` is now byte-exact. No public API changes. Nothing external depends on new names.

- [ ] **Step 1: Write the failing rejection test**

Append to the test module in `crates/zsign/src/bundle/code_resources.rs` (same imports/style as `test_scan_bundle_with_symlinks`):

```rust
#[test]
#[cfg(unix)]
fn test_scan_bundle_rejects_non_utf8_symlink_target() {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::symlink;

    let temp_dir = tempdir().unwrap();
    let bundle_path = temp_dir.path().join("Test.app");
    fs::create_dir(&bundle_path).unwrap();

    let link_path = bundle_path.join("LinkToFile.txt");
    symlink(
        std::ffi::OsStr::from_bytes(b"real\xFFtarget"),
        &link_path,
    )
    .unwrap();

    let mut builder = CodeResourcesBuilder::new(&bundle_path).unwrap();
    let res = builder.scan();
    assert!(
        matches!(&res, Err(Error::Core(zsign_core::Error::Signing(m)))
            if m.contains("Symlink target is not valid UTF-8")),
        "non-UTF-8 symlink target must fail the seal, got {:?}",
        res.as_ref().err()
    );
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-rs test_scan_bundle_rejects_non_utf8_symlink_target`
Expected: FAIL — `scan()` currently succeeds (the lossy conversion at `:306` records `real\u{FFFD}target`), so the `matches!` assertion panics with the `got Ok(...)` footer.

- [ ] **Step 3: Implement fail-closed validation in `hash_symlink_entry`**

Replace the body of `hash_symlink_entry` in `crates/zsign/src/bundle/code_resources.rs` (the function spanning current lines 300-308) so that hashing still covers the raw bytes, then the bytes are consumed by a strict UTF-8 conversion whose failure maps to the pinned typed error:

```rust
/// Hash a symlink by hashing its raw target bytes; a target that is not
/// valid UTF-8 is rejected so the recorded string always equals the bytes
/// on disk.
fn hash_symlink_entry(store: &dyn Store, path: &Path) -> Result<SymlinkHashes> {
    // `FsStore::read_link` serves the raw target bytes on unix and
    // reproduces this fn's non-unix rejection on other platforms.
    let target_bytes = store.read_link(path)?;
    let (sha1, sha256) = zsign_core::bundle::CodeResourcesBuilder::hash_data(&target_bytes);
    let target_str = String::from_utf8(target_bytes).map_err(|_| {
        zsign_core::Error::Signing(format!(
            "Symlink target is not valid UTF-8: {}",
            path.display()
        ))
    })?;
    Ok((sha1, sha256, target_str))
}
```

(`?` converts the core error via the existing `From<zsign_core::Error> for Error` impl, yielding `Error::Core(..)`. Order matters: `hash_data` must borrow the bytes before `String::from_utf8` consumes them.)

Also update the `SymlinkHashes` doc comment at lines 34-35 from "plus the lossy string form recorded in the plist" to:

```rust
/// Hash of a symlink's raw target bytes, plus the exact UTF-8 form recorded
/// in the plist (byte-identical to the target on disk; non-UTF-8 targets are
/// rejected by the scan).
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-rs test_scan_bundle_rejects_non_utf8_symlink_target`
Expected: PASS.

- [ ] **Step 5: Add the exclusion-precedence and exactness tests**

Append to the same test module:

```rust
#[test]
#[cfg(unix)]
fn test_scan_bundle_ignores_excluded_non_utf8_symlink_target() {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::symlink;

    let temp_dir = tempdir().unwrap();
    let bundle_path = temp_dir.path().join("Test.app");
    fs::create_dir(&bundle_path).unwrap();
    let excluded_dir = bundle_path.join("Excluded");
    fs::create_dir(&excluded_dir).unwrap();

    symlink(
        std::ffi::OsStr::from_bytes(b"real\xFFtarget"),
        excluded_dir.join("Link.txt"),
    )
    .unwrap();

    let mut builder = CodeResourcesBuilder::new(&bundle_path).unwrap();
    builder.exclude("Excluded/");
    builder
        .scan()
        .expect("excluded entries are never sealed, so their targets are never validated");
}

#[test]
#[cfg(unix)]
fn test_scan_bundle_records_exact_utf8_symlink_target() {
    use std::os::unix::fs::symlink;

    const TARGET: &str = "dir/targ\u{00E9}\u{FFFD}\u{65E5}";

    let temp_dir = tempdir().unwrap();
    let bundle_path = temp_dir.path().join("Test.app");
    fs::create_dir(&bundle_path).unwrap();

    symlink(TARGET, bundle_path.join("LinkUnicode.txt")).unwrap();

    let mut builder = CodeResourcesBuilder::new(&bundle_path).unwrap();
    builder.scan().unwrap();
    let plist_data = builder.build().unwrap();

    let value: plist::Value = plist::from_bytes(&plist_data).unwrap();
    let files2 = value
        .as_dictionary()
        .and_then(|d| d.get("files2"))
        .and_then(|v| v.as_dictionary())
        .expect("files2 dictionary");
    let recorded = files2
        .get("LinkUnicode.txt")
        .and_then(|v| v.as_dictionary())
        .and_then(|d| d.get("symlink"))
        .and_then(|v| v.as_string());
    assert_eq!(
        recorded,
        Some(TARGET),
        "recorded symlink target must be byte-identical to the on-disk target"
    );
}
```

Verify `exclude`'s actual signature in the file before running (it appears in the module docs as `builder.exclude("DebugResources/")`) and adjust the call shape (`&mut self` vs consuming) if needed — the behavior pinned here is that `Excluded/` entries are filtered before `hash_symlink_entry` runs.

- [ ] **Step 6: Run the whole crate's tests**

Run: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-rs`
Expected: all PASS, including the pre-existing `test_scan_bundle_with_symlinks` (ASCII/UTF-8 sealing unchanged).

- [ ] **Step 7: Run the scoped gates**

Run: `cargo fmt --all -- --check` then `cargo clippy --workspace --all-targets -- -D warnings`
Expected: both clean, zero warnings.

- [ ] **Step 8: Commit**

Controller commits exactly `crates/zsign/src/bundle/code_resources.rs` with subject `fix(bundle): stop recording lossy symlink targets in the seal` (no ticket ID, no trailing period). Never push.
