# Reject Non-UTF-8 Seal Map Keys — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development (recommended) with dispatching-parallel-agents for independent tasks to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fail the bundle scan with a typed error when an entry name is not valid UTF-8, so two distinct on-disk names can never collapse onto one seal-map key and silently unseal a file.

**Architecture:** The guard lives in the facade's `hash_entry` — the single site where walked paths become seal-map keys — after `should_exclude`, using `Path::to_str()`; failure surfaces as the established `Error::Core(zsign_core::Error::Signing(String))` refusal. The core map, verifier, wasm surface, CLI, store, and ipa writer are untouched except for two doc-comment lines in core that record the map's last-write-wins semantics.

**Tech Stack:** Rust (edition 2021), `plist` crate for test parsing, `tempfile` fixtures, unix-only raw-byte name fixtures via `std::os::unix::ffi::OsStrExt`.

**Spec:** `docs/superpowers/specs/2026-10-08-reject-nonutf8-seal-map-keys-design.md`

## Global Constraints

- Only two files may change: `crates/zsign/src/bundle/code_resources.rs` (guard, tests, doc comments) and `crates/zsign-core/src/bundle/code_resources.rs` (doc comments only — no code changes). No edits to `crates/zsign/src/error.rs`, `crates/zsign/src/verify.rs`, `crates/zsign/src/store.rs`, `crates/zsign/src/ipa/`, `crates/zsign-wasm/`, `crates/zsign-cli/`, `crates/zsign/src/macho/`, or any core code other than the two doc comments.
- No ticket IDs anywhere: not in code, comments, doc text, commit subjects, or commit bodies.
- Error shape is fixed: `Error::Core(zsign_core::Error::Signing(String))` with message exactly prefixed `File name is not valid UTF-8: ` followed by `path.display()`.
- The guard runs AFTER `should_exclude`; excluded entries are never validated; the lossy conversion remains only as the exclusion-matching input.
- No changes to `hash_symlink_entry` or its landed target guard; no verifier, store, wasm, or CLI behavior changes.
- Tests that create non-UTF-8 names must be `#[cfg(unix)]` and build fixtures from `std::ffi::OsStr::from_bytes`.
- Every `cargo test` run uses `TMPDIR=$PWD/target/tmp` (create with `mkdir -p target/tmp` first; `/tmp` is a small tmpfs on this machine).
- Zero-warning gate before completion: `cargo fmt --all -- --check` and `cargo clippy --workspace --all-targets -- -D warnings`, plus the affected crates' tests and `hk check --all`.
- Commit convention: `type(scope): imperative lowercase subject, no trailing period`; commit locally, never push.

## Review Focus

1. Two distinct non-UTF-8 names (`bad\xFF.dat`, `bad\xFE.dat`) collapsing onto one lossy key: `scan()` must return the pinned typed error and no seal can be built — pinned by `test_scan_bundle_rejects_colliding_non_utf8_file_names` (Task 1, Step 1).
2. The same class of bytes under an excluded directory: `scan()` must still succeed — the guard must sit after `should_exclude` — pinned by `test_scan_bundle_ignores_excluded_non_utf8_file_name` (Task 1, Step 5).
3. Valid-UTF-8 names, including a literal U+FFFD character and multibyte CJK: must NOT be rejected and must seal under byte-identical keys — pins that `to_str()` rejects invalid bytes, not the replacement character — pinned by `test_scan_bundle_seals_exact_utf8_file_names` (Task 1, Step 5).
4. Error-text drift: consumers and tests match on the message, so the rejection test asserts the exact substring `File name is not valid UTF-8` (Task 1, Step 1).
5. Regression of ordinary sealing and the landed symlink tests: the full-crate run (Task 1, Step 6) must stay green, including `test_scan_bundle_with_symlinks`, `test_scan_bundle_rejects_non_utf8_symlink_target`, `test_scan_bundle_ignores_excluded_non_utf8_symlink_target`, and `test_scan_bundle_records_exact_utf8_symlink_target`.

---

### Task 1: Fail-closed file-name validation at the key derivation

**Files:**
- Modify: `crates/zsign/src/bundle/code_resources.rs` — `hash_entry` (conversion chain and exclusion filter, current lines `:219-232`) and the test module (append after `test_scan_bundle_records_exact_utf8_symlink_target`, which ends ~`:593`).

**Interfaces:**
- Consumes: `path.strip_prefix(bundle_path)` returning `Result<&Path, StripPrefixError>`; `inner.should_exclude(&str) -> bool` (`crates/zsign-core/src/bundle/code_resources.rs:420`); `crate::{Error, Result}` already imported at the top of the file; `From<zsign_core::Error> for Error` (`crates/zsign/src/error.rs:62-70`), which hoists unknown core variants into `Error::Core(..)`.
- Produces: unchanged signatures — `fn hash_entry(store: &dyn Store, bundle_path: &Path, inner: &zsign_core::bundle::CodeResourcesBuilder, path: &Path, kind: StoreKind) -> Result<Option<ScannedEntry>>` and `pub fn scan(&mut self) -> Result<&mut Self>`; `ScannedEntry.path: String` (`:44`) is now guaranteed valid UTF-8. New observable behavior: `scan()` returns `Err(Error::Core(zsign_core::Error::Signing(..)))` whose message contains `File name is not valid UTF-8` for any bundle with a non-UTF-8 entry name. No public API changes.

- [ ] **Step 1: Write the failing collision test**

Append to the test module in `crates/zsign/src/bundle/code_resources.rs` (same imports/style as the landed symlink tests; `fs`, `tempdir`, `Error`, and `CodeResourcesBuilder` are already in scope via the module's `use` lines):

```rust
#[test]
#[cfg(unix)]
fn test_scan_bundle_rejects_colliding_non_utf8_file_names() {
    use std::os::unix::ffi::OsStrExt;

    let temp_dir = tempdir().unwrap();
    let bundle_path = temp_dir.path().join("Test.app");
    fs::create_dir(&bundle_path).unwrap();

    // Two distinct byte names whose lossy forms are identical, so before the
    // guard the second insert silently overwrites the first.
    fs::write(
        bundle_path.join(std::ffi::OsStr::from_bytes(b"bad\xFF.dat")),
        b"first",
    )
    .unwrap();
    fs::write(
        bundle_path.join(std::ffi::OsStr::from_bytes(b"bad\xFE.dat")),
        b"second",
    )
    .unwrap();

    let mut builder = CodeResourcesBuilder::new(&bundle_path).unwrap();
    let res = builder.scan();
    assert!(
        matches!(&res, Err(Error::Core(zsign_core::Error::Signing(m)))
            if m.contains("File name is not valid UTF-8")),
        "distinct non-UTF-8 names must not collapse onto one seal key, got {:?}",
        res.as_ref().err()
    );
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-rs test_scan_bundle_rejects_colliding_non_utf8_file_names`
Expected: FAIL — `scan()` currently succeeds (both names lossy-convert to `bad\u{FFFD}.dat` and the second `BTreeMap::insert` silently overwrites the first), so the assertion panics with `distinct non-UTF-8 names must not collapse onto one seal key, got None`.

- [ ] **Step 3: Implement the guard in `hash_entry`**

In `crates/zsign/src/bundle/code_resources.rs`, replace the lossy conversion chain and exclusion filter (current lines `:219-232`) so the exclusion check keeps the lossy form and the seal key comes from a strict conversion that fails closed. The `strip_prefix` error mapping is unchanged:

```rust
        let relative_path = path
            .strip_prefix(bundle_path)
            .map_err(|e| {
                Error::Io(std::io::Error::other(format!(
                    "Failed to strip prefix: {}",
                    e
                )))
            })?;

        if inner.should_exclude(&relative_path.to_string_lossy()) {
            return Ok(None);
        }

        // A lossy key would collapse distinct invalid byte sequences onto
        // U+FFFD, letting one entry overwrite another in the seal map.
        let relative_path = relative_path
            .to_str()
            .ok_or_else(|| {
                zsign_core::Error::Signing(format!(
                    "File name is not valid UTF-8: {}",
                    path.display()
                ))
            })?
            .to_string();
```

(`?` converts `zsign_core::Error` through the existing `From` impl into `Error::Core(..)`, the same path the landed `hash_symlink_entry` guard uses. `&Cow<str>` deref-coerces to the `&str` that `should_exclude` takes, so exclusion matching is byte-identical to today for every valid-UTF-8 name.)

- [ ] **Step 4: Run the test to verify it passes**

Run: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-rs test_scan_bundle_rejects_colliding_non_utf8_file_names`
Expected: PASS.

- [ ] **Step 5: Add the exclusion-precedence and exactness tests**

Append to the same test module:

```rust
#[test]
#[cfg(unix)]
fn test_scan_bundle_ignores_excluded_non_utf8_file_name() {
    use std::os::unix::ffi::OsStrExt;

    let temp_dir = tempdir().unwrap();
    let bundle_path = temp_dir.path().join("Test.app");
    fs::create_dir(&bundle_path).unwrap();
    let excluded_dir = bundle_path.join("Excluded");
    fs::create_dir(&excluded_dir).unwrap();

    fs::write(
        excluded_dir.join(std::ffi::OsStr::from_bytes(b"junk\xFF.tmp")),
        b"ignored",
    )
    .unwrap();

    let mut builder = CodeResourcesBuilder::new(&bundle_path).unwrap();
    builder.exclude("Excluded/");
    builder
        .scan()
        .expect("excluded entries are never sealed, so their names are never validated");
}

#[test]
fn test_scan_bundle_seals_exact_utf8_file_names() {
    let temp_dir = tempdir().unwrap();
    let bundle_path = temp_dir.path().join("Test.app");
    fs::create_dir(&bundle_path).unwrap();

    const NAMES: [&str; 3] = [
        "r\u{00E9}.txt",
        "u\u{FFFD}n.txt",
        "\u{65E5}\u{672C}.txt",
    ];
    for name in NAMES {
        fs::write(bundle_path.join(name), name.as_bytes()).unwrap();
    }

    let mut builder = CodeResourcesBuilder::new(&bundle_path).unwrap();
    builder.scan().unwrap();
    let plist_data = builder.build().unwrap();

    let value: plist::Value = plist::from_bytes(&plist_data).unwrap();
    let files2 = value
        .as_dictionary()
        .and_then(|d| d.get("files2"))
        .and_then(|v| v.as_dictionary())
        .expect("files2 dictionary");
    for name in NAMES {
        assert!(
            files2.get(name).is_some(),
            "valid UTF-8 name must seal under its exact key {name}, got keys {:?}",
            files2.keys().collect::<Vec<_>>()
        );
    }
}
```

(`exclude` is `pub fn exclude(&mut self, pattern: impl Into<String>) -> &mut Self` at `:134`, so the statement call compiles as written. The second fixture name contains a literal U+FFFD on purpose: `to_str()` must accept it — only invalid *bytes* are rejected, not the replacement *character*.)

- [ ] **Step 6: Run the whole crate's tests**

Run: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-rs`
Expected: all PASS, including the pre-existing `test_scan_bundle_with_symlinks` and the landed symlink trio (`test_scan_bundle_rejects_non_utf8_symlink_target`, `test_scan_bundle_ignores_excluded_non_utf8_symlink_target`, `test_scan_bundle_records_exact_utf8_symlink_target`) — ASCII/UTF-8 sealing and symlink behavior unchanged.

- [ ] **Step 7: Run the scoped gates**

Run: `cargo fmt --all -- --check` then `cargo clippy --workspace --all-targets -- -D warnings`
Expected: both clean, zero warnings.

- [ ] **Step 8: Commit Task 1**

Controller commits exactly `crates/zsign/src/bundle/code_resources.rs` with subject `fix(bundle): reject non-utf-8 entry names in the seal map` (no ticket ID, no trailing period). Never push.

---

### Task 2: Document the seal-key invariant

**Files:**
- Modify: `crates/zsign/src/bundle/code_resources.rs` — `scan()` `#Errors` list (line `:153`, append one bullet after the symlink bullet) and the `hash_entry` doc comment (lines `:204-205`).
- Modify: `crates/zsign-core/src/bundle/code_resources.rs` — `add_file` doc comment (the paragraph ending at `:484`) and `add_symlink` doc comment (the paragraph ending at `:519`).

**Interfaces:**
- Consumes: nothing new — doc comments only, no signature or behavior change.
- Produces: rustdoc text stating the new scan failure and the map's overwrite semantics; later readers and reviewers rely on these invariants.

- [ ] **Step 1: Add the new failure to `scan()`'s `#Errors` list**

In `crates/zsign/src/bundle/code_resources.rs`, after the line `/// - A symlink target is not valid UTF-8 (the seal would otherwise differ from disk)` (`:153`) append:

```rust
    /// - An entry name is not valid UTF-8 (a lossy key could collide with another entry)
```

- [ ] **Step 2: Extend the `hash_entry` doc comment**

Replace lines `:204-205`:

```rust
    /// Hashes one walked bundle entry (or `None` when it is an excluded
    /// directory), shared verbatim by the parallel and sequential scan arms.
```

with:

```rust
    /// Hashes one walked bundle entry (or `None` when it is an excluded
    /// directory), shared verbatim by the parallel and sequential scan arms.
    /// Fails when the entry name is not valid UTF-8; excluded entries are
    /// exempt because they are never sealed.
```

- [ ] **Step 3: Record last-write-wins at the core inserts**

In `crates/zsign-core/src/bundle/code_resources.rs`, in the `add_file` doc comment insert a new paragraph between the "Returns `true` if the file was added, `false` if it was excluded by the current exclusion rules." sentence and `# Examples`:

```rust
    ///
    /// Inserting a path that is already present replaces its entry (last write
    /// wins).
```

Insert the identical paragraph at the same position in the `add_symlink` doc comment (between its "Returns `true` if the symlink was added, ..." sentence and `# Examples`).

- [ ] **Step 4: Verify the docs compile and tests stay green**

Run: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-core -p zsign-rs`
Expected: all PASS (the touched doc comments' doctests included), then `cargo fmt --all -- --check` and `cargo clippy --workspace --all-targets -- -D warnings` — both clean.

- [ ] **Step 5: Commit Task 2**

Controller commits exactly `crates/zsign/src/bundle/code_resources.rs` and `crates/zsign-core/src/bundle/code_resources.rs` with subject `docs(bundle): document utf-8 entry name refusal` (no ticket ID, no trailing period). Never push.
