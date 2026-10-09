# Reject Non-Regular Files in Bundle Scan — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development (recommended) with dispatching-parallel-agents for independent tasks to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fail the bundle scan in bounded time with a typed error when a walked entry is not a regular file, directory, or symlink, so a FIFO in a bundle can no longer hang signing.

**Architecture:** First, `FsStore` classifies honestly: a new `StoreKind::NonRegular` plus one private `classify(&std::fs::FileType)` helper replaces the four fallback chains (`list`, `metadata`, `walk`, `walk_pruned`), making `StoreKind::File` mean regular file. Then `hash_entry` rejects `NonRegular` after `should_exclude` with the established `Error::Core(zsign_core::Error::Signing(String))` refusal, before the UTF-8 check and before any hashing. The store change is classification only — each consumer owns its reject/skip policy.

**Tech Stack:** Rust (edition 2021), `walkdir` for traversal, `rayon` scan arms, `tempfile` fixtures; unix-only FIFO fixtures via `std::process::Command::new("mkfifo")` (POSIX-mandated utility) and sockets via `std::os::unix::net::UnixListener` — no new dependencies.

**Spec:** `docs/superpowers/specs/2026-10-09-reject-nonregular-files-in-scan-design.md`

## Global Constraints

- Only two files may change: `crates/zsign/src/store.rs` (enum variant, classifier, tests, doc comments) and `crates/zsign/src/bundle/code_resources.rs` (gate, tests, doc comments). No edits to any `Cargo.toml`, `crates/zsign/src/error.rs`, `crates/zsign/src/verify.rs`, `crates/zsign/src/ipa/`, `crates/zsign-core/`, `crates/zsign-wasm/`, `crates/zsign-cli/`, or `crates/zsign/src/macho/`.
- No ticket IDs anywhere: not in code, comments, doc text, commit subjects, or commit bodies.
- Error shape is fixed: `Error::Core(zsign_core::Error::Signing(String))` with the message exactly prefixed `Unsupported file type (not a regular file, directory, or symlink): ` followed by `path.display()`.
- The gate runs AFTER `should_exclude`; excluded entries are never type-validated; the directory short-circuit stays first in `hash_entry`.
- `StoreKind::NonRegular` is classification only; its doc comment must state that each consumer decides whether to reject or skip such entries.
- FIFO/socket tests must be `#[cfg(unix)]`; fixtures use `mkfifo` via `std::process::Command` and `UnixListener` — no `libc`/`nix` dev-dependencies.
- Every `cargo test` run uses `TMPDIR=$PWD/target/tmp` (create with `mkdir -p target/tmp` first; `/tmp` is a small tmpfs on this machine).
- Zero-warning gate before completion: `cargo fmt --all -- --check` and `cargo clippy --workspace --all-targets -- -D warnings`, plus the affected crates' tests and `hk check --all`.
- Commit convention: `type(scope): imperative lowercase subject, no trailing period`; commit locally, never push.

## Review Focus

1. A FIFO anywhere in the bundle: `scan()` must return within bounded time with the typed error and never open the FIFO — pinned by `test_scan_bundle_rejects_fifo_without_blocking` (Task 2, Step 1), whose worker-thread + `recv_timeout(10s)` harness fails the suite instead of hanging it.
2. Gate placement: a FIFO under an excluded directory must scan cleanly — pinned by `test_scan_bundle_ignores_excluded_non_regular_entry` (Task 2, Step 1).
3. Classification breadth: FIFO and unix socket must classify as `NonRegular` through `metadata`, `list`, `walk`, and `walk_pruned` — pinned by `fifo_classifies_as_non_regular_in_every_reporting_method` and `unix_socket_classifies_as_non_regular` (Task 1, Step 1).
4. No collateral change to regular files, directories, or symlinks: kind pins in `regular_file_and_dir_keep_their_kinds` / `symlink_classifies_as_symlink` (Task 1, Step 1) plus the full-crate run (Task 2, Step 6).
5. Error-text drift: consumers and tests match on the message, so the rejection test asserts the exact substring `Unsupported file type` (Task 2, Step 1).

---

### Task 1: Honest non-regular classification in `FsStore`

**Files:**
- Modify: `crates/zsign/src/store.rs` — `StoreKind` enum (`:12-17`), the four classification chains (`list` `:118-124`, `metadata` `:131-137`, `walk` `:178-184`, `walk_pruned`'s `kind_of` `:198-205`), plus a new test module appended at end of file (the file has no test module today).

**Interfaces:**
- Consumes: `std::fs::FileType::is_symlink/is_dir/is_file` predicates (`is_file` is `S_ISREG` on unix); `std::fs::Metadata::file_type()`; `walkdir::DirEntry::file_type()` (returns `FileType`, not `Result`); `std::fs::DirEntry::file_type()` (returns `Result<FileType>`).
- Produces: `StoreKind::NonRegular` (fourth enum variant); private `fn classify(ft: &std::fs::FileType) -> StoreKind` in `store.rs`; observable behavior — `FsStore::{metadata, list, walk, walk_pruned}` report `NonRegular` for FIFO/socket/device entries, and `StoreKind::File` now means regular file. Task 2 consumes `kind == StoreKind::NonRegular` in `hash_entry`.

- [ ] **Step 1: Write the failing classification tests**

Append a test module to `crates/zsign/src/store.rs` (imports mirror the crate's test style; `Path`, `StoreKind`, `StoreStat`, `FsStore`, and the `Store` trait are all in scope via `use super::*`):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    /// `mkfifo` is a POSIX-mandated utility, so no crate dependency is needed.
    #[cfg(unix)]
    fn make_fifo(path: &Path) {
        let status = std::process::Command::new("mkfifo")
            .arg(path)
            .status()
            .expect("mkfifo must be on PATH");
        assert!(
            status.success(),
            "mkfifo must create the FIFO at {}",
            path.display()
        );
    }

    #[test]
    fn regular_file_and_dir_keep_their_kinds() {
        let td = tempdir().unwrap();
        let root = td.path().join("bundle");
        let sub = root.join("sub");
        fs::create_dir_all(&sub).unwrap();
        let file = sub.join("a.txt");
        fs::write(&file, b"x").unwrap();

        assert_eq!(
            FsStore.metadata(&file).unwrap().kind,
            StoreKind::File,
            "regular files must stay File"
        );
        assert_eq!(
            FsStore.metadata(&sub).unwrap().kind,
            StoreKind::Dir,
            "directories must stay Dir"
        );

        let listed = FsStore.list(&root).unwrap();
        let listed_kind = listed.iter().find(|(n, _)| n == "sub").map(|(_, k)| *k);
        assert_eq!(
            listed_kind,
            Some(StoreKind::Dir),
            "list must keep classifying directories as Dir, got {listed:?}"
        );

        let walked = FsStore.walk(&root).unwrap();
        let walk_kind = walked
            .iter()
            .filter_map(|e| e.as_ref().ok())
            .find(|(p, _)| p == &file)
            .map(|(_, k)| *k);
        assert_eq!(
            walk_kind,
            Some(StoreKind::File),
            "walk must keep classifying regular files as File"
        );
    }

    #[test]
    #[cfg(unix)]
    fn symlink_classifies_as_symlink() {
        let td = tempdir().unwrap();
        let root = td.path().join("bundle");
        fs::create_dir(&root).unwrap();
        let target = root.join("real.txt");
        fs::write(&target, b"x").unwrap();
        let link = root.join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        assert_eq!(
            FsStore.metadata(&link).unwrap().kind,
            StoreKind::Symlink,
            "metadata must not follow the final symlink"
        );
        let walked = FsStore.walk(&root).unwrap();
        let walk_kind = walked
            .iter()
            .filter_map(|e| e.as_ref().ok())
            .find(|(p, _)| p == &link)
            .map(|(_, k)| *k);
        assert_eq!(
            walk_kind,
            Some(StoreKind::Symlink),
            "walk must classify symlinks as Symlink"
        );
    }

    #[test]
    #[cfg(unix)]
    fn fifo_classifies_as_non_regular_in_every_reporting_method() {
        let td = tempdir().unwrap();
        let root = td.path().join("bundle");
        fs::create_dir(&root).unwrap();
        let fifo = root.join("odd.pipe");
        make_fifo(&fifo);

        let stat = FsStore.metadata(&fifo).unwrap();
        assert_eq!(
            stat.kind,
            StoreKind::NonRegular,
            "metadata must classify a FIFO as non-regular, got {:?}",
            stat.kind
        );
        assert!(!stat.is_file(), "a FIFO must not answer is_file");
        assert!(!stat.is_dir(), "a FIFO must not answer is_dir");
        assert!(!stat.is_symlink(), "a FIFO must not answer is_symlink");

        let listed = FsStore.list(&root).unwrap();
        let listed_kind = listed.iter().find(|(n, _)| n == "odd.pipe").map(|(_, k)| *k);
        assert_eq!(
            listed_kind,
            Some(StoreKind::NonRegular),
            "list must classify a FIFO as non-regular, got {listed:?}"
        );

        let walked = FsStore.walk(&root).unwrap();
        let walk_kind = walked
            .iter()
            .filter_map(|e| e.as_ref().ok())
            .find(|(p, _)| p == &fifo)
            .map(|(_, k)| *k);
        assert_eq!(
            walk_kind,
            Some(StoreKind::NonRegular),
            "walk must classify a FIFO as non-regular"
        );

        let pruned = FsStore.walk_pruned(&root, &|_, _| true).unwrap();
        let pruned_kind = pruned
            .iter()
            .filter_map(|e| e.as_ref().ok())
            .find(|(p, _)| p == &fifo)
            .map(|(_, k)| *k);
        assert_eq!(
            pruned_kind,
            Some(StoreKind::NonRegular),
            "walk_pruned must classify a FIFO as non-regular"
        );
    }

    #[test]
    #[cfg(unix)]
    fn unix_socket_classifies_as_non_regular() {
        let td = tempdir().unwrap();
        let sock = td.path().join("app.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();

        let stat = FsStore.metadata(&sock).unwrap();
        assert_eq!(
            stat.kind,
            StoreKind::NonRegular,
            "metadata must classify a unix socket as non-regular, got {:?}",
            stat.kind
        );
    }
}
```

- [ ] **Step 2: Run the tests to verify the type-level failure**

Run: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-rs store::tests`
Expected: FAIL to compile — `no variant or associated item named `NonRegular` found for enum `StoreKind``, because the tests pin the new variant before it exists (the red for an enum addition).

- [ ] **Step 3: Add the variant, the classifier, and rewire the four sites**

In `crates/zsign/src/store.rs`:

1. Add the fourth variant with its doc comment to `StoreKind` (`:12-17`):

```rust
pub(crate) enum StoreKind {
    File,
    Dir,
    Symlink,
    /// Anything lstat reports that is not a regular file, directory, or
    /// symlink (FIFO, socket, device node). Classification only — whether a
    /// consumer rejects or skips entries of this kind is that consumer's
    /// policy. `File` always means a regular file.
    NonRegular,
}
```

2. Add a private classifier directly above `impl Store for FsStore`:

```rust
/// Lstat-style classification of one filesystem file type: `File` means a
/// regular file (`S_ISREG`); anything that is neither that, a directory, nor
/// a symlink is [`StoreKind::NonRegular`].
fn classify(ft: &std::fs::FileType) -> StoreKind {
    if ft.is_symlink() {
        StoreKind::Symlink
    } else if ft.is_dir() {
        StoreKind::Dir
    } else if ft.is_file() {
        StoreKind::File
    } else {
        StoreKind::NonRegular
    }
}
```

3. Replace each fallback chain with `classify`:
   - `list` (`:118-124`): keep `let ft = entry.file_type()?;`, then push `(entry.file_name().to_string_lossy().into_owned(), classify(&ft))`.
   - `metadata` (`:131-137`): `let kind = classify(&md.file_type());`.
   - `walk` (`:178-184`): keep `let ft = entry.file_type();` (walkdir returns `FileType` directly), then push `Ok((entry.path().to_path_buf(), classify(&ft)))`.
   - `walk_pruned` (`:197-205`): delete the local `kind_of` closure and call `classify(&e.file_type())` in `filter_entry` and `classify(&entry.file_type())` in the yield.

- [ ] **Step 4: Run the classification tests to verify they pass**

Run: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-rs store::tests`
Expected: all four tests PASS (the two unix pins now see `NonRegular`; the portable kind pins confirm the refactor changed nothing for regular files and directories).

- [ ] **Step 5: Run the whole crate's tests**

Run: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-rs`
Expected: all PASS — every consumer of `StoreKind` is a comparison (audited in the spec), so no caller breaks; the `CFBundleExecutable` regular-file check and the dylib-discovery gates keep their fixtures green.

- [ ] **Step 6: Run the scoped gates**

Run: `cargo fmt --all -- --check` then `cargo clippy --workspace --all-targets -- -D warnings`
Expected: both clean, zero warnings.

- [ ] **Step 7: Commit Task 1**

Controller commits exactly `crates/zsign/src/store.rs` with subject `fix(store): classify non-regular files as a distinct kind` (no ticket ID, no trailing period). Never push.

---

### Task 2: Fail-closed scan gate for non-regular entries

**Files:**
- Modify: `crates/zsign/src/bundle/code_resources.rs` — `hash_entry` (gate inserted after the `should_exclude` filter at `:229-231`, before the UTF-8 name check at `:236-244`), `scan()`'s `# Errors` list (append after the entry-name bullet at `:153`), `hash_entry`'s doc comment (`:207-209`), and the test module (append at end).

**Interfaces:**
- Consumes: `StoreKind::NonRegular` from Task 1; `path.strip_prefix(bundle_path)` and `inner.should_exclude(&str)` as they stand; `Error` and `Result` already imported at the top of the file; `Error::Core(zsign_core::Error::Signing(String))`, the same rejection shape the UTF-8 guards use.
- Produces: unchanged signatures — `fn hash_entry(store: &dyn Store, bundle_path: &Path, inner: &zsign_core::bundle::CodeResourcesBuilder, path: &Path, kind: StoreKind) -> Result<Option<ScannedEntry>>` and `pub fn scan(&mut self) -> Result<&mut Self>`. New observable behavior: `scan()` returns `Err(Error::Core(zsign_core::Error::Signing(..)))` whose message contains `Unsupported file type` for any bundle containing a non-regular entry that is not excluded. No public API changes.

- [ ] **Step 1: Write the failing bounded-time scan tests**

Append to the test module in `crates/zsign/src/bundle/code_resources.rs` (same imports/style as the landed symlink and UTF-8 tests; `fs`, `tempdir`, `Error`, `Result`, and `CodeResourcesBuilder` are already in scope):

```rust
    #[test]
    #[cfg(unix)]
    fn test_scan_bundle_rejects_fifo_without_blocking() {
        use std::sync::mpsc;
        use std::time::Duration;

        let temp_dir = tempdir().unwrap();
        let bundle_path = temp_dir.path().join("Test.app");
        fs::create_dir(&bundle_path).unwrap();
        fs::write(
            bundle_path.join("Info.plist"),
            b"<?xml version=\"1.0\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n<key>CFBundleExecutable</key>\n<string>Test</string>\n</dict>\n</plist>",
        )
        .unwrap();
        let fifo = bundle_path.join("odd.pipe");
        let status = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap();
        assert!(
            status.success(),
            "mkfifo must create the FIFO at {}",
            fifo.display()
        );

        // A regression opens the FIFO and blocks forever, so the scan runs on
        // a worker thread and the assertion is bounded: the suite fails on
        // timeout instead of hanging.
        let (tx, rx) = mpsc::channel();
        let scanned = bundle_path.clone();
        std::thread::spawn(move || {
            let result = (|| -> Result<()> {
                let mut builder = CodeResourcesBuilder::new(&scanned)?;
                builder.scan()?;
                Ok(())
            })();
            let _ = tx.send(result);
        });
        let result = rx
            .recv_timeout(Duration::from_secs(10))
            .expect("scan must not block on a FIFO");
        assert!(
            matches!(&result, Err(Error::Core(zsign_core::Error::Signing(m)))
                if m.contains("Unsupported file type")),
            "a FIFO in the bundle must fail the scan with the typed error, got {:?}",
            result.err()
        );
    }

    #[test]
    #[cfg(unix)]
    fn test_scan_bundle_ignores_excluded_non_regular_entry() {
        let temp_dir = tempdir().unwrap();
        let bundle_path = temp_dir.path().join("Test.app");
        fs::create_dir(&bundle_path).unwrap();
        let excluded_dir = bundle_path.join("Skipper");
        fs::create_dir(&excluded_dir).unwrap();
        let fifo = excluded_dir.join("pipe");
        let status = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap();
        assert!(
            status.success(),
            "mkfifo must create the FIFO at {}",
            fifo.display()
        );

        let mut builder = CodeResourcesBuilder::new(&bundle_path).unwrap();
        builder.exclude("Skipper/");
        builder
            .scan()
            .expect("excluded entries are never sealed, so their types are never validated");
        assert!(
            builder.files().all(|(p, _, _)| !p.starts_with("Skipper/")),
            "excluded entries must not be sealed"
        );
    }
```

- [ ] **Step 2: Run the FIFO test to verify it fails**

Run: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-rs test_scan_bundle_rejects_fifo_without_blocking`
Expected: FAIL after ~10 seconds — the worker blocks in `hash_file_streaming`'s `store.open` on the writerless FIFO (the walk now classifies it `NonRegular`, but `hash_entry` has no gate yet), so the main thread panics with `scan must not block on a FIFO`. The suite does not hang. The exclusion test passes both before and after the change; it pins the gate's placement.

- [ ] **Step 3: Implement the gate and the doc updates**

In `crates/zsign/src/bundle/code_resources.rs`:

1. In `hash_entry`, insert this gate between the `should_exclude` early return (`:229-231`) and the UTF-8 name conversion (`:236-244`):

```rust
        // A non-regular entry (FIFO, socket, device node) has no seal shape
        // and can never be streamed: opening a writerless FIFO blocks
        // forever. Fail closed before hashing; excluded entries never reach
        // this gate because they are never sealed.
        if kind == StoreKind::NonRegular {
            return Err(Error::Core(zsign_core::Error::Signing(format!(
                "Unsupported file type (not a regular file, directory, or symlink): {}",
                path.display()
            ))));
        }
```

2. Append one bullet to `scan()`'s `# Errors` list, after the entry-name bullet (`:153`):

```rust
    /// - A bundle entry is not a regular file, directory, or symlink (it cannot be hashed safely)
```

3. Extend `hash_entry`'s doc comment (`:207-209`) so its final sentence reads:

```rust
    /// Fails when the entry name is not valid UTF-8 or the entry is not a
    /// regular file, directory, or symlink; excluded entries are exempt
    /// because they are never sealed.
```

- [ ] **Step 4: Run the scan tests to verify they pass**

Run: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-rs test_scan_bundle`
Expected: all PASS — `test_scan_bundle_rejects_fifo_without_blocking` now receives the typed error well inside the 10-second bound, and the exclusion pin stays green.

- [ ] **Step 5: Run the whole crate's tests**

Run: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-rs`
Expected: all PASS — regular-file sealing, the symlink trio, and the UTF-8 trio are untouched by the gate.

- [ ] **Step 6: Run the scoped gates**

Run: `cargo fmt --all -- --check` then `cargo clippy --workspace --all-targets -- -D warnings`
Expected: both clean, zero warnings.

- [ ] **Step 7: Commit Task 2**

Controller commits exactly `crates/zsign/src/bundle/code_resources.rs` with subject `fix(bundle): reject non-regular files before hashing` (no ticket ID, no trailing period). Never push.

---

### Completion gates (controller, after both tasks)

- [ ] `cargo fmt --all -- --check` — clean.
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` — zero warnings.
- [ ] `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-core -p zsign-rs` — all PASS (affected crates).
- [ ] `hk check --all` — the land gate; all checks pass.
