# ZSN-39 Faithful IPA Re-pack Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: subagent-driven-development with dispatching-parallel-agents. Tasks are strictly sequential (later tasks share `archive.rs`/`mod.rs` machinery with earlier ones), dispatched one at a time: Tester-red → implementer-green → scoped gate → controller commit. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Make `IpaSigner::sign` output faithful to its input (root entries preserved, ambiguous multi-`.app` archives rejected, ZIP64 write support, canonical `/` names, creation-time symlink-target policy) and make `CodeResourcesBuilder::build` emit entries that agree with the rules it declares.

**Architecture:** `create_ipa` and the new crate-private `create_ipa_from_root` share one private walker (`write_tree`) in `crates/zsign/src/ipa/archive.rs`; `IpaSigner::sign` repacks the extraction root after a multi-`.app` guard. `build()` in `crates/zsign-core/src/bundle/code_resources.rs` gains a private rule resolver mirroring ZSN-26's `rule_action`/`tie_rank` (zsign-core cannot depend on zsign-rs; `verify.rs` is not editable) and derives every per-dict omission/optional flag from the winning emitted rule.

**Tech Stack:** Rust 2021, zip 7.2.0, walkdir, inline `#[cfg(test)]` tests, `tempfile::TempDir` per test.

**Gate (run after every task):**
```bash
mkdir -p .tmptmp && TMPDIR=$PWD/.tmptmp cargo test -p zsign-rs ipa -- --skip test_ipa_signing_is_deterministic
```
Task 5 also runs: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-core code_resources`
Baseline is established before Task 1 (both commands green at base, minus the skipped determinism test). Never run `cargo fmt`/`cargo clippy`/`hk`.

**Shared conventions:** errors via existing `Error` variants (`Error::Io(io::Error::new(InvalidData, …))`, `Error::Zip(zip::result::ZipError::InvalidArchive(...))`); assertions carry reason messages; test names `test_*`; ticket ID in commit subjects only, never in code comments; scope: edit ONLY `crates/zsign/src/ipa/{archive.rs,mod.rs}` and `crates/zsign-core/src/bundle/code_resources.rs` (+ their inline test modules); each task ends with the controller committing.

**Reference facts (verified at base `0f07c30`):**
- `IpaSigner::sign` = mod.rs:264-286; repack call `create_ipa(&app_bundle, output_ipa, self.compression_level)` at :283.
- `find_app_bundle` first-match loop = extract.rs:599-625 (loop :609-620, `return Ok(path)` :616); its 0-app error construction (`Error::Zip(ZipError::InvalidArchive(Cow::Borrowed(...)))`) is the pattern to mirror at :622-624.
- `create_ipa` = archive.rs:160-291; options at :207-218; `Payload/` dir entry :221; walk :222-224; name format! :237-241; dir trailing-slash :248-252; symlink branch :254-260; unix_permissions :271-276; `start_file` :278; `finish` :288.
- Test fixtures: `create_test_ipa` mod.rs:1108, `create_test_app_bundle` archive.rs:301, `test_credentials()` test_util.rs:29, `minimal_macho()` test_util.rs:9.
- `build()` = code_resources.rs:405-475; `standard_rules()` :83-113; `standard_rules2()` :119-188; `should_exclude` :252-281.

---

### Task 1 — Reject ambiguous multi-`.app` archives (commit 1)

**Files:**
- Modify: `crates/zsign/src/ipa/mod.rs` — new private helper next to `resolve_within` (~:476), call in `sign()` after `resolve_within` (:280); test module.
- [ ] **Step 1: Write the failing test**

Add to `crates/zsign/src/ipa/mod.rs` tests module:

```rust
#[test]
fn test_sign_rejects_multiple_app_bundles() {
    let temp = TempDir::new().unwrap();
    let ipa_path = temp.path().join("multi.ipa");
    let file = fs::File::create(&ipa_path).unwrap();
    let mut zip = ZipWriter::new(file);
    let options = SimpleFileOptions::default();
    zip.add_directory("Payload/", options).unwrap();
    zip.add_directory("Payload/First.app/", options).unwrap();
    zip.add_directory("Payload/Second.app/", options).unwrap();
    zip.finish().unwrap();

    let output = temp.path().join("signed.ipa");
    let err = IpaSigner::new(&crate::test_util::test_credentials())
        .sign(&ipa_path, &output)
        .expect_err("two .app bundles must be rejected");
    let msg = err.to_string();
    assert!(msg.contains("multiple .app bundles"), "actionable message: {msg}");
    assert!(
        msg.contains("First.app") && msg.contains("Second.app"),
        "candidates named: {msg}"
    );
    assert!(!output.exists(), "no output may be written for an ambiguous archive");
}
```

- [ ] **Step 2: Run the test, verify it fails for the right reason**

Run: `mkdir -p .tmptmp && TMPDIR=$PWD/.tmptmp cargo test -p zsign-rs test_sign_rejects_multiple_app_bundles`
Expected: FAIL — assertion `msg.contains("multiple .app bundles")` (today `sign()` proceeds and fails later with a missing-`Info.plist` error, or signs the first `.app` found).

- [ ] **Step 3: Implement the guard**

In `crates/zsign/src/ipa/mod.rs`, add (near `resolve_within`, before `impl` test module):

```rust
    /// Rejects archives whose `Payload/` holds more than one `.app` bundle.
    ///
    /// `extract_ipa` selects the first `Payload/*.app` it meets in `read_dir`
    /// order, so a multi-candidate archive would be signed and repacked from
    /// an arbitrary pick. Failing here names every candidate instead.
    fn ensure_single_app_bundle(payload_dir: &Path) -> Result<()> {
        let mut candidates: Vec<String> = Vec::new();
        for entry in fs::read_dir(payload_dir)? {
            let path = entry?.path();
            if path.is_dir() && path.extension().is_some_and(|ext| ext == "app") {
                if let Some(name) = path.file_name() {
                    candidates.push(name.to_string_lossy().into_owned());
                }
            }
        }
        candidates.sort();
        if candidates.len() > 1 {
            return Err(Error::Zip(zip::result::ZipError::InvalidArchive(
                std::borrow::Cow::Owned(format!(
                    "multiple .app bundles in Payload/: {}",
                    candidates.join(", ")
                )),
            )));
        }
        Ok(())
    }
```

(The `Error::Zip(ZipError::InvalidArchive(Cow::…))` construction mirrors extract.rs:622-624; the variant lives at `zip::result::ZipError` (zip 7.2.0 has no crate-root re-export) and `zip` is already a dependency of this crate. Place it as an associated fn in `impl IpaSigner` beside `resolve_within`.)

In `sign()`, **after** `Self::resolve_within(temp_dir.path(), &app_bundle)?;` (:280) — containment first, so the guard's `read_dir` never follows an unvalidated `Payload` component:

```rust
        Self::ensure_single_app_bundle(&temp_dir.path().join("Payload"))?;
```

- [ ] **Step 4: Run the scoped gate**

Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-rs ipa -- --skip test_ipa_signing_is_deterministic`
Expected: PASS, including the new test (all base ipa tests still green).

- [ ] **Step 5: Controller commit**

`fix(ipa): reject ambiguous multi-app ipa archives (ZSN-39)`

---

### Task 2 — Carry extraction-root entries through repack (commit 2)

**Files:**
- Modify: `crates/zsign/src/ipa/archive.rs` — extract a shared `write_tree` walker out of `create_ipa`'s loop, add `zip_entry_name` + `create_ipa_from_root`.
- Modify: `crates/zsign/src/ipa/mod.rs` — `sign()` repacks `temp_dir.path()`; test fixture refactor + round-trip test.

**Sequencing note:** the walker owns entry *writing*; each closure owns *naming*. `create_ipa`'s closure keeps its existing `format!("Payload/{}/{}", app_name, relative.display())` wording in this task (its migration to `zip_entry_name` is Task 4); the new `create_ipa_from_root` closure uses `zip_entry_name` from day one. No `display()`-based name is ever introduced anew.

- [ ] **Step 1: Write the failing test**

Refactor the mod.rs fixture: rename the body of `create_test_ipa` (mod.rs:1108) to `write_test_ipa(ipa_path: &Path, extras: &[(&str, &[u8])])` — same zip construction, plus after the `data.bin` entry:

```rust
        for (name, bytes) in extras {
            zip.start_file(*name, options).unwrap();
            zip.write_all(bytes).unwrap();
        }
```

and keep `create_test_ipa(dir) -> PathBuf` as `write_test_ipa(&dir.join("test.ipa"), &[])` (all existing callers unchanged). Add `use zip::ZipArchive;` to the `mod tests` import block of `mod.rs` (the existing block imports `ZipWriter`/`SimpleFileOptions` only); the block already has `use std::fs;`.

Add:

```rust
    #[test]
    fn test_sign_preserves_non_payload_entries() {
        let temp = TempDir::new().unwrap();
        let ipa_path = write_test_ipa(
            &temp.path().join("test.ipa"),
            &[
                ("SwiftSupport/iphoneos/libswiftCore.dylib", b"swift-support-bytes".as_slice()),
                ("iTunesMetadata.plist", b"<plist></plist>".as_slice()),
                ("META-INF/com.apple.ZipMetadata.plist", b"<plist></plist>".as_slice()),
            ],
        );
        let output = temp.path().join("signed.ipa");
        IpaSigner::new(&crate::test_util::test_credentials())
            .sign(&ipa_path, &output)
            .expect("signing must succeed");

        let file = fs::File::open(&output).unwrap();
        let mut archive = ZipArchive::new(file).unwrap();
        let names: Vec<String> = (0..archive.len())
            .map(|i| archive.by_index(i).unwrap().name().to_string())
            .collect();
        for expected in [
            "Payload/Test.app/Info.plist",
            "Payload/Test.app/data.bin",
            "SwiftSupport/iphoneos/libswiftCore.dylib",
            "iTunesMetadata.plist",
            "META-INF/com.apple.ZipMetadata.plist",
        ] {
            assert!(
                names.iter().any(|n| n == expected),
                "entry {expected} must survive re-signing; got {names:?}"
            );
        }

        let extracted = temp.path().join("extracted");
        extract_ipa(&output, &extracted).unwrap();
        assert!(
            extracted.join("SwiftSupport/iphoneos/libswiftCore.dylib").exists(),
            "carried entries must re-extract"
        );
    }
```

- [ ] **Step 2: Run, verify it fails**

Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-rs test_sign_preserves_non_payload_entries`
Expected: FAIL — `SwiftSupport/iphoneos/libswiftCore.dylib must survive re-signing` (today only the bundle is archived).

- [ ] **Step 3: Implement the shared walker + `create_ipa_from_root`**

In `crates/zsign/src/ipa/archive.rs`:

1. Add the name helper (documentation comment cites platform-independent construction):

```rust
/// Builds a ZIP entry name by joining `relative`'s path components with `/`.
///
/// `Path::components()` splits on both separators on Windows, so the result
/// never carries the platform separator into the archive.
fn zip_entry_name(relative: &Path) -> String {
    relative
        .components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}
```

2. Extract the walk loop of `create_ipa` (:222-286) into a shared walker. It receives the walk root, the options, and a naming closure; directory names get the trailing `/` appended here; the caller keeps file-level options (Stored/precompressed, unix permissions) — those move into the walker because they depend on per-entry metadata:

```rust
/// Walks `walk_root` and writes every entry into `zip`, mapping each
/// strip-prefix-relative path to an archive name through `name_of`
/// (`None` skips the entry). Directories get their trailing separator here.
fn write_tree(
    zip: &mut ZipWriter<std::io::BufWriter<File>>,
    walk_root: &Path,
    options: SimpleFileOptions,
    name_of: &dyn Fn(&Path) -> Option<String>,
) -> Result<()> {
    for entry in WalkDir::new(walk_root).follow_links(false) {
        let entry = entry
            .map_err(|e| Error::Io(io::Error::other(format!("Failed to walk directory: {}", e))))?;
        let path = entry.path();
        let relative_path = path.strip_prefix(walk_root).map_err(|_| {
            Error::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Failed to compute relative path",
            ))
        })?;
        let Some(mut archive_path) = name_of(relative_path) else {
            continue;
        };

        let metadata = fs::symlink_metadata(path)?;
        if metadata.is_dir() {
            archive_path.push('/');
            zip.add_directory(&archive_path, options).map_err(Error::Zip)?;
        } else if metadata.file_type().is_symlink() {
            let target = fs::read_link(path)?;
            let target_str = target.to_string_lossy();
            zip.add_symlink(&archive_path, target_str, options)
                .map_err(Error::Zip)?;
        } else {
            let file_options = if is_precompressed(path) {
                options
                    .compression_method(CompressionMethod::Stored)
                    .compression_level(None)
            } else {
                options
            };
            #[cfg(unix)]
            let file_options = {
                use std::os::unix::fs::PermissionsExt;
                let mode = metadata.permissions().mode();
                file_options.unix_permissions(mode)
            };
            zip.start_file(&archive_path, file_options)
                .map_err(Error::Zip)?;
            let mut file = File::open(path)?;
            io::copy(&mut file, &mut zip)?;
        }
    }
    Ok(())
}
```

3. Rewrite `create_ipa` to validate as today (:167-197 region), build `options` as today (:207-218), `zip.add_directory("Payload/", options)`, then:

```rust
    let name_prefix = format!("Payload/{}", app_name);
    write_tree(&mut zip, app_bundle_path, options, &|relative_path| {
        if relative_path.as_os_str().is_empty() {
            Some(name_prefix.clone())
        } else {
            Some(format!("{}/{}", name_prefix, relative_path.display()))
        }
    })?;
    zip.finish().map_err(Error::Zip)?;
    Ok(())
```

(`app_name` is a `Cow<str>` today; `.to_string()` it once for the prefix. The trailing `/` for the bundle root now comes from the walker — output name identical to today's special case.)

4. Add the crate-private repack entry point:

```rust
/// Creates an IPA from a whole extraction root: every top-level entry of the
/// root (`Payload/…` plus any siblings such as `SwiftSupport/` or
/// `iTunesMetadata.plist`) is archived verbatim under its relative name.
///
/// This is the repack half of [`extract_ipa`](crate::ipa::extract_ipa); unlike
/// [`create_ipa`] it does not synthesize a `Payload/` structure.
pub(crate) fn create_ipa_from_root(
    extraction_root: impl AsRef<Path>,
    output_path: impl AsRef<Path>,
    compression_level: CompressionLevel,
) -> Result<()> {
    let extraction_root = extraction_root.as_ref();
    let output_path = output_path.as_ref();
    if !extraction_root.is_dir() {
        return Err(Error::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Not a directory: {}", extraction_root.display()),
        )));
    }
    if let Some(parent) = output_path.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent)?;
        }
    }
    let file = File::create(output_path)?;
    let mut zip = ZipWriter::new(std::io::BufWriter::new(file));
    let options = archive_options(compression_level);
    write_tree(&mut zip, extraction_root, options, &|relative_path| {
        if relative_path.as_os_str().is_empty() {
            None
        } else {
            Some(zip_entry_name(relative_path))
        }
    })?;
    zip.finish().map_err(Error::Zip)?;
    Ok(())
}
```

5. Extract the existing options block (:207-218) verbatim into `fn archive_options(compression_level: CompressionLevel) -> SimpleFileOptions` (with its determinism comment) and call it from both entry points — no behavior change.

- [ ] **Step 4: Wire `sign()`**

In `crates/zsign/src/ipa/mod.rs`: add a **separate private import** `use archive::create_ipa_from_root;` in the module's import block (next to the existing `use archive::…` imports) — do **not** extend the `pub use archive::{create_ipa, CompressionLevel};` re-export at :57 (re-exporting a `pub(crate)` item there is E0364 and would grow the `lib.rs` public surface). Then replace :283:

```rust
        self.sign_bundle_from_options(&app_bundle)?;

        create_ipa_from_root(temp_dir.path(), output_ipa, self.compression_level)?;
```

Doc updates in the same file: `sign()` workflow list step 6 ("Repack via [`create_ipa`]") → repack the extraction root via `create_ipa_from_root` (keeps non-`Payload` entries), and the `IpaSigner` struct-level workflow doc at mod.rs:104 ("5. Repack via [`create_ipa`]") gets the same wording (it links the same flow). Module-level `## Manual extraction and repacking` example stays valid (`create_ipa` unchanged).

- [ ] **Step 5: Run the scoped gate**

Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-rs ipa -- --skip test_ipa_signing_is_deterministic`
Expected: PASS — new round-trip test green; `test_extract_and_repack_ipa`, `test_ipa_signer_workflow` and friends green against the refactored walker.

- [ ] **Step 6: Controller commit**

`fix(ipa): carry extraction-root entries through repack (ZSN-39)`

---

### Task 3 — ZIP64 write support for oversized members (queue item 2)

**Files:**
- Modify: `crates/zsign/src/ipa/archive.rs` — gate constant + predicate + walker wiring; tests.

- [ ] **Step 1: Write the pure-contract test**

```rust
    #[test]
    fn test_needs_zip64_boundaries() {
        assert!(!needs_zip64(0), "empty member is never zip64");
        assert!(!needs_zip64(4096), "typical member is never zip64");
        assert!(!needs_zip64(ZIP64_SIZE_GATE), "the gate itself is still 32-bit");
        assert!(needs_zip64(ZIP64_SIZE_GATE + 1), "one byte past the gate opts in");
        assert!(needs_zip64(u64::from(u32::MAX)), "u32::MAX is not reachable safely");
        assert!(needs_zip64(u64::from(u32::MAX) + 1), "beyond 32 bits");
    }
```

- [ ] **Step 2: Run, verify compile failure**

Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-rs test_needs_zip64` — Expected: FAIL to compile (`needs_zip64` / `ZIP64_SIZE_GATE` not found).

- [ ] **Step 3: Add the gate constant and predicate (not yet wired)**

In `crates/zsign/src/ipa/archive.rs`:

```rust
/// Uncompressed-size gate for opting a member into ZIP64 extended fields.
///
/// Sits 1 MiB below the 32-bit size ceiling, so no compressed size derived
/// from a member at or below the gate can cross `0xFFFFFFFF`; members below
/// the gate keep byte-identical headers.
const ZIP64_SIZE_GATE: u64 = u32::MAX as u64 - (1 << 20);

/// True when a member of `uncompressed_len` bytes must carry ZIP64
/// extended information extra fields to be written without error.
fn needs_zip64(uncompressed_len: u64) -> bool {
    uncompressed_len > ZIP64_SIZE_GATE
}
```

- [ ] **Step 4: Run the pure contract**

Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-rs test_needs_zip64`
Expected: PASS.

- [ ] **Step 5: Add the end-to-end proof (still red — not wired)**

Add to the `archive.rs` tests module (imports: `std::io::Read` for the probe; `File`/`ZipArchive` are already in scope there):

```rust
    /// End-to-end proof that an oversized member is written instead of
    /// aborting mid-copy: a 4 GiB+1 sparse file of zeros compresses to a
    /// few MiB but crosses the size guard that zip only clears with
    /// `large_file(true)`. Ignored so the routine suite never streams four
    /// gigabytes through deflate; run explicitly with
    /// `cargo test -p zsign-rs zip64_oversized -- --ignored`.
    #[test]
    #[ignore = "streams more than 4 GiB through deflate"]
    fn test_create_ipa_zip64_oversized_member() {
        let temp = TempDir::new().unwrap();
        let app_dir = temp.path().join("Big.app");
        fs::create_dir_all(&app_dir).unwrap();
        let big = app_dir.join("big.bin");
        let file = File::create(&big).unwrap();
        file.set_len(u64::from(u32::MAX) + 1).unwrap();
        drop(file);

        let out = temp.path().join("big.ipa");
        create_ipa(&app_dir, &out, CompressionLevel::DEFAULT)
            .expect("oversized member must be written with zip64 enabled");

        let reader = File::open(&out).unwrap();
        let mut archive = ZipArchive::new(reader).unwrap();
        let mut entry = archive
            .by_name("Payload/Big.app/big.bin")
            .expect("member present");
        // zip 7.2.0 patches the local header with the true 64-bit length,
        // then clamps the struct the central directory is derived from to
        // the 0xFFFFFFFF sentinel, so the recorded size saturates at
        // `ZIP64_BYTES_THR`. What this proves is that the write completed
        // without the mid-write guard aborting the entry.
        assert!(
            entry.size() >= zip::ZIP64_BYTES_THR,
            "recorded size must reach the zip64 threshold, got {}",
            entry.size()
        );
        let mut probe = [0u8; 16];
        entry
            .read_exact(&mut probe)
            .expect("oversized member reads back");
    }
```

- [ ] **Step 6: Run, verify the pre-fix red**

Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-rs zip64_oversized -- --ignored`
Expected: FAIL with `oversized member must be written with zip64 enabled: Large file option has not been set` (pre-fix red; may take minutes — runs once at red and once at green).

- [ ] **Step 7: Wire the gate into the walker**

In `write_tree`'s regular-file branch, after the `#[cfg(unix)]` permissions block and before `start_file`:

```rust
            #[cfg(unix)]
            let file_options = { /* existing unix_permissions block, unchanged */ };
            let file_options = if needs_zip64(metadata.len()) {
                file_options.large_file(true)
            } else {
                file_options
            };
```

- [ ] **Step 8: Run gates**

Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-rs ipa -- --skip test_ipa_signing_is_deterministic`
Expected: PASS (the ignored test does not run here).
Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-rs zip64_oversized -- --ignored`
Expected: PASS — evidence for the final report (paste verbatim output).

- [ ] **Step 9: Controller commit**

`fix(ipa): enable zip64 for oversized archive members (ZSN-39)`

---

### Task 4 — Canonical `/` entry names (queue item 3)

**Files:**
- Modify: `crates/zsign/src/ipa/archive.rs` — `create_ipa`'s naming closure migrates to `zip_entry_name` (introduced in Task 2); tighten an existing assertion; tests.

- [ ] **Step 1: Write the pinning tests**

```rust
    #[test]
    fn test_zip_entry_name_joins_components_with_forward_slash() {
        assert_eq!(
            zip_entry_name(Path::new("dir/sub/file.bin")),
            "dir/sub/file.bin",
            "nested paths join with '/'"
        );
        assert_eq!(zip_entry_name(Path::new("file.bin")), "file.bin");
        assert_eq!(zip_entry_name(Path::new("")), "", "root relative path");
    }
```

Tighten `test_create_ipa` (archive.rs:332): alongside the existing loose checks, assert the exact nested name:

```rust
        assert!(
            names.iter().any(|n| n == "Payload/Test.app/Resources/icon.png"),
            "nested entry names are '/'-joined, got {names:?}"
        );
```

(`names: Vec<String>` collected in the existing `by_index` loop.)

- [ ] **Step 2: Run, verify current state**

Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-rs zip_entry_name`
Expected: PASS even before the migration (on Linux `display()` joins with `/` already) — these are contract pins; the separator defect is Windows-only and Windows CI is check-only (`ci.yml:64-73`). The review evidence is the *construction* change below, not red-on-Linux.

- [ ] **Step 3: Migrate the remaining `display()` name site**

In `create_ipa`'s closure (Task 2 code):

```rust
    write_tree(&mut zip, app_bundle_path, options, &|relative_path| {
        if relative_path.as_os_str().is_empty() {
            Some(name_prefix.clone())
        } else {
            Some(format!("{}/{}", name_prefix, zip_entry_name(relative_path)))
        }
    })?;
```

Verify no other entry name is built from `Path::display()` in the file (grep `display()` in `archive.rs`: only error messages may keep it — they are not entry names).

- [ ] **Step 4: Run the scoped gate**

Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-rs ipa -- --skip test_ipa_signing_is_deterministic`
Expected: PASS — output names byte-identical to before on Linux.

- [ ] **Step 5: Controller commit**

`fix(ipa): build zip entry names from path components (ZSN-39)`

---

### Task 5 — Reject unsafe symlink targets at creation (queue item 4)

**Files:**
- Modify: `crates/zsign/src/ipa/archive.rs` — validator + constant; walker symlink branch; tests.

- [ ] **Step 1: Write the failing tests**

Add `use crate::ipa::extract_ipa;` to the `mod tests` import block of `archive.rs` (`mod tests`'s `super` is the `archive` module, so the crate-root re-export is not reachable unqualified); `create_test_app_bundle`, `File`, `ZipArchive`, `TempDir` are already in scope there.

```rust
    #[test]
    fn test_checked_symlink_target_boundaries() {
        assert_eq!(
            checked_symlink_target("e", std::ffi::OsStr::new("Versions/Current/x")).unwrap(),
            "Versions/Current/x",
            "framework-style relative targets pass verbatim"
        );
        let max = "a".repeat(MAX_SYMLINK_TARGET_BYTES);
        assert!(
            checked_symlink_target("e", std::ffi::OsStr::new(&max)).is_ok(),
            "a target of exactly the extractor's limit is accepted"
        );
        let too_long = "a".repeat(MAX_SYMLINK_TARGET_BYTES + 1);
        let err = checked_symlink_target("e", std::ffi::OsStr::new(&too_long))
            .expect_err("targets above the extractor's limit are rejected");
        assert!(err.to_string().contains("too long"), "{err}");
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            let non_utf8 = std::ffi::OsStr::from_bytes(b"bad\xfftarget");
            assert!(
                checked_symlink_target("e", non_utf8).is_err(),
                "non-UTF-8 targets are rejected rather than lossily rewritten"
            );
        }
    }

    #[test]
    #[cfg(unix)]
    fn test_create_ipa_rejects_unsafe_symlink_targets() {
        for target in ["/etc/passwd", "../escape", "sub/../../escape"] {
            let temp = TempDir::new().unwrap();
            let app = create_test_app_bundle(temp.path());
            std::os::unix::fs::symlink(target, app.join("BadLink")).unwrap();
            let out = temp.path().join("out.ipa");
            let err = create_ipa(&app, &out, CompressionLevel::DEFAULT)
                .expect_err("unsafe symlink target must fail at creation");
            let msg = err.to_string();
            assert!(msg.contains("Unsafe symlink target"), "target {target}: {msg}");
            assert!(msg.contains("BadLink"), "entry named: {msg}");
        }
    }

    #[test]
    #[cfg(unix)]
    fn test_create_ipa_framework_symlink_round_trips() {
        let temp = TempDir::new().unwrap();
        let app = create_test_app_bundle(temp.path());
        let versions = app.join("Frameworks").join("Extra.framework").join("Versions");
        fs::create_dir_all(versions.join("A")).unwrap();
        fs::write(versions.join("A").join("resource.txt"), b"payload").unwrap();
        std::os::unix::fs::symlink("A", versions.join("Current")).unwrap();
        std::os::unix::fs::symlink(
            "Versions/Current/resource.txt",
            app.join("Frameworks").join("Extra.framework").join("Extra"),
        )
        .unwrap();

        let out = temp.path().join("framework.ipa");
        create_ipa(&app, &out, CompressionLevel::DEFAULT).expect("creation succeeds");

        let extracted = temp.path().join("extracted");
        extract_ipa(&out, &extracted).unwrap();
        let root = extracted.join("Payload").join("Test.app").join("Frameworks").join("Extra.framework");
        assert_eq!(
            std::fs::read_link(root.join("Versions").join("Current")).unwrap(),
            std::path::Path::new("A"),
            "targets round-trip verbatim"
        );
        assert_eq!(
            std::fs::read_link(root.join("Extra")).unwrap(),
            std::path::Path::new("Versions/Current/resource.txt"),
            "targets round-trip verbatim"
        );
    }
```

- [ ] **Step 2: Run, verify failure**

Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-rs checked_symlink_target` — Expected: FAIL to compile (`checked_symlink_target` not found).
Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-rs test_create_ipa_rejects_unsafe` — Expected after adding just the validator is absent → compile-fail; once the validator exists but before wiring, `create_ipa` still succeeds → `expect_err` panics (red). The round-trip test passes at every stage (it pins the invariant against future normalization).

- [ ] **Step 3: Implement**

In `crates/zsign/src/ipa/archive.rs`:

```rust
/// Largest symlink target the extractor will read back for a written
/// archive; mirrors `MAX_SYMLINK_TARGET_BYTES` in the extract module,
/// which is not editable from this lane.
const MAX_SYMLINK_TARGET_BYTES: usize = 4096;

/// Validates a symlink target against the extractor's target policy before
/// it is written, so every archive the writer accepts re-extracts through
/// `extract_ipa` with its targets byte-identical. Returns the target.
fn checked_symlink_target(entry_name: &str, target: &std::ffi::OsStr) -> Result<String> {
    let target = target.to_str().ok_or_else(|| {
        Error::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Non-UTF-8 symlink target for archive entry: {entry_name}"),
        ))
    })?;
    if target.starts_with('/') || target.split('/').any(|component| component == "..") {
        return Err(Error::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Unsafe symlink target for archive entry {entry_name}: {target}"),
        )));
    }
    if target.len() > MAX_SYMLINK_TARGET_BYTES {
        return Err(Error::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Symlink target too long for archive entry {entry_name}: {} bytes",
                target.len()
            ),
        )));
    }
    Ok(target.to_string())
}
```

(The safety predicate mirrors `is_safe_symlink_target` in the extract module — no leading `/`, no `..` component — which stays private and unedited.)

In `write_tree`'s symlink branch, replace the verbatim emission:

```rust
        } else if metadata.file_type().is_symlink() {
            let target = fs::read_link(path)?;
            let target = checked_symlink_target(&archive_path, &target.as_os_str())?;
            zip.add_symlink(&archive_path, &target, options)
                .map_err(Error::Zip)?;
        }
```

Doc updates in `archive.rs`: the module/features list "Preserves Unix file permissions and symlinks" → note targets must satisfy the extractor's policy (rejected at creation otherwise); `create_ipa` `# Errors` section gains "symlink targets that are absolute, escaping (`..`), non-UTF-8, or longer than 4096 bytes".

- [ ] **Step 4: Run the scoped gate**

Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-rs ipa -- --skip test_ipa_signing_is_deterministic`
Expected: PASS — including `test_create_ipa_preserves_symlinks` (safe targets unaffected).

- [ ] **Step 5: Controller commit**

`fix(ipa): reject unsafe symlink targets at archive creation (ZSN-39)`

---

### Task 6 — Rule-consistent CodeResources emission (queue item 5)

**Files:**
- Modify: `crates/zsign-core/src/bundle/code_resources.rs` — private resolver + `build()` rewrite + doc updates; tests.

- [ ] **Step 1: Write the failing tests**

```rust
    #[test]
    fn test_build_omits_rule_declared_paths() {
        let mut builder = CodeResourcesBuilder::new();
        let (sha1, sha256) = CodeResourcesBuilder::hash_data(b"x");
        for path in [
            "Info.plist",
            "PkgInfo",
            ".DS_Store",
            "en.lproj/locversion.plist",
            "en.lproj/Localizable.strings",
            "Base.lproj/Notes.strings",
            "data.bin",
        ] {
            builder.add_file(path, sha1, sha256);
        }
        let bytes = builder.build().unwrap();
        let value: Value = plist::from_bytes(&bytes).unwrap();
        let root = value.as_dictionary().unwrap();
        let files = root.get("files").unwrap().as_dictionary().unwrap();
        let files2 = root.get("files2").unwrap().as_dictionary().unwrap();

        // rules2 declares these omit: absent from files2 …
        for omitted in ["Info.plist", "PkgInfo", ".DS_Store", "en.lproj/locversion.plist"] {
            assert!(!files2.contains_key(omitted), "{omitted} is rule-omitted");
        }
        // … and the legacy dict drops what the v1 rules omit.
        assert!(
            !files.contains_key("en.lproj/locversion.plist"),
            "v1 rules declare locversion omit"
        );
        // v1 rules carry no Info/PkgInfo/.DS_Store omission: still sealed there.
        assert!(matches!(files.get("Info.plist"), Some(Value::Data(_))));
        assert!(files.contains_key(".DS_Store"), "kept in the legacy dict");

        // Rule-derived optional: .lproj optional, Base.lproj (weight 1010) included.
        let en = files2
            .get("en.lproj/Localizable.strings")
            .and_then(|v| v.as_dictionary())
            .expect("en.lproj file sealed");
        assert_eq!(en.get("optional"), Some(&Value::Boolean(true)));
        let base = files2
            .get("Base.lproj/Notes.strings")
            .and_then(|v| v.as_dictionary())
            .expect("Base.lproj file sealed");
        assert!(
            base.get("optional").is_none(),
            "Base.lproj resolves to Include, not Optional"
        );
        assert!(
            matches!(files.get("Base.lproj/Notes.strings"), Some(Value::Data(_))),
            "v1 Base.lproj entry is bare data, not an optional dict"
        );
        assert!(files2.contains_key("data.bin"));
    }

    #[test]
    fn test_custom_exclude_emits_matching_omit_rule() {
        let mut builder = CodeResourcesBuilder::new();
        builder.exclude("DebugResources/");
        let (sha1, sha256) = CodeResourcesBuilder::hash_data(b"x");
        assert!(!builder.add_file("DebugResources/asset.dat", sha1, sha256));
        assert!(builder.add_file("keep.txt", sha1, sha256));

        let bytes = builder.build().unwrap();
        let value: Value = plist::from_bytes(&bytes).unwrap();
        let root = value.as_dictionary().unwrap();
        for key in ["rules", "rules2"] {
            let rules = root.get(key).unwrap().as_dictionary().unwrap();
            let spec = rules
                .get("^DebugResources/")
                .unwrap_or_else(|| panic!("{key} must declare the exclusion as omit"));
            let dict = spec.as_dictionary().expect("rule spec is a dict");
            assert_eq!(dict.get("omit"), Some(&Value::Boolean(true)));
            assert_eq!(dict.get("weight"), Some(&Value::Real(2000.0)));
        }
        let rules2 = root.get("rules2").unwrap().as_dictionary().unwrap();
        assert_eq!(
            rule_action(rules2, "DebugResources/asset.dat"),
            Some(RuleAction::Omit),
            "the emitted rules resolve excluded paths to Omit"
        );
        assert_eq!(rule_action(rules2, "keep.txt"), Some(RuleAction::Include));
        let files = root.get("files").unwrap().as_dictionary().unwrap();
        let files2 = root.get("files2").unwrap().as_dictionary().unwrap();
        assert!(!files.contains_key("DebugResources/asset.dat"));
        assert!(!files2.contains_key("DebugResources/asset.dat"));
    }

    #[test]
    fn test_rule_action_weights_and_ties() {
        let rules2 = standard_rules2();
        assert_eq!(rule_action(&rules2, "data.bin"), Some(RuleAction::Include));
        assert_eq!(
            rule_action(&rules2, "en.lproj/Localizable.strings"),
            Some(RuleAction::Optional)
        );
        assert_eq!(
            rule_action(&rules2, "Base.lproj/Notes.strings"),
            Some(RuleAction::Include),
            "weight 1010 beats the optional rule at 1000"
        );
        assert_eq!(
            rule_action(&rules2, "en.lproj/locversion.plist"),
            Some(RuleAction::Omit)
        );
        assert_eq!(rule_action(&rules2, "Info.plist"), Some(RuleAction::Omit));
        assert_eq!(
            rule_action(&rules2, "Frameworks/.DS_Store"),
            Some(RuleAction::Omit)
        );
        assert_eq!(
            rule_action(&rules2, "missing-under-.lproj/en.lproj/x"),
            Some(RuleAction::Optional)
        );

        // Equal weight: strictest-first tie-break — Include outranks Omit.
        let mut tied = Dictionary::new();
        let mut omit = Dictionary::new();
        omit.insert("omit".to_string(), Value::Boolean(true));
        omit.insert("weight".to_string(), Value::Real(5.0));
        tied.insert("^Info\\.".to_string(), Value::Dictionary(omit));
        let mut include = Dictionary::new();
        include.insert("weight".to_string(), Value::Real(5.0));
        tied.insert("^Info".to_string(), Value::Dictionary(include));
        assert_eq!(
            rule_action(&tied, "Info.x"),
            Some(RuleAction::Include),
            "tie_rank: Include < Omit"
        );

        // The escaped rules2 spelling of the version key matches exactly;
        // a prefix read would let its weight-20 Include beat the weight-10
        // Omit below on "version.plist.bak".
        let mut exact = Dictionary::new();
        let mut include20 = Dictionary::new();
        include20.insert("weight".to_string(), Value::Real(20.0));
        exact.insert(
            "^version\\.plist$".to_string(),
            Value::Dictionary(include20),
        );
        let mut omit10 = Dictionary::new();
        omit10.insert("omit".to_string(), Value::Boolean(true));
        omit10.insert("weight".to_string(), Value::Real(10.0));
        exact.insert("^version".to_string(), Value::Dictionary(omit10));
        assert_eq!(
            rule_action(&exact, "version.plist.bak"),
            Some(RuleAction::Omit),
            "the escaped key must not prefix-match past version.plist"
        );
    }
```

- [ ] **Step 2: Run, verify failure**

Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-core test_build_omits_rule_declared_paths test_custom_exclude`
Expected: FAIL to compile (`rule_action`/`RuleAction` not found) — then, after adding only the resolver, the assertions fail against today's `build()` (`en.lproj/locversion.plist` present in `files2`, `Base.lproj` carrying `optional`, no `^DebugResources/` key).

- [ ] **Step 3: Implement the resolver**

In `crates/zsign-core/src/bundle/code_resources.rs` (private, above `impl CodeResourcesBuilder`):

```rust
/// Action a resource rule assigns to a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuleAction {
    Include,
    Omit,
    Optional,
}

/// Tie-break on equal weight, strictest first: Include beats Omit beats
/// Optional. Mirrors the verifier's `tie_rank` in the zsign crate; the
/// verifier lives in a crate this one cannot depend on, so emission carries
/// the same resolution over the dicts it emits.
fn tie_rank(action: RuleAction) -> u8 {
    match action {
        RuleAction::Include => 0,
        RuleAction::Omit => 1,
        RuleAction::Optional => 2,
    }
}

/// Parses one emitted rule spec into `(action, weight)`; unusable specs are
/// dropped, mirroring the verifier's treatment of invalid rules.
fn parse_rule(spec: &Value) -> Option<(RuleAction, f64)> {
    match spec {
        Value::Boolean(true) => Some((RuleAction::Include, 1.0)),
        Value::Boolean(false) => Some((RuleAction::Omit, 1.0)),
        Value::Dictionary(dict) => {
            if dict
                .keys()
                .any(|k| !matches!(k.as_str(), "omit" | "optional" | "weight"))
            {
                return None;
            }
            let bad_type = matches!(dict.get("omit"), Some(v) if !matches!(v, Value::Boolean(_)))
                || matches!(dict.get("optional"), Some(v) if !matches!(v, Value::Boolean(_)));
            if bad_type {
                return None;
            }
            let omit = matches!(dict.get("omit"), Some(Value::Boolean(true)));
            let optional = matches!(dict.get("optional"), Some(Value::Boolean(true)));
            if omit && optional {
                return None;
            }
            let weight = match dict.get("weight") {
                None => 1.0,
                Some(Value::Real(w)) if w.is_finite() => *w,
                Some(Value::Integer(w)) => w
                    .as_signed()
                    .map(|v| v as f64)
                    .or_else(|| w.as_unsigned().map(|v| v as f64))
                    .unwrap_or(f64::NAN),
                _ => return None,
            };
            if !weight.is_finite() {
                return None;
            }
            let action = if omit {
                RuleAction::Omit
            } else if optional {
                RuleAction::Optional
            } else {
                RuleAction::Include
            };
            Some((action, weight))
        }
        _ => None,
    }
}

/// True when an emitted rule key matches `rel`. The standard vocabulary is
/// matched exactly as the verifier matches it (including the deliberately
/// unescaped dot before `plist`); any other `^`-anchored key is read as the
/// literal-prefix form `build()` emits for `exclude()` patterns, and keys
/// outside that vocabulary never match.
fn rule_pattern_matches(pattern: &str, rel: &str) -> bool {
    match pattern {
        "^.*" => true,
        "^.*\\.lproj/" => rel.contains(".lproj/"),
        "^.*\\.lproj/locversion.plist$" => rel
            .match_indices(".lproj/locversion")
            .any(|(idx, _)| {
                let rest = &rel[idx + ".lproj/locversion".len()..];
                let mut chars = rest.chars();
                matches!(chars.next(), Some(c) if c != '\n') && chars.as_str() == "plist"
            }),
        "^Base\\.lproj/" => rel.starts_with("Base.lproj/"),
        "^version.plist$" => rel == "version.plist",
        "^version\\.plist$" => rel == "version.plist",
        ".*\\.dSYM($|/)" => rel.ends_with(".dSYM") || rel.contains(".dSYM/"),
        "^(.*/)?\\.DS_Store$" => rel == ".DS_Store" || rel.ends_with("/.DS_Store"),
        "^Info\\.plist$" => rel == "Info.plist",
        "^PkgInfo$" => rel == "PkgInfo",
        "^embedded\\.provisionprofile$" => rel == "embedded.provisionprofile",
        other => other
            .strip_prefix('^')
            .is_some_and(|literal| rel.starts_with(&unescape_regex_literal(literal))),
    }
}

/// Escapes regex metacharacters so `format!("^{}", escape_regex_literal(p))`
/// matches exactly the paths `p` is a literal prefix of.
fn escape_regex_literal(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        if matches!(
            ch,
            '\\' | '.' | '+' | '*' | '?' | '(' | ')' | '[' | ']' | '{' | '}' | '^' | '$' | '|'
        ) {
            out.push('\\');
        }
        out.push(ch);
    }
    out
}

/// Inverse of [`escape_regex_literal`] for keys this module emitted.
fn unescape_regex_literal(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            if let Some(escaped) = chars.next() {
                out.push(escaped);
            }
        } else {
            out.push(ch);
        }
    }
    out
}

/// Winning rule for `rel`: highest weight wins; equal weights resolve
/// strictest-first via [`tie_rank`]. Mirrors the verifier's `rule_action`.
fn rule_action(rules: &Dictionary, rel: &str) -> Option<RuleAction> {
    let mut best: Option<(RuleAction, f64)> = None;
    for (pattern, spec) in rules {
        let Some((action, weight)) = parse_rule(spec) else {
            continue;
        };
        if !rule_pattern_matches(pattern, rel) {
            continue;
        }
        best = Some(match best {
            None => (action, weight),
            Some((best_action, best_weight)) => match weight.total_cmp(&best_weight) {
                std::cmp::Ordering::Greater => (action, weight),
                std::cmp::Ordering::Equal if tie_rank(action) < tie_rank(best_action) => {
                    (action, weight)
                }
                _ => (best_action, best_weight),
            },
        });
    }
    best.map(|(action, _)| action)
}
```

- [ ] **Step 4: Rewrite `build()`**

```rust
    /// Builds the CodeResources plist as XML bytes.
    ///
    /// `files`/`files2` entries are derived from the rule sets this method
    /// emits: a path whose winning rule is `omit` is not sealed, and the
    /// entry-level `optional` flag is copied from a winning `optional` rule,
    /// so the sealed entries and the declared rules can never contradict each
    /// other. Each `exclude()` pattern is declared as a matching omit rule in
    /// both `rules` and `rules2`.
    ///
    /// # Errors
    ///
    /// Returns an error if plist serialization fails.
    pub fn build(&self) -> Result<Vec<u8>> {
        let mut root = Dictionary::new();

        let mut rules = standard_rules();
        let mut rules2 = standard_rules2();
        for pattern in &self.exclusions {
            let mut spec = Dictionary::new();
            spec.insert("omit".to_string(), Value::Boolean(true));
            spec.insert("weight".to_string(), Value::Real(EXCLUSION_RULE_WEIGHT));
            let key = format!("^{}", escape_regex_literal(pattern));
            rules.insert(key.clone(), Value::Dictionary(spec.clone()));
            rules2.insert(key, Value::Dictionary(spec));
        }

        // Legacy "files": SHA-1 only, symlinks unsupported by the old format.
        let mut files = Dictionary::new();
        for (path, entry) in &self.files {
            if entry.symlink_target.is_some() {
                continue;
            }
            match rule_action(&rules, path) {
                Some(RuleAction::Omit) => continue,
                Some(RuleAction::Optional) => {
                    let mut file_dict = Dictionary::new();
                    file_dict.insert("hash".to_string(), Value::Data(entry.sha1.to_vec()));
                    file_dict.insert("optional".to_string(), Value::Boolean(true));
                    files.insert(path.clone(), Value::Dictionary(file_dict));
                }
                _ => {
                    files.insert(path.clone(), Value::Data(entry.sha1.to_vec()));
                }
            }
        }
        root.insert("files".to_string(), Value::Dictionary(files));

        // Modern "files2": SHA-1 + SHA-256, symlink targets instead of hashes.
        let mut files2 = Dictionary::new();
        for (path, entry) in &self.files {
            let action = rule_action(&rules2, path);
            if action == Some(RuleAction::Omit) {
                continue;
            }
            let mut file_dict = Dictionary::new();
            if let Some(ref target) = entry.symlink_target {
                file_dict.insert("symlink".to_string(), Value::String(target.clone()));
            } else {
                file_dict.insert("hash".to_string(), Value::Data(entry.sha1.to_vec()));
                file_dict.insert("hash2".to_string(), Value::Data(entry.sha256.to_vec()));
            }
            if action == Some(RuleAction::Optional) {
                file_dict.insert("optional".to_string(), Value::Boolean(true));
            }
            files2.insert(path.clone(), Value::Dictionary(file_dict));
        }
        root.insert("files2".to_string(), Value::Dictionary(files2));

        root.insert("rules".to_string(), Value::Dictionary(rules));
        root.insert("rules2".to_string(), Value::Dictionary(rules2));

        let mut buf = Vec::new();
        plist::to_writer_xml(&mut buf, &Value::Dictionary(root)).map_err(Error::Plist)?;
        Ok(buf)
    }
```

Add the constant with its rationale:

```rust
/// Weight emitted for `exclude()` omit rules: ties the most-specific
/// standard class (`.DS_Store` omit at 2000) and outranks every other
/// standard weight, so an excluded path resolves to `omit` regardless of
/// which other rules match it — matching `should_exclude`'s precedence.
const EXCLUSION_RULE_WEIGHT: f64 = 2000.0;
```

Doc updates in the same file: `# Exclusions` module section and `exclude()` docs gain one sentence: custom patterns are also declared as omit rules in the emitted `rules`/`rules2`. Delete the now-obsolete `files2` hardcode comment block ("C++ Reference: bundle.cpp:186-192 / Omits .DS_Store…") — its behavior is now rule-derived; keep the C++ reference only where it still describes the shape (files dict loop).

- [ ] **Step 5: Run gates**

Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-core code_resources`
Expected: PASS (5 existing + 3 new tests).
Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-rs ipa -- --skip test_ipa_signing_is_deterministic`
Expected: PASS.
Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-rs verify -- --skip test_ipa_signing_is_deterministic`
Expected: PASS — the ZSN-26 regression fixtures (`omitted_locversion_deletion_stays_valid`, `optional_lproj_deletion_after_signing_stays_valid`, `base_lproj_deletion_is_not_optional`, `nested_ds_store_is_not_flagged_unsealed`, `unsupported_rule_is_reported`) stay green against the new emission.

- [ ] **Step 6: Controller commit**

`fix(bundle): emit code resources entries consistent with declared rules (ZSN-39)`

---

## Self-review checklist (controller, before cold review)

- [ ] Spec coverage: queue items 1–5 map to Tasks 1–6 (item 1 = Tasks 1+2); every design-doc §2 decision appears as plan code or an explicit step.
- [ ] Placeholder scan: no TBD/TODO/“similar to Task N”; every code step shows full code or exact edit location.
- [ ] Type consistency: `create_ipa_from_root` signature identical at definition and call; `checked_symlink_target` returns `Result<String>` everywhere; `rule_action(&Dictionary, &str) -> Option<RuleAction>` used by `build()` and all three tests; `zip_entry_name` defined once (Task 2) and used by both closures after Task 4.
- [ ] Scope: only `crates/zsign/src/ipa/{archive.rs,mod.rs}` and `crates/zsign-core/src/bundle/code_resources.rs` are ever edited; `extract.rs`/`verify.rs`/`lib.rs` untouched.
