# ZSN-7 / ZSN-15 Zip Encoding and Determinism Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development
> (recommended) with dispatching-parallel-agents for independent tasks to
> implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for
> tracking. Tester subagent writes the failing test first; implementer subagent
> greens it; the controller runs the scoped gate and commits before the next task.

**Goal:** Make non-ASCII entry names survive extract→sign→repack round-trips
with the UTF-8 general-purpose bit handled correctly on both read and write
(ZSN-7), and make archive entry order deterministic by sorting the walk so
identical inputs produce byte-identical zips (ZSN-15).

**Architecture:** One decode helper in `crates/zsign/src/ipa/extract.rs`
(`canonical_entry_name`: raw bytes as UTF-8 when valid, zip's decode otherwise)
plus a fast path that keeps today's `enclosed_name()` containment chain
unchanged when both readings agree. One restructure of
`crates/zsign/src/ipa/archive.rs::write_tree` (collect → sort by archive-name
bytes → write) covering both `create_ipa` and `create_ipa_from_root` including
ZSN-39's pass-through root entries. Design decisions, item-0 matrix, and the
evidence base: `docs/superpowers/specs/2026-09-26-zip-encoding-determinism-design.md`.

**Tech Stack:** Rust 2021 workspace; zip 7.2.0 (pinned, `Cargo.lock:1786-1789`);
walkdir 2.5; rayon (extraction only) — no dependency changes.

**Shared conventions (apply to every task):**
- Scoped gate only, always: `mkdir -p .tmptmp && TMPDIR=$PWD/.tmptmp cargo test
  -p zsign-rs <filter>` — never project-wide fmt/clippy/hk mid-flight; fresh
  `cargo fmt --all --check` + `cargo clippy --workspace --all-targets -- -D
  warnings` + `cargo test --workspace --no-fail-fast` only at final report time.
- TDD: the failing test must be observed red BEFORE the production edit of the
  same task; run the test by name.
- Ticket IDs go in commit subjects only, never in code comments.
- If `.tmptmp/` shows up untracked after test runs, do NOT commit it and do NOT
  edit `.gitignore` (ZSN-30 owns it) — stage named files only.
- Never edit `crates/zsign/src/ipa/mod.rs`, `crates/zsign/src/bundle/*`,
  `crates/zsign-core/**`, `.github/**`, or `Cargo.*` (lane fences).
- Tests touching symlinks carry `#[test]` + `#[cfg(unix)]` (extract.rs
  convention, e.g. `:844`, `:1200`).
- Expected failures below assume this dev machine (btrfs, creation-order
  readdir). If a "red" step comes up green, STOP and report — do not proceed.

**Shared test helper (Task 1 introduces it in the `extract.rs` test module,
next to `patch_central_dir_unix_mode` at `extract.rs:913-951`; it is the same
byte-patch pattern, extended to both headers):**

```rust
    /// Rewrite one entry's raw name bytes and clear general-purpose bit 11 in
    /// both headers — the flag-clear input class real-world zippers emit
    /// (zip 7.2.0 always sets the bit for non-ASCII `&str` names, so fixtures
    /// must patch it off to exercise the cp437 decode path).
    ///
    /// `new_name` must have the same byte length as the stored name; header
    /// name-length fields are not rewritten. Finding is by the ORIGINAL name
    /// as written by `ZipWriter`, so patch each entry exactly once.
    #[cfg(unix)]
    fn rewrite_entry_header(archive_path: &Path, find_name: &str, new_name: &[u8]) {
        let mut bytes = fs::read(archive_path).unwrap();

        let eocd = bytes
            .windows(4)
            .rposition(|w| w == [0x50, 0x4b, 0x05, 0x06])
            .expect("end-of-central-directory record not found");
        let entry_count = u16::from_le_bytes([bytes[eocd + 10], bytes[eocd + 11]]) as usize;
        let mut pos = u32::from_le_bytes([
            bytes[eocd + 16],
            bytes[eocd + 17],
            bytes[eocd + 18],
            bytes[eocd + 19],
        ]) as usize;

        for _ in 0..entry_count {
            assert_eq!(
                &bytes[pos..pos + 4],
                b"PK\x01\x02",
                "bad central directory entry"
            );
            let name_len = u16::from_le_bytes([bytes[pos + 28], bytes[pos + 29]]) as usize;
            let extra_len = u16::from_le_bytes([bytes[pos + 30], bytes[pos + 31]]) as usize;
            let comment_len = u16::from_le_bytes([bytes[pos + 32], bytes[pos + 33]]) as usize;
            let name = std::str::from_utf8(&bytes[pos + 46..pos + 46 + name_len]).unwrap();
            if name == find_name {
                assert_eq!(
                    name_len,
                    new_name.len(),
                    "rewrites must keep the stored name length"
                );
                // Central header: general-purpose flags at +8, name bytes at
                // +46, local header offset at +42.
                let flags = u16::from_le_bytes([bytes[pos + 8], bytes[pos + 9]]);
                let cleared = flags & !(1 << 11);
                bytes[pos + 8..pos + 10].copy_from_slice(&cleared.to_le_bytes());
                bytes[pos + 46..pos + 46 + name_len].copy_from_slice(new_name);
                let local = u32::from_le_bytes([
                    bytes[pos + 42],
                    bytes[pos + 43],
                    bytes[pos + 44],
                    bytes[pos + 45],
                ]) as usize;
                assert_eq!(&bytes[local..local + 4], b"PK\x03\x04", "bad local header");
                // Local header: general-purpose flags at +6, name bytes at +30.
                let lflags = u16::from_le_bytes([bytes[local + 6], bytes[local + 7]]);
                let lcleared = lflags & !(1 << 11);
                bytes[local + 6..local + 8].copy_from_slice(&lcleared.to_le_bytes());
                bytes[local + 30..local + 30 + name_len].copy_from_slice(new_name);
                fs::write(archive_path, &bytes).unwrap();
                return;
            }
            pos += 46 + name_len + extra_len + comment_len;
        }
        panic!("entry {find_name} not found in central directory");
    }
```

---

### Task 1: ZSN-7 — non-ASCII round-trip (extraction decode)

**Files:**
- Modify: `crates/zsign/src/ipa/extract.rs` (tests: add helper + one test;
  production: add `canonical_entry_name`, rewire the collect pass at :353-372)

- [ ] **Step 1: Write the failing test**

Add to `crates/zsign/src/ipa/extract.rs`'s `#[cfg(test)] mod tests`, together
with the shared `rewrite_entry_header` helper above:

```rust
    #[test]
    #[cfg(unix)]
    fn test_extract_repack_roundtrip_preserves_non_ascii_names() {
        let temp_dir = TempDir::new().unwrap();
        let ipa_path = temp_dir.path().join("nonascii.ipa");
        let file = File::create(&ipa_path).unwrap();
        let mut zip = ZipWriter::new(file);
        let options = SimpleFileOptions::default();
        zip.add_directory("Payload/", options).unwrap();
        zip.add_directory("Payload/App.app/", options).unwrap();
        // Non-ASCII directory and file: patched to flag-clear below.
        zip.add_directory("Payload/App.app/资源/", options).unwrap();
        zip.start_file("Payload/App.app/资源/测试文件.txt", options)
            .unwrap();
        zip.write_all(b"chinese content").unwrap();
        // Flag-set control entry: written by zip with bit 11 already set.
        zip.start_file("Payload/App.app/资料/说明.txt", options)
            .unwrap();
        zip.write_all(b"flag-set content").unwrap();
        // Non-ASCII symlink name; the target rides in the entry content.
        zip.add_symlink("Payload/App.app/资源链接", "资源/测试文件.txt", options)
            .unwrap();
        // Placeholder for the adversarial cp437 entry, rewritten below.
        zip.start_file("Payload/App.app/zz", options).unwrap();
        zip.write_all(b"cp437 content").unwrap();
        zip.finish().unwrap();

        // The bug-class input: UTF-8 name bytes with bit 11 clear.
        rewrite_entry_header(
            &ipa_path,
            "Payload/App.app/资源/",
            "Payload/App.app/资源/".as_bytes(),
        );
        rewrite_entry_header(
            &ipa_path,
            "Payload/App.app/资源/测试文件.txt",
            "Payload/App.app/资源/测试文件.txt".as_bytes(),
        );
        rewrite_entry_header(
            &ipa_path,
            "Payload/App.app/资源链接",
            "Payload/App.app/资源链接".as_bytes(),
        );
        // Adversarial: same-length rewrite to cp437 é bytes (0x82), which
        // are NOT valid UTF-8 — the cp437 reading must survive every hop
        // without double-mangling. Must stay the last patch: later helper
        // calls would scan over the now-invalid UTF-8 name bytes.
        rewrite_entry_header(&ipa_path, "Payload/App.app/zz", b"Payload/App.app/\x82\x82");

        // Hop 1: extract.
        let hop1 = temp_dir.path().join("hop1");
        let app1 = extract_ipa(&ipa_path, &hop1).unwrap();
        assert_eq!(
            fs::read(app1.join("资源").join("测试文件.txt")).unwrap(),
            b"chinese content",
            "flag-clear UTF-8 file name must extract unmangled"
        );
        assert!(
            app1.join("资料").join("说明.txt").exists(),
            "flag-set control entry must extract"
        );
        assert_eq!(
            fs::read_link(app1.join("资源链接"))
                .unwrap()
                .to_str(),
            Some("资源/测试文件.txt"),
            "non-ASCII symlink name and target must survive"
        );
        assert_eq!(
            fs::read(app1.join("\u{e9}\u{e9}")).unwrap(),
            b"cp437 content",
            "non-UTF-8 cp437 name must decode via cp437"
        );

        // Repack the whole extraction root (the signing repack path).
        let out = temp_dir.path().join("repacked.ipa");
        super::super::archive::create_ipa_from_root(
            &hop1,
            &out,
            crate::ipa::CompressionLevel::DEFAULT,
        )
        .unwrap();

        // The produced archive must flag every non-ASCII name as UTF-8 and
        // carry the literal names.
        use zip::HasZipMetadata;
        let mut reader = ZipArchive::new(File::open(&out).unwrap()).unwrap();
        let mut seen: Vec<(String, u16)> = Vec::new();
        for i in 0..reader.len() {
            let entry = reader.by_index(i).unwrap();
            seen.push((entry.name().to_string(), entry.get_metadata().flags));
        }
        for (name, flags) in &seen {
            if !name.is_ascii() {
                assert!(
                    flags & (1 << 11) != 0,
                    "UTF-8 general-purpose bit must be set on {name}"
                );
            }
        }
        for expected in [
            "Payload/App.app/资源/",
            "Payload/App.app/资源/测试文件.txt",
            "Payload/App.app/资料/说明.txt",
            "Payload/App.app/资源链接",
            "Payload/App.app/\u{e9}\u{e9}",
        ] {
            assert!(
                seen.iter().any(|(n, _)| n == expected),
                "missing {expected} in {seen:?}"
            );
        }

        // Hop 2: extract the repack — every hop keeps the same names.
        let hop2 = temp_dir.path().join("hop2");
        let app2 = extract_ipa(&out, &hop2).unwrap();
        assert_eq!(
            fs::read(app2.join("资源").join("测试文件.txt")).unwrap(),
            b"chinese content"
        );
        assert!(app2.join("资料").join("说明.txt").exists());
        assert_eq!(
            fs::read_link(app2.join("资源链接")).unwrap().to_str(),
            Some("资源/测试文件.txt")
        );
        assert_eq!(fs::read(app2.join("\u{e9}\u{e9}")).unwrap(), b"cp437 content");
    }
```

Note: `ZipArchive` is already in scope via `use super::*` (production import
`extract.rs:35`). Uses of `é` above are written as `\u{e9}` escapes so the
source file stays pure ASCII where the compiler doesn't need literal CJK;
literal CJK strings in this test are intentional and required.

- [ ] **Step 2: Run the test to verify it fails**

Run: `mkdir -p .tmptmp && TMPDIR=$PWD/.tmptmp cargo test -p zsign-rs ipa::extract -- --nocapture`
Expected: `test_extract_repack_roundtrip_preserves_non_ascii_names` FAILS —
extraction itself succeeds, but the first literal-path `fs::read`
(`app1.join("资源").join("测试文件.txt")`) panics on `unwrap()` because the file
landed under its cp437-mojibake name. If it passes, STOP and report.

- [ ] **Step 3: Write the implementation**

In `crates/zsign/src/ipa/extract.rs` production code, directly above the
collect pass (near `is_unsafe_entry_name`):

```rust
/// The entry name as UTF-8 when the raw bytes are valid UTF-8, otherwise the
/// zip crate's own decode: cp437 for flag-clear legacy names, lossy UTF-8
/// when a flag-set name is not valid UTF-8.
///
/// Reading the raw bytes first fixes entries whose writer stored UTF-8
/// without setting general-purpose bit 11 — the zip crate cp437-decodes
/// those into mojibake, which the repack would then persist.
fn canonical_entry_name<'f, R: io::Read + ?Sized>(file: &'f zip::read::ZipFile<'_, R>) -> &'f str {
    std::str::from_utf8(file.name_raw()).unwrap_or_else(|_| file.name())
}
```

Rewire the collect pass (`extract.rs:353-372`) — replace
`let name = file.name();` with `let name = canonical_entry_name(&file);` and
replace the `outpath` match with:

```rust
        let outpath = if name == file.name() {
            // Fast path: both readings agree (all flag-set and all-ASCII
            // names) — today's containment chain runs unchanged.
            match file.enclosed_name() {
                Some(path) if !path.as_os_str().is_empty() => dest_dir.join(path),
                _ => {
                    return Err(Error::Io(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("Unsafe entry name in IPA: {}", name),
                    )))
                }
            }
        } else {
            // Divergence: flag-clear valid-UTF-8 non-ASCII name. Mirror
            // enclosed_name's acceptance set on the canonical name: the
            // NUL gate first (the one check is_unsafe_entry_name lacks),
            // then drop empty/"." segments, reject any segment that is not
            // a plain path component — a Windows drive prefix anywhere
            // would make PathBuf::push replace the whole path, an escape
            // enclosed_name never produces (it pushes only Normal
            // components) — and join the survivors under dest_dir.
            // Traversal, leading separators, and whole-name drive prefixes
            // are already rejected by is_unsafe_entry_name above; PathBuf
            // equality is component-based, so duplicate/type-conflict
            // detection keys canonically on either branch.
            if name.contains('\0') {
                return Err(Error::Io(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("Unsafe entry name in IPA: {}", name),
                )));
            }
            let mut rel = PathBuf::new();
            for segment in name.split(['/', '\\']) {
                if segment.is_empty() || segment == "." {
                    continue;
                }
                let bytes = segment.as_bytes();
                if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
                    return Err(Error::Io(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("Unsafe entry name in IPA: {}", name),
                    )));
                }
                rel.push(segment);
            }
            dest_dir.join(rel)
        };
```

The `is_unsafe_entry_name(name)` call and both error messages stay exactly as
they are — only the value fed to them changes from `file.name()` to the
canonical name.

- [ ] **Step 4: Run the test to verify it passes, then the full module gate**

Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-rs ipa::extract`
Expected: ALL `ipa::extract` tests pass (including every hostile-name,
zip-bomb, duplicate/type-conflict, setuid, and symlink pin — they all take the
fast path, byte-for-byte unchanged behavior).

- [ ] **Step 5: Controller commits**

`git add crates/zsign/src/ipa/extract.rs` (and nothing else) → commit subject:
`fix(ipa): decode flag-clear utf-8 entry names on extraction (ZSN-7)`

---

### Task 2: ZSN-15 — deterministic entry order (sorted walk)

**Files:**
- Modify: `crates/zsign/src/ipa/archive.rs` (production: `write_tree` at
  :338-405 plus the `Path` import at :27; tests: add two tests)

- [ ] **Step 1: Write the failing tests**

Add to `crates/zsign/src/ipa/archive.rs`'s `#[cfg(test)] mod tests` (helpers
`create_ipa`, `create_ipa_from_root`, `CompressionLevel`, `File`, `fs`,
`PathBuf`, `TempDir`, `ZipArchive` are all already in scope there):

```rust
    #[test]
    fn test_create_ipa_writes_entries_in_sorted_order() {
        let temp_dir = TempDir::new().unwrap();
        let src = temp_dir.path().join("Demo.app");
        // Created in an order that differs from bytewise sorted order.
        fs::create_dir_all(src.join("zdir")).unwrap();
        fs::create_dir_all(src.join("adir")).unwrap();
        fs::write(src.join("zdir/b.txt"), b"b").unwrap();
        fs::write(src.join("adir/a.txt"), b"a").unwrap();
        fs::write(src.join("Info.plist"), b"info").unwrap();
        fs::write(src.join("zz.txt"), b"zz").unwrap();

        let out = temp_dir.path().join("out.ipa");
        create_ipa(&src, &out, CompressionLevel::NONE).unwrap();

        let mut reader = ZipArchive::new(File::open(&out).unwrap()).unwrap();
        let mut names = Vec::with_capacity(reader.len());
        for i in 0..reader.len() {
            let entry = reader.by_index(i).unwrap();
            assert_eq!(
                entry.last_modified(),
                Some(zip::DateTime::default()),
                "entry {} must carry the pinned 1980-01-01 timestamp",
                entry.name()
            );
            names.push(entry.name().to_string());
        }
        assert_eq!(
            names,
            [
                "Payload/",
                "Payload/Demo.app/",
                "Payload/Demo.app/Info.plist",
                "Payload/Demo.app/adir/",
                "Payload/Demo.app/adir/a.txt",
                "Payload/Demo.app/zdir/",
                "Payload/Demo.app/zdir/b.txt",
                "Payload/Demo.app/zz.txt",
            ],
            "entries must be in bytewise archive-name order with directories \
             before their children"
        );
    }

    #[test]
    fn test_create_ipa_from_root_is_byte_identical_across_creation_order() {
        // Same content, two extraction roots, opposite file-creation order —
        // including ZSN-39's pass-through siblings.
        fn build_root(root: &Path, forward: bool) {
            let app = root.join("Payload").join("Demo.app");
            let mut files: Vec<(PathBuf, Vec<u8>)> = vec![
                (app.join("Info.plist"), b"info".to_vec()),
                (
                    root.join("iTunesMetadata.plist"),
                    b"meta".to_vec(),
                ),
                (
                    root.join("SwiftSupport")
                        .join("iphoneos")
                        .join("libswiftCore.dylib"),
                    b"swift".to_vec(),
                ),
            ];
            for i in 0..24u8 {
                files.push((app.join("res").join(format!("f{i:02}.bin")), vec![i; 8]));
            }
            if !forward {
                files.reverse();
            }
            for (path, bytes) in files {
                fs::create_dir_all(path.parent().unwrap()).unwrap();
                fs::write(path, bytes).unwrap();
            }
        }

        let temp_dir = TempDir::new().unwrap();
        let root_fwd = temp_dir.path().join("fwd");
        let root_rev = temp_dir.path().join("rev");
        build_root(&root_fwd, true);
        build_root(&root_rev, false);

        let out_fwd = temp_dir.path().join("fwd.ipa");
        let out_rev = temp_dir.path().join("rev.ipa");
        create_ipa_from_root(&root_fwd, &out_fwd, CompressionLevel::DEFAULT).unwrap();
        create_ipa_from_root(&root_rev, &out_rev, CompressionLevel::DEFAULT).unwrap();

        assert_eq!(
            fs::read(&out_fwd).unwrap(),
            fs::read(&out_rev).unwrap(),
            "identical content must produce byte-identical archives regardless \
             of filesystem creation order"
        );
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-rs ipa::archive`
Expected: both new tests FAIL on this btrfs machine — the sorted-order test
reports creation/readdir order, the byte-identity test reports an entry-order
byte divergence. If either passes, STOP and report (do not weaken the tests).

- [ ] **Step 3: Write the implementation**

In `crates/zsign/src/ipa/archive.rs`:
1. Change the import at :27 from `use std::path::Path;` to
   `use std::path::{Path, PathBuf};`.
2. Restructure `write_tree` (:338-405) to three phases — collect, sort, write:

```rust
/// Walks `walk_root` and writes every entry into `zip`, mapping each
/// strip-prefix-relative path to an archive name through `name_of`
/// (`None` skips the entry). Directories get their trailing separator here.
///
/// Entries are written in bytewise archive-name order so archive output
/// never depends on filesystem readdir order: identical inputs produce
/// byte-identical archives.
fn write_tree(
    zip: &mut ZipWriter<std::io::BufWriter<File>>,
    walk_root: &Path,
    options: SimpleFileOptions,
    name_of: &dyn Fn(&Path) -> Option<String>,
) -> Result<()> {
    // Collect: map every walked entry to its archive name (None skips it).
    let mut entries: Vec<(String, PathBuf)> = Vec::new();
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

        if let Some(archive_path) = name_of(relative_path) {
            entries.push((archive_path, path.to_path_buf()));
        }
    }

    // Sort: bytewise order of the archive name ('/'-joined relative path),
    // which is platform-stable and keeps every directory before its children
    // (a child's name carries its directory's name as a byte prefix).
    entries.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));

    // Write: the per-entry body is unchanged from the previous walk loop.
    for (mut archive_path, path) in entries {
        // Use symlink_metadata to check the entry type without following links
        let metadata = fs::symlink_metadata(&path)?;

        if metadata.is_dir() {
            archive_path.push('/');
            zip.add_directory(&archive_path, options)
                .map_err(Error::Zip)?;
        } else if metadata.file_type().is_symlink() {
            let target = fs::read_link(&path)?;
            let target = checked_symlink_target(&archive_path, target.as_os_str())?;
            zip.add_symlink(&archive_path, &target, options)
                .map_err(Error::Zip)?;
        } else {
            // Regular file — use Stored for pre-compressed formats
            let file_options = if is_precompressed(&path) {
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

            let file_options = if needs_zip64(metadata.len()) {
                file_options.large_file(true)
            } else {
                file_options
            };

            zip.start_file(&archive_path, file_options)
                .map_err(Error::Zip)?;

            // Stream file directly without loading into memory
            let mut file = File::open(&path)?;
            io::copy(&mut file, &mut *zip)?;
        }
    }

    Ok(())
}
```

Notes: the write body is byte-for-byte the previous body (ZIP64 gate,
`unix_permissions`, pre-compressed Stored override, symlink policy all
untouched — ZSN-35/ZSN-39 behavior preserved). The synthetic `Payload/` header
entry is still written before `write_tree` in `create_ipa` (:255-256), so it
stays first; `name_of` still handles root skipping (`create_ipa_from_root` →
`None`, :305-311) and the root→`name_prefix` mapping (`create_ipa`, :260-266).

- [ ] **Step 4: Run the tests to verify they pass, then the module gate**

Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-rs ipa::archive`
Expected: ALL `ipa::archive` tests pass, including both new tests, the ZIP64
gate tests, entry-name tests, and symlink-policy tests.

- [ ] **Step 5: Controller commits**

`git add crates/zsign/src/ipa/archive.rs` (and nothing else) → commit subject:
`fix(ipa): sort archive entries by name for deterministic output (ZSN-15)`

---

### Task 3: Proofs (controller-run, no code changes)

- [ ] **Step 1: 5× no-skip determinism proof (brief acceptance)**

Run exactly (NO `--skip` anywhere in this lane once the fix lands):

```
for i in 1 2 3 4 5; do
  echo "=== run $i ==="
  TMPDIR=$PWD/.tmptmp cargo test -p zsign-rs test_ipa_signing_is_deterministic 2>&1 | tail -3
done
```

Expected: five `test result: ok. 1 passed` lines. Paste the verbatim output in
the final report. Any failure → systematic-debugging skill, do not re-scope.

- [ ] **Step 2: Non-ASCII round-trip evidence (brief acceptance)**

Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-rs test_extract_repack_roundtrip_preserves_non_ascii_names -- --nocapture`
Expected: pass; paste verbatim output in the final report.

- [ ] **Step 3: Whole ipa module, unskipped**

Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-rs ipa::`
Expected: all `ipa::` tests pass (extract, archive, and mod tests including
`test_ipa_signing_is_deterministic` — one run, no skip).

---

### Final report gates (after Tasks 1-3, report time only)

- [ ] `cargo fmt --all --check` → clean
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` → zero diagnostics
- [ ] `TMPDIR=$PWD/.tmptmp cargo test --workspace --no-fail-fast` → all pass,
  NO `--skip` anywhere; paste verbatim summary lines
- [ ] Confirm `git status` clean except `.tmptmp/` (never staged); commit list
  per ticket; cross-lane seams and docs-lane notes recorded (design doc
  "Scope fence" section); no merge, no push — orchestrator lands with
  `wt merge --no-squash`.

**Deviations policy:** any deviation from this plan goes into the final report
(plan-vs-actual); scope never shrinks silently.
