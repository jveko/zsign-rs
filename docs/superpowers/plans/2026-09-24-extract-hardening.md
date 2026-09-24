# ZSN-28 Hostile-Archive Extraction Hardening — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development
> with dispatching-parallel-agents where tasks are independent (here they are
> NOT — all tasks edit one file, so execution is strictly sequential).
> Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `crates/zsign/src/ipa/extract.rs` fail closed and stay bounded
against hostile IPA archives: unsafe names, zip bombs, huge symlink targets,
setuid bits, duplicate/conflicting paths, undocumented mmap, TOCTOU.

**Architecture:** Seven ordered, independently-green tasks, all inside
`crates/zsign/src/ipa/extract.rs` + its inline tests (task 6 also drops the
obsolete `memmap2` dependency from `crates/zsign/Cargo.toml`/`Cargo.lock`).
Each task follows red-green: Tester subagent writes the failing test first,
implementer subagents green it, controller runs the scoped gate and commits.
Twelve new tests total; expected gate counts: task 1 → 16, task 2 → 19,
task 3 → 20, task 4 → 21, task 5 → 24.

**Tech Stack:** Rust 2021, zip 7.2.0 (writer fixtures), rayon (unchanged),
`std::sync::atomic::AtomicU64` (new), tempfile (existing tests).

**Scoped gate after every task (never project-wide):**

```
cargo test -p zsign-rs ipa::extract -- --skip test_ipa_signing_is_deterministic
```

Known pre-existing failure `test_ipa_signing_is_deterministic` (ZSN-15) is
skipped by that command; everything else must stay green. Do NOT run
`cargo fmt` / `cargo clippy` / `hk` — the orchestrator runs those at merge.

**Anchors:** every `extract.rs:N` reference below is the base `ee42c12`
line. Tasks 1-4 add lines above the collect pass, so later tasks' numbers
drift — locate statements by their code text, not the number. Counts
(16/19/20/21/24) assume the Unix target.

**Design reference:** `docs/superpowers/specs/2026-09-24-extract-hardening-design.md`
(error messages, invariants, rejected alternatives are fixed there; this plan
must not contradict it).

---

### Task 1: Fail closed on unsafe entry names

**Files:**
- Modify: `crates/zsign/src/ipa/extract.rs` (helper next to
  `is_safe_symlink_target` ~:49; collect pass :170-176; tests `mod tests`)

- [ ] **Step 1: Write the failing tests** (append to `mod tests`, with the
  helper next to `create_test_ipa`)

```rust
    /// Build an otherwise-valid IPA that additionally contains `hostile_name`.
    fn create_ipa_with_hostile_entry(dir: &Path, hostile_name: &str) -> PathBuf {
        let ipa_path = dir.join("hostile.ipa");
        let file = File::create(&ipa_path).unwrap();
        let mut zip = ZipWriter::new(file);
        let options = SimpleFileOptions::default();

        zip.add_directory("Payload/", options).unwrap();
        zip.add_directory("Payload/Test.app/", options).unwrap();
        zip.start_file("Payload/Test.app/Info.plist", options)
            .unwrap();
        zip.write_all(b"<?xml version=\"1.0\"?><plist><dict></dict></plist>")
            .unwrap();

        zip.start_file(hostile_name, options).unwrap();
        zip.write_all(b"evil content").unwrap();

        zip.finish().unwrap();
        ipa_path
    }

    fn assert_rejects_hostile_entry(hostile_name: &str) {
        let temp_dir = TempDir::new().unwrap();
        let ipa_path = create_ipa_with_hostile_entry(temp_dir.path(), hostile_name);
        let extract_dir = temp_dir.path().join("extracted");
        let err = extract_ipa(&ipa_path, &extract_dir)
            .expect_err("hostile entry name must fail the extraction");
        let msg = err.to_string();
        assert!(
            msg.contains("Unsafe entry name in IPA"),
            "unexpected error: {msg}"
        );
        assert!(
            msg.contains(hostile_name),
            "error must name the entry: {msg}"
        );
    }

    #[test]
    fn test_extract_ipa_rejects_parent_traversal_entry() {
        assert_rejects_hostile_entry("../evil");
    }

    #[test]
    fn test_extract_ipa_rejects_nested_traversal_entry() {
        assert_rejects_hostile_entry("Payload/../../evil");
        // Spelling that enclosed_name() silently normalizes instead of
        // rejecting — the raw-name check must still fail closed.
        assert_rejects_hostile_entry("Payload/../evil");
    }

    #[test]
    fn test_extract_ipa_rejects_absolute_entry_name() {
        assert_rejects_hostile_entry("/abs/evil");
        // Names with no real component: zip encloses these as an empty path
        // resolving to the destination itself.
        assert_rejects_hostile_entry("");
        assert_rejects_hostile_entry(".");
        assert_rejects_hostile_entry("./");
        // A NUL name is the one form that reaches the `enclosed_name()`
        // non-`Some` arm (the raw check passes) — this pins that arm.
        assert_rejects_hostile_entry("Payload/\0evil");
    }

    #[test]
    fn test_extract_ipa_rejects_windows_style_absolute_entry_name() {
        assert_rejects_hostile_entry("C:/abs/evil");
        assert_rejects_hostile_entry("\\abs\\evil");
        // Backslash traversal that Windows-path componentization pops
        // instead of rejecting.
        assert_rejects_hostile_entry("Payload\\sub\\..\\evil");
    }
```

- [ ] **Step 2: Run the gate — expect FAIL**

Run: `cargo test -p zsign-rs ipa::extract -- --skip test_ipa_signing_is_deterministic`
Expected: the four new tests FAIL (pre-fix the entries are silently skipped
or relocated, so extraction *succeeds*); all pre-existing tests PASS.

- [ ] **Step 3: Implement fail-closed name validation**

Add the helper after `is_safe_symlink_target` (:49-54):

```rust
/// Returns true if an archive entry name is absolute, uses `..` traversal,
/// or has no substantive component.
///
/// Both separator spellings are checked because the zip reader
/// componentizes names with Windows-path semantics (`Utf8WindowsPath`):
/// `C:/evil` and `\evil` would otherwise be silently relocated inside the
/// destination instead of rejected. Empty and dot-only names (``, `.`,
/// `./`) are rejected too: zip encloses them as an empty path that resolves
/// to the destination directory itself.
fn is_unsafe_entry_name(name: &str) -> bool {
    if name.starts_with('/') || name.starts_with('\\') {
        return true;
    }
    let bytes = name.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        return true;
    }
    let mut substantive = false;
    for segment in name.split(['/', '\\']) {
        if segment == ".." {
            return true;
        }
        if !segment.is_empty() && segment != "." {
            substantive = true;
        }
    }
    !substantive
}
```

In the collect pass, replace the `enclosed_name` match (:173-176) with:

```rust
        let name = file.name();
        if is_unsafe_entry_name(name) {
            return Err(Error::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Unsafe entry name in IPA: {}", name),
            )));
        }

        let outpath = match file.enclosed_name() {
            Some(path) if !path.as_os_str().is_empty() => dest_dir.join(path),
            _ => {
                return Err(Error::Io(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("Unsafe entry name in IPA: {}", name),
                )))
            }
        };
```

- [ ] **Step 4: Run the gate — expect PASS**

Run: `cargo test -p zsign-rs ipa::extract -- --skip test_ipa_signing_is_deterministic`
Expected: all tests pass (4 new + 12 existing = 16).

- [ ] **Step 5: Update `extract_ipa`'s `# Errors` doc** (:122-129) — add a
  bullet: `- Returns [`Error::Io`] if an archive entry name is unsafe
  (traversal or absolute)`

**Acceptance:** the four tests above pass; no entry can be silently skipped
or relocated; gate green. **Controller commits:**
`fix(zsign): fail closed on unsafe ipa entry names (ZSN-28)`

---

### Task 2: Zip-bomb budgets with injectable limits

**Files:**
- Modify: `crates/zsign/src/ipa/extract.rs` (new `BudgetedWriter` +
  `ExtractionLimits` + `extract_ipa_with_limits` above `extract_ipa` :130;
  rayon copy loop :239-254; symlink pass; imports; tests)

- [ ] **Step 1: Write the failing tests** (append to `mod tests`)

```rust
    #[test]
    fn test_extract_ipa_rejects_oversized_entry() {
        let temp_dir = TempDir::new().unwrap();
        let ipa_path = temp_dir.path().join("entry_bomb.ipa");
        let file = File::create(&ipa_path).unwrap();
        let mut zip = ZipWriter::new(file);
        let options = SimpleFileOptions::default();
        zip.add_directory("Payload/", options).unwrap();
        zip.add_directory("Payload/Test.app/", options).unwrap();
        zip.start_file("Payload/Test.app/Info.plist", options)
            .unwrap();
        zip.write_all(&vec![b'A'; 2048]).unwrap();
        zip.finish().unwrap();

        let limits = ExtractionLimits {
            max_entry_bytes: 100,
            max_total_bytes: 100_000,
        };
        let extract_dir = temp_dir.path().join("extracted");
        let err = extract_ipa_with_limits(&ipa_path, &extract_dir, limits)
            .expect_err("oversized entry must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("Archive exceeds extraction limit"),
            "unexpected error: {msg}"
        );
        assert!(
            msg.contains("Payload/Test.app/Info.plist"),
            "error must name the entry: {msg}"
        );
    }

    #[test]
    fn test_extract_ipa_rejects_oversized_total() {
        let temp_dir = TempDir::new().unwrap();
        let ipa_path = temp_dir.path().join("total_bomb.ipa");
        let file = File::create(&ipa_path).unwrap();
        let mut zip = ZipWriter::new(file);
        let options = SimpleFileOptions::default();
        zip.add_directory("Payload/", options).unwrap();
        zip.add_directory("Payload/Test.app/", options).unwrap();
        zip.start_file("Payload/Test.app/Info.plist", options)
            .unwrap();
        zip.write_all(&vec![b'A'; 600]).unwrap();
        zip.start_file("Payload/Test.app/Test", options).unwrap();
        zip.write_all(&vec![b'B'; 600]).unwrap();
        zip.finish().unwrap();

        let limits = ExtractionLimits {
            max_entry_bytes: 1_000,
            max_total_bytes: 1_000,
        };
        let extract_dir = temp_dir.path().join("extracted");
        let err = extract_ipa_with_limits(&ipa_path, &extract_dir, limits)
            .expect_err("total size over budget must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("Archive exceeds extraction limit"),
            "unexpected error: {msg}"
        );
        assert!(msg.contains("total"), "error must mention the total: {msg}");
    }

    #[test]
    #[cfg(unix)]
    fn test_extract_ipa_rejects_total_overflow_from_symlinks() {
        let temp_dir = TempDir::new().unwrap();
        let ipa_path = temp_dir.path().join("symlink_budget.ipa");
        let file = File::create(&ipa_path).unwrap();
        let mut zip = ZipWriter::new(file);
        let options = SimpleFileOptions::default();
        zip.add_directory("Payload/", options).unwrap();
        zip.add_directory("Payload/Test.app/", options).unwrap();
        zip.start_file("Payload/Test.app/Info.plist", options)
            .unwrap();
        zip.write_all(b"<?xml version=\"1.0\"?><plist><dict></dict></plist>")
            .unwrap();
        zip.add_symlink("Payload/Test.app/link1", "a".repeat(4090), options)
            .unwrap();
        zip.add_symlink("Payload/Test.app/link2", "a".repeat(4090), options)
            .unwrap();
        zip.finish().unwrap();

        let limits = ExtractionLimits {
            max_entry_bytes: 1_000_000,
            max_total_bytes: 5_000,
        };
        let extract_dir = temp_dir.path().join("extracted");
        let err = extract_ipa_with_limits(&ipa_path, &extract_dir, limits)
            .expect_err("symlink bytes over the total budget must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("Archive exceeds extraction limit"),
            "unexpected error: {msg}"
        );
        assert!(msg.contains("total"), "error must mention the total: {msg}");
    }
```

Determinism notes: the two 600-byte file entries sum to 1200 > 1000, so at
least one reservation observes an over-total value regardless of chunk
scheduling; the symlink test runs in the sequential symlink pass (file
bytes 49 + first target 4090 = 4139 ≤ 5000, second target crosses 5000), so
it is fully ordered. Because the reservation happens *before* each write,
disk bytes can never exceed the caps even when the error fires late.

- [ ] **Step 2: Run the gate — expect FAIL**

Run: `cargo test -p zsign-rs ipa::extract -- --skip test_ipa_signing_is_deterministic`
Expected: FAIL to compile (`ExtractionLimits` / `extract_ipa_with_limits`
not found) — that is the red state.

- [ ] **Step 3: Implement the limits API**

Add the import `use std::sync::atomic::{AtomicU64, Ordering};` alongside the
existing `use std::sync::...` group (there is none yet — add it as its own
line after `use std::path::{Path, PathBuf};`).

Add above `extract_ipa` (:130):

```rust
/// Byte budgets enforced while writing extracted archive contents.
///
/// Defaults (used by [`extract_ipa`]): 2 GiB per entry, 8 GiB total.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtractionLimits {
    /// Maximum uncompressed size of a single archive entry, in bytes.
    pub max_entry_bytes: u64,
    /// Maximum total uncompressed size across all entries, in bytes.
    pub max_total_bytes: u64,
}

impl Default for ExtractionLimits {
    fn default() -> Self {
        ExtractionLimits {
            max_entry_bytes: 2 * 1024 * 1024 * 1024,
            max_total_bytes: 8 * 1024 * 1024 * 1024,
        }
    }
}
```

Add the budgeted writer (file-level, next to `ExtractEntry`):

```rust
/// Wraps the extraction output and enforces byte budgets before any data
/// reaches the underlying writer.
///
/// Every buffer is checked against the entry cap and reserved from the
/// shared total first, so parallel workers cannot overshoot either cap: what
/// reaches disk stays within budget.
struct BudgetedWriter<'a, W> {
    inner: W,
    relative: &'a Path,
    entry_written: u64,
    max_entry_bytes: u64,
    total: &'a AtomicU64,
    max_total_bytes: u64,
}

impl<W: io::Write> io::Write for BudgetedWriter<'_, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = buf.len() as u64;
        if self.entry_written + n > self.max_entry_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Archive exceeds extraction limit: entry '{}' exceeds {} bytes",
                    self.relative.display(),
                    self.max_entry_bytes
                ),
            ));
        }
        let total = self.total.fetch_add(n, Ordering::Relaxed) + n;
        if total > self.max_total_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Archive exceeds extraction limit: total extracted size exceeds {} bytes",
                    self.max_total_bytes
                ),
            ));
        }
        let written = self.inner.write(buf)?;
        self.entry_written += written as u64;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
```

Convert the existing `extract_ipa` body into the delegating pair:

```rust
pub fn extract_ipa(ipa_path: impl AsRef<Path>, dest_dir: impl AsRef<Path>) -> Result<PathBuf> {
    extract_ipa_with_limits(ipa_path, dest_dir, ExtractionLimits::default())
}

/// Extracts an IPA file with explicit extraction byte budgets.
///
/// Same as [`extract_ipa`], but the caller chooses the zip-bomb limits.
/// Extraction fails with [`Error::Io`] (`InvalidData`) as soon as an entry
/// or the archive total exceeds its budget — the check runs before each
/// buffer is written, so no unbudgeted bytes reach disk.
///
/// # Examples
///
/// ```no_run
/// use zsign_rs::ipa::extract::{extract_ipa_with_limits, ExtractionLimits};
///
/// let limits = ExtractionLimits {
///     max_entry_bytes: 512 * 1024 * 1024,
///     max_total_bytes: 2 * 1024 * 1024 * 1024,
/// };
/// let app_bundle = extract_ipa_with_limits("MyApp.ipa", "extracted", limits)?;
/// println!("Extracted to: {}", app_bundle.display());
/// # Ok::<(), zsign_rs::Error>(())
/// ```
///
/// # Errors
///
/// Returns [`Error::Io`] if the IPA is missing, an entry name is unsafe, a
/// path is a pre-existing symlink, or an extraction byte budget is exceeded.
/// Returns [`Error::Zip`] if the file is not a valid ZIP archive or no
/// `.app` bundle is found in `Payload/`.
pub fn extract_ipa_with_limits(
    ipa_path: impl AsRef<Path>,
    dest_dir: impl AsRef<Path>,
    limits: ExtractionLimits,
) -> Result<PathBuf> {
    // ... existing extract_ipa body moved here verbatim, except for Step 4 ...
}
```

The original `extract_ipa` doc comment stays on `extract_ipa`; extend its
`# Errors` section with: `- Returns [`Error::Io`] if an archive entry or the
archive total exceeds the default extraction limits (2 GiB per entry, 8 GiB
total)`.

- [ ] **Step 4: Enforce budgets while writing**

Before the rayon phase (:230), add:

```rust
    let total_written = AtomicU64::new(0);
```

Inside the per-entry loop, replace `BufWriter::new(outfile)` + bare
`io::copy` (:243-244) with:

```rust
                let relative = entry
                    .outpath
                    .strip_prefix(dest_dir_ref)
                    .unwrap_or(&entry.outpath);
                let mut budgeted = BudgetedWriter {
                    inner: BufWriter::new(outfile),
                    relative,
                    entry_written: 0,
                    max_entry_bytes: limits.max_entry_bytes,
                    total: &total_written,
                    max_total_bytes: limits.max_total_bytes,
                };
                io::copy(&mut file, &mut budgeted)?;
```

(The `validate_output_path` → `File::create` sequence above is unchanged;
task 7 later inserts its re-verify between them. The `#[cfg(unix)]`
permission-restore block after the copy is unchanged for now.)

In the symlink pass, insert between `file.read_to_string(&mut target)?;`
(:267) and `if !is_safe_symlink_target(&target) {` (:269):

```rust
            // Symlink targets count toward both budgets, reserved before
            // the link is created.
            if target.len() as u64 > limits.max_entry_bytes {
                let relative = entry
                    .outpath
                    .strip_prefix(dest_dir)
                    .unwrap_or(&entry.outpath);
                return Err(Error::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "Archive exceeds extraction limit: entry '{}' exceeds {} bytes",
                        relative.display(),
                        limits.max_entry_bytes
                    ),
                )));
            }
            let target_bytes = target.len() as u64;
            let total = total_written.fetch_add(target_bytes, Ordering::Relaxed) + target_bytes;
            if total > limits.max_total_bytes {
                return Err(Error::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "Archive exceeds extraction limit: total extracted size exceeds {} bytes",
                        limits.max_total_bytes
                    ),
                )));
            }
```

The closure captures `limits` (Copy) and `&total_written` by reference; both
live in the function scope, as does `total_written` for the symlink pass.

- [ ] **Step 5: Run the gate — expect PASS**

Run: `cargo test -p zsign-rs ipa::extract -- --skip test_ipa_signing_is_deterministic`
Expected: all tests pass (3 new, 19 total). The pre-existing happy-path
tests prove the 2 GiB/8 GiB defaults do not trip on tiny IPAs.

**Acceptance:** all three budget tests pass with injected low limits;
bytes reaching disk provably stay within both caps; `extract_ipa` signature
unchanged (callers `ipa/mod.rs:277`, `verify.rs:234` compile untouched).
**Controller commits:**
`feat(zsign): enforce extraction byte limits for ipa archives (ZSN-28)`

---

### Task 3: Bound the symlink-target read

**Files:**
- Modify: `crates/zsign/src/ipa/extract.rs` (new const near
  `is_safe_symlink_target`; symlink pass; tests)

- [ ] **Step 1: Write the failing test** (append to `mod tests`)

```rust
    #[test]
    #[cfg(unix)]
    fn test_extract_ipa_rejects_long_symlink_target() {
        let temp_dir = TempDir::new().unwrap();
        let ipa_path = temp_dir.path().join("long_target.ipa");
        let file = File::create(&ipa_path).unwrap();
        let mut zip = ZipWriter::new(file);
        let options = SimpleFileOptions::default();
        zip.add_directory("Payload/", options).unwrap();
        zip.add_directory("Payload/Test.app/", options).unwrap();
        zip.start_file("Payload/Test.app/Info.plist", options)
            .unwrap();
        zip.write_all(b"<?xml version=\"1.0\"?><plist><dict></dict></plist>")
            .unwrap();
        zip.add_symlink("Payload/Test.app/link", "a".repeat(5000), options)
            .unwrap();
        zip.finish().unwrap();

        let extract_dir = temp_dir.path().join("extracted");
        let err = extract_ipa(&ipa_path, &extract_dir)
            .expect_err("oversized symlink target must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("Symlink target too long in IPA"),
            "unexpected error: {msg}"
        );
    }
```

- [ ] **Step 2: Run the gate — expect FAIL**

Run: `cargo test -p zsign-rs ipa::extract -- --skip test_ipa_signing_is_deterministic`
Expected: the new test FAILS. Pre-fix the message comes from `symlink(2)`
(`IO error: File name too long ...`), which does not contain
`Symlink target too long in IPA`, so the assertion cannot false-green.

- [ ] **Step 3: Implement the bounded read**

Add near `is_safe_symlink_target`:

```rust
/// Maximum symlink target length accepted during extraction.
///
/// Matches Linux `PATH_MAX`: longer targets can never be created by
/// `symlink(2)`, and bounding the read keeps a hostile entry from buffering
/// gigabytes before validation. Unix-only, like the symlink pass that uses it.
#[cfg(unix)]
const MAX_SYMLINK_TARGET_BYTES: usize = 4096;
```

Replace the current symlink-pass region — from
`let mut file = archive.by_index(entry.index)?;` through the budget blocks
added in task 2, up to (but not including) `if !is_safe_symlink_target` —
with this final state:

```rust
            let file = archive.by_index(entry.index).map_err(Error::Zip)?;
            // Bound the read before validation: a hostile symlink entry must
            // never buffer more than the limit into memory.
            let mut target = String::new();
            file.take(MAX_SYMLINK_TARGET_BYTES as u64 + 1)
                .read_to_string(&mut target)?;
            if target.len() > MAX_SYMLINK_TARGET_BYTES {
                return Err(Error::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "Symlink target too long in IPA: {} ({} bytes, limit {})",
                        entry.outpath.display(),
                        target.len(),
                        MAX_SYMLINK_TARGET_BYTES
                    ),
                )));
            }
            // Symlink targets count toward both budgets, reserved before
            // the link is created.
            if target.len() as u64 > limits.max_entry_bytes {
                let relative = entry
                    .outpath
                    .strip_prefix(dest_dir)
                    .unwrap_or(&entry.outpath);
                return Err(Error::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "Archive exceeds extraction limit: entry '{}' exceeds {} bytes",
                        relative.display(),
                        limits.max_entry_bytes
                    ),
                )));
            }
            let target_bytes = target.len() as u64;
            let total = total_written.fetch_add(target_bytes, Ordering::Relaxed) + target_bytes;
            if total > limits.max_total_bytes {
                return Err(Error::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "Archive exceeds extraction limit: total extracted size exceeds {} bytes",
                        limits.max_total_bytes
                    ),
                )));
            }
```

The length check runs **before** the budget accounting and before
`is_safe_symlink_target` (unchanged below). `file` is consumed by `take`,
so its binding loses `mut`.

- [ ] **Step 4: Run the gate — expect PASS**

Run: `cargo test -p zsign-rs ipa::extract -- --skip test_ipa_signing_is_deterministic`
Expected: all tests pass (1 new, 20 total), including the four adversarial
symlink tests.

**Acceptance:** long-target test passes with the pinned message; peak
symlink-read memory ≤ 4097 bytes. **Controller commits:**
`fix(zsign): bound symlink target reads during ipa extraction (ZSN-28)`

---

### Task 4: Strip setuid/setgid/sticky bits

**Files:**
- Modify: `crates/zsign/src/ipa/extract.rs` (permission restore :249-252;
  tests: CDE patch helper + regression test)

- [ ] **Step 1: Write the failing test + fixture helper** (append to
  `mod tests`)

```rust
    /// Overwrite one central-directory entry's unix mode.
    ///
    /// The zip write API masks modes through `unix_permissions(0o777)`, so a
    /// setuid fixture has to patch the central-directory record directly.
    /// `external_file_attributes` (offset 38) stores the mode in its high 16
    /// bits; the low 16 bits hold DOS attributes and are preserved.
    #[cfg(unix)]
    fn patch_central_dir_unix_mode(archive_path: &Path, entry_name: &str, mode: u32) {
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
            if name == entry_name {
                let attr_pos = pos + 38;
                let mut attr = [0u8; 4];
                attr.copy_from_slice(&bytes[attr_pos..attr_pos + 4]);
                let old = u32::from_le_bytes(attr);
                let patched = (mode << 16) | (old & 0xffff);
                bytes[attr_pos..attr_pos + 4].copy_from_slice(&patched.to_le_bytes());
                fs::write(archive_path, &bytes).unwrap();
                return;
            }
            pos += 46 + name_len + extra_len + comment_len;
        }
        panic!("entry {entry_name} not found in central directory");
    }

    #[test]
    #[cfg(unix)]
    fn test_extract_ipa_strips_setuid_bit() {
        let temp_dir = TempDir::new().unwrap();
        let ipa_path = temp_dir.path().join("setuid.ipa");
        let file = File::create(&ipa_path).unwrap();
        let mut zip = ZipWriter::new(file);
        let options = SimpleFileOptions::default();
        zip.add_directory("Payload/", options).unwrap();
        zip.add_directory("Payload/Test.app/", options).unwrap();
        // Empty content on purpose: the kernel strips setuid/setgid on any
        // write, and production chmods before the BufWriter's final flush.
        // With zero bytes the permission restore is the last filesystem
        // operation, so a surviving setuid bit stays observable — otherwise
        // the post-chmod flush would clear it and this test would false-green.
        zip.start_file("Payload/Test.app/Info.plist", options)
            .unwrap();
        zip.finish().unwrap();

        // 0o104755 = S_IFREG | setuid | rwxr-xr-x
        patch_central_dir_unix_mode(&ipa_path, "Payload/Test.app/Info.plist", 0o104755);

        let extract_dir = temp_dir.path().join("extracted");
        let app = extract_ipa(&ipa_path, &extract_dir).unwrap();

        use std::os::unix::fs::PermissionsExt;
        let mode = app
            .join("Info.plist")
            .metadata()
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o7777,
            0o755,
            "setuid must not survive extraction, got {mode:o}"
        );
    }
```

Note the assertion masks with `0o7777`: `0o4755 & 0o777` is still `0o755`,
so a `& 0o777` assert would not see the setuid bit at all.

- [ ] **Step 2: Run the gate — expect FAIL**

Run: `cargo test -p zsign-rs ipa::extract -- --skip test_ipa_signing_is_deterministic`
Expected: `test_extract_ipa_strips_setuid_bit` FAILS with
`setuid must not survive extraction, got 104755`.

- [ ] **Step 3: Implement the mask change**

Replace :250:

```rust
                        let perms = mode & 0o7777;
```

with:

```rust
                        let perms = mode & 0o777;
```

- [ ] **Step 4: Run the gate — expect PASS**

Run: `cargo test -p zsign-rs ipa::extract -- --skip test_ipa_signing_is_deterministic`
Expected: all tests pass (1 new, 21 total).

**Acceptance:** extracted `Info.plist` lands as `0o755` from a `0o104755`
archive entry. **Controller commits:**
`fix(zsign): strip setuid and setgid bits from extracted files (ZSN-28)`

---

### Task 5: Reject duplicate/conflicting entry paths before any write

**Files:**
- Modify: `crates/zsign/src/ipa/extract.rs` (collect pass :166-215; new
  `file_ancestor` helper; tests)

- [ ] **Step 1: Write the failing tests** (append to `mod tests`)

```rust
    #[test]
    fn test_extract_ipa_rejects_duplicate_normalized_paths() {
        let temp_dir = TempDir::new().unwrap();
        let ipa_path = temp_dir.path().join("duplicate.ipa");
        let file = File::create(&ipa_path).unwrap();
        let mut zip = ZipWriter::new(file);
        let options = SimpleFileOptions::default();
        zip.add_directory("Payload/", options).unwrap();
        zip.add_directory("Payload/Test.app/", options).unwrap();
        zip.start_file("Payload/Test.app/Info.plist", options)
            .unwrap();
        zip.write_all(b"<?xml version=\"1.0\"?><plist><dict></dict></plist>")
            .unwrap();
        // Textually distinct raw name, identical path once normalized.
        zip.start_file("./Payload/Test.app/Info.plist", options)
            .unwrap();
        zip.write_all(b"second copy").unwrap();
        zip.finish().unwrap();

        let extract_dir = temp_dir.path().join("extracted");
        let err = extract_ipa(&ipa_path, &extract_dir)
            .expect_err("duplicate normalized path must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("Duplicate entry path in IPA"),
            "unexpected error: {msg}"
        );
        assert!(
            msg.contains("Payload/Test.app/Info.plist"),
            "error must name the path: {msg}"
        );
    }

    /// Build an IPA from `build`, extract it, and assert a collect-pass
    /// type conflict naming `expected` with no payload content written.
    fn assert_type_conflict(expected: &str, build: impl FnOnce(&mut ZipWriter<File>, SimpleFileOptions)) {
        let temp_dir = TempDir::new().unwrap();
        let ipa_path = temp_dir.path().join("conflict.ipa");
        let file = File::create(&ipa_path).unwrap();
        let mut zip = ZipWriter::new(file);
        let options = SimpleFileOptions::default();
        zip.add_directory("Payload/", options).unwrap();
        build(&mut zip, options);
        zip.finish().unwrap();

        let extract_dir = temp_dir.path().join("extracted");
        let err = extract_ipa(&ipa_path, &extract_dir)
            .expect_err("type conflict must be rejected in the collect pass");
        let msg = err.to_string();
        assert!(
            msg.contains("Conflicting entry path in IPA"),
            "unexpected error: {msg}"
        );
        assert!(msg.contains(expected), "error must name {expected}: {msg}");
        assert!(
            !extract_dir.join("Payload").exists(),
            "collect-pass rejection must write no payload content"
        );
    }

    #[test]
    fn test_extract_ipa_rejects_type_conflicting_entries() {
        // Same path, directory entry first.
        assert_type_conflict("Payload/D", |zip, options| {
            zip.add_directory("Payload/D", options).unwrap();
            zip.start_file("Payload/D", options).unwrap();
            zip.write_all(b"file where a directory is").unwrap();
        });
        // Same path, file entry first — the dir branch's same-path check.
        assert_type_conflict("Payload/D", |zip, options| {
            zip.start_file("Payload/D", options).unwrap();
            zip.write_all(b"file where a directory will be").unwrap();
            zip.add_directory("Payload/D", options).unwrap();
        });
        // Directory entry under an already-registered file — the dir
        // branch's ancestor walk.
        assert_type_conflict("Payload/a", |zip, options| {
            zip.start_file("Payload/a", options).unwrap();
            zip.write_all(b"i am a file").unwrap();
            zip.add_directory("Payload/a/b", options).unwrap();
        });
        // File entry after a directory chain claimed its path — the
        // ancestor claim registered by the dir branch.
        assert_type_conflict("Payload/a", |zip, options| {
            zip.add_directory("Payload/a/b", options).unwrap();
            zip.start_file("Payload/a", options).unwrap();
            zip.write_all(b"i am a file").unwrap();
        });
    }

    #[test]
    fn test_extract_ipa_rejects_descendant_of_file_entry() {
        // Order 1: file ancestor first, then its descendant.
        let temp_dir = TempDir::new().unwrap();
        let ipa_path = temp_dir.path().join("descendant.ipa");
        let file = File::create(&ipa_path).unwrap();
        let mut zip = ZipWriter::new(file);
        let options = SimpleFileOptions::default();
        zip.add_directory("Payload/", options).unwrap();
        zip.start_file("Payload/a", options).unwrap();
        zip.write_all(b"i am a file").unwrap();
        zip.start_file("Payload/a/b/c", options).unwrap();
        zip.write_all(b"descendant of a file").unwrap();
        zip.finish().unwrap();

        let extract_dir = temp_dir.path().join("extracted");
        let err = extract_ipa(&ipa_path, &extract_dir)
            .expect_err("entry under a file must be rejected in the collect pass");
        let msg = err.to_string();
        assert!(
            msg.contains("Conflicting entry path in IPA"),
            "unexpected error: {msg}"
        );
        assert!(msg.contains("Payload/a"), "error must name the path: {msg}");

        // Order 2: descendant registered first — the later ancestor file
        // must hit the same collect-pass conflict, not an OS error after
        // directories have been created.
        let temp_dir = TempDir::new().unwrap();
        let ipa_path = temp_dir.path().join("descendant_first.ipa");
        let file = File::create(&ipa_path).unwrap();
        let mut zip = ZipWriter::new(file);
        zip.add_directory("Payload/", options).unwrap();
        zip.start_file("Payload/a/b/c", options).unwrap();
        zip.write_all(b"descendant of a file").unwrap();
        zip.start_file("Payload/a", options).unwrap();
        zip.write_all(b"i am a file").unwrap();
        zip.finish().unwrap();

        let extract_dir = temp_dir.path().join("extracted");
        let err = extract_ipa(&ipa_path, &extract_dir)
            .expect_err("ancestor file after its descendant must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("Conflicting entry path in IPA"),
            "unexpected error: {msg}"
        );
        assert!(msg.contains("Payload/a"), "error must name the path: {msg}");
    }
```

- [ ] **Step 2: Run the gate — expect FAIL**

Run: `cargo test -p zsign-rs ipa::extract -- --skip test_ipa_signing_is_deterministic`
Expected: all three new tests FAIL. Duplicate: pre-fix last write wins and
extraction *succeeds*. Type conflict (all four orderings): pre-fix the
directory pass creates the conflicting directory (`Payload/D` or
`Payload/a`), then `File::create` fails with
`IO error: Is a directory (os error 21)`. Descendant: pre-fix the
directory pass (`extract.rs:217-220`) creates `Payload/a` as a directory
before any archive file exists, then phase 1 fails at
`File::create(Payload/a)` with `IO error: Is a directory (os error 21)` —
in both archive orders. None match the pinned messages.

- [ ] **Step 3: Implement collect-pass detection**

Add the ancestor helper next to `is_unsafe_entry_name`:

```rust
/// Returns an ancestor of `path` strictly below `dest_dir` that is already
/// registered as a file entry, if any.
///
/// Walks the whole parent chain: a file `Payload/a` must also reject
/// `Payload/a/b/c`, whose immediate parent is not itself registered. The
/// walk stops at `dest_dir` and never proceeds above it.
fn file_ancestor<'a>(
    path: &Path,
    dest_dir: &Path,
    file_paths: &'a HashSet<PathBuf>,
) -> Option<&'a PathBuf> {
    let mut ancestor = path.parent();
    while let Some(dir) = ancestor {
        if dir == dest_dir || !dir.starts_with(dest_dir) {
            return None;
        }
        if let Some(hit) = file_paths.get(dir) {
            return Some(hit);
        }
        ancestor = dir.parent();
    }
    None
}
```

Add the ancestor-claim helper next to it:

```rust
/// Registers every ancestor of `path` strictly below `dest_dir` as a path
/// that must exist as a directory.
///
/// Claims are recorded when each entry is seen so conflict detection is
/// order-independent: an archive listing `Payload/a/b/c` before
/// `Payload/a` is rejected the same way as the reverse order. The walk
/// stops at `dest_dir` and never claims the destination or anything above
/// it, even if a name encloses to the destination itself.
fn register_ancestor_dirs(path: &Path, dest_dir: &Path, dirs: &mut HashSet<PathBuf>) {
    let mut ancestor = path.parent();
    while let Some(dir) = ancestor {
        if dir == dest_dir || !dir.starts_with(dest_dir) {
            break;
        }
        if !dirs.contains(dir) {
            dirs.insert(dir.to_path_buf());
        }
        ancestor = dir.parent();
    }
}
```

Declare next to `dirs_to_create` (:168):

```rust
    let mut file_paths: HashSet<PathBuf> = HashSet::new();
```

Replace the dir branch's `dirs_to_create.insert(outpath.clone());`
statement (base `extract.rs:190`; the `entries.push(ExtractEntry { ... })`
for the directory entry at base `:191-198` immediately below stays
untouched) with the checks plus registration:

```rust
            if file_paths.contains(&outpath) {
                let relative = outpath.strip_prefix(dest_dir).unwrap_or(&outpath);
                return Err(Error::Io(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("Conflicting entry path in IPA: {}", relative.display()),
                )));
            }
            if let Some(hit) = file_ancestor(&outpath, dest_dir, &file_paths) {
                let relative = hit.strip_prefix(dest_dir).unwrap_or(hit);
                return Err(Error::Io(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("Conflicting entry path in IPA: {}", relative.display()),
                )));
            }
            dirs_to_create.insert(outpath.clone());
            // Claim every implied ancestor as a must-be-directory so a
            // later file at the same path is rejected in the collect pass,
            // whichever order the archive lists them. A dir entry that
            // contains registered files stays legal — claims add no new
            // rejection here.
            register_ancestor_dirs(&outpath, dest_dir, &mut dirs_to_create);
```

Replace the file branch (:200-214) with:

```rust
        } else {
            if file_paths.contains(&outpath) {
                let relative = outpath.strip_prefix(dest_dir).unwrap_or(&outpath);
                return Err(Error::Io(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("Duplicate entry path in IPA: {}", relative.display()),
                )));
            }
            if dirs_to_create.contains(&outpath) {
                let relative = outpath.strip_prefix(dest_dir).unwrap_or(&outpath);
                return Err(Error::Io(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("Conflicting entry path in IPA: {}", relative.display()),
                )));
            }
            if let Some(hit) = file_ancestor(&outpath, dest_dir, &file_paths) {
                let relative = hit.strip_prefix(dest_dir).unwrap_or(hit);
                return Err(Error::Io(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("Conflicting entry path in IPA: {}", relative.display()),
                )));
            }
            // Claim this entry's ancestor chain as must-be-directories; the
            // walk above already rejected file ancestors, and a later file
            // at any claimed path conflicts below.
            register_ancestor_dirs(&outpath, dest_dir, &mut dirs_to_create);
            file_paths.insert(outpath.clone());
            entries.push(ExtractEntry {
                index: i,
                outpath,
                is_dir: false,
                is_symlink,
                #[cfg(unix)]
                unix_mode,
            });
        }
```

Directory duplicates stay legal: explicit dir entries and implicit
ancestors legitimately collide in every normal IPA. `file_paths` grows only
with non-dir entries, so `file_ancestor` never sees a directory hit, and
ancestor-claim registration in *both* branches makes the two-set conflict
rule order-independent: whichever of two contradictory entries comes second
finds the claim. A dir entry that *contains* registered files stays legal —
the dir branch claims ancestors but adds no file-descendant rejection.

- [ ] **Step 4: Run the gate — expect PASS**

Run: `cargo test -p zsign-rs ipa::extract -- --skip test_ipa_signing_is_deterministic`
Expected: all tests pass (3 new, 24 total).

**Acceptance:** all three tests pass with pinned messages; detection happens
in the collect pass — including the deep-ancestor case — before any
directory or file is created. **Controller commits:**
`fix(zsign): reject duplicate ipa entry paths before extraction (ZSN-28)`

---

### Task 6: Replace mmap with buffered reads (remove the only `unsafe`)

**Files:**
- Modify: `crates/zsign/src/ipa/extract.rs` (module docs :7-12, imports
  :28-34, open site :142-149, rayon chunk open :236, symlink pass open :261)
- Modify: `crates/zsign/Cargo.toml` (delete line 24 `memmap2 = "0.9"`)
- Modify: `Cargo.lock` (regenerated by the gate run)

- [ ] **Step 1: Red check**

Run: `cargo test -p zsign-rs ipa::extract -- --skip test_ipa_signing_is_deterministic`
Expected: PASS — this is a behavior-preserving refactor; the red state is the
pre-change evidence that the suite is green before the swap (record output).

- [ ] **Step 2: Remove mmap**

Imports (:28-34) become:

```rust
use crate::{Error, Result};
use rayon::prelude::*;
use std::borrow::Cow;
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use zip::ZipArchive;
```

(delete `use memmap2::Mmap;`, `use std::sync::Arc;`, and `Cursor`; add
`BufReader`; keep the `AtomicU64` import added in task 2.)

Open site (:142-149):

```rust
    // Buffered reads; rayon already parallelizes across entries, so
    // re-opening the archive per pass keeps memory bounded without mmap.
    let file = File::open(ipa_path)?;
    let mut archive = ZipArchive::new(BufReader::new(file)).map_err(Error::Zip)?;
```

Rayon chunk open (inside the closure, replacing the `Cursor::new(&mmap[..])`
lines):

```rust
            let file = File::open(ipa_path)?;
            let mut archive = ZipArchive::new(BufReader::new(file)).map_err(Error::Zip)?;
```

Symlink-pass open: identical replacement.

Delete: the `Arc::new(mmap)` binding, every `Cursor::new(&mmap[..])`, and
the `// Memory-map the IPA file ...` / `// Open ZIP archive from
memory-mapped data` comments. Update the module feature bullet (`extract.rs:9`)
`- Memory-mapped file access for performance` →
`- Buffered file reads with bounded memory use`.

- [ ] **Step 3: Drop the obsolete dependency**

Delete `memmap2 = "0.9"` from `crates/zsign/Cargo.toml:24`. The gate run
below refreshes `Cargo.lock` (memmap2 has no other consumer — verified).

- [ ] **Step 4: Run the gate — expect PASS**

Run: `cargo test -p zsign-rs ipa::extract -- --skip test_ipa_signing_is_deterministic`
Expected: all tests pass (24 total); `Cargo.lock` no longer lists `memmap2`.

- [ ] **Step 5: Confirm zero `unsafe` remains**

Run: grep tool, pattern `unsafe \{`, path `crates/`
Expected: no `unsafe {` in `crates/zsign/src` (the workspace's only block
was `Mmap::map`).

**Acceptance:** identical test results before/after; no `unsafe` left;
`memmap2` gone from `Cargo.toml` + `Cargo.lock`. **Controller commits:**
`refactor(zsign): replace ipa mmap with buffered reads (ZSN-28)`
(Cargo.toml + Cargo.lock ride in this commit as the obsolete-code cleanup.)

---

### Task 7: Re-verify the extraction path after `File::create`

**Files:**
- Modify: `crates/zsign/src/ipa/extract.rs` (rayon copy loop, between
  `File::create` and the `BudgetedWriter` construction)

- [ ] **Step 1: Red check**

Run: `cargo test -p zsign-rs ipa::extract -- --skip test_ipa_signing_is_deterministic`
Expected: PASS (baseline). There is no deterministic test for this
best-effort race guard — a window between `validate_output_path` and
`File::create` cannot be triggered without instrumentation, and the existing
`test_extract_ipa_rejects_descendant_symlink` covers the pre-create check.
Recorded honestly; the gate proves no regression.

- [ ] **Step 2: Implement the post-create check**

Between `File::create(&entry.outpath)?;` and
`let relative = entry.outpath.strip_prefix(...)` insert:

```rust
                // Best-effort TOCTOU guard: re-verify that the path just
                // created is still a regular file before any bytes are
                // written. A full openat(O_NOFOLLOW) rework is out of scope.
                let created = fs::symlink_metadata(&entry.outpath)?;
                if !created.file_type().is_file() {
                    return Err(Error::Io(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!(
                            "Extraction path is not a regular file: {}",
                            entry.outpath.display()
                        ),
                    )));
                }
```

- [ ] **Step 3: Run the gate — expect PASS**

Run: `cargo test -p zsign-rs ipa::extract -- --skip test_ipa_signing_is_deterministic`
Expected: all tests pass (24 total; all four adversarial symlink tests
included).

**Acceptance:** gate green; the copy loop reads validate → create →
re-verify → copy. **Controller commits:**
`fix(zsign): recheck extraction path after file creation (ZSN-28)`

---

## Final verification (after task 7)

1. Full scoped gate: `cargo test -p zsign-rs ipa::extract -- --skip test_ipa_signing_is_deterministic`
   — paste verbatim output into the final report.
2. Whole-workspace compile with the known-failing test skipped (evidence that
   no other lane's code broke):
   `cargo test --workspace -- --skip test_ipa_signing_is_deterministic`
   — run ONCE at the end, never mid-flight.
3. Grep tool over `crates/` for `unsafe \{` → zero hits.
4. Commit list must be exactly: design+plan docs, then tasks 1-7 in order.
   No merges, no pushes — the orchestrator lands the branch.

## Task dependency map

All seven tasks edit `crates/zsign/src/ipa/extract.rs` → strictly sequential,
one task = one commit, gate green before the next task starts. No parallel
subagent batches are safe on this queue.
