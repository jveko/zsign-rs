# ZSN-28 Hostile-Archive Extraction Hardening — Design

Date: 2026-09-24
Branch: `zsn-28-extract-hardening` (worktree `.worktrees/zsn-28-extract-hardening`)
Scope: `crates/zsign/src/ipa/extract.rs` + its inline tests. Consequence-only
edits: `crates/zsign/Cargo.toml` + `Cargo.lock` (memmap2 becomes unused in
task 6). Explicitly out of scope (owned by other lanes): `ipa/mod.rs`
(lane 27), `ipa/archive.rs` (ZSN-39), `verify.rs` (lane 26), `.github/**`
(lane 31).

## 1. Problem

`extract_ipa` runs on untrusted input (also inside `zsign -V`'s TempDir). A
verified 8-agent review found seven hostile-archive weaknesses: unsafe entry
names are silently skipped, zip bombs fill the disk, symlink targets are read
into unbounded memory, setuid/setgid bits survive extraction, duplicate or
type-conflicting entry paths win nondeterministically, the sole `unsafe`
block in the workspace (`Mmap::map`) has no safety documentation, and the
validate-then-create sequence has an unmitigated TOCTOU window.

## 2. Verified source premises (scout-checked, 2026-09-24)

All line numbers are current at base `ee42c12`; brief citations drifted ≤4
lines and were re-anchored.

| # | Finding | Exact location |
|---|---|---|
| 1 | `enclosed_name()` match, `None => continue` (silent skip) | `extract.rs:173-176` (`None` arm :175) |
| 2 | Uncapped `io::copy(&mut file, &mut outfile)` in rayon closure | `extract.rs:244` |
| 3 | Unbounded `file.read_to_string(&mut target)` before safety check | `extract.rs:266-267` (check :269) |
| 4 | `let perms = mode & 0o7777` (keeps setuid/setgid/sticky) | `extract.rs:250` |
| 5 | Collect pass builds `entries`/`dirs_to_create` with no duplicate/conflict detection | `extract.rs:166-215` |
| 6 | `unsafe { Mmap::map(&file)? }`, no `SAFETY` comment, `Arc`-shared across rayon | `extract.rs:143-145` |
| 7 | `validate_output_path` → `File::create` → `io::copy`, no re-verify | `extract.rs:241-244` |

### Brief premise corrections (source-verified)

1. **`enclosed_name()` does not return `None` for every traversal or absolute
   name in zip 7.2.0.** It componentizes via `Utf8WindowsPath`
   (`zip-7.2.0/src/types.rs:589-607`): `ParentDir` pops and only yields `None`
   on `checked_sub` underflow; a leading `RootDir` or drive `Prefix` is
   *ignored while depth is 0*; `CurDir` is ignored. Consequences, verified
   against the implementation:
   - `"../evil"` → `None` (underflow) → currently skipped. ✔ matches brief.
   - `"Payload/../../evil"` → `None` (second `..` underflows) → currently
     skipped. ✔ matches brief.
   - `"/abs/evil"` → `Some("abs/evil")` — **silently relocated inside the
     dest, not skipped**. The brief's "absolute entry names are skipped"
     premise is wrong; rejecting them needs an explicit raw-name check.
   - `"C:/abs/evil"` and `"\\abs\\evil"` behave like `/abs/evil` (prefix/root
     ignored at depth 0, then relocated) — the raw-name check must be
     Windows-form aware, not just `/`-based.
   - `"Payload/../x"` → `Some("x")` — silently normalized (contained but
     laundered).
   Therefore the fix is two-part: an explicit raw-name traversal/absolute
   check (both separator spellings, drive and UNC prefixes) **plus**
   `None => Err` (covers NUL names and underflow). All four brief regression
   cases error via the raw check.
2. **`SimpleFileOptions::unix_permissions(0o4755)` cannot forge a setuid
   fixture**: it masks `mode & 0o777` on write
   (`zip-7.2.0/src/write.rs:466-470`) and `FileOptions.permissions` is
   `pub(crate)` (`zip-7.2.0/src/types.rs:74-83`). The mode lives only in the
   central directory record at byte offset 38 (packed layout
   `types.rs:1028-1044`), stored as `mode << 16` (`types.rs:708-713`, reader
   `>> 16` at `types.rs:611-616`). The setuid fixture therefore patches the
   CDE's `external_file_attributes` high half to `0o104755` (i.e.
   `(mode << 16) | (old & 0xffff)`, preserving the low DOS-attribute bits)
   after `ZipWriter::finish()`.
3. **`ZipWriter::start_file` rejects byte-identical duplicate names**
   (`zip-7.2.0/src/write.rs:1128-1134`) but accepts *textually distinct,
   semantically equal* names — `./a` vs `a`, `a//b` vs `a/b` (both
   `enclosed_name()` to the same path) and directory `"Payload/D"` (stored as
   `"Payload/D/"`) vs file `"Payload/D"`. Duplicate-path tests use these.
4. `extract_ipa` has exactly two production call sites — `ipa/mod.rs:277`
   (inside `IpaSigner::sign`, directly after `validate_ipa(input_ipa)?` at
   `:268`) and `verify.rs:234` — both positional 2-arg + `?`. The signature
   must not change (verify.rs is lane 26's).
5. `pub mod extract;` (`ipa/mod.rs:55`) makes new pub items reachable as
   `zsign_rs::ipa::extract::*` with **no** `mod.rs`/`lib.rs` edits.
6. `memmap2` has exactly one consumer: `extract.rs:28,:144`; dependency at
   `crates/zsign/Cargo.toml:24`; goblin does not pull it (`Cargo.lock:611`).
7. Error conventions in `extract.rs`: `Error::Io(io::Error::new(kind, msg))`
   for policy violations (`InvalidInput` for path policy, `InvalidData` for
   content policy) and `Error::Zip(ZipError::InvalidArchive(...))` for
   archive-shape rejections. The `Error` enum (`error.rs:31-55`) is published
   and not `#[non_exhaustive]` → **no new variant** (breaking change).
8. Tests: 12 inline tests (`extract.rs:368-612`); the four adversarial ones
   are `test_is_safe_symlink_target` (:539), `test_extract_ipa_rejects_
   malicious_symlink` (:549), `..._rejects_symlink_dest` (:579),
   `..._rejects_descendant_symlink` (:595). Existing tests assert bare
   `is_err()`; new tests must also pin the error message so an unrelated I/O
   error cannot false-green them.

## 3. Per-item candidate designs

### Item 1 — fail closed on unsafe entry names
- **A (chosen):** In the collect pass, reject any raw entry name that is
  absolute in either spelling — starts with `/` or `\`, or carries an
  alphabetic `X:` drive prefix — whose `/`- **and** `\`-separated segments
  contain `..`, or that has no substantive component at all (``, `.`, `./`;
  zip encloses these as an empty path resolving to the destination itself).
  Additionally the `enclosed_name()` arm errors on `None` **and** on an
  empty enclosed path, naming the raw entry. Both checks use the raw
  `file.name()` and run before any directory or file is written. The dual spelling matters: the reader componentizes names with
  Windows-path semantics (`Utf8WindowsPath`), so `C:/evil` and `\evil` would
  otherwise be silently relocated inside the dest instead of rejected.
- **B:** Rely on `enclosed_name() == None` alone. Rejected: does not catch
  absolute names or safely-normalized `..` (they are silently relocated, see
  premise correction 1), so the "absolute entry names" part of the brief
  stays broken.
- **C:** Collect violations and report after extraction. Rejected: partial
  extraction has already happened; violates fail-closed.
- Error: `Error::Io(InvalidInput)` with `Unsafe entry name in IPA: <raw>`,
  mirroring the sibling symlink policy that hard-errors.

### Item 2 — zip-bomb budgets
- **A (chosen):** `ExtractionLimits { max_entry_bytes, max_total_bytes }`
  (`Default` = 2 GiB / 8 GiB), enforced **while writing**: a
  `BudgetedWriter` adapter wraps the output file and, for every buffer, (a)
  checks `entry_written + buf.len()` against the entry cap, then (b)
  `fetch_add`s `buf.len()` into a shared `AtomicU64` total
  (`Relaxed`, captured by reference across rayon workers) and checks it
  against the total cap — all **before** the buffer reaches the underlying
  writer. Neither cap can be overshot by parallel workers: bytes reaching
  disk stay ≤ `max_entry_bytes` per entry and ≤ `max_total_bytes` overall.
  Symlink target bytes count toward both caps in the sequential symlink pass
  (entry cap: target length; total: reserved before `symlink(2)` is called).
  New sibling `extract_ipa_with_limits(ipa, dest, limits: ExtractionLimits)`
  ; `extract_ipa` delegates with `ExtractionLimits::default()` so the two
  call sites keep their 2-arg signature.
- **B:** Pre-check declared `file.size()` at collect time only. Rejected:
  header sizes are attacker-controlled; a lying-small header bypasses it.
  Write-time counting is the only guarantee the brief requires.
- **C:** Pre-check *and* write-time counting. Rejected as redundant code for
  a check that cannot change any outcome the write-time cap does not already
  catch (at best it fails a few seconds earlier on a declared bomb).
- Error: `Error::Io(InvalidData)`, message must contain
  `Archive exceeds extraction limit`.
- Symlink targets participate fully: each target is checked against the
  entry cap and its length reserved against the total before the link is
  created; the item-3 read bound (4096 bytes) still caps each individual
  read.

### Item 3 — bound the symlink-target read
- **A (chosen):** A `#[cfg(unix)]` const `MAX_SYMLINK_TARGET_BYTES: usize
  = 4096` (Linux `PATH_MAX`; longer targets can never be `symlink()`ed
  anyway). Read via
  `file.take(MAX + 1).read_to_string(&mut target)`, then reject
  `target.len() > MAX` **before** the budget accounting and
  `is_safe_symlink_target`. Peak memory bounded at ~4097 bytes.
- **B:** Read into a fixed `[u8; 4096]` with `read_exact`. Rejected:
  more code (short-read handling, UTF-8 conversion) for the same bound.
- Error: `Error::Io(InvalidData)` with
  `Symlink target too long in IPA: ...`.

### Item 4 — strip setuid/setgid/sticky
- **A (chosen):** `mode & 0o777` when restoring permissions. The extraction
  target is app-bundle content; no archive-supplied privilege or sticky bit
  should ever reach disk.
- **B:** `mode & 0o7777 & !0o7000` (strip setuid/setgid only, keep sticky).
  Rejected: identical result to `0o777` for every value where sticky matters
  nothing for bundle content, and the brief specifies `0o777`.
- Fixture: CDE byte-patch helper in the inline tests (premise correction 2).

### Item 5 — duplicate/conflicting paths
- **A (chosen):** In the collect pass, maintain two claims per path —
  `file_paths: HashSet<PathBuf>` (every file/symlink entry) and
  `dirs_to_create` (every path that must exist as a directory: explicit dir
  entries **and the full ancestor chain of every entry**, claimed when the
  entry is seen). Checks at each insert, all before any write:
  - file/symlink path already in `file_paths` → `Duplicate entry path in
    IPA: <rel>`;
  - file/symlink path already in `dirs_to_create` → `Conflicting entry path
    in IPA: <rel>` — this catches a same-path dir entry *and* an ancestor
    implied by an already-registered descendant, so archive orders
    `Payload/a` → `Payload/a/b/c` **and** `Payload/a/b/c` → `Payload/a`
    fail identically, both naming `Payload/a`;
  - dir entry whose path is in `file_paths` → conflict;
  - any ancestor of the current entry (walk bounded by
    `starts_with(dest_dir)` — it stops at `dest_dir` and never proceeds
    above it) already in `file_paths` → conflict naming that ancestor.
  Because every entry claims its full ancestor chain when seen, detection is
  order-independent: whichever of the two contradictory entries comes second
  finds the claim. The dir branch adds claims but no new rejection: a dir
  entry that *contains* registered files (`Payload/a/b/` with
  `Payload/a/b/c`) is agreement, not conflict, and must keep passing.
  Directory duplicates stay legal (explicit dir entries and implicit
  ancestors legitimately collide; erroring would reject every normal IPA).
  All errors `Error::Io(InvalidInput)`, message carries the path relative to
  `dest_dir` (stable across TempDir prefixes).
- **B:** Single `HashMap<PathBuf, EntryKind>`. Rejected: equivalent
  semantics, but a bigger rewrite of the collect pass than the fix needs;
  two sets match the existing structure (dirs are already a `HashSet`).
- **C:** Detect during/after writes. Rejected: nondeterministic winner is
  already on disk — detection must precede any write.

### Item 6 — remove the bare `unsafe` mmap
- **A (chosen):** Plain buffered reads. Each pass opens
  `ZipArchive::new(BufReader::new(File::open(ipa_path)?))`: the collect pass
  once, each rayon chunk once (rayon already parallelizes entries; the
  per-chunk `ZipArchive::new` already re-reads the central directory today),
  the symlink pass once. Removes `Mmap`, `Arc`, `Cursor`, and the workspace's
  only `unsafe` block entirely; memory stays bounded regardless of archive
  size. Consequence: drop `memmap2` from `crates/zsign/Cargo.toml:24` and
  refresh `Cargo.lock`.
- **B:** Keep mmap, add a `// SAFETY:` comment. Rejected: the brief prefers
  buffered reads and the residual risk (external truncation → SIGBUS during
  the extraction window) is only documented, not removed.
- **C:** Read the whole file into an `Arc<Vec<u8>>`. Rejected: holds the
  entire archive in anonymous RAM (multi-GiB IPAs) where mmap pages were
  evictable.

### Item 7 — narrow the validate-then-create TOCTOU
- **A (chosen):** After `File::create`, re-check
  `fs::symlink_metadata(&entry.outpath)?.file_type().is_file()` before
  `io::copy`; otherwise `Error::Io(InvalidInput)` "Extraction path is not a
  regular file". Comment states this is best-effort and that a full
  `openat(O_NOFOLLOW)` rework is out of scope.
- **B:** `create_new(true)` (O_EXCL) or `O_NOFOLLOW` custom flags. Rejected:
  `create_new` breaks legitimate re-extraction into an existing directory;
  `O_NOFOLLOW` needs platform-specific flag plumbing beyond the brief's
  "best-effort" scope.
- No dedicated regression test: the race has no deterministic trigger
  without instrumentation; the four existing symlink tests keep covering the
  pre-create check. Recorded honestly rather than adding a flaky test.

## 4. Cross-cutting design

### API shape
```rust
pub struct ExtractionLimits {
    pub max_entry_bytes: u64,   // Default: 2 GiB
    pub max_total_bytes: u64,   // Default: 8 GiB
}
impl Default for ExtractionLimits { ... }

pub fn extract_ipa(ipa_path, dest_dir) -> Result<PathBuf>;            // delegates, unchanged signature
pub fn extract_ipa_with_limits(ipa_path, dest_dir, limits: ExtractionLimits) -> Result<PathBuf>;
```
`ExtractionLimits` is `Copy` and passed by value, matching the
`CompressionLevel` precedent (`archive.rs:51-97`, required positional value
param on `create_ipa`). Reachable as `zsign_rs::ipa::extract::ExtractionLimits`
through `pub mod extract;` — no `mod.rs`/`lib.rs` re-export churn (those
files belong to other lanes; a crate-root alias can be added by whoever owns
them later).

### Error mapping (no new `Error` variants)
| Condition | Variant / kind | Message (asserted substring **bold**) |
|---|---|---|
| `..` segment, `/`- or `\`-rooted, or drive-prefixed raw name; `enclosed_name()` → `None` | `Io(InvalidInput)` | `Unsafe entry name in IPA: <raw>` |
| entry over `max_entry_bytes` (file write or symlink target) | `Io(InvalidData)` | `Archive exceeds extraction limit: entry '<rel>' exceeds <N> bytes` |
| total over `max_total_bytes` (file bytes or symlink targets) | `Io(InvalidData)` | `Archive exceeds extraction limit: total extracted size exceeds <N> bytes` |
| symlink target > 4096 bytes | `Io(InvalidData)` | `Symlink target too long in IPA: <path> (...)` |
| duplicate file path | `Io(InvalidInput)` | `Duplicate entry path in IPA: <rel>` |
| dir/file, parent/file, or ancestor/file conflict | `Io(InvalidInput)` | `Conflicting entry path in IPA: <rel>` |
| post-create path not a regular file | `Io(InvalidInput)` | `Extraction path is not a regular file: <path>` |

`<rel>` = `outpath.strip_prefix(dest_dir)` (TempDir-stable in tests). The
published `Error` enum stays untouched; `thiserror` forwards the inner
message so every substring above is visible via `err.to_string()`.

### Byte-accounting detail
`BudgetedWriter<W>` wraps `BufWriter<File>` in the rayon loop. Its `write()`
(a) rejects `entry_written + buf.len() > max_entry_bytes`, then (b)
`fetch_add`s `buf.len()` into the shared total and rejects
`total > max_total_bytes` — both **before** `inner.write(buf)`. Bytes
actually reaching disk are therefore ≤ `max_entry_bytes` per entry and ≤
`max_total_bytes` in aggregate, no matter how many workers run concurrently;
the only overshoot possible is bytes held in `io::copy`'s small read buffer
in memory, never on disk. `Ordering::Relaxed` suffices: atomicity of the
tally is what matters, not ordering. A short inner write may over-reserve
the total by the unwritten remainder — conservative, fails closed. Symlink
pass: after the bounded read and its length check, the target length is
checked against the entry cap and reserved against the total, both before
`symlink(2)` is called. On error the `BufWriter` flushes its already-
reserved partial file on drop — same as every other mid-extraction failure
today; the destination is caller-invalidated on `Err`, which the existing
contract already assumes.

## 5. Invariants

1. **Fail closed:** any rejection aborts the whole extraction; no entry is
   ever silently skipped or relocated.
2. **No writes before name validation:** unsafe-name and duplicate/conflict
   checks run in the collect pass, before any payload write — a rejected
   name or path leaves no payload files. Budget and mid-write I/O failures
   are *not* rolled back: they may leave partial destination content (the
   destination is caller-invalidated on `Err`; no rollback is in scope).
3. **Bounded resource use:** bytes reaching disk ≤ `max_entry_bytes` per
   entry and ≤ `max_total_bytes` in aggregate (symlink targets included);
   per-worker overshoot beyond disk is only `io::copy`'s in-memory read
   buffer; symlink target read ≤ 4097 bytes; no `unsafe` code remains in
   the workspace.
4. **Privilege hygiene:** extracted files carry only `mode & 0o777`.
5. **Signature stability:** `extract_ipa`/`validate_ipa` keep their current
   signatures; the two `extract_ipa` call sites compile unchanged.
6. **Existing security tests unchanged:** the four adversarial symlink tests
   and `test_is_safe_symlink_target` keep passing as written.
7. **Scope:** only `extract.rs` (+ inline tests), plus the memmap2 removal
   in `crates/zsign/Cargo.toml` / `Cargo.lock` that task 6 obsoletes.

## 6. Test strategy

All tests are inline (`extract.rs` `mod tests`), built with `ZipWriter`
(string-name APIs only — `*_from_path` sanitizes). Every new test pins the
error **message substring** (and where useful the `Error::Io` kind) so an
unrelated `NotFound`/`ENAMETOOLONG`/`EISDIR` error cannot false-green it.
Twelve new tests across tasks 1-5.

| Test | Fixture | Pre-fix result (proof of regression value) |
|---|---|---|
| `test_extract_ipa_rejects_parent_traversal_entry` | `start_file("../evil")` inside an otherwise-valid IPA | pre-fix: skipped silently, extraction *succeeds* → test fails |
| `test_extract_ipa_rejects_nested_traversal_entry` | `start_file("Payload/../../evil")` plus the accepted `start_file("Payload/../evil")` spelling | pre-fix: first → `None` skipped, second → silently normalized to `evil`; extraction succeeds → fails |
| `test_extract_ipa_rejects_absolute_entry_name` | `start_file("/abs/evil")`, component-less `""`/`"."`/`"./"`, and a NUL name `Payload/\0evil` (the only form reaching the non-`Some` enclosure arm) | pre-fix: `/abs…` relocated, empty/dot resolve to `dest_dir` (unpinned dir error), NUL skipped silently — extraction succeeds or errs unpinned → fails |
| `test_extract_ipa_rejects_windows_style_absolute_entry_name` | `start_file("C:/abs/evil")`, `start_file("\\abs\\evil")`, and backslash traversal `start_file("Payload\\sub\\..\\evil")` | pre-fix: prefix/root ignored or `..` popped, relocated inside dest, succeeds → fails |
| `test_extract_ipa_rejects_oversized_entry` | 2048-byte entry, `ExtractionLimits { max_entry_bytes: 100, ... }` | pre-fix: no limits API → red at compile |
| `test_extract_ipa_rejects_oversized_total` | two 600-byte entries, `max_total_bytes: 1000` | pre-fix: no limits API → red at compile |
| `test_extract_ipa_rejects_total_overflow_from_symlinks` (unix) | small file + two 4090-byte symlink targets, `max_total_bytes: 5000` | pre-fix: no limits API → red at compile |
| `test_extract_ipa_strips_setuid_bit` (unix) | CDE-patched `0o104755` mode on `Info.plist`; assert on-disk `mode & 0o7777 == 0o755` | pre-fix: on-disk `0o4755` → fails |
| `test_extract_ipa_rejects_duplicate_normalized_paths` | `Payload/Test.app/Info.plist` + `./Payload/Test.app/Info.plist` | pre-fix: last-write-wins, succeeds → fails |
| `test_extract_ipa_rejects_type_conflicting_entries` | one helper, four orderings: dir→file and file→dir at `Payload/D`, then file→dir-under-file and dir→file-ancestor at `Payload/a`; asserts pinned message **and** `!Payload` written | pre-fix: dir pass runs, `File::create` → `Is a directory (os error 21)`, unpinned → fails message assert |
| `test_extract_ipa_rejects_descendant_of_file_entry` | both archive orders in one test fn: file `Payload/a` → file `Payload/a/b/c`, and `Payload/a/b/c` → `Payload/a` | pre-fix: dir pass creates `Payload/a`, then `File::create(Payload/a)` → `Is a directory (os error 21)`, unpinned → fails message assert |
| `test_extract_ipa_rejects_long_symlink_target` (unix) | `add_symlink` with a 5000-char safe target | pre-fix: fails later at `symlink()` with `File name too long`; message assert on `Symlink target too long in IPA` → fails |

Determinism notes:
- The two 600-byte entries sum to 1200 > 1000, so at least one reservation
  observes an over-total value regardless of chunk scheduling — that test
  always errors, and disk bytes can never exceed the cap because the
  reservation happens before each write.
- The symlink budget test runs in the sequential symlink pass after the
  files pass (49-byte file + 4090 = 4139 ≤ 5000; second target crosses
  5000) — fully ordered, no scheduling dependence.

Scoped gate after every task (never project-wide, per brief):

```
cargo test -p zsign-rs ipa::extract -- --skip test_ipa_signing_is_deterministic
```

## 7. Design-decisions (rejected alternatives, consolidated)

1. Skipped-entry silent skip → hard error (fail-closed over partial
   extraction). — item 1
2. Raw-name check **and** non-`Some`/empty enclosure → `Err`:
   `enclosed_name` alone cannot see absolute names or component-less names;
   the raw check is Windows-form aware (both separators, drive/UNC prefixes)
   and rejects names with no substantive segment (``, `.`, `./`). — item 1
3. Write-time byte counting over declared-size prechecks; no redundant
   preflight. — item 2
4. Sibling `extract_ipa_with_limits` + `Copy` struct over changing
   `extract_ipa`'s signature (would break `verify.rs:234`, lane 26), over
   `Option<ExtractionLimits>` (callers would pass `None` habitually), and
   over a builder (one knob, YAGNI). — item 2
5. Pre-write reservation (`BudgetedWriter`) over a post-copy `fetch_add`
   tally: a post-hoc tally lets every parallel worker commit a full entry
   to disk before the error fires, overshooting `max_total_bytes`. — item 2
6. Symlink target bytes counted toward both caps: partitioning symlinks out
   of the file loop must not exempt them from the budget. — item 2
7. Two `HashSet`s over a kind-map rewrite in the collect pass; directory
   duplicates remain legal; every entry claims its full ancestor chain at
   collect time so conflict detection is order-independent — both
   `Payload/a` → `Payload/a/b/c` and the reverse order fail identically,
   and a dir entry containing registered files stays legal. — item 5
8. Buffered per-pass `File` reopens over mmap-with-SAFETY (residual SIGBUS
   stays) and over whole-file `Arc<Vec<u8>>` (unbounded RAM). — item 6
9. Best-effort post-create `symlink_metadata` check over `create_new`/O_EXCL
   (breaks re-extraction) and over full `openat` plumbing (out of scope). — item 7
10. No new `Error` variant: the enum is published and non-`#[non_exhaustive]`;
    `Error::Io(kind, msg)` is this file's existing idiom.
11. CDE byte-patch setuid fixture (with low 16 bits preserved) over
    `unix_permissions` (masks to `0o777`) over symlink/dir mode tricks (never
    reach `set_permissions`).
12. Message-pinning assertions over bare `is_err()` for all new tests.

## 8. Deferred

- Signing-time path containment / discovery classification: lane 27
  (`ipa/mod.rs`).
- Re-pack fidelity: ZSN-39 (`ipa/archive.rs`).
- Consuming these errors in reports: lane 26 (`verify.rs`).
- CI wiring: lane 31 (`.github/**`).
