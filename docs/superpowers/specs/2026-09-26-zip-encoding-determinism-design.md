# ZSN-7 / ZSN-15 Zip Encoding and Deterministic Output — Design

**Date:** 2026-09-26
**Branch:** `zsn41-zip` (base 97e8460)
**Scope authority:** `/tmp/zsn41.txt` mission brief — two tickets, queue order fixed:
ZSN-7 (entry-name encoding for non-ASCII paths) then ZSN-15 (deterministic zip
output). Each ticket is its own independently-green commit series.

## Problem

**ZSN-7:** IPAs carrying non-ASCII (e.g. Chinese) entry names come out garbled
after our extract→sign→repack round-trip (upstream zhlynn/zsign issue #337
class). The zip crate decodes an entry name as UTF-8 only when general-purpose
bit 11 is set, and as cp437 otherwise (zip-7.2.0 `read.rs:1456-1465`) — so any
input whose writer left bit 11 clear while storing UTF-8 bytes (upstream zsign's
own minizip does exactly this: `flagBase=0`, `zip.c:1271-1276`) extracts to
mojibake on disk, and the repack then persists the mojibake with the flag set.
The ticket requires the flag handled correctly on extraction *and* creation so
file names, directory names, and symlink targets survive every hop.

**ZSN-15:** IPA creation walks the filesystem with an unsorted WalkDir
(`archive.rs:344`), so archive entry order is readdir order — filesystem- and
creation-order-dependent. Parallel (rayon) extraction of regular files
(`extract.rs:470-472`) jitters file creation order between runs, so signing the
same input twice can produce different archive bytes; `test_ipa_signing_is_deterministic`
(`ipa/mod.rs:1126-1146`) is confirmed failing on this machine (3/3, byte diff at
the 7th local header) and is skipped fleet-wide in the release CI job
(`.github/workflows/ci.yml:59-62`). The ticket requires a deterministic walk
sort, verified pinned timestamps, and a no-skip 5× green proof.

## Item-0 re-audit matrix (evidence at base 97e8460)

The ticket line numbers date 2026-09-24; main has since gained ZSN-39, ZSN-35,
ZSN-34. Every cited location was re-derived against current source:

| # | Ticket claim | Verdict | Evidence |
|---|---|---|---|
| a | Extraction name decoding site (`extract.rs`) garbles non-ASCII | **STILL OPEN** | `crates/zsign/src/ipa/extract.rs:356` takes `file.name()`; zip 7.2.0 decodes flag-clear names via cp437 (`~/.cargo/registry/src/…/zip-7.2.0/src/read.rs:1456-1465`) → flag-clear UTF-8 input extracts to mojibake, repack persists it |
| b | Creation name writing (`archive.rs` zip_options/entry_name) needs flag handling | **ALREADY SATISFIED at the crate contract — test-only deliverable** | zip 7.2.0 recomputes bit 11 from the written name bytes on every header: set iff valid UTF-8 **and** non-ASCII (`types.rs:874-890`, used by local `types.rs:920` and central `types.rs:944`); names are `&str` (`write.rs:1245`, raw bytes built at `types.rs:711-712`), so every non-ASCII name is flagged and no public setter exists to change it. `zip_entry_name` (`archive.rs:411-417`, ZSN-39's '/'-join) remains the single creation-name path — integrate, do not duplicate. Deliverable: acceptance test asserting the bit on produced entries |
| c | WalkDir walk at `archive.rs:344` is unsorted | **STILL OPEN (line number coincidentally current)** | `archive.rs:344` = `for entry in WalkDir::new(walk_root).follow_links(false) {` — no sort option; walkdir 2.5.0 (`Cargo.lock:1588-1591`) yields OS readdir order; this machine is btrfs (`stat -f` = `btrfs`, creation-order readdir) |
| d | Repack entry point may be in `ipa/mod.rs` | **NOT THERE — no cross-lane seam needed** | `ipa/mod.rs:283` `extract_ipa`, `:290` `create_ipa_from_root`, `:329` `create_ipa`; zero ordering logic in `mod.rs` (only signing-order sort `:395` and error-text sort `:532`). All zip writing funnels through `write_tree` (`archive.rs:338-405`) — both `create_ipa` (`:260-266`) and `create_ipa_from_root` (`:305-311`) |
| e | CodeResources ordering | **ALREADY SATISFIED (BTreeMap)** | `bundle/code_resources.rs` — not touched, per brief |
| f | Pinned 1980-01-01 timestamps | **ALREADY SATISFIED — load-bearing, will be test-verified** | `archive_options` pins `zip::DateTime::default()` at `archive.rs:325` and `:331`; zip 7.2.0 `DateTime::default()` = 1980-01-01 (`types.rs:254-257`). The pin matters because `SimpleFileOptions::default()` would stamp *now* with the enabled `time` feature (`write.rs:576`, `types.rs:139-145`) |
| g | Fleet-wide `--skip test_ipa_signing_is_deterministic` | **Located; NOT edited (orchestrator's call)** | `.github/workflows/ci.yml:62` (release job, rationale comment `:59-60`); debug test job `:49` and `hk.pkl:32` run unskipped already |
| h | Upstream issue #337 | **Context: effectively unfixed upstream** | Issue closed COMPLETED 2025-05-13 with zero comments and no linked commit; master 614caa8 still writes with vendored minizip `flagBase=0` (`src/third-party/minizip/zip.c:1271-1276`) → upstream-produced IPAs carry flag-clear UTF-8 names, precisely the input class our extraction garbles |

## Scope fence and named seams

- **In scope (edits):** `crates/zsign/src/ipa/extract.rs` and
  `crates/zsign/src/ipa/archive.rs`, production code and their inline
  `#[cfg(test)] mod tests`.
- **Zero-overlap fences:** `crates/zsign/src/ipa/mod.rs` (lane zsn40) — not
  edited; its `test_ipa_signing_is_deterministic` is only *run*. The sort hook
  lives entirely inside `archive.rs::write_tree`, so no mod.rs seam exists
  (matrix row d). `crates/zsign-core/**` (lane zsn42), `bundle/code_resources.rs`
  (row e), WASM zip path (ZSN-16), fixture consolidation/`.gitignore` (ZSN-30),
  README/docs (docs lane), `.github/workflows/ci.yml` skip removal
  (orchestrator's call after landing).
- **Docs-lane notes:** `.tmptmp/` is used for `TMPDIR` but is not gitignored
  (do not commit it; gitignore is ZSN-30's); README could later document
  deterministic output and non-ASCII round-trip support.

## Chosen design

### ZSN-7 — canonical entry-name decode on extraction; creation verified, not changed

1. **One helper in `extract.rs`:**

   ```rust
   /// The entry name as UTF-8 when the raw bytes are valid UTF-8, otherwise
   /// the zip crate's decode (cp437 for flag-clear legacy bytes; lossy UTF-8
   /// when a flag-set name is not valid UTF-8).
   fn canonical_entry_name<'f, R: io::Read + ?Sized>(file: &'f zip::read::ZipFile<'_, R>) -> &'f str {
       std::str::from_utf8(file.name_raw()).unwrap_or_else(|_| file.name())
   }
   ```

   `name_raw()` is inherent and public in zip 7.2.0 (`read.rs:1779`); no trait
   import is needed. Decoding matrix:

   | Input | Result | vs today |
   |---|---|---|
   | flag set, valid UTF-8 | raw bytes (== `name()`) | identical |
   | flag set, invalid UTF-8 | `name()` = `from_utf8_lossy` | identical |
   | flag clear, ASCII | raw bytes (== cp437 decode) | identical |
   | flag clear, valid UTF-8, non-ASCII | **raw bytes = the fix** | was cp437 mojibake |
   | flag clear, non-UTF-8 (genuine legacy cp437, e.g. `0xE9`) | `name()` = cp437 decode | identical |

   Divergence from `name()` happens **iff** flag clear ∧ valid UTF-8 ∧
   non-ASCII — the exact bug class.

2. **Collect pass rewiring (`extract.rs:353-372`):** `let name =
   canonical_entry_name(&file);` replaces `file.name()`; `is_unsafe_entry_name`
   runs on the canonical name (its verdicts are encoding-invariant: every
   structural char it inspects is ASCII — cp437 maps only bytes ≥ 0x80 to
   non-ASCII glyphs, and UTF-8 lead/continuation bytes never decode to ASCII —
   so cp437 and UTF-8 readings of the same bytes reject the same names).
   Outpath building keeps a **fast path**: when `name == file.name()` (every
   input that works today), the existing `enclosed_name()` chain runs
   byte-for-byte unchanged — all hostile-name pins, `./` normalization
   (`extract.rs:1023-1053`), and Windows-path semantics keep their exact
   behavior. Only when they differ (the fix class) a divergence branch runs:
   reject `name.contains('\0')` — the one protection `enclosed_name` provided
   that `is_unsafe_entry_name` does not, pinned by `extract.rs:766-768` — then
   `dest_dir.join(Path::new(name))`. Containment holds because
   `is_unsafe_entry_name` (`extract.rs:120-137`) already rejects leading
   `/`/`\`, drive prefixes (`:125`), `..` segments under both separators, and
   empty/dot-only names. The canonical name is used in the error messages too
   (better diagnostics than the cp437 mojibake).

3. **Creation: no production change.** Matrix row b: zip 7.2.0 sets bit 11 on
   every non-ASCII name automatically and exposes no setter; `zip_entry_name`
   stays the sole name builder. The acceptance test asserts the flag on the
   produced entries by reading them back with the zip crate reader
   (`HasZipMetadata`/`get_metadata().flags`, re-exported at `zip-7.2.0
   lib.rs:36`).

4. **Symlink targets** are entry *content* (zip `write.rs:1565` stores
   `target.to_string()` bytes; extraction reads via `read_to_string`
   `extract.rs:530-531`; creation validates UTF-8-only via
   `checked_symlink_target`, `archive.rs:147-170`) — encoding-independent and
   unchanged; the round-trip test covers it with a non-ASCII target.

### ZSN-15 — sort the walk by archive-name bytes inside `write_tree`

1. **Restructure `write_tree` (`archive.rs:338-405`)** into three phases:
   collect → sort → write. Collect walks WalkDir unchanged
   (`follow_links(false)`, same error mapping), applies `strip_prefix` and
   `name_of` (returning `None` still skips — root suppression for
   `create_ipa_from_root` and the root → `name_prefix` mapping for `create_ipa`
   both live in `name_of`, unchanged), and stores `(archive_name, path)` pairs.
   Sort: `entries.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()))`. Write:
   the existing dir/symlink/file body runs over the sorted pairs.
2. **Ordering policy:** total order = byte-wise order of the archive entry name
   as built by `name_of`/`zip_entry_name` ('/'-joined relative path). This is
   platform-stable (a UTF-8 string, no OsStr/platform variance — the ticket's
   "by relative path bytes, stable across platforms"), guarantees
   parent-before-child (a child's name carries its directory's name as a strict
   byte prefix), keeps the synthetic `Payload/` header first (written before
   `write_tree` at `archive.rs:255-256`), and sweeps ZSN-39's pass-through
   root entries (`SwiftSupport/…`, `iTunesMetadata.plist`) into the same total
   order because they are ordinary walk entries.
3. **Everything else stays pinned:** `archive_options` timestamps (`:325`,
   `:331`), compression method/level (`:330`, extension-based Stored override
   `:374-379`), `unix_permissions` (`:383-387`), ZIP64 gate (`:389-393`),
   symlink policy (`:367-371`) — all per-entry bytes are already deterministic
   for identical inputs; only entry order was not. Verified by test.

## Design decisions (candidates considered)

**E1 — how extraction should decode entry names.**
(i) prefer raw bytes as UTF-8 when valid, fall back to the zip crate's decode,
with a fast path through `enclosed_name()` when both readings agree;
(ii) strict APPNOTE reading — keep zip's decode untouched (flag clear ⇒ cp437
always), fix nothing on read;
(iii) always rebuild the outpath from the canonical name, dropping
`enclosed_name()` entirely.
**Chosen (i).** (ii) leaves the ticket's confirmed symptom unfixed — the input
class is produced by upstream zsign itself (row h) and by any zipper that omits
bit 11; (iii) would re-implement `enclosed_name`'s normalization (the `./`
duplicate-path pin at `extract.rs:1023-1053`) and Windows-path containment for
zero benefit on the 99% fast path — rejected as regression risk against the
extract-hardening suite.
**Acknowledged ambiguity:** flag-clear ∧ valid-UTF-8 ∧ non-ASCII bytes are
genuinely ambiguous (APPNOTE D.2 says such names SHOULD use the original ZIP
charset; modern real-world writers store UTF-8 bytes anyway). We read them as
UTF-8; genuine legacy cp437 names are non-UTF-8 byte sequences and keep the
cp437 decode. The adversarial test pins both readings.

**E2 — creation-side flag handling.**
(i) rely on zip 7.2.0's automatic bit 11 (verified by acceptance test); (ii)
post-write byte-patch of the headers to set the bit (mirroring the setuid
fixture's central-directory patch); (iii) also reject non-UTF-8 on-disk file
names instead of `to_string_lossy` (`archive.rs:232-240`, `:414`).
**Chosen (i).** The crate already computes the bit from the exact bytes it
writes on every header (`types.rs:874-890` → `:920`/`:944`) and offers no
public setter — (ii) re-derives, in production byte-patching, what the crate
guarantees — rejected. (iii) would be a real hardening but is beyond this
ticket: extraction only ever creates filenames from decoded `String`s, so the
extract→sign→repack flow cannot produce non-UTF-8 names; the lossy path is
reachable only from user-supplied directories and is pre-existing behavior.
Recorded as a known limitation, not fixed here (smallest correct change;
no re-scope).

**D1 — where to sort.**
(i) collect-then-sort inside `write_tree`; (ii) WalkDir
`.sort_by_file_name(...)`/`.sort_by(...)` (per-directory sibling sorting);
(iii) sort at each entry point (`create_ipa`, `create_ipa_from_root`) after
name mapping.
**Chosen (i).** Single funnel: both entry points and the ZSN-39 pass-through
roots flow through `write_tree`, so one hook covers all output with zero
`ipa/mod.rs` edits (lane zsn40 fence). (ii) yields only sibling-ordered
traversal with an OsStr comparator that is platform-dependent unless
custom-crafted, and does not express the ticket's global "sort by relative
path bytes". (iii) duplicates the sort at two call sites — second convention —
and silently misses any future `write_tree` caller.

**D2 — sort key.**
(i) the archive entry name (String) bytes as produced by `name_of`;
(ii) raw relative `Path`/`OsStr` bytes.
**Chosen (i).** `OsStr` ordering differs per platform (unix bytes vs Windows
WTF-8), breaking "stable across platforms"; the '/'-joined UTF-8 name is
platform-stable and equals the relative path bytes for every UTF-8 name
(`zip_entry_name` splits on both separators, `archive.rs:411-417`). Parent
ordering is guaranteed by the strict-prefix property; sorting uses the name as
`name_of` returns it (directories without the trailing `/`, which the write
phase appends — a suffix cannot reorder a prefix relationship).

**D3 — determinism proof shape.**
Candidates: rely solely on the existing sign test; or add unit-level pins.
**Chosen: both.** The mandated no-skip 5× run of
`test_ipa_signing_is_deterministic` proves the end-to-end symptom; a
sorted-sequence contract test pins the policy independently of any filesystem's
readdir quirks; a cross-creation-order byte-identity test for
`create_ipa_from_root` (with `SwiftSupport` pass-through entries) is red on
this btrfs machine's creation-order readdir and proves order-independence of
identical inputs.

## Invariants

- Every hostile-name, zip-bomb, duplicate/type-conflict, setuid, and symlink
  test in `extract.rs` keeps passing **unmodified** — the fast path executes
  today's exact `enclosed_name()` code for every input whose two readings agree.
- Zero edits: `ipa/mod.rs`, `bundle/code_resources.rs`, `zsign-core/**`,
  `.github/**`, `Cargo.toml`/`Cargo.lock`, `.gitignore`.
- Entry order: total byte order of archive names; the synthetic `Payload/`
  header entry stays first; directories precede their children.
- Timestamps remain 1980-01-01 on every entry (both compression branches).
- One name convention: `zip_entry_name` remains the only creation-side name
  builder; one decode convention: `canonical_entry_name` is the only place
  extract reads entry names.
- Ticket IDs appear in commit subjects only, never in code comments.
- No stubs, no TODOs, no second conventions; every caller migrated.

## Test strategy

All tests are inline in the owning file's `#[cfg(test)] mod tests` (AGENTS.md),
run with `TMPDIR=$PWD/.tmptmp`, and use the existing helpers/patterns
(`patch_central_dir_unix_mode`-style byte patching, `SimpleFileOptions`,
`TempDir`, `#[cfg(unix)]` on symlink-touching tests).

| # | Test (file) | What it pins | Red before fix? |
|---|---|---|---|
| T1 | `test_extract_repack_roundtrip_preserves_non_ascii_names` (`extract.rs`) | Fixture: `Payload/App.app/资源/` (dir), `资源/测试文件.txt` (file), `资料/说明.txt` (flag-set control), `资源链接` → target `资源/测试文件.txt` (symlink), plus an adversarial entry patched to raw `[0xE9,0xE9]` with bit 11 clear. Fixture builder patches: bit 11 cleared in **local** (+6) and **central** (+8) headers (local offset at central +42), mirroring `patch_central_dir_unix_mode` (`extract.rs:913-951`). Assertions: extract→`create_ipa_from_root`→extract yields the exact literal names at both hops (files, non-ASCII directory, `read_link` target), file contents route correctly, the adversarial name decodes to `éé` at every hop (cp437 fallback, no double-mangle), and every non-ASCII entry of the produced zip has bit 11 set (`get_metadata().flags`, read via the zip crate reader) | **Yes** — flag-clear UTF-8 entries extract to cp437 mojibake today, so the literal-path assertions fail. The adversarial and flag-set assertions are guards (green before and after) |
| T2 | `test_create_ipa_writes_entries_in_sorted_order` (`archive.rs`) | Small tree created in non-sorted order; asserts the exact full `by_index` name sequence (sorted, dirs with trailing `/`, `Payload/` first) and that every entry's `last_modified()` equals `Some(zip::DateTime::default())` (1980-01-01 pin, matrix row f; `last_modified()` returns `Option<DateTime>`, zip-7.2.0 `read.rs:1967`) | **Yes** on this btrfs machine — walk yields creation/readdir order ≠ sorted (Tester confirms red before the fix) |
| T3 | `test_create_ipa_from_root_is_byte_identical_across_creation_order` (`archive.rs`) | Two extraction roots with identical content but opposite file-creation order, including `SwiftSupport/iphoneos/…` and `iTunesMetadata.plist` pass-through siblings (ZSN-39 coverage) → `create_ipa_from_root` outputs compared as whole bytes | **Yes** on this btrfs machine — readdir order differs between the roots → entry order diverges (same divergence class as the confirmed 3/3 sign-test failure) |
| T4 | `test_ipa_signing_is_deterministic` (`ipa/mod.rs:1126-1146`, pre-existing, unmodified) | End-to-end sign-the-same-input-twice byte identity | **Yes** today (3/3 confirmed); must be green **without skip**, proven 5× (brief's acceptance) |

Scoped gates (mid-flight, never project-wide):
`TMPDIR=$PWD/.tmptmp cargo test -p zsign-rs ipa::extract` after Task 1,
`TMPDIR=$PWD/.tmptmp cargo test -p zsign-rs ipa::archive` after Task 2, and the
5× no-skip `test_ipa_signing_is_deterministic` run as Task 2's proof. Final
report gates only: `cargo fmt --all --check`,
`cargo clippy --workspace --all-targets -- -D warnings`,
`TMPDIR=$PWD/.tmptmp cargo test --workspace --no-fail-fast` (no skip anywhere).
