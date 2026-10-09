# Reject Non-Regular Files in Bundle Scan — Design
> Line citations are anchored to the pre-implementation base commit `b8b71e6`. The gate commit shifted `code_resources.rs` items from `hash_entry` onward down by a few lines; cited statements and symbols remain the ones described.

## Problem

The bundle scan hashes every walked entry that is not a directory and not a
symlink. `scan()` (`crates/zsign/src/bundle/code_resources.rs:166`) collects
`store.walk(&bundle_path)` (`:173-177`), maps every entry through `hash_entry`
(parallel arm `:180-186`, wasm sequential arm `:190-196`), and `hash_entry`
dispatches on kind: directory → `Ok(None)` (`:218-220`), symlink →
`hash_symlink_entry` (`:317-330`), otherwise → `hash_file_streaming(store,
path)?` (`:254`). `hash_file_streaming` (`:332-355`) does `store.open(path)?`
(`:337`) and reads to EOF (`:341-347`). There is no buffered fast path and no
size threshold — every non-dir non-symlink entry streams unconditionally.

POSIX: an open-for-read on a FIFO waits for a writer. With no writer the call
blocks indefinitely (as does the first read if open returns), so the rayon
worker driving `hash_entry` never returns, `collect::<Result<Vec<_>>>` never
completes, and signing hangs forever — a trivial denial of service.

The root cause is classification. `FsStore` classifies by fallback
(`dir / symlink / else File`) at four sites: `list`
(`crates/zsign/src/store.rs:118-124`), `metadata` (`:131-137`), `walk`
(`:178-184`), and `walk_pruned`'s `kind_of` closure (`:198-205`). Every inode
that is not a directory and not a symlink — FIFO, socket, device node —
becomes `StoreKind::File` and is handed to the hashing arm. `StoreStat::is_file()`
(`store.rs:31-33`) exists but is never used to classify; its single production
caller — the `CFBundleExecutable` regular-file check
(`crates/zsign/src/ipa/mod.rs:1827-1834`, message "does not name a regular
file") — receives `File` for a FIFO, so that check can never fire for one.

Every current `StoreKind` consumer was audited; all are comparisons, none is
an exhaustive `match`, so a new kind variant breaks no code:

- `hash_entry` dispatch (`code_resources.rs:216-218`) — the hashing arm in question.
- Nested-bundle/app-dir detection: `ipa/mod.rs:1238`, `:1335` (`kind == Dir`) — unchanged for FIFOs (they were never `Dir`).
- Dylib/binary discovery gates `!matches!(kind, StoreKind::File) → continue`
  (`ipa/mod.rs:1441`, `:1682`) — today a FIFO passes this gate and proceeds as
  a candidate binary input.
- App-dir scan in extraction (`ipa/extract.rs:839`, `kind != Dir → continue`) — unchanged.
- Archive write path (`ipa/archive.rs:430-455`) reads `store.metadata` and
  branches `is_dir / is_symlink / else read` — a non-regular entry still
  reaches its read arm; that path is a separate workstream (see Deferred).
- `MemStore` maps its own `Node` enum (`ipa/mem_store.rs:38-42`) and cannot
  represent a non-regular entry.
- The verifier already skips non-regular files during its disk walk
  (`crates/zsign/src/verify.rs:886-888`), so verify never hangs on one.

There is no FIFO or special-file test anywhere: a workspace grep for
`mkfifo|fifo|S_IFIFO|mknod|FileTypeExt|special file` returns zero matches.

## External contract (researched)

Verified against Apple's open-source Security framework
(`apple-oss-distributions/Security` @ Security-61901.0.87.0.1), upstream
zsign (`zhlynn/zsign` master @ 614caa8), and third-party tooling, read
2026-10-09:

1. **Apple's signer hard-errors on non-regular entries before any open.**
   `ResourceBuilder::scan` switches on `fts_read()`'s `fts_info`
   (`OSX/libsecurity_codesigning/lib/resources.cpp:285-296`): only `FTS_F`
   (hash), `FTS_SL` (record symlink), `FTS_D`/`FTS_DP` (recurse) are handled;
   everything else hits `default:`, which throws
   `errSecCSResourceNotSupported` (-67016) — defined with the exact condition
   at `OSX/include/security_codesigning/CSCommon.h:122`: "unsupported resource
   found (something not a directory, file or symlink)". The throw runs before
   any hash/open, so Apple never opens a FIFO. The error is gated by
   `mCheckUnknownType = strict && !toleratedErrors.contains(...)`
   (`resources.cpp:66-68`): in non-strict mode Apple **silently skips** the
   entry — no CodeResources record at all. Apple provides a hard-error mode
   and a silent-skip mode; it never provides a "recorded omission" mode.
2. **The CodeResources format has no slot for an irregular file.**
   `ResourceSeal::ResourceSeal(CFTypeRef)` (`resources.cpp:459-490`) accepts
   only a bare `CFData` hash or a dict matching `{requirement=…}`,
   `{symlink=…}`, or `{optional=…}`; anything else →
   `errSecCSResourcesInvalid`. The `omitted` flag exists only on *rules*
   (`resources.cpp:106-118`), never on an emitted per-entry value. Emitting a
   fabricated entry for a FIFO would be unparseable by Apple's verifier, not
   merely different.
3. **Upstream zsign hangs identically; it is no precedent.**
   `ZFile::EnumFolder` classifies with `d_type`, treating only `DT_DIR` as
   folder (`src/common/fs.cpp:522-532`); a grep for `S_ISREG` across its `src/`
   returns zero matches. `ZBundle::GenerateCodeResources` then hashes every
   non-folder entry via `ZSHA::SHABase64File` with the result ignored
   (`src/bundle.cpp:189-194`) → `SHAFile` opens and streams to EOF
   (`src/common/sha.cpp:82-90`). "Match upstream" here means "hang"; any
   divergence is intentional.
4. **Third-party tooling splits.** `rcodesign`'s bundle walker warns and
   continues on an unexpected file type
   (`apple-codesign/src/code_resources.rs:1150-1241`) — a skip with a log
   line. There is no third-party consensus to conform to.
5. **This repo already fails closed for the sibling scan-time integrity
   conditions.** Non-UTF-8 entry names (`code_resources.rs:236-244`) and
   non-UTF-8 symlink targets (`:316-330`) both return
   `Error::Core(zsign_core::Error::Signing(String))`, as does the
   `CFBundleExecutable` regular-file check (`ipa/mod.rs:1827-1834`). Silent
   skips exist only for entries that are never sealed (directories `:218-220`,
   excluded paths `:229-231`, the verifier's disk walk `verify.rs:886-888`).

## Candidate designs

### A — Honest classification + fail-closed scan gate (chosen)

Add `StoreKind::NonRegular`; classify through one helper over
`std::fs::FileType` (`is_symlink / is_dir / is_file(=S_ISREG) / else
NonRegular`) at all four `FsStore` sites; reject `NonRegular` in `hash_entry`
after `should_exclude` with the established typed scan error.

- Pros: fixes the root cause (the kind collapse) rather than the symptom;
  matches Apple's strict behavior, which rejects before any open; reuses the
  existing `Error::Core(Signing)` family, so the exhaustive wasm error mapping
  and CLI need no changes; needs no warnings channel; separates mechanism
  (store classifies) from policy (each consumer decides), which is exactly the
  extension point the archive-write workstream needs; `StoreStat::is_file()`
  gains its stated meaning for its existing caller; the dylib-discovery gates
  start skipping special files instead of opening them; zero extra syscalls
  (the walk already lstats every entry).
- Cons: four classification sites change in a file other workstreams touch
  (the change is mechanical and the variant's doc records the policy
  split); consumers that previously saw `File` for special files now see
  `NonRegular` (audited above — every affected site becomes fail-safe).

### B — Skip with recorded omission (rejected)

Return `Ok(None)` for non-regular entries and record an omission. The format
has no per-entry omission slot (finding 2), so "recording" would mean emitting
a per-path `omitted` rule — which tells every verifier to *ignore that path*.
The premise of this bug is that an attacker can plant an FIFO in the bundle;
skip-with-omission would let whoever planted it later plant *any* content at
that path and have it pass verification silently. It would also be invisible:
there is no warnings/omissions channel in the CLI (`SignDoc`/`ErrorDoc` only,
`crates/zsign-cli/src/main.rs:762-790`). Apple skips only in non-strict mode
and records nothing; this repo has no strict/non-strict switch.

### C — Gate in the scan via `unix_mode` S_IFMT bits, leave classification alone (rejected)

Call `store.metadata` per entry and test `(unix_mode & 0o170000)` before
hashing. Rejected: an extra stat syscall per entry (or a `walk` signature
change); unix-specific bit logic in a facade module compiled to wasm where
`unix_mode` is `None` and would need an assume-regular special case; and the
kind collapse survives, so `is_file()` stays wrong and the dylib-discovery
gates still pass FIFOs. A symptom patch.

### D — Refuse inside `Store::open`/`read` (rejected)

Guard every open with an lstat. Rejected: the guard must run before open, so
it needs either flag plumbing (`O_NONBLOCK`, platform-specific) or a
lstat-then-open sequence that is TOCTOU-racy against the same attacker; and it
changes the contract of every `Store` IO primitive for all consumers —
precisely the "keep the store change minimal, classification only" boundary.

### E — Make `FsStore::metadata`/`walk` error on non-regular entries (rejected)

Rejected: it bakes policy into the shared mechanism. `walk` is also the
archive write path's enumerator, so erroring there would deliver that
workstream's rejection for it (duplication, not extension), and `exists()` is
defined as `metadata(path).is_ok()` (`store.rs:90-92`), so non-regular
entries would silently change `exists()` answers across the flow.

## Decisions recorded

- **Error shape:** `Error::Core(zsign_core::Error::Signing(String))` with the
  message exactly prefixed `Unsupported file type (not a regular file,
  directory, or symlink): ` followed by `path.display()` (rendered as
  `Signing failed: Unsupported file type …`). No new `Error` variant — the wasm
  `code_for_zsign_error` match is deliberately exhaustive, and `Signing`
  already maps to the stable `ZSIGN_SIGNING_FAILED`.
- **Gate placement is after `should_exclude`
  (`code_resources.rs:229-231`)**, before the UTF-8 name check and before any
  hashing: an excluded entry is never sealed and therefore never opened, so it
  needs no type validation — the same exclusion-precedence principle the
  landed UTF-8 guards use. The directory short-circuit (`:218-220`) stays
  first.
- **`StoreKind::NonRegular` is classification only.** Its doc comment states
  that each consumer decides whether to reject or skip such entries, so the
  archive-write workstream extends the same mechanism instead of duplicating
  it.
- **One classifier, four call sites.** A private `fn classify(&std::fs::FileType)
  -> StoreKind` replaces the four fallback chains (`list`, `metadata` via
  `md.file_type()`, `walk`, `walk_pruned`). `File` now means *regular file*
  (`S_ISREG`), which is what `StoreStat::is_file()`'s doc already implies.
- **What the seal records:** nothing. The scan aborts with the path-named
  error before `build()`, so no partial CodeResources is produced and signing
  fails closed.
- **Verify round-trip:** the verifier's disk walk already skips non-regular
  entries (`verify.rs:886-888`), and the only bundles this change lets through
  signing are those without irregular entries — seal behavior for every
  signable bundle is byte-identical. No verifier change.
- **No new dependencies.** Fixtures use `std::process::Command::new("mkfifo")`
  (a POSIX-mandated utility) and `std::os::unix::net::UnixListener` — both
  `#[cfg(unix)]`; `Cargo.toml` files are untouched.

## Deferred (explicitly out of scope)

- **Archive write side:** `write_tree`'s metadata branch
  (`ipa/archive.rs:430-455`) still opens a non-regular entry in its final
  arm. That workstream owns the rejection; this change deliberately hands it
  an honest kind and nothing else.
- **Extract-side entry types:** whether extraction materializes special files
  from a crafted archive — separate workstream.
- **Other `store.read` sites for a planted `Info.plist`:** the builder's
  constructor reads it (`read_main_executable`, `code_resources.rs:290-311`,
  blocking read at `:297`) and the sign flow reads the same path at several
  sites outside this file (`bundle/mod.rs:110`, `ipa/mod.rs:1136`, `:1163`,
  `:1718`, `:1754`, `:1795`, `:1956`) — each of those reads blocks on a FIFO
  at that exact path, while the `exists()` probes preceding some of them
  (`ipa/mod.rs:1711`, `:1747`, `:1788`) are lstat-only and do not block. The
  ticket's fix text gates hashing; guarding every read site is a separate
  hardening workstream.
- **Verifier-side policy for irregular entries** beyond the existing skip:
  unchanged by this design.

## Testing strategy

1. **Classification (new `#[cfg(test)]` module in
   `crates/zsign/src/store.rs`):** a FIFO created with `mkfifo` must classify
   as `NonRegular` through `metadata`, `list`, `walk`, and `walk_pruned`, with
   `is_file()/is_dir()/is_symlink()` all false; a `UnixListener` socket likewise
   via `metadata`; regular file/dir/symlink kinds unchanged (portable test for
   the common cases). Fails before the change: all classify as `File` today.
2. **Hang regression (`crates/zsign/src/bundle/code_resources.rs` tests):** a
   bundle containing a FIFO must make `scan()` return the typed error within a
   bounded time — the scan runs on a worker thread with
   `mpsc::recv_timeout(Duration::from_secs(10))` (the house bounded-time
   precedent, `ipa/mem_store.rs:614-639`); the timeout arm panics, so a
   regression fails the suite instead of hanging it.
3. **Exclusion precedence:** a FIFO under an excluded directory must scan
   cleanly — pins the gate's position after `should_exclude`.
4. **No collateral change:** the full crate's tests (symlink trio, UTF-8 trio,
   plist-shape tests) stay green.

## Acceptance

- Sealing a bundle that contains a FIFO (or any non-regular entry) completes
  in bounded time and fails with a typed, matchable error naming the path; no
  CodeResources output is produced.
- `FsStore` classifies FIFO/socket/device entries as `StoreKind::NonRegular`
  everywhere it reports kinds; `StoreKind::File` means regular file.
- Excluded entries, directories, symlinks, and all regular files seal exactly
  as today; `CFBundleExecutable` pointing at a FIFO now fails its existing
  regular-file check.
- Changes limited to `crates/zsign/src/store.rs` (variant, classifier, tests,
  doc) and `crates/zsign/src/bundle/code_resources.rs` (gate, tests, doc).
- `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --
  -D warnings`, crate tests, and `hk check --all` all pass.
