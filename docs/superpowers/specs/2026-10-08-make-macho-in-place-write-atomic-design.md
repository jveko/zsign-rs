# Atomic in-place Mach-O write — Design

**Date:** 2026-10-08
**Slug:** make-macho-in-place-write-atomic
**Scope:** `write_signed_macho_in_place` only (`crates/zsign/src/macho/mod.rs:49-57`).

## Problem

`write_signed_macho_in_place` reads the whole file, builds the new image in
memory, then calls `std::fs::write` on the **same path**
(`crates/zsign/src/macho/mod.rs:53,55`). `std::fs::write` is documented as
"`File::create` and `write_all`", and `File::create` "will truncate it if it
does" exist — the original bytes are destroyed at open time, before any new
byte lands. Any failure after that point (ENOSPC, EIO, RLIMIT_FSIZE, SIGKILL)
leaves a zero-length or partial Mach-O with no recovery path, and a concurrent
reader can observe the empty window. There is no temp-file+rename, no fsync,
and no read lock.

## Verified context (research, 2026-10-08)

- **Callers:** zero in-repo callers of either write function; the function is
  public API of the published `zsign-rs` crate only (defs/docs at
  `macho/mod.rs:15,37,49`; stale doc bullet `zsign-core/src/macho/writer.rs:11`
  refers to a nonexistent function — pre-existing, untouched). Behavior change
  affects external consumers only; nothing in-repo to migrate.
- **No existing atomic-replace facility** anywhere in the workspace: every
  production write site uses plain `File::create`/`std::fs::write`. The only
  tempfile use in production is scratch `TempDir`s (`verify.rs:393`,
  `ipa/mod.rs:667`).
- **`tempfile = "3.10"` is already a normal runtime dependency** of `zsign-rs`
  (`crates/zsign/Cargo.toml:27`, resolved 3.27.0 in Cargo.lock:1472). No
  manifest change is needed; no second convention is introduced.
- **Error plumbing:** `Error::Io(#[from] std::io::Error)` at
  `crates/zsign/src/error.rs:35`; `crate::Result` at `lib.rs:66`. All io
  failures surface as `Error::Io` via `?`.
- **No cfg gating** on `pub mod macho` (`lib.rs:40-46`); the "(native-only)"
  markers are doc-only. `tempfile` already compiles for every target this
  crate builds for.
- **Upstream correction:** upstream zsign's Mach-O signing path is an
  in-place `MAP_SHARED` mmap write (`src/macho.cpp:60-65,94-105`), not a
  distinct output path — `-o` applies to IPA/bundle output only
  (`src/zsign.cpp:131`). However upstream *does* use write-sibling +
  `rename()` inside `ReallocCodeSignSpace` (`src/macho.cpp:181-187,252-253`),
  which is direct precedent for the approach chosen here.
- **tempfile semantics** (docs + source, Stebalien/tempfile):
  `NamedTempFile::persist` on unix is `rustix::fs::rename` (overwrite path);
  it atomically replaces an existing target; it must be same-filesystem (so
  the temp file must be created **in the target's directory**); default mode
  is 0600 and persist copies **no** metadata from the original; `PersistError`
  carries both the io error and the recoverable temp file; persist does **no**
  fsync of file or directory.
- **rename(2)/POSIX:** atomic replace; observers see old-or-new, never
  missing/mixed; `EXDEV` across filesystems; provides no serialization
  between concurrent writers (last rename wins).
- **fsync policy source:** fsync(2) — syncing the file is not enough for the
  directory entry; an explicit fsync on the directory is needed. Data must be
  on stable storage *before* the rename or a crash can expose partial blocks.

## Design

Replace the final `std::fs::write` with a same-directory temp-file + rename
sequence. The read and `embed_signature` steps are unchanged, preserving
current error precedence (missing file / invalid Mach-O fail exactly as today,
before any filesystem mutation is attempted).

Sequence after `output` is built:

1. `target = std::fs::canonicalize(binary_path)?` — resolves symlinks so the
   function keeps its read-through/write-through-symlink behavior, and yields
   an absolute path whose parent is a real directory.
2. `perms = std::fs::metadata(&target)?.permissions()` — captured before any
   write (carries the full unix mode; the readonly flag on windows).
3. `temp = tempfile::NamedTempFile::new_in(target.parent())?` — same directory
   as the target, hence same filesystem (rename can never hit EXDEV).
4. `temp.as_file_mut().write_all(&output)?` — all fallible writes happen against
   the temp file; the original is never opened for writing.
5. `temp.as_file().sync_all()?` — data + metadata on stable storage **before**
   the replace; a failure here surfaces as `Error::Io` while the original is
   still fully intact (the dropped temp file cleans itself up).
6. `std::fs::set_permissions(temp.path(), perms)?` — mode restored **before**
   the rename, so the visible file never exists with tempfile's 0600 default.
7. `temp.persist(&target)` — atomic rename; readers see old-or-new. On
   `PersistError`, return `Err(Error::Io(pe.error))` (the temp file is dropped
   and removed; the original is untouched because a failed rename leaves it
   alone per POSIX).
8. Best-effort durability of the directory entry:
   `let _ = std::fs::File::open(parent).and_then(|d| d.sync_all());` —
   ignored on purpose: at this point the content is complete and synced, and
   turning a *completed* replace into an `Err` would misreport success state.

### Error surfaces

| Failure point | Error | State of the original |
|---|---|---|
| `fs::read` / `embed_signature` | as today | untouched |
| `canonicalize` / `metadata` | `Error::Io` | untouched |
| temp create / `write_all` / `sync_all` / `set_permissions` | `Error::Io` | untouched; temp removed on drop |
| `persist` (rename) | `Error::Io` | untouched (POSIX: failed rename affects no file) |
| directory fsync | ignored | replaced image is complete |

### Decisions and rejected alternatives

- **temp-in-same-dir + rename via `tempfile` (chosen).** Atomic for readers,
  durable for data, zero new dependencies, matches upstream's
  `ReallocCodeSignSpace` trick.
- **Rejected: hand-rolled temp file with `OpenOptions::create_new`.**
  Reimplements what the already-present `tempfile` dependency provides
  (random names, drop cleanup) — a second convention for no benefit.
- **Rejected: any truncate-in-place variant** (`ftruncate` + overwrite).
  Still loses data on mid-write failure; does not fix the ticket.
- **Rejected: backup-and-rename-original dance.** Multi-step with crash
  windows where the path is missing or a stale backup lingers.
- **Rejected: file locking.** rename already eliminates the reader's empty
  window; writer-writer serialization has no in-repo caller to justify a lock
  dependency, and rename-based replace deliberately keeps the "last writer
  wins" semantics of today.
- **Rejected: shared helper for this and the sibling in-place sink.** This
  lane must stand alone; infrastructure for the later lane is not pre-built.
- **fsync policy: file `sync_all` propagated, directory fsync best-effort.**
  The file sync is the step that makes crash-time corruption impossible; the
  directory sync only protects rename durability, after the replace already
  succeeded.

### Accepted consequences

- The inode is replaced: hard links to the original now diverge, ownership
  becomes the calling process's uid/gid, and xattrs/ACLs are not carried over
  (mode is preserved). Upstream's rename path has the same properties.
- The containing directory must be writable (previously only the file had to
  be).
- A SIGKILL between temp creation and persist can leave an orphaned temp file
  in the directory; it never affects the original.

## Acceptance criteria

1. A mid-write failure leaves the original bytes intact — regression test
   that is RED against the current implementation and GREEN after.
2. Happy path output is byte-identical to the two-path `write_signed_macho`
   of the same input+signature, and the original file mode survives.
3. Calling through a symlink keeps the symlink and replaces the target.
4. Gates green: `cargo fmt --all -- --check`,
   `cargo clippy --workspace --all-targets -- -D warnings`, affected crate
   tests, `hk check --all`.

## Out of scope

`write_signed_macho` (distinct output path, already safe), `builder.rs`
`sign_macho`, `FsStore::write`, post-write verification/re-parse, store
error kinds, bundle/IPA staging.
