# Atomic in-place Mach-O write — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development with dispatching-parallel-agents for independent tasks to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `write_signed_macho_in_place` replace the binary through a same-directory temp file + rename so a mid-write failure can never leave a truncated Mach-O.

**Architecture:** All changes live in `crates/zsign/src/macho/mod.rs`. The read + `embed_signature` steps stay exactly as they are (error precedence unchanged); the final `std::fs::write` on the same path is replaced by: canonicalize → capture permissions → `NamedTempFile::new_in(parent)` → `write_all` → `sync_all` → `set_permissions` → `persist` (rename), then a best-effort directory fsync. The file's first-ever `#[cfg(test)] mod tests` holds three tests.

**Tech Stack:** Rust, edition 2021; `tempfile` (already a normal dependency of this crate, `crates/zsign/Cargo.toml:27`); inline `#[cfg(test)]` tests; `zsign_core::macho::fixtures` (available to tests via the `test-fixtures` dev-dependency).

**Spec:** `docs/superpowers/specs/2026-10-08-make-macho-in-place-write-atomic-design.md`

## Global Constraints

- Touch ONLY `crates/zsign/src/macho/mod.rs` (function, doc comment, new test module). Do NOT touch `builder.rs`, `store.rs`, `zsign-core`, `zsign-cli`, `zsign-wasm`, `writer.rs`.
- No ticket IDs in code, comments, docs, or commit messages; the slug names the change (`make-macho-in-place-write-atomic`).
- Zero-warning gate: `cargo fmt --all -- --check` + `cargo clippy --workspace --all-targets -- -D warnings`.
- Tests: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-rs` (scoped runs during flight; `/tmp` is a small tmpfs — never use it).
- Commit on this branch; NEVER push.
- Error style: io failures flow through `?` into `Error::Io` (`error.rs:35`); `PersistError` is unwrapped with `.map_err(|pe| pe.error)?` so its owned `NamedTempFile` drops and removes the temp file.
- No new dependencies; no shared helper for the sibling sink lane.
- Test module conventions: `assert!(matches!(...))` footers print the actual value (`res.as_ref().err()`); unix-only tests gated `#[cfg(unix)]` (repo idiom); conditional-skip guard if DAC enforcement is absent follows `ipa/mod.rs:3142-3147`.

## Review Focus

- **Relative-path parent trap:** `binary_path.parent()` is `Some("")` for a bare filename; the implementation must derive the temp directory from the *canonicalized* path, never the caller's raw path. No test pins cwd-relative calls (cwd mutation is process-global and races parallel tests) — code-read check in review.
- **Mode set before rename, not after:** if `set_permissions` runs after `persist`, there is a visible window where the replaced file has tempfile's 0600 default. Pinned by `in_place_write_matches_two_path_output_and_preserves_mode`; order itself is a code-read check.
- **`sync_all` failure must propagate while the original is intact** (ENOSPC at flush time). Cannot be fault-injected portably — code-read check; the mid-write test exercises the adjacent `write_all` failure.
- **Directory fsync must not fail a completed replace** (best-effort, `let _ =`). Code-read check; a mistaken `?` here would turn success into `Err`.
- **Subprocess test false-green:** if the child never reaches the write, the original stays intact and the test would pass vacuously. Pinned by the marker assertion (`stdout` must contain `in-place-write-attempted`) in `mid_write_failure_leaves_original_intact`.

---

### Task 1: Tests (failing regression first)

**Files:**
- Modify: `crates/zsign/src/macho/mod.rs` — append `#[cfg(test)] mod tests { ... }` at end of file (the file has no test module today; this becomes its first).

**Interfaces:**
- Consumes: `write_signed_macho`, `write_signed_macho_in_place` (`super::`), `zsign_core::macho::fixtures::make_minimal_macho`, `tempfile::tempdir`.
- Produces: three test fns (names fixed for Task 2's run commands) + private helper `signature_bytes() -> Vec<u8>`.

- [ ] **Step 1: Add the test module with helper + three tests**

Append at end of `crates/zsign/src/macho/mod.rs`:

```rust
#[cfg(test)]
mod tests {
    use std::fs;
    use std::process::Command;

    use zsign_core::macho::fixtures;

    use super::{sign_macho_adhoc, write_signed_macho, write_signed_macho_in_place, MachOFile};

    /// A real signature payload: sign a thin fixture ad-hoc and extract its
    /// LC_CODE_SIGNATURE blob. Mirrors `signature_bytes` in zsign-core's
    /// writer tests (crates/zsign-core/src/macho/writer.rs:2524-2535).
    fn signature_bytes() -> Vec<u8> {
        let macho = MachOFile::parse(fixtures::make_minimal_macho()).expect("fixture parses");
        let signed = sign_macho_adhoc(&macho, "com.zsign.blobsrc", None, None, None, false)
            .expect("adhoc sign of minimal fixture");
        let m = MachOFile::parse(signed.clone()).expect("signed parses");
        let sl = &m.slices()[0];
        let sig = sl.code_sig_offset.expect("signature present") as usize;
        let len = sl.code_sig_size.expect("signature size present") as usize;
        signed[sig..sig + len].to_vec()
    }
```

Then the three tests, in this order:

1. **`mid_write_failure_leaves_original_intact`** — `#[test]` + `#[cfg(unix)]`. Constants: env var `ZSIGN_IN_PLACE_WRITE_TARGET`, marker string `in-place-write-attempted`.
   - **Child branch first** (entered when `ZSIGN_IN_PLACE_WRITE_TARGET` is set, i.e. this invocation is the re-exec'd child, running under `ulimit -f 1`): `println!("{marker}")`, then `let res = write_signed_macho_in_place(env_target, &signature_bytes());` then `assert!(res.is_err(), "write must fail under a file-size limit, got {res:?}")`. Return. The child creates **no files of its own** — an 8 KiB fixture write would itself hit the limit.
   - **Parent branch:** `tempdir()`; write `fixtures::make_minimal_macho()` (0x2000 bytes) to `td/app.bin`; keep a copy of the original bytes. Re-exec self:
     ```rust
     let exe = std::env::current_exe().unwrap();
     let out = Command::new("sh")
         .arg("-c")
         .arg(r#"ulimit -f 1; exec "$0" "$@""#)
         .arg(&exe)
         .arg("mid_write_failure_leaves_original_intact") // substring filter, runs only this test
         .arg("--nocapture")                              // marker must reach stdout
         .env(CHILD_TARGET_ENV, &target)
         .output()
         .unwrap();
     ```
   - Parent asserts, in order: (a) `String::from_utf8_lossy(&out.stdout).contains(MARKER)` — child reached the write, else fail printing captured stdout+stderr; (b) `fs::read(&target) == original` — "mid-write failure must leave the original bytes intact".
   - Do **not** assert on child exit status: post-fix the child is expected to die by SIGXFSZ during the temp write as often as to return `Err`. The byte comparison is the discriminator (pre-fix `std::fs::write` truncates at open, so the file is 0/partial bytes).

2. **`in_place_write_matches_two_path_output_and_preserves_mode`** — `#[test]` + `#[cfg(unix)]` (uses `PermissionsExt`). Write the fixture twice into one tempdir: path A goes through `write_signed_macho(in, out, &sig)`, path B through `write_signed_macho_in_place` after `fs::set_permissions(path_b, Permissions::from_mode(0o755))`. Assert `fs::read(path_b) == fs::read(out)` (byte-identical to the two-path write) and the surviving mode `& 0o777 == 0o755`. **Invariant pin:** passes before and after; it is what breaks a naive temp+rename that forgets metadata.

3. **`in_place_write_through_symlink_replaces_target_not_link`** — `#[test]` + `#[cfg(unix)]` (uses `std::os::unix::fs::symlink`). Fixture at `real.bin`, `symlink(real, link)`, call the function **on `link`**. Assert `fs::symlink_metadata(&link).file_type().is_symlink()` (link itself not replaced) and `fs::read(&link) != original` with equality to the two-path output of the same input+signature (target carries the signed image). **Invariant pin:** passes before; fails a fix that renames over the un-canonicalized symlink path.

- [ ] **Step 2: Run the regression test, expect RED**

Run: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-rs mid_write_failure_leaves_original_intact -- --nocapture`
Expected: FAIL — the parent's byte comparison reports the original was destroyed (current code truncates `app.bin` before the failing write). If the marker assertion fails instead, the injection wrapper is broken: debug the `sh -c`/`ulimit` invocation before proceeding.

- [ ] **Step 3: Run the two pins, expect GREEN**

Run: `TMPDIR=$PWD/target/tmp cargo test -p zsign-rs in_place_write -- --nocapture`
Expected: the mode and symlink pins pass against the current implementation (they constrain the coming change, they are not red-first).

### Task 2: Implement the atomic replace (TDD green)

**Files:**
- Modify: `crates/zsign/src/macho/mod.rs` — `write_signed_macho_in_place` (:49-57), its doc comment (:48), and add `use std::io::Write;` to the file's imports (before the `pub use` block).

**Interfaces:**
- Consumes: Task 1's tests (names above), `tempfile::NamedTempFile`, `Error::Io` via `?`.
- Produces: unchanged public signature `write_signed_macho_in_place(impl AsRef<Path>, &[u8]) -> crate::Result<()>`.

- [ ] **Step 1: Replace the final `std::fs::write` with the spec's sequence**

Body after the unchanged `read` + `embed_signature` lines (spec §Design, sequence 1-8; order is load-bearing — permissions before `persist`, directory fsync last and best-effort):

```rust
let target = std::fs::canonicalize(binary_path.as_ref())?;
let perms = std::fs::metadata(&target)?.permissions();
let parent = target
    .parent()
    .ok_or_else(|| std::io::Error::other(format!("{} has no parent directory", target.display())))?;
let mut temp = tempfile::NamedTempFile::new_in(parent)?;
temp.as_file_mut().write_all(&output)?;
temp.as_file().sync_all()?;
std::fs::set_permissions(temp.path(), perms)?;
temp.persist(&target).map_err(|pe| pe.error)?;
let _ = std::fs::File::open(parent).and_then(|dir| dir.sync_all());
```

Extend the doc comment (keep the `/// Write signed Mach-O in place (native-only).` first line) with one short paragraph stating: the image is written to a temp file in the same directory, synced, given the original file's permissions, then renamed over the path; a failure before the rename leaves the original untouched; readers see old-or-new.

- [ ] **Step 2: Run all three tests, expect GREEN**

Run: `TMPDIR=$PWD/target/tmp cargo test -p zsign-rs in_place_write` then `TMPDIR=$PWD/target/tmp cargo test -p zsign-rs mid_write_failure`
Expected: all three pass — regression red→green, pins stay green.

- [ ] **Step 3: Run the scoped gates**

Run: `cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings` then `TMPDIR=$PWD/target/tmp cargo test -p zsign-rs`
Expected: clean format, zero clippy warnings, full zsign-rs suite green.

### Task 3: Full gates + commits (controller-owned)

- [ ] `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test --workspace`
- [ ] `cargo fmt --all -- --check` and `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] `hk check --all` once (the land gate) — paste verbatim output into the final report.
- [ ] Commits (never push): `docs: design atomic in-place macho write` (spec + plan), then `fix(macho): write in-place macho through a temp file` (code + tests + doc comment). No ticket IDs anywhere.
