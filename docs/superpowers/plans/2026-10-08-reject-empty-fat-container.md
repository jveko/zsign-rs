# Reject Empty FAT Container at Parse Time — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development (recommended) with dispatching-parallel-agents for independent tasks to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `MachOFile::parse` reject a FAT container whose header declares zero architectures, so no consumer can observe parse/verify/sign success for a magic-only FAT.

**Architecture:** One floor check in the `Mach::Fat` arm of `MachOFile::parse` (the single entry point every consumer shares), returning the crate's existing `Error::MachO("Empty FAT binary")` payload. Tests land first in the parser and core verify modules.

**Tech Stack:** Rust 2021, workspace crate `zsign-core`, goblin for Mach-O parsing, `cargo test` for verification.

**Spec:** `docs/superpowers/specs/2026-10-08-reject-empty-fat-container-design.md`

## Global Constraints

- No ticket IDs anywhere: code, comments, docs, commit subjects, commit bodies.
- Commit on the current branch; NEVER push.
- Keep `TMPDIR` inside the repo: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test …` (`/tmp` is a small tmpfs).
- Only `crates/zsign-core/src/macho/parser.rs` and its inline test module plus `crates/zsign-core/src/macho/verify.rs` tests may change. Writer guards and the signer's own empty-FAT guard stay untouched (defence in depth; see spec "Decision record").
- Error payload must be exactly `"Empty FAT binary"` (matches `signer.rs:431-433`); the variant must be the existing `Error::MachO(String)` (`crates/zsign-core/src/error.rs:7-9`) — no new enum variant.
- Zero-warning gate before finishing: `cargo fmt --all -- --check` and `cargo clippy --workspace --all-targets -- -D warnings`.

## Review Focus

- A magic-only FAT (8 bytes: big-endian `0xcafebabe` + `nfat_arch = 0`) must fail `MachOFile::parse` with `Empty FAT binary` — most likely first: a future refactor drops the post-loop check and the container parses again.
- `verify_macho` on those bytes must return `Err`, never `Ok` with an empty report — a consumer reading `error_count() == 0` would treat it as clean.
- Signing must be unreachable for such bytes: `MachOFile` fields are private (`parser.rs:103-107`), so `parse` is the only constructor; if that invariant is ever broken, the signer's guard is the backstop (not tested here by design).
- Containers that DO carry slices (1- and 2-slice FAT fixtures) must keep parsing and signing green — the floor must not over-reject.
- Big-endian `FAT_CIGAM` handling must be unchanged — this change adds no magic handling, only a count floor.

---

### Task 1: Failing tests for zero-architecture FAT rejection

**Files:**
- Modify: `crates/zsign-core/src/macho/parser.rs` (inline `#[cfg(test)] mod tests`, starts at line 474)
- Modify: `crates/zsign-core/src/macho/verify.rs` (inline `#[cfg(test)] mod tests`, starts at line 572)

**Interfaces:**
- Consumes: `MachOFile::parse(data: Vec<u8>) -> Result<MachOFile>` (parser.rs:185); `verify_macho(data: &[u8], inputs: &SignatureInputs<'_>) -> Result<MachOVerifyReport>` (verify.rs:99); `crate::Error::MachO(String)` renders as `Invalid Mach-O: {0}`.
- Produces: two new tests, `parse_rejects_zero_arch_fat_container` and `verify_rejects_zero_arch_fat_container`, both failing until Task 2.

- [ ] **Step 1: Write the failing parser test**

Append to `mod tests` in `crates/zsign-core/src/macho/parser.rs`:

```rust
#[test]
fn parse_rejects_zero_arch_fat_container() {
    // Magic-only universal container: fat_header with nfat_arch = 0.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&0xcafebabeu32.to_be_bytes());
    bytes.extend_from_slice(&0u32.to_be_bytes());
    let res = MachOFile::parse(bytes);
    assert!(
        matches!(&res, Err(Error::MachO(m)) if m.contains("Empty FAT binary")),
        "zero-arch FAT must be rejected at parse, got {:?}",
        res.as_ref().err()
    );
}
```

- [ ] **Step 2: Write the failing verify test**

Append to `mod tests` in `crates/zsign-core/src/macho/verify.rs` (the module already imports `SignatureInputs` and `verify_macho` via `use super::*`):

```rust
#[test]
fn verify_rejects_zero_arch_fat_container() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&0xcafebabeu32.to_be_bytes());
    bytes.extend_from_slice(&0u32.to_be_bytes());
    let res = verify_macho(&bytes, &SignatureInputs::none());
    assert!(
        matches!(&res, Err(crate::Error::MachO(m)) if m.contains("Empty FAT binary")),
        "zero-arch FAT must not verify as success, got {:?}",
        res.as_ref().err()
    );
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-core zero_arch_fat`
Expected: compile OK; `parse_rejects_zero_arch_fat_container` FAILS (`parse` currently returns `Ok`), `verify_rejects_zero_arch_fat_container` FAILS (`verify_macho` currently returns `Ok`). Failure footers print the actual outcomes.

- [ ] **Step 4: Commit the failing tests**

Run: `git add crates/zsign-core/src/macho/parser.rs crates/zsign-core/src/macho/verify.rs && git commit -m "test(macho): cover zero-architecture fat containers"`
Expected: commit created on the current branch; no push.

### Task 2: Reject zero-arch FAT at parse time

**Files:**
- Modify: `crates/zsign-core/src/macho/parser.rs` (`Mach::Fat` arm of `parse`, lines 195-224)

**Interfaces:**
- Consumes: `Error::MachO(String)` (error.rs:7-9); the `slices` vector built by the arch loop.
- Produces: `MachOFile::parse` returns `Err(Error::MachO("Empty FAT binary".into()))` for `nfat_arch == 0`; every downstream consumer (verify, wasm, CLI, ipa probe, signer) inherits the error. No signature changes.

- [ ] **Step 1: Add the floor check**

In parser.rs, in the `Mach::Fat(fat) => { … }` arm, immediately after the `for (i, arch) in fat.iter_arches()` loop and before the arm's `(true, slices)` tail expression, insert:

```rust
if slices.is_empty() {
    return Err(Error::MachO("Empty FAT binary".into()));
}
```

Post-loop emptiness is exactly `nfat_arch == 0`: any arch entry that fails its per-arch checks already returns `Err` from inside the loop.

- [ ] **Step 2: Run the new tests to verify they pass**

Run: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-core zero_arch_fat`
Expected: both tests PASS.

- [ ] **Step 3: Run the crate's macho tests to verify no container that carries slices is rejected**

Run: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-core`
Expected: full `zsign-core` suite PASS (one- and two-slice FAT fixtures, sign/verify round-trips, writer guards).

- [ ] **Step 4: Run scoped cross-crate tests**

Run: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-rs && mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-cli`
Expected: PASS — no consumer depends on the old accept-empty behaviour.

- [ ] **Step 5: Commit the fix**

Run: `git add crates/zsign-core/src/macho/parser.rs && git commit -m "fix(macho): reject fat containers with zero architectures"`
Expected: commit created on the current branch; no push.

### Task 3: Final gates

**Files:** none (verification only).

- [ ] **Step 1: Formatting check**

Run: `cargo fmt --all -- --check`
Expected: no output, exit 0.

- [ ] **Step 2: Clippy zero-warning gate**

Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: no warnings, exit 0.

- [ ] **Step 3: Land gate**

Run: `hk check --all`
Expected: all checks pass; paste the full output into the final report.

- [ ] **Step 4: Confirm no push**

Run: `git log --oneline -3 && git status --short --branch`
Expected: both commits present, working tree clean, no push performed.

---

## Self-Review

- Spec coverage: parse-time floor (Task 2), verify no-Ok (Task 1 Step 2), sign unreachable via private fields (Review Focus), writer/signer guards untouched (Global Constraints), no ceiling (Global Constraints).
- Step scan: every step is one test, one insertion, one command, or one commit.
- Type consistency: `Error::MachO(String)` and `"Empty FAT binary"` identical across spec, both tests, and Task 2.
- Proportion: plan is one insertion and two tests — no transcript bodies.
