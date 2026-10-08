# Fail-closed __LINKEDIT + correct realloc vmsize delta — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development with dispatching-parallel-agents. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Make `embed_signature_single` fail closed on missing `__LINKEDIT`, and make both realloc variants declare a vmsize that covers the new filesize (correct delta base + fail-closed disagreement guard).

**Architecture:** All changes in `crates/zsign-core/src/macho/writer.rs`. One `else` arm reuses the siblings' exact error; the two realloc sites rebase `size_increase` from `required - data.len()` to `required - code_length` and gain a `new_vmsize >= new_filesize` guard after `new_filesize` is computed, before `write_linkedit_sizes`.

**Tech Stack:** Rust 2021, inline `#[cfg(test)]` tests, fixtures from `crates/zsign-core/src/macho/fixtures.rs`.

**Spec:** `docs/superpowers/specs/2026-10-08-linkedit-failclosed-vmsize-design.md`

## Global Constraints

- Zero-warning gate: `cargo fmt --all -- --check` + `cargo clippy --workspace --all-targets -- -D warnings`.
- Tests: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test --workspace` at final gate; scoped `cargo test -p zsign-core <filter>` during flight.
- No ticket IDs in code, comments, docs, or commit messages.
- Edits ONLY in `crates/zsign-core/src/macho/writer.rs` (tests in its inline test mod).
- Preserve the wave-1 checked chains (`checked_sub` for new_filesize, `try_from/checked_add/align_to_checked` vmsize chain) — rebase the delta, do not restructure the chains.
- Error style: reused sibling message is a literal `"No __LINKEDIT segment found".into()`; the new guard uses `Error::MachO(format!(...))` naming both values.
- Existing tests must stay green — never weaken or delete a test.

## Review Focus

- The else-arm message must be byte-identical to the five siblings' `"No __LINKEDIT segment found"`.
- Delta rebase: `size_increase = required - code_length` (NOT `required - data.len()`) at BOTH sites; the metadata twin must also persist corrected values (it already writes `new_vmsize`/`new_filesize` into `updated_metadata`).
- The new vmsize guard must run AFTER `new_filesize` is computed and BEFORE `write_linkedit_sizes`, at BOTH sites.
- Do not touch the early-return ordering (`required <= data.len()` / `code_length > data.len()` guards) that makes the plain `-` subtraction safe.
- Hostile-vmsize `Err` tests (writer.rs:3101/:3119/:3142) and huge-passthrough test (:3161) must remain green — the fix must not add/remove overflow behavior.

---

### Task 1: Fail-closed missing __LINKEDIT (TDD)

**Files:**
- Modify: `crates/zsign-core/src/macho/writer.rs` — `embed_signature_single` terminal `if let ... linkedit_cmd` (~:656-666); tests appended at end of inline test mod.

**Interfaces:**
- Produces: `embed_signature` returns `Err("No __LINKEDIT segment found")` when `linkedit_cmd` is None.

- [ ] **Step 1: Write failing test**
  `test_embed_signature_rejects_missing_linkedit`: build `fixtures::make_minimal_macho_32_mixed_linkedit()`, sign-obtain a signature (mirror how sibling embed tests obtain `signature_bytes` / the existing embed test setup), call `embed_signature(&data, &signature)`; `expect_err` + `contains("No __LINKEDIT segment found")`.
- [ ] **Step 2: Run, expect failure**
  `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-core rejects_missing_linkedit` → FAIL (currently returns Ok; print the Ok-vs-Err panic value).
- [ ] **Step 3: Implement**
  Add `else { return Err(Error::MachO("No __LINKEDIT segment found".into())); }` to the terminal `if let Some((offset, seg_fileoff, _seg_vmsize, _seg_filesize)) = linkedit_cmd` arm in `embed_signature_single`. No other change in the fn.
- [ ] **Step 4: Run tests**
  `TMPDIR=$PWD/target/tmp cargo test -p zsign-core writer` → green (incl. the new test).

### Task 2: Realloc delta rebase + vmsize guard (TDD)

**Files:**
- Modify: `crates/zsign-core/src/macho/writer.rs` — `realloc_code_sign_space_single` (~:204-225) and `realloc_code_sign_space_with_metadata` (~:1377-1402); tests appended at end of inline test mod.

**Interfaces:**
- Consumes: Task 1 (independent — different fns, can be verified separately).
- Produces: both realloc fns guarantee `new_vmsize >= new_filesize` or return `Err`.

- [ ] **Step 1: Write failing tests**
  - `test_realloc_vmsize_covers_linkedit_filesize`: `realloc_code_sign_space(&big_signed_buffer(), 0x3000)`; parse output, read `__LINKEDIT` vmsize (`lc+32` LE for 64-bit) and filesize (`lc+48`); assert `vmsize >= filesize` and `vmsize == 0x7000` (the corrected-delta value from the spec's concrete example). Mirror variant for `realloc_code_sign_space_with_metadata` if the existing metadata fixture setup makes it cheap; otherwise cover the metadata site by reusing the same readback helper on the metadata call path used by existing metadata tests.
  - `test_realloc_rejects_vmsize_below_filesize`: construct input where `old_vmsize + fileoff < code_length` (e.g. `__LINKEDIT` fileoff `0x1000`, old vmsize `0x1000`, `code_length = 0x5000` per spec §Testing.3); `expect_err` + `contains` on the guard message naming vmsize/filesize.
- [ ] **Step 2: Run, expect failure**
  `TMPDIR=$PWD/target/tmp cargo test -p zsign-core realloc_vmsize` and `... realloc_rejects_vmsize` → first FAILS with `vmsize (0x2000) < filesize (0x7000)`; second FAILS with Ok-returned panic value.
- [ ] **Step 3: Rebase the delta at both sites**
  Replace `let size_increase = required - data.len();` with `let size_increase = required - code_length;` in BOTH fns (writer.rs:206 and :1379). Touch nothing else in the chains.
- [ ] **Step 4: Add the guard at both sites**
  After `let new_filesize = required.checked_sub(...)` and BEFORE `write_linkedit_sizes(...)`:
  `if new_vmsize < new_filesize { return Err(Error::MachO(format!("__LINKEDIT vmsize {new_vmsize:#x} does not cover filesize {new_filesize:#x}"))); }`
  (Site B: place before `write_linkedit_sizes` and before persisting into `updated_metadata`.)
- [ ] **Step 5: Run scoped tests**
  `TMPDIR=$PWD/target/tmp cargo test -p zsign-core writer` → ALL green, especially :2143/:2169/:2339 (case-a realloc), :3101/:3119/:3142 (hostile Err), :3161 (huge passthrough), plus both new tests.

### Task 3: Full gate + commits (controller-owned)

- [ ] `cargo fmt --all -- --check` && `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test --workspace`
- [ ] Controller commits (no ticket IDs): Task 1 → `fix(macho): fail closed when linkedit segment is missing`; Task 2 → `fix(macho): declare linkedit vmsize from actual realloc growth`.
