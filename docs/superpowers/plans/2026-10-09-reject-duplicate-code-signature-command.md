# Reject Duplicate LC_CODE_SIGNATURE Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development (recommended) with dispatching-parallel-agents for independent tasks to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reject a Mach-O whose load-command list contains two LC_CODE_SIGNATURE commands with a typed parse error, instead of silently collapsing to the last one.

**Architecture:** A `code_sig_offset.is_some()` guard at the head of the existing `CommandVariant::CodeSignature` arm in `MachOFile::parse_single` returns `Err(Error::MachO("multiple LC_CODE_SIGNATURE load commands"))` before any assignment. `parse_single` is the single funnel for the thin arm (parser.rs:192) and every FAT slice (parser.rs:218), and every sign/verify/CLI/wasm/ipa entry parses through it, so one guard covers all paths. No signatures, types, or public APIs change.

**Tech Stack:** Rust 2021 workspace, existing `crate::Error` (`thiserror`), `crate::Result` alias, in-repo byte fixtures (`crate::macho::fixtures`).

**Spec:** `docs/superpowers/specs/2026-10-09-reject-duplicate-code-signature-command-design.md` — the plan argues from the spec; executors read both.

## Global Constraints

- No ticket IDs anywhere in the repo: code, comments, commit subjects/bodies, docs, messages. The slug naming this change is `reject-duplicate-code-signature-command`.
- Keep `TMPDIR` inside the worktree: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test …` (`/tmp` is a small tmpfs).
- Error channel: reuse `Error::MachO(String)` (`crates/zsign-core/src/error.rs:7-8`); payload verbatim `multiple LC_CODE_SIGNATURE load commands`; no new variants, no new dependencies.
- Minimal diff confined to: the `CommandVariant::CodeSignature` arm in `crates/zsign-core/src/macho/parser.rs` (currently :279-283) and new tests in that file's `#[cfg(test)] mod tests` (starts :509). Nothing else — no changes to `fixtures.rs`, `verify.rs`, `signer.rs`, `writer.rs`, `error.rs`, the facade, CLI, wasm, or fuzz targets.
- Do NOT touch the other last-wins arms in the same loop (`text_segment_*` :286-288/:303-305, `meta_linkedit_cmd` :293-296/:307-312, `record_encryption` :496-508) — out of scope per the spec's Decision record; sibling lanes own `verify.rs`, `signer.rs`, and `bundle/code_resources.rs`.
- SKILL (required): test-driven-development within Task 1 — failing tests first, run them, then implement. SKILL (required): subagent-driven-development — Tester subagent writes the tests, implementer subagent greens them, orchestrator runs gates and commits.
- Commits: conventional, imperative mood, lowercase, no trailing period, no ticket ID.
- Scoped gates while working; the full gate list runs in Task 2.

## Review Focus

1. **A second LC_CODE_SIGNATURE must be `Err` with the exact payload** — `multiple LC_CODE_SIGNATURE`, not a downstream bounds or goblin error. Pinned by `test_duplicate_code_signature_command_is_rejected`'s `m.contains("multiple LC_CODE_SIGNATURE")` assertion.
2. **Verification must never pass a duplicate off as one** — `verify_macho` returns `Err`, never `Ok(report)`. Pinned by `test_duplicate_code_signature_command_rejects_verify`.
3. **A duplicate inside a FAT slice hits the same guard** (the FAT arm funnels through `parse_single`). Pinned by `test_duplicate_code_signature_rejects_fat_slice`.
4. **The first occurrence must stay accepted** — a single LC_CODE_SIGNATURE still parses/signs/verifies (no first-occurrence regression). Pinned by the unchanged existing single-signature tests (e.g. `writer.rs:2324`'s `make_signed_minimal_macho(0x800)` round-trip, verify.rs's signed round-trips) staying green in Task 1's gate run.
5. **The error discriminant stays `Error::MachO(String)`** so wasm keeps its stable `ZSIGN_INVALID_MACHO` code and the CLI keeps printing the message verbatim. Pinned by all three new tests asserting the `Err(Error::MachO(m))` shape.

---

### Task 1: Reject duplicate LC_CODE_SIGNATURE in `parse_single` (failing tests first)

**Files:**
- Modify: `crates/zsign-core/src/macho/parser.rs` — the `CommandVariant::CodeSignature` arm (currently :279-283); `#[cfg(test)] mod tests` (starts :509) gains one fixture helper and three tests appended after the existing tests.

**Interfaces:**
- Consumes: `crate::Error::MachO(String)` and `crate::Result` (already in scope at the top of `parser.rs`; `Error` and `MachOFile` reach the tests module via `use super::*` at parser.rs:511); fixture `crate::macho::fixtures::make_signed_minimal_macho(slot_len: u32) -> Vec<u8>` (fixtures.rs:416, appends one LC_CODE_SIGNATURE at `dataoff` 0x2000) and `crate::macho::fixtures::make_fat_macho(slices: &[Vec<u8>], aligns: &[u32]) -> Vec<u8>` (fixtures.rs:663); verify entry `crate::macho::verify_macho(data: &[u8], inputs: &SignatureInputs) -> Result<MachOVerifyReport>` with `crate::codesign::verify::SignatureInputs::none()`.
- Produces: no new API. Behaviour contract: `MachOFile::parse` (and everything downstream) returns `Err(Error::MachO("multiple LC_CODE_SIGNATURE load commands"))` when any slice's load-command list contains two LC_CODE_SIGNATURE commands.

- [ ] **Step 1: Tester writes the failing tests**

Append to `crates/zsign-core/src/macho/parser.rs` inside `#[cfg(test)] mod tests`, after the existing tests and before the closing brace:

```rust
    /// Thin arm64 image carrying TWO conflicting LC_CODE_SIGNATURE commands:
    /// the first points at (0x2000, 0x800), the second at (0x2400, 0x400) —
    /// both in bounds, so parse succeeds today with last-wins collapse and
    /// the conflicting values silently decide the signature location.
    fn make_duplicate_code_signature_macho() -> Vec<u8> {
        let mut b = crate::macho::fixtures::make_signed_minimal_macho(0x800);
        let ncmds = u32::from_le_bytes(b[16..20].try_into().unwrap());
        let sizeofcmds = u32::from_le_bytes(b[20..24].try_into().unwrap());
        b[16..20].copy_from_slice(&(ncmds + 1).to_le_bytes());
        b[20..24].copy_from_slice(&(sizeofcmds + 16).to_le_bytes());
        let lc = 32 + sizeofcmds as usize;
        b[lc..lc + 4].copy_from_slice(&0x1du32.to_le_bytes()); // LC_CODE_SIGNATURE
        b[lc + 4..lc + 8].copy_from_slice(&16u32.to_le_bytes()); // cmdsize
        b[lc + 8..lc + 12].copy_from_slice(&0x2400u32.to_le_bytes()); // dataoff
        b[lc + 12..lc + 16].copy_from_slice(&0x400u32.to_le_bytes()); // datasize
        b
    }

    #[test]
    fn test_duplicate_code_signature_command_is_rejected() {
        let res = MachOFile::parse(make_duplicate_code_signature_macho());
        assert!(
            matches!(&res, Err(Error::MachO(m)) if m.contains("multiple LC_CODE_SIGNATURE")),
            "two LC_CODE_SIGNATURE commands must be rejected, got {:?}",
            res.as_ref().err()
        );
    }

    #[test]
    fn test_duplicate_code_signature_command_rejects_verify() {
        let res = crate::macho::verify_macho(
            &make_duplicate_code_signature_macho(),
            &crate::codesign::verify::SignatureInputs::none(),
        );
        assert!(
            matches!(&res, Err(Error::MachO(m)) if m.contains("multiple LC_CODE_SIGNATURE")),
            "verification must not pass a duplicate off as one, got {:?}",
            res.as_ref().err()
        );
    }

    #[test]
    fn test_duplicate_code_signature_rejects_fat_slice() {
        let fat =
            crate::macho::fixtures::make_fat_macho(&[make_duplicate_code_signature_macho()], &[12]);
        let res = MachOFile::parse(fat);
        assert!(
            matches!(&res, Err(Error::MachO(m)) if m.contains("multiple LC_CODE_SIGNATURE")),
            "a duplicate inside a FAT slice must be rejected, got {:?}",
            res.as_ref().err()
        );
    }
```

Notes for the Tester: the helper is a test-local function (the shared `fixtures.rs` stays untouched); byte surgery mirrors `make_signed_minimal_macho_at` (fixtures.rs:422-441) — after it runs, `ncmds == 4` and `sizeofcmds == 264`, so the appended command lands at 296..312 inside the zero-filled first page. The `matches!` + `got {:?}` footer via `res.as_ref().err()` is the module's dominant assertion style.

- [ ] **Step 2: Run the tests, confirm the expected failure**

Run: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-core parser::tests::test_duplicate`
Expected: all three tests FAIL. Today's loop is last-wins, so `MachOFile::parse` returns `Ok` (the second command's in-bounds values win) and `verify_macho` likewise returns `Ok(report)`; each `matches!(… Err …)` assertion is false and the footer prints the actual `Ok(…)` payload. Any other failure (e.g. a fixture-construction compile error or a goblin parse error) is NOT this red — fix the fixture so the failure is the assertion. Record the verbatim output.

- [ ] **Step 3: Implement the duplicate guard in the CodeSignature arm**

Edit `crates/zsign-core/src/macho/parser.rs` — replace the arm at :279-283 with:

```rust
                CommandVariant::CodeSignature(cs) => {
                    if code_sig_offset.is_some() {
                        return Err(Error::MachO(
                            "multiple LC_CODE_SIGNATURE load commands".into(),
                        ));
                    }
                    code_sig_offset = Some(cs.dataoff);
                    code_sig_size = Some(cs.datasize);
                    meta_code_sig_cmd = Some((lc.offset, cs.dataoff, cs.datasize));
                }
```

The guard returns BEFORE any assignment; `code_sig_offset` is written only by this arm and starts `None` (parser.rs:247), so it is an exact "seen before" sentinel. `Error` is already in scope in `parse_single` (the `Mach::Fat` arm builds `Error::MachO("Empty FAT binary")` the same way). No other line of the loop changes; the comment above the guard (if added) must describe behaviour, not restate the code — the spec's Decision record carries the rationale, so no comment is required.

- [ ] **Step 4: Run the tests, verify they pass**

Run: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-core parser::tests::test_duplicate`
Expected: 3 passed.

- [ ] **Step 5: Run the scoped gates**

Run: `cargo fmt --all && cargo fmt --all -- --check && TMPDIR=$PWD/target/tmp cargo test -p zsign-core && TMPDIR=$PWD/target/tmp cargo test -p zsign-rs && cargo clippy --workspace --all-targets -- -D warnings`
Expected: fmt clean (run `cargo fmt` first so the new code is formatted), every `zsign-core` and `zsign-rs` test green (the three new tests plus all pre-existing ones — a first-occurrence regression shows up here as a failure in an existing signed-fixture test), zero clippy warnings. Paste verbatim failures if any.

- [ ] **Step 6: Commit**

`git add crates/zsign-core/src/macho/parser.rs` (only — the docs were committed earlier), then:
`git commit -m "fix(macho): reject duplicate code signature load command"`
(imperative, lowercase, no ticket ID, no trailing period.)

---

### Task 2: Full gate run (verification only, no code changes expected)

**Files:** none — if a gate fails, fix within Task 1's file list as a new conventional commit.

- [ ] **Step 1: Run the land gate**

Run: `cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings && mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test --workspace && hk check --all`
Expected: zero warnings, all workspace tests pass, `hk check --all` exits 0. Paste its verbatim output into the final report. If `hk check --all` is unavailable in the sandbox, attempt it once and record the outcome honestly.

- [ ] **Step 2: Confirm the repo is clean and committed**

Run: `git status --short && git log --oneline -5`
Expected: clean tree; design-doc commit, plan-doc commit, and the Task 1 fix commit present; no pushes performed.
