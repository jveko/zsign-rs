# ZSN-66 Dead intra-doc link and dead helper Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development (recommended) with dispatching-parallel-agents for independent tasks to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove one dead intra-doc link from `zsign-core`'s macho writer module doc and delete the unreferenced `embed_signature_into_prepared` helper from the macho signer, leaving zero new warnings.

**Architecture:** Two independent, single-file edits in `crates/zsign-core/src/macho/`. Task 1 turns a dead rustdoc link into plain code formatting; Task 2 deletes a function whose workspace-wide references are provably empty. No behavior changes; the existing test suite plus `cargo doc` are the behavioral gates.

**Tech Stack:** Rust edition 2021, cargo/rustdoc, clippy `-D warnings`.

**Spec:** `docs/superpowers/specs/2026-10-07-zsn-66-dead-doc-and-helper-design.md` (the plan argues from this spec; executors read both).

## Global Constraints

- Files in scope, exhaustive: `crates/zsign-core/src/macho/writer.rs`, `crates/zsign-core/src/macho/signer.rs`. Nothing under `crates/zsign-core/src/codesign/` or `crates/zsign-core/src/crypto/` (other lanes); no files outside the two named.
- Smallest correct change: no drive-by refactors, no second conventions, no "while you're here" warning fixes.
- Deletion must leave **zero new warnings**: `cargo clippy -p zsign-core --all-targets -- -D warnings` green.
- Ticket ID never appears in code comments; allowed in commit subjects.
- No stubs, TODOs, placeholders; no new dependencies; commit subjects: imperative mood, lowercase, conventional commits.
- Test conventions when a test is touched: inline `#[cfg(test)] mod tests` per file; error assertions use `assert!(… , "…, got {:?}", res.as_ref().err())`. (Neither task is expected to add or alter tests — see Review Focus.)

## Review Focus

- Live links at `writer.rs:12–14` and `:30` (`` embed_signature ``, `` embed_signature_fat ``, `` prepare_code_for_signing ``) must remain bracketed links — de-linking them is over-reach.
- `embed_signature_in_place` (`signer.rs:780–801`) and its call sites (`:722`, `:733`) must survive untouched; the deletion boundary is `signer.rs:752–778` only.
- Post-fix `cargo doc -p zsign-core --no-deps` must show **no** `unresolved link` warning (pre-fix it shows exactly one, to `write_signed_macho`).
- Post-deletion `grep -rn embed_signature_into_prepared crates/ fuzz/` must return **zero** hits, and the full `-p zsign-core` suite must stay green — a dangling reference would surface as a compile error here.
- For a pure doc/dead-code removal the "failing test" is an observable check, not a new unit test: Task 1's red state is the `cargo doc` warning; Task 2's red state is the grep proving the dead, unreferenced function exists. Adding unit tests for either would pin implementation details; none are warranted, and the brief allows an existing-suite/`cargo doc` check to serve — stated here explicitly.

---

### Task 1: Fix the dead intra-doc link in writer.rs

**Files:**
- Modify: `crates/zsign-core/src/macho/writer.rs:11` (module doc `//!` block, lines 1–14)
- Test: none created — the observable check is `cargo doc`'s `rustdoc::broken_intra_doc_links` warning (warn-by-default; no rustdoc config exists in this repo).

**Interfaces:**
- Consumes: nothing.
- Produces: writer.rs line 11 references `` `write_signed_macho` `` as plain code (no brackets), all other doc lines byte-identical.

- [ ] **Step 1: Capture the red state (the failing check)**

Run:
```
cargo doc -p zsign-core --no-deps 2>&1 | grep -E "unresolved link|warning" | head -20
```
Expected FAIL state: a line `warning: unresolved link to \`write_signed_macho\`` (rustdoc lint `broken_intra_doc_links`, warn-by-default). Save this output as the before-evidence.

- [ ] **Step 2: Apply the one-line doc fix**

In `crates/zsign-core/src/macho/writer.rs` line 11, replace:

```rust
//! - [`write_signed_macho`] - Write signed binary to a new file
```
with:
```rust
//! - `write_signed_macho` - Write signed binary to a new file
```

Lines 12–14 (the alive links) are not touched. Exact single-token change: `[`write_signed_macho`]` → `` `write_signed_macho` ``.

- [ ] **Step 3: Run the check to verify green**

Run:
```
cargo doc -p zsign-core --no-deps 2>&1 | grep -cE "unresolved link"
```
Expected: `0`. Also confirm the doc run exits 0 and the three alive links still render (`grep -c "unresolved link"` over the full output is the gate).

---

### Task 2: Delete the dead `embed_signature_into_prepared` helper

**Files:**
- Modify: `crates/zsign-core/src/macho/signer.rs:752–778` (`#[allow(dead_code)]` attribute + function)
- Test: none removed — no test anywhere references the function (proven in Step 1); no test created (pure deletion; existing suite is the regression net).

**Interfaces:**
- Consumes: nothing.
- Produces: `signer.rs` no longer contains `embed_signature_into_prepared`; `embed_signature_in_place` (`:780–801`, calls at `:722`/`:733`) untouched; exactly one blank line remains between `SpecialSlotHashes` (closes `:751`) and `fn embed_signature_in_place`.

- [ ] **Step 1: Capture the red state (deadness proof)**

Run:
```
grep -rn "embed_signature_into_prepared" crates/ fuzz/
```
Expected FAIL state: exactly two hits, both in `crates/zsign-core/src/macho/signer.rs` — the `#[allow(dead_code)]` attribute (line 752) and the `fn` definition (line 753). Zero hits elsewhere proves no caller and no test exists. Save the output as before-evidence.

- [ ] **Step 2: Delete lines 752–778**

Remove the entire `#[allow(dead_code)]` attribute line and the whole `fn embed_signature_into_prepared(...) -> Vec<u8> { … }` body (definition `signer.rs:753`, closing brace `:778`), so the file reads `}` (struct close, line 751), blank line, `fn embed_signature_in_place(`. Delete nothing else.

- [ ] **Step 3: Verify deletion is complete and self-consistent**

Run:
```
grep -rn "embed_signature_into_prepared" crates/ fuzz/ | wc -l
```
Expected: `0`.

- [ ] **Step 4: Run the scoped gate (both tasks together)**

Run, capturing verbatim output as evidence:
```
cargo fmt --all -- --check
cargo clippy -p zsign-core --all-targets -- -D warnings
mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-core
cargo doc -p zsign-core --no-deps 2>&1 | grep -cE "unresolved link"
```
Expected: fmt clean (exit 0, no diff); clippy zero warnings (exit 0); tests all pass; the final grep prints `0`. Zero new warnings is the hard acceptance criterion for the deletion.

- [ ] **Step 5: Commit**

Stage exactly the two source files (and only them; the design/plan docs were committed earlier):
```
git add crates/zsign-core/src/macho/writer.rs crates/zsign-core/src/macho/signer.rs
git commit -m "fix(macho): drop dead intra-doc link and unused helper (ZSN-66)"
```
Worktree after commit: `git status --porcelain` empty.

---

## Self-review

- Spec coverage: spec sub-item (a) → Task 1; sub-item (b) → Task 2; risks/zero-warning invariant → Task 2 Step 4; commit/doc rules → Global Constraints + Task 2 Step 5. No gaps.
- Step scan: every step is one action with a checkable result; no step decides nothing, no step hands the implementer a body the signature already determines.
- Type consistency: no new symbols; both tasks are removals — nothing for later tasks to name.
- Review Focus: each line maps to a step (alive links → Task 1 Step 2/3; deletion boundary → Task 2 Step 2; doc warning → Task 1 Steps 1/3; grep + suite → Task 2 Steps 3/4; no-unit-test rationale stated explicitly).
- Proportion: plan is comparable in length to the spec; code blocks are only the exact before/after lines.
