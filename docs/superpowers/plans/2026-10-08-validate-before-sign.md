# Validate FAT container before signing — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development with dispatching-parallel-agents. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Make `sign_macho_all_slices` (and every sibling entry point via the shared impl) reject structurally invalid FAT containers before any per-slice signing work.

**Architecture:** Widen `validate_fat_arches` to `pub(crate)` in writer.rs (call wiring only), then call it at the top of `sign_all_slices_impl` in signer.rs, gated on `macho.is_fat()`, with arches re-parsed from `macho.data()` via the same goblin `Mach`/`iter_arches` idiom `embed_signature_fat` uses. One migrated writer test + one new signer red test.

**Tech Stack:** Rust 2021, goblin Mach parsing, rayon untouched, inline `#[cfg(test)]` tests.

**Spec:** `docs/superpowers/specs/2026-10-08-validate-before-sign-design.md`

## Global Constraints

- Zero-warning gate: `cargo fmt --all -- --check` + `cargo clippy --workspace --all-targets -- -D warnings`.
- Tests: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test --workspace` at final gate; scoped `cargo test -p zsign-core <filter>` during flight.
- No ticket IDs in code, comments, docs, or commit messages.
- Edits ONLY in `crates/zsign-core/src/macho/signer.rs` and `crates/zsign-core/src/macho/writer.rs` (the latter: visibility + doc line on `validate_fat_arches` only — no other writer changes).
- parser.rs is read-only (other lanes own FAT-parse).
- Reuse existing error strings — overlap keeps `"FAT slices {} and {} overlap"` from the validator; no new message variants.
- Existing tests must stay green — migrate, never weaken.

## Review Focus

- Validation must run BEFORE `reject_encrypted`, `SigningContext::new`, and the `par_iter` — the whole point is no signing work on invalid containers.
- The gate must be `macho.is_fat()` — thin inputs must not be re-parsed as FAT; non-Fat parse results must fail closed with `Err`, never panic (`unreachable!` forbidden in production paths).
- The migrated writer test must still assert `embed_signature_fat`'s own overlap rejection (its original purpose) without relying on `sign_macho_all_slices` returning `Ok`.
- `validate_fat_arches` visibility change is the ONLY writer.rs change besides its doc comment.
- The new red test must fail pre-fix because `sign_macho_all_slices` returns `Ok` (behavior gap), not because of parse/construction errors.

---

### Task 1: Wiring + pre-sign validation call (TDD)

**Files:**
- Modify: `crates/zsign-core/src/macho/writer.rs` — `validate_fat_arches` visibility + doc (~:412-441)
- Modify: `crates/zsign-core/src/macho/signer.rs` — `sign_all_slices_impl` top (~:410-434); tests appended at end of signer.rs test mod
- Test migration: `crates/zsign-core/src/macho/writer.rs` — `test_embed_fat_rejects_overlapping_slices` (~:2751-2789)

**Interfaces:**
- Produces: `pub(crate) fn validate_fat_arches(arches: &[FatArch], data: &[u8]) -> Result<()>`; `sign_all_slices_impl` returns `Err` for overlapping containers.

- [ ] **Step 1: Write failing test + migrate the gap-pinning test**
  - New signer test `test_sign_macho_all_slices_rejects_overlapping_container`: reuse the hand-built hostile FAT bytes idiom from writer.rs (~:2757-2774 — copy the construction), `MachOFile::parse`, call `sign_macho_all_slices(&macho, ...)` with the same args existing signer tests use (read them first); `expect_err` + `contains("overlap")`.
  - Migrate writer's `test_embed_fat_rejects_overlapping_slices` so it no longer `.unwrap()`s a successful `sign_macho_all_slices`: keep its assertion that `embed_signature_fat` rejects the overlapping container. Preferred construction (spec §Chosen design details): hand-construct the two `SignedSlice`s matching the hostile arch identity fields (offset/original_size/cpu_type) with dummy `signed_data` — `embed_signature_fat` validates the container at writer.rs:408 before touching `signed_data`, so the overlap `Err` fires regardless. If hand-constructing `SignedSlice` proves awkward (private fields etc.), sign the slices from a VALID container layout and then present them against the hostile container ONLY if identity fields still match — document whichever route you take.
- [ ] **Step 2: Run both tests, expect failure**
  `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-core rejects_overlapping` → new test FAILS (Ok returned — capture verbatim); migrated test FAILS or is red by construction until the fix lands (capture state; it asserts post-fix behavior of embed, which passes even pre-fix — record honestly which state applies).
- [ ] **Step 3: Implement the wiring + call**
  - writer.rs: `fn validate_fat_arches` → `pub(crate) fn validate_fat_arches`; extend its doc comment to mention the signer entry point (no ticket IDs).
  - signer.rs: at the TOP of `sign_all_slices_impl`, before `reject_encrypted`:
    ```rust
    if macho.is_fat() {
        let arches = match goblin::mach::Mach::parse(macho.data())
            .map_err(|e| Error::MachO(format!("Failed to parse FAT container: {e}")))?
        {
            goblin::mach::Mach::Fat(fat) => fat
                .iter_arches()
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|e| Error::MachO(format!("Failed to read FAT arches: {}", e)))?,
            _ => return Err(Error::MachO("FAT container did not parse as FAT".into())),
        };
        super::writer::validate_fat_arches(&arches, macho.data())?;
    }
    ```
    Match the exact parse/collect idiom already used in `embed_signature_fat` (writer.rs ~:373-410) — read it first and mirror its error wording if it differs. Import path: check how writer.rs spells `Mach` (goblin import style) and mirror.
- [ ] **Step 4: Run scoped tests**
  `TMPDIR=$PWD/target/tmp cargo test -p zsign-core writer` and `... signer` → ALL green (new test passes; migrated test passes; FAT suite, sign_any/adhoc/sha256 tests, Items 1-2 tests unchanged).

### Task 2: Full gate + commits (controller-owned)

- [ ] `cargo fmt --all -- --check` && `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test --workspace`
- [ ] Controller commit (no ticket ID): `fix(macho): validate fat container before signing slices`.
