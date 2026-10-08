# Bounds-Checked Slice Accessors Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development (recommended) with dispatching-parallel-agents for independent tasks to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `MachOFile::code_bytes` and `MachOFile::slice_data` return a typed error instead of panicking when handed a forged or cross-file `ArchSlice`, and migrate every caller.

**Architecture:** Both accessors switch from unchecked `start + len` + direct indexing to the module's existing `checked_add(...).and_then(|end| data.get(start..end)).ok_or_else(|| Error::MachO(..))?` shape, changing their return type to `crate::Result<&[u8]>`. The `zsign-rs` facade wrappers mirror the new signatures. The core signature change, the four production callers, the four test call sites, and the two facade wrappers are one atomic unit — splitting them would leave a commit that does not compile — so Task 1 carries the whole change behind a single test-first cycle.

**Tech Stack:** Rust 2021 workspace, existing `crate::Error` (`thiserror`), `crate::Result` alias, rayon (already in use at one call site).

**Spec:** `docs/superpowers/specs/2026-10-08-bound-slice-accessor-indexing-design.md` — the plan argues from the spec; executors read both.

## Global Constraints

- No ticket IDs anywhere in the repo: code, comments, commit subjects/bodies, docs, messages. The slug naming this change is `bound-slice-accessor-indexing`.
- Keep `TMPDIR` inside the worktree: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test …` (`/tmp` is a small tmpfs).
- Error channel: reuse `Error::MachO(String)` (`crates/zsign-core/src/error.rs:7-8`); no new variants, no new dependencies.
- Minimal diff confined to: the two accessor bodies/signatures/doc comments in `crates/zsign-core/src/macho/parser.rs`, their callers (`signer.rs` :259, :312, :356, :458, :1393, :1467; `writer.rs` :3073, :3078), new tests in `parser.rs`, and the two facade wrappers (`crates/zsign/src/macho/parser.rs:56-61`).
- Do NOT touch: the zero-`nfat_arch` parse guard, `macho/verify.rs`, `codesign/verify.rs`, `crypto/pkcs12.rs`, `cli/main.rs`, `wasm/lib.rs`, `crates/zsign/src/macho/mod.rs` (other than nothing), `bundle/code_resources.rs`.
- SKILL (required): test-driven-development within Task 1 — failing test first, run it, then implement. SKILL (required): subagent-driven-development — Tester subagent writes the test, implementer subagent greens it, orchestrator runs gates and commits.
- Commits: conventional, imperative mood, lowercase, no trailing period, no ticket ID.
- Scoped gates while working; the full gate list runs in Task 2.

## Review Focus

These are the failure modes the spec implies but a careless implementation would miss; each pins to a test in Task 1.

1. **Overflow at a forged `offset` near `usize::MAX`** must be `Err` in every build profile — the body must never contain a plain `+`. Pinned by `test_forged_slice_offset_length_overflow_is_rejected`.
2. **An in-bounds `offset` whose `length` runs past the file end** (slice aliased from a larger file) must be `Err`, not a truncated or empty slice. Pinned by `test_slice_range_pasting_file_end_is_rejected`.
3. **An `offset` entirely past the file end** must be `Err` for *both* accessors. Pinned by `test_forged_offset_beyond_file_is_rejected`.
4. **Valid inputs must stay byte-identical**: the zero-length range at exactly `data.len()` stays `Ok(&[])` (in bounds), and all existing signer/writer assertions keep their exact expected values after migration. Pinned by `test_zero_length_range_at_file_end_is_valid` plus the unchanged assertions of the migrated existing tests.
5. **Error discriminant and wording**: both failure modes surface as `Error::MachO(String)` with the spec's messages ("… overflows" / "… exceeds file …"), so downstream `matches!(… Err(Error::MachO(m)) if m.contains(..))` consumers keep working. Pinned by the message assertions inside Task 1's four tests.

---

### Task 1: Bounds-checked slice accessors with failing test first

**Files:**
- Modify: `crates/zsign-core/src/macho/parser.rs` — `code_bytes` (currently :429-433), `slice_data` (currently :440-444), their doc comments, and the `#[cfg(test)] mod tests` block (starts :477) gains four tests.
- Modify: `crates/zsign-core/src/macho/signer.rs:259, 312, 356, 458` (add `?`), `:1393, :1467` (add `.expect(..)`).
- Modify: `crates/zsign-core/src/macho/writer.rs:3073, 3078` (add `.expect(..)`).
- Modify: `crates/zsign/src/macho/parser.rs:56-61` (both wrappers).

**Interfaces:**
- Consumes: `crate::Error::MachO(String)`, `crate::Result<T>` (already imported in `parser.rs:27`); fixture `crate::macho::fixtures::make_minimal_macho() -> Vec<u8>` (0x2000 bytes); `MachOFile::data() -> &[u8]`.
- Produces (both crates, for later lanes and the facade):
  - `pub fn code_bytes(&self, slice: &ArchSlice) -> Result<&[u8]>`
  - `pub fn slice_data(&self, slice: &ArchSlice) -> Result<&[u8]>`
  - Facade: `pub fn code_bytes(&self, slice: &ArchSlice) -> Result<&[u8]>` / `slice_data` likewise, where `Result` is the facade's `crate::Result`.

- [ ] **Step 1: Tester writes the four failing tests**

Append to `crates/zsign-core/src/macho/parser.rs` `#[cfg(test)] mod tests` (after the existing tests, before the closing brace):

```rust
#[test]
fn test_forged_offset_beyond_file_is_rejected() {
    let macho =
        MachOFile::parse(crate::macho::fixtures::make_minimal_macho()).expect("fixture must parse");
    let mut forged = macho.slices()[0].clone();
    forged.offset = macho.data().len() + 1;

    let res = macho.slice_data(&forged);
    assert!(
        matches!(&res, Err(Error::MachO(m)) if m.contains("exceeds")),
        "forged offset must be an error, got {:?}",
        res.as_ref().err()
    );
    let res = macho.code_bytes(&forged);
    assert!(
        matches!(&res, Err(Error::MachO(m)) if m.contains("exceeds")),
        "forged offset must be an error, got {:?}",
        res.as_ref().err()
    );
}

#[test]
fn test_slice_range_pasting_file_end_is_rejected() {
    let macho =
        MachOFile::parse(crate::macho::fixtures::make_minimal_macho()).expect("fixture must parse");
    // A range that fits a larger file but not this 0x2000-byte one — the
    // cross-file aliased-slice case.
    let mut forged = macho.slices()[0].clone();
    forged.offset = 0x1800;
    forged.size = 0x1000;
    forged.code_length = 0x1000;

    let res = macho.slice_data(&forged);
    assert!(
        matches!(&res, Err(Error::MachO(m)) if m.contains("exceeds")),
        "range past the file end must be an error, got {:?}",
        res.as_ref().err()
    );
    let res = macho.code_bytes(&forged);
    assert!(
        matches!(&res, Err(Error::MachO(m)) if m.contains("exceeds")),
        "range past the file end must be an error, got {:?}",
        res.as_ref().err()
    );
}

#[test]
fn test_forged_slice_offset_length_overflow_is_rejected() {
    let macho =
        MachOFile::parse(crate::macho::fixtures::make_minimal_macho()).expect("fixture must parse");
    let mut forged = macho.slices()[0].clone();
    forged.offset = usize::MAX - 3;
    forged.size = 100;
    forged.code_length = 100;

    let res = macho.slice_data(&forged);
    assert!(
        matches!(&res, Err(Error::MachO(m)) if m.contains("overflows")),
        "offset + length overflow must be an error, got {:?}",
        res.as_ref().err()
    );
    let res = macho.code_bytes(&forged);
    assert!(
        matches!(&res, Err(Error::MachO(m)) if m.contains("overflows")),
        "offset + length overflow must be an error, got {:?}",
        res.as_ref().err()
    );
}

#[test]
fn test_zero_length_range_at_file_end_is_valid() {
    let macho =
        MachOFile::parse(crate::macho::fixtures::make_minimal_macho()).expect("fixture must parse");
    let mut at_end = macho.slices()[0].clone();
    at_end.offset = macho.data().len();
    at_end.size = 0;
    at_end.code_length = 0;

    assert_eq!(
        macho.slice_data(&at_end).expect("empty range at the end is in bounds"),
        b""
    );
    assert_eq!(
        macho.code_bytes(&at_end).expect("empty range at the end is in bounds"),
        b""
    );
}
```

Notes for the Tester: `Error` and `MachOFile` are in scope via `use super::*`; assertion style (message footer with `got {:?}`) matches the module's dominant pattern. These tests target the NEW signature, so they do not compile against current code — that is the expected red for an API-shape change.

- [ ] **Step 2: Run the tests, confirm the expected failure**

Run: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-core parser::tests::test_forged`
Expected: FAIL to compile — `error[E0308]: mismatched types` at the new assertions (`expected \`Result<…>\`, found \`&[u8]\``), because `slice_data`/`code_bytes` still return `&[u8]`. Record the exact error; no other outcome counts.

- [ ] **Step 3: Implement the checked accessors in `parser.rs`**

Replace both bodies; the signature becomes `pub fn code_bytes(&self, slice: &ArchSlice) -> Result<&[u8]>`:

```rust
let end = slice
    .offset
    .checked_add(slice.code_length)
    .ok_or_else(|| {
        Error::MachO(format!(
            "slice offset {} + length {} overflows",
            slice.offset, slice.code_length
        ))
    })?;
self.data.get(slice.offset..end).ok_or_else(|| {
    Error::MachO(format!(
        "slice range {}..{} exceeds file of {} bytes",
        slice.offset,
        end,
        self.data.len()
    ))
})
```

`slice_data` is identical with `slice.size` in place of `slice.code_length`. Extend each doc comment with an `# Errors` section naming the two conditions (offset + length overflows; range exceeds the file), and keep the existing "See also" cross-references. No plain `+` may remain in either body.

- [ ] **Step 4: Migrate every caller in `zsign-core`**

- `signer.rs:259, 312, 356`: `let slice_data = macho.slice_data(slice)?;` (each fn already returns `Result<…>`).
- `signer.rs:458`: `let slice_data = macho.slice_data(slice)?;` (inside the rayon closure returning `Result<SignedSlice>`).
- `signer.rs:1393`: `assert_eq!(macho.code_bytes(&macho.slices()[0]).expect("code region is in bounds").len(), 0x2000);`
- `signer.rs:1467`: `let code = signed_macho.code_bytes(slice).expect("code region is in bounds");`
- `writer.rs:3073`: bind first — `let image = m.slice_data(sl).expect("embedded slice must be in bounds");` above the `assert_eq!`, then index `&image[sig_off..sig_off + replacement.len()]`.
- `writer.rs:3078`: `m.slice_data(sl).expect("embedded slice must be in bounds").len(),`

Existing assertion values change nowhere.

- [ ] **Step 5: Mirror the signatures in the facade**

`crates/zsign/src/macho/parser.rs:56-61`:

```rust
pub fn code_bytes(&self, slice: &ArchSlice) -> Result<&[u8]> {
    Ok(self.inner.code_bytes(slice)?)
}
pub fn slice_data(&self, slice: &ArchSlice) -> Result<&[u8]> {
    Ok(self.inner.slice_data(slice)?)
}
```

The `?` converts through the existing `From<zsign_core::Error> for Error`; core `MachO(..)` surfaces as `Error::Core(..)`. No other facade or crate (`zsign-cli`, `zsign-wasm`, `fuzz`) has callers.

- [ ] **Step 6: Run the scoped gates**

Run: `cargo fmt --all && cargo fmt --all -- --check && TMPDIR=$PWD/target/tmp cargo test -p zsign-core && TMPDIR=$PWD/target/tmp cargo test -p zsign-rs && cargo clippy --workspace --all-targets -- -D warnings`
Expected: all four pass — the four new tests PASS, every previously green test stays green, fmt and clippy clean.

- [ ] **Step 7: Commit**

`git add` the files listed above, then:
`git commit -m "fix(macho): bounds check slice accessor indexing"`
(imperative, lowercase, no ticket ID, no trailing period.)

### Task 2: Full gate run (verification only, no code changes expected)

**Files:** none — if a gate fails, fix within Task 1's file list and amend Task 1's commit scope as a new conventional commit.

- [ ] **Step 1: Run the land gate**

Run: `cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings && mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test --workspace && hk check --all`
Expected: zero warnings, all tests pass, `hk check --all` exits 0. Paste its verbatim output into the final report. If `hk check --all` is unavailable in the sandbox, attempt it once and record the outcome honestly.

- [ ] **Step 2: Confirm the repo is clean and committed**

Run: `git status --short && git log --oneline -3`
Expected: clean tree; docs commit plus the Task 1 fix commit present; no pushes performed.
