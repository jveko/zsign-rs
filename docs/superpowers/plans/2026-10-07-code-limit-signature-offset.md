# codeLimit / Signature-Offset Agreement Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development (recommended) with dispatching-parallel-agents for independent tasks to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make every signed output satisfy `CodeDirectory.codeLimit == LC_CODE_SIGNATURE.dataoff == physical blob offset` by materializing the 16-byte alignment pad in the prepared (hashed) buffer, so the hashed region never stops short of the signature.

**Architecture:** All three prepare paths in `crates/zsign-core/src/macho/writer.rs` zero-extend the prepared buffer from `code_length` to `sig_offset = align_to(code_length, 16)`. The signer already hashes `buf` and derives `codeLimit` from `buf.len()`, so no signer or code-directory logic changes.

**Tech Stack:** Rust, goblin, in-repo Mach-O byte fixtures, `cargo test -p zsign-core`.

**Spec:** `docs/superpowers/specs/2026-10-07-code-limit-signature-offset-design.md`

## Global Constraints

- Zero-warning gate: `cargo fmt --all -- --check` and `cargo clippy --workspace --all-targets -- -D warnings` must pass.
- Tests run with `TMPDIR=$PWD/target/tmp cargo test --workspace` (`mkdir -p target/tmp` first).
- No ticket IDs anywhere in code, comments, docs, or commit messages.
- Only files named by a task may be touched. Deferred files (`crates/zsign/**`, `crates/zsign-core/src/crypto/**`, `macho/verify.rs`, `codesign/verify.rs`, `crates/zsign-cli/**`, `examples/**`) are off limits.
- `align_to`, `calculate_signature_space`, `has_enough_signature_space`, the realloc delta computations (`size_increase` / `new_vmsize`), and `embed_signature*` placement logic are NOT touched.
- `crates/zsign-core/src/codesign/code_directory.rs` is NOT touched — the buffer length remains the single source of truth for `codeLimit`.
- 16-byte alignment of `dataoff` must be preserved (existing tests pin `dataoff % 16 == 0`).
- `nCodeSlots` must remain `ceil(code_length / 4096)` — unchanged by the zero-width-or-smaller pad.
- Already-aligned inputs must produce byte-identical results (zero-width pad).
- Conventional commits: imperative, lowercase, no trailing period, no ticket IDs.

## Review Focus

1. Odd-length unsigned input (code_length 0x2001, dataoff 0x2010): `codeLimit` must equal `dataoff` — pinned by `test_code_limit_equals_dataoff_for_odd_length` (Task 1).
2. Re-sign of an image with an unaligned existing `dataoff`: same equality after the re-sign heals the offset — pinned by `test_code_limit_equals_dataoff_after_odd_resign` (Task 1).
3. The 15 pad bytes must be zero-filled in the file AND covered by the code slots — pinned by the zero-byte assert and the `check_code_pages == Matched` assert in `test_code_limit_equals_dataoff_for_odd_length` (Task 1).
4. The alignment/reserve machinery must be untouched: `test_realloc_writes_aligned_dataoff_for_odd_code_length`, `test_sign_unaligned_length_keeps_signature_in_bounds`, `test_odd_dataoff_resign_roundtrip`, `test_prepare_capacity_guard_counts_alignment_pad_for_odd_dataoff`, `test_align_to`, `test_calculate_signature_space_non_aligned` must stay green (gate in Task 2).
5. The common aligned case must be unchanged: existing signer roundtrips, `verify_code_directory` (`code_limit == code.len()`), FAT exec-seg assertions, and full workspace suites must stay green (gate in Task 2).

---

### Task 1: Regression tests for codeLimit == dataoff

**Files:**
- Test: `crates/zsign-core/src/macho/writer.rs` (inline `mod tests`, next to `test_sign_unaligned_length_keeps_signature_in_bounds`)

**Interfaces:**
- Consumes: `crate::macho::fixtures::{make_minimal_macho, make_signed_minimal_macho_at}`, `crate::macho::{MachOFile, sign_macho_adhoc}`, `crate::codesign::verify::{parse_superblob, check_code_pages, PageCheck}` — all already used by neighbouring tests.
- Produces: two tests, `test_code_limit_equals_dataoff_for_odd_length` and `test_code_limit_equals_dataoff_after_odd_resign` — Task 2 greens them; the reviewer checks them by name.

- [ ] **Step 1: Write the two failing tests**

In `crates/zsign-core/src/macho/writer.rs`, inside the existing `mod tests`, append:

```rust
#[test]
fn test_code_limit_equals_dataoff_for_odd_length() {
    let mut data = crate::macho::fixtures::make_minimal_macho();
    data.resize(0x2001, 0); // unsigned image whose length is not 16-aligned
    let macho = crate::macho::MachOFile::parse(data).expect("fixture must parse");
    let signed =
        crate::macho::sign_macho_adhoc(&macho, "com.example.oddlen", None, None, None, false)
            .expect("signing an odd-length unsigned binary must succeed");
    let reparsed =
        crate::macho::MachOFile::parse(signed.clone()).expect("signed output must reparse");
    let slice = &reparsed.slices()[0];
    let dataoff = slice
        .code_sig_offset
        .expect("signed output carries LC_CODE_SIGNATURE") as usize;
    let size = slice.code_sig_size.expect("signed size") as usize;
    assert_eq!(dataoff, 0x2010, "sig offset is align_to(0x2001, 16)");
    let superblob = crate::codesign::verify::parse_superblob(&signed[dataoff..dataoff + size])
        .expect("embedded superblob parses");
    let cd = superblob
        .code_directory
        .as_ref()
        .expect("code directory present");
    let code_limit = u32::from_be_bytes(cd.raw()[32..36].try_into().unwrap()) as usize;
    assert_eq!(
        code_limit, dataoff,
        "codeLimit must equal LC_CODE_SIGNATURE.dataoff: no file byte may sit between the hashed region and the signature"
    );
    assert!(
        signed[0x2001..0x2010].iter().all(|&b| b == 0),
        "the pad between code_length 0x2001 and dataoff 0x2010 must be zero-filled"
    );
    assert!(
        matches!(
            crate::codesign::verify::check_code_pages(cd, &signed[..dataoff]),
            crate::codesign::verify::PageCheck::Matched
        ),
        "every byte below dataoff, pad included, must verify against the code slots"
    );
}

#[test]
fn test_code_limit_equals_dataoff_after_odd_resign() {
    let signed = crate::macho::fixtures::make_signed_minimal_macho_at(0x2001, 0x400);
    let macho = crate::macho::MachOFile::parse(signed).expect("odd input must parse");
    let resigned =
        crate::macho::sign_macho_adhoc(&macho, "com.example.odd", None, None, None, false)
            .expect("re-sign must succeed");
    let reparsed =
        crate::macho::MachOFile::parse(resigned.clone()).expect("resigned output must reparse");
    let slice = &reparsed.slices()[0];
    let dataoff = slice
        .code_sig_offset
        .expect("signed output carries LC_CODE_SIGNATURE") as usize;
    let size = slice.code_sig_size.expect("signed size") as usize;
    let superblob = crate::codesign::verify::parse_superblob(&resigned[dataoff..dataoff + size])
        .expect("embedded superblob parses");
    let cd = superblob
        .code_directory
        .as_ref()
        .expect("code directory present");
    let code_limit = u32::from_be_bytes(cd.raw()[32..36].try_into().unwrap()) as usize;
    assert_eq!(
        code_limit, dataoff,
        "re-signing an odd-dataoff image must still yield codeLimit == dataoff"
    );
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-core writer::tests::test_code_limit`
Expected: FAIL — both tests fail on the `codeLimit == dataoff` assertion with `left = 8193 (0x2001)`, `right = 8208 (0x2010)` (pre-fix `codeLimit` is the truncated buffer length `code_length`). All other tests in the filter are unaffected (they are not in it).

---

### Task 2: Materialize the alignment pad in the prepare paths

**Files:**
- Modify: `crates/zsign-core/src/macho/writer.rs`

**Interfaces:**
- Consumes: Task 1's tests (already written; this task greens them).
- Produces: prepared buffers of length `sig_offset` from `prepare_code_in_place`, `prepare_code_single` (backing `prepare_code_for_signing` / `prepare_code_for_signing_slice`), and `prepare_code_with_metadata`. Return types are unchanged — only the first tuple element's length contract changes, documented in each function's doc comment.

- [ ] **Step 1: Pad `prepare_code_in_place`**

In `crates/zsign-core/src/macho/writer.rs`, `prepare_code_in_place` currently does `buf.truncate(code_length);` (the line whose comment and the following lines declare the buffer holds the code bytes). Keep the truncate — it discards stale old-signature bytes — and immediately zero-extend to `sig_offset`:

```rust
    buf.truncate(code_length);
    buf.resize(sig_offset, 0);
```

Order matters: truncate first, then resize, so the pad bytes are zeros rather than leftover old-signature bytes. Update the function's doc comment to state that the buffer is returned `sig_offset` bytes long (code bytes plus zero alignment pad) and that this length is the hash region, equal to the `LC_CODE_SIGNATURE.dataoff` written by the same call.

- [ ] **Step 2: Pad the other two prepare paths**

Same file:

- `prepare_code_single`: after `let mut prepared = data[..code_length].to_vec();` add `prepared.resize(sig_offset, 0);`.
- `prepare_code_with_metadata`: after its `let mut prepared = data[..code_length].to_vec();` add `prepared.resize(sig_offset, 0);`.

Update both functions' doc comments to state the returned buffer is `sig_offset` bytes (code plus zero pad) — the region to hash. Do NOT change what `sig_offset`/`code_length` return values mean, and do not touch `realloc_*`, `embed_*`, `align_to`, or the reserve math.

- [ ] **Step 3: Update the signer's step comment**

In `crates/zsign-core/src/macho/signer.rs`, the comment above `let dual_hashes = hash_code_pages_dual(&buf);` says the buffer "now contains exactly the code bytes (code_length)". Update it to say the buffer now contains the code bytes plus the zero alignment pad, i.e. `sig_offset == LC_CODE_SIGNATURE.dataoff` bytes — the hashed region that `codeLimit` must equal. Comment only; no logic change in `signer.rs`.

- [ ] **Step 4: Run the scoped tests to verify they pass**

Run: `TMPDIR=$PWD/target/tmp cargo test -p zsign-core writer` then `TMPDIR=$PWD/target/tmp cargo test -p zsign-core signer`
Expected: PASS — the two new tests pass, and every pre-existing writer/signer test stays green (alignment, capacity guard, roundtrips, `verify_code_directory`). If any pre-existing test asserted the OLD buffer length (`prepared.len() == code_length`), report it in your report file rather than silently changing it — it pins the pre-fix behavior and the controller will rule on it.

- [ ] **Step 5: Run the full workspace gate**

Run:
```
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
TMPDIR=$PWD/target/tmp cargo test --workspace
```
Expected: fmt clean, clippy zero warnings, all suites pass (including facade/CLI/wasm — no deferred file may need edits; if one does, STOP and report instead of editing it).

- [ ] **Step 6: Commit**

Controller commits (implementers never commit):

```
git add crates/zsign-core/src/macho/writer.rs crates/zsign-core/src/macho/signer.rs
git commit -m "fix(macho): hash through the signature alignment pad"
```
