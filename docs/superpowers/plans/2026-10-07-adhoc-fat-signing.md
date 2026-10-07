# Ad-hoc FAT Signing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development (recommended) with dispatching-parallel-agents for independent tasks to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `sign_macho_adhoc` signs every slice of a FAT/Universal container ad-hoc and reassembles it, exactly like its two FAT-capable siblings, with tests pinning the contract.

**Architecture:** Reuse the existing shared per-slice engine `sign_all_slices_impl` with `credentials = None` (the ad-hoc axis) and `sha256_only = false`, then reassemble with `super::writer::embed_signature_fat` — the identical body shape already used by `sign_any_macho` and `sign_macho_sha256_only`. No public signature changes.

**Tech Stack:** Rust 2021, `zsign-core` (rayon per-slice signing), `thiserror` errors, `cargo test`/`cargo clippy` for verification.

**Spec:** `docs/superpowers/specs/2026-10-07-adhoc-fat-signing-design.md` — the plan argues from the spec; executors read both.

**Tree state at plan time:** the routing body, its doc comment, and its success-path test are already on this branch (commit `b546fb6`, verified in the spec's "Current tree status"). Tasks therefore verify existing contracts and add the one guard test the spec's test strategy identifies as missing; a step that would be red-first is marked with the exact fix to apply only if it comes back red.

## Global Constraints

- Scope: `crates/zsign-core/src/macho/` only. `crates/zsign/**`, `crates/zsign-core/src/codesign/der.rs`, and CI workflows are deferred to other lanes — no edits, no doc fixes there (report findings instead).
- Repo invariants: edition 2021; `thiserror`; `crate::Result<T>`; inline `#[cfg(test)] mod tests` per file; error assertions use `assert!(matches!(&res, Err(Error::Variant(m)) if m.contains("…")), "…, got {:?}", res.as_ref().err());`; one `use` block per module matching the file being edited; no second conventions.
- No ticket IDs in any commit subject, commit body, comment, or doc line.
- Conventional commit subjects, imperative mood, lowercase, no trailing period.
- Never merge, never push. `TMPDIR` stays inside the worktree: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo …`.
- Scoped gates only — never a project-wide cold CI run mid-flight.
- No stubs, TODOs, placeholders, or new public API.

## Review Focus

Input classes the spec implies but a careless change would break — each line is pinned by a test in the task named after it:

1. **Encrypted slice inside a container, ad-hoc entry:** a caller signing a universal binary with an encrypted slice must get `Error::EncryptedBinary` naming the slice, and `allow_encrypted=true` must let the same input sign — Task 2 (the sibling test at `signer.rs:1584` covers only `sign_any_macho`, so this entry's guard is currently unpinned).
2. **Output must stay a FAT container with both architectures preserved:** Task 1 (`test_sign_macho_adhoc_signs_fat_container`).
3. **Every slice must be ad-hoc and verify:** `CS_ADHOC` flag, `PageCheck::Matched`, `is_valid()` per slice — Task 1 (same test).
4. **The credential-gated thin entry must still refuse containers** with an error naming the FAT-capable entry — Task 1 (`test_sign_macho_rejects_fat_containers`).
5. **Facade parity, deferred crate:** the existing facade test must keep passing without any edit there — Task 3 (`cargo test -p zsign-rs test_sign_macho_adhoc_signs_fat`).

---

### Task 1: Ad-hoc FAT routing contract (core, already on branch — verify)

**Files:**
- Verify: `crates/zsign-core/src/macho/signer.rs:287-322` (routing body), `signer.rs:1247-1314` (the two contract tests)

**Interfaces:**
- Consumes: `sign_all_slices_impl(macho, identifier, entitlements, credentials: Option<&SigningCredentials>, info_plist, code_resources, allow_encrypted, sha256_only) -> Result<Vec<SignedSlice>>` (`signer.rs:410-459`); `super::writer::embed_signature_fat(data, slices) -> Result<Vec<u8>>`.
- Produces: `pub fn sign_macho_adhoc(macho: &MachOFile, identifier: &str, entitlements: Option<&[u8]>, info_plist: Option<&[u8]>, code_resources: Option<&[u8]>, allow_encrypted: bool) -> Result<Vec<u8>>` — unchanged signature; FAT input returns a reassembled signed container.

- [ ] **Step 1: Run the two contract tests**

Run: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-core test_sign_macho_adhoc_signs_fat_container`
Run: `TMPDIR=$PWD/target/tmp cargo test -p zsign-core test_sign_macho_rejects_fat_containers`
Expected: `test result: ok` from both commands (the tests exist at `signer.rs:1264` and `signer.rs:1248`).

- [ ] **Step 2: If red or missing, implement the FAT branch**

Only if Step 1 fails: in `sign_macho_adhoc` replace the hard-error `if macho.is_fat() { return Err(...) }` with the spec's "Chosen design" block — `reject_encrypted(...)?`, then `sign_all_slices_impl(macho, identifier, entitlements, None, info_plist, code_resources, allow_encrypted, false)?`, then `return super::writer::embed_signature_fat(macho.data(), &signed);` — and add the missing test per the spec's test strategy item 1.

- [ ] **Step 3: Re-run Step 1**

Run: the same two commands as Step 1.
Expected: `test result: ok`, both tests pass.

---

### Task 2: Encrypted-slice guard at the ad-hoc FAT entry (core, new test)

**Files:**
- Test: `crates/zsign-core/src/macho/signer.rs` — add one test to the existing `#[cfg(test)] mod tests`, next to `test_sign_refuses_fat_with_encrypted_slice` (`signer.rs:1584`).

**Interfaces:**
- Consumes: `sign_macho_adhoc(...)` (Task 1), fixtures `make_fat_macho(&[Vec<u8>], &[u32])`, `make_minimal_macho()`, `make_minimal_macho_encrypted(cryptid: u32, cryptsize: u32)` (cryptoff is fixed at `0x1000` inside the fixture, `fixtures.rs:468`) from the tests module imports (`signer.rs:908-910`).
- Produces: no production code. If and only if the test comes back red, the fix is the `reject_encrypted(macho, identifier, allow_encrypted)?;` line as the first statement of `sign_macho_adhoc`'s `if macho.is_fat()` branch (`signer.rs:296`).

- [ ] **Step 1: Write the failing test**

Append to `crates/zsign-core/src/macho/signer.rs` tests:

```rust
#[test]
fn test_sign_macho_adhoc_refuses_fat_with_encrypted_slice() {
    let fat = make_fat_macho(
        &[
            make_minimal_macho(),
            make_minimal_macho_encrypted(1, 0x1000),
        ],
        &[12, 12],
    );
    let macho = MachOFile::parse(fat).expect("FAT binary must parse");
    assert!(macho.slices()[1].is_encrypted(), "second slice must be encrypted");

    let err = sign_macho_adhoc(&macho, "com.zsign.adhocenc", None, None, None, false)
        .expect_err("ad-hoc FAT signing must refuse an encrypted slice");
    match err {
        crate::Error::EncryptedBinary(msg) => {
            assert!(msg.contains("slice 1"), "message must name the encrypted slice: {msg}");
        }
        other => panic!("expected EncryptedBinary, got {other:?}"),
    }

    let signed = sign_macho_adhoc(&macho, "com.zsign.adhocenc", None, None, None, true)
        .expect("allow_encrypted=true must sign the FAT binary");
    assert!(
        signed.len() > macho.data().len(),
        "signed FAT must include the embedded signature"
    );
}
```

- [ ] **Step 2: Run the test**

Run: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-core test_sign_macho_adhoc_refuses_fat_with_encrypted_slice`
Expected: PASS — the guard already ships with the branch's FAT arm, so the red-first state is unavailable (recorded as a plan deviation). If it FAILS with a signing success instead of `EncryptedBinary`, apply the Interfaces "Produces" line: add `reject_encrypted(macho, identifier, allow_encrypted)?;` before `sign_all_slices_impl` in the FAT branch, then re-run until PASS.

- [ ] **Step 3: Run the whole signer test module**

Run: `TMPDIR=$PWD/target/tmp cargo test -p zsign-core signer`
Expected: `test result: ok`, all tests pass (baseline before this task: 32 passed).

---

### Task 3: Scoped gate and commit

**Files:**
- No source edits; this task observes and commits.

**Interfaces:**
- Consumes: Tasks 1-2 results.
- Produces: one commit carrying the new test (docs commits happen earlier, in the design/plan step).

- [ ] **Step 1: Formatting check**

Run: `cargo fmt --all -- --check`
Expected: no output, exit 0.

- [ ] **Step 2: Scoped lint**

Run: `TMPDIR=$PWD/target/tmp cargo clippy -p zsign-core --all-targets -- -D warnings`
Expected: `Finished` with zero warnings; no workspace-wide cold run.

- [ ] **Step 3: Scoped tests (core + the deferred facade call path, read-only)**

Run: `TMPDIR=$PWD/target/tmp cargo test -p zsign-core signer` then `TMPDIR=$PWD/target/tmp cargo test -p zsign-rs test_sign_macho_adhoc_signs_fat`
Expected: `test result: ok` in both; the facade test passes without touching `crates/zsign/**`.

- [ ] **Step 4: Commit**

Run: `git add crates/zsign-core/src/macho/signer.rs && git commit -m "test: cover ad-hoc encrypted slice guard on fat containers"`
Expected: commit created on the current branch; never merge, never push.
