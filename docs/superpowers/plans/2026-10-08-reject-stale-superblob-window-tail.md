# Reject Stale Data Past the Declared SuperBlob Length — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development (recommended) with dispatching-parallel-agents for independent tasks to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `-V` reject any nonzero data past the SuperBlob's declared length inside the `LC_CODE_SIGNATURE` window, so a planted second signature can no longer verify clean.

**Architecture:** One new check in `verify_slice` (the policy layer), running immediately after `parse_superblob` succeeds; `parse_superblob` keeps its documented by-design tolerance. Tests live inline in the same file's `#[cfg(test)]` module, reusing the existing ad-hoc signing helpers.

**Tech Stack:** Rust 2021 workspace, `cargo test -p zsign-core`, inline test module, no new dependencies.

**Spec:** `docs/superpowers/specs/2026-10-08-reject-stale-superblob-window-tail-design.md` — the plan argues from it; executors read both.

## Global Constraints

- No ticket IDs anywhere: code, comments, commit subjects/bodies, docs, messages.
- Commits: conventional format `type(scope): subject`, imperative mood, lowercase, no trailing period. Commit, never push.
- Only `crates/zsign-core/src/macho/verify.rs` may be changed (its inline test module included). No writer, parser, CLI, wasm, bundle, or `codesign/verify.rs` changes.
- Exact error message (substring asserted by tests): `code signature window contains {n} nonzero bytes past the declared SuperBlob length`.
- The check runs only after `parse_superblob` returns `Ok`, before the primary-CodeDirectory check; it pushes into `report.errors` — never `warnings`, never a returned `Err`.
- Do not touch the codeLimit/dataoff tying, coverage-check, or CodeDirectory field-validation regions of this file; they belong to other work.
- Keep `TMPDIR` inside the worktree: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-core` (`/tmp` is a small tmpfs).
- Scoped gates while working: `cargo fmt --all -- --check` and `cargo clippy -p zsign-core --all-targets -- -D warnings`. The orchestrator runs the full workspace gates and `hk check --all` once at the end.
- No stubs/TODOs/placeholders. Implementers never spawn subagents and never commit; the controller commits.

## Review Focus

1. Planted complete second SuperBlob (the attack class) must yield exactly the new error and nothing else → Task 1 test `planted_second_superblob_in_window_tail_is_rejected`.
2. A non-magic stray nonzero byte must also be rejected — the predicate is "nonzero", not "magic" → Task 1 test `stray_nonzero_byte_in_window_tail_is_rejected`.
3. The own writer's zero tail (`datasize > declared`, arbitrary length) must stay valid, non-vacuously (assert the tail exists and is zero) → Task 1 test `zero_filled_window_tail_is_accepted`.
4. An exact-fit window (`declared == datasize`) must stay valid → Task 1 test `exact_fit_window_tail_is_accepted`.

---

### Task 1: Failing tests for window-tail strictness

**Files:**
- Modify: `crates/zsign-core/src/macho/verify.rs` — inline `mod tests` (append after the last existing test, around line 1590).

**Interfaces:**
- Consumes: existing test-module helpers and API — `make_minimal_macho`, `sign_macho_adhoc`, `MachOFile::parse`, `SignatureInputs::none()`, `verify_macho`, `MachOVerifyReport::{is_valid, error_count}`; `ArchSlice::{code_sig_offset, code_sig_size}` and `ArchSlice.metadata.code_sig_cmd: Option<(usize, u32, u32)>` (`(lc_offset, dataoff, datasize)`).
- Produces: four tests with the exact names below. Task 2 must make tests 1–2 pass without modifying tests 3–4.

- [ ] **Step 1: Write the four tests**

Shared shape: `let macho = MachOFile::parse(make_minimal_macho()).unwrap();` then `let mut signed = sign_macho_adhoc(&macho, "com.example.window", None, None, None, false).unwrap();`. Window location: parse `signed`, take `slices()[0]`, `sig_off = code_sig_offset.unwrap() as usize`, `sig_len = code_sig_size.unwrap() as usize`, `declared = u32::from_be_bytes(signed[sig_off + 4..sig_off + 8].try_into().unwrap()) as usize` (fixture is little-endian arm64; the SuperBlob header fields themselves are big-endian).

1. `planted_second_superblob_in_window_tail_is_rejected`
   - Baseline: `verify_macho(&signed, &SignatureInputs::none())` → `assert!(baseline.is_valid(), "{:?}", baseline.slices[0].errors)` (ad-hoc fixtures verify clean; pinned precedent at verify.rs:1390-1393).
   - Precondition: `assert!(sig_len >= 2 * declared, "reserve must fit a full duplicate: sig_len={sig_len} declared={declared}")` (reserve ≈ 20 KB, blob ≈ well under 2 KB for this fixture).
   - Plant a complete second signature: `signed.copy_within(sig_off..sig_off + declared, sig_off + declared);` (adjacent, non-overlapping ranges).
   - Assert: `!report.is_valid()` with message `"planted second signature must not verify clean: {:?}"` + errors; `report.error_count() == 1` with footer printing `report.slices[0].errors`; `slice.errors[0].contains("nonzero bytes past the declared SuperBlob length")`.

2. `stray_nonzero_byte_in_window_tail_is_rejected`
   - Same baseline sign; then `signed[sig_off + declared] = 0xff;`.
   - Assert: `!report.is_valid()`; `error_count() == 1` with errors footer; `errors[0].contains("nonzero bytes past the declared SuperBlob length")`.

3. `zero_filled_window_tail_is_accepted`
   - Same baseline sign; locate window as above.
   - Vacuity guards: `assert!(declared < sig_len, "fixture must carry a reserved tail: declared={declared} sig_len={sig_len}")` and `assert!(signed[sig_off + declared..sig_off + sig_len].iter().all(|&b| b == 0), "fixture tail must be zero-filled")`.
   - Assert: `report.is_valid()` with footer `report.slices[0].errors` and `report.error_count() == 0`.

4. `exact_fit_window_tail_is_accepted`
   - Same baseline sign; read `(lc_off, dataoff, datasize)` from `slices()[0].metadata.code_sig_cmd.expect("fixture is signed")`; `declared` as above (also assert `declared < datasize as usize` so the shrink is real).
   - Shrink the window to exact fit: `signed[lc_off + 12..lc_off + 16].copy_from_slice(&(declared as u32).to_le_bytes());` (little-endian fixture; the load command stores native-endian fields, precedent at writer.rs:2151-2152).
   - The load-command area is inside the hashed code region (page 0 covers header + load commands), so the shrink invalidates the stored page-0 hashes: patch code slot 0 in BOTH CodeDirectories (`entry_offset` with `CSSLOT_CODEDIRECTORY` / `CSSLOT_ALTERNATE_CODEDIRECTORIES`; hash offset = u32 at cd+16, hash size = byte at cd+36, hash type = byte at cd+37, code slot 0 at `cd + hash_offset` — special slots sit below, see `bind_special_slot`) with `digest(bytes[0 .. 1 << page_size_log2])` under each CD's own hash type, computed AFTER the datasize shrink. Fixture surgery only — this mirrors the existing `bind_special_slot` precedent; it must not touch CD-validation code. Sanity-assert `page_size == 4096` and `hash_size` matching the hash type.
   - Assert: `report.is_valid()` with errors footer and `error_count() == 0`.
   - Fallback (controller-ruled, only if a binding check beyond page hashes makes full validity unreachable by fixture surgery): assert that no error contains `nonzero bytes past the declared SuperBlob length`, keep the `declared < datasize` precondition, and document which checks fired in the task report.

Follow the file's assertion idiom: every negative assertion carries a footer that prints the actual errors (e.g. `"{:?}", slice.errors`).

- [ ] **Step 2: Run the tests and record the fail-before state**

Run: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-core --lib window_tail`
(`window_tail` is unique to the four new test names — verified against the current source)
Expected: tests 1–2 FAIL (expected error message absent — `error_count()` is 0), tests 3–4 PASS (they pin current acceptance). Paste both outputs into the report; if 3–4 fail, stop and report (baseline assumption broken).

- [ ] **Step 3: Scoped gates**

Run: `cargo fmt --all -- --check` and `cargo clippy -p zsign-core --all-targets -- -D warnings`.
Expected: both clean (tests must compile warning-free even while red).

- [ ] **Step 4: Controller commits**

Commit message: `test(macho): cover signature window tail strictness`

---

### Task 2: Implement the window-tail check

**Files:**
- Modify: `crates/zsign-core/src/macho/verify.rs` — `verify_slice`, immediately after the `parse_superblob` `match` arm (:157-165) and before the `let Some(primary) = superblob.code_directory` check (:167-172).

**Interfaces:**
- Consumes: the `sig: &[u8]` window already validated by `parse_superblob` (`sig.len() >= 12`, `declared <= sig.len()` — so both header and tail slices below are in bounds); Task 1's four tests.
- Produces: at most one additional `SliceVerifyReport::errors` entry with the exact message
  `code signature window contains {n} nonzero bytes past the declared SuperBlob length`.

- [ ] **Step 1: Confirm fail-before**

Run: `TMPDIR=$PWD/target/tmp cargo test -p zsign-core --lib window_tail_is_rejected`
Expected: both FAIL (same reason as Task 1, Step 2). Record output.

- [ ] **Step 2: Implement the check**

Insert after the `parse_superblob` match arm:

```rust
// `parse_superblob` validated the header (sig.len() >= 12, declared <=
// sig.len()), so both slices below are in bounds. The declared length is
// authoritative: the rest of the LC window is empty by contract, so a
// nonzero tail is stale or smuggled data (e.g. a planted second SuperBlob).
let declared = u32::from_be_bytes(sig[4..8].try_into().unwrap()) as usize;
let nonzero = sig[declared..].iter().filter(|&&b| b != 0).count();
if nonzero > 0 {
    report.errors.push(format!(
        "code signature window contains {nonzero} nonzero bytes past the declared SuperBlob length"
    ));
}
```

Notes: `.unwrap()` mirrors the identical header read in `parse_superblob`
(`codesign/verify.rs:110`) and cannot fire — `Ok` guarantees the bounds. The
error is pushed, not returned; downstream checks still run so a valid-but-tailed
binary reports exactly one error. Do not reorder or edit any neighbouring
check (no-LC, bounds, parse, primary-CD, coverage, codeLimit regions).

- [ ] **Step 3: Run the four task tests**

Run: `TMPDIR=$PWD/target/tmp cargo test -p zsign-core --lib window_tail`
Expected: all 4 PASS. Paste output.

- [ ] **Step 4: Run the full crate suite**

Run: `TMPDIR=$PWD/target/tmp cargo test -p zsign-core`
Expected: all pass — in particular the existing sign→verify round-trips
(`verify_signed_binary_round_trip`, `verify_signed_32bit_armv7_round_trip`,
`verify_signed_fat_armv7_arm64_round_trip`, ad-hoc validity tests) prove the
zero tail does not false-positive. Paste the summary line.

- [ ] **Step 5: Scoped gates**

Run: `cargo fmt --all -- --check` and `cargo clippy -p zsign-core --all-targets -- -D warnings`
Expected: both clean.

- [ ] **Step 6: Controller commits**

Commit message: `fix(macho): reject nonzero data past declared superblob length`
