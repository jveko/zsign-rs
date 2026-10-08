# FAT align cap + offset cross-check + output guard — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development with dispatching-parallel-agents. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Close the FAT reassembly memory-exhaustion amplifier in `embed_fat_from_signed_slices` by capping the align exponent at 15, cross-checking the input arch offset against `2^align`, and bounding `total_size` against input size before allocating.

**Architecture:** All changes live in `crates/zsign-core/src/macho/writer.rs`. Guard 1 (exponent cap ≤ 15) and guard 2 (input `offset % 2^align == 0`) go inside the existing per-arch cursor loop; guard 3 threads `input_len: usize` into the private `embed_fat_from_signed_slices` from its three call sites and rejects `total_size` above `input_len + signed_total + n * (1 << 15)` before `vec![0u8; total_size]`.

**Tech Stack:** Rust, edition 2021, inline `#[cfg(test)]` tests, `fixtures::make_fat_macho`.

**Spec:** `docs/superpowers/specs/2026-10-08-fat-align-cap-design.md`

## Global Constraints

- Zero-warning gate: `cargo fmt --all -- --check` + `cargo clippy --workspace --all-targets -- -D warnings`.
- Tests: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test --workspace` (scoped runs during flight).
- No ticket IDs in code, comments, docs, or commit messages.
- Do NOT edit parser.rs, code_directory.rs, verify.rs, crypto/**, crates/zsign/**, crates/zsign-cli/**, examples/**, README.md.
- Do not remove or bypass the wave-1 `checked_add` chains at writer.rs:506-509.
- Error style: `Error::MachO(format!(...))` naming the offending value (file convention).
- Tests match surrounding FAT-test idiom: `expect_err("...")` + `err.to_string().contains("...")` (writer.rs:2526-2537); hostile fields patched at table bytes `8 + i*20` (idiom writer.rs:2707-2712).

## Review Focus

- Exponent boundary: align 15 must remain accepted, align 16 must be rejected — the cap is `> 15`, not `>= 15`.
- Offset cross-check must run on the *input* arch offset (parsed container), not the recomputed cursor offsets (which are aligned by construction) — a test that patches the input offset proves which one is checked.
- `total_size` guard must be evaluated BEFORE `vec![0u8; total_size]` (writer.rs:521) — no allocation on the failing path.
- Existing behaviour tests (writer.rs:2611-2672 declared-exponent layout; :2504-2757 FAT suite) must stay green — guards must not reject well-formed containers.
- The three call sites of `embed_fat_from_signed_slices` must all pass the correct `input_len` (same `data` they parsed) — migrating every caller, no default/0 passthrough.

---

### Task 1: Exponent cap + input offset cross-check (TDD)

**Files:**
- Modify: `crates/zsign-core/src/macho/writer.rs` (fn `embed_fat_from_signed_slices`, loop at :498-518; tests appended at the end of the FAT region, after :2869 — not mid-suite)
- Test: same file, inline `#[cfg(test)]` tests

**Interfaces:**
- Produces: guards inside the existing loop; no signature change (Task 2 adds the parameter).

- [ ] **Step 1: Write failing tests**
  In the FAT test region of writer.rs's test mod, add:
  - `test_embed_fat_rejects_align_exponent_above_15`: build via `fixtures::make_fat_macho(&slices, &[16])` (or clone a 2-slice fixture and patch the align field at table byte `8 + i*20 + 16` to `16`), call `embed_signature_fat(&data, &signed)`; expect `Err` containing `"align exponent"` and `"15"`. Also assert align 31 (the 2^31 amplifier) is rejected with the same guard.
  - `test_embed_fat_accepts_align_exponent_15`: `make_fat_macho(&slices, &[15, 12])` reassembles `Ok` (boundary stays open; duplicates the accepted side of the boundary — the existing :2611 test already covers 15/12 layout, this one pins only acceptance of exactly 15 if not already covered).
- [ ] **Step 2: Run tests, expect failure**
  `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-core embed_fat_rejects_align` → FAIL (currently Ok for align 16/31 only blocked at ≥32... note: align 31 currently passes the ≥32 guard and would allocate ~2^31; if that OOMs the test machine, use align 16 as the failing-before case and add align 31 only after the cap lands).
- [ ] **Step 3: Implement the cap**
  In the loop at writer.rs:499, replace `if arch.align >= 32` with `if arch.align > 15`, message: `"FAT arch align exponent {} exceeds the maximum supported exponent 15"`. Keep the rest of the chain untouched.
- [ ] **Step 4: Implement the offset cross-check**
  Immediately after the cap, reject `arch.offset as usize % (1usize << arch.align) != 0` with `"FAT slice {i}: offset {} is not aligned to 2^{}"`.
  Add failing-before test `test_embed_fat_rejects_unaligned_input_offset`: patch a well-formed fixture arch's offset field (`8 + i*20 + 8`, big-endian) to a non-multiple of `2^align` (e.g. offset+1), **and update the corresponding `SignedSlice`'s `offset` (and any other identity fields) to match the patched arch** so the identity check at writer.rs:469 passes and the new alignment check is what fires — keep the patched range inside the file and disjoint so `validate_fat_arches` (:413-438, runs before the loop) does not fire first. Expect `Err` containing `"not aligned"`. Guard order: the exponent cap check must run before the cross-check inside the loop.
- [ ] **Step 5: Run tests**
  `TMPDIR=$PWD/target/tmp cargo test -p zsign-core writer` → all FAT tests green.

### Task 2: total_size guard vs input_len (TDD)

**Files:**
- Modify: `crates/zsign-core/src/macho/writer.rs` (fn signature + 3 call sites :357, :404, :1004; guard before :521; tests appended at the end of the FAT region, after :2869 — not mid-suite)

**Interfaces:**
- Consumes: Task 1 guards.
- Produces: `embed_fat_from_signed_slices(fat: &MultiArch, signed_slices: &[SignedSlice], input_len: usize)`.

- [ ] **Step 1: Write the invariant-pin test**
  `test_embed_fat_output_bounded_by_input`: for a successful reassembly (align 15/12 fixture), assert `output.len() <= input_len + signed_total + arches * (1 << 15)` — pins the invariant the guard enforces. This is an **invariant-pin**: it passes before and after the guard (it constrains a successful output, which already satisfies the bound under guards 1+2 — no constructible input trips guard 3 once the cap and cross-check are in place, by design). The failing-before/passing-after coverage for this item is the cap and cross-check tests of Task 1.
- [ ] **Step 2: Thread `input_len`**
  Add `input_len: usize` parameter; update all three call sites with `data.len()` (`embed_signature` :357, `embed_signature_fat` :404, `inject_dylib_command` :1004). Grep for any other caller before finishing (`embed_fat_from_signed_slices` must have zero remaining 2-arg call sites).
- [ ] **Step 3: Implement the guard**
  After the cursor loop (`let total_size = cursor;` :520) and BEFORE `vec![0u8; total_size]` (:521):
  compute `signed_total = slice_data_vec.iter().map(|s| s.len()).sum::<usize>()`;
  `let max_total = input_len.checked_add(signed_total).and_then(|v| v.checked_add(arches.len().checked_mul(1 << 15)?)).ok_or_else(|| Error::MachO("FAT output size bound overflows".into()))?;`
  `if total_size > max_total { return Err(Error::MachO(format!("FAT output size {total_size} exceeds bound {max_total} for input of {input_len} bytes"))); }`
- [ ] **Step 4: Run scoped gate**
  `TMPDIR=$PWD/target/tmp cargo test -p zsign-core` then `cargo fmt --all -- --check` && `cargo clippy --workspace --all-targets -- -D warnings`.

### Task 3: Full gate + commit (controller-owned)

- [ ] `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test --workspace`
- [ ] `cargo fmt --all -- --check` and `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] Controller commits: `fix(macho): cap fat align exponent and bound reassembly output` (no ticket ID).
