# Hostile `__LINKEDIT` vmsize Overflow Guard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development (recommended) with dispatching-parallel-agents for independent tasks to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the two unchecked `align_to(vmsize as usize + size_increase, PAGE_SIZE)` computations in the realloc path with checked conversion/add/alignment that returns `Error::MachO("__LINKEDIT vmsize extension overflows")` instead of panicking.

**Architecture:** A private `align_to_checked` helper beside the public `align_to` in `crates/zsign-core/src/macho/writer.rs`, plus one checked expression at each of the two cited call sites. Nothing else changes.

**Tech Stack:** Rust, goblin, in-repo Mach-O byte fixtures, `cargo test -p zsign-core`.

**Spec:** `docs/superpowers/specs/2026-10-07-linkedit-vmsize-overflow-design.md`

## Global Constraints

- Zero-warning gate: `cargo fmt --all -- --check` and `cargo clippy --workspace --all-targets -- -D warnings` must pass.
- Tests run with `TMPDIR=$PWD/target/tmp cargo test --workspace` (`mkdir -p target/tmp` first).
- No ticket IDs anywhere in code, comments, docs, or commit messages.
- Only files named by a task may be touched. Deferred files (`crates/zsign/**`, `crates/zsign-core/src/crypto/**`, `macho/verify.rs`, `codesign/verify.rs`, `crates/zsign-cli/**`, `examples/**`) are off limits.
- The `size_increase = required - data.len()` lines and their operands (`writer.rs:205`, `:1343`) are NOT touched — the wrong-realloc-delta gap is a separate ticket.
- `align_to`'s signature and body stay byte-identical (public, re-exported). `write_linkedit_sizes`, the 0x4000 floor (`:1088`), seg_fileoff extents, FAT padding, and datasize echo are NOT touched.
- Non-overflowing values keep today's passthrough behavior — no clamping, no magnitude threshold.
- Error style: static `&str` `Error::MachO(...)` via `.ok_or_else(...)`, matching the guards lines above each site.
- Conventional commits: imperative, lowercase, no trailing period, no ticket IDs.

## Review Focus

1. `u64::MAX` vmsize through the goblin realloc path must be a typed error, not a panic — pinned by `test_realloc_rejects_hostile_linkedit_vmsize` (Task 1).
2. Same through the metadata realloc path (the one the signer actually calls) — pinned by `test_realloc_metadata_rejects_hostile_linkedit_vmsize` (Task 1).
3. End-to-end `sign_macho_adhoc` must return `Err`, not abort the CLI/wasm surface — pinned by `test_sign_rejects_hostile_linkedit_vmsize` (Task 1).
4. No over-eager rejection: a large-but-fitting vmsize (`1 << 63`) still reallocates and the written value is not clamped — pinned by `test_realloc_keeps_large_nonoverflowing_linkedit_vmsize` (Task 1; passes before and after).
5. The coupled delta and alignment machinery stay untouched: existing realloc/capacity/alignment tests (`test_realloc_writes_aligned_dataoff_for_odd_code_length`, `test_align_to`, `test_calculate_signature_space_non_aligned`, `test_prepare_rejects_hostile_linkedit_fileoff`) must stay green (gate in Task 2).

---

### Task 1: Regression tests for the vmsize overflow guard

**Files:**
- Test: `crates/zsign-core/src/macho/writer.rs` (inline `mod tests`)

**Interfaces:**
- Consumes: `crate::macho::fixtures::make_minimal_macho`, `crate::macho::MachOFile::parse`, `crate::macho::sign_macho_adhoc`, and the module-local `realloc_code_sign_space` / `realloc_code_sign_space_with_metadata` — all already used by neighbouring tests.
- Produces: four tests named exactly as below — Task 2 greens the first three; the reviewer checks them by name.

- [ ] **Step 1: Write the four tests**

In `crates/zsign-core/src/macho/writer.rs`, inside the existing `mod tests`, append:

```rust
#[test]
fn test_realloc_rejects_hostile_linkedit_vmsize() {
    let mut data = crate::macho::fixtures::make_minimal_macho();
    // __LINKEDIT LC at 184; segment_command_64.vmsize field at +32.
    data[216..224].copy_from_slice(&u64::MAX.to_le_bytes());
    let result = std::panic::catch_unwind(|| realloc_code_sign_space(&data, data.len()));
    match result {
        Ok(inner) => {
            let err = inner
                .expect_err("hostile __LINKEDIT vmsize must be rejected, not accepted");
            assert!(err.to_string().contains("__LINKEDIT vmsize"), "{err}");
        }
        Err(_) => panic!(
            "realloc must not panic on a hostile __LINKEDIT vmsize (u64 add overflow)"
        ),
    }
}

#[test]
fn test_realloc_metadata_rejects_hostile_linkedit_vmsize() {
    let mut data = crate::macho::fixtures::make_minimal_macho();
    data[216..224].copy_from_slice(&u64::MAX.to_le_bytes());
    let macho = crate::macho::MachOFile::parse(data.clone()).expect("patched fixture must parse");
    let meta = macho.slices()[0].metadata.clone();
    let result = std::panic::catch_unwind(|| {
        realloc_code_sign_space_with_metadata(&data, &meta, data.len(), 0x1000)
    });
    match result {
        Ok(inner) => {
            let err = inner
                .expect_err("hostile __LINKEDIT vmsize must be rejected, not accepted");
            assert!(err.to_string().contains("__LINKEDIT vmsize"), "{err}");
        }
        Err(_) => panic!(
            "metadata realloc must not panic on a hostile __LINKEDIT vmsize (u64 add overflow)"
        ),
    }
}

#[test]
fn test_sign_rejects_hostile_linkedit_vmsize() {
    let mut data = crate::macho::fixtures::make_minimal_macho();
    data[216..224].copy_from_slice(&u64::MAX.to_le_bytes());
    let result = std::panic::catch_unwind(|| {
        let macho =
            crate::macho::MachOFile::parse(data.clone()).expect("patched fixture must parse");
        crate::macho::sign_macho_adhoc(&macho, "com.example.linkedit", None, None, None, false)
    });
    match result {
        Ok(inner) => {
            let err = inner
                .expect_err("hostile __LINKEDIT vmsize must be rejected, not accepted");
            assert!(err.to_string().contains("__LINKEDIT vmsize"), "{err}");
        }
        Err(_) => panic!(
            "signing must not panic on a hostile __LINKEDIT vmsize (u64 add overflow)"
        ),
    }
}

#[test]
fn test_realloc_keeps_large_nonoverflowing_linkedit_vmsize() {
    let mut data = crate::macho::fixtures::make_minimal_macho();
    const HUGE: u64 = 1 << 63;
    data[216..224].copy_from_slice(&HUGE.to_le_bytes());
    let out = realloc_code_sign_space(&data, data.len())
        .expect("large-but-non-overflowing vmsize must still be accepted");
    let written = u64::from_le_bytes(out[216..224].try_into().unwrap());
    assert!(
        written >= HUGE,
        "vmsize passthrough must not clamp: got {written:#x}"
    );
}
```

- [ ] **Step 2: Run the tests to verify the red state**

Run: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-core writer`
Expected: the three hostile-vmsize tests FAIL (the `catch_unwind` returns `Err(_)` — the overflow panic — tripping the `must not panic` arm; on a hypothetical release build the wrap path instead fails the `expect_err`); `test_realloc_keeps_large_nonoverflowing_linkedit_vmsize` PASSES (it pins the passthrough policy and is expected green both before and after). All pre-existing writer tests stay green.

---

### Task 2: Checked vmsize extension in both realloc variants

**Files:**
- Modify: `crates/zsign-core/src/macho/writer.rs`

**Interfaces:**
- Consumes: Task 1's tests (already written; this task greens the three hostile ones).
- Produces: private `fn align_to_checked(value: usize, alignment: usize) -> Option<usize>` beside `align_to`, used by both realloc variants. Return types of the public functions are unchanged.

- [ ] **Step 1: Add the checked-alignment helper**

In `crates/zsign-core/src/macho/writer.rs`, immediately after the existing `pub fn align_to` definition, add:

```rust
/// [`align_to`] with overflow checking: `None` when the rounding step
/// `value + alignment - 1` would overflow `usize`. `alignment` must be a
/// power of two, as [`align_to`] requires.
fn align_to_checked(value: usize, alignment: usize) -> Option<usize> {
    value
        .checked_add(alignment - 1)
        .map(|v| v & !(alignment - 1))
}
```

- [ ] **Step 2: Guard the goblin realloc variant**

In `realloc_code_sign_space_single`, replace exactly

```rust
        let new_vmsize = align_to(old_vmsize as usize + size_increase, PAGE_SIZE) as u64;
```

with

```rust
        let new_vmsize = usize::try_from(old_vmsize)
            .ok()
            .and_then(|v| v.checked_add(size_increase))
            .and_then(|v| align_to_checked(v, PAGE_SIZE))
            .ok_or_else(|| Error::MachO("__LINKEDIT vmsize extension overflows".into()))?
            as u64;
```

Leave the `size_increase` line above it untouched.

- [ ] **Step 3: Guard the metadata realloc variant**

In `realloc_code_sign_space_with_metadata`, replace exactly

```rust
        let new_vmsize = align_to(vmsize as usize + size_increase, PAGE_SIZE) as u64;
```

with the same checked expression, using `vmsize` instead of `old_vmsize`
(`usize::try_from(vmsize) ... as u64;`). Leave the `size_increase` line
untouched.

- [ ] **Step 4: Update the error documentation**

In the `# Errors` doc list of `realloc_code_sign_space_with_metadata`
(the bullets ending with "The signature reserve end overflows `usize`"),
append a bullet for the new rejection: `- The \`__LINKEDIT\` vmsize
extension overflows \`usize\``. Apply the same bullet to any `# Errors`
list on the goblin `realloc_code_sign_space` wrapper if one exists.
Doc comments only.

- [ ] **Step 5: Run the scoped tests to verify they pass**

Run: `TMPDIR=$PWD/target/tmp cargo test -p zsign-core writer`
Expected: PASS — all four new tests green (including the passthrough pin) and every pre-existing writer test unchanged-green.

- [ ] **Step 6: Run the full workspace gate**

Run:
```
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
TMPDIR=$PWD/target/tmp cargo test --workspace
```
Expected: fmt clean, clippy zero warnings, all suites pass (including facade/CLI/wasm — no deferred file may need edits; if one does, STOP and report instead of editing it).

- [ ] **Step 7: Commit**

Controller commits (implementers never commit):

```
git add crates/zsign-core/src/macho/writer.rs
git commit -m "fix(macho): reject overflowing linkedit vmsize extension"
```
