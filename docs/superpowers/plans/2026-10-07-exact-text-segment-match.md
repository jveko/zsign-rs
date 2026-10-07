# Exact `__TEXT` Segment Selection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development (recommended) with dispatching-parallel-agents for independent tasks to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `parse_single` capture the executable segment only when the 16-byte segment name equals `__TEXT`, so a `__TEXT_EXEC` (or any `__TEXT*`) segment can no longer overwrite `ArchSlice::text_segment_*` and the emitted `execSegBase`/`execSegLimit`.

**Architecture:** Two width arms in `crates/zsign-core/src/macho/parser.rs` switch from `segname.starts_with(b"__TEXT")` to equality against one module-level `[u8; 16]` constant. Regression fixtures are derived from the existing byte-patch fixture pattern in `crates/zsign-core/src/macho/fixtures.rs`.

**Tech Stack:** Rust, goblin 0.10.7 (`segname: [u8; 16]`), in-repo Mach-O byte fixtures, `cargo test -p zsign-core`.

**Spec:** `docs/superpowers/specs/2026-10-07-exact-text-segment-match-design.md`

## Global Constraints

- Zero-warning gate: `cargo fmt --all -- --check` and `cargo clippy --workspace --all-targets -- -D warnings` must pass.
- Tests run with `TMPDIR=$PWD/target/tmp cargo test --workspace` (`mkdir -p target/tmp` first; `/tmp` is a small tmpfs).
- No ticket IDs anywhere in code, comments, docs, or commit messages.
- Only files named by a task may be touched; deferred files (`crates/zsign/**`, `crates/zsign-core/src/crypto/**`, `macho/verify.rs`, `codesign/verify.rs`, `crates/zsign-cli/**`) are off limits.
- The `__LINKEDIT` prefix sites stay unchanged — this change is `__TEXT` selection only.
- Value semantics unchanged: `execSegBase` = `__TEXT.fileoff`, `execSegLimit` = `__TEXT.filesize`.
- Conventional commits: imperative, lowercase, no trailing period, no ticket IDs.

## Review Focus

1. 64-bit arm last-match-wins overwrite by a trailing `__TEXT_EXEC` — pinned by `test_text_segment_selection_ignores_text_exec` (Task 1).
2. 32-bit arm same overwrite — pinned by `test_text_segment_selection_ignores_text_exec_32` (Task 1).
3. The reported defect itself: emitted `execSegBase`/`execSegLimit` naming the wrong segment — pinned by `test_exec_seg_fields_ignore_text_exec` (Task 1).
4. Exact-match strictness must not break ordinary `__TEXT` images — existing `test_text_segment_fileoff_is_exposed`, `test_text_segment_size_is_file_backed_extent`, `test_exec_seg_limit_written_from_filesize` must stay green (gate in Task 2).
5. FAT slices share `parse_single`; per-slice exec-seg assertions in `signer.rs` (`base == text_segment_fileoff`, `limit == text_segment_size`) must stay green (gate in Task 2).

---

### Task 1: Regression fixtures and failing tests

**Files:**
- Modify: `crates/zsign-core/src/macho/fixtures.rs` (append two builders after `make_minimal_dylib` / after `make_minimal_macho_32`)
- Test: `crates/zsign-core/src/macho/parser.rs` (inline `mod tests`)

**Interfaces:**
- Consumes: existing `make_minimal_macho()` and `make_minimal_macho_32()` byte builders; `MachOFile::parse`, `macho.slices()`; `crate::macho::sign_macho_adhoc`; `crate::codesign::verify::parse_superblob` (all already used by neighbouring tests).
- Produces: `pub fn make_minimal_macho_text_exec() -> Vec<u8>` and `pub fn make_minimal_macho_32_text_exec() -> Vec<u8>` — Task 2 does not consume them, but later tasks and the reviewer rely on their exact names.

- [ ] **Step 1: Add the 64-bit `__TEXT_EXEC` fixture**

In `crates/zsign-core/src/macho/fixtures.rs`, after `make_minimal_dylib`, add:

```rust
/// [`make_minimal_macho`] with an extra `LC_SEGMENT_64 "__TEXT_EXEC"`
/// command inserted after `__TEXT`, mirroring ld64's `-text_exec`
/// ordering. Its vmaddr/fileoff/filesize deliberately differ from
/// `__TEXT`'s, so a prefix-based capture of the executable segment is
/// observable in tests.
pub fn make_minimal_macho_text_exec() -> Vec<u8> {
    let mut b = make_minimal_macho();
    // mach_header_64: ncmds at 16..20, sizeofcmds at 20..24.
    let ncmds = u32::from_le_bytes(b[16..20].try_into().unwrap());
    b[16..20].copy_from_slice(&(ncmds + 1).to_le_bytes());
    let sizeofcmds = u32::from_le_bytes(b[20..24].try_into().unwrap());
    b[20..24].copy_from_slice(&(sizeofcmds + 72).to_le_bytes());

    let mut cmd = Vec::new();
    cmd.extend_from_slice(&0x19u32.to_le_bytes()); // LC_SEGMENT_64
    cmd.extend_from_slice(&72u32.to_le_bytes()); // cmdsize
    let mut segname = [0u8; 16];
    segname[..11].copy_from_slice(b"__TEXT_EXEC");
    cmd.extend_from_slice(&segname);
    cmd.extend_from_slice(&0x1_0000_1000u64.to_le_bytes()); // vmaddr
    cmd.extend_from_slice(&0x400u64.to_le_bytes()); // vmsize
    cmd.extend_from_slice(&0x1400u64.to_le_bytes()); // fileoff
    cmd.extend_from_slice(&0x400u64.to_le_bytes()); // filesize
    cmd.extend_from_slice(&5u32.to_le_bytes()); // maxprot (r-x)
    cmd.extend_from_slice(&5u32.to_le_bytes()); // initprot (r-x)
    cmd.extend_from_slice(&0u32.to_le_bytes()); // nsects
    cmd.extend_from_slice(&0u32.to_le_bytes()); // flags

    // After __TEXT: 32-byte header + 152-byte __TEXT command.
    b.splice(32 + 152..32 + 152, cmd);
    b
}
```

- [ ] **Step 2: Add the 32-bit `__TEXT_EXEC` fixture**

In the same file, after `make_minimal_macho_32`, add:

```rust
/// [`make_minimal_macho_32`] with an extra `LC_SEGMENT "__TEXT_EXEC"`
/// command inserted after `__TEXT`, mirroring ld64's `-text_exec`
/// ordering. Its vmaddr/fileoff/filesize differ from `__TEXT`'s so a
/// prefix-based capture of the executable segment is observable.
pub fn make_minimal_macho_32_text_exec() -> Vec<u8> {
    let mut b = make_minimal_macho_32();
    // mach_header: ncmds at 16..20, sizeofcmds at 20..24.
    let ncmds = u32::from_le_bytes(b[16..20].try_into().unwrap());
    b[16..20].copy_from_slice(&(ncmds + 1).to_le_bytes());
    let sizeofcmds = u32::from_le_bytes(b[20..24].try_into().unwrap());
    b[20..24].copy_from_slice(&(sizeofcmds + 56).to_le_bytes());

    let mut cmd = Vec::new();
    cmd.extend_from_slice(&0x01u32.to_le_bytes()); // LC_SEGMENT
    cmd.extend_from_slice(&56u32.to_le_bytes()); // cmdsize
    let mut segname = [0u8; 16];
    segname[..11].copy_from_slice(b"__TEXT_EXEC");
    cmd.extend_from_slice(&segname);
    cmd.extend_from_slice(&0x3000u32.to_le_bytes()); // vmaddr
    cmd.extend_from_slice(&0x400u32.to_le_bytes()); // vmsize
    cmd.extend_from_slice(&0x1400u32.to_le_bytes()); // fileoff
    cmd.extend_from_slice(&0x400u32.to_le_bytes()); // filesize
    cmd.extend_from_slice(&5u32.to_le_bytes()); // maxprot (r-x)
    cmd.extend_from_slice(&5u32.to_le_bytes()); // initprot (r-x)
    cmd.extend_from_slice(&0u32.to_le_bytes()); // nsects
    cmd.extend_from_slice(&0u32.to_le_bytes()); // flags

    // After __TEXT: 28-byte header + 124-byte __TEXT command.
    b.splice(28 + 124..28 + 124, cmd);
    b
}
```

- [ ] **Step 3: Write the three failing tests**

In `crates/zsign-core/src/macho/parser.rs`, inside the existing `mod tests`, append:

```rust
#[test]
fn test_text_segment_selection_ignores_text_exec() {
    let data = crate::macho::fixtures::make_minimal_macho_text_exec();
    let macho = MachOFile::parse(data).expect("fixture must parse");
    let slice = &macho.slices()[0];
    assert_eq!(
        slice.text_segment_fileoff, 0x1000,
        "execSegBase input must come from the exact __TEXT segment, not a __TEXT* prefix match"
    );
    assert_eq!(
        slice.text_segment_size, 0x1000,
        "execSegLimit input must come from the exact __TEXT segment, not a __TEXT* prefix match"
    );
    assert_eq!(
        slice.text_segment_base, 0x1_0000_0000,
        "vmaddr must come from the exact __TEXT segment, not a __TEXT* prefix match"
    );
}

#[test]
fn test_text_segment_selection_ignores_text_exec_32() {
    let data = crate::macho::fixtures::make_minimal_macho_32_text_exec();
    let macho = MachOFile::parse(data).expect("fixture must parse");
    let slice = &macho.slices()[0];
    assert!(!slice.is_64, "armv7 fixture must be 32-bit");
    assert_eq!(
        slice.text_segment_fileoff, 0x1000,
        "32-bit execSegBase input must come from the exact __TEXT segment"
    );
    assert_eq!(
        slice.text_segment_size, 0x1000,
        "32-bit execSegLimit input must come from the exact __TEXT segment"
    );
    assert_eq!(
        slice.text_segment_base, 0x1000,
        "32-bit vmaddr must come from the exact __TEXT segment"
    );
}

#[test]
fn test_exec_seg_fields_ignore_text_exec() {
    let data = crate::macho::fixtures::make_minimal_macho_text_exec();
    let macho = MachOFile::parse(data).expect("fixture must parse");
    let signed = crate::macho::sign_macho_adhoc(
        &macho, "com.example.textexec", None, None, None, false,
    )
    .expect("sign must succeed");
    let reparsed = MachOFile::parse(signed.clone()).expect("signed output parses");
    let slice = &reparsed.slices()[0];
    let off = slice.code_sig_offset.expect("signed") as usize;
    let size = slice.code_sig_size.expect("signed") as usize;
    let superblob = crate::codesign::verify::parse_superblob(&signed[off..off + size])
        .expect("embedded superblob parses");
    let cd = superblob
        .code_directory
        .as_ref()
        .expect("code directory present");
    let raw = cd.raw();
    let exec_seg_base = u64::from_be_bytes(raw[64..72].try_into().unwrap());
    let exec_seg_limit = u64::from_be_bytes(raw[72..80].try_into().unwrap());
    assert_eq!(
        exec_seg_base, 0x1000,
        "execSegBase must be __TEXT.fileoff, not __TEXT_EXEC's"
    );
    assert_eq!(
        exec_seg_limit, 0x1000,
        "execSegLimit must be __TEXT.filesize, not __TEXT_EXEC's"
    );
}
```

- [ ] **Step 4: Run the tests to verify they fail**

Run: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-core macho::parser`
Expected: FAIL — the three new tests fail on assertion (prefix capture yields `text_segment_fileoff == 0x1400`, `text_segment_size == 0x400`, `text_segment_base == 0x1_0000_1000` in the 64-bit test; the 32-bit test gets `0x1400`/`0x400`/`0x3000`; the CD test gets `execSegBase == 0x1400`, `execSegLimit == 0x400`). All pre-existing tests in the filter pass.

---

### Task 2: Exact 16-byte segment-name match

**Files:**
- Modify: `crates/zsign-core/src/macho/parser.rs` (constant + two arm conditions)

**Interfaces:**
- Consumes: Task 1's fixtures/tests (already written; this task greens them).
- Produces: module-level `const TEXT_SEGMENT_NAME: [u8; 16]` in `parser.rs` — private to the module, referenced by both width arms.

- [ ] **Step 1: Add the constant and switch both arms**

In `crates/zsign-core/src/macho/parser.rs`, immediately above `fn parse_single`, add:

```rust
/// `__TEXT` as it appears in a 16-byte segment-name field: 6 name
/// bytes followed by 10 NULs. Compared for exact equality, matching
/// Apple's `findSegment("__TEXT")`.
const TEXT_SEGMENT_NAME: [u8; 16] = *b"__TEXT\0\0\0\0\0\0\0\0\0\0";
```

Then replace BOTH occurrences of

```rust
if seg.segname.starts_with(b"__TEXT") {
```

(the 64-bit `CommandVariant::Segment64` arm and the 32-bit `CommandVariant::Segment32` arm) with

```rust
if seg.segname == TEXT_SEGMENT_NAME {
```

The `__LINKEDIT` `starts_with` conditions in the same arms are NOT touched.

- [ ] **Step 2: Run the scoped tests to verify they pass**

Run: `TMPDIR=$PWD/target/tmp cargo test -p zsign-core macho::parser`
Expected: PASS — all tests in the filter, including the three new ones.

- [ ] **Step 3: Run the full workspace gate**

Run:
```
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
TMPDIR=$PWD/target/tmp cargo test --workspace
```
Expected: fmt reports no diffs; clippy reports zero warnings; all workspace tests pass (existing `test_text_segment_fileoff_is_exposed`, `test_exec_seg_limit_written_from_filesize`, and the signer FAT exec-seg assertions stay green).

- [ ] **Step 4: Commit**

Controller commits (implementers never commit):

```
git add crates/zsign-core/src/macho/fixtures.rs crates/zsign-core/src/macho/parser.rs
git commit -m "fix(macho): select text segment by exact name"
```
