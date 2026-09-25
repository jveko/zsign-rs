# ZSN-32 Mach-O Writer Mutation Correctness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: subagent-driven-development with dispatching-parallel-agents. Tasks are strictly sequential (every task touches `writer.rs`/`parser.rs`), dispatched one at a time: Tester-red → implementer-green → scoped gate → controller commit. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Fix six writer/parser mutation-correctness defects (insertion bound, endian detection, signature-space early return, `__LINKEDIT` shrink, unaligned `dataoff`, `execSegLimit`) with regression tests that fail before the fix.

**Architecture:** Two writer stacks (live metadata stack used by `signer.rs`, goblin-reparse stack used by public `embed_signature`/`realloc_code_sign_space`/`prepare_code_for_signing`) share byte-level helpers in `writer.rs`; `parser.rs` produces `MachOMetadata`/`ArchSlice`. All fixes stay inside `crates/zsign-core/src/macho/{writer.rs, parser.rs, fixtures.rs}`; `signer.rs` is called but never edited.

**Tech Stack:** Rust 2021, goblin 0.10.7, inline `#[cfg(test)]` tests, in-memory fixtures (no tempfile).

**Gate (run after every task):**
```bash
mkdir -p .tmptmp && TMPDIR=$PWD/.tmptmp cargo test -p zsign-core macho -- --skip test_ipa_signing_is_deterministic
```
Expected: all tests green (41 baseline + new). Baseline is established before Task 1. Never run `cargo fmt`/`cargo clippy`/`hk`.

**Shared conventions for every task:** error strings via `Error::MachO(String)`; assertions carry reason messages; test names `test_*`; fixtures added to `fixtures.rs` as `pub(crate) fn`; ticket ID never appears in code comments; each task ends with the controller committing (conventional subject, e.g. `fix(macho): bound load-command insertion by first file-backed content (ZSN-32)`).

---

### Task 1 — Insertion bound from first file-backed content

**Files:** Modify `crates/zsign-core/src/macho/writer.rs` (`find_first_segment_offset` 673-695, `inject_dylib_command` LC walk 567-612 + guard 617-626, `realloc_code_sign_space_single` guard 169-187, `realloc_code_sign_space_with_metadata` guard 927-939, `add_code_signature_command` guard 491-500 → unified form); Modify `crates/zsign-core/src/macho/parser.rs` (`parse_single` segment scan 245-256, fallback 294-298, `MachOMetadata.first_segment_offset` doc 61-62); Create fixtures in `crates/zsign-core/src/macho/fixtures.rs`; Tests in writer.rs + parser.rs test modules.

- [ ] **Step 1: Fixture**

Add to `fixtures.rs`:

```rust
/// Realistic two-segment arm64 Mach-O with `__TEXT.fileoff == 0` (the layout
/// produced by the linker) and a `__text` section inside `__TEXT`.
/// With `tight_gap`, the section starts only 8 bytes after the last load
/// command, i.e. there is no room to append a 16-byte load command.
pub(crate) fn make_text_fileoff0_macho(tight_gap: bool) -> Vec<u8> {
    let mut b = Vec::new();
    let mut u32w = |v: u32| b.extend_from_slice(&v.to_le_bytes());
    let mut u64w = |v: u64| b.extend_from_slice(&v.to_le_bytes());
    let mut name = |s: &str, len: usize| {
        let mut n = [0u8; 16];
        n[..s.len()].copy_from_slice(s.as_bytes());
        b.extend_from_slice(&n[..len]);
    };
    u32w(0xfeedfacf);            // MH_MAGIC_64
    u32w(0x0100_000c);           // CPU_TYPE_ARM64
    u32w(0);
    u32w(2);                     // MH_EXECUTE
    u32w(3);                     // ncmds
    u32w(152 + 72 + 24);         // sizeofcmds = 248
    u32w(1);                     // MH_NOUNDEFS
    u32w(0);
    // LC_SEGMENT_64 "__TEXT": fileoff 0, filesize 0x1000, one __text section
    u32w(0x19); u32w(152); name("__TEXT", 16);
    u64w(0x1_0000_0000); u64w(0x1000); u64w(0); u64w(0x1000);
    u32w(7); u32w(7); u32w(1); u32w(0);
    name("__text", 16); name("__TEXT", 16);
    u64w(0x1_0000_0000);         // addr
    u64w(4);                     // size
    u32w(if tight_gap { 32 + 248 + 8 } else { 0x400 }); // section file offset
    u32w(0); u32w(0); u32w(0);
    u32w(0x8000_0400);           // S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS
    u32w(0); u32w(0); u32w(0);
    // LC_SEGMENT_64 "__LINKEDIT": fileoff 0x1000, filesize 0 (signature home)
    u32w(0x19); u32w(72); name("__LINKEDIT", 16);
    u64w(0x1_0000_1000); u64w(0x1000); u64w(0x1000); u64w(0);
    u32w(1); u32w(1); u32w(0); u32w(0);
    // LC_BUILD_VERSION (24 bytes)
    u32w(0x32); u32w(24); u32w(1); u32w(0x000f_0000); u32w(0x000f_0000); u32w(0);
    assert_eq!(b.len(), 280, "load commands end at 32 + 248");
    b.resize(0x1000, 0);
    b.extend_from_slice(&[0x1f, 0x20, 0x03, 0xd5]); // __text at 0x1000
    b.resize(0x2000, 0);
    b
}
```

- [ ] **Step 2: Write failing tests** (append to writer.rs `mod tests` and parser.rs `mod tests`)

```rust
// writer.rs tests
#[test]
fn test_inject_dylib_refuses_section_clobber_with_fileoff0_text() {
    let data = crate::macho::fixtures::make_text_fileoff0_macho(true);
    let err = inject_dylib_command(&data, "@rpath/libtest.dylib", false)
        .expect_err("8-byte gap before the first section must refuse a new load command");
    let msg = match err { crate::Error::MachO(m) => m, other => panic!("expected MachO error, got {other:?}") };
    assert!(msg.contains("no space"), "message must explain missing room: {msg}");
}

#[test]
fn test_inject_dylib_keeps_section_bytes_with_fileoff0_text() {
    let data = crate::macho::fixtures::make_text_fileoff0_macho(false);
    let section_off = 0x400;
    let before = data[section_off..section_off + 4].to_vec();
    let output = inject_dylib_command(&data, "@rpath/libtest.dylib", false)
        .expect("comfortable gap must accept the new load command");
    assert_eq!(&output[section_off..section_off + 4], &before[..], "section bytes must be preserved");
    assert_eq!(read_u32(&output, 16, false).unwrap(), 4, "ncmds must grow");
}

#[test]
fn test_metadata_first_segment_offset_sees_fileoff0_sections() {
    let data = crate::macho::fixtures::make_text_fileoff0_macho(false);
    let macho = crate::macho::MachOFile::parse(data).expect("fixture must parse");
    let meta = &macho.slices()[0].metadata;
    assert_eq!(meta.first_segment_offset, 0x400,
        "insertion bound must be the first section offset, not a later segment fileoff");
}

#[test]
fn test_realloc_refuses_insertion_across_first_section() {
    let data = crate::macho::fixtures::make_text_fileoff0_macho(true);
    let macho = crate::macho::MachOFile::parse(data.clone()).expect("fixture must parse");
    let meta = macho.slices()[0].metadata.clone();
    let err = realloc_code_sign_space_with_metadata(&data, &meta, data.len())
        .expect_err("adding LC_CODE_SIGNATURE into an 8-byte gap must be refused");
    let msg = match err { crate::Error::MachO(m) => m, other => panic!("expected MachO error, got {other:?}") };
    assert!(msg.contains("No space"), "message must explain missing room: {msg}");
}

#[test]
fn test_sign_refuses_tight_fileoff0_fixture() {
    let data = crate::macho::fixtures::make_text_fileoff0_macho(true);
    let macho = crate::macho::MachOFile::parse(data).expect("fixture must parse");
    assert!(crate::macho::sign_macho_adhoc(&macho, "com.example.tight", None, None, None, false).is_err(),
        "signing must not overwrite __text by appending LC_CODE_SIGNATURE");
}
```

Run (expected FAIL — precisely: tests 1, 4, 5 get `Ok`/`is_err()==false` where they demand refusal, and test 3's `first_segment_offset` assert reads `0x1000` instead of `0x400`; test 2 is a success-path preservation check that passes pre-fix too and only pins behavior):
```bash
TMPDIR=$PWD/.tmptmp cargo test -p zsign-core macho -- --skip test_ipa_signing_is_deterministic
```

- [ ] **Step 3: Implement bound derivation**

`parser.rs` — replace the segment-fileoff scan/fallback inside `parse_single` (245-256, 294-298) with the union bound. After the existing `for lc in &macho.load_commands` loop, add section candidates inside the `Segment64`/`Segment32` arms:

```rust
// inside CommandVariant::Segment64(ref seg) arm, after __LINKEDIT capture:
if seg.fileoff > 0 && seg.filesize > 0 && (seg.fileoff as u64) < first_segment_offset {
    first_segment_offset = seg.fileoff as u64;
}
// segment sections: bound by first file-backed section of ANY segment
for s in macho.sections.iter().filter(|s| s.size > 0 && s.offset > 0) {
    if (s.offset as u64) < first_segment_offset {
        first_segment_offset = s.offset as u64;
    }
}
```
(Do the section loop once, outside the per-LC match — e.g. right before the fallback computation — so `__PAGEZERO`-style arms and 32-bit segments are covered by the same union; keep the existing `Segment32` fileoff arm but add `filesize > 0`.) Keep the `u64::MAX → 4096` fallback (294-298) unchanged. Update `MachOMetadata.first_segment_offset` doc (parser.rs:61-62) to: `/// Lowest file offset of file-backed content (nonzero sections and nonzero
/// fileoff/filesize segments), bounding load-command insertion; 4096 when none exists.`

`writer.rs` `find_first_segment_offset` (673-695): same union using `macho.sections` and segment `fileoff > 0 && filesize > 0`, `4096` fallback preserved.

`writer.rs` `inject_dylib_command`: inside the `LC_SEGMENT_64` arm (590-595) add `&& filesize > 0` (filesize read at `offset + 48`); same for `LC_SEGMENT` (39 at `offset + 36`). Add a section walk per segment:

```rust
LC_SEGMENT_64 => {
    let fileoff = read_u64(input, offset + 40, is_big_endian)? as usize;
    let filesize = read_u64(input, offset + 48, is_big_endian)? as usize;
    let nsects = read_u32(input, offset + 64, is_big_endian)? as usize;
    let cmdsize = read_u32(input, offset + 4, is_big_endian)? as usize;
    if fileoff > 0 && filesize > 0 && fileoff < first_segment_offset {
        first_segment_offset = fileoff;
    }
    let sects_bytes = nsects
        .checked_mul(80)
        .ok_or_else(|| Error::MachO("section count overflow".into()))?;
    let sects_end = offset
        .checked_add(72)
        .and_then(|base| base.checked_add(sects_bytes))
        .ok_or_else(|| Error::MachO("section table overflow".into()))?;
    let lc_end = offset
        .checked_add(cmdsize)
        .ok_or_else(|| Error::MachO("load command size overflow".into()))?;
    if sects_end > lc_end || sects_end > input.len() {
        return Err(Error::MachO("section table exceeds load command".into()));
    }
    for i in 0..nsects {
        let so = offset + 72 + i * 80;
        let ssize = read_u64(input, so + 40, is_big_endian)? as usize;
        let soff = read_u64(input, so + 48, is_big_endian)? as usize;
        if ssize > 0 && soff > 0 && soff < first_segment_offset {
            first_segment_offset = soff;
        }
    }
}
```
Mirror for `LC_SEGMENT` (sections at `offset + 56`, 68 bytes each, `size` at +36, `offset` at +40, `nsects` at `offset + 48`). `usize::MAX → DEFAULT_FIRST_SEGMENT_OFFSET` fallback unchanged (611-612).

- [ ] **Step 4: Unify the insertion guards**

Replace the `sizeofcmds`-subtraction guards in `realloc_code_sign_space_single` (173-187) and `realloc_code_sign_space_with_metadata` (927-939) with the addition-only test used by `add_code_signature_command`:

```rust
let new_cmd_size = LINKEDIT_DATA_COMMAND_SIZE as usize;
let header_size = if metadata.is_64 { 32 } else { 28 };   // or `is_64` in the goblin variant
let sizeofcmds = read_u32(&output, 20, is_big_endian)? as usize;
let insert_end = metadata.max_load_cmd_end                      // or `max_load_cmd_end`
    .max(header_size + sizeofcmds)
    .checked_add(new_cmd_size)
    .ok_or_else(|| Error::MachO("load command end overflow".into()))?;
if insert_end > metadata.first_segment_offset                   // or `first_segment_offset`
    || insert_end > output.len()
{
    return Err(Error::MachO("No space for LC_CODE_SIGNATURE in load commands area".into()));
}
```
Also wrap `add_code_signature_command`'s `load_commands_end + new_cmd_size` (494) and `add_code_signature_command_with_metadata`'s `metadata.max_load_cmd_end + new_cmd_size` (1043) in `checked_add`, keep their existing `> bound` semantics plus the `> data.len()` companion check. `inject_dylib_command`'s guard (617-626) already compares `new_cmd_end > first_segment_offset` and checks `output.len()` — only its bound derivation changes (Step 3).

- [ ] **Step 5: Run gate, expect GREEN**

```bash
TMPDIR=$PWD/.tmptmp cargo test -p zsign-core macho -- --skip test_ipa_signing_is_deterministic
```
Expected: new tests pass; the 13 writer + 6 parser + 12 signer + 10 verify baseline all pass (notably `test_inject_dylib_command_no_slack`, `test_inject_dylib_command`, `test_parse_32bit_encryption_info` — fixtures without sections keep today's bound).

- [ ] **Step 6: Commit (controller).** Subject: `fix(macho): bound load-command insertion by first file-backed content (ZSN-32)`.

---

### Task 2 — Single magic-constant endian detection + big-endian e2e fixture

**Files:** Modify `crates/zsign-core/src/macho/parser.rs` (new helper + detector site 300-303); Modify `crates/zsign-core/src/macho/writer.rs` (detector sites 140-143, 473-476, 502-505, 701-704; `inject_dylib_command` 553-557); Add `make_minimal_macho_be` to `fixtures.rs`; Test in writer.rs test module.

- [ ] **Step 1: Fixture** — add to `fixtures.rs`: `pub(crate) fn make_minimal_macho_be() -> Vec<u8>` building byte-identical structure to `make_minimal_macho` (same fields, same offsets, `__TEXT` fileoff `0x1000`, `__LINKEDIT` fileoff `0x2000` filesize 0, file length `0x2000`, `__text` at `0x1000`) but every `u32`/`u64` written with `to_be_bytes()` and magic `0xfeedfacf` big-endian (on-disk prefix `FE ED FA CF`). Implementation: copy `make_minimal_macho`'s body with `macro_rules` swapping `to_le_bytes` → `to_be_bytes`; add a self-check fixture assertion `assert_eq!(&b[0..4], &[0xfe, 0xed, 0xfa, 0xcf])`.

- [ ] **Step 2: Failing/locking test** — append to writer.rs tests:

```rust
#[test]
fn test_big_endian_sign_parse_roundtrip() {
    let data = crate::macho::fixtures::make_minimal_macho_be();
    assert_eq!(&data[0..4], &[0xfe, 0xed, 0xfa, 0xcf], "fixture must be a real big-endian image");
    let macho = crate::macho::MachOFile::parse(data).expect("big-endian Mach-O must parse");
    let slice = &macho.slices()[0];
    assert!(slice.metadata.is_big_endian, "parser must classify the slice as big-endian");

    let signed = crate::macho::sign_macho_adhoc(&macho, "com.example.be", None, None, None, false)
        .expect("big-endian signing must succeed");
    let reparsed = crate::macho::MachOFile::parse(signed.clone()).expect("signed big-endian output must reparse");
    let out = &reparsed.slices()[0];
    assert!(out.metadata.is_big_endian, "signed output must still be big-endian");

    // __LINKEDIT.filesize must have been rewritten big-endian: decode raw bytes both ways.
    let (lc_off, _, _, _) = out.metadata.linkedit_cmd.expect("signed output keeps __LINKEDIT");
    let raw = u64::from_be_bytes(signed[lc_off + 48..lc_off + 56].try_into().unwrap());
    assert_eq!(raw, out.metadata.linkedit_cmd.unwrap().3,
        "__LINKEDIT filesize must be encoded big-endian");
    assert_ne!(raw, u64::from_le_bytes(signed[lc_off + 48..lc_off + 56].try_into().unwrap()),
        "little-endian decoding must not yield the filesize value");
    assert!(raw > 0, "signing must have given __LINKEDIT a nonzero filesize");

    // LC_CODE_SIGNATURE.dataoff must also be big-endian on the wire.
    let (cmd_off, _, _) = out.metadata.code_sig_cmd.expect("signed output carries LC_CODE_SIGNATURE");
    let dataoff_be = u32::from_be_bytes(signed[cmd_off + 8..cmd_off + 12].try_into().unwrap());
    let dataoff_le = u32::from_le_bytes(signed[cmd_off + 8..cmd_off + 12].try_into().unwrap());
    assert_eq!(dataoff_be, out.code_sig_offset.expect("parsed dataoff"),
        "LC_CODE_SIGNATURE.dataoff must be encoded big-endian");
    assert_ne!(dataoff_be, dataoff_le,
        "little-endian decoding must not yield the dataoff");

    // Verify leg: the embedded superblob and its CodeDirectory must round-trip.
    let sig_off = out.code_sig_offset.expect("signed output carries LC_CODE_SIGNATURE") as usize;
    let sig_size = out.code_sig_size.expect("signed output carries LC_CODE_SIGNATURE") as usize;
    let superblob = crate::codesign::verify::parse_superblob(&signed[sig_off..sig_off + sig_size])
        .expect("big-endian signed output must carry a parseable superblob");
    let cd = superblob.code_directory.as_ref().expect("superblob carries a code directory");
    let cd_raw = cd.raw();
    assert_eq!(
        u64::from_be_bytes(cd_raw[72..80].try_into().unwrap()),
        0x1000,
        "CodeDirectory execSegLimit must round-trip for a big-endian image"
    );
}
```
Run scoped gate. Expected: **PASS pre-fix** (per design §1.2 the current byte arms already classify `FE ED FA CF`; this test is the contract lock the brief demands) — record the actual result verbatim in the task report; if it FAILS, the root cause is in-scope (fix it) or in `signer.rs`/`verify.rs` (stop, raise one question).

- [ ] **Step 3: Implement the helper** — add to `parser.rs` (near `MachOMetadata`):

```rust
/// True when the Mach-O image starting at byte `base` is big-endian. Detection
/// keys on the byte-swapped magic constants (CIGAM == on-disk big-endian),
/// which is exactly equivalent to comparing the raw prefix against the
/// big-endian magic byte patterns.
pub(crate) fn is_big_endian_macho(data: &[u8], base: usize) -> bool {
    match data.get(base..base + 4) {
        Some(raw) => {
            let magic = u32::from_le_bytes(raw.try_into().expect("4-byte slice"));
            matches!(magic, goblin::mach::header::MH_CIGAM
                | goblin::mach::header::MH_CIGAM_64
                | goblin::mach::fat::FAT_CIGAM)
        }
        None => false,
    }
}
```
(`base + 4` may overflow only for absurd bases — use `base.checked_add(4)` inside `get` range to keep it total: `base.checked_add(4).and_then(|end| data.get(base..end))`.)

- [ ] **Step 4: Migrate the five sites**
- `parser.rs:300-303` → `let is_big_endian = is_big_endian_macho(data, base_offset);`
- `writer.rs:140-143` (realloc_single), `473-476` (`update_linkedit_data_command`), `502-505` (`add_code_signature_command`), `701-704` (`update_linkedit_segment`) → `let is_big_endian = super::parser::is_big_endian_macho(data, 0);` (writer already `use super::parser::MachOMetadata` — extend that import or path-qualify).
- `writer.rs:553-557` (`inject_dylib_command`) → keep the 64-bit gate, derive endian from the helper:
```rust
let magic = read_u32(input, 0, false)?;
if magic != MH_MAGIC_64 && magic != MH_CIGAM_64 {
    return Err(Error::MachO("not a 64-bit Mach-O binary".into()));
}
let is_big_endian = super::parser::is_big_endian_macho(input, 0);
```
Behavior parity: `MH_CIGAM` (32-bit BE) previously produced `is_big_endian=false` only because the function errored first; now the helper says `true` before the same error — outcome identical.

- [ ] **Step 5: Gate (expect all green, baseline + BE test), commit (controller).**
Subject: `fix(macho): detect endianness from magic constants in one helper (ZSN-32)`.

---

### Task 3 — realloc expands from the declared reserve + prepare capacity guard

**Files:** Modify `crates/zsign-core/src/macho/writer.rs` (`realloc_code_sign_space_single` 111-115 + LC rewrite 157-220; `realloc_code_sign_space_with_metadata` 886-890 + LC rewrite 910-977; `prepare_code_in_place` 1089-1128; `prepare_code_with_metadata` 993-1037); Tests in writer.rs.

- [ ] **Step 1a: Shared helpers** in `writer.rs`:

```rust
/// End of the signature range currently declared by the LC_CODE_SIGNATURE
/// command, read from the buffer's own bytes at the command offset.
fn declared_signature_end(data: &[u8], lc_offset: usize, is_big_endian: bool) -> Result<Option<usize>> {
    let cmd_end = lc_offset
        .checked_add(16)
        .ok_or_else(|| Error::MachO("LC_CODE_SIGNATURE offset overflow".into()))?;
    if cmd_end > data.len() {
        return Err(Error::MachO(format!(
            "LC_CODE_SIGNATURE at {lc_offset} extends past the {}-byte buffer", data.len()
        )));
    }
    let dataoff = read_u32(data, lc_offset + 8, is_big_endian)? as usize;
    let datasize = read_u32(data, lc_offset + 12, is_big_endian)? as usize;
    Ok(Some(dataoff.checked_add(datasize).ok_or_else(|| {
        Error::MachO("LC_CODE_SIGNATURE: offset + size overflow".into())
    })?))
}
```
(`read_u32` itself bounds-checks its offsets, but the `checked_add` on `lc_offset` keeps the helper total even for a hostile `MachOMetadata` built around `usize::MAX` — the design's promise that overflow becomes `Error::MachO`, never a panic.)

- [ ] **Step 1b: Signed fixture** — add to `fixtures.rs` (used by tasks 3, 4, 5):

```rust
/// `make_minimal_macho` extended with an existing LC_CODE_SIGNATURE whose
/// `slot_len`-byte slot begins at 0x2000 (inside `__LINKEDIT`, whose filesize
/// covers the slot), filled with 0xAA. Builds a parseable already-signed image.
pub(crate) fn make_signed_minimal_macho(slot_len: u32) -> Vec<u8> {
    make_signed_minimal_macho_at(0x2000, slot_len)
}

/// As `make_signed_minimal_macho`, but the signature starts at an arbitrary
/// (possibly unaligned) `dataoff`.
pub(crate) fn make_signed_minimal_macho_at(dataoff: u32, slot_len: u32) -> Vec<u8> {
    let mut b = make_minimal_macho();
    let ncmds = u32::from_le_bytes(b[16..20].try_into().unwrap());
    let sizeofcmds = u32::from_le_bytes(b[20..24].try_into().unwrap());
    b[16..20].copy_from_slice(&(ncmds + 1).to_le_bytes());
    b[20..24].copy_from_slice(&(sizeofcmds + 16).to_le_bytes());
    let lc = 32 + sizeofcmds as usize; // 280
    b[lc..lc + 4].copy_from_slice(&0x1du32.to_le_bytes());
    b[lc + 4..lc + 8].copy_from_slice(&16u32.to_le_bytes());
    b[lc + 8..lc + 12].copy_from_slice(&dataoff.to_le_bytes());
    b[lc + 12..lc + 16].copy_from_slice(&slot_len.to_le_bytes());
    // __LINKEDIT filesize (LC at 184, field at +48) covers the slot tail.
    let linkedit_end = dataoff as u64 + slot_len as u64;
    b[232..240].copy_from_slice(&(linkedit_end - 0x2000).to_le_bytes());
    b.resize(linkedit_end as usize, 0);
    for byte in &mut b[dataoff as usize..] {
        *byte = 0xAA;
    }
    b
}
```

- [ ] **Step 2: Failing tests** (append to writer.rs tests). Shared builder — a `0x8000`-byte buffer shaped like the minimal fixture whose appended `LC_CODE_SIGNATURE` is in exactly the state `prepare_code_in_place` leaves behind: `dataoff=0x3000`, `datasize=0x6000` (a reserve **larger than the `0x5000`-byte tail** that actually follows `dataoff`), declared end `0x9000 > 0x8000`, while `calculate_signature_space(0x3000) = 0x8000 <= 0x8000` makes the old early return fire:

```rust
fn big_signed_buffer() -> Vec<u8> {
    let mut data = crate::macho::fixtures::make_minimal_macho();
    data.resize(0x8000, 0);
    let ncmds = u32::from_le_bytes(data[16..20].try_into().unwrap());
    let sizeofcmds = u32::from_le_bytes(data[20..24].try_into().unwrap());
    data[16..20].copy_from_slice(&(ncmds + 1).to_le_bytes());
    data[20..24].copy_from_slice(&(sizeofcmds + 16).to_le_bytes());
    let lc = 32 + sizeofcmds as usize; // 280
    data[lc..lc + 4].copy_from_slice(&0x1du32.to_le_bytes());       // LC_CODE_SIGNATURE
    data[lc + 4..lc + 8].copy_from_slice(&16u32.to_le_bytes());     // cmdsize
    data[lc + 8..lc + 12].copy_from_slice(&0x3000u32.to_le_bytes());  // dataoff
    data[lc + 12..lc + 16].copy_from_slice(&0x6000u32.to_le_bytes()); // datasize
    data
}

#[test]
fn test_realloc_expands_to_cover_declared_reserve() {
    let data = big_signed_buffer();
    // goblin parses the input without bounds-checking the declared range;
    // MachOFile::parse would (correctly) reject it, which is the bug's symptom.
    let out = realloc_code_sign_space(&data, 0x3000).expect("expansion must succeed");
    let reparsed = crate::macho::MachOFile::parse(out.clone())
        .expect("expanded output must reparse: the declared reserve has to fit");
    let slice = &reparsed.slices()[0];
    let dataoff = slice.code_sig_offset.expect("output carries LC_CODE_SIGNATURE") as usize;
    let datasize = slice.code_sig_size.expect("output carries LC_CODE_SIGNATURE") as usize;
    assert!(dataoff + datasize <= out.len(),
        "declared signature range {dataoff:#x}+{datasize:#x} must fit in {:#x}-byte output", out.len());
    assert_eq!(slice.code_length, 0x3000, "code region must end at the existing dataoff");
}

#[test]
fn test_realloc_with_metadata_expands_to_cover_declared_reserve() {
    use crate::macho::parser::MachOMetadata;
    let data = big_signed_buffer();
    let metadata = MachOMetadata {
        code_sig_cmd: Some((280, 0x3000, 0x6000)),
        linkedit_cmd: Some((184, 0x2000, 0x1000, 0)),
        max_load_cmd_end: 296,
        first_segment_offset: 0x1000,
        is_big_endian: false,
        is_64: true,
    };
    let (out, meta) = realloc_code_sign_space_with_metadata(&data, &metadata, 0x3000)
        .expect("expansion must succeed");
    let (_, dataoff, datasize) = meta.code_sig_cmd.expect("metadata echoes the command");
    assert!((dataoff as usize) + (datasize as usize) <= out.len(),
        "declared range {dataoff:#x}+{datasize:#x} must fit in {:#x}-byte output", out.len());
}

#[test]
fn test_prepare_rejects_reserve_exceeding_buffer_capacity() {
    let data = crate::macho::fixtures::make_minimal_macho(); // 0x2000, unsigned
    let macho = crate::macho::MachOFile::parse(data.clone()).expect("fixture must parse");
    let meta = macho.slices()[0].metadata.clone();
    let mut buf = data;
    let err = prepare_code_in_place(&mut buf, &meta, 0x2000, 0x3000)
        .expect_err("declaring 0x3000 bytes of reserve in a 0x2000 buffer must be refused");
    let msg = match err { crate::Error::MachO(m) => m, other => panic!("expected MachO error, got {other:?}") };
    assert!(msg.contains("reserve"), "message must name the reserve: {msg}");
    assert_eq!(buf.len(), 0x2000, "buffer must be untouched on refusal");
}

#[test]
fn test_prepare_capacity_guard_counts_alignment_pad_for_odd_dataoff() {
    // Odd dataoff 0x2001: the signature starts at 0x2010, so a 0x400 reserve
    // ends at 0x2410 — 15 bytes past the 0x2401-byte input the caller passed.
    let signed = crate::macho::fixtures::make_signed_minimal_macho_at(0x2001, 0x400);
    let macho = crate::macho::MachOFile::parse(signed.clone()).expect("odd input must parse");
    let slice = &macho.slices()[0];
    assert_eq!(slice.code_length, 0x2001, "fixture precondition: odd dataoff");
    let mut buf = signed;
    let err = prepare_code_in_place(&mut buf, &slice.metadata, slice.code_length, 0x400)
        .expect_err("reserve plus the 15-byte alignment pad exceeds the caller's buffer");
    let msg = match err { crate::Error::MachO(m) => m, other => panic!("expected MachO error, got {other:?}") };
    assert!(msg.contains("exceeds"), "message must explain the overflow: {msg}");
}

#[test]
fn test_aligned_resign_roundtrip() {
    let first = crate::macho::sign_macho_adhoc(
        &crate::macho::MachOFile::parse(crate::macho::fixtures::make_minimal_macho())
            .expect("fixture parses"),
        "com.example.first", None, None, None, false).expect("first sign");
    let second = crate::macho::sign_macho_adhoc(
        &crate::macho::MachOFile::parse(first).expect("first output parses"),
        "com.example.second", None, None, None, false).expect("aligned re-sign must succeed");
    crate::macho::MachOFile::parse(second).expect("re-signed output parses");
}
```
Run gate: both `test_realloc_*` RED (pre-fix early-returns at `calculate(0x3000)=0x8000 <= 0x8000`, leaving the declared `0x9000 > 0x8000` dangling → output reparse fails), both `test_prepare_*` RED (pre-fix `Ok`: truncates and declares past EOF). `test_aligned_resign_roundtrip` is a **contract lock** (green at base — it proves the new guards don't break the preserve/aligned path). Record the actual failures verbatim.

- [ ] **Step 3: Implement — realloc early return + expansion**

Both variants, replacing `if new_length <= data.len() { return Ok(data.to_vec()); }` (`_single`; `_with_metadata` returns `Ok((data.to_vec(), metadata.clone()))`):

```rust
if code_length > data.len() {
    return Err(Error::MachO(format!(
        "code_length {code_length} exceeds the {}-byte buffer", data.len()
    )));
}
let sig_offset = align_to(code_length, 16);
let reserve = calculate_signature_space(code_length)
    .checked_sub(code_length)
    .ok_or_else(|| Error::MachO("signature space smaller than code length".into()))?;
let formula_end = sig_offset.checked_add(reserve)
    .ok_or_else(|| Error::MachO("signature space overflow".into()))?;
let declared_end = match code_sig_cmd {
    Some((lc_off, _, _)) => declared_signature_end(&output_or_data, lc_off, is_big_endian)?,
    None => None,
};
let required = declared_end.map_or(formula_end, |d| d.max(formula_end));
if required <= data.len() {
    // _single returns Ok(data.to_vec()); the _with_metadata twin returns
    // Ok((data.to_vec(), metadata.clone())) — unchanged early-exit semantics.
    return Ok(data.to_vec());
}
// expansion: target = required (strictly greater than data.len() here)
```
The `code_length > data.len()` check runs first in both variants — it is what makes the later `data[..code_length]` truncation total (checked arithmetic per the brief; the pre-fix code panics on that slice for a metadata/`code_length` past EOF).
- Expansion path: `output.resize(required, 0)` (replacing `resize(new_length, 0)` at 221/977); `sig_datasize = checked_u32(required - code_length, "sig_datasize")` for this task (Task 5 later switches both the `+8` dataoff write and this subtraction to the aligned `sig_offset`); the `+8`/`+20` dataoff writes keep `checked_u32(code_length, "code_length")` until Task 5, keeping `dataoff + datasize` exact for aligned inputs. `__LINKEDIT` update uses `required` wherever `new_length` appears (`new_filesize = required.checked_sub(linkedit_fileoff)`), `size_increase = required - data.len()` stays valid because `required > data.len()` here.
- The goblin variant reads `declared_signature_end` from `data` when `code_sig_cmd` was found by its load-command walk (existing-command branch at writer.rs:160-167; metadata twin at writer.rs:912-919); the metadata variant passes `metadata.code_sig_cmd.0` **but must read the bytes from `data`, not the metadata tuple's stale sizes** (metadata gives the offset, the buffer gives the values).
- Keep early-return semantics for `code_sig_cmd == None` inputs exactly: `required = formula_end` (unsigned binaries behave as today).

- [ ] **Step 4: Implement — prepare capacity guard** in `prepare_code_in_place` and `prepare_code_with_metadata`, after `sig_offset`/`sig_size` are computed and **before** any `truncate`/`to_vec`:

```rust
let declared_end = sig_offset.checked_add(sig_size as usize).ok_or_else(|| {
    Error::MachO("signature reserve overflows the buffer index".into())
})?;
if declared_end > buf.len() {
    return Err(Error::MachO(format!(
        "signature reserve of {sig_size} bytes at offset {sig_offset} exceeds the {}-byte buffer",
        buf.len()
    )));
}
```
(`prepare_code_with_metadata` checks against `data.len()` before `data[..code_length].to_vec()`; `prepare_code_single` intentionally unchanged per design §2 item 3.)

- [ ] **Step 5: Gate (new + all baseline green), commit (controller).**
Subject: `fix(macho): expand signature space from the declared reserve (ZSN-32)`.

---

### Task 4 — `embed_signature_single` re-spans `__LINKEDIT` on shrink

**Files:** Modify `crates/zsign-core/src/macho/writer.rs` (`embed_signature_single` 424-431); uses `make_signed_minimal_macho` added in Task 3; Test in writer.rs.

- [ ] **Step 1: Failing test** (writer.rs):

```rust
#[test]
fn test_embed_signature_shrink_respans_linkedit() {
    let signed = crate::macho::fixtures::make_signed_minimal_macho(0x800);
    let small = [0xBBu8; 0x40];
    let out = embed_signature(&signed, &small)
        .expect("re-signing with a smaller signature must succeed");
    let reparsed = crate::macho::MachOFile::parse(out.clone())
        .expect("shrinking re-sign output must reparse: a stale __LINKEDIT filesize would exceed the file");
    let (_, fileoff, vmsize_after, filesize) =
        reparsed.slices()[0].metadata.linkedit_cmd.expect("__LINKEDIT present");
    assert_eq!(fileoff + filesize, out.len() as u64,
        "__LINKEDIT must end exactly at the new file end");
    assert_eq!(out.len(), 0x2000 + small.len(),
        "output must drop the old 0x800-byte slot");
    // update_linkedit_segment may GROW vmsize to the 16 KiB-aligned minimum
    // (0x4000 here) but must never shrink it below the original page.
    assert!(vmsize_after >= filesize, "vmsize must cover filesize");
    assert!(vmsize_after >= 0x1000, "vmsize must never shrink below the original page");
}
```
Run gate: RED pre-fix — `embed_signature_single` skips the update when the end shrinks, `fileoff+filesize = 0x2800 > 0x2040`, reparse fails.

- [ ] **Step 3: Implement** — replace the guarded update at writer.rs:424-431 with an unconditional, checked re-span:

```rust
if let Some((offset, seg)) = linkedit_cmd {
    let sig_end = (sig_offset as u64).checked_add(signature.len() as u64)
        .ok_or_else(|| Error::MachO("signature end overflow".into()))?;
    let new_filesize = sig_end.checked_sub(seg.fileoff).ok_or_else(|| {
        Error::MachO("signature end precedes the __LINKEDIT segment".into())
    })?;
    update_linkedit_segment(&mut output, offset, new_filesize)?;
}
```
The `sig_offset + signature.len() > linkedit_end` condition disappears entirely — growth and shrink both re-span; `new_filesize` is now computed only after the checked add, eliminating the pre-guard underflow. `update_linkedit_segment` keeps `vmsize = max(align(filesize, 0x4000), original_vmsize)` — virtual size never shrinks (loader.h: `vmsize ≥ filesize`).

- [ ] **Step 4: Gate (green), commit (controller).** Subject: `fix(macho): re-span linkedit on signature shrink (ZSN-32)`.

---

### Task 5 — Aligned `dataoff` writes from realloc

**Files:** Modify `crates/zsign-core/src/macho/writer.rs` — both realloc variants' four raw-`code_length` dataoff writes (writer.rs:164/200/916/954), their metadata echoes (921-925/969-973), and `sig_datasize`; Tests in writer.rs. **No alignment reject in `prepare_*` and `has_enough_signature_space` stays unchanged** — review round 1 (finding 1) showed `code_sig_cmd.is_some()` cannot distinguish a pre-existing command from one realloc just added, so a reject would refuse valid odd-length fresh signs; the Task 3 capacity guard (odd preserve → `sig_offset + slot = len + pad > len` → clean `Err`) plus Task 3's sig-offset-based target (odd expand → pad allocated, output healed) already enforce the invariant.

- [ ] **Step 1: Failing tests** (writer.rs):

```rust
#[test]
fn test_realloc_writes_aligned_dataoff_for_odd_code_length() {
    use crate::macho::parser::MachOMetadata;
    let data = crate::macho::fixtures::make_signed_minimal_macho_at(0x2001, 0x400);
    assert_eq!(data.len(), 0x2401, "fixture precondition: odd dataoff, slot ends at EOF");
    let metadata = MachOMetadata {
        code_sig_cmd: Some((280, 0x2001, 0x400)),
        linkedit_cmd: Some((184, 0x2000, 0x1000, 0x401)),
        max_load_cmd_end: 296,
        first_segment_offset: 0x1000,
        is_big_endian: false,
        is_64: true,
    };
    // metadata variant
    let (out, meta) = realloc_code_sign_space_with_metadata(&data, &metadata, 0x2001)
        .expect("expansion must succeed");
    let (_, dataoff, datasize) = meta.code_sig_cmd.expect("metadata echoes the command");
    assert_eq!(dataoff % 16, 0, "realloc must write a 16-aligned dataoff, got {dataoff:#x}");
    assert!((dataoff as usize) + (datasize as usize) <= out.len(),
        "declared range {dataoff:#x}+{datasize:#x} must fit {:#x}-byte output", out.len());
    assert_eq!(u32::from_le_bytes(out[288..292].try_into().unwrap()), dataoff,
        "LC bytes and metadata must carry the same dataoff");
    // goblin variant, same contract
    let out2 = realloc_code_sign_space(&data, 0x2001).expect("expansion must succeed");
    let macho2 = crate::macho::MachOFile::parse(out2.clone()).expect("expanded output must reparse");
    let d2 = macho2.slices()[0].code_sig_offset.expect("LC present");
    assert_eq!(d2 % 16, 0, "goblin variant must also write a 16-aligned dataoff, got {d2:#x}");
    assert!((d2 as usize) + macho2.slices()[0].code_sig_size.expect("size") as usize <= out2.len(),
        "declared range must fit the output");
}

#[test]
fn test_sign_unaligned_length_keeps_signature_in_bounds() {
    let mut data = crate::macho::fixtures::make_minimal_macho();
    data.resize(0x2001, 0); // unsigned image with odd length: pad to sig_offset is normal
    let macho = crate::macho::MachOFile::parse(data).expect("fixture must parse");
    let signed = crate::macho::sign_macho_adhoc(&macho, "com.example.oddlen", None, None, None, false)
        .expect("signing an odd-length unsigned binary must succeed");
    let reparsed = crate::macho::MachOFile::parse(signed.clone())
        .expect("signed output must reparse: declared range must fit");
    let slice = &reparsed.slices()[0];
    let dataoff = slice.code_sig_offset.expect("signed output carries LC_CODE_SIGNATURE");
    assert_eq!(dataoff % 16, 0, "dataoff must be 16-byte aligned");
    assert!((dataoff as usize) + slice.code_sig_size.expect("size") as usize <= signed.len(),
        "declared range must fit the output");
}

#[test]
fn test_odd_dataoff_resign_roundtrip() {
    let signed = crate::macho::fixtures::make_signed_minimal_macho_at(0x2001, 0x400);
    let macho = crate::macho::MachOFile::parse(signed).expect("odd input must parse");
    let resigned = crate::macho::sign_macho_adhoc(&macho, "com.example.odd", None, None, None, false)
        .expect("expand-path odd re-sign must succeed with the pad allocated");
    let reparsed = crate::macho::MachOFile::parse(resigned.clone())
        .expect("odd re-sign output must reparse: no dangling declared range");
    let slice = &reparsed.slices()[0];
    let dataoff = slice.code_sig_offset.expect("signed output carries LC_CODE_SIGNATURE");
    assert_eq!(dataoff % 16, 0, "re-signing must heal the signature start to 16 bytes, got {dataoff:#x}");
    assert!((dataoff as usize) + slice.code_sig_size.expect("size") as usize <= resigned.len(),
        "declared range must fit the output");
}
```
Red/green ledger (be precise in the tester's report): **test 1 is RED at this task's boundary** (realloc still writes raw `code_length` — `0x2001 % 16 != 0` — until Step 3 lands) and covers all four write sites; **tests 2 and 3 are RED at base but already green since Task 3** (they prove the base bug and then lock Task 3's sig-offset target — label them contract locks in this task's report, not this task's red proof).

- [ ] **Step 2: Implement — no alignment guard (deliberate).** Do **not** add any `code_length % 16` / `code_sig_cmd.is_some()` rejection to `prepare_code_in_place` or `prepare_code_with_metadata`, and do not touch `has_enough_signature_space`. Enforcement is exactly the Task 3 pair: the capacity guard (`sig_offset + sig_size > buffer → Err`, which necessarily fires for odd preserve) and the `sig_offset`-based expansion target (which allocates the pad for odd expand). Design §2 item 5 records why the reject candidate was withdrawn (review round 1, finding 1).

- [ ] **Step 3: Implement — aligned writes.** In both realloc variants: `let sig_offset = align_to(code_length, 16);` already exists from Task 3; at all four dataoff writes (writer.rs:164/200/916/954) write `checked_u32(sig_offset, "sig_offset")` instead of `checked_u32(code_length, "code_length")`; set `sig_datasize = checked_u32(required - sig_offset, "sig_datasize")` (replacing `required - code_length`) and the metadata echoes at 921-925/969-973 to `(cmd_offset, sig_offset, sig_datasize)`. Early-return path untouched. For aligned inputs every value is byte-identical to before; for odd `code_length` this is the only step that makes the written LC agree with the aligned target (`dataoff + datasize == required == out.len()`).

- [ ] **Step 4: Gate (green), commit (controller).** Subject: `fix(macho): write aligned signature dataoff from realloc (ZSN-32)`.

---

### Task 6 — `execSegLimit` from `__TEXT.filesize`

**Files:** Modify `crates/zsign-core/src/macho/parser.rs` (237-240, 250-253, doc 110-111); Add `make_minimal_macho_text_vmsize_pad` to `fixtures.rs`; Tests in parser.rs.

- [ ] **Step 1: Fixture** — add to `fixtures.rs`:

```rust
/// `make_minimal_macho` with zero-fill in `__TEXT`: `vmsize` 0x2000 over a
/// file-backed `filesize` of 0x1800 (file length unchanged at 0x2000).
pub(crate) fn make_minimal_macho_text_vmsize_pad() -> Vec<u8> {
    let mut b = make_minimal_macho();
    // LC_SEGMENT_64 __TEXT starts at 32: vmsize at +32, filesize at +48.
    b[64..72].copy_from_slice(&0x2000u64.to_le_bytes());
    b[80..88].copy_from_slice(&0x1800u64.to_le_bytes());
    b
}
```

- [ ] **Step 2: Failing tests** (parser.rs):

```rust
#[test]
fn test_text_segment_size_is_file_backed_extent() {
    let data = crate::macho::fixtures::make_minimal_macho_text_vmsize_pad();
    let macho = super::MachOFile::parse(data).expect("fixture must parse");
    let slice = &macho.slices()[0];
    assert_eq!(slice.text_segment_size, 0x1800,
        "execSegLimit input must be __TEXT.filesize, not vmsize (zero-fill excluded)");
    assert_eq!(slice.text_segment_base, 0x1_0000_0000, "execSegBase input stays the segment base");
}

#[test]
fn test_exec_seg_limit_written_from_filesize() {
    let data = crate::macho::fixtures::make_minimal_macho_text_vmsize_pad();
    let macho = super::MachOFile::parse(data).expect("fixture must parse");
    let signed = crate::macho::sign_macho_adhoc(&macho, "com.example.textpad", None, None, None, false)
        .expect("sign must succeed");
    let reparsed = super::MachOFile::parse(signed.clone()).expect("signed output parses");
    let slice = &reparsed.slices()[0];
    let off = slice.code_sig_offset.expect("signed") as usize;
    let size = slice.code_sig_size.expect("signed") as usize;
    let superblob = crate::codesign::verify::parse_superblob(&signed[off..off + size])
        .expect("embedded superblob parses");
    let cd = superblob.code_directory.as_ref().expect("code directory present");
    let exec_seg_limit = u64::from_be_bytes(cd.raw()[72..80].try_into().unwrap());
    assert_eq!(exec_seg_limit, 0x1800,
        "CodeDirectory execSegLimit must equal __TEXT.filesize (byte offsets as in signer.rs:1400-1403)");
}
```
Run gate: RED pre-fix (`text_segment_size == 0x2000`, CD limit `0x2000`).

- [ ] **Step 3: Implement** — parser.rs:237-240 and 250-253: `text_segment_size = seg.filesize;` (32-bit arm: `seg.filesize as u64`). Doc at parser.rs:110-111 becomes:

```rust
/// File-backed size of the `__TEXT` segment (`filesize`, excluding
/// zero-fill — used for `execSegLimit` in code signing).
pub text_segment_size: u64,
```

- [ ] **Step 4: Gate (green), commit (controller).** Subject: `fix(macho): derive exec seg limit from text segment filesize (ZSN-32)`.

---

## Self-review checklist (controller, before cold review)

- [ ] Every brief queue item maps to exactly one task: 1→bound, 2→endian, 3→realloc/guard, 4→shrink, 5→alignment, 6→execSegLimit. ✔
- [ ] No placeholders in this plan; each task carries real test code and exact commands. ✔
- [ ] Red expectations are deterministic: Task 1 (three refusals + one offset assert red; preservation test is a lock), Task 3 (two realloc + two prepare red; roundtrip is a lock), Task 4 (shrink reparse red), Task 5 (aligned-dataoff realloc test red at that boundary; two base-red locks explicitly labeled), Task 6 (both red). Task 2 is a contract lock by design (design §1.2). ✔
- [ ] Type/name consistency: `is_big_endian_macho`, `declared_signature_end`, `make_signed_minimal_macho_at`, `prepare_code_in_place`, `realloc_code_sign_space_with_metadata` used identically across tasks. ✔
- [ ] Scope: no edits outside `crates/zsign-core/src/macho/{writer,parser,fixtures}.rs`; `signer.rs`/`verify.rs` called only from tests. ✔
