# ZSN-33 FAT/Universal Signing + execSegFlags Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: subagent-driven-development; dispatching-parallel-agents only where tasks are independent (here they are sequential — queue order is binding). Steps use checkbox syntax. Tester writes each task's failing tests first; implementer greens them; controller runs the scoped gate and commits before the next task starts.

**Goal:** Make every signer/writer path handle FAT/Universal containers correctly (per-slice sha256-only, container preservation, strict reassembly, per-arch alignment, trailing-byte preservation, hostile-input bounds, dylib injection, builder routing) and emit Apple-parity execSeg fields (`fileoff` base, `MAIN_BINARY` on every `MH_EXECUTE`), with the signer's reserve flowing into realloc (R1/R3).

**Architecture:** All fixes land behind unchanged public signatures in `crates/zsign-core/src/macho/{signer,writer,parser,fixtures}.rs` + `crates/zsign/src/builder.rs`. One rule: container kind (`macho.is_fat()`) decides dispatch; slice count never does. FAT-capable entries = `sign_any_macho`, `sign_macho_sha256_only`; thin-only entries = `sign_macho`, `sign_macho_adhoc` (clean `Err` on containers).

**Tech Stack:** Rust 2021 workspace, goblin (Mach-O/FAT parse), rayon, in-memory `#[cfg(test)]` fixtures.

**Design:** `docs/superpowers/specs/2026-09-25-fat-universal-design.md` (authoritative for decisions/alternatives). **Gate per task:** `mkdir -p .tmptmp && TMPDIR=$PWD/.tmptmp cargo test -p zsign-core macho -- --skip test_ipa_signing_is_deterministic` (task 8 additionally `TMPDIR=$PWD/.tmptmp cargo test -p zsign builder`). Never run `cargo fmt`/`clippy`/`hk`. One conventional commit per task, controller-authored.

**Shared test fixture (added in Task 1, used by every later task)** — `crates/zsign-core/src/macho/fixtures.rs`:

```rust
/// Assembles a big-endian FAT/Universal container around the given thin
/// slices. Offsets follow the per-entry align exponent (lipo's rule:
/// round each slice up to a multiple of 2^align), so fixtures obey the
/// same invariant the writer must emit.
pub fn make_fat_macho(slices: &[Vec<u8>], aligns: &[u32]) -> Vec<u8> {
    assert_eq!(slices.len(), aligns.len());
    assert!(!slices.is_empty());
    let mut out = Vec::new();
    out.extend_from_slice(&0xcafebabeu32.to_be_bytes());
    out.extend_from_slice(&(slices.len() as u32).to_be_bytes());
    let header_size = 8 + slices.len() * 20;
    let mut offsets = Vec::with_capacity(slices.len());
    let mut cursor = header_size;
    for (slice, align) in slices.iter().zip(aligns) {
        let step = 1usize << *align;
        cursor = cursor.checked_add(step - 1).unwrap() & !(step - 1);
        offsets.push(cursor);
        cursor += slice.len();
    }
    // Entries are appended directly after the 8-byte fat_header (magic +
    // nfat_arch), so the table lands at offset 8 where goblin reads it.
    for ((slice, align), offset) in slices.iter().zip(aligns).zip(&offsets) {
        let cpu = u32::from_le_bytes(slice[4..8].try_into().expect("cputype"));
        let sub = u32::from_le_bytes(slice[8..12].try_into().expect("cpusubtype"));
        out.extend_from_slice(&cpu.to_be_bytes());
        out.extend_from_slice(&sub.to_be_bytes());
        out.extend_from_slice(&(*offset as u32).to_be_bytes());
        out.extend_from_slice(&(slice.len() as u32).to_be_bytes());
        out.extend_from_slice(&align.to_be_bytes());
    }
    for (slice, offset) in slices.iter().zip(&offsets) {
        out.resize(*offset, 0);
        out.extend_from_slice(slice);
    }
    out
}
```

Tests may derive a second arch by patching `make_minimal_macho()` bytes 4..8 to `0x0100_0007` (x86_64 cputype) — the body parses identically and gives order assertions a visible signal.

---

### Task 1 (queue item 1): Per-slice SHA-256-only FAT signing

**Files:** `crates/zsign-core/src/macho/fixtures.rs` (add `make_fat_macho` above), `crates/zsign-core/src/macho/signer.rs` (guard region 320-347; new private impl; `sign_macho_all_slices` 360-407).

- [ ] **Step 1 — failing test** in `signer.rs` mod tests:

```rust
#[test]
fn test_sha256_only_signs_two_arch_fat_container() {
    let mut b = make_minimal_macho();
    b[4..8].copy_from_slice(&0x0100_0007u32.to_le_bytes()); // x86_64-headed second slice
    let fat = make_fat_macho(&[make_minimal_macho(), b], &[12, 12]);
    let macho = MachOFile::parse(fat).unwrap();
    assert!(macho.is_fat());
    let creds = test_credentials();
    // This is exactly the call the default IpaSigner (sha256_only=true) makes.
    let signed = sign_macho_sha256_only(&macho, "com.zsign.fatsha", None, &creds, None, None, false)
        .expect("default sha256-only path must sign a two-arch FAT executable");
    let m = MachOFile::parse(signed.clone()).unwrap();
    assert!(m.is_fat(), "FAT container must survive sha256-only signing");
    assert_eq!(m.slices().len(), 2);
    let cpus: Vec<u32> = m.slices().iter().map(|s| s.cpu_type).collect();
    assert_eq!(cpus, vec![0x0100_000c, 0x0100_0007], "architecture order must be preserved");
    for slice in m.slices() {
        let sig = slice.code_sig_offset.expect("each slice must carry a signature");
        let blob = &signed[slice.offset + sig as usize
            ..slice.offset + (sig + slice.code_sig_size.unwrap()) as usize];
        // Mirror the slot scan of test_sha256_only_signature_omits_sha1_code_directory:
        // superblob count at [8..12] (BE), entries 12.., and the primary CD's
        // hashType byte — assert hashType == 2 (SHA-256) and NO SHA-1 CodeDirectory
        // anywhere in the blob (no CSSLOT_CODEDIRECTORY hashType==1, no 0x1000 alternate).
    }
}
```
(Filler comment aside: the slot scan must be written out fully — read `count = u32::from_be_bytes(blob[8..12])`, walk 8-byte entries, parse each CD entry's `hashType` at entry offset + 37, assert every CD seen has `hashType == 2` and at least one CD exists.)

- [ ] **Step 2 — run red:** `TMPDIR=$PWD/.tmptmp cargo test -p zsign-core macho test_sha256_only_signs_two_arch_fat_container` ⇒ FAIL with `Err "sign_macho_sha256_only only supports single-arch Mach-O"`.
- [ ] **Step 3 — implement** in `signer.rs`:
  1. Rename the body of `sign_macho_all_slices` to `fn sign_all_slices_impl(..., sha256_only: bool)`; inside, replace the hardwired `false` (:399) with the parameter. Public `sign_macho_all_slices` becomes a one-line delegate passing `false`. Doc comment of the impl states it is the shared per-slice engine.
  2. In `sign_macho_sha256_only`, replace the `slices().len() != 1` guard with:

```rust
if macho.is_fat() {
    reject_encrypted(macho, identifier, allow_encrypted)?;
    let signed = sign_all_slices_impl(
        macho, identifier, entitlements, credentials,
        info_plist, code_resources, allow_encrypted, true,
    )?;
    return super::writer::embed_signature_fat(macho.data(), &signed);
}
```
  (entitlements pass through unchanged — same convention as this function's thin path; `reject_encrypted` also runs inside the impl, exactly as `sign_macho_all_slices` does today.) The thin body below stays as-is (non-FAT `MachOFile` always has exactly one slice — parser guarantees; remove the now-dead `len()!=1` guard).
  3. Doc comment on `sign_macho_sha256_only`: "Signs every slice of a FAT/Universal binary with SHA-256-only code directories, or a single thin binary."

- [ ] **Step 4 — run green** (same command as Step 2), then full gate. **Commit:** `feat(macho): per-slice sha256-only fat signing (ZSN-33)`.

**Acceptance:** default sha256-only call signs a two-arch FAT; container + order preserved; every slice SHA-256-only. All pre-existing tests green (`sign_macho_all_slices` behavior byte-identical).

---

### Task 2 (queue item 2): FAT dispatch by container kind

**Files:** `crates/zsign-core/src/macho/signer.rs` (158-201, guards at 256-260 and 298-302).

- [ ] **Step 1 — failing tests** in `signer.rs`:

```rust
#[test]
fn test_sign_any_macho_preserves_one_arch_fat_container() {
    let fat = make_fat_macho(&[make_minimal_macho()], &[12]);
    let macho = MachOFile::parse(fat).unwrap();
    assert!(macho.is_fat() && macho.slices().len() == 1);
    let creds = test_credentials();
    let signed = sign_any_macho(&macho, "com.zsign.onefat", None, &creds, None, None, false)
        .expect("one-arch FAT must sign through the FAT-capable path");
    assert_eq!(&signed[0..4], &[0xca, 0xfe, 0xba, 0xbe],
        "one-arch FAT output must keep the fat_header, not be stripped to thin");
    let m = MachOFile::parse(signed).unwrap();
    assert!(m.is_fat());
    assert_eq!(m.slices().len(), 1);
    assert!(m.slices()[0].code_sig_offset.is_some(), "embedded slice must be signed");
}

#[test]
fn test_thin_only_signers_reject_fat_containers() {
    let fat = make_fat_macho(&[make_minimal_macho()], &[12]);
    let macho = MachOFile::parse(fat).unwrap();
    let creds = test_credentials();
    let err = sign_macho(&macho, "com.zsign.no", None, &creds, None, None, false)
        .expect_err("thin-only signer must reject a container, never strip it");
    assert!(err.to_string().contains("sign_any_macho"),
        "error must point at the FAT-capable entry: {err}");
    let err = sign_macho_adhoc(&macho, "com.zsign.no", None, None, None, false)
        .expect_err("adhoc thin-only signer must reject a container");
    assert!(err.to_string().contains("sign_any_macho"), "{err}");
}
```

- [ ] **Step 2 — run red** ⇒ test 1 FAILS (output starts `cf fa ed fe`, `is_fat()==false` — the silent strip); test 2 FAILS (`sign_macho` succeeds and strips instead of erroring).
- [ ] **Step 3 — implement** in `signer.rs`:
  1. `sign_any_macho`: change `if macho.slices().len() == 1` (179) to `if !macho.is_fat()`; the `else` branch stays `sign_all_slices_impl(..., false)` + `embed_signature_fat` (already true after task 1 — reuse it; entitlements keep flowing through `sign_any_macho`'s existing first-slice `EMPTY_ENTITLEMENTS` selection). Doc updated: dispatch is container-based; one-arch FAT preserves the container.
  2. `sign_macho` guard becomes `if macho.is_fat() { Err("sign_macho signs thin Mach-O only; use sign_any_macho for FAT/Universal binaries") }`; `sign_macho_adhoc` same shape with its own name. The old `len()!=1` checks are deleted (non-FAT implies one slice).
- [ ] **Step 4 — run green** + full gate. **Commit:** `fix(macho): dispatch fat containers by kind in signers (ZSN-33)`.

**Acceptance:** one-arch FAT survives container round trip through `sign_any_macho` with a signature inside; thin-only signers fail closed with an actionable message; thin paths unchanged (existing tests green).

---

### Task 3 (queue item 3): Reassembly integrity — strict signed-slice set

**Files:** `crates/zsign-core/src/macho/writer.rs` (`SignedSlice` 31-40, `embed_signature` 282-311, `embed_signature_fat` 323-336, `embed_fat_from_signed_slices` 338-396), `crates/zsign-core/src/macho/signer.rs` (SignedSlice construction in `sign_slice_complete`, ~667-683).

- [ ] **Step 1 — failing tests** in `writer.rs` mod tests:

```rust
#[test]
fn test_embed_fat_requires_one_signed_slice_per_arch() {
    let fat = make_fat_macho(&[make_minimal_macho(), {
        let mut b = make_minimal_macho();
        b[4..8].copy_from_slice(&0x0100_0007u32.to_le_bytes());
        b
    }], &[12, 12]);
    let macho = MachOFile::parse(fat.clone()).unwrap();
    let creds = test_credentials();
    let full = sign_macho_all_slices(&macho, "com.zsign.set", None, &creds, None, None, false).unwrap();
    assert_eq!(full.len(), 2);

    let one = embed_signature_fat(&fat, &full[0..1]);
    let err = one.expect_err("one-of-two signed slices must be rejected, not reassembled unsigned");
    assert!(err.to_string().contains("exactly one signed slice"), "{err}");

    let none = embed_signature_fat(&fat, &[]);
    let err = none.expect_err("zero-of-two signed slices must be rejected");
    assert!(err.to_string().contains("exactly one signed slice"), "{err}");
}

#[test]
fn test_embed_fat_rejects_signed_slice_identity_mismatch() {
    // build `full` as above, then tamper one field at a time:
    // original_size += 1  => Err contains "identity mismatch"
    // offset += 0x1000    => Err contains "identity mismatch"
    // cpu_type = 0xdead   => Err contains "identity mismatch"
}

#[test]
fn test_embed_signature_rejects_multi_arch_fat() {
    let fat = make_fat_macho(&[make_minimal_macho(), make_minimal_macho()], &[12, 12]);
    let sig = <a minimal valid superblob bytes or a real one from a thin adhoc sign>;
    let err = embed_signature(&fat, &sig)
        .expect_err("embed_signature must not produce a partially signed universal");
    assert!(err.to_string().contains("exactly one signed slice"), "{err}");
}
```
(the middle test's body is written out fully by the Tester; signature bytes for the third test: sign a thin `make_minimal_macho()` ad-hoc and slice out its `code_sig` blob — that is a valid signature payload.)

- [ ] **Step 2 — run red:** tests 1-2 FAIL (one-of-two silently half-signs: `Ok` whose slice 1 has no `code_sig_offset`; identity tampering ignored → `Ok`); test 3 FAILS (`Ok` with slice 1 unsigned). Note in the run log which assertion observed the half-signed output.
- [ ] **Step 3 — implement** in `writer.rs` + `signer.rs`:
  1. `SignedSlice` gains `/// CPU type of the original slice, validated against the FAT table on reassembly. pub cpu_type: u32`. Populate at every construction: `sign_slice_complete` (both return paths — from `slice.cpu_type`) and `embed_signature`'s FAT arm (from `first_macho.header.cputype`).
  2. `embed_fat_from_signed_slices` — after the arches are collected, replace the per-arch find-or-copy loop with:

```rust
if signed_slices.len() != arches.len() {
    return Err(Error::MachO(format!(
        "FAT reassembly requires exactly one signed slice per architecture: {} arches, {} signed slices",
        arches.len(), signed_slices.len()
    )));
}
let mut slice_data_vec: Vec<&[u8]> = Vec::with_capacity(arches.len());
for (i, arch) in arches.iter().enumerate() {
    let signed = signed_slices
        .iter()
        .find(|s| s.slice_index == i)
        .ok_or_else(|| Error::MachO(format!("FAT reassembly: no signed slice for architecture {i}")))?;
    if signed.offset != arch.offset as usize
        || signed.original_size != arch.size as usize
        || signed.cpu_type != arch.cputype
    {
        return Err(Error::MachO(format!(
            "FAT reassembly: signed slice {i} identity mismatch: signed (offset={}, size={}, cpu=0x{:x}) vs container (offset={}, size={}, cpu=0x{:x})",
            signed.offset, signed.original_size, signed.cpu_type,
            arch.offset, arch.size, arch.cputype
        )));
    }
    slice_data_vec.push(&signed.signed_data);
}
```
  The unsigned `data[offset..offset+size]` fallback (358-361) is **deleted** (duplicate/extra indexes fall out of the `len == arches.len()` + per-index find combination: a duplicate leaves some arch unmatched ⇒ `Err`).
  3. `embed_signature_fat` thin arm: require `signed_slices.len() == 1` and `signed_slices[0].original_size == data.len()` else `Err` (today: silent `signed_slices[0]` pick).
  4. `embed_signature`'s FAT arm is left intact — it now fails naturally through the count check (1 vs N) and validates identity on the one-arch path.
- [ ] **Step 4 — run green** + full gate (`fat_code_limit_beyond_slice_is_rejected` must stay green: it signs the full set). **Commit:** `fix(macho): require full signed-slice set for fat reassembly (ZSN-33)`.

**Acceptance:** partial sets, identity tampering, and `embed_signature`-on-multi-arch-FAT all return the specific `Err`; full-set signing paths unchanged.

---

### Task 4 (queue item 4): Per-arch alignment

**Files:** `crates/zsign-core/src/macho/writer.rs` (`embed_fat_from_signed_slices` 363-401, `write_u32_be` 399-401).

- [ ] **Step 1 — failing test** in `writer.rs`:

```rust
#[test]
fn test_embed_fat_aligns_each_slice_to_its_declared_exponent() {
    let mut b = make_minimal_macho();
    b[4..8].copy_from_slice(&0x0100_0007u32.to_le_bytes());
    // align 15 on the first arch: 16 KiB placement (today's hardcode) violates 2^15.
    let fat = make_fat_macho(&[make_minimal_macho(), b], &[15, 12]);
    let macho = MachOFile::parse(fat).unwrap();
    let creds = test_credentials();
    let signed = sign_any_macho(&macho, "com.zsign.align", None, &creds, None, None, false).unwrap();

    let n = u32::from_be_bytes(signed[4..8].try_into().unwrap());
    let mut prev_end = 8 + n as usize * 20; // header end; probe zone zero-filled
    for i in 0..n {
        let e = 8 + i as usize * 20;
        let off = u32::from_be_bytes(signed[e + 8..e + 12].try_into().unwrap()) as usize;
        let size = u32::from_be_bytes(signed[e + 12..e + 16].try_into().unwrap()) as usize;
        let align = u32::from_be_bytes(signed[e + 16..e + 20].try_into().unwrap());
        assert_eq!(off % (1usize << align), 0,
            "slice {i} offset {off:#x} must be a multiple of 2^{align}");
        assert!(off >= prev_end, "slices must not overlap the table");
        let gap = off - prev_end;
        assert!(gap < (1usize << align),
            "gap {gap:#x} before slice {i} must be < 2^{align} (codesign strict rule)");
        assert!(signed[prev_end..off].iter().all(|&b| b == 0), "gap bytes must be zero");
        prev_end = off + size;
    }
    assert_eq!(signed.len(), prev_end, "output must end exactly at the last slice");
}
```
Red pre-fix: slice 0 lands at `align_up(48, 0x4000) = 0x4000`, `0x4000 % 0x8000 != 0` ⇒ first assert fires.

- [ ] **Step 2 — run red** (confirm the alignment assert is the failure; later asserts are contract locks).
- [ ] **Step 3 — implement** in `writer.rs`, replacing 364-401 arithmetic:

```rust
let header_size = 8usize
    .checked_add(
        arches
            .len()
            .checked_mul(20)
            .ok_or_else(|| Error::MachO("FAT arch table size overflow".into()))?,
    )
    .ok_or_else(|| Error::MachO("FAT arch table size overflow".into()))?;
let mut new_offsets: Vec<(u32, u32)> = Vec::with_capacity(arches.len());
let mut cursor = header_size;
for (arch, slice) in arches.iter().zip(&slice_data_vec) {
    if arch.align >= 32 {
        return Err(Error::MachO(format!(
            "FAT arch align exponent {} exceeds the 32-bit FAT offset space", arch.align
        )));
    }
    let align = 1usize << arch.align;
    cursor = cursor
        .checked_add(align - 1)
        .ok_or_else(|| Error::MachO("FAT offset overflow while aligning".into()))?
        & !(align - 1);
    let offset = u32::try_from(cursor)
        .map_err(|_| Error::MachO("FAT slice offset exceeds 32-bit FAT limit".into()))?;
    let size = u32::try_from(slice.len())
        .map_err(|_| Error::MachO("FAT slice size exceeds 32-bit FAT limit".into()))?;
    new_offsets.push((offset, size));
    cursor = cursor
        .checked_add(slice.len())
        .ok_or_else(|| Error::MachO("FAT offset overflow".into()))?;
}
let total_size = cursor;
let mut output = vec![0u8; total_size];
```
Header/table writes switch from `write_u32_be` to the checked `write_u32(&mut output, at, value, true)?` (n via `u32::try_from(arches.len())`); the per-slice copy uses `output.get_mut(off..off+len)` → `copy_from_slice`, erroring via `ok_or_else` if None. **Delete `write_u32_be`** — all **five** call sites (the cputype/cpusubtype/offset/size/align writes in the arch-table loop, writer.rs:384-388) migrate to the checked helper; grep confirms no other users.

- [ ] **Step 4 — run green** + full gate (existing FAT fixtures declare align 12 → placement changes from 16 KiB to 4 KiB grid; reparse-based tests must stay green). **Commit:** `fix(macho): align fat slices to declared per-arch alignment (ZSN-33)`.

**Acceptance:** every emitted `offset % 2^align == 0`, gaps `< 2^align` and zero, output ends exactly at the last slice; `align ≥ 32` and `u32` overflows return `Err`.

---

### Task 5 (queue item 5): Trailing-byte preservation

**Files:** `crates/zsign-core/src/macho/parser.rs` (content clamp 338-371, `code_length` 373-375, struct init ~385-400), tests in `parser.rs` + `signer.rs`.

- [ ] **Step 1 — failing tests:**

```rust
// parser.rs
#[test]
fn test_unsigned_fat_code_length_covers_declared_size() {
    let mut a = make_minimal_macho();
    let declared = a.len() + 0x400;
    a.extend(std::iter::repeat(0xAB).take(0x400)); // trailing bytes inside the slice
    let fat = make_fat_macho(&[a, make_minimal_macho()], &[12, 12]);
    let macho = MachOFile::parse(fat).unwrap();
    let slice = &macho.slices()[0];
    assert_eq!(slice.size, declared);
    assert_eq!(slice.code_length, declared,
        "unsigned FAT slices must hash up to the declared arch size, not the last segment end");
}

// signer.rs
#[test]
fn test_sign_preserves_fat_slice_trailing_bytes() {
    let mut a = make_minimal_macho();
    let tail_start = a.len();
    a.extend(std::iter::repeat(0xAB).take(0x400));
    let mut b = make_minimal_macho();
    b[4..8].copy_from_slice(&0x0100_0007u32.to_le_bytes());
    let fat = make_fat_macho(&[a.clone(), b], &[12, 12]);
    let macho = MachOFile::parse(fat).unwrap();
    let creds = test_credentials();
    let signed = sign_any_macho(&macho, "com.zsign.tail", None, &creds, None, None, false).unwrap();
    let m = MachOFile::parse(signed.clone()).unwrap();
    let s = &m.slices()[0];
    let end = s.offset + s.code_sig_offset.unwrap() as usize;
    let got = &signed[s.offset + tail_start..end];
    assert!(got.iter().all(|&b| b == 0xAB),
        "trailing bytes must be preserved (and hashed) before the signature; got {:02x?}", &got[..8.min(got.len())]);
}
```

- [ ] **Step 2 — run red:** parser test fails (`code_length == a.len()` ≠ declared); signer test fails (realloc rebuild drops the tail ⇒ region reads `0x00`/signature bytes).
- [ ] **Step 3 — implement** in `parser.rs` `parse_single`:
  1. Delete the whole `let slice_data = if base_offset == 0 { data } else { …content-end clamp… };` block (338-371 — through the `slice_end` bounds checks, immediately before `let code_length` at 373) — its bounds are already guaranteed by `MachOFile::parse`'s per-arch validation (186-201) and the LC/LINKEDIT checks (306-328); `is_big_endian_macho(data, base_offset)` is untouched (does not use the local).
  2. `let code_length = code_sig_offset.map(|o| o as usize).unwrap_or(declared_size);` (keeps the existing `code_length > declared_size ⇒ Err` check below it, which still guards hostile `dataoff`).
  3. Struct init: `size: declared_size` (replaces `slice_data.len()`; `MachOFile::parse` still overwrites `offset`/`size` for FAT from the arch table — same values, no behavior change). Confirm by grep inside the function that nothing else used the deleted local.
  4. Update the `ArchSlice.code_length` doc: "Length of code to be signed: the existing signature start, or the full declared size for unsigned slices (thin: full file)."
- [ ] **Step 4 — run green** + full gate — pay attention to `test_odd_dataoff_resign_roundtrip`, `test_sign_unaligned_length_keeps_signature_in_bounds`, `fat_code_limit_beyond_slice_is_rejected` (all exercise this derivation). **Commit:** `fix(parser): hash full declared slice size to preserve trailing bytes (ZSN-33)`.

**Acceptance:** unsigned FAT `code_length == declared_size`; tail bytes survive re-signing byte-for-byte before `LC_CODE_SIGNATURE.dataoff`; thin behavior unchanged (thin already used the whole file).

---

### Task 6 (queue item 6): Hostile FAT bounds — checked everywhere in writer.rs

**Files:** `crates/zsign-core/src/macho/writer.rs` (`embed_signature` FAT arm 288-310, `embed_fat_from_signed_slices`, `embed_signature_single` code_length ~430-440, `prepare_code_single` ~926-935, `prepare_code_with_metadata` ~1113/:1121/:1140, `update_linkedit` subtraction sites ~955/:1159/:1261, `write_u32_be` — already deleted in task 4).

- [ ] **Step 1 — failing tests** in `writer.rs` (each must fail by PANIC or wrong-Ok pre-fix, never by a passing assert):

```rust
#[test]
fn test_embed_signature_rejects_truncated_fat_slice() {
    let fat = make_fat_macho(&[make_minimal_macho(), make_minimal_macho()], &[12, 12]);
    // align-12 fixture places arch0 at [0x1000, 0x3000); cutting to 0x2000
    // puts that declared range past EOF, which pre-fix panics at the raw index.
    let cut = &fat[..0x2000];
    let err = embed_signature(cut, &signature_bytes())
        .expect_err("truncated FAT must be a clean error");
    assert!(err.to_string().contains("exceeds"), "{err}"); // pre-fix: PANIC at data[offset..offset+size]
}

#[test]
fn test_embed_fat_rejects_arch_range_beyond_file() {
    // sign on the intact container, then hand embed_fat a truncated copy of it:
    let fat = make_fat_macho(&[make_minimal_macho(), make_minimal_macho()], &[12, 12]);
    let macho = MachOFile::parse(fat.clone()).unwrap();
    let full = sign_macho_all_slices(&macho, "com.zsign.trunc", None, &test_credentials(), None, None, false).unwrap();
    let cut = fat[..fat.len() - 0x800].to_vec();
    let err = embed_signature_fat(&cut, &full)
        .expect_err("container whose arch ranges exceed it must be rejected");
    assert!(err.to_string().contains("exceeds"), "{err}"); // pre-fix: Ok (range never validated)
}

#[test]
fn test_embed_fat_rejects_overflowing_arch_range() {
    let fat = make_fat_macho(&[make_minimal_macho()], &[12]);
    let mut bad = fat.clone();
    // arch[0].offset = 0xFFFF_FFF0, size = 0x0000_0100 => offset+size = 0x1_0000_00F0 (u64-safe, EOF-far)
    let e = 8;
    bad[e + 8..e + 12].copy_from_slice(&0xFFFF_FFF0u32.to_be_bytes());
    bad[e + 12..e + 16].copy_from_slice(&0x100u32.to_be_bytes());
    let err = embed_signature(&bad, &signature_bytes())
        .expect_err("overflowing arch range must be a clean error");
    assert!(err.to_string().contains("exceeds"), "{err}");
}

#[test]
fn test_embed_fat_rejects_overlapping_slices() {
    // arch[0] = [0x1030, 0x3030), arch[1] = [0x2030, 0x4030): both regions
    // parse as Mach-O (the 0x30 in the offsets is the 8+2*20-byte container
    // header, so slice 0's header + LCs sit below slice 1's start) and the
    // ranges overlap by 0x1000 bytes.
    const HEADER: usize = 8 + 2 * 20; // 48
    let mut fat = vec![0u8; 0x4030];
    fat[0..4].copy_from_slice(&0xcafebabeu32.to_be_bytes());
    fat[4..8].copy_from_slice(&2u32.to_be_bytes());
    for (i, (off, size)) in [(0x1030u32, 0x2000u32), (0x2030u32, 0x2000u32)]
        .into_iter()
        .enumerate()
    {
        let e = HEADER + i * 20;
        fat[e..e + 4].copy_from_slice(&0x0100_000cu32.to_be_bytes());
        fat[e + 4..e + 8].copy_from_slice(&0u32.to_be_bytes());
        fat[e + 8..e + 12].copy_from_slice(&off.to_be_bytes());
        fat[e + 12..e + 16].copy_from_slice(&size.to_be_bytes());
        fat[e + 16..e + 20].copy_from_slice(&12u32.to_be_bytes());
    }
    fat[0x1030..0x3030].copy_from_slice(&make_minimal_macho());
    fat[0x2030..0x4030].copy_from_slice(&make_minimal_macho());
    let macho = MachOFile::parse(fat.clone()).unwrap(); // both slices parse
    let full = sign_macho_all_slices(&macho, "com.zsign.overlap", None, &test_credentials(), None, None, false).unwrap();
    let err = embed_signature_fat(&fat, &full)
        .expect_err("overlapping slices must be rejected");
    assert!(err.to_string().contains("overlap"), "{err}"); // pre-fix: Ok
}

#[test]
fn test_prepare_rejects_hostile_linkedit_fileoff() {
    // minimal thin Mach-O whose __LINKEDIT.fileoff points past the file:
    let mut data = make_minimal_macho();
    let macho = MachO::parse(&data, 0).unwrap();
    let lc = macho.load_commands.iter()
        .find(|lc| matches!(lc.command, CommandVariant::Segment64(s) if s.segname.starts_with(b"__LINKEDIT")))
        .expect("__LINKEDIT present");
    let off = lc.offset + 40; // segment_command_64.fileoff field within the LC
    data[off..off + 8].copy_from_slice(&0x9000u64.to_le_bytes());
    let err = std::panic::catch_unwind(|| prepare_code_for_signing(&data, 0x4000));
    // assert clean Err — pre-fix this underflows (SIGABRT/panic in debug)
    match err { Ok(inner) => assert!(inner.is_err()), Err(_) => panic!("prepare must not panic on hostile __LINKEDIT.fileoff") }
}
```
(`signature_bytes()` helper: sign a thin fixture ad-hoc, extract the `code_sig` blob — same trick as task 3.)

- [ ] **Step 2 — run red:** record which tests panic (truncated/overflow/underflow) and which wrongly return `Ok` (overlap, truncated-embed-fat).
- [ ] **Step 3 — implement** in `writer.rs`:
  1. New private helper (placed next to `embed_fat_from_signed_slices`):

```rust
/// Validates a FAT arch table against the container bytes: every arch's
/// [offset, offset+size) range must lie inside `data`, must not overflow,
/// and ranges must be pairwise disjoint. Reused by every writer entry
/// point that consumes a container.
fn validate_fat_arches(arches: &[FatArch], data: &[u8]) -> Result<()> {
    let mut ranges: Vec<(usize, usize, usize)> = Vec::with_capacity(arches.len());
    for (i, arch) in arches.iter().enumerate() {
        let start = arch.offset as usize;
        let end = start
            .checked_add(arch.size as usize)
            .ok_or_else(|| Error::MachO(format!("FAT slice {i}: offset + size overflow")))?;
        if data.get(start..end).is_none() {
            return Err(Error::MachO(format!(
                "FAT slice {i}: range {start}..{end} exceeds file of {} bytes", data.len()
            )));
        }
        ranges.push((start, end, i));
    }
    ranges.sort_unstable();
    for pair in ranges.windows(2) {
        if pair[0].1 > pair[1].0 {
            return Err(Error::MachO(format!(
                "FAT slices {} and {} overlap", pair[0].2, pair[1].2)));
        }
    }
    Ok(())
}
```
  2. Call it from `embed_signature`'s FAT arm (right after `fat.iter_arches()` collection — before any indexing, replacing the raw `&data[offset..offset+size]` with a validated `.get(start..end)` copy) and from `embed_fat_from_signed_slices` (after collecting `arches`).
  3. `embed_signature_single` (writer.rs:440), `prepare_code_single` (writer.rs:935), **and `prepare_code_with_metadata` (code_length derived from raw `dataoff` at writer.rs:1121, sliced at :1140)**: before every `data[..code_length]` built from `LC_CODE_SIGNATURE.dataoff`, add `if code_length > data.len() { return Err(Error::MachO("LC_CODE_SIGNATURE dataoff exceeds file length".into())) }` — mirroring realloc's existing guard at writer.rs:154-190/985-990. This is the last unguarded site of that class (the `realloc` siblings are already guarded).
  4. The three `u64` subtractions (`new_filesize = (sig_offset + estimated) as u64 - seg.fileoff` at ~955/~1159/~1261): compute `let sig_end = sig_offset.checked_add(estimated_signature_size).ok_or_else(|| Error::MachO("signature end overflow".into()))? as u64;` then `sig_end.checked_sub(seg.fileoff).ok_or_else(|| Error::MachO("__LINKEDIT fileoff lies beyond the signature end".into()))?`.
  5. Grep `writer.rs` for `[..` slicing on externally-derived indexes and `write_u32_be` — zero remaining unguarded sites.
- [ ] **Step 4 — run green** + full gate. **Commit:** `fix(macho): bounds-check fat reassembly and prepare arithmetic (ZSN-33)`.

**Acceptance:** all five tests return `Err` with the asserted substrings, none panics; existing writer bound tests (`test_read_u32_out_of_bounds`, etc.) stay green.

---

### Task 7 (queue item 7): Dylib injection across FAT

**Files:** `crates/zsign-core/src/macho/writer.rs` (`inject_dylib_command` 579-766).

- [ ] **Step 1 — failing test** in `writer.rs`:

```rust
#[test]
fn test_inject_dylib_command_injects_every_fat_slice_then_signs() {
    let mut b = make_minimal_macho();
    b[4..8].copy_from_slice(&0x0100_0007u32.to_le_bytes()); // x86_64-headed second slice
    let fat = make_fat_macho(&[make_minimal_macho(), b], &[12, 12]);
    let m0 = MachOFile::parse(fat.clone()).unwrap();
    let ncmds_before: Vec<u32> = m0.slices().iter().map(|s| {
        let hdr = &fat[s.offset..];
        u32::from_le_bytes(hdr[16..20].try_into().unwrap()) // ncmds
    }).collect();

    let out = inject_dylib_command(&fat, "/usr/lib/libzsigntest.dylib", false)
        .expect("FAT injection must succeed");
    let m = MachOFile::parse(out.clone()).unwrap();
    assert_eq!(m.slices().len(), 2, "injection must keep the container");
    for (i, slice) in m.slices().iter().enumerate() {
        let hdr = &out[slice.offset..];
        let ncmds = u32::from_le_bytes(hdr[16..20].try_into().unwrap());
        assert_eq!(ncmds, ncmds_before[i] + 1, "slice {i} must gain one LC_LOAD_DYLIB");
    }

    // injected container must still be signable end-to-end:
    let creds = test_credentials();
    let signed = sign_any_macho(&m, "com.zsign.injectfat", None, &creds, None, None, false)
        .expect("signing after FAT injection must succeed");
    let ms = MachOFile::parse(signed).unwrap();
    assert!(ms.is_fat() && ms.slices().iter().all(|s| s.code_sig_offset.is_some()));

    // a slice without load-command slack fails closed, with a non-misleading error:
    let tight = make_text_fileoff0_macho(true);
    let fat_tight = make_fat_macho(&[tight, make_minimal_macho()], &[12, 12]);
    let err = inject_dylib_command(&fat_tight, "/usr/lib/libzsigntest.dylib", false)
        .expect_err("tight slice must refuse injection");
    assert!(!err.to_string().contains("not a 64-bit"),
        "FAT must not fall into the thin magic guard: {err}");
}
```
- [ ] **Step 2 — run red:** `Err … "not a 64-bit Mach-O binary"` (dispatch missing).
- [ ] **Step 3 — implement** in `writer.rs`:
  1. Rename the current function body to `fn inject_dylib_thin(input: &[u8], dylib_name: &str, weak: bool) -> Result<Vec<u8>>` (verbatim move; doc comment keeps the 64-bit/slack contract).
  2. New public entry:

```rust
pub fn inject_dylib_command(input: &[u8], dylib_name: &str, weak: bool) -> Result<Vec<u8>> {
    if let Ok(Mach::Fat(fat)) = Mach::parse(input) {
        let arches = fat.iter_arches()
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::MachO(format!("Failed to read FAT arches: {e}")))?;
        validate_fat_arches(&arches, input)?;
        let mut signed_slices = Vec::with_capacity(arches.len());
        for (i, arch) in arches.iter().enumerate() {
            let start = arch.offset as usize;
            let end = start + arch.size as usize; // validated above
            let injected = inject_dylib_thin(&input[start..end], dylib_name, weak)?;
            signed_slices.push(SignedSlice {
                slice_index: i,
                offset: start,
                original_size: arch.size as usize,
                cpu_type: arch.cputype,
                signed_data: injected,
            });
        }
        return embed_fat_from_signed_slices(input, &fat, &signed_slices);
    }
    inject_dylib_thin(input, dylib_name, weak)
}
```
  3. Update the public doc: injects into every slice of a FAT/Universal binary and reassembles via the hardened FAT writer; thin behavior unchanged. (`Mach::parse` errors and `Mach::Binary` fall through to the thin path — today's errors for garbage/32-bit inputs are preserved exactly.)
- [ ] **Step 4 — run green** + full gate (existing thin injection tests must be untouched-green). **Commit:** `feat(macho): dylib injection across fat containers (ZSN-33)`.

**Acceptance:** every slice gains exactly one `LC_LOAD_DYLIB`, container reassembles, subsequent FAT signing succeeds; slack-less slice ⇒ clean `Err` that is not the thin magic guard.

---

### Task 8 (queue item 8): Builder routing

**Files:** `crates/zsign/src/builder.rs` (dual branch 329-338; tests module 492-622).

- [ ] **Step 1 — failing tests** in `builder.rs` mod tests (inline FAT helper: copy the `make_fat_macho` body from `fixtures.rs` as a local `fn make_fat_for_test(slices: &[Vec<u8>]) -> Vec<u8>` — the facade cannot reach core's `#[cfg(test)]` fixtures):

```rust
#[test]
fn test_sign_macho_fat_default_sha256_only_routes_through_fat_path() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("universal_bin");
    let output = dir.path().join("universal_signed");
    let mut b = crate::test_util::minimal_macho(); // -> Vec<u8> (include_bytes!)
    b[4..8].copy_from_slice(&0x0100_0007u32.to_le_bytes());
    std::fs::write(&input, make_fat_for_test(&[
        crate::test_util::minimal_macho(), b])).unwrap();

    ZSign::new()
        .credentials(crate::test_util::test_credentials())
        .sign_macho(&input, &output)
        .expect("default direct-sign (sha256_only=true) must handle FAT");

    let signed = std::fs::read(&output).unwrap();
    assert_eq!(&signed[0..4], &[0xca, 0xfe, 0xba, 0xbe]);
    let m = crate::macho::MachOFile::parse(signed).unwrap();
    assert!(m.is_fat() && m.slices().len() == 2);
    assert!(m.slices().iter().all(|s| s.code_sig_offset.is_some()),
        "both slices must be signed");
}

#[test]
fn test_sign_macho_fat_dual_digest_routes_through_sign_any() {
    // same fixture; ZSign::new().credentials(...).sha256_only(false)
    // => Ok, FAT preserved, both slices signed
}

#[test]
fn test_sign_macho_adhoc_rejects_fat() {
    // same fixture; ZSign::new().adhoc(true).sign_macho(..) => Err (fail-closed contract)
}
```
(`crate::test_util::minimal_macho()` takes no path and returns an owned `Vec<u8>` (`crates/zsign/src/test_util.rs:9-11`) — call it bare, as `builder.rs:592` does; `tempfile` is already a facade dev-dependency — pattern from `test_sign_bundle_folder_in_place`.)

- [ ] **Step 2 — run red:** default test fails with the core thin-guard `Err "sign_macho_sha256_only only supports single-arch…"` (task 1 has landed by queue order — re-anchor: at THIS point sha256 is already FAT-capable, so the default test may be GREEN pre-change; the **red** comes from `sha256_only(false)` → `sign_macho` guard `Err`, and the adhoc test is a contract lock. Record honestly which are red vs locks in the run log.)
- [ ] **Step 3 — implement** in `builder.rs` — dual branch becomes:

```rust
} else if macho.is_fat() {
    crate::macho::sign_any_macho(
        &macho,
        identifier,
        entitlements.as_deref(),
        credentials,
        None,
        None,
        self.allow_encrypted,
    )?
} else {
    sign_macho(&macho, identifier, entitlements.as_deref(), credentials, None, None, self.allow_encrypted)?
}
```
  Doc comment on `ZSign::sign_macho`: direct-sign accepts FAT/Universal binaries (sha256-only default and dual path); adhoc mode rejects containers.
- [ ] **Step 4 — run green:** `TMPDIR=$PWD/.tmptmp cargo test -p zsign builder` AND the core gate. **Commit:** `fix(zsign): route fat direct-sign through fat-capable path (ZSN-33)`.

**Acceptance:** builder default signs a two-arch FAT (container + both signatures + sha256-only CDs via task 1), dual path works, adhoc fails closed.

---

### Task 9 (queue item 9, ZSN-13 + rider R2): execSeg — fileoff base + MAIN_BINARY coverage

**Files:** `crates/zsign-core/src/macho/parser.rs` (ArchSlice fields 114-141, init ~235-236, Segment64 ~270-272, Segment32 ~283-285, struct assign ~392-393), `crates/zsign-core/src/macho/signer.rs` (:825 emission, :1402 pin, tests), `crates/zsign-core/src/macho/fixtures.rs` (`make_minimal_dylib`).

- [ ] **Step 1 — failing tests:**

```rust
// parser.rs
#[test]
fn test_text_segment_fileoff_is_exposed() {
    let macho = MachOFile::parse(make_minimal_macho()).unwrap();
    let slice = &macho.slices()[0];
    assert_eq!(slice.text_segment_fileoff, 0x1000, "__TEXT fileoff of the fixture");
    assert_eq!(slice.text_segment_base, 0x1_0000_0000, "vmaddr arm stays for the verifier");
    assert_eq!(slice.text_segment_size, 0x1000, "file-backed size (the filesize rider field)");
}

// signer.rs
#[test]
fn test_exec_seg_main_binary_and_fileoff_base_on_every_fat_slice() {
    let mut b = make_minimal_macho();
    b[4..8].copy_from_slice(&0x0100_0007u32.to_le_bytes());
    let fat = make_fat_macho(&[make_minimal_macho(), b], &[12, 12]);
    let macho = MachOFile::parse(fat).unwrap();
    let creds = test_credentials();
    let signed = sign_any_macho(&macho, "com.zsign.execseg", None, &creds, None, None, false).unwrap();
    let m = MachOFile::parse(signed.clone()).unwrap();
    for (i, slice) in m.slices().iter().enumerate() {
        let sig = slice.code_sig_offset.unwrap() as usize;
        let size = slice.code_sig_size.unwrap() as usize;
        let blob = &signed[slice.offset + sig..slice.offset + sig + size];
        // primary CD: walk superblob entries (pattern from task 1), entry at CSSLOT_CODEDIRECTORY:
        let cd = <offset of the CodeDirectory entry inside blob>;
        let base = u64::from_be_bytes(blob[cd + 64..cd + 72].try_into().unwrap());
        let limit = u64::from_be_bytes(blob[cd + 72..cd + 80].try_into().unwrap());
        let flags = u64::from_be_bytes(blob[cd + 80..cd + 88].try_into().unwrap());
        assert_eq!(base, slice.text_segment_fileoff,
            "slice {i}: execSegBase must be __TEXT fileoff (Apple convention), got {base:#x}");
        assert_eq!(limit, slice.text_segment_size, "slice {i}: execSegLimit stays __TEXT.filesize");
        assert_ne!(flags & 0x1, 0,
            "slice {i}: CS_EXECSEG_MAIN_BINARY must be set on every MH_EXECUTE slice");
    }
}

#[test]
fn test_exec_seg_flags_zero_for_non_executable() {
    let macho = MachOFile::parse(make_minimal_dylib()).unwrap();
    let signed = sign_macho_adhoc(&macho, "com.zsign.dylib", None, None, None, false).unwrap();
    let m = MachOFile::parse(signed.clone()).unwrap();
    let sl = &m.slices()[0];
    let sig = sl.code_sig_offset.unwrap() as usize;
    let blob = &signed[sig..sig + sl.code_sig_size.unwrap() as usize];
    let cd = <primary CD offset in blob>;
    let flags = u64::from_be_bytes(blob[cd + 80..cd + 88].try_into().unwrap());
    assert_eq!(flags, 0, "non-executables must not claim CS_EXECSEG_MAIN_BINARY"); // contract lock
}
```
Plus **migrate the existing pin** `signer.rs:1402` `assert_eq!(exec_seg_base, 0x1_0000_0000)` → `assert_eq!(exec_seg_base, 0x1000)` with a one-line comment: `// Apple emits __TEXT.fileoff, not vmaddr (machorep.cpp execSegBase)`.

- [ ] **Step 2 — run red:** FAT test fails on `base == 0x1_0000_0000` (R2 proof) and the migrated pin fails; parser test fails (`text_segment_fileoff` doesn't exist yet — compile red is acceptable here, then re-run after adding the field to see the assertion red); dylib test is a contract lock (green pre-fix — flag logic already correct).
- [ ] **Step 3 — implement:**
  1. `parser.rs`: add to `ArchSlice`:
     ```rust
     /// File offset of the `__TEXT` segment (slice-relative). Emitted as
     /// `execSegBase` per Apple convention (`machorep.cpp`: `__TEXT.fileoff`).
     pub text_segment_fileoff: u64,
     ```
     init `text_segment_fileoff: 0` alongside `text_segment_base`; set it in both `Segment64` (`seg.fileoff`) and `Segment32` (`seg.fileoff as u64`) `__TEXT` arms; add to the struct literal. Update the existing field docs: `text_segment_base` → "Base virtual address of `__TEXT` (vmaddr — consumed by the verifier's exact-match arm; NOT emitted as execSegBase)"; `text_segment_size` → "File-backed size of `__TEXT` (`filesize`, zero-fill excluded) — the `execSegLimit` value and the `text_segment_filesize` member of the fileoff/filesize rider pair."
  2. `signer.rs:825`: `.exec_seg_base(slice.text_segment_fileoff)` (limit line unchanged). Leave the flag block 783-790 untouched (already Apple-parity — tests now lock it).
  3. `fixtures.rs`: `make_minimal_dylib()` = `make_minimal_macho()` bytes with `filetype` at offset **12..16** patched to `6u32.to_le_bytes()` (`MH_DYLIB` — `mach_header_64` layout: magic 0..4, cputype 4..8, cpusubtype 8..12, filetype 12..16, ncmds 16..20; same offset the wasm fixture uses at `zsign-wasm/src/lib.rs:1013`), doc comment stating its purpose.
- [ ] **Step 4 — run green** + full gate — the verifier suite is the compatibility proof: `exec_segment_range_mismatch_is_rejected`, `main_binary_flag_is_required_for_executables`, `test_exec_seg_limit_written_from_filesize`, `test_text_segment_size_is_file_backed_extent`, `test_big_endian_sign_parse_roundtrip`, `test_sign_then_verify_roundtrip` (via its migrated pin), plus facade `cargo test -p zsign verify` spot-run for the `errors.len()==1` tripwires. **Commit:** `fix(macho): emit exec seg base as text fileoff, lock main-binary flag (ZSN-33)`.

**Acceptance:** CD `execSegBase == __TEXT.fileoff` per slice (thin + every FAT slice); `MAIN_BINARY` set on every `MH_EXECUTE` slice and clear on the dylib; all verifier tests green (their `file_space_ok` arm accepts fileoff emission — traced in design §1.1).

---

### Task 10 (queue item 10, riders R1/R3): pass the signing reserve into realloc

**Files:** `crates/zsign-core/src/macho/writer.rs` (`realloc_code_sign_space_with_metadata` 977-1106 + its test callers), `crates/zsign-core/src/macho/signer.rs` (initial 419-456, retry 548-600, test).

- [ ] **Step 1 — failing tests:**

```rust
// writer.rs
#[test]
fn test_realloc_expands_to_cover_caller_reserve() {
    // just-fitting success + red proof that the reserve param is honored:
    let data = make_signed_minimal_macho(0x400);           // has an LC_CODE_SIGNATURE slot
    let macho = MachO::parse(&data, 0).unwrap();
    let md = metadata_for(&data, &macho);                   // existing test helper or build MachOMetadata via MachOFile::parse
    let code_length = <existing dataoff from md.code_sig_cmd>;
    let formula = calculate_signature_space(code_length) - code_length;
    let reserve = formula + 0x1000;                          // strictly larger than the formula
    let (out, out_md) = realloc_code_sign_space_with_metadata(&data, &md, code_length, reserve)
        .expect("realloc must honor a caller reserve larger than its formula");
    let sig_offset = (code_length + 15) & !15;
    assert!(out.len() >= sig_offset + reserve, "expanded buffer must cover sig_offset + reserve");
    let mut buf = out;
    let r = prepare_code_in_place(&mut buf, &out_md, code_length, reserve);
    // red pre-fix: prepare guard fires ("exceeds the N-byte buffer") because realloc
    // expanded only to its formula; post-fix: Ok
    r.expect("prepare with the same reserve must fit after realloc");
}

#[test]
fn test_realloc_reserve_smaller_than_prepare_reserve_fails_cleanly() {
    // genuine too-small reserve: realloc gets a small R, prepare declares bigger
    let data = make_signed_minimal_macho(0x400);
    ... realloc_code_sign_space_with_metadata(&data, &md, code_length, 0x100) ...
    let err = prepare_code_in_place(&mut buf, &out_md, code_length, 0x8000)
        .expect_err("reserve genuinely too small must stay a clean Err");
    assert!(err.to_string().contains("exceeds"), "{err}"); // contract lock
}

// signer.rs — R3 red→green:
#[test]
fn test_sign_with_large_entitlements_fits_reserve() {
    // ~20 KiB entitlements plist => tight estimate exceeds the formula reserve.
    let mut ent = String::from"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n");
    for i in 0..400 { ent.push_str(&format!("<key>com.example.pad{i}</key><string>{}</string>\n", "x".repeat(30))); }
    ent.push_str("</dict>\n</plist>\n");
    let macho = MachOFile::parse(make_minimal_macho()).unwrap();
    let creds = test_credentials();
    let first = sign_macho(&macho, "com.zsign.bigents", Some(ent.as_bytes()), &creds, None, None, false)
        .expect("tight-heavy estimate must be covered by realloc (R3)");   // RED pre-fix: Err "…exceeds the …-byte buffer"
    let m = MachOFile::parse(first.clone()).unwrap();
    let second = sign_macho(&m, "com.zsign.bigents", Some(ent.as_bytes()), &creds, None, None, false)
        .expect("re-sign of the signed output must succeed with the reserve flowing into realloc (R1/R3 window)");
}
```
(If the plist size needs tuning to push `tight` past the formula, adjust the loop bound and record the measured `estimate` vs `formula` in the run log — the assertion is the `expect`, not the number.)

- [ ] **Step 2 — run red:** writer test 1 fails in `prepare` with "exceeds the N-byte buffer" (reserve ignored); signer test fails the same way on first sign; writer test 2 is a contract lock (may pass pre-fix — record honestly).
- [ ] **Step 3 — implement:**
  1. `writer.rs` — signature and required computation:
     `pub fn realloc_code_sign_space_with_metadata(data: &[u8], metadata: &MachOMetadata, code_length: usize, estimated_signature_size: usize) -> Result<(Vec<u8>, MachOMetadata)>`
     In the body: `let sig_offset = align_to(code_length, 16);` then
     `let reserve_end = sig_offset.checked_add(estimated_signature_size).ok_or_else(|| Error::MachO("signature reserve end overflow".into()))?;`
     and fold `required = required.max(reserve_end)` into the existing `max(formula_end, declared_end)` (keep ZSN-32's early-return semantics: return unchanged only when `required <= data.len()`; expansion target stays `required`; `LC_CODE_SIGNATURE.datasize = required - sig_offset`). Update the fn doc: "…expanded so the buffer also covers `estimated_signature_size` bytes of signature reserve starting at the 16-aligned signature offset."
  2. `signer.rs` call sites: initial realloc (:424-428) passes the estimate computed at :419; the retry (:557-561) passes `padded_sig_size` (:552).
  3. Migrate every existing caller (grep `realloc_code_sign_space_with_metadata`): signer sites above; writer tests `test_realloc_refuses_insertion_across_first_section` (1629), `test_realloc_expands_to_cover_declared_reserve` (1760), `test_realloc_with_metadata_expands_to_cover_declared_reserve` (1786), `test_realloc_writes_aligned_dataoff_for_odd_code_length` (1904) — pass `calculate_signature_space(code_length) - code_length` (the formula) so their asserted behavior is unchanged, except where the test name says "declared reserve" in which case pass the declared/estimated value the test is about. No other callers exist (verified in research §1.1); `realloc_code_sign_space`/`_slice` twins are untouched by design (§2 item 10).
- [ ] **Step 4 — run green** + full gate + `TMPDIR=$PWD/.tmptmp cargo test -p zsign-core` (whole crate). **Commit:** `fix(macho): pass signing reserve into realloc (ZSN-33)`.

**Acceptance:** reserve-just-fitting writer flow succeeds (`len ≥ sig_offset + reserve`, prepare Ok); genuinely-too-small reserve stays a clean `Err`; the large-entitlements sign and re-sign both succeed (R3/R1 red→green); all migrated tests green with identical semantics.

---

## Plan self-review (executed before cold review)

- **Spec coverage:** design items 1-10 map 1:1 to tasks 1-10; fixtures (`make_fat_macho`, `make_minimal_dylib`) land in tasks 1 and 9 respectively; §4 acceptance table rows each have a named test; §5 follow-ups have no tasks (by design).
- **Placeholder scan:** test sketches with `<…>` markers are instructions to the Tester for values that depend on runtime parsing (superblob offsets, measured estimates) — each names exactly how to compute them; no `TBD`/`TODO`/stub code in any implementation step.
- **Type consistency:** `sign_all_slices_impl(..., sha256_only: bool)` used identically in tasks 1/2; `validate_fat_arches(&[FatArch], &[u8])` introduced task 6, consumed tasks 6/7; `SignedSlice.cpu_type: u32` introduced task 3, consumed tasks 3/7; `realloc_code_sign_space_with_metadata` 4-arg form task 10 consumed by all migrated callers; `text_segment_fileoff: u64` task 9 consumed by signer emission + tests.
- **Order safety:** each task's red tests only depend on tasks < it (queue order); task 8's red note honestly accounts for task 1 having already made the default branch green.
- **Skills:** implementation executes under subagent-driven-development (Tester red → implementer green → controller gate/commit per task); systematic-debugging applies to any red-that-should-be-green; no parallel dispatch (sequential queue, shared files).
