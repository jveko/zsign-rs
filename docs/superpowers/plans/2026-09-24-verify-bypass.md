# ZSN-24 Verify Bypass Fixes — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development
> with dispatching-parallel-agents for independent tasks to implement this plan
> task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
> Tasks are strictly sequential (all four touch the same two files) — batch
> size 1; no parallel implementers.

**Goal:** Close four verification bypasses in `zsign-core` so crafted
binaries cannot produce `verified: yes`.

**Architecture:** All fixes live inside `verify_slice`
(`crates/zsign-core/src/macho/verify.rs`) and `parse_superblob` /
`check_code_pages` (`crates/zsign-core/src/codesign/verify.rs`). Every
rejection is a `report.errors.push(...)` (keeps the `Ok(report)` contract);
parse-layer failures stay `Error::Verification`.

**Tech Stack:** Rust 2021 workspace, `cargo test -p zsign-core` scoped
filters, inline `#[cfg(test)] mod tests` (repo convention).

---

## Shared context (every task)

- Worktree: `/home/dimaz/workspace/projects/zsign-rs/.worktrees/zsn-24-verify-bypass`
- Scope: ONLY `crates/zsign-core/src/macho/verify.rs` and
  `crates/zsign-core/src/codesign/verify.rs`. Never edit `.gitignore`,
  `crypto/cms_verify.rs`, `crates/zsign/src/verify.rs`, `signer.rs`,
  `writer.rs`, `constants.rs`, or the CLI. Read-only reference is fine.
- Every full-suite run MUST append `-- --skip test_ipa_signing_is_deterministic`
  (known pre-existing failure, ZSN-15).
- Never run `cargo fmt` / `cargo clippy` / `hk` — the orchestrator gates at
  merge; commits trigger the pre-commit hook automatically.
- TDD rule: the regression test MUST be observed RED (failing against
  unfixed code) before the fix is applied, then GREEN. Paste both outputs.
- Commit style: conventional, imperative, lowercase subject, ticket allowed
  in subject only. Commits are made by the controller (not subagents).
- Design doc (authoritative rationale): `docs/superpowers/specs/2026-09-24-verify-bypass-design.md`.

## Test helper (introduced in Task 1, reused by Tasks 2 and 4)

Add to `crates/zsign-core/src/macho/verify.rs` `mod tests`:

```rust
    /// Offset of the child blob whose header carries `slot`, relative to the
    /// SuperBlob start.
    fn entry_offset(sb: &[u8], slot: u32) -> Option<usize> {
        let count = u32::from_be_bytes(sb[8..12].try_into().unwrap()) as usize;
        (0..count).find_map(|i| {
            let e = 12 + i * 8;
            let s = u32::from_be_bytes(sb[e..e + 4].try_into().unwrap());
            (s == slot).then(|| u32::from_be_bytes(sb[e + 4..e + 8].try_into().unwrap()) as usize)
        })
    }
```

Extend the existing test imports to include `CSSLOT_CODEDIRECTORY`:

```rust
    use crate::codesign::constants::{
        CSSLOT_CODEDIRECTORY, CSSLOT_SIGNATURESLOT, CSMAGIC_EMBEDDED_SIGNATURE,
    };
```

---

### Task 1: Empty-CMS signature-strip bypass

**Files:**
- Modify: `crates/zsign-core/src/macho/verify.rs` (CMS block ~:168-197, top imports ~:10-13, `mod tests`)
- Test: same file, new `#[test] non_adhoc_truncated_cms_is_rejected`

- [ ] **Step 1: Write the failing test** (append to `mod tests`)

```rust
    #[test]
    fn non_adhoc_truncated_cms_is_rejected() {
        let creds = rsa_credentials();
        let mut signed = sign_round_trip(&creds, "com.example.trunc");
        let m = MachOFile::parse(signed.clone()).unwrap();
        let sl = &m.slices()[0];
        let sig_off = sl.code_sig_offset.unwrap() as usize;
        let sig_len = sl.code_sig_size.unwrap() as usize;

        // Truncate the CMS child to its 8-byte blob-wrapper header, leaving
        // everything else intact.
        let sb = &mut signed[sig_off..sig_off + sig_len];
        let cms_off = entry_offset(sb, CSSLOT_SIGNATURESLOT).expect("CMS entry");
        sb[cms_off + 4..cms_off + 8].copy_from_slice(&8u32.to_be_bytes());

        let report = verify_macho(&signed, &SignatureInputs::none()).unwrap();
        let slice = &report.slices[0];
        assert!(!slice.adhoc, "credential-signed CD must stay non-ad-hoc");
        assert!(
            !report.is_valid(),
            "8-byte CMS wrapper on a non-ad-hoc CD must not verify: {:?}",
            slice.errors
        );
        assert!(
            slice.errors.iter().any(|e| e.contains("empty CMS wrapper")),
            "expected the empty-wrapper rejection, got {:?}",
            slice.errors
        );
    }
```

- [ ] **Step 2: Run and confirm RED**

Run: `cargo test -p zsign-core non_adhoc_truncated_cms`
Expected: FAIL at `assert!(!report.is_valid(), ...)` — pre-fix the
`len() <= 8` shortcut returns `adhoc_report()` and `errors` is empty.

- [ ] **Step 3: Fix** — add the constant import at the top of
`macho/verify.rs` (after the `codesign::verify` use block, ~:13):

```rust
use crate::codesign::constants::CSMAGIC_BLOBWRAPPER;
```

Replace the shortcut (macho/verify.rs:170-174) with:

```rust
    if let Some(cms_blob) = superblob.cms {
        let empty_wrapper =
            cms_blob.len() == 8 && cms_blob[0..4] == CSMAGIC_BLOBWRAPPER.to_be_bytes();
        if empty_wrapper {
            if primary.is_adhoc() {
                report.cms = Some(crate::crypto::cms_verify::adhoc_report());
            } else {
                report
                    .errors
                    .push("empty CMS wrapper but not ad-hoc flagged".into());
            }
            return Ok(report);
        }

        let cd_sha256: [u8; 32] = primary.cdhash_sha256();
        // ... existing verify_code_signature path unchanged ...
```

Update the block comment above (`// CMS signature. An empty signature
slot...`) to state the two conditions (exact 8-byte wrapper + CS_ADHOC).
Leave the `cms == None` branch untouched.

- [ ] **Step 4: Run and confirm GREEN**

Run: `cargo test -p zsign-core non_adhoc_truncated_cms`
Expected: PASS.

- [ ] **Step 5: Scoped gate**

Run: `cargo test -p zsign-core verify -- --skip test_ipa_signing_is_deterministic`
Expected: all PASS (round-trip, tampered-CMS, special-slots, unsigned tests
unaffected — they use full CMS or no slot).

- [ ] **Step 6: Controller commit**

`fix: require ad-hoc flag for empty cms wrapper (ZSN-24)`

---

### Task 2: FAT cross-slice page check

**Files:**
- Modify: `crates/zsign-core/src/macho/verify.rs` (`check_code_pages_in_file` ~:205-213, call site ~:141, `mod tests`)
- Test: same file, new `#[test] fat_code_limit_beyond_slice_is_rejected` + FAT builder helper

- [ ] **Step 1: Write the failing test**

Add a two-slice FAT builder (header pattern from
`signer.rs:1230-1258`; `make_minimal_macho()` slices are exactly 0x2000
bytes so fixed offsets 0x1000/0x3000 work):

```rust
    fn build_two_slice_fat() -> Vec<u8> {
        let a = make_minimal_macho();
        let b = make_minimal_macho();
        let mut out = Vec::new();
        out.extend_from_slice(&0xcafebabeu32.to_be_bytes()); // FAT_MAGIC
        out.extend_from_slice(&2u32.to_be_bytes());
        for (offset, size) in [(0x1000u32, a.len() as u32), (0x3000u32, b.len() as u32)] {
            out.extend_from_slice(&0x0100_000cu32.to_be_bytes()); // CPU_TYPE_ARM64
            out.extend_from_slice(&0u32.to_be_bytes());
            out.extend_from_slice(&offset.to_be_bytes());
            out.extend_from_slice(&size.to_be_bytes());
            out.extend_from_slice(&12u32.to_be_bytes()); // align 2^12
        }
        out.resize(0x1000, 0);
        out.extend_from_slice(&a);
        out.resize(0x3000, 0);
        out.extend_from_slice(&b);
        out
    }

    #[test]
    fn fat_code_limit_beyond_slice_is_rejected() {
        let fat = build_two_slice_fat();
        let macho = MachOFile::parse(fat).unwrap();
        assert_eq!(macho.slices().len(), 2);
        let creds = rsa_credentials();
        let mut signed =
            sign_any_macho(&macho, "com.example.fat", None, &creds, None, None, false).unwrap();

        // Trailing pad: slice 2's tail (pre-fix data[offset..]) must outlive
        // its declared fat_arch size so an oversized codeLimit fits the tail.
        signed.extend_from_slice(&[0u8; 0x1000]);

        let m = MachOFile::parse(signed.clone()).unwrap();
        let s = &m.slices()[1];
        let slice_off = s.offset as usize;
        let slice_size = s.size as usize;
        let tail_len = signed.len() - slice_off;
        let sig_off = slice_off + s.code_sig_offset.unwrap() as usize;
        let sig_len = s.code_sig_size.unwrap() as usize;

        // Neutralize CMS binding: shrink the CMS child to the 8-byte wrapper
        // (pre-fix shortcut keeps the slice green; post-fix the page error is
        // asserted specifically, since the wrapper also trips Task 1's error).
        let cms = entry_offset(&signed[sig_off..sig_off + sig_len], CSSLOT_SIGNATURESLOT)
            .expect("CMS entry")
            + sig_off;
        signed[cms + 4..cms + 8].copy_from_slice(&8u32.to_be_bytes());

        // Patch the primary CD: 8 KiB pages, codeLimit past the slice.
        let cd = entry_offset(&signed[sig_off..sig_off + sig_len], CSSLOT_CODEDIRECTORY)
            .expect("primary CD entry")
            + sig_off;
        let n_slots =
            u32::from_be_bytes(signed[cd + 28..cd + 32].try_into().unwrap()) as usize;
        let hash_offset =
            u32::from_be_bytes(signed[cd + 16..cd + 20].try_into().unwrap()) as usize;
        let hash_size = signed[cd + 36] as usize;
        assert_eq!(hash_size, 32, "primary CD must be SHA-256");

        let c_prime = (slice_size + 0x100) as u32;
        // Fixture invariant (design doc): slice.size < C' <= tail_len and the
        // stored slot count must still match the region at the new page size.
        assert!((c_prime as usize) <= tail_len, "C' must fit the tail");
        assert_eq!(
            (c_prime as usize).div_ceil(1 << 13),
            n_slots,
            "slot count must be unchanged at 8 KiB pages"
        );

        signed[cd + 39] = 13; // page_size_log2: 4 KiB -> 8 KiB
        signed[cd + 32..cd + 36].copy_from_slice(&c_prime.to_be_bytes());
        // Recompute every code slot over the tail region at the new page size
        // so pre-fix verification is internally consistent (Matched).
        for i in 0..n_slots {
            let start = i << 13;
            let end = (((i + 1) << 13).min(c_prime as usize)).max(start + 1);
            let d = Sha256::digest(&signed[slice_off + start..slice_off + end]);
            let at = cd + hash_offset + i * hash_size;
            signed[at..at + hash_size].copy_from_slice(&d);
        }

        let report = verify_macho(&signed, &SignatureInputs::none()).unwrap();
        assert_eq!(report.slices.len(), 2);
        assert!(
            report.slices[0].is_valid(),
            "first slice is untouched: {:?}",
            report.slices[0].errors
        );
        // Assert the page error specifically (not merely !is_valid): the
        // post-fix wrapper error from Task 1 would make a nonempty-errors
        // assertion ambiguous.
        assert!(
            report.slices[1]
                .errors
                .iter()
                .any(|e| e.contains("code slot count mismatch")),
            "codeLimit beyond the slice must fail the page check, got {:?}",
            report.slices[1].errors
        );
        assert!(!report.is_valid());
    }
```

Notes for the implementer:
- `sign_any_macho` is `pub` in `crate::macho::signer`; import from
  `crate::macho` per how the module re-exports (check `macho/mod.rs`;
  fall back to `crate::macho::signer::sign_any_macho`).
- Slot recompute loop guard: if `end == start` cannot occur because
  `c_prime > 0`; `.max(start + 1)` only defends an off-by-one if
  `c_prime` lands on a page boundary — keep it.
- If the `slot count must be unchanged` assertion fails empirically the
  signed CMS is larger than 8 KiB headroom allows: fall back to
  `page_size_log2 = 14` (16 KiB) with `c_prime` chosen so
  `div_ceil(c_prime, 1 << 14) == n_slots` and `c_prime > slice_size`
  (requires additional trailing pad), adjusting the recompute shifts to
  `<< 14`. Record which variant was used in the report.

- [ ] **Step 2: Run and confirm RED**

Run: `cargo test -p zsign-core fat_code_limit_beyond_slice`
Expected: FAIL at `assert!(... any(contains("code slot count mismatch")))` —
pre-fix the oversized codeLimit is checked against the whole tail and all
recomputed slots match, so `slices[1].errors` is empty.

- [ ] **Step 3: Fix** — change the wrapper (macho/verify.rs:205-213) and
its call site (:141):

```rust
    report.pages = check_code_pages_in_file(primary, data, slice);
```

```rust
/// Page check variant that reads exactly the slice's byte range from the
/// file, using the CodeDirectory `codeLimit` as authoritative. A codeLimit
/// beyond the slice therefore overruns the bounded region and reports
/// `CountMismatch` instead of hashing the next architecture.
fn check_code_pages_in_file(
    cd: &CodeDirectory<'_>,
    data: &[u8],
    slice: &crate::macho::ArchSlice,
) -> PageCheck {
    let Some(range) = slice
        .offset
        .checked_add(slice.size)
        .and_then(|end| data.get(slice.offset..end))
    else {
        return PageCheck::CountMismatch {
            stored: cd.n_code_slots as usize,
            computed: 0,
        };
    };
    check_code_pages(cd, range)
}
```

No other changes: `check_code_pages`'s existing
`code_limit > code.len()` guard (codesign/verify.rs:403-408) now fires
against the bounded slice and `verify_slice` already pushes
`CountMismatch` as an error.

- [ ] **Step 4: Run and confirm GREEN**

Run: `cargo test -p zsign-core fat_code_limit_beyond_slice`
Expected: PASS (post-fix: bounded region shorter than `codeLimit` →
`CountMismatch` → `"code slot count mismatch"` pushed).

- [ ] **Step 5: Scoped gate**

Run: `cargo test -p zsign-core verify -- --skip test_ipa_signing_is_deterministic`
Expected: all PASS — thin binaries are unaffected (thin `slice.size` =
whole file, so the bound equals the old tail).

- [ ] **Step 6: Controller commit**

`fix: bound fat page check to the architecture slice (ZSN-24)`

---

### Task 3: SuperBlob parsing hardening

**Files:**
- Modify: `crates/zsign-core/src/codesign/verify.rs` (`parse_superblob` ~:60-116, `mod tests`)
- Test: same file, four new `#[test]` cases

- [ ] **Step 1: Write the failing tests** (append to `mod tests`)

```rust
    /// Minimal SuperBlob: header + `entries` index + child regions.
    /// `children` = (offset, item_len) pairs placed verbatim; child magic
    /// bytes are written by the caller afterwards.
    fn synth_superblob(total: u32, entries: &[(u32, u32)]) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&CSMAGIC_EMBEDDED_SIGNATURE.to_be_bytes());
        b.extend_from_slice(&total.to_be_bytes());
        b.extend_from_slice(&(entries.len() as u32).to_be_bytes());
        for (slot, off) in entries {
            b.extend_from_slice(&slot.to_be_bytes());
            b.extend_from_slice(&off.to_be_bytes());
        }
        b.resize(total as usize, 0);
        b
    }

    #[test]
    fn superblob_shorter_declared_length_is_rejected() {
        // Declared total below the index extent: pre-fix this parses
        // because bytes 4..8 are never read.
        let mut b = build_blob(true);
        b[4..8].copy_from_slice(&4u32.to_be_bytes());
        assert!(parse_superblob(&b).is_err(), "declared length below index extent");

        // Declared length past the actual buffer.
        let mut b = build_blob(true);
        let len = b.len() as u32;
        b[4..8].copy_from_slice(&(len + 64).to_be_bytes());
        assert!(parse_superblob(&b).is_err(), "declared length overruns buffer");

        // Declared length inside the index but with children beyond it:
        // bound all reads to blob[..declared].
        let mut b = build_blob(true);
        let count = u32::from_be_bytes(b[8..12].try_into().unwrap());
        let index_end = 12 + count * 8;
        b[4..8].copy_from_slice(&(index_end + 4).to_be_bytes());
        assert!(parse_superblob(&b).is_err(), "children outside declared length");
    }

    #[test]
    fn superblob_entry_inside_header_is_rejected() {
        // Child offset 0 aliases the SuperBlob header itself.
        let b = synth_superblob(40, &[(0, 0)]);
        assert!(parse_superblob(&b).is_err(), "entry inside header/index");
    }

    #[test]
    fn superblob_short_child_is_rejected() {
        // Valid index (12 + 8 = 20), child at 20 declares item_len 4 (< 8).
        let mut b = synth_superblob(28, &[(0, 20)]);
        b[20..24].copy_from_slice(&0xfade0c00u32.to_be_bytes());
        b[24..28].copy_from_slice(&4u32.to_be_bytes());
        assert!(parse_superblob(&b).is_err(), "item_len < 8");
    }

    #[test]
    fn superblob_overlapping_children_are_rejected() {
        // Index ends at 28. Child A [28,44), child B [36,44) — B sits
        // inside A; duplicates would overlap identically.
        let mut b = synth_superblob(44, &[(0, 28), (1, 36)]);
        b[28..32].copy_from_slice(&0xfade0c00u32.to_be_bytes());
        b[32..36].copy_from_slice(&16u32.to_be_bytes());
        b[36..40].copy_from_slice(&0xfade0c01u32.to_be_bytes());
        b[40..44].copy_from_slice(&8u32.to_be_bytes());
        assert!(parse_superblob(&b).is_err(), "overlapping children");
    }
```

- [ ] **Step 2: Run and confirm RED**

Run: `cargo test -p zsign-core superblob_`
Expected: 4 FAILURES — every case parses successfully pre-fix (declared
length ignored; no header/index, item_len-floor, or overlap checks).

- [ ] **Step 3: Fix** — rewrite the head of `parse_superblob`
(codesign/verify.rs:60-101):

```rust
pub fn parse_superblob(blob: &[u8]) -> Result<SuperBlob<'_>> {
    if blob.len() < 12 {
        return Err(crate::Error::Verification(
            "code signature blob too short for SuperBlob header".into(),
        ));
    }
    if blob[0..4] != CSMAGIC_EMBEDDED_SIGNATURE.to_be_bytes() {
        return Err(crate::Error::Verification(
            "not an embedded signature SuperBlob (magic mismatch)".into(),
        ));
    }

    // The declared total length bounds every subsequent read; trailing bytes
    // in the LC window beyond it are tolerated (third-party pad) but never
    // parsed.
    let declared = u32::from_be_bytes(blob[4..8].try_into().unwrap()) as usize;
    if declared > blob.len() {
        return Err(crate::Error::Verification(format!(
            "SuperBlob declared length ({declared}) overruns blob of {} bytes",
            blob.len()
        )));
    }
    let sb = &blob[..declared];

    let count = u32::from_be_bytes(sb[8..12].try_into().unwrap()) as usize;
    let index_end = count
        .checked_mul(8)
        .and_then(|e| e.checked_add(12))
        .ok_or_else(|| crate::Error::Verification("SuperBlob index extent overflow".into()))?;
    if index_end > declared {
        return Err(crate::Error::Verification(format!(
            "SuperBlob index ({} entries) overruns declared length of {declared} bytes",
            count
        )));
    }

    let mut entries = Vec::with_capacity(count);
    let mut ranges: Vec<(usize, usize)> = Vec::with_capacity(count);
    for i in 0..count {
        let entry_off = 12 + i * 8;
        let slot = u32::from_be_bytes(sb[entry_off..entry_off + 4].try_into().unwrap());
        let offset =
            u32::from_be_bytes(sb[entry_off + 4..entry_off + 8].try_into().unwrap()) as usize;
        if offset < index_end {
            return Err(crate::Error::Verification(format!(
                "SuperBlob entry {i} (slot 0x{slot:08x}) points inside the header/index"
            )));
        }
        let Some(item) = sb.get(offset..).filter(|b| b.len() >= 8) else {
            return Err(crate::Error::Verification(format!(
                "SuperBlob entry {i} (slot 0x{slot:08x}) points outside the blob"
            )));
        };
        // Each blob carries its own magic+length header; bound it precisely so
        // hashing a slot blob never implicitly includes later blobs.
        let item_len = u32::from_be_bytes(item[4..8].try_into().unwrap()) as usize;
        if item_len < 8 {
            return Err(crate::Error::Verification(format!(
                "SuperBlob entry {i} (slot 0x{slot:08x}) declares a {item_len}-byte blob"
            )));
        }
        let end = offset
            .checked_add(item_len)
            .filter(|end| *end <= declared)
            .ok_or_else(|| {
                crate::Error::Verification(format!(
                    "SuperBlob entry {i} (slot 0x{slot:08x}) length overruns blob"
                ))
            })?;
        ranges.push((offset, end));
        entries.push(SlotEntry {
            slot,
            blob: &sb[offset..end],
        });
    }

    // Children must be pairwise disjoint (duplicates overlap identically).
    ranges.sort_unstable();
    for pair in ranges.windows(2) {
        if pair[1].0 < pair[0].1 {
            return Err(crate::Error::Verification(format!(
                "SuperBlob entries at {} and {} overlap",
                pair[0].0, pair[1].0
            )));
        }
    }

    // ... slot dispatch loop unchanged (iterates &entries) ...
    Ok(SuperBlob { entries, code_directory, alternate_code_directories, cms })
}
```

Note: `ranges` must be collected in the entry loop *before* sorting, and
the second loop (slot dispatch, codesign/verify.rs:106-122) stays as-is.
Doc comment of `parse_superblob` gets the new error conditions listed.

- [ ] **Step 4: Run and confirm GREEN**

Run: `cargo test -p zsign-core superblob_`
Expected: 4 PASS.

- [ ] **Step 5: Scoped gate**

Run: `cargo test -p zsign-core verify -- --skip test_ipa_signing_is_deterministic`
Expected: all PASS — `build_superblob` writes the exact total length
(superblob.rs:160-167) and the writer records `datasize = signature.len()`
(writer.rs:921-924), so own signer output satisfies the new bounds;
`rejects_garbage` still fails on magic.

- [ ] **Step 6: Controller commit**

`fix: harden superblob parsing against malformed structures (ZSN-24)`

---

### Task 4: Zero-coverage CodeDirectory accepted

**Files:**
- Modify: `crates/zsign-core/src/macho/verify.rs` (page match arm ~:142-153, `mod tests`)
- Modify: `crates/zsign-core/src/codesign/verify.rs` (:406 diagnostic)
- Test: `macho/verify.rs` new `#[test] zero_code_coverage_is_rejected`

- [ ] **Step 1: Write the failing test**

```rust
    #[test]
    fn zero_code_coverage_is_rejected() {
        let macho = MachOFile::parse(make_minimal_macho()).unwrap();
        let signed = sign_macho_adhoc(
            &macho,
            "com.example.zero",
            None,
            None,
            None,
            false,
        )
        .unwrap();

        // Collapse the primary CD to zero coverage: nCodeSlots = 0,
        // codeLimit = 0.
        let m = MachOFile::parse(signed.clone()).unwrap();
        let sl = &m.slices()[0];
        let sig_off = sl.code_sig_offset.unwrap() as usize;
        let sig_len = sl.code_sig_size.unwrap() as usize;
        let sb = &signed[sig_off..sig_off + sig_len];
        let cd = entry_offset(sb, CSSLOT_CODEDIRECTORY).expect("primary CD entry");
        let signed_slice = &mut signed[sig_off..sig_off + sig_len];
        signed_slice[cd + 28..cd + 32].copy_from_slice(&0u32.to_be_bytes()); // nCodeSlots
        signed_slice[cd + 32..cd + 36].copy_from_slice(&0u32.to_be_bytes()); // codeLimit

        let report = verify_macho(&signed, &SignatureInputs::none()).unwrap();
        let slice = &report.slices[0];
        assert!(
            slice.errors.iter().any(|e| e.contains("zero code bytes")),
            "zero-coverage CD must be rejected, got {:?}",
            slice.errors
        );
        assert!(!report.is_valid());
    }
```

Ad-hoc signing (no CMS payload) keeps the mutated CD free of CDHash
binding; the 8-byte wrapper still takes the Task-1 ad-hoc path (flag set
by the signer), so the only new error is the zero-coverage one.

- [ ] **Step 2: Run and confirm RED**

Run: `cargo test -p zsign-core zero_code_coverage`
Expected: FAIL — pre-fix `PageCheck::Empty` shares the pass arm with
`Matched` (macho/verify.rs:142-143), `errors` is empty.

- [ ] **Step 3: Fix (a)** — macho/verify.rs match arm becomes:

```rust
    match &report.pages {
        PageCheck::Matched => {}
        PageCheck::Empty => {
            report
                .errors
                .push("code directory covers zero code bytes".into());
        }
        PageCheck::Mismatch { page_index } => { /* unchanged */ }
        PageCheck::CountMismatch { stored, computed } => { /* unchanged */ }
    }
```

- [ ] **Step 4: Fix (b)** — codesign/verify.rs:406 diagnostic uses the
directory's page size (the `page_size` local from :399):

```rust
            computed: region_len.div_ceil(page_size),
```

`PAGE_SIZE` (the constant) keeps its other legitimate uses; this is the
only hardcode inside `check_code_pages`.

- [ ] **Step 5: Run and confirm GREEN**

Run: `cargo test -p zsign-core zero_code_coverage`
Expected: PASS with `"code directory covers zero code bytes"`.

- [ ] **Step 6: Scoped gate + whole-workspace proof**

Run: `cargo test -p zsign-core verify -- --skip test_ipa_signing_is_deterministic`
Expected: all PASS.

Run: `cargo test --workspace -- --skip test_ipa_signing_is_deterministic`
Expected: all PASS — the only `PageCheck::Empty` matches outside scope are
display-only (cli main.rs:236/:328); no caller outside scope asserts
`Empty` validity (scout-verified).

- [ ] **Step 7: Controller commit**

`fix: reject code directories with zero coverage (ZSN-24)`

---

## Final verification (controller, after all four commits)

1. `cargo test --workspace -- --skip test_ipa_signing_is_deterministic`
   → paste verbatim output as report evidence.
2. `git log --oneline` → four commits, none touching out-of-scope files:
   `git diff ee42c12..HEAD --stat` must list only
   `crates/zsign-core/src/macho/verify.rs`,
   `crates/zsign-core/src/codesign/verify.rs`, and the two force-added docs.
3. Confirm RED-before-fix evidence for each regression test is in the
   report (subagent transcripts / captured outputs).
4. Do NOT merge, do NOT push, do NOT run fmt/clippy/hk.

## Plan-vs-expected deviations log

Record here during execution (e.g. if Task 2 needs the `page_size_log2 = 14`
fallback, or exact fixture offsets differ): each deviation needs its reason.
