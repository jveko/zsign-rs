# ZSN-24 Verify Bypass Fixes — Design

**Date:** 2026-09-25
**Branch:** `zsn-24-verify-bypass` · **Base:** `ee42c12`
**Scope:** `crates/zsign-core/src/macho/verify.rs`, `crates/zsign-core/src/codesign/verify.rs` (+ inline tests only)

## Problem

A verified 8-agent review found four independent verification bypasses in
`zsign-core`. Items 1, 3, and 4 let a crafted binary produce a slice report
with no findings — `SliceVerifyReport::is_valid()` is `errors.is_empty()`
(macho/verify.rs:42-44) — and the whole-binary
`MachOVerifyReport::is_valid()` requires a non-empty slice list where every
slice is valid (macho/verify.rs:58-60):

1. **Empty-CMS strip.** `verify_slice` short-circuits any CMS slot of
   `len() <= 8` to `adhoc_report()` (valid=true) without checking
   `primary.is_adhoc()` (macho/verify.rs:170-174). The `cms == None` branch
   (macho/verify.rs:192-197) correctly requires `is_adhoc`. Truncating an
   identity signature to an 8-byte wrapper header yields "verified: yes".
2. **FAT cross-slice page check.** `check_code_pages_in_file` passes
   `data[offset..]` — everything from the slice to EOF — instead of the
   slice's own range (macho/verify.rs:205-213). A `codeLimit` beyond
   `slice.size` therefore hashes bytes of the *next* architecture (or
   trailing file bytes) and reports its diagnostics over the wrong region:
   the page count is derived from the tail (`ceil(C'/page)` over
   `tail_len`), not from the slice. Note: a *successful* (`Matched`) check
   under this condition is not constructible for our own output — the
   parser forces the LC signature (and thus the CodeDirectory and its
   stored slot hashes) to lie inside `slice.size` (parser.rs:269-278), so
   once `codeLimit > slice.size` the hashed region covers the slot storage
   itself and the count or the page hash can never be satisfied — but the
   check still reads across the slice boundary, and its reported page count
   and hashed byte range are wrong (test-strategy item 2 pins this
   observable difference).
3. **SuperBlob parsing gaps.** `parse_superblob` (codesign/verify.rs:60-116)
   never reads the declared total-length field (blob[4..8]); `12 + count * 8`
   (line 73) is unchecked arithmetic (wraps on wasm32, where
   `count: usize = u32 as usize`); children may point into the header/index,
   be zero-length (`item_len` is only bounded above, never below), or overlap
   each other.
4. **Zero-coverage CD accepted.** `PageCheck::Empty`
   (`expected_slots == 0`, e.g. `codeLimit = 0`, codesign/verify.rs:418-419)
   is accepted as a pass alongside `Matched` in `verify_slice`
   (macho/verify.rs:142-143) — a CodeDirectory covering zero code bytes
   verifies. The over-declaration diagnostic (codesign/verify.rs:406)
   hardcodes `PAGE_SIZE` (4096) instead of `1 << cd.page_size_log2`.

## Chosen designs (per queue item)

### Item 1 — Empty-CMS signature-strip bypass

**Chosen (A):** gate the shortcut on *both* conditions inside `verify_slice`:

- Accept the ad-hoc shortcut only when `cms_blob.len() == 8` **and** the
  first four bytes equal `CSMAGIC_BLOBWRAPPER.to_be_bytes()` **and**
  `primary.is_adhoc()`; then set `adhoc_report()` as today.
- Exactly-8-byte wrapper on a **non-ad-hoc** CD → push
  `"empty CMS wrapper but not ad-hoc flagged"` (mirrors the existing
  `"no CMS signature slot but not ad-hoc flagged"` phrasing) and return.
- Anything else (len ≠ 8, wrong magic) falls through to
  `verify_code_signature`, which already rejects short/wrong-magic blobs
  (cms_verify.rs:281-297).

**Alternatives:**

- **B — shared helper** `is_empty_adhoc_wrapper()` used by both the
  shortcut and the `cms == None` branch: DRY, but the two sites test
  different things (absent slot vs. present wrapper); a shared predicate
  would obscure that. Rejected.
- **C — reject at `parse_superblob`:** wrong layer; parse must stay
  structural (magic/bounds), and the ad-hoc flag lives on the CodeDirectory,
  not the wrapper. Rejected.

**Evidence:** our signer's ad-hoc output *is* exactly the 8-byte
`CSMAGIC_BLOBWRAPPER` header (`build_adhoc_signature_blob`,
superblob.rs:486-493; slot always present, signer.rs:535), so own ad-hoc
output keeps passing. Credential-signed output has a non-empty wrapper, so
it takes the CMS path unchanged.

### Item 2 — FAT cross-slice page check

**Chosen (A):** `check_code_pages_in_file` takes the `&ArchSlice` instead of
a bare `offset` and passes **exactly** `data[slice.offset..slice.offset+slice.size]`
via `checked_add` + `data.get(..)`; an unrepresentable/out-of-file range
returns `CountMismatch { computed: 0 }` (same shape as today's fallback).
With the slice-bounded input, `check_code_pages`'s existing
`code_limit > code.len()` guard (codesign/verify.rs:403-408) fires for a CD
whose `codeLimit` exceeds the slice and returns `CountMismatch`, which
`verify_slice` already pushes as an error — error, never a silent clip
(`region_len = min(...)`, codesign/verify.rs:401, only runs when
`code_limit <= code.len()`).

**Alternatives:**

- **B — delete the wrapper, inline the bound in `verify_slice`:** marginally
  less code, but the wrapper carries the documented "read region straight
  from the file using codeLimit" contract and a single call site; changing
  its parameter is the smaller diff. Rejected.
- **C — dedicated `"codeLimit exceeds slice"` message with a pre-gate:**
  nicer prose, but duplicates a guard that already produces a correct error
  and adds a branch that can desync from `check_code_pages`. The brief
  requires *an* error (not a clip); a distinct message is only mandated for
  item 4's Empty case. Rejected (minimal change wins).

**Bounds safety:** the parser already validates FAT slice ranges and that
`LC_CODE_SIGNATURE` fits inside the declared slice (parser.rs:164-190,
269-278), so the `checked_add`/`get` fallback is defense in depth.

### Item 3 — SuperBlob parsing hardening

**Chosen (A):** strict structural validation in `parse_superblob`, all
computed with `checked_mul`/`checked_add`:

1. Read the declared total length `L = u32(blob[4..8])`.
2. Read `count` from `blob[8..12]` — safe because `blob.len() >= 12` was
   already checked — and compute `index_end = 12 + count*8` with
   `checked_mul`/`checked_add` (overflow → error). Require
   `index_end <= L` **and** `L <= blob.len()` (trailing bytes in the LC
   window tolerated). Because `index_end >= 12`, this rejects `L < 12`
   *before* any slicing, so `&blob[..L]` is always at least the header.
3. Bound **all** subsequent reads (index and children) to `&blob[..L]`.
4. Reject: child `offset` inside the header/index (`offset < 12 + count*8`),
   `item_len < 8`, `offset + item_len > L`, and any pair of child ranges
   that overlap (sort by start, compare adjacent — duplicates overlap too).

**Alternatives:**

- **B — checked arithmetic only** (no overlap/zero-length/entry-region
  checks): closes the wasm32 wrap but leaves children free to alias the
  index or each other. Insufficient per brief. Rejected.
- **C — require `L == blob.len()` exactly:** our own writer records the
  *reserved* signature space as the LC datasize (`sig_datasize =
  new_length - code_length`, writer.rs:910/919-924), so the LC window is
  regularly **larger** than the embedded SuperBlob — strict equality would
  reject our own signed output (only one embed path sizes the window to
  the exact signature, writer.rs:396). Rejected outright: not merely a
  third-party tolerance, it is the compatibility mechanism for own output.

**Compatibility:** `build_superblob` writes the true total into `blob[4..8]`
(superblob.rs:160-167), so our own signed output satisfies (1)-(4) by
construction (offsets are cumulative + 4-byte aligned → strictly
non-overlapping), and `L <= blob.len()` absorbs the LC window's reserved
padding (see alternative C).

### Item 4 — Zero-coverage CD accepted

**Chosen (A):** keep the `PageCheck::Empty` variant (it is public API with
display-only consumers in the CLI, main.rs:236/328, and is the
`#[default]` of `SliceVerifyReport::pages`), but in `verify_slice` give it
its own arm that pushes a distinct error, e.g.
`"code directory covers zero code bytes"` — instead of the current
`Matched | Empty => {}`. `codeLimit == 0` / `nCodeSlots == 0` therefore
produces `Empty` → error. Fix the diagnostic at codesign/verify.rs:406 to
`region_len.div_ceil(1 << cd.page_size_log2)` (the `page_size` local
already computed at line 399).

**Alternatives:**

- **B — remove the `Empty` variant entirely:** forces every consumer
  (including out-of-scope CLI display code) to restructure; the default
  value of `pages` would need a new variant. More churn for no gain.
  Rejected.
- **C — reject inside `check_code_pages` itself (return `Mismatch`):**
  blurs a structural fact (zero coverage) into a hash failure and changes
  a public function's contract for direct callers/tests. Rejected.

**Note:** slices that return early (no LC, no SuperBlob, no primary CD)
never reach the page check, so their default `Empty` is unaffected.

## Invariants

- Two distinct rejection channels, used consistently: **semantic
  verification findings** (page mismatch, ad-hoc flag violations, empty
  coverage) are `report.errors.push(...)` inside `verify_slice`, preserving
  its `Ok(report)` contract so `verify_macho` keeps returning `Ok` for
  parseable Mach-Os; **structural malformations** detected by the public
  `parse_superblob` return `Error::Verification` (next bullet).
- All structural parse failures stay `Error::Verification` inside
  `parse_superblob` (existing convention: `Err` = malformed structure,
  `report.errors` = signature findings).
- Own signer output must remain valid end-to-end: credential-signed thin
  (full CMS), ad-hoc thin (8-byte wrapper + `CS_ADHOC`). For FAT
  credential output, **only the page check's contract is ours**: the
  bounded check must keep `PageCheck::Matched` for `codeLimit <
  slice.size`; whole-report FAT validity already fails at base under the
  deferred dual-CDHash defect (ZSN-25) and is explicitly out of scope —
  no test in this lane may assert overall FAT validity.
- Out of scope, untouched: dual-CDHash binding (ZSN-25), `crypto/cms_verify.rs`
  (lane 23), `crates/zsign/src/verify.rs` (lane 26), constants/signer/writer,
  CLI main.
- No new files; all tests inline in the two target files
  (`#[cfg(test)] mod tests`, per repo convention).

## Test strategy (regression tests must be RED before their fix)

1. **Item 1** — credential-sign a thin Mach-O, truncate the CMS entry's
   declared length to 8 bytes (in-place patch of the entry header, same
   byte-mutation pattern as `tampered_signature_bytes_fail_cms`,
   macho/verify.rs:376-405). Pre-fix: shortcut → `valid == true` → the
   `assert!(!report.is_valid())` fails. Post-fix: `"empty CMS wrapper but
   not ad-hoc flagged"`.
2. **Item 2** — hand-built 2-slice FAT (header pattern from
   `make_fat_with_encrypted_second_slice`, signer.rs:1230-1258), signed via
   `sign_any_macho`; append trailing pad so the second slice's tail
   (`data[offset..]`) is longer than its declared `slice.size`, then patch
   the second slice's primary CD `codeLimit` to `C' = slice_size + 0x100`
   (fits the tail, exceeds the slice). The regression is pinned on the
   **observable diagnostic difference**, not on validity: pre-fix the
   page check runs over the tail, so with `slice_size = 28672`
   (`calculate_signature_space(8192)`, writer.rs:51-55) it computes
   `ceil(28928/4096) = 8` and reports `CountMismatch { stored: 2,
   computed: 8 }`; post-fix the bounded region is the slice itself and
   the `code_limit > code.len()` guard reports `{ stored: 2, computed: 7 }`
   (`ceil(28672/4096)`). The test asserts `pages ==
   CountMismatch { stored: nCodeSlots, computed: ceil(slice_size/page) }`
   (read from the parsed slice + CD, not hardcoded) → RED pre-fix
   (computed 8 ≠ 7), GREEN post-fix. A pre-fix *successful* check is
   deliberately not targeted: the parser forces the CodeDirectory inside
   `slice.size` (parser.rs:269-278), so a `codeLimit > slice.size` region
   covers the CD's own slot storage and no internally consistent `Matched`
   construction exists — the honest RED/GREEN is the computed-count
   difference. The test asserts only `report.slices[1].pages` /
   `report.slices[1].errors` — never slice-0 or whole-report validity
   (slice 0's dual-CD CMS binding fails under deferred ZSN-25).
3. **Item 3** — hand-built SuperBlobs in `codesign/verify.rs` tests:
   declared length shorter than the index extent; child inside the
   header/index; `item_len < 8`; two overlapping children. All four parse
   successfully pre-fix (→ RED) and return `Error::Verification` post-fix.
4. **Item 4** — ad-hoc-sign a thin Mach-O (`sign_macho_adhoc`), patch the
   primary CD's `nCodeSlots` and `codeLimit` to 0. Pre-fix: `Empty` →
   accepted → assert fails. Post-fix: distinct zero-coverage error.

**Fixture notes:**
- Item 1's test truncates the CMS entry's declared length to 8 bytes so the
  pre-fix shortcut fires and the mutated binary is otherwise clean — that
  neutralization is specific to item 1 (it *is* the bypass under test) and
  is not reused elsewhere.
- Item 2's test needs no CMS neutralization: the assertion targets
  `slices[1].pages` only, the page check runs before the CMS block, and
  CMS/CDHash errors from the patched CD (cdhash changes when `codeLimit`
  is patched) do not affect the `pages` field. The test asserts the exact
  `PageCheck` variant + values, never `errors.is_empty()`/`is_valid()`,
  so unrelated extra errors cannot make it pass or fail spuriously.

Existing verify tests encode no buggy behavior (scout-verified: no test
asserts `Empty` acceptance, truncated-CMS validity, `codeLimit=0` validity,
or FAT-tail reads) — none need adjustment beyond exercising the new errors.

## Design decisions

1. **Ad-hoc shortcut requires ad-hoc flag + exact 8-byte wrapper** (item 1,
   option A). Wrong-magic/short blobs fall to `verify_code_signature`.
2. **Slice bounding via `&ArchSlice` parameter with `checked_add`**
   (item 2, option A); the existing `code_limit > len` guard supplies the
   error — no new pre-gate, no new message.
3. **Declared length bounds reads but tolerates trailing bytes**
   (`L <= blob.len()`, item 3 option C rejected): compatibility with padded
   LC windows; security comes from bounding to `L`, not from equality.
4. **Overlap rejection via sort + adjacent comparison** (covers duplicates;
   zero-length children already rejected by `item_len < 8`).
5. **`PageCheck::Empty` stays a variant; rejection lives in `verify_slice`**
   (item 4, option A) with a distinct message; diagnostic uses
   `1 << cd.page_size_log2`.
6. **All findings are `report.errors` pushes**, preserving the
   `Ok(report)` contract of `verify_slice`.
7. **Error phrasings reuse existing conventions** (lowercase, no
   punctuation drift, `format!` with slot/counts), e.g.
   `"empty CMS wrapper but not ad-hoc flagged"`,
   `"code directory covers zero code bytes"`.

## Rejected alternatives (summary)

| Item | Rejected | Why |
|---|---|---|
| 1 | shared `is_empty_adhoc_wrapper()` helper | two sites test different facts; abstraction hides it |
| 1 | reject at parse layer | wrong layer; ad-hoc flag is CD state |
| 2 | inline bound in `verify_slice`, delete wrapper | larger diff, loses the documented helper contract |
| 2 | dedicated "codeLimit exceeds slice" pre-gate | duplicates an existing correct guard |
| 3 | checked arithmetic only | leaves index/child aliasing open |
| 3 | `L == blob.len()` exactly | rejects legit padded windows, no gain |
| 4 | remove `Empty` variant | breaks public API + CLI display arms |
| 4 | return `Mismatch` from `check_code_pages` | conflates structure with hash failure |

## Source excerpts under fix (as of base `ee42c12`, verified 2026-09-25)

Headings give exact `file:line`; `…` marks elided unchanged lines (this
section is excerpted, not re-derived).

**Item 1 — macho/verify.rs:168-197 (CMS block):**

```rust
    // CMS signature. An empty signature slot (wrapper header only) is what
    // codesign emits for ad-hoc output.
    if let Some(cms_blob) = superblob.cms {
        if cms_blob.len() <= 8 {
            report.cms = Some(crate::crypto::cms_verify::adhoc_report());
            return Ok(report);
        }

        let cd_sha256: [u8; 32] = primary.cdhash_sha256();
        let cd_sha1 = alternate_sha1(&superblob);
        match crate::crypto::cms_verify::verify_code_signature(
            cms_blob,
            primary.raw(),
            cd_sha1.as_ref(),
            &cd_sha256,
        ) {
            Ok(cms_report) => {
                if !cms_report.valid {
                    report.errors.extend(cms_report.errors.clone());
                }
                report.cms = Some(cms_report);
            }
            Err(e) => report.errors.push(format!("CMS verification error: {e}")),
        }
    } else if primary.is_adhoc() {
        report.cms = Some(crate::crypto::cms_verify::adhoc_report());
    } else {
        report
            .errors
            .push("no CMS signature slot but not ad-hoc flagged".into());
    }
```

**Item 2 — macho/verify.rs:141 (call) and 205-213 (wrapper):**

```rust
    report.pages = check_code_pages_in_file(primary, data, slice.offset);
    ...
fn check_code_pages_in_file(cd: &CodeDirectory<'_>, data: &[u8], offset: usize) -> PageCheck {
    let Some(tail) = data.get(offset..) else {
        return PageCheck::CountMismatch {
            stored: cd.n_code_slots as usize,
            computed: 0,
        };
    };
    check_code_pages(cd, tail)
}
```

**Item 2/4 — macho/verify.rs:142-153 (page match arm):**

```rust
    match &report.pages {
        PageCheck::Matched | PageCheck::Empty => {}
        PageCheck::Mismatch { page_index } => {
            report.errors.push(format!(
                "code page {page_index} hash mismatch (code region modified?)"
            ));
        }
        PageCheck::CountMismatch { stored, computed } => {
            report.errors.push(format!(
                "code slot count mismatch: {stored} stored vs {computed} pages computed"
            ));
        }
    }
```

**Item 3 — codesign/verify.rs:60-101 (parse_superblob, exact lines :72-100):**

```rust
    let count = u32::from_be_bytes(blob[8..12].try_into().unwrap()) as usize;
    if 12 + count * 8 > blob.len() {
        return Err(crate::Error::Verification(format!(
            "SuperBlob index ({} entries) overruns blob of {} bytes",
            count,
            blob.len()
        )));
    }

    let mut entries = Vec::with_capacity(count);
    for i in 0..count {
        let entry_off = 12 + i * 8;
        let slot = u32::from_be_bytes(blob[entry_off..entry_off + 4].try_into().unwrap());
        let offset =
            u32::from_be_bytes(blob[entry_off + 4..entry_off + 8].try_into().unwrap()) as usize;
        let Some(item) = blob.get(offset..).filter(|b| b.len() >= 8) else {
            return Err(crate::Error::Verification(format!(
                "SuperBlob entry {i} (slot 0x{slot:08x}) points outside the blob"
            )));
        };
        // Each blob carries its own magic+length header; bound it precisely so
        // hashing a slot blob never implicitly includes later blobs.
        let item_len = u32::from_be_bytes(item[4..8].try_into().unwrap()) as usize;
        let Some(bounded) = blob.get(offset..offset.saturating_add(item_len)) else {
            return Err(crate::Error::Verification(format!(
                "SuperBlob entry {i} (slot 0x{slot:08x}) length overruns blob"
            )));
        };
        entries.push(SlotEntry { slot, blob: bounded });
    }
```

Note: bytes `blob[4..8]` (declared total length) are never read; no check
rejects `offset < 12 + count*8`, `item_len < 8`, or overlapping children.

**Item 4 — codesign/verify.rs:397-419 (page check head) and :406:**

```rust
pub fn check_code_pages(cd: &CodeDirectory<'_>, code: &[u8]) -> PageCheck {
    let page_size = 1usize << cd.page_size_log2;             // :399
    let region_len = (cd.code_limit as usize).min(code.len());
    if cd.code_limit as usize > code.len() {
        return PageCheck::CountMismatch {
            stored: cd.n_code_slots as usize,
            computed: region_len.div_ceil(PAGE_SIZE),        // :406 hardcodes 4096
        };
    }
    let stored = cd.code_hashes();
    let expected_slots = region_len.div_ceil(page_size);
    if stored.len() != expected_slots * cd.hash_size {
        return PageCheck::CountMismatch {
            stored: cd.n_code_slots as usize,
            computed: expected_slots,
        };
    }
    if expected_slots == 0 {
        return PageCheck::Empty;                             // :418-419
    }
    ...
```

## Scope boundaries (cold-review checklist)

Fixes touch ONLY `crates/zsign-core/src/macho/verify.rs` and
`crates/zsign-core/src/codesign/verify.rs` (code + inline tests). Explicitly
out of scope, must remain byte-identical:

- **ZSN-25 (wave 2):** dual-CDHash binding (`alternate_sha1` usage,
  `cd_sha256` derivation), alternate-CD verification, special-slot
  strictness, constants.rs version gates/slot magics.
- **Lane 23:** `crates/zsign-core/src/crypto/cms_verify.rs` (read-only
  reference: `adhoc_report`, `verify_code_signature`).
- **Lane 26:** `crates/zsign/src/verify.rs`.
- **Wave 2:** `macho/signer.rs`, `macho/writer.rs`.
- **Lane (CLI):** `crates/zsign-cli/src/main.rs` — its `PageCheck::Empty`
  display arms (main.rs:236, :328) are display-only and need no change.
- `.gitignore` is NOT edited; these two docs are force-added with
  `git add -f`.
