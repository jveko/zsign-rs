# ZSN-29 Checked Arithmetic & Bounded Recursion — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development with dispatching-parallel-agents where tasks are independent. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the seven still-open findings of the 2026-09-24 review (b, c, d, e, f, g, h) with checked arithmetic, explicit range validation, and bounded recursion on every untrusted-input path of `zsign-core`.

**Architecture:** Untrusted read paths (`codesign/verify.rs`, `cms_verify.rs` BER normalizer) fail with `Error::Verification` (Err-not-panic). Trusted builder paths (`codesign/superblob.rs`, `codesign/code_directory.rs`) get release-active checked preconditions, because making them `Result` would break out-of-scope callers (`macho/signer.rs`, `codesign/mod.rs` doctest) — the brief forbids editing those files. No `PageCheck` variants (exhaustive matches in out-of-scope `zsign-cli`), no signature changes anywhere.

**Tech Stack:** Rust 2021, inline `#[cfg(test)]` tests, `TMPDIR=$PWD/.tmptmp` for every cargo run (per brief; `/tmp` flakes under parallel-lane load).

**Baseline evidence:** at `0f07c30`, `TMPDIR=$PWD/.tmptmp cargo test -p zsign-core codesign` → `107 passed; 0 failed` (recorded 2026-09-25). Full suite baseline: 316 tests (ZSN-15 determinism test excluded from full runs: `--skip test_ipa_signing_is_deterministic`).

**Hard rules for every task:** edit ONLY `crates/zsign-core/src/codesign/{verify.rs, superblob.rs, code_directory.rs}` and the BER-normalizer region of `crates/zsign-core/src/crypto/cms_verify.rs` (+ their inline tests). No `cargo fmt` / `cargo clippy` / `hk`. No ticket IDs in code comments. Conventional commit per task, gate green before the next task starts.

---

### Task 1: Validate `page_size_log2` at parse + whole-file semantics in `check_code_pages` (finding c)

**Files:**
- Modify: `crates/zsign-core/src/codesign/verify.rs` — `CodeDirectory::parse` (page-size read ~line 613), `check_code_pages` (~lines 856-903), inline tests
- Test: same file, `#[cfg(test)]` tests

- [ ] **Step 1: Write failing tests (T1-T4)**

```rust
/// Craft a CodeDirectory from the real builder, then patch header byte 39
/// (pageSize log2) — the field the builder always writes as 12.
fn cd_bytes_with_page_size(log2: u8) -> Vec<u8> {
    let code = vec![0x5au8; 4096];
    let mut cd = CodeDirectoryBuilder::new("com.example.pages", &code).build_sha256();
    cd[39] = log2;
    cd
}

#[test]
fn parse_rejects_page_size_log2_above_16() {
    for log2 in [17u8, 20, 63, 64, 127, 255] {
        let err = CodeDirectory::parse(&cd_bytes_with_page_size(log2)).unwrap_err();
        assert!(
            matches!(err, crate::Error::Verification(ref m) if m.contains("page size log2")),
            "log2 {log2}: {err:?}"
        );
    }
}

#[test]
fn parse_rejects_per_byte_page_size() {
    // log2 1/2/.../11 would hash 2/4/.../2048-byte "pages"; 1 = per-byte SHA-256 DoS.
    for log2 in [1u8, 6, 11] {
        assert!(CodeDirectory::parse(&cd_bytes_with_page_size(log2)).is_err());
    }
}

#[test]
fn parse_accepts_whole_file_and_legal_page_sizes() {
    for log2 in [0u8, 12, 13, 14, 15, 16] {
        CodeDirectory::parse(&cd_bytes_with_page_size(log2))
            .unwrap_or_else(|e| panic!("legal page size {log2} rejected: {e}"));
    }
}

#[test]
fn whole_file_page_size_hashes_region_as_one_slot() {
    // Builder emits exactly one code slot for <=4096 bytes of code, hashing
    // the region in one digest — identical to Apple's pageSize=0 whole-file page.
    let code = vec![0x5au8; 4096];
    let cd_bytes = cd_bytes_with_page_size(0);
    let cd = CodeDirectory::parse(&cd_bytes).unwrap();
    assert_eq!(check_code_pages(&cd, &code), PageCheck::Matched);

    // A region shorter than codeLimit hits the pre-existing `limit > code_len`
    // guard; with whole-file page size the computed count is 1 (region_len /
    // region_len), pre-fix it was 1000 (page_size = 1). Either way: no panic,
    // CountMismatch — pin the post-fix exact values.
    let short = &code[..1000];
    assert_eq!(
        check_code_pages(&cd, short),
    PageCheck::CountMismatch { stored: 1, computed: 1 }
);
}

#[test]
fn check_code_pages_rejects_mutated_page_size_without_panic() {
    // Post-fix, parse rejects every illegal page size, so the only way the
    // consumer's fallback arm is reached is a consumer mutating the pub
    // field — which must fail closed, not shift blindly (pre-fix: 1 << 33
    // succeeds on x86_64 and the check proceeds with a bogus page size).
    let mut cd = CodeDirectory::parse(&cd_bytes_with_page_size(12)).unwrap();
    cd.page_size_log2 = 33;
    assert_eq!(
        check_code_pages(&cd, &[0x5au8; 4096]),
        PageCheck::CountMismatch { stored: 1, computed: 0 }
    );
}
```

- [ ] **Step 2: Run tests, confirm they fail pre-fix**

Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-core parse_rejects -- --nocapture`
Expected: FAIL — pre-fix `parse` accepts every log2, `unwrap_err()` panics with "called `Result::unwrap_err()` on an `Ok` value".

Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-core whole_file_page_size -- --nocapture`
Expected: FAIL pre-fix — `page_size = 1 << 0 = 1` → 4096 expected slots vs 1 stored → `CountMismatch` instead of `Matched`.

(These are the recorded 64-bit pre-fix failure evidence for finding (c); capture verbatim output for the final report.)

- [ ] **Step 3: Implement the parse-time range validation**

In `CodeDirectory::parse`, immediately after `let page_size_log2 = data[39];`:

```rust
// Legal CodeDirectory page sizes: 12..=16 (2^log2-byte pages; 4096 on iOS,
// 16384 on modern macOS) plus 0, which Apple's verifier treats as one page
// covering the whole code region. Everything else would either shift-overflow
// or degrade hashing to per-byte work.
match page_size_log2 {
    0 | 12..=16 => {}
    other => {
        return Err(crate::Error::Verification(format!(
            "unsupported CodeDirectory page size log2 {other}"
        )));
    }
}
```

- [ ] **Step 4: Rework `check_code_pages` (whole-file + panic-free)**

Replace the opening of `check_code_pages` (current lines 856-886) so page size is derived once, whole-file semantics for 0, and the length product is checked:

```rust
let limit = cd.effective_code_limit();
let code_len = code.len() as u64;
let region_len_u64 = limit.min(code_len);

// pageSize 0 means one page covering the entire code region (Apple's
// whole-file page); 12..=16 means 2^log2-byte pages. Parse validates the
// range, but the field is public — treat anything else as a count
// mismatch instead of shifting blindly.
let page_size_u64: u64 = match cd.page_size_log2 {
    0 => region_len_u64.max(1),
    log2 @ 12..=16 => 1u64 << log2,
    _ => {
        return PageCheck::CountMismatch {
            stored: cd.n_code_slots as usize,
            computed: 0,
        }
    }
};

// Guard against a CodeDirectory claiming more code than exists.
if limit > code_len {
    return PageCheck::CountMismatch {
        stored: cd.n_code_slots as usize,
        computed: region_len_u64.div_ceil(page_size_u64) as usize,
    };
}
let region_len = region_len_u64 as usize; // safe: <= code.len()

let stored = cd.code_hashes();
let expected_slots = region_len.div_ceil(page_size_u64 as usize);
let Some(stored_len) = expected_slots.checked_mul(cd.hash_size) else {
    return PageCheck::CountMismatch {
        stored: cd.n_code_slots as usize,
        computed: expected_slots,
    };
};
if stored.len() != stored_len {
    return PageCheck::CountMismatch {
        stored: cd.n_code_slots as usize,
        computed: expected_slots,
    };
}
```

Everything from `if expected_slots == 0 { return PageCheck::Empty; }` down through the digest loop stays byte-for-byte identical, **including the ORDER**: the stored-length guard runs first and is *inert* when `expected_slots == 0` (`stored_len == 0`, passes only when the stored region is also empty), then `Empty` returns for empty regions, then the loop. Do NOT move the `Empty` return ahead of the stored-length guard — `macho/verify.rs:113-116` (out of scope) matches on `PageCheck::Empty` and that contract must keep working. The loop's chunk size becomes `page_size_u64 as usize` (whole-file: one chunk of `region_len`; `page_size_u64` is ≥ 1 on every path, so no division or `chunks` can see 0; an empty region never reaches the loop because `expected_slots == 0` returns `Empty` first).

Post-fix evaluation of T4's two assertions (sanity pin for the implementer): full region → `expected_slots = 4096.div_ceil(4096) = 1`, `stored_len = 32`, one 4096-byte chunk hashed and compared → `Matched`. Short region → `limit(4096) > code_len(1000)` early branch → `CountMismatch { stored: 1, computed: 1 }`.

- [ ] **Step 5: Run scoped gate**

Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-core codesign`
Expected: all pass (baseline 107 + 4 new). Also run `TMPDIR=$PWD/.tmptmp cargo test -p zsign-core macho` — `macho/verify.rs` consumes `check_code_pages`; every fixture there uses page size 12, so results must be unchanged.

- [ ] **Step 6: Commit**

`git add crates/zsign-core/src/codesign/verify.rs && git commit -m "fix(codesign): validate code directory page size and honor whole-file pages (ZSN-29)"`

---

### Task 2: Bind the `n_code * hash_size` product and make the accessors panic-free (finding b)

**Files:**
- Modify: `crates/zsign-core/src/codesign/verify.rs` — `CodeDirectory::parse` (~lines 694-708), `special_slot_hash` (~770-785), `code_hashes` (~787-789), inline tests
- Test: same file, inline tests

- [ ] **Step 1: Write failing tests (T5-T7)**

```rust
#[test]
fn code_hashes_is_panic_free_on_inconsistent_header() {
    let cd_bytes = CodeDirectoryBuilder::new("com.example.bound", &[0x11u8; 8192]).build_sha256();
    let mut cd = CodeDirectory::parse(&cd_bytes).unwrap();
    assert!(!cd.code_hashes().is_empty());
    // The header field is public; a hostile or buggy consumer can set it to
    // anything after parse. Slicing must not panic.
    cd.n_code_slots = u32::MAX;
    assert!(cd.code_hashes().is_empty());
    assert!(matches!(
        check_code_pages(&cd, &[0x11u8; 8192]),
        PageCheck::CountMismatch { .. }
    ));
}

#[test]
fn special_slot_hash_is_panic_free_on_inconsistent_header() {
    let cd_bytes = CodeDirectoryBuilder::new("com.example.bound", &[0x11u8; 4096])
        .requirements_hash(vec![0xcd; 32])
        .build_sha256();
    let mut cd = CodeDirectory::parse(&cd_bytes).unwrap();
    assert!(cd.special_slot_hash(1).is_some());
    cd.n_special_slots = u32::MAX;
    assert!(cd.special_slot_hash(u32::MAX as usize).is_none());
    assert!(cd.special_slot_hash(1).is_some()); // still within bounds
}

#[test]
fn parse_rejects_hash_region_product_overflow() {
    // nCodeSlots * hashSize = 0x0FFFFFFF * 32 = 8.5 GiB worth of slots.
    // On 64-bit the product fits and the bounds check rejects it; on
    // 32-bit/wasm32 the unchecked product wraps to ~4 GiB and (pre-fix)
    // defeats that bounds check entirely — the checked_mul must reject
    // before any comparison on every width.
    let mut cd = CodeDirectoryBuilder::new("com.example.overflow", &[0x22u8; 4096]).build_sha256();
    cd[28..32].copy_from_slice(&0x0FFF_FFFFu32.to_be_bytes());
    let err = CodeDirectory::parse(&cd).unwrap_err();
    assert!(
        matches!(err, crate::Error::Verification(ref m)
            if m.contains("hash region") || m.contains("overruns blob")),
        "{err:?}"
    );
}

#[cfg(target_pointer_width = "32")]
#[test]
fn parse_checked_mul_rejects_wrapping_hash_region() {
    // Same hostile header as above; on a 32-bit target the checked-mul
    // overflow path is the one that must fire (pre-fix, the wrapped product
    // passed the bounds check and parse accepted the blob).
    let mut cd = CodeDirectoryBuilder::new("com.example.overflow", &[0x22u8; 4096]).build_sha256();
    cd[28..32].copy_from_slice(&0x0FFF_FFFFu32.to_be_bytes());
    let err = CodeDirectory::parse(&cd).unwrap_err();
    assert!(matches!(err, crate::Error::Verification(ref m)
        if m.contains("hash region overflow")));
}
```

Also add the regression pin for the ALREADY-FIXED index-extent guard (audit (a)/(i-2) — no existing test exercised it; review round 1):

```rust
#[test]
fn parse_superblob_rejects_hostile_count() {
    // count = u32::MAX would make 12 + count*8 wrap on 32-bit; the guard
    // must reject via the checked product before any bounds comparison.
    let mut b = build_blob(true);
    b[8..12].copy_from_slice(&u32::MAX.to_be_bytes());
    let err = parse_superblob(&b).unwrap_err();
    assert!(
        matches!(err, crate::Error::Verification(ref m) if m.contains("index extent")),
        "{err:?}"
    );
}
```

- [ ] **Step 2: Run tests, confirm failures**

Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-core code_hashes_is_panic_free -- --nocapture`
Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-core special_slot_hash_is_panic_free -- --nocapture`
(cargo accepts exactly one positional filter per invocation — one command per filter.)
Expected: both FAIL pre-fix with slice/underflow panic (`range end index out of range` / `attempt to subtract with overflow` in debug).

(`parse_rejects_hash_region_product_overflow` passes pre-fix on 64-bit via the bounds path — by design; its 32-bit distinguishing sibling is cfg-gated, and the wasm32 `cargo check` in Task 6 is the width evidence the brief allows. `parse_superblob_rejects_hostile_count` also passes at base — it is a regression *pin* for the already-landed guard, not a fix.)

- [ ] **Step 3: Implement the checked product at parse**

Replace lines ~696-698:

```rust
let expected_tail = n_code
    .checked_mul(hash_size)
    .and_then(|bytes| hash_offset.checked_add(bytes))
    .ok_or_else(|| crate::Error::Verification("hash region overflow".into()))?;
if expected_tail > data.len() {
    // existing message unchanged
}
```

The existing `expected_tail > data.len()` block and the `n_special > hash_offset / hash_size.max(1)` check stay exactly as they are.

- [ ] **Step 4: Make the accessors panic-free (parse invariant + defensive `get`)**

```rust
/// The special-slot hash for slot `-index` (1 = Info.plist slot −1).
/// …
pub fn special_slot_hash(&self, index: usize) -> Option<&'a [u8]> {
    if index == 0 || index > self.n_special_slots as usize {
        return None;
    }
    // Slots are stored most-negative-first, so slot −index is the
    // index-th hash counting back from the code-hash area.
    index
        .checked_mul(self.hash_size)
        .and_then(|off| self.hash_offset.checked_sub(off))
        .and_then(|start| start.checked_add(self.hash_size).map(|end| (start, end)))
        .and_then(|(start, end)| self.data.get(start..end))
}

/// All code-page hashes (one `hashSize`-byte digest per page).
pub fn code_hashes(&self) -> &'a [u8] {
    (self.n_code_slots as usize)
        .checked_mul(self.hash_size)
        .and_then(|bytes| self.hash_offset.checked_add(bytes))
        .and_then(|end| self.data.get(self.hash_offset..end))
        .unwrap_or(&[])
}
```

`check_code_pages` already gained its `checked_mul` in Task 1 Step 4 — no further change here.

- [ ] **Step 5: Run scoped gate**

Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-core codesign`
Expected: all green (baseline + T5-T7).

- [ ] **Step 6: Commit**

`git add crates/zsign-core/src/codesign/verify.rs && git commit -m "fix(codesign): bind code directory hash region product with checked arithmetic (ZSN-29)"`

---

### Task 3: Depth-cap the BER normalizer (finding d)

**Files:**
- Modify: `crates/zsign-core/src/crypto/cms_verify.rs` — BER region only: `normalize_ber_lengths` (~127), `write_norm` (~140), inline normalizer tests (~1915+)
- Test: same file, inline tests

- [ ] **Step 1: Write failing tests (T8)**

```rust
/// n levels of indefinite-length constructed TLVs: `30 80 … 00 00`.
fn nested_indefinite(depth: usize) -> Vec<u8> {
    let mut v = vec![0x00, 0x00];
    for _ in 0..depth {
        let mut next = vec![0x30, 0x80];
        next.append(&mut v);
        next.extend_from_slice(&[0x00, 0x00]);
        v = next;
    }
    v
}

#[test]
fn normalize_ber_rejects_overdeep_nesting() {
    let err = normalize_ber_lengths(&nested_indefinite(50_000)).unwrap_err();
    assert!(
        matches!(err, Error::Verification(ref m) if m.contains("nesting depth")),
        "{err:?}"
    );
}

#[test]
fn normalize_ber_boundary_depth() {
    // Depth 32 is the accepted ceiling (matches the DER cap precedent);
    // 33 levels must be rejected, not overflow the stack.
    assert!(normalize_ber_lengths(&nested_indefinite(32)).is_ok());
    assert!(normalize_ber_lengths(&nested_indefinite(33)).is_err());
}
```

- [ ] **Step 2: Record the pre-fix stack overflow (evidence for final report)**

Run ONLY the deep test pre-fix: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-core normalize_ber_rejects_overdeep -- --nocapture`
Expected: pre-fix the test process **aborts** with `thread '…' has overflowed its stack` (capture verbatim). If it does not abort, raise depth (frame size dependent) — the abort IS the finding's reproduction.

- [ ] **Step 3: Implement the depth parameter**

```rust
/// Maximum accepted nesting depth for BER constructed TLVs. Matches the
/// DER parser's depth cap; real CMS structures nest well under this.
const MAX_BER_NEST_DEPTH: usize = 32;
```

- `normalize_ber_lengths` driver: `let (bytes, consumed) = write_norm(input, i, 0)?;`
- `fn write_norm(input: &[u8], mut i: usize, depth: usize) -> Result<(std::vec::Vec<u8>, usize)>` with, as the first statement:

```rust
if depth >= MAX_BER_NEST_DEPTH {
    return Err(Error::Verification(
        "BER nesting depth exceeds limit".into(),
    ));
}
```

- Indefinite-frame recursion (~line 167): `write_norm(input, i, depth + 1)?`
- Constructed-children recursion (~line 214): `write_norm(content, j, depth + 1)?`
- Update the doc comment of `normalize_ber_lengths` to state the depth bound.

Boundary math: driver depth 0 = outermost TLV; an input nested N deep reaches `depth == N-1`, so `depth >= 32` rejects at N = 33 — matches Step 1's boundary test (32 ok / 33 err).

- [ ] **Step 4: Run scoped gate**

Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-core cms_verify`
Expected: all `crypto::cms_verify` tests green, including both new ones (no abort).

- [ ] **Step 5: Commit**

`git add crates/zsign-core/src/crypto/cms_verify.rs && git commit -m "fix(crypto): bound ber normalizer recursion depth (ZSN-29)"`

---

### Task 4: Builder preconditions in `code_directory.rs` — checked narrowing, release-active asserts, digest lengths (findings f, g, h)

**Files:**
- Modify: `crates/zsign-core/src/codesign/code_directory.rs` — `build_from_hashes` (~322-405), `build_internal` (~408-470), `build_special_slots` (~545-576), inline tests
- Test: same file, inline tests

- [ ] **Step 1: Write failing tests (T9-T11)**

```rust
#[test]
#[should_panic(expected = "page_hashes length")]
fn build_from_hashes_panics_on_length_mismatch() {
    // 8192 bytes of code = 2 pages = 64 bytes of SHA-256 page hashes expected.
    let code = vec![0x33u8; 8192];
    let _ = CodeDirectoryBuilder::new("com.example.mismatch", &code)
        .build_sha256_from_hashes(&[0u8; 32]);
}

#[test]
#[should_panic(expected = "special slot digest")]
fn build_rejects_special_slot_digest_of_wrong_length() {
    // build_internal has NO length check today: pre-fix this returns a
    // self-inconsistent blob silently (release AND debug). Post-fix the
    // per-slot precondition fires at build time.
    let code = vec![0x44u8; 4096];
    let _ = CodeDirectoryBuilder::new("com.example.slot", &code)
        .entitlements_hash(vec![0u8; 64])
        .build_sha256();
}

#[test]
fn u32_len_accepts_u32_max() {
    assert_eq!(u32_len(u32::MAX as usize, "test"), u32::MAX);
    assert_eq!(u32_len(0, "test"), 0);
}

#[cfg(target_pointer_width = "64")]
#[test]
#[should_panic(expected = "exceeds u32::MAX")]
fn u32_len_panics_instead_of_truncating() {
    // >4 GiB: `as u32` used to truncate silently (finding f's root cause).
    let _ = u32_len(u32::MAX as usize + 1, "test");
}
```

- [ ] **Step 2: Run tests, confirm pre-fix failures (record evidence)**

Debug: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-core build_rejects_special_slot_digest -- --nocapture`
Expected: FAIL pre-fix — no panic (silent corrupt blob) → "test did not panic".

Debug: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-core u32_len -- --nocapture`
Expected: FAIL pre-fix — compile error (helper does not exist yet). This is the honest ceiling for (e)/(f): the truncation is not observable on 64-bit without a >4 GiB allocation, so the contract is pinned at the helper boundary.

Release (for T9's distinguishing run): `TMPDIR=$PWD/.tmptmp cargo test --release -p zsign-core build_from_hashes_panics -- --nocapture`
Expected: FAIL pre-fix — `debug_assert` compiled out, no panic. (In debug, T9 passes pre-fix because `debug_assert_eq!` already panics with the same "page_hashes length mismatch" message — record both facts.)

- [ ] **Step 3: Add the shared narrowing helper**

Place near the top of `code_directory.rs` (after the constants; it is also used by `superblob.rs` via `super::code_directory::u32_len`):

```rust
/// Narrows a computed extent to the wire format's u32 field, failing loudly
/// instead of silently truncating a signature blob into self-inconsistency.
/// Builder inputs are trusted (the signer's own buffers), so an overflow is
/// a programming error, not attacker input.
pub(crate) fn u32_len(value: usize, what: &str) -> u32 {
    u32::try_from(value).unwrap_or_else(|_| panic!("{what} length {value} exceeds u32::MAX"))
}
```

- [ ] **Step 4: Replace every `as u32` length narrowing in this file**

In BOTH `build_from_hashes` and `build_internal` (the audit's line refs; they are duplicates by design):

```rust
let code_limit = u32_len(self.code.len(), "code");              // was: self.code.len() as u32
let ident_len = u32_len(self.identifier.len() + 1, "identifier"); // was: … as u32 + 1
let team_len = self.team_id.as_ref()
    .map(|t| u32_len(t.len() + 1, "team identifier"))
    .unwrap_or(0);
let hash_offset = ident_offset
    .checked_add(ident_len)
    .and_then(|off| off.checked_add(team_len))
    .and_then(|off| off.checked_add(n_special_slots as u32 * hash_size as u32))
    .expect("CodeDirectory hash offset overflows u32");
let total_len = hash_offset
    .checked_add(n_code_slots as u32 * hash_size as u32)
    .expect("CodeDirectory length overflows u32");
```

(`n_special_slots ≤ 7` and — once `code_limit` is bounded — `n_code_slots ≤ 2^20`, `hash_size ∈ {20,32}`, so the two products cannot overflow u32; the `checked_add` chain covers the sums. Keep `buf.extend(&(n_special_slots as u32).to_be_bytes())`-style field writes: those are bounds-proven by the same limits — convert them to `u32_len(...)` only if the surrounding expression's type requires it; do not churn working code.)

- [ ] **Step 5: Upgrade the debug asserts + add the slot-length precondition**

- `debug_assert_eq!(page_hashes.len(), n_code_slots * hash_size, …)` → `assert_eq!` (same args, same message — runs in release now).
- `debug_assert_eq!(buf.len(), total_len as usize)` → `assert_eq!`.
- In `build_special_slots`, inside the emit loop:

```rust
for slot in &slots[start..] {
    assert_eq!(
        slot.len(),
        hash_size,
        "special slot digest length {} does not match hash size {hash_size}",
        slot.len()
    );
    out.extend_from_slice(slot);
}
```

Notes (review round 1): the always-present `-6`/`-4` placeholder slots are pushed as `&empty` where `empty = vec![0u8; hash_size]` — correctly sized, they pass. The assert is a **hard panic on the public builder API** for any caller that mixes hash sizes (documented trusted-path contract, same class as `panic!("Unsupported hash type")` at `:589`); `build_special_slots` itself is a private method (`fn`, `code_directory.rs:545`), so out-of-scope files can only reach it through `build_sha1/256(_from_hashes)`. The sole production caller, `macho/signer.rs:793-843`, selects algorithm-matched digests via `is_sha1` from `DualHash { sha1, sha256 }` (`:852-874`), so no in-repo signing flow trips it.

- [ ] **Step 6: Run scoped gate (debug + release evidence)**

Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-core codesign`
Expected: green — all pre-existing digest tests already pass 32-byte digests into SHA-256 builds (verified by grep: `code_directory.rs:785/:797/:812/:945-949`, `verify.rs:1532-1533`), so the new asserts change no existing expectation.

Run (one positional filter per cargo invocation):
`TMPDIR=$PWD/.tmptmp cargo test --release -p zsign-core build_from_hashes_panics -- --nocapture`
`TMPDIR=$PWD/.tmptmp cargo test --release -p zsign-core build_rejects_special_slot_digest -- --nocapture`
`TMPDIR=$PWD/.tmptmp cargo test --release -p zsign-core u32_len -- --nocapture`
Expected: all 4 pass (post-fix release behavior = pre-fix debug behavior).

- [ ] **Step 7: Commit**

`git add crates/zsign-core/src/codesign/code_directory.rs && git commit -m "fix(codesign): enforce code directory builder preconditions in release builds (ZSN-29)"`

---

### Task 5: Checked narrowing in `superblob.rs` (finding e)

**Files:**
- Modify: `crates/zsign-core/src/codesign/superblob.rs` — `build_superblob` (~138-193), `build_entitlements_blob` (~219), `build_der_entitlements_blob` (~252), `build_requirements_blob_full` (~385-428), `build_signature_blob` (~458), inline tests

- [ ] **Step 1: Confirm the shared-helper contract is green**

Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-core u32_len`
Expected: PASS (Task 4's T11 pins the helper this file now relies on; the wrap itself needs ≥4 GiB inputs to observe — see design doc §4, honest classification).

- [ ] **Step 2: Replace every `as u32` narrowing + unchecked u32 arithmetic**

Add at the top: `use super::code_directory::u32_len;`

`build_superblob`:

```rust
let count = u32_len(entries.len(), "entry count");
let header_size = u32_len(
    (count as usize)
        .checked_mul(INDEX_ENTRY_SIZE as usize)
        .and_then(|bytes| bytes.checked_add(SUPERBLOB_HEADER_SIZE as usize))
        .expect("SuperBlob index extent overflows u32"),
    "index extent",
);
let mut offsets = Vec::with_capacity(entries.len());
let mut current_offset = header_size;
for entry in &entries {
    offsets.push(current_offset);
    current_offset = current_offset
        .checked_add(u32_len(entry.data.len(), "entry"))
        .expect("SuperBlob entry offset overflows u32");
    let remainder = current_offset % 4;
    if remainder != 0 {
        current_offset = current_offset
            .checked_add(4 - remainder)
            .expect("SuperBlob alignment overflows u32");
    }
}
let total_length = current_offset;
```

…then the loop below stays as-is except `let current_pos = u32_len(buf.len(), "buffer position");`.

Wrapper blobs (`build_entitlements_blob`, `build_der_entitlements_blob`, `build_signature_blob`):

```rust
let total_len = u32_len(8 + plist_data.len(), "entitlements blob"); // etc.
```

`build_requirements_blob_full`: compute both lengths in `usize` with `checked_add`, then narrow once:

```rust
let inner_length = u32_len(
    [4, 4, pack2.len(), 4, padded_bundle_id.len(), pack3.len(), 4, padded_subject_cn.len(), pack4.len()]
        .iter()
        .try_fold(0usize, |acc, &part| acc.checked_add(part))
        .expect("requirement inner length overflows usize"),
    "requirement inner",
);
let outer_length = u32_len(
    [4, 4, pack1.len(), inner_length as usize]
        .iter()
        .try_fold(0usize, |acc, &part| acc.checked_add(part))
        .expect("requirement outer length overflows usize"),
    "requirement outer",
);
buf.extend(&u32_len(bundle_id.len(), "bundle id").to_be_bytes());   // was bundle_id.len() as u32
buf.extend(&u32_len(subject_cn.len(), "subject cn").to_be_bytes()); // was subject_cn.len() as u32
```

- [ ] **Step 3: Grep for leftovers, then run scoped gate**

Run: `grep -n "as u32" crates/zsign-core/src/codesign/superblob.rs` (tooling: use the grep tool)
Expected: only test-module occurrences remain (tests at `:1237`-region construct fixtures inside `verify.rs`, not this file) — production sites all routed through `u32_len`/`checked_*`.

Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-core codesign`
Expected: green — every existing superblob round-trip test (`test_superblob_*`, alignment tests at `:1163`/`:1197`, empty-entries `:891`) passes unchanged: correct paths produce byte-identical output.

- [ ] **Step 4: Commit**

`git add crates/zsign-core/src/codesign/superblob.rs && git commit -m "fix(codesign): check superblob length arithmetic before narrowing to u32 (ZSN-29)"`

---

### Task 6: Final verification gates + evidence capture (no code changes)

- [ ] **Step 1: Full scoped suite**

Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-core -- --skip test_ipa_signing_is_deterministic`
Expected: green; baseline 316 + new tests (T1-T10, boundary variants ≈ +12). Record verbatim `test result:` line.

- [ ] **Step 2: wasm32 compile check (queue item 3)**

Run: `cargo check -p zsign-core --target wasm32-unknown-unknown`
Expected: `Finished` with no errors — compiles the fixed code for the 32-bit target where the (b)/(e)/(f) wraps would occur. If the target is missing, attempt `rustup target add wasm32-unknown-unknown` once; record the outcome honestly either way.

- [ ] **Step 3: Sanity-grep for scope violations**

Run: `git diff --name-only 0f07c30..HEAD`
Expected: exactly `crates/zsign-core/src/codesign/{verify,superblob,code_directory}.rs`, `crates/zsign-core/src/crypto/cms_verify.rs`, plus the two docs (`docs/superpowers/...`, force-added).

- [ ] **Step 4: Record the final audit table + ZSN-4 notes** in the final report (design doc §1 already carries it; verify no status changed during implementation).

No commit (evidence only). The lane ends here: no merge, no push.
