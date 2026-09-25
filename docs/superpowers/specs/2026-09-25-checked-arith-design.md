# ZSN-29 Checked Arithmetic & Bounded Recursion — Design

**Date:** 2026-09-25 · **Base:** main @ `0f07c30` · **Branch:** `zsn29-checked-arith`
**Scope (brief-locked):** `crates/zsign-core/src/codesign/{verify.rs, superblob.rs, code_directory.rs}`, `crates/zsign-core/src/crypto/cms_verify.rs` BER-normalizer region only (`normalize_ber_lengths` / `write_norm` / `len_len` / `write_len`), plus inline tests. Nothing else may be edited.

## 1. Re-anchor audit (review findings dated 2026-09-24 vs. `0f07c30`)

Line numbers are re-anchored to the current tree (the old review's numbers drifted through the ZSN-24/25/3/38 landings).

| id | finding (original) | status @ 0f07c30 | evidence (current file:line) | what remains |
|----|--------------------|------------------|------------------------------|--------------|
| (a) | `parse_superblob` unchecked `12 + count*8` wraps on 32-bit, defeats bounds check | **ALREADY-FIXED** | `codesign/verify.rs:118-121` (`count.checked_mul(8).and_then(\|e\| e.checked_add(12))` → `Error::Verification("SuperBlob index extent overflow")`), bounds compare `:122`, per-entry `offset.checked_add(item_len).filter(<=declared)` `:155-158`; requirements twin `:437-439`; guard tests `:1381-1385`, `:1467-1472` | nothing on the parse side; write-side `count * INDEX_ENTRY_SIZE` lives in superblob.rs → (e) |
| (b) | `n_code * hash_size` multiplied outside `checked_add` (old :250) and reused unchecked in `code_hashes` (old :328) | **STILL-OPEN** | `verify.rs:696-697` — `hash_offset.checked_add(n_code * hash_size)`: the product itself is unchecked and wraps on 32-bit/wasm32 before `checked_add` sees it; `n_code_slots` is raw untrusted u32 (`:599`); use sites `code_hashes()` `:788`, `special_slot_hash()` `:781`, `check_code_pages` `:875` all recompute unchecked | bind the product at parse; make the three use sites panic-free |
| (c) | `1usize << page_size_log2` with unvalidated u8; ≥64 debug panic; =1 per-byte CPU DoS; Apple pageSize 0 = whole-file unhandled | **STILL-OPEN** | `verify.rs:613` reads `data[39]` with no range check anywhere in `parse` (`:540-708`); shift at `:859`; `=0` yields `page_size == 1` (per-byte) not whole-file; `≥usize::BITS` → shift-overflow **panic in debug**, and in release the shift amount is masked (`1usize << 64` → `1`, per the Rust Reference/std `unbounded_shl` semantics) → same per-byte DoS or a wrong-but-plausible page size, never 0. Same raw shift out-of-scope at `macho/verify.rs:843` (test-side) | parse-time range validation {0} ∪ 12..=16, whole-file semantics for 0, panic-free `check_code_pages` |
| (d) | BER `write_norm` unbounded recursion → stack overflow at ~2 bytes/level (old cms_verify.rs:125-177) | **STILL-OPEN** | `cms_verify.rs:140` `fn write_norm(&[u8], usize) -> Result<(Vec<u8>, usize)>` has no depth parameter; recursion at `:167` (indefinite frame) and `:214` (constructed children); no `MAX_*_DEPTH` const in the file; untrusted callers `:334`, `:394`. Arithmetic inside is already checked (`:194-197`, `:201-203`) | depth cap + regression tests |
| (e) | superblob/code_directory builders narrow sizes to u32 unchecked (old superblob.rs:138-143) | **STILL-OPEN** | superblob.rs: `:139` `entries.len() as u32`, `:143` `SUPERBLOB_HEADER_SIZE + count * INDEX_ENTRY_SIZE` (u32), `:151` `current_offset += entry.data.len() as u32`, `:187` `buf.len() as u32`, `:220`/`:253`/`:459` `8 + len as u32`, `:391-404` requirements u32 sums, `:420`/`:427` string-length writes. Zero `checked_*`/`try_from` in the file | checked narrowing at every u32 field write |
| (f) | `code_length` stored as u32 wraps >4GiB (old code_directory.rs:323-337) | **STILL-OPEN** | `code_directory.rs:323` and `:410` `self.code.len() as u32`; `codeLimit64` hardcoded 0 (`:379`, `:464` region) | checked narrowing (loud failure instead of silent truncation) |
| (g) | `debug_assert` on page-hash count disappears in release, then all bytes copied regardless (old :330) | **STILL-OPEN (release behavior exactly as described)** | `code_directory.rs:330-338` `debug_assert_eq!(page_hashes.len(), n_code_slots * hash_size, …)`, `:399` `buf.extend_from_slice(page_hashes)` copies regardless, second `debug_assert_eq!(buf.len(), total_len)` `:402` | release-active precondition |
| (h) | special-slot digests of any length accepted, shifting every following slot (old :568-574) | **STILL-OPEN** | five setters take `Vec<u8>` unchecked (`code_directory.rs:212`, `:220`, `:228`, `:236`, `:244`); `build_special_slots` `:545-576` concatenates each digest with no length check (`:574`); `count_special_slots` `:501` counts presence, never bytes; no digest-length test exists | per-slot length validation at build time |
| (i-1) | `cdhash()` hashes whole slice vs declared length — likely fixed by ZSN-25 | **ALREADY-FIXED** | `parse` truncates to declared (`verify.rs:544-552` `let data = &blob[..declared]`); digests read `self.data` (`:750-754`, `:767-769`); regression test `cdhash_binds_declared_length` `:1773-1781` | none |
| (i-2) | count×8 superblob guard — likely hardened by ZSN-24 | **ALREADY-FIXED** | same evidence as (a) | none |

**Bottom line:** (a), (i-1), (i-2) closed — no duplicate fixes. Open work: (b), (c), (d) on the untrusted read path; (e), (f), (g), (h) on the builder (write) path.

### Checked-op sites that already exist (must not be duplicated)

- `verify.rs:118-121`, `:155-158`, `:354-360`, `:437-439`, `:663-667` (u64-widened linkage), `:696-703` (`checked_add` present, product not — finding (b)), `:704-708` (division-based special-slot bound).
- Recursion caps already landed: requirement exprs depth 64 (`verify.rs:374`), entitlements DER depth 32 (`verify.rs:1115`, `:1143`, `:1154`), pkcs12 `MAX_SAFE_CONTENTS_DEPTH = 5` (`pkcs12.rs:153`, enforced `:780-784`, tested `:1360`).
- `cms_verify.rs:194-197` long-form length `checked_mul(256).and_then(checked_add)`, `:201-203` `content_end` `checked_add`, `:645-647` `read_tlv` extent.
- `macho/writer.rs:837-840` `pub(crate) fn checked_u32(value: usize, field_name: &str) -> Result<u32>` — in-crate narrowing precedent (Error::MachO class; not reused directly, see §3).

## 2. Constraints discovered by the caller/error scouts (these shape every decision)

1. **`PageCheck` is matched exhaustively in out-of-scope files** — `zsign-cli/src/main.rs:234-243`, `:326-335` (production) and `macho/verify.rs:113-123` (production). ⇒ **no new `PageCheck` variant**; invalid page sizes must surface through existing variants or a parse-time `Err`.
2. **Builder fallibility is un-migratable in scope.** Making `build_superblob`, `SuperBlobBuilder::build`, `build_sha1/256(_from_hashes)` return `Result` breaks `macho/signer.rs` (9 production sites: `:548`, `:658`, `:846-848`, …) and `codesign/mod.rs:52-56` re-exports + crate doctest `:26-43` — all out of scope. ⇒ **builder signatures stay `-> Vec<u8>`**.
3. **Error convention:** one central thiserror `Error` (`error.rs:6`); malformed *codesign blob* bytes always use `Error::Verification(String)` (`verify.rs`, all of `cms_verify.rs`, `provisioning.rs:614` test pins the variant). `Error::MachO` is the macho-container class; `Error::Signing` is CMS-construction only. ⇒ all new read-path errors are `Error::Verification`. Existing error-substring assertions in out-of-scope tests (`macho/verify.rs:~1174` pins `"unsupported CodeDirectory hash type 7"`, `:1694` pins `"unsupported CodeDirectory version"`) must keep matching — new messages use their own new substrings.
4. **`CodeDirectory` fields `n_code_slots`, `hash_size`, `page_size_log2` are `pub`** and read by `macho/verify.rs:178`, `:503`. Field *types* must not change; construction only happens via `parse`, and production code never mutates them — but the accessors should not panic even if a consumer does (see tests T5/T6).
5. **Scope conflict that drove the central design decision (queue item 2 vs. hard rule “edit only files in your scope”):** queue item 2 demands Err-not-panic semantics, yet the builder cluster (e/f/g/h) *cannot* return `Err` without violating constraint 2. Resolution: **untrusted read paths fail with `Error::Verification`; trusted builder paths use release-active checked preconditions** (the brief's own sanctioned form for (g): “replace debug_assert with a release-mode checked precondition”). Alternatives considered in §3 per finding.

## 3. Candidate designs per finding (brainstorm, decided internally — no external questions)

### (b) `n_code * hash_size` product

- **B1 — checked product at parse (CHOSEN).** `n_code.checked_mul(hash_size).and_then(|bytes| hash_offset.checked_add(bytes)).ok_or_else(|| Error::Verification("hash region overflow"))?` then the existing `> data.len()` bounds reject. Once parse guarantees the product both *fits* `usize` and is *bounded* by the blob, the three use sites recompute the same operands and cannot wrap — provided they also stop panicking on slices: `code_hashes()` switches to `data.get(hash_offset..end).unwrap_or(&[])` (fail-closed: empty → `check_code_pages` reports `CountMismatch`, never a slice panic), `special_slot_hash()` uses `checked_mul` + `checked_sub` returning `Option` (signature unchanged), `check_code_pages` uses `expected_slots.checked_mul(cd.hash_size)` → `CountMismatch` on `None`. This is exactly the brief's “checked ops BEFORE bounds checks”.
- B2 — store the precomputed `hash_region_end` on the struct: rejected — new private field + wider diff for the same guarantee; B1 is the repo's established shape (`:118-121`, `:437-439`).
- B3 — u64-widen the compare like the linkage check (`:663-667`): rejected — fixes the parse check but leaves the *use sites* re-deriving wrapped products on 32-bit; B1 closes both with one op.

### (c) `page_size_log2`

- **C1 — validate at parse + panic-free consumer (CHOSEN).** `CodeDirectory::parse` rejects anything outside `{0} ∪ 12..=16` with `Error::Verification` (single choke point — every consumer downstream sees only legal values, including `check_code_pages` and `macho/verify.rs`). `check_code_pages` computes page size via a helper: `12..=16 → 1usize << log2` (shift amount provably < 64), `0 → whole-file semantics`: the entire code region is one page (`expected = if region_len == 0 { 0 } else { 1 }`, single chunk), anything else (only reachable by post-parse field mutation) → `CountMismatch { stored, computed: 0 }` — fail-closed, **no new enum variant** (constraint 1). The `limit > code_len` early branch and `div_ceil` are restructured so the empty-region case returns `Empty` before any division.
- C2 — validate only inside `check_code_pages`: rejected — leaves every other raw consumer (incl. out-of-scope `macho/verify.rs:843`) unguarded and puts untrusted-input policy in a hot loop.
- C3 — new `PageCheck::InvalidPageSize` variant: rejected — breaks exhaustive matches in `zsign-cli/src/main.rs` and `macho/verify.rs` (out of scope), and `SliceVerifyReport` already documents warnings, not new variants.

### (d) BER `write_norm` recursion

- **D1 — depth parameter + cap (CHOSEN).** `fn write_norm(input: &[u8], i: usize, depth: usize)`, `const MAX_BER_NEST_DEPTH: usize = 32`, entry guard `if depth >= MAX_BER_NEST_DEPTH → Err(Error::Verification("BER nesting depth exceeds limit"))`, `depth + 1` at both recursion sites (`:167` indefinite loop, `:214` constructed children), driver passes 0 — so nesting depth 32 is accepted, 33 rejected (boundary-tested). Cap 32 matches the landed DER cap precedent (`verify.rs:1115/:1143/:1154`) and sits far above real CMS nesting (~12–15 for SignedData → certs → RDNs) and between the OpenSSL (30) and RustCrypto `der` (64) caps. Signature of `normalize_ber_lengths` unchanged → zero caller migration (`:334`, `:394`, provisioning path keeps `Error::Verification` per `provisioning.rs:614`).
- D2 — fully iterative rewrite with an explicit stack: rejected — much larger diff in a security-critical parser for behavior identical to D1; recursion depth becomes bounded either way, which is the whole fix.
- D3 — input-size-based limit only: rejected — size does not bound *depth* (512 KiB of `30 80 … 00 00` nests ~130k deep); depth is the correct invariant.

### (e) superblob u32 narrowings

- **E1 — checked narrowing helper with release-active panic (CHOSEN).** `pub(crate) fn u32_len(value: usize, what: &str) -> u32` in `code_directory.rs` (imported by `superblob.rs` via `super::code_directory::u32_len`) — `u32::try_from(value).unwrap_or_else(|_| panic!("{what} length {value} exceeds u32::MAX"))` — plus `checked_mul`/`checked_add` on the u32 arithmetic (`count * 8`, `current_offset += …`), applied at every `as u32` listed in audit (e). Panic only fires for inputs ≥4 GiB — unreachable through the crate's enforced limits (Mach-O ≤512 MiB, plists ≤16 MiB), and when reached (direct public-API misuse) a loud failure beats emitting a self-inconsistent blob that the hardened reader will later reject. In-repo precedent for trusted-path builder panics: `code_directory.rs:589` `panic!("Unsupported hash type")`.
- E2 — `build_superblob(entries) -> Result<Vec<u8>>`: rejected — breaks `macho/signer.rs:548/:658` and `codesign/mod.rs` doctest (constraint 2; out of scope).
- E3 — saturating/clamping arithmetic: rejected — silently corrupt signature output is the exact defect class this ticket exists to remove.

### (f) `code_length` u32

- **F1 — checked narrowing (CHOSEN).** Both build paths narrow through the same helper: `let code_limit = u32_len(self.code.len(), "code");` (§E1). Optionally populate `codeLimit64` for completeness? **No** — emitting `codeLimit64` changes CD semantics/version gates and is feature work beyond this ticket; the fix is *fail loudly instead of truncate*.
- F2 — truncate to `u32::MAX` + populate `codeLimit64 = len`: rejected as scope creep (would need reader-side `effective_code_limit` interaction review and changes observable signature bytes).
- F3 — fall back to `build_internal`… not applicable (both build paths share the defect).

### (g) page-hash length `debug_assert`

- **G1 — always-on precondition (CHOSEN).** `debug_assert_eq!` → `assert_eq!` at `:330-338` (message already names the invariant) and `:402`. The invariant `page_hashes.len() == n_code_slots * hash_size` holds for every in-scope caller (`hash_code_pages_dual` output of the *same* slice, guaranteed once (f) pins `code_limit`), so this fires only on programming error — the brief's “release-mode checked precondition”.
- G2 — derive hashes internally when the length mismatches: rejected — silently discards the caller's hashes (masks “caller hashed different bytes” bugs) and silently doubles hashing cost; correctness bug class hidden behind a perf cliff.
- G3 — truncate/pad to the expected length: rejected — fabricates signature bytes.

### (h) special-slot digest lengths

- **H1 — per-slot length assert at build (CHOSEN).** In `build_special_slots`: `assert_eq!(slot.len(), hash_size, …)` per slot — `hash_size` is only known at build time (it is a build argument), so setter-time validation cannot know the target size anyway. Verified against the production caller: `macho/signer.rs:793-843` feeds algorithm-matched digests (20-byte for SHA-1 CDs, 32-byte for SHA-256) via `dual_hash` (`:857-874`), so the assert holds for every real signing flow, including dual mode.
- H2 — reject at setters (`-> Self` cannot return `Err`): rejected — changes the fluent API and still cannot see `hash_size`.
- H3 — treat wrong-length digests as absent: rejected — silently zero-fills a slot the caller intended to seal; corruption discovered downstream at verify time instead of at build time.

### Cross-cutting: why not `Error::MachO`-class `checked_u32` from writer.rs

`macho/writer.rs:837-840` is `pub(crate)` but returns `Error::MachO` (macho-container class) and would couple `codesign/*` onto `macho/writer` — architecturally backwards (writer depends on codesign types). Read-path errors use `Error::Verification` per the landed convention (§2.3); builder-path violations are trusted-input preconditions (panics), so no shared helper is warranted — YAGNI.

## 4. Test strategy (queue item 3: “fail pre-fix even on 64-bit” where the defect is observable there)

Inline tests only, in the scope files, following the existing `#[cfg(test)]` conventions. Classification of every planned test by whether it demonstrably fails **pre-fix on this 64-bit debug host**:

| # | test (planned name) | location | fails pre-fix on 64-bit? | mechanism |
|---|---------------------|----------|--------------------------|-----------|
| T1 | `parse_rejects_page_size_log2_above_16` | verify.rs tests | **YES** | craft CD header byte 39 = 64 (and 17): pre-fix `parse` accepts → `unwrap_err()` panics; post-fix `Err(Verification)` |
| T2 | `parse_rejects_per_byte_page_size` | verify.rs tests | **YES** | byte 39 = 1 (the CPU-DoS value) and 11: same mechanism |
| T3 | `parse_accepts_whole_file_and_legal_page_sizes` | verify.rs tests | **YES** | byte 39 = 0, 12, 14, 16 accepted; combined with T1/T2 pins `{0} ∪ 12..=16` exactly |
| T4 | `whole_file_page_size_hashes_region_as_one_slot` | verify.rs tests | **YES** | builder emits 1 slot for ≤4096-byte code (page hash == whole-region hash); patch byte 39 → 0; pre-fix `check_code_pages` computes `page_size = 1` → 4096 expected slots vs 1 stored → `CountMismatch`; post-fix → `Matched` |
| T5 | `code_hashes_is_panic_free_on_inconsistent_header` | verify.rs tests | **YES** | parse a valid CD, mutate `cd.n_code_slots = u32::MAX` (pub field): pre-fix `code_hashes()` slice-pansics (`hash_offset + u32::MAX*32` OOB); post-fix `get()` fallback → empty → `check_code_pages` returns `CountMismatch` (fail-closed, no panic) |
| T6 | `special_slot_hash_is_panic_free_on_inconsistent_header` | verify.rs tests | **YES** | mutate `cd.n_special_slots = u32::MAX`, call `special_slot_hash(u32::MAX as usize)`: pre-fix `hash_offset - index*32` underflow-panics; post-fix `checked_mul`/`checked_sub` → `None` |
| T7 | `parse_rejects_hash_region_product_overflow` | verify.rs tests | **64-bit: rejects via bounds; 32-bit: via checked_mul (see note)** | craft `n_code_slots = 0x0FFFFFFF`, `hash_size = 32`: on 64-bit the product fits and the *bounds* check rejects (also pre-fix — not distinguishing here); on 32-bit the product wraps pre-fix and parse *accepts* (defeated bounds), post-fix `checked_mul` → `Err("hash region overflow")`. The 32-bit distinguishing variant is `#[cfg(target_pointer_width = "32")]`; on this host it compiles out and wasm32 evidence is the `cargo check` (queue item 3's explicit allowance). Test asserts the hostile input is rejected on **both** widths so the contract is width-independent. |
| T8 | `normalize_ber_rejects_overdeep_nesting` + boundary `…_allows_legal_nesting_depth` | cms_verify.rs tests | **YES (with recorded pre-fix abort)** | 50k-deep `30 80 … 00 00` chain: pre-fix this **aborts the test process** (stack overflow — captured verbatim as evidence by running this single test before the fix lands); post-fix returns `Err` fast. Boundary: depth 32 `Ok`, depth 33 `Err` |
| T9 | `build_from_hashes_panics_on_length_mismatch` | code_directory.rs tests | **YES in release; debug passes pre-fix by message coincidence** | `#[should_panic(expected = "page_hashes length")]` feeding wrong-length hashes: debug pre-fix already panics via `debug_assert_eq!` *with the same message substring* → passes (still a valid post-fix pin); **release** pre-fix has no assert → "test did not panic" → fails. Both modes recorded around the fix |
| T10 | `build_rejects_special_slot_digest_of_wrong_length` | code_directory.rs tests | **YES in debug AND release (silent-corruption path)** | `.entitlements_hash(vec![0; 64])` then `build_sha256()` (the `build_internal` path, which has **no** trailing length assert at all): `#[should_panic(expected = "special slot digest")]` — pre-fix no panic in either profile (returns a self-inconsistent blob silently) → fails; post-fix the per-slot precondition fires |
| T11 | `u32_len_accepts_u32_max` + `u32_len_panics_instead_of_truncating` | code_directory.rs tests (shared helper used by both builder files) | **not observable pre-fix on 64-bit without ≥4 GiB allocations** (honest note) | direct boundary tests of the narrowing helper `u32_len`: `u32::MAX as usize` → `u32::MAX`, `u32::MAX as usize + 1` → panic "exceeds u32::MAX". The defect itself (`len as u32` truncation) needs a >4 GiB input to observe, which the suite will not allocate; the helper test pins the contract at the only testable boundary |
| T12 | (folded into T11) superblob.rs routes every `as u32` through the same `u32_len`; its regression coverage is the existing round-trip suite (`test_superblob_*`, alignment `:1163`/`:1197`, empty `:891`) staying green | superblob.rs tests | not separately observable pre-fix (same ≥4 GiB class) | production-site sweep verified by grep (zero remaining `as u32` outside tests) + round-trips unchanged |

Gate commands (per brief): `mkdir -p .tmptmp` once, then every run as `TMPDIR=$PWD/.tmptmp cargo test -p zsign-core codesign` / `… cms_verify` (scoped per change), full-run evidence `TMPDIR=$PWD/.tmptmp cargo test -p zsign-core -- --skip test_ipa_signing_is_deterministic` (316 tests at base; ZSN-15 determinism skip as instructed), plus `cargo check -p zsign-core --target wasm32-unknown-unknown` recorded verbatim. No `cargo fmt` / `cargo clippy` / `hk` (brief forbids; orchestrator gates at merge). Release-mode evidence for T9/T10: `TMPDIR=$PWD/.tmptmp cargo test --release -p zsign-core <filter>` run before and after the fix, output quoted in the final report.

## 5. Cross-lane notes for ZSN-4 (fuzzing, active in parallel)

Panics this lane's fixes remove from the fuzzable surface:
1. `check_code_pages`: shift-overflow panic on hostile `pageSize` ≥ `usize::BITS` (debug builds; any byte 0–255 today), plus the `pageSize = 0/1` per-byte CPU-DoS via `1 << 0` — fixed by T1–T4. (Note: release-mode `<<` masks the shift amount, so `page_size` is never 0 — there is no `div_ceil(0)`/`chunks(0)` panic; the release failure mode is a wrong page size, now impossible after parse validation.)
2. `CodeDirectory::parse`/`code_hashes`/`special_slot_hash`: slice/underflow panics from hostile `nCodeSlots`/`nSpecialSlots` — T5–T7.
3. `normalize_ber_lengths`: stack overflow on deep nesting — T8. (A corpus of nested `30 80 … 00 00` crashes today.)
4. Builder panics are **not** fuzz-reachable through verify paths (builders are never called on untrusted bytes); after this lane, fuzzers hitting the *builder* API with absurd lengths would see the new preconditions panic — by design (trusted-API contract).

Out-of-scope observations for other lanes: see §7.

## 6. Research inputs (librarian, source-verified 2026-09-25/26) and how they shaped decisions

### pageSize semantics (feeds C1)
- Apple's field contract is `uint8_t pageSize; // log2(page size in bytes); 0 => infinite` — `apple-oss-distributions/Security` `OSX/libsecurity_codesigning/lib/codedirectory.h` L201; identical in xnu `osfmk/kern/cs_blobs.h` L225. **SUPPORTS** the whole-file reading of 0.
- Apple's integrity check treats 0 as one slot over the whole range and *requires* `nCodeSlots == (limit > 0)`: `if ((limit > 0) != nCodeSlots) throw` (`codedirectory.cpp` L207-210, L399). **SUPPORTS** the chosen `expected = if region empty {0} else {1}` semantics exactly.
- For `pageSize != 0` Apple's only check is the coverage equation `coveredPages = ((limit-1) >> pageSize) + 1 == nCodeSlots` plus the slot-array bounds (`codedirectory.cpp` L201-206) — the equation `check_code_pages` already implements as `div_ceil` + length compare. No `12..=16` allow-list exists in open Apple sources (**[UNVERIFIED]** as an Apple rule; the kernel-side enforcer is not open). **Decision:** the `12..=16` bound is adopted from the **lane brief's hardening mandate** (“constrain to the legal range (12..=16 plus Apple's 0…)”), not claimed as Apple's: it covers every value observed in the wild (ldid `PageShift_ = 0x0c`, zsign `pageSize = 12`, go-macho `PAGE_SIZE_BITS = 12`, Apple TN3126 `Page size=4096`; 16 KiB → 14 for modern macOS) while excluding the shift-overflow/DoS region and implausible values. Rejecting outside this set is deliberately **stricter than Apple** — fail-closed for a verifier; recorded as a policy choice so the tradeoff is visible.
- Apple performs its own slot arithmetic in 64-bit intermediates (`hashSize * (int64_t(nSpecialSlots) + nCodeSlots)`, `codedirectory.cpp` L180-181) **SUPPORTS** (b)'s checked/widened product.
- Bug-class precedent: go-macho ships the same unchecked `1 << cd.Header.PageSize` on an untrusted u8 (`pkg/codesign/codesign.go` L413) — cross-lane evidence this class is real in the ecosystem.
- Rust semantics (feeds test expectations): the Reference lists `<<`/`>>` with rhs ≥ type width as debug-mode integer-overflow **panic** (reference/expressions/operator-expr.html#overflow); with checks off the shift masks (`1usize << 64` → `1`, std `unbounded_shl`/`wrapping_shl` docs) — release gives a *wrong page size*, never 0, so no `div_ceil(0)` is possible; the DoS reading (=0 → per-byte) comes only from the `1 << 0` case. `as` casts “truncate” silently (reference, `expr.as.numeric.int-truncation`) — the justification for `u32::try_from` over `as`.

### Special slots / hash sizes (feeds H1, (b))
- The digest array is a flat fixed-stride array: element size is the declared `hashSize` for **both** special and code slots (`codedirectory.h` L152-160, L193-201: `getSlot()` = `at(hashOffset) + hashSize * slot`); absent special slots are zero-filled and “this is not an error”. **SUPPORTS** per-slot `len == hash_size` at build time (H1) and the existing zero-fill behavior for missing slots (unchanged).
- Type→length table per Apple: {1→20, 2→32, 3→20 truncated, 4→48} (`CSCommon.h` L380-387, `cs_blobs.h` L137-141). The builder passes `CS_SHA1_LEN`/`CS_SHA256_LEN` paired with the hash type itself, so H1 validates against “the current algorithm's hash size” as the brief requires. The parse side already whitelists `hash_type ∈ {1,2}` and `hash_size ∈ {20,32}` (`verify.rs:670-677`); a stricter hash_type↔hash_size pairing check exists in Apple only partially (`checkIntegrity` does not cross-check) and is **not** one of findings (a)–(i) — noted, not added (scope discipline).
- CDHash is always 20 bytes regardless of hash type (`CS_CDHASH_LEN = 20`, TN3126) — no code in this lane assumes `cdhash.len() == hash_size` (verified: `cdhash()`/`cdhash_sha256()`/`cdhash_pair` compute per declared type independently).

### Depth cap (feeds D1)
- OpenSSL caps constructed ASN.1 nesting at **30** with the explicit anti-DoS comment “excessive recursion … limit the stack depth” (`crypto/asn1/tasn_dec.c` L23-27).
- RustCrypto `der` caps at **64** with `checked_add` (`der/src/reader/position.rs` L14-20, L75-79, “prevents stack exhaustion”).
- `bcder` (behind `cryptographic-message-syntax`) has **no** numeric cap; it bounds structurally (per-level `limit.checked_sub`, explicit stack) — structural containment alone does not bound *depth* for tiny nested frames, which is exactly finding (d). **Decision:** numeric cap 32 = in-repo precedent (`verify.rs` DER cap 32, requirements cap 64) + OpenSSL's magnitude; simple depth parameter, not a parser rewrite (D2 rejected).
- The brief's suggested RFC 5649/8410 citations are irrelevant to length/depth rules (AES Key Wrap padding / ECC algorithm identifiers respectively); the governing spec for definite-length strictness is ITU-T X.690 §8.1.3.5/§8.1.3.6.1/§10.1. `read_tlv`'s `count > 8` long-form rejection is stricter than `der`'s ≤4-octet rule but bounds the same way (≤8 bytes accumulated, extent-checked immediately after) — inside the *checked* set already; unchanged (and read_tlv is outside the normalizer region anyway).

### wasm32 (feeds T7 + Task 6 gate)
- `wasm32-unknown-unknown` `pointer_width: 32` (rustc target spec); `usize::BITS == 32` (reference/types/numeric.html). On wasm32, `pageSize = 40` is a **debug panic** where x86_64 succeeds — target-divergent behavior for identical bytes; and `n_code * hash_size` wraps where 64-bit does not. Checked ops are width-parameterised in contract, `as` casts are not. **SUPPORTS** checked arithmetic everywhere + the `cargo check --target wasm32-unknown-unknown` compile evidence the brief allows (tests for the 32-bit wrap branch are additionally `cfg(target_pointer_width = "32")`-gated, see T7).

## 7. Explicitly out of this lane (observed, documented, not fixed)

- `cms_verify.rs:643-644` `len = (len << 8) | *b` inside `read_tlv` (signed-attrs TLV reader — *not* the BER normalizer region; brief: “if your fix needs non-BER changes there, STOP and report”). Silent bit-loss only on 32-bit with >4-byte lengths; the following `checked_add` + extent `get()` rejects the result. Noted for ZSN-4/possible follow-up ticket.
- `macho/verify.rs:843` `1usize << signed[cd + 39]` — ZSN-25 file, read-only per brief; test-side fixture code pinned to page size 12.
- `macho/parser.rs:439` `start + slice.code_length` — parser territory (other lanes).
- hash_type↔hash_size pairing check at parse (see §6) — beyond findings (a)–(i); current whitelists already fail closed.
- `u32` truncation observability (e)/(f): the *defect* requires ≥4 GiB inputs to reproduce; the suite will not allocate that. Contract is pinned at the helper boundary (T11/T12) and the production sites are swept by grep — stated honestly rather than engineered around with fabricated slices.

## 8. Deliverables

- Design: `docs/superpowers/specs/2026-09-25-checked-arith-design.md` (this document).
- Plan: `docs/superpowers/plans/2026-09-25-checked-arith.md`.
- Both force-added (`git add -f`); root `.gitignore` untouched (lane-collision rule).
