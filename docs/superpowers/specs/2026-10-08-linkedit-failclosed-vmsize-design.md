# Fail-closed missing __LINKEDIT + correct realloc vmsize delta — Design

Date: 2026-10-08
Lane: w2-macho-writer (branch w2-macho-writer)
Scope: `crates/zsign-core/src/macho/writer.rs` only.

## Problem 1 — fail-open missing __LINKEDIT

`embed_signature_single` (writer.rs:575) writes the LC_CODE_SIGNATURE
(update at :640-647 or insert at :648-661) and then consults `linkedit_cmd`
with `if let Some(...)` at :656-664 having **no else arm**, falling through
to `Ok(output)` at :666. On a Mach-O whose `__LINKEDIT` was not captured
(parser.rs:58/:290-310 only records a `__LINKEDIT` whose segment width matches
the header — a 32-bit header with an LC_SEGMENT_64 `__LINKEDIT` is
deliberately left as `None`, "failing closed rather than corrupting sizes",
parser.rs:287-289; a genuinely absent `__LINKEDIT` likewise), the function
returns `Ok` with an LC_CODE_SIGNATURE whose `dataoff = sig_offset` lies
outside every mapped segment.

Five sibling write paths already fail closed on the identical condition with
`Err(Error::MachO("No __LINKEDIT segment found".into()))`:
1. `realloc_code_sign_space_single` (writer.rs:227)
2. `prepare_code_single` (writer.rs:1311)
3. `realloc_code_sign_space_with_metadata` (writer.rs:1402)
4. `prepare_code_for_signing_with_metadata` (writer.rs:1549)
5. `prepare_code_in_place` (writer.rs:1658)

`embed_signature_single` is the sole outlier; it is reachable from the
exported `embed_signature` (writer.rs:319-321, Mach::Binary arm) → facade
`write_signed_macho`/`write_signed_macho_in_place` (crates/zsign/src/macho/mod.rs:43,54).

### External contract (research-phase citations; [UNVERIFIED EXTERNAL] — not re-checkable in this worktree)
- dyld rejects missing `__LINKEDIT` outright for non-preload images
  (MachOFile.cpp:2914-2917) and rejects a code signature extending beyond the
  LINKEDIT segment (MachOLayout.cpp:266-269; Image.cpp:479-481).
- Apple's own signer refuses to produce such a file:
  `codesign_alloc.cpp:232-233` "malformed mach-o file, no __LINKEDIT segment".
- Upstream zsign fails closed (archo.cpp:610-612 → macho.cpp:172-176).
- Conclusion: the current `Ok` output is an unloadable `malformed mach-o`,
  never a usable binary; `Err` is the only outcome consistent with all tooling.

## Problem 2 — wrong realloc growth delta

Both realloc variants compute the vmsize delta from the WRONG base:

- `realloc_code_sign_space_single` (writer.rs:204-212):
  `size_increase = required - data.len()` (:206), then
  `new_vmsize = align_to_checked(old_vmsize + size_increase, PAGE_SIZE)` chain (:207-212).
- `realloc_code_sign_space_with_metadata` (writer.rs:1377-1385): byte-identical
  at :1379-1385, and it *persists* the value into
  `updated_metadata.linkedit_cmd` (:1400), returned to the signer's callers
  (the `realloc_code_sign_space_with_metadata` call sites at signer.rs:475
  and :610 receive the updated `MachOMetadata`).

But the returned buffer is built as `data[..code_length].to_vec()`
(:202 / :1373) and resized to `required` (:296 / :1472) — actual growth is
`required - code_length`. Whenever `data.len() > code_length` (the tail
`[code_length, data.len())` is discarded) the declared vmsize is under-declared
by exactly `D = data.len() - code_length` before page rounding.

Verified regimes:
- `data.len() > code_length` — the live bug (declared delta smaller than real growth).
- `data.len() == code_length` — deltas agree; every existing delta test sits here.
- `data.len() < code_length` — impossible (rejected at :180-185 / :1345-1350).

Concrete reproduction (arithmetic over source constants, fixture
`make_minimal_macho` + `big_signed_buffer` writer.rs:2128, exercised by the
existing `test_realloc_expands_to_cover_declared_reserve` writer.rs:2144):
`realloc_code_sign_space(&big_signed_buffer(), 0x3000)` writes
`__LINKEDIT.vmsize = 0x2000` but `__LINKEDIT.filesize = 0x7000`
(`new_filesize = required - fileoff = 0x9000 - 0x2000`) — `filesize > vmsize`,
the exact dyld-fatal shape (MachOFile.cpp:2821-2826 "filesize exceeds vmsize").
The corrected delta (`required - code_length = 0x6000`) yields
`vmsize = align4096(0x1000 + 0x6000) = 0x7000 = filesize`.

No test pins the delta today: the only vmsize read after a realloc is
`written >= HUGE` (writer.rs:3168-3172, passthrough/floor policy); case-(a)
tests (writer.rs:2144, :2340) assert only length/reparse/dataoff and pass with
the malformed output. `parser.rs:343-354` validates only
`fileoff + filesize <= slice_len`, never vmsize, so the bad output reparses.

### External contract (research-phase citations; [UNVERIFIED EXTERNAL] — not re-checkable in this worktree)
- Load-time invariant: `filesize <= vmsize` is hard dyld-fatal
  (MachOFile.cpp:2821-2826/2846-2851); page-alignment of vmsize is NOT
  dyld-enforced (MachOFile.cpp:2052-2054) but is the ld64/codesign convention.
- `vmsize >= filesize` and `vmsize >= original vmsize` are the invariants;
  `update_linkedit_segment` (writer.rs:1105-1125) already implements
  `align_to(new_filesize, 0x4000).max(original_vmsize)`.
- Pinned repo policies the fix must not disturb: non-overflowing huge
  old vmsize passes through (writer.rs:3161 `written >= HUGE`); overflowing
  extension errors `"__LINKEDIT vmsize extension overflows"`
  (tests writer.rs:3102, :3120, :3141).

## Candidate designs

Note: the dyld / codesign_alloc / ld64 / upstream-zsign line citations in the
two External contract sections were gathered during the research phase by
fetching those projects' public sources; they are accurate to those fetches
but cannot be re-verified against this worktree.

### Problem 1 candidates
**A — else arm with the siblings' exact error (CHOSEN).**
Add `else { return Err(Error::MachO("No __LINKEDIT segment found".into())) }`
to the terminal `if let` of `embed_signature_single`. Identical message to all
five siblings; smallest possible change; matches Apple/ld64/upstream-zsign
fail-closed behaviour.
**B — omit the LC_CODE_SIGNATURE when `linkedit_cmd` is None.** Rejected:
diverges from all five siblings (inconsistent error surface for one
condition), and an "successfully" unsigned output from a signing API is a
silent no-op contract violation.
**C — synthesize a `__LINKEDIT` segment.** Rejected: invents load commands,
far outside a defect fix.

### Problem 2 candidates
**A — fix the delta base to `required - code_length` + fail-closed
disagreement guard (CHOSEN).**
1. `size_increase = required - code_length` at both sites — declared growth
   equals the buffer's actual growth. The wave-1 chains
   (`checked_sub` for `new_filesize` :213-216/:1386-1389, the
   `try_from/checked_add/align_to_checked` vmsize chain :207-212/:1380-1385)
   stay structurally intact; only the subtraction base changes. Ordering
   guaranteeing positivity is preserved: early return `required <= data.len()`
   (:199/:1368) + guard `code_length <= data.len()` (:180-185/:1345-1350)
   ⇒ `required > code_length`.
2. After `new_filesize` is computed, add a fail-closed guard at both sites:
   `new_vmsize < new_filesize` ⇒ `Err(Error::MachO(...))` (message names both
   values) — the dyld-fatal condition can never be written. Fix 1 alone leaves
   a residual corner (see Chosen design details) that hostile-but-reparse-clean
   inputs (tiny old vmsize, far-out code_length) can still reach.
   The guard is the unconditional closer for "vmsize and filesize disagree".
- Note on the ticket's "no `max(original_vmsize, ..)` guard" observation: on a
  delta path the floor is vacuous — the delta is strictly positive (above), so
  `align(old + delta) >= old` always. A `max()` floor is only meaningful for a
  filesize-derived recompute (candidate B), which is why it is absent here.
- Residual corner: `new_vmsize < new_filesize` requires
  `old_vmsize + fileoff < code_length` (necessary; sufficient only modulo the
  0..4095 page-pad absorbed by `align_to_checked`), which hostile-but-reparse-clean
  inputs (tiny old vmsize, far-out code_length) can still reach.
  The guard is the unconditional closer for "vmsize and filesize disagree".
- Existing case-(a) tests stay green under fix 1 (delta correction turns their
  written vmsize from `0x2000` to `0x7000`, which is what they implicitly need);
  the guard never trips on them (verified arithmetic above).
**B — recompute vmsize absolutely: `align(new_filesize).max(old_vmsize)` (the
`update_linkedit_segment` pattern / Apple `codesign_alloc.cpp:308-319`).**
Rejected: `max()` passes a hostile huge old vmsize through, converting the
three pinned `"vmsize extension overflows"` `Err` tests (writer.rs:3102,
:3120, :3141) into successes-with-huge-vmsize — it changes the overflow
ticket's pinned passthrough policy rather than composing with it; it also
rewrites benign outputs (its `update_linkedit_segment` rule would turn the
control example's delta-derived vmsize `0x7000` into
`align_to(0x7000, 0x4000) = 0x8000`), churning behaviour beyond the defect.
**C — disagreement guard only, leave delta.** Rejected: the wrong delta would
make the guard fire on the existing passing case-(a) tests, converting green
tests to `Err` — the delta is the bug, not the inputs.

## Chosen design details

- Problem 1: else arm exactly as sibling Err strings (verbatim reuse).
- Problem 2: both realloc sites; `size_increase` rebased to `required - code_length`
  (plain `-`, same style as today — underflow impossible by the ordering above);
  new guard after `new_filesize` in both fns, before `write_linkedit_sizes`.
  Site B keeps persisting both corrected values into `updated_metadata`.
- Error style per file convention: `Error::MachO(format!(...))` naming the
  offending values for the new guard; literal `.into()` for the reused sibling message.
- No changes to parser.rs, signer.rs, prepare_* fns, or the wave-1 chains.

## Testing strategy

TDD; tests appended at the end of writer.rs's inline test mod (after the
Item-1 tests; NOT mid-suite). Idioms: `expect_err` + `contains` for errors,
`matches!` + `res.as_ref().err()` footer where surrounding tests use it,
`catch_unwind` for adversarial inputs, `MachOFile::parse` round-trip.

1. **Red test A (fail-closed)** `test_embed_signature_rejects_missing_linkedit`:
   feed `fixtures::make_minimal_macho_32_mixed_linkedit()` (fixtures.rs:256 —
   the constructible None-`linkedit_cmd` input) through `embed_signature`;
   failing-before: `Ok` returned; passing-after: `Err` containing
   `"No __LINKEDIT segment found"`.
2. **Red test B (delta)** `test_realloc_vmsize_covers_linkedit_filesize`:
   run `realloc_code_sign_space(&big_signed_buffer(), 0x3000)` (the case-(a)
   geometry), read `__LINKEDIT.vmsize` and `.filesize` from the output;
   failing-before: `vmsize (0x2000) < filesize (0x7000)`; passing-after:
   `vmsize >= filesize` (and pin `vmsize == 0x7000` to the corrected delta).
   Required metadata mirror via `realloc_code_sign_space_with_metadata`
   (hand-built `MachOMetadata`, asserting both the returned buffer and the
   persisted `updated_metadata.linkedit_cmd` pair).
3. **Red test C (guard)** `test_realloc_rejects_vmsize_below_filesize`:
   grow the buffer first so `data.len() >= code_length` (else the
   `code_length exceeds buffer` guard fires first), patch `__LINKEDIT` fileoff
   to `0x1000` and old vmsize to `0x1000`, then call with
   `code_length = 0x5000`, so the corrected delta still cannot cover
   `new_filesize`;
   failing-before: `Ok` with `vmsize < filesize`; passing-after: `Err` naming
   vmsize/filesize.
4. **Regression sweep**: entire writer test suite must stay green, especially
   writer.rs:2144/:2170/:2340 (case (a) realloc), :3102/:3120/:3141 (hostile
   `Err`), :3162 (huge passthrough), and the Item-1 FAT tests.

## Acceptance

- `cargo fmt --all -- --check` clean; `cargo clippy --workspace --all-targets -- -D warnings` clean.
- `TMPDIR=$PWD/target/tmp cargo test --workspace` green.
- Failing-before/passing-after tests for all three behaviours (49, 50-delta, 50-guard).
- Existing suite (incl. hostile-vmsize and passthrough policy tests) unchanged and green.
