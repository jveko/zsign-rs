# FAT reassembly: align exponent cap, offset cross-check, output size guard — Design

Date: 2026-10-08
Lane: w2-macho-writer (branch w2-macho-writer)
Scope: `crates/zsign-core/src/macho/writer.rs` only.

## Problem

`embed_fat_from_signed_slices` (writer.rs:440) honours an attacker-controlled
`fat_arch.align` exponent when reassembling a universal binary:

- The only guard is `arch.align >= 32` (writer.rs:499-504) before
  `1usize << arch.align` (writer.rs:505) and cursor alignment (writer.rs:506-509).
- `u32::try_from(cursor)` (writer.rs:510-511) accepts 2^31 (< u32::MAX), so it
  does not bound the allocation.
- `let total_size = cursor;` (writer.rs:520) and `vec![0u8; total_size]`
  (writer.rs:521) allocate before any size relationship to the input exists.
- The function never receives the input container bytes, so `total_size` is
  never capped relative to input size; the input `arch.offset` is only used in
  the identity cross-check (`signed.offset != arch.offset`, writer.rs:469) and
  `arch.offset % 2^align == 0` is checked nowhere (parser.rs FAT branch
  :195-225 and `validate_fat_arches` :413-438 never read `align`).

Verified arithmetic: one arch with `align = 31` and a signed slice of length L
yields `total_size = 2^31 + L`; for the 12,288-byte reference container
(L = 28,672) that is a 2,147,512,320-byte allocation ≈ 174,765× amplification.
Reachable from four public families: `embed_signature_fat` /
`embed_signature` (re-exported by `zsign_core::macho` and `zsign_rs::macho`),
`sign_any_macho` / `sign_macho_adhoc` / `sign_macho_sha256_only` (also via IPA,
CLI and wasm `sign_macho_fat`), and `inject_dylib_command`.

## External contract (verified, cited in research log)

- `fat_arch.align` is "alignment as a power of 2" (cctools include/mach-o/fat.h:67);
  the spec states no upper bound.
- cctools `lipo` hard-caps input exponents: `MAXSEGALIGN/MAXSECTALIGN = 15`
  (align.h:31, lipo.c:75), fatals any incoming `fat_arch.align > 15`
  (lipo.c:1262-1268, 1346-1352) and fatals `offset % (1 << align) != 0`
  (lipo.c:1269-1276, 1353-1360).
- LLVM's universal writer clamps to `MaxSectionAlignment = 15`
  (MachOUniversal.h:37, MachOUniversalWriter.cpp:37-67) and checks the 32-bit
  offset limit (MachOUniversalWriter.cpp:266-285) — the same limit our
  `u32::try_from` already provides.
- dyld bounds slice count (16) and page alignment of slice offsets, but imposes
  no align-exponent bound (Universal.h:72, Universal.cpp:136-145).
- Upstream zsign discards the input align and hardcodes 14 (macho.cpp:188,210).
- No real producer emits an exponent above 15; realistic values are 2/3/12/14/15.

## Candidate designs (brainstorm record)

**A — cap only (`align > 15` rejected).**
Smallest change, lipo parity. Leaves two named gap clauses open: no
input-offset cross-check, and `total_size` still unrelated to input size.
Rejected as insufficient alone.

**B — cap ≤ 15 + input offset cross-check + total_size guard (CHOSEN).**
Closes all three gap clauses:
1. `arch.align > 15` → `Error::MachO` (replaces the `>= 32` check; same
   `format!`-style message naming the offending value). Per-slice padding
   becomes absolutely bounded to 32,767 bytes — the memory amplifier is gone
   even before the other two guards.
2. `arch.offset % (1 << arch.align) == 0` → `Error::MachO`, exactly lipo's
   interop check; validates the *input* container the reassembly came from.
3. Pass the input container length into `embed_fat_from_signed_slices` from
   its three call sites (embed_signature :357, embed_signature_fat :404,
   inject_dylib_command :1004 — all already hold `data`) and, after the
   cursor loop, require
   `total_size <= input_len + sum(signed slice len) + arches.len() * (1 << 15)`.
   Rationale: `header_size <= input_len` (the arch table lives in the input;
   goblin bounds `nfat_arch` at parse time), `sum(signed)` is caller-provided
   memory, and `n * 2^15` is the exact ceiling of `sum(padding)` under the cap
   (each slice's padding is `< 2^align <= 2^15`). The bound is linear in
   input + provided slices, is satisfiable by every well-formed container, and
   fails closed if any upstream assumption drifts. This is the epic's stated
   "cap <= 15 + total_size guard" direction.
Cost: one extra `usize` parameter on a private fn; three call-site updates.
Trade-off accepted: the guard is defense-in-depth (guards 1+2 are the primary
fix), which is what a memory-exhaustion ticket should have.

**C — recompute align like upstream zsign (hardcode 14, ignore input).**
Rejected: changes output bytes for every FAT reassembly, breaks the existing
behavioural test `test_embed_fat_aligns_each_slice_to_its_declared_exponent`
(writer.rs:2611-2672) which pins per-declared-exponent layout, and discards
container identity the identity checks deliberately preserve.

## Chosen design details (B)

- Guard order inside the per-arch loop: exponent cap first (cheap, absolute),
  then `arch.offset % (1 << arch.align) == 0`, then the existing cursor math.
  With `align <= 15`, `1usize << arch.align` cannot overflow; the wave-1
  `checked_add` chains (writer.rs:506-509) stay untouched.
- The offset cross-check applies to the *input* arch (from the parsed
  container), not the recomputed offsets — the recomputed ones are aligned by
  construction.
- `total_size` guard runs after the loop, before `vec![0u8; total_size]`
  (writer.rs:521), so no oversized allocation can occur on the failing path.
- New/changed error messages follow the file's convention
  (`Error::MachO(format!(...))` naming the offending value); the old
  "exceeds the 32-bit FAT offset space" message is superseded by the ≤15 cap
  message (no existing test asserts that string — verified: none of the 11
  FAT/align tests exercise align ≥ 32).
- No slice-count cap here: FAT parse/count policy belongs to other lanes'
  parser tickets; this design must not edit parser.rs.

## Testing strategy

TDD; tests live in writer.rs's inline test mod (the FAT/reassembly suite runs
writer.rs:2504-2869). Reuse `fixtures::make_fat_macho(slices, aligns)`
(fixtures.rs:663-697) and the established hostile-field idiom of patching the
arch table bytes at `8 + i*20` (idiom at writer.rs:2707-2712). Assertion style
matches the surrounding FAT tests (`expect_err(...)` + `contains(...)`, with
the `matches!` + `res.as_ref().err()` footer where the surrounding test uses it).

1. **Cap**: container with align 16 (and 31) → `Err` naming the exponent;
   align 15 still accepted (boundary), align 12/15 accepted (existing test
   at :2611 already pins 15/12 — must keep passing).
2. **Offset cross-check**: patch a well-formed fixture's arch offset to a
   value not divisible by `2^align` → `Err`.
3. **total_size guard**: the guard must hold on every well-formed path
   (existing FAT tests keep passing) and be unit-asserted where reachable;
   if no natural input can trip it under guards 1+2, assert the invariant on
   the successful output (`output.len() <= input_len + signed_total + n*32768`)
   in the boundary test instead of contriving a trip.

## Acceptance

- `cargo fmt --all -- --check` clean, `cargo clippy --workspace --all-targets -- -D warnings` clean.
- `TMPDIR=$PWD/target/tmp cargo test --workspace` green.
- New failing-before/passing-after tests for the cap and cross-check.
- Existing FAT tests (writer.rs:2504-2869, including the
  `inject_dylib_command` FAT reassembly tests that exercise call site :1004)
  unchanged and green.
