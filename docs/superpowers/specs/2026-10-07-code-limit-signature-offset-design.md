# Design: codeLimit and the signature offset must be one value

## Problem

The CodeDirectory's `codeLimit` and the signature's file offset are derived
from two independently computed values that disagree whenever
`code_length % 16 != 0`:

- `codeLimit` comes from the length of the hashed buffer:
  `code_directory.rs:331` / `:423` compute
  `code_limit = u32_len(self.code.len())`, where `self.code` is the buffer
  `CodeDirectoryBuilder::new` by the signer
  (`signer.rs:851` over `&buf` from `signer.rs:529`/`:648`). The signer's
  `buf` is truncated to `code_length` by `prepare_code_in_place`
  (`writer.rs:1573`).
- `LC_CODE_SIGNATURE.dataoff` and the physical blob placement both come
  from `align_to(code_length, 16)`, at seven sites in `writer.rs`
  (`:185`, `:302`, `:601`, `:1234`, `:1306`, `:1455`, `:1561`; `align_to`
  itself at `:1112-1114`).

Consequence: the interval `[code_length, align_to(code_length, 16))` — 1
to 15 bytes, zero-filled at `writer.rs:606-608` or `signer.rs:758-759` —
is written into the file, sits below the declared `dataoff`, is inside the
rewritten `__LINKEDIT.filesize` extent (`writer.rs:1596`), and is covered
by no code slot (`nCodeSlots = ceil(code_length/4096)`). The hashed region
stops short of the signature offset.

`code_length` is `LC_CODE_SIGNATURE.dataoff` when re-signing and the whole
declared slice size for unsigned inputs (`parser.rs:363`), so the gap fires
on unsigned images with a length that is not a multiple of 16 and on
re-signs of images with an unaligned existing `dataoff`.

## Verified external contract

Citations in this section are externally verified against upstream sources
at the reviewed commits (Apple Security db15acbe, ld64 f60a74e, xnu
f6217f8, cctools e0d5662, zhlynn/zsign 614caa8) — not files in this
worktree.

- Apple derives both values from ONE number. `MachO::signingExtent()` is
  `LC_CODE_SIGNATURE.dataoff` verbatim when present, else file length
  (`macho++.cpp:515-524`); `signer.cpp:668-670` feeds it to the builder as
  `mExecLength`; `cdbuilder.cpp:229-234` sets `codeLimit` from
  `mExecLength`, `cdbuilder.cpp:158` derives `nCodeSlots` from it, and
  `cdbuilder.cpp:293-309` hashes exactly that many bytes; the blob is then
  written at the same `signingOffset()` (`signerutils.cpp:234-238`). So
  `codeLimit == dataoff` always holds in Apple's output.
- ld64 likewise passes the `__code_sign` section's own `fileOffset` as
  libcd's `image_size` (`LinkEdit.hpp:2231`, `libcodedirectory.c:838-844`).
- zsign (C++) rounds the length up to 16 FIRST and uses that single value
  everywhere: `m_uCodeLength = (uLength % 16 == 0) ? uLength :
  uLength + 16 - (uLength % 16)` (`archo.cpp:35`), then `codeLimit` from it
  (`signing.cpp:484`), `dataoff` from it (`archo.cpp:646`), and the blob
  copied at it (`archo.cpp:600`).
- Format-wise the pair may differ (`codeLimit` is only "limit to main image
  signature range", `cs_blobs.h:164`; the only structural check is
  `codeLimit` vs `nCodeSlots`, `codedirectory.cpp:206-215`), and the
  kernel/userspace hash only up to `codeLimit` (`ubc_subr.c:5798-5880`,
  `StaticCode.cpp:1308-1330`) — so today's gap does not fail verification,
  it silently leaves the last 1-15 bytes unhashed. 16-byte alignment of
  `dataoff` is a codesign/ld64 layout choice (`codesign_alloc.cpp:299`,
  `LinkEdit.hpp:2201`), not a format rule.

## Chosen design

Make the prepared buffer the single source of truth: every prepare path
materializes the alignment pad, so the buffer handed to the hasher and the
CodeDirectory builder is exactly `sig_offset` bytes long. Then

```
buffer.len() == codeLimit == LC_CODE_SIGNATURE.dataoff == blob offset
```

holds by construction, exactly like Apple's `signingExtent()` and zsign's
`m_uCodeLength`.

Changes (all in `crates/zsign-core/src/macho/writer.rs`):

- `prepare_code_in_place` (`:1553`): after the existing
  `buf.truncate(code_length)` (`:1573`), zero-extend to `sig_offset`
  (`buf.resize(sig_offset, 0)`). Order matters: truncate first so stale
  old-signature bytes in `[code_length, sig_offset)` are discarded before
  the pad is (re)filled with zeros.
- `prepare_code_single` (`:1178`, backing `prepare_code_for_signing` /
  `prepare_code_for_signing_slice`): `prepared` (currently
  `data[..code_length].to_vec()` at `:1237`) is zero-extended to
  `sig_offset` before being returned as the hash-ready buffer.
- `prepare_code_with_metadata` (`:1437`): same extension of `prepared`
  (`:1467`).
- Doc comments on the three functions and the signer's step comment
  (`signer.rs:528`) updated to describe the padded buffer.

No signer changes are needed: `hash_code_pages_dual(&buf)`
(`signer.rs:529`, `:648`) and `CodeDirectoryBuilder` already derive
`codeLimit`/`nCodeSlots` from `buf.len()`, which becomes `sig_offset`.
`nCodeSlots` is unchanged by the pad: `ceil(align16(cl)/4096) ==
ceil(cl/4096)` for all `cl`, and the pad is absorbed by the
`CODE_SIGN_PADDING` (16 KiB) reserve, so no bound check changes outcome.

`crates/zsign-core/src/codesign/code_directory.rs` needs NO change: with
the buffer as the single truth, `codeLimit != dataoff` becomes impossible
at construction; a redundant explicit invariant there would be a second
source of truth.

## Alternatives considered

- **Place the blob at `code_length`, drop 16-byte alignment**: rejected.
  Four `dataoff % 16 == 0` asserts across three tests pin the convention —
  `writer.rs:2283-2337` (asserts at `:2309`, `:2329`), `:2340-2358`
  (assert at `:2353`), `:2361-2380` (assert at `:2374`), plus a
  `sig_offset` pin at `writer.rs:2800` — matching codesign/ld64 layout, and the whole write path
  (`has_enough_signature_space`, reserve formula, embed) computes from
  `align_to(code_length, 16)`. Inverting seven sites for a format-legal
  but convention-breaking offset is strictly more blast radius for the
  same closure.
- **Explicit `code_limit` parameter on `CodeDirectoryBuilder`**:
  rejected. It re-introduces two sources of truth (caller-declared limit
  vs buffer the hashes actually came from) and the pad bytes must exist in
  the hashed buffer regardless — the buffer length is already the natural
  single value.
- **Fix only `prepare_code_in_place`, leave the other two prepare
  paths**: rejected. `prepare_code_for_signing` /
  `prepare_code_for_signing_slice` are public API whose documented purpose
  is producing a buffer "for hash computation"; leaving two of three
  prepare paths returning a buffer whose length is not the declared
  `dataoff` would keep the gap alive through the public surface and create
  a second convention inside one file.

## Invariants

1. For every signed output: CodeDirectory `codeLimit` ==
   `LC_CODE_SIGNATURE.dataoff` == physical blob offset.
2. The 1-15 pad bytes between the old `code_length` and `sig_offset` are
   zeros in the file AND covered by the final code slot.
3. `nCodeSlots` equals `ceil(code_length / 4096)` — unchanged from today.
4. Already-16-aligned inputs (the overwhelmingly common case, including
   every re-sign of our own output) produce byte-identical results: the pad
   is zero-width.
5. `align_to`, the reserve formula, the realloc delta computations, and
   `has_enough_signature_space` semantics are untouched.

## Out of scope (owned by other tickets, deliberately untouched)

- The realloc delta computations (`writer.rs:205-210`, `:1333-1337`).
- The `ArchSlice` metadata stamp `code_sig_offset: code_length`
  (`signer.rs:488`, `:622`) — a separate surface of the same root cause,
  mapped but not ours; the emitted LC/CD bytes are what this invariant
  binds.
- `codeLimit64` always-0, `u32_len` 4 GiB cap (`code_directory.rs`).
- FAT container padding and `__LINKEDIT` capture gaps.

## Test strategy

Tests fail before the fix (codeLimit `0x2001` vs dataoff `0x2010`) and
pass after it; all live next to the existing unaligned-signing tests in
`crates/zsign-core/src/macho/writer.rs`:

1. **Unsigned unaligned thin image**: `make_minimal_macho()` resized to
   `0x2001` bytes, signed with `sign_macho_adhoc`, reparsed — assert the
   CodeDirectory `codeLimit` equals the `LC_CODE_SIGNATURE.dataoff`
   (`0x2010`), and `check_code_pages` over `signed[..dataoff]` reports
   `Matched`, proving the pad bytes are hashed consistently.
2. **Re-sign with unaligned existing dataoff**:
   `make_signed_minimal_macho_at(0x2001, …)` re-signed — assert the same
   `codeLimit == dataoff` equality on the output.
3. Existing suite is the regression net for invariants 3-5 (alignment
   tests, `verify_code_directory`'s `code_limit == code.len()`, capacity
   guard, roundtrips) — run in the gate.

## Test verification commands

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test --workspace
```

Scoped during flight:
`TMPDIR=$PWD/target/tmp cargo test -p zsign-core writer` and
`TMPDIR=$PWD/target/tmp cargo test -p zsign-core signer`.
