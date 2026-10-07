# Design: no panic on hostile `__LINKEDIT` vmsize in the realloc path

## Problem

Both realloc variants compute the extended `__LINKEDIT` vmsize with fully
unchecked arithmetic from an attacker-controlled `u64`:

- `realloc_code_sign_space_single`
  (`crates/zsign-core/src/macho/writer.rs:206`):
  `let new_vmsize = align_to(old_vmsize as usize + size_increase, PAGE_SIZE) as u64;`
- `realloc_code_sign_space_with_metadata`
  (`crates/zsign-core/src/macho/writer.rs:1334`, expression at `:1344`):
  same shape from `metadata.linkedit_cmd`'s `vmsize`.

`old_vmsize`/`vmsize` is `segment_command_64.vmsize` (`u64`, captured at
`writer.rs:166`/`:170-174` from parser metadata `parser.rs:290-292`,
`:304-310`); the parser validates only `fileoff + filesize`
(`parser.rs:342-353`), never `vmsize`. Consequences:

- On 64-bit, `vmsize as usize + size_increase` overflows for
  `vmsize >= usize::MAX - size_increase + 1`: a panic in debug AND
  release builds. There is no `catch_unwind` anywhere in the workspace, so
  the panic reaches CLI (`zsign-cli`), wasm, and facade callers instead of
  an `Error`.
- `align_to` itself (`writer.rs:1112-1114`,
  `(value + alignment - 1) & !(alignment - 1)`) is a second overflow
  point for `value > usize::MAX - (PAGE_SIZE - 1)`.
- On wasm32 (a CI-checked target, `.github/workflows/ci.yml:88`),
  `vmsize as usize` truncates the `u64` silently before the add.
- When the arithmetic does not overflow, the value is written verbatim
  into the signed image by `write_linkedit_sizes` (`writer.rs:1037`;
  `u64` at `lc_offset + 32` for 64-bit images) and propagated into the
  returned metadata (`writer.rs:1361`).

The surrounding code is already fully checked: `signature space overflow`
(`:189-191`), `__LINKEDIT fileoff exceeds required length` (`:207-210`),
`signature reserve end overflow` (`:1327-1329`), and — further down the
same call chain — `checked_u32(vmsize …, "__LINKEDIT vmsize")` inside
`write_linkedit_sizes` for 32-bit images (`writer.rs:1049-1058`). These
two `new_vmsize` lines are the unchecked hole.

## Verified external contract

Citations are externally verified against upstream sources at the reviewed
commits — not files in this worktree.

- zsign (C++) extends the input value with NO guard:
  `seglc->vmsize = ZUtil::ByteAlign(BO((uint32_t)seglc->vmsize) +
  (uNewLength - m_uLength), 4096)` (`src/archo.cpp:627-631`);
  `ByteAlign` is plain wrapping `u32` addition (`src/common/util.cpp:74-77`)
  and the `(uint32_t)` cast truncates first — silent wraparound, no
  rejection.
- Apple's `codesign_allocate` ignores the input vmsize entirely and
  recomputes `vmsize = (newFileSize - fileoff + 0x3FFF) & -0x4000`
  (`codesign_alloc.cpp:308-319`), and uses `os_add_overflow` for the
  adjacent file-size computation (`codesign_alloc.cpp:301-304`) — checked
  arithmetic plus typed rejection is Apple's house style too.
- dyld rejects `vmaddr + vmsize` wrap outright (`MachOFile.cpp:2891-2895`)
  and requires `filesize <= vmsize` (`:2820-2825`); page rounding of
  `__LINKEDIT` vmsize is explicitly NOT required (`:2052`). A wrapped or
  absurd vmsize is a malformed-image condition, not something to paper
  over.
- The kernel trusts `seg->vmsize` when computing VM bounds
  (`dyld_kernel_fixups.h:451-497`) — a silently wrapped value yields
  bogus highest-vmaddr math rather than a clean failure.

## Chosen design

Convert, add, and align with checked arithmetic only; on any overflow,
return the repo's typed error instead of panicking:

```rust
let new_vmsize = usize::try_from(old_vmsize)
    .ok()
    .and_then(|v| v.checked_add(size_increase))
    .and_then(|v| align_to_checked(v, PAGE_SIZE))
    .ok_or_else(|| Error::MachO("__LINKEDIT vmsize extension overflows".into()))?
    as u64;
```

with a private helper next to `align_to` (`writer.rs:1112`):

```rust
/// [`align_to`] with overflow checking: `None` when the rounding step
/// `value + alignment - 1` would overflow `usize`. `alignment` must be a
/// power of two, as [`align_to`] requires.
fn align_to_checked(value: usize, alignment: usize) -> Option<usize> {
    value.checked_add(alignment - 1).map(|v| v & !(alignment - 1))
}
```

- Applied at both cited sites (`:206`, `:1344`), each expression only;
  the `size_increase = required - data.len()` lines (`:205`, `:1343`) and
  their operands are untouched (the wrong-delta gap is a separate ticket).
- `usize::try_from` closes the wasm32 truncation hole: on 64-bit hosts it
  is infallible, on wasm32 a `vmsize > u32::MAX` is rejected instead of
  silently truncated. Segment32 values (`<= u32::MAX`) still fit on every
  target, so behavior for legitimate 32-bit images is unchanged.
- `align_to` keeps its public signature — it is re-exported
  (`macho/mod.rs:24`, facade `crates/zsign/src/macho/mod.rs:32`), and
  changing it would ripple through deferred crates and non-`Result`
  callers (`has_enough_signature_space`). The guard belongs at the two
  unbounded-input call sites.
- Error style matches the dominant idiom at these exact lines: static
  `&str` `Error::MachO(...)` from `.ok_or_else(...)`, same as
  `signature space overflow` a few lines above.

## Alternatives considered

- **Saturating arithmetic**: rejected — `saturating_add` followed by
  `align_to(usize::MAX)` still overflows inside `align_to`, and clamping
  would write a fabricated page-aligned maximum verbatim into the signed
  image: corruption replacing the panic, with no typed signal.
- **Changing `align_to` to return `Option`**: rejected — public,
  re-exported API (breaks the deferred facade lane's compile surface) and
  called from `bool`-returning contexts that cannot `?`.
- **Recomputing vmsize from `filesize` (Apple's policy)**: rejected for
  this item — it changes the vmsize VALUE policy, which is coupled to the
  wrong-realloc-delta ticket we must not pre-empt; this item closes the
  overflow gap only.
- **Magnitude threshold** (reject `vmsize > f(file size)`): rejected —
  invents a magic bound with no in-repo precedent; dyld's real rule
  (`vmaddr + vmsize` no-wrap, `filesize <= vmsize`) is exactly what the
  checked add enforces for the value this code produces.
- **Catching the panic at the boundary (`catch_unwind` in signer/CLI)**:
  rejected — symptom suppression; the repo's convention is typed errors at
  the arithmetic site.

## Policy on non-overflowing values

Passthrough stays: when `vmsize + size_increase` does not overflow, the
extended, page-aligned value is still written verbatim (today's behavior,
mirroring zsign's add-the-input-value semantics). Only overflow and
wasm32 truncation become typed rejections. This keeps the change strictly
to the overflow guard and leaves the value policy to the coupled
realloc-delta ticket.

## Invariants

1. Neither realloc variant ever panics on any `u64` vmsize — every
   overflow path returns `Error::MachO` with a stable `__LINKEDIT
   vmsize` substring.
2. Segment32 images and 64-bit images with benign vmsize behave
   byte-identically to today (the guard is a no-op when the add fits).
3. Large-but-non-overflowing vmsize still signs successfully (no
   over-eager rejection, no clamping).
4. `size_increase` derivation, `align_to`'s signature, `write_linkedit_sizes`,
   and every other writer gap are untouched.
5. The metadata variant's returned `updated_metadata.linkedit_cmd` can
   never carry an overflowed vmsize (the error fires first).

## Test strategy

Tests follow the existing `test_prepare_rejects_hostile_linkedit_fileoff`
pattern (`writer.rs`, `catch_unwind` + `expect_err` + `contains`), and
fail before the fix (overflow panic caught, or bogus value accepted):

1. `test_realloc_rejects_hostile_linkedit_vmsize` —
   `make_minimal_macho` with `__LINKEDIT.vmsize` bytes 216..224 set to
   `u64::MAX` (LC at 184, vmsize field at +32), passed to
   `realloc_code_sign_space` — must return the typed error, must not
   panic.
2. `test_realloc_metadata_rejects_hostile_linkedit_vmsize` — same bytes
   through `MachOFile::parse` metadata into
   `realloc_code_sign_space_with_metadata`.
3. `test_sign_rejects_hostile_linkedit_vmsize` — end-to-end
   `sign_macho_adhoc` on the patched fixture (the signer calls the
   metadata variant at `signer.rs:475`/`:610`), proving the CLI/wasm
   surface gets an `Err`, not an abort.
4. `test_realloc_keeps_large_nonoverflowing_linkedit_vmsize` — vmsize
   `1 << 63` still reallocates successfully and the written vmsize stays
   `>= 1 << 63` (pins the passthrough policy; passes before and after).

## Test verification commands

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test --workspace
```

Scoped during flight:
`TMPDIR=$PWD/target/tmp cargo test -p zsign-core writer`.
