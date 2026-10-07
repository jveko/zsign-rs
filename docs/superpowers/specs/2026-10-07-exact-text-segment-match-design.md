# Design: exact `__TEXT` segment selection in the Mach-O parser

## Problem

`parse_single` in `crates/zsign-core/src/macho/parser.rs` selects the
executable segment with a prefix test in both width arms:

- 64-bit arm: `crates/zsign-core/src/macho/parser.rs:277`
  `if seg.segname.starts_with(b"__TEXT")` captures `seg.filesize`,
  `seg.vmaddr`, `seg.fileoff` into the locals that become
  `ArchSlice::text_segment_size` / `text_segment_base` /
  `text_segment_fileoff` (`parser.rs:241-243`, struct fields `:132`,
  `:135`, `:138`).
- 32-bit arm: `crates/zsign-core/src/macho/parser.rs:294`, same prefix
  test, same three captures widened `as u64`.

The load-command loop (`parser.rs:264`) is last-match-wins, so any segment
whose 16-byte name merely begins with `__TEXT` overwrites the captured
values. `__TEXT_EXEC` is a real ld64 output (emitted for `-text_exec` and
forced for arm64 kext bundles) and is ordered after `__TEXT`, so it
normally wins the overwrite.

Downstream, `build_code_directory_from_hashes`
(`crates/zsign-core/src/macho/signer.rs:804`) emits
`.exec_seg_base(slice.text_segment_fileoff)` (`:854`) and
`.exec_seg_limit(slice.text_segment_size)` (`:855`), serialized as
`execSegBase`/`execSegLimit` at `code_directory.rs:394-395`. The one-line
defect: the emitted `execSegBase`/`execSegLimit` come from the wrong
segment.

## Verified external contract

The citations in this section are externally verified against upstream
sources (Apple/ld64/zsign), not files in this worktree — line numbers
refer to those upstream repositories at the reviewed commits:

- Apple resolves the segment by exact comparison: `MachOBase::findSegment`
  returns the first segment where
  `!strncmp(seg->segname, segname, sizeof(seg->segname))` with a
  16-byte field and a 6-byte `"__TEXT"` literal — `__TEXT_EXEC` differs at
  byte 6 and cannot match
  (`lib/macho++.cpp:332-351`, compare at `:343`;
  `machorep.cpp:180-227` derive `execSegBase`/`execSegLimit` from
  `findSegment("__TEXT")`'s `fileoff`/`filesize`).
- ld64 emits `__TEXT_EXEC` as a distinct `LC_SEGMENT_64` sharing the first
  six bytes with `__TEXT` (`ld64` `Options.cpp:5264-5268`,
  `ld.cpp:318-323` order 1 vs 2).
- zsign (C++) also uses exact comparison:
  `if (0 == strcmp("__TEXT", seglc->segname))` (`src/archo.cpp:53`, `:73`).
- A wrong-segment `execSegBase`/`execSegLimit` does not corrupt code or
  special slots (the kernel consumes `execSegFlags`; slots bind
  independently), but it breaks the documented field semantics
  (`execSegBase` = "offset of executable segment", `execSegLimit` =
  "limit of executable segment", xnu `cs_blobs.h:243-247`), disagrees with
  `codesign` output byte-for-byte, and makes the range `[base, base+limit)`
  name the wrong pages for any consumer that trusts it.

## Chosen design

Exact 16-byte equality against the NUL-padded `__TEXT` name, applied in
both width arms of `parse_single`.

- goblin 0.10.7 types `segname` as a plain `[u8; 16]`
  (`goblin-0.10.7/src/mach/load_command.rs:105`, `:129`), so the comparison
  is a direct array equality — no helper, no allocation.
- A module-level constant states the intent once:

  ```rust
  /// `__TEXT` as it appears in a 16-byte segment-name field: 6 name
  /// bytes followed by 10 NULs. Compared for exact equality, matching
  /// Apple's `findSegment("__TEXT")`.
  const TEXT_SEGMENT_NAME: [u8; 16] = *b"__TEXT\0\0\0\0\0\0\0\0\0\0";
  ```

  used as `seg.segname == TEXT_SEGMENT_NAME` at the two former prefix
  sites.

Nothing else changes: `ArchSlice` keeps its three fields, the signer keeps
reading them, the writer is untouched (it has no `__TEXT` selection —
verified by grep), and the `__LINKEDIT` prefix sites stay as they are.

## Alternatives considered

- **Prefix + NUL-terminator** (`starts_with(b"__TEXT") && segname[6] == 0`):
  byte-for-byte equivalent to Apple's `strncmp` semantics (which stops at
  the literal's NUL and never inspects bytes 7-15). Rejected because it
  keeps a prefix idiom at the site of a prefix bug and diverges from the
  stated gap ("exact 16-byte match"). Full equality differs only for the
  malformed name `__TEXT\0<garbage>` (no linker emits it), where we would
  report no `__TEXT` instead of Apple's match — accepted as strictly closing
  the gap with a simpler, deterministic predicate.
- **First-match-wins prefix**: would dodge `__TEXT_EXEC` only because ld64
  orders `__TEXT` first; any `__TEXT*` segment appearing first would still
  win. Does not close the gap.
- **Shared segment-name comparison helper extended to the `__LINKEDIT`
  sites**: introduces a second convention beside the repo-wide
  `starts_with` idiom and edits unrelated code; the `__LINKEDIT` sites are
  out of scope for this change. YAGNI.

## Invariants

1. `ArchSlice::text_segment_size` / `text_segment_base` /
   `text_segment_fileoff` equal the exact `__TEXT` segment's `filesize` /
   `vmaddr` / `fileoff`, regardless of what other `__TEXT*` segments
   exist or where they appear in the load-command order.
2. A Mach-O with no exact `__TEXT` segment captures the zero defaults
   (unchanged behavior).
3. Thin and FAT paths share `parse_single`, so the fix covers both
   (`parser.rs:187`, `parser.rs:213`); no other workspace site selects
   `__TEXT`.
4. Emitted `execSegBase`/`execSegLimit` equal `__TEXT.fileoff` /
   `__TEXT.filesize` even when `__TEXT_EXEC` is present.

## Test strategy

Regression tests fail before the fix (prefix capture picks `__TEXT_EXEC`)
and pass after it:

- New fixtures in `crates/zsign-core/src/macho/fixtures.rs`, derived from
  the existing byte-patch pattern (`make_minimal_macho_text_vmsize_pad`,
  `make_minimal_dylib`): insert an `LC_SEGMENT_64` / `LC_SEGMENT` named
  `__TEXT_EXEC` **after** `__TEXT` (mirroring ld64 order), bumping `ncmds`
  and `sizeofcmds`, with `fileoff`/`filesize`/`vmaddr` chosen to differ
  from `__TEXT`'s so the wrong capture is observable.
- Parser tests (64-bit and 32-bit arms) assert the captured triplet equals
  `__TEXT`'s values, not `__TEXT_EXEC`'s.
- One end-to-end test signs the 64-bit fixture and reads
  `execSegBase`/`execSegLimit` back out of the CodeDirectory bytes,
  following the existing `test_exec_seg_limit_written_from_filesize`
  pattern, pinning the reported defect at the emitted-field level.

## Design decisions

- **Exact 16-byte equality, not prefix-with-terminator**: chosen for
  literal gap closure and a single obvious predicate; costs a theoretical
  mismatch with Apple on names containing bytes after the first NUL, which
  no toolchain emits.
- **One named constant instead of two inline literals**: the 16-byte form
  with 10 invisible NULs is easy to get wrong inline; the constant is
  documented and used by both arms.
- **Both width arms fixed in the same change**: the two arms duplicate the
  bug; fixing one would leave an obviously broken sibling.
- **`__LINKEDIT` prefix sites untouched**: they are a separate concern
  outside this item's gap; converting them would add scope and risk for no
  closure of this gap.
- **No change to value semantics**: `execSegBase` stays `fileoff` and
  `execSegLimit` stays `filesize` (Apple convention). zsign C++ uses
  `vmsize` for the limit and hardcodes base 0 — deliberately not imported.

## Test verification commands

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test --workspace
```

Scoped during flight:
`TMPDIR=$PWD/target/tmp cargo test -p zsign-core macho::parser`.
