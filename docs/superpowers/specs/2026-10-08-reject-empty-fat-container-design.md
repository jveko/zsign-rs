# Reject Empty FAT Container at Parse Time — Design

**Date:** 2026-10-08
**Status:** Approved for planning
**Scope:** `crates/zsign-core/src/macho/parser.rs` (primary)

## Problem

`MachOFile::parse` (parser.rs:185) delegates FAT containers to goblin and
builds the slice list by iterating `fat.iter_arches()` (parser.rs:195-224).
The loop has no lower bound: when the header declares `nfat_arch == 0`
(magic-only container, 8 bytes: `0xcafebabe` + `0u32`), the loop body never
runs and `parse` returns `Ok(MachOFile { is_fat: true, slices: [] })`.

Observed consequences of that `Ok` today:

- Core `verify_macho` (crates/zsign-core/src/macho/verify.rs:99-110) returns
  `Ok(MachOVerifyReport { fat: true, slices: [] })`. `is_valid()` is already
  `false` (verify.rs:78-80), but `error_count()` is 0 and the report is a
  success result.
- Facade `verify_bundle_dir` (crates/zsign/src/verify.rs:409; slice loop
  at :503-504 inside the :494-538 region) iterates `report.slices`; an
  empty list means nothing is checked (vacuous pass).
- WASM `parse_macho` (crates/zsign-wasm/src/lib.rs:520-532) returns
  `MachOInfo { is_fat: true, slices_count: 0 }` with no error — the clearest
  consumer-visible symptom.
- CLI dylib validation (crates/zsign-cli/src/main.rs:229) checks only parse
  success, so a magic-only FAT passes.
- IPA executable probe (crates/zsign/src/ipa/mod.rs:1909-1914) reads
  `slices().first()` → `None`, silently treated as not-executable.

The signing path is already guarded independently: `sign_all_slices_impl`
(crates/zsign-core/src/macho/signer.rs:431-433) re-parses the container and
returns `Err(Error::MachO("Empty FAT binary"))` for zero arches, and the
writer has four `arches.is_empty()` guards (writer.rs:336-338, 405-407,
456-458, 1006-1008). The parser is the one entry point with no guard, and
every non-signing consumer inherits the hole from it.

## External contract (researched)

Every authoritative implementation treats a zero-architecture FAT as
malformed; none accepts it as a valid empty container:

- Apple cctools `ld/pass1.c` `check_fat()` explicitly rejects:
  `fat file: %s malformed (contains zero architecture types)`.
- Apple `otool/ofile_print.c` prints
  `nfat_arch 0 (malformed, contains zero architecture types)`.
- Upstream zsign `src/macho.cpp` `OpenFile` returns
  `(!m_arrArchOes.empty())`, so a magic-only FAT fails to open (generic
  failure, no dedicated diagnostic).
- dyld `mach_o/Universal.cpp` `valid()` only upper-bounds the count
  (`fat file has too many slices`); a zero count yields no slices and later
  best-selection fails.
- lld `MachO/InputFiles.cpp` iterates the declared count; with zero arches
  the fallback warns and fails the file.

Conclusion: rejecting at parse time is the convention, and it lets us reuse
the in-repo wording that the signer/writer guards already emit.

## Candidate designs

### A. Parse-time floor in the FAT arm (chosen)

In parser.rs's `Mach::Fat` branch, after the loop, return
`Err(Error::MachO("Empty FAT binary".into()))` when `slices.is_empty()`.

- Single choke point: parse, verify, wasm, CLI, and the ipa probe all fail
  with one typed error instead of per-caller re-checks.
- Reuses the exact payload the signer guard and writer guards already use;
  `Error::MachO` is the crate's structural-parse rejection variant
  (error.rs:7-9), so no new variant and no error-taxonomy churn.
- Predicate: post-loop `slices.is_empty()` is exactly `nfat_arch == 0`
  (any arch entry that fails its own checks returns `Err` before the loop
  ends), so no goblin-internal count access is needed.
- Minimal diff on a file other lanes will also touch.

### B. Per-consumer guards (rejected)

Add emptiness checks at verify, wasm, CLI, and the ipa probe.

- Rejected: N call sites now and forever; any future caller of `parse` must
  remember the check; does not satisfy "must not parse as success" — the
  parser itself would still lie.

### C. Parse-time floor + ceiling (rejected)

Floor as in A, plus a dyld-style `kMaxSliceCount` upper bound on
`nfat_arch`.

- Rejected: the ceiling is a distinct behaviour (defends against a huge
  declared count), out of this change's scope; per-arch bounds checks
  (offset overflow, `end > bytes.len()`) already reject out-of-range
  entries as they are read. Adding it would widen the diff in a file that
  later lanes rebase on.

## Decision record

- **Where the bound lives:** the `Mach::Fat` arm of `MachOFile::parse` —
  the only entry point every consumer shares.
- **Predicate:** `slices.is_empty()` after the arch loop.
- **Error:** existing `Error::MachO(String)` with payload
  `"Empty FAT binary"` (matches signer.rs:431-433 and the writer guards;
  renders as `Invalid Mach-O: Empty FAT binary`).
- **Ceiling:** not added — out of scope, rejected above.
- **Writer guards:** untouched. They validate arch data re-parsed inside
  each write path; they remain correct as defence in depth, and removing
  them would enlarge the diff without changing behaviour. This is
  deliberate, not an oversight.
- **Signer guard:** untouched (redundant after the parser floor but
  harmless; it guards its own fresh goblin parse).

## Out of scope

Slice alignment/offset validation, duplicate load commands, big-endian
`FAT_CIGAM` support, and slice accessor bounds checks are separate concerns
owned by other work; this change must not alter their behaviour.

## Testing

- New fixture bytes built inline in the test (the shared
  `make_fat_macho` helper asserts non-empty input): 8-byte header
  `0xcafebabe` big-endian + `nfat_arch = 0`.
- `MachOFile::parse` on those bytes → `Err` whose payload is
  `Empty FAT binary`.
- Core `verify_macho` on those bytes → `Err` (no `Ok` empty report).
- Signing entry point on those bytes → `Err` (fails at parse now, earlier
  than the signer's own guard).
- Existing FAT tests (two-slice, one-slice, sign/verify round-trips) must
  stay green — the floor must not reject any container that carries
  slices.
