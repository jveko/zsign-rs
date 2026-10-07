# Ad-hoc FAT signing for `sign_macho_adhoc` — Design

**Date:** 2026-10-07
**Scope:** `crates/zsign-core/src/macho/` (the macho slice). Nothing else.

## Problem

`sign_macho_adhoc` was the only one of the three macho signing entry points
that refused FAT/Universal containers: it hard-errored on `macho.is_fat()`
with a message telling callers to use `sign_any_macho` — an API that requires
`&SigningCredentials`. A caller with a mixed workload (thin and universal
binaries, some signed ad-hoc) therefore had no ad-hoc FAT path and had to
special-case the container kind. The two siblings, `sign_any_macho` and
`sign_macho_sha256_only`, both route FAT correctly.

The brief's cited evidence (`signer.rs:293-298` hard-error) no longer matches
the source: research against the current worktree shows the gap is already
closed on this branch. This document records the design that closure follows,
the alternatives that were rejected, and the exact state of the tree the plan
verifies.

## Current tree status (verified 2026-10-07)

- `sign_macho_adhoc` (`crates/zsign-core/src/macho/signer.rs:287-322`) has a
  FAT branch: `reject_encrypted` → `sign_all_slices_impl(..., credentials =
  None, sha256_only = false)` → `super::writer::embed_signature_fat`. Landed on
  this branch in commit `b546fb6` ("fix(macho): sign fat binaries ad-hoc in
  sign_macho_adhoc"), together with:
  - the doc comment at `signer.rs:281-286` ("Every slice of a FAT/Universal
    binary is signed ad-hoc and the container is reassembled");
  - `sign_all_slices_impl` taking `credentials: Option<&SigningCredentials>`
    (`signer.rs:414`), so ad-hoc vs credentialed signing is one parameter —
    `None` yields `CS_ADHOC` code directories and an empty CMS wrapper
    (`signer.rs:403-405`, `signer.rs:581`, `signer.rs:853`);
  - the contract test `test_sign_macho_adhoc_signs_fat_container`
    (`signer.rs:1264-1315`): a 2-arch (32-bit + 64-bit) container signs, keeps
    both arches, and every slice reports `CS_ADHOC`, `PageCheck::Matched`, and
    `is_valid()`;
  - `test_sign_macho_rejects_fat_containers` (`signer.rs:1247-1262`), which
    keeps `sign_macho` (credential-gated, thin-only) refusing containers;
  - facade caller migration and facade test flip
    (`crates/zsign/src/builder.rs:1073`, `crates/zsign/src/macho/mod.rs:107-111`).
- Remaining stale claim found during research:
  `crates/zsign/src/builder.rs:393-396` still says "Adhoc mode rejects
  containers and fails closed" — false since `b546fb6`. That file is in the
  deferred facade crate (a parallel lane owns its docs), so this lane reports
  it and does not edit it.

## Chosen design

Keep the three-entry-point shape and make ad-hoc FAT routing a parameter
choice on the existing shared engine, exactly mirroring
`sign_macho_sha256_only`:

```rust
pub fn sign_macho_adhoc(macho, identifier, entitlements, info_plist,
                        code_resources, allow_encrypted) -> Result<Vec<u8>> {
    if macho.is_fat() {
        reject_encrypted(macho, identifier, allow_encrypted)?;
        let signed = sign_all_slices_impl(
            macho, identifier, entitlements, /* credentials */ None,
            info_plist, code_resources, allow_encrypted, /* sha256_only */ false,
        )?;
        return super::writer::embed_signature_fat(macho.data(), &signed);
    }
    // thin path unchanged: SigningContext::new(..., None, ...) + sign_slice_complete
}
```

Why this shape:

- **No new code path.** `sign_all_slices_impl` already parameterizes the only
  two axes that differ between the siblings: `credentials: Option<...>` (ad-hoc
  vs identity) and `sha256_only`. Passing `None`/`false` reproduces
  `sign_any_macho`'s slice pipeline with the ad-hoc signature shape.
- **Symmetry.** All three FAT-capable entries now have the identical body
  shape — `reject_encrypted` → `sign_all_slices_impl` →
  `embed_signature_fat` — so a reader can diff the three and see only the
  parameter changes.
- **Frozen public API.** Every `pub` signature keeps its exact shape; no
  caller (facade, wasm, CLI) changes.

## Alternatives considered (rejected)

1. **Widen `sign_any_macho` to `credentials: Option<&SigningCredentials>`.**
   Would give one FAT-capable entry for both modes, but it changes the
   contract of a public, documented, credential-required API (its callers in
   the facade, wasm, and IPA paths all pass `&SigningCredentials`), forces
   every existing caller to reason about `None`, and moves ad-hoc semantics
   into a function whose name says nothing about them. Larger blast radius,
   no capability gain over the chosen design.
2. **Keep the hard error, change only the message.** Points callers at an
   API that requires credentials — the exact gap the brief describes. Does
   not close it.
3. **Duplicate the per-slice FAT loop inside `sign_macho_adhoc`.** A second
   copy of the slice/sign/reassemble sequence beside
   `sign_all_slices_impl` — a second convention in the same file, free to
   drift (reserve/retry logic already lives in the shared engine). Rejected
   outright by the repo's "reuse the pattern already in the codebase" rule.

## Invariants the design preserves

Verified against source, not assumed:

- **Dispatch by container kind, never slice count.** `macho.is_fat()`
  (`parser.rs:403`) decides; a one-arch FAT container still takes the FAT
  branch (existing coverage: `test_sign_any_macho_preserves_one_arch_fat_container`).
- **Encryption guard runs before signing, on both branches.** The FAT branch
  calls `reject_encrypted` before the engine (the engine re-checks at
  `signer.rs:425`), and `allow_encrypted` is forwarded, so the override
  behaves identically to the siblings.
- **Ad-hoc signature shape.** `credentials = None` ⇒ `ctx.adhoc = true`
  (`signer.rs:75`) ⇒ `CS_ADHOC` code-directory flags (`signer.rs:853`) and an
  empty CMS blob wrapper (`signer.rs:581`). The superblob still grows the
  slice, so reallocation/retry behaves exactly as in credentialed signing.
- **Reassembly recomputes the arch table.** `embed_signature_fat` rebuilds
  `fat_arch` offset/size entries big-endian with each offset rounded up to
  `1 << arch.align` (`writer.rs:478-534`); slice growth shifts later slices.
  No intra-slice load-command offsets need adjusting — reassembly is a byte
  copy.
- **Signature placement is `align_to(code_length, 16)`** (`writer.rs:1561`);
  4096 is the hash page size and reserve granularity, not a signature
  alignment requirement.
- **Big-endian 32-bit slices stay rejected**, per slice, inside the parallel
  signing loop (`ensure_signable_bitness`, `writer.rs:52-58`).

## Test strategy

Behavior, not wiring — each test pins a contract a caller can observe:

1. `test_sign_macho_adhoc_signs_fat_container` (exists, `signer.rs:1264`):
   ad-hoc signing of a 2-arch container succeeds, preserves arches, and every
   slice carries `CS_ADHOC`, matched page hashes, and a valid report.
2. `test_sign_macho_rejects_fat_containers` (exists, `signer.rs:1248`): the
   credential-gated thin entry still refuses containers with an error naming
   the FAT-capable entry.
3. **New:** ad-hoc entry + FAT container holding an encrypted slice refuses
   with `Error::EncryptedBinary` naming the slice, and `allow_encrypted=true`
   lets the same input sign — the guard is owned by this entry's new branch,
   and its sibling coverage (`signer.rs:1584`) exercises only
   `sign_any_macho`.
4. Facade parity, verification only: `test_sign_macho_adhoc_signs_fat`
   (`crates/zsign/src/builder.rs:1073`) — the deferred facade crate is not
   edited by this lane.

Scoped verification commands are listed in the plan; no project-wide gate
runs mid-flight.

## Upstream and format references

Verified against upstream sources on 2026-10-07 (research agent, read-only):

- **Upstream tool is `zhlynn/zsign`** (the `zhangao0086/zsign` URL does not
  resolve — 404). FAT logic lives in `src/macho.cpp`, thin-slice logic in
  `src/archo.cpp`, blob building in `src/signing.cpp`.
- **Upstream splits containers and signs each slice independently**:
  `ZMachO::OpenFile` reads `nfat_arch`, iterates `fat_arch`, and points a
  `ZArchO` at each `offset`/`size`
  (<https://github.com/zhlynn/zsign/blob/master/src/macho.cpp#L60-L92>).
  `ZMachO::Sign` signs per slice with a whole-container realloc retry on
  insufficient space (<https://github.com/zhlynn/zsign/blob/master/src/macho.cpp#L124-L162>).
- **Upstream rewrites `fat_arch` on growth**: `ReallocCodeSignSpace`
  recomputes every `arch.offset`/`arch.size` and hard-codes `align = 14`
  (16 KiB) with zero padding
  (<https://github.com/zhlynn/zsign/blob/master/src/macho.cpp#L164-L256>).
  When no slice grows, the table is left untouched (in-place overwrite).
  This repo's `embed_signature_fat` is stricter: it always rebuilds the
  table and honors each entry's declared `arch.align` (`writer.rs:478-534`),
  matching lipo-produced containers instead of forcing 2^14.
- **Upstream has an ad-hoc mode routed through the same FAT path**:
  `-a/--adhoc` sets `bAdhoc`
  (<https://github.com/zhlynn/zsign/blob/master/src/zsign.cpp#L28-L29>,
  <https://github.com/zhlynn/zsign/blob/master/src/zsign.cpp#L219-L221>),
  and `signing.cpp` writes `CS_SEC_CODESIGNATURE_ADHOC` into the code
  directory flags. Upstream therefore never had this lane's asymmetry —
  ad-hoc and FAT are orthogonal to its single per-slice pipeline.
- **Old signatures are consumed, not stripped, upstream**: the old blob is
  overwritten at `LC_CODE_SIGNATURE.dataoff` (`src/archo.cpp`), the same
  contract this crate implements by truncating each slice to `code_length`
  before writing the new blob (`writer.rs:1573`).
- **Apple format authority**: `fat_header`/`fat_arch` and `FAT_MAGIC` are
  defined in `include/mach-o/fat.h` of
  `apple-oss-distributions/cctools` (lines 80-88 of the current file; xnu's
  `loader.h` does not define them). `LC_CODE_SIGNATURE` and
  `linkedit_data_command { dataoff, datasize }` are in
  `include/mach-o/loader.h` (`apple-oss-distributions/cctools`, line 323 and
  lines 1243-1254). FAT headers/arch tables are big-endian by format rule —
  this crate writes them big-endian in fixtures and in reassembly
  (`fixtures.rs:600-632`, `writer.rs:520-534`).

Nothing in the upstream or format references contradicts the chosen design;
the design is the same per-slice split → sign → reassemble flow, with
per-entry alignment preserved rather than normalized.

## Design decisions

| Decision | Choice | Why |
| --- | --- | --- |
| Where FAT routing lives | Existing `sign_all_slices_impl` + `embed_signature_fat` | One shared engine; three entries differ only in parameters |
| Ad-hoc vs identity switch | `credentials: Option<&SigningCredentials>` | Already the engine's parameter; `None` is the natural ad-hoc value |
| Public API shape | Unchanged (`pub` signatures frozen) | No caller migration, no contract break |
| `sign_macho` stays thin-only | Kept, with its existing error | It is credential-gated by design; changing it is out of the queue item |
| Facade stale doc (`builder.rs:393-396`) | Reported, not edited | `crates/zsign/**` is deferred to a parallel lane |
