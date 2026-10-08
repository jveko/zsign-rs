# Validate the FAT container before per-slice signing — Design

Date: 2026-10-08
Lane: w2-macho-writer (branch w2-macho-writer)
Scope: `crates/zsign-core/src/macho/signer.rs` (primary), plus minimal call wiring in `crates/zsign-core/src/macho/writer.rs`.

## Problem

`sign_macho_all_slices` (signer.rs:379-397) delegates to `sign_all_slices_impl`
(signer.rs:410-459), which contains exactly three checks before the work:
`reject_encrypted` (:425, per-slice encryption only), `SigningContext::new`
(:426-433), and per-slice `sign_slice_complete` (:444) inside the rayon
`par_iter` (:437-456). There is zero container-geometry validation — no
bounds, no overflow, no pairwise-disjoint check — and `validate_fat_arches`
appears nowhere in signer.rs.

All four FAT-capable public entry points sign first and validate after:
`sign_any_macho` signs at :184 then calls `embed_signature_fat` at :193
(which validates at writer.rs:408); `sign_macho_adhoc` :297→:307;
`sign_macho_sha256_only` :341→:351; and `sign_macho_all_slices` returns
`Vec<SignedSlice>` and never touches the writer at all — for it, container
validation never runs.

Gap: an overlapping-arch container is FULLY signed (CMS built, superblob
embedded) and only rejected afterwards inside `embed_signature_fat`'s
`validate_fat_arches` (writer.rs:418-443, called at writer.rs:340/:408/:1008).
A caller that trusts `sign_macho_all_slices`'s `Ok` receives signed slices
from a structurally impossible container. The repo's own test
`test_embed_fat_rejects_overlapping_slices` (writer.rs:~2751-2789) records
the gap: its fixture makes `sign_macho_all_slices(...).unwrap()` SUCCEED and
the error surfaces only from `embed_signature_fat` — the trailing
`// pre-fix: Ok` comment documents today's ordering.

**One-liner (scoped — cold review finding 6):** after this fix, no `Ok` from
`sign_macho_all_slices` for a container `embed_signature_fat` rejects on
input-structure grounds: the empty-container rejection and every
`validate_fat_arches` rejection (bounds, overflow, overlap) all fire pre-sign.
Explicitly OUT of scope, with reasons:
- the align-cap/offset-alignment rejections (the Item-1 guards) live in
  `embed_fat_from_signed_slices` and remain post-sign by design — they were
  already there before this item's brief and are this branch's earlier work;
  pre-sign enforcement would require moving those guards out of the
  reassembly path (a writer change beyond this item's "call wiring"), or
  duplicating them in signer (a second convention the repo prohibits);
- count/identity rejections are satisfied by construction pre-sign (signed
  slices are produced one-per-parse from the same container);
- output-side reassembly rejections (u32 offset bound on the recomputed
  layout) depend on signature sizes that do not exist until signing has run,
  so they are undecidable at validation time.

Key narrowing (verified): `MachOFile::parse` already enforces the other two
`validate_fat_arches` reasons — overflow (parser.rs:201-203) and out-of-file
(parser.rs:204-210) — at parse time, so for a parsed `&MachOFile` only the
pairwise-overlap check (writer.rs:433-441) is reachable as a silent `Ok`.
The fix still calls the whole validator rather than only the overlap rule,
and additionally rejects the empty container (the one `validate_fat_arches`
gap: `validate_fat_arches([])` is a vacuous `Ok`, while `embed_signature_fat`
rejects `"Empty FAT binary"` at writer.rs:405-407 before validating), so the
scoped one-liner above holds by construction.

## External contract (research-phase citations; [UNVERIFIED EXTERNAL] — not re-checkable in this worktree)

- Apple cctools validates the fat container at input-processing time, before
  any per-arch work: table bounds, offset+size vs file size, align cap,
  offset alignment, duplicate-arch — all `fatal` in `lipo.c:1217-1287` and
  `ld/pass1.c:888-957`. Validate-before-work is the domain norm.
- Rust API Guidelines C-VALIDATE: validate inputs "ahead of time, if
  necessary"; deferred checks cause "delayed detection of bugs".
- The house style already validates before work in the writer paths
  (writer.rs:340/:408/:1008 all call `validate_fat_arches` first); the signer
  path is the outlier.
- Upstream zsign never validates disjointness at all — no counter-evidence;
  no consumer can depend on today's ordering (every production route
  — builder, IPA, wasm — already errors out downstream via
  `embed_signature_fat`; only tests calling `sign_macho_all_slices`
  directly observe the gap).

## Candidate designs

**A — pre-sign call into the writer's validator (CHOSEN).**
1. Widen `validate_fat_arches` from private `fn` to `pub(crate) fn`
   (writer.rs:418 — `pub(crate)` matches the existing `checked_u32` wiring
   precedent; signer.rs already reaches writer via `super::writer::…`).
2. At the TOP of `sign_all_slices_impl` (before `reject_encrypted`,
   `SigningContext::new`, and the `par_iter`), gate on `macho.is_fat()`:
   parse `macho.data()` with the house goblin `Mach` idiom (mirroring
   `embed_signature_fat`'s import style and error strings), reject an empty
   arch table with the same `"Empty FAT binary"` message `embed_signature_fat`
   uses (writer.rs:405-407), collect `fat.iter_arches()` into `Vec<FatArch>`,
   and `super::writer::validate_fat_arches(&arches, macho.data())?`.
- Same validator, same inputs as the downstream `embed_signature_fat` call ⇒
  the one-liner holds by construction; all four entry points inherit the fix
  through the shared impl; thin (non-fat) inputs skip the gate unchanged.
- Re-parse cost: one goblin header parse per sign call — negligible next to
  CMS signing.
**B — generalize `validate_fat_arches` to take `(offset, size)` pairs.**
Rejected: changes the fn signature and its three existing writer call sites —
more than the "call wiring" this item is granted, and it would need FatArch
synthesis or a parallel path anyway.
**C — signer-local disjointness check over `macho.slices()`.**
Rejected: reimplements the overlap rule in a second module (second
convention); a future rule added to `validate_fat_arches` would silently
diverge and weaken the one-liner.
**D — validate in `MachOFile::parse` (parser.rs).**
Rejected: parser.rs is explicitly another lane's file (FAT-parse tickets);
this item must not edit it.

## Chosen design details (A)

- Placement: first statement of `sign_all_slices_impl` (after `is_executable`
  is irrelevant — validation precedes all of it; concretely: before
  `reject_encrypted` at :426). Rationale: "validate the container BEFORE
  signing" — also before context construction, which is still pre-work but
  later.
- `macho.is_fat()` gate: `validate_fat_arches` is FAT-only (as at all three
  writer call sites, which run inside FAT match arms); a thin `MachOFile`
  cannot overlap and must not be re-parsed as FAT.
- Parse-failure handling: if `Mach::parse(macho.data())` fails or does not
  yield `Mach::Fat`, return `Err(Error::MachO(...))` (the `is_fat()` gate
  makes this unreachable for inputs that parsed before, but the path must
  fail closed, never panic; no `unreachable!` in production paths).
- Error surfaces unchanged: overlap keeps the validator's existing
  `"FAT slices {} and {} overlap"` message, so tests assert the same strings
  as the writer tests.
- Doc touch: `validate_fat_arches`'s doc comment ("every writer entry
  point") gains the signer mention; `sign_macho_all_slices` rustdoc error
  section (C-FAILURE) notes container-structure rejection. No ticket IDs.
- Test migration: `test_embed_fat_rejects_overlapping_slices`
  (writer.rs:~2751-2789) currently pins the gap with
  `sign_macho_all_slices(...).unwrap()` — after the fix that `unwrap` panics.
  Its REAL purpose is proving `embed_signature_fat`'s own rejection; migrate it
  to still assert that (e.g. hand-construct the two `SignedSlice`s matching
  the hostile arch identity fields — `embed_signature_fat` validates the
  container at writer.rs:408 BEFORE it looks at `signed_data`, so dummy data
  suffices), or restructure as the plan specifies. The gap itself gets a new
  dedicated signer-side red test.

## Testing strategy

TDD; new test lives in signer.rs's inline test mod (end of it; locate
`#[cfg(test)]`), fixture idiom copied from writer.rs:~2757-2774 (hand-built
hostile FAT bytes). Errors asserted with the repo's `expect_err` +
`contains` / `matches!` idiom.

1. **Red test** `test_sign_macho_all_slices_rejects_overlapping_container`:
   build the overlapping container (two archs, second offset inside first's
   range), `MachOFile::parse`, call `sign_macho_all_slices`;
   failing-before: `Ok` (today, with the full CMS work done);
   passing-after: `Err` containing `"overlap"`.
2. **Migration** of `test_embed_fat_rejects_overlapping_slices`: keeps
   asserting `embed_signature_fat` rejects overlap (its original purpose),
   no longer depends on `sign_macho_all_slices` returning `Ok`.
3. **Regression sweep**: whole suite green — especially sign_macho_all_slices
   consumers (writer.rs FAT tests using it), `sign_any_macho`/
   `sign_macho_adhoc`/`sign_macho_sha256_only` tests, and Items 1-2 tests.

## Acceptance

- `cargo fmt --all -- --check` clean; `cargo clippy --workspace --all-targets -- -D warnings` clean.
- `TMPDIR=$PWD/target/tmp cargo test --workspace` green.
- Failing-before/passing-after test for the red test; migrated writer test green.
- One-liner (scoped as defined in Gap) demonstrable: every container
  `embed_signature_fat` rejects on input-structure grounds (empty, bounds,
  overflow, overlap) is rejected by `sign_macho_all_slices` before any slice
  is signed.
