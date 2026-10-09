# Reject Duplicate LC_CODE_SIGNATURE at Parse Time — Design

**Date:** 2026-10-09
**Status:** Approved for planning
**Scope:** `crates/zsign-core/src/macho/parser.rs` (the load-command loop and its tests)

## Problem

`MachOFile::parse_single` (parser.rs:237) walks every load command in a
single loop (parser.rs:272-330). The `CommandVariant::CodeSignature` arm
(parser.rs:279-283) assigns on every occurrence, with no counter:

```rust
CommandVariant::CodeSignature(cs) => {
    code_sig_offset = Some(cs.dataoff);
    code_sig_size = Some(cs.datasize);
    meta_code_sig_cmd = Some((lc.offset, cs.dataoff, cs.datasize));
}
```

A Mach-O carrying two LC_CODE_SIGNATURE commands therefore collapses to
the LAST one (last-wins), and the ambiguity is destroyed before any
consumer can see it:

- `ArchSlice.code_sig_offset` / `code_sig_size` (parser.rs:126, :128) and
  `MachOMetadata.code_sig_cmd` (parser.rs:55) receive only the survivor;
  the slice is built at parser.rs:375-396.
- The post-loop bounds validation (parser.rs:333-343) and the
  `code_length` derivation (parser.rs:366) describe only the survivor —
  a malformed or conflicting first command is never checked.
- `verify_slice` reads only the survivor (verify.rs:137-144), so
  verification can never report the duplicate; it verifies "as if one".
- The write path works from the same captured survivor
  (`metadata.code_sig_cmd`, writer.rs:1477) plus its own append helpers
  (`add_code_signature_command` writer.rs:723,
  `add_code_signature_command_with_metadata` writer.rs:1568), so it
  neither sees nor repairs the duplicate either.

Both parse arms funnel through `parse_single`: `Mach::Binary` at
parser.rs:192 and `Mach::Fat` per-slice at parser.rs:218. Every public
entry point inherits the loop: sign entries take an already-parsed
`&MachOFile` (workflow step 1 is "Parse binary with MachOFile",
signer.rs:18-19; `sign_macho` signer.rs:242, `sign_macho_adhoc`
signer.rs:288, `sign_macho_all_slices` signer.rs:380), `verify_macho`
parses the caller's bytes and propagates the error with `?`
(verify.rs:99), and the CLI, wasm, and ipa/dylib probes all reach the
same parse. A rejection placed in the loop covers every path at once.

No test or fixture in the workspace currently builds a Mach-O with two
LC_CODE_SIGNATURE commands, so nothing pins the last-wins behaviour.

## External contract (researched)

Sources pinned at specific commits; every quote below was read directly
unless marked as inference.

- **dyld (load-time authority): rejects.**
  `MachOLoaded::getLinkEditLoadCommands` (apple-oss dyld @ `fd8d0c4`,
  common/MachOLoaded.cpp:134-140) errors on the second occurrence:
  `else if ( result.codeSig != nullptr ) diag.error("multiple
  LC_CODE_SIGNATURE load commands");` — the result is only trusted when
  `diag.noError()` (MachOLoaded.cpp:189). The same duplicate-check idiom
  covers every singular linkedit command in that switch
  (MachOLoaded.cpp:75-179: LC_SYMTAB, LC_DYSYMTAB, LC_UUID, LC_SEGMENT_
  SPLIT_INFO, LC_FUNCTION_STARTS, LC_DATA_IN_CODE, LC_VERSION_MIN_*,
  LC_ENCRYPTION_INFO_64 …), i.e. Apple treats singularity as a class, not
  an LC_CODE_SIGNATURE special case. Caveat: dyld4's
  `MachOAnalyzer::getLayoutInfo` (MachOAnalyzer.cpp:5436-5443) is a
  permissive last-wins layout path — dyld is internally inconsistent and
  the validating arm is the one that gates loading.
- **cctools (backs ld/otool/codesign's object reader): hard error.**
  libstuff/checkout.c:146-150: `fatal_arch(arch, member, "malformed file
  (more than one LC_CODE_SIGNATURE load command): ")`;
  libstuff/ofile.c:4721-4729: `Mach_O_error(… "malformed object (more
  than one LC_CODE_SIGNATURE command)")`. codesign_allocate strips all
  LC_CODE_SIGNATURE commands before (re)signing (misc/codesign_allocate.c:
  1017-1021), but the shared libstuff reader errors on the malformed
  input first — net observable codesign behaviour on a duplicate-bearing
  file is a hard malformed-file failure. [INFERENCE: codesign(1) itself
  is closed-source; this is derived from the open tools it shares.]
- **xnu kernel: permissive (last-wins).**
  bsd/kern/mach_loader.c:1561-1578 calls `load_code_signature` per
  occurrence with no seen-flag — contrast LC_LOAD_DYLINKER directly above
  it (:1546-1553), which the kernel does hard-reject as a duplicate. A
  differing second signature fails only incidentally, via the blob cache
  ("embedded signature doesn't match attached signature"); an identical
  duplicate loads fine.
- **upstream zsign: last-wins — the behaviour we inherited.** The
  historically cited `zhengmin1989/zsign` repository no longer exists on
  GitHub; the canonical upstream is `zhlynn/zsign` @ `614caa8`.
  `ZArchO::Init` (src/archo.cpp:99-106) unconditionally overwrites
  `m_pCodeSignSegment`, `m_uCodeLength`, `m_pSignBase`, `m_uSignLength`
  on each occurrence — a second command silently relocates the signing
  base with no diagnostic.
- **goblin: lossless, with a first-wins precedent.** Every load command
  is kept verbatim in file order (`mach/mod.rs:60`,
  `pub load_commands: Vec<load_command::LoadCommand>`); its one singular-
  command resolution rule is LC_MAIN, first-wins, with a comment citing
  dyld ("dyld cares only about the first LC_MAIN"). goblin never rejects
  and never loses the duplicate.

Conclusion: for a signing tool the strict arm is dyld's validating path
plus cctools' hard error. Being stricter than the kernel is safe — no
legitimately signed binary contains two LC_CODE_SIGNATURE commands, so
the rejection cannot break valid input. The wording of Apple's own
errors is the natural payload (see Decision record).

## Candidate designs

### A. In-loop duplicate rejection in `parse_single` (chosen)

Guard the CodeSignature arm: on a second occurrence return
`Err(Error::MachO("multiple LC_CODE_SIGNATURE load commands".into()))`.

- One choke point; every entry point (sign, verify, CLI, wasm, ipa/dylib
  probes) inherits it, thin and FAT alike.
- The ambiguity never reaches a consumer: parse stops lying, matching the
  required behaviour (surface as an error rather than silently collapse —
  the error arm of the dyld/cctools contract).
- Reuses `Error::MachO(String)` (error.rs:7-8): no new variant, no error-
  taxonomy churn. wasm keeps its stable `ZSIGN_INVALID_MACHO` code; the
  wasm docs state `error.message` may change and only the code is a
  contract (zsign-wasm/src/lib.rs:16-22). The CLI prints the message
  verbatim (cli/main.rs:743; JSON ErrorDoc cli/main.rs:733-741) and no
  test pins it.
- Smallest possible diff in a file several lanes rebase on.

### B. Lossless parse + verify-time report (rejected)

Keep parsing permissive (first-wins), record the duplicate on the parsed
output (e.g. a `code_sig_count` field on `ArchSlice`/`MachOMetadata`),
and let verify — and sign — reject or report it.

- Rejected: signing does not run `verify_macho`, so either the sign path
  grows the same check (two checks kept in sync forever) or a duplicate
  still signs silently. Both violate the required behaviour: a duplicate
  fixture must not silently verify **or sign** as if one.
- Adds a public field to `ArchSlice`/`MachOMetadata` (API churn for later
  lanes) and requires edits inside `verify.rs`/signer territory that
  concurrent lanes own.
- Parse would still resolve the ambiguity, so every future consumer must
  remember the new field — the failure mode this fix exists to remove.
- Mirrors xnu's permissive arm; for a signing tool that is the weaker
  contract.

### C. Post-loop duplicate pass (rejected)

After the loop, iterate `macho.load_commands` counting LC_CODE_SIGNATURE
occurrences, erroring if > 1 — alongside the existing post-loop
validations.

- Rejected: functionally identical to A but strictly worse — a second
  full walk of a list the loop already visits (no avoided computation),
  and the check sits away from the assignment it protects. The existing
  post-loop passes exist because they need loop-derived aggregates; this
  check needs nothing the loop did not already see.

## Decision record

- **Where:** the `CommandVariant::CodeSignature` arm inside
  `parse_single` (parser.rs:279-283) — the single funnel for the thin
  arm (parser.rs:192) and FAT slices (parser.rs:218) alike.
- **Predicate:** `code_sig_offset.is_some()` at arm entry. The three
  destinations (parser.rs:280-282) are written together only by this arm
  and start as `None` (parser.rs:247), so any one of them is an exact
  "seen a previous LC_CODE_SIGNATURE" sentinel; the guard returns before
  overwriting anything.
- **Error payload:** `multiple LC_CODE_SIGNATURE load commands` — dyld's
  exact phrase (MachOLoaded.cpp:139), rendering as
  `Invalid Mach-O: multiple LC_CODE_SIGNATURE load commands`.
  Rejected alternatives: cctools' attested strings start with "malformed
  file/object", which would render redundantly after the
  `Invalid Mach-O:` prefix; free-hand wording loses the attested phrasing
  and pins nothing.
- **Scope: LC_CODE_SIGNATURE only.** The same silent-collapse shape
  exists elsewhere in the loop — `text_segment_*` (parser.rs:286-288,
  :303-305), `meta_linkedit_cmd` (parser.rs:293-296, :307-312), and the
  shared `record_encryption` helper (parser.rs:496-508) — and dyld's
  uniform class-check implies they deserve the same treatment eventually.
  They are deliberately untouched: this change answers the cited
  behaviour, sibling lanes also touch this file, and widening the diff
  now buys nothing. (One in, one out: recorded here so a follow-up lane
  can pick it up.)
- **Writer's internal goblin re-parses untouched.** writer.rs re-derives
  `code_sig_cmd` with the same last-wins shape when it re-parses raw
  bytes internally (writer.rs:160-162, :597-599, :1250-1252). After this
  change no public entry point can hand duplicate-bearing bytes to the
  writer — all of them parse first — so those loops are unreachable for
  the duplicate case. [INFERENCE: no current caller bypasses `parse`.]
  Fixing them anyway would enlarge the diff beyond the cited concern.
- **Signer untouched.** Every `sign_macho*` entry takes `&MachOFile`
  produced by `parse`; the parse error IS the sign-path rejection.

## Out of scope

FAT slice alignment/offset validation, FAT_CIGAM, accessor bounds,
code-length unification, duplicate treatment for any other load command,
and `writer.rs`/`signer.rs` internals (some owned by concurrent lanes).

## Testing

All in `parser.rs`'s existing `#[cfg(test)] mod tests` (parser.rs:509).
The fixture is a test-local helper that builds a thin Mach-O carrying
TWO LC_CODE_SIGNATURE commands by applying the same byte surgery as
`make_signed_minimal_macho_at` (fixtures.rs:422-441): a second 16-byte
`LC_CODE_SIGNATURE` (cmd `0x1d`) appended after the first, with `ncmds`
and `sizeofcmds` bumped in the `mach_header_64`. The second command
CONFLICTS with the first (different `dataoff`/`datasize`) so a surviving
winner would be observable.

1. `MachOFile::parse` of the duplicate fixture → `Err(Error::MachO(_))`
   whose payload contains `multiple LC_CODE_SIGNATURE`.
2. `verify_macho` of the duplicate fixture → the same `Err` (never an
   `Ok(report)`), pinning that verification cannot pass it off as one.
3. `MachOFile::parse` of a FAT container wrapping the duplicate slice →
   the same `Err`, pinning the FAT arm's funnel through `parse_single`.
4. No first-occurrence regression: existing single-signature tests (e.g.
   writer.rs:2324's `make_signed_minimal_macho(0x800)` round-trip) stay
   green — the guard fires only on the second occurrence.

Sign-path coverage is the parse test itself: `sign_macho*` cannot be
handed raw bytes (they take `&MachOFile`), and the mandatory first
workflow step is parse (signer.rs:18-19), so a parse `Err` is the
sign-path rejection.
