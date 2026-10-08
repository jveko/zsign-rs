# CodeDirectory CMS binding and report sourcing — design

Date: 2026-10-08
Status: drafted for cold review
Files in scope:
- `crates/zsign-core/src/macho/verify.rs` (selection rule + cross-CD agreement)
- `crates/zsign-core/src/codesign/verify.rs` — `parse_superblob` only
  (duplicate-hash-type rejection is the binding-every-CD structural check the
  lane brief explicitly allows on the codesign side)

Never edited: `crates/zsign-core/src/crypto/**`,
`crates/zsign-core/src/macho/{writer,signer,parser}.rs`, facade, CLI
(deferred to other lanes).

## Goal

`report.pages` and `report.special_slots` can be sourced from a CodeDirectory
the CMS signature does not bind, because `strongest = cds.max_by_key(|cd|
cd.hash_size)` is last-on-tie while `cdhash_pair` binds only the first CD of
each hash type. Four fix directions from the lane brief, resolved into three
mechanisms:

- (a) select `strongest` from the CMS-bound set, first-on-tie;
- (b)+(c) make "every emitted CD" and "at most one CD per hash type" one
  structural parse-time check (see Ruling below);
- (d) add a cross-CD header agreement check anchored at the primary.

## Defect — verified at 1b074a3 (source unchanged since)

- `crates/zsign-core/src/macho/verify.rs:174` builds
  `cds = emitted_cds(&superblob)` (primary first, then alternates in slot
  order, up to slots 0x1000..=0x1005); `:175-179`
  `max_by_key(|cd| cd.hash_size).unwrap_or(primary)` — Rust's
  `max_by_key` returns the LAST maximum on ties.
- `CodeDirectory::parse` rejects `hashType ∉ {1,2}` and `hashSize ∉ {20,32}`
  (`codesign/verify.rs:672-681`), so every SHA-256 CD ties at 32: with two
  SHA-256 directories, `strongest` is deterministically the LAST-emitted one.
- `cdhash_pair` (`macho/verify.rs:471-484`) uses `find` = FIRST of each type;
  `verify_code_signature(cms_blob, primary.raw(), cd_sha1, cd_sha256)` at
  `:381-393` therefore binds exactly: the slot-0 CD (messageDigest over
  `primary.raw()`), the first SHA-1 CD (v1 attribute), and the first SHA-256
  CD (v1 truncated + v2 attribute). The crypto check
  (`crypto/cms_verify.rs:974-987`, `cdhash_v1_matches` accepts exactly
  `[trunc]` or `[sha1, trunc]`) exposes only booleans — no raw attribute
  access — and `crypto/**` is deferred, so extra CDs can never be fed to it
  from this lane.
- Consumers of the sourced fields: `report.pages` is assigned at
  `macho/verify.rs:239`, `report.special_slots` at `:240` (captured from
  `strongest` inside the per-CD loop at `:200-205`); the facade reads
  `special_slots` positionally (`crates/zsign/src/verify.rs` `.first()` =
  Info.plist, `.get(2)` = CodeResources — deferred file, compile-safe under
  this design), the CLI table and `--json` DTO synthesize slot numbers from
  vector index (same). Net effect today: a second SHA-256 directory at
  0x1001 can decide two report fields while bound by nothing.

## External contract (verified: apple-oss-distributions/Security + xnu @ main)

- **CMS content** = slot-0 CD bytes only: `SecStaticCode::verifySignature`
  sets `CMSDecoderSetDetachedContent(cms, mBaseDir)` where `baseDir` is
  loaded only for `cdCodeDirectorySlot` (StaticCode.cpp:870-874, :586-587).
  Alternate CDs are NOT covered by the message digest.
- **Apple binds every other CD via the hash-agility bags**: v1
  `cdhashes` array compared against ALL CDs' cdhashes
  (`cdHashes()`, StaticCode.cpp:624-637); v2 requires the dictionary count to
  EQUAL the CD count ("no stripping out code directories") plus per-entry
  cdhash equality (StaticCode.cpp:925-965). Signing writes both bags from the
  full CD set (`CodeDirectorySet::hashList()/hashDict()`).
- **At most one CD per hash type**: `loadCodeDirectories`
  (StaticCode.cpp:568-601) inserts each CD into a map keyed by `hashType`
  and throws `errSecCSInvalidSignature` on the second ("duplicate hashType,
  go to heck"). Legal alternate slot range is 0x1000..=0x1004 (`LIMIT =
  0x1000 + 5` is one-past-the-last); this repo admits through 0x1005 — that
  range gap is explicitly NOT this item's scope, but any third directory
  admitted through it must duplicate a hash type and is rejected by the
  check below.
- **No `nSpecialSlots` value invariant exists**: Apple's only checks are
  bounds (`CodeDirectory::checkIntegrity`, `slotIsPresent` clamps);
  production values run 0..11+ (cdbuilder spans `cdInfoSlot..cdLibraryConstraint`).
- **No Apple cross-CD header comparison**: selection is per-algorithm
  priority (`bestHashOf`: SHA384 > SHA256 > SHA256-truncated > SHA1); nothing
  in Apple code compares identifier/version/flags across CDs. A (d)-style
  agreement check is deliberate local strictness (defense-in-depth), not
  Apple parity.

## Ruling on direction (c)

The brief's direction (c) reads "require `nSpecialSlots <= 1` per hash type".
Research found no such invariant anywhere in Apple's code (bounds checks
only; production values 0..11+), and this repo's own signer emits
nSpecialSlots 3/5/7 (`code_directory.rs` `count_special_slots`), so a
literal `<= 1` rejection would fail verification of zsign-signed AND
Apple-signed entitlement-bearing binaries and would empty the
`special_slots` vector the deferred facade reads positionally —
contradicting the same brief's mandatory green workspace gate.

The escalation was raised (blocked task, options + recommendation). The
brief also states: "Quoted fix directions are suggestions — you may choose
a different design if it closes the gap; record why." Under that clause the
decision, pending any supervisor redirect before landing, is:

**Ruling:** implement (c) as Apple's verified per-hash-type invariant —
**at most one CodeDirectory per hash type** (StaticCode.cpp:598-600,
duplicate `hashType` ⇒ `errSecCSInvalidSignature`). The brief's own phrasing
("… <= 1 per hash type") maps to this count; the librarian independently
flagged it as "exactly the shape of fix direction (b)/(c)".
- Cost if wrong: revertible pre-landing (nothing is pushed or merged); the
  supervisor can redirect at `sbx-lane land`.
- Rejected alternative: literal `nSpecialSlots <= 1` (breaks our own signer's
  output and the positional consumer); dropping (c) (silently drops a
  mandated direction). Neither closes the gap the direction points at —
  unbound extra directories — while the chosen reading does, exactly.

## Design decisions

### D1 — (a): static bound set + first-on-tie selection (chosen)

```rust
let first_sha1 = cds.iter().copied().find(|cd| cd.is_sha1());
let first_sha256 = cds.iter().copied().find(|cd| cd.is_sha256());
let cms_is_real = superblob.cms.map_or(false, |blob| {
    !(blob.len() == 8 && blob[0..4] == CSMAGIC_BLOBWRAPPER.to_be_bytes())
});
let mut bound: Vec<&CodeDirectory<'_>> = vec![primary];
if let Some(cd) = first_sha1.filter(|cd| !std::ptr::eq(*cd, primary)) {
    bound.push(cd);
}
if let Some(cd) = first_sha256.filter(|cd| !std::ptr::eq(*cd, primary)) {
    bound.push(cd);
}
let strongest = if cms_is_real {
    bound.iter().copied().fold(None, |acc, cd| match acc {
        Some(best) if best.hash_size >= cd.hash_size => Some(best),
        _ => Some(cd),
    })
    .unwrap_or(primary)
} else {
    primary
};
```

- The rule is **static**: the bound set depends only on the CMS blob's shape
  (which crypto will check), not on the check's outcome — so `strongest`
  stays computable at `verify.rs:174`, before the CMS branch at `:363`.
  `cms_is_real` replaces the later recomputation of `empty_wrapper` (one
  definition, reused).
- Real CMS ⇒ bound = {primary (messageDigest), first SHA-1, first SHA-256} —
  exactly the set `verify_code_signature` verifies, aligned with
  `cdhash_pair` (both use `find`, first-of-type).
- Ad-hoc / absent / empty-wrapper CMS ⇒ bound = {primary}: nothing else is
  bound, and the report's other metadata fields (`signed`, `adhoc`,
  `identifier`) already come from the primary. Per-CD page/slot errors still
  cover every directory, so tampering with an alternate still fails
  verification — only the *field source* changes (recorded test rework below).
- First-on-tie: the fold keeps the first strictly-greater element. After
  direction (b)+(c) a size tie cannot occur (≤1 CD per type ⇒ sizes {20,32}),
  but the brief mandates the tie rule and it future-proofs a wider type set.
- Rejected A2 (bound = all CDs even without CMS): leaves the ad-hoc source
  gap and does not match the brief's expected test rework. Rejected A3
  (rank by Apple hash-priority): parse already restricts types to {1,2}, so
  size order ≡ priority order — YAGNI, recorded as a note.

### D2 — (b)+(c): one structural check in `parse_superblob` (chosen)

In `codesign/verify.rs`'s child-classification loop, after each
`CodeDirectory::parse`, reject a directory whose `hash_type` already appears
among the parsed set (both arms: an alternate listed before slot 0 in the
index, and an alternate duplicating an earlier one):

```rust
// alternate arm, after parse:
if code_directory.as_ref().is_some_and(|p| p.hash_type == cd.hash_type)
    || alternate_code_directories
        .iter()
        .any(|prev| prev.hash_type == cd.hash_type)
{
    return Err(crate::Error::Verification(format!(
        "duplicate CodeDirectory hash type {} at slot 0x{:08x}: at most one CodeDirectory per hash type",
        cd.hash_type, entry.slot
    )));
}
// primary arm: the mirror check against already-parsed alternates.
```

Why this single check IS directions (b) and (c):
- After it lands, at most one directory per type survives parsing, so
  "first of each type" (what `cdhash_pair` binds) **is** every emitted
  directory — direction (b)'s outcome, with the CMS check already covering
  all of them, and no deferred crypto code touched.
- It is Apple's own structural rule at its natural layer
  (`loadCodeDirectories` ≙ our `parse_superblob`), so crafted blobs adding a
  second SHA-256 at 0x1001 — including ones admitted by the out-of-scope
  slot-range gap — are rejected outright.
- Parse-time rejection propagates to `verify_slice` through the existing
  "embedded code signature is not a valid SuperBlob: {e}" push
  (`macho/verify.rs:161-166`) — no new verify-slice wiring.
- Rejected: implementing (b) as a verify-slice loop over `cds` (redundant
  once parse rejects, and its error would double-report); rejected: touching
  `verify_code_signature`'s signature (deferred crypto).

### D3 — (d): cross-CD header agreement anchored at the primary (chosen)

Private helper in `macho/verify.rs`, called from the existing per-CD page
loop for every non-primary directory (reusing that loop's label):

```rust
fn cross_cd_disagreements(
    cd: &CodeDirectory<'_>,
    primary: &CodeDirectory<'_>,
) -> Vec<&'static str> {
    let mut out = Vec::new();
    if cd.identifier() != primary.identifier() { out.push("identifier"); }
    if cd.team_id() != primary.team_id() { out.push("team ID"); }
    if cd.effective_code_limit() != primary.effective_code_limit() { out.push("code limit"); }
    if cd.n_code_slots != primary.n_code_slots { out.push("code slot count"); }
    if cd.page_size_log2 != primary.page_size_log2 { out.push("page size"); }
    if cd.flags != primary.flags { out.push("flags"); }
    if cd.exec_seg_base != primary.exec_seg_base { out.push("exec segment base"); }
    if cd.exec_seg_limit != primary.exec_seg_limit { out.push("exec segment limit"); }
    if cd.exec_seg_flags != primary.exec_seg_flags { out.push("exec segment flags"); }
    out
}
```

Push site (inside the existing `for cd in &cds` loop, after
`push_page_errors`):

```rust
if !std::ptr::eq(*cd, primary) {
    for field in cross_cd_disagreements(cd, primary) {
        report.errors.push(format!(
            "{label}CodeDirectory disagrees with the primary: {field}"
        ));
    }
}
```

- Field set: identity (`identifier`, `team_id`), hashing authority
  (`effective_code_limit`, `n_code_slots`, `page_size_log2`), and claims
  (`flags`, `exec_seg_*`). Excluded with reasons: `version`/`runtime` and
  `platform` (librarian: Apple does not require them to agree), and
  `n_special_slots` (explicitly may differ across directories); hash
  type/size are the difference itself; special-slot *contents* are
  per-algorithm and out of scope.
- Safe for honest output by construction: both directories of a dual signing
  run are built from identical builder inputs
  (`signer.rs` `build_code_directory_from_hashes` — same identifier/ctx/slice;
  `count_special_slots` sees the same `Option` set), and
  `dual_signing_binds_cdhash_pair` (asserts `errors.len() == 1`) is the
  canary that fails if the field set were ever over-tight.

## Test strategy (includes one expected rework)

1. **(c)/(b) parse-level rejection** (new test beside the existing
   `parse_superblob` tests in `codesign/verify.rs`): a hand-built SuperBlob
   (`CSMAGIC_EMBEDDED_SIGNATURE` header + index) carrying a SHA-256
   directory at slot 0 and a second SHA-256 directory at slot 0x1000 must be
   `Err(Verification)` whose message contains
   `duplicate CodeDirectory hash type`. Red before the fix (today it parses
   `Ok`).
2. **(a) rework of `tampered_alternate_page_hash_is_rejected`** (expected
   rewrite): today it pins `slice.pages == Mismatch{page_index: 0}` with the
   comment "Metadata = strongest CD (the tampered SHA-256 alternate)". Under
   the new rule the ad-hoc alternate is not CMS-bound, so the field sources
   from the primary: `pages == Matched`, while the assertion that the
   tamper is caught (`alternate SHA-256 code page 0 hash mismatch` in
   `errors`) is KEPT — coverage preserved (tamper still fails verification),
   only the metadata-source expectation flips. Rationale: the old assertion
   pinned the exact behavior being fixed (field sourced from an unbound
   directory).
   `fat_code_limit_beyond_slice_is_rejected` (comment at :802-803) was
   reviewed: that fixture is CMS-signed dual mode, where the bound set
   includes the SHA-256 alternate, so its comment stays accurate and no
   assertion touches the field — no rework, recorded as a deviation-check.
3. **(d) disagreement test** (new test in `macho/verify.rs`): ad-hoc dual
   signature, patch the alternate CD's first identifier byte (identOffset at
   CD+20) → `errors` contains
   `alternate SHA-256 CodeDirectory disagrees with the primary: identifier`
   and the report is invalid. Red before the fix (no such check).
4. **Canaries** (must stay green, unchanged): `dual_signing_binds_cdhash_pair`
   (`errors.len() == 1` proves no false positives from (d) on honest output
   and no new errors from (b)/(c) on valid dual signatures),
   `corrupt_alternate_cd_is_rejected_with_detail` (hashType 7 still fails in
   `CodeDirectory::parse` before any duplicate check), `embedded_superblob_parses`.

## Non-goals / out of scope (deliberate)

- The alternate-slot range admitting 0x1000..=0x1005 (Apple's range ends at
  0x1004) — a different ticket's finding; this design only ensures anything
  extra through that gap duplicates a hash type and is rejected.
- No edits to `crypto/**` (cdhash attribute parsing stays as-is), the signer
  or writer, parser.rs, the facade, or the CLI. Consumer notes: the facade's
  positional `.first()`/`.get(2)` reads and the CLI's index-derived JSON slot
  numbers keep compiling (no public type changes); their displayed values may
  now come from the bound primary in ad-hoc mode — consumer follow-up for
  their owning lanes, noted in the final report.
- No Apple hash-priority re-ranking, no special-slot content agreement, no
  version/runtime/platform agreement, no changes to the per-CD page/special
  slot loops or error wording.
