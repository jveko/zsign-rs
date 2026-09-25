# ZSN-25 Verifier Enforcement — Design

Date: 2026-09-25 · Branch: `zsn25-verify-enforce` · Base: `c9ff0fb`
Scope files (hard limit): `crates/zsign-core/src/codesign/verify.rs`,
`crates/zsign-core/src/codesign/constants.rs`, `crates/zsign-core/src/macho/verify.rs`.

## Problem

The core verifier accepts signatures it cannot actually justify. Re-anchored against
c9ff0fb (all pre-landing citations moved; verdicts from the re-anchor pass):

| # | Defect | Current anchor | Verdict |
|---|---|---|---|
| 1 | Dual-signed binaries fail CDHash v1/v2: `verify_slice` derives `cd_sha256` from the primary (SHA-1 in dual mode) and `alternate_sha1` demands a SHA-1 *alternate* that is never emitted (the alternate is SHA-256) → `None` | `macho/verify.rs:190-197`, `:241-260`; `cms_verify.rs:886-906, 909-930` | BUG-PRESENT |
| 2 | Alternate CodeDirectory parse failures silently dropped; no alternate is ever page/slot-checked; `parse_superblob` error detail discarded | `codesign/verify.rs:154-166`; `macho/verify.rs:120-124, 141, 163-164` | BUG-PRESENT |
| 3 | Special slots whose content is unavailable (`NotChecked`) and zero-hash slots are never elevated; only `Mismatch` errors | `codesign/verify.rs:515-545`; `macho/verify.rs:166-172` | BUG-PRESENT |
| 4 | Slot children validated by slot number only — no magic checks for requirements/XML/DER (or CMS/CD); distinct-content duplicate slots silently first/last-win | `codesign/verify.rs:154-166, 563-580`; identical duplicates already rejected by overlap check `:140-148` | BUG-PRESENT (magic + distinct dupes) |
| 5 | XML and DER entitlements are hashed into −5/−7 but never compared; no DER requirement for modern main executables | `codesign/verify.rs:534-536`; no comparison anywhere | BUG-PRESENT |
| 6 | Launch-constraint slots −8..−11 fall through `_ => None` → non-fatal `NotChecked` | `codesign/verify.rs:528-541`; routing `_ => {}` at `:165` | BUG-PRESENT |
| 7 | `execSegBase/execSegLimit/execSegFlags` are not parsed at all (struct has no fields, reads stop at byte 52) and never enforced | `codesign/verify.rs:181-207, 252-264` | BUG-PRESENT (hole larger than briefed) |
| 8 | Requirements blob hashed into −2; the designated requirement is never parsed or evaluated | no requirement-expression parser in any verify code | BUG-PRESENT |
| 9 | Version→header-size table wrong (88/80/76/52); no upper version gate; `codeLimit64` unused; `scatterOffset`/`preEncryptOffset` unvalidated; `CodeDirectory::parse` never binds `data` to the declared length (direct callers) | `codesign/verify.rs:228-243, 343-354` | BUG-PRESENT (table/fields); cdhash-oversize already closed on production paths by ZSN-24 child bounding `:119-136` |
| 10 | `CSSLOT_TICKETSLOT = 0x10001` (must be `0x10002`); version gates mislabeled (`RUNTIME=0x20600`, `LINKAGE=0x20700`); missing `CSMAGIC_EMBEDDED_SIGNATURE_OLD`, launch-constraint magic, special slots −8..−11 | `constants.rs:110, 244-269, 33-60, 116-135` | BUG-PRESENT as code state |

Queue corrections accepted from research (brief vs evidence):
- "valid pre-0x20400 directories are rejected" is imprecise: the oversized header check
  only bites trivially-short blobs; the real defects are the wrong table, the missing
  upper gate, and the unread fields. The fix (correct table) still applies.
- "bare signing can leave the vector length 2": both the brief and an intermediate
  correction were imprecise. The *raw builder* all-empty fallback floors at
  `n_special = 3` (`code_directory.rs:501-535`, test `:772-779`), but *actual bare
  signer output* is `n_special = 2`: the signer always binds a nonzero requirements
  hash (`signer.rs:793-797, 822-823`), `count_special_slots` trims unbound high
  slots (−3..−7 absent → window stops at −2), and −1 stays inside the window
  zero-filled. Unaffected either way: the elevation rule keys on nonzero stored
  hashes, not on vector length.
- `execSeg*` fields are *unparsed* today, not "parsed then discarded".
- The 0x20600 header size is **108 bytes, not 112** (librarian: `sizeof` 112 is compiler
  trailing padding; Apple's ld64 uses `offsetof(end_withLinkage)`). The design uses ≥108.

## Goals

1. Every emitted signature component that verification claims to check is actually
   checked, and everything that cannot be checked fails closed (error) or is visibly
   downgraded (warning) — never silently skipped.
2. Dual-signed binaries verify: CDHash v1/v2 are bound by emitted CD *type*.
3. All findings ride the existing `report.errors` / `report.warnings` channels;
   `verify_macho` keeps its `Ok(report)` channel for parseable Mach-O.
4. No NEW failures against the macOS interop gate
   (`scripts/verify-apple-interop.sh` `agree_valid` on our ad-hoc bundle, `/bin/ls`,
   codesign ad-hoc output, and the tampered negative control). The `agree_valid
   "cert-signed bundle"` line (`:191`) is **already red at c9ff0fb, pre-existing and
   out of scope**: the script self-signs its certificate (`:58-64`) while production
   CMS verification hard-defaults to Apple roots (`crypto/cms_verify.rs:281-288`) and
   the facade report is error-sensitive (`zsign/src/verify.rs:135-138`), so
   `zsign -V` reports the anchoring failure that the dual-pin design intentionally
   produces. This lane neither fixes nor worsens it; it is escalated as a supervisor
   decision (see Findings for the supervisor).

## Frozen contracts (must not break — compiled from the consumer map)

- **C-1** `PageCheck` variant set and field names are exhaustively matched in
  `crates/zsign-cli/src/main.rs:234-243, 326-335`. No add/remove/rename.
- **C-2** `SpecialSlotCheck` variant set exhaustively matched at
  `crates/zsign-cli/src/main.rs:275-281`. No add/remove/rename.
- **C-3** `SliceVerifyReport.special_slots` stays positional, length == `n_special_slots`,
  with `NotChecked` entries at index 0 (slot −1) and 2 (slot −3):
  `crates/zsign/src/verify.rs:354-366, 496-509` compare `== Some(&NotChecked)`; test
  `macho/verify.rs:678-679` asserts all-`Matched` for the supplied-input fixture.
- **C-4** `verify_macho`/`verify_slice` must return `Ok(report)` for a parseable Mach-O
  with a broken signature: `crates/zsign/src/verify.rs:348` `?`-propagates, tests
  `:1090/:1239/:1253` unwrap. Signature findings = `report.errors.push(...)`.
- **C-5** `SignatureInputs` keeps exactly the fields `{info_plist, code_resources}`
  (full literal at `crates/zsign/src/verify.rs:483-486`); `verify_macho` signature frozen;
  `parse_superblob` keeps `Result<SuperBlob>` (doctest `codesign/verify.rs:20-26`).
- **C-6** The report structs are re-exported through the facade at
  `crates/zsign/src/verify.rs:33`, and `codesign`/`crypto` modules are re-exported by
  `crates/zsign/src/lib.rs:49` — changes are allowed only with in-workspace migration;
  downstream semver impact is out of lane scope and noted in the report.
- **C-7** The following constants keep name and value (current in-workspace consumers,
  from the constants-usage sweep): `CSMAGIC_EMBEDDED_SIGNATURE`,
  `CSMAGIC_CODEDIRECTORY`, `CSMAGIC_REQUIREMENTS`, `CSMAGIC_REQUIREMENT`,
  `CSMAGIC_EMBEDDED_ENTITLEMENTS`, `CSMAGIC_EMBEDDED_DER_ENTITLEMENTS`,
  `CSMAGIC_BLOBWRAPPER`, `CSSLOT_CODEDIRECTORY`, `CSSLOT_REQUIREMENTS`,
  `CSSLOT_ENTITLEMENTS`, `CSSLOT_DER_ENTITLEMENTS`,
  `CSSLOT_ALTERNATE_CODEDIRECTORIES`/`_MAX`/`_LIMIT`, `CSSLOT_SIGNATURESLOT`,
  `CS_HASHTYPE_SHA1`, `CS_HASHTYPE_SHA256`, `CS_SHA1_LEN`, `CS_SHA256_LEN`, `CS_ADHOC`,
  `CS_EXECSEG_MAIN_BINARY`, `CS_EXECSEG_ALLOW_UNSIGNED`, `CODEDIRECTORY_VERSION`,
  `CODEDIRECTORY_VERSION_EARLIEST`, `CODEDIRECTORY_VERSION_TEAMID`,
  `CODEDIRECTORY_VERSION_CODELIMIT64`, `CODEDIRECTORY_VERSION_EXECSEG`,
  `CSREQ_DESIGNATED`. `CS_EXECSEG_DEBUGGER`/`JIT`/`SKIP_LV` and
  `CODEDIRECTORY_VERSION_SCATTER` are currently unconsumed and become first-used by
  tasks 7/9; `CSSLOT_TICKETSLOT`, `CODEDIRECTORY_VERSION_RUNTIME`,
  `CODEDIRECTORY_VERSION_LINKAGE`, `CSSLOT_SPECIAL_*`, `CSMAGIC_*_OLD`, and the
  launch-constraint magic are the revalued/added set owned by queue items 9/10.

## Architecture

Cross-cutting decisions (brainstorm picks, refined by research):

- **Patch-in-place inside the three scope files.** No new module files (out of lane
  scope). Structure-bearing helpers become methods on `SuperBlob`/`CodeDirectory` or
  private functions in the file that owns them.
- **Two channels only.** Structural failures (malformed SuperBlob, malformed
  CodeDirectory, malformed requirements) stay `Err` from the parsers and are converted
  to `report.errors` strings at `verify_slice` (with the error *detail* passed through —
  today it is discarded at `macho/verify.rs:120-124`). Semantic findings (page mismatch,
  slot findings, exec-seg policy, entitlements comparison, designated requirement) are
  `report.errors.push(...)`; unverifiable-but-not-false conditions are
  `report.warnings.push(...)`.
- **All CDs verified; strongest governs metadata; primary anchors CMS and
  identity.** `parse_superblob` errors on any CodeDirectory slot child that fails to
  parse (primary and alternates). `verify_slice` collects the emitted-CD list ONCE,
  immediately after `primary` is established (so the CMS branch and the
  post-CMS designated-requirement step both see it), and runs
  page-check + special-slot-check for *every* emitted CD. Split of authority:
  - **CMS `content`** = `primary.raw()` — the CMS signs slot 0 (librarian: detached
    over the primary; signer `signer.rs:515`). "Strongest" must NEVER be applied to
    the `content` argument or `messageDigest`/`signature_ok` break on dual output.
  - **Report metadata** (`report.pages`, `report.special_slots`) = the **strongest
    viable CD** (`max_by_key(hash_size)` — the SHA-256 CD in dual output), per queue
    item 2's "choose the strongest viable CD"; these are what consumers read and
    `is_valid` gates on (all CDs' failures land in `report.errors` either way).
  - **Identity** (`report.identifier`, `report.adhoc`) stays primary (CMS content
    anchor; identical across CDs in honest output).
  - Alternate-CD findings are error strings tagged with the CD's hash type, e.g.
    `alternate SHA-256 code page 3 hash mismatch (code region modified?)`; the
    primary's message texts stay byte-identical (unlabeled) for pinned tests.
- **Special-slot content map** moves into `codesign/verify.rs` as one lookup used by
  `check_special_slots(cd, inputs, superblob)`:
  - `k = 1` (Info.plist): caller input only (`inputs.info_plist`); superblob fallback is
    deliberately NOT used (librarian: Apple's `MachORep::component()` reads info from the
    filesystem; missing superblob child for slots 1/3 is normal).
  - `k = 3` (CodeResources): caller input only (`inputs.code_resources`).
  - `k = 2, 5, 7`: superblob children (magic-validated by parse).
  - `k = 8..=11`: superblob children `0x0008..0x000b` (task 6; magic-checked in task 10
    together with `CSMAGIC_LAUNCH_CONSTRAINT`).
  - `k = 4, 6`: no content source; stay non-fatal `NotChecked` (never in the brief's
    required list; blanketing them risks the interop gate on Apple output).
  Hashing always uses the FULL child blob (magic+length header included — that is what
  the signer hashes); semantic parsing (XML plist, DER entitlements) uses a new
  additive `SlotEntry::payload()` accessor returning the child *after* its 8-byte
  header, bounded by the child's declared length — `SlotEntry::blob` carries the
  header, so passing it straight to `plist::from_bytes`/
  `der_entitlements_to_plist` would parse `fade7171/fade7172 + length` as data.
- **Elevation rule (item 3)** lives in `macho/verify.rs` where errors are owned (C-4):
  ONE loop walks `(label, checks)` pairs — the primary (label `""`) plus every
  alternate (label `alternate {SHA-1|SHA-256} `) — pushing
  `{label}special slot -{k} hash mismatch` on `Mismatch` (primary text byte-identical
  to the pinned string) and, when `NotChecked` and the slot is *required*,
  `{label}special slot -{k} is bound but its content was not supplied`. Alternate
  `NotChecked` IS elevated (a tampered alternate can diverge from the primary).
  **Requiredness is context-split (read-only-caller constraint):**
  - `k ∈ {1, 3}` (Info.plist / CodeResources — caller-supplied): required ONLY when
    bundle context is actually supplied, i.e. `inputs.info_plist.is_some() ||
    inputs.code_resources.is_some()`. `SignatureInputs::none()` means "standalone:
    caller cannot supply these" — the read-only facade
    (`zsign/src/verify.rs:344-368`) owns that message, and core stays silent so the
    standalone contract and its test survive (bound-nonzero + no-context stays
    `NotChecked`).
  - `k ∈ {2, 5, 7}` and `k ∈ {8..=11}` (SuperBlob-sourced): required UNCONDITIONALLY —
    their content comes from the signature itself, so `NotChecked` there is always a
    core failure regardless of caller context.
  Membership is expressed as two `i32` arrays matched against `-k`
  (`CSSLOT_SPECIAL_INFOSLOT`, `CSSLOT_SPECIAL_RESOURCEDIR` for the context pair;
  `CSSLOT_SPECIAL_REQUIREMENTS/_ENTITLEMENTS/_DER_ENTITLEMENTS` plus the new
  `CSSLOT_SPECIAL_LAUNCH_CONSTRAINT_*`/`CSSLOT_SPECIAL_LIBRARY_CONSTRAINT` for the
  SuperBlob set) — no offset arithmetic anywhere.
  `Missing` (stored hash all-zero = not bound) stays silent — how the rule self-scopes
  to "what the signer actually binds" (dylibs never bind −1/−3; bare signing
  zero-fills −1).
- **CDHash pair by emitted type (item 1)**, private helper in `macho/verify.rs`:
  `cd_sha1 = SHA1(bytes of the SHA-1 CD among {primary} ∪ alternates)`,
  `cd_sha256 = SHA256(bytes of the SHA-256 CD)`, CMS `content` stays `primary.raw()`.
  `cd_sha1 = None` when no SHA-1 CD exists (sha256-only → v1 single-element arm, current
  behavior). No SHA-256 CD while a non-empty CMS is present → explicit error
  (cannot verify CDHash v2). Only computed inside the non-ad-hoc branch (a
  branch, not an early return — after task 8's restructure the designated-requirement
  step still runs on every path), so ad-hoc output never hits it. `alternate_sha1` is
  deleted (only caller is the site being rewritten).
- **Requirements evaluation (item 8)**: bounded parser in `codesign/verify.rs`
  (Requirements SuperBlob `0xfade0c01` → typed index → requirement blob `0xfade0c00`
  with `kind == exprForm(1)`; `lwcrForm(2)` rejected), expression tree with bounded
  recursion, Kleene three-valued evaluator. `macho/verify.rs` wires it AFTER the whole
  CMS/ad-hoc chain: the 8-byte empty-wrapper branch keeps its exact current semantics
  (sets `adhoc_report()` and skips `verify_code_signature` — the guard is preserved by
  branching, not by early-returning) and control then falls through to the
  designated-requirement step, so ad-hoc output is evaluated too without ever feeding
  the empty wrapper to the CMS parser. `Violated` → error, `Unsupported` → warning
  `designated requirement not fully evaluated: <reason>`, empty/absent designated
  requirement → pass.
- **Version-gated header reads (item 9)** in `CodeDirectory::parse`, with `data`
  sliced to the blob's own declared length so `cdhash()` binds declared length by
  construction for every caller (production paths already bounded; direct callers
  hardened).

## Per-item design

### 1. Dual-CDHash binding
Select v1/v2 digests by emitted CD type (see Architecture). Signer needs **no changes**:
`signer.rs:502-524` emits `cdhash_sha1 = SHA1(SHA-1 CD)`, `cdhash_sha256 =
SHA256(SHA-256 CD)`, content = SHA-1 primary; `cms.rs:254-263` builds v1
`[SHA1(SHA-1 CD), SHA256(SHA-256 CD)[..20]]`; `cms_verify` arms match exactly these
values once passed correctly. Rejected alternatives: trying candidates until attributes
match (nondeterministic, masks mismatches); pushing selection into `crypto/cms_verify.rs`
(out of scope — ZSN-3). Centerpiece regression: first dual-mode sign→verify round trip
in the repo (`sign_macho` + credentials): production path must yield exactly the
anchoring error, `cdhash_v1_ok && cdhash_v2_ok`; injected anchors → `valid`. The
existing test helper `cms_report_with_test_anchor` hardcodes `cd_sha1 = None` and the
primary's `cdhash_sha256()`, which is wrong for dual output — it is generalized to use
the same emitted-type pair selector as production (a small private `cdhash_pair(&SuperBlob)`
function in `macho/verify.rs`, shared by `verify_slice` and the helper; sha256-only
behavior is unchanged).

### 2. Alternate CodeDirectory parsing and verification
`parse_superblob` returns `Err` (with detail) when any CodeDirectory slot child fails
`CodeDirectory::parse`, and on a duplicate slot-0 entry (today's `is_none()` guard
silently ignores it; distinct-content duplicates are the residual case ZSN-24's
overlap check does not catch — identical duplicates already rejected
(`codesign/verify.rs:140-148`)). `verify_slice` passes the parse error detail into
`report.errors`. Every emitted CD gets `check_code_pages_in_file` + `check_special_slots`;
primary findings keep the exact pinned strings (`code page {i} hash mismatch…`,
`code slot count mismatch`, `zero code bytes`); alternate findings are tagged
`alternate SHA-256 …`. Rejected: verifying only the strongest CD (leaves the primary
unchecked in ad-hoc output, where no CMS binds it); strongest-only + structural checks
(weaker, no real saving). Checking *all* CDs is a superset of the brief's
"strongest viable" requirement and keeps every existing test contract (they pin
primary-patched fixtures).

### 3. Required special slots (core rule)
Uniform elevation rule in `macho/verify.rs` (Architecture) — no new parameter, no
binary-kind argument: a nonzero stored hash with no content source is the *only*
signal needed, so `SignatureInputs` and `verify_macho` stay frozen (C-4/C-5). Rejected
alternatives: adding a bundle/main-executable parameter (breaks the read-only
re-entrance in `zsign/src/verify.rs:483`; core has no filesystem access); moving
ZSN-26's bundle-level variant checks into core (explicitly forbidden duplication).
`SpecialSlotCheck` variants unchanged (C-2); the `NotChecked` variant remains
constructible (C-3). Core errors for −1/−3 will co-fire with ZSN-26's messages in the
`zsign` layer — accepted overlap (both use `.any()`, tests unaffected), recorded here
because the `zsign` file is not editable from this lane.

### 4. Slot routing: typed magic checks and duplicate rejection
`parse_superblob` gains a per-slot expected-magic table and a seen-slot set, both
driving `Err`:
- `0x0000`, `0x1000..=0x1005` → `CSMAGIC_CODEDIRECTORY` (`0xfade0c02`, also enforced
  by `CodeDirectory::parse`);
- `0x10000` → `CSMAGIC_BLOBWRAPPER` (`0xfade0b01`);
- `0x0002` → `CSMAGIC_REQUIREMENTS` (`0xfade0c01`);
- `0x0005` → `CSMAGIC_EMBEDDED_ENTITLEMENTS` (`0xfade7171`);
- `0x0007` → `CSMAGIC_EMBEDDED_DER_ENTITLEMENTS` (`0xfade7172`).
Constraints `0x0008..0x000b` join the table in task 10 together with
`CSMAGIC_LAUNCH_CONSTRAINT` (ordering constraint — see "Commit order" below).
Duplicate *recognized* slot values with distinct content → `Err` (identical duplicates
already rejected by the overlap check). Magic mismatch →
`SuperBlob entry {i} (slot 0x…): blob magic 0x…, expected 0x…`.
Known compatibility pin: the truncated-CMS fixture (`macho/verify.rs:603`) keeps its
8-byte wrapper with intact magic, so the magic check passes and the existing
`empty CMS wrapper` rule still fires (R5).

### 5. XML vs DER entitlements
- **Comparison:** private `der_entitlements_to_plist(&[u8]) -> Result<plist::Value>`
  in `codesign/verify.rs`, reversed from the in-repo encoder `codesign/der.rs::plist_to_der`
  and extended for Apple's shapes. The repository encoder emits the canonical **v1**
  envelope — `0x70` [APPLICATION 16] constructed, `INTEGER version`, `0xb0`
  [16]-constructed entries SET of `SEQUENCE { UTF8String key, value }`
  (`der.rs:258-276`, pinned by its tests `:348-369`) — with nested dicts as `SET 0x31`
  and arrays as `SEQUENCE 0x30`; values `BOOLEAN 0x01 | INTEGER 0x02 | UTF8String 0x0C`
  (the encoder refuses Data/Date/Real). The decoder therefore: accepts the `0x70`
  envelope (require leading `INTEGER` version, value ignored) OR no envelope (v0 —
  older Apple blobs start directly at the entries container); walks the entries
  container tag-agnostically (`0xb0 | 0x31 | 0x30 | 0x60 | 0xA0` — sources disagree on
  the inner tag, so only the pair structure is required); maps
  `BOOLEAN|INTEGER|UTF8String/IA5String|OCTET STRING→Data|GeneralizedTime/UTCTime→Date|
  SEQUENCE→Array|nested container→Dictionary`; `NULL` and unknown tags → `Err`
  (plist has no null — fail closed; our own encoder cannot produce them).
  Bounds-checked lengths, recursion depth capped (32). Semantic parsing reads the
  child payload AFTER the 8-byte blob header via `SlotEntry::payload()`; the XML side
  parses `payload()` with `plist::from_bytes` (parse failure → error). Dictionaries
  compared with `Value` equality (order-insensitive: `plist::Dictionary` is
  IndexMap-backed and `sort_keys` is never called — key order is document order, NOT
  normative). Rejected: re-encoding XML via `plist_to_der` and byte-comparing (byte
  order equals *our* XML order only; third-party encoders would false-mismatch).
- **DER requirement:** gated on BINDING, not just child presence: compute
  `xml_bound` = stored −5 hash nonzero and `der_bound` = stored −7 hash nonzero.
  For `slice.is_executable`, primary CD version ≥ `CODEDIRECTORY_VERSION_EXECSEG`,
  and `xml_bound`: require `der_bound` AND the `0x0007` child present, else error
  `XML entitlements bound (slot -5) without bound DER entitlements (slot -7)` — a
  present-but-unbound DER child (attacker zeroes the −7 hash while supplying a
  matching blob) is rejected too. When both children are present they are compared
  regardless of binding (the binding rule above covers the bound cases). Scoped to
  executables because the signer emits DER only for executables (`signer.rs:85-93`)
  and dylibs legitimately bind −5 without −7 (`EMPTY_ENTITLEMENTS`,
  `signer.rs:166-176`) — a blanket rule breaks `zsign`'s `signed_bundle_verifies`
  (`errors.len()==1` pins on the framework binary). Apple TN3126 backs the
  main-executable rule ("re-sign your app to include the new DER entitlements").

### 6. Launch-constraint slots −8..−11
Content lookup extends to superblob children `0x0008..0x000b` (contiguous with the
existing positive constants `CSSLOT_LAUNCH_CONSTRAINT_*`); digest verified like every
other self-consistent slot (integrity = the "verify" half of the brief's first option).
Bound without a superblob child → `NotChecked` → elevated by the item-3 whitelist
(explicit failure for nonzero unsupported slots — the brief's second option — when the
content genuinely cannot exist). Rejected: unconditional reject of nonzero −8..−11
(needlessly fails signatures whose constraint blobs *are* present and checkable).
Magic validation of `0x0008..0x000b` lands in task 10 with its constant.

### 7. execSeg fields
`CodeDirectory::parse` reads (version ≥ `0x20400`): `exec_seg_base: u64 @64`,
`exec_seg_limit: u64 @72`, `exec_seg_flags: u64 @80` — new pub fields (additive).
Enforcement in `macho/verify.rs` against the slice, primary CD only (honest output is
identical across CDs; keeps messages single):
- **Range** (`0/0` = unset → accepted):
  1. `(base, limit) == (text_segment_base, text_segment_size)` → OK — our signer's
     convention (`signer.rs:825-826` passes `__TEXT` **vmaddr/vmsize**); exact match,
     fully sound.
  2. Otherwise, a **plausibility fallback** for file-convention signatures (Apple
     writes `__TEXT` **fileoff/filesize** — librarian: Security source + `/bin/ps`
     sample `Base 0x0 Limit 0x8000`; ld64 `textSeg.Offset/Filesz`):
     `base <= slice.size && limit >= 0x1000 && limit <= text_segment_size &&
     base + limit <= slice.size`. The `≥ 0x1000` floor rejects degenerate ranges
     like `(0, 1)`; still, with `base == 0` a small-but-plausible tampered `limit`
     is NOT detectable — this branch is explicitly NOT sound enforcement.
  3. otherwise → error `executable segment range 0x…+0x… does not match __TEXT`.
  **Exact file-convention enforcement is BLOCKED**: it needs `__TEXT` fileoff/filesize
  exposed by `macho/parser.rs` (`ArchSlice` carries only vmaddr/vmsize at
  `parser.rs:110-114, 237-252`, and `first_segment_offset` skips `fileoff == 0`), and
  `parser.rs` is outside this lane's three-file scope. Recorded as a scope question
  for the supervisor (Findings); the fallback above is the strongest sound-adjacent
  check available in scope.
- **Flags**: known mask `0x3F1` = MAIN_BINARY|ALLOW_UNSIGNED|DEBUGGER|JIT|SKIP_LV|
  CAN_LOAD_CDHASH|CAN_EXEC_CDHASH (librarian enumerated Apple's set; it ends at
  `0x200`). Unknown bits → error `unknown exec segment flags bits 0x…`.
  `MAIN_BINARY` set ⇔ `slice.is_executable` (both directions errors; our signer sets it
  iff `MH_EXECUTE`, `signer.rs:785-786`).
- **Entitlement cross-check (SUBSET rule, flag ⇒ key, never equality):**
  ALLOW_UNSIGNED ⇒ `get-task-allow` OR `run-unsigned-code`;
  JIT ⇒ `dynamic-codesigning` (NOT `allow-jit` — absent from the Security corpus);
  DEBUGGER ⇒ `com.apple.private.cs.debugger`; SKIP_LV ⇒
  `com.apple.private.skip-library-validation`. CAN_LOAD/CAN_EXEC have no pinned key
  names (librarian: `com.apple.private.amfi.*`) → not enforced. Key present in the
  bound XML dict but flag unset → no finding (subset direction only).
  Entitlements XML absent while a cross-checkable flag is set → warning
  `exec segment flags 0x… cannot be cross-checked without entitlements` (error would
  fail closed on re-signed/ent-stripped inputs we cannot disprove; ad-hoc flag tampering
  is still caught by the range and MAIN_BINARY rules).
  Rejected: making the cross-check an equality (signer only ever adds ALLOW_UNSIGNED;
  Apple derives more bits from private entitlements we would have to guess).

### 8. Designated requirement
Parser (in `codesign/verify.rs`): Requirements SuperBlob (`0xfade0c01`: magic/length/
count + `{type u32, offset u32}` index) → single requirement blob (`0xfade0c00`,
`kind u32` must be `exprForm(1)`; `lwcrForm(2)` → `Err`) → expression bytecode.
Opcodes are `u32` big-endian; high byte = flag mask (`opFlagMask 0xFF000000`,
`opGenericFalse 0x80000000`, `opGenericSkip 0x40000000`). Supported nodes:
`opFalse(0), opTrue(1), opIdent(2), opAppleAnchor(3), opAnd(6), opOr(7), opCDHash(8),
opNot(9), opAppleGenericAnchor(15)`; `opAnd/opOr` are **binary** (nested; n-ary chains
are the emitter's sugar). Strings = `u32 len` + raw bytes, next operand 4-aligned, no
NUL (librarian, from Apple's requirement reader). **One grammar rule, no
contradictions:** the parser fully parses only the supported set with correct operand
layouts; **ANY other opcode — known-but-unsupported (`opCertField(11)`,
`opCertGeneric`, …), unknown, or flag-bearing — terminates parsing of that requirement
and marks the whole designated requirement `Unsupported`** without inspecting
operands (bounded by the child's declared length). Structural malformation *inside the
supported grammar* (truncated operand, bad header/magic/count/`kind != 1`, recursion
depth > 64) → `Err` (hard error), matching Apple's `errSecCSReqInvalid` posture.
Bounded recursion likewise.
Evaluator (Kleene `{T,F,U}` over fully-supported trees): `Violated` (result F) → error
`designated requirement not satisfied`; `Unsupported` (result U) → warning
`designated requirement not fully evaluated: <reason>` (must stay a warning — the
interop gate's `/bin/ls` DR uses `anchor apple generic` + certificate-policy ops whose
cert chain DER is not exposed by `crypto/cms_verify.rs`, which is out of scope);
no designated entry in the set → pass (our signer always emits the count=0 empty set —
`signer.rs:76-82` — so no self-output regression; Apple synthesizes a default DR that
cannot be re-derived here). Context: `identifier` from the primary CD; `cdhashes` =
truncated (`min(len,20)`) digest of *each* emitted CD (its own hashType) for `opCDHash`;
anchors map to `CmsVerifyReport.anchored` when a real (non-ad-hoc) CMS report exists,
`U` when there is no CMS. The `U` source is always the single whole-requirement
`Unsupported` marker produced by the parser. Rejected: strict unsupported→error
(would fail every real Apple DR and the interop gate); full cert-aware evaluation
(needs `crypto/cms_verify.rs` edits — explicitly deferred to ZSN-3).

### 9. CD version handling
Header-size table in `CodeDirectory::parse` (verified against Apple's struct via
`offsetof`, librarian):
`≥0x20600 → 108`, `≥0x20500 → 96`, `≥0x20400 → 88`, `≥0x20300 → 64`,
`≥0x20200 → 52`, `≥0x20100 → 48`, else → `44` (earliest `0x20001`).
`version > CODEDIRECTORY_VERSION_LINKAGE (0x20600)` → `Err` — stricter than Apple
(which merely logs newer versions up to `compatibilityLimit 0x2F000`); deliberate
fail-closed policy per brief item 9, recorded as a design decision.
Version-gated reads and policies:
- `≥0x20100`: `scatter_offset @44`; nonzero → `Err`
  `scatter CodeDirectories are not supported` (run-list hashing changes how page hashes
  are interpreted; Apple's own `Builder::scatter()` has no callers — unsupported
  format feature, not tampering).
- `≥0x20200`: `team_offset @48` (unchanged).
- `≥0x20300`: `code_limit64 @56`; nonzero overrides `codeLimit` — exposed as
  `effective_code_limit() -> u64`; `check_code_pages`/`check_code_pages_in_file`
  switch to it (`signingLimit()` semantics: `version ≥ 0x20300 && codeLimit64 != 0`).
  **All guard arithmetic runs in `u64` first; `usize` casts only after the value is
  proven ≤ `code.len()`** — on 32-bit targets (`wasm32` ships `zsign-core`) a
  `u64 as usize` cast truncates ≥ 4 GiB values and can route around the oversize
  guard (post-adjudication reviewer finding, disposition: plan task 9 amended).
  `code_limit: u32` field type unchanged (C-6).
- `≥0x20400`: exec seg fields (item 7).
- `≥0x20500`: `runtime @88` (pub field), `pre_encrypt_offset @92` (private);
  `pre_encrypt_offset != 0` → `Err` (`pre-encrypted CodeDirectory hashes are not
  supported` — hashes cover plaintext pages, so on-disk pages legitimately differ);
  `runtime != 0 && flags & CS_RUNTIME == 0` → `Err`
  (`runtime version recorded without the CS_RUNTIME flag` — cross-field consistency;
  the reverse direction is allowed because older SDKs legitimately record 0).
- `≥0x20600`: linkage fields `u8 hash_type @96, u8 application_type @97,
  u16 application_subtype @98, u32 linkage_offset @100, u32 linkage_size @104`;
  `linkage_size == 0` → absent; `linkage_size == 20 && (linkage_offset as u64) + 20
  <= data.len() as u64` → structural OK (u64 comparison — `linkage_offset ==
  u32::MAX` must not overflow/panic; linkage is a single truncated cdhash pointing
  outside this
  signature's verifiable scope — metadata, not a verification input); any other size
  or out-of-bounds offset → `Err`. Not exposed (no consumer).
- `data = &blob[..declared_length]` inside `parse` (declared = `blob[4..8]`;
  `declared < header_size || declared > blob.len()` → `Err`) → `cdhash()`/`cdhash_sha256()`
  bind the declared length for every caller (Apple: `cdhash = H(CD bytes over declared
  length)`; CMS is detached over `cd->length()` — librarian, Security source).
  Existing production path unchanged (ZSN-24 already bounds children to exactly this).

### 10. constants.rs
- `CSSLOT_TICKETSLOT: 0x10001 → 0x10002` (librarian: Apple `blob.h` — brief was right;
  `0x10001` is the cd-identification slot, detached signatures only). Zero in-workspace
  consumers; add a test pinning `0x10002`.
- Version gates: `CODEDIRECTORY_VERSION_RUNTIME: 0x20600 → 0x20500`,
  `CODEDIRECTORY_VERSION_LINKAGE: 0x20700 → 0x20600` (librarian: `CS_SUPPORTSRUNTIME
  0x20500`, `CS_SUPPORTSLINKAGE 0x20600`; `0x20700` exists in no authoritative source).
  `CODEDIRECTORY_VERSION_PREENCRYPT` stays `0x20500` — that value is correct
  (`supportsPreEncrypt` gates both runtime and preEncryptOffset); docs corrected to say
  so. All four are currently zero-consumer → free to revalue; task 9 adopts
  RUNTIME/LINKAGE first, task 10 finishes docs/tests.
- Add `CSMAGIC_EMBEDDED_SIGNATURE_OLD = 0xfade0b02` (value confirmed; purpose
  UNVERIFIED — Apple's comment is `/* XXX */`, no reader/writer in Security/xnu/ld64)
  → used ONLY to make `parse_superblob`'s wrong-magic error diagnose
  `old embedded signature magic 0xfade0b02` instead of the generic message; never
  gates acceptance.
- Add `CSMAGIC_LAUNCH_CONSTRAINT = 0xfade8181` (one magic for all four constraint
  types) → adopted by the item-4 magic table for slots `0x0008..0x000b`.
- Add `CSSLOT_SPECIAL_LAUNCH_CONSTRAINT_SELF/PARENT/RESPONSIBLE = -8/-9/-10` and
  `CSSLOT_SPECIAL_LIBRARY_CONSTRAINT = -11` → adopted in the elevation whitelist
  (`macho/verify.rs`) and the content map (`codesign/verify.rs`), replacing the
  numeric literals introduced by tasks 3/6.

## Invariants

1. `verify_macho(data, &inputs)` returns `Ok` for any parseable Mach-O; all signature
   findings are strings in `report.errors` (C-4). Parsers (`parse_superblob`,
   `CodeDirectory::parse`, requirements parse) may `Err`; `verify_slice` converts.
2. `special_slots` vector: length == `n_special_slots`, positional, `NotChecked`
   constructible (C-1..C-3). Strongest CD drives `pages`/`special_slots`; primary CD
   drives `identifier`/`adhoc` and is the sole CMS `content`.
3. Existing pinned strings stay byte-identical: `code page {i} hash mismatch (code
   region modified?)`, `code slot count mismatch`, `zero code bytes`,
   `special slot -{k} hash mismatch`, `empty CMS wrapper but not ad-hoc flagged`,
   `not anchored to a trusted root`, `LC_CODE_SIGNATURE`.
4. Own-output round trips stay valid: sha256-only fixtures → exactly 1 production error
   (anchoring) + injected-anchor `valid`; dual fixtures → same after task 1; ad-hoc
   fixtures → `valid` with no CMS errors.
5. Emitted constants: `CODEDIRECTORY_VERSION == 0x20400` unchanged; USED constants
   unchanged (C-7); `CSSLOT_TICKETSLOT == 0x10002`.
6. Signer/crypto/other files: zero edits. If a queue item reveals a signer-side defect,
   stop that sub-thread and report (brief rule) — known signer observations recorded in
   "Findings for the supervisor" below.

## Test strategy

Scoped gate (every task, before its commit):
`mkdir -p .tmptmp && TMPDIR=$PWD/.tmptmp cargo test -p zsign-core verify -- --skip test_ipa_signing_is_deterministic`
(`/tmp` is tmpfs and SIGBUS-flakes under parallel-lane load; `test_ipa_signing_is_deterministic`
is the pre-existing ZSN-15 failure and is skipped in every run, baseline verified:
54 passed / 0 failed at c9ff0fb.) Task 10 additionally requires
`TMPDIR=$PWD/.tmptmp cargo test -p zsign-core constants` — the `verify` substring
filter does not select `codesign::constants::tests::*` (baseline there: 5 tests).

Every queue item gets a failing-first regression (Tester writes, implementer greens),
inline in the scope files per repo convention:

1. dual sign→verify round trip (`sign_macho` + credentials): production errors == 1
   (`not anchored`), `cdhash_v1_ok && cdhash_v2_ok`, injected anchors → `valid`
   (helper generalized to the emitted-type `cdhash_pair` selector).
2. corrupt alternate CD *hashType byte* (magic left intact so task 4's magic table
   stays out of the way — the assertion must remain stable after task 4 lands) →
   error carries the parse detail (`unsupported CodeDirectory hash type`); tampered
   alternate page hash → `alternate SHA-256 code page …` error AND
   `report.pages == Mismatch { page_index: 0 }` (metadata = strongest = the tampered
   alternate); primary message texts unchanged. Existing
   `fat_code_limit_beyond_slice_is_rejected` loses its exact `pages` equality (the
   field now carries the strongest CD's verdict) and pins the exact stored/computed
   numbers through the error string instead — documented deviation for queue item 2.
3. context gating: sign with `code_resources` only, verify with
   `info_plist: Some(_)` (context supplied, −3 content absent) →
   `special slot -3 is bound but its content was not supplied` on primary AND
   `alternate SHA-256`-tagged; the same binary with the right inputs → no findings;
   `SignatureInputs::none()` on an info-bound fixture → SILENT (standalone contract,
   facade owns that message); dropping the `0x0002` child (index rename) →
   `special slot -2 …` fails UNCONDITIONALLY with `none()` (SuperBlob-sourced slots
   need no caller context).
4. requirements child magic patched → `parse_superblob` `Err`; distinct-content
   duplicate `0x0002` → `Err`; truncated-CMS fixture still reaches the
   `empty CMS wrapper` rule.
5. decoder units: `xml → plist_to_der → decode == xml` round trip (exercises the real
   `0x70`/`0xb0` v1 envelope), a hand-built v0 (no-envelope) blob, order-insensitive
   dict equality, malformed DER → `Err`; e2e: DER value byte flipped + `-7` hash
   recomputed in both CDs → `XML and DER entitlements dictionaries differ`; slot type
   `0x0007` rewritten + `-7` hash zeroed → missing-DER error on an executable;
   dylib-shape fixture (no DER) unaffected.
6. content-map unit: a synthetic CD whose stored −8 hash equals
   `SHA256(child)` over a `0xfade8181` child → `Matched`; e2e: `n_special`
   patched `7 → 8` (deterministic nonzero stored hash from the header/ident bytes that
   enter the grown window; no panic — `hash_offset/hash_size` stays ≥ 8) with no
   constraint child → `special slot -8 is bound but its content was not supplied`
   (this fixture has no `0x0008` child, so task 10's magic check cannot affect it).
7. ad-hoc fixture, primary CD bytes patched: `execSegBase` → vm-space junk → range
   error; `execSegFlags |= 0x800` → unknown-bits error; `MAIN_BINARY` cleared on an
   executable → error; JIT bit without entitlements → warning; unchanged fixture →
   no new findings.
8. requirements parser/evaluator units (satisfied / violated / unsupported opcode /
   malformed → `Err` / `kind=lwcr` → `Err` / count=0 → none); e2e: ad-hoc fixture with
   its requirements blob replaced by a well-formed DR requiring a mismatching
   identifier (superblob rebuilt in-place using the reserved LC slack, `-2` hash
   recomputed) → `designated requirement not satisfied`.
9. synth CD bytes at `0x20001/0x20300/0x20500/0x20600` parse; `0x20601` → `Err`;
   `scatter != 0` → `Err`; `preEncryptOffset != 0` → `Err`; nonzero `codeLimit64`
   drives `check_code_pages`' count guard; direct `CodeDirectory::parse` of an
   oversized buffer → `cdhash()` equals digest of the declared slice.
10. `CSSLOT_TICKETSLOT == 0x10002`, gate-constant values, launch-constraint magic
    adopted (wrong-magic patch on `0x0008` → `Err`).

Adjustments to existing tests are limited to assertions the queue intentionally
changes; currently anticipated: none (all ten B.1/B.2/B.3 fixtures re-verified green by
analysis — any change discovered during implementation is reported in the final
plan-vs-actual section).

## Commit order and the constants reconciliation

The queue is executed strictly in order (1→10), one independently-green commit series
per item. The brief assigns constants work to item 10, but items 4/6/9 consume some of
those constants' semantics *earlier*. Resolution — a constant is introduced by the
first task that needs it, and item 10 completes the remainder:

- Task 4 needs only constants that already exist (`CSMAGIC_REQUIREMENTS`,
  `CSMAGIC_EMBEDDED_ENTITLEMENTS`, `CSMAGIC_EMBEDDED_DER_ENTITLEMENTS`,
  `CSMAGIC_BLOBWRAPPER`, `CSMAGIC_CODEDIRECTORY`, `CSSLOT_*`) → no new constants.
- Task 6 routes constraints via the existing positive `CSSLOT_LAUNCH_CONSTRAINT_*`
  (`0x0008..0x000b`); magic check deferred to task 10 with its constant.
- Task 9 revalues `CODEDIRECTORY_VERSION_RUNTIME`/`_LINKAGE` (its own inputs).
- Task 10 then delivers the rest of the constants checklist: `CSSLOT_TICKETSLOT`,
  `CSMAGIC_EMBEDDED_SIGNATURE_OLD` (+ diagnostic message), `CSMAGIC_LAUNCH_CONSTRAINT`
  (+ magic-table entry for `0x0008..0x000b`), special slots −8..−11 (+ adoption in
  `check_special_slots`), version-gate docs, constants tests.

This keeps every commit green, introduces no dead constants at any point, and leaves
the final tree containing every constant the brief's item 10 lists.

## Interop-gate risk register

`scripts/verify-apple-interop.sh` (macOS CI, not part of the scoped cargo gate) runs
`zsign -V` and requires `verified: yes` for our cert bundle, our ad-hoc bundle,
`/bin/ls`, and codesign ad-hoc output; and requires *no* `verified: yes` for a tampered
control. **Pre-existing status: the cert-signed-bundle line (`:191`) is already red at
c9ff0fb** — the script's self-signed certificate (`:58-64`) can never satisfy the
production Apple-root anchoring (`crypto/cms_verify.rs:281-288`) that the dual-pin
design intentionally enforces (`zsign/src/verify.rs:135-138` makes the facade
error-sensitive). Out of scope; escalated below. The lane's acceptance bar is therefore
*no new failures* on the other four lines. Per-rule analysis:

| Rule | Our output | `/bin/ls` / codesign ad-hoc |
|---|---|---|
| slot elevation (context-split) | bound slots always have content in fixtures | −2 self-consistent; −1/−3 NOT elevated when `SignatureInputs::none()` (standalone = facade's message, zero core delta — strictly safer than the original blanket rule); −4/−6 excluded |
| execSeg range | exact vm-pair match (branch 1) | file-space plausibility fallback (branch 2, ≥0x1000 floor) — NOT sound enforcement; see BLOCKED note §7 |
| unknown execSeg bits | `0x1`/`0x11` ⊂ mask | `/bin/ps` sample: `0x1` ⊂ mask |
| MAIN_BINARY ⇔ executable | signer sets iff `MH_EXECUTE` | same per Apple source |
| entitlement subset checks | ALLOW_UNSIGNED only ever with get-task-allow | no such flags on `/bin/ls` |
| DER compare / DER-required | fixtures carry no entitlements; entitlement fixtures emit both (bound) | `/bin/ls` has both, semantically equal — decoder accepts the repo's `0x70`/`0xb0` v1 form plus no-envelope v0 (accepted risk, fail-closed on decode error) |
| DR evaluation | empty set → pass | ad-hoc: identifier/`opCDHash` evaluable; any other opcode → whole-DR `Unsupported` → warning, never error |
| version reject `>0x20600` | `0x20400` | `/bin/ls` ≤ `0x20600` (hardened `0x20500`-class; a hypothetical `>0x20600` Apple CD would be rejected — accepted strictness, flagged) |

Residual risks accepted and reported: DER decoder fidelity against Apple's real-world
DER on the macOS runner; execSeg file-space branch is plausibility-only (exact
enforcement BLOCKED on parser exposure — §7).

## Design-decisions record (with source citations)

Brainstorm alternatives and their rejections are inlined per item above ("Rejected:").
External facts, each source-verified by the librarian pass (full fact sheet:
`agent://AppleContractLibrarian/answer`; sources: apple-oss-distributions/Security
headers incl. `blob.h`/`requirement` reader, xnu, ld64, Apple TN3126/TN3127/TN2206,
codesign(1)/csreq(1), apple-platform-rs/ipsw/go-macho/darwinscope; header offsets
computed by compiling Apple's own struct and printing `offsetof`):

- Header sizes 44/48/52/64/88/96/**108** at gates `0x20001…0x20600`; `sizeof==112` is
  compiler padding (brief's 112 corrected).
- `signingLimit() = (version ≥ 0x20300 && codeLimit64 != 0) ? codeLimit64 : codeLimit`.
- scatter = run-list `{count, base, targetOffset, spare}`; Apple validates bounds only;
  `Builder::scatter()` has no callers in the OSS drop → unsupported-feature reject.
- `preEncryptOffset` points at a parallel plaintext-page hash array → nonzero makes
  on-disk pages legitimately differ from stored hashes → reject.
- linkage = single 20-byte truncated cdhash at `linkageOffset` (no trailing table,
  no `nLinkageSlots`).
- `CSSLOT_TICKETSLOT = 0x10002`; `0x10001` = cd-identification slot.
- `CSMAGIC_EMBEDDED_SIGNATURE_OLD = 0xfade0b02` (purpose `/* XXX */` → diagnostic only);
  `kSecCodeMagicLaunchConstraint = 0xfade8181` covers all four constraint blobs.
- CMS is detached over the **primary** CD's declared bytes; primary = SHA-1 CD when
  present. v1 = `[SHA1(SHA-1 CD), SHA256(SHA-256 CD)[..20]]` for dual (exact
  CFEqual list required by Apple's verifier). v2 = SET of `AgileHash {OID, value}`
  per CD — our single-value verifier (crypto layer, out of scope) is a deliberate
  simplification; the fix must not demand a SHA-1 AgileHash entry.
- Requirements: `kind == exprForm(1)`; opcodes `u32 BE` with high-byte flags; `opAnd/
  opOr` binary; strings `u32 len` + bytes, 4-aligned, no NUL; Apple's own evaluator
  fails unknown zero-flag opcodes categorically; bounded recursion via stack limit. We
  deliberately deviate for unknown/unsupported opcodes (whole-DR `Unsupported` →
  warning, §8) because cert-chain operands are unreachable in-scope. DR may be absent →
  Apple synthesizes a default we cannot rederive → absence passes.
- execSegBase/Limit = `__TEXT` **fileoff/filesize** (both 0 when `platform()==0`);
  entitlement derivations ALLOW_UNSIGNED ⇐ get-task-allow OR run-unsigned-code, JIT ⇐
  dynamic-codesigning, DEBUGGER ⇐ com.apple.private.cs.debugger, SKIP_LV ⇐
  com.apple.private.skip-library-validation; enforcement of execSeg bits lives in
  closed AMFI/PPL (zero callers in OSS) → self-consistency + subset rules only.
- DER entitlements: v1 `[APPLICATION 16]{INTEGER version, entries}` where entries is a
  set of `SEQUENCE {UTF8String key, value}`; v0 = the entries set without the envelope;
  inner dictionary tag disputed across sources (`0x30/0x31/0x60/0xA0`, and the repo
  encoder emits `0xb0`) → tag-agnostic walk; key order non-normative →
  order-insensitive compare; the repo encoder (`codesign/der.rs:258-276`, tests
  `:348-369`) emits the **v1 `0x70`/`0xb0` form** (its "sorted keys" doc claim is
  false — `plist::Dictionary` is IndexMap-backed, `sort_keys` never called).
- Apple's own verifier rejects `version > compatibilityLimit (0x2F000)` or `< 0x20001`
  and only *logs* newer-than-current versions → our `> 0x20600` reject is documented
  stricter-than-Apple policy.

## Findings for the supervisor (not this lane's scope)

1. **Signer execSeg convention divergence**: `signer.rs:825-826` writes `__TEXT`
   vmaddr/vmsize into `execSegBase/execSegLimit`; Apple writes fileoff/filesize
   (librarian). `codesign --verify` does not enforce either (zero OSS callers), which
   is why the interop gate's codesign steps pass today. The verifier accepts both
   forms (design §7); fixing the signer belongs to ZSN-32/33/34.
2. `codesign/der.rs::plist_to_der` doc claims sorted keys; the encoder preserves XML
   document order (IndexMap, no `sort_keys`) and errors on Data/Date/Real values that
   Apple v1 DER uses. Cosmetic/docs; `codesign/der.rs` is out of scope.
3. `zsign/src/verify.rs` will show duplicate messaging for slots −1/−3 (core error +
   ZSN-26's message) once task 3 lands; harmless (`.any()` assertions), removable only
   by editing a file this lane may not touch.
4. **QUESTION 1 (interop cert line).** `scripts/verify-apple-interop.sh:191`
   `agree_valid "cert-signed bundle"` requires `zsign -V` → `verified: yes` on a bundle
   signed with the script's self-signed certificate, but production verification is
   hard-anchored to Apple's root, so this line is red at c9ff0fb and will stay red
   regardless of this lane. Options: (a) leave it red and let the script/crypto owner
   reconcile it (e.g. script injects a test anchor or asserts the dual-pin form) —
   default, what this lane assumes; (b) authorize a follow-up lane to edit the script;
   (c) authorize `crypto/cms_verify.rs` to expose an anchor-injection flag for the CLI.
   The lane proceeds under (a) and reports the line honestly.
5. **QUESTION 2 (execSeg exact range).** Sound `execSegBase/execSegLimit` enforcement
   against `__TEXT` requires `macho/parser.rs` to expose `__TEXT` fileoff/filesize
   (outside this lane's three-file scope; `ArchSlice` carries only vmaddr/vmsize).
   Options: (a) accept the in-scope plausibility fallback (exact vm-pair match +
   bounded file-space check with a 4 KiB floor) — default; (b) authorize a follow-up
   to add `text_segment_fileoff`/`text_segment_filesize` to `parser.rs` and tighten
   the check to exact equality; (c) reject every non-vm-pair range now (breaks the
   `/bin/ls` interop line). The lane proceeds under (a); design §7 labels the fallback
   explicitly as not-sound.

## Known items

Round 1 (NOT-READY, 16 findings) — all applied in commit `6566c71`.

Round 2 (NOT-READY) — the adjudication rule applied: every finding classified
**doc/nit** (each is a defect in document text/snippets/expectations/citations that
resolves by editing the docs; the designed logic they contradict is already correctly
specified in the same documents — no control-flow, error-channel, match-arm,
panic-path, or bounds-check decision in the design itself changed). All findings are
recorded verbatim below and were applied alongside this record before implementation:

1. "F9 NOT-LANDED/partial: policy landed design 138-146, plan 340-380, but test at
   plan 326 expects alternate SHA-1 while dual output alternate is SHA-256 (signer
   286-315; superblob 544-559); fix label." → APPLIED: label corrected to
   `alternate SHA-256` with the routing rationale in the test comment.
2. "F13 NOT-LANDED/partial: digest/synthetic CD landed plan 748-774,1649-1650, but
   snippet line 778 references CSMAGIC_LAUNCH_CONSTRAINT before task10 (defer
   statement 798-799); compile failure." → APPLIED: snippet uses the `0xfade8181u32`
   literal with the task-10 swap note inline.
3. "(1) logic-level plan 154-161 retains `return Ok(report)` on missing SHA-256,
   contradicting plan 1327/design 165-170 no-early-return; can skip DR on that CMS
   path." → APPLIED: task-1 snippet rewritten as a `match cd_sha256_opt` branch with
   full error handling and no return; task 8 now carries explicit three-step edit
   instructions plus the no-early-return invariant.
4. "(2) logic-level Task1 `cdhash_pair` uses Sha256 at plan 143, but production
   macho/verify.rs top imports only Sha1; no import instruction, compile failure." →
   APPLIED: task 1 instructs adding `use sha2::{Digest, Sha256};` to production
   imports.
5. "(3) doc-nit stale design 158 says pair after empty-wrapper early return,
   contradicts revised branch/fallthrough." → APPLIED (design ~160).
6. "(4) doc-nit plan 421-422 code comment includes ZSN-24 ticket ID, violating brief
   no ticket IDs in proposed code comments." → APPLIED: comment reworded to
   `pairwise-overlap check`.
7. "(5) doc-nit plan 1282-1284/163 retain `/* ... */` placeholder comments despite
   self-review claim; named helpers are complete." → APPLIED: public-surface struct
   sketches now carry real fields; task-1 error handling written out;
   `push_page_errors` signature made concrete.
8. "(6) doc-nit plan 810-817 says 326/32=10 but primary is SHA-1 (20-byte) in dual
   fixture; comment only, test still lands bytes." → APPLIED: comment corrected to
   the SHA-1 arithmetic (`hashOffset = 242`, `8 <= 12`, window `[82, 102)`).
9. "(7) doc-nit design 69 cites macho/verify.rs:686 (actual 678-679), design 52/616
   script :190 (actual 191), design 33 signer lines 798-801 (requirements actually
   793-797/822-823)." → APPLIED to all three citation sites.

Reviewer's overall verdict line: "Overall NOT-READY due F9/F13 + NEW logic issues; if
adjudication treats only landed fixes, F9/F13 NOT-LANDED means not ready."

**Post-adjudication steering (terminal — no round 3) — supervisor classified ALL
remaining round-2 items doc/nit; applied with this revision. Verbatim findings and
dispositions carried into the final report:**

- wasm32 bounds (reviewer addendum, bounds-check class): "plan task 9's
  `cd.effective_code_limit() as usize` truncates u64 >4GiB on 32-bit targets
  (zsign-wasm is wasm32), which can route around the oversize guard; 64-bit tests can
  never catch it." → **DISPOSITION:** plan task 9 amended to compare in `u64` before
  any cast (`limit > code.len() as u64` guard, cast only after the value is proven to
  fit); design §9 records the invariant; regression case added to
  `linkage_fields_are_bounds_checked`.
- linkage overflow (reviewer addendum, panic-path class): "`linkage_offset + 20 <=
  declared` with u32 offset; `linkage_offset = u32::MAX` overflows (debug panic,
  release wraparound possible acceptance). Use checked_add/u64 comparison." →
  **DISPOSITION:** both design §9 and plan task 9 now compare in `u64`; `u32::MAX`
  case added to the linkage test.
- `Expr::Unsupported` marker (reviewer addendum, type-sketch class): the grammar
  requires whole-DR `Unsupported` but the listed `Expr` variants carried no marker →
  **DISPOSITION:** `Expr::Unsupported(String)` added with parser-storage and
  evaluator-mapping semantics.
- Supervisor advisories weighed (applied): strongest-CD metadata with CMS content
  pinned to the primary (item-1/item-2 split); context-gated −1/−3 elevation with
  unconditional SuperBlob-sourced slots (item-3 read-only-facade constraint:
  `SignatureInputs::none()` keeps bound −1/−3 `NotChecked` and the facade message
  alive); `-p zsign-rs` package id; task-10 Files list includes `macho/verify.rs`.
- Supervisor advisories weighed (NOT adopted, rationale): "unsupported-opcode policy
  as explicit reject" for the DR evaluator — the warning policy was reviewed and
  blessed because the interop gate's `/bin/ls` DR carries certificate-chain ops whose
  chain DER `crypto/cms_verify.rs` does not expose (design §8); "execSeg range
  mismatch → WARNING, never error" — the design's file-space branch accepts the cited
  Apple sample (`Base 0x0, Limit 0x8000`), error fires only when the range matches
  NEITHER convention (design §7), and this was reviewed as F11.
