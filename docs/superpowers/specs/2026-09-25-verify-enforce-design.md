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
- "bare signing can leave the vector length 2": real builder minimum is `n_special = 3`
  (`code_directory.rs:501-535`, test `:772-779`); n=2 exists only in hand-synthesized
  test blobs. Unaffected: the rule keys on nonzero stored hashes, not on vector length.
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
4. Existing tests and the macOS interop gate (`scripts/verify-apple-interop.sh`
   `agree_valid` on our cert bundle, our ad-hoc bundle, `/bin/ls`, and codesign ad-hoc
   output) stay green.

## Frozen contracts (must not break — compiled from the consumer map)

- **C-1** `PageCheck` variant set and field names are exhaustively matched in
  `crates/zsign-cli/src/main.rs:234-243, 326-335`. No add/remove/rename.
- **C-2** `SpecialSlotCheck` variant set exhaustively matched at
  `crates/zsign-cli/src/main.rs:275-281`. No add/remove/rename.
- **C-3** `SliceVerifyReport.special_slots` stays positional, length == `n_special_slots`,
  with `NotChecked` entries at index 0 (slot −1) and 2 (slot −3):
  `crates/zsign/src/verify.rs:354-366, 496-509` compare `== Some(&NotChecked)`; test
  `macho/verify.rs:686` asserts all-`Matched` for the supplied-input fixture.
- **C-4** `verify_macho`/`verify_slice` must return `Ok(report)` for a parseable Mach-O
  with a broken signature: `crates/zsign/src/verify.rs:348` `?`-propagates, tests
  `:1090/:1239/:1253` unwrap. Signature findings = `report.errors.push(...)`.
- **C-5** `SignatureInputs` keeps exactly the fields `{info_plist, code_resources}`
  (full literal at `crates/zsign/src/verify.rs:483-486`); `verify_macho` signature frozen;
  `parse_superblob` keeps `Result<SuperBlob>` (doctest `codesign/verify.rs:20-26`).
- **C-6** `verify_macho`, `SpecialSlotCheck`, `PageCheck`, report structs, `SuperBlob`,
  `SlotEntry`, `CodeDirectory` pub members are published through the `zsign` facade
  (`zsign/src/lib.rs:49`) — changes are allowed only with in-workspace migration;
  downstream semver impact is out of lane scope and noted in the report.
- **C-7** Constants in the "USED" set (see plan) keep name and value; the whole constants
  module is published via the facade.

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
- **All CDs verified, primary reports.** `parse_superblob` errors on any CodeDirectory
  slot child that fails to parse (primary and alternates). `verify_slice` runs
  page-check + special-slot-check for *every* emitted CD; `report.pages`,
  `report.special_slots`, `report.identifier`, `report.adhoc` keep reflecting the
  primary CD (C-3; existing tests pin primary-patched fixtures). Alternate-CD findings
  are error strings tagged with the CD's hash type, e.g.
  `alternate SHA-256 code page 3 hash mismatch (code region modified?)`.
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
- **Elevation rule (item 3)** lives in `macho/verify.rs` where errors are owned (C-4):
  after `check_special_slots`, `NotChecked` at `k ∈ {1,2,3,5,7} ∪ {8,9,10,11}` pushes
  `special slot -{k} is bound but its content was not supplied`. `Mismatch` at any `k`
  keeps pushing `special slot -{k} hash mismatch` (existing string, pinned at
  `macho/verify.rs:690`). `Missing` (stored hash all-zero = not bound) stays silent —
  this is how the rule self-scopes to "what the signer actually binds" (dylibs never
  bind −1/−3; bare signing zero-fills them).
- **CDHash pair by emitted type (item 1)**, private helper in `macho/verify.rs`:
  `cd_sha1 = SHA1(bytes of the SHA-1 CD among {primary} ∪ alternates)`,
  `cd_sha256 = SHA256(bytes of the SHA-256 CD)`, CMS `content` stays `primary.raw()`.
  `cd_sha1 = None` when no SHA-1 CD exists (sha256-only → v1 single-element arm, current
  behavior). No SHA-256 CD while a non-empty CMS is present → explicit error
  (cannot verify CDHash v2). Only computed inside the non-ad-hoc branch (after the
  empty-wrapper early return), so ad-hoc output never hits it. `alternate_sha1` is
  deleted (only caller is the site being rewritten).
- **Requirements evaluation (item 8)**: bounded parser in `codesign/verify.rs`
  (Requirements SuperBlob `0xfade0c01` → typed index → requirement blob `0xfade0c00`
  with `kind == exprForm(1)`; `lwcrForm(2)` rejected), expression tree with bounded
  recursion, Kleene three-valued evaluator. `macho/verify.rs` wires it after the CMS
  branch (restructured so the ad-hoc path no longer early-returns before it):
  `Violated` → error, `Unsupported` → warning `designated requirement not fully
  evaluated: <reason>`, empty/absent designated requirement → pass.
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
anchoring error, `cdhash_v1_ok && cdhash_v2_ok`; injected anchors → `valid`.

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
  and extended for Apple's shapes: v1 envelope `[APPLICATION 16]{INTEGER version, dict}`
  (macOS 12+) and v0 bare `SET OF KeyValuePair` (Big Sur … macOS 14); dictionary
  container handled tag-agnostically (0x30/0x31/0x60/0xA0 walked as pairs) because
  sources disagree on the inner tag; values map `NULL|BOOLEAN|OCTET STRING|GeneralizedTime|
  SEQUENCE|array|UTF8String|INTEGER|nested dict` onto `plist::Value` (`Data`/`Date`
  supported — Apple v1 uses them). Unmappable or malformed DER → `Err` → error
  (fail-closed; our own encoder can only emit values the decoder handles).
  XML parsed with `plist::from_bytes`; parse failure → error. Dictionaries compared
  with `Value` equality (order-insensitive: `plist::Dictionary` is IndexMap-backed and
  `sort_keys` is never called by the encoder — key order is document order, NOT
  normative, so the comparison must not depend on it). Rejected: re-encoding XML via
  `plist_to_der` and byte-comparing (byte order equals *our* XML order only; third-party
  encoders would false-mismatch).
- **DER requirement:** error when slot −5 is bound, −7 is absent/unbound, the slice is
  an executable (`slice.is_executable`), and the primary CD version ≥
  `CODEDIRECTORY_VERSION_EXECSEG` (`0x20400`):
  `XML entitlements bound (slot -5) without DER entitlements (slot -7)`.
  Scoped exactly this way because the signer emits DER only for executables
  (`signer.rs:85-93`) and dylibs legitimately bind −5 without −7
  (`EMPTY_ENTITLEMENTS`, `signer.rs:166-176`) — a blanket rule breaks
  `zsign`'s `signed_bundle_verifies` (`errors.len()==1` pins on the framework binary).
  Apple TN3126 backs the main-executable rule ("re-sign your app to include the new
  DER entitlements").

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
     convention (`signer.rs:825-826` passes `__TEXT` **vmaddr/vmsize**);
  2. file-space form `base <= slice.size && limit <= text_segment_size &&
     base + limit <= slice.size` → OK — Apple writes `__TEXT` **fileoff/filesize**
     (librarian: Security source + `/bin/ps` sample `Base 0x0 Limit 0x8000`; ld64
     `textSeg.Offset/Filesz`). The in-scope parser does not expose `__TEXT`
     fileoff/filesize (`parser.rs` keeps vmaddr/vmsize only and `first_segment_offset`
     skips `fileoff == 0`), so exact file-convention equality is not computable without
     touching `parser.rs` (out of scope) — the file-space form is the strongest sound
     check available and still rejects any vm-space tampering;
  3. otherwise → error `executable segment range 0x…+0x… does not match __TEXT`.
  Known limitation (documented): with `base == 0` a tampered-but-small `limit` below
  `vmsize` is not detectable; parser-level fileoff/filesize exposure is the follow-up.
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
NUL (librarian, from Apple's requirement reader). Bounded recursion; structural
malformation (truncation, unknown count extent, `kind != 1`) → `Err` (hard error),
matching Apple's `errSecCSReqUnsupported`/`errSecCSReqInvalid` posture. Any other
opcode (including flagged generic forms) parses to `Unknown` — it does not abort
structure parsing but makes evaluation unsupported.
Evaluator (Kleene `{T,F,U}`): `Violated` (result F) → error
`designated requirement not satisfied`; `Unsupported` (result U) → warning
`designated requirement not fully evaluated: opcode <n>` (must stay a warning — the
interop gate's `/bin/ls` DR uses `anchor apple generic` + certificate-policy ops whose
cert chain DER is not exposed by `crypto/cms_verify.rs`, which is out of scope);
no designated entry in the set → pass (our signer always emits the count=0 empty set —
`signer.rs:76-82` — so no self-output regression; Apple synthesizes a default DR that
cannot be re-derived here). Context: `identifier` from the primary CD; `cdhashes` =
truncated (`min(len,20)`) digest of *each* emitted CD (its own hashType) for `opCDHash`;
anchors map to `CmsVerifyReport.anchored` when a CMS report exists, `U` for ad-hoc.
Cert-dependent opcodes (`opCertField`, `opCertGeneric`, `opTrustedCert(s)`,
`opCertPolicy`, `opAnchorHash`, `opInfo*`, `opEntitlementField`, `opNotarized`,
…) → `U` (warning). Rejected: strict unsupported→error (would fail every real Apple DR
and the interop gate); full cert-aware evaluation (needs `crypto/cms_verify.rs` edits —
explicitly deferred to ZSN-3).

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
  `effective_code_limit() -> u64`; `check_code_pages`/`check_code_pages_in_file` switch
  to it (`signingLimit()` semantics: `version ≥ 0x20300 && codeLimit64 != 0`).
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
  `linkage_size == 0` → absent; `linkage_size == 20 && linkage_offset + 20 <= data.len()`
  → structural OK (linkage is a single truncated cdhash pointing outside this
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
  `CSSLOT_SPECIAL_LIBRARY_CONSTRAINT = -11` → adopted in `check_special_slots`'s
  whitelist and content map (replacing the numeric literals introduced by tasks 3/6).

## Invariants

1. `verify_macho(data, &inputs)` returns `Ok` for any parseable Mach-O; all signature
   findings are strings in `report.errors` (C-4). Parsers (`parse_superblob`,
   `CodeDirectory::parse`, requirements parse) may `Err`; `verify_slice` converts.
2. `special_slots` vector: length == `n_special_slots`, positional, `NotChecked`
   constructible (C-1..C-3). Primary CD drives `pages`/`special_slots`/`identifier`/
   `adhoc`.
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
54 passed / 0 failed at c9ff0fb.)

Every queue item gets a failing-first regression (Tester writes, implementer greens),
inline in the scope files per repo convention:

1. dual sign→verify round trip (`sign_macho` + credentials): production errors == 1
   (`not anchored`), `cdhash_v1_ok && cdhash_v2_ok`, injected anchors → `valid`.
2. corrupt alternate CD magic → error carries parse detail; tampered alternate page
   hash → `alternate SHA-256 code page …` error; primary messages unchanged.
3. ad-hoc fixture signed with `info_plist`, verified with `SignatureInputs::none()` →
   `special slot -1 is bound but its content was not supplied`; zero-hash (unbound)
   slots stay silent (existing bare fixtures).
4. requirements child magic patched → `parse_superblob` `Err`; distinct-content
   duplicate `0x0002` → `Err`; truncated-CMS fixture still reaches the
   `empty CMS wrapper` rule.
5. decoder unit: `xml → plist_to_der → decode == xml` round trip, synthetic Apple-v1
   envelope, order-insensitive dict equality; e2e: DER value byte flipped + `-7` hash
   recomputed → `XML and DER entitlements dictionaries differ`; slot type `0x0007`
   rewritten + `-7` hash zeroed → missing-DER error on an executable; dylib-shape
   fixture (no DER) unaffected.
6. content-map unit: superblob slot `0x0008` present → `Some(blob)`; e2e: `n_special`
   patched `7 → 8` (deterministic nonzero stored hash from the header/ident bytes that
   enter the grown window; no panic — `hash_offset/hash_size` stays ≥ 8) with no
   constraint child → `special slot -8 is bound but its content was not supplied`.
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
control. Per-rule analysis:

| Rule | Our output | `/bin/ls` / codesign ad-hoc |
|---|---|---|
| slot elevation (whitelist) | bound slots always have content in fixtures | −2 self-consistent; −1/−3 unbound for CLI tools (and if bound, `zsign`'s own standalone check already fails today — no delta); −4/−6 excluded from whitelist |
| execSeg range | exact vm-pair match | Apple file-space form accepted (base 0, limit ≤ vmsize, within slice) |
| unknown execSeg bits | `0x1`/`0x11` ⊂ mask | `/bin/ps` sample: `0x1` ⊂ mask |
| MAIN_BINARY ⇔ executable | signer sets iff `MH_EXECUTE` | same per Apple source |
| entitlement subset checks | ALLOW_UNSIGNED only ever with get-task-allow | no such flags on `/bin/ls` |
| DER compare / DER-required | fixtures carry no entitlements; entitlement fixtures emit both | `/bin/ls` has both, semantically equal — decoder must parse Apple v0/v1 (accepted risk, fail-closed on decode error) |
| DR evaluation | empty set → pass | ad-hoc: identifier/opCDHash evaluable; anchor/cert ops → warning, never error |
| version reject `>0x20600` | `0x20400` | `/bin/ls` ≤ `0x20600` (hardened `0x20500`-class; a hypothetical `>0x20600` Apple CD would be rejected — accepted strictness, flagged) |

Residual risks accepted and reported: DER decoder fidelity against Apple v1 on the
macOS runner; execSeg range file-space form is plausibility-only (parser does not
expose `__TEXT` fileoff/filesize).

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
  opOr` binary; strings `u32 len` + bytes, 4-aligned, no NUL; unknown zero-flag opcode
  fails evaluation categorically; bounded recursion via stack limit. DR may be absent →
  Apple synthesizes a default we cannot rederive → absence passes.
- execSegBase/Limit = `__TEXT` **fileoff/filesize** (both 0 when `platform()==0`);
  entitlement derivations ALLOW_UNSIGNED ⇐ get-task-allow OR run-unsigned-code, JIT ⇐
  dynamic-codesigning, DEBUGGER ⇐ com.apple.private.cs.debugger, SKIP_LV ⇐
  com.apple.private.skip-library-validation; enforcement of execSeg bits lives in
  closed AMFI/PPL (zero callers in OSS) → self-consistency + subset rules only.
- DER entitlements: v1 `[APPLICATION 16]{INTEGER version, dict}`, v0 bare
  `SET OF {UTF8String key, value}`; inner dictionary tag disputed across sources →
  tag-agnostic walk; key order non-normative → order-insensitive compare; repo encoder
  emits v0 (its "sorted keys" doc claim is false — `plist::Dictionary` is
  IndexMap-backed, `sort_keys` never called).
- Apple's own verifier rejects `version > compatibilityLimit (0x2F000)` or `< 0x20001`
  and only *logs* newer-than-current versions → our `> 0x20600` reject is documented
  stricter-than-Apple policy.

## Findings for the supervisor (not this lane's scope)

1. **Signer execSeg convention divergence**: `signer.rs:825-826` writes `__TEXT`
   vmaddr/vmsize into `execSegBase/execSegLimit`; Apple writes fileoff/filesize
   (librarian). `codesign --verify` does not enforce either (zero OSS callers), which
   is why the interop gate passes today. Verifier accepts both forms (design §7);
   fixing the signer belongs to ZSN-32/33/34.
2. `codesign/der.rs::plist_to_der` doc claims sorted keys; the encoder preserves XML
   document order (IndexMap, no `sort_keys`) and errors on Data/Date/Real values that
   Apple v1 DER uses. Cosmetic/docs; `codesign/der.rs` is out of scope.
3. `zsign/src/verify.rs` will show duplicate messaging for slots −1/−3 (core error +
   ZSN-26's message) once task 3 lands; harmless (`.any()` assertions), removable only
   by editing a file this lane may not touch.

## Known items

(Reserved for the cold-review adjudication rule: findings from a NOT-READY re-review
that are doc/nit-level and were authorized to proceed verbatim. Empty at round 1.)
