# Bundle/CodeResources Verify Fail-Opens — Design (ZSN-26)

Status: implemented by lane 26 (branch `zsn-26-bundle-verify`).
Scope: **`crates/zsign/src/verify.rs` and its inline tests only.** Everything else is
explicitly deferred (see "Out of scope").

## Problem

`zsign -V` over-reports validity. Nine fail-open defects in the bundle verifier, each
independently enough to let a missing, tampered, or malformed bundle verify as valid:

1. **Hard-error fail-open.** `verify_bundle("missing.app")` returns `Ok` with a
   default-valid empty report: the `WalkDir` root error is swallowed by
   `filter_map(|e| e.ok())` (verify.rs:267, :456) and `read_opt` collapses every I/O
   error to `None` (verify.rs:368-370).
2. **CodeResources optional.** `BundleVerification::valid()` maps
   `code_resources: None` to `true` (verify.rs:93-97), so a missing/unreadable
   `_CodeSignature/CodeResources` at an app/framework root counts as absent rather
   than invalid.
3. **Nested bundles never checked.** `inside_nested_bundle` is evaluated against the
   *app root* path during recursion (verify.rs:276, :282), so inside a nested frame's
   own walk every file still contains a bundle-dir component → nested frame binaries
   never enter `direct_binaries` and are never Mach-O verified. `nested_dirs` also
   collects deep bundles at every ancestor (verify.rs:271-272) → duplicate
   verification of depth ≥ 2 bundles.
4. **Symlink entries always fail.** Our builder emits files2 symlink entries as
   `{symlink: "<target>"}` with **no** hash fields (zsign-core
   code_resources.rs:444-453); the verifier reads the link target as a regular file,
   finds no hash, reports "sealed without a hash" → every valid symlink makes the
   bundle invalid.
5. **Legacy hash algorithm mismatch.** The digest is always SHA-256 (verify.rs:433)
   regardless of field: an entry carrying only the legacy 20-byte `hash` (SHA-1) can
   only mismatch. The legacy `files` dictionary — which our builder always emits
   (zsign-core code_resources.rs:429) and which is the *only* dict holding root
   `Info.plist`/`PkgInfo` and nested `.DS_Store` — is never read (verify.rs:412-420).
6. **rules/rules2 never applied.** Only hard-coded omissions exist (verify.rs:171-187),
   several dead (`rel.ends_with(".lproj/")` can never match a walked file). Declared
   omit/optional/weight semantics are ignored → e.g. a nested `.DS_Store`
   (dropped from files2 at build, kept in `files`, omitted by rules2 w=2000) is
   reported unsealed. Unknown rule formats are silently ignored instead of errored.
7. **Malformed entries silently skipped.** A non-dict files2 entry hits
   `continue` (verify.rs:429-432) → tamper hides.
8. **Plist-key path traversal.** `bundle.join(rel)` with the plist key verbatim
   (verify.rs:424): `../…` traverses out of the bundle, an absolute key replaces the
   base → arbitrary-file existence + attacker-chosen-hash content oracle.
9. **Unchecked special slots surface as valid.** `verify_macho_file` passes
   `SignatureInputs::none()` (verify.rs:199). Core reports `NotChecked` for a
   **nonzero** declared slot with no content (zsign-core codesign/verify.rs:494-496)
   and `Missing` for zero-filled slots (same file :477-480); `SliceVerifyReport::
   is_valid()` only fails on `Mismatch` (zsign-core macho/verify.rs:160-165). So a
   bundle-signed binary checked bare reports `is_valid()` with slots -1/-3 unverified.

## Research facts the design rests on

All verified against current source (line numbers as of base `ee42c12`).

- **Builder emission (the contract to verify against).**
  - files2 file entry: `{hash: SHA-1 20B, hash2: SHA-256 32B, optional?: true}`
    (`optional` iff path contains `.lproj/`); no other keys.
  - files2 symlink entry: `{symlink: "<target string>"}` plus `optional: true` when
    the path contains `.lproj/` (the flag is inserted outside the if/else,
    zsign-core code_resources.rs:455-457) — but **no** hash fields: hashes are
    computed by the scanner and discarded.
  - legacy `files`: always emitted; symlinks skipped; `.lproj` entries
    `{hash, optional}`; everything else a bare 20-byte SHA-1 `Data` value; root
    `Info.plist`/`PkgInfo` present here (they are dropped from files2 at build,
    zsign-core code_resources.rs:438-439, together with any `*.DS_Store`).
  - `rules` (5 entries) and `rules2` (10 entries) are emitted verbatim from
    `standard_rules()`/`standard_rules2()`; the full known pattern set is pinned in
    "Rules engine" below.
  - Scan excludes only root `_CodeSignature/*` and the frame's main executable by
    exact name; nested bundle contents — including nested
    `_CodeSignature/CodeResources` — are sealed into the parent's dicts; symlinks
    are sealed (target string as the seal).
  - Signing is per-frame self-binding: each frame's main executable is signed with
    *that frame's* Info.plist and CodeResources (zsign ipa/mod.rs:530-587), so nested
    frames become Mach-O-verifiable once item 3 stops skipping them.
- **Core verify semantics.** `SignatureInputs {info_plist, code_resources}` only.
  Slot index → meaning: 0 = -1 Info.plist, 1 = -2 requirements, 2 = -3 CodeResources,
  3 = -4 application (content never available at Mach-O level), 4 = -5 entitlements,
  5 = -6, 6 = -7 DER entitlements. `NotChecked` requires a *nonzero* declared hash
  with content `None`; zero-filled slots read `Missing` (normal, unbound). Bare
  signing leaves -1/-3 zero-filled → `Missing`, so `bare_macho_verifies` never sees
  `NotChecked`.
- **Consumers.** CLI `print_bundle` prints `bundle.errors` (main.rs:359-361) and the
  `CodeResourcesVerification` lists; `lib.rs:59` re-exports only
  `verify_bundle/verify_ipa/verify_macho_file/VerifyReport`; no other reader of the
  report structs exists (no `tests/` dirs; wasm has zero verify consumers).
- **Dependencies.** `sha1` is a first-class dep of the `zsign` crate
  (Cargo.toml:21); `regex` exists nowhere linkable (only inside criterion, a
  dev-dependency of zsign-core) → the rules engine cannot use a regex crate.
- **In-repo error pattern.** Walk failures are mapped as
  `Error::Io(std::io::Error::other(format!("Failed to walk directory: {e}")))`
  (zsign bundle/code_resources.rs:154-158, ipa/archive.rs:225-226).

## Cross-cutting contracts

**C1 — `Err` vs report errors.** Two failure channels, never blurred:

- `Err` = verification *cannot be performed*: root missing/not a directory, any
  `WalkDir` entry error, `Info.plist` unreadable (non-`NotFound` I/O), CodeResources
  unreadable (non-`NotFound` I/O), bare Mach-O file unreadable.
- Report errors (`BundleVerification.errors`, `VerifyReport.errors`) = verification
  *was performed and found problems*: missing CodeResources, malformed/unsupported
  CodeResources content, path-escape keys, unverifiable required slot bindings.

`read_opt` becomes `Result<Option<Vec<u8>>>`: `NotFound → Ok(None)`, any other
I/O error → `Err`. Nothing is swallowed anymore.

**C2 — content-error channel.** All CodeResources *content* problems (missing file at
a bundle root, unparseable plist, missing dictionaries, non-dict/malformed entries,
unsupported rules, path escapes, "sealed without a hash") are pushed as strings into
`BundleVerification.errors` — already printed by the CLI — instead of being smuggled
through `CodeResourcesVerification::unsealed`. After the change the four
`CodeResourcesVerification` lists keep strict meanings:
`mismatched`/`missing` = hash/target state of sealed entries, `unsealed` = an
on-disk file in neither sealed dict and not rule-omitted, `matched` = entries
verified (hash match or symlink-target match). `check_code_resources` gains an
`errors: &mut Vec<String>` parameter and returns `Result<…>` (its disk walk
propagates `Err` per C1).

**C3 — sealed set and hash verification.** The sealed set is the union of `files2`
and legacy `files` keys, with explicit dictionary ownership:

- `files2` is **required** — absent → the content error
  `CodeResources has no files2 dictionary` (owned by the Task 1 channel rework);
  a bundle without it is invalid and no union logic runs.
- `files` is optional — absent simply contributes nothing; present keys not in
  `files2` are verified from `files`.
- Either dictionary *present but not a dictionary* (wrong plist type) → content
  error `CodeResources <key> is not a dictionary`, treated as absent for
  evaluation (the report is already invalid — never a silent fallback).

Per sealed entry, *every* declared hash field is checked with its own algorithm
(`hash2` → SHA-256, `hash` → SHA-1); all present fields must match. `files2` wins a
key collision (its entries carry both algorithms, so SHA-1 is covered anyway);
`files`-only keys are verified with their declared value type. Bare `Data` values
are legal in `files` (SHA-1) and malformed in `files2`.

**C4 — rules engine (no regex crate).** Evaluate **the rules our builder emits**;
anything else is an explicit `unsupported CodeResources rule: <pattern>` report
error — never a silent ignore. Rule source: `rules2` when present, else `rules`;
`rules2` *present but not a dictionary* → content error
`CodeResources rules2 is not a dictionary`, treated as absent for evaluation (the
report is already invalid — no silent fallback); **neither** present → report error
`CodeResources has no rules dictionary`. Semantics per rule value:
`Boolean(true)` → Include, `Boolean(false)` → Omit; dictionary keys restricted to
`{omit, optional, weight}` (both `omit` and `optional` true, or any other key/type →
unsupported error); `weight` default 1.0. Among *matching* rules the highest weight
wins; ties resolve strictest first: Include > Omit > Optional (the builder's own
weights never tie). Path checks:

- disk→sealed: on-disk file in neither dict → Omit rule matches → exempt,
  otherwise `unsealed`.
- sealed→disk: sealed entry absent on disk → tolerated only when the winning rule
  action is Optional; otherwise `missing`. The per-entry `optional` flag (and the
  same key inside legacy `files` entries) is deliberately **not** consulted: our
  builder stamps it on every `.lproj/` path — including `Base.lproj`, which its own
  weight rule (1010 > 1000) declares *required*. Letting the entry flag override
  would make weight precedence unimplementable. One authority: the rules layer.
  Unknown *entry* keys (`size`, metadata from other tools) are ignored — they are
  not rules; unknown rule patterns error per C4.

Structural omissions that no rule can express stay hard-coded in
`is_rule_omitted`: `_CodeSignature` (root prefix/exact) and the frame's main
executable (exact name from its own Info.plist). The obsolete `Info.plist` /
`PkgInfo` / `.DS_Store` / `.lproj` arms are deleted — rules2 covers them
(`^Info\.plist$` w=20, `^PkgInfo$` w=20, `^(.*/)?\.DS_Store$` w=2000,
`^.*\.lproj/` optional w=1000).

Recognized pattern set (translated to plain string predicates — the complete
builder emission, both dicts):

| pattern | predicate |
|---|---|
| `^.*` | always |
| `^.*\.lproj/` | contains `.lproj/` |
| `^.*\.lproj/locversion.plist$` | ends with `.lproj/locversion.plist` |
| `^Base\.lproj/` | starts with `Base.lproj/` |
| `^version.plist$`, `^version\.plist$` | equals `version.plist` |
| `.*\.dSYM($|/)` | ends with `.dSYM` or contains `.dSYM/` |
| `^(.*/)?\.DS_Store$` | equals `.DS_Store` or ends with `/.DS_Store` |
| `^Info\.plist$` | equals `Info.plist` |
| `^PkgInfo$` | equals `PkgInfo` |
| `^embedded\.provisionprofile$` | equals `embedded.provisionprofile` |

If a builder pattern ever changes, verification fails closed with the explicit
unsupported-rule error (coordination point with the builder lane, not a silent gap).

**C5 — symlink semantics.** A sealed entry with a `symlink` key is verified as a
symlink: the on-disk object must be a symlink (`symlink_metadata`) and
`fs::read_link` must equal the sealed target string; no hash is expected either
way. Conversely an entry expecting file content whose on-disk object is a symlink is
`mismatched` (content replaced by a link). The disk→sealed walk includes symlinks
(files *and* symlinks), so an unsealed symlink is flagged like any unsealed file.
Symlinks are skipped by the binary-collection walk: their target is sealed as a
string, and the real target file is verified where it actually lives (also removes
double-verification of macOS-style framework symlink chains).

**C6 — depth-aware nesting.** All membership predicates are evaluated against the
path relative to the *current frame* (`strip_prefix(dir)`), never the root:

- a file is a direct binary of this frame iff no component of its dir-relative path
  names a bundle directory;
- a directory entry is collected for recursion iff it is a bundle dir and no
  *ancestor* component (all but the last) names a bundle dir → each bundle is
  visited exactly once by its immediate owning frame (also kills the depth ≥ 2
  duplicate-collection).

Reported paths keep using `strip_prefix(root)` (documented "relative to the
verified root"). Walk entries use `entry.file_type()` (no-follow) instead of
`Path::is_dir()` (which follows symlinks).

**C7 — required slots.** In bundle context, any signed slice whose special slot 0
(Info.plist) or 2 (CodeResources) reads `NotChecked` gets a binary-level error —
ungated on file-presence (with C1, `NotChecked` at those indices means the content
file is genuinely absent; a missing CodeResources *also* raises the bundle-level C2
error). In the bare path, `NotChecked` at those indices pushes
`VerifyReport.errors` ("cannot verify … without bundle context") → the report is
invalid rather than silently valid. Indices 3/5 (`-4`/`-6`) are never surfaced:
their content is defined as unavailable at the Mach-O level. Zero-filled slots
(`Missing`) remain silent — unbound is normal.

**C8 — path containment (two stages).** Stage 1, lexical: before any `join`, every
`Path::components()` of the plist key must be `Normal` (rejects `ParentDir`,
`RootDir`, `Prefix`, `CurDir`, and the empty key) → bundle error
`CodeResources entry path escapes the bundle: <key>`, entry skipped. Stage 2,
resolved containment: a lexical-clean key can still traverse an in-bundle symlink
directory (`Escape -> /etc`, key `Escape/passwd`) because `fs::read` and
`fs::read_link` both resolve intermediate links. Before *reading* anything for an
entry, canonicalize the entry's parent directory against `canonicalize(bundle)`:
`NotFound` → the entry is `missing` (no content is read, so no oracle); resolution
outside the bundle → the same escape error, entry skipped; any other I/O error →
content error. Stage 2 runs for **both** dispatch branches (hash reads *and*
symlink target reads — `read_link` resolves intermediate links too). Resolving the
parent instead of an `openat`-style no-follow traversal is a deliberate trade: the
residual TOCTOU window (an attacker mutating the tree *during* verification) is out
of threat model — the tree being verified is read-only to us by contract. Our
builder never emits symlink-traversing keys (both sealing walks use
`follow_links(false)`), so stage 2 only ever fires for crafted keys — exactly the
oracle to close. The disk→sealed direction is inherently safe (keys come from the
filesystem walk, which does not follow links).

## Per-item design decisions (brainstorm record)

Each item lists the chosen design and the rejected alternatives. Decisions were
made internally per the adapted brainstorming skill; no open questions remain.

**1. Hard-error fail-open — chosen: A.** Validate `dir` with `fs::metadata` at the
top of `verify_bundle_dir` (covers `verify_bundle`, `verify_ipa` after extraction,
and every recursive frame): missing → `Err(Io(NotFound))`, non-directory →
`Err(Io(InvalidInput))`. Propagate every `WalkDir` entry error as `Err` in both
walks; `read_opt → Result<Option<Vec<u8>>>` (`NotFound → None`); `is_macho_file →
Result<bool>` (open `NotFound → Ok(false)`, other I/O → `Err`) so an unreadable file
at bundle root cannot be silently skipped as "not a Mach-O".
*Rejected:* (B) root validation only — an unreadable subtree stays invisible, the
fail-open survives at depth; (C) walk errors as report errors — the brief mandates
`Err`, and a missing root has no report to attach to.

**2. CodeResources required — chosen: A.** Every `verify_bundle_dir` frame *is* a
bundle root by construction, so `read_opt(CodeResources)` `None` (only `NotFound`
after item 1) → `out.errors.push("missing _CodeSignature/CodeResources")`; an
unreadable CodeResources surfaces as `Err` per C1 (an explicit hard error, stronger
than "invalid", still never silently valid). `code_resources` stays `None` there —
`BundleVerification.errors`, not the vacuous `unwrap_or(true)`, carries validity.
*Rejected:* (B) top-app-root only — the brief says app *and framework* roots;
(C) treat "no `_CodeSignature` dir" as acceptable unsigned state — the brief
requires missing = invalid.

**3. Depth-aware nesting — chosen: A (C6).** Dir-relative predicates for both files
and collected bundle dirs; report paths unchanged; `entry.file_type()` no-follow.
*Rejected:* (B) `filter_entry` pruning at bundle boundaries — same observable
behavior, larger rewrite, no correctness gain over A (kept as a possible later
optimization); (C) swapping `root`→`dir` in `inside_nested_bundle` only — deep
bundles would still be collected by every ancestor and verified twice.

**4. Symlink entries — chosen: A (C5).** Both directions, no hash expected for
`symlink` entries; disk walk includes symlinks.
*Rejected:* (B) hash the target string — our builder emits no hash for symlinks,
and target comparison is the seal of record anyway; (C) trust/skip symlink entries —
fail-open, tampered links invisible.

**5. Legacy hash mismatch — chosen: A (C3).** Per-field algorithm selection, all
declared fields must match, legacy `files` dict verified for non-colliding keys.
Verifying *both* fields is deliberately stricter than "prefer hash2": an attacker
who re-seals only `hash2` after tampering still trips the untouched SHA-1.
*Rejected:* (B) length-sniffing (20 vs 32 bytes) — hides malformed entries behind
guesswork, field presence is authoritative; (C) keep ignoring `files` — root
`Info.plist`/`PkgInfo` and nested `.DS_Store` live only there.

**6. Rules — chosen: A (C4).** Full evaluation of the builder's emitted rule set
with weight precedence; explicit unsupported-rule errors for anything else;
hard-coded list reduced to structural omissions only. Missing-tolerance follows the
winning rule only (entry-level `optional` deliberately ignored — see C4).
*Rejected:* (B) table of exact (pattern, spec) pairs with error on any deviation —
unnecessarily brittle: a rule with an unknown pattern but *known structure* still
can't be evaluated soundly without matching, so pattern-level recognition with
structural spec parsing is the honest boundary; (C) keep hard-coded omissions and
only validate that rules parse — the false unsealed/missing behavior survives.

**7. Malformed entries — chosen: A.** Non-dict `files2` value → bundle error
`malformed CodeResources entry: <key>` (C2 channel), entry skipped for hash
checking but the error already invalidates the bundle. Bare `Data` remains legal in
`files` (C3), a `String` value in `files` is malformed (our builder never emits it;
unknown forms fail closed).
*Rejected:* (C) `Err` — this is content corruption, not an I/O failure; the partial
report is useful.

**8. Path traversal — chosen: A (C8, two stages).** Lexical component rejection
before joining, plus resolved-containment of the entry's parent directory before
any read — both stages required (stage 1 alone leaves the symlink-directory oracle
open, which the cold review caught). Applies to `files2` and `files` keys alike.
*Rejected:* (B) lexical check only — explicitly refuted: `fs::read`/`fs::read_link`
resolve intermediate in-bundle symlinks, so `Escape -> /etc` + key `Escape/passwd`
passes a Normal-component check and restores the arbitrary-file oracle (the original
"builder never seals through symlinked dirs" argument only protects *legitimate*
keys, not crafted ones); (C) sanitize/strip the key — verifies the wrong path
silently. A pure `openat`-style no-follow traversal was also considered and
rejected as disproportionate: parent canonicalization closes every read with a
documented, out-of-threat-model TOCTOU window.

**9. Unchecked required slots — chosen: A (C7).** Bundle: ungated binary-level
errors for `NotChecked` at slots -1/-3 (behaviorally the -1 branch exists today via
a redundant gate; the change makes the invariant explicit and covers -3
independently of the item-2 bundle error). Bare: `NotChecked` at -1/-3 →
`VerifyReport.errors` → invalid.
*Rejected:* (B) bare path → warnings only — non-silent but still reports
`verified: yes` while a declared binding went unchecked, which is the defect the
ticket names; (C) flipping `SliceVerifyReport::is_valid` in zsign-core — core verify
internals belong to lanes 23/24 and `NotChecked` is legitimate there.

## Test strategy

Gate for every task (scoped, never project-wide):
`cargo test -p zsign-rs verify -- --skip test_ipa_signing_is_deterministic`
(the filter matches the `verify::tests::*` module path; the skip covers the known
pre-existing ZSN-15 zip-order flake).

Mandated regressions. Five are fail-before-fix tests; **#3 is a documented
guard-test exception** — the brief itself defines it as "existing tests keep
passing", and those tests (`modified_sealed_resource_fails`,
`tampered_resource_fails_code_resources`) already pass at baseline (verified: the
pre-fix gate runs 7/7 green), so they cannot fail before the fix by construction.
Their mandate is keep-green: every task's gate must keep them passing, which it
does — they would catch any change that un-detects sealed-file tampering.

| # | test | pre-fix behavior |
|---|---|---|
| 1 | `verify_bundle("…/missing.app")` → `Err` | FAILS pre-fix: returns `Ok` + default-valid report |
| 2 | signed bundle with framework symlink verifies clean end-to-end | FAILS pre-fix: symlink entry → "sealed without a hash" → invalid |
| 3 | existing tampered-sealed-file tests keep passing | guard exception (see above): passes before and after every task |
| 4 | files2 keys `../../../../etc/passwd`, `/etc/passwd` → rejected | FAILS pre-fix: no escape error; keys silently read outside |
| 5 | missing CodeResources at app root → invalid | FAILS pre-fix: no *bundle-level* error (a binary-level slot error exists today, so the assertion targets `bundle.errors`) |
| 6 | tampered nested `Frameworks/Sub.framework/Sub` → detected *by the nested frame's binary report* | FAILS pre-fix: nested `binaries` is empty (parent files2 already catches raw content edits; the new signal is the Mach-O verification itself) |

Per-item tests: legacy SHA-1-only entry accepted at the CodeResources layer; both
hash fields enforced (partial re-seal detected); nested `.DS_Store` (builder
emission: files2-dropped, `files`-kept, rules2-omitted) verifies clean E2E;
optional `.lproj` entry deleted after signing stays valid while a deleted
`Base.lproj` file (weight 1010 > 1000) stays invalid; injected unknown rule →
explicit unsupported error; non-dict entry → malformed error; bare verify of a
bundle-bound binary → invalid with a slot error; **symlink-parent traversal**
(fixture seals `Escape -> <dir outside the bundle>`, crafted key
`Escape/secret.txt` resolving outside → escape error; fails pre-fix because the
key is read and hash-compared without complaint — the C8 stage-2 regression)**.

Where a test must edit `CodeResources` after signing, that edit also breaks the main
executable's slot -3 binding — so such tests assert at the CodeResources/bundle-error
layer (the precise unit under test), not at `report.valid()`.

## Out of scope (deferred to other lanes — report, do not edit)

- Builder emission gaps (files2/symlink/omission rules): ZSN-39,
  `crates/zsign-core/src/bundle/code_resources.rs`, `crates/zsign/src/bundle/`.
  Coordination note: if builder rule patterns change, C4 fails closed with
  `unsupported CodeResources rule` — that is the designed tripwire.
- Exit-code mapping: ZSN-5, `crates/zsign-cli/src/main.rs`. The CLI already prints
  `bundle.errors`; new content errors are visible without CLI changes.
- CMS/Mach-O verify internals: lanes 23/24, zsign-core.
- IPA extract/mod: lanes 27/28. `.github`: lane 31.
- Observed but unowned here: `IPA` signer's silent skip of a missing main executable
  and its `code_resources_data: None` fallback (builder-side fail-opens, ZSN-39
  territory); `VerifyReport::valid()`'s vacuous `None → true` arms (unreachable:
  every entry point sets exactly one of `macho`/`bundle`).
