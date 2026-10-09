# Enforce Designated Requirement Strictness — Design

## Problem

Two verify-side gaps let a tampered or unverifiable binary ride to
`valid: true` / CLI exit 0.

1. **Unevaluable designated requirements (DR) are recorded as warnings.**
   `verify_slice` evaluates the DR (`crates/zsign-core/src/macho/verify.rs:448-493`)
   and maps the verdict at :480-488: `Violated` → `errors`,
   `Unsupported(why)` → `warnings` (:484-486). `SliceVerifyReport::is_valid()`
   is `errors.is_empty()` (:62-64), so a DR the evaluator cannot decide never
   fails verification. The evaluator implements only 9 of Apple's 24 opcodes —
   its parse dispatch (`crates/zsign-core/src/codesign/verify.rs:401-431`)
   handles ops 0, 1, 2, 3, 6, 7, 8, 9, 15; every other op collapses to
   `Expr::Unsupported` via the catch-all at :429 — exactly ops 4, 5, 10-14,
   16-23 (15 opcodes; 12 predicate families: `anchorHash` (1), `infoKeyValue`
   legacy (1), `infoKeyField` (1), `certField` (1), `trustedCert` +
   `trustedCerts` (2), `certGeneric` (1), `entitlementField` (1), `certPolicy`
   (1), `namedAnchor` + `namedCode` (2), `platform` (1), `notarized` (1),
   `certFieldDate` + `legacyDevID` (2)). The security predicates that
   real Xcode/Developer ID DRs are built from are precisely the unevaluable
   ones.

2. **The CodeDirectory team identifier is never bound to the signer.**
   `CodeDirectory::team_id()` (`codesign/verify.rs:782-784`) is parsed but its
   only consumer is the cross-CD agreement check (`macho/verify.rs:533`). The
   CMS report exposes only flattened strings — `signer_subject`,
   `signer_serial`, `chain` (`crypto/cms_verify.rs:296-325`) — no
   organizational unit, so a CD claiming team A while signed by team B
   verifies without comment. The extractor already exists:
   `extract_team_id` (`crypto/cert.rs:924-929`, subject OU) but is private
   and never reaches the verify path.

### Measured baseline (current source, `fix/designated-requirement` @ f928eba)

Fixture: `make_minimal_macho` + `sign_macho_adhoc`; DR spliced with the
existing `replace_requirements_child` helper; identifier tamper rewrites the
CD identifier string in place (all CDs, same length).

| # | Scenario | Observed today |
|---|----------|----------------|
| A | DR containing `certField` (op 0x0b) | `valid=true`, `errors=[]`, warning `designated requirement not fully evaluated: opcode 0x0000000b` — **false accept** |
| B | `ident` DR + identifier tampered (all CDs) | `valid=false`, error `designated requirement not satisfied` — already enforced |
| C | no DR + identifier tampered (all CDs) | `valid=true`, `errors=[]`, report shows the attacker's identifier — undetectable: no DR means no ground truth |
| D | unimplemented-opcode DR + identifier tampered (all CDs) | `valid=true`, `errors=[]`, warning only — **the reported identity silently becomes the attacker's** |

Scenario D is the acceptance target; B pins the existing enforcement; C is
excluded with the DR emission work (see Scope boundaries).

## External contract (Apple semantics)

Verified against Apple open-source, man pages, and tech notes:

- `codesign --verify` **does** evaluate the DR: the codesign man page
  (manpagez.com/man/1/codesign) states that verbose verification also checks
  the code "against its own designated requirement"; TN2206 confirms
  ("every program should satisfy its own DR ... `codesign -vv` checks for
  this").
- **Identity binding is not** part of `codesign --verify`. TN2206: "Trust is
  determined by policy ... Each macOS subsystem has its own policy, and makes
  this determination separately." `spctl --assess` simulates Gatekeeper's
  allow/deny; `SecStaticCodeCheckValidityWithErrors` takes an explicit
  requirement and returns typed errors. The ticket's caveat is therefore
  correct and stated plainly: Apple's own static verify defers signer-identity
  trust to other tools — yet it still never lets an undecided DR pass.
- Unknown opcode → Apple's interpreter throws `errSecCSUnimplemented`
  (`reqinterp.cpp` default case: "An unrecognized opcode with zero flag byte
  causes evaluation to categorically fail", `requirement.h`); error -67072
  "code signing feature is unimplemented". There is **no pass path**.
- Exit codes: 0 success, 1 verification failure, 2 invalid arguments,
  3 requirement specified with `-R` not met (codesign man page). Unimplemented
  evaluation is a failed verification operation → exit 1, not a pass and not
  a usage error.
- Tri-state precedent exists (`errSecCSReqFailed` = evaluated-and-failed vs
  other `OSStatus` = could-not-evaluate; `spctl` exit 3 = denial vs 1 =
  operational failure), which is why a machine-readable status field accompanies
  the hard failure below.
- Upstream zsign (zhlynn/zsign) never evaluates a DR: `SlotParseRequirements`
  only hashes/dumps the slot and shells out to `csreq` for display, always
  returning true. There is no upstream behavior to preserve.

## Repository facts (re-anchored against current source)

- DR block: `macho/verify.rs:448-493`; verdict match :480-488; warning
  recording :484-486; `is_valid()` :62-64.
- Warnings never invalidate (pinned by the test at :1597-1601), and the
  bundle/IPA human printer never prints slice warnings at all
  (`crates/zsign-cli/src/main.rs:609-663`) — any design that keeps the finding
  in `warnings` is silent for bundle inputs.
- `SliceVerifyReport` is built with `..SliceVerifyReport::default()`
  (`macho/verify.rs:132-135`) — a new field needs no constructor changes.
- CLI exit contract (`main.rs:474-533`): report valid → 0; else top-level
  `errors.is_empty()` → 1; else 2. Slice errors therefore exit 1 with no
  change to the contract. JSON schema v1 note (`main.rs:747-752`): "renaming
  or removing one is a breaking change" — an added field is additive.
- Own output cannot false-positive on the binding check: the signer takes the
  CD team id from `credentials.team_id` (`macho/signer.rs:125`,
  :874-875) and `credentials.team_id` is `extract_team_id(certificate)`
  (`crypto/cert.rs:638`, :832) — CD team and leaf-cert OU are the same value
  by construction.
- The verify fixture's certificate (`macho/fixtures.rs:821`) hardcoded
  `team_id: Some("TESTTEAM")` while its subject carried **no OU** — an
  inconsistency with production, where `credentials.team_id` is always
  `extract_team_id(certificate)` (`crypto/cert.rs:638`, :832). Task 4
  restores the invariant by adding `OU=TESTTEAM` to the leaf subject
  (precedent: every other code-signing fixture in the repo, e.g.
  `zsign/src/test_util.rs:36`, carries `,OU=TESTTEAM`). A binding test can
  then rewrite the CD team string in place (`teamOffset` is the big-endian
  u32 at CD byte 48, `codesign/verify.rs:639-642`,
  `code_directory.rs:679`).
- `adhoc_report()` builds on `..default()`
  (`crypto/cms_verify.rs:447-452`); the first signer claims the report
  scalars whether or not it validated (`cms_verify.rs:1280-1282`), so a
  resolved signer's OU is available even when the chain is rejected.
- `zsign-wasm` has no verify API; the `zsign` facade re-exports the core
  report structs unchanged.

## Decision

1. **Fail-closed recording.** `RequirementVerdict::Unsupported` moves from
   `warnings` to `errors` with its message wording unchanged
   (`designated requirement not fully evaluated: {why}`). `Violated` and
   `Satisfied` behave exactly as today. The slice becomes invalid →
   `is_valid()` false → CLI exit 1 — Apple parity for a failed verification
   operation (`errSecCSUnimplemented` never passes).
2. **Explicit status field.** `SliceVerifyReport` gains
   `requirement_status: Option<RequirementVerdict>` — `None` when the
   signature carries no DR (or none parseable; a malformed requirements blob
   is already a hard error), `Some(...)` carrying the verdict alongside its
   recording. The JSON `SliceDto` gains a typed `requirement_status` field
   with vocabulary `absent` | `satisfied` | `violated` | `not_evaluated`,
   so consumers can distinguish "bad binary" from "this tool could not decide"
   without parsing message text.
3. **Team-id binding assertion.** `CmsVerifyReport` gains
   `signer_ou: Option<String>`, populated where the signer certificate is
   resolved (`cms_verify.rs:948` region) via `extract_team_id` (visibility
   widened to `pub(crate)`). `verify_slice` compares it with
   `primary.team_id()` after the CMS block: **definite mismatch** (both
   present, different) → one error
   `code directory team identifier {cd_team} does not match signing certificate organizational unit {signer_ou}`.
   If either side is absent (ad-hoc, cert without OU, CD without team id) the
   check is skipped — an opportunistic assertion with no false-positive mode.
   Error, not status: a status field alone would leave exit 0 unchanged, and
   the bundle printer shows neither warnings nor per-slice messages.
4. **No flag, no new opcodes, no emission changes, no new exit codes.**

### Error vs status vs flag — the weighing

- **Status-only** (verdict recorded in a field, validity untouched): exit 0
  survives → fails the acceptance criterion outright; bundle inputs never even
  print the finding.
- **Flag-gated strictness**: default-off preserves today's silent false-accept
  → fails acceptance; default-on is this design with extra surface in a file
  shared by later lanes.
- **Error promotion** (chosen): closes the acceptance, matches Apple's
  no-pass-path semantics and exit 1, and needs zero exit-contract changes.
  The residual conflation ("invalid" vs "undecidable") is carried by the
  distinct message wording and the `requirement_status` field rather than by a
  second exit code.
- **Implementing the cert-family opcodes instead**: rejected as insufficient —
  it would still leave 12 of 15 unimplemented opcodes collapsing to
  `Unsupported` (acceptance not closed), and requires threading certificate
  objects and Apple's match-suffix semantics into `RequirementContext`,
  far beyond this lane's verify-only scope.

## Rejected alternatives

- **Keep the warning, add status reporting only** — exits 0; fails acceptance;
  invisible for bundle inputs.
- **Distinct exit 2 for "could not evaluate"** — more honest taxonomy, but it
  rewires the shared CLI exit contract for a class Apple maps to a plain
  verification failure (exit 1); churn in a file many lanes share, no gain
  against the acceptance.
- **Fail binaries with no DR** — no ground truth exists to check; would mark
  our own output invalid and deviate from Apple; the remedy for our output is
  DR emission, which is excluded from this lane.
- **Emitting a DR for our own output** (`macho/signer.rs:77-82`, dead
  `SuperBlobBuilder` wiring at `codesign/superblob.rs:676-681`): excluded by
  the lane's hard split rule — emission belongs to a later lane in this slot,
  and `signer.rs` is concurrently owned by another lane. This design is
  verify-side only.

## Assumptions and accepted risk

- A genuinely well-signed third-party binary whose DR uses cert-family
  predicates now reports invalid under *this tool* with
  `designated requirement not fully evaluated` — accepted: required by the
  acceptance criterion; the message and `requirement_status` make the cause
  actionable, and the alternative is a silent false-accept.
- A no-DR binary's identifier remains self-asserted (scenario C): detectable
  only when a second CD disagrees or a DR binds it. Closing it needs DR
  emission (excluded) — recorded, not silently ignored.
- Multisigner CMS: `signer_ou` follows the same winning signer as
  `signer_subject` (first-valid-wins claim logic), so the binding compares the
  CD against the signer the report already names.
- The binding check runs even when the CMS report itself is invalid; that
  can only add an error beside errors that already fail the slice.

## Scope boundaries

- No DR emission: `macho/signer.rs`, `codesign/superblob.rs` bundle-id /
  subject-cn wiring untouched.
- Concurrently owned lanes untouched: `macho/parser.rs`,
  `zsign/src/bundle/code_resources.rs`, `crypto/pkcs12.rs`.
- No new opcodes; no `RequirementContext`/evaluator semantic changes
  (`codesign/verify.rs` unchanged).
- No new CLI flags, no exit-code changes, no `print_bundle` changes; the only
  CLI/JSON surface addition is the `requirement_status` field.
- No wasm, facade, or dependency changes.

## Acceptance criteria

1. A DR containing an unimplemented opcode (`certField`, 0x0b) verifies
   **invalid**: one slice error `designated requirement not fully evaluated`,
   nothing in `warnings`, `requirement_status == not_evaluated`, CLI exit 1
   (via the unchanged exit mapping).
2. That same fixture with the CD identifier rewritten in place (all CDs)
   verifies **invalid** — the report shows the attacker's identifier as data
   but never as valid.
3. A satisfied `ident` DR and a no-DR (own output) fixture still verify
   **valid**, with `requirement_status` `satisfied` / `absent`.
4. CD team id ≠ signer certificate OU → slice error containing
   `code directory team identifier … does not match signing certificate
   organizational unit …`; equal values produce no such error (existing
   sign→verify round-trip keeps its single anchoring error).
5. `--json` verify output carries `slices[].requirement_status` with the
   documented vocabulary; existing v1 fields unchanged.
6. `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --
   -D warnings`, workspace tests, and `hk check --all` all pass.
