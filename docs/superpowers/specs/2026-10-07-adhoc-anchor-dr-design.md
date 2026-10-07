# Ad-hoc slices satisfying an Apple-anchored designated requirement — Design

**Date:** 2026-10-07 · **Branch:** `w1-crypto-cms`
**Status:** approved for planning (cold review gate follows this doc and the plan)

## Goal

An ad-hoc-signed or unsigned Mach-O slice must FAIL verification when its
designated requirement demands `anchor apple` (or `anchor apple generic`),
instead of passing with a warning.

## Evidence (verified against current source, zero drift)

- `crates/zsign-core/src/macho/verify.rs:435-439` —
  `let anchored = report.cms.as_ref().filter(|cms| !cms.no_signature).map(|cms| cms.anchored);`
  `adhoc_report()` (`crates/zsign-core/src/crypto/cms_verify.rs:415-422`,
  `no_signature: true`) is filtered out, so `anchored` is `None` for ad-hoc slices.
- `crates/zsign-core/src/codesign/verify.rs:302-306` —
  `Expr::AppleAnchor | Expr::AppleGenericAnchor` maps `anchored: None` to `Tri::Unknown`.
- `crates/zsign-core/src/codesign/verify.rs:278-280` —
  `Tri::Unknown` becomes `RequirementVerdict::Unsupported("boolean context unevaluable")`,
  which `macho/verify.rs:449-451` turns into a **warning**; `SliceVerifyReport::is_valid()`
  (`macho/verify.rs:62-64`) only inspects `errors`, so the slice still verifies.

Net effect: a DR demanding an Apple anchor is silently satisfied by an
ad-hoc or unsigned binary.

## External contract (verified against authoritative sources)

1. Apple Security framework, `OSX/libsecurity_codesigning/lib/CSCommon.h:263-266`,
   on `kSecCodeSignatureAdhoc`: *"The code has been sealed without a signing
   identity. No identity may be retrieved from it, and **any code requirement
   placing restrictions on the signing identity will fail**."* — a MUST-fail,
   not "unknown".
2. Apple's requirement interpreter is boolean, not tri-state:
   `reqinterp.cpp:122-126` `appleAnchored()` returns `true` only when a cert
   chain exists and its anchor is an Apple CA; **no chain ⇒ `false`**.
   For ad-hoc code `SecStaticCode::verifySignature()`
   (`StaticCode.cpp:856-863`) returns early and `mCertChain` stays `NULL`, so
   `anchor apple` evaluates to `false`.
3. Requirement failure is fatal, not a diagnostic:
   `StaticCode.cpp:2379-2384` `validateRequirement` throws `errSecCSReqFailed`;
   `codesign(1)` DIAGNOSTICS class 3 = "failed to satisfy the requirement".
4. `codesign(1)` (VERIFYING): the program "is also checked against its own
   designated requirement, which should never fail for a properly signed program".

Conclusion: mapping absent-anchor to `Tri::Unknown` (warn-only) has no basis in
Apple's contract. The correct value for `anchor apple` when the anchor is not
known to be an Apple root is **false**.

## Candidate designs

**A — blanket gate in `macho/verify.rs`** ("ad-hoc + any DR ⇒ error").
Rejected: over-broad. Apple evaluates identity-*neutral* DRs (identifier,
cdhash) fine on ad-hoc code — its own default ad-hoc DR is a cdhash
requirement (`StaticCode.cpp:2179-2197`) — and the existing passing test
`designated_requirement_is_enforced_end_to_end` (`macho/verify.rs:688-708`,
ad-hoc slice + identifier DR, asserts `is_valid()`) would break.

**B — anchor semantics in `codesign/verify.rs`** (CHOSEN).
One match arm: `Expr::AppleAnchor | Expr::AppleGenericAnchor` with
`anchored: None` returns `Tri::False` instead of `Tri::Unknown`.
- Matches Apple's interpreter exactly (boolean; absent chain ⇒ false).
- Composes correctly: `Not(anchor apple)` on `None` ⇒ `True`; `And(ident-ok,
  anchor)` ⇒ `False` ⇒ `Violated` ⇒ existing error
  `"designated requirement not satisfied"`; within the supported-opcode
  subset the `False` arm short-circuits ahead of `Unsupported` in `And`, so a
  `False` anchor never degrades to a warning there. Caveat: DRs containing
  unsupported cert-chain opcodes are collapsed to `Expr::Unsupported` at
  parse time (`codesign/verify.rs:385-406`) and never reach evaluation —
  that warning-only path is a separate, out-of-scope gap.
- Identifier/cdhash DRs on ad-hoc slices are untouched (`anchored` unused).
- Blast radius is tiny: `Tri` is private, `Requirement::evaluate` has a single
  production caller (`macho/verify.rs:445`); no facade/CLI code touches
  `RequirementVerdict`/`RequirementContext`.

**C — hybrid (B + an explicit ad-hoc error string in `macho/verify.rs`).**
Rejected: a second, redundant signal for the same failure — two conventions
for one condition, more code, no additional coverage.

## Chosen design (B) — behavior after the change

| `ctx.anchored` | `anchor apple` today | after |
|---|---|---|
| `Some(true)` | True | True (unchanged) |
| `Some(false)` | False | False (unchanged) |
| `None` (ad-hoc / no CMS / anchor undetermined) | Unknown → warning | **False → `Violated` → error** |

Fail-closed also covers a slice whose CMS verification already errored
(`report.cms = None`): the extra DR error lands on a report that is already
invalid.

`adhoc_report()` itself is NOT modified (owned by later items).

## Files in scope

- `crates/zsign-core/src/codesign/verify.rs` — the `evaluate_expr` anchor arm
  (production) + inline unit tests.
- `crates/zsign-core/src/macho/verify.rs` — inline end-to-end test only
  (production triage code unchanged).

Explicitly out of scope: `crypto/cms_verify.rs`, `macho/parser.rs`,
`macho/writer.rs`, `macho/signer.rs`, `macho/code_directory.rs`, `crates/zsign/**`,
`crates/zsign-cli/**`, and the unrelated open gaps in these same files
(requirement-warning policy, cert-chain opcode support).

## Testing strategy

- Unit (codesign): DR = `anchor apple` evaluated with `anchored: None` asserts
  `RequirementVerdict::Violated` — fails before the change (`Unsupported`).
  Companion asserts: `Some(true)` ⇒ `Satisfied`, `Some(false)` ⇒ `Violated`,
  `Not(anchor apple)` with `None` ⇒ `Satisfied`.
- End-to-end (macho): ad-hoc-sign the minimal fixture, inject a DR blob
  demanding `anchor apple` (mirroring the existing `ident_dr_blob` /
  `replace_requirements_child` helpers), assert the report is invalid and
  `errors` contains `"designated requirement not satisfied"` — fails before
  (warning-only).
- Regression: existing `designated_requirement_is_enforced_end_to_end`
  (ad-hoc + identifier DR stays valid) must keep passing unchanged.

## Verification commands

```
cargo test -p zsign-core designated_requirement
cargo test -p zsign-core anchor
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test --workspace
```
