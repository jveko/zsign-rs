# Requirement expressions: parse both and/or operands — design

Date: 2026-10-08
Status: drafted for cold review
Sole file in scope: `crates/zsign-core/src/codesign/verify.rs`

## Goal

The `and`/`or` parser arms discard the decisive operand: a designated
requirement Apple must reject (`and(opFalse, …)`) collapses to an
`Unsupported` leaf, which the consumer records as a warning, and the binary
verifies as valid. Fix: parse both operands, build `Expr::And`/`Expr::Or`
unconditionally, and let `evaluate_expr`'s three-valued precedence decide —
while an unsupported opcode on its own stays a non-fatal warning (never
turned into a hard error here; that enforcement is another ticket's
ownership).

## Defect — verified at 8e15ce8 (source unchanged at current HEAD 408f476)

`parse_requirement_expr` is `verify.rs:376-421`. Four early-returns:

- `and` arm `:388-398`: after parsing `left`, `:390-392` returns it without
  ever parsing `right`; after parsing `right`, `:394-396` returns `right`
  and throws the (already parsed) `left` away.
- `or` arm `:399-409`: symmetric guards at `:401-403` and `:405-407`.

Both guards collapse the whole node into a bare `Expr::Unsupported` leaf.
`evaluate_expr` (`verify.rs:293-341`) implements correct three-valued
precedence but can only see the tree the parser builds:

- `Expr::And` arm `:316-323`: `(False, _) | (_, False)` first, then
  `(True, True)`, then `Unsupported`, else `Unknown`.
- `Expr::Or` arm `:324-331`: `(True, _) | (_, True)` first, then
  `(False, False)`, then `Unsupported`, else `Unknown`.
- Both arms evaluate both children eagerly (a Rust tuple match — no
  evaluation skipping; precedence comes from arm order).

Precise trace of the security-relevant direction (`and(opFalse,
opCertField)`): `left` parses to `Expr::False`, so the left guard does not
fire; `right` (opcode 11, outside the supported set) parses to
`Expr::Unsupported` and the right guard at `:394-396` collapses the node.
`Requirement::evaluate` (`:273-284`) maps that to
`RequirementVerdict::Unsupported(reason)`, and the sole production consumer
(`crates/zsign-core/src/macho/verify.rs:446-451`) pushes `Violated` to
`report.errors` but `Unsupported` to `report.warnings` ("designated
requirement not fully evaluated: …"); `is_valid()`
(`macho/verify.rs:62-64`) ignores warnings. Net: a designated requirement
that must fail becomes `valid: true`. The benign direction
`or(opTrue, …)` is mishandled the same way (today it warns instead of
satisfying).

## External contract (verified: apple-oss-distributions/Security @ main)

Sources: `OSX/libsecurity_codesigning/lib/{reqinterp.cpp, requirement.h,
requirement.cpp}` (github.com/apple-oss-distributions/Security).

- **opAnd/opOr — both operands evaluated, then `&&`/`||`**
  (`reqinterp.cpp:130-148`): `bool left = eval(depth); bool right =
  eval(depth); return left && right;` (resp. `||`). Apple does NOT skip an
  operand. Consequences confirmed: `and(opFalse, X)` is false always;
  `or(opTrue, X)` is true always — for any X the interpreter accepts.
- **Unrecognized opcodes are fail-closed, not neutral**
  (`reqinterp.cpp:220-236`, `requirement.h:139-186`): an unknown opcode
  with no `opGenericFalse`/`opGenericSkip` flag throws
  `errSecCSUnimplemented` — "An unrecognized opcode with zero flag byte
  causes evaluation to categorically fail". Apple therefore never returns
  "unsupported but not fatal"; the repo's three-valued
  `RequirementVerdict` with a non-fatal `Unsupported` is a deliberate
  divergence (established in this file's tests: Apple's DRs carry
  cert-chain ops whose chain DER this repo does not expose).
- **Opcodes** (`requirement.h` enum): opFalse=0, opTrue=1, opIdent=2,
  opAnchorApple=3, opAnd=6, opOr=7, opCDHash=8, opNot=9, opCertField=11,
  opAppleGenericAnchor=15 — matching this file's parser arms and tests.
  `opCertField` is a first-class Apple opcode (`reqinterp.cpp:170-178`);
  it is this repo that cannot evaluate it, so it must stay in the
  non-fatal `Unsupported` class.
- **opFalse/opTrue** are unconditional constants, no operands consumed
  (`reqinterp.cpp:115-121`).

## Design decisions

### D1 — delete the four early-returns; always build the node (chosen)

```rust
6 => {
    let left = parse_requirement_expr(bytes, offset, depth + 1)?;
    let right = parse_requirement_expr(bytes, offset, depth + 1)?;
    Ok(Expr::And(Box::new(left), Box::new(right)))
}
7 => {
    let left = parse_requirement_expr(bytes, offset, depth + 1)?;
    let right = parse_requirement_expr(bytes, offset, depth + 1)?;
    Ok(Expr::Or(Box::new(left), Box::new(right)))
}
```

- **A (chosen):** parse both operands unconditionally, build
  `Expr::And`/`Expr::Or` even when a child is `Expr::Unsupported`, and let
  the evaluator decide. This matches Apple's eager both-operand evaluation
  with `&&`/`||` precedence, is the smallest diff, and keeps `Unsupported`
  in non-decisive positions a warning exactly as required.
- **B (rejected):** parse both operands but still collapse to
  `Unsupported` if either child is unsupported. This fixes only the
  under-parsing (offset advance) and leaves the security gap intact —
  `and(opFalse, unsupported)` would still mask the `False` and verify
  valid.
- **C (rejected):** turn an `Unsupported` child under and/or into a hard
  parse error. Over-tightening: legitimately anchored designated
  requirements containing cert-chain opcodes would start failing, and that
  enforcement decision is another ticket's ownership (this fix must not
  implement it).

### D2 — `evaluate_expr` stays byte-for-byte unchanged

Its arm order already encodes the required precedence once the tree
exists:

| expression | arm order outcome |
|---|---|
| `And(False, Unsupported)` | `(False, _)` first → `Tri::False` → `Violated` |
| `And(Unsupported, False)` | `(_, False)` first → `Tri::False` → `Violated` |
| `Or(True, Unsupported)` | `(True, _)` first → `Tri::True` → `Satisfied` |
| `Or(Unsupported, True)` | `(_, True)` first → `Tri::True` → `Satisfied` |
| `And/Or` with no decisive sibling | falls through to the `Unsupported` arm → warning, as before |

The brief's "short-circuits decide" means this match-arm precedence, not
evaluation skipping: both children are evaluated eagerly (pure — no side
effects), which is also what Apple's interpreter does.

### D3 — `not` arm audited, deliberately untouched

The `not` arm (`:411-417`) also returns a bare `Unsupported` leaf instead
of `Expr::Not(unsupported)`. Verdict-equivalent: `evaluate_expr`'s `Not`
arm propagates `Tri::Unsupported(reason)` unchanged, so both shapes yield
the identical verdict, and `not` has no sibling to mask. Out of scope;
changing it would be churn without a behavior difference.

### D4 — consequence accepted: previously-skipped right operands now parse

Deleting the left guards means the right operand is parsed even when the
left is `Unsupported`. A genuinely truncated/malformed right operand now
propagates a hard `Err` where the blob previously "succeeded" with an
`Unsupported` leaf. That is fail-closed and correct — the blob is
malformed — and matches how a supported left operand already behaves
today. `parse_requirements` performs no trailing-consumption check
(`:424+`), so unconsumed junk after an unknown opcode (as in the tests'
`[0u8; 16]` operands) remains tolerated, unchanged.

### D5 — consequence recorded, not fixed: `or(opTrue, <Apple-unknown>)`

For opcodes Apple itself does not recognize, Apple throws
`errSecCSUnimplemented` (never valid) while this repo — by the mandated
non-fatal `Unsupported` model — will report `Satisfied` for
`or(opTrue, …)`. That divergence is inherent to the warning model the
brief pins (and to the required test `or(opTrue, opCertField) ->
Satisfied`, where Apple agrees: opCertField is Apple-supported, so
`true || x` is true). Closing the general enforcement question is the
adjacent ticket's ownership; this fix must not silently implement it.

## Test strategy (includes one expected rewrite)

Rewrite `unsupported_opcode_is_not_a_hard_error` (`verify.rs:1462-1481`)
in place. Its current comment pins the buggy contract ("The whole DR
becomes Unsupported (operands never inspected)") and its single scenario
does not exercise `and`/`or`. The rewritten test keeps every original
property and adds the decisive-sibling properties, so it fails before the
fix (scenarios 2-3) and passes after:

1. **Alone (original coverage):** bare `opCertField` + `[0u8; 16]` junk
   → `RequirementVerdict::Unsupported(_)` — still a warning, never a hard
   error; an unknown opcode's operands are still never consumed.
2. **`and(opFalse, opCertField)` → `RequirementVerdict::Violated`** — the
   false operand decides; pre-fix this collapses to `Unsupported`.
3. **`or(opTrue, opCertField)` → `RequirementVerdict::Satisfied`** — the
   true operand decides; pre-fix this collapses to `Unsupported`.

Rationale recorded for the rewrite: the old assertion pinned
"operands never inspected" as an observable outcome for the and/or path —
exactly the behavior being fixed — so keeping it verbatim would pin the
defect. The new version preserves its real contract (unsupported opcode ⇒
non-fatal warning, junk operands ⇒ never parsed/hard error) and adds the
two directions the fix makes observable. House styles reused:
`req_blob_with_dr` + `parse_requirements(...).designated()` for blob
construction, `matches!(v, RequirementVerdict::Unsupported(_), "{v:?}")`
for the warning shape, `assert_eq!(v, RequirementVerdict::…)` for the
decisive verdicts (as `anchor_requirement_fails_without_a_known_anchor`
does).

## Non-goals / out of scope (deliberate)

- No `Unsupported` → hard-error enforcement (adjacent ticket's ownership).
- No changes to `evaluate_expr`, the `not` arm, opcode coverage, the
  depth/offset guards, `parse_requirements`, or any consumer
  (`macho/verify.rs`, facade, CLI).
- No Apple flag-byte (`opGenericFalse`/`opGenericSkip`) support.
- No new supported opcodes (opCertField stays unsupported here).
