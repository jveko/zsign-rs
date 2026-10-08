# Requirement and/or operand parsing — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development
> with dispatching-parallel-agents for independent tasks to implement this
> plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `parse_requirement_expr` parse both operands of `and`/`or`
and build the node unconditionally, so a decisive `opFalse`/`opTrue` sibling
decides the verdict instead of being masked by an `Unsupported` leaf.

**Architecture:** Delete four early-return guards in the op-6/op-7 arms of
`parse_requirement_expr`; `evaluate_expr`'s existing match-arm precedence
then decides (`False`/`True` dominate, `Unsupported` warns only when
non-decisive). One test is rewritten to pin the new contract; nothing else
changes.

**Tech Stack:** Rust (edition 2021), cargo test/clippy/fmt.

**Spec:** `docs/superpowers/specs/2026-10-08-requirement-and-or-operands-design.md`

## Global Constraints

- Sole edited file: `crates/zsign-core/src/codesign/verify.rs`
  (parser arms + one test in that file's test module). `evaluate_expr`,
  the `not` arm, `macho/*`, facade, and CLI files are never edited.
- `Unsupported` stays a non-fatal warning — never escalate it to a hard
  error anywhere in this change.
- Zero-warning gate before the item closes:
  `cargo fmt --all -- --check` and
  `cargo clippy --workspace --all-targets -- -D warnings`, both clean.
- Tests run as `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test …`.
- No ticket IDs, no TODOs, no stubs anywhere (code, comments, docs, commits).
- Commits are controller-owned; implementers and testers never commit.
  Commit subjects: conventional, imperative, lowercase, no trailing period.
- The rewritten test is an EXPECTED contract change (the old comment
  pinned buggy behavior); its coverage is preserved and extended, never
  silently deleted.

## Review Focus

- **The warning must survive:** a lone unsupported opcode must still
  yield `RequirementVerdict::Unsupported(_)`, not `Err` and not
  `Violated` — scenario 1 of the rewritten test, plus the pre-existing
  `macho/verify.rs` warning path exercised by the crate-wide run.
- **Both decisive directions:** `and(opFalse, …)` → `Violated` AND
  `or(opTrue, …)` → `Satisfied`, each pre-fix `Unsupported` — scenarios
  2-3; the test as a whole must be red before the parser change.
- **Junk operands stay unconsumed:** the `[0u8; 16]` tail after the bare
  `opCertField` must not parse into anything or hard-error (leftover
  bytes are tolerated because `parse_requirements` checks no trailing
  consumption) — scenarios 1-3 all carry the junk tail.
- **No evaluator drift:** `evaluate_expr` (`verify.rs:293-341`) must stay
  byte-for-byte unchanged — the fix is parser-only; a reviewer diffing
  Task 2 sees changes only inside `parse_requirement_expr`'s op-6/op-7
  arms.
- **Regression surface:** existing `and`/`or`/`not`/anchor tests
  (`designated_requirement_evaluates_identifier`,
  `anchor_requirement_fails_without_a_known_anchor`,
  `malformed_requirements_are_errors`) must stay green — Task 2's
  crate-scoped run.

---

### Task 1: Rewrite `unsupported_opcode_is_not_a_hard_error` to pin the new contract

**Files:**
- Modify: `crates/zsign-core/src/codesign/verify.rs` — test module only,
  test at `verify.rs:1462-1481` (replaces it in place).

**Interfaces:**
- Consumes: helpers `req_blob_with_dr(expr: &[u8]) -> Vec<u8>`
  (`verify.rs:1319`), `parse_requirements(&[u8]) -> Result<RequirementsSet>`
  with `.designated() -> Option<&Requirement>`, types
  `RequirementContext { identifier, cdhashes, anchored }` and
  `RequirementVerdict::{Satisfied, Violated, Unsupported(String)}`.
- Produces: nothing for later tasks — Task 2's parser change turns this
  test green.

- [ ] **Step 1: Replace the test body**

Delete the current `unsupported_opcode_is_not_a_hard_error` at
`verify.rs:1462-1481` and insert in its place:

```rust
#[test]
fn unsupported_opcode_is_not_a_hard_error() {
    // opCertField(11): a zero-flag opcode OUTSIDE the supported set. On its own
    // the whole DR is Unsupported - a warning, never a hard error, because
    // Apple's DRs carry cert-chain ops whose chain DER crypto/cms_verify.rs does
    // not expose (out of scope). Inside and/or the sibling operand must still
    // be parsed and decide the verdict: a decisive false/true operand cannot be
    // masked by the Unsupported leaf.
    let ctx = RequirementContext {
        identifier: Some("com.example"),
        cdhashes: &[],
        anchored: None,
    };

    // Alone: warning, not a hard error; an unknown opcode's operands are never
    // consumed (the junk tail parses as nothing and does not error).
    let mut alone = 11u32.to_be_bytes().to_vec(); // opCertField
    alone.extend_from_slice(&[0u8; 16]); // junk operands - must NOT be parsed
    let alone_set = parse_requirements(&req_blob_with_dr(&alone)).unwrap();
    let alone_dr = alone_set.designated().expect("dr present");
    let alone_v = alone_dr.evaluate(&ctx);
    assert!(
        matches!(alone_v, RequirementVerdict::Unsupported(_)),
        "{alone_v:?}"
    );

    // and(opFalse, opCertField) -> Violated: the false operand decides.
    let mut and_expr = 6u32.to_be_bytes().to_vec(); // opAnd
    and_expr.extend_from_slice(&0u32.to_be_bytes()); // opFalse
    and_expr.extend_from_slice(&11u32.to_be_bytes()); // opCertField (unsupported here)
    and_expr.extend_from_slice(&[0u8; 16]); // junk operands - must NOT be parsed
    let and_set = parse_requirements(&req_blob_with_dr(&and_expr)).unwrap();
    let and_dr = and_set.designated().expect("dr present");
    let and_v = and_dr.evaluate(&ctx);
    assert_eq!(
        and_v,
        RequirementVerdict::Violated,
        "false operand must decide, got {and_v:?}"
    );

    // or(opTrue, opCertField) -> Satisfied: the true operand decides.
    let mut or_expr = 7u32.to_be_bytes().to_vec(); // opOr
    or_expr.extend_from_slice(&1u32.to_be_bytes()); // opTrue
    or_expr.extend_from_slice(&11u32.to_be_bytes()); // opCertField (unsupported here)
    or_expr.extend_from_slice(&[0u8; 16]); // junk operands - must NOT be parsed
    let or_set = parse_requirements(&req_blob_with_dr(&or_expr)).unwrap();
    let or_dr = or_set.designated().expect("dr present");
    let or_v = or_dr.evaluate(&ctx);
    assert_eq!(
        or_v,
        RequirementVerdict::Satisfied,
        "true operand must decide, got {or_v:?}"
    );
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-core unsupported_opcode_is_not_a_hard_error`
Expected: FAIL at scenario 2 — `false operand must decide, got
Unsupported("opcode 0x0000000b")` (the op-7/`or` scenario is behind it and
also red, but the run stops at the first assertion). Scenario 1's
`matches!` passes first (bare unsupported is already a warning today).

- [ ] **Step 3: Confirm no other test broke**

Run: `TMPDIR=$PWD/target/tmp cargo test -p zsign-core`
Expected: exactly one failing test — `unsupported_opcode_is_not_a_hard_error`.
Any other failure is a signal the rewrite touched more than the test
module: stop and report it.

### Task 2: Delete the four early-returns in the and/or arms

**Files:**
- Modify: `crates/zsign-core/src/codesign/verify.rs` — only the op-6 arm
  (`:388-398`) and op-7 arm (`:399-409`) of `parse_requirement_expr`.

**Interfaces:**
- Consumes: `parse_requirement_expr(bytes: &[u8], offset: &mut usize,
  depth: u32) -> Result<Expr>` (recursive; `Expr::{Unsupported(String),
  And(Box<Expr>, Box<Expr>), Or(…)}`) — signature unchanged.
- Produces: unchanged signatures; `evaluate_expr` receives real
  `Expr::And`/`Expr::Or` trees containing `Unsupported` children.

- [ ] **Step 1: Replace both arms**

Op-6 arm, currently:

```rust
6 => {
    let left = parse_requirement_expr(bytes, offset, depth + 1)?;
    if matches!(left, Expr::Unsupported(_)) {
        return Ok(left);
    }
    let right = parse_requirement_expr(bytes, offset, depth + 1)?;
    if matches!(right, Expr::Unsupported(_)) {
        return Ok(right);
    }
    Ok(Expr::And(Box::new(left), Box::new(right)))
}
```

becomes:

```rust
6 => {
    let left = parse_requirement_expr(bytes, offset, depth + 1)?;
    let right = parse_requirement_expr(bytes, offset, depth + 1)?;
    Ok(Expr::And(Box::new(left), Box::new(right)))
}
```

Op-7 arm: the same edit, with `7 =>` and `Ok(Expr::Or(...))`. Both
`if matches!(...) { return Ok(...) }` guards disappear from each arm —
four guards deleted, nothing else in the function touched (`not`, opcode
coverage, depth guard, error strings all byte-for-byte).

- [ ] **Step 2: Run the rewritten test to verify it passes**

Run: `TMPDIR=$PWD/target/tmp cargo test -p zsign-core unsupported_opcode_is_not_a_hard_error`
Expected: PASS (all three scenarios).

- [ ] **Step 3: Run the whole zsign-core crate**

Run: `TMPDIR=$PWD/target/tmp cargo test -p zsign-core`
Expected: all tests pass — including
`designated_requirement_evaluates_identifier`,
`anchor_requirement_fails_without_a_known_anchor`, and
`malformed_requirements_are_errors` (the hard-error paths for truncated
operands are untouched).

- [ ] **Step 4: Controller commit (not an implementer step)**

The orchestrator stages exactly `crates/zsign-core/src/codesign/verify.rs`
and commits `fix(codesign): parse both operands of requirement and or expressions`.

### Task 3: Zero-warning gate for the item

**Files:** none edited; verification only.

- [ ] **Step 1: Format check**

Run: `cargo fmt --all -- --check`
Expected: no output, exit 0.

- [ ] **Step 2: Clippy gate**

Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: no warnings, exit 0.

- [ ] **Step 3: Full workspace tests**

Run: `TMPDIR=$PWD/target/tmp cargo test --workspace`
Expected: all workspace tests pass.

Acceptance for the item: Steps 1-3 all exit 0 with no warnings and no test
failures, the fix commit exists on the branch, and the rewritten test is
recorded as an expected contract change in the final report.
