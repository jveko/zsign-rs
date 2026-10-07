# Ad-hoc anchor designated-requirement — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development (recommended) with dispatching-parallel-agents for independent tasks to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** An ad-hoc or unsigned slice fails verification when its designated
requirement demands `anchor apple` / `anchor apple generic`.

**Architecture:** One production change — `evaluate_expr` maps
`Expr::AppleAnchor | Expr::AppleGenericAnchor` to `Tri::False` when
`ctx.anchored` is `None` — plus one unit test and one end-to-end test, both
written first so they fail against current code. Report plumbing,
`adhoc_report()`, and the `macho/verify.rs` triage code are untouched.

**Tech Stack:** Rust (edition 2021), inline `#[cfg(test)]` modules, `thiserror`.

**Spec:** `docs/superpowers/specs/2026-10-07-adhoc-anchor-dr-design.md`

## Global Constraints

- Files modifiable: `crates/zsign-core/src/codesign/verify.rs`,
  `crates/zsign-core/src/macho/verify.rs` (test code only in the latter).
- `crypto/cms_verify.rs` and `adhoc_report()` must NOT change.
- No ticket IDs anywhere (code, comments, docs, commit messages).
- Zero-warning gate: `cargo fmt --all -- --check` + `cargo clippy --workspace --all-targets -- -D warnings`.
- Tests run with `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test …`.
- Every new assertion prints the actual value in its failure footer
  (`…, got {:?}` with the report or verdict actually received).
- No existing test pins `anchor` + `anchored: None` ⇒ `Unsupported`
  (verified: `unsupported_opcode_is_not_a_hard_error` uses opcode 11), so no
  pre-existing assertions change.

## Review Focus

- `anchor apple` with `anchored: None` must become a hard error end-to-end,
  not a warning — pinned by Task 1's e2e test.
- Identity-neutral DRs on ad-hoc slices must stay valid — the existing
  `designated_requirement_is_enforced_end_to_end` must pass unchanged.
- `Not(anchor apple)` on `None` must be `Satisfied` (Apple's boolean
  complement), not `Violated` — pinned by Task 1's unit test.
- `anchored: Some(true)` / `Some(false)` verdicts unchanged — pinned by
  Task 1's unit test.
- Fail-closed ordering: `And(ident-match, anchor-unknown)` yields `Violated`,
  never `Unsupported` — pinned by Task 1's unit test.

---

### Task 1: Failing tests (unit + end-to-end)

**Files:**
- Test: `crates/zsign-core/src/codesign/verify.rs` inline test module (next to
  `designated_requirement_evaluates_identifier`, ~line 1360)
- Test: `crates/zsign-core/src/macho/verify.rs` inline test module (next to
  `designated_requirement_is_enforced_end_to_end`, ~line 688)

**Interfaces:**
- Consumes: `req_blob_with_dr(&[u8])` and `ident_expr(&str)`
  (codesign/verify.rs tests); `ident_dr_blob`-style helpers,
  `replace_requirements_child`, `sign_macho_adhoc`, `verify_macho`,
  `SignatureInputs::none()` (macho/verify.rs tests).
- Produces: test `anchor_requirement_fails_without_a_known_anchor`
  (codesign) and helper `anchor_dr_blob()` + test
  `anchor_designated_requirement_fails_on_adhoc_slice` (macho) — names later
  tasks and reviewers rely on.

- [ ] **Step 1: Unit test — `codesign/verify.rs` inline tests**

```rust
#[test]
fn anchor_requirement_fails_without_a_known_anchor() {
    // opAnchorApple (3), no operands.
    let blob = req_blob_with_dr(&3u32.to_be_bytes());
    let set = parse_requirements(&blob).unwrap();
    let dr = set.designated().expect("dr present");
    let ctx = |anchored: Option<bool>| RequirementContext {
        identifier: Some("com.example"),
        cdhashes: &[],
        anchored,
    };
    assert_eq!(
        dr.evaluate(&ctx(None)),
        RequirementVerdict::Violated,
        "ad-hoc/unsigned code must not satisfy anchor apple, got {:?}",
        dr.evaluate(&ctx(None))
    );
    assert_eq!(dr.evaluate(&ctx(Some(false))), RequirementVerdict::Violated);
    assert_eq!(dr.evaluate(&ctx(Some(true))), RequirementVerdict::Satisfied);

    // Not(anchor apple) with no known anchor is satisfied (boolean complement).
    let mut not_expr = 9u32.to_be_bytes().to_vec(); // opNot
    not_expr.extend_from_slice(&3u32.to_be_bytes()); // opAnchorApple
    let not_dr = parse_requirements(&req_blob_with_dr(&not_expr))
        .unwrap()
        .designated()
        .expect("dr present");
    assert_eq!(not_dr.evaluate(&ctx(None)), RequirementVerdict::Satisfied);

    // And(identifier matches, anchor unknown) fails closed, not Unsupported.
    let mut and_expr = 6u32.to_be_bytes().to_vec(); // opAnd
    and_expr.extend_from_slice(&ident_expr("com.example"));
    and_expr.extend_from_slice(&3u32.to_be_bytes()); // opAnchorApple
    let and_dr = parse_requirements(&req_blob_with_dr(&and_expr))
        .unwrap()
        .designated()
        .expect("dr present");
    assert_eq!(and_dr.evaluate(&ctx(None)), RequirementVerdict::Violated);
}
```

- [ ] **Step 2: End-to-end test — `macho/verify.rs` inline tests**

Add a DR-blob helper next to `ident_dr_blob` (~line 616). It is
`ident_dr_blob` verbatim except the expression: instead of `opIdent` + name,
emit only the 4-byte `opAnchorApple` operand (already 4-aligned, so no padding
loop is needed):

```rust
/// Requirements SuperBlob whose designated requirement is bare
/// `anchor apple` (opAnchorApple = 3, no operands).
fn anchor_dr_blob() -> Vec<u8> {
    let expr = 3u32.to_be_bytes().to_vec();
    let child_len = 12 + expr.len();
    let total = 0x14 + child_len;
    let mut b = Vec::with_capacity(total);
    b.extend_from_slice(&CSMAGIC_REQUIREMENTS.to_be_bytes());
    b.extend_from_slice(&(total as u32).to_be_bytes());
    b.extend_from_slice(&1u32.to_be_bytes());
    b.extend_from_slice(&3u32.to_be_bytes()); // CSREQ_DESIGNATED
    b.extend_from_slice(&0x14u32.to_be_bytes());
    b.extend_from_slice(&CSMAGIC_REQUIREMENT.to_be_bytes());
    b.extend_from_slice(&(child_len as u32).to_be_bytes());
    b.extend_from_slice(&1u32.to_be_bytes()); // exprForm
    b.extend_from_slice(&expr);
    b
}
```

Then the test (same structure as `designated_requirement_is_enforced_end_to_end`):

```rust
#[test]
fn anchor_designated_requirement_fails_on_adhoc_slice() {
    let macho = MachOFile::parse(make_minimal_macho()).unwrap();
    let mut signed =
        sign_macho_adhoc(&macho, "com.example.anchor", None, None, None, false).unwrap();
    replace_requirements_child(&mut signed, &anchor_dr_blob());
    let report = verify_macho(&signed, &SignatureInputs::none()).unwrap();
    assert!(
        report.slices[0]
            .errors
            .iter()
            .any(|e| e.contains("designated requirement not satisfied")),
        "ad-hoc slice must fail an anchor-apple DR, got errors: {:?}",
        report.slices[0].errors
    );
    assert!(
        report.slices[0]
            .warnings
            .iter()
            .all(|w| !w.contains("designated requirement not fully evaluated")),
        "anchor failure must not degrade to a warning, got warnings: {:?}",
        report.slices[0].warnings
    );
}
```

- [ ] **Step 3: Run both tests to verify they fail**

Run: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-core anchor_requirement_fails_without_a_known_anchor`
and `… cargo test -p zsign-core anchor_designated_requirement_fails_on_adhoc_slice`
Expected: both FAIL — unit test receives `Unsupported("boolean context unevaluable")`;
e2e test reports an empty `errors` list (the DR finding is a warning today).

---

### Task 2: Anchor arm maps absent anchor to false

**Files:**
- Modify: `crates/zsign-core/src/codesign/verify.rs:302-306` (`evaluate_expr`)

**Interfaces:**
- Consumes: `Tri`, `RequirementContext.anchored: Option<bool>` — private, unchanged.
- Produces: unchanged `Requirement::evaluate` signature; verdict change only.

- [ ] **Step 1: Change the anchor arm**

Replace lines 302-306 with:

```rust
// Apple's interpreter is boolean: no certificate chain (ad-hoc or
// unsigned code) evaluates anchor checks to false, never unknown.
Expr::AppleAnchor | Expr::AppleGenericAnchor => match ctx.anchored {
    Some(true) => Tri::True,
    Some(false) => Tri::False,
    None => Tri::False,
},
```

- [ ] **Step 2: Run both Task 1 tests — they must pass**

Run: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-core anchor_`
Expected: both `anchor_requirement_fails_without_a_known_anchor` and
`anchor_designated_requirement_fails_on_adhoc_slice` PASS.

- [ ] **Step 3: Regression run — existing DR behavior unchanged**

Run: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-core designated_requirement unsupported_opcode`
Expected: PASS — in particular
`designated_requirement_is_enforced_end_to_end` (ad-hoc + identifier DR still
valid) and `unsupported_opcode_is_not_a_hard_error`.

- [ ] **Step 4: Scoped gate**

Run: `cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings && mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test --workspace`
Expected: no diff, no warnings, all tests pass.

- [ ] **Step 5: Commit**

`git add crates/zsign-core/src/codesign/verify.rs crates/zsign-core/src/macho/verify.rs docs/superpowers/specs/2026-10-07-adhoc-anchor-dr-design.md docs/superpowers/plans/2026-10-07-adhoc-anchor-dr.md`
then commit as `fix(codesign): fail anchor apple requirements when no anchor is known` — no ticket ID in subject or body.

---

## Self-review

- Spec coverage: chosen design B (single match arm) → Task 2; unit + e2e +
  regression testing strategy → Tasks 1-2; verification commands → Task 2
  step 4. Files-in-scope respected (macho/verify.rs production untouched).
- Step scan: each step is one action with a checkable result; no step carries
  a body the signature and test already determine beyond the exact snippet
  shown.
- Type consistency: `RequirementContext`, `RequirementVerdict`, `Tri`,
  `req_blob_with_dr`, `ident_expr`, `replace_requirements_child`,
  `sign_macho_adhoc` names match current source (verified while researching).
- Review Focus: all five lines have an owning test in Task 1 (unit) or are
  covered by an existing regression assert in Task 2 step 3.
- Proportion: plan size tracks the one-arm change it describes.
