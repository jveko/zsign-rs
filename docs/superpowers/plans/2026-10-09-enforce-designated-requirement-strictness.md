# Enforce Designated Requirement Strictness — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development (recommended) with dispatching-parallel-agents for independent tasks to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `-V` fail closed when a designated requirement cannot be evaluated (unimplemented opcode), expose the evaluation verdict as `requirement_status`, and bind the CodeDirectory team identifier to the signing certificate's OU.

**Architecture:** All behavior changes live in `zsign-core`'s verify layer: `macho/verify.rs` records the existing `RequirementVerdict::Unsupported` as a slice *error* (wording unchanged), stores the verdict in a new `requirement_status` field, and asserts `team_id()` against a new `CmsVerifyReport.signer_ou` populated in `crypto/cms_verify.rs`. The CLI gains one additive JSON field. No evaluator, signer, or exit-contract changes.

**Tech Stack:** Rust 2021 workspace, `cargo test -p zsign-core` / `-p zsign-cli`, inline `#[cfg(test)]` modules, no new dependencies.

**Spec:** `docs/superpowers/specs/2026-10-09-enforce-designated-requirement-strictness-design.md` — the plan argues from it; executors read both.

## Global Constraints

- No ticket IDs anywhere: code, comments, commit subjects/bodies, docs, messages.
- Commits: conventional format `type(scope): subject`, imperative mood, lowercase, no trailing period. Commit, never push. The controller commits; implementers never commit.
- Files that may change: `crates/zsign-core/src/macho/verify.rs`, `crates/zsign-core/src/crypto/cms_verify.rs`, `crates/zsign-core/src/crypto/cert.rs` (visibility of `extract_team_id` only), `crates/zsign-cli/src/main.rs`. Nothing else — NOT `macho/signer.rs`, NOT `codesign/superblob.rs`, NOT `macho/parser.rs`, NOT `crates/zsign/src/bundle/code_resources.rs`, NOT `crypto/pkcs12.rs`, NOT `codesign/verify.rs`.
- Exact messages (substring-asserted by tests, wording fixed):
  - `designated requirement not fully evaluated: {why}` — moves from `warnings` to `errors`; wording unchanged.
  - `designated requirement not satisfied` — unchanged, stays in `errors`.
  - `code directory team identifier {cd_team} does not match signing certificate organizational unit {signer_ou}` — new.
- New report field: `SliceVerifyReport.requirement_status: Option<RequirementVerdict>` (`None` = no designated requirement). JSON vocabulary: `absent` | `satisfied` | `violated` | `not_evaluated`.
- `RequirementVerdict::Unsupported` must land in `errors`, never `warnings`; exit contract (0/1/2) unchanged; no new flags.
- Keep `TMPDIR` inside the worktree: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test …` (`/tmp` is a small tmpfs).
- Scoped gates while working: `cargo fmt --all -- --check` and `cargo clippy -p <crate> --all-targets -- -D warnings`. The orchestrator runs the full workspace gates and `hk check --all` once at the end.
- No stubs/TODOs/placeholders. Implementers never spawn subagents and never commit; the controller commits.

## Review Focus

1. An unimplemented-opcode DR must stop riding to `valid: true` → Task 1 test `unimplemented_designated_requirement_opcode_is_invalid` (red before Task 2).
2. Identifier tamper under an unevaluable DR must never report the attacker's identity as valid → Task 1 test `tampered_identifier_under_unimplemented_requirement_is_invalid` (red before Task 2).
3. Own output (no DR) and satisfied DRs must stay valid — the strictness must not false-positive → Task 2 test `requirement_status_reports_evaluation_outcome`, plus the pre-existing sign→verify round-trips which must stay green.
4. The binding assertion must not false-positive on our own signatures (CD team == cert OU by construction) → Task 3 baseline assertion (no mismatch error before tamper) + the pre-existing `verify_signed_binary_round_trip` (exactly one anchoring error, unchanged).
5. `--json` v1 stays additive: only `requirement_status` is added, existing fields byte-compatible → Task 5 assertion in `json_verify_valid_and_invalid_documents`.

---

### Task 1: Failing tests for designated requirement strictness

**Files:**
- Modify: `crates/zsign-core/src/macho/verify.rs` — inline `mod tests` (append after the last existing test, around line 1749).

**Interfaces:**
- Consumes: existing test-module helpers — `make_minimal_macho`, `sign_macho_adhoc`, `MachOFile::parse`, `SignatureInputs::none()`, `verify_macho`, `ident_dr_blob`, `replace_requirements_child`, `entry_offset`, `CSSLOT_CODEDIRECTORY` / `CSSLOT_ALTERNATE_CODEDIRECTORIES` (all already imported in the module); `ArchSlice` fields `code_sig_offset` / `code_sig_size` (field access, no import needed).
- Produces: two new helpers (`certfield_dr_blob`, `tamper_cd_identifiers`) and two tests with the exact names below. These tests use only pre-existing API (`is_valid()`, `errors`, `warnings`, `identifier`) so they compile clean while red. Task 2 must make them pass without changing their meaning; the single additive assertion in Task 2 Step 4 is the only permitted edit.

- [ ] **Step 1: Write the two failing tests plus helpers**

Shared shape: `let macho = MachOFile::parse(make_minimal_macho()).unwrap();` then `let mut signed = sign_macho_adhoc(&macho, "com.example.dr", None, None, None, false).unwrap();`.

Helper `certfield_dr_blob(cn: &str) -> Vec<u8>` — a requirements SuperBlob whose designated requirement starts with `opCertField` (opcode 11), i.e. an unimplemented opcode. Exact byte layout (mirrors `ident_dr_blob`'s wrapper):

```rust
fn certfield_dr_blob(cn: &str) -> Vec<u8> {
    // op=11 (opCertField, unimplemented — the parse catch-all returns
    // Unsupported without consuming operands); remaining words are filler
    // mirroring ident_dr_blob's shape: certIndex 0 (leaf), key "subject.CN",
    // match op 1, value = cn.
    let mut expr = 11u32.to_be_bytes().to_vec();
    expr.extend_from_slice(&0u32.to_be_bytes());
    let key = b"subject.CN";
    expr.extend_from_slice(&(key.len() as u32).to_be_bytes());
    expr.extend_from_slice(key);
    expr.extend_from_slice(&1u32.to_be_bytes());
    expr.extend_from_slice(&(cn.len() as u32).to_be_bytes());
    expr.extend_from_slice(cn.as_bytes());
    while !expr.len().is_multiple_of(4) {
        expr.push(0);
    }
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

Helper `tamper_cd_identifiers(signed: &mut [u8], new_ident: &str)` — rewrite the identifier string in **every** CodeDirectory (primary and alternates), same byte length (the fixture identifier `com.example.dr` and the attacker value `com.evil.plz12` are both 14 bytes):

```rust
fn tamper_cd_identifiers(signed: &mut [u8], new_ident: &str) {
    let m = MachOFile::parse(signed.to_vec()).unwrap();
    let sl = &m.slices()[0];
    let sig_off = sl.code_sig_offset.unwrap() as usize;
    let sig_len = sl.code_sig_size.unwrap() as usize;
    let sb = signed[sig_off..sig_off + sig_len].to_vec();
    let count = u32::from_be_bytes(sb[8..12].try_into().unwrap()) as usize;
    for i in 0..count {
        let e = 12 + i * 8;
        let slot = u32::from_be_bytes(sb[e..e + 4].try_into().unwrap());
        if slot != CSSLOT_CODEDIRECTORY && slot != CSSLOT_ALTERNATE_CODEDIRECTORIES {
            continue;
        }
        let cd = sig_off + u32::from_be_bytes(sb[e + 4..e + 8].try_into().unwrap()) as usize;
        let ident_off = u32::from_be_bytes(signed[cd + 20..cd + 24].try_into().unwrap()) as usize;
        let at = cd + ident_off;
        let old_len = signed[at..].iter().position(|&b| b == 0).unwrap();
        assert_eq!(old_len, new_ident.len(), "same-length identifier tamper");
        signed[at..at + old_len].copy_from_slice(new_ident.as_bytes());
    }
}
```

1. `unimplemented_designated_requirement_opcode_is_invalid`
   - Splice: `replace_requirements_child(&mut signed, &certfield_dr_blob("Whatever"));`
   - `let report = verify_macho(&signed, &SignatureInputs::none()).unwrap();`
   - `assert!(!report.is_valid(), "an unevaluable designated requirement must not verify clean: {:?}", report.slices[0].errors);`
   - `assert!(report.slices[0].errors.iter().any(|e| e.contains("designated requirement not fully evaluated")), "errors: {:?}", report.slices[0].errors);`
   - `assert!(report.slices[0].warnings.iter().all(|w| !w.contains("designated requirement not fully evaluated")), "must not be a warning: {:?}", report.slices[0].warnings);`

2. `tampered_identifier_under_unimplemented_requirement_is_invalid`
   - Splice `certfield_dr_blob("Whatever")`, then `tamper_cd_identifiers(&mut signed, "com.evil.plz12");`
   - `let report = verify_macho(&signed, &SignatureInputs::none()).unwrap();`
   - `assert!(!report.is_valid(), "a tampered identity must never verify valid: {:?}", report.slices[0].errors);`
   - `assert!(report.slices[0].errors.iter().any(|e| e.contains("designated requirement not fully evaluated")), "errors: {:?}", report.slices[0].errors);`
   - `assert_eq!(report.slices[0].identifier.as_deref(), Some("com.evil.plz12"), "the report must surface the bytes actually present");`

Follow the file's assertion idiom: every negative assertion carries a footer printing the actual errors.

- [ ] **Step 2: Run the tests and record the fail-before state**

Run: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-core --lib designated_requirement_opcode_is_invalid`
Run: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-core --lib tampered_identifier_under`
Expected: both FAIL — today the slice is `valid=true`, `errors=[]`, the finding sits in `warnings`. Paste both outputs into the report.

- [ ] **Step 3: Scoped gates**

Run: `cargo fmt --all -- --check` and `cargo clippy -p zsign-core --all-targets -- -D warnings`.
Expected: both clean (red tests must compile warning-free).

- [ ] **Step 4: Controller commits**

Commit message: `test(macho): cover designated requirement strictness`

---

### Task 2: Implement fail-closed recording + `requirement_status`

**Files:**
- Modify: `crates/zsign-core/src/macho/verify.rs` — the `SliceVerifyReport` struct (:39-58) and the designated-requirement block in `verify_slice` (:448-493); inline `mod tests`.

**Interfaces:**
- Consumes: `RequirementVerdict` from `crate::codesign::verify` (already imported in this file), Task 1's two tests.
- Produces: `pub requirement_status: Option<RequirementVerdict>` on `SliceVerifyReport`; `Unsupported` verdicts recorded in `errors` with the exact wording `designated requirement not fully evaluated: {why}`; `requirement_status == Some(verdict)` whenever a DR was evaluated, `None` otherwise. Task 3's binding check and Task 5's JSON field both read this field; the facade and wasm need no changes (the report is built with `..Default::default()`, :132-135).

- [ ] **Step 1: Confirm fail-before**

Run: `TMPDIR=$PWD/target/tmp cargo test -p zsign-core --lib designated_requirement_opcode_is_invalid`
Expected: FAIL (same reason as Task 1, Step 2). Record output.

- [ ] **Step 2: Add the `requirement_status` field**

On `SliceVerifyReport`, after the `warnings` field:

```rust
/// Outcome of the designated-requirement evaluation; `None` when the
/// signature carries no designated requirement.
pub requirement_status: Option<RequirementVerdict>,
```

No constructor change needed — `verify_slice` builds the report with `..SliceVerifyReport::default()`.

- [ ] **Step 3: Record the verdict as an error and store it**

In the `Ok(set) =>` arm of the requirements block, replace the current `match dr.evaluate(&context)` (:480-488) with: evaluate once into `verdict`, match on `&verdict` (so the reason string is not moved), push errors exactly as today's arms do except `Unsupported` pushes into `report.errors` instead of `report.warnings`, then `report.requirement_status = Some(verdict);`. Concretely the three arms:

```rust
RequirementVerdict::Violated => report
    .errors
    .push("designated requirement not satisfied".to_string()),
RequirementVerdict::Unsupported(why) => report
    .errors
    .push(format!("designated requirement not fully evaluated: {why}")),
RequirementVerdict::Satisfied => {}
```

`violated`/`satisfied` wording unchanged; only the target vector of the `Unsupported` arm changes. Do not touch: the malformed-blob arm, the `if let Some(req)` discovery, `cdhashes`/`anchored`/context construction, the CMS block above it, or any neighbouring check. `requirement_status` stays `None` when there is no requirements slot or `set.designated()` is `None`.

- [ ] **Step 4: Add the status-reporting test**

Append to the inline tests (this test references the new field, so it is written with the implementation):

```rust
#[test]
fn requirement_status_reports_evaluation_outcome() {
    let macho = MachOFile::parse(make_minimal_macho()).unwrap();
    let plain = sign_macho_adhoc(&macho, "com.example.dr", None, None, None, false).unwrap();
    let r = verify_macho(&plain, &SignatureInputs::none()).unwrap();
    assert!(r.is_valid(), "{:?}", r.slices[0].errors);
    assert!(r.slices[0].requirement_status.is_none(), "no designated requirement -> None");

    let mut satisfied = sign_macho_adhoc(&macho, "com.example.dr", None, None, None, false).unwrap();
    replace_requirements_child(&mut satisfied, &ident_dr_blob("com.example.dr"));
    let r = verify_macho(&satisfied, &SignatureInputs::none()).unwrap();
    assert!(r.is_valid(), "{:?}", r.slices[0].errors);
    assert_eq!(r.slices[0].requirement_status, Some(RequirementVerdict::Satisfied));

    let mut violated = sign_macho_adhoc(&macho, "com.example.dr", None, None, None, false).unwrap();
    replace_requirements_child(&mut violated, &ident_dr_blob("com.evil"));
    let r = verify_macho(&violated, &SignatureInputs::none()).unwrap();
    assert!(!r.is_valid(), "{:?}", r.slices[0].errors);
    assert_eq!(r.slices[0].requirement_status, Some(RequirementVerdict::Violated));
}
```

(Task 1's two tests additionally pin `matches!(…, Some(RequirementVerdict::Unsupported(_)))`-adjacent behavior through `errors`; add `assert!(matches!(report.slices[0].requirement_status, Some(RequirementVerdict::Unsupported(_))));` to `unimplemented_designated_requirement_opcode_is_invalid` in this step — it can only compile once the field exists.)

- [ ] **Step 5: Run the task tests**

Run: `TMPDIR=$PWD/target/tmp cargo test -p zsign-core --lib designated_requirement`
Run: `TMPDIR=$PWD/target/tmp cargo test -p zsign-core --lib tampered_identifier_under`
Run: `TMPDIR=$PWD/target/tmp cargo test -p zsign-core --lib requirement_status_reports`
Expected: all PASS. Paste outputs.

- [ ] **Step 6: Run the full crate suite**

Run: `TMPDIR=$PWD/target/tmp cargo test -p zsign-core`
Expected: all pass — in particular `designated_requirement_is_enforced_end_to_end`, `anchor_designated_requirement_fails_on_adhoc_slice`, `verify_signed_binary_round_trip` (still exactly one anchoring error), the warning-invalidation pin at :1597, and the window-tail tests. Paste the summary line.

- [ ] **Step 7: Scoped gates**

Run: `cargo fmt --all -- --check` and `cargo clippy -p zsign-core --all-targets -- -D warnings`
Expected: both clean.

- [ ] **Step 8: Controller commits**

Commit message: `fix(macho): fail closed on unevaluable designated requirement`

---

### Task 3: Failing test for team-identifier binding

**Files:**
- Modify: `crates/zsign-core/src/macho/verify.rs` — inline `mod tests`.

**Interfaces:**
- Consumes: `sign_round_trip(&test_signing_credentials(), ident)` (test module :599, fixture cert subject `CN=zsign roundtrip,OU=TESTTEAM`), `verify_macho`, `MachOFile::parse`, the CD/superblob helpers.
- Produces: helper `tamper_cd_team_id` and test `code_directory_team_id_must_match_signer_organizational_unit`. Uses only pre-existing API so it compiles red (the binding error does not exist yet). Task 4 must make it pass without changing its meaning; the single additive assertion in Task 4 Step 4 is the only permitted edit.

- [ ] **Step 1: Write the failing test plus helper**

```rust
/// Rewrite the team-id string in every CodeDirectory (same byte length).
fn tamper_cd_team_id(signed: &mut [u8], new_team: &str) {
    let m = MachOFile::parse(signed.to_vec()).unwrap();
    let sl = &m.slices()[0];
    let sig_off = sl.code_sig_offset.unwrap() as usize;
    let sig_len = sl.code_sig_size.unwrap() as usize;
    let sb = signed[sig_off..sig_off + sig_len].to_vec();
    let count = u32::from_be_bytes(sb[8..12].try_into().unwrap()) as usize;
    for i in 0..count {
        let e = 12 + i * 8;
        let slot = u32::from_be_bytes(sb[e..e + 4].try_into().unwrap());
        if slot != CSSLOT_CODEDIRECTORY && slot != CSSLOT_ALTERNATE_CODEDIRECTORIES {
            continue;
        }
        let cd = sig_off + u32::from_be_bytes(sb[e + 4..e + 8].try_into().unwrap()) as usize;
        let team_off = u32::from_be_bytes(signed[cd + 48..cd + 52].try_into().unwrap()) as usize;
        assert!(team_off != 0, "fixture must carry a CD team id");
        let at = cd + team_off;
        let old_len = signed[at..].iter().position(|&b| b == 0).unwrap();
        assert_eq!(old_len, new_team.len(), "same-length team-id tamper");
        signed[at..at + old_len].copy_from_slice(new_team.as_bytes());
    }
}

#[test]
fn code_directory_team_id_must_match_signer_organizational_unit() {
    let creds = crate::macho::fixtures::test_signing_credentials();
    let signed = sign_round_trip(&creds, "com.example");

    // Baseline: CD team id equals the signer's OU ("TESTTEAM") — no finding.
    let base = verify_macho(&signed, &SignatureInputs::none()).unwrap();
    assert!(
        base.slices[0]
            .errors
            .iter()
            .all(|e| !e.contains("does not match signing certificate organizational unit")),
        "matching team id must not trigger the binding check: {:?}",
        base.slices[0].errors
    );

    // Tamper both CDs: claim a different team than the signing certificate.
    let mut tampered = sign_round_trip(&creds, "com.example");
    tamper_cd_team_id(&mut tampered, "EVILTEAM");
    let report = verify_macho(&tampered, &SignatureInputs::none()).unwrap();
    assert!(
        !report.is_valid(),
        "mismatched team id must fail verification: {:?}",
        report.slices[0].errors
    );
    assert!(
        report.slices[0].errors.iter().any(|e| e.contains(
            "code directory team identifier EVILTEAM does not match signing certificate organizational unit TESTTEAM"
        )),
        "errors: {:?}",
        report.slices[0].errors
    );
}
```

Notes: after the tamper the stored CDHash attributes in the CMS also mismatch, so the slice gains cdhash errors — that is expected; assert only on the presence of the binding message, never on `errors.len()`. Both `TESTTEAM` and `EVILTEAM` are 8 bytes.

- [ ] **Step 2: Run the test and record the fail-before state**

Run: `TMPDIR=$PWD/target/tmp cargo test -p zsign-core --lib code_directory_team_id_must_match`
Expected: FAIL — the tampered fixture produces only the anchoring error (and cdhash errors), never the binding message. Paste output.

- [ ] **Step 3: Scoped gates**

Run: `cargo fmt --all -- --check` and `cargo clippy -p zsign-core --all-targets -- -D warnings`
Expected: both clean.

- [ ] **Step 4: Controller commits**

Commit message: `test(macho): cover team identifier binding to signer`

---

### Task 4: Implement signer-OU plumbing and the binding assertion

**Files:**
- Modify: `crates/zsign-core/src/crypto/cert.rs` — `extract_team_id` (:924-929): `fn` → `pub(crate) fn` only (no logic change).
- Modify: `crates/zsign-core/src/crypto/cms_verify.rs` — `CmsVerifyReport` (:289-330), `StagedSigner` (:734-745), the signer-resolution site that sets `staged.subject` (:948), `StagedSigner::claim_into` (:747-760).
- Modify: `crates/zsign-core/src/macho/verify.rs` — `verify_slice`, between the CMS block and the requirements block; inline `mod tests` (one vacuity assertion).

**Interfaces:**
- Consumes: `crate::crypto::cert::extract_team_id(&Certificate) -> Option<String>`; `CodeDirectory::team_id()`; Task 3's test.
- Produces: `pub signer_ou: Option<String>` on `CmsVerifyReport` (None whenever no signer certificate was resolved — including ad-hoc reports, which build on `..default()`), and the binding error with the exact wording
  `code directory team identifier {cd_team} does not match signing certificate organizational unit {signer_ou}`.
  Task 5 does **not** expose `signer_ou` in JSON; the error message is the evidence surface.

- [ ] **Step 1: Confirm fail-before**

Run: `TMPDIR=$PWD/target/tmp cargo test -p zsign-core --lib code_directory_team_id_must_match`
Expected: FAIL (same reason as Task 3, Step 2). Record output.

- [ ] **Step 2: Widen `extract_team_id` and add `signer_ou` to the CMS report**

In `crypto/cert.rs`, change the signature to `pub(crate) fn extract_team_id(cert: &Certificate) -> Option<String>` (doc comment stays accurate as-is).

In `crypto/cms_verify.rs`:

1. On `CmsVerifyReport`, directly after `signer_serial` (:298):

```rust
/// The signer certificate's subject organizational unit (the Apple Team
/// ID), when the signing certificate was found.
pub signer_ou: Option<String>,
```

2. On `StagedSigner`, after `serial`:

```rust
signer_ou: Option<String>,
```

(`StagedSigner` derives `Default`, so no initializer changes.)

3. Where `staged.subject` is set from the resolved certificate (:948), also set:

```rust
staged.signer_ou = crate::crypto::cert::extract_team_id(cert);
```

4. In `claim_into`, copy it alongside the other scalars:

```rust
report.signer_ou = self.signer_ou.clone();
```

No other construction site needs touching: `adhoc_report()` and the default-based builders pick up `None` automatically. Do not change signer selection, warnings, or validation logic.

- [ ] **Step 3: Add the binding check in `verify_slice`**

In `macho/verify.rs`, after the `if let Some(cms_blob) = superblob.cms { … } else if …` CMS block and **before** the `if let Some(req) = superblob.entries.iter().find(…)` requirements block:

```rust
// The CD's team identifier is self-asserted metadata; bind it to the
// signer's certificate OU when both are present.
if let (Some(cd_team), Some(signer_ou)) = (
    primary.team_id(),
    report
        .cms
        .as_ref()
        .and_then(|cms| cms.signer_ou.as_deref()),
) {
    if cd_team != signer_ou {
        report.errors.push(format!(
            "code directory team identifier {cd_team} does not match signing certificate organizational unit {signer_ou}"
        ));
    }
}
```

Do not touch the surrounding blocks (anchored computation, cdhashes, requirements evaluation, cross-CD checks).

- [ ] **Step 4: Add the vacuity assertion to Task 3's test**

In `code_directory_team_id_must_match_signer_organizational_unit`, inside the baseline block, assert the plumbing is real:

```rust
assert_eq!(
    base.slices[0].cms.as_ref().unwrap().signer_ou.as_deref(),
    Some("TESTTEAM"),
    "the signer's OU must reach the verify report"
);
```

- [ ] **Step 5: Run the task tests**

Run: `TMPDIR=$PWD/target/tmp cargo test -p zsign-core --lib code_directory_team_id_must_match`
Expected: PASS. Paste output.

- [ ] **Step 6: Run the full crate suite**

Run: `TMPDIR=$PWD/target/tmp cargo test -p zsign-core`
Expected: all pass — the binding check must add **no** finding to any fixture where CD team and cert OU match: `verify_signed_binary_round_trip` keeps asserting exactly one error (`not anchored to a trusted root`). Paste the summary line.

- [ ] **Step 7: Scoped gates**

Run: `cargo fmt --all -- --check` and `cargo clippy -p zsign-core --all-targets -- -D warnings`
Expected: both clean.

- [ ] **Step 8: Controller commits**

Commit message: `fix(verify): bind code directory team identifier to signer ou`

---

### Task 5: Surface `requirement_status` in the CLI JSON output

**Files:**
- Modify: `crates/zsign-cli/src/main.rs` — `SliceDto` (:828-840 region) and its `From` impl; the JSON DTO area near `SlotCheckDto`; test `json_verify_valid_and_invalid_documents` (:1444).

**Interfaces:**
- Consumes: `zsign_rs::verify::SliceVerifyReport.requirement_status: Option<RequirementVerdict>` (Task 2) and `zsign_rs::codesign::verify::RequirementVerdict` (facade re-export; confirm the exact path compiles).
- Produces: JSON field `slices[].requirement_status` with the stable v1 vocabulary `absent` | `satisfied` | `violated` | `not_evaluated`.

- [ ] **Step 1: Add the DTO enum and field**

Near `SlotCheckDto`, following its exact style (and add `use zsign_rs::codesign::verify::RequirementVerdict;` to the imports — the CLI already imports siblings from that path at `main.rs:9`):

```rust
#[derive(serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum RequirementStatusDto {
    Absent,
    Satisfied,
    Violated,
    NotEvaluated,
}
```

On `SliceDto`, after `warnings`:

```rust
requirement_status: RequirementStatusDto,
```

In `impl From<&SliceVerifyReport> for SliceDto`, map:

- `None` → `RequirementStatusDto::Absent`
- `Some(RequirementVerdict::Satisfied)` → `Satisfied`
- `Some(RequirementVerdict::Violated)` → `Violated`
- `Some(RequirementVerdict::Unsupported(_))` → `NotEvaluated`

No other DTO, status, or exit mapping changes; the schema-version comment at :747-752 stays as-is (the change is additive).

- [ ] **Step 2: Extend the JSON verify test**

In `json_verify_valid_and_invalid_documents`, alongside the existing `slices[0]` assertions (:1470-1479), add:

```rust
assert_eq!(
    doc["report"]["macho"]["slices"][0]["requirement_status"], "absent",
    "the signed fixture carries no designated requirement"
);
```

(The signed CLI fixture's requirements slot holds no designated requirement, so `absent` is the correct pin.)

- [ ] **Step 3: Run the CLI tests**

Run: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-cli`
Expected: all pass. Paste the summary line.

- [ ] **Step 4: Scoped gates**

Run: `cargo fmt --all -- --check` and `cargo clippy -p zsign-cli --all-targets -- -D warnings`
Expected: both clean.

- [ ] **Step 5: Controller commits**

Commit message: `feat(cli): report designated requirement status in verify json`
