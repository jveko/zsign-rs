# ZSN-94 Dead DER Branch & Unused Constants Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development (recommended) with dispatching-parallel-agents for independent tasks to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Delete one unreachable error branch in `plist_to_der` and the 66 definition-only constants in `codesign/constants.rs`, with unchanged behavior and zero new warnings.

**Architecture:** Two independent single-file deletions in `zsign-core`. No API/behavior change: the removed branch was unreachable (min output is the 7-byte canonical envelope pinned by `test_plist_to_der_empty`), and the removed constants have zero references workspace-wide. `Error::DerEncoding(String)` survives with its other construction sites.

**Tech Stack:** Rust 2021 / cargo / thiserror; gates via `cargo fmt`, `cargo clippy`, `cargo test -p zsign-core`.

**Spec:** `docs/superpowers/specs/2026-10-07-zsn-94-dead-der-branch-design.md` — the plan argues from the spec; executors read both.

## Global Constraints

- Files in scope ONLY: `crates/zsign-core/src/codesign/der.rs` and `crates/zsign-core/src/codesign/constants.rs` (plus their inline `#[cfg(test)]` modules). Nothing else — no `macho/`, no `crypto/`, no `superblob.rs` comment edits, no drive-by refactors.
- Do NOT remove the `Error::DerEncoding(String)` variant (error.rs:37-38) — only the `"Empty DER output"` construction site.
- Keep every constant with any workspace reference (56 of 122); delete exactly the 66 definition-only ones listed in Task 2.
- Zero new warnings: `cargo clippy -p zsign-core --all-targets -- -D warnings` must stay clean.
- No `TODO`/stubs/placeholders; no commits by subagents (controller commits); ticket ID never in code comments.
- Scope gates only (no project-wide cold gates): `cargo fmt --all -- --check`; `cargo clippy -p zsign-core --all-targets -- -D warnings`; `cargo test -p zsign-core`.

## Review Focus

- Broken intra-doc links: module doc (constants.rs:1-34) links constants with `[`…`]` — verify every linked name survives (all links point at kept constants).
- Missed reference: a "dead" constant actually used via glob import (`verify.rs`, `code_directory.rs`, `superblob.rs`, `macho/verify.rs` import `constants::*`) — re-grep each of the 66 immediately before deletion; any hit moves it to the kept list.
- Dangling section headers: full-group deletions (all 24 `OP_*`, all 15 `MATCH_*`) must remove their `// ===` section header comments.
- Behavior pin: `test_plist_to_der_empty` (der.rs:465, exact 7 bytes) and both doctests asserting `!der.is_empty()` must still pass unchanged.
- Payload uniqueness: `"Empty DER output"` must vanish workspace-wide while other `DerEncoding` constructors remain.

These map to Task 1 steps 2/3 and Task 2 steps 1/3/4 below.

---

## Task 1: Remove unreachable empty-DER branch in `plist_to_der`

**Files:**
- Modify: `crates/zsign-core/src/codesign/der.rs` (function tail at :375-379; `# Errors` bullet at :327)
- Test: none created — this is pure dead-code removal; the EXISTING suite is the regression proof (stated explicitly per brief). The `Err` arm was unexercisable, so no test can fail-then-pass on its removal; `test_plist_to_der_empty` (der.rs:451-466) already pins the observable output.

**Interfaces:**
- Consumes: nothing new.
- Produces: `pub fn plist_to_der(plist_xml: &[u8]) -> Result<Vec<u8>>` — unchanged signature, now ending in `Ok(der)`.

- [ ] **Step 1: Baseline the existing der tests**

Run: `cargo test -p zsign-core der`
Expected: PASS (baseline before the edit; record the summary line).

- [ ] **Step 2: Replace the `if/else` tail with a direct `Ok(der)`**

In `der.rs`, replace exactly:

```rust
    if der.is_empty() {
        Err(Error::DerEncoding("Empty DER output".into()))
    } else {
        Ok(der)
    }
```

with:

```rust
    Ok(der)
```

- [ ] **Step 3: Delete the obsolete `# Errors` bullet**

In the `plist_to_der` doc comment, delete the single line:

```rust
/// - The resulting DER encoding is empty
```

(The remaining bullets — parse failure, non-dictionary root, Real type, i64 range, GeneralizedTime range — all still correspond to live `Err` arms.)

- [ ] **Step 4: Verify payload gone, behavior unchanged**

Run: `grep -rn "Empty DER output" crates/ fuzz/`
Expected: no output.
Run: `cargo test -p zsign-core der`
Expected: PASS, same test set as baseline (includes `test_plist_to_der_empty`, `test_plist_to_der_simple`, doctests at der.rs:26/:332).

---

## Task 2: Delete the 66 definition-only constants from `constants.rs`

**Files:**
- Modify: `crates/zsign-core/src/codesign/constants.rs` (definitions + doc comments at :41-452; section headers)
- Test: none created — deletion contract is compile + clippy + unchanged existing suite (the inline test module :454-514 references none of the 66; stated explicitly per brief).

**Interfaces:**
- Consumes: the audit list below (66 identifiers, proven definition-only workspace-wide including crates/, fuzz/, tests, docs, comments, strings, doctests).
- Produces: `constants.rs` exporting exactly the 56 referenced constants; no other file changes.

- [ ] **Step 1: Re-verify liveness per identifier immediately before deletion**

For each of the 66 identifiers below, run `grep -rn "\b<IDENT>\b" crates/ fuzz/` and confirm the ONLY hit is its own definition (+ doc comment) inside `constants.rs`. If ANY hit appears elsewhere, keep that constant, note it in the report, and continue with the rest.

The 66 (file order):

```
CSMAGIC_DETACHED_SIGNATURE
CSSLOT_INFOSLOT
CSSLOT_RESOURCEDIR
CSSLOT_APPLICATION
CSSLOT_REP_SPECIFIC
CSSLOT_SPECIAL_APPLICATION
CSSLOT_SPECIAL_REP_SPECIFIC
CS_HASHTYPE_NOHASH
CS_HASHTYPE_SHA256_TRUNCATED
CS_HASHTYPE_SHA384
CS_HASHTYPE_SHA512
CS_MAX_HASH_LEN
CS_VALID
CS_HARD
CS_KILL
CS_RESTRICT
CS_ENFORCEMENT
CS_REQUIRE_LV
CS_ENTITLEMENTS_VALIDATED
CS_NVRAM_UNRESTRICTED
CS_LINKER_SIGNED
CS_EXECSEG_CAN_LOAD_CDHASH
CS_EXECSEG_CAN_EXEC_CDHASH
OP_FALSE
OP_TRUE
OP_IDENT
OP_APPLE_ANCHOR
OP_ANCHOR_HASH
OP_INFO_KEY_VALUE
OP_AND
OP_OR
OP_CDHASH
OP_NOT
OP_INFO_KEY_FIELD
OP_CERT_FIELD
OP_TRUSTED_CERT
OP_TRUSTED_CERTS
OP_CERT_GENERIC
OP_APPLE_GENERIC_ANCHOR
OP_ENTITLEMENT_FIELD
OP_CERT_POLICY
OP_NAMED_ANCHOR
OP_NAMED_CODE
OP_PLATFORM
OP_NOTARIZED
OP_CERT_FIELD_DATE
OP_LEGACY_DEV_ID
CSREQ_HOST
CSREQ_GUEST
CSREQ_LIBRARY
CSREQ_PLUGIN
MATCH_EXISTS
MATCH_EQUAL
MATCH_CONTAINS
MATCH_BEGINS_WITH
MATCH_ENDS_WITH
MATCH_LESS_THAN
MATCH_GREATER_THAN
MATCH_LESS_THAN_OR_EQUAL
MATCH_GREATER_THAN_OR_EQUAL
MATCH_ON
MATCH_BEFORE
MATCH_AFTER
MATCH_ON_OR_BEFORE
MATCH_ON_OR_AFTER
MATCH_ABSENT
```

- [ ] **Step 2: Delete each constant with its doc comment**

Remove each listed identifier's `///` doc comment block and its `pub const …;` line. Do not touch neighboring kept constants or their docs.

- [ ] **Step 3: Remove the two now-empty section headers**

After deletion, the Opcodes group (all 24 `OP_*`) and the Match group (all 15 `MATCH_*`) are empty: delete their `// ==== … ====` header comment blocks too (no dangling empty sections). Every other section keeps ≥1 constant and its header.

- [ ] **Step 4: Verify zero survivors and zero references**

Run: `grep -rn -E "\b(CSMAGIC_DETACHED_SIGNATURE|OP_AND|MATCH_EQUAL|CS_VALID|CSREQ_HOST)\b" crates/ fuzz/` (spot check; repeat per-identifier as needed)
Expected: no output — and for the full list, no identifier from Step 1 appears anywhere outside git history.
Run: `cargo test -p zsign-core` (doctests included → catches broken intra-doc links in constants.rs:1-34)
Expected: PASS, identical suite to the pre-edit run of the same command (deletion must not remove or skip any test).

---

## Final gate (controller-run, both tasks committed)

- [ ] `cargo fmt --all -- --check` → clean
- [ ] `cargo clippy -p zsign-core --all-targets -- -D warnings` → clean
- [ ] `cargo test -p zsign-core` → PASS
- [ ] `git status --porcelain` → empty after commits
