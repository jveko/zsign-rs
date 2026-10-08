# DER entitlement reader fixes — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development
> with dispatching-parallel-agents for independent tasks to implement this plan
> task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the DER entitlement reader decode every writer-produced
negative/large INTEGER correctly and reject duplicate dictionary keys instead
of collapsing them last-wins.

**Architecture:** Both fixes live in one file,
`crates/zsign-core/src/codesign/verify.rs`: a corrected sign seed in
`der_integer`, a size-guard ceiling of 9 content octets, and an
`insert`-return duplicate check in `decode_der_entries`. The writer
(`der.rs`) is reference-only; tests round-trip through
`plist_to_der` → `der_entitlements_to_plist`.

**Tech Stack:** Rust (edition 2021), `plist` 1.10.1, cargo test/clippy/fmt.

**Spec:** `docs/superpowers/specs/2026-10-08-der-reader-signed-integer-and-duplicate-keys-design.md`

## Global Constraints

- Sole edited file: `crates/zsign-core/src/codesign/verify.rs`. `der.rs`,
  `macho/*`, facade, and CLI files are never edited by this plan.
- Zero-warning gate before the item closes:
  `cargo fmt --all -- --check` and
  `cargo clippy --workspace --all-targets -- -D warnings`, both clean.
- Tests run as `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test …`
  (`/tmp` is a small tmpfs; TMPDIR must stay in the worktree).
- No ticket IDs, no TODOs, no stubs anywhere (code, comments, docs, commits).
- Commits are controller-owned (the orchestrator commits after each task is
  green); implementers and testers never commit. Commit subjects: conventional,
  imperative, lowercase, no trailing period.
- Duplicate-key rejection is parser-divergence hardening, never described as
  an X.690 conformance requirement (X.690 11.6 is ordering only; X.680 28.3
  NOTE 3 allows repeated SET OF elements — see spec).
- The minimality check `prefix.len() - significant > 1` stays byte-for-byte
  as-is (its laxness is another ticket's ownership); only the adjacent size
  ceiling changes `8` → `9`.

## Review Focus

- **9-octet inputs other than i64::MAX:** minimal positive `00 FF×8` must
  decode to i64::MAX; minimal negative 9-octet encodings must still be
  rejected by `i64::try_from` with the existing message — Task 1's table
  covers i64::MAX; the oversized path is covered by the unchanged
  `der_malformed_is_error` plus Task 1's run of the whole crate module.
- **Seed double-count:** folding `prefix` (not `content`) after seeding from
  `first` must leave positives and zero bit-identical — Task 1's table keeps
  0 and uses only writer-produced inputs, so a double-counted first byte
  shows immediately.
- **Distinct keys must not trip the duplicate check** (including the v0/v1
  shapes already in the file) — Task 2's control half asserts two distinct
  pairs parse, and the scoped run re-executes `der_v0_and_v1_shapes_parse`.
- **Error variant stability:** the duplicate rejection must stay
  `crate::Error::DerEncoding` so `macho/verify.rs:271-273`'s report-string
  path is untouched — Task 2's assertion matches that exact variant.
- **Format/lint drift in a 2288-line file:** Task 3 runs the fmt check and
  clippy `-D warnings` over the workspace, not just the crate.

---

### Task 1: Signed-integer round-trip test + `der_integer` fix

**Files:**
- Modify: `crates/zsign-core/src/codesign/verify.rs` (function `der_integer`,
  currently :1081-1104)
- Test: same file, `#[cfg(test)] mod tests` (new test beside
  `der_entitlements_round_trip` at :1668)

**Interfaces:**
- Consumes: `crate::codesign::der::plist_to_der(plist_xml: &[u8]) -> Result<Vec<u8>>`
  and `der_entitlements_to_plist(content: &[u8]) -> Result<plist::Value>`
  (both already exist; no signature changes).
- Produces: corrected `der_integer(content: &[u8]) -> Result<plist::Value>`
  semantics — every canonical i64 encoding round-trips; everything else keeps
  its current accept/reject behavior. No other task depends on new names.

- [ ] **Step 1: Write the failing test**

Add to the test module in `crates/zsign-core/src/codesign/verify.rs`:

```rust
#[test]
fn der_integers_round_trip_signed_extremes() {
    // Writer -> reader: each value is encoded by der::plist_to_der and must
    // decode back unchanged. 0 is the control that already passed.
    for value in [-1i64, -128, -129, -2_147_483_648, i64::MIN, i64::MAX, 0] {
        let xml = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>v</key><integer>{value}</integer></dict></plist>"#
        );
        let der = crate::codesign::der::plist_to_der(xml.as_bytes()).unwrap();
        let decoded = der_entitlements_to_plist(&der).unwrap();
        let got = decoded
            .as_dictionary()
            .and_then(|dict| dict.get("v"))
            .and_then(|v| v.as_integer());
        assert_eq!(got, Some(value), "round trip of {value}");
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-core der_integers_round_trip_signed_extremes`
Expected: FAIL — either an assertion mismatch (−1, −128, −129, −2^31, i64::MIN
decode wrong) or an `.unwrap()` panic on `Err("DER encoding error: non-minimal
or oversized DER INTEGER")` for i64::MAX. Record which values failed and how.

- [ ] **Step 3: Fix `der_integer` in `crates/zsign-core/src/codesign/verify.rs`**

Replace the size guard `content.len() > 8` (in
`if prefix.len() - significant > 1 || content.len() > 8`) with
`content.len() > 9` — the widest canonical i64 INTEGER is 9 content octets;
`i64::try_from` below still rejects out-of-range values.

Replace the seed + loop:

```rust
let mut value = if negative {
    -1i128 << (8 * content.len())
} else {
    0
};
for &byte in content {
    value = (value << 8) | byte as i128;
}
```

with:

```rust
let mut value = if negative {
    first as i128 - 256
} else {
    first as i128
};
for &byte in prefix {
    value = (value << 8) | byte as i128;
}
```

Nothing else in the function changes: the `split_first`, the minimality
pre-check expression (other than the literal `8` → `9`), and the
`i64::try_from(...)` conversion stay byte-for-byte.

- [ ] **Step 4: Run the test to verify it passes**

Run: `TMPDIR=$PWD/target/tmp cargo test -p zsign-core der_integers_round_trip_signed_extremes`
Expected: PASS — `7 passed` loop iterations inside 1 test.

- [ ] **Step 5: Run the whole zsign-core crate to catch regressions**

Run: `TMPDIR=$PWD/target/tmp cargo test -p zsign-core`
Expected: all tests pass (in particular `der_entitlements_round_trip`,
`der_v0_and_v1_shapes_parse`, `der_malformed_is_error`,
`test_encode_integer_*` in der.rs stay green).

- [ ] **Step 6: Controller commit (not an implementer step)**

The orchestrator stages exactly `crates/zsign-core/src/codesign/verify.rs`
and commits `fix(codesign): decode negative der integers with a first-octet sign seed`.

### Task 2: Duplicate-key rejection test + `decode_der_entries` fix

**Files:**
- Modify: `crates/zsign-core/src/codesign/verify.rs` (function
  `decode_der_entries`, insert at :1199)
- Test: same file's test module

**Interfaces:**
- Consumes: `der_error(message: impl Into<String>) -> crate::Error` (:1040)
  and `plist::Dictionary::insert(k, v) -> Option<Value>` (returns displaced
  value; locked plist 1.10.1).
- Produces: `decode_der_entries` still returns `Result<plist::Value>`; on a
  repeated key it now returns `Err(crate::Error::DerEncoding(...))` whose
  message contains `duplicate key`. No signature change.

- [ ] **Step 1: Write the failing test**

Add beside Task 1's test:

```rust
#[test]
fn der_entries_reject_duplicate_keys() {
    // Two-entry SET (v0 shape): distinct keys parse...
    let distinct = [
        0x31, 0x10, 0x30, 0x06, 0x0c, 0x01, b'k', 0x0c, 0x01, b'a', 0x30, 0x06, 0x0c, 0x01, b'j',
        0x0c, 0x01, b'b',
    ];
    let parsed = der_entitlements_to_plist(&distinct).unwrap();
    let dict = parsed.as_dictionary().unwrap();
    assert_eq!(dict.get("k").and_then(|v| v.as_string()), Some("a"));
    assert_eq!(dict.get("j").and_then(|v| v.as_string()), Some("b"));

    // ...the same shape with a repeated key is rejected (last-wins vs
    // first-wins vs reject is a consumer divergence; we fail closed).
    let duplicate = [
        0x31, 0x10, 0x30, 0x06, 0x0c, 0x01, b'k', 0x0c, 0x01, b'a', 0x30, 0x06, 0x0c, 0x01, b'k',
        0x0c, 0x01, b'b',
    ];
    let res = der_entitlements_to_plist(&duplicate);
    assert!(
        matches!(&res, Err(crate::Error::DerEncoding(m)) if m.contains("duplicate key")),
        "duplicate key must be rejected, got {:?}",
        res.as_ref().err()
    );
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `TMPDIR=$PWD/target/tmp cargo test -p zsign-core der_entries_reject_duplicate_keys`
Expected: FAIL on the `matches!` assertion — today the parse succeeds with
`Ok` (last-wins), so `got` prints the decoded dictionary. The distinct-keys
control half passes.

- [ ] **Step 3: Enforce the duplicate check in `decode_der_entries`**

Replace the bare insert:

```rust
dictionary.insert(key, decode_der_value(value_tag, value_bytes, depth + 1)?);
```

with:

```rust
if dictionary
    .insert(key, decode_der_value(value_tag, value_bytes, depth + 1)?)
    .is_some()
{
    return Err(der_error(format!(
        "DER entitlement entry has duplicate key '{key}'"
    )));
}
```

No other line of the loop changes; the value decode still runs as the
`insert` argument (nested duplicates error first — accepted, see spec D3).

- [ ] **Step 4: Run the test to verify it passes**

Run: `TMPDIR=$PWD/target/tmp cargo test -p zsign-core der_entries_reject_duplicate_keys`
Expected: PASS.

- [ ] **Step 5: Run the whole zsign-core crate**

Run: `TMPDIR=$PWD/target/tmp cargo test -p zsign-core`
Expected: all tests pass — both new tests plus the pre-existing DER suite.

- [ ] **Step 6: Controller commit (not an implementer step)**

Stage exactly `crates/zsign-core/src/codesign/verify.rs` and commit
`fix(codesign): reject duplicate keys in der entitlement entries`.

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
Expected: all workspace tests pass (wasm crate's native unit tests included).

Acceptance for the item: Steps 1-3 all exit 0 with no warnings and no test
failures, and both fix commits exist on the branch.
