# Native Provisioning-Profile Size Cap Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development with
> dispatching-parallel-agents for independent tasks. Steps use checkbox (`- [ ]`)
> syntax for tracking.

**Goal:** Enforce a 16 MiB `MAX_PROFILE_BYTES` cap inside `zsign-core::provisioning`
before any byte scanning, on native and wasm surfaces, via `Error::InputTooLarge`.

**Architecture:** Single constant + private size-check helper in core; the check is
the first statement of the two funnel functions (`validate_and_extract_profile`,
`profile_document`); a new core error variant maps through the facade `From` impl to
the live `zsign_rs::Error::InputTooLarge`; wasm re-exports the core constant and adds
the compile-forced `code_for_core_error` arm.

**Tech Stack:** Rust workspace (zsign-core, zsign-rs facade, zsign-wasm), thiserror,
plist 1.10.1. Spec: `docs/superpowers/specs/2026-09-28-native-profile-cap-design.md`.

**Conventions:** `TMPDIR=$PWD/target/tmp` (create with `mkdir -p target/tmp`) for all
test runs. Scoped commands while iterating; workspace gate once at the end. No ticket
IDs in code comments. TDD: Task 1/2 tests fail first.

---

### Task 1: Core cap + error variant + forced wasm arm + native tests (TDD)

**Files:**
- Modify: `crates/zsign-core/src/error.rs` (new variant at end of enum, ~line 41)
- Modify: `crates/zsign-core/src/provisioning.rs` (constant, helper, two funnel checks, tests)
- Modify: `crates/zsign-wasm/src/lib.rs:141-154` (`code_for_core_error` — compile-forced new arm)
- Test: inline `#[cfg(test)] mod tests` in both core files (existing modules)

- [ ] **Step 1.1: Write failing tests in `provisioning.rs` tests module**

Add these tests (follow the file's existing idiom:
`assert!(matches!(&res, Err(Error::Variant(m)) if m.contains("…")), "…, got {:?}", res.as_ref().err());`):

```rust
#[test]
fn oversized_profile_is_rejected_before_any_scanning() {
    let big = vec![0u8; 17 * 1024 * 1024];
    let req = ProfileRequest::default();
    let res = validate_and_extract_profile(&big, &req);
    assert!(
        matches!(&res, Err(Error::InputTooLarge(m)) if m.contains("17825792") && m.contains("16777216")),
        "expected pre-scan InputTooLarge, got {:?}", res.as_ref().err()
    );
    let res = profile_document(&big);
    assert!(
        matches!(&res, Err(Error::InputTooLarge(_))),
        "expected pre-scan InputTooLarge, got {:?}", res.as_ref().err()
    );
    let res = extract_entitlements_from_profile(&big);
    assert!(
        matches!(&res, Err(Error::InputTooLarge(_))),
        "expected pre-scan InputTooLarge, got {:?}", res.as_ref().err()
    );
    for allow_unsafe in [false, true] {
        let res = extract_entitlements_checked(&big, &req, allow_unsafe);
        assert!(
            matches!(&res, Err(Error::InputTooLarge(_))),
            "allow_unsafe={allow_unsafe}: expected pre-scan InputTooLarge, got {:?}",
            res.as_ref().err()
        );
    }
}
```

The 17 MiB buffer contains no `<?xml ` marker and no CMS envelope: reaching the
scanner would yield `ProvisioningProfile("No XML plist found …")` (or a CMS error),
so observing `InputTooLarge` proves the cap ran first — no O(n) window scan occurred.

```rust
#[test]
fn exactly_at_the_cap_is_not_rejected_by_the_size_guard() {
    let big = vec![0u8; MAX_PROFILE_BYTES];
    let res = profile_document(&big);
    assert!(
        !matches!(&res, Err(Error::InputTooLarge(_))),
        "exactly-at-limit input must pass the cap, got {:?}", res.as_ref().err()
    );
    // Garbage at the limit still fails parsing, just not on size:
    assert!(matches!(&res, Err(Error::ProvisioningProfile(_))), "got {:?}", res.as_ref().err());
}
```

```rust
#[test]
fn hundred_kb_valid_profile_still_validates() {
    let pad = "x".repeat(100 * 1024);
    let xml = plist_xml(&format!(
        "<key>PPDDebugInfo</key>\n  <string>{pad}</string>\n"
    ));
    let sp = signed_profile(&xml);
    let req = request(&sp, 1_770_000_000); // inside the 2026-01-01..2026-07-01 window
    let info = validate_and_extract_profile(&sp.data, &req)
        .expect("100 KB profile must validate");
    assert!(info.entitlements_xml.is_some());
    let raw = extract_entitlements_checked(&sp.data, &req, false)
        .expect("checked seam must accept a 100 KB profile");
    assert!(raw.is_some());
}
```

```rust
#[test]
fn wide_fifty_thousand_element_document_parses_as_today() {
    let mut xml = String::from(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><array>"#,
    );
    for i in 0..50_000 {
        xml.push_str(&format!("<string>element-{i:06}</string>"));
    }
    xml.push_str("</array></plist>");
    let mut profile = vec![b'X'; 64];
    profile.extend_from_slice(xml.as_bytes());
    profile.extend_from_slice(b"Y".repeat(64).as_slice());
    let res = profile_document(&profile);
    assert!(
        matches!(&res, Ok(plist::Value::Array(a)) if a.len() == 50_000),
        "50k-element document must parse exactly as today (no element budget), got {:?}",
        res.as_ref().map(|v| format!("{v:?}").len()).map_err(|e| e.to_string())
    );
}
```

(50k elements × ~30 bytes ≈ 1.5 MB — if measured size differs from the brief's
550 KB estimate, the pin is the *behavior* (parses OK), not the byte count; adjust
comment accordingly. Measure with `xml.len()` in-test if desired.)

- [ ] **Step 1.2: Run tests, verify FAIL with compile error (variant missing)**

Run: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-core oversized_profile -- --nocapture`
Expected: compile error `no variant named InputTooLarge found on enum Error` — proves tests precede implementation.

- [ ] **Step 1.3: Add core error variant**

In `crates/zsign-core/src/error.rs`, append as the last variant (after `Verification`):

```rust
    /// An input exceeds its published size limit; rejected before any parsing.
    #[error("Input too large: {0}")]
    InputTooLarge(String),
```

- [ ] **Step 1.4: Satisfy the compile-forced wasm match arm**

`code_for_core_error` (`crates/zsign-wasm/src/lib.rs:141-154`) is an exhaustive
match with no wildcard, so this variant is a forced compile error there. Add before
the match's closing brace:

```rust
        zsign_core::Error::InputTooLarge(_) => WasmErrorCode::InputTooLarge,
```

This is the only Task 1 touch in wasm — the constant re-export and the facade `From`
arm stay in Task 2. Run `cargo check --workspace --all-targets` here to confirm every
commit in this plan compiles workspace-wide.

- [ ] **Step 1.5: Implement cap in `provisioning.rs`**

Near the top of the module (after imports / before first use), add:

```rust
/// Maximum accepted size of a provisioning profile, shared by every surface.
/// Inputs above this limit are rejected before any byte scanning or parsing.
pub const MAX_PROFILE_BYTES: usize = 16 * 1024 * 1024;

fn ensure_profile_size(profile_data: &[u8]) -> Result<()> {
    let len = profile_data.len();
    if len > MAX_PROFILE_BYTES {
        return Err(Error::InputTooLarge(format!(
            "provisioning profile is {len} bytes; the limit is {MAX_PROFILE_BYTES} bytes"
        )));
    }
    Ok(())
}
```

Insert `ensure_profile_size(profile_data)?;` as the **first statement** of
`validate_and_extract_profile` (before `resolve_now`) and of `profile_document`
(before `windows(6)`). Update both functions' `# Errors`/doc comments to mention the
size rejection. Do NOT add the check to `extract_entitlements_from_profile` /
`extract_entitlements_checked` — they delegate; add a one-line doc note pointing at
the funnel invariants instead.

- [ ] **Step 1.6: Run scoped tests, expect PASS**

Run: `TMPDIR=$PWD/target/tmp cargo test -p zsign-core`
Expected: all pass (baseline ~N core tests + 4 new).

- [ ] **Step 1.7: Commit**

Run: `git add crates/zsign-core/src/error.rs crates/zsign-core/src/provisioning.rs crates/zsign-wasm/src/lib.rs && git commit -m "enforce profile size cap in core before scanning"`

---

### Task 2: Facade mapping + wasm constant reuse

**Files:**
- Modify: `crates/zsign/src/error.rs:62-68` (`From<zsign_core::Error>` impl)
- Modify: `crates/zsign-wasm/src/lib.rs:75-76` (constant → re-export)
- Test: facade `crates/zsign/src/error.rs` tests (add module if absent); wasm tests stay green

- [ ] **Step 2.1: Write failing facade test**

In `crates/zsign/src/error.rs` (extend existing `mod tests` or add one):

```rust
#[test]
fn core_input_too_large_maps_to_the_live_facade_variant() {
    let core_err: zsign_core::Error = zsign_core::Error::InputTooLarge(
        "provisioning profile is 17825792 bytes; the limit is 16777216 bytes".into(),
    );
    let err: Error = core_err.into();
    assert!(
        matches!(&err, Error::InputTooLarge(m) if m.contains("16777216")),
        "got {err:?}"
    );
    assert_eq!(
        err.to_string(),
        "Input too large: provisioning profile is 17825792 bytes; the limit is 16777216 bytes"
    );
}
```

- [ ] **Step 2.2: Run, verify FAIL (lands in `Error::Core` today)**

Run: `TMPDIR=$PWD/target/tmp cargo test -p zsign-rs core_input_too_large`
Expected: FAIL — `got Core(InputTooLarge(...))`.

- [ ] **Step 2.3: Add the facade `From` arm**

In `crates/zsign/src/error.rs` `impl From<zsign_core::Error>`, insert before the
wildcard arm:

```rust
        zsign_core::Error::InputTooLarge(m) => Error::InputTooLarge(m),
```

- [ ] **Step 2.4: Wasm constant becomes a re-export**

In `crates/zsign-wasm/src/lib.rs`, replace:

```rust
/// Maximum size of a provisioning profile.
const MAX_PROFILE_BYTES: usize = 16 * 1024 * 1024;
```

with (adding the import alongside the crate's existing `use` block):

```rust
use zsign_core::provisioning::MAX_PROFILE_BYTES;
```

(Doc comment moves to the core constant; no local wrapper const — the two
`ensure_size(..., MAX_PROFILE_BYTES, ...)` call sites and all tests compile
unchanged. Value identical by construction.)

- [ ] **Step 2.5: Run scoped gates**

Run: `TMPDIR=$PWD/target/tmp cargo test -p zsign-rs && cargo check -p zsign-wasm`
Expected: PASS / no errors. Then, if `wasm-pack` is available:
`wasm-pack test --node crates/zsign-wasm` — all wasm tests green (the existing
oversize tests at `lib.rs:1400-1420`, `:1466-1469` unmodified). If wasm-pack is
missing from the environment, record that and rely on `cargo check -p zsign-wasm`
plus the native unit tests of the wasm crate (`cargo test -p zsign-wasm`).

- [ ] **Step 2.6: Commit**

Run: `git add crates/zsign/src/error.rs crates/zsign-wasm/src/lib.rs && git commit -m "map core size cap through facade and wasm"`

---

### Task 3: Workspace zero-warning gate (final verification)

**Files:** none modified; verification only.

- [ ] **Step 3.1: Format check**

Run: `cargo fmt --all -- --check`
Expected: clean (no output).

- [ ] **Step 3.2: Clippy gate**

Run: `TMPDIR=$PWD/target/tmp cargo clippy --workspace --all-targets -- -D warnings`
Expected: zero warnings.

- [ ] **Step 3.3: Full workspace test suite**

Run: `TMPDIR=$PWD/target/tmp cargo test --workspace`
Expected: ≥760 passed / 1 ignored (baseline was 760/1; this change adds ≥4 tests —
expect 764+ passed / 1 ignored; report exact numbers).

- [ ] **Step 3.4: Confirm no scope leakage**

Run: `git diff --stat main...HEAD` and `git status --porcelain`
Expected: only `crates/zsign-core/src/{error,provisioning}.rs`,
`crates/zsign/src/error.rs`, `crates/zsign-wasm/src/lib.rs`, plus the two
`docs/superpowers/**` files; no README/docs tables, no verify.rs/Mach-O/CLI changes,
no ticket IDs inside source comments (`git diff main...HEAD | grep -i 'ZSN-123'`
must hit only commit subjects — verify via `git log main..HEAD --format=%s`).

---

## Plan self-review (writing-plans checklist)

- **Spec coverage:** D1 → Task 1 Step 1.5; D2 → Step 1.5 funnel placement;
  D3 → Step 1.3; D4 → Task 2 Steps 2.1-2.3; D5 → Step 1.4 (forced wasm arm) +
  Step 2.4 (constant re-export), byte-identity via unchanged `ensure_size` call
  sites + green unmodified wasm tests (Step 2.5); D6 → Step 1.5 (`len > MAX`) +
  boundary test; D7 → Task 1 wide-document pin test.
  Test contract items 1-5 map to: oversized (1.1), wasm unchanged (2.5), 100 KB (1.1),
  50k elements (1.1), facade variant (2.1). Acceptance criteria → Task 3.
- **Placeholder scan:** no TBD/TODO; every step has exact code or exact commands.
  One deliberate flexibility note (100 KB pad / 550 KB byte count) is stated as an
  observable invariant, not a placeholder.
- **Type consistency:** `ensure_profile_size(&[u8]) -> Result<()>` used identically at
  both funnels; `Error::InputTooLarge(String)` payload-only across core/facade; wasm
  `WasmErrorCode::InputTooLarge` matches existing variant name (`lib.rs:100,123`).

## Execution handoff

Executed via subagent-driven-development (mandated by the lane brief): Tester first
per task batch, implementer greens, scoped gate before each commit, workspace gate
once at the end. Independent tasks 1 and 2 both touch provisioning/facade/wasm
separately but share the compile graph, so they run sequentially (Task 2 depends on
Task 1's variant existing); no parallel fan-out is safe within this plan.
