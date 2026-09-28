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

The 17 MiB buffer contains no `<?xml ` marker and no CMS envelope: without the
cap, the scan funnels would return `ProvisioningProfile("No XML plist found …")`
(`profile_document` is the first byte scanner) and the validate funnel would
return `Error::Verification` — its first statements are
`cms_verify::resolve_now(request.now)?` then CMS envelope verification
(`provisioning.rs:99-105`), and `ProfileRequest::default()` has `now: None`,
which resolves to the wall clock natively before the envelope check fails.
Observing `InputTooLarge` therefore proves the cap ran first in every funnel:
no O(n) window scan and no CMS work happened. The `allow_unsafe = true` arm
matters because that flag deliberately routes to the raw byte-scan extractor
(`extract_entitlements_from_profile` → `profile_document`) — the bypass must
reject oversized input exactly like the validated path, or `--allow-unsafe-profile`
would reopen the hole this cap closes. The buffer itself is only `.len()`-read
by the guard; it is never scanned (mirroring `lib.rs:1466-1469`, which allocates
`MAX_PROFILE_BYTES + 1` without scanning it).

```rust
#[test]
fn size_guard_boundaries_are_inclusive_at_the_limit() {
    // Pinned at the helper, not end-to-end: a full profile_document run over a
    // 16 MiB buffer would execute two O(n) windows scans plus a plist parse in
    // debug — exactly the work the guard exists to avoid testing. The guard is
    // a pure `len > MAX` predicate over the shared constant, so these three
    // assertions pin D6 (and the native MAX+1 rejection the wasm guest tests
    // cover only under wasm-pack).
    assert!(
        ensure_profile_size(&[]).is_ok(),
        "empty input must pass the size guard"
    );
    let at_limit = vec![0u8; MAX_PROFILE_BYTES];
    assert!(
        ensure_profile_size(&at_limit).is_ok(),
        "exactly-at-limit input must pass the size guard"
    );
    let over_limit = vec![0u8; MAX_PROFILE_BYTES + 1];
    let res = ensure_profile_size(&over_limit);
    assert!(
        matches!(&res, Err(Error::InputTooLarge(m)) if m.contains("16777217")),
        "one byte over the limit must be rejected, got {:?}", res.as_ref().err()
    );
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
    use std::fmt::Write as _;
    let mut xml = String::from(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><array>"#,
    );
    // One pass over a pre-sized buffer: 50k format! temporaries would dominate
    // the test's runtime for no behavioral gain.
    for i in 0..50_000 {
        write!(xml, "<string>element-{i:06}</string>").unwrap();
    }
    xml.push_str("</array></plist>");
    let mut profile = vec![b'X'; 64];
    profile.extend_from_slice(xml.as_bytes());
    profile.extend_from_slice(&[b'Y'; 64]);
    let res = profile_document(&profile);
    match &res {
        Ok(plist::Value::Array(a)) => assert_eq!(
            a.len(),
            50_000,
            "all 50k elements must parse (no element budget in this change)"
        ),
        other => panic!(
            "50k-element document must parse exactly as today; got {}",
            match other {
                Ok(_) => "non-array top-level value".to_string(),
                Err(e) => e.to_string(),
            }
        ),
    }
}
```

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
`extract_entitlements_checked` — they delegate; extend their doc comments to state
the D2 invariant explicitly: every `pub fn` taking profile bytes must either call
`ensure_profile_size` first or delegate immediately to a function that does, so a
future entry point cannot silently skip the guard.

- [ ] **Step 1.6: Run scoped tests, expect PASS**

Run: `TMPDIR=$PWD/target/tmp cargo test -p zsign-core`
Expected: all pass (baseline ~N core tests + 4 new).

- [ ] **Step 1.7: Commit**

Run: `git add crates/zsign-core/src/error.rs crates/zsign-core/src/provisioning.rs crates/zsign-wasm/src/lib.rs && git commit -m "enforce profile size cap in core before scanning"`

---

### Task 2: Facade mapping + profile-map wrap fix + wasm constant reuse

**Files:**
- Modify: `crates/zsign/src/error.rs:62-68` (`From<zsign_core::Error>` impl)
- Modify: `crates/zsign/src/ipa/mod.rs:771-776` (`load_bundle_profiles` map_err — D8)
- Modify: `crates/zsign-wasm/src/lib.rs:75-76` (constant → re-export)
- Test: `crates/zsign/src/ipa/mod.rs` tests module (real-funnel + regression);
  wasm tests stay green

- [ ] **Step 2.1: Write failing facade tests (real funnels first)**

In `crates/zsign/src/ipa/mod.rs`'s tests module, alongside
`test_profile_map_invalid_profile_names_bundle` (:4051). These are the
contract tests: they fail today because the oversized core error is either
wrapped as `Core(Config)` (map path) or never produced (no cap yet — Task 1
has landed the cap, so by this step the root path already returns
`Error::Core(InputTooLarge(...))` from the wildcard arm, which is also a
failure of `matches!(err, Error::InputTooLarge(_))`).

```rust
#[test]
fn oversized_root_profile_surfaces_as_input_too_large() {
    let temp = TempDir::new().unwrap();
    let (app, _appex) = create_bundle_with_appex(temp.path());
    let big = temp.path().join("huge.mobileprovision");
    std::fs::write(&big, vec![0u8; 17 * 1024 * 1024]).unwrap();
    let err = IpaSigner::new_adhoc()
        .provisioning_profile(&big)
        .sign_folder_in_place(&app)
        .expect_err("a 17 MiB root profile must fail the sign");
    assert!(
        matches!(&err, Error::InputTooLarge(m) if m.contains("17825792") && m.contains("16777216")),
        "oversized root profile must surface as InputTooLarge with lengths named, got {err:?}"
    );
}

#[test]
fn oversized_profile_map_entry_surfaces_as_input_too_large_naming_bundle() {
    let temp = TempDir::new().unwrap();
    let (app, _appex) = create_bundle_with_appex(temp.path());
    let big = temp.path().join("huge-ext.mobileprovision");
    std::fs::write(&big, vec![0u8; 17 * 1024 * 1024]).unwrap();
    let err = IpaSigner::new_adhoc()
        .bundle_profiles(vec![("com.test.app.ext".to_string(), big.clone())])
        .sign_folder_in_place(&app)
        .expect_err("a 17 MiB mapped profile must fail the sign");
    assert!(
        matches!(&err, Error::InputTooLarge(_)),
        "the size rejection must keep its variant through the map context wrap, got {err:?}"
    );
    let message = err.to_string();
    assert!(
        message.contains("com.test.app.ext") && message.contains("huge-ext.mobileprovision"),
        "the error must still name the offending bundle and file: {message}"
    );
}

#[test]
fn malformed_profile_map_entry_keeps_the_config_shape() {
    let temp = TempDir::new().unwrap();
    let (app, _appex) = create_bundle_with_appex(temp.path());
    let bad = temp.path().join("broken.mobileprovision");
    std::fs::write(&bad, b"not a provisioning profile at all").unwrap();
    let err = IpaSigner::new_adhoc()
        .allow_unsafe_profile(true)
        .bundle_profiles(vec![("com.test.app.bad".to_string(), bad.clone())])
        .sign_folder_in_place(&app)
        .expect_err("a malformed mapped profile must fail the sign");
    assert!(
        matches!(&err, Error::Core(zsign_core::Error::Config(_))),
        "only the size rejection changes shape; malformed profiles keep Core(Config), got {err:?}"
    );
    let message = err.to_string();
    assert!(
        message.contains("com.test.app.bad") && message.contains("broken.mobileprovision"),
        "the Config wrap must keep naming bundle and file: {message}"
    );
}
```

Notes for the implementer: `provisioning_profile(&Path)` / `bundle_profiles(Vec<(String, PathBuf)>)`
are the existing builder methods (`ipa/mod.rs:558`, and the root-profile setter —
check its exact name/shape against `test_profile_map_embeds_and_derives_for_nested`
at :3920 and mirror it); `create_bundle_with_appex`, `TempDir`, and the adhoc
signer are the established harness in this module. The first test fails today
only if Task 1's cap is absent — after Task 1 it fails on the wildcard `Core(...)`
arm, which is exactly the mapping gap Step 2.3 closes. The second fails until
the D8 map_err arm lands. The third must PASS both before and after Step 2.4 —
run it first to pin the pre-change shape.

- [ ] **Step 2.2: Run, verify FAIL**

Run: `TMPDIR=$PWD/target/tmp cargo test -p zsign-rs oversized -- --nocapture` and
`TMPDIR=$PWD/target/tmp cargo test -p zsign-rs malformed_profile_map`
Expected: first two FAIL (variant is `Core(...)`, not `InputTooLarge`);
`malformed_profile_map` PASSES (pins today's Config shape).

- [ ] **Step 2.3: Add the facade `From` arm**

In `crates/zsign/src/error.rs` `impl From<zsign_core::Error>`, insert before the
wildcard arm:

```rust
        zsign_core::Error::InputTooLarge(m) => Error::InputTooLarge(m),
```

- [ ] **Step 2.4: D8 — the profile-map wrap preserves the size variant**

In `crates/zsign/src/ipa/mod.rs:771-776`, replace the single `map_err` closure
with a match that changes exactly one arm (see design D8):

```rust
            .map_err(|e| match e {
                zsign_core::Error::InputTooLarge(detail) => Error::InputTooLarge(format!(
                    "{detail} (provisioning profile for bundle '{id}' at '{}')",
                    path.display()
                )),
                other => Error::Core(zsign_core::Error::Config(format!(
                    "provisioning profile for bundle '{id}' at '{}' is invalid: {other}",
                    path.display()
                ))),
            })?;
```

Both arms append the bundle id + path context; only the outer variant differs.
The size arm appends it AFTER the core detail so the facade's single
`Input too large: <detail>` Display prefix stays intact (D4) and the message
still matches a bare `too large` predicate like the wasm `ensure_size` messages.
Keep the existing explanatory comment above this `map_err` and extend it: the
wrap exists to name the offending map entry, and it must not reclassify the size
rejection (which has its own contract row).

- [ ] **Step 2.5: Wasm constant becomes a re-export**

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

- [ ] **Step 2.6: Leave the `sign_ipa` limitation note unchanged**

An implementation-time review established the original Step 2.6 premise was
wrong: on the wasm surface an oversized profile is unreachable at plan build —
the `WasmSigner` constructor's `ensure_size` (`lib.rs:277-284`) caps the only
profile source, `sign_ipa` forwards only that pre-capped `self.profile_bytes`
(`lib.rs:740-741`), and the crate has no `bundle_profiles` setter. Therefore
`crates/zsign-wasm/src/lib.rs:40` keeps its original text
(`ZSIGN_VERIFICATION` / `ZSIGN_INVALID_PROFILE`); if a temporary edit was made
there, revert it so `git diff HEAD -- crates/zsign-wasm/src/lib.rs` shows only
the constant re-export (import change + const deletion) and the Task 1 match
arm. Do not touch any doc line.

- [ ] **Step 2.7: Run scoped gates**

Run: `TMPDIR=$PWD/target/tmp cargo test -p zsign-rs && cargo check -p zsign-wasm`
Expected: PASS / no errors — including all three new ipa tests and the
pre-existing `test_profile_map_invalid_profile_names_bundle` (unchanged
behavior). Then, if `wasm-pack` is available:
`wasm-pack test --node crates/zsign-wasm` — all wasm tests green (the existing
oversize tests at `lib.rs:1400-1420`, `:1466-1469` unmodified). If wasm-pack is
missing from the environment, record that in the final report and rely on
`cargo check -p zsign-wasm` plus the native unit tests of the wasm crate
(`cargo test -p zsign-wasm`) — noting that the wasm-guest `MAX+1` assertions
then did NOT run in this environment (the native `ensure_profile_size` `MAX+1`
test from Task 1 remains the in-gate coverage of the shared constant).

- [ ] **Step 2.8: Commit**

Run: `git add crates/zsign/src/error.rs crates/zsign/src/ipa/mod.rs crates/zsign-wasm/src/lib.rs && git commit -m "map core size cap through facade, profile map, and wasm"`

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
Expected: ≥760 passed / 1 ignored (baseline was 760/1; this change adds 7 tests —
4 in zsign-core, 3 in the facade ipa module — so expect 767 passed / 1 ignored;
report exact numbers).

- [ ] **Step 3.4: Confirm no scope leakage**

Run: `git diff --stat main...HEAD` and `git status --porcelain`
Expected: only `crates/zsign-core/src/{error,provisioning}.rs`,
`crates/zsign/src/{error.rs,ipa/mod.rs}`, `crates/zsign-wasm/src/lib.rs`, plus the
two `docs/superpowers/**` files; no README/docs tables, no verify.rs/Mach-O/CLI
changes, no ticket IDs inside source comments (`git diff main...HEAD | grep -i 'ZSN-123'`
must hit only commit subjects — verify via `git log main..HEAD --format=%s`).

---

## Plan self-review (writing-plans checklist)

- **Spec coverage:** D1 → Task 1 Step 1.5; D2 → Step 1.5 funnel placement +
  invariant doc note; D3 → Step 1.3; D4 → Task 2 Steps 2.1-2.3 (real-funnel
  tests + From arm); D5 → Step 1.4 (forced wasm arm) + Step 2.5 (constant
  re-export) + Step 2.6 (doc note deliberately unchanged — wasm plan build
  unreachable for size), byte-identity via unchanged
  `ensure_size` call sites + green unmodified wasm tests (Step 2.7); D6 → Step 1.5
  (`len > MAX`) + boundary test; D7 → Task 1 wide-document pin test; D8 → Task 2
  Steps 2.1 (three ipa tests incl. Config-shape regression) + 2.4 (match arm).
  Test contract items 1-6 map to: oversized + allow_unsafe (1.1), wasm unchanged
  + native MAX+1 boundary (1.1 helper test, 2.7), 100 KB (1.1), 50k elements
  (1.1), facade real funnel (2.1), context-wrap regression (2.1 third test).
  Acceptance criteria → Task 3.
- **Placeholder scan:** no TBD/TODO; every step has exact code or exact commands.
  The one deliberate flexibility note (100 KB pad key name) is stated as an
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
