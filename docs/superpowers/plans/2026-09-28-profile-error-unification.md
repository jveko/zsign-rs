# Provisioning-Profile Error Unification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development (recommended) with dispatching-parallel-agents for independent tasks to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Route every root/nested provisioning-profile load through one shared
helper pair so the same mistake yields one error class + a source-naming
message at every entry point — without moving any wasm `ZSIGN_*` code.

**Architecture:** Two `pub(crate)` helpers in `crates/zsign/src/builder.rs`
(`read_profile_file`, `profile_validation_error`) replace three hand-rolled
`map_err` blocks in `builder.rs`/`ipa/mod.rs`. Validation failures keep their
`zsign_core` class (`Verification`/`ProvisioningProfile`/`InputTooLarge`) with
the source appended to the message; the nested map's `Core(Config)` rewrap is
deleted. `ipa/mod.rs` calls the helpers fully-qualified as
`crate::builder::…` (existing convention).

**Tech Stack:** Rust edition 2021, MSRV 1.88, `thiserror`, `wasm-bindgen`
tests via `wasm-pack test --node`.

**Spec:** `docs/superpowers/specs/2026-09-28-profile-error-unification-design.md`

## Global Constraints

- Zero-warning gate: `cargo fmt --all -- --check` and
  `cargo clippy --workspace --all-targets -- -D warnings` must pass.
- Tests: `TMPDIR=$PWD/target/tmp` prefix (in-tree `/tmp` is small tmpfs).
- Wasm tests: `wasm-pack test --node crates/zsign-wasm`.
- Fail-closed posture (ZSN-118) unchanged: only HOW failures are reported
  changes, never WHETHER they fail. CMS-less/expired/wrong-team profiles must
  keep failing with their current classes.
- `Error::InputTooLarge` (ZSN-123): single `Input too large:` prefix, detail
  payload, map-entry suffix exactly
  `{detail} (provisioning profile for bundle '<id>' at '<path>')`.
- No ticket IDs in code comments (ZSN-143 allowed in commit subjects only);
  no `println!`/`eprintln!` in `src/`; no placeholders/TODOs.
- No wasm-visible code changes: `code_for_zsign_error`, `code_for_core_error`,
  and the lib.rs doc table stay untouched.
- Deferred files stay untouched: `crates/zsign-core/src/crypto/*`,
  wasm `p12_err`, `verify.rs`, README, `scripts/`, `.github/`.
- NEVER merge, NEVER push. Conventional commits: imperative, lowercase, no
  trailing period.

## Review Focus

1. Nested CMS-less profile must surface `Core(Verification(_))` (was
   `Core(Config(_))`) — pin: Task 1 new `nested_cms_less_profile_keeps_verification_class`.
2. Root path read must name the path — pin: Task 1 new
   `missing_root_profile_read_names_the_path` (red before Task 2).
3. `Input too large:` must appear exactly once and the map-entry suffix
   format must survive — pin: Task 1 additions to
   `oversized_profile_map_entry_surfaces_as_input_too_large_naming_bundle`.
4. Map-key rejections (invalid/root-id/duplicate) must STAY
   `Core(Config(_))` — existing pins `test_profile_map_root_id_rejected`,
   `test_profile_map_duplicate_key_errors` must pass untouched.
5. Bytes-arm messages (wasm sign_ipa path) must stay byte-identical —
   existing pins `sign_ipa_bytes_rejects_{forged,expired,wrong_team,wrong_app}_profile`
   must pass untouched.

---

### Task 1: Matrix regression pins (Tester first)

**Files:**
- Modify: `crates/zsign/src/ipa/mod.rs` (tests module, ~:4016-4212, :5082-5162)
- Modify: `crates/zsign/src/builder.rs` (tests module, ~:1938-1965)
- Modify: `crates/zsign-wasm/src/lib.rs` (tests module, ~:1766-1822)

**Interfaces:**
- Consumes: existing fixtures — `FORGED_PROFILE_XML` (ipa:1962),
  `profile_fixture_bytes`/`profile_fixture_anchors` (ipa:1995-2010),
  wasm `PROFILE_XML` (:847) and the `new_signer_with_profile` helper (:928-934),
  and the existing test invocation patterns named below.
- Produces: no production code. Pins the post-design behavior so Task 2's
  implementation greens exactly these tests.

- [ ] **Step 1: Migrate the Config-shape pin (red)**

In `crates/zsign/src/ipa/mod.rs`, rewrite
`malformed_profile_map_entry_keeps_the_config_shape` (~:4133):

```rust
// rename to:
malformed_profile_map_entry_keeps_the_validation_class
```

Same fixture (`b"not a provisioning profile at all"`, `allow_unsafe_profile(true)`,
one map entry `com.test.app.bad`), changed assertions:

```rust
assert!(
    matches!(&err, Error::Core(zsign_core::Error::ProvisioningProfile(_))),
    "a malformed map entry must keep its validation class, got: {err:?}"
);
assert!(msg.contains("com.test.app.bad"), "…");
assert!(msg.contains("broken.mobileprovision"), "…");
```

Rewrite its doc comment (it currently pins `Core(Config(_))`): the wrap's job
is naming the offending entry; class preservation is what makes the name
possible. No ticket IDs.

Expected: FAIL today (`Core(Config(_))` is produced).

- [ ] **Step 2: Add the nested CMS-less class pin (red)**

New test in the same module, modeled on the Step 1 test but WITHOUT
`allow_unsafe_profile` (default validation), fixture `FORGED_PROFILE_XML`
written to a temp file, map entry `com.test.app.bad`:

```rust
#[test]
fn nested_cms_less_profile_keeps_verification_class() { … }
```

```rust
assert!(
    matches!(&err, Error::Core(zsign_core::Error::Verification(_))),
    "a CMS-less map entry is a verification failure, got: {err:?}"
);
assert!(msg.contains("com.test.app.bad"), "…");
assert!(msg.contains("forged.mobileprovision"), "…");
```

Expected: FAIL today (`Core(Config(_))`).

- [ ] **Step 3: Pin the root path read (red)**

New test in `crates/zsign/src/ipa/mod.rs`, invocation modeled on
`test_profile_map_missing_profile_file_names_path` (:4196-4212) but using
`.provisioning_profile(dir.path().join("nope.mobileprovision"))` on the root
profile:

```rust
#[test]
fn missing_root_profile_read_names_the_path() { … }
```

```rust
assert!(matches!(&err, Error::Io(_)), "got: {err:?}");
assert!(msg.contains("provisioning profile"), "…");
assert!(msg.contains("nope.mobileprovision"), "…");
```

Expected: FAIL today (bare `fs::read(path)?` message has no path).

- [ ] **Step 4: Pin root path malformed class + path (red on path)**

New test in `crates/zsign/src/ipa/mod.rs`, modeled on
`sign_ipa_bytes_rejects_forged_profile` (:5083) but writing
`FORGED_PROFILE_XML` to a temp file and using
`.provisioning_profile(path)` (the `Path` arm):

```rust
#[test]
fn sign_ipa_path_profile_forged_keeps_verification_class_and_names_path() { … }
```

```rust
assert!(
    matches!(&err, Error::Core(zsign_core::Error::Verification(_))),
    "got: {err:?}"
);
assert!(msg.contains("forged.mobileprovision"), "…");
```

Expected: class assertion passes, path assertion FAILS today.

- [ ] **Step 5: Extend the sign_macho forged pin with the path (red)**

In `crates/zsign/src/builder.rs`, extend `sign_macho_rejects_forged_profile`
(~:1939) with one assertion (the profile path variable already exists in the
test):

```rust
assert!(
    err.to_string().contains(<profile path str>),
    "the validation failure must name the profile file: {err}"
);
```

Expected: FAIL today (bare `?` at builder.rs:674-680 adds no path).

- [ ] **Step 6: Pin the single `Input too large:` prefix (green — regression)**

In `crates/zsign/src/ipa/mod.rs`, add to
`oversized_profile_map_entry_surfaces_as_input_too_large_naming_bundle`
(:4108):

```rust
let msg = err.to_string();
assert!(msg.starts_with("Input too large: "), "single prefix: {msg}");
assert_eq!(msg.matches("Input too large:").count(), 1, "prefix never doubled: {msg}");
```

Expected: PASS today and after Task 2.

- [ ] **Step 7: wasm `ZSIGN_INVALID_PROFILE` pin (green — contract)**

In `crates/zsign-wasm/src/lib.rs`, new `#[wasm_bindgen_test]` modeled on
`new_signer_with_profile` (:928-934): construct `WasmSigner` with
`allow_unsafe_profile = true` and profile bytes that parse as an XML plist
but whose root is not a dictionary
(`<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist …><plist version="1.0"><string>not a dictionary</string></plist>`):

```rust
let e = ….expect_err("non-dictionary profile must be rejected");
assert_eq!(error_code(&e), Some("ZSIGN_INVALID_PROFILE".into()));
```

Expected: PASS today (ctor maps core directly; this pins the stable code the
matrix requires).

- [ ] **Step 8: Run scoped suites; record the red list**

Run:
```
TMPDIR=$PWD/target/tmp cargo test -p zsign-rs profile
TMPDIR=$PWD/target/tmp cargo test -p zsign-rs oversized
wasm-pack test --node crates/zsign-wasm
```
Expected: the new/migrated tests from Steps 1-5 FAIL with the documented
expectations; Step 6-7 and every regression pin in the brief (ZSN-118
`sign_macho_rejects_forged_profile`, `sign_ipa_bytes_rejects_*`,
`missing_profile_error_names_the_file`, `forged_profile_fails_closed`,
core provisioning pins, ZSN-123 oversized pins) PASS. Paste the red list
into the task output.

- [ ] **Step 9: Commit**

`git add crates/zsign/src/ipa/mod.rs crates/zsign/src/builder.rs crates/zsign-wasm/src/lib.rs`
→ `test: pin provisioning profile error matrix`
(Intermediate red is intended TDD state; the pre-push hook runs clippy, not
tests, and Task 2 restores green.)

---

### Task 2: Shared helpers + rewire every site (Implementer greens)

**Files:**
- Modify: `crates/zsign/src/builder.rs` (add helpers after
  `entitlements_read_error` ~:709-715; rewire
  `load_entitlements_from_profile` :656-681)
- Modify: `crates/zsign/src/ipa/mod.rs` (rewire `load_profile` :702-722 and
  `load_bundle_profiles` :730-786; rewrite the wrap-justification comment
  :761-764)

**Interfaces:**
- Consumes: `zsign_core::Error` payload variants (`ProvisioningProfile(String)`,
  `Verification(String)`, `InputTooLarge(String)`), facade `Error`.
- Produces (exactly these signatures, in `crates/zsign/src/builder.rs`):

```rust
fn profile_source(path: &Path, bundle_id: Option<&str>) -> String;

pub(crate) fn read_profile_file(path: &Path, bundle_id: Option<&str>) -> Result<Vec<u8>, Error>;

pub(crate) fn profile_validation_error(
    e: zsign_core::Error,
    path: &Path,
    bundle_id: Option<&str>,
) -> Error;
```

- [ ] **Step 1: Implement the three helpers in `builder.rs`**

Approach: `profile_source` formats
`provisioning profile '<path>'` or
`provisioning profile for bundle '<id>' at '<path>'`.
`read_profile_file` is `std::fs::read(path).map_err(|e| Error::Io(std::io::Error::new(e.kind(), format!("failed to read {source}: {e}"))))` where
`source = profile_source(path, bundle_id)`.
`profile_validation_error` matches:

```rust
match e {
    zsign_core::Error::ProvisioningProfile(detail) => Error::Core(
        zsign_core::Error::ProvisioningProfile(format!("{detail} ({source})")),
    ),
    zsign_core::Error::Verification(detail) => Error::Core(
        zsign_core::Error::Verification(format!("{detail} ({source})")),
    ),
    zsign_core::Error::InputTooLarge(detail) => {
        Error::InputTooLarge(format!("{detail} ({source})"))
    }
    other => Error::Core(other),
}
```

Doc comments state intent (path always named; class never changed), no
ticket IDs. Match the file's existing import block and `///` style.

- [ ] **Step 2: Rewire `builder.rs::load_entitlements_from_profile`**

Replace the hand-rolled read wrap (:658-666) with
`let profile_data = crate::builder::read_profile_file(profile_path, None)?;`
(plain `read_profile_file(profile_path, None)?` — same module) and wrap the
`extract_entitlements_checked(…)` error arm with
`profile_validation_error(e, profile_path, None)`.

- [ ] **Step 3: Rewire `ipa/mod.rs::load_profile`**

`Path` arm: `let data = crate::builder::read_profile_file(path, None)?;` and
`.map_err(|e| crate::builder::profile_validation_error(e, path, None))` on
`extract_entitlements_checked`. `Bytes` arm unchanged.

- [ ] **Step 4: Rewire `ipa/mod.rs::load_bundle_profiles`**

Replace the read wrap (:753-761) with
`crate::builder::read_profile_file(path, Some(id))?`. Replace the whole
validation `map_err` (the inline `InputTooLarge` arm AND the `Core(Config)`
rewrap, :764-781) with
`.map_err(|e| crate::builder::profile_validation_error(e, path, Some(id)))`.
Rewrite the comment at :761-764: the helper names the offending entry by
preserving the failure's class (the old text justifies the deleted rewrap).
Map-key rejections stay `Error::Core(Config(...))`.

- [ ] **Step 5: Scoped test run — Task 1 greens**

Run:
```
TMPDIR=$PWD/target/tmp cargo test -p zsign-rs
```
Expected: PASS — all of Task 1's tests plus every regression pin in
`ipa/mod.rs`, `builder.rs`. Paste the summary line.

- [ ] **Step 6: Scoped lint + fmt**

Run:
```
cargo fmt --all -- --check
cargo clippy -p zsign-rs --all-targets -- -D warnings
```
Expected: clean, zero warnings.

- [ ] **Step 7: Commit**

`git add crates/zsign/src/builder.rs crates/zsign/src/ipa/mod.rs`
→ `fix: unify provisioning profile load errors`

---

### Task 3: Full gates (final verification)

**Files:** none modified.

- [ ] **Step 1: Zero-warning gate**

Run:
```
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
```
Expected: both clean.

- [ ] **Step 2: Full workspace tests**

Run:
```
mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test --workspace
```
Expected: all green. Baseline was 778 passed / 1+12 ignored; plus the Task 1
additions (counts rise accordingly), 0 failed. Paste the verbatim summary.

- [ ] **Step 3: Wasm tests**

Run:
```
wasm-pack test --node crates/zsign-wasm
```
Expected: 28 + the Task 1 addition passed, 0 failed. Paste the verbatim
summary.

- [ ] **Step 4: Confirm no deferred files touched**

Run:
```
git status --porcelain
git log --oneline main..HEAD
```
Expected: only the three commits (docs, test, fix) plus any plan/spec
follow-ups; no `crypto/*`, `p12_err`, `verify.rs`, README, `scripts/`,
`.github/` changes.

---

## Self-Review

1. **Spec coverage:** spec §2 decision → Task 2 Steps 1-4; §7 test matrix
   N1-N7/R1-R4 → Task 1 Steps 1-7 (N1 facade/CLI pin exists; N3=Step 3,
   N2=Step 5, N4=Step 4, N5 existing, N6=Steps 1-2, N7=Step 6, wasm=Step 7,
   R-pins = Step 8 run list); §4 site list → Task 2 Steps 2-4 (bytes arm
   deliberately untouched); §5 contract → no wasm/CLI/README edits anywhere
   in the plan; §6 invariants → Global Constraints + Task 3 gates.
2. **Step scan:** every step names one test/one rewiring/one command with an
   expected result; no TBDs or "handle edges".
3. **Type consistency:** helper signatures in Task 1's mental model match
   Task 2's Interfaces block verbatim; `bundle_id: Option<&str>` everywhere.
4. **Review Focus:** all five lines have owning pins (Task 1 Steps 1, 3, 6
   + existing untouched pins named in Steps 4/8).
5. **Proportion:** plan is test-and-signal sized; the only code bodies are
   the three helpers whose exact output format is the contract.
