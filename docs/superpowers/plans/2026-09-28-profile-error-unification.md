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

**Supersedes (landed specs are not edited):** the `Config`-shape sentences in
`docs/superpowers/specs/2026-09-28-native-profile-cap-design.md:159` ("other
errors from that site keep their `Config` shape") and
`docs/superpowers/specs/2026-09-28-profile-validation-wiring-design.md:176`
("`load_bundle_profiles` keeps its existing Config wrapper"). This plan's
Task 1 Step 1 migrates the pin those sentences describe.

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
   `Core(Config(_))` — pinned by Task 1 Step 9 (class assertions added to
   `test_profile_map_root_id_rejected`,
   `test_profile_map_duplicate_key_errors`, plus the new invalid-bundle-id
   test).
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

- [ ] **Step 5: Pin that sign_macho names the profile file (red)**

New test in `crates/zsign/src/builder.rs` — do NOT edit
`sign_macho_rejects_forged_profile` (:1939); it stays pristine as the ZSN-118
class pin. Model the new test on it, reusing `forged_profile_sign_paths`
(:1930-1936):

```rust
#[test]
fn sign_macho_forged_profile_names_the_file() { … }
```

```rust
let file_name = profile.file_name().unwrap().to_str().unwrap();
assert!(
    matches!(&err, Error::Core(zsign_core::Error::Verification(_))),
    "class pin: {err:?}"
);
assert!(
    err.to_string().contains(file_name),
    "the validation failure must name the profile file: {err}"
);
```

Expected: class assertion passes, file-name assertion FAILS today (bare `?`
at builder.rs:674-680 adds no path).

- [ ] **Step 6: Pin that sign_macho's missing profile names the file (green — regression)**

New test in `crates/zsign/src/builder.rs`, same shape but with a profile path
that does not exist:

```rust
#[test]
fn sign_macho_missing_profile_names_the_file() { … }
```

```rust
assert!(matches!(&err, Error::Io(_)), "got: {err:?}");
assert!(msg.contains("provisioning profile"), "…");
assert!(msg.contains("absent.mobileprovision"), "…");
```

Expected: PASS today (builder's read wrap already names the path) — this is
the facade-level N1 pin; the CLI pin
`missing_profile_error_names_the_file` covers only the end-to-end stderr.

- [ ] **Step 7: Pin the single `Input too large:` prefix (green — regression)**

In `crates/zsign/src/ipa/mod.rs`, add to
`oversized_profile_map_entry_surfaces_as_input_too_large_naming_bundle`
(:4108):

```rust
let msg = err.to_string();
assert!(msg.starts_with("Input too large: "), "single prefix: {msg}");
assert_eq!(msg.matches("Input too large:").count(), 1, "prefix never doubled: {msg}");
```

Expected: PASS today and after Task 2.

- [ ] **Step 8: wasm `ZSIGN_INVALID_PROFILE` pin (green — contract)**

In `crates/zsign-wasm/src/lib.rs`, new `#[wasm_bindgen_test]`. Build the
signer through the same path `new_signer_with_profile` (:928-934) uses —
`WasmSigner::assemble` with `allow_unsafe = true` — NOT the public
`WasmSigner::new`, whose Apple-root-anchored p12 load rejects the self-issued
fixture identity (see `constructor_rejects_unanchored_credentials` :1832).
Profile bytes: an XML plist whose root is not a dictionary, starting with
`<?xml ` so the raw byte scan finds the document marker:

```rust
let non_dict = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\"><plist version=\"1.0\"><string>not a dictionary</string></plist>";
let e = WasmSigner::assemble(credentials, Some(non_dict.to_vec()), true)
    .expect_err("non-dictionary profile must be rejected");
assert_eq!(error_code(&e), Some("ZSIGN_INVALID_PROFILE".into()));
```

(Adapt the exact `assemble` signature to what `new_signer_with_profile`
calls — credentials source and argument shape stay as in that helper.)

Expected: PASS today (raw scan reaches `profile_document`, whose non-dict
root returns `ProvisioningProfile` → `ZSIGN_INVALID_PROFILE`); pins the
stable code the matrix requires.

- [ ] **Step 9: Pin that map-key rejections stay `Config` (green — contract)**

These are the genuine configuration errors that must NOT move with the
validation failures:

1. In `crates/zsign/src/ipa/mod.rs`, add a class assertion to
   `test_profile_map_root_id_rejected` (:4156) and
   `test_profile_map_duplicate_key_errors` (:4174):

```rust
assert!(
    matches!(&err, Error::Core(zsign_core::Error::Config(_))),
    "a map-key rejection is a config error, got: {err:?}"
);
```

2. New test for the third rejection, which currently has no pin at all
   (ipa/mod.rs:739-741), e.g. map key `com.test.app/../escape`:

```rust
#[test]
fn profile_map_invalid_bundle_id_is_config() { … }
// same class assertion as above, message contains the offending id
```

Expected: PASS today and after Task 2 (Task 2 must not touch these arms).

- [ ] **Step 10: Run scoped suites; record the red list**

Run:
```
TMPDIR=$PWD/target/tmp cargo test -p zsign-rs profile
TMPDIR=$PWD/target/tmp cargo test -p zsign-rs oversized
TMPDIR=$PWD/target/tmp cargo test -p zsign-core provisioning
wasm-pack test --node crates/zsign-wasm
```
Expected: the new/migrated tests from Steps 1-5 FAIL with the documented
expectations; Steps 6-9 and every regression pin in the brief (ZSN-118
`sign_macho_rejects_forged_profile`, `sign_ipa_bytes_rejects_*`,
`missing_profile_error_names_the_file`, `forged_profile_fails_closed`,
core provisioning pins, ZSN-123 oversized pins) PASS. Paste the red list
into the task output.

- [ ] **Step 11: Commit**

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
`read_profile_file` derives its source label from BOTH parameters, then wraps
the read:

```rust
pub(crate) fn read_profile_file(path: &Path, bundle_id: Option<&str>) -> Result<Vec<u8>, Error> {
    let source = profile_source(path, bundle_id);
    std::fs::read(path).map_err(|e| {
        Error::Io(std::io::Error::new(
            e.kind(),
            format!("failed to read {source}: {e}"),
        ))
    })
}
```

`profile_validation_error` computes the same `source` and matches:

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
`let profile_data = read_profile_file(profile_path, None)?;` (no module
prefix — the helper lives in this file) and wrap the
`extract_entitlements_checked(…)` error with
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
git diff --name-only "$(git merge-base main HEAD)"..HEAD
```
Expected: the file list contains ONLY
`docs/superpowers/specs/2026-09-28-profile-error-unification-design.md`,
`docs/superpowers/plans/2026-09-28-profile-error-unification.md`,
`crates/zsign/src/builder.rs`, `crates/zsign/src/ipa/mod.rs`, and
`crates/zsign-wasm/src/lib.rs` — explicitly NO
`crates/zsign-core/src/crypto/*`, no wasm `p12_err` region edits, no
`verify.rs`, no `README.md`, no `scripts/`, no `.github/`. (`git status
--porcelain` alone proves nothing here: committed edits never appear in it.)

---

## Self-Review

1. **Spec coverage:** spec §2 decision → Task 2 Steps 1-4; §7 test matrix
   N1-N7/R1-R4 → Task 1 (N1=Step 6 facade pin + existing CLI pin, N2=Step 5,
   N3=Step 3, N4=Step 4, N5 existing, N6=Steps 1-2, N7=Step 7, wasm=Step 8,
   map-key Config=Step 9, R-pins = Step 10 run list incl. `-p zsign-core`);
   §4 site list → Task 2 Steps 2-4 (bytes arm deliberately untouched); §5
   contract → no wasm/CLI/README edits anywhere in the plan, supersession
   linked in the header; §6 invariants → Global Constraints + Task 3 gates.
2. **Step scan:** every step names one test/one rewiring/one command with an
   expected result; no TBDs or "handle edges".
3. **Type consistency:** helper signatures in Task 1's mental model match
   Task 2's Interfaces block verbatim; `bundle_id: Option<&str>` everywhere;
   Task 2's Step 1 recipe shows the two-parameter `read_profile_file` body
   that Steps 2-4 call.
4. **Review Focus:** all five lines have owning pins (Task 1 Steps 1, 3, 9
   + Step 8 for wasm + the existing untouched bytes-arm pins named in
   Step 10).
5. **Proportion:** plan is test-and-signal sized; the only code bodies are
   the three helpers whose exact output format is the contract.
