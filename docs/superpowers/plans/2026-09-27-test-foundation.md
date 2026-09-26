# Test Foundation (ZSN-30) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development
> with dispatching-parallel-agents for independent tasks to implement this plan
> task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Execute the still-open half of ZSN-30 per
`docs/superpowers/specs/2026-09-27-test-foundation-design.md` — delete the
last plumbing scratch test, consolidate Mach-O fixture builders and shared
test credentials behind `zsign_core::macho::fixtures` + `OnceLock`, fill
four coverage gaps red-first, and remove the one stale CI skip.

**Architecture:** expose the canon fixtures module to workspace test builds
via a dev-dependency-only `test-fixtures` feature (resolver 2 keeps it out
of release/wasm artifacts); migrate stragglers crate-by-crate with a
full-suite green after each batch; cache duplicate leaf-credential recipes
behind `OnceLock` returning owned clones (`Clone` derives added to
`SigningCredentials`/`SigningKeyType`).

**Tech stack:** Rust workspace (4 crates + fuzz), cargo, hk 1.55.0. No new
external dependencies.

**Ground rules (from brief + AGENTS.md):**
- All scoped runs use `TMPDIR=$PWD/.tmptmp` (never `/tmp`).
- Final gates: `cargo fmt --all --check`,
  `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo test --workspace --no-fail-fast` (**no skip**), `hk check`.
  Gates are never weakened to pass; fix code/tests instead.
- Ticket IDs in commit subjects only — never in code comments.
- Migration = callers move in the same change that deletes the helper; no
  aliases, no re-exports, no shims; delete what is obsoleted.
- Expected baseline: 740 tests passing (7 suites) before any change.

---

### Task 1: Remove plumbing scratch + scratch-dir ignores

**Files:**
- Modify: `.gitignore` (already edited during re-audit — verify only)
- Modify: `crates/zsign-core/src/macho/verify.rs` (delete `debug_req_slot`)

- [ ] **Step 1: Verify the gitignore edit landed**

Run: `grep -n "tmptmp" .gitignore`
Expected: lines 45-47 with comment `# Lane scratch dirs …` and both
`.tmptmp/`, `.tmptmp-orch/`. If absent, re-add exactly those lines after
`/.mcp.json`.

- [ ] **Step 2: Read the scratch test before deleting**

Read `crates/zsign-core/src/macho/verify.rs:510-551` — confirm it is
`fn debug_req_slot()` with `println!`s and no `assert!`/`unwrap`-as-check.
It sits at the top of `mod tests` before `use super::*;` (unusual but
compiles). Design §2 justifies deletion.

- [ ] **Step 3: Delete the function**

Remove the whole `#[test] fn debug_req_slot() { … }` block (verify.rs
:512-549 at re-audit time). Leave surrounding code untouched.

- [ ] **Step 4: Scoped gate**

Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-core --lib macho::verify`
Expected: `test result: ok` with **one fewer test** than before (baseline
`-p zsign-core --lib` total 433 → 432; the deleted name must be absent:
`cargo test -p zsign-core debug_req_slot` → `0 passed; 0 failed … 433
filtered out`).

- [ ] **Step 5: Commit**

`git add .gitignore crates/zsign-core/src/macho/verify.rs`
Subject: `test: remove debug slot scratch and ignore lane scratch dirs (ZSN-30)`

---

### Task 2: Expose fixtures behind the `test-fixtures` feature

**Files:**
- Modify: `crates/zsign-core/Cargo.toml` (add `[features]`)
- Modify: `crates/zsign-core/src/macho/mod.rs:14-15` (gate + `pub`)
- Modify: `crates/zsign-core/src/macho/fixtures.rs` (visibility of needed fns)
- Modify: `crates/zsign/Cargo.toml`, `crates/zsign-cli/Cargo.toml`,
  `crates/zsign-wasm/Cargo.toml` (dev-dependency edges)

- [ ] **Step 1: Add the feature to zsign-core**

Append to `crates/zsign-core/Cargo.toml` (after `[features]` position —
create the table):

```toml
[features]
# Test-only fixture access for sibling crates; enabled exclusively through
# dev-dependencies so it never reaches release or wasm artifacts.
test-fixtures = []
```

- [ ] **Step 2: Widen the module gate**

In `crates/zsign-core/src/macho/mod.rs`, replace:

```rust
#[cfg(test)]
pub(crate) mod fixtures;
```

with:

```rust
#[cfg(any(test, feature = "test-fixtures"))]
pub mod fixtures;
```

- [ ] **Step 3: Make fixture fns `pub`**

In `crates/zsign-core/src/macho/fixtures.rs`, change every `pub(crate) fn`
to `pub fn` (`make_minimal_macho`, `make_minimal_macho_text_vmsize_pad`,
`make_minimal_macho_32`, `make_minimal_macho_32_mixed_linkedit`,
`make_minimal_macho_32_be`, `make_signed_minimal_macho`,
`make_signed_minimal_macho_at`, `make_minimal_macho_be`,
`make_minimal_macho_encrypted`, `make_text_fileoff0_macho`,
`test_signing_credentials`). `make_minimal_dylib` and `make_fat_macho` are
already `pub`. All already carry `///` docs (no `missing_docs` deny exists
— verified `lib.rs` has no `#![deny]` attrs). Module-level gating keeps
them out of normal builds; no doc changes needed beyond the existing ones.

- [ ] **Step 4: Add dev-dependency edges**

`crates/zsign/Cargo.toml` `[dev-dependencies]` (zsign-core already in
`[dependencies]` — same package in both tables is legal and features merge
only while dev-deps are active):

```toml
zsign-core = { path = "../zsign-core", version = "0.1.0", features = ["test-fixtures"] }
```

`crates/zsign-cli/Cargo.toml` `[dev-dependencies]`:

```toml
zsign-core = { path = "../zsign-core", version = "0.1.0", features = ["test-fixtures"] }
```

`crates/zsign-wasm/Cargo.toml` `[dev-dependencies]` (same pattern):

```toml
zsign-core = { path = "../zsign-core", version = "0.1.0", features = ["test-fixtures"] }
```

- [ ] **Step 5: Verify compile matrix**

Run:
```
TMPDIR=$PWD/.tmptmp cargo check --workspace --all-targets
TMPDIR=$PWD/.tmptmp cargo check --release -p zsign-wasm
```
Expected: both `Finished` with no warnings. The second command proves the
feature stays OFF for release/wasm builds (fixtures module absent — if it
were present the gate is wrong).

- [ ] **Step 6: Commit**

Subject: `refactor: expose macho fixtures behind test-fixtures feature (ZSN-30)`

---

### Task 3: Migrate zsign-core in-crate stragglers (design §3.2 rows 1-6)

**Files:**
- Modify: `crates/zsign-core/src/macho/fixtures.rs` (add 2 moved builders)
- Modify: `crates/zsign-core/src/macho/parser.rs`, `signer.rs`,
  `verify.rs`, `writer.rs` (delete locals, migrate callers)

- [ ] **Step 1: Move `minimal_macho_32_with_encryption` into canon**

Cut the body of `parser.rs:714` `minimal_macho_32_with_encryption()` into
`fixtures.rs` as:

```rust
/// [`make_minimal_macho_32`] with an appended `LC_ENCRYPTION_INFO` load
/// command (32-bit FairPlay-encrypted binary shape), for refusal/verify tests.
pub fn make_minimal_macho_32_encrypted() -> Vec<u8> { /* moved body, unchanged */ }
```

In `parser.rs`, delete the local fn; update its caller (`parser.rs:744`)
from `minimal_macho_32_with_encryption()` to
`crate::macho::fixtures::make_minimal_macho_32_encrypted()`.

- [ ] **Step 2: Delete `minimal_macho_with_encryption` and
`minimal_macho_plain` in parser.rs**

First diff the two local fns against canon (design §3.2 asserts
byte-equivalence for the encrypted variant — `make_minimal_macho_encrypted`
:466 writes the same `LC_ENCRYPTION_INFO_64` words as `parser.rs:481` did).
Then:

- `parser.rs:575,591,606` → `fixtures::make_minimal_macho_encrypted(cryptid, cryptsize)`
  with the same arguments each caller passes today.
- `parser.rs:704` → `fixtures::make_minimal_macho()`.
- Delete both local fns (`parser.rs:481`, `parser.rs:617`).

- [ ] **Step 3: Compose the signer FAT helper away**

In `signer.rs`, replace the caller at `:1627`:

```rust
// before: let fat = make_fat_with_encrypted_second_slice(...);
let fat = crate::macho::fixtures::make_fat_macho(
    &[
        crate::macho::fixtures::make_minimal_macho(),
        crate::macho::fixtures::make_minimal_macho_encrypted(/* args from old helper, e.g. */ 1, 0x1000),
    ],
    &[12, 12],
);
```

Read the old helper body first to carry over exact cryptid/cryptsize and
any identifier/label bytes; if the helper also patched the fat header
fields canon does not emit (cputype/cpusubtype for the encrypted slice),
preserve those by adjusting the call — the deciding rule is the scoped
suite staying green with byte-identical output (assert in Step 5). Then
delete `make_fat_with_encrypted_second_slice` (`signer.rs:1596`).

- [ ] **Step 4: Delete `build_two_slice_fat` (verify.rs) and move
`build_test_binary` (writer.rs) to canon**

- `verify.rs:817` caller → `crate::macho::fixtures::make_fat_macho(&[make_minimal_macho(), make_minimal_macho()], &[12, 12])`
  (import path adjust as needed); delete `build_two_slice_fat` (`:795`).
  The existing test at `verify.rs:795+` that constructed *overlapping*
  slices deliberately is a different, inline hostile fixture — leave it.
- Cut `writer.rs:1814` `build_test_binary(segment_fileoff)` into
  `fixtures.rs` as `pub fn make_linkedit_only_macho(segment_fileoff: u64) -> Vec<u8>`
  (body unchanged, doc comment added); update the three writer.rs callers
  (`:1845,:1915,:1926`) to `crate::macho::fixtures::make_linkedit_only_macho(...)`;
  delete the local fn.

- [ ] **Step 5: Scoped gate + byte-identity spot check**

Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-core --lib`
Expected: same pass count as Task 1 end (432), `0 failed`. Every migrated
test passing on identical inputs is the byte-identity proof the design
requires (tests assert on parsed structures/digests of these fixtures).

- [ ] **Step 6: Commit**

Subject: `test: consolidate zsign-core macho fixture builders into fixtures (ZSN-30)`

---

### Task 4: Migrate cross-crate stragglers + delete the `.bin` (design §3.2 rows 7-14)

**Files:**
- Modify: `crates/zsign/src/test_util.rs`, `crates/zsign/src/builder.rs`,
  `crates/zsign/src/ipa/mod.rs`
- Modify: `crates/zsign-wasm/src/lib.rs`
- Modify: `crates/zsign-cli/src/main.rs`
- Delete: `crates/zsign/src/ipa/fixtures/minimal_macho.bin`

- [ ] **Step 1: zsign crate — replace the three test_util macho wrappers**

In every zsign test module that calls them (grep first):
`minimal_macho()` → `zsign_core::macho::fixtures::make_minimal_macho()`,
`minimal_macho_encrypted()` → `zsign_core::macho::fixtures::make_minimal_macho_encrypted(1, 0x1000)`,
`minimal_dylib()` → `zsign_core::macho::fixtures::make_minimal_dylib()`.
Add `use zsign_core::macho::fixtures;` where a module has several call
sites (then `fixtures::make_minimal_macho()`); keep full paths where a
site is singular. Known caller clusters from the re-audit: `builder.rs`
(:794,887,888,892,1087,1117,1169), `ipa/mod.rs` (:1972,2443,2482,2496,2787,3839),
`verify.rs` (:1228), `test_util.rs` internals. Re-grep to catch all.

- [ ] **Step 2: zsign — delete `make_fat_for_test`, rewire
`write_two_arch_fat_fixture`**

`builder.rs:892` caller → `fixtures::make_fat_macho(slices, &[12, 12])`
(matching the slice count: pass `&[12u32][..slices.len()]` or a
`vec![12; slices.len()]`). Inside `write_two_arch_fat_fixture` (`:886`)
replace its hand-rolled header with the same canon call. Delete
`make_fat_for_test` (`:856`).

- [ ] **Step 3: zsign — replace the `include_bytes!` zip write**

`ipa/mod.rs:1972`: `zip.write_all(include_bytes!("fixtures/minimal_macho.bin"))`
→ `zip.write_all(&fixtures::make_minimal_macho())`.

- [ ] **Step 4: zsign — delete the three test_util fns**

After Steps 1-3, `minimal_macho`, `minimal_macho_encrypted`,
`minimal_dylib` in `crates/zsign/src/test_util.rs` have zero callers
(grep to confirm). Delete them. (`test_credentials` stays for Task 5.)

- [ ] **Step 5: wasm crate migration**

`crates/zsign-wasm/src/lib.rs`:
- Delete `MINIMAL_MACHO` const (`:769`) and route its 9 uses
  (`:929,1049,1063,1070,1145,1185,1207,1210,1674`) to
  `zsign_core::macho::fixtures::make_minimal_macho()` (bind
  `let macho = fixtures::make_minimal_macho();` then use `&macho` where a
  slice is needed).
- Delete `build_fat_macho` (`:1035`, callers `:1098,1160,1614`) →
  `fixtures::make_fat_macho(&[make_minimal_macho(), make_minimal_macho()], &[12, 12])`.
- Delete `build_fat_macho_one_arch` (`:1054`, caller `:1110`) →
  `fixtures::make_fat_macho(&[make_minimal_macho()], &[12])`.
- Design invariant: canon output for these inputs is 20 480 B / 12 288 B —
  any wasm test that asserts fixture *sizes* keeps passing; if one fails,
  the offsets disagree → re-derive aligns before proceeding (do not
  weaken the test).

- [ ] **Step 6: cli crate migration**

`crates/zsign-cli/src/main.rs`:
- Delete `encrypted_macho()` (`:979`, caller `:1073`) →
  `zsign_core::macho::fixtures::make_minimal_macho_encrypted(1, 0x1000)`
  (verify the old fn's cryptid/cryptsize words match before swapping).
- Delete `MINIMAL_MACHO` const (`:1130`) and route its ~15 uses to
  `fixtures::make_minimal_macho()` (same bind-then-slice pattern).

- [ ] **Step 7: Delete the committed `.bin`**

Run first, expecting hits ONLY at the four known include sites:
`grep -rn "minimal_macho.bin" crates/`. After Steps 1/5/6 all four are
gone → `git rm crates/zsign/src/ipa/fixtures/minimal_macho.bin`
(the `fixtures/` dir then disappears; `crates/zsign/src/ipa/` keeps its
other files).

- [ ] **Step 8: Full workspace suite (migration batch gate)**

Run: `TMPDIR=$PWD/.tmptmp cargo test --workspace --no-fail-fast`
Expected: all suites green, total ≥ 740 (no test deleted in this task).

- [ ] **Step 9: Duplicate-residue grep (acceptance evidence)**

Run: `grep -rn "make_fat_for_test\|build_fat_macho\|build_two_slice_fat\|minimal_macho_plain\|encrypted_macho(\|include_bytes!(\"../../zsign/src/ipa\|include_bytes!(\"ipa/fixtures" crates/ fuzz/`
Expected: no matches. Record output for the final report.

- [ ] **Step 10: Commit**

Subject: `test: route cross-crate macho fixtures through zsign-core (ZSN-30)`

---

### Task 5: Credential consolidation + `OnceLock` (design §4)

**Files:**
- Modify: `crates/zsign-core/src/crypto/cert.rs` (Clone derives)
- Modify: `crates/zsign-core/src/macho/fixtures.rs` (OnceLock wrappers +
  2 moved recipes)
- Modify: `crates/zsign-core/src/macho/verify.rs`,
  `crates/zsign-core/src/macho/signer.rs`,
  `crates/zsign-core/src/crypto/cms_verify.rs`
- Modify: `crates/zsign/src/test_util.rs`, `crates/zsign/src/verify.rs`
  (delete local builders)

- [ ] **Step 0: Independence pre-flight (must pass before any wrapping)**

For each helper being cached (`fixtures::test_signing_credentials`,
`verify.rs:573 rsa_credentials`, `signer.rs:960 test_credentials`,
`zsign test_util::test_credentials`, `zsign verify.rs:948
local_test_credentials`, `cms_verify.rs:1744 rsa_credentials`): grep every
caller function body for a **second** call to the same helper within one
`#[test]`. Expected findings from re-audit: only `cms_verify`
`attacker_self_signed_resign_is_invalid` (`:2231,:2232`) and
`missing_issuer` (`:2259`) require *distinct* identities from the same
helper. Any additional hit ⇒ stop, keep that helper uncached, and record
the deviation in design §9. This step is the guard against silently
sharing an identity a test depends on being unique.

- [ ] **Step 1: Add Clone derives**

`crates/zsign-core/src/crypto/cert.rs`:

```rust
#[derive(Clone)]
pub enum SigningKeyType { … }
```

and directly above `pub struct SigningCredentials` (`:102`):

```rust
#[derive(Clone)]
pub struct SigningCredentials { … }
```

Keep the existing `#[allow(clippy::large_enum_variant)]` on
`SigningKeyType` and move it above the derive (allow-before-derive order).
Run `TMPDIR=$PWD/.tmptmp cargo check -p zsign-core` → clean; this also
proves every field is `Clone`.

- [ ] **Step 2: OnceLock the canon recipe**

Split `fixtures.rs:603 test_signing_credentials` body into a private
`fn build_test_signing_credentials() -> crate::crypto::SigningCredentials`
(the current body, unchanged) and add:

```rust
static CANON_CREDS: OnceLock<crate::crypto::SigningCredentials> = OnceLock::new();

/// Shared self-signed RSA-2048 code-signing credentials (`Profile::Leaf`,
/// codeSigning EKU, `team_id = Some("TESTTEAM")`), cached after first use.
pub fn test_signing_credentials() -> crate::crypto::SigningCredentials {
    CANON_CREDS.get_or_init(build_test_signing_credentials).clone()
}
```

with `use std::sync::OnceLock;`. Signature unchanged ⇒ zero caller churn.

- [ ] **Step 3: Delete the exact duplicate in macho/verify.rs**

`verify.rs:573 rsa_credentials` is byte-equivalent (same CN/serial/Leaf/
E KU/team — design §4.1). Replace its 13 callers
(`:514,820,947,981,1016,1066,1077,1088,1122,1152,1214,1224,3415,3437`
— re-grep for `rsa_credentials()` in that file) with
`crate::macho::fixtures::test_signing_credentials()`, then delete the
local fn. (If a caller destructures a tuple it doesn't — this one returns
`SigningCredentials` only — signature matches canon exactly.)

- [ ] **Step 4: Move the Root recipe into canon**

Cut `signer.rs:960 test_credentials` (Profile::Root, `CN=zsign roundtrip`)
into `fixtures.rs` as:

```rust
static ROOT_CREDS: OnceLock<crate::crypto::SigningCredentials> = OnceLock::new();

/// Shared self-signed RSA-2048 `Profile::Root` credentials for signer
/// round-trip tests (`team_id = Some("TESTTEAM")`).
pub fn test_root_credentials() -> crate::crypto::SigningCredentials {
    ROOT_CREDS.get_or_init(build_test_root_credentials).clone()
}
```

(body of the moved fn becomes `build_test_root_credentials`, unchanged
recipe). Delete the signer.rs local; its 12 callers
(`:1121,1181,1259,1288,1312,1414,1446,1530,1577,1640,1685,1824` — re-grep)
become `crate::macho::fixtures::test_root_credentials()`.

- [ ] **Step 5: zsign-side recipe moves**

In `crates/zsign/src/test_util.rs`:
- Rename-and-move `test_credentials` body into `fixtures.rs` as
  `build_team_ou_test_credentials` + `static TEAM_OU_CREDS: OnceLock<…>`
  + public `pub fn team_ou_test_credentials() -> SigningCredentials`
  (cached clone; recipe `CN=zsign test,OU=TESTTEAM` preserved byte-for-byte).
  Also store a `static TEAM_OU_WITH_KEY: OnceLock<(SigningCredentials, RsaPrivateKey)>`
  built from the *same* recipe so `local_test_credentials` callers keep a
  matching key: add `pub fn team_ou_test_credentials_with_key() -> (SigningCredentials, RsaPrivateKey)`
  returning clones of the tuple. Build both from one init fn to avoid two
  keygens (the tuple's `.0` and the creds-only accessor share one static —
  implement as one `OnceLock<(creds, key)>` and derive both accessors from
  it, constructing `creds` once inside).
- Replace `zsign/src/verify.rs:948 local_test_credentials` — delete it;
  its callers (`:1049,:1227` — re-grep) use
  `zsign_core::macho::fixtures::team_ou_test_credentials_with_key()`.
- Replace all `test_util::test_credentials()` callers (~40 sites:
  `builder.rs:777,787,815,848,905,930,1042,1049,1100,1125,1316`,
  `ipa/mod.rs:1871,1907,2103,2174,2189,2203,2241,2261,2291,2364,2446,2485,2723,2768,2791,2943,3034,3087` — re-grep)
  with `zsign_core::macho::fixtures::team_ou_test_credentials()`.

- [ ] **Step 6: cms_verify cache + fresh split**

`crates/zsign-core/src/crypto/cms_verify.rs:1744`:
- Rename current body to `fn build_rsa_test_credentials() -> (SigningCredentials, RsaPrivateKey)`.
- Add `static CMS_CREDS: OnceLock<(SigningCredentials, RsaPrivateKey)>`;
  `fn rsa_credentials() -> (SigningCredentials, RsaPrivateKey)` returns
  `CMS_CREDS.get_or_init(build_rsa_test_credentials).clone()` (signature
  unchanged ⇒ 15 callers untouched).
- Add `fn fresh_rsa_credentials() -> (SigningCredentials, RsaPrivateKey)`
  calling `build_rsa_test_credentials()` directly (doc comment: identities
  must be independent per call). Point the three independence sites
  (`:2231`, `:2232`, `:2259`) at `fresh_rsa_credentials()`.

- [ ] **Step 7: Scoped gates per crate, then full suite**

```
TMPDIR=$PWD/.tmptmp cargo test -p zsign-core --lib
TMPDIR=$PWD/.tmptmp cargo test -p zsign-rs
TMPDIR=$PWD/.tmptmp cargo test -p zsign-cli
TMPDIR=$PWD/.tmptmp cargo test --workspace --no-fail-fast
```
Expected: all green; zsign-cli baseline 46 passed.

- [ ] **Step 8: Residue grep (acceptance evidence)**

Run: `grep -rn "fn rsa_credentials\|fn test_credentials\|fn local_test_credentials" crates/`
Expected: only the three private `build_*`/`fresh_*` helpers named above
remain (no stray local duplicates). Record output.

- [ ] **Step 9: Commit**

Subject: `test: share test credentials through oncelock fixtures (ZSN-30)`

---

### Task 6: Gap tests — red-first (design §5; Tester writes, implementer greens)

Per subagent-driven-development: the Tester agent authors each test, runs
it against current source, and records the first-run result. Two red
paths are acceptable evidence: (a) real defect found → fix → green, or
(b) code correct → test green immediately → **mutation probe**: break the
suspect production line, confirm the new test fails, restore, confirm
green. Probe edits are never committed.

- [ ] **Step 1 (e1b): extend the on-disk FAT test with verify**

File: `crates/zsign/src/builder.rs`, test
`test_sign_macho_fat_default_sha256_only_routes_through_fat_path`
(`:899`). After the existing "both slices signed" assertions, read the
written output back and verify it end-to-end:

```rust
let written = std::fs::read(&output).unwrap();
let report = zsign_core::macho::verify_macho(
    &written,
    &zsign_core::macho::verify::SignatureInputs::none(),
)
.unwrap();
assert!(report.fat);
assert_eq!(report.slices.len(), 2);
for (i, slice) in report.slices.iter().enumerate() {
    assert!(slice.signed, "slice {i} must verify as signed");
    assert_eq!(slice.pages, zsign_core::codesign::verify::PageCheck::Matched, "slice {i}: {:?}", slice.errors);
}
```

Confirm the exact import paths against `verify.rs:1014-1058` (which uses
`SignatureInputs::none()` and `PageCheck::Matched` in-module); adjust
paths to what `zsign` can name publicly. Run scoped:
`TMPDIR=$PWD/.tmptmp cargo test -p zsign-rs test_sign_macho_fat_default`
→ red/green per rules above. Mutation probe: temporarily break slice
offset emission in the write path → test must go red → restore.

- [ ] **Step 2 (e2): sign-IPA → `verify_ipa` end-to-end**

File: `crates/zsign/src/verify.rs` tests mod (has `local_test_credentials`
replaced in Task 5 — use `fixtures::team_ou_test_credentials()`).

```rust
#[test]
fn signed_ipa_verifies_end_to_end() {
    let td = tempfile::TempDir::new().unwrap();
    let app = td.path().join("Payload").join("Test.app");
    std::fs::create_dir_all(app.join("SCInfo")).unwrap();
    std::fs::write(
        app.join("Info.plist"),
        br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleIdentifier</key><string>com.test.e2e</string>
  <key>CFBundleExecutable</key><string>Test</string>
  <key>CFBundlePackageType</key><string>APPL</string>
</dict></plist>"#,
    )
    .unwrap();
    std::fs::write(app.join("Test"), minimal_macho()).unwrap();
    let ipa = td.path().join("signed.ipa");
    let zsign = crate::ZSign::new()
        .credentials(zsign_core::macho::fixtures::team_ou_test_credentials());
    zsign.sign_bundle(&app, Some(&ipa)).unwrap();

    let report = crate::verify::verify_ipa(&ipa).expect("verify_ipa must run");
    assert!(report.valid(), "errors: {:?}", report);
}

#[test]
fn verify_ipa_rejects_unsigned_bundle() {
    // build the same minimal .ipa WITHOUT signing → verify_ipa must not report valid
}
```

Build the unsigned case by zipping the same layout with the `zip` crate
(mirroring `ipa/mod.rs:1954-1980`) or by reusing an existing unsigned-ipa
helper — check first; do not duplicate if one exists. If `sign_bundle`
needs a directory outside `Payload/` layout, mirror the exact folder
construction used by `builder.rs:794-850` tests (copy that block's shape).
Negative variant: tamper → `!report.valid()`. First run recorded; mutation
probe: make `verify_ipa` extraction skip the executable → positive test
red → restore.

- [ ] **Step 3 (e3): 16KB `page_size_log2=14` behavioral test**

File: `crates/zsign-core/src/codesign/verify.rs` tests mod, next to
`cd_bytes_with_page_size` (`:1785`). The builder always writes pageSize=12
and hashes at 4KB boundaries, so the test hand-patches a multi-page CD:

```rust
/// Patch a builder-produced CD to `log2`-byte pages: page size byte,
/// stored slot count, and the code-slot digests recomputed at the new
/// page boundary. `code` is the region the digests cover.
fn cd_with_log2_pages(code: &[u8], log2: u8) -> Vec<u8> {
    let mut cd = CodeDirectoryBuilder::new("com.example.pages16k", code).build_sha256();
    let page = 1usize << log2;
    let slots = code.len().div_ceil(page);
    // header: nCodeSlots u32 BE at offset 24, pageSize u8 at offset 39
    cd[24..28].copy_from_slice(&(slots as u32).to_be_bytes());
    cd[39] = log2;
    // hashes start at hashOffset (u32 BE at offset 12), digest i covers
    // code[i*page .. min((i+1)*page, len)]
    let hash_offset = u32::from_be_bytes(cd[12..16].try_into().unwrap()) as usize;
    for (i, chunk) in code.chunks(page).enumerate() {
        let digest = sha2::Sha256::digest(chunk);
        let at = hash_offset + i * digest.len();
        cd[at..at + digest.len()].copy_from_slice(&digest);
    }
    cd
}
```

Verify header offsets against `CodeDirectory::parse` (`verify.rs:618-742`)
before running — if nCodeSlots/hashOffset live elsewhere, fix the helper,
not the assertions. Tests:

```rust
#[test]
fn check_code_pages_accepts_16k_pages() {
    let code = vec![0x5au8; 16384 * 2 + 1000]; // two full pages + partial tail
    let cd = CodeDirectory::parse(&cd_with_log2_pages(&code, 14)).unwrap();
    assert_eq!(check_code_pages(&cd, &code), PageCheck::Matched);
    // exact-multiple boundary: no partial page
    let exact = vec![0x5au8; 16384 * 2];
    let cd = CodeDirectory::parse(&cd_with_log2_pages(&exact, 14)).unwrap();
    assert_eq!(check_code_pages(&cd, &exact), PageCheck::Matched);
    // corruption in the second page is localized
    let mut bad = code.clone();
    bad[20000] ^= 0x01;
    assert_eq!(
        check_code_pages(&cd, &bad),
        PageCheck::Mismatch { page_index: 1 }
    );
}

#[test]
fn check_code_pages_16k_count_mismatch() {
    let code = vec![0x5au8; 16384 + 10]; // 2 pages at 16k …
    let mut cd_bytes = cd_with_log2_pages(&code, 14);
    // … but claim 3 stored slots
    cd_bytes[24..28].copy_from_slice(&3u32.to_be_bytes());
    let cd = CodeDirectory::parse(&cd_bytes).unwrap();
    assert_eq!(
        check_code_pages(&cd, &code),
        PageCheck::CountMismatch { stored: 3, computed: 2 }
    );
}
```

If `CodeDirectory::parse` rejects the patched bytes (offset/order
mismatch), fix `cd_with_log2_pages` to match the parser — never loosen the
parser. Red-first evidence: mutation probe changing
`log2 @ 12..=16 => 1u64 << log2` to `1u64 << 12` must turn
`check_code_pages_accepts_16k_pages` red → restore.

- [ ] **Step 4 (e4): `should_exclude` / `add_symlink` tables**

File: `crates/zsign-core/src/bundle/code_resources.rs` tests mod (mirror
the existing table style at `:736-793`):

```rust
#[test]
fn should_exclude_table() {
    let mut b = CodeResourcesBuilder::new();
    b.exclude("TestData/");
    assert!(b.should_exclude("_CodeSignature/"));
    assert!(b.should_exclude("_CodeSignature"));
    assert!(b.should_exclude("_CodeSignature/CodeResources"));
    assert!(b.should_exclude("TestData/a.bin"));
    assert!(!b.should_exclude("TestDataX/a.bin")); // prefix needs exact segment
    assert!(!b.should_exclude("Resources/data.bin"));
    let mut b = CodeResourcesBuilder::new().main_executable("Test.app/Test"); // check real setter name
    assert!(b.should_exclude("Test.app/Test"));
    assert!(!b.should_exclude("Test.app/TestHelper"));
}
```

Read `should_exclude` (`:420-449`) and the builder's real setter names
first; the nested-bundle non-exclusion comment (`:445-447`) must get an
explicit `assert!(!b.should_exclude("Frameworks/F.framework/Headers/h"))`
row if that behavior holds. For `add_symlink`:

```rust
#[test]
fn add_symlink_respects_exclusions_and_stores_target() {
    let mut b = CodeResourcesBuilder::new();
    assert!(!b.add_symlink("_CodeSignature/x", "y", [0; 20], [0; 32]));
    assert!(b.add_symlink("Frameworks/F.framework/F", "Versions/Current/F", [1; 20], [2; 32]));
    let xml = String::from_utf8(b.build().unwrap()).unwrap();
    assert!(xml.contains("Versions/Current/F")); // target observable in output
}
```

Confirm `build()` output shape from the existing
`test_custom_exclude_emits_matching_omit_rule` (`:796`) before asserting
substring form; assert on parsed plist if the XML form is ambiguous.
Mutation probe: remove the `should_exclude` gate in `add_symlink` →
first assert red → restore.

- [ ] **Step 5: Scoped gates**

```
TMPDIR=$PWD/.tmptmp cargo test -p zsign-core --lib codesign::verify
TMPDIR=$PWD/.tmptmp cargo test -p zsign-core --lib bundle::code_resources
TMPDIR=$PWD/.tmptmp cargo test -p zsign-rs verify
TMPDIR=$PWD/.tmptmp cargo test -p zsign-rs builder
```
Expected: green, new tests present in output.

- [ ] **Step 6: Commit (new tests only — no probe leftovers)**

`git diff` review: no mutated production lines. Subject:
`test: cover verify-ipa, 16k pages, and code resources tables (ZSN-30)`

---

### Task 7: Remove the stale CI skip (design §7)

**Files:**
- Modify: `.github/workflows/ci.yml:59-62`

- [ ] **Step 1: Delete the skip and its stale comment**

Remove the two comment lines (`:59-60`, claiming a known nondeterminism
flake — fixed by ZSN-15/ZSN-41) and change the run line to:

```yaml
      - name: Run tests (release)
        run: cargo test --workspace --release
```

No other workflow, script, or config changes.

- [ ] **Step 2: Skip-remnant grep (acceptance evidence — record verbatim)**

Run: `grep -rn "test_ipa_signing_is_deterministic\|--skip" scripts/ .github/ mise.toml hk.pkl`
Expected: only the `#[test] fn test_ipa_signing_is_deterministic`
*definition* in `crates/zsign/src/ipa/mod.rs` if that path is included by
the glob (it isn't — scope is scripts/.github/mise/hk) ⇒ **zero matches**
in scope, or matches only in prose comments that describe running the
full suite. Any `--skip` hit is a failure of this step.

- [ ] **Step 3: Confirm the determinism test passes unskipped (scoped)**

Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-rs test_ipa_signing_is_deterministic`
Expected: `1 passed; 0 failed`.

- [ ] **Step 4: Commit**

Subject: `ci: drop stale determinism skip from release test job (ZSN-30)`

---

### Task 8: Final gates (verbatim, in order)

- [ ] **Step 1:** `cargo fmt --all --check` → must be clean; if not,
  `cargo fmt --all` and include the fix in the next commit.
- [ ] **Step 2:** `TMPDIR=$PWD/.tmptmp cargo clippy --workspace --all-targets -- -D warnings`
  → `0 warnings`.
- [ ] **Step 3:** `TMPDIR=$PWD/.tmptmp cargo test --workspace --no-fail-fast`
  → all suites green, **no skip flags anywhere in the command**. Record
  per-suite counts for the report.
- [ ] **Step 4:** `hk check` (runs lint + clippy + `cargo test --workspace`
  via `hk.pkl:52-54`) → exit 0. If hk is unavailable at run time, record
  that and rely on Steps 1-3 (which are its constituent commands).
- [ ] **Step 5:** `grep -rn -- "--skip" . --include="*.yml" --include="*.toml" --include="*.pkl" --include="*.sh"`
  → zero matches (final skip-free evidence).

---

## Plan self-review

- **Spec coverage:** design §1 (re-audit — done in-doc, no code),
  §2 (Task 1), §3 (Tasks 2-4), §4 (Task 5), §5 e1b/e2/e3/e4 (Task 6),
  §6 assert_cmd (decision recorded in design; no task — nothing to
  change), §7 (Tasks 7-8), §8 acceptance (gates + residue greps in each
  task), §9 deviations (appended during execution). Covered.
- **Placeholder scan:** no TBD/TODO; every code step shows real code or an
  explicit read-then-act instruction with line numbers.
- **Type consistency:** `test_signing_credentials() -> SigningCredentials`
  (owned) everywhere; `make_minimal_macho_32_encrypted`,
  `make_linkedit_only_macho`, `team_ou_test_credentials`,
  `team_ou_test_credentials_with_key`, `test_root_credentials`,
  `fresh_rsa_credentials` names are identical across tasks 3-6.
- **Dependency order:** Task 2 (feature) precedes Tasks 4-5 (cross-crate
  use); Task 5 Step 0 precedes any caching; Task 6 assumes Tasks 1-5
  landed (uses `fixtures::` paths). Task 7 independent; Task 8 last.
