# Provisioning-Profile Validation Wiring — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development with
> dispatching-parallel-agents for independent tasks. Steps use checkbox (`- [ ]`) syntax.
> Tester writes the red tests first for each task; an implementer greens them; scoped gate;
> commit per task. Research agents skip formatters/linters/project-wide tests.

**Goal:** Route every production provisioning-profile consumer through
`validate_and_extract_profile` behind an explicit, per-surface `allow_unsafe_profile` opt-in,
so forged/expired/wrong-team/wrong-app-id profiles error on native, wasm, and CLI surfaces.

**Architecture:** One new core seam (`extract_entitlements_checked`) is called from the two
native loaders (`ZSign::load_entitlements_from_profile`, `IpaSigner::load_profile` /
`load_bundle_profiles`) and the two wasm entry points (constructor, static extractor). Requests
carry the signing-cert team id and the post-rewrite bundle id; wasm passes an explicit `now`
via `js_sys::Date::now()`. Fixtures opt into an explicit bypass; validation behavior is proven
by new tests against CMS-signed fixtures embedded as base64 consts with injected trust anchors.

**Tech Stack:** Rust (edition 2021, MSRV 1.88), `time`, `js-sys`, wasm-bindgen, RustCrypto
x509/cms. Design: docs/superpowers/specs/2026-09-28-profile-validation-wiring-design.md (D1-D8).

**Conventions:** every test command starts with `mkdir -p target/tmp` and runs with
`TMPDIR=$PWD/target/tmp`. Never delete `target/tmp`. No ticket IDs in code comments
(ZSN-118 only in commit subjects). No `println!`/`eprintln!` in `src/`. Repo error-assert
convention: `assert!(matches!(err, Error::Variant(_)), "…, got {err}")`.

---

### Task 1: Core seam `extract_entitlements_checked`

**Files:**
- Modify: `crates/zsign-core/src/provisioning.rs` (new pub fn after
  `extract_entitlements_from_profile`, module docs :1-29)
- Modify: `crates/zsign-core/src/lib.rs:16-17` (re-export)

- [ ] **Step 1: Red test** — add to `provisioning.rs` `mod tests` (next to
  `forged_plaintext_profile_is_rejected_but_legacy_extractor_is_unchanged`, :666):

```rust
#[test]
fn checked_seam_validates_by_default_and_bypasses_only_when_asked() {
    let sp = signed_profile(&plist_xml(""));
    let req = ProfileRequest {
        now: Some(at(T_2026_APR)),
        anchors: Some(sp.anchors.clone()),
        ..Default::default()
    };
    let checked = extract_entitlements_checked(&sp.data, &req, false)
        .unwrap()
        .unwrap();
    let legacy = extract_entitlements_from_profile(&sp.data).unwrap().unwrap();
    assert_eq!(
        checked, legacy,
        "validated extraction must yield the extractor's entitlement bytes"
    );

    let forged = plist_xml("");
    let plain = ProfileRequest {
        now: Some(at(T_2026_APR)),
        ..Default::default()
    };
    let err = extract_entitlements_checked(forged.as_bytes(), &plain, false).unwrap_err();
    assert!(
        matches!(err, crate::Error::Verification(_)),
        "a profile without a CMS envelope must be rejected, got: {err}"
    );
    let bypassed = extract_entitlements_checked(forged.as_bytes(), &plain, true)
        .unwrap()
        .unwrap();
    assert!(
        String::from_utf8(bypassed).unwrap().contains("get-task-allow"),
        "explicit bypass keeps the raw byte-scan contract"
    );
}
```

- [ ] **Step 2: Run red** — `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-core checked_seam`
  Expected: compile failure — cannot find function `extract_entitlements_checked`.

- [ ] **Step 3: Implement** in `provisioning.rs` (place directly after
  `extract_entitlements_from_profile`), with a `///` doc stating: validated by default;
  `allow_unsafe` is the explicit caller-side bypass that keeps the historical raw byte scan:

```rust
pub fn extract_entitlements_checked(
    profile_data: &[u8],
    request: &ProfileRequest,
    allow_unsafe: bool,
) -> Result<Option<Vec<u8>>> {
    if allow_unsafe {
        return extract_entitlements_from_profile(profile_data);
    }
    Ok(validate_and_extract_profile(profile_data, request)?.entitlements_xml)
}
```

Add `extract_entitlements_checked` to the `lib.rs` re-export at :17. Rewrite the module doc
(:3-7) and the `ProfileRequest` bypass paragraph (:17-19) so the "allow-unsafe is a caller-side
choice" promise names the flag and the seam instead of telling callers to keep using the raw
extractor; `extract_entitlements_from_profile`'s own doc keeps its historical-contract wording.

- [ ] **Step 4: Green + gate** — `TMPDIR=$PWD/target/tmp cargo test -p zsign-core provisioning`
  Expected: all provisioning tests pass (existing ~20 + the new one).

- [ ] **Step 5: Commit** — `feat: add validated profile extraction seam (ZSN-118)`

### Task 2: Native facade wiring (IpaSigner + ZSign) with CMS fixtures

**Files:**
- Modify: `crates/zsign-core/src/provisioning.rs` (temporary fixture generator, deleted in this task)
- Modify: `crates/zsign/Cargo.toml` (add `time = "0.3"` dependency)
- Modify: `crates/zsign/src/ipa/mod.rs` (struct fields, setters, `load_profile`, `load_bundle_profiles`, tests)
- Modify: `crates/zsign/src/builder.rs` (field, setter, forwarding, loader, tests)

- [ ] **Step 1: Generate fixtures (throwaway).** Add a temporary test in
  `provisioning.rs mod tests` that reuses the machinery of `signed_profile` (:547-618) but with
  (a) cert validity 2020-01-01→2099-01-01 (copy of its root/leaf builders, `Validity { not_before, not_after }`
  swapped) and (b) four hand-written plist payloads (the full `<plist>` document, not `plist_xml`,
  because `plist_xml` pins an already-expired 2026 window):

  - `VALID`: `Name=Valid Fixture`, `CreationDate=2020-01-01`, `ExpirationDate=2099-01-01`,
    `TeamIdentifier=[TESTTEAM]`, `ApplicationIdentifierPrefix=[TESTTEAM]`, Entitlements
    `application-identifier=TESTTEAM.com.test.app`, `get-task-allow=true`.
  - `EXPIRED`: identical but `ExpirationDate=2001-01-02`.
  - `WRONG_TEAM`: identical to VALID but both team keys `[EVILTEAM]` and
    `application-identifier=EVILTEAM.com.test.app`.
  - `WRONG_APP`: VALID teams, `application-identifier=TESTTEAM.com.other.app`.

  The test prints `NAME=<base64>` lines for the four profile byte blobs plus the root
  certificate DER, using the crate's `base64` dependency. Run
  `TMPDIR=$PWD/target/tmp cargo test -p zsign-core generate -- --nocapture`, capture the output,
  and paste the base64 strings as consts into the `ipa/mod.rs` tests module:
  `VALID_PROFILE_B64`, `EXPIRED_PROFILE_B64`, `WRONG_TEAM_PROFILE_B64`,
  `WRONG_APP_PROFILE_B64`, `PROFILE_TEST_ROOT_DER_B64`, plus the bare-XML forgery const
  `FORGED_PROFILE_XML` carrying the brief's payload: no CMS envelope, `TeamIdentifier=[EVILTEAM]`,
  `application-identifier=EVILTEAM.com.other.app`, `ExpirationDate=2001-01-02`,
  `get-task-allow=true`, `keychain-access-groups=[*]`.

- [ ] **Step 2: Fixture sanity test** (green even before wiring — it exercises core directly):

```rust
#[test]
fn valid_fixture_validates_against_injected_root() {
    let profile = base64_engine().decode(VALID_PROFILE_B64).unwrap();
    let root = x509_cert::Certificate::from_der(
        &base64_engine().decode(PROFILE_TEST_ROOT_DER_B64).unwrap(),
    )
    .expect("root fixture must be a certificate");
    let info = zsign_core::validate_and_extract_profile(
        &profile,
        &ProfileRequest {
            anchors: Some(TrustAnchors::from_certificates(vec![root])),
            expected_team_id: Some("TESTTEAM".into()),
            target_bundle_id: Some("com.test.app".into()),
            ..Default::default()
        },
    )
    .expect("valid fixture must validate at the wall clock");
    assert!(
        info.entitlements_xml.is_some(),
        "the valid fixture must carry entitlements"
    );
    assert!(
        String::from_utf8(info.entitlements_xml.unwrap()).unwrap().contains("get-task-allow"),
        "fixture entitlements round-trip"
    );
}
```

  `base64_engine` = a small helper using `base64::engine::general_purpose::STANDARD`, already a
  facade dependency; `TrustAnchors` via `zsign_core::crypto::cms_verify::TrustAnchors`; `from_der`
  via `spki::der::Decode`, a facade dev-dependency. Adapt imports to the file's existing `use`
  block style.) If this fails, the generated window/chain is wrong — fix the generator and
  regenerate. **Only after this test passes, delete the temporary generator** from
  `provisioning.rs`; it must not survive into any commit.

- [ ] **Step 3: Red regression tests** (add to `ipa/mod.rs` tests; these fail before Step 4 —
  `allow_unsafe_profile`/`profile_anchors` do not exist, and the forged profile currently signs):

  1. `sign_ipa_bytes_rejects_forged_profile` — `IpaSigner::new(&test_credentials())`
     `.provisioning_profile_bytes(FORGED_PROFILE_XML.to_vec())`
     `.sign_ipa_bytes(&test_ipa_bytes(&[]))` → `Err`; assert `matches!(…, Error::Core(zsign_core::Error::Verification(_)))`
     with the `got:` footer convention.
  2. `sign_ipa_bytes_accepts_forged_profile_with_explicit_bypass` — same plus
     `.allow_unsafe_profile(true)` → `Ok` (dual-pin: the bypass is the only way a forged
     profile signs).
  3. `sign_ipa_bytes_accepts_valid_profile_with_injected_anchors` — VALID bytes +
     `.profile_anchors(root)` → `Ok`, and the output zip contains
     `Payload/Test.app/embedded.mobileprovision` (verify the actual payload dir name from
     `write_test_ipa` first — its Info.plist declares `com.test.app`, which is exactly the
     fixture App ID).
  4. `sign_ipa_bytes_rejects_expired_profile`, `…_wrong_team_…`, `…_wrong_app_id_profile` —
     each `Err(Error::Core(zsign_core::Error::ProvisioningProfile(_)))`; assert the message
     contains the fixture's `Name` ("Valid Fixture" / "Wrong Team" / … — every gate message
     names the profile per the `validate_and_extract_profile` doc) and, respectively, the gate
     wording actually used at provisioning.rs:143-212 (read those lines and pin one substring
     each: expiry / team / App-ID).
  5. builder tests in `builder.rs`: `sign_macho_rejects_forged_profile` (`ZSign::new()`
     `.credentials(…)` `.provisioning_profile(forged_path)` `.sign_macho(in, out)` →
     `Err(Verification)`) and `sign_macho_accepts_forged_profile_with_explicit_bypass`
     (`.allow_unsafe_profile(true)` → `Ok`).

- [ ] **Step 4: Implement the wiring.**

  `crates/zsign/Cargo.toml` `[dependencies]`: add `time = "0.3"`.

  `ipa/mod.rs` — add three fields to `IpaSigner` and initialize them in **both** `new` (:385)
  and `new_adhoc` (:405):

```rust
/// Skip CMS/expiry/team/App-ID validation of provisioning profiles (explicit opt-in)
allow_unsafe_profile: bool,
/// Injected trust anchors for profile CMS verification; `None` anchors to Apple's root
profile_anchors: Option<TrustAnchors>,
/// Explicit verification instant for profile validation; `None` uses the wall
/// clock on native and errors on wasm32
profile_now: Option<OffsetDateTime>,
```

  Setters (builder style, `mut self -> Self`, docs naming the default and the risk, following
  `remove_embedded_profile` at :434): `allow_unsafe_profile(bool)`,
  `profile_anchors(TrustAnchors)`, `profile_now(OffsetDateTime)`.

  Private helper used by both loaders:

```rust
fn profile_request(&self, target_bundle_id: Option<String>) -> ProfileRequest {
    ProfileRequest {
        now: self.profile_now,
        anchors: self.profile_anchors.clone(),
        expected_team_id: self.credentials.and_then(|c| c.team_id.clone()),
        target_bundle_id,
        target_device_udid: None,
    }
}
```

  `load_profile` gains a `root_id: &str` parameter (sole caller: `sign_bundle` (:842), the
  `load_profile()` call at :878 — pass `&root_id_final`), builds
  `self.profile_request(Some(root_id.to_string()))`, and replaces
  both `zsign_core::extract_entitlements_from_profile` calls (:646, :650) with
  `zsign_core::extract_entitlements_checked(&data, &request, self.allow_unsafe_profile)`.
  Keep the `fs::read` and error shape unchanged.

  `load_bundle_profiles` — inside the loop, after the existing wrappers:
  `let request = self.profile_request(Some(id.clone()));` and swap the :696 extractor call for
  `extract_entitlements_checked(&data, &request, self.allow_unsafe_profile)` inside the existing
  `map_err` that names bundle id + path (do not alter that message).

  `builder.rs` — add field `allow_unsafe_profile: bool` (init `false` in `new`), setter
  `pub fn allow_unsafe_profile(mut self, allow: bool) -> Self`. In `sign_ipa` (:509-521) and
  `sign_bundle` (:578-587) construction blocks, forward
  `if self.allow_unsafe_profile { signer = signer.allow_unsafe_profile(true); }` after the
  existing chained setters. In `load_entitlements_from_profile` (:636-654) build

```rust
let request = ProfileRequest {
    now: None,
    anchors: None,
    expected_team_id: self.credentials.as_ref().and_then(|c| c.team_id.clone()),
    target_bundle_id: self.bundle_id.clone(),
    target_device_udid: None,
};
match extract_entitlements_checked(&profile_data, &request, self.allow_unsafe_profile)? { … }
```

  and drop the now-unused `use crate::extract_entitlements_from_profile;` (:29) — imports must
  match the file's existing grouping. `ZSign::sign_macho` keeps its eager `.or()`; nothing else
  in builder changes.

- [ ] **Step 5: Migrate every broken fixture test** by adding the explicit bypass to the signer
  that loads the profile (`.allow_unsafe_profile(true)` on `IpaSigner`, or the `ZSign` setter for
  builder tests). Known sites (the gate will reveal any residual):

  - `ipa/mod.rs`: test_sign_ipa_bytes_entitlements_bytes_override, test_entitlements_override_applies_to_root_bundle,
    test_blob_source_bytes_setters_match_path_form, test_entitlements_dir_hit_replaces_profile,
    test_entitlements_dir_miss_falls_back_to_profile, test_entitlements_dir_traversal_id_never_reads_outside,
    test_entitlements_dir_non_regular_entry_falls_back, test_profile_map_embeds_and_derives_for_nested,
    test_profile_map_unused_key_errors, test_profile_map_invalid_profile_names_bundle,
    test_nested_app_id_uses_own_profile_prefix (inline TESTTEAM2 profile), test_bundle_id_change_child_profile_resolves_by_rewritten_id,
    test_without_bundle_id_change_entitlements_not_reserialized, test_bundle_id_change_rewrites_entitlements_identifiers,
    test_app_groups_never_rewritten, test_without_bundle_id_change_entitlements_verbatim,
    test_distribution_profile_drops_get_task_allow, test_bundle_id_change_rewrites_legacy_app_id_key,
    test_remove_embedded_profile_skips_embed_but_keeps_derived_entitlements
  - `builder.rs`: test_sign_macho_adhoc_applies_profile_entitlements,
    test_sign_macho_entitlements_override_replaces_profile (eager `.or()` loads the profile even
    when the override wins), test_sign_macho_entitlements_override_with_credentials,
    test_sign_bundle_forwards_bundle_profiles, test_sign_ipa_forwards_bundle_profiles

  Do NOT touch tests that never load profile bytes (root-id/duplicate/missing-file rejections
  fire before extraction) or that call `extract_entitlements_from_profile` directly — that
  function's contract is unchanged.

- [ ] **Step 6: Gate** — `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-rs`
  Expected: all facade tests green (including the new regression set).

- [ ] **Step 7: Commit** — `feat: validate provisioning profiles on the native sign path (ZSN-118)`

### Task 3: wasm wiring (constructor + static extractor + IPA forwarding)

**Files:**
- Modify: `crates/zsign-wasm/Cargo.toml` (add `time = "0.3"` dependency)
- Modify: `crates/zsign-wasm/src/lib.rs` (fields, `new` signature, static
  `extract_entitlements`, `sign_ipa` forwarding at :680-683, tests at :770+, :819+, :1646+, :1659+)

- [ ] **Step 0: Manifest** — add `time = "0.3"` to `crates/zsign-wasm/Cargo.toml`
  `[dependencies]` (the `host_now` helper below constructs `OffsetDateTime`; the wasm-bindgen
  feature of `time` is not needed — only type construction).

- [ ] **Step 1: Red tests** in `zsign-wasm` `mod tests` (bare-XML const `FORGED_PROFILE_XML`,
  same payload as Task 2: no CMS envelope, EVILTEAM, wrong app-id, `ExpirationDate` 2001-01-02,
  `get-task-allow=true`, `keychain-access-groups=[*]`):

  1. `constructor_rejects_forged_profile` —
     `WasmSigner::new(&decode_base64(LEAF_P12_B64), "test", Some(FORGED_PROFILE_XML.to_vec()), None)`
     → `Err`; assert `error_code(&e) == Some("ZSIGN_VERIFICATION")` (a missing CMS envelope is
     `zsign_core::Error::Verification` — read the message with `err_message(e)` in the footer).
  2. `constructor_accepts_forged_profile_with_explicit_bypass` — same with
     `Some(true)` → `Ok`, and `signer.entitlements()` contains `get-task-allow` (dual-pin).
  3. `extract_entitlements_rejects_forged_profile` — `WasmSigner::extract_entitlements(&FORGED, None)`
     → `Err(ZSIGN_VERIFICATION)`; `…(&FORGED, Some(true))` → `Ok`.
  4. Update `constructor_rejects_bad_profile` (:1659): the expected code moves from
     `ZSIGN_INVALID_PROFILE` to `ZSIGN_VERIFICATION`, with a one-line comment that the raw-scan
     parse error became a CMS-envelope verification failure.

- [ ] **Step 2: Run red** — `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-wasm`
  Expected: compile failure (arity/missing symbols) and/or assertion failures.

- [ ] **Step 3: Implement** in `lib.rs`:

```rust
/// Verification instant for profile validation: the browser clock on wasm32
/// (resolve_now hard-errors on an omitted instant there), the native wall
/// clock elsewhere.
fn host_now() -> Option<OffsetDateTime> {
    #[cfg(target_arch = "wasm32")]
    {
        let ms = js_sys::Date::now();
        OffsetDateTime::from_unix_timestamp_nanos((ms as i128) * 1_000_000).ok()
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        None
    }
}
```

  - `WasmSigner` gains field `allow_unsafe_profile: bool`.
  - `new` becomes `new(p12_bytes, p12_password, profile_bytes, allow_unsafe_profile: Option<bool>)`
    (trailing `Option` stays optional for existing JS callers); replace the :261 extractor call
    with `zsign_core::extract_entitlements_checked(data, &ProfileRequest { now: host_now(),
    anchors: None, expected_team_id: credentials.team_id.clone(), target_bundle_id: None,
    target_device_udid: None }, allow)`.
  - static `extract_entitlements(profile_data, allow_unsafe_profile: Option<bool>)` (:477-486):
    same request but `expected_team_id: None` (static — no credentials).
  - `sign_ipa` forwarding (:680-683): after `provisioning_profile_bytes`,
    `if self.allow_unsafe_profile { signer = signer.allow_unsafe_profile(true); }` and
    `if let Some(now) = host_now() { signer = signer.profile_now(now); }`.
  - Keep `MAX_PROFILE_BYTES` guards exactly where they are (:249-256, :478-483) — the cap does
    not move (bundle-6 owns that).

- [ ] **Step 4: Migrate fixture consumers** — `new_signer_with_profile` (:819-826) passes
  `Some(true)` as the 4th argument (covers non_executable_input_ignores_profile_entitlements,
  entitlements_setter_overrides_then_reverts_to_profile, constructor_extracts_profile_entitlements_and_team_id);
  any other constructor call feeding `PROFILE_XML` gets the same opt-in. `sign_ipa_round_trip`
  (no profile) is untouched.

- [ ] **Step 5: Gate** — `TMPDIR=$PWD/target/tmp cargo test -p zsign-wasm`, then
  `wasm-pack test --node crates/zsign-wasm` (if `wasm-pack` is missing, wait ~30s and retry
  once — post-start warm-up — before reporting a blocker). Expected: both green; the native
  run exercises `host_now`'s wall-clock arm, the wasm-pack run its `js_sys::Date` arm.

- [ ] **Step 6: Commit** — `feat: validate profiles on the wasm sign surfaces (ZSN-118)`

### Task 4: CLI bypass flag + interop script migration

**Files:**
- Modify: `crates/zsign-cli/src/main.rs` (flag, wiring, tests)
- Modify: `scripts/verify-apple-interop.sh` (signing invocation ~:155)

- [ ] **Step 1: Red tests** in `main.rs mod tests`:

  1. `forged_profile_fails_closed` — write `FORGED_PROFILE_XML` (bare-XML const, same payload
     as Task 2/3) to `<temp>/forged.mobileprovision`; `run_cli(&["-k", IDENTITY_P12 path,
     "-p", "testpassword", "-m", forged, "-o", out, input])` with `input` from
     `fixtures::make_minimal_macho()` → `assert_eq!(r.code, 1, …)` and stderr non-empty.
  2. `allow_unsafe_profile_flag_accepts_forged_profile` — same args plus
     `--allow-unsafe-profile` → `assert_eq!(r.code, 0, …)` (dual-pin at the CLI surface).

  Follow the exact `run_cli`/`TempDir` idioms of `missing_profile_error_names_the_file` (:2128).

- [ ] **Step 2: Run red** — `TMPDIR=$PWD/target/tmp cargo test -p zsign-cli forged_profile`
  Expected: unknown-argument usage error (exit 2 from clap) / assertion failure.

- [ ] **Step 3: Implement** — add next to the other profile flags (`-m/--profile`, :52-54):

```rust
/// Skip CMS/expiry/team/App-ID validation of the provisioning profile (unsafe)
#[arg(long)]
allow_unsafe_profile: bool,
```

  and wire it where the other options are applied (:230-248):
  `if cli.allow_unsafe_profile { signer = signer.allow_unsafe_profile(true); }`.

- [ ] **Step 4: Migrate `scripts/verify-apple-interop.sh`** — append `--allow-unsafe-profile`
  to the `zsign … -m fixture.mobileprovision …` invocation and adjust its comment: the script's
  fixture is deliberately a plist-window profile, not a CMS envelope (its own comment at :149
  already says so), so it opts into the bypass explicitly. The script is macOS-only and cannot
  be executed on this host — state that as an unexercised edit in the final report.

- [ ] **Step 5: Gate** — `TMPDIR=$PWD/target/tmp cargo test -p zsign-cli` (the subprocess tests
  rebuild the binary first; expected green).

- [ ] **Step 6: Commit** — `feat: add cli opt-in for unvalidated provisioning profiles (ZSN-118)`

### Task 5: Zero-warning gate + cleanup audit

- [ ] **Step 1:** `cargo fmt --all -- --check` — fix with `cargo fmt --all` if needed (style-only
  follow-up commit allowed: `style: apply rustfmt (ZSN-118)`).
- [ ] **Step 2:** `cargo clippy --workspace --all-targets -- -D warnings` — zero diagnostics.
- [ ] **Step 3:** `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test --workspace`
  — must finish green **with no skip flags**; if any test fails, diagnose (systematic-debugging)
  and fix it rather than filtering it out.
- [ ] **Step 4:** `wasm-pack test --node crates/zsign-wasm` once more after any fix from Step 3.
- [ ] **Step 5: Cleanup audit** (all must hold):
  - `git status` shows only intended files; the temporary fixture generator is gone.
  - `grep -rn "TODO\|FIXME\|PLACEHOLDER" crates/zsign-core/src/provisioning.rs crates/zsign/src crates/zsign-wasm/src crates/zsign-cli/src` → empty.
  - `grep -rn "ZSN-" crates/` → empty (ticket ids live in commit subjects only).
  - No `println!`/`eprintln!` added under `src/`.
  - No production caller of `extract_entitlements_from_profile` remains except the seam
    itself: `grep -rn "extract_entitlements_from_profile" crates --include=*.rs` must show only
    provisioning.rs (definition/docs/tests), lib.rs re-exports, and fuzz.
  - `target/tmp` still exists (never deleted).

## Self-review (writing-plans checklist)

- Spec coverage: design §1 sites 1-6 → Tasks 1-4; D1→T1, D2/D5/D7→T2, D4/D6→T3, D4 CLI→T4,
  D8 error shapes → T2/T3 test assertions, §6 acceptance → the four test groups + T5 gates.
  Scope fences (§5) are enforced by "do not touch" instructions inside the tasks.
- Placeholders: none — every step names exact files, symbols, and commands.
- Type consistency: `extract_entitlements_checked(data, request, allow_unsafe)` and
  `ProfileRequest { now, anchors, expected_team_id, target_bundle_id, target_device_udid }`
  are used identically across T1-T4; setter names `allow_unsafe_profile` / `profile_anchors` /
  `profile_now` match between T2 definition and T3/T4 use.
