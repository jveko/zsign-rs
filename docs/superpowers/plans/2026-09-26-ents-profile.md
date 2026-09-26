# Entitlements & Provisioning-Resolution Pipeline (ZSN-10/22/12/11/20) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development
> with dispatching-parallel-agents for independent tasks to implement this
> plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** One per-bundle entitlements/profile resolution pipeline: `-e` override,
`--entitlements-dir`, `--profile-map id=path`, bundle-id-change rewriting, `-R`
strip — as specified in `docs/superpowers/specs/2026-09-26-ents-profile-design.md`
(normative: §3 precedence table, §4 D1-D10, §5 invariants).

**Architecture:** All five options ride the existing ZSN-35 forwarding convention
(Cli → `ZSign` → `IpaSigner`), replace the hard-coded `is_main_bundle ? x : None`
pair at `crates/zsign/src/ipa/mod.rs:397-405` with a resolver loop, and reuse the
existing discovery predicate, profile extractor, and DER validation gate — no new
modules, no new predicates, no zsn41/zsn42 files touched.

**Tech Stack:** Rust workspace (`zsign-rs`, `zsign-cli`, `zsign-wasm`), `plist`,
`clap` 4 derive, inline `#[cfg(test)]` tests only.

**Conventions (every task):**
- Test commands: `TMPDIR=$PWD/.tmptmp cargo test -p <pkg> <filter> -- --skip test_ipa_signing_is_deterministic`.
  The skip is a TEMPORARY machine-flake workaround tracked by ZSN-15 (lane zsn41
  owns the fix); removal condition: drop it once ZSN-15 lands. Never copy it into CI config.
- Scoped fmt/clippy mid-flight only (`cargo fmt -p <pkg>`, `cargo clippy -p <pkg> --all-targets -- -D warnings`);
  project-wide gates run only in Task 6.
- Every red step must be observed failing for the RIGHT reason (assertion / named
  error), not incidental compile breakage of unrelated code. New-option compile
  failure (`cannot find method`) is acceptable red for the flag tests.
- Commit subjects: lowercase imperative, ticket ID in subject only, never in code.

---

### Task 1: ZSN-10 — custom entitlements file override (`-e` / `--entitlements`)

**Files:**
- Modify: `crates/zsign/src/builder.rs` (field ~:88, setter after :157,
  `sign_macho` :320, loaders :509-526, forwarding blocks :420-424 and :474-477,
  tests mod)
- Modify: `crates/zsign/src/ipa/mod.rs` (field :122-136 region, setters :189-192
  region, `sign_bundle_from_options` :337-354, tests mod)
- Modify: `crates/zsign-cli/src/main.rs` (`Cli` :47-49 region, `-V` conflict list
  :113-135, forwarding :170-172, tests mod)
- Verify-only: `crates/zsign-wasm/src/lib.rs` — the ZSN-40 setter already
  implements override > profile precedence (`effective_entitlements` :304-308,
  pinned by `entitlements_setter_overrides_then_reverts_to_profile` :1052).
  NO wasm code. Item-0 verify-then-skip, record in the report.

- [ ] **Step 1.1 (Tester): failing library tests** in `builder.rs` tests mod.
  Reuse the existing fixtures: `PROFILE_FIXTURE` (~:960, carries
  `com.zsign.test.entitlement` + `TESTTEAM` app-id) and the slot-reading pattern
  of `test_sign_macho_adhoc_applies_profile_entitlements` (:973-1017). New const:

```rust
const OVERRIDE_ENTITLEMENTS: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>application-identifier</key>
    <string>TESTTEAM.com.override.app</string>
    <key>com.zsign.override.ent</key>
    <true/>
</dict>
</plist>"#;
```

  Tests (names pinned):
  - `test_sign_macho_entitlements_override_replaces_profile`: adhoc + profile +
    `.entitlements(file)` → slot contains `com.zsign.override.ent` and NOT
    `com.zsign.test.entitlement` (replace semantics, adhoc honored — the brief's
    precedence-over-ab8ced8 case).
  - `test_sign_macho_entitlements_override_with_credentials`: same with
    `test_credentials()` non-adhoc (uses `ZSign::new().credentials(...)` — mirror
    existing credential-test setup in this mod).
  - `test_sign_macho_adhoc_entitlements_override_without_profile`: adhoc +
    `-e` only → slot carries the override.
  - `test_entitlements_override_missing_file_names_path`: nonexistent path →
    `Err`, message contains the file name and the label `entitlements file`.
  - `test_entitlements_override_rejects_non_dictionary`: top-level array plist →
    `Err` containing `dictionary`.
  - `test_entitlements_override_rejects_unencodable_values`: dict with a
    `<date>` value (DER encoder rejects Real/Date per der.rs doc) → `Err`.

- [ ] **Step 1.2:** Run `TMPDIR=$PWD/.tmptmp cargo test -p zsign-rs entitlements_override -- --skip test_ipa_signing_is_deterministic`;
  expect compile failure `no method named 'entitlements'` (red).

- [ ] **Step 1.3 (Implementer): builder state + resolution.**
  `ZSign` gains after `allow_encrypted` (:88):

```rust
    /// Custom entitlements file: replaces profile-derived entitlements
    entitlements: Option<PathBuf>,
```

  both `new`-family initializers gain `entitlements: None` (tests at :542-556
  extend to assert the field defaults). Setter mirrors `provisioning_profile`
  (:141-157) including a `/// # Examples` no_run block. Loader (next to
  `load_entitlements_from_profile`, which stays untouched):

```rust
    /// Reads and validates a custom entitlements file. Every rejection is a
    /// hard error naming the path — silently falling back to the profile is
    /// the upstream failure mode this port deliberately does not reproduce.
    fn load_entitlements_override(&self) -> Result<Option<Vec<u8>>> {
        let Some(path) = &self.entitlements else {
            return Ok(None);
        };
        let data = std::fs::read(path).map_err(|e| {
            std::io::Error::new(
                e.kind(),
                format!("failed to read entitlements file '{}': {e}", path.display()),
            )
        })?;
        validate_entitlements_blob(&data, path)?;
        Ok(Some(data))
    }
```

  `sign_macho` :320 becomes:

```rust
        let entitlements = self.load_entitlements_override()?.or(self.load_entitlements_from_profile()?);
```

  Shared gate as a `pub(crate)` free fn in `builder.rs` (ipa reuses it in Task 2):

```rust
/// Validates entitlements bytes against the blob contract: XML-or-binary
/// plist, dictionary root, and DER-encodable by the signer's encoder —
/// the same three checks the wasm setter runs before accepting an override.
pub(crate) fn validate_entitlements_blob(data: &[u8], source: &std::path::Path) -> crate::Result<()> {
    let value: plist::Value = plist::from_bytes(data).map_err(|e| {
        crate::Error::Core(zsign_core::Error::Signing(format!(
            "entitlements file '{}' is not a valid plist: {e}",
            source.display()
        )))
    })?;
    if value.as_dictionary().is_none() {
        return Err(crate::Error::Core(zsign_core::Error::Signing(format!(
            "entitlements file '{}' must contain a top-level dictionary",
            source.display()
        ))));
    }
    zsign_core::codesign::der::plist_to_der(data).map_err(|e| {
        crate::Error::Core(zsign_core::Error::DerEncoding(format!(
            "entitlements in '{}' contain types the signer cannot encode: {e}",
            source.display()
        )))
    })?;
    Ok(())
}
```

(`Error::Plist` carries a `#[from] plist::Error` only, so path-naming parse
rejections use `Error::Core(Error::Signing(..))`; `DerEncoding(String)` takes
the message directly — both variants verified in `zsign-core/src/error.rs:31-38`.)

- [ ] **Step 1.4: IpaSigner plumbing.** Field `entitlements_override:
  Option<PathBuf>` + `pub fn entitlements(mut self, path: impl AsRef<Path>) ->
  Self` setter (style of :189-192); `sign_bundle_from_options` :348-353 becomes:

```rust
        let (profile_data, profile_entitlements) = self.load_profile()?;
        let entitlements = self.load_entitlements_override()?.or(profile_entitlements);
        self.sign_bundle(bundle_path, entitlements.as_deref(), profile_data.as_deref())
```

  plus a private `load_entitlements_override` mirroring the builder's
  (path-named Io error + `crate::builder::validate_entitlements_blob`).

- [ ] **Step 1.5: forwarding + CLI.** Add to BOTH rebind blocks (sign_ipa
  :422-424 region, sign_bundle :475-477 region), right after the
  `provisioning_profile` rebind:

```rust
        if let Some(ref entitlements) = self.entitlements {
            signer = signer.entitlements(entitlements);
        }
```

  `Cli` (after `profile` :49):

```rust
    /// Custom entitlements file (replaces the profile's entitlements)
    #[arg(short = 'e', long)]
    entitlements: Option<PathBuf>,
```

  `"entitlements"` appended to `-V`'s `conflicts_with_all` list; forwarding in
  `run()` after the profile forward (:170-172).

- [ ] **Step 1.6 (Tester): CLI tests** — `entitlements_flag_parses_short_and_long`,
  `verify_conflicts_with_entitlements` (both orders + alone-valid control,
  `parse_err` pattern :1573+).
- [ ] **Step 1.7:** Run library + CLI scoped:
  `TMPDIR=$PWD/.tmptmp cargo test -p zsign-rs entitlements -- --skip test_ipa_signing_is_deterministic`,
  `TMPDIR=$PWD/.tmptmp cargo test -p zsign-cli -- --skip test_ipa_signing_is_deterministic`
  — green.
- [ ] **Step 1.8:** `cargo fmt -p zsign-rs -p zsign-cli && cargo clippy -p zsign-rs --all-targets -- -D warnings && cargo clippy -p zsign-cli --all-targets -- -D warnings`.
- [ ] **Step 1.9:** Commit: `git add -A && git commit -m "feat(signing): add custom entitlements file override (ZSN-10)"`
  (red tests may share the commit; green is what the subject guarantees).

---

### Task 2: ZSN-22 — entitlements directory (`--entitlements-dir`), root application

**Files:**
- Modify: `crates/zsign/src/builder.rs` (field/setter/forwarding),
  `crates/zsign/src/ipa/mod.rs` (field/setter + dir lookup + root resolution),
  `crates/zsign-cli/src/main.rs`, tests in both lib files

Scope note: this task applies the directory to the ROOT bundle only; nested
application arrives with Task 3's resolver (design §3.2). Precedence after this
task: `-e` > dir(root id) > profile-derived > none.

- [ ] **Step 2.1 (Tester): failing tests.**
  Library (ipa/mod.rs tests mod; reuse `create_folder_bundle`/`info_plist_xml`
  helpers ~:1250-1281 and a temp `ents/` dir):
  - `test_entitlements_dir_hit_replaces_profile`: `com.test.app.plist` with
    `com.zsign.dir.ent` inside the dir, profile also supplied → root main
    binary's slot contains the dir marker, not the profile marker.
  - `test_entitlements_dir_miss_falls_back_to_profile`.
  - `test_entitlements_dir_traversal_id_never_reads_outside`: root
    `CFBundleIdentifier` literally `"../evil"`, planted `evil.plist` (marker
    `com.zsign.evil`) one level above the dir → falls back to profile
    entitlements; evil marker absent from the slot.
  - `test_entitlements_dir_invalid_file_names_path`: dir file is garbage →
    `Err` naming the file (and signing aborted before any mutation).
  CLI: `entitlements_dir_flag_parses`, `verify_conflicts_with_entitlements_dir`.
- [ ] **Step 2.2:** Red run (`-- --skip test_ipa_signing_is_deterministic`),
  expect `no method named 'entitlements_dir'`.
- [ ] **Step 2.3 (Implementer).** `ZSign` + `IpaSigner` field
  `entitlements_dir: Option<PathBuf>` + setters (doc: directory of
  `<bundle-id>.plist` files; exact-key only). Forward in both rebind blocks +
  `run()`. `Cli`: `#[arg(long)] entitlements_dir: Option<PathBuf>` + `-V`
  conflict. Builder `sign_macho` does NOT consult the directory (bare files
  have no bundle identity — design §3.2 first row).
  IpaSigner lookup:

```rust
    /// Exact-key entitlements directory hit: `<dir>/<bundle-id>.plist`.
    /// Ids with separators, `..` components, or NUL never hit the directory
    /// (they are malformed identities, and reading through them is an escape).
    fn entitlements_from_dir(&self, dir: &Path, bundle_id: &str) -> Result<Option<Vec<u8>>> {
        if bundle_id.is_empty()
            || bundle_id.contains('/')
            || bundle_id.contains('\\')
            || bundle_id.contains('\0')
            || bundle_id.contains("..")
        {
            return Ok(None);
        }
        let path = dir.join(format!("{bundle_id}.plist"));
        let data = match fs::read(&path) {
            Ok(data) => data,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => {
                return Err(Error::Io(std::io::Error::new(
                    e.kind(),
                    format!("failed to read entitlements file '{}': {e}", path.display()),
                )))
            }
        };
        crate::builder::validate_entitlements_blob(&data, &path)?;
        Ok(Some(data))
    }
```

  Root resolution (the id read happens AFTER the root rewrite, so the
  resolution lives where `root_id` is available; the red tests pin behavior,
  not placement):

```rust
        let entitlements = self
            .load_entitlements_override()?
            .or(self.dir_hit(&root_id)?)
            .or(profile_entitlements);
```

  with `root_id = self.get_bundle_identifier(bundle_path)?` computed after the
  existing rewrites, and `dir_hit` returning `Ok(None)` when
  `entitlements_dir` is unset. (`sign_bundle`'s `entitlements`/`profile_data`
  params may be restructured by this move — Task 3 finalizes the signature
  either way; keep `sign_bundle` compiling green at task end.)
- [ ] **Step 2.4:** Green runs (library filters `entitlements_dir`, CLI
  package), fmt/clippy scoped, then commits: red-test commit, then
  `git commit -m "feat(signing): add bundle-keyed entitlements directory (ZSN-22)"`.

---

### Task 3: ZSN-12 — per-nested-bundle profiles (`--profile-map id=path`) + the resolver

**Files:**
- Modify: `crates/zsign/src/ipa/mod.rs` (resolver loop replaces :397-405
  hard-coding; `sign_single_bundle` :681-747 loses `copy_provisioning_profile`;
  new `load_bundle_profiles`; fixtures/tests)
- Modify: `crates/zsign/src/builder.rs` (`bundle_profiles` field/setter/forward)
- Modify: `crates/zsign-cli/src/main.rs` (`--profile-map` + parse-time
  validation + `-V` conflict + forward)
- Contract tests that MUST stay green untouched: `already_signed` bookkeeping
  :387-391, dylib no-ents pin :1766-1768, nested default pin :2111-2113.

- [ ] **Step 3.1 (Tester): fixture + failing library tests.**
  Inline const `EXT_PROFILE_FIXTURE`: XML profile dict with
  `Entitlements.application-identifier = "TESTTEAM.com.test.app.ext"`, marker
  key `com.zsign.ext.ent`, `TeamIdentifier = ["TESTTEAM"]`, and
  `ProvisionedDevices` (development profile) — shape copied from builder.rs
  `PROFILE_FIXTURE` (:960: the unvalidated extractor scans
  `<?xml …</plist>` anywhere, so an XML-only fixture is accepted).
  Bundle fixture: root app `com.test.app` + `PlugIns/Ext.appex`
  `com.test.app.ext` (reuse the XPC discovery test pattern :2052+, which shows
  the minimal appex skeleton: Info.plist markers + a minimal_macho executable).
  Tests:
  - `test_profile_map_embeds_and_derives_for_nested`: map entry
    `("com.test.app.ext", ext profile)` → appex dir contains
    `embedded.mobileprovision` equal to the map bytes; appex main binary slot
    carries `com.zsign.ext.ent`; root binary slot still carries the root
    profile marker (no bleed either way).
  - `test_profile_map_unused_key_errors`: entry `com.test.app.nope` → `Err`
    naming the unused key.
  - `test_profile_map_root_id_rejected`: key == root id → `Err` mentioning
    `--profile`.
  - `test_profile_map_duplicate_key_errors`.
  - `test_profile_map_missing_profile_file_names_path`.
  - no-map regression = the existing :2111 pin (do NOT duplicate).
  CLI: `profile_map_parses_repeated_pairs`, `profile_map_rejects_malformed_at_parse`
  (`nopath`, `=x`, `a=` → `ErrorKind::ValueValidation`),
  `verify_conflicts_with_profile_map`.
- [ ] **Step 3.2:** Red run, expect `no method named 'bundle_profiles'`.
- [ ] **Step 3.3 (Implementer): map loading.** `ZSign` + `IpaSigner` field
  `bundle_profiles: Vec<(String, PathBuf)>`, replacing setter
  `bundle_profiles(Vec<(String, PathBuf)>)`; forward in both rebind blocks.
  IpaSigner loader (called once per run, before the bundle loop):

```rust
    /// Loads the exact-key nested-profile map. Root-id keys are rejected (the
    /// root profile belongs in `provisioning_profile`), as are ids that could
    /// escape the precedence lookup; every entry's bytes + derived
    /// entitlements load up front so failures precede any mutation.
    fn load_bundle_profiles(&self, root_id: &str) -> Result<HashMap<String, ProfilePayload>> {
        let mut map = HashMap::new();
        for (id, path) in &self.bundle_profiles {
            if id.is_empty()
                || id.contains('/')
                || id.contains('\\')
                || id.contains('\0')
                || id.contains("..")
            {
                return Err(Error::Core(zsign_core::Error::Signing(format!(
                    "invalid bundle id '{id}' in provisioning profile map"
                ))));
            }
            if id == root_id {
                return Err(Error::Core(zsign_core::Error::Signing(format!(
                    "profile map key '{id}' is the main bundle; the root profile belongs in --profile"
                ))));
            }
            if map.contains_key(id) {
                return Err(Error::Core(zsign_core::Error::Signing(format!(
                    "duplicate profile map key '{id}'"
                ))));
            }
            let data = fs::read(path).map_err(|e| {
                std::io::Error::new(
                    e.kind(),
                    format!(
                        "failed to read provisioning profile for bundle '{id}' at '{}': {e}",
                        path.display()
                    ),
                )
            })?;
            let ent = zsign_core::extract_entitlements_from_profile(&data)?;
            map.insert(id.clone(), (Some(data), ent));
        }
        Ok(map)
    }
```

- [ ] **Step 3.4 (Implementer): the resolver loop.** `sign_bundle` absorbs
  resolution (its `entitlements`/`profile_data` params die), so the loop reads
  (design §3.1; deep-first order and the dylib pass unchanged):

```rust
        let root_id = self.get_bundle_identifier(bundle_path)?;
        let (profile_data, profile_entitlements) = self.load_profile()?;
        let root_entitlements = self
            .load_entitlements_override()?
            .or(self.dir_hit(&root_id)?)
            .or(profile_entitlements);
        let mut profile_map = self.load_bundle_profiles(&root_id)?;
        let mut nested_ids = Vec::new();
        for (nested_bundle_path, _depth) in &bundles {
            let is_main_bundle = nested_bundle_path == bundle_path;
            let (entitlements, profile_data) = if is_main_bundle {
                (root_entitlements.clone(), profile_data.clone())
            } else {
                let id = self.get_bundle_identifier(nested_bundle_path)?;
                nested_ids.push(id.clone());
                match profile_map.remove(&id) {
                    Some((pd, pe)) => (self.dir_hit(&id)?.or(pe), pd),
                    None => (self.dir_hit(&id)?, None),
                }
            };
            self.sign_single_bundle(
                nested_bundle_path,
                entitlements.as_deref(),
                profile_data.as_deref(),
                &already_signed,
            )?;
        }
        if !profile_map.is_empty() {
            let mut unused: Vec<_> = profile_map.keys().cloned().collect();
            unused.sort();
            nested_ids.sort();
            return Err(Error::Core(zsign_core::Error::Signing(format!(
                "provisioning profile map keys matched no bundle: {unused:?}; nested bundle ids: {nested_ids:?}"
            ))));
        }
```

  `sign_single_bundle`: drop the `copy_provisioning_profile: bool` param; embed
  iff `profile_data` is `Some` (the block at :711-723 unwraps one level).
  Update the `sign_bundle` doc step list (:367-370) from "main app only" to
  per-bundle resolution wording. `dir_hit(id)` = Task 2's
  `entitlements_from_dir` against `self.entitlements_dir`, `Ok(None)` unset.
- [ ] **Step 3.5 (Implementer): CLI.** After `profile` in `Cli`:

```rust
    /// Per-bundle provisioning profile as bundle-id=profile-path (repeatable)
    #[arg(
        long = "profile-map",
        value_name = "BUNDLE_ID=PATH",
        value_parser = parse_profile_map
    )]
    profile_map: Vec<(String, PathBuf)>,
```

  free fn `fn parse_profile_map(s: &str) -> std::result::Result<(String, PathBuf), String>`
  via `split_once('=')` requiring both sides non-empty (error message:
  `"expected bundle-id=path, got '{s}'"`); add `"profile_map"` (the field id)
  to `-V`'s conflict list; `run()` forwards `signer.bundle_profiles(cli.profile_map.clone())`
  when non-empty.
- [ ] **Step 3.6:** Green runs (filters `profile_map` + ipa mod, then
  `-p zsign-cli`); confirm :1766/:2111 pins pass unchanged. fmt/clippy scoped.
  Commits: red-test commit, then
  `git commit -m "feat(ipa): resolve nested-bundle provisioning profiles by bundle id (ZSN-12)"`.

---

### Task 4: ZSN-11 — rewrite entitlements + nested identifiers on bundle-id change

**Files:**
- Modify: `crates/zsign-core/src/provisioning.rs` (new `profile_document` +
  refactor of `extract_entitlements_from_profile` :385-407; its tests mod)
- Modify: `crates/zsign/src/ipa/mod.rs` (cascade rewrite after root rewrite;
  entitlements transform in the resolver loop; helpers; tests)
- NOT modified: `crates/zsign/src/builder.rs`, CLI (the trigger is the
  existing `-b`/`bundle_id` surface)

- [ ] **Step 4.1 (Tester): failing tests.**
  `zsign-core/src/provisioning.rs`:
  - `profile_document_returns_full_profile_dict` — fixture (existing
    test-plist/CMS harness ~:565): returns top-level dict exposing `Name`,
    `TeamIdentifier`, `Entitlements`.
  Existing extract tests MUST stay green after the refactor (no behavior change).
  `crates/zsign/src/ipa/mod.rs` (folder fixture: root `com.test.app`,
  `PlugIns/Ext.appex` `com.test.app.ext`, `Watch/1/Companion.app` carrying
  `WKCompanionAppBundleIdentifier = com.test.app`, appex `NSExtension` →
  `NSExtensionAttributes` → `WKAppBundleIdentifier = com.test.app.watch`):
  - `test_bundle_id_change_rewrites_nested_identifiers`: `-b com.new.app` →
    appex id becomes `com.new.app.ext`; watch companion becomes `com.new.app`;
    `WKAppBundleIdentifier` becomes `com.new.app.watch`; keys absent before
    stay absent.
  - `test_bundle_id_change_rewrites_entitlements_identifiers`: root dev
    profile (prefix `TESTTEAM`, `keychain-access-groups =
    ["TESTTEAM.com.test.app", "TESTTEAM.sharedgroup"]`,
    `get-task-allow = true`) → root binary slot:
    `application-identifier = TESTTEAM.com.new.app`; KCG becomes
    `["TESTTEAM.com.new.app", "TESTTEAM.sharedgroup"]`; `get-task-allow`
    still present (development).
  - `test_distribution_profile_drops_get_task_allow`: same but fixture lacks
    `ProvisionedDevices` → slot blob must NOT contain `get-task-allow`.
  - `test_app_groups_never_rewritten`: `com.apple.security.application-groups
    = ["group.com.test.shared"]` byte-unchanged after `-b`.
  - `test_bundle_id_change_child_profile_resolves_by_rewritten_id`: `-b` + map
    key `com.new.app.ext` → appex embeds the mapped profile (integration of
    Task 3's machinery with the cascade ordering).
  - `test_without_bundle_id_change_entitlements_verbatim` (control,
    invariant 1/trigger): no `-b` → slot still carries
    `TESTTEAM.com.test.app` + `get-task-allow` untouched.
- [ ] **Step 4.2:** Red run (filters `bundle_id_change`, `profile_document`).
- [ ] **Step 4.3 (Implementer): unverified profile reader** in
  `zsign-core/src/provisioning.rs` — lift the scan+parse (:386-402) verbatim:

```rust
/// Reads the XML document embedded in a provisioning profile WITHOUT any
/// cryptographic or expiry validation. For metadata that only needs to be
/// consistent with the profile bytes about to be embedded (App ID prefix,
/// team, distribution shape); trust decisions belong to
/// [`validate_and_extract_profile`].
pub fn profile_document(profile_data: &[u8]) -> Result<plist::Value> { /* scan + parse as :386-402 */ }
```

  `extract_entitlements_from_profile` becomes
  `profile_document(...)?.as_dictionary()… entitlements_to_xml(dict)`.
  Re-export convention (verified): `crates/zsign/src/lib.rs:48` has
  `pub use zsign_core::provisioning::extract_entitlements_from_profile;` —
  add the identical line for `profile_document` beside it; consumers call
  `zsign_core::provisioning::profile_document` (ipa/mod.rs already addresses
  core through `zsign_core::` paths, e.g. :300).
- [ ] **Step 4.4 (Implementer): boundary-safe id replacement + nested cascade**
  in `ipa/mod.rs`:

```rust
/// Rewrites `value` when it IS the old id or a sub-id of it
/// (`old.<suffix>`); never a bare substring (com.a must not match com.ab).
fn replace_id_prefix(value: &str, old: &str, new: &str) -> Option<String> {
    if value == old {
        return Some(new.to_string());
    }
    let rest = value.strip_prefix(old)?.strip_prefix('.')?;
    Some(format!("{new}.{rest}"))
}
```

  `fn rewrite_nested_identifiers(&self, bundles: &[(PathBuf, usize)], root: &Path, old: &str, new: &str) -> Result<()>`:
  for every bundle EXCEPT `root` (root already rewritten at :377-379): read
  Info.plist (skip missing/parse-fail? No — nested bundles by discovery always
  have one; propagate errors), then per dictionary mutate: `CFBundleIdentifier`,
  top-level `WKCompanionAppBundleIdentifier`, top-level `WKAppBundleIdentifier`,
  and `NSExtension` → `NSExtensionAttributes` → `WKAppBundleIdentifier` — each
  only when a string value passes `replace_id_prefix`. One read-modify-write
  per bundle; serialize XML like `rewrite_plist_string` (:821-827). Caller: in
  `sign_bundle`, capture `old_root_id = self.get_bundle_identifier(bundle_path)?`
  BEFORE the root rewrites, then after `collect_nested_bundles` (:393-395) and
  BEFORE the resolver loop, run the cascade when `self.bundle_id` is `Some`.
  (Move collection above the dylib pass if that keeps ordering honest —
  discovery does not depend on signing.)
- [ ] **Step 4.5 (Implementer): entitlements transform.** In the resolver loop,
  after `entitlements` resolves and when the trigger is active, for the bundle's
  OLD/NEW ids (nested: from the cascade map path→(old,new); root: old_root/
  new_root):

```rust
/// Aligns signature entitlements with a changed bundle id (design §3.5):
/// application-identifier := <prefix>.<new id>; every keychain-access-groups
/// entry re-prefixed (all prefixes must match the App ID prefix — TN2415)
/// with its suffix rewritten only when it was the old id; get-task-allow
/// dropped for distribution profiles (TN2319); all other keys verbatim.
fn rewrite_entitlements_for_id(
    ents: &[u8],
    old_id: &str,
    new_id: &str,
    prefix: Option<&str>,
    drop_get_task_allow: bool,
) -> Result<Vec<u8>>
```

  (free fn, plist parse → mutate dict → `plist::to_writer_xml`). Prefix chain
  helper `fn app_id_prefix(profile_data: Option<&[u8]>) -> Option<String>`:
  `profile_document` → `Entitlements['application-identifier']` (macOS spelling
  `com.apple.application-identifier` fallback, mirroring ProfileInfo :58-60) →
  text before first `.`; else `TeamIdentifier[0]`; else `None` (transform then
  keeps the existing value's own prefix). Distribution detection:
  `fn profile_is_distribution(profile_data: Option<&[u8]>) -> bool` = document
  present and lacks `ProvisionedDevices` (get-task-allow untouched when no
  profile resolves at all — design D7). Applied per bundle to the bundle's own
  resolved `(entitlements, profile_data)`, root included.
- [ ] **Step 4.6:** Green runs (filters above; full `-p zsign-rs ipa::` mod;
  `-p zsign-core` provisioning tests). fmt/clippy scoped on the three touched
  packages. Commits: red-test commit, then
  `git commit -m "feat(ipa): rewrite entitlements and nested identifiers on bundle id change (ZSN-11)"`.

---

### Task 5: ZSN-20 — remove embedded profile (`-R` / `--remove-profile`)

**Files:**
- Modify: `crates/zsign/src/ipa/mod.rs` (`sign_single_bundle` top strip +
  embed gate; setter/field; tests)
- Modify: `crates/zsign/src/builder.rs` (bool field/setter/forward ×2)
- Modify: `crates/zsign-cli/src/main.rs` (`-R` + `-V` conflict + forward)

- [ ] **Step 5.1 (Tester): failing tests.**
  - `test_remove_embedded_profile_strips_every_bundle`: folder fixture pre-seeds
    `embedded.mobileprovision` (junk bytes) at root AND in `PlugIns/Ext.appex`
    (source-shipped profiles); `remove_embedded_profile(true)`, no profile
    options → after `sign_folder_in_place` both files are gone, and
    `crate::verify::verify_bundle` on the result reports the tree valid (no
    `missing` findings) — the seal never references them (design §3.6).
  - `test_remove_embedded_profile_skips_embed_but_keeps_derived_entitlements`:
    `-m` root profile + map entry for the appex + `-R` → no
    `embedded.mobileprovision` at root or appex; root slot keeps profile
    marker; appex slot keeps `com.zsign.ext.ent` (derive-but-don't-embed,
    design D9).
  CLI: `remove_profile_flag_parses_short_and_long` (`-R`, `--remove-profile`),
  `verify_conflicts_with_remove_profile`.
- [ ] **Step 5.2:** Red run (expect `no method named 'remove_embedded_profile'`).
- [ ] **Step 5.3 (Implementer).** `ZSign` + `IpaSigner` field
  `remove_embedded_profile: bool` (default false), setter doc: strips
  `embedded.mobileprovision` from every bundle before sealing; stripped IPAs
  only install where profile validation is bypassed (issue #271 scope note).
  Unconditional rebind next to `allow_encrypted` in both forwarding blocks +
  `run()`. In `sign_single_bundle`, at the top (before binaries sign and before
  `generate_code_resources`):

```rust
        if self.remove_embedded_profile {
            let embedded_path = Self::resolve_relative(bundle_path, "embedded.mobileprovision")?;
            match fs::remove_file(&embedded_path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(Error::Io(e)),
            }
        }
```

  and change the embed condition (Task 3's `if let Some(data) = profile_data`)
  to `if let Some(data) = profile_data.filter(|_| !self.remove_embedded_profile)`.
  `Cli`:

```rust
    /// Remove embedded.mobileprovision from every bundle after signing
    #[arg(short = 'R', long)]
    remove_profile: bool,
```

  + `-V` conflict entry + forward.
- [ ] **Step 5.4:** Green runs; fmt/clippy scoped. Commits: red-test commit,
  then `git commit -m "feat(ipa): add remove embedded profile flag (ZSN-20)"`.

---

### Task 6: Final gates and report (run once, at the end)

- [ ] **Step 6.1:** `cargo fmt --all -- --check` (must be clean; if not, fix +
  amend nothing — new commit `style: apply cargo fmt`).
- [ ] **Step 6.2:** `cargo clippy --workspace --all-targets -- -D warnings`
  (zero diagnostics).
- [ ] **Step 6.3:** `TMPDIR=$PWD/.tmptmp cargo test --workspace --no-fail-fast -- --skip test_ipa_signing_is_deterministic`
  (the temporary ZSN-15 flake skip; NOT a CI line — see §Conventions and design §6).
- [ ] **Step 6.4:** Report per brief §6: commit list per ticket, verbatim gate
  output, red→green evidence, plan-vs-actual deviations, seams, docs-lane needs
  (flag docs for `-e`/`--entitlements-dir`/`--profile-map`/`-R` incl. the
  stripped-IPA installability caveat; upstream `-u` claim correction).

---

## Acceptance mapping (ticket → proof)

| Ticket | Acceptance | Proof |
|---|---|---|
| ZSN-10 | `-e` overrides profile-derived ents on every surface; adhoc honors it; invalid input hard-fails naming the path; wasm untouched (already conforms) | Task 1 steps 1.1-1.9 (6 library tests + 2 CLI tests; wasm item-0 verify-then-skip) |
| ZSN-22 | `<dir>/<id>.plist` beats profile for the root; miss falls back; traversal-shaped ids never escape; precedence table as designed | Task 2 steps 2.1-2.4 + design §3.2 |
| ZSN-12 | nested bundle embeds its OWN mapped profile before seal + derives its ents from it; unknown nested = today's default (ZSN-34 pins green); unused/root/duplicate keys error; `-p`-style mapping documented as our extension after the mis-citation finding | Task 3 steps 3.1-3.6 + design §3.4 |
| ZSN-11 | `-b` cascades nested ids + dependent keys (documented set only), rewrites application-identifier/keychain-access-groups to prefix+own id, drops get-task-allow for distribution, never touches app groups; child profiles resolve by rewritten id | Task 4 steps 4.1-4.6 |
| ZSN-20 | no `embedded.mobileprovision` at any level, output self-verifies, derive-but-don't-embed with maps | Task 5 steps 5.1-5.4 |
| — | defaults unchanged | invariant-1 controls: existing :1766/:2111 pins + Task 4 verbatim control test |

## Self-review checklist

- [x] Spec coverage: design §3.1→Task 3/4 ordering; §3.2→Tasks 1-3 table tests;
  §3.3→setters/forwards in Tasks 1/2/3/5; §3.4→Task 3; §3.5→Task 4; §3.6→Task 5;
  §3.7→Task 1 verify-only; §5 invariants→controls listed in acceptance table.
- [x] Placeholder scan: none (all steps carry real code or exact commands).
- [x] Type consistency: `validate_entitlements_blob` defined Task 1, used Task 2;
  `ProfilePayload` reused Task 3; `dir_hit`/`entitlements_from_dir` naming fixed
  in Task 2; `bundle_profiles(Vec<(String, PathBuf)>)` identical in builder,
  IpaSigner, CLI forward.
- [ ] Executor note: line anchors date to HEAD `97e8460` + Tasks 1-4 shifting;
  re-anchor with reads, never trust these numbers blindly.
