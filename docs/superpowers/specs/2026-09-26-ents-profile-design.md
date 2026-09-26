# Entitlements & Provisioning-Resolution Pipeline Design (ZSN-10, ZSN-22, ZSN-12, ZSN-11, ZSN-20)

**Date:** 2026-09-26
**Branch:** `zsn40-ents-profile`
**Tickets:** ZSN-10 (custom entitlements override), ZSN-22 (entitlements directory),
ZSN-12 (per-extension provisioning profiles), ZSN-11 (entitlements rewrite on
bundle-id change), ZSN-20 (remove embedded profile flag). Executed as ONE coherent
resolution pipeline: one per-bundle resolver, one precedence table.

## 1. Problem

Today the entitlements/provisioning flow is a 3-hop single-blob pipeline with **no
per-bundle concept anywhere**: one profile path on the builder → one
`(profile_bytes, ent_xml)` tuple read once at sign time → handed to the ROOT bundle
only; every nested bundle gets `(None, None)`.

### 1.1 Item-0 evidence matrix (ticket citations → current source)

All citations re-derived against HEAD `97e8460` (2026-09-26). Ticket-era line
numbers date 2026-09-24; "~350 commits" note honored.

| Citation / prior claim | Status | Current evidence |
|---|---|---|
| ZSN-10: "ZSign state has no entitlements field (builder.rs:79-88)" | TRUE, shifted | `ZSign` struct `crates/zsign/src/builder.rs:77-89` (11 fields, none for entitlements); setters :146-238; `IpaSigner` likewise single `provisioning_profile_path` `crates/zsign/src/ipa/mod.rs:116-136` |
| ZSN-10: "adhoc sign_macho branch must honor override; ab8ced8 made adhoc apply profile ents" | LANDED as described | ab8ced8 = `builder.rs:320-330`: `sign_macho` loads profile ents via `load_entitlements_from_profile` (:509-527) and passes them to `sign_macho_adhoc` (the two `None`s are `info_plist`/`code_resources`); pinned by `test_sign_macho_adhoc_applies_profile_entitlements` builder.rs:973-1017 |
| ZSN-10: "wasm has a validated entitlements setter (ZSN-40)" | LANDED | `crates/zsign-wasm/src/lib.rs`: `profile_entitlements`+`entitlements_override` :204-205, `set_entitlements` 4-gate validation :269-302 (size, plist parse, dict root, `plist_to_der` encodability), `effective_entitlements` override-first :304-308; tests :1052, :1075 — caveat: `:1075` (the invalid-input test) is guest-only (`#[wasm_bindgen_test]` without `unsupported = test`), so the DER arm's only host-pinned precedent is `test_plist_to_der_unsupported_real_type` (der.rs:468-480); Task 1 re-pins every gate host-side natively |
| ZSN-22: per-bundle entitlements picking | ABSENT | no `entitlements_dir`/`-e` anywhere in CLI (flag inventory main.rs:21-140: `-e`, `-R` free; `-p`=password :55, `-r`=bundle_version :78, `-m`=profile :48) |
| ZSN-12: "root-only branch passes entitlements=None/profile_data=None for nested (ipa/mod.rs:380-386)" | TRUE, shifted | `ipa/mod.rs:397-405`; nulling at :402 (ents) / :403 (profile); embed gate is `copy_provisioning_profile: bool` param of `sign_single_bundle` :684 fed by `is_main_bundle` :401, embed block :711-721 |
| ZSN-12: "extensions get NO profile" | TRUE | zero production callers of profile-per-bundle logic; nested bundles keep whatever the source archive shipped (extract writes every entry verbatim; `ipa/extract.rs` has no profile handling) |
| ZSN-12: "do not regress ZSN-34 exactly-once/no-ents emission" | CONTRACT LOCATED | dylib-exactly-once bookkeeping :387-391 (`already_signed: HashSet<PathBuf>`); nested-no-ents pins: `ipa/mod.rs:2111-2113`, :1766-1768; core coercion `zsign-core/src/macho/signer.rs:83-98` (fe176bd) |
| ZSN-11: "ZSN-35 landed bundle_name/version/bundle_id forwarding for MAIN Info.plist only" | TRUE | rewrites at `ipa/mod.rs:377-385` through `rewrite_plist_string` :799-833 (CFBundleIdentifier / CFBundleDisplayName / CFBundleShortVersionString, root only) |
| ZSN-11: entitlements rewriting on id change | ABSENT | `application-identifier` / `keychain-access-groups` never rewritten anywhere in `crates/` (only read in `zsign-core/src/provisioning.rs:125-126`); `validate_and_extract_profile` + `ProfileInfo` + `app_id_covers` (`provisioning.rs:93-234`, :325-360) have ZERO production callers — idle primitives this design consumes |
| ZSN-20: `-R` flag | ABSENT | no remove-profile surface; `embedded.mobileprovision` has NO CodeResources rule and falls under `^.*` Include (`zsign-core/src/bundle/code_resources.rs:127,175-181`), so it is always sealed — a strip MUST happen before that bundle's `generate_code_resources` (`ipa/mod.rs:725`) or `verify_*` reports it as `missing` (`verify.rs:62,652-724`) |
| Motivating upstream iOS-26 AMFI kills (#396) | ALREADY FIXED in core | `CS_EXECSEG_MAIN_BINARY` set unconditionally for every executable slice, `ALLOW_UNSIGNED` gated on real `get-task-allow=true` (`zsign-core/src/macho/signer.rs:831-836`; pins :1737-1739, :1754-1755) |

Net: none of the five tickets' behaviors exists; everything below is net-new surface
reusing the option-forwarding (ZSN-35) and nested-discovery (ZSN-34) conventions.

## 2. External contract verification (phase-2 librarian findings)

Verified against `zhlynn/zsign` master @ `614caa8` (v1.1.2), `fastlane/fastlane`
master, and Apple developer documentation (live fetches 2026-09-26).

**Upstream zhlynn/zsign (refactored layout — the ticket's `main.cpp`/`Signing.h`
references are dead; current files are `src/zsign.cpp`, `src/bundle.cpp`,
`src/openssl.cpp`, `src/archo.cpp`):**

- `-p` = **password**, `-m` = profile (`getopt` string zsign.cpp:200, usage
  :126/:132). A `-p bundle-id=profile` mapping NEVER existed upstream and does not
  exist in fastlane sigh either (sigh `-p` = `:platform`, options.rb:173-177;
  `:app_identifier` single string :59-62; no id→profile option in sigh or match).
  The ticket's "fastlane sigh -p mapping" premise is a **mis-citation** — we design
  the mapping freely and say so.
- `-e` = **wholesale REPLACE, never merge** (openssl.cpp:853 vs fallback :865-867).
  Adhoc uses `-e` exclusively (:842-848). Bug we deliberately do NOT copy: the
  non-adhoc `ReadFile` failure is unchecked — a typo'd `-e` silently degrades to
  profile entitlements (issue #303). Our contract: **hard fail** naming the path.
- Upstream `-e` is applied to EVERY bundle in the tree (archo.cpp:342-343) — the
  exact limitation #401 ("--entitlements 无法满足主程序和插件不一样的场景") complains
  about; its answer is the per-bundle directory (PR #401, closed UNMERGED:
  `<dir>/<bundle_id>.entitlements.plist` lookup per bundle, save/patch/restore of
  the shared asset).
- Nested profile embed ordering (bundle.cpp:403-421): "The matched profile must land
  in the bundle BEFORE CodeResources is generated: the seal hashes every file in the
  bundle, so a profile written after sealing leaves the bundle failing Apple's
  verifier". Upstream multi-`-m` (dfb74d4) suffix-matches
  `endsWith(profile.AppID, bundle_id)` reverse-order and — the bug we fix — after a
  no-match scan signs with `zsaList.front()` anyway (bundle.cpp:411-421 + 902-907).
- `-R` = `--rm_provision` (7626a77): per-bundle, inside `GenerateCodeResources`,
  `remove(embedded.mobileprovision)` + `continue` (skip the seal entry)
  (bundle.cpp:183-189) — file gone before hashing ⇒ output stays self-consistent.
  Strips nested bundles too, including profiles just embedded by multi-`-m`.
- `-b` id change cascades: root `CFBundleIdentifier`, then for every nested
  `.app`/`.appex`: substring replace on `CFBundleIdentifier` + rewrite
  `WKCompanionAppBundleIdentifier` and `NSExtension→NSExtensionAttributes→WKAppBundleIdentifier`
  (bundle.cpp:495-519, 653-666). Upstream does NOT rewrite entitlements — that is
  what the classic "keychain-access-group in the embedded.mobileprovision and your
  binary don't match" install failure is made of (TN2319).

**Apple docs (TN2415, TN2319, bundle-resource references):**

- `application-identifier` = `<prefix>.<bundle_id>`; prefix is the profile's App ID
  Prefix (text before the first `.` of the profile's own `application-identifier`),
  *often* but **not always** the Team ID — never assume prefix==TeamID (tn2415:461);
  on the signature it is always fully qualified, so a wildcard profile app-id
  (`TEAM.*`) must be materialized to `TEAM.<bundle-id>` (tn2415:461).
- `keychain-access-groups`: `"<prefix>.<suffix>"` entries; **all prefixes must match**
  the App ID prefix (tn2415:465); default group = first entry. On an id/team change:
  rewrite the prefix of every entry; rewrite an entry's suffix only when it
  equals the old bundle id or one of its sub-ids (`old.<rest>`) (shared group
  names keep their suffix — rewriting orphans
  keychain items, TN2319 migration warnings). The "max 5 groups" claim is
  undocumented folklore [librarian INFERENCE; not enforced].
- `get-task-allow`: true on development profiles, false/absent on distribution
  (tn2319:225). Distribution detection: profile has no `ProvisionedDevices`
  (`ProfileInfo::provisions_all_devices` / `provisioned_devices`,
  `zsign-core/src/provisioning.rs:66-70`) — contract: drop the key when the bundle's
  resolved profile is distribution.
- `com.apple.security.application-groups`: `group.<name>` — team-scoped, NO
  bundle-id component ⇒ **never rewritten** on bundle-id change (verified).
- Dependent Info.plist keys holding other bundles' ids (complete documented set):
  `WKCompanionAppBundleIdentifier` (watch app → iOS app), `WKAppBundleIdentifier`
  (watch extension → watch app; both top-level modern and
  `NSExtension→NSExtensionAttributes→` legacy per tn2319:357-359), plus each
  bundle's own `CFBundleIdentifier`. `NSExtensionAttributes['HostBundleIdentifier']`
  is **NOT an Apple-documented key** (absent from the exhaustive App Extension Keys
  table) — silently unsupported, matching upstream; `com.apple.watchkit` is an
  `NSExtensionPointIdentifier` *value*, not an id slot.
- Legitimate `embedded.mobileprovision` locations: app + plugin/extension bundles
  (tn2319:393-397 audits "the app and each of its plugins"); Apple documents no
  profile for frameworks and never embeds one into `Frameworks/` ⇒ embed only into
  bundles that are signing targets with an id, never standalone dylibs (ZSN-34
  contract).
- Issue #289 (watch-extension signing failure) root cause = nested bundles need
  their own profile/entitlements (upstream's answer: dfb74d4 + `-W/--rm_watch`
  escape hatch); #396 is already satisfied in `zsign-rs` (see evidence matrix).
  Issue #271 (`-R`) has zero discussion; the only public conclusion is upstream's
  shipped semantics above. [INFERENCE] stripped IPAs are for validation-bypassing
  pipelines, not stock-device installs (tn2415:411 compares signature app-id against
  the EMBEDDED profile; a missing profile breaks that check) — the -R help text
  states this scope honestly.

## 3. Design — one resolution pipeline

**Chosen design.** All five tickets become stages of a single per-bundle resolver
that runs once per signing operation inside `IpaSigner` (bundle/IPA path), with the
bare-Mach-O path sharing the same override/derive logic through `ZSign`. There is
exactly **one precedence table**, one resolver object, and zero new discovery
predicates (nested bundles keep being found by `crate::bundle::is_nested_bundle_dir`,
shared with the verifier — ZSN-34 invariant).

### 3.1 Pipeline shape

```
sign_bundle (option resolution absorbed; entry: sign_bundle_from_options :337)
  1. capture old_root_id = root CFBundleIdentifier (pre-rewrite)
  2. root Info.plist rewrites (existing :377-385)   [unchanged entry point]
  3. collect + sort bundles deepest-first (existing :393-395)
  4. ZSN-11 cascade (only when bundle_id override set): nested
       CFBundleIdentifier, WKCompanionAppBundleIdentifier,
       WKAppBundleIdentifier (top level AND NSExtension>NSExtensionAttributes>)
       rewritten by the boundary-aware rule (value == old, or old = prefix of
       a sub-id; NEVER a bare substring)                        [new]
  5. build the resolution plan ONCE, before the first sign mutation: for each
       bundle (deepest-first) read its id, resolve (entitlements, profile)
       through the precedence table — every option-input read/validate (-e,
       dir hits, map loads) and the unused-key check (map keys vs discovered
       nested ids) happen here; failure aborts before any binary is signed
  6. ZSN-11 entitlements transform (when override active) during plan build
  7. dylib pass (existing :387-391) then the sign loop from the plan:
       sign_single_bundle(b, ents, profile_data, already_signed)
       embed embedded.mobileprovision iff plan profile_data.is_some() && !remove_profile
       strip existing embedded.mobileprovision when remove_profile (before signing/seal)
```

`sign_single_bundle` loses its `copy_provisioning_profile: bool` parameter (the
resolver returning `profile_data: Some(..)` for a bundle IS the embed decision);
its call site (:399-405) stops hard-coding the root/nested split.

### 3.2 The precedence table (normative)

| Target | entitlements source (first hit wins) | embedded profile |
|---|---|---|
| bare Mach-O (`sign_macho`) | `-e` file (replace) > root profile-derived > none | n/a (no bundle) |
| root bundle | `-e` file (replace) > `<ents-dir>/<id>.plist` > root profile (`-m`)-derived > none | `-m` profile bytes, unless `-R` |
| nested bundle (.app/.appex/.watch/XPC/…) | `<ents-dir>/<id>.plist` > `bundle_profiles[id]` profile-derived > **none** (ZSN-34 default) | `bundle_profiles[id]` bytes, unless `-R` |
| standalone dylib / framework binaries | none (core coercion `signer.rs:83-98`) | none (ZSN-34 contract) |

Semantics locked by D1-D8 below: replace-not-merge, hard-fail-not-silent-ignore,
nested never inherits the root's `-e` or the root profile's entitlements.

### 3.3 API surface (mirrors the ZSN-35 forwarding convention on both crates)

`ZSign` (builder.rs) and `IpaSigner` (ipa/mod.rs) each gain, next to the existing
`provisioning_profile` setter, four options forwarded through BOTH the `sign_ipa`
and `sign_bundle` rebind blocks verbatim (duplicated block = the established
convention, not a second one):

```rust
/// Custom entitlements file: replaces profile-derived entitlements
entitlements: Option<PathBuf>,                       // -e / --entitlements
/// Directory of per-bundle-id entitlements: <dir>/<bundle-id>.plist
entitlements_dir: Option<PathBuf>,                   //     --entitlements-dir
/// Nested-bundle profile map, exact-keyed by (post-rewrite) bundle id
bundle_profiles: Vec<(String, PathBuf)>,             //     --profile-map ID=PATH
/// Strip embedded.mobileprovision from every bundle before sealing
remove_embedded_profile: bool,                       // -R / --remove-profile
```

Validation gate for every entitlements source (`-e` file AND each directory hit),
identical in spirit to the existing wasm setter (`zsign-wasm/src/lib.rs:269-302`,
which is REUSED, not replaced): read file (path-named error per the `d3dfaab`
convention) → `plist::from_bytes` must parse → root must be a dictionary →
`zsign_core::codesign::der::plist_to_der` must encode. The encoder today
accepts Data/Date and rejects Real and out-of-range integers
(`der.rs:284-302`, `:609-612`) — the wasm setter's inline comment claiming
"Data/Date/Real are rejected" overstates (recorded for the docs lane). Types
the signer cannot embed fail at load time, not half-way through signing.
Silently ignoring an unreadable/invalid `-e` is prohibited — that is upstream
bug #303 and our contract is the opposite.

CLI (`crates/zsign-cli/src/main.rs`): `-e/--entitlements <path>`,
`--entitlements-dir <dir>`, repeatable `--profile-map <BUNDLE_ID>=<PATH>`
(`Vec` option styled exactly like `-l/--dylibs`, value-parsed at parse time like
`-z` uses `value_parser`, rejecting malformed `id=path` with
`ErrorKind::ValueValidation`), `-R/--remove-profile` (upstream's letter, see
§2; long name differs because local longs are descriptive). All four join the
`-V` `conflicts_with_all` list; `-e`+`-a` is legal (upstream adhoc consumes
`-e`); no new conflicts beyond `-V`.

### 3.4 ZSN-12: map resolution + embed

`bundle_profiles` loads at resolver-build time: each `(id, path)` → file read +
`extract_entitlements_from_profile` (same `ProfilePayload` tuple as `load_profile`
:296-304). Rejections at build time: empty id, duplicate id, id equal to the root
bundle's identifier ("the root profile belongs in `--profile`"), id containing a
path separator or `..` component (never legal, and it is the lookup key for the
entitlements directory too). During the pre-sign plan build (§3.1 step 5), an
entry whose key matches no discovered nested bundle id is a hard error listing
unused keys and the discovered ids (match's "readonly miss lists available
profiles" posture, §2) — before any on-disk mutation, and silent fallthrough to
another profile (upstream's bug, bundle.cpp:411-421) is prohibited. Unknown
nested bundle (present in the tree, absent from the map) keeps today's
behavior: no profile, no entitlements — the map is opt-in per extension, so the
ZSN-34 default pins (:2111-2113) stay green untouched.

Embed order: the resolver's profile bytes reach `sign_single_bundle` before its
CodeResources seal (:725), which is already the internal order of the current
embed block (:711-721 before :725) — the upstream "must land BEFORE CodeResources"
rule (bundle.cpp:403-407) is satisfied by construction. Deeper bundles are signed
(sort :395 deepest-first) before their parent scans, so a nested profile is
sealed by its own bundle first and by the parent's unfiltered walk
(`bundle/code_resources.rs:145-217`) with identical bytes.

Watch/XPC coverage: `is_nested_bundle_dir`'s location arm already discovers
`Watch/`, `XPCServices/`, `Extensions/`, `AppClips/` children with valid markers
(`bundle/mod.rs:46-105`); no extension to the predicate — ZSN-12 gives *whatever is
discovered* a profile when the map names its id. #289's watch failure is fixed the
root-cause way (right profile + right entitlements per bundle), not via an
upstream-style `-W/--rm_watch` removal hatch (out of scope).

### 3.5 ZSN-11: rewrite stages

Trigger: a bundle-id override is set (`-b` / `ZSign::bundle_id`). Nothing is
rewritten without it (a plain re-sign with the same profile must not churn
entitlements; the wildcard-App-ID materialization for profile-less re-signs is
recorded as a future seam, §7).

1. **Info.plist cascade (before resolution).** Capture `old_root` (root
   CFBundleIdentifier pre-rewrite). For every discovered nested bundle, apply
   the boundary-aware replacement (value equals `old_root`, or `old_root`
   followed by `.` prefixes the remainder — never a bare substring, so a
   sibling like `com.old.test` cannot match `com.old`): in its
   `CFBundleIdentifier`, in `WKCompanionAppBundleIdentifier` (watch apps),
   and in `WKAppBundleIdentifier` at top level and under
   `NSExtension→NSExtensionAttributes` (legacy location, TN2319:357-359) —
   each only when the key exists. Keys are never created.
   `HostBundleIdentifier` is NOT handled — not an Apple-documented key (§2)
   and upstream doesn't touch it.
2. **Per-bundle entitlements transform (after resolution, on the bundle's own
   resolved entitlements; a bundle with no entitlements gets none invented):**
   - `application-identifier` := `<prefix>.<this bundle's id>` when the key is
     present or a prefix is known; prefix = text before the first `.` of the
     **bundle's own resolved profile's** `Entitlements["application-identifier"]`,
     else the root profile's, else `TeamIdentifier[0]`, else the existing value's
     own prefix (never assume prefix == TeamID — TN2415:461).
  - `keychain-access-groups`: each entry's prefix normalized to the prefix
    above (TN2415:465: all prefixes must match); an entry's suffix is rewritten
    only when it IS the old id or a sub-id of it (`old.<rest>` → `new.<rest>`
    via the same boundary-aware rule as the Info.plist cascade — never a bare
    substring); shared names (`prefix.groupname`) keep their suffix verbatim
    (rewriting them orphans existing keychain items, TN2319 migration warnings).
   - `get-task-allow`: removed iff a profile resolves for the signing AND that
     profile has no `ProvisionedDevices` (distribution, TN2319:225). No profile →
     key untouched (cert-type sniffing would mean crypto-lane internals — seam).
   - `com.apple.security.application-groups` and every other key: untouched
     (team-scoped, §2).
3. Child profile lookup then runs on the **rewritten** ids (stage 1 precedes
   stages 2/§3.1 step 6), which is what makes `--profile-map` usable together
   with `-b` (map key = new id).

Profile plist fields (`Entitlements["application-identifier"]`, `TeamIdentifier`,
`ProvisionedDevices`) come from a new tiny unverified reader in
`zsign-core/src/provisioning.rs` — `profile_document(&[u8]) -> Result<plist::Value>`
returning the embedded XML document, refactored out of the scan `extract_entitlements_from_profile`
already performs (:386-393), and consumed by the prefix/distribution decisions.
Deliberately un-verified: CMS-validating via `validate_and_extract_profile` would
tie *prefix reading* to a trust-anchor outcome and break on exactly the expired /
self-signed profiles re-signing workflows exist for; the bytes embedded are
unchanged either way. `provisioning.rs` is not in the crypto lane's zone
(deferral covers `crypto/**` only).

### 3.6 ZSN-20: remove embedded profile

`remove_embedded_profile` makes `sign_single_bundle` (a) skip the embed write and
(b) `fs::remove_file` an `embedded.mobileprovision` that exists in the bundle
(source-shipped or otherwise) at the **top** of the function — i.e. before that
bundle signs binaries and before its CodeResources scan/seal, so the seal never
references the file (upstream's `-R` semantics, bundle.cpp:183-189, and the only
ordering that passes our own verifier: `^.*` Include seals the profile, §1.1).
Applies to every bundle, including nested ones a map would have embedded —
`-R` with a profile map is legal: profiles still *resolve* (their bytes derive
entitlements) but nothing is embedded; the help text says a stripped IPA installs
only where profile validation is bypassed (§2, #271 [INFERENCE]).

### 3.7 Wasm (ZSN-10 only): verify, do not replace

`zsign-wasm` already implements the ZSN-10 contract natively for its surface:
`set_entitlements` validation + `effective_entitlements` override-first fallback
(§1.1). This lane adds **no wasm code**; a verification test mirrors the native
precedence (override > profile-derived) and the adhoc-parity expectation is pinned
native-side. The native gate intentionally mirrors the wasm setter's checks so
both surfaces reject the same inputs.

## 4. Design decisions

Candidates were generated per ticket (phase 1) and converged on the §3 pipeline;
rejected alternatives are recorded here with the tradeoff that killed them.

- **D1 — `-e` replaces, never merges (ZSN-10).** Rejected: key-level merge with the
  profile dict (unpredictable precedence, no precedent — upstream zsign
  openssl.cpp:853-867, `ldid -e/-S`, `codesign --entitlements`, and the existing
  wasm setter all replace). The wasm ZSN-40 setter is the in-repo contract; native
  mirrors it. Rejected: accepting entitlements as base64/raw DER — plist is the
  only signer input format anywhere today.
- **D2 — Hard fail on unreadable/invalid `-e` (ZSN-10).** Rejected upstream's
  unchecked `ReadFile` (issue #303: "just ignore my custom entitlement"). A path
  that cannot be read, a non-dict root, or DER-unencodable values abort before any
  on-disk mutation, error naming the file (d3dfaab convention).
- **D3 — `-e` applies to the bare Mach-O and the ROOT bundle only (ZSN-10/22
  refinement of the brief's flat table).** The brief's precedence `-e > dir >
  profile > empty` is recorded verbatim for the root; for nested bundles the table
  starts at the directory. Rationale: upstream applying one `-e` to the whole tree
  is the exact limitation issue #401 asks to escape, and injecting the root's
  `application-identifier` into an appex re-creates the AMFI/entitlement mismatch
  #396-style kills the pipeline exists to fix. A user who wants one file for a
  nested bundle puts it in the entitlements directory under that bundle's id.
- **D4 — entitlements directory key = `<dir>/<bundle-id>.plist` (ZSN-22).** The
  brief's example pins the name form. Rejected: `<id>.entitlements.plist`
  (upstream PR #401's naming — kept unmerged upstream, and the brief overrides),
  and glob/suffix matching (ambiguous ownership between `com.a.app` and
  `com.a.app.widget`). Lookup is exact-key, read-only, and the resolved path must
  stay inside the directory; ids containing separators or `..` never hit the
  directory at all (malformed identity ⇒ miss, not escape).
- **D5 — `--profile-map id=path` repeated flag, exact keys (ZSN-12).** Rejected:
  upstream-compatible repeatable `-m` with implicit `endsWith(AppID, id)` suffix
  matching — wildcard profiles never match explicit ids, reverse-order tie wins
  are user-invisible, and its no-match path silently signs with `zsaList.front()`
  (bundle.cpp:411-421 bug); the brief's "fastlane sigh `-p` mapping" premise is a
  verified mis-citation (§2), so there is no external letter to honor. Rejected:
  a mapping file (new format, two sources of truth; the CLI Vec flag reuses the
  `-l/--dylibs` precedent). Rejected: a profiles *directory* mirroring ZSN-22
  (profiles need per-team/expiry intent; exact `id=path` keeps it explicit).
  Failure posture borrowed from `match --readonly`: unused map key = error
  listing the keys and the discovered bundle ids.
- **D6 — Map never overrides the root profile (ZSN-12).** A key equal to the root
  id is rejected at build time ("the root profile belongs in `--profile`") —
  avoids two silent winners for one slot.
- **D7 — ZSN-11 trigger = bundle-id override present.** Rewriting
  app-identifier/KCG on every sign would churn byte-identical re-signs and
  surprise the (rare) user whose profile has no `application-identifier`. Team
  changes are expressed as new profile + new id, which the trigger covers.
  Prefix source chain (bundle's own profile app-id → root profile's app-id →
  TeamIdentifier[0] → existing prefix) and "never assume prefix == TeamID"
  follow TN2415:453-477; KCG suffix rewrite only when it equals the old id or
  a sub-id of it, shared suffixes untouched (keychain-item orphans,
  TN2319); app-groups never rewritten (§2). `get-task-allow` removal is
  profile-driven (`ProvisionedDevices` absence = distribution); cert-EKU sniffing
  is a crypto-lane seam, §7.
- **D8 — Profile fields read unverified (ZSN-11).** `profile_document` does no CMS
  validation. Validating prefix/distribution reads via `validate_and_extract_profile`
  would fail exactly on the expired/self-signed profiles re-signing workflows
  target, while the embedded bytes are untouched either way — validation policy
  for profiles is unchanged elsewhere in the repo.
- **D9 — `-R` strips before sealing at every bundle, upstream semantics (ZSN-20).**
  Rejected: post-write zip entry filtering (would break the sealed-resources
  invariant — `embedded.mobileprovision` falls under `^.*` Include, §1.1 — and
  touches zsn41's archive files); rejected: root-only strip (nested source-shipped
  profiles survive and mislead). `-R` + profile map is legal: derive-but-don't-embed.
- **D10 — One resolver, one table, no new predicates.** The single per-bundle
  resolver (step 4 of §3.1) replaces the hard-coded `is_main_bundle ? x : None`
  pair at :402-403 rather than adding a second conditional beside it; the
  verifier's shared discovery predicate (`is_nested_bundle_dir`) is the only
  bundle-identity source, per ZSN-34.

## 5. Invariants

1. Defaults unchanged: with none of the four new options set, every surface
   produces byte-identical decisions to today — root gets profile-derived
   entitlements + embed; nested and standalone dylibs get `(None, None)`; the
   ZSN-34 pins (exactly-once dylib signing, no-ents nested emission
   :1766/:2111, non-executable coercion signer.rs:83-98) stay green untouched.
2. A nested bundle's entitlements never originate from the root's `-e`, the root
   profile, or another bundle's map entry; each bundle's embed and derived
   entitlements come from the same payload.
3. `embedded.mobileprovision` is absent from a bundle's CodeResources seal iff the
   file is absent from disk when the seal is generated (embed-before-seal,
   strip-before-seal), so every signing output self-verifies.
4. With the ZSN-11 trigger active, after signing, for every bundle whose
   signature carries entitlements (bundles resolving to none get none
   invented — stage 2 of §3.5): the
   signature's `application-identifier` equals `<resolved-prefix>.<the bundle's
   own final CFBundleIdentifier>`, all `keychain-access-groups` prefixes equal
   that prefix, `get-task-allow` is absent when the bundle's resolved profile is
   distribution, and app-group values are byte-unchanged.
5. Every option-input rejection happens before the first SIGN mutation of the
   target tree (the pre-sign plan build of §3.1 step 5 performs every option
   read and validation — including directory hits and unused-map-key detection
   — before the first binary is signed, embedded, or sealed; the only earlier
   writes are the explicitly requested CFBundle identity rewrites of steps
   2/4, which are pure data edits, not signing output; the only fallible step
   afterwards is fs I/O itself).
6. No new entitlements slots for non-executables, no profile for standalone
   dylibs/frameworks (fe176bd / ZSN-34 contract).

## 6. Test strategy

Conventions for every task (repo AGENTS.md + brief): inline `#[cfg(test)]` tests;
run scoped packages only, never project-wide mid-flight;
`TMPDIR=$PWD/.tmptmp` for every test command. The
`-- --skip test_ipa_signing_is_deterministic` flag is a **temporary machine-flake
skip tracked by issue ZSN-15** (lane zsn41 is fixing the underlying flake in
parallel); removal condition: delete it from lane commands once ZSN-15's fix is
merged — it MUST NOT be copied into any CI configuration (ci-no-gate-weakening).
All other gates run with `-D warnings` at final report time, unweakened.

Fixtures: two new inline profile byte fixtures (extension profile with
`com.zsign.ext` app-id; distribution profile without `ProvisionedDevices`)
alongside the existing builder `PROFILE_FIXTURE` pattern; nested `.appex` bundle
fixtures extend the existing `create_folder_bundle`/`info_plist_xml` test
helpers in ipa/mod.rs. Red-first per task (Tester writes the failing test,
implementer greens it), per the subagent-driven-development workflow.

Acceptance probes per ticket (observable outcomes, not plumbing):
- ZSN-10: signed Mach-O entitlements slot carries the `-e` file's marker key while
  a profile is also supplied; control without `-e` carries the profile marker;
  missing/invalid `-e` fails with the path in the message before output exists.
- ZSN-22: root bundle picks `<dir>/<root-id>.plist`; miss falls back to profile;
  traversal-shaped ids never read outside the directory.
- ZSN-12: appex on disk contains the mapped profile bytes and its binary's
  `CSSLOT_ENTITLEMENTS` carries the appex profile's marker; unused key errors;
  no-map run equals today's bytes for the nested binary (pin reuse).
- ZSN-11: after `-b com.new.app`, the appex Info.plist id is
  `com.new.app.appex`, its `WKAppBundleIdentifier`/`WKCompanionAppBundleIdentifier`
  rewrote, signature `application-identifier` = `<prefix>.com.new.app.appex`,
  distribution profile drops `get-task-allow`, `group.*` entries byte-unchanged.
- ZSN-20: no `embedded.mobileprovision` at root or nested in output; the tree
  self-seals — `verify_bundle`'s CodeResources report has no missing/mismatched
  finding for the profile path (CMS-anchor validity of the self-signed fixture
  is NOT asserted; see plan Task 5 wording).

## 7. Out of scope and seams for other lanes

- `crates/zsign/src/ipa/archive.rs` / `extract.rs`: untouched (lane zsn41). The
  design needed no archive/ edit — the -R strip and nested embed are pure
  on-disk operations in `ipa/mod.rs` before `create_ipa*` re-reads the tree.
- Cert-type EKU sniffing for `get-task-allow` (vs profile-driven):
  `zsign-core/src/crypto/**` is lane zsn42; not touched.
- `ipa/mod.rs` grows by ~350 lines; a follow-up split (`resolve.rs`) is a seam
  after the pipeline stabilizes, deliberately not done mid-flight.
- Wildcard profile without `-b`: signature keeps `TEAM.*` in
  `application-identifier` (TN2415 says the signature form is fully qualified).
  Fixing it outside the ZSN-11 trigger changes today's default-path bytes;
  recorded as a follow-up ticket candidate for the orchestrator.
- `-u` upstream flag: does not exist upstream (verified); any local ticket
  claiming it is stale.
- README/AGENTS flag docs (`-e`, `--entitlements-dir`, `--profile-map`, `-R`
  semantics + the stripped-IPA installability caveat): docs lane.
- `examples/web` per-bundle profile flow keeps working: wasm surface unchanged;
  nested bundles that still ship their own profile are untouched by default
  (invariant 1) and get re-embedded only when a map entry names them.
