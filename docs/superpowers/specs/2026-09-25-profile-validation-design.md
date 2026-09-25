# ZSN-3 Provisioning-Profile Validation — Design

**Date:** 2026-09-25
**Lane:** ZSN-3 (branch `zsn3-profiles`), base main @ `c9ff0fb`
**Scope source:** lane brief `/tmp/zsn-3.txt` (authoritative; distills ticket ZSN-3)

## 1. Problem

`crates/zsign-core/src/provisioning.rs:12-42` locates the profile plist by scanning raw
bytes for the first `<?xml ` and the last `</plist>` and never touches the CMS envelope
around it. A completely forged `.mobileprovision` is trusted and its entitlements get
sealed into output signatures (consumers: `crates/zsign/src/builder.rs:471`,
`crates/zsign/src/ipa/mod.rs:289`, `crates/zsign-wasm/src/lib.rs:69/:161`). There is also
no `ExpirationDate`/`CreationDate` parsing anywhere (grep-verified across the workspace),
no team/app-ID/device validation, and `crypto/cms_verify.rs:1354-1365` pins "now" to a
fixed 2027-01-15 timestamp on wasm32, which silently breaks every validity window in the
browser.

## 2. Research basis (phase 2, one parallel batch)

Four reports (three read-only scouts re-anchoring citations against `c9ff0fb`, one
librarian source-verifying external contracts):

- **ScoutCmsVerify:** full public/private map of the post-ZSN-23 `cms_verify.rs`;
  `leaf_purpose_reason` (`:1286-1314`) requires the codeSigning EKU unconditionally;
  `verify_signed_data` (`:523-880`) skips the optional `[0] eContent` unread (`:590-593`);
  digest gate is SHA-256-only (`:733-738`); `time_now()` (`:1354`) has exactly one caller,
  `verify_chain` (`:1036`); citations `provisioning.rs:12-42` and
  `builder.rs:471` exact, `ipa/mod.rs:286` drifted to `:289`.
- **ScoutProfileConsumers:** exactly one producer and four production consumers of
  `extract_entitlements_from_profile`; `zsign/src/lib.rs:48` re-exports the flat function
  only (not the module); no `ProfileInfo`-type conflicts; no public API takes a timestamp
  today; `time` 0.3 declared without features (relies on plist's feature unification);
  `zsign-core` has zero wasm-bindgen/js-sys; CI gates wasm via `cargo check --target
  wasm32-unknown-unknown` + `wasm-pack test --node`.
- **ScoutTestFixtures:** no `tests/`/`testdata/` anywhere — inline `#[cfg(test)] mod
  tests` per file; binary fixtures colocated in `src/<mod>/fixtures/` + `include_bytes!`
  + `Cargo.toml exclude` (pkcs12 precedent); generated fixtures via
  `#[cfg(test)] pub(crate) mod fixtures` (macho precedent); `TrustAnchors::from_certificates`
  is the anchor-injection helper; `local_test_credentials` (Leaf + codeSigning EKU) is the
  leaf-credential pattern; root `.gitignore:34` ignores `docs/` with no negation.
- **LibrarianProfileSpec** (source-verified, 10 real Apple-signed profiles dissected):
  1. Container = CMS SignedData, `eContent` **attached**, XML plist, SignedData version 1.
  2. **SignerInfo digest = SHA-1, signatureAlgorithm = `rsaEncryption` (all 10 samples,
     2015-2021; post-2022 UNVERIFIED)**; `messageDigest` = digest over the eContent
     **value octets only**; signature verifies over signedAttrs re-tagged `0x31`.
  3. Signed attribute set is open and non-sorted (contentType, signingTime, messageDigest,
     optional CMSAlgorithmProtection, S/MIME Capabilities) — never assume a closed set.
  4. Chain: leaf `CN=Apple [iPhone OS|Mac OS X] Provisioning Profile Signing` ←
     Apple-issued CA ← Apple Root CA; all three certs embedded; leaf is **not**
     `certs[0]`; 2015 profiles embed the legacy Apple Root subject — same public key,
     so anchors must match by SPKI (`TrustAnchors::contains_spki` already does).
  5. **Profile leaves carry NO EKU extension**; only KU `digitalSignature` + critical
     BC `CA=FALSE`. Requiring codeSigning EKU (current `leaf_purpose_reason`) rejects
     every genuine profile. RFC 5280 §4.2.1.12: an absent EKU imposes no purpose.
  6. Dates: XML `<date>` is ISO-8601 `YYYY-MM-DDTHH:MM:SSZ` (Apple DTD); the `plist`
     crate parses to `plist::Date` (newtype over `SystemTime`), `From<Date> for
     SystemTime` at plist-1.10.1 `date.rs:101-104`.
  7. `ProvisionsAllDevices` true ⇒ all devices (no `ProvisionedDevices` in practice);
     else `ProvisionedDevices` UDID membership; neither ⇒ App Store (no device
     constraint). Both-present case never observed (UNVERIFIED) — precedence rule
     below is the safe reading of TN3125.
  8. App ID = `PREFIX.bundleid`; wildcard = exactly one trailing `*` (QA1713 + Team
     Administration Guide); match = prefix-compare `PREFIX.bundleid` against the
     profile App ID minus the trailing `*`. macOS profiles use
     `Entitlements['com.apple.application-identifier']` instead of
     `application-identifier` (TN3125).
  9. Team set: `TeamIdentifier[]` ∪ `ApplicationIdentifierPrefix[]` ∪
     `Entitlements['com.apple.developer.team-identifier']` (identical 10/10, but the
     union is the defensive rule).
  10. **No hostname/host field exists** in any profile (all 16 top-level keys
      enumerated across both platforms; regex over key names matched nothing;
      TN3125 + Bitrise agree).

## 3. Candidate designs and decisions

### Item 1 — generic CMS SignedData verification

- **A (chosen): one generic attached-content entry inside `crypto/cms_verify.rs`**,
  refactoring `verify_signed_data` into a mode-parameterized core shared with the
  code-signature path. Reuses the ZSN-23-hardened structural parse, signed-attr
  parsing, signer resolution, signature verification, chain walk, and anchoring —
  no second CMS convention in the crate.
- B: new `crypto/profile_cms.rs` module duplicating the SignedData walker — rejected:
  a second hand-rolled CMS parser beside an already-hardened one (duplicate security
  surface, two places to fix the next parsing bug).
- C: verify with the `cms` crate — rejected: 0.2.x is signer-only, no verification API
  (module doc `cms_verify.rs:4-5`).

Mode differences baked into the core (evidence §2):

| Aspect | Code-signature mode | Profile (attached) mode |
|---|---|---|
| Framing | `CSMAGIC_BLOBWRAPPER` stripped | bare ContentInfo |
| Content for `messageDigest` | caller's CodeDirectory bytes (detached) | eContent value octets (attached, required) |
| Signer digest | SHA-256 only (unchanged) | SHA-256 or SHA-1 (real profiles are SHA-1) |
| Apple CDHash attrs | required (unchanged) | not checked |
| Leaf purpose | codeSigning EKU + digitalSignature + non-CA (unchanged) | **no EKU required**; KU digitalSignature present + BC CA=FALSE |
| `now` | `time_now()` at the public boundary | explicit parameter (see item 4) |

### Item 4 — clock injection shape

- **A (chosen): explicit `now: Option<time::OffsetDateTime>` parameter** on the new
  APIs, resolved by one helper: `Some(t)` → `t`; `None` → real wall clock on native,
  `Err` on wasm32 with an actionable message telling the caller to pass
  `Date.now()/1000`. The core therefore has a sensible default on native and no
  silent wrong answer in the browser.
- B: a `Clock` trait — rejected: over-engineering for two call sites, would ripple
  through every signature.
- C: thread-local/`#[cfg(test)]` override clock — rejected: hidden global state;
  tests would stop proving what callers actually pass.
- The legacy entries `verify_code_signature[_with_anchors]` keep their exact
  signatures (callers `macho/verify.rs`, `zsign/src/verify.rs` are other lanes'
  files) and resolve `now = time_now()` internally; `time_now()` keeps its wasm32
  fixed fallback for those legacy callers only, with a comment redirecting new code
  to the explicit parameter.

### Items 2+3 — model, validation, and API surface

- **A (chosen): new validated path as an additional API in `provisioning.rs`** —
  `pub struct ProfileInfo` + `pub struct ProfileRequest` + `validate_and_extract_profile` —
  while `extract_entitlements_from_profile(&[u8]) -> Result<Option<Vec<u8>>>` keeps
  its signature **and its current raw-scan behavior** so `zsign-wasm` (deferred,
  ZSN-40), `builder.rs`, and `ipa/mod.rs` (consumer-adoption follow-up) keep
  compiling and behaving exactly as today.
- B: reimplement the old function on top of the validated path — rejected: would
  start rejecting unsigned/synthetic profiles at four production call sites before
  their lanes adopt validation, breaking the "keep consumers working" rule.
- C: validate inside the facade/CLI — rejected: `zsign-core` is the pure engine and
  the wasm crate needs the same validation; the core must own it.
- Validation is a pure function of (profile bytes, request): no bundle mutation
  exists in the core path, and consumers adopt in later lanes. The escape hatch
  (`allow-unsafe`) belongs to the CLI lane: we expose a typed request/result only,
  no flag, no CLI surface.

## 4. Architecture

```
crates/zsign-core/src/crypto/cms_verify.rs
  verify_cms_envelope(envelope, now) -> Result<CmsEnvelopeReport>
  verify_cms_envelope_with_anchors(envelope, now, anchors) -> Result<CmsEnvelopeReport>
      │  bare ContentInfo, BER-normalized; captures eContent; SHA-256|SHA-1 signer
      │  digest; profile leaf purpose; chain + anchoring at resolved `now`
      ▼
crates/zsign-core/src/provisioning.rs
  pub struct ProfileRequest { now, anchors, expected_team_id, target_bundle_id, target_device_udid }
  pub struct ProfileInfo { name, team_identifiers, application_identifier,
                           creation_date, expiration_date, provisions_all_devices,
                           provisioned_devices, entitlements_xml, cms: CmsVerifyReport }
  pub fn validate_and_extract_profile(profile_data: &[u8], request: &ProfileRequest)
      -> Result<ProfileInfo>
      │  1. verify_cms_envelope (default anchors = TrustAnchors::apple_root)
      │  2. parse plist from the VERIFIED eContent bytes
      │  3. structural fields (Name, ExpirationDate required)
      │  4. window: CreationDate <= now <= ExpirationDate
      │  5. team set vs request.expected_team_id        (when supplied)
      │  6. App-ID coverage of request.target_bundle_id (when supplied)
      │  7. device: ProvisionsAllDevices ⇒ pass; else ProvisionedDevices
      │     membership of request.target_device_udid    (when supplied)
      ▼
  extract_entitlements_from_profile — UNCHANGED (signature and behavior)
```

Errors: `Error::ProvisioningProfile(String)` (`error.rs:28-29`) with actionable text —
profile name, the offending date/value, and the remedy. CMS structural failures surface
as `Error::Verification` from the envelope entry; `validate_and_extract_profile` wraps
an invalid report into `Error::ProvisioningProfile` naming the report's errors, so
callers see one error channel for "this profile is unusable".

### 4.1 Profile leaf purpose (evidence-driven)

```rust
// cms_verify.rs — selected by mode
enum SignerPurpose { CodeSigning, ProvisioningProfile }
```
- `CodeSigning` → existing `leaf_purpose_reason` unchanged.
- `ProvisioningProfile` → KU, if present, must set `digitalSignature`; BC, if present,
  must decode with `CA=false`; **EKU ignored entirely** (RFC 5280 §4.2.1.12: absent
  EKU imposes no purpose; every real profile leaf has none — librarian §2).

### 4.2 Digest agility (evidence-driven)

`verify_signed_data` gains a mode; in profile mode the SignerInfo `digestAlgorithm`
may be SHA-256 **or** SHA-1. The `messageDigest` check and the RSA signature check
both dispatch on that OID (PKCS#1 v1.5 embeds a DigestInfo naming the digest, so
`rsaEncryption` + SHA-1 requires `VerifyingKey::<Sha1>`). SHA-1 in profile mode is
accepted and recorded as a non-fatal report warning, mirroring `sha1_warning` for
certificate signatures. Code-signature mode stays SHA-256-only.

### 4.3 Wildcard matching

- Read `application-identifier` **or** `com.apple.application-identifier` (macOS).
- Explicit App ID (no `*`): `target == "PREFIX." + bundle_id` exact match.
- Wildcard: exactly one `*`, last character (mid-string/multiple `*` ⇒ reject as
  "not producible by Apple"); compare `PREFIX.bundleid` against the App ID with the
  trailing `*` stripped, as a prefix (empty match allowed — Apple's wording "starts
  with" favors it; flagged in known items).
- Comparison is case-sensitive (bundle identifiers are case-sensitive per Apple).

### 4.4 Clock plumbing

- `verify_chain(certs, leaf, anchors, now, purpose)` — `now` becomes a parameter;
  the single internal `time_now()` call moves to the public boundaries.
- `resolve_now(Option<OffsetDateTime>) -> Result<OffsetDateTime>`: native `None` →
  `time_now()`; wasm32 `None` →
  `Err("explicit timestamp required on wasm32: pass Date.now()/1000 …")`.
- `ProfileRequest.now: Option<OffsetDateTime>` flows into both the envelope
  (cert-chain validity) and the profile window checks — one instant for both, so a
  caller cannot validate the chain at one time and the window at another.

## 5. Testing strategy

Fixtures are generated in-test (macho/fixtures precedent) — no committed binaries:

- `#[cfg(test)] pub(crate)` profile-signing helper in `crypto/cms.rs` reusing
  `build_cms_signed_data`: attached eContent (the plist bytes), no CDHash attrs,
  digest SHA-256 (and a SHA-1 variant), built on `Profile::Leaf` credentials issued
  by a test root.
- Chain fixtures reuse the `cms_verify.rs` helpers' idiom: `build_rsa_root`-style
  test root + leaf issued by it; anchors injected with `TrustAnchors::from_certificates`.

Required behaviors (each an inline test):

1. **Forged profile rejected:** plaintext XML with no CMS envelope → `Err` from
   `validate_and_extract_profile` (the headline regression: today it is trusted).
2. **Dual-pin:** synthetic profile verified with default anchors (Apple roots) →
   invalid/unanchored; same profile with injected test anchors → valid.
3. **Tamper:** modified plist bytes inside the envelope → messageDigest mismatch →
   invalid.
4. **Clock independence:** cert chain expired at `now = expiry + 1` → rejected; at
   `now = expiry − 1` → accepted, and vice versa for not-yet-valid certs — no wall
   clock involved.
5. **Profile window:** expired profile → error naming profile name, ExpirationDate,
   and remedy; not-yet-valid (CreationDate in the future) → error; in-window → ok.
6. **Team:** mismatch → error; match against the union set → ok; `expected_team_id`
   absent → no check.
7. **App-ID:** explicit match/mismatch; `TEAMID.*` wildcard coverage; prefix wildcard
   `TEAMID.com.foo.*` covers `TEAMID.com.foo.bar` but not `TEAMID.com.foobar`;
   malformed `*` placement → error; macOS `com.apple.application-identifier` key.
8. **Device:** `ProvisionsAllDevices` true + UDID not listed → pass (precedence);
   listed → pass; not listed with a device list → error; neither key (App Store) →
   pass; no UDID supplied → no check.
9. **SHA-1 profile:** SHA-1-signed envelope verifies with the SHA-1 warning;
   SHA-1 rejected in code-signature mode (unchanged).
10. **Retained API:** the three existing `extract_entitlements_from_profile` tests
    still pass unchanged (raw-scan behavior preserved).

Gate commands (per brief): mid-flight
`TMPDIR=$PWD/.tmptmp cargo test -p zsign-core provisioning` (+ `crypto` when
`cms_verify` is touched), final full-suite runs with
`--skip test_ipa_signing_is_deterministic` (ZSN-15 pre-existing failure).

## 6. Known items / evidence gaps

- Hostname check (brief item 2) is **not implementable**: no host-identifying field
  exists in any profile (librarian §6: all 16 top-level keys enumerated on iOS +
  macOS; TN3125 + Bitrise agree). Scoped question stated to the supervisor; design
  proceeds with `target_device_udid` only.
- Post-2022 Apple profile signer identity/algorithm unverified (all obtainable
  fixtures ≤ 2021-01, SHA-1 + rsaEncryption). The design accepts SHA-1|SHA-256 so
  observed real profiles verify; future SHA-256/ECDSA rotation is tolerated by the
  mode's allowed-set.
- `ProvisionsAllDevices` + `ProvisionedDevices` co-occurrence never observed; the
  precedence (all-devices wins) follows TN3125's wording and fails closed only for
  the unlisted-UDID case.
- Whether `*` may match the empty string: Apple texts favor prefix semantics; chosen.
- `DER-Encoded-Profile` (iOS 15+) not parsed — optional field, absent from every
  fixture; out of the brief's queue.
- `DeveloperCertificates` binding and entitlement-allowlist subset checks are
  librarian-recommended but **not in the brief's scope** — deliberately not built.
