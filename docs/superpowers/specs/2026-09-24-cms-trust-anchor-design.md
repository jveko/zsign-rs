# CMS Trust Anchor — Design (ZSN-23)

Date: 2026-09-24 · Branch: `zsn-23-cms-trust` · Base: `ee42c12`

Scope (hard): `crates/zsign-core/src/crypto/{cms_verify.rs, cert.rs, assets.rs}` and
their inline tests **only**. No other file may be edited. Deferred files
(`macho/verify.rs`, `codesign/verify.rs`, `crates/zsign/src/verify.rs`,
`crates/zsign-cli/src/main.rs`, `cms.rs`, `.github/**`, manifests) are owned by
other lanes — see §6 for the cross-lane fallout this design knowingly produces.

## 1. Problem

Five verified gaps in `crates/zsign-core/src/crypto/cms_verify.rs` (line numbers
from the base commit; verified by four read-only scouts):

1. **Chains are not anchored to anything trusted.** `verify_chain`
   (`cms_verify.rs:818-916`) treats any self-signed terminal certificate as an
   "anchor" without verifying its self-signature (`cms_verify.rs:890-894`), and
   a chain that runs out with no issuer returns `chain_ok = true,
   anchored = false` (`cms_verify.rs:895-905`). `verify_signed_data` sets
   `report.valid` from an empty local error list only (`cms_verify.rs:682-686`);
   `anchored` never gates it and no root store exists
   (`cms_verify.rs:654-686`). An attacker who re-signs a copy of a real
   CodeDirectory with a fresh self-signed certificate therefore gets
   `report.valid = true` → Mach-O slice has no errors (`macho/verify.rs:184-187`)
   → CLI exit 0 (`zsign-cli/src/main.rs:192-202`).
2. **No X.509 purpose enforcement.** The leaf EKU check runs only when the
   extension is present (`cms_verify.rs:827-837`), and `leaf_eku` maps every
   malformed-encoding case to `None`, i.e. "absent → unrestricted"
   (`cms_verify.rs:977-1000`). There is no digital-signature `keyUsage` check,
   no "leaf must not be a CA" check, and no parent `pathLen` enforcement
   anywhere in the file.
3. **SKI-only SignerInfo produces invalid-with-empty-errors.** The `[0]
   subjectKeyIdentifier` arm pushes a warning and `continue`s
   (`cms_verify.rs:544-549`). If it is the only SignerInfo, the loop ends with
   `valid = false` (default) and `errors` empty; `macho/verify.rs:184-187` only
   copies errors when `!cms.valid`, so the slice stays error-free and
   `SliceVerifyReport::is_valid()` (`macho/verify.rs:40-44`) returns `true` —
   the Mach-O layer reports a skipped signer as valid.
4. **Signed `contentType` is never checked.** `parse_signed_attrs`
   (`cms_verify.rs:316-367`) parses only `messageDigest` and the Apple CDHash
   attributes; `OID_CONTENT_TYPE` is a dead constant (`cms_verify.rs:46-48`).
   RFC 5652 requires exactly one signed `contentType` (§5.3 presence,
   §11.1 single-valued SET) equal to the encapsulated content type (§5.6).
5. **SHA-1 certificate signatures are accepted silently at any depth.**
   `verify_cert_signature` has a SHA-1 branch (`cms_verify.rs:945-949`) and no
   caller records that SHA-1 was used.

## 2. Chosen design

All changes live in `cms_verify.rs` (plus tests; `cert.rs`/`assets.rs` need no
production change — see D6).

### 2.1 `TrustAnchors` — the explicit anchor input

```rust
/// Certificates whose public keys are trusted as chain termini.
#[derive(Debug, Clone, Default)]
pub struct TrustAnchors {
    roots: Vec<x509_cert::Certificate>,
}

impl TrustAnchors {
    /// Wraps the given certificates as trust anchors.
    pub fn from_certificates(roots: Vec<x509_cert::Certificate>) -> TrustAnchors;
    /// The Apple Root CA embedded in `crypto::assets` (the default anchor set).
    pub fn apple_root() -> Result<TrustAnchors>;
}
```

Internal helpers (private): `contains_spki(spki_der: &[u8]) -> bool`
(byte-equality of a DER-encoded `SubjectPublicKeyInfo` against every anchor)
and `find_by_subject(&x509_cert::name::Name) -> Option<&Certificate>` (for the
runs-out issuer lookup, D4).

Two public entry points:

```rust
/// Verifies with the default anchors (Apple Root CA from `crypto::assets`).
pub fn verify_code_signature(cms_blob, content, cd_sha1, cd_sha256)
    -> Result<CmsVerifyReport>;            // signature unchanged

/// Verifies against caller-supplied anchors (tests inject their test root).
pub fn verify_code_signature_with_anchors(cms_blob, content, cd_sha1, cd_sha256,
    anchors: &TrustAnchors) -> Result<CmsVerifyReport>;
```

The 4-arg signature is preserved so the one production caller
(`macho/verify.rs:178-183`, deferred to lane 24) needs **no migration** and
immediately inherits the fix: attacker CMS → `valid=false` with a non-empty
error → slice error → `report.valid()` false while the top-level
`VerifyReport.errors` stays empty → CLI exit 1
(`zsign-cli/src/main.rs:194-198`).

### 2.2 `verify_chain` — anchoring + purpose

New signature and return type:

```rust
struct ChainOutcome {
    ok: bool,                      // structural + cryptographic checks
    anchored: bool,                // terminus verified against `anchors`
    subjects: Vec<String>,         // leaf → terminus
    reason: Option<String>,        // why `ok == false`
    warnings: Vec<String>,         // SHA-1 notes (item 5)
}

fn verify_chain(certs: &[Certificate], leaf: &Certificate,
                anchors: &TrustAnchors) -> ChainOutcome;
```

Walk order (all failures return immediately with `reason` set; `warnings`
collected so far are preserved):

1. **Leaf purpose rules** — applied unconditionally to the leaf, including a
   self-signed one (D5). Strict-decode each extension with `Type::from_der`
   (rejects trailing bytes, per der 0.7 `Decode::from_der` → `reader.finish`):
   - EKU (`2.5.29.37`) **required**; malformed → error; decoded list must
     contain `1.3.6.1.5.5.7.3.3` (codeSigning), else error.
   - `keyUsage` (`2.5.29.15`), if present: must include `digitalSignature`.
   - `basicConstraints` (`2.5.29.19`), if present: `ca` must be `false`.
2. **Leaf validity window** (unchanged, `cms_verify.rs:838-848`).
3. **Climb** — for each parent `p` found in `certs` (distinct from `current`),
   before verifying its signature over `current`:
   - `p`'s `basicConstraints` required, strict-decoded, `ca == true`.
   - `p`'s `pathLenConstraint`, if present: the number of CA certificates
     already chained below `p` must be `<= pathLen`. That count is the
     pre-append `chain.len() - 1` (the built chain holds `[leaf … current]`,
     the leaf is never a CA under the leaf rules, so everything except the
     leaf counts; after appending `p` it would be `chain.len() - 2`).
   - `p`'s `keyUsage`, if present: must include `keyCertSign`.
   - validity window (unchanged) and signature verification (unchanged).
   - Whenever a certificate's signature is verified with SHA-1
     (`child.signature_algorithm == sha1WithRSA`), push a warning naming the
     subject (item 5).
4. **Terminus — self-signed candidate** (`subject == issuer`, no distinct
   parent): verify the self-signature with `verify_cert_signature(current,
   current)`; failure → `ok=false`, reason
   `self-signed certificate at depth N fails self-signature verification`.
   Then require `current`'s SPKI DER to byte-match some anchor's SPKI:
   match → `anchored = true`; no match → `ok = true, anchored = false`
   (structurally complete, trust not granted — see D3).
5. **Terminus — chain runs out** (no parent in `certs`, not self-signed):
   look up `current.issuer` among the anchors by subject name.
   - Found and `verify_cert_signature(current, anchor)` succeeds →
     `anchored = true, ok = true` (D4 — this is the real Apple case where the
     root is not embedded in the CMS).
   - Found but signature fails → `ok=false`, reason
     `certificate at depth N fails trust-anchor signature verification`.
   - Not found → `ok=false`, reason
     `issuer "X" not present in the embedded set or trust anchors`
     (brief mandate: runs-out unanchored ⇒ `chain_ok=false`).

### 2.3 Validity gating — `verify_signed_data`

- New parameter `anchors: &TrustAnchors`, threaded from the entry points.
- Report errors become two tiers:
  - **Global errors** (SignedData-level, pushed before the SignerInfo loop):
    `no SignerInfo present`, non-`id-data` `eContentType` (upgraded from the
    current warning at `cms_verify.rs:440-443`).
  - **Per-signer errors** (messageDigest / CDHash / signature / chain /
    anchoring / contentType / SKI resolution), accumulated per SignerInfo as
    today, first failing signer kept for diagnostics.
- A SignerInfo sets `report.valid = true` only when **its** errors are empty
  **and** no global error exists. The current unconditional
  `report.errors.clear()` on success (`cms_verify.rs:684`) becomes a
  **conditional** clear: a clean signer still clears previously stored
  *signer* errors (best-signer-wins across a multi-signer set is preserved),
  but only when `global_errors` is empty — structural errors live in
  `global_errors` until `seal` attaches them and are never wiped by a clean
  signer.
- **Every `Ok(report)` exit re-attaches global errors through a small
  `seal(report, global_errors)` helper** — several paths inside the
  SignerInfo loop return early (unsupported digest algorithm, signing
  certificate not found, the clean-signer gate, the no-SignerInfo check, the
  post-loop fallthrough); a bare early return would silently drop the
  SignedData-level diagnostic. `seal` prepends `global_errors` to
  `report.errors` when non-empty (a clean signer cannot clear structural
  errors); it is a no-op for `Err` returns, where the whole report is
  discarded anyway.
- **Anchoring gate:** when `chain_ok` holds but `anchored` is false, push
  `certificate chain is not anchored to a trusted root` into that signer's
  errors (the "gate `valid` on anchoring" requirement, kept observable as a
  distinct report field).
- Invariant (tested): `!report.valid ⇒ !report.errors.is_empty()` — closes the
  SKI invalid-with-empty-errors hole together with §2.4.

### 2.4 SKI-only SignerInfo (item 3)

- **Wire format (reviewer-verified):** cms 0.2.3 encodes
  `SignerIdentifier::SubjectKeyIdentifier` as an *IMPLICIT primitive* `[0]`
  OCTET STRING (`cms-0.2.3/src/signed_data.rs:170-174`; der-derive defaults to
  primitive), so the sid arm must match `Tag::ContextSpecific { number: 0, .. }`
  **regardless of the constructed bit** — matching only the constructed
  `TAG_CTX0` const would send every conformant SKI SignerInfo down the
  unexpected-tag error path. For the primitive form `sid.value()` is the raw
  key id; for a constructed wrapper it is the inner OCTET STRING TLV, which is
  decoded before comparison.
- The sid resolves into either issuer+serial lookup (existing) or a
  pre-resolved `&Certificate` from `find_cert_by_ski`.
- New pure function (unit-testable per brief):
  `fn find_cert_by_ski(certs: &[Certificate], key_id: &[u8]) -> Option<&
  Certificate>` — for each certificate, strict-decode extension `2.5.29.14`
  from `extn_value` as an OCTET STRING and byte-compare the inner key id
  against `key_id`; malformed SKI extensions are skipped.
- No match → per-signer error
  `signer subjectKeyIdentifier does not match any embedded certificate`, then
  `continue` to the next SignerInfo (multi-signer semantics preserved; the
  error lands in `report.errors` when no signer validates).
- The obsolete warning
  `signer identified by subjectKeyIdentifier; skipping` is deleted.
- **Report-level coverage:** the sid sits outside `signedAttrs` (unsigned), so
  a fixture utility re-encodes a round-trip CMS with its sid replaced by
  `80 <len> <key id>` (ancestor lengths rebuilt bottom-up). Positive: own key
  id → full verification succeeds through `verify_signed_data`; negative: a
  wrong key id → `valid == false` with the fatal message above. Unit tests on
  `find_cert_by_ski` remain as edge coverage.

### 2.5 Signed contentType (item 4)

- `parse_signed_attrs` gains per-attribute contentType handling that
  delimits **every complete TLV** of every `contentType` Attribute SET
  (AnyRef walk; each delimited TLV is strict-decoded as an OID separately):
  each TLV increments an occurrence count — so a value *after* a non-OID or
  malformed value is still counted, which the current parser's
  first-value-only + `continue`-on-error behaviour would swallow — and
  decodable OIDs are collected. `OID_CONTENT_TYPE` loses its
  `#[allow(dead_code)]`.
- Per-signer check over `(occurrences, decoded)`:
  - `0` occurrences → `signed contentType attribute missing`
  - `>1` occurrences → `duplicate signed contentType attribute`
  - one occurrence, undecodable → `signed contentType attribute is malformed`
  - one occurrence, decoded ≠ id-data →
    `signed contentType attribute is X (expected id-data)`
- `eContentType != id-data` in `encapContentInfo` becomes a global error
  (`encapContentInfo eContentType is X (expected id-data)`), replacing the
  current warning. Because the signer copies `eContentType` into the attribute,
  the signer side (`crypto/cms.rs`, cms-crate 0.2.3 `SignerInfoBuilder`, which
  auto-adds exactly one `contentType` = `ID_DATA`) satisfies every
  per-signer contentType check —
  verified against `cms-0.2.3/src/builder.rs:226-255` and
  `crypto/cms.rs:103-106`.

### 2.6 SHA-1 warnings (item 5)

Warnings originate in `verify_chain` (§2.2 steps 3/4/5) and are appended to
`report.warnings` **with deduplication** (`if !report.warnings.contains(w)`):
a multi-signer CMS where each SignerInfo walks the same chain would otherwise
repeat identical entries, and the walk itself has no visited-set protection
against pathological cyclic subject-name chains. No other uniqueness guarantee
is made. SHA-1 verification behavior itself is unchanged (still accepted) —
anchoring already confines it to chains under trusted roots, and the existing
`chain_accepts_sha1_signed_intermediate` fixture must keep passing under an
injected anchor.

## 3. Design decisions (alternatives considered)

**D1 — Injection API: parallel `*_with_anchors` function, 4-arg signature kept.**
- Chosen: `verify_code_signature` keeps its signature and defaults to
  `TrustAnchors::apple_root()?`; `verify_code_signature_with_anchors` takes
  `&TrustAnchors`.
- Rejected: adding an `anchors` parameter to `verify_code_signature` — forces an
  edit of `macho/verify.rs` (deferred, forbidden) or breaks its compile.
- Rejected: a verifier builder/config struct — one input does not justify a
  builder; no repo precedent.
- Rejected: `Option<&TrustAnchors>` parameter — `None` would need a semantic
  ("trust anything" reintroduces the vulnerability; "trust nothing" cannot be
  a silent default behind a `None`).

**D2 — Anchor membership = SPKI byte equality on DER.**
- Chosen: compare DER-encoded `SubjectPublicKeyInfo` of candidate vs anchor.
- Rejected: full certificate DER equality — rejects a byte-different but
  identical root re-issued by the operator's store; no security gain (trust is
  granted by the key).
- Rejected: subject-name equality — names are attacker-controlled in a
  self-signed candidate; name match without key match must not grant trust.
- Brief mandates "DER/SPKI" — SPKI is the safe half of that disjunction.

**D3 — Self-signed terminal not in the store: `chain_ok = true,
`anchored = false` + explicit anchoring error.**
- Chosen: structure and self-signature were verified; trust was not granted;
  the report keeps the two facts separable and `valid` is gated by an added
  error. Matches the brief's split ("gate `valid` on anchoring" as its own
  condition).
- Rejected: folding trust into `chain_ok = false` — would make the `anchored`
  field redundant and merge two distinct report facts the CLI prints
  separately (`zsign-cli/src/main.rs:244-257`).

**D4 — Runs-out: look the issuer up in the anchor set before failing.**
- Chosen: if `current.issuer` names an anchor, verify `current`'s signature
  with that anchor's key; only "not found anywhere" ⇒ `chain_ok = false`.
  Apple's CMS often embeds leaf + WWDR intermediate without the root; failing
  those under the default anchors would reject genuinely Apple-signed binaries.
- Rejected: requiring the root to be embedded — would make verification depend
  on signer embedding choices we do not control (Apple's `codesign`).
- Rejected: trusting an unverified runs-out position (status quo) — the
  vulnerability.

**D5 — Purpose rules apply to the leaf unconditionally; anchor treatment
governs only the terminus.**
- Chosen: `leaf_purpose_reason(leaf)` runs for every leaf, self-signed or not:
  EKU codeSigning required, `keyUsage` → `digitalSignature` when present,
  `basicConstraints` → `CA=false` when present. The brief's item 2 is
  unconditional ("missing/malformed code-signing EKU on leaf → error") and the
  brief is authoritative; a self-signed signer is still the leaf of its own
  chain. CA rules (`CA=true`, `pathLen`, `keyCertSign`) apply only to
  certificates climbed to as *distinct* issuers — never to the leaf, so a
  single self-signed certificate is never asked to be both CA and end-entity.
  Anchor membership (self-signature + SPKI) remains the separate terminus
  grant.
- Rejected: exempting self-signed termini from purpose rules (the original
  D5 carve-out) — it contradicts the brief's literal leaf requirement. It
  would also have kept round-trip fixtures working without extension updates;
  under the chosen rule every self-signed test credential must carry
  codeSigning EKU, a digitalSignature `keyUsage`, and `CA=false`
  basicConstraints (plan Task 2 migrates the fixture), and the cross-lane
  handover (§6) must say the same about lanes 24/26's credentials.

**D6 — `assets.rs` and `cert.rs` stay untouched.**
- `APPLE_ROOT_CA_CERT` already exists (`assets.rs:126`) with a PEM-parsing
  doctest; `TrustAnchors::apple_root()` parses it. No production change needed
  in either file. (They remain in scope for tests if a fixture needs them.)

**D7 — Parse the Apple root PEM per call; no `OnceLock`.**
- Rejected: `std::sync::OnceLock` cache — zero precedent in this repo (scout:
  no `OnceLock`/`lazy_static`/`once_cell` in `crates/`), adds global state and
  wasm32 reasoning for no benefit: a PEM parse of a small embedded constant is
  qualitatively far cheaper than the RSA verification that immediately
  follows it (design rationale — no benchmark was run, so no numeric ratio is
  claimed).
- Per-call cost in context: one `Certificate::from_pem` of a ~1.2 KB PEM
  versus one RSA-2048 PKCS#1 v1.5 modular exponentiation.

**D8 — `chain_accepts_sha1_signed_intermediate` migrates, never weakens.**
- The test calls `verify_chain` directly; it gains the `anchors` argument with
  its own root injected and keeps `ok && anchored` assertions; item 5 adds
  warning assertions to it. Brief explicitly protects this fixture.

**D9 — SKI coverage: pure function (brief-sanctioned) + sid-splice
report-level fixtures.**
- Chosen: `find_cert_by_ski` unit tests (positive, negative,
  malformed-SKI-extension cases, using `Profile::Root` fixtures which always
  carry `2.5.29.14`) **plus** two report-level fixtures built by re-encoding a
  round-trip CMS with a spliced primitive `[0]` sid — the sid is outside
  `signedAttrs`, so the signature survives, and ancestor lengths are rebuilt
  bottom-up (no fragile in-place byte surgery). Added after cold review found
  that pure tests alone could not establish SID dispatch end-to-end.
- Rejected: replicating the cms 0.2.3 signer in the test to mint a SKI
  SignerInfo from scratch — duplicates `crypto/cms.rs` build logic, which the
  scope forbids touching.
- Rejected: in-place sid byte replacement without length rebuild — shrinks the
  SignerInfo and desynchronises every ancestor DER length.

**D10 — contentType failures are per-signer errors; `eContentType` failure is
global.** Mirrors RFC 5652: `eContentType` is SignedData-level, the attribute
is SignerInfo-level; a second clean SignerInfo may still validate the CMS only
if the SignedData itself is well-formed.

## 4. Invariants

1. `!report.valid ⇒ !report.errors.is_empty()` (never invalid-with-empty-errors).
2. `report.valid` requires: messageDigest, both CDHash bindings, CMS signature,
   `chain_ok`, **and** `anchored`, with no global error.
3. Only a certificate whose self-signature verifies **and** whose SPKI matches
   an anchor can set `anchored = true` via the embedded-root path; only a
   signature that verifies against an anchor's key can set it via runs-out.
4. Default anchors = Apple Root CA only. WWDR certificates are intermediates,
   never anchors (rejected: adding them would grant intermediate-level trust —
   a compromised intermediate would then be a full trust root).
5. Existing public surface otherwise unchanged: `CmsVerifyReport` fields keep
   their names/types (only `anchored`'s documentation is corrected),
   `adhoc_report()` semantics unchanged, ad-hoc and error-path behavior
   unchanged.
6. Round-trip verification of this repo's own signatures still succeeds when
   the signer's own certificate is injected as an anchor: the signer fixture
   is a self-issued `Profile::Leaf` carrying codeSigning EKU, a
   digitalSignature keyUsage, and `CA=false` basicConstraints, and it
   terminates at itself as its own anchor (cms 0.2.3 emits exactly one
   id-data `contentType`). `Profile::Root` is reserved for issuer fixtures,
   which face the CA rules rather than the leaf rules.

## 5. Test strategy

All tests are inline `#[cfg(test)]` tests in `cms_verify.rs` (repo convention).
Gate per task: `cargo test -p zsign-core crypto -- --skip
test_ipa_signing_is_deterministic` (narrower filters per task).

**Regression tests — written first, must FAIL on the base commit:**

| Test | Setup | Pre-fix result |
|---|---|---|
| `attacker_self_signed_resign_is_invalid` | Sign content+CDHash with victim creds; re-sign the *same* content/CDHash with fresh attacker self-signed creds; verify attacker CMS against anchors = {victim root} | `valid = true` (all bindings match; structural self-signed "anchor") ⇒ test RED |
| `chain_missing_issuer_is_invalid` | Leaf issued by a root, but only the leaf is embedded (`cert_chain: []`); anchors = {unrelated root}; leaf carries codeSigning EKU so purpose passes | `chain_ok = true, anchored = false` ⇒ `valid = true` ⇒ test RED |
| `unanchored_structural_chain_is_invalid` | Self-signed creds B verified against anchors = {root A} | `valid = true` ⇒ test RED |

**Migrations (item 1 test churn — intended design, not regression):**
`round_trip_rsa_signs_and_verifies`, `tampered_content_fails_digest`,
`tampered_signature_fails_crypto`, `wrong_cdhash_fails_binding`,
`ber_indefinite_cms_verifies` switch to `verify_code_signature_with_anchors`
with their own `rsa_credentials().certificate` as anchor; `rejects_non_cms` /
`rejects_wrong_wrapper_magic` keep the 4-arg path (parse fails first);
`chain_accepts_sha1_signed_intermediate` gains the `anchors` argument (D8).
The migrated `unanchored_structural_chain_is_invalid` stays on the 4-arg
entry point, pinning the Apple-root default itself.

**Per-item tests:**
- Item 2: 2-cert `[leaf, root]` fixtures through `verify_chain` directly —
  missing EKU (Profile::Leaf default) ⇒ fail; EKU present without codeSigning
  (`add_extension`) ⇒ fail; malformed EKU / KU-without-digitalSignature /
  leaf-CA-true / issuer-not-CA / violated `pathLen` ⇒ fail, each asserting the
  matching `reason` substring; positive: Profile::Leaf + codeSigning EKU under
  a `Profile::Root` issuer ⇒ `ok && anchored`.
- Item 3: `find_cert_by_ski` unit tests (own key id resolves, wrong bytes do
  not, malformed SKI extension skipped) **plus report-level fixtures** built by
  re-encoding a round-trip CMS with a spliced primitive `[0]` sid (unsigned
  field): positive proves resolution through `verify_signed_data`
  (`valid == true`, `signer_subject` set); negative (wrong key id) proves the
  fatal report error. No byte-surgery shortcut — ancestor lengths are rebuilt
  bottom-up.
- Item 4: parser-level tests over raw signedAttrs DER fed to the real
  `parse_signed_attrs` — duplicate contentType attributes, a
  malformed-second-value case, and a malformed-middle-with-valid-trailing-value
  case (asserting the full TLV count of 3) must all be counted and rejected — plus the
  pure `content_type_reason` decision cases (missing / exactly one id-data /
  duplicate / wrong OID / malformed), plus a report-level fixture that patches
  `encapContentInfo.eContentType` to a non-id-data OID (one-byte, same-length,
  outside `signedAttrs`) asserting the global error lands in `errors` and a
  clean SignerInfo cannot clear it (`valid == false`, `errors` non-empty), plus
  the round trip staying green (signer emits exactly one id-data contentType —
  pinned by `cms-0.2.3/src/builder.rs:240-254` for the single auto-added
  value and `crypto/cms.rs:103-106` for the value being `ID_DATA`).
- Item 5: migrated SHA-1 chain asserts `warnings` mention SHA-1 while `ok &&
  anchored` still hold; a SHA-256 chain asserts no SHA-1 warning.

**Verification commands (scoped):**
- Per task: `cargo test -p zsign-core crypto::cms_verify` (or the narrowest
  filter covering the changed code).
- Lane gate: `cargo test -p zsign-core crypto -- --skip
  test_ipa_signing_is_deterministic`.
- Final: `cargo test --workspace -- --skip test_ipa_signing_is_deterministic`
  — expected cross-lane failures documented in §6; everything else green.

## 6. Cross-lane impact (known, out of this lane's file scope)

Keeping the 4-arg entry point source-compatible means **no production caller
needs edits**, but four positive round-trip tests in deferred files sign with
self-signed credentials and then assert validity through `verify_macho` /
`verify_bundle`. After item 1 they become unanchored (expected churn per the
brief) and will fail **until those files' owners inject anchors** — their
verify entry points (`verify_macho`, `verify_bundle`, `SignatureInputs`) have
no anchor parameter yet, so the injection requires a small plumbing change in
the deferred files themselves:

| Test | Assertions that newly fail |
|---|---|
| `zsign-core/src/macho/verify.rs::verify_signed_binary_round_trip` | `:348-352`, `:359` |
| `zsign-core/src/macho/verify.rs::special_slots_bind_info_and_resources` | `:431-435` |
| `zsign/src/verify.rs::signed_bundle_verifies` | `:539-548`, `:551-559` |
| `zsign/src/verify.rs::bare_macho_verifies` | `:621-622` |

Additionally `scripts/verify-apple-interop.sh` (macOS-only, not part of
`cargo test`) signs a self-signed bundle that is "its own implicit trust
anchor" (`:11-12`) and requires `zsign -V` to accept it (`agree_valid`,
`:153-175`); with Apple-root default anchors that interop check turns red.
**Handover requirement (wave-2/interop follow-up — this lane does NOT edit the
script):** its signing certificate is `CA:TRUE`
(`scripts/verify-apple-interop.sh:36-45`), which the unconditional leaf rules
(D5) reject **even after anchor injection** — restoring the interop needs two
changes together: (a) verify-surface anchor plumbing (inject the target's own
certificate), and (b) switching the script's certificate to an end-entity
constraint (`basicConstraints { ca: false }` plus the codeSigning EKU and
digitalSignature keyUsage the leaf rules require).

This lane edits none of those files (hard scope rule). The handover contract
for lanes 24/26: `zsign_core::crypto::cms_verify::{TrustAnchors,
verify_code_signature_with_anchors}` — plumb an optional `&TrustAnchors`
(lease: `TrustAnchors::from_certificates(vec![creds.certificate.clone()])` in
tests, `TrustAnchors::apple_root()` in production defaults). **Because leaf
purpose rules are unconditional (D5), their self-signed test credentials must
also carry codeSigning EKU, a `digitalSignature` keyUsage, and
`basicConstraints { ca: false }`** — `Profile::Root` defaults (no EKU,
`keyCertSign|cRLSign`, `CA=true`) fail the leaf rules even after anchor
injection; see plan Task 2's `rsa_credentials` migration for the exact shape.

**Handover (settled):** lanes 24/26 own the migration of those four tests
with the plumbing contract stated above — this lane never edits deferred test
functions (hard scope rule; no scope-waiver path exists). The failing-test
table is the handoff artifact.

## 7. Explicitly out of scope

- Revocation / OCSP / CRL — not in the brief; `valid` remains
  validity+binding+chain+anchor only.
- `adhoc_report()` / empty-CMS semantics (`macho/verify.rs` — lane 24).
- Dual-CDHash binding, FAT/superblob bounds (lane 24 / ZSN-25).
- `zsign-cli` exit-code handling (main.rs lane) — unaffected: its
  `0/1/2` contract (`main.rs:90-95`) derives from `report.valid()` and
  `report.errors`, both of which now reflect anchoring for free.
- Signer-side changes (`crypto/cms.rs`, `macho/signer.rs`, `writer.rs`) — the
  signer already emits everything the new verifier requires (scout-verified).
- `.gitignore`, `.github/**`, manifests — untouched (docs are force-added).

## 8. Documentation updates (in `cms_verify.rs`)

- Module header: replace the trust-policy paragraph (currently "deliberately
  left to the device/`codesign`", `cms_verify.rs:21-23`) with the new contract:
  integrity + bindings + chain structure + **anchoring to an explicit trust
  anchor set (default Apple Root CA)**; revocation remains a device concern.
  Extend the numbered check list with purpose enforcement, signed contentType,
  SKI resolution, SHA-1 warnings.
- `CmsVerifyReport::anchored` field doc: "chain terminates at a verified trust
  anchor" (was: "terminates at a self-signed anchor").
- `verify_code_signature` doc: note the default anchor set and point at
  `verify_code_signature_with_anchors` for injection.
