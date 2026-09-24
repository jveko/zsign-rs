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
   (`cms_verify.rs:316-378`) parses only `messageDigest` and the Apple CDHash
   attributes; `OID_CONTENT_TYPE` is a dead constant (`cms_verify.rs:46-48`).
   RFC 5652 §5.6 requires exactly one `contentType` attribute equal to the
   encapsulated content type.
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

Internal helpers (private): `contains_spki(&Certificate) -> bool` (byte-equality
on DER-encoded `SubjectPublicKeyInfo`) and
`find_by_subject(&x509_cert::name::Name) -> Option<&Certificate>` (for the
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
error → slice error → CLI exit 1.

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

1. **Leaf purpose rules** — applied only when `leaf.subject != leaf.issuer`
   (D5). Strict-decode each extension with `Type::from_der` (rejects trailing
   bytes, per der 0.7 `Decode::from_der` → `reader.finish`):
   - EKU (`2.5.29.37`) **required**; malformed → error; decoded list must
     contain `1.3.6.1.5.5.7.3.3` (codeSigning), else error.
   - `keyUsage` (`2.5.29.15`), if present: must include `digitalSignature`.
   - `basicConstraints` (`2.5.29.19`), if present: `ca` must be `false`.
2. **Leaf validity window** (unchanged, `cms_verify.rs:838-848`).
3. **Climb** — for each parent `p` found in `certs` (distinct from `current`),
   before verifying its signature over `current`:
   - `p`'s `basicConstraints` required, strict-decoded, `ca == true`.
   - `p`'s `pathLenConstraint`, if present: number of CA certificates below
     `p` in the built chain (`chain.len() - 1` after `p` is appended) must be
     `<= pathLen`.
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
  `report.errors.clear()` on success (`cms_verify.rs:684`) is removed so
  global errors can never be wiped by a clean signer.
- **Anchoring gate:** when `chain_ok` holds but `anchored` is false, push
  `certificate chain is not anchored to a trusted root` into that signer's
  errors (the "gate `valid` on anchoring" requirement, kept observable as a
  distinct report field).
- Invariant (tested): `!report.valid ⇒ !report.errors.is_empty()` — closes the
  SKI invalid-with-empty-errors hole together with §2.4.

### 2.4 SKI-only SignerInfo (item 3)

- The sid is decoded into `SignerId::IssuerAndSerialNumber { issuer_der,
  serial_der }` or `SignerId::SubjectKeyIdentifier(Vec<u8>)` and resolution
  happens where the signing certificate is located today
  (`cms_verify.rs:600-613`).
- New pure function (unit-testable per brief):
  `fn find_cert_by_ski(certs: &[Certificate], key_id: &[u8]) -> Option<&
  Certificate>` — for each certificate, strict-decode extension `2.5.29.14`
  (`x509_cert::ext::pkix::SubjectKeyIdentifier`, an `OctetString` newtype) from
  `extn_value` and byte-compare the inner key id against `key_id`; malformed
  SKI extensions are skipped.
- No match → per-signer error
  `signer subjectKeyIdentifier does not match any embedded certificate`, then
  `continue` to the next SignerInfo (multi-signer semantics preserved; the
  error lands in `report.errors` when no signer validates).
- The obsolete warning
  `signer identified by subjectKeyIdentifier; skipping` is deleted.

### 2.5 Signed contentType (item 4)

- `parse_signed_attrs` gains `content_types: Vec<ObjectIdentifier>` (all
  occurrences of `1.2.840.113549.1.9.3` in the SET); `OID_CONTENT_TYPE` loses
  its `#[allow(dead_code)]`.
- Per-signer check, feeding the per-signer error tier:
  - `0` occurrences → `signed contentType attribute missing`
  - `>1` occurrences → `duplicate signed contentType attribute`
  - the single value must be `1.2.840.113549.1.7.1` (id-data) →
    `signed contentType attribute is X (expected id-data)`
- `eContentType != id-data` in `encapContentInfo` becomes a global error
  (`encapContentInfo eContentType is X (expected id-data)`), replacing the
  current warning. Because the signer copies `eContentType` into the attribute,
  the signer side (`crypto/cms.rs`, cms-crate 0.2.3 `SignerInfoBuilder`, which
  auto-adds exactly one `contentType` = `ID_DATA`) satisfies all three checks —
  verified against `cms-0.2.3/src/builder.rs:226-255` and
  `crypto/cms.rs:103-106`.

### 2.6 SHA-1 warnings (item 5)

Warnings originate in `verify_chain` (§2.2 step 3/4/5) and are appended to
`report.warnings`. SHA-1 verification behavior itself is unchanged (still
accepted) — anchoring already confines it to chains under trusted roots, and
the existing `chain_accepts_sha1_signed_intermediate` fixture must keep passing
under an injected anchor.

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

**D5 — Purpose rules (EKU/KU/leaf-BC) apply to non-self-signed leaves only.**
- Chosen: `if leaf.subject != leaf.issuer` then enforce EKU/KU/leaf-BC.
  A self-signed terminal is either an explicitly trusted anchor (membership is
  the stronger, operator-granted trust — RFC 5280 does not validate trust-anchor
  constraints) or it fails the anchoring gate anyway. Every meaningful path
  (real Apple chains, attacker chains under a trusted root, misissued leaves)
  has a non-self-signed leaf and is fully purpose-checked.
- Rejected: unconditional leaf rules — would require every test credential to
  be a synthetic "CA that is also an end-entity" (Profile::Root certs carry
  `keyCertSign|cRLSign` KU and `CA=true` BC by construction,
  `x509-cert-0.2.5/src/builder.rs:162-192`), i.e. the fixture could never
  satisfy both its anchor role and its leaf role. This is the design's one
  deliberate carve-out; it is what keeps the security property (no untrusted
  key ever validates) while making the rules consistent.

**D6 — `assets.rs` and `cert.rs` stay untouched.**
- `APPLE_ROOT_CA_CERT` already exists (`assets.rs:126`) with a PEM-parsing
  doctest; `TrustAnchors::apple_root()` parses it. No production change needed
  in either file. (They remain in scope for tests if a fixture needs them.)

**D7 — Parse the Apple root PEM per call; no `OnceLock`.**
- Rejected: `std::sync::OnceLock` cache — zero precedent in this repo (scout:
  no `OnceLock`/`lazy_static`/`once_cell` in `crates/`), adds global state and
  wasm32 reasoning for a PEM parse that is ~1000× cheaper than the RSA
  verification that immediately follows it.
- Rejects per-call cost concern with evidence: one `Certificate::from_pem` of a
  ~1.2 KB PEM vs one RSA-2048 PKCS#1 v1.5 verify (milliseconds).

**D8 — `chain_accepts_sha1_signed_intermediate` migrates, never weakens.**
- The test calls `verify_chain` directly; it gains the `anchors` argument with
  its own root injected and keeps `ok && anchored` assertions; item 5 adds
  warning assertions to it. Brief explicitly protects this fixture.

**D9 — SKI resolution is a pure function + inline wiring; no full SKI CMS
fixture.**
- The signer side (`crypto/cms.rs`) always builds
  `IssuerAndSerialNumber`; fabricating a complete SKI-identified CMS with
  matching Apple CDHash attributes by hand would duplicate the signer in the
  test. The brief explicitly allows factoring the decision into a pure
  function (`find_cert_by_ski`) and unit-testing it (positive, negative,
  malformed-SKI-extension cases, using `Profile::Root` fixtures which always
  carry `2.5.29.14`).

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
   the signer's own root is injected (cms 0.2.3 emits exactly one `contentType`
   = id-data; `Profile::Root` fixtures terminate at an injectable self-signed
   root).

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
A `default_anchors_reject_self_signed` test exercises the 4-arg entry point so
the Apple default itself is pinned.

**Per-item tests:**
- Item 2: 2-cert `[leaf, root]` fixtures through `verify_chain` directly —
  missing EKU (Profile::Leaf default) ⇒ fail; EKU present without codeSigning
  (`add_extension`) ⇒ fail; malformed EKU / KU-without-digitalSignature /
  leaf-CA-true / issuer-not-CA / violated `pathLen` ⇒ fail, each asserting the
  matching `reason` substring; positive: Profile::Leaf + codeSigning EKU under
  a `Profile::Root` issuer ⇒ `ok && anchored`.
- Item 3: `find_cert_by_ski` unit tests — own key id resolves, wrong bytes do
  not, malformed SKI extension is skipped; wiring: the deleted warning and the
  new error string are asserted absent/present via a report-level path where
  reachable.
- Item 4: pure-function tests over the contentType decision (missing / exactly
  one id-data / duplicate / wrong OID), plus the round trip staying green
  (signer emits exactly one id-data contentType — pinned by scout evidence and
  `cms.rs:584-599`).
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

This lane edits none of those files (hard scope rule). The handover contract
for lanes 24/26: `zsign_core::crypto::cms_verify::{TrustAnchors,
verify_code_signature_with_anchors}` — plumb an optional `&TrustAnchors`
(lease: `TrustAnchors::from_certificates(vec![creds.certificate.clone()])` in
tests, `TrustAnchors::apple_root()` in production defaults).

**Open question for the supervisor** (stated once, per brief): who migrates
these four tests — (a) lanes 24/26 absorb it with the plumbing above (this
design's default assumption; the failing-test list above is the handover), or
(b) this lane receives an explicit scope waiver to touch *only those test
functions*? Nothing else in this design depends on the answer.

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
