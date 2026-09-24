# CMS Trust Anchor Implementation Plan (ZSN-23)

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development
> (recommended) with dispatching-parallel-agents for independent tasks to
> implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for
> tracking. Controller commits after each task passes its gate; implementer
> subagents never commit.

**Goal:** Make CMS verification anchor certificate chains to an explicit
trust-anchor set (default: the embedded Apple Root CA) and enforce X.509
purpose, SKI-signer, signed-contentType, and SHA-1-warning rules.

**Architecture:** All changes are confined to
`crates/zsign-core/src/crypto/cms_verify.rs` (+ its inline tests). A new
`TrustAnchors` type threads through `verify_code_signature_with_anchors`;
the existing 4-arg `verify_code_signature` keeps its signature and defaults to
`TrustAnchors::apple_root()`, so the deferred caller
`macho/verify.rs:178-183` compiles untouched. `verify_chain` returns a
`ChainOutcome` struct (adds `warnings`) and takes `anchors`.

**Tech Stack:** Rust 2021, `x509-cert` 0.2.5 (`x509_cert::ext::pkix::
{BasicConstraints, KeyUsage, ExtendedKeyUsage, SubjectKeyIdentifier}`,
strict decode via `der::Decode::from_der`), `der` 0.7, existing test fixture
builders (`x509_cert::builder::{CertificateBuilder, Profile}`).

**Design:** `docs/superpowers/specs/2026-09-24-cms-trust-anchor-design.md`
(authoritative; this plan executes it — section refs like "D5" point there).

**Scoped gate (run before every commit):**
`cargo test -p zsign-core crypto -- --skip test_ipa_signing_is_deterministic`
Never run `cargo fmt` / `cargo clippy` / `hk` mid-flight; the pre-commit hook
runs automatically at controller commits.

---

### Task 1: Anchor CMS chains to explicit trust anchors (queue item 1)

**Files:**
- Modify: `crates/zsign-core/src/crypto/cms_verify.rs` (module docs ~:1-40,
  `CmsVerifyReport` ~:214-245, `verify_code_signature` ~:258-269,
  `verify_signed_data` ~:380-697, `verify_chain` ~:818-916, tests ~:1028-1290)

- [ ] **Step 1.1: Write the three regression tests (RED — must fail on base)**

Add to the `tests` module in `cms_verify.rs`. They use the **current** 4-arg
API so they compile against the base commit; all three must FAIL there
(assertions expect `!report.valid`, base returns `valid = true`):

```rust
#[test]
fn attacker_self_signed_resign_is_invalid() {
    let (victim, _k1) = rsa_credentials();
    let (attacker, _k2) = rsa_credentials();
    let content: &[u8] = b"the code directory bytes";
    let cd_sha256: [u8; 32] = Sha256::digest(content).into();
    // The attacker re-signs the same CodeDirectory (same CDHash binding)
    // with a fresh self-signed certificate that nobody trusts.
    let cms = sign_code_directory(content, &attacker, None, &cd_sha256).unwrap();
    let report = verify_code_signature(&wrap(&cms), content, None, &cd_sha256).unwrap();
    assert!(!report.valid, "attacker re-sign must not verify: {:?}", report.errors);
    assert!(!report.errors.is_empty());
}

#[test]
fn chain_missing_issuer_is_invalid() {
    // leaf issued by `root`, but only the leaf gets embedded (cert_chain empty);
    // the anchors available at verification time are an UNRELATED root.
    let (_root_key, root, root_signer) = build_rsa_root("CN=zsign missing issuer root");
    let leaf_key = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
    let leaf_signing = rsa::pkcs1v15::SigningKey::<Sha256>::new(leaf_key.clone());
    let leaf_subject = Name::from_str("CN=zsign missing issuer leaf").unwrap();
    let mut leaf_builder = CertificateBuilder::new(
        Profile::Leaf {
            issuer: root.tbs_certificate.subject.clone(),
            enable_key_agreement: false,
            enable_key_encipherment: false,
        },
        SerialNumber::from(7u32),
        Validity::from_now(Duration::from_secs(3600)).unwrap(),
        leaf_subject,
        SubjectPublicKeyInfoOwned::from_der(
            leaf_key.to_public_key().to_public_key_der().unwrap().as_ref(),
        )
        .unwrap(),
        &root_signer,
    )
    .unwrap();
    leaf_builder
        .add_extension(&ExtendedKeyUsage(vec![OID_CODE_SIGNING]))
        .unwrap();
    let leaf = leaf_builder.build::<rsa::pkcs1v15::Signature>().unwrap();
    let creds = SigningCredentials {
        certificate: leaf,
        signing_key: SigningKeyType::Rsa(leaf_signing),
        cert_chain: vec![],
        team_id: None,
    };
    let content: &[u8] = b"the code directory bytes";
    let cd_sha256: [u8; 32] = Sha256::digest(content).into();
    let cms = sign_code_directory(content, &creds, None, &cd_sha256).unwrap();
    let report = verify_code_signature(&wrap(&cms), content, None, &cd_sha256).unwrap();
    assert!(!report.valid, "unanchored missing-issuer chain: {:?}", report.errors);
    assert!(!report.errors.is_empty());
}

#[test]
fn unanchored_structural_chain_is_invalid() {
    let (creds, _k) = rsa_credentials();
    let content: &[u8] = b"the code directory bytes";
    let cd_sha256: [u8; 32] = Sha256::digest(content).into();
    let cms = sign_code_directory(content, &creds, None, &cd_sha256).unwrap();
    // Default anchors = Apple Root CA: this self-signed test root is not one.
    let report = verify_code_signature(&wrap(&cms), content, None, &cd_sha256).unwrap();
    assert!(!report.valid, "structural-but-unanchored chain must be invalid");
    assert!(report.chain_ok, "structure itself is fine: {:?}", report.chain_reason);
    assert!(!report.anchored);
}
```

Add the fixture helper the second test uses (same test module; a SHA-256
counterpart of the existing SHA-1 root builder at `:1230-1248`):

```rust
fn build_rsa_root(cn: &str) -> (rsa::RsaPrivateKey, x509_cert::Certificate, rsa::pkcs1v15::SigningKey<Sha256>) {
    let key = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
    let signing_key = rsa::pkcs1v15::SigningKey::<Sha256>::new(key.clone());
    let subject = Name::from_str(cn).unwrap();
    let pub_key = SubjectPublicKeyInfoOwned::from_der(
        key.to_public_key().to_public_key_der().unwrap().as_ref(),
    )
    .unwrap();
    let cert = CertificateBuilder::new(
        Profile::Root,
        SerialNumber::from(9u32),
        Validity::from_now(Duration::from_secs(3600)).unwrap(),
        subject,
        pub_key,
        &signing_key,
    )
    .unwrap()
    .build::<rsa::pkcs1v15::Signature>()
    .unwrap();
    (key, cert, signing_key)
}
```

Add missing test imports if the compiler asks: `x509_cert::ext::pkix::ExtendedKeyUsage`.

- [ ] **Step 1.2: Run tests to confirm they fail**

Run: `cargo test -p zsign-core crypto::cms_verify -- --skip test_ipa_signing_is_deterministic`
Expected: the three new tests FAIL (each asserts `!report.valid`; base builds
`valid = true`); every pre-existing test still passes.

- [ ] **Step 1.3: Implement `TrustAnchors` and the anchor-aware entry point**

In `cms_verify.rs`, directly after `adhoc_report()` (~:278), add:

```rust
/// Certificates whose public keys are trusted as chain termini.
///
/// A chain must terminate at a certificate that either matches one of these
/// anchors (embedded self-signed root) or whose missing issuer names one
/// (unembedded root); otherwise verification fails as unanchored.
#[derive(Debug, Clone, Default)]
pub struct TrustAnchors {
    roots: Vec<x509_cert::Certificate>,
}

impl TrustAnchors {
    /// Wraps the given certificates as trust anchors.
    pub fn from_certificates(roots: Vec<x509_cert::Certificate>) -> Self {
        Self { roots }
    }

    /// The Apple Root CA embedded in [`crate::crypto::assets`].
    ///
    /// This is the default anchor set for [`verify_code_signature`].
    pub fn apple_root() -> Result<Self> {
        let cert =
            x509_cert::Certificate::from_pem(crate::crypto::assets::APPLE_ROOT_CA_CERT.as_bytes())
                .map_err(|e| {
                    Error::Verification(format!("embedded Apple root CA certificate is invalid: {e}"))
                })?;
        Ok(Self { roots: vec![cert] })
    }

    /// Whether an anchor's DER-encoded SubjectPublicKeyInfo equals `spki_der`.
    fn contains_spki(&self, spki_der: &[u8]) -> bool {
        self.roots.iter().any(|r| {
            r.tbs_certificate
                .subject_public_key_info
                .to_der()
                .map(|d| d.as_slice() == spki_der)
                .unwrap_or(false)
        })
    }

    /// The anchor whose subject equals `name` (issuer lookup for unembedded roots).
    fn find_by_subject(&self, name: &x509_cert::name::Name) -> Option<&x509_cert::Certificate> {
        self.roots.iter().find(|r| r.tbs_certificate.subject == *name)
    }
}
```

(Imports: `Certificate::from_pem` requires `der::DecodePem` in scope — it is
currently missing from the `der` imports at the top of `cms_verify.rs
(~:35-40)`; `to_der` requires `der::Encode`. Add both explicitly.)

Change `verify_code_signature` to delegate and add the new function:

```rust
pub fn verify_code_signature(
    cms_blob: &[u8],
    content: &[u8],
    cd_sha1: Option<&[u8; 20]>,
    cd_sha256: &[u8; 32],
) -> Result<CmsVerifyReport> {
    verify_code_signature_with_anchors(cms_blob, content, cd_sha1, cd_sha256, &TrustAnchors::apple_root()?)
}

/// Like [`verify_code_signature`], but against an explicit anchor set.
///
/// Tests inject their own root here; production callers that need a custom
/// trust policy pass their store. The default entry point uses
/// [`TrustAnchors::apple_root`].
pub fn verify_code_signature_with_anchors(
    cms_blob: &[u8],
    content: &[u8],
    cd_sha1: Option<&[u8; 20]>,
    cd_sha256: &[u8; 32],
    anchors: &TrustAnchors,
) -> Result<CmsVerifyReport> {
    let cms = strip_blob_wrapper(cms_blob)?;
    let cms = normalize_ber_lengths(cms)?;
    verify_signed_data(&cms, content, cd_sha1, cd_sha256, anchors)
}
```

- [ ] **Step 1.4: Restructure `verify_chain`**

Replace the tuple return with:

```rust
/// The result of walking a certificate chain toward a trust anchor.
struct ChainOutcome {
    /// Structural + cryptographic checks passed (every link verified).
    ok: bool,
    /// The terminus was matched against the trust anchors.
    anchored: bool,
    /// Certificate subjects, leaf first.
    subjects: Vec<String>,
    /// Why `ok` is false, when it is.
    reason: Option<String>,
    /// Non-fatal observations (SHA-1 signatures — added by queue item 5).
    warnings: Vec<String>,
}
```

New signature: `fn verify_chain(certs: &[x509_cert::Certificate],
leaf: &x509_cert::Certificate, anchors: &TrustAnchors) -> ChainOutcome`.

Keep the existing leaf-validity check and climb loop intact, changing only:

1. Every `return (false, false, names, Some(...))` /
   `return (true, _, names, ...)` becomes
   `return ChainOutcome { ok: …, anchored: …, subjects: names, reason: …,
   warnings }` (initialise `let warnings: Vec<String> = Vec::new();` next to
   `let mut names = …`).
2. The self-signed terminus branch (currently `:890-894`) becomes:

```rust
if self_signed {
    if !verify_cert_signature(current, current) {
        return ChainOutcome {
            ok: false,
            anchored: false,
            subjects: names,
            reason: Some(format!(
                "self-signed certificate at depth {depth} fails self-signature verification"
            )),
            warnings,
        };
    }
    let spki_der = current
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map(|d| d.to_vec())
        .map_err(|_| ())
        .unwrap_or_default();
    if anchors.contains_spki(&spki_der) {
        return ChainOutcome { ok: true, anchored: true, subjects: names, reason: None, warnings };
    }
    // Structure complete, trust not granted — `valid` is gated on `anchored`.
    return ChainOutcome { ok: true, anchored: false, subjects: names, reason: None, warnings };
}
```

3. The runs-out branch (currently `:895-905`) becomes:

```rust
// Chain runs out: try the trust anchors for the missing issuer before failing.
let missing = current.tbs_certificate.issuer.clone();
if let Some(anchor) = anchors.find_by_subject(&missing) {
    if verify_cert_signature(current, anchor) {
        names.push(anchor.tbs_certificate.subject.to_string());
        return ChainOutcome { ok: true, anchored: true, subjects: names, reason: None, warnings };
    }
    return ChainOutcome {
        ok: false,
        anchored: false,
        subjects: names,
        reason: Some(format!(
            "certificate at depth {depth} fails trust-anchor signature verification"
        )),
        warnings,
    };
}
return ChainOutcome {
    ok: false,
    anchored: false,
    subjects: names,
    reason: Some(format!(
        "issuer \"{missing}\" not present in the embedded set or trust anchors"
    )),
    warnings,
};
```

4. The post-loop fallback (`:909-915`) returns `ChainOutcome { ok: false, … }`
   as before. (`let _ = chain;` can be deleted if still present.)
5. Update the function's doc comment: it now also takes anchors and reports
   warnings; delete the stale `(chain_ok, anchored, …)` tuple mention.

- [ ] **Step 1.5: Gate `valid` on anchoring inside `verify_signed_data`**

`verify_signed_data` (~:380) gains `anchors: &TrustAnchors` (threaded from
`verify_code_signature_with_anchors`) and passes it to `verify_chain`. The
`eContentType` warning, the SignerInfo loop structure, and the clean-signer
gate stay exactly as they are in this task — anchoring is a per-signer
condition and does not need a global tier (queue item 4 introduces that in
Task 4). Replace the chain block (~:654-680) with:

```rust
// 4. Chain structure and trust anchoring.
let outcome = verify_chain(&certs, cert, anchors);
report.chain_ok = outcome.ok;
report.anchored = outcome.anchored;
report.chain = outcome.subjects;
report.chain_reason = outcome.reason.clone();
for w in outcome.warnings {
    if !report.warnings.contains(&w) {
        report.warnings.push(w);
    }
}
```

and in the error-accumulation block below it, replace the `!chain_ok` push
with:

```rust
if !outcome.ok {
    errors.push(
        report
            .chain_reason
            .clone()
            .unwrap_or_else(|| "certificate chain is not structurally valid".into()),
    );
} else if !outcome.anchored {
    errors.push("certificate chain is not anchored to a trusted root".into());
}
```

Everything else in `verify_signed_data` is unchanged in this task; the
existing clean-signer gate (`if errors.is_empty() { report.valid = true;
report.errors.clear(); … }`) already routes the new anchoring error into
`report.errors` for every non-anchored signer.

- [ ] **Step 1.6: Migrate existing tests to anchor injection**

Add to the test module:

```rust
fn anchors_for(creds: &SigningCredentials) -> TrustAnchors {
    TrustAnchors::from_certificates(vec![creds.certificate.clone()])
}
```

- `round_trip_rsa_signs_and_verifies`, `tampered_content_fails_digest`,
  `tampered_signature_fails_crypto`, `wrong_cdhash_fails_binding`,
  `ber_indefinite_cms_verifies`: change each `verify_code_signature(&wrap(…) …)`
  call to `verify_code_signature_with_anchors(&wrap(…) …, &anchors_for(&creds))`.
  Assertions stay as they are (round trip keeps asserting `report.anchored`).
- `chain_accepts_sha1_signed_intermediate`: destructure the new outcome and
  pass anchors:
  ```rust
  let outcome = verify_chain(
      &[root.clone(), leaf.clone()],
      &leaf,
      &TrustAnchors::from_certificates(vec![root.clone()]),
  );
  assert!(outcome.ok, "SHA-1-signed intermediate must chain: {:?}", outcome.reason);
  assert!(outcome.anchored);
  ```
- `attacker_self_signed_resign_is_invalid`: switch to
  `verify_code_signature_with_anchors(…, &anchors_for(&victim))` and keep all
  assertions; add `assert!(!report.anchored);`.
- `chain_missing_issuer_is_invalid`: switch to
  `verify_code_signature_with_anchors(…, &anchors_for(&unrelated))` where
  `let (unrelated, _uk) = rsa_credentials();` — pins that the issuer lookup
  consults the anchor set, not just the default store; add
  `assert!(report.errors.iter().any(|e| e.contains("not present in the embedded set or trust anchors")));`
- `unanchored_structural_chain_is_invalid`: **stays on the 4-arg
  `verify_code_signature`** — it pins the Apple-root default itself.
- `rejects_non_cms` / `rejects_wrong_wrapper_magic`: unchanged (4-arg; parse
  fails before anchors matter).

- [ ] **Step 1.7: Update documentation (design §8)**

- Module header (~:1-40): replace the trust-policy paragraph
  ("Trust *policy* … deliberately left to the device/`codesign`") with:
  the module proves integrity, Apple-attribute binding, chain structure,
  **and anchoring to an explicit trust-anchor set —
  [`TrustAnchors::apple_root`] by default; revocation remains a device
  concern.** Extend the numbered check list with: certificate chain anchored
  to a trusted root.
- `CmsVerifyReport::anchored` field doc (~:235-236): "Whether the chain
  terminates at a verified trust anchor" (was "…at a self-signed anchor").
- `verify_code_signature` doc (~:250-257): note the default anchor set and
  link `verify_code_signature_with_anchors`.
- The module doc example (~:27-32) compiles unchanged — verify.

- [ ] **Step 1.8: Run the gate**

Run: `cargo test -p zsign-core crypto -- --skip test_ipa_signing_is_deterministic`
Expected: PASS — the three regression tests green, every migrated test green.
This is the task's definition of green (the lane's scoped gate).

Known red **outside this lane's scope**, produced deliberately by this change
and documented in design §6 — do NOT touch them, report them in the handover:
- `crates/zsign-core/src/macho/verify.rs::verify_signed_binary_round_trip` and
  `::special_slots_bind_info_and_resources` (positive self-signed round trips
  through the production caller → default Apple anchors);
- `crates/zsign/src/verify.rs::signed_bundle_verifies` and
  `::bare_macho_verifies` (same, one layer up);
- `scripts/verify-apple-interop.sh` (macOS-only; requires `zsign -V` to accept
  a self-signed bundle — `scripts/verify-apple-interop.sh:11-12,153-175`).
They need anchor injection in deferred files (design §6 handover contract),
which this lane may not edit.

- [ ] **Step 1.9: Acceptance**

- Regression trio passes: attacker re-sign invalid + non-empty errors;
  missing-issuer chain invalid; structural-unanchored chain invalid with
  `chain_ok` true / `anchored` false.
- The scoped gate (Step 1.8) is fully green; the known deferred/interop reds
  are exactly the ones enumerated there — no others.
- Scope audit: `macho/verify.rs` and all other non-crypto files show zero
  diff (`git diff --stat ee42c12..HEAD` limited to `crypto/cms_verify.rs`).
  Zero diff is a *scope* guarantee only — it deliberately does not make the
  deferred tests green (design §6 owns that handover).
- Commit (controller): `feat(zsign-core): anchor cms verification to explicit trust anchors`

---

### Task 2: Enforce X.509 purpose constraints (queue item 2)

**Files:**
- Modify: `crates/zsign-core/src/crypto/cms_verify.rs` (OID consts ~:76-79,
  `verify_chain` ~:818+, `leaf_eku` ~:977-1000 → deleted, tests)

- [ ] **Step 2.1: Write failing tests (RED)**

Add beside the existing chain tests. All call `verify_chain` directly with an
explicit `TrustAnchors` built from the chain's own root, so failures isolate
purpose rules (pre-fix they pass or fail for the wrong reasons — EKU-absent
passes today, CA/pathLen unchecked today ⇒ asserting the reason string is RED):

```rust
fn chain_with(root: &x509_cert::Certificate, leaf: &x509_cert::Certificate) -> ChainOutcome {
    verify_chain(
        &[root.clone(), leaf.clone()],
        leaf,
        &TrustAnchors::from_certificates(vec![root.clone()]),
    )
}

/// Builds `Profile::Leaf` signed by `root_signing`, optionally adding EKU.
fn build_leaf(
    cn: &str,
    issuer: &x509_cert::name::Name,
    root_signing: &rsa::pkcs1v15::SigningKey<Sha256>,
    eku: Option<x509_cert::ext::pkix::ExtendedKeyUsage>,
) -> (rsa::RsaPrivateKey, x509_cert::Certificate) {
    let key = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
    let pub_key = SubjectPublicKeyInfoOwned::from_der(
        key.to_public_key().to_public_key_der().unwrap().as_ref(),
    )
    .unwrap();
    let mut b = CertificateBuilder::new(
        Profile::Leaf {
            issuer: issuer.clone(),
            enable_key_agreement: false,
            enable_key_encipherment: false,
        },
        SerialNumber::from(3u32),
        Validity::from_now(Duration::from_secs(3600)).unwrap(),
        Name::from_str(cn).unwrap(),
        pub_key,
        root_signing,
    )
    .unwrap();
    if let Some(eku) = &eku {
        b.add_extension(eku).unwrap();
    }
    let cert = b.build::<rsa::pkcs1v15::Signature>().unwrap();
    (key, cert)
}

#[test]
fn leaf_without_eku_fails_purpose() {
    let (_k, root, root_signing) = build_rsa_root("CN=zsign purpose root");
    let (_lk, leaf) = build_leaf("CN=zsign no eku leaf", &root.tbs_certificate.subject, &root_signing, None);
    let outcome = chain_with(&root, &leaf);
    assert!(!outcome.ok);
    assert!(outcome.reason.as_deref().unwrap_or_default().contains("leaf lacks codeSigning EKU"));
}

#[test]
fn leaf_wrong_purpose_eku_fails() {
    let (_k, root, root_signing) = build_rsa_root("CN=zsign purpose root");
    let (_lk, leaf) = build_leaf(
        "CN=zsign tls leaf",
        &root.tbs_certificate.subject,
        &root_signing,
        Some(ExtendedKeyUsage(vec![ObjectIdentifier::new_unwrap(
            "1.3.6.1.5.5.7.3.1", // serverAuth — a purpose that is not codeSigning
        )])),
    );
    let outcome = chain_with(&root, &leaf);
    assert!(!outcome.ok);
    assert!(outcome.reason.as_deref().unwrap_or_default().contains("leaf EKU lacks codeSigning"));
}

#[test]
fn leaf_with_code_signing_eku_chains() {
    let (_k, root, root_signing) = build_rsa_root("CN=zsign purpose root");
    let (_lk, leaf) = build_leaf(
        "CN=zsign good leaf",
        &root.tbs_certificate.subject,
        &root_signing,
        Some(ExtendedKeyUsage(vec![OID_CODE_SIGNING])),
    );
    let outcome = chain_with(&root, &leaf);
    assert!(outcome.ok, "{:?}", outcome.reason);
    assert!(outcome.anchored);
}

#[test]
fn self_signed_leaf_still_needs_code_signing_eku() {
    // D5 has no self-signed carve-out: a self-signed signer is still the leaf
    // of its own chain and must pass the leaf purpose rules.
    let (_k, self_signed, _s) = build_rsa_root("CN=zsign bare self-signed");
    let outcome = verify_chain(
        &[self_signed.clone()],
        &self_signed,
        &TrustAnchors::from_certificates(vec![self_signed.clone()]),
    );
    assert!(!outcome.ok);
    assert!(outcome
        .reason
        .as_deref()
        .unwrap_or_default()
        .contains("leaf lacks codeSigning EKU"));
}
```

- [ ] **Step 2.2: Run to confirm RED**

Run: `cargo test -p zsign-core crypto::cms_verify`
Expected: `leaf_without_eku_fails_purpose` and
`self_signed_leaf_still_needs_code_signing_eku` FAIL — after Task 1 the EKU
rule is still "consulted only when present", so an EKU-less leaf chains
(`outcome.ok == true`) and the assertions are RED. `leaf_wrong_purpose_eku_fails`
PASSES already (the base containment check rejects a serverAuth-only EKU) —
it is a pin, not a witness; the two missing-EKU tests are the RED witnesses.
`leaf_with_code_signing_eku_chains` PASSES. Record which of these behaved as
predicted in the final report.

- [ ] **Step 2.3: Implement purpose enforcement**

Add OIDs beside the existing ones (~:76-79):

```rust
/// keyUsage extension: `2.5.29.15`
const OID_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.15");
/// basicConstraints extension: `2.5.29.19`
const OID_BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");
```

Strict extension accessor + the two rule functions (design §2.2 rules 1-3,
D5):

```rust
/// The DER value of extension `id`, or `None` when the extension is absent.
fn ext_value<'a>(cert: &'a x509_cert::Certificate, id: ObjectIdentifier) -> Option<&'a [u8]> {
    let exts = cert.tbs_certificate.extensions.as_ref()?;
    exts.iter().find(|e| e.extn_id == id).map(|e| e.extn_value.as_bytes())
}

/// End-entity purpose constraints; applied unconditionally to the leaf
/// (design D5 — a self-signed signer is still a leaf).
fn leaf_purpose_reason(leaf: &x509_cert::Certificate) -> Option<String> {
    use x509_cert::ext::pkix::{BasicConstraints, ExtendedKeyUsage, KeyUsage};
    let Some(eku_bytes) = ext_value(leaf, OID_EXT_KEY_USAGE) else {
        return Some("leaf lacks codeSigning EKU extension".into());
    };
    let Ok(eku) = ExtendedKeyUsage::from_der(eku_bytes) else {
        return Some("leaf EKU extension is malformed".into());
    };
    if !eku.0.contains(&OID_CODE_SIGNING) {
        return Some(format!("leaf EKU lacks codeSigning: {:?}", eku.0));
    }
    if let Some(ku_bytes) = ext_value(leaf, OID_KEY_USAGE) {
        let Ok(ku) = KeyUsage::from_der(ku_bytes) else {
            return Some("leaf keyUsage extension is malformed".into());
        };
        if !ku.digital_signature() {
            return Some("leaf keyUsage lacks digitalSignature".into());
        }
    }
    if let Some(bc_bytes) = ext_value(leaf, OID_BASIC_CONSTRAINTS) {
        let Ok(bc) = BasicConstraints::from_der(bc_bytes) else {
            return Some("leaf basicConstraints extension is malformed".into());
        };
        if bc.ca {
            return Some("leaf basicConstraints asserts CA".into());
        }
    }
    None
}

/// CA constraints for a certificate used to issue another. `cas_below` is the
/// number of CA certificates already chained below it (leaf excluded).
fn issuer_ca_reason(issuer: &x509_cert::Certificate, cas_below: usize) -> Option<String> {
    use x509_cert::ext::pkix::{BasicConstraints, KeyUsage};
    let Some(bc_bytes) = ext_value(issuer, OID_BASIC_CONSTRAINTS) else {
        return Some("issuer lacks basicConstraints extension".into());
    };
    let Ok(bc) = BasicConstraints::from_der(bc_bytes) else {
        return Some("issuer basicConstraints extension is malformed".into());
    };
    if !bc.ca {
        return Some("issuer basicConstraints is not CA".into());
    }
    if let Some(path_len) = bc.path_len_constraint {
        if cas_below > path_len as usize {
            return Some(format!(
                "issuer pathLen constraint violated ({cas_below} CA certificates below, pathLen {path_len})"
            ));
        }
    }
    if let Some(ku_bytes) = ext_value(issuer, OID_KEY_USAGE) {
        let Ok(ku) = KeyUsage::from_der(ku_bytes) else {
            return Some("issuer keyUsage extension is malformed".into());
        };
        if !ku.key_cert_sign() {
            return Some("issuer keyUsage lacks keyCertSign".into());
        }
    }
    None
}
```

Wire into `verify_chain`:

1. **Replace** the current `if let Some(eku) = leaf_eku(leaf) { … }` block
   (~:827-837) with the unconditional purpose check (before the leaf-validity
   check, keeping today's EKU-first precedence — design D5: no self-signed
   carve-out; the brief's item 2 has no exception):
   ```rust
   if let Some(reason) = leaf_purpose_reason(leaf) {
       return ChainOutcome { ok: false, anchored: false, subjects: names,
                             reason: Some(reason), warnings };
   }
   ```
2. In the `Some(p) if !std::ptr::eq(p, current)` branch, after the existing
   `in_validity(p, now)` check and before
   `verify_cert_signature(current, p)`:
   ```rust
   if let Some(reason) = issuer_ca_reason(p, chain.len().saturating_sub(1)) {
       return ChainOutcome { ok: false, anchored: false, subjects: names,
                             reason: Some(reason), warnings };
   }
   ```
   (`chain` holds `[leaf … current]` at that point; `chain.len() - 1`
   counts the CA certificates below `p`, excluding the leaf.)
3. **Delete** `leaf_eku` (~:977-1000) — superseded by `ext_value` +
   `leaf_purpose_reason`; migrate any other user (none — verify with
   `grep leaf_eku`).
4. Update `verify_chain`'s doc comment to mention purpose enforcement.

- [ ] **Step 2.4: Add remaining negatives + run GREEN**

Fixture helpers first (all typed — no hand-rolled DER):

```rust
/// Self-issued `Profile::SubCA` acting as the chain root (subject == issuer).
fn build_subca(
    cn: &str,
    path_len: Option<u8>,
) -> (x509_cert::Certificate, rsa::pkcs1v15::SigningKey<Sha256>) {
    let key = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
    let signing_key = rsa::pkcs1v15::SigningKey::<Sha256>::new(key.clone());
    let subject = Name::from_str(cn).unwrap();
    let pub_key = SubjectPublicKeyInfoOwned::from_der(
        key.to_public_key().to_public_key_der().unwrap().as_ref(),
    )
    .unwrap();
    let cert = CertificateBuilder::new(
        Profile::SubCA {
            issuer: subject.clone(),
            path_len_constraint: path_len,
        },
        SerialNumber::from(11u32),
        Validity::from_now(Duration::from_secs(3600)).unwrap(),
        subject,
        pub_key,
        &signing_key,
    )
    .unwrap()
    .build::<rsa::pkcs1v15::Signature>()
    .unwrap();
    (cert, signing_key)
}

/// `Profile::SubCA` issued by `issuer`, no pathLen constraint.
fn build_subca_issued_by(
    cn: &str,
    issuer: &x509_cert::name::Name,
    issuer_signing: &rsa::pkcs1v15::SigningKey<Sha256>,
) -> (x509_cert::Certificate, rsa::pkcs1v15::SigningKey<Sha256>) {
    let key = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
    let signing_key = rsa::pkcs1v15::SigningKey::<Sha256>::new(key.clone());
    let pub_key = SubjectPublicKeyInfoOwned::from_der(
        key.to_public_key().to_public_key_der().unwrap().as_ref(),
    )
    .unwrap();
    let cert = CertificateBuilder::new(
        Profile::SubCA {
            issuer: issuer.clone(),
            path_len_constraint: None,
        },
        SerialNumber::from(12u32),
        Validity::from_now(Duration::from_secs(3600)).unwrap(),
        Name::from_str(cn).unwrap(),
        pub_key,
        issuer_signing,
    )
    .unwrap()
    .build::<rsa::pkcs1v15::Signature>()
    .unwrap();
    (cert, signing_key)
}

/// Replaces (or appends) extension `id` on `cert` with `value`'s DER.
///
/// Mutation invalidates the mutated certificate's own signature; every
/// fixture below only exercises checks that run before any verification of
/// that certificate's signature (leaf purpose checks first, issuer CA checks
/// before the child-signature check).
fn replace_extension(
    cert: &mut x509_cert::Certificate,
    id: ObjectIdentifier,
    value: &impl der::Encode,
) {
    use der::Encode;
    let bytes = value.to_der().unwrap();
    // x509_cert::ext::Extensions is a plain Vec<Extension>.
    let exts = cert.tbs_certificate.extensions.get_or_insert_with(Vec::new);
    exts.retain(|e| e.extn_id != id);
    exts.push(x509_cert::ext::Extension {
        extn_id: id,
        critical: false,
        extn_value: der::asn1::OctetString::new(bytes).unwrap(),
    });
}
```

Negative tests (add `use x509_cert::ext::pkix::{BasicConstraints, KeyUsage, KeyUsages};`
to the test module imports):

```rust
#[test]
fn issuer_without_ca_bit_fails() {
    let (_k, root, root_signing) = build_rsa_root("CN=zsign seed root");
    // A Profile::Leaf certificate carries basicConstraints CA=false; using it
    // to issue another certificate must be rejected before any signature check.
    let (issuer_key, issuer_like) = build_leaf(
        "CN=zsign not a ca",
        &root.tbs_certificate.subject,
        &root_signing,
        None,
    );
    let issuer_signing = rsa::pkcs1v15::SigningKey::<Sha256>::new(issuer_key);
    let (_lk, leaf) = build_leaf(
        "CN=zsign child leaf",
        &issuer_like.tbs_certificate.subject,
        &issuer_signing,
        Some(ExtendedKeyUsage(vec![OID_CODE_SIGNING])),
    );
    let outcome = verify_chain(
        &[issuer_like.clone(), leaf.clone()],
        &leaf,
        &TrustAnchors::from_certificates(vec![issuer_like.clone()]),
    );
    assert!(!outcome.ok);
    assert!(outcome
        .reason
        .as_deref()
        .unwrap_or_default()
        .contains("issuer basicConstraints"));
}

#[test]
fn issuer_key_usage_without_key_cert_sign_fails() {
    let (_k, mut root, root_signing) = build_rsa_root("CN=zsign ku issuer root");
    // Root profile KU is keyCertSign|cRLSign; flip it to digitalSignature only.
    replace_extension(
        &mut root,
        OID_KEY_USAGE,
        &KeyUsage(KeyUsages::DigitalSignature.into()),
    );
    let (_lk, leaf) = build_leaf(
        "CN=zsign ku issuer leaf",
        &root.tbs_certificate.subject,
        &root_signing,
        Some(ExtendedKeyUsage(vec![OID_CODE_SIGNING])),
    );
    let outcome = chain_with(&root, &leaf);
    assert!(!outcome.ok);
    assert!(outcome
        .reason
        .as_deref()
        .unwrap_or_default()
        .contains("keyUsage lacks keyCertSign"));
}

#[test]
fn parent_path_len_violation_fails() {
    // subca: self-issued Profile::SubCA with pathLen 0, one CA (int) below it.
    let (subca, subca_signing) = build_subca("CN=zsign pathlen subca", Some(0));
    let (int, int_signing) = build_subca_issued_by(
        "CN=zsign pathlen int",
        &subca.tbs_certificate.subject,
        &subca_signing,
    );
    let (_lk, leaf) = build_leaf(
        "CN=zsign pathlen leaf",
        &int.tbs_certificate.subject,
        &int_signing,
        Some(ExtendedKeyUsage(vec![OID_CODE_SIGNING])),
    );
    let outcome = verify_chain(
        &[leaf.clone(), int.clone(), subca.clone()],
        &leaf,
        &TrustAnchors::from_certificates(vec![subca.clone()]),
    );
    assert!(!outcome.ok);
    assert!(outcome.reason.as_deref().unwrap_or_default().contains("pathLen"));
}

#[test]
fn leaf_without_digital_signature_fails() {
    let (_k, root, root_signing) = build_rsa_root("CN=zsign weak ku root");
    let (_lk, mut leaf) = build_leaf(
        "CN=zsign weak ku leaf",
        &root.tbs_certificate.subject,
        &root_signing,
        Some(ExtendedKeyUsage(vec![OID_CODE_SIGNING])),
    );
    replace_extension(
        &mut leaf,
        OID_KEY_USAGE,
        &KeyUsage(KeyUsages::KeyCertSign.into()),
    );
    let outcome = chain_with(&root, &leaf);
    assert!(!outcome.ok);
    assert!(outcome
        .reason
        .as_deref()
        .unwrap_or_default()
        .contains("leaf keyUsage lacks digitalSignature"));
}

#[test]
fn leaf_asserting_ca_fails() {
    let (_k, root, root_signing) = build_rsa_root("CN=zsign bc root");
    let (_lk, mut leaf) = build_leaf(
        "CN=zsign ca leaf",
        &root.tbs_certificate.subject,
        &root_signing,
        Some(ExtendedKeyUsage(vec![OID_CODE_SIGNING])),
    );
    replace_extension(
        &mut leaf,
        OID_BASIC_CONSTRAINTS,
        &BasicConstraints {
            ca: true,
            path_len_constraint: None,
        },
    );
    let outcome = chain_with(&root, &leaf);
    assert!(!outcome.ok);
    assert!(outcome
        .reason
        .as_deref()
        .unwrap_or_default()
        .contains("leaf basicConstraints asserts CA"));
}

#[test]
fn malformed_leaf_eku_fails() {
    let (_k, root, root_signing) = build_rsa_root("CN=zsign bad eku root");
    let (_lk, mut leaf) = build_leaf(
        "CN=zsign bad eku leaf",
        &root.tbs_certificate.subject,
        &root_signing,
        Some(ExtendedKeyUsage(vec![OID_CODE_SIGNING])),
    );
    // `replace_extension` stores the argument's DER inside `extn_value`, so
    // the extension value becomes the OCTET STRING TLV `04 02 05 00` — not a
    // DER SEQUENCE of OIDs, hence a malformed EKU.
    replace_extension(
        &mut leaf,
        OID_EXT_KEY_USAGE,
        &der::asn1::OctetString::new(b"\x05\x00").unwrap(),
    );
    let outcome = chain_with(&root, &leaf);
    assert!(!outcome.ok);
    assert!(outcome
        .reason
        .as_deref()
        .unwrap_or_default()
        .contains("leaf EKU extension is malformed"));
}
```

- [ ] **Step 2.5: Migrate self-signed fixtures to the leaf rules (D5)**

Between Step 2.3 and this step the self-signed-credential tests are
intentionally red: `round_trip_rsa_signs_and_verifies`,
`ber_indefinite_cms_verifies`, and `unanchored_structural_chain_is_invalid`
assert `valid`/`chain_ok` on a `Profile::Root` credential that now fails the
unconditional leaf rules. Two migrations make them green again:

**(a) `rsa_credentials` gains the leaf extensions.** `Profile::Root` emits no
EKU, `keyCertSign|cRLSign` keyUsage, and `CA=true` basicConstraints — this
credential is only ever a leaf + trust anchor in these tests (it never issues
a distinct certificate), so reshape it:

```rust
let mut builder = CertificateBuilder::new(
    Profile::Root,
    serial,
    validity,
    subject,
    pub_key,
    &signing_key,
)
.unwrap();
builder
    .add_extension(&ExtendedKeyUsage(vec![OID_CODE_SIGNING]))
    .unwrap();
let mut cert = builder.build::<rsa::pkcs1v15::Signature>().unwrap();
// Leaf rules: keyUsage must offer digitalSignature, basicConstraints must
// not assert CA (the profile defaults are CA-oriented).
replace_extension(
    &mut cert,
    OID_KEY_USAGE,
    &KeyUsage(KeyUsages::DigitalSignature.into()),
);
replace_extension(
    &mut cert,
    OID_BASIC_CONSTRAINTS,
    &BasicConstraints {
        ca: false,
        path_len_constraint: None,
    },
);
(
    SigningCredentials {
        certificate: cert,
        signing_key: SigningKeyType::Rsa(signing_key),
        cert_chain: vec![],
        team_id: None,
    },
    key,
)
```

(`replace_extension` and the `BasicConstraints`/`KeyUsage`/`KeyUsages`
imports come from Step 2.4; adapt the surrounding `rsa_credentials` body,
which currently builds `cert` inline in one expression.)

**(b) The SHA-1 chain fixture's leaf** chains a `Profile::Leaf` (no EKU)
under a root and must also gain a codeSigning EKU. Split its inline leaf
build into a mutable binding and add the extension before `.build()`:

```rust
let mut leaf_builder = CertificateBuilder::new(
    Profile::Leaf {
        issuer: root_subject.clone(),
        enable_key_agreement: false,
        enable_key_encipherment: false,
    },
    leaf_serial,
    leaf_validity,
    leaf_subject,
    leaf_pub,
    &root_signing,
)
.unwrap();
leaf_builder
    .add_extension(&ExtendedKeyUsage(vec![OID_CODE_SIGNING]))
    .unwrap();
let leaf = leaf_builder.build::<rsa::pkcs1v15::Signature>().unwrap();
```

(The current fixture inlines `CertificateBuilder::new(…).build::<…>()` and
binds its values directly — introduce `leaf_serial`/`leaf_validity`/
`leaf_subject`/`leaf_pub` bindings first if they are not already bound. The
same requirement applies to any other non-self-signed `Profile::Leaf` fixture
in this file.)

- [ ] **Step 2.6: Run GREEN**

Run: `cargo test -p zsign-core crypto::cms_verify`
Expected: all purpose tests GREEN — including the migrated SHA-1 fixture, the
upgraded self-signed credential tests (round trip, BER-indefinite,
unanchored-structural), and the SHA-256 pins.

- [ ] **Step 2.7: Run the lane gate + acceptance**

Run: `cargo test -p zsign-core crypto -- --skip test_ipa_signing_is_deterministic`
Expected: PASS. Acceptance: missing/malformed EKU, wrong-purpose EKU, weak
leaf KU/BC, non-CA issuer, pathLen violation, missing issuer KU — each fails
with its distinct reason; positive 2-cert chain anchors; the SHA-1 fixture
still chains (warnings assertions land in Task 5).
Commit (controller): `feat(zsign-core): enforce x.509 purpose constraints in chain verification`

---

### Task 3: Resolve SKI-only SignerInfo (queue item 3)

**Files:**
- Modify: `crates/zsign-core/src/crypto/cms_verify.rs` (OID consts ~:76-79,
  sid handling in `verify_signed_data` ~:521-554, signer-cert lookup ~:600-613,
  `ext_value` from Task 2, tests)

- [ ] **Step 3.1: Write failing tests (RED)**

New const beside the existing OIDs (used by both production code and tests):

```rust
/// SubjectKeyIdentifier extension: `2.5.29.14`
const OID_SUBJECT_KEY_IDENTIFIER: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.5.29.14");
```

Tests (they compile only after Step 3.2 adds `find_cert_by_ski` — new-function
TDD; the pure-function choice is design D9, sanctioned by the brief):

```rust
/// The SubjectKeyIdentifier key id of `cert` (Profile::Root fixtures always
/// carry the extension).
fn ski_of(cert: &x509_cert::Certificate) -> Vec<u8> {
    use der::Decode;
    let bytes = ext_value(cert, OID_SUBJECT_KEY_IDENTIFIER).expect("fixture must have SKI");
    // The extension value is the DER of SubjectKeyIdentifier, itself an
    // OCTET STRING over the raw key id.
    der::asn1::OctetString::from_der(bytes).unwrap().as_bytes().to_vec()
}

#[test]
fn ski_resolves_to_matching_certificate() {
    let (_ka, cert_a, _sa) = build_rsa_root("CN=zsign ski a");
    let (_kb, cert_b, _sb) = build_rsa_root("CN=zsign ski b");
    let key_id = ski_of(&cert_a);
    let found = find_cert_by_ski(&[cert_b.clone(), cert_a.clone()], &key_id)
        .expect("key id must resolve to its own certificate");
    assert_eq!(
        found.tbs_certificate.subject,
        cert_a.tbs_certificate.subject
    );
}

#[test]
fn ski_unknown_key_id_finds_nothing() {
    let (_ka, cert_a, _sa) = build_rsa_root("CN=zsign ski solo");
    let mut wrong = ski_of(&cert_a);
    let last = wrong.len() - 1;
    wrong[last] ^= 0xFF;
    assert!(find_cert_by_ski(&[cert_a.clone()], &wrong).is_none());
}

#[test]
fn ski_malformed_extension_is_skipped() {
    let (_ka, mut cert_a, _sa) = build_rsa_root("CN=zsign ski bad");
    // Extension value that is not an OCTET STRING: strict decode fails and
    // the certificate must be skipped, not panic.
    replace_extension(
        &mut cert_a,
        OID_SUBJECT_KEY_IDENTIFIER,
        &der::asn1::Null,
    );
    assert!(find_cert_by_ski(&[cert_a.clone()], b"any key id").is_none());
}
```

(`ext_value` and `replace_extension` come from Task 2; `der::asn1::OctetString`
and `der::asn1::Null` are in `der` 0.7. If `ext_value` is `pub(crate)`/private, the
test module accesses it via `use super::*` as with the other helpers.)

- [ ] **Step 3.2: Implement resolution + wiring**

1. Add the pure function next to `ext_value`:

```rust
/// Finds the embedded certificate whose SubjectKeyIdentifier equals `key_id`.
///
/// Malformed SKI extensions are skipped; `None` means the SignerInfo cannot
/// be resolved and must be rejected with a fatal report error.
fn find_cert_by_ski<'a>(
    certs: &'a [x509_cert::Certificate],
    key_id: &[u8],
) -> Option<&'a x509_cert::Certificate> {
    use der::Decode;
    certs.iter().find(|c| {
        let Some(bytes) = ext_value(c, OID_SUBJECT_KEY_IDENTIFIER) else {
            return false;
        };
        der::asn1::OctetString::from_der(bytes)
            .map(|ski| ski.as_bytes() == key_id)
            .unwrap_or(false)
    })
}
```

2. In `verify_signed_data`, restructure the sid block (~:521-554) — the
   issuerAndSerialNumber arm keeps its exact slice-capture logic; the SKI arm
   resolves instead of skipping:

```rust
// sid: issuerAndSerialNumber SEQUENCE or [0] subjectKeyIdentifier.
let sid = AnyRef::decode(&mut si_r)
    .map_err(|e| Error::Verification(format!("malformed signer id: {e}")))?;
let sid_body = sid.value();
let mut ski_cert: Option<&x509_cert::Certificate> = None;
let mut issuer_der: &[u8] = &[];
let mut serial_der: &[u8] = &[];
match sid.tag() {
    Tag::Sequence => {
        let mut sidr = reader(sid_body, "malformed issuerAndSerialNumber")?;
        let ib = usize::try_from(sidr.position()).unwrap_or(0);
        let _issuer_any = AnyRef::decode(&mut sidr)
            .map_err(|e| Error::Verification(format!("malformed issuer: {e}")))?;
        let ie = usize::try_from(sidr.position()).unwrap_or(0);
        let sb = usize::try_from(sidr.position()).unwrap_or(0);
        let _serial_any = AnyRef::decode(&mut sidr)
            .map_err(|e| Error::Verification(format!("malformed serial: {e}")))?;
        let se = usize::try_from(sidr.position()).unwrap_or(0);
        issuer_der = sid_body.get(ib..ie).unwrap_or_default();
        serial_der = sid_body.get(sb..se).unwrap_or_default();
    }
    // cms 0.2.3 encodes the SKI sid as an IMPLICIT *primitive* [0] OCTET
    // STRING (der-derive default); tolerate a constructed wrapper too — its
    // value is then the inner OCTET STRING TLV rather than the raw key id.
    Tag::ContextSpecific { number, constructed } if number == TagNumber::new(0) => {
        let key_id: Option<Vec<u8>> = if constructed {
            der::asn1::OctetString::from_der(sid_body)
                .ok()
                .map(|o| o.as_bytes().to_vec())
        } else {
            Some(sid_body.to_vec())
        };
        let resolved = key_id
            .as_deref()
            .and_then(|kid| find_cert_by_ski(&certs, kid));
        match resolved {
            Some(c) => ski_cert = Some(c),
            None => {
                // Never leave the report invalid-with-empty-errors: record why
                // this SignerInfo was unusable and move to the next one.
                if report.errors.is_empty() {
                    report.errors.push(
                        "signer subjectKeyIdentifier does not match any embedded certificate"
                            .into(),
                    );
                }
                continue;
            }
        }
    }
    other => {
        return Err(Error::Verification(format!(
            "unexpected signer id tag {other:?}"
        )));
    }
}
```

3. At the signing-certificate lookup (~:600-613), honour the pre-resolved SKI:

```rust
let signer_cert = match ski_cert {
    Some(c) => Some(c),
    None => certs.iter().find(|c| {
        c.tbs_certificate
            .issuer
            .to_der()
            .map(|d| d.as_slice() == issuer_der)
            .unwrap_or(false)
            && c.tbs_certificate
                .serial_number
                .to_der()
                .map(|d| d.as_slice() == serial_der)
                .unwrap_or(false)
    }),
};
```

4. Delete the obsolete warning
   `signer identified by subjectKeyIdentifier; skipping` (grep to confirm no
   other occurrence).

- [ ] **Step 3.3: Report-level fixtures (sid splice — RED first, GREEN after Step 3.2)**

The sid sits *outside* `signedAttrs`, so a fixture can swap it without
invalidating the signature; ancestor lengths are rebuilt bottom-up so every
DER length stays consistent. Add to the test module:

```rust
/// tag byte + minimal DER length (module's own `write_len`) + body.
fn der_tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    write_len(&mut out, body.len());
    out.extend_from_slice(body);
    out
}

/// Re-encodes the raw CMS with the first SignerInfo's sid swapped for
/// `new_sid` (a complete TLV). Assumes the single-SignerInfo output of
/// `sign_code_directory` (asserted below).
fn replace_first_sid(cms: &[u8], new_sid: &[u8]) -> Vec<u8> {
    // ContentInfo ::= SEQUENCE { contentType OID, [0] EXPLICIT SignedData }
    let ci = AnyRef::from_der(cms).unwrap();
    assert_eq!(ci.tag(), Tag::Sequence);
    let ci_body = ci.value();
    let mut ci_r = SliceReader::new(ci_body).unwrap();
    let _oid = AnyRef::decode(&mut ci_r).unwrap();
    let oid_end = usize::try_from(ci_r.position()).unwrap();
    let wrap = AnyRef::decode(&mut ci_r).unwrap();
    assert_eq!(wrap.tag(), TAG_CTX0);
    let wrap_tlv = &ci_body[oid_end..]; // [0] wrapper TLV (last field)
    // [0] is EXPLICIT: its value carries the full SignedData TLV (`30 …`),
    // so the SEQUENCE must be decoded before its fields can be iterated.
    let sd_tlv = wrap.value();
    let sd_seq = AnyRef::from_der(sd_tlv).expect("SignedData SEQUENCE inside [0]");
    assert_eq!(sd_seq.tag(), Tag::Sequence);
    let sd_body_src = sd_seq.value();

    // SignedData fields; signerInfos SET is the LAST one (digestAlgorithms is
    // also a SET — select by position, never by tag, or it gets dropped).
    let mut sd_r = SliceReader::new(sd_body_src).unwrap();
    let mut fields: Vec<&[u8]> = Vec::new(); // version, digestAlgs, encap, certs, set
    while !sd_r.is_finished() {
        let start = usize::try_from(sd_r.position()).unwrap();
        let _field = AnyRef::decode(&mut sd_r).unwrap();
        let end = usize::try_from(sd_r.position()).unwrap();
        fields.push(&sd_body_src[start..end]);
    }
    let set_tlv = fields.pop().expect("SignedData fields required");
    assert_eq!(
        AnyRef::from_der(set_tlv).unwrap().tag(),
        Tag::Set,
        "signerInfos SET must be the last SignedData field"
    );
    let fixed: Vec<&[u8]> = fields;

    // SignerInfo: replace the sid (the field after version).
    let set_any = AnyRef::from_der(set_tlv).unwrap();
    let si_list = set_any.value();
    let mut set_r = SliceReader::new(si_list).unwrap();
    let si_any = AnyRef::decode(&mut set_r).unwrap();
    assert_eq!(si_any.tag(), Tag::Sequence);
    assert!(set_r.is_finished(), "fixture assumes a single SignerInfo");
    let si_body = si_any.value();
    // RFC 5652 §5.3: a subjectKeyIdentifier sid requires SignerInfo version 3,
    // and one v3 SignerInfo forces SignedData version 3. Both are `INTEGER 1`
    // today — bump each with a one-byte patch so lengths never change.
    assert_eq!(&si_body[..3], &[0x02, 0x01, 0x01], "SignerInfo.version assumed INTEGER 1");
    let mut si_body = si_body.to_vec();
    si_body[2] = 0x03;
    let mut si_r = SliceReader::new(&si_body).unwrap();
    let _version = AnyRef::decode(&mut si_r).unwrap();
    let sid_start = usize::try_from(si_r.position()).unwrap();
    let _sid = AnyRef::decode(&mut si_r).unwrap();
    let sid_end = usize::try_from(si_r.position()).unwrap();
    let mut new_si_body = Vec::new();
    new_si_body.extend_from_slice(&si_body[..sid_start]);
    new_si_body.extend_from_slice(new_sid);
    new_si_body.extend_from_slice(&si_body[sid_end..]);

    // Rebuild bottom-up: SignerInfo → SET → SignedData → [0] → ContentInfo.
    let new_si = der_tlv(si_list[0], &new_si_body);
    let new_set = der_tlv(set_tlv[0], &new_si);
    let mut sd_body = Vec::new();
    for (i, f) in fixed.iter().enumerate() {
        if i == 0 {
            assert_eq!(*f, &[0x02, 0x01, 0x01], "SignedData.version assumed INTEGER 1");
            sd_body.extend_from_slice(&[0x02, 0x01, 0x03]);
        } else {
            sd_body.extend_from_slice(f);
        }
    }
    sd_body.extend_from_slice(&new_set);
    let new_sd = der_tlv(sd_tlv[0], &sd_body);
    let new_wrap = der_tlv(wrap_tlv[0], &new_sd);
    let mut ci2 = Vec::new();
    ci2.extend_from_slice(&ci_body[..oid_end]);
    ci2.extend_from_slice(&new_wrap);
    der_tlv(cms[0], &ci2)
}

#[test]
fn ski_signer_resolves_end_to_end() {
    let (creds, _k) = rsa_credentials();
    let content: &[u8] = b"the code directory bytes";
    let cd_sha256: [u8; 32] = Sha256::digest(content).into();
    let cms = sign_code_directory(content, &creds, None, &cd_sha256).unwrap();

    let key_id = ski_of(&creds.certificate);
    let mut sid = vec![0x80u8, key_id.len() as u8];
    sid.extend_from_slice(&key_id);
    let spliced = replace_first_sid(&cms, &sid);

    let report = verify_code_signature_with_anchors(
        &wrap(&spliced),
        content,
        None,
        &cd_sha256,
        &anchors_for(&creds),
    )
    .unwrap();
    assert!(report.valid, "SKI signer must resolve: {:?}", report.errors);
    assert_eq!(report.signer_subject.as_deref(), Some("CN=zsign verify test"));
}

#[test]
fn ski_signer_with_unknown_key_id_is_fatal() {
    let (creds, _k) = rsa_credentials();
    let content: &[u8] = b"the code directory bytes";
    let cd_sha256: [u8; 32] = Sha256::digest(content).into();
    let cms = sign_code_directory(content, &creds, None, &cd_sha256).unwrap();

    let real = ski_of(&creds.certificate);
    let wrong = vec![0x5Au8; real.len()];
    let mut sid = vec![0x80u8, wrong.len() as u8];
    sid.extend_from_slice(&wrong);
    let spliced = replace_first_sid(&cms, &sid);

    let report = verify_code_signature_with_anchors(
        &wrap(&spliced),
        content,
        None,
        &cd_sha256,
        &anchors_for(&creds),
    )
    .unwrap();
    assert!(!report.valid);
    assert!(!report.errors.is_empty());
    assert!(report
        .errors
        .iter()
        .any(|e| e.contains("subjectKeyIdentifier")));
}
```

Write the two tests first and run them: `ski_signer_resolves_end_to_end` is
RED on Step 3.1/3.2 state only if the wiring is wrong — on the *base* code the
splice lands in the unexpected-tag/`warning+continue` path, so it fails there
(combine Steps 3.1-3.3 in one red/green cycle: tests first, wiring second).

- [ ] **Step 3.4: Run GREEN + acceptance**

Run: `cargo test -p zsign-core crypto -- --skip test_ipa_signing_is_deterministic`
Expected: PASS. Acceptance: a sole SKI SignerInfo whose key id matches no
embedded certificate yields `valid == false` with
`signer subjectKeyIdentifier does not match any embedded certificate` in
`errors` (structurally guaranteed — push precedes `continue`, and no path
returns `valid = false` with an empty `errors`); a conformant **primitive**
`[0]` sid resolves end-to-end (`valid == true`, `signer_subject` set);
resolution unit tests green; multi-signer best-signer-wins behaviour
unchanged.
Commit (controller): `fix(zsign-core): resolve subjectkeyidentifier signers against embedded certificates`

---

### Task 4: Require signed contentType (queue item 4)

**Files:**
- Modify: `crates/zsign-core/src/crypto/cms_verify.rs` (OID_CONTENT_TYPE
  ~:46-48, `SignedAttrs` ~:307-313, `parse_signed_attrs` ~:316-367,
  `verify_signed_data` ~:380-697, tests)

- [ ] **Step 4.1: Write failing test (RED)**

```rust
#[test]
fn signed_content_type_must_be_single_id_data() {
    assert!(content_type_reason(0, &[]).unwrap_or_default().contains("missing"));
    assert_eq!(content_type_reason(1, &[OID_ID_DATA]), None);
    assert!(content_type_reason(2, &[OID_ID_DATA, OID_ID_DATA])
        .unwrap_or_default()
        .contains("duplicate"));
    let other = ObjectIdentifier::new_unwrap("1.2.840.113635.100.9.1");
    assert!(content_type_reason(1, &[other])
        .unwrap_or_default()
        .contains("expected id-data"));
    // One occurrence whose value did not decode: malformed, not "missing".
    assert!(content_type_reason(1, &[]).unwrap_or_default().contains("malformed"));
}
```

Run: `cargo test -p zsign-core crypto::cms_verify` — RED (no such function).

- [ ] **Step 4.2: Implement**

1. Remove `#[allow(dead_code)]` from `OID_CONTENT_TYPE` (~:47).
2. `SignedAttrs` gains two fields — `content_type_count: usize` and
   `content_types: Vec<ObjectIdentifier>` (initialised `0` / empty in
   `parse_signed_attrs`). In the attribute loop, insert **immediately after
   the `values.tag() != Tag::Set` check and `let vbytes = values.value();`,
   before the generic first-value decode** (which skips malformed values with
   `continue` and only ever reads one value per Attribute):

```rust
if oid == OID_CONTENT_TYPE {
    // RFC 5652 §5.6: exactly one value. Count every value — including
    // undecodable ones — so an extra or malformed value can never evade
    // duplicate detection.
    let mut vr = reader(vbytes, "malformed contentType value")?;
    while !vr.is_finished() {
        content_type_count += 1;
        match ObjectIdentifier::decode(&mut vr) {
            Ok(ct) => content_types.push(ct),
            Err(_) => break,
        }
    }
    continue;
}
```

   (The generic decode below keeps handling messageDigest / CDHash unchanged.)

3. The decision function:

```rust
/// RFC 5652 §5.6: exactly one signed `contentType` value, equal to id-data —
/// which also pins it to `encapContentInfo`'s eContentType (id-data is
/// required separately below). `count` is every value seen, `decoded` the
/// subset that decoded as OIDs.
fn content_type_reason(count: usize, decoded: &[ObjectIdentifier]) -> Option<String> {
    match count {
        0 => Some("signed contentType attribute missing".into()),
        1 => match decoded.first() {
            Some(only) if *only == OID_ID_DATA => None,
            Some(only) => Some(format!(
                "signed contentType attribute is {only} (expected id-data)"
            )),
            None => Some("signed contentType attribute is malformed".into()),
        },
        _ => Some("duplicate signed contentType attribute".into()),
    }
}
```

4. Global-error tier (eContentType is SignedData-level, design D10 — and
   **every** `Ok(report)` exit must re-attach it, or an early return inside
   the SignerInfo loop silently drops the diagnostic):
   - After `let mut report = CmsVerifyReport::default();` add
     `let mut global_errors: Vec<String> = Vec::new();`.
   - Add the seal helper beside `content_type_reason`:
     ```rust
     /// Attaches SignedData-level errors to the report on every `Ok` exit so
     /// an early return inside the SignerInfo loop can never drop them.
     fn seal(
         mut report: CmsVerifyReport,
         mut global_errors: Vec<String>,
     ) -> Result<CmsVerifyReport> {
         if !global_errors.is_empty() {
             global_errors.append(&mut report.errors);
             report.errors = global_errors;
         }
         Ok(report)
     }
     ```
   - Replace the `unusual eContentType` warning (~:440-443) with:
     ```rust
     if econtent_type != OID_ID_DATA {
         global_errors.push(format!(
             "encapContentInfo eContentType {econtent_type} (expected id-data)"
         ));
     }
     ```
   - The `no SignerInfo present` early return (~:511-512) becomes:
     ```rust
     if signer_infos_raw.is_empty() {
         report.errors.push("no SignerInfo present".into());
         return seal(report, global_errors);
     }
     ```
   - The other two in-loop bare returns — unsupported digest algorithm
     (~:569) and signing certificate not found (~:618) — keep their pushes
     and become `return seal(report, global_errors);`.
   - In the per-signer error-accumulation block (after the CDHash pushes, ~:661-680):
     ```rust
     if let Some(reason) = content_type_reason(attrs.content_type_count, &attrs.content_types) {
         errors.push(reason);
     }
     ```
   - The clean-signer gate (~:682-686) becomes:
     ```rust
     if errors.is_empty() {
         if global_errors.is_empty() {
             report.valid = true;
             report.errors.clear();
         }
         // No-op when globals are empty; otherwise the structural errors
         // land first and keep `valid` false.
         return seal(report, global_errors);
     }
     ```
     (The `if report.errors.is_empty() { report.errors = errors; }` store
     below stays unchanged.)
   - The final `Ok(report)` (~:692) becomes `seal(report, global_errors)`.

- [ ] **Step 4.3: Parser-level and report-level fixtures**

The signed `contentType` attribute lives inside `signedAttrs`, so unlike the
sid it cannot be spliced without breaking the signature — coverage splits
honestly: the *real parser* gets hand-built DER, and the *global-error gate*
gets a report-level fixture (its field is unsigned).

```rust
/// An Attribute SEQUENCE { OID, SET { value } } for parser-level fixtures.
fn attr_tlv(oid: ObjectIdentifier, value_tlv: &[u8]) -> Vec<u8> {
    use der::Encode;
    let mut body = oid.to_der().unwrap();
    body.extend_from_slice(&der_tlv(0x31, value_tlv)); // SET OF
    der_tlv(0x30, &body)
}

#[test]
fn duplicate_signed_content_type_attributes_are_counted() {
    use der::Encode;
    let id_data = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1")
        .to_der()
        .unwrap();
    let mut body = attr_tlv(OID_CONTENT_TYPE, &id_data);
    body.extend_from_slice(&attr_tlv(OID_CONTENT_TYPE, &id_data));
    let attrs = parse_signed_attrs(&body).unwrap();
    assert_eq!(attrs.content_type_count, 2);
    let reason = content_type_reason(attrs.content_type_count, &attrs.content_types)
        .unwrap_or_default();
    assert!(reason.contains("duplicate"), "{reason}");
}

#[test]
fn extra_malformed_content_type_value_is_counted() {
    use der::Encode;
    let mut value = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1")
        .to_der()
        .unwrap();
    value.extend_from_slice(&[0x05, 0x00]); // malformed second value (NULL)
    let body = attr_tlv(OID_CONTENT_TYPE, &value);
    let attrs = parse_signed_attrs(&body).unwrap();
    // A valid id-data first value plus a malformed extra must never read as
    // "exactly one".
    assert_eq!(attrs.content_type_count, 2);
    let reason = content_type_reason(attrs.content_type_count, &attrs.content_types)
        .unwrap_or_default();
    assert!(reason.contains("duplicate"), "{reason}");
}

#[test]
fn global_econtent_type_error_beats_clean_signer() {
    let (creds, _k) = rsa_credentials();
    let content: &[u8] = b"the code directory bytes";
    let cd_sha256: [u8; 32] = Sha256::digest(content).into();
    let cms = sign_code_directory(content, &creds, None, &cd_sha256).unwrap();

    // encapContentInfo.eContentType is the first id-data OID TLV in the CMS:
    // everything preceding it (ContentInfo's signedData OID `…1.7.2`, the
    // version INTEGER, digestAlgorithms' SHA-256 OID) shares no bytes with
    // the 11-byte pattern — which includes the OID's own `06 09` header, so
    // a mid-TLV match cannot start — while the signedAttrs copy of id-data
    // and the CDHash payload live much later. Patch the trailing arc 1 → 2:
    // id-data becomes id-signedData, same DER length, and the field is
    // outside signedAttrs, so every per-signer check stays green. (A wrong
    // landing would fail the `encapContentInfo` assertion below loudly.)
    let id_data: &[u8] = &[0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01];
    let pos = cms
        .windows(id_data.len())
        .position(|w| w == id_data)
        .expect("id-data OID must be present");
    let mut patched = cms.clone();
    patched[pos + id_data.len() - 1] = 0x02;

    let report = verify_code_signature_with_anchors(
        &wrap(&patched),
        content,
        None,
        &cd_sha256,
        &anchors_for(&creds),
    )
    .unwrap();
    assert!(report.signature_ok, "unsigned field must not break the signature");
    assert!(!report.valid, "global error must block a clean signer");
    assert_eq!(
        report.errors.len(),
        1,
        "clean signer must not clear or mask the global error: {:?}",
        report.errors
    );
    assert!(report.errors[0].contains("encapContentInfo eContentType"));
}
```

(`der_tlv` comes from Task 3's test module — same `tests` module, Task 3 runs
first.)

- [ ] **Step 4.4: Run GREEN + acceptance**

Run: `cargo test -p zsign-core crypto -- --skip test_ipa_signing_is_deterministic`
Expected: PASS — the migrated round trip proves the signer emits exactly one
id-data `contentType` (cms 0.2.3 builder evidence, design §2.5). Acceptance:
missing/duplicate/wrong-OID/malformed signed contentType each rejected with
its own message (parser-level fixtures drive the real `parse_signed_attrs`);
the extra-malformed-value evasion from the review is closed; `eContentType !=
id-data` is a global error that a clean SignerInfo cannot clear
(`global_econtent_type_error_beats_clean_signer`: `valid == false`, exactly
one error, `signature_ok == true`).
Commit (controller): `feat(zsign-core): require signed contenttype attribute in cms verification`

---

### Task 5: Warn on SHA-1 certificate signatures (queue item 5)

**Files:**
- Modify: `crates/zsign-core/src/crypto/cms_verify.rs` (`verify_chain`, tests)

- [ ] **Step 5.1: Write failing assertions (RED)**

Extend the migrated `chain_accepts_sha1_signed_intermediate` (Task 1) with:

```rust
assert!(
    outcome.warnings.iter().any(|w| w.contains("SHA-1")),
    "SHA-1 chain must warn: {:?}",
    outcome.warnings
);
```

and pin the quiet case in `leaf_with_code_signing_eku_chains` (Task 2):

```rust
assert!(outcome.warnings.is_empty(), "SHA-256 chain must not warn: {:?}", outcome.warnings);
```

Run: `cargo test -p zsign-core crypto::cms_verify` — the SHA-1 assertion is
RED (warnings are still always empty); the quiet pin is GREEN.

- [ ] **Step 5.2: Implement**

```rust
/// Notes that a certificate's own signature uses SHA-1 (accepted, but
/// recorded so consumers can surface weak-crypto usage).
fn sha1_warning(child: &x509_cert::Certificate) -> Option<String> {
    (child.signature_algorithm.oid == OID_SHA1_WITH_RSA).then(|| {
        format!(
            "certificate \"{}\" is signed with SHA-1",
            child.tbs_certificate.subject
        )
    })
}
```

Push at every site inside `verify_chain` where a certificate signature is
verified, immediately before the `verify_cert_signature` call:
1. the climb branch — `if let Some(w) = sha1_warning(current) { warnings.push(w); }`
   (verifies `current`'s signature at this depth);
2. the self-signed terminus branch (self-signature of `current`);
3. the runs-out trust-anchor branch (signature of `current` against the anchor).

The warning rides out on every `ChainOutcome` return path (the `warnings`
vec is threaded through Task 1). Duplicate suppression is solely the report
append added in Step 1.5 — make no uniqueness guarantee about a single walk
(no visited-set protects pathological cyclic subject-name chains, and a
multi-signer CMS repeats the walk once per SignerInfo).

- [ ] **Step 5.3: Run GREEN + acceptance**

Run: `cargo test -p zsign-core crypto -- --skip test_ipa_signing_is_deterministic`
Expected: PASS — SHA-1 chains still verify (anchored under an injected root)
but report warnings; SHA-256 chains stay silent.
Commit (controller): `feat(zsign-core): report sha-1 certificate signatures as verification warnings`

---

### Task 6: Final verification and handover evidence (no commit)

**Files:** none — evidence collection only.

- [ ] **Step 6.1: Lane gate (verbatim capture)**

Run: `cargo test -p zsign-core crypto -- --skip test_ipa_signing_is_deterministic`
Expected: all green. Save the output for the final report.

- [ ] **Step 6.2: Workspace suite (verbatim capture)**

Run: `cargo test --workspace -- --skip test_ipa_signing_is_deterministic`
Expected: exactly the four cross-lane failures listed in design §6
(`macho/verify.rs::verify_signed_binary_round_trip`,
`macho/verify.rs::special_slots_bind_info_and_resources`,
`zsign/src/verify.rs::signed_bundle_verifies`,
`zsign/src/verify.rs::bare_macho_verifies`) and nothing else.
Any additional failure: diagnose with the systematic-debugging skill before
proceeding; report it — do NOT edit deferred files.

- [ ] **Step 6.3: Scope audit**

Run: `git status --short` and `git diff --stat ee42c12..HEAD`
Expected: only `crates/zsign-core/src/crypto/cms_verify.rs` and the two
force-added docs files (`docs/superpowers/specs/…-design.md`,
`docs/superpowers/plans/…-cms-trust-anchor.md`) appear. `cert.rs`,
`assets.rs`, `.gitignore`, and every deferred file untouched.

- [ ] **Step 6.4: Assemble final report**

Commit list (5 code + 1 docs commit), verbatim gate/workspace outputs, the
design-vs-actual deviations, and the cross-lane handover note (the
`TrustAnchors` / `verify_code_signature_with_anchors` contract for lanes
24/26 plus the four-test failure table). Do not merge; do not push.
