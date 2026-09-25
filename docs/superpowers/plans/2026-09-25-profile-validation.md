# ZSN-3 Provisioning-Profile Validation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development (recommended) with dispatching-parallel-agents for independent tasks to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Verify the CMS envelope of `.mobileprovision` profiles before their
entitlements are used, and validate profile fields (expiry, team, App ID, devices)
through a new `validate_and_extract_profile` API — while keeping
`extract_entitlements_from_profile` byte-for-byte compatible for existing consumers.

**Architecture:** One generic attached-content mode inside
`crypto/cms_verify.rs`'s existing `verify_signed_data` core (mode enum + injected
`now` + leaf-purpose policy), consumed by a new `provisioning.rs` model/validation
layer. Tests sign synthetic profiles in-process with a test CA via a
`#[cfg(test)]` helper in `crypto/cms.rs`.

**Tech Stack:** Rust workspace; `der`/`cms`/`x509-cert`/`rsa`/`plist`/`time`
(all already declared in `crates/zsign-core/Cargo.toml`; `time` gains
`parsing`/`formatting` features in Task 3).

**Ground rules (lane brief):** never merge/push; no fmt/clippy/hk mid-flight; no
stubs/TODOs; inline `#[cfg(test)] mod tests`; `TMPDIR=$PWD/.tmptmp` (mkdir first)
for every cargo command; skip `test_ipa_signing_is_deterministic` (ZSN-15
pre-existing); ticket ID in commit subjects only, never in code comments.

---

### Task 1: Queue item 1 (part A) — thread verification time and signer purpose through the chain walk

**Queue-order note:** the brief's queue is delivered as Task 1+2 (item 1: profile
CMS verification), Task 3 (items 2+3: model + validation + retained surface),
Task 4 (item 4: the wasm clock contract — `resolve_now`, wasm32 behavior, and the
wall-clock-independence tests), Task 5 (gates). The `now`/purpose threading in
this task is item 1's substrate — the profile envelope must verify certificate
validity at the caller's instant — not item 4's delivery; item 4's public
artifacts land after items 2-3, in queue order.

**Files:**
- Modify: `crates/zsign-core/src/crypto/cms_verify.rs`
  (`verify_signed_data` :523, `verify_chain` :1028, `leaf_purpose_reason` :1286,
  `time_now` :1354, public entries :275/:295, `mod tests` :1371)
- Test: inline `mod tests` in the same file

**Intent:** `verify_chain` reads the wall clock internally (`let now =
time_now();` at :1036) and unconditionally applies the codeSigning-EKU leaf rule
(`leaf_purpose_reason` at :1038). Nothing can validate a certificate against an
arbitrary instant, and a profile leaf (which carries no EKU — see design §2.5)
can never pass. This task makes both injectable; observable behavior of the two
existing public entries must not change.

- [ ] **Step 1: Write the failing tests** — append to `mod tests` in
`crates/zsign-core/src/crypto/cms_verify.rs` (the module already has
`use super::*` plus `Name`/`CertificateBuilder`/`Profile`/`SerialNumber`/
`Validity`/`SubjectPublicKeyInfoOwned`/`ExtendedKeyUsage`/`Duration` imported):

```rust
    // ---- injected clock + signer purpose ----

    const T_2025: i64 = 1_735_689_600; // 2025-01-01T00:00:00Z
    const T_2026_START: i64 = 1_767_225_600; // 2026-01-01T00:00:00Z
    const T_2026_APR: i64 = 1_775_001_600; // 2026-04-01T00:00:00Z
    const T_2026_JUL: i64 = 1_782_864_000; // 2026-07-01T00:00:00Z
    const T_2027: i64 = 1_798_761_600; // 2027-01-01T00:00:00Z
    const T_2030: i64 = 1_893_456_000; // 2030-01-01T00:00:00Z

    /// Root valid 2020-01-01..2030-01-01 (covers every fixed instant below);
    /// leaf valid exactly [not_before, not_after].
    fn fixed_validity_chain(
        not_before_unix: u64,
        not_after_unix: u64,
        eku: Option<ExtendedKeyUsage>,
    ) -> (
        x509_cert::Certificate,
        x509_cert::Certificate,
        rsa::RsaPrivateKey,
        TrustAnchors,
    ) {
        let to_time = |unix: u64| {
            x509_cert::time::Time::try_from(
                std::time::UNIX_EPOCH + Duration::from_secs(unix),
            )
            .unwrap()
        };
        let root_key = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
        let root_signing = rsa::pkcs1v15::SigningKey::<Sha256>::new(root_key.clone());
        let root_name = Name::from_str("CN=zsn3 fixed-time root").unwrap();
        let root_pub = SubjectPublicKeyInfoOwned::from_der(
            root_key.to_public_key().to_public_key_der().unwrap().as_ref(),
        )
        .unwrap();
        let root_cert = CertificateBuilder::new(
            Profile::Root,
            SerialNumber::from(21u32),
            Validity {
                not_before: to_time(1_577_836_800),
                not_after: to_time(T_2030 as u64),
            },
            root_name.clone(),
            root_pub,
            &root_signing,
        )
        .unwrap()
        .build::<rsa::pkcs1v15::Signature>()
        .unwrap();

        let leaf_key = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
        let leaf_signing = rsa::pkcs1v15::SigningKey::<Sha256>::new(leaf_key.clone());
        let leaf_name = Name::from_str("CN=zsn3 fixed-time leaf").unwrap();
        let leaf_pub = SubjectPublicKeyInfoOwned::from_der(
            leaf_key.to_public_key().to_public_key_der().unwrap().as_ref(),
        )
        .unwrap();
        let mut leaf_builder = CertificateBuilder::new(
            Profile::Leaf {
                issuer: root_name.clone(),
                enable_key_agreement: false,
                enable_key_encipherment: false,
            },
            SerialNumber::from(22u32),
            Validity {
                not_before: to_time(not_before_unix),
                not_after: to_time(not_after_unix),
            },
            leaf_name,
            leaf_pub,
            &root_signing,
        )
        .unwrap();
        if let Some(eku) = &eku {
            leaf_builder.add_extension(eku).unwrap();
        }
        let leaf_cert = leaf_builder.build::<rsa::pkcs1v15::Signature>().unwrap();

        let anchors = TrustAnchors::from_certificates(vec![root_cert.clone()]);
        (root_cert, leaf_cert, leaf_key, anchors)
    }

    fn at(unix: i64) -> time::OffsetDateTime {
        time::OffsetDateTime::from_unix_timestamp(unix).unwrap()
    }

    #[test]
    fn chain_validity_follows_injected_now_not_wall_clock() {
        let (root, leaf, _leaf_key, anchors) = fixed_validity_chain(
            T_2026_START as u64,
            T_2026_JUL as u64,
            Some(ExtendedKeyUsage(vec![OID_CODE_SIGNING])),
        );
        let certs = vec![root, leaf.clone()];

        let inside =
            verify_chain(&certs, &leaf, &anchors, at(T_2026_APR), SignerPurpose::CodeSigning);
        assert!(inside.ok, "inside window must pass: {:?}", inside.reason);

        let expired =
            verify_chain(&certs, &leaf, &anchors, at(T_2027), SignerPurpose::CodeSigning);
        assert!(!expired.ok);
        assert!(
            expired.reason.as_deref().unwrap_or("").contains("outside validity"),
            "reason: {:?}",
            expired.reason
        );

        let early =
            verify_chain(&certs, &leaf, &anchors, at(T_2025), SignerPurpose::CodeSigning);
        assert!(!early.ok);
        assert!(
            early.reason.as_deref().unwrap_or("").contains("outside validity"),
            "reason: {:?}",
            early.reason
        );
    }

    #[test]
    fn profile_purpose_accepts_eku_less_leaf_and_code_purpose_rejects_it() {
        let (root, leaf, _leaf_key, anchors) =
            fixed_validity_chain(T_2026_START as u64, T_2030 as u64, None);
        let certs = vec![root, leaf.clone()];
        let now = at(T_2026_APR);

        let profile = verify_chain(
            &certs,
            &leaf,
            &anchors,
            now,
            SignerPurpose::ProvisioningProfile,
        );
        assert!(profile.ok, "profile purpose must not require EKU: {:?}", profile.reason);
        assert!(profile.anchored);

        let code =
            verify_chain(&certs, &leaf, &anchors, now, SignerPurpose::CodeSigning);
        assert!(!code.ok);
        assert!(
            code.reason.as_deref().unwrap_or("").contains("codeSigning EKU"),
            "reason: {:?}",
            code.reason
        );
    }

    #[test]
    fn profile_purpose_still_enforces_key_usage_and_ca_flag() {
        let (root, mut leaf, _leaf_key, anchors) =
            fixed_validity_chain(T_2026_START as u64, T_2030 as u64, None);
        replace_extension(
            &mut leaf,
            OID_BASIC_CONSTRAINTS,
            &BasicConstraints { ca: true, path_len_constraint: None },
        );
        let certs = vec![root, leaf.clone()];

        let outcome = verify_chain(
            &certs,
            &leaf,
            &anchors,
            at(T_2026_APR),
            SignerPurpose::ProvisioningProfile,
        );
        assert!(!outcome.ok);
        assert!(
            outcome
                .reason
                .as_deref()
                .unwrap_or("")
                .contains("basicConstraints asserts CA"),
            "reason: {:?}",
            outcome.reason
        );
    }
```

- [ ] **Step 2: Run to confirm red**

Run: `mkdir -p .tmptmp && TMPDIR=$PWD/.tmptmp cargo test -p zsign-core chain_validity_follows_injected_now`
Expected: FAIL to compile — `verify_chain` takes 3 args and `SignerPurpose`
does not exist.

- [ ] **Step 3: Implement** in `crates/zsign-core/src/crypto/cms_verify.rs`

1. Add near `ChainOutcome` (:1001):

```rust
/// Which end-entity policy applies to the signer certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SignerPurpose {
    /// Mach-O code signatures: the leaf must assert the codeSigning EKU.
    CodeSigning,
    /// Provisioning-profile CMS: Apple's profile-signing leaves carry no EKU
    /// extension, so RFC 5280 4.2.1.12 imposes no purpose; only the shared
    /// keyUsage/basicConstraints rules apply.
    ProvisioningProfile,
}
```

2. Change `verify_chain` (:1028) signature to:

```rust
fn verify_chain(
    certs: &[x509_cert::Certificate],
    leaf: &x509_cert::Certificate,
    anchors: &TrustAnchors,
    now: time::OffsetDateTime,
    purpose: SignerPurpose,
) -> ChainOutcome {
```

   Delete `let now = time_now();` (:1036). Replace
   `if let Some(reason) = leaf_purpose_reason(leaf) {` (:1038) with:

```rust
    let purpose_reason = match purpose {
        SignerPurpose::CodeSigning => leaf_purpose_reason(leaf),
        SignerPurpose::ProvisioningProfile => leaf_ku_bc_reason(leaf),
    };
    if let Some(reason) = purpose_reason {
```

3. Split `leaf_purpose_reason` (:1286): keep its EKU block — the
   `ext_value(leaf, OID_EXT_KEY_USAGE)` / `ExtendedKeyUsage::from_der` /
   `eku.0.contains(&OID_CODE_SIGNING)` checks with their existing messages —
   and move the existing keyUsage + basicConstraints checks verbatim
   (currently :1297-1312) into a new helper, ending `leaf_purpose_reason` with
   `leaf_ku_bc_reason(leaf)`. Concretely, after the split:

```rust
/// End-entity purpose constraints; applied unconditionally to the leaf.
fn leaf_purpose_reason(leaf: &x509_cert::Certificate) -> Option<String> {
    use x509_cert::ext::pkix::ExtendedKeyUsage;
    let Some(eku_bytes) = ext_value(leaf, OID_EXT_KEY_USAGE) else {
        return Some("leaf lacks codeSigning EKU extension".into());
    };
    let Ok(eku) = ExtendedKeyUsage::from_der(eku_bytes) else {
        return Some("leaf EKU extension is malformed".into());
    };
    if !eku.0.contains(&OID_CODE_SIGNING) {
        return Some(format!("leaf EKU lacks codeSigning: {:?}", eku.0));
    }
    leaf_ku_bc_reason(leaf)
}

/// keyUsage/basicConstraints rules shared by every leaf purpose: both
/// extensions are optional, but when present keyUsage must set
/// digitalSignature and basicConstraints must assert CA=false.
fn leaf_ku_bc_reason(leaf: &x509_cert::Certificate) -> Option<String> {
    use x509_cert::ext::pkix::{BasicConstraints, KeyUsage};
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
```

4. Visibility for the clock default: change `fn time_now` (:1354) to
   `pub(crate) fn time_now` and note in its doc that new entry points take an
   explicit `now: Option<OffsetDateTime>` defaulted with
   `now.unwrap_or_else(time_now)` — the wasm32 contract for that default
   (queue item 4) lands in Task 4 as `resolve_now`.

5. `verify_signed_data` (:523): add trailing parameter
   `now: time::OffsetDateTime`; at its `verify_chain` call (:827) pass
   `verify_chain(&certs, cert, anchors, now, SignerPurpose::CodeSigning)`.
   (Task 2 replaces this constant with a mode dispatch.)

6. `verify_code_signature_with_anchors` (:295): compute
   `let now = time_now();` and pass it to `verify_signed_data`
   (signature of the public fn itself does NOT change).

7. Update every in-module `verify_chain(...)` call site to the new arity —
   there are exactly six: the production call (:827, covered in step 5) and
   five test call sites at :1666, :1724 (inside the `chain_with` helper,
   :1723), :1825 (bare self-signed), :2043 (issuer-like), and :2095 (subca) —
   each test call passing `time_now(), SignerPurpose::CodeSigning` so its
   wall-clock behavior is unchanged. Confirm completeness by searching
   `verify_chain(` after the edit: no 3-argument call may remain.

- [ ] **Step 4: Scoped gate (green)**

Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-core crypto -- --skip test_ipa_signing_is_deterministic`
Expected: all `crypto` tests pass including the three new ones.

- [ ] **Step 5: Commit**

`git add -u crates/zsign-core/src/crypto/cms_verify.rs && git commit -m "refactor(zsign-core): thread verification time and signer purpose through chain (ZSN-3)"`

---

### Task 2: Queue item 1 (part B) — attached-content CMS verification (the profile envelope)

**Files:**
- Modify: `crates/zsign-core/src/crypto/cms_verify.rs`
  (`verify_signed_data` :523, digest gate :734-739, eContent skip :590, messageDigest
  :802, cdhash gates :842, `verify_signer_signature` :934, public entries :275/:295,
  `CmsVerifyReport` :229)
- Modify: `crates/zsign-core/src/crypto/cms.rs` (test-only attached/detached signers)
- Test: inline `mod tests` in `cms_verify.rs`

**Intent:** verify a bare `ContentInfo` (no Mach-O blob wrapper) whose plist is
attached as `eContent`, with the signer digest Apple actually uses (SHA-1 in all
observed real profiles — librarian §1) and the profile leaf purpose from Task 1.

- [ ] **Step 1: Test-only attached-content signer** in
`crates/zsign-core/src/crypto/cms.rs`

Add (uses the module's existing imports; `signing_err`, `SHA256_OID` are
already defined there):

```rust
/// Digest used by the test-only content signers.
#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum TestDigest {
    Sha1,
    Sha256,
}

impl TestDigest {
    fn digest(self, bytes: &[u8]) -> Vec<u8> {
        match self {
            TestDigest::Sha1 => {
                use sha1::Digest;
                sha1::Sha1::digest(bytes).to_vec()
            }
            TestDigest::Sha256 => Sha256::digest(bytes).to_vec(),
        }
    }

    fn algorithm(self) -> AlgorithmIdentifierOwned {
        AlgorithmIdentifierOwned {
            oid: match self {
                TestDigest::Sha1 => const_oid::db::rfc5912::ID_SHA_1,
                TestDigest::Sha256 => SHA256_OID,
            },
            parameters: None,
        }
    }
}

/// Builds a bare CMS SignedData with `content` attached as eContent — the
/// provisioning-profile shape: no blob wrapper, no Apple CDHash attributes;
/// `contentType`/`messageDigest` are computed by the builder. Test-only;
/// production signing uses [`sign_code_directory`].
#[cfg(test)]
pub(crate) fn sign_attached_content(
    content: &[u8],
    signing_cert: &x509_cert::Certificate,
    cert_chain: &[x509_cert::Certificate],
    private_key: &rsa::RsaPrivateKey,
    digest: TestDigest,
) -> Result<Vec<u8>> {
    let encap = EncapsulatedContentInfo {
        econtent_type: const_oid::db::rfc5911::ID_DATA,
        econtent: Some(
            Any::new(Tag::OctetString, content)
                .map_err(|e| signing_err("Failed to attach content", e))?,
        ),
    };
    sign_test_content(signing_cert, cert_chain, private_key, digest, &encap, None)
}

/// Detached variant: no eContent; `messageDigest` is computed over `content`
/// externally (RFC 5652 §5.2). Used to prove code-signature mode still
/// rejects a SHA-1 signer digest.
#[cfg(test)]
pub(crate) fn sign_detached_content(
    content: &[u8],
    signing_cert: &x509_cert::Certificate,
    cert_chain: &[x509_cert::Certificate],
    private_key: &rsa::RsaPrivateKey,
    digest: TestDigest,
) -> Result<Vec<u8>> {
    let encap = EncapsulatedContentInfo {
        econtent_type: const_oid::db::rfc5911::ID_DATA,
        econtent: None,
    };
    let external = digest.digest(content);
    sign_test_content(
        signing_cert,
        cert_chain,
        private_key,
        digest,
        &encap,
        Some(external.as_slice()),
    )
}

#[cfg(test)]
fn sign_test_content(
    signing_cert: &x509_cert::Certificate,
    cert_chain: &[x509_cert::Certificate],
    private_key: &rsa::RsaPrivateKey,
    digest: TestDigest,
    encap: &EncapsulatedContentInfo,
    external_message_digest: Option<&[u8]>,
) -> Result<Vec<u8>> {
    let sid = SignerIdentifier::IssuerAndSerialNumber(cms::cert::IssuerAndSerialNumber {
        issuer: signing_cert.tbs_certificate.issuer.clone(),
        serial_number: signing_cert.tbs_certificate.serial_number.clone(),
    });

    fn build<S, Sig>(
        encap: &EncapsulatedContentInfo,
        sid: SignerIdentifier,
        digest_algorithm: AlgorithmIdentifierOwned,
        external_message_digest: Option<&[u8]>,
        signing_cert: &x509_cert::Certificate,
        cert_chain: &[x509_cert::Certificate],
        signer: &S,
    ) -> Result<Vec<u8>>
    where
        S: signature::Keypair + spki::DynSignatureAlgorithmIdentifier + signature::Signer<Sig>,
        Sig: spki::SignatureBitStringEncoding,
    {
        let sib = SignerInfoBuilder::new(
            signer,
            sid,
            digest_algorithm.clone(),
            encap,
            external_message_digest,
        )
        .map_err(|e| signing_err("Failed to create SignerInfoBuilder", e))?;
        let mut builder = SignedDataBuilder::new(encap);
        builder
            .add_digest_algorithm(digest_algorithm)
            .map_err(|e| signing_err("Failed to add digest algorithm", e))?;
        builder
            .add_certificate(CertificateChoices::Certificate(signing_cert.clone()))
            .map_err(|e| signing_err("Failed to add signing certificate", e))?;
        for cert in cert_chain {
            builder
                .add_certificate(CertificateChoices::Certificate(cert.clone()))
                .map_err(|e| signing_err("Failed to add chain certificate", e))?;
        }
        builder
            .add_signer_info::<S, Sig>(sib)
            .map_err(|e| signing_err("Failed to add signer info", e))?;
        builder
            .build()
            .map_err(|e| signing_err("Failed to build CMS SignedData", e))?
            .to_der()
            .map_err(|e| signing_err("Failed to encode CMS to DER", e))
    }

    let digest_algorithm = digest.algorithm();
    match digest {
        TestDigest::Sha256 => {
            let signer = rsa::pkcs1v15::SigningKey::<Sha256>::new(private_key.clone());
            build(
                encap,
                sid,
                digest_algorithm,
                external_message_digest,
                signing_cert,
                cert_chain,
                &signer,
            )
        }
        TestDigest::Sha1 => {
            let signer = rsa::pkcs1v15::SigningKey::<sha1::Sha1>::new(private_key.clone());
            build(
                encap,
                sid,
                digest_algorithm,
                external_message_digest,
                signing_cert,
                cert_chain,
                &signer,
            )
        }
    }
}
```

Notes for the implementer: all `use` statements resolve from `crypto/cms.rs`
module scope (`SignedDataBuilder`, `SignerInfoBuilder`, `CertificateChoices`,
`EncapsulatedContentInfo`, `SignerIdentifier`, `AlgorithmIdentifierOwned`,
`Any`, `Tag`, `signing_err`, `SHA256_OID` are already imported there — do not
re-import them inside these functions); `IssuerAndSerialNumber` is referenced
by full path because the module does not import it. The attached builder
computes `messageDigest` from `encap.eContent` (cms-0.2.3 `builder.rs:195-213`)
and auto-adds `contentType`. `rsa`'s `sha1` feature (enabled in this crate's
Cargo.toml) already pulls `sha1` with its `oid` feature, so
`SigningKey::<sha1::Sha1>`'s `AssociatedOid` bound is satisfied on every
target — no Cargo.toml change is needed.

- [ ] **Step 2: Write the failing tests** — append to `mod tests` in
`cms_verify.rs` (add `use crate::crypto::cms::{sign_attached_content, sign_detached_content, TestDigest};`
to the module imports):

```rust
    // ---- attached-content (profile) envelope ----

    fn sample_plist() -> &'static [u8] {
        b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
          <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
          <plist version=\"1.0\">\n\
          <dict>\n\
          <key>Name</key><string>Test Profile</string>\n\
          <key>Entitlements</key><dict><key>get-task-allow</key><true/></dict>\n\
          </dict>\n\
          </plist>"
    }

    #[test]
    fn attached_profile_envelope_round_trips_with_injected_anchors() {
        let (root, leaf, leaf_key, anchors) =
            fixed_validity_chain(T_2026_START as u64, T_2030 as u64, None);
        let envelope = sign_attached_content(
            sample_plist(),
            &leaf,
            &[root],
            &leaf_key,
            TestDigest::Sha256,
        )
        .unwrap();

        let out =
            verify_cms_envelope_with_anchors(&envelope, Some(at(T_2026_APR)), &anchors)
                .unwrap();
        assert!(out.report.valid, "errors: {:?}", out.report.errors);
        assert_eq!(out.content.as_deref(), Some(sample_plist()));
        assert!(out.report.anchored);
        assert!(out.report.message_digest_ok);
        assert!(out.report.signature_ok);
        assert!(out.report.chain_ok);
        assert!(out.report.signer_subject.is_some());
    }

    #[test]
    fn attached_profile_envelope_is_unanchored_against_apple_roots() {
        let (root, leaf, leaf_key, _anchors) =
            fixed_validity_chain(T_2026_START as u64, T_2030 as u64, None);
        let envelope = sign_attached_content(
            sample_plist(),
            &leaf,
            &[root],
            &leaf_key,
            TestDigest::Sha256,
        )
        .unwrap();

        let out = verify_cms_envelope(&envelope, Some(at(T_2026_APR))).unwrap();
        assert!(!out.report.valid);
        assert!(!out.report.anchored);
        assert!(
            out.report.errors.iter().any(|e| e.contains("anchored")),
            "errors: {:?}",
            out.report.errors
        );
    }

    #[test]
    fn tampered_attached_content_fails_message_digest() {
        let (root, leaf, leaf_key, anchors) =
            fixed_validity_chain(T_2026_START as u64, T_2030 as u64, None);
        let mut envelope = sign_attached_content(
            sample_plist(),
            &leaf,
            &[root],
            &leaf_key,
            TestDigest::Sha256,
        )
        .unwrap();
        let idx = envelope
            .windows(sample_plist().len())
            .position(|w| w == sample_plist())
            .expect("eContent embedded in envelope");
        envelope[idx] = b'!'; // same length: DER structure survives, digest does not

        let out =
            verify_cms_envelope_with_anchors(&envelope, Some(at(T_2026_APR)), &anchors)
                .unwrap();
        assert!(!out.report.valid);
        assert!(!out.report.message_digest_ok);
        assert!(
            out.report.errors.iter().any(|e| e.contains("messageDigest")),
            "errors: {:?}",
            out.report.errors
        );
    }

    #[test]
    fn attached_profile_accepts_sha1_signer_digest_with_warning() {
        let (root, leaf, leaf_key, anchors) =
            fixed_validity_chain(T_2026_START as u64, T_2030 as u64, None);
        let envelope = sign_attached_content(
            sample_plist(),
            &leaf,
            &[root],
            &leaf_key,
            TestDigest::Sha1,
        )
        .unwrap();

        let out =
            verify_cms_envelope_with_anchors(&envelope, Some(at(T_2026_APR)), &anchors)
                .unwrap();
        assert!(out.report.valid, "errors: {:?}", out.report.errors);
        assert!(
            out.report.warnings.iter().any(|w| w.contains("SHA-1")),
            "warnings: {:?}",
            out.report.warnings
        );
    }

    #[test]
    fn detached_code_cms_reports_missing_attached_content() {
        let creds = rsa_credentials();
        let content: &[u8] = b"detached content";
        let cd_sha256: [u8; 32] = Sha256::digest(content).into();
        let cms = sign_code_directory(content, &creds.0, None, &cd_sha256).unwrap();

        let out =
            verify_cms_envelope_with_anchors(&cms, Some(at(T_2026_APR)), &anchors_for(&creds.0))
                .unwrap();
        assert!(!out.report.valid);
        assert!(out.content.is_none());
        assert!(
            out.report.errors.iter().any(|e| e.contains("no attached content")),
            "errors: {:?}",
            out.report.errors
        );
    }

    #[test]
    fn code_signature_mode_still_rejects_sha1_signer_digest() {
        let (creds, key) = rsa_credentials();
        let content: &[u8] = b"detached sha1 content";
        let cd_sha256: [u8; 32] = Sha256::digest(content).into();
        let cms =
            sign_detached_content(content, &creds.certificate, &[], &key, TestDigest::Sha1)
                .unwrap();
        let wrapped = wrap(&cms);

        let report =
            verify_code_signature_with_anchors(&wrapped, content, None, &cd_sha256, &anchors_for(&creds))
                .unwrap();
        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|e| e.contains("only SHA-256 is supported")),
            "errors: {:?}",
            report.errors
        );
    }

    #[test]
    fn rsa_signature_rejects_digest_and_signature_oid_mismatches() {
        use signature::Signer;

        let (creds, key) = rsa_credentials();
        // Deliberately not 0xA0-prefixed, so `verify_signer_signature` treats
        // these bytes as the single candidate message.
        let msg: &[u8] = b"\x02\x01\x01 mismatch-probe";

        let sha256_key = rsa::pkcs1v15::SigningKey::<Sha256>::new(key.clone());
        let sig256: rsa::pkcs1v15::Signature = sha256_key.sign(msg);

        // Consistent pairs verify.
        assert!(verify_signer_signature(
            &creds.certificate,
            OID_SHA256_WITH_RSA,
            SignerDigest::Sha256,
            msg,
            sig256.as_bytes(),
        ));
        assert!(verify_signer_signature(
            &creds.certificate,
            OID_RSA_ENCRYPTION,
            SignerDigest::Sha256,
            msg,
            sig256.as_bytes(),
        ));

        // Mismatch direction 1: SHA-256 digestAlgorithm presented with the
        // SHA-1 signature OID (a real SHA-256 signature must not be accepted
        // under the SHA-1 label).
        assert!(!verify_signer_signature(
            &creds.certificate,
            OID_SHA1_WITH_RSA,
            SignerDigest::Sha256,
            msg,
            sig256.as_bytes(),
        ));

        let sha1_key = rsa::pkcs1v15::SigningKey::<sha1::Sha1>::new(key.clone());
        let sig1: rsa::pkcs1v15::Signature = sha1_key.sign(msg);

        // Consistent SHA-1 pairs (the profile shape, incl. Apple's
        // digest-less rsaEncryption form) verify.
        assert!(verify_signer_signature(
            &creds.certificate,
            OID_SHA1_WITH_RSA,
            SignerDigest::Sha1,
            msg,
            sig1.as_bytes(),
        ));
        assert!(verify_signer_signature(
            &creds.certificate,
            OID_RSA_ENCRYPTION,
            SignerDigest::Sha1,
            msg,
            sig1.as_bytes(),
        ));

        // Mismatch direction 2: SHA-1 digestAlgorithm presented with the
        // SHA-256 signature OID — rejected for both a SHA-256 and a SHA-1
        // signature payload.
        assert!(!verify_signer_signature(
            &creds.certificate,
            OID_SHA256_WITH_RSA,
            SignerDigest::Sha1,
            msg,
            sig256.as_bytes(),
        ));
        assert!(!verify_signer_signature(
            &creds.certificate,
            OID_SHA256_WITH_RSA,
            SignerDigest::Sha1,
            msg,
            sig1.as_bytes(),
        ));
    }
```

- [ ] **Step 3: Run to confirm red**

Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-core attached_profile_envelope_round_trip`
Expected: FAIL to compile — `verify_cms_envelope_with_anchors`,
`CmsEnvelopeReport`, `TestDigest`, `sign_attached_content` do not exist.

- [ ] **Step 4: Implement** in `crates/zsign-core/src/crypto/cms_verify.rs`

1. Add the OID and digest/mode types:

```rust
/// SHA-1: `1.3.14.3.2.26` (legacy profile CMS signer digest).
const OID_SHA1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.14.3.2.26");

/// The signer's message-digest algorithm, carried through verification so the
/// `messageDigest` attribute and the PKCS#1 v1.5 DigestInfo agree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SignerDigest {
    Sha1,
    Sha256,
}

/// Verification policy for a CMS SignedData structure.
enum SignedDataMode<'a> {
    /// Mach-O code signature: detached CodeDirectory content supplied by the
    /// caller, mandatory Apple CDHash attributes, SHA-256 signer digest.
    CodeSignature {
        cd_sha1: Option<&'a [u8; 20]>,
        cd_sha256: &'a [u8; 32],
    },
    /// Provisioning profile: attached eContent required, SHA-256 or SHA-1
    /// signer digest, no Apple attributes.
    AttachedProfile,
}
```

2. `verify_signed_data` (:523) — new signature:

```rust
fn verify_signed_data(
    cms: &[u8],
    content: Option<&[u8]>,
    mode: &SignedDataMode<'_>,
    anchors: &TrustAnchors,
    now: time::OffsetDateTime,
) -> Result<(CmsVerifyReport, Option<Vec<u8>>)> {
```

   - Every `return seal(report, global_errors);` becomes
     `return Ok((seal(report, global_errors)?, econtent));` — so `econtent`
     (next point) must be declared before the first one (:657).
   - Replace the eContent skip (:590-593) with capture:

```rust
    // Optional [0] EXPLICIT eContent { OCTET STRING }; detached signatures omit it.
    let mut econtent: Option<Vec<u8>> = None;
    if !encap_r.is_finished() {
        let ec = AnyRef::decode(&mut encap_r)
            .map_err(|e| Error::Verification(format!("malformed eContent: {e}")))?;
        if ec.tag() != TAG_CTX0 {
            return Err(Error::Verification(format!(
                "eContent is not in [0] EXPLICIT wrapper (tag {:?})",
                ec.tag()
            )));
        }
        let mut ecr = reader(ec.value(), "malformed eContent wrapper")?;
        if !ecr.is_finished() {
            let inner = AnyRef::decode(&mut ecr)
                .map_err(|e| Error::Verification(format!("malformed eContent: {e}")))?;
            if inner.tag() != Tag::OctetString {
                return Err(Error::Verification(
                    "attached eContent is not an OCTET STRING".into(),
                ));
            }
            econtent = Some(inner.value().to_vec());
        }
    }
```

   - Resolve the bytes the `messageDigest` attribute must cover (owned clone
     keeps the early-return moves borrow-free):

```rust
    let bound_content: Option<Vec<u8>> = match mode {
        SignedDataMode::CodeSignature { .. } => content.map(<[u8]>::to_vec),
        SignedDataMode::AttachedProfile => match econtent {
            Some(ref c) => Some(c.clone()),
            None => {
                global_errors.push(
                    "CMS has no attached content (eContent required for profile verification)"
                        .into(),
                );
                None
            }
        },
    };
```

   - Return `Ok((report, econtent))` from the final `seal(report, global_errors)`.

3. Digest gate (:734-739) — replace the SHA-256-only check with per-mode policy:

```rust
        let signer_digest = match mode {
            SignedDataMode::CodeSignature { .. } => {
                if dig_oid != OID_SHA256 {
                    report.errors.push(format!(
                        "unsupported digest algorithm {dig_oid} (only SHA-256 is supported)"
                    ));
                    return Ok((seal(report, global_errors)?, econtent));
                }
                SignerDigest::Sha256
            }
            SignedDataMode::AttachedProfile => match dig_oid {
                OID_SHA256 => SignerDigest::Sha256,
                OID_SHA1 => {
                    let w = "profile CMS is signed with a SHA-1 message digest";
                    if !report.warnings.iter().any(|x| x == w) {
                        report.warnings.push(w.to_string());
                    }
                    SignerDigest::Sha1
                }
                other => {
                    report.errors.push(format!(
                        "unsupported digest algorithm {other} (profile CMS allows SHA-256 or SHA-1)"
                    ));
                    return Ok((seal(report, global_errors)?, econtent));
                }
            },
        };
```

4. messageDigest check (:802-808):

```rust
        let md_ok = match bound_content {
            Some(ref b) => {
                let computed: Vec<u8> = match signer_digest {
                    SignerDigest::Sha1 => sha1::Sha1::digest(b).to_vec(),
                    SignerDigest::Sha256 => Sha256::digest(b).to_vec(),
                };
                // `SignedAttrs::message_digest` is `Option<&[u8]>` — compare
                // the slices directly, mirroring the existing check.
                attrs
                    .message_digest
                    .map(|md| md == computed.as_slice())
                    .unwrap_or(false)
            }
            None => false,
        };
        report.message_digest_ok = md_ok;
```

   Add `use sha1::Digest as _;` next to the existing `use sha2::{Digest, Sha256};`
   if the trait is not already in scope through `super::*`.

5. CDHash checks (:811-820) become mode-gated; the report fields keep their
   default `false` in attached mode (document on `CmsVerifyReport` at :242/:244:
   “only meaningful for code-signature verification; always false for envelope
   verification”):

```rust
        if let SignedDataMode::CodeSignature { cd_sha1, cd_sha256 } = mode {
            report.cdhash_v1_ok = attrs
                .cdhash_v1_plist
                .as_ref()
                .map(|p| cdhash_v1_matches(p, *cd_sha1, cd_sha256))
                .unwrap_or(false);
            report.cdhash_v2_ok = attrs
                .cdhash_v2_der
                .as_ref()
                .map(|d| cdhash_v2_matches(d, cd_sha256))
                .unwrap_or(false);
        }
```

   and the aggregation (:842-847) wraps both pushes in
   `if let SignedDataMode::CodeSignature { .. } = mode { ... }`.

6. `verify_signer_signature` (:934) gains `digest: SignerDigest` and must also
   accept `sha1WithRSAEncryption` — real profile SignerInfos carry that OID
   when the fixture signs with `SigningKey::<sha1::Sha1>` (rsa-0.9.10
   `pkcs1v15.rs:230-233`), and Apple profiles use `rsaEncryption` naming no
   digest. Three coordinated changes inside the function:

   a. The RSA predicate gains the SHA-1 OID (the constant already exists at
   `cms_verify.rs` `OID_SHA1_WITH_RSA`, :73-74):

```rust
    let rsa_sig = sig_oid == OID_SHA256_WITH_RSA
        || sig_oid == OID_SHA1_WITH_RSA
        || sig_oid == OID_RSA_ENCRYPTION;
```

   b. Before the signature dispatch, gate the pair for consistency — RFC 5652
   SignerInfo semantics require `signatureAlgorithm` and `digestAlgorithm` to
   name the same hash (RFC 5754 §2 pair rules): `rsaEncryption` names no
   digest and inherits the SignerInfo digest, while an explicit
   `*WithRSAEncryption` OID must agree with it. An inconsistent pair is
   rejected outright (`return false`) — this is a strict pair-consistency
   rule, not accept-set widening: pre-patch behavior refused
   `sha1WithRSAEncryption` entirely; the gate keeps refusing every
   mismatched combination (both directions) while admitting the two
   consistent SHA-1 pairs real profiles use:

```rust
    if rsa_sig {
        let consistent = sig_oid == OID_RSA_ENCRYPTION
            || (sig_oid == OID_SHA256_WITH_RSA && digest == SignerDigest::Sha256)
            || (sig_oid == OID_SHA1_WITH_RSA && digest == SignerDigest::Sha1);
        if !consistent {
            // signatureAlgorithm/digestAlgorithm mismatch — reject outright.
            return false;
        }
    }
    // The digest the RSA PKCS#1 v1.5 DigestInfo must carry: explicit
    // *WithRSAEncryption OIDs were checked against `digest` above;
    // rsaEncryption inherits it.
    let effective_digest = if sig_oid == OID_SHA1_WITH_RSA {
        SignerDigest::Sha1
    } else if sig_oid == OID_SHA256_WITH_RSA {
        SignerDigest::Sha256
    } else {
        digest
    };
```

   Place both blocks after the `rsa_sig`/`ecdsa_sig` predicates and before
   the `for msg in candidates` loop (ECDSA never enters the gate; it keeps
   its SHA-256 dispatch). Also update the stale comment above `rsa_sig`
   (“the digest OID carrying SHA-256”) to describe the pair rule.

   c. In the `rsa_sig && alg == OID_RSA_ENCRYPTION` branch, dispatch on
   `effective_digest` instead of hard-coded `Sha256`:

```rust
            let ok = match effective_digest {
                SignerDigest::Sha256 => rsa::pkcs1v15::VerifyingKey::<Sha256>::new(pub_key)
                    .verify(msg, &sig)
                    .is_ok(),
                SignerDigest::Sha1 => rsa::pkcs1v15::VerifyingKey::<sha1::Sha1>::new(pub_key)
                    .verify(msg, &sig)
                    .is_ok(),
            };
```

   ECDSA stays SHA-256. The call site (:823) passes `signer_digest` (the
   per-mode gate's result). Net effect: profile SHA-1 verifies (both with
   `rsaEncryption` and `sha1WithRSAEncryption`), while code-signature mode
   behaves exactly as before — its digest gate has already forced
   `SignerDigest::Sha256`, so a `sha1WithRSAEncryption` blob still fails
   verification, and the SHA-1 gate itself still rejects SHA-1 digest
   algorithms outright (covered by
   `code_signature_mode_still_rejects_sha1_signer_digest`).

7. Chain call (:827): purpose now derives from the mode —
   `let purpose = match mode { SignedDataMode::CodeSignature { .. } => SignerPurpose::CodeSigning, SignedDataMode::AttachedProfile => SignerPurpose::ProvisioningProfile };`
   — passed as `verify_chain(&certs, cert, anchors, now, purpose)`.

8. Legacy entry (:295) adapts to the tuple return and mode:

```rust
    let now = time_now();
    let (report, _attached) = verify_signed_data(
        &normalized,
        Some(content),
        &SignedDataMode::CodeSignature { cd_sha1, cd_sha256 },
        anchors,
        now,
    )?;
    Ok(report)
```

9. New public surface (after `adhoc_report`, :310):

```rust
/// Result of verifying a bare CMS SignedData envelope with attached content —
/// the provisioning-profile shape (no Mach-O blob wrapper, plist in eContent).
///
/// `content` is returned even when `report.valid` is false so callers can
/// inspect what the envelope claims; only consume it after `report.valid`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CmsEnvelopeReport {
    /// Signature, chain, and anchoring outcome (same shape as code signing;
    /// the `cdhash_*` fields are not applicable and stay false).
    pub report: CmsVerifyReport,
    /// The attached eContent bytes — for profiles, the XML plist.
    pub content: Option<Vec<u8>>,
}

/// Verifies a provisioning-profile-style CMS envelope against
/// [`TrustAnchors::apple_root`].
///
/// `now` is the verification instant; `None` falls back to the wall clock
/// (`time_now`).
///
/// ```ignore
/// let out = zsign_core::crypto::cms_verify::verify_cms_envelope(&profile_bytes, None)?;
/// assert!(out.report.valid);
/// let plist = out.content.expect("profile carries its plist");
/// ```
///
/// # Errors
///
/// Returns [`Error::Verification`] when the bytes are not a well-formed CMS
/// structure; integrity failures are report data (`report.valid == false`).
pub fn verify_cms_envelope(
    envelope: &[u8],
    now: Option<time::OffsetDateTime>,
) -> Result<CmsEnvelopeReport> {
    let anchors = TrustAnchors::apple_root()?;
    verify_cms_envelope_with_anchors(envelope, now, &anchors)
}

/// Like [`verify_cms_envelope`], but against an explicit anchor set (tests
/// inject their own root here — mirror of `verify_code_signature_with_anchors`).
pub fn verify_cms_envelope_with_anchors(
    envelope: &[u8],
    now: Option<time::OffsetDateTime>,
    anchors: &TrustAnchors,
) -> Result<CmsEnvelopeReport> {
    let now = now.unwrap_or_else(time_now);
    let normalized = normalize_ber_lengths(envelope)?;
    let (report, content) = verify_signed_data(
        &normalized,
        None,
        &SignedDataMode::AttachedProfile,
        anchors,
        now,
    )?;
    Ok(CmsEnvelopeReport { report, content })
}
```

   (Queue item 4 replaces this `unwrap_or_else(time_now)` with `resolve_now(now)?`
   in Task 4 — that is where the wasm32 contract lands.)

- [ ] **Step 5: Scoped gate (green)**

Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-core crypto -- --skip test_ipa_signing_is_deterministic && TMPDIR=$PWD/.tmptmp cargo test -p zsign-core provisioning -- --skip test_ipa_signing_is_deterministic`
Expected: all `crypto` tests (existing + new envelope tests) and the three
existing `provisioning` tests pass.

- [ ] **Step 6: Commit**

`git add -u crates/zsign-core/src/crypto/cms_verify.rs crates/zsign-core/src/crypto/cms.rs && git commit -m "feat(zsign-core): verify provisioning profile cms envelopes (ZSN-3)"`

---

### Task 3: Queue items 2+3 — profile model, validation, and the retained legacy API

**Files:**
- Modify: `crates/zsign-core/src/provisioning.rs` (whole file: new API + retained fn)
- Modify: `crates/zsign-core/src/lib.rs` (re-exports, next to :16)
- Modify: `crates/zsign-core/Cargo.toml` (`time` features)
- Test: inline `mod tests` in `provisioning.rs`

**Intent:** parse and validate the verified profile (window, team, App ID,
devices) with actionable errors, expose the result as a struct, and keep
`extract_entitlements_from_profile` byte-for-byte compatible.

- [ ] **Step 1: `time` features** in `crates/zsign-core/Cargo.toml` (:17):
  replace `time = "0.3"` with
  `time = { version = "0.3", features = ["parsing", "formatting"] }`
  (RFC3339 rendering of dates in error messages must not depend on feature
  unification through `plist`).

- [ ] **Step 2: Write the failing tests** — replace the test module in
`crates/zsign-core/src/provisioning.rs` with the existing three tests **kept
verbatim** plus the fixtures and new tests below (append after them):

```rust
    // ---- validated extraction fixtures ----

    use crate::crypto::cms::{sign_attached_content, TestDigest};
    use der::Decode;
    use spki::{EncodePublicKey, SubjectPublicKeyInfoOwned};
    use std::str::FromStr;
    use std::time::{Duration as StdDuration, UNIX_EPOCH};
    use x509_cert::builder::{Builder, CertificateBuilder, Profile};
    use x509_cert::name::Name;
    use x509_cert::serial_number::SerialNumber;
    use x509_cert::time::{Time, Validity};

    const T_2025: i64 = 1_735_689_600; // 2025-01-01T00:00:00Z
    const T_2026_START: i64 = 1_767_225_600; // 2026-01-01T00:00:00Z
    const T_2026_APR: i64 = 1_775_001_600; // 2026-04-01T00:00:00Z
    const T_2026_JUL: i64 = 1_782_864_000; // 2026-07-01T00:00:00Z
    const T_2027: i64 = 1_798_761_600; // 2027-01-01T00:00:00Z

    fn at(unix: i64) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(unix).unwrap()
    }

    struct SignedProfile {
        data: Vec<u8>,
        anchors: TrustAnchors,
    }

    /// Test CA plus a profile-shaped leaf (no EKU; `Profile::Leaf` supplies
    /// KU digitalSignature and CA=false), chain validity 2020..2030 so every
    /// injected instant below stays inside the chain window.
    fn signed_profile(plist_xml: &str) -> SignedProfile {
        let to_time = |unix: u64| {
            Time::try_from(UNIX_EPOCH + StdDuration::from_secs(unix)).unwrap()
        };
        let root_key = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
        let root_signing = rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(root_key.clone());
        let root_name = Name::from_str("CN=zsn3 profile test root").unwrap();
        let root_pub = SubjectPublicKeyInfoOwned::from_der(
            root_key.to_public_key().to_public_key_der().unwrap().as_ref(),
        )
        .unwrap();
        let root_cert = CertificateBuilder::new(
            Profile::Root,
            SerialNumber::from(31u32),
            Validity {
                not_before: to_time(1_577_836_800),
                not_after: to_time(1_893_456_000),
            },
            root_name.clone(),
            root_pub,
            &root_signing,
        )
        .unwrap()
        .build::<rsa::pkcs1v15::Signature>()
        .unwrap();

        let leaf_key = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
        let leaf_signing = rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(leaf_key.clone());
        let leaf_name = Name::from_str("CN=zsn3 profile test leaf").unwrap();
        let leaf_pub = SubjectPublicKeyInfoOwned::from_der(
            leaf_key.to_public_key().to_public_key_der().unwrap().as_ref(),
        )
        .unwrap();
        let leaf_cert = CertificateBuilder::new(
            Profile::Leaf {
                issuer: root_name.clone(),
                enable_key_agreement: false,
                enable_key_encipherment: false,
            },
            SerialNumber::from(32u32),
            Validity {
                not_before: to_time(1_577_836_800),
                not_after: to_time(1_893_456_000),
            },
            leaf_name,
            leaf_pub,
            &root_signing,
        )
        .unwrap()
        .build::<rsa::pkcs1v15::Signature>()
        .unwrap();

        let data = sign_attached_content(
            plist_xml.as_bytes(),
            &leaf_cert,
            &[root_cert.clone()],
            &leaf_key,
            TestDigest::Sha256,
        )
        .unwrap();
        SignedProfile {
            data,
            anchors: TrustAnchors::from_certificates(vec![root_cert]),
        }
    }

    /// A well-formed profile plist: Name/CreationDate/ExpirationDate
    /// 2026-01-01..2026-07-01, team TESTTEAM, explicit App ID, plus `extra`
    /// keys injected before `</dict>`.
    fn plist_xml(extra: &str) -> String {
        format!(
            concat!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n",
                "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n",
                "<plist version=\"1.0\">\n<dict>\n",
                "  <key>Name</key>\n  <string>Test Profile</string>\n",
                "  <key>CreationDate</key>\n  <date>2026-01-01T00:00:00Z</date>\n",
                "  <key>ExpirationDate</key>\n  <date>2026-07-01T00:00:00Z</date>\n",
                "  <key>TeamIdentifier</key>\n  <array>\n    <string>TESTTEAM</string>\n  </array>\n",
                "  <key>Entitlements</key>\n  <dict>\n",
                "    <key>application-identifier</key>\n    <string>TESTTEAM.com.example.app</string>\n",
                "    <key>get-task-allow</key>\n    <true/>\n",
                "  </dict>\n",
                "{}",
                "</dict>\n</plist>\n"
            ),
            extra
        )
    }

    fn request(sp: &SignedProfile, now_unix: i64) -> ProfileRequest {
        ProfileRequest {
            now: Some(at(now_unix)),
            anchors: Some(sp.anchors.clone()),
            ..Default::default()
        }
    }
```

Then the tests:

```rust
    #[test]
    fn forged_plaintext_profile_is_rejected_but_legacy_extractor_is_unchanged() {
        let xml = plist_xml("");
        // Legacy contract: raw scan, no verification — unchanged.
        let legacy = String::from_utf8(extract_entitlements_from_profile(xml.as_bytes()).unwrap().unwrap())
            .unwrap();
        assert!(legacy.contains("get-task-allow"));
        // New API: no CMS envelope at all.
        let req = ProfileRequest {
            now: Some(at(T_2026_APR)),
            ..Default::default()
        };
        let err = validate_and_extract_profile(xml.as_bytes(), &req).unwrap_err();
        assert!(matches!(err, crate::Error::Verification(_)), "got: {err}");
    }

    #[test]
    fn valid_profile_verifies_and_exposes_every_field() {
        let sp = signed_profile(&plist_xml(
            "  <key>ProvisionedDevices</key>\n  <array>\n    <string>UDID-ONE</string>\n  </array>\n",
        ));
        let info = validate_and_extract_profile(&sp.data, &request(&sp, T_2026_APR)).unwrap();

        assert_eq!(info.name, "Test Profile");
        assert_eq!(info.team_identifiers, ["TESTTEAM".to_string()]);
        assert_eq!(
            info.application_identifier.as_deref(),
            Some("TESTTEAM.com.example.app")
        );
        assert_eq!(info.creation_date, Some(at(T_2026_START)));
        assert_eq!(info.expiration_date, at(T_2026_JUL));
        assert!(!info.provisions_all_devices);
        assert_eq!(
            info.provisioned_devices,
            Some(vec!["UDID-ONE".to_string()])
        );
        let xml = String::from_utf8(info.entitlements_xml.clone().unwrap()).unwrap();
        assert!(xml.contains("get-task-allow"));
        assert!(info.cms.valid);
        assert!(info.cms.signer_subject.is_some());
    }

    #[test]
    fn synthetic_profile_is_rejected_against_production_anchors() {
        let sp = signed_profile(&plist_xml(""));
        let info = ProfileRequest {
            now: Some(at(T_2026_APR)),
            ..Default::default()
        };
        let err = validate_and_extract_profile(&sp.data, &info).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("CMS verification failed"), "{msg}");
        assert!(msg.contains("anchored"), "{msg}");
    }

    #[test]
    fn tampered_profile_is_rejected() {
        let sp = signed_profile(&plist_xml(""));
        let mut data = sp.data.clone();
        let needle = plist_xml("");
        let idx = data
            .windows(needle.len())
            .position(|w| w == needle.as_bytes())
            .expect("plist embedded as eContent");
        data[idx] = b'!';

        let err = validate_and_extract_profile(&data, &request(&sp, T_2026_APR)).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("CMS verification failed"), "{msg}");
        assert!(msg.contains("messageDigest"), "{msg}");
    }

    #[test]
    fn expired_profile_names_profile_date_and_remedy() {
        let sp = signed_profile(&plist_xml(""));
        let err =
            validate_and_extract_profile(&sp.data, &request(&sp, T_2027)).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("expired"), "{msg}");
        assert!(msg.contains("Test Profile"), "{msg}");
        assert!(msg.contains("2026-07-01"), "{msg}");
        assert!(msg.contains("renew"), "{msg}");
    }

    #[test]
    fn not_yet_valid_profile_is_rejected() {
        let sp = signed_profile(&plist_xml(""));
        let err =
            validate_and_extract_profile(&sp.data, &request(&sp, T_2025)).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("not valid until"), "{msg}");
        assert!(msg.contains("2026-01-01"), "{msg}");
    }

    #[test]
    fn team_mismatch_is_rejected_and_match_passes() {
        let sp = signed_profile(&plist_xml(""));
        let mut req = request(&sp, T_2026_APR);
        req.expected_team_id = Some("OTHERTEAM".to_string());
        let err = validate_and_extract_profile(&sp.data, &req).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("OTHERTEAM"), "{msg}");
        assert!(msg.contains("TESTTEAM"), "{msg}");

        let mut ok_req = request(&sp, T_2026_APR);
        ok_req.expected_team_id = Some("TESTTEAM".to_string());
        assert!(validate_and_extract_profile(&sp.data, &ok_req).is_ok());
    }

    #[test]
    fn team_match_accepts_the_union_of_team_sources() {
        // Case 1: TeamIdentifier absent — ApplicationIdentifierPrefix carries the team.
        let prefix_only = signed_profile(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <plist version=\"1.0\">\n<dict>\n\
             <key>Name</key><string>Test Profile</string>\n\
             <key>ExpirationDate</key><date>2026-07-01T00:00:00Z</date>\n\
             <key>ApplicationIdentifierPrefix</key>\n<array>\n<string>TESTTEAM</string>\n</array>\n\
             <key>Entitlements</key>\n<dict>\n\
             <key>application-identifier</key>\n<string>TESTTEAM.com.example.app</string>\n\
             </dict>\n</dict>\n</plist>\n",
        );
        let mut req = request(&prefix_only, T_2026_APR);
        req.expected_team_id = Some("TESTTEAM".to_string());
        assert!(validate_and_extract_profile(&prefix_only.data, &req).is_ok());

        // Case 2: TeamIdentifier says WRONGTEAM, the team-identifier
        // entitlement says TESTTEAM — the union must accept TESTTEAM.
        let with_entitlement = signed_profile(
            &plist_xml("")
                .replace(
                    "    <string>TESTTEAM</string>\n  </array>",
                    "    <string>WRONGTEAM</string>\n  </array>",
                )
                .replace(
                    "    <key>get-task-allow</key>\n    <true/>\n",
                    "    <key>get-task-allow</key>\n    <true/>\n    <key>com.apple.developer.team-identifier</key>\n    <string>TESTTEAM</string>\n",
                ),
        );
        let mut req = request(&with_entitlement, T_2026_APR);
        req.expected_team_id = Some("TESTTEAM".to_string());
        assert!(validate_and_extract_profile(&with_entitlement.data, &req).is_ok());

        // Case 3: TeamIdentifier alone disagrees — rejected, and the message
        // names the profile's team.
        let wrong_only = signed_profile(&plist_xml("").replace(
            "    <string>TESTTEAM</string>\n  </array>",
            "    <string>WRONGTEAM</string>\n  </array>",
        ));
        let mut req = request(&wrong_only, T_2026_APR);
        req.expected_team_id = Some("TESTTEAM".to_string());
        let err = validate_and_extract_profile(&wrong_only.data, &req).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("WRONGTEAM"), "{msg}");
        assert!(msg.contains("not the signing team TESTTEAM"), "{msg}");
    }

    #[test]
    fn explicit_app_id_covers_only_the_matching_bundle() {
        let sp = signed_profile(&plist_xml(""));
        let mut ok_req = request(&sp, T_2026_APR);
        ok_req.target_bundle_id = Some("com.example.app".to_string());
        assert!(validate_and_extract_profile(&sp.data, &ok_req).is_ok());

        let mut bad_req = request(&sp, T_2026_APR);
        bad_req.target_bundle_id = Some("com.example.other".to_string());
        let err = validate_and_extract_profile(&sp.data, &bad_req).unwrap_err();
        assert!(err.to_string().contains("does not cover"), "{err}");
    }

    #[test]
    fn wildcard_app_id_covers_by_trailing_star_only() {
        let wildcard = plist_xml("").replace(
            "TESTTEAM.com.example.app",
            "TESTTEAM.com.foo.*",
        );
        let sp = signed_profile(&wildcard);

        let mut covered = request(&sp, T_2026_APR);
        covered.target_bundle_id = Some("com.foo.bar".to_string());
        assert!(validate_and_extract_profile(&sp.data, &covered).is_ok());

        let mut not_covered = request(&sp, T_2026_APR);
        not_covered.target_bundle_id = Some("com.foobar".to_string());
        let err = validate_and_extract_profile(&sp.data, &not_covered).unwrap_err();
        assert!(err.to_string().contains("does not cover"), "{err}");

        let any = plist_xml("").replace("TESTTEAM.com.example.app", "TESTTEAM.*");
        let sp_any = signed_profile(&any);
        let mut any_req = request(&sp_any, T_2026_APR);
        any_req.target_bundle_id = Some("com.anything.at.all".to_string());
        assert!(validate_and_extract_profile(&sp_any.data, &any_req).is_ok());
    }

    #[test]
    fn malformed_wildcard_app_id_is_rejected() {
        let bad = plist_xml("").replace("TESTTEAM.com.example.app", "TESTTEAM.com.*.bar");
        let sp = signed_profile(&bad);
        let mut req = request(&sp, T_2026_APR);
        req.target_bundle_id = Some("com.example.app".to_string());
        let err = validate_and_extract_profile(&sp.data, &req).unwrap_err();
        assert!(err.to_string().contains("single trailing"), "{err}");
    }

    #[test]
    fn app_id_under_a_foreign_prefix_is_rejected() {
        let foreign = signed_profile(
            &plist_xml("").replace(
                "    <string>TESTTEAM.com.example.app</string>",
                "    <string>OTHERTEAM.com.example.app</string>",
            ),
        );
        let mut req = request(&foreign, T_2026_APR);
        req.target_bundle_id = Some("com.example.app".to_string());
        let err = validate_and_extract_profile(&foreign.data, &req).unwrap_err();
        assert!(err.to_string().contains("does not start with"), "{err}");
    }

    #[test]
    fn macos_application_identifier_entitlement_is_used() {
        let mac = plist_xml("").replace(
            "    <key>application-identifier</key>\n    <string>TESTTEAM.com.example.app</string>\n",
            "    <key>com.apple.application-identifier</key>\n    <string>TESTTEAM.com.example.app</string>\n",
        );
        assert!(!mac.contains("\n    <key>application-identifier</key>"));
        let sp = signed_profile(&mac);
        let mut req = request(&sp, T_2026_APR);
        req.target_bundle_id = Some("com.example.app".to_string());
        assert!(validate_and_extract_profile(&sp.data, &req).is_ok());
    }

    #[test]
    fn target_bundle_id_must_not_wildcard() {
        let sp = signed_profile(&plist_xml(""));
        let mut req = request(&sp, T_2026_APR);
        req.target_bundle_id = Some("com.example.*".to_string());
        let err = validate_and_extract_profile(&sp.data, &req).unwrap_err();
        assert!(err.to_string().contains("must not contain a wildcard"), "{err}");
    }

    #[test]
    fn device_registration_checks_follow_provisions_all_devices_precedence() {
        let devices_only = signed_profile(&plist_xml(
            "  <key>ProvisionedDevices</key>\n  <array>\n    <string>UDID-ONE</string>\n  </array>\n",
        ));
        let mut listed = request(&devices_only, T_2026_APR);
        listed.target_device_udid = Some("UDID-ONE".to_string());
        assert!(validate_and_extract_profile(&devices_only.data, &listed).is_ok());

        let mut unlisted = request(&devices_only, T_2026_APR);
        unlisted.target_device_udid = Some("UDID-TWO".to_string());
        let err = validate_and_extract_profile(&devices_only.data, &unlisted).unwrap_err();
        assert!(err.to_string().contains("not registered"), "{err}");

        // ProvisionsAllDevices wins over an (unlisted) device list.
        let all_devices = signed_profile(&plist_xml(concat!(
            "  <key>ProvisionedDevices</key>\n  <array>\n    <string>UDID-ONE</string>\n  </array>\n",
            "  <key>ProvisionsAllDevices</key>\n  <true/>\n"
        )));
        let mut all_req = request(&all_devices, T_2026_APR);
        all_req.target_device_udid = Some("UDID-TWO".to_string());
        assert!(validate_and_extract_profile(&all_devices.data, &all_req).is_ok());

        // App Store profile: neither key — nothing to enforce.
        let app_store = signed_profile(&plist_xml(""));
        let mut store_req = request(&app_store, T_2026_APR);
        store_req.target_device_udid = Some("UDID-TWO".to_string());
        assert!(validate_and_extract_profile(&app_store.data, &store_req).is_ok());

        // Present but non-boolean ProvisionsAllDevices fails closed.
        let malformed = signed_profile(&plist_xml(
            "  <key>ProvisionsAllDevices</key>\n  <string>yes</string>\n",
        ));
        let err =
            validate_and_extract_profile(&malformed.data, &request(&malformed, T_2026_APR))
                .unwrap_err();
        assert!(err.to_string().contains("non-boolean"), "{err}");
    }

    #[test]
    fn missing_name_or_expiration_date_is_rejected() {
        let no_name = signed_profile(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <plist version=\"1.0\">\n<dict>\n\
             <key>ExpirationDate</key><date>2026-07-01T00:00:00Z</date>\n\
             </dict>\n</plist>\n",
        );
        let err =
            validate_and_extract_profile(&no_name.data, &request(&no_name, T_2026_APR))
                .unwrap_err();
        assert!(err.to_string().contains("missing the Name"), "{err}");

        let no_exp = signed_profile(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <plist version=\"1.0\">\n<dict>\n\
             <key>Name</key><string>Test Profile</string>\n\
             <key>CreationDate</key><date>2026-01-01T00:00:00Z</date>\n\
             </dict>\n</plist>\n",
        );
        let err =
            validate_and_extract_profile(&no_exp.data, &request(&no_exp, T_2026_APR))
                .unwrap_err();
        assert!(err.to_string().contains("has no ExpirationDate"), "{err}");
    }
```

- [ ] **Step 3: Run to confirm red**

Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-core forged_plaintext_profile`
Expected: FAIL to compile — `ProfileRequest`, `validate_and_extract_profile`,
`SignedProfile` targets do not exist.

- [ ] **Step 4: Implement** in `crates/zsign-core/src/provisioning.rs`

1. Module header and imports (replace the current `use crate::{Error, Result};`
   block; keep the existing module doc, extending it):

```rust
//! Provisioning profile parsing and validation utilities.
//!
//! Profiles are CMS-signed XML plists. [`extract_entitlements_from_profile`]
//! is the historical unvalidated extractor (raw byte scan — kept byte-for-byte
//! for existing consumers); [`validate_and_extract_profile`] verifies the CMS
//! envelope against Apple's roots (or injected anchors) and validates the
//! profile fields before any consumer touches them.

use crate::crypto::cms_verify::{self, TrustAnchors};
use crate::{Error, Result};
use std::time::SystemTime;
use time::OffsetDateTime;
```

2. The request struct (place before `validate_and_extract_profile`):

```rust
/// Inputs that scope *when* and *against what* a profile is validated.
///
/// Every field is optional: an omitted check simply does not run, so callers
/// validate only the context they have. A bypass (`allow-unsafe`) is a
/// caller-side choice — keep calling [`extract_entitlements_from_profile`] for
/// unvalidated extraction.
///
/// ```ignore
/// let request = ProfileRequest {
///     now: None, // wall clock on native targets
///     expected_team_id: Some("TESTTEAM".into()),
///     target_bundle_id: Some("com.example.app".into()),
///     ..Default::default()
/// };
/// let info = validate_and_extract_profile(&profile_bytes, &request)?;
/// ```
#[derive(Debug, Clone, Default)]
pub struct ProfileRequest {
    /// Verification instant consumed by both the CMS chain check and the
    /// profile window check — one instant for both, so a caller cannot
    /// validate the chain at one time and the window at another. `None` falls
    /// back to the wall clock; the wasm32 contract for that fallback is
    /// finalized with queue item 4 in Task 4.
    pub now: Option<OffsetDateTime>,
    /// Trust anchors for the profile's CMS chain. `None` uses Apple's root —
    /// production profiles are Apple-signed.
    pub anchors: Option<TrustAnchors>,
    /// Team ID of the signing certificate; the profile must belong to it.
    pub expected_team_id: Option<String>,
    /// Target app's `CFBundleIdentifier`; the profile App ID must cover it.
    pub target_bundle_id: Option<String>,
    /// Target device UDID; must be listed in `ProvisionedDevices` unless the
    /// profile carries `ProvisionsAllDevices`.
    pub target_device_udid: Option<String>,
}
```

3. The result struct:

```rust
/// A CMS-verified, validated provisioning profile.
#[derive(Debug, Clone)]
pub struct ProfileInfo {
    /// `Name` — present and validated.
    pub name: String,
    /// `TeamIdentifier` array (empty when the key is absent).
    pub team_identifiers: Vec<String>,
    /// `Entitlements['application-identifier']`, falling back to
    /// `Entitlements['com.apple.application-identifier']` (macOS).
    pub application_identifier: Option<String>,
    /// `CreationDate`, when present.
    pub creation_date: Option<OffsetDateTime>,
    /// `ExpirationDate` — present and validated against the request clock.
    pub expiration_date: OffsetDateTime,
    /// `ProvisionsAllDevices` (Enterprise / Developer ID profiles).
    pub provisions_all_devices: bool,
    /// `ProvisionedDevices`, when present.
    pub provisioned_devices: Option<Vec<String>>,
    /// Entitlements re-serialized as XML plist — the same bytes
    /// [`extract_entitlements_from_profile`] would return.
    pub entitlements_xml: Option<Vec<u8>>,
    /// CMS verification report: signer, chain, warnings (e.g. SHA-1 digests).
    pub cms: cms_verify::CmsVerifyReport,
}
```

4. The validated entry point:

```rust
/// Verifies a provisioning profile's CMS envelope and validates its fields.
///
/// Checks, in order: CMS signature/chain/anchoring at the request instant;
/// required `Name`/`ExpirationDate`; `CreationDate <= now <= ExpirationDate`;
/// team match (when `expected_team_id` is set); App-ID coverage of
/// `target_bundle_id` (when set); device registration for
/// `target_device_udid` (when set — `ProvisionsAllDevices` takes precedence
/// over the device list, and an App Store profile carries neither key).
///
/// # Errors
///
/// Returns [`Error::Verification`] for a malformed CMS envelope,
/// [`Error::ProvisioningProfile`] for every failed check — messages name the
/// profile, the offending value, and the remedy.
pub fn validate_and_extract_profile(
    profile_data: &[u8],
    request: &ProfileRequest,
) -> Result<ProfileInfo> {
    let now = request.now.unwrap_or_else(cms_verify::time_now);
    let envelope = match &request.anchors {
        Some(anchors) => {
            cms_verify::verify_cms_envelope_with_anchors(profile_data, Some(now), anchors)?
        }
        None => cms_verify::verify_cms_envelope(profile_data, Some(now))?,
    };
    if !envelope.report.valid {
        return Err(Error::ProvisioningProfile(format!(
            "CMS verification failed: {}",
            envelope.report.errors.join("; ")
        )));
    }
    let content = envelope.content.ok_or_else(|| {
        Error::ProvisioningProfile(
            "Profile CMS verification produced no attached plist content".into(),
        )
    })?;
    let value: plist::Value = plist::from_bytes(&content)
        .map_err(|e| Error::ProvisioningProfile(format!("Failed to parse profile plist: {e}")))?;
    let dict = value
        .as_dictionary()
        .ok_or_else(|| Error::ProvisioningProfile("Profile plist is not a dictionary".into()))?;

    let name = required_string(dict, "Name")?;
    let expiration_date = required_date(dict, "ExpirationDate", &name)?;
    let creation_date = optional_date(dict, "CreationDate", &name)?;
    let team_identifiers = string_array(dict, "TeamIdentifier")?;
    let application_identifier = entitlement_string(dict, "application-identifier")
        .or_else(|| entitlement_string(dict, "com.apple.application-identifier"));
    let provisions_all_devices = match dict.get("ProvisionsAllDevices") {
        None => false,
        Some(v) => v.as_boolean().ok_or_else(|| {
            Error::ProvisioningProfile(format!(
                "Provisioning profile \"{name}\" has a non-boolean ProvisionsAllDevices"
            ))
        })?,
    };
    let provisioned_devices = match dict.get("ProvisionedDevices") {
        None => None,
        Some(v) => Some(string_values(v, "ProvisionedDevices")?),
    };

    if now > expiration_date {
        return Err(Error::ProvisioningProfile(format!(
            "Provisioning profile \"{name}\" expired on {}; renew it in the Apple developer \
             portal (Certificates, Identifiers & Profiles) and re-download it",
            fmt_date(expiration_date)
        )));
    }
    if let Some(created) = creation_date {
        if now < created {
            return Err(Error::ProvisioningProfile(format!(
                "Provisioning profile \"{name}\" is not valid until {}; wait until then, or \
                 re-download it from the Apple developer portal",
                fmt_date(created)
            )));
        }
    }

    if let Some(expected) = &request.expected_team_id {
        let mut teams = team_identifiers.clone();
        for t in string_array(dict, "ApplicationIdentifierPrefix")? {
            if !teams.contains(&t) {
                teams.push(t);
            }
        }
        if let Some(t) = entitlement_string(dict, "com.apple.developer.team-identifier") {
            if !teams.contains(&t) {
                teams.push(t);
            }
        }
        if !teams.iter().any(|t| t == expected) {
            let listed = if teams.is_empty() {
                "no team identifiers".to_string()
            } else {
                teams.join(", ")
            };
            return Err(Error::ProvisioningProfile(format!(
                "Provisioning profile \"{name}\" is for {listed}, not the signing team {expected}"
            )));
        }
    }

    if let Some(target) = &request.target_bundle_id {
        if target.contains('*') {
            return Err(Error::ProvisioningProfile(format!(
                "Target bundle identifier \"{target}\" must not contain a wildcard"
            )));
        }
        let app_id = application_identifier.clone().ok_or_else(|| {
            Error::ProvisioningProfile(format!(
                "Provisioning profile \"{name}\" has no application-identifier entitlement; \
                 cannot check coverage of \"{target}\""
            ))
        })?;
        let app_id_prefix = string_array(dict, "ApplicationIdentifierPrefix")?
            .into_iter()
            .next()
            .or_else(|| team_identifiers.first().cloned());
        if !app_id_covers(&app_id, app_id_prefix.as_deref(), target)? {
            return Err(Error::ProvisioningProfile(format!(
                "Provisioning profile \"{name}\" App ID {app_id} does not cover bundle \
                 identifier {target}; use a profile whose App ID matches it"
            )));
        }
    }

    if !provisions_all_devices {
        if let (Some(udid), Some(devices)) =
            (&request.target_device_udid, &provisioned_devices)
        {
            if !devices.iter().any(|d| d == udid) {
                return Err(Error::ProvisioningProfile(format!(
                    "Device {udid} is not registered for provisioning profile \"{name}\"; \
                     register it in the Apple developer portal and re-download the profile"
                )));
            }
        }
    }

    let entitlements_xml = entitlements_to_xml(dict)?;

    Ok(ProfileInfo {
        name,
        team_identifiers,
        application_identifier,
        creation_date,
        expiration_date,
        provisions_all_devices,
        provisioned_devices,
        entitlements_xml,
        cms: envelope.report,
    })
}
```

5. Private helpers (place below the entry point):

```rust
fn required_string(dict: &plist::Dictionary, key: &str) -> Result<String> {
    dict.get(key)
        .and_then(|v| v.as_string())
        .map(str::to_owned)
        .ok_or_else(|| Error::ProvisioningProfile(format!("Profile is missing the {key}")))
}

fn required_date(dict: &plist::Dictionary, key: &str, name: &str) -> Result<OffsetDateTime> {
    let date = dict
        .get(key)
        .and_then(|v| v.as_date())
        .ok_or_else(|| {
            Error::ProvisioningProfile(format!("Provisioning profile \"{name}\" has no {key}"))
        })?;
    plist_date_to_offset(date).ok_or_else(|| {
        Error::ProvisioningProfile(format!(
            "Provisioning profile \"{name}\" has an unparseable {key}"
        ))
    })
}

fn optional_date(dict: &plist::Dictionary, key: &str, name: &str) -> Result<Option<OffsetDateTime>> {
    match dict.get(key) {
        None => Ok(None),
        Some(v) => {
            let date = v.as_date().ok_or_else(|| {
                Error::ProvisioningProfile(format!(
                    "Provisioning profile \"{name}\" has a non-date {key}"
                ))
            })?;
            plist_date_to_offset(date)
                .map(Some)
                .ok_or_else(|| {
                    Error::ProvisioningProfile(format!(
                        "Provisioning profile \"{name}\" has an unparseable {key}"
                    ))
                })
        }
    }
}

/// `plist::Date` (a `SystemTime` newtype, `Copy`) in RFC 3339; `None` before
/// 1970 or outside the `time` crate's range — no real profile predates 1970.
fn plist_date_to_offset(date: plist::Date) -> Option<OffsetDateTime> {
    let system: SystemTime = date.into();
    let seconds = system
        .duration_since(SystemTime::UNIX_EPOCH)
        .ok()?
        .as_secs() as i64;
    OffsetDateTime::from_unix_timestamp(seconds).ok()
}

fn fmt_date(t: OffsetDateTime) -> String {
    t.format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| t.unix_timestamp().to_string())
}

fn string_array(dict: &plist::Dictionary, key: &str) -> Result<Vec<String>> {
    match dict.get(key) {
        None => Ok(Vec::new()),
        Some(v) => string_values(v, key),
    }
}

fn string_values(value: &plist::Value, key: &str) -> Result<Vec<String>> {
    let arr = value
        .as_array()
        .ok_or_else(|| Error::ProvisioningProfile(format!("Profile {key} is not an array")))?;
    arr.iter()
        .map(|item| {
            item.as_string().map(str::to_owned).ok_or_else(|| {
                Error::ProvisioningProfile(format!("Profile {key} contains a non-string entry"))
            })
        })
        .collect()
}

fn entitlement_string(dict: &plist::Dictionary, key: &str) -> Option<String> {
    dict.get("Entitlements")?
        .as_dictionary()?
        .get(key)?
        .as_string()
        .map(str::to_owned)
}

/// Apple App IDs are `PREFIX.search`: `PREFIX` is the fixed team prefix
/// (`ApplicationIdentifierPrefix`/`TeamIdentifier`) and `search` is either
/// exact or a single trailing `*` (QA1713 / Team Administration Guide). The
/// candidate compared against the profile is the full `PREFIX.bundle_id`
/// (design §4.3) — a bundle id under any other prefix never matches.
fn app_id_covers(app_id: &str, app_id_prefix: Option<&str>, bundle_id: &str) -> Result<bool> {
    let prefix = app_id_prefix.ok_or_else(|| {
        Error::ProvisioningProfile(
            "Profile has no App ID prefix (ApplicationIdentifierPrefix or TeamIdentifier); \
             cannot check bundle coverage"
                .into(),
        )
    })?;
    if prefix.is_empty() || prefix.contains('.') || prefix.contains('*') {
        return Err(Error::ProvisioningProfile(format!(
            "App ID prefix \"{prefix}\" is malformed: a team prefix is a fixed, wildcard-free \
             string without dots"
        )));
    }
    let rest = app_id
        .strip_prefix(prefix)
        .and_then(|r| r.strip_prefix('.'))
        .ok_or_else(|| {
            Error::ProvisioningProfile(format!(
                "App ID \"{app_id}\" does not start with the profile's App ID prefix {prefix}"
            ))
        })?;
    let stars = rest.matches('*').count();
    if stars == 0 {
        return Ok(rest == bundle_id);
    }
    if stars > 1 || !rest.ends_with('*') {
        return Err(Error::ProvisioningProfile(format!(
            "App ID \"{app_id}\" contains a wildcard Apple cannot produce: a single trailing \
             '*' is required"
        )));
    }
    Ok(bundle_id.starts_with(&rest[..rest.len() - 1]))
}

/// Serializes the `Entitlements` dictionary back to XML plist bytes, or
/// `Ok(None)` when the profile carries no `Entitlements` key.
fn entitlements_to_xml(dict: &plist::Dictionary) -> Result<Option<Vec<u8>>> {
    let Some(ent) = dict.get("Entitlements") else {
        return Ok(None);
    };
    let mut buf = Vec::new();
    plist::to_writer_xml(&mut buf, ent).map_err(|e| {
        Error::ProvisioningProfile(format!("Failed to serialize entitlements: {}", e))
    })?;
    Ok(Some(buf))
}
```

6. Keep `extract_entitlements_from_profile` (raw scan, boundaries, error text —
   all unchanged), but extend its doc with:

```rust
/// This is the historical unvalidated extractor: it byte-scans for the plist
/// and trusts whatever it finds — no CMS verification, no expiry check. Callers
/// that must reject forged or expired profiles use
/// [`validate_and_extract_profile`].
```

   and replace its tail (plist dictionary lookup + Entitlements + XML
   serialization, current :30-41) with `entitlements_to_xml(dict)` — behavior
   identical: `Ok(None)` without `Entitlements`, same serialization error text.

7. `crates/zsign-core/src/lib.rs` (:16): add next to the existing re-export:

```rust
pub use provisioning::{validate_and_extract_profile, ProfileInfo, ProfileRequest};
```

- [ ] **Step 5: Scoped gate (green)**

Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-core provisioning -- --skip test_ipa_signing_is_deterministic`
Expected: the three legacy tests plus all new tests pass.

- [ ] **Step 6: Commit**

`git add -u crates/zsign-core/src/provisioning.rs crates/zsign-core/src/lib.rs crates/zsign-core/Cargo.toml && git commit -m "feat(zsign-core): validate provisioning profiles before use (ZSN-3)"`

---

### Task 4: Queue item 4 — wasm32 clock contract (`resolve_now`) and wall-clock-independence tests

**Files:**
- Modify: `crates/zsign-core/src/crypto/cms_verify.rs` (`resolve_now`, the
  envelope entry's `now` default, `time_now` doc)
- Modify: `crates/zsign-core/src/provisioning.rs` (the single `now`
  resolution + `ProfileRequest.now` doc)
- Test: inline `mod tests` in both files

**Intent:** deliver item 4's public contract now that items 1-3 exist: an
explicit timestamp parameter with a sensible native default, a hard error
instead of a silently wrong fixed timestamp on wasm32, the documented
`Date.now() / 1000` contract, and tests proving cert/profile expiry depend
only on the injected `now` — never on the wall clock.

- [ ] **Step 1: Write the failing tests**

Append the first two to `mod tests` in `crates/zsign-core/src/crypto/cms_verify.rs`:

```rust
    #[test]
    fn resolve_now_defaults_on_native_and_honors_explicit_values() {
        let fallback =
            resolve_now(None).expect("native builds default to the wall clock");
        let drift = fallback - time::OffsetDateTime::now_utc();
        assert!(
            drift > time::Duration::seconds(-30) && drift < time::Duration::seconds(30),
            "fallback drift: {drift:?}"
        );
        let explicit = at(T_2026_APR);
        assert_eq!(resolve_now(Some(explicit)).unwrap(), explicit);
    }

    #[test]
    fn expired_signer_cert_is_clock_dependent_not_wall_clock_dependent() {
        let (root, leaf, leaf_key, anchors) =
            fixed_validity_chain(T_2026_START as u64, T_2026_JUL as u64, None);
        let envelope = sign_attached_content(
            sample_plist(),
            &leaf,
            &[root],
            &leaf_key,
            TestDigest::Sha256,
        )
        .unwrap();

        let inside =
            verify_cms_envelope_with_anchors(&envelope, Some(at(T_2026_APR)), &anchors)
                .unwrap();
        assert!(inside.report.valid, "errors: {:?}", inside.report.errors);

        let after =
            verify_cms_envelope_with_anchors(&envelope, Some(at(T_2027)), &anchors)
                .unwrap();
        assert!(!after.report.valid);
        assert!(
            after.report.errors.iter().any(|e| e.contains("outside validity")),
            "errors: {:?}",
            after.report.errors
        );
    }
```

Append to `mod tests` in `crates/zsign-core/src/provisioning.rs`:

```rust
    #[test]
    fn profile_window_is_driven_by_request_now_not_wall_clock() {
        let sp = signed_profile(&plist_xml(""));
        // Fixed instant inside the 2026-01-01..2026-07-01 window — passes
        // whatever today's date is.
        assert!(validate_and_extract_profile(&sp.data, &request(&sp, T_2026_APR)).is_ok());
        // One instant after ExpirationDate — rejected.
        let err = validate_and_extract_profile(&sp.data, &request(&sp, T_2027)).unwrap_err();
        assert!(err.to_string().contains("expired"), "{err}");
        // One instant before CreationDate — rejected as not yet valid.
        let err = validate_and_extract_profile(&sp.data, &request(&sp, T_2025)).unwrap_err();
        assert!(err.to_string().contains("not valid until"), "{err}");
    }
```

- [ ] **Step 2: Run to confirm red**

Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-core resolve_now_defaults`
Expected: FAIL to compile — `resolve_now` does not exist.

- [ ] **Step 3: Implement**

In `crates/zsign-core/src/crypto/cms_verify.rs`:

1. Add next to `time_now` (:1354):

```rust
/// Resolves the verification instant for APIs that accept an explicit clock.
///
/// `None` falls back to the wall clock on native targets. wasm32 has no
/// reliable clock (see [`time_now`]), so `None` there is a hard error instead
/// of a silently wrong fixed timestamp: browser callers must pass
/// `Date.now() / 1000`.
pub(crate) fn resolve_now(now: Option<time::OffsetDateTime>) -> Result<time::OffsetDateTime> {
    match now {
        Some(t) => Ok(t),
        None => {
            #[cfg(not(target_arch = "wasm32"))]
            {
                Ok(time_now())
            }
            #[cfg(target_arch = "wasm32")]
            {
                Err(Error::Verification(
                    "an explicit `now` timestamp is required on wasm32 (no wall \
                     clock available); pass Date.now() / 1000"
                        .into(),
                ))
            }
        }
    }
}
```

2. Rewrite the `time_now` comment (:1355-1356): it now backs only the legacy
   `verify_code_signature*` entries and `resolve_now`'s native arm; every new
   API takes `now: Option<OffsetDateTime>` and resolves it through
   `resolve_now`.

3. In `verify_cms_envelope_with_anchors`, replace
   `let now = now.unwrap_or_else(time_now);` with `let now = resolve_now(now)?;`
   and extend the `verify_cms_envelope` doc: “`None` uses the wall clock on
   native targets and is an error on wasm32 — browser callers must pass
   `Date.now() / 1000`.”

In `crates/zsign-core/src/provisioning.rs`:

4. Replace `let now = request.now.unwrap_or_else(cms_verify::time_now);` with
   `let now = cms_verify::resolve_now(request.now)?;` and restore the
   `ProfileRequest.now` doc sentence: “`None` uses the wall clock on native
   targets and is an error on wasm32 (pass `Date.now() / 1000` there)” —
   including the request example comment.

- [ ] **Step 4: Scoped gate (green)**

Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-core -- --skip test_ipa_signing_is_deterministic`
Expected: all `zsign-core` tests pass, including the three new ones (the
wasm32 arm of `resolve_now` is compile-checked later by the Task 5 wasm
`cargo check`).

- [ ] **Step 5: Commit**

`git add -u crates/zsign-core/src/crypto/cms_verify.rs crates/zsign-core/src/provisioning.rs && git commit -m "feat(zsign-core): require explicit verification clock on wasm32 (ZSN-3)"`

---

### Task 5: Full-suite gates and consumer compile proof

**Files:** none changed; verification only.

- [ ] **Step 1: Workspace tests (ZSN-15 skip applies everywhere)**

Run: `TMPDIR=$PWD/.tmptmp cargo test --workspace -- --skip test_ipa_signing_is_deterministic`
Expected: green; baseline counts were 182 `zsign-core` / 89 `zsign-rs` tests
plus this plan's additions (3 Task-1 + 7 Task-2 + 16 Task-3 + 3 Task-4 = 29, exact
numbers recorded in the lane report). Any other pre-existing failure is a
blocker — stop and diagnose (skill: systematic-debugging).

- [ ] **Step 2: wasm32 compile proof (the clock contract must build)**

Run: `TMPDIR=$PWD/.tmptmp cargo check -p zsign-wasm --target wasm32-unknown-unknown`
Expected: OK (the target may be absent on this machine — attempt once, record
the outcome honestly; CI runs the same check). This is what proves
`resolve_now`'s wasm arm compiles.

- [ ] **Step 3: Consumer compile proof**

Run: `TMPDIR=$PWD/.tmptmp cargo check --workspace`
Expected: OK — `extract_entitlements_from_profile` signature untouched, so
`zsign/src/builder.rs`, `zsign/src/ipa/mod.rs`, `zsign-wasm`, and
`zsign-cli` compile without edits (their adoption is later lanes' work).

- [ ] **Step 4: Verify the retained legacy contract**

Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-core test_extract_entitlements -- --exact` is
not a single name — instead run the three names explicitly:
`TMPDIR=$PWD/.tmptmp cargo test -p zsign-core test_extract_entitlements_no_xml && TMPDIR=$PWD/.tmptmp cargo test -p zsign-core test_extract_entitlements_no_entitlements_key && TMPDIR=$PWD/.tmptmp cargo test -p zsign-core test_extract_entitlements_valid`
Expected: 3 passed, unchanged from baseline (this is the ZSN-3 rule that keeps
`zsign-wasm` and the facade consumers working).

---

## Self-review (plan vs spec)

- **Queue order:** Task 1+2 = queue item 1 (their internal `now`/purpose
  threading is item 1's substrate); Task 3 = queue items 2+3 (model, validation,
  retained legacy API with its regression tests); Task 4 = queue item 4
  (`resolve_now`, wasm32 contract, clock-independence tests); Task 5 = gates.
- **Spec coverage:** design §4 architecture → Tasks 1-4; §4.1 purpose policy →
  Task 1; §4.2 digest agility (SHA-1|SHA-256 in profile mode, SHA-256-only in
  code mode) → Task 2 + its `code_signature_mode_still_rejects_sha1_signer_digest`;
  §4.3 prefix-based wildcard matching → Task 3 (`app_id_covers` +
  `app_id_under_a_foreign_prefix_is_rejected`); §4.4 clock plumbing → Task 4;
  design §5 tests → Task 2 (forged/dual-pin/tamper/SHA-1),
  Task 3 (expiry/team/union/app-id/device/retained), Task 4 (cert+profile
  window at injected `now`); retained API (queue rule 3) → Task 3 + Task 5
  step 4; wasm contract (queue item 4) → Task 4 + Task 5 step 2.
- **Hostname:** design known-items records it as unimplementable (no field in
  the format); no task implements it — deliberate, not a gap.
- **Placeholder scan:** no TBD/TODO; every step shows concrete code or commands;
  no signature-only blocks.
- **Type consistency:** `fixed_validity_chain -> (root, leaf, leaf_key, anchors)`
  used identically in Tasks 1/2/4; `TestDigest` + `sign_attached_content` /
  `sign_detached_content(content, cert, chain, key, digest)` match cms.rs and
  every call site; `verify_signed_data(cms, content, mode, anchors, now)` matches
  both call sites; `app_id_covers(app_id, prefix, bundle_id)` matches its call
  site and tests; `ProfileRequest`/`ProfileInfo` field names match tests and
  implementation; `resolve_now` is the single clock resolver in Task 4.
