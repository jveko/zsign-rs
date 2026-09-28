# Apple Root Anchoring (ZSN-96) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development (recommended) with dispatching-parallel-agents for independent tasks to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make every public credential loader reject certificate chains that do not
terminate at the Apple Root CA, with test-only unanchored constructors preserving
self-issued fixture tests.

**Architecture:** Assembly (`build_chain_from_leaf`) gains root completion; a new
`require_anchored_chain` in `crates/zsign-core/src/crypto/cert.rs` reuses the
verify-side `verify_chain` (made `pub(crate)`) as the load-time policy; the
constructors `from_p12`/`from_pem` always enforce, while
`from_p12_unanchored`/`from_pem_unanchored`-style constructors exist only under
`cfg(any(test, feature = "test-fixtures"))`. Sibling crates (wasm, CLI) migrate
their fixture tests; the CLI keeps production-loader coverage via a new subprocess
test. Full rationale: `docs/superpowers/specs/2026-09-28-apple-root-anchor-design.md`.

**Tech Stack:** Rust 2021 / MSRV 1.88, x509-cert 0.2.5, in-tree
`cms_verify::{verify_chain, TrustAnchors, verify_cert_signature}`. No new
dependencies.

---

## Conventions (apply to every task)

- Working dir: `/home/dimaz/workspace/projects/zsign-rs/.worktrees/zsn-96-apple-root-anchor`.
- Scoped test gate for every task (never the workspace gate while iterating):

  ```bash
  mkdir -p target/tmp .tmptmp && TMPDIR=$PWD/target/tmp cargo test -p <crate>
  cargo clippy -p <crate> --all-targets -- -D warnings
  cargo fmt --all -- --check
  ```

  NEVER delete `target/tmp` or `.tmptmp`; they are required by every gate.
- No ticket IDs in code comments; comments explain behavior only. No `println!`/
  `eprintln!` in `src/`, no TODOs/stubs. Commit subjects may carry `(ZSN-96)`.
- Implementers do NOT commit; the controller commits after the scoped gate and
  reviews pass.
- Exact line numbers drift — locate by symbol name.

## Batch structure

- **Batch 1 (sequential): Task 1** — everything in `zsign-core` lands first; wasm
  and CLI tests are red against it until Batch 2.
- **Batch 2 (parallel, file-isolated): Task 2 + Task 3** — `zsign-wasm/src/lib.rs`
  vs `zsign-cli/src/main.rs`, both only depend on Task 1 outputs, no shared files.
- **Task 4 (controller, sequential):** workspace gates.

---

### Task 1: Core anchoring in `zsign-core`

**Files:**
- Modify: `crates/zsign-core/src/crypto/cert.rs`
- Modify: `crates/zsign-core/src/crypto/cms_verify.rs` (visibility only)
- Modify: `crates/zsign-core/src/crypto/keychain.rs` (test build routing)
- Create: `crates/zsign-core/src/crypto/fixtures/evil_root_chain.p12`

- [ ] **Step 1.1: Generate the evil-chain fixture** (OpenSSL 3.6.3, same generator
  convention as every committed fixture; commands will be recorded verbatim in the
  lane's final report):

  ```bash
  mkdir -p .tmptmp
  d=.tmptmp/evil-gen; mkdir -p "$d"
  openssl req -x509 -newkey rsa:2048 -nodes -keyout "$d/root.key" -out "$d/root.pem" \
    -days 3650 -sha256 -subj "/CN=Evil Root CA" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign"
  openssl req -newkey rsa:2048 -nodes -keyout "$d/int.key" -out "$d/int.csr" \
    -subj "/CN=Evil Intermediate CA"
  printf '%s\n' "basicConstraints=critical,CA:TRUE" "keyUsage=critical,keyCertSign,cRLSign" > "$d/int.ext"
  openssl x509 -req -in "$d/int.csr" -CA "$d/root.pem" -CAkey "$d/root.key" -CAcreateserial \
    -out "$d/int.pem" -days 3650 -sha256 -extfile "$d/int.ext"
  openssl req -newkey rsa:2048 -nodes -keyout "$d/leaf.key" -out "$d/leaf.csr" \
    -subj "/CN=Evil Code Signing/OU=TESTTEAM"
  printf '%s\n' "basicConstraints=critical,CA:FALSE" "keyUsage=critical,digitalSignature" \
    "extendedKeyUsage=critical,codeSigning" > "$d/leaf.ext"
  openssl x509 -req -in "$d/leaf.csr" -CA "$d/int.pem" -CAkey "$d/int.key" -CAcreateserial \
    -out "$d/leaf.pem" -days 3650 -sha256 -extfile "$d/leaf.ext"
  cat "$d/int.pem" "$d/root.pem" > "$d/chain.pem"
  openssl pkcs12 -export -inkey "$d/leaf.key" -in "$d/leaf.pem" -certfile "$d/chain.pem" \
    -passout pass:testpassword -out crates/zsign-core/src/crypto/fixtures/evil_root_chain.p12
  ```

  Verify: `openssl pkcs12 -in crates/zsign-core/src/crypto/fixtures/evil_root_chain.p12 -nokeys -passin pass:testpassword 2>/dev/null | grep -c "BEGIN CERTIFICATE"` → `3`.
  The private-key commit gate refuses private-key *PEM files*; `.p12` fixtures
  containing keys are the established committed convention (`identity_single.p12`
  et al.), so this fixture commits normally. If the pre-commit hook rejects it
  anyway, STOP and report — do not bypass the hook.

- [ ] **Step 1.2: Write the failing regression tests** (Tester) — in the `tests`
  module of `crates/zsign-core/src/crypto/cert.rs`: first refactor `build_cert`
  so the issuer can be given as a parsed `Name` (needed for exact DER equality
  with the embedded root's subject): rename the existing body to
  `build_cert_issuer_name(subject: &str, issuer: &x509_cert::name::Name,
  subject_key, issuer_key, validity, eku)` (the body already does
  `Name::from_str(issuer)` — replace that line with the parameter), and leave
  `build_cert` as a wrapper:

  ```rust
  fn build_cert(
      subject: &str,
      issuer: &str,
      subject_key: &rsa::RsaPrivateKey,
      issuer_key: &rsa::RsaPrivateKey,
      validity: Validity,
      eku: Option<ExtendedKeyUsage>,
  ) -> Certificate {
      build_cert_issuer_name(
          subject,
          &x509_cert::name::Name::from_str(issuer).unwrap(),
          subject_key,
          issuer_key,
          validity,
          eku,
      )
  }
  ```

  (`use std::str::FromStr;` is already imported inside the builder helper). Then
  append the new fixture const and tests:

  ```rust
  const EVIL_CHAIN: &[u8] = include_bytes!("fixtures/evil_root_chain.p12");

  #[test]
  fn from_p12_rejects_evil_root_chain() {
      let res = SigningCredentials::from_p12(EVIL_CHAIN, PASS);
      assert!(
          matches!(&res, Err(Error::Certificate(m))
              if m.contains("Evil") && m.contains("not anchored to a trusted root")),
          "self-issued chain must be rejected, got {:?}",
          res.as_ref().err()
      );
  }

  #[test]
  fn from_p12_rejects_self_issued_identity() {
      let res = SigningCredentials::from_p12(IDENTITY_SINGLE, PASS);
      assert!(
          matches!(&res, Err(Error::Certificate(m))
              if m.contains("not anchored to a trusted root")),
          "self-signed leaf must be rejected, got {:?}",
          res.as_ref().err()
      );
  }

  #[test]
  fn from_pem_rejects_self_signed_leaf() {
      let key = fresh_2048();
      let cert = build_cert("CN=zsn unanchored", "CN=zsn unanchored", &key, &key,
                            present(), Some(code_signing_eku()));
      let res = load(&cert, &key);
      assert!(
          matches!(&res, Err(Error::Certificate(m))
              if m.contains("not anchored to a trusted root")),
          "got {:?}",
          res.as_ref().err()
      );
  }

  #[test]
  fn build_chain_appends_embedded_root_for_direct_issue() {
      let root = Certificate::from_pem(crate::crypto::assets::APPLE_ROOT_CA_CERT.as_bytes())
          .expect("embedded root parses");
      let key = fresh_2048();
      let cert = build_cert_issuer_name(
          "CN=zsn direct",
          &root.tbs_certificate.subject,
          &key, &key, present(), Some(code_signing_eku()),
      );
      let chain = build_chain_from_leaf(&cert, vec![]);
      assert_eq!(chain.len(), 1, "dangling issuer at the Apple Root CA must complete the chain");
      assert!(chain.iter().any(is_apple_root));
  }
  ```

- [ ] **Step 1.3: Run the tests, confirm RED.**

  Run: `mkdir -p target/tmp .tmptmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-core`
  Expected: the three new load tests (`from_p12_rejects_evil_root_chain`,
  `from_p12_rejects_self_issued_identity`, `from_pem_rejects_self_signed_leaf`)
  fail with `got Ok(...)`, and `build_chain_appends_embedded_root_for_direct_issue`
  fails on the chain length (the
  remaining suite still passes — enforcement does not exist yet). Record the
  failing test names as the red evidence.

- [ ] **Step 1.4: Implement enforcement** (Implementer).

  a) `crates/zsign-core/src/crypto/cms_verify.rs` — visibility only, no logic:
     - `fn verify_chain(` → `pub(crate) fn verify_chain(`
     - `struct ChainOutcome {` → `pub(crate) struct ChainOutcome`, and make each
       field `pub(crate)` (`ok`, `anchored`, `subjects`, `reason`, `warnings`).
     - `enum SignerPurpose {` → `pub(crate) enum SignerPurpose {`.
     Extend `verify_chain`'s doc comment with one line: also used by the credential
     load path to require an Apple-root-anchored chain.

  b) `crates/zsign-core/src/crypto/cert.rs` — add next to
     `build_chain_from_leaf`:

  ```rust
  /// Requires `chain` to pass the verify-side walk and terminate at one of
  /// `anchors`: every link signed by its parent, intermediates valid CAs, and
  /// the terminus self-signed with a pinned anchor key. Fail-closed — any
  /// structural or trust failure names the unanchored leaf.
  fn require_anchored_chain(
      leaf: &Certificate,
      chain: &[Certificate],
      anchors: &super::cms_verify::TrustAnchors,
  ) -> Result<()> {
      let outcome = super::cms_verify::verify_chain(
          chain,
          leaf,
          anchors,
          time_now(),
          super::cms_verify::SignerPurpose::CodeSigning,
      );
      if outcome.ok && outcome.anchored {
          return Ok(());
      }
      let detail = outcome.reason.unwrap_or_else(|| {
          "certificate chain is not anchored to a trusted root".to_string()
      });
      Err(Error::Certificate(format!(
          "signing certificate \"{}\": {}",
          leaf.tbs_certificate.subject, detail
      )))
  }
  ```

  c) Thread an anchors parameter through the private loaders (no behavior change
     for existing callers other than the new enforcement):

  - Rename the body of `from_p12` to `fn load_p12(p12_data: &[u8], password: &str,
    anchors: Option<&super::cms_verify::TrustAnchors>) -> Result<Self>`; its tail
    becomes `Self::finish_p12(decoded, certificate, rest, anchors)`.
  - `from_p12` becomes:

    ```rust
    pub fn from_p12(p12_data: &[u8], password: &str) -> Result<Self> {
        Self::load_p12(p12_data, password, Some(&TrustAnchors::apple_root()?))
    }
    ```

    (add `use super::cms_verify::TrustAnchors;` following the file's import style).
  - `finish_p12` gains `anchors: Option<&TrustAnchors>`; after
    `build_chain_from_leaf` insert:

    ```rust
    if let Some(anchors) = anchors {
        require_anchored_chain(&certificate, &cert_chain, anchors)?;
    }
    ```

    and its doc comment gains: "When `anchors` is `Some`, the assembled chain must
    terminate at one of them."
  - `from_p12_with_leaf_sha1`: rename body to a private
    `from_p12_with_leaf_sha1_impl(..., anchors: Option<&TrustAnchors>)` (keep
    `#[cfg(not(target_arch = "wasm32"))]`), public wrapper passes
    `Some(&TrustAnchors::apple_root()?)`.
  - Rename the body of `from_pem` to `fn load_pem(cert_pem: &[u8], key_pem: &[u8],
    password: Option<&str>, anchors: Option<&TrustAnchors>) -> Result<Self>`;
    insert the `if let Some(anchors) { require_anchored_chain(&certificate, &cert_chain, anchors)?; }`
    block **after the `code_signing_policy_violation` check — the last check before
    the final `Ok(Self { ... })`, NOT after `build_chain_from_leaf`** (ordering
    guarantee: policy errors keep precedence over anchoring errors on the PEM route
    too). `from_pem` passes `Some(&TrustAnchors::apple_root()?)`.

  d) Root completion in `build_chain_from_leaf`: replace the
     `has_wwdr && !chain.iter().any(is_apple_root)` block (`cert.rs:376-380`, the
     append block — the `has_wwdr` binding itself is at 373-375) with:

  ```rust
  // Complete the chain at the embedded Apple Root CA whenever the walk dangles
  // at an issuer that names it, whether the last link came from the container
  // or from the WWDR injection above. A name match alone proves nothing — the
  // policy step verifies the final link against this certificate's key.
  let root = Certificate::from_pem(super::assets::APPLE_ROOT_CA_CERT.as_bytes()).ok();
  let complete = match (&root, chain.last().unwrap_or(leaf)) {
      (Some(root), terminal) => {
          terminal.tbs_certificate.subject != terminal.tbs_certificate.issuer
              && terminal.tbs_certificate.issuer == root.tbs_certificate.subject
      }
      _ => false,
  };
  if complete && !chain.iter().any(is_apple_root) {
      if let Some(root) = root {
          chain.push(root);
      }
  }
  ```

     Delete the now-unused `has_wwdr` binding. Update the function's doc comment
     to describe the generalized completion rule (the WWDR-only sentence becomes
     obsolete — replace it, do not leave it).

  e) Test-only constructors (right after `from_p12` / `from_pem` / the
     leaf-sha1 wrapper):

  ```rust
  /// Loads a PKCS#12 container without requiring the certificate chain to
  /// reach the Apple Root CA.
  ///
  /// Exists for test fixtures built from self-issued certificates, which can
  /// never satisfy the anchoring policy. Production callers must use
  /// [`SigningCredentials::from_p12`]; every other load-time check (parse,
  /// identity pairing, key strength, code-signing policy) still applies.
  #[cfg(any(test, feature = "test-fixtures"))]
  pub fn from_p12_unanchored(p12_data: &[u8], password: &str) -> Result<Self> {
      Self::load_p12(p12_data, password, None)
  }
  ```

  ```rust
  /// Loads PEM credentials without requiring the certificate chain to reach
  /// the Apple Root CA. Test fixtures only — see
  /// [`SigningCredentials::from_p12_unanchored`].
  #[cfg(any(test, feature = "test-fixtures"))]
  pub fn from_pem_unanchored(
      cert_pem: &[u8],
      key_pem: &[u8],
      password: Option<&str>,
  ) -> Result<Self> {
      Self::load_pem(cert_pem, key_pem, password, None)
  }
  ```

  ```rust
  /// [`Self::from_p12_with_leaf_sha1`] without the Apple-root anchoring
  /// requirement; test builds only.
  #[cfg(all(test, not(target_arch = "wasm32")))]
  pub(crate) fn from_p12_with_leaf_sha1_unanchored(
      p12_data: &[u8],
      password: &str,
      leaf_sha1: &[u8; 20],
  ) -> Result<Self> {
      Self::from_p12_with_leaf_sha1_impl(p12_data, password, leaf_sha1, None)
  }
  ```

  f) Documentation updates in `cert.rs`:
     - `cert_chain` field doc (`:111-114`): state that chains loaded through the
       public constructors are verified at load time to reach the Apple Root CA.
     - `from_p12` and `from_pem` `# Errors` lists: add "The certificate chain does
       not reach the Apple Root CA (each link must be signed by its parent and the
       terminus must match the embedded Apple root)".
     - Module `//!` intro: one sentence that public loads are Apple-root anchored.
     - `load_p12`/`load_pem`/`finish_p12` doc comments note the `anchors` contract.

- [ ] **Step 1.5: Migrate success-on-self-issued tests to the unanchored
  constructors** (Implementer): in `crates/zsign-core/src/crypto/cert.rs` tests,
  change only the loader call in each of:
  `from_p12_with_leaf_sha1_selects_the_matching_pair`, `from_p12_selects_single_identity_with_empty_chain`,
  `from_pem_self_signed_leaf_yields_empty_chain`, `from_pem_accepts_compliant_leaf`,
  `from_pem_accepts_leaf_without_ku_and_bc`, `from_pem_loads_every_supported_key_form`,
  `from_pem_keeps_the_password_free_pkcs8_path_unchanged`, `from_pem_loads_unencrypted_traditional_keys` — i.e.
  `SigningCredentials::from_p12(` → `from_p12_unanchored(`,
  `SigningCredentials::from_pem(` → `from_pem_unanchored(` (the `load()` helper
  keeps calling `from_pem` — its rejection tests stay on the anchored path; the
  success tests that go through `load()` switch to a `load_unanchored()` helper
  that wraps `from_pem_unanchored`). Add the tiny `load_unanchored` helper beside
  `load`. All error-expecting tests stay on the public anchored constructors —
  including `from_pem_still_pairs_the_decrypted_key_with_the_certificate`
  (`:1603`), which asserts an SPKI-mismatch failure that fires before anchoring
  and needs no migration.

- [ ] **Step 1.6: Route the keychain test pipeline through the unanchored loader.**
  In `crates/zsign-core/src/crypto/keychain.rs`, extract the body of the
  `(|| { ... })()` closure in `load_with` into:

  ```rust
  fn load_pair(
      data: &[u8],
      leaf_sha1: &[u8; 20],
  ) -> Result<crate::crypto::SigningCredentials, KeychainError> {
      #[cfg(test)]
      return crate::crypto::cert::SigningCredentials::from_p12_with_leaf_sha1_unanchored(
          data, "", leaf_sha1,
      )
      .map_err(KeychainError::Credential);
      #[cfg(not(test))]
      crate::crypto::cert::SigningCredentials::from_p12_with_leaf_sha1(data, "", leaf_sha1)
          .map_err(KeychainError::Credential)
  }
  ```

  (The two `#[cfg]` arms are mutually exclusive, so each build sees exactly one
  body: `return` first under `cfg(test)`, tail expression otherwise. Consecutive
  cfg-gated blocks in tail position were also compiled with `rustc --edition 2021
  --test` as a sanity check; the `return` form removes any doubt.)

  and have `load_with` call `runner.export_identities(&path)`, `std::fs::read`,
  then `load_pair(&data, &selected.hash)`. `load_with_selects_one_identity_from_multi_identity_export`
  (`keychain.rs:471`) must stay green unchanged.

- [ ] **Step 1.7: Unit tests for the policy function** (Tester) — in `cert.rs`
  tests, beside the Step 1.2 helper. Add two builder helpers for CA certificates
  (the x509-cert `Profile` enum auto-adds `basicConstraints` and the matching
  `keyUsage` per profile — verified against the vendored 0.2.5 source):

  ```rust
  fn build_root_cert(subject: &str, key: &rsa::RsaPrivateKey, validity: Validity) -> Certificate {
      use spki::EncodePublicKey;
      use std::str::FromStr;
      use x509_cert::builder::{Builder, CertificateBuilder, Profile};
      let spki = SubjectPublicKeyInfoOwned::from_der(
          key.to_public_key().to_public_key_der().unwrap().as_ref(),
      ).unwrap();
      let signer = rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(key.clone());
      CertificateBuilder::new(
          Profile::Root,
          SerialNumber::from(11u32),
          validity,
          x509_cert::name::Name::from_str(subject).unwrap(),
          spki,
          &signer,
      )
      .unwrap()
      .build::<rsa::pkcs1v15::Signature>()
      .unwrap()
  }

  fn build_subca_cert(
      subject: &str,
      issuer: &x509_cert::name::Name,
      subject_key: &rsa::RsaPrivateKey,
      issuer_key: &rsa::RsaPrivateKey,
      validity: Validity,
  ) -> Certificate {
      use spki::EncodePublicKey;
      use std::str::FromStr;
      use x509_cert::builder::{Builder, CertificateBuilder, Profile};
      let spki = SubjectPublicKeyInfoOwned::from_der(
          subject_key.to_public_key().to_public_key_der().unwrap().as_ref(),
      ).unwrap();
      let signer = rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(issuer_key.clone());
      CertificateBuilder::new(
          Profile::SubCA { issuer: issuer.clone(), path_len_constraint: None },
          SerialNumber::from(12u32),
          validity,
          x509_cert::name::Name::from_str(subject).unwrap(),
          spki,
          &signer,
      )
      .unwrap()
      .build::<rsa::pkcs1v15::Signature>()
      .unwrap()
  }
  ```

  Then a shared chain builder plus six self-contained policy tests:

  ```rust
  /// root → int → leaf, all properly signed, with the root and intermediate
  /// keys returned because several tests rebuild one link of the chain.
  fn anchored_test_chain() -> (
      Certificate,
      Certificate,
      Certificate,
      rsa::RsaPrivateKey,
      rsa::RsaPrivateKey,
  ) {
      let root_key = fresh_2048();
      let int_key = fresh_2048();
      let leaf_key = fresh_2048();
      let root = build_root_cert("CN=zsn test root", &root_key, present());
      let int = build_subca_cert(
          "CN=zsn test int",
          &root.tbs_certificate.subject,
          &int_key,
          &root_key,
          present(),
      );
      let leaf = build_cert_issuer_name(
          "CN=zsn leaf",
          &int.tbs_certificate.subject,
          &leaf_key,
          &int_key,
          present(),
          Some(code_signing_eku()),
      );
      (root, int, leaf, root_key, int_key)
  }

  #[test]
  fn require_anchored_chain_accepts_anchor_terminated_chain() {
      let (root, int, leaf, _, _) = anchored_test_chain();
      let anchors = TrustAnchors::from_certificates(vec![root.clone()]);
      let res = require_anchored_chain(&leaf, &[int, root], &anchors);
      assert!(res.is_ok(), "properly anchored chain must be accepted, got {:?}", res.err());
  }

  #[test]
  fn require_anchored_chain_rejects_chain_under_production_anchors() {
      // same well-formed chain; production callers pin the embedded Apple root
      let (root, int, leaf, _, _) = anchored_test_chain();
      let res = require_anchored_chain(&leaf, &[int, root], &TrustAnchors::apple_root().unwrap());
      assert!(
          matches!(&res, Err(Error::Certificate(m)) if m.contains("not anchored")),
          "got {:?}", res.err()
      );
  }

  #[test]
  fn require_anchored_chain_rejects_link_signed_by_the_wrong_key() {
      // the leaf names the intermediate as issuer but was signed by another
      // key; the terminus reaches the injected anchor, so only the link check
      // can produce the failure
      let (root, int, _, _, _) = anchored_test_chain();
      let wrong = fresh_2048();
      let leaf = build_cert_issuer_name(
          "CN=zsn leaf",
          &int.tbs_certificate.subject,
          &wrong,
          &wrong,
          present(),
          Some(code_signing_eku()),
      );
      let anchors = TrustAnchors::from_certificates(vec![root.clone()]);
      let res = require_anchored_chain(&leaf, &[int, root], &anchors);
      assert!(matches!(&res, Err(Error::Certificate(m))
          if m.contains("issuer-signature verification")), "got {:?}", res.err());
  }

  #[test]
  fn require_anchored_chain_rejects_non_ca_intermediate() {
      // a Profile::Leaf certificate acting as the issuer: CA:FALSE, and the
      // basicConstraints check fires before any signature check
      let (root, _, _, root_key, _) = anchored_test_chain();
      let int_key = fresh_2048();
      let leaf_key = fresh_2048();
      let int = build_cert_issuer_name(
          "CN=zsn not a ca",
          &root.tbs_certificate.subject,
          &int_key,
          &root_key,
          present(),
          None,
      );
      let leaf = build_cert_issuer_name(
          "CN=zsn leaf",
          &int.tbs_certificate.subject,
          &leaf_key,
          &int_key,
          present(),
          Some(code_signing_eku()),
      );
      let anchors = TrustAnchors::from_certificates(vec![root.clone()]);
      let res = require_anchored_chain(&leaf, &[int, root], &anchors);
      assert!(matches!(&res, Err(Error::Certificate(m))
          if m.contains("basicConstraints")), "got {:?}", res.err());
  }

  #[test]
  fn require_anchored_chain_rejects_expired_intermediate() {
      // issuer validity (design §6.4) is checked before anything cryptographic
      let (root, _, leaf, root_key, _) = anchored_test_chain();
      let int_key = fresh_2048();
      let int = build_subca_cert(
          "CN=zsn test int",
          &root.tbs_certificate.subject,
          &int_key,
          &root_key,
          window(1_600_000_000, 1_650_000_000),
      );
      let anchors = TrustAnchors::from_certificates(vec![root.clone()]);
      let res = require_anchored_chain(&leaf, &[int, root], &anchors);
      assert!(matches!(&res, Err(Error::Certificate(m))
          if m.contains("outside validity")), "got {:?}", res.err());
  }

  #[test]
  fn require_anchored_chain_rejects_forged_terminus_with_anchor_key() {
      // self-issued certificate carrying the anchor root's public key but
      // signed by a different key: the intermediate link verifies against that
      // key, so only the terminus self-signature check can catch the forgery
      use std::str::FromStr;
      let (root, int, leaf, root_key, _) = anchored_test_chain();
      let attacker = fresh_2048();
      let forged = build_subca_cert(
          "CN=zsn test root",
          &x509_cert::name::Name::from_str("CN=zsn test root").unwrap(),
          &root_key,
          &attacker,
          present(),
      );
      let anchors = TrustAnchors::from_certificates(vec![root.clone()]);
      let res = require_anchored_chain(&leaf, &[int, forged], &anchors);
      assert!(matches!(&res, Err(Error::Certificate(m))
          if m.contains("self-signature")), "got {:?}", res.err());
  }
  ```

- [ ] **Step 1.8: Scoped gate** (Implementer self-check, then reviewer):

  ```bash
  mkdir -p target/tmp .tmptmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-core
  cargo clippy -p zsign-core --all-targets -- -D warnings
  cargo fmt --all -- --check
  ```

  Expected: all green (the previously listed success tests now run through the
  unanchored constructors; the four tests from Step 1.2 and the six policy
  tests from Step 1.7 pass).

- [ ] **Step 1.9: Controller commit** after spec + quality reviews:
  `feat: reject certificate chains that do not reach the apple root (ZSN-96)`

---

### Task 2: wasm surface (`zsign-wasm`) — Batch 2, parallel with Task 3

**Files:**
- Modify: `crates/zsign-wasm/src/lib.rs`

- [ ] **Step 2.1: Confirm RED** (Tester): after Task 1,
  `wasm-pack test --node crates/zsign-wasm` fails broadly — `WasmSigner::new`
  now rejects the self-issued `LEAF_P12_B64`, so `new_signer()`/`new_signer_with_profile()`
  and every dependent test panic with "fixture p12 loads". Record the failing
  test names.

- [ ] **Step 2.2: Extract `assemble`** (Implementer). Move the part of
  `WasmSigner::new` after `from_p12` (entitlement extraction + struct init,
  `lib.rs:259-272`) into a private constructor in a **plain** (non-`wasm_bindgen`)
  `impl WasmSigner` block so tests can call it:

  ```rust
  impl WasmSigner {
      /// Builds a signer from already-loaded credentials and an optional
      /// provisioning profile, extracting profile entitlements once.
      fn assemble(
          credentials: SigningCredentials,
          profile_bytes: Option<Vec<u8>>,
      ) -> Result<WasmSigner, JsValue> {
          let entitlements = match profile_bytes.as_deref() {
              Some(data) => extract_entitlements_from_profile(data).map_err(core_err)?,
              None => None,
          };
          Ok(WasmSigner {
              credentials,
              profile_bytes,
              profile_entitlements: entitlements,
              entitlements_override: None,
              main_executable: None,
              resource_builder: CodeResourcesBuilder::new(),
              streaming_hashes: HashMap::new(),
              finalized_paths: HashSet::new(),
          })
      }
  }
  ```

  `new()` keeps its size guards, then `let credentials =
  SigningCredentials::from_p12(p12_bytes, p12_password).map_err(p12_err)?;` and
  `Self::assemble(credentials, profile_bytes)`. Verify no other construction
  site of `WasmSigner { .. }` exists besides `new`.

- [ ] **Step 2.3: Migrate the test helpers** (Implementer):

  ```rust
  fn new_signer() -> WasmSigner {
      let credentials = SigningCredentials::from_p12_unanchored(
          &decode_base64(LEAF_P12_B64),
          "test",
      )
      .expect("fixture p12 loads");
      WasmSigner::assemble(credentials, None).expect("fixture p12 assembles")
  }

  fn new_signer_with_profile() -> WasmSigner {
      let credentials = SigningCredentials::from_p12_unanchored(
          &decode_base64(LEAF_P12_B64),
          "test",
      )
      .expect("fixture p12 loads");
      WasmSigner::assemble(credentials, Some(PROFILE_XML.as_bytes().to_vec()))
          .expect("fixture p12 + profile load")
  }
  ```

  The ~17 dependent tests are untouched.

- [ ] **Step 2.4: Fix `constructor_rejects_bad_profile`** (`lib.rs:1659`): it
  currently proves profile validation through `WasmSigner::new`, which now fails
  earlier at anchoring. Repoint it at `assemble` so the contract (bad profile →
  `ZSIGN_INVALID_PROFILE`, message about entitlements) is preserved at the layer
  that owns it:

  ```rust
  let credentials = SigningCredentials::from_p12_unanchored(
      &decode_base64(LEAF_P12_B64), "test",
  ).expect("fixture p12 loads");
  let e = match WasmSigner::assemble(credentials, Some(b"<not a profile".to_vec())) {
      Err(e) => e,
      Ok(_) => panic!("bad profile must be rejected"),
  };
  // keep the existing code/message assertions, unchanged
  ```

- [ ] **Step 2.5: Add the binding-level regression test** (Tester), beside the
  other constructor tests, with the same attribute as
  `errors_carry_stable_zsign_codes_and_real_error_instances` (`lib.rs:1594`,
  plain `#[wasm_bindgen_test]` — the convention this module uses for
  `error_code`/`err_message`-touching tests; they run under
  `wasm-pack test --node`):

  ```rust
  #[wasm_bindgen_test]
  fn constructor_rejects_unanchored_credentials() {
      let Err(err) = WasmSigner::new(&decode_base64(LEAF_P12_B64), "test", None) else {
          panic!("self-issued chain must not load through the public constructor");
      };
      assert_eq!(
          error_code(&err).as_deref(),
          Some("ZSIGN_INVALID_CERTIFICATE"),
          "anchoring failures surface as a certificate error"
      );
      assert!(
          err_message(err).contains("not anchored to a trusted root"),
          "message must name the anchoring failure"
      );
  }
  ```

- [ ] **Step 2.6: Scoped gate:**

  ```bash
  mkdir -p target/tmp .tmptmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-wasm
  wasm-pack test --node crates/zsign-wasm
  cargo clippy -p zsign-wasm --all-targets -- -D warnings
  cargo fmt --all -- --check
  ```

  Expected: all green.

- [ ] **Step 2.7: Controller commit** after reviews:
  `test: route wasm signer fixtures through the unanchored loader (ZSN-96)`

---

### Task 3: CLI surface (`zsign-cli`) — Batch 2, parallel with Task 2

**Files:**
- Modify: `crates/zsign-cli/src/main.rs`

- [ ] **Step 3.1: Confirm RED** (Tester):
  `mkdir -p target/tmp .tmptmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-cli`.
  Expected failures (subprocess child binary is production-anchored after
  Task 1): `key_route_pkcs12_content_loads_with_password`,
  `check_revocation_flag_never_gates_a_signing_run`, `env_password_signs_p12_without_flag`,
  `argv_password_beats_env_password`, `encrypted_pem_routes_through_the_password_flow`,
  `missing_profile_error_names_the_file`. Expected to stay green — verify, don't
  assume: `pkcs12_content_with_certificate_names_the_conflict` (`:1357`, misuse
  guard fires before loading), the PEM-route password tests (`:2022`,
  `:2053` — key decode/parse fails before anchoring), and `:1544`/`:1573`
  (MAC/policy precede anchoring). Any additional failure must be
  triaged against `docs/superpowers/specs/2026-09-28-apple-root-anchor-design.md`
  §5.3 (error-class rewrite if password/routing-shaped, in-process conversion if
  downstream-of-load-shaped) and reported — not silently skipped.

- [ ] **Step 3.2: Add the test-build loader wrapper** (Implementer), beside
  `load_credentials`:

  ```rust
  /// Loads PKCS#12 credentials for a CLI run. Test builds use the unanchored
  /// loader so fixture-driven tests can exercise behavior downstream of
  /// credential loading; the shipped binary is always Apple-root anchored —
  /// a subprocess test proves it.
  #[cfg(test)]
  fn load_p12_credentials(
      p12_data: &[u8],
      password: &str,
  ) -> Result<SigningCredentials, Box<dyn std::error::Error>> {
      Ok(SigningCredentials::from_p12_unanchored(p12_data, password)?)
  }

  #[cfg(not(test))]
  fn load_p12_credentials(
      p12_data: &[u8],
      password: &str,
  ) -> Result<SigningCredentials, Box<dyn std::error::Error>> {
      Ok(SigningCredentials::from_p12(p12_data, password)?)
  }
  ```

  Use it at the `--pkcs12` site (`main.rs:859`) and the `-k`-p12 site
  (`main.rs:916`). Leave the keychain site, the two PEM sites, and the
  `resolve_p12_password` trial (`main.rs:931`) on their current constructors.

- [ ] **Step 3.3: Rewrite the four password/routing tests to error-class
  assertions** (Tester + Implementer). Each stays a `run_cli` subprocess test;
  only the success assertion changes. The stable anchoring marker is
  `"not anchored to a trusted root"`.

  - `key_route_pkcs12_content_loads_with_password` (`:1331`): keep all args;
    assert `r.code == 1`, `r.stderr.contains("not anchored to a trusted root")`,
    `!r.stderr.contains("MAC mismatch")`, `!out.exists()` — content routing and
    `-p` reaching `from_p12` are proven by getting past decryption and policy to
    the anchoring stage.
  - `env_password_signs_p12_without_flag` (`:1473`): assert `r.code == 1`,
    stderr contains the marker, and `!r.stderr.contains("no password supplied")`
    and `!r.stderr.contains("MAC mismatch")` — had the env value been ignored,
    the empty-password trial would have produced a MAC/channel error.
  - `argv_password_beats_env_password` (`:1495`): first half (env-only wrong
    password → `MAC mismatch`, exit 1) unchanged; second half asserts exit 1,
    marker present, `"MAC mismatch"` absent (if the env had won, the wrong
    password would give a MAC error).
  - `encrypted_pem_routes_through_the_password_flow` (`:1950`): first two
    assertions unchanged; third becomes `r.code == 1`, marker present, and
    neither `"Invalid password"` nor `"requires a password"` in stderr.
  Update each test's leading comment to state what the new discrimination proves.

- [ ] **Step 3.4: Convert the two downstream tests to in-process** (Implementer):

  ```rust
  #[test]
  fn check_revocation_flag_never_gates_a_signing_run() {
      // help half unchanged (subprocess --help, exit 0, flag present)
      let dir = TempDir::new().unwrap();
      let key = dir.path().join("identity.p12");
      std::fs::write(&key, IDENTITY_P12).unwrap();
      let input = dir.path().join("in.bin");
      std::fs::write(&input, fixtures::make_minimal_macho()).unwrap();
      let out = dir.path().join("out.bin");
      let cli = Cli::try_parse_from([
          "zsign", "-k", key.to_str().unwrap(), "-p", "testpassword",
          "-C", "-o", out.to_str().unwrap(), input.to_str().unwrap(),
      ])
      .expect("args parse");
      let code = run(cli).expect("-C must never gate signing");
      assert_eq!(code, ExitCode::SUCCESS);
      assert!(out.exists());
  }
  ```

  ```rust
  #[test]
  fn missing_profile_error_names_the_file() {
      // same args as before (-k identity.p12 -p testpassword -m absent.mobileprovision -o out in.bin)
      let cli = Cli::try_parse_from([...]).expect("args parse");
      let err = run(cli).expect_err("missing profile must fail");
      let msg = err.to_string();
      assert!(msg.contains("absent.mobileprovision"), "stderr must name the profile file: {msg}");
      assert!(msg.contains("provisioning profile"), "stderr must name the label: {msg}");
  }
  ```

  Both rely on `load_p12_credentials` from Step 3.2 (`ExitCode` and `Cli` are
  already imported through `use super::*`).

- [ ] **Step 3.5: Add the production-loader regression test** (Tester), beside
  the other subprocess tests:

  ```rust
  #[test]
  fn pkcs12_load_rejects_unanchored_chain() {
      // The shipped binary must refuse a self-issued chain even with the
      // correct password: anchoring is a production load-time contract.
      let dir = TempDir::new().unwrap();
      let key = dir.path().join("identity.p12");
      std::fs::write(&key, IDENTITY_P12).unwrap();
      let input = dir.path().join("in.bin");
      std::fs::write(&input, fixtures::make_minimal_macho()).unwrap();
      let out = dir.path().join("out.bin");
      let r = run_cli(
          &[
              OsStr::new("--pkcs12"), key.as_os_str(),
              OsStr::new("-p"), OsStr::new("testpassword"),
              OsStr::new("-o"), out.as_os_str(),
              input.as_os_str(),
          ],
          &[],
      );
      assert_eq!(r.code, 1, "unanchored chain must be refused: {}", r.stderr);
      assert!(
          r.stderr.contains("not anchored to a trusted root"),
          "stderr: {}",
          r.stderr
      );
      assert!(!out.exists(), "no output may be produced");
  }
  ```

  (`--pkcs12` is a long-only flag, `main.rs:39-45`.)

- [ ] **Step 3.6: Scoped gate:**

  ```bash
  mkdir -p target/tmp .tmptmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-cli
  cargo clippy -p zsign-cli --all-targets -- -D warnings
  cargo fmt --all -- --check
  ```

  Expected: all green.

- [ ] **Step 3.7: Controller commit** after reviews:
  `test: cover cli credential loading under apple root anchoring (ZSN-96)`

---

### Task 4: Workspace gates (controller)

- [ ] **Step 4.1:** Revalidate that Batch 2 left no triaged CLI failures
  outstanding (Step 3.1 report) and run, in order:

  ```bash
  cargo fmt --all -- --check
  cargo clippy --workspace --all-targets -- -D warnings
  mkdir -p target/tmp .tmptmp && TMPDIR=$PWD/target/tmp cargo test --workspace
  wasm-pack test --node crates/zsign-wasm
  ```

- [ ] **Step 4.2:** Fix any fallout in scope (a failure caused by this change);
  out-of-scope failures (deferred tickets' files) are reported, not fixed.
  `cargo fmt` fixes may be applied via `cargo fmt --all`. If changes are needed,
  one follow-up commit, e.g. `chore: fix workspace gate fallout (ZSN-96)`.

- [ ] **Step 4.3:** Final evidence for the report: verbatim output of every gate
  command, `git log --oneline a428a68..HEAD`, and the fixture-generation commands
  from Step 1.1. NEVER merge, NEVER push.

---

## Self-review

- Spec coverage: acceptance (i) → Steps 1.2/3.5; (ii) → Step 1.7 accept test with
  injected anchors (real-Apple positive not constructible — design §6.1);
  (iii) → Steps 1.5/1.6/2.3/2.4/3.3/3.4; (iv) → Tasks 2/3/4 gates; fail-closed →
  `require_anchored_chain` returns `Error::Certificate` for every non-anchored
  outcome, no warnings anywhere in the load path.
- Placeholders: none — every step carries concrete code or exact commands.
- Type consistency: `load_p12`/`load_pem`/`finish_p12`/
  `from_p12_with_leaf_sha1_impl` all take `Option<&TrustAnchors>`;
  `require_anchored_chain(leaf, chain, anchors)` matches every call site;
  unanchored constructors are `#[cfg(any(test, feature = "test-fixtures"))]`
  except the keychain twin, which is `#[cfg(all(test, not(target_arch =
  "wasm32")))]` because it wraps a `cfg(not(wasm32))` function.
