# CMS hardening (signer observability, trailing bytes, RSA floor) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development (recommended) with dispatching-parallel-agents for independent tasks to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rejected co-signers become visible (count + per-signer summaries +
warnings) while the OR-reduction is kept; SignerInfo trailing bytes are
rejected after consuming the optional unsignedAttrs; RSA keys below 2048
bits are rejected in both the signer and certificate verification paths with
explicit reasons.

**Architecture:** All three changes live in `crates/zsign-core/src/crypto/cms_verify.rs`:
(1) a trailing-bytes guard right after the signature decode in the SignerInfo
loop; (2) a `MIN_RSA_MODULUS_BITS` floor — `verify_signer_signature` gains a
`Result<(), String>` reason channel, `verify_cert_signature` enforces the
floor internally (staying `bool` for its deferred-file caller), and
`verify_chain` pre-checks the three signature-verifying sites for explicit
chain reasons; (3) the SignerInfo loop evaluates every signer, stages
per-signer fields locally, and records summaries/warnings — `CmsVerifyReport`
gains only additive fields.

**Tech Stack:** Rust (edition 2021), der 0.7 `SliceReader`, rsa 0.9.10
(`n().bits()`), cms 0.2.3 (dev `builder`), inline `#[cfg(test)]` tests.

**Spec:** `docs/superpowers/specs/2026-10-07-cms-hardening-design.md`

## Global Constraints

- Files modifiable: `crates/zsign-core/src/crypto/cms_verify.rs` ONLY
  (production + inline tests). `crypto/revocation.rs` (deferred, calls
  `verify_cert_signature`), facade, CLI, wasm, macho/codesign — untouched.
  `verify_cert_signature` must KEEP its exact `-> bool` signature.
- `CmsVerifyReport` changes must be additive public fields with the struct's
  existing derives (Debug/Clone/PartialEq/Eq/Default — no serde exists);
  `adhoc_report()` behavior unchanged (it uses `..Default::default()`).
- Existing single-signer observable behavior preserved: valid gating,
  `report.errors` first-failure content, `seal()` ordering of
  `global_errors`, and the exact string
  `signature does not verify over the signed attributes` for ordinary
  signature failures.
- No ticket IDs anywhere (code, comments, docs, commit messages).
- Zero-warning gate: `cargo fmt --all -- --check` + `cargo clippy --workspace --all-targets -- -D warnings`.
- Tests run with `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test …`;
  multi-filter commands go through `cargo test -p zsign-core -- f1 f2 …`.
- Every assertion prints the actual received value in its failure footer.
- rsa 0.9.10 reality: measure with `pub_key.n().bits()` (u64) against
  `const MIN_RSA_MODULUS_BITS: u64 = 2048`; there is no `key_size()`/`bits()`
  method and `PublicKeyParts::size()` is BYTES.

## Review Focus

- A valid signer plus an appended rejected SignerInfo still yields
  `valid == true` (OR-reduction kept) while BOTH signers appear in
  `signers` and a warning names the rejected one — pinned by Task 3.
- Report consistency under mixed outcomes: scalar fields describe the first
  valid signer when one exists, otherwise the last evaluated — pinned by
  Task 3.
- Unsupported-digest / missing-cert signers become per-signer rejections
  (graceful handling) instead of whole-envelope aborts, with identical
  single-signer reports — pinned by Task 3's regression run.
- A SignerInfo ending in `[1] unsignedAttrs` still verifies; ANY other
  trailing bytes reject — pinned by Task 1.
- 2048-bit keys still verify everywhere (existing suite), 1024-bit keys
  reject in signer, issuer, self-signed, and anchor positions — pinned by
  Task 2.

---

### Task 1: SignerInfo trailing bytes

**Files:**
- Modify: `crates/zsign-core/src/crypto/cms_verify.rs` — guard in
  `verify_signed_data` after the signature decode + inline tests.

**Interfaces:**
- Consumes: `si_r` (`der::SliceReader`), `reader()`, `AnyRef::decode`,
  `TAG_CTX1`, `Error::Verification`, and the test fixture stack:
  `sign_code_directory`, `wrap()` (~:2463), `replace_first_sid`
  (~:4940-5027), `der_tlv` (~:4849), `fresh_rsa_credentials` (~:2420).
- Produces: guard behavior — leftover bytes after the signature decode are
  accepted ONLY when they are exactly one `[1]` TLV that consumes the rest;
  anything else returns
  `Err(Error::Verification("SignerInfo has trailing fields after signature".into()))`.
  Test helper: `fn append_first_signer_info_tail(cms: &[u8], tail: &[u8]) -> Vec<u8>`
  — a clone of `replace_first_sid`'s bottom-up rewriter that appends `tail`
  bytes to the first SignerInfo SEQUENCE body while rebuilding
  SignerInfo → SET OF → SignedData → [0] → ContentInfo, WITHOUT
  `replace_first_sid`'s `assert!(set_r.is_finished(), "fixture assumes a single SignerInfo")`.

- [ ] **Step 1: Write the failing tests**

Fixture pattern copied from `ski_signer_resolves_end_to_end`
(`cms_verify.rs:5150-5174`): `rsa_credentials()`, `content =
b"the code directory bytes"`, `cd_sha256 = Sha256::digest(content)`,
`cms = sign_code_directory(content, &creds, None, &cd_sha256)`, entry
`verify_code_signature_with_anchors(&wrap(&bytes), content, None,
&cd_sha256, &anchors_for(&creds))`.

```rust
#[test]
fn signer_info_trailing_bytes_are_rejected() {
    let (creds, _k) = rsa_credentials();
    let content: &[u8] = b"the code directory bytes";
    let cd_sha256: [u8; 32] = Sha256::digest(content).into();
    let cms = sign_code_directory(content, &creds, None, &cd_sha256).unwrap();
    let tampered = append_first_signer_info_tail(&cms, &[0x05, 0x00]); // DER NULL TLV
    let res = verify_code_signature_with_anchors(
        &wrap(&tampered),
        content,
        None,
        &cd_sha256,
        &anchors_for(&creds),
    );
    assert!(
        res.as_ref()
            .err()
            .map(|e| e.to_string().contains("SignerInfo has trailing fields after signature"))
            .unwrap_or(false),
        "trailing bytes after the signature must be rejected, got {:?}",
        res.as_ref().err()
    );
}

#[test]
fn signer_info_with_unsigned_attrs_still_verifies() {
    let (creds, _k) = rsa_credentials();
    let content: &[u8] = b"the code directory bytes";
    let cd_sha256: [u8; 32] = Sha256::digest(content).into();
    let cms = sign_code_directory(content, &creds, None, &cd_sha256).unwrap();
    // One empty [1] IMPLICIT TLV — the only field RFC 5652 §5.3 allows
    // after signatureValue.
    let tampered = append_first_signer_info_tail(&cms, &[0xA1, 0x00]);
    let report = verify_code_signature_with_anchors(
        &wrap(&tampered),
        content,
        None,
        &cd_sha256,
        &anchors_for(&creds),
    )
    .unwrap();
    assert!(
        report.valid,
        "a SignerInfo ending in unsignedAttrs must still verify: {:?}",
        report.errors
    );
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-core -- signer_info_trailing signer_info_with_unsigned`
Expected: `signer_info_trailing_bytes_are_rejected` FAILS (today the tail is
silently accepted → the result has no error); `signer_info_with_unsigned_attrs_still_verifies`
PASSES already (standing control: currently accepted for the wrong reason).

- [ ] **Step 3: Implement the guard**

Immediately after `let signature = sig_any.value();`:

```rust
// RFC 5652 §5.3: unsignedAttrs [1] IMPLICIT is the only field after the
// signature; consume it if present, then the SEQUENCE must be done.
if !si_r.is_finished() {
    let clean = AnyRef::decode(&mut si_r)
        .map(|next| next.tag() == TAG_CTX1)
        .unwrap_or(false)
        && si_r.is_finished();
    if !clean {
        return Err(Error::Verification(
            "SignerInfo has trailing fields after signature".into(),
        ));
    }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-core -- signer_info_trailing signer_info_with_unsigned`
Expected: both PASS.

- [ ] **Step 5: Scoped regression**

Run: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-core crypto::`
Expected: all green — no existing fixture carries trailing SignerInfo bytes.

---

### Task 2: RSA 2048-bit floor (signer + certificate paths)

**Files:**
- Modify: `crates/zsign-core/src/crypto/cms_verify.rs` — floor constant,
  `verify_signer_signature` reason channel, `verify_cert_signature` internal
  floor, `verify_chain` pre-checks, inline tests.

**Interfaces:**
- Consumes: `rsa::RsaPublicKey` (inherent `n()` → `.bits() -> u64`),
  `OID_RSA_ENCRYPTION`, `verify_chain` sites (parent branch after the
  name-constraints hook; self-signed terminal before
  `verify_cert_signature(current, current)`; resolved-anchor branch before
  `verify_cert_signature(current, anchor)`), `rsa_credentials()` /
  `build_rsa_root` / `build_leaf_signed` / `chain_with` test helpers.
- Produces:
  - `const MIN_RSA_MODULUS_BITS: u64 = 2048;` (private, near the OID consts)
  - `fn rsa_key_below_floor(cert: &x509_cert::Certificate) -> bool` — true
    iff SPKI alg == `OID_RSA_ENCRYPTION` and `modulus.bits() < MIN_…`
    (decode failures ⇒ false; the signature path handles those as today).
  - `verify_signer_signature(...) -> Result<(), String>` — `Ok(())` on
    success; `Err("rsa public key is below the 2048-bit minimum".into())`
    for the floor; every other failure keeps the EXACT existing string
    `signature does not verify over the signed attributes`. Sole caller:
    `verify_signed_data` ~:1104 — `report.signature_ok = res.is_ok();` and
    `if let Err(reason) = res { errors.push(reason); }` replacing today's
    fixed push.
  - `verify_cert_signature` KEEPS `-> bool`; inside the RSA branch, right
    after decoding `pub_key`, `if pub_key.n().bits() < MIN_RSA_MODULUS_BITS
    { return false; }` (fail-closed for the deferred-file caller).
  - Chain reasons (exact strings, all containing
    `below the 2048-bit minimum`):
    - parent: `format!("certificate at depth {depth} has an rsa key below the 2048-bit minimum")`
    - self-signed: `format!("self-signed certificate at depth {depth} has an rsa key below the 2048-bit minimum")`
    - anchor: `"trust anchor has an rsa key below the 2048-bit minimum"`
    Each pre-check returns `ChainOutcome { ok: false, anchored: false,
    subjects: names, reason: Some(..), warnings }` like its neighbors.
- Test fixture helpers (new, mirroring existing builders with a key-size
  parameter; existing helpers unchanged): `fn rsa_root_with_bits(cn: &str,
  bits: usize) -> (rsa::RsaPrivateKey, x509_cert::Certificate,
  rsa::pkcs1v15::SigningKey<Sha256>)` (body of `build_rsa_root` ~:3043 with
  `RsaPrivateKey::new(&mut rand::thread_rng(), bits)`), and
  `fn rsa_credentials_with_bits(bits: usize) -> (SigningCredentials, …)`
  mirroring `rsa_credentials()` ~:2420. rsa 0.9.10 allows 1024-bit
  generation (only a 4096-bit maximum is enforced).

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn signer_rsa_key_below_minimum_is_rejected() {
    // creds = rsa_credentials_with_bits(1024); same fixture skeleton as
    // Task 1 (sign_code_directory + verify_code_signature_with_anchors +
    // anchors_for(&creds)); chain still validly issued (root 2048).
    // assert !report.valid AND report.signature_ok == false AND
    // report.errors contains "rsa public key is below the 2048-bit
    // minimum", footer prints report.errors
}
#[test]
fn issuer_rsa_key_below_minimum_is_chain_rejected() {
    // let (root, root_cert, root_signing) = rsa_root_with_bits("CN=…", 1024);
    // let (_, leaf) = build_leaf_signed("CN=…", &root_cert.subject, &root_signing, |b|{});
    // let out = chain_with(&root_cert, &leaf);
    // assert !out.ok && out.reason contains "below the 2048-bit minimum",
    // footer prints out.reason
}
#[test]
fn trust_anchor_rsa_key_below_minimum_is_rejected() {
    // 1024-bit root; leaf issued by it; verify_chain(std::slice::from_ref(&leaf),
    // &leaf, &TrustAnchors::from_certificates(vec![root_cert]), time_now(),
    // SignerPurpose::CodeSigning) — issuer resolved via find_by_subject.
    // assert !out.ok && out.reason == "trust anchor has an rsa key below the
    // 2048-bit minimum", footer prints out.reason
}
#[test]
fn self_signed_rsa_key_below_minimum_is_rejected() {
    // a self-signed 1024-bit cert used as its own chain leaf (mirror the
    // existing self-signed-leaf test's construction, keying it at 1024):
    // verify_chain over [self_signed] with empty/skip anchors ->
    // the self-signed terminal pre-check fires; assert !out.ok && reason
    // contains "self-signed certificate at depth … below the 2048-bit
    // minimum", footer prints out.reason
}
```

(If `chain_with`'s anchors include the root by SPKI, the parent pre-check
fires first — that is the point of test 2; tests 3 and 4 target the other
two sites with fixtures that reach them.)

- [ ] **Step 2: Run the tests to verify they fail**

Run: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-core -- rsa_key_below_minimum`
Expected: FAIL — today every fixture verifies (floor absent); reason/valid
footers show the actual outcomes.

- [ ] **Step 3: Implement the floor**

Per the Interfaces block: constant, `rsa_key_below_floor`, the `Result`
refactor + caller update, the internal floor in `verify_cert_signature`
(signature unchanged), and the three `verify_chain` pre-checks placed after
the name-constraints hook / at their respective terminal branches.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-core -- rsa_key_below_minimum`
Expected: all four PASS.

- [ ] **Step 5: Scoped regression (single-signer error string preserved)**

Run: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-core crypto::`
Expected: all green — 2048-bit fixtures unaffected and no test observes a
changed signature-failure string (the generic message is unchanged).

---

### Task 3: Signer observability (signers_total/signers + rejected-signer warnings)

**Files:**
- Modify: `crates/zsign-core/src/crypto/cms_verify.rs` — `CmsVerifyReport`
  fields, `CmsSignerSummary`, SignerInfo loop restructure, inline tests.

**Interfaces:**
- Consumes: the Task 1/2 loop state (the trailing guard, and Task 2's
  `Result`-returning `verify_signer_signature` call site), `seal()`
  (:618-624), warning dedup pattern (`if !report.warnings.contains(&w)`),
  fixture stack (`sign_code_directory`, `wrap`, `rsa_credentials`,
  `anchors_for`, `replace_first_sid` ~:4940).
- Produces:
  - `#[derive(Debug, Clone, PartialEq, Eq, Default)] pub struct
    CmsSignerSummary { pub subject: Option<String>, pub serial:
    Option<String>, pub anchored: bool }` — documented, declared next to
    `CmsVerifyReport`.
  - Two additive `CmsVerifyReport` fields: `pub signers_total: usize` and
    `pub signers: Vec<CmsSignerSummary>` (Default derive keeps
    `adhoc_report()` at `0`/`[]`; no consumer constructs the struct by
    literal, so this cannot break compilation; the CLI DTO/README exposure
    is a noted follow-up OUTSIDE this file).
  - Loop restructure in `verify_signed_data`:
    1. Before the loop: `report.signers_total = signer_infos_raw.len();`
    2. Stage ALL per-signer outputs in a local struct (same fields as the
       today-assigned report scalars: signer_subject, signer_serial,
       message_digest_ok, cdhash_v1_ok, cdhash_v2_ok, signature_ok,
       chain_ok, anchored, chain, chain_reason) instead of writing
       `report.*` during evaluation.
    3. Structural per-signer failures that today early-return — unsupported
       digest (`:983`/`:1000`), missing signing certificate (`:1059`) —
       and the unresolvable-SKI `continue` (`:945-958`) become per-signer
       REJECTIONS: record the reason, skip the remaining evaluation for
       that signer, and fall through to the bookkeeping below (do not
       return from the loop).
    4. Bookkeeping per signer: push
       `CmsSignerSummary { subject, serial, anchored }` from the staged
       data (`None`/`false` when the signer got that far); on rejection
       push the deduped warning
       `format!("rejected signer #{idx} of {total}: {reason}")` when the
       subject is unknown, or
       `format!("rejected signer #{idx} of {total} (\"{subject}\"): {reason}")`
       when known (`idx` is 1-based, `reason` is the first per-signer
       error/rejection reason — the index keeps warnings distinct so
       dedup cannot collapse two identical signers);
       copy the staged fields into `report` unless a valid signer has
       already claimed them (first-valid wins; last-rejected otherwise).
    5. Track `any_valid` (a signer whose per-signer `errors` is empty, still
       gated by `global_errors` as today) and the FIRST rejected signer's
       errors; after the loop: `any_valid && global_errors.is_empty()` ⇒
       `report.valid = true; report.errors.clear();` else if
       `report.errors.is_empty() { report.errors = first_rejected_errors; }`
       — preserving today's single-signer outputs exactly; then return
       through `seal(report, global_errors)` as today.
    6. The `no SignerInfo present` path and all envelope-level errors are
       unchanged.
- Fixture helper: `fn spliced_signer_info(cms: &[u8], at_front: bool,
  corrupt: bool) -> Vec<u8>` — a clone of `replace_first_sid`'s rewriter
  (WITHOUT its `assert!(set_r.is_finished(), "fixture assumes a single
  SignerInfo")`) that inserts an additional SignerInfo into the SET OF
  (front or back). `corrupt = true` flips ONE byte of the inserted
  SignerInfo's signature OCTET STRING CONTENT (structure stays valid DER;
  content is only checked by crypto) so the clone fails signature
  verification with the ordinary generic reason. The insertion is a copy of
  the genuine SignerInfo (same sid ⇒ same signer certificate — the tests
  pin traceability, not subject diversity; note this in the helper's doc
  comment).

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn appended_rejected_signer_is_traced_but_chain_stays_valid() {
    // (creds, content, cd_sha256, cms) as Task 1's fixture;
    // let spliced = spliced_signer_info(&cms, /*at_front=*/false, /*corrupt=*/true);
    // let report = verify_code_signature_with_anchors(&wrap(&spliced), …).unwrap();
    // assert report.valid                       // OR-reduction kept
    // assert_eq!(report.signers_total, 2)
    // assert_eq!(report.signers.len(), 2)
    // assert!(report.warnings.iter().any(|w| w.contains("rejected signer #2 of 2")),
    //     "…, got warnings: {:?}", report.warnings)
}
#[test]
fn rejected_signer_before_valid_still_traces_and_valid_signer_owns_scalars() {
    // spliced = spliced_signer_info(&cms, /*at_front=*/true, /*corrupt=*/true);
    // assert report.valid
    // assert_eq!(report.signers.len(), 2)
    // warnings contains "rejected signer #1 of 2"
    // assert_eq!(report.signer_subject.as_deref(), Some("CN=zsign verify test"))
    // assert!(report.signature_ok, "scalars must describe the valid signer, got {:?}", report)
}
#[test]
fn all_rejected_signers_are_listed_and_warned() {
    // two corrupted signers (genuine corrupted in place is not enough —
    // use spliced_signer_info(cms, false, true) AND corrupt the original
    // first entry, OR splice two corrupted clones; whichever construction
    // you use must produce signers_total == 2 with both rejected).
    // assert !report.valid && !report.errors.is_empty()
    // assert_eq!(report.signers_total, 2); assert_eq!(report.signers.len(), 2)
    // both summaries carry subject Some("CN=zsign verify test") (footer prints signers)
    // warnings contain BOTH "#1 of 2" and "#2 of 2"
}
```

(For the third test the simplest construction is
`spliced_signer_info(&cms, false, true)` followed by corrupting the FIRST
signer too — extend the helper with an enum/second flag if that is cleaner;
the observable requirements above are binding, the construction is yours.)

- [ ] **Step 2: Run the tests to verify they fail**

Run: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-core -- rejected_signer all_rejected`
Expected: COMPILE ERROR (red): `signers_total`/`signers` do not exist yet —
the API-creating red state. (Behaviorally today: the appended-corrupt case
returns `valid == true` with empty warnings.)

- [ ] **Step 3: Implement the restructure**

Per the Interfaces block items 1-6: report fields + `CmsSignerSummary`,
local staging struct, rejection conversion of the three early exits, the
bookkeeping/warning/copy rules, and the post-loop valid/errors settlement.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-core -- rejected_signer all_rejected`
Expected: all three PASS.

- [ ] **Step 5: Single-signer behavior regression**

Run: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-core crypto::`
Expected: all green — no single-signer test may observe changed errors,
valid gating, or scalar contents; if one fails, the restructure diverged
from the preservation contract (fix the restructure, not the test) unless
the test pins absence of the NEW warnings — in that case update the test to
tolerate the added rejected-signer warning and record it in your report.

- [ ] **Step 6: Full scoped gate + commit**

Run: `cargo fmt --all -- --check`, then
`cargo clippy --workspace --all-targets -- -D warnings`, then
`mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test --workspace`.
Expected: exit 0 throughout (the four pre-existing license manifest
warnings may appear in clippy output).
Then `git add crates/zsign-core/src/crypto/cms_verify.rs
docs/superpowers/specs/2026-10-07-cms-hardening-design.md
docs/superpowers/plans/2026-10-07-cms-hardening.md` (force-add docs paths;
NOTE: stage docs and code together in ONE commit whenever both are dirty —
the pre-commit hook's stash step fails on unstaged gitignored `docs/`
paths) and commit per task in plan order, e.g.
`fix(crypto): reject trailing fields after signerinfo signature`,
`fix(crypto): reject rsa keys below 2048 bits in verification`,
`feat(crypto): record every evaluated signer in cms verification reports`
— conventional, imperative, lowercase, no ticket ID.

---

## Self-review

- Spec coverage: trailing guard (spec Trailing-bytes candidates B1) → Task 1;
  RSA floor (spec RSA-floor candidates C1: signer Result, cert-internal
  floor, three chain pre-checks) → Task 2; observability (spec
  Observability candidates A1: evaluate-all, signers_total/signers,
  rejected-signer warnings, local staging) → Task 3; consumer follow-up and
  behavior table live in the spec and are not tasks (CLI/README are out of
  scope by the brief's scope anchors).
- Step scan: every step is one action with a checkable result; test steps
  pin exact names/assertions/footers; code steps pin signatures, strings,
  and hook locations.
- Type consistency: `append_first_signer_info_tail`, `rsa_key_below_floor`,
  `MIN_RSA_MODULUS_BITS`, `rsa_root_with_bits`, `rsa_credentials_with_bits`,
  `CmsSignerSummary`, `spliced_signer_info` used identically across tasks;
  Task 3 consumes Task 2's `Result` call site by name.
- Review Focus: all five lines have owning tests (Task 1: trailing +
  unsignedAttrs control; Task 2: four floor positions + preserved generic
  string via regression; Task 3: appended-trace, front-trace/scalar
  ownership, all-rejected listing).
- Proportion: the plan fixes decisions (exact strings, ownership rules,
  rejection conversions, fixture constructions); bodies stay with the
  implementers.
