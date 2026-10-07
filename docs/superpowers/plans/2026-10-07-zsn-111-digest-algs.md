# ZSN-111 digestAlgorithms Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development (recommended) with dispatching-parallel-agents for independent tasks to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `verify_signed_data` validate `SignedData.digestAlgorithms` — structurally (hard `Error::Verification`) and against each accepted SignerInfo digest (report failure via `global_errors`).

**Architecture:** One file changes: `crates/zsign-core/src/crypto/cms_verify.rs`. The discard site at `:744-746` becomes a validating decode that collects the SET's OIDs; the SignerInfo loop gains a membership check after mode gating. Both failure channels are pre-existing module conventions (see spec).

**Tech Stack:** Rust 2021, `der` crate (`AnyRef`, `Tag`, `SliceReader` via the in-house `reader()` helper), `thiserror`, inline `#[cfg(test)]` tests.

**Spec:** `docs/superpowers/specs/2026-10-07-zsn-111-digest-algs-design.md`

## Global Constraints

- Files touched: `crates/zsign-core/src/crypto/cms_verify.rs` and these two docs only. Nothing else in the repo.
- Failure channels: structural violation → `Err(Error::Verification(msg))` containing `digestAlgorithms`; semantic mismatch → `global_errors.push(msg)` containing `digestAlgorithms` (never `report.warnings`, never a bare `report.errors.push` before an early return).
- Error assertions use `assert!(matches!(&res, Err(Error::Verification(m)) if m.contains("...")), "..., got {:?}", res.as_ref().err());`.
- No ticket ID in code comments. No new dependencies. No refactors beyond the two edits above.
- Gates (scoped only): `cargo fmt --all -- --check`; `cargo clippy -p zsign-core --all-targets -- -D warnings`; `cargo test -p zsign-core crypto`.

## Review Focus

- Existing suite must stay green untouched — the fixture invariant (same `digest_algorithm` to SignerInfoBuilder and SignedDataBuilder, `cms.rs:177/216/223`, `339/403/417`) means every real fixture already contains its signer's OID. If a green test breaks, stop and re-diagnose; do not weaken the check. Owned by Task 1's Step 4 gate.
- Empty digestAlgorithms SET (valid DER per RFC 5652 §5.1) must NOT hard-error at decode; it must fail per-SignerInfo membership. Covered by Task 2's test variant with `der_tlv(0x31, &[])`.
- `hand_built_constructed_econtent_cms` has an empty SET and empty signerInfos — it must keep failing earlier with "no SignerInfo present" (already asserted by `code_signature_entry_tolerates_unparseable_econtent`); covered by the untouched-suite gate.
- SHA-1 AttachedProfile signer: an accepted digest (SHA-1 accepted with warning at `:963-967`) is still membership-checked; the positive path is exercised by the untouched `attached_profile_accepts_sha1_signer_digest_with_warning`, the negative path by Task 2's primary variant (SHA-256 signer, SHA-1-only SET).
- Malformed child inside the SET (bare OID, not AlgorithmIdentifier SEQUENCE) must hard-error, not panic and not fall through to the field-dispatch loop. Owned by Task 1's test.

---

### Task 1: Structural validation of digestAlgorithms

**Files:**
- Modify: `crates/zsign-core/src/crypto/cms_verify.rs` — decode site `:744-746`; tests module (`#[cfg(test)] mod tests`, `:1726`) next to `replace_first_sid` (`:2981`).

**Interfaces:**
- Consumes: `reader()` (`:495-498`), `der_tlv` (test helper, `:2890`), `wrap()` (`:1803`), `rsa_credentials`/`anchors_for` (`:1753`/`:1799`), `sign_code_directory` (imported already), `TAG_CTX0`, `Tag`, `AnyRef`, `ObjectIdentifier`.
- Produces: `digest_alg_oids: Vec<ObjectIdentifier>` — the validated SET members, in scope for the rest of `verify_signed_data` (Task 2's membership check reads it).

- [ ] **Step 1: Write the failing test + its fixture helper**

Add to the tests module (next to `replace_first_sid`):

```rust
/// Replaces the digestAlgorithms SET (SignedData field 2, RFC 5652 §5.1
/// order) with `new_set` (a complete TLV). Assumes the single-SignerInfo
/// output of `sign_code_directory`.
fn replace_digest_algs(cms: &[u8], new_set: &[u8]) -> Vec<u8> {
    let ci = AnyRef::from_der(cms).unwrap();
    assert_eq!(ci.tag(), Tag::Sequence);
    let ci_body = ci.value();
    let mut ci_r = SliceReader::new(ci_body).unwrap();
    let _oid = AnyRef::decode(&mut ci_r).unwrap();
    let oid_end = usize::try_from(ci_r.position()).unwrap();
    let wrap_any = AnyRef::decode(&mut ci_r).unwrap();
    assert_eq!(wrap_any.tag(), TAG_CTX0);
    let wrap_tag = ci_body[oid_end]; // [0] wrapper tag byte
    let sd_seq = AnyRef::from_der(wrap_any.value()).expect("SignedData SEQUENCE inside [0]");
    assert_eq!(sd_seq.tag(), Tag::Sequence);
    let sd_tag = wrap_any.value()[0];
    let sd_body_src = sd_seq.value();

    // Positional split: version, digestAlgorithms, encap, [certs], signerInfos.
    let mut sd_r = SliceReader::new(sd_body_src).unwrap();
    let mut fields: Vec<&[u8]> = Vec::new();
    while !sd_r.is_finished() {
        let start = usize::try_from(sd_r.position()).unwrap();
        let _field = AnyRef::decode(&mut sd_r).unwrap();
        let end = usize::try_from(sd_r.position()).unwrap();
        fields.push(&sd_body_src[start..end]);
    }
    assert!(fields.len() >= 3, "SignedData fields required");
    assert_eq!(
        AnyRef::from_der(fields[1]).unwrap().tag(),
        Tag::Set,
        "digestAlgorithms must be SignedData field 2"
    );
    fields[1] = new_set;

    let new_sd = der_tlv(sd_tag, &fields.concat());
    let new_wrap = der_tlv(wrap_tag, &new_sd);
    let mut ci2 = Vec::new();
    ci2.extend_from_slice(&ci_body[..oid_end]);
    ci2.extend_from_slice(&new_wrap);
    der_tlv(cms[0], &ci2)
}

#[test]
fn malformed_digest_algorithms_set_fails_verification() {
    let (creds, _key) = rsa_credentials();
    let content: &[u8] = b"the code directory bytes";
    let cd_sha256: [u8; 32] = Sha256::digest(content).into();
    let cms = sign_code_directory(content, &creds, None, &cd_sha256).unwrap();
    let sha1 = ObjectIdentifier::new_unwrap("1.3.14.3.2.26");

    // (a) SET child is a bare OID, not an AlgorithmIdentifier SEQUENCE.
    let bare_child = der_tlv(0x31, &sha1.to_der().unwrap());
    let res = verify_code_signature_with_anchors(
        &wrap(&replace_digest_algs(&cms, &bare_child)),
        content,
        None,
        &cd_sha256,
        &anchors_for(&creds),
    );
    assert!(
        matches!(&res, Err(Error::Verification(m)) if m.contains("digestAlgorithms")),
        "malformed digestAlgorithms child must fail with Error::Verification, got {:?}",
        res.as_ref().err()
    );

    // (b) digestAlgorithms is not a SET at all (SEQUENCE-wrapped entries).
    let not_a_set = der_tlv(0x30, &der_tlv(0x30, &sha1.to_der().unwrap()));
    let res = verify_code_signature_with_anchors(
        &wrap(&replace_digest_algs(&cms, &not_a_set)),
        content,
        None,
        &cd_sha256,
        &anchors_for(&creds),
    );
    assert!(
        matches!(&res, Err(Error::Verification(m)) if m.contains("digestAlgorithms")),
        "non-SET digestAlgorithms must fail with Error::Verification, got {:?}",
        res.as_ref().err()
    );
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p zsign-core crypto::cms_verify::tests::malformed_digest_algorithms_set_fails_verification -- --nocapture`
Expected: FAIL — variant (a) currently decodes fine and drops the SET, so verification proceeds (report-based `Ok`); variant (b) likewise. The failure message must show the actual outcome via the `got {:?}` footer.

- [ ] **Step 3: Implement the validating decode in `verify_signed_data`**

Replace the discard site (`:744-746`, `let _digest_algs = ...`) with:

```rust
    // digestAlgorithms SET OF AlgorithmIdentifier — keep the OIDs so each
    // accepted SignerInfo digest can be checked against the collection.
    let dig_algs = AnyRef::decode(&mut sdr)
        .map_err(|e| Error::Verification(format!("malformed digestAlgorithms: {e}")))?;
    if dig_algs.tag() != Tag::Set {
        return Err(Error::Verification("digestAlgorithms is not a SET".into()));
    }
    let mut digest_alg_oids: Vec<ObjectIdentifier> = Vec::new();
    let mut dar = reader(dig_algs.value(), "malformed digestAlgorithms body")?;
    while !dar.is_finished() {
        let alg = AnyRef::decode(&mut dar)
            .map_err(|e| Error::Verification(format!("malformed digestAlgorithms entry: {e}")))?;
        if alg.tag() != Tag::Sequence {
            return Err(Error::Verification(
                "digestAlgorithms entry is not a SEQUENCE".into(),
            ));
        }
        let mut alg_r = reader(alg.value(), "malformed digestAlgorithms entry body")?;
        let oid = ObjectIdentifier::decode(&mut alg_r)
            .map_err(|e| Error::Verification(format!("malformed digestAlgorithms OID: {e}")))?;
        digest_alg_oids.push(oid);
    }
```

No other production edit in this task. `digest_alg_oids` is intentionally unread until Task 2 — if clippy flags it there, that is Task 2's trigger to land, not a reason to gate early.

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test -p zsign-core crypto::cms_verify::tests::malformed_digest_algorithms_set_fails_verification -- --nocapture`
Expected: PASS (both variants).

- [ ] **Step 5: Confirm the untouched suite is still green**

Run: `cargo test -p zsign-core crypto`
Expected: PASS — the fixture invariant (same `digest_algorithm` into `SignerInfoBuilder` and `SignedDataBuilder`, `cms.rs:177/216/223`, `339/403/417`) means every existing fixture's SET parses and lists its signer's digest; no existing test asserts on this code path.

### Task 2: Require each accepted SignerInfo digest in the SET

**Files:**
- Modify: `crates/zsign-core/src/crypto/cms_verify.rs` — SignerInfo loop, immediately after the mode-gated `let signer_digest = match mode { ... };` (`:950-976`); tests module.

**Interfaces:**
- Consumes: `digest_alg_oids` (Task 1), `dig_oid` (`:942-949`), `global_errors` (`:705`), `seal()` (`:609-613`), `replace_digest_algs` (Task 1).
- Produces: a `global_errors` entry containing `digestAlgorithms` and the offending OID; `report.valid == false` with that message in `report.errors` (via `seal()`).

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn digest_algorithms_missing_signer_digest_fails_verification() {
    let (creds, _key) = rsa_credentials();
    let content: &[u8] = b"the code directory bytes";
    let cd_sha256: [u8; 32] = Sha256::digest(content).into();
    let cms = sign_code_directory(content, &creds, None, &cd_sha256).unwrap();
    let sha1 = ObjectIdentifier::new_unwrap("1.3.14.3.2.26");

    // Structurally valid SETs that do not list the SHA-256 SignerInfo digest:
    // (a) SHA-1 only, (b) empty (RFC 5652 §5.1 allows zero elements).
    let sha1_only = der_tlv(0x31, &der_tlv(0x30, &sha1.to_der().unwrap()));
    let empty = der_tlv(0x31, &[]);
    for (label, new_set) in [("sha1-only", sha1_only.as_slice()), ("empty", empty.as_slice())] {
        let bad = replace_digest_algs(&cms, new_set);
        let report = verify_code_signature_with_anchors(
            &wrap(&bad),
            content,
            None,
            &cd_sha256,
            &anchors_for(&creds),
        )
        .unwrap_or_else(|e| panic!("{label}: mismatch must stay report-based, got {e:?}"));
        assert!(!report.valid, "{label}: mismatch must fail verification, report: {report:?}");
        assert!(
            report
                .errors
                .iter()
                .any(|e| e.contains("digestAlgorithms") && e.contains("2.16.840.1.101.3.4.2.1")),
            "{label}: errors: {:?}",
            report.errors
        );
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p zsign-core crypto::cms_verify::tests::digest_algorithms_missing_signer_digest_fails_verification -- --nocapture`
Expected: FAIL — both variants currently produce `report.valid == true` (SET ignored), so the `!report.valid` assertion fires with the report printed.

- [ ] **Step 3: Implement the membership check**

Insert directly after the closing `};` of the mode-gated `let signer_digest = match mode { ... }`:

```rust
        if !digest_alg_oids.contains(&dig_oid) {
            global_errors.push(format!(
                "digestAlgorithms does not include the SignerInfo digest algorithm {dig_oid}"
            ));
        }
```

No early return (the `eContentType` precedent `:760-762`): remaining checks still run, and `seal()` (`:609-613`) merges the entry into `report.errors` while `report.valid` stays false (`:1120-1124`).

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test -p zsign-core crypto::cms_verify::tests::digest_algorithms_missing_signer_digest_fails_verification -- --nocapture`
Expected: PASS for both variants.

### Task 3: Scoped gates + commit

**Files:** none modified; verification only.

- [ ] **Step 1: Run the scoped gates**

```
cargo fmt --all -- --check
cargo clippy -p zsign-core --all-targets -- -D warnings
cargo test -p zsign-core crypto
```
Expected: all PASS, zero warnings. (Never project-wide cold gates mid-flight — the supervisor's `hk check --all` is the land gate.)

- [ ] **Step 2: Commit**

Stage `crates/zsign-core/src/crypto/cms_verify.rs`, `docs/superpowers/specs/2026-10-07-zsn-111-digest-algs-design.md`, `docs/superpowers/plans/2026-10-07-zsn-111-digest-algs.md`. Subject: `fix(crypto): validate SignedData digestAlgorithms (ZSN-111)`. Verify `git status --porcelain` is empty afterward.

## Self-review

- Spec coverage: structural decode → Task 1; membership check → Task 2; failure-channel alignment → Global Constraints; the three regression criteria → Task 1 Step 5 (well-formed stays green, untouched suite), Task 1 test (malformed → `Error::Verification`), Task 2 test (mismatch → report failure).
- Type consistency: `digest_alg_oids: Vec<ObjectIdentifier>` defined in Task 1, read in Task 2; `dig_oid` binding starts at `:945` (`dig_oid` extraction block `:945-949`).
- Proportion: the plan names exact insertion points and messages; bodies the signature+tests already fix are not transcribed.
