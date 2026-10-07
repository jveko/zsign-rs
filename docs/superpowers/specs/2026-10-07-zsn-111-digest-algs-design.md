# ZSN-111 digestAlgorithms Design

**Ticket:** ZSN-111 — SignedData.digestAlgorithms parsed and discarded
**Date:** 2026-10-07
**File in scope:** `crates/zsign-core/src/crypto/cms_verify.rs` only

## Problem

`verify_signed_data` decodes the `digestAlgorithms` field of SignedData and
drops it (`cms_verify.rs:744-746`, `let _digest_algs = ...`). Nothing
cross-checks the SET against the `digestAlgorithm` each SignerInfo declares,
so a CMS whose SET is structurally wrong or omits the signer's digest
algorithm verifies exactly as a consistent one.

## Verified facts (research, 2026-10-07)

Codebase (line numbers verified against `cbb53a0`):

- Discard site: `cms_verify.rs:744-746`; field-position comment `:730-731`.
- SignerInfo digest parsing: `cms_verify.rs:942-976` — `dig_oid` extracted at
  `:942-949`, mode-gated at `:950-976`. CodeSignature accepts only
  `OID_SHA256` (`:94`, `2.16.840.1.101.3.4.2.1`); AttachedProfile accepts
  `OID_SHA256` and `OID_SHA1` (`:53`, `1.3.14.3.2.26`, SHA-1 pushes a warning
  `:963-967`); anything else is a signer-level fatal (`report.errors.push` +
  early `Ok(seal(...))`, `:953-956` and `:970-973`).
- Failure-mode conventions already in the module:
  - Malformed DER / structural violations → hard `Err(Error::Verification)`
    (e.g. `:745-746`, `encapContentInfo is not a SEQUENCE` `:751-755`).
  - SignedData-level semantic mismatches → `global_errors` (declared `:705`);
    the precedent is the `eContentType` mismatch `:760-762`. `seal()`
    (`:609-613`) merges them into `report.errors` on every `Ok` exit, and
    `report.valid = true` requires `global_errors.is_empty()` (`:1120-1124`).
  - Non-fatal observations → `report.warnings` (SHA-1 signer digest `:963-967`);
    warnings never clear validity.
- SET-iteration precedent: the signerInfos loop decodes children one
  `AnyRef` at a time and checks the tag (`:850-856`); `reader()` (`:495-498`)
  wraps `der::SliceReader` with contextual `Error::Verification`.
- Fixture invariant: both production and test signers pass the *same*
  `digest_algorithm` to `SignerInfoBuilder` and
  `SignedDataBuilder::add_digest_algorithm` (`cms.rs:177/216/223`,
  `339/403/417`), so every existing fixture's SET already contains its
  SignerInfo's digest OID. `hand_built_constructed_econtent_cms`
  (`cms_verify.rs:3876-3897`) has an empty SET but also an empty
  signerInfos SET, so it fails earlier with "no SignerInfo present" (`:871-873`)
  and is unaffected.

External contract (source-verified, librarian report 2026-10-07):

- RFC 5652 §5.1/§5.3: `DigestAlgorithmIdentifiers ::= SET OF
  DigestAlgorithmIdentifier` is mandatory; §5.3 says the signer's digest
  algorithm "SHOULD be among those listed in the digestAlgorithms field" and
  "Implementations MAY fail to validate signatures that use a digest
  algorithm that is not included in the SignedData digestAlgorithms set."
  The RFC does **not** mandate cross-checking; hard-failing on mismatch is
  explicitly RFC-licensed, and so is ignoring the SET. (The brief's
  "§4.1" is really §5.1 — §4 is the id-data content type.)
- Message-digest OIDs: SHA-1 `1.3.14.3.2.26` (RFC 3370 §2.1),
  SHA-256 `2.16.840.1.101.3.4.2.1`, SHA-384 `2.16.840.1.101.3.4.2.2`,
  SHA-512 `2.16.840.1.101.3.4.2.3` (RFC 5754 §2.2-2.4).
- Apple: hard fail. `SecCmsSignedDataVerifySignerInfo_internal` resolves the
  digest through the SET; a missing member → `errSecDataNotAvailable` →
  `kCMSSignerInvalidSignature` → codesign's `errSecCSSignatureFailed`
  (`cmssigdata.c:807-815`, `CMSDecoder.cpp:552-559`,
  `StaticCode.cpp:884-896`).
- OpenSSL 3.3.0: hard fail — digests are computed only for SET members, and
  `ossl_cms_DigestAlgorithm_find_ctx` raises `CMS_R_NO_MATCHING_DIGEST`
  (`cms_lib.c:455-457`). BoringSSL has no CMS verifier; RFC 8551 says nothing
  about `digestAlgorithms`.

## Candidate designs

**A — strict structural decode + per-SignerInfo containment via
`global_errors` (chosen).** At the decode site: require `Tag::Set`, decode each
child as `AlgorithmIdentifier` (SEQUENCE whose first element is an OID), keep
the OIDs. Structural failure → hard `Error::Verification`, exactly like the
surrounding decode. Inside the SignerInfo loop, after the digest OID passes
mode gating: if the OID is not in the collected set, push a
`global_errors` entry. *Pros:* two failure channels, both already established
in the module; the report stays intact for the other findings; mirrors the
`eContentType` precedent byte-for-byte. *Cons:* the mismatch is a report
failure (`report.valid == false`) rather than an early abort — this is the
module's verification-failure channel, not a weaker one.

**B — hard `Err(Error::Verification)` on missing OID (rejected).** Aborts
decode mid-flight. Diverges from the module's convention: only *structure*
hard-errors; *semantic* SignedData mismatches go through `global_errors`.

**C — warning only (rejected).** `report.warnings` never clears validity, so
a mismatched CMS would still verify `valid == true`. The brief requires a
verification failure.

**D — decode-time check over all SignerInfos (rejected).** SignerInfo parsing
already lives in the per-signer loop; re-parsing positionally at decode time
duplicates that logic for no benefit.

## Decision

Implement A:

1. Replace `let _digest_algs = ...` with a decode that (a) requires
   `Tag::Set`, (b) iterates children requiring `Tag::Sequence` with a
   decodable leading `ObjectIdentifier`, (c) collects the OIDs into a
   `Vec<ObjectIdentifier>`. Any structural violation returns
   `Err(Error::Verification(...))` with a `digestAlgorithms` message, in the
   style of the neighboring decode errors.
2. In the SignerInfo loop, immediately after the mode-gated `signer_digest`
   match (`:950-976`), push `global_errors.push(format!("digestAlgorithms
   does not include the SignerInfo digest algorithm {dig_oid}"))` when
   `dig_oid` is absent. No early return — like the `eContentType` precedent,
   the remaining checks still run and `seal()` guarantees the entry lands in
   `report.errors` with `report.valid == false`. The check applies to every
   SignerInfo the module inspects: the loop returns on the first fully-valid
   signer (`:1120-1127`), exactly like every existing per-signer check
   (`:950-976`), so "each SignerInfo" means each one reached at the module's
   existing per-signer semantics; repo fixtures are single-SignerInfo.
3. Empty SET: valid DER (RFC 5652 §5.1 allows zero elements), so it parses;
   membership then fails for every SignerInfo → report failure.

Failure-mode alignment rationale (cited): structural → `Error::Verification`
matches `:745-746` and `:751-755`; semantic mismatch → `global_errors` matches
the `eContentType` precedent `:760-762` merged by `seal()` `:609-613`; Apple
and OpenSSL both treat a missing SET member as a verification failure, and
RFC 5652 §5.1/§5.3 license the rejection ("MAY fail to validate").

## Testing

Reuse the in-file builders (`der_tlv` `:2890`, `attr_tlv` `:2898`,
`replace_first_sid` `:2981`, `wrap()` `:1803`, `sign_code_directory`,
`rsa_credentials`/`anchors_for`):

1. Well-formed CMS with a matching SET still verifies — covered by the
   existing suite (notably `round_trip_rsa_signs_and_verifies` `:1811` and
   `attached_profile_accepts_sha1_signer_digest_with_warning` `:3695`),
   which must stay green untouched.
2. SET missing the SignerInfo's digest OID → new test: sign with
   `sign_code_directory` (SHA-256 signer), swap the digestAlgorithms SET for
   a SET containing only a SHA-1 AlgorithmIdentifier, expect
   `report.valid == false` with an error naming `digestAlgorithms`.
3. Malformed SET → new test: swap in a SET whose child is a bare OID (not an
   AlgorithmIdentifier SEQUENCE), expect `Err(Error::Verification)` naming
   `digestAlgorithms`, asserted with the module's
   `assert!(matches!(...), "..., got {:?}", res.as_ref().err())` pattern.
