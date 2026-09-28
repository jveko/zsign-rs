# Duplicate-certificate dedupe at CMS signing — design

Date: 2026-09-28
Branch: `zsn-99-dup-cert-panic` (cut from main @ `fca8748`, after ZSN-96 and ZSN-98)

## Problem

`SignedDataBuilder::build()` in cms 0.2.3 internally runs
`CertificateSet::try_from(certificates.to_owned()).unwrap()`
(cms-0.2.3 `src/builder.rs:404-407`). `CertificateSet::try_from` delegates to
`SetOfVec::try_from` (cms-0.2.3 `src/signed_data.rs:63-68`), whose insertion
sort returns `der::ErrorKind::SetDuplicate` for equal members
(der-0.7.10 `src/asn1/set_of.rs:455-471`, `src/error.rs:231`). Equality is
byte-identical DER of the re-encoded `CertificateChoices`
(cms-0.2.3 `src/cert.rs:37-43`).

Our signing path accumulates certificates without any dedupe:

- production: `build_cms_signed_data` adds `ctx.signing_cert`
  (`crates/zsign-core/src/crypto/cms.rs:393-395`) then every `ctx.cert_chain`
  member (`cms.rs:397-401`); the trailing `builder.build().map_err(...)`
  (`cms.rs:407-409`) is dead for the duplicate case because the panic fires
  inside `build()` before any `Result` exists;
- test twin: `build_test_cms` (`cms.rs:197-239`) has the identical shape.

`add_certificate` (cms-0.2.3 `builder.rs:349-357`) only pushes into a `Vec`
and always returns `Ok`, so duplicates survive to the `unwrap`.

`SigningCredentials` has all-public fields and is re-exported from
`zsign-core` and `zsign-rs` (`crates/zsign-core/src/crypto/cert.rs:107-125`),
so any caller can build `cert_chain: vec![certificate.clone()]`. The CLI's p12
paths dodge this today only because `build_chain_from_leaf` happens to
dedupe by walking issuer links (`cert.rs:355-395`); a struct literal, or a
`.p12` containing two byte-identical intermediate bags loaded via the
unanchored constructors, can still reach the panic. Proven: with
`cert_chain = vec![certificate.clone()]` the public `sign_code_directory`
panics with `Error { kind: SetDuplicate, position: None }`.

This is the single uncontrolled panic in the signing path — every other fallible
call in `build_cms_signed_data` is `?`-propagated.

## Constraints (from the ticket)

- Fail-closed: a duplicate chain must produce a typed `Error` (never panic) or
  a correct signature over a deduped set. A panic is not acceptable.
- Do not touch `require_anchored_chain` / anchoring code (ZSN-96) or the
  ZSN-98 key↔certificate guard beyond coexisting with them.
- We cannot edit the cms crate; we can guarantee we never hand it a
  duplicate set.
- No ticket IDs in code comments; no `println!`/`eprintln!` in `src/`.

## Candidates considered

**(a) `BTreeSet` keyed by DER before `build()`.** Guarantees uniqueness but
reorders members by DER bytes. Rejected: gratuitous reordering of input we
control, and the sort must happen on every sign even though duplicates are
the exceptional case.

**(b) Order-preserving first-wins dedupe keyed by DER (CHOSEN).** Walk
`[signing_cert] ++ cert_chain`, keep a member only if its DER encoding has not
been seen. First-wins means the signer's certificate always survives (it is
added first), chain order is preserved, and the exact input we intended is
what the builder receives. RFC 5652 §5.1 makes `certificates` a `SET OF`
(order-insensitive) and the der layer re-sorts canonically anyway, so
preserving our input order costs nothing and keeps the code's intent readable.
Duplicates are byte-identical, so first-wins vs last-wins is only observable
through which *bytes* survive — and for true duplicates they are the same
bytes; the ordering guarantee matters only for the signer-first invariant.

**(c) Explicit early `Err` on duplicates (strictest).** Rejected: the old
path silently accepted benign caller repeats (CLI chains arrive pre-deduped,
so a repeat is never a real chain-integrity signal), and erroring would break
callers who today succeed. It also cannot distinguish "benign repeat" from
"broken chain" without chain semantics we don't have here.

## Decision

Dedupe (b), implemented as one private helper in
`crates/zsign-core/src/crypto/cms.rs`:

```rust
fn deduped_certificates<'a>(
    signing_cert: &'a Certificate,
    cert_chain: &'a [Certificate],
) -> Result<Vec<&'a Certificate>>
```

- Keys a `std::collections::HashSet<Vec<u8>>` on `cert.to_der()?`, returns the
  signing certificate first followed by chain members in input order,
  skipping any DER already seen.
- A `to_der()` failure propagates as a typed error via the existing
  `signing_err` helper (fail-closed; cannot happen for a parsed certificate,
  but must not panic either).
- Both certificate-adding loops (`build_cms_signed_data` at `cms.rs:393-401`
  and `build_test_cms` at `cms.rs:223-230`) collapse into one loop over the
  helper's output. `add_certificate` is infallible in cms 0.2.3, so merging
  the two `map_err` messages ("signing certificate" / "chain certificate")
  into a single "Failed to add certificate" loses no diagnostics.

### SignerInfo sid interaction

`sid` is `IssuerAndSerialNumber` (`cms.rs:323-330`); a verifier resolves it by
(issuer, serial) content match against the certificate set, not by position.
The signer's certificate is kept first-wins, so `sid` resolution is
unaffected. Deduping cannot drop the signer's certificate — it is always the
first member considered.

### Why no defensive `catch_unwind` around `build()`

We guarantee our inputs contain no duplicates, which makes the `unwrap`
unreachable from this crate. The other `unwrap`s inside `SignedDataBuilder::build`
(digest algorithms at `builder.rs:400`, CRLs at `:412`, signer infos at
`:414`) are also unreachable from our single call sites: we add exactly one
digest algorithm, zero CRLs, and one signer info. Wrapping a library call in
`catch_unwind` would convert a programming error into silent recovery and add
noise to the hot signing path; the dedupe at our boundary is the correct
layer for this fix. Recorded here as the ticket requires.

## Non-goals

- No changes to `require_anchored_chain`, `build_chain_from_leaf`,
  `verify_key_matches_cert`, or any loader in `cert.rs`.
- No changes to `zsign-cli`, `zsign-wasm`, `zsign` facade, `verify.rs`, or
  Mach-O code.
- No dependency bumps; cms stays at 0.2.3.

## Verification

1. Regression A (red first): `SigningCredentials { cert_chain:
   vec![certificate.clone()], .. }` — `sign_code_directory` currently panics;
   after the fix it must return `Ok` and the emitted `SignedData` must carry
   exactly one certificate (the signer's).
2. Regression B (red first): 3-element chain with the signer certificate
   repeated mid-chain — after the fix `sign_code_directory` returns `Ok`, the
   emitted set carries exactly the deduplicated certificates, and
   `verify_code_signature_with_anchors` reports `valid` for the result.
3. Regression C (red first): a non-signer chain member repeated intra-chain
   (`[inter, inter, root]`) — the same shape also panics today; after the fix
   `sign_code_directory` returns `Ok` with a 3-member set. This pins that the
   dedupe is over the whole set, not just against the signer's certificate.
4. Zero-warning gate: `cargo fmt --all -- --check`,
   `cargo clippy --workspace --all-targets -- -D warnings`,
   `TMPDIR=$PWD/target/tmp cargo test --workspace` (779 baseline; 782
   expected after the three regressions, 1+12 ignored),
   `TMPDIR=$PWD/target/tmp wasm-pack test --node crates/zsign-wasm` (28 passed).

Tests live beside the existing `sign_code_directory` behavior tests in the
`cms_verify.rs` test module (where `wrap`, `anchors_for`, `build_subca`,
`build_subca_issued_by`, and the ZSN-98 mismatch test already live), matching
the precedent set by ZSN-98's test commit.
