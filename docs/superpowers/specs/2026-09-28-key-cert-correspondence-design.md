# Design: Key↔certificate correspondence at CMS signing (ZSN-98)

Status: authored 2026-09-28 on branch `zsn-98-key-cert-match` (base `a77ca09`).
All file:line citations refer to that revision.

## 1. Problem

`sign_code_directory` (`crates/zsign-core/src/crypto/cms.rs:292`) builds the
SignerInfo `sid` from `credentials.certificate` (`cms.rs:322-329`) while the
signature bytes are produced by `credentials.signing_key` (`cms.rs:342-347`).
Nothing at sign time checks that the two belong together.

A mismatched pair therefore yields a *well-formed* CMS whose SignerInfo names
certificate A and whose signature was made with key B. Per RFC 5652 §5.6 the
verifier sources the public key from the certificate matched by `sid`, so the
signature can never verify under it — a silently broken signature handed to
every consumer. Our own verifier reports it only at verify time, not at sign
time; an iOS install would reject it after the binary was shipped.

Why a mismatch is reachable at all:

- `SigningCredentials` is a `pub` struct with all-`pub` fields
  (`crates/zsign-core/src/crypto/cert.rs:107-127`: `certificate`,
  `signing_key`, `cert_chain`, `team_id`) and is re-exported as
  `zsign_rs::SigningCredentials` — any downstream crate can assemble a
  mismatched pair after a valid load, or without loading at all.
- The pairing invariant is enforced only on the *load* paths:
  `verify_key_matches_cert` runs on the PEM route (`cert.rs:638`, sole call
  site of the function defined at `cert.rs:882`) and `select_identity`
  pairs PKCS#12 entries by SPKI equality (`cert.rs:276-286`). Research
  confirmed no non-test code constructs `SigningCredentials` outside
  `from_p12`/`from_pem` today — the exposure is the public API surface and
  future callers, which construction-time checks cannot fence (fields are
  public by design).

Why checking inside `sign_code_directory` has no bypass:

- It is the **single production CMS producer** in the workspace (scout
  audit): its only builder `build_cms_signed_data` (`cms.rs:365`) is called
  nowhere else; the other blob builders (`sign_attached_content`
  `cms.rs:111`, `sign_attached_content_ecdsa` `cms.rs:244`,
  `sign_detached_content` `cms.rs:132`, `build_test_cms` `cms.rs:198`) are
  `cfg(test)`-gated. Revocation, provisioning, and every verify-side module
  only parse SignedData, never produce it.
- Every public signing entry point funnels into it: facade (`zsign`), wasm,
  and CLI contain zero direct calls; all reach CMS through
  `sign_slice_complete` (`crates/zsign-core/src/macho/signer.rs:558` first
  attempt, `:673` oversize retry), i.e. through `sign_macho` /
  `sign_macho_sha256_only` and the bundle/IPA layers above them.

## 2. Requirements (from the ticket)

- (i) A mismatched key/cert pair must **ERROR at sign time**, typed as
  `Error::Certificate`, before any CMS byte is produced. Fail-closed:
  never warn, never emit a blob.
- (ii) A matched pair still signs, and its CMS verifies.
- (iii) The existing suite stays green. No test may pin the mismatched-pair
  behavior (audit: none exists — see §5).
- (iv) The `zsign-wasm` and `zsign-cli` surfaces keep working with no new
  error mapping (evidence in §4.3).
- Constraints: reuse `verify_key_matches_cert`; no new dependencies; do not
  modify the ZSN-96 Apple-root anchoring code; no new public API unless a
  design requires it; `cert_pair` construction stays possible (we guard the
  use, not the type).

## 3. Candidate designs

**A — guard at the top of `sign_code_directory` only** (chosen). One choke
point covers every CMS consumer because the producer enumeration above is
exhaustive; the check is enforced inside the code that needs the invariant,
so no caller can forget it.

**B — guard at every CMS producer plus a `debug_assert` in a shared
helper.** Rejected: there is exactly one production producer (so "every
producer" == A), the only other producers are `cfg(test)` helpers that are
not a production bypass, and `debug_assert` is compiled out in release —
not fail-closed, which the ticket forbids.

**C — a validated `SigningCredentials::check_pair()` called by all sign
entry points (facade + core).** Rejected: with all-`pub` fields, a method
callers *should* invoke adds no coverage over an enforced choke-point guard
— direct core users and future entry points bypass it, and it widens the
public API (YAGNI). The guard in A is exactly C's intent with C's holes
closed.

Also considered and rejected: moving the check into `build_cms_signed_data`
— that function receives the raw signer and a `CmsBuildContext` separately,
not the credentials pair, so it cannot compare them without an API
refactor that adds churn and zero coverage.

## 4. Chosen design

### 4.1 The guard

First statement of `sign_code_directory`, before the CDHash attributes are
built (cheap early exit):

```rust
verify_key_matches_cert(&credentials.signing_key, &credentials.certificate)?;
```

The helper already returns exactly the required typed error —
`Error::Certificate("Private key does not match certificate's public key")`
(`cert.rs:911-915`) — after DER-encoding the certificate's SPKI
(`cert.rs:886-889`) and the key-derived SPKI (RSA `cert.rs:893-899`,
ECDSA `cert.rs:900-910`) and byte-comparing them. That is the standard
correspondence check (librarian: SPKI DER equality; RFC 5652 §5.3 binds
`sid` to the signer's certificate, §5.6 makes verification use that
certificate's public key). Both key arms are covered by the one call, which
runs before the `match &credentials.signing_key` dispatch (`cms.rs:342`).

Only `certificate` vs `signing_key` is compared — never `cert_chain`
members, which legitimately hold unrelated issuer keys (pinned by the
existing `test_estimate_cms_size_rsa_with_chain` at `cms.rs:1035`).

Cost: two SPKI DER encodes per call (microseconds) against an RSA-2048
sign operation (milliseconds); `signer.rs` calls the function at most twice
per slice. Negligible.

### 4.2 Visibility change in `cert.rs`

`verify_key_matches_cert` is module-private (`fn`, `cert.rs:882`); `cms.rs`
is a sibling module. Widen it to `pub(crate)` — the same visibility
`verify_cert_signature` uses to cross modules inside the crate
(`cms_verify.rs:1518`). This is the sanctioned "cert.rs reuse only" change;
it touches no anchoring code and exposes nothing outside the crate.

### 4.3 Error surface — no new mapping anywhere

- `Error::Certificate(String)` (`crates/zsign-core/src/error.rs:16-17`)
  Displays as `Invalid certificate: {0}`.
- WASM: `code_for_core_error` is exhaustive by design and already maps
  `Error::Certificate` → `WasmErrorCode::InvalidCertificate` →
  `"ZSIGN_INVALID_CERTIFICATE"` (`crates/zsign-wasm/src/lib.rs:140`,
  `:113`); sign paths route through it (`lib.rs:592` sign_macho, `lib.rs:157-166`
  → `:741-742` for sign_ipa via `Error::Core`). The `p12_err`
  re-code to `ZSIGN_INVALID_PASSWORD` (`lib.rs:187-197`) applies only to
  credential loading, never signing. Existing wasm test already asserts
  the code (`lib.rs:1218-1224`).
- CLI: no code table; every signing error is exit 1 with a schema-v1
  `{"status":"error","error":"<Display>"}` document on stderr.

Therefore zero changes in `zsign-wasm`, `zsign-cli`, and the facade —
which also keeps this ticket clear of ZSN-143's files.

### 4.4 Documentation

`sign_code_directory`'s `# Errors` section (`cms.rs:290-291`) documents only
`Error::Signing`; it gains a sentence for `Error::Certificate` naming the
key↔certificate mismatch. No other doc surface exists for this behavior.

## 5. Testing (summary; exact steps live in the plan)

- **Regression, written first (red):** struct-literal credentials with a
  foreign key → `sign_code_directory` returns
  `Err(Error::Certificate(_))` whose payload contains `does not match`
  (repo's `matches!` + `contains` convention), no CMS bytes; then the
  matched identity signs and its CMS verifies through
  `verify_code_signature_with_anchors` with `anchors_for(...)`. Home:
  `cms_verify.rs` tests — they already import `sign_code_directory`
  (`cms_verify.rs:1731`) and own the verify helpers (`wrap` `:1801`,
  `anchors_for` `:1797`, `fresh_rsa_credentials` `:1756`).
- **Migration audit:** none required. All 15 struct-literal test sites
  pair cert and key from one private key in one scope; the only tests that
  deliberately cross key and cert do so through the *load* path and already
  assert `Error::Certificate`. No test pins the bug.
- **Gates:** `cargo fmt --all -- --check`,
  `cargo clippy --workspace --all-targets -- -D warnings`,
  `TMPDIR=$PWD/target/tmp cargo test --workspace`,
  `TMPDIR=$PWD/target/tmp wasm-pack test --node crates/zsign-wasm`.

## 6. Out of scope

- crypto-4 (duplicate cert in chain panics, `cms.rs:390`) — the NEXT ticket
  in this lane; this design must not touch it.
- ZSN-143 facade error-code unification (`zsign/src/builder.rs`,
  `zsign/src/ipa/`, facade/wasm error mapping) — lane 2's files.
- `verify.rs`, Mach-O, CLI, docs waves; `sign_attached_content*` test
  helpers; load-path pairing (already enforced); any new public API.
