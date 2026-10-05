# ZSN-102 — Sign-time code-signing policy gate (design)

Date: 2026-10-05 · Branch: `zsn-102-sign-policy-gate` · Ticket: ZSN-102 [MEDIUM] [crypto]

## Problem

Code-signing policy is enforced only on the load paths. All claims below
were verified against current source:

- `code_signing_policy_violation(cert: &Certificate, now: time::OffsetDateTime) -> Option<String>`
  (`crates/zsign-core/src/crypto/cert.rs:480`) is called from exactly two
  places: `load_pem` (`cert.rs:640`, behind `from_pem`/`from_pem_unanchored`)
  and `finish_p12` (`cert.rs:822`, behind the PKCS#12 entry points).
- `sign_code_directory` (`crates/zsign-core/src/crypto/cms.rs:291`) never
  calls it; its only pre-sign check is `verify_key_matches_cert`
  (`cms.rs:297`, the ZSN-98 gate; that helper is `pub(crate)` at
  `cert.rs:882`, visible in current source).
- `SigningCredentials` (`cert.rs:107-128`) is `#[derive(Clone)]` with four
  `pub` fields and no invariant enforcement, so a struct literal skips every
  load-time check.

Consequence: a struct-literal credential whose leaf has `basicConstraints
CA=true`, whose `keyUsage` lacks `digitalSignature`, or whose validity window
does not contain the signing instant — including "loaded while valid, signed
after expiry" — signs successfully today. The two production signing paths
(`macho/signer.rs:569` and `macho/signer.rs:684`) both funnel through
`sign_code_directory`, and the `#[cfg(test)]`-only helpers at
`cms.rs:111/132/155/241` are not production paths.

## Chosen design

Call the existing policy function at the top of `sign_code_directory`,
following the landed ZSN-98 pattern (`verify_key_matches_cert`: `pub(crate)`
bump in `cert.rs`, one-line import in `cms.rs:38`, first-statement call):

1. Bump `code_signing_policy_violation` and `time_now` in `cert.rs` from
   private to `pub(crate)`.
2. Import both in `cms.rs` alongside the existing `crate::` import block
   (starts at `cms.rs:38`).
3. First statement of `sign_code_directory`:

   ```rust
   if let Some(violation) = code_signing_policy_violation(&credentials.certificate, time_now()) {
       return Err(Error::Certificate(violation));
   }
   ```

   followed by the existing `verify_key_matches_cert(...)` call.
4. Extend the function's `# Errors` doc to name the policy rejection via
   `Error::Certificate`.

The policy check runs **before** `verify_key_matches_cert`. This is a
deliberate choice, not load-path mimicry: `load_pem` runs the key match
(`cert.rs:638`) before the policy check (`cert.rs:640`). At sign time the
certificate's purpose and validity are treated as the more fundamental
rejection; both checks map to `Error::Certificate`, so the error contract is
unchanged either way. The ZSN-98 mismatched-key test is unaffected (its cert
is policy-clean, so the key check still fires).

## Alternatives considered

- **Policy call at each sign call site in `macho/signer.rs`** (ticket's
  secondary option): keeps `cms.rs` untouched but needs two synchronized
  sites, and every future direct caller of `sign_code_directory` must
  remember the gate — the exact forgettable-invariant bug class this ticket
  fixes. Rejected.
- **Enforce at construction (private fields + validating constructor)**:
  the only way to make the invariant unforgeable, but it restructures the
  public API, touches every construction site (facade, CLI, wasm, dozens of
  tests), and duplicates checks `from_pem`/`finish_p12` already run.
  Scope expansion beyond the ticket's specified fix. Rejected.

## Invariants

- Every signature emitted through `sign_code_directory` is produced by a
  leaf that passes the same purpose/validity rules the load paths enforce,
  evaluated at the **signing instant** (`time_now()`), not at load time.
- One enforcement choke point: no production signing path bypasses
  `sign_code_directory`.
- No new error variants: policy violations surface as `Error::Certificate`
  with the existing message shape (`signing certificate "<subject>": …`),
  identical to the load paths.
- wasm32 behavior unchanged: `cert::time_now` already cfg-gates to the
  frozen clock (unix 1_800_000_000 = 2027-01-15); ZSN-100 owns that time
  source, this change calls it as-is.

## Test strategy

Required contract tests live in the `cms_verify.rs` test module (helpers:
`fresh_rsa_credentials` at `cms_verify.rs:1758`, `replace_extension` at
`cms_verify.rs:2606`, `fixed_validity_chain` at `cms_verify.rs:3310`):

- **(a) CA=true leaf** — a struct-literal `SigningCredentials` carrying a
  leaf with codeSigning EKU **and** `basicConstraints CA=true` (flip via
  `replace_extension`; same composition as `leaf_asserting_ca_fails`,
  `cms_verify.rs:2735`) is rejected: `Err(Error::Certificate(m))` with
  `m.contains("CA=true")`. The EKU must be present so the named violation is
  the CA check, not the mandatory-EKU check (policy checks EKU first).
- **(b) expired / not-yet-valid leaf** — leaves built by
  `fixed_validity_chain(not_before_unix, not_after_unix, eku)`
  (`cms_verify.rs:3310`) with `eku = Some(ExtendedKeyUsage(vec![OID_CODE_SIGNING]))`
  and windows computed from the current time (`±86_400`/`±172_800` seconds
  around `SystemTime::now()`, converted through `Time::try_from`, the idiom
  at `cms_verify.rs:3316-3318`), composed into `SigningCredentials` struct
  literals directly, are rejected with `m.contains("expired")` and
  `m.contains("not yet valid")`. Relative windows are deliberate: the
  load-time tests at `cert.rs:1707/1726` use fixed windows, which we do not
  mirror because they rot as wall time crosses their bounds. With
  `Profile::Leaf` the builder emits `basicConstraints ca:false` and
  `keyUsage DigitalSignature|NonRepudiation` (x509-cert 0.2.5
  `builder.rs:177,199`), so with the EKU supplied the named violation is
  the validity one.
- **(c) regression** — a normal end-entity credential still signs; proven by
  the existing success tests (`cms_verify.rs:1816`, `cms_verify.rs:1858`,
  `cms.rs:1244` determinism test) staying green. No duplicate test added.

Existing tests that sign with a `Profile::Root` (ca:true, KeyUsage
KeyCertSign|CRLSign, no EKU — x509-cert 0.2.5 `builder.rs:164,190`) signer
cert are pinning the wrong behavior once the gate lands; their **signer**
fixtures move to a valid end-entity cert (chain/anchor roles keep the root).
Each adjustment is recorded in the final report:

- five `cms.rs` tests: `cms.rs:719`, `cms.rs:836`, `cms.rs:905`,
  `cms.rs:925`, `cms.rs:985` — inline builder and helpers
  `build_test_rsa_credentials(bits: usize)` (`cms.rs:944`,
  `Profile::Root` hard-coded) and `build_test_ecdsa_credentials`
  (`cms.rs:1077`); each becomes `Profile::Leaf` +
  `builder.add_extension(&ExtendedKeyUsage(vec![OID_CODE_SIGNING]))` before
  `.build()`, the idiom at `cms_verify.rs:1786-1788`.
- `macho/signer.rs` tests that sign with `test_root_credentials()`
  (`macho/fixtures.rs:702`) swap signer-role usage to the existing
  `test_signing_credentials()` (`macho/fixtures.rs:686`, `Profile::Leaf` +
  codeSigning EKU + `team_id = Some("TESTTEAM")`); tests that fail before
  signing (e.g. `signer.rs:1283`, FAT-container rejection) need no change.
- `benches/signing.rs:99` `test_credentials()` → `Profile::Leaf` + codeSigning
  EKU.

## Design-decisions

| # | Decision | Rationale | Cost if wrong |
|---|----------|-----------|---------------|
| 1 | Gate at top of `sign_code_directory` | Ticket's primary option; single choke point follows the ZSN-98 pattern; future callers inherit it | None material — alternative was two drifting sites |
| 2 | Reuse `code_signing_policy_violation` + `Error::Certificate` as-is | Same messages as load paths; no new variants | Callers matching on messages see identical text |
| 3 | `cert::time_now` (bumped `pub(crate)`), not `cms_verify::time_now` | Policy fn and its clock live in one module; sign path stays out of the verify module | Trivial; both helpers are equivalent cfg-gated mirrors |
| 4 | Policy check before key-match check (deliberate divergence from `load_pem`'s key-then-policy order) | Purpose/validity is the fundamental rejection; both are `Error::Certificate`, so the contract is identical | None; ZSN-98 test fires on its policy-clean cert |
| 5 | No new test for (c) | Existing success tests already pin it; a duplicate would be a wiring test | Reviewer must accept existing tests as the regression evidence |
| 6 | Adjust wrong-pinning fixtures to end-entity, keep root for chain roles | Root-as-signer was a lazy fixture, never the assertion subject; `test_signing_credentials()` already exists for this | Some tests may pin signer identity details; fix those assertions minimally |
| 7 | Validity windows computed relative to `SystemTime::now()` | Load tests' fixed windows (`cert.rs:1707/1726`) rot as wall time crosses them | None; relative windows never expire |
