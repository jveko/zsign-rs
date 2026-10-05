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
  (`cms.rs:297`, the ZSN-98 gate).
- `SigningCredentials` (`cert.rs:107-128`) is `#[derive(Clone)]` with four
  `pub` fields and no invariant enforcement, so a struct literal skips every
  load-time check.

Consequence: a struct-literal credential whose leaf has `basicConstraints
CA=true`, whose `keyUsage` lacks `digitalSignature`, or whose validity window
does not contain the signing instant — including "loaded while valid, signed
after expiry" — signs successfully today. The two production signing paths
(`macho/signer.rs:569` and `macho/signer.rs:684`) both funnel through
`sign_code_directory`, and the `#[cfg(test)]`-only helpers at `cms.rs:111/132`
are not production paths.

## Chosen design

Call the existing policy function at the top of `sign_code_directory`,
mirroring the ZSN-98 landed pattern exactly:

1. Bump `code_signing_policy_violation` and `time_now` in `cert.rs` from
   private to `pub(crate)` (same bump ZSN-98 gave `verify_key_matches_cert`).
2. Import both in `cms.rs` alongside the existing `crate::` imports.
3. First statement of `sign_code_directory`:

   ```rust
   if let Some(violation) = code_signing_policy_violation(&credentials.certificate, time_now()) {
       return Err(Error::Certificate(violation));
   }
   ```

   followed by the existing `verify_key_matches_cert(...)` call.
4. Extend the function's `# Errors` doc to name the policy rejection via
   `Error::Certificate`.

The policy check runs **before** `verify_key_matches_cert`: certificate
purpose and validity are the more fundamental rejection and match the load
paths' check order; both map to `Error::Certificate`, so the error contract
is unchanged. The ZSN-98 mismatched-key test is unaffected (its cert is
policy-clean, so the key check still fires).

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

Required contract tests live in the `cms_verify.rs` test module (the file's
existing `fresh_rsa_credentials` / `build_subca` / `replace_extension`
helpers):

- **(a) CA=true leaf** — a struct-literal `SigningCredentials` carrying a
  leaf with codeSigning EKU **and** `basicConstraints CA=true` (flip via the
  existing `replace_extension` pattern, `cms_verify.rs:2606`, precedent at
  `cms_verify.rs:2741-2748`) is rejected: `Err(Error::Certificate(m))` with
  `m.contains("CA=true")`. The EKU must be present so the named violation is
  the CA check, not the mandatory-EKU check.
- **(b) expired / not-yet-valid leaf** — leaf credentials composed directly
  (struct literal) with a validity window entirely in the past, and one
  entirely in the future, are rejected with `m.contains("expired")` and
  `m.contains("not yet valid")` respectively. Windows are computed relative
  to the current time (mirroring the load-time tests at `cert.rs:1707/1726`)
  so the tests do not rot.
- **(c) regression** — a normal end-entity credential still signs; proven by
  the existing success tests (e.g. `cms_verify.rs:1816`, `cms_verify.rs:1858`,
  `cms.rs:1244` determinism test) staying green. No duplicate test added.

Existing tests that sign with a `Profile::Root` (CA=true, no EKU,
no digitalSignature) signer cert are pinning the wrong behavior once the
gate lands; their **signer** fixtures are adjusted to a valid end-entity
cert (chain/anchor roles keep the root): five `cms.rs` tests
(`cms.rs:719/836/911/927/985`), the `macho/fixtures.rs:702` signer usage in
`macho/signer.rs` tests, and `benches/signing.rs:100`. Each adjustment is
recorded in the final report.

## Design-decisions

| # | Decision | Rationale | Cost if wrong |
|---|----------|-----------|---------------|
| 1 | Gate at top of `sign_code_directory` | Ticket's primary option; single choke point mirrors ZSN-98; future callers inherit it | None material — alternative was two drifting sites |
| 2 | Reuse `code_signing_policy_violation` + `Error::Certificate` as-is | Same messages/order as load paths; no new variants | Callers matching on messages see identical text |
| 3 | `cert::time_now` (bumped `pub(crate)`), not `cms_verify::time_now` | Policy fn and its clock live in one module; sign path stays out of the verify module | Trivial; both helpers are equivalent cfg-gated mirrors |
| 4 | Policy check before key-match check | Purpose/validity is the fundamental rejection; ZSN-98 test unaffected | None; both are `Error::Certificate` |
| 5 | No new test for (c) | Existing success tests already pin it; a duplicate would be a wiring test | Reviewer must accept existing tests as the regression evidence |
| 6 | Adjust wrong-pinning fixtures to end-entity, keep root for chain roles | Root-as-signer was a lazy fixture, never the assertion subject | Some tests may pin signer identity details; fix those assertions minimally |
