# CMS verification hardening (signer observability, SignerInfo trailing bytes, RSA floor) — Design

**Date:** 2026-10-07 · **Branch:** `w1-crypto-cms`
**Status:** approved for planning (cold review gate follows this doc and the plan)

## Goal

Three hardening gaps in `crates/zsign-core/src/crypto/cms_verify.rs`:

1. **Observability** — rejected co-signers vanish: a genuine signer plus an
   appended attacker SignerInfo verifies `valid` with zero trace, and when all
   signers fail the report's per-signer fields describe only the last one
   examined.
2. **Trailing bytes** — a SignerInfo is accepted with arbitrary bytes after
   `signatureValue`; the module's own `encapContentInfo` guard rejects the
   same class of defect.
3. **RSA floor** — RSA keys below 2048 bits verify valid in both the signer
   path and the certificate path (RustCrypto enforces no minimum).

## Evidence (verified against current source)

- `verify_signed_data` loops `for si_raw in &signer_infos_raw`
  (`cms_verify.rs:904`) and **early-returns on the first clean signer**
  (`:1159`); structural per-signer failures also early-return
  (unsupported digest `:983`/`:1000`, missing signing cert `:1059`); the
  only `continue` is the unresolvable-SKI path (`:945-958`).
- Per-signer scalars are assigned BEFORE the per-signer `errors` vector is
  built and surfaced: `signer_subject`/`signer_serial` `:1062-1069`,
  `message_digest_ok` `:1081`, `cdhash_*_ok` `:1090-1099`, `signature_ok`
  `:1103`, `chain_ok`/`anchored`/`chain`/`chain_reason` `:1112-1116`; errors
  built `:1118-1131`, first-failure assignment guarded by
  `if report.errors.is_empty()` `:1155-1157`, valid set + cleared at
  `:1159-1161`. ⇒ all-fail reports mix first-failure errors with
  last-signer scalars; success returns before later SignerInfos are ever
  parsed. `signer_infos_raw.len()` is only checked for emptiness (`:898`).
- `CmsVerifyReport` (`:270-308`) has no signer count/list; derives
  Debug/Clone/PartialEq/Eq/Default, **no serde**; no consumer constructs it
  by literal (only `adhoc_report` `:423-430` via `..Default::default()`), so
  adding public fields cannot break compilation. Only the CLI hand-maps
  fields (`zsign-cli/src/main.rs:751-764`, `README.md:271`) — a consumer
  follow-up OUTSIDE this file, noted not edited.
- Trailing bytes: `let signature = sig_any.value();` (`:1036`) is the last
  read of `si_r` (`der::SliceReader`; `is_finished()` supported —
  der-0.7.10 `reader.rs:82-85`). Module's own guard:
  `:816-820` rejects `encapContentInfo has trailing fields after eContent`
  and has a dedicated negative test. All structural SignerInfo problems are
  hard `Err(Error::Verification(..))` (`:884`, `:1015`, `:1032-1034`).
- RSA: `verify_signer_signature` (`:1234-1326`) and `verify_cert_signature`
  (`:2182-2241`) decode `RsaPublicKey` and pass it to
  `rsa::pkcs1v15::VerifyingKey::new` with no size predicate; both return
  plain `bool` and there is no reason channel. `verify_cert_signature` is
  `pub(crate)` and ALSO called from `crypto/revocation.rs:670` — a DEFERRED
  file — **its signature must not change**.

## External contracts (verified against vendored source / primary docs)

1. **rsa 0.9.10 (locked):** there is **no `key_size()`/`bits()`** on
   `RsaPublicKey`; the API is the `rsa::traits::PublicKeyParts` trait —
   `n()` (implemented at `key.rs:134-137`) and `size()` (BYTES — a
   2048-bit floor is `size() < 256`) — which must be in scope
   (`use rsa::traits::PublicKeyParts;`).
   The crate enforces only a maximum (4096-bit default cap,
   `key.rs:173-182`); `pkcs1v15::VerifyingKey::new` performs zero
   validation (`verifying_key.rs:33-39`), and `verify` only checks
   `sig < n` and `sig_len == size()` (`pkcs1v15.rs:205-221`) — **a
   correctly-produced 512-bit signature verifies as valid.**
2. **Floors:** RFC 5280 imposes NO key-length requirement (its §4.2.1.12 is
   Extended Key Usage and says nothing about key size).
   CA/B Forum Baseline Requirements v2.3.1 §6.1.5: "the modulus size … at
   least 2048 bits". NIST SP 800-131A Rev. 2 §3: ≥2048 acceptable for
   verification, 1024–2047 "legacy use", <1024 "unacceptable risks" — a
   hard 2048 gate is the single defensible constant and is what the
   requirement mandates.
3. **SignerInfo (RFC 5652 §5.3, verbatim):** the ONLY field after
   `signature` is `unsignedAttrs [1] IMPLICIT UnsignedAttributes OPTIONAL`.
   A bare `is_finished()` would reject legitimate countersignatures — the
   optional `[1]` must be decoded (and ignored) first, then
   `is_finished()` required. No RFC sentence says "MUST reject trailing
   data"; the requirement is structural (BER SEQUENCE, RFC 5652 §1) and the
   in-repo justification is consistency with the module's own
   encapContentInfo guard. (RFC 5692 is unrelated — a WiMAX document, not
   an authority for CMS.)
4. **Multi-signer (RFC 5652 §5/§5.1, verbatim):** the reduction is
   **per-signer** ("the successful validation of one signature … from a
   given signer"); implementations "MUST gracefully handle unimplemented
   signature algorithms"; `SignerInfos` is an unordered SET — loop order
   carries no semantics, so describing the report by evaluation order is
   unsound. OpenSSL's `CMS_verify` is all-or-nothing; pyca silently drops
   unverifiable signers — no universal partial-failure policy exists, so
   the OR-reduction (mandated as matching Apple) plus
   explicit per-signer observability is the chosen contract.

## Candidate designs

**Observability design candidates:**
- **A1 (CHOSEN):** evaluate ALL SignerInfos (no early return), keep the
  OR-reduction as a materialized `any_valid`, add
  `signers_total: usize` + `signers: Vec<CmsSignerSummary>` populated for
  every evaluated SignerInfo, push a deduped non-fatal warning naming each
  rejected signer, and stage per-signer scalars locally (first-valid wins;
  last-rejected when none valid).
- A2 — warnings only, no struct fields. Rejected: the requirement explicitly
  states `signers_total`/`signers`.
- A3 — aggregate every failing signer's errors into `report.errors`.
  Rejected: changes existing single-signer error output that tests pin, and
  the warnings + `signers` list already carry the observability.

**Trailing-bytes design candidates:**
- **B1 (CHOSEN):** decode optional `[1] unsignedAttrs` (consume, ignore),
  then require `si_r.is_finished()`, else
  `Err(Error::Verification("SignerInfo has trailing fields after signature"))`
  — structural error, matching the module's hard-error convention and the
  encapContentInfo guard's phrasing.
- B2 — bare `is_finished()` after the signature. Rejected: would reject
  SignerInfos legitimately carrying unsignedAttrs (countersignatures),
  which RFC 5652 §5.3/§11.4 permit.

**RSA-floor design candidates:**
- **C1 (CHOSEN):** `const MIN_RSA_MODULUS_BITS: u64 = 2048` measured via
  `PublicKeyParts::n(&key).bits()` (exact bits — avoids the byte
  rounding of `size()`).
  - Signer path: `verify_signer_signature` returns `Result<(), String>`;
    the weak key yields `Err("rsa public key is below the 2048-bit minimum")`,
    every other failure keeps the EXACT existing string
    `"signature does not verify over the signed attributes"` (no consumer
    behavior change). Sole caller updated; it is private to this file.
  - Cert path: `verify_cert_signature` STAYS `bool` (revocation.rs is
    deferred and must keep compiling) but enforces the floor internally —
    fail-closed for the revocation caller without a signature change. The
    explicit reason surfaces in `verify_chain` via a pre-check helper
    `rsa_key_below_floor(cert) -> bool` at all three
    signature-verifying sites (parent, self-signed terminus, resolved
    trust anchor), each formatting its own reason
    (exact strings pinned in the plan, all containing
    `below the 2048-bit minimum`).
- C2 — change `verify_cert_signature` to a Result and migrate revocation.rs.
  Rejected: revocation.rs is a deferred file owned by another wave.

## Behavior after the change (summary)

| case | today | after |
|---|---|---|
| valid signer + appended bad SignerInfo | `valid=true`, no trace | `valid=true`, `signers_total=2`, `signers` has both, warning names the rejected one |
| all signers fail | errors = first failure, scalars = last signer | same errors/scalars rule, PLUS `signers` records every signer and each gets a warning |
| unsupported-digest / missing-cert signer among several | whole envelope rejected early | that signer rejected with a warning; OR-reduction still applies to the others (RFC §5.1 graceful handling) |
| trailing bytes after `signatureValue` | accepted | `Err("SignerInfo has trailing fields after signature")` |
| SignerInfo ending in `[1] unsignedAttrs` | accepted | still accepted (field decoded then finished) |
| 1024-bit signer key | verifies | `signature_ok=false`, error `rsa public key is below the 2048-bit minimum` |
| 1024-bit issuer/anchor/self-signed key | verifies | chain rejected with an explicit below-minimum reason; revocation's call fails closed silently |

## Scope anchors

- Files in scope: `crates/zsign-core/src/crypto/cms_verify.rs` ONLY.
- `CmsVerifyReport` changes are additive; CLI DTO/README follow-up noted,
  not edited. `adhoc_report()` behavior unchanged.
- SHA-1 signing policy and Apple-EKU policy gaps in this file are other
  owners' scope — untouched.

## Verification commands

```
cargo test -p zsign-core crypto::cms_verify
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test --workspace
```
