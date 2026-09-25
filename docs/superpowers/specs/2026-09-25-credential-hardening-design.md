# Credential Loading Hardening — Design (ZSN-37)

**Date:** 2026-09-25 · **Branch:** `zsn37-credentials` · **Base:** `main` @ `7f6d06a`
(rebased twice: originally `c9ff0fb`, then `c174240`, then `7f6d06a` — every doc commit
was replayed cleanly and the crypto files stayed byte-identical throughout, so all
`cert.rs`/`pkcs12.rs`/`cms_verify.rs` line citations hold at every base; commit hashes
cited below without the "pre-rebase" label are current-branch hashes)
**Scope (authoritative):** lane brief `/tmp/zsn-37.txt`, queue items 1–5, files
`crates/zsign-core/src/crypto/{cert.rs,pkcs12.rs}` + their inline `#[cfg(test)]` tests ONLY.

## Problem statement

Signing credentials are loaded with almost no validation:

1. **Identity selection is positional.** `SigningCredentials::from_p12` takes `certs[0]` and
   `keys[0]`; a bundle whose matching certificate is not at index 0 fails with
   "Private key does not match certificate's public key" even though a matching pair is
   present, and unrelated certificates at `certs[1..]` are copied verbatim into
   `cert_chain`.
2. **No policy at load.** Both loaders prove only key↔cert match. Expired, not-yet-valid,
   wrong-purpose (no `codeSigning` EKU), or CA-asserting leaf certificates load happily and
   fail only after Apple rejects the produced signature. ZSN-23's verify side
   (`crypto/cms_verify.rs`) already enforces leaf purpose rules; the load side must be
   consistent with them, not contradict them.
3. **No RSA strength floor on import.** `rsa` 0.9.10 applies *no* minimum key size at
   decode *or* generation (verified against the vendored source: the only guards are a
   `TooFewPrimes` check below 64 bits at generation and `RsaPublicKey::MAX_SIZE = 4096`;
   the lane brief's "1024-bit floor guards generation" premise is refuted) — a 1024-bit
   PKCS#8/PEM key wraps straight into `SigningKeyType::Rsa`. The ≥2048 floor is this
   lane's policy.
4. **PBKDF2 PRF is discarded.** The parser reads and drops the optional `keyLength` and
   `prf` from `PBKDF2-params` and always derives with HMAC-SHA256. RFC 8018's default when
   `prf` is absent is HMAC-SHA1, so standards-compliant PKCS#12 files fail to decrypt, and a
   declared-but-mismatched `keyLength` is silently accepted.
5. **Only shrouded key bags are recognized.** `collect_bags` dispatches solely on
   `1.2.840.113549.1.12.10.1.2` (pkcs8ShroudedKeyBag; the constant is misleadingly named
   `KEY_BAG`). Raw `keyBag` (`…10.1.1`) and `safeContentsBag` (`…10.1.6`) are skipped, so
   valid files report "no private key".

## Hard constraints (derived from brief + repo reality)

- **Edit surface:** only `cert.rs`, `pkcs12.rs`, and their inline tests. `error.rs`,
  `cms_verify.rs`, `assets.rs`, `provisioning.rs`, `cli/main.rs`, `wasm/lib.rs`, `ipa/**` are
  out of scope (deferred to other lanes; editing them is a lane collision).
- **`SigningCredentials` must keep its exact public shape.** It is struct-literal-constructed
  in out-of-scope files (cms.rs tests, macho/signer.rs tests, verify.rs tests,
  zsign/test_util.rs, benches/signing.rs). Adding a field (e.g. a `warnings` channel) would
  break every one of them → no new fields, no new constructor parameters, no new error enum
  variants (`Error::Certificate(String)` already exists and is the load-error convention).
- **Behavior of the verify side is owned by ZSN-23** (`cms_verify.rs`); this lane's load
  policy must be *consistent* with it. If implementation appears to need a `cms_verify.rs`
  edit → stop and report instead.
- Never merge, never push; conventional commits with the ticket ID in the subject only
  (never in code comments); no stubs/TODOs/placeholders; no `cargo fmt`/`clippy`/`hk`
  mid-flight (orchestrator gates at merge).

## Queue items and candidate designs

### Item 1 — PKCS#12 identity by SPKI, not bag order

**Candidates considered:**

- **A. Pairwise SPKI match + issuer-walk chain build.** Decode every key →
  `SigningKeyType`, derive its SPKI DER; parse every certificate; match each key's SPKI
  against each certificate's `subject_public_key_info`. Exactly one distinct
  `(key_der, cert_der)` pair → select it. Build the chain by walking issuer↔subject links
  from the selected leaf over the remaining parsed certificates; inject the embedded Apple
  WWDR intermediate only when the walk found none for the leaf's issuer; append the Apple
  Root only when a WWDR intermediate is in the chain. Zero pairs → clear "no matching
  certificate for any private key" error; more than one distinct pair → clear ambiguous error
  listing candidate subjects.
- **B. `localKeyId` bag-attribute pairing with SPKI fallback.** Rejected: many exporters omit
  `localKeyId`; SPKI is always authoritative; two pairing mechanisms is a second convention.
- **C. Policy-weighted pair selection (pick the currently-valid code-signing identity when
  several pairs exist).** Rejected: conflates item 1 (pairing) with item 2 (policy);
  genuine ambiguity must surface as an actionable error, and policy evaluation order stays
  orthogonal and testable.

**Decision: A.** Rationale: SPKI equality *is* the definition of key↔cert match already used
by `verify_key_matches_cert`; using it for selection removes positional dependence without a
second matching rule. Duplicate identical pairs collapse (dedupe by
`(key_der, cert_der)`); distinct pairs remain ambiguous by design — `from_p12` has no
identity selector parameter and adding one would change the public API of a
deferred-to-another-lane caller surface. Unparseable certificate DERs are skipped for
pairing and chain assembly (a cert that does not parse cannot be the signing cert anyway);
an error is raised only when nothing usable remains. `verify_key_matches_cert` stays for
`from_pem` (single key, single cert — no pairing needed) and its now-redundant re-verify in
`from_p12` is deleted (selection by construction proves the match).

**Chain-build behavior change:** today `build_apple_ca_chain` appends the Apple Root CA
*unconditionally* (even for a self-signed non-Apple leaf, producing a bogus chain entry).
New rule: the embedded WWDR intermediate is added only when the walk over provided
certificates found no certificate whose subject equals the leaf's issuer *and* the leaf's
issuer CN identifies an Apple WWDR CA; the Apple Root is appended only when a WWDR
intermediate is present in the chain (provided or injected). A self-signed non-Apple leaf
yields an empty `cert_chain`.

### Item 2 — Code-signing policy at load

**Candidates considered:**

- **A. Hard-error leaf policy + chain/anchor validation also gated at load.** Rejected:
  unchainable-but-valid certificates must keep loading for re-sign workflows (the brief
  names this explicitly); anchoring is ZSN-23's verify-side job.
- **B. Hard-error leaf policy; chain trust not gated at load.** **Picked.**
- **C. Escaped-structural result: `(SigningCredentials, warnings)`.** Rejected: changes the
  public shape and breaks every struct-literal construction in out-of-scope files; there is
  no logging facility in `zsign-core` and adding one is out of scope.

**Leaf policy (mirrors `cms_verify.rs` verify-side shape rules exactly, including check
order: `leaf_purpose_reason` runs before `in_validity` in `verify_chain`, so the load side
checks purpose first and validity last — both sides name the same violation for a
certificate that breaks several rules):**

| # | Check | Rule | Violation message names |
|---|---|---|---|
| 1 | Extended key usage | extension **present** and contains `codeSigning` (`1.3.6.1.5.5.7.3.3`) | subject, EKU contents / absence |
| 2 | Key usage | if present, must include `digitalSignature` | subject, KU bits |
| 3 | Basic constraints | if present, must assert `CA=false` | subject, CA flag |
| 4 | Validity window | `notBefore ≤ now ≤ notAfter` (mirrored `time_now()`) | subject, the *violated* bound (`notBefore` when future, `notAfter` when expired) and current time — matching the plan's emitted messages exactly |

Consistency note: the verify side *requires* the EKU extension, tolerates a *missing* KU and
a *missing* BC (checking them only when present). The load side mirrors that exactly —
requiring KU/BC presence would reject certificates the verify side accepts, i.e. would
contradict ZSN-23. Violations are hard errors of the form
`Error::Certificate("signing certificate <subject>: <property violation>")`.

**Chain validation tradeoff (recorded per brief):** *fail* would break legitimate re-signing
with valid certificates that don't chain to an Apple root; *warn* is impossible without a
warnings channel, which is out of scope (public-shape constraint above). Decision: load
performs **structural** chain assembly only (item 1); cryptographic chain/anchor validation
remains solely at verify time. Cost accepted: a user with a broken chain discovers it at
verify, not load. The ordered chain is still truthful (issuer-walk only), so no bogus
certificates are embedded in signatures.

Clock source: mirrors `cms_verify.rs` exactly — `time_now()` (`cms_verify.rs:1354-1364`:
`OffsetDateTime::now_utc()` native, fixed `1_800_000_000` on wasm32) and the
`nb <= now <= na` unix-seconds comparison of `in_validity` (`cms_verify.rs:1346-1352`).
Using `SystemTime::now()` directly would *panic* on `wasm32-unknown-unknown` (where
`WasmSigner::new` calls `from_p12`), and a divergent clock convention would let load and
verify disagree; no clock injection — determinism comes from fixtures sitting far outside
any plausible window (expired ≪ today, not-yet-valid ≫ today).

**Known duplication:** `ext_value`, the four extension OIDs, and `time_now` are
module-private in `cms_verify.rs`; sharing them would require editing that file, which the
brief forbids (deferred to ZSN-23's owners — "if your policy work seems to need a
`cms_verify.rs` edit — STOP and report"). `cert.rs` therefore re-implements `ext_value`,
the OIDs and `time_now` verbatim, and inlines the `in_validity` comparison inside the
policy function (no separate helper). The mirror is pinned by quoting both rule sets
side-by-side in this document and by asserting *the same violation wording shapes* in
`cert.rs` tests.

### Item 3 — RSA ≥ 2048 on import

**Candidates considered:**

- **A. Guard at decode, single shared helper.** After `RsaPrivateKey::from_pkcs8_der` /
  `from_pkcs8_pem` succeeds, check `PublicKeyParts::n().bits() >= 2048` *before* wrapping
  into the pkcs1v15 signing key; both `from_pem` and `from_p12` route through one helper so
  the floor cannot drift between paths. **Picked.** (`n()` returns `&BigUint`; `.bits()`
  works via auto-deref — `rsa-0.9.10/src/traits/keys.rs:10-18`.)
- **B. Guard after `SigningKeyType` is built.** Rejected: `rsa::pkcs1v15::SigningKey` has no
  clean public accessor back to the `RsaPrivateKey`'s modulus; recovering it would re-derive
  material for no benefit.
- **C. Guard only on the PKCS#12 path.** Rejected: `from_pem` has the identical hole; a
  floor that holds on one path only is a bug waiting for a second caller.

Error text names the actual bit count
(`"RSA key too small: {bits} bits (minimum 2048)"`). The ECDSA path is unchanged: only
`p256` keys compile into `SigningKeyType::Ecdsa`, so P-256 (256-bit) is the only possible
curve by construction.

### Item 4 — PBKDF2 PRF + keyLength

**Candidates considered:**

- **A. Retain both fields, validate, dispatch.** `Pbkdf2Parameter::parse` keeps
  `key_length: Option<u32>` and `prf: Option<ObjectIdentifier>` (PRF parameters dropped; only the OID drives dispatch); `pbes2_decrypt`
  validates `key_length` against the scheme-derived key size (AES-128 → 16, AES-192 → 24,
  AES-256 → 32) and dispatches the PRF: absent → HMAC-SHA1 (RFC 8018 DEFAULT), declared
  HMAC-SHA1 → `Sha1`, SHA-2 OIDs (HMAC-SHA224/256/384/512) → matching `sha2` digest,
  anything else → `P12Error::Unsupported` naming the OID. **Picked.**
- **B. Dispatch PRF only, keep discarding `keyLength`.** Rejected: the brief explicitly
  requires retaining *and validating* it; silent acceptance is one of the named bugs.
- **C. Treat a missing PRF as HMAC-SHA256 (preserve current behavior).** Rejected: it
  contradicts RFC 8018's DEFAULT and is precisely why standards-compliant files fail today.

A declared `keyLength` that differs from the scheme's required key size is a hard
`P12Error::Der` naming declared vs. required — deriving a different-length key and letting
CBC fail later would misreport the real fault. `keyLength` is therefore validated as
`Option`: absent (the case in **all four** committed `modern_*` fixtures — verified by DER
walk) is accepted, a *declared* mismatch is rejected. Compatibility verified: every
`modern_*` fixture carries an explicit `prf = hmacWithSHA256` (`1.2.840.113549.2.9`), so
the RFC-default fix is behavior-preserving for them — none of the nine fixtures can newly
fail.

### Item 5 — Raw and nested key bags

**Candidates considered:**

- **A. Four-way bag-type dispatch in `collect_bags` (raw key / shrouded key / cert /
  nested safe-contents) with depth-capped recursion.**
  `…10.1.1` (keyBag) → the bag value *is* an unencrypted PKCS#8 `PrivateKeyInfo`, push its
  DER bytes; `…10.1.2` (pkcs8ShroudedKeyBag) → keep `decrypt_key_bag` (and rename the
  mislabeled `KEY_BAG` constant to `SHROUDED_KEY_BAG`); `…10.1.6` (safeContentsBag) →
  recurse into `collect_bags` with a `depth` parameter, cap at 5, `P12Error::Der` on
  overflow. **Picked.**
- **B. Iterative flattening with an explicit stack.** Rejected: equivalent semantics, but
  recursion with a depth parameter matches the function's existing shape and reads
  directly against RFC 7292's `SafeContents ::= SEQUENCE OF SafeBag` definition.
- **C. Better rejection messages for `.1.1`/`.1.6`.** Rejected: the brief mandates support,
  not diagnostics.

Depth cap rationale: real PKCS#12 files nest at most one or two levels; the cap bounds
adversarial inputs (the DER length checks already bound each level) and the value 5 leaves
headroom over any real producer without being unbounded. The nested `.1.6` coverage
builds `SafeContents` DER in-memory inside the `pkcs12.rs` test module (which can call
`collect_bags` directly) — openssl cannot emit that structure, so no binary fixture is
possible for it; the raw `.1.1` path additionally gets an end-to-end `raw_keybag.p12`
fixture, which openssl *can* emit.

## Cross-cutting design

### Error surface (no new enum variants)

All load failures stay on `Error::Certificate(String)` via the existing
`Error::Certificate(format!(...))` convention. Messages must name the exact violation and
the offending subject, for example:

- `signing certificate "CN=…, OU=…": expired (notAfter=2026-01-01 00:00:00.000000000, now=2026-09-25 …)`
- `signing certificate "CN=…": extended key usage missing codeSigning (1.3.6.1.5.5.7.3.3)`
- `signing certificate "CN=…": keyUsage present but lacks digitalSignature`
- `signing certificate "CN=…": basicConstraints asserts CA=true (leaf must be end-entity)`
- `PKCS#12 contains 2 identities (CN=…, CN=…); expected exactly one key/certificate pair`
- `PKCS#12 contains 1 private key and 2 certificates but no certificate matches any key`
- `RSA key too small: 1024 bits (minimum 2048)`

PKCS#12 parse-stage failures keep their `P12Error` variants (`Der`/`Mac`/`Decrypt`/
`Unsupported`) and keep being wrapped by `extract_p12`'s caller into
`Error::Certificate("Failed to parse PKCS#12: {p12error}")` — the existing channel.

### New/changed internal functions

(Signatures below match the plan's delivered code — the plan is the executable form of
these decisions.)

| Location | Function | Role |
|---|---|---|
| cert.rs | `DecodedKey::{from_pkcs8_der, from_pkcs8_pem, spki_der, into_signing_key}` | single decode path for both loaders; `spki_der` feeds pairing; `into_signing_key` carries the ≥2048 floor and wraps into `SigningKeyType` |
| cert.rs | `select_identity(keys, certs) -> Result<(DecodedKey, Certificate, Vec<Certificate>)>` | SPKI pairing, ambiguity/no-match errors; returns selected key, leaf, and remaining parsed certs for the chain walk |
| cert.rs | `build_chain_from_leaf(leaf, rest: Vec<Certificate>) -> Vec<Certificate>` | issuer/subject walk + conditional Apple WWDR/Root injection |
| cert.rs | `code_signing_policy_violation(cert, now) -> Option<String>` | leaf policy in verify-side order (EKU → KU → BC → validity); `Some` = violation text naming subject+property |
| cert.rs | `embedded_wwdr_for_leaf` / `is_apple_root` / un-gated `extract_subject_cn` | Apple-material lookup used by `build_chain_from_leaf`; `build_apple_ca_chain` and `parse_private_key_der` are **deleted** as obsolete |
| pkcs12.rs | `Pbkdf2Parameter { salt, iterations, key_length, prf }` | retained fields |
| pkcs12.rs | `pbes2_decrypt` | keyLength validation + PRF dispatch (complete code in the plan) |
| pkcs12.rs | `collect_bags(bytes, password, depth, keys, certs)` | four bag-type branches (raw key / shrouded key / cert / nested safe-contents) with depth-capped recursion |
| pkcs12.rs | oid `SHROUDED_KEY_BAG` (rename of the mislabeled `KEY_BAG`), `PRIVATE_KEY_BAG`, `SAFE_CONTENTS_BAG` | RFC 7292 registry names |

Callers: `from_p12` and `from_pem` are the only entry points; both are inside scope files.
No other file in the repo calls `extract_p12`, `collect_bags`, `parse_private_key_der`,
`verify_key_matches_cert`, or `build_apple_ca_chain` (confirmed by search; re-verified by
the citation scout against `c9ff0fb`).

### Test strategy

Tests live inline in `cert.rs` and `pkcs12.rs` (repo convention). Layers:

1. **In-memory certificate fixtures** (cert.rs): build leaf certs with `x509-cert`'s
   builder — the pattern already exists in `cms_verify.rs` tests
   (`Profile::Leaf`, explicit extension replacement) — to cover every policy violation
   (expired, future, missing/wrong EKU, KU without digitalSignature, BC CA=true) and the
   happy path, plus a 1024-bit RSA pair for the strength floor. No binary fixtures needed.
2. **Committed `.p12` fixtures** (from_p12 contract): only where real PKCS#12 structure is
   under test. Generation capability was probed empirically on this machine
   (OpenSSL 3.6.3). Three planned cases are **not openssl-producible** — an
   unrelated-cert-*first* bundle (openssl always orders the `-in` matching cert first; the
   only proven route is a MAC-less DER bag swap = hand-editing), a no-match bundle
   (`-inkey` requires a matching cert), and PBKDF2 PRF/keyLength variants (no flags exist;
   openssl always writes `prf` explicitly and never a `keyLength`) — so they are covered
   by in-memory tests (layers 1/3). Four fixtures are produced in total:
   - `identity_single.p12` — plain 1-key/1-cert bundle → happy-path selection plus the
     empty-chain behavior for a self-signed non-Apple leaf (Task 1);
   - `identity_duplicate_certs.p12` — 1 key, 2 distinct certs with identical
     subject+SPKI (`openssl x509 -req -set_serial 401/402`) → **ambiguous-pair error**;
   - `weak_rsa1024.p12` — `openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:1024`
     → **RSA floor error** through `from_p12`;
   - `raw_keybag.p12` — `openssl pkcs12 -export -keypbe NONE -certpbe NONE` emits a raw
     `keyBag` (`-info`: `PKCS7 Data / Key bag`) → **item 5 `.1.1` end-to-end**.
   All four carry policy-compliant leaves where loaded through `from_p12` (codeSigning
   EKU, digitalSignature KU, `basicConstraints CA:FALSE`, ~10-year validity), generated by
   a documented one-off `openssl` script step (recorded verbatim in the final report),
   stored under `crates/zsign-core/src/crypto/fixtures/` (package-excluded since ZSN-31,
   `Cargo.toml:9` `exclude = ["/src/crypto/fixtures"]` — verified to cover new files),
   never hand-edited. Scratch keys live in a `mktemp -d` directory **outside the repo**
   (`.tmptmp` is not gitignored) and are deleted after generation.
   The identity *selection* cases that openssl cannot encode (unrelated cert before the
   match, no-match bundle) are covered at `select_identity` level with in-memory DER —
   the same private-fn testing convention `pkcs12.rs` already uses for `pkcs12_kdf`.
3. **In-memory `SafeContents`/params DER** (pkcs12.rs): nested safeContentsBag coverage
   (openssl cannot emit `.1.6` — verified across all fixtures and generator flags) and the
   PBKDF2 PRF/keyLength dispatch cases call `collect_bags` / `Pbkdf2Parameter::parse` /
   `pbes2_decrypt` directly with hand-built DER (the hand-rolled `tlv`/`seq` helpers;
   OID TLVs use a local `der::Encode` import); raw keyBag additionally has the
   end-to-end `raw_keybag.p12` fixture.
4. **Regression guard:** the existing 9-fixture `pkcs12` suite runs at
   `extract_p12` level and must stay green unchanged; the gate command's full 59-test
   `crypto` set (including ZSN-23's 33-test `cms_verify` module) must stay green —
   measured 59 passed / 0 failed at base `c9ff0fb`.

New `.p12` fixtures are generated with **policy-compliant leaf certificates** (codeSigning
EKU, digitalSignature KU, `basicConstraints CA:FALSE`, ~10-year validity) so that landing
item 2 does not break item 1's pairing tests (queue order dependency).

### Gate

Scoped mid-flight gate after every task:
`TMPDIR=$PWD/.tmptmp cargo test -p zsign-core crypto -- --skip test_ipa_signing_is_deterministic`
(`.tmptmp` pre-created; `/tmp` tmpfs flakes under parallel-lane load). ZSN-15: the skipped
determinism test fails pre-existing and is skipped in full runs.

## Research findings (batch 1)

### Consumer map (scout)

- **Public shape is load-bearing.** `SigningCredentials` (cert.rs) has *no* derives; 13
  struct-literal sites exist (12 helpers/locations — `zsign/verify.rs` has two), all in
  `#[cfg(test)]` helpers or the criterion bench
  (`cms.rs:531/647/751/828/884`, `cms_verify.rs:1415/1897`, `macho/signer.rs:947`,
  `macho/verify.rs:601`, `zsign/test_util.rs:60`, `zsign/verify.rs:982/1056`,
  `benches/signing.rs:133`). Adding any field would break all of them — outside this
  lane's edit scope. Confirms the hard constraint above.
- **Production loaders:** only `zsign-cli/src/main.rs:379/:386` and
  `zsign-wasm/src/lib.rs:236` (re-anchored after the rebase). Neither `ZSign` nor
  `IpaSigner` loads credentials; they borrow values already constructed.
- **Apple-interop consumer:** the macOS CI interop job signs via the CLI with the
  self-signed certificate from `scripts/verify-apple-interop.sh`; since ZSN-38
  (`7f6d06a`) that certificate is `CA:FALSE` + codeSigning EKU + digitalSignature KU,
  i.e. policy-compliant, so the planned load policy keeps that job green. The upstream
  CA:FALSE line has only been validated by `bash -n` + structural checks — macOS CI is
  the real SecTrustEvaluate test, and a failure there is a ZSN-38 finding, not this
  lane's. (Round 4's logic-level interop finding was resolved by this upstream change;
  this lane never edits the script.)
- **Error surfacing:** CLI propagates `?` raw to `main`'s `Result` (rendered via
  `Debug`, exit 1); wasm routes the loader through `p12_err` (`lib.rs:236`; `p12_err`
  at `:144-160`) and flattens `Display` into a JS `Error` with a mapped code; the
  zsign facade forwards core errors `#[error(transparent)]`
  (`zsign/src/error.rs:56-67`). **No consumer string-matches `Error::Certificate` text** —
  policy-message wording is free to change (the closest coupling there is ZSN-23's
  `cms_verify.rs:2077/2128`, which asserts *verify-report* strings). **However —
  cross-crate contract (round-4 finding):** `p12_err` string-matches the wrapped
  *`P12Error` Display* markers `"invalid PKCS#12 password (MAC mismatch)"` and
  `"PKCS#12 decryption failed"` to map `ZSIGN_INVALID_PASSWORD`, pinned by
  `zsign-wasm/src/lib.rs:947-960`. Those two parse-stage strings must be preserved
  verbatim by any future wording change in `pkcs12.rs`; this lane does not touch them.
- **Existing loader tests cannot newly fail:** `cert.rs:401` and `cert.rs:407` assert
  `is_err()` on garbage input, failing at parse before any policy check. Every
  credential-consuming test elsewhere builds the struct literally, bypassing loaders. The
  `pkcs12.rs` inline tests assert `extract_p12` shapes (`keys.len()/certs.len()`), which
  pairing (a `cert.rs` concern) does not alter.
- **Doctests:** all `from_p12`/`from_pem` examples in scope files are ```` ```ignore ````
  (never compiled); facade examples are `no_run` (compiled, never executed) — signature
  stability only, which is preserved.
- `Error::Certificate` Display is `"Invalid certificate: {0}"` (`error.rs:16`); an unused
  `Error::InvalidPassword` variant exists — not used by this lane (changing the channel is
  out of scope).

### External contracts (librarian, source-verified)

**RFC 8018 (PBKDF2)** — §A.2: `keyLength INTEGER (1..MAX) OPTIONAL, prf AlgorithmIdentifier
{{PBKDF2-PRFs}} DEFAULT algid-hmacWithSHA1`; §A.2: "The default pseudorandom function is
HMAC-SHA-1"; keyLength is "the length **in octets** of the derived key … provided for
convenience only; the key length is not cryptographically protected." RFC 8018 §B: PRF
OID decimals — hmacWithSHA1 `.2.7`, SHA224 `.2.8`, SHA256 `.2.9`, SHA384 `.2.10`, SHA512
`.2.11` (corroborated by RFC 4231 §3.1; IANA has no registry page for the
`1.2.840.113549.2` arc — both candidate URLs 404, so the RFCs are the authority).
Consequences for item 4: the omitted-PRF → HMAC-SHA1 dispatch is a standards requirement;
**keyLength-mismatch rejection is our policy, not the RFC's** — and it is exactly what
OpenSSL does (`crypto/evp/p5_crpt2.c`: `if (kdf->keylength && ASN1_INTEGER_get(…) !=
(int)keylen) ERR_raise(… EVP_R_UNSUPPORTED_KEYLENGTH)` plus `else prf_nid =
NID_hmacWithSHA1`), so the code comment must cite OpenSSL precedent, not RFC mandate.

**RFC 7292 (bags)** — §4.2: `keyBag … {bagtypes 1}` = `1.2.840.113549.1.12.10.1.1`,
`pkcs8ShroudedKeyBag {bagtypes 2}`, `certBag {3}`, `crlBag {4}`, `secretBag {5}`,
`safeContentsBag {bagtypes 6}`; §4.2.1 "KeyBag ::= PrivateKeyInfo"; §4.2.2
"PKCS8ShroudedKeyBag ::= EncryptedPrivateKeyInfo"; §4.2.6 safeContents "allows for
arbitrary nesting". **The standard does NOT bound recursion depth** — "there can be a more
or less arbitrary number of instances of SafeContents" (§5.1) — so the depth cap is an
implementer DoS decision (bounded by the per-level DER length checks), and §5.2's "should
ignore any object identifiers that it is not familiar with" supports skipping unknown bag
types. RFC 7292 mandates **BER** tolerance for AuthenticatedSafe/SafeContents while
`DerReader` is definite-length-only — in-scope docs must keep the existing "subset of
RFC 7292" wording and not claim full coverage.

**OpenSSL behavior (3.6.3 local + 1.1.1/3.0 source)** — 3.x `-export` writes
`prf = hmacWithSHA256` explicitly and *omits* prf only when it is HMAC-SHA1
(`p5_pbev2.c`: "prf can stay NULL if we are using hmacWithSHA1"), and writes `keyLength`
only for RC2; the four committed `modern_*` fixtures match this shape exactly. OpenSSL's
own PKCS#12 NOTES warn "There is no guarantee that the first certificate present is the
one corresponding to the private key" and `PKCS12_parse` matches certs to the parsed key
via `X509_check_private_key` — independent precedent for item 1. Raw keyBag export exists
(`-keypbe NONE`, `PKCS12_SAFEBAG_create0_p8inf`); **no CLI/API path emits a nested
safeContentsBag** (only a parser) — in-memory DER is the only test route for `.1.6`.

**Crate APIs at Cargo.lock pins** — `rsa` 0.9.10: no min-size check at decode
(`from_pkcs8_der` → `TryFrom<PrivateKeyInfo>` → `validate()` → exponent/parity checks
only) nor generation; `x509-cert` 0.2.5: `Profile::Leaf` emits SubjectKeyIdentifier,
AuthorityKeyIdentifier, `BasicConstraints{ca:false}` and KU `digitalSignature|nonRepudiation`
but **no EKU** (tests must add `ExtendedKeyUsage(vec![codeSigning])` explicitly — same as
`cms_verify.rs:1410-1412`); `Validity`/`Time` are public and `Time::to_date_time()`
→ `DateTime::unix_duration()` is the repo's existing timestamp idiom
(`cms_verify.rs:1348-1349`); `pbkdf2` 0.12.2 `pbkdf2_hmac::<D>` (default `hmac` feature)
accepts `Sha1`/`Sha224`/`Sha256`/`Sha384`/`Sha512` (the `IsLess<U256>` block-size bound
holds for 64- and 128-byte blocks); `sha2` 0.10.9 exports all variants with no extra
features. SPKI equality by DER bytes is sound (RFC 5280 §4.1 DER for signatures;
X.690 §7.4 "No alternative encodings are permitted"; the `der` crate decoder enforces
canonical form) and is the comparison `verify_key_matches_cert` already performs.

**Rejected alternative (recorded):** `x509-cert` offers a typed
`tbs_certificate.get::<T>()` extension reader that would avoid hand-rolled OID constants;
rejected in favor of mirroring `cms_verify.rs`'s `ext_value` + explicit OIDs so the load
policy stays line-for-line diffable against the verify policy (consistency is the brief's
hard requirement; two extension-reading idioms in sibling modules would be a second
convention).

**Verify-side congruence check (librarian §5):** `leaf_purpose_reason` runs *before* the
validity test in `verify_chain`; EKU required-present, KU/BC optional, `bc.ca` only,
criticality ignored on both sides, inclusive `nb <= now <= na` in unix seconds with the
wasm32 fixed clock — the load policy table above is exactly congruent, rules *and* check
order (the plan checks purpose before validity, matching `verify_chain`; the table carries
an explicit ordering note). The verify side has
**no key-size check at all**, so the ≥2048 floor is load-side-only and its 2048 value is
this lane's policy (no external standard mandating ≥2048 specifically for code-signing
*import* was verified — marked UNVERIFIED; Apple platform requirements are the assumed
rationale, not a cited source).

### Citation re-anchor (scout, against c9ff0fb)

- **Line anchors confirmed.** `from_p12` is `cert.rs:202-243`: `certs[0]` at 215-217,
  `keys[0]` at 219-220, `skip(1)` chain at 222-226 (unparseable certs silently dropped via
  `.ok()`), Apple fallback at 228-231 (reachable only when the chain ends up empty),
  `verify_key_matches_cert` re-check at 235. `from_pem` is `cert.rs:132-166` (RSA wrap at
  145-146, ECDSA at 147-148, unconditional `build_apple_ca_chain` at 156). The brief's
  citations hold; `build_apple_ca_chain` is `cert.rs:269-298` with the Apple Root appended
  unconditionally at 293-295.
- **PRF/keyLength discard:** `Pbkdf2Parameter` is `pkcs12.rs:512-541` — struct carries only
  `salt`/`iterations`; `keyLength` discarded at 532-534, PRF at 535-537; unconditional
  `pbkdf2_hmac::<Sha256>` at `pkcs12.rs:500-501`. `pkcs12.rs` imports only `Sha1`/`Sha256`
  (lines 26-27) and defines only `HMAC_SHA1`/`HMAC_SHA256` OIDs (53-54) — SHA-224/384/512
  PRF OIDs (`1.2.840.113549.2.8/.10/.11`) must be added.
- **Bag dispatch:** `collect_bags` is `pkcs12.rs:687-720`, two-way dispatch at 711-715,
  skip comment at 716-717; `KEY_BAG` constant is `pkcs12.rs:55-56` and equals
  `…10.1.2` (shrouded) — mislabeled; no `…10.1.1` or `…10.1.6` constants exist.
  `decrypt_key_bag` (`pkcs12.rs:722-730`) assumes `EncryptedPrivateKeyInfo`
  unconditionally — raw `keyBag` bytes would be misparsed, confirming the dispatch must
  branch *before* it.
- **Call-graph isolation:** `mod pkcs12` is private (`crypto/mod.rs:33`); `extract_p12`
  has one non-test caller (cert.rs:203), `collect_bags` one (pkcs12.rs:133),
  `parse_private_key_der` one (cert.rs:220), `build_apple_ca_chain` two (156, 230),
  `verify_key_matches_cert` two (158, 235). Deleting the from_p12 re-verify at 235 leaves
  `verify_key_matches_cert` with one caller — no dead-code fallout.
- **Manifest:** `time = "0.3"` already a dependency (`Cargo.toml:17`); `x509-cert`
  extension types (`BasicConstraints`, `KeyUsage`, `ExtendedKeyUsage`) are already used by
  `cms_verify.rs` *non-test* code with `features = ["pem"]` — the load policy needs no
  manifest change; the `builder` feature is dev-only (`Cargo.toml:54`) and is what
  in-memory test certs will use.
- **Docs to migrate (in-scope files only):** cert.rs module doc line 9, `SigningKeyType`
  doc line 41 ("commonly 2048 or 4096 bits" → must state the ≥2048 floor), `from_pem` doc
  error list (116-120), `from_p12` doc error list (181-186), pkcs12.rs module docs lines
  6-9 (PRF/bag capability claims), `collect_bags` doc 684-686 + skip comment 716-717,
  `decrypt_key_bag` doc 722, `Pbkdf2Parameter` doc 512-516 (grammar already *names*
  keyLength/prf while the code drops them).

## Cold review outcome — STOPPED at the adjudication gate (2026-09-25)

Round 1: `NOT-READY` (16 findings — non-compilable Task-4 snippets, prose-only tests,
undefined fixture constants, broken verification pipelines, design/plan API mismatches).
All 16 were applied and committed (`f145d19`, `e50cd85`).

Round 2 (fresh re-review, told which fixes landed): 11/12 round-1 fixes LANED,
verification-pipelines fix NOT-LANED, plus 10 new findings → `VERDICT: NOT-READY`.
The brief's binding adjudication rule — *NOT-READY after re-review + ANY logic-level
defect → STOP and report* — is triggered, so implementation did not start.

### Findings classified logic-level (triggered the STOP; all since fixed in the disposition commit below)

1. **Panic path in plan test code** — multi-RDN test DNs contain spaces after commas
   (plan Task 1 `wwdr_issuer_injects_missing_intermediate_and_root` and
   `provided_chain_is_completed_without_duplicates`): `Name::from_str` →
   `AttributeTypeAndValue::from_str` does not trim (`x509-cert-0.2.5/src/attr.rs:226-231`
   → `ObjectIdentifier::new(" CN")` errors) → the helper's `.unwrap()` aborts before the
   chain logic runs. Verified directly against the vendored source.
2. **Contradictory `from_pem` control-flow instruction** — the plan simultaneously says
   the password gate (`cert.rs:141-144`, head of the `if/else if` expression) stays
   untouched and replaces that expression; the fix requires restructuring production
   control flow (standalone `if password.is_some()` before decode).
3. **Compile-breaking production snippets** — `build_cert` borrows a temporary signer
   (E0716); `select_identity` calls `to_der()` without `der::Encode` in scope (E0599);
   the policy OID constants/`ext_value` use bare `ObjectIdentifier` with no production
   import; Task 5's direct `collect_bags` calls lack the new `depth` argument.
4. **Impossible RED sequencing** — Tasks 1 and 5 claim compile-failing tests and
   runtime-red tests coexist in one test binary; a build error prevents any run.
5. **Task-1 PEM test breaks Task 2's gate** — the self-signed no-EKU certificate asserted
   to load must fail once the policy lands, unless made policy-compliant (codeSigning
   EKU) in Task 1.
6. **Task 5 tests are prose-only** (no bodies) — violates the brief's no-placeholder rule.

### Findings classified doc/nit (round-2 state — all since fixed in the disposition commit below)

- Duplicate-fixture verification still uses `-clcerts` (misses serial 0402 on OpenSSL
  3.6.3) and the awk writes `Bag Attributes` into `dup_.pem` (spurious third file);
  raw-keybag grep pattern `key bag` cannot detect `Shrouded Keybag`.
- `-nodes` explanation imprecise; design item-5 wording vs fixtures (in-memory DER *and*
  an additional `raw_keybag.p12` E2E fixture); design says "three new fixtures" but four
  are planned; `plan:218` wrongly claims `x509_cert::spki` does not exist (it re-exports
  `spki`); design wrongly claims the pkcs12 test module imports `der::Encode` (it imports
  `Decode`); `plan:801` names the private module `key_usage` (actual name `keyusage`).

### State at STOP

- Docs committed (pre-rebase lineage — those hashes were rewritten by the two rebases;
  current equivalents: `53fc53d` design+plan, `9d55d0c` round-1 fixes, `8f4b2ba`
  import-note delta, `7d9fc9a` round-2 record, `3714f22` round-2 fixes, `d55447d`
  round-3 fixes, `a2654b4` round-3 disposition, `89b7135` round-4 record): `4a87a64`,
  `f145d19`, `e50cd85`. No source or fixture commits at any point.
- Baseline gate measured green: `59 passed; 0 failed` for the mandated scoped command.
- Worktree untouched beyond docs: `crates/zsign-core/src/crypto/{cert.rs,pkcs12.rs}` are
  byte-identical to `c9ff0fb`; all nine committed fixtures intact; zero new fixtures.

### Disposition

The supervisor accepted the STOP and its classification, then authorized the fix path:
all round-2 findings above (6 logic-level + every doc/nit) were applied to the two
documents and committed, and a fresh round-3 cold review was dispatched with an
addressed-preamble (its verdict weighs the round-1/round-2 fixes landing plus NEW
material defects only; re-litigation does not count; any disputed RED/GREEN claim must
arrive with a step-by-step derivation naming the pre-fix lines and values). Per that
authorization, round 3 replaces the brief's exhausted re-review budget.

**Correction to the paragraph above:** round 3 verified that two round-2 logic findings
had *not* actually been applied (the `use der::Encode;` instruction inside
`select_identity` and the production `use const_oid::ObjectIdentifier;` import
instruction), despite this section claiming all round-2 findings landed. They were
applied with the round-3 batch (see below); the original claim was written in error.

### Round 3 → round 4 (supervisor-authorized)

Round 3 returned `NOT-READY` with 7 findings. Classified logic-level (5): the two
missed round-2 imports above; the Task-1 EKU test's missing
`const_oid::ObjectIdentifier` import; 11 `expect_err` calls on success types that do
not implement `Debug` (`SigningCredentials` and `DecodedKey` derive nothing — std's
`Result::expect_err` requires `T: Debug`, so every negative loader test failed E0277
before running); and two fixture-verification guards that `echo`ed a warning yet exited
0, so they could never fail the sequence. Doc/nit (2): the Task-5 build-failure
rationale (three E0061 call sites, not four/E0425) and this document's
`prf: Option<AlgorithmIdentifier>` vs the plan's `Option<ObjectIdentifier>`.

The supervisor accepted the classification and authorized the fix path + round 4:
all 7 findings were applied and committed (`1044a1d`). The negative tests now use
`matches!(&res, Err(Error::Certificate(m) if …))` guards with `res.as_ref().err()` on
the panic side — `Debug` is deliberately NOT derived on credential types (it would
format private key material); the three remaining `expect_err` calls are on
`Ok = Vec<u8>` / `Ok = ()`, which implement `Debug`; both shell guards now `exit 1`;
the imports and wording corrections are in place. A fresh round-4 cold review was then
dispatched under the same addressed-preamble and derivation rules.

### Round 4 → STOP (second)

Round 4 verified **every round-2/round-3 fix LANED** (11 `matches!` negative tests,
both imports, hoisted signer, standalone password gate, build-failure red steps, Task-5
bodies, `exit 1` guards, corrected rationale, aligned `prf` type — all with path:line
evidence), then returned `NOT-READY` with 7 new findings.

Logic-level (3, each re-verified against source before classification):

1. **Apple-interop consumer conflict (out of lane scope).** `scripts/verify-apple-interop.sh`
   generated its certificate with `basicConstraints=critical,CA:TRUE` deliberately and
   signed through `zsign-cli -p` → `SigningCredentials::from_p12` on every macOS CI run,
   so Task 2's CA=false leaf policy would have rejected the script's ground-truth signing
   step; `scripts/` and CI files are outside this lane's fence.
2. **Orphaned trait import.** The plan's `from_pem` rewrite replaces the direct decode
   expression but does not remove `cert.rs:133`'s `use pkcs8::DecodePrivateKey;` →
   `unused_imports`, promoted to an error by the repo's `-D warnings` clippy gate
   (`.github/workflows/ci.yml`, `hk.pkl`).
3. **Duplicate Task-1 test imports.** The prose instructed module-scope imports the
   helper bodies already import locally → ~11 unused outer bindings (including
   `DecodePrivateKey`, `rand::thread_rng`) → same `-D warnings` failure. Fix: each name
   imported exactly once; helpers keep their local trait imports; module scope keeps only
   names used bare across test bodies.

Doc/nit (4+): the design's absolute "no consumer string-matches error text" claim is
false — `zsign-wasm`'s `p12_err` (`lib.rs:144-160`, pinned by tests `:947-960`)
string-matches the two `P12Error` Display markers to map `ZSIGN_INVALID_PASSWORD`, so
those markers are a cross-crate contract while `Error::Certificate` policy wording stays
free; consumer-map citations drifted with the rebase (`macho/verify.rs` literal
`344`→`601`, wasm loader `:64`→`:236`); the header still names base `c9ff0fb`; the
validity-row message contract (design says both timestamps, plan names the violated
bound); plus wording nits (`E0432`→`E0425`, the module-import anchor line, two
print-only fixture greps, and the temporally backwards "already takes depth" prose).

Classification: logic-level present → **STOP and report**; phase 5 not started.

**Supervisor ruling:** finding 1 was resolved upstream after the previous rebase —
ZSN-38 landed `7f6d06a` on main rewriting the interop script's certificate to
`basicConstraints=critical,CA:FALSE` end-entity (verified via
`git show main:scripts/verify-apple-interop.sh`), so this lane absorbs the resolution by
rebasing and never edits the script (scope stays crypto-only; a policy carve-out was
rejected). Findings 2-7 were authorized to apply on top of that rebase, followed by one
fresh cold review (round 5). Monitoring note for the record: the upstream CA:FALSE line
has only been validated by `bash -n` + structural checks — macOS CI is the true
SecTrustEvaluate test, and a failure there is a ZSN-38 finding, not this lane's.
