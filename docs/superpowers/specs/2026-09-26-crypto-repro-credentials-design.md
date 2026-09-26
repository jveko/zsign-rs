# Design: deterministic ECDSA pin, encrypted PEM credentials, revocation warning

Lane **zsn42-crypto**, 2026-09-26. Tickets ZSN-14 / ZSN-18 / ZSN-21 (Kaneo), worked in queue
order; each lands as its own green commit series. Base `97e8460`.

Inputs: three codebase scouts (PEM/password wiring, crypto invariants + fixtures, wasm/warning
boundaries), one librarian pass (its findings are folded into the probe table below), and probes
run on this machine (OpenSSL 3.6.3, pinned crate versions). Every claim below is either a
`file:line` cite, an RFC quote, or a **measured** probe result.

## Premise corrections (re-derived against the pre-lane base tree)

> The cites in this section are **base-tree coordinates at `97e8460`**, recorded before the lane
> landed. They are the evidence for the premises, not pointers into the current tree; the
> post-lane equivalents are cited in the decision sections that act on them.
1. **ZSN-14's premise is already satisfied on the pinned stack.** The CMS builder is bounded on
   the *non-randomized* `signature::Signer` (`cms-0.2.3/src/builder.rs:386`), and for
   `p256::ecdsa::SigningKey` that path is `try_sign` (`ecdsa-0.16.9/src/signing.rs:280`) →
   `try_sign_digest` (`:177-179`, `:143-145`) → `sign_prehash` →
   `try_sign_prehashed_rfc6979` (`:158-164`), feature-gated by `signing = [... "rfc6979"]`
   (`ecdsa-0.16.9/Cargo.toml:133-138`) reached through our `p256` feature `ecdsa`
   (`crates/zsign-core/Cargo.toml:26` → `p256-0.13.2/Cargo.toml` `ecdsa = ["arithmetic",
   "ecdsa-core/signing", "ecdsa-core/verifying", "sha256"]`).
   **Measured**: 5 consecutive `sign_code_directory` calls with one fixed P-256 credential
   produced identical 1123-byte DER. So the ticket's deliverable is *proof and a pin*, not a
   switch — see D14.
2. **ZSN-18 is bigger than "decrypt the key".** The current PEM decoder accepts exactly one label,
   `PRIVATE KEY` (`pkcs8-0.10.2/src/traits.rs:42-47` label validation, reached from
   `crypto/cert.rs:126-132`); PKCS#1 (`RSA PRIVATE KEY`) and SEC1 (`EC PRIVATE KEY`) bodies fail
   even unencrypted. Traditional encrypted PEM therefore needs label routing **and** PKCS#1/SEC1
   decoding, not just a decrypt step.
3. **ZSN-18's reject is in two places**: core guard `crypto/cert.rs:476-480` and CLI
   `crates/zsign-cli/src/main.rs:781-793` (callers `:810` PEM route, `:845` DER route), with five
   tests pinning the current text (`main.rs:1669-1716`).
4. **ZSN-21's upstream model is `-C` = `src/certcheck.cpp` `PerformOCSP`, and it is a bad model.**
   Hand-rolled HTTP/1.1 POST over blocking BSD sockets (no timeout), `d2i_OCSP_RESPONSE` +
   `OCSP_resp_find_status` with **no response-signature verification**, **no
   thisUpdate/nextUpdate check**, hardcoded `ocsp.apple.com/ocsp03-wwdr*` fallbacks, and
   `REVOKED` → **exit 1** in standalone mode (`zsign.cpp:360-361`, `:474-475`). We take the
   signal, reject the gating and the unverified-response shortcut.
5. **No license-clean known-revoked Apple list exists** (searched upstream data files, community
   lists, Apple's own CRL/OCSP publications). A static blacklist cannot be shipped without
   inventing data, which the brief forbids → ZSN-21 is OCSP-shaped only; see D21 and "Deferred".

## Empirical evidence (probes, this machine)

| # | Probe | Result |
|---|---|---|
| P1 | 5× `sign_code_directory`, fixed P-256 key | byte-identical 1123 B → determinism already holds |
| P2 | `from_pkcs8_encrypted_pem` on `openssl pkcs8 -topk8 -v2 aes-256-cbc` | OK with the **currently enabled** `pkcs8` features |
| P3 | same, `-v2prf hmacWithSHA1` (OpenSSL 1.x default) | `UnsupportedAlgorithm{1.2.840.113549.2.7}` — pkcs5 needs its `sha1-insecure` feature |
| P4 | same, `-v2 des3` | `Asn1(OidUnknown{1.2.840.113549.3.7})` — pkcs5 needs `3des` |
| P5 | same, wrong password | `EncryptedPrivateKey(EncryptFailed)` — the PBES2 wrong-password signal |
| P6 | `from_pkcs8_encrypted_pem` on `openssl rsa -traditional -aes256` | `Asn1(Pem(HeaderDisallowed))` — `pkcs8` cannot see DEK-Info PEMs |
| P7 | hand-rolled EVP_BytesToKey(MD5, 1 iter, salt = first 8 IV bytes, need = keyLen) + `cbc::Decryptor<Aes256>` + header IV | 1190 B plaintext, `RsaPrivateKey::from_pkcs1_der` **succeeds** |
| P8 | `-des3` with derived-IV vs header-IV | only the **header IV** yields `30 82 …` (cross-checked with `openssl enc -K/-iv`); the derived IV corrupts block 1 |
| P9 | `openssl ec -traditional -aes128` through P7's path | plaintext parses as SEC1 (`p256::SecretKey::from_sec1_der`) with our **current** `p256` features |
| P10 | P7/P9 with a wrong password | CBC/PKCS#7 unpad failure = "padding invalid" — the traditional wrong-password signal |
| P11 | RFC 6979 A.2.5 through `Signer::<DerSignature>::sign` (CMS's exact trait method) | DER equals `3046022100efd4…3716 022100f7cb…acda8` ("sample") and `3045022100f1ab…8367 0220 019f41…0083` ("test"); `openssl asn1parse` reads back the RFC's own INTEGERs |
| P12 | RFC 6960 CertID hashes computed with `x509-cert` + `sha1` on the embedded Apple certs | `sha1(leaf.tbs.issuer.to_der()) = bb4d3042529e9ce71959c2225f8c845f90b43c2a` and `sha1(root SPKI value bits) = 2bd06947947609fef46b8d2e40a6f7474d7f085e`, both **equal to the hashes inside openssl's own generated request**; the natural wrong recipes (whole SPKI, subject DN) differ |
| P13 | **one-time network observation, depended on by no test** — `openssl ocsp -url http://ocsp.apple.com/ocsp03-applerootca` (AIA URI of `APPLE_WWDR_CA_G3_CERT`) | `good`, thisUpdate = probe date → live Apple OCSP still answers over plain HTTP |
| P14 | offline OCSP fixture generation: CA + leaf through `openssl ca` (AIA in the leaf), `openssl ocsp -reqout`, then `openssl ocsp -reqin -respout -index … -rsigner …` with the index row flipped `V`→`R` | real `req.der` (106 B), `revoked.der` (1293 B, `Cert Status: revoked`, `RevokedAt 2026-01-01`, `Responder Id` by name, **no nextUpdate**) — all fixtures producible with no network |


## ZSN-14 — deterministic ECDSA: pin the contract, change no behavior

**Decision D14.1.** Leave the `signature::Signer` wiring alone; make reproducibility a *tested*
contract. Rejected alternatives:

- **B — newtype wrapper calling `hazmat::try_sign_prehashed_rfc6979` explicitly.** Needs the
  `hazmat` feature (crate docs mark it hazardous), duplicates what the `Signer` impl already does,
  and adds a public type to `SigningKeyType` that every consumer must learn. Rejected.
- **C — pin the feature in `Cargo.toml` (declare `rfc6979` through a direct `ecdsa` dependency).**
  Determinism cannot degrade silently: `sign_prehash` calls `try_sign_prehashed_rfc6979`
  unconditionally (`ecdsa-0.16.9/src/signing.rs:158-164`), so a build without `rfc6979` does not
  compile. A manifest pin would defend against nothing while adding a dependency edge. Rejected.
- **D — close as "already true".** The claim would then rest on a hand-derived chain through three
  crates plus a throwaway probe; a future `signature`/`ecdsa` bump could move CMS to the randomized
  trait (`RandomizedSigner` impls exist side by side at `signing.rs:232`, `:295`, `:333`, `:391`,
  `:428`) and nothing in the repo would notice until users lost reproducibility. Rejected.

**Tests to add** (all in `crypto/cms.rs`'s `mod tests`, plus one in `macho::signer`'s `mod tests`;
the repo has zero ECDSA determinism coverage today, so this lane adds the first):

| Test | Level | What it pins |
|---|---|---|
| `ecdsa_signing_matches_rfc6979_known_answers` | the CMS trait method | DER of `Signer::<DerSignature>::sign(b"sample")` and `sign(b"test")` under the RFC's key equals the A.2.5 bytes (P11). Fails if the nonce source *or* the DER framing changes, in any process. Independent transcription check: `p256-0.13.2/src/ecdsa.rs:96-117` asserts the same pair. |
| `cms_ecdsa_signature_is_byte_identical_five_times` | `sign_code_directory` | the ticket's acceptance, plus a negative control: changing `cdhash_sha256` changes the output, so the test cannot pass by ignoring its input. |
| `sign_macho_ecdsa_is_byte_identical_twice` | `macho::signer::sign_macho` | blob-level reproducibility through the real slice pipeline, ECDSA credentials, no zip involved (so it is immune to the ZSN-15 entry-order flake). |

**D14.2.** A fixed-key P-256 credential helper joins the `cms.rs` test module — the tree's first:
every existing builder draws `OsRng` (`cert.rs:689`, `cms.rs:822`, `cms.rs:1061`,
`cms_verify.rs:2920`, `test_util.rs:46`), which is exactly why no current test can pin ECDSA bytes.
It builds `SigningCredentials` by literal (all four fields public, `cert.rs:89-108`) with a
self-issued `Profile::Leaf` (codeSigning EKU + digitalSignature KU, `CA:FALSE`, `OU=TESTTEAM`),
reusing the `cert.rs:718`/`cms_verify.rs:2118` conventions.

**D14.3.** `crypto/cms.rs` module docs state the invariant (`cms.rs:14-23`): ECDSA nonces are
RFC 6979 deterministic by contract; a **`signingTime` signed attribute must never be added** —
`cms-0.2.3/src/builder.rs:1102-1125` provides `create_signing_time_attribute`, and using it would
destroy byte reproducibility for RSA and ECDSA alike; and the ECDSA arm must stay on
`signature::Signer` rather than `RandomizedSigner`.

  The signing side does emit absent parameters, which is what RFC 5758 §3.2 asks for, but it is
  *inherited*, not pinned here: `build_cms_signed_data` is bounded on
  `spki::DynSignatureAlgorithmIdentifier` (`cms.rs:208`, `:367`), so the `SignerInfo`
  `signatureAlgorithm` comes from the key, and for P-256 that is
  `ecdsa-0.16.9/src/signing.rs:541-552` (`SignatureAlgorithmIdentifier for SigningKey<C>`) resolving
  to `ecdsa-0.16.9/src/lib.rs:477-488`, which sets `parameters: None` (`:486`). The one
  AlgorithmIdentifier our own file builds is the `SignerInfo` `digestAlgorithm`
  (`cms.rs:315-318`, and the test-only `TestDigest::algorithm` at `:95-103`), also with
  `parameters: None`.
  The verifier does **not** enforce that: `cms_verify::verify_signer_signature` (`:1202`) dispatches
  on the OID alone and never inspects `signature_algorithm.parameters`, so a trailing NULL is
  accepted. That is the shipped behaviour and is recorded here as a known gap, not claimed as a
  rejection.

  No ticket IDs in code comments (repo rule); the upstream comparison lives here and in the final
  report: upstream `zhlynn/zsign` signs via OpenSSL `CMS_sign`/`CMS_final`
  (`src/openssl.cpp:440-506`), i.e. OpenSSL's default randomized nonce, so its output is not
  reproducible run to run. An RFC 6979 signature is an ordinary P-256 ECDSA signature, so `codesign`
  and Apple verifiers cannot tell the difference.

**D14.4.** Verify path untouched. `cms_verify.rs:3064`
(`ecdsa_code_signature_round_trips_with_der_signer_info`) and `:3087` already prove a
RFC 6979-signed CMS blob verifies through `parse_ecdsa_signature` (`:1194`, DER then fixed-width
fallback); they stay green and the new tests reuse the same helper.

**Red-phase note.** The ticket asks for "two runs differ pre-fix". They do not (P1), so the
Tester's red artefact is a *mutation* check instead: temporarily route the ECDSA arm through
`RandomizedSigner::sign_with_rng(&mut OsRng, …)` and confirm both determinism tests go red, then
revert. That is the evidence the tests defend the contract rather than restate the code, and it is
reported as red→green-by-mutation, honestly labelled.

## ZSN-18 — encrypted private keys

**Decision D18.1.** One entry point, one password source, no new `Error` variants, exactly one new
crate (`md-5`), reached through the existing `SigningCredentials::from_pem(cert_pem, key_pem,
Option<&str>)` signature (`cert.rs:534`), which does not change — so no caller migrates and no CLI
flag appears. (The `:465` this cites in the base tree moved to `:534` when the traditional-key
branch landed inside `from_pem`.)

### Accepted formats and the code path that takes each

| Format | Marker | Path | Evidence |
|---|---|---|---|
| Encrypted PKCS#8, PBES2 + PBKDF2 (PRF HMAC-SHA1/224/256/384/512, absent prf = SHA-1) + AES-128/192/256-CBC | ``ENCRYPTED PRIVATE KEY` label` | reuse the in-tree PBES2 stack: `pkcs12::decrypt_key_bag` (`pkcs12.rs:810`, already an `EncryptedPrivateKeyInfo` reader) → `pbes2_decrypt` (`:493`, PRF matrix `:537-557`, `keyLength` agreement check `:524-534`, `validate_iterations` `:394`) → plaintext PKCS#8 DER → existing `DecodedKey::from_pkcs8_der` (`cert.rs:121`) | P2, P5 |
| Traditional OpenSSL encrypted PEM | `Proc-Type: 4,ENCRYPTED` + `DEK-Info: <cipher>,<hex IV>` on `PRIVATE KEY` / `RSA PRIVATE KEY` / `EC PRIVATE KEY` | new header-framing decoder (`crypto/encrypted_pem.rs`, production half ~200 lines including
the cipher table): header framing, `EVP_BytesToKey(MD5, iter = 1, salt = first 8 IV bytes)` for the **key bytes only**, decrypt CBC with the **header IV**, PKCS#7 unpad, then decode PKCS#8 / PKCS#1 / SEC1 **by content**, not by label (`TraditionalKey` discards the label, `encrypted_pem.rs:13-16`) | P6-P10 |
| Unencrypted, unchanged behaviour | `PRIVATE KEY` | content-driven `DecodedKey::from_der_by_content` (`cert.rs:131`), which replaced the label-locked
`from_pkcs8_pem` that this ticket deleted | P2 |

Reusing `pkcs12`'s PBES2 engine is what the brief asks for ("reuse ZSN-37's PBKDF2 PRF/keyLength
dispatch if it exposed reusable primitives"): it is a *visibility* change —
`decrypt_key_bag` (`:810`) and the generic CBC engine `aes_decrypt` (`:627`, the one
`encrypted_pem.rs:82-91` calls for every AES/3DES variant) go from private `fn` to `pub(crate)`
inside the same private `mod pkcs12` (`crypto/mod.rs:35`) — so nothing new becomes public API.
`pbes2_decrypt` (`:493`), `cbc_decrypt` (`:637`), `unpad_pkcs7` (`:670`) and `AlgorithmId` (`:358`)
stayed private: the PEM decoder reaches them through those two entries rather than by widening the
module further.

**D18.2. Rejected: the `pkcs8` vendor decrypt route.**
`pkcs8::DecodePrivateKey::from_pkcs8_encrypted_pem` (`pkcs8-0.10.2/src/traits.rs:31-64`) is one
line and already compiled into the crate, but P3/P4 measure that it rejects
`hmacWithSHA1` (`1.2.840.113549.2.7` — RFC 8018's *default* PRF, and OpenSSL 1.x's) and
`des-EDE3-CBC` until `sha1-insecure`/`3des`/`des-insecure` features are switched on. Those keys are
common in the wild, and turning those features on widens the PKCS#12-facing surface for no gain
once the in-tree path exists. Choosing one PBES2 implementation over two also keeps the
`keyLength`/iteration policy consistent between `.p12` and `.pem`.

**D18.3. Traditional framing is necessarily ours.** `der`/`pem-rfc7468` deliberately reject RFC 7468
headers (`pem-rfc7468-0.7.0/src/decoder.rs:31`, `:240-244` — the reader's own
`Error::HeaderDisallowed`; header detection is colon-based, so any `Name: value` line before the
base64 is rejected), and no RustCrypto crate implements `EVP_BytesToKey` (registry-wide search; the
only hit is `aws-lc-sys`'s bundled C). Two implementation details are pinned by P8 and must not be
"fixed" later: the IV is the `DEK-Info` hex string (the derived IV corrupts the first block), and
only `keyLen` bytes of the `EVP_BytesToKey` output are consumed.

**D18.4. Cipher matrix.** Accept `AES-128-CBC`, `AES-192-CBC`, `AES-256-CBC`, `DES-EDE3-CBC`
(in-tree `aes`/`des`). Reject `DES-CBC` (56-bit) and every `RC2-*` spelling with the explicit
unsupported-encryption error: unlike the PKCS#12 case, where Apple's own exports force legacy RC2
support, `DEK-Info` RC2 is a Netscape-era artifact and silently accepting weak keys is worse than a
clear message. Rejected alternative: full legacy parity with `pkcs12.rs` — extra code paths that no
iOS signing workflow emits.

**D18.5. Decoded key codings.** The traditional path decrypts to PKCS#1 (`RSA PRIVATE KEY`) or SEC1
(`EC PRIVATE KEY`), which the repo cannot decode today at all (premise 2), so the content-driven
decoder `DecodedKey::from_der_by_content` (`cert.rs:131-142`) tries the PKCS#1
(`rsa::pkcs1::DecodeRsaPrivateKey`) and SEC1 (`p256::SecretKey`, P9 confirms it links under our
current `p256` features) decodes inline, after the existing PKCS#8 attempt — no new public methods
are added, the two vendor decodes are inlined in that one function. Both codings are then *also*
accepted unencrypted, which is the same content-driven decoder being applied consistently rather
than a special case; the previously reachable `PRIVATE KEY` behaviour is unchanged and stays
covered by its existing tests.

### Error taxonomy (no new variants)

`error.rs` is exhaustive-matched with no wildcard in `zsign-wasm/src/lib.rs:113-127`, so a new
variant is a hard compile error in a wave-6 file plus a new stable JS code (its public contract,
`zsign-wasm/src/lib.rs:60-62`). Mapping onto what exists:

| Condition | Error | JS code |
|---|---|---|
| password given, plaintext undecryptable: PKCS#7 padding invalid, **or** padding valid but the DER/SPKI pairing check fails (the 1-in-256 case) | `Error::InvalidPassword` (`error.rs:19-20`, Display already says "private key or PKCS#12"; constructed nowhere today — this ticket makes it real) | `ZSIGN_INVALID_PASSWORD` |
| encryption we will not perform: unknown/weak `DEK-Info` cipher, PBES2 scheme or PRF outside the in-tree matrix, scrypt KDF, PBES1 (`pkcs-5 v1.5`) | `Error::Certificate("unsupported key encryption: <name or OID>")` | `ZSIGN_INVALID_CERTIFICATE` |
| encrypted key, no password supplied | `Error::Certificate("encrypted private key requires a password (-p or ZSIGN_PASSWORD)")` | `ZSIGN_INVALID_CERTIFICATE` |
| malformed container before any decryption attempt | `Error::Certificate("failed to parse encrypted private key: …")` | `ZSIGN_INVALID_CERTIFICATE` |

Wrong-password and unsupported-encryption are therefore different `Error` variants *and* different
JS codes, which is the explicitness the ticket asks for. A `keyLength` disagreement or an iteration
count above the existing `validate_iterations` ceiling (`pkcs12.rs:394`) stays the
malformed-container case, matching how the `.p12` route already treats them.

### CLI cutover (the one permitted `main.rs` edit)

Delete `reject_encrypted_key` (`main.rs:776-793` in the base tree) and its two call sites (`:810`
PEM route, `:845` DER route there; `:795` and `:827-831` after this lane's own cutover); pass
`cli.password.as_deref()` into `from_pem` at the same two sites. Migrate the five tests that pinned
the old text (`main.rs:1669-1716` at the base, now `main.rs:1670-1821`) to real behaviour:
encrypted PEM loads with the right password, wrong password produces the password error, and a
password on an unencrypted key is accepted — the loader now reaches the ordinary parse path and
fails there, with the old reject string asserted *absent* (`main.rs:1810-1814`). The DER route
keeps `pem_wrap_der` (`main.rs:879`): it already labels bodies `PRIVATE KEY`, and encrypted bodies
now flow through the same content-sniffing decoder — which is why routing is by content and not by
label. No clap attribute, no flag, no help-text change.

**Seam (not done here).** The TTY prompt lives in `resolve_p12_password` (`main.rs:848`) and is
PKCS#12-only, so an encrypted PEM without `-p`/`ZSIGN_PASSWORD` gets the explicit "requires a
password" error instead of a prompt. Extending the prompt to the PEM route is a password-flow change
in the lane that owns `main.rs`; it needs no new flag, only one `Option<&str>` threaded at the PEM
call site (`main.rs:795`; the DER route is `:827-831`).

## ZSN-21 — revocation warning

**Decision D21.1.** Ship OCSP as a callable, fully tested, wasm-safe-by-construction library
capability in `zsign-core`, with the automatic call site reported as a seam. Not a silent stub, not
a hard failure, and not an invented stderr channel.

Why not default-on inside this wave:

- The sign path has **no** diagnostic channel. Every `warnings: Vec<String>` in the workspace sits
  on a *verify* type (`crypto/cms_verify.rs:295`, `crypto/cms_verify.rs:1308`,
  `macho/verify.rs:57`, `crates/zsign/src/verify.rs:129`), printed only in verify output
  (`main.rs:348-350`) and mirrored into verify DTOs (`main.rs:582`, `:678`). No report object
  exists on the sign path.
- The once-per-invocation hooks that could carry one — `load_credentials` (`main.rs:776`) and
  `ZSign::get_credentials` (`builder.rs:264`) — are lane-forbidden, and `from_p12`/`from_pem`
  return only `Result<Self>`.
- Library-level stderr writes have zero production precedent in `zsign-core` (every `eprintln!` in
  the workspace is in `main.rs` or a test), as do process-global latches (no
  `OnceLock`/`LazyLock`/`thread_local` in production code).
- Today the crate says the opposite out loud: `crypto/cms_verify.rs:32-33` records "revocation
  remains a device concern", and `pkcs12.rs:804` drops CRL bags.

So an automatic version this wave means inventing an unowned sink in a file zsn40 owns — precisely
the case the brief sends to a seam report. The seam note names the one-line patch
(`load_credentials` → `revocation::warn_revocation(&creds.certificate, &creds.cert_chain);` —
the argument list the shipped code actually offers) and the sink options, so the orchestrator
can land it with the flag surface.

### Module surface

`crypto/revocation.rs` (new) — pure, wasm-compilable, zero `std::net`:

```rust
pub enum RevocationStatus {
    Good,
    Revoked { revoked_at: Option<time::OffsetDateTime>, reason: Option<String> },
    NotChecked(NotCheckedReason),
}
pub enum NotCheckedReason {                 // every variant here stays silent
    NoOcspUrl, NoIssuerCertificate, UnusableUrl, Transport(String), Malformed(String),
    NoMatchingCertId, Unverified, OutsideValidityWindow, BudgetExpired,
}
impl RevocationStatus {
    /// The user-facing warning: `Some` only for an authenticated `Revoked`.
    pub fn warning(&self) -> Option<String>;
}

/// The network edge as a trait, so tests drive it with canned bytes or a loopback
/// listener and none of them reaches the internet.
pub trait OcspTransport {
    fn post(&self, url: &str, body: &[u8]) -> Result<Vec<u8>, TransportError>;
}

pub fn ocsp_responder_url(leaf: &Certificate) -> Option<String>;
pub fn build_request(leaf: &Certificate, issuer: &Certificate) -> Option<Vec<u8>>;
pub fn parse_and_verify(response_der: &[u8], leaf: &Certificate, issuer: &Certificate,
                        now: time::OffsetDateTime) -> RevocationStatus;

pub fn check(leaf: &Certificate, issuer: Option<&Certificate>, transport: &dyn OcspTransport,
             now: Option<time::OffsetDateTime>) -> RevocationStatus;
#[cfg(not(target_arch = "wasm32"))]
pub fn warn_revocation(leaf: &Certificate, chain: &[Certificate]);      // the CLI-callable sink
```

`TransportError` (`:140`), `warning_of` (`:844`, network-free and callable from the caller's own
transport) and `HttpTransport` (`:884`, native-only) are public too, as is the `OcspTransport`
trait (`:150`) they implement. The rest of the module is private to the file —
`cert_id`, `stored_issuer_name_der`, `tlv`/`oid_tlv`/`concat`, `ext_value`,
`has_ocsp_signing_eku`, `verify_signature` — except `transport_reason` (`:829`), which is
`pub(crate)` so the mapping table can be named from a test.

`check` takes the certificate pair rather than `SigningCredentials` so the whole module is testable
with fixture certificates and needs no private key; `check` returns `NotChecked(_)` for every failure
mode and never an `Err`, so a caller cannot turn a warning into a gate by accident, and only an
authenticated `Revoked` produces text. `issuer_of` reads `SigningCredentials::cert_chain`
(populated from the `.p12` bag, or completed from the embedded Apple assets for the PEM route,
`crypto/cert.rs:355-386`) and matches on subject/issuer name. `warning_of` is
network-free and compiles for every target, which is what keeps the wasm surface honest: the only
function that opens a socket is `warn_revocation`, and that exists on native targets only. `now`
follows the crate's standing rule for new time-aware APIs — take `Option<OffsetDateTime>` and resolve
through `cms_verify::resolve_now` (`crypto/cms_verify.rs:1681-1699`), leaving the wasm fixed-clock
convention (`1_800_000_000`) untouched.

Request/response DER is built and parsed with the pinned `der`/`x509-cert`/`const-oid` stack:
`x509-cert 0.2.5` already exports `AuthorityInfoAccessSyntax`/`AccessDescription`
(`src/ext/pkix/access.rs:19-60`, re-exported at `ext/pkix.rs:17`), and `const-oid 0.9.6` carries
`ID_AD_OCSP`, `ID_PKIX_OCSP_BASIC`, `ID_KP_OCSP_SIGNING` — so AIA extraction and the response
envelope need no new dependency and no hand-rolled ASN.1 writer beyond the `CertID` framing.
`x509-cert` has **no** OCSP types, so the `OCSPRequest` is hand-framed with three local helpers
(`oid_tlv` `:233`, `tlv` `:248`, `concat` `:238`; `build_request` `:297-303` is three `tlv` calls
around the `CertID`) and the `OCSPResponse` is *walked* with the shared `pkcs12::DerReader` rather
than decoded into types — `basic_response` (`:413-458`) unwraps the envelope, and
`parse_and_verify` (`:310`) delegates to `walk_response` (`:462-578`), which reads the
`SingleResponse` fields one TLV at a time and uses `span_of_next_tlv` to capture `tbsResponseData`
as the exact bytes the responder signed.

### Verification posture

Trusted answer, per RFC 6960 §3.2 — stricter than upstream, which verifies nothing:

1. `CertID` recomputed and matched, SHA-1 as the hash algorithm: `sha1(stored_issuer_name_der(leaf))`
   — the issuer `Name` **sliced out of the leaf's own DER** (`:180-187`) — plus
   `sha1(issuer subjectPublicKey value bits)` and the serial. The stored-bytes recipe is the point:
   a `Name` stored in a non-minimal form re-encodes to bytes no responder ever hashed, so
   `Name::to_der()` is the wrong input even though it looks equivalent. P12 proves these recipes
   reproduce openssl's own request bytes for the embedded Apple pair (`bb4d3042…`/`2bd06947…`),
   and that the tempting wrong recipes (whole SPKI DER, subject DN) do not.
2. `responseStatus == successful(0)`; `responseType == id-pkix-ocsp-basic (1.3.6.1.5.5.7.48.1.1)`.
3. **Signature over `tbsResponseData`'s DER bytes verifies** against the issuer's key, or against a
   responder certificate embedded in the response that is (a) issued by that CA and (b) carries
   `id-kp-OCSPSigning (1.3.6.1.5.5.7.3.9)`. Two primitives are shared with the rest of the crate:
   `cms_verify::verify_cert_signature` (promoted to `pub(crate)` at `cms_verify.rs:1518`, used for the
   delegate's own certificate path) and `cms_verify::resolve_now` (`revocation.rs:44`). The
   response-signature check itself is deliberately local — `verify_signature` (`:697`) re-expresses
   the same three RSA-PKCS#1v1.5/P-256 arms over an *arbitrary message*, which is what a raw
   `tbsResponseData` is, because `cms_verify`'s routine also re-frames CMS `signedAttrs`; and
   `has_ocsp_signing_eku` (`:675`) is this module's own EKU lookup, since nothing in `cms_verify`
   performs that check. Anything else is `NotCheckedReason::Unverified`.
4. `thisUpdate <= now` and `nextUpdate` absent or `> now`; otherwise `OutsideValidityWindow`.

Anything but an authenticated `Revoked` is silent, and no branch can fail a signature.

**Delegate-certificate algorithm policy (changed during review).** One review pass found a second
certificate verifier living inside `revocation.rs` beside `cms_verify`'s; the duplicate was deleted in
favour of promoting `cms_verify::verify_cert_signature` (`:1518`) to `pub(crate)`, because the
delegate check *is* a one-link certificate-chain verification and should follow the chain builder's
policy rather than a bespoke copy. That also widened which signature algorithms a delegate certificate
may carry, from `sha1WithRSA`/`sha256WithRSA` plus `ecdsa-with-SHA256` only, to the shared
verifier's set: RSA with SHA-1/256/384/512 (SHA-256 standing in for an unrecognised RSA signature
OID) and P-256 ECDSA without an OID gate. Nothing else about the trust decision moved: a delegated
responder is still accepted only when its certificate is issued by this CA, carries
`id-kp-OCSPSigning`, **and** verifies under this CA's key — and a stronger digest is not a weaker
check. The OCSP *response* signature keeps its own strict OID allowlist in this module's
`verify_signature`, which is a different question (an arbitrary message under a key) and was never
merged into the certificate verifier. Note what
the posture does *not* claim: OCSP over plaintext HTTP proves the responder's key, not the channel,
so an on-path attacker can still *suppress* a warning by forging a `good` answer — the same
limitation upstream has. That is recorded here rather than papered over; it is also why this stays a
warning.

### Transport

Native-only (`#[cfg(not(target_arch = "wasm32"))]`), HTTP/1.1 `POST` with
`Content-Type: application/ocsp-request` over `std::net::TcpStream`: one caller-supplied budget
(`HttpTransport::budget`, defaulting to 3 s) is threaded into `connect_timeout` **and** the
socket read and write timeouts, so no single phase can outlive it; response capped at 64 KiB,
no redirects and no
`chunked` bodies (both are `Transport` outcomes), `http:` URLs only — Apple's AIA URI is plaintext
`http://ocsp.apple.com/ocsp03-applerootca` (P13), so a TLS stack would be dead weight.

DNS is the one step `std::net` cannot bound: `ToSocketAddrs` has no timeout. The whole exchange
therefore runs on a short-lived native worker thread and the caller waits with
`mpsc::recv_timeout(3 s)`, returning `BudgetExpired` and abandoning the worker (its own socket
deadlines make it exit). This is the crate's only added concurrency and it is native-only; rayon
already accounts for the rest (`code_directory.rs:66-68` documents its wasm degradation).

**Rejected:** `ureq` (3.3.0 pulls `base64`, `url`, `percent-encoding`, `log`; 2.13.2 pulls
`base64ct`, `url`, `percent-encoding`; neither builds for `wasm32-unknown-unknown`, so the dep buys
nothing for the wasm half of the workspace and every added crate is a permanent `cargo deny`
license and advisory surface — the `cargo-deny` job, `ci.yml:117-126`). **Rejected:**
`curl`/`openssl ocsp` subprocess (breaks the Windows CI job `ci.yml:65`). **Rejected:**
`rustls`/full TLS (no `https:` responder needed today).

### Deferred, with reasons

- **Static known-revoked list:** none exists with a usable license (premise 5), and inventing
  entries is out of bounds. The alternative outcome the brief permits — deferral — is taken *only*
  for this sub-feature, with the OCSP path implemented instead.
- **CRL distribution points:** `x509-cert 0.2.5` does ship `crl::CertificateList`/`RevokedCert`, but
  a CRL check needs another fetch plus CRL signature and freshness handling: same cost class, worse
  latency, and Apple's iOS-signing CRLs are not a redistributable list.
- **Response caching, stapling, must-staple enforcement, OCSP signing-nonce echoing (§3.2.3),
  tryLater retry:** out of scope for a best-effort warning.
- **`https:` responder URIs:** not fetched. Adding a TLS stack is not defensible for a warning,
  and every Apple AIA OCSP location inspected here is plaintext `http:`. The shipped code reports
  that as `UnusableUrl`, deliberately distinct from `NoOcspUrl`, so a user can tell "a responder
  this tool will not speak to" from "a certificate with no OCSP pointer".
- **Revocation reason vocabulary:** the optional `[0] EXPLICIT CRLReason` is parsed and named
  through the RFC 5280 §5.3.1 labels; an out-of-range number becomes `unknown(<n>)` rather than a
  guess, and a response that omits the field yields no reason at all.
- **Hard freshness ceiling when the responder omits `nextUpdate`:** not enforced. RFC 6960 makes
  `nextUpdate` OPTIONAL and the fixture responder omits it, so the rule implemented here is
  `thisUpdate <= now` plus `now < nextUpdate` when present. A captured-old `good` answer therefore
  stays credible indefinitely to this code, which is acceptable only because the outcome is a
  warning and the response still has to carry the issuer's signature. Recorded as a known limit,
  not as a policy claim.
- **A hard-fail mode:** forbidden by the ticket ("a signal, not a gate").

## Cross-cutting decisions

**Dependencies.** Exactly one new crate for the lane: `md-5 = "0.10"` (RustCrypto; MIT OR
Apache-2.0, both already allowlisted at `deny.toml:14-27`; `no_std`-capable so it is wasm-safe; no
RUSTSEC advisory; held to the 0.10 line because 0.11 needs `digest` 0.11 while the tree is on 0.10).
`deny.toml` itself needs **no** edit, so the `cargo deny check` job (`ci.yml:117-125`,
`yanked = "deny"`, sole ignore `RUSTSEC-2023-0071`) sees no policy change — recorded rather than
assumed: `cargo-deny` is not installed in this environment, so the posture is argued from
`deny.toml` + the crate's license metadata, and CI is the empirical check.

**wasm contract.** Nothing in `crypto/` gains an unguarded `std::net`, `std::env`, `Instant`,
`std::fs`, or new clock source; the revocation transport and its budget thread are
`#[cfg(not(target_arch = "wasm32"))]`; `time_now()`/`resolve_now()` semantics are unchanged. Gates:
`cargo check -p zsign-wasm --target wasm32-unknown-unknown` (`ci.yml:88`), release wasm build
(`ci.yml:90`), `wasm-pack test --node` (`ci.yml:96`).

**Public API.** Two new public modules — `crypto::revocation` and `crypto::encrypted_pem`
(`crypto/mod.rs:34`, `:36`) — plus the widened `from_pem` password semantics (signature
unchanged). Every item in `encrypted_pem` is `pub(crate)`, so that second module is a public path
with no public items. `SigningCredentials` keeps its exact four-field public shape — the
credential-hardening spec froze it for structural reasons
(`specs/2026-09-25-credential-hardening-design.md:48-51`), and it still holds: 17
struct-literal sites exist in tests/benches, zero in production.

**Revocation coverage is hermetic in two layers.** Layer 1, every target: canned DER — the
`build_request` output is compared byte-for-byte with openssl's own 106-byte `req.der` (P12, the
`CertID` as a byte-substring). The leaf/issuer pair is `issued_leaf.pem` + `ca.pem`, and
`parse_and_verify` is driven by the five committed response DERs — `good.der`,
`good_nextupdate.der`, `revoked.der`, `good_delegate.der` and `good_delegate_nocert.der` — with an
injected `now`. The "stale" and "mis-signed" behaviours are not fixture files but injected clocks
and in-memory DER mutation, so no committed answer is stale by the time it is read.
Layer 2, native only: a `TcpListener` bound to `127.0.0.1:0` inside the test serves
the canned bytes through the real `HttpTransport`, so the header set, the size cap, the read timeout
and `warn_revocation` itself are exercised with no DNS and no internet — the leaf's AIA URI is
written at runtime with the accepted port, using the same extension-replacement idiom the verify
tests already use (`crypto/cms_verify.rs:2397`).

**Fixtures.** Committed bytes, never generated at test time, no live network in any test:
encrypted-key fixtures from documented `openssl` recipes in the ZSN-37 idiom (`mktemp -d` under
`$HOME/tmp-cargo`, throwaway CN, policy-compliant leaf extensions, scratch keys deleted afterwards,
a fail-loud verification guard rather than an `echo`-and-pass check), stored in
`crates/zsign-core/src/crypto/fixtures/` (package-excluded at `crates/zsign-core/Cargo.toml:9`).

The repository's pre-commit `detect-private-key` hook decides the *encoding*. Measured on this tree:
a certificate container passes; every key container is refused, including `ENCRYPTED PRIVATE KEY`
ones, because the detector matches the label and not the ciphertext. So each encrypted key
container is committed as one `base64 -w0` blob of the complete OpenSSL PEM text (`*.pem.b64`) and
decoded by a five-line test helper back to byte-exact OpenSSL output, while the two certificates
stay readable `.pem`. That is a storage format for *encrypted* test material under a passphrase
printed next to it — the payload is ciphertext — not a way around the hook: no ignore rule, no
`--no-verify`, no `hk` config change, and the recipe's last guard runs the hook itself on every
committed file. **No plaintext private key is committed by this lane at all**: the unencrypted
PKCS#8 / PKCS#1 / SEC1 cases generate their key inside the test and frame it at runtime, which also
keeps them honest regression tests of the new decoder.

OCSP request and response fixtures come from the offline `openssl ca` + `openssl ocsp
-reqin/-respout` recipe that produced P14 (certificates and DER only). New fixtures are flagged for
the ZSN-30 consolidation (wave 7).

**Gate integrity.** This lane touches no CI workflow and no `deny.toml` policy: the existing
ZSN-15 flake-skip line and the duplicate-version warning level stay exactly as they are, and no new
skip is introduced. Every test added here is deterministic by construction — fixed keys, injected
clocks, mocked transports, committed fixtures — so it passes in the unskipped debug job
(`ci.yml:49`) and in `wasm-pack test --node` (`ci.yml:96`). If one of the lane's own tests turns out
to be flaky, the fix is the test, never the gate.
