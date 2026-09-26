# Design: deterministic ECDSA pin, encrypted PEM credentials, revocation warning

Lane **zsn42-crypto**, 2026-09-26. Tickets ZSN-14 / ZSN-18 / ZSN-21 (Kaneo), worked in queue
order; each lands as its own green commit series. Base `97e8460`.

Inputs: three codebase scouts (PEM/password wiring, crypto invariants + fixtures, wasm/warning
boundaries), one librarian pass (`.tmptmp/research/zsn42-crypto-research.md`), and probes run on
this machine (OpenSSL 3.6.3, pinned crate versions). Every claim below is either a `file:line`
cite, an RFC quote, or a **measured** probe result.

## Premise corrections (re-derived against current source)

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

**Tests to add** (all in `crypto/cms.rs`'s `mod tests`; the repo has zero ECDSA determinism coverage
today — `macho/signer.rs:973` and `cert.rs:1219` are RSA-only):

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

**D14.3.** `crypto/cms.rs` module docs state the invariant: ECDSA nonces are RFC 6979 deterministic
by contract; `signatureAlgorithm` is `ecdsa-with-SHA256 (1.2.840.10045.4.3.2)` with **parameters
absent** (RFC 5758 §3.2; `cms_verify.rs:1235` already rejects a NULL-parameter form); and a
**`signingTime` signed attribute must never be added** — `cms-0.2.3/src/builder.rs:1102-1125`
provides `create_signing_time_attribute`, and using it would destroy byte reproducibility for RSA
and ECDSA alike. No ticket IDs in code comments (repo rule); the upstream comparison lives here and
in the final report: upstream `zhlynn/zsign` signs via OpenSSL `CMS_sign`/`CMS_final`
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
Option<&str>)` signature (`cert.rs:465`), which does not change — so no caller migrates and no CLI
flag appears.

### Accepted formats and the code path that takes each

| Format | Marker | Path | Evidence |
|---|---|---|---|
| Encrypted PKCS#8, PBES2 + PBKDF2 (PRF HMAC-SHA1/224/256/384/512, absent prf = SHA-1) + AES-128/192/256-CBC | ``ENCRYPTED PRIVATE KEY` label` | reuse the in-tree PBES2 stack: `pkcs12::decrypt_key_bag` (`pkcs12.rs:793`, already an `EncryptedPrivateKeyInfo` reader) → `pbes2_decrypt` (`:481`, PRF matrix `:525-545`, `keyLength` agreement check `:516-522`, `validate_iterations` `:382`) → plaintext PKCS#8 DER → existing `DecodedKey::from_pkcs8_der` (`cert.rs:118`) | P2, P5 |
| Traditional OpenSSL encrypted PEM | `Proc-Type: 4,ENCRYPTED` + `DEK-Info: <cipher>,<hex IV>` on `PRIVATE KEY` / `RSA PRIVATE KEY` / `EC PRIVATE KEY` | new ~90-line decoder: header framing, `EVP_BytesToKey(MD5, iter = 1, salt = first 8 IV bytes)` for the **key bytes only**, decrypt CBC with the **header IV**, PKCS#7 unpad, then decode PKCS#8 / PKCS#1 / SEC1 by label | P6-P10 |
| Unencrypted, unchanged behaviour | `PRIVATE KEY` | existing `DecodedKey::from_pkcs8_pem` (`cert.rs:126-132`) | P2 |

Reusing `pkcs12`'s PBES2 engine is what the brief asks for ("reuse ZSN-37's PBKDF2 PRF/keyLength
dispatch if it exposed reusable primitives"): it is a *visibility* change —
`decrypt_key_bag`, `cbc_decrypt`, `unpad_pkcs7`, `AlgorithmId` go from private `fn`/`struct` to
`pub(crate)` inside the same private `mod pkcs12` (`crypto/mod.rs:33`) — so nothing new becomes
public API.

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
(`EC PRIVATE KEY`), which the repo cannot decode today at all (premise 2), so
`DecodedKey` grows `from_pkcs1_der` (`rsa::pkcs1::DecodeRsaPrivateKey`) and
`from_sec1_der` (`p256::SecretKey`, P9 confirms it links under our current `p256` features) next to
the existing PKCS#8 attempts. Both are then *also* accepted unencrypted, which is the
label-driven decoder being applied consistently rather than a special case; the previously
reachable `PRIVATE KEY` behaviour is unchanged and stays covered by its existing tests.

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
count above the existing `validate_iterations` ceiling (`pkcs12.rs:382`) stays the
malformed-container case, matching how the `.p12` route already treats them.

### CLI cutover (the one permitted `main.rs` edit)

Delete `reject_encrypted_key` (`main.rs:776-793`) and its two call sites (`:810` PEM route, `:845`
DER route); pass `cli.password.as_deref()` into `from_pem` at `:815` and `:848`. Migrate the five
tests that pin the old text (`main.rs:1669-1716`) to real behaviour: encrypted PEM loads with the
right password, wrong password produces the password error, and a password on an unencrypted key is
accepted (the "any password is a reject" rule disappears with the function). The DER route keeps
`pem_wrap_der` (`main.rs:896-908`): it already labels bodies `PRIVATE KEY`, and encrypted bodies now
flow through the same content-sniffing decoder. No clap attribute, no flag, no help-text change.

**Seam (not done here).** The TTY prompt lives in `resolve_p12_password` (`main.rs:865-892`) and is
PKCS#12-only, so an encrypted PEM without `-p`/`ZSIGN_PASSWORD` gets the explicit "requires a
password" error instead of a prompt. Extending the prompt to the PEM route is a password-flow change
in the lane that owns `main.rs`; it needs no new flag, only one `Option<&str>` threaded at `:815`.

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
- The once-per-invocation hooks that could carry one — `load_credentials` (`main.rs:795`) and
  `ZSign::get_credentials` (`builder.rs:264`) — are lane-forbidden, and `from_p12`/`from_pem`
  return only `Result<Self>`.
- Library-level stderr writes have zero production precedent in `zsign-core` (every `eprintln!` in
  the workspace is in `main.rs` or a test), as do process-global latches (no
  `OnceLock`/`LazyLock`/`thread_local` in production code).
- Today the crate says the opposite out loud: `crypto/cms_verify.rs:32-33` records "revocation
  remains a device concern", and `pkcs12.rs:787` drops CRL bags.

So an automatic version this wave means inventing an unowned sink in a file zsn40 owns — precisely
the case the brief sends to a seam report. The seam note names the two-line patch
(`builder.rs:264` → `if let Some(w) = revocation::warning_of(creds) { … }`) and the sink options, so
the orchestrator can land it with the flag surface.

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
pub fn build_request(leaf: &Certificate, issuer: &Certificate) -> Result<Vec<u8>>;
pub fn parse_and_verify(response_der: &[u8], leaf: &Certificate, issuer: &Certificate,
                        now: time::OffsetDateTime) -> RevocationStatus;
pub fn check(leaf: &Certificate, issuer: Option<&Certificate>, transport: &dyn OcspTransport,
             now: Option<time::OffsetDateTime>) -> RevocationStatus;
#[cfg(not(target_arch = "wasm32"))]
pub fn warn_revocation(leaf: &Certificate, chain: &[Certificate]);      // the CLI-callable sink
```

`check` takes the certificate pair rather than `SigningCredentials` so the whole module is testable
with fixture certificates and needs no private key; `check` returns `NotChecked(_)` for every failure
mode and never an `Err`, so a caller cannot turn a warning into a gate by accident, and only an
authenticated `Revoked` produces text. `issuer_of` reads `SigningCredentials::cert_chain`
(populated from the `.p12` bag, or completed from the embedded Apple assets for the PEM route,
`crypto/cert.rs:271-322`) and matches on subject/issuer name. `warning_of` is
network-free and compiles for every target, which is what keeps the wasm surface honest: the only
function that opens a socket is `warn_revocation`, and that exists on native targets only. `now`
follows the crate's standing rule for new time-aware APIs — take `Option<OffsetDateTime>` and resolve
through `cms_verify::resolve_now` (`crypto/cms_verify.rs:1681-1703`), leaving the wasm fixed-clock
convention (`1_800_000_000`) untouched.

Request/response DER is built and parsed with the pinned `der`/`x509-cert`/`const-oid` stack:
`x509-cert 0.2.5` already exports `AuthorityInfoAccessSyntax`/`AccessDescription`
(`src/ext/pkix/access.rs:19-60`, re-exported at `ext/pkix.rs:17`), and `const-oid 0.9.6` carries
`ID_AD_OCSP`, `ID_PKIX_OCSP_BASIC`, `ID_KP_OCSP_SIGNING` — so AIA extraction and the response
envelope need no new dependency and no hand-rolled ASN.1 writer beyond the `CertID` framing.
`x509-cert` has **no** OCSP types, so `OCSPRequest`/`OCSPResponse` are local `#[derive(Sequence)]`
structs in this module (the same pattern `cms_verify.rs` uses for its hand-parsed envelopes).

### Verification posture

Trusted answer, per RFC 6960 §3.2 — stricter than upstream, which verifies nothing:

1. `CertID` recomputed and matched: `sha1(leaf.tbs_certificate.issuer.to_der())` and
   `sha1(issuer subjectPublicKey value bits)` plus the serial, SHA-1 as the hash algorithm. P12
   proves these exact recipes reproduce openssl's own request bytes for the embedded Apple pair
   (`bb4d3042…`/`2bd06947…`), and that the tempting wrong recipes (whole SPKI DER, subject DN) do
   not.
2. `responseStatus == successful(0)`; `responseType == id-pkix-ocsp-basic (1.3.6.1.5.5.7.48.1.1)`.
3. **Signature over `tbsResponseData`'s DER bytes verifies** against the issuer's key, or against a
   responder certificate embedded in the response that is (a) issued by that CA and (b) carries
   `id-kp-OCSPSigning (1.3.6.1.5.5.7.3.9)`. Reuses the existing RSA-PKCS#1v1.5/P-256 verify
   primitives (`cms_verify.rs:1237-1286`, `:1518-1566`). Anything else is `UnverifiedResponse`.
4. `thisUpdate <= now` and `nextUpdate` absent or `> now`; otherwise `OutsideValidityWindow`.

Anything but an authenticated `Revoked` is silent, and no branch can fail a signature. Note what
the posture does *not* claim: OCSP over plaintext HTTP proves the responder's key, not the channel,
so an on-path attacker can still *suppress* a warning by forging a `good` answer — the same
limitation upstream has. That is recorded here rather than papered over; it is also why this stays a
warning.

### Transport

Native-only (`#[cfg(not(target_arch = "wasm32"))]`), HTTP/1.1 `POST` with
`Content-Type: application/ocsp-request` over `std::net::TcpStream`: `connect_timeout(1.5 s)`,
`set_write_timeout`/`set_read_timeout(2 s)`, response capped at 64 KiB, no redirects and no
`chunked` bodies (both are `Transport` outcomes), `http:` URLs only — Apple's AIA URI is plaintext
`http://ocsp.apple.com/ocsp03-applerootca` (P13), so a TLS stack would be dead weight.

DNS is the one step `std::net` cannot bound: `ToSocketAddrs` has no timeout. The whole exchange
therefore runs on a short-lived native worker thread and the caller waits with
`mpsc::recv_timeout(3 s)`, returning `BudgetExpired` and abandoning the worker (its own socket
deadlines make it exit). This is the crate's only added concurrency and it is native-only; rayon
already accounts for the rest (`code_directory.rs:66-68` documents its wasm degradation).

**Rejected:** `ureq` (3.3.0 pulls `base64`, `url`, `percent-encoding`, `log`; 2.13.2 pulls
`base64ct`, `url`, `percent-encoding`; neither builds for `wasm32-unknown-unknown`, so the dep buys
nothing for the wasm half of the workspace and every added crate is a permanent
`cargo deny check`/`cargo hack --feature-powerset` surface — `ci.yml:131`). **Rejected:**
`curl`/`openssl ocsp` subprocess (breaks the Windows CI job `ci.yml:75`). **Rejected:**
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

**Public API.** Two new public paths only: the `crypto::revocation` module and the widened
`from_pem` password semantics (signature unchanged). `SigningCredentials` keeps its exact four-field
public shape — the credential-hardening spec froze it for structural reasons
(`specs/2026-09-25-credential-hardening-design.md:48-51`), and it still holds: 14 struct-literal
sites exist in tests/benches, zero in production.

**Revocation coverage is hermetic in two layers.** Layer 1, every target: canned DER — the
`build_request` output is compared byte-for-byte with openssl's own 106-byte request (P12), and
`parse_and_verify` is driven by the `good`/`revoked`/`stale`/`mis-signed` DER fixtures (P14) with an
injected `now`. Layer 2, native only: a `TcpListener` bound to `127.0.0.1:0` inside the test serves
the canned bytes through the real `HttpTransport`, so the header set, the size cap, the read timeout
and `warn_revocation` itself are exercised with no DNS and no internet — the leaf's AIA URI is
written at runtime with the accepted port, using the same extension-replacement idiom the verify
tests already use (`crypto/cms_verify.rs:2397`).

**Fixtures.** Committed bytes, never generated at test time, no live network in any test:
encrypted-key fixtures from documented `openssl` recipes in the ZSN-37 idiom
(`mktemp -d` under `$HOME/tmp-cargo`, throwaway CN, policy-compliant leaf extensions, scratch keys
deleted afterwards, a fail-loud verification guard rather than an `echo`-and-pass check), stored in
`crates/zsign-core/src/crypto/fixtures/` (package-excluded at `crates/zsign-core/Cargo.toml:9`) and
loaded through `include_bytes!` inside `#[cfg(test)]` (`pkcs12.rs:901-909` precedent). OCSP request
and response fixtures come from the offline `openssl ca` + `openssl ocsp -reqin/-respout` recipe
that produced P14. New fixtures are flagged for the ZSN-30 consolidation (wave 7).

**Gate integrity.** This lane touches no CI workflow and no `deny.toml` policy: the existing
ZSN-15 flake-skip line and the duplicate-version warning level stay exactly as they are, and no new
skip is introduced. Every test added here is deterministic by construction — fixed keys, injected
clocks, mocked transports, committed fixtures — so it passes in the unskipped debug job
(`ci.yml:49`) and in `wasm-pack test --node` (`ci.yml:96`). If one of the lane's own tests turns out
to be flaky, the fix is the test, never the gate.
