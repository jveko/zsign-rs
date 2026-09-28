# Design: Apple Root anchoring for the credential load path (ZSN-96)

Status: authored 2026-09-28 on branch `zsn-96-apple-root-anchor` (base `a428a68`).
All file:line citations refer to that revision.

## 1. Problem

`build_chain_from_leaf` (`crates/zsign-core/src/crypto/cert.rs:347-382`) assembles a
certificate chain by issuer/subject name equality only. Neither it nor its callers
(`from_pem` `cert.rs:546-571`, `finish_p12` `cert.rs:680-699`, which serves `from_p12`
`cert.rs:615-630` and `from_p12_with_leaf_sha1` `cert.rs:644-676`) check that:

1. the walk terminates at a certificate whose SPKI equals the embedded Apple Root CA
   (`crypto/assets.rs` `APPLE_ROOT_CA_CERT`),
2. each link is actually signed by its parent, or
3. each link is a CA.

A fully self-issued "Evil Root CA" PKCS#12 therefore loads through the public
`SigningCredentials::from_p12` and the unanchored chain is embedded verbatim into the
emitted CMS (`crypto/cms.rs:394-398`). This contradicts the field's own doc
(`cert.rs:111-114`, "These certificates connect the signing certificate to the Apple
Root CA") and the project's fail-closed posture. `team_id` is attacker-chosen OU —
once the chain is anchored, an Apple-anchored leaf implies Apple-issued OU, so no
separate `team_id` change is required.

The verify side already implements the required checks: `verify_chain`
(`crypto/cms_verify.rs:1336-1511`) verifies every link signature
(`verify_cert_signature`, `cms_verify.rs:1518-1572`, `pub(crate)`), enforces
CA constraints via `issuer_ca_reason` (`cms_verify.rs:1641-1668`: basicConstraints
CA, pathLen, keyCertSign), verifies a self-signed terminus's self-signature
(`cms_verify.rs:1432-1442`), and matches the terminus SPKI against a `TrustAnchors`
set (`cms_verify.rs:1444-1452` via `contains_spki`, `cms_verify.rs:455-463`).
`TrustAnchors::apple_root()` (`cms_verify.rs:443-452`) parses the embedded Apple
root. The load path simply never calls any of it.

## 2. Requirements (from the ticket)

- (i) An Evil-Root p12 is rejected by `from_p12` with a typed `Error::Certificate`
  that names the unanchored leaf.
- (ii) A correctly Apple-anchored chain is accepted.
- (iii) The existing suite stays green; tests that need self-issued chains move to a
  gated path.
- (iv) `zsign-wasm` and `zsign-cli` compile and their relevant tests pass.
- Fail-closed: a wrong chain must ERROR, never warn. No shims — every caller migrated.
- The gated constructor must never be reachable from the CLI, facade, or wasm
  bindings as shipped.

## 3. Candidate designs

**A — hard-anchor inside `build_chain_from_leaf`** (make it return `Result`,
terminate-SPKI check inline). Rejected: couples assembly with policy, so the existing
pure-assembly unit tests (`cert.rs:1191,1207,1221,1265`) can no longer be written,
and a termination check alone (no link-signature/CA checks) is forgeable — an
attacker's leaf claiming `issuer=Apple WWDR CA` plus the *publicly available* real
WWDR and real Apple Root certificates as `rest` would pass name-walk + SPKI pin.

**B — a separate load-time policy step in the constructors** (chosen). Assembly stays
pure; a new `require_anchored_chain` runs at the end of `finish_p12` and `from_pem`,
reusing the verify-side chain walk.

**C — injectable anchor set with production default = Apple roots at the public
constructors.** Rejected: widens the public API with a production-reachable knob
(callers could inject attacker anchors), and it does not help the fixtures anyway —
self-signed leaves produce *empty* chains, so tests would have to manufacture an
anchor from the very certificate under test. Injection stays where it already exists
and is safe: the private policy function's `anchors` parameter (unit tests only), with
production callers hardcoded to `TrustAnchors::apple_root()`. This mirrors the
in-tree `verify_code_signature` / `verify_code_signature_with_anchors` split.

**Other rejected alternatives**

- *Feature-flag that flips `from_p12`'s behavior* (`test-fixtures` on → skip
  anchoring): rejected — it would make it impossible to write the primary regression
  test (rejection through the public `from_p12`) in test builds, and it turns a
  fixture feature into a silent security switch.
- *New verification crate* (`x509-verify`, `pkix-path`, …): rejected — `x509-cert`
  0.2.5 is parse-only (RustCrypto/formats#838 still open), but the repository already
  ships the exact primitive (`verify_cert_signature`), already reused by
  `revocation.rs:670`. No new dependency is warranted.
- *Pin the full DER of the terminal certificate*: rejected as stricter than the
  ticket specifies; SPKI pin + self-signature verification of the terminus gives the
  same security (a cert carrying Apple's public key but signed by any other key fails
  its own self-signature check under that key).
- *Embed Apple Root CA - G2/G3 as additional anchors* (real gap — WWDR G2/G6 chain to
  Apple Root CA - G3, WWDR MP CA 1 to G2): deferred. It requires new embedded assets
  and `p384` signature support (`verify_cert_signature` is P-256-only and `p384` is
  absent from `Cargo.lock`), which is outside this ticket's files. Documented as a
  known limitation in §6.
- *Name-only `is_apple_root` CN check as the anchor test*: rejected — CN equality is
  exactly the hole this ticket closes.
- *Rewriting CLI success tests into error-class assertions everywhere*: rejected in
  favor of preserving strong assertions (see §5).

## 4. Chosen design

### 4.1 Assembly: complete the chain at the embedded root

`build_chain_from_leaf` keeps its walk and the WWDR injection
(`embedded_wwdr_for_leaf`, `cert.rs:384-398`) unchanged, but the root-completion rule
is generalized. Today the embedded root is appended only when a WWDR intermediate is
present (`cert.rs:375-381`). New rule, replacing the `has_wwdr` gate:

> Let `terminal` be the last chain element, or the leaf when the chain is empty. If
> `terminal` is not self-signed (`subject != issuer`), and `terminal`'s issuer
> `Name` equals the parsed embedded Apple Root CA's subject `Name`, and the chain
> does not already contain a root (existing `is_apple_root` dedup), append the
> embedded `APPLE_ROOT_CA_CERT`.

Name equality is full-DN (the same comparison `verify_chain` uses to find a parent),
not CN substring. Consequences:

- leaf directly issued by the Apple Root CA with no extras in the p12 → chain
  `[root]`, literally terminating at the pinned SPKI (today: empty chain, rejected);
- leaf + non-WWDR Apple intermediate (Developer ID, …) without the root in the p12 →
  `[int, root]`;
- WWDR chains behave exactly as before (`cert.rs:1221` stays green);
- a forged issuer that merely *names* Apple Root CA either fails the DN match (no
  injection → `verify_chain` reports a missing issuer) or, when the DN matches,
  fails leaf→root signature verification. Both fail closed.

A dangling terminal whose issuer is not the Apple root (evil chains) is left as-is;
the policy step rejects it.

### 4.2 Policy: `require_anchored_chain`

New private function in `cert.rs`:

```rust
fn require_anchored_chain(
    leaf: &Certificate,
    chain: &[Certificate],
    anchors: &TrustAnchors,
) -> Result<()> {
    let outcome = super::cms_verify::verify_chain(
        chain, leaf, anchors, time_now(), SignerPurpose::CodeSigning,
    );
    if outcome.ok && outcome.anchored {
        return Ok(());
    }
    let detail = outcome.reason.unwrap_or_else(|| {
        "certificate chain is not anchored to a trusted root".to_string()
    });
    Err(Error::Certificate(format!(
        "signing certificate \"{}\": {}",
        leaf.tbs_certificate.subject, detail
    )))
}
```

The `anchors` parameter exists so unit tests can exercise the accept path with an
injected test root; both production call sites pass `TrustAnchors::apple_root()?`.
The default detail string matches the verify-side wording (`cms_verify.rs:1113`).
Every failure is `Error::Certificate` — typed, naming the unanchored leaf.

`verify_chain` supplies, in its own audited order: leaf purpose (codeSigning EKU,
KU digitalSignature, BC CA=false — identical rules to the already-run
`code_signing_policy_violation`, so no divergence), leaf and issuer validity windows,
issuer CA constraints (BC CA present, pathLen, keyCertSign), every link's signature,
the terminus self-signature, and the terminus SPKI anchor match (with a
find-the-anchor-by-subject fallback that still verifies the final link against the
real anchor key). The attack shapes from §3 (name-walk forgery, forged terminus
carrying Apple's public key, leaf claiming Apple-root issuer without being signed by
it) each fail a distinct check.

To call it from `cert.rs`, `verify_chain`, `ChainOutcome` (and its fields), and
`SignerPurpose` in `cms_verify.rs` change from private to `pub(crate)`. No behavior
of the verify side changes.

### 4.3 Gate ordering

- `finish_p12` (`cert.rs:680-699`): key decode → `code_signing_policy_violation` →
  `build_chain_from_leaf` → **`require_anchored_chain`** → assemble. Policy before
  anchoring is deliberate: the CLI's empty-password trial
  (`zsign-cli/src/main.rs:931-936`) and its test (`main.rs:1573`) depend on a
  policy-gate error surfacing for `empty_password.p12`, and wrong-password handling
  must keep its existing error classes.
- `from_pem` (`cert.rs:546-571`): existing order unchanged, with
  **`require_anchored_chain`** added after the existing policy check.
- `resolve_p12_password` (`main.rs:928-959`) needs no change: an anchoring error is
  not "password-shaped" (its two markers are MAC/decryption strings), so it surfaces
  verbatim, exactly like a policy rejection — which its doc comment already
  prescribes ("Other failures (policy rejection, corruption) surface verbatim").

### 4.4 Test-only surface

Two public constructors, gated exactly like `macho::fixtures`
(`#[cfg(any(test, feature = "test-fixtures"))]`, precedent at
`macho/mod.rs:14`), plus one crate-internal:

```rust
#[cfg(any(test, feature = "test-fixtures"))]
pub fn from_p12_unanchored(p12_data: &[u8], password: &str) -> Result<Self>;
#[cfg(any(test, feature = "test-fixtures"))]
pub fn from_pem_unanchored(cert_pem: &[u8], key_pem: &[u8], password: Option<&str>) -> Result<Self>;
#[cfg(test)]
pub(crate) fn from_p12_with_leaf_sha1_unanchored(p12_data: &[u8], password: &str, leaf_sha1: &[u8; 20]) -> Result<Self>;
```

They run every existing check (parse, pairing, weak-key, code-signing policy) and
skip only `require_anchored_chain`. Their doc comments state they exist for
self-issued test fixtures and must not be used in production. Shared bodies are
private (`finish_p12(..., ChainTrust)` / `from_pem_inner(..., ChainTrust)` with a
module-private `enum ChainTrust { AppleRoot, Unanchored }`) — the public anchored
constructors never branch on build configuration: **`from_p12`/`from_pem` are
anchored in every build, including test builds**, so the primary regression test can
always call them.

The `test-fixtures` feature is already declared (`zsign-core/Cargo.toml:61-64`,
"enabled exclusively through dev-dependencies so it never reaches release or wasm
artifacts") and already enabled by all three sibling crates' dev-dependencies
(`zsign/Cargo.toml:31`, `zsign-cli/Cargo.toml:19`, `zsign-wasm/Cargo.toml:26`).
The workspace uses resolver "2" (root `Cargo.toml:2`), so those dev features cannot
leak into release builds or the CLI child binary that the subprocess tests build
(`cargo build -p zsign-cli`, `main.rs:1016-1027`).

## 5. Test strategy

### 5.1 New fixture: an evil three-certificate chain

`crates/zsign-core/src/crypto/fixtures/evil_root_chain.p12` (password
`testpassword`), generated with the OpenSSL 3.6.3 already used for every committed
fixture — commands recorded verbatim in this lane's final report, no tracked
generation script (precedent: `docs/superpowers/plans/2026-09-25-credential-hardening.md`).
Contents:

- `CN=Evil Root CA` — self-signed root, `CA:TRUE`;
- `CN=Evil Intermediate CA` — `CA:TRUE`, signed by the evil root (matches the
  observed attack in the ticket: `chain=["CN=Evil Intermediate CA"]`);
- a policy-compliant leaf (codeSigning EKU, digitalSignature KU, `CA:FALSE`, ~10y
  validity) signed by the evil intermediate, plus its key.

Through `from_p12` the walk yields `[int, root]`; the terminus is the evil root.
The same walk *is* the assembly invariant the ticket observed (`chain_len=1` when the
root is omitted); a variant with only leaf+int is not needed because the policy step
is terminus-driven, not shape-driven.

### 5.2 `zsign-core` unit tests (`cert.rs`)

New (red first, written by the Tester):

- `from_p12_rejects_evil_root_chain` — `SigningCredentials::from_p12(EVIL_CHAIN,
  PASS)` is `Err(Error::Certificate(m))` with `m` containing the leaf subject and
  `"not anchored to a trusted root"` (the evil root self-signs fine, so
  `verify_chain` returns `ok: true, anchored: false, reason: None` → default detail).
- `from_p12_rejects_self_issued_identity` — `IDENTITY_SINGLE` (self-signed leaf,
  empty chain) rejected the same way: the terminus *is* the leaf, its SPKI is not
  the Apple root's.
- `from_pem_rejects_self_signed_leaf` — a policy-compliant self-signed leaf through
  the public `from_pem` is rejected with the same message.
- `require_anchored_chain_accepts_anchor_terminated_chain` — build
  root (`Profile::Root`) → intermediate (`Profile::SubCA`) → leaf
  (codeSigning EKU) in-memory with `fresh_2048()` keys, pass
  `chain = [int, root]` with `TrustAnchors::from_certificates(vec![root.clone()])`
  → `Ok`. This is acceptance criterion (ii): a correctly linked, correctly
  terminated chain is accepted. (Constructing a chain that anchors to the *real*
  Apple root is impossible without Apple's private key — see §6.)
- `require_anchored_chain_rejects_chain_under_production_anchors` — the same chain
  with `TrustAnchors::apple_root()` → `Err` containing `"not anchored"`. This is
  the wiring test: production callers really do use the Apple anchor set.
- `require_anchored_chain_rejects_link_signed_by_the_wrong_key` — names link, but
  the leaf is signed by a key other than the intermediate's; terminus reaches an
  injected anchor → `Err` containing `"issuer-signature verification"`.
- `require_anchored_chain_rejects_non_ca_intermediate` — intermediate without
  `basicConstraints CA` → `Err` containing `"basicConstraints"`.
- `require_anchored_chain_rejects_forged_terminus_with_anchor_key` — a
  self-issued certificate carrying the *test root's* SPKI but signed by a
  different key (the §4.2 forgery) → `Err` containing `"self-signature"`.

Migrated to the unanchored constructors (they assert success on self-issued
material; behavior otherwise unchanged): `from_p12_with_leaf_sha1_selects_the_matching_pair`
(`cert.rs:1066`), `from_p12_selects_single_identity_with_empty_chain` (`:1119`),
`from_pem_self_signed_leaf_yields_empty_chain` (`:1133`), `from_pem_accepts_compliant_leaf`
(`:1278`), `from_pem_accepts_leaf_without_ku_and_bc` (`:1420`),
`from_pem_loads_every_supported_key_form` (`:1500`),
`from_pem_keeps_the_password_free_pkcs8_path_unchanged` (`:1537`),
`from_pem_loads_unencrypted_traditional_keys` (`:1555`),
`from_pem_still_pairs_the_decrypted_key_with_the_certificate` (`:1603`), and any
other success-asserting load found by running the suite. Error-expecting tests
(policy, weak key, password, ambiguity) are untouched: those gates still fire
before anchoring. Assembly tests (`:1191,1207,1221,1265`) stay on
`build_chain_from_leaf`, which remains pure; one new assembly test covers the
direct-issue root completion.

`keychain.rs`: `load_with` (`keychain.rs:195-219`) routes through a
`#[cfg(test)]` private wrapper that calls `from_p12_with_leaf_sha1_unanchored`, so
`load_with_selects_one_identity_from_multi_identity_export` (`keychain.rs:471`)
keeps its full pipeline coverage. Shipped builds keep the anchored call — the
wrapper contains a single call each side, no duplicated logic.

### 5.3 `zsign-cli` (`main.rs`)

The subprocess tests drive a production child binary (`main.rs:1003-1027`), which
stays anchored in every build. Test-by-test:

- **New** `pkcs12_load_rejects_unanchored_chain` (subprocess): identity p12 +
  correct `-p` → exit 1, stderr contains `"not anchored to a trusted root"`, no
  output file. This pins the *shipped* loader's fail-closed contract.
- **Rewritten, still subprocess, error-class assertions** — each proves its
  contract by discriminating the failure stage (wrong password → MAC markers;
  correct password → anchoring marker):
  - `key_route_pkcs12_content_loads_with_password` (`:1331`): exit 1,
    `"not anchored"` present, `"MAC mismatch"` absent → content routing + `-p`
    reached `from_p12` and decrypted.
  - `env_password_signs_p12_without_flag` (`:1473`): exit 1, `"not anchored"`
    present, `"MAC mismatch"` and `"no password supplied"` absent → the env value
    was read and correct (had it been ignored, the empty-password trial would
    produce a MAC error).
  - `argv_password_beats_env_password` (`:1495`): first half (env-only wrong
    password → MAC, exit 1) unchanged; second half asserts `"not anchored"` and
    not `"MAC mismatch"` → the flag beat the env.
  - `encrypted_pem_routes_through_the_password_flow` (`:1950`): first two
    assertions unchanged; the correct-password assertion becomes exit 1 +
    `"not anchored"` + no password markers → key decode, pairing and policy all
    passed with the right password.
- **Converted to in-process** (they assert behavior *downstream* of loading, which
  needs successful credentials; `run(cli)` is documented as "testable without
  argv", `main.rs:214`):
  - `check_revocation_flag_never_gates_a_signing_run` (`:1412`):
    `Cli::try_parse_from([... -p testpassword -C ...])` → `run(cli)` returns
    `Ok(ExitCode::SUCCESS)` and the output exists; the `--help` half stays a
    subprocess call. Original strength preserved.
  - `missing_profile_error_names_the_file` (`:2128`): in-process `run(cli)` →
    `Err` whose text contains `"absent.mobileprovision"` and
    `"provisioning profile"`.
  Both need `load_credentials` to produce credentials in test builds; a
  `#[cfg(test)]`-only private wrapper `load_p12_credentials` (one line per side:
  `from_p12_unanchored` under `cfg(test)`, `from_p12` otherwise) is used at the
  two `--pkcs12`/`-k`-p12 call sites (`main.rs:859`, `main.rs:916`). The password
  *trial* at `main.rs:931` keeps calling the anchored `from_p12` in all builds —
  it probes password shape, and no in-process test uses it (both pass `-p`).
- Unchanged: every parse/help/error test, `:1544` (MAC), `:1573` (policy error
  before anchoring — the ordering guarantee in §4.3), adhoc success tests.

### 5.4 `zsign-wasm` (`lib.rs`)

- Extract the tail of `WasmSigner::new` (after `from_p12`, `lib.rs:258-272`) into a
  private `WasmSigner::assemble(credentials, profile_bytes) -> Result<WasmSigner,
  JsValue>` holding entitlement extraction and struct initialization.
- Test helpers `new_signer`/`new_signer_with_profile` (`lib.rs:815-826`) switch to
  `SigningCredentials::from_p12_unanchored(...)` + `WasmSigner::assemble(...)`;
  the ~17 dependent tests are untouched.
- New `constructor_rejects_unanchored_credentials`: `WasmSigner::new` with
  `LEAF_P12_B64` fails (match via `let Err(err) = ... else { panic!(...) }`,
  `WasmSigner` is not `Debug`), `error_code(&err)` (`lib.rs:1588`) equals
  `"ZSIGN_INVALID_CERTIFICATE"` (`code_for_core_error`, `lib.rs:124`), message
  contains `"not anchored to a trusted root"` (matched via `Reflect`, message
  substring only for the human-readable detail).
- `p12_err` (`lib.rs:170-182`) needs no change: an anchoring rejection is not
  password-shaped and falls through to `code_for_core_error`.

### 5.5 Facade and fuzz

`crates/zsign` tests build `SigningCredentials` struct literals via
`test_util.rs:62`; `from_p12`/`from_pem` there appear only in non-running doc
examples. `fuzz/fuzz_targets/pkcs12.rs:14` ignores the `Result`. No changes.
`cms.rs` is untouched: it embeds `credentials.cert_chain` as given
(`cms.rs:394-398`) and its tests construct credentials directly.

## 6. Residual exposure and known limitations (documented, accepted)

1. **No positive end-to-end test with the real Apple anchor.** A chain that
   terminates at the genuine embedded Apple Root CA requires Apple's private key to
   construct. The accept path is therefore tested with injected anchors at the
   policy-function level (§5.2), and the production wiring is proven by rejection
   tests (core, wasm, CLI subprocess). This is an inherent limit of any test
   environment without Apple-issued credentials.
2. **Apple Root CA - G2/G3 lineage is rejected at load.** Credentials under WWDR
   G2/G6 (ECDSA "Swift signing") or MP CA chains terminate at roots this repository
   does not embed; `p384` support would also be required. Fail-closed: they error
   with the anchoring message instead of being silently accepted. Extending the
   anchor set is follow-up work.
3. **`test-fixtures` misuse.** A downstream crate that enables `test-fixtures` in a
   shipped build would compile `from_p12_unanchored` in. The feature's contract
   ("never reaches release or wasm artifacts", `zsign-core/Cargo.toml:62-63`) and
   the resolver-2 dev-dependency wiring make this a deliberate, visible misuse, not
   an accident; `cfg(test)` wrappers in the CLI and keychain cannot ship at all.
4. **Intermediate validity is now enforced at load** (via `verify_chain`), where
   before only the leaf's window was checked. This matches the verify side and RFC
   5280 §6.1.3(a)(2). The only in-repo Apple intermediate that has expired (legacy
   WWDR, 2023-02-07) could only accompany already-expired leaves, which the leaf
   check rejects first.
5. **RFC 5280 completeness.** The policy covers anchor match, name chaining, link
   signatures, terminus self-signature, CA constraints (BC/pathLen/keyCertSign),
   leaf purpose and validity. Revocation stays a device concern (module doc,
   `cms_verify.rs:32-33`); certificate policy processing and name constraints are
   not implemented — §6.1 permits omitting optional steps, and Apple code-signing
   intermediates carry their private OIDs non-critically.

## 7. Out of scope

- Deferred lane tickets (crypto-3 key↔cert, crypto-4 duplicate-cert panic in
  `cms.rs`, crypto-5 wasm clock, crypto-7/8/10/11), lane-2 files
  (`builder.rs`, `ipa/mod.rs`, `provisioning.rs`), all Wave-2 `verify.rs` work,
  Wave-3 Mach-O work, Wave-8 docs/README. `team_id` handling, `cms.rs` embedding
  behavior, and `resolve_p12_password` logic are unchanged.

## 8. Acceptance mapping

| Criterion | Proof |
|---|---|
| (i) Evil-Root p12 rejected by `from_p12`, typed error | `from_p12_rejects_evil_root_chain` (§5.2) + `from_p12_rejects_self_issued_identity` |
| (ii) Apple-anchored chain accepted | `require_anchored_chain_accepts_anchor_terminated_chain` with injected anchors + existing `verify_chain` accept tests; real-Apple positive not constructible (§6.1) |
| (iii) Suite green, gated path for self-issued fixtures | migrations §5.2–5.4; `cargo test --workspace` at the final gate |
| (iv) wasm + CLI compile, relevant tests pass | §5.3 new subprocess test + rewritten/converted tests; §5.4 constructor test; `cargo build -p zsign-cli`, `cargo test -p zsign-wasm`, `wasm-pack test --node` |

## 9. Research provenance

Phase-2 batch (all read-only): a caller/fixture scout (blast radius across the four
crates + fuzz, test inventories used in §5), a verification-machinery scout
(`verify_chain`/`TrustAnchors` inventory and commit-1b99239 anchor-injection
precedent — explicit `&TrustAnchors` parameters, no builder/thread-local), and a
librarian sweep (RFC 5280 §6.1/§6.2 anchor semantics; x509-cert is parse-only;
Apple's three-root PKI and TN3161's `unable to build chain to self-signed root`;
upstream `zhlynn/zsign` performs *no* chain validation at load, so this is a
deliberate strengthening; PKCS#12 files carry no root by default, which is why root
completion in §4.1 matters).
