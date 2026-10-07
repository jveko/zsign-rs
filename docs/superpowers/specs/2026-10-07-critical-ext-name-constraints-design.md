# Critical X.509 extensions and name constraints in CMS path validation — Design

**Date:** 2026-10-07 · **Branch:** `w1-crypto-cms`
**Status:** approved for planning (cold review gate follows this doc and the plan)

## Goal

`verify_chain` in `crates/zsign-core/src/crypto/cms_verify.rs` must (1) reject any
chain member carrying a critical extension the module does not process, and
(2) evaluate nameConstraints (2.5.29.30) on CA certificates against the
certificates below them — both are certificate-path validation failures
required by RFC 5280.

## Evidence (verified against current source)

- `cms_verify.rs:1601-1606` — `ext_value(cert, id)` is a first-match
  `.find(|e| e.extn_id == id)` returning raw `extn_value.as_bytes()`; the
  `critical` flag on `x509_cert::ext::Extension` (`critical: bool`, x509-cert
  0.2.5 `src/ext.rs:29-36`) is structurally unobservable through it, and
  nothing else in the file reads `critical`.
- No `2.5.29.30` / name-constraint handling exists anywhere in the module;
  grep for `critical` in the workspace finds only three `critical: false`
  literals in test helpers (`cms_verify.rs:2734`, `cert.rs:1359`,
  `revocation.rs:2048`).
- Path validation is the single function `verify_chain`
  (`cms_verify.rs:1362-1536`): leaf checks at entry (purpose, validity), then
  a bottom-up walk resolving each `parent` by subject match
  (`validity → issuer_ca_reason → sha1_warning → signature → names.push`),
  with three success terminals (self-signed anchored, self-signed unanchored,
  `anchors.find_by_subject` resolution) and failure returns of the form
  `ChainOutcome { ok: false, anchored: false, subjects, reason: Some(...), warnings }`.
- Failure plumbing: `verify_signed_data` copies `outcome.reason` into
  `report.chain_reason` (`:1108`) and pushes it into `report.errors`
  (`:1133-1140`), forcing `valid = false`; `crypto/cert.rs:410-427`
  (`require_anchored_chain`, the only other caller) folds the same string
  into `Error::Certificate`. New failures therefore need **no struct change**.
- `CmsVerifyReport` (`:262-299`) derives Debug/Clone/PartialEq/Eq/Default —
  no serde; the CLI maps fields by hand. Adding strings to existing fields
  ripples nowhere; adding a struct field would hit the CLI DTO/README owned
  by other lanes — so this design adds none.

## External contract (RFC 5280, quoted verbatim by research)

1. **§4.2:** "A certificate-using system MUST reject the certificate if it
   encounters a critical extension it does not recognize **or** a critical
   extension that contains information that it cannot process. A non-critical
   extension MAY be ignored if it is not recognized, but MUST be processed if
   it is recognized." Same MUST restated at §6.1 ("clients MUST reject the
   certificate if it contains an unsupported critical extension") and
   §6.1.4(o).
2. **§4.2.1.10:** constraints "apply only when the specified name form is
   present"; "Any name matching a restriction in the excludedSubtrees field
   is invalid regardless of information appearing in the permittedSubtrees";
   empty sequences are forbidden ("either the permittedSubtrees field or the
   excludedSubtrees MUST be present"); `minimum MUST be zero, maximum MUST be
   absent`; "MUST be able to process … directoryName … SHOULD be able to
   process … rfc822Name, uniformResourceIdentifier, dNSName, and iPAddress";
   "If a name constraints extension that is marked as critical imposes
   constraints on a particular name form, and an instance of that name form
   appears in … a subsequent certificate, then the application MUST either
   process the constraint or reject the certificate."
3. **§6.1.3(b)/(c):** constraints are checked against the subject DN and
   subjectAltName entries "critical or non-critical"; self-issued
   certificates are skipped unless final in the path (§4.2.1.10 repeats this).
4. **§7.1 floor:** DN comparison must at minimum support `caseIgnoreMatch`
   with insignificant-space handling (LDAP StringPrep / RFC 4518).
5. **§6.2:** for a trust anchor's self-signed certificate, "implementations
   … are free to process or ignore" its name constraints.
6. Crate reality (verified against locked sources): x509-cert 0.2.5 provides
   `NameConstraints { permitted_subtrees, excluded_subtrees }`,
   `GeneralSubtree { base, minimum, maximum }`, `GeneralName` (no x400Address
   variant), `Extension.critical`, and `ID_CE_NAME_CONSTRAINTS` via const-oid
   `db` — but **no comparison logic**; all subtree matching is ours to write.
   `CertificateBuilder` is a dev-only feature (fine: tests only).

## Candidate designs

**D1 — gate + full nameConstraints evaluation inside `verify_chain` (CHOSEN).**
A `processed` OID allow-list scanned per path certificate, plus a constraint
evaluation that implements directoryName (the RFC's MUST form), dNSName,
rfc822Name, and URI, failing closed for every other form when an instance of
that form is present, bounded by a comparison budget.

**D2 — critical-extension gate only.** Rejected: the ticket explicitly names
nameConstraints evaluation as the substantive case; §4.2 alone leaves the
second gap open.

**D3 — gate + directoryName-only constraints (all other forms
reject-on-presence).** Rejected: DNS/email/URI matchers are small and the
RFC says SHOULD; mixing "processed here, rejected there" across similar string
forms buys little compatibility and adds conditional complexity. (webpki's
stricter directoryName-rejects-everything stance is a documented deviation of
theirs, not a conformance baseline.)

## Chosen design (D1)

### 1. Critical-extension gate

New private helper in `cms_verify.rs`:

```rust
fn unrecognized_critical(cert: &x509_cert::Certificate) -> Option<ObjectIdentifier>
```

scanning `cert.tbs_certificate.extensions` for `e.critical` with `extn_id`
absent from the processed set, returning the first offender. The processed
set is exactly what the module semantically reads (plus what this design
adds):

| OID | extension | why processed |
|---|---|---|
| 2.5.29.14 | subjectKeyIdentifier | `find_cert_by_ski` (`:1612`) |
| 2.5.29.15 | keyUsage | `leaf_ku_bc_reason` |
| 2.5.29.19 | basicConstraints | `leaf_ku_bc_reason`, `issuer_ca_reason` |
| 2.5.29.37 | extendedKeyUsage | `leaf_purpose_reason` |
| 2.5.29.17 | subjectAltName | read by the new name-constraint evaluation |
| 2.5.29.30 | nameConstraints | new — this design |

Everything else critical (certificatePolicies, AKID, AIA, …) fails with
`reason: Some(format!("certificate has unrecognized critical extension {oid}"))`
— lowercase-prose convention matching `issuer_ca_reason`.

Hook points (every certificate that participates in the path, exactly once):
- leaf — at `verify_chain` entry, before the purpose gate;
- each `parent` in the walk, after `issuer_ca_reason`;
- the self-signed embedded root is covered by the parent branch; a leaf that
  is itself self-signed is covered at entry;
- a trust anchor resolved through `anchors.find_by_subject` is **not** a path
  certificate (§6.1 doesn't include the anchor; §6.2 gives explicit latitude)
  — not gated, and its name constraints are not applied.

### 2. nameConstraints evaluation

New private helpers (all `cms_verify.rs`): decode via
`x509_cert::ext::pkix::constraints::NameConstraints` from the extension
value; structural validation (decode failure ⇒ reject;
empty (no permitted, no excluded) ⇒ reject;
`minimum != 0 || maximum.is_some()` on any subtree ⇒ reject — all
"cannot process ⇒ reject" readings of §4.2.1.10).

Evaluation model (equivalent to §6.1.4(g)'s state intersection/union, but
local): when the walk accepts a CA `p`, evaluate `p`'s decoded constraints
against **every certificate strictly below it** (leaf and lower
intermediates). Per-certificate evaluation against each CA's constraints is
exactly "permitted = intersection over CAs, excluded = union over CAs":
a name must satisfy every CA's permitted set and avoid every CA's excluded set.

Per evaluated certificate, the names checked are:
- its subject DN (when non-empty) — directoryName form;
- every `subjectAltName` entry (critical or not);
- when no rfc822Name is present in the SAN, any `emailAddress` attribute in
  the subject DN counts as an rfc822Name instance (§4.2.1.10 legacy rule).

Skip rule: a certificate that is self-issued (subject == issuer) and is not
the leaf is skipped (§6.1.3(b)/(c)).

Per name-form semantics:
- **directoryName** (MUST): `base` is an RDN-prefix of the target DN, RDNs
  compared attribute-type-OID + value with `caseIgnoreMatch` normalization
  (trim, collapse internal whitespace, Unicode lowercase) — the §7.1 floor;
  full LDAP StringPrep is not implemented (documented deviation below).
- **dNSName:** case-insensitive equality with the constraint, or a subdomain
  of it (name ends with `.constraint`); an optional leading `.` on the
  constraint is stripped.
- **rfc822Name:** constraint containing `@` ⇒ full-address match; otherwise
  domain-subtree match against the address's domain (case-insensitive).
- **URI:** apply to the host component only (scheme://[userinfo]host[:port]/…);
  a URI whose authority has no host, under a URI constraint, ⇒ reject.
- **Any other form** (iPAddress, otherName, ediPartyName, registeredId): if
  an instance of that form is present in an evaluated certificate while a
  constraint on that form exists ⇒ reject with an explicit
  "not supported" reason (§4.2.1.10's process-or-reject; also fail-closed for
  forms whose syntax/semantics the RFC leaves undefined). No instance ⇒ the
  constraint is inert ("restrictions apply only when the specified name form
  is present").

Semantics guards: excluded beats permitted unconditionally; permitted is
"at least one same-form entry exists ⇒ at least one must match"; entries of
other forms neither help nor hurt.

**Comparison budget:** a saturating counter caps total
(name × subtree) comparisons (`MAX_NAME_COMPARISONS`); exceeding it returns a
rejection reason — constraint lists are attacker-shaped input, and an
unbounded loop would be a DoS vector this change itself introduces.

Failures reuse `ChainOutcome { ok: false, reason: Some(...) }`; warnings path
untouched; no `CmsVerifyReport` change.

## Decisions and rejected alternatives (recorded)

- **Errors, not new report fields** — struct change would ripple into the
  CLI DTO/README (other lanes); `chain_reason`/`errors` already carry the
  reason to every consumer.
- **`ext_value` untouched** — the gate scans extensions directly; changing
  the shared accessor's signature would touch every call site for no gain.
- **Trust-anchor certificate (resolved out-of-chain) not gated, constraints
  ignored** — §6.2 explicitly permits it, and it keeps the embedded Apple root
  behavior identical. (Research flagged the "same root embedded in the CMS is
  a path member and therefore IS gated/evaluated" interaction as an
  interpretation: §4.2's MUST is unconditioned, so we take the fail-closed
  reading for in-chain certs.)
- **IP constraints not implemented** — iPAddress SANs are vanishing in code
  signing; reject-on-presence is licensed and far cheaper than CIDR v4/v6
  matching. Revisit only if a real chain needs it.
- **Leaf's own nameConstraints extension is recognized but imposes nothing**
  (a leaf has no subsequent certificates), mirroring RFC's "used only in a CA
  certificate"; it therefore passes the gate without evaluation. webpki makes
  the same choice (documented deviation there too).
- **Full LDAP StringPrep not implemented** — §7.1's floor
  (`caseIgnoreMatch` + insignificant-space handling) is implemented; a
  documented deviation, acceptable because name constraints in code-signing
  chains are absent in practice and the comparison errs toward the encoded
  identity being matched, not looser trust.

## Residual risks / out of scope

- Unknown **non-critical** extensions remain ignored (correct per §4.2).
- Extension OIDs the module does not read (certificatePolicies, …) now fail
  only when marked critical — RFC-correct, but a real-world chain carrying a
  critical one would newly reject; the full workspace suite is the canary.
- SHA-1 policy, Apple EKU policy, revocation, and the requirement-evaluation
  gaps in other files belong to other tickets and are untouched.

## Files in scope

- `crates/zsign-core/src/crypto/cms_verify.rs` — production helpers +
  inline tests, only.

## Verification commands

```
cargo test -p zsign-core crypto::cms_verify
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test --workspace
```
