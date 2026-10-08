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

- `cms_verify.rs:1600-1606` — `ext_value(cert, id)` is a first-match
  `.find(|e| e.extn_id == id)` returning raw `extn_value.as_bytes()`; the
  `critical` flag on `x509_cert::ext::Extension` (`critical: bool`, x509-cert
  0.2.5 `src/ext.rs:29-36`) is structurally unobservable through it, and
  nothing else in the file reads `critical`.
- No `2.5.29.30` / name-constraint handling exists anywhere in the module;
  grep for `critical` in the workspace finds only three `critical: false`
  literals in test helpers (`cms_verify.rs:2734`, `cert.rs:1359`,
  `revocation.rs:2048`).
- Path validation is the single function `verify_chain`
  (`cms_verify.rs:1362-1537`): leaf checks at entry (purpose, validity), then
  a bottom-up walk resolving each `parent` by subject match
  (`validity :1411 → issuer_ca_reason :1425 → sha1_warning :1434 → signature
  :1437 → names.push :1448`), with three success terminals (self-signed
  anchored :1474-1482, self-signed unanchored :1484-1490,
  `anchors.find_by_subject` :1494-1506) and failure returns of the form
  `ChainOutcome { ok: false, anchored: false, subjects, reason: Some(...), warnings }`.
  A self-signed embedded root is processed as a **parent** in the iteration
  where it is first accepted (`current` is still the child, so
  `!ptr::eq(p, current)` holds at :1410); only the *next* iteration's
  self-match routes to the terminal. Consequently hooks placed on the leaf
  entry and in the parent branch cover every path certificate exactly once —
  verified by the owning tests named in the plan (`self_signed_root_with_unknown_critical_rejects`,
  root-with-constraints fixtures).
- Failure plumbing: `verify_signed_data` copies `outcome.reason` into
  `report.chain_reason` (`:1108`) and pushes it into `report.errors`
  (`:1130-1136`), forcing `valid = false`; `crypto/cert.rs:405-427`
  (`require_anchored_chain`, the only other caller) folds the same string
  into `Error::Certificate`. New failures therefore need **no struct change**.
- `CmsVerifyReport` (`:262-298`) derives Debug/Clone/PartialEq/Eq/Default —
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
- the embedded self-signed root **is** covered by the parent branch: it is
  first seen as `p` while `current` is still its child (the `!ptr::eq(p,
  current)` guard at `:1410` only rejects the *self*-match that occurs one
  iteration later, after the root has already been processed);
- a leaf that is itself self-signed is covered at entry;
- a trust anchor resolved through `anchors.find_by_subject` is **not** a path
  certificate (§6.1 doesn't include the anchor; §6.2 gives explicit latitude)
  — not gated, and its name constraints are not applied. Pinned by the plan's
  `out_of_chain_anchor_extensions_are_ignored` test.

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
- when the certificate does **not include a subject alternative name
  extension at all**, any `emailAddress` attribute (OID
  `1.2.840.113549.1.9.1`; the rfc4519 UID OID `0.9.2342.19200300.100.1.1` is
  accepted too for robustness) in the subject DN counts as an rfc822Name
  instance — RFC 5280 §4.2.1.10: "When constraints are imposed on the
  rfc822Name name form, but the certificate does not include a subject
  alternative name, the rfc822Name constraint MUST be applied to the
  attribute of type emailAddress in the subject distinguished name."

Skip rule: a certificate that is self-issued (subject == issuer) and is not
the leaf is skipped (§6.1.3(b)/(c)).

Per name-form semantics:
- **directoryName** (MUST): `base` is an RDN-prefix of the target DN, RDNs
  compared attribute-type-OID + value with `caseIgnoreMatch` normalization
  (trim, collapse internal whitespace, Unicode lowercase) — the §7.1 floor;
  full LDAP StringPrep is not implemented (documented deviation below).
- **dNSName** (§4.2.1.10: "Any DNS name that can be constructed by simply
  adding zero or more labels to the left-hand side of the name satisfies the
  name constraint"): case-insensitive equality with the constraint, or
  `name.ends_with(".{constraint}")`. A leading `.` (not defined for dNSName
  by the RFC) is handled with the URI/email period semantics: strict
  subdomain match against the remainder, equality excluded.
- **rfc822Name** (§4.2.1.10, verbatim semantics): constraint containing `@`
  ⇒ exact full-address match; constraint **with** leading period ⇒ address
  domain is a strict subdomain of the remainder (".example.com" matches
  `a.example.com`, not `example.com`); plain host constraint ⇒ the
  address's domain equals the constraint exactly ("example.com" is satisfied
  only by addresses at the host `example.com`). Case-insensitive throughout
  (the emailAddress attribute is not case-sensitive per RFC 5280 §4.1.2.2).
- **URI** (§4.2.1.10: "When the constraint does not begin with a period, it
  specifies a host"): apply to the host component only
  (scheme://[userinfo]host[:port]/…); plain constraint ⇒ host equality;
  leading-period constraint ⇒ host is a strict subdomain of the remainder.
  A URI instance whose authority has no host or names an IP address, under
  any URI constraint, ⇒ reject ("the application MUST reject the
  certificate").
- **Any other form** (iPAddress, otherName, ediPartyName, registeredId): if
  an instance of that form is present in an evaluated certificate while a
  constraint on that form exists ⇒ reject with an explicit
  "not supported" reason (§4.2.1.10's process-or-reject; also fail-closed for
  forms whose syntax/semantics the RFC leaves undefined). No instance ⇒ the
  constraint is inert ("restrictions apply only when the specified name form
  is present").

Semantics guards: excluded beats permitted unconditionally; permitted is
evaluated **per name instance** — every name of a constrained form present in
an evaluated certificate must lie within at least one same-form permitted
basis (RFC 5280 §6.1.3(b): "verify that EACH of the alternative names ...
is within one of the permitted_subtrees"), while one name matching an
excluded basis rejects the certificate; entries of other forms neither help
nor hurt. A subjectAltName extension that fails to decode while any CA in
the path imposes constraints rejects with `subject alternative name extension
is malformed` (a decoded-absent SAN must not silently drop instances —
that would be the exact evasion this design closes).

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
  identity being matched, not looser trust. BMPString/UniversalString DN
  values fall back to exact tag+bytes comparison instead of normalization
  (defense-in-depth residual: constraint base and subject encodings are
  CA-consistent in practice; a mismatch fails closed on permitted subtrees).
- **`uri_host` keeps a trailing-colon empty port** (`host:`) — treated as a
  distinct host; fail-closed for permitted constraints (never matches an
  equality basis) on malformed input.

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
