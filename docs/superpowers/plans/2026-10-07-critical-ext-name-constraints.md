# Critical extensions & name constraints — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development (recommended) with dispatching-parallel-agents for independent tasks to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `verify_chain` rejects path certificates carrying unrecognized
critical extensions and enforces CA nameConstraints (directoryName, dNSName,
rfc822Name, URI; fail-closed on other forms) against the certificates below
each imposing CA.

**Architecture:** Two new private helper families in `cms_verify.rs`, both
hooked into the existing `verify_chain` walk: `unrecognized_critical(cert)`
scanned per path certificate, and a constraint evaluation run when each CA is
accepted. Failures return the existing `ChainOutcome { ok: false, reason:
Some(...) }` shape; no report/DTO change anywhere.

**Tech Stack:** Rust (edition 2021), x509-cert 0.2.5 (dev `builder` for
fixtures), inline `#[cfg(test)]` modules.

**Spec:** `docs/superpowers/specs/2026-10-07-critical-ext-name-constraints-design.md`

## Global Constraints

- Files modifiable: `crates/zsign-core/src/crypto/cms_verify.rs` ONLY
  (production + its inline tests). `ext_value`, `CmsVerifyReport`, facade,
  CLI, wasm, other crypto modules untouched.
- Failure reasons are lowercase prose, returned via
  `ChainOutcome { ok: false, anchored: false, reason: Some(..) }` — the
  existing convention (cf. `issuer_ca_reason` at `:1667-1694`).
- No ticket IDs anywhere (code, comments, docs, commit messages).
- Zero-warning gate: `cargo fmt --all -- --check` + `cargo clippy --workspace --all-targets -- -D warnings`.
- Tests run with `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test …`.
- Every new assertion prints the actual received value in its failure footer.
- Processed critical-OID set (final state): 2.5.29.14, 2.5.29.15,
  2.5.29.17, 2.5.29.19, 2.5.29.30, 2.5.29.37 — as module-local
  `const OID_*` consts in the file's existing style (`:109-118`).
- Test sketches in this plan abbreviate `GeneralName` constructors:
  `DnsName`/`Rfc822Name`/`UniformResourceIdentifier` payloads are
  `der::asn1::Ia5String` (not `&str`) and `IpAddress` takes an
  `OctetString` of raw bytes — build them with
  `Ia5String::new("…").unwrap()` / `OctetString::new(vec![…]).unwrap()`.
- `replace_extension` (test helper, hardcodes `critical: false`) invalidates
  the mutated certificate's signature — it may only be used for fixtures
  whose rejection fires before any signature verification of the mutated
  cert. Positive-path fixtures MUST be built fully signed via
  `CertificateBuilder` (dev-only `builder` feature).

## Review Focus

- Leaf, every in-walk parent, and the embedded self-signed root each get the
  critical-gate exactly once — pinned by
  `self_signed_root_with_unknown_critical_rejects` and
  `unknown_critical_extension_rejects_an_intermediate` (Task 1); the
  out-of-chain trust anchor resolved by `anchors.find_by_subject` gets
  neither gate nor constraints (§6.2) — pinned by
  `out_of_chain_anchor_extensions_are_ignored` (Task 1).
- Positive control: an unknown **non-critical** extension still verifies —
  pinned by Task 1.
- Excluded beats permitted unconditionally; permitted is at-least-one-match —
  pinned by Task 2.
- Empty nameConstraints and non-default `minimum`/`maximum` reject — pinned
  by Task 2 (`…maximum_rejects`, `…minimum_rejects`).
- A constraint with no instance of its name form is inert — pinned by Task 3.
- Email host-form constraints are exact-domain (subdomains need the
  leading-period form); URI plain form is host-only — pinned by Task 3.
- The legacy DN-email rule fires only when the certificate has no
  subjectAltName extension, and the fixture proves it carries the matched
  OID — pinned by Task 3.
- Comparison budget caps attacker-shaped constraint lists — pinned by Task 3.

---

### Task 1: Unknown critical-extension gate

**Files:**
- Modify: `crates/zsign-core/src/crypto/cms_verify.rs` — new
  `unrecognized_critical` helper + OID consts, hooks in `verify_chain`
  (leaf entry, parent branch), inline tests.
- Test: same file, inline test module.

**Interfaces:**
- Consumes: `x509_cert::ext::Extension { extn_id, critical, .. }`,
  `ObjectIdentifier` (imported at `:45`), `ChainOutcome` (`:1322-1333`),
  `verify_chain` (`:1362`), test helpers `build_rsa_root` (`:2405`),
  `build_leaf` (`:2444`), `chain_with` (`:2433`).
- Produces:
  - `fn unrecognized_critical(cert: &x509_cert::Certificate) -> Option<ObjectIdentifier>` (private)
  - OID consts: REUSE the existing `OID_SUBJECT_KEY_IDENTIFIER` (`:110`),
    `OID_KEY_USAGE` (`:112`), `OID_BASIC_CONSTRAINTS` (`:114`),
    `OID_EXT_KEY_USAGE` (`:116`); ADD only `OID_SUBJECT_ALT_NAME` (`2.5.29.17`)
    and `OID_NAME_CONSTRAINTS` (`2.5.29.30`) in the same
    `const OID_*: ObjectIdentifier = ObjectIdentifier::new_unwrap("…")` style
    with one-line `///` docs. Task 2 consumes `OID_NAME_CONSTRAINTS`.
  - Reason string format: `certificate has unrecognized critical extension {oid}` (lowercase, `{oid}` = dotted form).

- [ ] **Step 1: Test-only extension authoring types**

In the inline test module, two zero-sized authoring types for the builder:
each carries its own OID (experimental arc `2.999.1` / `2.999.2`), encodes as
an empty DER NULL, and reports the trait's full method
`fn critical(&self, subject: &x509_cert::name::Name, extensions:
&[x509_cert::ext::Extension]) -> bool` as `true` / `false` respectively.
They must implement `x509_cert::ext::AsExtension` + `AssociatedOid` + `Encode`
— read the exact trait definition in the vendored source
`~/.cargo/registry/src/index.crates.io-*/x509-cert-0.2.5/src/ext.rs` first
(the `to_extension` default, if absent, is a manual
`Extension { extn_id: <Self as AssociatedOid>::OID, critical, extn_value:
OctetString::new(NULL-der) }`). Wire them with `builder.add_extension(&…)`.

- [ ] **Step 2: Write the failing tests**

```rust
#[test]
fn unknown_critical_extension_rejects_the_leaf() {
    let (_root_key, root, root_signing) = build_rsa_root("CN=zsign seed root");
    let (_, leaf) = build_leaf_signed(
        "CN=zsign leaf",
        &root.tbs_certificate.subject,
        &root_signing,
        &|b| { b.add_extension(&UnknownCritical).unwrap(); },
    );
    let out = chain_with(&root, &leaf);
    assert!(
        matches!(&out.reason, Some(r) if r.contains("unrecognized critical extension 2.999.1")),
        "expected critical-extension rejection, got ok={} reason={:?}",
        out.ok,
        out.reason
    );
    assert!(!out.ok);
}

#[test]
fn unknown_non_critical_extension_still_verifies() {
    // same fixture but UnknownNonCritical (2.999.2)
    // assert out.ok && out.anchored, footer prints out.reason
}

#[test]
fn unknown_critical_extension_rejects_an_intermediate() {
    // root -> subca(with UnknownCritical via signed builder) -> leaf
    // assert reason names 2.999.1, !out.ok
}

#[test]
fn self_signed_root_with_unknown_critical_rejects_the_chain() {
    // root built Profile::Root with UnknownCritical (signed builder);
    // leaf issued by that root. The root is first accepted as the leaf's
    // parent (Hook B) before the walk reaches the self-signed terminal.
    // assert !out.ok and reason names 2.999.1.
}

#[test]
fn out_of_chain_anchor_extensions_are_ignored() {
    // root built Profile::Root carrying UnknownCritical AND an excluded
    // nameConstraints subtree matching the leaf subject (signed builder).
    // Chain: verify_chain(&[leaf], leaf, &TrustAnchors::from_certificates(
    // vec![root]), time_now(), SignerPurpose::CodeSigning) — the issuer is
    // resolved via anchors.find_by_subject, which is §6.2 anchor territory:
    // assert out.ok && out.anchored (footer prints out.reason) — neither the
    // unknown critical extension nor the constraints of an out-of-chain
    // trust anchor gate or fail the path.
}
```

Note: `build_leaf`/`build_subca_issued_by` currently take fixed arguments —
add ONE generic extension hook per builder, e.g.
`fn build_leaf_signed(cn: &str, issuer: &x509_cert::name::Name,
issuer_signing: &rsa::pkcs1v15::SigningKey<Sha256>, extend:
impl FnOnce(&mut CertificateBuilder<rsa::pkcs1v15::SigningKey<Sha256>>))`
(`build_subca_issued_by_signed` analogous), that delegates to the same
construction, **adds `ExtendedKeyUsage(vec![OID_CODE_SIGNING])` by default**
(`leaf_purpose_reason` at `:1628-1632` rejects a leaf without the
codeSigning EKU, so every positive control through these helpers needs it —
the `extend` closure runs after that default and may add SANs or
constraints), then invokes `extend` before
`build::<rsa::pkcs1v15::Signature>()`. Call as `build_leaf_signed(…, |b| { … })`
— generic `impl FnOnce`, NOT `&dyn FnOnce` and NOT `&|b|` (a `&F` where
`F: FnOnce` does not implement `FnOnce`; the builder is generic over its
signer type). Do not modify existing helpers; existing
tests must compile unchanged.

- [ ] **Step 3: Run the tests to verify they fail**

Run: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-core -- unknown_ self_signed_root_with_unknown_critical out_of_chain_anchor`
Expected: the three rejection tests FAIL — leaf/intermediate/root fixtures
currently verify (`ok=true, anchored=true`); the reason footers show the
actual outcomes. `out_of_chain_anchor_extensions_are_ignored` PASSES already
and is a standing guard: it fails only if a future change wrongly applies
the gate/evaluation to an out-of-chain anchor.

- [ ] **Step 4: Implement the gate**

- Reuse the existing four OID consts and add the two missing ones
  (`OID_SUBJECT_ALT_NAME`, `OID_NAME_CONSTRAINTS`) in the existing
  `const OID_*` style with one-line `///` docs.
- `fn unrecognized_critical(cert) -> Option<ObjectIdentifier>` iterating
  `cert.tbs_certificate.extensions`, returning the first `e.critical` entry
  whose `extn_id` is not in the six-OID set.
- Hook A — `verify_chain` entry, before the purpose gate:
  `if let Some(oid) = unrecognized_critical(leaf) { return ChainOutcome { ok: false, anchored: false, subjects: names, reason: Some(format!("certificate has unrecognized critical extension {oid}")), warnings }; }`
- Hook B — parent branch, directly after the `issuer_ca_reason(p, …)` block,
  same construction with `p`. (This also covers the embedded self-signed
  root: it passes through the parent branch as `p` while `current` is still
  its child; the `!ptr::eq` guard only rejects the later self-match.)

- [ ] **Step 5: Run the tests to verify they pass**

Run: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-core -- unknown_ self_signed_root_with_unknown_critical out_of_chain_anchor`
Expected: PASS — the four rejection/control tests green, and
`out_of_chain_anchor_extensions_are_ignored` proves the anchor path never
hits the gate.

- [ ] **Step 6: Scoped regression run**

Run: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-core crypto::`
Expected: PASS — existing chains built by `CertificateBuilder` carry
critical BC/KU/EKU (all in the processed set), so nothing regresses.

---

### Task 2: nameConstraints structure + directoryName evaluation

**Files:**
- Modify: `crates/zsign-core/src/crypto/cms_verify.rs` — constraint
  helpers, `verify_chain` hook, inline tests.

**Interfaces:**
- Consumes: `OID_NAME_CONSTRAINTS` and the `verify_chain` hooks from
  Task 1; `x509_cert::ext::pkix::constraints::NameConstraints` plus the
  subtree types at `x509_cert::ext::pkix::constraints::name::{GeneralSubtrees,
  GeneralSubtree}` (the `constraints` module re-exports only
  `BasicConstraints`/`NameConstraints`/`PolicyConstraints`); test helpers
  `build_rsa_root`/`build_leaf`/`build_subca`/`chain_with`.
- Produces (all private, exact names later tasks/reviewers rely on):
  - `enum NcScan { Absent, Malformed, Present(NameConstraints) }` and
    `fn scan_name_constraints(cert: &x509_cert::Certificate) -> NcScan`
  - `fn nc_shape_reason(nc: &NameConstraints) -> Option<String>` (empty
    sequence, non-default minimum/maximum)
  - `fn check_certificate_names(cert: &x509_cert::Certificate, is_final:
    bool, constraints: &[NameConstraints], budget: &mut usize) -> Option<String>`
    — Task 3 extends this body with the remaining name forms; Task 2
    implements directoryName only and treats every other form as absent.
  - `const MAX_NAME_COMPARISONS: usize = 4096` (budget consumed in Task 3;
    declared here because the signature takes `budget`).
  - Hook in `verify_chain` parent branch (after the Task-1 gate): maintain
    `let mut path: Vec<&x509_cert::Certificate> = vec![leaf];` before the
    loop; when parent `p` is accepted: `scan_name_constraints(p)` →
    `Malformed` ⇒ reject with `malformed name constraints extension`;
    `Present(nc)` ⇒ `nc_shape_reason` ⇒ reject if `Some`; then evaluate
    `p`'s constraints against every entry of `path` (in order) calling
    `check_certificate_names(entry, idx == 0, &[nc], &mut budget)` and reject
    on the first `Some`; then `path.push(p)`.
  - Fixed reason strings (tests pin these substrings): `subject or
    alternative name outside permitted name constraints`, `subject or
    alternative name within excluded name constraints`, `name constraints
    extension has neither permitted nor excluded subtrees`, `name constraints
    subtree specifies minimum or maximum`, `malformed name constraints
    extension`.
- New test fixtures (signed, positive-path capable): `build_rsa_root_signed`
  and `build_subca_issued_by_signed` — same bodies as `build_rsa_root`
  (`:2405`) / `build_subca_issued_by` (`:2689`) plus a pre-build
  `builder.add_extension(&nc)` (the `NameConstraints` type's
  `impl_extension!` marks it critical, which is what conforming CAs emit).
  A non-critical-NC authoring wrapper follows Task 1's authoring-type
  pattern (its `Encode` delegates to the `NameConstraints` value, OID
  2.5.29.30, `critical() == false`).

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn permitted_directory_name_subtree_accepts_the_leaf() {
    // root signed with permitted_subtrees = [DirectoryName(leaf subject)] ->
    // chain_with(&root, &leaf) must stay ok && anchored; footer prints reason.
}
#[test]
fn permitted_directory_name_mismatch_rejects() {
    // permitted base = "CN=unrelated subtree" -> !ok,
    // reason contains "outside permitted name constraints"
}
#[test]
fn excluded_subtree_beats_permitted() {
    // permitted = [leaf subject DN], excluded = [leaf subject DN] -> !ok,
    // reason contains "within excluded name constraints"
}
#[test]
fn empty_name_constraints_reject() {
    // permitted: None, excluded: None -> reason contains
    // "neither permitted nor excluded"
}
#[test]
fn non_default_subtree_maximum_rejects() {
    // GeneralSubtree { base: DnsName("example.com"), minimum: 0,
    // maximum: Some(5) } permitted -> reason contains
    // "specifies minimum or maximum"
}
#[test]
fn non_default_subtree_minimum_rejects() {
    // GeneralSubtree { base: DnsName("example.com"), minimum: 1,
    // maximum: None } permitted -> same "specifies minimum or maximum"
    // reason (the RFC's floor is minimum == 0 AND maximum absent)
}
#[test]
fn non_critical_name_constraints_are_enforced() {
    // excluded subtree via the non-critical authoring wrapper, matching the
    // leaf subject -> !ok with the excluded reason (recognized => processed)
}
#[test]
fn self_issued_certificate_skips_constraints_unless_final() {
    // unit-level: let (subca, _) = build_subca("CN=self issued", None);
    // let nc = NameConstraints { permitted: Some([base "CN=other"]), .. };
    // assert check_certificate_names(&subca, false, &[nc.clone()], &mut b)
    //     == None  (subject == issuer, not final -> skipped)
    // assert check_certificate_names(&subca, true, &[nc], &mut b)
    //     .is_some() with the permitted-reason substring
}
```

(For the first two tests the permitted base DN is built as
`x509_cert::name::Name::from_str("CN=…")` → `GeneralName::DirectoryName`.)

- [ ] **Step 2: Run the tests to verify they fail**

Run: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-core name_constraint`
Expected: FAIL — helpers don't exist yet (compile error), or if written
first, fixtures currently verify with `ok=true`.

- [ ] **Step 3: Implement the helpers and hook**

- `scan_name_constraints` / `nc_shape_reason` per the Interfaces block
  (decode via `NameConstraints::from_der` on `ext_value(cert,
  OID_NAME_CONSTRAINTS)`).
- `check_certificate_names`: skip when `!is_final && cert.tbs_certificate.subject
  == cert.tbs_certificate.issuer`; build the evaluated name list = subject DN
  (directoryName form) — Task 3 adds SAN/legacy-email names; evaluate
  directoryName entries: excluded match (RDN-prefix, each RDN compared by
  attribute OID + value normalized: trim, collapse internal whitespace,
  Unicode lowercase) ⇒ excluded reason; else any permitted directoryName
  entries exist and none is an RDN-prefix ⇒ permitted reason; each
  (name, subtree) comparison increments `budget`, and `*budget >
  MAX_NAME_COMPARISONS` short-circuits to `Some("name constraints comparison
  budget exceeded")`.
- Hook in `verify_chain` per the Interfaces block (entry `let mut path =
  vec![leaf]; let mut budget = 0usize;`).

- [ ] **Step 4: Run the tests to verify they pass**

Run: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-core name_constraint`
Expected: PASS (all eight).

- [ ] **Step 5: Scoped regression run**

Run: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-core crypto::`
Expected: PASS — no existing fixture carries nameConstraints, so the new
hook is inert on them.

---

### Task 3: dNSName / rfc822Name / URI matching, unsupported forms, budget proof

**Files:**
- Modify: `crates/zsign-core/src/crypto/cms_verify.rs` — extend
  `check_certificate_names` + inline tests.

**Interfaces:**
- Consumes: Task 2's `check_certificate_names`, `MAX_NAME_COMPARISONS`,
  signed-builder fixture helpers.
- Produces: the complete per-form dispatch in `check_certificate_names`;
  new reason strings `unsupported name form under name constraints: {form}`
  and `uri name constraint cannot be applied to a uri without a host`;
  `budget` semantics (increment per same-form (name, subtree) comparison).

Name matching rules (RFC 5280 §4.2.1.10 verbatim semantics; each returns
match / no-match):
- **dNSName:** "Any DNS name that can be constructed by simply adding zero
  or more labels to the left-hand side of the name satisfies the name
  constraint" — case-insensitive equality with the constraint, or
  `name.ends_with(".{constraint}")`. A leading `.` on a dNSName constraint
  (undefined by the RFC) uses the period form below: strict subdomain match
  against the remainder, equality excluded.
- **rfc822Name:** three forms — a constraint containing `@` matches the
  full address exactly (case-insensitive; emailAddress attribute values are
  not case-sensitive per §4.1.2.2); a constraint beginning with `.` matches
  address domains that are strict subdomains of the remainder (".example.com"
  matches `a.example.com`, NOT `example.com`); a plain host constraint
  matches only when the address's domain EQUALS the constraint ("example.com"
  is satisfied by any address at the host `example.com`, not its
  subdomains).
- **URI:** apply to the host only
  (`scheme://[userinfo@]host[:port]/…` — host is the span between `//` and
  the next `/`, `?`, `#`, after stripping `userinfo@` and `:port`). Plain
  constraint ⇒ host equality; leading-period constraint ⇒ host is a strict
  subdomain of the remainder. A URI instance whose authority has no host or
  names an IP address, under any URI constraint, rejects with the fixed
  `uri name constraint…` reason ("the application MUST reject the
  certificate").
- Forms without a matcher (iPAddress, otherName, ediPartyName,
  registeredId): if a constraint on that form exists and an instance of that
  form appears in the evaluated certificate ⇒ `unsupported name form under
  name constraints: {form}` (`form` = `ip address`, `other name`,
  `edi party name`, `registered id`); otherwise inert.

Evaluated name instances per certificate: subject DN (directoryName) +
every `subjectAltName` entry (all forms; critical or not) + the legacy rule:
when the certificate does **not include a subject alternative name extension
at all**, each `emailAddress` attribute in the subject DN counts as an
rfc822Name instance — RFC 5280 §4.2.1.10: "When constraints are imposed on
the rfc822Name name form, but the certificate does not include a subject
alternative name, the rfc822Name constraint MUST be applied to the
attribute of type emailAddress in the subject distinguished name." The
matcher checks attribute OID `1.2.840.113549.1.9.1` (PKCS#9 emailAddress)
and also accepts `0.9.2342.19200300.100.1.1` (rfc4519 UID) for robustness.
Per form: excluded match ⇒ excluded
reason (checked first);
else if same-form permitted entries exist and none matches ⇒ permitted
reason; cross-form entries never compare and never increment `budget`.

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn dns_subtree_constraint_accepts_subdomain_leaf() {
    // root permitted = [DnsName("example.com")]; leaf SAN =
    // [DnsName("api.dev.example.com")] -> ok && anchored (footer: reason)
}
#[test]
fn dns_constraint_rejects_name_outside_subtree() {
    // leaf SAN = [DnsName("evil.example.org")] -> !ok,
    // reason contains "outside permitted name constraints"
}
#[test]
fn constraint_form_without_instance_is_inert() {
    // root permitted = [DnsName("example.com")]; leaf with NO SAN -> ok
}
#[test]
fn uri_constraint_matches_host_and_subdomain_forms() {
    // leaf SAN = [UniformResourceIdentifier("https://build.example.com/x")]
    // permitted = [UniformResourceIdentifier(".example.com")] -> ok
    // (period form = subdomains); sibling assert: plain constraint
    // "build.example.com" also ok (host equality), and plain "example.com"
    // against the same leaf -> permitted-rejection (plain form is host-only).
}
#[test]
fn uri_without_host_under_constraint_rejects() {
    // leaf SAN = [UniformResourceIdentifier("file:///tmp/x")], permitted =
    // [UniformResourceIdentifier("example.com")] -> !ok with the fixed
    // "uri name constraint" reason
}
#[test]
fn email_constraint_matches_san_address() {
    // permitted = [Rfc822Name("example.com")] (host form): leaf SAN =
    // [Rfc822Name("dev@example.com")] -> ok; [Rfc822Name("dev@other.org")]
    // -> permitted rejection; [Rfc822Name("dev@mail.example.com")] -> ALSO
    // rejected (host form is exact-domain only). Sibling fixture with
    // permitted = [Rfc822Name(".example.com")] accepts
    // dev@mail.example.com (period form = strict subdomains).
}
#[test]
fn legacy_email_dn_attribute_is_constrained_when_san_absent() {
    // leaf subject carries emailAddress and NO subjectAltName extension;
    // permitted = [Rfc822Name("example.com")].
    // FIRST assert the fixture provably carries the matched OID:
    //   assert the leaf's subject DN contains an AttributeTypeAndValue with
    //   type 1.2.840.113549.1.9.1 (or 0.9.2342.19200300.100.1.1) — build it
    //   with Name::from_str("CN=zsign leaf,emailAddress=dev@example.com")
    //   if that parser emits the emailAddress OID; otherwise construct the
    //   RDNSequence manually with AttributeTypeAndValue { type:
    //   1.2.840.113549.1.9.1, value: IA5String }.
    // Case A: emailAddress=dev@example.com -> ok && anchored (host-form
    // constraint equals the address domain).
    // Case B: emailAddress=dev@other.org -> !ok, reason contains
    // "outside permitted name constraints".
}
#[test]
fn unsupported_ip_constraint_with_instance_rejects() {
    // leaf SAN = [IpAddress(127.0.0.1 as 4 bytes)], permitted =
    // [IpAddress(127.0.0.0 + mask 8 bytes)] -> !ok reason contains
    // "unsupported name form under name constraints: ip address";
    // control: same root, leaf WITHOUT ip SAN -> ok (inert)
}
#[test]
fn comparison_budget_exceeds_and_rejects() {
    // root permitted = 5000 distinct DnsName entries; leaf SAN =
    // [DnsName("nomatch.example")] -> !ok, reason contains
    // "comparison budget exceeded" (5000 same-form comparisons > 4096)
}
```

All positive fixtures go through the signed-builder helpers; leaf SANs are
added via `builder.add_extension(&x509_cert::ext::pkix::SubjectAltName(...))`
in the `extend` closure.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-core -- dns_constraint uri email_constraint legacy_email unsupported_ip comparison_budget constraint_form`
Expected: FAIL — SAN names are not evaluated yet (Task 2's helper only
handles directoryName): the DNS/URI/email/IP cases verify or fail with the
wrong reason; compile-time if helpers are absent.

- [ ] **Step 3: Implement the per-form dispatch**

Extend `check_certificate_names`: extract instances (SAN + legacy email),
iterate constraint entries per the rules above, keep the excluded-first /
permitted-at-least-one order and the `budget` increments on same-form
comparisons only.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-core -- dns_constraint uri email_constraint legacy_email unsupported_ip comparison_budget constraint_form`
Expected: PASS (all nine).

- [ ] **Step 5: Full scoped gate**

Run: `cargo fmt --all -- --check` then
`cargo clippy --workspace --all-targets -- -D warnings` then
`mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test --workspace`
Expected: no diff; no rust warnings (the four pre-existing
`license`/`license-file` manifest warnings may appear); all workspace tests
pass — this doubles as the canary that no legitimate fixture carries an
unrecognized critical extension.

- [ ] **Step 6: Commit**

`git add crates/zsign-core/src/crypto/cms_verify.rs docs/superpowers/specs/2026-10-07-critical-ext-name-constraints-design.md docs/superpowers/plans/2026-10-07-critical-ext-name-constraints.md`
then commit per task in plan order, e.g.
`feat(crypto): reject unrecognized critical extensions in chain validation`
and
`feat(crypto): evaluate name constraints during chain validation`
— conventional, imperative, lowercase, no ticket ID in subject or body.

---

## Self-review

- Spec coverage: gate (design §1) → Task 1, including the self-signed-root
  and out-of-chain-anchor owning tests the cold review required; NC
  structure/directoryName (design §2, decisions on empty/min-max/malformed/
  self-issued skip) → Task 2; remaining name forms with the RFC's host/period
  semantics, unsupported-form fail-closed, budget, legacy email rule →
  Task 3.
- Step scan: each step is one action with a checkable result; test steps pin
  exact names/assertions/reason substrings; code steps pin signatures.
- Type consistency: `unrecognized_critical`, `NcScan`, `nc_shape_reason`,
  `check_certificate_names`, `MAX_NAME_COMPARISONS`,
  `build_rsa_root_signed`, `build_subca_issued_by_signed` used identically
  across tasks.
- Review Focus: every line has an owning test: Task 1 pins the parent/root
  gate coverage (`unknown_critical_extension_rejects_an_intermediate`,
  `self_signed_root_with_unknown_critical_rejects`), the non-critical
  control, and the §6.2 anchor exclusion
  (`out_of_chain_anchor_extensions_are_ignored`); Task 2 pins
  excluded-beats-permitted, empty, minimum and maximum rejection plus the
  self-issued skip (direct helper unit test); Task 3 pins inert forms, host
  vs period email/URI semantics, the legacy DN-email rule
  (`legacy_email_dn_attribute_is_constrained_when_san_absent`, with a
  fixture assertion on the matched OID), and the comparison budget.
- Proportion: plan size tracks three helper families and their fixtures;
  no step restates a body the signature and tests already determine.
