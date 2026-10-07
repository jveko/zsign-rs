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
  existing convention (cf. `issuer_ca_reason` at `:1667-1692`).
- No ticket IDs anywhere (code, comments, docs, commit messages).
- Zero-warning gate: `cargo fmt --all -- --check` + `cargo clippy --workspace --all-targets -- -D warnings`.
- Tests run with `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test …`.
- Every new assertion prints the actual received value in its failure footer.
- Processed critical-OID set (final state): 2.5.29.14, 2.5.29.15,
  2.5.29.17, 2.5.29.19, 2.5.29.30, 2.5.29.37 — as module-local
  `const OID_*` consts in the file's existing style (`:109-118`).
- `replace_extension` (test helper, hardcodes `critical: false`) invalidates
  the mutated certificate's signature — it may only be used for fixtures
  whose rejection fires before any signature verification of the mutated
  cert. Positive-path fixtures MUST be built fully signed via
  `CertificateBuilder` (dev-only `builder` feature).

## Review Focus

- Leaf, every in-walk parent, and the embedded self-signed root each get the
  critical-gate exactly once; the out-of-chain trust anchor resolved by
  `anchors.find_by_subject` gets neither gate nor constraints (§6.2).
- Positive control: an unknown **non-critical** extension still verifies —
  pinned by Task 1.
- Excluded beats permitted unconditionally; permitted is at-least-one-match —
  pinned by Task 2.
- Empty nameConstraints and non-default `minimum`/`maximum` reject — pinned
  by Task 2.
- A constraint with no instance of its name form is inert — pinned by Task 3.
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
  `ObjectIdentifier` (imported at `:45`), `ChainOutcome` (`:1322-1334`),
  `verify_chain` (`:1362`), test helpers `build_rsa_root` (`:2405`),
  `build_leaf` (`:2444`), `chain_with` (`:2433`).
- Produces:
  - `fn unrecognized_critical(cert: &x509_cert::Certificate) -> Option<ObjectIdentifier>` (private)
  - `const OID_CE_SUBJECT_KEY_IDENTIFIER / OID_CE_KEY_USAGE / OID_CE_SUBJECT_ALT_NAME / OID_CE_BASIC_CONSTRAINTS / OID_CE_NAME_CONSTRAINTS / OID_CE_EXT_KEY_USAGE` — the last four exist already as `OID_*` for 14/15/19/37; reuse those and add only the missing ones (`2.5.29.17`, `2.5.29.30`) in the same style. Task 2 consumes `OID_CE_NAME_CONSTRAINTS`.
  - Reason string format: `certificate has unrecognized critical extension {oid}` (lowercase, `{oid}` = dotted form).

- [ ] **Step 1: Test-only extension authoring types**

In the inline test module, two zero-sized authoring types for the builder:
each carries its own OID (experimental arc `2.999.1` / `2.999.2`), encodes as
an empty DER NULL, and reports `critical()` as `true` / `false` respectively.
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
```

Note: `build_leaf`/`build_subca_issued_by` currently take fixed arguments —
add ONE new helper `fn build_leaf_signed(cn, issuer, issuer_signing, extend:
&dyn FnOnce(&mut CertificateBuilder<…>))`… (or the equivalent generic form)
that delegates to the same construction but runs `extend` before
`build::<rsa::pkcs1v15::Signature>()`, and the analogous
`build_subca_issued_by_signed`. Do not modify existing helpers; existing
tests must compile unchanged.

- [ ] **Step 3: Run the tests to verify they fail**

Run: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-core unknown_`
Expected: FAIL — leaf/intermediate fixtures currently verify
(`ok=true, anchored=true`); the reason footer shows the actual outcome.

- [ ] **Step 4: Implement the gate**

- Add the two missing OID consts (`2.5.29.17`, `2.5.29.30`) in the existing
  `const OID_*` style with one-line `///` docs.
- `fn unrecognized_critical(cert) -> Option<ObjectIdentifier>` iterating
  `cert.tbs_certificate.extensions`, returning the first `e.critical` entry
  whose `extn_id` is not in the six-OID set.
- Hook A — `verify_chain` entry, before the purpose gate:
  `if let Some(oid) = unrecognized_critical(leaf) { return ChainOutcome { ok: false, anchored: false, subjects: names, reason: Some(format!("certificate has unrecognized critical extension {oid}")), warnings }; }`
- Hook B — parent branch, directly after the `issuer_ca_reason(p, …)` block,
  same construction with `p`.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-core unknown_`
Expected: PASS (all three).

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
- Consumes: `OID_CE_NAME_CONSTRAINTS` and the `verify_chain` hooks from
  Task 1; `x509_cert::ext::pkix::constraints::NameConstraints` /
  `GeneralSubtrees` / `GeneralSubtree`; test helpers
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
  OID_CE_NAME_CONSTRAINTS)`).
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
Expected: PASS (all seven).

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

Name matching rules (from the spec; each returns match / no-match):
- **dNSName:** strip an optional leading `.` from the constraint, then
  case-insensitive equality or `name.ends_with(".{constraint}")`.
- **rfc822Name:** a constraint containing `@` matches the full address
  (case-insensitive); otherwise it matches the address's domain subtree with
  the dNSName rule.
- **URI:** apply the dNSName rule to the URI's host
  (`scheme://[userinfo@]host[:port]/…` — host is the span between `//` and
  the next `/`, `?`, `#`, after stripping `userinfo@` and `:port`). A URI
  instance whose authority has no host, under any URI constraint, rejects
  with the fixed `uri name constraint…` reason.
- Forms without a matcher (iPAddress, otherName, ediPartyName,
  registeredId): if a constraint on that form exists and an instance of that
  form appears in the evaluated certificate ⇒ `unsupported name form under
  name constraints: {form}` (`form` = `ip address`, `other name`,
  `edi party name`, `registered id`); otherwise inert.

Evaluated name instances per certificate: subject DN (directoryName) +
every `subjectAltName` entry (all forms; critical or not) + the legacy rule:
when the certificate has **no subjectAltName extension at all**, each
`emailAddress` attribute in the subject DN (OID
`0.9.2342.19200300.100.1.1`) counts as an rfc822Name instance (§4.2.1.10
legacy rule as cited in the spec). Per form: excluded match ⇒ excluded
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
fn uri_constraint_matches_host_subtree() {
    // leaf SAN = [UniformResourceIdentifier("https://build.example.com/x")]
    // permitted = [UniformResourceIdentifier("example.com")] -> ok
}
#[test]
fn uri_without_host_under_constraint_rejects() {
    // leaf SAN = [UniformResourceIdentifier("file:///tmp/x")], permitted =
    // [UniformResourceIdentifier("example.com")] -> !ok with the fixed
    // "uri name constraint" reason
}
#[test]
fn email_constraint_matches_san_address() {
    // leaf SAN = [Rfc822Name("dev@example.com")], permitted =
    // [Rfc822Name("example.com")] -> ok; sibling assert: address outside
    // the domain -> permitted-reason rejection
}
#[test]
fn legacy_email_dn_attribute_is_constrained_when_san_absent() {
    // leaf subject carries emailAddress and NO subjectAltName extension;
    // permitted = [Rfc822Name("example.com")].
    // Case A: emailAddress=dev@example.com -> ok && anchored.
    // Case B: emailAddress=dev@other.org -> !ok, reason contains
    // "outside permitted name constraints".
    // Build the DN with Name::from_str("CN=zsign leaf,emailAddress=…"); if
    // that parser rejects the emailAddress short name, construct the
    // RDNSequence manually with AttributeTypeAndValue { type:
    // 0.9.2342.19200300.100.1.1, value: UTF8String }.
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

- Spec coverage: gate (design §1) → Task 1; NC structure/directoryName
  (design §2, decisions on empty/min-max/malformed/self-issued skip) →
  Task 2; remaining name forms, unsupported-form fail-closed, budget,
  legacy email rule → Task 3; trust-anchor exclusion is implemented by hook
  placement (only `certs`-resolved parents are evaluated) and asserted by
  existing anchored-chain tests plus Task 1's controls.
- Step scan: each step is one action with a checkable result; test steps pin
  exact names/assertions/reason substrings; code steps pin signatures.
- Type consistency: `unrecognized_critical`, `NcScan`, `nc_shape_reason`,
  `check_certificate_names`, `MAX_NAME_COMPARISONS`,
  `build_rsa_root_signed`, `build_subca_issued_by_signed` used identically
  across tasks.
- Review Focus: all five lines have owning tests (Task 1 controls; Task 2
  excluded/empty/min-max; Task 3 inert-form + budget). The legacy DN-email
  rule is pinned by Task 3's `legacy_email_dn_attribute_is_constrained_when_san_absent`;
  the trust-anchor exclusion is enforced by hook placement (only parents
  resolved from `certs` are gated/evaluated) and exercised by the unchanged
  `require_anchored_chain` tests.
- Proportion: plan size tracks three helper families and their fixtures;
  no step restates a body the signature and tests already determine.
