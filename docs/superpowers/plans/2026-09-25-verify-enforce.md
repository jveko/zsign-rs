# ZSN-25 Verifier Enforcement — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development
> (recommended) with dispatching-parallel-agents for independent tasks to implement this
> plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. The Tester agent
> authors each failing test; the implementer greens it; the controller runs the scoped
> gate and commits between tasks. Design rationale and citations:
> `docs/superpowers/specs/2026-09-25-verify-enforce-design.md`.

**Goal:** Make the core verifier reject every signature it cannot justify — dual-CDHash
binding, alternate-CD verification, required special slots, typed slot routing,
XML/DER entitlements equality, launch-constraint slots, exec-seg policy, designated
requirement evaluation, CodeDirectory version handling, and corrected constants.

**Architecture:** Patch-in-place inside the three scope files
(`crates/zsign-core/src/codesign/verify.rs`, `crates/zsign-core/src/codesign/constants.rs`,
`crates/zsign-core/src/macho/verify.rs`). Parsers may `Err`; `verify_slice` converts to
`report.errors` strings (the `Ok(report)` channel is frozen — see design C-4). All
findings ride `report.errors`/`report.warnings`. No signer/crypto/zsign edits.

**Tech Stack:** Rust 2021, `sha1`/`sha2` digests, `plist` for XML, in-repo
`codesign/der.rs::plist_to_der` as the reference for the DER decoder, inline
`#[cfg(test)] mod tests` (repo convention).

---

## Gates (run exactly these; never fmt/clippy/hk mid-flight)

- Scoped gate (every task, before its commit):
  `mkdir -p .tmptmp && TMPDIR=$PWD/.tmptmp cargo test -p zsign-core verify -- --skip test_ipa_signing_is_deterministic`
  Baseline at c9ff0fb: `54 passed; 0 failed`. `/tmp` is tmpfs and flakes SIGBUS under
  parallel-lane load — `TMPDIR` is mandatory. The `verify` substring selects
  `codesign::verify::tests::*` and `macho::verify::tests::*`.
- Constants gate (task 10 only): `TMPDIR=$PWD/.tmptmp cargo test -p zsign-core constants`
  — baseline `5 passed`, after task 10 `7 passed` (the `verify` filter does NOT match
  `codesign::constants::tests::*`).
- Caller-migration check (after any task that changes a `pub` signature — tasks 1, 2, 5, 6):
  `TMPDIR=$PWD/.tmptmp cargo check -p zsign-rs -p zsign-cli --all-targets`
- Final (task 11 only): scoped gate + constants gate +
  `TMPDIR=$PWD/.tmptmp cargo check --workspace --all-targets`.
- Expected scoped-gate count chain (54 baseline + new tests; each task's count is
  derived from ITS OWN test list below — if any actual number differs, stop and
  report the drift in plan-vs-actual instead of adjusting silently):
  T1 +1 → 55 · T2 +2 → 57 · T3 +3 → 60 · T4 +3 → 63 · T5 +5 → 68 · T6 +2 → 70 ·
  T7 +5 → 75 · T8 +5 → 80 · T9 +7 → 87 · T10 +2 → 89 in the `verify` filter, plus
  2 task-10 tests under the `constants` filter (5 → 7 there).
- Commits trigger the pre-commit hook; let it run and react to its output (do not
  manually invoke `cargo fmt`/`cargo clippy`/`hk`).

## Frozen contracts (from the design doc — every task must uphold)

C-1 `PageCheck` variants frozen (cli exhaustive matches). C-2 `SpecialSlotCheck`
variants frozen (cli exhaustive matches). C-3 `special_slots` positional, length ==
`n_special_slots`, `NotChecked` constructible at idx 0/2. C-4 `verify_macho` returns
`Ok(report)` for broken signatures. C-5 `SignatureInputs` = exactly `{info_plist,
code_resources}`; `verify_macho`/`parse_superblob` signatures frozen. Pinned error
substrings that must stay byte-identical: `code page {i} hash mismatch (code region
modified?)`, `code slot count mismatch`, `zero code bytes`,
`special slot -{k} hash mismatch`, `empty CMS wrapper but not ad-hoc flagged`,
`not anchored to a trusted root`, `LC_CODE_SIGNATURE`.

## Test fixtures available (macho/verify.rs tests module)

`rsa_credentials()` (Leaf-shaped, codeSigning EKU), `sign_round_trip` (sha256-only),
`make_minimal_macho()` (MH_EXECUTE, `__TEXT` vmaddr `0x1_0000_0000`), `signed_superblob`,
`entry_offset(sb, slot)` (superblob-relative child offset), `cms_report_with_test_anchor`
(injected `TrustAnchors`), `synth_superblob(total, entries)` (codesign/verify.rs tests).
Signing entry points: `sign_macho` (dual+creds), `sign_macho_sha256_only`,
`sign_macho_adhoc` (dual, ad-hoc — last bool is `allow_encrypted`, NOT sha256_only).

---

### Task 1: Dual-CDHash binding (queue item 1)

**Files:**
- Modify: `crates/zsign-core/src/macho/verify.rs` — CMS branch of `verify_slice`
  (~lines 190-197), delete `alternate_sha1` (~lines 239-260), tests module.

- [ ] **Step 1: Failing test first** (Tester)

Add `dual_signing_binds_cdhash_pair` to `macho/verify.rs` tests:

```rust
#[test]
fn dual_signing_binds_cdhash_pair() {
    let creds = rsa_credentials();
    let macho = MachOFile::parse(make_minimal_macho()).unwrap();
    // sign_macho signs in DUAL mode (sha256_only=false): SHA-1 primary at slot 0,
    // SHA-256 alternate at 0x1000, CMS over the primary.
    let signed = sign_macho(&macho, "com.example.dual", None, &creds, None, None, false).unwrap();
    let report = verify_macho(&signed, &SignatureInputs::none()).unwrap();
    assert!(!report.is_valid());
    let slice = &report.slices[0];
    assert!(slice.signed && !slice.adhoc);
    // Pre-fix: cdhash v1/v2 errors inflate this beyond 1.
    assert_eq!(slice.errors.len(), 1, "errors: {:?}", slice.errors);
    assert!(slice.errors[0].contains("not anchored to a trusted root"));
    assert_eq!(slice.pages, PageCheck::Matched);
    let cms = slice.cms.as_ref().unwrap();
    assert!(cms.signature_ok && cms.message_digest_ok && cms.chain_ok);
    assert!(cms.cdhash_v1_ok, "v1 errors: {:?}", cms.errors);
    assert!(cms.cdhash_v2_ok, "v2 errors: {:?}", cms.errors);
    let injected = cms_report_with_test_anchor(&signed, &creds);
    assert!(injected.valid, "cms errors: {:?}", injected.errors);
    assert!(injected.anchored);
}
```

Add `sign_macho` to the test module imports (`crate::macho::{sign_macho, ...}`).
The test's last block calls the existing `cms_report_with_test_anchor`, which hardcodes
`cd_sha1 = None` + the primary's `cdhash_sha256()` — wrong for dual output — so the
test fails both on `errors.len()` (production bug) and on `injected.valid` (helper
bug); both are fixed in Step 3.

- [ ] **Step 2: Run and confirm failure**

Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-core dual_signing_binds_cdhash_pair`
Expected: FAIL — `slice.errors.len()` is 3 (v1/v2 mismatch messages).

- [ ] **Step 3: Implement type-based pair selection**

In `macho/verify.rs`, add ONE shared selector used by production and by the test
helper, hoisted so both the CMS branch and later steps can see the emitted-CD list:

```rust
/// Every emitted CodeDirectory: primary first, then alternates, in slot order.
fn emitted_cds<'a>(superblob: &'a SuperBlob<'a>) -> Vec<&'a CodeDirectory<'a>> {
    let mut cds = Vec::with_capacity(1 + superblob.alternate_code_directories.len());
    if let Some(p) = superblob.code_directory.as_ref() {
        cds.push(p);
    }
    cds.extend(superblob.alternate_code_directories.iter());
    cds
}

/// The CDHash pair bound into the CMS attributes, selected BY EMITTED TYPE:
/// v1's first entry hashes the SHA-1 CD, v1's second entry and v2 hash the
/// SHA-256 CD. `None` when that type is not emitted.
fn cdhash_pair(cds: &[&CodeDirectory<'_>]) -> (Option<[u8; 20]>, Option<[u8; 32]>) {
    let sha1 = cds.iter().find(|cd| cd.is_sha1())
        .map(|cd| { let d: [u8; 20] = Sha1::digest(cd.raw()).into(); d });
    let sha256 = cds.iter().find(|cd| cd.is_sha256())
        .map(|cd| { let d: [u8; 32] = Sha256::digest(cd.raw()).into(); d });
    (sha1, sha256)
}
```

In `verify_slice`, bind `let cds = emitted_cds(&superblob);` immediately AFTER
`primary` is established (before the page/slot checks — the CMS branch and later
tasks reuse it). Add `use sha2::{Digest, Sha256};` to `macho/verify.rs`'s PRODUCTION
imports (today only `sha1` is imported there). Replace the `let cd_sha256 … let cd_sha1
= alternate_sha1(…)` block in the non-empty CMS path with a branch — **no early
return** (task 8's designated-requirement step must run on every path):

```rust
let (cd_sha1, cd_sha256_opt) = cdhash_pair(&cds);
match cd_sha256_opt {
    None => report.errors.push(
        "CMS signature present but no SHA-256 CodeDirectory to bind CDHash v2"
            .to_string(),
    ),
    Some(cd_sha256) => {
        match crate::crypto::cms_verify::verify_code_signature(
            cms_blob, primary.raw(), cd_sha1.as_ref(), &cd_sha256,
        ) {
            Ok(cms_report) => {
                if !cms_report.valid {
                    report.errors.extend(cms_report.errors.clone());
                }
                report.cms = Some(cms_report);
            }
            Err(e) => report.errors.push(format!("CMS verification error: {e}")),
        }
    }
}
```

Delete `fn alternate_sha1` entirely (its only caller is this site; its
"SHA-1 primary, no alternate" fallback has no emission counterpart).

Rewrite the test helper `cms_report_with_test_anchor` (tests module) to use the same
selectors instead of hardcoded `None`/primary:

```rust
let sb = parse_superblob(&bin[off..off + size]).unwrap();
let cds = emitted_cds(&sb);
let (cd_sha1, cd_sha256) = cdhash_pair(&cds);
let cd_sha256 = cd_sha256.expect("emitted SHA-256 CodeDirectory");
crate::crypto::cms_verify::verify_code_signature_with_anchors(
    sb.cms.expect("signed superblob carries a CMS slot"),
    sb.code_directory.as_ref().expect("primary").raw(),
    cd_sha1.as_ref(),
    &cd_sha256,
    &crate::crypto::cms_verify::TrustAnchors::from_certificates(vec![creds.certificate.clone()]),
)
.unwrap()
```

For sha256-only fixtures this yields exactly the old behavior (`cd_sha1 = None`,
`cd_sha256` = primary digest) — every existing caller of the helper stays valid.

- [ ] **Step 4: Green + migration check**

Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-core verify -- --skip test_ipa_signing_is_deterministic`
Expected: `55 passed; 0 failed` (54 baseline + 1 new).
Run: `TMPDIR=$PWD/.tmptmp cargo check -p zsign-rs -p zsign-cli --all-targets` → OK.

- [ ] **Step 5: Commit**

`git add crates/zsign-core/src/macho/verify.rs && git commit` with subject:
`fix(verify): bind cms cdhash attributes by emitted code directory type`

---

### Task 2: Verify every CodeDirectory; surface parse detail (queue item 2)

**Files:**
- Modify: `crates/zsign-core/src/codesign/verify.rs` — CD routing in `parse_superblob`
  (~lines 154-166).
- Modify: `crates/zsign-core/src/macho/verify.rs` — `verify_slice` superblob error site
  (~lines 120-124), page/slot loop (~lines 141-172), tests.

- [ ] **Step 1: Failing tests first** (Tester)

Both tests go in `macho/verify.rs` tests; add `CSSLOT_ALTERNATE_CODEDIRECTORIES` to
the test-module import list `crate::codesign::constants::{...}`:

```rust
#[test]
fn corrupt_alternate_cd_is_rejected_with_detail() {
    let macho = MachOFile::parse(make_minimal_macho()).unwrap();
    let mut signed = sign_macho_adhoc(&macho, "com.example.alt", None, None, None, false).unwrap();
    let m = MachOFile::parse(signed.clone()).unwrap();
    let sl = &m.slices()[0];
    let sig_off = sl.code_sig_offset.unwrap() as usize;
    let sig_len = sl.code_sig_size.unwrap() as usize;
    let cd = sig_off + entry_offset(&signed[sig_off..sig_off + sig_len],
        CSSLOT_ALTERNATE_CODEDIRECTORIES).unwrap();
    // Corrupt the child's hashType (byte 37) — the magic at [0..4) stays intact so
    // task 4's slot-magic table does not change this assertion's message.
    signed[cd + 37] = 0x07;
    // Pre-fix: the parse failure is silently dropped and this binary verifies.
    let report = verify_macho(&signed, &SignatureInputs::none()).unwrap();
    assert!(!report.is_valid());
    assert!(report.slices[0].errors.iter()
        .any(|e| e.contains("unsupported CodeDirectory hash type 7")),
        "errors: {:?}", report.slices[0].errors);
}

#[test]
fn tampered_alternate_page_hash_is_rejected() {
    let macho = MachOFile::parse(make_minimal_macho()).unwrap();
    let mut signed = sign_macho_adhoc(&macho, "com.example.alt2", None, None, None, false).unwrap();
    let m = MachOFile::parse(signed.clone()).unwrap();
    let sl = &m.slices()[0];
    let sig_off = sl.code_sig_offset.unwrap() as usize;
    let sig_len = sl.code_sig_size.unwrap() as usize;
    let cd = sig_off + entry_offset(&signed[sig_off..sig_off + sig_len],
        CSSLOT_ALTERNATE_CODEDIRECTORIES).unwrap();
    let hash_offset = u32::from_be_bytes(signed[cd + 16..cd + 20].try_into().unwrap()) as usize;
    signed[cd + hash_offset] ^= 0xFF; // first stored code hash of the SHA-256 alternate
    let report = verify_macho(&signed, &SignatureInputs::none()).unwrap();
    assert!(!report.is_valid());
    assert!(report.slices[0].errors.iter().any(|e| e.contains(
        "alternate SHA-256 code page 0 hash mismatch (code region modified?)")),
        "errors: {:?}", report.slices[0].errors);
    // Metadata = strongest CD (the tampered SHA-256 alternate), so the field
    // itself now reflects the tamper:
    assert_eq!(report.slices[0].pages, PageCheck::Mismatch { page_index: 0 });
}
```

- [ ] **Step 2: Confirm failure** — both FAIL today (parse failure dropped; alternate
pages never checked).

- [ ] **Step 3: Implement**

`parse_superblob` routing (both CD arms propagate detail):

```rust
CSSLOT_CODEDIRECTORY if code_directory.is_none() => {
    code_directory = Some(CodeDirectory::parse(entry.blob).map_err(|e| {
        crate::Error::Verification(format!("primary CodeDirectory: {e}"))
    })?);
}
CSSLOT_ALTERNATE_CODEDIRECTORIES..=CSSLOT_ALTERNATE_CODEDIRECTORY_LIMIT => {
    let cd = CodeDirectory::parse(entry.blob).map_err(|e| {
        crate::Error::Verification(format!("alternate CodeDirectory (slot 0x{:08x}): {e}", entry.slot))
    })?;
    alternate_code_directories.push(cd);
}
```

`verify_slice` (design §2 + architecture: CMS content stays the primary; report
METADATA is governed by the strongest viable CD):
- error site: `Err(e) => { report.errors.push(format!("embedded code signature is not a valid SuperBlob: {e}")); return Ok(report); }`
- emit `let strongest = cds.iter().max_by_key(|cd| cd.hash_size)` (SHA-256 beats
  SHA-1; own output emits at most one of each, so the maximum is unique). Pages: run `check_code_pages_in_file`
  for EVERY emitted CD; push failures through the local
  `fn push_page_errors(report: &mut SliceVerifyReport, label: &str, pages: &PageCheck)`
  — empty label for the PRIMARY (byte-identical pinned strings), `alternate
  {SHA-1|SHA-256} ` for alternates. Then set
  `report.pages = check_code_pages_in_file(strongest, data, slice)` (recomputed for
  the strongest CD — its result IS the metadata verdict that `is_valid` gates on via
  errors).
- special slots: run `check_special_slots(cd, inputs, req, ent, der)` for every
  emitted CD (pre-task-6 signature), collect `(label, checks)` pairs where label =
  `""` for primary and `alternate {SHA-1|SHA-256} ` (label from
  `if cd.is_sha1() { "SHA-1" } else { "SHA-256" }`) — the pairs are task 3's
  elevation hand-off. Push `Mismatch` findings from all pairs NOW (tagged);
  `report.special_slots = check_special_slots(strongest, …)` — the strongest CD's
  vector is the metadata. `NotChecked` elevation for BOTH primary and alternates
  lands in task 3.
- identity (`identifier`, `adhoc`) and the CMS `content` argument stay the PRIMARY
  (the CMS signs slot 0; strongest must NEVER be applied to `content`).

**Existing-test adjustment (intentional, queue item 2):**
`fat_code_limit_beyond_slice_is_rejected` asserts an EXACT
`report.slices[1].pages == CountMismatch { stored, computed }` on the PRIMARY it
patched. Under strongest-metadata the field now carries the unpatched SHA-256
alternate's verdict, so move the exact pin into the error channel (the test's second
assert already checks the substring):

```rust
assert!(report.slices[1].errors.iter().any(|e| e.contains(&format!(
    "code slot count mismatch: {n_slots} stored vs {} pages computed",
    slice_size.div_ceil(page_size)))),
    "errors: {:?}", report.slices[1].errors);
```

(drop the exact `pages` equality assert; keep every other line of that test). This is
a documented deviation: queue item 2 makes the strongest CD's verdict authoritative.

- [ ] **Step 4: Green + migration check** — scoped gate → `57 passed; 0 failed`;
  `cargo check -p zsign-rs -p zsign-cli --all-targets` → OK.

- [ ] **Step 5: Commit** — `fix(verify): verify every emitted code directory and surface parse detail`

---

### Task 3: Elevate bound-but-unavailable special slots (queue item 3)

**Files:**
- Modify: `crates/zsign-core/src/macho/verify.rs` — special-slot loop
  (~lines 166-172), tests.

- [ ] **Step 1: Failing tests first** (Tester)

```rust
#[test]
fn bound_slots_fail_when_context_is_supplied() {
    let resources =
        b"<?xml version=\"1.0\"?><plist><dict><key>files2</key><dict/></dict></plist>";
    let macho = MachOFile::parse(make_minimal_macho()).unwrap();
    let signed = sign_macho_adhoc(&macho, "com.example", None, None, Some(resources), false).unwrap();
    // Context supplied (any SignatureInputs field present) but the bound -3 content
    // is not → core-level failure, on primary and alternate alike:
    let inputs = SignatureInputs { info_plist: Some(b"not-the-fixture".as_slice()), code_resources: None };
    let report = verify_macho(&signed, &inputs).unwrap();
    assert!(!report.is_valid());
    let errors = &report.slices[0].errors;
    assert!(errors.iter()
        .any(|e| e.contains("special slot -3 is bound but its content was not supplied")),
        "primary: {:?}", errors);
    // Dual output's alternate is the SHA-256 CD; its unavailable slot elevates tagged:
    assert!(errors.iter().any(|e| e.contains(
        "alternate SHA-256 special slot -3 is bound but its content was not supplied")),
        "alternate: {:?}", errors);
    // With BOTH contents supplied the same binary has no slot finding:
    let ok = verify_macho(&signed, &SignatureInputs {
        info_plist: None, code_resources: Some(resources) }).unwrap();
    assert!(ok.slices[0].errors.is_empty(), "{:?}", ok.slices[0].errors);
}

#[test]
fn standalone_without_context_stays_silent() {
    // SignatureInputs::none() means "caller cannot supply -1/-3" (standalone
    // verification): bound-but-unavailable -1 stays NotChecked, the facade
    // (zsign verify_macho_file) reports it — core must not fail here.
    let info = b"<?xml version=\"1.0\"?><plist><dict><key>CFBundleIdentifier</key><string>com.example</string></dict></plist>";
    let macho = MachOFile::parse(make_minimal_macho()).unwrap();
    let signed = sign_macho_adhoc(&macho, "com.example", None, Some(info), None, false).unwrap();
    let report = verify_macho(&signed, &SignatureInputs::none()).unwrap();
    assert!(report.is_valid(), "{:?}", report.slices[0].errors);
    assert!(report.slices[0].errors.iter().all(|e| !e.contains("bound but")));
}

#[test]
fn requirements_slot_failure_needs_no_context() {
    // SuperBlob-sourced slots (-2 here) need NO caller context: drop the 0x0002
    // child by renaming its index entry to an unknown slot and keep the nonzero
    // -2 hash → unconditional core failure, even with SignatureInputs::none().
    let macho = MachOFile::parse(make_minimal_macho()).unwrap();
    let mut signed = sign_macho_adhoc(&macho, "com.example.bare", None, None, None, false).unwrap();
    let m = MachOFile::parse(signed.clone()).unwrap();
    let sl = &m.slices()[0];
    let sig_off = sl.code_sig_offset.unwrap() as usize;
    let sig_len = sl.code_sig_size.unwrap() as usize;
    let count = u32::from_be_bytes(
        signed[sig_off + 8..sig_off + 12].try_into().unwrap()) as usize;
    for i in 0..count {
        let e = sig_off + 12 + i * 8;
        if u32::from_be_bytes(signed[e..e + 4].try_into().unwrap()) == CSSLOT_REQUIREMENTS {
            signed[e..e + 4].copy_from_slice(&0x0040u32.to_be_bytes());
        }
    }
    let report = verify_macho(&signed, &SignatureInputs::none()).unwrap();
    assert!(!report.is_valid());
    assert!(report.slices[0].errors.iter().any(|e| e
        .contains("special slot -2 is bound but its content was not supplied")),
        "errors: {:?}", report.slices[0].errors);
}
```

(Add `CSSLOT_REQUIREMENTS` to the test imports if absent.)

- [ ] **Step 2: Confirm failure** — all three FAIL (no elevation exists yet; test 2
  currently passes trivially and guards the gating rule once elevation lands).

- [ ] **Step 3: Implement elevation** — REPLACE task 2's Mismatch-only push site with
one unified loop over the primary plus every collected alternate pair:

```rust
// -1/-3 need caller-supplied content: elevate ONLY when the caller demonstrated
// bundle context (any SignatureInputs field present). SignatureInputs::none()
// means "standalone: caller cannot supply these" — the zsign facade reports them.
const CONTEXT_SLOTS: [i32; 2] = [CSSLOT_SPECIAL_INFOSLOT, CSSLOT_SPECIAL_RESOURCEDIR];
// -2/-5/-7 and the launch-constraint slots are SuperBlob-sourced: their content
// needs no caller context, so NotChecked there is ALWAYS a core failure.
const SUPERBLOB_SLOTS: [i32; 7] = [
    CSSLOT_SPECIAL_REQUIREMENTS,       // -2
    CSSLOT_SPECIAL_ENTITLEMENTS,       // -5
    CSSLOT_SPECIAL_DER_ENTITLEMENTS,   // -7
    -8, -9, -10, -11,                  // launch constraints; task 10 swaps in the new constants
];
let context_supplied =
    inputs.info_plist.is_some() || inputs.code_resources.is_some();
// pairs: Vec<(String /* label, "" for primary */, Vec<SpecialSlotCheck>)>,
// built from ("".to_string(), report.special_slots-from-strongest-CD...) — use the
// PRIMARY's checks for the primary pair (task 2 collected them) plus the alternates.
for (label, checks) in &pairs {
    for (i, check) in checks.iter().enumerate() {
        let k = i + 1;
        let slot = -(k as i32);
        match check {
            SpecialSlotCheck::Mismatch => report.errors.push(format!(
                "{label}special slot -{k} hash mismatch")),
            SpecialSlotCheck::NotChecked
                if SUPERBLOB_SLOTS.contains(&slot)
                    || (context_supplied && CONTEXT_SLOTS.contains(&slot)) =>
            {
                report.errors.push(format!(
                    "{label}special slot -{k} is bound but its content was not supplied"));
            }
            _ => {}
        }
    }
}
```

`-4`/`-6` and `k ≥ 12` stay non-fatal `NotChecked` (never in the brief's required
list; blanketing them risks the interop gate on Apple output). With empty labels the
primary's `Mismatch` string stays byte-identical to the pinned
`special slot -{k} hash mismatch`. NOTE: task 2 stores `report.special_slots` from the
strongest CD; the PRIMARY's own vector must also be retained for this loop (collect
it in task 2 before overwriting — e.g. clone the primary checks into `pairs` first).

- [ ] **Step 4: Green** — scoped gate → `60 passed; 0 failed`. No pub signature
  change → no migration check needed.

- [ ] **Step 5: Commit** — `fix(verify): fail on bound special slots whose content is unavailable`

---

### Task 4: Typed slot-magic checks and duplicate rejection (queue item 4)

**Files:**
- Modify: `crates/zsign-core/src/codesign/verify.rs` — `parse_superblob` child walk
  (~lines 96-148), tests.

- [ ] **Step 1: Failing tests first** (Tester) — codesign/verify.rs tests:

```rust
#[test]
fn slot_magic_mismatch_is_rejected() {
    let mut b = build_blob(true);
    // locate the requirements child (slot 0x0002) via its index entry
    let count = u32::from_be_bytes(b[8..12].try_into().unwrap()) as usize;
    let mut off = 0usize;
    for i in 0..count {
        let e = 12 + i * 8;
        if u32::from_be_bytes(b[e..e + 4].try_into().unwrap()) == CSSLOT_REQUIREMENTS {
            off = u32::from_be_bytes(b[e + 4..e + 8].try_into().unwrap()) as usize;
        }
    }
    assert!(off > 0, "fixture must carry a requirements child");
    b[off..off + 4].copy_from_slice(&0u32.to_be_bytes());
    assert!(parse_superblob(&b).is_err(), "wrong magic must be rejected");
}

#[test]
fn distinct_duplicate_slot_is_rejected() {
    // Two DIFFERENT children both claiming slot 0x0002 (distinct ranges, so the
    // pairwise-overlap check passes): today last-wins Ok.
    let mut b = synth_superblob(60, &[(CSSLOT_REQUIREMENTS, 28), (CSSLOT_REQUIREMENTS, 44)]);
    b[28..32].copy_from_slice(&CSMAGIC_REQUIREMENTS.to_be_bytes());
    b[32..36].copy_from_slice(&16u32.to_be_bytes());
    b[44..48].copy_from_slice(&CSMAGIC_REQUIREMENTS.to_be_bytes());
    b[48..52].copy_from_slice(&16u32.to_be_bytes());
    assert!(parse_superblob(&b).is_err(), "duplicate slot must be rejected");
}

#[test]
fn duplicate_code_directory_slot_is_rejected() {
    // Two DIFFERENT valid CodeDirectory children both claiming slot 0x0000:
    // today the second is silently ignored by the is_none() guard.
    let a = CodeDirectoryBuilder::new("com.example.a", TEST_CODE).build_sha256();
    let c = CodeDirectoryBuilder::new("com.example.bbbb", TEST_CODE).build_sha256();
    let a_off = 28u32; // index = 12 + 2*8
    let c_off = a_off + a.len() as u32;
    let total = c_off + c.len() as u32;
    let mut b = synth_superblob(total,
        &[(CSSLOT_CODEDIRECTORY, a_off), (CSSLOT_CODEDIRECTORY, c_off)]);
    b[a_off as usize..a_off as usize + a.len()].copy_from_slice(&a);
    b[c_off as usize..c_off as usize + c.len()].copy_from_slice(&c);
    assert!(parse_superblob(&b).is_err(), "duplicate slot 0 must be rejected");
}
```

(`build_sha256()` output starts with the CD's own magic+length header, which is
exactly what the SuperBlob child must contain.)

- [ ] **Step 2: Confirm failure** — all three FAIL today.

- [ ] **Step 3: Implement in `parse_superblob`'s child walk** (the loop that pushes
`entries`):

```rust
fn expected_magic(slot: u32) -> Option<u32> {
    use crate::codesign::constants::*;
    Some(match slot {
        CSSLOT_CODEDIRECTORY | CSSLOT_ALTERNATE_CODEDIRECTORIES..=CSSLOT_ALTERNATE_CODEDIRECTORY_LIMIT
            => CSMAGIC_CODEDIRECTORY,
        CSSLOT_SIGNATURESLOT => CSMAGIC_BLOBWRAPPER,
        CSSLOT_REQUIREMENTS => CSMAGIC_REQUIREMENTS,
        CSSLOT_ENTITLEMENTS => CSMAGIC_EMBEDDED_ENTITLEMENTS,
        CSSLOT_DER_ENTITLEMENTS => CSMAGIC_EMBEDDED_DER_ENTITLEMENTS,
        _ => return None,
    })
}
```

Inside the walk (after `item` is bounded): if `let Some(want) = expected_magic(slot)`,
require `item[0..4] == want.to_be_bytes()` else
`Err(Verification(format!("SuperBlob entry {i} (slot 0x{slot:08x}): blob magic 0x{:08x}, expected 0x{want:08x}", u32::from_be_bytes(...))))`.
Track `seen: std::collections::HashSet<u32>` for the same recognized set (i.e. add to
`seen` only when `expected_magic` returned `Some`) — a second occurrence →
`Err(Verification(format!("duplicate SuperBlob slot 0x{slot:08x}")))`.
`code_directory.is_none()` guard in the routing loop stays (task 2 shape) — the
duplicate case can no longer reach it. Constraint slots `0x0008..0x000b` are NOT in the
table yet (their magic arrives with task 10). The truncated-CMS fixture keeps an
8-byte child with intact `CSMAGIC_BLOBWRAPPER` magic → passes the table; the
`empty CMS wrapper` rule still fires (design R5).

- [ ] **Step 4: Green** — scoped gate → `63 passed; 0 failed` (60 + 3 new).

- [ ] **Step 5: Commit** — `fix(verify): validate slot blob magics and reject duplicate slots`

---

### Task 5: XML vs DER entitlements comparison + DER requirement (queue item 5)

**Files:**
- Modify: `crates/zsign-core/src/codesign/verify.rs` — add
  `pub(crate) fn der_entitlements_to_plist(der: &[u8]) -> Result<plist::Value>`, tests.
- Modify: `crates/zsign-core/src/macho/verify.rs` — `verify_slice` wiring, tests.

- [ ] **Step 1: Failing tests first** (Tester)

codesign/verify.rs units (`der_entitlements_to_plist` takes the child PAYLOAD — the
8-byte blob header is stripped by callers; these tests pass raw encoder output, which
has no header):

```rust
#[test]
fn der_entitlements_round_trip() {
    let xml = br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>com.example.flag</key><true/>
<key>com.example.count</key><integer>7</integer>
<key>com.example.name</key><string>demo</string>
<key>com.example.list</key><array><string>a</string><integer>2</integer></array>
<key>com.example.nested</key><dict><key>inner</key><string>v</key></dict>
</dict></plist>"#;
    let der = crate::codesign::der::plist_to_der(xml).unwrap();
    let decoded = der_entitlements_to_plist(&der).unwrap();
    let expected = plist::from_bytes::<plist::Value>(xml.as_slice()).unwrap();
    assert_eq!(decoded, expected);
}

#[test]
fn der_v0_and_v1_shapes_parse() {
    // v1 as the repo encoder emits (der.rs:258-276):
    //   0x70 { INTEGER 1, 0xb0 { SEQUENCE{ UTF8String "k", UTF8String "v" } } }
    let v1 = [0x70u8, 0x0d, 0x02, 0x01, 0x01, 0xb0, 0x08,
              0x30, 0x06, 0x0c, 0x01, b'k', 0x0c, 0x01, b'v'];
    // v0: the bare entries SET with no envelope (older Apple blobs)
    let v0 = [0x31u8, 0x08, 0x30, 0x06, 0x0c, 0x01, b'k', 0x0c, 0x01, b'v'];
    for bytes in [v1.as_slice(), v0.as_slice()] {
        let v = der_entitlements_to_plist(bytes).unwrap();
        assert_eq!(v.as_dictionary().unwrap().get("k").unwrap().as_str(), Some("v"));
    }
}

#[test]
fn der_malformed_is_error() {
    assert!(der_entitlements_to_plist(&[0x31, 0x02, 0xff, 0xff]).is_err()); // length overrun
    assert!(der_entitlements_to_plist(&[]).is_err());
    assert!(der_entitlements_to_plist(&[0x70, 0x02, 0x05, 0x00]).is_err()); // no INTEGER version
}
```

macho/verify.rs e2e — add these test-module fixtures/helpers first:

```rust
const ENT_PLIST: &[u8] = br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>com.example.ent</key><string>same</string></dict></plist>"#;

fn adhoc_ent_fixture() -> Vec<u8> {
    let macho = MachOFile::parse(make_minimal_macho()).unwrap();
    sign_macho_adhoc(&macho, "com.example.ent", Some(ENT_PLIST), None, None, false).unwrap()
}

/// File offset of a SuperBlob child inside `signed` (slice 0 only).
fn child_off_in_signed(signed: &[u8], slot: u32) -> usize {
    let m = MachOFile::parse(signed.to_vec()).unwrap();
    let sl = &m.slices()[0];
    let sig_off = sl.code_sig_offset.unwrap() as usize;
    let sig_len = sl.code_sig_size.unwrap() as usize;
    sig_off + entry_offset(&signed[sig_off..sig_off + sig_len], slot).unwrap()
}

/// Rewrite stored special slot `k` (1-based) in BOTH CodeDirectories:
/// digest of `content` under each CD's own hash type, or all-zero when `None`.
fn bind_special_slot(signed: &mut [u8], k: usize, content: Option<&[u8]>) {
    let m = MachOFile::parse(signed.to_vec()).unwrap();
    let sl = &m.slices()[0];
    let sig_off = sl.code_sig_offset.unwrap() as usize;
    let sig_len = sl.code_sig_size.unwrap() as usize;
    let cds: Vec<usize> = [CSSLOT_CODEDIRECTORY, CSSLOT_ALTERNATE_CODEDIRECTORIES]
        .iter()
        .map(|s| sig_off + entry_offset(&signed[sig_off..sig_off + sig_len], *s).unwrap())
        .collect();
    for cd in cds {
        let hash_offset = u32::from_be_bytes(signed[cd + 16..cd + 20].try_into().unwrap()) as usize;
        let hash_size = signed[cd + 36] as usize;
        let hash_type = signed[cd + 37];
        let start = cd + hash_offset - k * hash_size;
        let bytes: Vec<u8> = match content {
            None => vec![0; hash_size],
            Some(c) => match hash_type {
                1 => Sha1::digest(c).to_vec(),
                _ => Sha256::digest(c).to_vec(),
            },
        };
        assert_eq!(bytes.len(), hash_size);
        signed[start..start + hash_size].copy_from_slice(&bytes);
    }
}

#[test]
fn differing_xml_der_entitlements_are_rejected() {
    let mut signed = adhoc_ent_fixture();
    // Flip ONE character inside the DER child's value: same length → still valid
    // DER, semantically different dictionary ("same" -> "sane").
    let der_off = child_off_in_signed(&signed, CSSLOT_DER_ENTITLEMENTS);
    let der_len = u32::from_be_bytes(signed[der_off + 4..der_off + 8].try_into().unwrap()) as usize;
    let pos = signed[der_off..der_off + der_len]
        .windows(4).position(|w| w == b"same").expect("value bytes in DER");
    signed[der_off + pos + 2] = b'n'; // "same" -> "sane", same length
    // Rebind -7 in both CDs so the integrity check stays green and the compare runs:
    let der_bytes = signed[der_off..der_off + der_len].to_vec();
    bind_special_slot(&mut signed, 7, Some(&der_bytes));
    let report = verify_macho(&signed, &SignatureInputs::none()).unwrap();
    assert!(report.slices[0].errors.iter()
        .any(|e| e.contains("XML and DER entitlements dictionaries differ")),
        "errors: {:?}", report.slices[0].errors);
}

#[test]
fn missing_der_for_modern_main_executable_is_rejected() {
    let mut signed = adhoc_ent_fixture();
    // Unbind -7 in both CDs (zero the stored hash): present-but-unbound must fail.
    bind_special_slot(&mut signed, 7, None);
    // Drop the 0x0007 index entry by renaming its slot type to an unknown value
    // (routing and the magic table ignore unknown slots; offsets stay valid).
    let m = MachOFile::parse(signed.clone()).unwrap();
    let sl = &m.slices()[0];
    let sig_off = sl.code_sig_offset.unwrap() as usize;
    let sig_len = sl.code_sig_size.unwrap() as usize;
    let count = u32::from_be_bytes(
        signed[sig_off + 8..sig_off + 12].try_into().unwrap()) as usize;
    for i in 0..count {
        let e = sig_off + 12 + i * 8;
        if u32::from_be_bytes(signed[e..e + 4].try_into().unwrap())
            == CSSLOT_DER_ENTITLEMENTS
        {
            signed[e..e + 4].copy_from_slice(&0x0040u32.to_be_bytes());
        }
    }
    let report = verify_macho(&signed, &SignatureInputs::none()).unwrap();
    assert!(report.slices[0].errors.iter().any(|e| e.contains(
        "XML entitlements bound (slot -5) without bound DER entitlements (slot -7)")),
        "errors: {:?}", report.slices[0].errors);
}
```

(Add `CSSLOT_DER_ENTITLEMENTS` to the test imports if absent; `Sha1`/`Sha256` are
already in scope via the module's `use super::*` + top-level imports.)

- [ ] **Step 2: Confirm failure** — all FAIL (no decoder, no comparison).

- [ ] **Step 3: Implement**

(1) Add the payload accessor to `SlotEntry` (codesign/verify.rs, next to the struct —
`parse_superblob` already guarantees `blob.len() >= 8` and `blob` is exactly the
child's declared length):

```rust
impl<'a> SlotEntry<'a> {
    /// The child's payload: its declared bytes AFTER the 8-byte magic+length
    /// header. Semantic parsers (plist, DER) need this; the special-slot
    /// hashes cover the FULL blob including the header.
    pub fn payload(&self) -> &'a [u8] {
        &self.blob[8..]
    }
}
```

(2) `der_entitlements_to_plist(der: &[u8]) -> Result<plist::Value>` in
codesign/verify.rs (private `fn` + `pub(crate)` re-export used by macho/verify.rs):

- `parse_tlv(bytes, depth) -> Result<plist::Value>` walking one tag-length-value at a
  time with `depth > 32 → Err`; every length checked against remaining input
  (short/long form, first byte `0x80|n` with n ≤ size-of-usize, reject indefinite
  `0x80`).
- Top level: if first tag is `0x70` (APPLICATION 16 constructed) → decode its content
  as `INTEGER version` (any value) followed by the entries container; else the whole
  input IS the entries container (v0).
- Entries container tags accepted (tag-agnostic pair walk): `0xb0 | 0x31 | 0x30 | 0x60
  | 0xa0`; each child must be a `SEQUENCE (0x30)` pair of `UTF8String (0x0c)` key +
  value.
- Value tags: `0x01` BOOLEAN (0x00/0xff; other → `Err`), `0x02` INTEGER (minimal DER,
  sign-extended to i64 → `plist::Integer`), `0x0c | 0x16 | 0x1e` UTF8/IA5/BMP strings
  (`0x1e` UTF-16BE → decode), `0x04` OCTET STRING → `Data`, `0x17/0x18` UTCTime /
  GeneralizedTime → `Date` (parse via `plist::Date` from a unix timestamp),
  `0x30` → `Array` of decoded elements, container tags → nested `Dictionary`.
  `0x05 NULL` and any other tag → `Err` (plist has no null — fail closed; the repo
  encoder never emits them).
- Depth cap applies to nested containers.

(3) `verify_slice` wiring — place AFTER the special-slot loop (tasks 1-3), BEFORE the
CMS branch; `payload()` everywhere, and the binding rule:

```rust
let child = |slot: u32| superblob.entries.iter().find(|e| e.slot == slot);
let xml_bound = primary.special_slot_hash(5)
    .map(|h| h.iter().any(|&b| b != 0)).unwrap_or(false);
let der_bound = primary.special_slot_hash(7)
    .map(|h| h.iter().any(|&b| b != 0)).unwrap_or(false);

if let Some(xml_entry) = child(CSSLOT_ENTITLEMENTS) {
    let xml_val = plist::from_bytes::<plist::Value>(xml_entry.payload())
        .map(Some)
        .unwrap_or_else(|e| {
            report.errors.push(format!("XML entitlements do not parse: {e}"));
            None
        });
    match child(CSSLOT_DER_ENTITLEMENTS) {
        Some(der_entry) => match der_entitlements_to_plist(der_entry.payload()) {
            Ok(der_val) => {
                if let Some(xml_val) = &xml_val {
                    if &der_val != xml_val {
                        report.errors.push(
                            "XML and DER entitlements dictionaries differ".to_string());
                    }
                }
            }
            Err(e) => report.errors.push(format!("DER entitlements do not parse: {e}")),
        },
        None => {}
    }
}
// Binding rule: a bound -5 on a modern main executable requires a BOUND -7 child.
if xml_bound
    && slice.is_executable
    && primary.version >= CODEDIRECTORY_VERSION_EXECSEG
    && !(der_bound && child(CSSLOT_DER_ENTITLEMENTS).is_some())
{
    report.errors.push(
        "XML entitlements bound (slot -5) without bound DER entitlements (slot -7)"
            .to_string());
}
```

Rationale for both conditions: a present-but-unbound DER child (hash zeroed) fails
`der_bound`; an unbound-but-present child also reaches the compare above, which is
harmless (the binding rule is what rejects it). Non-executables and pre-0x20400 CDs
never fire the rule (dylibs bind −5 without −7 by design).

- [ ] **Step 4: Green + migration check** — scoped gate → `68 passed; 0 failed`
  (63 + 5 new);
  `cargo check -p zsign-rs -p zsign-cli --all-targets` → OK (`SlotEntry::payload` is
  additive; `self_consistent_blobs` untouched until task 6).

- [ ] **Step 5: Commit** — `fix(verify): compare xml and der entitlements and require der for main executables`

---

### Task 6: Launch-constraint slots −8..−11 (queue item 6)

**Files:**
- Modify: `crates/zsign-core/src/codesign/verify.rs` — `check_special_slots` signature +
  content map; delete `self_consistent_blobs` and the `SlotBlobs` type alias.
- Modify: `crates/zsign-core/src/macho/verify.rs` — caller migration, tests.

- [ ] **Step 1: Failing tests first** (Tester)

codesign/verify.rs unit — build a CD whose −8 window holds the REAL digest of a
`0xfade8181` child (valid magic from the start, so task 10's magic table cannot break
this test):

```rust
fn synth_cd_with_slot8(child: &[u8]) -> Vec<u8> {
    // 0x20400 layout: 88-byte header + ident + 8 special slots + 0 code slots.
    let ident = b"com.example.lc\0";
    let n_special = 8usize;
    let hash_size = 32usize;
    let hash_offset = 88 + ident.len() + n_special * hash_size;
    let mut cd = vec![0u8; hash_offset];
    cd[0..4].copy_from_slice(&CSMAGIC_CODEDIRECTORY.to_be_bytes());
    cd[4..8].copy_from_slice(&(hash_offset as u32).to_be_bytes());
    cd[8..12].copy_from_slice(&CODEDIRECTORY_VERSION.to_be_bytes());
    cd[16..20].copy_from_slice(&(hash_offset as u32).to_be_bytes()); // hashOffset
    cd[20..24].copy_from_slice(&88u32.to_be_bytes()); // identOffset
    cd[24..28].copy_from_slice(&(n_special as u32).to_be_bytes());
    cd[36] = hash_size as u8;
    cd[37] = CS_HASHTYPE_SHA256;
    cd[39] = 12; // pageSize log2
    cd[88..88 + ident.len()].copy_from_slice(ident);
    let digest = Sha256::digest(child);
    cd[hash_offset - 8 * hash_size..hash_offset - 7 * hash_size]
        .copy_from_slice(&digest);
    cd
}

#[test]
fn launch_constraint_content_comes_from_superblob_slot_8() {
    let child: Vec<u8> = [0xfade8181u32.to_be_bytes(), // CSMAGIC_LAUNCH_CONSTRAINT (task 10 swaps the literal for the constant)
                          12u32.to_be_bytes(), [0u8; 4]].concat();
    let cd_bytes = synth_cd_with_slot8(&child);
    let cd = CodeDirectory::parse(&cd_bytes).unwrap();
    assert_eq!(cd.n_special_slots, 8);

    let total = (12 + 8 + child.len()) as u32;
    let mut sb = synth_superblob(total, &[(CSSLOT_LAUNCH_CONSTRAINT_SELF, 20)]);
    sb[20..20 + child.len()].copy_from_slice(&child);
    let parsed = parse_superblob(&sb).expect("slot 0x0008 child parses");
    let checks = check_special_slots(&cd, &SignatureInputs::none(), &parsed);
    assert_eq!(checks[7], SpecialSlotCheck::Matched); // k=8 verified against 0x0008

    let empty = synth_superblob(20, &[]);
    let parsed_empty = parse_superblob(&empty).unwrap();
    let checks2 = check_special_slots(&cd, &SignatureInputs::none(), &parsed_empty);
    assert_eq!(checks2[7], SpecialSlotCheck::NotChecked);
}
```

(`CSMAGIC_LAUNCH_CONSTRAINT` does not exist until task 10 — use the literal
`0xfade8181u32` here with a comment, and task 10 swaps it for the constant.)
Pre-fix: fails to compile against the old `check_special_slots` signature (that
counts as the failing step).

macho/verify.rs e2e (`ENT_PLIST` and helpers come from task 5's test module):

```rust
#[test]
fn bound_launch_constraint_without_blob_is_rejected() {
    let macho = MachOFile::parse(make_minimal_macho()).unwrap();
    let mut signed = sign_macho_adhoc(&macho, "com.example.lc", Some(ENT_PLIST), None, None, false).unwrap();
    // Grow the special-slot window 7 -> 8 on the primary CD. The new -8 region
    // [hashOffset-256, hashOffset-224) overlaps exec-seg header/ident bytes, which
    // are deterministically nonzero for this fixture => stored hash "bound";
    // no 0x0008 child exists => content unavailable => elevation must fire.
    let cd = child_off_in_signed(&signed, CSSLOT_CODEDIRECTORY);
    let n_special = u32::from_be_bytes(signed[cd + 24..cd + 28].try_into().unwrap());
    assert_eq!(n_special, 7, "fixture precondition: main + entitlements binds 7 slots");
    signed[cd + 24..cd + 28].copy_from_slice(&8u32.to_be_bytes());
    let report = verify_macho(&signed, &SignatureInputs::none()).unwrap();
    assert!(report.slices[0].errors.iter().any(|e| e.contains(
        "special slot -8 is bound but its content was not supplied")),
        "errors: {:?}", report.slices[0].errors);
}
```

(`child_off_in_signed` is task 5's helper. The fixture's PRIMARY is the SHA-1 CD
(dual output, `hash_size` 20): ident `com.example.lc\0` = 15 bytes, so
`hashOffset = 88 + 15 + 7*20 = 243`, the parse guard `n_special <= hashOffset/hash_size`
gives `8 <= 12` ✓, and the grown −8 window `[243-160, 243-140) = [83, 103)` lands on
the exec-segment header tail (nonzero flags word) plus the identifier bytes —
deterministically nonzero "bound" storage. The alternate CD keeps `n = 7`, so only
the primary contributes the −8 finding — tagged with the empty primary label.)

- [ ] **Step 2: Confirm failure** — unit FAILS (old `check_special_slots` signature —
  compile error counts as the failing step; the `Matched` path does not exist yet).
  The e2e already PASSES at this point (task 3's numeric 8..11 elevation fires on the
  old `_ => None` arm) — it is the end-to-end guard for that elevation, not the delta
  for this task; the delta is the unit's `Matched` path.

- [ ] **Step 3: Implement**

New signature (sole caller `macho/verify.rs` — migrate it in this task):

```rust
pub fn check_special_slots(
    cd: &CodeDirectory<'_>,
    inputs: &SignatureInputs<'_>,
    superblob: &SuperBlob<'_>,
) -> Vec<SpecialSlotCheck>
```

Content mapping inside the `k` loop replaces the old `match k` arms:

```rust
let slot_child = |slot: u32| superblob.entries.iter()
    .find(|e| e.slot == slot).map(|e| e.blob); // FULL blob: hashes cover the header
let content: Option<&[u8]> = match k {
    1 => inputs.info_plist,                       // caller only (design: no superblob fallback)
    3 => inputs.code_resources,                   // caller only
    2 => slot_child(CSSLOT_REQUIREMENTS),
    5 => slot_child(CSSLOT_ENTITLEMENTS),
    7 => slot_child(CSSLOT_DER_ENTITLEMENTS),
    8 => slot_child(CSSLOT_LAUNCH_CONSTRAINT_SELF),
    9 => slot_child(CSSLOT_LAUNCH_CONSTRAINT_PARENT),
    10 => slot_child(CSSLOT_LAUNCH_CONSTRAINT_RESPONSIBLE),
    11 => slot_child(CSSLOT_LIBRARY_CONSTRAINT),
    4 | 6 => None,
    _ => None,
};
```

Digest selection unchanged (`cd.hash_type` drives SHA-1/SHA-256). Delete
`self_consistent_blobs` + the `SlotBlobs` alias; migrate `macho/verify.rs` to a single
`check_special_slots(primary, inputs, &superblob)` call (tasks 1-5 read entitlements
children directly from `superblob.entries`, so nothing else consumed the deleted
items). Note the alternate-CD slot checks from task 2 also migrate to the new
signature in this task.

- [ ] **Step 4: Green + migration check** — scoped gate → `70 passed; 0 failed`
  (68 + 2 new); `cargo check -p zsign-rs -p zsign-cli --all-targets` → OK.

- [ ] **Step 5: Commit** — `fix(verify): verify launch constraint slots against their superblob blobs`

---

### Task 7: Parse and enforce executable-segment fields (queue item 7)

**Files:**
- Modify: `crates/zsign-core/src/codesign/verify.rs` — `CodeDirectory` struct + `parse`
  (version-gated reads), tests.
- Modify: `crates/zsign-core/src/macho/verify.rs` — policy enforcement, tests.

- [ ] **Step 1: Failing tests first** (Tester)

```rust
// codesign/verify.rs
#[test]
fn parse_reads_exec_segment_fields() {
    let cd_bytes = CodeDirectoryBuilder::new("com.example.exec", TEST_CODE)
        .exec_seg_base(0x1_0000_0000)
        .exec_seg_limit(0x1000)
        .exec_seg_flags(CS_EXECSEG_MAIN_BINARY)
        .build_sha256();
    let cd = CodeDirectory::parse(&cd_bytes).unwrap();
    assert_eq!(cd.exec_seg_base, 0x1_0000_0000);
    assert_eq!(cd.exec_seg_limit, 0x1000);
    assert_eq!(cd.exec_seg_flags, CS_EXECSEG_MAIN_BINARY);
}
```

macho/verify.rs — four tests on ad-hoc fixtures (patch the PRIMARY CD; ad-hoc means
no CMS binding interferes). Common prelude, write it once as a helper:

```rust
/// Ad-hoc dual fixture with `__TEXT` vm exec-seg values; returns bytes with the
/// PRIMARY CD's exec-seg header already patched by `f(base, limit, flags)`.
fn adhoc_with_patched_execseg(
    f: impl FnOnce(u64, u64, u64) -> (u64, u64, u64),
) -> Vec<u8> {
    let macho = MachOFile::parse(make_minimal_macho()).unwrap();
    let mut signed = sign_macho_adhoc(&macho, "com.example.xseg", None, None, None, false).unwrap();
    let cd = child_off_in_signed(&signed, CSSLOT_CODEDIRECTORY);
    let base = u64::from_be_bytes(signed[cd + 64..cd + 72].try_into().unwrap());
    let limit = u64::from_be_bytes(signed[cd + 72..cd + 80].try_into().unwrap());
    let flags = u64::from_be_bytes(signed[cd + 80..cd + 88].try_into().unwrap());
    let (b, l, g) = f(base, limit, flags);
    signed[cd + 64..cd + 72].copy_from_slice(&b.to_be_bytes());
    signed[cd + 72..cd + 80].copy_from_slice(&l.to_be_bytes());
    signed[cd + 80..cd + 88].copy_from_slice(&g.to_be_bytes());
    signed
}

#[test]
fn exec_segment_range_mismatch_is_rejected() {
    let signed = adhoc_with_patched_execseg(|_, _, g| (0xDEAD_0000_0000_0000u64, 0x1000, g));
    let report = verify_macho(&signed, &SignatureInputs::none()).unwrap();
    assert!(report.slices[0].errors.iter()
        .any(|e| e.contains("does not match __TEXT")),
        "errors: {:?}", report.slices[0].errors);
}

#[test]
fn unknown_exec_segment_flag_bits_are_rejected() {
    let signed = adhoc_with_patched_execseg(|b, l, g| (b, l, g | 0x800));
    let report = verify_macho(&signed, &SignatureInputs::none()).unwrap();
    assert!(report.slices[0].errors.iter()
        .any(|e| e.contains("unknown exec segment flags bits 0x800")),
        "errors: {:?}", report.slices[0].errors);
}

#[test]
fn main_binary_flag_is_required_for_executables() {
    let signed = adhoc_with_patched_execseg(|b, l, _| (b, l, 0));
    let report = verify_macho(&signed, &SignatureInputs::none()).unwrap();
    assert!(report.slices[0].errors.iter()
        .any(|e| e.contains("exec segment flags missing CS_EXECSEG_MAIN_BINARY")),
        "errors: {:?}", report.slices[0].errors);
}

#[test]
fn jit_flag_without_entitlements_warns() {
    let signed = adhoc_with_patched_execseg(|b, l, g| (b, l, g | 0x40)); // CS_EXECSEG_JIT
    let report = verify_macho(&signed, &SignatureInputs::none()).unwrap();
    assert!(report.slices[0].warnings.iter()
        .any(|w| w.contains("cannot be cross-checked without entitlements")),
        "warnings: {:?}", report.slices[0].warnings);
    assert!(report.is_valid(),
        "a warning must not invalidate: {:?}", report.slices[0].errors);
}
```

(`child_off_in_signed` is task 5's helper; add `CSSLOT_CODEDIRECTORY` to test imports
if absent — it is already there.)

- [ ] **Step 2: Confirm failure** — all FAIL (fields don't exist / nothing enforces).

- [ ] **Step 3: Implement**

`CodeDirectory`: add pub fields `exec_seg_base: u64`, `exec_seg_limit: u64`,
`exec_seg_flags: u64` (0 when version < `0x20400`). In `parse`, for
`version >= CODEDIRECTORY_VERSION_EXECSEG` read `rd_u64(64)`, `rd_u64(72)`, `rd_u64(80)`
(add a `rd_u64` helper beside `rd_u32`).

`verify_slice` (primary CD only, only when `primary.version >= CODEDIRECTORY_VERSION_EXECSEG`,
placed after the special-slot loop):

```rust
let (base, limit, flags) = (primary.exec_seg_base, primary.exec_seg_limit, primary.exec_seg_flags);
if base != 0 || limit != 0 {
    // Branch 1: our signer's convention (vmaddr/vmsize) — exact, sound.
    let vm_matches = base == slice.text_segment_base && limit == slice.text_segment_size;
    // Branch 2: file-convention plausibility fallback (Apple: fileoff/filesize).
    // NOT sound enforcement — the parser does not expose __TEXT fileoff/filesize
    // (design §7 BLOCKED note); the >= 4 KiB floor rejects degenerate ranges.
    let file_space_ok = base <= slice.size as u64
        && limit >= 0x1000
        && limit <= slice.text_segment_size
        && base.saturating_add(limit) <= slice.size as u64;
    if !vm_matches && !file_space_ok {
        report.errors.push(format!(
            "executable segment range 0x{base:x}+0x{limit:x} does not match __TEXT"));
    }
}
const KNOWN_EXECSEG_FLAGS: u64 = 0x1 | 0x10 | 0x20 | 0x40 | 0x80 | 0x100 | 0x200;
if flags & !KNOWN_EXECSEG_FLAGS != 0 {
    report.errors.push(format!(
        "unknown exec segment flags bits {:#x}", flags & !KNOWN_EXECSEG_FLAGS));
}
if (flags & CS_EXECSEG_MAIN_BINARY != 0) != slice.is_executable {
    report.errors.push(if slice.is_executable {
        "exec segment flags missing CS_EXECSEG_MAIN_BINARY".to_string()
    } else {
        "CS_EXECSEG_MAIN_BINARY set on a non-executable slice".to_string()
    });
}
// Entitlement SUBSET cross-check (flag => key present; never equality).
const CROSS_CHECK_FLAGS: u64 = CS_EXECSEG_ALLOW_UNSIGNED | CS_EXECSEG_JIT
    | CS_EXECSEG_DEBUGGER | CS_EXECSEG_SKIP_LV;
if flags & CROSS_CHECK_FLAGS != 0 {
    let ent_dict = child(CSSLOT_ENTITLEMENTS)
        .and_then(|e| plist::from_bytes::<plist::Dictionary>(e.payload()).ok());
    match ent_dict {
        Some(dict) => {
            let has = |k: &str| dict.get(k).is_some();
            if flags & CS_EXECSEG_ALLOW_UNSIGNED != 0
                && !(has("get-task-allow") || has("run-unsigned-code")) {
                report.errors.push(
                    "CS_EXECSEG_ALLOW_UNSIGNED requires get-task-allow or run-unsigned-code"
                        .to_string());
            }
            if flags & CS_EXECSEG_JIT != 0 && !has("dynamic-codesigning") {
                report.errors.push(
                    "CS_EXECSEG_JIT requires dynamic-codesigning".to_string());
            }
            if flags & CS_EXECSEG_DEBUGGER != 0 && !has("com.apple.private.cs.debugger") {
                report.errors.push(
                    "CS_EXECSEG_DEBUGGER requires com.apple.private.cs.debugger".to_string());
            }
            if flags & CS_EXECSEG_SKIP_LV != 0
                && !has("com.apple.private.skip-library-validation") {
                report.errors.push(
                    "CS_EXECSEG_SKIP_LV requires com.apple.private.skip-library-validation"
                        .to_string());
            }
            // CAN_LOAD_CDHASH / CAN_EXEC_CDHASH: no pinned entitlement key names
            // (design §7) → not enforced.
        }
        None => report.warnings.push(format!(
            "exec segment flags {:#x} cannot be cross-checked without entitlements",
            flags)),
    }
}
```

`CS_EXECSEG_DEBUGGER|CS_EXECSEG_JIT|CS_EXECSEG_SKIP_LV` already exist in constants (zero
consumers today → first use here).

- [ ] **Step 4: Green** — scoped gate → `75 passed; 0 failed` (70 + 5 new; any drift
  must be explained in the final report; existing fixtures must stay green — the
  dual/sha256-only/ad-hoc fixtures all carry `(base,limit)` = vm pair, flags `0x1`).

- [ ] **Step 5: Commit** — `feat(verify): parse and enforce executable segment fields`

---

### Task 8: Designated requirement parser + evaluator (queue item 8)

**Files:**
- Modify: `crates/zsign-core/src/codesign/verify.rs` — parser + Kleene evaluator, tests.
- Modify: `crates/zsign-core/src/macho/verify.rs` — restructure the CMS block so both
  paths fall through, then wire evaluation after the whole chain; tests.

- [ ] **Step 1: Failing tests first** (Tester) — codesign/verify.rs units:

```rust
fn req_blob_with_dr(expr: &[u8]) -> Vec<u8> {
    // Requirements SuperBlob: magic/length/count=1, index {type=designated,
    // offset=0x14}, child: CSMAGIC_REQUIREMENT / length / kind=exprForm(1) / expr.
    let child_len = 12 + expr.len();
    let total = 0x14 + child_len;
    let mut b = Vec::with_capacity(total);
    b.extend_from_slice(&CSMAGIC_REQUIREMENTS.to_be_bytes());
    b.extend_from_slice(&(total as u32).to_be_bytes());
    b.extend_from_slice(&1u32.to_be_bytes());            // count
    b.extend_from_slice(&CSREQ_DESIGNATED.to_be_bytes()); // type = designated
    b.extend_from_slice(&0x14u32.to_be_bytes());         // child offset
    b.extend_from_slice(&CSMAGIC_REQUIREMENT.to_be_bytes());
    b.extend_from_slice(&(child_len as u32).to_be_bytes());
    b.extend_from_slice(&1u32.to_be_bytes());            // kind = exprForm
    b.extend_from_slice(expr);
    b
}

fn ident_expr(name: &str) -> Vec<u8> {
    let mut e = 2u32.to_be_bytes().to_vec(); // opIdent
    e.extend_from_slice(&(name.len() as u32).to_be_bytes());
    e.extend_from_slice(name.as_bytes());
    while e.len() % 4 != 0 { e.push(0); }    // string operand 4-aligned
    e
}

fn kind_lwcr_blob() -> Vec<u8> {
    let expr = ident_expr("x");
    let child_len = 12 + expr.len();
    let total = 0x14 + child_len;
    let mut b = Vec::with_capacity(total);
    b.extend_from_slice(&CSMAGIC_REQUIREMENTS.to_be_bytes());
    b.extend_from_slice(&(total as u32).to_be_bytes());
    b.extend_from_slice(&1u32.to_be_bytes());
    b.extend_from_slice(&CSREQ_DESIGNATED.to_be_bytes());
    b.extend_from_slice(&0x14u32.to_be_bytes());
    b.extend_from_slice(&CSMAGIC_REQUIREMENT.to_be_bytes());
    b.extend_from_slice(&(child_len as u32).to_be_bytes());
    b.extend_from_slice(&2u32.to_be_bytes()); // kind = lwcrForm → must Err
    b.extend_from_slice(&expr);
    b
}

fn truncated_expr_blob() -> Vec<u8> {
    let mut expr = 2u32.to_be_bytes().to_vec(); // opIdent …
    expr.extend_from_slice(&16u32.to_be_bytes()); // … declares 16 bytes …
    expr.extend_from_slice(b"abc");               // … provides 3 → operand overrun
    req_blob_with_dr(&expr)
}

#[test]
fn designated_requirement_evaluates_identifier() {
    let blob = req_blob_with_dr(&ident_expr("com.example"));
    let set = parse_requirements(&blob).unwrap();
    let dr = set.designated().expect("dr present");
    assert_eq!(dr.evaluate(&RequirementContext {
        identifier: Some("com.example"), cdhashes: &[], anchored: None }),
        RequirementVerdict::Satisfied);
    assert_eq!(dr.evaluate(&RequirementContext {
        identifier: Some("com.evil"), cdhashes: &[], anchored: None }),
        RequirementVerdict::Violated);
    // Binary AND (opAnd = 6) over left/right subtrees:
    let mut and_true = 6u32.to_be_bytes().to_vec();
    and_true.extend_from_slice(&ident_expr("com.example"));
    and_true.extend_from_slice(&1u32.to_be_bytes()); // opTrue
    let set2 = parse_requirements(&req_blob_with_dr(&and_true)).unwrap();
    assert_eq!(set2.designated().unwrap().evaluate(&RequirementContext {
        identifier: Some("com.example"), cdhashes: &[], anchored: None }),
        RequirementVerdict::Satisfied);
}

#[test]
fn empty_requirements_has_no_designated() {
    assert!(parse_requirements(crate::codesign::superblob::build_requirements_blob())
        .unwrap().designated().is_none());
}

#[test]
fn unsupported_opcode_is_not_a_hard_error() {
    // opCertField(11): a zero-flag opcode OUTSIDE the supported set. The whole DR
    // becomes Unsupported (operands never inspected) — never a hard error, because
    // Apple's DRs carry cert-chain ops whose chain DER crypto/cms_verify.rs does
    // not expose (out of scope).
    let mut expr = 11u32.to_be_bytes().to_vec();
    expr.extend_from_slice(&[0u8; 16]); // junk operands — must NOT be parsed
    let set = parse_requirements(&req_blob_with_dr(&expr)).unwrap();
    let v = set.designated().expect("dr present").evaluate(&RequirementContext {
        identifier: Some("com.example"), cdhashes: &[], anchored: None });
    assert!(matches!(v, RequirementVerdict::Unsupported(_)), "{v:?}");
}

#[test]
fn malformed_requirements_are_errors() {
    assert!(parse_requirements(&[0; 8]).is_err());           // too short
    assert!(parse_requirements(&kind_lwcr_blob()).is_err());  // kind = lwcrForm(2)
    assert!(parse_requirements(&truncated_expr_blob()).is_err()); // operand overrun
}
```

Enum: `#[derive(Debug, Clone, PartialEq, Eq)] pub enum RequirementVerdict {
Satisfied, Violated, Unsupported(String) }`. Evaluator semantics (design §8): trees
are fully-supported-only (an unsupported opcode anywhere makes the WHOLE requirement
`Unsupported` at parse time — no mixed trees exist); within a tree Kleene `T/F/U`
applies: `opAnd`/`opOr` binary; `opNot` negates `T/F`, preserves `U`; `opIdent` →
`T/F` (`ctx.identifier == None` → `U`); `opCDHash` → `T` if operand equals ANY
emitted CD's truncated (`min(len,20)`, own hashType) digest, else `F`;
`opAppleAnchor`/`opAppleGenericAnchor` → `ctx.anchored` (`Some(b)` → b, `None` → `U`).

macho/verify.rs e2e — its test module needs its own 20-line copy of the ident-DR
builder (test modules cannot share private items) plus the superblob rebuild helper:

```rust
fn ident_dr_blob(name: &str) -> Vec<u8> {
    let mut expr = 2u32.to_be_bytes().to_vec(); // opIdent
    expr.extend_from_slice(&(name.len() as u32).to_be_bytes());
    expr.extend_from_slice(name.as_bytes());
    while expr.len() % 4 != 0 { expr.push(0); }
    let child_len = 12 + expr.len();
    let total = 0x14 + child_len;
    let mut b = Vec::with_capacity(total);
    b.extend_from_slice(&CSMAGIC_REQUIREMENTS.to_be_bytes());
    b.extend_from_slice(&(total as u32).to_be_bytes());
    b.extend_from_slice(&1u32.to_be_bytes());
    b.extend_from_slice(&3u32.to_be_bytes()); // CSREQ_DESIGNATED
    b.extend_from_slice(&0x14u32.to_be_bytes());
    b.extend_from_slice(&CSMAGIC_REQUIREMENT.to_be_bytes());
    b.extend_from_slice(&(child_len as u32).to_be_bytes());
    b.extend_from_slice(&1u32.to_be_bytes()); // exprForm
    b.extend_from_slice(&expr);
    b
}

/// Replace the requirements child of `signed`'s SuperBlob with `new_child`
/// (shifting later children, fixing declared length + index offsets), then
/// rebind stored special slot -2 in BOTH CDs to the new child.
fn replace_requirements_child(signed: &mut [u8], new_child: &[u8]) {
    let m = MachOFile::parse(signed.to_vec()).unwrap();
    let sl = &m.slices()[0];
    let sig_off = sl.code_sig_offset.unwrap() as usize;
    let sig_len = sl.code_sig_size.unwrap() as usize;
    let sb = &signed[sig_off..sig_off + sig_len];
    let declared = u32::from_be_bytes(sb[4..8].try_into().unwrap()) as usize;
    let count = u32::from_be_bytes(sb[8..12].try_into().unwrap()) as usize;
    let index_end = 12 + count * 8;
    let mut entries: Vec<(u32, usize, usize)> = Vec::with_capacity(count);
    for i in 0..count {
        let e = 12 + i * 8;
        let slot = u32::from_be_bytes(sb[e..e + 4].try_into().unwrap());
        let off = u32::from_be_bytes(sb[e + 4..e + 8].try_into().unwrap()) as usize;
        let len = u32::from_be_bytes(sb[off + 4..off + 8].try_into().unwrap()) as usize;
        entries.push((slot, off, len));
    }
    let (req_off, req_len) = entries.iter()
        .find(|(s, _, _)| *s == CSSLOT_REQUIREMENTS)
        .map(|(_, o, l)| (*o, *l)).expect("requirements child");
    let delta = new_child.len() as isize - req_len as isize;
    assert!(declared as isize + delta <= sig_len as isize,
        "LC window slack too small for the DR blob");
    entries.sort_by_key(|(_, off, _)| *off);
    let mut out: Vec<u8> = Vec::with_capacity((declared as isize + delta) as usize);
    out.extend_from_slice(&sb[0..index_end]); // header (length fixed below) + index
    let mut new_off = std::collections::HashMap::new();
    for (slot, off, len) in &entries {
        new_off.insert(*slot, out.len());
        if *off == req_off { out.extend_from_slice(new_child); }
        else { out.extend_from_slice(&sb[*off..*off + *len]); }
    }
    let new_declared = out.len() as u32;
    out[4..8].copy_from_slice(&new_declared.to_be_bytes());
    for i in 0..count {
        let e = 12 + i * 8;
        let slot = u32::from_be_bytes(out[e..e + 4].try_into().unwrap());
        let off = new_off[&slot] as u32;
        out[e + 4..e + 8].copy_from_slice(&off.to_be_bytes());
    }
    signed[sig_off..sig_off + out.len()].copy_from_slice(&out);
    bind_special_slot(signed, 2, Some(new_child)); // task 5 helper
}

#[test]
fn designated_requirement_is_enforced_end_to_end() {
    let macho = MachOFile::parse(make_minimal_macho()).unwrap();
    // Satisfied: DR demanding this fixture's own identifier → no DR finding.
    let mut ok_signed = sign_macho_adhoc(&macho, "com.example.dr", None, None, None, false).unwrap();
    replace_requirements_child(&mut ok_signed, &ident_dr_blob("com.example.dr"));
    let ok_report = verify_macho(&ok_signed, &SignatureInputs::none()).unwrap();
    assert!(ok_report.is_valid(),
        "satisfied DR must verify: {:?}", ok_report.slices[0].errors);
    // Violated: DR demanding a different identifier → hard error.
    let mut bad_signed = sign_macho_adhoc(&macho, "com.example.dr", None, None, None, false).unwrap();
    replace_requirements_child(&mut bad_signed, &ident_dr_blob("com.evil"));
    let report = verify_macho(&bad_signed, &SignatureInputs::none()).unwrap();
    assert!(report.slices[0].errors.iter()
        .any(|e| e.contains("designated requirement not satisfied")),
        "errors: {:?}", report.slices[0].errors);
}
```

(Add `CSMAGIC_REQUIREMENTS`, `CSMAGIC_REQUIREMENT`, `CSSLOT_REQUIREMENTS` to the
macho test imports if absent. The writer reserves the LC window larger than the
SuperBlob — see `parse_superblob` docs — and `replace_requirements_child` asserts the
slack exists; identifier strings ≤ 16 bytes keep the growth ~50 bytes.)

- [ ] **Step 2: Confirm failure** — units fail to compile / FAIL; e2e FAILS (no
evaluation exists).

- [ ] **Step 3: Implement**

Public surface in `codesign/verify.rs` (all `pub`):

```rust
pub struct RequirementsSet<'a> {
    entries: Vec<(u32, Requirement<'a>)>, // u32 = index type; CSREQ_DESIGNATED among them
}
impl RequirementsSet<'_> {
    pub fn designated(&self) -> Option<&Requirement<'_>>;
}
pub struct Requirement<'a> {
    expr: Expr,               // fully-supported expression tree (never mixed Unsupported)
    raw: &'a [u8],            // the requirement child payload, for diagnostics
}
pub enum RequirementVerdict { Satisfied, Violated, Unsupported(String) }
pub struct RequirementContext<'a> {
    pub identifier: Option<&'a str>,
    pub cdhashes: &'a [&'a [u8]],   // truncated digests of every emitted CD
    pub anchored: Option<bool>,     // None = no CMS (ad-hoc) or unknown
}
impl Requirement<'_> { pub fn evaluate(&self, ctx: &RequirementContext<'_>) -> RequirementVerdict; }
pub fn parse_requirements(blob: &[u8]) -> Result<RequirementsSet<'_>>;
```

(`Expr` is the private tree enum: `True | False | Ident(Vec<u8>) | AppleAnchor |
AppleGenericAnchor | Not(Box<Expr>) | And(Box<Expr>, Box<Expr>) | Or(Box<Expr>,
Box<Expr>) | CdHash(Vec<u8>) | Unsupported(String)`. The parser stores
`Unsupported(reason)` — the opcode number/flags that stopped it — as the WHOLE tree
at the first out-of-set opcode (it never builds a mixed tree), and
`Requirement::evaluate` maps `Expr::Unsupported(reason)` to
 `RequirementVerdict::Unsupported(reason)`; every other variant evaluates per the
Kleene rules below.)

Parser details — **one grammar rule (design §8), no contradictions**: SuperBlob
`magic == CSMAGIC_REQUIREMENTS`, `count` bounded by the declared length (read from the
child's own `blob[4..8]` — `parse_requirements` receives the FULL `SlotEntry::blob`
and bounds itself; it does NOT use `payload()`), index entries `{type u32, offset
u32}`; child at `offset` must be `CSMAGIC_REQUIREMENT` with `kind == 1`
(`lwcrForm` 2 → `Err`). The expression parser fully supports ONLY
`opFalse(0), opTrue(1), opIdent(2), opAppleAnchor(3), opAnd(6), opOr(7), opCDHash(8),
opNot(9), opAppleGenericAnchor(15)` with operand layouts: `opIdent`/`opCDHash` = `u32
len` + bytes, consumed = `4 + align4(len)`; `opAnd`/`opOr` = left subtree then right
subtree; `opNot` = one subtree; anchors/true/false = no operand; next opcode always
4-aligned. **Any other opcode — known-but-unsupported (e.g. `opCertField(11)`),
unknown, or flag-bearing (`0x80000000`/`0x40000000`) — stops parsing and marks the
WHOLE requirement `Unsupported`**; operands are never inspected (the child's declared
length bounds everything, so stopping is safe). Structural failure *within the
supported grammar* (operand runs past the child's declared end; bad magic; `kind !=
1`; count/offset extent errors; recursion depth > 64) → `Err`. `count == 0` → empty
set (`designated()` → `None` → pass). Only fully-supported trees ever reach the
evaluator, so `RequirementVerdict::Unsupported` is produced solely by this parse-time
marker.

`verify_slice` control flow — **the empty-wrapper guard is preserved by branching,
not early-returning**. Explicit edits to the CMS block:
1. In the empty-wrapper branch, DELETE the `return Ok(report);` — the branch keeps
   setting `report.cms` (or pushing the non-ad-hoc error) and falls out of the
   `if let Some(cms_blob)` block.
2. The non-empty path already branches without returning (task 1's
   `match cd_sha256_opt { … }`) — no change.
3. After the ENTIRE chain — including the `else if adhoc` and `else` (no CMS slot but
   not ad-hoc flagged) arms — place the designated-requirement block below.
Invariant: `verify_code_signature` is called only for non-empty wrappers, and no path
returns early from `verify_slice` between `primary` being established and the end of
the function.

```rust
// Designated requirement (AFTER the whole chain; `cds` from task 1):
if let Some(req) = superblob.entries.iter().find(|e| e.slot == CSSLOT_REQUIREMENTS) {
    match parse_requirements(req.blob) {
        Err(e) => report.errors.push(format!("malformed requirements blob: {e}")),
        Ok(set) => if let Some(dr) = set.designated() {
            let cdhashes: Vec<Vec<u8>> = cds.iter().map(|cd| {
                let d: Vec<u8> = match cd.hash_type {
                    1 => Sha1::digest(cd.raw()).to_vec(),
                    _ => Sha256::digest(cd.raw()).to_vec(),
                };
                d[..d.len().min(20)].to_vec()
            }).collect();
            let refs: Vec<&[u8]> = cdhashes.iter().map(|v| v.as_slice()).collect();
            let anchored = report.cms.as_ref()
                .filter(|c| !c.no_signature).map(|c| c.anchored);
            let ctx = RequirementContext {
                identifier: primary.identifier(), cdhashes: &refs, anchored };
            match dr.evaluate(&ctx) {
                RequirementVerdict::Violated => report.errors.push(
                    "designated requirement not satisfied".to_string()),
                RequirementVerdict::Unsupported(why) => report.warnings.push(format!(
                    "designated requirement not fully evaluated: {why}")),
                RequirementVerdict::Satisfied => {}
            }
        },
    }
}
```

- [ ] **Step 4: Green + migration check** — scoped gate → `80 passed; 0 failed`
  (75 + 5 new);
  `cargo check -p zsign-rs -p zsign-cli --all-targets` → OK.

- [ ] **Step 5: Commit** — `feat(verify): parse and evaluate the designated requirement`

---

### Task 9: CodeDirectory version handling (queue item 9)

**Files:**
- Modify: `crates/zsign-core/src/codesign/verify.rs` — `CodeDirectory::parse`,
  `check_code_pages`, `cdhash()` binding, tests.
- Modify: `crates/zsign-core/src/codesign/constants.rs` — revalue
  `CODEDIRECTORY_VERSION_RUNTIME` (`0x20600 → 0x20500`) and
  `CODEDIRECTORY_VERSION_LINKAGE` (`0x20700 → 0x20600`) with corrected doc comments
  (both are zero-consumer today; task 9 adopts them).

- [ ] **Step 1: Failing tests first** (Tester) — codesign/verify.rs:

```rust
/// Minimal CodeDirectory: 44-byte base header + version-gated tail + ident "x",
/// no special/code slots. `tail` occupies bytes [44, 44+len) — exactly where the
/// version-gated fields live — so each version's blob is EXACTLY its header size
/// plus ident, making the header-size check the discriminator.
fn synth_cd(version: u32, tail: &[u8]) -> Vec<u8> {
    let ident = b"x\0";
    let hash_offset = 44 + tail.len() + ident.len();
    let mut cd = vec![0u8; hash_offset];
    cd[0..4].copy_from_slice(&CSMAGIC_CODEDIRECTORY.to_be_bytes());
    cd[4..8].copy_from_slice(&(hash_offset as u32).to_be_bytes());
    cd[8..12].copy_from_slice(&version.to_be_bytes());
    cd[16..20].copy_from_slice(&(hash_offset as u32).to_be_bytes()); // hashOffset
    cd[20..24].copy_from_slice(&((44 + tail.len()) as u32).to_be_bytes()); // identOffset
    cd[36] = 32; // hashSize
    cd[37] = CS_HASHTYPE_SHA256;
    cd[39] = 12; // pageSize log2
    cd[44..44 + tail.len()].copy_from_slice(tail);
    cd[44 + tail.len()..].copy_from_slice(ident);
    cd
}

#[test]
fn version_header_sizes_are_correct() {
    // header sizes: 44/48/52/64/88/96/108 at gates 0x20001..0x20600
    for (version, tail_len) in [
        (0x20001u32, 0usize), (0x20100, 4), (0x20200, 8), (0x20300, 20),
        (0x20400, 44), (0x20500, 52), (0x20600, 64),
    ] {
        let cd = synth_cd(version, &vec![0u8; tail_len]);
        assert!(CodeDirectory::parse(&cd).is_ok(),
            "version 0x{version:05x} (tail {tail_len}) must parse");
    }
    let too_new = synth_cd(0x20601, &vec![0u8; 64]);
    let err = CodeDirectory::parse(&too_new).unwrap_err();
    assert!(err.to_string().contains("unsupported CodeDirectory version"), "{err}");
}

#[test]
fn scatter_is_rejected() {
    let mut tail = vec![0u8; 4];
    tail[3] = 4; // scatterOffset @44 = 4 (nonzero)
    let err = CodeDirectory::parse(&synth_cd(0x20100, &tail)).unwrap_err();
    assert!(err.to_string().contains("scatter"), "{err}");
}

#[test]
fn preencrypted_hashes_are_rejected() {
    let mut tail = vec![0u8; 52]; // 0x20500: runtime@88 = tail[44..48], preEncrypt@92 = tail[48..52]
    tail[48..52].copy_from_slice(&0x100u32.to_be_bytes());
    let err = CodeDirectory::parse(&synth_cd(0x20500, &tail)).unwrap_err();
    assert!(err.to_string().contains("pre-encrypted"), "{err}");
}

#[test]
fn runtime_without_flag_is_rejected() {
    let mut tail = vec![0u8; 52];
    tail[44..48].copy_from_slice(&0x0D_0000u32.to_be_bytes()); // runtime, flags = 0
    let err = CodeDirectory::parse(&synth_cd(0x20500, &tail)).unwrap_err();
    assert!(err.to_string().contains("CS_RUNTIME"), "{err}");
}

#[test]
fn code_limit_64_drives_page_check() {
    // 0x20300 tail: scatter4 + team4 + spare3 4 + codeLimit64 8 = 20 bytes;
    // codeLimit64 @56 = tail[12..20].
    let mut tail = vec![0u8; 20];
    tail[12..20].copy_from_slice(&0x1000_0000u64.to_be_bytes());
    let mut cd = synth_cd(0x20300, &tail);
    cd[32..36].copy_from_slice(&32u32.to_be_bytes()); // codeLimit = 32 (u32)
    cd[28..32].copy_from_slice(&1u32.to_be_bytes());  // nCodeSlots = 1
    cd.resize(cd.len() + 32, 0);                      // room for the one code hash
    let new_len = cd.len() as u32;
    cd[4..8].copy_from_slice(&new_len.to_be_bytes()); // keep declared length honest
    let parsed = CodeDirectory::parse(&cd).unwrap();
    // Without honoring codeLimit64 the region (32 bytes) is one page → Matched.
    // With it, codeLimit64 (256 MiB) overruns any real region → guard fires.
    assert_eq!(check_code_pages(&parsed, &[0u8; 4096]),
        PageCheck::CountMismatch { stored: 1, computed: 1 });
}

#[test]
fn linkage_fields_are_bounds_checked() {
    // 0x20600 tail[52..64) = u8 hashType, u8 appType, u16 appSub, u32 offset, u32 size
    let mut t = vec![0u8; 64];
    t[56..60].copy_from_slice(&200u32.to_be_bytes()); // offset 200 + 20 > declared
    t[60..64].copy_from_slice(&20u32.to_be_bytes());
    assert!(CodeDirectory::parse(&synth_cd(0x20600, &t)).is_err());

    let mut t2 = vec![0u8; 64];
    t2[56..60].copy_from_slice(&40u32.to_be_bytes()); // 40 + 20 <= declared (110)
    t2[60..64].copy_from_slice(&20u32.to_be_bytes());
    assert!(CodeDirectory::parse(&synth_cd(0x20600, &t2)).is_ok());

    let mut t3 = vec![0u8; 64];
    t3[60..64].copy_from_slice(&7u32.to_be_bytes()); // size must be 0 or 20
    assert!(CodeDirectory::parse(&synth_cd(0x20600, &t3)).is_err());

    // u32::MAX offset must NOT overflow the bounds arithmetic (debug panic /
    // release wrap) — it is simply out of range:
    let mut t4 = vec![0u8; 64];
    t4[56..60].copy_from_slice(&u32::MAX.to_be_bytes());
    t4[60..64].copy_from_slice(&20u32.to_be_bytes());
    assert!(CodeDirectory::parse(&synth_cd(0x20600, &t4)).is_err());
}

#[test]
fn cdhash_binds_declared_length() {
    let mut cd = synth_cd(0x20400, &[0u8; 44]);
    let declared = cd.len();
    cd.extend_from_slice(&[0xAA; 64]); // trailing bytes beyond the declared length
    let parsed = CodeDirectory::parse(&cd).unwrap();
    assert_eq!(parsed.data.len(), declared);
    let expected: [u8; 32] = Sha256::digest(&cd[..declared]).into();
    assert_eq!(parsed.cdhash_sha256(), expected);
}
```

- [ ] **Step 2: Confirm failure** — several FAIL (0x20001/0x20100/0x20200/0x20300 too
  short for the wrong table entries, 0x20601 accepted for lack of an upper gate,
  scatter/preEncrypt/codeLimit64/linkage unenforced, trailing bytes hashed).

- [ ] **Step 3: Implement**

Replace the header-size `if/else` chain with the bucket table:

```rust
let header_size = if version >= CODEDIRECTORY_VERSION_LINKAGE { 108 }
    else if version >= CODEDIRECTORY_VERSION_PREENCRYPT { 96 }   // 0x20500 (gates runtime+preEncrypt)
    else if version >= CODEDIRECTORY_VERSION_EXECSEG { 88 }
    else if version >= CODEDIRECTORY_VERSION_CODELIMIT64 { 64 }
    else if version >= CODEDIRECTORY_VERSION_TEAMID { 52 }
    else if version >= CODEDIRECTORY_VERSION_SCATTER { 48 }
    else { 44 };
// upper gate, BEFORE the size check:
if version > CODEDIRECTORY_VERSION_LINKAGE {
    return Err(Verification(format!("unsupported CodeDirectory version 0x{version:08x} (newer than 0x20600)")));
}
```

Binding `data` to the declared length (right after the magic check, before the version
gates): `let declared = u32::from_be_bytes(blob[4..8]) as usize;` → `declared <
header_size || declared > blob.len()` → `Err`; then read all subsequent fields from
`&blob[..declared]`.

Gated reads (add `rd_u64`): `≥0x20100` `scatter_offset @44` (≠0 →
`Err("scatter CodeDirectories are not supported")`); `≥0x20300` `code_limit64 @56`
(private field + `pub fn effective_code_limit(&self) -> u64`:
`if self.version >= CODEDIRECTORY_VERSION_CODELIMIT64 && self.code_limit64 != 0
{ self.code_limit64 } else { self.code_limit as u64 }`);
`≥0x20500` `runtime @88` (pub field; ≠0 && `flags & CS_RUNTIME == 0` →
`Err("runtime version recorded without the CS_RUNTIME flag")`) and
`pre_encrypt_offset @92` (private; ≠0 → `Err("pre-encrypted CodeDirectory hashes are not supported")`);
`≥0x20600` linkage quintet `@96..108` (private; `linkage_size == 0` ok;
`== 20 && (linkage_offset as u64) + 20 <= declared as u64` ok — u64 comparison so
`linkage_offset == u32::MAX` cannot overflow; else `Err`).

`check_code_pages`: honor `effective_code_limit()` with ALL arithmetic in `u64`
FIRST — `usize` casts only after the value is proven to fit (post-adjudication
reviewer findings: on 32-bit targets such as `wasm32`, `u64 as usize` truncates
values ≥ 4 GiB and can route around the oversize guard):

```rust
let limit: u64 = cd.effective_code_limit();
let code_len = code.len() as u64;
let region_len_u64 = limit.min(code_len);
if limit > code_len {
    // proven: region_len_u64 == code_len <= usize::MAX, so this cast is safe
    return PageCheck::CountMismatch {
        stored: cd.n_code_slots as usize,
        computed: region_len_u64.div_ceil(page_size as u64) as usize,
    };
}
let region_len = region_len_u64 as usize; // safe: <= code.len()
```

(equivalent alternative: `usize::try_from(limit).unwrap_or(usize::MAX)` before the
existing logic — either is acceptable, the invariant is "no `u64 → usize` cast before
the comparison that the guard relies on".) The linkage bounds check gets the same
treatment (u32 overflow): replace `linkage_offset + 20 <= declared` with
`(linkage_offset as u64) + 20 <= declared as u64` (or
`usize::try_from(linkage_offset).ok().and_then(|o| o.checked_add(20)).is_some_and(|end| end <= declared)`)
so `linkage_offset == u32::MAX` cannot panic in debug or wrap in release.
`check_code_pages_in_file` (macho) inherits this through `check_code_pages`.

Update the constants (this task): `CODEDIRECTORY_VERSION_RUNTIME = 0x20500` and
`CODEDIRECTORY_VERSION_LINKAGE = 0x20600`, doc comments fixed to the librarian's
`CS_SUPPORTSRUNTIME`/`CS_SUPPORTSLINKAGE` facts; `CODEDIRECTORY_VERSION_PREENCRYPT`
keeps `0x20500` with a comment that `supportsPreEncrypt` gates *both* runtime and
preEncryptOffset. Note: `CODEDIRECTORY_VERSION_LINKAGE` is now the table's top bucket —
its old `0x20700` value exists in no authoritative source.

- [ ] **Step 4: Green** — scoped gate → `87 passed; 0 failed` (80 + 7 new; baseline
  fixtures all emit `0x20400` with zeroed gated fields → unchanged).

- [ ] **Step 5: Commit** — `fix(verify): honor codedirectory version layout and code limit64`

---

### Task 10: Constants completion (queue item 10)

**Files:**
- Modify: `crates/zsign-core/src/codesign/constants.rs`
- Modify: `crates/zsign-core/src/codesign/verify.rs` — adopt the three new constants
  (old-magic diagnostic, constraint-slot magic table entry).
- Modify: `crates/zsign-core/src/macho/verify.rs` — swap the task-3/6 numeric
  literals for the new constants (`SUPERBLOB_SLOTS` −8..−11 entries; the task-6 test's
  `0xfade8181u32` literal → `CSMAGIC_LAUNCH_CONSTRAINT`).

- [ ] **Step 1: Failing tests first** (Tester)

```rust
// constants.rs tests
#[test]
fn ticket_slot_is_the_notarization_slot() {
    assert_eq!(CSSLOT_TICKETSLOT, 0x10002); // Apple blob.h: 0x10001 is the cd-identification slot
}
#[test]
fn version_gate_values_match_apple() {
    assert_eq!(CODEDIRECTORY_VERSION_SCATTER, 0x20100);
    assert_eq!(CODEDIRECTORY_VERSION_TEAMID, 0x20200);
    assert_eq!(CODEDIRECTORY_VERSION_CODELIMIT64, 0x20300);
    assert_eq!(CODEDIRECTORY_VERSION_EXECSEG, 0x20400);
    assert_eq!(CODEDIRECTORY_VERSION_RUNTIME, 0x20500);
    assert_eq!(CODEDIRECTORY_VERSION_LINKAGE, 0x20600);
    assert_eq!(CODEDIRECTORY_VERSION, 0x20400); // unchanged alias target
}

// codesign/verify.rs tests
#[test]
fn old_embedded_signature_magic_is_diagnosed() {
    let mut b = build_blob(true);
    b[0..4].copy_from_slice(&CSMAGIC_EMBEDDED_SIGNATURE_OLD.to_be_bytes());
    let err = parse_superblob(&b).unwrap_err();
    assert!(err.to_string().contains("old embedded signature"), "{err}");
}

#[test]
fn launch_constraint_slot_magic_is_validated() {
    // child at slot 0x0008 with the WRONG magic → parse error after this task
    let child = [0u32.to_be_bytes(), 12u32.to_be_bytes(), [0u8; 4]].concat();
    let total = (12 + 8 + child.len()) as u32;
    let mut b = synth_superblob(total, &[(CSSLOT_LAUNCH_CONSTRAINT_SELF, 20)]);
    b[20..20 + child.len()].copy_from_slice(&child);
    assert!(parse_superblob(&b).is_err(), "wrong constraint magic must be rejected");
    // …and the correct magic parses (routing ignores it until a CD binds -8):
    let mut ok = synth_superblob(total, &[(CSSLOT_LAUNCH_CONSTRAINT_SELF, 20)]);
    let good: Vec<u8> = [CSMAGIC_LAUNCH_CONSTRAINT.to_be_bytes(),
                         12u32.to_be_bytes(), [0u8; 4]].concat();
    ok[20..20 + good.len()].copy_from_slice(&good);
    assert!(parse_superblob(&ok).is_ok(), "0xfade8181 child must parse");
}
```

- [ ] **Step 2: Confirm failure** — `ticket_slot_is_the_notarization_slot` FAILS
  (0x10001);
`old_embedded_signature_magic_is_diagnosed` and
`launch_constraint_slot_magic_is_validated` FAIL (constants/arms absent);
`version_gate_values_match_apple` FAILS on RUNTIME/LINKAGE until task 9's revalue
(already landed — it is a guard here, not a trigger).

- [ ] **Step 3: Implement**

constants.rs:
- `pub const CSSLOT_TICKETSLOT: u32 = 0x10002;` (doc: ticket/notarization slot; note
  `0x10001` is the cd-identification slot used only by detached signatures — not added
  as a constant, no consumer).
- `pub const CSMAGIC_EMBEDDED_SIGNATURE_OLD: u32 = 0xfade0b02;` (doc: legacy embedded
  signature magic; value from Apple's headers, purpose undocumented there —
  diagnostic use only).
- `pub const CSMAGIC_LAUNCH_CONSTRAINT: u32 = 0xfade8181;` (doc: one magic for all four
  launch-constraint blobs).
- `pub const CSSLOT_SPECIAL_LAUNCH_CONSTRAINT_SELF: i32 = -8;`
- `pub const CSSLOT_SPECIAL_LAUNCH_CONSTRAINT_PARENT: i32 = -9;`
- `pub const CSSLOT_SPECIAL_LAUNCH_CONSTRAINT_RESPONSIBLE: i32 = -10;`
- `pub const CSSLOT_SPECIAL_LIBRARY_CONSTRAINT: i32 = -11;`
- Doc-header pass: fix any comment still claiming `CSSLOT_TICKETSLOT = 0x10001` or the
  old gate values; mention the launch-constraint magic and slots −8..−11 in the module
  docs where slot types are listed.

codesign/verify.rs adoptions:
- `parse_superblob` top-magic check: before the generic failure, `if blob[0..4] ==
  CSMAGIC_EMBEDDED_SIGNATURE_OLD.to_be_bytes()` →
  `Err("old embedded signature format (magic 0xfade0b02) is not supported")`.
- `expected_magic`: add
  `CSSLOT_LAUNCH_CONSTRAINT_SELF..=CSSLOT_LIBRARY_CONSTRAINT => CSMAGIC_LAUNCH_CONSTRAINT`
  (slots `0x0008..=0x000b` — positive `u32` constants — join the `seen` duplicate set
  automatically).
- `check_special_slots` content map: replace task 6's arm `8 => slot_child(CSSLOT_LAUNCH_CONSTRAINT_SELF)`
  etc. (already the positive constants — verify all four are, no change expected) and,
  in `macho/verify.rs`, replace the task-3 literals: the `REQUIRED_SPECIAL_SLOTS`
  array becomes

```rust
const REQUIRED_SPECIAL_SLOTS: [i32; 9] = [
    CSSLOT_SPECIAL_INFOSLOT, CSSLOT_SPECIAL_REQUIREMENTS, CSSLOT_SPECIAL_RESOURCEDIR,
    CSSLOT_SPECIAL_ENTITLEMENTS, CSSLOT_SPECIAL_DER_ENTITLEMENTS,
    CSSLOT_SPECIAL_LAUNCH_CONSTRAINT_SELF, CSSLOT_SPECIAL_LAUNCH_CONSTRAINT_PARENT,
    CSSLOT_SPECIAL_LAUNCH_CONSTRAINT_RESPONSIBLE, CSSLOT_SPECIAL_LIBRARY_CONSTRAINT,
];
```

  keeping `REQUIRED_SPECIAL_SLOTS.contains(&-(k as i32))` (k is the positive 1-based
  index; `-k` lands on the negative constants — valid i32 range −1..=−11, ascending
  constants irrelevant because `contains` on an array checks membership). Behavior
  identical to the numeric version.
- `macho/verify.rs` elevation: the task-3 `SUPERBLOB_SLOTS` array literals
  `-8, -9, -10, -11` become
  `CSSLOT_SPECIAL_LAUNCH_CONSTRAINT_SELF, CSSLOT_SPECIAL_LAUNCH_CONSTRAINT_PARENT,
  CSSLOT_SPECIAL_LAUNCH_CONSTRAINT_RESPONSIBLE, CSSLOT_SPECIAL_LIBRARY_CONSTRAINT`
  (membership via `contains(&-(k as i32))` — no offset arithmetic anywhere; the task-6
  content map already routes `8 => slot_child(CSSLOT_LAUNCH_CONSTRAINT_SELF)` etc.
  with direct positive-constant match arms and needs no change).
- `macho/verify.rs` task-6 test: swap its `0xfade8181u32` literal for
  `CSMAGIC_LAUNCH_CONSTRAINT`.

- [ ] **Step 4: Green + final migration** — scoped gate → `89 passed; 0 failed`
  (87 + 2 new) AND constants gate `TMPDIR=$PWD/.tmptmp cargo test -p zsign-core
  constants` → `7 passed` (5 baseline + 2 new);
  `cargo check -p zsign-rs -p zsign-cli --all-targets` → OK.

- [ ] **Step 5: Commit** — `fix(constants): correct ticket slot and version gates, add launch constraint magic`

---

### Task 11: Final verification

**Files:** none (verification only).

- [ ] **Step 1: Full scoped gates**

Run: `mkdir -p .tmptmp && TMPDIR=$PWD/.tmptmp cargo test -p zsign-core verify -- --skip test_ipa_signing_is_deterministic`
Expected: `89 passed; 0 failed` (54 baseline + 35 new across tasks 1-10; if the actual
number differs, report the drift rather than adjusting the expectation).
Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-core constants`
Expected: `7 passed; 0 failed`. Save both verbatim tails for the final report.

- [ ] **Step 2: Workspace compile (caller migration proof)**

Run: `TMPDIR=$PWD/.tmptmp cargo check --workspace --all-targets`
Expected: OK — proves `zsign`, `zsign-cli`, `zsign-wasm`, benches, and every test target
still compile against the changed core APIs (`check_special_slots` signature,
`self_consistent_blobs` deletion, new `CodeDirectory` fields, `SlotEntry::payload`).

- [ ] **Step 3: Diff hygiene**

Run: `git status --short && git log --oneline c9ff0fb..HEAD`
Expected: only the three scope files + the two force-added docs changed; 12-13 commits
(design+plan docs, tasks 1-10, none touching signer/crypto/zsign sources).

---

## Self-review record (round-2 revision)

- **Spec coverage:** queue items 1-10 ↔ tasks 1-10 one-to-one; task 11 covers the final
  gates; design-doc sections (frozen contracts, interop register, test strategy) are
  each owned by a task step. No queue item without a task.
- **Type consistency:** `check_special_slots(cd, inputs, superblob)` introduced in task 6
  and only there; `SlotEntry::payload()` introduced in task 5 and used by tasks 5/7;
  `der_entitlements_to_plist` name is identical in task 5's test and implementation;
  `effective_code_limit()` defined in task 9, consumed in task 9;
  `RequirementContext`/`RequirementVerdict` names identical between task 8 tests and
  implementation; `cdhash_pair`/`emitted_cds` defined in task 1, reused by tasks 1/8;
  constants names used in task 10 exist in no earlier task.
- **Placeholder scan:** every test helper is complete executable code (no `/* … */`,
  no undefined helpers): `synth_cd` (t9), `synth_cd_with_slot8` (t6),
  `req_blob_with_dr`/`ident_expr`/`kind_lwcr_blob`/`truncated_expr_blob` (t8 cv),
  `ident_dr_blob`/`replace_requirements_child` (t8 mv), `ENT_PLIST`/
  `adhoc_ent_fixture`/`child_off_in_signed`/`bind_special_slot`/
  `adhoc_with_patched_execseg` (t5/t7 mv). Per-task pass counts derive from each
  task's own test list and chain from the 54 baseline (gates section).
- **Cold-review round 1:** NOT-READY with 16 findings (13 logic-level, 3 doc-nit) —
  all applied before this revision: header-payload stripping, repo-actual DER tags
  (`0x70`/`0xb0`), generalized injected-anchor helper, preserved empty-CMS guard,
  single unsupported-opcode rule, interop cert-line recorded as pre-existing red,
  emitted-CD list hoisted, direct positive-constant mapping + membership-list
  elevation (no offset arithmetic anywhere), alternate `NotChecked`
  elevation, binding-gated DER rule, honest execSeg fallback with 4 KiB floor,
  task-2/task-6 fixtures immune to later-task magic checks, complete helper code,
  constants-filter command + corrected count chain, bare-signing n-slot correction,
  C-7 USED list inlined.
- **Post-adjudication amendments (this revision):** strongest-CD metadata with CMS
  content pinned to the primary (task 2 + design); context-gated −1/−3 elevation with
  unconditional SuperBlob-sourced slots (task 3 + design); `u64`-first
  `effective_code_limit` bounds and `u64` linkage comparison (task 9, post-adjudication
  reviewer findings); `Expr::Unsupported(String)` storage marker (task 8);
  `-p zsign-rs` package id everywhere; task-10 Files list includes
  `macho/verify.rs`; gate count chain recomputed (T3 +3 → 60 … final 89 + 2
  constants-filter).
- **Deviation handling:** any plan change discovered during implementation (e.g. a
  fixture whose pass-count differs, an existing test that must be adjusted) is recorded
  in the final report's plan-vs-actual section, per the brief.
