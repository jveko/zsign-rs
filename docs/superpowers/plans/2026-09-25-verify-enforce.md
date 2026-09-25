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
  parallel-lane load — `TMPDIR` is mandatory.
- Caller-migration check (after any task that changes a `pub` signature — tasks 1, 2, 5, 6):
  `TMPDIR=$PWD/.tmptmp cargo check -p zsign -p zsign-cli --all-targets`
- Final (task 11 only): scoped gate + `TMPDIR=$PWD/.tmptmp cargo check --workspace --all-targets`.
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

- [ ] **Step 2: Run and confirm failure**

Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-core dual_signing_binds_cdhash_pair`
Expected: FAIL — `slice.errors.len()` is 3 (v1/v2 mismatch messages).

- [ ] **Step 3: Implement type-based pair selection**

In `verify_slice` replace the `let cd_sha256 … let cd_sha1 = alternate_sha1(…)` block:
collect every emitted CD once (`std::iter::once(primary).chain(superblob.alternate_code_directories.iter())`),
then:

```rust
let cd_sha1: Option<[u8; 20]> = cds.iter()
    .find(|cd| cd.is_sha1())
    .map(|cd| Sha1::digest(cd.raw()).into());
let Some(cd_sha256) = cds.iter().find(|cd| cd.is_sha256()).map(|cd| Sha256::digest(cd.raw()).into::<[u8; 32]>().into())
else {
    report.errors.push(
        "CMS signature present but no SHA-256 CodeDirectory to bind CDHash v2".to_string(),
    );
    return Ok(report);
};
```
(adjust syntax to real Rust: `map(|cd| { let d: [u8;32] = Sha256::digest(cd.raw()).into(); d })`;
`content` stays `primary.raw()`). Call
`verify_code_signature(cms_blob, primary.raw(), cd_sha1.as_ref(), &cd_sha256)`.

Delete `fn alternate_sha1` entirely (its only caller is this site; its
"SHA-1 primary, no alternate" fallback has no emission counterpart).

- [ ] **Step 4: Green + migration check**

Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-core verify -- --skip test_ipa_signing_is_deterministic`
Expected: `55 passed; 0 failed` (54 baseline + 1 new).
Run: `TMPDIR=$PWD/.tmptmp cargo check -p zsign -p zsign-cli --all-targets` → OK.

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

```rust
#[test]
fn corrupt_alternate_cd_is_rejected_with_detail() {
    let macho = MachOFile::parse(make_minimal_macho()).unwrap();
    let signed = sign_macho_adhoc(&macho, "com.example.alt", None, None, None, false).unwrap();
    let mut blob = signed_superblob(&signed);
    // Corrupt the alternate CD (slot 0x1000): pre-fix the parse failure is dropped.
    let off = entry_offset(&blob, CSSLOT_ALTERNATE_CODEDIRECTORIES).unwrap();
    blob[off..off + 4].copy_from_slice(&0u32.to_be_bytes());
    let report = verify_macho(&signed[..], &SignatureInputs::none()); // see note
    // NOTE: patch `blob` back into `signed` at the signature region first (helper below).
    // ...
}
```

Implementation note for the Tester: patch bytes inside `signed` directly (locate the
signature region like `tampered_signature_bytes_fail_cms` does, then
`entry_offset(&signed[sig_off..sig_off+sig_len], 0x1000)`); assert
`!report.is_valid()` and
`report.slices[0].errors.iter().any(|e| e.contains("not a CodeDirectory blob"))`.

```rust
#[test]
fn tampered_alternate_page_hash_is_rejected() {
    // dual ad-hoc fixture; flip one byte of the alternate CD's stored code hash:
    // let cd = entry_offset(..., 0x1000) + sig_off;
    // let hash_offset = u32::from_be_bytes(signed[cd+16..cd+20]) as usize;
    // signed[cd + hash_offset] ^= 0xFF;
    assert!(errors.iter().any(|e| e.contains(
        "alternate SHA-256 code page 0 hash mismatch (code region modified?)")));
    assert_eq!(report.slices[0].pages, PageCheck::Matched); // primary untouched
}
```

- [ ] **Step 2: Confirm failure** — run both names, expect FAIL (parse detail absent;
  alternate never checked).

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

`verify_slice`:
- error site: `Err(e) => { report.errors.push(format!("embedded code signature is not a valid SuperBlob: {e}")); return Ok(report); }`
- pages: keep `report.pages = check_code_pages_in_file(primary, …)` and its existing
  four message arms verbatim; then for each alternate run `check_code_pages_in_file`
  and push failures as `alternate {SHA-1|SHA-256} ` + the same message texts
  (`code page {i} hash mismatch (code region modified?)`, `code slot count mismatch…`,
  `… covers zero code bytes` — reuse a small local closure `push_page_errors(label: &str, …)`
  so primary stays byte-identical with empty label).
- special slots: keep the primary flow writing `report.special_slots`; additionally run
  `check_special_slots(cd, inputs, req, ent, der)` for each alternate and push ONLY
  `Mismatch` findings as `alternate {type} special slot -{k} hash mismatch`
  (alternate `NotChecked`/`Missing` mirror the primary verdict — the two CDs bind
  identical inputs — and are deliberately not elevated here; elevation is task 3,
  primary vector only).

Label: `if cd.is_sha1() { "SHA-1" } else { "SHA-256" }`.

- [ ] **Step 4: Green + migration check** — scoped gate → `57 passed; 0 failed`;
  `cargo check -p zsign -p zsign-cli --all-targets` → OK.

- [ ] **Step 5: Commit** — `fix(verify): verify every emitted code directory and surface parse detail`

---

### Task 3: Elevate bound-but-unavailable special slots (queue item 3)

**Files:**
- Modify: `crates/zsign-core/src/macho/verify.rs` — special-slot loop
  (~lines 166-172), tests.

- [ ] **Step 1: Failing tests first** (Tester)

```rust
#[test]
fn bound_info_plist_without_input_is_an_error() {
    let info = b"<?xml version=\"1.0\"?><plist><dict><key>CFBundleIdentifier</key><string>com.example</string></dict></plist>";
    let macho = MachOFile::parse(make_minimal_macho()).unwrap();
    let signed = sign_macho_adhoc(&macho, "com.example", None, Some(info), None, false).unwrap();
    let report = verify_macho(&signed, &SignatureInputs::none()).unwrap();
    assert!(!report.is_valid());
    assert!(report.slices[0].errors.iter().any(|e| e
        .contains("special slot -1 is bound but its content was not supplied")));
    // With the real input the same binary has no slot finding:
    let ok = verify_macho(&signed, &SignatureInputs { info_plist: Some(info), code_resources: None }).unwrap();
    assert!(ok.slices[0].errors.is_empty(), "{:?}", ok.slices[0].errors);
}

#[test]
fn unbound_special_slots_stay_silent() {
    // ad-hoc, no info/resources/entitlements: slots -1/-3 zero-filled (not bound)
    let macho = MachOFile::parse(make_minimal_macho()).unwrap();
    let signed = sign_macho_adhoc(&macho, "com.example.bare", None, None, None, false).unwrap();
    let report = verify_macho(&signed, &SignatureInputs::none()).unwrap();
    assert!(report.is_valid(), "{:?}", report.slices[0].errors);
}
```

- [ ] **Step 2: Confirm failure** — first test FAILS (no elevation), second PASSES
  (keep it as the guard for the whitelist scoping).

- [ ] **Step 3: Implement elevation** — extend the existing loop over `slot_checks`
  (primary vector only):

```rust
for (i, check) in slot_checks.iter().enumerate() {
    let k = i + 1;
    match check {
        SpecialSlotCheck::Mismatch => report
            .errors
            .push(format!("special slot -{k} hash mismatch")),
        SpecialSlotCheck::NotChecked
            if matches!(k, 1 | 2 | 3 | 5 | 7 | 8 | 9 | 10 | 11) =>
        {
            report.errors.push(format!(
                "special slot -{k} is bound but its content was not supplied"
            ));
        }
        _ => {}
    }
}
```

(`-4`/`-6` and `k ≥ 12` stay non-fatal — design §special-slot content map: never in the
brief's required list; blanketing them risks the interop gate.) Keep the loop
structure from task 2 intact.

- [ ] **Step 4: Green** — scoped gate → `58 passed; 0 failed`. No pub signature
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
    let off = /* child offset of the requirements slot (0x0002) */;
    b[off..off + 4].copy_from_slice(&0u32.to_be_bytes());
    assert!(parse_superblob(&b).is_err());
}

#[test]
fn distinct_duplicate_slot_is_rejected() {
    // synth_superblob with TWO different children both claiming slot 0x0002:
    // today: last-wins Ok; post-fix: Err.
    let mut b = synth_superblob(60, &[(2, 28), (2, 44)]);
    // child A at 28: magic 0xfade0c01, len 16; child B at 44: magic 0xfade0c01, len 16
    assert!(parse_superblob(&b).is_err());
}

#[test]
fn duplicate_code_directory_slot_is_rejected() {
    // two distinct children both claiming slot 0x0000 (valid CD magic each)
    // today: second silently ignored; post-fix: Err.
}
```

For `duplicate_code_directory_slot_is_rejected` build child A as a real
`CodeDirectoryBuilder::build_sha256()` and child B as a second, different-length CD
(valid magic+length), both indexed under slot 0.

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
table yet (their magic arrives with task 10).

Compatibility pin: the truncated-CMS fixture keeps an 8-byte child with intact
`CSMAGIC_BLOBWRAPPER` magic → passes the table; the `empty CMS wrapper` rule still
fires (design R5).

- [ ] **Step 4: Green** — scoped gate → `61 passed; 0 failed`.

- [ ] **Step 5: Commit** — `fix(verify): validate slot blob magics and reject duplicate slots`

---

### Task 5: XML vs DER entitlements comparison + DER requirement (queue item 5)

**Files:**
- Modify: `crates/zsign-core/src/codesign/verify.rs` — add
  `pub(crate) fn der_entitlements_to_plist(der: &[u8]) -> Result<plist::Value>`, tests.
- Modify: `crates/zsign-core/src/macho/verify.rs` — `verify_slice` wiring, tests.

- [ ] **Step 1: Failing tests first** (Tester)

codesign/verify.rs units:

```rust
#[test]
fn der_entitlements_round_trip() {
    let xml = br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>com.example.flag</key><true/>
<key>com.example.count</key><integer>7</integer>
<key>com.example.name</key><string>demo</string>
</dict></plist>"#;
    let der = crate::codesign::der::plist_to_der(xml).unwrap();
    let decoded = der_entitlements_to_plist(&der).unwrap();
    let expected = plist::from_bytes::<plist::Value>(xml.as_slice()).unwrap();
    assert_eq!(decoded, expected);
}

#[test]
fn der_v1_envelope_parses() {
    // synth: [APPLICATION 16] { INTEGER 1, SET{ {UTF8String "k", UTF8String "v"} } }
    // encode by hand (tag 0x60 / 0x02 0x01 0x01 / 0x31 …) — ~15 lines
    let v = der_entitlements_to_plist(&bytes).unwrap();
    assert_eq!(v.as_dictionary().unwrap().get("k").unwrap().as_str(), Some("v"));
}

#[test]
fn der_malformed_is_error() {
    assert!(der_entitlements_to_plist(&[0x31, 0x02, 0xFF, 0xFF]).is_err());
}
```

macho/verify.rs e2e (adhoc + entitlements fixture — signer emits XML `-5` and DER `-7`
for executables):

```rust
#[test]
fn differing_xml_der_entitlements_are_rejected() {
    // fixture: sign_macho_adhoc(&macho, "com.example.ent", Some(ENT_PLIST), None, None, false)
    // 1) locate the DER child (slot 0x0007) and flip one byte inside its UTF-8 string
    //    value (same length → still valid DER, semantically different dict);
    // 2) recompute the stored -7 hashes in BOTH CDs and patch them
    //    (primary SHA-1: cd.hash_type at cd+37; hash at hashOffset - 7*hash_size;
    //     hashOffset raw at cd+16, hash_size raw at cd+36);
    let report = verify_macho(&signed, &SignatureInputs::none()).unwrap();
    assert!(report.slices[0].errors.iter()
        .any(|e| e.contains("XML and DER entitlements dictionaries differ")));
}

#[test]
fn missing_der_for_modern_main_executable_is_rejected() {
    // same fixture; rewrite the superblob INDEX entry type 0x0007 -> 0x0040 (unknown
    // slot, routing ignores it) and zero the -7 stored hashes in both CDs
    // (zero = "not bound" so task 3's slot-7 elevation stays silent),
    assert!(errors.iter().any(|e| e.contains(
        "XML entitlements bound (slot -5) without DER entitlements (slot -7)")));
}
```

- [ ] **Step 2: Confirm failure** — all FAIL (no decoder, no comparison).

- [ ] **Step 3: Implement**

`der_entitlements_to_plist` (codesign/verify.rs, ~120 lines, private helper +
`pub(crate)` wrapper):
- Top-level: if tag `0x60` (APPLICATION 16, constructed) → children = payload; require
  first child `INTEGER` (version, value ignored) then the dictionary container.
  Otherwise treat top-level as the dictionary container directly (v0).
- Dictionary container: accept tag `0x30 | 0x31 | 0x60 | 0xA0` (sources disagree —
  tag-agnostic walk); children are `SEQUENCE { UTF8String key, value }` pairs.
- Value CHOICE: `BOOLEAN` → `Boolean`, `INTEGER` → `Integer` (sign/length per DER),
  `UTF8String/IA5String` → `String`, `OCTET STRING` → `Data`, `GeneralizedTime/UTCTime`
  → `Date`, `SEQUENCE`/constructed `0x30` → `Array` of decoded values, nested dict tag
  → `Dictionary`, `NULL` → `Err` (plist has no null — fail closed). Any other tag →
  `Err`. Bounds: every length checked against remaining input; recursion depth capped
  (e.g. 32) → `Err`.
- Reuse `Result`/`Error::DerEncoding`-style error messages already present in
  `codesign/der.rs` (`Error::DerEncoding(String)`).

`verify_slice` wiring (after the special-slot loop, before CMS):

```rust
let slot_child = |slot: u32| superblob.entries.iter().find(|e| e.slot == slot)
    .map(|e| e.blob);
if let (Some(xml_blob), der_blob) = (slot_child(CSSLOT_ENTITLEMENTS), slot_child(CSSLOT_DER_ENTITLEMENTS)) {
    let xml_val = plist::from_bytes::<plist::Value>(xml_blob)
        .map_err(|e| /* report.errors.push(format!("XML entitlements do not parse: {e}")) */);
    match der_blob {
        Some(der) => match der_entitlements_to_plist(der) {
            Ok(der_val) if Some(&der_val) != xml_val.as_ref() => report.errors.push(
                "XML and DER entitlements dictionaries differ".to_string()),
            Err(e) => report.errors.push(format!("DER entitlements do not parse: {e}")),
            _ => {}
        },
        None => {
            let der_bound = primary.special_slot_hash(7)
                .map(|h| h.iter().any(|&b| b != 0)).unwrap_or(false);
            if slice.is_executable && !der_bound
                && primary.version >= CODEDIRECTORY_VERSION_EXECSEG
            {
                report.errors.push(
                    "XML entitlements bound (slot -5) without DER entitlements (slot -7)"
                        .to_string());
            }
        }
    }
}
```

Structural refinement for the implementer: keep it linear (no nested closure gymnastics);
`CODEDIRECTORY_VERSION_EXECSEG` is already in scope via the constants glob. Compare with
`plist::Value` equality (order-insensitive because `plist::Dictionary` is IndexMap-backed).

- [ ] **Step 4: Green + migration check** — scoped gate → `65 passed; 0 failed`;
  `cargo check -p zsign -p zsign-cli --all-targets` → OK (new `pub(crate)` item —
  verify nothing in `zsign` expected the old shape; `self_consistent_blobs` untouched).

- [ ] **Step 5: Commit** — `fix(verify): compare xml and der entitlements and require der for main executables`

---

### Task 6: Launch-constraint slots −8..−11 (queue item 6)

**Files:**
- Modify: `crates/zsign-core/src/codesign/verify.rs` — `check_special_slots` signature +
  content map; delete `self_consistent_blobs` and the `SlotBlobs` type alias.
- Modify: `crates/zsign-core/src/macho/verify.rs` — caller migration, tests.

- [ ] **Step 1: Failing tests first** (Tester)

codesign/verify.rs unit (against the new content lookup — write the test against
`check_special_slots`'s new signature so it fails to compile, then implement):

```rust
#[test]
fn launch_constraint_content_comes_from_superblob_slot_8() {
    // CD: CodeDirectoryBuilder… + raw patch n_special to 8 is awkward; instead build
    // the CD bytes with n_special = 8 via raw construction OR reuse a main+ent
    // builder CD (n = 7) and patch n_special (cd+24) to 8 with hash_offset large
    // enough (parse guard: n_special <= hash_offset/hash_size).
    let sb = synth_superblob(/* … */); // child at slot 0x0008: magic irrelevant pre-task10
    let checks = check_special_slots(&cd, &SignatureInputs::none(), &sb);
    assert_eq!(checks[7], SpecialSlotCheck::Matched); // slot -8 verified against 0x0008
}
```

macho/verify.rs e2e:

```rust
#[test]
fn bound_launch_constraint_without_blob_is_rejected() {
    let macho = MachOFile::parse(make_minimal_macho()).unwrap();
    let signed = sign_macho_adhoc(&macho, "com.example.lc", None, Some(ENT_PLIST), None, false).unwrap();
    // patch primary CD n_special (cd+24) 7 -> 8; the grown -8 window [hashOffset-256,
    // hashOffset-224) lands on header/ident bytes -> deterministically nonzero stored
    // hash; parse guard n_special(8) <= hash_offset/hash_size holds (window ≥ 10 slots)
    let report = verify_macho(&signed, &SignatureInputs::none()).unwrap();
    assert!(report.slices[0].errors.iter().any(|e| e
        .contains("special slot -8 is bound but its content was not supplied")));
}
```

- [ ] **Step 2: Confirm failure** (compile error on new signature counts as failing step).

- [ ] **Step 3: Implement**

New signature (sole caller `macho/verify.rs:163-164`):

```rust
pub fn check_special_slots(
    cd: &CodeDirectory<'_>,
    inputs: &SignatureInputs<'_>,
    superblob: &SuperBlob<'_>,
) -> Vec<SpecialSlotCheck>
```

Content mapping inside the `k` loop replaces the old `match k` arms:

```rust
let content: Option<&[u8]> = match k {
    1 => inputs.info_plist,                       // caller only (design: no superblob fallback)
    3 => inputs.code_resources,                   // caller only
    2 => slot_child(CSSLOT_REQUIREMENTS),
    5 => slot_child(CSSLOT_ENTITLEMENTS),
    7 => slot_child(CSSLOT_DER_ENTITLEMENTS),
    8..=11 => slot_child(CSSLOT_LAUNCH_CONSTRAINT_SELF + (k as u32 - 8)),
    4 | 6 => None,
    _ => None,
};
// where slot_child = |s| superblob.entries.iter().find(|e| e.slot == s).map(|e| e.blob)
```

Digest selection unchanged (`cd.hash_type` drives SHA-1/SHA-256). Delete
`self_consistent_blobs` + `SlotBlobs`; migrate `macho/verify.rs:163-164` to a single
`check_special_slots(primary, inputs, &superblob)` call. (Tasks 1-5 read entitlements
children directly from `superblob.entries`, so nothing else consumed the deleted items.)

- [ ] **Step 4: Green + migration check** — scoped gate → `66 passed; 0 failed`;
  `cargo check -p zsign -p zsign-cli --all-targets` → OK.

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
    let cd_bytes = /* CodeDirectoryBuilder … .exec_seg_base(0x1_0000_0000)
                      .exec_seg_limit(0x1000).exec_seg_flags(CS_EXECSEG_MAIN_BINARY) … */;
    let cd = CodeDirectory::parse(&cd_bytes).unwrap();
    assert_eq!(cd.exec_seg_base, 0x1_0000_0000);
    assert_eq!(cd.exec_seg_limit, 0x1000);
    assert_eq!(cd.exec_seg_flags, CS_EXECSEG_MAIN_BINARY);
}
```

macho/verify.rs (adhoc fixture; patch the PRIMARY CD header bytes — no CMS involved):

```rust
#[test]
fn exec_segment_range_mismatch_is_rejected() {       // base@cd+64 <- 0xDEAD_0000_0000_0000
    assert!(errors.iter().any(|e| e.contains("does not match __TEXT"))); }

#[test]
fn unknown_exec_segment_flag_bits_are_rejected() {   // flags@cd+80 |= 0x800
    assert!(errors.iter().any(|e| e.contains("unknown exec segment flags bits 0x800"))); }

#[test]
fn main_binary_flag_is_required_for_executables() {  // flags@cd+80 <- 0
    assert!(errors.iter().any(|e| e.contains("exec segment flags missing CS_EXECSEG_MAIN_BINARY"))); }

#[test]
fn jit_flag_without_entitlements_warns() {           // flags@cd+80 |= 0x40, no entitlements
    assert!(report.slices[0].warnings.iter()
        .any(|w| w.contains("cannot be cross-checked without entitlements")));
    assert!(report.is_valid(), "warning must not invalidate: {:?}", report.slices[0].errors); }
```

(Patch helper: locate CD child via `entry_offset(&sb, CSSLOT_CODEDIRECTORY)`; raw offsets
64/72/80 per the 88-byte 0x20400 layout our builder emits.)

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
    let vm_matches = base == slice.text_segment_base && limit == slice.text_segment_size;
    let file_space_ok = base <= slice.size as u64
        && limit <= slice.text_segment_size
        && base + limit <= slice.size as u64;
    if !vm_matches && !file_space_ok {
        report.errors.push(format!(
            "executable segment range 0x{base:x}+0x{limit:x} does not match __TEXT"));
    }
}
const KNOWN_EXECSEG_FLAGS: u64 = 0x1 | 0x10 | 0x20 | 0x40 | 0x80 | 0x100 | 0x200;
if flags & !KNOWN_EXECSEG_FLAGS != 0 {
    report.errors.push(format!("unknown exec segment flags bits {:#x}", flags & !KNOWN_EXECSEG_FLAGS));
}
let want_main = slice.is_executable;
if (flags & CS_EXECSEG_MAIN_BINARY != 0) != want_main {
    report.errors.push(if want_main {
        "exec segment flags missing CS_EXECSEG_MAIN_BINARY".to_string()
    } else {
        "CS_EXECSEG_MAIN_BINARY set on a non-executable slice".to_string()
    });
}
// entitlement subset cross-checks (only when any of these flags is set)
let cross_check: u64 = CS_EXECSEG_ALLOW_UNSIGNED | CS_EXECSEG_JIT | CS_EXECSEG_DEBUGGER | CS_EXECSEG_SKIP_LV;
if flags & cross_check != 0 {
    match ent_xml_dict {                       // parse the XML child once (already in scope from task 5)
        Some(dict) => {
            let need: [&str; …] = …;           // ALLOW_UNSIGNED => "get-task-allow" OR "run-unsigned-code";
            // JIT => "dynamic-codesigning"; DEBUGGER => "com.apple.private.cs.debugger";
            // SKIP_LV => "com.apple.private.skip-library-validation"
            // missing key(s) → report.errors.push("exec segment flag … requires entitlement …")
        }
        None => report.warnings.push(format!(
            "exec segment flags {:#x} cannot be cross-checked without entitlements", flags)),
    }
}
```

`CS_EXECSEG_DEBUGGER|CS_EXECSEG_JIT|CS_EXECSEG_SKIP_LV` already exist in constants (zero
consumers today → first use here). CAN_LOAD/CAN_EXEC have no pinned entitlement keys
(design §7) → not enforced.

- [ ] **Step 4: Green** — scoped gate → `70 passed; 0 failed` (any drift in the count
  must be explained in the final report; existing fixtures must stay green — the
  dual/sha256-only/ad-hoc fixtures all carry `(base,limit)` = vm pair, flags `0x1`).

- [ ] **Step 5: Commit** — `feat(verify): parse and enforce executable segment fields`

---

### Task 8: Designated requirement parser + evaluator (queue item 8)

**Files:**
- Modify: `crates/zsign-core/src/codesign/verify.rs` — parser + Kleene evaluator, tests.
- Modify: `crates/zsign-core/src/macho/verify.rs` — wiring after the CMS branch, tests.

- [ ] **Step 1: Failing tests first** (Tester) — codesign/verify.rs units:

```rust
fn req_blob_with_dr(expr: &[u8]) -> Vec<u8> {
    // Requirements SuperBlob: magic 0xfade0c01, length, count=1,
    // index (type=CSREQ_DESIGNATED, offset=0x14),
    // child: magic 0xfade0c00, length, kind=exprForm(1), expr bytes
}
fn ident_expr(name: &str) -> Vec<u8> {
    // opIdent = u32 2 BE, u32 len BE, bytes, pad to 4
}

#[test]
fn designated_requirement_evaluates_identifier() {
    let blob = req_blob_with_dr(&ident_expr("com.example"));
    let set = parse_requirements(&blob).unwrap();
    let dr = set.designated().expect("dr present");
    let ctx = RequirementContext { identifier: Some("com.example"), cdhashes: &[], anchored: None };
    assert_eq!(dr.evaluate(&ctx), RequirementVerdict::Satisfied);
    let ctx2 = RequirementContext { identifier: Some("com.evil"), cdhashes: &[], anchored: None };
    assert_eq!(dr.evaluate(&ctx2), RequirementVerdict::Violated);
}

#[test]
fn empty_requirements_has_no_designated() {
    assert!(parse_requirements(crate::codesign::superblob::build_requirements_blob())
        .unwrap().designated().is_none());
}

#[test]
fn unsupported_opcode_is_not_a_hard_error() {
    // DR = opCertField(11) … → parses; evaluate → Unsupported("opcode 11")
}

#[test]
fn malformed_requirements_are_errors() {
    assert!(parse_requirements(&[0; 8]).is_err());        // too short
    assert!(parse_requirements(&kind_lwcr_blob()).is_err()); // kind = lwcrForm(2)
    assert!(parse_requirements(&truncated_expr_blob()).is_err()); // expr bytes overrun
}
```

Verdict enum: `Satisfied | Violated | Unsupported(&'static str /* or String */)` with
`PartialEq`. Evaluator semantics (design §8): Kleene `T/F/U`; `opAnd`/`opOr` binary;
`opNot` negates `T/F`, preserves `U`; `opIdent` → `T/F` (missing identifier → `U`);
`opCDHash` → `T` if operand equals any emitted CD's truncated (`min(len,20)`) digest,
else `F`; `opAppleAnchor`/`opAppleGenericAnchor` → `ctx.anchored.map(…)` else `U`;
flagged/unknown opcodes → `U("opcode 0x…")`; recursion cap 64 → `U` on overflow
(structure already bounded at parse: expression bytes must be fully consumed).

macho/verify.rs e2e:

```rust
#[test]
fn unsatisfied_designated_requirement_is_rejected() {
    // ad-hoc fixture; replace the requirements child (slot 0x0002) with a DR blob
    // demanding identifier "com.evil": rebuild the SuperBlob in place using the
    // reserved LC slack (shift trailing children, fix declared length), then patch
    // BOTH CDs' stored -2 hashes to SHA1/SHA256 of the new child.
    let report = verify_macho(&signed, &SignatureInputs::none()).unwrap();
    assert!(report.slices[0].errors.iter()
        .any(|e| e.contains("designated requirement not satisfied")));
}
// companion: same surgery with identifier "com.example…" (the fixture's identifier)
// → no "designated requirement" finding.
```

Helper note for the Tester: reuse `entry_offset` to find children; the LC signature
window is reserved larger than the SuperBlob by the writer (see `parse_superblob` docs),
so growing the requirements child by ≤ slack is safe; if the slack is insufficient for
the DR, pad the fixture's `sign_macho_adhoc` output region instead and shrink the DR to
the available bytes (identifier strings ≤ 16 bytes keep the blob tiny).

- [ ] **Step 2: Confirm failure** — units fail to compile / FAIL; e2e FAILS (no
evaluation exists).

- [ ] **Step 3: Implement**

Public surface in `codesign/verify.rs` (all `pub`):

```rust
pub struct RequirementsSet<'a> { /* entries: Vec<(u32 kind, Requirement<'a>)> */ }
impl RequirementsSet<'_> { pub fn designated(&self) -> Option<&Requirement<'_>>; }
pub struct Requirement<'a> { /* expr: Expr, raw: &'a [u8] */ }
pub enum RequirementVerdict { Satisfied, Violated, Unsupported(String) }
pub struct RequirementContext<'a> {
    pub identifier: Option<&'a str>,
    pub cdhashes: &'a [&'a [u8]],   // truncated digests of every emitted CD
    pub anchored: Option<bool>,     // None = no CMS (ad-hoc) or unknown
}
impl Requirement<'_> { pub fn evaluate(&self, ctx: &RequirementContext<'_>) -> RequirementVerdict; }
pub fn parse_requirements(blob: &[u8]) -> Result<RequirementsSet<'_>>;
```

Parser details: SuperBlob `magic == CSMAGIC_REQUIREMENTS`, `count` bounded by declared
length, index entries `{type u32, offset u32}`; child at `offset` must be
`CSMAGIC_REQUIREMENT` with `kind == 1` (`lwcrForm` 2 → `Err`); expression parser reads
`u32 BE` opcodes, dispatches per the supported set with correct operand layouts
(`opIdent`: `u32 len` + bytes + 4-align; binary `opAnd`/`opOr` parse left then right;
`opCDHash`: `u32 len` + data; no-operand ops: none), unknown opcode with zero flag byte
→ `Err` (categorical failure — Apple parity), flagged opcode (`0x80000000|0x40000000`
set) → record `Unsupported` node WITHOUT trying to parse its operands: stop expression
parsing there and treat the whole requirement as unsupported-but-structurally-bounded
(consume nothing further; the requirement child's own length already bounds it).
Depth cap 64 → `Err`. Top-level `count == 0` → empty set (no designated → pass).

`verify_slice` wiring — restructure so BOTH paths reach it (replace the ad-hoc early
`return` with fall-through; `report.cms` is already set in both branches):

```rust
// after the CMS / ad-hoc block, still inside verify_slice:
if let Some(req) = superblob.entries.iter().find(|e| e.slot == CSSLOT_REQUIREMENTS) {
    match parse_requirements(req.blob) {
        Err(e) => report.errors.push(format!("malformed requirements blob: {e}")),
        Ok(set) => if let Some(dr) = set.designated() {
            let cdhashes: Vec<&[u8]> = cds.iter().map(|cd| /* truncated digest, own hashType, min(len,20) */).collect();
            let anchored = report.cms.as_ref().filter(|c| !c.no_signature).map(|c| c.anchored);
            let ctx = RequirementContext { identifier: primary.identifier(), cdhashes: &cdhashes, anchored };
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

(`cds` = the primary+alternates vec from task 1.)

- [ ] **Step 4: Green + migration check** — scoped gate → `74 passed; 0 failed`;
  `cargo check -p zsign -p zsign-cli --all-targets` → OK.

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
fn synth_cd(version: u32, tail: &[u8], hash_offset: u32) -> Vec<u8> { /* … */ }
// minimal CD: magic 0xfade0c02, length, version, flags=0, hashOffset, identOffset,
// nSpecial=0, nCode=0, codeLimit=0, hashSize=32, hashType=2, platform=0, pageSize=12,
// spare2=0, + version-gated tail bytes + ident "x\0"

#[test]
fn version_header_sizes_are_correct() {
    // 0x20001 with 44-byte header → Ok (pre-fix expects ≥52 → Err only if blob short;
    //   build the blob EXACTLY header+ident so the size check is the discriminator)
    // 0x20100 → Ok at 48; 0x20200 → 52; 0x20300 → 64; 0x20400 → 88; 0x20500 → 96;
    // 0x20600 → 108
    // 0x20601 → Err("unsupported CodeDirectory version")
}
#[test]
fn scatter_is_rejected() { /* 0x20100 CD, scatterOffset@44 = 4 → Err */ }
#[test]
fn preencrypted_hashes_are_rejected() { /* 0x20500, preEncryptOffset@92 = 0x100 → Err */ }
#[test]
fn runtime_without_flag_is_rejected() { /* 0x20500, runtime@88 = 0x0D0000, flags=0 → Err */ }
#[test]
fn code_limit_64_drives_page_check() {
    // 0x20300 CD: codeLimit(u32@32)=32, codeLimit64@56=0x1000_0000, nCodeSlots=1,
    // code = [0u8; 4096] → check_code_pages == CountMismatch { stored: 1, computed: 1 }
    // (without honoring codeLimit64 it would be Matched)
}
#[test]
fn linkage_fields_are_bounds_checked() {
    // 0x20600: linkageSize@104 = 0 → Ok; = 20 with linkageOffset@100 in range → Ok;
    // = 20 out of range → Err; = 7 → Err
}
#[test]
fn cdhash_binds_declared_length() {
    let mut cd = /* valid 0x20400 CD bytes */;
    cd.extend_from_slice(&[0xAA; 64]);          // trailing bytes beyond declared length
    let parsed = CodeDirectory::parse(&cd).unwrap();
    assert_eq!(parsed.data.len() as u32,
               u32::from_be_bytes(cd[4..8].try_into().unwrap()));
    assert_eq!(parsed.cdhash_sha256(), Sha256::digest(&cd[..declared]).into());
}
```

- [ ] **Step 2: Confirm failure** — several FAIL (0x20001-size bucket, upper gate
absent, scatter/preEncrypt/codeLimit64/linkage unenforced, trailing bytes hashed).

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
(private field + `pub fn effective_code_limit(&self) -> u64`
= `(version >= CODEDIRECTORY_VERSION_CODELIMIT64 && self.code_limit64 != 0) as u64 *
(u64::MAX)` … write it plainly: `if version ≥ gate && code_limit64 != 0 { code_limit64 } else { code_limit as u64 }`);
`≥0x20500` `runtime @88` (pub field; ≠0 && `flags & CS_RUNTIME == 0` →
`Err("runtime version recorded without the CS_RUNTIME flag")`) and
`pre_encrypt_offset @92` (private; ≠0 → `Err("pre-encrypted CodeDirectory hashes are not supported")`);
`≥0x20600` linkage quintet `@96..108` (private; `linkage_size == 0` ok;
`== 20 && linkage_offset + 20 <= declared` ok; else `Err`).

`check_code_pages`: replace `cd.code_limit as usize` with
`cd.effective_code_limit() as usize` (both the `region_len` computation and the
oversize guard). `check_code_pages_in_file` (macho) inherits this through
`check_code_pages` — no change there beyond keeping its slice-bound comment accurate.

Update the constants (this task): `CODEDIRECTORY_VERSION_RUNTIME = 0x20500` and
`CODEDIRECTORY_VERSION_LINKAGE = 0x20600`, doc comments fixed to the librarian's
`CS_SUPPORTSRUNTIME`/`CS_SUPPORTSLINKAGE` facts; `CODEDIRECTORY_VERSION_PREENCRYPT`
keeps `0x20500` with a comment that `supportsPreEncrypt` gates *both* runtime and
preEncryptOffset. Note: `CODEDIRECTORY_VERSION_LINKAGE` is now the table's top bucket —
its old `0x20700` value exists in no authoritative source.

- [ ] **Step 4: Green** — scoped gate → `81 passed; 0 failed` (baseline fixtures all
emit `0x20400` with zeroed gated fields → unchanged).

- [ ] **Step 5: Commit** — `fix(verify): honor codedirectory version layout and code limit64`

---

### Task 10: Constants completion (queue item 10)

**Files:**
- Modify: `crates/zsign-core/src/codesign/constants.rs`
- Modify: `crates/zsign-core/src/codesign/verify.rs` — adopt the three new constants
  (old-magic diagnostic, constraint-slot magic table entry, −8..−11 names).

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
    // top-level magic 0xfade0b02 → Err mentioning "old embedded signature"
}
#[test]
fn launch_constraint_slot_magic_is_validated() {
    // synth_superblob with a child at slot 0x0008 whose magic != 0xfade8181 → Err
    // …and with magic 0xfade8181 → Ok (routing ignores it until a CD binds -8)
}
```

- [ ] **Step 2: Confirm failure** — `TICKETSLOT` test FAILS (0x10001); the two
`parse_superblob` tests FAIL (constants/arms absent); `version_gate_values` FAILS on
RUNTIME/LINKAGE until task 9's revalue is asserted (if task 9 already landed, this
sub-assert passes — it is a guard, not a trigger).

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
  (slots `0x0008..=0x000b` join the `seen` duplicate set automatically).
- `check_special_slots`: replace numeric literals — content arm
  `k if (8..=11).contains(&k) => slot_child((CSSLOT_LAUNCH_CONSTRAINT_SELF + (k as i32 - CSSLOT_SPECIAL_LAUNCH_CONSTRAINT_SELF)) as u32)`
  and the elevation whitelist in `macho/verify.rs`:
  `matches!(k as i32, 1 | 2 | 3 | 5 | 7 | CSSLOT_SPECIAL_LAUNCH_CONSTRAINT_SELF..=CSSLOT_SPECIAL_LIBRARY_CONSTRAINT)`
  (keeps behavior identical; constants become the single source of truth).

- [ ] **Step 4: Green + final migration** — scoped gate → `84 passed; 0 failed`
  (exact count = baseline + new tests across tasks 1-10; adjust the expectation to the
  actual arithmetic and report it); `cargo check -p zsign -p zsign-cli --all-targets` → OK.

- [ ] **Step 5: Commit** — `fix(constants): correct ticket slot and version gates, add launch constraint magic`

---

### Task 11: Final verification

**Files:** none (verification only).

- [ ] **Step 1: Full scoped gate**

Run: `mkdir -p .tmptmp && TMPDIR=$PWD/.tmptmp cargo test -p zsign-core verify -- --skip test_ipa_signing_is_deterministic`
Expected: all pass, 0 failed. Save verbatim tail for the final report.

- [ ] **Step 2: Workspace compile (caller migration proof)**

Run: `TMPDIR=$PWD/.tmptmp cargo check --workspace --all-targets`
Expected: OK — proves `zsign`, `zsign-cli`, `zsign-wasm`, benches, and every test target
still compile against the changed core APIs (`check_special_slots` signature,
`self_consistent_blobs` deletion, new `CodeDirectory` fields).

- [ ] **Step 3: Diff hygiene**

Run: `git status --short && git log --oneline c9ff0fb..HEAD`
Expected: only the three scope files + the two force-added docs changed; 12-13 commits
(design+plan docs, tasks 1-10, none touching signer/crypto/zsign sources).

---

## Self-review record

- **Spec coverage:** queue items 1-10 ↔ tasks 1-10 one-to-one; task 11 covers the final
  gate; design-doc sections (frozen contracts, interop register, test strategy) are
  each owned by a task step. No queue item without a task.
- **Type consistency:** `check_special_slots(cd, inputs, superblob)` introduced in task 6
  and only there; `der_entitlements_to_plist` name is identical in task 5's test and
  implementation; `effective_code_limit()` defined in task 9, consumed in task 9;
  `RequirementContext`/`RequirementVerdict` names identical between task 8 tests and
  implementation; constants names used in task 10 exist in no earlier task.
- **Placeholder scan:** every step names test functions with concrete assertions,
  exact error substrings, raw byte offsets, and gate commands with expected outcomes.
  Estimated pass counts are derived from the 54-test baseline plus the listed new
  tests; where arithmetic could drift, the step says to report the actual number.
- **Deviation handling:** any plan change discovered during implementation (e.g. a
  fixture whose pass-count differs, an existing test that must be adjusted) is recorded
  in the final report's plan-vs-actual section, per the brief.
