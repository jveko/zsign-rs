# CodeDirectory binding and report sourcing — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development
> with dispatching-parallel-agents for independent tasks to implement this
> plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make report pages/special-slot fields come only from a
CMS-bound CodeDirectory, reject duplicate-hash-type directories at parse
time, and reject cross-CD header disagreement — so no report field can be
decided by a directory the signature does not bind.

**Architecture:** Two edits in two files: `codesign/verify.rs`
`parse_superblob` gains a duplicate-`hashType` rejection (directions (b)+(c)
as one structural check, mirroring Apple's `loadCodeDirectories`), and
`macho/verify.rs` replaces the last-on-tie `max_by_key` with a static
bound-set selection (direction (a)) and gains a `cross_cd_disagreements`
helper wired into the existing per-CD loop (direction (d)). The crypto crate,
signer, writer, parser, facade, and CLI are untouched.

**Tech Stack:** Rust (edition 2021), cargo test/clippy/fmt.

**Spec:** `docs/superpowers/specs/2026-10-08-codedirectory-binding-and-report-sourcing-design.md`

## Global Constraints

- Edited files ONLY: `crates/zsign-core/src/codesign/verify.rs`
  (`parse_superblob` + its test module) and
  `crates/zsign-core/src/macho/verify.rs` (selection + agreement + tests).
  Nothing in `crypto/**`, `macho/{writer,signer,parser}.rs`, facade, or CLI.
- `crypto/cms_verify.rs`'s `verify_code_signature` signature is frozen — no
  extra CD hashes can be passed to it; the binding completeness argument
  lives entirely in `parse_superblob`.
- The alternate-slot range (0x1000..=0x1005 vs Apple's 0x1004) stays
  untouched — a different ticket owns it.
- Zero-warning gate before the item closes:
  `cargo fmt --all -- --check` and
  `cargo clippy --workspace --all-targets -- -D warnings`, both clean.
- Tests run as `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test …`.
- No ticket IDs, no TODOs, no stubs anywhere (code, comments, docs, commits).
- Commits are controller-owned; implementers and testers never commit.
  Commit subjects: conventional, imperative, lowercase, no trailing period.
- The tampered-alternate test rewrite is an EXPECTED contract change (old
  assertion pinned the field-source bug); its tamper coverage must be kept
  and the rewrite recorded in the final report.

## Review Focus

- **Honest dual output must stay pristine:** `dual_signing_binds_cdhash_pair`
  asserts `errors.len() == 1` — any false positive from the agreement field
  set or the duplicate check on our own signer's output trips it. Task 2's
  crate run is the gate; if it fires, the field set is wrong, not the test.
- **Parse-time rejection must not eat existing negative tests:**
  `corrupt_alternate_cd_is_rejected_with_detail` patches hashType to 7 —
  `CodeDirectory::parse` must still fail first with
  "unsupported CodeDirectory hash type 7" (the duplicate check runs after a
  successful parse, so it cannot shadow that error) — Task 1's crate run.
- **Bound set is static, not outcome-dependent:** `strongest` at
  `verify.rs:174` must depend only on the CMS blob's shape (reuse
  `cms_is_real` in the later CMS branch instead of recomputing
  `empty_wrapper`); a reviewer diffing Task 2 sees no behavior change for
  CMS-signed dual binaries (bound = both directories ⇒ strongest = SHA-256
  alternate, same as today).
- **Ad-hoc field source flips by design:** `pages` on ad-hoc dual binaries
  moves from the unbound SHA-256 alternate to the primary; only the
  tampered-alternate test's field assertion changes — every other ad-hoc test
  asserts errors/validity, not the field.
- **Positional consumers:** `special_slots` must remain a
  `Vec<SpecialSlotCheck>` indexed from slot −1 with no placeholder entries
  (facade `.first()`/`.get(2)`, CLI index-derived JSON) — this plan adds no
  vector entries; a reviewer confirms the vector's construction is untouched.

---

### Task 1: Reject duplicate CodeDirectory hash types in `parse_superblob`

**Files:**
- Modify: `crates/zsign-core/src/codesign/verify.rs` — `parse_superblob`
  child-classification loop (:197-216) + test module (`#[cfg(test)]` at
  :1271).

**Interfaces:**
- Consumes: `CodeDirectory::parse` (returns `Err` on unsupported hashType —
  runs BEFORE this check), `CodeDirectory.hash_type` (pub), constants
  `CSMAGIC_EMBEDDED_SIGNATURE`, `CSSLOT_CODEDIRECTORY`,
  `CSSLOT_ALTERNATE_CODEDIRECTORIES` (glob-imported via
  `use super::constants::*`), test fixtures `TEST_CODE` and
  `CodeDirectoryBuilder`.
- Produces: `parse_superblob(&[u8]) -> Result<SuperBlob<'_>>` (signature
  unchanged) now returning
  `Err(crate::Error::Verification(msg))` with `msg` containing
  `duplicate CodeDirectory hash type` for a second directory of an existing
  type. `verify_slice` surfaces it through its existing
  "embedded code signature is not a valid SuperBlob: {e}" push — no new
  wiring.

- [ ] **Step 1: Write the failing test**

Add to `codesign/verify.rs`'s test module:

```rust
/// Minimal SuperBlob: header + index + children, declared length fixed up.
fn test_superblob(children: &[(u32, &[u8])]) -> Vec<u8> {
    let index_end = 12 + children.len() * 8;
    let mut out = Vec::new();
    out.extend_from_slice(&CSMAGIC_EMBEDDED_SIGNATURE.to_be_bytes());
    out.extend_from_slice(&0u32.to_be_bytes()); // declared length, patched below
    out.extend_from_slice(&(children.len() as u32).to_be_bytes());
    let mut offset = index_end as u32;
    for (slot, bytes) in children {
        out.extend_from_slice(&slot.to_be_bytes());
        out.extend_from_slice(&offset.to_be_bytes());
        offset += bytes.len() as u32;
    }
    for (_, bytes) in children {
        out.extend_from_slice(bytes);
    }
    let len = out.len() as u32;
    out[4..8].copy_from_slice(&len.to_be_bytes());
    out
}

#[test]
fn duplicate_code_directory_hash_type_is_rejected() {
    // A second directory of an already-present hash type can never be bound
    // by the CMS cdhash attributes; Apple rejects duplicate hashType outright.
    let cd_a = CodeDirectoryBuilder::new("com.example.dup", TEST_CODE).build_sha256();
    let cd_b = CodeDirectoryBuilder::new("com.example.dup.other", TEST_CODE).build_sha256();
    let blob = test_superblob(&[
        (CSSLOT_CODEDIRECTORY, cd_a.as_slice()),
        (CSSLOT_ALTERNATE_CODEDIRECTORIES, cd_b.as_slice()),
    ]);
    let res = parse_superblob(&blob);
    assert!(
        matches!(&res, Err(crate::Error::Verification(m)) if m.contains("duplicate CodeDirectory hash type")),
        "duplicate hash type must be rejected, got {:?}",
        res.as_ref().err()
    );
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-core duplicate_code_directory_hash_type_is_rejected`
Expected: FAIL — pre-fix both directories parse, `res` is `Ok`, so
`res.as_ref().err()` is `None` and the `matches!` assertion prints
`got None`.

- [ ] **Step 3: Add the duplicate-type checks to `parse_superblob`**

In the child-classification loop, alternate arm — immediately after the
successful `CodeDirectory::parse` and before `alternate_code_directories.push(cd)`:

```rust
if code_directory
    .as_ref()
    .is_some_and(|primary_cd| primary_cd.hash_type == cd.hash_type)
    || alternate_code_directories
        .iter()
        .any(|prev| prev.hash_type == cd.hash_type)
{
    return Err(crate::Error::Verification(format!(
        "duplicate CodeDirectory hash type {} at slot 0x{:08x}: at most one CodeDirectory per hash type",
        cd.hash_type, entry.slot
    )));
}
```

Primary arm — after the successful parse, before `code_directory = Some(cd)`,
the mirror check against already-parsed alternates (index order can list an
alternate before slot 0):

```rust
if alternate_code_directories
    .iter()
    .any(|prev| prev.hash_type == cd.hash_type)
{
    return Err(crate::Error::Verification(format!(
        "duplicate CodeDirectory hash type {} at slot 0x{:08x}: at most one CodeDirectory per hash type",
        cd.hash_type, entry.slot
    )));
}
```

Nothing else in `parse_superblob` changes: header/index validation, magic
checks, the duplicate-slot `seen` set, overlap checks, and the CMS arm stay
byte-for-byte.

- [ ] **Step 4: Run the new test to verify it passes**

Run: `TMPDIR=$PWD/target/tmp cargo test -p zsign-core duplicate_code_directory_hash_type_is_rejected`
Expected: PASS.

- [ ] **Step 5: Run the whole zsign-core crate**

Run: `TMPDIR=$PWD/target/tmp cargo test -p zsign-core`
Expected: all tests pass — in particular
`corrupt_alternate_cd_is_rejected_with_detail` (hashType 7 still rejected by
`CodeDirectory::parse` first), `embedded_superblob_parses`, and every
signing round-trip (our signer emits at most one directory per type).

- [ ] **Step 6: Controller commit (not an implementer step)**

Stage exactly `crates/zsign-core/src/codesign/verify.rs` and commit
`fix(codesign): reject duplicate code directory hash types`.

### Task 2: Bound-set selection and cross-CD agreement in `macho/verify.rs`

**Files:**
- Modify: `crates/zsign-core/src/macho/verify.rs` — `verify_slice`
  (selection block :174-179, CMS branch :367-372, page loop :185-196) +
  new private helper near `emitted_cds`/`cdhash_pair` (:463-484) + tests.

**Interfaces:**
- Consumes: `emitted_cds(&superblob) -> Vec<&CodeDirectory>` (unchanged),
  `cdhash_pair(&cds)` (unchanged — its first-of-type picks ARE the bound
  set), `CodeDirectory` pub fields/methods (`hash_size`, `is_sha1`,
  `is_sha256`, `identifier()`, `team_id()`, `effective_code_limit()`,
  `n_code_slots`, `page_size_log2`, `flags`, `exec_seg_*`),
  `CSMAGIC_BLOBWRAPPER` (already imported), test helpers `entry_offset`,
  `sign_macho_adhoc`, `make_minimal_macho`.
- Produces: private `fn cross_cd_disagreements(cd: &CodeDirectory<'_>,
  primary: &CodeDirectory<'_>) -> Vec<&'static str>`; `strongest` now drawn
  from the bound set with first-on-tie; new error strings
  `"{label}CodeDirectory disagrees with the primary: {field}"`. No public
  type changes — `SliceVerifyReport` shape untouched.

- [ ] **Step 1: Write the failing tests**

(a) REWRITE the tail of `tampered_alternate_page_hash_is_rejected`
(replace its final comment + `assert_eq!` exactly):

```rust
        // Metadata (pages) is sourced from the CMS-bound set; ad-hoc signing
        // binds nothing beyond the primary, so the field reflects the
        // unmodified primary while the tampered alternate is caught above.
        assert_eq!(report.slices[0].pages, PageCheck::Matched);
```

replacing:

```rust
        // Metadata = strongest CD (the tampered SHA-256 alternate), so the field
        // itself now reflects the tamper:
        assert_eq!(
            report.slices[0].pages,
            PageCheck::Mismatch { page_index: 0 }
        );
```

Everything else in that test (byte surgery + the
`alternate SHA-256 code page 0 hash mismatch` errors assertion) stays.

(b) NEW test, added beside it:

```rust
#[test]
fn alternate_header_disagreement_is_rejected() {
    let macho = MachOFile::parse(make_minimal_macho()).unwrap();
    let mut signed =
        sign_macho_adhoc(&macho, "com.example.agree", None, None, None, false).unwrap();
    let m = MachOFile::parse(signed.clone()).unwrap();
    let sl = &m.slices()[0];
    let sig_off = sl.code_sig_offset.unwrap() as usize;
    let sig_len = sl.code_sig_size.unwrap() as usize;
    let cd = sig_off
        + entry_offset(
            &signed[sig_off..sig_off + sig_len],
            CSSLOT_ALTERNATE_CODEDIRECTORIES,
        )
        .expect("alternate CD entry");
    // identOffset sits at CD+20; flip the first identifier byte of the
    // SHA-256 alternate so it describes a different identity than the primary.
    let ident_off = u32::from_be_bytes(signed[cd + 20..cd + 24].try_into().unwrap()) as usize;
    signed[cd + ident_off] = b'X';
    let report = verify_macho(&signed, &SignatureInputs::none()).unwrap();
    assert!(!report.is_valid(), "disagreement must fail verification");
    assert!(
        report.slices[0].errors.iter().any(|e| e.contains(
            "alternate SHA-256 CodeDirectory disagrees with the primary: identifier"
        )),
        "errors: {:?}",
        report.slices[0].errors
    );
}
```

- [ ] **Step 2: Run both tests to verify they fail**

Run: `TMPDIR=$PWD/target/tmp cargo test -p zsign-core -- tampered_alternate_page_hash_is_rejected alternate_header_disagreement`
Expected: both FAIL —
- tampered: assertion `left: Mismatch { page_index: 0 }, right: Matched`
  (today's field source is the tampered unbound alternate);
- disagreement: pre-fix nothing compares alternate headers, so
  `report.is_valid()` is `true` and the first assertion fails — a doctored
  binary currently verifies.

- [ ] **Step 3: Implement (a) — replace the selection block**

In `verify_slice`, replace exactly:

```rust
    let cds = emitted_cds(&superblob);
    let strongest = cds
        .iter()
        .copied()
        .max_by_key(|cd| cd.hash_size)
        .unwrap_or(primary);
```

with:

```rust
    let cds = emitted_cds(&superblob);
    let first_sha1 = cds.iter().copied().find(|cd| cd.is_sha1());
    let first_sha256 = cds.iter().copied().find(|cd| cd.is_sha256());
    let cms_is_real = superblob.cms.map_or(false, |blob| {
        !(blob.len() == 8 && blob[0..4] == CSMAGIC_BLOBWRAPPER.to_be_bytes())
    });
    let mut bound: Vec<&CodeDirectory<'_>> = vec![primary];
    if let Some(cd) = first_sha1.filter(|cd| !std::ptr::eq(*cd, primary)) {
        bound.push(cd);
    }
    if let Some(cd) = first_sha256.filter(|cd| !std::ptr::eq(*cd, primary)) {
        bound.push(cd);
    }
    let strongest = if cms_is_real {
        bound
            .iter()
            .copied()
            .fold(None::<&CodeDirectory<'_>>, |acc, cd| match acc {
                Some(best) if best.hash_size >= cd.hash_size => Some(best),
                _ => Some(cd),
            })
            .unwrap_or(primary)
    } else {
        primary
    };
```

Then, in the later CMS branch, replace:

```rust
        let empty_wrapper =
            cms_blob.len() == 8 && cms_blob[0..4] == CSMAGIC_BLOBWRAPPER.to_be_bytes();
        if empty_wrapper {
```

with:

```rust
        if !cms_is_real {
```

(one definition of the predicate; `cms_blob` stays bound for the
`verify_code_signature` call below it).

- [ ] **Step 4: Implement (d) — helper + push site**

Add near `emitted_cds`/`cdhash_pair`:

```rust
/// Header fields one signing session guarantees identical across every
/// CodeDirectory of one file; a difference means the alternate describes a
/// different binary than the primary the report anchors on.
fn cross_cd_disagreements(
    cd: &CodeDirectory<'_>,
    primary: &CodeDirectory<'_>,
) -> Vec<&'static str> {
    let mut out = Vec::new();
    if cd.identifier() != primary.identifier() {
        out.push("identifier");
    }
    if cd.team_id() != primary.team_id() {
        out.push("team ID");
    }
    if cd.effective_code_limit() != primary.effective_code_limit() {
        out.push("code limit");
    }
    if cd.n_code_slots != primary.n_code_slots {
        out.push("code slot count");
    }
    if cd.page_size_log2 != primary.page_size_log2 {
        out.push("page size");
    }
    if cd.flags != primary.flags {
        out.push("flags");
    }
    if cd.exec_seg_base != primary.exec_seg_base {
        out.push("exec segment base");
    }
    if cd.exec_seg_limit != primary.exec_seg_limit {
        out.push("exec segment limit");
    }
    if cd.exec_seg_flags != primary.exec_seg_flags {
        out.push("exec segment flags");
    }
    out
}
```

In the existing per-CD page loop, after `push_page_errors(&mut report, &label, &pages);`:

```rust
        if !std::ptr::eq(*cd, primary) {
            for field in cross_cd_disagreements(cd, primary) {
                report.errors.push(format!(
                    "{label}CodeDirectory disagrees with the primary: {field}"
                ));
            }
        }
```

Nothing else in `verify_slice` changes: the per-CD page/special-slot loops,
`report.pages`/`report.special_slots` assignments, `cdhash_pair`, the
requirements/DR block, and all error wording stay as-is.

- [ ] **Step 5: Run both tests to verify they pass**

Run: `TMPDIR=$PWD/target/tmp cargo test -p zsign-core -- tampered_alternate_page_hash_is_rejected alternate_header_disagreement`
Expected: both PASS.

- [ ] **Step 6: Run the whole zsign-core crate (the canary run)**

Run: `TMPDIR=$PWD/target/tmp cargo test -p zsign-core`
Expected: all tests pass — especially `dual_signing_binds_cdhash_pair`
(`errors.len() == 1`: the agreement field set produces no false positives on
our signer's honest dual output and the duplicate check adds no error to
valid two-directory signatures), `fat_code_limit_beyond_slice_is_rejected`
(its comment/assertions unaffected), and all facade-facing doctests. If
`dual_signing_binds_cdhash_pair` fails, STOP and report which field
disagreed — the field set, not the test, is then wrong.

- [ ] **Step 7: Controller commit (not an implementer step)**

Stage exactly `crates/zsign-core/src/macho/verify.rs` and commit
`fix(macho): source report fields from the bound code directory`.

### Task 3: Zero-warning gate for the item

**Files:** none edited; verification only.

- [ ] **Step 1: Format check**

Run: `cargo fmt --all -- --check`
Expected: no output, exit 0.

- [ ] **Step 2: Clippy gate**

Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: no warnings, exit 0.

- [ ] **Step 3: Full workspace tests**

Run: `TMPDIR=$PWD/target/tmp cargo test --workspace`
Expected: all workspace tests pass.

Acceptance for the item: Steps 1-3 all exit 0 with no warnings and no test
failures, both fix commits exist on the branch, the tampered-alternate
rewrite is recorded as an expected contract change in the final report, and
the direction-(c) ruling is carried there as well.
