# Nested-Code Emission (ZSN-34) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development
> with dispatching-parallel-agents for independent tasks to implement this
> plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop emitting entitlements for non-executables, sign every code
entity exactly once, and recognize nested code by Info.plist/location
instead of a three-extension whitelist.

**Architecture:** One policy coercion in `zsign-core`'s `SigningContext::new`;
a processed-path `HashSet<PathBuf>` threaded from the standalone-dylib pass
into the per-bundle immediate-binary discovery; one shared
`crate::bundle::is_nested_bundle_dir` predicate (legacy extension arm +
bundle markers + Apple nested-code locations + `CFBundlePackageType`) used
by signer, depth calculation, and verifier alike.

**Tech Stack:** Rust workspace (`zsign-core`, `zsign-rs`, `zsign-wasm`),
`plist`, `walkdir`, `rayon`, inline `#[cfg(test)]` modules.

**Reference doc:** `docs/superpowers/specs/2026-09-26-nested-emit-design.md`
(all file:line citations below were verified against current source).

**Conventions (every task):** run tests as
`TMPDIR=$PWD/.tmptmp cargo test -p <crate> <filter> -- --skip test_ipa_signing_is_deterministic`.
No project-wide fmt/clippy until the final report. Never put ticket IDs in
code or comments (they go in commit subjects only). No stubs/TODOs. Delete
what a change obsoletes; migrate every caller.

---

### Task 1: Core — no entitlements emitted for non-executables

**Files:**
- Modify: `crates/zsign-core/src/macho/signer.rs` (tests module;
  `SigningContext::new` ~:67-128; `sign_any_macho` ~:161-199; const :131)
- Modify: `crates/zsign-core/src/macho/mod.rs:18-21` (re-export)
- Modify: `crates/zsign/src/macho/mod.rs:149-170` (doc comment only)
- Modify: `crates/zsign-wasm/src/lib.rs` (thin path ~:524-533; pin-test
  comment ~:1006-1040)
- Modify: `crates/zsign/src/ipa/mod.rs` (two comments only — `sign_binary`
  doc ~:966-969 and the Info.plist comment ~:1017-1019; see Step 1.3(g))

- [ ] **Step 1.1: Write the failing test**

Add to the `#[cfg(test)]` tests module of
`crates/zsign-core/src/macho/signer.rs` (reuses that module's existing
`test_credentials()` helper, as at `signer.rs:1158`):

```rust
#[test]
fn test_non_executable_signing_carries_no_entitlements() {
    const ENT: &[u8] = br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>com.example.ent</key><string>yes</string></dict></plist>"#;

    fn assert_no_entitlements(signed: &[u8], via: &str) {
        let m = MachOFile::parse(signed.to_vec()).unwrap();
        let sl = &m.slices()[0];
        let sig_off = sl.code_sig_offset.unwrap() as usize;
        let sig_len = sl.code_sig_size.unwrap() as usize;
        let sb = crate::codesign::verify::parse_superblob(&signed[sig_off..sig_off + sig_len])
            .unwrap_or_else(|e| panic!("{via}: superblob must parse: {e}"));
        assert!(
            sb.entries.iter().all(|e| e.slot != 0x0005),
            "{via}: entitlements blob (slot -5) must not be emitted for a dylib"
        );
        assert!(
            sb.entries.iter().all(|e| e.slot != 0x0007),
            "{via}: DER entitlements blob must not be emitted for a dylib"
        );
        let cd = sb
            .code_directory
            .as_ref()
            .unwrap_or_else(|| panic!("{via}: primary CodeDirectory must be present"));
        match cd.special_slot_hash(5) {
            None => {}
            Some(h) => assert!(
                h.iter().all(|&b| b == 0),
                "{via}: slot -5 must be unbound, got {h:02x?}"
            ),
        }
        let report = crate::macho::verify_macho(
            signed,
            &crate::codesign::verify::SignatureInputs::none(),
        )
        .unwrap_or_else(|e| panic!("{via}: verify must accept the signed dylib: {e}"));
        assert!(
            report.is_valid(),
            "{via}: verify errors: {:?}",
            report.slices.iter().flat_map(|s| &s.errors).collect::<Vec<_>>()
        );
    }

    let macho = MachOFile::parse(crate::macho::fixtures::make_minimal_dylib()).unwrap();
    let creds = test_credentials();

    let signed = sign_macho(&macho, "com.zsign.dylib", Some(ENT), &creds, None, None, false).unwrap();
    assert_no_entitlements(&signed, "sign_macho");
    let signed = sign_macho_sha256_only(&macho, "com.zsign.dylib", Some(ENT), &creds, None, None, false).unwrap();
    assert_no_entitlements(&signed, "sign_macho_sha256_only");
    let signed = sign_macho_adhoc(&macho, "com.zsign.dylib", Some(ENT), None, None, false).unwrap();
    assert_no_entitlements(&signed, "sign_macho_adhoc");
    let signed = sign_any_macho(&macho, "com.zsign.dylib", Some(ENT), &creds, None, None, false).unwrap();
    assert_no_entitlements(&signed, "sign_any_macho");
}
```

Notes for the implementer: call the fixture fully-qualified as
`crate::macho::fixtures::make_minimal_dylib()` (the tests module's
`use`-list at `signer.rs:934-936` does NOT import it — `signer.rs:1754`
uses the fully-qualified path for the same reason). `verify_macho` takes a
second `&SignatureInputs` argument (`macho/verify.rs:99`); pass
`&crate::codesign::verify::SignatureInputs::none()` like existing call
sites (`macho/verify.rs:937`).
`special_slot_hash(index)` is 1-based: index 5 ↔ slot −5
(`codesign/verify.rs:788-791`; `None` when `n_special < 5`, i.e. unbound).
`SuperBlob::code_directory` is `Option<CodeDirectory>` (`codesign/verify.rs:72`)
— always bind `sb.code_directory.as_ref().expect("primary CD")` first, as
`crates/zsign/src/verify.rs:1002` does.

- [ ] **Step 1.2: Run the test to verify it fails**

Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-core non_executable_signing -- --skip test_ipa_signing_is_deterministic`
Expected: FAIL — every entry binds slot −5 (`sign_macho`/`sign_macho_adhoc`
with the supplied `ENT`, `sign_any_macho`/sha256 with `ENT` or the empty
dict), so the `slot != 0x0005` assert fires.

- [ ] **Step 1.3: Implement the coercion, delete the injections**

(a) In `SigningContext::new` (`signer.rs:67-128`), insert before the
`entitlements_blob` construction:

```rust
// Non-executables (dylibs, frameworks) carry no entitlements: an absent
// entitlements slot is the codesign baseline, and unallocated special
// slots are presumed absent rather than being an error.
let entitlements = if is_executable { entitlements } else { None };
```

(b) In `sign_any_macho` (`signer.rs:161-199`): delete the
`let is_executable = …` local and the `let ent = if is_executable { … }
else { Some(EMPTY_ENTITLEMENTS) };` block; pass `entitlements` directly at
both former `ent` call sites (`sign_macho` and `sign_macho_all_slices`).
Update the function doc (`:156-160`), replacing the
"Automatically selects entitlements … Non-executables … use empty
entitlements" bullets with: `* Entitlements are ignored for
non-executables: no entitlements slot is emitted (absent slot is the
codesign baseline).`

(c) Delete `pub const EMPTY_ENTITLEMENTS` (`signer.rs:130-131`) and its
re-export line in `crates/zsign-core/src/macho/mod.rs:18-21`.

(d) `crates/zsign/src/macho/mod.rs:149-170`: update the wrapper's doc
bullet that repeats "Non-executables (dylibs, frameworks) use empty
entitlements" to the same wording as (b).

(e) `crates/zsign-wasm/src/lib.rs` thin path (~:524-533): delete the
`is_executable` local and the `if is_executable { … } else {
Some(zsign_core::macho::EMPTY_ENTITLEMENTS) }` block; call
`sign_macho_sha256_only` with `self.effective_entitlements()` directly.
(The fat entry at ~:577-584 already passes `effective_entitlements()`;
core now coerces it — no change needed there.)

(f) `crates/zsign-wasm/src/lib.rs` pin test
`non_executable_input_ignores_profile_entitlements` (~:1006-1040): update
the doc comment (lines ~:1006-1009) so it no longer names
`EMPTY_ENTITLEMENTS` — new text: `/// Pins the executable/non-executable
entitlements policy: non-executable input must ignore profile
entitlements entirely (no entitlements slot either way), executable input
must not. The non-executable assertion goes red if any entitlements slot
is ever emitted for non-executables again (the pre-change state); the
executable assertions go red if profile entitlements stop being applied.`
And strengthen the non-executable assertion block (~:1022-1027) by adding,
immediately before the existing `assert_eq!(entitlements_slot(&a),
entitlements_slot(&b), …)`:

```rust
assert!(
    entitlements_slot(&a).is_none(),
    "non-executable input must emit no entitlements slot at all"
);
```

Keep the existing executable-side `assert_ne!` unchanged. (Strengthened
this way the pin is RED before the coercion — today `sign_macho` injects
the empty dict — and GREEN after Task 1's change; the existing
`assert_eq!(a, b)` stays green in both states.)

(g) `crates/zsign/src/ipa/mod.rs` — two comments become false/unsourced
once the coercion lands; update them (comments only, no behavior change):

1. The `sign_binary` doc comment (~:966-969), currently
   `/// For non-executable binaries (dylibs, frameworks), empty entitlements are used
   /// instead of the full entitlements. This matches the behavior of the C++ zsign.`
   →

```rust
    /// Entitlements are emitted only for executables: non-executables
    /// (dylibs, frameworks) are signed with no entitlements slot at all
    /// (enforced in `zsign-core`'s signing context; the C++ upstream
    /// instead emits an empty-dict slot, which this port deliberately
    /// does not reproduce).
```

2. The Info.plist comment inside `sign_binary` (~:1017-1019), currently
   `// Dylibs/frameworks must NOT include Info.plist or AMFI rejects them
   // with "has entitlements but is not a main binary".` — keep the
   truthful first line above it and replace these two lines with:

```rust
        // The Info.plist hash arrives with the bundle's CodeResources,
        // which only the main-executable path receives.
```

- [ ] **Step 1.4: Sweep for leftover references**

Run: `grep -rn "EMPTY_ENTITLEMENTS\|empty entitlements" crates docs README.md 2>/dev/null`
Expected: zero hits in code/docs (the grep is the check; if an external doc
describes the old behavior, update that sentence).

- [ ] **Step 1.5: Run the test to verify it passes + scoped neighbors**

Run:
`TMPDIR=$PWD/.tmptmp cargo test -p zsign-core non_executable -- --skip test_ipa_signing_is_deterministic`
Expected: PASS (new test + `test_non_executable_ignores_der_entitlements_slots`).

Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-core sign_any -- --skip test_ipa_signing_is_deterministic`
Expected: PASS (`sign_any_macho` tests after coercion removal).

Run: `cargo check -p zsign-wasm`
Expected: `Finished` — no errors (confirms wasm migration compiles).

- [ ] **Step 1.6: Commit**

`git add -A && git commit -m "fix(core): emit no entitlements for non-executable binaries (ZSN-34)"`
(pre-commit hook runs `cargo fmt`/file hygiene automatically — if it
reports a fmt fix, let it restage and complete the commit).

---

### Task 2: IPA — standalone dylibs signed exactly once

**Files:**
- Modify: `crates/zsign/src/test_util.rs` (new fixture helper)
- Modify: `crates/zsign/src/ipa/mod.rs`
  (`sign_bundle` ~:368-404, `sign_single_bundle` ~:684-747,
  `find_immediate_macho_binaries` ~:752-789, tests from ~:1106)
- Test: same file, `#[cfg(test)]` module in `ipa/mod.rs`

- [ ] **Step 2.1: Add the MH_DYLIB fixture helper**

Append to `crates/zsign/src/test_util.rs` (modeled on
`minimal_macho_encrypted` at `:14-27`):

```rust
/// `minimal_macho()` with the Mach-O filetype patched to `MH_DYLIB` (6).
pub(crate) fn minimal_dylib() -> Vec<u8> {
    let mut data = minimal_macho();
    data[12..16].copy_from_slice(&6u32.to_le_bytes());
    data
}
```

- [ ] **Step 2.2: Write the failing end-to-end test (old API)**

Add to the tests module of `crates/zsign/src/ipa/mod.rs`:

```rust
#[test]
fn test_standalone_dylib_signed_exactly_once() {
    use zsign_core::codesign::verify::parse_superblob;

    let temp = TempDir::new().unwrap();
    let app = create_folder_bundle(temp.path(), "Test", true);
    std::fs::create_dir_all(app.join("Frameworks")).unwrap();
    std::fs::write(
        app.join("Frameworks").join("libfoo.dylib"),
        crate::test_util::minimal_dylib(),
    )
    .unwrap();

    let creds = crate::test_util::test_credentials();
    IpaSigner::new(&creds)
        .sign_folder_in_place(&app)
        .expect("folder containing a Frameworks dylib must sign");

    let data = std::fs::read(app.join("Frameworks").join("libfoo.dylib")).unwrap();
    let m = crate::macho::MachOFile::parse(data.clone()).unwrap();
    let sl = &m.slices()[0];
    let sig_off = sl.code_sig_offset.unwrap() as usize;
    let sig_len = sl.code_sig_size.unwrap() as usize;
    let sb = parse_superblob(&data[sig_off..sig_off + sig_len]).unwrap();
    let cd = sb
        .code_directory
        .as_ref()
        .expect("primary CodeDirectory must be present");

    assert_eq!(
        cd.identifier(),
        Some("libfoo"),
        "the standalone pass's file-stem identifier must be the on-disk identifier"
    );
    assert!(
        sb.entries.iter().any(|e| e.slot == 0x1000),
        "the standalone pass's dual code directories must survive: a second \
         sha256-only pass over the same file would leave a single SHA-256 CD"
    );
    assert!(
        sb.entries.iter().all(|e| e.slot != 0x0005),
        "no entitlements blob may be applied to a dylib"
    );

    let report = crate::verify::verify_bundle(&app).expect("verify must run");
    assert!(
        report.valid(),
        "ipa sign→verify must pass: {:?}",
        report.bundle.as_ref().map(|b| &b.errors)
    );
}
```

Test design rationale: without a provisioning profile the two passes emit
identical entitlements (`None`), so bytes cannot prove "signed once". The
discriminator is the code-directory shape — pass A signs with the dual
SHA-1+SHA-256 entries (`sign_standalone_dylib` → `sign_macho`,
`ipa/mod.rs:652`), pass B with the default `sha256_only = true`
single-CD path (`sign_binary` → `sign_macho_sha256_only`, `:1039`). Any
second pass destroys the `0x1000` alternate CD.

- [ ] **Step 2.3: Run the test to verify it fails**

Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-rs signed_exactly_once -- --skip test_ipa_signing_is_deterministic`
Expected: FAIL on the `0x1000` alternate-CD assertion (pass B re-signs the
dylib through the single-CD sha256-only path today).

- [ ] **Step 2.4: Thread the processed-path set**

(a) `sign_bundle` (`ipa/mod.rs:368-404`) — after the standalone loop
(`:384-387`) and before `collect_nested_bundles` (`:389`), materialize the
set; then pass it to every `sign_single_bundle` call:

```rust
let dylibs = self.find_standalone_dylibs(bundle_path)?;
dylibs
    .par_iter()
    .try_for_each(|dylib_path| self.sign_standalone_dylib(bundle_path, dylib_path))?;
let already_signed: HashSet<PathBuf> = dylibs.iter().cloned().collect();

let mut bundles = self.collect_nested_bundles(bundle_path)?;
bundles.sort_by_key(|b| std::cmp::Reverse(b.1));
for (nested_bundle_path, _depth) in &bundles {
    let is_main_bundle = nested_bundle_path == bundle_path;
    self.sign_single_bundle(
        nested_bundle_path,
        is_main_bundle,
        if is_main_bundle { entitlements } else { None },
        if is_main_bundle { profile_data } else { None },
        &already_signed,
    )?;
}
```

Add `use std::collections::HashSet;` to the module's imports if absent
(check first: `extract.rs` uses its own import; `ipa/mod.rs` may not have
one yet).

(b) `sign_single_bundle` (`:684`): add parameter
`already_signed: &HashSet<PathBuf>` after `profile_data`; forward it:
`let binaries = self.find_immediate_macho_binaries(bundle_path, already_signed)?;`

(c) `find_immediate_macho_binaries` (`:752`): add parameter
`already_signed: &HashSet<PathBuf>`; in the walk loop, change the push
condition from

```rust
if path != main_executable && self.is_macho_binary(path)? {
    binaries.push(path.to_path_buf());
}
```

to

```rust
if path != main_executable
    && !already_signed.contains(&path.to_path_buf())
    && self.is_macho_binary(path)?
{
    binaries.push(path.to_path_buf());
}
```

The main executable is pushed before this loop (`:757-760`) and is never
filtered — the main-executable contract (own CodeResources, bundle
identifier, entitlements) stays intact.

(d) Migrate the existing direct caller in the tests module
(`test_symlinked_dylib_is_skipped_and_target_untouched`, `ipa/mod.rs:1671-1707`,
`#[cfg(unix)]`): its `find_immediate_macho_binaries(&app)` call at `:1694`
becomes

```rust
let processed: std::collections::HashSet<_> = dylibs.iter().cloned().collect();
let binaries = signer.find_immediate_macho_binaries(&app, &processed).unwrap();
```

(`dylibs` is the variable already bound at `:1684`.) Extend its assertion
block with: the discovered real dylib must not reappear as an immediate
target when its path is in the processed set:

```rust
assert!(
    !binaries.contains(&app.join("real.dylib")),
    "a standalone-signed dylib must not be re-offered by the immediate walk: {binaries:?}"
);
```

Note: because this test is `#[cfg(unix)]`, it does not compile on
non-unix targets — that is fine: the production caller in
`sign_single_bundle` compiles the new signature on every target, so
`cargo check`/`clippy` still cover it everywhere.

- [ ] **Step 2.5: Run the test to verify it passes**

Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-rs signed_exactly_once -- --skip test_ipa_signing_is_deterministic`
Expected: PASS.

- [ ] **Step 2.6: Scoped neighbor runs**

Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-rs symlinked -- --skip test_ipa_signing_is_deterministic`
Expected: PASS (both migrated symlink tests — dylib and framework).

Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-rs ipa -- --skip test_ipa_signing_is_deterministic`
Expected: PASS (whole ipa tests module: path-security suite,
`test_ipa_signer_workflow`, missing-executable tolerance, etc. — catches
any regression from the signature changes).

- [ ] **Step 2.7: Commit**

`git add -A && git commit -m "fix(ipa): sign standalone dylibs exactly once (ZSN-34)"`

---

### Task 3: Shared nested-code predicate — XPC services discovered and sealed

**Files:**
- Modify: `crates/zsign/src/bundle/mod.rs` (new predicate + inline unit tests)
- Modify: `crates/zsign/src/ipa/mod.rs`
  (`collect_nested_bundles` doc ~:406, `is_bundle_directory` ~:431-437,
  `calculate_bundle_depth` ~:578-592, `filter_entry` ~:763-770, module doc
  ~:13-22, tests)
- Modify: `crates/zsign/src/verify.rs`
  (`is_bundle_dir` ~:143-152, `has_nested_bundle_component` ~:157-165,
  walk ~:447-476, docs ~:12-14 and ~:82, tests)
- Test: both inline test modules + new XPC test in `ipa/mod.rs`

- [ ] **Step 3.1: Write the failing XPC acceptance test**

Add to the tests module of `crates/zsign/src/ipa/mod.rs`:

```rust
#[test]
fn test_xpc_service_is_discovered_and_signed_as_nested_bundle() {
    use zsign_core::codesign::verify::parse_superblob;

    let temp = TempDir::new().unwrap();
    let app = create_folder_bundle(temp.path(), "Test", true);
    let xpc = app.join("XPCServices").join("Foo.xpc");
    std::fs::create_dir_all(&xpc).unwrap();
    std::fs::write(
        xpc.join("Info.plist"),
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
    <key>CFBundleIdentifier</key><string>com.test.foo.xpc</string>
    <key>CFBundleExecutable</key><string>Foo</string>
    <key>CFBundlePackageType</key><string>XPC!</string>
</dict></plist>"#,
    )
    .unwrap();
    std::fs::write(xpc.join("Foo"), crate::test_util::minimal_macho()).unwrap();

    // `.xpc` is not in the {app, framework, appex} whitelist: only the
    // Info.plist/location arms can discover this bundle.
    let bundles = IpaSigner::new_adhoc().collect_nested_bundles(&app).unwrap();
    assert!(
        bundles.iter().any(|(p, d)| p == &xpc && *d == 1),
        "the XPC service must be collected as a depth-1 nested bundle: {bundles:?}"
    );

    IpaSigner::new_adhoc()
        .sign_folder_in_place(&app)
        .expect("a folder containing an XPC service must sign");
    assert!(
        xpc.join("_CodeSignature/CodeResources").exists(),
        "the XPC bundle must be sealed with its own CodeResources"
    );

    let foo = std::fs::read(xpc.join("Foo")).unwrap();
    let m = crate::macho::MachOFile::parse(foo.clone()).unwrap();
    let sl = &m.slices()[0];
    let sig_off = sl.code_sig_offset.unwrap() as usize;
    let sig_len = sl.code_sig_size.unwrap() as usize;
    let sb = parse_superblob(&foo[sig_off..sig_off + sig_len]).unwrap();
    let cd = sb
        .code_directory
        .as_ref()
        .expect("primary CodeDirectory must be present");
    assert_eq!(
        cd.identifier(),
        Some("com.test.foo.xpc"),
        "the XPC binary must carry its bundle identifier, not its file stem"
    );
    let info_hash = cd
        .special_slot_hash(1)
        .expect("nested bundle main executable must bind its Info.plist slot -1");
    assert!(
        info_hash.iter().any(|&b| b != 0),
        "slot -1 must hold a real Info.plist hash"
    );
    assert!(
        sb.entries.iter().all(|e| e.slot != 0x0005),
        "a nested bundle binary must be signed without entitlements"
    );

    let vreport = crate::verify::verify_bundle(&app).expect("verify must run");
    assert!(
        vreport.valid(),
        "ipa sign→verify must pass: {:?}",
        vreport.bundle.as_ref().map(|b| &b.errors)
    );
    let bundle = vreport.bundle.as_ref().unwrap();
    assert_eq!(bundle.nested.len(), 1, "exactly the XPC service is nested");
    assert_eq!(
        bundle.nested[0].path, "XPCServices/Foo.xpc",
        "the verifier must recognize the XPC bundle by the same predicate"
    );
}
```

- [ ] **Step 3.2: Write the predicate unit tests (they fail to compile —
  the function does not exist yet)**

Add `#[cfg(test)] mod tests` at the end of `crates/zsign/src/bundle/mod.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn write_info_plist(dir: &Path, body: &str) {
        fs::write(
            dir.join("Info.plist"),
            format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>{body}</dict></plist>"#
            ),
        )
        .unwrap();
    }

    const MARKERS: &str = "<key>CFBundleIdentifier</key><string>com.test.x</string>\
         <key>CFBundleExecutable</key><string>X</string>";

    #[test]
    fn nested_bundle_dir_matches_every_arm_and_no_more() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();

        // Legacy extension arm: matches with no Info.plist at all.
        let fw = root.join("Loose.framework");
        fs::create_dir_all(&fw).unwrap();
        assert!(is_nested_bundle_dir(&fw));

        // Location arm: a plain directory under Frameworks/ is not code…
        let plain = root.join("Frameworks").join("Plain");
        fs::create_dir_all(&plain).unwrap();
        assert!(!is_nested_bundle_dir(&plain));
        // …but a marker-complete container there is.
        write_info_plist(&plain, MARKERS);
        assert!(is_nested_bundle_dir(&plain));

        // Markers alone, outside documented locations, without a
        // recognized package type: not nested code.
        let widget = root.join("Resources").join("Widget");
        fs::create_dir_all(&widget).unwrap();
        write_info_plist(&widget, MARKERS);
        assert!(!is_nested_bundle_dir(&widget));

        // Package-type arm: a renamed XPC container is recognized anywhere.
        let renamed = root.join("Whatever");
        fs::create_dir_all(&renamed).unwrap();
        write_info_plist(
            &renamed,
            &format!("{MARKERS}<key>CFBundlePackageType</key><string>XPC!</string>"),
        );
        assert!(is_nested_bundle_dir(&renamed));

        // BNDL is CFBundle's fallback default: never a nested-code signal.
        let bndl = root.join("Fallback");
        fs::create_dir_all(&bndl).unwrap();
        write_info_plist(
            &bndl,
            &format!("{MARKERS}<key>CFBundlePackageType</key><string>BNDL</string>"),
        );
        assert!(!is_nested_bundle_dir(&bndl));

        // Markers gated: location without Info.plist is not nested code.
        let no_plist = root.join("PlugIns").join("Thing");
        fs::create_dir_all(&no_plist).unwrap();
        assert!(!is_nested_bundle_dir(&no_plist));
    }
}
```

(`tempfile` is already a dev-dependency of this crate — `ipa/mod.rs` tests
use `TempDir`.)

- [ ] **Step 3.3: Run both tests to verify they fail**

Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-rs xpc_service -- --skip test_ipa_signing_is_deterministic`
Expected: FAIL — `collect_nested_bundles` does not collect `Foo.xpc`
(three-extension whitelist at `ipa/mod.rs:431-437`).

Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-rs nested_bundle_dir -- --skip test_ipa_signing_is_deterministic`
Expected: compilation FAIL — `is_nested_bundle_dir` is not defined.

- [ ] **Step 3.4: Implement the shared predicate**

Append to `crates/zsign/src/bundle/mod.rs` (before the new tests module):

```rust
/// Directories that Apple documents as nested-code locations
/// ("Placing content in a bundle"; TN2206 "Nested Code" Table 3).
/// `Extensions` is not Apple-documented; it is kept because upstream
/// zsign treats it as an app-extension location.
const NESTED_CODE_LOCATIONS: [&str; 7] = [
    "Frameworks",
    "SharedFrameworks",
    "PlugIns",
    "XPCServices",
    "Watch",
    "AppClips",
    "Extensions",
];

/// `CFBundlePackageType` values that identify a bundle container
/// (Bundle Programming Guide: `APPL`, `FMWK`; "Creating XPC Services":
/// `XPC!`). `BNDL` is excluded: it is CFBundle's fallback default.
const BUNDLE_PACKAGE_TYPES: [&str; 3] = ["APPL", "FMWK", "XPC!"];

/// True when `path` is a nested-code bundle directory.
///
/// A directory qualifies when it carries a legacy bundle extension
/// (`.app`, `.framework`, `.appex`), or when its child `Info.plist`
/// declares bundle markers (`CFBundleIdentifier` + `CFBundleExecutable`)
/// and it sits in a documented nested-code location or declares a
/// recognized `CFBundlePackageType`. Detection is best-effort: an
/// unreadable or unparseable `Info.plist` just means "not a bundle".
pub fn is_nested_bundle_dir(path: &Path) -> bool {
    if let Some(ext) = path.extension() {
        if matches!(
            ext.to_string_lossy().to_lowercase().as_str(),
            "app" | "framework" | "appex"
        ) {
            return true;
        }
    }

    let Some(markers) = bundle_markers(path) else {
        return false;
    };
    if !markers.0 || !markers.1 {
        return false;
    }

    let parent_is_location = path
        .parent()
        .and_then(|p| p.file_name())
        .map(|n| {
            let parent = n.to_string_lossy();
            NESTED_CODE_LOCATIONS
                .iter()
                .any(|location| location.eq_ignore_ascii_case(parent.as_ref()))
        })
        .unwrap_or(false);
    if parent_is_location {
        return true;
    }

    markers
        .2
        .is_some_and(|package_type| BUNDLE_PACKAGE_TYPES.contains(&package_type.as_str()))
}

/// `(has non-empty CFBundleIdentifier, has non-empty CFBundleExecutable,
/// CFBundlePackageType)` from `path/Info.plist`, or `None` when the file is
/// missing or unparseable.
fn bundle_markers(path: &Path) -> Option<(bool, bool, Option<String>)> {
    let data = std::fs::read(path.join("Info.plist")).ok()?;
    let value = plist::from_bytes::<plist::Value>(&data).ok()?;
    let dict = value.as_dictionary()?;
    let non_empty = |key: &str| {
        dict.get(key)
            .and_then(|v| v.as_string())
            .is_some_and(|s| !s.is_empty())
    };
    Some((
        non_empty("CFBundleIdentifier"),
        non_empty("CFBundleExecutable"),
        dict.get("CFBundlePackageType")
            .and_then(|v| v.as_string())
            .map(str::to_owned),
    ))
}
```

Add `use std::path::Path;` at the top of `bundle/mod.rs` if absent (the
module currently only re-exports `CodeResourcesBuilder`). Prefer a tuple
struct/destructuring over `markers.0/ markers.1/ markers.2` if clippy
flags tuple-field access (`clippy::type_complexity` does not apply to a
3-tuple; `get_first`-style lints may suggest named fields — a small
`struct BundleMarkers { has_identifier: bool, has_executable: bool,
package_type: Option<String> }` is the fallback and is equally acceptable).

- [ ] **Step 3.5: Run predicate unit tests**

Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-rs nested_bundle_dir -- --skip test_ipa_signing_is_deterministic`
Expected: PASS.

- [ ] **Step 3.6: Migrate the signer side (`ipa/mod.rs`)**

(a) Delete `is_bundle_directory` (`:431-437`). At its two call sites,
call `crate::bundle::is_nested_bundle_dir` instead:
- `collect_nested_bundles` (`:421`): `if entry.file_type().is_dir() &&
  crate::bundle::is_nested_bundle_dir(path) {`
- `find_immediate_macho_binaries` `filter_entry` (`:763-770`): keep the
  structure (`path != bundle_path && e.file_type().is_dir() &&
  crate::bundle::is_nested_bundle_dir(path)` → `return false;`).

(b) Rewrite `calculate_bundle_depth` (`:578-592`) to count prefixes with
the shared predicate (this also removes the case-sensitivity asymmetry):

```rust
fn calculate_bundle_depth(&self, bundle_path: &Path, root_bundle: &Path) -> usize {
    let Ok(relative) = bundle_path.strip_prefix(root_bundle) else {
        return 0;
    };

    let mut depth = 0;
    let mut prefix = root_bundle.to_path_buf();
    for component in relative.components() {
        prefix.push(component);
        if crate::bundle::is_nested_bundle_dir(&prefix) {
            depth += 1;
        }
    }

    depth
}
```

Intended behavior notes (call these out, do not "fix" them): the previous
implementation used `strip_prefix(root_bundle).unwrap_or(bundle_path)` and
still counted suffix components for paths not under the root — the rewrite
returns 0 instead. That is deliberate: callers only ever pass paths
collected from `root_bundle`, and depth feeds only the deepest-first sort
at `sign_bundle`. Re-evaluating `is_nested_bundle_dir` per component may
re-read an intermediate bundle's Info.plist once per component below it —
negligible for bundle-shaped trees and the price of one shared predicate.

(c) Doc updates in this file: the tree/module doc at `:13-22` (add an
`XPCServices/ └── *.xpc/` example under the tree if the doc shows a
layout), the `collect_nested_bundles` doc at `:406` ("Collect all nested
bundles (.app, .framework, .appex)" → "Collect all nested-code bundle
directories — see [`crate::bundle::is_nested_bundle_dir`]"), and the
`find_immediate_macho_binaries` doc at `:750-751` ("excludes binaries
inside nested .framework or .appex directories" → "excludes binaries
inside nested-code bundle directories").

- [ ] **Step 3.7: Migrate the verifier (`verify.rs`)**

(a) Delete `is_bundle_dir` (`:143-152`). At `:456`, replace with
`crate::bundle::is_nested_bundle_dir(p)`.

(b) Change `has_nested_bundle_component` (`:157-165)` to evaluate the
predicate on cumulative full paths:

```rust
/// True when any ancestor component of `rel` (below `root`) names a
/// nested-code bundle directory. With `ignore_last` the final component is
/// exempt, which lets a directory entry itself be the bundle while its
/// ancestors must not be.
fn has_nested_bundle_component(root: &Path, rel: &Path, ignore_last: bool) -> bool {
    let mut components: Vec<_> = rel.components().collect();
    if ignore_last {
        components.pop();
    }
    let mut prefix = root.to_path_buf();
    components
        .iter()
        .any(|c| {
            prefix.push(c);
            crate::bundle::is_nested_bundle_dir(&prefix)
        })
}
```

Note: `prefix.push` inside `any` accumulates across iterations (each
component extends the previous prefix) — that is the intended
cumulative-prefix evaluation; do not reset `prefix` per iteration.

(c) Update both call sites (`:456`, `:466`) to pass `root` as the first
argument (both sit inside `verify_bundle_dir(root, dir, rel)`, which has
it). If either call site constructs `rel` differently, re-read the
surrounding walk code (`:416-543`) before editing.

(d) Doc updates: module doc `:12-14` and `BundleVerification.nested` doc
`:82` — describe nested bundles as "nested-code bundles recognized by
[`crate::bundle::is_nested_bundle_dir`]" instead of listing extensions.

- [ ] **Step 3.8: Run the XPC acceptance test**

Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-rs xpc_service -- --skip test_ipa_signing_is_deterministic`
Expected: PASS (discovery, depth, own CodeResources, bundle identifier,
slot −1 bound, no entitlements, verifier recursion).

- [ ] **Step 3.9: Scoped neighbor runs**

Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-rs verify -- --skip test_ipa_signing_is_deterministic`
Expected: PASS (verifier suite: nested framework fixtures, tamper tests —
catches predicate desync between signer and verifier).

Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-rs bundle -- --skip test_ipa_signing_is_deterministic`
Expected: PASS (CodeResources suite — nested-bundle files still sealed in
the parent).

Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-rs ipa -- --skip test_ipa_signing_is_deterministic`
Expected: PASS (whole ipa module incl. symlinked-framework collection,
missing-executable tolerance, path-security suite).

- [ ] **Step 3.10: Commit**

`git add -A && git commit -m "feat(ipa): detect nested code by plist, location, and package type (ZSN-34)"`

---

### Task 4: Final gates and report (run once, at the end)

- [ ] **Step 4.1: Formatting**

Run: `cargo fmt --all --check`
Expected: no output (exit 0). If it reports diffs, run `cargo fmt --all`,
re-run the affected scoped tests, and amend nothing — commit the formatting
fix as its own `style:` commit.

- [ ] **Step 4.2: Clippy**

Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: 0 diagnostics.

- [ ] **Step 4.3: Full workspace test run**

Run: `TMPDIR=$PWD/.tmptmp cargo test --workspace --no-fail-fast -- --skip test_ipa_signing_is_deterministic`
Expected: all tests pass; paste verbatim summary lines into the final
report.

- [ ] **Step 4.4: Final report (no merge, no push)**

Produce the report: commit list with subjects, verbatim gate output for
4.1-4.3, and plan-vs-actual deviations. Stop after reporting — the
orchestrator lands the branch with `wt merge --no-squash`.

---

## Acceptance mapping (ticket → proof)

| Ticket acceptance | Proof |
|---|---|
| 1. MH_DYLIB asserts neither slot −5 nor an entitlements blob; still verifies via the existing verify path; new MH_DYLIB round-trip | `test_non_executable_signing_carries_no_entitlements` — four entries × (no `0x0005`/`0x0007` child, unbound −5, `verify_macho` valid) |
| 2. `Frameworks/*.dylib` under a root `.app` signed once, identifier stable, main-app entitlements never applied, ipa sign→verify passes | `test_standalone_dylib_signed_exactly_once` — identifier `libfoo`, surviving dual CD (`0x1000`) as the signed-once discriminator, no `0x0005`, `verify_bundle` valid; discovery seam locked by the migrated `test_symlinked_dylib_is_skipped_and_target_untouched` |
| 3. XPC-service-shaped fixture discovered and signed with bundle relationship intact; extension whitelist no longer the sole predicate | `test_xpc_service_is_discovered_and_signed_as_nested_bundle` — `.xpc` ∉ whitelist yet collected at depth 1, own `_CodeSignature/CodeResources`, bundle-id identifier, Info.plist slot −1 bound, no entitlements, verifier recognizes the same bundle (`nested[0].path`) |

Known coverage limit (recorded): no provisioning-profile fixture exists in
this workspace, so the item-2 test runs with `entitlements = None` on both
passes; the entitlements half of "main-app entitlements never applied" is
covered by the no-`0x0005` post-condition plus Task 1's coercion (which
guarantees that even if a profile were supplied, a non-executable emits no
entitlements slot).

## Self-review checklist

- [x] Spec coverage: design §3.1 → Task 1; §3.2 → Task 2; §3.3 → Task 3;
  §6 test strategy → test code in each task; §7 final gates → Task 4.
- [x] Placeholders: no TBD/TODO/"similar to" steps; every code step shows
  real code or an exact surgical diff.
- [x] Type consistency: `already_signed: &HashSet<PathBuf>` identical at
  all three threading sites; `is_nested_bundle_dir(&Path) -> bool` used by
  signer, depth, and verifier; test helpers reuse existing names
  (`create_folder_bundle`, `test_credentials`, `minimal_macho`,
  `parse_superblob`, `special_slot_hash`).
- [x] Red/green order: Task 1 test compiles against the old API and fails at
  runtime; Task 2 e2e test compiles against the old API (the discovery
  assertion is added only after the signature change); Task 3's acceptance
  test fails at runtime and the unit test fails to compile — both are valid
  red phases.
