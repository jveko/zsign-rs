# ZSN-35 Option Forwarding Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development
> (recommended) with dispatching-parallel-agents for independent tasks to
> implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for
> tracking. Tester subagent writes the failing test first; implementer subagent
> greens it; the controller runs the scoped gate and commits before the next task.

**Goal:** Make every CLI signing flag reach its signing sink with an observable
effect, reject the two missing flag conflicts at parse time, name the profile
path in read errors, and pin validate-before-mutation — with zero edits under
`crates/zsign/src/ipa/*`.

**Architecture:** All forwarding fixes live in `crates/zsign/src/builder.rs`
(chained `IpaSigner` setters; pre-sign dylib injection via
`zsign_core::macho::writer::inject_dylib_command`; identifier override; hoisted
profile-entitlements load; one `map_err`). Conflicts live in
`crates/zsign-cli/src/main.rs` as field-level `conflicts_with_all` in the
existing ZSN-5 style. Design decisions and the item-0 evidence matrix:
`docs/superpowers/specs/2026-09-26-option-forwarding-design.md`.

**Tech Stack:** Rust 2021 workspace; clap 4.6.7 derive; zip 7.2.0; goblin 0.10;
plist 1.7 (resolves 1.10.1); tempfile 3.10 (resolves 3.27.0) — all already
dependencies of `zsign`.

**Shared conventions (apply to every task):**
- Scoped gate only, always with the brief's env conventions:
  - builder tasks: `mkdir -p .tmptmp && TMPDIR=$PWD/.tmptmp cargo test -p zsign-rs <filter> -- --skip test_ipa_signing_is_deterministic`
  - CLI tasks: `mkdir -p .tmptmp && TMPDIR=$PWD/.tmptmp cargo test -p zsign-cli <filter> -- --skip test_ipa_signing_is_deterministic`
- TDD: the failing test must be observed red BEFORE the production edit of the
  same task; run the test by name.
- Ticket IDs go in commit subjects only, never in code comments.
- If `.tmptmp/` shows up as untracked after test runs, do NOT commit it and do
  NOT edit `.gitignore` (repo hygiene is the docs lane's; note it in the report).
- Every test below must fail on the unmodified tree for the reason stated.
- Never edit anything under `crates/zsign/src/ipa/*` or
  `crates/zsign-core/src/macho/signer.rs`.

**Shared test helpers (defined once, in the `crates/zsign/src/builder.rs` test
module — Task 1 introduces them; Tasks 2-4 reuse them unchanged):**

```rust
// Entry names inside the fixture/output IPA (mirrors ipa/mod.rs write_test_ipa,
// which is #[cfg(test)]-private to that module and fenced).
const FIXTURE_PLIST: &[u8] = br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleExecutable</key><string>Test</string>
  <key>CFBundleIdentifier</key><string>com.zsign.test</string>
</dict></plist>"#;

fn write_ipa_fixture(path: &std::path::Path) {
    use std::io::Write;
    use zip::write::SimpleFileOptions;
    let file = std::fs::File::create(path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    let opts = SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    zip.start_file("Payload/Test.app/Info.plist", opts).unwrap();
    zip.write_all(FIXTURE_PLIST).unwrap();
    zip.start_file("Payload/Test.app/Test", opts).unwrap();
    zip.write_all(&crate::test_util::minimal_macho()).unwrap();
    zip.start_file("Payload/Test.app/data.bin", opts).unwrap();
    zip.write_all(&[0xCD; 4096]).unwrap();
    zip.finish().unwrap();
}

/// Read one entry's bytes back out of an IPA.
fn ipa_entry(path: &std::path::Path, name: &str) -> Vec<u8> {
    use std::io::Read;
    let f = std::fs::File::open(path).unwrap();
    let mut zip = zip::ZipArchive::new(f).unwrap();
    let mut buf = Vec::new();
    zip.by_name(name).unwrap().read_to_end(&mut buf).unwrap();
    buf
}

/// Locate the code signature of a thin Mach-O and parse its SuperBlob.
/// LC_CODE_SIGNATURE lookup follows the repo idiom at
/// zsign-core/src/macho/signer.rs:1364-1376 (goblin 0.10 MachO has no
/// `code_signature` field — only the `CommandVariant::CodeSignature` variant).
fn thin_code_signature(bytes: &[u8]) -> crate::codesign::verify::SuperBlob<'_> {
    use goblin::mach::load_command::CommandVariant;
    let mach = goblin::mach::Mach::parse(bytes).unwrap();
    let macho = match mach {
        goblin::mach::Mach::Binary(b) => b,
        goblin::mach::Mach::Fat(_) => panic!("thin binary expected"),
    };
    let lc = macho
        .load_commands
        .iter()
        .find_map(|cmd| match cmd.command {
            CommandVariant::CodeSignature(cs) => Some(cs),
            _ => None,
        })
        .expect("LC_CODE_SIGNATURE");
    let start = lc.dataoff as usize;
    let end = start + lc.datasize as usize;
    crate::codesign::verify::parse_superblob(&bytes[start..end]).unwrap()
}

fn has_sha1_directory(sb: &crate::codesign::verify::SuperBlob<'_>) -> bool {
    sb.code_directory.as_ref().is_some_and(|cd| cd.is_sha1())
        || sb.alternate_code_directories.iter().any(|cd| cd.is_sha1())
}
```

Notes verified against source: `goblin`, `zip`, `plist`, `tempfile` are direct
deps of `crates/zsign` (Cargo.toml:18-26); `parse_superblob`/`SuperBlob`
fields/`CodeDirectory::is_sha1` are pub
(`zsign-core/src/codesign/verify.rs:68-74,87,811`); `crate::test_util` is the
existing test-only credential/fixture module (lib.rs:51-52).

---

### Task 1: `sign_ipa` forwards `sha256_only`, `bundle_name`, `bundle_version` (claim a)

**Files:**
- Test: `crates/zsign/src/builder.rs` (`#[cfg(test)] mod tests`, append)
- Modify: `crates/zsign/src/builder.rs` `sign_ipa` (chain at :393-419)

- [ ] **Step 1: Write the failing test** (includes the shared helpers above)

Append to the builder tests module:

```rust
    #[test]
    fn test_sign_ipa_forwards_bundle_options() {
        use crate::test_util::test_credentials;
        let dir = tempfile::TempDir::new().unwrap();
        let input = dir.path().join("in.ipa");
        write_ipa_fixture(&input);

        // Control: ZSign defaults — sha256_only=true, no name/version rewrites.
        let control = dir.path().join("control.ipa");
        ZSign::new()
            .credentials(test_credentials())
            .sign_ipa(&input, &control)
            .expect("control sign");

        // Treatment: forwarded options must reach the output.
        let out = dir.path().join("out.ipa");
        ZSign::new()
            .credentials(test_credentials())
            .bundle_name("Renamed")
            .bundle_version("9.9")
            .sha256_only(false)
            .sign_ipa(&input, &out)
            .expect("treatment sign");

        let plist: plist::Value =
            plist::from_bytes(&ipa_entry(&out, "Payload/Test.app/Info.plist")).unwrap();
        let dict = plist.as_dictionary().unwrap();
        assert_eq!(
            dict.get("CFBundleDisplayName").unwrap().as_string().unwrap(),
            "Renamed"
        );
        assert_eq!(
            dict.get("CFBundleShortVersionString").unwrap().as_string().unwrap(),
            "9.9"
        );

        let control_exe = ipa_entry(&control, "Payload/Test.app/Test");
        let treatment_exe = ipa_entry(&out, "Payload/Test.app/Test");
        assert!(
            !has_sha1_directory(&thin_code_signature(&control_exe)),
            "default sha256_only must emit no SHA-1 directory"
        );
        assert!(
            has_sha1_directory(&thin_code_signature(&treatment_exe)),
            "sha256_only(false) must be forwarded as a dual directory"
        );
    }
```

- [ ] **Step 2: Run the test to verify it FAILS**

Run: `mkdir -p .tmptmp && TMPDIR=$PWD/.tmptmp cargo test -p zsign-rs test_sign_ipa_forwards_bundle_options -- --skip test_ipa_signing_is_deterministic`
Expected: FAIL — `CFBundleDisplayName` missing (control: present-but-old name is
absent entirely; plist has no such key) and/or `"sha256_only(false) must be
forwarded as a dual directory"`. Any of these assertions failing proves the gap.

- [ ] **Step 3: Forward the three options in `sign_ipa`**

Edit `sign_ipa` (builder.rs:393-419). Both construction branches gain
`.sha256_only(self.sha256_only)` right after `.compression_level(...)` (matching
`sign_bundle` builder.rs:443/446), and the chain gains the two rewrites next to
the existing `bundle_id` forwarding (:414-416):

```rust
        let mut signer = if self.adhoc {
            IpaSigner::new_adhoc()
                .compression_level(self.compression_level)
                .sha256_only(self.sha256_only)
        } else {
            let credentials = self
                .credentials
                .as_ref()
                .ok_or_else(|| Error::MissingCredentials("No credentials configured".into()))?;
            IpaSigner::new(credentials)
                .compression_level(self.compression_level)
                .sha256_only(self.sha256_only)
        };
        // ... existing dylibs / allow_encrypted / profile forwarding unchanged ...
        if let Some(ref id) = self.bundle_id {
            signer = signer.bundle_id(id);
        }
        if let Some(ref name) = self.bundle_name {
            signer = signer.bundle_name(name.as_str());
        }
        if let Some(ref version) = self.bundle_version {
            signer = signer.bundle_version(version.as_str());
        }

        signer.sign(input, output)
```

No other call sites change (`sign_bundle` already forwards these; `IpaSigner`
setters exist at `ipa/mod.rs:204/213/223` — read-only).

- [ ] **Step 4: Run the test to verify it PASSES**

Run: same command as Step 2.
Expected: PASS `1 test passed`.

- [ ] **Step 5: Scoped regression gate for the touched crate**

Run: `mkdir -p .tmptmp && TMPDIR=$PWD/.tmptmp cargo test -p zsign-rs builder -- --skip test_ipa_signing_is_deterministic`
Expected: PASS (all builder tests, old and new).

- [ ] **Step 6: Commit**

`git add crates/zsign/src/builder.rs && git commit -m "fix(zsign): forward sign_ipa options to IpaSigner (ZSN-35)"`

---

### Task 2: `sign_bundle` forwards `compression_level` (claim b)

**Files:**
- Test: `crates/zsign/src/builder.rs` tests
- Modify: `crates/zsign/src/builder.rs` `sign_bundle` (chain at :440-463)

- [ ] **Step 1: Write the failing test**

```rust
    #[test]
    fn test_sign_bundle_forwards_compression_level() {
        use crate::test_util::{minimal_macho, test_credentials};
        use std::io::Write;

        let dir = tempfile::TempDir::new().unwrap();
        let app = dir.path().join("Test.app");
        std::fs::create_dir_all(&app).unwrap();
        std::fs::write(app.join("Info.plist"), FIXTURE_PLIST).unwrap();
        std::fs::write(app.join("Test"), minimal_macho()).unwrap();
        let mut f = std::fs::File::create(app.join("data.bin")).unwrap();
        f.write_all(&[0xCD; 2048]).unwrap();

        let out = dir.path().join("out.ipa");
        ZSign::new()
            .credentials(test_credentials())
            .compression_level(0)
            .sign_bundle(&app, Some(&out))
            .expect("folder to ipa must succeed");

        let f = std::fs::File::open(&out).unwrap();
        let mut zip = zip::ZipArchive::new(f).unwrap();
        let entry = zip.by_name("Payload/Test.app/Info.plist").unwrap();
        assert_eq!(
            entry.compression(),
            zip::CompressionMethod::Stored,
            "compression_level(0) must reach the repack as Stored"
        );
    }
```

(`FIXTURE_PLIST` and `write_ipa_fixture` are the shared helpers defined at the
top of this plan, living in the same `mod tests`; reference them directly. The
`.app` layout mirrors `test_sign_bundle_folder_in_place` at builder.rs:577-605.)

- [ ] **Step 2: Run the test to verify it FAILS**

Run: `mkdir -p .tmptmp && TMPDIR=$PWD/.tmptmp cargo test -p zsign-rs test_sign_bundle_forwards_compression_level -- --skip test_ipa_signing_is_deterministic`
Expected: FAIL — `left: Deflated, right: Stored` (repack runs at IpaSigner
default 6).

- [ ] **Step 3: Forward the compression level in `sign_bundle`**

Both construction branches gain `.compression_level(self.compression_level)`
immediately after construction, mirroring `sign_ipa` (builder.rs:397,403):

```rust
        let mut signer = if self.adhoc {
            crate::ipa::IpaSigner::new_adhoc()
                .compression_level(self.compression_level)
                .sha256_only(self.sha256_only)
        } else {
            let credentials = self.get_credentials()?;
            crate::ipa::IpaSigner::new(credentials)
                .compression_level(self.compression_level)
                .sha256_only(self.sha256_only)
        };
```

- [ ] **Step 4: Run the test to verify it PASSES**

Run: same command as Step 2. Expected: PASS.

- [ ] **Step 5: Scoped regression gate**

Run: `mkdir -p .tmptmp && TMPDIR=$PWD/.tmptmp cargo test -p zsign-rs builder -- --skip test_ipa_signing_is_deterministic`
Expected: PASS.

- [ ] **Step 6: Commit**

`git add crates/zsign/src/builder.rs && git commit -m "fix(zsign): forward compression level into sign_bundle (ZSN-35)"`

---

### Task 3: `sign_macho` applies configured dylibs and `bundle_id` (claim c)

**Files:**
- Test: `crates/zsign/src/builder.rs` tests
- Modify: `crates/zsign/src/builder.rs` `sign_macho` (:302-358)

- [ ] **Step 1: Write the failing test**

```rust
    #[test]
    fn test_sign_macho_applies_dylibs_and_bundle_id() {
        use crate::test_util::{minimal_macho, test_credentials};

        let dir = tempfile::TempDir::new().unwrap();
        let input = dir.path().join("app.bin");
        std::fs::write(&input, minimal_macho()).unwrap();
        let out = dir.path().join("signed.bin");

        ZSign::new()
            .credentials(test_credentials())
            .dylib_injection(vec!["/usr/lib/libzsn.dylib".to_string()], false)
            .bundle_id("com.zsign.forwarded")
            .sign_macho(&input, &out)
            .expect("sign");

        let signed = std::fs::read(&out).unwrap();

        // (1) the injected dylib appears as a load command in the SIGNED output
        let mach = goblin::mach::Mach::parse(&signed).unwrap();
        let macho = match mach {
            goblin::mach::Mach::Binary(b) => b,
            goblin::mach::Mach::Fat(_) => panic!("thin binary expected"),
        };
        assert!(
            macho.libs.contains(&"/usr/lib/libzsn.dylib"),
            "injected dylib missing from signed load commands: {:?}",
            macho.libs
        );

        // (2) bundle_id becomes the code-signing identifier
        let sb = thin_code_signature(&signed);
        let cd = sb.code_directory.as_ref().expect("code directory");
        assert_eq!(
            cd.identifier(),
            Some("com.zsign.forwarded"),
            "configured bundle_id must replace the file-stem identifier"
        );
    }
```

(`goblin::mach::MachO::libs` collects `LC_LOAD_DYLIB`/`LC_LOAD_WEAK_DYLIB`
paths; `CodeDirectory::identifier()` is pub — used the same way at
`zsign-core/src/codesign/verify.rs:1525`.)

- [ ] **Step 2: Run the test to verify it FAILS**

Run: `mkdir -p .tmptmp && TMPDIR=$PWD/.tmptmp cargo test -p zsign-rs test_sign_macho_applies_dylibs_and_bundle_id -- --skip test_ipa_signing_is_deterministic`
Expected: FAIL — `injected dylib missing from signed load commands` (identifier
assertion comes second and also fails on the unmodified tree).

- [ ] **Step 3: Inject dylibs before signing; override the identifier**

Rewrite the head of `sign_macho` (builder.rs:302-310). Read the bytes once,
inject every configured dylib into the bytes **before** parsing (load commands
are hashed into the CodeDirectory — injection must precede signing), then take
`bundle_id` as identifier with the current file-stem logic as fallback:

```rust
    pub fn sign_macho(&self, input: impl AsRef<Path>, output: impl AsRef<Path>) -> Result<()> {
        self.validate()?;
        let mut bytes = std::fs::read(input.as_ref())?;
        for dylib in &self.dylibs {
            bytes = zsign_core::macho::writer::inject_dylib_command(
                &bytes,
                dylib,
                self.weak_dylibs,
            )?;
        }
        let macho = MachOFile::parse(bytes)?;

        let identifier = match self.bundle_id {
            Some(ref id) => id.as_str(),
            None => input
                .as_ref()
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("unknown"),
        };
```

Match the exact import style for `inject_dylib_command` to what
`crates/zsign/src/ipa/mod.rs` already uses for the same function (read-only —
copy the path/`use` convention, do not edit that file). The four sign calls
below stay untouched in this task.

- [ ] **Step 4: Run the test to verify it PASSES**

Run: same command as Step 2. Expected: PASS.

- [ ] **Step 5: Scoped regression gate**

Run: `mkdir -p .tmptmp && TMPDIR=$PWD/.tmptmp cargo test -p zsign-rs builder -- --skip test_ipa_signing_is_deterministic`
Expected: PASS (includes the existing FAT routing tests — injection leaves
non-dylib inputs byte-identical when `dylibs` is empty, so FAT paths are
unaffected).

- [ ] **Step 6: Commit**

`git add crates/zsign/src/builder.rs && git commit -m "fix(zsign): apply dylibs and bundle id in sign_macho (ZSN-35)"`

---

### Task 4: ad-hoc `sign_macho` applies profile entitlements (claim d)

**Files:**
- Test: `crates/zsign/src/builder.rs` tests
- Modify: `crates/zsign/src/builder.rs` `sign_macho` adhoc branch (:312-320)

- [ ] **Step 1: Write the failing test**

```rust
    const PROFILE_FIXTURE: &[u8] = br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Entitlements</key>
  <dict>
    <key>application-identifier</key>
    <string>TESTTEAM.com.zsign.test.entitlement</string>
  </dict>
  <key>ExpirationDate</key>
  <date>2099-01-01T00:00:00Z</date>
</dict></plist>"#;

    #[test]
    fn test_sign_macho_adhoc_applies_profile_entitlements() {
        use crate::test_util::minimal_macho;
        use crate::codesign::constants::CSSLOT_ENTITLEMENTS;

        let dir = tempfile::TempDir::new().unwrap();
        let profile = dir.path().join("test.mobileprovision");
        std::fs::write(&profile, PROFILE_FIXTURE).unwrap();
        let input = dir.path().join("app.bin");
        std::fs::write(&input, minimal_macho()).unwrap();

        // Control: adhoc without a profile must not carry an entitlements slot.
        let control = dir.path().join("control.bin");
        ZSign::new().adhoc(true).sign_macho(&input, &control).expect("control");
        let control_bytes = std::fs::read(&control).unwrap();
        let control_sb = thin_code_signature(&control_bytes);
        assert!(
            !control_sb.entries.iter().any(|e| e.slot == CSSLOT_ENTITLEMENTS),
            "control must not carry an entitlements slot"
        );

        // Treatment: the profile's entitlements must reach the signed output.
        let out = dir.path().join("signed.bin");
        ZSign::new()
            .adhoc(true)
            .provisioning_profile(&profile)
            .sign_macho(&input, &out)
            .expect("adhoc sign with profile");
        let signed_bytes = std::fs::read(&out).unwrap();
        let sb = thin_code_signature(&signed_bytes);
        let ent = sb
            .entries
            .iter()
            .find(|e| e.slot == CSSLOT_ENTITLEMENTS)
            .expect("entitlements slot must be present");
        assert!(
            String::from_utf8_lossy(ent.blob).contains("com.zsign.test.entitlement"),
            "entitlements slot must carry the profile's entitlements"
        );
    }
```

Fixture rationale: `extract_entitlements_from_profile` is public and
deliberately CMS-unverified (`zsign-core/src/provisioning.rs:379-385`, doc
comment) — an XML plist with a top-level `Entitlements` dict
(`entitlements_to_xml`, provisioning.rs:362-371) is a complete input. The
0x0005 entry is emitted for signed executables (read side:
`macho/verify.rs:250,326`).

- [ ] **Step 2: Run the test to verify it FAILS**

Run: `mkdir -p .tmptmp && TMPDIR=$PWD/.tmptmp cargo test -p zsign-rs test_sign_macho_adhoc_applies_profile_entitlements -- --skip test_ipa_signing_is_deterministic`
Expected: FAIL — `entitlements slot must be present` (control passes: adhoc
without profile already emits none).

- [ ] **Step 3: Hoist the profile-entitlements load above the adhoc branch**

Keep the current branch shape (builder.rs:312-353) and make exactly three
surgical edits — no other restructuring:

1. Move `let entitlements = self.load_entitlements_from_profile()?;` from
   inside the credentialed branch (builder.rs:323) to just before
   `let signed_binary = if self.adhoc {` (builder.rs:312), so it runs once per
   call, after `validate()` (which stays the first statement — invariant).
2. In the adhoc call (builder.rs:313-320), replace the third argument `None`
   with `entitlements.as_deref()`.
3. Delete the now-duplicate `let entitlements = ...` line at builder.rs:323.
   The credentialed branch already passes `entitlements.as_deref()` at
   builder.rs:328/:338/:348 — those call sites do not change.

Result (head of the function, showing only the changed region):

```rust
        let entitlements = self.load_entitlements_from_profile()?;
        let signed_binary = if self.adhoc {
            crate::macho::sign_macho_adhoc(
                &macho,
                identifier,
                entitlements.as_deref(),
                None,
                None,
                self.allow_encrypted,
            )?
        } else {
            let credentials = self.get_credentials()?;
            if self.sha256_only {
                crate::macho::sign_macho_sha256_only(
                    &macho,
                    identifier,
                    entitlements.as_deref(),
                    credentials,
                    None,
                    None,
                    self.allow_encrypted,
                )?
            } else if macho.is_fat() {
                crate::macho::sign_any_macho(
                    &macho,
                    identifier,
                    entitlements.as_deref(),
                    credentials,
                    None,
                    None,
                    self.allow_encrypted,
                )?
            } else {
                sign_macho(
                    &macho,
                    identifier,
                    entitlements.as_deref(),
                    credentials,
                    None,
                    None,
                    self.allow_encrypted,
                )?
            }
        };
```

Observable contract: one profile read per call; adhoc passes the loaded
entitlements; credentialed behavior byte-identical to before.

- [ ] **Step 4: Run the test to verify it PASSES**

Run: same command as Step 2. Expected: PASS.

- [ ] **Step 5: Scoped regression gate**

Run: `mkdir -p .tmptmp && TMPDIR=$PWD/.tmptmp cargo test -p zsign-rs builder -- --skip test_ipa_signing_is_deterministic`
Expected: PASS (adhoc FAT-rejection test unaffected: no profile configured
there → `load_entitlements_from_profile` returns `Ok(None)` without I/O).

- [ ] **Step 6: Commit**

`git add crates/zsign/src/builder.rs && git commit -m "fix(zsign): apply profile entitlements in adhoc sign_macho (ZSN-35)"`

---

### Task 5: parse-time conflicts for `-2`/`-L` and `-a`/`-m` (claim e)

**Files:**
- Test: `crates/zsign-cli/src/main.rs` test module
- Modify: `crates/zsign-cli/src/main.rs` `legacy_sha1` (:90-91) and `adhoc` (:99-100) arg attributes

- [ ] **Step 1: Write the failing tests**

Append next to the existing conflict tests (after
`verify_conflicts_with_sign_only_flags`, main.rs:1591):

```rust
    #[test]
    fn sha256_only_conflicts_with_legacy_sha1_at_parse() {
        assert_eq!(
            parse_err(&["zsign", "-2", "-L", "in.ipa"]).kind(),
            clap::error::ErrorKind::ArgumentConflict
        );
        assert_eq!(
            parse_err(&["zsign", "-L", "-2", "in.ipa"]).kind(),
            clap::error::ErrorKind::ArgumentConflict
        );
        // each flag alone stays valid (adhoc supplies the credentials exemption)
        assert!(Cli::try_parse_from(["zsign", "-a", "-2", "in.ipa"]).is_ok());
        assert!(Cli::try_parse_from(["zsign", "-a", "-L", "in.ipa"]).is_ok());
    }

    #[test]
    fn adhoc_conflicts_with_profile_at_parse() {
        assert_eq!(
            parse_err(&["zsign", "-a", "-m", "p.mobileprovision", "in.ipa"]).kind(),
            clap::error::ErrorKind::ArgumentConflict
        );
        assert_eq!(
            parse_err(&["zsign", "-m", "p.mobileprovision", "-a", "in.ipa"]).kind(),
            clap::error::ErrorKind::ArgumentConflict
        );
        // profile stays valid with credentials and without adhoc
        assert!(Cli::try_parse_from([
            "zsign", "--pkcs12", "x.p12", "-p", "pw", "-m", "p.mobileprovision", "in.ipa"
        ])
        .is_ok());
        // adhoc without a profile stays valid
        assert!(Cli::try_parse_from(["zsign", "-a", "in.ipa"]).is_ok());
    }
```

- [ ] **Step 2: Run the tests to verify they FAIL**

Run: `mkdir -p .tmptmp && TMPDIR=$PWD/.tmptmp cargo test -p zsign-cli conflicts_with -- --skip test_ipa_signing_is_deterministic`
Expected: the two NEW tests FAIL (parse succeeds today → `parse_err` panics
with "must be rejected"); the existing conflict tests stay green.

- [ ] **Step 3: Declare the conflicts (existing ZSN-5 style)**

On the two fields (declaration is symmetric in clap 4.6.7; conflicts validate
before `required_unless_present_any`, `clap_builder-4.6.7/src/parser/validator.rs:54-57`):

```rust
    /// Legacy SHA-1 + SHA-256 dual code directories (iOS <= 10 only).
    /// Emitting a SHA-1 primary directory makes output fail
    /// `codesign --verify` on modern macOS.
    #[arg(short = 'L', long, conflicts_with_all = ["sha256_only"])]
    legacy_sha1: bool,
```

```rust
    /// Sign without an identity (ad-hoc)
    #[arg(short = 'a', long, conflicts_with_all = ["profile"])]
    adhoc: bool,
```

Keep each flag's existing doc comment exactly as-is (only the `#[arg(...)]`
line changes). Use `conflicts_with_all` (not plain `conflicts_with`) — the repo
has no plain `conflicts_with` anywhere and a second convention is prohibited.
Do NOT touch the `credentials` ArgGroup (main.rs:15-21 `multiple(true)` rationale).

- [ ] **Step 4: Run the tests to verify they PASS**

Run: same command as Step 2. Expected: all tests matching `conflicts_with` pass.

- [ ] **Step 5: Scoped regression gate (CLI parse surface + full CLI suite)**

Run: `mkdir -p .tmptmp && TMPDIR=$PWD/.tmptmp cargo test -p zsign-cli -- --skip test_ipa_signing_is_deterministic`
Expected: PASS — critical existing tests that must remain green:
`verify_conflicts_with_sign_only_flags` (its `-V … -2` row still yields
ArgumentConflict), `credentials_group_required_unless_adhoc_or_verify`,
`zip_level_range_is_enforced_at_parse`, `short_is_password…`.

- [ ] **Step 6: Commit**

`git add crates/zsign-cli/src/main.rs && git commit -m "feat(cli): reject conflicting signing flags at parse time (ZSN-35)"`

---

### Task 6: profile read errors name the file (claim h, builder site)

**Files:**
- Test: `crates/zsign-cli/src/main.rs` test module
- Modify: `crates/zsign/src/builder.rs` `load_entitlements_from_profile` (:486-495)

- [ ] **Step 1: Write the failing test**

Reuse the `IDENTITY_P12` recipe (`include_bytes!` const at main.rs:1070-1071;
`key_route_pkcs12_content_loads_with_password` main.rs:1329 writes it to a temp
file):

```rust
    #[test]
    fn missing_profile_error_names_the_file() {
        let dir = TempDir::new().unwrap();
        let key = dir.path().join("identity.p12");
        std::fs::write(&key, IDENTITY_P12).unwrap();
        let input = dir.path().join("in.bin");
        std::fs::write(&input, MINIMAL_MACHO).unwrap();
        let out = dir.path().join("out.bin");
        let profile = dir.path().join("absent.mobileprovision");
        let r = run_cli(
            &[
                OsStr::new("-k"),
                key.as_os_str(),
                OsStr::new("-p"),
                OsStr::new("testpassword"),
                OsStr::new("-m"),
                profile.as_os_str(),
                OsStr::new("-o"),
                out.as_os_str(),
                input.as_os_str(),
            ],
            &[],
        );
        assert_eq!(r.code, 1, "expected 1, stderr: {}", r.stderr);
        assert!(
            r.stderr.contains("absent.mobileprovision"),
            "stderr must name the profile file: {}",
            r.stderr
        );
        assert!(
            r.stderr.contains("provisioning profile"),
            "stderr must name the label: {}",
            r.stderr
        );
    }
```

The input MUST be a bare Mach-O: `.ipa`/`.app` inputs read the profile at the
`ipa/mod.rs:296` seam, which is lane zsn34's and stays unfixed by design.

- [ ] **Step 2: Run the test to verify it FAILS**

Run: `mkdir -p .tmptmp && TMPDIR=$PWD/.tmptmp cargo test -p zsign-cli missing_profile_error_names_the_file -- --skip test_ipa_signing_is_deterministic`
Expected: FAIL — stderr is `error: IO error: No such file or directory (os error 2)`
(pathless; the filename assertion fails).

- [ ] **Step 3: Wrap the read with path context**

Edit `load_entitlements_from_profile` (builder.rs:486-495; the bare read is at
builder.rs:488) — keep the existing
`Error::Io` variant and `?` conversion, wrap the io error so its Display names
label + path (phrasing mirrors `read_credential_file`, main.rs:768-774; exit
code stays 1 because `run()`'s `Err` arm maps to 1, main.rs:144-151):

```rust
    fn load_entitlements_from_profile(&self) -> Result<Option<Vec<u8>>> {
        if let Some(ref profile_path) = self.provisioning_profile {
            let profile_data = std::fs::read(profile_path).map_err(|e| {
                std::io::Error::new(
                    e.kind(),
                    format!(
                        "failed to read provisioning profile '{}': {e}",
                        profile_path.display()
                    ),
                )
            })?;
            match extract_entitlements_from_profile(&profile_data)? {
                Some(entitlements) => return Ok(Some(entitlements)),
                None => return Ok(None),
            }
        }
        Ok(None)
    }
```

(`map_err` yields `std::io::Error`, which the existing `#[from]
std::io::Error` converts to `Error::Io` unchanged — no enum changes.)

- [ ] **Step 4: Run the test to verify it PASSES**

Run: same command as Step 2. Expected: PASS.

- [ ] **Step 5: Scoped regression gates (both crates touched conceptually)**

Run: `mkdir -p .tmptmp && TMPDIR=$PWD/.tmptmp cargo test -p zsign-cli credential -- --skip test_ipa_signing_is_deterministic`
Expected: PASS — `credential_io_errors_name_the_file` and friends unaffected.
Run: `mkdir -p .tmptmp && TMPDIR=$PWD/.tmptmp cargo test -p zsign-rs builder -- --skip test_ipa_signing_is_deterministic`
Expected: PASS.

- [ ] **Step 6: Commit**

`git add crates/zsign/src/builder.rs crates/zsign-cli/src/main.rs && git commit -m "fix(zsign): name the profile path in read errors (ZSN-35)"`

---

### Task 7: pin validate-before-mutation (claim i — already satisfied; regression test only)

**Files:**
- Test: `crates/zsign/src/builder.rs` tests (test-only change; production code untouched)

- [ ] **Step 1: Write the regression test**

```rust
    #[test]
    fn validate_failure_leaves_input_tree_untouched() {
        use crate::test_util::minimal_macho;

        let dir = tempfile::TempDir::new().unwrap();

        // .app: abort before any bundle mutation
        let app = dir.path().join("Test.app");
        std::fs::create_dir_all(&app).unwrap();
        std::fs::write(app.join("Info.plist"), FIXTURE_PLIST).unwrap();
        std::fs::write(app.join("Test"), minimal_macho()).unwrap();
        let plist_before = std::fs::read(app.join("Info.plist")).unwrap();
        let result = ZSign::new().sign_bundle(&app, None);
        assert!(matches!(result, Err(Error::MissingCredentials(_))));
        assert!(!app.join("_CodeSignature").exists());
        assert_eq!(std::fs::read(app.join("Info.plist")).unwrap(), plist_before);

        // .ipa: output must never be created, input bytes unchanged
        let ipa = dir.path().join("in.ipa");
        write_ipa_fixture(&ipa);
        let ipa_before = std::fs::read(&ipa).unwrap();
        let out = dir.path().join("out.ipa");
        let result = ZSign::new().sign_ipa(&ipa, &out);
        assert!(matches!(result, Err(Error::MissingCredentials(_))));
        assert!(!out.exists());
        assert_eq!(std::fs::read(&ipa).unwrap(), ipa_before);

        // bare macho: output must never be created
        let input = dir.path().join("app.bin");
        std::fs::write(&input, minimal_macho()).unwrap();
        let out_bin = dir.path().join("signed.bin");
        let result = ZSign::new().sign_macho(&input, &out_bin);
        assert!(matches!(result, Err(Error::MissingCredentials(_))));
        assert!(!out_bin.exists());
    }
```

- [ ] **Step 2: Run the test**

Run: `mkdir -p .tmptmp && TMPDIR=$PWD/.tmptmp cargo test -p zsign-rs validate_failure_leaves_input_tree_untouched -- --skip test_ipa_signing_is_deterministic`
Expected: PASS **on the unmodified tree** — this is deliberate: item 0(i) was
audited ALREADY SATISFIED (validate() is the first statement of all three
entries, builder.rs:303/394/440), so this task pins the invariant rather than
driving a red→green cycle. If it fails, STOP — the audit is wrong and the
production ordering must be fixed first (re-open item 0(i)).

- [ ] **Step 3: Scoped regression gate**

Run: `mkdir -p .tmptmp && TMPDIR=$PWD/.tmptmp cargo test -p zsign-rs builder -- --skip test_ipa_signing_is_deterministic`
Expected: PASS.

- [ ] **Step 4: Commit**

`git add crates/zsign/src/builder.rs && git commit -m "test(zsign): pin validate-before-mutation abort behavior (ZSN-35)"`

---

## Self-review

- **Spec coverage:** design doc claims (a)→Task 1, (b)→Task 2, (c)→Task 3,
  (d)→Task 4, (e ×2 conflicts)→Task 5, (h builder site)→Task 6, (i)→Task 7.
  Already-satisfied (f)(g)(i production) and the `-V` conflict are recorded in
  the design matrix and deliberately have no implementation task. Seams
  (`ipa/mod.rs:296`, `sign_standalone_dylib`) and docs-lane notes are
  report-only. Forwarding acceptance ("one observable-effect test per path") is
  satisfied by Tasks 1 (ipa), 2 (bundle repack), 3+4 (macho).
- **Placeholder scan:** every task shows real test code, real production code,
  exact commands, and expected outcomes; no TBD/TODO/"similar to".
- **Type consistency:** helpers (`write_ipa_fixture`, `ipa_entry`,
  `thin_code_signature`, `has_sha1_directory`, `FIXTURE_PLIST`,
  `PROFILE_FIXTURE`) are defined once at the top and referenced identically in
  every task; `identifier` override keeps `&str` lifetimes (match on
  `self.bundle_id`); `map_err` output stays `std::io::Error` so the `#[from]`
  conversion is unchanged; conflict tests use `parse_err`/`Cli::try_parse_from`
  exactly as the existing suite does.
