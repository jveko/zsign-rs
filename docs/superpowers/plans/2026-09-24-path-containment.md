# Signing Path Containment (ZSN-27) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development with dispatching-parallel-agents for independent tasks to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make it impossible for `crates/zsign/src/ipa/mod.rs` to read or
write outside the bundle root, even when the input bundle is hostile
(traversing `CFBundleExecutable`, symlinked entries, planted symlinks).

**Architecture:** One private guard `resolve_within(root, path)` (repo
idiom: `strip_prefix` + component check + downward symlink walk, mirroring
`ipa/extract.rs::validate_output_path`) validates every path entering the
signing flow; discovery walks classify with walkdir's no-follow
`entry.file_type()`; `get_main_executable` hard-errors on anything that is
not an existing regular file under the bundle.

**Tech Stack:** Rust 2021, walkdir 2.5, plist, tempfile. Tests: inline
`#[cfg(test)] mod tests` in `crates/zsign/src/ipa/mod.rs`.

**Scope lock:** only `crates/zsign/src/ipa/mod.rs` (code + inline tests)
and the two docs. Never edit other files. Do NOT run `cargo fmt` /
`cargo clippy` / `hk` — the orchestrator's gates own those; git commits
trigger the pre-commit hook automatically, let it run.

**Scoped gate (run after every step):**

```
cargo test -p zsign-rs ipa::tests -- --skip test_ipa_signing_is_deterministic
```

(`test_ipa_signing_is_deterministic` lives *inside* `ipa::tests`
(mod.rs:914) and is a known pre-existing failure, ZSN-15 — the skip is
mandatory. Never run project-wide.)

Line numbers below are pre-fix anchors on branch `zsn-27-path-contain`
(base ee42c12); re-locate by symbol if they drift.

---

### Task 1: `resolve_within` helper + hardened `get_main_executable`

**Files:**
- Modify: `crates/zsign/src/ipa/mod.rs`
  - imports at `:66`
  - new free fn after `type ProfilePayload` (`:109`)
  - `get_main_executable` at `:700-733`
- Test: inline tests module (`:904+`), new helper + 2 tests

- [ ] **Step 1.1: Write the failing tests**

Add to `mod tests` (near `create_test_ipa`, `:936`), plus the shared
fixture helper they use:

```rust
    /// Build a minimal `.app` folder whose Info.plist declares
    /// `executable_value` as CFBundleExecutable.
    fn create_folder_bundle(dir: &Path, executable_value: &str, write_executable: bool) -> PathBuf {
        let app = dir.join("App.app");
        std::fs::create_dir_all(&app).unwrap();
        std::fs::write(
            app.join("Info.plist"),
            format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>com.test.app</string>
    <key>CFBundleExecutable</key>
    <string>{executable_value}</string>
</dict>
</plist>"#
            ),
        )
        .unwrap();
        if write_executable {
            std::fs::write(app.join("Test"), crate::test_util::minimal_macho()).unwrap();
        }
        app
    }

    #[test]
    fn test_sign_rejects_executable_path_outside_bundle() {
        let temp = TempDir::new().unwrap();
        let outside = temp.path().join("outside_macho");
        std::fs::write(&outside, crate::test_util::minimal_macho()).unwrap();
        let app = create_folder_bundle(temp.path(), "../outside_macho", true);
        let before = std::fs::read(&outside).unwrap();

        let error = IpaSigner::new_adhoc()
            .sign_folder_in_place(&app)
            .expect_err("parent traversal in CFBundleExecutable must be rejected");
        let message = error.to_string();
        assert!(
            message.contains("outside_macho") && message.contains("escapes"),
            "error must name the escaping value: {message}"
        );
        assert_eq!(
            std::fs::read(&outside).unwrap(),
            before,
            "outside file must stay untouched"
        );
    }

    #[test]
    fn test_sign_rejects_absolute_executable_path() {
        let temp = TempDir::new().unwrap();
        let outside = temp.path().join("outside_macho");
        std::fs::write(&outside, crate::test_util::minimal_macho()).unwrap();
        let app = create_folder_bundle(temp.path(), outside.to_str().unwrap(), true);
        let before = std::fs::read(&outside).unwrap();

        let error = IpaSigner::new_adhoc()
            .sign_folder_in_place(&app)
            .expect_err("absolute CFBundleExecutable must be rejected");
        let message = error.to_string();
        assert!(
            message.contains("is not under root"),
            "error must report the containment failure: {message}"
        );
        assert_eq!(
            std::fs::read(&outside).unwrap(),
            before,
            "outside file must stay untouched"
        );
    }
```

Notes: `new_adhoc()` is deliberate — both tests fail before any
credential/crypto work. Tempdir names are alphanumeric, so the raw path in
XML is safe.

- [ ] **Step 1.2: Run the gate, expect RED**

Run: `cargo test -p zsign-rs ipa::tests -- --skip test_ipa_signing_is_deterministic`
Expected: **2 failed** (`test_sign_rejects_executable_path_outside_bundle`,
`test_sign_rejects_absolute_executable_path` — both panic at
`expect_err` because the traversal currently signs successfully), all
other tests pass. Record the output.

- [ ] **Step 1.3: Add the `resolve_within` helper**

Change the import at `:66` from
`use std::path::{Path, PathBuf};` to
`use std::path::{Component, Path, PathBuf};`.

Insert after `type ProfilePayload = ...` (`:109`), before
`pub struct IpaSigner`:

```rust
/// Resolve `path` for use under `root`, rejecting anything that escapes it.
///
/// `path` is either already prefixed by `root` (as produced by the
/// discovery walks) or relative to `root` (literal names, plist values).
/// The part below `root` must consist of normal components only — no
/// `..`, no absolute prefix — and no existing component may be a
/// symlink. Returns the path re-joined onto `root`, lexically identical
/// to what WalkDir produces.
fn resolve_within(root: &Path, path: &Path) -> Result<PathBuf> {
    let relative: PathBuf = match path.strip_prefix(root) {
        Ok(rel) => rel.to_path_buf(),
        Err(_) if !path.is_absolute() => path.to_path_buf(),
        Err(_) => {
            return Err(Error::Core(zsign_core::Error::Signing(format!(
                "Path {} is not under root {}",
                path.display(),
                root.display()
            ))))
        }
    };

    if relative.components().any(|c| {
        matches!(
            c,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    }) {
        return Err(Error::Core(zsign_core::Error::Signing(format!(
            "Path {} escapes the bundle root {}",
            relative.display(),
            root.display()
        ))));
    }

    let mut current = root.to_path_buf();
    for component in relative.components() {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(Error::Core(zsign_core::Error::Signing(format!(
                    "Pre-existing symlink in signing path: {}",
                    current.display()
                ))));
            }
            Ok(_) => {}
            Err(_) => break,
        }
    }

    Ok(root.join(relative))
}
```

- [ ] **Step 1.4: Harden `get_main_executable`**

Replace the whole body of `fn get_main_executable` (`:700-733`) with:

```rust
    /// Get the main executable path from Info.plist.
    ///
    /// A present `CFBundleExecutable` value must resolve to an existing
    /// regular file inside the bundle; traversal, absolute paths and
    /// symlinked components are rejected. The file-stem fallback applies
    /// only when the key is absent.
    fn get_main_executable(&self, bundle_path: &Path) -> Result<PathBuf> {
        let info_plist_path = bundle_path.join("Info.plist");

        if !info_plist_path.exists() {
            return Err(Error::Core(zsign_core::Error::Signing(format!(
                "Info.plist not found in bundle: {}",
                bundle_path.display()
            ))));
        }

        let plist_data = fs::read(&info_plist_path)?;
        let plist: plist::Value = plist::from_bytes(&plist_data).map_err(|e| {
            Error::Core(zsign_core::Error::Signing(format!(
                "Failed to parse Info.plist: {}",
                e
            )))
        })?;

        let executable_value = match plist
            .as_dictionary()
            .and_then(|d| d.get("CFBundleExecutable"))
            .and_then(|v| v.as_string())
        {
            Some(value) => {
                let executable = resolve_within(bundle_path, Path::new(value))?;
                match fs::symlink_metadata(&executable) {
                    Ok(metadata) if metadata.is_file() => return Ok(executable),
                    Ok(_) => {
                        return Err(Error::Core(zsign_core::Error::Signing(format!(
                            "CFBundleExecutable \"{}\" does not name a regular file in {}",
                            value,
                            bundle_path.display()
                        ))))
                    }
                    Err(e) => {
                        return Err(Error::Core(zsign_core::Error::Signing(format!(
                            "CFBundleExecutable \"{}\" in {} is not an existing regular file: {}",
                            value,
                            bundle_path.display(),
                            e
                        ))))
                    }
                }
            }
            None => bundle_path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("unknown")
                .to_string(),
        };

        resolve_within(bundle_path, Path::new(&executable_value))
    }
```

Behavior changes (intended, recorded in the design doc):
- missing `Info.plist` → hard error (previously returned a file-stem
  join); in the signing flow `get_bundle_identifier` already errored
  first with the same message, so no caller-visible change;
- key present + non-regular/missing target → hard error naming the value
  (previously: silent skip via `.exists()` guards at `:575`/`:594`, or
  write-through escape);
- key absent → file-stem fallback preserved, now routed through
  `resolve_within`, still without an existence requirement (the
  `.exists()` guards stay).

- [ ] **Step 1.5: Run the gate, expect GREEN**

Run: `cargo test -p zsign-rs ipa::tests -- --skip test_ipa_signing_is_deterministic`
Expected: all tests pass (2 new + 4 existing; 1 filtered out).

- [ ] **Step 1.6: Commit**

```
git add crates/zsign/src/ipa/mod.rs
git commit -m "fix(ipa): contain CFBundleExecutable within the bundle root

ZSN-27"
```

Let the pre-commit hook run; do not invoke fmt/clippy/hk manually.

---

### Task 2: No-follow classification in the three discovery walks

**Files:**
- Modify: `crates/zsign/src/ipa/mod.rs`
  - `collect_nested_bundles` predicate at `:404`
  - `find_standalone_dylibs` predicate at `:458`
  - `find_immediate_macho_binaries` `filter_entry` at `:601-607`, body at `:612`
- Test: inline tests module, 2 new `#[cfg(unix)]` tests

- [ ] **Step 2.1: Write the failing tests**

Add to `mod tests` (after Task 1's tests; `create_folder_bundle` from
Task 1 is reused):

```rust
    #[cfg(unix)]
    #[test]
    fn test_symlinked_dylib_is_skipped_and_target_untouched() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().unwrap();
        let outside = temp.path().join("outside.dylib");
        std::fs::write(&outside, crate::test_util::minimal_macho()).unwrap();
        let app = create_folder_bundle(temp.path(), "Test", true);
        std::fs::write(app.join("real.dylib"), crate::test_util::minimal_macho()).unwrap();
        let link = app.join("lib.dylib");
        symlink(&outside, &link).unwrap();
        let before = std::fs::read(&outside).unwrap();

        let signer = IpaSigner::new_adhoc();
        let dylibs = signer.find_standalone_dylibs(&app).unwrap();
        assert!(
            dylibs.contains(&app.join("real.dylib")),
            "a real dylib must still be discovered: {dylibs:?}"
        );
        assert!(
            !dylibs.contains(&link),
            "a symlinked dylib must not be discovered: {dylibs:?}"
        );
        let binaries = signer.find_immediate_macho_binaries(&app).unwrap();
        assert!(
            !binaries.contains(&link),
            "a symlinked dylib must not be a signing target: {binaries:?}"
        );

        IpaSigner::new(&crate::test_util::test_credentials())
            .sign_folder_in_place(&app)
            .unwrap();
        assert_eq!(
            std::fs::read(&outside).unwrap(),
            before,
            "external dylib target must stay untouched"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_symlinked_framework_is_not_collected_and_target_untouched() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().unwrap();
        let evil = temp.path().join("EvilTarget.framework");
        std::fs::create_dir_all(&evil).unwrap();
        std::fs::write(
            evil.join("Info.plist"),
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>com.test.evil</string>
    <key>CFBundleExecutable</key>
    <string>Evil</string>
</dict>
</plist>"#,
        )
        .unwrap();
        std::fs::write(evil.join("Evil"), crate::test_util::minimal_macho()).unwrap();

        let app = create_folder_bundle(temp.path(), "Test", true);
        symlink(&evil, app.join("Evil.framework")).unwrap();
        let before = std::fs::read(evil.join("Evil")).unwrap();

        let bundles = IpaSigner::new_adhoc().collect_nested_bundles(&app).unwrap();
        assert!(
            bundles.iter().all(|(path, _)| path != &app.join("Evil.framework")),
            "a symlinked framework must not be collected: {bundles:?}"
        );
        assert!(
            bundles.iter().any(|(path, _)| path == &app),
            "the root bundle must still be collected: {bundles:?}"
        );

        IpaSigner::new(&crate::test_util::test_credentials())
            .sign_folder_in_place(&app)
            .unwrap();
        assert_eq!(
            std::fs::read(evil.join("Evil")).unwrap(),
            before,
            "external framework binary must stay untouched"
        );
        assert!(
            !evil.join("_CodeSignature").exists(),
            "no signature may be written outside the bundle"
        );
    }
```

- [ ] **Step 2.2: Run the gate, expect RED**

Run: `cargo test -p zsign-rs ipa::tests -- --skip test_ipa_signing_is_deterministic`
Expected: **2 failed** — `test_symlinked_dylib_is_skipped_and_target_untouched`
(fails on `!dylibs.contains(&link)` because `path.is_file()` follows the
link) and `test_symlinked_framework_is_not_collected_and_target_untouched`
(fails on `all(...)` because `path.is_dir()` follows the link). All
other tests pass. Record the output.

- [ ] **Step 2.3: Swap the four predicates to `entry.file_type()`**

1. `collect_nested_bundles` (`:404`):

```rust
            if entry.file_type().is_dir() && Self::is_bundle_directory(path) {
```

2. `find_standalone_dylibs` (`:458`):

```rust
            if !entry.file_type().is_file() {
                continue;
            }
```

3. `find_immediate_macho_binaries` `filter_entry` (`:601-607`):

```rust
            .filter_entry(|e| {
                let path = e.path();
                if path != bundle_path && e.file_type().is_dir() && Self::is_bundle_directory(path) {
                    return false;
                }
                true
            })
```

4. `find_immediate_macho_binaries` body (`:612`):

```rust
            if !entry.file_type().is_file() {
                continue;
            }
```

No other changes: walkdir's default `follow_links(false)` already keeps
the walker from descending symlinked directories; the predicates were the
only place that followed links. `CodeResourcesBuilder` already uses this
exact idiom (`bundle/code_resources.rs:166-171`).

- [ ] **Step 2.4: Run the gate, expect GREEN**

Run: `cargo test -p zsign-rs ipa::tests -- --skip test_ipa_signing_is_deterministic`
Expected: all tests pass (4 new + 4 existing; 1 filtered out).

- [ ] **Step 2.5: Commit**

```
git add crates/zsign/src/ipa/mod.rs
git commit -m "fix(ipa): classify bundle entries without following symlinks

ZSN-27"
```

Let the pre-commit hook run; do not invoke fmt/clippy/hk manually.

---

### Task 3: Wire `resolve_within` into every write site

**Files:**
- Modify: `crates/zsign/src/ipa/mod.rs`
  - `rewrite_plist_string` at `:629-635` (path binding)
  - `sign_single_bundle` profile write at `:555`, `sign_binary` calls at `:550`/`:576`
  - `generate_code_resources` at `:890-900`
  - `sign_standalone_dylib` at `:476` + its caller at `:370`
  - `sign_binary` at `:770` (signature + entry)
- Test: inline tests module, 1 new test

- [ ] **Step 3.1: Write the failing test**

Add to `mod tests`:

```rust
    #[cfg(unix)]
    #[test]
    fn test_sign_rejects_symlinked_info_plist_rewrite() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().unwrap();
        let app = create_folder_bundle(temp.path(), "Test", true);
        let outside_plist = temp.path().join("outside.plist");
        std::fs::copy(app.join("Info.plist"), &outside_plist).unwrap();
        std::fs::remove_file(app.join("Info.plist")).unwrap();
        symlink(&outside_plist, app.join("Info.plist")).unwrap();
        let before = std::fs::read(&outside_plist).unwrap();

        let error = IpaSigner::new_adhoc()
            .bundle_id("com.test.changed")
            .sign_folder_in_place(&app)
            .expect_err("a symlinked Info.plist must be rejected before the rewrite");
        let message = error.to_string();
        assert!(
            message.contains("Pre-existing symlink"),
            "error must name the cause: {message}"
        );
        assert_eq!(
            std::fs::read(&outside_plist).unwrap(),
            before,
            "external plist must stay untouched"
        );
    }
```

- [ ] **Step 3.2: Run the gate, expect RED**

Run: `cargo test -p zsign-rs ipa::tests -- --skip test_ipa_signing_is_deterministic`
Expected: **1 failed** — `test_sign_rejects_symlinked_info_plist_rewrite`
panics at `expect_err`: `rewrite_plist_string` currently reads and writes
through the symlink, so the sign succeeds (and the external plist
changes). All other tests pass. Record the output.

- [ ] **Step 3.3: Guard `rewrite_plist_string`**

In `rewrite_plist_string` (`:630`) replace the path binding:

```rust
        let info_plist_path = resolve_within(bundle_path, Path::new("Info.plist"))?;
```

(The existing `info_plist_path.exists()` not-found check stays; the guard
runs before the `fs::read` and the `fs::write`.)

- [ ] **Step 3.4: Guard the profile write in `sign_single_bundle`**

At `:555` replace:

```rust
                let embedded_path =
                    resolve_within(bundle_path, Path::new("embedded.mobileprovision"))?;
```

- [ ] **Step 3.5: Guard `generate_code_resources`**

Replace the tail of `generate_code_resources` (`:892-899`):

```rust
        let codesig_dir = resolve_within(bundle_path, Path::new("_CodeSignature"))?;
        fs::create_dir_all(&codesig_dir)?;

        let resources_path =
            resolve_within(bundle_path, Path::new("_CodeSignature/CodeResources"))?;
        fs::write(&resources_path, &code_resources)?;
```

(`CodeResourcesBuilder`'s scan above it is read-only and already
no-follow; no change there.)

- [ ] **Step 3.6: Thread `root` into `sign_standalone_dylib`**

Signature (`:476`):

```rust
    fn sign_standalone_dylib(&self, root: &Path, dylib_path: &Path) -> Result<()> {
        let validated = resolve_within(root, dylib_path)?;
        let dylib_path = validated.as_path();
```

Keep the rest of the body unchanged: the shadow is a `&Path`, so every
existing use (`MachOFile::open`, `dylib_path.file_stem()`,
`fs::write`) compiles as-is.

Update the single caller in `sign_bundle` (`:370`):

```rust
        dylibs
            .par_iter()
            .try_for_each(|dylib_path| self.sign_standalone_dylib(bundle_path, dylib_path))?;
```

- [ ] **Step 3.7: Thread `root` into `sign_binary`**

Signature (`:770`):

```rust
    fn sign_binary(
        &self,
        root: &Path,
        binary_path: &Path,
        identifier: &str,
        code_resources: Option<&[u8]>,
        entitlements: Option<&[u8]>,
    ) -> Result<()> {
        let validated = resolve_within(root, binary_path)?;
        let binary_path = validated.as_path();
```

The shadow is a `&Path`, so everything downstream (the open at `:777`,
the dylib-injection write at `:810`, the `binary_path.parent()` Info.plist
lookup at `:821`, the final write at `:867`) compiles and operates on
the validated path — no other edits inside the function.

Update the two callers in `sign_single_bundle`:

```rust
        non_main_binaries.par_iter().try_for_each(|binary_path| {
            let binary_identifier = binary_path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or(&identifier);
            self.sign_binary(bundle_path, binary_path, binary_identifier, None, entitlements)
        })?;
```

and at `:576`:

```rust
            self.sign_binary(
                bundle_path,
                &main_executable,
                &identifier,
                code_resources_data.as_deref(),
                entitlements,
            )?;
```

- [ ] **Step 3.8: Run the gate, expect GREEN**

Run: `cargo test -p zsign-rs ipa::tests -- --skip test_ipa_signing_is_deterministic`
Expected: all tests pass (5 new + 4 existing; 1 filtered out).

- [ ] **Step 3.9: Commit**

```
git add crates/zsign/src/ipa/mod.rs
git commit -m "fix(ipa): guard every bundle write with resolve_within

ZSN-27"
```

Let the pre-commit hook run; do not invoke fmt/clippy/hk manually.

---

## Self-review

- **Spec coverage:** item 1 → Task 1 (helper + hardening + tests 1-2);
  item 2 → Task 2 (four predicates + tests 3-4); item 3 → Task 3 (guard
  at all seven write/mkdir sites + test 5); design doc's invariants are
  restated as constraints in each task (lexical returns, no flow
  restructure, `.exists()` guards kept).
- **Placeholders:** none — every step carries complete code, exact
  commands, and expected outcomes.
- **Type consistency:** `resolve_within(root: &Path, path: &Path) ->
  Result<PathBuf>` used identically in Tasks 1 and 3;
  `sign_binary(&self, root, binary_path, identifier, code_resources,
  entitlements)` and `sign_standalone_dylib(&self, root, dylib_path)`
  match their single call sites; `create_folder_bundle(dir, executable_value,
  write_executable)` matches all five tests that use it.
- **Verification:** per-task scoped gate only; full-suite claim reserved
  for the orchestrator's merge gates (with the ZSN-15 skip).
