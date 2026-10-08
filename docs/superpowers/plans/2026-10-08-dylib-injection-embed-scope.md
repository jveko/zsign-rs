# Dylib Injection Embed + Scope Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development (recommended) with dispatching-parallel-agents for independent tasks to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `-l` actually embed the dylib file in the bundle with an
`@executable_path` rewrite, and scope injection to the app root by default
with `-P/--inject-extensions` extending it to top-level app extensions.

**Architecture:** Path-typed `-l` validated by a clap `value_parser`; the
file copy and the per-bundle injection strings are computed inside
`IpaSigner::sign_bundle` (the only layer that sees the extracted store) and
flow down to `sign_binary` through a new `injected: &[String]` parameter;
the bare-Mach-O path keeps verbatim injection.

**Tech Stack:** Rust 2021, clap 4 derive, thiserror; zsign (facade) over
zsign-core; `Store` (FsStore/MemStore) for tree mutation.

**Spec:** `docs/superpowers/specs/2026-10-08-dylib-injection-embed-scope-design.md`

## Global Constraints

- Zero ticket IDs anywhere: no issue references in code, comments, docs, or
  commit messages.
- Zero-warning gate at item end: `cargo fmt --all -- --check` AND
  `cargo clippy --workspace --all-targets -- -D warnings`.
- Tests: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test --workspace`
  (scoped `-p zsign-cli` / `-p zsign-rs` gates during flight).
- Files allowed: `crates/zsign-cli/src/main.rs`,
  `crates/zsign/src/ipa/mod.rs`, `crates/zsign/src/builder.rs`, `README.md`.
  Nothing else may change (writer/signer/verify/store/bundle-CodeResources and
  other lanes' files are read-only here).
- Exit contract stays 0/1/2: invalid `-l` = clap usage error = exit 2; runtime
  failures = exit 1; no new exit codes.
- Commits: conventional, imperative, lowercase, no trailing period, no ticket
  IDs. One commit per task, after its scoped gate is green.
- wasm invariant: the new copy/scope code must sit behind
  `self.dylibs.is_empty()`-equivalent guards so the wasm `MemStore` flow never
  reaches a host-FS read (wasm never sets `dylibs`, as it never sets a
  path-form profile — precedent `BlobSource::Path` in `ipa/mod.rs`).

## Review Focus

(input classes the spec implies that no single task's tests fully cover;
each line's pinning test is named in the owning task)

1. Default scope must not narrow *signing*: with `-l` and no `-P`, extension
   executables stay unsigned-of-injection but fully signed and sealed —
   pinned by `default_scope_leaves_extensions_uninjected_but_signed`.
2. Extension depth math: `PlugIns/Ext.appex` must produce exactly
   `@executable_path/../../<name>` (two `../`, not one) — pinned by
   `inject_extensions_injects_relative_path_into_top_level_appex`.
3. A copied dylib whose filename lacks the `.dylib` suffix must still be
   signed and sealed (the extension-based standalone scan would miss it) —
   pinned by `extensionless_dylib_copy_is_signed_and_sealed`.
4. Overwrite semantics: an existing file at the destination is replaced by
   the copy (upstream parity), keeping re-sign idempotent — pinned by
   `dylib_copy_overwrites_preexisting_file_with_same_name`.
5. The encrypted-input refusal must keep firing, and must still leave the
   encrypted binary byte-untouched, after the copy phase lands earlier in the
   flow — pinned by `test_ipa_signer_refuses_encrypted_bundle`
   (`ipa/mod.rs:2594`): migrated in Task 2 so its `-l` input becomes a real
   on-disk fixture; its assertions stay unchanged.

---

### Task 1: Parse-time `-l` validation and path typing

**Files:**
- Modify: `crates/zsign-cli/src/main.rs` (`dylibs` field at :138-140, new
  `parse_dylib` helper next to `parse_profile_map` at :192-200)
- Modify: `crates/zsign/src/builder.rs` (field :85-86, setter :345-349,
  `sign_macho` loop :421-425, test :1260-1262)
- Modify: `crates/zsign/src/ipa/mod.rs` (field :331-334, setter :599-607,
  injection loop :1826-1834, test :2612-2613)
- Test: `crates/zsign-cli/src/main.rs` tests module

**Interfaces:**
- Produces: `Cli.dylibs: Vec<PathBuf>` parsed with `value_parser = parse_dylib`;
  `fn parse_dylib(s: &str) -> std::result::Result<PathBuf, String>`;
  `ZSign::dylib_injection(self, dylibs: Vec<PathBuf>, weak: bool) -> Self`;
  `IpaSigner::dylib_injection(self, dylibs: Vec<PathBuf>, weak: bool) -> Self`.
  Behavior otherwise unchanged (bundle flows still inject verbatim until
  Task 2). Later tasks rely on these exact signatures.

- [ ] **Step 1: Write the failing CLI tests (Tester)**

Add to `crates/zsign-cli/src/main.rs` tests, using the existing
`parse_err` helper (:1696-1703) and `tempfile::TempDir`:

```rust
#[test]
fn dylib_flag_rejects_empty_value() {
    let err = parse_err(&["zsign", "-a", "-l", "", "in.ipa"]);
    assert_eq!(
        err.kind(),
        clap::error::ErrorKind::ValueValidation,
        "empty -l must be a clap value error, got {:?}",
        err.kind()
    );
}

#[test]
fn dylib_flag_rejects_missing_file() {
    let err = parse_err(&["zsign", "-a", "-l", "/no/such/lib.dylib", "in.ipa"]);
    assert_eq!(
        err.kind(),
        clap::error::ErrorKind::ValueValidation,
        "a missing -l file must be a clap value error, got {:?}",
        err.kind()
    );
}

#[test]
fn dylib_flag_rejects_non_macho_file() {
    let td = tempfile::TempDir::new().unwrap();
    let junk = td.path().join("junk.bin");
    std::fs::write(&junk, b"definitely not a macho").unwrap();
    let err = parse_err(&["zsign", "-a", "-l", junk.to_str().unwrap(), "in.ipa"]);
    assert_eq!(
        err.kind(),
        clap::error::ErrorKind::ValueValidation,
        "a non-Mach-O -l file must be a clap value error, got {:?}",
        err.kind()
    );
}

#[test]
fn dylib_flag_parses_existing_macho_path() {
    let td = tempfile::TempDir::new().unwrap();
    let file = td.path().join("lib.dylib");
    std::fs::write(&file, zsign_core::macho::fixtures::make_minimal_macho()).unwrap();
    let cli = Cli::try_parse_from(["zsign", "-a", "-l", file.to_str().unwrap(), "in.ipa"])
        .expect("an existing Mach-O must parse");
    let parsed: Vec<PathBuf> = cli.dylibs;
    assert_eq!(parsed, vec![file]);
}
```

(Each `assert_eq!` footer prints the actual kind/value — follow the repo's
`…` footer convention literally: include the actual value in every assert.)

- [ ] **Step 2: Run them, watch them fail**

Run: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-cli dylib_flag`
Expected: first three FAIL (today `Vec<String>` accepts any string, so
`parse_err` panics "must be rejected"); fourth FAILS to compile or on type
(`Vec<String>` vs `Vec<PathBuf>`) — all four fail for the missing feature.

- [ ] **Step 3: Type the field and add the validator**

In `main.rs`: change the field to
`#[arg(short = 'l', long, value_parser = parse_dylib)] dylibs: Vec<PathBuf>,`
(keep the existing doc comment/help text). Add, beside `parse_profile_map`:

```rust
/// Parses one `-l` dylib argument: a non-empty path to an existing regular
/// file that parses as Mach-O (mirrors upstream's pre-sign checks).
fn parse_dylib(s: &str) -> std::result::Result<PathBuf, String> {
    if s.is_empty() {
        return Err("dylib path must not be empty".into());
    }
    let path = PathBuf::from(s);
    if !path.is_file() {
        return Err(format!("dylib not found or not a regular file: {s}"));
    }
    let bytes = std::fs::read(&path).map_err(|e| format!("cannot read dylib {s}: {e}"))?;
    zsign_rs::macho::MachOFile::parse(bytes)
        .map_err(|e| format!("not a valid Mach-O file {s}: {e}"))?;
    Ok(path)
}
```

In `builder.rs`: field `dylibs: Vec<PathBuf>`; setter signature becomes
`pub fn dylib_injection(mut self, dylibs: Vec<PathBuf>, weak: bool) -> Self`;
`sign_macho` injects `&dylib.to_string_lossy()` (verbatim, unchanged
semantics); update the test at :1261 to
`vec![std::path::PathBuf::from("/usr/lib/libzsn.dylib")]`.

In `ipa/mod.rs`: field `dylibs: Vec<PathBuf>`; setter signature matches
builder; the `sign_binary` loop passes `&name.to_string_lossy()` (replaced
entirely by Task 2); test at :2613 becomes
`vec![std::path::PathBuf::from("lib.dylib")]` (still nonexistent on disk —
harmless until Task 2 adds the read; the test asserts the encrypted refusal).

- [ ] **Step 4: Watch them pass**

Run: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-cli dylib_flag`
Expected: 4 passed.

- [ ] **Step 5: Scoped gate + commit**

Run: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-cli -p zsign-rs`
and `cargo clippy -p zsign-cli -p zsign-rs --all-targets -- -D warnings`
and `cargo fmt --all -- --check`.
Expected: all green.
Commit: `feat(cli): validate dylib injection paths at parse time`

---

### Task 2: Copy into the app root, inject `@executable_path/<name>` at root scope

**Files:**
- Modify: `crates/zsign/src/ipa/mod.rs` (`sign_bundle` :889-1053, setters
  :599-607, `sign_single_bundle` :1429-1517, `sign_one_binary` :1519-1543,
  `sign_binary` :1784-1853, test at :2594, tests module)
- Modify: `crates/zsign/src/builder.rs` (setter doc :343-349, field comment :85)
- Test: `crates/zsign/src/ipa/mod.rs` tests module

**Interfaces:**
- Consumes: `IpaSigner::dylib_injection(Vec<PathBuf>, bool)` from Task 1.
- Produces: `sign_single_bundle(store, bundle_path, entitlements, profile_data,
  already_signed, injected: &[String])`, `sign_one_binary(…, injected: &[String])`,
  `sign_binary(…, injected: &[String])`; `sign_bundle` maintains a
  `HashMap<PathBuf, Vec<String>>` scope map (root arm only in this task);
  the copied dylib lands at `<bundle root>/<basename>` via `Store::write`.
  Copy runs before `find_standalone_dylibs` so copied paths are signed.

- [ ] **Step 1: Write the failing tests (Tester)**

Add to `crates/zsign/src/ipa/mod.rs` tests (reuse `create_folder_bundle`,
`create_bundle_with_appex`, `create_test_ipa`, `fixtures::make_minimal_dylib`,
`TempDir`; read load-command names through the same `MachOFile` accessor that
`builder.rs`'s `test_sign_macho_applies_dylibs_and_bundle_id` at :1250-1279
uses — read that test first and match it; parse signatures via
`crate::macho::MachOFile::parse` + `.slices()[0].code_sig_offset` as at
:2964-2967):

1. `injected_dylib_is_copied_into_root_and_load_path_rewritten`
   - app = `create_folder_bundle(temp.path(), "Test", true)`; source =
     `temp.path().join("libfoo.dylib")` written with `make_minimal_dylib()`
     (source lives OUTSIDE the app dir); sign folder with
     `IpaSigner::new_adhoc().dylib_injection(vec![source.clone()], false)`.
   - Assert: `app.join("libfoo.dylib")` reads successfully (the copy exists at
     the root), parses as Mach-O, and `code_sig_offset.is_some()` (the copy is
     signed); `std::fs::read(&source)` still equals the original bytes (the
     source file is untouched); the root executable's dylib load-command list
     contains `@executable_path/libfoo.dylib` and NO entry containing the host
     temp-dir path (assert on the full filtered list:
     `assert_eq!(injected, vec!["@executable_path/libfoo.dylib"], "… got {:?}", all_libs)`).
   - Expected failure today: the copy does not exist; the raw host path would
     be embedded instead.

2. `default_scope_leaves_extensions_uninjected_but_signed`
   - `(app, appex) = create_bundle_with_appex(temp.path())`; source written
     outside; sign with `dylib_injection(vec![source], false)` (no scope flag).
   - Assert: the root executable's list contains
     `@executable_path/libfoo.dylib`; the appex executable (`appex.join("Ext")`)
     contains NO entry mentioning `libfoo` (footer prints its full list);
     the appex executable still has `code_sig_offset.is_some()`; and
     `appex.join("_CodeSignature/CodeResources")` exists — default scope must
     not narrow *signing*, only injection.
   - Expected failure today: the appex executable carries the injected entry.

3. `dylib_copy_survives_repack_and_verifies`
   - `ipa = create_test_ipa(temp.path())`; output =
     `temp.path().join("out.ipa")`; source outside the ipa path; sign with
     `IpaSigner::new_adhoc().dylib_injection(vec![source], false)` calling the
     same in-crate `sign(input, output)` entry `builder.rs` uses at :572
     (`signer.sign(input, output)`).
   - Open the output with `zip::ZipArchive` (same imports style as the
     `create_test_ipa` writer at :2111+; add `ZipArchive` to the existing
     `use` block if absent): `by_name("Payload/Test.app/libfoo.dylib")` must
     resolve (`expect("the copied dylib must exist in the repacked IPA")`),
     its bytes must parse as Mach-O with `code_sig_offset.is_some()`.
   - `crate::verify::verify_ipa(&output)` must run and
     `report.valid()` must be true — footer pattern from
     `ipa/mod.rs:3339-3343`
     (`report.bundle.as_ref().map(|b| &b.errors)`).
   - Expected failure today: no such zip entry.

4. `dylib_copy_overwrites_preexisting_file_with_same_name`
   - `create_folder_bundle`; plant `app.join("libfoo.dylib") = b"stale bytes"`;
     source outside with `make_minimal_dylib()`; sign with
     `dylib_injection(vec![source], false)` (must succeed — the copy phase
     runs before the extension-based standalone scan, so the scan never sees
     the stale bytes).
   - Assert: `app.join("libfoo.dylib")` now parses as Mach-O and has
     `code_sig_offset.is_some()` — the destination was replaced by the copy
     and signed (upstream `CopyFileV` overwrite parity; this is what keeps
     re-signing idempotent).
   - Expected failure today: signing errors on the stale bytes (scan-before-
     copy) or leaves them in place.

5. `extensionless_dylib_copy_is_signed_and_sealed`
   - `create_folder_bundle`; source named `helper` (no extension, Mach-O
     bytes); sign with `dylib_injection(vec![source], false)`.
   - Assert: `app.join("helper")` exists, parses, `code_sig_offset.is_some()`
     (the extension-based standalone scan at :1337-1366 would miss it — the
     copy list must be merged in explicitly); then
     `crate::verify::verify_bundle(&app)` runs with `report.valid() == true`.
   - Expected failure today: no copy exists.

6. Migrate `test_ipa_signer_refuses_encrypted_bundle` (:2594): before its
   `signer` binding, write a real fixture
   (`temp_dir.path().join("inject.dylib")` with `make_minimal_dylib()`) and
   pass `vec![std::path::PathBuf::from(inject_path)]` to `dylib_injection`
   instead of `"lib.dylib".to_string()`. All assertions unchanged. (Without
   this, Task 2's host read turns the expected `cryptid` refusal into a
   NotFound error.)

- [ ] **Step 2: Run them, watch them fail**

Run: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-rs dylib`
Expected: tests 1, 3, 4, 5 FAIL for the reasons above (test 2 also fails —
today the appex IS hooked); `test_ipa_signer_refuses_encrypted_bundle` may
fail only after the copy lands — that migration is part of making the suite
green, written in the same step as the tests.

- [ ] **Step 3: Implement the copy phase in `sign_bundle`**

In `sign_bundle`, immediately before `let dylibs = self.find_standalone_dylibs(store, bundle_path)?;`
(:1035) — i.e. after the requested-rewrite phase, still before any binary
signing:

```rust
// Injected dylibs are embedded at the app root (the single copy every
// load command references). Host-read like load_profile's Path arm;
// the wasm surface never sets `dylibs`.
let mut copied_dylibs: Vec<PathBuf> = Vec::new();
for dylib in &self.dylibs {
    let bytes = std::fs::read(dylib)?;
    let name = dylib.file_name().ok_or_else(|| {
        Error::Core(zsign_core::Error::Config(format!(
            "dylib path must name a file: {}",
            dylib.display()
        )))
    })?;
    let dest = bundle_path.join(name);
    store.write(&dest, &bytes)?;
    copied_dylibs.push(dest);
}
```

Then merge into the standalone list (this replaces the current `let dylibs = …`
binding):

```rust
let mut dylibs = self.find_standalone_dylibs(store, bundle_path)?;
for dest in copied_dylibs {
    if !dylibs.contains(&dest) {
        dylibs.push(dest);
    }
}
```

(`already_signed` at :1037 stays as-is — it is derived from `dylibs` and now
correctly contains the copies.)

- [ ] **Step 4: Scope map + plumbing to `sign_binary`**

After the copy/merge, still before the plan loop:

```rust
// Which bundles receive injected load commands: the root always (the -P
// widening arm lands with the scope flag). Empty map = no injection.
let mut injection: HashMap<PathBuf, Vec<String>> = HashMap::new();
if !self.dylibs.is_empty() {
    let bases: Vec<String> = self
        .dylibs
        .iter()
        .filter_map(|p| p.file_name())
        .map(|n| n.to_string_lossy().into_owned())
        .collect();
    injection.insert(
        bundle_path.to_path_buf(),
        bases
            .iter()
            .map(|b| format!("@executable_path/{b}"))
            .collect(),
    );
}
```

In the plan loop (:1040-1048) compute
`let injected = injection.get(path).map(Vec::as_slice).unwrap_or(&[]);`
and pass it as a new last argument to `sign_single_bundle`.

`sign_single_bundle`: add parameter `injected: &[String]`; pass it to every
`sign_one_binary` call (parallel arm closure captures it by reference — it is
`Sync`) and to the main-executable `sign_binary` call (:1509-1516).
`sign_one_binary`: add `injected: &[String]`, forward to `sign_binary`.

`sign_binary`: add parameter `injected: &[String]`. At the top, BEFORE the
`resolve_within` shadowing of `binary_path`, compute
`let direct_child = binary_path.parent() == Some(root);`
(only binaries sitting directly in the bundle directory are hooked — upstream
folder parity, spec §Design). Replace the current injection gate
(:1826-1834, `!self.dylibs.is_empty() && is_executable`) with:

```rust
// Dylib injection applies to executables directly inside an in-scope
// bundle directory, before they are signed.
let mut binary_data = binary_data;
if !injected.is_empty() && is_executable && direct_child {
    for load_path in injected {
        binary_data = zsign_core::macho::writer::inject_dylib_command(
            &binary_data,
            load_path,
            self.weak_dylibs,
        )?;
    }
    store.write(binary_path, &binary_data)?;
}
```

- [ ] **Step 5: Watch the tests pass**

Run: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-rs`
Expected: all pass, including the six tests above and the whole package.

- [ ] **Step 6: Update docs-in-code and commit**

Update the doc comments the behavior change obsoletes: `IpaSigner::dylib_injection`
(:599-602, currently "into every signed bundle binary"), the `dylibs` field
doc (:331), `ZSign::dylib_injection` (:343-344, "into every signed executable"),
and the `ZSign.dylibs` field comment (:85) — each must state: the file is
copied to the app root and injected as `@executable_path/<basename>` for
bundle/IPA inputs (root scope in this task; extension widening described by
Task 3), while a bare Mach-O gets the path verbatim.

Scoped gate: `cargo test -p zsign-rs` + `cargo clippy -p zsign-rs --all-targets -- -D warnings` + `cargo fmt --all -- --check`.
Commit: `feat(ipa): embed injected dylibs in the app root`

---

### Task 3: `-P/--inject-extensions` scope widening + README rows

**Files:**
- Modify: `crates/zsign/src/ipa/mod.rs` (struct field + both constructors,
  setter next to `dylib_injection` :599-607, scope map in `sign_bundle`,
  private helper, tests module)
- Modify: `crates/zsign/src/builder.rs` (field :85-86, new setter beside
  `dylib_injection` :345, forwards in `sign_ipa` :536-538 and `sign_bundle`
  :605-607)
- Modify: `crates/zsign-cli/src/main.rs` (field after `weak` :142-144,
  `run()` beside the `dylib_injection` call :275-277, `-V` conflicts list
  :178-184, tests)
- Modify: `README.md` (flag-table rows :208-209, migration table
  ~:385-392, upstream-no-equivalent list ~:397-399 — item-scoped rows only,
  append-only within each section)
- Test: `crates/zsign/src/ipa/mod.rs` + `crates/zsign-cli/src/main.rs`

**Interfaces:**
- Consumes: Task 2's `injection: HashMap<PathBuf, Vec<String>>` and the
  `injected: &[String]` parameters.
- Produces: `IpaSigner::inject_extensions(self, bool) -> Self`;
  `ZSign::inject_extensions(self, bool) -> Self`;
  `Cli.inject_extensions: bool` (`-P`, `--inject-extensions`, conflicts `-V`);
  `fn is_top_level_app_extension(relative: &Path) -> bool` (private in
  `ipa/mod.rs`).

- [ ] **Step 1: Write the failing tests (Tester)**

In `crates/zsign/src/ipa/mod.rs` tests:

1. `inject_extensions_injects_relative_path_into_top_level_appex`
   - `(app, appex) = create_bundle_with_appex(temp.path())`; source outside =
     `make_minimal_dylib()` named `libfoo.dylib`; sign with
     `IpaSigner::new_adhoc().dylib_injection(vec![source], false)
     .inject_extensions(true)` and `sign_folder_in_place`.
   - Assert the appex executable's dylib list contains exactly
     `@executable_path/../../libfoo.dylib` for its `libfoo` entries (footer
     prints the full list — two `../`, matching the fixture path
     `PlugIns/Ext.appex` = two components), and the root executable contains
     `@executable_path/libfoo.dylib`.
   - Expected failure today: the setter does not exist (compile RED — the
     feature being expressed is absent).

2. `inject_extensions_skips_xpc_services`
   - `app = create_bundle_with_xpc(temp.path())`; source outside; sign with
     `dylib_injection(vec![source], false).inject_extensions(true)`.
   - Assert: the XPC executable (`XPCServices/Foo.xpc/Foo`) has NO dylib entry
     mentioning `libfoo` (footer prints its list), while the root executable
     has `@executable_path/libfoo.dylib` — `-P` widens only top-level
     PlugIns/Extensions `.appex`, per upstream `IsAppExtensionPath`.
   - Expected failure today: compile RED (same setter).

In `crates/zsign-cli/src/main.rs` tests:

3. `inject_extensions_flag_parses` — pattern of
   `entitlements_dir_flag_parses` (:1751-1757):
   `Cli::try_parse_from(["zsign", "-a", "-P", "in.ipa"])` must parse with
   `cli.inject_extensions == true` (no `-l` needed — `-P` alone is accepted,
   it is a no-op without dylibs). Expected RED today: unknown argument.

4. Add `vec!["zsign", "-V", "-P", "in.ipa"]` to the `extra` list of the
   existing `verify_conflicts_with_sign_only_flags` (:1706-1723) — same
   convention as every other signing flag; expected RED today: the pairing
   parses successfully so `parse_err` panics "must be rejected".

- [ ] **Step 2: Run them, watch them fail**

Run: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-rs inject_extensions`
then `TMPDIR=$PWD/target/tmp cargo test -p zsign-cli inject_extensions`
Expected: all FAIL (compile error on the missing setter in the crate tests;
`ErrorKind::UnknownArgument` / un-rejected pairing in the CLI tests).

- [ ] **Step 3: Implement the flag end-to-end**

`ipa/mod.rs`:
- Field `/// Widen injection to top-level PlugIns/Extensions .appex (CLI -P)` /
  `inject_extensions: bool` — add to BOTH `new()` and `new_adhoc()` (`false`).
- Setter beside `dylib_injection`:
  `pub fn inject_extensions(mut self, inject: bool) -> Self { self.inject_extensions = inject; self }`
  with a doc comment stating: without it only the root bundle directory is
  injected; with it, top-level `PlugIns/<name>.appex` and
  `Extensions/<name>.appex` executables are added, each referencing the
  app-root copy via `@executable_path/<../ × N><name>`.
- Private helper in the same file (beside `find_standalone_dylibs` or the
  other bundle helpers):

```rust
/// Upstream single-level app-extension classification for `-P`: exactly
/// `<PlugIns|Extensions>/<name>.appex`, nothing deeper.
fn is_top_level_app_extension(relative: &Path) -> bool {
    let mut parts = relative.components();
    let first = matches!(parts.next(), Some(Component::Normal(dir))
        if dir.to_str().is_some_and(|d| d == "PlugIns" || d == "Extensions"));
    let second = matches!(parts.next(), Some(Component::Normal(name))
        if name.to_str().is_some_and(|n| n.ends_with(".appex")));
    first && second && parts.next().is_none()
}
```

(use `std::path::Component` — import style per the file's existing `use` block.)

- Replace Task 2's root-only insert with the full loop over `bundles`:

```rust
for (path, _) in &bundles {
    let Ok(relative) = path.strip_prefix(&bundle_path) else {
        continue;
    };
    let in_scope = path == &bundle_path
        || (self.inject_extensions && is_top_level_app_extension(relative));
    if !in_scope {
        continue;
    }
    let up = "../".repeat(relative.components().count());
    injection.insert(
        path.clone(),
        bases.iter().map(|b| format!("@executable_path/{up}{b}")).collect(),
    );
}
```

(root: `strip_prefix` yields `""`, zero components, `up` empty — identical to
Task 2's root string.)

`builder.rs`: field `inject_extensions: bool` (+ `false` in `new()`), setter
with doc, and in BOTH `sign_ipa` and `sign_bundle` next to the existing
`allow_unsafe_profile` forwarding:
`if self.inject_extensions { signer = signer.inject_extensions(true); }`

`main.rs`:
- Field after `weak` (:142-144):

```rust
/// Also inject -l dylibs into top-level app extensions (PlugIns/,
/// Extensions/): each extension executable references the single
/// app-root copy via @executable_path/../../<name>. Without this flag
/// only the root bundle directory is injected.
#[arg(short = 'P', long)]
inject_extensions: bool,
```

- `-V` `conflicts_with_all` (:178-184): add `"inject_extensions"` after
  `"weak"`.
- `run()` after the `dylib_injection` block (:275-277):
  `if cli.inject_extensions { signer = signer.inject_extensions(true); }`

- [ ] **Step 4: Watch the tests pass**

Run: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-rs`
and `TMPDIR=$PWD/target/tmp cargo test -p zsign-cli`
Expected: all pass.

- [ ] **Step 5: README rows (same commit)**

- Flag table (:208-209): replace the `-l, --dylibs` description with the
  copy-and-rewrite contract (file must exist and be Mach-O — rejected at
  parse time; copied to the app root and injected as
  `@executable_path/<name>`; root bundle directory only unless `-P`; a bare
  Mach-O input gets the path injected verbatim). Insert a new `-P,
  --inject-extensions` row after `-w, --weak` (mirrors the help text).
- Migration table (~:385-392, same three-column shape): add one row for
  `-l`/`-P` — upstream copies to the app root and injects
  `@executable_path/<name>`, extensions only with `-P`, and silently skips a
  failed copy; zsign-rs matches the layout and scope, fails loudly instead of
  skipping, validates `-l` at parse time, and never injects XPC/Watch/
  AppClips (upstream does not either).
- Upstream-no-equivalent list (~:397-399): remove `-P` from the flag string
  and `extension injection` from the parenthetical (the feature now exists).

- [ ] **Step 6: Full zero-warning gate, then commit**

Run:
```
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test --workspace
```
Expected: all clean, all tests pass (this is the item's final gate).
Commit: `feat(cli): scope dylib injection behind extension flag`

---

## Plan self-review

- Spec coverage: embed gap → Task 2 (copy, rewrite, always-signed copy,
  overwrite parity, round trip + verify); validation → Task 1; scope gap →
  Task 2 default root-only + Task 3 `-P` widening and README classification;
  acceptance criteria 1-6 map to Task 1 Step 4, Task 2 tests 1/3/5, Task 2
  test 2, Task 3 test 1, and Task 3 Step 6 respectively.
- Step scan: every step names one deliverable (tests, one function body, one
  flag, one gate); no step carries undecidable "handle edge cases" lines.
- Type consistency: `Vec<PathBuf>` and `injected: &[String]` are defined in
  Task 1 / Task 2 Interfaces and reused unchanged in later tasks;
  `inject_extensions(bool)` is identical across CLI, builder, and IpaSigner.
- Review Focus: all five lines have a named pinning test in Task 2 or 3.
- Proportion: the plan names signatures, test names, and assertions; bodies
  appear only where the algorithm (scope formula, copy/merge order) is a
  decision the spec fixes.
