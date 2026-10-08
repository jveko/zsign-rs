# Content Dispatch and Default Output Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development (recommended) with dispatching-parallel-agents for independent tasks to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Route sign/verify on input content (directory, `PK` magic, Mach-O
magic) instead of file extension, and derive the default output name by
inserting `-signed` before the existing extension so the verify round trip
works.

**Architecture:** Two private helpers in `crates/zsign-cli/src/main.rs` —
`classify_input` (directory → 2-byte `PK` → eight Mach-O magics → unknown)
and `signed_output_path` — consumed by both `run()` and `run_verify()` at the
exact position the old extension computation occupied. The facade keeps
ownership of bundle `-o` semantics and all input validation.

**Tech Stack:** Rust 2021, clap 4 derive; fixtures from `zsign-core`
`test-fixtures` and the public `zsign_rs::create_ipa`.

**Spec:** `docs/superpowers/specs/2026-10-08-content-dispatch-default-output-design.md`

## Global Constraints

- Zero ticket IDs anywhere: no issue references in code, comments, docs, or
  commit messages.
- Files allowed: `crates/zsign-cli/src/main.rs` and `README.md` ONLY. Every
  other file (zsign facade, zsign-core, examples, CI) is read-only fact.
- Exit contract stays 0/1/2: unrecognized sign input → 1; unrecognized or
  unreadable `-V` input → 2; `verify_missing_file_exits_two` must keep passing
  byte-for-byte (its assertions unchanged).
- Zero-warning gate at item end: `cargo fmt --all -- --check` AND
  `cargo clippy --workspace --all-targets -- -D warnings`.
- Tests: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test --workspace`
  (scoped `-p zsign-cli` gates during flight).
- Commits: conventional, imperative, lowercase, no trailing period, no ticket
  IDs. One commit per task, after its scoped gate is green.
- The bundle arm's behavior (in place; `-o` forwarded to
  `ZSign::sign_bundle`, which owns the `.ipa`-suffix repack rule) must not
  change; `--json` document shapes must not change.

## Review Focus

1. Missing/unreadable input keeps its codes and `error: ` prefix: sign → 1,
   `-V` → 2 — pinned by the new `missing_input_sign_exits_one` plus the
   existing `verify_missing_file_exits_two` (unchanged).
2. Every existing `-V` exit-code pin survives content routing (valid → 0,
   unsigned Mach-O → 1, garbage/script/loose-signed → 2) — pinned by those
   existing tests running unmodified in the scoped gate.
3. Default naming edges: `app` (no extension) → `app-signed` (never
   `.signed`), `a.b.tar.gz` → `a.b.tar-signed.gz` — pinned by
   `signed_output_path_preserves_extension`.
4. Directory classification beats a misleading name: a directory called
   `sneaky.ipa` routes to the bundle arm — pinned by
   `classify_input_routes_by_content_not_name`.
5. The bundle arm keeps facade semantics: directory signs in place with no
   `-o`, repacks with `-o out.ipa` — pinned by
   `directory_without_app_suffix_routes_to_bundle`.

---

### Task 1: Content dispatch + extension-preserving default output

**Files:**
- Modify: `crates/zsign-cli/src/main.rs` — private helpers beside
  `parse_dylib`/`parse_profile_map` (:197-223); the `input` field doc
  (:23-24); `run()` dispatch (:309-341); `run_verify()` dispatch (:346-355);
  tests module

**Interfaces:**
- Produces:
  - `enum InputKind { Bundle, Archive, MachO, Unknown }` (private)
  - `fn classify_input(path: &Path) -> Result<InputKind, String>`
  - `fn signed_output_path(input: &Path) -> PathBuf`
- Consumes: `parse_err`, `run_cli`, `TempDir`, `fixtures` (test-only);
  `zsign_rs::create_ipa(app_dir, ipa_path, zsign_rs::CompressionLevel::DEFAULT)`
  for the IPA fixture (public re-export, `ipa/archive.rs:212`).
- Supersedes: the `let ext = …` + `match ext…` blocks — both are deleted and
  replaced by `classify_input` matches (nothing else in `run()` moves; the
  classify call sits exactly where `ext` was computed, after signer
  construction, so credential-error precedence is unchanged).

- [ ] **Step 1: Write the failing tests (Tester)**

Add to `crates/zsign-cli/src/main.rs` tests. Conventions: `TempDir`, footers
print actual values (write real footer strings, never an ellipsis), `run_cli`
takes `&[&OsStr]`.

**Unit tests:**

1. `classify_input_routes_by_content_not_name`
   - directory named `sneaky.ipa` → `InputKind::Bundle` (directory test must
     precede the magic test);
   - file `renamed.signed` containing `b"PK\x03\x04payload"` → `Archive`;
   - file containing `b"PK\x05\x06"` (empty-archive magic, APPNOTE §4.3.16)
     → `Archive`;
   - files whose first 4 bytes are `[0xcf,0xfa,0xed,0xfe]` (thin 64),
     `[0xce,0xfa,0xed,0xfe]` (thin 32), `[0xca,0xfe,0xba,0xbe]` (FAT),
     `[0xca,0xfe,0xba,0xbf]` (FAT64) → `MachO` each (loop, footer prints the
     case name and the actual `classify_input` result);
   - file containing `b"neither a zip nor a mach-o"` → `Unknown`;
   - `classify_input(&root.join("nope.bin"))` returns `Err` whose message
     contains `nope.bin`.
2. `signed_output_path_preserves_extension`
   - `in.ipa` → `in-signed.ipa`; `tool.bin` → `tool-signed.bin`; `app` →
     `app-signed`; `a.b.tar.gz` → `a.b.tar-signed.gz`; all under the same
     parent `TempDir` (assert full paths so the parent is pinned).

**Integration tests (real binary via `run_cli`):**

3. New fixture helper in the tests module (tests-only, beside
   `make_encrypted_app` at :1039-1058): `fn make_signable_app(dir: &Path, name: &str) -> PathBuf`
   — mirrors `make_encrypted_app`'s `Info.plist` XML exactly but with
   `CFBundleExecutable` = `Test`, `CFBundleIdentifier` = `com.test.plain`, and
   the main binary written as `Test` = `fixtures::make_minimal_macho()`
   (unsigned; adhoc-signable), plus a `data.bin` (2048 × 0xAB, same as the
   encrypted helper). Returns the bundle directory path.
4. `default_output_preserves_extension_and_verifies`
   - `let app = make_signable_app(root, "App.app"); let ipa = root.join("app.ipa");`
     then `zsign_rs::create_ipa(&app, &ipa, zsign_rs::CompressionLevel::DEFAULT).unwrap();`
   - `run_cli(&[OsStr::new("-a"), ipa.as_os_str()], &[])` → exit 0
     (absolute TempDir paths via `.as_os_str()`, the `&[…], &[]` two-argument
     form of `run_cli` at :1099);
   - assert `root.join("app-signed.ipa")` EXISTS and `root.join("app.signed")`
     does NOT (footer prints the directory entries);
   - `run_cli(&[OsStr::new("-V"), root.join("app-signed.ipa").as_os_str()], &[])`
     → exit 0, stdout contains `verified: yes`.
   - RED today: the sign writes `app.signed`, so `app-signed.ipa` is missing.
5. `zip_input_routes_to_archive`
   - `let app = make_signable_app(root, "App.app"); let zip = root.join("bundle.zip");`
     then `zsign_rs::create_ipa(&app, &zip, zsign_rs::CompressionLevel::DEFAULT).unwrap();`
     (the fixture is a real zip regardless of its `.zip` name);
   - `let out = root.join("out.ipa"); run_cli(&[OsStr::new("-a"), OsStr::new("-o"), out.as_os_str(), zip.as_os_str()], &[])`
     → exit 0, `out` exists; `run_cli(&[OsStr::new("-V"), out.as_os_str()], &[])`
     → exit 0.
   - RED today: extension `_` arm hits the Mach-O parser → exit 1.
6. `directory_without_app_suffix_routes_to_bundle`
   - `let plain = make_signable_app(root, "PlainBundle");` (no `.app` suffix);
   - `run_cli(&[OsStr::new("-a"), plain.as_os_str()], &[])` → exit 0 (in
     place: `plain` still has `Info.plist`);
   - `run_cli(&[OsStr::new("-V"), plain.as_os_str()], &[])` → exit 0, stdout
     contains `verified: yes`;
   - second sign: `let repack = root.join("repack.ipa"); run_cli(&[OsStr::new("-a"), OsStr::new("-o"), repack.as_os_str(), plain.as_os_str()], &[])`
     → exit 0 and `repack` exists (bundle arm still forwards `-o` to the
     facade).
   - RED today: extension `""` arm reads a directory → exit 1; `-V` routes to
     `verify_macho_file` → 2.
7. `unknown_input_is_reported_clearly`
   - `let blob = root.join("blob.dat"); std::fs::write(&blob, b"neither a zip nor a mach-o").unwrap();`
   - `run_cli(&[OsStr::new("-a"), blob.as_os_str()], &[])` → exit 1 and
     stderr contains `unsupported input` AND `blob.dat`;
   - `run_cli(&[OsStr::new("-V"), blob.as_os_str()], &[])` → exit 2 and
     stderr contains `unsupported input`.
   - RED today: both fail with the Mach-O parser's `Failed to parse` message,
     which contains neither phrase.
8. `missing_input_sign_exits_one` (preservation guard — expected to PASS
   before AND after; it defends the refactor):
   - `run_cli(&[OsStr::new("-a"), root.join("nope.ipa").as_os_str()], &[])`
     → exit 1; stderr starts with `error: `.

- [ ] **Step 2: Run them, watch them fail**

Run: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-cli classify_input`
→ compile RED (missing symbols). After Step 1's full module is in place the
whole package cannot compile, which is the RED for every test above; capture
that compiler error verbatim. Tests 1-7 must fail for the missing feature;
test 8 is the stated preservation guard.

- [ ] **Step 3: Implement the classifier, default-name helper, and wiring**

Add to `main.rs`, beside `parse_dylib` (:197-223) — exact bodies from the
spec §Classifier / §Default output name:

```rust
/// Content classes the CLI routes on. Detection order (upstream parity):
/// directory, then the 2-byte `PK` zip marker, then Mach-O magic.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum InputKind {
    Bundle,
    Archive,
    MachO,
    Unknown,
}

/// Mach-O magic as seen by a little-endian reader: thin 32/64 (native and
/// byte-swapped headers) plus FAT/FAT64 containers. Dispatch is permissive —
/// the Mach-O arm's parser decides signability.
const MACHO_MAGICS: [u32; 8] = [
    0xfeed_face, 0xcefa_edfe, // MH_MAGIC, MH_CIGAM
    0xfeed_facf, 0xcffa_edfe, // MH_MAGIC_64, MH_CIGAM_64
    0xcafe_babe, 0xbeba_feca, // FAT_MAGIC, FAT_CIGAM
    0xcafe_babf, 0xbfbafeca, // FAT_MAGIC_64, FAT_CIGAM_64
];

/// Classifies the input by content, never by extension. Read failures keep
/// the path the raw OS error would drop: NotFound becomes "input not found:
/// <path>", everything else "cannot read input <path>: <err>".
fn classify_input(path: &Path) -> Result<InputKind, String> {
    use std::io::Read as _;

    if path.is_dir() {
        return Ok(InputKind::Bundle);
    }
    let mut file = std::fs::File::open(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            format!("input not found: {}", path.display())
        } else {
            format!("cannot read input {}: {e}", path.display())
        }
    })?;
    let mut buf = [0u8; 4];
    let n = file
        .read(&mut buf)
        .map_err(|e| format!("cannot read input {}: {e}", path.display()))?;
    if n >= 2 && buf[..2] == *b"PK" {
        return Ok(InputKind::Archive);
    }
    if n == 4 && MACHO_MAGICS.contains(&u32::from_le_bytes(buf)) {
        return Ok(InputKind::MachO);
    }
    Ok(InputKind::Unknown)
}

/// Default output for archive/binary signing: insert `-signed` before the
/// existing extension (`in.ipa` → `in-signed.ipa`, `app` → `app-signed`),
/// preserving the extension so `-V` round trips on content.
fn signed_output_path(input: &Path) -> PathBuf {
    let mut name = std::ffi::OsString::new();
    if let Some(stem) = input.file_stem() {
        name.push(stem);
    }
    name.push("-signed");
    if let Some(ext) = input.extension() {
        name.push(".");
        name.push(ext);
    }
    let mut out = input.to_path_buf();
    out.set_file_name(name);
    out
}
```

(If `Path`/`PathBuf` are not already imported under those names at file
scope, use fully-qualified `std::path::…` types as the file's neighbors do —
match the existing import block, do not add a second `use` style.)

**Routing — `run()`**: replace the `let ext = …` block (:309) and the
`match ext…` (:311-341) with a match on `classify_input(&cli.input)?`
(exact position: after signer construction, where `ext` was; `String` errors
box into the existing `Result` → exit 1):

```rust
match classify_input(&cli.input)? {
    InputKind::Bundle => {
        signer.sign_bundle(&cli.input, cli.output.as_deref())?;
        match &cli.output {
            Some(ipa) => report_sign(json, false, &ipa.display().to_string()),
            None => report_sign(json, true, &cli.input.display().to_string()),
        }
    }
    InputKind::Archive => {
        let output = cli
            .output
            .unwrap_or_else(|| signed_output_path(&cli.input));
        signer.sign_ipa(&cli.input, &output)?;
        report_sign(json, false, &output.display().to_string());
    }
    InputKind::MachO => {
        let output = cli
            .output
            .unwrap_or_else(|| signed_output_path(&cli.input));
        signer.sign_macho(&cli.input, &output)?;
        report_sign(json, false, &output.display().to_string());
    }
    InputKind::Unknown => {
        return Err(format!(
            "unsupported input '{}': expected an app bundle directory, ZIP archive, or Mach-O binary",
            cli.input.display()
        )
        .into());
    }
}
```

(arm bodies are the current arms verbatim — only the discriminant changes.)

**Routing — `run_verify()`**: replace the extension match (:346-355) with:

```rust
let kind = match classify_input(input) {
    Ok(kind) => kind,
    Err(msg) => {
        emit_error(json, &msg);
        return ExitCode::from(2);
    }
};
let report = match kind {
    InputKind::Bundle => zsign_rs::verify::verify_bundle(input),
    InputKind::Archive => zsign_rs::verify::verify_ipa(input),
    InputKind::MachO => zsign_rs::verify::verify_macho_file(input),
    InputKind::Unknown => {
        emit_error(
            json,
            &format!(
                "unsupported input '{}': expected an app bundle directory, ZIP archive, or Mach-O binary",
                input.display()
            ),
        );
        return ExitCode::from(2);
    }
};
```

(The `Err(report)` / `report.errors` handling below stays byte-for-byte.)

**Input doc** (:23-24): `/// Input: app bundle directory, IPA/ZIP archive, or Mach-O binary (detected by content, not extension)`.

- [ ] **Step 4: Watch them pass**

Run: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-cli`
Expected: all tests pass, including tests 1-8 and every pre-existing test
(`verify_missing_file_exits_two`, the five `-V` exit pins, the dylib tests).

- [ ] **Step 5: Scoped gate + commit**

Run: `cargo clippy -p zsign-cli --all-targets -- -D warnings` and
`cargo fmt --all -- --check`.
Expected: clean.
Commit: `feat(cli): route inputs by content and keep output extension`

---

### Task 2: README rows + full zero-warning gate

**Files:**
- Modify: `README.md` (append-only within each section; four spots from the
  spec §README)

**Interfaces:**
- Consumes: Task 1's user-visible behavior (help text now says
  content-detected; default output `<name>-signed.<ext>`).

- [ ] **Step 1: Edit the four README spots (implementer)**

1. `<INPUT>` row (~:188): `|<INPUT>|path|Input: app bundle directory, IPA/ZIP archive, or Mach-O binary — detected by content, not extension; required|`
2. `-o, --output` row (~:189): `|`-o, --output`|path|Output file; without it, archives and binaries default to `<name>-signed.<ext>` (extension preserved, e.g. `in.ipa` → `in-signed.ipa`) and bundles sign in place|`
3. CLI quick start (~:159-176): append one example block after the PEM example:
   ```bash
   # No -o: the default output keeps the extension (input.ipa -> input-signed.ipa)
   zsign-cli -a input.ipa
   ```
4. Migration table (~:385-388): append one row in the existing three-column
   shape:
   `|input routing / default `-o`|sniffs the 2-byte `PK` marker and folders (no extension check); zip without `-o` errors, Mach-O signs in place|same content sniff (directory, `PK`, Mach-O magic incl. FAT) with an explicit unsupported-input error; default output preserves the extension (`in-signed.ipa`) instead of signing in place|`

Match the surrounding table's exact column syntax (verify against the
neighbors you quote while editing).

- [ ] **Step 2: Full zero-warning gate**

Run:
```
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test --workspace
```
Expected: all clean, all tests pass (this is the item's final gate).

- [ ] **Step 3: Real-binary smoke + commit**

Smoke (after `cargo build -p zsign-cli`):
- `target/debug/zsign-cli -a -l '' in.ipa` still exits 2 (parse-time dylib
  validation untouched);
- `target/debug/zsign-cli -a /path/to/garbage-file` exits 1 with
  `unsupported input`;
- `target/debug/zsign-cli -V /path/to/garbage-file` exits 2 with the same
  message; `target/debug/zsign-cli --help` shows the new input description.
Record verbatim output in the report.
Commit: `docs(cli): document content dispatch and default output`

---

## Plan self-review

- Spec coverage: dispatch gap → Task 1 (classifier + both routings, tests
  4/5/6/7); default-name gap → Task 1 (`signed_output_path`, tests 1/2/4);
  acceptance 1-6 map to tests 4/5/6/7, test 8 + existing
  `verify_missing_file_exits_two`, and Task 2 Step 2 respectively; README
  spec section → Task 2 Step 1.
- Step scan: every step names one deliverable; the only embedded code is the
  bodies the spec fixes (classifier, name derivation, arm wiring).
- Type consistency: `InputKind`/`classify_input`/`signed_output_path` names
  and signatures identical between Task 1's test and implementation blocks
  and the spec.
- Review Focus: all five lines have a named pinning test in Task 1.
- Proportion: tests and exact strings carry the decisions; prose stays at the
  level the spec already fixed. Two tasks, each independently green, matching
  the two-file scope (code, then docs).
