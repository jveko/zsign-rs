# ZSN-5 CLI Surface Implementation Plan (ZSN-5 + ZSN-6 + ZSN-36)

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development with
> dispatching-parallel-agents for independent tasks to implement this plan task-by-task.
> Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the `zsign-cli` surface honest and scriptable: a real 0/1/2 exit-code
contract for verify, a stable `--json` schema, upstream-compatible `-p`/`-k` flag
meanings with content-based key loading, an env+prompt password channel, and clap-level
flag validation with file-naming credential errors.

**Architecture:** All work lives in `crates/zsign-cli/src/main.rs` (single-file CLI).
`main() -> ExitCode` with `run(cli) -> Result<ExitCode, …>` replaces `Result`-based
termination; `run_verify` catches constructor errors at its boundary and maps 0/1/2
explicitly; `--json` renders CLI-local serde mirror DTOs of the verify report graph
(no lib changes — every report field is `pub`); credential routing sniffs key content
(PEM marker / DER / PKCS#12) in `load_credentials`; password resolution is
flag → env (`ZSIGN_PASSWORD`, clap `env`) → `""` trial → single no-echo TTY prompt
(`rpassword`, gated by `std::io::IsTerminal`).

**Tech Stack:** Rust 2021, clap 4.6.7 (locked; features `derive`+`env`), serde +
serde_json + base64 + rpassword (all carriers justified in the design doc),
`std::process::Command` subprocess tests (no dev-dep additions).

**Design authority:** `docs/superpowers/specs/2026-09-25-cli-surface-design.md`
(every decision + rejected alternative recorded there; this plan only executes it —
the JSON schema section is normative for Task 2).

**Scope fence (violating = lane collision):** edit ONLY
`crates/zsign-cli/src/main.rs` (source + inline tests) and the dependency lines of
`crates/zsign-cli/Cargo.toml`, plus the two sanctioned outside edits: the `-p`→`--pkcs12`
caller migration in `scripts/verify-apple-interop.sh` (Task 3) and the two force-added
docs. Never edit `builder.rs`, `zsign/src/verify.rs`, `zsign-core/**`, `.gitignore`,
README. No `cargo fmt` / `cargo clippy` / `hk` mid-flight. Never merge, never push.
No ticket IDs in code comments.

**Gates (run after every task; never fmt/clippy/hk):**

```bash
mkdir -p .tmptmp
TMPDIR=$PWD/.tmptmp cargo test -p zsign-cli
TMPDIR=$PWD/.tmptmp cargo test -p zsign-rs verify -- --skip test_ipa_signing_is_deterministic
```

Baseline in this worktree before any change: `cargo test -p zsign-cli` → **2 passed,
0 failed**; `cargo test -p zsign-rs verify -- --skip test_ipa_signing_is_deterministic`
→ 22 passed, 0 failed (ZSN-15: the skipped determinism test fails pre-existing —
the skip is mandatory). Existing tests `cli_refuses_encrypted_without_force` and
`cli_signing_encrypted_with_force_succeeds` must stay green in every run.

**Commit rule:** one commit series per queue item, in queue order 1→5, each
independently green at the gate. Conventional subject, imperative, lowercase, ticket in
the subject only:

1. `feat(cli): map verification hard errors to exit 2 (zsn-5)`
2. `feat(cli): add machine-readable json output (zsn-5)`
3. `feat(cli): restore upstream -p/-k password and key semantics (zsn-36)`
4. `feat(cli): add env fallback and tty prompt for p12 passwords (zsn-6)`
5. `feat(cli): validate flag combinations and credential errors (zsn-5)`

**Pipeline per task (subagent-driven-development):** a Tester subagent writes the
failing inline tests first (red gate), an implementer subagent greens them, the
controller runs the scoped gate and commits before the next task. Subagents skip
formatters, linters, and project-wide tests.

---

## File structure

| File | Role |
|---|---|
| `crates/zsign-cli/src/main.rs` | Everything: `Cli` attrs (T3/T4/T5), `main`/`run`/`run_verify` (T1), JSON DTOs + emitters (T2), `load_credentials` routing (T3), password resolution + prompt (T4), constraints + `read_credential_file` (T5), inline `mod tests` (all tasks) |
| `crates/zsign-cli/Cargo.toml` | T2: `serde`(derive)+`serde_json`; T3: `base64`; T4: `clap` features `["derive","env"]` + `rpassword`. No dev-dep changes, ever |
| `scripts/verify-apple-interop.sh` | T3 only: `-p "$WORK/cs.p12"` → `--pkcs12 "$WORK/cs.p12"` (sign_and_verify invocations) |

**Test-harness contract (every task's subprocess tests use these helpers, introduced
in Task 1 and reused verbatim):**

```rust
/// Path to the freshly built zsign-cli binary, building it once per test process.
/// Cargo does not build the bin target for unit tests (no tests/ dir), so the child
/// `cargo build` is what makes the executable exist and be current.
fn zsign_bin() -> std::path::PathBuf {
    static BIN: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();
    BIN.get_or_init(|| {
        let exe = std::env::current_exe().expect("test executable path");
        let profile_dir = exe.parent().expect("deps dir").parent().expect("profile dir");
        let out = std::process::Command::new("cargo")
            .args(["build", "-p", "zsign-cli", "-q"])
            .output()
            .expect("spawn cargo build for zsign-cli");
        assert!(
            out.status.success(),
            "cargo build -p zsign-cli failed:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        profile_dir.join(format!("zsign-cli{}", std::env::consts::EXE_SUFFIX))
    })
}

struct CliRun {
    code: i32,
    stdout: String,
    stderr: String,
}

fn run_cli(args: &[&std::ffi::OsStr], envs: &[(&str, &str)]) -> CliRun { /* spawn zsign_bin(),
    capture output, map exit code (None => -1). Environment handling: start from the
    inherited env, REMOVE any inherited ZSIGN_PASSWORD (so a developer's shell export
    cannot flake the tests), then apply the `envs` pairs on top. */ }
```

Subprocess tests pass absolute paths only (fixtures written into `TempDir`), so the
child's cwd is irrelevant. `TempDir` honors `TMPDIR=$PWD/.tmptmp` (tempfile delegates
to `std::env::temp_dir`, tempfile-3.27.0/src/env.rs:11-48).

**Fixtures available to tests (all already committed, `include_bytes!` from main.rs):**
- `crates/zsign/src/ipa/fixtures/minimal_macho.bin` — unencrypted minimal arm64
  Mach-O; the same bytes zsign-wasm's proven adhoc roundtrip signs
  (zsign-wasm/src/lib.rs:700, 1441-1466). Path from main.rs:
  `../../zsign/src/ipa/fixtures/minimal_macho.bin`.
- `crates/zsign-core/src/crypto/fixtures/identity_single.p12` — policy-compliant leaf,
  password `testpassword` (loads successfully in cert.rs:895-897). Path:
  `../../zsign-core/src/crypto/fixtures/identity_single.p12`.
- `encrypted_macho()` / `make_encrypted_app()` (main.rs:399-497, existing helpers) —
  for bundle-level cases.
- No PEM/DER cert/key fixtures exist in the repo; PEM/DER routes are therefore tested
  at the routing/error layer (design doc, item 5 test rationale) — the loaders
  themselves are pinned by zsign-core tests.

---

## Task 1: Exit-code contract (queue item 1, commit 1)

**Files:**
- Modify: `crates/zsign-cli/src/main.rs` — `main` (98-100), `run` (103-174),
  `run_verify` (176-203), `print_report` warnings loop (215-217)
- Test: `crates/zsign-cli/src/main.rs` inline `mod tests` (new helpers + 6 tests)

- [ ] **Step 1.1: Write the failing subprocess tests (Tester subagent)**

Add the harness contract helpers (`zsign_bin`, `run_cli`, `CliRun`) plus:

```rust
const MINIMAL_MACHO: &[u8] =
    include_bytes!("../../zsign/src/ipa/fixtures/minimal_macho.bin");

#[test]
fn verify_valid_input_exits_zero() {
    let dir = TempDir::new().unwrap();
    let input = dir.path().join("in.bin");
    std::fs::write(&input, MINIMAL_MACHO).unwrap();
    let signed = dir.path().join("signed.bin");
    let sign = run_cli(&[OsStr::new("-a"), OsStr::new("-o"), signed.as_os_str(),
                         input.as_os_str()], &[]);
    assert_eq!(sign.code, 0, "adhoc sign failed: {}", sign.stderr);
    let v = run_cli(&[OsStr::new("-V"), signed.as_os_str()], &[]);
    assert_eq!(v.code, 0, "expected 0, stderr: {}", v.stderr);
    assert!(v.stdout.contains("verified: yes"), "stdout: {}", v.stdout);
}

#[test]
fn verify_invalid_input_exits_one() {
    // unsigned minimal macho: slice error (no LC_CODE_SIGNATURE), top-level errors empty
    let dir = TempDir::new().unwrap();
    let input = dir.path().join("in.bin");
    std::fs::write(&input, MINIMAL_MACHO).unwrap();
    let v = run_cli(&[OsStr::new("-V"), input.as_os_str()], &[]);
    assert_eq!(v.code, 1, "expected 1, stderr: {}", v.stderr);
    assert!(v.stdout.contains("verified: no"), "stdout: {}", v.stdout);
}

#[test]
fn verify_missing_file_exits_two() {
    let dir = TempDir::new().unwrap();
    let v = run_cli(&[OsStr::new("-V"), dir.path().join("nope.bin").as_os_str()], &[]);
    assert_eq!(v.code, 2, "expected 2, stderr: {}", v.stderr);
    assert!(v.stderr.starts_with("error: "), "stderr: {}", v.stderr);
    // regression pin: Rust's Result-termination prefix must not come back
    assert!(!v.stderr.starts_with("Error:"), "stderr: {}", v.stderr);
}

#[test]
fn verify_invalid_zip_exits_two() {
    let dir = TempDir::new().unwrap();
    let input = dir.path().join("garbage.ipa");
    std::fs::write(&input, b"this is not a zip archive").unwrap();
    let v = run_cli(&[OsStr::new("-V"), input.as_os_str()], &[]);
    assert_eq!(v.code, 2, "expected 2, stderr: {}", v.stderr);
}

#[test]
fn verify_non_macho_input_exits_two() {
    let dir = TempDir::new().unwrap();
    let input = dir.path().join("plain.bin");
    std::fs::write(&input, b"#!/bin/sh\necho hi\n").unwrap();
    let v = run_cli(&[OsStr::new("-V"), input.as_os_str()], &[]);
    assert_eq!(v.code, 2, "expected 2, stderr: {}", v.stderr);
}

#[test]
fn verify_bound_slot_without_bundle_context_exits_two() {
    // bundle signing binds slot content on its main executable (IpaSigner's
    // adhoc path passes info_data/code_resources, ipa/mod.rs:1029-1035);
    // verifying that executable loose (no bundle context) makes
    // verify_macho_file populate top-level report errors => exit 2
    let dir = TempDir::new().unwrap();
    let app = make_encrypted_app(dir.path());
    let sign = run_cli(&[OsStr::new("-a"), OsStr::new("-f"), app.as_os_str()], &[]);
    assert_eq!(sign.code, 0, "bundle sign failed: {}", sign.stderr);
    let loose = dir.path().join("loose.bin");
    std::fs::copy(app.join("Enc"), &loose).unwrap();
    let v = run_cli(&[OsStr::new("-V"), loose.as_os_str()], &[]);
    assert_eq!(v.code, 2, "expected 2, stderr: {}", v.stderr);
    assert!(v.stdout.contains("verified: no"), "stdout: {}", v.stdout);
}
```

Also migrate the two existing tests' expectations only if compilation forces it —
`run(cli)` keeps returning `Result`, so they must compile unchanged.

- [ ] **Step 1.2: Run the red gate**

Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-cli`
Expected: new tests FAIL (the bin still exits 1 for missing/zip/non-Mach-O; the
report-based class exits 2 today only if reachable) and the suite compiles.
Diagnose any compile error before proceeding (Systematic-debugging skill).

- [ ] **Step 1.3: Restructure entry points (implementer subagent)**

Replace `main` (main.rs:98-100):

```rust
fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::from(1) // signing/credential failures: unchanged contract (design, item 1)
        }
    }
}
```

`run` (main.rs:103-174): signature becomes `fn run(cli: Cli) -> Result<ExitCode, Box<dyn std::error::Error>>`;
the verify short-circuit becomes `return Ok(run_verify(&cli.input));`; the sign path
gains `Ok(ExitCode::from(0))` where it currently returns `Ok(())` (main.rs:172).
Everything else in `run` stays byte-identical.

Rewrite `run_verify` (main.rs:176-203):

```rust
/// Maps verification to the exit-code contract: 0 valid, 1 invalid,
/// 2 could-not-complete (unreadable/unsupported input or a report with
/// top-level errors).
fn run_verify(input: &std::path::Path) -> ExitCode {
    let report = match input
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_lowercase())
        .as_deref()
    {
        Some("ipa") => zsign_rs::verify::verify_ipa(input),
        Some("app") => zsign_rs::verify::verify_bundle(input),
        _ => zsign_rs::verify::verify_macho_file(input),
    };
    let report = match report {
        Ok(report) => report,
        Err(err) => {
            eprintln!("error: {err}");
            return ExitCode::from(2);
        }
    };

    print_report(&report);

    if report.valid() {
        ExitCode::from(0)
    } else if report.errors.is_empty() {
        ExitCode::from(1)
    } else {
        eprintln!("error: verification could not complete");
        ExitCode::from(2)
    }
}
```

Delete in `print_report` (main.rs:215-217): the `for w in &report.warnings` loop —
`VerifyReport.warnings` has zero writers in the workspace (dead code). Keep the
`report.errors` stdout loop (reachable). Keep `print_macho`/`print_bundle` untouched.
Add `use std::process::ExitCode;` to the imports.

- [ ] **Step 1.4: Green gate**

Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-cli`
Expected: all tests pass (2 old + 6 new). Then the zsign-rs gate (unchanged surface):
`TMPDIR=$PWD/.tmptmp cargo test -p zsign-rs verify -- --skip test_ipa_signing_is_deterministic`
Expected: 22 passed.

- [ ] **Step 1.5: Commit**

`git add crates/zsign-cli/src/main.rs && git commit -m "feat(cli): map verification hard errors to exit 2 (zsn-5)"`
(pre-commit hook runs automatically; do not invoke fmt/clippy/hk yourself.)

---

## Task 2: `--json` output (queue item 2, commit 2)

**Files:**
- Modify: `crates/zsign-cli/Cargo.toml` — `[dependencies]` gains
  `serde = { version = "1", features = ["derive"] }` and `serde_json = "1"`
  (both versions already in Cargo.lock; no other manifest change)
- Modify: `crates/zsign-cli/src/main.rs` — `Cli` (new `json` field), `run`,
  `run_verify`, new DTO module section, new emitters; inline tests

- [ ] **Step 2.1: Write the failing JSON tests (Tester subagent)**

```rust
fn parse_json(s: &str) -> serde_json::Value {
    serde_json::from_str(s).unwrap_or_else(|e| panic!("invalid JSON {e}: {s}"))
}

#[test]
fn json_sign_reports_output() {
    let dir = TempDir::new().unwrap();
    let input = dir.path().join("in.bin");
    std::fs::write(&input, MINIMAL_MACHO).unwrap();
    let signed = dir.path().join("signed.bin");
    let r = run_cli(&[OsStr::new("--json"), OsStr::new("-a"), OsStr::new("-o"),
                      signed.as_os_str(), input.as_os_str()], &[]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    let doc = parse_json(&r.stdout);
    assert_eq!(doc["status"], "signed");
    assert_eq!(doc["output"], signed.to_str().unwrap());
    assert!(signed.exists());
}

#[test]
fn json_verify_valid_and_invalid_documents() {
    let dir = TempDir::new().unwrap();
    let input = dir.path().join("in.bin");
    std::fs::write(&input, MINIMAL_MACHO).unwrap();
    let signed = dir.path().join("signed.bin");
    assert_eq!(run_cli(&[OsStr::new("-a"), OsStr::new("-o"), signed.as_os_str(),
                         input.as_os_str()], &[]).code, 0);

    let ok = run_cli(&[OsStr::new("--json"), OsStr::new("-V"), signed.as_os_str()], &[]);
    assert_eq!(ok.code, 0, "{}", ok.stderr);
    let doc = parse_json(&ok.stdout);
    assert_eq!(doc["status"], "valid");
    assert_eq!(doc["report"]["valid"], true);
    assert_eq!(doc["report"]["macho"]["slices"][0]["arch"], "arm64");
    assert_eq!(doc["report"]["macho"]["slices"][0]["pages"]["kind"], "matched");
    assert_eq!(doc["report"]["macho"]["slices"][0]["cms"]["no_signature"], true);

    let bad = run_cli(&[OsStr::new("--json"), OsStr::new("-V"), input.as_os_str()], &[]);
    assert_eq!(bad.code, 1, "{}", bad.stderr);
    let doc = parse_json(&bad.stdout);
    assert_eq!(doc["status"], "invalid");
    assert_eq!(doc["report"]["valid"], false);
}

#[test]
fn json_error_is_a_single_stderr_object() {
    let dir = TempDir::new().unwrap();
    let r = run_cli(&[OsStr::new("--json"), OsStr::new("-V"),
                      dir.path().join("nope.bin").as_os_str()], &[]);
    assert_eq!(r.code, 2, "{}", r.stderr);
    assert!(r.stdout.is_empty(), "stdout must stay empty: {}", r.stdout);
    let doc = parse_json(&r.stderr);
    assert_eq!(doc["status"], "error");
    assert!(doc["error"].as_str().unwrap().len() > 0);
}

#[test]
fn human_output_is_unchanged_without_json_flag() {
    // guard for the interop script's pinned stdout lines
    let dir = TempDir::new().unwrap();
    let input = dir.path().join("in.bin");
    std::fs::write(&input, MINIMAL_MACHO).unwrap();
    let r = run_cli(&[OsStr::new("-V"), input.as_os_str()], &[]);
    assert!(r.stdout.starts_with("verified: no\n"), "stdout: {}", r.stdout);
    assert!(r.stdout.contains("slice: arm64"), "stdout: {}", r.stdout);
}
```

The report-based `--json` case (status `"error"` **with** a report on stdout, plus the
stderr summary object) is covered by extending Task 1's
`verify_bound_slot_without_bundle_context_exits_two` with a `--json` twin only if the
schema test for `report.errors` proves cheap — the schema section is pinned by the
three tests above plus `json_verify_valid_and_invalid_documents`.

- [ ] **Step 2.2: Red gate** — `TMPDIR=$PWD/.tmptmp cargo test -p zsign-cli`
  Expected: FAIL to compile (no `serde_json` yet) → add the two dependency lines, rerun:
  Expected: new tests FAIL (`--json` unknown flag), old tests pass.

- [ ] **Step 2.3: Implement (implementer subagent)**

1. `Cli` gains:

```rust
    /// Emit a machine-readable JSON document on stdout; failures become JSON
    /// objects on stderr. Human-readable output stays the default.
    #[arg(long)]
    json: bool,
```

2. DTO section (place after the printers, before `load_credentials`) — `#[derive(serde::Serialize)]
   ` structs mirroring the design doc's "JSON schema v1" exactly:
   `VerifyDoc { status, input, report }`, `SignDoc { status, output }`,
   `ErrorDoc { status: "error", error }` (serialize `status` via a unit struct field
   typed as a private `Status` enum with `#[serde(rename_all = "snake_case")]`),
   `ReportDto`, `MachoDto`, `SliceDto`, `PagesDto` (internally tagged enum
   `#[serde(tag = "kind", rename_all = "snake_case")]` with variants `Matched`,
   `Empty`, `Mismatch { page_index }`, `CountMismatch { stored, computed }`),
   `SlotDto { slot: i32, name, check }` (check as a snake_case string enum), `CmsDto`
   (all 14 `CmsVerifyReport` fields except none — see schema), `BundleDto`
   (recursive), `BinaryDto`, `CrDto`. Implement `From<&T> for Dto` for each lib type;
   reuse the existing slot-label table (main.rs:264-272) for `SlotDto.name` (index i
   ⇒ slot `-(i+1)`, label lookup identical to `print_macho`).

3. Emitters:

```rust
fn emit_error(json: bool, message: &str) {
    if json {
        eprintln!("{}", serde_json::to_string(&ErrorDoc::new(message)).expect("error doc"));
    } else {
        eprintln!("error: {message}");
    }
}
```

4. Wiring: `run` reads `cli.json` before moving `cli`; sign success prints
   `serde_json::to_string(&SignDoc { status: Signed, output })` when `json`, else the
   existing `println!("Signed: …")` lines (byte-identical); sign `Err` still propagates
   and `main` renders it through `emit_error(json, &err)`; `run_verify(input, json)`
   prints `VerifyDoc` (single line, stdout) instead of `print_report` when `json`,
   keeps `print_report` otherwise, routes its hard-error branch and summary line
   through `emit_error`, and drops the human `error:` line when `json` already emitted
   the object… (follow the channel table: report-based case emits BOTH the stdout doc
   with `status: "error"` and the stderr summary object).

- [ ] **Step 2.4: Green gate** — both scoped gates (expected: all tests green —
  original 2 + Task 1's 6 + Task 2's 4; verify suite untouched at 22).

- [ ] **Step 2.5: Commit**
  `git add crates/zsign-cli/src/main.rs crates/zsign-cli/Cargo.toml Cargo.lock && git commit -m "feat(cli): add machine-readable json output (zsn-5)"`

Channel rule for implementers (design doc is normative): when `json` is set, EVERY
message the human path would print to stdout goes to stdout as the single `VerifyDoc`
/`SignDoc`; every message the human path would print to stderr (`error: …` lines)
becomes one `ErrorDoc` line on stderr; no human-format line may mix into either stream.

---

## Task 3: Upstream `-p`/`-k` restoration (queue item 3, commit 3)

**Files:**
- Modify: `crates/zsign-cli/src/main.rs` — `Cli` (`password`/`pkcs12`/`private_key`
  attrs, `after_help`), `load_credentials` (375-391) rewritten around content routing
- Modify: `crates/zsign-cli/Cargo.toml` — `[dependencies]` gains `base64 = "0.22"`
  (0.22.1 already in the lock)
- Modify: `scripts/verify-apple-interop.sh` — `-p "$WORK/cs.p12"` →
  `--pkcs12 "$WORK/cs.p12"` in every `sign_and_verify` invocation (grep `-p ` first;
  expected: the two callsites around :272-273)

- [ ] **Step 3.1: Write the failing tests (Tester subagent)**

```rust
const IDENTITY_P12: &[u8] =
    include_bytes!("../../zsign-core/src/crypto/fixtures/identity_single.p12");

#[test]
fn short_p_is_password_and_pkcs12_is_long_only() {
    let cli = Cli::parse_from(["zsign", "-a", "-p", "secret", "in.bin"]);
    assert_eq!(cli.password.as_deref(), Some("secret"));
    assert!(cli.pkcs12.is_none());
    // old -p <path> invocations now parse as a password string, not a path
    let cli = Cli::parse_from(["zsign", "-a", "-p", "some/path.p12", "in.bin"]);
    assert_eq!(cli.password.as_deref(), Some("some/path.p12"));
    // pkcs12 remains reachable, long-only
    let cli = Cli::parse_from(["zsign", "-a", "--pkcs12", "some/path.p12", "in.bin"]);
    assert_eq!(cli.pkcs12.as_deref(), Some(std::path::Path::new("some/path.p12")));
}

#[test]
fn help_carries_upstream_migration_note() {
    let r = run_cli(&[OsStr::new("--help")], &[]);
    assert_eq!(r.code, 0);
    assert!(
        r.stdout.contains("upstream users: -p/-k now match upstream; --pkcs12 is long-only"),
        "stdout: {}", r.stdout
    );
}

#[test]
fn key_route_pkcs12_content_loads_with_password() {
    // `-k` carrying p12 bytes + `-p` password signs a bare Mach-O to exit 0:
    // proves content routing (p12 branch) and that -p feeds from_p12.
    let dir = TempDir::new().unwrap();
    let key = dir.path().join("identity.p12");
    std::fs::write(&key, IDENTITY_P12).unwrap();
    let input = dir.path().join("in.bin");
    std::fs::write(&input, MINIMAL_MACHO).unwrap();
    let out = dir.path().join("out.bin");
    let r = run_cli(
        &[
            OsStr::new("-k"), key.as_os_str(),
            OsStr::new("-p"), OsStr::new("testpassword"),
            OsStr::new("-o"), out.as_os_str(),
            input.as_os_str(),
        ],
        &[],
    );
    assert_eq!(r.code, 0, "expected signed output, stderr: {}", r.stderr);
    assert!(out.exists());
}

#[test]
fn pkcs12_content_with_certificate_names_the_conflict() {
    let dir = TempDir::new().unwrap();
    let key = dir.path().join("identity.p12");
    std::fs::write(&key, IDENTITY_P12).unwrap();
    let input = dir.path().join("in.bin");
    std::fs::write(&input, MINIMAL_MACHO).unwrap();
    // the OID check runs before the certificate is read, so a nonexistent
    // -c path proves the misuse error fires first
    let r = run_cli(
        &[OsStr::new("-k"), key.as_os_str(), OsStr::new("-c"),
          dir.path().join("absent.pem").as_os_str(), OsStr::new("-o"),
          dir.path().join("o.bin").as_os_str(), input.as_os_str()],
        &[],
    );
    assert_eq!(r.code, 1, "stderr: {}", r.stderr);
    assert!(r.stderr.contains("PKCS#12"), "stderr: {}", r.stderr);
    assert!(r.stderr.contains("--certificate"), "stderr: {}", r.stderr);
}

#[test]
fn pem_key_without_certificate_names_the_missing_flag() {
    let dir = TempDir::new().unwrap();
    let key = dir.path().join("key.pem");
    std::fs::write(&key, concat!("-----BEGIN ", "PRIVATE KEY-----", "\n")).unwrap();
    let input = dir.path().join("in.bin");
    std::fs::write(&input, MINIMAL_MACHO).unwrap();
    let out = dir.path().join("o.bin");
    let r = run_cli(
        &[OsStr::new("-k"), key.as_os_str(), OsStr::new("-o"), out.as_os_str(),
          input.as_os_str()],
        &[],
    );
    assert_eq!(r.code, 1, "stderr: {}", r.stderr);
    assert!(r.stderr.contains("--certificate"), "stderr: {}", r.stderr);
}
```

Note: neither test uses `-a` — adhoc bypasses `load_credentials` entirely
(main.rs:108-113), so credential-routing tests must go through the signing path.

- [ ] **Step 3.2: Red gate** — `TMPDIR=$PWD/.tmptmp cargo test -p zsign-cli`
  Expected: new tests FAIL (`-p` still means pkcs12; no epilog; `-k` p12 content
  unparseable as PEM).

- [ ] **Step 3.3: Implement (implementer subagent)**

1. Flag attrs:

```rust
    /// Password for the PKCS#12 or key material (empty password is valid).
    /// Precedence: this flag beats the ZSIGN_PASSWORD environment variable.
    /// Values passed on the command line are visible to other users in
    /// process listings; prefer ZSIGN_PASSWORD where possible.
    #[arg(short = 'p', long)]
    password: Option<String>,

    /// PKCS#12 file (.p12)
    #[arg(long)]
    pkcs12: Option<PathBuf>,

    /// Private key or PKCS#12 file: format detected by content
    /// (PEM `-----BEGIN` key, DER key, or PKCS#12 — use `-k` alone for PKCS#12)
    #[arg(short = 'k', long)]
    private_key: Option<PathBuf>,
```

plus `#[command(after_help = "upstream users: -p/-k now match upstream; --pkcs12 is long-only"))]`
next to the existing `#[command(about …)]`. (The `env` attribute arrives in Task 4 —
do NOT add it yet; the help text's ZSIGN_PASSWORD sentence is added in Task 4 with it.)

2. `load_credentials` rewrite (routing table = design doc item 3):

```rust
fn load_credentials(cli: &Cli) -> Result<SigningCredentials, Box<dyn std::error::Error>> {
    if let Some(ref p12_path) = cli.pkcs12 {
        let data = std::fs::read(p12_path)?;
        let password = cli.password.as_deref().unwrap_or("");
        return Ok(SigningCredentials::from_p12(&data, password)?);
    }
    let Some(ref key_path) = cli.private_key else {
        // unreachable after Task 5's clap requirement; until then keep the
        // existing fallthrough message (deleted in Task 5)
        return Err("Must provide either --pkcs12 or both --certificate and --private-key".into());
    };
    let key_data = std::fs::read(key_path)?;
    if key_data.starts_with(b"-----BEGIN") {
        let Some(ref cert_path) = cli.certificate else {
            return Err("--certificate <FILE> is required with a PEM private key".into());
        };
        let cert_data = std::fs::read(cert_path)?;
        return Ok(SigningCredentials::from_pem(&cert_data, &key_data, None)?);
    }
    match &cli.certificate {
        // no PEM marker + certificate present: PKCS#12 content here is a
        // flag-combination mistake, not a key file — detect before the cert
        // loader misdiagnoses the ASN.1 as a broken certificate
        Some(cert_path) => {
            const P12_PKCS7_DATA_OID: &[u8] =
                &[0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02];
            if key_data
                .windows(P12_PKCS7_DATA_OID.len())
                .any(|w| w == P12_PKCS7_DATA_OID)
            {
                return Err("--private-key contains a PKCS#12 file, which cannot be \
                    combined with --certificate; pass -k alone (password via -p) or \
                    use --pkcs12"
                    .into());
            }
            let cert_data = std::fs::read(cert_path)?;
            let wrapped = pem_wrap_der(&key_data);
            Ok(SigningCredentials::from_pem(&cert_data, wrapped.as_bytes(), None)?)
        }
        // no PEM marker + no certificate => PKCS#12 content
        None => {
            let password = cli.password.as_deref().unwrap_or("");
            Ok(SigningCredentials::from_p12(&key_data, password)?)
        }
    }
}

/// Wraps raw DER key bytes in a PEM envelope so the PEM-only loader can
/// decode them (the library exposes no public DER entry point).
fn pem_wrap_der(der: &[u8]) -> String {
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = String::with_capacity(b64.len() + b64.len() / 64 + 64);
    out.push_str(concat!("-----BEGIN ", "PRIVATE KEY-----", "\n"));
    for line in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).expect("base64 is ascii"));
        out.push('\n');
    }
    out.push_str(concat!("-----END ", "PRIVATE KEY-----", "\n"));
    out
}
```

3. Interop script: replace `-p "$WORK/cs.p12"` with `--pkcs12 "$WORK/cs.p12"`
   (verify with `grep -n 'cs.p12' scripts/verify-apple-interop.sh` — only the
   `sign_and_verify` argument lists change; `--password test` lines stay).

- [ ] **Step 3.4: Green gate** — both scoped gates; additionally sanity-check that the
  script migration left no `-p "` path usage:
  `grep -n '`-p "' scripts/verify-apple-interop.sh` → no matches expected (grep via
  the Grep tool).

- [ ] **Step 3.5: Commit**
  `git add crates/zsign-cli/src/main.rs crates/zsign-cli/Cargo.toml Cargo.lock scripts/verify-apple-interop.sh && git commit -m "feat(cli): restore upstream -p/-k password and key semantics (zsn-36)"`

---

## Task 4: Password channel — env fallback + TTY prompt (queue item 4, commit 4)

**Files:**
- Modify: `crates/zsign-cli/Cargo.toml` — `clap = { version = "4.5.53", features = ["derive", "env"] }`
  and `[dependencies]` gains `rpassword = "7.5"`
- Modify: `crates/zsign-cli/src/main.rs` — `password` attr, `load_credentials` p12
  branches, new `resolve_p12_password`, inline tests

- [ ] **Step 4.1: Write the failing tests (Tester subagent)**

All subprocess tests; `run_cli`'s `envs` parameter carries `ZSIGN_PASSWORD` values.
Piped stdin (the default of `Command::output`) is the deterministic non-TTY case —
in-process tests must ALWAYS pass a password explicitly so no test can ever reach the
prompt and hang.

```rust
#[test]
fn env_password_signs_p12_without_flag() {
    let dir = TempDir::new().unwrap();
    let key = dir.path().join("identity.p12");
    std::fs::write(&key, IDENTITY_P12).unwrap();
    let input = dir.path().join("in.bin");
    std::fs::write(&input, MINIMAL_MACHO).unwrap();
    let out = dir.path().join("out.bin");
    let r = run_cli(
        &[OsStr::new("-k"), key.as_os_str(), OsStr::new("-o"), out.as_os_str(),
          input.as_os_str()],
        &[("ZSIGN_PASSWORD", "testpassword")],
    );
    assert_eq!(r.code, 0, "env password must work, stderr: {}", r.stderr);
    assert!(out.exists());
}

#[test]
fn argv_password_beats_env_password() {
    // env-only wrong password must FAIL first (proves the env value is read
    // at all), then flag+wrong-env must succeed (proves the flag wins) —
    // either case alone cannot distinguish precedence from env being ignored
    let dir = TempDir::new().unwrap();
    let key = dir.path().join("identity.p12");
    std::fs::write(&key, IDENTITY_P12).unwrap();
    let input = dir.path().join("in.bin");
    std::fs::write(&input, MINIMAL_MACHO).unwrap();

    let env_only = run_cli(
        &[OsStr::new("-k"), key.as_os_str(), OsStr::new("-o"),
          dir.path().join("o1.bin").as_os_str(), input.as_os_str()],
        &[("ZSIGN_PASSWORD", "wrong-password")],
    );
    assert_eq!(env_only.code, 1, "env value must be read: {}", env_only.stderr);
    assert!(env_only.stderr.contains("MAC mismatch"), "stderr: {}", env_only.stderr);

    let out = dir.path().join("o2.bin");
    let r = run_cli(
        &[OsStr::new("-k"), key.as_os_str(), OsStr::new("-p"),
          OsStr::new("testpassword"), OsStr::new("-o"), out.as_os_str(),
          input.as_os_str()],
        &[("ZSIGN_PASSWORD", "wrong-password")],
    );
    assert_eq!(r.code, 0, "flag must win over env, stderr: {}", r.stderr);
    assert!(out.exists());
}

#[test]
fn missing_password_on_non_tty_degrades_to_clear_error() {
    // no flag, no env, piped stdin: "" trial fails (MAC mismatch) and the
    // error must name both password channels instead of prompting
    let dir = TempDir::new().unwrap();
    let key = dir.path().join("identity.p12");
    std::fs::write(&key, IDENTITY_P12).unwrap();
    let input = dir.path().join("in.bin");
    std::fs::write(&input, MINIMAL_MACHO).unwrap();
    let r = run_cli(
        &[OsStr::new("-k"), key.as_os_str(), OsStr::new("-o"),
          dir.path().join("o.bin").as_os_str(), input.as_os_str()],
        &[],
    );
    assert_eq!(r.code, 1, "stderr: {}", r.stderr);
    assert!(r.stderr.contains("--password"), "stderr: {}", r.stderr);
    assert!(r.stderr.contains("ZSIGN_PASSWORD"), "stderr: {}", r.stderr);
    assert!(r.stderr.contains("MAC mismatch"), "must surface the real cause: {}", r.stderr);
}

#[test]
fn help_does_not_leak_env_password_value() {
    let r = run_cli(&[OsStr::new("--help")], &[("ZSIGN_PASSWORD", "s3cret-value")]);
    assert_eq!(r.code, 0);
    assert!(!r.stdout.contains("s3cret-value"), "leaked: {}", r.stdout);
    assert!(r.stdout.contains("[env: ZSIGN_PASSWORD]"), "stdout: {}", r.stdout);
}
```

```rust
const EMPTY_PASSWORD_P12: &[u8] =
    include_bytes!("../../zsign-core/src/crypto/fixtures/empty_password.p12");

#[test]
fn empty_password_container_is_never_treated_as_missing() {
    // no flag, no env: this fixture's `""` trial fails at the certificate
    // policy gate (not MAC), and a non-password failure must surface verbatim —
    // never the "no password supplied" channel hint, and never a prompt
    // (stdin is piped here, and a prompt would hang a CI job)
    let dir = TempDir::new().unwrap();
    let key = dir.path().join("empty.p12");
    std::fs::write(&key, EMPTY_PASSWORD_P12).unwrap();
    let input = dir.path().join("in.bin");
    std::fs::write(&input, MINIMAL_MACHO).unwrap();
    let r = run_cli(
        &[OsStr::new("-k"), key.as_os_str(), OsStr::new("-o"),
          dir.path().join("o.bin").as_os_str(), input.as_os_str()],
        &[],
    );
    assert!(!r.stderr.contains("MAC mismatch"), "not a password failure: {}", r.stderr);
    assert!(!r.stderr.contains("ZSIGN_PASSWORD"), "must not demand a password: {}", r.stderr);
    assert!(!r.stderr.contains("no password supplied"), "verbatim surface: {}", r.stderr);
}
```

Safety invariant for all tasks: in-process tests (the ones calling `run(cli)`)
MUST pass `-p`/env explicitly whenever credentials are involved — a test that reaches
the prompt on a developer's terminal would hang. Only subprocess tests (piped stdin)
exercise the no-password paths.

- [ ] **Step 4.2: Red gate** — `TMPDIR=$PWD/.tmptmp cargo test -p zsign-cli`
  Expected: env test FAILS (env feature not enabled → `ZSIGN_PASSWORD` ignored → MAC
  mismatch), degradation test FAILS (stderr lacks the channel names), help test FAILS
  (`[env: ZSIGN_PASSWORD]` absent).

- [ ] **Step 4.3: Implement (implementer subagent)**

1. Manifest: enable clap `env` feature; add `rpassword = "7.5"`.
2. `password` arg becomes:

```rust
    /// Password for the PKCS#12 or key material (empty password is valid).
    /// Precedence: this flag beats the ZSIGN_PASSWORD environment variable.
    /// Values passed on the command line are visible to other users in
    /// process listings; prefer ZSIGN_PASSWORD where possible.
    #[arg(short = 'p', long, env = "ZSIGN_PASSWORD", hide_env_values = true)]
    password: Option<String>,
```

3. Password resolution for every p12 call site (the `--pkcs12` branch and the
   `-k`-p12 branch in `load_credentials`):

```rust
/// Resolves the PKCS#12 password: flag/env first; otherwise the historical
/// empty-password attempt, and only a *password-shaped* trial failure may
/// prompt (TTY) or name the password channels (non-TTY). Other failures
/// (policy rejection, corruption) surface verbatim — they are not password
/// problems and must not be reported as "no password supplied".
fn resolve_p12_password(cli: &Cli, data: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
    if let Some(pw) = &cli.password {
        return Ok(pw.clone());
    }
    let trial_err = match SigningCredentials::from_p12(data, "") {
        Ok(_) => return Ok(String::new()), // empty-password containers never prompt
        Err(e) => e.to_string(),
    };
    // Same two markers the wasm adapter sniffs for "wrong/needed password"
    let password_shaped = trial_err.contains("invalid PKCS#12 password (MAC mismatch)")
        || trial_err.contains("PKCS#12 decryption failed");
    if !password_shaped {
        return Err(trial_err.into());
    }
    if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        // one prompt, no pre-validation: the call site's from_p12 is the
        // single retry (a wrong prompt surfaces its loader error there)
        let prompted = rpassword::prompt_password("PKCS#12 password: ")
            .map_err(|e| format!("password prompt failed: {e}"))?;
        Ok(prompted)
    } else {
        Err(format!(
            "{trial_err}; no password supplied: pass -p/--password or set \
             ZSIGN_PASSWORD (stdin is not a terminal, cannot prompt)"
        ).into())
    }
}
```

Parse cost (recorded in the design doc): flag/env = one p12 parse; the trial paths
parse twice (trial + call site) — forced because `extract_p12` is `pub(crate)` and
zsign-core is out of fence.

4. `load_credentials` p12 branches (`--pkcs12` and `-k` content route) replace
   `let password = cli.password.as_deref().unwrap_or("");` with
   `let password = resolve_p12_password(cli, &data)?;` then `from_p12(&data, &password)`.

- [ ] **Step 4.4: Green gate** — both scoped gates.

- [ ] **Step 4.5: Manual TTY prompt smoke (no automation possible in CI)**
  Run an interactive prompt check through a PTY (e.g. `hub start` a pty shell or
  `script -qec`): signing `identity_single.p12` with neither `-p` nor
  `ZSIGN_PASSWORD` must print `PKCS#12 password: ` with echo off and accept
  `testpassword`. Record the observed output in the final report.

- [ ] **Step 4.6: Commit**
  `git add crates/zsign-cli/src/main.rs crates/zsign-cli/Cargo.toml Cargo.lock && git commit -m "feat(cli): add env fallback and tty prompt for p12 passwords (zsn-6)"`

---

## Task 5: Flag validations + credential error quality (queue item 5, commit 5)

**Files:**
- Modify: `crates/zsign-cli/src/main.rs` — `Cli` attrs (constraints, zip range,
  `credentials` group), `load_credentials` (read wrapper, PEM-password failure,
  fallthrough deletion), inline tests

- [ ] **Step 5.1: Write the failing tests (Tester subagent)**

Parse-level tests use `Cli::try_parse_from` (no subprocess needed) and assert
`clap::error::ErrorKind`:

```rust
fn parse_err(args: &[&str]) -> clap::error::Error {
    Cli::try_parse_from(args).expect_err("must be rejected")
}

#[test]
fn verify_conflicts_with_sign_only_flags() {
    for extra in [
        vec!["zsign", "-V", "-o", "x.ipa", "in.ipa"],
        vec!["zsign", "-V", "-m", "p.mobileprovision", "in.ipa"],
        vec!["zsign", "-V", "-z", "5", "in.ipa"],
        vec!["zsign", "-V", "-a", "in.ipa"],
        vec!["zsign", "-V", "-c", "c.pem", "-k", "k.pem", "in.ipa"],
        vec!["zsign", "-V", "--pkcs12", "x.p12", "in.ipa"],
        vec!["zsign", "-V", "-2", "in.ipa"],
    ] {
        assert_eq!(parse_err(&extra).kind(), clap::error::ErrorKind::ArgumentConflict);
    }
    // verify itself stays valid, and ZSIGN_PASSWORD must NOT conflict (env presentness)
    assert!(Cli::try_parse_from(["zsign", "-V", "in.ipa"]).is_ok());
}

#[test]
fn credentials_group_required_unless_adhoc_or_verify() {
    assert_eq!(parse_err(&["zsign", "in.ipa"]).kind(),
               clap::error::ErrorKind::MissingRequiredArgument);
    assert!(Cli::try_parse_from(["zsign", "-a", "in.ipa"]).is_ok());
    assert!(Cli::try_parse_from(["zsign", "-V", "in.ipa"]).is_ok());
    assert!(Cli::try_parse_from(["zsign", "--pkcs12", "x.p12", "in.ipa"]).is_ok());
    assert!(Cli::try_parse_from(["zsign", "-k", "x.p12", "in.ipa"]).is_ok());
    assert!(Cli::try_parse_from(["zsign", "-c", "c.pem", "-k", "k.pem", "in.ipa"]).is_ok());
    // certificate without private key
    assert_eq!(parse_err(&["zsign", "-c", "c.pem", "in.ipa"]).kind(),
               clap::error::ErrorKind::MissingRequiredArgument);
    // pkcs12 conflicts with the certificate/key pair
    assert_eq!(parse_err(&["zsign", "--pkcs12", "x.p12", "-c", "c.pem", "-k", "k.pem", "in.ipa"]).kind(),
               clap::error::ErrorKind::ArgumentConflict);
}

#[test]
fn zip_level_range_is_enforced_at_parse() {
    assert_eq!(parse_err(&["zsign", "-a", "-z", "99", "in.ipa"]).kind(),
               clap::error::ErrorKind::ValueValidation);
    assert!(Cli::try_parse_from(["zsign", "-a", "-z", "9", "in.ipa"]).is_ok());
    assert!(Cli::try_parse_from(["zsign", "-a", "-z", "0", "in.ipa"]).is_ok());
}

#[test]
fn password_with_key_route_fails_explicitly() {
    // content sniff fires before any parsing, so no real cert is needed
    let dir = TempDir::new().unwrap();
    let key = dir.path().join("key.pem");
    std::fs::write(&key, concat!("-----BEGIN ", "ENCRYPTED PRIVATE KEY-----", "\n")).unwrap();
    let input = dir.path().join("in.bin");
    std::fs::write(&input, MINIMAL_MACHO).unwrap();
    // encrypted content, no password: still the explicit unsupported error
    let r = run_cli(&[OsStr::new("-k"), key.as_os_str(), OsStr::new("-o"),
                      dir.path().join("o.bin").as_os_str(), input.as_os_str()], &[]);
    assert_eq!(r.code, 1, "stderr: {}", r.stderr);
    assert!(r.stderr.contains("encrypted PEM keys are unsupported"), "stderr: {}", r.stderr);
    // password supplied with an unencrypted key: same explicit failure, never silence
    std::fs::write(&key, concat!("-----BEGIN ", "PRIVATE KEY-----", "\n")).unwrap();
    let r = run_cli(&[OsStr::new("-k"), key.as_os_str(), OsStr::new("-p"), OsStr::new("pw"),
                      OsStr::new("-o"), dir.path().join("o.bin").as_os_str(),
                      input.as_os_str()], &[]);
    assert_eq!(r.code, 1, "stderr: {}", r.stderr);
    assert!(r.stderr.contains("encrypted PEM keys are unsupported"), "stderr: {}", r.stderr);
}

#[test]
fn credential_io_errors_name_the_file() {
    let dir = TempDir::new().unwrap();
    let input = dir.path().join("in.bin");
    std::fs::write(&input, MINIMAL_MACHO).unwrap();
    let missing_key = dir.path().join("absent.key");
    let r = run_cli(&[OsStr::new("-k"), missing_key.as_os_str(), OsStr::new("-o"),
                      dir.path().join("o.bin").as_os_str(), input.as_os_str()], &[]);
    assert_eq!(r.code, 1);
    assert!(r.stderr.contains("absent.key"), "stderr: {}", r.stderr);
    assert!(r.stderr.contains("private key"), "label the flag: {}", r.stderr);
}
```

- [ ] **Step 5.2: Red gate** — `TMPDIR=$PWD/.tmptmp cargo test -p zsign-cli`
  Expected: every new test FAILS (no constraints today; `-z 99` parses; PEM password
  silently ignored; io errors lack labels).

- [ ] **Step 5.3: Implement (implementer subagent)**

1. `Cli` constraints (design doc item 5 is normative for the full list):

```rust
    /// ZIP compression level (0-9, default: 6; 0 = no compression)
    #[arg(short = 'z', long, default_value = "6",
          value_parser = clap::value_parser!(u32).range(0..=9))]
    zip_level: u32,
```

   `certificate`: add `requires = "private_key"`;
   `pkcs12`: add `conflicts_with_all = ["certificate", "private_key"]`;
   `verify`: add
   `conflicts_with_all = ["output", "certificate", "private_key", "pkcs12", "profile", "zip_level", "bundle_id", "bundle_name", "bundle_version", "sha256_only", "legacy_sha1", "force", "adhoc", "dylibs", "weak"]`
   (NOT `password` — env presentness; see design doc);
   container gains:

```rust
#[command(group = clap::ArgGroup::new("credentials")
    .args(["pkcs12", "certificate", "private_key"])
    .multiple(true))] // mandatory: non-multiple groups auto-conflict their members
                      // in clap 4.6.7 (validator.rs:509-515), which would reject
                      // the legitimate -c + -k pairing
```

   and each of `pkcs12`/`certificate`/`private_key` gains
   `required_unless_present_any = ["adhoc", "verify", "credentials"]`.
   (`required_unless_present*` implies required — clap arg.rs:3289-3292.)

2. `load_credentials` hardening:
   - Replace raw `std::fs::read` calls with a wrapper that labels the file:

```rust
fn read_credential_file(path: &std::path::Path, label: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    std::fs::read(path).map_err(|e| format!("failed to read {label} '{}': {e}", path.display()).into())
}
```

   - Key routes only (PEM branch and DER branch — never the p12 branches): immediately
     after reading the key bytes and BEFORE the certificate-presence check, run

```rust
    let password = cli.password.clone().unwrap_or_default();
    let encrypted_marker = key_data
        .windows(b"ENCRYPTED PRIVATE KEY".len())
        .any(|w| w == b"ENCRYPTED PRIVATE KEY")
        || key_data
            .windows(b"Proc-Type: 4,ENCRYPTED".len())
            .any(|w| w == b"Proc-Type: 4,ENCRYPTED");
    if encrypted_marker || !password.is_empty() {
        return Err("encrypted PEM keys are unsupported (see ZSN-18)".into());
    }
```

     This replaces the silently-ignored `None` at the old main.rs:386 (the loader's
     identical guard at cert.rs:476-480 stays unreachable — the CLI side is the
     contract). Order within the key branch is load-bearing for one case: an
     *unencrypted* key with `-p/--password` and no `-c` must produce the mandated
     message (password check first), while an unencrypted key with no password and
     no `-c` must still produce the `--certificate` error — the sniff block falls
     through cleanly in that case. The p12 branches keep using the password normally.
   - Delete the old fallthrough message ("Must provide either --pkcs12 or both
     --certificate and --private-key", old main.rs:390): clap's required-group now
     guarantees a credential arg reaches this function. The structural
     `let Some(key_path) = cli.private_key else` (only reachable if clap's guarantees
     are ever loosened) returns `Err("--pkcs12 or --private-key is required".into())`
     as defense in depth; it has no test because clap makes it unreachable — state
     that in the code comment (no ticket IDs).
   - `-k` PEM/DER route without `-c` keeps its Task-3 message (now covered by the
     static `requires` only for `-c`-first invocations; `-k`-only PEM content still
     hits the runtime check).

3. `-V` help text: keep `Exit 0 = valid, 1 = invalid, 2 = hard error.` (matches the
   final contract table).

- [ ] **Step 5.4: Green gate** — both scoped gates + a final full-lane sweep:
  `TMPDIR=$PWD/.tmptmp cargo test -p zsign-cli` and
  `TMPDIR=$PWD/.tmptmp cargo test -p zsign-rs verify -- --skip test_ipa_signing_is_deterministic`.
  Expected: all inline tests (2 original + Tasks 1-5 additions) green; verify 22 green.

- [ ] **Step 5.5: Commit**
  `git add crates/zsign-cli/src/main.rs && git commit -m "feat(cli): validate flag combinations and credential errors (zsn-5)"`

---

## README needs (wave-4 docs lane — do NOT edit README here)

1. Flag table: `-p` is now `--password` (string, env-backed), `--pkcs12` is
   long-only, `-k` accepts PEM/DER/PKCS#12 by content, `-z` rejects out-of-range.
2. Exit-status table: replace README:155-157 with the design doc's final contract
   (0/1/2 split by mode; sign failure = 1; clap usage = 2; `--json` `status` is the
   machine-stable signal).
3. Password channel section: argv exposure warning, `ZSIGN_PASSWORD`, single TTY
   prompt, non-TTY degradation message, empty-password compatibility.
4. `--json` section: schema v1 reference (design doc), stream rules (stdout document,
   stderr error object).
5. Upstream migration note mirroring the `--help` epilog + the breaking-change note
   recommending version 0.2.0 at the next release.

## Verification checklist (controller, end of lane)

- [ ] Both scoped gates green (verbatim output captured for the final report)
- [ ] `git log --oneline` shows exactly the 5 feature commits + 1 docs commit on
  `zsn5-cli-surface`; tree clean; no fmt/clippy/hk invoked manually
- [ ] `grep`-audit: no `process::exit` left in `run_verify`; no `report.warnings`
  printer; no `-p "` path usage in `scripts/verify-apple-interop.sh`; no ticket IDs
  in `crates/zsign-cli/src/main.rs` comments; no `TODO`/`FIXME`/stubs
- [ ] Manual TTY prompt smoke recorded (Task 4, Step 4.5)
- [ ] Plan-vs-actual deviations + README-needs list carried into the final report
