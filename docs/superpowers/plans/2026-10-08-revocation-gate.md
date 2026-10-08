# Revocation Gating Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development (recommended) with dispatching-parallel-agents for independent tasks to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `-C/--check-revocation` a real gate — exit 1 before signing
on an authenticated revocation, plus a credentials-sourced check-only mode
(no input) exiting 0/1/2 — with the fail-open posture documented loudly in
the flag's help text and the old never-gates pin rewritten to pin the new
contract.

**Architecture:** One new native function `revocation::status_of` (the
status-returning twin of `warning_of`, same transport/clock); `run()` becomes
a wrapper over `run_with_revocation(cli, probe)` where production passes
`status_of` and tests pass stubs; the gate sits in the credentials branch of
`run_with_revocation` after `load_credentials` and before `ZSign::new`, so it
fires before any signing and before input dispatch.

**Tech Stack:** Rust 2021, clap 4 derive; committed OCSP DER fixtures +
loopback listener for the network-bound test.

**Spec:** `docs/superpowers/specs/2026-10-08-revocation-gate-design.md`

## Global Constraints

- Zero ticket IDs anywhere — including the rewritten pin test's comment
  (the old comment carries a foreign ticket ID; the rewrite must not).
- Files allowed: `crates/zsign-cli/src/main.rs`,
  `crates/zsign-core/src/crypto/revocation.rs`, `README.md` ONLY.
- `warning()`, `warning_of`, `warn_revocation` semantics preserved verbatim;
  `status_of` is an addition, cfg-gated `not(wasm32)` like `warn_revocation`.
- Exit contract stays 0/1/2: during-sign revocation → 1 (Err path, nothing
  signed); check-only → 0 Good / 1 Revoked (and any credential-load failure,
  which is where expired lands) / 2 NotChecked; usage errors → 2.
- `NotChecked` during signing stays silent + exit 0 (the documented
  fail-open posture).
- Zero-warning gate at item end: `cargo fmt --all -- --check` AND
  `cargo clippy --workspace --all-targets -- -D warnings`.
- Tests: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test --workspace`
  (scoped `-p zsign-cli` / `-p zsign-core` gates during flight).
- Commits: conventional, imperative, lowercase, no trailing period, no
  ticket IDs. One commit per task, after its scoped gate is green.
- No network in tests: only loopback or short-circuited (no-AIA) paths.

## Review Focus

1. The gate fires BEFORE signing: an injected `Revoked` status produces exit
   1 and no output file — pinned by
   `check_revocation_gates_revoked_and_fails_open_when_uncheckable` scenario A.
2. The fail-open arm runs through the PRODUCTION probe (real `status_of`,
   no socket, `NoOcspUrl`) and still signs with exit 0, and the help text
   loudly documents fail-open — pinned by that test's scenario B plus its
   `FAIL-OPEN` help assertion.
3. Check-only never signs and reports the full exit matrix — pinned by
   `check_only_mode_reports_and_gates_without_signing` (parse-without-input,
   three stub arms through `run_with_revocation`, real spawned-binary
   `NotChecked` run with stderr text).
4. Making `input` optional with `-C` must not relax the credentials
   requirement: bare `zsign -C` still fails usage with exit 2 naming the key
   flag — pinned by `check_only_still_requires_credentials`.
5. `status_of` walks the exact network path `warn_revocation` uses (same
   issuer resolution, transport, budget) — pinned by the new loopback test in
   revocation.rs plus the untouched `warning_of`/`warn_revocation` tests.

---

### Task 1: `revocation::status_of` + loopback proof

**Files:**
- Modify: `crates/zsign-core/src/crypto/revocation.rs` — beside
  `warning_of` (`:844`) / `warn_revocation` (`:861`); native test module
  (`mod native`, `:2026+`) beside the existing `http_transport_round_trips…`
  test (`:2084+`)

**Interfaces:**
- Produces (consumed by Task 2):
  `#[cfg(not(target_arch = "wasm32"))] pub fn status_of(leaf: &Certificate, chain: &[Certificate]) -> RevocationStatus`
  — reachable as `zsign_rs::crypto::revocation::status_of`.
- `warning_of`/`warn_revocation` signatures unchanged.

- [ ] **Step 1: Write the failing test (Tester)**

Add to the `mod native` test module in `revocation.rs`, mirroring the
existing `http_transport_round_trips_against_a_loopback_responder` test
(read it first — reuse `fixture_pair()`, `rewrite_ocsp_uri`, `build_request`
expectations, and the one-shot HTTP responder loop exactly):

```rust
#[test]
fn status_of_reports_revoked_against_a_loopback_responder() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (mut leaf, issuer) = fixture_pair();
    rewrite_ocsp_uri(&mut leaf, &format!("http://127.0.0.1:{port}/ocsp"));
    let expected_request = build_request(&leaf, &issuer).expect("request");
    let server = std::thread::spawn(move || {
        // same read-head/body loop as the existing round-trip test,
        // answering with REVOKED_DER
    });
    let status = status_of(&leaf, &[issuer.clone()]);
    server.join().unwrap();
    assert_eq!(status, RevocationStatus::Revoked {
        revoked_at: <the fixture's revocation time — derive it from REVOKED_DER
        the way the existing revoked test does, or construct the expected value
        from that test's assertion>,
        reason: <as the existing revoked test asserts>,
    }, "got {status:?}");
}
```

(Read the existing `parse_and_verify`-revoked test first and copy its exact
expected `RevocationStatus` value — the loopback test must assert the same
equality shape. If `RevocationStatus` is not `PartialEq`-comparable in that
form, mirror however the existing tests assert it.)

- [ ] **Step 2: Run it, watch it fail**

Run: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-core status_of`
Expected: compile RED — `status_of` does not exist. Capture verbatim.

- [ ] **Step 3: Implement `status_of`**

Beside `warn_revocation` in `revocation.rs`:

```rust
/// Status-returning companion of [`warning_of`] for gate decisions.
///
/// Same issuer resolution, transport, and clock as [`warn_revocation`]
/// (3s [`HttpTransport`] budget, `now` = wall clock), but returns the full
/// [`RevocationStatus`] so callers can distinguish `Good` from
/// `NotChecked` — the distinction a gate needs and `Option<String>` cannot
/// carry. Native-only because it opens the socket.
#[cfg(not(target_arch = "wasm32"))]
pub fn status_of(leaf: &Certificate, chain: &[Certificate]) -> RevocationStatus {
    check(leaf, issuer_of(leaf, chain), &HttpTransport::default(), None)
}
```

Do not touch `warning_of`, `warn_revocation`, `RevocationStatus`, or
`warning()`.

- [ ] **Step 4: Watch it pass, then scoped gate + commit**

Run: `TMPDIR=$PWD/target/tmp cargo test -p zsign-core revocation` (whole
module — all pre-existing warning/transport tests must stay green), then
`cargo clippy -p zsign-core --all-targets -- -D warnings` and
`cargo fmt --all -- --check`.
Expected: green.
Commit: `feat(crypto): expose revocation status for gating`

---

### Task 2: CLI gate + check-only mode + rewritten pin test

**Files:**
- Modify: `crates/zsign-cli/src/main.rs` — `input` field (`:22-23`), `-C`
  field doc/attr (`:153-158`), `run()` (`:311+`), the `check_revocation`
  use (`:320-326`), tests module

**Interfaces:**
- Consumes: `zsign_rs::crypto::revocation::status_of` from Task 1;
  `zsign_rs::SigningCredentials`; `zsign_rs::crypto::revocation::RevocationStatus`.
- Produces:
  - `fn run_with_revocation(cli: Cli, probe: &dyn Fn(&SigningCredentials) -> RevocationStatus) -> Result<ExitCode, Box<dyn std::error::Error>>`
    — `run()` delegates to it with the production `status_of` probe.
  - `fn check_good_report(json: bool) -> String` — the check-only success
    document/line (unit-pinned, because in-process stdout is not capturable
    and the production probe cannot reach `Good` offline).
  - `Cli.input` optional only when `-C` is present
    (`required_unless_present = "check_revocation"`).

- [ ] **Step 1: Write the failing tests (Tester)**

Add/rewrite in `crates/zsign-cli/src/main.rs` tests. Conventions: existing
`parse_err`/`run_cli` helpers, `TempDir`, `ExitCode::from(n)` assertions,
footers print actual values.

1. **Rewrite** `check_revocation_flag_never_gates_a_signing_run` (`:1576-1612`)
   into `check_revocation_gates_revoked_and_fails_open_when_uncheckable`.
   Delete the old body's ticket-ID comment entirely. New body:
   - keep the `--help` assertions: exit 0, stdout contains
     `--check-revocation`, and add `stdout.to_uppercase().contains("FAIL-OPEN")`
     — the loud-posture pin (footer prints the help text).
   - build args exactly as today's test does (`-k key -p testpassword -C -o
     out.bin in.bin`, `IDENTITY_P12` written to a TempDir, `in.bin` =
     `fixtures::make_minimal_macho()`), parsing FRESH for each run
     (`Cli::try_parse_from`, `Cli` is not `Clone`).
   - scenario A (gate): `run_with_revocation(cli, |_| RevocationStatus::Revoked { revoked_at: None, reason: Some("stubbed".into()) })`
     → `.expect("gate returns an exit code")`; assert
     `code == ExitCode::from(1)` AND `!out.exists()` — the gate fires before
     any signing.
   - scenario B (fail-open through production code): a fresh parse, then
     `run(cli).expect("fail-open run must succeed")`; assert
     `code == ExitCode::SUCCESS` and `out.exists()` — the identity names no
     OCSP responder, so `status_of` short-circuits `NoOcspUrl` with no
     socket and the documented posture applies.
   - RED today: `run_with_revocation` does not exist (compile RED); the old
     assertion `assert_eq!(code, ExitCode::SUCCESS)` for the stubbed-Revoked
     scenario is exactly what the rewrite flips.

2. **New** `check_only_mode_reports_and_gates_without_signing`:
   - parse `["zsign", "-k", key, "-p", "testpassword", "-C"]` (NO input) —
     `.expect("check-only must parse without an input")` (RED today:
     missing `<INPUT>` usage error).
   - three in-process `run_with_revocation` runs on fresh parses, asserting
     exit codes only (in-process stdout is not capturable):
     stub `RevocationStatus::Good` → `ExitCode::SUCCESS`;
     stub `RevocationStatus::Revoked { revoked_at: None, reason: Some("stubbed".into()) }`
     → `ExitCode::from(1)`;
     stub `RevocationStatus::NotChecked(NotCheckedReason::NoOcspUrl)` →
     `ExitCode::from(2)`.
     (`NotCheckedReason` needs importing in the tests module.)
   - one real-binary arm: `run_cli(&[OsStr::new("-k"), key.as_os_str(),
     OsStr::new("-p"), OsStr::new("testpassword"), OsStr::new("-C")], &[])`
     → exit 2, stderr contains `could not be checked` (production
     `status_of` → `NoOcspUrl`, offline-safe, no socket).
   - RED today: parse fails; `run_with_revocation` does not exist.

3. **New** `check_only_still_requires_credentials` (preservation guard,
   expected green before AND after — it defends the input-optional shape):
   `parse_err(&["zsign", "-C"])` → `ErrorKind::MissingRequiredArgument`,
   and the message names the key flag (footer prints the rendered message).

4. **New** `check_good_report_formats` (unit pin of the documented strings):
   `check_good_report(false) == "revocation: good"` and
   `check_good_report(true) == "{\"status\":\"checked\",\"revocation\":\"good\"}"`
   (exact strings from the spec; print actual values in footers).

- [ ] **Step 2: Run them, watch them fail**

Run: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-cli check`
Expected: compile RED first (missing `run_with_revocation`,
`check_good_report`; missing `input` attribute does not break compile —
scenario 2's parse assertion and scenario 1's `FAIL-OPEN` assertion fail at
runtime once it compiles). Capture verbatim; note which failures are compile
vs runtime.

- [ ] **Step 3: Implement**

`main.rs`:

1. `input` field: add `required_unless_present = "check_revocation"` to the
   `#[arg]` (`:22-23`). Do NOT touch `-k`/`--pkcs12` requirements.
2. `-C` doc comment rewrite (`:153-156`) — gate first, then loud fail-open,
   then check-only exits; keep the `#[arg(short = 'C', long,
   conflicts_with_all = ["verify", "adhoc"])]` line as-is:

```rust
    /// Check the signing certificate's revocation status via OCSP and GATE
    /// on it: an authenticated revocation aborts the run with exit 1 before
    /// anything is signed. FAIL-OPEN by design: offline use, an unreachable
    /// responder inside the 3s budget, or a certificate that names no
    /// responder leaves the run exactly as without -C (signing proceeds,
    /// exit 0) — only a definitive revocation stops it, and invalid or
    /// expired credentials fail at load as they always do. Without an input
    /// file this is a check that never signs: exit 0 (good), 1 (revoked or
    /// invalid credentials), 2 (status could not be determined). One bounded
    /// network request per run.
```

3. Replace `fn run(cli: Cli)` with the wrapper + new
   `run_with_revocation` (rename the old body):

```rust
fn run(cli: Cli) -> Result<ExitCode, Box<dyn std::error::Error>> {
    run_with_revocation(cli, &|credentials| {
        zsign_rs::crypto::revocation::status_of(
            &credentials.certificate,
            &credentials.cert_chain,
        )
    })
}

/// `run` with the OCSP status source injected; production passes
/// [`zsign_rs::crypto::revocation::status_of`], tests pass stubs.
fn run_with_revocation(
    cli: Cli,
    probe: &dyn Fn(&SigningCredentials) -> RevocationStatus,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    // ... old run() body verbatim ...
}
```

(import `SigningCredentials` from `zsign_rs` and `RevocationStatus`,
`NotCheckedReason` (tests) from `zsign_rs::crypto::revocation` per the
file's single-use-block style; drop the `warn_revocation` import if now
unused.)

4. In the credentials branch, replacing the current `:320-326` block —
   SAME position (after `load_credentials`, before `ZSign::new`):

```rust
        let credentials = load_credentials(&cli)?;
        if cli.check_revocation {
            let status = probe(&credentials);
            match &status {
                RevocationStatus::Revoked { .. } => {
                    return Err(status
                        .warning()
                        .unwrap_or_else(|| "certificate is revoked".into())
                        .into());
                }
                _ if cli.input.is_none() => {
                    return Ok(match status {
                        RevocationStatus::Good => {
                            println!("{}", check_good_report(cli.json));
                            ExitCode::from(0)
                        }
                        RevocationStatus::NotChecked(reason) => {
                            emit_error(
                                cli.json,
                                &format!("revocation could not be checked: {reason:?}"),
                            );
                            ExitCode::from(2)
                        }
                        // Revoked returned above.
                        RevocationStatus::Revoked { .. } => ExitCode::from(1),
                    });
                }
                _ => {}
            }
        }
        ZSign::new().credentials(credentials)
```

(If `NotCheckedReason` already implements `Display`, prefer `{reason}`
over `{reason:?}` — check first and use the nicer one consistently in the
test assertion too.)

5. `check_good_report`:

```rust
/// The check-only success document: human line or the `--json` object.
fn check_good_report(json: bool) -> String {
    if json {
        "{\"status\":\"checked\",\"revocation\":\"good\"}".to_string()
    } else {
        "revocation: good".to_string()
    }
}
```

6. Note in the report: verify no other call sites of `run(` broke (tests
   call `run(cli)` — signature unchanged).

- [ ] **Step 4: Watch them pass**

Run: `TMPDIR=$PWD/target/tmp cargo test -p zsign-cli` — all new tests plus
every pre-existing test (credentials matrix, `-C` conflict test, `-V` pins).
Expected: green.

- [ ] **Step 5: Scoped gate + commit**

Run: `cargo clippy -p zsign-cli --all-targets -- -D warnings` and
`cargo fmt --all -- --check`.
Expected: clean.
Commit: `feat(cli): gate signing on authenticated revocation`

---

### Task 3: README `-C` rows + full zero-warning gate + smoke

**Files:**
- Modify: `README.md` (only the `-C`/revocation-related spots the spec
  enumerates; append-only within each section)

**Interfaces:**
- Consumes: Task 2's user-visible behavior (help text, check-only exits,
  `revocation: good` line, success JSON document).

- [ ] **Step 1: Edit the README spots (implementer)**

Spec §README is authoritative; concretely:
1. Feature bullet (:23): replace the "warns … never gates" bullet with the
   gate + check-only + loud-fail-open summary (keep the 3s-budget / silent-
   offline facts accurate — offline now means "fails open during signing,
   exits 2 in check-only").
2. Flag-table `-C` row (:214): new semantics in one cell — gates on
   authenticated revocation (exit 1, before signing); without an input runs
   check-only (0/1/2); fails open when the check cannot complete (stated
   loudly); conflicts `-V`, `-a`.
3. "### Revocation checking (`-C/--check-revocation`)" section (:303-315):
   rewrite the contract paragraphs — gate conditions, the explicit fail-open
   list (offline / unreachable within 3s / no responder URL → signing
   proceeds, exit 0), the check-only invocation example
   (`zsign-cli -C -k dev.p12 -p 123` with no input) and its exit table,
   and keep the "ad-hoc signing runs no credential check at all" note.
4. Migration table `-C` row (:389): flip per the spec — upstream gates only
   its keyless standalone mode (artifact-based, 0/1/2/255) and discards the
   result during signing; this port gates during signing on authenticated
   revocation, adds a credentials-sourced check-only mode (0/1/2), and does
   not port keyless artifact checking (extraction lives in modules owned by
   another lane).
5. Exit-status table (:241-255): add the check-only row(s) if the table has
   a natural place (match neighbors exactly).
6. JSON section (:257-280): append the check-only success document row
   (`{"status":"checked","revocation":"good"}`) and note failures reuse the
   error document.
7. Re-read every OTHER `-C` mention (grep README for `check-revocation` and
   `never gates`) and update any leftover warn-only claim — report each.

- [ ] **Step 2: Full zero-warning gate**

Run:
```
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test --workspace
```
Expected: all clean, all tests pass (item's final gate).

- [ ] **Step 3: Real-binary smoke + commit**

Smoke (after `cargo build -p zsign-cli`; use the `IDENTITY_P12` fixture the
tests use — find its `include_bytes!` path in main.rs, copy it to
target/tmp with the test password `testpassword`):
- `zsign-cli -C -k <identity> -p testpassword` (no input) → **exit 2**,
  stderr `revocation could not be checked` (offline-safe: the identity has
  no responder URL, so no socket opens).
- `zsign-cli -C` (no key) → exit 2, credentials-usage error.
- `zsign-cli --help` → the new `-C` text containing `FAIL-OPEN`.
Record verbatim output in the report. The sign-with-`-C` fail-open arm and
the revoked gate are covered in-process by Task 2's scenarios A/B (a shell
smoke would need a Mach-O fixture the repo only generates in tests).
Commit: `docs(cli): document revocation gating and check-only mode`

---

## Plan self-review

- Spec coverage: gate → Task 2 scenario A + `status_of` Task 1; check-only
  exits → Task 2 scenario 2 (parse + three stub arms + spawned `NotChecked`);
  loud help → Task 2 help text + `FAIL-OPEN` assertion; expired-via-load →
  cited core tests, no new code (spec §acceptance 4); README spec section →
  Task 3 Step 1; acceptance 1-6 map to Task 2 scenarios A/B/2/3, Task 1, and
  Task 3 Step 2 respectively.
- Step scan: every step names one deliverable; embedded code is only what the
  spec fixed (probe seam shape, gate match, report formatter, `status_of`
  body).
- Type consistency: `run_with_revocation` / `check_good_report` /
  `status_of` signatures identical across test, impl, and spec blocks;
  `RevocationStatus` variant patterns identical.
- Review Focus: all five lines have a named pinning test.
- Proportion: the loopback test deliberately reuses the existing responder
  helper rather than re-describing HTTP; CLI assertions are exit codes and
  file side effects where stdout cannot be captured, with the two documented
  strings pinned through `check_good_report` and the one observable spawned
  arm.
