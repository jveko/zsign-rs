# ZSN-5 CLI Surface — Design (ZSN-5 + ZSN-6 + ZSN-36)

**Date:** 2026-09-26 · **Branch:** `zsn5-cli-surface` · **Base:** `main` @ `0f07c30`
(17 tickets had landed across two waves; worktree HEAD verified byte-identical to
`0f07c30519e66958285957be26d9ef46989549ef` — no drift, every brief citation was
re-anchored rather than shifted.)
**Scope (authoritative):** lane brief `/tmp/zsn-5.txt`, queue items 1–5, files
`crates/zsign-cli/src/main.rs` + its inline `#[cfg(test)]` tests ONLY. Documented
carriers outside that fence (each recorded in "Deviations" below): dependency lines in
`crates/zsign-cli/Cargo.toml` (items 2/3/4 need them), the `--help` epilog migration
note (item 3 names it), and the caller migration in `scripts/verify-apple-interop.sh`
(item 3's short-flag change makes its `-p <path>` invocation invalid; the brief's hard
rule "migrate every caller" governs).

## Problem statement (re-anchored against `0f07c30`)

| # | Defect | Current anchor | Verdict |
|---|---|---|---|
| 1a | `run_verify` documents `0=valid / 1=invalid / 2=hard-error`, but constructor `Err`s (unreadable file, invalid zip, extraction failure, non-Mach-O input) propagate via `?` → `main`'s `Result` termination → exit **1** with a `Debug`-formatted `Error: …` | main.rs:176-203 (`?` at 185-187), main.rs:98-100 | CONFIRMED — real defect; README.md:155-157 documents the contract the code breaks |
| 1b | Brief claims the exit-2 branch (main.rs:196-201) is UNREACHABLE because no constructor populates top-level `VerifyReport.errors` | brief item 1 | **REFUTED (S2):** `verify_macho_file` builds `slot_errors` and passes them as top-level `errors` (crates/zsign/src/verify.rs:349-374) for signed bare Mach-Os whose bound slots `-1`/`-3` cannot be checked without bundle context. `verify_bundle`/`verify_ipa` never set it (:385-389, :405-409). The branch is REACHABLE and its semantics ("could not complete") are correct — keep it, and additionally catch constructor `Err`s into exit 2 |
| 1c | `print_report` prints `report.errors` to stdout (main.rs:216-222) while the exit-2 branch re-prints the same strings to stderr (main.rs:197-200) | main.rs:190-202 | CONFIRMED duplicate; keep stdout report (externally pinned), keep one stderr summary line, drop the duplicate detail loop |
| 1d | `report.warnings` printer (main.rs:215-217) is dead code | main.rs:215-217 | CONFIRMED dead (S2: zero writers of `VerifyReport.warnings` anywhere in the workspace) — delete the printer; do not serialize the field |
| 2 | No `--json` flag exists anywhere | main.rs:12-96 | CONFIRMED; report graph has **zero** serde derives and no workspace crate depends on serde (S2) — JSON requires CLI-local mirror DTOs |
| 3 | `-p` is `--pkcs12` (a path), `--password` has no short flag, `-k` is PEM-only | main.rs:24-41 | CONFIRMED; upstream zhlynn/zsign has `-p/--password` (string, default `""`) and `-k/--pkey` accepting **PEM, DER, or PKCS#12 by content cascade** (L1: src/zsign.cpp:33/222-224, src/openssl.cpp:876-907) |
| 4 | `--password` is argv-only; no env fallback, no prompt; exposure undocumented | main.rs:39-41, main.rs:378 | CONFIRMED; upstream has no prompt either (L1: `getpass|isatty|prompt` grep = 0 hits) — this lane adds what upstream lacks |
| 5 | PEM path hardcodes `from_pem(..., None)` — `--password` silently ignored; `-z 99` silently clamps to 9; no clap conflict/requirement constraints at all; `fs::read` errors don't name which file | main.rs:386, main.rs:43-47, main.rs:12-96, main.rs:377-385 | CONFIRMED; upstream `-z` **rejects** out-of-range (L1: src/zsign.cpp:327-330, archive.cpp:88-91 — never clamps) |

## Hard constraints (from brief + repo reality)

- **Edit surface:** `crates/zsign-cli/src/main.rs` + inline tests ONLY. Never edit
  `builder.rs` (ZSN-35 owns it), `zsign/src/verify.rs` (landed ZSN-26, read-only),
  `zsign-core/**` (other lanes), `.gitignore` (lane collision), README (wave-4 docs
  lane — see "README needs"). Manifest dependency lines and the interop-script caller
  migration are the only sanctioned outside edits (brief's carriers + hard rule
  "migrate every caller"). If an implementation need appears to require a
  `zsign-core`/`zsign` API change → STOP and report instead.
- **No `cargo fmt` / `cargo clippy` / `hk` mid-flight** — the orchestrator gates at
  merge; pre-commit runs automatically.
- Never merge, never push. Conventional commits, ticket ID in the subject only —
  **never** in code comments. No stubs/TODOs/placeholders; migrate every caller;
  delete what the change obsoletes; no second conventions (repo AGENTS.md on top).
- **Gates (scoped, after every task):**
  `mkdir -p .tmptmp && TMPDIR=$PWD/.tmptmp cargo test -p zsign-cli` and
  `TMPDIR=$PWD/.tmptmp cargo test -p zsign-rs verify -- --skip test_ipa_signing_is_deterministic`.
  ZSN-15: `test_ipa_signing_is_deterministic` fails pre-existing — skip it in every
  full run. Baseline measured in this worktree: `cargo test -p zsign-cli` = 2 passed.
- **Downstream pins (must stay green or migrate in the same change):**
  `scripts/verify-apple-interop.sh` — `agree_valid` requires `-V` exit 0 + `^verified: yes`
  (:255-262); cert-signed pins grep exact human printer lines (:276-299);
  `sign_and_verify` fails on any non-zero sign exit and invokes `-p <path> --password test`
  (:103-108, :272-273 region). Human stdout format without `--json` must therefore be
  byte-stable; the `-p <path>` callsite must migrate to `--pkcs12` with item 3.
- CI (`.github/workflows/ci.yml`): fmt check, `clippy -D warnings --all-targets`,
  `cargo test --workspace` (no `--locked`), cargo-deny (license allow-list
  MIT/Apache-2.0/BSD-2/3/ISC/Unicode-3.0/CC0/Unlicense/Zlib; `multiple-versions = "warn"`),
  MSRV 1.88, macOS interop job. Every new dependency below is checked against this.

## Item 1 — Exit-code contract (ZSN-5 core)

**Candidates considered:**

- **EC-A. Uniform operational-error mapping:** `main() -> ExitCode`; verify hard errors
  AND all signing failures map to 2 ("2 = any operational error"); delete the
  report-based exit-2 branch as dead. Rejected on two counts: S2 refuted the deadness
  premise (the branch is reachable and its "could not complete" semantics are correct),
  and mapping sign failures to 2 is an unrequested behavior change (README:155-157
  scopes the 0/1/2 grammar to `-V`; today's sign failure exits 1) that would collide
  with clap's hardcoded usage exit 2, making sign-failure indistinguishable from bad
  flags — while Apple `codesign` (the tool this audience knows) uses 1 for
  "signing/verification failed" and 2 for "invalid arguments" (L3: codesign(1)
  DIAGNOSTICS).
- **EC-C. Fabricate `VerifyReport { errors }` at the CLI boundary** when `verify_*`
  returns `Err`, keeping every path flowing through `print_report`. Rejected:
  fabricating a report conflates "invalid" with "could not verify" on stdout and
  couples the CLI to a lib struct shape this lane may not evolve.
- **EC-B (DECISION). Explicit boundary mapping, verify-only:**
  - `fn main() -> ExitCode`; `fn run(cli: Cli) -> Result<ExitCode, Box<dyn Error>>`
    (the existing testable seam, upgraded to carry a code).
  - `run_verify(input, json) -> ExitCode` — no `process::exit` inside:
    - `Ok(report)` + `report.valid()` → **0** (report printed).
    - `Ok(report)` + `!valid()` + empty top-level `errors` → **1** (report printed).
    - `Ok(report)` + non-empty top-level `errors` (reachable: bound `-1`/`-3` slots
      unverifiable without bundle context, verify.rs:349-374) → report printed, one
      stderr line `error: verification could not complete`, **2**. The duplicate
      per-error stderr loop is dropped (stdout already carries those lines).
    - `Err(e)` from `verify_ipa`/`verify_bundle`/`verify_macho_file` (unreadable file,
      invalid zip, extraction failure, non-Mach-O input) → caught AT THIS BOUNDARY,
      rendered (`error: {e}` on stderr, or the JSON error object under `--json`),
      **2** — never propagates to `main`.
  - Signing path: `Ok` → 0; `Err` → propagates to `main`, which renders it
    (`error: {e}` Display-formatted — replacing Rust Termination's `Debug` noise) and
    returns **1** (unchanged semantics).
  - `report.warnings` printer (main.rs:215-217) deleted — dead (zero writers, S2);
    the field is not serialized to JSON either.

**Final contract (documented verbatim in the design/plan/help text):**

| Code | Verify mode | Sign mode | Precedent (L3) |
|---|---|---|---|
| 0 | verification completed, input valid | signed successfully | POSIX "positive result" |
| 1 | verification completed, input invalid | signing failed | POSIX grep/diff 1 = completed-negative; codesign sign-fail = 1 |
| 2 | could not complete (constructor `Err` or unverifiable report) | — (sign failures stay 1) | POSIX >1 = trouble; clap `USAGE_CODE = 2`; codesign invalid-args = 2 |
| 2 (clap) | usage/parse errors (clap-owned, unchanged) | same | GNU ls / argparse / clap |

Accepted overlap: usage errors and verify-hard-errors both exit 2 — clap hardcodes
this (`clap_builder/src/util/mod.rs:32`); overriding it would require `try_parse`
plumbing for no documented benefit. The ecosystem has no majority (grype: findings=2
and errors=1; openssl verify: invalid=2; trivy/syft/cosign: everything except findings
= 1), so the table above is the local source of truth and `--json` `status` is the
machine-stable signal (L3's recommendation).

**Test mechanism (subprocess, inline — brief's file fence honored):** Cargo does NOT
set `CARGO_BIN_EXE_*` for unit tests and `cargo test` does NOT build the plain bin
target when no `tests/` directory exists — **empirically verified in this worktree**:
after `rm target/debug/zsign-cli && cargo test -p zsign-cli`, the binary is ABSENT
while both unit tests pass. Therefore inline tests use a `OnceLock`-guarded
ensure-build: run `cargo build -p zsign-cli -q` as a child process once per test
process (warm cost measured: 0.8 s; no deadlock — also empirically verified with a
throwaway test, then reverted), derive the binary path from
`std::env::current_exe().parent().parent().join(format!("zsign-cli", EXE_SUFFIX))`,
spawn it with `std::process::Command`, assert exit codes + stdout/stderr. `assert_cmd`
was considered and rejected: it locates but never builds binaries, so it does not
close the actual gap, and it would add `assert_cmd`+`predicates` lock entries for
value std already provides. **No new dev-dependencies.**

Exit-code test classes (all subprocess-level, as the brief requires):
- **0:** adhoc-sign `include_bytes!`-ed `crates/zsign/src/ipa/fixtures/minimal_macho.bin`
  (the same fixture zsign-wasm's proven adhoc roundtrip uses, lib.rs:700/1441-1466),
  then `-V` the output → 0. Adhoc is the only fixture class that can verify valid:
  credential-signed output is permanently "not anchored to a trusted root"
  (zsign/src/verify.rs:1106-1113, :1229-1246); CLI adhoc signing binds no `-1`/`-3`
  slots (builder.rs:306-314) so top-level `errors` stays empty.
- **1:** `-V` the unsigned `minimal_macho.bin` → slice error (no
  `LC_CODE_SIGNATURE`) lives at slice level, top-level `errors` empty → 1.
- **2:** three constructor-`Err` classes per the brief: nonexistent path (Io),
  `garbage.ipa` (invalid zip), non-Mach-O bytes with a Mach-O-ish name (Core);
  plus the report-based class: verify the bundle-signed main executable copied out of
  its `.app` (bound `-1`, no context) → 2.

## Item 2 — `--json` output (ZSN-5)

**Candidates considered:**

- **J-A (DECISION).** Local `#[derive(Serialize)]` mirror DTOs in `main.rs` +
  envelope documents. Every field of the report graph is `pub` (S2), so `From<&lib>`
  conversions need no lib changes; the DTOs *are* the stable schema (documented below).
- **J-B.** Inline `serde_json::json!` maps in the print paths — rejected: schema
  discipline then lives only in tests.
- **J-C.** Serialize the lib structs directly — impossible: zero serde derives
  anywhere in the workspace (S2 grep), and adding them touches read-only files.

**Channels (mirrors human-mode streams exactly):**
- stdout: exactly one JSON document per run —
  verify → `{"status": "valid"|"invalid"|"error", "input": ..., "report": {...}}`;
  sign → `{"status": "signed", "output": ...}`.
- stderr: on failure, exactly one JSON object —
  `{"status": "error", "error": "<message>"}` (constructor-`Err` and sign failures;
  for the report-based verify "could not complete" case both channels emit, exactly as
  human mode prints report + summary line).
- Human output without `--json` is byte-stable (interop script pins it).
- clap parse errors stay human + exit 2 (documented non-goal: clap's own error
  rendering is not intercepted).

**Schema (v1, stable; field renames or removals are breaking):** see the JSON schema
section below — the DTO set mirrors everything `print_report`/`print_macho`/
`print_bundle` print, minus the dead top-level `warnings`.

## Item 3 — Upstream `-p`/`-k` restoration (ZSN-36)

User decision (brief): restore upstream meanings. Verified upstream surface
(L1, zhlynn/zsign master @ `614caa8d`, 2026-08-21): `-p/--password` is a plain
passphrase string defaulting to `""` (src/zsign.cpp:186, 222-224); `-k/--pkey` is
"Path to private key or p12 file" loaded by a **content try-cascade**
PEM → DER → PKCS#12 (src/openssl.cpp:876-907, no extension sniffing).

**Candidates for `-k` format detection:**

- **K-A. Pure content sniff (marker → key, else p12).** Cannot distinguish bare-DER
  key from p12 (both are ASN.1 `SEQUENCE`) without a DER walker.
- **K-B. Extension routing.** Rejected: extensions lie; upstream decides by content.
- **K-C. Upstream-faithful try-cascade (PEM → DER → p12).** Rejected for our loader
  stack: `from_p12` failures carry the valuable ZSN-37 messages ("invalid PKCS#12
  password (MAC mismatch)" etc., pkcs12.rs:87, cert.rs:547) — a cascade that *then*
  falls through to key parsing masks them behind a generic "Failed to parse private
  key" and blames the wrong format. (Upstream tolerates this because it reports one
  generic "Can't load p12 or private key file…" message, openssl.cpp:904-907.)
- **K-A′ (DECISION). Content marker + credential-shape routing** — deterministic,
  one interpretation per input, ZSN-37 errors preserved verbatim:

| `-k` content | `-c` present? | Route | Password |
|---|---|---|---|
| starts with `-----BEGIN` (PEM) | required | `SigningCredentials::from_pem(cert, key, None)` | non-empty → explicit error (item 5) |
| no PEM marker | required | DER key → in-memory PEM-wrap (label `PRIVATE KEY`, base64 of the DER bytes) → `from_pem(cert, wrapped, None)` | same as PEM |
| no PEM marker | absent | **p12 route** → `from_p12(bytes, password)` | flag → env → `""` trial → prompt (item 4) |

  PEM + no `-c` → error naming the missing `--certificate`. p12 content + `-c`
  (misuse) → DER-wrap fails parsing with the file named — acceptable; the help text
  states the `-k`-alone-means-p12 rule. `--pkcs12` keeps its behavior, now long-only.
  Upstream's DER-cert support (`-c` accepts DER, openssl.cpp:909) is **not** in the
  brief's item 3 → stays PEM-only, recorded as a follow-up.

**Flag migration:**

- `password`: gains `short = 'p'`, `env = "ZSIGN_PASSWORD"`, `hide_env_values = true`
  (mandatory — clap prints `[env: ZSIGN_PASSWORD=<value>]` into `--help` otherwise,
  L2: help_template.rs:770-787); help text documents argv exposure
  (`ps`-visible) and recommends the env var.
- `pkcs12`: **loses its short flag** (`#[arg(long)]` only).
- `private_key`: keeps `-k/--private-key`; help text becomes
  "Private key or PKCS#12 file (PEM, DER, or PKCS#12 auto-detected by content)".
- `#[command(after_help = "upstream users: -p/-k now match upstream; --pkcs12 is long-only")]`
  (brief's migration note; the password-channel note for `--help` lives in the
  `--password` help text).
- **Semver:** short-flag re-meaning is a breaking CLI change; repo is pre-1.0
  (zsign-cli 0.1.1) → the next release must bump 0.1.x → **0.2.0** (pre-1.0 breaking
  = minor bump). Version numbers are release management — **not edited in this lane.**
- **Caller migration (hard rule "migrate every caller"):**
  `scripts/verify-apple-interop.sh` passes `-p "$WORK/cs.p12"` (sign_and_verify
  invocations, :103-108/:272-273) — migrates to `--pkcs12 "$WORK/cs.p12"`; its
  `--password test` stays valid. README flag tables are deferred to the wave-4 docs
  lane (listed under "README needs").
- Issues #116/#303/#401 (brief's conditional citation): verified via GitHub API —
  all three concern `-e`/entitlements, **none** about `-p`/`-k` (#401 is a closed
  unmerged PR). Not cited as `-p`/`-k` provenance.

## Item 4 — Password channel (ZSN-6)

**Candidates considered:**

- **P1 (DECISION). flag → env → empty-trial → single TTY prompt.** Resolution order
  for the p12 routes: (1) `--password` argv value (clap: flag beats env,
  parser.rs:1417-1421); (2) `ZSIGN_PASSWORD` env (same arg via clap `env`); (3)
  neither set → attempt `from_p12(bytes, "")` first (preserves today's
  empty-password behavior for CI/piped use — `""` is a valid p12 password and is
  fixture-proven, pkcs12.rs:909/922); (4) that attempt fails →
  `std::io::stdin().is_terminal()`? one no-echo `rpassword::prompt_password` and a
  single retry (any failure after an explicit flag/env password surfaces the loader
  error untouched — no prompt) : clear error naming `-p/--password` and
  `ZSIGN_PASSWORD` ("stdin is not a terminal"). At most one prompt ever; the
  password never appears in messages or logs (credential types have no `Debug`
  impls, cert.rs:92-107, so it cannot leak through formatting).
- **P2.** Prompt on every TTY when unset, error otherwise — rejected: breaks
  empty-password non-TTY workflows (today's implicit `""`), and forces a pointless
  prompt for empty-password p12s.
- **P3.** Keep silent `""` — under-delivers the brief's prompt requirement.

**Degradation gate:** `rpassword` alone is insufficient — it reads `/dev/tty`, so it
would happily prompt with piped stdin (L2: src/unix.rs:11-12); the explicit
`stdin().is_terminal()` check (std, stable 1.70 ≤ MSRV 1.88) is what makes piped
stdin degrade to the mandated clear error. `hide_env_values = true` prevents `--help`
from echoing the live env value.

**Prompt backend: `rpassword` 7.5 (new runtime dep — justification per brief):**
- Rivals rejected: `dialoguer` Password natively refuses non-TTY but costs 4–5 new
  lock entries (console/shell-words/unicode-width/encode_unicode) for themed
  machinery we would not use; hand-rolled termios over `libc` costs zero lock
  entries but is Unix-only (Windows CI + README claim cross-platform), must
  replicate rpassword's SIGINT/`Drop` restore dance (a default SIGINT handler skips
  `Drop` → terminal left with echo off) and `/dev/tty` policy; std has no echo
  control at all (L2 verdict: impossible).
- rpassword: exactly **one** new lock entry (`rtoolbox 0.0.6`); `libc 0.2.189`,
  `windows-sys 0.61.2` already locked; actively released (7.5.4, 2026-05-31); MSRV
  1.85 ≤ 1.88; covers unix/windows/macOS/wasm; license **Apache-2.0** (rpassword
  *and* rtoolbox, both verified on crates.io/GitHub) — in deny.toml's allow-list.
  Known caveat recorded: `rtoolbox` is 0.0.x with no BC guarantees.

## Item 5 — Flag validations in `Cli`

- **Mode conflicts:** `verify` gains `conflicts_with_all` over every sign-only,
  argv-only flag: `output, certificate, private_key, pkcs12, profile, zip_level,
  bundle_id, bundle_name, bundle_version, sha256_only, legacy_sha1, force, adhoc,
  dylibs, weak`. **`password` is deliberately excluded**: clap treats *env-supplied*
  values as present (L2: value_source.rs:14-16), so a shell with `ZSIGN_PASSWORD`
  exported must not make `zsign -V file` a usage error; `--password` in verify mode
  is ignored (documented).
- **Credential group:** an explicit `credentials` ArgGroup (`pkcs12`,
  `certificate`, `private_key`), and each member carries
  `required_unless_present_any = ["adhoc", "verify", "credentials"]`. This is the
  clap-idiomatic "required group with adhoc/verify exceptions": a required ArgGroup
  itself has no `required_unless*` and its validation ignores conflicts (L2:
  arg_group.rs:92-528, validator.rs:255-271), so a `required = true` group would
  reject `zsign -a file`. Group presence is recorded in the matcher
  (parser.rs:1540-1544), so `--pkcs12 x` alone satisfies `certificate`'s and
  `private_key`'s requirement. `certificate` additionally gains
  `requires = "private_key"` (cert without key is never valid; key without cert may
  be a p12). Missing-everything is now a clap usage error (exit 2) naming the
  credential flags; the runtime fallthrough error (main.rs:390) becomes unreachable
  and is **deleted**.
- **`-k` runtime halves:** PEM/DER content with no `-c` → error naming
  `--certificate` (reachable only from the key routes; clap cannot know the content).
- **`--zip-level`:** `value_parser = clap::value_parser!(u32).range(0..=9)` — rejects
  99 at parse with `error: invalid value '99' for '-z <ZIP_LEVEL>: 99 is not in 0..=9'`
  (exit 2), matching upstream's reject-not-clamp (zsign.cpp:327-330). The help text
  states the range explicitly (clap does not render ranges).
- **PEM password:** explicit failure instead of silent ignore. In the key routes, a
  non-empty resolved password → `Err("encrypted PEM keys are unsupported (see ZSN-18)")`;
  additionally the key bytes are sniffed for `ENCRYPTED PRIVATE KEY` /
  `Proc-Type: 4,ENCRYPTED` → same error even without a password (the loader's own
  guard, cert.rs:476-480, is unreachable today because the CLI hardcodes `None` at
  main.rs:386; an *unencrypted* key with no password behaves exactly as before).
  Rationale for CLI-side: `from_pem`'s password param is rejection-only (never
  decrypts), so "pass it through" and "fail explicitly" collapse to the same
  observable outcome — the brief's two options, implemented as the explicit one.
- **IO context:** every `fs::read` in the credential path wraps its error with the
  flag label and path: `failed to read private key '<path>': <io>` (brief: errors
  must NAME the missing file).
- **Not touched (ownership):** sha256-flag mutual exclusion and adhoc+profile
  conflicts (ZSN-35, owns `builder.rs`); `-a` + credential-flags silent ignore
  (pre-existing; noted as follow-up overlap with ZSN-35); `builder.rs` option
  forwarding — including the found defect that `sign_ipa` drops `sha256_only`
  (builder.rs:381-388, `-L` silently inert for `.ipa`), recorded as a ZSN-35
  follow-up below.

## JSON schema v1 (`--json`)

Emitted by CLI-local DTOs (`#[derive(serde::Serialize)]`, `main.rs` only). `status`
is authoritative for machine consumers; exit codes remain the human/shell signal.

```jsonc
// verify, stdout (one document)
{ "status": "valid" | "invalid" | "error",
  "input": "<path as given>",
  "report": {
    "valid": true | false,
    "macho": {                      // null for bundle/ipa inputs
      "fat": false,
      "slices": [{
        "arch": "arm64", "signed": true, "identifier": "com.x", "adhoc": false,
        "valid": true,
        "pages": { "kind": "matched" },                       // or "empty",
          // { "kind": "mismatch", "page_index": 7 },
          // { "kind": "count_mismatch", "stored": 42, "computed": 41 }
        "special_slots": [ { "slot": -1, "name": "Info.plist", "check": "matched" } ],
          // check: "matched" | "not_checked" | "mismatch" | "missing";
          // name mirrors the human label table; "missing" = unbound, normal
        "cms": {                                            // null only for early-fail slices
          "valid": true, "no_signature": false,
          "signer_subject": "CN=…", "signer_serial": "…",    // may be null
          "message_digest_ok": true, "cdhash_v1_ok": true, "cdhash_v2_ok": true,
          "signature_ok": true, "chain_ok": true, "anchored": true,
          "chain_reason": null, "chain": ["CN=B", "CN=A"],
          "errors": [], "warnings": []
        },
        "errors": [], "warnings": []
      }]
    },
    "bundle": {                      // null for bare macho; recursive via "nested"
      "path": "Payload/App.app", "valid": true,
      "binaries": [{ "path": "App", "valid": true,
                     "report": { /* MachO as above */ }, "errors": [] }],
      "code_resources": { "valid": true, "matched": 12,
                          "mismatched": [], "missing": [], "unsealed": [] },  // may be null
      "errors": [], "nested": [ /* bundle */ ]
    },
    "errors": []                     // top-level: only verify_macho_file fills this
  } }

// verify sign failure / constructor Err, stderr (one object)
{ "status": "error", "error": "<Display of the error>" }

// sign, stdout
{ "status": "signed", "output": "<path written, or input path for in-place>" }

// sign failure, stderr
{ "status": "error", "error": "<Display of the error>" }
```

Deliberate omissions: top-level `report.warnings` (dead field), `exit_code` (derivable
from `status`), `problem_count()` (derivable). `pages`/`special_slots` reflect the
strongest CodeDirectory only — mirroring the lib's own projection (macho/verify.rs:239-240);
`cms.errors` are included even though invalid CMS verdicts are mirrored into slice
`errors` (:394-397) — consumers dedupe by design note. Schema tests pin exact JSON for
one valid + one invalid + one error run.

## Dependency additions (all carriers justified)

| Crate | Where | Why | Lock impact | License (deny.toml) |
|---|---|---|---|---|
| `serde` (derive) + `serde_json` | `[dependencies]`, item 2 | `--json`; no workspace crate depends on serde (S2) | versions already in lock (1.0.229 / 1.0.151); only `zsign-cli`'s dep list changes + `rtoolbox` below | MIT/Apache-2.0 ✓ |
| `base64` | `[dependencies]`, item 3 | DER key → PEM wrap for the `-k` route (no public DER loader exists, S3) | already in lock (0.22.1) | MIT OR Apache-2.0 ✓ |
| `rpassword` | `[dependencies]`, item 4 | no-echo TTY prompt (see item 4) | +1 entry `rtoolbox 0.0.6` | Apache-2.0 ✓ both |
| `clap` features `["derive", "env"]` | item 4 | `env = "ZSIGN_PASSWORD"` attribute is a hard compile error without it | zero (cfg switch in locked clap_builder) | — |
| dev-deps | — | **none** (assert_cmd rejected: cannot locate-or-build from unit tests, ~6 lock entries, silent-stale-binary hazard — L2 source-cited) | — | — |

CI note: `cargo test --workspace` runs without `--locked`, so the lock update rides
the first build; cargo-deny and clippy gate at merge as usual.

## Deviations from the brief (each one, with reason)

1. **Test placement.** Brief's scope fence says `main.rs (+ its inline tests) ONLY`;
   item 1's test mandate says "subprocess-level exit-code tests … use assert_cmd as a
   NEW dev-dependency". Both the brief's suggested carrier and any `tests/`-file
   solution are impossible/forbidden: assert_cmd panics in unit tests (its own error
   text says to move to an integration test) and its fallback only passes against a
   stale binary; a `tests/` directory is outside the fence (supervisor directive).
   Resolution: **inline tests + once-guarded child `cargo build` + `current_exe`-derived
   path + `std::process::Command`** — empirically validated (0.8 s warm, no deadlock;
   throwaway experiment reverted). No dev-dep added — strictly narrower than the
   brief's blessed carve-out.
2. **Caller migration in `scripts/verify-apple-interop.sh`.** Outside the file fence
   but mandated by the brief's hard rule "migrate every caller": item 3 reassigns
   `-p` from path to password, breaking the script's `-p "$WORK/cs.p12"`. Exactly two
   callsites change to `--pkcs12`; nothing else in that file moves.
3. **Brief premises refuted by research (behavior follows the refutation):**
   (a) the exit-2 branch is NOT dead — `verify_macho_file` populates top-level
   `errors` (verify.rs:349-374), so it is kept and its stderr detail loop deduplicated;
   (b) "ZSN-37's loaders already exist and validate [DER]" — `from_pkcs8_der` is
   private and `from_pem` rejects DER (cert.rs:469-483, S3); the DER route is
   implemented in the CLI by PEM-wrapping instead of a core API change (which the
   brief forbids: "if your exit-code mapping needs a VerifyReport API change there,
   STOP and report" — same fence discipline);
   (c) `Cargo.lock` DOES contain `libc`/`rustix`/`windows-sys` (the brief's
   "check what's in Cargo.lock" note) — recorded so the rpassword justification
   cites the real lock state;
   (d) issues #116/#303/#401 are `-e`/entitlements threads, not `-p`/`-k`
   provenance — verified, not cited as such.
4. **No `assert_cmd`** — the brief offered it as a question ("?"); answered no, with
   sources (above). Manifest gains only the item 2/3/4 runtime carriers.

## Follow-ups (owners recorded, not touched here)

- **ZSN-35 (`builder.rs`)**: option forwarding incl. the newly found defect
  `sign_ipa` never forwards `sha256_only` (builder.rs:381-388) so `-L` is inert for
  `.ipa`; sha256-flag mutual exclusion; adhoc-vs-credentials/profile conflicts.
- **Wave-4 docs lane (README)**: flag table (`-p`/`-k` new meanings, `--pkcs12`
  long-only, `-z` range, `--json`), exit-status table (final form above, sign-failure
  = 1 called out), password-channel section (argv exposure + `ZSIGN_PASSWORD` +
  prompt + degradation), `--json` schema section, pre-1.0 semver note recommending
  0.2.0, and the epilog migration text mirrored in prose.
- **Core-level gaps (out of lane)**: DER certificates for `-c` (upstream accepts
  them); PKCS#1 `RSA PRIVATE KEY` PEM keys (`pkcs1` feature off, cert.rs:481-483);
  a public `from_pkcs8`-style loader so format routing could live in the library;
  `VerifyReport.warnings` writers or field removal (zsign/src/verify.rs ownership).

## Rejected-alternatives register (summary)

| Item | Rejected | Why |
|---|---|---|
| 1 | EC-A uniform 2 for sign failures | unrequested behavior change; collides with clap usage=2; codesign parity is 1 |
| 1 | EC-C fabricated VerifyReport | conflates invalid/unknown on stdout; couples to read-only struct |
| 1 | assert_cmd dev-dep / `tests/` file | cannot work from unit tests / outside the file fence (L2 + experiment) |
| 2 | `json!`-inline emission | schema only test-enforced |
| 2 | lib-struct serialization | no serde derives anywhere; read-only files |
| 3 | upstream-faithful try-cascade | masks ZSN-37 p12 error fidelity behind generic key-parse noise |
| 3 | extension-based routing | non-deterministic vs real-world files; not upstream behavior |
| 4 | dialoguer | 4-5 lock entries, unused theming |
| 4 | hand-rolled termios | Unix-only; SIGINT/Drop echo-restore hazards; Windows story broken |
| 4 | prompt-always (P2) / silent `""` (P3) | breaks empty-password flows / under-delivers brief |
| 5 | required ArgGroup | clap: no `required_unless*` on groups, group branch ignores conflicts |
| 5 | password in verify's conflicts | env values count as present → `-V` would break under exported `ZSIGN_PASSWORD` |
