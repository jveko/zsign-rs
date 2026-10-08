# `-C/--check-revocation` gating — design

**Date:** 2026-10-08
**Status:** approved for implementation (cold review gate applies to this document together with the plan)

## Problem

`-C` is documented and implemented as warn-only: the field's doc comment says
"Signing always proceeds — this is a signal, not a gate"
(`crates/zsign-cli/src/main.rs:153-156`), the only use calls
`revocation::warn_revocation(&credentials.certificate, &credentials.cert_chain)`
in `run()` (`main.rs:320-326`) which returns `()` after a bare `eprintln!`
(`crates/zsign-core/src/crypto/revocation.rs:861-866`), and `run()` always
continues to `Ok(ExitCode::from(0))`. A CI gate written as
`zsign -C … || exit 1` is therefore a no-op that signs with a revoked
certificate and reports success — fail-open on a security signal. The pin
test `check_revocation_flag_never_gates_a_signing_run`
(`main.rs:1576-1612`) locks that warn-only success in place (its comment
also carries a foreign ticket ID, which the rewrite in this work removes).

There is no way to run a check without signing: `input` is an unconditionally
required positional (`main.rs:22-23`), `-C` satisfies none of the
`required_unless_present_any` clauses on `-k`/`--pkcs12` (`main.rs:36,43`),
and `-C` conflicts with `-a`/`-V` (`main.rs:157`).

## Verified facts about current behavior

- Public revocation surface (`crates/zsign-core/src/crypto/revocation.rs`):
  `RevocationStatus` (`:75-84`) = `Good | Revoked { revoked_at, reason } |
  NotChecked(NotCheckedReason)`; `NotCheckedReason` (`:90-111`) includes
  `NoOcspUrl`, `NoIssuerCertificate`, `Transport(_)`, `BudgetExpired`, …;
  `RevocationStatus::warning()` (`:120-131`) yields `Some` **only** for an
  authenticated `Revoked`; `warning_of(leaf, chain, transport, now)` (`:844-852`)
  = `issuer_of` + `check` + `warning`; `warn_revocation` (`:861-866`) is the
  native-only `eprintln!` wrapper. `issuer_of` (`:868-874`) matches the issuer
  **by subject/issuer name inside the supplied chain only** — no embedded
  fallback. `HttpTransport` is native-only with a 3 s budget (`:882-936`) and
  is constructible inside the crate but the CLI has no transport to pass to
  `warning_of` (it takes `&dyn OcspTransport`), and `warning()`/`Option<String>`
  cannot distinguish `Good` from `NotChecked` — a status-returning, network-
  bound API is required for gating; that is the one addition the brief allows
  in this file.
- Test seams already in-repo: committed OCSP fixtures
  (`crates/zsign-core/src/crypto/fixtures/revocation/{good,revoked,…}.der` +
  `ca.pem`, `issued_leaf.pem`); `parse_and_verify(REVOKED_DER, …)` derives
  `Revoked` deterministically; the native test module rewrites a fixture
  leaf's AIA URI in memory ("nothing downstream re-verifies the leaf",
  `revocation.rs:2036-2061`) and runs `HttpTransport` end-to-end against a
  loopback `TcpListener` serving a fixture DER (`:2084+`) — no internet.
- `SigningCredentials` exposes `pub certificate: Certificate` and
  `pub cert_chain: Vec<Certificate>` (`crypto/cert.rs:110,121`); the chain is
  chain-complete (p12 bags + embedded WWDR injection at `cert.rs:355-397`), so
  `issuer_of` resolves real Apple issuers from credentials.
- Expiry is already enforced at credential load: `code_signing_policy_violation`
  (`cert.rs:480-554`) rejects expired / not-yet-valid leaves and is called from
  `from_pem`/`from_p12` (`:643,:825`) and again per sign (`crypto/cms.rs:302`).
  Core tests pin it: `from_pem_rejects_expired_leaf` (`cert.rs:1710`),
  not-yet-valid (`:1742`), expired intermediate (`:1264`). A check-only run
  that loads credentials inherits these as exit-1 failures with no new code.
- The pin test's identity names no OCSP responder (no AIA), so a real `-C`
  signing run with `IDENTITY_P12` deterministically yields
  `NotChecked(NoOcspUrl)` **without opening a socket** — an offline-safe
  integration case.
- No public cert-only parse API exists in the editable surface (grep: none in
  `crypto/`), and extracting signer certificates from signed artifacts lives
  in `cms_verify.rs`/`codesign/verify.rs`/`zsign/src/verify.rs` — all
  read-only for this work.

## External contract (transcribed from upstream @ 614caa8d; not vendored here)

- One flag, two modes. Standalone — `if (bCheckSignature && strPKeyFile.empty()
  && strProvFile.empty()) return CheckCertificate(strPath, strPassword);`
  (`src/zsign.cpp:360-362`) — checks the *input file* (IPA/Mach-O/provision/
  p12/cer/pem, extension+content sniff, `certcheck.cpp:654-698`) and returns
  its code straight from `main`: **0 valid, 1 revoked, 2 expired, −1 error,
  −2 not signed** (`certcheck.h:5-11`), so the shell sees 0/1/2/255.
- During signing, upstream's post-sign `CheckSignedBinary` return value is
  **discarded** (`src/zsign.cpp:473-476`, final `return bRet ? 0 : -1` at
  `:515-517`) — upstream is fail-open during signing and gates only in
  standalone mode.
- Help text: `Check certificate validity and OCSP revocation status.`
  (`src/zsign.cpp:146`). OCSP transport upstream is a blocking raw socket,
  no TLS, no timeout; unreachable → −1 → 255; non-WWDR issuer skip → 0 unless
  expired → 2 (`certcheck.cpp:711-737`).

## Candidate designs

**A (chosen). Dual-mode `-C`, credentials-sourced, status-gated.** `-C`
gates during signing on an *authenticated revocation* (exit 1 before anything
is signed); without an input it runs a check-only mode that never signs and
exits 0/1/2. The certificate always comes from the credential flags
(`-k`/`--pkcs12`/`--keychain-identity`); a new native
`revocation::status_of(leaf, chain) -> RevocationStatus` supplies the status.
Fail-open stays exactly where the ticket tells us to document it loudly: any
`NotChecked` outcome during signing proceeds silently with exit 0, and the
help text names that posture in capitals.

**B. Rejected — upstream-parity keyless input checking (`zsign -C demo.ipa`).**
Requires extracting the signer certificate (and chain for `issuer_of`) from
IPA/Mach-O/provisioning artifacts: that code lives in `cms_verify.rs`,
`codesign/verify.rs`, and `zsign/src/verify.rs` — all read-only for this
work — and there is no public cert-only parse entry in the editable surface
(a bare `.cer/.pem` leaf would additionally hit `NoIssuerCertificate`
because `issuer_of` only searches the supplied chain). The divergence is
recorded in the README migration row instead.

**C. Rejected — a separate `--check-certificate` flag.** Functionally the
same surface as A's second mode, but adds a second spelling where upstream
has one dual-mode `-C`; the brief explicitly offers either shape and A needs
less help/README surface and matches upstream's mental model.

**D. Rejected — gating on `NotChecked` during signing too.** Upstream returns
255 on transport error, but this port's documented contract is "3s budget,
unreachable responders and offline use stay silent" for `-C` signers;
the ticket mandates nonzero for *revoked/expired*, and its instruction to
document a fail-open posture implies one remains. CI that needs the hard
"could-not-be-checked = failure" answer points at check-only mode, where
`NotChecked` exits 2.

**E. Rejected — test-only status override via env var / cfg flag.** Bakes
test behavior into production. The chosen dependency injection (below) passes
the production `status_of` in `run()` and a stub only from tests.

## Design (candidate A)

### `crates/zsign-core/src/crypto/revocation.rs` — one addition

```rust
/// Status-returning companion of [`warning_of`] for gate decisions: same
/// issuer resolution and clock, native-only because it opens the socket via
/// [`HttpTransport`]. `warning_of`/`warn_revocation` keep their semantics.
#[cfg(not(target_arch = "wasm32"))]
pub fn status_of(leaf: &Certificate, chain: &[Certificate]) -> RevocationStatus
```

Body: `check(leaf, issuer_of(leaf, chain), &HttpTransport::default(), None)`
(the exact network path `warn_revocation` takes today, returned instead of
printed). `warning()`, `warning_of`, `warn_revocation` are untouched.

### `crates/zsign-cli/src/main.rs`

**Clap:**
- `input`: add `required_unless_present = "check_revocation"` — `-C` without
  an input parses (check-only); every other invocation still requires input.
- `-k`/`--pkcs12` requirement is untouched: bare `zsign -C` still fails with
  a missing-credentials usage error (exit 2).
- `-C` conflicts (`verify`, `adhoc`) unchanged.

**`-C` doc/help rewrite (loud):** gate semantics first, then the fail-open
posture in caps-equivalent plain words: authenticated revocation aborts with
exit 1 *before* signing; **FAIL-OPEN — offline, an unreachable responder
within the 3s budget, or a certificate naming no responder leaves the run
exactly as before (signing proceeds, exit 0)**; without an input, check-only
mode never signs and exits 0 good / 1 revoked-or-invalid-credentials /
2 status-undeterminable.

**Plumbing:** `run(cli)` becomes a one-line wrapper over
`fn run_with_revocation(
 cli: Cli,
 probe: &dyn Fn(&SigningCredentials) -> RevocationStatus,
) -> Result<ExitCode, Box<dyn Error>>` — production passes
`|creds| revocation::status_of(&creds.certificate, &creds.cert_chain)`;
tests pass stubs. `SigningCredentials` and `RevocationStatus` are already
nameable from the CLI (`zsign_rs::SigningCredentials`,
`zsign_rs::crypto::revocation::RevocationStatus`), so the seam needs no new
types.

Inside `run_with_revocation`, in the credentials branch (unchanged
position — after `load_credentials`, before `ZSign::new`, so the gate is
before any signing and before input dispatch):

```text
if cli.check_revocation:
    status = probe(&credentials)
    match status:
        Revoked  -> return Err(<warning() text>)            # exit 1, nothing signed
        _        -> continue
    if cli.input.is_none():                                  # check-only mode
        match status:
            Good       -> print "revocation: good" (or the success JSON doc) ; return 0
            NotChecked -> emit_error("revocation could not be checked: {reason:?}") ; return 2
            Revoked    -> (already returned above)
```

Expired/not-yet-valid credentials never reach the probe: `load_credentials`
refuses them first (exit 1 via the existing `Error::Certificate` path).

**Tests (RED first):**

1. `check_revocation_gates_revoked_and_fails_open_when_uncheckable` — the
   **rewrite** of `check_revocation_flag_never_gates_a_signing_run` (foreign
   ticket-ID comment disappears with it). Scenarios:
   - (A) same parse as today's test (`-k … -p testpassword -C -o out.bin in.bin`)
     run through `run_with_revocation` with a stub returning
     `RevocationStatus::Revoked { revoked_at: None, reason: Some(…) }` →
     assert exit `ExitCode::from(1)` AND `!out.exists()` — the gate fires
     before any signing. Compile-RED today (no such function), and the
     assertion it pins (nonzero, unsigned) is the exact opposite of the old
     expectation.
   - (B) the real wiring preserved from the old body: `run(cli)` (production
     probe → `status_of` → `NotChecked(NoOcspUrl)`, no socket) →
     `ExitCode::SUCCESS` and `out.exists()` — pins the documented fail-open
     arm end-to-end through the production code path.
   - keep the `--help contains "--check-revocation"` assertion.
2. `check_only_mode_reports_and_gates_without_signing` (new): parse
   `["zsign","-k",key,"-p","testpassword","-C"]` (no input — RED today:
   missing-`<INPUT>` usage error); then three `run_with_revocation` runs with
   stub `Good` → exit 0 + stdout `revocation: good` (+ the success JSON doc
   when `--json`), stub `Revoked` → exit 1 + stderr `revoked`, stub
   `NotChecked(NoOcspUrl)` → exit 2 + stderr naming the reason; in every case
   assert nothing was signed (there is no input, so nothing can be).
3. `check_only_still_requires_credentials` (preservation guard): bare
   `["zsign","-C"]` still fails at parse with a missing-credentials error
   (exit 2) — defends the new input-optional shape against accidentally
   relaxing `-k`.
4. Existing `check_revocation_rejects_verify_and_adhoc_at_parse_time` and
   the credentials-requirement matrix stay untouched and green.
5. `crates/zsign-core/src/crypto/revocation.rs` (native module): loopback
   test for `status_of` mirroring the existing `HttpTransport` round-trip
   test — rewrite the fixture leaf's AIA to the bound port, serve
   `REVOKED_DER`, assert `status_of(...) == Revoked`. Deterministic, no
   internet (RED: `status_of` does not exist).

### README (`-C` rows only, append/replace within each section)

- Feature bullet (:23): warn-only wording → gate + check-only + loud
  fail-open summary.
- Flag-table row (:214) and the flag's conflicts cell: new semantics, the
  check-only invocation, exit codes.
- "### Revocation checking" section (:303-315): rewrite the contract
  paragraph — gate conditions, the fail-open list (offline / unreachable /
  no responder URL), check-only table of exits, and the note that ad-hoc
  signing still runs no credential check at all (unchanged).
- Migration table `-C` row (:389): upstream gates only standalone (keyless,
  artifact-based, 0/1/2/255) and discards the result during signing; this
  port does the opposite pair — gates during signing on authenticated
  revocation, adds a credentials-sourced check-only mode with 0/1/2, and
  does not port keyless artifact checking (its extraction lives in modules
  owned by another lane).
- Exit-status table (:241-255): append the check-only rows if the table
  shape has a per-mode section (match its neighbors).
- JSON section (:257-280): one appended success document row for check-only
  (`{"status":"checked","revocation":"good"}`); failures reuse the existing
  `{"status":"error","error":…}` document via `emit_error`.

### Explicitly out of scope

- Keyless artifact/provision checking (candidate B) — deferred modules.
- `warning()`/`warning_of`/`warn_revocation` semantics — preserved verbatim.
- `NotChecked` during signing stays silent + exit 0 (the documented
  fail-open posture); JSON schema for sign/verify modes unchanged.
- `-C` conflicts, `-V` wiring, `--json` flag mechanics beyond the one new
  success document.

## Acceptance criteria

1. A signing run `-C` whose probe reports an authenticated revocation exits
   1 **before** producing any signed output (the pin test's old expectation
   is gone; the rewrite pins this).
2. Check-only: `zsign -C -k <p12> -p <pass>` (no input) parses, never signs,
   and exits 0 on `Good`, 1 on `Revoked`, 2 on `NotChecked` — each asserted
   through `run_with_revocation` stubs; production `status_of` is proven by
   the revocation.rs loopback test and wired by scenario B.
3. The fail-open arm is pinned end-to-end: a real `-C` signing run with the
   no-responder test identity still signs and exits 0, and the `-C` help
   text loudly documents that posture.
4. Expired credentials exit 1 in check-only mode via the pre-existing
   load-time rejection (core tests `cert.rs:1710` etc. keep proving the
   policy; no new expiry code).
5. Bare `zsign -C` still fails usage with a credentials error (exit 2);
   `-C` still conflicts with `-V`/`-a`.
6. `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --
   -D warnings`, `TMPDIR=$PWD/target/tmp cargo test --workspace` all pass,
   and no changed line carries a ticket ID.
