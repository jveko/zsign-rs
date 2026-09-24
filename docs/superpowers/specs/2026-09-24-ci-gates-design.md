# Design — CI gates + publish supply chain (lane 31)

- Branch: `zsn-31-ci-gates`, base `ee42c12`.
- Scope authority: the lane-31 mission brief (`/tmp/zsn-31.txt`, inlined ZSN-31 ticket).
  The brief wins over any ticket text; no re-scope, no expansion.
- Research: one batch of 4 read-only scouts (workflow map, fixture references,
  action pins, MSRV/tooling), run 2026-09-25. Findings cited below.

## Problem

CI and release workflows have four classes of gaps:

1. **File-gated lint.** The `lint` job runs `hk check --pr`, whose cargo-fmt and
   cargo-clippy steps are gated on `**/*.rs` (verified: `hk.pkl` step globs), so a
   Cargo.toml- or workflow-only change merges without the `-D warnings` gate.
2. **Test-matrix gaps.** The suite runs on ubuntu/debug only. `--release`
   integer-overflow behavior, `cfg(not(unix))` branches (`crates/zsign/src/ipa/extract.rs`,
   `crates/zsign/src/bundle/code_resources.rs`), and wasm tests are never executed
   (zsign-wasm currently has zero `#[wasm_bindgen_test]` tests).
3. **No supply-chain tooling.** No `deny.toml`, no advisory/license/source policy,
   no Dependabot. The wasm publish installs wasm-pack via unpinned `curl | sh`
   (`.github/workflows/publish-wasm.yml:24`).
4. **Ungated publishing.** Any `v*` tag publishes all three crates: no green-CI
   requirement, no dry-run, no tag↔version assertion. Versions already drift
   (core 0.1.0 / facade 0.1.2 / cli 0.1.1). No manifest declares `rust-version`.

Hygiene gaps: no concurrency cancellation, no `timeout-minutes`, interop
diagnostics die with the script's temp dir (`scripts/verify-apple-interop.sh:30-31`),
and `cargo package -p zsign-core` would ship the 9 `.p12` private-key test
fixtures (manifest has no include/exclude).

## Invariants (from the brief; non-negotiable)

- Config/manifest files only. The single non-workflow/manifest exception is
  `scripts/verify-apple-interop.sh`, in scope **only** for writing a diagnostics file.
- Never merge, never push. Conventional commits; ticket ID may appear in the
  commit subject, never in code comments.
- Queue order 1→8; each item lands as its own independently-green commit series
  before the next begins.
- Never touch `hk.pkl`, README/AGENTS.md, `examples/web` sources, other lanes'
  `.rs` files, or `.gitignore` (the two design docs are force-added instead).
- Existing jobs stay intact: `lint` (hk check), `test` (debug, full suite),
  `wasm` (compile-only), `interop` (macOS interop script).
- Known failure `test_ipa_signing_is_deterministic` (ZSN-15, zip entry-order
  nondeterminism): the existing `test` job keeps running it unchanged; **new**
  jobs that execute the suite skip it so the flake cannot block unrelated PRs.
- Validation: `actionlint` (baseline captured: exit 0 on `ee42c12`) after every
  workflow change; targeted `cargo check` / `cargo package` for manifest changes;
  `cargo deny check` locally if installable. Never `cargo fmt` / `cargo clippy` /
  `hk` as my own gate — the orchestrator runs those at merge.

## Evidence base (scout-verified)

| Fact | Evidence |
|---|---|
| ci.yml = 65 lines; lint 12-30 (hk step 24-30), test 32-39 (`cargo test --workspace` :39), wasm 41-53, interop 55-65 | ScoutWorkflowMap |
| publish-crates.yml = 27 lines; the three publish steps are 22-27 | ScoutWorkflowMap |
| publish-wasm.yml:23-24 is the `curl … \| sh` wasm-pack installer | ScoutWorkflowMap, own count |
| hk.pkl:31-34 cargo-test step exists (`check = "cargo test --workspace"`, unconditional); cargo-fmt/cargo-clippy gated `**/*.rs`; actionlint gated `.github/workflows/*.yml` | ScoutWorkflowMap |
| deny.toml, .github/dependabot.yml absent; docs/ absent and gitignored (`.gitignore:34`); exactly 3 workflow files | ScoutWorkflowMap |
| All 9 `.p12` fixtures live in `crates/zsign-core/src/crypto/fixtures/`; every reference is `include_bytes!` inside `#[cfg(test)] mod tests` (`crates/zsign-core/src/crypto/pkcs12.rs:822-839`); zero non-test reads | ScoutFixtureRefs |
| zsign-wasm: 0 wasm tests; `wasm-bindgen-test` only an unused dev-dependency | ScoutFixtureRefs |
| Max declared `rust-version` across 197 resolved packages = **1.88.0** (plist 1.10.1, time 0.3.55, time-core, time-macros); 44 packages declare none; no manifest declares `rust-version` today | ScoutMsrvTools |
| actionlint 1.7.12 present; baseline run exit 0, zero output. cargo-deny/wasm-pack/cargo-msrv NOT installed locally; rustup present with `stable`/`1.98.0`/`1.98.1`/nightly | ScoutMsrvTools |
| cargo-deny current schema (0.20 era): `advisories.yanked`, `[licenses] allow`, `[bans] multiple-versions`, `[sources] unknown-registry/unknown-git`; pre-0.15 keys removed | ScoutActionPins (cargo-deny book) |
| `cargo-deny-action@v2.1.1` (bundles cargo-deny 0.20.2) runs all four checks by default; `taiki-e/install-action` current `v2` line, latest `v2.87.20`, supports `tool: wasm-pack`; `dtolnay/rust-toolchain@1.88.0` version branches exist upstream | ScoutActionPins (GitHub API/READMEs) |
| `wasm-pack test --node <path>` targets wasm32-unknown-unknown and auto-installs it via rustup | ScoutActionPins (wasm-pack docs) |
| examples/web: `npm run build` = `vite build`, `package-lock.json` present, but depends on `file:../../crates/zsign-wasm/pkg` which must be produced by `wasm-pack build` first | ScoutWorkflowMap |

## Decisions per queue item

### 1. Unconditional lint gates

**Chosen:** keep the `lint` job and its `hk check --pr` / `hk check --all` step
unchanged (per-file hygiene + the unconditional cargo-test step), and append two
plain steps to the same job: `cargo fmt --all -- --check` and
`cargo clippy --workspace --all-targets -- -D warnings`. They run on every push
and PR regardless of which files changed, reusing the job's existing toolchain
(`rustfmt`, `clippy` components already requested).

**Alternatives considered:**
- *Separate `fmt`/`clippy` jobs parallel to `lint`* — rejected: duplicates
  checkout/toolchain/cache setup for no added rigor; longer wall clock for the
  same two commands.
- *Remove the `**/*.rs` file gate in `hk.pkl`* — rejected: `hk.pkl` is
  explicitly out of scope (wave 0 owns it).

### 2. Test-matrix gaps

**Chosen (three additions):**
1. New job `test-release`: `cargo test --workspace --release -- --skip
   test_ipa_signing_is_deterministic`. Skipping the known ZSN-15 flake in the
   *new* job is required by the brief (must not block unrelated PRs); the
   existing debug `test` job stays byte-identical and keeps running it.
2. New job `windows-check` on `windows-latest`: `cargo check --workspace
   --all-targets` — check-only in this iteration so `cfg(not(unix))` branches
   at least compile; full Windows test execution is documented as a follow-up
   (in the job's YAML comment and the final report, no ticket ID in comments).
3. Two steps appended to the existing `wasm` job: install wasm-pack via
   `taiki-e/install-action` and run `wasm-pack test --node crates/zsign-wasm`.
   A step (not a job) reuses the job's existing toolchain, wasm32 target, and
   cache; it passes today with zero wasm tests, establishing the scaffold.

**Alternatives considered:**
- *Release tests as a second step inside the existing `test` job* — rejected:
  serializes debug+release under one timeout and mixes both failure modes into
  one status; a separate job gives independent caching, timeout, and signal.
- *Full os×profile matrix (macOS tests, Windows tests)* — rejected: macOS is
  already covered by the interop job (release build + Apple verification);
  running the full suite on Windows is unverified territory the brief
  deliberately defers.
- *Separate `wasm-test` job* — rejected: buys nothing over a step; the wasm job
  already has the exact toolchain the test needs.

### 3. Supply-chain tooling

**Chosen:**
- New `deny.toml` (repo root) on the current 0.20-era schema:
  `[advisories] yanked = "deny"` (brief's "advisories (yank)" as an actual gate;
  warn would be the default and gates nothing),
  `[licenses] allow = [...]` covering MIT, Apache-2.0, BSD-2/3-Clause, ISC,
  Unicode-3.0/Unicode-DFS-2016, CC0-1.0, Unlicense, Zlib, plus any additional
  license the tree actually declares — the final list is validated empirically
  by running `cargo deny check` locally;
  `[bans] multiple-versions = "warn"` (per brief);
  `[sources] unknown-registry = "deny"`, `unknown-git = "deny"` (crates-io is
  in `allow-registry` by default → "source crates-io only").
- New `deny` job in ci.yml: `actions/checkout@v4` +
  `EmbarkStudios/cargo-deny-action@v2.1.1` (the action installs cargo-deny and
  runs all four checks by default; exact tag pinned — see cross-cutting decision).
- New `.github/dependabot.yml`: `cargo` (workspace root) + `github-actions`,
  both weekly.

**Alternatives considered:**
- *`cargo audit` instead of cargo-deny* — rejected: advisories-only; the brief
  explicitly asks for license bans and source policy too.
- *Floating `cargo-deny-action@v2`* — rejected: brief says "pinned-tag"; the
  upstream README itself recommends immutable `v2.x.y` tags for install-action.
- *Matrix form (`command: check` per check group) from the action README* —
  rejected: one job running all four checks is simpler and matches
  "a `cargo deny check` job".
- *Yank policy `warn`* — rejected: would never fail; the point of item 3 is a gate.

### 4. MSRV

**Chosen:** `rust-version = "1.88"` — the exact floor of the resolved dependency
set (max declared = 1.88.0 from `plist 1.10.1` / `time 0.3.55`). Declared once
in root `Cargo.toml` under `[workspace.package]` and inherited by all four
members via `rust-version.workspace = true` (single source of truth, no drift).
New `msrv` job pins `dtolnay/rust-toolchain@1.88.0` and runs
`cargo check --workspace --all-targets`. Validated locally by installing the
1.88.0 toolchain and running the same check — if the dep set does not actually
build on 1.88 (44 packages declare no MSRV), the version is raised to whatever
the evidence supports and the job pin follows.

**Alternatives considered:**
- *`cargo msrv` binary-search* — rejected: not installed, and `cargo install
  cargo-msrv` is a heavy compile; the metadata floor plus an actual
  `cargo +1.88.0 check` is equivalent evidence for less cost.
- *Literal `rust-version` duplicated in each manifest* — rejected: four copies
  invite drift; the brief's "workspace+manifests" phrasing points at the
  workspace-inheritance mechanism.
- *Conservative recent stable (e.g. 1.98) without evidence* — rejected: cargo
  metadata gives a defensible exact floor, so guesswork is unnecessary; an
  over-high MSRV would lie to downstream users.

### 5. Publish gating

**Chosen for `publish-crates.yml`:**
- New `verify` job: checkout → toolchain (rustfmt, clippy) → rust-cache →
  **tag↔version assertion** (first, fail-fast) → `cargo fmt --all -- --check` →
  `cargo clippy --workspace --all-targets -- -D warnings` → `cargo test --workspace`.
  The assertion strips the `v` from `GITHUB_REF_NAME` and compares it against
  `cargo metadata --no-deps` versions of `zsign-core`, `zsign-rs`, `zsign-cli`
  via `jq`; any mismatch exits 1 with a per-crate message.
- `publish` job gains `needs: verify` and a first step
  `cargo publish -p zsign-core --dry-run` (no token required) before the three
  real publishes, which stay byte-identical.
- Consequence (intentional): while versions drift (0.1.0/0.1.2/0.1.1) the gate
  fails on any tag — that is the forcing function the brief asks for. Equalizing
  versions is a release-management decision explicitly *not* in this lane's
  scope; it is reported as a follow-up.

**Chosen for `publish-wasm.yml`:** same `verify` job shape (fmt → clippy → test,
`needs: verify`), and the `curl | sh` installer replaced by
`taiki-e/install-action@v2.87.20` with `tool: wasm-pack`. The `wasm-v*` tag gets
no version assertion — the brief specifies the assertion only for the `v*`
crates workflow ("same verify gate" = the verify job).

**Alternatives considered:**
- *Assert tag equals versions inside the publish job* — rejected: wastes test
  minutes before failing; `needs: verify` should fail fast.
- *Bump all crate versions to match as part of this lane* — rejected: release
  decision + dependency-requirement bumps = re-scope.
- *Version assertion in publish-wasm too* — rejected: not requested; `wasm-v*`
  tag semantics differ (single npm package).
- *Dry-run every crate* — rejected: brief specifies zsign-core only (it is the
  package whose tarball contents this lane changes; facade/cli would require
  index-published dependencies to be meaningful).

### 6. Keep private keys out of the crates.io tarball

**Chosen:** add `exclude = ["/src/crypto/fixtures"]` to
`crates/zsign-core/Cargo.toml` (exclude, not include-list: preserves the default
package contents — `benches/signing.rs`, which the `[[bench]]` target needs —
with the smallest manifest diff). Safety argument, confirmed empirically not
assumed: every fixture reference is a compile-time `include_bytes!` inside
`#[cfg(test)]` (`pkcs12.rs:822-839`), and `cargo package`'s verify build does
not compile `cfg(test)` code. Validation: `cargo package -p zsign-core
--allow-dirty --list` must show zero `.p12`, then a full `cargo package
-p zsign-core --allow-dirty` must succeed. Fixtures stay in the repo.

**Alternatives considered:**
- *Explicit `include` list* — rejected: must enumerate everything the package
  needs (src, benches, …); a missing pattern breaks packaging silently later;
  exclusion achieves the goal with less surface.
- *Move fixtures out of `src/` to `tests/fixtures/`* — rejected: touches
  `pkcs12.rs` (a `.rs` file — forbidden) and does not by itself stop packaging.

### 7. CI hygiene

**Chosen:** workflow-level
`concurrency: { group: ci-${{ github.ref }}, cancel-in-progress: true }` in
ci.yml; `timeout-minutes` on **every** ci.yml job (existing and all new jobs,
values sized per job: 10 deny / 20 lint / 30 test, wasm, windows / 45
test-release, msrv, interop — release and cold-MSRV builds and macOS release
builds are the slow paths). For interop diagnostics: the script writes
`target/interop-diagnostics.log` (inside the gitignored `target/`, so no
.gitignore edit) containing an environment header (uname/sw_vers/openssl/date),
every `fail()` message plus a `ls -laR` snapshot of `$WORK`, and the
`codesign -d --verbose=4` dump; ci.yml uploads it with
`actions/upload-artifact@v4` under `if: failure()`.

**Alternatives considered:**
- *Diagnostics file in the repo root* — rejected: creates an untracked file and
  would force a `.gitignore` edit, which is forbidden (lane collisions).
- *Tee the whole transcript to the diagnostics file* — rejected: process-
  substitution race on failure exit; deterministic appends at key points are
  reliable.
- *Disable the temp-dir `trap`* — rejected: leaves MBs of artifacts on runners
  and changes the script's cleanup contract.
- *Timeouts also in publish workflows* — rejected: item 7 scopes CI hygiene to
  ci.yml; publish workflows get only the changes item 5 specifies.

### 8. Scheduled examples/web build

**Chosen (it is cheap enough to take):** new `.github/workflows/examples-web.yml`
with `schedule` (weekly cron) + `workflow_dispatch`, running: checkout →
toolchain with wasm32 target → rust-cache → wasm-pack install →
`wasm-pack build crates/zsign-wasm --target web` (no `--scope`, because
examples/web consumes the unscoped `zsign-wasm` file: dependency) → setup-node 24 →
`npm ci` → `npm run build` (vite) in `examples/web`. This catches wasm API drift.

**Alternatives considered:**
- *Job inside ci.yml* — rejected: ci.yml runs on every push/PR; a scheduled,
  wasm-toolchain-heavy build belongs in its own workflow (and gets its own
  `workflow_dispatch` for on-demand runs).
- *Defer to a follow-up* — rejected: tooling is present (node/npm local, actions
  already chosen), so it meets the brief's "optional if cheap" bar.

## Cross-cutting decisions

1. **Pinning convention for NEW action refs:** exact release tags
   (`cargo-deny-action@v2.1.1`, `install-action@v2.87.20`) because the brief
   demands pinned tags and these are supply-chain additions. Existing refs
   (`@v4`, `@v2`) stay untouched — converting the repo to SHA-pinning is a
   separate, repo-wide decision, deliberately rejected here (second convention
   risk vs. existing files; SHA-pinning everything belongs in its own lane).
2. **Known-failure policy:** existing `test` job unchanged (runs
   `test_ipa_signing_is_deterministic`); new suite-executing jobs
   (`test-release`, publish `verify`) — `test-release` skips it (blocks no PR);
   publish `verify` runs the full suite as the brief's verbatim spec
   (`cargo test --workspace`) since publish workflows never run on PRs. Risk
   noted in the final report.
3. **No cargo-fmt/clippy/hk run by this lane** (orchestrator's merge gate);
   no `cargo test` run either — zero `.rs` changes, suite state cannot move.

## Validation strategy

- `actionlint` after every commit touching workflows (baseline: clean on
  `ee42c12`); final run over all five workflow files.
- Item 4: `rustup toolchain install 1.88.0` + `cargo +1.88.0 check
  --workspace --all-targets` (manifest claim == observed build).
- Item 6: `cargo package -p zsign-core --allow-dirty --list` (assert no `.p12`)
  then full `cargo package -p zsign-core --allow-dirty`.
- Item 3: install cargo-deny (prebuilt release binary; `cargo install` fallback)
  and run `cargo deny check`; if neither is feasible, keep config to the
  documented schema and say so honestly.
- Item 2/8: install wasm-pack (prebuilt) and run `wasm-pack test --node
  crates/zsign-wasm`; for examples/web run `npm ci && npm run build` locally.
  Network-dependent steps that fail once are recorded as unvalidated, not
  retried indefinitely.
- Existing jobs intact: structural diff review (lint/test/wasm/interop
  definitions unchanged apart from appends) + actionlint.

## Risks & deferred follow-ups

- **Windows `cargo check` may legitimately fail** if `cfg(not(unix))` code has
  bit-rotted — that is the gate doing its job; first CI run decides. Full
  Windows *test* execution is an explicit follow-up.
- **Publish gate vs. version drift:** until versions are equalized, every `v*`
  tag fails the assertion — intended; version alignment is a follow-up decision.
- **clippy/fmt pass-state on merge** is the orchestrator's gate (not run here).
- **Out-of-scope observation:** `publish-crates.yml` interpolates
  `secrets.CARGO_REGISTRY_TOKEN` into `run:` — standard pattern but a known
  injection-surface class; recorded for a future security lane, not changed here.
- **examples/web scheduled runs** only take effect after merge to the default
  branch (GitHub schedules run from the default branch).
