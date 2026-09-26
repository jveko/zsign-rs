# Docs refresh design — README + AGENTS for the four-crate workspace

**Date:** 2026-09-27 · **Lane:** zsn46 (docs-only) · **Branch:** `zsn46-docs` @ `2725bf2`
**Scope:** one unticketed-but-tracked work item ("Refresh README and AGENTS for the
four-crate workspace and full CLI surface") plus the accumulated docs-lane needs recorded
by landing lanes. The code is the truth: document what is, never what was planned.

## Structure decisions

### README.md — targeted sectioned rewrite (chosen), full rewrite and incremental patch rejected

- **Full rewrite** was rejected: it would churn the ~40% of the README the stale-claim
  audit proved still true (SuperBlob layout, page hashing, depth-first signing,
  build/dev commands, references — inventory Part 2) and make review unbounded.
- **Incremental patch** was rejected: the needs list (complete flag surface, exit-code
  contract, JSON schema, password channels, migration notes, WASM surface, four new
  capabilities, crypto boundary, test/quality facts) adds whole sections; bolting them
  onto the current Usage block would leave the CLI story split across old and new text.
- **Chosen:** keep verified-true sections (How iOS Code Signing Works, Learning
  Resources skeleton, References, License) with surgical fixes; rewrite the Usage block
  into a CLI reference (flag table → exit status → `--json` → password); insert four new
  sections (Trust & crypto boundary, Migration/upstream parity, New capabilities,
  Test/quality update inside Development). Every rewritten claim is re-derived from the
  binary or source, so drift cannot survive in the rewritten parts.

### AGENTS.md — full lean rewrite (~50 lines)

The file is uniformly stale (2-crate claim, wrong crate names, wrong import/doc-comment
rules), so patching would leave a document assembled from corrections. Rewrite in place
with five sections: Build & Test, Architecture (four crates + `fuzz` member, wasm-safety
rule, store seam), Code Style (corrected rules + the `matches!`/`res.as_ref().err()`
assert convention). Keep it short: project rules only, no personal rules.

## Fact-verification policy

1. **Binary first.** Every flag, default, conflict, env var, and help string comes from
   `target/debug/zsign-cli --help` (captured after `cargo build -p zsign-cli`, 0
   warnings) or a live invocation of that binary (conflict errors, exit codes — all
   observed, exit 2 confirmed per case).
2. **Source second.** Exit-code mapping, password precedence, JSON DTO shapes, wasm
   signatures/caps: `crates/zsign-cli/src/main.rs` and `crates/zsign-wasm/src/lib.rs`
   at cited lines.
3. **Design docs for rationale and contracts** the code cannot show (JSON schema v1
   status, upstream-parity rationale, OCSP posture, trust-anchor policy), cited by path
   under `docs/superpowers/specs/`.
4. **No aspiration.** Anything not landed (CI keychain recipe, `crates/zsign-wasm`
   README refresh, LICENSE file, release version bumps) is either omitted or explicitly
   labelled as recorded-not-shipped; never stated as existing.
5. **Ticket IDs never appear in README/AGENTS prose** — design docs are cited by path.
   Ticket IDs appear only in commit subjects if at all.

## Corrections to the brief's assumptions (verified, recorded before writing)

- **README has no crypto-boundary text at `:32-57`** (or anywhere: 0 matches for
  `trust|anchor|revocation|Apple Root|OCSP|deterministic|keychain|32-bit` in 253
  lines). Brief item 2h is **additive**, not a reconciliation.
- **"ZSN-42" does not exist in the repo.** The crypto doc is lane `zsn42-crypto`
  (tickets ZSN-14/18/21) and has no section headed "boundary"; the boundary claim is
  assembled from `2026-09-24-cms-trust-anchor-design.md` §4/§8,
  `2026-09-26-crypto-repro-credentials-design.md` "Verification posture", and
  `cms_verify.rs:31-33`.
- **ZSN-41 is the web-demo ticket, not determinism.** Determinism = ZSN-15 (zip sort +
  1980-01-01 pins) + ZSN-14 (RFC 6979); ZSN-16 reuses both on the wasm bytes path.
- **The workspace has five members**, not four: `crates/{zsign,zsign-core,zsign-wasm,
  zsign-cli}` + `fuzz` (`zsign-fuzz`, `publish = false`). README/AGENTS document four
  product crates plus the fuzz member.
- **`--version` is unsupported** (exit 2, clap has no `version` attribute) — never
  documented.
- **No badges exist** (0 matches in README, 5 workflows on disk) — no badge section is
  added; CI facts are stated as plain statements.

## Stale-claim inventory being addressed

25 items (14 AGENTS.md, 11 README.md) from the lane's line-by-line audit against
source; plus a 22-entry verified-true list that is deliberately not churned. Status
resolution is tracked in the final report. Headline resolutions:

| Area | Items | Resolution |
|---|---|---|
| AGENTS two-crate claim, module list, crate names (`x509-certificate`, `cryptographic-message-syntax`), import grouping, doc-comment claim, `Error::Variant` claim, missing assert convention, missing wasm/fuzz/gates | 1–14 | rewritten in the new AGENTS.md |
| README library import (`use zsign::` → `use zsign_rs::`), crate table, architecture tree, wasm example story, exit-status sentence, features/key-concepts gaps, core "no fs/threading" wording | 15–24 | fixed by the targeted rewrite |
| MIT license with no root `LICENSE` file | 25 | reworded to match the manifests; adding a LICENSE file is an orchestrator note, not this lane's edit |

Unverifiable-but-plausible items handled honestly: Windows is **checked** in CI, not
suite-tested (worded as such); `-V` enumeration is described from `verify.rs` module
docs, not re-derived exhaustively.

## Scope fences (discovered needs this lane cannot act on)

- `crates/zsign-wasm/README.md` (72 lines) predates `sign_ipa` — stale, but it is not
  this lane's file per the brief (README.md/AGENTS.md only) → orchestrator note.
- `Cargo.toml` version fields (0.1.x → 0.2.0) → orchestrator's release decision; the
  README records the migration rationale only.
- `ci.yml:59-62` still carries the release-job `--skip test_ipa_signing_is_deterministic`
  line although ZSN-15 landed; removal was explicitly reserved to the orchestrator.
  README wording cites the unskipped debug job and named tests, never release coverage.
- No root `LICENSE` file; scripts/, tests, fixtures, hk config, `.gitignore` belong to
  lane zsn45 / orchestrator (zero overlap required; this lane edits only README.md,
  AGENTS.md, and this design/plan pair).
