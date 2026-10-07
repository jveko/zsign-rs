# ZSN-66 — Dead intra-doc link and dead helper: Design

**Date:** 2026-10-07
**Ticket:** ZSN-66 (lane zsn66, branch `zsn-66-macho-dead-doc-link`, base `cbb53a0`)
**Scope (authoritative brief):** two independent cleanups, both verified on main at `cbb53a0`:

- (a) `crates/zsign-core/src/macho/writer.rs` — module doc advertises a dead intra-doc link.
- (b) `crates/zsign-core/src/macho/signer.rs` — `embed_signature_into_prepared` retained only under `#[allow(dead_code)]`, superseded by `embed_signature_in_place`.

Files in scope: `writer.rs`, `signer.rs` (plus a test in one of those two files only if (b) requires test removal). Everything in `codesign/` and `crypto/` belongs to other lanes and must not be touched.

## Research findings (parallel scout + librarian batch)

### Sub-item (a): the dead link

`writer.rs` module doc (lines 1–14) item list at lines 11–14:

| Line | Link | Target | Verdict |
|---|---|---|---|
| 11 | `` [`write_signed_macho`] `` | `crates/zsign/src/macho/mod.rs:37` only; string absent from all of `crates/zsign-core/` | **DEAD** |
| 12 | `` [`embed_signature`] `` | `writer.rs:310` | alive |
| 13 | `` [`embed_signature_fat`] `` | `writer.rs:364` | alive |
| 14 | `` [`prepare_code_for_signing`] `` | `writer.rs:1136` | alive |
| 28 | `` [`embed_signature_fat`] `` (in `SignedSlice` doc) | `writer.rs:364` | alive |

Only line 11 carries the defect; lines 12–14 and 28 link in-crate items and must be left alone
("fix each occurrence [of the defect] the same way" — there is exactly one occurrence).

In-repo pattern: sibling zsign-core module docs use bracketed `` [`item`] `` links for **in-crate**
items and plain backticks for literals (this very module doc uses plain backticks at lines 4–8).
No other zsign-core module doc links a symbol defined only in `crates/zsign` (spot-verified
across codesign/, crypto/, macho/, provisioning/ docs).

External contract (librarian, source-cited):

- Intra-doc links resolve "in the scope of the module where the item is defined"; a crate can
  link its **dependencies**, never a sibling workspace member it does not depend on. `zsign`
  depends on `zsign-core`, not vice versa — the link is unfixable as a link without introducing
  a circular dependency.
- A broken link is warn-by-default (`rustdoc::broken_intra_doc_links`), renders as plain
  bracketed text, and fails the build only under `-D rustdoc::broken_intra_doc_links`.
- Plain backticks without brackets are inline code and never undergo link resolution.
- Repo has **no** RUSTDOCFLAGS / `[lints]` / rustdoc settings anywhere (no `.cargo/config.toml`,
  no workflow rustdoc env), so `cargo doc -p zsign-core --no-deps` warns on the dead link today —
  that warning is the observable failing state for (a).

`writer.rs` test infrastructure: `#[cfg(test)] mod tests` at lines 1690–1691; the `//!` doc has
no code blocks, so no doctest depends on it. (The only doctest in the file is on `align_to`.)

### Sub-item (b): the dead helper

- `#[allow(dead_code)]` at `signer.rs:752`; `fn embed_signature_into_prepared` at
  `signer.rs:753–778`; superseding `fn embed_signature_in_place` at `signer.rs:780–801`
  with production call sites at `signer.rs:722` and `:733`.
- Workspace-wide grep (crates/, fuzz/, docs/, tests) for `embed_signature_into_prepared`:
  **exactly one hit — its own definition** at `signer.rs:753` (the `#[allow(dead_code)]`
  attribute at `:752` does not contain the identifier and does not match).
  Zero calls, zero tests, zero doc references anywhere. No test in `signer.rs`'s
  `#[cfg(test)] mod tests` (starts line 933) touches it directly or indirectly.
- Deadness proof complete → the brief's delete branch applies; there are **no tests to remove**
  (none exist for this function), and nothing else references it.

Librarian: removing a private `#[allow(dead_code)]`-gated function has no rustdoc implications —
rustdoc only documents publicly reachable items; `#[allow(dead_code)]` is a rustc lint attribute
with no rustdoc behavior.

## Candidate approaches and decisions

### (a) Fix the dead intra-doc link — line 11

| # | Approach | Tradeoff | Decision |
|---|---|---|---|
| A1 | Replace `[`write_signed_macho`]` with plain code formatting `` `write_signed_macho` `` | One-token diff; matches the brief's first suggestion and the module's existing plain-backtick usage; zero link-resolution risk | **CHOSEN** |
| A2 | Reword the bullet to name the facade function in prose ("`write_signed_macho` in the `zsign` facade crate") | More context for readers but a larger copy change than the defect warrants | rejected (YAGNI, smallest correct change) |
| A3 | Make it a real cross-crate link | Impossible: would require `zsign-core` → `zsign` dependency = circular; rustdoc cannot resolve non-dependency siblings (cited) | rejected (infeasible) |

Lines 12–14 and 28 stay bracketed links — they are alive and touching them is scope creep.

### (b) Remove the dead helper

| # | Approach | Tradeoff | Decision |
|---|---|---|---|
| B1 | Delete `signer.rs:752–778` (attribute + function) | Zero references proven; brief mandates deletion when dead; no test removal needed | **CHOSEN** |
| B2 | Keep function, drop only the `#[allow(dead_code)]` | Triggers a `dead_code` warning → breaks the `-D warnings` zero-warning gate | rejected |
| B3 | Keep as-is and report a production caller | No production caller exists (N/A) | rejected (condition not met) |

## Risks / invariants

- Deletion must leave **zero new warnings**: `cargo clippy -p zsign-core --all-targets -- -D warnings`
  and `cargo test -p zsign-core` must stay green.
- Only the two named files may change; no drive-by fixes to nearby warnings.
- After (a), `cargo doc -p zsign-core --no-deps` must emit no `unresolved link to \`write_signed_macho\`` warning. Baseline measured on clean HEAD during implementation: 10 warnings / 7 unresolved-link — 1 ours (`write_signed_macho`) plus 6 pre-existing in out-of-scope/deferred files (`superblob`, `code_directory` at codesign/verify.rs:3, `Error::Verification` ×3, `Error::MachO`), plus 3 private-item link warnings. Acceptance is therefore the delta: unresolved-link 7 → 6, total 10 → 9, zero new. The 6 pre-existing warnings are findings for other lanes/out-of-scope files — reported, not fixed.
- No ticket ID in code comments; docs/commit subject may carry ZSN-66.
