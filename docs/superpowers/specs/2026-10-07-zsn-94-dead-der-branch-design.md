# ZSN-94 Dead DER Branch & Unused Constants — Design

**Date:** 2026-10-07 · **Ticket:** ZSN-94 · **Branch:** `zsn-94-codesign-dead-der-branch`
**Status:** approved for planning (cold review gate follows this doc and the plan)

## Goal

Two independent dead-code cleanups in `zsign-core`'s codesign module, each proven dead before deletion, each leaving zero new warnings and unchanged observable behavior:

1. **(a)** Remove the unreachable `Empty DER output` error branch in `plist_to_der`.
2. **(b)** Remove every unused constant in `codesign/constants.rs` (ticket cites line 70; scope is all siblings of the same class per the brief).

Files in scope — nothing else may be touched:

- `crates/zsign-core/src/codesign/der.rs` (incl. its inline test module)
- `crates/zsign-core/src/codesign/constants.rs` (incl. its inline test module)

## Evidence — sub-item (a): the branch is unreachable

Current code, verified at cbb53a0: `crates/zsign-core/src/codesign/der.rs:375-379`, inside `pub fn plist_to_der` (der.rs:345):

```rust
if der.is_empty() {
    Err(Error::DerEncoding("Empty DER output".into()))
} else {
    Ok(der)
}
```

Proof that `der` is never empty:

- **By construction:** `seq_content` unconditionally receives the 3-byte INTEGER version (`02 01 01`, der.rs:364-367) plus `entries`; `der` then unconditionally receives tag `0x70` (der.rs:371), one-or-more length octets from `encode_length` (der.rs:372; `encode_length` always pushes ≥1 byte, der.rs:69-71), and `seq_content` (der.rs:373). Minimum output = 7 bytes.
- **By test:** `test_plist_to_der_empty` pins the minimum output exactly — `assert_eq!(der, vec![0x70, 0x05, 0x02, 0x01, 0x01, 0xb0, 0x00])` (der.rs:465). Supporting: `test_plist_to_der_simple` envelope checks (der.rs:446-449), doctest `assert!(!der.is_empty())` (der.rs:38, :344).
- **By encode paths:** `encode_dictionary` always pushes `0xb0` + length ≥2 bytes even for `{}` (der.rs:182-183); every `encode_value` Ok arm pushes ≥1 tag byte before `Ok(output)` (der.rs:304). Failure paths return `Err` before `der` is built.
- **By external contract (librarian, source-verified):** ITU-T X.690 (08/2015 official PDF, identical clause numbering in 02/2021): §8.1.1.1 mandates identifier + length octets for every encoding; §10.1 mandates definite form in the minimum octets. No valid DER is ever zero bytes; empty SEQUENCE = `30 00` (2 octets). Upstream `zhlynn/zsign` (`zurbrigg/zsign` is 404) treats empty output as failure (`return (!strCMSOutput.empty())`, openssl.cpp); Apple's `EntitlementDERBlob` always carries ≥8-byte `BlobCore` header; OpenSSL `ASN1_object_size` minimum is 2 bytes. No consumer can observe empty output from this writer.

**Payload uniqueness:** the string `"Empty DER output"` has exactly one construction site workspace-wide — der.rs:376 (fuzz/ has zero matches; wasm maps the variant, not the payload, at `zsign-wasm/src/lib.rs:146`). `Error::DerEncoding(String)` itself (error.rs:37-38) has many other constructors (der.rs:108, 215, 297, 300, 349, 355; verify.rs `der_error` call sites; builder.rs:780) — **the variant stays; only this construction site dies.**

Also obsolete with the branch: the `# Errors` doc bullet `- The resulting DER encoding is empty` (der.rs:327).

## Evidence — sub-item (b): dead constants

Workspace-wide audit (crates/ + fuzz/, incl. tests, docs, comments, strings, doctests) of all **122** `pub const` items in `constants.rs`:

- **66 are definition-only** (zero references anywhere, incl. own inline tests) → candidates for deletion.
- **56 have at least one reference** → kept per the brief's rule ("if any reference exists, keep it and report").
- Of the 56 kept, **4 are referenced only by constants.rs's own inline tests**: `CSSLOT_TICKETSLOT` (test :501), `CS_SHA384_LEN` (:473), `CS_SHA512_LEN` (:474), `CODEDIRECTORY_VERSION_RUNTIME` (:510). A reference exists → keep and report, per the brief's literal rule.
- `CSSLOT_ALTERNATE_CODEDIRECTORY_MAX` (def :116) is referenced by `CSSLOT_ALTERNATE_CODEDIRECTORY_LIMIT` (used at verify.rs:36) → kept.
- Inline tests do not reference any of the 66 → no test-module edits are required by the deletion itself.
- All module-doc intra-doc links (constants.rs:1-34) point at kept constants → no broken intra-doc links.
- Two section groups become fully empty: **Opcodes** (all 24 `OP_*`) and **Match** (all 15 `MATCH_*`) — their section header comments are obsoleted by the deletion and must go with it.
- `superblob.rs:368-397` mentions `OP_*`/`MATCH_*` names in *comments only* — not code references; that file is out of scope (brief forbids touching it), and comment mentions produce no warnings.

## Design decisions

### (a) Approach

- **A1 (chosen):** replace the `if/else` with a direct `Ok(der)` tail and delete the `# Errors` bullet at der.rs:327. Smallest correct change; matches the brief's instruction ("simplify to return Ok(der) directly").
- **A2 (rejected):** keep a `debug_assert!(!der.is_empty())` — adds a behavior guard instead of deleting dead code; not what the brief asks.
- **A3 (rejected):** restructure the encoder to a type that cannot produce empty output — drive-by refactor, violates smallest-change.

No new test: this is pure dead-code removal; the existing suite is the regression proof (the branch's `Err` arm was never exercisable, and `test_plist_to_der_empty` already pins the output envelope). Stated explicitly per the brief.

### (b) Approach

- **B1 (chosen):** delete all **66** definition-only constants (with their doc comments and the two now-empty section headers); keep all 56 referenced; report the 4 test-only-referenced constants as kept.
- **B2 (rejected):** delete only `CSMAGIC_DETACHED_SIGNATURE` (line 70) — under-delivers: the ticket title is plural and the brief extends scope to "any sibling constants in the same file the ticket class would cover".
- **B3 (rejected):** also delete the 4 test-only-referenced constants and their tests — exceeds the brief's literal rule: a reference exists, so they are kept and reported.

No new test: the deletion's contract is "compile + clippy + full existing suite unchanged", proven by the scoped gate run.

## Acceptance criteria

1. `der.rs` has no `is_empty` branch and no `"Empty DER output"` string; `plist_to_der` ends in `Ok(der)`; doc bullet removed; `Error::DerEncoding` variant untouched.
2. `constants.rs` contains exactly the 56 referenced constants; zero occurrences of any of the 66 deleted identifiers remain workspace-wide (crates/ + fuzz/); no empty section headers left behind.
3. Scoped gates green, verbatim in the final report: `cargo fmt --all -- --check`; `cargo clippy -p zsign-core --all-targets -- -D warnings`; `cargo test -p zsign-core`.
4. Worktree clean; everything committed; no merge, no push, no git-config changes.
