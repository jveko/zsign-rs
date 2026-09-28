# Native Provisioning-Profile Size Cap — Design (ZSN-123)

Date: 2026-09-28
Branch: zsn-123-native-profile-cap (cut from main @ c88c4c0, post-ZSN-118)
Status: internal design decision record — no human review loop; supervisor pane is the escalation path.

## Problem

`MAX_PROFILE_BYTES = 16 * 1024 * 1024` exists only in `crates/zsign-wasm/src/lib.rs:76`
and is enforced only at two wasm pre-check sites (ctor `ensure_size` at
`lib.rs:279-284`, `extract_entitlements` at `lib.rs:526-532`). The native path has
no equivalent:

- `zsign-core::provisioning` accepts arbitrarily large profile bytes.
  `validate_and_extract_profile` (`provisioning.rs:95`) runs CMS verification first;
  `profile_document` (`provisioning.rs:432`) does `windows(6).position(...)` /
  `windows(8).rposition(...)` O(n) scans and then hands the span to
  `plist::from_bytes` — no size budget anywhere.
- `zsign::Error::InputTooLarge` (`crates/zsign/src/error.rs:58-59`) is raised only by
  IPA extraction limits (`ipa/extract.rs:691-704`), never by a profile path.
- README.md:348-350 presents "plists/profiles 16 MiB" as a global cap (README is
  Wave 8-owned; not edited here).

## Verified current-state facts (2026-09-28, this worktree)

- Core has NO size variant: `zsign_core::Error` variants are MachO, EncryptedBinary,
  Signing, Certificate, InvalidPassword, MissingCredentials, Config,
  ProvisioningProfile, Plist, Goblin, DerEncoding, Verification
  (`crates/zsign-core/src/error.rs:6-41`).
- Facade `From<zsign_core::Error>` (`crates/zsign/src/error.rs:62-68`) has two arms:
  `Plist(e) => Plist(e)`, `other => Core(other)` (wildcard). A new core variant lands
  in `Error::Core` unless an explicit arm is added.
- Wasm `code_for_core_error` (`crates/zsign-wasm/src/lib.rs:141-154`) is an EXHAUSTIVE
  match on `zsign_core::Error` with no wildcard — adding a core variant is a forced
  compile error there, which forces an explicit wasm-code decision. `code_for_zsign_error`
  already maps `zsign_rs::Error::InputTooLarge` → `ZSIGN_INPUT_TOO_LARGE` (`lib.rs:161`)
  and routes `Error::Core(inner)` through `code_for_core_error` (`lib.rs:160`).
- zsign-wasm depends on zsign-core directly (`crates/zsign-wasm/Cargo.toml:16`).
- The four core entry points taking profile bytes, all in `provisioning.rs`:
  `validate_and_extract_profile` :95, `extract_entitlements_from_profile` :387
  (delegates to `profile_document` :388), `extract_entitlements_checked` :411
  (delegates to one of the other two), `profile_document` :432.
- Native callers: facade builder `load_entitlements_from_profile`
  (`crates/zsign/src/builder.rs:674`), ipa `profile_document` at
  `ipa/mod.rs:191,237` and `extract_entitlements_checked` at `ipa/mod.rs:707,715,766`;
  facade re-exports `extract_entitlements_from_profile` and `profile_document`
  (`crates/zsign/src/lib.rs:49-50`); fuzz target `fuzz/fuzz_targets/provisioning.rs:17-18`
  calls both `validate_and_extract_profile` and `extract_entitlements_from_profile`.
  CLI touches profiles only via the facade (`crates/zsign-cli/src/main.rs:237,240,556,622`).
- `plist` 1.10.1 (Cargo.lock:988-992) enforces NO element-count and NO depth limit on
  the XML path (`stream/xml_reader.rs` has no depth/count/size field; `de.rs` has no
  recursion guard). quick-xml 0.42.0's `max_depth: 128` guard lives in its serde
  Deserializer, which plist does not use — unreachable. A ~550 KB / 50k-element XML
  plist is accepted by `plist::from_bytes` (source-path argument, to be pinned by
  measurement in the implementation test).
- Real `.mobileprovision` sizes: ~12-20 KB typical (FILExt corpus avg 12 KB;
  fastlane thread listings ~20 KB). Two orders of magnitude below 16 MiB — the cap
  cannot reject any legitimate profile.

## Design candidates (brainstorm record)

- **(a) Cap check as first statement of the core entry funnels** — O(1), before any
  scanning, covers native + wasm uniformly because wasm also calls into core.
  Chosen.
- **(b) Dedicated `read_profile_checked(reader)` entry every caller funnels through** —
  forces signature changes across builder/ipa/fuzz/wasm with no behavioral gain over
  (a). Rejected: larger diff, same enforcement point.
- **(c) Cap only inside `profile_document`** — weakest: `validate_and_extract_profile`
  (the CMS path the native signer uses by default) never calls `profile_document`;
  its O(n) CMS work would run first. Rejected.

## Decisions

**D1 — Cap lives in `zsign-core::provisioning`.**
`pub const MAX_PROFILE_BYTES: usize = 16 * 1024 * 1024;` added to
`crates/zsign-core/src/provisioning.rs`. One definition, both surfaces.

**D2 — Enforcement at the two funnels, first statement each.**
A private `fn ensure_profile_size(profile_data: &[u8]) -> Result<()>` is the first
statement of `validate_and_extract_profile` (before `resolve_now`/CMS) and of
`profile_document` (before the `windows()` scans). `extract_entitlements_from_profile`
and `extract_entitlements_checked` delegate to those two without their own check —
no call path reaches scanning without passing a check first. Invariant: every
`pub fn` taking `profile_bytes: &[u8]` either performs the check or delegates
immediately to one that does.

**D3 — Error variant: new core `Error::InputTooLarge(String)`.**
`#[error("Input too large: {0}")]` — same Display prefix as the facade variant.
Payload is detail only (e.g. `"provisioning profile is N bytes; the limit is M bytes"`),
so the facade mapping cannot double-prefix. Rationale: `Config` is for configuration
mistakes, `ProvisioningProfile` for profile content/shape failures — an input-size
rejection is a distinct, already-established taxonomy (`ZSIGN_INPUT_TOO_LARGE`,
facade `InputTooLarge`). Fail-closed: rejected before any byte is scanned or parsed.

**D4 — Facade mapping arm makes `Error::InputTooLarge` live natively.**
Add `zsign_core::Error::InputTooLarge(m) => Error::InputTooLarge(m)` to
`crates/zsign/src/error.rs:62-68`. Payload passed through (not the rendered string),
so Display stays `"Input too large: <detail>"`.

**D5 — Wasm stays byte-identical; constant becomes a re-export.**
The two wasm `ensure_size` pre-checks remain in place, unchanged messages and codes —
their behavior for >16 MiB is exactly today's `ZSIGN_INPUT_TOO_LARGE`. The local
`const MAX_PROFILE_BYTES` at `lib.rs:76` becomes a re-export of the core constant
(same value, one source of truth). The forced `code_for_core_error` arm maps core
`InputTooLarge` → `WasmErrorCode::InputTooLarge` (defense in depth: any future
direct-core call also codes correctly).

**D6 — Boundary semantics match `ensure_size`: reject `len > MAX`, accept `len == MAX`.**
Verified against wasm test `ensure_size_accepts_exactly_at_limit` (`lib.rs:1384-1398`).

**D7 — No element/depth budget in this change (recorded decision).**
`plist` 1.10.1 enforces neither; a deeply nested XML plist can recurse unboundedly
on the native stack. Adding a correct depth guard requires XML-aware scanning with
edge cases (escaped content, whitespace-in-tags) beyond this ticket's scope, and the
size cap alone does not eliminate it (16 MiB of `<dict>` nesting is still deep
enough to overflow). Decision: do not add a guard here; record the residual risk
below for a dedicated follow-up. The 550 KB / 50k-element wide-document behavior
stays exactly as today (accepted by `profile_document`; no element budget added).

## Error contract after this change

| Surface | Path | >16 MiB result |
|---|---|---|
| native core | `validate_and_extract_profile` | `Err(zsign_core::Error::InputTooLarge(detail))` before CMS/scanning |
| native core | `profile_document` (and delegates) | `Err(zsign_core::Error::InputTooLarge(detail))` before `windows()` scans |
| native facade | any profile entry (builder, ipa, re-exports) | `Err(zsign_rs::Error::InputTooLarge(detail))` via the new `From` arm — Display `Input too large: <detail>` |
| wasm `WasmSigner` ctor / `extract_entitlements` | `ensure_size` pre-check first | `ZSIGN_INPUT_TOO_LARGE`, message shape unchanged from today |
| wasm direct-core callers (future) | `code_for_core_error` new arm | `ZSIGN_INPUT_TOO_LARGE` |
| CLI | inherits via facade | exit contract unchanged (variant-specific mapping is ZSN-143's scope; this change only feeds `InputTooLarge`, the already-established variant) |

Exactly-at-limit (16 MiB) input passes the cap and proceeds to normal
parsing/validation — same semantics as wasm `ensure_size`.

## Test contract (TDD — written before implementation)

1. **Native 17 MiB rejected before scanning.** Feed `17 * 1024 * 1024` bytes (no XML
   marker, no CMS) to `validate_and_extract_profile`, `profile_document`, and
   `extract_entitlements_from_profile` (+ `extract_entitlements_checked` both
   `allow_unsafe` values). All must return `Error::InputTooLarge`, NOT
   `ProvisioningProfile("No XML plist found")` / CMS errors — the error *kind*
   distinguishes pre-scan rejection: reaching the scanner would produce a different
   variant and (for the scan path) requires O(n) windows passes first. Assert the
   message carries the observed length and the 16 MiB limit.
   Boundary: exactly `MAX_PROFILE_BYTES` does NOT produce `InputTooLarge`.
2. **Wasm unchanged.** Existing tests already pin `MAX_PROFILE_BYTES + 1` →
   `ZSIGN_INPUT_TOO_LARGE` / "too large" (`lib.rs:1400-1420`, `:1466-1469`); they
   must stay green without modification. Additionally assert the core constant
   equals the wasm-consumed value (re-export makes this structural).
3. **100 KB valid profile still works.** A valid signed profile padded to ~100 KB
   (extra non-validated key with a large string value) passes
   `validate_and_extract_profile` and `extract_entitlements_checked`.
4. **550 KB / 50k-element document pinned as today.** Build an XML plist with 50k
   top-level array elements (~550 KB); assert `profile_document` parses it to `Ok`
   (pinning current behavior: no element budget in this change).
5. **Facade variant live.** Native facade-level call returns
   `zsign_rs::Error::InputTooLarge` (not `Error::Core`) for an oversized profile.

## Residual risks (recorded, out of scope here)

- Deep XML nesting remains unbounded by `plist` 1.10.1 (D7) — candidate follow-up
  ticket: explicit depth guard for `profile_document`/`plist::from_bytes` inputs.
- README.md:348-350 caps claim stays partially aspirational for non-profile plists
  until Wave 8 docs work; this change makes the *profile* half of the claim true
  natively.

## Acceptance criteria

- `MAX_PROFILE_BYTES` single-sourced in zsign-core; wasm consumes it via re-export.
- Oversized profile errors on native AND wasm before any byte scanning; native
  variant is `InputTooLarge` end-to-end (core → facade).
- Zero-warning gate: `cargo fmt --all -- --check`,
  `cargo clippy --workspace --all-targets -- -D warnings`, and
  `TMPDIR=$PWD/target/tmp cargo test --workspace` green at ≥760 tests.
- No README/docs-table edits; no ticket IDs in code comments.
