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
  CLI reaches profiles only through the facade: `crates/zsign-cli/src/main.rs:237`
  (`provisioning_profile`), `:240` (`allow_unsafe_profile`),
  `:252-253` (`bundle_profiles` from `--profile-map`).
- One facade site re-wraps core profile errors: `IpaSigner::load_bundle_profiles`
  (`crates/zsign/src/ipa/mod.rs:771-776`) formats ANY `extract_entitlements_checked`
  error into `Error::Core(Config("… is invalid: {e}"))` to name the offending
  bundle id + path. Without a deliberate arm, a size rejection on a `--profile-map`
  entry would surface as `Config`, not `InputTooLarge` (decision D8). Root-profile
  paths (`load_profile` `ipa/mod.rs:707,715`, builder
  `load_entitlements_from_profile` `builder.rs:674`) propagate via `?` and map
  through the `From` arm unchanged.
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
`zsign_core::Error::InputTooLarge(m) => Error::InputTooLarge(m)` added to
`crates/zsign/src/error.rs:62-68`. Payload passed through (not the rendered string),
so Display stays `"Input too large: <detail>"`. Where a facade site appends its
own context to the payload (D8), that context rides inside `<detail>` — one
prefix, never doubled.

**D5 — Wasm pre-check behavior byte-identical; constant becomes a re-export.**
"Byte-identical" scopes to the two surfaces that already reject today (the
`ensure_size` pre-checks): their messages and codes for >16 MiB are exactly
today's `ZSIGN_INPUT_TOO_LARGE`. Paths that had NO cap before (wasm `sign_ipa`
plan build) newly reject — that is the fail-closed fix, not a regression, and
the contract table below records it. The local
`const MAX_PROFILE_BYTES` at `lib.rs:76` becomes a re-export of the core constant
(same value, one source of truth). The forced `code_for_core_error` arm maps core
`InputTooLarge` → `WasmErrorCode::InputTooLarge` (defense in depth: any future
direct-core call also codes correctly). The `sign_ipa` limitation note
(`lib.rs:40`, "profile validation during plan build can surface
`ZSIGN_VERIFICATION` or `ZSIGN_INVALID_PROFILE`") gains `ZSIGN_INPUT_TOO_LARGE`:
that path now rejects oversized embedded profiles via the facade arm — crate
rustdoc in a file already being edited, not the Wave 8-owned README caps claim.

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

**D8 — The profile-map context wrap preserves the `InputTooLarge` variant.**
`load_bundle_profiles` keeps its bundle-id/path context for every rejection, but
for the size rejection it returns `Error::InputTooLarge` (context appended to the
payload) instead of `Error::Core(Config(…))`. Rationale: the wrap exists to name
the offending map entry, not to reclassify failures; swallowing the variant would
make the facade contract below false for exactly the fail-closed case the cap is
about, and would force wasm `sign_ipa` plan-build size rejections through the
`Config` code instead of `ZSIGN_INPUT_TOO_LARGE`. Every other error from that
site keeps today's `Config` shape byte-for-byte. This is not the ZSN-143
error-code unification (which reorganizes codes across profile entry points); it
is the propagation rule for this change's own new variant.

## Error contract after this change

| Surface | Path | >16 MiB result |
|---|---|---|
| native core | `validate_and_extract_profile` | `Err(zsign_core::Error::InputTooLarge(detail))` before CMS/scanning |
| native core | `profile_document` (and delegates) | `Err(zsign_core::Error::InputTooLarge(detail))` before `windows()` scans |
| native facade | root profile entries (builder, ipa `load_profile`, re-exports) | `Err(zsign_rs::Error::InputTooLarge(detail))` via the new `From` arm — Display `Input too large: <detail>` |
| native facade | `--profile-map` entries (`load_bundle_profiles`) | `Err(zsign_rs::Error::InputTooLarge)` with bundle id + path appended to the payload (D8); other errors from that site keep their `Config` shape |
| wasm `WasmSigner` ctor / `extract_entitlements` | `ensure_size` pre-check first | `ZSIGN_INPUT_TOO_LARGE`, message shape unchanged from today |
| wasm `sign_ipa` plan build (embedded/bundle profile) | facade `Error::InputTooLarge` (existing arm `lib.rs:161`) | `ZSIGN_INPUT_TOO_LARGE` — newly rejectable: this path had no cap anywhere before this change (the wasm-only cap covered only the two `WasmSigner` pre-checks), and fail-closed requires the error here too |
| wasm direct-core callers (future) | `code_for_core_error` new arm | `ZSIGN_INPUT_TOO_LARGE` |
| CLI | inherits via facade | exit contract unchanged (variant-specific mapping is ZSN-143's scope; this change only feeds `InputTooLarge`, the already-established variant) |

Exactly-at-limit (16 MiB) input passes the cap and proceeds to normal
parsing/validation — same semantics as wasm `ensure_size`.

## Test contract (TDD — written before implementation)

1. **Native 17 MiB rejected before scanning.** Feed `17 * 1024 * 1024` bytes (no XML
   marker, no CMS) to `validate_and_extract_profile`, `profile_document`, and
   `extract_entitlements_from_profile` (+ `extract_entitlements_checked` both
   `allow_unsafe` values — the `true` arm is the raw byte-scan bypass reachable
   from `--allow-unsafe-profile`, and must reject exactly the same way). All must
   return `Error::InputTooLarge`. The observed kind distinguishes pre-scan
   rejection: without the cap the scan funnels would return
   `ProvisioningProfile("No XML plist found …")`, and the validate funnel would
   return `Error::Verification` (its first operation is
   `cms_verify::resolve_now` → CMS envelope verification at
   `provisioning.rs:99-105` — on wasm32 a `None` clock errors even earlier with
   the same variant). The 17 MiB heap buffer is never touched beyond `.len()` —
   the guard runs before any scan, mirroring how the wasm oversize test
   (`lib.rs:1466-1469`) allocates `MAX_PROFILE_BYTES + 1` without ever scanning it;
   the wasm 512/128 MiB guards by contrast take `len` as a bare number and never
   allocate at all (`lib.rs:1380-1383`) — boundary behavior is pinned by calling
   `ensure_profile_size` directly with `MAX_PROFILE_BYTES` (Ok) and
   `MAX_PROFILE_BYTES + 1` (Err), NOT by running an end-to-end parse over a 16 MiB
   buffer. Assert the message carries the observed length and the 16 MiB limit.
2. **Wasm unchanged.** Existing tests already pin `MAX_PROFILE_BYTES + 1` →
   `ZSIGN_INPUT_TOO_LARGE` / "too large" (`lib.rs:1400-1420`, `:1466-1469`); they
   must stay green without modification. These run under `wasm-pack test --node`,
   NOT under the workspace gate — the plan records whether wasm-pack ran, and the
   native `ensure_profile_size` boundary test (`MAX+1` ⇒ Err) is the in-gate
   assertion for the shared constant. Additionally assert the core constant
   equals the wasm-consumed value (re-export makes this structural).
3. **100 KB valid profile still works.** A valid signed profile padded to ~100 KB
   (extra non-validated key with a large string value) passes
   `validate_and_extract_profile` and `extract_entitlements_checked`.
4. **550 KB / 50k-element document pinned as today.** Build an XML plist with 50k
   top-level array elements (fixture built in one `std::fmt::Write` pass over a
   pre-sized String; the failure message reports counts, never Debug-formats the
   document); assert `profile_document` parses it to `Ok` with exactly 50k
   elements (pinning current behavior: no element budget in this change).
5. **Facade variant live — via a real funnel, end to end.** A facade-level signer
   fed an oversized profile file (root `provisioning_profile` AND a
   `bundle_profiles` entry) returns `zsign_rs::Error::InputTooLarge` — not
   `Error::Core` — with the limit bytes in the message; the `--profile-map` case
   additionally names the bundle id and profile path (D8). A synthetic
   `From`-conversion unit test may complement but not replace this.
6. **Context-wrap regression.** A malformed (non-oversized) `--profile-map`
   profile still surfaces as `Error::Core(Config(…))` naming bundle id + path —
   pinning that D8 changed exactly one arm and nothing else.

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
