# Design: Provisioning-Profile Error Unification (ZSN-143)

Status: final (cold-reviewed before implementation; whole-branch reviewed)
Base: main @ a77ca09 (ZSN-118 validation + `allow_unsafe_profile`, ZSN-123 `InputTooLarge` all landed)

## 1. Problem

The same operator mistake (a missing or invalid `-m/--profile` / `--profile-map`
entry) reports differently depending on which entry point loads the profile.
Verified against the current worktree (ticket line numbers drifted across
ZSN-118/ZSN-123; the table below is source-of-truth):

| Entry point | Site | Missing file | Malformed profile |
|---|---|---|---|
| `ZSign::sign_macho` | `crates/zsign/src/builder.rs:656-681` `load_entitlements_from_profile` | `Error::Io` **with path** (`:658-666`) → `ZSIGN_SIGNING_FAILED` | bare `?` (`:674-680`): `Verification` → `ZSIGN_VERIFICATION`, `ProvisioningProfile` → `ZSIGN_INVALID_PROFILE`, `InputTooLarge` → `ZSIGN_INPUT_TOO_LARGE` |
| `ZSign::sign_ipa` / `sign_bundle` (root, path) | `crates/zsign/src/ipa/mod.rs:702-712` `load_profile` `Path` arm | bare `fs::read(path)?` (`:705`) — **no path in message** → `ZSIGN_SIGNING_FAILED` | bare `?` → same classes as above |
| `sign_ipa`/`sign_bundle` (root, bytes; wasm `sign_ipa`) | `ipa/mod.rs:714-721` `Bytes` arm | n/a | bare `?` → same classes |
| `--profile-map` nested entry | `ipa/mod.rs:730-786` `load_bundle_profiles` | `Error::Io` with id+path (`:753-761`) → `ZSIGN_SIGNING_FAILED` | `Core(Config)` rewrap (`:777-781`) → **`ZSIGN_CONFIG`**, except `InputTooLarge` (`:772-776`) |
| wasm ctor / `extract_entitlements` (bytes) | `crates/zsign-wasm/src/lib.rs:754-767`, `:515-519` | n/a | direct `core_err` → per-variant code |

Two defects:

1. **Message**: 1 of 3 file-reading sites names no path (`load_profile` root);
   root validation errors name no file at all.
2. **Class**: a nested map entry whose profile fails validation is reclassified
   from its real class (`ProvisioningProfile`/`Verification`) into
   `Error::Core(Config)` → `ZSIGN_CONFIG`, while the identical root-profile
   failure keeps its real class. One mistake, divergent stable codes.

Validation-failure surface of `zsign_core` (provisioning.rs:103-111 and every
return path): only `InputTooLarge`, `Verification` (CMS envelope / wasm
no-clock), and `ProvisioningProfile` (every failed check, including raw-scan
plist failures). `Error::Plist` and `Error::Config` are **not reachable** from
`extract_entitlements_checked` / `validate_and_extract_profile` /
`extract_entitlements_from_profile` / `profile_document`.

## 2. Decision

**Canonical classes — Option A, preserve-variant with source context:**

- **Missing/unreadable profile file** → facade `Error::Io`, message always
  names the source (`failed to read provisioning profile '<path>': …`,
  nested: `… for bundle '<id>' at '<path>': …`). Stable code
  `ZSIGN_SIGNING_FAILED` — unchanged; it is the facade's universal file-read
  class and was already consistent across all sites (only the message was
  defective). The 2026-09-26 option-forwarding design already chose `Io` over
  `ProvisioningProfile` for missing files; that decision stands.
- **Profile validation failure** → the core variant is **preserved** and the
  source context is **appended to its message payload**:
  - `Verification` → stays `Error::Core(Verification)` → `ZSIGN_VERIFICATION`
    (keeps ZSN-118 deviation #8 / D8: CMS-less profiles fail as
    verification failures on every surface, wasm ctor included);
  - `ProvisioningProfile` → stays `Error::Core(ProvisioningProfile)` →
    `ZSIGN_INVALID_PROFILE`;
  - `InputTooLarge` → facade `Error::InputTooLarge("{detail} ({source})")` —
    single `Input too large:` prefix, detail-only payload (ZSN-123 D3/D4
    convention), suffix format for map entries identical to today;
  - any other core variant (not currently reachable) passes through as
    `Error::Core(other)` unchanged — appending context is opt-in per variant:
    `ProvisioningProfile`, `Verification` and `InputTooLarge` opt in, every
    other variant is forwarded verbatim as the safe default, so a future
    reachable variant is never silently reclassified or reworded.
- **Bytes sources** (wasm ctor, `BlobSource::Bytes`) get no appended context:
  there is no file to name and the root profile is unique; their behavior is
  unchanged today and stays unchanged.

**Candidates weighed:**

- (b) per-call-site `map_err` blocks — the status quo; three hand-rolled
  copies that drifted apart. Rejected: this is the bug.
- (c) dedicated `ProfileLoadError` mapped once at the facade boundary —
  rejected: a new published enum, wasm mapper churn, and migrations of the
  D8 pins, for no behavioral gain over (A).
- collapsing all validation failures (incl. CMS) into `ProvisioningProfile` —
  rejected: flips ZSN-118's D8 (`ZSIGN_VERIFICATION` → `ZSIGN_INVALID_PROFILE`
  on the wasm ctor), erases the signature-vs-fields distinction, and forces
  wasm-mapper and doc-table edits.

**Why each old code moves (or does not):**

| Old | New | Reason |
|---|---|---|
| nested validation → `ZSIGN_CONFIG` | `ZSIGN_INVALID_PROFILE` / `ZSIGN_VERIFICATION` (per failure kind) | `Config` misreported profile-content failures as signing-configuration errors. `Config` stays for real configuration rejections (map-key validation, entitlements dir, unused keys). |
| missing file → `ZSIGN_SIGNING_FAILED` | unchanged | Already consistent everywhere; only the message lacked paths. |
| root malformed → `ZSIGN_INVALID_PROFILE` / `ZSIGN_VERIFICATION` | unchanged | Already the canonical classes; now also carry the file path in the message. |
| `InputTooLarge` → `ZSIGN_INPUT_TOO_LARGE` | unchanged | ZSN-123 contract, prefix and suffix format preserved exactly. |
| wasm codes overall | **zero wasm-visible change** | `--profile-map` and path-backed profile reads are unreachable on wasm (no `bundle_profiles` setter, `sign_ipa` takes bytes); wasm root failures already surface per-variant. |

## 3. Helper API

One host module: `crates/zsign/src/builder.rs`, beside the existing shared
helpers (`read_entitlements_file`, `entitlements_read_error`,
`validate_entitlements_blob`). `ipa/mod.rs` calls them fully-qualified as
`crate::builder::…`, the existing convention (no `use` lines).

```rust
/// Source label for error messages:
/// `provisioning profile '<path>'` or
/// `provisioning profile for bundle '<id>' at '<path>'`.
fn profile_source(path: &Path, bundle_id: Option<&str>) -> String;

/// Reads profile bytes; every failure names the source:
/// `failed to read {source}: {e}` as `Error::Io` (io kind preserved).
pub(crate) fn read_profile_file(path: &Path, bundle_id: Option<&str>) -> Result<Vec<u8>, Error>;

/// Attaches `({source})` to a validation failure WITHOUT changing its class:
/// `ProvisioningProfile`/`Verification` payloads get the suffix appended;
/// `InputTooLarge` gets `{detail} ({source})` as the facade payload;
/// anything else passes through as `Error::Core(other)` unchanged.
pub(crate) fn profile_validation_error(
    e: zsign_core::Error,
    path: &Path,
    bundle_id: Option<&str>,
) -> Error;
```

Resulting messages (substring pins survive):
- root read: `IO error: failed to read provisioning profile '<path>': No such file…`
- nested read: `IO error: failed to read provisioning profile for bundle '<id>' at '<path>': …`
- root validation: `Verification failed: <detail> (provisioning profile '<path>')`
- nested validation: `<detail> (provisioning profile for bundle '<id>' at '<path>')`
- nested oversize: `Input too large: <detail> (provisioning profile for bundle '<id>' at '<path>')`

## 4. Sites rewired

1. `builder.rs` `load_entitlements_from_profile` — read via
   `read_profile_file(path, None)`; validation via
   `profile_validation_error(e, path, None)`.
2. `ipa/mod.rs` `load_profile` `Path` arm — same with `None`.
3. `ipa/mod.rs` `load_profile` `Bytes` arm — unchanged.
4. `ipa/mod.rs` `load_bundle_profiles` — read via
   `read_profile_file(path, Some(id))`; validation via
   `profile_validation_error(e, path, Some(id))`; the `Core(Config)` rewrap
   and the inline `InputTooLarge` arm are deleted. Map-key rejections
   (`invalid bundle id`, root-id key, duplicate key) stay `Core(Config)`.
5. The justification comment above the old wrap (`ipa/mod.rs:761-764`) is
   rewritten: context is now added *by preserving the class*, not by
   rewrapping.
6. **No changes**: `crates/zsign/src/error.rs` (no new variant),
   `crates/zsign-wasm/src/lib.rs` `code_for_zsign_error`/`code_for_core_error`
   (still exhaustive; `Config` arm still used by real config errors), the
   wasm doc table (its `sign_ipa` row already promises
   `ZSIGN_VERIFICATION`/`ZSIGN_INVALID_PROFILE` for profile validation),
   CLI exit codes and `--json` schema (no `code` field; failures are
   `status` + `error` text, exit 1).

## 5. Contract impact

- **wasm stable codes**: unchanged — no doc-table row moves.
- **native enum**: nested validation failures change
  `Error::Core(Config(_))` → `Error::Core(ProvisioningProfile(_))` /
  `Error::Core(Verification(_))`. Pre-1.0 breaking = minor bump per the
  repo's own rule; the only in-repo pin is
  `ipa/mod.rs:4133 malformed_profile_map_entry_keeps_the_config_shape`,
  migrated in Task 1. The ZSN-123 spec sentence "other errors from that site
  keep their `Config` shape" is a point-in-time record of that lane — landed
  specs are not edited; this design supersedes that sentence and is linked
  from the plan.
- **CLI**: exit codes 0/1/2 and the JSON envelope are derived from mode, not
  variant — unchanged. Profile error messages keep the substrings the CLI
  tests pin (`absent.mobileprovision`, `provisioning profile`,
  `Verification failed`).
- **Messages are not a contract** (README: "match on the code, never the
  message"); message changes are safe, but existing substring pins must keep
  passing.

## 6. Invariants (must not regress)

- **Fail-closed posture (ZSN-118)**: every validation still rejects; the
  forgery/expiry/team/App-ID pins keep passing unmodified in class.
- **ZSN-123**: `Error::InputTooLarge` variant, single `Input too large:`
  prefix, and the map-entry suffix format `{detail} (provisioning profile for
  bundle '<id>' at '<path>')`.
- Zero-warning gate; no ticket IDs in code comments; no `println!`/`eprintln!`
  in `src/`; no placeholders.

## 7. Test matrix (regression scope for Task 1)

Native (class + message; the wasm mapper is exhaustive by construction):

| # | Entry | Input | Assert |
|---|---|---|---|
| N1 | `ZSign::sign_macho` | missing path | `Error::Io(_)`; msg contains `provisioning profile` + path — facade-level pin added (plan Task 1 Step 6); CLI pin `missing_profile_error_names_the_file` covers end-to-end |
| N2 | `ZSign::sign_macho` | CMS-less profile | `Core(Verification(_))`; msg contains the file name — new pin beside the existing `builder.rs:1939` class pin (plan Task 1 Step 5) |
| N3 | `sign_ipa`/`sign_bundle` root, path | missing path | `Error::Io(_)`; msg contains `provisioning profile` + path — **red today** |
| N4 | root, path | forged/CMS-less profile | `Core(Verification(_))`; msg contains path — **red for path** |
| N5 | `--profile-map` | missing path | `Error::Io(_)`; msg contains id + path (exists, `ipa/mod.rs:4196`) |
| N6 | `--profile-map` | malformed entry | `Core(ProvisioningProfile(_))` or `Core(Verification(_))`; msg contains id + path — **red today (Config)** |
| N7 | `--profile-map` | oversized entry | `Error::InputTooLarge`; single `Input too large:` prefix; suffix format (exists; prefix count added) |
| R1–R3 | ZSN-118 pins | forgery/expired/wrong-team | classes unchanged (existing tests must pass untouched) |
| R4 | valid profile | signs | existing happy-path tests |

wasm (code pins): ctor CMS-less → `ZSIGN_VERIFICATION` (exists), ctor
raw-scan non-dictionary profile under `allow_unsafe` → `ZSIGN_INVALID_PROFILE`
(new), plus existing bypass controls. Cells with no file-backed API on wasm
(root path read, profile-map) are `N/A` on wasm by reachability — recorded,
not fabricated.

## 8. Non-goals

ZSN-98 (`crypto/*`), wasm `p12_err` (ZSN-230), `verify.rs`, Mach-O parsing,
CLI flags, README, `scripts/`+`.github/`, entitlements read helpers,
`dir_hit`, entitlements-dir and map-key `Config` errors.
