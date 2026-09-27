# Provisioning-Profile Validation Wiring — Design

Ticket: ZSN-118 · Date: 2026-09-28 · Branch: `zsn-118-profile-validator`
Status: final (post research; cold-reviewed before implementation)

## 1. Problem

`validate_and_extract_profile` (crates/zsign-core/src/provisioning.rs:93) implements a
complete fail-closed defense — CMS chain verification against Apple roots, creation/expiration
window, team match, App-ID coverage (incl. wildcard) — and has **zero production callers**.
Every consumer routes through `extract_entitlements_from_profile` (provisioning.rs:385), a raw
byte scan that trusts whatever it finds:

| # | Site | File |
|---|------|------|
| 1 | `ZSign::load_entitlements_from_profile` (sign_macho path) | crates/zsign/src/builder.rs:647 |
| 2 | `IpaSigner::load_profile` Path arm | crates/zsign/src/ipa/mod.rs:646 |
| 3 | `IpaSigner::load_profile` Bytes arm | crates/zsign/src/ipa/mod.rs:650 |
| 4 | `IpaSigner::load_bundle_profiles` per-entry | crates/zsign/src/ipa/mod.rs:696 |
| 5 | `WasmSigner::new` constructor | crates/zsign-wasm/src/lib.rs:261 |
| 6 | `WasmSigner::extract_entitlements` static | crates/zsign-wasm/src/lib.rs:485 |

Observed today: a profile with no CMS envelope, team `EVILTEAM`, application-identifier for a
different app, `ExpirationDate` 2001-01-02, `get-task-allow: true`,
`keychain-access-groups: *` is accepted and signed in; its bytes are embedded verbatim.

## 2. Research findings that constrain the design

- **Root id ordering**: `root_id_final` is computed at crates/zsign/src/ipa/mod.rs:847-850
  strictly before `load_profile()` (:878) and `load_bundle_profiles(&root_id_final)` (:885),
  both inside the read-only plan-build phase. Every native site can pass the post-rewrite
  target id without reordering.
- **Team id source**: `SigningCredentials.team_id: Option<String>` (crates/zsign-core/src/crypto/cert.rs:116-120,
  subject OU) — public field, available at every credential-holding site.
- **wasm clock**: `cms_verify::resolve_now` (crates/zsign-core/src/crypto/cms_verify.rs:1684-1700)
  hard-errors on wasm32 when `now` is `None`, with the message "pass Date.now() / 1000".
  `js-sys` is a direct dependency of zsign-wasm (Cargo.toml:19); `js_sys::Date` is used nowhere
  yet. zsign-core alone resolves `time` without the wasm-bindgen feature — core must not take a
  wasm wall clock (crypto-5's lane; untouched here).
- **Wasm bundle id**: the `WasmSigner` constructor has credentials + profile bytes but no
  Info.plist; on the wasm IPA path the facade's plan build re-validates with `root_id_final`.
- **CMS**: `provisioning.rs` already reuses `cms_verify::{resolve_now, verify_cms_envelope,
  verify_cms_envelope_with_anchors}` (provisioning.rs:9, :97-103) with
  `ProfileRequest.anchors` as the injection hook. No second anchoring implementation exists or
  will be added (couples to ZSN-96, lane 1 — we only call what is there).
- **Fixtures**: every in-tree profile fixture feeding sites 1-6 is a bare XML plist with no CMS
  envelope and no `Name` key (≈25 facade tests + 3 wasm tests). Real-CMS fixture generation
  exists only inside zsign-core's `#[cfg(test)]` module (`signed_profile` +
  `cms::sign_attached_content`) and is unreachable from sibling crates; `crypto/cms.rs` is
  lane-1-owned and MUST NOT be touched.
- **Injection precedent** (1b99239-era, current home): `TrustAnchors::from_certificates` +
  `verify_*_with_anchors` + `ProfileRequest.anchors` — a public API, never `cfg(test)`, never a
  bypass flag; per-crate dual-pin helpers pair "production path is gated" with "injected-anchor
  path is valid".

## 3. Candidate designs (brainstorm record)

- **(a) Validate inside the `load_*` helpers** — one choke point per surface; all callers fixed
  at once. Gap: wasm constructor has no bundle id for the App-ID check.
- **(b) Validate at plan-build time with the post-rewrite root id everywhere** — correctest
  target id, but the wasm constructor freezes entitlements at construction (contract change,
  existing `constructor_rejects_bad_profile` test pins construction-time failure) and deferring
  would weaken fail-fast.
- **(c) A validated wrapper around the extractor with a typed policy seam** — single shared
  function every site calls; the bypass becomes one explicit argument instead of six ad-hoc
  `match` blocks.

**Chosen: (a) + (c) combined.** Validation runs inside the `load_*` helpers (they are the
choke points and all inputs are reachable there), and all six sites call ONE new core seam
function so the bypass policy is written down exactly once. The wasm constructor validates the
context it has (CMS + window + team) and the wasm IPA path gets full App-ID coverage from the
facade plan build. Candidate (b)'s post-rewrite id is still used wherever the id is known.

## 4. Decisions

### D1 — Core seam (provisioning.rs)

```rust
pub fn extract_entitlements_checked(
    profile_data: &[u8],
    request: &ProfileRequest,
    allow_unsafe: bool,
) -> Result<Option<Vec<u8>>>
```

- `allow_unsafe == false` (the default everywhere): `validate_and_extract_profile`, returning
  `ProfileInfo.entitlements_xml`.
- `allow_unsafe == true`: the historical raw extractor, byte-for-byte.

All six production sites switch to this function. The module docs at provisioning.rs:17-19 are
rewritten to describe the flag instead of gesturing at "keep calling the extractor".
`extract_entitlements_from_profile` stays public (its own unit tests and the fuzz target pin
its behavior); nothing else in production calls it directly.

### D2 — Request built at each site

| Site | `now` | `anchors` | `expected_team_id` | `target_bundle_id` |
|---|---|---|---|---|
| builder loader (sign_macho) | `None` (native wall clock) | `None` (Apple root) | `credentials.team_id` | `self.bundle_id` — `None` skips (file-stem fallback is not a bundle id) |
| `load_profile(root_id)` | `self.profile_now` (`None` → wall clock on native) | `self.profile_anchors` | `credentials.and_then(team_id)` | `Some(root_id)` — post-rewrite |
| `load_bundle_profiles` | same | same | same | `Some(entry id)` (the map key is the target id) |
| wasm constructor | `host_now()` (D6) | `None` | `credentials.team_id` | `None` — not knowable at construction |
| wasm static `extract_entitlements` | `host_now()` | `None` | `None` — static, no credentials | `None` |

`target_device_udid` stays `None` everywhere — no source exists on any surface (no CLI flag,
no wasm input); the device check remains skipped by design, not by accident.

### D3 — Ad-hoc + profile

`expected_team_id: None` skips **only** the team check; CMS, window, and App-ID coverage still
enforce. Rationale: `ProfileRequest` already documents per-field semantics ("an omitted check
simply does not run"), the CLI forbids `-a` with `--profile` (main.rs:130-131), and a profile
without a certificate still must be Apple-signed, in-window, and cover its target id.

### D4 — The bypass flag (the module docs' missing "allow-unsafe")

- `IpaSigner::allow_unsafe_profile(bool)` and `ZSign::allow_unsafe_profile(bool)` — builder
  setters, default `false`; ZSign forwards to the `IpaSigner` it constructs (builder.rs:509-521,
  :578-587) and uses it in its own `load_entitlements_from_profile`.
- wasm: constructor gains a 4th parameter `allow_unsafe_profile: Option<bool>` (wasm-bindgen
  makes trailing `Option` optional at the JS call site — `examples/web` needs no change);
  the static `extract_entitlements` gains the same parameter. The flag also forwards to the
  facade `IpaSigner` built for `sign_ipa`.
- CLI: `--allow-unsafe-profile` → `ZSign::allow_unsafe_profile(true)`.

Every surface can therefore set the bypass; none can set it implicitly.

### D5 — Ad-hoc / fixture / test policy

Fixtures stay bare XML (generating cross-crate CMS fixtures would require touching lane-1
`crypto/cms.rs`, which is forbidden). Existing fixture-driven tests opt in explicitly with
`.allow_unsafe_profile(true)` / the wasm constructor parameter — the brief sanctions "explicit
bypass in fixtures". Validation behavior itself is proven by NEW tests against CMS-signed
fixtures (D7). Production checks are not weakened anywhere.

### D6 — wasm `now`

`host_now()` helper in crates/zsign-wasm/src/lib.rs:

- `wasm32`: `js_sys::Date::now()` (ms) → `OffsetDateTime::from_unix_timestamp_nanos(ms·1e6)`;
  conversion failure yields `None`, which makes validation error (fail-closed).
- not `wasm32` (native `cargo test -p zsign-wasm`): `None` → `resolve_now` uses the wall clock.

This follows the existing `resolve_now` contract — the caller passes an explicit instant on
wasm32 — instead of fixing the core clock (crypto-5, lane 1). The wasm IPA path forwards the
same instant through a new `IpaSigner::profile_now(OffsetDateTime)` setter, because the facade
plan build re-validates on wasm32 where `now: None` errors.

### D7 — Regression fixtures (generated once, embedded)

A throwaway generator (a temporary test in provisioning.rs, reusing its `signed_profile`
machinery with custom plists and cert validity 2020→2099) produces, on first implementation run:

- `VALID` — `TESTTEAM.com.test.app`, `ExpirationDate` 2099, CMS-signed by a fresh RSA test root;
- `EXPIRED` — same, `ExpirationDate` 2001-01-02 (window gate);
- `WRONG_TEAM` — team `EVILTEAM` (team gate);
- `WRONG_APP` — `TESTTEAM.com.other.app` vs target `com.test.app` (App-ID gate);
- the test root certificate (DER) for `TrustAnchors::from_certificates`.

The base64 strings are embedded as consts in the facade ipa tests; the generator is deleted in
the same commit. Tests inject anchors via the new `IpaSigner::profile_anchors(TrustAnchors)`
(public API — the 1b99239 dual-pin precedent, never `cfg(test)`). The brief's forgery (no CMS
+ expired + wrong team + wrong app-id + `get-task-allow`) is a bare-XML const shared by the
native and wasm error tests.

### D8 — Error shapes (no unification)

Gate order is untouched: missing/broken CMS → `Error::Verification` → wasm `ZSIGN_VERIFICATION`;
field failures → `Error::ProvisioningProfile` → `ZSIGN_INVALID_PROFILE`. The existing wasm test
pinning `ZSIGN_INVALID_PROFILE` for a CMS-less profile moves to `ZSIGN_VERIFICATION` (that is
honestly what the core returns; facade-16 owns later unification). `load_bundle_profiles`
keeps its existing `Config` wrapper naming bundle id + path.

## 5. Scope fences and couplings (recorded, not acted on)

- **ZSN-96 (lane 1, `crypto/{cert,assets,cms}.rs`)**: untouched. This wiring calls only
  `provisioning.rs`'s existing `cms_verify` entry points; `ProfileRequest.anchors` already
  accepts injected roots. No second anchoring implementation.
- **crypto-5 (wasm clock)**: untouched; D6 passes an explicit instant instead.
- **facade-16 / bundle-6**: no error-code unification; the 16 MiB profile cap stays wasm-side
  exactly where it is (`MAX_PROFILE_BYTES`, zsign-wasm:58, enforced :250 and :478). The core
  seam in D1 is the single choke point where a future native cap would belong — noted here so
  bundle-6 does not reintroduce per-site reads.
- **verify.rs / Mach-O / docs**: Wave 2/3/8, untouched. Inline doc comments on changed items
  are updated in place; no README/changelog edits.
- **`scripts/verify-apple-interop.sh:149-158`** writes a bare-plist profile and signs with
  `-m`; it gains `--allow-unsafe-profile` (macOS-only script, not runnable on this host).
- **`profile_document` metadata readers** (ipa/mod.rs:191, :237) do not switch — they read
  fields for distribution-shape decisions alongside bytes that are themselves validated at load.

## 6. Acceptance (observable)

1. Native: sign with the forgery profile errors (ipa plan build and ZSign sign_macho); the
   same bytes with the explicit bypass succeed; a CMS-valid profile signs successfully with
   injected anchors; expired / wrong-team / wrong-app profiles each error naming their gate.
2. wasm: `WasmSigner::new` and `WasmSigner::extract_entitlements` reject the forgery with
   `ZSIGN_VERIFICATION` and accept it only with the explicit `allow_unsafe_profile` opt-in.
3. CLI: forged profile → non-zero exit via the facade error; `--allow-unsafe-profile` parses
   and is wired.
4. All pre-existing tests green under explicit bypass or unchanged behavior; zero-warning gate
   (`cargo fmt --check`, `clippy -D warnings`, `cargo test --workspace` with in-worktree TMPDIR).
