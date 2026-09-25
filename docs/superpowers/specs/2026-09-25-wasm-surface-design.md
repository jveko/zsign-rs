# ZSN-40 — WASM signing surface hardening: design

Date: 2026-09-25 · Lane: ZSN-40 · Branch: `zsn40-wasm` · Base: main `c9ff0fb`
Scope (brief-won): `crates/zsign-wasm/src/lib.rs` + its tests ONLY.

## 0. Problem statement

The browser-facing signing surface is unsafe in five ways and untested in one:

1. `sign_macho` always routes through `sign_any_macho`, so every signed binary
   carries dual SHA-1+SHA-256 code directories, contradicting the project's
   SHA-256-only default.
2. Entitlements can only come from a provisioning profile at construction time;
   browser callers cannot override them.
3. Every byte input from JS is unbounded (`Vec<u8>`/`&[u8>`), so a hostile or
   buggy page can push the wasm32 linear memory into an abort.
4. `hash_file_chunk` silently corrupts when a path is reused after finalize:
   the shared state is removed, later chunks seed a fresh digest, and the
   resulting CodeResources entry hashes only part of the content.
5. Every error collapses to `JsError(to_string)`; JS cannot distinguish a wrong
   password from a malformed Mach-O without string-matching messages.
6. The crate has zero tests, so ZSN-31's `wasm-pack test --node` CI job passes
   vacuously.

## 1. Evidence base (research, all cited)

- `crates/zsign-wasm/src/lib.rs` is 244 lines; 14 exported members; 12
  `JsError::new` sites (lines 65, 69, 142, 150, 161, 167, 188, 199, 220, 224,
  238, 240), 10 of them pure `Display` text; zero size checks anywhere.
  `sign_macho` body: lib.rs:180-200; the trailing `false` at lib.rs:197 is
  `sign_any_macho`'s `allow_encrypted` (signer.rs:165), **not** a hash flag.
- Core signing entry points (`crates/zsign-core/src/macho/signer.rs`):
  - `sign_any_macho` (158-166): thin → `sign_macho` (dual), FAT →
    `sign_macho_all_slices` (dual per slice) + `embed_signature_fat`. No hash
    parameter exists on it.
  - `sign_macho_sha256_only` (320-347): pub, re-exported at macho/mod.rs:19,
    emits SHA-256 CodeDirectory only; rejects multi-slice (329-333) —
    **thin-only**. FAT SHA-256-only = ZSN-33 (not this lane).
  - `sign_macho_adhoc` (290-316): thin-only, dual, no credentials.
  - `sign_slice_complete(..., sha256_only)` (410-417): when true, skips the
    SHA-1 CD (479-487), signs the SHA-256 CD (515), omits the SHA-1 entry
    from the CDHash v1 attribute (519-523 — the attribute itself is still
    emitted with a single truncated-SHA-256 entry, cms_verify.rs:897-900),
    omits the legacy SHA-1 slot (536-538).
- Entitlements selection: `sign_any_macho` passes `EMPTY_ENTITLEMENTS` for
  non-executables (signer.rs:167-177); `SigningContext::new` builds the
  entitlements blob from **any** `Some` but only the DER blob behind
  `is_executable` (signer.rs:85-97). Therefore a thin SHA-256-only path that
  calls `sign_macho_sha256_only` directly MUST replicate the
  executable/non-executable selection itself, or dylibs would be signed with
  profile entitlements. `ArchSlice.is_executable` is pub (parser.rs:105) and
  `EMPTY_ENTITLEMENTS` is re-exported (macho/mod.rs:21).
- Sole in-repo JS consumer: `examples/web/src/main.js`.
  - `sign_macho_fat` at :341 (thin dylibs) and :394 (main executable, thin or
    FAT); catches read `e.message` only and keep the **unsigned** original.
    → `sign_macho_fat` MUST keep accepting thin inputs; making it strict would
    silently ship unsigned files.
  - `hash_file` at :367 (every bundle resource), bool discarded, **no
    per-call catch** → a new throw aborts the whole run via :538.
  - `hash_file_chunk`, `sign_macho`, `parse_macho`, `add_symlink`,
    `reset_resources`, `extract_entitlements`: never called in-repo.
  - All error handling reads `e.message` or ignores the object → adding a
    `.code` property with unchanged message text is impact-free.
- `CodeResourcesBuilder::add_file` (code_resources.rs:327-345): exclude-gate
  then `BTreeMap::insert`, duplicate paths silently overwrite (last wins),
  returns `false` only for excluded paths (main executable, `_CodeSignature`,
  exclusions).
- Credentials/fixtures:
  - PKCS#12 creation has no Rust API anywhere; the only p12 creation in-repo
    is openssl invocations in `scripts/verify-apple-interop.sh` (CI runtime,
    never committed). `from_p12` is decode-only and performs no
    validity/clock check (cert.rs:202).
  - 9 throwaway p12 fixtures are git-**tracked** under
    `crates/zsign-core/src/crypto/fixtures/`, but their cert is
    `CN=zsign-test-fixture`, `CA:TRUE`, **no EKU** — not Leaf-shaped, so they
    cannot pass strict leaf-purpose verification. Fine for constructor tests,
    wrong for anchored round-trip verify.
  - The fixture-reality round-trip recipe (crates/zsign/src/verify.rs:955-1011):
    `Profile::Leaf` + `ExtendedKeyUsage(1.3.6.1.5.5.7.3.3)` self-issued cert →
    sign → `zsign_core::codesign::verify::parse_superblob` (pub) →
    `verify_code_signature_with_anchors(..., TrustAnchors::from_certificates(
    vec![creds.certificate.clone()]))` (cms_verify.rs:295, 330). All pub.
    Caveat verified against the signer: that helper's `cd_sha1=None` argument
    is only correct for SHA-256-only output (which zsign's own tests sign —
    macho/verify.rs:352-355). Dual output has a SHA-1 primary in slot 0
    (CMS-signed) and a SHA-256 alternate (superblob.rs:37-41, 544-557; the CMS
    content is the primary — signer.rs:515), and its CDHash-v1 attribute
    carries `[sha1, truncated-sha256]`, so verification must pass the SHA-1
    digest of the SHA-1 CD and the SHA-256 digest of the SHA-256 CD
    (cms_verify.rs:897-900; signer.rs:508-526). The lane's test helper derives
    both from `is_sha1()` slot classification (§ Fixture strategy), correct for
    both layouts.
  - All existing in-crate credential builders are `#[cfg(test)]`-private;
    `x509-cert`'s `builder` feature is only enabled in other crates'
    dev-deps. Generating credentials at test runtime would need new dev-deps
    on zsign-wasm (out of scope) and `Validity::from_now` panics on wasm32.
- Clocks: the SIGN path has no wall-clock call anywhere (cms 0.2.3's
  `create_signing_time_attribute` is never called by zsign; signed attributes
  are CDHash v1/v2 only; `from_p12` is clock-free). VERIFY uses
  `time_now()` with a wasm shim: fixed epoch `1_800_000_000` ≈ 2027-01-15
  (cms_verify.rs:1354-1365, owned by ZSN-3 — not touched by this lane).
  Consequence: wasm round-trip verify works if the test certificate's validity
  covers **both** real now and 2027-01-15.
- wasm-bindgen contracts (source-verified, versions from Cargo.lock:
  wasm-bindgen 0.2.128, wasm-bindgen-test 0.3.78, js-sys 0.3.105):
  - `#[wasm_bindgen_test]` is not registered under native `cargo test`: the
    macro's runner export is `#[cfg(target_family = "wasm")]`, so the
    function body still compiles (under `allow(dead_code)`) but never runs
    natively; with
    `unsupported = test` the SAME function also becomes a real native `#[test]`
    (wasm-bindgen-test-macro:146-147, guide usage.md:32-36). Tests must live
    at crate root or in a `pub mod` (guide usage.md:42-43).
  - On native targets, every JS import is a generated stub that **panics at
    call** (`JsError::new`, `js_sys::Error::new`, `Reflect::set`,
    `JsValue::from` — codegen.rs:5263-5286). Linking succeeds; only executed
    JS-touching paths panic.
  - Throwing `Err(JsValue)` re-throws that exact object (binding.rs:1520-1533):
    a `js_sys::Error` with a `Reflect::set` `code` property survives in Node
    as a real `Error` with `.message`, `.stack`, `.code`.
  - `#[wasm_bindgen]` enums export NUMBERS; Node's documented convention is a
    string `error.code` (Node errors doc: "error.code is the most stable way
    to identify an error"). `examples/web` reads `.message` only.
  - `wasm-pack test --node crates/zsign-wasm` is the CI command
    (ci.yml:96, no `--release`); `--node` is required; extra args pass
    through after `--` (e.g. `-- --nocapture`). Local wasm-pack 0.13.1 lives
    at `~/.local/bin/wasm-pack` (not on PATH); wasm32-unknown-unknown target
    installed; wasm-bindgen CLI cached; node v26.
- Test assets: `crates/zsign/src/ipa/fixtures/minimal_macho.bin` is tracked,
  8192 bytes, thin arm64 `MH_EXECUTE` (magic `cffaedfe`, filetype 2). No FAT
  fixture exists in the repo.

## 2. Decisions per queue item

Each item lists candidates, the pick, and why the others lost. Rejected
alternatives are recorded here permanently.

### Item 1 — SHA-256-only default for `sign_macho`

Candidates:

- **A (picked): default = SHA-256-only for thin inputs; FAT input rejected
  with an actionable error; `sign_macho_fat` remains the explicit dual opt-in.**
- B: FAT falls back to dual signing and reports a JS-visible warning field.
  Rejected: the success type of `sign_macho` is `Uint8Array` — adding a warning
  field means changing the return shape, breaking every caller, and a warning
  on a signing result is easy to miss. Fail-closed beats warn-and-continue.
- C: add an options object (`{ hashes: 'sha256' | 'dual' }`) as a new
  parameter. Rejected: changes the positional signature (breaks callers anyway)
  for two behaviors that map cleanly onto two existing methods.

Behavior after the change:

- `sign_macho(data, ...)`:
  1. size guard (item 3);
  2. `MachOFile::parse`;
  3. if `slices().len() > 1` → throw `ZSIGN_FAT_UNSUPPORTED` telling the caller
     to use `sign_macho_fat(...)` to opt into dual hashing explicitly (FAT
     SHA-256-only arrives with per-slice signing, owned by another lane);
  4. executable selection replicated from `sign_any_macho`:
     `ent = if first_slice.is_executable { self.effective_entitlements() }
     else { Some(EMPTY_ENTITLEMENTS) }`;
  5. `sign_macho_sha256_only(&macho, identifier, ent, &self.credentials,
     info_plist, code_resources, false)` — it performs its own
     `reject_encrypted(allow_encrypted=false)`.
- `sign_macho_fat(data, ...)`: no longer delegates to `sign_macho`; calls
  `sign_any_macho` directly with the same arguments as today's body (size
  guard first). Net behavior **unchanged**: dual SHA-1+SHA-256, thin or FAT.
  This is what `examples/web` (:341, :394) and both READMEs rely on.
- Doc comments on both methods and the crate-level bullet are rewritten to
  state the hash algorithms each method emits.

Dependency recorded: FAT SHA-256-only signing (`sign_macho_all_slices` with a
hash flag + reassembly) is ZSN-33 in zsign-core `signer.rs` — not this lane.
When it lands, step 3 above can be replaced by the per-slice call.

### Item 2 — validated entitlements setter

Candidates:

- **A (picked): `set_entitlements(data: Option<Vec<u8>>) -> Result<()>`.**
  `Some(bytes)` = validated override: (a) size ≤ plist limit — oversize fails
  the item-3 guard with `ZSIGN_INPUT_TOO_LARGE` (not this setter's code);
  (b) parses as a plist dictionary; (c) is DER-encodable by the signer —
  the setter runs `zsign_core::codesign::der::plist_to_der` (pub, der.rs:230)
  so types the signer's encoder refuses at signing time (Data/Date/Real,
  der.rs:176-188) are rejected up front with `ZSIGN_INVALID_ENTITLEMENTS`
  instead of failing later under a different code. `None` = clear the
  override so the profile-derived value applies again.
- B: setter replaces a single stored field wholesale. Rejected: clearing loses
  the profile-derived value forever, breaking the documented fallback.
- C: two methods (`set_entitlements(&[u8])` + `clear_entitlements()`).
  Rejected: same expressiveness as A with a larger surface.

Shape:

- Field `entitlements: Option<Vec<u8>>` splits into
  `profile_entitlements: Option<Vec<u8>>` (immutable after `new`) and
  `entitlements_override: Option<Vec<u8>>`.
- Private `fn effective_entitlements(&self) -> Option<&[u8]>` =
  `override.as_deref().or(profile_entitlements.as_deref())`; the public
  `entitlements()` getter returns it cloned (JS-visible value unchanged when
  no override is set); the sign path borrows it (zero copies).
- Fallback semantics preserved: constructor still derives entitlements from
  the profile; override wins while set; `None` reverts to profile-derived.
- Documented limitation: an override of "explicitly no entitlements" while a
  profile is loaded is not expressible through `None` (it means "clear the
  override"); callers wanting no entitlements construct the signer without
  profile bytes, or set an empty dictionary plist. Recorded as a deliberate
  YAGNI boundary — no third state (Option-of-Option) is added.

### Item 3 — input size guards

Candidates:

- **A (picked): per-surface byte-limit constants, checked as the first
  statement of each method body — before any parse or processing —
  throwing `ZSIGN_INPUT_TOO_LARGE` with surface, actual size, limit, and
  remedy in the message.** Honest boundary note (known items): wasm-bindgen
  copies `Vec<u8>`/`&[u8]` arguments into linear memory *before* the body
  runs, so the guard bounds all processing/retention but not the initial 1×
  boundary copy; an adversarial JS caller handing over a buffer large
  enough to exhaust memory at the boundary still hits a generic allocation
  failure rather than this error. Closing that gap would require accepting
  `Uint8Array`-typed parameters (length check before `.to_vec()`) — a
  public-signature redesign deliberately not taken in this lane.
- B: one global limit for everything. Rejected: cannot justify a Mach-O-sized
  ceiling for plists or a plist-sized ceiling for binaries; the error cannot
  name a remedy.
- C: warnings without refusal. Rejected: the brief requires actionable errors,
  and a warning still lets memory exhaustion happen.

Limits and their justification (checked on every byte-buffer input at the
top of its method body, before parsing/processing — see the boundary note
above for the wasm-bindgen copy caveat):

| Constant | Value | Surfaces | Justification |
|---|---|---|---|
| `MAX_MACHO_BYTES` | 512 MiB | `parse_macho`, `sign_macho`, `sign_macho_fat` | wasm32 address space is 4 GiB; signing peaks at ≈2-3× input (owned input + parsed MachO + signed output + per-slice intermediates for FAT) → ≤ ~1.5 GiB peak. Realistic iOS main binaries ≤ ~300 MiB; larger universal binaries belong to the native CLI (message says so). |
| `MAX_HASH_BYTES` | 128 MiB | `hash_file` (whole buffer), `hash_file_chunk` (per chunk) | The one-shot path holds the caller's JS copy plus one wasm copy (≤ 256 MiB across the boundary); larger single buffers must stream — the error names `hash_file_chunk`. Per-chunk cap keeps streaming honest (a single huge chunk defeats its purpose). Total streamed size is intentionally unbounded. |
| `MAX_PLIST_BYTES` | 16 MiB | `parse_info_plist`, `sign_macho`/`sign_macho_fat` `info_plist` + `code_resources`, `set_entitlements` | Info.plist is typically < 100 KiB; CodeResources for ~10k files ≈ 1.5 MiB; 16 MiB is two orders of magnitude of headroom. |
| `MAX_PROFILE_BYTES` | 16 MiB | constructor `profile_bytes`, `extract_entitlements` | Real `.mobileprovision` files are ≤ ~1 MiB even with embedded chains. |
| `MAX_P12_BYTES` | 4 MiB | constructor `p12_bytes` | Real .p12 files (chain + key) are ≤ ~100 KiB. |

- String inputs (`identifier`, `p12_password`, relative paths, symlink
  targets) are deliberately NOT length-checked: they are not bulk-data paths,
  JS has already materialized them as strings, and bounding them risks
  rejecting legitimate long paths for no memory-pressure benefit. Recorded so
  the omission reads as a decision, not an oversight.
- `ensure_size(len, max, surface, remedy) -> Result<(), JsValue>` private
  helper; each Mach-O surface calls it as its first statement (one uniform
  line per method — no separate parse helper is introduced; the wiring is
  pinned by the per-constant boundary tests and the cheap-surface
  integrations).
- Wiring proof strategy (see §4): exact-boundary unit tests on `ensure_size`
  for every constant + cheap over-limit integration tests on the smallest
  surfaces; a 513 MiB allocation is not made in CI (identical call site,
  covered by unit tests).

### Item 4 — `hash_file_chunk` state machine

Candidates:

- **A (picked): explicit per-round sealing.** `streaming_hashes` (active
  streams) plus a new `finalized_paths: HashSet<String>` (sealed this round).
  Both `hash_file` and `hash_file_chunk` return `Result` and enforce:
  - chunk on a sealed path → `ZSIGN_PATH_ALREADY_FINALIZED`
    ("…call reset_resources() before hashing it again");
  - `hash_file` while the same path has an active stream →
    `ZSIGN_PATH_IN_PROGRESS`;
  - `is_final` with an active state → finalize and seal;
  - `is_final` as the first and only call → legitimate single-chunk stream,
    finalize and seal (preserved behavior);
  - non-final first chunk → open a stream;
  - sealing happens only when `add_file` actually stores the entry: excluded
    paths (main executable, `_CodeSignature`, exclusion rules — the only
    causes of a `false` return, code_resources.rs:334-345) keep their old
    always-false, re-callable no-op behavior and are never sealed;
  - `build_code_resources` keeps its unfinished-stream guard
    (`ZSIGN_UNFINISHED_HASHES`, message unchanged);
  - `reset_resources` clears active streams, sealed paths, and the builder —
    the documented boundary of a "resources round".
- B: split the API into start/chunk/finalize methods. Rejected: breaks the
  existing three-argument API for no gain — the state info already exists.
- C: allow silent re-streaming after finalize (implicitly start a new round).
  Rejected: that is the current silent-corruption bug with extra steps;
  implicit rounds hide caller bugs. Reset must be explicit.

Why `hash_file` joins the machine: it is one of "the same path … interleaved
across independent streams" the brief names. Sealing only the chunk path would
leave `hash_file` clobbering a streamed entry (and vice versa) — one path, one
rule, one round. Undetectable case documented: two non-final chunk streams for
the same path that both start before either finalizes merge into one digest —
the arguments cannot distinguish them; the detectable failure (post-finalize
resurrection) is what this guard closes.

Scope decision: `add_symlink` stays `-> bool` with last-wins duplicate
semantics (pre-existing, outside the named failure class; changing its
signature adds churn without a named bug). Documented in the method doc.

### Item 5 — stable error codes

Candidates:

- **A (picked): every thrown error is a real `js_sys::Error` with an added
  string property `code` (`ZSIGN_*`, SCREAMING_SNAKE); message text unchanged;
  Rust-side `WasmErrorCode` enum + `js_err(code, message) -> JsValue`
  helper; methods switch `Result<T, JsError>` → `Result<T, JsValue>`.**
- B: put the code in `Error.name`. Rejected: `name` is the standard
  type slot (`Error.prototype.name`); overwriting it with a code fights
  `toString()`/logger conventions, and MDN/Node both steer machine matching to
  `code`/`cause`.
- C: a custom `ZsignError` JS class exported from wasm. Rejected: needs class
  registration machinery across the boundary and forces `instanceof` adoption
  on consumers for no extra information — a plain `Error` + `code` is the
  Node-idiomatic contract and keeps `e.message` consumers working.
- D: `#[wasm_bindgen]` string enum exported to JS. Rejected after source
  verification: unit enums export as numbers; string enums require literals on
  every variant and center the TS→Rust direction we never use. The stable
  contract is the documented string table; JS compares literals.

Mechanics (source-verified): `js_sys::Error::new(msg)` +
`Reflect::set(&err, &"code".into(), &code.into())` (default untyped
`Reflect::set` shape, matching the existing call at lib.rs:231) +
`Err(err.into())`. In Node the thrown value keeps `instanceof Error`,
`.message`, `.stack`, and gains an own enumerable `.code`. On native targets
this path panics by design — all code-assertion tests are wasm-only (§4).

The core-error mapping is an exhaustive `match &zsign_core::Error` so a new
core variant fails to compile until categorized:

| `WasmErrorCode` | `code` string | Sources |
|---|---|---|
| `InvalidMachO` | `ZSIGN_INVALID_MACHO` | `Error::MachO`, `Error::Goblin` |
| `EncryptedBinary` | `ZSIGN_ENCRYPTED_BINARY` | `Error::EncryptedBinary` |
| `SigningFailed` | `ZSIGN_SIGNING_FAILED` | `Error::Signing` |
| `InvalidCertificate` | `ZSIGN_INVALID_CERTIFICATE` | `Error::Certificate` |
| `InvalidPassword` | `ZSIGN_INVALID_PASSWORD` | constructor classifier: `from_p12` failures whose message contains a password-layer marker — MAC mismatch or decryption failure (see below) |
| `MissingCredentials` | `ZSIGN_MISSING_CREDENTIALS` | `Error::MissingCredentials` |
| `Config` | `ZSIGN_CONFIG` | `Error::Config` |
| `InvalidProfile` | `ZSIGN_INVALID_PROFILE` | `Error::ProvisioningProfile` |
| `InvalidPlist` | `ZSIGN_INVALID_PLIST` | `Error::Plist`, `parse_info_plist` parse + not-a-dictionary |
| `DerEncoding` | `ZSIGN_DER_ENCODING` | `Error::DerEncoding` |
| `Verification` | `ZSIGN_VERIFICATION` | `Error::Verification` |
| `InputTooLarge` | `ZSIGN_INPUT_TOO_LARGE` | all size guards |
| `InvalidEntitlements` | `ZSIGN_INVALID_ENTITLEMENTS` | `set_entitlements` validation |
| `UnfinishedHashes` | `ZSIGN_UNFINISHED_HASHES` | `build_code_resources` guard |
| `PathAlreadyFinalized` | `ZSIGN_PATH_ALREADY_FINALIZED` | chunk/`hash_file` seal guard |
| `PathInProgress` | `ZSIGN_PATH_IN_PROGRESS` | `hash_file` vs active stream |
| `FatUnsupported` | `ZSIGN_FAT_UNSUPPORTED` | `sign_macho` FAT reject |
| `Internal` | `ZSIGN_INTERNAL` | `Reflect::set` failures on a fresh object (unreachable in practice) |

The full table is documented in the crate-level doc comment of `lib.rs` —
that doc is the public contract; codes only change across major versions.
Existing message texts are preserved verbatim (the brief's requirement);
new guards introduce new messages.

Wrong-password classification (mechanics): `SigningCredentials::from_p12`
wraps every `extract_p12` failure — including the wrong-password MAC
failure — as `Error::Certificate` (cert.rs:203-205), and core never
constructs `Error::InvalidPassword` (error.rs:19-20 has no producer). The
wasm constructor therefore classifies `from_p12` errors before falling back
to the generic mapping, keyed on BOTH password-layer markers:
`invalid PKCS#12 password (MAC mismatch)` (P12Error::Mac's Display,
pkcs12.rs:79 — the standard unencrypted-authSafe flow, proven across all
nine core fixtures) and `PKCS#12 decryption failed` (P12Error::Decrypt's
Display — encrypted AuthenticatedSafe/key-bag files, where a wrong
password fails at decryption before any MAC check). Either marker yields
`ZSIGN_INVALID_PASSWORD`; everything else yields the variant-derived code.
Residual, documented fail-safe: for an encrypted/no-MAC file whose wrong
password degenerates into a malformed-ASN.1 parse error, no password-layer
signal survives and the code degrades to `ZSIGN_INVALID_CERTIFICATE`
(classifier tests pin both markers and the generic fallback; a message
change anywhere degrades to generic and the marker test goes red). The
exhaustive `match` still maps `Error::InvalidPassword` for completeness.

### Item 6 — test suite

Structural facts driving the design:

- One inline test module in `lib.rs` (repo convention) declared
  `#[cfg(test)] pub mod tests` — `pub` satisfies wasm-bindgen-test's
  "crate root or `pub mod`" requirement; `#[cfg(test)]` keeps it out of
  production builds. No `tests/` directory, no Cargo.toml changes (the
  existing `wasm-bindgen-test = "0.3"` dev-dep is sufficient).
- Dual-target tests use `#[wasm_bindgen_test(unsupported = test)]`: one
  definition runs as a native `#[test]` (the "native-run subset") and as a
  node test. Only JS-free paths get this attribute — on native targets every
  JS import panics at call time.
- Wasm-only tests use plain `#[wasm_bindgen_test]` (never registered under
  native cargo test — the wasm export is cfg-gated, the body compiles as
  dead code): anything asserting an error, `parse_info_plist` (builds
  `js_sys::Object`), and the `.code` property contract.

Fixture strategy (no new files, no new deps, CI-safe):

- **Leaf p12 embedded in the test module** as a base64 `&str` const with a
  ~15-line test-local decoder. Generated once, locally, with openssl:
  self-issued **RSA-2048**, `CA:FALSE`, `keyUsage=digitalSignature`,
  `extendedKeyUsage=codeSigning`, `OU=ZSN40TEST`, validity from generation
  time (2026-09) to ≥2030 — the binding constraint is that it covers native
  now **and** the wasm fixed epoch 2027-01-15 (and any near-future epoch
  ZSN-3 might pick), AES-256 p12, fixed password. RSA (not the originally
  considered P-256) because this repo's verify path only handles RSA today:
  `cms_verify.rs` parses ECDSA signatures as fixed 64-byte raw
  (`p256::ecdsa::Signature::from_slice`, :986 SignerInfo / :1250 cert
  chain) while `crypto/cms.rs` signs with DER-encoded ECDSA, so every ECDSA
  CMS/cert verification fails to parse (observed live during Task 1; core
  defect owned by ZSN-3 — cross-lane finding, recorded in known items).
  RSA matches the in-repo `rsa_credentials` precedent and the
  fixture-reality pattern (`Profile::Leaf` + codeSigning EKU +
  self-issued anchor) without x509-cert dev-deps and without
  `Validity::from_now` (which panics on wasm32). `from_p12` performs no
  validity check, so construction works on both targets.
- **Thin executable Mach-O**: `include_bytes!("../../zsign/src/ipa/fixtures/minimal_macho.bin")`
  — tracked upstream, thin arm64 MH_EXECUTE. Verified at implementation time;
  if it turns out unsuitable for signing, a minimal macho is built in the test
  module instead (decision logged in the plan).
- **FAT input for the reject test**: hand-built in the test module (FAT header
  `0xcafebabe`, 2 × `fat_arch`, two copies of the thin fixture, big-endian
  fields) — no FAT fixture exists in the repo; the FAT only has to parse.
- Expected digests for the chunk machine come from the crate's existing
  `sha1`/`sha2` deps.

Test matrix (what each covers):

| Test | Target attr | Asserts |
|---|---|---|
| constructor round-trip | dual | `WasmSigner::new` ok, `entitlements()` = profile-derived value, `team_id()` |
| wrong password | wasm-only | throws, `code == ZSIGN_INVALID_PASSWORD`, message non-empty |
| bad profile bytes | wasm-only | `code == ZSIGN_INVALID_PROFILE` |
| entitlements setter: set/clear/fallback | dual (+ wasm-only for invalid) | effective getter before/after; invalid plist → `ZSIGN_INVALID_ENTITLEMENTS` |
| size guards: `ensure_size` boundaries | Ok side dual, Err side wasm-only | every constant at limit (Ok) and limit+1 (`ZSIGN_INPUT_TOO_LARGE`, message contains surface name) — no large allocations, `len` is a plain parameter |
| size guard wiring (cheap surfaces) | wasm-only | constructor over `MAX_P12_BYTES`, `parse_info_plist` over `MAX_PLIST_BYTES`, `hash_file` over `MAX_HASH_BYTES` (129 MiB — the largest allocation kept in CI) → `ZSIGN_INPUT_TOO_LARGE` before parsing; the 513 MiB Mach-O case is covered by the boundary rows above |
| chunk: continue/finalize | dual | built CodeResources digest == digest of full content (sha1+sha256) |
| chunk: single-call finalize | dual | preserved behavior, entry present |
| chunk: double finalize | wasm-only | `ZSIGN_PATH_ALREADY_FINALIZED` |
| chunk: post-finalize chunk (interleave) | wasm-only | `ZSIGN_PATH_ALREADY_FINALIZED` (previously silent partial hash) |
| `hash_file` vs active stream | wasm-only | `ZSIGN_PATH_IN_PROGRESS` |
| excluded paths stay re-callable | dual | main-executable path: repeated `hash_file` returns `false` both times, never sealed, never throws |
| build with unfinished stream | wasm-only | `ZSIGN_UNFINISHED_HASHES` (existing guard, now coded) |
| reset clears seals | wasm-only | after `reset_resources()`, a sealed path can be hashed again and builds (the test also asserts the pre-reset throws) |
| sign round-trip thin (default) | dual | `sign_macho` output re-parses thin; superblob has exactly one CodeDirectory (slot 0, SHA-256 hashType, no alternate); anchored CMS verify via `TrustAnchors::from_certificates` valid |
| sign round-trip dual via `sign_macho_fat` | dual | dual layout present (SHA-1 primary in slot 0 + SHA-256 alternate, superblob.rs:544-557) and anchored verify valid with both CD digests — pins that `sign_macho_fat` behavior did not change |
| FAT rejected by default | wasm-only | hand-built FAT → `ZSIGN_FAT_UNSUPPORTED`, message names `sign_macho_fat` |
| adhoc round-trip | dual | `sign_macho_adhoc` (core, called from the test) + `verify_macho` → signed, adhoc, pages Matched, report valid |
| dylib-style non-executable entitlements | dual | a non-executable input signs with the SAME entitlements special slot whether or not a profile is loaded (both use `EMPTY_ENTITLEMENTS`), while executable input's slot differs between profile/no-profile — pins the replication of `sign_any_macho`'s selection without depending on blob internals |
| `parse_info_plist` XML + binary | wasm-only | bundle_id/executable values; absent keys → `""`; not-a-dictionary → `ZSIGN_INVALID_PLIST` |
| error object contract | wasm-only | thrown value `instanceof Error`, `.code` string, `.message` unchanged text |

Gates (per brief): `TMPDIR=$PWD/.tmptmp cargo test -p zsign-wasm` (native
subset) and `~/.local/bin/wasm-pack test --node crates/zsign-wasm`
(job-equivalent to ci.yml:96; `-- --nocapture` for diagnosis). No
`cargo fmt`/`clippy`/`hk` mid-flight. No workspace-wide test runs (ZSN-15
determinism skip therefore irrelevant to this lane's scoped gates).

## 3. Known items, dependencies, cross-lane

- **ZSN-33 (zsign-core signer.rs)**: FAT SHA-256-only signing. This lane
  rejects FAT under the default instead; wiring point documented in item 1.
- **ZSN-3 (zsign-core cms_verify.rs)**: owns the wasm verify clock. This lane
  does not touch `cms_verify.rs`. The fixed-epoch shim is used only by the
  test certificate's multi-year validity window; if ZSN-3 changes the epoch
  to any near-future value, the window (≥2030) keeps covering it. No code dependency.
  **Cross-lane finding for ZSN-3 (observed live, Task 1):** ECDSA signature
  verification in `cms_verify.rs` is broken — the module parses signatures
  as fixed 64-byte raw ECDSA (`p256::ecdsa::Signature::from_slice` at :986
  for SignerInfo and :1250 for cert chains) while `crypto/cms.rs` produces
  DER-encoded ECDSA signatures; every ECDSA CMS or certificate verification
  fails at parse ("signature does not verify over signed attributes",
  "self-signed cert fails self-signature verification"). RSA is unaffected.
  Out of this lane's scope; reported to the supervisor, not fixed here, and
  this lane's fixture is RSA-2048 because of it.
- **ZSN-41 (examples/web)**: must be briefed with the API delta (§ below);
  edits there are out of this lane's scope.
- **ZSN-31 (.github)**: workflows untouched. Local gate command matches the
  CI job exactly. If a flag change were needed it would be reported, not
  edited — none is needed.
- Deferred core API: `sign_any_macho` has no hash-algorithm parameter; this
  design routes around it from the wasm layer rather than changing core
  (out of scope).
- **Boundary-copy residual (final-review finding, doc-narrowed):** the size
  guards run at the top of each method body, but wasm-bindgen has already
  copied byte arguments into linear memory by then — a hostile oversized JS
  buffer can still exhaust memory at the boundary before
  `ZSIGN_INPUT_TOO_LARGE` is produced. Full pre-copy enforcement requires
  `Uint8Array`-typed parameters (length check before copy), which changes
  every byte-input signature and the native-runnable test harness; recorded
  as possible future work, reported to the supervisor, not taken in this
  lane. All in-body processing/retention is guarded.
- Cold-review adjudication record (round 2, NOT-READY): the single residual
  finding was the plan's `err_message` helper spelled as
  `JsValue::from(err)` under an `impl Into<JsValue>` bound — `From<T>` is
  not derivable from an `Into` bound on a generic parameter, so the snippet
  would not compile. Classified **doc-level (API spelling)**: no control
  flow, error channel, match arm, panic path, or bounds check is affected;
  the helper's design (convert to `JsValue`, then `unchecked_into`) is
  unchanged. Corrected in the plan to `let value: JsValue = err.into();`
  and recorded here per the adjudication rule; reported prominently in the
  lane's final report.

## 4. API delta (contract for examples/web and external JS consumers)

Additive or impact-free:

1. NEW `set_entitlements(data: Option<Uint8Array>)` — validated override;
   `null`/`undefined` clears back to profile-derived.
2. All thrown errors gain a stable string `error.code` (`ZSIGN_*`, table in
   § item 5); `.message` text unchanged; values are still real `Error`
   instances.
3. Doc-only: `parse_info_plist` documents that `bundle_id`/`executable`
   default to `""` (code already did this).

Behavioral changes:

4. `sign_macho` now emits SHA-256-only output for thin inputs (no SHA-1
   CodeDirectory slot) and **throws `ZSIGN_FAT_UNSUPPORTED` for FAT input**
   (previously accepted, dual). Callers wanting dual output — thin or FAT —
   use `sign_macho_fat`, whose behavior is unchanged.
5. `hash_file` now throws `ZSIGN_INPUT_TOO_LARGE` above 128 MiB,
   `ZSIGN_PATH_IN_PROGRESS` while that path is streaming, and
   `ZSIGN_PATH_ALREADY_FINALIZED` when the path was already sealed this round
   (previously silent accept/overwrite). Return type stays boolean.
6. `hash_file_chunk` now throws `ZSIGN_INPUT_TOO_LARGE` per chunk above
   128 MiB and `ZSIGN_PATH_ALREADY_FINALIZED` after finalize (previously
   silently re-seeded a fresh digest). Return stays undefined.
7. NEW size guards `ZSIGN_INPUT_TOO_LARGE` on every byte input, checked
   at the top of each method body before parsing/processing: constructor
   `p12_bytes` (4 MiB) and `profile_bytes`
   (16 MiB), `extract_entitlements` (16 MiB), `parse_info_plist` (16 MiB),
   `set_entitlements` (16 MiB), `parse_macho`/`sign_macho`/`sign_macho_fat`
   data (512 MiB) plus `sign_macho`/`sign_macho_fat` `info_plist` and
   `code_resources` (16 MiB each). Messages state surface, size, limit, and
   remedy. String arguments are not length-checked (deliberate, § item 3).
8. Re-hashing any path in the same round now requires `reset_resources()`.
   Excluded paths (never stored) keep their old re-callable no-op behavior.

Known consumer impact (from the scout, for the lane-41 brief):

- `examples/web/src/main.js:367` hashes every bundle resource with no
  per-file catch — a >128 MiB resource now aborts the run at :538. Lane 41
  should size-gate that loop or route large files to `hash_file_chunk`.
  `main.js:375` (`embedded.mobileprovision`) is subject to the same guard
  (profiles are small — low risk — but it lacks a local catch too).
- `examples/web` never calls bare `sign_macho`, so change (4) touches it only
  through docs; `sign_macho_fat` at :341/:394 keeps working unchanged.
- Error `.code` adoption is optional; `e.message` handling stays valid.

## 5. Spec self-review notes

- No placeholders: every limit, code, and test listed above is concrete.
- Scope: one file (+ its inline tests) and two docs; consistent with the
  brief's queue order 1→6.
- Consistency: item 1's FAT error is produced before item 5 exists in the
  commit sequence and is migrated to `WasmErrorCode` in item 5's series; the
  final state has a single error mechanism (`js_err`) and no residual
  `JsError::new` call sites.
