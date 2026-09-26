# zsign-rs

A Rust implementation of [zsign](https://github.com/zhlynn/zsign) — a cross-platform iOS code signing tool.

> **Note**: This is a learning project porting the original C++ implementation to Rust. It aims to provide the same functionality while leveraging Rust's safety guarantees and modern tooling.

## Overview

zsign-rs signs iOS application packages (IPA files) and Mach-O binaries on macOS, Linux, Windows, **and in the browser via WebAssembly**. It provides an alternative to Apple's official `codesign` utility, enabling iOS app signing outside of the macOS ecosystem.

### Features

- **IPA Signing** — Re-sign existing IPA files with new certificates and provisioning profiles
- **Bundle Signing** — Sign `.app` folders and nested bundles (frameworks, extensions)
- **Mach-O Support** — Single-architecture and FAT/Universal binaries; little-endian 32-bit (armv7/i386) and 64-bit sign, big-endian 32-bit is rejected with a typed error
- **Verification (`-V`)** — `codesign --verify --deep --strict`-style checks on any platform, with the exit-status contract below
- **Cross-Platform** — macOS, Linux, Windows (`cargo check`-gated in CI), and WebAssembly
- **Certificate Formats** — PKCS#12, PEM, and DER key material detected by content; encrypted PEM keys load with a password
- **SHA-256 Primary Code Directory** — the native default; legacy SHA-1 + SHA-256 dual directories opt-in via `-L` for iOS <= 10 targets only
- **Bundle Editing** — rewrite bundle id/name/version (`-b`/`-n`/`-r`), custom entitlements (`-e`, `--entitlements-dir`), profiles (`-m`, `--profile-map`, `-R`)
- **Ad-hoc Signing & Dylib Injection** — `-a` signs without an identity; `-l`/`-w` inject dylib load commands
- **Machine-Readable Output** — `--json` schema v1 (documented below)
- **OCSP Revocation Warning** — `-C` warns on authenticated revocation, never gates; 3s budget, silent offline
- **macOS Keychain Identities** — `--keychain-identity` signs with identities from the macOS keychain
- **Deterministic Output** — sorted zip entries, pinned timestamps, RFC 6979 ECDSA (documented below)
- **WASM Support** — browser-based signing, including whole-IPA `sign_ipa` bytes-to-bytes
- **Apple Interop Verified** — CI signs bundles and verifies them with Apple's
  own `codesign --verify --deep --strict` on macOS (`scripts/verify-apple-interop.sh`)

## Architecture

```
zsign-rs/
├── crates/
│   ├── zsign-core/       # pure signing + verification engine, wasm32-safe
│   │   ├── macho         # parse/sign/write Mach-O (LE 32-bit, 64-bit, FAT)
│   │   ├── codesign      # CodeDirectory, SuperBlob, DER, verification
│   │   ├── crypto        # certificates, CMS sign + verify, OCSP, keychain
│   │   ├── bundle        # CodeResources hash computation
│   │   └── provisioning  # entitlements extraction from profiles
│   ├── zsign/            # native facade (filesystem, threading, IPA handling)
│   │   ├── builder       # high-level signing API (ZSign)
│   │   ├── ipa           # IPA archive extraction and creation
│   │   ├── macho         # filesystem wrapper over zsign-core
│   │   ├── store         # Store trait seam (FsStore/MemStore, crate-private)
│   │   └── verify        # the -V verification engine
│   ├── zsign-wasm/       # WebAssembly bindings (wasm-bindgen)
│   └── zsign-cli/        # command-line interface (single main.rs)
├── fuzz/                 # cargo-fuzz targets (zsign-fuzz, not published)
└── examples/
    └── web/              # browser-based signing demo (Vite)
```

### Crate Overview

| Crate | Description |
|-------|-------------|
| `zsign-core` | Pure-Rust signing **and** verification engine — Mach-O, CodeDirectory/SuperBlob, CMS signatures, trust anchoring. Compiles to `wasm32-unknown-unknown`: keychain, OCSP, and filesystem access are `cfg`-gated off that target; rayon executes sequentially there via its runtime wasm shim. |
| `zsign-rs` | Native library wrapping `zsign-core` with filesystem access, parallel bundle traversal, IPA archive handling, an internal `Store` trait (`FsStore`/`MemStore`, crate-private), and the `-V` verifier. |
| `zsign-wasm` | `wasm-bindgen` bindings over `zsign-rs`/`zsign-core` — credential loading, Mach-O signing, CodeResources with streaming hashes, and whole-IPA `sign_ipa` bytes-to-bytes signing. |
| `zsign-cli` | CLI tool using `clap` for signing IPAs, app bundles, and Mach-O binaries, verifying signatures, and emitting `--json`. |
| `fuzz` | `cargo-fuzz` harness (`zsign-fuzz`, six targets, `publish = false`); smoke-fuzzed weekly by CI. |

## Trust and crypto boundary

All signing **and** verification cryptography is pure Rust in `zsign-core::crypto`; no
Apple frameworks and no OpenSSL are involved.

- **CMS verification** is hand-parsed over the same `der`/`rsa`/`p256` stack used for
  signing (the `cms` crate is signer-only) and validates in Apple's order: message
  digest, `contentType`, Apple CDHash attributes, signature over the signed attributes,
  signer certificate binding, chain structure, X.509 purpose (codeSigning EKU), trust
  anchoring, SKI SignerInfo resolution, and SHA-1 certificate signatures — accepted
  only as non-fatal warnings naming the affected subject
  (`crates/zsign-core/src/crypto/cms_verify.rs`).
- **Trust anchors** are an explicit set whose default is the embedded **Apple Root CA
  only**; WWDR certificates are intermediates, never anchors. `chain_ok` without
  anchoring fails verification, so self-signed test bundles report "not anchored"
  rather than success
  (`docs/superpowers/specs/2026-09-24-cms-trust-anchor-design.md`).
- **Load-time credential policy** checks key type and strength (RSA ≥ 2048),
  codeSigning EKU + digitalSignature KU, `CA:FALSE` leaf rules, and validity windows —
  it never grants chain trust, which happens only at verify time.
- **Revocation is a warning, never a gate** (`-C`, documented below), and CRL,
  `https:` OCSP responders, stapling, and hard-fail modes are explicitly out of scope
  (`docs/superpowers/specs/2026-09-26-crypto-repro-credentials-design.md`).

## How iOS Code Signing Works

The signing process follows Apple's code signature format:

### 1. Bundle Traversal

```
Payload/
└── App.app/
    ├── Info.plist
    ├── App (executable)
    ├── embedded.mobileprovision
    ├── Frameworks/
    │   └── SomeFramework.framework/
    └── PlugIns/
        └── Extension.appex/
```

Bundles are signed depth-first (nested bundles before containers).

### 2. CodeResources Generation

For each bundle, a `_CodeSignature/CodeResources` plist is created containing SHA-1 and SHA-256 hashes of all resource files.

### 3. Mach-O Binary Signing

For each executable:

1. **Page Hashing** — Divide code into 4KB pages, hash each with SHA-1 and SHA-256
2. **Special Slots** — Hash Info.plist, CodeResources, entitlements, requirements
3. **CodeDirectory** — Build the directory structure containing all hashes
4. **CMS Signature** — Generate cryptographic signature of the CodeDirectory
5. **SuperBlob Assembly** — Combine all components into a single blob

Little-endian 32-bit slices (armv7/i386) sign alongside 64-bit ones — thin and as FAT
slices, through the same writer path; big-endian 32-bit (`MH_CIGAM`) is rejected with a
typed error naming the supported alternatives.

```
SuperBlob (0xfade0cc0)
├── CodeDirectory SHA-1 (slot 0x0000)
├── Requirements (slot 0x0002)
├── Entitlements XML (slot 0x0005)
├── Entitlements DER (slot 0x0007)
├── CodeDirectory SHA-256 (slot 0x1000)
└── CMS Signature (slot 0x10000)
```

### 4. Binary Modification

The SuperBlob is written to the `__LINKEDIT` segment, and the `LC_CODE_SIGNATURE` load command is updated.

## Usage

### Library

```rust
use zsign_rs::{ZSign, SigningCredentials};

// Load credentials from PKCS#12
let p12_data = std::fs::read("certificate.p12")?;
let credentials = SigningCredentials::from_p12(&p12_data, "password")?;

// Sign an IPA
ZSign::new()
    .credentials(credentials)
    .provisioning_profile("app.mobileprovision")
    .bundle_id("com.example.myapp")     // optional: rewrite bundle ID
    .sign_ipa("input.ipa", "output.ipa")?;
```

### CLI quick start

```bash
# Sign an IPA with a PKCS#12 certificate and provisioning profile
zsign-cli --pkcs12 cert.p12 --password secret \
    --profile app.mobileprovision --output signed.ipa input.ipa

# Same via -k (content-detected PKCS#12) and the ZSIGN_PASSWORD env var
ZSIGN_PASSWORD=secret zsign-cli -k cert.p12 -m app.mobileprovision -o signed.ipa input.ipa

# PEM certificate + PEM/DER key pair
zsign-cli -k key.pem -c cert.pem -m app.mobileprovision -o signed.ipa input.ipa

# Ad-hoc sign an app bundle in place
zsign-cli -a MyApp.app

# Verify a signed IPA, bundle, or Mach-O
zsign-cli -V signed.ipa
```

Signing requires a credential source — `--pkcs12`, `-k` (with `-c` for PEM/DER key
material), or `--keychain-identity` — or one of `-a`/`-V`, which need none.

### CLI reference

Complete surface of `zsign-cli` (from `zsign-cli --help`, captured 2026-09-27):

|Flag|Value|Description|
|---|---|---|
|`<INPUT>`|path|Input file (IPA, Mach-O, or app bundle); required|
|`-o, --output`|path|Output file|
|`-c, --certificate`|path|Certificate file (PEM format); requires `-k`|
|`-k, --private-key`|path|Private key **or** PKCS#12 file — format detected by content (PEM `-----BEGIN` key, DER key, or PKCS#12; use `-k` alone for PKCS#12)|
|`--pkcs12`|path|PKCS#12 file (`.p12`); long-only, conflicts `-c`/`-k`|
|`--keychain-identity`|name/hash|macOS keychain codesigning identity (name or SHA-1 hash from `security find-identity -v -p codesigning`); conflicts `--pkcs12`/`-c`/`-k`/`-V`; macOS-only — other platforms fail with exit 1|
|`-m, --profile`|path|Provisioning profile; conflicts `-a`|
|`--profile-map`|`BUNDLE_ID=PATH`|Per-bundle provisioning profile (repeatable); app bundles only, ignored for a bare Mach-O|
|`-R, --remove-profile`|—|Remove `embedded.mobileprovision` from every bundle before signing; bundles/IPAs only, ignored for bare Mach-O|
|`-e, --entitlements`|path|Custom entitlements file (replaces the profile's entitlements)|
|`--entitlements-dir`|path|Directory of per-bundle-id entitlements (`<dir>/<bundle-id>.plist`); falls back to the profile when no file matches|
|`-p, --password`|string|Password for PKCS#12 or key material (empty password is valid); beats `ZSIGN_PASSWORD`; prefer the env var — argv values are visible in process listings. Env: `ZSIGN_PASSWORD` (value hidden from help/errors)|
|`-z, --zip-level`|0–9|ZIP compression level, default `6` (`0` = no compression, matches C++ zsign; `9` = slowest/smallest); out-of-range is a usage error, never clamped|
|`-b, --bundle-id`|id|New bundle identifier (`CFBundleIdentifier`)|
|`-n, --bundle-name`|name|New display name (`CFBundleDisplayName`)|
|`-r, --bundle-version`|version|New short version (`CFBundleShortVersionString`)|
|`-2, --sha256-only`|—|Emit only the SHA-256 code directory (the modern default)|
|`-L, --legacy-sha1`|—|Legacy SHA-1 + SHA-256 dual code directories (iOS <= 10 only); conflicts `-2`|
|`-f, --force`|—|Override the FairPlay-encryption refusal and sign encrypted binaries anyway (already-decrypted input only)|
|`-a, --adhoc`|—|Sign without an identity (ad-hoc); conflicts `-m`, `-C`, `-V`|
|`-l, --dylibs`|path|Dylib load path to inject (repeatable)|
|`-w, --weak`|—|Inject dylibs as `LC_LOAD_WEAK_DYLIB`|
|`-C, --check-revocation`|—|OCSP revocation **warning** (semantics below); conflicts `-V`, `-a`|
|`-V, --verify`|—|Verify like `codesign --verify --deep --strict`; conflicts with every signing option (clap rejects each pairing at parse time)|
|`--json`|—|Machine-readable JSON output (documented below); works in both signing and verify modes|
|`-h, --help`|—|Print help (there is no `--version` flag)|

`zsign-cli` prints an `upstream users: -p/-k now match upstream; --pkcs12 is long-only`
epilog after the option list — see the migration section below.

#### Verify a signed binary, bundle, or IPA

`-V/--verify` checks the input the way `codesign --verify --deep --strict`
does: code-page hashes, special-slot digests (Info.plist, CodeResources,
entitlements), the embedded CMS signature (message digest, Apple CDHash
attributes, signer certificate + chain), and — for bundles/IPAs — the
CodeResources file and every nested code (Frameworks, appex, nested apps).

```bash
# Verify a signed IPA (deep)
zsign-cli -V signed.ipa

# Verify an app bundle in place
zsign-cli -V Test.app

# Verify a single Mach-O
zsign-cli -V Test
```

### Exit status

|Code|Signing|`--verify`|
|---|---|---|
|`0`|signed successfully|verification completed, input **valid**|
|`1`|any signing or credential failure|verification completed, input **invalid** (issues printed)|
|`2`|usage/parse errors (clap)|could not complete — unreadable/unsupported input, or a report with top-level errors (e.g. a slot that cannot be verified without bundle context); also usage/parse errors (clap)|

- With `--json`, failures are JSON objects on **stderr**
  (`{"status":"error","error":"…"}`); clap usage errors stay human-readable by design.
- The report-based exit-2 class applies to bare-Mach-O inputs; bundle/IPA problems are
  completed-negative verdicts exiting `1`.
- Sign failures deliberately stay `1` so they remain distinguishable from clap's
  hardcoded usage exit `2`
  (`docs/superpowers/specs/2026-09-25-cli-surface-design.md`).

### JSON output (`--json`)

One compact (single-line) JSON document per run: successes on stdout, failures on
stderr. Schema v1 — field names and enum spellings are stable; renaming one is a
breaking change (source: `docs/superpowers/specs/2026-09-25-cli-surface-design.md`,
§ “JSON schema v1”; DTOs in `crates/zsign-cli/src/main.rs`):

- Sign: `{"status":"signed","output":"<path>"}`
- Verify: `{"status":"valid"|"invalid"|"error","input":"<path as given>","report":{…}}`
- Error (stderr): `{"status":"error","error":"<message>"}`
- “Could not complete” emits both: the verify document on stdout with
  `"status":"error"` **and** the error object on stderr.

`report` = `{"valid":bool,"macho":{…}|null,"bundle":{…}|null,"errors":[…]}`:

- `macho`: `{"fat":bool,"slices":[{arch,signed,identifier,adhoc,valid,pages,special_slots,cms,errors,warnings}]}` — `null` for bundle/IPA inputs
- `pages`: `{"kind":"matched"}` | `{"kind":"empty"}` | `{"kind":"mismatch","page_index":n}` | `{"kind":"count_mismatch","stored":n,"computed":n}`
- `special_slots`: `[{slot,name,check}]` — `slot` is synthesized `-1`…`-7` with labels `Info.plist`, `requirements`, `CodeResources`, `application`, `entitlements`, `rep-specific`, `der entitlements`; `check` ∈ `matched` | `not_checked` | `mismatch` | `missing`
- `cms`: `{valid,no_signature,signer_subject,signer_serial,message_digest_ok,cdhash_v1_ok,cdhash_v2_ok,signature_ok,chain_ok,anchored,chain_reason,chain,errors,warnings}` — `null` only for early-failed slices
- `bundle`: `{path,valid,binaries:[{path,valid,report,errors}],code_resources:{valid,matched,mismatched,missing,unsealed}|null,errors,nested:[…]}` — `nested` is recursive; `bundle` is `null` for bare-Mach-O inputs

`status` is authoritative for machine consumers; exit codes remain the human/shell
signal. Deliberately absent: `report.warnings`, `exit_code`, `problem_count` (the
first has no writers, the others are derivable).

### Password channels

Resolution order for PKCS#12 material:

1. `-p/--password` — beats the environment (clap consults `ZSIGN_PASSWORD` only when
   the flag is absent).
2. `ZSIGN_PASSWORD` environment variable — its value is never echoed in help or errors
   (`hide_env_values`).
3. Empty-password trial — an empty password is valid and never triggers a prompt.
4. One interactive prompt (`PKCS#12 password: `) — only when stdin is a terminal, and
   only on PKCS#12 paths (`--pkcs12`, or `-k` pointing at PKCS#12 content).
5. Otherwise the error names both channels:
   `… no password supplied: pass -p/--password or set ZSIGN_PASSWORD (stdin is not a terminal, cannot prompt)`.

- PEM and bare-DER key paths never prompt — pass `-p`/`ZSIGN_PASSWORD` if the key is
  encrypted (encrypted PEM is accepted with the right password).
- argv exposure: `-p secret` is visible to other users in process listings — prefer
  `ZSIGN_PASSWORD`.
- Misuse guard: PKCS#12 content passed to `-k` **together with** `-c` fails with an
  error telling you to pass `-k` alone or use `--pkcs12`.

### Revocation checking (`-C/--check-revocation`)

- **Warn-only, never a gate:** only an *authenticated* responder saying “revoked”
  prints `warning: …` to stderr; signing always proceeds and exit codes never change.
  Every other outcome — good, unreachable, offline, missing OCSP URL, budget expired —
  stays silent.
- One bounded network request per run with a 3s budget covering connect/read/write
  (DNS runs on a short-lived native worker thread under the same budget); native
  targets only.
- Known limits, recorded rather than papered over: plaintext `http:` OCSP proves the
  responder's key, not the channel; `https:` responder URLs are not fetched (reported
  as a distinct reason); no `nextUpdate` freshness ceiling when the responder omits it;
  CRL, stapling, and hard-fail modes are out of scope
  (`docs/superpowers/specs/2026-09-26-crypto-repro-credentials-design.md`).
- Conflicts `-V` and `-a`; ad-hoc signing runs no credential check at all.

### Keychain identities (`--keychain-identity`, macOS only)

- Select by identity name or 40-hex hash from `security find-identity -v -p
  codesigning`; an ambiguous name errors with the candidate hashes.
- Loads through the same PKCS#12 pipeline (`security export` → selector → `from_p12`),
  so every load-time policy check (RSA ≥ 2048, EKU/KU, leaf rules) still runs.
- Non-macOS platforms fail with `--keychain-identity is only available on macOS; use
  --pkcs12, -k/--private-key, or -c/--certificate on this platform` (exit 1).
  `-p`/`ZSIGN_PASSWORD` is never consulted on this path.
- A macOS CI job recipe (create-keychain → import identity p12 → `cargo test -p
  zsign-core keychain`) is recorded in
  `docs/superpowers/specs/2026-09-26-32bit-keychain-design.md` §3.6 — it is **not**
  wired into CI yet and needs a CI-held identity secret.

### WASM (Browser)

Whole-IPA signing with no JS-side zip handling:

```javascript
import init, { WasmSigner } from 'zsign-wasm';

await init();

const signer = new WasmSigner(p12Bytes, "password", profileBytes);
const signedIpa = signer.sign_ipa(
    ipaBytes,             // complete IPA as bytes
    "com.example.newid",  // optional bundle_id rewrite
    "New Name",           // optional bundle_name
    "2.0.1",              // optional bundle_version
    6,                    // optional compression_level (0-9, default 6)
);                        // -> Uint8Array (signed IPA)
```

- **Size caps:** input ≤ 512 MiB; declared uncompressed per entry ≤ 512 MiB and total
  ≤ 2 GiB (violations throw `ZSIGN_INPUT_TOO_LARGE`). Existing caps unchanged:
  Mach-O 512 MiB, hash input 128 MiB, plists/profiles 16 MiB, PKCS#12 4 MiB.
- **Errors:** every thrown error is a real `Error` with a stable `error.code` — match
  on the code, never the message. The family: `ZSIGN_INVALID_MACHO`,
  `ZSIGN_ENCRYPTED_BINARY`, `ZSIGN_SIGNING_FAILED`, `ZSIGN_INVALID_CERTIFICATE`,
  `ZSIGN_INVALID_PASSWORD`, `ZSIGN_MISSING_CREDENTIALS`, `ZSIGN_CONFIG`,
  `ZSIGN_INVALID_PROFILE`, `ZSIGN_INVALID_PLIST`, `ZSIGN_DER_ENCODING`,
  `ZSIGN_VERIFICATION`, `ZSIGN_INPUT_TOO_LARGE`, `ZSIGN_INVALID_ENTITLEMENTS`,
  `ZSIGN_UNFINISHED_HASHES`, `ZSIGN_PATH_ALREADY_FINALIZED`,
  `ZSIGN_PATH_IN_PROGRESS`, `ZSIGN_FAT_UNSUPPORTED`, `ZSIGN_INTERNAL`.
  `sign_ipa` adds no new codes: a malformed archive maps to `ZSIGN_SIGNING_FAILED`;
  **declared-size** cap violations throw `ZSIGN_INPUT_TOO_LARGE`, while **actual-byte**
  overruns caught mid-stream (a zip header that lies about its size) surface as
  `ZSIGN_SIGNING_FAILED`.
- **Memory:** peak ≈ input + uncompressed tree + output plus per-file working set;
  linear memory never shrinks, so a large sign leaves a per-tab watermark — use a
  desktop-class browser above ~100 MiB inputs.
- Contract: `docs/superpowers/specs/2026-09-26-wasm-ipa-bytes-design.md`.

The fine-grained per-entry API remains available and is what `examples/web`
demonstrates: `hash_file`/`hash_file_chunk`, `build_code_resources`, `sign_macho`
(SHA-256-only, thin input — FAT input is rejected), `sign_macho_fat` (the explicit
dual SHA-1+SHA-256 opt-in for FAT/Universal input), `parse_macho`, `parse_info_plist`.

## Migrating from upstream zsign

`zsign-cli` restores upstream flag meanings where it could, and diverges deliberately
elsewhere (contract: `docs/superpowers/specs/2026-09-25-cli-surface-design.md`):

|Flag|Upstream zsign|zsign-rs|
|---|---|---|
|`-p/--password`|password string|**now the password too** — in zsign-rs it was the PKCS#12 path short until 0.1.x; also reads `ZSIGN_PASSWORD`|
|`-k/--private-key`|PEM or DER key (PKCS#12 tried last)|PEM / DER / PKCS#12 **detected by content**; use `-k` alone for PKCS#12|
|`--pkcs12`|—|the PKCS#12 path flag, **long-only** (no `-p` short anymore)|
|`-z/--zip-level`|0–9, default `0`, rejects out-of-range|0–9, **default `6`**, rejects out-of-range (never clamps)|
|`-f/--force`|bypass the folder re-sign cache|override the FairPlay-encryption refusal (zsign-rs has no cache layer)|
|`-C`|standalone certificate report whose exit codes scripts may depend on|**warning-only** OCSP probe while signing; never gates|
|exit codes|`0` / catch-all `255`|`0` / `1` / `2` contract above|

There is no compatibility shim: old `zsign-cli -p cert.p12 …` invocations fail loudly
at parse time. `zsign-cli --help` ends with the same reminder:
`upstream users: -p/-k now match upstream; --pkcs12 is long-only`.

Upstream flags with **no** zsign-rs equivalent — transcribed from upstream
`src/zsign.cpp` (long-option table + `usage()`, commit `614caa8d`, 2026-08-21) by
this lane's upstream parity research; upstream source is not vendored in this tree:
`-d -q -i -t -D -x -I -S -M -E -W -U
-P -v` (debug dumps, quiet, ideviceinstaller install, temp folder, dylib removal,
metadata/icon extraction, Files-app toggles, MinimumOSVersion, extension/watch/
UISupportedDevices cleanup, extension injection, version print), plus the
`.zsign_cache` fast re-sign layer. zsign-rs extensions with no upstream counterpart:
`--pkcs12`, `--keychain-identity`, `--profile-map`, `--entitlements-dir`, `--json`,
`-V/--verify`, `ZSIGN_PASSWORD`.

**Versioning:** the `-p`/`-k` re-meaning is a breaking CLI change; the next release
bumps the pre-1.0 crates from 0.1.x to **0.2.0** (manifest versions change at release
time, not with this documentation).

## Deterministic output

Signing the same input twice produces byte-identical output. The mechanisms:

- **Sorted zip entries** — archive names sorted bytewise (parents before children,
  `Payload/` first, pass-through roots like `SwiftSupport/` included) in
  `crates/zsign/src/ipa/archive.rs`.
- **Pinned timestamps** — every zip entry carries 1980-01-01 (`zip::DateTime::default()`).
- **Deterministic signatures** — RFC 6979 ECDSA nonces and PKCS#1 v1.5 RSA; adding a
  `signingTime` attribute or moving ECDSA to a randomized signer would make the
  module's byte-identical tests fail (contract in `crates/zsign-core/src/crypto/cms.rs`).
  Upstream zsign inherits OpenSSL's randomized nonce, so its output is not
  reproducible run to run.
- **Ordered structures** — CodeResources files live in a `BTreeMap`; the wasm build
  uses a pinned clock (cert-validity checks only).

Pinned by tests: `test_create_ipa_writes_entries_in_sorted_order`,
`test_create_ipa_from_root_is_byte_identical_across_creation_order`,
`cms_ecdsa_signature_is_byte_identical_five_times`,
`sign_macho_ecdsa_is_byte_identical_twice`, and `test_ipa_signing_is_deterministic`
— the CI debug test job runs the full suite, this test included.

## Building

```bash
# Build all crates
cargo build --release

# Run tests
cargo test

# Build WASM package (requires wasm-pack)
wasm-pack build crates/zsign-wasm --target web --release

# Generate documentation
cargo doc --open
```

## Development

Tools are pinned with [mise](https://mise.jdx.dev) and git hooks run through
[hk](https://hk.jdx.dev):

```bash
mise install   # install pinned tools and register git hooks
hk check --all # full local gate: file hygiene, `cargo fmt --all -- --check`,
               # actionlint, `cargo clippy --workspace --all-targets -- -D warnings`,
               # `cargo test --workspace`
hk fix         # auto-fix what the lint steps can
```

Pre-commit runs file hygiene, `cargo fmt`, and `actionlint`; pre-push runs
`cargo clippy --workspace --all-targets -- -D warnings`.

**Tests:** 740 passing, 0 failing, 13 ignored as of 2026-09-27 (`cargo test
--workspace`, measured on this branch) — 679 unit tests (zsign-cli 46, zsign-core
433, zsign-rs 189, zsign-wasm 11) plus 61 doctests. The 12 ignored doctests need real
key material and one ignored test streams >4 GiB; the wasm crate's
`unsupported = test` cases run natively under `cargo test`, while wasm-target cases
run via `wasm-pack test --node`. Run the suite with `cargo test`; keep `TMPDIR`
inside the worktree if `/tmp` is tight.

**CI** (`.github/workflows/`): `ci.yml` runs lint (`hk`), the debug test job
(`cargo test --workspace`, full suite), a release-profile test job, Windows
`cargo check`, wasm check/build/`wasm-pack test --node`, the macOS
`codesign --verify --deep --strict` interop (`scripts/verify-apple-interop.sh`),
`cargo-deny`, and an MSRV 1.88 check. Separate workflows: weekly fuzz smoke, weekly
web-example build, and tag-gated crates.io/npm publishing.

## Learning Resources

This project serves as a learning exercise for:

- **Mach-O Binary Format** — Understanding Apple's executable format
- **Apple Code Signing** — How iOS verifies app integrity
- **Cryptographic Signatures** — CMS/PKCS#7 signature generation
- **Rust Systems Programming** — Binary parsing, memory safety, FFI patterns

### Key Concepts Implemented

| Concept | Implementation |
|---------|----------------|
| Mach-O Parsing | `zsign-core::macho::parser` — Load commands, segments, FAT headers |
| Code Hashing | `zsign-core::codesign::code_directory` — Page hashing, special slots |
| Blob Structures | `zsign-core::codesign::superblob` — Apple's nested blob format |
| DER Encoding | `zsign-core::codesign::der` — Entitlements plist to DER conversion |
| CMS Signatures | `zsign-core::crypto::cms` — Apple-specific signed attributes |
| Certificate Handling | `zsign-core::crypto::cert` — PKCS#12, PEM, X.509 parsing |
| WASM Bindings | `zsign-wasm` — Browser-compatible signing via `wasm-bindgen` |
|CMS Verification|`zsign-core::crypto::cms_verify` — Apple-order checks + trust anchoring|
|Revocation (OCSP)|`zsign-core::crypto::revocation` — warn-only probe, 3s budget|
|macOS Keychain|`zsign-core::crypto::keychain` — `security` shell-out + identity selector|
|Full verification (`-V`)|`zsign::verify` — bundle/Mach-O/IPA report engine|

## References

### Original Project

- **[zhlynn/zsign](https://github.com/zhlynn/zsign)** — Original C++ implementation (MIT License)

### Apple Documentation

- [Code Signing Guide](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Introduction/Introduction.html)
- [Mach-O Programming Topics](https://developer.apple.com/library/archive/documentation/DeveloperTools/Conceptual/MachOTopics/0-Introduction/introduction.html)
- [TN3127: Inside Code Signing](https://developer.apple.com/documentation/technotes/tn3127-inside-code-signing-requirements)

### Technical References

- [Apple Code Signing Internals](https://www.objc.io/issues/17-security/inside-code-signing/)
- [Mach-O File Format Reference](https://github.com/aidansteele/osx-abi-macho-file-format-reference)
- [Code Signature Format (XNU Source)](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/kern/cs_blobs.h.auto.html)

## License

MIT, as declared in the crate manifests (`license = "MIT"` in each
`crates/*/Cargo.toml`). This project ports [zhlynn/zsign](https://github.com/zhlynn/zsign),
which is MIT-licensed.

## Acknowledgments

- [zhlynn](https://github.com/zhlynn) for the original zsign implementation
- The Rust community for excellent parsing and cryptography libraries
