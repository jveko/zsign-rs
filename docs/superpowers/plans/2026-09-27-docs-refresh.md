# Docs refresh implementation plan — README + AGENTS

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development with
> dispatching-parallel-agents for independent tasks to implement this plan section by
> section. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rewrite `AGENTS.md` and refresh `README.md` so every documented flag, command,
and behavior matches the shipped four-crate workspace and full CLI surface.

**Architecture:** Docs-only lane. Facts come from three verified layers: the built
binary (`target/debug/zsign-cli`, `cargo build -p zsign-cli` — 0 warnings), source
file:line citations, and landed design docs under `docs/superpowers/specs/`. Design:
`docs/superpowers/specs/2026-09-27-docs-refresh-design.md`.
The `#### Verify a signed binary, bundle, or IPA` subsection stays where it is
(under Usage, after the reference table) and is handled by Task 4.

**Tech Stack:** Markdown only; no code, no config, no Cargo files.

---

## Evidence base (all captured 2026-09-27 on `zsn46-docs` @ `2725bf2`)

- `target/debug/zsign-cli --help` verbatim (exit 0) — 25 options + positional INPUT.
- Live binary invocations: conflict errors (all exit 2), `-V` error paths (exit 2),
  `ZSIGN_PASSWORD` hidden in help, no-args usage error (exit 2).
- `cargo test --workspace --no-fail-fast -- --skip …` (research only, for counts):
  **739 passed, 0 failed, 13 ignored, 1 filtered** = 678 unit (cli 46 / core 433 /
  rs 188 / wasm 11) + 61 doctests. **Caveat:** measured on this branch base while lane
  zsn45 runs concurrently; README presents the number with its measurement date.
- Exit mapping: `main.rs:197` (clap 2), `:199-205` (sign fail 1), `:303` (sign ok 0),
  `:320-325` (verify constructor Err 2), `:345-352` (verify 0/1/2).
- Conflicts: `main.rs:42,49,121,130,145` and `-V`'s 21-name list `:155-177`.
- Password: `resolve_p12_password` `main.rs:927-954`; `env = "ZSIGN_PASSWORD"` `:86`.
- JSON DTOs: `main.rs:567-839`; emitters `:542-565`.
- Design docs: `2026-09-25-cli-surface-design.md` (exit/JSON/migration),
  `2026-09-26-wasm-ipa-bytes-design.md` (sign_ipa), `2026-09-26-32bit-keychain-design.md`
  (keychain + 32-bit), `2026-09-26-crypto-repro-credentials-design.md` (OCSP,
  RFC 6979), `2026-09-26-zip-encoding-determinism-design.md` (zip sort/pins),
  `2026-09-24-cms-trust-anchor-design.md` (anchor policy).

**Gate policy (hard):** final gates are `cargo fmt --all -- --check`,
`cargo clippy --workspace --all-targets -- -D warnings`, and
`cargo test --workspace --no-fail-fast` — **no `--skip`, no weakened thresholds**.
The README must not present the release-CI skip as a contributor instruction.

---

### Task 1: Rewrite AGENTS.md

**Files:**
- Modify: `AGENTS.md` (whole file, in place)

- [ ] **Step 1: Replace the whole file with the following content**

````markdown
# AGENTS.md — zsign-rs

## Build & Test
- Tooling: `mise install` installs pinned tools (hk, actionlint) from `mise.toml` and registers git hooks
- Hooks: `hk` — pre-commit (file hygiene, `cargo fmt`, actionlint), pre-push (`cargo clippy --workspace --all-targets -- -D warnings`); `hk check --all` runs the superset (hygiene + fmt + actionlint + clippy + `cargo test --workspace`), `hk fix` rewrites what the lint steps can
- Build: `cargo build --release`
- Test all: `cargo test`
- Test single: `cargo test -p zsign-cli <name>` | `-p zsign-core <name>` | `-p zsign-rs <name>` (the facade package is `zsign-rs`, its directory is `crates/zsign/`)
- WASM tests: `wasm-pack test --node crates/zsign-wasm` for `#[wasm_bindgen_test]` cases; plain `cargo test` still runs the wasm crate's native unit tests
- Temp files: keep `TMPDIR` inside the worktree (`mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test …`) — `/tmp` is a small tmpfs on this machine
- Check: `cargo check` | Lint: `cargo clippy` | Docs: `cargo doc --open`
- Zero-warning gate: `cargo fmt --all -- --check` + `cargo clippy --workspace --all-targets -- -D warnings`

## Architecture
Workspace members (`Cargo.toml:3`): `crates/zsign-core`, `crates/zsign` (package **`zsign-rs`**), `crates/zsign-wasm`, `crates/zsign-cli`, `fuzz` (`zsign-fuzz`, `publish = false`).

- **`zsign-core`** (`crates/zsign-core/`) — pure engine: `macho` (parse/sign/write; little-endian 32-bit + 64-bit + FAT; big-endian 32-bit rejected with a typed error), `codesign` (CodeDirectory, SuperBlob, DER, verification), `crypto` (certificates, CMS signing **and** verification, OCSP revocation, macOS keychain, encrypted PEM), `bundle` (CodeResources), `provisioning`. Compiles to `wasm32-unknown-unknown`: nothing on the wasm path reaches `std::fs`/`std::net`/`std::thread` (keychain exec, OCSP transport + budget thread are `cfg`-gated off wasm32; rayon degrades to sequential there).
- **`zsign-rs`** (`crates/zsign/`) — native facade over `zsign-core`: `builder` (high-level `ZSign` API), `bundle`, `ipa` (zip extract/create), `macho` (filesystem wrapper over the core parser), `store` (`Store` trait — stateless `FsStore` ZST + `MemStore`, all-`&self` + `Sync` so rayon closures capture `&S` unchanged), `verify` (the `-V` engine), `error`. Re-exports `codesign`, `crypto`, `SigningCredentials` from core.
- **`zsign-wasm`** (`crates/zsign-wasm/`) — `wasm-bindgen` bindings: `WasmSigner` per-entry CodeResources API plus whole-IPA `sign_ipa` bytes-to-bytes; stable `ZSIGN_*` error codes surface as `error.code` (match via `Reflect`, never string-match messages).
- **`zsign-cli`** (`crates/zsign-cli/`) — single `main.rs`, clap derive; exit contract 0/1/2 and `--json` schema v1 live here.

## Code Style
- Edition 2021, MSRV 1.88, `thiserror` for error enums, `crate::Result<T>` alias throughout
- Module docs (`//!`) are thorough; per-item `///` coverage is expected but uneven — error enums and small accessors are often bare
- Tests: inline `#[cfg(test)] mod tests` per file (exceptions: `fuzz/` binary targets; `#[wasm_bindgen_test]` cases run via `wasm-pack test --node`)
- Error assertions: `assert!(matches!(&res, Err(Error::Variant(m)) if m.contains("…")), "…, got {:?}", res.as_ref().err());` — the `res.as_ref().err()` footer prints the actual failure (dominant pattern, 30+ sites)
- Errors: `#[from]` for external crates, `#[error(transparent)]` wrappers, `Error::Variant(String)` payloads, unit variants for policy failures — all four shapes are in use
- Imports: one alphabetically-sorted `use` block, no blank-line grouping, `crate::`/`super::` interleaved by name
- Key deps: `goblin` (Mach-O), `zip` (IPA), `plist`, `sha1`/`sha2`, `rayon`, RustCrypto (`rsa`, `p256`, `pkcs8`, `der`, `x509-cert`, `cms`), `clap`/`serde`/`serde_json`/`rpassword` (CLI), `wasm-bindgen` (wasm)
````

- [ ] **Step 2: Verify the rewritten claims**

Run: `grep -c 'two crates' AGENTS.md` → expected: `0`.
Confirm `cargo test -p zsign-rs --help`-style package names by
`cargo metadata --no-deps --format-version 1 | grep -o '"name":"[^"]*"' | head -5`
→ packages include `zsign-rs`, `zsign-core`, `zsign-wasm`, `zsign-cli`.

- [ ] **Step 3: Commit**

```bash
git add AGENTS.md
git commit -m "docs: rewrite agents guide for the four-crate workspace"
```

---

### Task 2: README — intro, features, architecture, trust boundary

**Files:**
- Modify: `README.md` — `### Features` (replace bullets), `## Architecture` (tree +
  crate table), insert new `## Trust and crypto boundary` section before
  `## How iOS Code Signing Works`, one sentence in `### 3. Mach-O Binary Signing`.

- [ ] **Step 1: Replace the `### Features` bullet list**

````markdown
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
````

- [ ] **Step 2: Replace the architecture tree and crate table**

Tree (replaces the fenced block under `## Architecture`):

````
zsign-rs/
├── crates/
│   ├── zsign-core/       # pure signing engine, wasm32-safe
│   │   ├── macho         # parse/sign/write Mach-O (LE 32-bit, 64-bit, FAT)
│   │   ├── codesign      # CodeDirectory, SuperBlob, DER, verification
│   │   ├── crypto        # certificates, CMS sign + verify, OCSP, keychain
│   │   ├── bundle        # CodeResources hash computation
│   │   └── provisioning  # entitlements extraction from profiles
│   ├── zsign/            # native facade (filesystem, threading, IPA handling)
│   │   ├── builder       # high-level signing API (ZSign)
│   │   ├── ipa           # IPA archive extraction and creation
│   │   ├── macho         # filesystem wrapper over zsign-core
│   │   ├── store         # Store trait: FsStore / MemStore seam
│   │   └── verify        # the -V verification engine
│   ├── zsign-wasm/       # WebAssembly bindings (wasm-bindgen)
│   └── zsign-cli/        # command-line interface (single main.rs)
├── fuzz/                 # cargo-fuzz targets (zsign-fuzz, not published)
└── examples/
    └── web/              # browser-based signing demo (Vite)
````

Crate overview table (replace the `### Crate Overview` table):

| Crate | Description |
|-------|-------------|
| `zsign-core` | Pure-Rust signing **and** verification engine — Mach-O, CodeDirectory/SuperBlob, CMS signatures, trust anchoring. Compiles to `wasm32-unknown-unknown`; keychain, OCSP, and filesystem access are `cfg`-gated off that target and rayon runs sequential there. |
| `zsign-rs` | Native library wrapping `zsign-core` with filesystem access, parallel bundle traversal, IPA archive handling, the `Store` trait (`FsStore`/`MemStore`), and the `-V` verifier. |
| `zsign-wasm` | `wasm-bindgen` bindings over `zsign-rs`/`zsign-core` — credential loading, Mach-O signing, CodeResources with streaming hashes, and whole-IPA `sign_ipa` bytes-to-bytes signing. |
| `zsign-cli` | CLI tool using `clap` for signing IPAs, app bundles, and Mach-O binaries, verifying signatures, and emitting `--json`. |
| `fuzz` | `cargo-fuzz` harness (`zsign-fuzz`, six targets, `publish = false`); smoke-fuzzed weekly by CI. |

- [ ] **Step 3: Insert `## Trust and crypto boundary` before `## How iOS Code Signing Works`**

````markdown
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
````

- [ ] **Step 4: Add the 32-bit sentence to `### 3. Mach-O Binary Signing`**

After the numbered list (1. Page Hashing … 5. SuperBlob Assembly), add:

```markdown
Little-endian 32-bit slices (armv7/i386) sign alongside 64-bit ones — thin and as FAT
slices, through the same writer path; big-endian 32-bit (`MH_CIGAM`) is rejected with a
typed error naming the supported alternatives.
```

- [ ] **Step 5: Commit**

```bash
git add README.md
git commit -m "docs: refresh readme features, architecture, and trust boundary"
```

---

### Task 3: README — Usage: library, quick start, complete flag table

**Files:**
- Modify: `README.md` — `### Library` (fix import), replace `### CLI` with
  `### CLI quick start` + `### CLI reference`.

- [ ] **Step 1: Fix the library example import**

In `### Library`, replace `use zsign::{ZSign, SigningCredentials};` with:

```rust
use zsign_rs::{ZSign, SigningCredentials};
```

(Verified: `crates/zsign/Cargo.toml:2` package name `zsign-rs`; `lib.rs` re-exports
`ZSign` and `SigningCredentials`. The method chain stays unchanged — verified against
`builder.rs`.)

- [ ] **Step 2: Replace the `### CLI` section with quick start + reference**

````markdown
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

| Flag | Value | Description |
|---|---|---|
| `<INPUT>` | path | Input file (IPA, Mach-O, or app bundle); required |
| `-o, --output` | path | Output file |
| `-c, --certificate` | path | Certificate file (PEM format); requires `-k` |
| `-k, --private-key` | path | Private key **or** PKCS#12 file — format detected by content (PEM `-----BEGIN` key, DER key, or PKCS#12; use `-k` alone for PKCS#12) |
| `--pkcs12` | path | PKCS#12 file (`.p12`); long-only, conflicts `-c`/`-k` |
| `--keychain-identity` | name/hash | macOS keychain codesigning identity (name or SHA-1 hash from `security find-identity -v -p codesigning`); conflicts `--pkcs12`/`-c`/`-k`/`-V`; macOS-only — other platforms fail with exit 1 |
| `-m, --profile` | path | Provisioning profile; conflicts `-a` |
| `--profile-map` | `BUNDLE_ID=PATH` | Per-bundle provisioning profile (repeatable); app bundles only, ignored for a bare Mach-O |
| `-R, --remove-profile` | — | Remove `embedded.mobileprovision` from every bundle before signing; bundles/IPAs only, ignored for bare Mach-O |
| `-e, --entitlements` | path | Custom entitlements file (replaces the profile's entitlements) |
| `--entitlements-dir` | path | Directory of per-bundle-id entitlements (`<dir>/<bundle-id>.plist`); falls back to the profile when no file matches |
| `-p, --password` | string | Password for PKCS#12 or key material (empty password is valid); beats `ZSIGN_PASSWORD`; prefer the env var — argv values are visible in process listings. Env: `ZSIGN_PASSWORD` (value hidden from help/errors) |
| `-z, --zip-level` | 0–9 | ZIP compression level, default `6` (`0` = no compression, matches C++ zsign; `9` = slowest/smallest); out-of-range is a usage error, never clamped |
| `-b, --bundle-id` | id | New bundle identifier (`CFBundleIdentifier`) |
| `-n, --bundle-name` | name | New display name (`CFBundleDisplayName`) |
| `-r, --bundle-version` | version | New short version (`CFBundleShortVersionString`) |
| `-2, --sha256-only` | — | Emit only the SHA-256 code directory (the modern default) |
| `-L, --legacy-sha1` | — | Legacy SHA-1 + SHA-256 dual code directories (iOS <= 10 only); conflicts `-2` |
| `-f, --force` | — | Override the FairPlay-encryption refusal and sign encrypted binaries anyway (already-decrypted input only) |
| `-a, --adhoc` | — | Sign without an identity (ad-hoc); conflicts `-m`, `-C`, `-V` |
| `-l, --dylibs` | path | Dylib load path to inject (repeatable) |
| `-w, --weak` | — | Inject dylibs as `LC_LOAD_WEAK_DYLIB` |
| `-C, --check-revocation` | — | OCSP revocation **warning** (semantics below); conflicts `-V`, `-a` |
| `-V, --verify` | — | Verify like `codesign --verify --deep --strict`; conflicts with every signing option (clap rejects each pairing at parse time) |
| `--json` | — | Machine-readable JSON output (documented below); works in both signing and verify modes |
| `-h, --help` | — | Print help (there is no `--version` flag) |

`zsign-cli` prints an `upstream users: -p/-k now match upstream; --pkcs12 is long-only`
epilog after the option list — see the migration section below.
````

- [ ] **Step 3: Verify every table row against the binary**

Run: `target/debug/zsign-cli --help` and diff the flag set against the table
(25 options + `-h`; no others). Spot-check three conflict errors live:

```bash
target/debug/zsign-cli -a -m p in.bin; echo $?    # exit 2, adhoc/profile conflict
target/debug/zsign-cli -C -V in.bin;  echo $?    # exit 2, check-revocation/verify
target/debug/zsign-cli -k k -2 -L in.bin; echo $? # exit 2, sha256-only/legacy-sha1
```

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs: document the complete cli flag surface"
```

---

### Task 4: README — contracts: exit status, `--json`, password, `-C`, keychain

**Files:**
- Modify: `README.md` — keep the existing `#### Verify a signed binary, bundle, or IPA`
  description paragraph and its three `-V` examples verbatim (audit: verified true),
  but **delete** the trailing `Exit status: \`0\` valid…` sentence (stale: omits sign
  semantics, the report-based exit-2 class, and clap's usage exit) and insert the
  sections below after the verify subsection.

- [ ] **Step 1: Insert the exit-status contract (replaces the deleted sentence)**

````markdown
### Exit status

| Code | Signing | `--verify` |
|---|---|---|
| `0` | signed successfully | verification completed, input **valid** |
| `1` | any signing or credential failure | verification completed, input **invalid** (issues printed) |
| `2` | usage/parse errors (clap) | could not complete — unreadable/unsupported input, or a report with top-level errors (e.g. a slot that cannot be verified without bundle context); also usage/parse errors (clap) |

- With `--json`, failures are JSON objects on **stderr**
  (`{"status":"error","error":"…"}`); clap usage errors stay human-readable by design.
- The report-based exit-2 class applies to bare-Mach-O inputs; bundle/IPA problems are
  completed-negative verdicts exiting `1`.
- Sign failures deliberately stay `1` so they remain distinguishable from clap's
  hardcoded usage exit `2`
  (`docs/superpowers/specs/2026-09-25-cli-surface-design.md`).
````

- [ ] **Step 2: Insert the JSON schema section**

````markdown
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
````

- [ ] **Step 3: Insert the password-channel section**

````markdown
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
````

- [ ] **Step 4: Insert revocation + keychain subsections**

````markdown
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
````

- [ ] **Step 5: Verify contract claims against the binary/source**

```bash
target/debug/zsign-cli -V --json nonexistent.bin; echo $?   # 2, {"status":"error",…} on stderr
target/debug/zsign-cli; echo $?                             # 2, human usage error
grep -n 'ExitCode::from' crates/zsign-cli/src/main.rs       # matches the table rows
```

- [ ] **Step 6: Commit**

```bash
git add README.md
git commit -m "docs: document exit status, json schema, and password channels"
```

---

### Task 5: README — migration, deterministic output, WASM

**Files:**
- Modify: `README.md` — insert `## Migrating from upstream zsign` and
  `## Deterministic output` after the CLI-reference subsections (before
  `## Building`); replace the existing `### WASM (Browser)` section wholesale.

- [ ] **Step 1: Insert the migration section**

````markdown
## Migrating from upstream zsign

`zsign-cli` restores upstream flag meanings where it could, and diverges deliberately
elsewhere (contract: `docs/superpowers/specs/2026-09-25-cli-surface-design.md`):

| Flag | Upstream zsign | zsign-rs |
|---|---|---|
| `-p/--password` | password string | **now the password too** — in zsign-rs it was the PKCS#12 path short until 0.1.x; also reads `ZSIGN_PASSWORD` |
| `-k/--private-key` | PEM or DER key (PKCS#12 tried last) | PEM / DER / PKCS#12 **detected by content**; use `-k` alone for PKCS#12 |
| `--pkcs12` | — | the PKCS#12 path flag, **long-only** (no `-p` short anymore) |
| `-z/--zip-level` | 0–9, default `0`, rejects out-of-range | 0–9, **default `6`**, rejects out-of-range (never clamps) |
| `-f/--force` | bypass the folder re-sign cache | override the FairPlay-encryption refusal (zsign-rs has no cache layer) |
| `-C` | standalone certificate report whose exit codes scripts may depend on | **warning-only** OCSP probe while signing; never gates |
| exit codes | `0` / catch-all `255` | `0` / `1` / `2` contract above |

There is no compatibility shim: old `zsign-cli -p cert.p12 …` invocations fail loudly
at parse time. `zsign-cli --help` ends with the same reminder:
`upstream users: -p/-k now match upstream; --pkcs12 is long-only`.

Upstream flags with **no** zsign-rs equivalent: `-d -q -i -t -D -x -I -S -M -E -W -U
-P -v` (debug dumps, quiet, ideviceinstaller install, temp folder, dylib removal,
metadata/icon extraction, Files-app toggles, MinimumOSVersion, extension/watch/
UISupportedDevices cleanup, extension injection, version print), plus the
`.zsign_cache` fast re-sign layer. zsign-rs extensions with no upstream counterpart:
`--pkcs12`, `--keychain-identity`, `--profile-map`, `--entitlements-dir`, `--json`,
`-V/--verify`, `ZSIGN_PASSWORD`.

**Versioning:** the `-p`/`-k` re-meaning is a breaking CLI change; the next release
bumps the pre-1.0 crates from 0.1.x to **0.2.0** (manifest versions change at release
time, not with this documentation).
````

- [ ] **Step 2: Insert the determinism section**

````markdown
## Deterministic output

Signing the same input twice produces byte-identical output. The mechanisms:

- **Sorted zip entries** — archive names sorted bytewise (parents before children,
  `Payload/` first, pass-through roots like `SwiftSupport/` included) in
  `crates/zsign/src/ipa/archive.rs`.
- **Pinned timestamps** — every zip entry carries 1980-01-01 (`zip::DateTime::default()`).
- **Deterministic signatures** — RFC 6979 ECDSA nonces and PKCS#1 v1.5 RSA; adding a
  `signingTime` attribute or moving ECDSA to a randomized signer is rejected by tests
  (contract in `crates/zsign-core/src/crypto/cms.rs`). Upstream zsign inherits OpenSSL's
  randomized nonce, so its output is not reproducible run to run.
- **Ordered structures** — CodeResources files live in a `BTreeMap`; error lists are
  sorted; the wasm build uses a pinned clock (cert-validity checks only).

Pinned by tests: `test_create_ipa_writes_entries_in_sorted_order`,
`test_create_ipa_from_root_is_byte_identical_across_creation_order`,
`cms_ecdsa_signature_is_byte_identical_five_times`,
`sign_macho_ecdsa_is_byte_identical_twice`, and `test_ipa_signing_is_deterministic`
— the CI debug test job runs the full suite, this test included.
````

- [ ] **Step 3: Replace the `### WASM (Browser)` section**

````markdown
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
  `sign_ipa` adds no new codes: a malformed archive maps to `ZSIGN_SIGNING_FAILED`,
  cap violations to `ZSIGN_INPUT_TOO_LARGE`.
- **Memory:** peak ≈ input + uncompressed tree + output plus per-file working set;
  linear memory never shrinks, so a large sign leaves a per-tab watermark — use a
  desktop-class browser above ~100 MiB inputs.
- Contract: `docs/superpowers/specs/2026-09-26-wasm-ipa-bytes-design.md`.

The fine-grained per-entry API remains available and is what `examples/web`
demonstrates: `hash_file`/`hash_file_chunk`, `build_code_resources`, `sign_macho`
(SHA-256-only, thin input — FAT input is rejected), `sign_macho_fat` (the explicit
dual SHA-1+SHA-256 opt-in for FAT/Universal input), `parse_macho`, `parse_info_plist`.
````

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs: document migration, determinism, and the wasm surface"
```

---

### Task 6: README — building, development/testing, key concepts, license

**Files:**
- Modify: `README.md` — `## Building` (wasm line), `## Development` (replace),
  `### Key Concepts Implemented` (add rows), `## License` (replace).

- [ ] **Step 1: Building section — update the wasm line**

Replace `wasm-pack build crates/zsign-wasm --target web` with:

```bash
wasm-pack build crates/zsign-wasm --target web --release
```

(That is what CI runs: `.github/workflows/examples-web.yml`.)

- [ ] **Step 2: Replace `## Development`**

````markdown
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

**Tests:** 739 passing, 0 failing, 13 ignored as of 2026-09-27 — 678 unit tests
(zsign-cli 46, zsign-core 433, zsign-rs 188, zsign-wasm 11) plus 61 doctests. The
ignored doctests need real key material; one ignored test streams >4 GiB. Run the
suite with `cargo test`; keep `TMPDIR` inside the worktree if `/tmp` is tight.

**CI** (`.github/workflows/`): `ci.yml` runs lint (`hk`), the debug test job
(`cargo test --workspace`, full suite), a release-profile test job, Windows
`cargo check`, wasm check/build/`wasm-pack test --node`, the macOS
`codesign --verify --deep --strict` interop (`scripts/verify-apple-interop.sh`),
`cargo-deny`, and an MSRV 1.88 check. Separate workflows: weekly fuzz smoke, weekly
web-example build, and tag-gated crates.io/npm publishing.
````

- [ ] **Step 3: Extend `### Key Concepts Implemented`**

Add these rows to the existing table (existing rows stay — all seven resolve):

| Concept | Implementation |
|---------|----------------|
| CMS Verification | `zsign-core::crypto::cms_verify` — Apple-order checks + trust anchoring |
| Revocation (OCSP) | `zsign-core::crypto::revocation` — warn-only probe, 3s budget |
| macOS Keychain | `zsign-core::crypto::keychain` — `security` shell-out + identity selector |
| Full verification (`-V`) | `zsign::verify` — bundle/Mach-O/IPA report engine |

- [ ] **Step 4: Replace the `## License` paragraph**

````markdown
## License

MIT, as declared in the crate manifests (`license = "MIT"` in each
`crates/*/Cargo.toml`). This project ports [zhlynn/zsign](https://github.com/zhlynn/zsign),
which is MIT-licensed.
````

(Stale claim removed: the old text pointed at a root `LICENSE` file that does not
exist in this tree; adding one is an orchestrator decision, recorded in the final
report.)

- [ ] **Step 5: Commit**

```bash
git add README.md
git commit -m "docs: refresh build, test, and license sections"
```

---

### Task 7: Cross-check, scoped gates, final commit

- [ ] **Step 1: Stale-claim sweep**

```bash
grep -n 'two crates\|use zsign::\|x509-certificate\|cryptographic-message-syntax\|--skip test_ipa_signing\|zsign -V.*trustworthy' README.md AGENTS.md
```
Expected: no matches (exit 1). Also grep for any leftover `Modules:` list in
AGENTS.md and any flag in README not present in `target/debug/zsign-cli --help`.

- [ ] **Step 2: Verify documented commands actually run**

```bash
target/debug/zsign-cli --help                                    # table matches, exit 0
cargo metadata --no-deps --format-version 1 | grep -o '"name":"[^"]*"' # package names
mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo build -p zsign-cli  # 0 warnings
```
Spot-check every conflict pair cited in the flag table against live exit-2 errors
(rows `-a`/`-m`, `-C`/`-V`, `-2`/`-L`, `--pkcs12`/`-c`, `--keychain-identity`/`-k`).

- [ ] **Step 3: Scoped gates (unweakened — no `--skip`)**

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test --workspace --no-fail-fast
```
All three must exit 0. If the known release-flake test fails in this run, fix nothing
docs-side: report it verbatim in the final report (the fix belongs to the owning lane).

- [ ] **Step 4: Final commit (if the sweep produced fixes)**

```bash
git add README.md AGENTS.md
git commit -m "docs: apply cross-check fixes to readme and agents"
```

---

## Self-review

- **Spec coverage:** brief items 1 (AGENTS) → Task 1; 2a flag table → Task 3; 2b exit
  status → Task 4; 2c JSON → Task 4; 2d password → Task 4; 2e migration/semver →
  Task 5; 2f WASM → Task 5; 2g capabilities (32-bit → Task 2 Step 4; OCSP/keychain →
  Task 4 Step 4; determinism → Task 5 Step 2); 2h crypto boundary → Task 2 Step 3;
  2i test/quality → Task 6; item 3 cross-check → Task 7.
- **Placeholders:** none — every section carries its full target text.
- **Gate integrity:** no skip flags, no thresholds moved; README never presents the
  release-CI skip as a contributor instruction.
