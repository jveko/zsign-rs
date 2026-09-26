# Design: 32-bit Mach-O signing + macOS keychain identities (ZSN-17, ZSN-19)

- **Lane:** zsn44-smalls · **Branch:** zsn44-smalls · **Date:** 2026-09-26
- **Status:** pre-implementation design; sources cited as `file:line` against this worktree
- **Scope:** exactly two tickets; wasm crate, `builder.rs`, `ipa/**`, README are owned by parallel lanes (seams in §4)

## 1. Context

The writer rejects every 32-bit Mach-O with a bare `Error::MachO("32-bit Mach-O binaries not supported")`, and credentials can only come from p12/PEM files. This design records the evidence-led decision for each ticket: ZSN-17 gets **real little-endian 32-bit signing support** (not merely a typed rejection), ZSN-19 gets **keychain identity loading by shelling out to `/usr/bin/security`** behind a new `--keychain-identity` flag.

## 2. ZSN-17 — Decision: implement LE 32-bit signing support

### 2.1 Evidence

| Fact | Source |
|---|---|
| Six explicit guards reject `!is_64` before any mutation | `crates/zsign-core/src/macho/writer.rs:131-136`, `:521-524`, `:1074-1077`, `:1174-1176`, `:1315-1317`, `:1434-1436` |
| Parser already parses 32-bit and records `is_64=false`; armv7 fixture test exists | `macho/parser.rs:236`, `:360`, `:703-741` |
| `linkedit_cmd` metadata is a width-neutral tuple `(offset, fileoff, vmsize, filesize)`; only the `Segment32` capture arm is missing | `macho/parser.rs:58`, populated at `:282-285` (Segment64) vs `:290-303` (Segment32, no capture) |
| Header-size ternaries 32/28 already written but unreachable | `macho/writer.rs:216`, `:1247` |
| Manual load-command walker already has a correct LC_SEGMENT (32-bit) arm | `macho/writer.rs:787-822` |
| `LC_CODE_SIGNATURE` is byte-identical 16-byte `linkedit_data_command` both widths | xnu `EXTERNAL_HEADERS/mach-o/loader.h:1192-1202` (goblin `SIZEOF_LINKEDIT_DATA_COMMAND=16`) |
| Header 28 vs 32 B; `segment_command` u32 fields at `vmaddr@24 vmsize@28 fileoff@32 filesize@36`; `segment_command_64` u64 at `vmaddr@24 vmsize@32 fileoff@40 filesize@48`; cmdsize multiple-of-4 vs multiple-of-8 | `loader.h:54-85`, `:355-388`, `:238-241` |
| CodeDirectory has no bitness field; one emission path for both widths | ldid.cpp `:1118-1149`, `:2664-2682`; upstream zsign `src/signing.cpp:449-494` |
| Signer itself has zero bitness logic; verify path has no 64-bit assumption | `macho/signer.rs` (is_64 only re-armed at `:475`, `:609`); `macho/verify.rs:130+`, `:492-512` |
| Upstream zsign signs 32-bit end-to-end (LC_SEGMENT arms, header-size ternary) | zhlynn/zsign `src/archo.cpp:37-96`, `:615-648` |
| ldid signs 32-bit end-to-end (its only TODO is the opposite direction: fat_arch_64) | ldid.cpp `:841-894`, `:942-961`, `:1596` |
| goblin 0.10.7 fully parses 32-bit (`mach32` default feature; `Segment32`, `Header32`) | `crates/zsign-core/Cargo.toml:12`, goblin src `mach/mod.rs:39-46`, `load_command.rs:1421-1423` |
| FAT reassembly, page hashing, superblob, CMS are bitness-agnostic; failure today is pre-mutation (thin) and all-or-nothing (FAT: rayon `collect::<Result<Vec<_>>>()` before embed) | `macho/writer.rs:378-517`; `macho/signer.rs:444`; `builder.rs:470` writes only after `Ok` |
| iOS dropped 32-bit apps at iOS 11; legacy/jailbreak re-signing and old FAT IPAs remain the realistic 32-bit inputs | support.apple.com/en-us/102991; upstream README targets "iOS 12+" |

### 2.2 Supported subset (precise)

- **Sign:** little-endian 32-bit Mach-O (`MH_MAGIC`, e.g. armv7/i386), thin and as FAT slices alongside 64-bit slices, through every writer entry point the ticket exposes: realloc, prepare, embed, and dylib injection.
- **Reject with typed, actionable error:** big-endian 32-bit (`MH_CIGAM`) — message names `big-endian` and points at the little-endian/64-bit alternatives. Shared helper `ensure_signable_bitness(is_64, is_big_endian)` replaces the six bare guards.
- **Unchanged status quo:** `MH_CIGAM_64` (big-endian 64-bit) keeps passing exactly as today — untested before, untested after, out of scope.
- 64-bit behavior byte-identical; existing suite green.

### 2.3 Behavior pins (acceptance)

- **P1** thin LE armv7 fixture → `sign_macho*` succeeds; zsign's own `verify_macho` reports valid; output still has 32-bit magic and an `LC_CODE_SIGNATURE`.
- **P2** FAT `[armv7, arm64]` (built with existing `make_fat_macho`) → both slices signed, container verifies; failure semantics stay all-or-nothing (no partial output).
- **P3** two layers pin the typed rejection: the `ensure_signable_bitness(false, true)` unit call returns an error whose text contains `big-endian`, AND an end-to-end attempt on a big-endian 32-bit fixture (`make_minimal_macho_32_be`, `MH_CIGAM`) through `sign_any_macho` fails with `Error::MachO` containing `big-endian` (replacing the bare one).
- **P4** dylib injection (`inject_dylib_command`) succeeds on a thin 32-bit input and on a 32-bit FAT slice.
- **P5** no bare `32-bit Mach-O binaries not supported` string remains anywhere in `crates/`.
- **P6** `cargo test --workspace --no-fail-fast` green (no skips).

### 2.4 Rejected alternatives

- **Typed rejection only** (bare error → nicer error): smallest diff, but research shows support is narrow (§2.1) and rejecting would regress FAT `armv7+arm64` inputs that upstream zsign and ldid both handle — the exact legacy-FAT case the ticket calls realistic. The dead 32/28 ternaries and the existing LC_SEGMENT walker show the codebase was already shaped for this.
- **FAT-partial (sign 64-bit slices, skip 32-bit):** produces a container with unsigned slices — a silent semantic change to the output (and `verify --deep` would fail on it). All-or-nothing failure is more honest; not chosen.

### 2.5 Error surface decision

No new `zsign_core::Error` variant. `zsign-wasm`'s `code_for_core_error` is a documented exhaustive match with no wildcard (`crates/zsign-wasm/src/lib.rs:110-127`), so a new variant would force an edit in `crates/zsign-wasm/**` — owned by parallel lane zsn43. The typed rejection therefore lives in `Error::MachO(String)` with precise, pinned text (precedent: `EncryptedBinary` shows narrow messages already ride existing variants), keeping zero cross-lane seams.

### 2.6 Known risks

- [INFERENCE] Real-device acceptance of a signed armv7 image on legacy iOS cannot be exercised here; the in-repo guarantee is structural round-trip through zsign's own verify, which is the same guarantee 64-bit inputs have.
- Exec-segment CodeDirectory flags for 32-bit images are emitted from the same filetype-keyed logic as 64-bit (`signer.rs:831-835`); upstream zsign emits the same values from both parser arms (`archo.cpp:66/:74`).

## 3. ZSN-19 — Decision: shell out to `/usr/bin/security`

### 3.1 Evidence

| Fact | Source |
|---|---|
| `find-identity -v -p codesigning` output: `  N) <40-hex SHA-1> "<CN>"` lines + `N valid identities found`; indent varies, summary never matches line regex | security(1) man (macOS 13/15/26); OWASP MASTG-TECH-0079 capture; Chromium `find_signing_identity.py:47-52`; dinghy `xcode.rs:90` regex `^ *[0-9]+\) ([A-Z0-9]{40}) "(.+)"$` |
| The 40-hex is the signing certificate's SHA-1 (same as `find-certificate -Z`) | Chromium/fastlane usage; librarian corroboration |
| `security export -t identities -f pkcs12 -P <pw> -o <file>` exports **all** identities, never one; no `security` verb selects a single pair | security(1) export synopsis; rcodesign docs `apple_codesign_certificate_management.rst:234-241` |
| Established Rust pattern: shell out, parse, then use name/hash — dioxus (39k★), OpenLogi (22k★), nikivdev/code (21k★), makepad, dinghy, fluxer; 172 GitHub hits | GitHub code search `find-identity language:rust` |
| `security-framework` fits poorly: `SecKey` is an opaque handle (rcodesign returns `private_key_data() -> None`), no PKCS#12 export wrapper (raw FFI only), no code-signing policy, CMS module is S/MIME-flavoured, maintenance badge "looking-for-maintainer" | security-framework `identity.rs:22-61`, `key.rs:254`; apple-codesign `macos.rs:146-175`, `import_export.rs:84`; crates.io stats 378M downloads but badge status |
| `security cms -S` cannot carry Apple's `cdhashes` signed attribute → cannot mint a valid code-signature CMS blob | [INFERENCE from documented option set]; rejected |
| `/usr/bin/security` ships since Mac OS X 10.3; GitHub-hosted macOS runners use it unmodified | security(1) HISTORY; GitHub Actions docs "Installing an Apple certificate on macOS runners" |
| ldid never touches keychains (p12/PKCS#11 only); ios-app-signer shells to `/usr/bin/security` but delegates signing to `codesign`; upstream zsign has no keychain support at all | ldid.cpp symbol grep; `MainView.swift:57/:261-268`; zhlynn/zsign README `:100-110` |
| Existing credential checks all run inside `from_p12` (SPKI pairing, RSA≥2048, code-signing policy incl. expiry, chain build, team id) | `crypto/cert.rs:603-623` |

### 3.2 Flag design

`--keychain-identity <NAME_OR_HASH>` (long-only, `Option<String>`, no short — mirrors the long-only `--pkcs12` precedent; `-k` scheme-reuse rejected: content-sniffing an identity string through a path flag is dishonest at parse time).

- Added to the `credentials` `ArgGroup` (`main.rs:19-21`, stays `.multiple(true)`), so `required_unless_present_any = ["adhoc", "verify", "credentials"]` on `-k`/`--pkcs12` accepts it as the credential source.
- `conflicts_with_all = ["pkcs12", "certificate", "private_key"]` on the new flag (same one-directional declaration style `pkcs12` already uses, `main.rs:40`).
- Appended to `-V`'s explicit 19-name `conflicts_with_all` list (`main.rs:152-171`).
- Help text names the producer command: `macOS keychain codesigning identity (name or SHA-1 hash from security find-identity -v -p codesigning)`.
- Not in conflict with `-a/--adhoc` or `-p/--password`: consistent with how `-k` behaves today (parses, unused when adhoc); `-p`/`ZSIGN_PASSWORD` is simply not consulted on the keychain path.

### 3.3 Loading flow (macOS)

1. `crypto::keychain::load(identity)` runs `/usr/bin/security find-identity -v -p codesigning`.
2. Pure parser (cross-platform `&str` fn) yields `Vec<IdentityLine { hash: [u8;20], name: String }>`; selector resolves `<NAME_OR_HASH>`: 40-hex → case-insensitive hash match; otherwise exact name match; 0 matches → error listing available identities; >1 → error listing candidate hashes (mirrors the `from_p12` ambiguity style at `cert.rs:319-323`). Summary/noise lines fail the line shape and are skipped; a trailing marker after the closing quote (e.g. `[REVOKED]`) is excluded from the extracted name — harmless in practice because the command always runs with `-v`, which lists only valid identities (the fixture pins both behaviors).
3. `/usr/bin/security export -t identities -f pkcs12 -P "" -o <temp>` (export-all; **cannot select one** — see §3.1). Temp file: `std::env::temp_dir()` (honors `TMPDIR`) + pid + counter; read; best-effort `remove_file` on all paths.
4. `SigningCredentials::from_p12` path with a leaf-certificate SHA-1 selector: `from_p12`'s post-selection tail (RSA ≥ 2048 gate, code-signing policy, chain build, team id) is extracted into a shared private `finish_p12(decoded, certificate, rest)`; the new `from_p12_with_leaf_sha1(data, pw, hash)` partitions certBags by SHA-1 (the find-identity hash), runs the existing `select_identity` pairing on the matched subset, then rebuilds `rest` from every non-matching certificate so the export-provided chain still feeds `build_chain_from_leaf`. Every load-time check (§3.1 last row) runs on the selected pair — no check bypass is possible by choosing this source.
5. Exported container contains *all* identities; the SHA-1 filter reduces it to the selected pair (its chain certs stay as `rest` for `build_chain_from_leaf`). Zero-match after filtering → `Error::Certificate` naming the hash and the cause.

### 3.4 Error design

Module-local `KeychainError` (`thiserror`) in `crypto/keychain.rs` — again to keep the wasm exhaustive match untouched (§2.5). Variants: `MacOsOnly` (typed non-macOS error naming `--keychain-identity` and macOS), `CommandFailed { tool, status, stderr }`, `NoIdentities`, `Ambiguous { … }`, `NotFound { … }`. It implements `std::error::Error`, so the CLI's `Box<dyn Error>` path prints it through the existing `emit_error` (`main.rs:546-560`) and exits 1. Failures *inside* credential construction keep flowing as `zsign_core::Error` from `from_p12`.

### 3.5 Platform behavior & cfg gating

- `crypto/mod.rs` declares `#[cfg(not(target_arch = "wasm32"))] pub mod keychain;` — never compiled into the wasm surface.
- Inside `keychain.rs`: pure parser + selector compile on **all** non-wasm targets (Linux CI included); the exec/export step is `#[cfg(target_os = "macos")]`; the non-macOS native branch of `load()` returns `KeychainError::MacOsOnly` before any exec. Running `cargo check` on Linux must stay clean (recorded in final report).
- Zero new dependencies (std `process::Command` is the first production spawn; test-code precedent `main.rs:1083`, `:1108`).

### 3.6 Test strategy

- **Linux-runnable (all CI):**
  - canned `security find-identity` outputs as `crates/zsign-core/src/crypto/fixtures/find-identity-*.txt` via `include_str!` (zsn37 recipe: committed fixtures anchored to themselves) — parse/select: happy path, ragged indent, summary line, zero identities, duplicate names (ambiguous), hash case-insensitivity, no-match listing.
  - `from_p12` selector: reuse the committed multi-identity `IDENTITY_DUP` fixture (`cert.rs:981`) — select identity A by SHA-1 → loads; wrong hash → typed Certificate error (red pre-refactor).
  - CLI: parse-time conflicts (`--keychain-identity` × `-k`/`-c`/`--pkcs12`/`-V`) asserting `ErrorKind::ArgumentConflict` in the `parse_err` style (`main.rs:1673-1678`); `--keychain-identity` alone satisfies `required_unless_present_any`; `run()` on Linux returns the `MacOsOnly` message (assert substring `macOS`), exit 1.
- **macOS-gated (recorded, NOT run on this Linux machine):** `#[cfg(target_os = "macos")]` integration test in `keychain.rs`: executes `find-identity` live; asserts parse succeeds; if ≥1 identity exists, completes export → `from_p12` selector → credentials (exercising the full check chain). Skips gracefully (test still passes) when the machine has zero identities.
- **macOS CI job recipe** (for the CI lane; recorded here and in the final report):
  ```bash
  # GitHub-documented flow on runs-on: macos-latest
  security create-keychain -p ci-pass zsign.keychain-db
  security import fixtures/ci-identity.p12 -t cert -f pkcs12 -k zsign.keychain-db -P "$P12_PW" -A
  security list-keychain -d user -s zsign.keychain-db
  cargo test -p zsign-core keychain   # cfg(macos) tests execute live find-identity/export
  ```
  Requires a CI-held identity p12 (secret) — provisioning is out of this lane's scope; without it the cfg(macos) test still validates live listing/parsing.

### 3.7 Rejected alternatives

- **`security-framework` crate:** §3.1 — opaque `SecKey` cannot produce the concrete `rsa`/`p256` keys the RustCrypto `cms` builder requires, so adoption means trait-refactoring the whole CMS path plus a target-gated dependency in the wasm-first core crate; also no single-identity export helper (raw FFI) and no code-signing policy binding.
- **`security cms -S` for the CMS blob:** cannot emit Apple's code-signing signed attributes; wrong tool.
- **Export-all then *no* selector (feed straight to `from_p12`):** fails on any machine with >1 codesigning identity via the existing ambiguity rejection — unacceptable UX for the primary feature.
- **Scheme-reuse of `-k`:** rejects at content-sniffing time, keeps `-k` a path type, and cannot express hash selection; less honest than a dedicated flag.

### 3.8 Credential-policy coverage & gaps (seams)

- **Covered:** SPKI pairing, RSA ≥ 2048, code-signing EKU/KU/basicConstraints, validity (not-before/expiry), chain build with embedded WWDR/Apple roots, team-id — all run identically because the source converges on `from_p12` (§3.3.4). The weak-key and policy gates are additionally *proven* end-to-end through the selector by tests on the existing `WEAK_RSA1024` and non-policy `modern_pbes2_aes256.p12` fixtures; expiry is the same `code_signing_policy_violation` call already exercised directly by the existing validity tests (`cert.rs:474-489`).
- **Gap 1 (seam):** non-exportable / token-backed keys cannot be exported by `security export` (mechanism: `import -x`; error text undocumented); ldid solves this with PKCS#11 (`-K pkcs11:…`) — out of scope, documented.
- **Gap 2 (seam):** first use of a key may trigger a GUI ACL/passphrase prompt (CI recipes answer it with `security set-key-partition-list`); headless runs pass `-P ""` so only the key ACL can prompt. Live behavior unverifiable on Linux — [INFERENCE] flagged honestly.
- **Gap 3 (seam):** which keychain the export searches is the default search list — same list `find-identity` used, so selection and export stay consistent by construction.
- **Gap 4 (seam):** the export temp file (containing unencrypted key material) is removed best-effort on every path, but a process kill or a failing `remove_file` can leak it (worst case under a world-readable `$TMPDIR`); hardening options (private 0700 directory, `create_new` placeholder) recorded as a follow-up — no correctness defect.

## 4. Cross-lane seams & deferred needs

- **Lane zsn43 (zero overlap):** no edits to `crates/zsign-wasm/**`, `crates/zsign/src/ipa/**`, or `builder.rs` are required by this design (no new core `Error` variant; keychain module is cfg-gated off wasm). If implementation discovers a needed one-liner there, it will be reported as a seam, not edited.
- **Docs lane (wave-7):** README notes for 32-bit support and `--keychain-identity` (incl. macOS-only behavior + `security find-identity` discovery hint) — record only.
- **ZSN-30 (wave 7):** new fixtures follow current patterns (`crypto/fixtures/*.txt`, `macho/fixtures.rs` builders) and are flagged for later consolidation.
