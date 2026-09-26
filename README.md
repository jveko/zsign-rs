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
use zsign::{ZSign, SigningCredentials};

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

### CLI

```bash
zsign-cli \
    --pkcs12 certificate.p12 \
    --password "password" \
    --profile app.mobileprovision \
    --bundle-id com.example.myapp \
    --output signed.ipa \
    input.ipa
```

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

Exit status: `0` valid, `1` invalid (issues printed), `2` hard error
(unreadable/unsupported input).

### WASM (Browser)

```javascript
import init, { WasmSigner } from 'zsign-wasm';

await init();

const signer = new WasmSigner(p12Bytes, "password", profileBytes);
signer.set_main_executable("App");

// Hash resource files
signer.hash_file("Assets.car", assetData);

// Build CodeResources and sign the binary
const codeResources = signer.build_code_resources();
const signed = signer.sign_macho_fat(machoData, "com.example.app", infoPlist, codeResources);
```

## Building

```bash
# Build all crates
cargo build --release

# Run tests
cargo test

# Build WASM package (requires wasm-pack)
wasm-pack build crates/zsign-wasm --target web

# Generate documentation
cargo doc --open
```

## Development

Tools are pinned with [mise](https://mise.jdx.dev) and git hooks run through [hk](https://hk.jdx.dev):

```bash
mise install        # install pinned tools and register git hooks
hk check --all      # run all lint steps (fmt, clippy, hygiene, actionlint)
hk fix              # auto-fix what hk can
```

Pre-commit runs file hygiene, `cargo fmt`, and `actionlint` on your workflows;
pre-push runs `cargo clippy --workspace --all-targets -- -D warnings`.
The full test suite runs in CI.

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

This project is licensed under the MIT License — see the original [zsign](https://github.com/zhlynn/zsign) project.

## Acknowledgments

- [zhlynn](https://github.com/zhlynn) for the original zsign implementation
- The Rust community for excellent parsing and cryptography libraries
