# zsign-rs

A Rust implementation of [zsign](https://github.com/zhlynn/zsign) — a cross-platform iOS code signing tool.

> **Note**: This is a learning project porting the original C++ implementation to Rust. It aims to provide the same functionality while leveraging Rust's safety guarantees and modern tooling.

## Overview

zsign-rs signs iOS application packages (IPA files) and Mach-O binaries on macOS, Linux, and Windows. It provides an alternative to Apple's official `codesign` utility, enabling iOS app signing outside of the macOS ecosystem.

### Features

- **IPA Signing** — Re-sign existing IPA files with new certificates and provisioning profiles
- **Bundle Signing** — Sign `.app` folders and nested bundles (frameworks, extensions)
- **Mach-O Support** — Handle single-architecture and FAT/Universal binaries
- **Cross-Platform** — Works on macOS, Linux, and Windows
- **Multiple Certificate Formats** — PKCS#12 (`.p12`) and PEM support
- **Dual Hash Generation** — SHA-1 (legacy) and SHA-256 code directories

## Architecture

```
zsign-rs/
├── crates/
│   ├── zsign/           # Core library
│   │   ├── builder      # High-level signing API (ZSign)
│   │   ├── bundle       # App bundle handling, CodeResources generation
│   │   ├── codesign     # Code signature structures (CodeDirectory, SuperBlob)
│   │   ├── crypto       # Certificate parsing, CMS signature generation
│   │   ├── ipa          # IPA archive extraction and creation
│   │   └── macho        # Mach-O binary parsing and signing
│   └── zsign-cli/       # Command-line interface
```

### Module Overview

| Module | Description |
|--------|-------------|
| `macho` | Parses Mach-O binaries, handles FAT archives, extracts load commands and segments |
| `codesign` | Builds CodeDirectory blobs with page hashes, assembles SuperBlob containers |
| `crypto` | Loads certificates/keys, generates CMS signatures with Apple-specific attributes |
| `bundle` | Traverses app bundles, generates CodeResources plist with file hashes |
| `ipa` | Extracts and creates IPA archives (ZIP format) |
| `builder` | High-level `ZSign` API orchestrating the signing workflow |

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
    .sign_ipa("input.ipa", "output.ipa")?;
```

### CLI

```bash
zsign-cli sign \
    --cert certificate.p12 \
    --password "password" \
    --provision app.mobileprovision \
    --output signed.ipa \
    input.ipa
```

## Building

```bash
# Build all crates
cargo build --release

# Run tests
cargo test

# Generate documentation
cargo doc --open
```

## Learning Resources

This project serves as a learning exercise for:

- **Mach-O Binary Format** — Understanding Apple's executable format
- **Apple Code Signing** — How iOS verifies app integrity
- **Cryptographic Signatures** — CMS/PKCS#7 signature generation
- **Rust Systems Programming** — Binary parsing, memory safety, FFI patterns

### Key Concepts Implemented

| Concept | Implementation |
|---------|----------------|
| Mach-O Parsing | `macho::parser` — Load commands, segments, FAT headers |
| Code Hashing | `codesign::code_directory` — Page hashing, special slots |
| Blob Structures | `codesign::superblob` — Apple's nested blob format |
| DER Encoding | `codesign::der` — Entitlements plist to DER conversion |
| CMS Signatures | `crypto::cms` — Apple-specific signed attributes |
| Certificate Handling | `crypto::cert` — PKCS#12, PEM, X.509 parsing |

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
