# AGENTS.md — zsign-rs

## Build & Test
- Tooling: `mise install` installs pinned tools (hk, actionlint) from `mise.toml` and registers git hooks
- Hooks: `hk` — pre-commit (file hygiene, `cargo fmt`, actionlint), pre-push (`cargo clippy --workspace --all-targets -- -D warnings`); manual runs: `hk check --all`, `hk fix`
- Build: `cargo build --release`
- Test all: `cargo test`
- Test single: `cargo test -p zsign-rs test_name` or `cargo test -p zsign-cli test_name`
- Check: `cargo check` | Lint: `cargo clippy` | Docs: `cargo doc --open`

## Architecture
Rust workspace with two crates:
- **`zsign-rs`** (`crates/zsign/`) — Core library for iOS code signing (Mach-O parsing, CodeDirectory/SuperBlob generation, CMS signatures, app bundle traversal, IPA archive handling)
  - Modules: `macho` (binary parsing/signing), `codesign` (blobs, CodeDirectory, DER), `crypto` (certs, CMS), `bundle` (CodeResources), `ipa` (extract/create), `builder` (high-level `ZSign` API)
- **`zsign-cli`** (`crates/zsign-cli/`) — CLI using `clap` derive, single `main.rs`

## Code Style
- Edition 2021, `thiserror` for error enums, `crate::Result<T>` alias throughout
- Doc comments (`///` and `//!`) on all public items with examples
- Tests: inline `#[cfg(test)] mod tests` per file, not separate test files
- Key deps: `goblin` (Mach-O), `zip` (IPA), `plist`, `sha1`/`sha2`, `rayon` (parallelism), RustCrypto ecosystem (`rsa`, `p256`, `pkcs8`, `der`, `x509-certificate`, `cryptographic-message-syntax`)
- Errors: use `Error::Variant(String)` pattern; use `#[from]` for external error conversions
- Imports: group std, external crates, then `crate::`/`super::` imports
