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
Workspace members (root `Cargo.toml` `members` array; package names in each `crates/*/Cargo.toml`): `crates/zsign-core`, `crates/zsign` (package **`zsign-rs`**), `crates/zsign-wasm`, `crates/zsign-cli`, `fuzz` (`zsign-fuzz`, `publish = false`).

- **`zsign-core`** (`crates/zsign-core/`) — pure engine: `macho` (parse/sign/write; little-endian 32-bit + 64-bit + FAT; big-endian 32-bit rejected with a typed error), `codesign` (CodeDirectory, SuperBlob, DER, verification), `crypto` (certificates, CMS signing **and** verification, OCSP revocation, macOS keychain, encrypted PEM), `bundle` (CodeResources), `provisioning`. Compiles to `wasm32-unknown-unknown`: nothing on the wasm path reaches `std::fs`/`std::net`/`std::thread` — keychain exec, the OCSP transport, and its budget thread are `cfg`-gated off wasm32; rayon is an unconditional dependency and executes sequentially there via its runtime wasm shim (the explicit cfg-gated rayon arms live in the facade's `bundle`/`ipa`).
- **`zsign-rs`** (`crates/zsign/`) — native facade over `zsign-core`: `builder` (high-level `ZSign` API), `bundle`, `ipa` (zip extract/create), `macho` (filesystem wrapper over the core parser), `store` (`Store` trait — stateless `FsStore` ZST + `MemStore`, all-`&self` + `Sync` so rayon closures capture `&S` unchanged), `verify` (the `-V` engine), `error`. Re-exports `codesign`, `crypto`, `SigningCredentials` from core.
- **`zsign-wasm`** (`crates/zsign-wasm/`) — `wasm-bindgen` bindings: `WasmSigner` per-entry CodeResources API plus whole-IPA `sign_ipa` bytes-to-bytes; stable `ZSIGN_*` error codes surface as `error.code` (match via `Reflect`, never string-match messages).
- **`zsign-cli`** (`crates/zsign-cli/`) — single `main.rs`, clap derive; exit contract 0/1/2 and `--json` schema v1 live here.

## Code Style
- Edition 2021, MSRV 1.88, `thiserror` for error enums, `crate::Result<T>` alias throughout
- Module docs (`//!`) are thorough; per-item `///` coverage is expected but uneven — error enums and small accessors are often bare
- Tests: inline `#[cfg(test)] mod tests` per file (exceptions: `fuzz/` binary targets; `#[wasm_bindgen_test]` cases run via `wasm-pack test --node`)
- Error assertions: `assert!(matches!(&res, Err(Error::Variant(m)) if m.contains("…")), "…, got {:?}", res.as_ref().err());` — the `res.as_ref().err()` footer prints the actual failure (dominant pattern, 30+ sites)
- Errors: `#[from]` for external crates, `#[error(transparent)]` wrappers, `Error::Variant(String)` payloads, unit variants for policy failures — all four shapes are in use
- Imports: one `use` block per module, mostly alphabetized; a few files split std/external/`crate::` with a blank line — match the file you are editing
- Key deps: `goblin` (Mach-O), `zip` (IPA), `plist`, `sha1`/`sha2`, `rayon`, RustCrypto (`rsa`, `p256`, `pkcs8`, `der`, `x509-cert`, `cms`), `clap`/`serde`/`serde_json`/`rpassword` (CLI), `wasm-bindgen` (wasm)
