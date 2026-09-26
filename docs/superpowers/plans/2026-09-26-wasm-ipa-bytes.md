# WASM bytes-to-bytes IPA signing implementation plan (ZSN-16)

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development
> with dispatching-parallel-agents for independent tasks. Steps use checkbox
> (`- [ ]`) syntax for tracking.

**Goal:** Deliver `WasmSigner::sign_ipa(input, ...) -> signed IPA bytes` so a
browser signs a complete IPA with no JS glue.

**Architecture:** Candidate A from
`docs/superpowers/specs/2026-09-26-wasm-ipa-bytes-design.md` — a `Store`
trait (`FsStore` = `std::fs` delegator, `MemStore` = rooted in-memory tree),
sign stage generic over the store, bytes extract/repack reusing the pure zip
decision logic, thin wasm binding. Read the design doc first; it pins every
semantic decision (error codes, limits, determinism, symlink bytes).

**Tech Stack:** Rust workspace (`zsign-rs`, `zsign-wasm`), zip 7.2.0 over
`Cursor`, wasm-bindgen 0.2, wasm-bindgen-test.

**Environment:** every cargo/wasm-pack command runs with
`TMPDIR=$PWD/.tmptmp`. Ticket IDs belong in commit subjects, NEVER in code
comments. No stubs/TODOs/placeholders. After each task: scoped verification
only (targeted `cargo test -p ...`), full gates only at the end.

---

### Task 0: Red test first (Tester agent — before any implementation)

**Files:**
- Modify: `crates/zsign-wasm/Cargo.toml` (add `zip = "7.0"` to
  `[dev-dependencies]`, same version/features resolution as the workspace lock)
- Modify: `crates/zsign-wasm/src/lib.rs` (tests module, after the existing
  helpers around `:738-754`)

- [ ] **Step 0.1: Add the failing round-trip test**

Add this test to `crates/zsign-wasm/src/lib.rs` `pub mod tests`
(`lib.rs:627-628`). It is pure Rust, so it uses
`#[wasm_bindgen_test(unsupported = test)]` like the other host-executable
signing tests (`lib.rs:887`):

```rust
    /// Builds a minimal IPA in-test, signs it through the bytes-to-bytes
    /// surface, and verifies the output structurally: archive shape,
    /// CodeResources presence, a verifying main-executable signature,
    /// root-entry pass-through, and re-sign determinism.
    #[wasm_bindgen_test(unsupported = test)]
    fn sign_ipa_round_trip_signs_and_verifies_structurally() {
        let input = build_test_ipa_bytes();
        let signer = new_signer();

        let output = signer
            .sign_ipa(&input, None, None, None, None)
            .expect("bytes-to-bytes IPA signing must succeed");

        // The output is a zip with Payload/ and a signed CodeResources.
        let mut archive =
            zip::ZipArchive::new(std::io::Cursor::new(&output)).expect("output must be a zip");
        let mut code_resources = Vec::new();
        {
            let mut entry = archive
                .by_name("Payload/Test.app/_CodeSignature/CodeResources")
                .expect("CodeResources must be present");
            entry.read_to_end(&mut code_resources).unwrap();
        }
        assert!(!code_resources.is_empty(), "CodeResources must not be empty");
        archive
            .by_name("SwiftSupport/keep.txt")
            .expect("non-Payload root entries must pass through");

        // The main executable carries a signature that verifies against the
        // fixture credential's certificate.
        let main = {
            let mut entry = archive
                .by_name("Payload/Test.app/Test")
                .expect("main executable must be present");
            let mut buf = Vec::new();
            entry.read_to_end(&mut buf).unwrap();
            buf
        };
        let signed = zsign_core::macho::MachOFile::parse(main).expect("executable must parse");
        let report = anchored_verify_slice(&signed, 0, &signer.credentials);
        assert!(report.valid, "main executable must verify: {:?}", report);

        // Re-signing the output is byte-identical (determinism).
        let resigned = signer
            .sign_ipa(&output, None, None, None, None)
            .expect("re-sign must succeed");
        assert_eq!(output, resigned, "re-sign must be byte-identical");
    }

    /// Minimal signable IPA: Payload/Test.app with Info.plist, the
    /// minimal mach-o executable, plus a root-level pass-through entry.
    fn build_test_ipa_bytes() -> Vec<u8> {
        use std::io::Write as _;

        let mut cursor = std::io::Cursor::new(Vec::new());
        let mut zip = zip::ZipWriter::new(&mut cursor);
        let opts =
            zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        zip.start_file("Payload/Test.app/Info.plist", opts).unwrap();
        zip.write_all(info_plist_xml("Test").as_bytes()).unwrap();
        zip.start_file("Payload/Test.app/Test", opts).unwrap();
        zip.write_all(MINIMAL_MACHO).unwrap();
        zip.start_file("SwiftSupport/keep.txt", opts).unwrap();
        zip.write_all(b"pass-through").unwrap();
        zip.finish().unwrap();
        drop(zip);
        cursor.into_inner()
    }
```

Notes for the Tester:
- `info_plist_xml` does not exist in the wasm tests yet — write it as a
  helper mirroring the native fixture shape
  (`crates/zsign/src/ipa/mod.rs:1811-1828`): XML plist with
  `CFBundleIdentifier = com.zsign.test`, `CFBundleExecutable = Test`,
  `CFBundleName = Test`, `CFBundleVersion = 1.0`, `CFBundlePackageType = APPL`.
- `anchored_verify_slice` and `new_signer` already exist in this test module
  (`lib.rs:806-852`, `lib.rs:738-741`); `MINIMAL_MACHO` at `lib.rs:691`.
- Also add `use std::io::Read as _;` inside the test if not already in scope.

- [ ] **Step 0.2: Confirm red**

Run: `TMPDIR=$PWD/.tmptmp cargo check -p zsign-wasm 2>&1 | tail -20`
Expected: FAIL — `no method named sign_ipa found for struct WasmSigner`
(and `unresolved import zip` before the dev-dep is added). Record the exact
error; this is the red state.

- [ ] **Step 0.3: Also add the limit red tests**

Next to the existing limit tests (`lib.rs:1104-1199`), add:

```rust
    #[wasm_bindgen_test(unsupported = test)]
    fn sign_ipa_rejects_oversize_input() {
        let signer = new_signer();
        let input = vec![0u8; MAX_IPA_BYTES + 1];
        let e = signer
            .sign_ipa(&input, None, None, None, None)
            .expect_err("oversize input must be rejected");
        assert_eq!(error_code(&e), Some("ZSIGN_INPUT_TOO_LARGE".into()));
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn sign_ipa_maps_malformed_archive_to_stable_code() {
        let signer = new_signer();
        let e = signer
            .sign_ipa(b"not a zip", None, None, None, None)
            .expect_err("malformed input must be rejected");
        assert_eq!(error_code(&e), Some("ZSIGN_SIGNING_FAILED".into()));
    }
```

(`error_code` helper at `lib.rs:1364-1368`, `MAX_IPA_BYTES` does not exist
yet — the red state includes it.)

Run: `TMPDIR=$PWD/.tmptmp cargo check -p zsign-wasm 2>&1 | tail -20`
Expected: FAIL with the same two root causes (`sign_ipa` missing,
`MAX_IPA_BYTES` missing).

---

### Task 1: `Store` trait + `FsStore`

**Files:**
- Create: `crates/zsign/src/store.rs`
- Modify: `crates/zsign/src/lib.rs` (add `mod store;` next to `pub mod ipa;` at `:43`)

- [ ] **Step 1.1: Write the trait**

Create `crates/zsign/src/store.rs` with the exact surface from the design
doc §1:

```rust
//! Storage abstraction separating the sign flow's IO primitives from the
//! medium they run on: `FsStore` wraps the filesystem, `MemStore` (in
//! `ipa::mem_store`) is an in-memory tree used by the bytes-to-bytes path.

use crate::{Error, Result};
use std::io::{Read, Seek};
use std::path::{Path, PathBuf};

/// Kind of a directory entry, reported lstat-style: a symlink is `Symlink`
/// even when its target is a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StoreKind {
    File,
    Dir,
    Symlink,
}

/// lstat-style metadata for one path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct StoreStat {
    pub kind: StoreKind,
    pub len: u64,
    /// Unix mode bits when the medium carries them; `None` when it does not.
    pub unix_mode: Option<u32>,
}

impl StoreStat {
    pub fn is_dir(&self) -> bool {
        self.kind == StoreKind::Dir
    }
    pub fn is_file(&self) -> bool {
        self.kind == StoreKind::File
    }
    pub fn is_symlink(&self) -> bool {
        self.kind == StoreKind::Symlink
    }
}

/// Every IO primitive the sign flow needs. Paths are root-relative keys.
pub(crate) trait Store {
    fn read(&self, path: &Path) -> Result<Vec<u8>>;
    /// Streaming reader over an existing file; native keeps `File` so
    /// callers that `io::copy` never buffer the whole file.
    fn open(&self, path: &Path) -> Result<Box<dyn Read + Seek + '_>>;
    fn write(&mut self, path: &Path, data: &[u8]) -> Result<()>;
    fn create_dir_all(&mut self, path: &Path) -> Result<()>;
    fn list(&self, path: &Path) -> Result<Vec<(String, StoreKind)>>;
    /// lstat: metadata of the entry itself, never following a final symlink.
    fn metadata(&self, path: &Path) -> Result<StoreStat>;
    /// Pre-order walk (parent before children) of everything under `root`,
    /// excluding `root` itself from the returned list.
    fn walk(&self, root: &Path) -> Result<Vec<(PathBuf, StoreKind)>>;
    /// Raw target bytes of a symlink, without following it.
    fn read_link(&self, path: &Path) -> Result<Vec<u8>>;
    fn symlink(&mut self, target: &[u8], path: &Path) -> Result<()>;
    fn remove_file(&mut self, path: &Path) -> Result<()>;
    fn set_permissions(&mut self, path: &Path, mode: u32) -> Result<()>;

    /// `path.exists()` semantics: any failure answers `false`.
    fn exists(&self, path: &Path) -> bool {
        self.metadata(path).is_ok()
    }
}
```

- [ ] **Step 1.2: Implement `FsStore`**

Same file. Each method is a one-line delegation preserving today's errors
(the `?` conversions produce the same `Error::Io` variants the current call
sites produce):

```rust
/// Filesystem-backed store: every method delegates to `std::fs`/`WalkDir`
/// exactly as the native flow does today.
pub(crate) struct FsStore;

impl Store for FsStore {
    fn read(&self, path: &Path) -> Result<Vec<u8>> {
        Ok(std::fs::read(path)?)
    }
    fn open(&self, path: &Path) -> Result<Box<dyn Read + Seek + '_>> {
        Ok(Box::new(std::fs::File::open(path)?))
    }
    fn write(&mut self, path: &Path, data: &[u8]) -> Result<()> {
        Ok(std::fs::write(path, data)?)
    }
    fn create_dir_all(&mut self, path: &Path) -> Result<()> {
        Ok(std::fs::create_dir_all(path)?)
    }
    fn list(&self, path: &Path) -> Result<Vec<(String, StoreKind)>> {
        let mut out = Vec::new();
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let kind = if entry.file_type()?.is_dir() {
                StoreKind::Dir
            } else if entry.file_type()?.is_symlink() {
                StoreKind::Symlink
            } else {
                StoreKind::File
            };
            out.push((entry.file_name().to_string_lossy().into_owned(), kind));
        }
        Ok(out)
    }
    fn metadata(&self, path: &Path) -> Result<StoreStat> {
        let md = std::fs::symlink_metadata(path)?;
        let kind = if md.is_symlink() {
            StoreKind::Symlink
        } else if md.is_dir() {
            StoreKind::Dir
        } else {
            StoreKind::File
        };
        let unix_mode = {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                Some(md.permissions().mode())
            }
            #[cfg(not(unix))]
            {
                None
            }
        };
        Ok(StoreStat { kind, len: md.len(), unix_mode })
    }
    fn walk(&self, root: &Path) -> Result<Vec<(PathBuf, StoreKind)>> {
        // Mirrors the call sites' WalkDir usage: follow_links(false),
        // depth-first pre-order, entries yielded in readdir order, errors
        // skipped exactly like the sites' filter_map(|e| e.ok()).
        let mut out = Vec::new();
        for entry in walkdir::WalkDir::new(root).follow_links(false) {
            let Ok(entry) = entry else { continue };
            if entry.path() == root {
                continue;
            }
            let kind = if entry.file_type().is_dir() {
                StoreKind::Dir
            } else if entry.file_type().is_symlink() {
                StoreKind::Symlink
            } else {
                StoreKind::File
            };
            out.push((entry.path().to_path_buf(), kind));
        }
        Ok(out)
    }
    fn read_link(&self, path: &Path) -> Result<Vec<u8>> {
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            Ok(std::fs::read_link(path)?.as_os_str().as_bytes().to_vec())
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            Err(Error::SymlinkNotSupported)
        }
    }
    fn symlink(&mut self, target: &[u8], path: &Path) -> Result<()> {
        let target = std::str::from_utf8(target).map_err(|_| {
            Error::Io(std::io::Error::other("symlink target is not valid UTF-8"))
        })?;
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(target, path)?;
            Ok(())
        }
        #[cfg(not(unix))]
        {
            let _ = (target, path);
            Err(Error::SymlinkNotSupported)
        }
    }
    fn remove_file(&mut self, path: &Path) -> Result<()> {
        Ok(std::fs::remove_file(path)?)
    }
    fn set_permissions(&mut self, path: &Path, mode: u32) -> Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
            Ok(())
        }
        #[cfg(not(unix))]
        {
            let _ = (path, mode);
            Ok(())
        }
    }
}
```

Before writing Step 1.2, check each native site the trait will replace and
adjust `walk`'s per-site fidelity notes (the implementer MUST verify, not
assume): `ipa/mod.rs:966` (`collect_nested_bundles`), `:1145`
(`find_standalone_dylibs`), `:1323` (`find_immediate_macho_binaries`),
`bundle/code_resources.rs:150` (scan), `ipa/archive.rs:350` (`write_tree`),
`ipa/extract.rs:658` (`find_app_bundle` via `read_dir`). If a site skips
walk *errors* differently than `continue`, the genericized site keeps its own
error handling around `store.walk`'s `Result`.

- [ ] **Step 1.3: Compile and run the scoped native gate**

Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-rs --no-fail-fast 2>&1 | tail -15`
Expected: PASS (nothing consumes `store` yet; the module must at least
compile — silence dead-code by construction: `pub(crate)` items used from
Task 3 onward may need `#[allow(dead_code)]` ONLY if clippy/fmt gate demands;
prefer wiring Task 3 immediately after so no allow is needed).

---

### Task 2: `MemStore` + native unit tests

**Files:**
- Create: `crates/zsign/src/ipa/mem_store.rs`
- Modify: `crates/zsign/src/ipa/mod.rs` (add `mod mem_store;` beside the
  module's other private items, near `:60-75` imports)

- [ ] **Step 2.1: Implement `MemStore`**

```rust
//! Rooted in-memory file tree backing the bytes-to-bytes IPA path.

use crate::store::{Store, StoreKind, StoreStat};
use crate::{Error, Result};
use std::collections::BTreeMap;
use std::io::{Cursor, Read, Seek};
use std::path::{Component, Path, PathBuf};

enum Node {
    Dir,
    File { bytes: Vec<u8>, unix_mode: Option<u32> },
    Symlink { target: Vec<u8>, unix_mode: Option<u32> },
}

/// In-memory store keyed by normalized root-relative paths. Children iterate
/// in sorted order (BTreeMap), so walks are deterministic regardless of input
/// zip entry order.
pub(crate) struct MemStore {
    nodes: BTreeMap<PathBuf, Node>,
}
```

Required behavior (implement exactly; each is load-bearing):

- `normalize(path) -> Result<PathBuf>`: reject absolute paths, `..`, `.`
  components and empty paths with `Error::Io` (`InvalidInput`), mirroring
  `validate_output_path`/`resolve_relative` intent (`extract.rs:201-237`,
  `mod.rs:990-1010`). All public methods normalize first; the root `""` key
  is the extraction root (a `Dir`).
- `create_dir_all`: create every ancestor `Dir` node; error if any existing
  ancestor is `File`/`Symlink` (same conflict class as native).
- `write`: error unless every ancestor is `Dir` and none is `Symlink`
  (containment guard — the in-memory twin of the native TOCTOU/symlink
  component checks); then insert/replace `File`.
- `symlink`: insert `Symlink { target, .. }`; reject if the parent chain is
  not all `Dir`.
- `metadata`: `BTreeMap::get` → `Ok`; `NotFound` →
  `Err(Error::Io(std::io::Error::from(std::io::ErrorKind::NotFound)))`
  (same shape `fs::symlink_metadata` produces, so `exists()`/`is_dir()`
  call sites behave identically).
- `walk(root)`: DFS pre-order over keys strictly under `root`, children
  sorted by file name; returns absolute-shaped keys joined the way native
  sites expect (they `strip_prefix(root)` — return `root.join(child)` keys
  exactly like `WalkDir` does: full paths, root excluded).
- `read_link`: return stored target bytes; on a non-symlink, return the
  `NotFound`-shaped io error `fs::read_link` would produce.
- `open`: `Cursor::new(bytes.as_slice())` boxed — zero copy.

- [ ] **Step 2.2: Native unit tests for `MemStore`**

Add `#[cfg(test)] mod tests` inside `mem_store.rs` covering: normalize
rejects `../`, absolute, and `.` paths; `write` refuses when an ancestor is a
symlink; `walk` returns sorted pre-order entries and excludes the root;
`metadata` NotFound mirrors `exists() == false`; `read_link` round-trips
target bytes; `open` reads back the written bytes.

- [ ] **Step 2.3: Scoped gate**

Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-rs store 2>&1 | tail -10`
Expected: PASS (new unit tests only).

---

### Task 3: Genericize the sign stage over `Store` (the core refactor)

**Files:**
- Modify: `crates/zsign/src/ipa/mod.rs` (every tree-touching method below)
- Modify: `crates/zsign/src/bundle/code_resources.rs` (`new`/`scan`/hashing)
- Modify: `crates/zsign/src/macho/parser.rs` — NOT needed: `MachOFile::parse`
  already exists (`parser.rs:34-39`); only call sites change.

- [ ] **Step 3.1: Add `store: &mut S` parameters to the sign-stage methods**

Signature pattern (bodies otherwise unchanged except the swaps in Step 3.2):

```rust
fn sign_bundle_from_options<S: Store>(&self, store: &mut S, bundle_path: &Path) -> Result<()>
fn sign_bundle<S: Store>(&self, store: &mut S, bundle_path: &Path) -> Result<()>
fn sign_single_bundle<S: Store>(&self, store: &mut S, bundle_path: &Path,
    entitlements: Option<&[u8]>, depth: usize) -> Result<()>
fn sign_binary<S: Store>(&self, store: &mut S, root: &Path, binary_path: &Path,
    identifier: Option<&str>) -> Result<()>
fn sign_standalone_dylib<S: Store>(&self, store: &mut S, root: &Path,
    dylib_path: &Path) -> Result<()>
fn collect_nested_bundles<S: Store>(store: &S, bundle_path: &Path) -> Result<Vec<(PathBuf, usize)>>
fn rewrite_nested_identifiers<S: Store>(&self, store: &mut S, ...) -> Result<...>
fn find_standalone_dylibs<S: Store>(store: &S, bundle_path: &Path) -> Result<Vec<PathBuf>>
fn find_immediate_macho_binaries<S: Store>(&self, store: &S, ...) -> Result<Vec<PathBuf>>
fn generate_code_resources<S: Store>(store: &mut S, bundle_path: &Path) -> Result<()>
fn rewrite_plist_string<S: Store>(store: &mut S, bundle_path: &Path, key: &str, value: &str) -> Result<bool>
fn get_bundle_identifier<S: Store>(store: &S, bundle_path: &Path) -> Result<Option<String>>
fn get_main_executable<S: Store>(store: &S, bundle_path: &Path) -> Result<PathBuf>
fn is_macho_binary<S: Store>(store: &S, path: &Path) -> Result<bool>
fn resolve_relative<S: Store>(store: &S, base: &Path, rel: &str) -> Result<PathBuf>
fn resolve_within<S: Store>(store: &S, root: &Path, path: &Path) -> Result<PathBuf>
fn check_no_symlink_components<S: Store>(store: &S, root: &Path, relative: &Path) -> Result<()>
fn ensure_single_app_bundle<S: Store>(store: &S, payload_dir: &Path) -> Result<()>
fn calculate_bundle_depth(bundle_path: &Path, root_bundle: &Path) -> usize  // pure, no store
```

Free functions take `store` as first parameter; associated fns keep `&self`
where they read config. The exact list MUST be derived by compiling: every
callee of the functions above must pass a store. The public API
(`sign`, `sign_folder_in_place`, `sign_folder_to_ipa`, all builder setters)
keeps its current signatures and constructs `FsStore` internally:

```rust
    pub fn sign(&self, input_ipa: impl AsRef<Path>, output_ipa: impl AsRef<Path>) -> Result<()> {
        // ... unchanged validate + TempDir + extract ...
        let mut store = FsStore;
        self.sign_bundle_from_options(&mut store, &app_bundle)?;
        create_ipa_from_root(temp_dir.path(), output_ipa, self.compression_level)?;
        Ok(())
    }
```

- [ ] **Step 3.2: Mechanical IO swaps inside generic bodies**

Swap table (site → replacement), applied to every genericized body:

| native call | store call |
| --- | --- |
| `fs::read(p)` / `MachOFile::open(p)` | `store.read(p)` / `MachOFile::parse(store.read(p)?)` |
| `fs::write(p, d)` | `store.write(p, d)` |
| `fs::create_dir_all(p)` | `store.create_dir_all(p)` |
| `fs::remove_file(p)` | `store.remove_file(p)` |
| `p.exists()` / `p.is_dir()` / `fs::symlink_metadata(p)` | `store.exists(p)` / `store.metadata(p)?.is_dir()` / `store.metadata(p)` |
| `WalkDir::new(p)...` | `store.walk(p)?` + the site's existing filter/prune logic over the returned list |
| `fs::File::open(p)` (magic probes, CodeResources streaming) | `store.open(p)?` |
| `fs::read_link(p)` | `store.read_link(p)?` (returns raw bytes — the `#[cfg(unix)]` block in `code_resources.rs:270-279` becomes store-based; the `cfg(not(unix))` arm at `:281-288` moves into `FsStore::read_link`, so the error variant is preserved on native and `MemStore` serves symlink targets) |
| `CodeResourcesBuilder::new(path)?.scan()?` (`mod.rs:1665`) | `CodeResourcesBuilder::new(store, path)?.scan()?` — `new`/`scan` gain `&'a S` |

`resolve_relative`/`resolve_within`/`check_no_symlink_components`
(`mod.rs:990-1108`): the pure component checks stay as written; only the
`fs::symlink_metadata` component walk (`:1096`) becomes `store.metadata`.

- [ ] **Step 3.3: Rayon gates**

Every rayon site inside now-generic code gets a cfg pair, native arm first
(unchanged behavior), sequential arm for wasm:

```rust
        #[cfg(not(target_arch = "wasm32"))]
        {
            binaries.par_iter().try_for_each(|p| self.sign_binary(store, root, p, ident))?;
        }
        #[cfg(target_arch = "wasm32")]
        {
            for p in binaries {
                self.sign_binary(store, root, p, ident)?;
            }
        }
```

Sites: `ipa/mod.rs:857-859` (standalone dylibs), `:1264` (non-main
binaries), `bundle/code_resources.rs:163` (scan). Note borrow rules: the
sequential arm may need `store` re-borrowed per iteration (signature takes
`&mut S`; split reads from writes the way the native par arm already does —
native par closures capture `&`-borrows, so the genericized signatures must
accept what each site actually needs; prefer `&S` for read-only sites and
`&mut S` only where mutations happen).

- [ ] **Step 3.4: `CodeResourcesBuilder` over the store**

`bundle/code_resources.rs`:

```rust
impl<'a, S: Store> CodeResourcesBuilder<'a, S> {   // was non-generic
    pub fn new(store: &'a S, bundle_path: &Path) -> Result<Self>
    pub fn scan(mut self) -> Result<Self>
}
```

`scan` keeps its structure (collect paths, iterate, exclude, hash); reads go
through `store`. The hashing helpers keep raw symlink target bytes from
`store.read_link`. Streaming file hashing (`:296-317`) uses `store.open` in
its 64 KiB loop. The build step continues to call the filesystem-free
`zsign_core::bundle::CodeResourcesBuilder` unchanged (`:221`).

Check every external constructor: `mod.rs:1665` (sign path) and any tests in
`bundle/code_resources.rs` / `verify.rs` — update them to pass `&FsStore`
with no behavioral change. `crates/zsign/src/verify.rs` also constructs the
builder (grep `CodeResourcesBuilder::new`); it is native and gets `&FsStore`.

- [ ] **Step 3.5: Full native regression gate (THE checkpoint)**

Run:
```
TMPDIR=$PWD/.tmptmp cargo test --workspace --no-fail-fast 2>&1 | tail -25
```
Expected: **every pre-existing test passes unmodified**. Any diff to an
existing test body is a design violation — stop and re-check the swap table
rather than "fixing" the test.

Run: `TMPDIR=$PWD/.tmptmp cargo clippy -p zsign-rs --all-targets -- -D warnings 2>&1 | tail -10`
Expected: PASS.

---

### Task 4: Blob sources + bytes setters

**Files:**
- Modify: `crates/zsign/src/ipa/mod.rs` (config fields + `load_*` fns)
- Modify: `crates/zsign/src/error.rs` (new `InputTooLarge` variant)

- [ ] **Step 4.1: Add `Error::InputTooLarge`**

In `crates/zsign/src/error.rs`, beside the existing variants:

```rust
    /// An input exceeds a documented size limit.
    #[error("Input too large: {0}")]
    InputTooLarge(String),
```

Then grep the workspace for exhaustive matches on `zsign_rs::Error`
(`match` without a catch-all arm) and update any to handle the variant
(the wasm mapping is written in Task 6; `zsign-cli` formats errors via
`Display` — verify with `cargo check -p zsign-cli`).

- [ ] **Step 4.2: `BlobSource` for profile and entitlements override**

In `ipa/mod.rs`, replace the two path fields used on the bytes path:

```rust
/// Where a blob input comes from: a native path (resolved at the same flow
/// point as today) or caller-provided bytes (wasm surface, no IO).
enum BlobSource {
    Path(PathBuf),
    Bytes(Vec<u8>),
}
```

- `provisioning_profile_path: Option<PathBuf>` →
  `provisioning_profile: Option<BlobSource>`; the `provisioning_profile(path)`
  setter stores `BlobSource::Path`; new public setter:

```rust
    /// Uses the given provisioning profile bytes instead of reading a path.
    /// The bytes are validated during plan build, mirroring the path form.
    pub fn provisioning_profile_bytes(mut self, data: Vec<u8>) -> Self {
        self.provisioning_profile = Some(BlobSource::Bytes(data));
        self
    }
```

- `entitlements_override: Option<PathBuf>` → `Option<BlobSource>`; existing
  `entitlements(path)` setter stores `Path`; new `entitlements_bytes(data)`
  setter as above. The shared reader (`builder.rs` `read_entitlements_file`
  currently, `builder.rs:672`) splits: the `Path` arm keeps today's
  `fs::read` + `validate_entitlements_blob`; the `Bytes` arm validates the
  bytes directly. Keep one helper so validation logic is not duplicated —
  change `read_entitlements_file` to take `&BlobSource` or add
  `read_entitlements(source: &BlobSource) -> Result<Option<Vec<u8>>>` in
  `ipa/mod.rs`, leaving `builder.rs`'s path-based helper in place for the
  `ZSign` builder if it has other callers (grep before deleting).
- `load_profile` (`mod.rs:535-547`) and `load_entitlements_override`
  (`:597-599`) switch to the source reader; error timing stays identical
  (same call sites, same plan-build ordering — pinned by
  `test_entitlements_*` and `test_profile_map_*`).
- `bundle_profiles` stays path-only (not exposed to wasm; its `fs::read` at
  `:573` is unreachable on the bytes path).

- [ ] **Step 4.3: Scoped gate**

Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-rs --no-fail-fast 2>&1 | tail -15`
Expected: PASS, existing tests unchanged.

---

### Task 5: Bytes extract into `MemStore` + generic repack

**Files:**
- Modify: `crates/zsign/src/ipa/extract.rs` (generic collect reader, new
  `extract_ipa_into_store`, store-based `find_app_bundle` sibling)
- Modify: `crates/zsign/src/ipa/archive.rs` (generic `write_tree` + bytes repack)

- [ ] **Step 5.1: Make the collect pass reader-generic**

The collect pass inside `extract_ipa_with_limits` (`extract.rs:364-490`) is
zip-read + pure judgement. Extract it (or genericize it in place) as:

```rust
fn collect_entries<R: std::io::Read + std::io::Seek>(
    archive: &mut zip::ZipArchive<R>,
    dest_dir: &Path,
    file_paths: &mut HashSet<PathBuf>,
    dirs_to_create: &mut HashSet<PathBuf>,
) -> Result<Vec<ExtractEntry>>
```

Native `extract_ipa_with_limits` calls it with its existing
`ZipArchive<BufReader<File>>` — no behavior change. All pure helpers
(`canonical_entry_name`, `is_unsafe_entry_name`, `file_ancestor`,
`register_ancestor_dirs`) are reused verbatim.

- [ ] **Step 5.2: `extract_ipa_into_store`**

```rust
/// Extracts a zip (read from `input`) into `store` under `dest_root`,
/// enforcing the given limits before and while materializing entries.
pub(crate) fn extract_ipa_into_store<S: Store, R: std::io::Read + std::io::Seek>(
    input: R,
    store: &mut S,
    dest_root: &Path,
    limits: ExtractionLimits,
) -> Result<PathBuf>
```

Sequence (mirrors the native pass order, sequential):

1. `ZipArchive::new(input).map_err(Error::Zip)`.
2. **Pre-check declared sizes** before any materialization: iterate
   `by_index(i)`, accumulate `file.size()`; if any entry `> limits.max_entry`
   or the sum `> limits.max_total_bytes` →
   `Err(Error::InputTooLarge(format!(...)))` naming the limit (same phrasing
   style as the native budget error, `extract.rs:80-86`).
3. `collect_entries(...)`.
4. Materialize: `store.create_dir_all` for dirs (entry list order is fine —
   `MemStore::create_dir_all` creates ancestors); for regular entries read
   with `BudgetedWriter` (`extract.rs:53-93`, unchanged — backstop against
   lying headers) into a `Vec<u8>` via `io::copy`, then `store.write`;
   `#[cfg(unix)]` permission application is NOT needed for `MemStore`
   (mode stored from `ExtractEntry.unix_mode` alongside the bytes — extend
   `MemStore::write` with a `write_with_mode(path, data, mode: Option<u32>)`
   used only by this path so wasm output replays unix modes);
   symlinks: read the bounded target (`take(MAX_SYMLINK_TARGET_BYTES + 1)`,
   `extract.rs:578-580` — the const is `#[cfg(unix)]`; move it out of the
   cfg so both paths share the cap, and keep `is_safe_symlink_target`
   `extract.rs:96-101` applied), then `store.symlink`.
5. `find_app_bundle_in_store(store, dest_root)` — same first-`.app` scan via
   `store.list` (`extract.rs:648-674`); ambiguity is still rejected later by
   `ensure_single_app_bundle`, which is already store-generic from Task 3.

- [ ] **Step 5.3: Generic `write_tree` + bytes repack in `archive.rs`**

Change the signature to
`fn write_tree<S: Store, W: std::io::Write + std::io::Seek>(zip: &mut zip::ZipWriter<W>, store: &S, walk_root: &Path, options: SimpleFileOptions, name_of: &dyn Fn(&Path) -> Option<String>) -> Result<()>`
and swap its body's IO per the Task 3 table (walk via `store.walk`, stat via
`store.metadata` — source of the unix mode, symlink via `store.read_link`,
content via `store.open` + `io::copy`). The bytewise sort (`:370`),
precomputed-stored bypass (`:388-394`), ZIP64 gate (`:403-407`), pinned
timestamp and compression options stay byte-for-byte.

Native callers `create_ipa` (`:208`) and `create_ipa_from_root` (`:280`)
pass `&FsStore` — their outputs must stay byte-identical (the existing
byte-identity tests at `archive.rs:879` and `mod.rs:1687` pin this).

New bytes repack:

```rust
/// Repacks `store` (keyed under `root`) into an in-memory IPA, mirroring
/// `create_ipa_from_root` including non-Payload root entries.
pub(crate) fn create_ipa_from_store<S: Store>(store: &S, root: &Path, level: CompressionLevel) -> Result<Vec<u8>> {
    let mut cursor = std::io::Cursor::new(Vec::new());
    let mut zip = zip::ZipWriter::new(&mut cursor);
    let options = archive_options(level);
    zip.add_directory("Payload/", options).map_err(Error::Zip)?;
    write_tree(&mut zip, store, root, options, &|rel| Some(zip_entry_name(rel)))?;
    let _ = zip.finish().map_err(Error::Zip)?;
    Ok(cursor.into_inner())
}
```

(Exact `name_of` closure mirrors `create_ipa_from_root`'s mapping at
`:305-311`; read it while implementing and match it — `zip_entry_name`
`archive.rs:425`.)

- [ ] **Step 5.4: Scoped gate**

Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-rs --no-fail-fast 2>&1 | tail -15`
Expected: PASS, existing tests unchanged (byte-identity pins included).

---

### Task 6: `IpaSigner::sign_ipa_bytes` + native round-trip tests

**Files:**
- Modify: `crates/zsign/src/ipa/mod.rs` (new public entry + tests)

- [ ] **Step 6.1: The bytes entry point**

```rust
    /// Signs a complete IPA held in memory and returns the signed IPA
    /// bytes. Same stages as [`Self::sign`], running over an in-memory
    /// store: no filesystem access, deterministic output.
    ///
    /// Limits: input ≤ 512 MiB (enforced by the wasm surface), declared
    /// uncompressed total ≤ 2 GiB (enforced here).
    pub fn sign_ipa_bytes(&self, input: &[u8]) -> Result<Vec<u8>> {
        validate_ipa_bytes(input)?;

        let mut store = MemStore::new();
        let app_bundle = extract_ipa_into_store(
            std::io::Cursor::new(input),
            &mut store,
            Path::new(""),
            ExtractionLimits::wasm_default(),
        )?;
        Self::resolve_within(&store, Path::new(""), &app_bundle)?;
        Self::ensure_single_app_bundle(&store, Path::new("Payload"))?;
        self.sign_bundle_from_options(&mut store, &app_bundle)?;

        create_ipa_from_store(&store, Path::new(""), self.compression_level)
    }
```

Supporting pieces (all small, all in `ipa/`):

- `validate_ipa_bytes(input: &[u8]) -> Result<()>` mirroring `validate_ipa`
  (`extract.rs:695-718`): empty → `Error::Zip`; first four bytes must be the
  local-file-header magic `PK\x03\x04` (same probe `validate_ipa` performs
  after opening), else `Error::Zip`.
- `ExtractionLimits::wasm_default()` — `max_entry_bytes = 512 MiB`,
  `max_total_bytes = 2 GiB`, documented as the browser-oriented caps (native
  default at `extract.rs:247-252` unchanged).
- `MemStore::new()` seeds the root directory node (`""` → `Dir`).

- [ ] **Step 6.2: Native round-trip tests**

Add to `ipa/mod.rs` tests (reusing `write_test_ipa`-style fixture building,
`mod.rs:1766-1807`, writing to a `Vec` via `Cursor` instead of a file):

1. `test_sign_ipa_bytes_round_trip` — sign the fixture IPA bytes; assert:
   output opens as a zip; `Payload/Test.app/_CodeSignature/CodeResources`
   exists and seals the non-excluded files (reuse the sealing assertions
   pattern from `test_ipa_signer_workflow`, `mod.rs:1897-1909`); the main
   executable parses as a signed SuperBlob (pattern `mod.rs:1911-1933`);
   `SwiftSupport/...` root entry survives (`test_sign_preserves_non_payload_entries`
   pattern, `mod.rs:1710-1756`).
2. `test_sign_ipa_bytes_is_deterministic` — two signs of the same input are
   byte-identical; also signing the *output* again is byte-identical
   (matches `test_ipa_signing_is_deterministic`, `mod.rs:1687-1707`).
3. `test_sign_ipa_bytes_rejects_oversize_declared_entries` — a fixture zip
   whose entry declares > 512 MiB uncompressed (`zip` writer with a lied
   size or a direct `ExtractionLimits` unit test on
   `extract_ipa_into_store`) → `Error::InputTooLarge`.
4. `test_sign_ipa_bytes_rejects_hostile_entry_names` — `../evil` entry →
   error (collect-pass gate reused; mirrors `extract.rs:757-774` fixture).
5. `test_sign_ipa_bytes_entitlements_bytes_override` — sign with
   `entitlements_bytes(custom_xml)` set and a profile configured; assert the
   signed main executable's entitlements slot equals the custom plist, not
   the profile's (pattern `mod.rs:4067-4106`), pinning ZSN-10 precedence for
   the bytes form.

- [ ] **Step 6.3: Scoped gate**

Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-rs ipa::tests --no-fail-fast 2>&1 | tail -15`
Expected: PASS (new + existing ipa tests).

---

### Task 7: Wasm binding — turn the red tests green

**Files:**
- Modify: `crates/zsign-wasm/Cargo.toml` (add
  `zsign-rs = { path = "../zsign", version = "0.1.2" }` to `[dependencies]`;
  Task 0 already added the `zip` dev-dependency)
- Modify: `crates/zsign-wasm/src/lib.rs`

- [ ] **Step 7.1: `MAX_IPA_BYTES` + doc table row**

Beside the existing limits (`lib.rs:49-58`):

```rust
/// Maximum size of a whole IPA input to `sign_ipa` (compressed bytes).
/// Matches `MAX_MACHO_BYTES`; the uncompressed entry budget is enforced
/// inside the pipeline (512 MiB per entry, 2 GiB total).
const MAX_IPA_BYTES: usize = 512 * 1024 * 1024;
```

Extend the module-doc error table (`lib.rs:15-43`) with a `sign_ipa` note
row: it can additionally raise `ZSIGN_SIGNING_FAILED` (malformed archive) and
`ZSIGN_INPUT_TOO_LARGE` (IPA/entry/total caps) — existing codes, no new
family. Also add the method to the crate's feature bullet list at the top.

- [ ] **Step 7.2: `profile_bytes` retention**

In `WasmSigner` (`lib.rs:202-209`) add
`profile_bytes: Option<Vec<u8>>`; populate it in `new` from the `profile_bytes`
argument already received (`lib.rs:236-241`) before entitlements extraction.
No other behavior changes (the existing constructor tests must stay green).

- [ ] **Step 7.3: Exhaustive zsign error mapping**

```rust
/// Maps the native crate's error enum onto the stable public codes.
/// Exhaustive by construction: a new `zsign_rs::Error` variant must fail to
/// compile until it is assigned a code.
fn code_for_zsign_error(e: &zsign_rs::Error) -> WasmErrorCode {
    match e {
        zsign_rs::Error::Core(inner) => code_for_core_error(inner),
        zsign_rs::Error::Plist(_) => WasmErrorCode::InvalidPlist,
        zsign_rs::Error::MissingCredentials(_) => WasmErrorCode::MissingCredentials,
        zsign_rs::Error::InputTooLarge(_) => WasmErrorCode::InputTooLarge,
        zsign_rs::Error::Zip(_) => WasmErrorCode::SigningFailed,
        zsign_rs::Error::Io(_) => WasmErrorCode::SigningFailed,
        zsign_rs::Error::SymlinkNotSupported => WasmErrorCode::SigningFailed,
    }
}
```

- [ ] **Step 7.4: `sign_ipa` method**

```rust
    /// Signs a complete IPA in memory and returns the signed IPA bytes —
    /// no JS-side zip handling needed.
    ///
    /// Options: `bundle_id`/`bundle_name`/`bundle_version` rewrite the root
    /// bundle's Info.plist keys before signing; `compression_level` (0-9,
    /// default 6) selects the output zip compression.
    ///
    /// Limits: input ≤ 512 MiB; declared uncompressed total ≤ 2 GiB
    /// (`ZSIGN_INPUT_TOO_LARGE`). Peak memory ≈ input + uncompressed tree +
    /// output plus per-file signing working set, with one ABI copy of the
    /// input and one of the output; linear memory never shrinks, so large
    /// signs leave a per-tab watermark. Desktop-class browsers are
    /// recommended above ~100 MiB inputs.
    ///
    /// Errors: stable codes per the module table; malformed archives map to
    /// `ZSIGN_SIGNING_FAILED`.
    #[wasm_bindgen]
    pub fn sign_ipa(
        &self,
        input: &[u8],
        bundle_id: Option<String>,
        bundle_name: Option<String>,
        bundle_version: Option<String>,
        compression_level: Option<u8>,
    ) -> Result<Vec<u8>, JsValue> {
        ensure_size(input.len(), MAX_IPA_BYTES, "IPA input", "split or reduce the archive before signing")?;

        let mut signer = zsign_rs::ipa::IpaSigner::new(&self.credentials);
        if let Some(data) = &self.profile_bytes {
            signer = signer.provisioning_profile_bytes(data.clone());
        }
        if let Some(data) = &self.entitlements_override {
            signer = signer.entitlements_bytes(data.clone());
        }
        if let Some(id) = bundle_id {
            signer = signer.bundle_id(id);
        }
        if let Some(name) = bundle_name {
            signer = signer.bundle_name(name);
        }
        if let Some(version) = bundle_version {
            signer = signer.bundle_version(version);
        }
        if let Some(level) = compression_level {
            signer = signer.compression_level(zsign_rs::CompressionLevel::new(level.into()));
        }
        signer.sign_ipa_bytes(input).map_err(|e| {
            js_err(code_for_zsign_error(&e), format!("sign_ipa failed: {e}"))
        })
    }
```

(Verify exact import paths and setter signatures while implementing —
`CompressionLevel::new` is `archive.rs:78-80`, exported at
`crates/zsign/src/lib.rs:59`.)

- [ ] **Step 7.5: Green check**

Run: `TMPDIR=$PWD/.tmptmp cargo check -p zsign-wasm --target wasm32-unknown-unknown 2>&1 | tail -15`
Expected: PASS (0 errors).

Run: `TMPDIR=$PWD/.tmptmp wasm-pack test --node crates/zsign-wasm 2>&1 | tail -25`
Expected: all tests PASS, including Task 0's `sign_ipa_round_trip...`,
`sign_ipa_rejects_oversize_input`, and
`sign_ipa_maps_malformed_archive_to_stable_code`.

---

### Task 8: Final gates + commit

- [ ] **Step 8.1: Full gates (verbatim, unskipped)**

```
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo check -p zsign-wasm --target wasm32-unknown-unknown
TMPDIR=$PWD/.tmptmp cargo test --workspace --no-fail-fast 2>&1 | tail -40
TMPDIR=$PWD/.tmptmp wasm-pack test --node crates/zsign-wasm 2>&1 | tail -40
```

All must pass; the workspace test run has **no `--skip`** (ZSN-41 landed).

- [ ] **Step 8.2: Commit**

Conventional commit, imperative lowercase, ticket in subject only:

```
feat(wasm): add bytes-to-bytes ipa signing path (ZSN-16)
```

If the work lands as multiple commits, split by task groups (store
abstraction / bytes pipeline / wasm surface) — each subject gets the ticket
suffix, none of the code comments do.

## Plan self-review

- Spec coverage: constraints (a)-(f) map to Tasks 1-3 (wasm-safety via
  store/rayon gates), 7 (codes), 5 (determinism reuse), 4 (bytes inputs),
  0/7 (round-trip), 6/7 (limits + memory docs). Rejected alternatives live in
  the design doc. Error-code documentation: design §5 + Task 7.1.
- Deviations from the writing-plans skill (mandated by the lane brief):
  plan path is `docs/superpowers/plans/` and the "oracle review" step is
  replaced by the brief's cold-review gate (phase 4).
- Type consistency check: `Store`/`FsStore`/`MemStore`/`BlobSource`/
  `sign_ipa_bytes`/`sign_ipa`/`MAX_IPA_BYTES`/`InputTooLarge` names are used
  identically across tasks.
