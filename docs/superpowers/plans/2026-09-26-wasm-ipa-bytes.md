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
        archive
            .by_name("SwiftSupport/keep.txt")
            .expect("non-Payload root entries must pass through");

        // ... and it actually seals content: parse the plist and require a
        // known non-excluded path in the legacy `files` dict (Info.plist is
        // rule-omitted from `files2`, so `files` is the honest map here —
        // same choice the native test at mod.rs:1901-1905 makes).
        let cr: plist::Value =
            plist::from_bytes(&code_resources).expect("CodeResources must be a plist");
        let files = cr
            .as_dictionary()
            .and_then(|d| d.get("files"))
            .and_then(|v| v.as_dictionary())
            .expect("CodeResources must have a files dict");
        assert!(
            files.contains_key("Info.plist"),
            "CodeResources must seal Info.plist; keys: {:?}",
            files.keys().collect::<Vec<_>>()
        );

        // The main executable carries a signature that verifies against the
        // fixture credential's certificate. `anchored_verify_slice` takes the
        // raw bytes and parses internally (lib.rs:806-809).
        let main = {
            let mut entry = archive
                .by_name("Payload/Test.app/Test")
                .expect("main executable must be present");
            let mut buf = Vec::new();
            entry.read_to_end(&mut buf).unwrap();
            buf
        };
        let report = anchored_verify_slice(&main, 0, &signer.credentials);
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
  (`crates/zsign/src/ipa/mod.rs:1811-1826`): XML plist with exactly the
  two keys the native helper emits — `CFBundleIdentifier = com.zsign.test`
  and `CFBundleExecutable = Test`. Nothing in the sign flow reads other
  Info.plist keys (`get_bundle_identifier` reads `CFBundleIdentifier` at
  `mod.rs:1416`, `get_main_executable` reads `CFBundleExecutable`).
- `anchored_verify_slice` and `new_signer` already exist in this test module
  (`lib.rs:806-852`, `lib.rs:738-741`); `MINIMAL_MACHO` at `lib.rs:691`.
- Also add `use std::io::Read as _;` inside the test if not already in scope.

- [ ] **Step 0.2: Confirm red**

Run: `TMPDIR=$PWD/.tmptmp cargo check -p zsign-wasm --tests 2>&1 | tail -20`
(`--tests` matters: the red lives in `#[cfg(test)]` code, which a plain
`cargo check` never compiles.)
Expected: FAIL — `no method named sign_ipa found for struct WasmSigner`
(and `unresolved import zip` before the dev-dep is added). Record the exact
error; this is the red state.

- [ ] **Step 0.3: Also add the limit red tests**

Next to the existing limit tests (the `ensure_size_*` block at
`lib.rs:1104-1191`), add:

```rust
    #[wasm_bindgen_test(unsupported = test)]
    fn sign_ipa_size_guard_rejects_one_byte_over() {
        // Mirrors ensure_size_rejects_one_byte_over_every_limit (lib.rs:1120):
        // the guard is exercised directly rather than allocating a 513 MiB
        // input; sign_ipa applies it to input.len() as its first statement.
        ensure_size(MAX_IPA_BYTES, MAX_IPA_BYTES, "IPA input", "reduce the archive")
            .expect("exactly-at-limit must pass");
        let e = ensure_size(
            MAX_IPA_BYTES + 1,
            MAX_IPA_BYTES,
            "IPA input",
            "reduce the archive",
        )
        .expect_err("one byte over the IPA limit must be rejected");
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

(`error_code` helper at `lib.rs:1364-1368`, `ensure_size` at `lib.rs:165`;
`MAX_IPA_BYTES` does not exist yet — the red state includes it.)

Run: `TMPDIR=$PWD/.tmptmp cargo check -p zsign-wasm --tests 2>&1 | tail -20`
Expected: FAIL with the same two root causes (`sign_ipa` missing,
`MAX_IPA_BYTES` missing).

---

### Task 1: `Store` trait + `FsStore`

**Files:**
- Create: `crates/zsign/src/store.rs`
- Modify: `crates/zsign/src/lib.rs` (add `mod store;` next to `pub mod ipa;` at `:43`)

- [ ] **Step 1.1: Write the trait**

Create `crates/zsign/src/store.rs` with the exact surface from the design
doc §1 (all methods `&self`, `Sync` supertrait, per-entry walk results):

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
///
/// Methods take `&self` so rayon closures capture a shared `&S` exactly as
/// they capture `&self` today; the `Sync` supertrait discharges rayon's
/// bounds (`FsStore` is a unit struct; `MemStore` locks internally for the
/// duration of one method).
pub(crate) trait Store: Sync {
    fn read(&self, path: &Path) -> Result<Vec<u8>>;
    /// Owned reader over an existing file: native returns `File` so `io::copy`
    /// callers never buffer the whole file; `MemStore` returns an owned
    /// `Cursor` (one transient per-call copy, bounded by a single file).
    fn open(&self, path: &Path) -> Result<Box<dyn Read + Seek>>;
    fn write(&self, path: &Path, data: &[u8]) -> Result<()>;
    fn create_dir_all(&self, path: &Path) -> Result<()>;
    fn list(&self, path: &Path) -> Result<Vec<(String, StoreKind)>>;
    /// lstat: metadata of the entry itself, never following a final symlink.
    fn metadata(&self, path: &Path) -> Result<StoreStat>;
    /// Pre-order walk (parent before children) under `root`, **root
    /// included first** — exactly what `WalkDir` yields, so root handling
    /// stays per-site: `write_tree` needs the root entry (`create_ipa` maps
    /// the empty relative path to `Some("Payload/{app}")` at
    /// `archive.rs:260-266`, pinned by `archive.rs:865`), while the two
    /// historical `min_depth(1)` sites skip it explicitly. Per-entry
    /// results preserve each site's current WalkDir error handling:
    /// propagating sites write `let e = e?;`, skipping sites write
    /// `let Ok(e) = e else { continue };`.
    fn walk(&self, root: &Path) -> Result<Vec<Result<(PathBuf, StoreKind)>>>;
    /// Pruned walk mirroring `WalkDir::filter_entry` + `min_depth(1)` (the
    /// root is never yielded, as in the source chain at `mod.rs:1326`):
    /// `prune` returning `false` skips the whole subtree — never visited,
    /// never yielded, and any error inside it never surfaces.
    fn walk_pruned(
        &self,
        root: &Path,
        prune: &dyn Fn(&Path, StoreKind) -> bool,
    ) -> Result<Vec<Result<(PathBuf, StoreKind)>>>;
    /// Raw target bytes of a symlink, without following it.
    fn read_link(&self, path: &Path) -> Result<Vec<u8>>;
    fn symlink(&self, target: &[u8], path: &Path) -> Result<()>;
    fn remove_file(&self, path: &Path) -> Result<()>;
    fn set_permissions(&self, path: &Path, mode: u32) -> Result<()>;

    /// `path.exists()` semantics: any failure answers `false`.
    fn exists(&self, path: &Path) -> bool {
        self.metadata(path).is_ok()
    }
}
```

(`Result<(PathBuf, StoreKind)>` = `crate::Result` — the crate alias — so
per-entry errors are `Error` values.)

- [ ] **Step 1.2: Implement `FsStore`**

Same file. Each method is a one-line delegation preserving today's errors
(the `?` conversions produce the same `Error::Io` variants the current call
sites produce):

```rust
/// Filesystem-backed store: every method delegates to `std::fs`/`WalkDir`
/// exactly as the native flow does today. Stateless, hence `Sync` and
/// lock-free — the native rayon paths pay nothing for the abstraction.
pub(crate) struct FsStore;

impl Store for FsStore {
    fn read(&self, path: &Path) -> Result<Vec<u8>> {
        Ok(std::fs::read(path)?)
    }
    fn open(&self, path: &Path) -> Result<Box<dyn Read + Seek>> {
        Ok(Box::new(std::fs::File::open(path)?))
    }
    fn write(&self, path: &Path, data: &[u8]) -> Result<()> {
        Ok(std::fs::write(path, data)?)
    }
    fn create_dir_all(&self, path: &Path) -> Result<()> {
        Ok(std::fs::create_dir_all(path)?)
    }
    fn list(&self, path: &Path) -> Result<Vec<(String, StoreKind)>> {
        let mut out = Vec::new();
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let ft = entry.file_type()?;
            let kind = if ft.is_dir() {
                StoreKind::Dir
            } else if ft.is_symlink() {
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
    fn walk(&self, root: &Path) -> Result<Vec<Result<(PathBuf, StoreKind)>>> {
        // Mirrors the call sites' WalkDir usage 1:1: follow_links(false),
        // pre-order with the root yielded FIRST (root handling stays
        // per-site — create_ipa needs the root entry, archive.rs:260-266;
        // the min_depth(1) sites skip it themselves). Entry errors are
        // preserved as inner results: `write_tree` (archive.rs:349-356) and
        // the CodeResources scan (code_resources.rs:150-161) propagate them
        // with the message "Failed to walk directory: {e}" — reproduce that
        // exact format here; the min_depth(1) sites skip them
        // (filter_map(|e| e.ok()) at mod.rs:968-970, :1147-1149).
        let mut out = Vec::new();
        for entry in walkdir::WalkDir::new(root).follow_links(false) {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    out.push(Err(Error::Io(std::io::Error::other(format!(
                        "Failed to walk directory: {}",
                        e
                    )))));
                    continue;
                }
            };
            let ft = entry.file_type();
            let kind = if ft.is_dir() {
                StoreKind::Dir
            } else if ft.is_symlink() {
                StoreKind::Symlink
            } else {
                StoreKind::File
            };
            out.push(Ok((entry.path().to_path_buf(), kind)));
        }
        Ok(out)
    }
    fn walk_pruned(
        &self,
        root: &Path,
        prune: &dyn Fn(&Path, StoreKind) -> bool,
    ) -> Result<Vec<Result<(PathBuf, StoreKind)>>> {
        // WalkDir::filter_entry semantics: a pruned subtree is never
        // descended into, so errors inside it never surface — identical to
        // find_immediate_macho_binaries today (mod.rs:1326-1346).
        let kind_of = |ft: walkdir::FileType| {
            if ft.is_dir() {
                StoreKind::Dir
            } else if ft.is_symlink() {
                StoreKind::Symlink
            } else {
                StoreKind::File
            }
        };
        let mut out = Vec::new();
        for entry in walkdir::WalkDir::new(root)
            .follow_links(false)
            .min_depth(1)
            .into_iter()
            .filter_entry(|e| prune(e.path(), kind_of(e.file_type())))
        {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    out.push(Err(Error::Io(std::io::Error::other(format!(
                        "Failed to walk directory: {}",
                        e
                    )))));
                    continue;
                }
            };
            out.push(Ok((entry.path().to_path_buf(), kind_of(entry.file_type()))));
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
            // Exactly what hash_symlink_entry's non-unix arm produces today
            // (bundle/code_resources.rs:281-290); the Error::SymlinkNotSupported
            // variant exists but is constructed nowhere in the workspace.
            Err(Error::Io(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                format!("Symlinks not supported on this platform: {}", path.display()),
            )))
        }
    }
    fn symlink(&self, target: &[u8], path: &Path) -> Result<()> {
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
            Err(Error::Io(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "Symlinks not supported on this platform",
            )))
        }
    }
    fn remove_file(&self, path: &Path) -> Result<()> {
        Ok(std::fs::remove_file(path)?)
    }
    fn set_permissions(&self, path: &Path, mode: u32) -> Result<()> {
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

Fidelity check the implementer MUST run (not assume):
- `walk` is root-inclusive (WalkDir 1:1). Root handling is **per-site**:
  - `write_tree` (`archive.rs:349`) NEEDS the root entry — `create_ipa`
    maps the empty relative path to `Some("Payload/{app}")`
    (`archive.rs:260-266`, a `Payload/{app}/` entry pinned by
    `test_create_ipa_writes_entries_in_sorted_order` at `archive.rs:865`),
    while `create_ipa_from_root` maps it to `None` (`archive.rs:305-311`).
    Excluding the root in the trait would silently drop that entry — this
    is the round-2 finding the current shape exists to avoid.
  - `collect_nested_bundles` (source chain `min_depth(1)` at `mod.rs:966`)
    must skip the root explicitly (`path == bundle_path → continue`; it
    already pushes `(bundle_path, 0)` manually at `:964`).
  - `find_standalone_dylibs` (source chain `min_depth(1)` at `mod.rs:1145`)
    excludes the root naturally — the root is a directory, and its
    `!entry.file_type().is_file() → continue` check drops it before the
    `.dylib` extension test. State this in a comment rather than adding a
    redundant guard.
  - the CodeResources scan drops the root through its existing `is_dir`
    early-return (`code_resources.rs:169-171`) — keep it.
- `walk_pruned`'s `min_depth(1)` matches `find_immediate_macho_binaries`'s
  current chain (`mod.rs:1326`) — root never yielded there, exactly as
  today.

If any site's current handling differs from the table above, preserve the
site's behavior, not the table's.

- [ ] **Step 1.3: Compile and run the scoped native gate**

Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-rs --no-fail-fast 2>&1 | tail -15`
Expected: PASS (nothing consumes `store` yet; the module must compile).

Dead-code handling — exact placement, because Task 8 runs `-D warnings`:
nothing consumes `Store`/`FsStore` until Task 3, so put ONE
`#![allow(dead_code)]`-equivalent at item level: `#[allow(dead_code)]` on the
`Store` trait declaration and on the `FsStore` impl block ONLY — never on
`StoreKind`/`StoreStat` (Task 2's unit tests use them) — and record in the
task report that these two attributes MUST be deleted in Task 3's final step
once every method has a consumer. Task 8 greps the workspace for
`allow(dead_code)` and fails if any remains.

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
use std::sync::Mutex;

enum Node {
    Dir { unix_mode: Option<u32> },
    File { bytes: Vec<u8>, unix_mode: Option<u32> },
    Symlink { target: Vec<u8>, unix_mode: Option<u32> },
}

/// In-memory store keyed by normalized root-relative paths. Children iterate
/// in sorted order (BTreeMap), so walks are deterministic regardless of input
/// zip entry order.
///
/// The map lives behind a `Mutex` so `MemStore: Sync` — required because the
/// generic sign stage compiles its rayon arm on non-wasm targets (the
/// native round-trip tests run this store there). Every method locks and
/// unlocks internally; no guard is ever returned or nested, so no deadlock
/// is possible and the uncontended lock costs nanoseconds next to signing.
pub(crate) struct MemStore {
    nodes: Mutex<BTreeMap<PathBuf, Node>>,
}
```

Required behavior (implement exactly; each is load-bearing):

- `MemStore::new()` seeds the root: insert `PathBuf::new() ->
  Node::Dir { unix_mode: Some(0o40755) }`. `create_dir_all` creates ancestor
  dirs with that same default (`set_permissions` can override it later, so
  zip directory modes replay on output).
- `lock()` helper returning the guard with
  `self.nodes.lock().unwrap_or_else(std::sync::PoisonError::into_inner)` —
  recovery is safe because `BTreeMap` stays memory-consistent after a panic;
  the operation in flight simply fails closed at a higher layer.
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
- `walk(root)`: DFS pre-order over `root` itself and every key strictly
  under it (root FIRST — matching `WalkDir`, whose root entry `create_ipa`
  depends on), children
  sorted by file name; full `root.join(child)`-shaped keys exactly like
  `WalkDir` (native sites `strip_prefix(root)`), inner
  results all `Ok` (an in-memory tree cannot fail mid-walk once built).
  Callers that historically used `min_depth(1)` skip the first (root)
  entry themselves.
- `walk_pruned(root, prune)`: same traversal but root-invisible — the root
  is never yielded (mirrors the source chain's `min_depth(1)`), and
  `prune(path, kind)` is consulted for each child before yielding AND before
  descending — a pruned subtree is
  never visited (matching `WalkDir::filter_entry`).
- `read_link`: return stored target bytes; on a non-symlink, return the
  `NotFound`-shaped io error `fs::read_link` would produce.
- `open`: `Cursor::new(bytes.clone())` boxed — one transient copy, bounded
  by a single file (a borrowed `&[u8]` cannot escape the lock guard).

- [ ] **Step 2.2: Native unit tests for `MemStore`**

Add `#[cfg(test)] mod tests` inside `mem_store.rs` covering: normalize
rejects `../`, absolute, and `.` paths; `write` refuses when an ancestor is a
symlink; `walk` returns sorted pre-order `Ok` entries and excludes the root;
`walk_pruned` never yields entries under a pruned subtree (and does not
descend — assert a poisoned child is unreachable); `metadata` NotFound
mirrors `exists() == false`; `read_link` round-trips target bytes and 4096+
byte targets are rejected at the extract layer (not here); `open` reads back
the written bytes. If `cargo check` flags a `MemStore` method these tests do
not reach, attach the same narrowly-scoped `#[allow(dead_code)]` treatment as
Step 1.3 (removed in Task 3/6 once consumed; Task 8 greps for leftovers).

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

- [ ] **Step 3.1: Add `store: &S` parameters to the sign-stage methods**

All stores are SHARED (`&S`) — writes go through `Store::write(&self, ..)`,
so the rayon closures keep compiling exactly as today (they capture `&S`
where they captured nothing before; `Store: Sync` discharges the bound).
Signature list (parameter order follows the existing source; `store` is
inserted right after `&self`/as first param for associated fns):

```rust
fn sign_bundle_from_options<S: Store>(&self, store: &S, bundle_path: &Path) -> Result<()>
fn sign_bundle<S: Store>(&self, store: &S, bundle_path: &Path) -> Result<()>
fn sign_single_bundle<S: Store>(&self, store: &S, bundle_path: &Path,
    entitlements: Option<&[u8]>, profile_data: Option<&[u8]>,
    already_signed: &HashSet<PathBuf>) -> Result<()>
fn sign_binary<S: Store>(&self, store: &S, root: &Path, binary_path: &Path,
    identifier: &str, code_resources: Option<&[u8]>,
    entitlements: Option<&[u8]>) -> Result<()>
fn sign_standalone_dylib<S: Store>(&self, store: &S, root: &Path,
    dylib_path: &Path) -> Result<()>
fn collect_nested_bundles<S: Store>(&self, store: &S, bundle_path: &Path)
    -> Result<Vec<(PathBuf, usize)>>
fn rewrite_nested_identifiers<S: Store>(&self, store: &S,
    bundles: &[(PathBuf, usize)], root: &Path, old_root_id: &str,
    new_root_id: &str) -> Result<()>
fn find_standalone_dylibs<S: Store>(&self, store: &S, bundle_path: &Path)
    -> Result<Vec<PathBuf>>
fn find_immediate_macho_binaries<S: Store>(&self, store: &S, bundle_path: &Path,
    already_signed: &HashSet<PathBuf>) -> Result<Vec<PathBuf>>
fn generate_code_resources<S: Store>(&self, store: &S, bundle_path: &Path) -> Result<()>
fn rewrite_plist_string<S: Store>(&self, store: &S, bundle_path: &Path,
    key: &str, value: &str) -> Result<()>
fn get_bundle_identifier<S: Store>(&self, store: &S, bundle_path: &Path) -> Result<String>
fn get_main_executable<S: Store>(&self, store: &S, bundle_path: &Path) -> Result<PathBuf>
fn is_macho_binary<S: Store>(&self, store: &S, path: &Path) -> Result<bool>
fn resolve_relative<S: Store>(store: &S, root: &Path, rel: &str) -> Result<PathBuf>
fn resolve_within<S: Store>(store: &S, root: &Path, path: &Path) -> Result<PathBuf>
fn check_no_symlink_components<S: Store>(store: &S, root: &Path, relative: &Path) -> Result<()>
fn ensure_single_app_bundle<S: Store>(store: &S, payload_dir: &Path) -> Result<()>
fn calculate_bundle_depth(&self, bundle_path: &Path, root_bundle: &Path) -> usize  // pure, no store
```

Signatures copied from source at `mod.rs:695,731,892-896,961,1120,1142,
1170,1226-1231,1311-1314,1360,1396,1437,1504,1541-1547,1664` — the
implementer derives any additional private helpers the same way (compile,
pass a store down every callee), and keeps `&self` exactly where the source
has it. The public API (`sign`, `sign_folder_in_place`,
`sign_folder_to_ipa`, all builder setters) keeps its current signatures and
constructs an `FsStore` internally:

```rust
    pub fn sign(&self, input_ipa: impl AsRef<Path>, output_ipa: impl AsRef<Path>) -> Result<()> {
        // ... unchanged validate + TempDir + extract ...
        let store = FsStore;
        self.sign_bundle_from_options(&store, &app_bundle)?;
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
| `fs::File::open(p)` (magic probes, CodeResources streaming) | `store.open(p)?` |
| `fs::read_link(p)` | `store.read_link(p)?` (returns raw bytes — the `#[cfg(unix)]` hashing block `code_resources.rs:270-280` becomes store-based; the `cfg(not(unix))` arm at `:281-290` moves into `FsStore::read_link` as the SAME `Error::Io(ErrorKind::Unsupported, "Symlinks not supported on this platform: {path}")`, and `MemStore` serves symlink targets) |
| `CodeResourcesBuilder::new(path)?.scan()?` (`mod.rs:1665`) | `CodeResourcesBuilder::new(store, path)?.scan()?` — `new`/`scan` gain `&'a S` |

Walk sites — each keeps its EXACT current chain, now over the trait's
per-entry results (inner `Result`s; `let e = e?` propagates, `let Ok(e) = e
else { continue }` skips):

| site | today | becomes |
| --- | --- | --- |
| `write_tree` collect (`archive.rs:349-356`) | propagates `Failed to walk directory: {e}` | `for entry in store.walk(walk_root)? { let entry = entry?; ... }` (FsStore reproduces that message verbatim; the root is yielded first and `name_of` decides its fate — `create_ipa` writes it as `Payload/{app}/` per `archive.rs:260-266`, `create_ipa_from_root` drops it via `None`) |
| `code_resources` scan (`code_resources.rs:150-161`) | propagates same message | `for entry in store.walk(&bundle_path)? { let entry = entry?; ... }` (the par phase then iterates the collected `Vec` as today; the root entry falls out through the existing `is_dir` early-return at `:169-171`) |
| `collect_nested_bundles` (`mod.rs:966-971`) | `min_depth(1).filter_map(ok)` | `store.walk(bundle_path)?` + **`if path == bundle_path { continue; }`** (standing in for `min_depth(1)` — the root is already pushed manually at `:964`) + `let Ok((path, kind)) = entry else { continue };` + the site's existing dir/nested-bundle predicate |
| `find_standalone_dylibs` (`mod.rs:1145-1150`) | `min_depth(1).filter_map(ok)` | `let Ok((path, kind)) = entry else { continue };` skip pattern; the root needs no guard — it is a directory and the site's `!is_file() → continue` drops it before the `.dylib` test (comment this) |
| `find_immediate_macho_binaries` (`mod.rs:1326-1348`) | `min_depth(1).filter_entry(prune).filter_map(ok)` | `store.walk_pruned(bundle_path, &prune_closure)?` + skip pattern — `walk_pruned` reproduces `filter_entry` subtree semantics (a flat walk + post-filter would surface errors inside pruned subtrees that this site never sees today) |

`resolve_relative` (`mod.rs:990`), `resolve_within` (`mod.rs:1022`),
`check_no_symlink_components` (`mod.rs:1091`): the pure component checks
stay as written; only the `fs::symlink_metadata` component walk
(`mod.rs:1096`) becomes `store.metadata`.

- [ ] **Step 3.3: Rayon gates**

Because every store parameter is `&S` (Step 3.1) and `Store: Sync`, the
native `par_iter` closures need NO restructuring — they capture `&S` the way
they already capture `&self`. Only two things change per site: pass `store`
into the callee, and add the wasm32 sequential arm (rayon's thread pool
cannot run on wasm32, so the parallel arm must not even compile there).

Sites: `ipa/mod.rs:857-859` (standalone dylibs), `ipa/mod.rs:1259`
(non-main binaries; its closure body starts at `:1260`), and
`bundle/code_resources.rs:162-163` (scan — read-only, its per-entry `map`
runs over the already-collected `Vec`).

Shape (site 1 shown; site 2 is multi-statement, so extract its closure body
into a private `fn sign_one_binary<S: Store>(...)` called by BOTH arms so
the two arms cannot drift; site 3 is a read-only `map` → `for` loop):

```rust
        #[cfg(not(target_arch = "wasm32"))]
        dylibs.par_iter().try_for_each(|dylib_path| {
            self.sign_standalone_dylib(store, bundle_path, dylib_path)
        })?;
        #[cfg(target_arch = "wasm32")]
        for dylib_path in dylibs {
            self.sign_standalone_dylib(store, bundle_path, dylib_path)?;
        }
```

Native arm first in source order, matching today's expression as closely as
the compiler allows — output bytes are order-independent (design §2), but
the native arm must remain `par_iter` so native signing performance is
untouched. A borrow error here is a design signal, not a test failure to
patch: it means a `&mut S` crept back in (the round-1 blocker) — fix the
signature instead.

- [ ] **Step 3.4: `CodeResourcesBuilder` over the store**

`bundle/code_resources.rs` — the struct is **publicly re-exported**
(`crates/zsign/src/lib.rs:57`), so do NOT genericize its type (a generic
`S: Store` bound would leak the `pub(crate)` trait into a public signature
and trip `private_bounds` under Task 8's `-D warnings`, plus break
`pub fn new`). The trait is object-safe (all-`&self`, no generic methods),
so store type-erasure is the surgical fix:

```rust
pub struct CodeResourcesBuilder<'a> {
    store: &'a dyn Store,   // private field — no public API leak
    // ... existing fields unchanged ...
}

impl<'a> CodeResourcesBuilder<'a> {
    /// Existing public constructor — unchanged signature, now backed by
    /// `FsStore` so external callers behave exactly as before.
    pub fn new(bundle_path: &Path) -> Result<Self> {
        Self::with_store(&FsStore, bundle_path)
    }
    /// Crate-internal constructor used by the generic sign stage.
    pub(crate) fn with_store(store: &'a dyn Store, bundle_path: &Path) -> Result<Self> { /* ... */ }
    pub fn scan(&mut self) -> Result<&mut Self>   // as today, at code_resources.rs:144
}
```

(`&S` arguments coerce to `&dyn Store` at the call site, so the generic
sign fns pass their store straight into `with_store`.)

`scan` keeps its structure — collect entries first (now
`store.walk(&bundle_path)?` mapped to `(PathBuf, StoreKind)` with the
existing root/`is_dir` handling), then the parallel phase over the collected
`Vec` (rayon gate per Step 3.3, site `code_resources.rs:162-163`), then
fold into the inner builder. Reads go through `store`: `fs::read` of
child Info.plists (`:253`), `store.read_link` for raw symlink target bytes
(`:274`, hashing unchanged at `:275-277`), and `store.open` in the 64 KiB
streaming loop of `hash_file_streaming` (fn at `:293`, buffer at `:301`).
The build step continues to call the filesystem-free
`zsign_core::bundle::CodeResourcesBuilder` unchanged (delegation at
`code_resources.rs:222`).

Check every internal constructor: `mod.rs:1665` (sign path → `with_store`),
`crates/zsign/src/verify.rs` (grep `CodeResourcesBuilder::new` →
`with_store(&FsStore, ..)` or keep `new` — both are the same FsStore), and
any tests/doctests in `bundle/code_resources.rs` — public `new(path)` keeps
compiling unchanged for them.

- [ ] **Step 3.5: Full native regression gate (THE checkpoint)**

First, delete the temporary `#[allow(dead_code)]` attributes from Steps 1.3
/ 2.1 — Task 3's wiring gives every `Store`/`FsStore`/`MemStore` item a
consumer, and Task 8 fails on any that remains. (A borrow checker error at
this stage means a `&mut S` crept back in — fix the signature per Step 3.3,
never work around it.)

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

The collect pass inside `extract_ipa_with_limits` (`extract.rs:364-500`) is
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

Data-plumbing change in the same step (cold-review round-1 finding):
`ExtractEntry.unix_mode` (`extract.rs:43`) loses its `#[cfg(unix)]` and the
collect pass records `file.unix_mode()` **unconditionally** (the zip crate's
method is not cfg-gated — verify with `cargo check -p zsign-rs --target
wasm32-unknown-unknown`). The **classification** stays exactly as today for
the FS path: `is_symlink` keeps the current cfg shape (`extract.rs:419-427`,
`true` from the `0o120000` bit on cfg-unix, `false` on cfg-not-unix), so
native non-unix extraction behaves identically. The mem materializer
(Step 5.2) re-derives symlink-ness from `entry.unix_mode` on every target.
Move `MAX_SYMLINK_TARGET_BYTES` (`extract.rs:108-109`) out of `#[cfg(unix)]`
so the cap is shared; it stays used by both the native symlink pass and the
new mem path, so no dead-code warning appears on any target.

- [ ] **Step 5.2: `extract_ipa_into_store`**

```rust
/// Extracts a zip (read from `input`) into `store` under `dest_root`,
/// enforcing the given limits before and while materializing entries.
pub(crate) fn extract_ipa_into_store<S: Store, R: std::io::Read + std::io::Seek>(
    input: R,
    store: &S,
    dest_root: &Path,
    limits: ExtractionLimits,
) -> Result<PathBuf>
```

Sequence (mirrors the native pass order, sequential):

1. `ZipArchive::new(input).map_err(Error::Zip)`.
2. **Pre-check declared sizes** before any materialization: iterate
   `by_index(i)`, accumulate `file.size()`; if any entry `> limits.max_entry`
   or the sum `> limits.max_total_bytes` →
   `Err(Error::InputTooLarge(...))` naming the limit — same phrasing style
   as the native budget messages (`extract.rs:69-71` per-entry,
   `:80-86` total).
3. `collect_entries(...)`.
4. Materialize: `store.create_dir_all` for dirs (entry list order is fine —
   `MemStore::create_dir_all` creates ancestors; dir entries carrying a
   `unix_mode` get `store.set_permissions(path, mode & 0o777)` — same mask
   the native pass applies at `extract.rs:556-563`; `MemStore` Dir nodes
   without an explicit mode default to `0o40755`); for regular entries read
   with `BudgetedWriter` (`extract.rs:53-93`, unchanged — backstop against
   lying headers) into a `Vec<u8>` via `io::copy`, then `store.write` +
   `store.set_permissions(path, mode & 0o777)` when the entry carries a mode
   (the mode rides into `MemStore`'s node so wasm output replays unix modes
   exactly as native does through `set_permissions` + `unix_permissions`);
   symlinks — classify from
   `entry.unix_mode & 0o170000 == 0o120000` on ALL targets (Step 5.1's
   unconditional field), read the bounded target (`take(
   MAX_SYMLINK_TARGET_BYTES + 1)` and error when the cap is exceeded, like
   the native pass at `extract.rs:578-580`), validate with
   `is_safe_symlink_target` (`extract.rs:96-101`), then `store.symlink`.
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

New bytes repack (structurally identical to `create_ipa_from_root` — the
ONLY difference is the `W: Write + Seek` sink; NO synthetic directory
entries, because `create_ipa_from_root` doesn't make them either —
`Payload/` in the output comes from the actual `Payload` directory node in
the tree, and adding one here would duplicate it and break byte identity
with the native twin):

```rust
pub(crate) fn create_ipa_from_store<S: Store>(store: &S, root: &Path, level: CompressionLevel) -> Result<Vec<u8>> {
    let mut cursor = std::io::Cursor::new(Vec::new());
    let mut zip = zip::ZipWriter::new(&mut cursor);
    let options = archive_options(level);
    // The name_of closure is create_ipa_from_root's, verbatim
    // (archive.rs:305-311): the extraction root's empty relative path maps
    // to None — that is what skips the root itself.
    write_tree(&mut zip, store, root, options, &|relative_path| {
        if relative_path.as_os_str().is_empty() {
            None
        } else {
            Some(zip_entry_name(relative_path))
        }
    })?;
    let _ = zip.finish().map_err(Error::Zip)?;
    Ok(cursor.into_inner())
}
```

(The `name_of` closure above is `create_ipa_from_root`'s, verbatim from
`archive.rs:305-311`; `zip_entry_name` is at `archive.rs:425`.)

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
    /// per-entry uncompressed ≤ 512 MiB and total ≤ 2 GiB (enforced here).
    pub fn sign_ipa_bytes(&self, input: &[u8]) -> Result<Vec<u8>> {
        validate_ipa_bytes(input)?;

        let store = MemStore::new();
        let app_bundle = extract_ipa_into_store(
            std::io::Cursor::new(input),
            &store,
            Path::new(""),
            ExtractionLimits::wasm_default(),
        )?;
        Self::resolve_within(&store, Path::new(""), &app_bundle)?;
        Self::ensure_single_app_bundle(&store, Path::new("Payload"))?;
        self.sign_bundle_from_options(&store, &app_bundle)?;

        create_ipa_from_store(&store, Path::new(""), self.compression_level)
    }
```

Supporting pieces (all small, all in `ipa/`):

- `validate_ipa_bytes(input: &[u8]) -> Result<()>` — a **byte-for-byte
  mirror** of `validate_ipa` (`extract.rs:695-713`), which checks only the
  two-byte `PK` prefix (not the 4-byte local-header magic): input shorter
  than 4 bytes → `Error::Io(UnexpectedEof)` shaped like its
  `read_exact(&mut magic)` failure; `&magic[0..2] != b"PK"` →
  `Error::Zip(ZipError::InvalidArchive("Not a valid ZIP/IPA file"))`
  (same `Cow` payload). The path-existence branch of `validate_ipa` has no
  bytes analogue and is not reproduced.
- `ExtractionLimits::wasm_default()` — `max_entry_bytes = 512 MiB`,
  `max_total_bytes = 2 GiB`, documented as the browser-oriented caps; the
  struct and its native `Default` (`extract.rs:238-252`) stay unchanged.
- `MemStore::new()` seeds the root directory node (Task 2.1).

- [ ] **Step 6.2: Native round-trip tests**

Add to `ipa/mod.rs` tests (reusing the existing helpers —
`crate::test_util::test_credentials()` for signing, `minimal_macho()` for
the executable, and `write_test_ipa`-style fixture building at
`mod.rs:1766-1807` writing to a `Vec` via `Cursor` instead of a file; no
new fixture code):

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
3. `test_sign_ipa_bytes_rejects_oversize_declared_entries` — drive
   `extract_ipa_into_store` directly with a small
   `ExtractionLimits { max_entry_bytes: 100, .. }` over a fixture zip whose
   entry declares more, → `Error::InputTooLarge` (mirrors the existing
   `test_extract_ipa_rejects_oversized_entry` pattern from the extract
   hardening work — same limits struct, no giant allocations).
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

(Add this method INSIDE the existing `#[wasm_bindgen] impl WasmSigner` block
(`lib.rs:201`) — the block already carries the attribute; do not repeat it on
the method. Verify exact import paths and setter signatures while
implementing — `CompressionLevel::new` is `archive.rs:78-80`, exported at
`crates/zsign/src/lib.rs:59`.)

- [ ] **Step 7.5: Green check**

Run: `TMPDIR=$PWD/.tmptmp cargo check -p zsign-wasm --target wasm32-unknown-unknown 2>&1 | tail -15`
Expected: PASS (0 errors).

Run: `TMPDIR=$PWD/.tmptmp wasm-pack test --node crates/zsign-wasm 2>&1 | tail -25`
Expected: all tests PASS, including Task 0's `sign_ipa_round_trip_signs_and_verifies_structurally`,
`sign_ipa_size_guard_rejects_one_byte_over`, and
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
Also verify no temporary attribute survived the refactor: no `allow(dead_code)`
anywhere under `crates/` (Step 1.3's promises), and no ticket ID in any code
comment (`grep`/glob over the diff — subjects only).

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
