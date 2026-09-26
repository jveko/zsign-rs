# WASM bytes-to-bytes IPA signing design (ZSN-16)

**Date:** 2026-09-26
**Lane:** zsn43 — branch `zsn43-wasm-full`
**Ticket:** ZSN-16 — full WASM signing path (ZIP in, ZIP out)

**Goal:** A browser hands the wasm module a complete IPA as bytes and gets a
signed IPA back with no JS glue: `sign_ipa_bytes(input: &[u8], config) ->
Result<Vec<u8>>`, exported from `zsign-wasm` as `WasmSigner::sign_ipa`.

## Constraints (from the ticket)

- (a) Wasm-safety: no `std::fs`/`std::thread`/`std::net` reachable on the wasm
  path; the zip codec runs over in-memory `Cursor`.
- (b) Reuse ZSN-40's per-surface size limits and stable `ZSIGN_*` codes; map
  new failures to existing codes — no new code family.
- (c) Honor ZSN-41 determinism (sorted entries, pinned timestamps) and ZSN-39
  root-entry pass-through.
- (d) Bundle/entitlements/profile inputs as BYTES (browsers have no paths).
- (e) wasm-pack round-trip test: build a small IPA in the wasm test, sign it,
  verify the output structurally.
- (f) Document peak memory; set an IPA-level cap consistent with ZSN-40's
  512 MiB / 128 MiB / 16 MiB / 4 MiB guards.
- Native semantics byte-identical: the 42 CLI + 167 facade tests are the
  regression net and must pass unchanged.

## Research facts the design rests on

- `crates/zsign` already compiles for `wasm32-unknown-unknown`
  (`cargo check -p zsign-rs --target wasm32-unknown-unknown` passes; only two
  `cfg(unix)`-related warnings in `ipa/extract.rs`).
- `zsign-wasm` depends only on `zsign-core` today
  (`crates/zsign-wasm/Cargo.toml`); `SigningCredentials` is the *same*
  zsign-core type re-exported by both crates (`crates/zsign/src/lib.rs:50`,
  `crates/zsign-wasm/src/lib.rs:45`), so `IpaSigner::new(&signer.credentials)`
  type-checks across the crate boundary.
- zip 7.2.0 (locked) works over `Cursor` in both directions
  (`ZipArchive<R: Read+Seek>`, `ZipWriter<W: Write+Seek>`, `finish() ->
  ZipResult<W>`), and every metadata/entry API the flow needs (`enclosed_name`,
  `is_symlink`, `unix_mode`, `name_raw`, `add_symlink`, `large_file`) is not
  `cfg(unix)`-gated. Nothing in the zip API is missing for an in-memory path.
- The repo has no `Cursor`-based zip usage today: `archive.rs` writes through
  `ZipWriter<BufWriter<File>>` (`archive.rs:250-251,342-346`) and `extract.rs`
  reads through `ZipArchive<BufReader<File>>` (`extract.rs:341-342`).
- wasm-bindgen 0.2.128 copies `&[u8]`/`Vec<u8>` in BOTH directions
  (`passArray8ToWasm0` copy-in; `.slice()` copy-out) — two full-size copies at
  the ABI are inherent; ZSN-40's known boundary-copy OOM residual stays. The
  only external project shipping a bytes-to-bytes signer in JS today
  (SideImpactor via lbr77/zsign-wasm) exposes exactly
  `signIPA(bytes, config) -> { data }`; Sylva/Quill drive C++ zsign via
  Emscripten FS+argv. No third-party consumes the Rust crate yet — this API is
  the Rust crate's first whole-IPA integration point.
- Browsers: wasm32 linear memory is hard-capped at 4 GiB and never shrinks;
  iOS Safari tabs die far earlier (jetsam). The repo's own demo caps input at
  512 MiB and uncompressed total at 2 GiB (`examples/web/src/main.js`).
- Determinism has no wall-clock/random dependency on the output path: CMS is
  nonce-free and RFC-6979 (`zsign-core/src/crypto/cms.rs:21-23`), the wasm
  clock is pinned (`zsign-core/src/crypto/cert.rs:402-409`), zip timestamps
  are pinned to `zip::DateTime::default()` (`archive.rs:320-333`), archive
  order is bytewise-sorted (`archive.rs:370`), and CodeResources is
  BTreeMap-ordered (`crates/zsign-core/src/bundle/code_resources.rs:67`,
  field `files: BTreeMap<String, FileEntry>` — the filesystem-free core
  builder, not the FS wrapper).

## Candidate architectures (brainstorm)

### Candidate A — storage abstraction over the native flow (CHOSEN)

Introduce a `Store` trait in `crates/zsign` covering the exhaustive IO
primitive set the sign flow needs (derived from the IO inventory: read, open,
write, create_dir_all, list, metadata/lstat, walk, read_link, symlink,
remove_file, set_permissions). `FsStore` delegates to `std::fs`/`WalkDir`
exactly as today; `MemStore` is a rooted in-memory tree. The sign stage becomes
generic over `S: Store`; a new bytes entry point runs
extract-into-`MemStore` → generic sign → repack-from-`MemStore`.

- **Pros:** one source of truth — the ZSN-10/11/12/22 entitlements cascade,
  nested discovery, id rewriting, ZSN-41/39 archive invariants all come from
  the same code the native suite already pins; `crates/zsign` compiles to
  wasm32 today, so no dependency fight; smallest long-term maintenance.
- **Cons:** largest refactor: ~30 `fs::` sites in `ipa/mod.rs`, four WalkDir
  walks, the `CodeResourcesBuilder::scan` walk, and three rayon sites must be
  routed through the store with behavior preserved exactly.

### Candidate B — dedicated wasm-only pipeline in `zsign-wasm` (REJECTED)

Zip decode → memory tree → re-implemented bundle orchestration on
`zsign-core` primitives → zip encode, all inside the wasm crate.

- **Why rejected:** the semantic core (plan build, entitlements cascade,
  nested-bundle discovery, CodeResources exclusions, symlink/containment
  guards) would be duplicated across ~2,000 lines from a very active native
  path. Divergence is guaranteed, and it violates the repo's
  single-convention rule. The existing JS glue in `examples/web/src/main.js`
  already demonstrates that this flow is reconstructible — as *glue*, not as a
  second Rust implementation.

### Candidate C — chunked/streaming bytes API (REJECTED)

Multi-pass streaming so only one zip member is resident at a time.

- **Why rejected:** the ABI forces a full input copy-in and full output
  copy-out regardless, and the API returns one `Vec<u8>` — those two buffers
  dominate peak memory, so streaming the middle saves little while adding a
  two-pass orchestration layer that still requires Candidate A's store
  abstraction. The `hash_file_chunk` streaming surface remains available for
  JS-driven flows. Rejected unless research showed memory demands it; it does
  not, given documented caps below. (OPFS/worker staging is a possible future
  extension, out of scope here.)

## Architecture (Candidate A, scoped)

### 1. `Store` trait — new module `crates/zsign/src/store.rs`

Primitive set derived from the exhaustive IO inventory of the native flow
(`ipa/mod.rs`, `ipa/extract.rs`, `ipa/archive.rs`, `bundle/code_resources.rs`):

```rust
/// Kind of a directory entry, lstat-style (symlink reported as symlink).
pub(crate) enum StoreKind { File, Dir, Symlink }

/// lstat-style metadata for one path.
pub(crate) struct StoreStat { kind: StoreKind, len: u64, unix_mode: Option<u32> }

/// All methods take `&self` so the rayon sites' closures can capture a
/// shared `&S` unchanged (`Sync` supertrait below). Mutation is an
/// implementation detail: `FsStore` is a stateless unit struct delegating
/// straight to `std::fs` (no locks, zero overhead vs today), `MemStore`
/// hides a `Mutex<BTreeMap<..>>` whose guard never leaves a single method.
pub(crate) trait Store: Sync {
    fn read(&self, path: &Path) -> Result<Vec<u8>>;
    /// Owned streaming reader (native: `File`, so `io::copy` callers never
    /// buffer the file; mem: an owned `Cursor` over a per-call clone — the
    /// one transient copy is bounded by a single file).
    fn open(&self, path: &Path) -> Result<Box<dyn Read + Seek>>;
    fn write(&self, path: &Path, data: &[u8]) -> Result<()>;
    fn create_dir_all(&self, path: &Path) -> Result<()>;
    fn list(&self, path: &Path) -> Result<Vec<(String, StoreKind)>>;
    fn metadata(&self, path: &Path) -> Result<StoreStat>;   // lstat; NotFound as io error
    /// Pre-order walk (parent before children) under `root`, root excluded.
    /// Per-entry results preserve each call site's current WalkDir error
    /// handling: sites that propagate errors write `entry?`, sites that
    /// skip write `let Ok(..) = entry else { continue }`. `FsStore` maps
    /// `WalkDir` 1:1 (entries in readdir order, entry errors as inner
    /// `Err`s); `MemStore` yields sorted entries, always `Ok`.
    fn walk(&self, root: &Path) -> Result<Vec<Result<(PathBuf, StoreKind), Error>>>;
    /// Pruned walk mirroring `WalkDir::filter_entry`: returning `false`
    /// skips the subtree entirely (never visited, never yielded, any error
    /// inside it never surfaces) — exact parity for
    /// `find_immediate_macho_binaries`'s nested-bundle pruning.
    fn walk_pruned(&self, root: &Path, prune: &dyn Fn(&Path, StoreKind) -> bool)
        -> Result<Vec<Result<(PathBuf, StoreKind), Error>>>;
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

Mutability split (cold-review round-1 blocker, resolved this way): the three
rayon sites (`ipa/mod.rs:857-859`, `:1259`, `bundle/code_resources.rs:162-163`)
stay structurally untouched — their closures capture `&S` exactly as they
capture `&self` today, writes go through `Store::write(&self, ..)`, and the
`Sync` supertrait discharges rayon's `Send + Sync` bounds (`FsStore` is a
ZST; `MemStore` is `Sync` because `Mutex<T: Send>` is `Sync`). The wasm32
build compiles only the sequential cfg arm at those sites, so rayon never
runs on wasm. A borrow error during implementation is a design-regression
signal, not something to patch around.

Semantics pinned to native behavior:

- `metadata` mirrors `fs::symlink_metadata` (lstat): containment guards
  (`resolve_within`, `check_no_symlink_components`, `extract.rs` TOCTOU checks)
  keep their exact meaning.
- `read_link` returns **raw bytes** so native symlink hashing stays
  byte-identical: `FsStore` (cfg unix) returns
  `read_link(..).as_os_str().as_bytes()`, matching `code_resources.rs:270-279`
  today; `FsStore` (cfg not unix) returns
  `Error::Io(ErrorKind::Unsupported, "Symlinks not supported on this
  platform: {path}")`, exactly what `hash_symlink_entry`'s non-unix arm
  builds today (`code_resources.rs:281-290` — the
  `Error::SymlinkNotSupported` variant exists at `error.rs:51` but is
  constructed nowhere, so the genericized call site must keep producing the
  `Io` variant). `MemStore` returns the zip entry's target bytes — which
  makes symlinked frameworks (symlink entries in the input zip) signable in
  the browser instead of erroring.
- `walk`/`walk_pruned` live in the trait so `FsStore` keeps using `WalkDir`
  exactly as each call site does today (`follow_links(false)`; per-entry
  error handling preserved site-by-site via the inner `Result`s; the
  `filter_entry` pruning at `mod.rs:1323-1334` maps to `walk_pruned` so
  pruned subtrees are never visited — a flat list plus post-filter would
  surface errors inside pruned subtrees that the native site never sees);
  `write_tree` keeps propagating walk errors (it does so today) rather than
  adopting the skip pattern. `MemStore` yields a deterministic pre-order
  traversal with children in sorted order. Walk order never determines
  output bytes (CodeResources is BTreeMap-ordered at
  `zsign-core/src/bundle/code_resources.rs:67`, per-file signs are
  independent, error lists are explicitly sorted at `mod.rs:825-835` and
  `mod.rs:1077`).
- All paths are root-relative keys; `MemStore` rejects absolute/`..`/
  symlink-ancestor writes (equivalent of `validate_output_path` +
  `resolve_within`), so no containment guard is weakened.

`FsStore` is a zero-logic delegator to `std::fs`/`WalkDir`. `MemStore` is a
`Mutex<BTreeMap<PathBuf, Node>>` with `Node = Dir { unix_mode } | File {
bytes, unix_mode } | Symlink { target, unix_mode }`, rooted at
`/`-relative keys (dir modes replay zip directory modes on output; the
default is `0o40755`); the lock guard
is acquired and released inside each method (no async, no nesting, so no
deadlock surface), making `MemStore: Sync` for the native-target tests that
run the pipeline under rayon's parallel arm.

### 2. Genericized sign stage (`ipa/mod.rs`, `bundle/code_resources.rs`)

Every sign-stage method that touches the tree gains a `store: &S`
(`S: Store`) parameter — struct fields and the public builder API of
`IpaSigner` do not change. Mechanical swaps at the inventoried sites:

- `fs::read(p)` → `store.read(p)`; `fs::write` → `store.write`;
  `fs::create_dir_all` → `store.create_dir_all`;
  `fs::remove_file` → `store.remove_file`;
  `exists`/`is_dir`/`symlink_metadata` → `store.metadata`;
  WalkDir sites (`mod.rs:966,1145` via `walk`, `mod.rs:1323` via
  `walk_pruned` — its `filter_entry` subtree pruning is load-bearing, and a
  flat list + post-filter would surface errors inside pruned subtrees that
  the native site never sees — `code_resources.rs:150` via `walk`) with each
  site's existing error handling preserved over the per-entry results;
  `MachOFile::open(p)` → `MachOFile::parse(store.read(p)?)` (open is exactly
  `fs::read` + `parse`, `macho/parser.rs:30-37` — byte-identical);
  `CodeResourcesBuilder` scan reads (`code_resources.rs:253,274`, streaming
  fn at `:293-317`) → store reads. The builder is publicly re-exported
  (`lib.rs:57`), so it is NOT genericized: it holds a `&'a dyn Store`
  (the trait is object-safe) set by a crate-private `with_store`, while the
  public `new(path)` keeps its exact signature backed by `FsStore` — no
  public API change, no `pub(crate)` trait leaking into a public bound.
- The path-based entry points (`IpaSigner::sign`,
  `sign_folder_in_place`, `sign_folder_to_ipa`) construct an `FsStore`
  internally and call the same generic stage — native behavior and signatures
  unchanged. `TempDir` stays native-only, inside `IpaSigner::sign`.
- rayon sites (`mod.rs:857-859`, `mod.rs:1259`, `code_resources.rs:162-163`)
  are gated:
  `#[cfg(not(target_arch = "wasm32"))] par_iter` (unchanged native) vs
  sequential iteration on wasm32. Output bytes are order-independent (see
  research facts), so the gate cannot change results.
- Blob loading (`load_profile`, `load_bundle_profiles`,
  `load_entitlements_override`) resolves through a private `BlobSource` enum:
  `Path(PathBuf)` (native setters, resolved with `fs::read` at the *same*
  point in the flow as today, preserving plan-build error timing) or
  `Bytes(Vec<u8>)` (new wasm-facing setters, resolved without IO). The
  `Path` arm is never constructed on the wasm path; the bytes arm never
  touches IO.
- `entitlements_dir` remains path-based and native-only; the wasm surface
  does not expose it (it never did).

### 3. Bytes-side extract and repack (new code, shared pure logic)

**Extract** (`ipa/extract.rs`): the decision logic — `canonical_entry_name`,
`is_unsafe_entry_name`, `file_ancestor`, `register_ancestor_dirs`,
`ExtractionLimits`, `ExtractEntry` — is already pure and is reused as-is; the
collect pass's reader becomes generic over `R: Read + Seek` so the native
`ZipArchive<BufReader<File>>` call sites keep their types. One data-plumbing
change (cold-review round-1 finding): `ExtractEntry.unix_mode` and the
`MAX_SYMLINK_TARGET_BYTES` const lose their `#[cfg(unix)]` so the bytes are
available on every target — `file.unix_mode()` is not cfg-gated in zip
7.2.0. The **classification** stays target-identical for the native FS path:
the collect pass computes `is_symlink` exactly as today (real mode test on
cfg-unix, `false` on cfg-not-unix, `extract.rs:419-427`), while the new mem
materializer re-derives symlink-ness from `entry.unix_mode`'s `0o120000` bit
unconditionally — so wasm32 (cfg-not-unix) still extracts symlinks as
symlinks without changing native non-unix behavior. A new
`extract_ipa_into_store<S: Store>(input: R, store, limits)` materializes the
collected `ExtractEntry` list sequentially through the store (mkdir entries
+ `set_permissions` for modes, `store.write` for files through
`BudgetedWriter`, `store.symlink` for symlinks classified from the
unconditional `unix_mode`) with the same validation order as the native
passes. The native
FS materialization (rayon, TOCTOU re-stat, `set_permissions`) is untouched.

- `find_app_bundle` gets a store-based sibling driven by `store.list` with
  the same first-`.app`-then-`ensure_single_app_bundle` ambiguity rejection
  (`mod.rs:1067`, candidates sorted at `:1077`).

**Repack** (`ipa/archive.rs`): `write_tree` becomes
`write_tree<S: Store, W: Write + Seek>(zip: &mut ZipWriter<W>, store: &S,
walk_root, options, name_of)`. The body keeps the exact invariants: bytewise
sort (`:370`), precomputed-stored bypass (`:388-394`), ZIP64 gate from entry
length (`:403-407`), pinned `DateTime::default()` via `archive_options`
(`:320-333`), unix mode now sourced from `store.metadata` — `FsStore` keeps
cfg(unix) `PermissionsExt` behavior, `MemStore` replays the mode read from the
input zip (so wasm output *also* carries unix modes). Native entry points
(`create_ipa`, `create_ipa_from_root`) call it with `FsStore` + `BufWriter<File>`
— byte-identical output; the wasm entry calls it with `MemStore` +
`Cursor<Vec<u8>>` and returns `cursor.into_inner()`.

### 4. Public API

`crates/zsign` (engine, compiled to wasm):

```rust
impl IpaSigner {
    /// Bytes-to-bytes IPA signing over an in-memory store.
    pub fn sign_ipa_bytes(&self, input: &[u8]) -> Result<Vec<u8>>;
    /// Bytes-source setters used by the wasm surface (native keeps path setters).
    pub fn provisioning_profile_bytes(self, data: Vec<u8>) -> Self;
    pub fn entitlements_bytes(self, data: Vec<u8>) -> Self;
}
```

Orchestration mirrors `IpaSigner::sign` (`mod.rs:509-532`) with the MemStore
pipeline: validate bytes (PK magic, same as `validate_ipa`) → extract into
`MemStore` (limits below) → `resolve_within` + `ensure_single_app_bundle`
(store-generic) → `sign_bundle_from_options(store)` → repack from store root
(ZSN-39 pass-through falls out of "walk the extraction root").

`crates/zsign-wasm` (ABI marshaling only):

```rust
#[wasm_bindgen]
impl WasmSigner {
    /// Sign a complete IPA in memory; returns the signed IPA bytes.
    pub fn sign_ipa(
        &self,
        input: &[u8],
        bundle_id: Option<String>,
        bundle_name: Option<String>,
        bundle_version: Option<String>,
        compression_level: Option<u8>,
    ) -> Result<Vec<u8>, JsValue>;
}
```

- `WasmSigner` gains a `profile_bytes: Option<Vec<u8>>` field (the raw
  profile is already accepted by `new`, only entitlements were kept —
  `lib.rs:238-247`); `sign_ipa` builds
  `IpaSigner::new(&self.credentials).provisioning_profile_bytes(...)`,
  wires `self.entitlements_override` into `entitlements_bytes` (ZSN-10
  precedence: explicit override beats profile, as `set_entitlements`
  documents), and applies the id/name/version/compression options.
- Shape matches the one external bytes-to-bytes precedent
  (SideImpactor's `signIPA(bytes, config)`) while reusing the ZSN-40
  constructor semantics (p12 + password + profile bytes, `set_entitlements`).
- Options intentionally limited to what browser glue does today
  (`examples/web/src/main.js`): id/name/version/compression. Path-only or
  operator features (`entitlements_dir`, `bundle_profiles` map,
  `remove_embedded_profile`, dylib injection, `allow_encrypted`) are not
  exposed — fail-closed defaults apply.

### 5. Error mapping (constraint b — existing codes only)

One new Rust variant, **no new `ZSIGN_*` code**: `zsign_rs::Error` gains
`InputTooLarge(String)` so the bytes pipeline can report size-cap breaches
type-safely (the wasm layer must never string-match `Display` output — stable
codes come via `Reflect` on `error.code`). The wasm layer adds an exhaustive
`code_for_zsign_error(&zsign_rs::Error) -> WasmErrorCode`:

| `zsign_rs::Error` variant | code | rationale |
| --- | --- | --- |
| `Core(e)` | existing `code_for_core_error(e)` | unchanged path |
| `Plist` | `ZSIGN_INVALID_PLIST` | matches current table row |
| `MissingCredentials` | `ZSIGN_MISSING_CREDENTIALS` | matches current table row |
| `InputTooLarge` (new) | `ZSIGN_INPUT_TOO_LARGE` | IPA/input caps, same family |
| `Zip` | `ZSIGN_SIGNING_FAILED` | malformed/hostile archive; message carries zip detail |
| `Io` | `ZSIGN_SIGNING_FAILED` | store/containment failures; fail-closed |
| `SymlinkNotSupported` | `ZSIGN_SIGNING_FAILED` | unreachable on wasm (`MemStore` supports symlinks) |

No new code family; the doc table in `crates/zsign-wasm/src/lib.rs` gains a
`sign_ipa` row noting which of the existing codes it can produce.

### 6. Limits and memory model (constraint f)

New limits, consistent with ZSN-40's registry:

| constant | value | where enforced | code |
| --- | --- | --- | --- |
| `MAX_IPA_BYTES` (new, `zsign-wasm`) | 512 MiB | `ensure_size(input)` before the call | `ZSIGN_INPUT_TOO_LARGE` |
| input zip per-entry uncompressed (new `ExtractionLimits` value for the bytes path) | 512 MiB | pre-check on `entry.size()` in `extract_ipa_into_store` | `ZSIGN_INPUT_TOO_LARGE` |
| input zip total uncompressed (bytes path) | 2 GiB | running sum of `entry.size()` + `BudgetedWriter` as backstop | `ZSIGN_INPUT_TOO_LARGE` / fail-closed `Io` |
| existing `MAX_P12_BYTES` 4 MiB, `MAX_PROFILE_BYTES`/`MAX_PLIST_BYTES` 16 MiB, `MAX_MACHO_BYTES` 512 MiB, `MAX_HASH_BYTES` 128 MiB | unchanged | unchanged | unchanged |

512 MiB mirrors `MAX_MACHO_BYTES` and the demo's `MAX_IPA_BYTES`; 2 GiB
uncompressed mirrors the demo's `MAX_UNCOMPRESSED_BYTES`.

**Peak-memory expectations (documented in the `sign_ipa` doc comment):**

- ABI: input copied into linear memory once (held for the whole call) and
  output copied out once — both inherent to wasm-bindgen 0.2.128
  (`passArray8ToWasm0` / `.slice()`), the known boundary-copy OOM residual.
- Wasm linear heap during the call ≈ `N` (input copy) + `U` (uncompressed
  `MemStore` tree) + `M` (output `Vec`) + per-file signing working set
  (roughly 2–3× the largest single binary, per the crate's existing sizing
  note). The caps are **per-stage guards, not a jointly-saturable envelope**:
  saturating every cap simultaneously (0.5 + 2.0 + 0.5 GiB + up to 1.5 GiB
  working set for a legal 512 MiB binary) reaches ~4.5 GiB and exceeds the
  4 GiB wasm32 ceiling. The binding constraint is therefore
  `N + U + M + working < 4 GiB`; the supported operational envelope is
  stated as: input ≤ 512 MiB **and** declared uncompressed total ≤ 2 GiB,
  with expected peaks ≈ 2–3× input for realistic archives (300–600 MiB
  inputs ≈ 1–1.8 GiB peak). Inputs whose combined footprint approaches the
  ceiling can abort on allocation — documented as a known OOM residual,
  alongside ZSN-40's boundary-copy residual, rather than hidden behind the
  per-stage numbers.
- JS heap simultaneously holds the original `Uint8Array` (`N`) and the result
  (`M`).
- Linear memory never shrinks: a large sign leaves a permanent per-tab
  watermark. Guidance to document: desktop-class browsers for inputs above
  ~100 MiB; iOS Safari tabs may be jetsam-killed regardless of the caps.

### 7. Determinism and archive invariants (constraint c)

The bytes path shares the same code that owns each invariant today:

- **Sorted entries + pinned timestamps + ZIP64 gate:** `write_tree`/
  `archive_options` (genericized, not duplicated) — `archive.rs:320-333,370,403-407`.
- **UTF-8 entry names (ZSN-7/41 work):** raw-bytes-first decode in
  `canonical_entry_name` (`extract.rs:111-120`) is reused by the shared
  collect pass; creation side stays as-is (zip recomputes bit 11).
- **Root-entry pass-through (ZSN-39):** repack walks the extraction *root*
  (not `Payload/`), so `SwiftSupport/`, `iTunesMetadata.plist`, etc. ride
  through verbatim — same as `create_ipa_from_root` (`archive.rs:280-313`).
- **No wall clock / randomness** reaches output bytes (research facts above);
  the pinned wasm clock (`1_800_000_000`) is used for cert validity
  accept/reject only.

## Test plan (constraint e)

1. **Native (regression + new pipeline):** existing 42 CLI + 167 facade tests
   must pass *unchanged*. New native tests in `crates/zsign/src/ipa/mod.rs`
   exercise `IpaSigner::sign_ipa_bytes` round-trip (fixture IPA built in-test
   with `ZipWriter`, mirroring `write_test_ipa` `mod.rs:1766-1807`): output is
   a valid zip, `_CodeSignature/CodeResources` seals every non-excluded file,
   main executable parses as a signed SuperBlob, non-`Payload` root entries
   survive, and a second sign is byte-identical (determinism, matching
   `test_ipa_signing_is_deterministic`).
2. **Wasm round-trip (the acceptance test):** one
   `#[wasm_bindgen_test(unsupported = test)]` in
   `crates/zsign-wasm/src/lib.rs` tests module: build a small IPA in-test
   (`zip` as a dev-dependency of `zsign-wasm`; `MINIMAL_MACHO` executable,
   existing `LEAF_P12_B64` + `PROFILE_XML` fixtures), call
   `signer.sign_ipa(...)`, then assert structurally by re-parsing the output
   with `zip::ZipArchive` over a `Cursor` — `Payload/` + `_CodeSignature/
   CodeResources` present, root pass-through entry present, main executable
   re-parses via `zsign_core` `parse_superblob` and its signature verifies
   with the existing `anchored_verify`/`anchored_verify_slice` helpers, and
   re-signing yields byte-identical output. `unsupported = test` runs it both
   under `wasm-pack test --node` and natively under `cargo test`.
3. **Limits/errors:** extend the ZSN-40 patterns — input one byte over
   `MAX_IPA_BYTES` → `ZSIGN_INPUT_TOO_LARGE`; corrupt input →
   `ZSIGN_SIGNING_FAILED` (asserted via `js_sys::Reflect` on `error.code`,
   never message matching).

## Files touched

- **Create:** `crates/zsign/src/store.rs` (trait, `StoreKind`, `StoreStat`,
  `FsStore`); `crates/zsign/src/ipa/mem_store.rs` (`MemStore` + unit tests).
- **Modify:** `crates/zsign/src/ipa/mod.rs` (generic sign stage, `BlobSource`,
  bytes setters, `sign_ipa_bytes`, rayon gates, new tests);
  `crates/zsign/src/ipa/extract.rs` (generic collect reader,
  `extract_ipa_into_store`, `find_app_bundle` store sibling);
  `crates/zsign/src/ipa/archive.rs` (generic `write_tree`, bytes repack
  entry); `crates/zsign/src/bundle/code_resources.rs` (scan over `&S`);
  `crates/zsign/src/error.rs` (`InputTooLarge` variant);
  `crates/zsign/src/lib.rs` (module wiring); `crates/zsign-wasm/Cargo.toml`
  (+ `zsign-rs` dep, `zip` dev-dep); `crates/zsign-wasm/src/lib.rs`
  (`sign_ipa`, `profile_bytes`, error mapping, doc table, tests).
- **Not touched:** `crates/zsign-core/src/macho/**`,
  `crates/zsign-core/src/crypto/**` (zsn44), `crates/zsign-cli/src/main.rs`
  (zsn44), README/docs (wave-7), fixtures/.gitignore policy (ZSN-30 wave 7 —
  no new committed fixture files; IPAs are built in-test).

## Acceptance

- `wasm-pack test --node crates/zsign-wasm` green including the new
  round-trip test; `cargo test --workspace --no-fail-fast` fully green with
  no skips; `cargo fmt --all --check`; `cargo clippy --workspace
  --all-targets -- -D warnings`; `cargo check -p zsign-wasm` (wasm32).
- Native output bytes for existing flows unchanged (existing determinism and
  byte-identity tests pass unmodified).
- Memory, limits, and error-code mapping documented in this spec and in the
  `sign_ipa` doc comment/table.

## Docs-lane needs (recorded, not done here)

- README/wasm README: document `sign_ipa` with the memory guidance table and
  error-code row; note that `examples/web` still demonstrates the fine-grained
  per-entry API and could later showcase `sign_ipa`.
