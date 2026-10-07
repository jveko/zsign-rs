# Store-threaded nested-bundle detection design

## Problem

Three coupled defects in the facade sign flow; the first two are a mandated
pair (fixing either alone makes the other worse), the third was discovered
during research and is forced into scope by the mandated parity test.

1. **Nested-bundle detection bypasses the `Store`.**
   `bundle_markers` reads `std::fs::read(path.join("Info.plist"))`
   (`crates/zsign/src/bundle/mod.rs:109`) with no `Store` parameter, so
   `is_nested_bundle_dir` (`bundle/mod.rs:69`) is invisible to the storage
   abstraction. On `MemStore` (the `sign_ipa_bytes` bytes-to-bytes pipeline,
   documented "no filesystem access" at `ipa/mod.rs:666-667`) the raw read
   fails against the host filesystem, the markers arm answers "not a bundle",
   and every extension-less/marker-detected nested bundle is silently skipped:
   never signed, never sealed, no cascade — plus a host-FS read at a
   CWD-resolvable path on the wasm path (`bundle/mod.rs` carries no cfg gate).
2. **Prune-under-lock deadlock.** `MemStore::walk_inner`
   (`ipa/mem_store.rs:214-232`) takes `let nodes = self.lock();` at `:221` and
   `walk_children` (`:235-252`) invokes the caller's prune closure at `:243`
   while that `MutexGuard` is alive on the same stack. The struct doc claims
   the opposite at `mem_store.rs:68-70` ("no guard is ever returned or nested,
   so no deadlock is possible"). The only in-tree prune predicate
   (`find_immediate_macho_binaries`, `ipa/mod.rs:1561-1570`) currently
   escapes because its body reads `std::fs` through the bypass in (1) — fixing
   (1) alone turns the deadlock live, which is why the pair must land
   together.
3. **`MemStore` prune polarity is inverted** (discovered, not ticketed).
   The trait contract says `prune` returning `false` skips the subtree
   (`store.rs:76-78`), which is `WalkDir::filter_entry` semantics, which is
   what `FsStore::walk_pruned` does (`store.rs:215-218`, closure passed
   straight to `filter_entry`, true = keep/descend) and what the only caller's
   intent and doc assume (`ipa/mod.rs:1544`, returns `false` for nested-bundle
   dirs). `MemStore::walk_children` does the opposite (`if prune(...) {
   continue; }` at `:243-245` — true = skip; its own inner doc at `:212-213`
   says so). Consequence: on `MemStore`, `find_immediate_macho_binaries`
   descends into nested bundles that native pruning excludes — the mem and
   native entry lists cannot match, so the mandated parity test forces this
   fix into the same landing.

## Verified evidence (current source)

- Detector: `pub fn is_nested_bundle_dir(path: &Path) -> bool`
  (`bundle/mod.rs:69`); extension arm `:70-77` (no IO); markers arm via
  `bundle_markers` `:108-123` with the single raw read at `:109`; marker rules
  `:82-100` (non-empty `CFBundleIdentifier` + `CFBundleExecutable`, then
  parent in `NESTED_CODE_LOCATIONS` `:46-54` or `CFBundlePackageType` in
  `{APPL, FMWK, XPC!}` `:59`).
- Callers (complete, grep-verified): `ipa/mod.rs:1165`
  (`collect_nested_bundles<S: Store>`, holds `&S`), `ipa/mod.rs:1324`
  (`calculate_bundle_depth(&self, bundle_path, root_bundle) -> usize`, holds
  no store; reached from `:1166`), `ipa/mod.rs:1564` (prune closure inside
  `find_immediate_macho_binaries<S: Store>`, holds `&S`),
  `verify.rs:155` (`has_nested_bundle_component`, native) and `verify.rs:449`
  (`verify_bundle_dir`, native), plus `bundle/mod.rs` tests (`:155-193`) and
  doc links.
- Public surface: `pub mod bundle` (`lib.rs:41`), `mod store` PRIVATE
  (`lib.rs:44`); `Store`/`FsStore`/`StoreKind`/`StoreStat`/`ReadSeek` are all
  `pub(crate)` (`store.rs`). The established shape for store-aware helpers on
  public types is `CodeResourcesBuilder`: `pub fn new(path)` delegating to
  `pub(crate) fn with_store(store: &'a dyn Store, …)` (`bundle/code_resources.rs:97-103`).
- Walk contracts: `Store::walk` / `Store::walk_pruned` (`store.rs:73-82`);
  `walk_pruned` doc pins `false` = skip (`store.rs:76-78`); `FsStore` passes
  the closure to `WalkDir::filter_entry` (`store.rs:216`); `MemStore`
  inverts (`mem_store.rs:243-245`); `walk_inner` locks once at `:221`,
  invokes the closure at `:243` with the guard alive; `walk`/`walk_pruned`
  entry points at `:356-372`; `lock()` recovers poisoning at `:107-111`.
  `children()` already materializes an owned `Vec<(PathBuf, PathBuf, StoreKind)>`
  per level (`mem_store.rs:186-199`), so per-level materialization adds no
  allocation — only the guard's scope changes.
- Owned-move precedent: `bundle/code_resources.rs:169-174` ("the walk hands
  back owned data") collects `Vec<WalkEntry>` before any further store use.
- Existing polarity tests: `walk_pruned_never_yields_root_or_pruned_subtree`
  (`mem_store.rs:560`) and `walk_pruned_prunes_a_single_entry_by_kind`
  (`mem_store.rs:591`) pin true=skip via their predicates
  (`p.ends_with("secret")`, `kind == StoreKind::File`); their asserted
  outputs express real pruning intent and stay unchanged when the predicates
  are inverted to the documented false=skip convention.

## External contract (source-verified)

- `std::sync::Mutex::lock`: "The exact behavior on locking a mutex in the
  thread which already holds the lock is left unspecified. However, this
  function will not return on the second call (it might panic or deadlock…)"
  — same-thread re-lock never returns (matches the observed 90s hang); it is
  a safe-API non-return, not UB. (std docs, `Mutex::lock`.)
- Poisoning: a panic while the guard is held poisons the mutex; `lock()`
  then errors for other threads. Moving the closure call outside the guard
  removes that side effect (a panicking predicate no longer poisons the
  store). (std docs, § Poisoning.)
- The std docs' own example endorses exactly this fix's shape: "We drop the
  `data` explicitly … If we had not dropped the mutex guard, a thread could be
  waiting forever for it, causing a deadlock." (std `Mutex` Examples.)

## Design (chosen)

One landing, four coordinated changes:

1. **Thread the store through the detector** (gap 1): make
   `is_nested_bundle_dir` `pub(crate) fn is_nested_bundle_dir(store: &dyn
   Store, path: &Path) -> bool`, with `bundle_markers(store, path)` reading
   `store.read(&path.join("Info.plist")).ok()?` (identical semantics for both
   stores: any read failure still means "not a bundle"). Migrate every
   caller: the three ipa sites pass their in-scope `store` (coerces `&S` →
   `&dyn Store`); the two native verify sites construct `&FsStore`; the bundle
   tests pass `&FsStore`. Shrinking `pub` → `pub(crate)` matches reality —
   `Store` is crate-private, so a public store-parameterized function would
   either trip the private-interface lint or force a public-`Store` cascade
   (trait + `StoreKind` + `StoreStat` + `ReadSeek` + `FsStore`) that expands
   the API for no external caller; the crate's precedent
   (`CodeResourcesBuilder::with_store`) is exactly this visibility.
   `calculate_bundle_depth` gains a `store: &dyn Store` parameter (threaded
   from `collect_nested_bundles`).
2. **Materialize per level, drop the guard, then prune and recurse** (gap 2):
   `walk_inner` scopes its lock to the root-node lookup; `walk_children`
   becomes a `&self` method that, per level, locks, calls `children()`,
   drops the guard, then applies `prune` and recurses (re-locking at each
   level). No caller closure ever runs under the guard. This is the
   owned-data move `bundle/code_resources.rs:169-174` already makes, applied
   per level.
3. **Align prune polarity** (gap 3): `walk_children` skips on
   `!prune(&path, kind)` (false = skip), matching `store.rs:76-78`,
   `FsStore`, and caller intent; correct the inner doc (`mem_store.rs:212-213`)
   and the struct doc's false no-deadlock claim (`mem_store.rs:68-70`); invert
  the two existing test predicates (asserted outputs unchanged).
4. **Doc truth**: the "no filesystem access" contract at `ipa/mod.rs:666-667`
   becomes true for detection as well; the two public doc links to
   `is_nested_bundle_dir` (`verify.rs:14`, `verify.rs:83`) become plain code
   spans so rustdoc does not link public docs to a crate-private item.

## Candidate designs considered

- **A (chosen): `&dyn Store` threading + per-level guard drop + polarity
  alignment.** Matches the ticket direction and the codebase's existing
  `&dyn Store` shape; per-level locking costs one uncontended lock per level
  (the doc already prices this at nanoseconds); polarity lands because the
  mandated parity test cannot pass without it.
- **B: snapshot the whole map under one lock, traverse offline.** Rejected:
  clones the entire tree per walk (unbounded cost, brief explicitly prescribes
  per-level materialization), and still needs the polarity fix.
- **C: reentrant lock / alternative lock type.** Rejected: new dependency or
  API surface for a callback-scope problem the std docs already prescribe a
  fix for; hides the real rule (no user code under the guard).

## Decisions and rejected alternatives

- **Visibility**: `pub(crate)` detector (above), not `pub fn` + public
  `Store` cascade; not a path-based wrapper kept beside a store-aware twin —
  a second convention/shim is prohibited, and the brief mandates threading the
  store *through* `is_nested_bundle_dir`.
- **Polarity flips the `MemStore` side**, not the trait doc/FsStore/caller:
  the documented contract, `WalkDir` semantics, and the only caller's intent
  and doc all agree on false=skip; only `MemStore` and its two test predicates
  disagree.
- **File-list deviation (compiler-forced, recorded):** the ticket's file list
  omits `verify.rs`, but its two detector call sites must migrate for the
  crate to compile ("migrate every caller" is a hard rule; the triage caller
  map missed them). The touch is exactly two call sites, one import, and two
  doc-link rewordings — no behavioral change in `verify.rs`.
- `store.rs` itself needs no change: its trait docs already state the correct
  contract.
- Semantics preserved: markers-arm read failures still mean "not a bundle";
  native behavior is byte-identical (`FsStore::read` = `std::fs::read`);
  extension-arm behavior is unchanged (no IO).

## Testing

- `walk_pruned_allows_a_store_consulting_predicate` (mem_store tests) — the
  same test compiles against the old and new implementation: it spawns a
  worker thread running `walk_pruned` with a predicate that calls back into
  the same store (`metadata`), and the test thread waits on a channel with a
  timeout. Before the fix the worker never returns (second `lock()` on the
  same thread) → the test FAILS at the timeout with a deadlock message; after
  the fix it completes → PASS. The leaked blocked thread cannot wedge the
  suite (isolated store instance; process exits normally).
- `mem_and_native_entry_lists_match_for_extension_less_nested_bundle`
  (bundle tests) — the same logical tree in a temp directory and in a
  `MemStore`, containing an extension-less marker-complete directory under
  `Frameworks/`; both stores run `walk_pruned` with the store-bound
  `find_immediate`-shaped predicate; native paths are stripped of the temp
  root; asserted equal, and both detectors agree (`true`) on their respective
  spellings of the nested bundle. This test uses the new signature, so its
  pre-fix RED is compile-gated by the API change itself (recorded honestly);
  its regression value is the cross-store contract.
- Existing suites: native sign/verify flows (unchanged behavior), mem
  round-trip tests, the two polarity tests (predicates inverted, outputs
  unchanged), bundle detection tests (now `&FsStore`).

## Acceptance

- `sign_ipa_bytes` detects extension-less nested bundles (no host-FS read on
  the bytes pipeline) and cascades to them.
- A store-consulting prune predicate completes without deadlock; no caller
  closure runs under a `MemStore` guard.
- `FsStore` and `MemStore` `walk_pruned` entry lists are identical for the
  same tree and predicate convention (false = skip everywhere).
- Zero-warning gate green: `cargo fmt --all -- --check`,
  `cargo clippy --workspace --all-targets -- -D warnings`,
  `TMPDIR=$PWD/target/tmp cargo test --workspace` (plus a scoped
  `cargo doc --no-deps -p zsign-rs` with no intra-doc-link warnings).
