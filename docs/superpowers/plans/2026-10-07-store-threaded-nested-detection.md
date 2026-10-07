# Store-Threaded Nested-Bundle Detection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development (recommended) with dispatching-parallel-agents for independent tasks to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make nested-bundle detection read through the `Store`, make
`MemStore` walks release their guard before invoking any caller closure, and
align `MemStore` prune polarity with the documented contract — one landing.

**Architecture:** The detector becomes
`pub(crate) fn is_nested_bundle_dir(store: &dyn Store, path: &Path)` and all
five production callers migrate (ipa passes its in-scope store, verify passes
`&FsStore`). `MemStore::walk_inner`/`walk_children` materialize each level's
children under the guard, drop it, then prune and recurse — with
`false = skip`, matching `store.rs`, `FsStore`, and the only caller.

**Tech Stack:** Rust 2021, `std::sync::Mutex` + `std::sync::mpsc` timeout
harness, inline `#[cfg(test)]` tests per file.

**Spec:** `docs/superpowers/specs/2026-10-07-store-threaded-nested-detection-design.md`

## Global Constraints

- Files: `crates/zsign/src/bundle/mod.rs`, `crates/zsign/src/ipa/mod.rs`,
  `crates/zsign/src/ipa/mem_store.rs`, `crates/zsign/src/verify.rs`
  (call-site migration + two doc-link rewordings only — compiler-forced, see
  spec), `crates/zsign/src/store.rs` only if a doc line needs it (expected:
  not needed). No other file.
- Detector signature (exact): `pub(crate) fn is_nested_bundle_dir(store:
  &dyn Store, path: &Path) -> bool`; `bundle_markers(store: &dyn Store,
  path: &Path)` reads `store.read(&path.join("Info.plist")).ok()?`.
- Prune polarity everywhere: `false` skips the subtree (`WalkDir::
  filter_entry` convention). Mem skip condition: `if !prune(&path, kind)`.
- No caller closure runs while a `MemStore` guard is alive; guard scope is
  the root lookup and the per-level `children()` materialization only.
- Doc claims updated to truth: `mem_store.rs:68-70` (no-deadlock claim) and
  the `walk_inner` `true`-skips line; `verify.rs:14` and `:83` lose their
  intra-doc links (plain code spans).
- No ticket IDs anywhere; no new dependencies; no stubs/TODOs; match each
  file's existing import style; `TMPDIR=$PWD/target/tmp` for tests.

## Review Focus

- Marker semantics must not drift: any `store.read` failure still maps to
  "not a bundle" (`.ok()?`), identical to today's `std::fs::read(...).ok()?`
  for both stores — the deadlock/polarity work must not turn read errors into
  detections or panics.
- The deadlock test must fail by TIMEOUT under the old implementation and
  pass quickly under the new one; it must compile against both (it uses only
  `walk_pruned` + `metadata`), and a regressed walk must fail the test, not
  wedge the suite.
- Parity test must compare entry SETS (sort both sides): native `WalkDir`
  order is readdir-dependent while `MemStore` is BTreeMap-sorted; the
  contract is membership (the nested subtree pruned on both sides), not
  sequence.
- The two pre-existing `walk_pruned` tests keep their asserted outputs; only
  their predicates invert to `false = skip` — a changed assertion means the
  polarity reasoning is wrong and the task stops.
- `verify.rs` behavior must be byte-identical (`&FsStore` = host FS, same
  reads); its touch is imports/call args/doc spans only.

---

### Task 1: Failing deadlock regression test

**Files:**
- Modify: `crates/zsign/src/ipa/mem_store.rs` (tests module, appended after
  `walk_pruned_prunes_a_single_entry_by_kind`)

**Interfaces:**
- Consumes: `store()` test helper (`mem_store.rs:431`), `MemStore` as a
  `Store` (`create_dir_all`, `write`, `walk_pruned`, `metadata`),
  `Path`/`StoreKind` already in scope, std `mpsc`/`Duration`.
- Produces: `walk_pruned_allows_a_store_consulting_predicate` — Task 2 must
  turn it from timeout-FAIL to PASS without changing it.

- [ ] **Step 1: Write the test**

```rust
#[test]
fn walk_pruned_allows_a_store_consulting_predicate() {
    let s = store();
    s.create_dir_all(Path::new("Payload/App.app/Frameworks"))
        .unwrap();
    s.write(Path::new("Payload/App.app/Info.plist"), b"<plist/>")
        .unwrap();
    s.write(Path::new("Payload/App.app/icon.png"), b"i").unwrap();

    let (tx, rx) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        // The predicate may consult the same store: the walk must not hold
        // its lock while the closure runs.
        let outcome = s.walk_pruned(Path::new("Payload"), &|p, _| {
            let _ = s.metadata(p);
            true
        });
        tx.send(outcome.map(|entries| entries.len())).ok();
    });
    match rx.recv_timeout(std::time::Duration::from_secs(10)) {
        Ok(Ok(n)) => assert!(n > 0, "walk should yield entries, got {n}"),
        Ok(Err(e)) => panic!("walk_pruned failed: {e}"),
        Err(_) => panic!(
            "walk_pruned deadlocked: a store-consulting prune predicate did not return within 10s"
        ),
    }
    worker.join().unwrap();
}
```

- [ ] **Step 2: Run it to confirm the RED failure**

Run: `TMPDIR=$PWD/target/tmp cargo test -p zsign-rs walk_pruned_allows_a_store_consulting_predicate`
Expected: FAIL after ~10s with the "walk_pruned deadlocked" panic (the
worker re-locks the mutex on the same thread and never returns), while the
test process stays responsive. Then run
`TMPDIR=$PWD/target/tmp cargo test -p zsign-rs mem_store` to confirm every
other `mem_store` test still passes. If any other test fails, STOP and
report.

---

### Task 2: Store threading, guard scope, polarity

**Files:**
- Modify: `crates/zsign/src/bundle/mod.rs`
- Modify: `crates/zsign/src/ipa/mod.rs`
- Modify: `crates/zsign/src/ipa/mem_store.rs`
- Modify: `crates/zsign/src/verify.rs` (call sites + doc spans only)

**Interfaces:**
- Consumes: `Store`/`FsStore` (`store.rs`, `pub(crate)`), `MaybePruneFn`,
  `children()` (`mem_store.rs:186-199`), Task 1's test.
- Produces: the detector signature in Global Constraints (Task 3 and any
  later caller rely on it); `walk_pruned` contract false=skip for both
  stores; Task 1's test turning GREEN.

- [ ] **Step 1: Thread the store through the detector (`bundle/mod.rs`)**

Add `use crate::store::Store;` to the file's use block. Change
`pub fn is_nested_bundle_dir(path: &Path) -> bool` to `pub(crate) fn
is_nested_bundle_dir(store: &dyn Store, path: &Path) -> bool`, pass `store`
to `bundle_markers`, and change `bundle_markers`'s first line from
`std::fs::read(path.join("Info.plist")).ok()?` to
`store.read(&path.join("Info.plist")).ok()?` (signature gains
`store: &dyn Store` first). Adjust the fn doc only where it implies a
filesystem read. Update every test call site in the same file's tests to
`is_nested_bundle_dir(&FsStore, …)` with `use crate::store::FsStore;` in the
test module.

- [ ] **Step 2: Migrate the ipa call sites (`ipa/mod.rs`)**

- `:1165` — `crate::bundle::is_nested_bundle_dir(store, &path)`.
- `calculate_bundle_depth` — add `store: &dyn Store` as its second parameter;
  its detector call passes `store`; its caller at `:1166` becomes
  `self.calculate_bundle_depth(store, &path, bundle_path)` (`&S` coerces).
- The `find_immediate_macho_binaries` prune closure — detector call becomes
  `crate::bundle::is_nested_bundle_dir(store, path)` (captures the in-scope
  `store: &S`).
- Fix any further call sites the compiler reports (including tests); do not
  change behavior anywhere else.

- [ ] **Step 3: Migrate the native verify call sites (`verify.rs`)**

Add `use crate::store::FsStore;` to the use block (alphabetized with the
existing `crate::` import). Call sites: `has_nested_bundle_component`
(`:155`) → `crate::bundle::is_nested_bundle_dir(&FsStore, &prefix)`; the walk
(`:449`) → `crate::bundle::is_nested_bundle_dir(&FsStore, p)`. Rewrite the two
public intra-doc links (`verify.rs:14` module doc, `verify.rs:83` field doc)
from ``[`crate::bundle::is_nested_bundle_dir`]`` to the plain code span
`` `crate::bundle::is_nested_bundle_dir` ``. No other change in this file.

- [ ] **Step 4: Restructure the walk and align polarity (`mem_store.rs`)**

`walk_inner`: scope the lock to the root lookup — lock, read the root kind
(or push `Err(not_found(root))` and return), let the guard drop, push the
root entry if `include_root`, then call `self.walk_children(&key, prune,
&mut out)`.

`walk_children`: becomes a `&self` method — per level, `{ let nodes =
self.lock(); Self::children(&nodes, dir) }` materializes the owned children
and the guard drops at the block's end; only then iterate: skip when
`!prune(&path, kind)` (false = skip), push, recurse via
`self.walk_children(&path, prune, out)`. No closure invocation, no
recursion, no `out` mutation happens while any guard is alive.

Docs and tests in the same file:
- `walk_inner` doc: "`prune` returning `true` skips" → "`prune` returning
  `false` skips the whole subtree — never yielded, never descended into."
- struct doc (`:68-70`): replace the "no guard is ever returned or nested, so
  no deadlock is possible" sentence with the true invariant — walks
  materialize each level's children under the guard and release it before
  running any caller closure, so no callback executes while the lock is held;
  keep the uncontended-cost and rayon rationale.
- Invert the two existing predicates (asserted outputs unchanged):
  `p.ends_with("secret")` → `!p.ends_with("secret")`;
  `kind == StoreKind::File` → `kind == StoreKind::Dir`.

- [ ] **Step 5: Green the deadlock test and the whole crate**

Run: `TMPDIR=$PWD/target/tmp cargo test -p zsign-rs mem_store` — all pass
(Task 1's test now returns promptly with `n > 0`; both polarity tests keep
their exact asserted vectors).
Run: `TMPDIR=$PWD/target/tmp cargo test -p zsign-rs` — full crate green
(false-rejection and signer-flow check; fix any compiler-reported callers
already handled in Steps 1-3).

---

### Task 3: Native/mem parity regression test

**Files:**
- Modify: `crates/zsign/src/ipa/mem_store.rs` (tests module)

**Interfaces:**
- Consumes: Task 2's detector signature, `FsStore`, `MemStore`, `walk_pruned`
  (false=skip on both stores).
- Produces: `mem_and_native_walk_pruned_match_for_extension_less_nested_bundle`
  pinning the cross-store contract.

- [ ] **Step 1: Write the parity test**

In the tests module add `use crate::bundle::is_nested_bundle_dir;` and
`use crate::store::{FsStore, Store};` (matching the file's import style; the
native side stays fully-qualified `tempfile::TempDir`).

Same logical tree both sides: `Frameworks/Legacy/` (extension-less) holding
`Info.plist` with non-empty `CFBundleIdentifier` + `CFBundleExecutable`, plus
`Frameworks/Legacy/inner.bin` and `top.bin` at the root. Native tree in a
`tempfile::TempDir`; mem tree via `create_dir_all`/`write` with the same
root-relative keys. Assertions, in order:
1. `is_nested_bundle_dir(&FsStore, native) == true` and
   `is_nested_bundle_dir(&mem, rel) == true` (detection parity).
2. `find_immediate`-shaped predicate per side — the `FsStore` side compares
   paths against `native_root` and consults `&FsStore`; the `MemStore` side
   compares against `Path::new("")` (the mem walk root) and consults `&mem`.
   For each entry, skip iff `path != <that side's root>` && `kind == Dir` &&
   that side's detector says nested (predicate returns false = skip).
3. Run `FsStore.walk_pruned(native_root, …)` and `mem.walk_pruned("", …)`;
   map native paths by `strip_prefix(native_root)` to `/`-separated strings,
   map mem paths via `to_string_lossy().replace('\\', "/")`; **sort both**;
   `assert_eq!` — expected membership on both sides:
   `["Frameworks", "top.bin"]` (the nested subtree neither yielded nor
   descended), with the actual vectors in the assertion footer.

- [ ] **Step 2: Run it**

Run: `TMPDIR=$PWD/target/tmp cargo test -p zsign-rs mem_and_native_walk_pruned_match`
Expected: PASS (it uses the post-Task-2 API; its pre-fix RED was
compile-gated by the signature change itself, as recorded in the spec).
Re-run `TMPDIR=$PWD/target/tmp cargo test -p zsign-rs mem_store` — all green.

---

### Task 4: Zero-warning gate

**Files:** none modified; verification only.

- [ ] **Step 1: Formatting**

Run: `cargo fmt --all -- --check`
Expected: no output, exit 0. If new code is unformatted, run `cargo fmt --all`
(reformats only this change — the tree was clean at base) and re-check.

- [ ] **Step 2: Clippy**

Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: no warnings, exit 0.

- [ ] **Step 3: Doc-link check**

Run: `cargo doc --no-deps -p zsign-rs 2>&1` inspected for warnings
Expected: no `private_intra_doc_links` / broken-link warnings (the two
reworded spans in `verify.rs` are the reason this is in the gate).

- [ ] **Step 4: Workspace tests**

Run: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test --workspace`
Expected: all PASS.

---

## Self-review

- Spec coverage: gap 1 → Task 2 Steps 1-3 (+3); gap 2 → Task 2 Step 4 (+1
  test); gap 3 → Task 2 Step 4 polarity + Task 3 parity; doc-claim updates →
  Task 2 Steps 3-4; acceptance → Tasks 1-4 verification steps.
- Step scan: each step is one compile-or-behavior checkable action; code
  bodies appear only where the signature and assertions do not determine
  them (the walk restructure's guard block, the parity predicate).
- Type consistency: `store: &dyn Store` at detector/depth; `walk_children`
  gains `&self` and drops the `nodes` parameter in both definition and its
  single recursive call; `MaybePruneFn` unchanged.
- Review Focus: each line maps to a step — marker semantics (Task 2 Step 1's
  `.ok()?` + unchanged native behavior verified by Task 2 Step 5 full-crate
  run), timeout-not-wedge (Task 1 Step 1 harness), set-vs-sequence (Task 3
  Step 1 sort), polarity-test outputs unchanged (Task 2 Step 4 exact
  inversions + Task 2 Step 5 exact-vector assert), verify byte-identical
  (Task 2 Step 3 limited-touch rule).
- Proportion: plan is shorter than the spec; no step restates a body the
  assertions pin.
