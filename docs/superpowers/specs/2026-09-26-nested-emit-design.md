# Nested-Code Emission Design (ZSN-34)

**Date:** 2026-09-26
**Branch:** `zsn34-nested-emit`
**Scope:** Kaneo ZSN-34 — three ordered queue items: (1) stop emitting
entitlements for non-executables, (2) guarantee no code entity is signed
twice, (3) replace the extension-whitelist bundle detection.

All ticket line numbers were re-derived against current source (the ticket
dates 2026-09-24; main has since gained ~350 commits). Every file:line below
was verified in this worktree during the phase-2 research batch.

---

## 1. Problem

### 1.1 Item 1 — entitlements emitted for non-executables

`zsign_core::macho::sign_any_macho` (`crates/zsign-core/src/macho/signer.rs:175-179`)
coerces every non-`MH_EXECUTE` binary to `Some(EMPTY_ENTITLEMENTS)`. The
constant is defined at `signer.rs:131` and re-exported from
`crates/zsign-core/src/macho/mod.rs:20`. A second, independent injection site
exists in the WASM SHA-256-only path
(`crates/zsign-wasm/src/lib.rs:524-533`).

The underlying emission locus is `SigningContext::new`
(`signer.rs:67-128`): `entitlements_blob = entitlements.map(build_entitlements_blob)`
at `signer.rs:83` is **not** gated on executability, while the DER blob at
`signer.rs:85-94` is. Result: a dylib signed through `sign_any_macho` carries
an `<?xml … <dict/> …>` `CSMAGIC_ENTITLEMENTS` blob hashed into CodeDirectory
special slot −5, with no slot −7.

Two further callers pass caller-supplied entitlements through **uncoerced** on
thin (non-FAT) paths:

- `crates/zsign/src/ipa/mod.rs:1039` (`sign_macho_sha256_only`) and
  `:1060` (`sign_macho_adhoc`) — `sign_binary` forwards the root bundle's
  profile entitlements for every non-main binary of the main bundle.
- `crates/zsign/src/builder.rs:327` and `:345` (direct thin signing) — this
  file is owned by parallel lane zsn35 and MUST NOT be edited by this lane.

Injection sites are exactly two (workspace-wide grep): `signer.rs:178` and
`zsign-wasm/src/lib.rs:532`. One test pins the replication:
`non_executable_input_ignores_profile_entitlements`
(`crates/zsign-wasm/src/lib.rs:1011-1040`).

### 1.2 Item 2 — the same dylib is signed twice

`IpaSigner::sign_bundle` (`crates/zsign/src/ipa/mod.rs:368`) runs two passes
over the root bundle:

- **Pass A** (`ipa/mod.rs:384-387`): `find_standalone_dylibs` (`:600-625`)
  collects every `*.dylib` below the root (no nested-bundle exclusion) and
  `sign_standalone_dylib` (`:628`) signs each with `identifier = file_stem`,
  entitlements `None`, dual SHA-1+SHA-256 code directories
  (`sign_macho`/`sign_macho_adhoc` at `:652/:661`).
- **Pass B** (`ipa/mod.rs:389-403`): `collect_nested_bundles` + per-bundle
  `sign_single_bundle` (`:684`) → `find_immediate_macho_binaries` (`:752-789`).
  This walk prunes only nested-*bundle* directories (`filter_entry` at
  `:763-770` calls `is_bundle_directory`) and `_CodeSignature`; bare
  `Frameworks/*.dylib` files are **not** excluded, so they are re-signed at
  `:699-711` through `sign_binary` (`:970`) → `sign_any_macho` (`:1049`, dual
  mode) or `sign_macho_sha256_only` (`:1039`, default mode) or
  `sign_macho_adhoc` (`:1060`).

Pass B wins (the root bundle signs last, depth-sorted). Consequences today:

- default `sha256_only` mode replaces pass A's dual CD with a single
  SHA-256-only CD — the on-disk signature depends on pass order;
- with a profile loaded, pass B binds the root's full entitlements into
  slot −5 of a dylib on `sha256_only`/adhoc paths (no coercion there), or an
  empty-dict blob via `sign_any_macho`;
- without a profile the passes are near-idempotent, so a byte-compare cannot
  prove "signed once" — the observable is the **CD shape** (dual vs single).

There is no processed/visited set anywhere in the walk (grep
`HashSet<PathBuf>|processed|visited` in `ipa/mod.rs`: zero hits in walk
logic). Closest in-repo precedent for a path-claim registry:
`crates/zsign/src/ipa/extract.rs:350-351` (`HashSet<PathBuf>` during a
walk) and `crates/zsign-wasm/src/lib.rs:209` (`finalized_paths` guard).

### 1.3 Item 3 — nested-code recognition is a 3-extension whitelist

Five independent copies of the predicate exist (no shared helper):

| Site | Location | Predicate |
|---|---|---|
| Signer collect | `ipa/mod.rs:431-437` `is_bundle_directory` (call `:421`) | ext ∈ {app, framework, appex}, lowercased |
| Signer depth | `ipa/mod.rs:578-592` `calculate_bundle_depth` | `ends_with(".app"|".framework"|".appex")`, case-sensitive (asymmetric with the above) |
| Signer immediate-walk prune | `ipa/mod.rs:763-770` `filter_entry` (call `:765`) | calls `is_bundle_directory` |
| Verifier | `crates/zsign/src/verify.rs:143-152` `is_bundle_dir` (calls `:164`, `:456`) | duplicate 3-ext whitelist |
| Verifier component prune | `verify.rs:157-165` `has_nested_bundle_component` (calls `:456`, `:466`) | per-component `is_bundle_dir` |

`ensure_single_app_bundle` (`ipa/mod.rs:526-545`, `ext == "app"`) selects the
single **root** app in `Payload/` — that is root-bundle selection, not
nested-code detection, and is out of scope.

XPC services are missed entirely: a workspace grep for `xpc|XPCServices`
across `crates/` returns zero hits. A `Foo.xpc` directory today:

1. is not collected as a nested bundle — no own `_CodeSignature`, no
   own CodeResources;
2. is not pruned from the parent's immediate-binary walk — its Mach-O is
   signed as a loose helper binary of the parent with `identifier = file_stem`
   and the parent's entitlements (`:704-711`), i.e. signed without its
   bundle relationship.

The verifier mirrors the same whitelist (`verify.rs:143-152`), so any signer
predicate change MUST be co-changed there or sign→verify desyncs.
`zsign_core::bundle::CodeResourcesBuilder` has **no** bundle predicate at all
(`zsign-core/src/bundle/code_resources.rs:420-449`; nested-bundle files are
deliberately included in the parent's CodeResources, asserted by
`crates/zsign/src/bundle/code_resources.rs:407-437`) — no change needed there.

---

## 2. External contract verification (phase-2 librarian findings)

Claims verified against Apple docs, Apple open-source, upstream
`zhlynn/zsign` (clone HEAD `614caa8`), and `ldid` (`af86971`):

1. **"Nested code must carry no entitlements or AMFI rejects it" — strong form
   REFUTED.** No Apple document or source states this. App extensions and XPC
   services are nested code and *do* carry entitlements (Apple entitlements
   docs: granted "to an executable"). The defensible, narrower rule: Apple's
   toolchain emits no entitlements slot for dylibs/framework binaries when
   none are supplied, and an *absent* special slot is explicitly normal —
   Security `codedirectory.h`: "Special slots that are in range but not
   present are zeroed out. Unallocated special slots are also presumed
   absent; this is not an error." `SecCodeSigner::populate()` emits slot −5
   iff entitlement data was supplied (signer.cpp:306-313, no file-type
   gate). In the wild, the empty-dict plist is treated as a *workaround*
   (apple-platform-rs#108; rcodesign stopped inheriting entitlements into
   nested binaries by default). The only "AMFI rejects" source is this repo's
   own comment (`ipa/mod.rs:1012-1021`) and it could not be traced to any
   public Apple source — flagged as unsourced lore. **Design consequence:**
   the rationale for item 1 is the codesign baseline (absent slot, no
   meaningful entitlements on non-executables), not a sourced AMFI claim; the
   doc comments that assert the old mechanism are rewritten accordingly.
2. **Slot map CONFIRMED** (xnu `cs_blobs.h:115-139`, Security
   `codedirectory.h:92-104`): SuperBlob index 5 = entitlements XML (CD slot
   −5), 7 = DER entitlements (−7), `0x1000` = alternate code directories.
3. **Nested-code locations are defined by LOCATION, not extension —
   CONFIRMED** (Apple "Placing content in a bundle"; TN2206 "Nested Code"
   Table 3): `Frameworks/` (iOS), `Contents/Frameworks/` (macOS),
   `PlugIns/`, `Contents/XPCServices/` (macOS row), `Watch/`, `AppClips/`,
   `Contents/Library/…`, plus Apple's own codesign nested rule
   (`bundlediskrep.cpp`): `^(Frameworks|SharedFrameworks|PlugIns|Plug-ins|XPCServices|Helpers|MacOS|Library/(…))`. `Extensions/` appears in NO
   Apple list — only in upstream zsign's comments (`bundle.cpp:296-309`);
   treat as a compatibility location.
4. **CFBundlePackageType — values CONFIRMED, "membership" predicate REFUTED
   as sound on its own:** `APPL`, `FMWK`, `BNDL` (Bundle Programming Guide;
   `BNDL` is also CFBundle's *fallback* default, so it cannot identify
   nested code), `XPC!` documented only for XPC services ("Creating XPC
   Services", `xpcservice.plist(5)`). App extensions are identified by
   location + `.appex` + `NSExtension`, never by package type. Upstream
   zsign's real gate is `CFBundleIdentifier` + `CFBundleExecutable`
   (`bundle.cpp:44-58`). **Design consequence:** package type is one OR-arm
   among several, never the sole signal; bundle markers
   (`CFBundleIdentifier` + `CFBundleExecutable` in the child Info.plist) gate
   the new arms.
5. **iOS has no documented XPC location** (placement table lists XPC
   services for macOS only; iOS uses `PlugIns/*.appex`). Upstream zsign
   neither detects `.xpc` nor seals XPC bundles — its loose-Mach-O walk would
   sign `Foo.xpc/Contents/MacOS/Foo` as a bare file.
6. **Upstream parity points:** upstream injects the empty-dict XML for
   non-executables (`archo.cpp:336-343`, `IsExecute()` at `:226-232`) — the
   port's `EMPTY_ENTITLEMENTS` was faithful parity; this lane **deliberately
   diverges** (see decision D1). Upstream's whitelist is four extensions
   (`.app`, `.appex`, `.framework`, `.xctest`, `bundle.cpp:90-98`) with the
   markers requirement; upstream signs each loose Mach-O exactly once
   (`bundle.cpp:118-148` single pass + `:336-474` bundle executables).
7. **ldid neither strips nor refuses entitlements by filetype**
   (`ldid.cpp:2555-2560`, `:860-868`); it reserves slot −5 whenever
   non-empty entitlements are passed. Not a counter-authority.

---

## 3. Design

### 3.1 Item 1 — coerce entitlements to `None` for non-executables at the core chokepoint

**Chosen design.** In `zsign_core::macho::signer.rs` `SigningContext::new`
(`:67-128`), immediately before blob construction:

```rust
// Non-executables (dylibs, frameworks) carry no entitlements: an absent
// entitlements slot is the codesign baseline, and special slots that are
// not allocated are presumed absent rather than being an error.
let entitlements = if is_executable { entitlements } else { None };
```

`SigningContext::new` already receives `is_executable` (callers pass
`slice.is_executable`; the DER gate at `:85-94` uses it) and is the single
point through which every signing entry (`sign_macho`, `sign_macho_adhoc`,
`sign_macho_sha256_only`, and `sign_macho_all_slices` via `sign_any_macho`)
constructs its blobs. Effects:

- `sign_any_macho`'s `if is_executable { … } else { Some(EMPTY_ENTITLEMENTS) }`
  (`:175-179`) becomes dead and is **deleted** — the function forwards
  `entitlements` unchanged; its now-unused `is_executable` local and the
  auto-selection doc lines are updated.
- `EMPTY_ENTITLEMENTS` (`signer.rs:131`) and its re-export
  (`macho/mod.rs:20`) are **deleted**; every reference is migrated.
- The WASM thin-path replication (`zsign-wasm/src/lib.rs:524-533`) becomes
  redundant and is **deleted** — it will forward `effective_entitlements()`
  and core coerces. This also closes the gap where `sign_macho_fat`
  (`lib.rs:577-584`) passed entitlements with no local guard: all WASM paths
  now inherit one policy.
- The uncoerced thin paths at `ipa/mod.rs:1039/:1060` and
  `builder.rs:327/:345` are fixed **without editing those files** — the
  coercion is downstream of them. Lane zsn35's `builder.rs` stays untouched;
  future lanes ZSN-10/12/22 (entitlements override, per-extension
  profiles/ents, entitlements-dir) keep a clean seam: callers still pass
  entitlements normally, and executability gating happens once in core.
- The DER gate at `:85-94` stays (harmless belt-and-suspenders once the
  input is already `None`; it still documents intent). Per-slice gating also
  improves the FAT case: a hypothetical mixed-type FAT no longer inherits
  slice 0's executability (the old site checked `slices().first()` only).

**Doc/comment migration:** `sign_any_macho` doc (`signer.rs:156-160`),
wrapper doc (`crates/zsign/src/macho/mod.rs:151-152`), the constant's
doc-comment (deleted with the constant), and the WASM pin-test comment
(`zsign-wasm/src/lib.rs:1006-1009`, which names `EMPTY_ENTITLEMENTS`).
Wording follows finding 2.1: no sourced AMFI claim.

**Alternatives considered.**

- *A2 — delete only the two injection sites, keep the constant for callers
  that want "empty dict".* Rejected: keeps the misleading concept alive,
  leaves the uncoerced thin paths leaking real entitlements onto
  non-executables, and forces every entry to remember the rule (a second
  convention).
- *A3 — push the decision to each caller (`ipa`, `builder`, `wasm`) instead
  of core.* Rejected: violates single-convention, requires editing
  `builder.rs` (lane zsn35, zero-overlap hard rule), and re-spreads the very
  policy this ticket is centralizing.
- *A4 — make non-executables with supplied entitlements a hard error.*
  Rejected: contradicts the established repo contract — the WASM pin test
  asserts profile entitlements are *ignored* (not rejected) for
  non-executables, and `ipa`/`builder` pass entitlements unconditionally.

### 3.2 Item 2 — processed-path set threaded through the discovery/signing walk

**Chosen design.**

1. `sign_bundle` (`ipa/mod.rs:368`) materializes the pass-A list as
   `let already_signed: HashSet<PathBuf> = dylibs.iter().cloned().collect();`
   after the standalone loop completes (the fail-fast `try_for_each` has
   returned, so the set is complete before any bundle is signed).
2. `sign_single_bundle` gains one parameter, `already_signed: &HashSet<PathBuf>`
   (its only production caller is the `sign_bundle` loop at `:393-403`).
3. `find_immediate_macho_binaries` gains the same parameter and skips walk
   results contained in the set. The bundle's main executable is pushed
   *before* the walk and is never filtered, so the main-executable contract
   (own CodeResources, bundle identifier, entitlements) is untouched; the
   filter applies only to walk results.

Why here and not elsewhere:

- The set is built exactly where the pass-A authority is established — the
  standalone pass remains the sole signer of `*.dylib` files with its policy
  (`identifier = file_stem`, no entitlements, dual CD), which is the policy
  item 2 asks to preserve.
- Discovery-level filtering is unit-testable in the same style as the
  existing `test_symlinked_dylib_is_skipped_and_target_untouched`
  (`ipa/mod.rs:1671-1708`), which already calls both discovery functions
  directly.
- Paths from `find_standalone_dylibs` and `find_immediate_macho_binaries`
  share lexical shape (both are `WalkDir` from the same bundle root,
  symlinks excluded by `file_type().is_file()` on both sides), so plain
  `PathBuf` equality is sound — the same assumption `sign_single_bundle`
  already makes for `path != main_executable`.

**Alternatives considered.**

- *B2 — exclude `ext == "dylib"` from `find_immediate_macho_binaries`.*
  Rejected: duplicates the discovery predicate in two functions (drift
  risk), i.e. a second convention; and it silently couples two walks that
  can evolve independently.
- *B3 — delete pass A entirely and adopt upstream's single loose-Mach-O
  pass (magic-sniffed walk).* Rejected: much larger blast radius (changes
  discovery for every non-`.dylib` Mach-O, error behavior, and identifier
  assignment across the walk) — a rewrite of the discovery model beyond the
  ticket's "introduce a processed-path set" instruction.
- *B4 — set filter inside `sign_single_bundle` instead of discovery.*
  Equivalent behavior; rejected only because filtering inside
  `find_immediate_macho_binaries` keeps `sign_single_bundle`'s body
  unchanged and makes the contract testable at the discovery seam.

**Accepted edge (recorded, not fixed):** a bundle whose *main executable*
is literally named `*.dylib` is written by pass A and then re-signed as the
main executable by pass B. The main-executable contract must win (it binds
CodeResources and bundle identifier), no iOS bundle names its main
executable `*.dylib`, and filtering it out of pass B would be a regression.
Standalone dylibs *inside* nested bundles are covered — the set is global to
the whole walk.

### 3.3 Item 3 — one shared nested-code predicate: markers + location + package type

**Chosen design.** A single function in `crates/zsign/src/bundle/mod.rs`
(the bundle-identity module; it already owns `CodeResourcesBuilder`, and
both `ipa` and `verify` can depend on it without cycles):

```rust
/// Child directories of Apple's documented nested-code locations
/// ("Placing content in a bundle", TN2206 Table 3). `Extensions` is not
/// Apple-documented; it is kept for compatibility with upstream zsign,
/// which treats it as an app-extension location (bundle.cpp:296-309).
const NESTED_CODE_LOCATIONS: [&str; 7] = [
    "Frameworks", "SharedFrameworks", "PlugIns", "XPCServices",
    "Watch", "AppClips", "Extensions",
];

/// CFBundlePackageType values that identify a bundle container
/// (Bundle Programming Guide: APPL/FMWK; "Creating XPC Services": XPC!).
/// BNDL is deliberately excluded — it is CFBundle's fallback default.
const BUNDLE_PACKAGE_TYPES: [&str; 3] = ["APPL", "FMWK", "XPC!"];

/// True when `path` is a nested-code bundle directory.
pub fn is_nested_bundle_dir(path: &Path) -> bool { /* order below */ }
```

Predicate, in order:

1. **Legacy extension arm (unchanged behavior):** lowercased extension ∈
   `{app, framework, appex}` → `true`. No Info.plist requirement — exactly
   today's semantics, including this port's deliberate tolerance for
   bundles whose Info.plist lacks `CFBundleExecutable`
   (`test_sign_tolerates_missing_executable_key`, `ipa/mod.rs:1641-1670`,
   relies on the file-stem fallback downstream).
2. **Bundle markers gate for everything else:** read `path/Info.plist` with
   the repo's standard idiom (`fs::read` + `plist::from_bytes` +
   `as_dictionary().get(…).as_string()`, the `get_bundle_identifier`
   pattern at `ipa/mod.rs:839-857`; best-effort: unreadable/unparseable →
   `false`). Both `CFBundleIdentifier` and `CFBundleExecutable` must be
   non-empty — upstream parity (`bundle.cpp:44-58`). Missing → `false` (a
   plain directory under a code location is not code).
3. **Location arm:** direct parent directory name (case-insensitive) ∈
   `NESTED_CODE_LOCATIONS` → `true`.
4. **Package-type arm:** `CFBundlePackageType` ∈ `BUNDLE_PACKAGE_TYPES` →
   `true` (catches renamed containers regardless of location).

A `Foo.xpc` under `App.app/XPCServices/` is therefore discovered by arm 1
miss → markers ✓ → location ✓ (and independently by arm 4 via `XPC!`);
`.xpc` is *not* in the extension whitelist, which the acceptance test uses
to prove the whitelist is no longer the sole predicate.

**Callers migrated (all predicate copies):**

| Site | Change |
|---|---|
| `ipa/mod.rs:431-437` `is_bundle_directory` | deleted; both callers (`:421`, `:765`) call `crate::bundle::is_nested_bundle_dir` |
| `ipa/mod.rs:578-592` `calculate_bundle_depth` | rewritten to cumulative-prefix evaluation: iterate `strip_prefix(root)` components, accumulate `root.join(prefix…)`, count prefixes satisfying the predicate (also fixes the existing case-sensitivity asymmetry with collect) |
| `verify.rs:143-152` `is_bundle_dir` | deleted; `:456` calls the shared predicate with the full path |
| `verify.rs:157-165` `has_nested_bundle_component` | gains `root: &Path`; evaluates the predicate on cumulative `root.join(prefix)` components (both call sites `:456`, `:466` sit inside `verify_bundle_dir(root, dir, rel)`, which has `root`) |
| docs | doc comments naming the old whitelist (`ipa/mod.rs:13-22`, `:406`, `verify.rs:12-14`, `:82`) updated to the new recognition rule |

`ensure_single_app_bundle` (root `Payload/*.app` selection,
`ipa/mod.rs:526-545`) is unchanged — a different concern.
`examples/web/src/main.js:783` keeps its own JS `BUNDLE_DIR` regex; it is a
standalone JS demo that cannot share Rust code and is not a caller
(decision D8).

**Fixture layout.** `App.app/XPCServices/Foo.xpc/{Info.plist, Foo}` — the
iOS-flat bundle layout this repo's whole bundle machinery supports
(`get_bundle_identifier` reads `bundle/Info.plist` directly,
`get_main_executable` resolves `CFBundleExecutable` relative to the bundle
root). The macOS `Foo.xpc/Contents/{Info.plist,MacOS/Foo}` layout requires
Contents-aware bundle resolution that the repo does not support anywhere
today (apps, frameworks and appexes are all read flat) — extending that is a
separate feature, not this ticket (decision D7). The location arm itself is
layout-agnostic (it matches on the parent name), so macOS-shaped paths start
working the moment bundle resolution does.

**Alternatives considered.**

- *C1 — extension whitelist + add `.xpc`/`.bundle`/`.xctest` names.*
  Rejected: still a pure name whitelist; the ticket requires detection via
  the child Info.plist's CFBundlePackageType and documented locations, not
  filename extensions alone.
- *C2 — CFBundlePackageType-only predicate.* Rejected by evidence: `BNDL`
  is a fallback default, app extensions have no documented package type,
  iOS frameworks may lack or wrongly set it — membership is neither
  necessary nor sufficient, and Apple's own codesign does not use it this
  way.
- *C3 — location-only predicate (no extension arm).* Rejected: would stop
  recognizing non-location legacy layouts the signer handles today (e.g. a
  `.framework` directly under the bundle root) — a silent regression; the
  ticket says extensions must not be the *sole* predicate, not that they
  must go.
- *C4 — hard-error/reject unrecognized XPC-shaped bundles.* Rejected: see
  decision D5 — rejection would fail legitimate bundles, and the acceptance
  criteria prefer discovery with the bundle relationship intact.

---

## 4. Design decisions

- **D1 — Deliberate divergence from upstream zsign on empty entitlements.**
  Upstream (`archo.cpp:336-343`) injects an empty-dict XML entitlements blob
  for every non-executable; this port will emit *no* entitlements slot
  instead. Rationale: an absent special slot is the codesign baseline
  ("presumed absent; this is not an error", Security `codedirectory.h`), the
  empty dict buys nothing (it can never be meaningful for
  non-executables), and it made the two signing passes produce different
  bytes. The old doc comments that presented the injection as required
  behavior are rewritten; the unsourced AMFI-rejection claim is not
  repeated.
- **D2 — Coercion lives in core `SigningContext::new`, not at call sites.**
  One policy point covers core entries, the WASM surface, `ipa`'s
  sha256-only/adhoc branches, and `builder.rs`'s thin paths without editing
  `builder.rs` (lane zsn35). See §3.1 alternatives A3/A4.
- **D3 — Processed-path set, filtered inside discovery.** Pass A owns
  `*.dylib` signing; pass B skips those paths; the main executable is never
  filtered. See §3.2.
- **D4 — Extension arm retained, unconditional (no Info.plist requirement
  for `*.app`/`*.framework`/`*.appex`).** Preserves today's behavior exactly
  for existing layouts and the repo's documented tolerance for missing
  `CFBundleExecutable` (file-stem fallback, `ipa/mod.rs:886-895`). New arms
  (location, package type) require bundle markers because a name-free
  directory under `Frameworks/` etc. has no other evidence of being code —
  upstream zsign applies the markers requirement to *its* four extensions,
  but changing the legacy arm's requirements would alter existing error
  behavior beyond this ticket's scope.
- **D5 — XPC services are SIGNED as nested bundles, not rejected.**
  Rejection would make any bundle containing an XPC service fail to sign,
  even though XPC services are ordinary nested code with their own
  `_CodeSignature` and seal (Apple "Creating XPC Services"). Signing with
  the bundle relationship intact matches the ticket's primary acceptance
  path. Policy: an XPC service binary is the bundle's main executable —
  signed with its **bundle identifier** from `CFBundleIdentifier`, its own
  Info.plist hash (slot −1) and CodeResources (slot −3), and **no
  entitlements** (nested-bundle policy: `sign_bundle` passes `None` to
  non-main bundles at `ipa/mod.rs:399-401`). macOS XPC services may carry
  their own minimal entitlements; emitting them is deferred to the
  per-extension entitlement lanes (ZSN-10/ZSN-12), which this design keeps
  seam-compatible (entitlements flow through the normal parameter).
- **D6 — `BNDL` excluded from `BUNDLE_PACKAGE_TYPES`** because it is
  CFBundle's fallback default value; including it would classify every
  marker-complete directory as nested code. `XPC!`/`APPL`/`FMWK` are
  documented, non-fallback values.
- **D7 — macOS `Contents/`-style bundle layouts stay unsupported.** All
  bundle reads in this repo (`get_bundle_identifier` `ipa/mod.rs:828-859`,
  `get_main_executable` `:869-931`) assume flat `bundle/Info.plist`. The
  XPC fixture uses the iOS-flat shape. Making the whole bundle machinery
  Contents-aware is a separate feature.
- **D8 — `examples/web/src/main.js` is out of scope.** Its `BUNDLE_DIR`
  regex is an independent JS reimplementation inside a demo app, not a
  caller of this codebase; it cannot share the Rust predicate. Touching the
  demo is not required by the ticket's file list and would expand scope.
- **D9 — `ensure_single_app_bundle` keeps its `.app`-only check.** It
  validates `Payload/` root selection (exactly one root `.app`), which is
  not nested-code recognition.

## 5. Invariants

1. A signed non-executable (dylib/framework binary/XPC binary as non-main)
   never has a `0x0005` SuperBlob child, never binds CodeDirectory slot −5,
   and `verify_macho` accepts it (absent slot is not an error).
2. Executables are unaffected: provided entitlements still bind −5 and −7
   exactly as before; `builder.rs`/`ipa` option forwarding behavior for
   executables is byte-identical.
3. Every file below a bundle root is written by the signing walk at most
   once per pass structure: `*.dylib` files exactly once (pass A), bundle
   main executables exactly once (their bundle's pass), other immediate
   Mach-Os exactly once (their bundle's pass).
4. Standalone-dylib policy survives: `identifier = file_stem`, no
   entitlements, dual SHA-1+SHA-256 code directories (the pass-A output is
   the on-disk output).
5. Signer and verifier recognize the same nested-code set: for every
   directory `d`, `collect_nested_bundles` includes `d` iff
   `verify_bundle_dir` recurses into `d`.
6. Depth ordering still signs deepest bundles first;
   `calculate_bundle_depth` counts exactly the components
   `is_nested_bundle_dir` recognizes.
7. Bundle identity for nested bundles: a nested bundle's main executable is
   signed with the bundle's `CFBundleIdentifier` (not the file stem) and
   its own Info.plist/CodeResources hashes.
8. No code comments or identifiers mention ticket IDs; no stubs, no
   placeholder code; obsolete code (`EMPTY_ENTITLEMENTS`, duplicated
   predicates) is deleted, not left behind.

## 6. Test strategy

Conventions for every task: `TMPDIR=$PWD/.tmptmp` and always append
`-- --skip test_ipa_signing_is_deterministic`; scoped `cargo test -p <crate>
<filter>` gates only (project-wide gates run once, at final report).
Red → green per task: the Tester subagent writes the failing test first.

**Item 1 (zsign-core).** New inline test
`test_non_executable_signing_carries_no_entitlements` in
`crates/zsign-core/src/macho/signer.rs` tests: sign `make_minimal_dylib()`
(`fixtures.rs:102-105`) through `sign_macho`, `sign_macho_sha256_only`,
`sign_macho_adhoc`, and `sign_any_macho`, each with a non-empty entitlements
plist. For each output assert, via `parse_superblob` on the
`code_sig_offset/size` region: no entry with `slot == 0x0005` and none with
`0x0007` (no entitlements blob), `code_directory.special_slot_hash(5)` is
`None` or all-zero (slot −5 unbound), and `verify_macho` reports the binary
valid (existing verify path). Pre-fix: RED on every entry (empty or real
dict bound into −5). The strengthened WASM pin
(`non_executable_input_ignores_profile_entitlements`) additionally asserts
`entitlements_slot(&a) == None` instead of only `a == b`.

**Item 2 (zsign-rs/ipa).** New `test_util::minimal_dylib()` helper
(`crates/zsign/src/test_util.rs`, modeled on `minimal_macho_encrypted` at
`:14-27`: patch `filetype` at bytes `12..16` to `6`). New test
`test_standalone_dylib_signed_exactly_once`: build
`App.app/{Info.plist, App, Frameworks/libfoo.dylib}` via
`create_folder_bundle` (`ipa/mod.rs:1260`) + the dylib fixture, sign with
`IpaSigner::new(&test_credentials())` (default `sha256_only = true`), then
assert on `Frameworks/libfoo.dylib`:

1. `parse_superblob` → `code_directory.identifier() == Some("libfoo")`
   (pass-A identity stable);
2. the SuperBlob contains the `0x1000` alternate-code-directory entry
   (pass A's dual CD — pass B would have overwritten it with a single
   SHA-256-only CD: this is the red/green discriminator);
3. no `0x0005` entry (no bundle entitlements on the dylib);
4. discovery seam: `find_immediate_macho_binaries(&app, &set)` where `set`
   is built from `find_standalone_dylibs` excludes the dylib (mirrors the
   `:1671` precedent);
5. `verify_bundle(&app)` → `report.valid()` (ipa sign→verify path).

Pre-fix RED comes from assertion 2 (single CD) — assertions 4's parameter
does not exist pre-fix, so the task sequence is: red e2e test first
(assertions 1-3,5 with old API), implement threading, then add assertion 4.
The existing `test_symlinked_dylib_is_skipped_and_target_untouched` is
migrated to the new `find_immediate_macho_binaries` signature.

**Item 3 (zsign-rs/ipa + verify).** New test
`test_xpc_service_is_discovered_and_signed_as_nested_bundle`:

- fixture `App.app/XPCServices/Foo.xpc/{Info.plist, Foo}` where Info.plist
  carries `CFBundleIdentifier com.test.foo.xpc`, `CFBundleExecutable Foo`,
  `CFBundlePackageType XPC!`, and `Foo` is a minimal `MH_EXECUTE`;
- discovery: `collect_nested_bundles(&app)` contains the `.xpc` path with
  depth 1 — since `.xpc` ∉ {app, framework, appex}, this fails pre-fix and
  proves the whitelist is no longer the sole predicate;
- sign (adhoc), then assert `XPCServices/Foo.xpc/_CodeSignature/CodeResources`
  exists, the signed `Foo` has identifier `com.test.foo.xpc` (bundle
  relationship: bundle id, not file stem) and no entitlements slot;
- `verify_bundle(&app)` valid with exactly one nested entry whose `path`
  is `XPCServices/Foo.xpc` (verifier co-migration).

Plus focused unit tests for `is_nested_bundle_dir` in
`crates/zsign/src/bundle/mod.rs` (inline `#[cfg(test)]` module per repo
convention): extension arm still matches without Info.plist; location arm
requires markers (dir under `Frameworks/` without Info.plist → false);
package-type arm matches a renamed dir (`APPL`/`XPC!`); marker-less
location dir → false; `BNDL`-only → false.

**Regression sweeps (scoped, per task):** `cargo test -p zsign-core
non_executable -- --skip test_ipa_signing_is_deterministic`;
`cargo check -p zsign-wasm`; `cargo test -p zsign-rs signed_exactly_once …`,
`… xpc …`, `… nested_bundle …`, plus the migrated direct-discovery tests.
Final gates (report time only): `cargo fmt --all --check`,
`cargo clippy --workspace --all-targets -- -D warnings`,
`cargo test --workspace --no-fail-fast -- --skip test_ipa_signing_is_deterministic`.

## 7. Out of scope and seams for other lanes

- `crates/zsign/src/builder.rs`, `crates/zsign-cli/src/main.rs` — lane
  zsn35 (option forwarding); not edited. Core coercion downstream keeps
  their behavior correct for non-executables without their cooperation.
- ZSN-10 (entitlements override), ZSN-12 (per-extension profiles/ents),
  ZSN-22 (entitlements-dir) — future lanes; entitlements keep flowing
  through the existing `sign_bundle(entitlements)` /
  `SigningContext::new(entitlements, is_executable)` parameters, and the
  executability gate gives them a single, documented enforcement point.
- ZSN-13 (execSegFlags) — already done; untouched.
- Adhoc+FAT behavior — ZSN-33's recorded limitation; untouched.
- FAT standalone dylibs (`sign_standalone_dylib` uses thin-only entries and
  rejects containers) — pre-existing behavior, unchanged.
- `examples/web` JS demo (D8), macOS `Contents/` layouts (D7),
  `ensure_single_app_bundle` (D9) — unchanged.
