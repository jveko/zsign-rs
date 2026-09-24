# Signing Path Containment Design (ZSN-27)

**Date:** 2026-09-24
**Scope:** `crates/zsign/src/ipa/mod.rs` + its inline `#[cfg(test)] mod tests` only.
**Status:** decisions final; reviewed by cold review before implementation.

## Problem

Three containment gaps let a hostile IPA/bundle cause writes outside the
bundle root during signing:

1. **`CFBundleExecutable` traversal.** `get_main_executable`
   (`crates/zsign/src/ipa/mod.rs:700-733`) joins the raw plist value onto
   `bundle_path` (`:732`) with no sanitization. A value like
   `../outside_macho` or `/tmp/outside_macho` replaces/escapes the base;
   `sign_binary` later `fs::write`s the signed bytes there (`:810`, `:867`).
   This is the **only** written path not pinned by a literal `join` or by
   WalkDir enumeration (verified: every other `fs::write` at `:517`, `:556`,
   `:659`, `:897` receives a literal-derived path under the bundle).
2. **Symlink-following classification.** The three discovery walks classify
   with `Path::is_dir()`/`is_file()`, which follow the final symlink:
   `collect_nested_bundles` (`:404`), `find_standalone_dylibs` (`:458`),
   `find_immediate_macho_binaries` (`:603` filter_entry, `:612` body).
   walkdir 2.5.0 is used with its default `follow_links(false)` (no
   `.follow_links` call exists in the file), so symlinked directories are
   never *descended*, but the entry is still yielded and the predicate
   follows it: `Frameworks/Evil.framework` or `lib.dylib` pointing outside
   passes classification and its external target gets signed/overwritten.
3. **No write-site guard.** Nothing between "path value chosen" and
   `fs::write` verifies containment; a future caller or planted symlink
   writes straight through.

## Chosen design

### Item 1 — `get_main_executable` hardening

Rewrite the function's value handling (keeping its name, signature, and
callers `:538` / `:593` untouched):

1. `Info.plist` missing → **hard error** `Error::Core(zsign_core::Error::Signing("Info.plist not found in bundle: {}"))`
   (same shape as `get_bundle_identifier :668-691`). The old file-stem
   fallback for a missing plist is removed: per the brief the fallback may
   exist **only** for a missing `CFBundleExecutable` key. In the signing
   flow this branch was already unreachable (`get_bundle_identifier` fires
   first on the same condition), so no live behavior moves.
2. Parse failure → unchanged existing error.
3. Key present (string) → value used verbatim but validated:
   - `resolve_within(bundle_path, Path::new(&value))?` (item 3 helper)
     rejects `RootDir`/`ParentDir`/`Prefix` components and any pre-existing
     symlink component, and requires the path to sit under the root —
     absolute values fail `strip_prefix`, `..` fails the component check.
   - `fs::symlink_metadata` must report a **regular file**; otherwise a
     hard `Error::Core(Signing(...))` naming the offending
     `CFBundleExecutable` value and the bundle. This fires for missing
     files, directories, and (final or intermediate) symlinks.
4. Key absent / not a string → keep the file-stem fallback, still passed
   through `resolve_within`, with **no** existence requirement (callers'
   `.exists()` guards at `:575`/`:594` stay load-bearing only for this
   branch).

The returned path is `root.join(relative)` — the same lexical shape
WalkDir produces. It is **never canonicalized** (see Invariants).

### Item 2 — no-follow classification

Replace every `path.is_dir()` / `path.is_file()` predicate inside the
three discovery walks with walkdir's `entry.file_type()` (lstat-based,
no-follow):

- `collect_nested_bundles :404` → `entry.file_type().is_dir()`
- `find_standalone_dylibs :458` → `entry.file_type().is_file()`
- `find_immediate_macho_binaries :603` → `e.file_type().is_dir()`;
  `:612` → `entry.file_type().is_file()`

**Decision: skip, don't reject.** A symlink entry is not classified as a
file/directory, so it is never signed and never collected; no error is
raised. Rejected alternatives below. This is not a new convention — it is
exactly how `CodeResourcesBuilder` already classifies
(`crates/zsign/src/bundle/code_resources.rs:150-171`: explicit
`.follow_links(false)` + `entry.file_type()`, symlinks recorded as symlinks
via `hash_symlink_entry`), so discovery and CodeResources scanning now agree
on what a symlink *is*. Real in-tree targets remain discoverable as regular
files; versioned-framework symlinked *binaries* are signed once via their
real path instead of twice (through the link and directly — a pre-existing
double-sign hazard today).

### Item 3 — `resolve_within` guard for every write

One private free function in `mod.rs` (mirrors `validate_output_path` in
`crates/zsign/src/ipa/extract.rs:61-92`, adapted for this file's inputs).
It is introduced by item 1's change (which needs it) and wired to the
remaining write sites in this item:

```rust
/// Resolve `path` for writing, rejecting anything that escapes `root`.
///
/// `path` is either already prefixed by `root` (as produced by the
/// discovery walks) or relative to it (literal names, plist values).
/// The part below `root` must contain only normal components — no `..`,
/// no absolute prefix — and no existing component may be a symlink.
/// Returns the path re-joined onto `root`, keeping it lexically identical
/// to what WalkDir produces.
fn resolve_within(root: &Path, path: &Path) -> Result<PathBuf>
```

Mechanism (repo idiom, not canonicalize — the workspace uses no
`canonicalize` anywhere):

1. `path.strip_prefix(root)` → `relative`; on failure, a path that is
   relative-and-not-`..` is taken as root-relative and joined; an absolute
   path that is not under `root` errors `"Path {} is not under root {}"`
   (verbatim `extract.rs:62-71` idiom).
2. Reject `Component::ParentDir | RootDir | Prefix(_)` in `relative` with
   `"Path {} escapes the bundle root {}"`.
3. Downward walk: push each component onto a `current` buffer starting at
   `root`; if `fs::symlink_metadata(&current)` says symlink →
   `"Pre-existing symlink in signing path: {}"` (cf. `extract.rs:79-86`);
   first `NotFound` stops the walk (fresh tail is safe).
4. Return `root.join(relative)` — lexical, never canonicalized.

All errors are `Error::Core(zsign_core::Error::Signing(format!(...)))`,
the established idiom of this file for signing-flow complaints.

Wiring — the guard runs at function entry of every function that writes,
so each `fs::write` is preceded by exactly one validation:

| Site | Root | Input |
|---|---|---|
| `rewrite_plist_string` `:659` (+ its read) | `bundle_path` | literal `"Info.plist"` at entry |
| `sign_standalone_dylib` `:517` (+ its open) | **new `root` param** from `sign_bundle :370` | `dylib_path` at entry |
| `sign_single_bundle` profile `:556` | `bundle_path` | literal `"embedded.mobileprovision"` |
| `generate_code_resources` mkdir `:894` / write `:897` | `bundle_path` | literals `"_CodeSignature"` and `"_CodeSignature/CodeResources"` |
| `sign_binary` `:810`, `:867` (+ its open, and the `parent()`-derived Info.plist read `:821`) | **new `root` param** from `sign_single_bundle :550`/`:576` | `binary_path` at entry |

The validated value shadows the parameter, so every downstream use
(open, read, write, `parent()`) operates on the contained path.

## Invariants (verified against source; must survive the change)

1. **Lexical path equality.** Three `PathBuf` equality checks partition
   work: root identity in `sign_bundle :377` (chooses profile/entitlements
   pass-through), main-exec dedup in `find_immediate_macho_binaries :620`,
   and dedup in `sign_single_bundle :543`. `resolve_within` therefore
   returns `root.join(relative)` and **never** a canonicalized/normalized
   path; `get_main_executable` likewise returns the lexical join.
2. **Signing order.** Non-main binaries (`:545-551`) → profile (`:553-564`)
   → `generate_code_resources` (`:566`) → main executable signed with the
   hash of those bytes (`:575-583`). The fix must not restructure this
   flow, not move `get_main_executable`'s call sites, and not remove the
   `.exists()` guards at `:575`/`:594` (still needed for the key-absent
   fallback).
3. **Deepest-first bundle ordering** by depth (`:374`) and the
   `(bundle_path, 0)` root entry (`:395`) are untouched.
4. **Parallelism.** Discovery results are consumed by `par_iter`
   (`:368-370`, `:545`); validation is per-path and stateless, safe inside
   or before the parallel closures. No shared mutable state introduced.
5. **Error surfacing.** `is_macho_binary` keeps swallowing open failures
   into `Ok(false)` (resource files depend on it); the new hard errors come
   only from `get_main_executable` and `resolve_within`.
6. **Scope.** Only `crates/zsign/src/ipa/mod.rs` changes. `extract.rs`,
   `archive.rs`, `builder.rs`, `verify.rs`, `.github/**`, nested
   profile/entitlement semantics are other lanes' (see brief DEFERRED).

## Test strategy

All tests are inline in `mod.rs`'s `mod tests` (repo convention), fixtures
built inline exactly like `test_ipa_signer_refuses_encrypted_bundle`
(`:1068-1105`): `create_dir_all`, `fs::write` Info.plist XML,
`fs::write` executable from `crate::test_util::minimal_macho()`. Symlink
tests are `#[cfg(unix)]` + `std::os::unix::fs::symlink` (precedent:
`ipa/extract.rs:470`, `ipa/archive.rs:426`,
`bundle/code_resources.rs:441`). Each test fails before its fix and
asserts the external target's bytes are byte-identical afterwards.

1. `test_sign_rejects_executable_path_outside_bundle` — `CFBundleExecutable`
   = `"../outside_macho"` (real Mach-O written beside the `.app` in the
   tempdir). `sign_folder_in_place` must `Err` with a message naming the
   escaping path; outside bytes unchanged. Covers item 1.
2. `test_sign_rejects_absolute_executable_path` — same with the absolute
   path of the outside Mach-O as the value; error contains
   `"is not under root"`; outside bytes unchanged. Covers item 1.
3. `test_symlinked_dylib_is_skipped_and_target_untouched` — bundle with
   real executable plus `lib.dylib` → `../outside.dylib` symlink.
   `find_standalone_dylibs` and `find_immediate_macho_binaries` (private,
   called directly from the inline tests) must not list it; a full
   `sign_folder_in_place` succeeds and `outside.dylib` bytes are
   unchanged. Covers item 2 (both walks that can see a file at bundle root).
4. `test_symlinked_framework_is_not_collected_and_target_untouched` —
   `Evil.framework` symlink → external dir containing `Info.plist` +
   executable; `collect_nested_bundles` must not list it; full sign
   succeeds; external executable bytes unchanged and no external
   `_CodeSignature` appears. Covers item 2.
5. `test_sign_rejects_symlinked_info_plist_rewrite` — `Info.plist` is a
   symlink to a valid external plist; `.bundle_id("com.x")` triggers
   `rewrite_plist_string` first; sign must `Err` and the external plist
   bytes must be unchanged. This is the failing-first test for the
   `resolve_within` write guard (items 3); without the guard the rewrite
   writes through the symlink and the bytes change.

Existing `ipa::tests` (4 non-skipped) plus the cross-crate signer tests
(`builder::tests :562`, `verify::tests :536/:572/:583/:596`, CLI
`:500`/`:519`) must stay green — all their fixtures ship a real
`CFBundleExecutable` file, verified by scout, so the hard-error change
breaks none of them. Gate command (scoped, never project-wide mid-flight):
`cargo test -p zsign-rs ipa::tests -- --skip test_ipa_signing_is_deterministic`
(the skipped test is itself inside `ipa::tests` — known pre-existing
failure, ZSN-15).

## Design decisions (brainstorm record)

**Item 1**
- *Chosen:* component rejection + `resolve_within` + `symlink_metadata`
  regular-file requirement; hard errors with the offending value in the
  message.
- *Rejected — canonicalize-only:* no component pre-check gives poor
  messages ("No such file" instead of naming the bad value) and cannot
  validate nonexistent targets; also inconsistent with the workspace,
  which contains no `canonicalize`-based containment at all.
- *Rejected — coerce to `file_name()`:* silently rewrites malformed input
  to a plausible name; guesses intent, hides the attack (violates the
  validate-don't-guess rule).
- *Rejected — tolerate missing executable (keep `.exists()` skip):* a
  bundle whose declared executable does not exist gets a valid-looking
  artifact with an unsigned main executable; fail-fast with an actionable
  message is the brief's explicit requirement.

**Item 2**
- *Chosen:* `entry.file_type()` no-follow predicates, symlinks silently
  skipped — matches `CodeResourcesBuilder`'s existing classification.
- *Rejected — classify-by-target with containment check:* keeps writing
  through links, contradicts a walker that never descends them, more
  complex, and re-introduces the double-sign hazard for versioned
  frameworks.
- *Rejected — hard error on any symlink:* bundles legitimately contain
  symlinks (the repo's own fixture `code_resources.rs:457-468` is a
  versioned framework); erroring would break them for no safety gain,
  since nothing follows the link after this change.
- Note: a symlinked *directory* named `*.framework` stops being collected.
  Its contents were never walked anyway (walkdir does not descend symlink
  roots with `follow_links(false)`), so today's "collection" only produced
  a partial, broken pass; the brief mandates "not collected".

**Item 3**
- *Chosen:* one dual-shape `resolve_within(root, path)` (root-prefixed or
  root-relative), guard at each writer's entry, `root` threaded into
  `sign_binary`/`sign_standalone_dylib` as a parameter.
- *Rejected — guard only at discovery boundaries:* the brief mandates a
  guard before every write; boundary-only checks give no protection once a
  new caller appears, and cannot catch a pre-planted symlink at a literal
  path (`Info.plist`, `embedded.mobileprovision`, `_CodeSignature`).
- *Rejected — store the root in `IpaSigner`:* stateful field on a `&self`
  builder reused across `sign()`/`sign_folder_in_place()` invites stale
  roots; parameters are explicit.
- *Rejected — canonicalize-based containment:* superseded by the
  `extract.rs` idiom (strip_prefix + downward symlink walk); works for
  nonexistent write targets and dangling symlinks without a
  deepest-existing-ancestor dance, and keeps error messages naming the
  first bad component.
- *Decision — guard reads too:* validation runs at function entry, before
  `File::open`/`fs::read`, so a planted symlink can neither be read into
  the artifact nor written through.

## Non-goals

- `extract.rs` extraction policy (lane 28), `archive.rs` repack fidelity
  (ZSN-39), `builder.rs` option forwarding (ZSN-35), nested
  profile/entitlement semantics (ZSN-11/12), `.github/**` (lane 31),
  `cms`/`macho`/`codesign` verification (lanes 23/24).
- `verify.rs` duplicates similar discovery predicates; it is outside this
  lane's file scope — parity follow-up belongs to the verify lanes.
- `CodeResourcesBuilder` already records symlinks without following them;
  no change there.
