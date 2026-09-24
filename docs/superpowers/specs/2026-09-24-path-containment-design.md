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
   Provenance inventory of all seven write/mkdir sites in this file:
   `:517` is WalkDir-derived (root-prefixed by construction); `:556`,
   `:659`, `:894`, `:897` are literal-derived under the bundle; `:810`
   and `:867` receive either the WalkDir-derived non-main path **or** the
   plist-derived `main_executable` — that plist-derived variant is the
   only escape. `main_executable` is therefore the only written path not
   pinned by a literal `join` or by WalkDir enumeration.
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
3. Key present but not a string → hard `Error::Core(Signing(...))`
   (`"CFBundleExecutable in {} must be a string"`). No fallback: the
   file-stem fallback is reserved for an *absent* key, per the brief.
4. Key present as a string → the value must be **relative**; an absolute
   value — whether it points outside or *inside* the root — is rejected
   up front with an actionable error naming the value and the bundle.
   Then `resolve_within(bundle_path, Path::new(value))?` (item 3 helper)
   rejects `RootDir`/`ParentDir`/`Prefix` components, non-plain spellings
   (`./Test`, `foo//Test`, `Test/`), and any pre-existing symlink
   component (`..` fails the component check).
   `fs::symlink_metadata` must report a **regular file**; otherwise a
   hard `Error::Core(Signing(...))` naming the offending value and the
   bundle. This fires for missing files, directories, and (final or
   intermediate) symlinks — so a layout whose `CFBundleExecutable` names
   a symlink (e.g. a versioned-framework root link) is rejected by
   design; naming the real in-root file is the supported form (see
   Item 2).
5. Key absent — or an Info.plist whose root is not a dictionary, which
   carries no value to validate — → keep the file-stem fallback, still
   passed through `resolve_within`, with **no** existence requirement
   (callers' `.exists()` guards at `:575`/`:594` stay load-bearing only
   for this branch).

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
on what a symlink *is*. Real in-tree targets remain discoverable as
regular files, and the root symlink is never a signing target — so where
such a layout signs at all, it is signed exactly once through the real
path instead of twice (through the link and directly — a pre-existing
double-sign hazard today). Composed with Item 1's regular-file rule, the
policy is explicit: a bundle whose `CFBundleExecutable` *names* the root
symlink is **rejected** with an actionable error; the supported form
names the real in-root file (`Versions/A/Foo`), which dedups normally
via the `:620`/`:543` equality checks. The `code_resources.rs:456-468`
fixture is scan-only and unaffected — `CodeResourcesBuilder` records
symlinks as symlinks.

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
2. Reject `Component::ParentDir | RootDir | Prefix(_)` in `relative`
   with `"Path {} escapes the bundle root {}"`.
3. Require plain spelling: split `relative`'s raw text on `/` (on
   Windows also `\`, where both are accepted separators) and reject any
   empty segment (redundant or trailing separator) or `.` segment
   (`./Test`, `foo//Test`, `Test/`), with
   `"Path {} is not a plain relative path under {}"`. The check is
   segment-based rather than a `PathBuf`-rebuild comparison because a
   rebuild joins with the *native* separator and would reject ordinary
   `/`-spelled values on Windows — including the literal
   `"_CodeSignature/CodeResources"` passed by Task 3's writers.
   CodeResources' main-executable exclusion compares the *raw*
   `CFBundleExecutable` string against WalkDir-relative paths
   (`zsign-core/src/bundle/code_resources.rs:264-267`), so only a plain
   raw value can keep that invariant. Root-prefixed inputs arrive via
   `strip_prefix`, which already returns plain remainders (verified
   against Rust std behavior), so the check only ever fires on
   literal/relative inputs — i.e. the raw plist value.
4. Downward walk: push each component onto a `current` buffer starting at
   root; if `fs::symlink_metadata(&current)` says symlink →
   `"Pre-existing symlink in signing path: {}"` (cf. `extract.rs:79-86`).
   The first `ErrorKind::NotFound` stops the walk (fresh tail is safe);
   any *other* metadata failure (permission, I/O) becomes a hard
   `Error::Core(Signing("Failed to inspect signing path {}: {}"))` — it
   is never treated as proof of absence. The walk starts *below* `root`;
   the root itself is validated once at signing entry (next paragraph).
5. Return `root.join(relative)` — lexical, never canonicalized.

All errors are `Error::Core(zsign_core::Error::Signing(format!(...)))`,
the established idiom of this file for signing-flow complaints.

Root handling: the bundle root itself is validated once, at
`sign_bundle_from_options` — `fs::symlink_metadata(bundle_path)` must
not report a symlink, otherwise hard error
(`"Bundle root must not be a symlink: {}"`). walkdir 2.5 follows a
symlinked walk root even with `follow_links(false)`
(`follow_root_links` defaults to true — walkdir 2.5.0 lib.rs:853, and
the root-descent branch at :861-871), and `resolve_within` deliberately
starts below the root, so this single entry check covers `sign()`,
`sign_folder_in_place`, and `sign_folder_to_ipa` through their common
funnel. This also covers a symlinked `Payload/*.app` returned by
extraction (in-tree redirect targets pass `is_safe_symlink_target`, so
the redirect is only blocked here). Because `lstat("link/")` follows a
final symlink when a trailing separator is present (verified against
`fs::symlink_metadata` on this toolchain), the check lstats the
component-rebuilt path — trailing separators stripped. Ancestor path
components of the
root (the path *above* the final component) are trusted operator input
— equivalent to the operator's choice of working directory — because
the threat model is hostile bundle content, and rejecting symlinked
ancestors would break standard layouts (macOS `/var` → `/private/var`,
tempdir roots). That trust applies to operator-supplied roots only. In
`sign()`, the components below the extraction TempDir are archive-created
— extraction permits relative, `..`-free targets like
`Payload → Payload2` — so `sign()` validates them with
`resolve_within(temp_dir.path(), app_bundle)` immediately after
extraction; a symlink among them is a hard error
(`test_sign_rejects_aliased_payload_root`). Only the TempDir path itself
and its system-level ancestors remain trusted there.

Wiring — every `fs::write`/`create_dir_all` is preceded by exactly one
validation: at function entry where the function also reads or dispatches
through the path (`rewrite_plist_string`, `sign_binary`,
`sign_standalone_dylib`), immediately before the write for the literal
paths inside `sign_single_bundle` and `generate_code_resources` (both
may run after earlier in-bundle writes):

| Site | Root | Input |
|---|---|---|
| `rewrite_plist_string` `:659` (+ its read) | `bundle_path` | literal `"Info.plist"` at entry |
| `sign_standalone_dylib` `:517` (+ its open) | **new `root` param** from `sign_bundle :370` | `dylib_path` at entry |
| `sign_single_bundle` profile `:556` | `bundle_path` | literal `"embedded.mobileprovision"` |
| `generate_code_resources` mkdir `:894` / write `:897` | `bundle_path` | literals `"_CodeSignature"` and `"_CodeSignature/CodeResources"` |
| `sign_binary` `:810`, `:867` (+ its open) | **new `root` param** from `sign_single_bundle :550`/`:576` | `binary_path` at entry |

The validated value shadows the parameter, so every downstream use of
`binary_path` (open, read, both writes) operates on the contained path.
The `parent()`-derived Info.plist read at `:821` is thereby lexically
contained (no `..` can appear below a validated path) but is *not*
symlink-checked — see "What is and is not guarded" under Design
decisions.

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
`bundle/code_resources.rs:441`). Each containment test fails before its
fix; where an external or target file exists, its bytes must be
byte-identical afterwards. Platform note: tests 6-13 are
`#[cfg(unix)]` (off-Unix only tests 1-5 exist), and test 7's probe
returns early — passing without asserting — where DAC permission checks
are bypassed (e.g. running as root). Test 12 is an explicit
trust-boundary pin: it passes before and after the fix and fails only if
ancestor-trusting is revoked. Windows: this lane's gates run on Unix;
the `cfg!(windows)` arm of the separator split is compile-checked but
not executed here (no Windows runner). Pre-existing, out-of-lane
limitation: `CodeResourcesBuilder::scan` stores native-separator
relative paths (`code_resources.rs:171-180`) while `CFBundleExecutable`
uses `/`, so on Windows *nested* (sub-path) executable values already
miss the raw-string main-executable exclusion; flat values — the iOS
norm — are unaffected. This change neither worsens nor repairs that (the
builder is another lane's file).

1. `test_sign_rejects_executable_path_outside_bundle` — `CFBundleExecutable`
   = `"../outside_macho"` (real Mach-O written beside the `.app` in the
   tempdir). `sign_folder_in_place` must `Err` with a message naming the
   escaping path; outside bytes unchanged. Covers item 1.
2. `test_sign_rejects_absolute_executable_path` — same with the absolute
   path of the outside Mach-O as the value; error contains
   `"must be a relative path"`; outside bytes unchanged. Covers item 1.
3. `test_sign_rejects_absolute_executable_path_inside_bundle` — the value
   is the absolute path of the *in-bundle* executable; must fail with
   `"must be a relative path"` (absolute rejected even when it points
   inside the root). Covers item 1's absolute rejection.
4. `test_sign_rejects_non_string_executable_value` — `CFBundleExecutable`
   is an `<integer>`; must fail with `"must be a string"` (the fallback
   is reserved for an absent key). Covers the fallback boundary.
5. `test_sign_rejects_nonplain_executable_value` — `CFBundleExecutable`
   = `"./Test"` over a real in-bundle `Test`; must fail with
   `"not a plain relative path"` — covers `CurDir`/redundant-separator
   rejection that keeps CodeResources' raw-string main-executable
   exclusion intact. Covers item 1 × item 3.
6. `test_sign_rejects_symlinked_main_executable` (`#[cfg(unix)]`) —
   `CFBundleExecutable` names an in-root symlink whose target is a real
   in-bundle file; sign must fail (`"Pre-existing symlink"`) and the real
   target's bytes must stay unchanged — documents that layouts whose
   plist names the root link are rejected (Item 1 × Item 2 composition).
7. `test_sign_errors_on_unreadable_path_component` (`#[cfg(unix)]`) — a
   bundle subdirectory is chmod'd unreadable and `CFBundleExecutable`
   points through it; sign must fail with
   `"Failed to inspect signing path"` — the metadata-error hard-error arm
   of `resolve_within`. Probe-guarded: environments that bypass DAC
   permission checks skip the assertions.
8. `test_symlinked_dylib_is_skipped_and_target_untouched`
   (`#[cfg(unix)]`) — bundle with real executable plus `lib.dylib` →
   `../outside.dylib` symlink. `find_standalone_dylibs` and
   `find_immediate_macho_binaries` (private, called directly from the
   inline tests) must not list it; a full `sign_folder_in_place` succeeds
   and `outside.dylib` bytes are unchanged. Covers item 2 (both walks
   that can see a file at bundle root).
9. `test_symlinked_framework_is_not_collected_and_target_untouched`
   (`#[cfg(unix)]`) — `Evil.framework` symlink → external dir containing
   `Info.plist` + executable; `collect_nested_bundles` must not list it;
   full sign succeeds; external executable bytes unchanged and no
   external `_CodeSignature` appears. Covers item 2.
10. `test_sign_rejects_symlinked_info_plist_rewrite` (`#[cfg(unix)]`) —
    `Info.plist` is a symlink to a valid external plist;
    `.bundle_id("com.x")` triggers `rewrite_plist_string` first; sign
    must `Err` and the external plist bytes must be unchanged. This is
    the failing-first test for the `resolve_within` write guard (items
    3); without the guard the rewrite writes through the symlink and the
    bytes change.
11. `test_sign_rejects_symlinked_bundle_root` (`#[cfg(unix)]`) — the
    fixture's real `App.app` is renamed to `Outside.app` and `App.app`
    recreated as a symlink to it; `sign_folder_in_place` must fail with
    `"Bundle root must not be a symlink"` both for the plain path and
    for the path with a trailing `/` (which would otherwise force the
    kernel to follow the final component); outside bytes unchanged and
    no external `_CodeSignature`. Covers item 3's root validation.
12. `test_sign_trusts_operator_root_ancestors` (`#[cfg(unix)]`) — a real
    bundle under `temp/real/App.app` is signed via `temp/link/App.app`
    where `temp/link` → `temp/real`; the sign must **succeed** with
    writes landing at the resolved location (`real/App.app/_CodeSignature`)
    — pinning the documented trust boundary: root *ancestors* are
    operator input, only the root's final component is checked.
13. `test_sign_rejects_aliased_payload_root` (`#[cfg(unix)]`) — a zip
    containing a real `Payload2/App.app` plus a `Payload → Payload2`
    symlink (a target shape `is_safe_symlink_target` permits);
    `sign()` must fail with `"Pre-existing symlink in signing path"` —
    the archive-created component above the bundle root is validated
    against the extraction root. Covers item 3's `sign()` ancestry
    validation.

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
- *Chosen:* non-string values rejected; absolute values (inside or
  outside the root) rejected; then component rejection via
  `resolve_within` + `symlink_metadata` regular-file requirement; hard
  errors with the offending value in the message.
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
- *Rejected — hard error on any symlink at walk level:* bundles
  legitimately contain symlinks (the repo's own fixture
  `code_resources.rs:457-468` is a versioned framework); erroring would
  break them for no safety gain, since nothing follows the link after
  this change. The one exception is the *declared main executable*, which
  the brief requires to be a regular file — walk-level skip, hard error
  for that single path.
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
- *Decision — what is and is not guarded:* `resolve_within` precedes
  every `fs::write`/`create_dir_all` and, for `rewrite_plist_string`,
  `sign_binary`, and `sign_standalone_dylib`, runs at function entry —
  which also guards those functions' reads of their write targets (the
  Info.plist read in `rewrite_plist_string`, the binary opens in
  `sign_binary`/`sign_standalone_dylib`). Deliberately **not** guarded,
  because they are read-only and outside the brief's write mandate:
  `get_bundle_identifier`'s and `get_main_executable`'s Info.plist reads,
  `sign_binary`'s parent-derived Info.plist read `:821`,
  `sign_single_bundle`'s CodeResources read-back, and
  `CodeResourcesBuilder`'s scan (a different file — lane scope). A read
  through an in-tree symlink yields content the bundle owner could have
  placed in the bundle directly, and no bytes are written outside the
  root; the `sign()` flow in addition cannot smuggle an *escaping*
  symlink target through extraction (`extract.rs`'s
  `is_safe_symlink_target` refuses absolute and `..` targets, so
  extracted links resolve in-tree), and a symlinked bundle root —
  extracted or operator-supplied — is rejected at signing entry
  (see "Root handling" above), so neither flow can redirect the write
  root.
- *Decision — root final-component check, ancestors trusted:*
  `sign_bundle_from_options` rejects a symlink *final* component of the
  root (checked on the component-rebuilt path so a trailing separator
  cannot force the kernel to follow it). Walking every lexical ancestor
  was rejected: operator-supplied ancestors are invocation-time input —
  outside the hostile-bundle threat model — and ancestry rejection would
  break standard layouts (macOS `/var` → `/private/var`, tempdir roots).
  Pinned by `test_sign_trusts_operator_root_ancestors`. In `sign()`,
  archive-created components above the bundle root are validated against
  the extraction root (`resolve_within(temp_dir.path(), app_bundle)`),
  closing the `Payload → Payload2` alias — pinned by
  `test_sign_rejects_aliased_payload_root`.
- *Decision — plain spelling enforced in `resolve_within`, not
  normalized:* the raw `CFBundleExecutable` string must equal its
  WalkDir-relative form for CodeResources' exclusion invariant, and
  `CodeResourcesBuilder` (out of lane scope) re-reads the raw string —
  so normalization inside this file could not restore the invariant.
  Reject instead: validate, don't guess.

## Non-goals

- `extract.rs` extraction policy (lane 28), `archive.rs` repack fidelity
  (ZSN-39), `builder.rs` option forwarding (ZSN-35), nested
  profile/entitlement semantics (ZSN-11/12), `.github/**` (lane 31),
  `cms`/`macho`/`codesign` verification (lanes 23/24).
- `verify.rs` duplicates similar discovery predicates; it is outside this
  lane's file scope — parity follow-up belongs to the verify lanes.
- `CodeResourcesBuilder` already records symlinks without following them;
  no change there.
