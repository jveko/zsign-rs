# Dylib injection: embed the file, scope the injection — design

**Date:** 2026-10-08
**Status:** approved for implementation (cold review gate applies to this document together with the plan)

## Problem

Two related gaps in the `-l/--dylibs` injection feature of the CLI:

1. **Embed gap.** `-l` values are forwarded as raw strings
   (`crates/zsign-cli/src/main.rs:138-140`, used once at `:275-277`) down through
   `ZSign::dylib_injection` (`crates/zsign/src/builder.rs:345-349`) into
   `IpaSigner::sign_binary` (`crates/zsign/src/ipa/mod.rs:1789`, injection at
   `:1826-1834`), which writes the verbatim string into the load command via
   `zsign_core::macho::writer::inject_dylib_command`. The dylib file itself is
   never copied into the bundle: a signed artifact can reference
   `@executable_path/…` or any typo/relative/empty string that does not exist
   inside the bundle, and the run still reports success. There is no validation
   at any layer — the three `self.dylibs` uses in `builder.rs` (`:421-425`,
   `:536-538`, `:605-607`) and the single use in `ipa/mod.rs` pass the value
   through untouched.

2. **Scope gap.** The same `sign_binary` is reached for the root app's main
   executable (`ipa/mod.rs:1505-1516`) and for every non-main executable of
   every nested bundle (`:1519-1540`, discovered through the depth-first plan
   loop at `:1040-1048`; bundle classification in
   `crates/zsign/src/bundle/mod.rs:47-101`). With one flat `dylibs` list there
   is no way to inject at the app root only; today every `MH_EXECUTE` in the
   archive — PlugIns/`.appex`, XPC services, Watch apps, AppClips — receives the
   load command, and there is no opt-out.

## Upstream contract (verified against zhlynn/zsign @ 614caa8d)

- `-l` files are copied into the **app root** (`m_strAppFolder`) and the
  injected string is rewritten to `@executable_path/<basename>`
  (`src/bundle.cpp:834-843`).
- With `-P/--inject_extensions`, extension executables get a relative prefix:
  `@executable_path/<../ × N><basename>` where N is the number of path
  components of the bundle directory under the app root
  (`src/bundle.cpp:391-399`; upstream README:171-175 documents
  `@executable_path/../../demo.dylib`). The `-P` scope is exactly top-level
  `PlugIns/*.appex` and `Extensions/*.appex` directories
  (`IsAppExtensionPath`, `src/bundle.cpp:295-308`); XPC/Watch/AppClips are not
  injected even with `-P`.
- Upstream validates each `-l` value **before signing**: must exist and parse
  as a Mach-O (`src/zsign.cpp:332-342`), otherwise the process exits nonzero.
- `@executable_path` resolves to the directory of the executable that carries
  the load command (Apple `dyld(1)`), so an app-root copy referenced by the
  root main executable resolves inside the app root, and an extension resolves
  the `../../` walk back to that same single copy.

## Candidate designs

**A (chosen).** Path-typed `-l` with parse-time validation; the copy into the
app root happens inside `IpaSigner::sign_bundle` (the only layer that sees the
extracted store) via `Store::write`, before the standalone-dylib pass so the
copy is signed and sealed; injection strings are computed per bundle in
`sign_bundle` (root always, top-level PlugIns/Extensions `.appex` only with
the new `-P` flag) and passed down to `sign_binary`; the bare-Mach-O path keeps
injecting the given path verbatim.

**B. Rejected — copy at the CLI/builder layer.** The CLI never sees the
extracted tree; extraction lives inside `IpaSigner` behind a `Store`
(`FsStore` for paths, `MemStore` for the wasm bytes flow). A CLI-side copy
would require duplicating extraction or leaking the store upward. It also
leaves the raw-string bundle injection in place.

**C. Rejected — copy into `Frameworks/`, uniform
`@executable_path/Frameworks/<name>`.** One string works at every depth (no
`../` math), but it diverges from the upstream layout the gap statement measures
this port against (root copy + `@executable_path/<basename>`), and would make
output byte-comparisons against upstream-derived expectations fail for no
correctness gain.

**D. Rejected — `--dylib-scope=root|extensions|all` enum.** More expressive than
needed; `all` has no upstream counterpart, and the brief's fix direction names
`-P/--inject-extensions`. A matching flag keeps the migration story one line.

## Design (candidate A)

### CLI (`crates/zsign-cli/src/main.rs`)

- `dylibs` becomes `Vec<PathBuf>` with
  `value_parser = parse_dylib` (mirrors the existing `parse_profile_map`
  helper pattern at `:192-200`; a clap value error is a usage error → exit 2).
  `parse_dylib` rejects, in order: empty string; a path that is not an existing
  regular file; bytes that do not parse as Mach-O. Validation reuses the
  public `zsign_rs::macho::MachOFile::parse` (`crates/zsign/src/macho/parser.rs:36`)
  rather than duplicating a magic table.
- New flag `-P, --inject-extensions` (upstream name and semantics), help text
  states it widens `-l` to top-level app extensions. `inject_extensions` joins
  the `-V` `conflicts_with_all` list (`:157-184`) like every other signing flag.
- `run()` forwards `cli.dylibs` unchanged (validation already happened) and
  forwards the scope flag next to the existing `dylib_injection` call.

### Builder (`crates/zsign/src/builder.rs`)

- `ZSign.dylibs: Vec<PathBuf>`; setter `dylib_injection(Vec<PathBuf>, bool)`;
  new setter `inject_extensions(bool)`; both `sign_ipa` and `sign_bundle`
  forward the scope flag the way they already forward `allow_unsafe_profile`.
- `sign_macho` (bare Mach-O, no bundle) keeps injecting the given path
  **verbatim** — there is no bundle root to copy into, and this matches
  upstream's standalone-Mach-O behavior. Its existing test
  (`:1250-1279`) changes type only.

### IpaSigner (`crates/zsign/src/ipa/mod.rs`)

- Fields: `dylibs: Vec<PathBuf>` (type change), new `inject_extensions: bool`
  with setter `inject_extensions(bool)`; `dylib_injection` doc updated to the
  new scope contract.
- In `sign_bundle`, immediately before `find_standalone_dylibs` (`:1035`) —
  i.e. after the read-only plan phase and the requested-rewrite phase, before
  any binary signing:
  1. **Copy phase.** For each `-l` path: read the file from the host FS (same
     precedent as `load_profile`'s `BlobSource::Path` arm at `:704-714`, which
     also reads host paths from store-generic code; the wasm surface never
     sets `dylibs`, exactly as it never sets a path-form profile), take
     `file_name()` as the destination name, and `store.write` it into the app
     root, overwriting any existing file of that name — upstream parity
     (`ZFile::CopyFileV` overwrites unconditionally). A content-comparing
     guard was considered and rejected: a re-sign of an archive that already
     contains the (now signed) copy sees bytes that differ from the source
     file, so any "different content → error" rule would break the idempotent
     re-sign workflow to protect against a rare basename clash. The clash
     (including `-l` basename collisions with the main executable) is a
     documented known behavior, same as upstream.
  2. **Signing phase.** The copied paths are merged into the standalone-dylib
     list (dedup against the extension-based scan at
     `:1337-1366`) so every copied file is signed regardless of its suffix —
     an extensionless copy must still be signed or `-V` on the output would
     find an unsigned Mach-O.
  3. **Scope map.** For every bundle `(path, depth)` in `bundles`: the root
     (`path == bundle_path`) is always in scope; a nested bundle is in scope
     iff `inject_extensions` holds **and** its path relative to the root is
     exactly `<PlugIns|Extensions>/<name>.appex` (two components, second
     ending `.appex`) — `IsAppExtensionPath` parity. In-scope bundles map to
     `[@executable_path/ + "../" × components(relative) + basename, …]`
     (`components == 0` at the root, so the root arm is the same formula).
- `sign_single_bundle` and `sign_one_binary` gain an `injected: &[String]`
  parameter (empty slice = no injection) taken from the scope map;
  `sign_binary` replaces its `!self.dylibs.is_empty()` gate with
  `!injected.is_empty() && is_executable && binary_path.parent() == Some(root)`
  — the parent check reproduces upstream's folder test, so only binaries
  sitting directly in an in-scope bundle directory are hooked (subdirectory
  helpers of the root app are not, matching upstream).
- The copy list and the scope map are computed only when `dylibs` is
  non-empty, so the wasm `MemStore` flow (which never sets `dylibs`) keeps its
  current path untouched.

### Errors and exit contract

- Invalid `-l` value → clap `ValueValidation` at parse time → exit 2.
- File unreadable at sign time (TOCTOU, library callers) → `Error::Io` via the
  existing `#[from]` (`crates/zsign/src/error.rs:35`) → run() error path → exit 1.
- Success path unchanged: exit 0. No new exit codes.

## Deliberately out of scope

- Re-signing with the same `-l` stacks a second `LC_LOAD_DYLIB` (the writer
  has no dedupe; `writer.rs` is owned by another lane). Pre-existing behavior,
  unchanged here.
- `-w` without `-l`; `-l` entries whose basenames collide (last one wins at
  the copy stage — upstream behaves the same); bare-Mach-O library callers
  passing nonexistent paths (the CLI validates at parse time; `sign_macho`
  never reads the file).

## Acceptance criteria

1. `zsign … -l ""`, `-l <missing>`, `-l <non-Mach-O>` each exit 2 with a clap
   value error naming the reason.
2. Signing a bundle/IPA with `-l <file>` places `<file>`'s bytes at the app
   root of the output, the copy is signed, and the root main executable's load
   commands contain `@executable_path/<basename>` (and only that string, not
   the host path).
3. By default no extension/XPC/Watch executable receives an injected load
   command; all of them are still signed and sealed.
4. With `-P`, top-level `PlugIns/*.appex` and `Extensions/*.appex` main
   executables receive `@executable_path/../../<basename>`; XPC/Watch/AppClips
   remain uninjected.
5. A repacked IPA containing the copy verifies valid through the `-V` engine.
6. `cargo fmt --all -- --check` and
   `cargo clippy --workspace --all-targets -- -D warnings` are clean;
   `TMPDIR=$PWD/target/tmp cargo test --workspace` passes.
