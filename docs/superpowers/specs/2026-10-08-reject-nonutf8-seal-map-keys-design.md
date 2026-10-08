# Reject Non-UTF-8 Seal Map Keys — Design

## Problem

`hash_entry` (`crates/zsign/src/bundle/code_resources.rs:206`) converts the
bundle-relative path of every walked entry with `.to_string_lossy().to_string()`
(`:227-228`) and uses that `String` both as the exclusion-check input
(`should_exclude`, `:230`) and as `ScannedEntry.path` (`:44`), which `scan()`
replays into the core seal map via `add_symlink` (`:195`) and `add_file`
(`:197`).

The core map is `files: BTreeMap<String, FileEntry>`
(`crates/zsign-core/src/bundle/code_resources.rs:67`). `add_file` (`:495`) and
`add_symlink` (`:530`) insert with an unguarded `self.files.insert(...)`
(`:505` and `:541`); the returned `bool` reports only exclusion
("Returns `true` if the file was added, `false` if it was excluded"),
never an overwrite, and `file_count()` is just `self.files.len()` (`:650-652`).

Lossy conversion is not injective: each invalid byte becomes U+FFFD, so two
distinct on-disk names that differ only in their invalid bytes — e.g.
`bad\xFF.dat` and `bad\xFE.dat` — map to the *same* key
`bad\u{FFFD}.dat`. The second insert overwrites the first, and the seal ends
up with one key carrying the last file's hashes: **one of the two files is
dropped from the seal with no error**, and `file_count()` under-reports it.
A single non-UTF-8 name is also wrong without any collision: its key matches
no file on disk.

The key-derivation site is unique: `hash_entry` is called only from `scan()`'s
two arms (`:182`, `:189`), and `scan()`'s only production caller is the
signing path (`crates/zsign/src/ipa/mod.rs:2022-2024`). The verifier re-derives
disk keys with the same lossy conversion
(`crates/zsign/src/verify.rs:891-892`), so the disk→sealed sweep dedups both
real names onto the one sealed key and never reports either as unsealed; the
sealed→disk direction (`verify_code_resource_entry`, `verify.rs:614-766`) joins
the fabricated key against disk, finds nothing, and reports a `missing` path
that never existed — the actually-dropped file is never identified
(`[INFERENCE]` for the full report shape: derived from the two loops in
`check_code_resources`, `verify.rs:766-909`, not from a live run).

No test anywhere in the workspace covers a non-UTF-8 file-name key.

## External contract (researched)

Verified against Apple's open-source Security and CoreFoundation sources
(`apple-oss-distributions/Security`, `apple-oss-distributions/CF`, `main`
as read 2026-10-08), plus comparable third-party tools:

1. **Apple fails closed at key creation; it never encodes or mangles.**
   Seal keys are `CFTempString(relpath)`
   (`OSX/libsecurity_codesigning/lib/signer.cpp:543,545`) → `makeCFString`
   (`OSX/include/security_utilities/cfutilities.h:307-334`): UTF-8 attempt,
   then ASCII attempt, else `CFError::throwMe()`
   (`OSX/libsecurity_utilities/lib/errors.cpp:233-234`), which aborts the
   operation (`errSecCoreFoundationUnknown = -4960`, `base/SecBase.h:340`).
   CoreFoundation returns NULL for undecodable input (`CFString.c:1303-1306`,
   `CFStringEncodings.c:333-340`). Plist dictionary keys are CFString
   (Unicode); there is no byte-string key type, no percent-encoding, and no
   lossy substitution anywhere in the chain. An Apple-produced CodeResources
   therefore cannot contain a collapsed or mangled key.
2. **Apple's verifier applies the identical conversion and rejects unsealed
   files.** `StaticCode.cpp:1479-1481` and `:1860` wrap paths in
   `CFTempString` (same throw); an on-disk file with no seal entry is reported
   as `errSecCSBadResource` (`-67054`) under `kSecCFErrorResourceAdded`
   (`StaticCode.cpp:1908-1921`, codes in `CSCommon.h`).
3. **No Apple prose states a filename-encoding policy.** TN2206 and
   codesign(1) are silent; the Code Signing Guide CodeResources pages 404.
   The reject-don't-encode conclusion above is read from source, not from
   documentation `[INFERENCE]`; no macOS host was available to execute
   `codesign` empirically `[INFERENCE]`.
4. **Comparable third-party tooling splits.** `rcodesign` derives seal keys
   with `to_string_lossy()` (`apple-codesign/src/code_resources.rs:922`) —
   the same defect class — and publishes no policy on non-UTF-8 names, so
   there is no third-party consensus to conform to `[INFERENCE: absence of
   documentation]`.
5. **This repo already chose fail-closed for the sibling conditions.**
   This session's landed fix refuses non-UTF-8 symlink *targets* inside
   `hash_symlink_entry` (`crates/zsign/src/bundle/code_resources.rs:311-316`);
   the archive writer refuses the same bytes for symlink targets
   (`crates/zsign/src/ipa/archive.rs:151-157`); the store refuses to *create*
   such a symlink (`crates/zsign/src/store.rs:247-249`). The file-name branch
   is the remaining gap in the same integrity concern; the landed fix's design
   explicitly deferred it as a separate workstream.

## Candidate designs

### A — Fail closed at the facade key derivation (chosen)

In `hash_entry`, after the `should_exclude` filter, derive the key with
`relative_path.to_str()` instead of `to_string_lossy()`; on `None` the scan
returns `Error::Core(zsign_core::Error::Signing(String))` and no seal is
produced. The lossy string survives only as the exclusion-matching input for
entries that are never sealed.

- Pros: guards the *unique* key-derivation site, so no native scan can put a
  lossy or colliding key in the map; the single conversion point sits before
  the symlink branch (`:234`), so file **and** symlink entry names are covered
  by one guard with no change to `hash_symlink_entry`'s landed target check;
  identical shape to the landed precedent (same error variant, same message
  pattern, same guard-after-exclusion placement); the wasm error mapping is
  untouched — `Signing` already routes to `ZSIGN_SIGNING_FAILED`
  (`crates/zsign-wasm/src/lib.rs:112,139,157`); exclusion precedence is
  preserved; smallest possible diff in the files later workstreams also touch.
- Cons: the core map insert itself stays unguarded — the design relies on the
  invariant that every caller now feeds distinct, valid-UTF-8 keys, documented
  at the insert (see Decisions).

### B — Make core `add_file`/`add_symlink` fallible and reject duplicate keys (rejected)

1. Core receives `impl Into<String>` (`:495-501`, `:530-536`) — already UTF-8
   by type. It can never detect the actual defect (invalid bytes), only a
   repeated key.
2. Duplicate detection does not close the hole: a lone non-UTF-8 name produces
   a wrong key with *no* duplicate to detect — silently sealed under a
   U+FFFD key matching neither file, with the self-consistent verifier
   unable to name it. The facade guard is necessary regardless, so the core
   guard buys no additional correctness for this failure.
3. The signature change would ripple into core doctests (`:493`, `:528`,
   `:572`), core unit tests, and the wasm callers (`hash_file` at
   `crates/zsign-wasm/src/lib.rs:380`, `hash_file_chunk` at `:438`,
   `add_symlink` at `:451-456`) — forcing edits to
   `crates/zsign-wasm/src/lib.rs`, a file this workstream must not touch
   (owned by a concurrent workstream), and breaking the documented JS
   contract "Duplicate symlink paths retain last-wins semantics"
   (`crates/zsign-wasm/src/lib.rs:449-450`).

### C — Detect the collision at verify/serialize time (rejected)

Too late: by then the wrong key is already the seal. The plist writer cannot
recover which of the two on-disk names the lossy key meant, and moving the
check to `verify.rs` would both leave broken seals being *produced* and
require editing the verifier, whose lossy-vs-lossy self-consistency is a
separate, already-deferred strictness workstream. Research reaches the same
conclusion: the guard must sit at key construction, not at serialization.

## Decisions recorded

- **Error shape:** `Error::Core(zsign_core::Error::Signing(String))` with the
  message exactly prefixed `File name is not valid UTF-8: ` followed by
  `path.display()` (rendered as `Signing failed: File name is not valid UTF-8: …`).
  A *new* facade `Error` variant was rejected for the reason recorded by the
  landed sibling fix: `code_for_zsign_error`
  (`crates/zsign-wasm/src/lib.rs:155-165`) is deliberately exhaustive, so a
  new variant would force an edit to a file outside this workstream's scope;
  `Signing` already maps to the stable `ZSIGN_SIGNING_FAILED`.
- **Guard placement is after `should_exclude` (`:230`)**, so exclusion
  precedence is preserved: an excluded entry is never sealed, therefore can
  never collide in the map, therefore is not validated — exactly the precedent
  set by the landed exclusion test for symlink targets.
- **The lossy conversion stays only as the exclusion input.** For valid UTF-8
  names `to_string_lossy()` and `to_str()` agree, so exclusion matching is
  byte-identical to today for every name that can be sealed.
- **`path.display()` in the message is diagnostic context only.** On a
  non-UTF-8 path `display()` is itself lossy; that is acceptable for a human
  message and matches the landed symlink message. It is never round-tripped.
- **Core gets documentation, not a signature change:** one line added to
  `add_file` and `add_symlink` stating that inserting an existing path
  replaces the entry (last write wins). This records the invariant the design
  relies on at the exact insert the concern names, without changing behavior
  any caller depends on.
- **No verifier, store, wasm, or CLI changes** (see Deferred).

## Deferred (explicitly out of scope)

- **Verifier-side strict key derivation** (`crates/zsign/src/verify.rs:891-892`,
  `:458`, target compare `:699`): separate verification-strictness
  workstream, already recorded as deferred by the landed sibling fix.
- **FIFO/kind collapse in `hash_entry`** and **symlink target containment**:
  separate workstreams in the same function; this change adds no kind or
  path-policy logic.
- **Extraction-side entry-name handling and the archive write side**: other
  workstreams' scope, read for context only.
- **Wasm per-entry duplicate semantics** (`finalized_paths` pre-rejection for
  files at `crates/zsign-wasm/src/lib.rs:250,371,409`; documented last-wins
  for symlinks at `:449-450`): a deliberate external contract on inputs that
  are valid UTF-8 by construction (JS strings), untouched.
- **`Store::list()`'s lossy listing** (`crates/zsign/src/store.rs:125`): not
  a seal-key path.

## Testing strategy

All in `crates/zsign/src/bundle/code_resources.rs`'s test module,
`#[cfg(unix)]`, fixtures created from raw `OsStr::from_bytes` bytes, mirroring
the landed symlink tests:

1. **Collision rejection (the regression test):** a bundle containing both
   `bad\xFF.dat` and `bad\xFE.dat` (distinct names, one lossy form) must make
   `scan()` return `Err(Error::Core(zsign_core::Error::Signing(..)))` whose
   message contains `File name is not valid UTF-8`. Fails before the change:
   `scan()` succeeds and the map holds a single key for the two files.
2. **Exclusion precedence:** a non-UTF-8 file name under an excluded directory
   scans cleanly — validation applies to entries that will be sealed, not to
   tree traversal.
3. **No over-rejection + exactness:** valid-UTF-8 non-ASCII names — `ré.txt`,
   a name containing a literal U+FFFD, and a multibyte CJK name — must not be
   rejected and must appear byte-identically as `files2` keys in the built
   plist (a literal U+FFFD proves `to_str()` does not ban the *character*,
   only invalid *bytes*).

The pre-existing tests — including the landed symlink trio
(`test_scan_bundle_rejects_non_utf8_symlink_target`,
`test_scan_bundle_ignores_excluded_non_utf8_symlink_target`,
`test_scan_bundle_records_exact_utf8_symlink_target`) — must stay green.

## Acceptance

- Sealing a bundle whose entry name is not valid UTF-8 fails with a typed,
  matchable error; no CodeResources output is produced for it.
- Two distinct on-disk names can no longer land on one seal-map key through
  any in-workspace caller: native scans validate at the single derivation
  site, wasm inputs are valid UTF-8 by type.
- Excluded entries keep today's behavior; valid-UTF-8 names seal exactly as
  today.
- Changes limited to `crates/zsign/src/bundle/code_resources.rs` (guard,
  tests, doc comments) and `crates/zsign-core/src/bundle/code_resources.rs`
  (doc comments only).
- `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --
  -D warnings`, crate tests, and `hk check --all` all pass.
