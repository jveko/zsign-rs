# Stop Lossy Symlink Targets in the Seal — Design

## Problem

`hash_symlink_entry` (`crates/zsign/src/bundle/code_resources.rs:301-308`)
hashes the **raw** symlink target bytes returned by `Store::read_link`
(`crates/zsign/src/store.rs:84`, byte-exact on unix), then records
`String::from_utf8_lossy(&target_bytes)` (`:306`) as the target in the
CodeResources plist. For a target that is not valid UTF-8, the recorded
string differs from the bytes on disk (invalid sequences become U+FFFD),
so the seal records a target that does not exist on disk. The seal hash
covers bytes the plist entry cannot express.

The verifier makes it worse by being self-consistent rather than correct:
`check_code_resources` compares `fs::read_link(..).to_string_lossy()` against
the recorded string (`crates/zsign/src/verify.rs:699`), so a lossy seal
verifies green against its own lossy record. Both sides agree on a value
that is neither what is on disk nor what an Apple-signed seal would hold.

There is no test today covering a non-UTF-8 symlink target anywhere in the
workspace; every symlink test uses ASCII targets.

## External contract (researched)

Verified against Apple's open-source Security framework
(`apple-oss-distributions/Security`, tag `Security-59306.140.5`) and against
the reimplementation tools' sources:

1. **Apple stores `{symlink: <string>}` in `files2`, with no hash entry.**
   Signing side: `OSX/libsecurity_codesigning/lib/signer.cpp:437-447` —
   `readlink()` output is inserted via `cfmake("{symlink=%s}", target)`, and
   `%s` resolves to `CFStringCreateWithCString(..., kCFStringEncodingUTF8)`
   (`OSX/libsecurity_utilities/lib/cfmunge.cpp:143-145`). The plist value is
   a UTF-8 `<string>`, never `<data>`.
2. **Apple never lossy-converts: it round-trips or fails.**
   `CFStringCreateWithCString` returns NULL for non-UTF-8 input, in which
   case the seal entry is not produced and the sign surfaces a resource
   error (inferred from API semantics; the fail-not-mangle consequence
   follows from `signer.cpp:448-451`). The recorded value must be
   byte-faithful because that is all verification compares.
3. **Apple's verifier string-compares, it does not hash.**
   `StaticCode.cpp:1620-1621` dispatches `seal.link()` to
   `validateSymlinkResource` (`:1682-1698`), which does
   `readlink()` and `if (seal != target)` → `errSecCSBadResource`
   ("resource altered"). Any byte-level difference fails verification.
4. **`<data>` breaks Apple verification.** `symlink` is scanned as
   `CFStringRef` (`resources.cpp:399`), while only `hash` is required to be
   `CFData` (`resources.cpp:409-416`). A `<data>` symlink value is rejected.
5. **Reimplementations split.** `ldid` passes raw `readlink()` bytes into
   the plist string (`ldid.cpp:3390-3391`); `rcodesign` is lossy
   (`apple-codesign/src/code_resources.rs:1423-1439` — same defect class,
   self-consistent but not byte-faithful); upstream `zsign` does not seal
   symlink targets at all, so there is no upstream behavior to preserve.
6. **Symlink target bytes are not guaranteed UTF-8.** APFS is a bag of
   bytes; no authoritative Apple statement constrains targets to UTF-8.
   Treat UTF-8 as an assumption that must be checked, not trusted.

## Candidate designs

### A — Fail closed: reject a non-UTF-8 target with a typed error (chosen)

`hash_symlink_entry` validates the raw bytes with `String::from_utf8`
before recording; on failure the scan returns a typed error and no seal is
produced. The recorded `String` becomes byte-exact by construction, which
is exactly what both Apple's signer (round-trip-or-fail) and Apple's
verifier (byte compare) require. For every seal this tool then produces,
`verify.rs`'s `to_string_lossy()` comparison at `:699` is the identity on
valid UTF-8, so verification becomes exact without touching `verify.rs`.

- Pros: smallest possible blast radius (one function plus its tests, inside
  one file); plist stays `<string>` and remains Apple-compatible; wasm and
  core writers untouched; matches the chosen fail-closed philosophy used
  elsewhere in this repo (`checked_symlink_target` already rejects the same
  bytes on the archive path, `crates/zsign/src/ipa/archive.rs:151-157`).
- Cons: signing a bundle that contains a non-UTF-8 symlink now fails
  instead of "succeeding" with a corrupt seal. That prior success was the
  bug — Apple's `codesign` would reject the same bundle, and the tool's own
  IPA writer already refuses the same target.

### B — Record the target as `Value::Data` (rejected)

Byte-faithful in the plist and no signing failure, but directly
non-Apple-compatible: Apple parses `symlink` as `CFString` only
(`resources.cpp:399`), so a `<data>` value would break verification of our
bundles by real `codesign`. It also forces coordinated changes in the core
writer (`zsign-core/src/bundle/code_resources.rs`), the verifier
(`verify.rs:637-650`, `:679`), and the wasm surface — a large footprint on
files this change is required to keep untouched. The ticket offered this as
a suggestion; the source evidence above refutes its compatibility.

### C — Raw-bytes-into-string pass-through, ldid-style (rejected — infeasible)

Not expressible with the current serialization layer: `plist::Value::String`
wraps a Rust `String` (UTF-8 invariant), and an XML plist is Unicode text —
arbitrary bytes have no representation. Implementing it would mean replacing
the plist writer/reader pair. Out of any reasonable scope for this fix.

## Decisions recorded

- **Error shape:** use the established policy-refusal path
  `Error::Core(zsign_core::Error::Signing(String))`, precedent
  `crates/zsign/src/ipa/mod.rs:848-850` ("Refusing symlinked entitlements
  file"), message `Symlink target is not valid UTF-8: <path>`. A *new*
  facade `Error` variant was considered and rejected:
  `code_for_zsign_error` in `crates/zsign-wasm/src/lib.rs:155-165` is
  deliberately exhaustive ("a new `zsign_rs::Error` variant must fail to
  compile until it is assigned a code"), so minting a variant would force an
  edit to a file outside this change's permitted scope, in a file another
  concurrent workstream owns. `Error::Io(InvalidData, ..)` was the runner-up;
  `Core(Signing(..))` wins because the failure is a signing policy refusal,
  matching the two nearest precedents.
- **Validation lives inside `hash_symlink_entry`**, after
  `should_exclude` has already filtered excluded entries
  (`code_resources.rs:228` before `:233`), so only entries that would be
  sealed are validated. Exclusion precedence is preserved and pinned by a
  test.
- **Hashing is unchanged**: the SHA-1/SHA-256 still cover the raw bytes
  (`hash_data(&target_bytes)`); post-change those bytes are valid UTF-8 and
  the recorded string encodes the identical bytes. Apple emits no hash for
  symlink entries and so does the core writer; that asymmetry is
  pre-existing and out of scope.
- **Doc-comment drift fixed in passing**: the `SymlinkHashes` alias
  (`code_resources.rs:34-36`) documents "the lossy string form recorded in
  the plist" — updated to state the exact-UTF-8 invariant.

## Deferred (explicitly out of scope)

- **Verifier-side strict comparison.** `verify.rs:699` compares
  lossy-decoded disk bytes against the sealed string; under post-sign
  tampering, a swapped non-UTF-8 target can lossy-decode onto a sealed
  string that contains a literal U+FFFD. Fixing that means changing
  `verify.rs`, which this change is required to leave alone; after this
  change the condition also requires a seal containing U+FFFD, which the
  sealing path now only produces if the original target did. Recorded here
  so a future verification-strictness workstream can pick it up.
- **Non-UTF-8 file-name keys in the seal map** (lossy path keys at
  `code_resources.rs:216-226`): a separate workstream, untouched.
- **FIFO/kind handling in `hash_entry`**: separate workstream, untouched.
- **Containment/escape checking of symlink targets**: separate workstream
  in the same function; this change adds no path-policy logic.
- **Extraction-side name/target gates** (`ipa/extract.rs`, `ipa/archive.rs`)
  and the store-side creation gate (`store.rs:247-249`): other
  workstreams' scope, read for context only.
- The stale line reference in `crates/zsign/src/store.rs:235-237` to
  "hash_symlink_entry's non-unix arm" (the arm now lives in
  `FsStore::read_link`): pre-existing, in a file this change must not touch.

## Testing strategy

All in `crates/zsign/src/bundle/code_resources.rs`'s test module, `#[cfg(unix)]`,
fixtures created with `std::os::unix::fs::symlink` over raw `OsStr` bytes
(bypassing `FsStore::symlink`'s own UTF-8 gate so the on-disk fixture is
genuinely non-UTF-8, as a real `ln -s` would be):

1. **Rejection (the regression test):** a bundle containing a symlink with
   target bytes `real\xFFtarget` must make `scan()` return
   `Err(Error::Core(zsign_core::Error::Signing(..)))` whose message
   contains `not valid UTF-8` — no seal can be built, so no target that
   differs from disk can be recorded. Fails before the change (`scan()`
   succeeds and records U+FFFD).
2. **Exclusion precedence:** the same bytes under an excluded path scan
   cleanly — validation applies to sealed entries, not to tree traversal.
3. **Exact round-trip:** a target that is valid UTF-8 but non-ASCII
   (multibyte characters plus a literal U+FFFD) must appear in the built
   plist `files2` entry as the exact string, byte-for-byte equal to the
   on-disk target — pins that the recording path performs no mangling in
   either direction.

Existing `test_scan_bundle_with_symlinks` must keep passing unchanged
(ASCII/UTF-8 symlink sealing behavior is not altered).

## Acceptance

- Sealing a bundle with a non-UTF-8 symlink target fails with a typed,
  matchable error; no CodeResources output is produced for it.
- Every target that *is* sealed is recorded byte-identically to disk, and
  the plist value remains a `<string>` (Apple-compatible shape).
- No changes outside `crates/zsign/src/bundle/code_resources.rs`.
- `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --
  -D warnings`, crate tests, and `hk check --all` all pass.
