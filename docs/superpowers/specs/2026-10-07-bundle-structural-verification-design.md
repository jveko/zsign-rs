# Bundle structural verification design

## Problem

`zsign-rs` bundle verification (`crates/zsign/src/verify.rs`) fails open on two
structural gaps:

1. **A deleted declared main executable still verifies.** `verify_bundle_dir`
   resolves `CFBundleExecutable` from `Info.plist` but only uses it to exempt a
   path from the disk-to-sealed pass; it never requires the file to exist among
   the collected Mach-O binaries. `BundleVerification::valid()` is a pure
   conjunction over collected results, so removing the executable from an
   otherwise-signed `.app` leaves the report valid and `-V` exits 0. The signer
   enforces this (`ZSign::get_main_executable` hard-errors), so signer and
   verifier disagree.
2. **A never-signed, zero-Mach-O bundle verifies.** A hand-built bundle
   (`Info.plist` + a well-formed `CodeResources` that seals nothing, no
   executable anywhere) collects no binaries, an empty sealed set produces
   `matched == 0` with three empty vecs, and every `valid()` term passes
   vacuously.

## Verified evidence (current source)

- `BundleVerification::valid()` — `verify.rs:91-100`: `errors.is_empty()` plus
  `all()` over `binaries`/`nested` and `unwrap_or(true)` on absent
  `code_resources`; no cardinality term. `problem_count` at `verify.rs:103-116`
  counts `errors`, so pushed errors surface everywhere automatically.
- `CodeResourcesVerification::valid()` — `verify.rs:69-71`: true when
  `mismatched`/`missing`/`unsealed` are all empty.
- `verify_bundle_dir` — `verify.rs:408-539`: `main_executable` resolved at
  `:428-430` (`plist_executable`, `:552-559`), used only by `is_rule_omitted`
  (`:316-326`, consumed in the disk pass inside `check_code_resources`); the
  walk collects `direct_binaries` at `:433-465`; recursion at `:531-537`.
  `verify_bundle` (`:374-382`) and `verify_ipa` (`:390-403`) are thin wrappers
  over `verify_bundle_dir`, so one implementation covers both entry points.
- `check_code_resources` — `verify.rs:745-925`: `files2` key required
  (`:787-790`, else an error is pushed), legacy `files` optional (`:797-805`),
  `sealed_set = files2 ∪ files` (`:814-820`); emptiness is never checked. All
  counts come from loops over the sealed dicts, so an empty set yields zeros.
- The only structural error precedent today is
  `out.errors.push("missing _CodeSignature/CodeResources")` at `verify.rs:424-426`.
- Signer asymmetry — `ipa/mod.rs:1678-1730`: `get_main_executable` requires
  `Info.plist`, a string `CFBundleExecutable`, a relative path, and an existing
  regular file at `bundle/CFBundleExecutable` (file-stem fallback when the key
  is absent); called from `sign_single_bundle` (`:1464`). The signed main
  executable is then parsed as Mach-O (`sign_binary`), so every zsign-signed
  bundle level has at least one direct Mach-O at exactly `bundle/<exe>`.
- Builder emission — `zsign-core/src/bundle/code_resources.rs`
  `build()`: legacy `files` is written from every scanned entry with no rule
  filtering (`:591-609`); `files2` skips entries whose `rules2` action is omit
  (`:611-630`), and `standard_rules2` declares `^Info\.plist$`/`^PkgInfo$`
  omit. The facade scanner always seals `Info.plist` (facade
  `bundle/code_resources.rs` test asserts `file_paths.contains("Info.plist")`)
  and always excludes the main executable (`should_exclude`, core `:420-436`).
  Consequence: every zsign-signed bundle has `files` ≥ {`Info.plist`}, so the
  union is non-empty even when `files2` legitimately is (minimal bundle:
  `Info.plist` + executable only).

## External contract (source-verified)

- `codesign --verify` fails hard when the declared main executable is missing:
  Apple's `bundlediskrep.cpp` opens the main executable via
  `CFBundleCopyExecutableURL`, and `DiskRep::bestGuess` maps `ENOENT` to
  `errSecCSStaticCodeNotFound` (-67068, "cannot find code object on disk",
  `CSCommon.h`). `codesign(1)` DIAGNOSTICS: verification failure ⇒ exit 1.
- TN2206: "It is acceptable to code-sign a bundle containing no main
  executable, and then treat it as nested code". Apple tolerates executable-less
  nested bundles via an Info.plist nominal-main fallback, but zsign's signer
  refuses them (file-stem fallback must resolve to an existing file). The
  verifier therefore follows zsign's signer, not the Apple fallback — a
  recorded, deliberate strictness deviation for hand-built trees neither tool
  should call valid.

## Design (chosen)

Push three structural errors into `BundleVerification.errors`, following the
`missing _CodeSignature/CodeResources` precedent. All policy stays where the
other structural errors live; `valid()`, `problem_count`, the CLI's
`print_report`, the `--json` DTOs, and the exit-1 contract inherit the change
with no signature or consumer edits.

1. **Declared main executable present.** In `verify_bundle_dir`, while walking,
   record whether any direct Mach-O's bundle-relative path (`rel_dir`,
   `/`-normalized) equals `main_executable`. After the walk, when
   `main_executable.is_some()` and no match was found, push
   `declared main executable "<exe>" not found in the bundle`.
2. **At least one direct Mach-O per verified bundle level.** After the walk, if
   `direct_binaries.is_empty()`, push `bundle contains no Mach-O binaries`.
   Unconditional: zsign-signed levels always have one, and every legitimately
   executable-less shape is already invalid (missing `CodeResources`) or cannot
   be produced by either signer.
3. **Non-empty sealed set.** In `check_code_resources`, after building
   `sealed_set = files2 ∪ files`, if it is empty push
   `CodeResources seals no files`. Evaluated on the union, never `files2`
   alone: the builder legitimately emits an empty `files2` for a minimal signed
   bundle while legacy `files` carries `Info.plist`.

## Candidate designs considered

- **A (chosen): error pushes in `verify_bundle_dir`/`check_code_resources`.**
  Single implementation serves `verify_bundle` and `verify_ipa`; matches the
  existing error-push convention; counts, DTOs, and exit codes follow
  automatically; reports stay structured (`--json` keeps emitting a report).
- **B: cardinality terms inside `BundleVerification::valid()`/`CodeResourcesVerification::valid()`.**
  Rejected: `BundleVerification` cannot see the sealed set, and the counts
  cannot express "sealed nothing" — an entry whose file is absent under an
  `optional` rule is suppressed from `missing` (`verify.rs:856-870`), so
  `matched == 0` with three empty vecs is reachable with a non-empty sealed set.
  It would also desynchronize `problem_count` (invalid but zero problems) and
  split policy across two layers.
- **C: hard `Err` return (like "not a bundle directory").** Rejected: loses the
  structured report and `--json` schema, diverges from the missing-`CodeResources`
  precedent for bundle-structure problems, and changes the CLI exit contract.

## Decisions and rejected alternatives

- **Exact bundle-relative match for the declared executable, not file-stem
  matching.** The ticket suggested matching on file stem. Rejected in favor of
  raw equality (`bundle_rel == exe`):
  - the signer resolves `CFBundleExecutable` as a bundle-relative *path*
    (`resolve_relative`, `ipa/mod.rs`), and `is_rule_omitted` already relies on
    raw equality (`rel == exe`), so exact match is the invariant the whole file
    already assumes;
  - a literal stem rule (`stem(binary_path) == exe`) rejects signer-valid
    path-style declarations (`exe = "Sub/Sub"` — `stem("Sub/Sub") = "Sub"`);
  - the looser reading (any directory, stem equal) admits a collision: with the
    real `Test` deleted, an unrelated `Other/Test` would satisfy the check —
    the same hiding class this design must not reintroduce.
  Exact match closes the deletion repro and never rejects a zsign-signable
  bundle.
- **Sealed-set emptiness on the `files2 ∪ files` union**, not `files2` alone —
  `files2`-only would reject legitimate minimal signed bundles.
- **Checks live in the shared recursion**, so every nested level is held to the
  same rule the signer enforces per level (`collect_nested_bundles` →
  `sign_single_bundle`).
- No changes to `valid()` signatures, CLI, DTOs, the signer, or any deferred
  file; scope is `crates/zsign/src/verify.rs` only.

## Testing

- `deleted_main_executable_is_invalid` — sign the standard fixture, assert the
  precondition valid, `fs::remove_file(app/"Test")`, then assert
  `!report.valid()` and that `bundle.errors` names the missing executable.
  Fails before the change (report stays valid).
- `zero_macho_empty_seal_bundle_is_invalid` — hand-build the never-signed
  bundle (`Info.plist` without `CFBundleExecutable`, `_CodeSignature/CodeResources`
  with empty `files`/`files2` and standard rules whose `^Info\.plist$` omit
  keeps the disk pass clean). Assert invalid and that both structural errors are
  present. Fails before the change (no errors at all).
- `minimal_signed_bundle_verifies` — sign a bundle containing only
  `Info.plist` + executable; assert it stays valid. Guards the union-based
  empty-seal check against over-strictness (`files2` is legitimately empty
  here). Passes before and after.
- Existing suites (`signed_bundle_verifies`, IPA end-to-end, CLI sign/verify
  round-trips) are the regression net for false rejections.

## Acceptance

- Deleted declared main executable ⇒ report invalid, error names the
  executable, `-V` exits 1, `problem_count > 0`.
- Zero-Mach-O never-signed bundle ⇒ report invalid with both structural errors.
- Minimal signed bundle and every existing fixture stay valid.
- Zero-warning gate green: `cargo fmt --all -- --check`,
  `cargo clippy --workspace --all-targets -- -D warnings`,
  `TMPDIR=$PWD/target/tmp cargo test --workspace`.
