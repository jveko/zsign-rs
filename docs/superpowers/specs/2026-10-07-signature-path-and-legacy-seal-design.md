# Signature-path skip and legacy-seal symlink design

## Problem

Two verification holes in `crates/zsign/src/verify.rs`:

1. **Substring skip lets a Mach-O escape verification.** The collection walk
   skips any file whose root-relative path merely CONTAINS the substring
   `_CodeSignature/` (`verify.rs:459`, `rel_str.contains("_CodeSignature/")`),
   so a binary planted at `X_CodeSignature/App` never reaches
   `is_macho_file` and is never verified — contradicting the module docs'
   promise that every Mach-O in the bundle is verified (`verify.rs:6-9`).
   Every other test in the codebase is component-exact
   (`ipa/mod.rs:1362` and `:1584`, both `components().any(|c| c.as_os_str()
   == "_CodeSignature")`; `is_rule_omitted` at `verify.rs:317-327` is
   anchored and correct).
2. **The legacy `files` arm is a content oracle over host files.** The raw
   SHA-1 (`entry.as_data()`) branch of the sealed→disk pass
   (`verify.rs:849-902`) inlines canonicalize-parent containment and then
   `std::fs::read(&file_path)` at `:883` with NO `symlink_metadata` guard.
   A final-component symlink whose parent is inside the bundle passes the
   containment check, `fs::read` follows it out of the bundle, and the
   attacker's chosen SHA-1 in their own CodeResources decides
   matched/mismatched — a per-path boolean oracle over arbitrary host files.
   The sibling `files2` path has the guard: `verify_code_resource_entry`
   lstats the sealed path before reading (`verify.rs:713-730`) and pushes
   `mismatched` when it is a symlink.

## Verified evidence (current source)

- Walk skip: `verify.rs:459`; variables in scope — `rel_path` (root-relative
  `&Path`, `:457`), `rel_str` (`:458`), `rel_dir` (bundle-dir-relative,
  `:448`); skip order: signature skip `:459` → nested-bundle skip `:462` →
  `is_macho_file` `:465` → direct-binary push `:471`.
- Recursion threads `root` unchanged (`verify.rs:554`-region), so a nested
  bundle's signature file appears in `rel_path` as
  `Frameworks/Sub.framework/_CodeSignature/CodeResources`.
- Legacy arm shape (`verify.rs:847-911`): keys present in `files2` are
  skipped (`:849-851`); raw-Data entries take the inline path
  (`:853-900`: safe key → canonicalize-parent containment → read → SHA-1
  compare); non-Data entries already delegate to
  `verify_code_resource_entry` (`:901-910`).
- `verify_code_resource_entry` (`verify.rs:610-760`), the hardened
  chokepoint: safe-key check, dict/malformed checks, canonicalize-parent
  containment with the same escapes error text, symlink-entry branch, the
  final-component `symlink_metadata` guard (NotFound → rule-gated `missing`;
  `is_symlink` → `mismatched`, never read), then content read and
  field-independent hash comparison — a hash-only dict verifies on SHA-1
  alone (`matched &=` per present field). Its parent-NotFound arm is
  rule-gated `missing`, identical to the inline arm's.
- `CodeResourcesVerification::valid()` (`verify.rs:70-72`): both `mismatched`
  and `missing` invalidate, so the guard's outcome value only matters to
  tests that inspect the list.
- Blast radius: repo-wide grep finds no `X_CodeSignature` fixture and no test
  asserting the skip predicate; legacy-arm tests (`ds_store` files-only
  sealing, optional/missing cases) all keep identical outcomes under
  delegation (see decisions). `rewrite_code_resources` (`:1042`-region)
  breaks the slot -3 binding, so rewrite-based tests assert at the
  CodeResources layer — the established pattern for both new tests.

## External contract (source-verified, Apple Security sources)

- v1 `files` values are raw hash data only — Apple's signer filters the
  legacy scan to regular files (`signer.cpp` legacy block) and the parser
  wraps CFData as `{hash=…}`; v1 cannot express a symlink seal
  (`resources.cpp` ResourceSeal).
- Apple's verifier never opens a hash-sealed path whose lstat says symlink:
  `validateResource` reports `errSecCSBadResource`/`kSecCFErrorResourceAltered`
  (`StaticCode.cpp` hash branch, `if (isSymlink) … ResourceAltered`) before
  any open/hash; the walk is `FTS_PHYSICAL` (`resources.cpp` fts_open flags).
  v2 `symlink` entries compare readlink output instead of hashing content.
- The oracle reasoning (INFERRED, no dedicated writeup found): following a
  final-component symlink makes the sealed hash a function of bytes outside
  the bundle, turning matched/mismatched into a chosen-SHA-1 probe of host
  file content; the in-bundle parent guard cannot catch it because the parent
  is legitimately inside the bundle.

## Design (chosen)

1. **Component-exact walk skip** — replace the substring test at
   `verify.rs:459` with
   `rel_path.components().any(|c| c.as_os_str() == "_CodeSignature")`
   (the root-relative `&Path` already in scope; `String` has no
   `components()`, and the `Path` form matches the `ipa` precedents).
   Behavioral delta is exactly one: `X_CodeSignature/`-style lookalikes are
   no longer skipped; everything today's substring skips (root and nested
   signature dirs) remains skipped, because `root` is threaded unchanged.
2. **Delegate legacy raw-Data entries through the hardened helper** — in the
   `files` loop, synthesize `{"hash": <sealed sha1 bytes>}` for raw-Data
   entries and call `verify_code_resource_entry` for both branches; delete
   the ~45-line inline canonicalize/read/compare block. The helper adds
   exactly the missing `symlink_metadata` guard and otherwise reproduces the
   inline semantics one-for-one (containment text, rule-gated `missing`,
   Io-error propagation, SHA-1-only comparison for hash-only dicts).
3. **Two regression tests** (below), both failing before the change.

## Candidate designs considered

- **A (chosen for gap 2): delegate via synthesized hash dict.** Zero
  duplicated logic (the rubric treats verbatim duplication of a logic block
  as a defect), deletes the parallel implementation, and every behavioral
  difference between the arms IS the bug — verified line-by-line in the
  evidence section.
- **B: add the same `symlink_metadata → mismatched` guard inline.** The
  brief's second option; rejected: copies a 16-line guard-plus-gating block
  that already exists in the same file, leaving two implementations to drift
  again (the exact condition that produced this bug).
- **C (gap 1 alternatives):** anchored `starts_with("_CodeSignature/")`
  only — would stop skipping nested bundles' signature dirs at the walk
  level and silently move that duty onto `has_nested_bundle_component`
  (today's two guards partition the work; equivalence is an accident of the
  current tree shape, not a contract); `rel_dir` component-exact — the
  brief's suggested variable, rejected: see decisions.

## Decisions and rejected alternatives

- **`rel_path` (root-relative), not `rel_dir` (bundle-relative).** The brief
  suggested `rel_dir`; source says otherwise: because `root` is threaded
  unchanged through recursion, component-exact on `rel_path` reproduces
  today's nested-signature skipping byte-for-byte (only the `X_CodeSignature`
  false positive disappears), whereas `rel_dir` would leave nested skipping
  entirely to `has_nested_bundle_component` — a second, unevidenced behavior
  change. `rel_path` is already the `&Path` in scope (`String` cannot be
  component-iterated anyway).
- **Guard outcome = `mismatched`, not `missing` or an error.** Matches both
  the sibling `files2` guard (`verify.rs:713-730`) and Apple's verdict
  (`ResourceAltered` for a sealed path that is a symlink); a symlink exists,
  so it is not "missing", and it is a policy verdict, not an IO failure.
- **Deletion, not deprecation:** the inline block, and only the inline
  block, is removed; the `else` delegate branch already present stays as the
  unified call.
- Module docs need no change — the fix makes the code match the documented
  promise. `is_rule_omitted`, the error strings, and every other
  `_CodeSignature` reference stay untouched.
- File scope: `crates/zsign/src/verify.rs` only, per the brief.

## Testing

- `macho_under_x_codesign_directory_is_verified` —
  `build_signed_bundle_with(dir, setup)` where `setup` plants
  `X_CodeSignature/App` as a `fixtures::make_minimal_macho()` (the setup
  runs pre-sign, so the file is sealed and signing stays clean); assert
  `bundle.binaries` contains a path starting with `X_CodeSignature/` and that
  entry carries a Mach-O report. Fails before the change (the substring skip
  drops it from `direct_binaries`).
- `legacy_files_symlink_is_mismatched` (`#[cfg(unix)]`, mirroring
  `symlink_parent_traversal_is_rejected`) — outside file with known bytes;
  setup symlinks `app/Leak` to it (the builder seals symlinks only in
  `files2`); `rewrite_code_resources` removes `Leak` from `files2` and
  inserts `files["Leak"] = Data(SHA-1 of the outside bytes)`; assert
  `cr.mismatched` contains `Leak` (with the mismatched/missing/unsealed
  footer). Fails before the change (the inline arm follows the link, the
  attacker's digest matches, `cr.valid()` stays true).
- Existing suites as the regression net: `ds_store` files-only sealing,
  `legacy_sha1_only_entry_verifies`, optional/missing rule tests, and the
  files2 symlink/parent tests all must stay green under delegation.

## Acceptance

- A Mach-O planted under a lookalike `X_CodeSignature/` directory is
  collected, slice-verified, and reported in `bundle.binaries`.
- A legacy `files` entry whose on-disk path is a final-component symlink is
  `mismatched` — content outside the bundle is never hashed into a verdict.
- All existing tests green; zero-warning gate: `cargo fmt --all -- --check`,
  `cargo clippy --workspace --all-targets -- -D warnings`,
  `TMPDIR=$PWD/target/tmp cargo test --workspace`.
