# ZSN-35 Option Forwarding — Design

**Date:** 2026-09-26
**Branch:** `zsn35-option-forwarding` (base f2f12ef)
**Scope authority:** `/tmp/zsn35.txt` mission brief + supervisor scope fence (zero edits under `crates/zsign/src/ipa/*`; `crates/zsign-core/src/macho/signer.rs` belongs to lane zsn34).

## Problem

CLI flags are parsed and stored on `ZSign`, but several options are silently dropped
before they reach the signing engine, so the flag has no observable effect on the
output. Two clap conflicts the ticket expects are missing (parse-time acceptance),
and one credential-adjacent error path does not name the file it failed on.

The ticket's line numbers (2026-09-24) are stale: `main.rs` was rewritten by
ZSN-5/6/36 and `builder.rs` grew in ZSN-33. Item 0 of the brief required a full
re-audit against current source before scoping.

## Item-0 re-audit matrix (evidence at base f2f12ef)

| # | Ticket claim | Verdict | Evidence |
|---|---|---|---|
| a | `ZSign::sign_ipa` drops `sha256_only`/`bundle_name`/`bundle_version` | **STILL OPEN** | `crates/zsign/src/builder.rs:393-419` configures compression (397,403), dylibs (405-407), force (408), profile (410-412), bundle_id (414-416), then `signer.sign()` (418) — no `sha256_only`/`bundle_name`/`bundle_version` calls. `sign_bundle` forwards all three (builder.rs:443-446, 458-462). Setters exist: `ipa/mod.rs:204` (`bundle_name`), `:213` (`bundle_version`), `:223` (`sha256_only`); consumed at `ipa/mod.rs:377-382` (plist rewrites) and `:1038` (digest mode). |
| b | `sign_bundle` omits `compression_level` so `-z` is ignored | **STILL OPEN** | builder.rs:440-463 never calls `.compression_level()`; `sign_ipa` does (builder.rs:397,403). `IpaSigner` defaults to 6 (`ipa/mod.rs:145,161`, `archive.rs:66`); the repack path would honor a configured level (`ipa/mod.rs:326-330` passes `self.compression_level` into `create_ipa`). Net: `-z` on a `.app`→`.ipa` repack always repacks at 6. |
| c | `sign_macho` never applies configured dylibs/`bundle_id` | **STILL OPEN** | builder.rs:302-358 never reads `self.dylibs`/`self.weak_dylibs`/`self.bundle_id`; identifier is hardcoded to `input.file_stem()` (306-310). The two positional `None`s in credentialed calls are `info_plist: Option<&[u8]>` and `code_resources: Option<&[u8]>` (`macho/mod.rs:68-69,112-113,133-134,159-160`) — bundle-context blobs, structurally absent for a loose binary; they are not the dylib/bundle_id slots. |
| d | ad-hoc `sign_macho` discards a configured profile's entitlements | **STILL OPEN** | builder.rs:313-320 passes `None` for entitlements (316) to `sign_macho_adhoc`; `load_entitlements_from_profile()` (486-495) runs only in the credentialed branch (323). Inconsistent with `sign_ipa` (410-412) and `sign_bundle` (452-454), which forward the profile even on ad-hoc signers (`ipa/mod.rs:296-304` applies profile entitlements regardless of credentials). |
| e | clap conflicts: `-2` vs `-L`, `-a` vs `-m`, `-V` vs signing opts | **PARTIAL** | Exists: `--verify` conflicts_with_all (main.rs:117-133, tested main.rs:1574-1591) and `--pkcs12` vs cert/key (main.rs:42, tested :1610-1614). Missing: `-2` vs `-L` (main.rs:84-91, both bare bools; `run()` applies `-2` then `-L`, so `-L` silently wins at main.rs:183-188) and `-a` vs `-m` (main.rs:99-100 vs :49 — no conflict). |
| f | `--zip-level` clamp vs 0-9 help | **ALREADY SATISFIED** | `value_parser = clap::value_parser!(u32).range(0..=9)` with help "ZIP compression level (0-9, default: 6)" (main.rs:58-67); parse-time rejection tested (`zip_level_range_is_enforced_at_parse`, main.rs:1617-1625). Library-side `CompressionLevel::new` clamps >9 to 9 (`archive.rs:78-80`). |
| g | PEM branch ignores CLI password → generic error | **ALREADY SATISFIED** | `reject_encrypted_key` (main.rs:781-793) returns exactly `encrypted PEM keys are unsupported (see ZSN-18)` and is called on both PEM (main.rs:810) and DER-wrap (main.rs:845) branches; backstop in `zsign-core/src/crypto/cert.rs:476-483`. Tested: `password_with_key_route_fails_explicitly` (main.rs:1628-1676). |
| h | credential errors don't name the missing file | **PARTIAL** | p12/cert/key landed: `read_credential_file` formats `failed to read {label} '{path}': {e}` (main.rs:768-774) with call sites :797/:808/:814/:846, tested `credential_io_errors_name_the_file` (main.rs:1679-1702). Still open **in my files**: `load_entitlements_from_profile` does a bare `std::fs::read(profile_path)?` (builder.rs:488) → `Error::Io` Displays as `IO error: {0}` (`error.rs:33-35`) with std's pathless message. Known seam (NOT mine): `ipa/mod.rs:296` `fs::read(path)?` in `load_profile` — reported to lane zsn34. |
| i | `validate()` runs after credential/file work | **ALREADY SATISFIED** | `validate()` is the first statement of every public entry: `sign_macho` builder.rs:303 (before `MachOFile::open` :304), `sign_ipa` :394, `sign_bundle` :440; `validate()` itself (254-261) is pure state checking. `sign_bundle` rejects a non-`.ipa` output before any folder mutation (465-483); downstream guards precede mutation (`ipa/mod.rs:310-315`, `:988-995`). CLI nuance: `run()` loads credential files (main.rs:165) before builder validate can run — unavoidable, since credential presence is what validate checks; credential reads themselves never touch the input tree. |

**Still-open list (drives queue items 1-3):** (a), (b), (c), (d), (e ×2 conflicts), (h profile site). (f)(g)(i) and the `-V` conflict are recorded as already satisfied and are not re-implemented.

## Scope fence and named seams

- **Hard fence:** zero edits under `crates/zsign/src/ipa/*` (lane zsn34). Every fix below lives in
  `crates/zsign/src/builder.rs` or `crates/zsign-cli/src/main.rs`. The re-audit confirmed all
  required `IpaSigner` setters already exist, so no `ipa/` edit is needed.
- **Seam 1 (report-only, zsn34):** profile-read error naming at `ipa/mod.rs:296` (bare `fs::read(path)?`, fn `load_profile` at :293-302)
  — the IPA/app entry points keep the pathless `IO error:` message until that lane fixes it.
  The builder-side sibling `builder.rs:488` is fixed here.
- **Seam 2 (report-only, zsn34):** `IpaSigner::sign_standalone_dylib` (`ipa/mod.rs:628`, dual `sign_macho` call at :652) always signs
  dual-digest, ignoring `self.sha256_only` — observed while mapping flows; `ipa/`-owned.
- **Docs lane notes:** no `-e/--entitlements` flag exists locally (upstream has one, `zsign.cpp:24-59`);
  local `-z` default is 6 vs upstream 0; local `-n`/`-r` write only `CFBundleDisplayName`/
  `CFBundleShortVersionString` while upstream also writes `CFBundleName`/`CFBundleVersion`
  (`bundle.cpp:677-683,709-710`); `.tmptmp` is not in `.gitignore`. None are in ZSN-35 scope.

## Chosen design

All fixes are forwarding corrections — no new public API, no `ipa/` edits.

1. **`sign_ipa` (a):** add three setter calls to the existing chain, mirroring
   `sign_bundle`: `.sha256_only(self.sha256_only)` on both construction branches,
   plus `.bundle_name(...)`/`.bundle_version(...)` next to the existing
   `.bundle_id(...)` call (builder.rs:414-416).
2. **`sign_bundle` (b):** add `.compression_level(self.compression_level)` at
   construction on both branches, exactly where `sign_ipa` already puts it
   (builder.rs:397,403). Observable only via the `sign_folder_to_ipa` repack.
3. **`sign_macho` dylibs (c-i):** read the input bytes once, and while
   `self.dylibs` is non-empty loop `zsign_core::macho::writer::inject_dylib_command`
   (pub, FAT-capable, `zsign-core/src/macho/writer.rs:906` — the same primitive
   `ipa/mod.rs:1005-1013` uses) over the bytes **before** `MachOFile::parse`,
   then sign. Injection must precede signing because load commands are hashed
   into the CodeDirectory.
4. **`sign_macho` bundle_id (c-ii):** `identifier` becomes
   `self.bundle_id` when set, falling back to the current `input.file_stem()`
   (builder.rs:306-310). For a loose binary the code-signing identifier is the
   only observable sink for `-b`; this aligns with the bundle path, where the
   identifier derives from the (rewritten) `CFBundleIdentifier`.
5. **`sign_macho` adhoc entitlements (d):** hoist
   `let entitlements = self.load_entitlements_from_profile()?;` above the
   `if self.adhoc` branch and pass `entitlements.as_deref()` to
   `sign_macho_adhoc` instead of `None`. One load, both branches — same shape
   `sign_ipa`/`sign_bundle` already have (profile forwarded unconditionally).
6. **Parse-time conflicts (e):** field-level `conflicts_with_all` in ZSN-5 style:
   on `legacy_sha1`: `conflicts_with_all = ["sha256_only"]`; on `adhoc`:
   `conflicts_with_all = ["profile"]`. clap 4.6.7 conflicts are symmetric
   (one declaration covers both orders) and are validated before
   `required_unless_present_any` (`clap_builder-4.6.7/src/parser/validator.rs:54-57`),
   so `-2 -L` is rejected even when credentials are also missing.
7. **Profile read naming (h):** in `load_entitlements_from_profile`
   (builder.rs:486-495; the bare read is at :488), `map_err` the `std::fs::read` failure into an error whose
   message names label + path — `failed to read provisioning profile '{path}': {e}` —
   matching `read_credential_file`'s phrasing (main.rs:768-774). Only this one
   site changes; `ipa/mod.rs:296` stays as the reported seam.
8. **Validate-before-mutation (i):** already satisfied (matrix above). No
   production change; one regression test pins the invariant.

## Design decisions (candidates considered)

**D1 — how to forward `sign_ipa`'s three missing options.**
(i) inline the three setters in the existing chain, mirroring `sign_bundle`;
(ii) extract a shared `configure_signer(IpaSigner) -> IpaSigner` helper used by
both `sign_ipa` and `sign_bundle`; (iii) an options struct passed to the
`IpaSigner` constructor.
**Chosen (i).** Smallest correct change; the in-file convention is inline chains
(second convention prohibited); (ii) refactors green `sign_bundle` code and adds
an abstraction for six call sites — rejected as unprompted refactor;
(iii) requires changing the `IpaSigner` constructor — an `ipa/` edit, fenced.

**D2 — `sign_bundle` compression.**
(i) `.compression_level(self.compression_level)` at construction (mirrors
`sign_ipa`); (ii) set it only on the repack arm.
**Chosen (i):** one call site covers in-place + repack, matches `sign_ipa`
exactly; (ii) duplicates state selection at two arms for no benefit.
In-place signing writes no archive, so the level is inert there by design —
the observable effect is the `.app → .ipa` repack.

**D3 — where to inject dylibs for a loose binary.**
(i) inject into raw input bytes before `MachOFile::parse`/sign using
`inject_dylib_command`; (ii) post-sign injection; (iii) add dylib parameters to
the four `sign_macho*` functions.
**Chosen (i):** load commands are hashed into the CodeDirectory, so (ii) would
produce a signature that fails verification — rejected outright; (iii) churns
`crates/zsign/src/macho/*` wrappers and touches `zsign-core` signing APIs
(zsn34-adjacent) for no observable gain — rejected. (i) is the exact primitive
`IpaSigner` already uses (`ipa/mod.rs:1005-1013`) and is builder.rs-only.
FAT containers are handled: `inject_dylib_command` reassembles every slice
(`writer.rs:906`, FAT loop at :917-938); the adhoc FAT rejection path is unchanged.

**D4 — `bundle_id` on the macho path.**
(i) use it as the code-signing identifier overriding `file_stem`; (ii) document
`-b` as bundle-only and leave the path untouched; (iii) error when `-b` is set
with a macho input.
**Chosen (i)** — the ticket demands an observable effect; the identifier is the
only legitimate sink for a loose binary (there is no Info.plist), and it matches
bundle semantics where `-b` rewrites `CFBundleIdentifier`, which then names the
main executable. (ii) leaves the ticket claim unfixed; (iii) rejects a currently
valid invocation — both worse.

**D5 — adhoc entitlements: where does the profile get read?**
(i) hoist `load_entitlements_from_profile()` above the adhoc/credentialed
branch and pass it to both; (ii) call it only inside the adhoc branch.
**Chosen (i):** one load site, both branches use the same value, matching
`sign_ipa`/`sign_bundle`'s unconditional profile forwarding; (ii) duplicates the
call and keeps the structural asymmetry that caused the bug.
Upstream contrast (librarian, `openssl.cpp:838-851`): upstream `-a` ignores
`-m` entirely; local `sign_ipa`/`sign_bundle` adhoc already apply profile
entitlements (`ipa/mod.rs:296-304`). This makes `sign_macho` consistent with the
local paths, as the ticket demands. The new CLI conflict `-a` vs `-m` (D6) means
the CLI can never reach adhoc+profile; the library API can, and now honors it —
both are ticketed behaviors, not a contradiction.

**D6 — conflict declaration style.**
(i) field-level `conflicts_with_all` (ZSN-5 style); (ii) an `ArgGroup` with
conflicts; (iii) a runtime check in `run()` before dispatch.
**Chosen (i).** clap 4.6.7 has no struct-level `conflicts_with` (it is an `Arg`
method); the repo's two existing conflicts are field-level `conflicts_with_all`
(main.rs:42, :117-133) and a second convention is prohibited. (ii) misuses
groups (the `credentials` group is `multiple(true)` precisely to avoid
auto-conflicts — main.rs:15-21 comment verified against `validator.rs:509-515`);
(iii) fails at the wrong layer — the ticket requires parse-time rejection.
Placement follows the existing "declare on the later field" pattern
(`pkcs12` conflicts with the earlier cert/key; `verify` with earlier flags):
`legacy_sha1` (main.rs:91) declares against `sha256_only` (:85); `adhoc` (:100)
declares against `profile` (:49).

**D7 — profile read error shape.**
(i) wrap the failing `std::io::Error` with label + path context while staying
on the existing `Error::Io` variant (`#[from] std::io::Error` preserved);
(ii) a new typed `Error::ProfileRead { path, source }` variant; (iii) route
through `zsign_core::Error::ProvisioningProfile(String)`.
**Chosen (i):** one call site; Display becomes
`IO error: failed to read provisioning profile '{path}': {e}`, mirroring
`read_credential_file`'s established phrasing (main.rs:768-774), and the exit
code stays 1 (`run()`'s `Err` arm maps every signing failure to 1,
main.rs:144-151) so the ZSN-5 exit-code contract is untouched. Note: the
`zsign::Error` enum has no free-form `Variant(String)` variant
(`error.rs:32-56`), so that repo-style pattern is not available here. (ii)
adds a public enum variant for one site — YAGNI; (iii) would mislabel a missing
file as an invalid profile (`ProvisioningProfile` Displays as
`Invalid provisioning profile: …`).

**D8 — item (i) test.**
Already satisfied in production code. Candidate: skip entirely vs add a
regression test. **Chosen: add one** — the brief's queue item 3 names the
acceptance ("invalid input → abort → tree untouched"), and a test-only change
is the smallest way to pin it without re-implementing anything.

## Invariants

- `validate()` remains the first statement of every public `sign_*` entry; no
  new file reads happen before it.
- No edits under `crates/zsign/src/ipa/*`, `crates/zsign-core/src/macho/signer.rs`,
  README/AGENTS docs, or the ZSN-5 exit-code/JSON contract.
- Dylib injection always happens before signing (load commands are hashed).
- Ticket IDs appear only in commit subjects, never in code comments.
- Every CLI flag that reaches `ZSign` has an observable effect on at least one
  signing path, or is documented (in the matrix) as N/A (e.g. `-z` for a raw
  binary writes no archive).
- New tests reuse the existing harness only: `run_cli`/`parse_err` (main.rs) and
  inline `#[cfg(test)]` builder tests (AGENTS.md); no second convention.

## Test strategy

One forwarding test per signing path (queue item 1), one parse test per conflict
(queue item 2), one zero-side-effect test (queue item 3), one error-naming test
(item h). All are red before their fix and green after — no test pins
incidental behavior.

| # | Test (location) | Setup | Observable assertion | Red because |
|---|---|---|---|---|
| 1 | `test_sign_ipa_forwards_bundle_options` (builder.rs tests) | inline IPA fixture: `Payload/Test.app/{Info.plist, Test=minimal_macho(), data.bin}` (mirrors `ipa/mod.rs:1195` `write_test_ipa`, which is test-private — re-declared locally) | sign with `.bundle_name("Renamed").bundle_version("9.9").sha256_only(false)` → open output zip: `CFBundleDisplayName == "Renamed"`, `CFBundleShortVersionString == "9.9"`; control sign with defaults → main executable superblob has **no** SHA-1 CodeDirectory, treatment has one (`codesign::verify::parse_superblob` + `SuperBlob.code_directory`/`alternate_code_directories` + `CodeDirectory::is_sha1`, all pub per `zsign-core/src/codesign/verify.rs:68-74,87,811`) | name/version never rewritten; SHA-1 CD absent in both |
| 2 | `test_sign_bundle_forwards_compression_level` (builder.rs tests) | `.app` folder built like `test_sign_bundle_folder_in_place` (builder.rs:577) | `.compression_level(0)` + `Some(out.ipa)` → `zip::ZipArchive` entry `Payload/Test.app/Info.plist`: `compression() == CompressionMethod::Stored` (level 0 maps to Stored, `archive.rs:320-333`; pattern precedent `archive.rs:699-731`) | default 6 reaches the repack → Deflated |
| 3 | `test_sign_macho_applies_dylibs_and_bundle_id` (builder.rs tests) | `minimal_macho()` input; `.dylib_injection(vec!["/usr/lib/libzsn.dylib"], false).bundle_id("com.zsign.forwarded")` | goblin parse of output: an `LC_LOAD_DYLIB` (0xC) command whose name is the injected path; superblob primary `CodeDirectory::identifier() == Some("com.zsign.forwarded")` (pub, used at `verify.rs:1525`) | no load command added; identifier is the file stem |
| 4 | `test_sign_macho_adhoc_applies_profile_entitlements` (builder.rs tests) | profile fixture file = XML plist with a top-level `Entitlements` dict (`extract_entitlements_from_profile` is pub and CMS-unverified by design — `provisioning.rs:379-385`); `.adhoc(true).provisioning_profile(path)` | superblob contains the entitlements special slot (CSSLOT_ENTITLEMENTS) whose bytes carry a key from the fixture; control sign without profile → slot absent | adhoc branch passes `None` → slot absent |
| 5 | `sha256_only_and_legacy_conflict_at_parse` (main.rs tests) | none | `parse_err(["zsign","-2","-L","in.ipa"]).kind() == ArgumentConflict` (both orders) + positives: `-a -2` and `-a -L` parse | no conflict declared |
| 6 | `adhoc_conflicts_with_profile_at_parse` (main.rs tests) | none | `parse_err(["zsign","-a","-m","p.mobileprovision","in.ipa"]).kind() == ArgumentConflict` + positive: `--pkcs12 x.p12 -p pw -m p.mobileprovision in.ipa` parses | no conflict declared |
| 7 | `missing_profile_error_names_the_file` (main.rs tests) | `IDENTITY_P12` recipe from `key_route_pkcs12_content_loads_with_password` (main.rs:1329) + bare-macho input | `run_cli(["-k", IDENTITY_P12, "-p", "testpassword", "-m", "<dir>/absent.mobileprovision", "-o", out, input])` → code 1, stderr contains `absent.mobileprovision` (mirrors main.rs:1679). **Must use a bare-macho input**: `.ipa`/`.app` inputs read the profile at the `ipa/mod.rs:296` seam, which stays unfixed. | bare `IO error:` has no path |
| 8 | `validate_failure_leaves_input_tree_untouched` (builder.rs tests) | `.app` fixture; `ZSign::new()` (no credentials, not adhoc) | `sign_bundle` → `Err(MissingCredentials)` and no `_CodeSignature/` created, `Info.plist` bytes identical to a pre-read copy; likewise `sign_ipa` → output path never created, input bytes unchanged | would only fail if a future change moves work before `validate()` — pins queue item 3 |

Scoped verification (every task, per brief hard rules):

```
TMPDIR=$PWD/.tmptmp cargo test -p zsign-rs <filter> -- --skip test_ipa_signing_is_deterministic   # tasks 1-4, 7(builder), 8
TMPDIR=$PWD/.tmptmp cargo test -p zsign-cli <filter> -- --skip test_ipa_signing_is_deterministic  # tasks 5, 6, 7
```

Final gate (report time only): `cargo fmt --all --check`,
`cargo clippy --workspace --all-targets -- -D warnings`,
`cargo test --workspace --no-fail-fast -- --skip test_ipa_signing_is_deterministic`.
