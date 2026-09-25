# ZSN-4 Fuzz Regression Net — Design

**Date:** 2026-09-25 · **Lane:** zsn4-fuzz · **Base:** main @ 0f07c30
**Scope (authoritative brief):** `fuzz/**` (new), root `Cargo.toml` (`members += "fuzz"` only),
`.github/workflows/fuzz.yml` (new file only). No library source edits; panics are reports.

## 1. Goal

A durable regression net over the six hardened parser surfaces (ZSN-24/25/3/37/38/28):
cargo-fuzz targets + committed seed corpus + a weekly CI smoke, so these parsers never
silently regress. Any panic found during the 60s-per-target smoke is reported with
panic-site routing to its owning lane — never fixed in this lane.

## 2. Brainstorm (internal — no stakeholder questions)

**Target structure:**
- **A — six raw-bytes targets, one per parser** (chosen): thin `&[u8]` harnesses over the six
  public parse entries; native libFuzzer mutation; per-parser crash attribution; only PKCS#12
  needs a two-part input, solved with an explicit 4-byte length prefix (seed-friendly).
- **B — `arbitrary`-structured inputs**: richer structure but an extra dep and wrapper
  complexity; rejected because all six entries are decoders over byte bags, and the rust-fuzz
  book (`cargo-fuzz/structure-aware-fuzzing`, citing the fitzgen.com 2026-06-01 experiment,
  both recorded in §10) notes mutation-based approaches beat `arbitrary` generation for
  coverage when only one is implemented.
- **C — single dispatch target** (route on a discriminator byte): one corpus, but corpus
  dilution and broken per-parser attribution — rejected.

**Corpus strategy:**
- Copy committed fixture bytes into `fuzz/corpus/<target>/` (chosen — mandated and matches
  RustCrypto practice of committed seeds); derive the four formats with no committed artifact
  (superblob, CodeDirectory, signed Mach-O/CMS, provisioning envelope) once via a throwaway
  generator using the crates' **public** builders, then delete the generator.
- Rejected: hand-written minimal headers only (too shallow); empty corpus (brief mandates seeds).

**Workflow shape:**
- Standalone `.github/workflows/fuzz.yml`, weekly cron + `workflow_dispatch`, one ubuntu job
  looping all six targets — chosen; matches the repo's one-job-per-concern convention
  (no matrices exist) and `examples-web.yml`'s schedule+dispatch idiom.
- Rejected: integrating into `ci.yml` (out of scope; noted as follow-up) and per-target jobs
  (6× setup overhead for 30s runs).

## 3. Target table — entry points (verified in-tree)

All entries live in `zsign-core` (lib name `zsign_core`); no crate exposes `[features]`.
The fuzz crate depends only on `zsign-core`, `libfuzzer-sys`, `time`.

| # | Target (bin) | Entry point (verified signature) | Site | Input shape / wrapper |
|---|---|---|---|---|
| a | `superblob` | `pub fn parse_superblob(blob: &[u8]) -> Result<SuperBlob<'_>>` | `crates/zsign-core/src/codesign/verify.rs:87` | raw bytes; on `Ok`, walk `entries[..].payload()`, `code_directory` accessors |
| b | `code_directory` | `pub fn CodeDirectory::parse(blob: &[u8]) -> Result<Self>` | `crates/zsign-core/src/codesign/verify.rs:538` | raw bytes; on `Ok`, accessors + `check_code_pages(&cd, …)` (`verify.rs:856`) |
| c | `verify_code_signature` | `zsign_core::macho::verify_macho(data, &SignatureInputs::none())` (`macho/verify.rs:99`, `SignatureInputs::none` at `codesign/verify.rs:831`) **and** `crypto::cms_verify::verify_code_signature(cms_blob, content, None, &[0u8;32])` (`crypto/cms_verify.rs:303`) | see sites | raw bytes fed **whole** to both calls (no split): `verify_macho` covers goblin→superblob→CD→requirements→CMS chain on framed input; the low-level call always executes `strip_blob_wrapper` (`cms_verify.rs:465`, which requires the `CSMAGIC_BLOBWRAPPER` `0xfade0b01` header and errors otherwise) and reaches `normalize_ber_lengths`/`verify_signed_data` only for inputs carrying that header — hence the blob-wrapped CMS seed in §5 |
| d | `pkcs12` | `SigningCredentials::from_p12(p12_data: &[u8], password: &str)` (`crypto/cert.rs:545`, re-exported `lib.rs:14`) | `crates/zsign-core/src/crypto/cert.rs:545` | `u32`-BE password length prefix ‖ password bytes ‖ p12 bytes. (`crypto::pkcs12::extract_p12` is `pub(crate)` behind a private `mod pkcs12;` — `pkcs12.rs:106`, `crypto/mod.rs:33` — unreachable externally; brief's "via SigningCredentials::from_p12" is the real entry.) |
| e | `plist_to_der` | `pub fn plist_to_der(plist_xml: &[u8]) -> Result<Vec<u8>>` | `crates/zsign-core/src/codesign/der.rs:346` | raw bytes (XML **or** binary plist — `plist::from_bytes` accepts both) |
| f | `provisioning` | `pub fn validate_and_extract_profile(profile_data: &[u8], request: &ProfileRequest) -> Result<ProfileInfo>` (`provisioning.rs:93`) + `pub fn extract_entitlements_from_profile(profile_data: &[u8]) -> Result<Option<Vec<u8>>>` (`provisioning.rs:385`) | `crates/zsign-core/src/provisioning.rs` | `ProfileRequest { now: Some(FIXED), ..Default::default() }` with `FIXED = OffsetDateTime::from_unix_timestamp(1_800_000_000)` — the repo's fixed-clock convention; both entries called per input |

**Brief-vs-tree deviations (entry points that exist TODAY):**
- Brief names `codesign::code_directory` for `CodeDirectory::parse`; the type and its `parse`
  live in `codesign::verify` (`code_directory.rs` holds only the builder). Target uses the
  real path.
- Brief names `parse_superblob (codesign::verify)` — confirmed as written.
- Target (c) is one bin calling both the top-level and the low-level entry: `verify_macho`
  alone cannot reach CMS parse without a signed seed, and the low-level call alone cannot
  cover the container chain.

## 4. Input-shape decisions

- **Raw bytes over `arbitrary`** for all six (RustCrypto `x509-cert` pattern: `fuzz_target!(|input: &[u8]| { let _ = CertReq::from_der(input); })`). Justification: every entry is a
  decoder over a byte bag, so `&[u8]` maps 1:1 and every committed seed loads verbatim —
  the macro's `()` return implies `Corpus::Keep`, so admission can never reject a seed.
  Structured input would defeat the seeds instead: fixed-shape `Arbitrary` types early-bail
  below their `size_hint` and return `-1` (libFuzzer corpus rejection), and a
  `(&[u8], &[u8])` tuple carves its split point from the bytes' own length encoding, so the
  committed p12 seeds would decode into unintended password/blob pairs instead of the
  fixture password.
- **PKCS#12 split**: explicit `u32`-BE length prefix instead of a delimiter byte (delimiters
  corrupt payloads containing that byte; a fixed-width prefix is decodable by construction, so
  real fixture bytes become valid seeds verbatim). Password decoded lossily (`from_utf8_lossy`)
  — non-UTF8 passwords are just another mutation class.
- **KDF work bound**: no in-target bound; guard is libFuzzer `-timeout` on every run (PBKDF2
  `iteration_count` is attacker-controlled in mutated inputs — known DoS class, see §8).
- **Fixed clock** `1_800_000_000` (2027-01-15) for provisioning so crashes reproduce; mirrors
  the wasm fixed-clock convention documented in this repo.

## 5. Seed corpus — provenance

Budget: <256 KB per target (actual max ≈ 35 KB). Files committed under `fuzz/corpus/<target>/`;
provenance below is the record the brief requires (no extra README; .gitignore leaves
`fuzz/corpus` trackable — verified with `git check-ignore`).

| Target | Seeds | Source |
|---|---|---|
| `pkcs12` | 13 × `*.bin` | `crates/zsign-core/src/crypto/fixtures/*.p12` (1707–3387 B each) prefixed with `u32`-BE password length + password. Password rule (verified for all 13): every fixture uses `testpassword` except `empty_password.p12` → length 0 — sources: `VARIANTS` table `pkcs12.rs:913-923` (9 fixtures), identity fixtures at `cert.rs:885/:896`, `raw_keybag` at `pkcs12.rs:1353`; `weak_rsa1024` proven by `cert.rs:1232-1235` passing `"testpassword"` and asserting the *weak-RSA policy* error — that error fires only after successful bag decryption, so a wrong password would have failed earlier with `InvalidPassword`. |
| `verify_code_signature` | `minimal_macho.bin` | copy of `crates/zsign/src/ipa/fixtures/minimal_macho.bin` (8192 B, unsigned thin arm64) |
| `verify_code_signature` | `signed_macho_adhoc.bin`, `code_directory_cms_wrapped.bin` | generated once via public API: `MachOFile::parse` + `sign_macho_adhoc` (`macho/signer.rs:290`, adhoc = no key material, deterministic); `sign_code_directory(cd, credentials, …)` (`crypto/cms.rs:281`) with credentials from `modern_pbes2_aes256.p12`/`testpassword` (RSA PKCS#1 v1.5 → deterministic) — its output is a **bare** DER `ContentInfo` (`crypto/cms.rs:397-399`), so the seed is minted **blob-wrapped**: prepend `CSMAGIC_BLOBWRAPPER` (`0xfade0b01`, `codesign/constants.rs:67`) + `u32::BE(8 + len)` — without that header `verify_code_signature` rejects at `strip_blob_wrapper` and never reaches `verify_signed_data` |
| `superblob` | 3 × `sb_*.bin` | generated via public builders: `build_superblob` (`codesign/superblob.rs:138`) over `CodeDirectoryBuilder` output + `build_requirements_blob()` (`:294`) + `build_entitlements_blob` (`:219`); includes an empty-entry edge seed |
| `code_directory` | 3 × `cd_*.bin` | `CodeDirectoryBuilder::new(id, code).build_sha256()/build_sha1()` (+ team-id variant) (`codesign/code_directory.rs:185,:296,:303`), fixed input code bytes |
| `plist_to_der` | 9 × `*.xml` | 6 input plists transcribed from golden-test inputs in `codesign/der.rs:384-723` (`dict_empty`, `dict_simple`, `dict_nested`, `dict_array`, `dict_time`, `dict_bigint` — the out-of-i64 rejection input at `der.rs:610`) + 2 constructed (see plan: `dict_long` = the 130×'x' string from `test_plist_to_der_long_form_lengths` `der.rs:653-677`; `dict_negint` = a `<integer>-42</integer>` entry — the negative-int cases at `der.rs:705-723` are `encode_value` unit tests with no XML fixture) + `profile_plist.xml` (copy of `PROFILE_XML`) |
| `provisioning` | `profile_plist.xml`, `cms_signed_data.bin` | `PROFILE_XML` (`crates/zsign-wasm/src/lib.rs:703-716`; exercises the raw-scan extractor + envelope reject path); `cms_signed_data.bin` = `sign_code_directory` output **verbatim** — a bare DER `ContentInfo`, which is exactly what `verify_cms_envelope` parses (`cms_verify.rs:391-399` strips no wrapper) → deep CMS parse on the envelope path |

Total committed seed files: 13 + 3 + 3 + 3 + 9 + 2 = **33**.

**Honest limitation:** no valid signed `.mobileprovision` can be minted from outside the crate
(`crypto/cms.rs` envelope signers are `#[cfg(test)] pub(crate)`), so target (f) exercises the
CMS **parse/reject** boundary and the raw-scan path, not a full chain-validated profile.
Seeds regenerate deterministically; the generator is a throwaway crate run once and deleted —
the exact recipe is this table plus the builders cited.

**Corpus writeback hygiene:** libFuzzer reads every corpus dir it is given but writes new
inputs only to the **first**; cargo-fuzz passes *only* the user-supplied dirs when any are
given — it adds the automatic `fuzz/corpus/<target>` solely when none are (`src/project.rs`
`if !run.corpus.is_empty()` branch; argv captured empirically under cargo-fuzz 0.13.2).
Every local/CI run therefore passes **both** dirs explicitly: scratch
`fuzz/target/smoke-corpus/<target>` first (the writeback target, ignored via `fuzz/.gitignore`),
committed `fuzz/corpus/<target>` second (read-only seeds) — seeds load, and run output never
dirties the committed corpus.

## 6. Workspace wiring (root `Cargo.toml`)

`members += "fuzz"` (the brief's only permitted manifest edit), plus in **`fuzz/Cargo.toml`**
(my scope):

```toml
[features]
fuzzing = []
# every [[bin]] gets: required-features = ["fuzzing"]
```

**Why `required-features`** — verified facts (librarian, cargo-fuzz 0.13.2 / libfuzzer-sys
0.4.13 source + live experiments):
- Plain membership drags fuzz bins into every existing CI gate; all of them run at
  `--workspace` scope with no `--exclude` (`ci.yml:39,49,62,75,136`,
  `publish-crates.yml:38-42`, `publish-wasm.yml:23-27`): `clippy --all-targets -D warnings`
  would lint fuzz code, `check --all-targets` (incl. the **Windows** job — libFuzzer is
  Unix-only) would run `libfuzzer-sys/build.rs`, which compiles vendored C++ every time.
- `test = false`/`doc = false`/`bench = false` (cargo-fuzz's template defaults, which we keep)
  already keep `cargo test --workspace` fuzz-invisible (verified: fuzz pkg never entered),
  but do **not** affect `check/build/clippy --workspace --all-targets`.
- `required-features` is the only mechanism verified to make those commands skip the fuzz
  bins entirely (`check --workspace`: 0.00 s, build script never runs), which is exactly the
  brief's "fuzz targets compile out of normal `cargo build`".
- Cost: **every** cargo-fuzz invocation must pass `--features fuzzing`. Without it,
  `cargo fuzz run <t>` fails with "target … requires the features: 'fuzzing'" (exit 101,
  reproduced in a throwaway crate) and bare `cargo fuzz build` matches no targets
  (warning: "no targets matched"; the `--bins` filter path) — the flag is load-bearing in
  both, and is encoded in the workflow, the plan, and the recorded gate commands.

Other wiring facts: root manifest has **no** `[workspace.dependencies]`/`[workspace.lints]`
(only `resolver = "2"` + `workspace.package.rust-version = "1.88"`), so nothing to inherit;
fuzz manifest declares `rust-version.workspace = true`, `publish = false`, edition 2021,
`[package.metadata] cargo-fuzz = true`, dependency `zsign-core = { path = "../crates/zsign-core" }`
(**never** `path = ".."` — `cargo fuzz init` at a virtual root emits a dangling path by
`metadata.packages.first()`). No `[workspace]` table (member + workspace table = "multiple
workspace roots" error). `Cargo.lock` gains exactly three entries — `libfuzzer-sys` 0.4.13,
`arbitrary` 1.4.2 (via libfuzzer-sys's unconditional dependency), and the path member
`zsign-fuzz` — with **no version changes** (measured on this worktree: 25 insertions, 0
deletions; existing `cc` 1.4.7 and its transitive deps already satisfy the new graph, so
nothing is bumped) — committed with the
fuzz-crate commit per brief. `time = { version = "0.3", features = ["parsing", "formatting"] }`
matches `crates/zsign-core/Cargo.toml:17`.

**Toolchain:** cargo-fuzz always passes `-Zsanitizer` → nightly mandatory (`has_sanitizers_on_stable`
is a `u32::MAX` placeholder in 0.13.2). Locally: `cargo +nightly-2026-04-30 fuzz …` (the installed
dated nightly; rustup propagates `RUSTUP_TOOLCHAIN` to cargo-fuzz's nested `cargo`). `cargo-fuzz
0.13.2` installed via `cargo install cargo-fuzz` (recorded).

## 7. CI workflow shape (`.github/workflows/fuzz.yml`)

Conventions reused from `ci.yml` / `examples-web.yml` (all verified by scout):
- Triggers: `schedule: cron: "43 3 * * 1"` (weekly Mon 03:43 UTC — off the top of the hour,
  non-round minute, distinct from `examples-web.yml`'s `23 5 * * 1`) + bare `workflow_dispatch`.
- `permissions: contents: read` (repo-wide idiom); `concurrency: group: fuzz-${{ github.ref }}`,
  `cancel-in-progress: true` (ZSN-31 block shape, own `fuzz-` prefix — never reuse `ci-`).
- One `ubuntu-latest` job, `timeout-minutes: 30` (repo range 10–45).
- Step prologue: `actions/checkout@v4` → `dtolnay/rust-toolchain@master` with explicit
  `toolchain: nightly-2026-04-30` (README's documented input form; a **dated** nightly so a
  weekly red is attributable to repo changes rather than a floating channel, and so CI runs
  the same toolchain the local evidence runs used) →
  `taiki-e/install-action@v2.87.20` with `tool: cargo-fuzz` (same pin as the wasm-pack
  installs) → `Swatinem/rust-cache@v2` bare.
- Build once (`cargo fuzz build --features fuzzing`), then loop over `cargo fuzz list`
  (assignment-captured so a list failure trips `set -eu`), per target:
  seed-dir precondition (`[ -d fuzz/corpus/<t> ] || { echo …; exit 1; }`), then
  `cargo fuzz run <t> --features fuzzing fuzz/target/smoke-corpus/<t> fuzz/corpus/<t> -- -max_total_time=30
  -timeout=25 -rss_limit_mb=2048 || status=$?` — both dirs passed explicitly, scratch first
  so writeback misses the committed corpus (§5); exit status accumulated so one crash cannot
  forfeit the remaining targets, job fails if any target failed. Artifacts uploaded with
  `actions/upload-artifact@v7.0.1` under `if: failure() || cancelled()` (crash files must
  survive job timeout / cancel-in-progress), path `fuzz/artifacts/`.
- No dictionaries in v1 (see §9). Workflow must pass `actionlint` 1.7.12 (mise pin), i.e.
  shellcheck-clean `run:` blocks.

## 8. Expected-failure classification (for recorded smoke results)

Every 60s-per-target run is recorded verbatim and classified:

| Class | Definition | Action |
|---|---|---|
| `CLEAN` | 60 s completed, no crash/hang | valid recorded result |
| `PANIC` | Rust panic (index/shift/assert/unwrap) with backtrace into zsign-core | REPORT: panic site `file:line`, owning lane, repro `cargo fuzz run <t> --features fuzzing fuzz/artifacts/<t>/<file> -- -runs=0` |
| `ABORT` | stack overflow / SIGSEGV / ASan report (recursion depth, OOB) | REPORT as above with ASan detail |
| `TIMEOUT` | one input exceeded `-timeout` | REPORT as DoS-class (attacker-controlled work factor, e.g. PBKDF2 iterations) unless it is a true livelock |
| `OOM` | RSS > `-rss_limit_mb` | REPORT as DoS-class allocation sizing |
| `ENV` | toolchain/disk/`/tmp` failure (known: tmpfs flakes under parallel-lane load) | retry once with `TMPDIR=$PWD/.tmptmp`; record honestly |

**Owner routing** (per brief; no fixes in this lane): `codesign/*` + `cms_verify` BER →
ZSN-29 · `macho` signer/writer/parser/builder → ZSN-33 · `ipa/*` → ZSN-39 · `main.rs` → ZSN-5 ·
panic in a file owned by **no** active lane (`macho/verify.rs`, `crypto/pkcs12.rs`,
`crypto/cert.rs`, `provisioning.rs`) → note as candidate with a one-line fix suggestion and
route to the supervisor; `codesign/der.rs` and all of `codesign/*` route to ZSN-29.

**Known candidates — status after ZSN-29 landing (supervisor update, verified against
`git show 2e06a17:…`; every post-fix line number below refers to the `2e06a17` blob read via
`git show`, NOT to this worktree's files):** this branch's base (0f07c30) **predates** main
commit `2e06a17`,
which landed `page_size_log2` validation + checked shift (`verify.rs:613-618,884`),
hash-region `checked_mul` including `special_slot_hash`/`code_hashes` (`verify.rs:709,795,804,906`),
the `write_norm` BER depth cap, and superblob u32 narrowing guards. Consequences for this lane:
- Crashes on **this branch** in the shift / multiply / special-slot / BER classes are
  **STALE findings** — record them citing `2e06a17` as already-fixed; no owner routing.
- The same classes crashing **after** the orchestrator merges `2e06a17` would be NEW findings.
- `plist_to_der` encode recursion remains **OPEN on main** (verified: `2e06a17`'s `der.rs`
  has no depth guard) → still routes to ZSN-29.

Bullet status (all route-targets below were evaluated against the branch base):
- ~~`check_code_pages`: `1usize << cd.page_size_log2` (`codesign/verify.rs:859`) — `page_size_log2`
  read unvalidated at `verify.rs:613`; `-Cdebug-assertions` → shift-overflow from a 44-byte
  blob (`page_size_log2 >= 64`), also CLI-reachable (`zsign verify` → `verify_macho` →
  `check_code_pages_in_file`, `macho/verify.rs:417-420,505`)~~ **FIXED on main `2e06a17`**
  (parse-time rejection + checked shift; test `parse_rejects_page_size_log2_above_16`);
  stale on this branch base.
- ~~Unchecked `expected_slots * cd.hash_size` before indexing `stored`
  (`codesign/verify.rs:883`, slice `:900`)~~ **FIXED on main `2e06a17`** (`verify.rs:906`
  `checked_mul` → `CountMismatch`); stale on this branch base.
- ~~`special_slot_hash` bare subtraction (`verify.rs:780`) safe only via parse-time guards~~
  **FIXED on main `2e06a17`** (full checked chain); stale on this branch base.
- ~~`normalize_ber_lengths` → `write_norm` uncapped recursion (`crypto/cms_verify.rs:152+`)~~
  **FIXED on main `2e06a17`** (BER depth cap landed); stale on this branch base.
- `plist_to_der` encode side has no recursion-depth cap (`codesign/der.rs:346+`; decode side
  *is* capped at 32/64 in `verify.rs:1115,1143,1154,373`) — **OPEN on main** (verified
  against `2e06a17`). Owner: ZSN-29 (`codesign/*`).
- PKCS#12 PBKDF2 work factor: `validate_iterations` accepts up to `MAX_ITERATIONS = 10_000_000`
  (`crypto/pkcs12.rs:149,383`) — attacker-controlled per-input cost; classified `TIMEOUT`
  under §8 rules, `-timeout=25` on every run. No active lane owns `crypto/pkcs12.rs` →
  report-only.

## 9. Limitations & follow-ups (out of scope, recorded for the owner)

- No valid signed provisioning-profile seed possible externally (§5) — target (f) covers
  parse/reject + raw-scan only.
- No `.dict` files in v1 (DER/magic dictionaries would deepen coverage); follow-up if smoke
  runs show shallow structure exploration.
- Fuzz bins are skipped by workspace-scoped `clippy --workspace --all-targets` (the only
  form every existing workflow runs, §6); a package-scoped `cargo clippy -p zsign-fuzz
  --all-targets` would still compile them. Lint coverage of target code comes from
  `cargo fuzz build` compilation warnings plus review.
- `ci.yml` integration (fuzz as a required PR gate instead of weekly) and `hk.pkl` test-step
  integration are follow-ups for their owners (both files are out of this lane's scope).
- **cargo-deny conflict (needs owner action — supervisor question raised):** making `fuzz` a
  workspace member puts `libfuzzer-sys 0.4.13` — license `(MIT OR Apache-2.0) AND NCSA`
  (`libfuzzer-sys-0.4.13/Cargo.toml:36`) — into the root `Cargo.lock`, while `deny.toml`'s
  `[licenses].allow` (`deny.toml:15-27`) has no `NCSA`; the required `cargo-deny` CI job
  (`ci.yml:117-125`) would then fail. `deny.toml` is outside this lane's scope (brief:
  "nothing else"). Options routed to the supervisor: **(A)** add `"NCSA"` to the allowlist —
  one line, the standard LLVM license, recommended; **(B)** land the branch with the deny job
  red until that line lands; **(C)** drop workspace membership (`fuzz` keeps its own
  `[workspace]` table — cargo-fuzz-supported and CI-green, but deviates from the brief's
  `members += "fuzz"` mandate). **Resolution: supervisor selected option A** — keep
  membership; the one-line `"NCSA"` allowlist addition to `deny.toml` is routed outside this
  lane (still out of this lane's scope; must land before the required cargo-deny job is green
  again). Lock delta measured on this worktree: three added entries (`libfuzzer-sys`,
  `arbitrary`, the path member `zsign-fuzz`), 25 insertions / 0 deletions, **no version
  changes** — `cc` stays 1.4.7 (a fresh-project lock would pull newer transitives; this
  repo's existing pins already satisfy the new graph, see §6).

## 10. Research evidence

- In-tree claims: file:line citations inline above (scout reports: entry points, fixtures,
  loading conventions, workflow conventions).
- External: cargo-fuzz 0.13.2 templates/flags (`rust-fuzz/cargo-fuzz` src/templates.rs,
  src/project.rs `if !run.corpus.is_empty()` dir handling — argv captured locally via a PATH
  shim, CHANGELOG), libfuzzer-sys 0.4.13 (`lf/src/lib.rs` Corpus/fuzz_target arms,
  `libfuzzer/FuzzerFlags.def`), arbitrary 1.4.2 tuple `arbitrary_take_rest` semantics,
  LLVM libFuzzer corpus writeback docs (first-dir writeback), rust-fuzz book
  `cargo-fuzz/structure-aware-fuzzing` (citing fitzgen.com 2026-06-01 experiment), GitHub
  Actions schedule /
  concurrency docs, dtolnay/rust-toolchain + Swatinem/rust-cache READMEs, RustCrypto
  `x509-cert`/`tls_codec` fuzz workflows as the ecosystem pattern.
