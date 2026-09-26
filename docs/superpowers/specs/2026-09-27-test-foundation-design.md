# Test Foundation Design — ZSN-30

> Lane zsn45 · branch `zsn45-test-foundation` · 2026-09-27
> Scope: one ticket (ZSN-30 "Rebuild the test foundation and fill critical
> coverage gaps"). The ticket text dates 2026-09-24; most items have since
> landed across seven waves. This design records a full re-audit against
> current source, then specifies only the still-open work.

**Goal:** delete the remaining plumbing tests, consolidate Mach-O fixture
builders and shared test credentials behind a single home
(`zsign_core::macho::fixtures` + `OnceLock`), fill the remaining coverage
gaps red-first, and make the documented local gate (`hk check`) trustworthy
(the suite it runs has no stale skip flags left).

**Architecture:** the fixtures module is currently `#[cfg(test)] pub(crate)`
inside `zsign-core`, unreachable from sibling crates. We expose it to
workspace test builds via a dev-dependency-only `test-fixtures` feature
(resolver 2 ⇒ enabled only when dev-deps are active, so release and wasm
artifacts are unaffected), migrate every straggler builder and duplicated
leaf-credential recipe into it behind `OnceLock`, and delete the committed
byte-duplicate `.bin` fixture (proven byte-identical to the builder output).

**Tech stack:** Rust workspace (4 crates + fuzz), cargo/hk gates, `OnceLock`
(std), no new external dependencies.

---

## 1. Still-open matrix (mandatory re-audit)

Evidence is `file:line` against the branch tip. LANDED = verify-and-skip;
OPEN = in scope for this lane.

| # | Ticket item | Verdict | Evidence |
|---|---|---|---|
| 1a | `.gitignore` ignores `crates/zsign/tests/` | **LANDED** | Rule removed in `ee42c12` ("ungate tests dir, commit lockfile, drop plumbing tests, add hk test gate"); no `crates/zsign/tests/` directory exists in the tree |
| 1a+ | `.tmptmp/`, `.tmptmp-orch/` scratch ignores | **OPEN → done in this lane** | Added at `.gitignore:45-47` (lane scratch dirs previously showed untracked in primary checkouts) |
| 1b | `Cargo.lock` gitignore rule vs tracked state | **LANDED** | `git check-ignore Cargo.lock` rc=1 (not ignored); `git ls-files Cargo.lock` → tracked; intent comment at `.gitignore:5-6` |
| 1c-1 | cert.rs compile-shape asserts (ticket cited :402-417) | **LANDED** | Removed in `ee42c12` (`test_signing_key_type_enum_exists`, `test_signing_credentials_struct_exists`); `cert.rs:402-417` is production code today; first test in `mod tests` is `cert.rs:972` |
| 1c-2 | cms_verify `debug_certs_dump` println scratch | **LANDED** | Removed in `ee42c12` (−52 lines, zero-assert hex dump); zero matches for `debug_certs_dump` in `crates/` |
| 1c-3 | two "validates the API compiles" stubs | **LANDED** | Both removed in `ee42c12` (`crates/zsign-core/src/macho/parser.rs` and `crates/zsign/src/macho/parser.rs`); grep for the phrase returns no matches |
| 1c-4 | empty `#[cfg(test)] mod` in `zsign/src/macho/mod.rs` | **LANDED** | Deleted in `ee42c12`; AST scan finds zero empty `mod tests {}` workspace-wide |
| 1c-5 | **`debug_req_slot` println-only scratch (successor found by re-audit)** | **OPEN → delete** | `crates/zsign-core/src/macho/verify.rs:512-549`: signs a Mach-O and `println!`s slot data; zero assertions, zero panics — same class as the deleted `debug_certs_dump`, cannot fail on a behavior regression |
| 1c-6 | other no-assert tests (AST scan) | KEEP | 3 hits are legitimate unwrap-driven behavior tests (`cert.rs:1276`, `cert.rs:1418`, `writer.rs:2257`) — they *can* fail |
| 1d | 5 duplicate Mach-O fixture builders (now 16 in-scope stragglers) | **OPEN → consolidate** | Full table in §3.2; canon home `crates/zsign-core/src/macho/fixtures.rs` (13 fns) |
| 1d | RSA-2048 keygen sites (now 18 counted) | **OPEN → consolidate + OnceLock** | Full disposition in §4; 3 exact/near-duplicate leaf recipes + canon to merge/OnceLock; the rest are distinct-by-design and stay (justified) |
| 1e-1 | FAT sign→re-parse→verify round-trip | **LANDED** | `crates/zsign-core/src/macho/verify.rs:1014-1058` `verify_signed_fat_armv7_arm64_round_trip`: make_fat_macho → parse → sign → verify with per-slice pages/cms/cdhash assertions (ZSN-33). Disk-path extension added anyway — see §5 e1b |
| 1e-2 | sign-IPA → `verify_ipa` end-to-end | **OPEN** | `verify_ipa` (`crates/zsign/src/verify.rs:390`) is never called from any test — only production (`verify.rs:390` re-export `lib.rs:61`, CLI `main.rs:316`). ZSN-41's determinism test signs twice but never verifies via `verify_ipa` |
| 1e-3 | 16KB `page_size_log2=14` CodeDirectory test | **PARTIAL** | Parse acceptance landed (`crates/zsign-core/src/codesign/verify.rs:1811-1817`, helper `cd_bytes_with_page_size` :1785, ZSN-29) but `check_code_pages` is never driven with log2=14 — only log2=0 gets behavioral coverage (:1820-1826) |
| 1e-4 | `should_exclude`/`add_symlink` table tests | **PARTIAL** | `should_exclude` (`code_resources.rs:420`) exercised only indirectly via `add_file` tables (:736-793, :796-826, :828-890); `add_symlink` (`code_resources.rs:530`) has **no** unit test of its own (grep hits are wasm/zip-writer, different APIs) |
| 1e-5 | credential-mismatch + Apple-chain-selection tests | **LANDED** | `cert.rs:1600-1609` (RSA key + EC cert → `Error::Certificate` "does not match"); chain tests `cert.rs:1150-1199`, `:1201-1206`, `:1208-1231`, `:1233-1273` (ticket's `:269`/`:342` line refs are stale — those are now production) |
| 1e-6 | `assert_cmd` CLI suite | **OPEN → decide** | Not a dependency anywhere (Cargo.lock clean). Decision: **REJECT** — full evidence in §6. `run_cli` (`crates/zsign-cli/src/main.rs:1116`) + 46 tests already pin the 0/1/2 contract (`main.rs:1157`, `:1178`, `:1189` …) |
| 1e-7 | DER golden vectors | **LANDED** | `crates/zsign-core/src/codesign/der.rs:628-702` byte-exact vectors + `verify.rs:1593-1629` round-trip (ZSN-38, commit `482e5a5`) |
| hk | add test step to `hk check` | **LANDED** | `hk.pkl:30-35` defines `cargo-test` step `cargo test --workspace`, `exclusive = true`, included in `static` → `check` hook (`hk.pkl:41-43`, `:52-54`). hk 1.55.0 installed and matches `min_hk_version` |
| skip | remove `--skip test_ipa_signing_is_deterministic` from scripted invocations | **OPEN** | Whole-repo grep: **only** `.github/workflows/ci.yml:62` (plus its stale justification comment `:59-60`). `scripts/verify-apple-interop.sh` has no `cargo test` at all; `mise.toml`, `hk.pkl`, fuzz/examples workflows clean |

Baseline: `cargo test --workspace --no-fail-fast` at branch tip = **740
passed, 0 failed** (7 suites; run with `TMPDIR=$PWD/.tmptmp`).

---

## 2. Plumbing-test deletions (queue item 2)

The four named plumbing tests are already gone (§1 1c-1..1c-4, removed by
wave-0 commit `ee42c12`). Nothing to delete for those — verified absent
before any edit, per brief. One live successor remains:

- **Delete `debug_req_slot`** — `crates/zsign-core/src/macho/verify.rs:512-549`.
  Justification: zero assertions, zero `panic!`/`unwrap`-as-assertion; it
  signs a Mach-O and `println!`s `n_special_slots`, per-entry slot lengths,
  and slot digests. It cannot fail on a behavior regression — the exact
  criterion the ticket uses for the four already-deleted tests. It is the
  same class as the removed `debug_certs_dump` scratch. The three remaining
  assertion-less tests found by AST scan (`cert.rs:1276`, `cert.rs:1418`,
  `writer.rs:2257`) are kept: they `unwrap()`/`expect()` real error paths
  and therefore *can* fail.

## 3. Fixture consolidation (queue item 3)

### 3.1 The reach seam: `test-fixtures` feature

`crates/zsign-core/src/macho/mod.rs:14` gates the canon home as
`#[cfg(test)] pub(crate) mod fixtures;` — invisible to the other three
crates' tests. Cross-crate consolidation therefore needs a controlled
exposure:

- `zsign-core` gains an empty feature `test-fixtures`.
- Gate becomes `#[cfg(any(test, feature = "test-fixtures"))] pub mod fixtures;`
  and the fixture fns the other crates need become `pub` (they are already
  documented).
- Each consumer (`zsign`, `zsign-cli`, `zsign-wasm`) adds
  `zsign-core = { path = "../zsign-core", features = ["test-fixtures"] }`
  to **dev-dependencies only**. Workspace `resolver = "2"`
  (`Cargo.toml:2`) means dev-dependency features are *not* unified into
  normal dependency builds: `cargo build --release`, `wasm-pack build`, and
  fuzz targets compile zsign-core **without** the feature, so no fixture
  code ships in release/wasm artifacts. `cargo test`/`clippy --all-targets`
  activate it for test builds only.
- Chosen over alternatives: (a) moving fixtures to a standalone
  `zsign-test-fixtures` crate — new crate + publish surface for test-only
  code, YAGNI; (b) `#[cfg(test)] pub` re-export through `zsign` — cannot
  work: `cfg(test)` only applies to the crate being tested, so `zsign`'s
  test builds still see `zsign-core` compiled *without* `cfg(test)`;
  (c) duplicating builders per crate — the status quo the ticket rejects.
- Dev-dependency justification (design-doc requirement): all three edges are
  *path* dev-deps on an existing workspace member — zero new external crates,
  zero lockfile churn; strictly smaller than any alternative that moves code.

### 3.2 Builder disposition table (stragglers → canon)

Canon = `crates/zsign-core/src/macho/fixtures.rs` (13 fns today, already
holds `make_fat_macho` :567, 32-bit builders :111/:191/:273,
`make_minimal_dylib` :102 — added by zsn33/44, not moved). One empirical
fact underpins the whole migration: `make_minimal_macho()` output was
proven **byte-identical** to the committed
`crates/zsign/src/ipa/fixtures/minimal_macho.bin` (8192 B, `cmp` exit 0,
probe run this lane and removed). The `.bin` and every `include_bytes!`
wrapper around it are therefore deletable in favor of the builder.

| Straggler (file:line) | Callers | Disposition |
|---|---|---|
| `parser.rs:481` `minimal_macho_with_encryption(cryptid, cryptsize)` | 3 (`parser.rs:575,591,606`) | **Delete** — byte-equivalent to canon `make_minimal_macho_encrypted(cryptid, cryptsize)` :466 |
| `parser.rs:617` `minimal_macho_plain()` | 1 (`:704`) | **Delete** — `make_minimal_macho()` :6 |
| `parser.rs:714` `minimal_macho_32_with_encryption()` | 1 (`:744`) | **Move to canon** as `make_minimal_macho_32_encrypted` (no canon equivalent; distinct parse arm must survive) |
| `signer.rs:1596` `make_fat_with_encrypted_second_slice()` | 1 (`:1627`) | **Delete** — compose `make_fat_macho(&[make_minimal_macho(), make_minimal_macho_encrypted(1, 0x1000)], &[12, 12])` |
| `verify.rs:795` `build_two_slice_fat()` | 1 (`:817`) | **Delete** — `make_fat_macho(&[make_minimal_macho(), make_minimal_macho()], &[12, 12])` |
| `writer.rs:1814` `build_test_binary(segment_fileoff)` | 3 (`:1845,:1915,:1926`) | **Move to canon** as `make_linkedit_only_macho(segment_fileoff)` (no-`__text` shape is the point of those tests; keep bytes, relocate home) |
| `writer.rs:2648` in-test FAT writer | 1 (`test_embed_fat_rejects_overlapping_slices`, `:2640`) | **Keep in place** — deliberately *invalid* (overlapping slices) hostile-input fixture; canon `make_fat_macho` produces only well-formed lipo layouts, so it is not a duplicate. Justified exception, documented here. |
| `benches/signing.rs:29` `build_synthetic_macho` + `:100` `test_credentials` | bench only | **Keep in place** — bench target, not a test; variable `code_size ≥ 4096` shape has no canon equivalent; benches compile without `cfg(test)` and without the feature. Justified exception. |
| `zsign/src/test_util.rs:9` `minimal_macho()` (include_bytes) | ~30 | **Delete** → `fixtures::make_minimal_macho()` (byte-identity proven) |
| `zsign/src/test_util.rs:14` `minimal_macho_encrypted()` | 2 | **Delete** → `fixtures::make_minimal_macho_encrypted(1, 0x1000)` (same patch semantics as canon :473-483) |
| `zsign/src/test_util.rs:29` `minimal_dylib()` | 2 | **Delete** → `fixtures::make_minimal_dylib()` :102 |
| `zsign/src/builder.rs:856` `make_fat_for_test` | 1 (`:892`) | **Delete** → `make_fat_macho(slices, &[12; n])`; `write_two_arch_fat_fixture` :886 **kept** (materializes files, rewire internals to canon) |
| `zsign-wasm/src/lib.rs:1035` `build_fat_macho` | 3 | **Delete** → `make_fat_macho(&[make_minimal_macho(), make_minimal_macho()], &[12, 12])` (fixed 20 480 B output equals canon layout for two 8 KiB slices, align 12) |
| `zsign-wasm/src/lib.rs:1054` `build_fat_macho_one_arch` | 1 | **Delete** → `make_fat_macho(&[make_minimal_macho()], &[12])` (12 288 B output) |
| `zsign-cli/src/main.rs:979` `encrypted_macho()` | 1 (`:1073`) | **Delete** → `fixtures::make_minimal_macho_encrypted(1, 0x1000)` |
| `MINIMAL_MACHO` `include_bytes!` consts: `zsign-cli/src/main.rs:1130` (15 uses), `zsign-wasm/src/lib.rs:769` (9 uses), `zsign/src/ipa/mod.rs:1972` (zip write) | 25 | **Delete** → `fixtures::make_minimal_macho()` (byte-identity proven) |
| Committed `crates/zsign/src/ipa/fixtures/minimal_macho.bin` | 4 include sites | **Delete file** once all four migrate — a byte-for-byte duplicate of builder output is a second source of truth |

Migration rule: every call site moves in the same change that deletes its
helper (no aliases, no re-exports, no shims); full workspace suite must be
green after each crate's migration batch.

### 3.3 What is *not* consolidated (justified)

- `codesign/verify.rs:1692` `synth_cd` — CodeDirectory blob, not a Mach-O.
- Bundle/directory fixtures (`archive.rs:569`, `ipa/mod.rs:2322` …) — on-disk
  `.app` trees, not Mach-O byte buffers.
- Committed `.p12`/PEM/OCSP blobs — format fixtures, correctly file-based.
- The two justified exceptions in §3.2 (hostile overlapping FAT, bench).

## 4. Credential consolidation + OnceLock (queue item 3)

### 4.1 Recipe taxonomy (18 keygen sites counted, dispositioned)

Only helpers that build a **full self-signed `SigningCredentials` leaf from
scratch** are consolidation candidates; the rest of the 18 RSA-2048 sites
are chain builders, payload keys, or parametrized factories and stay
(justified, §4.3).

| Recipe (file:line) | Callers | Disposition |
|---|---|---|
| canon `fixtures.rs:603` `test_signing_credentials` — `CN=zsign verify test`, serial 7, Leaf+E KU, `team_id=Some("TESTTEAM")` | 8 (`signer.rs:1912`, `writer.rs` ×7) | **Wrap in `OnceLock`** inside the canon home |
| `macho/verify.rs:573` `rsa_credentials` — byte-equivalent recipe (same CN/serial/Leaf/EKU/team) | 13 | **Delete** → canon (exact duplicate) |
| `macho/signer.rs:960` `test_credentials` — `CN=zsign roundtrip,OU=TESTTEAM`, serial 7, **`Profile::Root`** (no EKU ext) | 12 | **Not a duplicate** — `Profile::Root` vs `Leaf` changes BasicConstraints and the subject; migrating would alter signed-bytes and chain-shape assertions. **Move into fixtures** as a second named recipe (`test_root_credentials`), wrapped in its own `OnceLock`. One home, no recipe change. |
| `zsign/src/test_util.rs:37` `test_credentials` — `CN=zsign test,OU=TESTTEAM`, serial 7, Leaf+E KU, team | ~40 | **Move into canon home** as named recipe (`team_ou_test_credentials`), `OnceLock`-wrapped; `zsign` callers reach it via the `test-fixtures` feature. Subject differs from canon (`OU=TESTTEAM` present) so it is *not* merged into the canon recipe — but it is the same recipe as the next row, so one entry serves both. |
| `zsign/src/verify.rs:948` `local_test_credentials` — byte-equivalent to the row above, additionally returns `(creds, RsaPrivateKey)` | 2 (`:1049`, `:1227`) | **Delete** — replace with a `OnceLock<(SigningCredentials, RsaPrivateKey)>` accessor in the fixtures home (`test_credentials_with_key`) so the raw key (needed to rebuild a second creds set for anchored verify) is still reachable. |
| `crypto/cms_verify.rs:1744` `rsa_credentials` — `CN=zsign verify test`, serial **42**, `team_id=None`, returns key | 18 | **Stay local, gain `OnceLock`** *with one carve-out*: `attacker_self_signed_resign_is_invalid` (`:2231-2232`) calls it twice **expecting two independent identities**; `:2259` needs a third. Design: split into `OnceLock`-cached `rsa_credentials()` for the 16 single-identity callers and a `fresh_rsa_credentials()` for the three independence-dependent call sites (same recipe, uncached). Serial 42 / `team_id=None` differ from canon, so it does **not** merge into fixtures canon. |
| `crypto/cms.rs:926` `build_test_rsa_credentials(bits)` | 2 | **Keep** — parametrized by key size (1024-bit weak-key path exists) |
| `crypto/cms.rs:1059` / `:1166`, `signer.rs:1026` ECDSA builders | 1 each | **Keep** — P-256, fixed-scalar determinism twins with pinned validity windows; deterministic-by-construction, `OnceLock` buys nothing |
| `crypto/cert.rs:852` `fresh_2048()` | 25 | **Keep** — callers each *require a distinct key* (identity-selection, chain-walk ordering); caching would break the tests' premise |
| `crypto/cert.rs:882` `build_cert` | 24 | **Keep** — generic issuer/subject factory, not a keygen site |
| `crypto/cms_verify.rs:2082` `build_rsa_root` / `:2121` `build_leaf` / inline `:2341`,`:2371` | 7+5+2 | **Keep** — CN-parametrized chain shapes; distinct-by-design |
| `crypto/encrypted_pem.rs:224`, `crypto/pkcs12.rs:1340,1359` | 1 each | **Keep** — key is the *payload* under test |
| `provisioning.rs:548` `signed_profile` | ~8 | **Keep** — must mint a fresh keypair per profile (CMS signature must differ) |
| `benches/signing.rs:100` | 1 | **Keep** — bench-only (§3.2) |

### 4.2 OnceLock mechanics

```rust
// crates/zsign-core/src/macho/fixtures.rs
use std::sync::OnceLock;

static CANON_CREDS: OnceLock<crate::crypto::SigningCredentials> = OnceLock::new();

/// Shared self-signed RSA-2048 code-signing credentials (cached after first call).
pub fn test_signing_credentials() -> crate::crypto::SigningCredentials {
    CANON_CREDS.get_or_init(build_canon_credentials).clone()
}
```

- **Return type stays owned** — `.credentials(creds)` consumes by value at
  ~40 call sites (`builder.rs:815,848,1042,1049,1100,1125` and many more);
  an owned-clone return keeps *every* call site unchanged. The alternative
  (`&'static` accessors) was evaluated and rejected: it forces churn across
  all ~40 owned-consumption sites or a production API change to
  `ZSign::credentials`.
- **Production change required:** `#[derive(Clone)]` on
  `SigningCredentials` (`crypto/cert.rs:102`) and `SigningKeyType`
  (`crypto/cert.rs:63`). All fields are already `Clone`
  (`x509_cert::Certificate` is cloned in existing test code at
  `verify.rs:1052`; `rsa::pkcs1v15::SigningKey` and `p256::ecdsa::SigningKey`
  are `Clone`; `Vec<Certificate>`, `Option<String>` trivially so). The
  derive is a semantic no-op for production paths — the struct is already
  moved by value everywhere — and is the smallest possible surface for
  making a cached identity shareable. `RsaPrivateKey` (needed by the
  with-key variant) is already `Clone`.
- Process-wide caching is safe because: certs are minted
  `Validity::from_now(3600s)` (a test process lives well under an hour);
  tests never mutate credential contents (field access is read-only at all
  observed call sites); `OnceLock` gives thread-safe one-time init under the
  parallel test harness.
- Exceptions that must *not* share an identity: the three
  `cms_verify` independence sites (handled by `fresh_rsa_credentials`),
  `cert.rs:852 fresh_2048` (stays uncached by design), `provisioning.rs`
  (fresh CMS per profile), `attacker`/`victim` pattern anywhere else — the
  implementer must re-grep each migrated helper's callers for
  *two-calls-one-test* before wrapping (recorded as a plan step).

### 4.3 Why the rest are not consolidated

`fresh_2048` (distinct-key-by-premise), chain builders (CN/shape
parametrized), payload keys (the key *is* the fixture), `signed_profile`
(freshness required for distinct CMS), ECDSA determinism twins (fixed
scalar + pinned window — caching adds nothing and the twins live in
different modules testing module-local code). Forcing these behind one
`OnceLock` would either break test premises or centralize unrelated
concerns — both worse than the duplication they remove.

## 5. Gap tests (queue item 4) — red-first where a bug could plausibly exist

Repo policy: behavior, boundaries, invariants, transitions, errors — never
restatements of code. Each test below is written **red-first**: the test is
authored first and run against current source; if it passes immediately
because the behavior is already correct, the plan records that as the green
proof (no production bug existed); if it fails, the failure is a real defect
and gets fixed before green. Where a bug is *plausible but unverifiable
upfront* (new coverage over correct code), the plan uses a deliberate
mutation probe: temporarily break the suspect production line, confirm the
new test goes red, restore — proving the test can actually fail.

- **e1b — disk FAT write → verify (extension of landed e1).** The in-memory
  round-trip landed (`verify.rs:1014-1058`), but the on-disk FAT path
  (`zsign/src/builder.rs:898-921` `test_sign_macho_fat_default_sha256_only_…`)
  asserts only "both slices signed", never re-parses+verifies the written
  file. Add `MachOFile::parse` + `verify_macho` on the bytes read back from
  disk. Plausible-bug surface: emission slicing on write. Mutation probe:
  corrupt slice-offset arithmetic → red.
- **e2 — sign-IPA → `verify_ipa` end-to-end (OPEN).** `verify_ipa`
  (`zsign/src/verify.rs:390`) extracts to a `TempDir` then verifies — the
  extraction path is untested by any test today (only `verify_bundle` on
  hand-built dirs is). Test: sign a minimal IPA (reuse the zip-builder test
  helper pattern at `ipa/mod.rs:1954-1980`), write it, call `verify_ipa`,
  assert `report.valid()`; plus a tampered-entry negative (flip a byte in
  the sealed executable → `!valid`). Mutation probe: make extraction skip a
  file → red on the tamper half.
- **e3 — 16KB `page_size_log2=14` behavioral test (PARTIAL→fill).** Parse
  acceptance landed; behavior did not. Test drives `check_code_pages`
  (`codesign/verify.rs:875`) with a CD patched to `log2=14`
  (`cd_bytes_with_page_size(14)` helper `:1785`): (a) one full 16384-byte
  page + partial tail → `Matched`; (b) exact-multiple boundary (2×16384) →
  `Matched` (div_ceil edge); (c) corrupted second page → `Mismatch { page_index: 1 }`;
  (d) stored slot count vs computed → `CountMismatch`. Plausible-bug surface:
  the `log2 @ 12..=16 => 1u64 << log2` arm (`:886`) and partial-last-page
  handling have zero behavioral coverage at 14. Mutation probe: force the
  arm to `1u64 << 12` → red.
- **e4 — `should_exclude` / `add_symlink` tables (PARTIAL→fill).** Direct
  table tests at `bundle/code_resources.rs` tests mod:
  `should_exclude` — `_CodeSignature/` prefix, exact `_CodeSignature`,
  `CodeResources` self-exclusion, main-executable exact match (and
  non-match for siblings), custom exclusion prefix hit/miss, nested
  `Frameworks/*.framework/*` **not** excluded; `add_symlink` — excluded
  path returns `false` and inserts nothing, included path returns `true`
  and stores `symlink_target` (observable through `build()` XML), plus
  hash round-trip through the emitted plist. Mutation probe: drop the
  `should_exclude` gate from `add_symlink` → red.

Explicitly **not** added (LANDED, cite only): FAT in-memory round-trip
(`verify.rs:1014`), credential-mismatch (`cert.rs:1600`), Apple-chain
selection (`cert.rs:1150-1273`), DER golden vectors (`der.rs:628-702`),
`page_size_log2` parse acceptance (`verify.rs:1811`), CLI 0/1/2 contract
(`zsign-cli/src/main.rs:1157+`), determinism (`ipa/mod.rs:1867`).

## 6. `assert_cmd` decision (evidence-led, required justification)

**Verdict: REJECT — no new dev-dependency.** Source-verified librarian
findings (2026-09-27):

- assert_cmd 2.2.2 is healthy but feature-frozen (five maintenance
  releases in 7 months; recent commits are Renovate chores).
- Its dependency tree adds **11 crates** (assert_cmd, predicates,
  predicates-core, predicates-tree, difflib, termtree, bstr,
  wait-timeout, anstyle + transitive) to buy: `write_stdin`/`timeout`
  (unused by any of the 46 existing tests), predicate chaining, and
  diff-formatted failure output (`Display` ergonomics, not test signal).
- Its headline binary resolution (`CARGO_BIN_EXE_<name>`) is *unavailable*
  to the current suite: the tests are `#[cfg(test)]` unit tests inside
  `src/main.rs`, where cargo does not set `CARGO_BIN_EXE_*` (verified
  empirically by the librarian). Adopting it would force a ~46-test
  migration into `crates/zsign-cli/tests/` — including splitting ~16
  clap-parse tests that don't spawn at all — for zero new coverage.
- The existing `run_cli` helper (`main.rs:1116-1128`) already captures exit
  code + stdout + stderr with env isolation, and `zsign_bin()`
  (`main.rs:1084`) solves the harder release/debug profile mismatch by
  building first. The 0/1/2 contract is pinned by 26 subprocess tests
  (citations in §1 1e-6).

Cost (11 crates + a 46-test relocation) does not beat benefit (failure-message
formatting). Decision recorded here per brief; no `Cargo.toml` change.

## 7. `hk` gate + skip removal (queue item 5)

- **hk test step: LANDED, verify-and-record only.** `hk.pkl:30-35` defines
  `cargo-test` (`cargo test --workspace`, `exclusive = true`, no glob so it
  always runs), composed into the `check` hook at `hk.pkl:41-43,52-54`.
  Librarian confirmed this is the canonical hk-1.55 shape (matches hk's own
  repo `docs` step and `docs/mise_integration.md` globless-exclusive
  pattern; `Step` field set read from `pkl/Config.pkl:325+`). hk 1.55.0 is
  installed and matches `min_hk_version` (`hk.pkl:4`). No config change.
- **Skip removal:** delete `--skip test_ipa_signing_is_deterministic` and
  its stale two-line justification comment from
  `.github/workflows/ci.yml:59-62` (the comment claims a "known zip
  entry-order nondeterminism flake" — fixed and proven by ZSN-15/ZSN-41;
  the debug test job already runs the test unskipped). Evidence of
  completeness: repo-wide grep for `test_ipa_signing_is_deterministic` and
  `--skip` across `scripts/ .github/ mise.toml hk.pkl` returns **only**
  that one ci.yml hit; `scripts/verify-apple-interop.sh` contains no
  `cargo test` invocation at all (its other content is untouched — noted
  for the orchestrator per brief).
- **Re-confirm:** `test_ipa_signing_is_deterministic` is run (a) scoped,
  (b) inside the full no-skip workspace suite, (c) inside `hk check`.
- Gates may only be **strengthened** in this lane: the final gate list is
  `cargo fmt --all --check` + `cargo clippy --workspace --all-targets -- -D warnings`
  + `cargo test --workspace --no-fail-fast` (**no skip**) + `hk check` if
  runnable. No threshold, filter, or skip is added anywhere; if a test
  fails, the test or the code is fixed, never the gate.

## 8. Acceptance criteria (per queue item)

1. **Re-audit** — §1 matrix complete with file:line evidence; `.tmptmp/`
   scratch ignores present in `.gitignore`; no commits for audit alone.
2. **Plumbing deletions** — `debug_req_slot` gone; the four named tests
   verified already-absent; zero empty `#[cfg(test)]` mods; the three
   legit no-assert tests untouched; full suite green after deletion.
3. **Fixture consolidation** — §3.2 table executed: every "Delete"/"Move"
   row lands with its callers migrated in the same change; both justified
   exceptions documented; `minimal_macho.bin` deleted; a repo grep for the
   deleted fn names returns zero hits; `cargo test --workspace` green.
4. **Credentials** — §4.1 table executed: canon + root + team-OU recipes
   each `OnceLock`-wrapped in the fixtures home; exact dups deleted;
   `fresh_rsa_credentials` preserves the three independence sites; grep
   evidence that no two-calls-one-test caller shares an identity wrongly.
5. **Gap tests** — e1b/e2/e3/e4 exist, first run recorded (red → fixed, or
   green + mutation-probe red → restore); none assert production internals.
6. **hk/skip** — ci.yml edit landed; grep evidence recorded; determinism
   test passes unskipped in scoped + full + `hk check` runs.
7. **Gates** — all four final gates green verbatim, no skips anywhere
   (grep evidence in final report).

## 9. Seams, deviations, deferred

- **Docs lane (zsn46, zero overlap):** README.md and AGENTS.md edits are
  theirs; they read this lane's landed state for any test-count citation.
  Note for docs lane: the workspace has **five** members (four library/bins
  + `fuzz`), not two — current AGENTS.md architecture section is stale.
- **Orchestrator note:** `scripts/verify-apple-interop.sh` had no skip to
  remove and receives no other edits from this lane.
- **Design-vs-actual deviations** are appended here during implementation,
  never silently.
