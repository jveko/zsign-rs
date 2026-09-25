# ZSN-39 Faithful IPA Re-pack — Design

**Lane:** 39 (`zsn39-repack`) · **Base:** `0f07c30` · **Date:** 2026-09-26
**Scope (authoritative brief):** `crates/zsign/src/ipa/{archive.rs, mod.rs}`, `crates/zsign-core/src/bundle/code_resources.rs` + their inline `#[cfg(test)]` modules ONLY.
Explicitly out of scope: `extract.rs` (ZSN-28, read-only), `zsign/src/verify.rs` (ZSN-26, read-only), `builder.rs` (ZSN-35), `signer.rs`/`writer.rs`/`parser.rs` (ZSN-33), `main.rs` (ZSN-5), `codesign/**` (ZSN-29), wasm/web, `.github`.

**Gate (after every task):**
```bash
mkdir -p .tmptmp && TMPDIR=$PWD/.tmptmp cargo test -p zsign-rs ipa -- --skip test_ipa_signing_is_deterministic
```
Item 5 additionally gates on `TMPDIR=$PWD/.tmptmp cargo test -p zsign-core code_resources`. Baseline green before Task 1; no `cargo fmt` / `cargo clippy` / `hk` mid-flight.

---

## 1. Research summary (phase 2 evidence)

### 1.1 Re-anchored citations (scout ReanchorCitations, all vs `0f07c30`)

| Item | Brief citation | Re-anchored | Verdict |
|---|---|---|---|
| 1 repack from selected `.app` | `ipa/mod.rs:257-262` | `mod.rs:265-286`; `extract_ipa` at :277, `resolve_within` :280, **sole repack `create_ipa(&app_bundle, …)` :283**; second caller `sign_folder_to_ipa` :322-326 | CONFIRMED, lines moved |
| 1 multi-`.app` first-match | extract.rs ~615 | `find_app_bundle` :599-627; `return Ok(path)` on first `read_dir` hit :614-616; 0 apps → `Error::Zip(InvalidArchive("No .app bundle found in Payload/"))` :622-624; missing Payload :602-606 | CONFIRMED |
| 2 no `large_file` | `archive.rs:211-218` | options built `archive.rs:207-218`, both branches; repo-wide grep `large_file` → **0 matches**; zip pinned `7.2.0` (Cargo.lock:1749-1750) | CONFIRMED, drifted 2 lines |
| 3 `Path::display()` names | `archive.rs:238-241` | exact: `format!("Payload/{}/{}", app_name, relative_path.display())` at :240; all name sites :221/:238/:240/:248-252/:259/:278 | CONFIRMED |
| 4 `add_symlink` normalizes targets | `archive.rs:254-260` | **REFUTED — writer preserves targets verbatim**: `read_link` :256 → `to_string_lossy` :257 → `add_symlink` :259; no `trim_start_matches`/target `components()` anywhere. The real gap: extractor rejects unsafe targets (`is_safe_symlink_target` extract.rs:96-101, enforced :572-577) while the writer applies no policy | citation stale; gap real, opposite direction |
| 5 hardcoded files2 omissions | `code_resources.rs:436-460` | `build()` :405-479; legacy `files` loop skips only symlinks :412-429; **files2 skip `Info.plist\|PkgInfo\|*.DS_Store` at :437-440**; rules emitted :465/:468; `.lproj/locversion.plist` sealed in BOTH dicts (no emission-side filter anywhere) | CONFIRMED, drifted |

### 1.2 Flow and invariants (scout FlowInvariants)

- `extract_ipa` extracts **every** archive root into `temp_dir` (extract.rs:312-594), then `find_app_bundle` picks one `Payload/*.app` first-match. `IpaSigner::sign` repacks **only that bundle** (mod.rs:283), so everything else on disk in `temp_dir` is dropped: the repack input and the extraction root are different trees.
- Writer-must-satisfy extractor invariants (all READ-ONLY ZSN-28): entry names pass `is_unsafe_entry_name` (extract.rs:120-140) and `enclosed_name()` (:364-372); unique paths / no dir-file conflicts (:385-446); symlinks encoded via unix mode bits (:374-380); targets ≤ `MAX_SYMLINK_TARGET_BYTES = 4096` (:108-109, :529-541) and `is_safe_symlink_target` (no leading `/`, no `..` component, :96-101 enforced :568-576); budgets 2 GiB/entry, 8 GiB total (:227-241); modes re-chmod'ed `& 0o777` (:506-513).
- Emission-must-satisfy verifier invariants (READ-ONLY ZSN-26): `check_code_resources` (verify.rs:751-931) is bidirectional — every `files2`/`files` entry must exist and hash-match **unless the winning rule is Optional/Omit** (:651-660 etc.); every disk file must be in `sealed_set` or resolve to `Omit` (:900-929); **entry-level `optional` is never read by the verifier** — only `rule_action` matters (:622-628, :654-660). `compile_pattern` is a **closed allow-list of 10 keys** (:188-202); any other rule key → hard error `unsupported CodeResources rule` + rule dropped (:239-243). Rule resolution: max weight via `total_cmp`, ties broken strictest-first `Include(0) > Omit(1) > Optional(2)` (`tie_rank` :229-235, `rule_action` :305-321). Structural skips: `_CodeSignature` + main executable only (`is_rule_omitted` :324-338).
- Caller inventory: `create_ipa` production callers = mod.rs:283 + :322 only; `extract_ipa` = mod.rs:277 + verify.rs:402; wasm has zero archive-API users; public re-exports at `lib.rs:58` mean **no signature change to `create_ipa` itself** (new repack path is a separate crate-private function; `lib.rs` untouched).

### 1.3 Test patterns (scout TestPatterns)

- Inline `#[cfg(test)] mod tests` per file (AGENTS.md); **no `tests/` dir anywhere**; zsign-core has no `zip`/`walkdir`/`tempfile` dependency → archive round-trip tests must live in `zsign-rs`; zsign-core tests can only parse plists (`plist` is a normal dep, Cargo.toml:11).
- Canonical round-trip idiom: build zip with `ZipWriter` + explicit `add_directory("Payload/")` (mod.rs:1108, extract.rs:680); sign via `IpaSigner::new(&crate::test_util::test_credentials())` (mod.rs:1213); read back with `ZipArchive::new(File::open(..))` + `by_index` loop (archive.rs:342-352); rejections assert the exact source error prefix and that nothing was written (extract.rs:734-745, :1013-1019).
- `verify.rs` test helpers (`build_signed_bundle*`, `rewrite_code_resources`) are private to that file and unreachable from `ipa`/tests and from zsign-core (dependency direction `zsign-rs → zsign-core`). The regression fixture “`.lproj/locversion.plist` deleted-after-sign stays valid through ZSN-26's verifier” is **already in-tree**: `omitted_locversion_deletion_stays_valid` (verify.rs:1462-1488) — it must stay green after item 5; item 5's own new fixtures live in zsign-core.
- Determinism: `test_ipa_signing_is_deterministic` (mod.rs:1086) fails at base from unsorted WalkDir (ZSN-15); skipped by the gate command. No `ZSN-15` string exists in-tree — the only record is ci.yml:59-62. Our queue does not sort entries, so this stays exactly as-is.
- `SimpleFileOptions::default()` carries wall-clock stamps (`time` feature on), but `create_ipa` pins `zip::DateTime::default()` (archive.rs:211/216) — byte-identity claims may only concern `create_ipa` output, never hand-built fixtures.

### 1.4 External contracts (scout LibrarianContracts; full report `/tmp/lane39-external-contracts.md`)

1. **APPNOTE 6.3.10** (https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT): Zip64 extras “MUST only appear if the corresponding … field is set to 0xFFFF or 0xFFFFFFFF” (§4.5.3); “ZIP64 format MAY be used regardless of the size of a file” (§4.3.9.2) — eager Zip64 is permitted but not mandated; data descriptors are for non-seekable output only (§4.3.9.1) and our writer is seekable.
2. **zip 7.2.0 `large_file` contract** (vendored source `zip-7.2.0/src/`): threshold `ZIP64_BYTES_THR = u32::MAX` (spec.rs:144). Without `large_file(true)`, a ≥4 GiB member fails **mid-`write()`** — `io::Error::other("Large file option has not been set")` with `abort_file()` first (write.rs:601-608), i.e. after the output file already exists; a second guard fires at header rewrite when *compressed* size exceeds the threshold (write.rs:2134-2140, comment: “compressed size … can also be slightly larger”). `large_file(true)` on a **small** member is **not byte-neutral**: 20 B Zip64 extra, sentinel sizes, version-needed bumped to 45 (write.rs:475-476, types.rs:665-666, :1140-1160). `set_auto_large_file()` only affects the data-descriptor (stream) path (write.rs:1177-1181) — useless for our seekable writer. ⇒ **size-gated per-entry `large_file` is the only correct fix**, and the gate must sit below `u32::MAX` by deflate's worst-case expansion margin.
3. **Apple IPA top-level entries** (Apple `ipatool` source `[1P-code]`): `Payload/<App>.app` structurally required; `SwiftSupport/**`, `WatchKitSupport{,2}/WK`, `Symbols/`, `dSYMs/`, `BCSymbolMaps/` must round-trip for upload parity; `iTunesMetadata.plist`, `iTunesArtwork*`, `META-INF/` are store-injected informational (MAY drop, never fabricate); `AppThinning.plist` must not appear in output (ipatool fails with “Should have been removed”). Apple's own unpack `ditto -x -k --noqtn --noacl` discards xattrs/ACLs ⇒ preserving modes + symlinks is the fidelity bar, extended attributes are not.
4. **CodeResources semantics** (TN3126 + apple-oss-distributions/Security): `omit` = content-independence — omit-matched paths are skipped by both signing and verification scans, so they may be added/deleted/modified post-sign (`resources.cpp:207-211`); `optional` = presence-independence (`StaticCode.cpp:1870-1876`); the winning rule is the **highest weight** (`resources.cpp:325-341`, strict `>`); rule-derived `optional` **must be copied onto each per-file dict** (`signer.cpp:536`); Apple's flat-bundle key/weight set matches this repo's `standard_rules2` exactly, and Apple's v1 `rules` carry **no** `Info.plist`/`PkgInfo`/`.DS_Store` omit rules (so v1 `files` legitimately contains `Info.plist`). Only four omit patterns are permitted by Apple; custom omissions fail strict validation with `errSecCSWeakResourceRules` (`bundlediskrep.cpp:696-706`, `StaticCode.cpp:1613`). `_CodeSignature`/main-executable exclusions are injected in code and never written into the plist (`bundlediskrep.cpp:446-463`) — mirroring this repo's `should_exclude` + `is_rule_omitted`.

---

## 2. Design decisions per queue item

Each item lists the phase-1 candidates, the pick, and what was rejected. Diffs are contract-level; exact code lives in the implementation plan.

### Item 1 — Preserve top-level IPA entries; reject ambiguous multi-`.app` archives

**Problem.** `extract_ipa` materialises every archive root in `temp_dir` (extract.rs:312-594) but `sign()` repacks only the selected bundle (`mod.rs:283`), silently dropping `SwiftSupport/`, `iTunesMetadata.plist`, `WatchKitSupport/`, `META-INF/`, sibling roots — and any non-selected `Payload/*.app`. Selection itself is order-dependent (`find_app_bundle` returns the first `read_dir` hit, extract.rs:614-616).

**Candidates:**
- **(A) Repack from the extraction root.** New crate-private `create_ipa_from_root(extraction_root, output, level)` in `archive.rs` walks `temp_dir` itself (entry names = path relative to root, so `Payload/…` and every sibling root are emitted verbatim); `sign()` calls it instead of `create_ipa`. Ambiguity: after extract, scan `temp_dir/Payload` for `*.app` directories; >1 → actionable error naming all candidates.
- (B) Pre-scan the input zip for non-`Payload` roots and stage them separately, merging at repack. Rejected: duplicates extraction logic in the writer, two staging trees to keep in sync, more failure modes — and `extract.rs` cannot be edited to return the root list itself.
- (C) Change `extract_ipa` to detect/report ambiguity and return roots. Rejected: `extract.rs` is ZSN-28, explicitly deferred.

**Pick: (A).** One tree, one walker, no second staging path; everything that extraction validated is exactly what gets re-archived. Ambiguity check lives in `sign()` (mod.rs is in scope) and fires **after** extraction, where `Payload` is concrete on disk; it mirrors `find_app_bundle`'s membership test (`is_dir()` + extension `app`) so the check cannot disagree with the selection it guards. Error class: `Error::Zip(InvalidArchive(Cow::Owned(...)))` — the same class `find_app_bundle` uses for its 0-app error (extract.rs:622-624), message lists the candidates sorted (deterministic). Zero-apps is impossible at that point (extract already failed).
- `create_ipa(bundle, …)` keeps its signature and public contract (`lib.rs:58` untouched) — still used by `sign_folder_to_ipa` (mod.rs:322) and manual extract→sign_folder→repack flows; its `Payload/<name>/…` prefixing and explicit `Payload/` directory entry stay.
- Both public paths share one private entry-writing walker, so items 2/3/4 land once for both.
- Round-trip test: input IPA with root siblings (`SwiftSupport/iphoneos/libswift*`-shaped bytes, `iTunesMetadata.plist`, `META-INF/com.apple.ZipMetadata.plist`) → `sign()` → output zip contains all of them verbatim (exact entry names) **and** `extract_ipa(output)` succeeds. Multi-`.app` fixture: two bare `Payload/*.app` directory entries → `sign()` errors naming both.

**Boundaries stated:** carry-through is verbatim for every root the input contains — including `AppThinning.plist` if an input ever carries one (ipatool rejects such uploads; fabricating a filter is queue expansion, and our inputs never contain it). Export-folder siblings (`ExportOptions.plist` etc.) are files, not zip members, and cannot appear.

### Item 2 — ZIP64 write support for oversized members

**Problem.** `large_file` is never set (archive.rs:207-218, repo-wide grep = 0). On our **seekable** writer a member whose uncompressed size crosses `u32::MAX` fails mid-`io::copy` with `"Large file option has not been set"` **after** `File::create` already truncated the output (write.rs:601-608 aborts the entry; a second guard at write.rs:2134-2140 also watches *compressed* size). Read support exists; write support does not.

**Candidates:**
- **(A) Size-gated per-entry `large_file(true)`:** `if needs_zip64(metadata.len()) { options = options.large_file(true) }` in the regular-file branch, with a pure `needs_zip64(u64) -> bool` seam tested at boundaries.
- (B) `ZipWriter::set_auto_large_file(true)` once per archive. Rejected: in 7.2.0 the flag only reaches the data-descriptor (stream) path (write.rs:1177-1181); our writer is seekable (`seek_possible = true`, write.rs:661), so the mid-write guard would still fire.
- (C) Blanket `large_file(true)` on every entry. Rejected: **not byte-neutral** — every member would gain a 20 B Zip64 extra, sentinel size fields, version-needed 45 (write.rs:475-476, types.rs:665-666/:1140-1160), perturbing the pinned deterministic output (archive.rs:205-217) for zero benefit (APPNOTE §4.5.3 ties extras to sentineled fields; §4.3.9.2 permits but does not require eager Zip64).
- (D) Pre-scan and fail before truncating output. Rejected: the brief allows it only as a fallback; refusing large members is not a feature.

**Pick: (A).** Gate: `ZIP64_SIZE_GATE = u64::from(u32::MAX) - (1 << 20)`; `needs_zip64(len) = len > ZIP64_SIZE_GATE`. The **1 MiB margin** absorbs deflate's worst-case expansion (5 bytes per 65 535-byte stored block ≈ 328 KiB at 4 GiB) so the *compressed*-size guard (write.rs:2134-2140) can never fire while the gate stayed closed; below the gate nothing changes byte-for-byte. Directories and symlink entries are bounded (`≤ 4096`-byte targets) and never need the flag.

**Test seam (justified, as the brief permits).** A 4 GiB fixture is impractical for the routine gate (streams >4 GiB through deflate each run), so:
1. `test_needs_zip64_boundaries` — pure-fn contract: `ZIP64_SIZE_GATE` → false, `+1` → true, `u32::MAX`, `u32::MAX + 1`, 0, typical sizes → correct results. Runs in every gate.
2. `test_create_ipa_zip64_oversized_member` — `#[ignore]`d heavy proof: sparse file (`set_len(u64::from(u32::MAX) + 1)`) of zeros, `CompressionLevel::DEFAULT` (zeros compress to a few MiB, so disk stays small) → `create_ipa` succeeds, read back via `ZipArchive` reports `entry.size() > u32::MAX`. **Red pre-fix**: mid-write `"Large file option has not been set"` + aborted entry. Run once with `--ignored` for the final report as end-to-end evidence; `#[ignore]` keeps the full suite fast (no `#[ignore]` exists in-tree today — this is deliberate opt-in coverage, not a placeholder).

### Item 3 — Canonical `/` ZIP entry names

**Problem.** Names are built with `Path::display()` (archive.rs:240 and the dir branch :248-252) — on Windows that yields `\`-separated members, which the extractor rejects outright (`is_unsafe_entry_name` only splits on `/` and rejects a leading `\`, extract.rs:120-140) → unusable archives produced on Windows.

**Candidates:**
- **(A) Component-join helper:** `fn zip_entry_name(relative: &Path) -> String` = `relative.components()` mapped through `as_os_str().to_string_lossy()` and joined with `'/'`. `Path::components()` splits on both separators on Windows and yields only `Normal` components for strip-prefix results — a *construction-time* guarantee, no runtime platform check.
- (B) Post-hoc `display().to_string().replace(MAIN_SEPARATOR, '/')` — rejected: runtime platform check the brief explicitly forbids, and on Unix a legitimate file name containing `\` would be mangled.
- (C) Leave `display()` and document the Windows limitation — rejected: the defect is exactly the queue item.

**Pick: (A).** The helper is introduced with item 1's shared walker (the new walker needs names from day one; `create_ipa`'s existing `format!` sites migrate to the same helper in the item-3 commit — no second naming convention ever exists in-tree). On Unix the output is byte-identical to today's `display()` join (same lossy conversion, same `/`), so all existing assertions stay green.

**Tests:** unit tests pin `zip_entry_name` for a nested path (exact `'/'`-joined string), a single component, and the empty path; the item-1 round-trip test asserts **exact** entry names (tightening today's loose `ends_with` matching, archive.rs:354-363).

### Item 4 — Symlink targets: one policy, stated invariant

**Problem (re-anchored).** The brief's premise that the writer *normalizes* targets is refuted (§1.1 item 4): targets are written **verbatim** (`archive.rs:254-260`). The real asymmetry: the extractor fails closed on unsafe targets (`is_safe_symlink_target` extract.rs:96-101, enforced :572-577; ≤ 4096 bytes :108-109) while the writer applies **no** policy — so `sign_folder_to_ipa` on a disk tree containing an absolute or `..`-escaping symlink emits an archive **our own `extract_ipa` refuses to re-open**.

**Candidates:**
- **(A) Reject unsafe targets at CREATION** with the extractor's error class (`Error::Io(InvalidData, …)`), validating: no leading `/`, no `..` component, ≤ 4096 bytes, valid UTF-8.
- (B) Preserve raw targets and rely on the extractor to reject them loudly at next sign time (ZSN-28 behavior). Rejected: output would still be an archive we cannot round-trip — the brief's invariant fails by construction; failure also lands late and out of the writer's control.
- (C) Normalize/rewrite unsafe targets at write time (what the brief's stale premise described). Rejected: silently changes symlink semantics — the worst option.

**Pick: (A).** Fail-closed, same error class as the extractor, earliest possible failure, and the sign path is unaffected in practice (its symlinks already passed ZSN-28's gate on extraction; the check bites for folder-based signing and guarantees the invariant for every accepted tree).

**Round-trip invariant (the contract this item establishes):**
> For every tree `create_ipa`/`create_ipa_from_root` accepts, re-extracting the produced archive through `extract_ipa` succeeds and reproduces the tree's symlinks byte-for-byte — targets verbatim, no normalization. A tree whose symlink target is absolute, contains a `..` component, exceeds `MAX_SYMLINK_TARGET_BYTES` (4096), or is not valid UTF-8 is rejected at creation with `Error::Io(InvalidData)` naming the entry.

Boundary (documented, out of queue): the invariant covers **symlink targets**, per the brief. *Entry names* on the folder-signing path come straight from the filesystem; a on-disk name that `is_unsafe_entry_name` rejects (e.g. a leading `\` on Unix) is a pre-existing gap shared with today's writer and is not queue scope — in the `sign()` flow names are already extractor-vetted because they come from extraction itself.

**Validation is mirrored, not shared:** `extract.rs`'s predicate and `MAX_SYMLINK_TARGET_BYTES` are private and the file is ZSN-28-deferred, so `archive.rs` carries an equivalent private predicate + constant with comments citing the extractor. (Same policy, two crate-private copies — the alternative, editing `extract.rs` to export, is forbidden.)

**Tests (`#[cfg(unix)]`):** (a) framework-style round trip: `Versions/Current → A` and `X → Versions/Current/X` written by `create_ipa`, re-extracted, `read_link` equals the original targets exactly; (b) creation rejects `/etc/passwd` (absolute) and `../escape` (escaping) with message naming the entry — **red pre-fix** (today creation succeeds and the output fails extraction); (c) pure-fn boundary test for 4096 → ok, 4097 → rejected, non-UTF-8 → rejected (unfixtureable on disk: Linux `symlink(2)` caps targets below 4096, so the seam is the validator itself).

### Item 5 — Emission-side omission: entries agree with declared rules

**Problem.** `build()` (code_resources.rs:405-479) hardcodes the `files2` skip (`Info.plist|PkgInfo|*.DS_Store`, :437-440) while `.lproj/locversion.plist` is sealed in **both** dicts although `rules`/`rules2` declare it `omit` (:96-102/:146-152); `optional` is set by substring (`path.contains(".lproj/")`, :418-424/:455-458) instead of by rule, so `Base.lproj` entries are marked `optional` even though `^Base\.lproj/` (weight 1010) beats `^.*\.lproj/` (optional, 1000); and `exclude()` patterns never appear in the emitted rules, so excluded on-disk files are neither sealed nor rule-omitted — the exact `unsealed` failure `check_code_resources` reports (verify.rs:900-929).

**Candidates:**
- **(A) Rule-driven emission:** `build()` evaluates the rule sets it emits (same weight `total_cmp` + `tie_rank` resolution as ZSN-26) and derives every per-dict decision from the winning rule; plus a matching `omit` rule emitted for every `exclude()` pattern.
- (B) Change the standard rules to match current entries (drop the locversion omit, etc.) — rejected: alters weight/pattern semantics the brief pins and diverges from Apple's flat-bundle template (§1.4 item 4).
- (C) Delete `exclude()` instead of declaring it — rejected: the brief's fixture requires `exclude()` to "get consistent rules"; the API has doc+wrapper callers (zsign bundle wrapper :115-118).

**Pick: (A).**

**Rule-driven sealing mechanics.** `build()` constructs `rules = standard_rules()` and `rules2 = standard_rules2()`, appends exclusion rules (below), then for each collected entry consults the winning action of the dict it is about to write:
- `files` (legacy, evaluated against `rules`): `Omit` → drop (this is the **change**: `.lproj/locversion.plist` leaves `files`); `Optional` → `{hash, optional: true}` (non-Base `.lproj`, unchanged); `Include` → bare SHA-1 `Data` (`Base.lproj` switches from dict+optional to bare data — matching Apple, who copy rule-derived `optional` onto entries, `signer.cpp:536`; v1 rules carry no `Info.plist` omit so `Info.plist`/`PkgInfo`/`.DS_Store` stay in `files`, unchanged).
- `files2` (evaluated against `rules2`): `Omit` → drop — this subsumes the hardcoded skip (`Info.plist`, `PkgInfo`, `.DS_Store` by rule, same observable result) **and** drops `.lproj/locversion.plist` (the actual contradiction); `Optional` → `optional: true` on the dict (replaces the substring test; `Base.lproj` correctly loses it); `Include` → dict without `optional`.
- The resolver mirrors ZSN-26 exactly — max weight via `total_cmp`, ties by `tie_rank` `Include(0) < Omit(1) < Optional(2)`, weight-only dicts resolve to `Include` — over the *same* key vocabulary the matcher supports (`^.*`, `.lproj/` contains, locversion with the deliberately unescaped dot before `plist` (verify.rs:206-213), `Base.lproj/` prefix, exacts, dSYM, `.DS_Store`). `zsign-core` cannot depend on `zsign-rs`, and `verify.rs` is deferred, so this is a deliberate mirror of ~60 lines with a comment citing verify.rs — the only feasible reading of "evaluate the emitted rule set while sealing entries". Neither dict's keys nor weights change, so `tie_rank` ordering expectations are untouched.

**Custom `exclude()` → matching omit rule.** For each `exclude()` pattern `P`, insert into **both** `rules` and `rules2`: key `^` + regex-escaped literal `P`, spec `{omit: true, weight: 2000.0}`. The key encodes exactly `should_exclude`'s `starts_with(P)` semantics (prefix regex over the escaped literal), weight 2000 ties the most-specific standard class (`.DS_Store` omit 2000) and beats every other standard weight, and `{omit, weight}` is a spec shape ZSN-26's `compile_rules` accepts (keys ⊆ `omit|optional|weight`, verify.rs:251-254).

**Two consequences stated honestly (both documented, neither affects default output):**
1. **ZSN-26's closed pattern allow-list** (verify.rs:188-202) does not know `^<custom>` keys: verifying a bundle signed with a custom exclusion reports `unsupported CodeResources rule: <key>` — a *loud* hard error replacing today's silent `unsealed` divergence (both fail; the new failure declares intent). There are **zero production `exclude()` callers** (doc examples only; wasm never excludes), so default signed output remains verify-clean. There is no key form that both encodes an arbitrary prefix and passes the fixed allow-list, and `verify.rs` is deferred — emitting the rule is the brief's mandated option.
2. **Apple strict validation rejects custom omit rules** (`errSecCSWeakResourceRules`, bundlediskrep.cpp:696-706) — i.e. `exclude()` was *already* outside Apple's envelope ("it is no longer possible to exclude parts of a bundle from the signature", TN2206). The change makes the document internally consistent instead of silently contradictory.

**Observable changes vs today:** (i) `.lproj/locversion.plist` no longer sealed in `files`/`files2`; (ii) `Base.lproj` entries lose the spurious `optional` (dicts in `files2`, bare data in `files`); (iii) exclusion rules appear when (and only when) `exclude()` was called; (iv) the hardcoded skip is deleted. Everything else — key sets, weights, `.lproj` optional flags, `.DS_Store`/`Info.plist`/`PkgInfo` dispositions, symlink handling, `files()`/`file_count()` (they expose `self.files`, untouched) — is observably identical.

**Fixtures:**
- zsign-core inline tests parse `build()` output with `plist::from_bytes` (dep available, no manifest change): (a) rule-driven omission — `Omit` paths absent from the right dicts, `Optional`/`Include` shapes correct, raw vs dict forms per table above (red pre-fix: locversion present, `Base.lproj` optional); (b) `exclude("DebugResources/")` — excluded path absent from both dicts, `^DebugResources/` rule present with `{omit, 2000}` in both dicts, resolver returns `Omit` for `DebugResources/x` and `Include` for others (red pre-fix: no rule key); (c) resolver contract — standard weight/tie cases including an equal-weight `Include`-vs-`Omit` tie pinned to `tie_rank` order.
- **ZSN-26-side regression already exists and must stay green:** `omitted_locversion_deletion_stays_valid` (verify.rs:1462), `optional_lproj_deletion_after_signing_stays_valid` (:1413), `base_lproj_deletion_is_not_optional` (:1437), `nested_ds_store_is_not_flagged_unsealed` (:1325) — the first now passes because the entry is absent rather than tolerated, the others unchanged. Its comment (verify.rs:1464-1466, "the builder seals … locversion") becomes stale after this fix; `verify.rs` is deferred, so the stale comment is recorded in §3 as a follow-up observation rather than edited.

---

## 3. Findings and observations outside this queue

1. **ZSN-15 (determinism) is untouched.** The repack walk remains unsorted `WalkDir` (archive.rs:222-224); `test_ipa_signing_is_deterministic` (mod.rs:1086) keeps failing for its pre-existing root cause. Switching `sign()`'s walk root from the bundle to the extraction root changes *which* unsorted walk runs but not the mechanism — no new order-stability claim, no regression: the test is skipped by the gate exactly as at base. Reported to ZSN-15 as a finding, not fixed here.
2. **Stale comment in deferred `verify.rs`.** `omitted_locversion_deletion_stays_valid`'s comment (verify.rs:1464-1466) states the builder seals `*.lproj/locversion.plist`; after item 5 the entry is absent. The test's assertions remain valid (absence is trivially tolerated under the omit rule). Editing `verify.rs` is forbidden; flagged for the ZSN-26 owner.
3. **Writer/extractor name-safety gap (pre-existing).** A on-disk file name starting with `\` (legal on Unix) would be emitted by the folder-signing path and rejected by `is_unsafe_entry_name` on re-extraction. Same gap exists at base; the `sign()` path is safe because names come from extraction, which already vetted them. Out of queue scope (item 3 covers separators, not adversarial local names).
4. **`create_ipa_from_root` is deliberately crate-private.** It is an implementation detail of `IpaSigner::sign`; keeping it `pub(crate)` avoids growing the `lib.rs:58` public surface and avoids a doc-test/API commitment the brief did not ask for.
5. **`version.plist` legacy key is unescaped** (`^version.plist$`, code_resources.rs:108-111) versus Apple's escaped `^version\.plist$`. It cannot change any emission decision (both matching and non-matching resolve to `Include` under `^.*`), ZSN-26 never compiles the legacy dict when `rules2` exists, and `test_rules_structure` pins the current string — left untouched (no weight/pattern semantics changes per the brief).

## 4. Delivery shape

Plan: `docs/superpowers/plans/2026-09-25-repack-fidelity.md`. Six sequential tasks covering the five queue items (item 1 = two tasks), each: Tester-red → implementer-green → scoped gate → controller commit. Commit series (subjects only; ticket ID in subject, never in code comments):

1. `fix(ipa): reject ambiguous multi-app ipa archives (ZSN-39)`
2. `fix(ipa): carry extraction-root entries through repack (ZSN-39)`
3. `fix(ipa): enable zip64 for oversized archive members (ZSN-39)`
4. `fix(ipa): build zip entry names from path components (ZSN-39)`
5. `fix(ipa): reject unsafe symlink targets at archive creation (ZSN-39)`
6. `fix(bundle): emit code resources entries consistent with declared rules (ZSN-39)`

No merges, no pushes — the orchestrator lands the branch. Gate evidence and plan-vs-actual deviations go in the final report.
