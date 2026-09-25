# ZSN-33 FAT/Universal Signing + execSegFlags (incl. inlined ZSN-13) — Design

**Lane:** 33 (`zsn33-fat-universal`) · **Base:** `main @ 0f07c30` · **Date:** 2026-09-26
**Scope (authoritative brief):** `crates/zsign-core/src/macho/{signer.rs, writer.rs, parser.rs, fixtures.rs}`, `crates/zsign/src/builder.rs` + its inline tests ONLY.
Explicitly out of scope: `codesign/**`, `macho/verify.rs`, `constants.rs` (ZSN-29 lane), `crypto/**`, `ipa/**` (ZSN-39), `main.rs` (ZSN-5), `der.rs`, `fuzz/**` (ZSN-4), wasm/README, wave-4 follow-ups ZSN-34/35.

**Gate (every task):** `mkdir -p .tmptmp && TMPDIR=$PWD/.tmptmp cargo test -p zsign-core macho -- --skip test_ipa_signing_is_deterministic` (facade tasks additionally run scoped `TMPDIR=$PWD/.tmptmp cargo test -p zsign <module>`); existing 59+ core macho tests must stay green. No `cargo fmt` / `cargo clippy` / `hk` mid-flight (orchestrator gates at merge).

---

## 1. Research summary (phase-2 evidence)

Five parallel read-only agents (4 scouts + 1 librarian) re-anchored every brief citation against `0f07c30`; all external contracts were verified against Apple open source (`apple-oss-distributions`: cctools, Security, xnu, ld64, dyld) and upstream `zhlynn/zsign @ 614caa8`.

### 1.1 Re-anchored citations (brief review dated 2026-09-24 vs current source)

| Queue item | Brief citation | Re-anchored at 0f07c30 | Verdict |
|---|---|---|---|
| 1 `sign_macho_sha256_only` guard | signer.rs:328-333 | signer.rs:329-333 (msg at 331) | CONFIRMED, ±1 line |
| 1 `sign_slice_complete` flag | — (undocumented) | already takes `sha256_only: bool` at signer.rs:416; only `true` call site signer.rs:345; `sign_macho_all_slices` hardcodes `false` at :399 | NEW FACT |
| 2 `sign_any_macho` len==1 branch | signer.rs:179-188 | signer.rs:179-199 (thin 180-188; FAT 190-198 + `embed_signature_fat` :199) | CONFIRMED |
| 3 `embed_signature` first-arch-only | writer.rs:241-269 | writer.rs:288-310 (first arch :289-296, unchecked `&data[offset..offset+size]` :297, reassemble with 1 slice :309) | CONFIRMED |
| 3 unsigned fill-in | writer.rs:313-320 | writer.rs:355-361 (`slice_index == i` only at :355; missing → raw unsigned copy :358-360) | CONFIRMED |
| 4 hardcoded 16 KiB | writer.rs:323-347 | writer.rs:364-372 (`align_to(header_size, 0x4000)` :366, per-slice :371); `arch.align` copied verbatim :388; `total_size` u32 wrap :374 | CONFIRMED |
| 5 code_length clamp | parser.rs:312-321 | clamp is parser.rs:338-371 (312/317-328 are LC/LINKEDIT bounds checks); `code_length = dataoff.unwrap_or(slice_content_end)` :373-375; **thin unsigned already uses whole file** (base_offset==0 → `slice_data = data` :338-340) — the bug is FAT-only | CITATION DRIFT, bug CONFIRMED (FAT only) |
| 6 unchecked public indexing | writer.rs:253-256 | :297 (embed_signature FAT), :360 (unsigned fill-in), :440/:935/:1140 (`data[..code_length]` from raw `cs.dataoff` in embed_single, prepare_single, **prepare_code_with_metadata** — dataoff read at :1121, slice at :1140), `write_u32_be` :399-401 unchecked (five call sites :384-388); u64 underflow sites :955/:1159/:1261 | CONFIRMED + 4 more sites |
| 7 `inject_dylib_command` thin guard | writer.rs:557-562 | writer.rs:584-593 (32-byte header :584-588; magic-only `MH_MAGIC_64` check :590-593 — FAT gets misleading "not a 64-bit Mach-O") | CONFIRMED, drifted +27 |
| 8 builder direct-sign routing | builder.rs:318-317 | builder.rs:297-346; branches adhoc :307-315 → sha256_only :319-328 → sign_macho :329-338; **no FAT routing anywhere** | CONFIRMED |
| 9 execSeg emission | signer.rs:825-826 | signer.rs:825-827 in `build_code_directory_from_hashes` (:775-860); flags decision :783-790; parser inputs `text_segment_base`(:TEXT.vmaddr) :272/:285, `text_segment_size`(:TEXT.filesize) :271/:284 | CONFIRMED |
| 10 reserve/retry plumbing | signer.rs (R1/R3) | estimate `compute_superblob_reserved_size` :419 → :746-773; realloc :424-428 (initial) / :557-561 (retry `padded_sig_size` :552); prepare guard writer.rs:1235-1240; realloc formula reserve writer.rs:994-996 **never sees the signer's estimate** | CONFIRMED |

Structural facts that shape the design:

- **Container dispatch today keys on `slices().len()`**, not `macho.is_fat()` (public accessor parser.rs:419-421): a one-arch FAT passes every `len()!=1` guard and is silently stripped to thin by `sign_macho`/`sign_macho_adhoc`/`sign_macho_sha256_only` and by `sign_any_macho`'s thin branch (signer.rs:179-188).
- **Public signatures cannot change** for functions called outside lane files: `sign_macho`, `sign_macho_adhoc`, `sign_macho_sha256_only`, `sign_any_macho`, `sign_macho_all_slices` are wrapped by `crates/zsign/src/macho/mod.rs` (out of scope) and called by `ipa/mod.rs` (ZSN-39, active) and `zsign-wasm` (out of scope). Fixes must therefore land as **internal dispatch behind unchanged public signatures**, or as new private helpers.
- **No test anywhere pins the thin-signer guard messages** (`grep "only supports single-arch"`: source lines only; wasm's FAT refusal tests pin wasm's own pre-guard `ZSIGN_FAT_UNSUPPORTED`, which runs before core and is unaffected). Guard changes are test-safe.
- **The signer's per-slice SHA-256-only machinery already exists**: `sign_slice_complete(.., sha256_only)` gates SHA-1 CD omission (signer.rs:479-490), CMS binding (512-525) and slot omission (536-538); only the FAT plumbing is missing.
- **`SignedSlice` carries `slice_index`, `offset`, `original_size`, `signed_data`** (writer.rs:31-40) but embed matches on `slice_index` alone; there is no `cpu_type` field, and `ArchSlice` has no `cpusubtype` (identity = offset + size + cputype).
- **execSeg flags are already per-slice and already correct**: signer.rs:783-790 sets `CS_EXECSEG_MAIN_BINARY` (0x1, `codesign/constants.rs:249`) iff `slice.is_executable`, ORs `ALLOW_UNSIGNED` iff `ctx.has_get_task_allow` — parity with Apple `signer.cpp:650/808` (`mainBinary = type() == MH_EXECUTE`). What is missing is **test coverage of the emission** and the R2 base switch.
- **The verifier enforcement for execSeg lives in `macho/verify.rs:288-363`** (the brief's "codesign/verify.rs" label is wrong — `codesign/verify.rs` only parses the fields at :619-623). It is an OR-of-two-arms check (`vm_matches` :296 **or** `file_space_ok` :299-302), so fileoff-based emission is accepted today via the plausibility arm (traced for every fixture); `errors.len()==1` tripwires (macho/verify.rs:1139, facade verify.rs:1126/:1174/:1241) are the blast radius.
- **Fixture/test terrain**: `fixtures.rs` is thin-arm64-only (7 builders, all `MH_EXECUTE`); two-arch FAT bytes are hand-assembled 3× (signer.rs:1230 `make_fat_with_encrypted_second_slice` [encrypted slice], macho/verify.rs:795 `build_two_slice_fat` [read-only file], wasm lib.rs:864); zero FAT tests exist in writer.rs; `local_test_credentials` lives in **facade** verify.rs:954 (core equivalent `rsa_credentials()` macho/verify.rs:573; signer's own `test_credentials()` signer.rs:912).

### 1.2 External contracts (librarian, source-verified with citations)

1. **FAT fields are big-endian on disk** — `fat.h:36-37` "always written and read to/from disk in big-endian order"; `swap_fat_arch` swaps all five fields (`bytesex.c:302-320`); Apple's own fixture `cctools/tests/data/echo.fat` starts `ca fe ba be`. (ZSN-32's refuted claim stands: BE is the only correct encoding.)
2. **`align` is the power-of-two exponent; offset must be a multiple of `2^align`** — lipo `misc/lipo.c:1111-1118` fatals "not aligned on its alignment (2^%u)"; otool/nm `libstuff/ofile.c:2801-2807` same; classic ld `pass1.c:927-931`. lipo **repacks by rounding each slice to its own `1 << align`** (`lipo.c:891/1023`: `offset = rnd(offset, 1 << thin_files[i].fat_arch.align)`); it accepts an exponent up to `MAXSECTALIGN = 15` (`lipo.c:74-75,1104-1109`) and derives arm64 = 14, x86_64 = 12 by default (`get_align_64`). dyld ignores `align` but requires arm64 slice offsets 16 KiB-aligned (`MachOFile.cpp:158-167`); codesign additionally requires **the gap preceding each slice** `< 1 << align` **of that same slice** (`macho++.cpp:619-623`, checked against the iterator's own entry) and **zero gap bytes** and **no data after the last slice** (`macho++.cpp:619-666`, violations → `errSecCSBadMainExecutable` via `machorep.cpp:601-603`).
3. **Single-arch FAT is legal everywhere** — lipo emits `nfat_arch = nthin_files` with no minimum (`lipo.c:886-887`), dyld/ld64/codesign loops are count-driven (`MachOFile.cpp:188-215`, `FatFile.cpp:74-90`, `macho++.h` `isUniversal() = mArchList != NULL`); xnu has zero FAT handling. The one-arch container must therefore be preserved, not stripped.
4. **`CS_EXECSEG_MAIN_BINARY == 0x1`; Apple sets it iff `MH_EXECUTE`** — `cs_blobs.h:80`; `signer.cpp:650` `mainBinary = type() == MH_EXECUTE` → `signer.cpp:808` `builder.execSeg(base, limit, mainBinary ? kSecCodeExecSegMainBinary : 0)`. Upstream zsign issue #396 is CLOSED with exactly that fix in master (`archo.cpp:380-386`, "regardless of signing flavour"). Our signer already implements this per slice.
5. **`execSegBase`/`execSegLimit` are `__TEXT.fileoff`/`__TEXT.filesize`** — `machorep.cpp:180-203` reads `fileoff`, `:205-227` reads `filesize`; field comments `cs_blobs.h:244-245` ("offset/limit of executable segment"); builder member is literally `mExecSegOffset` (`cdbuilder.h:114`). Values are **slice-relative** (each fat member is a self-contained Mach-O). Our parser currently feeds vmaddr to base (contradiction = R2).
6. **SHA-256-only CodeDirectory is Apple's own default for modern targets** — `signer.cpp:369-370` "default to SHA256 only"; SHA-1 is added as an alternate CD only when some slice's minOS predates iOS 11 / macOS 10.11.4 (`machorep.cpp:105-153`); kernel picks strongest and rejects duplicate hash types (`ubc_subr.c:226-231,588-590`); TN3126: universal binaries sign "each architecture independently, each with its own code directory".
7. **Nothing contradicts big-endian FAT** — all Apple readers/writers agree; only read-tolerance for byte-swapped input exists (invalid little-endian-written fat headers). `FAT_MAGIC_64` is also BE, but goblin 0.10.7 has no fat64 support (parse would fail — fail-closed).

Additional Apple invariants the reassembly must honor (from the same sources): gap bytes and header padding zero (our `vec![0u8; total]` guarantees both), the 20 probe bytes at `8 + 20*nfat_arch` zero-filled (guaranteed by zero-fill + writing only `n` entries), `fat_arch.cputype/cpusubtype` unchanged so they keep matching slice headers, and output ending exactly at last `offset+size` (our `total_size` construction).

Known divergences deliberately **not** touched (out of queue, recorded for follow-ups): page-hash size is hardcoded 4 KiB (`codesign/constants.rs:305-308`) while Apple uses 16 KiB page hashes for arm64 (`machorep.cpp:574-591`); Apple gates execSeg emission on `platform != 0` (`machorep.cpp:171-177`) while we always emit; Apple ORs entitlement-derived execSeg bits for non-executables too (`signer.cpp:1092-1098`) while we gate them behind `slice.is_executable`.

---

## 2. Design decisions per queue item

Each item lists the candidates considered in phase 1 (internal brainstorm), the pick, and what was rejected. Queue order = implementation order; every item is an independently-green commit series.

### Item 1 — Per-slice SHA-256-only FAT signing

**Problem.** `sign_macho_sha256_only` rejects `slices().len() != 1` (signer.rs:329-333) while `IpaSigner.sha256_only` defaults to `true` (ipa/mod.rs:148/:164) and dispatches there (ipa/mod.rs:1006-1016) ⇒ every universal executable fails on the **default IPA path**, even though per-slice sha256-only machinery already exists (`sign_slice_complete(.., sha256_only)` signer.rs:416, hardwired `false` in `sign_macho_all_slices` :399).

**Candidates.**
- **(A) Internal dispatch behind the unchanged signature.** If `macho.is_fat()`, `sign_macho_sha256_only` signs every slice through a shared private all-slices helper carrying `sha256_only=true`, then reassembles via `embed_signature_fat`. No public signature changes ⇒ zero edits in `ipa/**`, `crates/zsign/src/macho/mod.rs`, `zsign-wasm` (all out of scope).
- (B) Add a `sha256_only: bool` parameter to `sign_macho_all_slices` / `sign_any_macho`. **Rejected:** both are re-exported and wrapped by `crates/zsign/src/macho/mod.rs` (out of scope) and called by `ipa/mod.rs:1018` and `zsign-wasm` (out of scope) — a signature change forces edits in other lanes' active files.
- (C) Route FAT with default settings to the dual-digest signer instead. **Rejected:** silently changes the documented default (sha256-only) and still leaves the IPA sha256 branch (`ipa/mod.rs:1008`) failing on FAT.

**Pick: (A).** New private `sign_all_slices_impl(..., sha256_only: bool)` holds today's `sign_macho_all_slices` body (rayon loop, `slice_index` patching) plus the flag; public `sign_macho_all_slices` delegates with `false` (byte-identical behavior). `sign_macho_sha256_only` gains a `macho.is_fat()` branch that passes entitlements through **unchanged** — identical to its own thin path (one convention per function; `sign_any_macho` keeps its own first-slice `EMPTY_ENTITLEMENTS` selection before it branches) — calls the impl with `true`, and returns `embed_signature_fat(...)`. Architecture order is preserved because `slices()` order is fat-table order and `embed_fat_from_signed_slices` writes entries in table order (validated by test).

### Item 2 — FAT dispatch by container kind

**Problem.** `sign_any_macho` branches on `slices().len() == 1` (signer.rs:179): a one-arch FAT takes the thin path, returns the embedded Mach-O, and **silently strips the FAT header**. The same strip exists behind the other thin-signer guards (`sign_macho` :256, `sign_macho_adhoc` :298, `sign_macho_sha256_only` :329) because `len() == 1` is indistinguishable from a one-arch container. Single-arch FAT is legal (librarian fact 3), so the FAT-capable path must preserve it rather than strip.

**Candidates.**
- **(A) Dispatch on `macho.is_fat()` (public accessor parser.rs:419-421): `sign_any_macho` routes containers through the all-slices helper + `embed_signature_fat` regardless of arch count; the thin-only signers (`sign_macho`, `sign_macho_adhoc`) replace their `len()!=1` guard with an `is_fat()` rejection** (message points at `sign_any_macho`), so a container can never be silently stripped by a thin-only entry point.
- (B) Keep count-based dispatch and special-case `nfat_arch == 1` only inside `embed_*`. **Rejected:** the strip happens in the signer's return value before any embed runs; re-wrapping thin output would need a second container path.
- (C) Make `sign_macho`/`sign_macho_adhoc` FAT-capable (full dispatch like sha256). **Rejected as scope expansion:** the brief names dispatch for `sign_any_macho` and sha256-only; adhoc-on-FAT is a new feature (no queue item demands it), and fail-closed rejection of containers from thin-only APIs fixes the silent strip without inventing un-requested behavior. Documented as a known limitation (§5).

**Pick: (A).** One rule everywhere: **container kind decides, slice count never does** — FAT-capable entries (`sign_any_macho`, `sign_macho_sha256_only`) dispatch on `is_fat()` and preserve the container; thin-only entries (`sign_macho`, `sign_macho_adhoc`) reject it with a pointer to the FAT-capable entry. Guard-message changes are test-safe (research §1.1: no test pins them).

### Item 3 — Reassembly integrity

**Problem.** `embed_signature` signs only the first FAT arch (writer.rs:288-310) and hands a 1-element set to `embed_fat_from_signed_slices`, which re-emits every other arch from **original unsigned bytes** (writer.rs:358-360) — a partially signed universal with no error. Matching is by `slice_index` alone (:355); `SignedSlice.offset/original_size` are populated but never validated.

**Candidates.**
- **(A) Strict full-set validation:** `embed_fat_from_signed_slices` requires exactly one `SignedSlice` per arch index (`signed_slices.len() == arches.len()` + per-index find; missing/duplicate/extra ⇒ `Err`), and each must match the fat table's `offset`, `size`, and `cputype`. The unsigned fallback is deleted. `SignedSlice` gains `cpu_type: u32` (populated from `ArchSlice.cpu_type` where signed slices are built, signer.rs:667-683, and from the parsed slice header in `embed_signature` :302-307). The thin branch of `embed_signature_fat` validates exactly-one + `original_size == data.len()`.
- (B) Keep the unsigned fallback but only when `slice_index` was never supplied (tolerant subset). **Rejected:** any missing entry means an unsigned slice ships in a "signed" universal — the defect the brief names; tolerance re-opens it.
- (C) Sign all arches inside `embed_signature` by re-invoking the signer. **Rejected:** the writer has no credentials/identifier context (layering violation) and receives exactly one signature blob.

**Pick: (A).** With the fallback gone, `embed_signature` on a multi-arch FAT automatically fails (1 slice vs N arches) instead of half-signing; on a one-arch FAT it becomes *correct* (the single arch is fully signed, container preserved) — no special case needed. Identity = offset + size + cputype because `ArchSlice` exposes no `cpusubtype`; the fat-table rewrite copies `cpusubtype` verbatim so it keeps matching the untouched slice header (librarian invariant 3).

### Item 4 — Per-arch alignment

**Problem.** Reassembly places every slice at `align_to(cursor, 0x4000)` (writer.rs:366/:371) while writing the original `arch.align` exponent back verbatim (:388) ⇒ declared alignment and actual placement disagree for any exponent ≠ 14; an input declaring 15 (legal, lipo `MAXSECTALIGN=15`) is emitted with 16 KiB placement and is rejected by lipo/otool ("not aligned on its alignment"). All offset arithmetic is unchecked (`len() as u32` :369, `(current_offset + size) as u32` :371, `*o + *s` :374 — release-mode wrap).

**Candidates.**
- **(A) Round each slice to its own declared alignment:** `offset_i = align_up(cursor, 1 << align_i)` with checked math, exactly like lipo (`offset = rnd(offset, 1 << align)`, `lipo.c:891`), reusing `arch.align` unchanged; `Err` on exponent ≥ 32 or any offset/size exceeding `u32::MAX`.
- (B) Align to `max(all aligns)` (uniform stride). **Rejected:** needlessly inflates output for mixed low-align inputs, diverges from lipo, and still leaves placement computed from a rule the table doesn't declare.
- (C) Keep 16 KiB placement and clamp the written exponent to ≤ 14. **Rejected:** mutates declared metadata to paper over placement (rewrites the `fat_arch.align` the caller handed us) and still fails inputs that require placement other than 16 KiB multiples.

**Pick: (A).** Gap invariant holds by construction: `gap = offset_i - end_{i-1} < 2^align_i` (satisfies codesign's `gap < 1 << align` check) and `offset_i % 2^align_i == 0` (satisfies lipo/otool); header padding and gaps are zero-filled by `vec![0u8; total]`; output ends exactly at last `offset+size` (no trailing data — codesign strict). Real Apple inputs declare 14 for arm64, so today's 16 KiB placement coincides for them.

### Item 5 — Trailing-byte preservation

**Problem.** For a FAT slice, `parse_single` derives `code_length` from `max(segment.fileoff+filesize)` clamped to the declared size (parser.rs:338-371 → :373-375); trailing bytes inside the declared slice fall outside `code_length`, so they are (i) not hashed, (ii) dropped when realloc rebuilds `data[..code_length]` (writer.rs:1009), or (iii) zero-filled when the preserve path re-extends to the captured target (signer.rs:677 → writer.rs:723-743). Thin unsigned inputs already use the whole file (`base_offset == 0` ⇒ `slice_data = data`, :338-340) — the defect is FAT-only.

**Candidates.**
- **(A) Derive the unsigned boundary from the declared arch size:** `code_length = code_sig_offset.unwrap_or(declared_size)`; the content-end clamp (parser.rs:338-371) becomes dead and is deleted (its bounds guarantees are already provided by `MachOFile::parse`'s per-arch validation parser.rs:186-201 and the LC/LINKEDIT checks :306-328). Trailing bytes become part of hashed content; the signature is placed after them.
- (B) Reject slices with trailing content. **Rejected:** legitimate padded slices (including lipo-produced ones) would fail to sign; preservation is strictly more useful and matches thin behavior.
- (C) Preserve tail bytes by copying them around the signature post-hoc. **Rejected:** a bespoke relocation step nothing else enforces; deriving the boundary at parse time makes tail handling identical to thin — one convention.

**Pick: (A).** Consequences: unsigned FAT slices always re-allocate (`has_enough_signature_space` room `len - code_length` becomes 0 — the "tail counts as free space" illusion at writer.rs:270-273 disappears); the rebuild path carries the tail inside `data[..code_length]`; `ArchSlice.size` (declared) stays the reassembly/identity boundary; container-level trailing data beyond the last slice is intentionally *dropped* by reassembly (Apple codesign: "Extra data after the last slice" is a strict-validation failure — librarian invariant 2).

### Item 6 — Hostile FAT bounds

**Problem.** Public writer entry points index by raw `fat_arch` values: `&data[offset..offset+size]` (writer.rs:297, :360), unguarded `data[..code_length]` from raw `cs.dataoff` (:440, :935, and :1140 in `prepare_code_with_metadata` — dataoff read at :1121), unchecked `write_u32_be` (:399-401, five call sites :384-388), u32 offset arithmetic (:369/:371/:374), and `prepare` paths with plain `u64` subtraction of `seg.fileoff` (:955/:1159/:1261 — debug panic on hostile `__LINKEDIT.fileoff`). Malformed arch headers panic instead of erroring.

**Candidates.**
- **(A) One table-validation helper + checked primitives everywhere in writer.rs:** private `validate_fat_arches(arches, data)` doing per-arch `checked_add` + `data.get(offset..end)` (truncated/malformed ⇒ `Err`, pattern: parser.rs:186-201) and pairwise overlap rejection over sorted ranges; called by `embed_signature` (FAT arm) and `embed_fat_from_signed_slices`. Reassembly arithmetic moves to checked `usize` (item 4); `write_u32_be` is deleted in favor of the existing checked `write_u32(.., big_endian)` (writer.rs:1314); `data[..code_length]` sites gain the `code_length <= data.len()` guard realloc already has (writer.rs:154-159); the three `u64` subtractions become `checked_sub ⇒ Err`.
- (B) Validate once at `MachOFile::parse` only. **Rejected:** `embed_signature`/`embed_signature_fat`/`prepare_*` are public entry points that re-parse raw bytes with goblin and bypass `MachOFile` entirely; the brief targets writer.rs specifically (ZSN-29 owns `codesign/*` arithmetic).
- (C) Keep indexing but catch panics. **Rejected:** `catch_unwind` is not a contract; repo rules demand clean `Err`.

**Pick: (A).** Fail-closed on every malformed input; overlaps are rejected even when each range is individually in-bounds (a slice sharing bytes with another makes identity and hashing meaningless). Tests (brief-named): malformed offset, size overflow, overlapping slices, truncated FAT — all assert `Err`, never panic; plus a hostile-thin `prepare` test for the underflow site.

### Item 7 — Dylib injection across FAT

**Problem.** `inject_dylib_command` rejects anything whose magic isn't `MH_MAGIC_64` (writer.rs:590-593), so a FAT input gets a misleading "not a 64-bit Mach-O"; `IpaSigner::sign_binary` feeds it the **whole file** (ipa/mod.rs:976-980) ⇒ universal + `--dylibs` fails today.

**Candidates.**
- **(A) Dispatch inside `inject_dylib_command`:** `Mach::parse` → `Mach::Fat` ⇒ validate the table (item 6 helper), inject each slice through the existing thin body (extracted as a private `inject_dylib_thin`), and reassemble via `embed_fat_from_signed_slices` (items 3/4/6 hardening applies for free). `Mach::Binary`/parse-failure ⇒ existing thin path unchanged. Sole caller (ipa) needs no edit.
- (B) New public `inject_dylib_fat` + change the ipa caller. **Rejected:** `ipa/**` is another lane's active edit scope.
- (C) Reject FAT with a clearer error. **Rejected:** leaves the feature broken (the brief demands injection working across FAT).

**Pick: (A).** One entry point, one convention. Injection lengthens no file (the command lands in load-command slack), but the container is rebuilt through the hardened writer anyway — offsets re-rounded per item 4, identity preserved per item 3. If any slice lacks slack, the whole operation returns `Err` (no partial injection).

### Item 8 — Builder routing

**Problem.** `ZSign::sign_macho` (builder.rs:297-346) routes every input to thin signers: adhoc → `sign_macho_adhoc` (:307-315), `sha256_only` (default true, builder.rs:109) → `sign_macho_sha256_only` (:319-328), else → `sign_macho` (:329-338). FAT input therefore either errors or (pre item 1/2) strips.

**Candidates.**
- **(A) Explicit container dispatch in the dual branch:** the `sha256_only` branch stays (FAT-capable via item 1); the dual branch becomes `if macho.is_fat() { sign_any_macho(...) } else { sign_macho(...) }`; adhoc branch untouched (item 2's guard turns FAT into a clean `Err` — documented, fail-closed).
- (B) Route everything through `sign_any_macho`. **Rejected for thin:** `sign_any_macho` substitutes `EMPTY_ENTITLEMENTS` for non-executables (signer.rs:167-175) while `sign_macho` passes caller entitlements through — switching would silently change thin dylib direct-sign behavior.
- (C) Make adhoc FAT-capable to close the last branch. **Rejected:** un-requested feature (queue names sha256 + sign_any dispatch only); clean rejection is the honest contract until a ticket asks for adhoc FAT.

**Pick: (A).** Thin behavior byte-identical; FAT routes through FAT-capable paths in every non-adhoc mode; adhoc+FAT is a clean `Err` with a test pinning that contract.

### Item 9 — execSegFlags on every executable slice (ZSN-13) + R2 fileoff emission

**Problem.** Two parts. (a) **Flag decision:** Apple sets `CS_EXECSEG_MAIN_BINARY` iff `MH_EXECUTE` (librarian fact 4); the signer's decision at signer.rs:783-790 already matches this *per slice* — but **no test anywhere asserts the emission** (the verifier test `main_binary_flag_is_required_for_executables` patches flags *away* and passes even if the signer never set them). (b) **R2/Q2 emission:** `execSegBase` is fed `text_segment_base` = `__TEXT.vmaddr` (parser.rs:272/:285 → signer.rs:825) while Apple emits `__TEXT.fileoff` (librarian fact 5); pinned by signer.rs:1402 (`assert_eq!(exec_seg_base, 0x1_0000_0000)`).

**Candidates.**
- **(A) Switch emission to fileoff + expose the parser field + lock the flag with tests:** add `ArchSlice.text_segment_fileoff` (u64, from `Segment64/Segment32.fileoff`), emit `.exec_seg_base(slice.text_segment_fileoff)` (limit already `text_segment_size` = `__TEXT.filesize` since ZSN-32), keep `text_segment_base` (vmaddr) because the read-only verifier consumes it (`macho/verify.rs:296`), migrate the signer.rs:1402 pin to the new contract, and add per-slice tests asserting `MAIN_BINARY` on every executable slice of a FAT + `0` on a non-executable + `execSegBase == fileoff` per slice.
- (B) Repurpose `text_segment_base` in place (store fileoff). **Rejected:** silently changes the meaning of a field the read-only verifier (`macho/verify.rs:296`) compares against its `vm_matches` arm — another lane's file would read altered data with no compile signal.
- (C) Rename `text_segment_base/size` to `text_segment_fileoff/filesize`. **Rejected:** the rename breaks compilation of read-only `macho/verify.rs` (consumes both fields); adding `text_segment_filesize` as an alias of the existing `text_segment_size` (same value, same source) would create a second name for one value — prohibited (no second conventions).

**Pick: (A).** Rider naming resolution: the requested `text_segment_fileoff` is added as a field; the requested `text_segment_filesize` **is** the existing `text_segment_size` (set from `__TEXT.filesize`, parser.rs:271/:284 — doc comment updated to state so). The verifier's exact-equality tightening (its `vm_matches` arm + stale "fileoff not exposed" comment at `macho/verify.rs:297-298`) is recorded as a **follow-up consuming the new field — not edited here** (brief: do not touch `codesign/*`/`macho/verify.rs`). Verifier compatibility proven by trace: fileoff emission passes its `file_space_ok` plausibility arm for every in-repo fixture (research §1.1), and the gate re-runs all existing verify tests.

### Item 10 — Reserve plumbing R1/R3

**Problem.** `realloc_code_sign_space_with_metadata` computes its own hash-slot formula reserve (writer.rs:994-996) and never learns the signer's estimate; prepare then declares `datasize = est` (or the retry's `padded_sig_size`). When `est > formula` (entitlements/CMS-heavy inputs ⇒ R3) or the retry reserve exceeds the first expansion (⇒ R1), the ZSN-32 capacity guard (writer.rs:1235-1240) fires a terminal `Err` that the signer's retry can never reach (retry only runs *after* a successful prepare).

**Candidates.**
- **(A) Pass the reserve through:** `realloc_code_sign_space_with_metadata(data, metadata, code_length, estimated_signature_size)` — `required = max(formula_end, declared_end, sig_offset + estimate)`; the signer's initial call passes the `compute_superblob_reserved_size` estimate (signer.rs:419), the retry passes `padded_sig_size` (:552). Workspace callers are signer.rs:424-428/:557-561 + writer inline tests only (no ipa/wasm/cli usage) ⇒ the signature change migrates entirely inside lane files.
- (B) Have prepare return the shortfall for a second realloc. **Rejected:** a two-pass handshake across functions that already take an estimate parameter; more states, same callers.
- (C) Pass the reserve into the goblin-stack twins (`realloc_code_sign_space`, `realloc_code_sign_space_slice`). **Rejected:** no in-tree callers and no signer path — adding an unconsumed required parameter is API churn; those remain formula-bounded with prepare's clean `Err` as backstop (their current fail-closed behavior).

**Pick: (A).** With the reserve flowing in, realloc's early-return and expansion target both cover prepare's declaration by construction: R3 disappears (estimate-driven expansion), R1 disappears (retry-driven expansion), and the prepare guard stays as the fail-closed backstop for *genuinely* too-small reserves passed by external callers.

---

## 3. Invariants (must hold after every task)

1. **Container preservation:** a FAT input (any `nfat_arch ≥ 1`) that signs successfully returns FAT bytes — magic `0xcafebabe`, arch count and table order preserved, `fat_arch.cputype/cpusubtype` unchanged; a thin input returns thin bytes. Slice count never decides; `is_fat()` does.
2. **Never silent partial signing:** every arch in the output carries a signature produced by this signing operation; any missing/mismatched `SignedSlice` is an `Err`.
3. **Declared alignment == actual placement:** for each output arch, `offset % (1 << align_i) == 0`, and the gap before slice *i* (`offset_i − (offset_{i-1} + size_{i-1})`) is `< 1 << align_i` — that slice's own exponent; gaps and header padding are zero; output length == last `offset + size` (no trailing bytes).
4. **No panic on hostile input:** every public writer entry point returns `Err` for out-of-bounds/overflowing/overlapping/truncated FAT structures and hostile thin LC values — indexing uses `checked_add` + `.get()`, arithmetic uses checked ops.
5. **Slice content is fully hashed:** for an unsigned slice, `code_length == declared_size` (FAT) / `== file length` (thin); trailing bytes inside a slice survive re-signing byte-for-byte before the signature region.
6. **Apple execSeg parity:** every emitted CD has `execSegBase = __TEXT.fileoff`, `execSegLimit = __TEXT.filesize`, `execSegFlags & CS_EXECSEG_MAIN_BINARY != 0` iff the slice is `MH_EXECUTE` (and `0` otherwise), per slice.
7. **Reserve covers declaration:** the buffer handed to `prepare_code_in_place` is always ≥ `sig_offset + est` on the signer's initial pass and ≥ `sig_offset + padded_sig_size` on the retry; a genuinely too-small external reserve yields a clean `Err`, never a panic or past-EOF bytes.
8. **Architecture order:** `slices()` order == fat-table order == output table order (rayon `map` over an indexed iterator preserves order; embed writes entries sequentially).
9. **Public signatures frozen** except `realloc_code_sign_space_with_metadata` (item 10 — all callers in-lane). No edits outside the five scoped files.
10. **Existing gates stay green:** 59+ core macho tests, including ZSN-24/25/32 additions; `test_ipa_signing_is_deterministic` skipped per ZSN-15.

## 4. Test strategy

House rules: inline `#[cfg(test)] mod tests` per file; in-memory fixtures (no tempfile in zsign-core); reasoned `assert!` messages; `expect_err(...)` + message `contains` for error contracts; raw CD byte assertions at documented offsets (64/72/80) as in signer.rs:1399-1403. Red/green discipline: **Tester** subagent writes each task's tests first and runs the scoped gate to record which assertions fail on unmodified sources; **implementer** greens them without weakening assertions; controller runs the gate and commits. Pre-fix-green tests are labeled *contract locks* in the test name/comment, never presented as proof of the bug.

Fixture additions (`fixtures.rs`, existing ones untouched):
- `make_fat_macho(slices, aligns)` — shared two-/one-arch FAT builder (big-endian `fat_header`/`fat_arch`, per-entry offsets and align exponents as arguments, distinct-cputype-capable slices where needed); replaces the need to hand-roll BE headers in each test module (existing ad-hoc builders in signer.rs/verify.rs/wasm stay — they are other files' scope).
- `make_minimal_dylib()` — `make_minimal_macho` shape with `filetype = MH_DYLIB` (item 9 non-executable flag case).
- Tail-extended FAT helper (inline in parser/signer tests): slice = `make_minimal_macho` + `0x400` tail bytes with `fat_arch.size` covering the tail (item 5).

Per-item observable acceptance:

| Item | Red pre-fix (proof) | Contract locks / acceptance |
|---|---|---|
| 1 | `sign_macho_sha256_only` on two-arch FAT ⇒ `Err "…only supports single-arch…"` | output reparses to 2 slices, table order unchanged, each slice's superblob omits the SHA-1 CD (slot scan pattern signer.rs:956-1007) |
| 2 | one-arch FAT via `sign_any_macho` ⇒ thin output (magic ≠ `0xcafebabe`, `is_fat()==false`) | container preserved + signed; `sign_macho`/`sign_macho_adhoc` on one-arch FAT ⇒ clean `Err`; thin paths unchanged |
| 3 | one-of-two ⇒ silently half-signed output today (assert now `Err`); zero-of-two ⇒ `Err` | identity mismatch (offset/size/cputype) ⇒ `Err`; `embed_signature` on multi-arch FAT ⇒ `Err`; full-set paths stay green |
| 4 | mixed align(12,15) FAT: output slice offsets not `2^15`-aligned (assert offset math ⇒ fails) | all `offset % 2^align == 0`, gaps `< 2^align`, zero gaps, output ends at last slice end |
| 5 | FAT slice with declared tail: `code_length == content end` (fails: excludes tail); signed output loses tail bytes | `code_length == declared_size`; tail bytes byte-identical in re-signed output before signature; thin behavior unchanged |
| 6 | malformed arch offset ⇒ **panic** at `data[offset..offset+size]` (index out of bounds) | truncated FAT / size-overflow / overlapping slices ⇒ `Err`; hostile `__LINKEDIT.fileoff` thin ⇒ `Err` from `prepare`, no panic |
| 7 | two-arch FAT + `inject_dylib_command` ⇒ `Err "not a 64-bit Mach-O"` | every slice gains `LC_LOAD_DYLIB` (+1 `ncmds`), container valid, subsequent `sign_any_macho` succeeds; slice lacking slack ⇒ clean `Err` |
| 8 | builder direct-sign of two-arch FAT with default options ⇒ `Err` (or strip pre item 1/2) | default (sha256) ⇒ Ok + 2 signed slices + SHA-256-only CDs; `sha256_only(false)` ⇒ Ok + dual CDs; adhoc+FAT ⇒ clean `Err` |
| 9 | R2: CD `execSegBase` == `0x1_0000_0000` (vmaddr) — fails once emission switches to fileoff `0x1000` | flag locks: `execSegFlags & 0x1` on every executable slice of a FAT (and thin), `== 0` for the dylib fixture; `execSegBase == text_segment_fileoff` per slice; existing verifier tests stay green |
| 10 | signer-level: sign with ≥16 KiB entitlements plist ⇒ clean `Err "…exceeds the N-byte buffer"` (tight > formula ⇒ R3); writer-level: realloc given reserve R then prepare(R) ⇒ `Err` (R ignored pre-fix) | realloc(estimate) ⇒ prepare(estimate) succeeds with `len ≥ sig_offset + estimate`; genuinely-too-small reserve ⇒ clean `Err` (guard contract lock) |

Test-count discipline: new tests only where the brief names an observable (table above); no duplicate same-path parameter rows; no implementation-detail assertions beyond raw CD/FAT byte pins already house style.

## 5. Known limitations & recorded follow-ups (not this lane)

- **Adhoc/FAT and thin-only entries reject containers** (clean `Err`): `sign_macho`, `sign_macho_adhoc` on any FAT; builder `adhoc` mode on FAT; `IpaSigner` adhoc branch and `sign_standalone_dylib` inherit the clean rejection. Adding adhoc-FAT support = a future ticket (research shows `sign_slice_complete(.., None)` could carry it mechanically).
- **Verifier exact-equality tightening** (`macho/verify.rs:294-307`: replace the `file_space_ok` plausibility arm + stale :297-298 comment with exact `fileoff/filesize` equality using the new `text_segment_fileoff`) = ZSN-29 follow-up, explicitly excluded here.
- **Page-hash size** hardcoded 4 KiB vs Apple's 16 KiB for arm64 (`machorep.cpp:574-591`) — out of queue; affects FAT mixes of arm64 with 4 K-page arches.
- **execSeg emission gating**: Apple zeroes base/limit when `platform == 0`; we always emit (pre-existing behavior, unchanged).
- **goblin 0.10.7 cannot parse `FAT_MAGIC_64`** — fat64 inputs fail closed at parse (consistent with fail-closed posture; no fat64 support added).
- **README FAT claims** (README.md:15) — wave-4 docs ticket, not edited here.

## 6. Verification gates

- Per task: `mkdir -p .tmptmp && TMPDIR=$PWD/.tmptmp cargo test -p zsign-core macho -- --skip test_ipa_signing_is_deterministic` — all existing core macho tests + new tests green.
- Facade task (item 8): additionally `TMPDIR=$PWD/.tmptmp cargo test -p zsign builder` (scoped to builder tests) and the core gate.
- Final: core gate + `TMPDIR=$PWD/.tmptmp cargo test -p zsign-core` (whole crate, determinism skip applies where named) + `git status --short` clean except intended commits.
- `cargo fmt`/`clippy`/`hk` deliberately NOT run mid-flight (merge gate belongs to the orchestrator; brief instruction). Commits: conventional subjects, ticket ID in subject only (never in code comments), controller-authored after each green task; docs force-added (`git add -f` — root `.gitignore` ignores `docs/`), `.gitignore` untouched.
