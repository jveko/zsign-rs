# ZSN-41 examples/web demo — security + correctness design

- **Lane:** zsn41-web · **Base:** main @ c9ff0fb · **Date:** 2026-09-25
- **Scope (edit):** `examples/web/src/main.js`, `examples/web/index.html`
  (`examples/web/package.json` only if a script is genuinely needed).
  No Rust, no `.github/**`, no native `ipa/**`, no `.gitignore`.
- **Gate:** CI-equivalent from `.github/workflows/examples-web.yml`:
  `wasm-pack build crates/zsign-wasm --target web --release` (reused, fresh this lane),
  then `npm ci && npm run build` in `examples/web`. Observed green at base before edits.
- **Nature of this lane:** hardening an existing two-file browser demo. The demo signs
  IPAs entirely in the browser through `zsign-wasm`; it holds P12 bytes and password in
  memory, so DOM-injection and fail-open signing paths are the top risks.

## 1. Research summary (phase-2 batch: 3 scouts + 1 librarian)

### 1.1 Anchors (`AnchorWebCitations`, re-anchored against c9ff0fb)

- XSS sink: `main.js:44` `line.innerHTML = ...${msg}` inside `log()` (40-47). It is the
  **only** unescaped sink; attacker-influenced inputs reaching it include file names
  (`:118`, `:261`), zip paths (`:147`, `:279`, `:322`, `:343`), plist-derived strings
  (`:158`, `:165`, `:324-327`), cert-derived team id (`:256`) and exception text
  (`:345`, `:406`, `:539`). `summaryEl.innerHTML` (`:525-530`) interpolates numerics
  only; `logEl.innerHTML = ""` (`:113`, `:236`) is a constant clear. No
  `insertAdjacentHTML`/`document.write`/`outerHTML` anywhere.
- Fail-open sites: dylib catch reuses original bytes (`:340-348`, reuse at `:347`);
  null main exec warns and falls through (`:321-328`); main-exec catch reuses original
  bytes (`:405-408`); no failure flag gates the write loop (`:411-513`) or the success
  log (`:521`).
- Nested bundles: no bundle discovery beyond the single root regex (`:138`, `:268`);
  nested binaries *are* signed as plain dylibs (`:295-315`, `:341`) but get no nested
  `_CodeSignature/CodeResources`, and the hash/write skip predicates (`:362`, `:450`)
  are root-anchored, so stale nested signatures are hashed into the new root manifest
  and copied verbatim.
- Bundle-ID: `sign_macho_fat(mainData, bundleId, infoPlistData, codeResourcesBytes)`
  (`:394-399`) with `infoPlistData` never modified (`:286-289`).
- wasmReady: `tryExtractExecutableName(infoPlistData)` at `:289` omits the second arg
  the signature requires (`:91-92`); `loadIpa` passes it (`:163`) but discards the result.
- App-root: both `loadIpa` (`:137-139`) and `signIpa` (`:267-269`) require a
  `Payload/<x>.app/` **directory** entry, byte-identical duplicated logic; `index.html:84`
  offers `accept=".ipa,.app,.zip"` although a file input cannot select a directory.
- Empty password: `updateSignButton` gate at `main.js:189`.
- Memory: `fileMap` (`:299`, full decompressed bundle) + `signedFiles` (`:331`, second
  copy of every Mach-O) + `entries` (`:263`) all live for the whole run; `signer.free()`
  (`:517`) and `zipReader.close()` (`:516`) are success-only; `URL.createObjectURL`
  (`:532`) is never revoked.

### 1.2 wasm API (`crates/zsign-wasm/src/lib.rs` — LANDED surface, main@c174240, source of truth)

- Two exported classes: `MachOInfo` (2 getters) and `WasmSigner`. Surface used/available
  to this demo: `new WasmSigner(p12, password, profileOrNull)` (throws; size limits
  **p12 ≤ 4 MiB, profile ≤ 16 MiB**, code `ZSIGN_INPUT_TOO_LARGE`), `team_id()`,
  `set_main_executable(name)`, `hash_file(path, data) -> bool` (**throws**:
  `ZSIGN_INPUT_TOO_LARGE` above 128 MiB per buffer, `ZSIGN_PATH_IN_PROGRESS` /
  `ZSIGN_PATH_ALREADY_FINALIZED` on per-round state misuse — each path hashed at most
  once per resources round), `hash_file_chunk(path, chunk, isFinal)` (≤128 MiB per
  chunk; the routing target for oversized files), **`add_symlink(path, target) -> bool`**
  (outside the file-path sealing state machine), **`reset_resources()`** (clears
  builder + streams + finalized seals and **preserves the main-executable exclusion** —
  one signer instance seals many bundle levels sequentially), `build_code_resources()`
  (throws `ZSIGN_UNFINISHED_HASHES` if a stream is open), static
  `parse_info_plist(data) -> {bundle_id, executable}` (XML and binary; ≤16 MiB; throws
  `ZSIGN_INVALID_PLIST`), static `parse_macho` (≤512 MiB), static
  `extract_entitlements`, `entitlements()`, `set_entitlements(Option<Vec<u8>>)`
  (override; `None` falls back to **profile** entitlements — the landed doc states:
  "To sign with no entitlements while holding a profile, construct the signer without
  profile bytes", which is exactly the two-signer split of §2.3), `sign_macho`,
  `sign_macho_fat`, `free()`.
- **Signing entry points:** `sign_macho` is thin-only with a SHA-256-only code
  directory and throws `ZSIGN_FAT_UNSUPPORTED` on FAT/Universal input;
  `sign_macho_fat(data, identifier, infoPlist, codeResources)` is the explicit dual
  SHA-1+SHA-256 opt-in accepting thin **or** FAT (≤512 MiB, plist args ≤16 MiB).
  **The demo routes every sign through `sign_macho_fat`** (plan Tasks 2/3/4 — no
  `sign_macho(` call exists anywhere in the plan), so FAT IPAs keep working and no
  `ZSIGN_FAT_UNSUPPORTED` path is reachable.
- **Error contract:** every throw is a JS `Error` carrying a stable string
  `error.code` (`ZSIGN_INVALID_PASSWORD`, `ZSIGN_INVALID_MACHO`, `ZSIGN_INPUT_TOO_LARGE`,
  `ZSIGN_FAT_UNSUPPORTED`, … — table in the crate docs). `error.message` is
  human-facing and may change: the demo **displays** both but **never matches on
  message text** (codes are the only stable surfacing channel).
- `info_plist` remains opaque bytes hashed into the signature context — whatever the
  demo passes must be byte-identical to what it writes into the IPA (the §2.4
  byte-identity contract, unchanged by the SHA-256-only switch).
- `zsign-core`'s `should_exclude` is shared with the native flow: root-anchored
  `_CodeSignature` exclusion, own-main-executable exact-match exclusion, `files2`
  omission of top-level `Info.plist`/`PkgInfo`/`.DS_Store`. The demo does **not** need
  to re-implement these predicates.
- No plist-writing API exists (item 4 is JS-owned).
- Path dependency: `zsign-wasm` is `file:../../crates/zsign-wasm/pkg` (must exist
  before `npm ci`). The lockfile records stale link metadata (0.1.0 vs pkg 0.1.1) —
  empirically harmless (`npm ci` green against exactly this lock) and out of lane
  scope to update; the gate always rebuilds the pkg first anyway.
- Generated glue is idempotent on init (early-returns when already initialized —
  re-verified on this worktree's built pkg), so the demo's second `initWasm` call in
  `signIpa` is safe.
- CI workflow (verbatim order): `wasm-pack build crates/zsign-wasm --target web --release`
  → `npm ci` (in `examples/web`) → `npm run build`.

### 1.3 Native flow reference (`MapNativeOrder`, READ-ONLY `crates/zsign/**`)

Correctness contract the demo mirrors:

1. **App-root discovery** derives from file paths after extraction; directory entries
   not required (`extract.rs:599-624`). Native takes the first `.app` (no uniqueness
   check); this demo is deliberately stricter — brief mandates exactly one (§2.7).
2. **Bundle set** = root + every ancestor directory with extension
   `.app`/`.framework`/`.appex` (case-insensitive, `is_bundle_directory`); depth =
   count of bundle components; processing order **deepest-first**
   (`mod.rs:405-424`, `:387`).
3. **Per bundle, deepest-first** (`sign_single_bundle`, `mod.rs:653-718`):
   a. read own `Info.plist` → identifier (`CFBundleIdentifier`, fallback file stem)
      and main executable (`CFBundleExecutable`);
   b. sign immediate non-main Mach-Os (walk prunes deeper bundle dirs and
      `_CodeSignature`), identifier = file stem, **no** plist/CodeResources args;
   c. root only: write `embedded.mobileprovision` **before** the scan (profile bytes
      are hashed into the root CodeResources);
   c2. before the bundle loop, native signs standalone `.dylib` files recursively as a
      pre-pass (`mod.rs:380-383`, `:569-649`, identifier = file stem, no plist/CR) —
      the demo's per-bundle "immediate non-main" rule (§3.2) subsumes it: every
      non-main binary is signed exactly once, before its bundle's scan;
   d. scan the whole subtree (follow_links=false) with exclusions = root-anchored
      `_CodeSignature` + own main executable → write `_CodeSignature/CodeResources`.
      Parent therefore seals: nested **signed** executable bytes, nested `Info.plist`,
      nested payload, nested `_CodeSignature/CodeResources`, root
      `embedded.mobileprovision`. Symlinks are sealed via `{"symlink": target}`
      entries produced by the builder's symlink path (`zsign-core code_resources.rs:445-446`),
      with legacy `files` skipping symlinks (`:414-416`);
   e. sign this bundle's main executable with (own identifier, own plist bytes, own
      CodeResources bytes). Entitlements: native passes the profile entitlements to the
      root bundle's binaries (main executable **and** its immediate non-main Mach-Os —
      `mod.rs:668-680`) and `None` to every nested-bundle binary (`mod.rs:394-395`).
4. **Bundle-ID rewrite** targets the **root** Info.plist only
   (`mod.rs:370-371`), parse-any-encoding → mutate → serialize (native always emits
   XML), before any CodeResources generation (`:370-377` before `:385+`).
5. **Symlink output**: `zip.add_symlink` with mode `0o120777`, made-by Unix, target
   bytes Stored (`archive.rs:254-260`, zip 7.2.0 `write.rs:1549-1573`).
6. **Fail-closed**: every step `?`-propagates and any signing error aborts before
   repack (`sign()` order: `mod.rs:281` before `:283`); the repacked archive's contents
   are only complete after total success (qualification: `create_ipa` opens/truncates
   the output file before archive I/O finishes, `archive.rs:199-203` — a partial file
   may exist after an I/O failure, but never after a *signing* failure). Encrypted
   Mach-O is a hard error.

### 1.4 External contracts (`VerifyExternalContracts`, source-verified)

- **Directory selection:** `showDirectoryPicker` is Chromium-only (Chrome/Edge 86+;
  Firefox/Safari = false), experimental, not Baseline
  (`web-features 3.40.0: file-system-access baseline=false`), secure-context +
  user-activation gated; the drop-zone route `DataTransferItem.getAsFileSystemHandle()`
  has the same Chromium-only matrix. A plain file input can never select a directory
  (WICG entries-api: only `webkitdirectory` enables it, and it yields a flat FileList
  with no modes/symlink metadata; iOS Safari only from 18.4).
  **Verdict: do not use it — keep the demo files-only and drop the unselectable
  `.app` from `accept`** (decision §2.7).
- **zip.js 2.8.23 symlink contract:** reader exposes `versionMadeBy`
  (`zip-reader.js:302`) and `externalFileAttributes` (`:311`) on every entry;
  `entry.unixExternalUpper` is NOT copied onto `Entry` (absent from
  `zip-entry.js PROPERTY_NAMES:77-124`) — derive `(entry.externalFileAttributes >>> 16)`
  (which `isSymlinkEntry` does). Writer options read by `addFile`: `versionMadeBy`
  (`zip-writer.js:403`, actual default 768 = `0x0300`, pass `(3<<8)|20`),
  `externalFileAttributes` (`:444`, default 0), `unixMode` (`:407`), `directory`
  (`:448`), `msDosCompatible`/`msdosAttributes*` (`:402/:424-425`); there is **no**
  `unixPermissions` option (that is JSZip) and no first-class symlink support. A
  non-zero `externalFileAttributes` is **not** masked: Unix defaults fire only when it
  is 0 (`:453-465`); the value is recomposed as `((unixMode & 0xffff) << 16) |
  (extAttr & 0xff)` (`:488`) preserving the Unix type/permission bits (bits 8-15
  dropped — irrelevant), and `setUint32` at `:1507` writes it verbatim. The one silent
  destroyer is passing `msdosAttributes*` without unix metadata (forces `msDosCompatible`,
  zeroes the host byte, skips Unix recomposition — `:431-433`): the demo never passes
  those. Writing a symlink = payload target bytes + `externalFileAttributes = mode << 16`
  + `versionMadeBy = 0x0314` + name NOT ending in `/` — the Task 6 branch. (The
  recorded §2.6 probe exercised the earlier fallback-options shape; Task 6 Step 5
  re-runs it with the final branch options — recomposed attributes plus
  `compressionMethod: 0`.)
- **innerHTML vs textContent (MDN):** "Node.textContent should be used when you know
  that the user-provided content should be plain text. This prevents it being parsed as
  HTML"; `createTextNode` "can be used to escape HTML characters"; `Node.textContent`
  is absent from MDN's TrustedHTML sink list (only `Element.innerHTML`,
  `insertAdjacentHTML`, `outerHTML`, … appear). Recommended shape = `createElement`
  structure + `textContent` for every dynamic string (decision §2.1).
- **Vite 6 + `?url` wasm:** importing `zsign_wasm_bg.wasm?url` is the documented
  pattern (Vite guide, "Accessing the WebAssembly Module"); the asset is emitted under
  `dist/assets` with a content-hashed name (this lane's builds observed e.g.
  `zsign_wasm_bg-UCv7etqo.wasm`; the hash tracks wasm content) and fetched at runtime; inlining only under 4 KiB (never
  for a 1.1 MB wasm); COOP/COEP not required (no `SharedArrayBuffer`/`Atomics` in the
  glue); the demo's ArrayBuffer init path (`initWasm({module_or_path: wasmBytes})`)
  uses `WebAssembly.instantiate` and sidesteps the `application/wasm` MIME requirement
  (`zsign_wasm.js:506-515`).
- **bplist00 rewrite feasibility:** normative layout = Apple `CFBinaryPList.c`
  (apple-oss-distributions/CF, comment block ~lines 239-281): 8-byte header, object
  table with marker nibbles (int `0x1n`, data `0x4n`, **ASCII string `0x5n`,
  UTF-16 string `0x6n`**, array `0xAn`, dict `0xDn` as keyref/objref pairs), offset
  table of big-endian ints, 32-byte trailer (offsetIntSize, objectRefSize, numObjects,
  topObject, offsetTableOffset). Empirically confirmed with Python `plistlib.FMT_BINARY`
  on this machine: value `"App"` preceded by `0x53` (type 5, len 3), `"com.foo.bar"`
  by `0x5B`, 18-char key by `0x5F 0x10 0x12` (extended count), UTF-16 value by `0x65`;
  trailer offsets match the read offsets used in Task 4. Node libs
  (`bplist-parser`/`bplist-creator`) are Node-only (module-level `node:fs`/`Buffer`) →
  no new deps (decision §2.4).

## 2. Decisions per queue item (phase-1 brainstorm, candidates recorded)

### 2.1 XSS via innerHTML

- **Candidates:** (A) build log/summary nodes with `textContent`/`createTextNode`;
  (B) HTML-escape helper at the `log()` boundary; (C) DOMPurify-style sanitizer.
- **Decision: A.** `log()` creates `<span class="ts">` and `<span class="msg">` via
  `createElement` + `textContent`; `section()` unchanged (calls `log`); the summary grid
  is built with `createElement` + `textContent` per stat; the two `logEl.innerHTML = ""`
  clears become `logEl.replaceChildren()`. Result: zero HTML-parsing sinks in the file.
- **Rejected:** B — escaping tables rot and keep an HTML sink one refactor from
  re-introducing XSS while the page holds P12 bytes; C — a dependency for a two-file
  demo (YAGNI).

### 2.2 Fail-open signing → fail-closed

- **Candidates:** (A) fail-fast on the first signing error; (B) collect all per-binary
  errors, log each with its path, throw one aggregated error after the loop;
  (C) partial-signing UI mode.
- **Decision: B for the binary loops, immediate throw for structural failures.**
  Non-main signing errors are accumulated (path + message), every failure is logged,
  then a single `Error` listing them aborts before hashing. Main-exec signing failure
  rethrows (no original-byte reuse). A null/unresolvable main executable throws
  immediately after classification — before any hashing, CodeResources, or zip work.
  The outer `catch` logs via the (now safe) `log()`; the download button, summary, and
  object URL are only ever set on the success path (they are inside the try after the
  blob). Resource cleanup moves to `finally`: freeing the signer(s) and closing the
  zip reader
  run on **every** path (currently success-only — a throw leaks the WASM signer with
  credentials).
- **Rejected:** A — with N broken binaries the user fixes one per attempt (poor
  diagnostics, no correctness gain); C — offering a knowingly-broken IPA is the bug.

### 2.3 Nested bundles: recurse vs reject

- **Candidates:** (A) full per-bundle sealing mirroring the native order;
  (B) honest rejection of IPAs containing nested bundles; (C) hash nested files into
  the parent only, without nested signatures.
- **Decision: A (full recursion).** Feasible without Rust changes:
  `reset_resources()` + `add_symlink()` + `build_code_resources()` are idempotent on one
  instance, and `should_exclude` is already the native predicate. Algorithm (§3) follows
  `MapNativeOrder` §1.3 exactly: discover bundles from ancestor dirs, deepest-first,
  per-bundle sign-immediate → scan (root: profile first) → build CR → sign own main
  executable with own identifier/plist/CR. Nested stale signatures are replaced in the
  output (map keyed by full zip path), not copied.
- **Rejected:** B — the brief permits rejection only if parity is genuinely out of
  scope; the wasm surface supports parity, so rejecting would keep a real bug
  (root CodeResources currently hashes stale nested signatures). C — an unsigned nested
  executable fails install anyway; that is "silent unsigning" with extra steps.
- **Tradeoffs recorded:** identifiers for non-main binaries = file stem and nested main
  executables = nested `CFBundleIdentifier` (native semantics) — the UI bundle-ID field
  rewrites the root only. Entitlements parity: `sign_macho_fat` delegates to
  `zsign-core`'s `sign_any_macho`, which applies the instance's entitlements to
  **executable** slices and `EMPTY_ENTITLEMENTS` to non-executables
  (`crates/zsign-core/src/macho/signer.rs:168-175`) — dylibs/framework binaries never
  carry profile entitlements under either signer, so what the two-signer split actually
  decides is the **nested main executables**: the demo runs **two signers** — a root
  signer `new WasmSigner(p12, password, profile)` (entitlements present; the root main
  executable is signed with them, matching the root-level flow of `mod.rs:668-680`)
  and a nested signer `new WasmSigner(p12, password, null)`
  (profile omitted → no entitlements, `lib.rs:238-241`; used for every nested bundle,
  matching `mod.rs:394-395`). Cost: one extra credential parse per run. This makes the
  original §6.1 cross-lane request unnecessary — see §6.

### 2.4 Bundle-ID rewrite

- **Candidates:** (A) pure-JS plist rewrite in `main.js` (XML splice + binary-plist
  targeted splice); (B) cross-lane wasm helper from ZSN-40, demo rejects until landed;
  (C) same-length in-place binary patch only.
- **Decision: A**, one pure helper `rewriteBundleIdentifier(plistBytes, newId)`:
  - fast path: if the parsed current identifier equals `newId`, return the original
    bytes untouched (common case carries zero rewrite risk);
  - `bplist00`: parse trailer → offset table → top dict → locate the
    `CFBundleIdentifier` key → its string value object → splice in the new ASCII string
    → fix every offset-table entry pointing past the splice (Δ shift) + trailer
    `offsetTableOffset`. Handles type-5 (ASCII) and type-6 (UTF-16BE) string encodings
    and extended-length markers; re-encodes the value as an ASCII type-5 object — the
    helper validates the new id **unconditionally, before the equality fast path**
    (always invoked at sign time, even when no change is requested) against
    `^[A-Za-z0-9._-]+$` / max 255 chars, so the spliced value is always ASCII
    (marker types verified empirically against Python `plistlib`, design §1.4);
  - XML (`<?xml`/`<plist`): locate the depth-1 `CFBundleIdentifier` key with a
    nesting-aware tag scan and replace the **element-bounded** `<string>` value that
    immediately follows it (anchored `^([^<]*)<\/string>` — never search onward
    through the document);
  - duplicate root `CFBundleIdentifier` keys (either encoding) → reject: plist
    parsers are last-wins while a first-match rewrite would touch only the first
    key, desynchronizing the emitted plist from the signed identifier;
  - anything else (no CFBundleIdentifier key, non-string value, unknown format) →
    throw a precise error (fail-closed; native inserts a missing key — known
    divergence, §5). Additional fail-closed rejections (cold-review round 1): input
    shorter than 8 bytes; trailer **not adjacent** to the offset table
    (`offsetTableOffset + numObjects * offsetIntSize !== bytes.length - 32` →
    "unsupported binary plist layout"); any object ref ≥ `numObjects` or any stored
    object offset ≥ `offsetTableOffset`; any string/dict payload ending past
    `offsetTableOffset`; a **shared value object** (the `CFBundleIdentifier` value
    referenced from anywhere besides that one dict slot — binary plists may
    deduplicate equal strings, so splicing would corrupt the other key → reject);
    a shifted offset that no longer fits the current `offsetIntSize` (e.g. 1-byte
    tables past 255 bytes → reject instead of wrapping).
  The rewritten bytes feed **both** `sign_macho_fat`'s `info_plist` argument and the
  zip write, preserving wasm's byte-identity requirement (§1.2).
- **Rejected:** B — blocks this lane on a parallel lane's schedule; C — silently
  constrains input length (bad ids fail for an unexplained reason). Both recorded as
  unnecessary once A lands; no cross-lane request needed for item 4.

### 2.5 wasmReady argument + fail-fast exec resolution

- **Candidates:** (A) module-level `wasmReady` flag maintained by both init paths,
  threaded into every `tryExtract*` call, fail-fast at sign time;
  (B) persist `loadIpa`'s parsed executable name in module state and reuse it.
- **Decision: A.** `initWasm` success sets `let wasmReady = true` (module scope);
  `loadIpa` and `signIpa` both maintain it; `signIpa` passes it to
  `tryExtractExecutableName`/`tryExtractBundleId`. After classification: no extractable
  executable name, or a name with no matching Mach-O in the bundle → throw before
  hashing (this is also the item-2 structural abort).
- **Rejected:** B — two sources of truth for one value (`loadIpa`'s discovery and
  `signIpa`'s re-read can disagree; the scout already found dead duplicate state
  `ipaEntries`/`appPrefix`/`appName`); `signIpa` must parse its own bytes anyway.

### 2.6 Symlinks

- **Candidates:** (A) explicit symlink branch on both the CodeResources and zip-write
  sides; (B) post-write central-directory byte patch; (C) leave the implicit
  pass-through as-is.
- **Empirical finding (probe, run at locked zip.js 2.8.23, `/tmp/zsn41-probes/symlink.mjs`,
  throwaway — not committed):** authoring a zip with a symlink entry
  (`externalFileAttributes = 0o120777 << 16`, `versionMadeBy = 788`) and re-emitting it
  with the demo's exact write options (`externalFileAttributes: entry… || UNIX_FILE_0644`,
  `versionMadeBy: VERSION_UNIX_20`) round-trips **intact**:
  `WRITE … mode=0xa1ff isSymlink=true content="../Versions/Current/Headers"`.
  zip.js 2.8.23 supports both options per source (`lib/core/zip-writer.js:403`, `:444`,
  `:467-488`) — no masking of file-type bits. The review's write-side claim does not
  reproduce for canonical inputs.
- **Decision: A.** The real defect is on the **sealing** side plus implicitness:
  1. CR: symlinks are currently `hash_file`d by target text → `files2` gets a regular
     file hash; native emits `{"symlink": target}` via the builder's symlink path.
     Fix: detect symlink entries and call `signer.add_symlink(relPath, targetText)`
     (same path namespace as `hash_file`). The target is decoded **strictly**
     (`TextDecoder` with `fatal: true`; non-UTF-8 targets throw — native extraction is
     strict too, `extract.rs:529-533`), and the sealed bytes are the
     `TextEncoder` re-encode of that same text, which is byte-identical for valid
     UTF-8 — so what the write pass emits and what CodeResources seals can never
     diverge.
  2. Write: add an explicit `isSymlinkEntry(entry)` branch that emits the target
     bytes with Unix made-by and `compressionMethod: 0` (Stored — matching native
     `add_symlink`; zip.js would otherwise deflate), instead of relying on
     `|| fallback` pass-through. Detection (cold-review FIX 7):
     `((entry.versionMadeBy >> 8) === 3) && ((((entry.externalFileAttributes >>> 16) & 0xffff) || (entry.unixMode ?? 0)) & 0xF000) === 0xA000` —
     the made-by gate plus either the central-directory mode or the mode zip.js
     derives from a `0x7855` Unix extra field (`zip-reader.js:808-838`).
     **Emit uses the SAME mode expression, written into `externalFileAttributes`** —
     the single authoritative field (zip.js `index.d.ts:1000-1014`: "treat
     `externalFileAttributes` as authoritative… set it explicitly"):
     `externalFileAttributes: ((mode & 0xffff) << 16) | (entry.externalFileAttributes & 0xff)`.
     The detection gate guarantees `mode` carries `0xa000`, so the value is never 0
     and the writer's regular-file default (`zip-writer.js:459-465`) cannot fire;
     recomposition at `:488` preserves it. Passing a raw zero/extra-field-only value
     would emit a regular file — detect and emit must never disagree. The
     `|| UNIX_FILE_0644` fallback stays for genuine regular files with zero
     attributes. The branch runs **after** directory handling and the reserved-path
     skips (a symlink planted at `_CodeSignature/…` or `embedded.mobileprovision`
     must stay excluded with those paths). The 4096-byte cap (native's bound,
     `extract.rs:103-109`; zip.js enforces nothing) is checked **before reading**
     from `entry.uncompressedSize`, and the read itself goes through a capped
     chunk reader that aborts the moment accumulated bytes exceed 4096 — a lying
     central directory cannot force a multi-gigabyte allocation first.
  3. Hashing symlink targets as file content is removed (replaced by 1); the write of
     target bytes continues (that *is* a symlink's content).
- **Rejected:** B — unnecessary, probe proves pass-through works; C — leaves CR
  sealing divergent from Apple/native format (the part that actually breaks installs).
- **Recorded for the report:** item 6's stated mechanism (write-side loss) was not
  reproduced; fix covers the real (sealing) defect + explicitness as the brief's
  wording asks.

### 2.7 App-root discovery

- **Candidates:** (A) one pure helper `findAppRoot(entries)` deriving prefixes from
  **file** entries, requiring exactly one app; (B) keep the directory-entry regex and
  add a file-derived fallback (two discovery paths); (C) common-prefix heuristic.
- **Decision: A.** `findAppRoot(entries)` collects distinct prefixes matching
  `^Payload/[^/]+\.app/` from file entries (directory entries irrelevant), returns the
  single prefix, throws if zero (listing that no `Payload/*.app` was found) or >1
  (listing all candidates). Both `loadIpa` and `signIpa` call it — deleting the
  duplicated regexes. `index.html:84`: `accept=".ipa,.zip"` (drop the unloadable `.app`)
  and the hint states the archive must contain exactly one `Payload/<name>.app`.
- **Rejected:** B — two discovery conventions in one flow is how the current
  load/sign divergence happened; C — over-clever, breaks on `Payload/App.app/Watch/…`.
- **Strictness vs native:** native takes the first `.app` found (no uniqueness check);
  the brief mandates exactly-one. Brief wins; the demo is intentionally stricter to
  make ambiguous inputs a loud, early error instead of a coin flip.

### 2.8 Empty P12 password

- **Candidates:** (A) drop the length check from `updateSignButton`; (B) keep a check
  plus an explicit "no password" checkbox.
- **Decision: A.** Readiness = IPA + P12 + profile + non-empty bundle ID. The
  placeholder is relabeled "certificate password (leave empty if none)". A wrong
  password still fails closed: `new WasmSigner` throws (MAC mismatch / parse error) and
  the item-2 catch surfaces it; empty-password P12s are supported by the parser
  (fixtures `empty_password.p12`, `pkcs12.rs:839/852/895-906`).
- **Rejected:** B — extra UI state for a case the credential constructor already
  distinguishes correctly.

### 2.9 Memory

- **Candidates:** (A) size guards + restructure so per-entry buffers are released
  after their last use (two-pass: hash during per-bundle processing, re-read source
  entries at write time); (B) guards only, keep the all-resident `fileMap`;
  (C) full streaming writer with interleaved signing.
- **Decision: A, with C explicitly deferred (per brief: demo scale, not a signer
  service).**
  - **Guards (documented in the error text):** reject input files > 512 MiB in
    `loadIpa`; after `getEntries`, reject archives whose declared uncompressed total
    over **all non-directory entries** exceeds 2 GiB (zip-bomb guard; both phases use
    the same sum, keeping the helper prefix-free). Runtime backstop (cold-review fix):
    at every decompression, if an entry's actual bytes exceed its **declared**
    `uncompressedSize`, throw immediately — that is the lying-central-directory case,
    and together with the declared-total cap it bounds total expansion. No
    cross-read cumulative counter: the per-bundle scans re-read nested subtrees once
    per ancestor level, so summing read events would false-reject legitimate large
    bundles. One helper `assertArchiveWithinLimits` used by both phases.
  - **Release:** no full `fileMap` at all. Per-bundle processing (item 3) reads one
    entry at a time: resources are hashed immediately and never retained; only
    signed/executable bytes, generated CodeResources, the rewritten plist, and the
    profile are retained (needed until the write pass). The write pass re-reads
    unchanged entries from the source zip (a second decompression — CPU tradeoff for
    the memory win) and uses the retained map for replaced bytes. `fileMap`/`bundleEntries`
    disappear.
  - Object URLs: remember the previous `URL.createObjectURL` result and
    `revokeObjectURL` it when a new run starts (currently every successful sign leaks
    a blob).
  - `hash_file` takes `&[u8]`: the generated glue (`pkg/zsign_wasm.js:126-131`)
    `malloc`s argument buffers and frees **no** arguments (all glue frees are return
    buffers). Empirically settled by probe: a metric-validated node run (known 200 MB
    alloc → `200.0` MB delta) showed 100 × 4 MB borrowed-arg calls → arrayBuffers
    delta `0.0`, RSS delta `0.1 MB` — **no per-call accumulation**; deallocation
    happens on the generated-Rust-shim side, so the wasm heap is bounded by live data,
    not by bytes hashed. The plan re-runs this probe pattern during implementation.
  - **Deferred, explicitly:** true streaming (`zip.js` writable-stream writer +
    `hash_file_chunk`) — the API exists (`hash_file_chunk`) but interleaving it with
    deepest-first bundle ordering is not worth it at demo scale; recorded in §5 and the
    final report as deferred, not as a stub.
- **Rejected:** B — the residency peak *is* the read-all phase, guards alone leave it
  intact; C — complexity far beyond demo scope, explicitly optional in the brief.

## 3. Revised flow architecture

Single file `main.js`, keeping the existing two-phase UX (load → configure → sign).

### 3.1 Pure helpers (node-probeable by source extraction)

- `findAppRoot(entries) -> { prefix, name }` — §2.7; throws on 0 or >1 apps.
- `rewriteBundleIdentifier(plistBytes, newId) -> Uint8Array` — §2.4; throws on
  unsupported format / missing key / non-ASCII id; identity fast path.
- `fileStem(path) -> string` — final path component first (split on `/`, drop empty
  parts — a trailing-slash bundle prefix yields its bundle component), then Rust
  `Path::file_stem` semantics on that component (strip after a non-leading dot;
  leading-dot names unchanged): `Frameworks/Foo.bar.framework/Foo` → `Foo`,
  `Payload/A.app/Frameworks/F.framework/` → `F`, `libFoo.dylib` → `libFoo`.
- `hashEntry(signer, relPath, bytes)` — routes one file into the signer's current
  resources round: `bytes.length <= 128 MiB` → `signer.hash_file(relPath, bytes)`;
  larger → `signer.hash_file_chunk` in 64 MiB slices with `isFinal` on the last slice
  (the landed `hash_file` throws `ZSIGN_INPUT_TOO_LARGE` above 128 MiB; the bytes are
  already in hand, so chunking needs no extra retention). Errors propagate —
  fail-closed.
- `isSymlinkEntry(entry) -> boolean` — §2.6.
- `assertArchiveWithinLimits(entries, file)` — §2.9 guards.
- `tryExtractBundleId/tryExtractExecutableName(plist, wasmReady)` — existing, all call
  sites now pass the flag; while wasm is ready, `parse_info_plist` failures propagate
  (`ZSIGN_INVALID_PLIST`) — the XML-regex fallback exists ONLY for the
  wasm-unavailable path.

### 3.2 Sign pipeline (replaces steps 3-9 of the current `signIpa`)

```
FIRST (synchronously, before any await): snapshot the run inputs —
    `run = { ipaFile, p12Bytes, password, profileBytes, bundleId }` captured from
    state/DOM at entry; every later step reads ONLY `run.*` (never live globals or
    DOM values), so a mid-run control change cannot split one run across two inputs
    (the corruption proof: profile A-derived entitlements embedded with profile-B
    bytes read at the late root scan). The credential/ID inputs and pickers are also
    disabled for the run and re-enabled in `finally` — belt; the snapshot is the fix.
→ init wasm (idempotent) → signers: rootSigner = new WasmSigner(run.p12Bytes, run.password, run.profileBytes)
    and nestedSigner = new WasmSigner(run.p12Bytes, run.password, null)   // entitlements parity, §2.3
→ open ZipReader (one reader for scan + write passes, closed in finally)
→ getEntries → findAppRoot (file-derived) → assertArchiveWithinLimits
    (the limits helper is introduced by plan Task 9; Tasks 3/7 defer this call until
    it exists — see the plan's explicit deferral notes)
→ metadata pass: reject any entry whose filename differs from its trim() (the zip.js
    writer trims names — sealing and output must share one canonical name, FIX 17);
    collect source directory names EXCLUDING the reserved root `_CodeSignature`
    subtree (those dirs are skipped on write — counting them would defeat append-time
    directory synthesis)
→ read root Info.plist → wasmReady? parse_info_plist : XML fallback
    → executable name: missing/empty → THROW (item 5, before any resource work)
    → run.bundleId is the root identifier
→ build bundle set {prefix → depth}: root + ancestor dirs with ext
  app/framework/appex (case-insensitive); sort deepest-first
→ classify: for each file entry under root **excluding symlink entries**
  (isSymlinkEntry first — a target beginning with Mach-O magic must be sealed as a
  symlink, never signed), resolve executable membership for EVERY bundle: read each
  bundle's Info.plist (bytes retained for its signing step), extract
  CFBundleExecutable (wasmReady flag), and require a matching Mach-O path in that
  bundle's subtree — any bundle failing → THROW before any hashing/signing (item 5
  generalized; mirrors native get_main_executable, `mod.rs:838-894`). Also THROW
  here if any SOURCE entry sitting at a **generated-override path** (root
  `Info.plist`, root `embedded.mobileprovision`, any discovered bundle's
  `_CodeSignature/CodeResources`) is a symlink — the scan would seal it as a
  symlink while the write pass would emit regular generated bytes (type/content
  disagreement must fail closed before signing)
→ per bundle B, deepest-first, using signer = (B is root ? rootSigner : nestedSigner):
    1. read B's Info.plist. ROOT ONLY, ALWAYS call
       infoPlistData = rewriteBundleIdentifier(infoPlistData, run.bundleId)
       (validates unconditionally, identity-fast-paths, §2.4) and ALWAYS
       signedFiles[rootPrefix + "Info.plist"] = infoPlistData  (BLOCKER 2)
    2. sign immediate non-main Mach-Os of B (subtree minus deeper bundles minus
       _CodeSignature): identifier = fileStem(relPath), args (null, null);
       successes → signedFiles[fullPath]; failures → logged + collected
       → if any failures: THROW aggregated (item 2) before any hashing of B
    3. signer.reset_resources(); signer.set_main_executable(B.execName)
    4. scan B: hash every FILE entry under B's prefix (relPath = strip(prefix)),
       plus every signedFiles key under B's prefix that has NO source file entry
       (virtual entries — generated nested CodeResources of already-sealed children,
       BLOCKER 1):
         - root embedded.mobileprovision: hash run.profileBytes (source bytes skipped)
           AND set signedFiles[rootPrefix + "embedded.mobileprovision"] =
           run.profileBytes — the write pass skips the source entry and emits this key
           through the append-unmatched rule; without the insert the output would
           lose the profile entirely
         - symlink entry → signer.add_symlink(relPath, targetText) (strict UTF-8
           decode; declared and actual size ≤ 4096 B enforced around the read — §2.6.
           FINAL state; staged: Task 3 hashes symlink payloads as regular files,
           Task 6 declares readCapped/decodeStrict and converts this branch)
         - else → hashEntry(signer, relPath, signedFiles[fullPath] ?? fresh source bytes)
           — chunk-routes buffers > 128 MiB (§3.1). NO in-scan existence expectation:
           B's own main executable is excluded from B's round by the builder and only
           signed at step 6, and B's CR does not exist yet — completeness is enforced
           solely by the step-6 post-loop assertion (FIX 11: signedFiles keys are
           ALWAYS full zip paths)
       (builder's should_exclude auto-skips B's _CodeSignature + B's main exec;
        deeper bundles' current signed bytes + their _CodeSignature are included —
        native parity)
    5. CR_B = signer.build_code_resources();
       signedFiles[B.prefix + "_CodeSignature/CodeResources"] = CR_B
    6. signedFiles[execFullPath] = signer.sign_macho_fat(currentExecBytes,
       identifier_B, plistBytes_B, CR_B)   // identifier_B = root: validated UI id
                                           // (== rewritten plist id); nested:
                                           // own CFBundleIdentifier || fileStem(prefix)
       // BEFORE the write pass: assert every bundle's execFullPath, every CR path,
       // the root Info.plist key, and the root embedded.mobileprovision key are in
       // signedFiles, else THROW (FIX 11)
→ counters for the summary UI (BLOCKER 6): machoSigned += successful sign calls;
  processedFiles = non-directory source entries under root (set in metadata pass)
→ output write pass — one uniform rule, in this exact order (FIX 12):
    emitted = new Set(); sourceDirs = <from metadata pass>
    for (entry of entries):
      1. name = entry.filename; skip if name starts with "__MACOSX/"
      2. if entry.directory:
           skip if name is inside the root _CodeSignature subtree (reserved);
           else emit dir with original attrs; sourceDirs already known; continue
      3. reserved skip: name inside root _CodeSignature subtree, or name ==
         rootPrefix + "embedded.mobileprovision" (source bytes replaced below)
      4. if signedFiles.has(name): emit signedFiles bytes (original attrs/made-by/
         lastModDate where the entry existed; generated attrs otherwise); mark emitted
      5. else if isSymlinkEntry(entry): emit target bytes, mode from the SAME
         detection expression written into externalFileAttributes
         (`((mode & 0xffff) << 16) | (entry.externalFileAttributes & 0xff)` —
         §2.6; never zero), versionMadeBy Unix, compressionMethod 0 (Stored)
      6. else: fresh-read source bytes (per-entry actual ≤ declared check) → emit
    then append unmatched output (BLOCKER 1): for (const key of
      [...signedFiles.keys()].filter((k) => !emitted.has(k)).sort()):
      - if key ends with "_CodeSignature/CodeResources" and its "_CodeSignature/"
        directory is neither a source dir nor already emitted → emit that dir entry
        first (root and nested alike — no special-cased synthetic block)
      - emit signedFiles[key]
→ zipWriter.close() → success UI only: textContent summary (processedFiles,
  machoSigned, output size, elapsed) + object URL (previous URL revoked)
```

Notes:

- Hashing happens once per bundle level over that level's subtree (native does the
  same via per-level scans — double hashing of nested subtrees is native-parity, not
  waste introduced here).
- `signedFiles` is the single **final-byte override map**, keyed by full zip path for
  its entire lifetime (root-relative keys of the interim Task 2 code are migrated when
  Task 3 lands). Membership = "this path's final content is generated". Missing
  expected overrides throw; ordinary resources fall back to a fresh source read.
- The write pass runs only after every bundle sealed successfully (fail-closed: no
  output exists on error).
- `loadIpa` uses `findAppRoot` + `assertArchiveWithinLimits` (limits added by Task 9)
  for early UX errors but performs no signing state; `signIpa` re-derives everything
  from its own reader (no shared mutable discovery state beyond `wasmReady`).

### 3.3 Error model

- Thrown `Error`s are the only failure channel; every failure is logged through the
  text-content `log()` (no HTML parsing), then rethrown or thrown fresh with context.
- Structural failures (no root app, limits exceeded, unresolvable executable, plist
  rewrite impossible) throw before hashing/signing where feasible.
- Per-binary signing failures accumulate → one aggregated throw before the bundle's
  hashing step (so a partial bundle is never sealed).
- `finally`: close the reader, free **both signers** (root and nested, when
  present), clear the in-flight guard, re-enable the inputs, re-enable the sign
  button. Download
  href/summary/object URL are set only after `zipWriter.close()` resolves.
- wasm `Error.message` strings are displayed verbatim but never parsed or matched
  (ZSN-40 may restyle them).

## 4. Verification strategy (per item, before its commit)

- **Gate (every item):** `npm ci && npm run build` in `examples/web` with the fresh
  `crates/zsign-wasm/pkg` (already built this lane; rebuild only if wasm sources
  change — they do not). This is the exact ZSN-31 scheduled-job path.
- **Red/green for pure logic:** throwaway node scripts that extract the helper
  functions from `main.js` source (balanced-brace slicing) and assert fixtures —
  e.g. `rewriteBundleIdentifier` on XML + binary plists (structural assertions:
  byte-diff bounds, marker preservation, offset-table consistency, re-parse with
  Python `plistlib.loads` — an independent implementation), `findAppRoot` on
  file-only / dir-ful / multi-app fixtures, `assertArchiveWithinLimits` on fabricated
  entry metadata, `isSymlinkEntry` on fixture attrs. Red = the pre-fix
  behavior described in the task; green = assertion passes. Probes live in
  `/tmp/zsn41-probes/` (outside the repo — scope allows only main.js/index.html/
  package.json scripts).
- **Behavioral scenarios without a harness:** each task records the exact failing
  observation pre-fix (e.g. "dylib signing throws → log shows ✗ … yet Done in …s and
  Download button visible") and the post-fix observation (error line + no download).
- **Browser flow (honesty note):** full end-to-end signing needs a real P12, profile,
  and IPA in a browser — out of CI scope. If a headless run is feasible locally, the
  report records what was observed; otherwise the report states exactly which paths
  need a browser.

## 5. Known items, limitations, divergences (recorded, not silent)

1. **Streaming deferred** (§2.9): `hash_file_chunk` + zip.js writable-stream streaming
   not used; demo-scale guards + release-as-you-go instead. Explicit deferral, not a stub.
2. **Missing `CFBundleIdentifier` key**: demo throws (native inserts the key). Real
   IPA Info.plists always carry it; divergence chosen to keep the pure helper small.
3. **Root-only rewrite**: UI bundle-ID edits do not touch nested `.appex`/`.framework`
   identifiers — matches native (`mod.rs:370-371`).
4. **Entitlements**: handled in-lane via the two-signer split (§2.3) — the root main
   executable uses the profile signer; nested main executables use the no-profile
   signer; root and nested **non-executables** receive `EMPTY_ENTITLEMENTS` under
   either signer (`signer.rs:168-175`) — matching native (`mod.rs:394-395`,
   `:668-680` through the same core path). Residual
   ergonomics only: the split costs one extra credential parse (§6).
5. **Strictness**: exactly-one `.app` enforced (brief) where native takes the first
   found (§2.7).
6. **Review divergence on item 6**: write-side symlink loss not reproduced at zip.js
   2.8.23 (probe output in §2.6); fix targets the sealing-side defect + explicit
   branch. Reported prominently.
7. **Bundle-ID input validation**: `^[A-Za-z0-9._-]+$` (≤255 chars) is enforced by
   `rewriteBundleIdentifier` itself, which is invoked at sign time on **every** run
   including the identity path (the HTML input has no pattern attribute — validation
   lives in the helper, not the UI).
8. **AppleDouble `._*` files** inside the bundle are still copied/hashed (pre-existing,
   out of queue — listed in the report's out-of-scope observations).
9. **`dataDescriptor: false`** writer setting retained (pre-existing; probe shows it
   round-trips symlink entries correctly).
10. **Out-of-scope observations** (from the anchor scout, report-only): no
    `response.ok` checks on wasm fetch; double `initWasm` (safe per glue idempotency);
    dead module state (`ipaEntries`, `appPrefix`, `appName` in load-phase);
    `outputName` edge cases
    for non-`.ipa` inputs; stale-credential retention across IPA reloads; dead
    `<pre id="plist-output">`. None fixed here — queue discipline (the summary-counter
    item formerly listed here IS fixed — Task 3 supplies `processedFiles`/`machoSigned`).

## 6. Cross-lane requests (ZSN-40, wasm) — ALL RESOLVED, none open

1. Entitlements suppression — **resolved two ways**: the landed `set_entitlements`
   setter exists, but its own docs state that "no entitlements while holding a
   profile" requires constructing without profile bytes — which is exactly the
   two-signer split adopted in §2.3 (no wasm change needed).
2. Stable error identity — **landed**: every throw carries `error.code`
   (`ZSIGN_*`, table in §1.2); the demo displays codes, never parses messages.
3. Argument-buffer freeing — **resolved with evidence**: the glue frees no arguments
   yet a metric-validated probe showed zero accumulation (§2.9); Rust-shim side
   deallocates. Wasm heap is bounded by live data; guard values stand.
