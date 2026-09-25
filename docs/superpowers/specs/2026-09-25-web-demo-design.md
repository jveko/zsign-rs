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

### 1.2 wasm API (`MapWasmApi`, READ-ONLY `crates/zsign-wasm/src/lib.rs`, 244 lines)

- Two exported classes: `MachOInfo` (2 getters) and `WasmSigner`. Surface used/available
  to this demo: `new WasmSigner(p12, password, profile)` (throws `Error` with Rust
  `Display` text — bad password surfaces here), `team_id()`,
  `set_main_executable(name)`, `hash_file(path, data) -> bool` (false = excluded),
  `hash_file_chunk`, **`add_symlink(path, target) -> bool`**,
  **`reset_resources()`**, `build_code_resources() -> Uint8Array` (idempotent, does not
  consume state; throws on unfinished streaming hashes), static
  `parse_info_plist(data) -> {bundle_id, executable}` (handles XML **and** binary
  plists), static `parse_macho`, static `extract_entitlements`, `entitlements()`,
  `sign_macho(data, id, infoPlist, codeResources)` + `sign_macho_fat` alias, `free()`.
- `sign_macho` treats `info_plist` as opaque bytes that are **hashed** (`lib.rs:195` →
  `signer.rs:111 dual_hash`) — no rewrite happens inside wasm. Whatever JS passes must
  be byte-identical to what JS writes into the IPA.
- Hash state: accumulated per instance; `set_main_executable` must precede hashing
  (exclusion is evaluated at insert time, `code_resources.rs:333-336`); `reset_resources()`
  clears the per-instance builder → one signer instance can seal many bundle levels
  sequentially. Instances are fully independent; multiple `WasmSigner`s can coexist.
- `zsign-core`'s `should_exclude` is shared with the native flow: root-anchored
  `_CodeSignature` exclusion, own-main-executable exact-match exclusion, `files2`
  omission of top-level `Info.plist`/`PkgInfo`/`.DS_Store`. The demo does **not** need
  to re-implement these predicates.
- No plist-writing API exists (item 4 is JS-owned). No error codes/warnings/size guards
  today; ZSN-40 may add additive fields — JS must not assume `Error.message` strings are
  stable (substring matching forbidden as a control-flow mechanism).
- `info_plist`/entitlements asymmetry: wasm applies the instance's profile-derived
  entitlements to **every** `sign_macho` call; native passes entitlements only for the
  main-bundle executable. JS cannot suppress this (no setter) → cross-lane note (§6).
- Locked deps: `@zip.js/zip.js` 2.8.23, vite 6.4.1; `zsign-wasm` is
  `file:../../crates/zsign-wasm/pkg` (must exist before `npm ci`).
- Generated glue is idempotent on init (`pkg/zsign_wasm.js:505` early-returns), so the
  demo's second `initWasm` call in `signIpa` is safe.
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
   d. scan the whole subtree (follow_links=false) with exclusions = root-anchored
      `_CodeSignature` + own main executable → write `_CodeSignature/CodeResources`.
      Parent therefore seals: nested **signed** executable bytes, nested `Info.plist`,
      nested payload, nested `_CodeSignature/CodeResources`, root
      `embedded.mobileprovision`. Symlinks are sealed via `{"symlink": target}`
      entries produced by the builder's symlink path (`zsign-core code_resources.rs:445-446`),
      with legacy `files` skipping symlinks (`:414-416`);
   e. sign this bundle's main executable with (own identifier, own plist bytes, own
      CodeResources bytes); entitlements only for the root bundle (`mod.rs:394-395`).
4. **Bundle-ID rewrite** targets the **root** Info.plist only
   (`mod.rs:370-371`), parse-any-encoding → mutate → serialize (native always emits
   XML), before any CodeResources generation (`:370-377` before `:385+`).
5. **Symlink output**: `zip.add_symlink` with mode `0o120777`, made-by Unix, target
   bytes Stored (`archive.rs:254-260`, zip 7.2.0 `write.rs:1549-1573`).
6. **Fail-closed**: every step `?`-propagates; the output IPA exists only after total
   success; encrypted Mach-O is a hard error.

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
  `zip-entry.js PROPERTY_NAMES:77-121`) — derive `(entry.externalFileAttributes >>> 16)`
  (which `isSymlinkEntry` does). Writer options read by `addFile`: `versionMadeBy`
  (`zip-writer.js:403`, actual default 768 = `0x0300`, pass `(3<<8)|20`),
  `externalFileAttributes` (`:444`, default 0), `unixMode` (`:407`), `directory`
  (`:445`), `msDosCompatible`/`msdosAttributes*` (`:402/:424-425`); there is **no**
  `unixPermissions` option (that is JSZip) and no first-class symlink support. A
  non-zero `externalFileAttributes` is **not** masked: Unix defaults fire only when it
  is 0 (`:453-465`); the value is recomposed as `((unixMode & 0xffff) << 16) |
  (extAttr & 0xff)` (`:488`) preserving the Unix type/permission bits (bits 8-15
  dropped — irrelevant), and `setUint32` at `:1507` writes it verbatim. The one silent
  destroyer is passing `msdosAttributes*` without unix metadata (forces `msDosCompatible`,
  zeroes the host byte, skips Unix recomposition — `:431-433`): the demo never passes
  those. Writing a symlink = payload target bytes + `externalFileAttributes = mode << 16`
  + `versionMadeBy = 0x0314` + name NOT ending in `/` — exactly what the Task 6 branch
  and the §2.6 probe exercise.
- **innerHTML vs textContent (MDN):** "Node.textContent should be used when you know
  that the user-provided content should be plain text. This prevents it being parsed as
  HTML"; `createTextNode` "can be used to escape HTML characters"; `Node.textContent`
  is absent from MDN's TrustedHTML sink list (only `Element.innerHTML`,
  `insertAdjacentHTML`, `outerHTML`, … appear). Recommended shape = `createElement`
  structure + `textContent` for every dynamic string (decision §2.1).
- **Vite 6 + `?url` wasm:** importing `zsign_wasm_bg.wasm?url` is the documented
  pattern (Vite guide, "Accessing the WebAssembly Module"); the asset is emitted under
  `dist/assets` with a hashed name (observed: `dist/assets/zsign_wasm_bg-BLrlmTX6.wasm`
  in this lane's green build) and fetched at runtime; inlining only under 4 KiB (never
  for a 1.1 MB wasm); COOP/COEP not required (no `SharedArrayBuffer`/`Atomics` in the
  glue); the demo's ArrayBuffer init path (`initWasm({module_or_path: wasmBytes})`)
  uses `WebAssembly.instantiate` and sidesteps the `application/wasm` MIME requirement
  (`zsign_wasm.js:466-474`).
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
  blob). Resource cleanup moves to `finally`: `signer.free()` and `zipReader.close()`
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
  rewrites the root only; wasm embeds profile entitlements into every signed binary
  (native: root executable only) — not suppressible from JS (§6).

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
    UI validates the new id against `^[A-Za-z0-9._-]+$` so it is always ASCII
    (marker types verified empirically against Python `plistlib`, design §1.4);
  - XML (`<?xml`/`<plist`): replace the `<string>` value following
    `<key>CFBundleIdentifier</key>`;
  - anything else (no CFBundleIdentifier key, non-string value, unknown format) →
    throw a precise error (fail-closed; native inserts a missing key — known
    divergence, §5).
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
- **Empirical finding (probe, run at locked zip.js 2.8.23, `examples/web/probe-symlink.mjs`,
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
     Fix: detect symlink entries and call `signer.add_symlink(relPath, target)`
     (same path namespace as `hash_file`).
  2. Write: add an explicit `isSymlinkEntry(entry)` branch
     (`(externalFileAttributes >>> 16) & 0xF000) === 0xA000`) that emits the target
     bytes with the original attributes and Unix made-by, instead of relying on
     `|| fallback` pass-through. The `|| UNIX_FILE_0644` fallback stays for genuine
     regular files with zero attributes.
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
    for bundle entries exceeds 2 GiB (zip-bomb guard); during hashing, keep a
    cumulative counter of actually-decompressed bytes and abort past the same 2 GiB
    (central-directory sizes can lie). One helper `assertArchiveWithinLimits` used by
    both phases.
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
  - `hash_file` takes `&[u8]` — glue behavior for wasm-side freeing is **verified
    against `pkg/zsign_wasm.js` during implementation** (plan step); if the glue does
    not free, note it as a wasm-side finding (§6) and cap expectations in the report.
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
- `fileStem(path) -> string` — Rust `Path::file_stem` semantics (strip after last dot).
- `isSymlinkEntry(entry) -> boolean` — §2.6.
- `assertArchiveWithinLimits(entries, file)` — §2.9 guards.
- `tryExtractBundleId/tryExtractExecutableName(plist, wasmReady)` — existing, all call
  sites now pass the flag.

### 3.2 Sign pipeline (replaces steps 3-9 of the current `signIpa`)

```
init wasm (idempotent) → new WasmSigner (throws on bad creds) → open ZipReader (one
reader for hash + write passes, closed in finally)
→ getEntries → findAppRoot (file-derived) → assertArchiveWithinLimits
→ read root Info.plist → wasmReady? parse_info_plist : XML fallback
    → executable name: missing/empty → THROW (item 5, before any resource work)
    → bundleId input is the root identifier (UI field)
→ metadata pass: build bundle set {prefix → depth}: root + ancestor dirs with ext
  app/framework/appex (case-insensitive); sort deepest-first
→ classify: for each file entry under root, resolve executable membership
    (root main exec must match a Mach-O by relative path → else THROW, item 2/5)
→ per bundle B, deepest-first:
    1. read B's Info.plist (root: rewrite via rewriteBundleIdentifier if id changed;
       root's rewritten bytes replace the map entry so the zip write matches)
    2. sign immediate non-main Mach-Os of B (subtree minus deeper bundles minus
       _CodeSignature): identifier = fileStem(relPath), args (null, null);
       successes → signedFiles[fullPath]; failures → logged + collected
       → if any failures: THROW aggregated (item 2) before any hashing of B
    3. reset_resources(); set_main_executable(B.execName)
    4. scan: every file entry under B's prefix, relPath = strip(prefix):
         - source embedded.mobileprovision at ROOT: hash profileBytes instead
         - symlink entry → add_symlink(relPath, targetText)
         - else → hash_file(relPath, signedFiles[fullPath] ?? fresh bytes)
       (builder's should_exclude auto-skips B's _CodeSignature + B's main exec;
        nested deeper bundles' current signed bytes + their _CodeSignature are
        included — native parity)
    5. CR_B = build_code_resources();
       signedFiles[prefix + "_CodeSignature/CodeResources"] = CR_B
    6. signedFiles[execFullPath] = sign_macho_fat(currentExecBytes, identifier_B,
       plistBytes_B, CR_B)   // identifier_B = root: UI id (rewritten plist id);
                             // nested: own CFBundleIdentifier || fileStem(prefix)
                             // plistBytes_B: root rewritten, nested raw
→ output write pass (same reader, entries re-read):
    iterate source entries: __MACOSX skipped; root _CodeSignature subtree skipped
    (re-emitted synthetically below); root embedded.mobileprovision skipped
    (re-emitted with profileBytes); anything present in signedFiles emitted from the
    map (signed binaries, all generated CRs, rewritten plist); symlink entries from
    source emitted via the explicit symlink branch (target bytes + original attrs);
    everything else emitted from a fresh read with original attrs/made-by/lastModDate
    → then synthetic adds: root _CodeSignature/ dir, root CodeResources,
      embedded.mobileprovision
→ close writer → success UI: textContent summary + object URL (previous URL revoked)
```

Notes:

- Hashing happens once per bundle level over that level's subtree (native does the
  same via per-level scans — double hashing of nested subtrees is native-parity, not
  waste introduced here).
- The write pass runs only after every bundle sealed successfully (fail-closed: no
  output exists on error).
- `loadIpa` uses `findAppRoot` + `assertArchiveWithinLimits` for early UX errors but
  performs no signing state; `signIpa` re-derives everything from its own reader (no
  shared mutable discovery state beyond `wasmReady`).

### 3.3 Error model

- Thrown `Error`s are the only failure channel; every failure is logged through the
  text-content `log()` (no HTML parsing), then rethrown or thrown fresh with context.
- Structural failures (no root app, limits exceeded, unresolvable executable, plist
  rewrite impossible) throw before hashing/signing where feasible.
- Per-binary signing failures accumulate → one aggregated throw before the bundle's
  hashing step (so a partial bundle is never sealed).
- `finally`: close reader, `signer.free()`, re-enable the sign button. Download
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
  byte-diff bounds, marker preservation, offset-table consistency, re-parse with an
  independent minimal bplist reader in the probe), `findAppRoot` on file-only /
  dir-ful / multi-app fixtures, `isSymlinkEntry` on fixture attrs. Red = the pre-fix
  behavior described in the task; green = assertion passes. Probes are deleted before
  the lane's commits (not committed — scope allows only main.js/index.html/
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
4. **Entitlements**: wasm embeds profile entitlements in every signed binary; native
   only in the root executable. Not controllable from JS (§6, cross-lane).
5. **Strictness**: exactly-one `.app` enforced (brief) where native takes the first
   found (§2.7).
6. **Review divergence on item 6**: write-side symlink loss not reproduced at zip.js
   2.8.23 (probe output in §2.6); fix targets the sealing-side defect + explicit
   branch. Reported prominently.
7. **Bundle-ID UI input validation**: `^[A-Za-z0-9._-]+$` enforced at sign time (also
   the ASCII precondition of the bplist splice).
8. **AppleDouble `._*` files** inside the bundle are still copied/hashed (pre-existing,
   out of queue — listed in the report's out-of-scope observations).
9. **`dataDescriptor: false`** writer setting retained (pre-existing; probe shows it
   round-trips symlink entries correctly).
10. **Out-of-scope observations** (from the anchor scout, report-only): no
    `response.ok` checks on wasm fetch; double `initWasm` (safe per glue idempotency);
    dead module state (`ipaEntries`, `appPrefix`, `appName` in load-phase);
    summary labels count attempted, not successful, signs; `outputName` edge cases
    for non-`.ipa` inputs; stale-credential retention across IPA reloads; dead
    `<pre id="plist-output">`. None fixed here — queue discipline.

## 6. Cross-lane requests (ZSN-40, wasm)

1. Optional entitlements suppression for non-root/nested signing (native parity:
   entitlements only in the root executable's signature).
2. Stable error identity (code field) would let the demo distinguish e.g.
   `InvalidPassword` from other cert failures without substring matching — currently
   the raw `Display` text is shown to the user (acceptable for a demo).
3. Confirm glue-side freeing of `&[u8]` arguments (`hash_file`) — if args leak into
   linear memory, wasm heap grows with total hashed bytes; demo mitigations are
   documented in §2.9 either way.
