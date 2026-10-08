# Content-based input dispatch and extension-preserving default output — design

**Date:** 2026-10-08
**Status:** approved for implementation (cold review gate applies to this document together with the plan)

## Problem

The CLI routes the input by file **extension** in exactly two places:

- `run()` reads `cli.input.extension()` once (`crates/zsign-cli/src/main.rs:309`)
  and matches `"ipa" | "app" | _` (`:311-341`), forwarding to `sign_ipa`,
  `sign_bundle`, or `sign_macho`.
- `run_verify()` matches the same way (`:346-355`) and forwards to
  `verify_ipa`, `verify_bundle`, or `verify_macho_file`.

There is no content sniffing anywhere in `main.rs` (grep for `PK`, magic
constants: zero hits; the only content sniff in the file is PEM detection at
`:906`). Two user-visible gaps follow:

1. **Mis-routed archives.** `zsign -o out.ipa app.zip` — the standard upstream
   invocation — falls into the `_` arm and hits the Mach-O parser
   (`ZSign::sign_macho` → `MachOFile::parse` at
   `crates/zsign/src/builder.rs:446`, `Error::MachO "Failed to parse: …"`),
   failing a perfectly valid input. Any archive or bundle whose name lacks the
   magic suffixes fails the same way.
2. **Broken default output / verify round trip.** With no `-o`, both file arms
   build the default via `out.set_extension("signed")` (`:315`, `:332`), so
   `zsign app.ipa` silently writes `app.signed`. `-V app.signed` then routes
   on the (now wrong) extension to `verify_macho_file` and errors with exit 2,
   even though the file is a signed IPA. The project's own design record
   rejected extension dispatch; this closes it.

Exit-code surface today: `main()` maps any `run()` error to exit 1
(`:226-238`); `run_verify` maps report-construction errors to 2 (`:357-361`)
and top-level `report.errors` to 2 (`:385-388`). `-V` conflicts with `-o`
(`:160-192`), so default-name logic only ever affects the sign side.

## Verified facts about current behavior

- Every reusable sniff primitive in the workspace is private to its crate and
  unreachable from the CLI: `is_macho_file`
  (`crates/zsign/src/verify.rs:583-599`, six magics), `IpaSigner::is_macho_binary`
  (`crates/zsign/src/ipa/mod.rs:1852-1876`, same six), the `b"PK"` checks at
  `crates/zsign/src/ipa/mod.rs:367` and `crates/zsign/src/ipa/extract.rs:918`.
  Only `main.rs` and `README.md` are editable for this work, so the CLI gets
  its own local classifier.
- `validate_ipa` accepts any file whose first **two** bytes are `PK`
  (`extract.rs:918-922`) — the same rule upstream uses.
- `sign_bundle(bundle, output: Option<&Path>)` repacks only when the output
  ends in `.ipa` (case-insensitive) and errors otherwise
  (`builder.rs:665-678`); `None` signs in place. That rule lives in the
  facade and must not be re-implemented in the CLI — the bundle arm keeps
  forwarding `cli.output` untouched.
- `create_ipa(app_bundle_dir, output_path, CompressionLevel)` is public via
  `zsign_rs` (`ipa/archive.rs:212`, re-export `lib.rs:60`) and synthesizes
  `Payload/` itself — tests can build real IPA fixtures with no new
  dependencies. `zsign-cli` already depends on `zsign-rs` and on
  `zsign-core` with the `test-fixtures` feature
  (`crates/zsign-cli/Cargo.toml`, dev-dependencies; feature line :22).
- No existing test pins the `set_extension("signed")` default (zero `.signed`
  literals in the tests module), and every existing `-V` test preserves its
  exit code under content routing: valid → 0, unsigned Mach-O → 1, missing /
  garbage / script files → 2 (`main.rs:1138-1198`), signed-out-of-bundle → 2
  (`:1201-1215`).

## External contract (verified against real sources)

*These sources are external and not vendored in this worktree; the citations
below are transcriptions from this item's research pass (upstream at commit
614caa8d; xnu/cctools headers; PKWARE APPNOTE 6.3.x) — the same way the
README migration table already labels its upstream transcriptions. The
in-repo facts this design actually gates on are `validate_ipa`'s 2-byte `PK`
rule (`crates/zsign/src/ipa/extract.rs:918-922`) and the six-magic private
helpers (`verify.rs:583-599`, `ipa/mod.rs:1852-1876`).*

- **Upstream zsign dispatches on content, not extension** at commit 614caa8d:
  `src/zsign.cpp:364-366` — `bZipFile = ZFile::IsZipFile(path)`; if not zip
  and not folder → Mach-O branch. `IsZipFile` reads the first **2 bytes** and
  compares to `"PK"` (`src/common/fs.cpp:313-325`); `IsFolder` is a directory
  test (`src/common/fs.cpp:190-198`). `.zip` inputs are accepted.
- Upstream has **no derived default output**: a zip without `-o` errors
  (`src/zsign.cpp:410-420`), Mach-O and folders sign **in place**; there is no
  `-V`. This port keeps its own default (now extension-preserving) — a
  documented divergence, recorded in the migration table below.
- **ZIP magics** (PKWARE APPNOTE 6.3.x): local file header `PK\x03\x04`
  (§4.3.7 line 389), end-of-central-directory / empty archive `PK\x05\x06`
  (§4.3.16 line 634), spanned/data-descriptor marker `PK\x07\x08`
  (§8.5.3-§8.5.5, with the spec's own conflict caveat) — all carry the
  `PK` 0x4b50 marker (§4.3.1 line 329), which is what the 2-byte rule tests.
- **Mach-O magics** (xnu `EXTERNAL_HEADERS/mach-o/loader.h:62-81`, `fat.h:54-55`;
  FAT64 in cctools `include/mach-o/fat.h:77-78`): `0xfeedface`,
  `0xcefaedfe`, `0xfeedfacf`, `0xcffaedfe`, `0xcafebabe`, `0xbebafeca`,
  `0xcafebabf`, `0xbfbafeca` — the first six match the in-repo private
  helpers; FAT64 (`0xcafebabf`/`0xbfbafeca`) is added here so dispatch is
  permissive (the Mach-O arm's own parser still decides signability and emits
  the precise error).
- No Apple tooling defines a canonical sniff order (UNVERIFIED/NONE); upstream
  zsign's order — directory test, then `PK`, then Mach-O — is the parity
  reference.

## Candidate designs

**A (chosen).** A private `classify_input` in `main.rs` + a private
`signed_output_path` helper; `run()` and `run_verify()` both match on the
classified kind. Local because every sniff helper in the workspace is private
and both editable files live in the CLI crate.

**B. Rejected — sniff with a full `MachOFile::parse` fallback.** Re-parses
large binaries before the signer parses them again (double read + parse of
hundreds of MB), and conflates "parseable" with "is a Mach-O": a FAT-64 file
or a truncated header would fall into a generic unknown-input error instead of
reaching the arm whose parser produces the precise diagnostic. A 4-byte magic
test is the cheaper, more informative boundary.

**C. Rejected — keep extension dispatch for `-V`, sniff only the sign path.**
Leaves the second gap (the `app.signed` verify round trip) exactly where it is;
the ticket's failure mode is a verify-side failure.

**D. Rejected — 4-byte `PK\x03\x04`-only archive test.** Diverges from both
upstream (`fs.cpp` 2-byte memcmp) and the in-repo `validate_ipa` (2-byte);
a `PK`-prefixed non-archive would then be misclassified as unknown instead of
reaching the archive arm whose zip error is the accurate diagnosis.

## Design (candidate A)

### Classifier (`crates/zsign-cli/src/main.rs`)

```rust
enum InputKind { Bundle, Archive, MachO, Unknown }
```

`fn classify_input(path: &Path) -> Result<InputKind, String>` — order:

1. `path.is_dir()` → `Bundle` (parity with upstream `IsFolder`; a directory is
   a bundle candidate regardless of its name — no `.app` suffix required).
2. Open the file and read up to 4 bytes. An open/read failure returns `Err`
   wrapped with the path (`input not found: <path>` for `NotFound`,
   `cannot read input <path>: <err>` otherwise) so the message keeps the path
   the raw OS error loses.
3. First two bytes `PK` → `Archive` (2-byte rule, upstream + `validate_ipa`
   parity; covers `PK\x03\x04`, `PK\x05\x06`, `PK\x07\x08`).
4. The 4 bytes (little-endian `u32`) ∈ the eight Mach-O magics → `MachO`.
5. Otherwise → `Unknown`.

### Routing

- `run()`: `Bundle` → `sign_bundle(&cli.input, cli.output.as_deref())` — the
  arm body is unchanged (the facade keeps ownership of the `.ipa`-suffix
  repack rule and of in-place signing); `Archive` → `sign_ipa` and `MachO` →
  `sign_macho`, both with default output `signed_output_path(&cli.input)` when
  `-o` is absent; `Unknown` → `Err("unsupported input '<path>': expected an
  app bundle directory, ZIP archive, or Mach-O binary")` → the existing error
  path → exit 1 (unchanged class for a failed sign); classify `Err` → same
  path → exit 1.
- `run_verify()`: `Bundle` → `verify_bundle`, `Archive` → `verify_ipa`,
  `MachO` → `verify_macho_file`; `Unknown` and classify `Err` →
  `emit_error` + `ExitCode::2` (the existing "could not complete" class for
  unreadable/unsupported input, same as today's construction errors at
  `:357-361`).
- `--json` shapes are untouched: `report_sign` and `emit_error` are called
  exactly as today.

### Default output name

`fn signed_output_path(input: &Path) -> PathBuf` — `OsString`-safe: take
`file_stem()`, push `"-signed"`, re-append `extension()` after a `.` when
present, and `set_file_name` on the input's parent. Results: `in.ipa` →
`in-signed.ipa`, `in.bin` → `in-signed.bin`, `app` → `app-signed`,
`a.b.tar.gz` → `a.b.tar-signed.gz` (inserted before the last extension, the
same segment `set_extension` used to replace). Used only in the `Archive` and
`MachO` arms; the `Bundle` arm stays in place / `-o`-driven.

### CLI surface

- `input` field doc: `/// Input: app bundle directory, IPA/ZIP archive, or
  Mach-O binary (detected by content, not extension)` — the only Cli doc
  change.

### README (append-only within each section)

- `<INPUT>` row (~:188): describe content detection.
- `-o, --output` row (~:189): document the default
  `<name>-signed.<ext>` (extension preserved) for archives and binaries, and
  in-place for bundles.
- CLI quick start (~:159-176): one appended example line showing the default
  naming (`input.ipa` → `input-signed.ipa`).
- Migration table (~:385-388): one appended row — upstream sniffs `PK` +
  folder with no extension check and has no default output (zip without `-o`
  errors, Mach-O signs in place); this port matches the content sniff, adds an
  explicit unsupported-input error, and derives an extension-preserving
  default instead.

### Explicitly out of scope

- The `.ipa`-suffix repack rule and in-place bundle semantics (facade-owned,
  unchanged).
- `-V`/`-o` conflict wiring, JSON schema, report formats (unchanged).
- The private in-crate sniff helpers in `zsign-rs` (not editable here; their
  six-magic lists differ from the CLI's permissive eight only on FAT64, which
  is a signability question their parsers answer).

## Acceptance criteria

1. `zsign -o out.ipa app.zip` exits 0 and `zsign -V out.ipa` exits 0 (the
   standard upstream invocation round-trips).
2. `zsign app.ipa` with no `-o` writes `app-signed.ipa` (never `app.signed`),
   and `-V app-signed.ipa` exits 0. The same content-first routing means an
   archive renamed to any extension still verifies through `verify_ipa`.
3. A bundle directory without an `.app` suffix signs in place (exit 0) and
   `-V <dir>` exits 0 through `verify_bundle`.
4. Unrecognized content: signing exits 1 with a message naming the path and
   the expected kinds; `-V` exits 2 with the same message.
5. Missing/unreadable input keeps its current codes: sign → 1, `-V` → 2
   (`verify_missing_file_exits_two` still passes unchanged).
6. `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --
   -D warnings`, and `TMPDIR=$PWD/target/tmp cargo test --workspace` all pass.
