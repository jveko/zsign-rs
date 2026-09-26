# 32-bit Mach-O Signing + macOS Keychain Identities Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development with dispatching-parallel-agents for independent tasks. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Sign little-endian 32-bit Mach-O binaries (thin + FAT slices) with a typed big-endian rejection, and load signing credentials from a macOS keychain identity via a new `--keychain-identity` flag.

**Architecture:** ZSN-17 removes six writer bitness guards behind one shared `ensure_signable_bitness` helper, adds width-aware `LC_SEGMENT` field writes, captures `__LINKEDIT` from `Segment32` in the parser, and relaxes `inject_dylib_thin` — pinned by sign→verify round-trip fixtures. ZSN-19 adds `crypto/keychain.rs` (pure `security find-identity` parser + selector + trait-faked loader, live exec `cfg(macos)`, module off on wasm32), a leaf-SHA-1 selector inside `from_p12` so every load-time check runs on the selected pair, and a clap-conflicting `--keychain-identity` flag. No new `zsign_core::Error` variant anywhere (wasm exhaustive match is another lane's file).

**Tech Stack:** Rust workspace, goblin 0.10.7, clap 4.5 derive, thiserror, sha1, canned fixtures via `include_bytes!`/`include_str!`.

**Behavior pins live in** `docs/superpowers/specs/2026-09-26-32bit-keychain-design.md` (§2.3 = P1–P6, §3.6 = tests). Gates: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-core <filter>` / `-p zsign-cli <filter>`; final full gate in Task 10.

**Conventions:** ticket IDs in commit subjects only, never in code comments; no stubs/TODOs; every caller migrated; matches!-style asserts keep the `res.as_ref().err()` footer.

---

### Task 0: Commit the design and plan docs

**Files:**
- Create: `docs/superpowers/specs/2026-09-26-32bit-keychain-design.md` (already written)
- Create: `docs/superpowers/plans/2026-09-26-32bit-keychain.md` (this file)

- [ ] **Step 0.1:** `docs/` is in `.gitignore:34` but prior spec files are tracked — add with force if status hides them:
  Run: `git status --short docs/ ; git add -f docs/superpowers/specs/2026-09-26-32bit-keychain-design.md docs/superpowers/plans/2026-09-26-32bit-keychain.md`
- [ ] **Step 0.2:** Commit:
  Run: `git commit -m "docs: add 32-bit signing and keychain identity design and plan (ZSN-17, ZSN-19)"`
  Expected: commit created on `zsn44-smalls`; never push, never merge.

---

### Task 1: ZSN-17 red — 32-bit fixtures and failing round-trip tests

**Files:**
- Modify: `crates/zsign-core/src/macho/fixtures.rs` (append after `make_minimal_dylib`, ~line 101)
- Modify: `crates/zsign-core/src/macho/verify.rs` tests (append near `verify_signed_binary_round_trip`, ~line 975)
- Modify: `crates/zsign-core/src/macho/writer.rs` tests (append near injection tests, ~line 2626)

- [ ] **Step 1.1:** Add the 32-bit fixture to `macho/fixtures.rs` (twin of `make_minimal_macho` at `fixtures.rs:6-91`; same slack layout, 32-bit header/command widths):

```rust
/// Minimal thin-armv7 (little-endian 32-bit) Mach-O bytes: `mach_header`
/// (28 B), `LC_SEGMENT` (56 B + one 68 B section), 32-bit `__LINKEDIT`.
/// No `LC_CODE_SIGNATURE` — an unsigned input for 32-bit signing tests.
pub(crate) fn make_minimal_macho_32() -> Vec<u8> {
    let mut b = Vec::new();
    macro_rules! u32le {
        ($v:expr) => {
            b.extend_from_slice(&($v as u32).to_le_bytes())
        };
    }
    macro_rules! name {
        ($s:expr, $len:expr) => {
            let mut n = [0u8; 16];
            n[..$s.len()].copy_from_slice($s.as_bytes());
            b.extend_from_slice(&n[..$len]);
        };
    }

    // mach_header (28 bytes, no reserved word)
    u32le!(0xfeedface); // MH_MAGIC
    u32le!(0x0000_000c); // CPU_TYPE_ARM
    u32le!(0x0000_0009); // CPU_SUBTYPE_ARM_V7
    u32le!(2); // MH_EXECUTE
    u32le!(3); // ncmds
    u32le!(124 + 56 + 24); // sizeofcmds
    u32le!(0x1); // MH_NOUNDEFS

    // LC_SEGMENT "__TEXT" (124 bytes: 56-byte command + one 68-byte section)
    u32le!(0x01);
    u32le!(124);
    name!("__TEXT", 16);
    u32le!(0x1000); // vmaddr
    u32le!(0x1000); // vmsize
    u32le!(0x1000); // fileoff: leaves room for load commands
    u32le!(0x1000); // filesize
    u32le!(7); // maxprot
    u32le!(7); // initprot
    u32le!(1); // nsects
    u32le!(0); // flags
    name!("__text", 16); // section sectname
    name!("__TEXT", 16); // section segname
    u32le!(0x1000); // addr
    u32le!(4); // size
    u32le!(0x1000); // offset
    u32le!(0); // align
    u32le!(0); // reloff
    u32le!(0); // nreloc
    u32le!(0); // flags
    u32le!(0); // reserved1
    u32le!(0); // reserved2

    // LC_SEGMENT "__LINKEDIT" (56 bytes, no sections)
    u32le!(0x01);
    u32le!(56);
    name!("__LINKEDIT", 16);
    u32le!(0x2000); // vmaddr
    u32le!(0x1000); // vmsize
    u32le!(0x2000); // fileoff
    u32le!(0); // filesize
    u32le!(1); // maxprot
    u32le!(1); // initprot
    u32le!(0); // nsects
    u32le!(0); // flags

    // LC_BUILD_VERSION (24 bytes, identical layout at both widths)
    u32le!(0x32);
    u32le!(24);
    u32le!(1); // platform
    u32le!(0x000f_0000); // minos 15.0
    u32le!(0x000f_0000); // sdk 15.0
    u32le!(0); // ntools

    // Same tail as the 64-bit fixture: load-command slack, 4-byte __text at
    // 0x1000, zero-fill through the __LINKEDIT page.
    b.resize(0x1000, 0);
    b.extend_from_slice(&[0x1f, 0x20, 0x03, 0xd5]);
    b.resize(0x2000, 0);
    b
}
```

- [ ] **Step 1.1b:** Add the big-endian 32-bit twin right after `make_minimal_macho_32` (mirror `make_minimal_macho_be` at `fixtures.rs:140` — every integer via `to_be_bytes`, so the header magic reads back as `MH_CIGAM`):

```rust
/// Byte-for-byte layout of [`make_minimal_macho_32`], with every integer
/// encoded big-endian (`MH_CIGAM`) — the typed-rejection input.
pub(crate) fn make_minimal_macho_32_be() -> Vec<u8> {
    let mut b = Vec::new();
    macro_rules! u32be {
        ($v:expr) => {
            b.extend_from_slice(&($v as u32).to_be_bytes())
        };
    }
    macro_rules! name {
        ($s:expr, $len:expr) => {
            let mut n = [0u8; 16];
            n[..$s.len()].copy_from_slice($s.as_bytes());
            b.extend_from_slice(&n[..$len]);
        };
    }

    // mach_header (28 bytes, big-endian)
    u32be!(0xfeedface); // MH_CIGAM once read little-endian
    u32be!(0x0000_000c); // CPU_TYPE_ARM
    u32be!(0x0000_0009); // CPU_SUBTYPE_ARM_V7
    u32be!(2); // MH_EXECUTE
    u32be!(3); // ncmds
    u32be!(124 + 56 + 24); // sizeofcmds
    u32be!(0x1); // MH_NOUNDEFS

    // LC_SEGMENT "__TEXT" (124 bytes: 56-byte command + one 68-byte section)
    u32be!(0x01);
    u32be!(124);
    name!("__TEXT", 16);
    u32be!(0x1000); // vmaddr
    u32be!(0x1000); // vmsize
    u32be!(0x1000); // fileoff
    u32be!(0x1000); // filesize
    u32be!(7); // maxprot
    u32be!(7); // initprot
    u32be!(1); // nsects
    u32be!(0); // flags
    name!("__text", 16);
    name!("__TEXT", 16);
    u32be!(0x1000); // addr
    u32be!(4); // size
    u32be!(0x1000); // offset
    u32be!(0); // align
    u32be!(0); // reloff
    u32be!(0); // nreloc
    u32be!(0); // flags
    u32be!(0); // reserved1
    u32be!(0); // reserved2

    // LC_SEGMENT "__LINKEDIT" (56 bytes, no sections)
    u32be!(0x01);
    u32be!(56);
    name!("__LINKEDIT", 16);
    u32be!(0x2000); // vmaddr
    u32be!(0x1000); // vmsize
    u32be!(0x2000); // fileoff
    u32be!(0); // filesize
    u32be!(1); // maxprot
    u32be!(1); // initprot
    u32be!(0); // nsects
    u32be!(0); // flags

    // LC_BUILD_VERSION (24 bytes)
    u32be!(0x32);
    u32be!(24);
    u32be!(1); // platform
    u32be!(0x000f_0000); // minos 15.0
    u32be!(0x000f_0000); // sdk 15.0
    u32be!(0); // ntools

    b.resize(0x1000, 0);
    b.extend_from_slice(&[0x1f, 0x20, 0x03, 0xd5]);
    b.resize(0x2000, 0);
    b
}
```

- [ ] **Step 1.2:** Add red round-trip tests to `macho/verify.rs` tests module (imports at `verify.rs:557-562` already include `sign_any_macho`, `sign_macho`, `make_minimal_macho`; add `make_fat_macho` and `make_minimal_macho_32` to that `use` if absent). Mirror `verify_signed_binary_round_trip` (`verify.rs:946-975`):

```rust
    #[test]
    fn verify_signed_32bit_armv7_round_trip() {
        let creds = rsa_credentials();
        let macho = MachOFile::parse(crate::macho::fixtures::make_minimal_macho_32()).unwrap();
        assert!(!macho.slices()[0].is_64, "fixture must be 32-bit");
        let signed =
            sign_macho(&macho, "com.example", None, &creds, None, None, false).unwrap();
        assert_eq!(
            &signed[..4],
            &0xfeedfaceu32.to_le_bytes(),
            "32-bit magic must survive signing"
        );
        let report = verify_macho(&signed, &SignatureInputs::none()).unwrap();
        let slice = &report.slices[0];
        assert!(slice.signed, "32-bit slice must carry a signature");
        assert!(!slice.adhoc);
        assert_eq!(slice.pages, PageCheck::Matched, "{:?}", slice.errors);
        assert_eq!(
            slice.errors.len(),
            1,
            "self-signed fixture may fail anchoring only: {:?}",
            slice.errors
        );
        assert!(slice.errors[0].contains("not anchored to a trusted root"));
        let cms = slice.cms.as_ref().expect("cms report");
        assert!(
            cms.signature_ok
                && cms.message_digest_ok
                && cms.cdhash_v1_ok
                && cms.cdhash_v2_ok
                && cms.chain_ok
        );
        let injected = cms_report_with_test_anchor(&signed, &creds);
        assert!(injected.valid, "cms errors: {:?}", injected.errors);
    }

    #[test]
    fn verify_signed_fat_armv7_arm64_round_trip() {
        let creds = rsa_credentials();
        let fat = make_fat_macho(
            &[
                crate::macho::fixtures::make_minimal_macho_32(),
                make_minimal_macho(),
            ],
            &[12, 12],
        );
        let macho = MachOFile::parse(fat).unwrap();
        assert!(macho.is_fat() && macho.slices().len() == 2);
        let signed =
            sign_any_macho(&macho, "com.example.fat", None, &creds, None, None, false).unwrap();
        let report = verify_macho(&signed, &SignatureInputs::none()).unwrap();
        assert!(report.fat);
        assert_eq!(report.slices.len(), 2, "both slices must report");
        for (i, slice) in report.slices.iter().enumerate() {
            assert!(slice.signed, "slice {i} must be signed");
            assert_eq!(slice.pages, PageCheck::Matched, "slice {i}: {:?}", slice.errors);
            assert!(
                slice
                    .errors
                    .iter()
                    .all(|e| e.contains("not anchored to a trusted root")),
                "slice {i}: unexpected errors {:?}",
                slice.errors
            );
        }
        let cms = report.slices[0].cms.as_ref().expect("32-bit slice cms");
        assert!(
            cms.signature_ok && cms.message_digest_ok && cms.cdhash_v1_ok && cms.cdhash_v2_ok && cms.chain_ok,
            "32-bit slice cms: {:?}",
            cms
        );
    }
```

- [ ] **Step 1.2b:** Add the end-to-end typed-rejection test to the same `macho/verify.rs` tests module (pins design P3 through a real `MH_CIGAM` input, not just the helper):

```rust
    #[test]
    fn sign_rejects_big_endian_32bit_with_typed_error() {
        let data = crate::macho::fixtures::make_minimal_macho_32_be();
        let macho = MachOFile::parse(data).expect("big-endian 32-bit fixture parses");
        let slice = &macho.slices()[0];
        assert!(!slice.is_64, "fixture must be 32-bit");
        let creds = rsa_credentials();
        let res = sign_any_macho(&macho, "com.example.be32", None, &creds, None, None, false);
        assert!(
            matches!(&res, Err(crate::Error::MachO(m)) if m.contains("big-endian")),
            "typed big-endian rejection required, got {:?}",
            res.as_ref().err()
        );
    }
```

- [ ] **Step 1.3:** Add the injection red test to `macho/writer.rs` tests (mirror `inject_dylib_command` FAT tests near `writer.rs:2576-2626`; `inject_dylib_command` is the public entry at `writer.rs:906`):

```rust
    #[test]
    fn test_inject_dylib_command_accepts_32bit_thin_and_fat() {
        let dylib = "/usr/lib/libzsigntest.dylib";
        let thin32 = crate::macho::fixtures::make_minimal_macho_32();
        let injected = inject_dylib_command(&thin32, dylib, false)
            .expect("little-endian 32-bit thin injection must succeed");
        assert!(
            injected.windows(dylib.len()).any(|w| w == dylib.as_bytes()),
            "injected dylib path must appear in output"
        );
        let m = crate::macho::MachOFile::parse(injected).unwrap();
        assert_eq!(m.slices().len(), 1);

        let fat = crate::macho::fixtures::make_fat_macho(
            &[
                crate::macho::fixtures::make_minimal_macho_32(),
                crate::macho::fixtures::make_minimal_macho(),
            ],
            &[12, 12],
        );
        let injected = inject_dylib_command(&fat, dylib, false)
            .expect("FAT containing a 32-bit slice must inject");
        assert!(injected.windows(dylib.len()).any(|w| w == dylib.as_bytes()));
        let m = crate::macho::MachOFile::parse(injected).unwrap();
        assert_eq!(m.slices().len(), 2, "both slices must survive injection");
    }
```

- [ ] **Step 1.4:** Run the red tests and record verbatim failures (this is the observed-red evidence for the report):
  Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-core 32bit -- --nocapture 2>&1 | tail -40`
  Expected FAIL: `verify_signed_32bit_armv7_round_trip` and `test_inject_dylib_command_accepts_32bit_thin_and_fat` with `Invalid Mach-O: 32-bit Mach-O binaries not supported` (and the FAT round-trip likewise).
  Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-core verify_signed_fat_armv7_arm64 2>&1 | tail -20`
  Expected FAIL with the same message.

---

### Task 2: ZSN-17 — parser captures `__LINKEDIT` from `Segment32`

**Files:**
- Modify: `crates/zsign-core/src/macho/parser.rs:290-303` (Segment32 arm), test near `test_parse_32bit_encryption_info` (~line 732)

- [ ] **Step 2.1:** In `MachOMetadata` construction, the `CommandVariant::Segment64` arm records `meta_linkedit_cmd = Some((lc.offset, seg.fileoff, seg.vmsize, seg.filesize))` (`parser.rs:282-285`). Add the identical capture in the `CommandVariant::Segment32` arm (`parser.rs:290-303`, fields are `u32`, upcast to `u64`):

```rust
                    if seg.segname.starts_with(b"__LINKEDIT") {
                        meta_linkedit_cmd =
                            Some((lc.offset, seg.fileoff as u64, seg.vmsize as u64, seg.filesize as u64));
                    }
```

- [ ] **Step 2.2:** Red-then-green parser test (red because `linkedit_cmd` is `None` today for 32-bit):

```rust
    #[test]
    fn test_parse_32bit_linkedit_metadata() {
        let data = crate::macho::fixtures::make_minimal_macho_32();
        let file = MachOFile::parse(data).expect("32-bit fixture parses");
        let slice = &file.slices()[0];
        assert!(!slice.is_64);
        let (lc_off, fileoff, _vmsize, filesize) = slice
            .metadata
            .linkedit_cmd
            .expect("__LINKEDIT must be captured from the Segment32 arm");
        assert!(lc_off > 0, "load command offset recorded");
        assert_eq!(fileoff, 0x2000);
        assert_eq!(filesize, 0);
    }
```

- [ ] **Step 2.3:** Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-core test_parse_32bit_linkedit_metadata`
  Expected: PASS after Step 2.1 (failed with `__LINKEDIT must be captured...` before it).

---

### Task 3: ZSN-17 — shared bitness helper + metadata writer path

**Files:**
- Modify: `crates/zsign-core/src/macho/writer.rs` — new helper (place near `is_big_endian_macho` consumers, top of file after constants ~line 96); guards at `:1174-1176`, `:1315-1317`, `:1434-1436`; segment-field writes near `:1195-1206` and `update_linkedit_segment` `:974-991`; doc comments at `:94`, `:1029`, `:1164`, `:1309`

- [ ] **Step 3.1:** Add the helper (mirrors the `EncryptedBinary` narrow-message pattern; doc comment explains behavior, no ticket IDs):

```rust
/// Little-endian 32-bit images are signable. Big-endian 32-bit (`MH_CIGAM`,
/// m68k/PowerPC-era) is rejected with an actionable message; 64-bit behavior
/// (either endianness) is unchanged.
fn ensure_signable_bitness(is_64: bool, is_big_endian: bool) -> Result<()> {
    if !is_64 && is_big_endian {
        return Err(Error::MachO(
            "big-endian 32-bit Mach-O (MH_CIGAM) is not supported; sign a little-endian i386/armv7 or a 64-bit binary instead".into(),
        ));
    }
    Ok(())
}
```

- [ ] **Step 3.2:** Red-then-green unit test in `writer.rs` tests:

```rust
    #[test]
    fn bitness_helper_typed_rejection_for_big_endian_32bit() {
        let res: crate::Result<()> = ensure_signable_bitness(false, true);
        let err = res.expect_err("big-endian 32-bit must be rejected");
        assert!(
            matches!(&err, crate::Error::MachO(m)
                if m.contains("big-endian") && m.contains("i386/armv7")),
            "typed actionable message required, got {err:?}"
        );
        ensure_signable_bitness(false, false).expect("little-endian 32-bit is supported");
        ensure_signable_bitness(true, false).expect("64-bit behavior unchanged");
        ensure_signable_bitness(true, true).expect("64-bit endianness unchanged");
    }
```

  Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-core bitness_helper` → red (function undefined), then green after Step 3.1.

- [ ] **Step 3.3:** Replace the three metadata-path guards with helper calls. Each currently reads (exact anchors re-derived at implementation time; shapes from the current source):
  - `realloc_code_sign_space_with_metadata` `writer.rs:1174-1176`: `if !metadata.is_64 { return Err(Error::MachO("32-bit Mach-O binaries not supported".into())); }` → `ensure_signable_bitness(metadata.is_64, metadata.is_big_endian)?;`
  - `prepare_code_with_metadata` `writer.rs:1315-1317`: same replacement.
  - `prepare_code_in_place` `writer.rs:1434-1436`: same replacement (stays before `buf.truncate`).
  Also update the three doc comments on these functions (`:1164`, `:1309`, and the one above `prepare_code_in_place`) which currently promise a 32-bit error: they must describe the big-endian-only rejection.

- [ ] **Step 3.4:** Make every segment-field byte write width-aware. Rule (from xnu `loader.h:355-388`): `LC_SEGMENT_64` — `vmsize@lc+32`, `fileoff@lc+40`, `filesize@lc+48` as `u64`; `LC_SEGMENT` — `vmaddr@lc+24`, `vmsize@lc+28`, `fileoff@lc+32`, `filesize@lc+36` as `u32`. Steps:
  1. Run a structural search for every raw segment write in `writer.rs`: all `write_u64(` calls whose target offset derives from a `linkedit_cmd` LC offset (known sites: realloc metadata `writer.rs:1195-1206`, `update_linkedit_segment` `writer.rs:974-991`, plus any twin inside `prepare_code_in_place`).
  2. Give each the slice's `metadata.is_64` (thread it into `update_linkedit_segment` as a parameter if it lacks it): `u64` write on the 64-bit path, `write_u32` at the 32-bit offsets on the 32-bit path. The page-align arithmetic (`align_to(..., PAGE_SIZE)`, `+0x4000` variants) stays identical — only the encoding width changes.
  3. `linkedit_data_command` writes (`dataoff@lc+8`, `datasize@lc+12`, `ncmds@hdr+16`, `sizeofcmds@hdr+20`) are `u32` at both widths — do not touch them.
  4. The header-size ternaries at `writer.rs:216` and `:1247` are already `if is_64 { 32 } else { 28 }` — leave as-is (they become live).

- [ ] **Step 3.5:** Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-core parser:: 2>&1 | tail -5` then `TMPDIR=$PWD/.tmptmp cargo test -p zsign-core bitness_helper`
  Expected: PASS. Full 32-bit round-trips still red until Task 4.

---

### Task 4: ZSN-17 — single/legacy writer paths + dylib injection

**Files:**
- Modify: `crates/zsign-core/src/macho/writer.rs` — guards `:131-136`, `:521-524`, `:1074-1077`; goblin `__LINKEDIT` caches `:139/:152-154`, `:527/:540-542`, `:1080/:1093-1095`; `inject_dylib_thin` `:703-716`; docs `:94` (realloc), `:1029` (prepare)

- [ ] **Step 4.1:** Replace the three single-path guards:
  - `realloc_code_sign_space_single` `writer.rs:131-136`: already computes `is_64` (`:131`) and `is_big_endian` (`:132`) — delete the `if !is_64 { return Err(...) }` block and call `ensure_signable_bitness(is_64, is_big_endian)?;` (keep both locals; `is_64` feeds `:216`).
  - `embed_signature_single` `writer.rs:521-524`: has `is_64`; add `let is_big_endian = super::parser::is_big_endian_macho(data, 0);` beside it and call the helper.
  - `prepare_code_single` `writer.rs:1074-1077`: same two lines.

- [ ] **Step 4.2:** Add `Segment32` capture to the three goblin load-command loops so a 32-bit `__LINKEDIT` is visible. Change each cache from `Option<(usize, SegmentCommand64)>` to the width-neutral tuple used by the parser (`Option<(usize, u64, u64, u64)>` = `(lc offset, fileoff, vmsize, filesize)`):
  - loops at `writer.rs:142-156`, `:531-544`, `:1083-1097`: match `CommandVariant::Segment64(seg) if seg.segname.starts_with(b"__LINKEDIT")` → store `(lc.offset, seg.fileoff, seg.vmsize, seg.filesize)`; add a twin arm for `CommandVariant::Segment32(seg)` with `as u64` upcasts.
  - update each consumer (realloc `:182-193`, embed `:587-600`, prepare `:1133-1145`) to the tuple fields, and apply the Task 3.4 width rule to any segment write in those bodies.

- [ ] **Step 4.3:** Relax `inject_dylib_thin` (`writer.rs:703-716`). Today: fixed `HEADER_SIZE = 32` (`:703`), too-short check wording `"...64-bit Mach-O header"` (`:707-710`), magic gate `"not a 64-bit Mach-O binary"` (`:713-716`). Change to:
  1. Read the LE magic from `data[0..4]`. Accept `MH_MAGIC` and the already-accepted 64-bit magics. If `MH_CIGAM` → `ensure_signable_bitness(false, true)?` (same typed message). Any other magic keeps a `"not a Mach-O binary"`-style error.
  2. `let header_size = if is_64 { 32 } else { 28 };` used for the too-short check (message becomes `binary too short for a Mach-O header`) and for the load-command insertion base (`lc_start = header_size`, currently hardcoded 32-byte assumptions — grep `HEADER_SIZE` inside the fn and replace with the local).
  3. `ncmds`/`sizeofcmds` are at header offsets 16/20 at both widths — no change there.
  4. The manual command walk after the gate already has a correct `LC_SEGMENT` arm (`writer.rs:787-822`) — untouched.
  5. Alignment: confirm the inserted `LC_LOAD_DYLIB` `cmdsize` is a multiple of 8 (existing padding behavior) — that satisfies both the 32-bit multiple-of-4 and 64-bit multiple-of-8 rules (`loader.h:238-241`); if the code pads to 4 anywhere, leave it — 4 is legal for both. Do not add width branching unless a test fails.
  6. Update the FAT error wrapper test comment context if needed: the existing pin at `writer.rs:2626-2629` (FAT must not hit the thin guard) stays valid.

- [ ] **Step 4.4:** Run the ZSN-17 tests green:
  Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-core 32bit 2>&1 | tail -25`
  Expected: PASS (`verify_signed_32bit_armv7_round_trip`, `test_parse_32bit_linkedit_metadata`, `test_inject_dylib_command_accepts_32bit_thin_and_fat`).
  Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-core verify_signed_fat_armv7_arm64 2>&1 | tail -25` → PASS.

- [ ] **Step 4.5:** If any test fails, diagnose with `skill://systematic-debugging` before touching more code. Common failure points and first checks:
  - `No __LINKEDIT segment found` → a loop from Step 4.2 missed the `Segment32` arm.
  - verify page-hash mismatch → a segment-field write from Task 3.4 used the wrong width/offset (recheck `vmsize@+28`/`filesize@+36` for `LC_SEGMENT`).
  - `binary too short` / offset panic → `lc_start` still 32 in `inject_dylib_thin`.
  - FAT failure only → check per-slice flow: failure must precede `embed_fat_from_signed_slices` (`writer.rs:405`); no partial output.

- [ ] **Step 4.6:** Sweep for leftovers (P5) and migrate every caller:
  Run: `grep -rn "32-bit Mach-O binaries not supported\|not a 64-bit Mach-O binary" crates/`
  Expected: no hits outside the new test asserting absence is unnecessary — zero hits in `src/` (tests may assert on the new typed message only). Fix any remaining doc comment claiming 32-bit is unsupported (`writer.rs:94`, `:1029`).
  Run: `grep -rn "realloc_code_sign_space\|prepare_code_for_signing\|embed_signature\b" crates/*/src --include=*.rs | grep -v "zsign-core/src/macho/writer.rs"`
  Expected: callers unchanged (behavior widened from error→success; no caller branches on the old error text — confirm and record).

- [ ] **Step 4.7:** Scoped gate for the ticket:
  Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-core macho 2>&1 | tail -15` → all macho tests PASS.
  Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-core 2>&1 | tail -10` → zsign-core PASS (no skip).

- [ ] **Step 4.8:** Format and lint before committing:
  Run: `cargo fmt --all -- --check` → clean (run `cargo fmt --all` first if not).
  Run: `TMPDIR=$PWD/.tmptmp cargo clippy --workspace --all-targets -- -D warnings 2>&1 | tail -10` → zero diagnostics.

- [ ] **Step 4.9:** Commit as two logical commits (each independently green — commit 1 is Tasks 1–2, commit 2 is Tasks 3–4; stage per file group):
  Run: `git add crates/zsign-core/src/macho/parser.rs crates/zsign-core/src/macho/fixtures.rs && git commit -m "parse linkedit segment metadata from 32-bit mach-o slices (ZSN-17)"`
  Run: `git add crates/zsign-core/src/macho/writer.rs crates/zsign-core/src/macho/verify.rs && git commit -m "sign little-endian 32-bit mach-o binaries with typed big-endian rejection (ZSN-17)"`
  Note: if splitting breaks either commit's greenness (fixtures referenced by both), stage `fixtures.rs` with the first commit only if it compiles there — verify with `git stash` + targeted test before each commit; otherwise use a single combined commit `add little-endian 32-bit mach-o signing support (ZSN-17)`. Never push.

---

### Task 5: ZSN-19 red — canned keychain fixtures and failing tests

**Files:**
- Create: `crates/zsign-core/src/crypto/fixtures/find-identity-two.txt`
- Create: `crates/zsign-core/src/crypto/fixtures/find-identity-zero.txt`
- Create: `crates/zsign-core/src/crypto/fixtures/find-identity-ambiguous.txt`
- Create: `crates/zsign-core/src/crypto/fixtures/find-identity-ragged.txt`
- Modify: `crates/zsign-core/src/crypto/cert.rs` (selector tests near `from_p12_rejects_ambiguous_identity` ~line 981)
- Modify: `crates/zsign-cli/src/main.rs` tests (near the credentials-group tests ~line 1884)

- [ ] **Step 5.1:** Write the four canned outputs (format pinned by design §3.1: `<indent><N>) <40-hex> "<name>"`, summary line `N valid identities found`):

`find-identity-two.txt`:
```
  1) 50034388646913B117AF1D6E51D9E045B77EA916 "Apple Development: alice@example.com (LVGBSLUQB4)"
  2) 0123456789ABCDEF0123456789ABCDEF01234567 "iPhone Distribution: Example Corp (ABCDE12345)"
     2 valid identities found
```

`find-identity-zero.txt`:
```
     0 valid identities found
```

`find-identity-ambiguous.txt`:
```
  1) 1111111111111111111111111111111111111111 "Apple Development: bob@example.com (TEAM000001)"
  2) 2222222222222222222222222222222222222222 "Apple Development: bob@example.com (TEAM000001)"
     2 valid identities found
```

`find-identity-ragged.txt` (single-space indent, noise lines that must be skipped, trailing summary):
```
     1) AABBCCDDEEFF00112233445566778899AABBCCDD "Apple Development: carol@example.com (TEAM999999)" [REVOKED]
not a security output line
     1 valid identities found
```

- [ ] **Step 5.2:** Red tests in `cert.rs` tests (they fail to compile until Step 6.2 adds the function — that IS the red). They pin that a leaf-SHA-1 selector drives `from_p12` through the same checks:

```rust
    #[test]
    fn from_p12_with_leaf_sha1_selects_the_matching_pair() {
        let contents = extract_p12(IDENTITY_DUP, "testpassword").expect("fixture parses");
        assert!(
            contents.certs.len() >= 2,
            "duplicate fixture must carry both identities"
        );
        let target = sha1_of(&contents.certs[0]);
        let creds =
            SigningCredentials::from_p12_with_leaf_sha1(IDENTITY_DUP, "testpassword", &target)
                .expect("selected identity must load through every load-time check");
        let leaf_der = creds.certificate.to_der().expect("leaf DER");
        assert_eq!(sha1_of(&leaf_der), target, "leaf must be the selected one");
    }

    #[test]
    fn from_p12_with_leaf_sha1_unknown_hash_errors() {
        let res = SigningCredentials::from_p12_with_leaf_sha1(
            IDENTITY_DUP,
            "testpassword",
            &[0u8; 20],
        );
        assert!(
            matches!(&res, Err(Error::Certificate(m))
                if m.contains("SHA-1") && m.contains("0000000000000000000000000000000000000000")),
            "actionable mismatch message required, got {:?}",
            res.as_ref().err()
        );
    }
```

  Add test-module helpers next to the existing fixture consts (`cert.rs:744-758`): `fn sha1_of(der: &[u8]) -> [u8; 20]` using `sha1::{Digest, Sha1}` (`Sha1::digest(der).into()`), and `use der::Encode;` if `to_der()` is not already in scope. Confirm `extract_p12` is reachable (`crypto/pkcs12.rs:107` `pub(crate)` ✓) and that `P12Contents.certs` is the raw-DER bag list — adjust field access to the actual shape when compiling.

- [ ] **Step 5.2b:** Red tests proving the load-time policy/weak-key gates cannot be bypassed through the selector (uses existing committed fixtures: `WEAK_RSA1024` and the non-policy `modern_pbes2_aes256.p12`, both already rejected by `from_p12` in `from_p12_rejects_weak_rsa_key` / `from_p12_rejects_non_policy_fixture`). Add beside Step 5.2:

```rust
    #[test]
    fn from_p12_with_leaf_sha1_enforces_weak_key_gate() {
        let contents = extract_p12(WEAK_RSA1024, "testpassword").expect("fixture parses");
        let leaf_sha1 = sha1_of(&contents.certs[0]);
        let res = SigningCredentials::from_p12_with_leaf_sha1(WEAK_RSA1024, "testpassword", &leaf_sha1);
        assert!(
            matches!(&res, Err(Error::Certificate(m)) if m.contains("1024") && m.contains("2048")),
            "keychain selector must not bypass the RSA minimum, got {:?}",
            res.as_ref().err()
        );
    }

    #[test]
    fn from_p12_with_leaf_sha1_enforces_code_signing_policy() {
        let p12: &[u8] = include_bytes!("fixtures/modern_pbes2_aes256.p12");
        let contents = extract_p12(p12, "testpassword").expect("fixture parses");
        let leaf_sha1 = sha1_of(&contents.certs[0]);
        let res = SigningCredentials::from_p12_with_leaf_sha1(p12, "testpassword", &leaf_sha1);
        assert!(
            matches!(&res, Err(Error::Certificate(m)) if m.contains("codeSigning")),
            "keychain selector must not bypass the code-signing policy, got {:?}",
            res.as_ref().err()
        );
    }
```

  (If `certs[0]` is not the leaf in a given fixture, locate the leaf as the certificate `select_identity` pairs with the container key — the existing `from_p12` tests on the same fixtures document which cert that is.)

- [ ] **Step 5.3:** Red CLI tests in `main.rs` tests (fail today: unknown argument / no `MacOsOnly`):

```rust
    #[test]
    fn keychain_identity_conflicts_with_credential_flags_at_parse() {
        for extra in [
            vec!["--keychain-identity", "Apple Development: a (T)", "-k", "k.p12"],
            vec!["--pkcs12", "a.p12", "--keychain-identity", "Apple Development: a (T)"],
            vec!["-c", "c.pem", "-k", "k.pem", "--keychain-identity", "Apple Development: a (T)"],
        ] {
            let mut args = vec!["zsign"];
            args.extend(extra);
            args.push("in.ipa");
            let err = parse_err(&args);
            assert_eq!(
                err.kind(),
                clap::error::ErrorKind::ArgumentConflict,
                "{err}"
            );
        }
        let err = parse_err(&["zsign", "-V", "--keychain-identity", "x", "in.ipa"]);
        assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict, "{err}");
    }

    #[test]
    fn keychain_identity_satisfies_credential_requirement() {
        let cli = Cli::parse_from([
            "zsign",
            "--keychain-identity",
            "Apple Development: a (T)",
            "in.ipa",
        ]);
        assert_eq!(
            cli.keychain_identity.as_deref(),
            Some("Apple Development: a (T)")
        );
        assert!(cli.private_key.is_none());
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn keychain_identity_refuses_on_non_macos() {
        let cli = Cli::parse_from([
            "zsign",
            "--keychain-identity",
            "Apple Development: a (T)",
            "in.ipa",
        ]);
        let err = load_credentials(&cli).expect_err("non-macOS must refuse keychain identities");
        assert!(err.to_string().contains("macOS"), "{err}");
    }
```

- [ ] **Step 5.4:** Record red:
  Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-cli keychain 2>&1 | tail -30` → compile-fail/unknown-arg (observed red).
  Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-core from_p12_with_leaf 2>&1 | tail -20` → compile-fail (observed red).

---

### Task 6: ZSN-19 — keychain module + `from_p12` leaf selector

**Files:**
- Modify: `crates/zsign-core/src/crypto/cert.rs` (`from_p12` `:603-623` refactor + selector)
- Create: `crates/zsign-core/src/crypto/keychain.rs`
- Modify: `crates/zsign-core/src/crypto/mod.rs` (`:32-42` submodule list)

- [ ] **Step 6.1:** Refactor `from_p12` (`cert.rs:603-623`) so the post-selection tail becomes a shared private fn — move lines `:617-623` (`into_signing_key`, `code_signing_policy_violation`, `build_chain_from_leaf`, `extract_team_id`, struct build) into:

```rust
    fn finish_p12(
        decoded: DecodedKey,
        certificate: Certificate,
        rest: Vec<Certificate>,
    ) -> Result<Self> {
        let signing_key = decoded.into_signing_key()?;
        if let Some(violation) = code_signing_policy_violation(&certificate, time_now()) {
            return Err(Error::Certificate(violation));
        }
        let cert_chain = build_chain_from_leaf(&certificate, rest);
        let team_id = extract_team_id(&certificate);
        Ok(Self { certificate, signing_key, cert_chain, team_id })
    }
```

  (Copy the exact expressions from the current `from_p12` body — the snippet above shows shape; the live code is authoritative, including any error wrapping. `from_p12` keeps its checks at `:604-616` and now ends with `Self::finish_p12(decoded, certificate, rest)`.)

- [ ] **Step 6.2:** Add the selector constructor to `cert.rs` (sha1 import at top: `use sha1::{Digest, Sha1};` if absent):

```rust
    /// Load from PKCS#12 selecting the identity whose leaf certificate's
    /// SHA-1 matches `leaf_sha1` (the hash printed by
    /// `security find-identity`). Every load-time check that [`Self::from_p12`]
    /// performs runs on the selected pair; the export-provided chain stays in
    /// `rest`, and an export that does not contain the certificate is rejected
    /// with an actionable message.
    pub(crate) fn from_p12_with_leaf_sha1(
        p12_data: &[u8],
        password: &str,
        leaf_sha1: &[u8; 20],
    ) -> Result<Self> {
        let contents = super::pkcs12::extract_p12(p12_data, password)
            .map_err(|e| Error::Certificate(format!("Failed to parse PKCS#12: {}", e)))?;
        let matches_leaf = |c: &[u8]| Sha1::digest(c).as_slice() == leaf_sha1;
        let selected: Vec<Vec<u8>> = contents.certs.iter().filter(|c| matches_leaf(c)).cloned().collect();
        if selected.is_empty() {
            return Err(Error::Certificate(format!(
                "no certificate in PKCS#12 has SHA-1 {} (the selected keychain identity was not exported)",
                hex_upper(leaf_sha1)
            )));
        }
        // Pair the key against the selected leaf only, then rebuild `rest`
        // from every non-leaf certificate so the export-provided chain still
        // feeds build_chain_from_leaf (select_identity's `rest` would only
        // cover the slice it was handed).
        let (decoded, certificate, _matched_rest) = select_identity(&contents.keys, &selected)?;
        let rest: Vec<Certificate> = contents
            .certs
            .iter()
            .filter(|c| !matches_leaf(c))
            .filter_map(|d| Certificate::from_der(d).ok())
            .collect();
        Self::finish_p12(decoded, certificate, rest)
    }
```

  Add a tiny `fn hex_upper(bytes: &[u8; 20]) -> String` beside it (`bytes.iter().map(|b| format!("{b:02X}")).collect()`). Match the exact `extract_p12` error wrapping used by `from_p12` at `:604-605`; `Certificate::from_der` needs `der::Decode`, already imported in `cert.rs`. The `.ok()` skip semantics mirror `select_identity`'s own per-cert parse (`cert.rs:250-257`).
  Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-core from_p12_with_leaf` → all four tests GREEN (Steps 5.2 + 5.2b; this closes those reds).

- [ ] **Step 6.3:** Create `crates/zsign-core/src/crypto/keychain.rs`. Module structure (one file, same-file split mirrors `revocation.rs`):

```rust
//! macOS keychain identity loading: list codesigning identities with
//! `security find-identity`, resolve the requested name or certificate SHA-1,
//! export identities to PKCS#12, and load credentials through the same
//! load-time checks as any other PKCS#12 source.
//!
//! The parser and selector are pure functions of the command output and
//! compile on every native target; the live `security` execution is
//! `cfg(target_os = "macos")`, and the whole module is excluded from
//! `wasm32` builds.
```

  Contents, in order:
  1. `KeychainError` — `#[derive(Debug, thiserror::Error)] pub enum KeychainError` with variants exactly as designed: `MacOsOnly` ("--keychain-identity is only available on macOS; use --pkcs12, -k/--private-key, or -c/--certificate on this platform"), `NoIdentities`, `Ambiguous { requested, candidates }`, `NotFound { requested, available }`, `CommandFailed { tool, status, stderr }`, `ExportFile(String)`, and `#[error(transparent)] Credential(#[from] crate::Error)`.
  2. `pub struct IdentityLine { pub hash: [u8; 20], pub name: String }`.
  3. `pub fn parse_find_identity(stdout: &str) -> Vec<IdentityLine>` — the hash follows the `)` (`<indent><N>) <40-hex> "<name>"`). Per line: `let Some((idx, rest)) = line.split_once(')')` else skip; `idx.trim()` must be non-empty and all ASCII digits; `rest = rest.trim_start()`; require `rest.len() >= 41` else skip; decode `rest[..40]` as case-insensitive hex else skip; `tail = rest[40..].trim_start()` must start with `"` else skip (this is what drops summary/noise lines); name = `tail[1..tail.rfind('"')?]`. Guard every slice against short lines — a malformed line is skipped, never a panic. No regex dependency.
  4. `pub fn select_identity_line(lines: &[IdentityLine], name_or_hash: &str) -> Result<IdentityLine, KeychainError>` — 40-hex input → case-insensitive hash match (exactly one; zero → `NotFound`); otherwise exact `name` equality (zero → `NotFound` with `available` = names joined by `"; "`; multiple → `Ambiguous` with `candidates` = `hash-hex "name"` joined by `"; "`). Empty `lines` → `NoIdentities`.
  5. `pub(crate) trait SecurityRunner { fn find_identity(&self) -> Result<String, KeychainError>; fn export_identities(&self, out: &std::path::Path) -> Result<(), KeychainError>; }`
  6. `pub(crate) fn load_with(name_or_hash: &str, runner: &dyn SecurityRunner) -> Result<crate::crypto::SigningCredentials, KeychainError>` — parse → empty check → select → build an export path `std::env::temp_dir().join(format!("zsign-identity-{}-{}.p12", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or_default()))` → `runner.export_identities(&path)` → closure body reads the file (`fs::read` error → `ExportFile(format!("{path}: {e}"))`), calls `crate::crypto::cert::SigningCredentials::from_p12_with_leaf_sha1(&data, "", &selected.hash).map_err(KeychainError::Credential)`, then `let _ = fs::remove_file(&path);` runs after the closure regardless (structure: `let result = (|| { … })(); let _ = std::fs::remove_file(&path); result`). (Module is never compiled on wasm32, so `SystemTime::now()` is safe here.)
  7. `#[cfg(target_os = "macos")] pub fn load(name_or_hash: &str) -> Result<crate::crypto::SigningCredentials, KeychainError> { load_with(name_or_hash, &LiveSecurity) }` plus `struct LiveSecurity;` with `impl SecurityRunner for LiveSecurity`: `find_identity` = `std::process::Command::new("/usr/bin/security").args(["find-identity", "-v", "-p", "codesigning"]).output()`; non-zero status or spawn failure → `CommandFailed { tool: "find-identity", … }` (spawn error stringified into `status`, stderr best-effort lossy). `export_identities` = same `Command` with `["export", "-t", "identities", "-f", "pkcs12", "-P", "", "-o", out.as_os_str()]`.
  8. `#[cfg(not(target_os = "macos"))] pub fn load(name_or_hash: &str) -> Result<crate::crypto::SigningCredentials, KeychainError> { let _ = name_or_hash; Err(KeychainError::MacOsOnly) }`.
  9. Doc comments on every `pub` item (workspace rule). **No ticket IDs in comments.**

- [ ] **Step 6.4:** Declare the module in `crypto/mod.rs` (beside the existing `pub mod` list at `:32-38`):

```rust
#[cfg(not(target_arch = "wasm32"))]
pub mod keychain;
```

- [ ] **Step 6.5:** Tests inside `keychain.rs` (`#[cfg(test)] mod tests`) — these close the parse/select red and add the Linux end-to-end:

```rust
    const TWO: &str = include_str!("fixtures/find-identity-two.txt");
    const ZERO: &str = include_str!("fixtures/find-identity-zero.txt");
    const AMBIGUOUS: &str = include_str!("fixtures/find-identity-ambiguous.txt");
    const RAGGED: &str = include_str!("fixtures/find-identity-ragged.txt");
    const IDENTITY_DUP: &[u8] = include_bytes!("fixtures/identity_duplicate_certs.p12");

    #[test]
    fn parse_find_identity_extracts_hash_and_name() {
        let lines = super::parse_find_identity(TWO);
        assert_eq!(lines.len(), 2);
        assert_eq!(
            hex_lower(&lines[0].hash),
            "50034388646913b117af1d6e51d9e045b77ea916"
        );
        assert_eq!(lines[0].name, "Apple Development: alice@example.com (LVGBSLUQB4)");
        assert_eq!(lines[1].name, "iPhone Distribution: Example Corp (ABCDE12345)");
    }

    #[test]
    fn parse_find_identity_handles_summary_noise_and_trailing_markers() {
        assert!(super::parse_find_identity(ZERO).is_empty());
        let lines = super::parse_find_identity(RAGGED);
        assert_eq!(lines.len(), 1, "summary + noise lines must not match");
        assert_eq!(
            lines[0].name, "Apple Development: carol@example.com (TEAM999999)",
            "a trailing marker after the closing quote is excluded from the name"
        );
    }

    #[test]
    fn select_identity_line_matches_hash_case_insensitively_and_name_exactly() {
        let lines = super::parse_find_identity(TWO);
        let by_hash = super::select_identity_line(
            &lines,
            "0123456789abcdef0123456789abcdef01234567",
        )
        .expect("lowercase hex selects");
        assert_eq!(by_hash.name, "iPhone Distribution: Example Corp (ABCDE12345)");
        let by_name = super::select_identity_line(
            &lines,
            "Apple Development: alice@example.com (LVGBSLUQB4)",
        )
        .expect("exact name selects");
        assert_eq!(by_name.hash[0], 0x50);
    }

    #[test]
    fn select_identity_line_reports_ambiguity_and_not_found() {
        let lines = super::parse_find_identity(AMBIGUOUS);
        let res = super::select_identity_line(&lines, "Apple Development: bob@example.com (TEAM000001)");
        assert!(
            matches!(&res, Err(KeychainError::Ambiguous { candidates, .. })
                if candidates.contains("1111111111111111111111111111111111111111")
                    && candidates.contains("2222222222222222222222222222222222222222")),
            "candidates must list both hashes, got {:?}",
            res.as_ref().err()
        );
        let res = super::select_identity_line(&lines, "nobody@example.com");
        assert!(
            matches!(&res, Err(KeychainError::NotFound { available, .. })
                if available.contains("TEAM000001")),
            "must list available identities, got {:?}",
            res.as_ref().err()
        );
        let res = super::select_identity_line(&super::parse_find_identity(ZERO), "x");
        assert!(matches!(res, Err(KeychainError::NoIdentities)));
    }
```

  Plus the trait-faked end-to-end (zsn37 `OcspTransport` fake pattern):

```rust
    struct FakeSecurity {
        listing: &'static str,
        export: Vec<u8>,
    }

    impl super::SecurityRunner for FakeSecurity {
        fn find_identity(&self) -> Result<String, KeychainError> {
            Ok(self.listing.to_string())
        }
        fn export_identities(&self, out: &std::path::Path) -> Result<(), KeychainError> {
            std::fs::write(out, &self.export).map_err(|e| KeychainError::ExportFile(e.to_string()))
        }
    }

    #[test]
    fn load_with_selects_one_identity_from_multi_identity_export() {
        use sha1::{Digest, Sha1};
        let contents = crate::crypto::pkcs12::extract_p12(IDENTITY_DUP, "testpassword")
            .expect("fixture parses");
        assert!(contents.certs.len() >= 2, "fixture must hold two identities");
        let hashes: Vec<[u8; 20]> = contents
            .certs
            .iter()
            .map(|c| Sha1::digest(c).into())
            .collect();
        let listing = format!(
            "  1) {} \"Apple Development: alpha (TESTTEAM)\"\n  2) {} \"Apple Development: beta (TESTTEAM)\"\n     2 valid identities found\n",
            hex_upper(&hashes[0]),
            hex_upper(&hashes[1])
        );
        let fake = FakeSecurity { listing: &listing, export: IDENTITY_DUP.to_vec() };
        let creds = super::load_with("Apple Development: beta (TESTTEAM)", &fake)
            .expect("name selection loads the exported pair");
        let leaf_der = creds.certificate.to_der().expect("leaf DER");
        assert_eq!(
            sha1_of(&leaf_der),
            hashes[1],
            "second identity must be selected"
        );
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn load_rejects_on_non_macos() {
        let err = super::load("Apple Development: a (T)").expect_err("must refuse");
        assert!(matches!(err, KeychainError::MacOsOnly));
        assert!(err.to_string().contains("macOS"), "{err}");
    }
```

  (Add local test helpers to the keychain tests module: `hex_lower(&[u8;20]) -> String` (`{b:02x}`), `hex_upper(&[u8;20]) -> String` (`{b:02X}`), `sha1_of(&[u8]) -> [u8;20]`, and ensure `der::Encode` is in scope for `to_der()` — helpers stay local to each test module, no cross-module test plumbing.)

- [ ] **Step 6.6:** Also pin the leftover export-path cleanup: in `load_with_selects_one_identity_from_multi_identity_export`, snapshot `std::env::temp_dir()` entry count (or the exact path pattern) before/after via a small assertion that no `zsign-identity-*` file remains — exact technique left to the implementer, but the invariant `no zsign-identity-*.p12 survives load_with` MUST be asserted.
  Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-core keychain 2>&1 | tail -30` → all keychain tests GREEN.
  Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-core from_p12 2>&1 | tail -10` → GREEN (selector tests + existing p12 tests untouched and passing).

---

### Task 7: ZSN-19 — CLI flag, conflicts, and load branch

**Files:**
- Modify: `crates/zsign-cli/src/main.rs` — `Cli` struct (`:14-184`), `load_credentials` (`:846+`), `-V` conflicts list (`:152-171`)

- [ ] **Step 7.1:** Add the flag immediately after `pkcs12` (`main.rs:39-45`):

```rust
    /// macOS keychain codesigning identity (name or SHA-1 hash from `security find-identity -v -p codesigning`)
    #[arg(long, conflicts_with_all = ["pkcs12", "certificate", "private_key"])]
    keychain_identity: Option<String>,
```

  Notes: the flag must NOT carry `required_unless_present_any` — required-ness lives on `-k`/`--pkcs12` (`:35`, `:42`), and they are satisfied because the flag joins the `credentials` group (Step 7.2); adding it here would make the flag itself required in some shapes and change the existing missing-argument error. Help text avoids backticks-in-comments issues by using plain prose if clippy/doc complains — keep the man-page command name readable.

- [ ] **Step 7.2:** Extend the two machine-readable lists:
  1. `credentials` group (`main.rs:19-21`): `.args(["pkcs12", "certificate", "private_key", "keychain_identity"])`.
  2. `-V` `conflicts_with_all` list (`main.rs:152-171`): append `"keychain_identity"`.
  Keep the existing comment at `:15-18` intact; add nothing ticket-related to comments.

- [ ] **Step 7.3:** Branch in `load_credentials` (`main.rs:846`) as the FIRST branch, before the `cli.pkcs12` check:

```rust
    if let Some(identity) = &cli.keychain_identity {
        return Ok(zsign_rs::crypto::keychain::load(identity)?);
    }
```

  `?` converts `KeychainError` into `Box<dyn std::error::Error>`; the existing `emit_error`/exit-1 path (`main.rs:190-200`, `:546-560`) renders it unchanged.

- [ ] **Step 7.4:** Run the Task 5.3 CLI tests green:
  Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-cli keychain 2>&1 | tail -30` → all three CLI tests GREEN.
  Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-cli credentials 2>&1 | tail -15` → existing group/conflict tests still GREEN (group membership change must not alter them).

- [ ] **Step 7.5:** Help-text sanity check (user-visible surface):
  Run: `cargo run -q -p zsign-cli -- --help 2>&1 | grep -A1 keychain-identity` → the flag appears with its description.
  Run: `cargo run -q -p zsign-cli -- -V --keychain-identity x in.ipa 2>&1 | head -3` → clap conflict error, exit ≠ 0.

---

### Task 8: ZSN-19 — macOS-gated integration test + recorded CI recipe

**Files:**
- Modify: `crates/zsign-core/src/crypto/keychain.rs` (tests module)

- [ ] **Step 8.1:** Add the live test — `cfg(target_os = "macos")` so Linux CI never compiles or runs it (design §3.6):

```rust
    #[cfg(target_os = "macos")]
    #[test]
    fn live_security_find_identity_round_trip() {
        // Runs only on macOS CI hosts; executes the real /usr/bin/security.
        let listing = super::LiveSecurity
            .find_identity()
            .expect("security find-identity must be present at /usr/bin/security");
        let lines = super::parse_find_identity(&listing);
        if let Some(first) = lines.first() {
            let creds = super::load(&hex_upper(&first.hash))
                .expect("an exportable identity must load through the full check chain");
            assert!(!creds.certificate.tbs_certificate.subject.is_empty());
        }
        // Zero identities is a valid CI state: listing + parsing still ran.
    }
```

  Requires `LiveSecurity` to be visible to the test module (it is in-file; keep it `pub(crate)` or in scope). On this Linux machine the test compiles away — state this honestly in the report.

- [ ] **Step 8.2:** Verify the cfg gates behave on Linux:
  Run: `cargo check --workspace --all-targets 2>&1 | tail -5` → clean; the macOS test does not compile here (expected).
  Run: `grep -n "cfg(target_os" crates/zsign-core/src/crypto/keychain.rs` → both `load` arms + the live test present.
  Run: `grep -rn "keychain" crates/zsign-wasm/` → zero hits (module gated off wasm32).

- [ ] **Step 8.3:** Record the macOS CI recipe verbatim in the final report and confirm the design doc §3.6 still matches what was built (it does unless Steps 6–8 deviated; if deviated, update the design doc in the same commit).

---

### Task 9: ZSN-19 — scoped gates and commits

- [ ] **Step 9.1:**
  Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-core keychain 2>&1 | tail -20` → PASS.
  Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-core from_p12 2>&1 | tail -10` → PASS.
  Run: `TMPDIR=$PWD/.tmptmp cargo test -p zsign-cli 2>&1 | tail -15` → PASS (full CLI suite: parse, conflicts, run harness).
  Run: `cargo fmt --all -- --check` → clean.
  Run: `TMPDIR=$PWD/.tmptmp cargo clippy --workspace --all-targets -- -D warnings 2>&1 | tail -10` → zero diagnostics.

- [ ] **Step 9.2:** Two commits (each green: commit 1 = core module + selector + fixtures/tests without the flag; the CLI tests live in commit 2 with the flag):
  Run: `git add crates/zsign-core/src/crypto/ && git commit -m "load signing credentials from a macOS keychain identity (ZSN-19)"`
  Run: `git add crates/zsign-cli/src/main.rs && git commit -m "add keychain-identity credential flag with parse-time conflicts (ZSN-19)"`
  Verify each staged set compiles standalone (`cargo test -p zsign-cli keychain` fails pre-flag? It must NOT be staged before the flag exists — order the staging exactly as written: CLI test files go with the flag commit, so the tree at commit 1 simply has no CLI tests yet). Never push.

---

### Task 10: Final gates and report evidence

- [ ] **Step 10.1 — verbatim gates (no skips):**
  Run: `cargo fmt --all -- --check; echo "fmt=$?"`
  Run: `TMPDIR=$PWD/.tmptmp cargo clippy --workspace --all-targets -- -D warnings 2>&1 | tail -5; echo "clippy=$?"`
  Run: `TMPDIR=$PWD/.tmptmp cargo test --workspace --no-fail-fast 2>&1 | tail -30` (NO `--skip`; ZSN-15 determinism runs green)
  Expected: all PASS; capture the summary lines verbatim for the report.

- [ ] **Step 10.2 — P5 evidence:**
  Run: `grep -rn "32-bit Mach-O binaries not supported" crates/ || echo "no hits"`
  Expected: `no hits`.

- [ ] **Step 10.3 — report assembly (no code changes):** commit list per ticket; verbatim gate outputs; red→green evidence from Tasks 1/5; the macOS CI recipe (design §3.6 / Task 8.3); deviations; seams (§4 of design: zsn43 zero-overlap confirmation, docs-lane README needs, non-exportable-key gap, export-search-list gap, macOS arm not executed locally).

---

## Self-review checklist (writing-plans)

- [x] **Spec coverage:** design §2.3 P1–P6 → Tasks 1–4 (P5 = Step 4.6/10.2, P6 = Step 10.1); design §3.6 tests → Tasks 5–8; flag design §3.2 → Task 7; error design §3.4 → Task 6.3; cfg gating §3.5 → Steps 6.4, 8.2; macOS recipe → Task 8.
- [x] **Placeholder scan:** no TBD/TODO; every code step shows code or exact anchors with the live source named as authoritative where line numbers drift.
- [x] **Type consistency:** `ensure_signable_bitness(bool, bool)` used at all guard sites (six `32-bit Mach-O binaries not supported` sites per design §2.2, plus the `inject_dylib_thin` magic gate as the seventh call site — not a seventh bare guard); `from_p12_with_leaf_sha1(&[u8], &str, &[u8;20])` consistent between cert.rs and keychain.rs; `SecurityRunner` method names identical across trait, live impl, fake; `KeychainError` variant names consistent across definition and all `matches!` tests; CLI flag id `keychain_identity` consistent between arg, group, conflicts lists, and tests.
- [x] **Sequencing:** red before green per ticket; commits only on green; docs commit precedes cold review.
