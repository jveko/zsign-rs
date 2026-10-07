# ZSN-91 CodeDirectory String Parsing Validation — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development (recommended) with dispatching-parallel-agents for independent tasks to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make malformed CodeDirectory string references fail loudly: `cstring_at` stops
accepting unterminated strings, and `CodeDirectory::parse` rejects identifier/team offsets
outside the blob or missing their NUL terminators — Apple's validator rules exactly
(`identifier()` additionally mirrors `csblob_get_identity` by returning `None` for
`identOffset == 0`).

**Architecture:** Two layered fixes, both inside `crates/zsign-core/src/codesign/verify.rs`:
(1) the private helper's NUL scan becomes strict (`?` instead of `unwrap_or(rest.len())`);
(2) the parse-time bounds block gains terminator checks that return
`Error::Verification`, mirroring Apple's validator: offset `< data.len()` (the
pre-existing bound, folded into one labelled helper) plus a NUL in `[offset, data.len())`
— no structural region, since Apple declines overlap checks (Security
`codedirectory.cpp:153-164`; XNU bounds `memchr` only by blob length). No public
signature changes; accessors stay `Option<&'a str>`.

**Tech Stack:** Rust 2021 / cargo / thiserror; gates via `cargo fmt`, `cargo clippy`,
`cargo test` (scoped with `TMPDIR=$PWD/target/tmp`).

**Spec:** `docs/superpowers/specs/2026-10-07-cstring-at-validation-design.md` — the plan
argues from the spec; executors read both.

## Global Constraints

- Files in scope ONLY: `crates/zsign-core/src/codesign/verify.rs` (helper, `CodeDirectory::parse`
  bounds block, accessor doc comments, inline `#[cfg(test)]` module). Nothing else — no
  `macho/`, no `code_directory.rs` (builder), no `error.rs`, no other tickets' findings.
- No public API change: `identifier()`/`team_id()` keep `Option<&'a str>`; no new error
  variants (`Error::Verification(String)` only, `crates/zsign-core/src/error.rs:40-41`);
  no new imports (the `use` block at `verify.rs:28-31` stays as-is).
- No `TODO`/stubs/placeholders; ticket ID never appears in code comments; subagents do not
  commit (the controller commits after each green task).
- Error assertions follow the file's dominant pattern:
  `assert!(matches!(&err, crate::Error::Verification(m) if m.contains("…")), "…, got {err:?}")`;
  `Option` results use `assert_eq!`.
- Scope gates only (no project-wide cold CI mid-flight), always with
  `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp`:
  `cargo fmt --all -- --check`; `cargo clippy -p zsign-core --all-targets -- -D warnings`;
  `cargo test -p zsign-core`. The final pre-report gate adds `cargo test --workspace`.

## Review Focus

1. **Layer split must not create a gap:** a missing NUL must be caught by BOTH the direct
   helper test (Task 1) and the parse rejection tests (Task 2) — neither layer may assume
   the other's tests cover it.
2. **Absent and offset-zero ≠ malformed:** `teamOffset == 0` (and version < 0x20200) must
   keep parsing and yield `team_id() == None` — pinned by the positive guard; `identOffset == 0`
   must parse and yield `identifier() == None` (never a parse error) — pinned by the
   `csblob_get_identity` parity test; all seven `synth_cd` versions (`verify.rs:1710-1735`)
   must keep parsing.
3. **False rejection of valid output:** builder round trips (with and without a team) must
   still parse — the positive guard in Task 2 plus the existing `verify.rs:1525` assertion;
   header-region offsets with an in-blob NUL must keep parsing — pinned by the overlap
   tolerance test (an off-by-one or a resurrected floor fails exactly there).
4. **Check ordering:** the terminator checks run AFTER `expected_tail`/`n_special`
   (the block's existing layout) yet preserve the existing diagnostics
   (`"hash region … overruns blob"`, `"special-slot region overruns hash offset"`,
   pinned by `verify.rs:2044-2057`).
5. **Slice safety inside the new closure:** `data[off..]` is only reached after
   `off < data.len()` is proven — the bounds check must be the
   first statement of `check_string`.

These map to Task 1 steps 1/3 and Task 2 steps 1/3/4 below.

---

## Task 1: Make `cstring_at` require a NUL terminator

**Files:**
- Modify: `crates/zsign-core/src/codesign/verify.rs` — helper at `:826-831`
- Test: same file, inline `#[cfg(test)] mod tests` (module at `:1247-1248`)

**Interfaces:**
- Consumes: nothing new (private free function, in-module only).
- Produces: `fn cstring_at(data: &[u8], offset: usize) -> Option<&str>` — signature
  unchanged; `None` now also when no terminator follows `offset` (documented on the
  doc comment). Callers `identifier()` (`:745-746`) and `team_id()` (`:750-751`) compile
  unchanged.

- [ ] **Step 1: Baseline the scoped suite**

Run: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-core codesign::verify::tests`
Expected: PASS — record the summary line (e.g. `test result: ok. N passed; 0 failed`).

- [ ] **Step 2: Write the failing helper tests (Tester)**

Add to the inline test module, next to the other small helper tests:

```rust
#[test]
fn cstring_at_requires_a_nul_terminator() {
    assert_eq!(
        cstring_at(b"com.example.test\0trailing", 0),
        Some("com.example.test"),
        "control: terminated string is returned without its tail"
    );
    assert_eq!(
        cstring_at(b"com.example.test", 0),
        None,
        "a missing NUL must not be read as end-of-string"
    );
    assert_eq!(
        cstring_at(b"com.example.test", usize::MAX),
        None,
        "an offset past the buffer must be None"
    );
    assert_eq!(
        cstring_at(b"com.\xff.example\0", 0),
        None,
        "bytes up to the terminator must be valid UTF-8"
    );
}
```

- [ ] **Step 3: Run the test, confirm it fails for the right reason**

Run: `TMPDIR=$PWD/target/tmp cargo test -p zsign-core cstring_at_requires_a_nul_terminator`
Expected: FAIL — assertion 2 gets `Some("com.example.test") == None` (the lenient
`unwrap_or(rest.len())` fallback), while assertions 1, 3, 4 already hold.

- [ ] **Step 4: Harden the helper**

In `verify.rs:826-831`, replace the doc comment and body exactly with:

```rust
/// Reads a NUL-terminated string from `data` at `offset`.
///
/// Returns [`None`] when `offset` is past the end of `data`, when no
/// terminator follows it, or when the bytes before the terminator are not
/// valid UTF-8.
fn cstring_at(data: &[u8], offset: usize) -> Option<&str> {
    let rest = data.get(offset..)?;
    let end = rest.iter().position(|&b| b == 0)?;
    std::str::from_utf8(&rest[..end]).ok()
}
```

- [ ] **Step 5: Run the test, confirm green**

Run: `TMPDIR=$PWD/target/tmp cargo test -p zsign-core cstring_at_requires_a_nul_terminator`
Expected: PASS (1 passed).

- [ ] **Step 6: Confirm no existing consumer regressed**

Run: `TMPDIR=$PWD/target/tmp cargo test -p zsign-core codesign`
Expected: PASS — every fixture feeds NUL-terminated strings (`synth_cd` at `:1692`,
builder output at `code_directory.rs:400`), so no existing assertion on
`identifier()`/`team_id()` can change; record the summary line.

- [ ] **Step 7: Scoped lint/format gate**

Run: `cargo fmt --all -- --check && cargo clippy -p zsign-core --all-targets -- -D warnings`
Expected: no output (both clean).

- [ ] **Step 8: Commit (controller)**

Run: `git add crates/zsign-core/src/codesign/verify.rs && git commit -m "reject unterminated strings in codesign cstring helper (ZSN-91)"`
Expected: clean worktree for this file; one commit, never pushed.

---

## Task 2: Reject unterminated CodeDirectory strings at parse (kernel parity)

**Files:**
- Modify: `crates/zsign-core/src/codesign/verify.rs` — bounds block `:692-721`; accessor
  doc comments `:744`, `:749`
- Test: same file, inline `#[cfg(test)] mod tests`

**Interfaces:**
- Consumes: Task 1's strict `cstring_at` (unchanged signature).
- Produces: `CodeDirectory::parse` guarantee — on `Ok`, `ident_offset < data.len()`
  and (when present) `team_offset < data.len()`, with a NUL inside
  `[offset, data.len())` for each; no structural (header/hash) constraint. Accessor
  docs state it; no type changes.

- [ ] **Step 1: Write the failing parse tests (Tester)**

Add to the inline test module (this set supersedes the earlier region-bound tests:
the two `*_inside_header_is_rejected` tests are deleted as part of this change):

```rust
#[test]
fn string_region_overlap_is_tolerated_like_the_kernel() {
    // Apple declines overlap checks (Security's codedirectory comment; XNU
    // only bounds its memchr by the blob length), so header-region offsets
    // whose bytes carry a terminator inside the blob must keep parsing.
    let mut ident = synth_cd(0x20400, &[0u8; 44]);
    ident[20..24].copy_from_slice(&40u32.to_be_bytes()); // inside the 88-byte header
    assert!(CodeDirectory::parse(&ident).is_ok(), "ident offset in header");

    let mut team = synth_cd(0x20400, &[0u8; 44]);
    team[48..52].copy_from_slice(&40u32.to_be_bytes()); // inside the 88-byte header
    assert!(CodeDirectory::parse(&team).is_ok(), "team offset in header");
}

#[test]
fn identifier_offset_inside_hash_region_is_rejected() {
    let mut cd = synth_cd_with_slot8(b"x");
    // offset 400 lands in the code-hash/trailing area; the 0x5A fill carries no NUL before the blob end, so the bounded scan rejects it (kernel parity).
    cd.extend_from_slice(&[0x5au8; 100]);
    cd[4..8].copy_from_slice(&459u32.to_be_bytes());
    cd[20..24].copy_from_slice(&400u32.to_be_bytes());
    let err = CodeDirectory::parse(&cd).unwrap_err();
    assert!(
        matches!(&err, crate::Error::Verification(m)
            if m.contains("identifier") && m.contains("NUL-terminated")),
        "got {err:?}"
    );
}

#[test]
fn unterminated_identifier_is_rejected() {
    let mut cd = synth_cd(0x20400, &[0u8; 44]);
    cd[89] = b'y'; // was the NUL: identifier "x" becomes "xy" with no terminator in the blob
    let err = CodeDirectory::parse(&cd).unwrap_err();
    assert!(
        matches!(&err, crate::Error::Verification(m)
            if m.contains("identifier") && m.contains("NUL-terminated")),
        "got {err:?}"
    );
}

#[test]
fn unterminated_team_id_is_rejected() {
    let mut cd = synth_cd(0x20400, &[0u8; 44]); // len 90; ident "x\0" at 88..90
    cd[48..52].copy_from_slice(&90u32.to_be_bytes()); // teamOffset = 90
    cd.extend_from_slice(b"yz"); // team bytes with no terminator
    cd[4..8].copy_from_slice(&92u32.to_be_bytes()); // declared length
    cd[16..20].copy_from_slice(&92u32.to_be_bytes()); // hashOffset grows with the declared blob
    let err = CodeDirectory::parse(&cd).unwrap_err();
    assert!(
        matches!(&err, crate::Error::Verification(m)
            if m.contains("team ID") && m.contains("NUL-terminated")),
        "got {err:?}"
    );
}

#[test]
fn ident_offset_zero_parses_and_reads_none_like_the_kernel() {
    // Per csblob_get_identity: the kernel validator accepts identOffset 0
    // (a NUL exists in the blob), while identity retrieval returns NULL —
    // so parse must succeed and identifier() must be None, not an error.
    let mut cd = synth_cd(0x20400, &[0u8; 44]);
    cd[20..24].copy_from_slice(&0u32.to_be_bytes());
    let parsed = CodeDirectory::parse(&cd).expect("offset 0 must parse");
    assert_eq!(parsed.identifier(), None, "magic bytes are not UTF-8");
}

#[test]
fn valid_strings_survive_region_checks() {
    let bytes = CodeDirectoryBuilder::new("com.example.team", TEST_CODE)
        .team_id("ABCDE12345")
        .build_sha256();
    let cd = CodeDirectory::parse(&bytes).expect("builder output must parse");
    assert_eq!(cd.identifier(), Some("com.example.team"));
    assert_eq!(cd.team_id(), Some("ABCDE12345"));

    let raw = synth_cd(0x20400, &[0u8; 44]);
    let no_team = CodeDirectory::parse(&raw).expect("parse");
    assert_eq!(
        no_team.team_id(),
        None,
        "teamOffset 0 is absent, not malformed"
    );
}
```

- [ ] **Step 2: Run, confirm three red / three green for the right reasons**

Run: `TMPDIR=$PWD/target/tmp cargo test -p zsign-core codesign::verify::tests::`
Expected: THREE tests FAIL because the structural bounds are still in the code —
`string_region_overlap_is_tolerated_like_the_kernel` and
`ident_offset_zero_parses_and_reads_none_like_the_kernel` (parse returns `Err`
"string region" where `Ok` is required) and
`identifier_offset_inside_hash_region_is_rejected` (parse fails, but with the
"string region" message where "NUL-terminated" is asserted). The two unterminated
tests and `valid_strings_survive_region_checks` PASS already and must keep passing
after the change. Record the failure list.

- [ ] **Step 3: Implement the blob-bounded terminator checks**

In `CodeDirectory::parse`, replace the span from the comment
`// Bounds: identifier/team strings, then special slots, then code slots.`
(`verify.rs:692`) through the end of the `n_special > hash_offset / hash_size.max(1)`
check (`verify.rs:721`) — the two existing hash checks keep their exact code, just moved
above the string checks — with:

```rust
        // Bounds: special slots, then code slots. Apple performs no overlap
        // checks on the identifier/team offsets (XNU only bounds its memchr by
        // the blob length), so each string must simply be found inside the blob
        // and carry its terminator there.
        let n_special = n_special_slots as usize;
        let n_code = n_code_slots as usize;
        let expected_tail = n_code
            .checked_mul(hash_size)
            .and_then(|bytes| hash_offset.checked_add(bytes))
            .ok_or_else(|| crate::Error::Verification("hash region overflow".into()))?;
        if expected_tail > data.len() {
            return Err(crate::Error::Verification(format!(
                "CodeDirectory hash region ({n_special} special + {n_code} code slots) overruns blob"
            )));
        }
        if n_special > hash_offset / hash_size.max(1) {
            return Err(crate::Error::Verification(
                "CodeDirectory special-slot region overruns hash offset".into(),
            ));
        }
        let team_offset = (team_offset_raw != 0).then_some(team_offset_raw as usize);
        let check_string = |label: &str, off: usize| -> Result<()> {
            if off >= data.len() {
                return Err(crate::Error::Verification(format!(
                    "CodeDirectory {label} offset out of bounds"
                )));
            }
            if data[off..].iter().position(|&b| b == 0).is_none() {
                return Err(crate::Error::Verification(format!(
                    "CodeDirectory {label} is not NUL-terminated"
                )));
            }
            Ok(())
        };
        check_string("identifier", ident_offset)?;
        if let Some(off) = team_offset {
            check_string("team ID", off)?;
        }
```

Notes for the implementer: `team_offset`'s definition moves into this block (it is only
consumed by the struct literal after it); `hash_size` is validated to 20 or 32 before this
point, so the division is safe; `Result` is already imported (`verify.rs:29`); no import
changes. Then replace the `identifier()` doc comment AND body with the first block below,
and the `team_id()` doc comment with the second (its body stays unchanged):

```rust
    /// The bundle identifier recorded in the CodeDirectory.
    ///
    /// [`CodeDirectory::parse`] validates the offset's bounds and terminator;
    /// [`None`] here also means `identOffset` is 0 (the kernel exposes no
    /// identity in that case) or the bytes are not valid UTF-8.
    pub fn identifier(&self) -> Option<&'a str> {
        if self.ident_offset == 0 {
            return None;
        }
        cstring_at(self.data, self.ident_offset)
    }
```

```rust
    /// The team ID recorded in the CodeDirectory, if any.
    ///
    /// [`None`] also means the directory records no team ID (offset 0, or
    /// versions before 0x20200); offsets and terminators are validated by
    /// [`CodeDirectory::parse`].
    pub fn team_id(&self) -> Option<&'a str> {
```

- [ ] **Step 4: Run the six tests, confirm green**

Run: `TMPDIR=$PWD/target/tmp cargo test -p zsign-core codesign::verify::tests::`
Expected: PASS — all six new tests green, no other test in the module newly failing;
record the summary line.

- [ ] **Step 5: Full scoped suite + lint/format**

Run: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test -p zsign-core && cargo fmt --all -- --check && cargo clippy -p zsign-core --all-targets -- -D warnings`
Expected: all green, no output from fmt/clippy. This proves the fixtures pinned in the
spec (all seven `synth_cd` versions, `linkage_fields_are_bounds_checked` `t2` arm at
`:1939`, `parse_rejects_hash_region_product_overflow` at `:2044`, the `:1525` identifier
assertion) still hold.

- [ ] **Step 6: Commit (controller)**

Run: `git add crates/zsign-core/src/codesign/verify.rs && git commit -m "validate codesign cd string offsets and terminators at parse (ZSN-91)"`
Expected: clean worktree; one commit, never pushed.

---

## Task 3: Final verification gate

**Files:** none (verification only).

- [ ] **Step 1: Full workspace gate**

Run: `mkdir -p target/tmp && TMPDIR=$PWD/target/tmp cargo test --workspace`
Expected: PASS — record the verbatim summary lines (this is the pre-report gate; it also
compiles the fuzz targets and facade crates, proving no caller broke).

- [ ] **Step 2: Zero-warning gate**

Run: `cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings`
Expected: no output.

- [ ] **Step 3: Commit-state check (controller)**

Run: `git status --short` and `git log --oneline -3`
Expected: empty status; the two implementation commits (plus the design/plan commit) at
the tip; nothing merged, nothing pushed.
