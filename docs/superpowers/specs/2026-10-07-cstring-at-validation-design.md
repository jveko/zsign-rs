# ZSN-91 CodeDirectory String Parsing Validation — Design

**Date:** 2026-10-07 · **Ticket:** ZSN-91 · **Branch:** `zsn-91`
**Status:** approved for planning (cold review gate follows this doc and the plan)

## Goal

Make malformed CodeDirectory string references fail loudly instead of yielding
plausible-looking values. Two defects, both in `crates/zsign-core/src/codesign/verify.rs`:

1. `cstring_at` silently accepts an unterminated string (falls back to the whole
   remaining buffer), so a missing NUL terminator is never noticed.
2. `identOffset`/`teamOffset` are only checked `< data.len()`; nothing constrains them
   to the CodeDirectory's header/string region, so a malformed directory produces a
   fabricated identifier/team through the `pub` accessors instead of a rejected parse.

Files in scope — nothing else may be touched:

- `crates/zsign-core/src/codesign/verify.rs` (private helper, the `CodeDirectory::parse`
  bounds block, accessor doc comments, inline `#[cfg(test)]` tests)

## Evidence — current behavior (verified at `1d3df58`)

- Helper, verbatim (`verify.rs:826-831`, doc comment :826, body :827-831):

  ```rust
  fn cstring_at(data: &[u8], offset: usize) -> Option<&str> {
      let rest = data.get(offset..)?;
      let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
      std::str::from_utf8(&rest[..end]).ok()
  }
  ```

  `unwrap_or(rest.len())` accepts an unterminated tail wholesale; the only bound is the
  non-panicking `data.get(offset..)`, and no caller passes a region end.
- Callers, both `pub`, both unchanged by this design:
  `identifier()` at `verify.rs:744-747` → `cstring_at(self.data, self.ident_offset)`;
  `team_id()` at `verify.rs:749-752` → `self.team_offset.and_then(|off| cstring_at(...))`.
- Offsets are u32 header fields read at parse: `identOffset` = `rd_u32(20)`
  (`verify.rs:597`), `teamOffset` = version-gated `rd_u32(48)` (`verify.rs:626-630`),
  with `teamOffset == 0 → None` (`verify.rs:698` — the absent-team convention).
- The only existing validation is `ident_offset >= data.len()` →
  `Error::Verification("CodeDirectory identifier offset out of bounds")`
  (`verify.rs:693-697`) and the team twin (`verify.rs:699-705`). `data` is the
  declared-length CD prefix `&blob[..declared]` (`verify.rs:551`), so "anywhere in
  `data`" includes the fixed header and the hash slots.
- Region bounds knowable at construction: per-version `header_size`
  (`verify.rs:570-586`), `hash_offset` (`verify.rs:596`), `data.len()`. The string
  region end is never stored on the struct (`verify.rs:492-527`).
- Consumers of a fabricated value: `macho/verify.rs:183` (`report.identifier`, JSON
  `null`-able field surfaced by the CLI) and `macho/verify.rs:441` → `RequirementContext`
  → `Expr::Ident` maps `None` to `Tri::Unknown` (`codesign/verify.rs:293-301`), which
  surfaces as an `Unsupported` **warning** (`macho/verify.rs:449-451`), never an error.
- No existing test relies on the lenient behavior. Every fixture places the identifier
  canonically: `synth_cd` writes `identOffset = 44 + tail.len() == header_size` with
  `b"x\0"` (`verify.rs:1692-1708`), exercised for all seven header sizes
  (`verify.rs:1710-1735`); `synth_cd_with_slot8` uses `identOffset = 88 == header_size`
  (`verify.rs:1642-1665`); builder output sets `identOffset = CODEDIRECTORY_HEADER_SIZE`
  (`code_directory.rs:350`, `code_directory.rs:126` — 88 for the emitted version
  `0x20400`, `constants.rs:229`) and lays strings out before the special-slot hashes
  (`code_directory.rs:364-367`, NUL pushes at `:400`/`:405`). The only read-side
  assertion is `assert_eq!(cd.identifier(), Some("com.example.test"))`
  (`verify.rs:1525`), builder-produced. Fuzz targets only discard the results
  (`fuzz/fuzz_targets/code_directory.rs:10-11`, `superblob.rs:24-25`).

## Evidence — external contract (librarian, source-verified)

Pinned sources: XNU `f6217f89` (2025-10-04), Apple Security `db15acbe`,
`zhlynn/zsign` `614caa8d`, `ldid` `af86971a`, `apple-platform-rs` (indygreg)
`0ebbd2ef`.

1. **Region:** offsets are relative to the start of the CodeDirectory blob;
   `identOffset == fixedSize(version)` (the header size) and
   `teamOffset == identOffset + strlen(ident) + 1` in every Apple builder; strings sit
   between the fixed header and the special-slot hashes
   (`hashOffset = end_of_team + nSpecialSlots * hashSize`).
2. **Terminator:** the identifier must be NUL-terminated. XNU comments it literally
   (`/* identifier is NUL terminated string */`) and validates with a **bounded** scan:
   `if (length < ntohl(cd->identOffset)) return EBADEXEC;` then
   `memchr((const char *)cd + ntohl(cd->identOffset), 0, length - identOffset) == NULL
   → EBADEXEC`. Security.framework's `BlobCore::stringAt()` likewise requires
   `offset < length()` and a NUL in `[offset, length)`; missing → `errSecCSSignatureFailed`
   from `checkIntegrity()` (the whole CD is rejected, not truncated).
3. **Malformed ⇒ reject:** kernel rejects the whole directory (EBADEXEC);
   apple-codesign returns typed `CodeDirectoryMalformedIdentifier`/`...Team` errors.
   There is no "return a degraded value" semantics anywhere on the Apple path.
4. **teamOffset == 0 ⇒ absent and legal**, even at version ≥ 0x20200 (ad-hoc). The
   kernel checks the team string only when `version >= 0x20200 && teamOffset != 0` —
   the same gate our parse already applies.
5. **Lenient readers are the anti-pattern:** upstream `zhlynn/zsign` prints
   `pSlotBase + LE(cdHeader.identOffset)` straight into `%s` (an unbounded read on
   malformed input); `ldid` does the same. Neither is a model to copy.
6. **Known kernel gap (deliberate):** the kernel does *not* check that the offset lies
   outside the header/hash regions — Security's own comment skips it ("flagged as
   nonsense later"). Our design closes that gap (see D4 tradeoff); this parser is
   already deliberately stricter than the kernel (scatter, pre-encrypt, runtime flag,
   page-size rejections).

## Design decisions

### D1 (chosen): parse-time string-region validation + strict `cstring_at`

Two layers, each independently testable, each reusing an existing in-repo convention:

**Layer 1 — parse (rejected parse, sibling convention).** In `CodeDirectory::parse`,
the ident/team bounds block (`verify.rs:692-705`) is replaced by region-aware checks
that run *after* the two existing hash-region checks (`expected_tail` :706-717,
`n_special` :718-721). The relocation is load-bearing: once `n_special <=
hash_offset / hash_size` holds, `string_end = hash_offset - n_special * hash_size`
cannot underflow on any width (the product is ≤ `hash_offset`, and `hash_size` was
already validated to 20 or 32 at :681-689), and `string_end <= data.len()` follows
from `expected_tail <= data.len()`. Rules, per string that exists (identifier always;
team only when `team_offset` is `Some`, i.e. the kernel's own gate):

- offset must satisfy `header_size <= offset < string_end`, else
  `Error::Verification("CodeDirectory {identifier|team ID} offset outside the string
  region")`;
- a NUL must exist in `data[offset..string_end]`, else
  `Error::Verification("CodeDirectory {identifier|team ID} is not NUL-terminated")`.

`Error::Verification(String)` is the sole convention for malformed-CD parse failures
in this file (:545, :553, :560, :578, :604, :611, :644, :650, :669, :693, :701, :715,
:719 — `crates/zsign-core/src/error.rs:40-41`), so no new variant is introduced. The
two old messages ("...offset out of bounds") are subsumed by the region message
(`string_end <= data.len()`, so any offset that failed the old check fails the new
one); no test or consumer matches those payloads (wasm maps the variant, not the
string).

**Layer 2 — helper (strict scan).** `cstring_at` (`verify.rs:827-831`) drops the
lenient fallback: `let end = rest.iter().position(|&b| b == 0)?;`. Its signature and
both callers are unchanged. After parse validation the missing-NUL arm is
unreachable through public API — it exists so the helper's own contract cannot
regress, and it is pinned by direct unit tests. Its doc comment states all three
`None` conditions (offset out of bounds, no terminator, non-UTF-8).

**Accessor docs** get one sentence each noting that offsets/terminators are validated
by `CodeDirectory::parse`; `None` from these accessors now means "absent team" or
"identifier bytes are not valid UTF-8".

**Why rejected parse, not `None` (this is the ticket's own words):** the ticket says a
malformed directory "currently yields a plausible-looking identifier/team instead of a
rejected parse". Downstream, `None` degrades the designated-requirement check to an
*Unknown* warning and ships `null` in the report — a verification engine should not
report "unknown" for a directory Apple's kernel would refuse to execute. The repo
agrees: the *identical* offset checks already error at parse today.

### Invariants after the change

- `CodeDirectory::parse` returns `Ok` ⟹ for the struct it produced:
  `header_size <= ident_offset < string_end <= data.len()`; the same holds for
  `team_offset` when `Some`; a NUL exists within `[offset, string_end)` for both.
- `identifier()` returns `Some(s)` ⟺ `s` is the NUL-terminated, in-region identifier
  reinterpreted as UTF-8; `team_id()` additionally returns `None` for absent teams
  (`teamOffset == 0` or version < 0x20200 — unchanged).
- No public signature or type changes: both accessors stay `Option<&'a str>`; fuzz
  targets, `macho/verify.rs`, the facade crates, and the CLI compile untouched.
- Only `verify.rs` changes; no sibling finding is fixed (see report for citations).

### Alternatives rejected

- **D2 — accessor-level strictness only** (`identifier()` returns `None` on
  malformed): contradicts the ticket's stated "rejected parse"; conflates "malformed"
  with "absent team"/"non-UTF-8" at the API; weaker than the repo's own precedent
  (offsets already error at parse); leaves a malformed directory constructing and
  flowing into cdhash/report machinery.
- **D3 — pre-resolve strings at parse** (store `ident: &'a str` fields):
  single validation site and O(1) access are real, but it restructures the struct,
  duplicates state (offsets + strings), and buys nothing observable on a low-priority
  ticket — YAGNI.
- **D4 — kernel-parity without the header-region lower bound** (only require
  `offset < string_end` + NUL): strictly matches XNU, but the ticket explicitly asks
  for offsets constrained to the header/string region, and an offset below
  `header_size` can only ever fabricate magic/version bytes as an "identifier".
  Tradeoff accepted: we reject some nonsense kernels would tolerate — consistent with
  this parser's existing stricter-than-kernel checks (evidence §6).
- **D5 — exact equality `ident_offset == header_size`**: what every builder emits, but
  a lower bound accepts non-canonical-yet-unambiguous layouts with zero extra risk;
  equality only adds false-rejection surface.

## Test strategy

Inline `#[cfg(test)] mod tests` in `verify.rs`, existing conventions only
(`assert!(matches!(&err, crate::Error::Verification(m) if m.contains("…")), …)`
for `Result`, `assert_eq!` for `Option`):

1. **Helper contract (direct calls):** unterminated input → `None` (red before the
   fix: returns the whole tail); offset past end → `None`; non-UTF-8 before NUL →
   `None`; terminated positive control → `Some`.
2. **Parse rejections (five, all red today — each currently parses `Ok`):**
   `identOffset < header_size`; `identOffset` inside the hash region
   (via `synth_cd_with_slot8`, patching bytes 20..24 ≥ `string_end`); identifier with
   its terminator byte overwritten; `teamOffset < header_size`; team string with no
   NUL before `string_end` (extend a `synth_cd` blob by two non-zero bytes, updating
   declared length, `hashOffset`, `teamOffset`).
3. **Positive guards (must stay green):** all seven `synth_cd` versions parse
   (`version_header_sizes_are_correct`, :1710); `linkage_fields_are_bounds_checked`
   ok-arm (:1939, `t2`); builder round trip `identifier() == Some("com.example.test")`
   (:1525); plus one new builder round trip with a team asserting
   `team_id() == Some(...)` so the region checks are proven not to false-reject the
   team path.
4. **Whole-scope gate:** `cargo fmt --all -- --check`,
   `cargo clippy -p zsign-core --all-targets -- -D warnings`,
   `cargo test -p zsign-core`, then `cargo test --workspace` before reporting.

## Acceptance criteria

1. `cstring_at` returns `None` for unterminated input (pinned by a direct helper test).
2. `CodeDirectory::parse` rejects: out-of-region identifier offset, out-of-region
   team offset, unterminated identifier, unterminated team — each with
   `Error::Verification` naming the region/terminator problem (five tests).
3. No fixture relying on pre-change behavior regresses; the scoped gates are green
   with verbatim output in the final report.
4. Exactly one production file changes (`verify.rs`); no public API change; no
   ticket ID in any code comment; worktree committed, never merged, never pushed.
