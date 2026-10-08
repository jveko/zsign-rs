# Bounds-checked Mach-O slice accessors — design

Date: 2026-10-08
Status: accepted

## Problem

`ArchSlice` (`crates/zsign-core/src/macho/parser.rs:113-147`) is `#[derive(Clone)]`
with every field `pub` and no back-reference to the file it was parsed from. It is
re-exported from `zsign-core` (`crates/zsign-core/src/macho/mod.rs:17`) and from the
`zsign-rs` facade (`crates/zsign/src/macho/mod.rs:30`), so any external caller can
construct, clone, and mutate values freely.

The two accessors translate `(offset, length)` pairs back into `MachOFile::data` with
no bounds check:

- `code_bytes` — `parser.rs:429-433`: `let end = start + slice.code_length; &self.data[start..end]`
- `slice_data` — `parser.rs:440-444`: `let end = start + slice.size; &self.data[start..end]`

Two failure modes, both verified against the standard library docs:

1. `Range<usize>` indexing panics when the end of the range is out of bounds or the
   start is greater than the end (std `SliceIndex` docs,
   <https://doc.rust-lang.org/std/primitive.slice.html#impl-SliceIndex%3C%5BT%5D%3E-for-Range%3Cusize%3E>).
2. `start + len` panics on `usize` overflow only when overflow checks are on (debug).
   In release builds the plain `+` wraps silently to a small `end`, which either
   panics in the index or — worse — yields a plausible but wrong subslice
   (<https://doc.rust-lang.org/reference/expressions/operator-expr.html#overflow-operations>,
   <https://doc.rust-lang.org/std/primitive.usize.html#method.wrapping_add>).

**Reachability calibration (kept from the ticket, re-verified):** the parse path
cannot trigger either failure. `parse_single` bounds `code_length` by `declared_size`
(`parser.rs:366-374`) and the FAT constructor validates `offset + size <= file_len`
with `checked_add` (`parser.rs:201-211`). This is API hardening of the public surface,
not untrusted-bytes handling; the design must not pretend otherwise.

## Verified call-site inventory

| Site | Location | Migration |
|---|---|---|
| `macho.slice_data(slice)` (production) | `signer.rs:259, 312, 356, 458` | add `?` — all four sit in `Result`-returning fns (`:458` inside a rayon closure returning `Result<SignedSlice>`) |
| `macho.code_bytes(...)` (test) | `signer.rs:1393, 1467` | `.expect(...)` at the assertion |
| `m.slice_data(sl)` (test) | `writer.rs:3073, 3078` | `.expect(...)` at the assertion |
| facade wrappers | `crates/zsign/src/macho/parser.rs:56-61` | signature → `Result<&[u8]>`, body `Ok(self.inner.…?)` |
| production callers of `code_bytes` | none anywhere in the workspace | — |
| callers in `zsign-cli`, `zsign-wasm`, `fuzz` | none (`wasm` uses only `slices().len()`) | — |

No struct-update syntax exists; construction sites are `parser.rs:375` (parse),
mutation at `parser.rs:219-220` (FAT branch), and rebuilds at `signer.rs:498, 632` —
all untouched by this design.

## Candidates considered

### A — Checked indexing returning `Result<&[u8]>` (chosen)

Both accessors return `crate::Result<&[u8]>`; the body is the module's own
`checked_add(...).and_then(|end| data.get(start..end)).ok_or_else(|| Error::MachO(..))?`
shape, already used at `parser.rs:201-211` and `writer.rs:344-349`.

- Removes both failure modes in every build profile: overflow becomes `Err`, an
  out-of-range end becomes `Err`, and no wrapped arithmetic is ever indexed.
- No silent-wrong-data path: a forged slice cannot produce an empty or truncated
  byte range that a caller would happily hash or re-sign.
- Matches the crate-wide convention: one `Error` enum, `MachO(String)` payloads,
  `crate::Result` everywhere (`crates/zsign-core/src/error.rs:7-8`).
- Cost: breaking signature change on a `pub` inherent method. Both crates are
  pre-1.0 (`zsign-core` 0.1.0, `zsign-rs` 0.1.2), where a `y` bump is a major
  release per Cargo's semver rules
  (<https://doc.rust-lang.org/cargo/reference/semver.html>); changing a return type
  is a Major change (RFC 1105 policy: <https://github.com/rust-lang/rfcs/blob/master/text/1105-api-evolution.md>).
  The brief classifies public-API change as in-scope, so the break is recorded as a
  deliberate decision rather than avoided.

### B — Saturating/empty-slice semantics, keep `-> &[u8]` (rejected)

`checked_add(...).and_then(get).unwrap_or(&[])` — exactly what goblin's
`FatArch::slice` ships (`github.com/m4b/goblin`, `src/mach/fat.rs:90-105`), whose
in-source `FIXME` says a `Result` would be preferable.

- Attractive: non-breaking, never panics.
- Rejected because a signing tool must not turn a forged/aliased slice into an
  empty byte range: `sign_slice_complete` and friends size signatures from
  `slice_data.len()` (`signer.rs:530`), so an empty result silently changes
  arithmetic instead of failing. A typed error is the honest outcome on this path.
  RFC 1105 leaves panic→`Err` behavior unspecified, so the behavior change alone
  would be defensible; the signature change (the real cost) is the same for
  `Option`-shaped variants anyway.

### C — API narrowing: private fields + validated construction (rejected)

Making `ArchSlice` fields private (Rust API guidelines C-STRUCT-PRIVATE,
<https://rust-lang.github.io/api-guidelines/future-proofing.html#c-struct-private>)
would enforce invariants structurally.

- Rejected as disproportionate: it forces changes through `parser.rs:219-220`,
  `signer.rs:498, 632`, `verify.rs`, `ipa/mod.rs`, and the facade — directly
  colliding with later parser.rs work queued this session, and still not tying a
  slice to *its* file (aliasing across files would need a lifetime parameter, a
  redesign). The per-call check in the accessors is where the buffer is known.

Returning `Option<&[u8]>` instead of `Result` was folded into B and rejected for
the same reason: it discards the diagnostic message the module's error style
carries everywhere else.

## Decision

Change both accessors to:

```rust
pub fn code_bytes(&self, slice: &ArchSlice) -> crate::Result<&[u8]> { … }
pub fn slice_data(&self, slice: &ArchSlice) -> crate::Result<&[u8]> { … }
```

Body shape (two steps, mirroring `parser.rs:201-211`):

```rust
let end = slice.offset.checked_add(slice.size).ok_or_else(|| /* "… overflows" */)?;
self.data.get(slice.offset..end).ok_or_else(|| /* "… exceeds file …" */)
```

- One error channel: existing `Error::MachO(String)` — no new variant.
- Two messages, matching nearby wording: overflow reports
  `offset + length overflows`; out-of-range reports the requested range against
  `self.data.len()`.
- Facade wrappers mirror the signature and convert via the existing
  `From<zsign_core::Error>` (`crates/zsign/src/error.rs`), so core `MachO(..)`
  surfaces as `Error::Core(..)`.
- Accessor doc comments gain the `# Errors` conditions; valid-input behavior and
  every existing assertion stay byte-identical.
- Boundary kept valid: `offset == data.len()` with length `0` returns `Ok(&[])`
  (`data.get(len..len)` is `Some`) — an empty range at the end is in bounds.

## Non-goals

- FAT parse-validation bounds, duplicate load commands, FAT endianness handling,
  code-length unification, `SlotEntry` payload checks — separate work; this change
  touches only the two accessor bodies, their signatures/docs, and their callers.
- No new error variant, no new dependency, no changes in `zsign-cli`,
  `zsign-wasm`, `fuzz`, `verify.rs`, or `writer.rs` logic.
- The zero-architecture FAT guard recently added at parse time is untouched.
