# Reject Stale Data Past the Declared SuperBlob Length — Design

## Problem

`verify_slice` (`crates/zsign-core/src/macho/verify.rs`, fn at :127) extracts
the whole `LC_CODE_SIGNATURE` window (`sig = data[sig_file_off..+sig_size]`,
:150-155) and hands it to `parse_superblob` (:157-165). It never compares the
SuperBlob's *declared* length (header field at bytes 4..8) against the window
size.

`parse_superblob` (`crates/zsign-core/src/codesign/verify.rs:87+`) bounds every
read to `blob[..declared]` and tolerates trailing bytes *by design* (comment at
:104-109: the own writer reserves the LC window larger than the SuperBlob).
That tolerance is correct for a parser, but it means any data after the first
SuperBlob inside the reserved window — including a complete planted second
signature smuggled into a re-signed bundle — is invisible to `-V`. The binary
"verifies clean" today.

## External contract (Apple semantics)

Verified against Apple open-source (apple-oss-distributions `Security` and
`xnu`), because no Apple document specifies these semantics; they live in code:

- SuperBlob header: `magic, length /* total length of SuperBlob */, count` —
  `osfmk/kern/cs_blobs.h`, `OSX/libsecurity_codesigning/lib/cscdefs.h`.
  "Declared length" is the self-inclusive byte count of the whole SuperBlob.
- Userspace verifier: `MachORep::signingData()`
  (`libsecurity_codesigning/lib/machorep.cpp:327-343`) passes `datasize` only
  as `maxSize` to `readBlob`, which allocates `header.length()` bytes. Bytes
  between declared length and `datasize` are never read.
- Kernel: `cs_validate_csblob` (`bsd/kern/ubc_subr.c:503+`) first requires
  declared ≤ window (`cs_validate_blob`: `length < ntohl(blob->length)` →
  `EBADEXEC`), then rebinds `length = ntohl(blob->length)` and uses the
  *declared* length for every subsequent check. The remainder of the window is
  treated as empty — not as an error, and not as signature data.
- Equality (`blob->length() == signatureLength`) is enforced by Apple only for
  disk-image formats (`encdiskimagerep.cpp`, `diskimagerep.cpp`), never for
  Mach-O.

Conclusion: the declared length is authoritative; the remainder of the window
belongs to nothing. A *nonzero* remainder contradicts the empty-remainder model
and is exactly the carrier for a planted second SuperBlob.

## Repository facts (verified against current source)

- Failure idiom: `verify_slice` accumulates `report.errors: Vec<String>`;
  `SliceVerifyReport::is_valid()` is `errors.is_empty()` (:62-64); warnings do
  not invalidate (pinned by the test at :1586-1590).
- `-V` path: slice errors make the report invalid → CLI exit 1 ("invalid");
  only top-level report errors exit 2. Adding a slice error does not change
  any exit-code contract or any wasm `error.code` (wasm has no verify API;
  `Error::Verification` maps to `ZSIGN_VERIFICATION` regardless of message).
- The own writer legitimately produces `datasize > declared`:
  `datasize` is set to a *reserve* (`writer.rs:1630-1652`,
  `signer.rs:791-818`), re-signing keeps `max(original, estimated)`
  (`signer.rs:530-535`), and the tail is zero-filled
  (`writer.rs:1642-1643` truncate + zero resize, `signer.rs:785-787`).
  Our own output therefore always carries an all-zero tail of arbitrary length.
- In-process sign→verify round-trip tests (e.g. `verify_signed_binary_round_trip`
  :949, bare ad-hoc validity at :1390-1393, FAT round-trip :1018) are the
  regression net for false positives.

## Decision

In `verify_slice`, immediately after `parse_superblob` succeeds and before the
primary-CodeDirectory check:

1. Read `declared = u32::from_be_bytes(sig[4..8])` — safe because
   `parse_superblob` already validated `sig.len() >= 12` and
   `declared <= sig.len()`.
2. Count nonzero bytes in `sig[declared..]`.
3. If the count `n > 0`, push
   `format!("code signature window contains {n} nonzero bytes past the declared SuperBlob length")`
   into `report.errors` and continue with the remaining checks.

**Error, not warning.** A warning leaves `is_valid()` true and `-V` exits 0 —
that is precisely the "verifies clean" bug being fixed. Foreign data in the
signature window is a verification failure, not a note.

**Predicate: any nonzero byte past `declared`.** Apple's model makes the
remainder empty; zero is the only benign filler (own writer, and Apple's
unverified-but-unread slack). This accepts `declared == window` (empty tail) and
any-length zero tail, and rejects a planted SuperBlob, stale partial data, or
any stray byte.

**Placement: `verify_slice` only; `parse_superblob` unchanged.** Its
by-design tolerance serves non-verification callers (builder post-sign checks,
ipa, wasm) and its contract is documented; the policy belongs to the verifier.

## Rejected alternatives

- **Exact fit (`declared == window`):** matches Apple's disk-image strictness
  but rejects our own writer's reserve (`datasize > declared` by design) and
  likely Apple-signed binaries → false positives on verify-after-sign.
- **Tail magic sniffing (reject only `0xfade0cc0` etc.):** narrow whack-a-mole;
  stale non-magic data stays invisible. "Empty remainder" is the invariant.
- **Warning instead of error:** does not invalidate; fails the goal.
- **Tightening `parse_superblob`:** changes a documented by-design contract
  shared by signing-side callers; the verifier is the correct policy layer.

## Assumptions and accepted risk

A third-party signer that pads the window with *nonzero* bytes would be
rejected. Accepted: such bytes have no legitimate source under Apple's model,
and neither zsign nor Apple produces them. Claim about real `codesign --verify`
runtime behavior on a mutated binary is source-derived, not observed (no macOS
host); the design relies on the documented kernel/userspace source semantics.

## Scope boundaries

- No changes to codeLimit/dataoff tying, coverage checks, or CodeDirectory
  field validation — other work owns those regions.
- No writer, parser, CLI, wasm, or bundle changes; no new dependencies.
- Fuzz target `verify_code_signature` feeds arbitrary bytes to `verify_macho`:
  the new check must index only within `parse_superblob`-validated bounds
  (no panics).

## Acceptance criteria

1. A fixture whose LC window carries a complete second SuperBlob past the
   declared length verifies **invalid**, with exactly one slice error matching
   `nonzero bytes past the declared SuperBlob length`.
2. A single stray nonzero byte past the declared length is likewise rejected.
3. An all-zero tail of any length (own writer output) and an exact-fit window
   (`declared == datasize`) still verify valid; existing sign→verify
   round-trips stay green.
