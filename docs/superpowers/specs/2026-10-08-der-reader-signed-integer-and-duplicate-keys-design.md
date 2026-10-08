# DER entitlement reader: signed-integer decode + duplicate-key rejection — design

Date: 2026-10-08
Status: drafted for cold review
Sole file in scope: `crates/zsign-core/src/codesign/verify.rs`
Reference only (never edited): `crates/zsign-core/src/codesign/der.rs` (the writer)

## Goal

Two independent defects in the DER entitlement reader, fixed in one bundle:

1. Every negative DER INTEGER decodes to the wrong value or is rejected, even
   though the repo's own writer emits exactly those byte strings.
2. A duplicated key inside a DER entries dictionary silently collapses
   last-wins, creating a parser-divergence surface on a security-decision
   input.

## Defect 1 — negative INTEGER sign extension (verified at d087c9d)

- `der_integer` lives at `verify.rs:1081-1104`. The negative seed
  `-1i128 << (8 * content.len())` (`verify.rs:1095`) already places the sign
  correction at magnitude 2^(8·len), then the Horner loop
  (`verify.rs:1098-1100`) shifts the accumulator left 8 bits once per content
  byte. The result is N − 2^(16·len) instead of N − 2^(8·len).
- Traced outcomes of today's code: content `[0x80]` → −65408 (correct −128);
  `[0xFF]` → −65281 (correct −1); `[0x80,0x00,0x00,0x00]` (−2^31) →
  "DER INTEGER does not fit i64" rejection; positives are unaffected.
- Sole caller: `decode_der_value` tag arm `0x02` (`verify.rs:1226`), reached
  from `der_entitlements_to_plist` (`verify.rs:1257`), invoked by
  `crates/zsign-core/src/macho/verify.rs:261` on the
  CSSLOT_DER_ENTITLEMENTS payload.
- The writer (`der.rs:211-262`) emits canonical minimal two's-complement and
  pins four encodings at `der.rs:700-728`: −1 → `02 01 FF`, −128 → `02 01 80`,
  −129 → `02 02 FF 7F`, i64::MIN → `02 08 80 00×7`, plus zero `02 01 00`
  (`der.rs:722-728`); i64::MAX traces to `02 09 00 FF×8` (sign pad + 8
  value octets). The reader must read every one of these.
- Secondary defect the required round-trip table exposes: the size guard
  `content.len() > 8` (`verify.rs:1092`) rejects i64::MAX outright — its
  canonical content is 9 octets. The guard's ceiling, not the sign logic, is
  what blocks that round-trip.

### External contract (verified: ITU-T X.690 02/2021, §8.3)

- 8.3.1: content octets primitive, one or more octets.
- 8.3.2: if more than one content octet, the bits of the first octet together
  with bit 8 of the second must not be all zeros nor all ones — the
  minimal-length rule.
- 8.3.3: content octets are two's-complement; the MSB of the first octet
  carries weight −2^(8n−1) for an n-octet content.
- Correct decode: seed the signed value from the FIRST octet alone
  (`first − 256` when its MSB is set, else `first`), then Horner-fold the
  remaining octets: `value = value·256 + b`. The seed must not be pre-shifted.

## Defect 2 — duplicate keys collapse last-wins (verified at d087c9d)

- `decode_der_entries` at `verify.rs:1177`; the bare
  `dictionary.insert(key, …)` at `verify.rs:1199`. plist is locked at 1.10.1;
  `Dictionary::insert` returns `Option<Value>` (the displaced old value) and
  the return is dropped, so a repeated key silently overwrites.
- Caller chain: `der_entitlements_to_plist` (`verify.rs:1257`), the `0x70`
  envelope arm (`verify.rs:1249`), and the `0x31|0x60|0xa0|0xb0` container arm
  (`verify.rs:1251`) — nested dictionaries share the same path. The consumer
  is `macho/verify.rs:261`, which compares decoded DER entitlements against
  XML entitlements (`macho/verify.rs:264`); on error it pushes a report string
  (`macho/verify.rs:271-273`).
- No existing test exercises a duplicate key anywhere in verify.rs.

### External-contract correction (verified: X.690 02/2021, X.680 02/2021)

An earlier statement of this work cited "X.690 11.6 requires distinct
components". Verification shows that citation is wrong:

- X.690 §11.6 ("Set-of components") is an ORDERING rule only: SET OF
  encodings appear in ascending octet-string order. It says nothing about
  distinctness.
- X.680 §28.3 NOTE 3 explicitly negates the reading: "The set-of type is not
  a mathematical set of values, thus, as an example, for SET OF INTEGER the
  values { 1 } and { 1 1 } are distinct." Repeated SET OF elements are legal
  abstract values.
- OpenSSL (`crypto/asn1/tasn_dec.c`) and RustCrypto `der` (`set_of.rs`
  `from_bytes`: decodes elements in a loop, checks only ordering) both ACCEPT
  duplicate SET OF elements; neither has a duplicate check.

Consequence for the design: duplicate-key rejection is **not** standards
conformance and the doc/comment/test must never claim it is. It is deliberate
strictness of this entitlement parser, justified by:

- Apple's encoder emits dictionary keys uniquely; a duplicate can only arrive
  in a crafted blob.
- The parse feeds a security decision (entitlement comparison at
  `macho/verify.rs:264`). Last-wins vs first-wins vs reject is exactly the
  consumer-divergence class behind the CVE-2021-30807 lineage: rejecting the
  ambiguous input removes the divergence instead of picking a side.
- It matches the strictness already in this reader: minimal-length INTEGER
  (`verify.rs:1091-1092`), depth cap 32 (`verify.rs:1178-1180`), trailing-bytes
  rejection (`verify.rs:1205-1212`).

## Design decisions

### D1 — signed first-octet seed, Horner over the tail (chosen)

```rust
let mut value = if negative {
    first as i128 - 256
} else {
    first as i128
};
for &byte in prefix {
    value = (value << 8) | byte as i128;
}
```

- Candidates considered:
  - **A (chosen):** signed seed from the first octet, fold `prefix` only.
    Smallest possible diff, exactly the §8.3.3 weight reading, zero
    allocation, and the accumulator stays below 2^72 in magnitude for the
    whole i64 range — no i128 overflow possible.
  - **B:** fold unsigned, then subtract `1i128 << (8 * len)` once at the end.
    Correct but two-step sign handling; no benefit over A.
  - **C:** widen the content into a 16-byte buffer and use
    `i128::from_be_bytes` with a shift. Needs a stack buffer and more shift
    arithmetic; strictly more room for error.
- The minimality pre-check (`verify.rs:1086-1093`) and the
  `i64::try_from` final conversion (`verify.rs:1102`) stay as they are; both
  remain correct against the new accumulator.

### D2 — raise the size guard from 8 to 9 content octets

- `content.len() > 8` becomes `content.len() > 9`. i64's widest canonical
  DER INTEGER is 9 octets (00 sign pad + 8 value octets); the mandated
  round-trip table includes i64::MAX, which is impossible under a ceiling of
  8. A minimal 10-octet encoding cannot fit i64, and `i64::try_from` still
  rejects anything outside the range, so behavior for genuinely oversized
  input is unchanged ("non-minimal or oversized DER INTEGER").
- Rejected: keeping 8 — fails the required i64::MAX round-trip. Rejected:
  dropping the guard — unbounded content would let the Horner fold leave the
  i128 range.

### D3 — duplicate detection via the `insert` return value

```rust
if dictionary
    .insert(key, decode_der_value(value_tag, value_bytes, depth + 1)?)
    .is_some()
{
    return Err(der_error(format!(
        "DER entitlement entry has duplicate key '{key}'"
    )));
}
```

- Candidates considered:
  - **A (chosen):** check `insert`'s `Option` return — one pass, no double
    lookup, uses the API exactly as designed for this. The value is decoded as
    the argument, so a duplicate *inside a nested* dictionary errors first;
    either way the parse fails, only the message differs, which is fine.
  - **B:** `contains_key` pre-check then insert — two hash lookups per entry
    and a TOCTOU-shaped two-step for no gain.
  - **C:** collect into a side `BTreeSet` — a second data structure for a
    property `insert` already reports; rejected as needless.
- Error phrasing follows the file's existing `DER entitlement entry …` family
  (`verify.rs:1186, 1190, 1197`) and includes the offending key, matching the
  file's precedent of interpolating the offending token
  (`verify.rs:1131, 1253`). The message contains the literal substring
  `duplicate key`, which the regression test pins.

## Test strategy

1. **Signed round-trip table** (new test `der_integers_round_trip_signed_extremes`,
   beside `der_entitlements_round_trip` at `verify.rs:1668`): for each of
   −1, −128, −129, −2147483648 (−2^31), i64::MIN, i64::MAX, 0, build the
   single-entry XML dict, encode with `crate::codesign::der::plist_to_der`
   (the writer), decode with `der_entitlements_to_plist`, and assert the
   decoded integer equals the input, with the value in the assertion message.
   Fails before the fix for −1, −128, −129, −2^31, i64::MIN (wrong value or
   rejection) and i64::MAX (size-guard rejection); 0 is the in-test control
   that already passes. This is writer→reader, so the writer octets pinned at
   `der.rs:700-728` and the reader are exercised end to end.
2. **Duplicate-key regression** (new test `der_entries_reject_duplicate_keys`):
   hand-built two-entry SET — distinct keys parse (control asserting both
   keys present), then the same shape with the key repeated must be
   `Err(Error::DerEncoding)` whose message contains `duplicate key`, using the
   crate's dominant footer
   `assert!(matches!(…), "…, got {:?}", res.as_ref().err())` pattern.

## Non-goals / out of scope (deliberate, per the lane brief)

- **Minimality laxness (BER-lax family, other ticket):** the existing check
  `prefix.len() - significant > 1` accepts one extra leading 0x00
  (e.g. content `00 00 FF FF FF FF FF FF` decodes as 2^48−1 today). This is
  pre-existing for ≤8-octet inputs and this work neither fixes nor deepens it
  deliberately; raising the size ceiling to 9 extends the same pre-existing
  window to 9-octet inputs (`00 00` + 7 octets, values ≤ 2^56−1). Recorded
  here so the minimality ticket can pick it up; fixing it would put a second
  convention beside §8.3.2 and is out of this queue item's ownership.
- No changes to the writer (`der.rs`), to `macho/verify.rs`, to the facade or
  CLI, and no new DER tags, containers, or depth rules.
- Rejecting duplicate keys does NOT implement any broader requirement-blob
  opcode enforcement; that is a different ticket's ownership.
