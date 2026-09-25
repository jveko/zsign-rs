# ZSN-38 Canonical DER Entitlements Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development
> with dispatching-parallel-agents for independent tasks to implement this plan
> task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
> The scope queue is strictly ordered: Task N's commit must be green before
> Task N+1 starts. Tasks share `der.rs`, so they are never parallel.

**Goal:** Make `plist_to_der` emit Apple-canonical V1 DER entitlements (0xb0
nested dictionaries, sorted SET members, Data/Date values, explicit integer
range errors) with golden vectors, and give the macOS interop script a real
slot -7 round-trip against Apple's own tools plus the end-entity certificate
flip.

**Architecture:** All encoding lives in
`crates/zsign-core/src/codesign/der.rs`; a new shared `encode_dictionary`
helper replaces the duplicated root/nested pair-building loops and performs the
X.690 §11.6 member sort. The single production caller
(`macho/signer.rs:88`) keeps its signature — no caller migration. The script
adds one self-contained step between its signing and structural-assert phases.

**Tech Stack:** Rust (plist 1.10.1, no new dependencies), bash + python3 +
openssl/codesign (macOS only).

**Gate (run before every commit):**

```bash
mkdir -p .tmptmp && TMPDIR=$PWD/.tmptmp cargo test -p zsign-core der -- --skip test_ipa_signing_is_deterministic
```

Expected: `0 failed` every time; baseline at c9ff0fb was `26 passed` unit +
`2 passed` doctests. Each task's new tests increase the unit count as noted.
Do NOT run `cargo fmt`, `cargo clippy`, or `hk` (orchestrator gates at merge);
the pre-commit hook runs automatically.

## Brief item-4 golden-vector coverage map

Every vector the brief lists lands exactly once, attached to the task that owns
the behavior:

| Brief item-4 vector | Task | Test name |
|---|---|---|
| nested dict (`0xb0`) | Task 1 (item 1) | `test_plist_to_der_nested_dictionary` |
| Data/Date values (TLV) | Task 2 (item 2) | `test_encode_data`, `test_encode_date`, `test_encode_date_fraction` |
| multi-key dict (ordering) | Task 3 (item 3) | `test_plist_to_der_sorts_set_members` |
| out-of-i64 integer edge | Task 4 (item 4) | `test_plist_to_der_rejects_out_of_i64_integer` |
| array values | Task 4 (item 4) | `test_plist_to_der_array_values` |
| >127-byte SET (long form) | Task 4 (item 4) | `test_plist_to_der_long_form_lengths` |
| Data/Date inside envelope | Task 4 (item 4) | `test_plist_to_der_data_and_date_in_envelope` |
| cross-check vs `codesign --generate-entitlement-der` | Task 5 (item 5) | script entitlements step (macOS) |

Negative-integer vectors landed under the supervisor's option-B ruling:
`test_encode_integer_negative_minimal` pins `-1 → 02 01 ff`,
`-128 → 02 01 80`, `-129 → 02 02 ff 7f`, `i64::MIN → 02 08 80 00…00`
(design doc item 4 records the question and the ruling).

---

### Task 1: Nested dictionaries encode as [16] 0xb0 (brief item 1)

**Files:**
- Modify: `crates/zsign-core/src/codesign/der.rs` (constants `:55-56`,
  `encode_value` Dictionary arm `:148-175`, `encode_value` doc list `:79-86`)

- [ ] **Step 1.1: Write the failing test** (append to the existing
  `#[cfg(test)] mod tests` in der.rs)

```rust
    #[test]
    fn test_plist_to_der_nested_dictionary() {
        let xml = br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>outer</key>
    <dict>
        <key>k</key>
        <true/>
    </dict>
</dict>
</plist>"#;

        let der = plist_to_der(xml).unwrap();
        // 70 18 | 02 01 01 | b0 13 | 30 11 0c 05 "outer" b0 08 30 06 0c 01 "k" 01 01 ff
        // nested dictionary must be [16] 0xb0, never universal SET 0x31.
        assert_eq!(
            der,
            vec![
                0x70, 0x18, 0x02, 0x01, 0x01, 0xb0, 0x13, 0x30, 0x11, 0x0c, 0x05, b'o', b'u',
                b't', b'e', b'r', 0xb0, 0x08, 0x30, 0x06, 0x0c, 0x01, b'k', 0x01, 0x01, 0xff,
            ]
        );
    }
```

- [ ] **Step 1.2: Run and confirm it fails**

```bash
TMPDIR=$PWD/.tmptmp cargo test -p zsign-core der -- --skip test_ipa_signing_is_deterministic
```

Expected: FAIL `test_plist_to_der_nested_dictionary` — actual bytes contain
`0x31, 0x08` where the vector has `0xb0, 0x08`. Everything else still passes.

- [ ] **Step 1.3: Implement.** In `encode_value`'s `Value::Dictionary(dict)`
  arm, replace

```rust
            output.push(DER_TAG_SET);
```

with

```rust
            output.push(0xb0); // [16] IMPLICIT SET (constructed)
```

Then delete the now-unused constant and its doc comment (dead code rule):

```rust
/// DER tag for SET (used for dictionaries).
const DER_TAG_SET: u8 = 0x31;
```

Update the `encode_value` doc list line

```rust
/// - Dictionary -> SET of key-value pairs
```

to

```rust
/// - Dictionary -> [16] (0xb0) IMPLICIT SET OF key-value pairs
```

- [ ] **Step 1.4: Run the gate.** Expected: `27 passed` unit (baseline 26 + 1
  new), `0 failed`. Note: this filtered command reports no doctest section —
  doctests run separately (`cargo test -p zsign-core --doc` → 26 passed) and
  are not part of the mid-flight gate.

- [ ] **Step 1.5: Commit**

```bash
git add crates/zsign-core/src/codesign/der.rs
git commit -m "fix(codesign): encode nested entitlement dictionaries as 0xb0 (ZSN-38)"
```

---

### Task 2: Data and Date value types (brief item 2)

**Files:**
- Modify: `crates/zsign-core/src/codesign/der.rs` (constants block, `encode_value`
  Data/Date arms `:176-181`, doc lists, `plist_to_der` `# Errors` section, test
  `test_plist_to_der_unsupported_data_type` `:373-384`)

- [ ] **Step 2.1: Write the failing tests** (append to `mod tests`)

```rust
    #[test]
    fn test_encode_data() {
        let value = Value::Data(vec![0x01, 0x02, 0x03]);
        let der = encode_value(&value).unwrap();
        assert_eq!(der, vec![0x04, 0x03, 0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_encode_date() {
        let date = plist::Date::from_xml_format("1981-05-16T11:32:06Z").unwrap();
        let der = encode_value(&Value::Date(date)).unwrap();
        // GeneralizedTime (X.690 11.7): YYYYMMDDHHMMSSZ, seconds precision, UTC.
        assert_eq!(
            der,
            vec![
                0x18, 0x0f, b'1', b'9', b'8', b'1', b'0', b'5', b'1', b'6', b'1', b'1', b'3',
                b'2', b'0', b'6', b'Z',
            ]
        );
    }

    #[test]
    fn test_encode_date_fraction() {
        let date = plist::Date::from_xml_format("1992-07-22T13:21:00.3Z").unwrap();
        let der = encode_value(&Value::Date(date)).unwrap();
        // Nonzero fraction kept, trailing zeros stripped (X.690 11.7.3).
        assert_eq!(
            der,
            vec![
                0x18, 0x11, b'1', b'9', b'9', b'2', b'0', b'7', b'2', b'2', b'1', b'3', b'2',
                b'1', b'0', b'0', b'.', b'3', b'Z',
            ]
        );
    }
```

- [ ] **Step 2.2: Run and confirm they fail** with the gate command. Expected:
  FAIL all three (`Unsupported plist type: Data` / `Date` errors on unwrap).

- [ ] **Step 2.3: Implement.** In `der.rs`:

1. Add imports at the top (std group, before `use plist::Value;`):

```rust
use std::time::{SystemTime, UNIX_EPOCH};
```

2. Add two constants after `DER_TAG_UTF8STRING`:

```rust
/// DER tag for OCTET STRING (used for Data).
const DER_TAG_OCTETSTRING: u8 = 0x04;

/// DER tag for GeneralizedTime (used for Date).
const DER_TAG_GENERALIZEDTIME: u8 = 0x18;
```

3. Replace the `Value::Data(_)` rejection arm with

```rust
        Value::Data(bytes) => {
            output.push(DER_TAG_OCTETSTRING);
            encode_length(&mut output, bytes.len());
            output.extend(bytes);
        }
```

4. Replace the `Value::Date(_)` rejection arm with

```rust
        Value::Date(date) => {
            let text = generalized_time(*date)?;
            output.push(DER_TAG_GENERALIZEDTIME);
            encode_length(&mut output, text.len());
            output.extend(text.as_bytes());
        }
```

5. Add the two helpers above `encode_value`:

```rust
/// Convert a plist date to a DER GeneralizedTime value (X.690 clause 11.7).
///
/// Output is `YYYYMMDDHHMMSSZ` in UTC; a fractional part is appended only when
/// the value carries subsecond precision, with trailing zeros stripped so the
/// encoding stays canonical. Years outside 0..=9999 are rejected.
fn generalized_time(date: plist::Date) -> Result<String> {
    let (secs, nanos) = match SystemTime::from(date).duration_since(UNIX_EPOCH) {
        Ok(d) => (d.as_secs() as i64, d.subsec_nanos()),
        Err(e) => {
            let d = e.duration();
            let secs = d.as_secs() as i64;
            if d.subsec_nanos() == 0 {
                (-secs, 0)
            } else {
                (-secs - 1, 1_000_000_000 - d.subsec_nanos())
            }
        }
    };
    let days = secs.div_euclid(86_400);
    let secs_of_day = secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    if !(0..=9999).contains(&year) {
        return Err(Error::DerEncoding(format!(
            "date value {}s from the Unix epoch is outside the GeneralizedTime year range",
            secs
        )));
    }
    let mut out = format!(
        "{:04}{:02}{:02}{:02}{:02}{:02}Z",
        year,
        month,
        day,
        secs_of_day / 3600,
        (secs_of_day % 3600) / 60,
        secs_of_day % 60
    );
    if nanos != 0 {
        let mut frac = format!("{:09}", nanos);
        while frac.ends_with('0') {
            frac.pop();
        }
        out.insert_str(out.len() - 1, &format!(".{}", frac));
    }
    Ok(out)
}

/// Convert days since the Unix epoch to a (year, month, day) civil date —
/// the inverse of Howard Hinnant's days-from-civil algorithm.
fn civil_from_days(z: i64) -> (i64, i32, i32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { yoe + era * 400 + 1 } else { yoe + era * 400 }, m as i32, d as i32)
}
```

6. Update the `encode_value` doc list — replace

```rust
/// - Dictionary -> [16] (0xb0) IMPLICIT SET OF key-value pairs
```

(now positioned after Task 1's edit) with the same line plus:

```rust
/// - Data -> OCTET STRING
/// - Date -> GeneralizedTime
```

7. In `plist_to_der`'s `# Errors` section replace

```rust
/// - An unsupported plist type is encountered (Data, Date, Real)
```

with

```rust
/// - An unsupported plist type is encountered (Real)
```

- [ ] **Step 2.4: Conscious test adjustment (report this).** Replace
  `test_plist_to_der_unsupported_data_type` (`der.rs:373-384`) — it pinned the
  pre-fix rejection of `<data>` — with the Real equivalent so rejection coverage
  survives:

```rust
    #[test]
    fn test_plist_to_der_unsupported_real_type() {
        let xml = br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>test-real</key>
    <real>1.5</real>
</dict>
</plist>"#;
        let result = plist_to_der(xml);
        assert!(result.is_err());
    }
```

- [ ] **Step 2.5: Run the gate.** Expected: `30 passed` unit (27 + 3 new; the
  renamed test is net-zero against its predecessor), `0 failed`.

- [ ] **Step 2.6: Commit**

```bash
git add crates/zsign-core/src/codesign/der.rs
git commit -m "feat(codesign): encode plist data and date entitlement values (ZSN-38)"
```

---

### Task 3: Canonical SET member ordering via shared helper (brief item 3)

**Files:**
- Modify: `crates/zsign-core/src/codesign/der.rs` (module doc `:16-19`,
  `encode_value` Dictionary arm `:148-175`, `plist_to_der` root loop `:235-256`
  and its comment, tests)

- [ ] **Step 3.1: Write the failing test** (append to `mod tests`)

```rust
    #[test]
    fn test_plist_to_der_sorts_set_members() {
        let xml = br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>aa</key>
    <true/>
    <key>b</key>
    <true/>
</dict>
</plist>"#;

        let der = plist_to_der(xml).unwrap();
        // Members are ordered by their complete encodings compared as octet
        // strings (X.690 11.6): pair "b" is 30 06 ..., pair "aa" is 30 07 ...,
        // so "b" sorts first even though the document/key order says otherwise.
        assert_eq!(
            der,
            vec![
                0x70, 0x16, 0x02, 0x01, 0x01, 0xb0, 0x11, 0x30, 0x06, 0x0c, 0x01, b'b', 0x01,
                0x01, 0xff, 0x30, 0x07, 0x0c, 0x02, b'a', b'a', 0x01, 0x01, 0xff,
            ]
        );

        // Encoding is independent of the document order of the same dict.
        let flipped = br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>b</key>
    <true/>
    <key>aa</key>
    <true/>
</dict>
</plist>"#;
        assert_eq!(plist_to_der(flipped).unwrap(), der);
    }
```

- [ ] **Step 3.2: Run and confirm it fails** with the gate command. Expected:
  FAIL `test_plist_to_der_sorts_set_members` — current encoder emits document
  order (`aa` pair first).

- [ ] **Step 3.3: Implement — shared dictionary encoder.** Add this helper to
  der.rs (above `encode_value`):

```rust
/// Encode a dictionary as its canonical entries container:
/// [16] (0xb0) IMPLICIT SET OF `SEQUENCE { UTF8String key, value }`.
///
/// Members are sorted by their complete encoded bytes before the container
/// length is computed — the DER SET OF ordering rule of X.690 clause 11.6
/// (encodings compared as octet strings; the standard's virtual trailing-zero
/// padding is equivalent to plain byte order for complete DER encodings).
fn encode_dictionary(dict: &plist::Dictionary) -> Result<Vec<u8>> {
    let mut members = Vec::with_capacity(dict.len());
    for (key, val) in dict {
        let encoded_val = encode_value(val)?;

        let mut key_encoded = Vec::new();
        key_encoded.push(DER_TAG_UTF8STRING);
        encode_length(&mut key_encoded, key.len());
        key_encoded.extend(key.as_bytes());

        let pair_len = key_encoded.len() + encoded_val.len();
        let mut pair = Vec::with_capacity(pair_len + 4);
        pair.push(DER_TAG_SEQUENCE);
        encode_length(&mut pair, pair_len);
        pair.extend_from_slice(&key_encoded);
        pair.extend_from_slice(&encoded_val);
        members.push(pair);
    }
    members.sort();

    let content_len: usize = members.iter().map(|m| m.len()).sum();
    let mut output = Vec::with_capacity(content_len + 4);
    output.push(0xb0); // [16] IMPLICIT SET (constructed)
    encode_length(&mut output, content_len);
    for member in &members {
        output.extend_from_slice(member);
    }
    Ok(output)
}
```

Then replace the whole body of `encode_value`'s `Value::Dictionary(dict)` arm
with (statement-style match: arms are unit-typed, and `encode_dictionary`
already returns `Result<Vec<u8>>` — exactly `encode_value`'s return type — so
return it directly; no `?`, no copying):

```rust
        Value::Dictionary(dict) => return encode_dictionary(dict),
```

Then replace, in `plist_to_der`, the whole span from the current `:235`
comment (`// Entitlements root must be a dictionary; encode its sorted key/value`)
through the end of the `entries` build (current `:266`, the
`entries.extend_from_slice(&pairs);` line) — that removes the `pairs` vector,
its loop, and the hand-built `entries` vector in one cut — with:

```rust
    // Entitlements root must be a dictionary; encode it as the canonical
    // [16] entries container (members sorted by encoded bytes).
    let dict = value
        .as_dictionary()
        .ok_or_else(|| Error::DerEncoding("Entitlements plist root must be a dictionary".into()))?;
    let entries = encode_dictionary(dict)?;

    // Apple canonical envelope (matches `codesign --generate-entitlement-der`):
    //   [APPLICATION 16] (0x70) IMPLICIT SEQUENCE {
    //       version  INTEGER (1),
    //       entries  [16] (0xB0) IMPLICIT SET OF Entitlement
    //   }
```

The existing `seq_content`/`der` assembly that follows stays untouched — it
already does `seq_content.extend_from_slice(&entries);` on the full 0xb0 TLV.

- [ ] **Step 3.4: Make the docs true.** In the module doc replace

```rust
//! Keys are sorted lexicographically and `BOOLEAN true` is encoded as `0xFF`
//! (DER canonical). This is the format Apple's `codesign --generate-entitlement-der`
//! emits; non-canonical variants (bare SETs, `BOOLEAN true = 0x01`) are rejected
//! by modern macOS verification and iOS 15+ installs.
```

with

```rust
//! Dictionary entries are ordered by their complete member encodings compared
//! as octet strings (DER SET OF rule, X.690 clause 11.6) and `BOOLEAN true` is
//! encoded as `0xFF` (DER canonical). This is the format Apple's
//! `codesign --generate-entitlement-der` emits; non-canonical variants
//! (unordered entries, bare SETs, `BOOLEAN true = 0x01`) are rejected by modern
//! macOS verification and iOS 15+ installs.
```

- [ ] **Step 3.5: Run the gate.** Expected: `31 passed` unit (30 + 1), `0
  failed`. If `test_plist_to_der_simple`/`test_plist_to_der_empty` fail, the
  envelope assembly regressed — re-read Step 3.3; their vectors are
  order-insensitive (≤1 key) and must stay green.

- [ ] **Step 3.6: Commit**

```bash
git add crates/zsign-core/src/codesign/der.rs
git commit -m "fix(codesign): sort der entitlement set members canonically (ZSN-38)"
```

---

### Task 4: Remaining golden vectors + explicit integer range error (brief item 4)

**Files:**
- Modify: `crates/zsign-core/src/codesign/der.rs` (`encode_value` Integer arm
  `:98-99`, `plist_to_der` `# Errors` doc, tests)

- [ ] **Step 4.1: Write the failing integer test first** (append to `mod tests`;
  the three golden vectors follow in Step 4.6)

```rust
    #[test]
    fn test_plist_to_der_rejects_out_of_i64_integer() {
        let xml = br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>huge</key>
    <integer>18446744073709551615</integer>
</dict>
</plist>"#;
        let err = plist_to_der(xml).unwrap_err();
        match err {
            Error::DerEncoding(msg) => {
                assert!(msg.contains("18446744073709551615"), "message: {msg}")
            }
            other => panic!("unexpected error variant: {other}"),
        }
    }
```

- [ ] **Step 4.2: Run and confirm the failure.** Expected: FAIL
  `test_plist_to_der_rejects_out_of_i64_integer` — current code returns `Ok`
  with a silent zero, so `unwrap_err` panics.

- [ ] **Step 4.3: Implement the integer range error.** In `encode_value`'s
  `Value::Integer(i)` arm, replace

```rust
            let val = i.as_signed().unwrap_or(0) as u64;
```

with

```rust
            let val = match i.as_signed() {
                Some(v) => v as u64,
                None => {
                    return Err(Error::DerEncoding(format!(
                        "integer value {} is outside the i64 range",
                        i
                    )));
                }
            };
```

(`plist::Integer` implements `Display` over its i128 storage, so the value is
always rendered; `as_signed()` is `None` exactly when the value exceeds i64 —
plist parses u64-range XML integers.)

- [ ] **Step 4.4: Update `plist_to_der`'s `# Errors` doc.** After the Real
  line (Task 2's edit), add:

```rust
/// - An integer value lies outside the i64 range
```

- [ ] **Step 4.5: Run the gate and commit the fix.** Expected: `32 passed`
  unit (31 + 1), `0 failed`.

```bash
git add crates/zsign-core/src/codesign/der.rs
git commit -m "fix(codesign): reject integers outside the i64 range in der encoding (ZSN-38)"
```

- [ ] **Step 4.6: Add the three golden-vector tests** (append to `mod tests`;
  these pin Tasks 1-3 behavior and should pass immediately — if any fails,
  stop and re-derive the vector against the encoder before touching code)

```rust
    #[test]
    fn test_plist_to_der_array_values() {
        let xml = br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>application-groups</key>
    <array>
        <string>g1</string>
        <string>g2</string>
    </array>
</dict>
</plist>"#;
        let der = plist_to_der(xml).unwrap();
        // 70 25 | 02 01 01 | b0 20 | 30 1e 0c 12 "application-groups"
        //       30 08 0c 02 "g1" 0c 02 "g2"
        assert_eq!(
            der,
            vec![
                0x70, 0x25, 0x02, 0x01, 0x01, 0xb0, 0x20, 0x30, 0x1e, 0x0c, 0x12, b'a', b'p',
                b'p', b'l', b'i', b'c', b'a', b't', b'i', b'o', b'n', b'-', b'g', b'r', b'o',
                b'u', b'p', b's', 0x30, 0x08, 0x0c, 0x02, b'g', b'1', 0x0c, 0x02, b'g', b'2',
            ]
        );
    }

    #[test]
    fn test_plist_to_der_long_form_lengths() {
        let xml = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>k</key>
    <string>{}</string>
</dict>
</plist>"#,
            "x".repeat(130)
        );
        let der = plist_to_der(xml.as_bytes()).unwrap();
        // Long-form (0x81 nn) lengths at every level once the entries SET
        // exceeds 127 bytes: value 0c 81 82, pair 30 81 88, entries b0 81 8b,
        // envelope 70 81 91.
        let mut expected = vec![
            0x70, 0x81, 0x91, 0x02, 0x01, 0x01, 0xb0, 0x81, 0x8b, 0x30, 0x81, 0x88, 0x0c, 0x01,
            b'k', 0x0c, 0x81, 0x82,
        ];
        expected.extend(std::iter::repeat_n(b'x', 130));
        assert_eq!(der, expected);
    }

    #[test]
    fn test_plist_to_der_data_and_date_in_envelope() {
        let xml = br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>ts</key>
    <date>1981-05-16T11:32:06Z</date>
    <key>bin</key>
    <data>AQID</data>
</dict>
</plist>"#;
        let der = plist_to_der(xml).unwrap();
        // Sorted member order puts "bin" (30 0a ...) before "ts" (30 15 ...)
        // despite the document order; date renders as GeneralizedTime
        // 18 0f "19810516113206Z".
        assert_eq!(
            der,
            vec![
                0x70, 0x28, 0x02, 0x01, 0x01, 0xb0, 0x23, 0x30, 0x0a, 0x0c, 0x03, b'b', b'i',
                b'n', 0x04, 0x03, 0x01, 0x02, 0x03, 0x30, 0x15, 0x0c, 0x02, b't', b's', 0x18,
                0x0f, b'1', b'9', b'8', b'1', b'0', b'5', b'1', b'6', b'1', b'1', b'3', b'2',
                b'0', b'6', b'Z',
            ]
        );
    }
```

- [ ] **Step 4.7: Run the gate and commit the vectors.** Expected: `35 passed`
  unit (32 + 3), `0 failed`.

```bash
git add crates/zsign-core/src/codesign/der.rs
git commit -m "test(codesign): pin golden der entitlement vectors (ZSN-38)"
```

---

### Task 5: Interop script — profile signing, slot -7 round-trip, cert flip (brief item 5)

**Files:**
- Modify: `scripts/verify-apple-interop.sh` (211 lines; anchors re-anchored at
  c9ff0fb)

- [ ] **Step 5.1: Flip the certificate to an end-entity constraint.** Header
  comment lines 11-12 — replace

```bash
# Runs only on macOS. No sudo, no persisted state (the signing certificate is
# a self-signed code-signing CA that is its own implicit trust anchor).
```

with

```bash
# Runs only on macOS. No sudo, no persisted state (the signing certificate is
# a self-signed end-entity certificate that is its own implicit trust anchor).
```

Section 1 comment (lines 51-55) — replace

```bash
# 1. Self-signed code-signing certificate.
#    EKU codeSigning + KU digitalSignature + CA:TRUE make it valid under
#    SecTrustEvaluate's code-signing policy even without a system anchor.
```

with

```bash
# 1. Self-signed end-entity code-signing certificate.
#    EKU codeSigning + KU digitalSignature + CA:FALSE satisfy the leaf rules
#    enforced by the strict verifier (codeSigning EKU, digitalSignature KU,
#    CA=false); the certificate is its own implicit trust anchor.
```

and in the `openssl req` invocation (line 61) replace

```bash
    -addext "basicConstraints=critical,CA:TRUE" >/dev/null 2>&1
```

with

```bash
    -addext "basicConstraints=critical,CA:FALSE" >/dev/null 2>&1
```

- [ ] **Step 5.2: Insert the new entitlements section** between the step-4
  call (`sign_and_verify "$WORK/adhoc" "ad-hoc" -a`) and the `# 5.
  Structural asserts` header. Complete section:

```bash
# ---------------------------------------------------------------------------
# 5. Entitlements ground truth: profile-derived slot -7 DER must round-trip
#    through Apple's own tools (display decode + generator cross-check).
# ---------------------------------------------------------------------------
cat > "$WORK/entitlements.xml" <<'ENTXML'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>zz-counter</key><integer>42</integer>
<key>get-task-allow</key><true/>
<key>zsign-data-sample</key><data>AQID</data>
<key>application-groups</key><array><string>group.com.zsign.interop</string></array>
<key>com.zsign.interop.nested</key><dict><key>enabled</key><true/></dict>
<key>application-identifier</key><string>TEAMID.com.zsign.interop</string>
</dict></plist>
ENTXML

# Minimal fixture profile: the entitlements extractor only needs the XML
# plist window, not a real CMS signature.
python3 - "$WORK/entitlements.xml" "$WORK/fixture.mobileprovision" <<'PYPROF'
import plistlib, sys
ent = plistlib.load(open(sys.argv[1], "rb"))
with open(sys.argv[2], "wb") as fh:
    plistlib.dump({"Entitlements": ent}, fh, fmt=plistlib.FMT_XML)
PYPROF

sign_and_verify "$WORK/ent" "cert-signed (RSA, entitlements)" \
    -p "$WORK/cs.p12" --password test -m "$WORK/fixture.mobileprovision"

app="$WORK/ent/Test.app"
D=$(codesign -d --verbose=4 "$app/Test" 2>&1)
printf '%s\n' "$D" >>"$DIAG"

codesign -d --entitlements - --der "$app/Test" >"$WORK/displayed.der" 2>/dev/null \
    || fail "codesign cannot dump DER entitlements of our signature"
codesign -d --entitlements - --xml "$app/Test" >"$WORK/displayed.xml" 2>/dev/null \
    || fail "codesign cannot dump XML entitlements of our signature"

# Apple's own DER for the same XML: the documented cross-check for the
# golden-vector tests (they pin literals locally; this pins them to Apple).
build_fixture "$WORK/ref/Test.app"
codesign --force --sign - --entitlements "$WORK/entitlements.xml" \
    --generate-entitlement-der "$WORK/ref/Test.app/Test" >/dev/null 2>&1 \
    || fail "codesign --generate-entitlement-der reference signing"

if ! python3 - "$app/Test" "$WORK/ref/Test.app/Test" \
    "$WORK/displayed.der" "$WORK/displayed.xml" "$WORK/entitlements.xml" <<'PYDER'
import plistlib, struct, sys, pathlib

def slot_blob(path, wanted_type):
    data = pathlib.Path(path).read_bytes()
    off = data.rfind(b"\xfa\xde\x0c\xc0")
    count = struct.unpack(">I", data[off + 8:off + 12])[0]
    for i in range(count):
        typ, eoff = struct.unpack(">II", data[off + 12 + i * 8:off + 20 + i * 8])
        if typ == wanted_type:
            base = off + eoff
            size = struct.unpack(">I", data[base + 4:base + 8])[0]
            return data[base:base + size]
    return None

ours = slot_blob(sys.argv[1], 7)
reference = slot_blob(sys.argv[2], 7)
if ours is None:
    sys.exit("our signature has no slot 7 (DER entitlements) blob")
if reference is None:
    sys.exit("codesign reference signature has no slot 7 blob")
if ours[8:] != reference[8:]:
    sys.exit("slot -7 MISMATCH vs codesign --generate-entitlement-der:\n"
             + "  ours:     " + ours[8:].hex() + "\n  codesign: " + reference[8:].hex())
displayed = pathlib.Path(sys.argv[3]).read_bytes()
if displayed != ours[8:]:
    sys.exit("codesign --entitlements - --der output differs from our slot -7 payload")
expected = plistlib.load(open(sys.argv[5], "rb"))
shown = plistlib.load(open(sys.argv[4], "rb"))
if shown != expected:
    sys.exit("XML round-trip mismatch:\n  expected: %r\n  shown:    %r"
             % (expected, shown))
print("OK  entitlements: slot -7 matches codesign --generate-entitlement-der")
PYDER
then
    fail "der entitlements round-trip (slot -7 ground truth)"
fi
```

Notes for the implementer:
- The fixture deliberately mixes key and value lengths so member order
  (encoded-bytes vs key-sort) is observable — a mismatch against Apple's
  generator is a real finding, not a script bug; report it, do not relax the
  comparison.
- No `<date>` in the fixture: no Apple reference output exists for dates
  (recorded in the design doc).
- `app` is reassigned here on purpose; the later structural section reassigns
  it to `$WORK/cert/Test.app`.

- [ ] **Step 5.3: Renumber the following sections and dual-pin the self-signed
  `zsign -V` agreement (supervisor ruling, ZSN-25 option b).** Replace the
  headers

```bash
# 5. Structural asserts on the signed main binary (format regressions).
# 6. CMS binding: the embedded CMS must cryptographically verify over the
# 7. zsign -V agreement: our verifier must agree with Apple's in both
```

with `# 6.`, `# 7.`, `# 8.` (keep their second lines verbatim), and rename the
in-section markers `7b.`→`8c.`, `7c.`→`8d.`, `7d.`→`8e.` (the `7a` block is
replaced wholesale below).

Then, in the renamed section 8, replace the `7a` block: CLI verification
anchors only to the embedded Apple Root (`cms_verify.rs:275-287`), and a
self-signed chain is accepted only when its SPKI is in that anchor set
(`cms_verify.rs:1113-1150`), so `verified: yes` is impossible by design —
pin structural validity PLUS the expected anchoring failure instead. Both
surfaces were probed against the landed CLI before writing these greps: the
bundle report prints no error text (print_bundle keeps per-binary CMS errors
internal, exit 1), while the detached main binary prints the anchoring
verdict (exit 2) with two expected `cannot verify special slot ... without
bundle context` errors that must NOT be asserted against. Replace

```bash
# 7a. The two bundles codesign accepted in steps 3/4.
agree_valid "cert-signed bundle" "$WORK/cert/Test.app"
agree_valid "ad-hoc bundle"       "$WORK/adhoc/Test.app"
```

with

```bash
# 8a. Cert-signed bundle: codesign accepts it (step 3), but zsign -V anchors
#     only to the Apple Root, so a self-signed signature must never report
#     verified: yes — pin structural validity plus the anchoring failure.
VB=$("$ZIGN" -V "$WORK/cert/Test.app" 2>&1 || true)
printf '%s\n' "$VB" >>"$DIAG"
grep -q '^verified: no'                     <<<"$VB" || fail "zsign -V must not report verified: yes for the cert-signed bundle:\n$VB"
grep -q '^    arm64: pages ok, CMS INVALID' <<<"$VB" || fail "zsign -V did not reach the structural+CMS verdict for the cert-signed bundle:\n$VB"
grep -q '^  code resources: ok'             <<<"$VB" || fail "zsign -V did not confirm sealed top-level code resources for the cert-signed bundle:\n$VB"
if grep -qi mismatch <<<"$VB"; then
    fail "zsign -V reported structural mismatches on the cert-signed bundle:\n$VB"
fi

# The detached main binary exposes the anchoring verdict: the bundle report
# keeps CMS details internal, so pin the parse evidence and the expected
# failure text on the binary instead.
VM=$("$ZIGN" -V "$WORK/cert/Test.app/Test" 2>&1 || true)
printf '%s\n' "$VM" >>"$DIAG"
grep -q '^verified: no'                   <<<"$VM" || fail "zsign -V accepted the self-signed main binary:\n$VM"
grep -q 'not anchored to a trusted root'   <<<"$VM" || fail "zsign -V missing the expected anchoring failure:\n$VM"
grep -q 'signer: CN=zsign interop CI'      <<<"$VM" || fail "zsign -V did not parse the self-signed CMS signer:\n$VM"
grep -q 'cms: INVALID (chain: CN=zsign interop CI, anchor: false)' <<<"$VM" || fail "zsign -V did not report the expected unanchored self-signed CMS state:\n$VM"
if grep -qi mismatch <<<"$VM"; then
    fail "zsign -V reported structural mismatches on the cert-signed main binary:\n$VM"
fi
echo "OK  zsign -V dual-pin: structure valid + unanchored (expected) for cert-signed bundle"

# 8b. The ad-hoc bundle codesign accepted in step 4.
agree_valid "ad-hoc bundle"       "$WORK/adhoc/Test.app"
```

Do NOT add a `zsign -V` check for the entitlements-signed bundle anywhere — it
is self-signed for the same reason; section 5's ground truth is codesign plus
the byte-level slot -7 asserts.

- [ ] **Step 5.4: Validate locally (macOS-only behavior runs on the CI
  runner).**

```bash
bash -n scripts/verify-apple-interop.sh
command -v shellcheck >/dev/null && shellcheck scripts/verify-apple-interop.sh || true
```

Expected: `bash -n` silent (exit 0). Also grep-verify ZSN-31's diagnostics
survived — every one of these lines must still be present:

```bash
grep -c 'DIAG' scripts/verify-apple-interop.sh   # ≥ 5 (definition, header block, fail(), codesign dump, new dump)
```

Shellcheck findings are reviewed by eye: suppress nothing, fix real issues in
the new code only.

- [ ] **Step 5.5: Run the cargo gate once more** (nothing in Rust changed, but
  the gate guards accidental drift). Expected: `35 passed`, `0 failed`.

- [ ] **Step 5.6: Commit**

```bash
git add scripts/verify-apple-interop.sh
git commit -m "test(scripts): round-trip der entitlements against codesign (ZSN-38)"
```

---

## Self-review (plan)

- **Spec coverage:** brief items 1-5 map to Tasks 1-5; the item-4 vector table
  above accounts for every vector the brief lists; the ZSN-23 cert handover is
  Step 5.1; the `--generate-entitlement-der` cross-check is Step 5.2.
- **Placeholders:** none — every step carries complete code or a complete
  command with expected output.
- **Type consistency:** `encode_dictionary(&plist::Dictionary) -> Result<Vec<u8>>`
  is the only new symbol; `generalized_time(plist::Date) -> Result<String>` and
  `civil_from_days(i64) -> (i64, i32, i32)` are Task 2-internal.
- **Known test adjustments to report:** `test_plist_to_der_unsupported_data_type`
  renamed/re-pointed to Real (Task 2); brief's "11 der tests" is actually 12.

## Execution handoff

Executed with subagent-driven-development (Tester-red → implementer-green per
task, scoped gate before each commit, strictly sequential — all tasks share
`der.rs`). The orchestrator runs the merge gates (`fmt`/`clippy`/`hk`); this
lane never pushes or merges.
