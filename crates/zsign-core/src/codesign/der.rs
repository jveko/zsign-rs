//! DER (Distinguished Encoding Rules) encoder for plist entitlements.
//!
//! This module converts XML plist entitlements to DER format as required by
//! iOS/macOS code signing for slot -7 (DER entitlements).
//!
//! The encoding uses Apple's canonical entitlements DER (slot -7):
//!
//! ```text
//! [APPLICATION 16] (0x70) IMPLICIT SEQUENCE {
//!     version INTEGER (1),
//!     entries [16] (0xB0) IMPLICIT SET OF Entitlement
//! }
//! Entitlement ::= SEQUENCE { UTF8String key, value }
//! ```
//!
//! Dictionary entries are ordered by their complete member encodings compared
//! as octet strings (DER SET OF rule, X.690 clause 11.6) and `BOOLEAN true` is
//! encoded as `0xFF` (DER canonical). This is the format Apple's
//! `codesign --generate-entitlement-der` emits; non-canonical variants
//! (unordered entries, bare SETs, `BOOLEAN true = 0x01`) are rejected by modern
//! macOS verification and iOS 15+ installs.
//!
//! # Examples
//!
//! ```
//! use zsign_core::codesign::der::plist_to_der;
//!
//! let xml = br#"<?xml version="1.0" encoding="UTF-8"?>
//! <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
//! <plist version="1.0">
//! <dict>
//!     <key>get-task-allow</key>
//!     <true/>
//! </dict>
//! </plist>"#;
//!
//! let der = plist_to_der(xml).unwrap();
//! assert!(!der.is_empty());
//! ```

use std::time::{SystemTime, UNIX_EPOCH};

use plist::Value;

use crate::{Error, Result};

/// DER tag for BOOLEAN.
const DER_TAG_BOOLEAN: u8 = 0x01;

/// DER tag for INTEGER.
const DER_TAG_INTEGER: u8 = 0x02;

/// DER tag for UTF8String.
const DER_TAG_UTF8STRING: u8 = 0x0c;

/// DER tag for OCTET STRING (used for Data).
const DER_TAG_OCTETSTRING: u8 = 0x04;

/// DER tag for GeneralizedTime (used for Date).
const DER_TAG_GENERALIZEDTIME: u8 = 0x18;

/// DER tag for SEQUENCE (used for arrays).
const DER_TAG_SEQUENCE: u8 = 0x30;

/// Encode a length value in DER format.
///
/// For lengths < 128, uses short form (1 byte).
/// For lengths >= 128, uses long form (1 + n bytes).
fn encode_length(output: &mut Vec<u8>, length: usize) {
    if length < 128 {
        output.push(length as u8);
    } else {
        // Calculate number of bytes needed for the length
        let bytes_needed = (64 - (length as u64).leading_zeros() as usize).div_ceil(8);

        // First byte: 0x80 | number of length bytes
        output.push(0x80 | bytes_needed as u8);

        // Length bytes in big-endian order
        for i in (0..bytes_needed).rev() {
            output.push(((length >> (i * 8)) & 0xFF) as u8);
        }
    }
}

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
    (
        if m <= 2 {
            yoe + era * 400 + 1
        } else {
            yoe + era * 400
        },
        m as i32,
        d as i32,
    )
}
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

/// Encode a plist Value to DER format.
///
/// Converts plist values to their corresponding ASN.1 DER representation:
/// - Bool -> BOOLEAN
/// - Integer -> INTEGER
/// - String -> UTF8String
/// - Array -> SEQUENCE
/// - Dictionary -> [16] (0xb0) IMPLICIT SET OF key-value pairs
/// - Data -> OCTET STRING
/// - Date -> GeneralizedTime
fn encode_value(value: &Value) -> Result<Vec<u8>> {
    let mut output = Vec::new();

    match value {
        Value::Boolean(b) => {
            output.push(DER_TAG_BOOLEAN);
            output.push(1); // length
                            // DER canonical: TRUE must be 0xFF, FALSE 0x00. Apple's parser
                            // rejects the lenient 0x01 for TRUE.
            output.push(if *b { 0xff } else { 0x00 });
        }
        Value::Integer(i) => {
            let val = match i.as_signed() {
                Some(v) => v as u64,
                None => {
                    return Err(Error::DerEncoding(format!(
                        "integer value {} is outside the i64 range",
                        i
                    )));
                }
            };
            output.push(DER_TAG_INTEGER);

            if val == 0 {
                output.push(1); // length
                output.push(0); // value
            } else {
                // Calculate number of bytes needed for the value
                let leading_zeros = val.leading_zeros() as usize;
                let significant_bits = 64 - leading_zeros;
                let mut bytes_needed = significant_bits.div_ceil(8);

                // Check if MSB of the encoded value is 1 (would be negative in signed DER)
                // This happens when significant_bits is exactly a multiple of 8
                let needs_sign_pad = (val >> ((bytes_needed * 8) - 1)) & 1 == 1;

                if needs_sign_pad {
                    bytes_needed += 1;
                }

                encode_length(&mut output, bytes_needed);

                if needs_sign_pad {
                    output.push(0x00);
                    bytes_needed -= 1;
                }

                // Write remaining bytes in big-endian order
                for i in (0..bytes_needed).rev() {
                    output.push(((val >> (i * 8)) & 0xFF) as u8);
                }
            }
        }
        Value::String(s) => {
            output.push(DER_TAG_UTF8STRING);
            encode_length(&mut output, s.len());
            output.extend(s.as_bytes());
        }
        Value::Array(arr) => {
            // Encode all elements first
            let mut array_content = Vec::new();
            for item in arr {
                array_content.extend(encode_value(item)?);
            }

            output.push(DER_TAG_SEQUENCE);
            encode_length(&mut output, array_content.len());
            output.extend(array_content);
        }
        Value::Dictionary(dict) => return encode_dictionary(dict),
        Value::Data(bytes) => {
            output.push(DER_TAG_OCTETSTRING);
            encode_length(&mut output, bytes.len());
            output.extend(bytes);
        }
        Value::Date(date) => {
            let text = generalized_time(*date)?;
            output.push(DER_TAG_GENERALIZEDTIME);
            encode_length(&mut output, text.len());
            output.extend(text.as_bytes());
        }
        Value::Real(_) => {
            return Err(Error::DerEncoding("Unsupported plist type: Real".into()));
        }
        _ => {
            return Err(Error::DerEncoding("Unknown plist value type".into()));
        }
    }

    Ok(output)
}

/// Convert XML plist entitlements to DER format.
///
/// This function parses the XML plist and encodes it as DER, suitable for
/// inclusion in slot -7 of the code signature.
///
/// # Arguments
///
/// * `plist_xml` - The XML plist data (entitlements)
///
/// # Returns
///
/// The DER-encoded entitlements data.
///
/// # Errors
///
/// Returns an error if:
/// - The XML plist cannot be parsed
/// - The resulting DER encoding is empty
/// - An unsupported plist type is encountered (Real)
/// - An integer value lies outside the i64 range
///
/// # Examples
///
/// ```
/// use zsign_core::codesign::der::plist_to_der;
///
/// let xml = br#"<?xml version="1.0" encoding="UTF-8"?>
/// <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
/// <plist version="1.0">
/// <dict>
///     <key>get-task-allow</key>
///     <true/>
/// </dict>
/// </plist>"#;
///
/// let der = plist_to_der(xml).unwrap();
/// assert!(!der.is_empty());
/// ```
pub fn plist_to_der(plist_xml: &[u8]) -> Result<Vec<u8>> {
    // Parse the plist
    let value: Value = plist::from_bytes(plist_xml)
        .map_err(|e| Error::DerEncoding(format!("Failed to parse plist: {}", e)))?;

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

    let mut seq_content = Vec::with_capacity(entries.len() + 4);
    seq_content.push(DER_TAG_INTEGER);
    seq_content.push(1); // length
    seq_content.push(1); // version 1
    seq_content.extend_from_slice(&entries);

    let mut der = Vec::with_capacity(seq_content.len() + 4);
    der.push(0x70); // [APPLICATION 16] IMPLICIT SEQUENCE (constructed)
    encode_length(&mut der, seq_content.len());
    der.extend_from_slice(&seq_content);

    if der.is_empty() {
        Err(Error::DerEncoding("Empty DER output".into()))
    } else {
        Ok(der)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_length_short() {
        let mut buf = Vec::new();
        encode_length(&mut buf, 10);
        assert_eq!(buf, vec![10]);
    }

    #[test]
    fn test_encode_length_long() {
        let mut buf = Vec::new();
        encode_length(&mut buf, 256);
        // 256 = 0x100 needs 2 bytes
        assert_eq!(buf, vec![0x82, 0x01, 0x00]);
    }

    #[test]
    fn test_encode_boolean_true() {
        let value = Value::Boolean(true);
        let der = encode_value(&value).unwrap();
        assert_eq!(der, vec![0x01, 0x01, 0xff]);
    }

    #[test]
    fn test_encode_boolean_false() {
        let value = Value::Boolean(false);
        let der = encode_value(&value).unwrap();
        assert_eq!(der, vec![0x01, 0x01, 0x00]);
    }

    #[test]
    fn test_encode_string() {
        let value = Value::String("test".to_string());
        let der = encode_value(&value).unwrap();
        assert_eq!(der, vec![0x0c, 0x04, b't', b'e', b's', b't']);
    }

    #[test]
    fn test_encode_integer() {
        let value = Value::Integer(42.into());
        let der = encode_value(&value).unwrap();
        // 42 = 0x2A, fits in 1 byte
        assert_eq!(der, vec![0x02, 0x01, 0x2A]);
    }

    #[test]
    fn test_plist_to_der_simple() {
        let xml = br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>get-task-allow</key>
    <true/>
</dict>
</plist>"#;

        let der = plist_to_der(xml);
        assert!(der.is_ok());
        let der = der.unwrap();

        // Should start with the [APPLICATION 16] envelope tag (0x70).
        assert_eq!(der[0], 0x70);
        // ... IMPLICIT SEQUENCE { INTEGER version 1, [16] IMPLICIT SET ... }
        assert_eq!(&der[1..6], &[0x1a, 0x02, 0x01, 0x01, 0xb0]);
    }

    #[test]
    fn test_plist_to_der_empty() {
        let xml = br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
</dict>
</plist>"#;

        let der = plist_to_der(xml);
        assert!(der.is_ok());
        let der = der.unwrap();

        // Empty dict: canonical envelope with empty entries SET.
        assert_eq!(der, vec![0x70, 0x05, 0x02, 0x01, 0x01, 0xb0, 0x00]);
    }

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

    #[test]
    fn test_encode_integer_high_bit() {
        // 128 = 0x80, needs leading zero to avoid negative interpretation
        let value = Value::Integer(128.into());
        let der = encode_value(&value).unwrap();
        // Should be: 0x02 (INTEGER), 0x02 (length=2), 0x00, 0x80
        assert_eq!(der, vec![0x02, 0x02, 0x00, 0x80]);
    }

    #[test]
    fn test_encode_integer_256() {
        // 256 = 0x0100, MSB is 0x01 so no leading zero needed
        let value = Value::Integer(256.into());
        let der = encode_value(&value).unwrap();
        // Should be: 0x02 (INTEGER), 0x02 (length=2), 0x01, 0x00
        assert_eq!(der, vec![0x02, 0x02, 0x01, 0x00]);
    }

    #[test]
    fn test_encode_integer_255() {
        // 255 = 0xFF, needs leading zero
        let value = Value::Integer(255.into());
        let der = encode_value(&value).unwrap();
        // Should be: 0x02 (INTEGER), 0x02 (length=2), 0x00, 0xFF
        assert_eq!(der, vec![0x02, 0x02, 0x00, 0xFF]);
    }

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
                0x70, 0x18, 0x02, 0x01, 0x01, 0xb0, 0x13, 0x30, 0x11, 0x0c, 0x05, b'o', b'u', b't',
                b'e', b'r', 0xb0, 0x08, 0x30, 0x06, 0x0c, 0x01, b'k', 0x01, 0x01, 0xff,
            ]
        );
    }

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
                0x18, 0x0f, b'1', b'9', b'8', b'1', b'0', b'5', b'1', b'6', b'1', b'1', b'3', b'2',
                b'0', b'6', b'Z',
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
                0x18, 0x11, b'1', b'9', b'9', b'2', b'0', b'7', b'2', b'2', b'1', b'3', b'2', b'1',
                b'0', b'0', b'.', b'3', b'Z',
            ]
        );
    }
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
                0x70, 0x16, 0x02, 0x01, 0x01, 0xb0, 0x11, 0x30, 0x06, 0x0c, 0x01, b'b', 0x01, 0x01,
                0xff, 0x30, 0x07, 0x0c, 0x02, b'a', b'a', 0x01, 0x01, 0xff,
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
}
