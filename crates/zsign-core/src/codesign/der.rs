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
//! Keys are sorted lexicographically and `BOOLEAN true` is encoded as `0xFF`
//! (DER canonical). This is the format Apple's `codesign --generate-entitlement-der`
//! emits; non-canonical variants (bare SETs, `BOOLEAN true = 0x01`) are rejected
//! by modern macOS verification and iOS 15+ installs.
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

use plist::Value;

use crate::{Error, Result};

/// DER tag for BOOLEAN.
const DER_TAG_BOOLEAN: u8 = 0x01;

/// DER tag for INTEGER.
const DER_TAG_INTEGER: u8 = 0x02;

/// DER tag for UTF8String.
const DER_TAG_UTF8STRING: u8 = 0x0c;

/// DER tag for SEQUENCE (used for arrays).
const DER_TAG_SEQUENCE: u8 = 0x30;

/// DER tag for SET (used for dictionaries).
const DER_TAG_SET: u8 = 0x31;

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

/// Encode a plist Value to DER format.
///
/// Converts plist values to their corresponding ASN.1 DER representation:
/// - Bool -> BOOLEAN
/// - Integer -> INTEGER
/// - String -> UTF8String
/// - Array -> SEQUENCE
/// - Dictionary -> SET of key-value pairs
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
            let val = i.as_signed().unwrap_or(0) as u64;
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
        Value::Dictionary(dict) => {
            // Build SET content from key-value pairs
            let mut set_content = Vec::new();

            for (key, val) in dict {
                let encoded_val = encode_value(val)?;

                // Each key-value pair is a SEQUENCE: { key_as_UTF8String, encoded_value }
                // Encode the key as UTF8String
                let mut key_encoded = Vec::new();
                key_encoded.push(DER_TAG_UTF8STRING);
                encode_length(&mut key_encoded, key.len());
                key_encoded.extend(key.as_bytes());

                // Build the pair content
                let pair_len = key_encoded.len() + encoded_val.len();

                // Pair header: SEQUENCE tag + length
                set_content.push(DER_TAG_SEQUENCE);
                encode_length(&mut set_content, pair_len);
                set_content.extend(key_encoded);
                set_content.extend(encoded_val);
            }

            output.push(DER_TAG_SET);
            encode_length(&mut output, set_content.len());
            output.extend(set_content);
        }
        Value::Data(_) => {
            return Err(Error::DerEncoding("Unsupported plist type: Data".into()));
        }
        Value::Date(_) => {
            return Err(Error::DerEncoding("Unsupported plist type: Date".into()));
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
/// - An unsupported plist type is encountered (Data, Date, Real)
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

    // Entitlements root must be a dictionary; encode its sorted key/value
    // pairs as the entries SET content (each pair is a SEQUENCE).
    let dict = value
        .as_dictionary()
        .ok_or_else(|| Error::DerEncoding("Entitlements plist root must be a dictionary".into()))?;
    let mut pairs = Vec::new();
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
        pairs.extend_from_slice(&pair);
    }

    // Apple canonical envelope (matches `codesign --generate-entitlement-der`):
    //   [APPLICATION 16] (0x70) IMPLICIT SEQUENCE {
    //       version  INTEGER (1),
    //       entries  [16] (0xB0) IMPLICIT SET OF Entitlement
    //   }
    let mut entries = Vec::with_capacity(pairs.len() + 4);
    entries.push(0xb0); // [16] IMPLICIT SET (constructed)
    encode_length(&mut entries, pairs.len());
    entries.extend_from_slice(&pairs);

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
    fn test_plist_to_der_unsupported_data_type() {
        let xml = br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>test-data</key>
    <data>AQID</data>
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
}
