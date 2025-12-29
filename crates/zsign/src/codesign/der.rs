//! DER (Distinguished Encoding Rules) encoder for plist entitlements
//!
//! This module converts XML plist entitlements to DER format as required by
//! iOS/macOS code signing for slot -7 (DER entitlements).
//!
//! The encoding uses the following ASN.1 DER tags:
//! - 0x01: BOOLEAN
//! - 0x02: INTEGER
//! - 0x0c: UTF8String
//! - 0x30: SEQUENCE (for arrays)
//! - 0x31: SET (for dictionaries)

use plist::Value;

/// DER tag for BOOLEAN
const DER_TAG_BOOLEAN: u8 = 0x01;

/// DER tag for INTEGER
const DER_TAG_INTEGER: u8 = 0x02;

/// DER tag for UTF8String
const DER_TAG_UTF8STRING: u8 = 0x0c;

/// DER tag for SEQUENCE (used for arrays)
const DER_TAG_SEQUENCE: u8 = 0x30;

/// DER tag for SET (used for dictionaries)
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
fn encode_value(value: &Value) -> Vec<u8> {
    let mut output = Vec::new();

    match value {
        Value::Boolean(b) => {
            output.push(DER_TAG_BOOLEAN);
            output.push(1); // length
            output.push(if *b { 1 } else { 0 });
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
                array_content.extend(encode_value(item));
            }

            output.push(DER_TAG_SEQUENCE);
            encode_length(&mut output, array_content.len());
            output.extend(array_content);
        }
        Value::Dictionary(dict) => {
            // Build SET content from key-value pairs
            let mut set_content = Vec::new();

            for (key, val) in dict {
                let encoded_val = encode_value(val);

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
            // Data type not supported in entitlements DER encoding
            // This shouldn't appear in entitlements
        }
        Value::Date(_) => {
            // Date type not supported in entitlements DER encoding
            // This shouldn't appear in entitlements
        }
        Value::Real(_) => {
            // Real/float type not supported in entitlements DER encoding
            // This shouldn't appear in entitlements
        }
        _ => {
            // Unknown type - skip
        }
    }

    output
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
/// The DER-encoded entitlements data, or None if parsing/encoding fails.
pub fn plist_to_der(plist_xml: &[u8]) -> Option<Vec<u8>> {
    // Parse the plist
    let value: Value = plist::from_bytes(plist_xml).ok()?;

    // Encode to DER
    let der = encode_value(&value);

    if der.is_empty() {
        None
    } else {
        Some(der)
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
        let der = encode_value(&value);
        assert_eq!(der, vec![0x01, 0x01, 0x01]);
    }

    #[test]
    fn test_encode_boolean_false() {
        let value = Value::Boolean(false);
        let der = encode_value(&value);
        assert_eq!(der, vec![0x01, 0x01, 0x00]);
    }

    #[test]
    fn test_encode_string() {
        let value = Value::String("test".to_string());
        let der = encode_value(&value);
        assert_eq!(der, vec![0x0c, 0x04, b't', b'e', b's', b't']);
    }

    #[test]
    fn test_encode_integer() {
        let value = Value::Integer(42.into());
        let der = encode_value(&value);
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
        assert!(der.is_some());
        let der = der.unwrap();

        // Should start with SET tag (0x31)
        assert_eq!(der[0], 0x31);
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
        assert!(der.is_some());
        let der = der.unwrap();

        // Empty dict: SET with 0 content
        assert_eq!(der, vec![0x31, 0x00]);
    }

    #[test]
    fn test_encode_integer_high_bit() {
        // 128 = 0x80, needs leading zero to avoid negative interpretation
        let value = Value::Integer(128.into());
        let der = encode_value(&value);
        // Should be: 0x02 (INTEGER), 0x02 (length=2), 0x00, 0x80
        assert_eq!(der, vec![0x02, 0x02, 0x00, 0x80]);
    }

    #[test]
    fn test_encode_integer_256() {
        // 256 = 0x0100, MSB is 0x01 so no leading zero needed
        let value = Value::Integer(256.into());
        let der = encode_value(&value);
        // Should be: 0x02 (INTEGER), 0x02 (length=2), 0x01, 0x00
        assert_eq!(der, vec![0x02, 0x02, 0x01, 0x00]);
    }

    #[test]
    fn test_encode_integer_255() {
        // 255 = 0xFF, needs leading zero
        let value = Value::Integer(255.into());
        let der = encode_value(&value);
        // Should be: 0x02 (INTEGER), 0x02 (length=2), 0x00, 0xFF
        assert_eq!(der, vec![0x02, 0x02, 0x00, 0xFF]);
    }
}
