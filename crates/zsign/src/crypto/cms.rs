//! CMS signing with Apple CDHash attributes
//!
//! Uses cryptographic-message-syntax crate for CMS signature generation.

use crate::{Error, Result};
use bcder::{encode::Values, Captured, Mode, OctetString, Oid};
use cryptographic_message_syntax::{SignedDataBuilder, SignerBuilder};
use x509_certificate::{
    rfc5652::AttributeValue,
    CapturedX509Certificate, KeyInfoSigner,
};

/// Apple CDHash v1 OID: 1.2.840.113635.100.9.1
/// Contains plist with SHA-1 and SHA-256 hashes
pub const APPLE_CDHASH_OID: &[u8] = &[
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x09, 0x01,
];

/// Apple CDHash v2 OID: 1.2.840.113635.100.9.2
/// Contains SEQUENCE { OID sha256, OCTET STRING hash }
pub const APPLE_CDHASH_V2_OID: &[u8] = &[
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x09, 0x02,
];

/// SHA-256 OID: 2.16.840.1.101.3.4.2.1
const SHA256_OID: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];

/// Generate CMS signature with Apple CDHash attributes
///
/// # Arguments
///
/// * `data` - The CodeDirectory data to sign
/// * `signing_key` - The private key implementing KeyInfoSigner trait
/// * `signing_cert` - The signing certificate as CapturedX509Certificate
/// * `cert_chain` - Certificate chain (intermediate CAs)
/// * `cdhash_sha1` - SHA-1 CDHash for Apple attribute
/// * `cdhash_sha256` - SHA-256 CDHash for Apple attribute
pub fn sign_with_apple_attrs<K: KeyInfoSigner>(
    data: &[u8],
    signing_key: &K,
    signing_cert: &CapturedX509Certificate,
    cert_chain: &[CapturedX509Certificate],
    cdhash_sha1: &[u8; 20],
    cdhash_sha256: &[u8; 32],
) -> Result<Vec<u8>> {
    let cdhash_plist = build_cdhash_plist(cdhash_sha1, cdhash_sha256);
    let cdhash_v2_value = build_cdhash_v2_attribute(cdhash_sha256);

    let cdhash_v1_oid = Oid(cryptographic_message_syntax::Bytes::copy_from_slice(APPLE_CDHASH_OID));
    let cdhash_v2_oid = Oid(cryptographic_message_syntax::Bytes::copy_from_slice(APPLE_CDHASH_V2_OID));

    let cdhash_v1_attr_value = AttributeValue::new(Captured::from_values(
        Mode::Der,
        OctetString::encode_slice(&cdhash_plist),
    ));

    let cdhash_v2_attr_value =
        AttributeValue::new(Captured::from_values(Mode::Der, CdHashV2Encoder(&cdhash_v2_value)));

    let signer = SignerBuilder::new(signing_key, signing_cert.clone())
        .signed_attribute(cdhash_v1_oid, vec![cdhash_v1_attr_value])
        .signed_attribute(cdhash_v2_oid, vec![cdhash_v2_attr_value]);

    let mut builder = SignedDataBuilder::default()
        .content_external(data.to_vec())
        .signer(signer);

    for cert in cert_chain {
        builder = builder.certificate(cert.clone());
    }

    let der = builder
        .build_der()
        .map_err(|e| Error::Signing(format!("Failed to build CMS signature: {}", e)))?;

    Ok(der)
}

/// Build CDHash plist for Apple attribute
///
/// Creates an XML plist with a "cdhashes" array containing SHA-1 and SHA-256 CDHashes.
/// Both hashes are 20 bytes (SHA-256 is truncated to match SHA-1 length).
/// This is used for the Apple CDHash v1 attribute (OID 1.2.840.113635.100.9.1).
pub fn build_cdhash_plist(sha1: &[u8; 20], sha256: &[u8; 32]) -> Vec<u8> {
    use plist::{Dictionary, Value};

    let mut dict = Dictionary::new();
    dict.insert(
        "cdhashes".to_string(),
        Value::Array(vec![
            Value::Data(sha1.to_vec()),
            Value::Data(sha256[..20].to_vec()),
        ]),
    );

    let mut buf = Vec::new();
    plist::to_writer_xml(&mut buf, &Value::Dictionary(dict)).expect("plist serialization failed");
    buf.push(b'\n');
    buf
}

/// Build the CDHash v2 attribute value.
///
/// This creates a DER-encoded SEQUENCE containing:
/// - OBJECT IDENTIFIER for SHA-256 (2.16.840.1.101.3.4.2.1)
/// - OCTET STRING containing the 32-byte SHA-256 CDHash
///
/// Format: SEQUENCE { OBJECT sha256, OCTET STRING hash }
fn build_cdhash_v2_attribute(cdhash_sha256: &[u8; 32]) -> Vec<u8> {
    let mut oid = Vec::new();
    oid.push(0x06);
    oid.push(SHA256_OID.len() as u8);
    oid.extend_from_slice(SHA256_OID);

    let mut hash_octet = Vec::new();
    hash_octet.push(0x04);
    hash_octet.push(cdhash_sha256.len() as u8);
    hash_octet.extend_from_slice(cdhash_sha256);

    let inner_len = oid.len() + hash_octet.len();

    let mut result = Vec::new();
    result.push(0x30);
    result.push(inner_len as u8);
    result.extend_from_slice(&oid);
    result.extend_from_slice(&hash_octet);

    result
}

struct CdHashV2Encoder<'a>(&'a [u8]);

impl<'a> Values for CdHashV2Encoder<'a> {
    fn encoded_len(&self, _mode: Mode) -> usize {
        self.0.len()
    }

    fn write_encoded<W: std::io::Write>(&self, _mode: Mode, target: &mut W) -> std::result::Result<(), std::io::Error> {
        target.write_all(self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_cdhash_plist() {
        let sha1 = [0u8; 20];
        let sha256 = [0u8; 32];
        let plist = build_cdhash_plist(&sha1, &sha256);

        assert!(!plist.is_empty());
        let plist_str = String::from_utf8_lossy(&plist);
        assert!(plist_str.contains("cdhashes"));
        assert!(plist_str.contains("<array>"));
        assert!(plist_str.contains("<data>"));
    }

    #[test]
    fn test_build_cdhash_plist_with_real_hashes() {
        let sha1: [u8; 20] = [
            0x2f, 0xd4, 0xe1, 0xc6, 0x7a, 0x2d, 0x28, 0xfc, 0xed, 0x84, 0x9e, 0xe1, 0xbb, 0x76,
            0xe7, 0x39, 0x1b, 0x93, 0xeb, 0x12,
        ];
        let sha256: [u8; 32] = [
            0xd7, 0xa8, 0xfb, 0xb3, 0x07, 0xd7, 0x80, 0x94, 0x69, 0xca, 0x9a, 0xbc, 0xb0, 0x08,
            0x2e, 0x4f, 0x8d, 0x56, 0x51, 0xe4, 0x6d, 0x3c, 0xdb, 0x76, 0x2d, 0x02, 0xd0, 0xbf,
            0x37, 0xc9, 0xe5, 0x92,
        ];

        let plist = build_cdhash_plist(&sha1, &sha256);

        let parsed: plist::Value = plist::from_bytes(&plist).unwrap();
        let dict = parsed.as_dictionary().unwrap();
        let cdhashes = dict.get("cdhashes").unwrap().as_array().unwrap();

        assert_eq!(cdhashes.len(), 2);
        assert_eq!(cdhashes[0].as_data().unwrap(), sha1);
        assert_eq!(cdhashes[1].as_data().unwrap(), &sha256[..20]);
    }

    #[test]
    fn test_build_cdhash_v2_attribute() {
        let sha256: [u8; 32] = [
            0xd7, 0xa8, 0xfb, 0xb3, 0x07, 0xd7, 0x80, 0x94, 0x69, 0xca, 0x9a, 0xbc, 0xb0, 0x08,
            0x2e, 0x4f, 0x8d, 0x56, 0x51, 0xe4, 0x6d, 0x3c, 0xdb, 0x76, 0x2d, 0x02, 0xd0, 0xbf,
            0x37, 0xc9, 0xe5, 0x92,
        ];

        let attr = build_cdhash_v2_attribute(&sha256);

        assert_eq!(attr[0], 0x30);
        assert!(attr.len() > 0);
        assert!(attr.windows(SHA256_OID.len()).any(|w| w == SHA256_OID));
        assert!(attr.windows(sha256.len()).any(|w| w == sha256));
    }

    #[test]
    fn test_apple_cdhash_oid_encoding() {
        assert_eq!(APPLE_CDHASH_OID.len(), 9);
        assert_eq!(APPLE_CDHASH_OID[0], 0x2a);
    }

    #[test]
    fn test_apple_cdhash_v2_oid_encoding() {
        assert_eq!(APPLE_CDHASH_V2_OID.len(), 9);
        assert_eq!(APPLE_CDHASH_V2_OID[8], 0x02);
    }
}
