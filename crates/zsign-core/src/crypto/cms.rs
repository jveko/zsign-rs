//! CMS (Cryptographic Message Syntax) signature generation.
//!
//! This module generates PKCS#7/CMS signatures with Apple-specific CDHash
//! (Code Directory Hash) attributes required for iOS code signing. These
//! signatures are embedded in the `LC_CODE_SIGNATURE` Mach-O load command.
//!
//! # CDHash Attributes
//!
//! Apple code signatures include two proprietary signed attributes:
//!
//! - **CDHash v1** ([`APPLE_CDHASH_OID`]): XML plist containing SHA-1 and SHA-256 hashes
//! - **CDHash v2** ([`APPLE_CDHASH_V2_OID`]): DER-encoded ASN.1 sequence with hash algorithm and value
//!
//! # Examples
//!
//! ```ignore
//! use zsign_core::crypto::cms::sign_code_directory;
//!
//! let signature = sign_code_directory(
//!     &code_directory_der,
//!     &credentials,
//!     &cdhash_sha1,
//!     &cdhash_sha256,
//! )?;
//! ```

use crate::crypto::cert::SigningKeyType;
use crate::crypto::SigningCredentials;
use crate::{Error, Result};
use cms::builder::{SignedDataBuilder, SignerInfoBuilder};
use cms::cert::CertificateChoices;
use cms::signed_data::{EncapsulatedContentInfo, SignerIdentifier};
use const_oid::ObjectIdentifier;
use der::asn1::SetOfVec;
use der::{Any, Encode, Tag};
use sha2::{Digest, Sha256};
use spki::AlgorithmIdentifierOwned;
use x509_cert::attr::Attribute;
use x509_cert::Certificate;

/// Creates an `Error::Signing` with a formatted context message.
fn signing_err(ctx: &str, err: impl std::fmt::Display) -> Error {
    Error::Signing(format!("{}: {}", ctx, err))
}

/// Apple CDHash v1 attribute OID: `1.2.840.113635.100.9.1`
///
/// This OID identifies the first generation of Apple's CDHash signed attribute.
/// The attribute value is an XML plist containing a `cdhashes` array with
/// SHA-1 and truncated SHA-256 (20 bytes) hash values.
pub const APPLE_CDHASH_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113635.100.9.1");

/// Apple CDHash v2 attribute OID: `1.2.840.113635.100.9.2`
///
/// This OID identifies the second generation of Apple's CDHash signed attribute.
/// The attribute value is a DER-encoded ASN.1 SEQUENCE containing the hash
/// algorithm OID and the full hash value (not truncated).
pub const APPLE_CDHASH_V2_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113635.100.9.2");

/// SHA-256 algorithm OID: `2.16.840.1.101.3.4.2.1`
const SHA256_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");

/// Generates a CMS signature with Apple CDHash attributes.
///
/// Creates a PKCS#7/CMS signed data structure containing the CodeDirectory
/// signature with Apple-specific CDHash v1 and v2 signed attributes.
///
/// # Arguments
///
/// * `data` - The CodeDirectory DER bytes to sign
/// * `credentials` - Signing credentials (certificate + private key)
/// * `cdhash_sha1` - 20-byte SHA-1 hash of the CodeDirectory
/// * `cdhash_sha256` - 32-byte SHA-256 hash of the CodeDirectory
///
/// # Returns
///
/// DER-encoded CMS SignedData structure ready for embedding in the binary.
///
/// # Errors
///
/// Returns [`Error::Signing`] if CMS signature construction fails.
pub fn sign_code_directory(
    data: &[u8],
    credentials: &SigningCredentials,
    cdhash_sha1: &[u8; 20],
    cdhash_sha256: &[u8; 32],
) -> Result<Vec<u8>> {
    let cdhash_plist = build_cdhash_plist(cdhash_sha1, cdhash_sha256);
    let cdhash_v2_value = build_cdhash_v2_attribute(cdhash_sha256);

    let cdhash_v1_attr = build_apple_octet_string_attribute(APPLE_CDHASH_OID, &cdhash_plist)?;
    let cdhash_v2_attr = build_apple_der_attribute(APPLE_CDHASH_V2_OID, &cdhash_v2_value)?;

    let message_digest: [u8; 32] = {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().into()
    };

    let encap_content_info = EncapsulatedContentInfo {
        econtent_type: const_oid::db::rfc5911::ID_DATA,
        econtent: None,
    };

    let digest_algorithm = AlgorithmIdentifierOwned {
        oid: SHA256_OID,
        parameters: None,
    };

    let sid = SignerIdentifier::IssuerAndSerialNumber(cms::cert::IssuerAndSerialNumber {
        issuer: credentials.certificate.tbs_certificate.issuer.clone(),
        serial_number: credentials
            .certificate
            .tbs_certificate
            .serial_number
            .clone(),
    });

    let ctx = CmsBuildContext {
        sid,
        digest_algorithm,
        encap_content_info: &encap_content_info,
        message_digest: &message_digest,
        attrs: CmsSignedAttrs {
            cdhash_v1: cdhash_v1_attr,
            cdhash_v2: cdhash_v2_attr,
        },
        signing_cert: &credentials.certificate,
        cert_chain: &credentials.cert_chain,
    };

    match &credentials.signing_key {
        SigningKeyType::Rsa(signing_key) => build_cms_signed_data(signing_key, ctx),
        SigningKeyType::Ecdsa(ecdsa_key) => {
            build_cms_signed_data::<_, p256::ecdsa::DerSignature>(ecdsa_key, ctx)
        }
    }
}

struct CmsSignedAttrs {
    cdhash_v1: Attribute,
    cdhash_v2: Attribute,
}

struct CmsBuildContext<'a> {
    sid: SignerIdentifier,
    digest_algorithm: AlgorithmIdentifierOwned,
    encap_content_info: &'a EncapsulatedContentInfo,
    message_digest: &'a [u8],
    attrs: CmsSignedAttrs,
    signing_cert: &'a Certificate,
    cert_chain: &'a [Certificate],
}

fn build_cms_signed_data<S, Sig>(signer: &S, ctx: CmsBuildContext<'_>) -> Result<Vec<u8>>
where
    S: signature::Keypair + spki::DynSignatureAlgorithmIdentifier + signature::Signer<Sig>,
    Sig: spki::SignatureBitStringEncoding,
{
    let mut sib = SignerInfoBuilder::new(
        signer,
        ctx.sid,
        ctx.digest_algorithm.clone(),
        ctx.encap_content_info,
        Some(ctx.message_digest),
    )
    .map_err(|e| signing_err("Failed to create SignerInfoBuilder", e))?;

    sib.add_signed_attribute(ctx.attrs.cdhash_v1)
        .map_err(|e| signing_err("Failed to add CDHash v1 attribute", e))?;
    sib.add_signed_attribute(ctx.attrs.cdhash_v2)
        .map_err(|e| signing_err("Failed to add CDHash v2 attribute", e))?;

    let mut builder = SignedDataBuilder::new(ctx.encap_content_info);

    builder
        .add_digest_algorithm(ctx.digest_algorithm)
        .map_err(|e| signing_err("Failed to add digest algorithm", e))?;

    builder
        .add_certificate(CertificateChoices::Certificate(ctx.signing_cert.clone()))
        .map_err(|e| signing_err("Failed to add signing certificate", e))?;

    for cert in ctx.cert_chain {
        builder
            .add_certificate(CertificateChoices::Certificate(cert.clone()))
            .map_err(|e| signing_err("Failed to add chain certificate", e))?;
    }

    builder
        .add_signer_info::<S, Sig>(sib)
        .map_err(|e| signing_err("Failed to add signer info", e))?;

    let content_info = builder
        .build()
        .map_err(|e| signing_err("Failed to build CMS SignedData", e))?;

    content_info
        .to_der()
        .map_err(|e| signing_err("Failed to encode CMS to DER", e))
}

/// Builds an Apple attribute wrapping the value in an `OCTET STRING` (for CDHash v1 plist).
fn build_apple_octet_string_attribute(
    oid: ObjectIdentifier,
    value_bytes: &[u8],
) -> Result<Attribute> {
    let attr_value = Any::new(Tag::OctetString, value_bytes)
        .map_err(|e| signing_err("Failed to create attribute value", e))?;

    let mut values = SetOfVec::new();
    values
        .insert(attr_value)
        .map_err(|e| signing_err("Failed to insert attribute value", e))?;

    Ok(Attribute { oid, values })
}

/// Builds an Apple attribute by parsing the value as raw DER (for CDHash v2 `SEQUENCE`).
fn build_apple_der_attribute(oid: ObjectIdentifier, value_der: &[u8]) -> Result<Attribute> {
    use der::Decode;
    let attr_value =
        Any::from_der(value_der).map_err(|e| signing_err("Failed to parse attribute DER", e))?;

    let mut values = SetOfVec::new();
    values
        .insert(attr_value)
        .map_err(|e| signing_err("Failed to insert attribute value", e))?;

    Ok(Attribute { oid, values })
}

/// Builds the CDHash v1 plist for the Apple signed attribute.
///
/// Creates an XML plist with a `cdhashes` array containing SHA-1 and SHA-256
/// hashes. The SHA-256 hash is truncated to 20 bytes to match SHA-1 length,
/// as required by the Apple CDHash v1 format.
///
/// # Arguments
///
/// * `sha1` - 20-byte SHA-1 hash of the CodeDirectory
/// * `sha256` - 32-byte SHA-256 hash of the CodeDirectory (will be truncated)
///
/// # Returns
///
/// UTF-8 encoded XML plist bytes with trailing newline.
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

/// Builds the CDHash v2 attribute value as DER-encoded ASN.1.
///
/// Returns a SEQUENCE containing the SHA-256 algorithm OID and the full
/// 32-byte hash value.
///
/// # ASN.1 Structure
///
/// ```text
/// CDHashV2 ::= SEQUENCE {
///     algorithm  OBJECT IDENTIFIER,
///     hash       OCTET STRING
/// }
/// ```
fn build_cdhash_v2_attribute(cdhash_sha256: &[u8; 32]) -> Vec<u8> {
    let sha256_oid_bytes: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];

    let mut oid = Vec::new();
    oid.push(0x06);
    oid.push(sha256_oid_bytes.len() as u8);
    oid.extend_from_slice(sha256_oid_bytes);

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

/// Estimates the upper bound of a CMS SignedData DER encoding.
///
/// Computes a conservative estimate based on:
/// - Fixed CMS structure overhead (~200 bytes)
/// - Signing certificate DER size
/// - Certificate chain DER sizes
/// - Signature size (key-type dependent)
/// - Signed attributes overhead (~300 bytes for CDHash v1/v2 + standard attrs)
///
/// Returns an upper bound in bytes. The actual CMS output will be smaller.
pub fn estimate_cms_size(credentials: &SigningCredentials) -> usize {
    let cms_overhead = 200;
    let signed_attrs_size = 400;

    let cert_size = credentials
        .certificate
        .to_der()
        .map(|d| d.len())
        .unwrap_or(2048);

    let chain_size: usize = credentials
        .cert_chain
        .iter()
        .map(|c| c.to_der().map(|d| d.len()).unwrap_or(2048))
        .sum();

    let signature_size = match &credentials.signing_key {
        SigningKeyType::Rsa(_) => 512,
        SigningKeyType::Ecdsa(_) => 72,
    };

    let signer_info_overhead = 100;

    let total = cms_overhead
        + signed_attrs_size
        + cert_size
        + chain_size
        + signature_size
        + signer_info_overhead;

    crate::macho::writer::align_to(total + 2048, 4096)
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
        assert!(!attr.is_empty());
        let sha256_oid_bytes: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
        assert!(attr
            .windows(sha256_oid_bytes.len())
            .any(|w| w == sha256_oid_bytes));
        assert!(attr.windows(sha256.len()).any(|w| w == sha256));
    }

    #[test]
    fn test_apple_cdhash_oid_encoding() {
        assert_eq!(APPLE_CDHASH_OID.to_string(), "1.2.840.113635.100.9.1");
    }

    #[test]
    fn test_apple_cdhash_v2_oid_encoding() {
        assert_eq!(APPLE_CDHASH_V2_OID.to_string(), "1.2.840.113635.100.9.2");
    }

    #[test]
    fn test_cdhash_v1_attribute_is_octet_string() {
        let plist_bytes = build_cdhash_plist(&[0xAA; 20], &[0xBB; 32]);
        let attr = build_apple_octet_string_attribute(APPLE_CDHASH_OID, &plist_bytes).unwrap();

        assert_eq!(attr.oid, APPLE_CDHASH_OID);
        assert_eq!(attr.values.len(), 1);

        let value_der = attr.values.iter().next().unwrap().to_der().unwrap();
        assert_eq!(
            value_der[0], 0x04,
            "CDHash v1 value tag must be OCTET STRING (0x04)"
        );
    }

    #[test]
    fn test_cdhash_v2_attribute_is_sequence() {
        let hash = [0xAA; 32];
        let v2_der = build_cdhash_v2_attribute(&hash);
        let attr = build_apple_der_attribute(APPLE_CDHASH_V2_OID, &v2_der).unwrap();

        assert_eq!(attr.oid, APPLE_CDHASH_V2_OID);
        assert_eq!(attr.values.len(), 1);

        let value_der = attr.values.iter().next().unwrap().to_der().unwrap();
        assert_eq!(
            value_der[0], 0x30,
            "CDHash v2 value tag must be SEQUENCE (0x30)"
        );

        let sha256_oid_bytes: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
        assert!(
            value_der
                .windows(sha256_oid_bytes.len())
                .any(|w| w == sha256_oid_bytes),
            "SEQUENCE must contain SHA-256 OID"
        );
        assert!(
            value_der.windows(hash.len()).any(|w| w == hash),
            "SEQUENCE must contain the 32-byte hash"
        );
    }

    #[test]
    fn test_cdhash_v2_contains_hash_and_oid() {
        use der::{Reader, SliceReader};

        let hash = [0xCC; 32];
        let v2_der = build_cdhash_v2_attribute(&hash);
        let attr = build_apple_der_attribute(APPLE_CDHASH_V2_OID, &v2_der).unwrap();
        let value_der = attr.values.iter().next().unwrap().to_der().unwrap();

        assert_eq!(value_der[0], 0x30, "outer tag must be SEQUENCE");
        let body = &value_der[2..]; // skip tag + 1-byte length

        let mut reader = SliceReader::new(body).unwrap();
        let oid: ObjectIdentifier = reader.decode().expect("first element must be an OID");
        assert_eq!(
            oid.to_string(),
            "2.16.840.1.101.3.4.2.1",
            "OID must be SHA-256"
        );

        let octet: der::asn1::OctetStringRef<'_> = reader
            .decode()
            .expect("second element must be an OCTET STRING");
        assert_eq!(
            octet.as_bytes(),
            &hash,
            "OCTET STRING must contain the exact 32-byte hash"
        );
    }

    #[test]
    fn test_sign_code_directory_structure() {
        use crate::crypto::cert::{SigningCredentials, SigningKeyType};
        use cms::content_info::ContentInfo;
        use cms::signed_data::SignedData;
        use der::{Decode, Encode};
        use rsa::RsaPrivateKey;
        use sha2::Sha256;
        use spki::{EncodePublicKey, SubjectPublicKeyInfoOwned};
        use std::str::FromStr;
        use std::time::Duration;
        use x509_cert::builder::{Builder, CertificateBuilder, Profile};
        use x509_cert::name::Name;
        use x509_cert::serial_number::SerialNumber;
        use x509_cert::time::Validity;

        let mut rng = rand::thread_rng();
        let rsa_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let signing_key = rsa::pkcs1v15::SigningKey::<Sha256>::new(rsa_key.clone());

        let subject = Name::from_str("CN=Test Signer,OU=TESTTEAM").unwrap();
        let serial = SerialNumber::from(42u32);
        let validity = Validity::from_now(Duration::from_secs(3600)).unwrap();
        let pub_key_der = rsa_key.to_public_key().to_public_key_der().unwrap();
        let pub_key = SubjectPublicKeyInfoOwned::from_der(pub_key_der.as_ref()).unwrap();

        let cert = CertificateBuilder::new(
            Profile::Root,
            serial,
            validity,
            subject,
            pub_key,
            &signing_key,
        )
        .unwrap()
        .build::<rsa::pkcs1v15::Signature>()
        .unwrap();

        let credentials = SigningCredentials {
            certificate: cert,
            signing_key: SigningKeyType::Rsa(rsa::pkcs1v15::SigningKey::<Sha256>::new(rsa_key)),
            cert_chain: vec![],
            team_id: Some("TESTTEAM".to_string()),
        };

        let code_dir_data = b"fake code directory data for testing";
        let cdhash_sha1: [u8; 20] = [0xAA; 20];
        let cdhash_sha256: [u8; 32] = [0xBB; 32];

        let cms_der =
            sign_code_directory(code_dir_data, &credentials, &cdhash_sha1, &cdhash_sha256).unwrap();

        let content_info = ContentInfo::from_der(&cms_der).unwrap();
        let signed_data = SignedData::from_der(&content_info.content.to_der().unwrap()).unwrap();

        // Detached signature: econtent must be None
        assert!(
            signed_data.encap_content_info.econtent.is_none(),
            "CMS signature should be detached (econtent = None)"
        );

        // Exactly 1 SignerInfo
        assert_eq!(
            signed_data.signer_infos.0.len(),
            1,
            "Expected exactly 1 SignerInfo"
        );

        let signer_info = signed_data.signer_infos.0.iter().next().unwrap();

        // SignerIdentifier is IssuerAndSerialNumber
        assert!(
            matches!(
                signer_info.sid,
                cms::signed_data::SignerIdentifier::IssuerAndSerialNumber(_)
            ),
            "SignerIdentifier should be IssuerAndSerialNumber"
        );

        // Digest algorithm is SHA-256
        assert_eq!(
            signer_info.digest_alg.oid.to_string(),
            "2.16.840.1.101.3.4.2.1",
            "Digest algorithm should be SHA-256"
        );

        // Verify signed attributes contain expected OIDs
        let signed_attrs = signer_info
            .signed_attrs
            .as_ref()
            .expect("SignerInfo should have signed attributes");

        let attr_oids: Vec<String> = signed_attrs.iter().map(|a| a.oid.to_string()).collect();

        assert!(
            attr_oids.contains(&"1.2.840.113549.1.9.3".to_string()),
            "Signed attributes should contain content-type OID"
        );
        assert!(
            attr_oids.contains(&"1.2.840.113549.1.9.4".to_string()),
            "Signed attributes should contain message-digest OID"
        );
        assert!(
            attr_oids.contains(&APPLE_CDHASH_OID.to_string()),
            "Signed attributes should contain Apple CDHash v1 OID"
        );
        assert!(
            attr_oids.contains(&APPLE_CDHASH_V2_OID.to_string()),
            "Signed attributes should contain Apple CDHash v2 OID"
        );
    }

    #[test]
    fn test_sign_code_directory_ecdsa() {
        use crate::crypto::cert::{SigningCredentials, SigningKeyType};
        use cms::content_info::ContentInfo;
        use cms::signed_data::SignedData;
        use der::{Decode, Encode};
        use p256::ecdsa::SigningKey;
        use p256::elliptic_curve::rand_core::OsRng;
        use spki::{EncodePublicKey, SubjectPublicKeyInfoOwned};
        use std::str::FromStr;
        use std::time::Duration;
        use x509_cert::builder::{Builder, CertificateBuilder, Profile};
        use x509_cert::name::Name;
        use x509_cert::serial_number::SerialNumber;
        use x509_cert::time::Validity;

        let ecdsa_key = SigningKey::random(&mut OsRng);
        let verifying_key = p256::ecdsa::VerifyingKey::from(&ecdsa_key);

        let subject = Name::from_str("CN=ECDSA Test Signer,OU=TESTTEAM").unwrap();
        let serial = SerialNumber::from(43u32);
        let validity = Validity::from_now(Duration::from_secs(3600)).unwrap();
        let pub_key_der = verifying_key.to_public_key_der().unwrap();
        let pub_key = SubjectPublicKeyInfoOwned::from_der(pub_key_der.as_ref()).unwrap();

        let cert = CertificateBuilder::new(
            Profile::Root,
            serial,
            validity,
            subject,
            pub_key,
            &ecdsa_key,
        )
        .unwrap()
        .build::<p256::ecdsa::DerSignature>()
        .unwrap();

        let credentials = SigningCredentials {
            certificate: cert,
            signing_key: SigningKeyType::Ecdsa(ecdsa_key),
            cert_chain: vec![],
            team_id: Some("TESTTEAM".to_string()),
        };

        let code_dir_data = b"fake code directory data for ECDSA test";
        let cdhash_sha1: [u8; 20] = [0xCC; 20];
        let cdhash_sha256: [u8; 32] = [0xDD; 32];

        let cms_der =
            sign_code_directory(code_dir_data, &credentials, &cdhash_sha1, &cdhash_sha256).unwrap();

        let content_info = ContentInfo::from_der(&cms_der).unwrap();
        let signed_data = SignedData::from_der(&content_info.content.to_der().unwrap()).unwrap();

        assert!(signed_data.encap_content_info.econtent.is_none());
        assert_eq!(signed_data.signer_infos.0.len(), 1);

        let signer_info = signed_data.signer_infos.0.iter().next().unwrap();
        let signed_attrs = signer_info.signed_attrs.as_ref().unwrap();
        let attr_oids: Vec<String> = signed_attrs.iter().map(|a| a.oid.to_string()).collect();
        assert!(attr_oids.contains(&APPLE_CDHASH_OID.to_string()));
        assert!(attr_oids.contains(&APPLE_CDHASH_V2_OID.to_string()));
    }

    #[test]
    fn test_estimate_cms_size_rsa_2048() {
        let credentials = build_test_rsa_credentials(2048);
        let estimated = estimate_cms_size(&credentials);

        let code_dir = b"test code directory";
        let cdhash_sha1 = [0xAA; 20];
        let cdhash_sha256 = [0xBB; 32];
        let actual =
            sign_code_directory(code_dir, &credentials, &cdhash_sha1, &cdhash_sha256).unwrap();

        assert!(
            estimated >= actual.len(),
            "Estimate {} must be >= actual CMS size {} for RSA 2048",
            estimated,
            actual.len()
        );
    }

    #[test]
    fn test_estimate_cms_size_ecdsa() {
        let credentials = build_test_ecdsa_credentials();
        let estimated = estimate_cms_size(&credentials);

        let code_dir = b"test code directory";
        let cdhash_sha1 = [0xCC; 20];
        let cdhash_sha256 = [0xDD; 32];
        let actual =
            sign_code_directory(code_dir, &credentials, &cdhash_sha1, &cdhash_sha256).unwrap();

        assert!(
            estimated >= actual.len(),
            "Estimate {} must be >= actual CMS size {} for ECDSA P-256",
            estimated,
            actual.len()
        );
    }

    fn build_test_rsa_credentials(bits: usize) -> SigningCredentials {
        use crate::crypto::cert::{SigningCredentials, SigningKeyType};
        use der::Decode;
        use rsa::RsaPrivateKey;
        use spki::{EncodePublicKey, SubjectPublicKeyInfoOwned};
        use std::str::FromStr;
        use std::time::Duration;
        use x509_cert::builder::{Builder, CertificateBuilder, Profile};
        use x509_cert::name::Name;
        use x509_cert::serial_number::SerialNumber;
        use x509_cert::time::Validity;

        let mut rng = rand::thread_rng();
        let rsa_key = RsaPrivateKey::new(&mut rng, bits).unwrap();
        let signing_key = rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(rsa_key.clone());
        let subject = Name::from_str("CN=CMS Size Test,OU=TESTTEAM").unwrap();
        let serial = SerialNumber::from(99u32);
        let validity = Validity::from_now(Duration::from_secs(3600)).unwrap();
        let pub_key_der = rsa_key.to_public_key().to_public_key_der().unwrap();
        let pub_key = SubjectPublicKeyInfoOwned::from_der(pub_key_der.as_ref()).unwrap();
        let cert = CertificateBuilder::new(
            Profile::Root,
            serial,
            validity,
            subject,
            pub_key,
            &signing_key,
        )
        .unwrap()
        .build::<rsa::pkcs1v15::Signature>()
        .unwrap();

        SigningCredentials {
            certificate: cert,
            signing_key: SigningKeyType::Rsa(signing_key),
            cert_chain: vec![],
            team_id: Some("TESTTEAM".to_string()),
        }
    }

    #[test]
    fn test_estimate_cms_size_rsa_with_chain() {
        use crate::crypto::cert::{SigningCredentials, SigningKeyType};
        use der::Decode;
        use rsa::RsaPrivateKey;
        use spki::{EncodePublicKey, SubjectPublicKeyInfoOwned};
        use std::str::FromStr;
        use std::time::Duration;
        use x509_cert::builder::{Builder, CertificateBuilder, Profile};
        use x509_cert::name::Name;
        use x509_cert::serial_number::SerialNumber;
        use x509_cert::time::Validity;

        let mut rng = rand::thread_rng();

        // Build root CA
        let root_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let root_signing_key = rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(root_key.clone());
        let root_subject = Name::from_str("CN=Test Root CA,O=Test Corp").unwrap();
        let root_pub_der = root_key.to_public_key().to_public_key_der().unwrap();
        let root_pub = SubjectPublicKeyInfoOwned::from_der(root_pub_der.as_ref()).unwrap();
        let root_cert = CertificateBuilder::new(
            Profile::Root,
            SerialNumber::from(1u32),
            Validity::from_now(Duration::from_secs(7200)).unwrap(),
            root_subject,
            root_pub,
            &root_signing_key,
        )
        .unwrap()
        .build::<rsa::pkcs1v15::Signature>()
        .unwrap();

        // Build intermediate CA
        let inter_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let inter_signing_key = rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(inter_key.clone());
        let inter_subject = Name::from_str("CN=Test Intermediate CA,O=Test Corp").unwrap();
        let inter_pub_der = inter_key.to_public_key().to_public_key_der().unwrap();
        let inter_pub = SubjectPublicKeyInfoOwned::from_der(inter_pub_der.as_ref()).unwrap();
        let inter_cert = CertificateBuilder::new(
            Profile::Root,
            SerialNumber::from(2u32),
            Validity::from_now(Duration::from_secs(7200)).unwrap(),
            inter_subject,
            inter_pub,
            &inter_signing_key,
        )
        .unwrap()
        .build::<rsa::pkcs1v15::Signature>()
        .unwrap();

        // Build leaf signing cert
        let leaf_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let leaf_signing_key = rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(leaf_key.clone());
        let leaf_subject = Name::from_str("CN=Test Leaf,OU=TESTTEAM").unwrap();
        let leaf_pub_der = leaf_key.to_public_key().to_public_key_der().unwrap();
        let leaf_pub = SubjectPublicKeyInfoOwned::from_der(leaf_pub_der.as_ref()).unwrap();
        let leaf_cert = CertificateBuilder::new(
            Profile::Root,
            SerialNumber::from(3u32),
            Validity::from_now(Duration::from_secs(3600)).unwrap(),
            leaf_subject,
            leaf_pub,
            &leaf_signing_key,
        )
        .unwrap()
        .build::<rsa::pkcs1v15::Signature>()
        .unwrap();

        let credentials = SigningCredentials {
            certificate: leaf_cert,
            signing_key: SigningKeyType::Rsa(leaf_signing_key),
            cert_chain: vec![inter_cert, root_cert],
            team_id: Some("TESTTEAM".to_string()),
        };

        let estimated = estimate_cms_size(&credentials);

        let code_dir = b"test code directory with chain";
        let cdhash_sha1 = [0xEE; 20];
        let cdhash_sha256 = [0xFF; 32];
        let actual =
            sign_code_directory(code_dir, &credentials, &cdhash_sha1, &cdhash_sha256).unwrap();

        assert!(
            estimated >= actual.len(),
            "Estimate {} must be >= actual CMS size {} for RSA 2048 with 2-cert chain",
            estimated,
            actual.len()
        );
    }

    fn build_test_ecdsa_credentials() -> SigningCredentials {
        use crate::crypto::cert::{SigningCredentials, SigningKeyType};
        use der::Decode;
        use p256::ecdsa::SigningKey;
        use p256::elliptic_curve::rand_core::OsRng;
        use spki::{EncodePublicKey, SubjectPublicKeyInfoOwned};
        use std::str::FromStr;
        use std::time::Duration;
        use x509_cert::builder::{Builder, CertificateBuilder, Profile};
        use x509_cert::name::Name;
        use x509_cert::serial_number::SerialNumber;
        use x509_cert::time::Validity;

        let ecdsa_key = SigningKey::random(&mut OsRng);
        let verifying_key = p256::ecdsa::VerifyingKey::from(&ecdsa_key);
        let subject = Name::from_str("CN=CMS Size Test ECDSA,OU=TESTTEAM").unwrap();
        let serial = SerialNumber::from(100u32);
        let validity = Validity::from_now(Duration::from_secs(3600)).unwrap();
        let pub_key_der = verifying_key.to_public_key_der().unwrap();
        let pub_key = SubjectPublicKeyInfoOwned::from_der(pub_key_der.as_ref()).unwrap();
        let cert = CertificateBuilder::new(
            Profile::Root,
            serial,
            validity,
            subject,
            pub_key,
            &ecdsa_key,
        )
        .unwrap()
        .build::<p256::ecdsa::DerSignature>()
        .unwrap();

        SigningCredentials {
            certificate: cert,
            signing_key: SigningKeyType::Ecdsa(ecdsa_key),
            cert_chain: vec![],
            team_id: Some("TESTTEAM".to_string()),
        }
    }
}
