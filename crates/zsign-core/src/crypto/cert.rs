//! Certificate and private key handling for code signing.
//!
//! This module loads signing credentials from PEM-encoded files or PKCS#12 (.p12)
//! containers. It supports RSA and ECDSA (P-256) private keys commonly used in
//! Apple code signing certificates.
//!
//! # Supported Formats
//!
//! - **PEM**: Separate certificate and private key files (unencrypted keys only)
//! - **PKCS#12**: Combined certificate and key in a password-protected container
//!
//! # Examples
//!
//! ```ignore
//! use zsign_core::crypto::SigningCredentials;
//!
//! // Load from PKCS#12 file (recommended)
//! let p12_data = std::fs::read("certificate.p12")?;
//! let credentials = SigningCredentials::from_p12(&p12_data, "password")?;
//!
//! // Load from PEM files
//! let cert_pem = std::fs::read("certificate.pem")?;
//! let key_pem = std::fs::read("private_key.pem")?;
//! let credentials = SigningCredentials::from_pem(&cert_pem, &key_pem, None)?;
//! # Ok::<(), zsign_core::Error>(())
//! ```

use crate::{Error, Result};
use der::{Decode, DecodePem};
use p256::ecdsa::SigningKey as EcdsaSigningKey;
use rsa::RsaPrivateKey;
use x509_cert::Certificate;

/// Private key for code signing, supporting multiple key types.
///
/// Apple code signing certificates typically use either RSA or ECDSA keys.
/// This enum abstracts over both types to provide a unified signing interface.
///
/// # Variants
///
/// * [`Rsa`](SigningKeyType::Rsa) - RSA private key (commonly 2048 or 4096 bits)
/// * [`Ecdsa`](SigningKeyType::Ecdsa) - ECDSA P-256 private key (secp256r1)
#[allow(clippy::large_enum_variant)]
pub enum SigningKeyType {
    /// RSA PKCS#1 v1.5 signing key with SHA-256 digest, pre-built for signing.
    ///
    /// RSA keys are the traditional choice for Apple code signing and are
    /// widely supported across all iOS versions.
    Rsa(rsa::pkcs1v15::SigningKey<sha2::Sha256>),

    /// ECDSA P-256 (secp256r1) private key for signing operations.
    ///
    /// ECDSA keys provide equivalent security with smaller key sizes and
    /// faster signing operations compared to RSA.
    Ecdsa(EcdsaSigningKey),
}

/// Code signing credentials containing certificate, private key, and certificate chain.
///
/// This struct holds all the cryptographic material needed to sign iOS applications:
/// - The signing certificate identifying the developer
/// - The private key for creating signatures
/// - Intermediate CA certificates for chain verification
/// - The extracted Apple Team ID
///
/// # Examples
///
/// ```ignore
/// use zsign_core::crypto::SigningCredentials;
///
/// let p12_data = std::fs::read("certificate.p12")?;
/// let credentials = SigningCredentials::from_p12(&p12_data, "password")?;
///
/// // Access the team ID
/// println!("Team ID: {:?}", credentials.team_id);
/// # Ok::<(), zsign_core::Error>(())
/// ```
///
/// # Security
///
/// The private key contained in this struct should be treated as sensitive data.
/// Avoid logging or exposing [`SigningCredentials`] instances.
pub struct SigningCredentials {
    /// X.509 signing certificate identifying the developer or organization.
    pub certificate: Certificate,

    /// Private key corresponding to the certificate's public key.
    pub signing_key: SigningKeyType,

    /// Intermediate CA certificates for building the certificate chain.
    ///
    /// These certificates connect the signing certificate to the Apple Root CA.
    pub cert_chain: Vec<Certificate>,

    /// Apple Team ID extracted from the certificate's Organizational Unit (OU) field.
    ///
    /// This is a 10-character alphanumeric identifier assigned by Apple to
    /// each developer or organization.
    pub team_id: Option<String>,
}

/// A PKCS#8 private key decoded to a form that can be SPKI-matched against certificates.
enum DecodedKey {
    Rsa(RsaPrivateKey),
    Ecdsa(EcdsaSigningKey),
}

impl DecodedKey {
    fn from_pkcs8_der(der: &[u8]) -> Option<Self> {
        use pkcs8::DecodePrivateKey;
        if let Ok(k) = RsaPrivateKey::from_pkcs8_der(der) {
            return Some(Self::Rsa(k));
        }
        EcdsaSigningKey::from_pkcs8_der(der).ok().map(Self::Ecdsa)
    }

    fn from_pkcs8_pem(pem: &str) -> Option<Self> {
        use pkcs8::DecodePrivateKey;
        if let Ok(k) = RsaPrivateKey::from_pkcs8_pem(pem) {
            return Some(Self::Rsa(k));
        }
        EcdsaSigningKey::from_pkcs8_pem(pem).ok().map(Self::Ecdsa)
    }

    /// DER-encoded SubjectPublicKeyInfo — the pairing identity, byte-compared
    /// exactly like `verify_key_matches_cert` compares key and certificate.
    fn spki_der(&self) -> Result<Vec<u8>> {
        use spki::EncodePublicKey;
        let der = match self {
            Self::Rsa(k) => rsa::RsaPublicKey::from(k).to_public_key_der(),
            Self::Ecdsa(k) => p256::ecdsa::VerifyingKey::from(k).to_public_key_der(),
        }
        .map_err(|e| Error::Certificate(format!("Failed to encode public key: {}", e)))?;
        Ok(der.to_vec())
    }

    fn into_signing_key(self) -> Result<SigningKeyType> {
        Ok(match self {
            Self::Rsa(k) => SigningKeyType::Rsa(rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(k)),
            Self::Ecdsa(k) => SigningKeyType::Ecdsa(k),
        })
    }
}

/// Selects the unique key/certificate pair by matching every decoded key's SPKI
/// against every parseable certificate.
///
/// Returns the selected key, the leaf certificate, and the remaining parsed
/// certificates for chain assembly. Unparseable keys/certificates are skipped;
/// zero matches and multiple distinct identities are errors.
fn select_identity(
    keys: &[Vec<u8>],
    certs: &[Vec<u8>],
) -> Result<(DecodedKey, Certificate, Vec<Certificate>)> {
    // cert.rs imports der::{Decode, DecodePem} only; to_der() below needs Encode.
    use der::Encode;

    let decoded: Vec<Option<DecodedKey>> =
        keys.iter().map(|d| DecodedKey::from_pkcs8_der(d)).collect();
    let parsed: Vec<Option<Certificate>> = certs
        .iter()
        .map(|d| Certificate::from_der(d).ok())
        .collect();
    if !certs.is_empty() && parsed.iter().all(Option::is_none) {
        return Err(Error::Certificate(
            "No parseable certificate in PKCS#12".into(),
        ));
    }

    let mut pairs: Vec<(usize, usize)> = Vec::new();
    for (i, key) in decoded.iter().enumerate() {
        let Some(key) = key else { continue };
        let Ok(key_spki) = key.spki_der() else {
            continue;
        };
        for (j, cert) in parsed.iter().enumerate() {
            let Some(cert) = cert else { continue };
            let Ok(cert_spki) = cert.tbs_certificate.subject_public_key_info.to_der() else {
                continue;
            };
            if cert_spki == key_spki {
                pairs.push((i, j));
            }
        }
    }

    // Duplicate bags of the same key+certificate collapse to one identity.
    let mut distinct: Vec<(usize, usize)> = Vec::new();
    for &(i, j) in &pairs {
        let dup = distinct
            .iter()
            .any(|&(i2, j2)| keys[i] == keys[i2] && certs[j] == certs[j2]);
        if !dup {
            distinct.push((i, j));
        }
    }

    match distinct.len() {
        0 => Err(Error::Certificate(format!(
            "PKCS#12 contains no certificate matching its {} private key(s); {} certificate(s) present",
            keys.len(),
            certs.len()
        ))),
        1 => {
            let (i, j) = distinct[0];
            let leaf = parsed[j].clone().expect("matched certificate parsed above");
            let key = decoded
                .into_iter()
                .nth(i)
                .flatten()
                .expect("matched key decoded above");
            let rest = parsed
                .iter()
                .enumerate()
                .filter_map(|(idx, c)| if idx != j { c.clone() } else { None })
                .collect();
            Ok((key, leaf, rest))
        }
        n => {
            let described: Vec<String> = distinct
                .iter()
                .map(|&(_, j)| {
                    let c = parsed[j].as_ref().expect("parsed");
                    let serial: String = c
                        .tbs_certificate
                        .serial_number
                        .as_bytes()
                        .iter()
                        .map(|b| format!("{:02X}", b))
                        .collect();
                    format!("{} (serial 0x{})", c.tbs_certificate.subject, serial)
                })
                .collect();
            Err(Error::Certificate(format!(
                "PKCS#12 contains {} identities: {}; expected exactly one key/certificate pair",
                n,
                described.join(", ")
            )))
        }
    }
}

/// Assembles the chain below `leaf` by issuer/subject links over `rest`,
/// then completes it with the embedded Apple material only where missing.
///
/// Unrelated certificates fall out of the walk. The embedded WWDR intermediate
/// is injected only when no provided certificate links to the leaf's issuer and
/// the issuer is an Apple WWDR CA; the Apple Root CA is appended only when a
/// WWDR intermediate is in the chain and the root is not already present.
fn build_chain_from_leaf(leaf: &Certificate, mut rest: Vec<Certificate>) -> Vec<Certificate> {
    let mut chain: Vec<Certificate> = Vec::new();
    let mut current = leaf.clone();
    loop {
        if current.tbs_certificate.subject == current.tbs_certificate.issuer {
            break;
        }
        let Some(pos) = rest
            .iter()
            .position(|c| c.tbs_certificate.subject == current.tbs_certificate.issuer)
        else {
            break;
        };
        current = rest.remove(pos);
        chain.push(current.clone());
    }

    let links_leaf = chain
        .iter()
        .any(|c| c.tbs_certificate.subject == leaf.tbs_certificate.issuer);
    if !links_leaf {
        if let Some(wwdr) = embedded_wwdr_for_leaf(leaf) {
            chain.push(wwdr);
        }
    }

    let has_wwdr = chain.iter().any(|c| {
        extract_subject_cn(c).is_some_and(|cn| cn.contains("Apple Worldwide Developer Relations"))
    });
    if has_wwdr && !chain.iter().any(|c| is_apple_root(c)) {
        if let Ok(root) = Certificate::from_pem(super::assets::APPLE_ROOT_CA_CERT.as_bytes()) {
            chain.push(root);
        }
    }
    chain
}

/// The embedded Apple WWDR intermediate matching `leaf`'s issuer, if the
/// issuer identifies an Apple WWDR CA.
fn embedded_wwdr_for_leaf(leaf: &Certificate) -> Option<Certificate> {
    use super::assets::{APPLE_WWDR_CA_CERT, APPLE_WWDR_CA_G3_CERT};
    let issuer_cn = extract_issuer_cn(leaf).unwrap_or_default();
    if !issuer_cn.contains("Apple Worldwide Developer Relations") {
        return None;
    }
    let pem = if extract_issuer_ou(leaf).unwrap_or_default() == "G3" {
        APPLE_WWDR_CA_G3_CERT
    } else {
        APPLE_WWDR_CA_CERT
    };
    Certificate::from_pem(pem.as_bytes()).ok()
}

fn is_apple_root(cert: &Certificate) -> bool {
    extract_subject_cn(cert).is_some_and(|cn| cn == "Apple Root CA")
}

impl SigningCredentials {
    /// Load credentials from PEM-encoded certificate and private key.
    ///
    /// Parses a PEM-encoded X.509 certificate and PKCS#8 private key. The private
    /// key must be unencrypted; encrypted PEM keys are not currently supported.
    ///
    /// # Arguments
    ///
    /// * `cert_pem` - PEM-encoded X.509 certificate
    /// * `key_pem` - PEM-encoded PKCS#8 private key (RSA or ECDSA)
    /// * `password` - Reserved for future encrypted key support (must be `None`)
    ///
    /// # Errors
    ///
    /// Returns [`Error::Certificate`] if:
    /// - The certificate PEM is malformed or invalid
    /// - The private key PEM is malformed or not valid PKCS#8
    /// - The private key is neither RSA nor ECDSA P-256
    /// - A password is provided (encrypted keys not yet supported)
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use zsign_core::crypto::SigningCredentials;
    ///
    /// let cert_pem = std::fs::read("certificate.pem")?;
    /// let key_pem = std::fs::read("private_key.pem")?;
    /// let credentials = SigningCredentials::from_pem(&cert_pem, &key_pem, None)?;
    /// # Ok::<(), zsign_core::Error>(())
    /// ```
    pub fn from_pem(cert_pem: &[u8], key_pem: &[u8], password: Option<&str>) -> Result<Self> {
        let certificate = Certificate::from_pem(cert_pem)
            .map_err(|e| Error::Certificate(format!("Failed to parse certificate PEM: {}", e)))?;

        let key_str = std::str::from_utf8(key_pem)
            .map_err(|e| Error::Certificate(format!("Invalid UTF-8 in key PEM: {}", e)))?;

        // The password rejection moves out of the decode expression into a
        // standalone guard (same message, same position in the flow): the old
        // `if let ... else if ... else` chain is being replaced wholesale, so the
        // gate cannot stay embedded in it.
        if password.is_some() {
            return Err(Error::Certificate(
                "Encrypted PEM keys are not yet supported. Use unencrypted keys or PKCS#12.".into(),
            ));
        }
        let decoded = DecodedKey::from_pkcs8_pem(key_str).ok_or_else(|| {
            Error::Certificate("Failed to parse private key as RSA or ECDSA".into())
        })?;
        let signing_key = decoded.into_signing_key()?;

        let team_id = extract_team_id(&certificate);
        let cert_chain = build_chain_from_leaf(&certificate, Vec::new());

        verify_key_matches_cert(&signing_key, &certificate)?;

        Ok(Self {
            certificate,
            signing_key,
            cert_chain,
            team_id,
        })
    }

    /// Load credentials from a PKCS#12 (.p12) container.
    ///
    /// Parses a PKCS#12 file and matches the private key to the certificate by
    /// public key, independent of bag order. The container may also include
    /// intermediate CA certificates. This is the recommended format for Apple
    /// code signing credentials exported from Keychain Access.
    ///
    /// # Arguments
    ///
    /// * `p12_data` - Raw bytes of the PKCS#12 file
    /// * `password` - Password used to decrypt the PKCS#12 container
    ///
    /// # Errors
    ///
    /// Returns [`Error::Certificate`] if:
    /// - The PKCS#12 data is malformed
    /// - The password is incorrect
    /// - No certificate is found in the container
    /// - No private key is found in the container
    /// - The private key is neither RSA nor ECDSA P-256
    /// - No private key matches a certificate
    /// - More than one distinct key/certificate identity is present
    ///
    /// # Security
    ///
    /// The password is used only during parsing and is not stored in the
    /// returned [`SigningCredentials`].
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use zsign_core::crypto::SigningCredentials;
    ///
    /// let p12_data = std::fs::read("certificate.p12")?;
    /// let credentials = SigningCredentials::from_p12(&p12_data, "password")?;
    /// # Ok::<(), zsign_core::Error>(())
    /// ```
    pub fn from_p12(p12_data: &[u8], password: &str) -> Result<Self> {
        let contents = super::pkcs12::extract_p12(p12_data, password)
            .map_err(|e| Error::Certificate(format!("Failed to parse PKCS#12: {}", e)))?;
        let keys = contents.keys;
        let certs = contents.certs;

        if certs.is_empty() {
            return Err(Error::Certificate("No certificate in PKCS#12".into()));
        }
        if keys.is_empty() {
            return Err(Error::Certificate("No private key in PKCS#12".into()));
        }

        let (decoded, certificate, rest) = select_identity(&keys, &certs)?;
        let signing_key = decoded.into_signing_key()?;
        let cert_chain = build_chain_from_leaf(&certificate, rest);
        let team_id = extract_team_id(&certificate);

        Ok(Self {
            certificate,
            signing_key,
            cert_chain,
            team_id,
        })
    }
}

/// Extracts a string attribute from an X.509 Name by OID.
///
/// Tries both UTF-8 and PrintableString encodings, matching Apple certificate conventions.
fn extract_name_attr(
    name: &x509_cert::name::Name,
    oid: const_oid::ObjectIdentifier,
) -> Option<String> {
    for rdn in name.0.iter() {
        for atav in rdn.0.iter() {
            if atav.oid == oid {
                if let Ok(s) = der::asn1::Utf8StringRef::try_from(&atav.value) {
                    return Some(s.as_str().to_string());
                }
                if let Ok(s) = der::asn1::PrintableStringRef::try_from(&atav.value) {
                    return Some(s.as_str().to_string());
                }
            }
        }
    }
    None
}

/// Extracts the Organizational Unit (OU) from a certificate's issuer.
fn extract_issuer_ou(cert: &Certificate) -> Option<String> {
    extract_name_attr(
        &cert.tbs_certificate.issuer,
        const_oid::db::rfc4519::ORGANIZATIONAL_UNIT_NAME,
    )
}

/// Extracts the Common Name (CN) from a certificate's issuer.
fn extract_issuer_cn(cert: &Certificate) -> Option<String> {
    extract_name_attr(
        &cert.tbs_certificate.issuer,
        const_oid::db::rfc4519::COMMON_NAME,
    )
}

/// Verifies that the private key matches the certificate's public key.
///
/// Compares the DER-encoded Subject Public Key Info from the certificate with
/// the public key derived from the private key. Returns an error if they differ.
fn verify_key_matches_cert(key: &SigningKeyType, cert: &Certificate) -> Result<()> {
    use der::Encode;
    use spki::EncodePublicKey;

    let cert_spki = &cert.tbs_certificate.subject_public_key_info;
    let cert_pub_bytes = cert_spki
        .to_der()
        .map_err(|e| Error::Certificate(format!("Failed to encode cert public key: {}", e)))?;

    let key_pub_bytes = match key {
        SigningKeyType::Rsa(signing_key) => {
            use signature::Keypair;
            signing_key
                .verifying_key()
                .to_public_key_der()
                .map_err(|e| Error::Certificate(format!("Failed to encode RSA public key: {}", e)))?
                .to_vec()
        }
        SigningKeyType::Ecdsa(ecdsa_key) => {
            use p256::ecdsa::VerifyingKey;
            let verifying_key = VerifyingKey::from(ecdsa_key);
            verifying_key
                .to_public_key_der()
                .map_err(|e| {
                    Error::Certificate(format!("Failed to encode ECDSA public key: {}", e))
                })?
                .to_vec()
        }
    };

    if cert_pub_bytes != key_pub_bytes {
        return Err(Error::Certificate(
            "Private key does not match certificate's public key".into(),
        ));
    }
    Ok(())
}

/// Extracts the Apple Team ID from a certificate's Organizational Unit field.
fn extract_team_id(cert: &Certificate) -> Option<String> {
    extract_name_attr(
        &cert.tbs_certificate.subject,
        const_oid::db::rfc4519::ORGANIZATIONAL_UNIT_NAME,
    )
}

/// Extracts the Common Name (CN) from a certificate's subject.
pub(crate) fn extract_subject_cn(cert: &Certificate) -> Option<String> {
    extract_name_attr(
        &cert.tbs_certificate.subject,
        const_oid::db::rfc4519::COMMON_NAME,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    use const_oid::ObjectIdentifier;
    use der::Decode;
    use spki::SubjectPublicKeyInfoOwned;
    use x509_cert::ext::pkix::ExtendedKeyUsage;
    use x509_cert::serial_number::SerialNumber;
    use x509_cert::time::{Time, Validity};

    const IDENTITY_SINGLE: &[u8] = include_bytes!("fixtures/identity_single.p12");
    const IDENTITY_DUP: &[u8] = include_bytes!("fixtures/identity_duplicate_certs.p12");

    fn fresh_2048() -> rsa::RsaPrivateKey {
        rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap()
    }

    /// RFC-style validity window from unix seconds.
    fn window(not_before: i64, not_after: i64) -> Validity {
        Validity {
            not_before: Time::UtcTime(
                der::asn1::UtcTime::from_unix_duration(std::time::Duration::from_secs(
                    not_before as u64,
                ))
                .unwrap(),
            ),
            not_after: Time::UtcTime(
                der::asn1::UtcTime::from_unix_duration(std::time::Duration::from_secs(
                    not_after as u64,
                ))
                .unwrap(),
            ),
        }
    }

    /// A window containing today (Nov 2023 → Nov 2039).
    fn present() -> Validity {
        window(1_700_000_000, 2_200_000_000)
    }

    /// Builds a certificate for `subject` signed by `issuer_key` (which may be the
    /// subject's own key). Signatures are irrelevant to every helper under test —
    /// pairing compares SPKIs and the chain walk compares names.
    fn build_cert(
        subject: &str,
        issuer: &str,
        subject_key: &rsa::RsaPrivateKey,
        issuer_key: &rsa::RsaPrivateKey,
        validity: Validity,
        eku: Option<ExtendedKeyUsage>,
    ) -> Certificate {
        use spki::EncodePublicKey;
        use std::str::FromStr;
        use x509_cert::builder::{Builder, CertificateBuilder, Profile};
        use x509_cert::name::Name;

        let spki = SubjectPublicKeyInfoOwned::from_der(
            subject_key
                .to_public_key()
                .to_public_key_der()
                .unwrap()
                .as_ref(),
        )
        .unwrap();
        // The builder borrows the signer, so bind it first — a temporary would be
        // dropped before `add_extension`/`build` (E0716).
        let signer = rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(issuer_key.clone());
        let mut b = CertificateBuilder::new(
            Profile::Leaf {
                issuer: Name::from_str(issuer).unwrap(),
                enable_key_agreement: false,
                enable_key_encipherment: false,
            },
            SerialNumber::from(7u32),
            validity,
            Name::from_str(subject).unwrap(),
            spki,
            &signer,
        )
        .unwrap();
        if let Some(eku) = &eku {
            b.add_extension(eku).unwrap();
        }
        b.build::<rsa::pkcs1v15::Signature>().unwrap()
    }

    fn der_of(cert: &Certificate) -> Vec<u8> {
        use der::Encode;
        cert.to_der().unwrap()
    }

    fn pkcs8_of(key: &rsa::RsaPrivateKey) -> Vec<u8> {
        use pkcs8::EncodePrivateKey;
        key.to_pkcs8_der().unwrap().as_bytes().to_vec()
    }

    /// PEM-encodes a certificate + private key for `from_pem`.
    fn leaf_pems(cert: &Certificate, key: &rsa::RsaPrivateKey) -> (Vec<u8>, Vec<u8>) {
        use der::{pem::LineEnding, EncodePem};
        use pkcs8::EncodePrivateKey;
        (
            cert.to_pem(LineEnding::LF).unwrap().into_bytes(),
            key.to_pkcs8_pem(Default::default())
                .unwrap()
                .as_bytes()
                .to_vec(),
        )
    }

    #[test]
    fn test_from_pem_invalid_cert() {
        let result = SigningCredentials::from_pem(b"not a cert", b"not a key", None);
        assert!(result.is_err());
    }

    #[test]
    fn test_from_p12_invalid_data() {
        let result = SigningCredentials::from_p12(b"not valid p12 data", "password");
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_team_id_from_apple_wwdr_cert() {
        use crate::crypto::assets::APPLE_WWDR_CA_G3_CERT;

        let cert = Certificate::from_pem(APPLE_WWDR_CA_G3_CERT.as_bytes()).unwrap();
        let team_id = extract_team_id(&cert);
        assert_eq!(team_id, Some("G3".to_string()));
    }

    #[test]
    fn test_extract_subject_cn_from_apple_wwdr_cert() {
        use crate::crypto::assets::APPLE_WWDR_CA_G3_CERT;

        let cert = Certificate::from_pem(APPLE_WWDR_CA_G3_CERT.as_bytes()).unwrap();
        let cn = extract_subject_cn(&cert);
        assert!(cn.is_some());
        assert!(cn.unwrap().contains("Apple Worldwide Developer Relations"));
    }

    #[test]
    fn test_extract_issuer_cn_from_apple_wwdr_cert() {
        use crate::crypto::assets::APPLE_WWDR_CA_G3_CERT;

        let cert = Certificate::from_pem(APPLE_WWDR_CA_G3_CERT.as_bytes()).unwrap();
        let cn = extract_issuer_cn(&cert);
        assert!(cn.is_some());
        assert!(cn.unwrap().contains("Apple Root CA"));
    }

    #[test]
    fn select_identity_picks_matching_pair_regardless_of_order() {
        let k1 = fresh_2048();
        let k2 = fresh_2048();
        let cert1 = build_cert("CN=zsn k1", "CN=zsn k1", &k1, &k1, present(), None);
        let cert2 = build_cert("CN=zsn k2", "CN=zsn k2", &k2, &k2, present(), None);
        // Unrelated certificate FIRST — the ordering openssl cannot produce.
        let keys = vec![pkcs8_of(&k1)];
        let certs = vec![der_of(&cert2), der_of(&cert1)];
        let (_key, leaf, rest) = select_identity(&keys, &certs).expect("pair exists");
        assert_eq!(leaf.tbs_certificate.subject, cert1.tbs_certificate.subject);
        assert_eq!(rest.len(), 1, "only the unrelated certificate remains");
        assert_eq!(
            rest[0].tbs_certificate.subject,
            cert2.tbs_certificate.subject
        );
    }

    #[test]
    fn select_identity_reports_no_match() {
        let k1 = fresh_2048();
        let k2 = fresh_2048();
        let cert2 = build_cert("CN=zsn k2", "CN=zsn k2", &k2, &k2, present(), None);
        let keys = vec![pkcs8_of(&k1)];
        let certs = vec![der_of(&cert2)];
        let res = select_identity(&keys, &certs);
        assert!(
            matches!(&res, Err(Error::Certificate(m))
                if m.contains("no certificate") && m.contains("1 private key")),
            "expected no-match rejection, got {:?}",
            res.as_ref().err()
        );
    }

    #[test]
    fn from_p12_rejects_ambiguous_identity() {
        let res = SigningCredentials::from_p12(IDENTITY_DUP, "testpassword");
        assert!(
            matches!(&res, Err(Error::Certificate(m))
                if m.contains("2 identities") && m.contains("CN=zsign-test-fixture")),
            "expected ambiguous-identity rejection, got {:?}",
            res.as_ref().err()
        );
    }

    #[test]
    fn from_p12_selects_single_identity_with_empty_chain() {
        let creds = SigningCredentials::from_p12(IDENTITY_SINGLE, "testpassword")
            .expect("unique pair must load");
        assert_eq!(
            creds.certificate.tbs_certificate.subject.to_string(),
            "CN=zsign-test-fixture"
        );
        assert!(
            creds.cert_chain.is_empty(),
            "self-signed non-Apple leaf must not receive the Apple Root CA"
        );
    }

    #[test]
    fn from_pem_self_signed_leaf_yields_empty_chain() {
        let key = fresh_2048();
        // codeSigning EKU inline (the production OID constant lands in Task 2): keeps
        // this loader test policy-compliant so Task 2's gate does not break it.
        let eku = ExtendedKeyUsage(vec![ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.3")]);
        let cert = build_cert(
            "CN=zsn pem self",
            "CN=zsn pem self",
            &key,
            &key,
            present(),
            Some(eku),
        );
        let (cert_pem, key_pem) = leaf_pems(&cert, &key);
        let creds = SigningCredentials::from_pem(&cert_pem, &key_pem, None)
            .expect("policy-compliant self-signed leaf must load");
        assert!(creds.cert_chain.is_empty());
    }

    #[test]
    fn chain_walk_orders_by_issuer_and_ignores_unrelated() {
        let root_key = fresh_2048();
        let int_key = fresh_2048();
        let leaf_key = fresh_2048();
        let unrelated_key = fresh_2048();
        let root = build_cert(
            "CN=zsn root",
            "CN=zsn root",
            &root_key,
            &root_key,
            present(),
            None,
        );
        let int = build_cert(
            "CN=zsn int",
            "CN=zsn root",
            &int_key,
            &root_key,
            present(),
            None,
        );
        let leaf = build_cert(
            "CN=zsn leaf",
            "CN=zsn int",
            &leaf_key,
            &int_key,
            present(),
            None,
        );
        let unrelated = build_cert(
            "CN=zsn unrelated",
            "CN=zsn unrelated",
            &unrelated_key,
            &unrelated_key,
            present(),
            None,
        );
        let chain =
            build_chain_from_leaf(&leaf, vec![unrelated.clone(), int.clone(), root.clone()]);
        assert_eq!(chain.len(), 2, "walk stops at the self-signed root");
        assert_eq!(
            chain[0].tbs_certificate.subject,
            int.tbs_certificate.subject
        );
        assert_eq!(
            chain[1].tbs_certificate.subject,
            root.tbs_certificate.subject
        );
    }

    #[test]
    fn self_signed_leaf_yields_empty_chain() {
        let k = fresh_2048();
        let leaf = build_cert("CN=zsn self", "CN=zsn self", &k, &k, present(), None);
        assert!(build_chain_from_leaf(&leaf, vec![]).is_empty());
    }

    #[test]
    fn wwdr_issuer_injects_missing_intermediate_and_root() {
        let k = fresh_2048();
        let leaf = build_cert(
            "CN=zsn wwdr leaf",
            "OU=G3,CN=Apple Worldwide Developer Relations CA,O=Apple Inc.,C=US",
            &k,
            &k,
            present(),
            None,
        );
        let chain = build_chain_from_leaf(&leaf, vec![]);
        assert_eq!(chain.len(), 2, "embedded WWDR intermediate + Apple Root");
        assert!(chain[0]
            .tbs_certificate
            .subject
            .to_string()
            .contains("Apple Worldwide Developer Relations"));
        assert_eq!(
            extract_subject_cn(&chain[1]).as_deref(),
            Some("Apple Root CA"),
            "the embedded Apple Root CA completes the chain"
        );
    }

    #[test]
    fn provided_chain_is_completed_without_duplicates() {
        let root_key = fresh_2048();
        let int_key = fresh_2048();
        let leaf_key = fresh_2048();
        let root = build_cert(
            "CN=Apple Root CA",
            "CN=Apple Root CA",
            &root_key,
            &root_key,
            present(),
            None,
        );
        let int = build_cert(
            "CN=Apple Worldwide Developer Relations CA,O=Apple Inc.,C=US",
            "CN=Apple Root CA",
            &int_key,
            &root_key,
            present(),
            None,
        );
        let leaf = build_cert(
            "CN=zsn full chain leaf",
            "CN=Apple Worldwide Developer Relations CA,O=Apple Inc.,C=US",
            &leaf_key,
            &int_key,
            present(),
            None,
        );
        // Provided chain already has WWDR + Root: nothing injected, nothing duplicated.
        let chain = build_chain_from_leaf(&leaf, vec![root.clone(), int.clone()]);
        assert_eq!(chain.len(), 2, "nothing injected or duplicated");
        assert_eq!(
            chain[0].tbs_certificate.subject, int.tbs_certificate.subject,
            "walk starts at the WWDR intermediate"
        );
        assert_eq!(
            chain[1].tbs_certificate.subject, root.tbs_certificate.subject,
            "walk continues to the provided root"
        );
    }
}
