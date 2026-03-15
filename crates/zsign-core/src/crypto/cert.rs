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
    /// RSA private key for signing operations.
    ///
    /// RSA keys are the traditional choice for Apple code signing and are
    /// widely supported across all iOS versions.
    Rsa(RsaPrivateKey),

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
        use pkcs8::DecodePrivateKey;

        let certificate = Certificate::from_pem(cert_pem)
            .map_err(|e| Error::Certificate(format!("Failed to parse certificate PEM: {}", e)))?;

        let key_str = std::str::from_utf8(key_pem)
            .map_err(|e| Error::Certificate(format!("Invalid UTF-8 in key PEM: {}", e)))?;

        let signing_key = if let Some(_pass) = password {
            return Err(Error::Certificate(
                "Encrypted PEM keys are not yet supported. Use unencrypted keys or PKCS#12.".into(),
            ));
        } else if let Ok(rsa_key) = RsaPrivateKey::from_pkcs8_pem(key_str) {
            SigningKeyType::Rsa(rsa_key)
        } else if let Ok(ecdsa_key) = EcdsaSigningKey::from_pkcs8_pem(key_str) {
            SigningKeyType::Ecdsa(ecdsa_key)
        } else {
            return Err(Error::Certificate(
                "Failed to parse private key as RSA or ECDSA".into(),
            ));
        };

        let team_id = extract_team_id(&certificate);
        let cert_chain = build_apple_ca_chain(&certificate);

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
    /// Parses a PKCS#12 file containing the signing certificate, private key,
    /// and optional intermediate CA certificates. This is the recommended format
    /// for Apple code signing credentials exported from Keychain Access.
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
        let pfx = p12::PFX::parse(p12_data)
            .map_err(|e| Error::Certificate(format!("Failed to parse PKCS#12: {:?}", e)))?;

        let keys = pfx
            .key_bags(password)
            .map_err(|e| Error::Certificate(format!("Failed to extract keys from PKCS#12: {:?}", e)))?;

        let certs = pfx
            .cert_x509_bags(password)
            .map_err(|e| Error::Certificate(format!("Failed to extract certs from PKCS#12: {:?}", e)))?;

        if certs.is_empty() {
            return Err(Error::Certificate("No certificate in PKCS#12".into()));
        }
        if keys.is_empty() {
            return Err(Error::Certificate("No private key in PKCS#12".into()));
        }

        let cert_der = &certs[0];
        let certificate = Certificate::from_der(cert_der)
            .map_err(|e| Error::Certificate(format!("Failed to parse certificate DER: {}", e)))?;

        let key_der = &keys[0];
        let signing_key = Self::parse_private_key_der(key_der)?;

        let mut cert_chain: Vec<Certificate> = certs
            .iter()
            .skip(1)
            .filter_map(|der| Certificate::from_der(der).ok())
            .collect();

        // If the P12 doesn't include the Apple CA chain, add it automatically
        if cert_chain.is_empty() {
            cert_chain = build_apple_ca_chain(&certificate);
        }

        let team_id = extract_team_id(&certificate);

        verify_key_matches_cert(&signing_key, &certificate)?;

        Ok(Self {
            certificate,
            signing_key,
            cert_chain,
            team_id,
        })
    }

    fn parse_private_key_der(der: &[u8]) -> Result<SigningKeyType> {
        use pkcs8::DecodePrivateKey;

        if let Ok(rsa_key) = RsaPrivateKey::from_pkcs8_der(der) {
            return Ok(SigningKeyType::Rsa(rsa_key));
        }

        if let Ok(ecdsa_key) = EcdsaSigningKey::from_pkcs8_der(der) {
            return Ok(SigningKeyType::Ecdsa(ecdsa_key));
        }

        Err(Error::Certificate(
            "Failed to parse private key as RSA or ECDSA".into(),
        ))
    }
}

/// Builds the Apple CA certificate chain for a signing certificate.
///
/// Matches the C++ zsign behavior: selects the appropriate Apple WWDR intermediate
/// CA certificate (legacy or G3) based on the signing certificate's issuer, and
/// includes the Apple Root CA.
fn build_apple_ca_chain(signing_cert: &Certificate) -> Vec<Certificate> {
    use super::assets::{APPLE_ROOT_CA_CERT, APPLE_WWDR_CA_CERT, APPLE_WWDR_CA_G3_CERT};

    let issuer_ou = extract_issuer_ou(signing_cert).unwrap_or_default();
    let issuer_cn = extract_issuer_cn(signing_cert).unwrap_or_default();

    let is_wwdr = issuer_cn.contains("Apple Worldwide Developer Relations");

    let wwdr_pem = if !is_wwdr {
        None
    } else if issuer_ou == "G3" {
        Some(APPLE_WWDR_CA_G3_CERT)
    } else {
        Some(APPLE_WWDR_CA_CERT)
    };

    let mut chain = Vec::new();

    if let Some(pem) = wwdr_pem {
        if let Ok(cert) = Certificate::from_pem(pem.as_bytes()) {
            chain.push(cert);
        }
    }

    if let Ok(root) = Certificate::from_pem(APPLE_ROOT_CA_CERT.as_bytes()) {
        chain.push(root);
    }

    chain
}

/// Extracts a string attribute from an X.509 Name by OID.
///
/// Tries both UTF-8 and PrintableString encodings, matching Apple certificate conventions.
fn extract_name_attr(name: &x509_cert::name::Name, oid: const_oid::ObjectIdentifier) -> Option<String> {
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
    extract_name_attr(&cert.tbs_certificate.issuer, const_oid::db::rfc4519::ORGANIZATIONAL_UNIT_NAME)
}

/// Extracts the Common Name (CN) from a certificate's issuer.
fn extract_issuer_cn(cert: &Certificate) -> Option<String> {
    extract_name_attr(&cert.tbs_certificate.issuer, const_oid::db::rfc4519::COMMON_NAME)
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
        SigningKeyType::Rsa(rsa_key) => rsa_key
            .to_public_key()
            .to_public_key_der()
            .map_err(|e| Error::Certificate(format!("Failed to encode RSA public key: {}", e)))?
            .to_vec(),
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
    extract_name_attr(&cert.tbs_certificate.subject, const_oid::db::rfc4519::ORGANIZATIONAL_UNIT_NAME)
}

/// Extracts the Common Name (CN) from a certificate's subject.
pub(crate) fn extract_subject_cn(cert: &Certificate) -> Option<String> {
    extract_name_attr(&cert.tbs_certificate.subject, const_oid::db::rfc4519::COMMON_NAME)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signing_key_type_enum_exists() {
        let _rsa: fn(RsaPrivateKey) -> SigningKeyType = SigningKeyType::Rsa;
        let _ecdsa: fn(EcdsaSigningKey) -> SigningKeyType = SigningKeyType::Ecdsa;
    }

    #[test]
    fn test_signing_credentials_struct_exists() {
        fn check_field_types(_creds: &SigningCredentials) {
            let _cert: &Certificate = &_creds.certificate;
            let _key: &SigningKeyType = &_creds.signing_key;
            let _chain: &Vec<Certificate> = &_creds.cert_chain;
            let _team: &Option<String> = &_creds.team_id;
        }
        let _ = check_field_types;
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
}
