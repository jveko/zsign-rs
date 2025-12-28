//! Pure Rust certificate and key handling
//!
//! Replaces OpenSSL X509/PKey with pure Rust equivalents using x509-certificate and p12 crates.

use crate::{Error, Result};
use p256::ecdsa::SigningKey as EcdsaSigningKey;
use rsa::RsaPrivateKey;
use x509_certificate::X509Certificate;

/// Signing key that can be either RSA or ECDSA
pub enum SigningKeyType {
    Rsa(RsaPrivateKey),
    Ecdsa(EcdsaSigningKey),
}

/// Pure Rust signing credentials
pub struct PureRustCredentials {
    /// X.509 certificate
    pub certificate: X509Certificate,
    /// Signing key
    pub signing_key: SigningKeyType,
    /// Certificate chain (intermediate CAs)
    pub cert_chain: Vec<X509Certificate>,
    /// Team ID extracted from certificate
    pub team_id: Option<String>,
}

impl PureRustCredentials {
    /// Load from PEM-encoded certificate and private key
    pub fn from_pem(cert_pem: &[u8], key_pem: &[u8], password: Option<&str>) -> Result<Self> {
        use pkcs8::DecodePrivateKey;

        let certificate = X509Certificate::from_pem(cert_pem)
            .map_err(|e| Error::Certificate(format!("Failed to parse certificate PEM: {}", e)))?;

        let key_str = std::str::from_utf8(key_pem)
            .map_err(|e| Error::Certificate(format!("Invalid UTF-8 in key PEM: {}", e)))?;

        let signing_key = if let Some(_pass) = password {
            return Err(Error::Certificate(
                "Encrypted PEM keys are not yet supported in pure Rust mode. Use unencrypted keys or PKCS#12.".into(),
            ));
        } else {
            if let Ok(rsa_key) = RsaPrivateKey::from_pkcs8_pem(key_str) {
                SigningKeyType::Rsa(rsa_key)
            } else if let Ok(ecdsa_key) = EcdsaSigningKey::from_pkcs8_pem(key_str) {
                SigningKeyType::Ecdsa(ecdsa_key)
            } else {
                return Err(Error::Certificate(
                    "Failed to parse private key as RSA or ECDSA".into(),
                ));
            }
        };

        let team_id = extract_team_id(&certificate);

        Ok(Self {
            certificate,
            signing_key,
            cert_chain: Vec::new(),
            team_id,
        })
    }

    /// Load from PKCS#12 (.p12) file
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
        let certificate = X509Certificate::from_der(cert_der)
            .map_err(|e| Error::Certificate(format!("Failed to parse certificate DER: {}", e)))?;

        let key_der = &keys[0];
        let signing_key = Self::parse_private_key_der(key_der)?;

        let cert_chain: Vec<X509Certificate> = certs
            .iter()
            .skip(1)
            .filter_map(|der| X509Certificate::from_der(der).ok())
            .collect();

        let team_id = extract_team_id(&certificate);

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

/// Extract team ID from certificate (look for OU in subject)
fn extract_team_id(cert: &X509Certificate) -> Option<String> {
    let subject = cert.subject_name();

    for atav in subject.iter_organizational_unit() {
        if let Ok(value) = atav.to_string() {
            return Some(value);
        }
    }
    None
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
    fn test_pure_rust_credentials_struct_exists() {
        fn check_field_types(_creds: &PureRustCredentials) {
            let _cert: &X509Certificate = &_creds.certificate;
            let _key: &SigningKeyType = &_creds.signing_key;
            let _chain: &Vec<X509Certificate> = &_creds.cert_chain;
            let _team: &Option<String> = &_creds.team_id;
        }
        let _ = check_field_types;
    }

    #[test]
    fn test_from_pem_invalid_cert() {
        let result = PureRustCredentials::from_pem(b"not a cert", b"not a key", None);
        assert!(result.is_err());
    }

    #[test]
    fn test_from_p12_invalid_data() {
        let result = PureRustCredentials::from_p12(b"not valid p12 data", "password");
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_team_id_from_apple_wwdr_cert() {
        use crate::crypto::assets::APPLE_WWDR_CA_G3_CERT;

        let cert = X509Certificate::from_pem(APPLE_WWDR_CA_G3_CERT.as_bytes()).unwrap();
        let team_id = extract_team_id(&cert);
        assert_eq!(team_id, Some("G3".to_string()));
    }
}
