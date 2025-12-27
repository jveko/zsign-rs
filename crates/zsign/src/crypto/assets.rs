//! Certificate, private key, and provisioning profile loading

use crate::{Error, Result};
use openssl::pkcs12::Pkcs12;
use openssl::pkey::{PKey, Private};
use openssl::x509::X509;
use secrecy::{ExposeSecret, SecretString};
use std::fs;
use std::path::Path;

/// Signing assets: certificate, private key, and optionally provisioning profile
pub struct SigningAssets {
    /// X.509 certificate
    pub certificate: X509,
    /// Private key
    pub private_key: PKey<Private>,
    /// Team ID extracted from certificate
    pub team_id: Option<String>,
    /// Entitlements from provisioning profile
    pub entitlements: Option<Vec<u8>>,
}

impl SigningAssets {
    /// Load from separate certificate and private key files
    ///
    /// The password, if provided, is handled securely via SecretString and will
    /// be zeroized when no longer needed.
    pub fn from_pem(
        cert_path: impl AsRef<Path>,
        key_path: impl AsRef<Path>,
        key_password: Option<&SecretString>,
    ) -> Result<Self> {
        let cert_data = fs::read(cert_path)?;
        let key_data = fs::read(key_path)?;

        let certificate = X509::from_pem(&cert_data)
            .or_else(|_| X509::from_der(&cert_data))
            .map_err(|e| Error::Certificate(format!("Failed to load certificate: {}", e)))?;

        let private_key = if let Some(pass) = key_password {
            PKey::private_key_from_pem_passphrase(&key_data, pass.expose_secret().as_bytes())
        } else {
            PKey::private_key_from_pem(&key_data)
                .or_else(|_| PKey::private_key_from_der(&key_data))
        }
        .map_err(|e| Error::Certificate(format!("Failed to load private key: {}", e)))?;

        let team_id = Self::extract_team_id(&certificate);

        // Validate that private key matches certificate
        Self::validate_key_pair(&certificate, &private_key)?;

        Ok(Self {
            certificate,
            private_key,
            team_id,
            entitlements: None,
        })
    }

    /// Load from PKCS#12 (.p12) file
    ///
    /// The password is handled securely via SecretString and will be zeroized
    /// when no longer needed. Defaults to empty string if not provided.
    pub fn from_p12(
        p12_path: impl AsRef<Path>,
        password: Option<&SecretString>,
    ) -> Result<Self> {
        let p12_data = fs::read(p12_path)?;

        let pkcs12 = Pkcs12::from_der(&p12_data)
            .map_err(|e| Error::Certificate(format!("Invalid PKCS#12: {}", e)))?;

        let pass = password
            .map(|s| s.expose_secret().as_str())
            .unwrap_or("");
        let parsed = pkcs12.parse2(pass)
            .map_err(|e| Error::Certificate(format!("Failed to parse PKCS#12: {}", e)))?;

        let certificate = parsed.cert
            .ok_or_else(|| Error::Certificate("No certificate in PKCS#12".into()))?;

        let private_key = parsed.pkey
            .ok_or_else(|| Error::Certificate("No private key in PKCS#12".into()))?;

        let team_id = Self::extract_team_id(&certificate);

        // Validate that private key matches certificate
        Self::validate_key_pair(&certificate, &private_key)?;

        Ok(Self {
            certificate,
            private_key,
            team_id,
            entitlements: None,
        })
    }

    /// Load provisioning profile and extract entitlements
    pub fn with_provisioning_profile(
        mut self,
        profile_path: impl AsRef<Path>,
    ) -> Result<Self> {
        let profile_data = fs::read(profile_path)?;

        // Provisioning profiles are CMS-signed plists
        // Extract the embedded plist content
        let entitlements = Self::extract_entitlements_from_profile(&profile_data)?;
        self.entitlements = Some(entitlements);

        Ok(self)
    }

    /// Extract team ID from certificate subject
    fn extract_team_id(cert: &X509) -> Option<String> {
        let subject = cert.subject_name();

        // Look for OU (Organizational Unit) which contains team ID
        for entry in subject.entries() {
            let nid = entry.object().nid();
            if nid == openssl::nid::Nid::ORGANIZATIONALUNITNAME {
                if let Ok(data) = entry.data().as_utf8() {
                    return Some(data.to_string());
                }
            }
        }
        None
    }

    /// Validate that the private key matches the certificate's public key
    fn validate_key_pair(cert: &X509, private_key: &PKey<Private>) -> Result<()> {
        let cert_public_key = cert.public_key()
            .map_err(|e| Error::Certificate(format!(
                "Failed to extract public key from certificate: {}", e
            )))?;

        if !private_key.public_eq(&cert_public_key) {
            return Err(Error::Certificate(
                "Private key does not match certificate public key".into()
            ));
        }

        Ok(())
    }

    /// Extract entitlements from provisioning profile
    pub fn extract_entitlements_from_profile(data: &[u8]) -> Result<Vec<u8>> {
        // Profile is CMS-wrapped, find the embedded plist
        // Look for <?xml or bplist marker
        let xml_marker = b"<?xml";
        let plist_start = data.windows(5)
            .position(|w| w == xml_marker)
            .ok_or_else(|| Error::ProvisioningProfile("No plist found in profile".into()))?;

        // Find end of plist
        let plist_end_marker = b"</plist>";
        let plist_end = data[plist_start..].windows(8)
            .position(|w| w == plist_end_marker)
            .map(|p| plist_start + p + 8)
            .ok_or_else(|| Error::ProvisioningProfile("Invalid plist in profile".into()))?;

        let plist_data = &data[plist_start..plist_end];

        // Parse plist and extract Entitlements key
        let plist: plist::Value = plist::from_bytes(plist_data)
            .map_err(|e| Error::ProvisioningProfile(format!("Failed to parse plist: {}", e)))?;

        let dict = plist.as_dictionary()
            .ok_or_else(|| Error::ProvisioningProfile("Profile is not a dictionary".into()))?;

        let entitlements = dict.get("Entitlements")
            .ok_or_else(|| Error::ProvisioningProfile("No Entitlements in profile".into()))?;

        // Serialize entitlements back to XML plist
        let mut buf = Vec::new();
        plist::to_writer_xml(&mut buf, entitlements)
            .map_err(|e| Error::ProvisioningProfile(format!("Failed to serialize: {}", e)))?;

        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::hash::MessageDigest;
    use openssl::nid::Nid;
    use openssl::x509::X509NameBuilder;
    use openssl::asn1::Asn1Time;

    #[test]
    fn test_extract_entitlements_finds_plist() {
        // Minimal test data with embedded plist
        let data = br#"junk<?xml version="1.0"?><plist><dict><key>Entitlements</key><dict></dict></dict></plist>more"#;
        let result = SigningAssets::extract_entitlements_from_profile(data);
        assert!(result.is_ok());
    }

    #[test]
    fn test_extract_entitlements_no_plist() {
        // Data without plist
        let data = b"just some random data without xml";
        let result = SigningAssets::extract_entitlements_from_profile(data);
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_entitlements_no_end_tag() {
        // Data with start but no end
        let data = b"<?xml version=\"1.0\"?><plist><dict>";
        let result = SigningAssets::extract_entitlements_from_profile(data);
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_entitlements_with_real_profile_structure() {
        // More realistic provisioning profile structure
        // Uses ASCII prefix to simulate CMS wrapper bytes
        let data = br#"BINARY_CMS_HEADER_DATA_HERE<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>AppIDName</key>
    <string>Test App</string>
    <key>Entitlements</key>
    <dict>
        <key>application-identifier</key>
        <string>TEAM123.com.example.app</string>
        <key>get-task-allow</key>
        <true/>
    </dict>
    <key>TeamName</key>
    <string>Example Team</string>
</dict>
</plist>
more binary data here..."#;

        let result = SigningAssets::extract_entitlements_from_profile(data);
        assert!(result.is_ok());

        let entitlements = result.unwrap();
        let entitlements_str = String::from_utf8_lossy(&entitlements);

        // Check that the entitlements contain expected keys
        assert!(entitlements_str.contains("application-identifier"));
        assert!(entitlements_str.contains("get-task-allow"));
    }

    /// Helper to generate a test EC key pair
    fn generate_test_ec_key() -> PKey<Private> {
        let group = EcGroup::from_curve_name(Nid::SECP256K1).unwrap();
        let ec_key = EcKey::generate(&group).unwrap();
        PKey::from_ec_key(ec_key).unwrap()
    }

    /// Helper to generate a self-signed certificate for a given private key
    fn generate_test_cert(private_key: &PKey<Private>) -> X509 {
        use openssl::x509::X509Builder;
        use openssl::bn::BigNum;

        let mut name_builder = X509NameBuilder::new().unwrap();
        name_builder.append_entry_by_text("CN", "Test Certificate").unwrap();
        let name = name_builder.build();

        let mut builder = X509Builder::new().unwrap();
        builder.set_version(2).unwrap();

        let serial = BigNum::from_u32(1).unwrap();
        builder.set_serial_number(&serial.to_asn1_integer().unwrap()).unwrap();

        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_pubkey(private_key).unwrap();

        let not_before = Asn1Time::days_from_now(0).unwrap();
        let not_after = Asn1Time::days_from_now(365).unwrap();
        builder.set_not_before(&not_before).unwrap();
        builder.set_not_after(&not_after).unwrap();

        builder.sign(private_key, MessageDigest::sha256()).unwrap();
        builder.build()
    }

    #[test]
    fn test_validate_key_pair_matching() {
        // Generate a key pair and certificate that match
        let private_key = generate_test_ec_key();
        let certificate = generate_test_cert(&private_key);

        // Validation should succeed
        let result = SigningAssets::validate_key_pair(&certificate, &private_key);
        assert!(result.is_ok(), "Matching key pair should validate successfully");
    }

    #[test]
    fn test_validate_key_pair_mismatched() {
        // Generate two different key pairs
        let key1 = generate_test_ec_key();
        let key2 = generate_test_ec_key();

        // Create certificate with key1, but try to validate with key2
        let certificate = generate_test_cert(&key1);

        // Validation should fail
        let result = SigningAssets::validate_key_pair(&certificate, &key2);
        assert!(result.is_err(), "Mismatched key pair should fail validation");

        // Check error message
        let err = result.unwrap_err();
        let err_msg = err.to_string();
        assert!(
            err_msg.contains("does not match"),
            "Error message should indicate key mismatch: {}", err_msg
        );
    }
}
