//! Certificate, private key, and provisioning profile loading

use crate::{Error, Result};
use openssl::pkcs12::Pkcs12;
use openssl::pkey::{PKey, Private};
use openssl::x509::X509;
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
    pub fn from_pem(
        cert_path: impl AsRef<Path>,
        key_path: impl AsRef<Path>,
        key_password: Option<&str>,
    ) -> Result<Self> {
        let cert_data = fs::read(cert_path)?;
        let key_data = fs::read(key_path)?;

        let certificate = X509::from_pem(&cert_data)
            .or_else(|_| X509::from_der(&cert_data))
            .map_err(|e| Error::Certificate(format!("Failed to load certificate: {}", e)))?;

        let private_key = if let Some(pass) = key_password {
            PKey::private_key_from_pem_passphrase(&key_data, pass.as_bytes())
        } else {
            PKey::private_key_from_pem(&key_data)
                .or_else(|_| PKey::private_key_from_der(&key_data))
        }
        .map_err(|e| Error::Certificate(format!("Failed to load private key: {}", e)))?;

        let team_id = Self::extract_team_id(&certificate);

        Ok(Self {
            certificate,
            private_key,
            team_id,
            entitlements: None,
        })
    }

    /// Load from PKCS#12 (.p12) file
    pub fn from_p12(
        p12_path: impl AsRef<Path>,
        password: &str,
    ) -> Result<Self> {
        let p12_data = fs::read(p12_path)?;

        let pkcs12 = Pkcs12::from_der(&p12_data)
            .map_err(|e| Error::Certificate(format!("Invalid PKCS#12: {}", e)))?;

        let parsed = pkcs12.parse2(password)
            .map_err(|e| Error::Certificate(format!("Failed to parse PKCS#12: {}", e)))?;

        let certificate = parsed.cert
            .ok_or_else(|| Error::Certificate("No certificate in PKCS#12".into()))?;

        let private_key = parsed.pkey
            .ok_or_else(|| Error::Certificate("No private key in PKCS#12".into()))?;

        let team_id = Self::extract_team_id(&certificate);

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
}
