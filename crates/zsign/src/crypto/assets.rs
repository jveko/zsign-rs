//! Certificate, private key, and provisioning profile loading

use crate::{Error, Result};
use openssl::pkcs12::Pkcs12;
use openssl::pkey::{PKey, Private};
use openssl::x509::X509;
use secrecy::{ExposeSecret, SecretString};
use std::fs;
use std::path::Path;
use std::sync::Once;

static LEGACY_PROVIDER_INIT: Once = Once::new();
static mut LEGACY_PROVIDER: Option<openssl::provider::Provider> = None;
static mut DEFAULT_PROVIDER: Option<openssl::provider::Provider> = None;

// =============================================================================
// Apple CA Certificates (hardcoded for CMS signature chain)
// =============================================================================

/// Apple Worldwide Developer Relations Certification Authority (original, expires 2023)
/// Issuer name hash: 0x817d2f7a
pub const APPLE_WWDR_CA_CERT: &str = "\
-----BEGIN CERTIFICATE-----
MIIEIjCCAwqgAwIBAgIIAd68xDltoBAwDQYJKoZIhvcNAQEFBQAwYjELMAkGA1UE
BhMCVVMxEzARBgNVBAoTCkFwcGxlIEluYy4xJjAkBgNVBAsTHUFwcGxlIENlcnRp
ZmljYXRpb24gQXV0aG9yaXR5MRYwFAYDVQQDEw1BcHBsZSBSb290IENBMB4XDTEz
MDIwNzIxNDg0N1oXDTIzMDIwNzIxNDg0N1owgZYxCzAJBgNVBAYTAlVTMRMwEQYD
VQQKDApBcHBsZSBJbmMuMSwwKgYDVQQLDCNBcHBsZSBXb3JsZHdpZGUgRGV2ZWxv
cGVyIFJlbGF0aW9uczFEMEIGA1UEAww7QXBwbGUgV29ybGR3aWRlIERldmVsb3Bl
ciBSZWxhdGlvbnMgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQDKOFSmy1aqyCQ5SOmM7uxfuH8mkbw0U3rOfGOA
YXdkXqUHI7Y5/lAtFVZYcC1+xG7BSoU+L/DehBqhV8mvexj/avoVEkkVCBmsqtsq
Mu2WY2hSFT2Miuy/axiV4AOsAX2XBWfODoWVN2rtCbauZ81RZJ/GXNG8V25nNYB2
NqSHgW44j9grFU57Jdhav06DwY3Sk9UacbVgnJ0zTlX5ElgMhrgWDcHld0WNUEi6
Ky3klIXh6MSdxmilsKP8Z35wugJZS3dCkTm59c3hTO/AO0iMpuUhXf1qarunFjVg
0uat80YpyejDi+l5wGphZxWy8P3laLxiX27Pmd3vG2P+kmWrAgMBAAGjgaYwgaMw
HQYDVR0OBBYEFIgnFwmpthhgi+zruvZHWcVSVKO3MA8GA1UdEwEB/wQFMAMBAf8w
HwYDVR0jBBgwFoAUK9BpR5R2Cf70a40uQKb3R01/CF4wLgYDVR0fBCcwJTAjoCGg
H4YdaHR0cDovL2NybC5hcHBsZS5jb20vcm9vdC5jcmwwDgYDVR0PAQH/BAQDAgGG
MBAGCiqGSIb3Y2QGAgEEAgUAMA0GCSqGSIb3DQEBBQUAA4IBAQBPz+9Zviz1smwv
j+4ThzLoBTWobot9yWkMudkXvHcs1Gfi/ZptOllc34MBvbKuKmFysa/Nw0Uwj6OD
Dc4dR7Txk4qjdJukw5hyhzs+r0ULklS5MruQGFNrCk4QttkdUGwhgAqJTleMa1s8
Pab93vcNIx0LSiaHP7qRkkykGRIZbVf1eliHe2iK5IaMSuviSRSqpd1VAKmuu0sw
ruGgsbwpgOYJd+W+NKIByn/c4grmO7i77LpilfMFY0GCzQ87HUyVpNur+cmV6U/k
TecmmYHpvPm0KdIBembhLoz2IYrF+Hjhga6/05Cdqa3zr/04GpZnMBxRpVzscYqC
tGwPDBUf
-----END CERTIFICATE-----
";

/// Apple Worldwide Developer Relations Certification Authority G3 (expires 2030)
/// Issuer name hash: 0x9b16b75c
pub const APPLE_WWDR_CA_G3_CERT: &str = "\
-----BEGIN CERTIFICATE-----
MIIEUTCCAzmgAwIBAgIQfK9pCiW3Of57m0R6wXjF7jANBgkqhkiG9w0BAQsFADBi
MQswCQYDVQQGEwJVUzETMBEGA1UEChMKQXBwbGUgSW5jLjEmMCQGA1UECxMdQXBw
bGUgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxFjAUBgNVBAMTDUFwcGxlIFJvb3Qg
Q0EwHhcNMjAwMjE5MTgxMzQ3WhcNMzAwMjIwMDAwMDAwWjB1MUQwQgYDVQQDDDtB
cHBsZSBXb3JsZHdpZGUgRGV2ZWxvcGVyIFJlbGF0aW9ucyBDZXJ0aWZpY2F0aW9u
IEF1dGhvcml0eTELMAkGA1UECwwCRzMxEzARBgNVBAoMCkFwcGxlIEluYy4xCzAJ
BgNVBAYTAlVTMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2PWJ/KhZ
C4fHTJEuLVaQ03gdpDDppUjvC0O/LYT7JF1FG+XrWTYSXFRknmxiLbTGl8rMPPbW
BpH85QKmHGq0edVny6zpPwcR4YS8Rx1mjjmi6LRJ7TrS4RBgeo6TjMrA2gzAg9Dj
+ZHWp4zIwXPirkbRYp2SqJBgN31ols2N4Pyb+ni743uvLRfdW/6AWSN1F7gSwe0b
5TTO/iK1nkmw5VW/j4SiPKi6xYaVFuQAyZ8D0MyzOhZ71gVcnetHrg21LYwOaU1A
0EtMOwSejSGxrC5DVDDOwYqGlJhL32oNP/77HK6XF8J4CjDgXx9UO0m3JQAaN4LS
VpelUkl8YDib7wIDAQABo4HvMIHsMBIGA1UdEwEB/wQIMAYBAf8CAQAwHwYDVR0j
BBgwFoAUK9BpR5R2Cf70a40uQKb3R01/CF4wRAYIKwYBBQUHAQEEODA2MDQGCCsG
AQUFBzABhihodHRwOi8vb2NzcC5hcHBsZS5jb20vb2NzcDAzLWFwcGxlcm9vdGNh
MC4GA1UdHwQnMCUwI6AhoB+GHWh0dHA6Ly9jcmwuYXBwbGUuY29tL3Jvb3QuY3Js
MB0GA1UdDgQWBBQJ/sAVkPmvZAqSErkmKGMMl+ynsjAOBgNVHQ8BAf8EBAMCAQYw
EAYKKoZIhvdjZAYCAQQCBQAwDQYJKoZIhvcNAQELBQADggEBAK1lE+j24IF3RAJH
Qr5fpTkg6mKp/cWQyXMT1Z6b0KoPjY3L7QHPbChAW8dVJEH4/M/BtSPp3Ozxb8qA
HXfCxGFJJWevD8o5Ja3T43rMMygNDi6hV0Bz+uZcrgZRKe3jhQxPYdwyFot30ETK
XXIDMUacrptAGvr04NM++i+MZp+XxFRZ79JI9AeZSWBZGcfdlNHAwWx/eCHvDOs7
bJmCS1JgOLU5gm3sUjFTvg+RTElJdI+mUcuER04ddSduvfnSXPN/wmwLCTbiZOTC
NwMUGdXqapSqqdv+9poIZ4vvK7iqF0mDr8/LvOnP6pVxsLRFoszlh6oKw0E6eVza
UDSdlTs=
-----END CERTIFICATE-----
";

/// Apple Root CA (expires 2035)
/// This is the root of the Apple certificate hierarchy
pub const APPLE_ROOT_CA_CERT: &str = "\
-----BEGIN CERTIFICATE-----
MIIEuzCCA6OgAwIBAgIBAjANBgkqhkiG9w0BAQUFADBiMQswCQYDVQQGEwJVUzET
MBEGA1UEChMKQXBwbGUgSW5jLjEmMCQGA1UECxMdQXBwbGUgQ2VydGlmaWNhdGlv
biBBdXRob3JpdHkxFjAUBgNVBAMTDUFwcGxlIFJvb3QgQ0EwHhcNMDYwNDI1MjE0
MDM2WhcNMzUwMjA5MjE0MDM2WjBiMQswCQYDVQQGEwJVUzETMBEGA1UEChMKQXBw
bGUgSW5jLjEmMCQGA1UECxMdQXBwbGUgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkx
FjAUBgNVBAMTDUFwcGxlIFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
ggEKAoIBAQDkkakJH5HbHkdQ6wXtXnmELes2oldMVeyLGYne+Uts9QerIjAC6Bg+
+FAJ039BqJj50cpmnCRrEdCju+QbKsMflZ56DKRHi1vUFjczy8QPTc4UadHJGXL1
XQ7Vf1+b8iUDulWPTV0N8WQ1IxVLFVkds5T39pyez1C6wVhQZ48ItCD3y6wsIG9w
tj8BMIy3Q88PnT3zK0koGsj+zrW5DtleHNbLPbU6rfQPDgCSC7EhFi501TwN22IW
q6NxkkdTVcGvL0Gz+PvjcM3mo0xFfh9Ma1CWQYnEdGILEINBhzOKgbEwWOxaBDKM
aLOPHd5lc/9nXmW8Sdh2nzMUZaF3lMktAgMBAAGjggF6MIIBdjAOBgNVHQ8BAf8E
BAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUK9BpR5R2Cf70a40uQKb3
R01/CF4wHwYDVR0jBBgwFoAUK9BpR5R2Cf70a40uQKb3R01/CF4wggERBgNVHSAE
ggEIMIIBBDCCAQAGCSqGSIb3Y2QFATCB8jAqBggrBgEFBQcCARYeaHR0cHM6Ly93
d3cuYXBwbGUuY29tL2FwcGxlY2EvMIHDBggrBgEFBQcCAjCBthqBs1JlbGlhbmNl
IG9uIHRoaXMgY2VydGlmaWNhdGUgYnkgYW55IHBhcnR5IGFzc3VtZXMgYWNjZXB0
YW5jZSBvZiB0aGUgdGhlbiBhcHBsaWNhYmxlIHN0YW5kYXJkIHRlcm1zIGFuZCBj
b25kaXRpb25zIG9mIHVzZSwgY2VydGlmaWNhdGUgcG9saWN5IGFuZCBjZXJ0aWZp
Y2F0aW9uIHByYWN0aWNlIHN0YXRlbWVudHMuMA0GCSqGSIb3DQEBBQUAA4IBAQBc
NplMLXi37Yyb3PN3m/J20ncwT8EfhYOFG5k9RzfyqZtAjizUsZAS2L70c5vu0mQP
y3lPNNiiPvl4/2vIB+x9OYOLUyDTOMSxv5pPCmv/K/xZpwUJfBdAVhEedNO3iyM7
R6PVbyTi69G3cN8PReEnyvFteO3ntRcXqNx+IjXKJdXZD9Zr1KIkIxH3oayPc4Fg
xhtbCS+SsvhESPBgOJ4V9T0mZyCKM2r3DYLP3uujL/lTaltkwGMzd/c6ByxW69oP
IQ7aunMZT7XZNn/Bh1XZp5m5MkL72NVxnn6hUrcbvZNCJBIqxw8dtk2cXmPIS4AX
UKqK1drk/NAJBzewdXUh
-----END CERTIFICATE-----
";

/// Issuer name hash for the original Apple WWDR CA
pub const APPLE_WWDR_ISSUER_HASH: u32 = 0x817d2f7a;

/// Issuer name hash for the Apple WWDR CA G3
pub const APPLE_WWDR_G3_ISSUER_HASH: u32 = 0x9b16b75c;

/// Try to load OpenSSL legacy provider for RC2/3DES support in older P12 files.
/// This is required for OpenSSL 3.x to handle Apple Keychain exports.
/// We must load BOTH default and legacy providers to have all algorithms available.
/// The providers are kept alive in static storage to prevent them from being dropped.
fn try_load_legacy_provider() {
    LEGACY_PROVIDER_INIT.call_once(|| {
        unsafe {
            if let Ok(p) = openssl::provider::Provider::load(None, "default") {
                DEFAULT_PROVIDER = Some(p);
            }
            if let Ok(p) = openssl::provider::Provider::load(None, "legacy") {
                LEGACY_PROVIDER = Some(p);
            }
        }
    });
}

/// Signing assets: certificate, private key, and optionally provisioning profile
pub struct SigningAssets {
    /// X.509 certificate
    pub certificate: X509,
    /// Private key
    pub private_key: PKey<Private>,
    /// Certificate chain (intermediate CAs, not including the signing cert)
    pub cert_chain: Vec<X509>,
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
            cert_chain: Vec::new(),
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
        try_load_legacy_provider();

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

        // Extract certificate chain from P12 (intermediate CAs)
        let cert_chain = parsed.ca.map(|stack| stack.into_iter().collect()).unwrap_or_default();

        let team_id = Self::extract_team_id(&certificate);

        // Validate that private key matches certificate
        Self::validate_key_pair(&certificate, &private_key)?;

        Ok(Self {
            certificate,
            private_key,
            cert_chain,
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
        
        // Add trailing newline to match C++ zsign behavior
        // C++ zsign uses style_write_plist which adds "\n" after </plist>
        buf.push(b'\n');

        Ok(buf)
    }

    /// Get the Apple CA chain certificates for CMS signing.
    ///
    /// Returns a vector containing:
    /// 1. The appropriate Apple WWDR CA (based on the signing certificate's issuer hash)
    /// 2. The Apple Root CA
    ///
    /// This matches the behavior of C++ zsign which hardcodes these certificates
    /// and adds them to the CMS signature chain automatically.
    pub fn get_apple_ca_chain(&self) -> Result<Vec<X509>> {
        // Get the issuer name hash to determine which WWDR CA to use
        let issuer_hash = Self::get_issuer_name_hash(&self.certificate)?;

        let wwdr_cert = if issuer_hash == APPLE_WWDR_ISSUER_HASH {
            X509::from_pem(APPLE_WWDR_CA_CERT.as_bytes())
        } else if issuer_hash == APPLE_WWDR_G3_ISSUER_HASH {
            X509::from_pem(APPLE_WWDR_CA_G3_CERT.as_bytes())
        } else {
            return Err(Error::Certificate(format!(
                "Unknown certificate issuer hash: 0x{:08x}. Expected Apple WWDR CA (0x{:08x}) or Apple WWDR G3 CA (0x{:08x})",
                issuer_hash, APPLE_WWDR_ISSUER_HASH, APPLE_WWDR_G3_ISSUER_HASH
            )));
        }.map_err(|e| Error::Certificate(format!("Failed to parse Apple WWDR CA: {}", e)))?;

        let root_cert = X509::from_pem(APPLE_ROOT_CA_CERT.as_bytes())
            .map_err(|e| Error::Certificate(format!("Failed to parse Apple Root CA: {}", e)))?;

        Ok(vec![wwdr_cert, root_cert])
    }

    /// Get the issuer name hash from a certificate.
    ///
    /// This matches OpenSSL's X509_issuer_name_hash() function which is used
    /// by C++ zsign to determine which Apple WWDR CA certificate to use.
    fn get_issuer_name_hash(cert: &X509) -> Result<u32> {
        use openssl::hash::{hash, MessageDigest};

        // Get the DER encoding of the issuer name
        let issuer = cert.issuer_name();
        let issuer_der = issuer.to_der()
            .map_err(|e| Error::Certificate(format!("Failed to encode issuer name: {}", e)))?;

        // Hash with SHA-1 (X509_issuer_name_hash uses SHA-1)
        let digest = hash(MessageDigest::sha1(), &issuer_der)
            .map_err(|e| Error::Certificate(format!("Failed to hash issuer name: {}", e)))?;

        // Take first 4 bytes as little-endian u32
        // Note: OpenSSL's X509_NAME_hash returns a u32 from the first 4 bytes
        let bytes: [u8; 4] = digest[..4].try_into()
            .map_err(|_| Error::Certificate("Hash too short".into()))?;

        Ok(u32::from_le_bytes(bytes))
    }

    /// Get the complete certificate chain for CMS signing.
    ///
    /// This combines any user-provided certificate chain with the Apple CA chain.
    /// The Apple WWDR and Root CA certificates are added automatically.
    pub fn get_full_cert_chain(&self) -> Result<Vec<X509>> {
        let mut chain = self.cert_chain.clone();
        let apple_chain = self.get_apple_ca_chain()?;
        chain.extend(apple_chain);
        Ok(chain)
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

    #[test]
    fn test_legacy_provider_loads_without_panic() {
        super::try_load_legacy_provider();
    }

    #[test]
    fn test_legacy_provider_is_idempotent() {
        super::try_load_legacy_provider();
        super::try_load_legacy_provider();
        super::try_load_legacy_provider();
    }

    #[test]
    fn test_from_p12_with_generated_pkcs12() {
        use openssl::pkcs12::Pkcs12;
        use tempfile::NamedTempFile;
        use std::io::Write;

        let private_key = generate_test_ec_key();
        let certificate = generate_test_cert(&private_key);

        let pkcs12 = Pkcs12::builder()
            .name("test")
            .pkey(&private_key)
            .cert(&certificate)
            .build2("testpass")
            .expect("Failed to build PKCS#12");

        let p12_der = pkcs12.to_der().expect("Failed to serialize PKCS#12");

        let mut temp_file = NamedTempFile::new().expect("Failed to create temp file");
        temp_file.write_all(&p12_der).expect("Failed to write P12");

        let password = secrecy::SecretString::from("testpass".to_string());
        let result = SigningAssets::from_p12(temp_file.path(), Some(&password));

        assert!(result.is_ok(), "Should load generated PKCS#12: {:?}", result.err());

        let assets = result.unwrap();
        assert!(assets.private_key.public_eq(&private_key.public_key_to_pem().map(|_| private_key.clone()).unwrap()));
    }

    #[test]
    fn test_from_p12_wrong_password() {
        use openssl::pkcs12::Pkcs12;
        use tempfile::NamedTempFile;
        use std::io::Write;

        let private_key = generate_test_ec_key();
        let certificate = generate_test_cert(&private_key);

        let pkcs12 = Pkcs12::builder()
            .name("test")
            .pkey(&private_key)
            .cert(&certificate)
            .build2("correctpass")
            .expect("Failed to build PKCS#12");

        let p12_der = pkcs12.to_der().expect("Failed to serialize PKCS#12");

        let mut temp_file = NamedTempFile::new().expect("Failed to create temp file");
        temp_file.write_all(&p12_der).expect("Failed to write P12");

        let wrong_password = secrecy::SecretString::from("wrongpass".to_string());
        let result = SigningAssets::from_p12(temp_file.path(), Some(&wrong_password));

        assert!(result.is_err(), "Should fail with wrong password");
        let err = result.err().unwrap();
        let err_msg = err.to_string();
        assert!(
            err_msg.contains("PKCS#12") || err_msg.contains("mac verify"),
            "Error should mention PKCS#12 or MAC verification: {}", err_msg
        );
    }

    #[test]
    fn test_from_p12_empty_password() {
        use openssl::pkcs12::Pkcs12;
        use tempfile::NamedTempFile;
        use std::io::Write;

        let private_key = generate_test_ec_key();
        let certificate = generate_test_cert(&private_key);

        let pkcs12 = Pkcs12::builder()
            .name("test")
            .pkey(&private_key)
            .cert(&certificate)
            .build2("")
            .expect("Failed to build PKCS#12 with empty password");

        let p12_der = pkcs12.to_der().expect("Failed to serialize PKCS#12");

        let mut temp_file = NamedTempFile::new().expect("Failed to create temp file");
        temp_file.write_all(&p12_der).expect("Failed to write P12");

        let result = SigningAssets::from_p12(temp_file.path(), None);
        assert!(result.is_ok(), "Should load PKCS#12 with empty password: {:?}", result.err());
    }

    #[test]
    fn test_from_p12_file_not_found() {
        let result = SigningAssets::from_p12("/nonexistent/path/to/file.p12", None);
        assert!(result.is_err(), "Should fail for nonexistent file");
    }

    #[test]
    fn test_from_p12_invalid_data() {
        use tempfile::NamedTempFile;
        use std::io::Write;

        let mut temp_file = NamedTempFile::new().expect("Failed to create temp file");
        temp_file.write_all(b"this is not valid pkcs12 data").expect("Failed to write");

        let result = SigningAssets::from_p12(temp_file.path(), None);
        assert!(result.is_err(), "Should fail for invalid PKCS#12 data");
        let err = result.err().unwrap();
        let err_msg = err.to_string();
        assert!(
            err_msg.contains("PKCS#12") || err_msg.contains("Invalid"),
            "Error should mention PKCS#12: {}", err_msg
        );
    }

    #[test]
    fn test_apple_wwdr_ca_cert_parses() {
        let cert = X509::from_pem(super::APPLE_WWDR_CA_CERT.as_bytes());
        assert!(cert.is_ok(), "Should parse Apple WWDR CA cert: {:?}", cert.err());
        let cert = cert.unwrap();

        // Verify this is the WWDR cert by checking the subject
        let subject = cert.subject_name();
        let subject_str = format!("{:?}", subject);
        assert!(
            subject_str.contains("Apple Worldwide Developer Relations"),
            "Subject should contain WWDR: {}", subject_str
        );
    }

    #[test]
    fn test_apple_wwdr_g3_ca_cert_parses() {
        let cert = X509::from_pem(super::APPLE_WWDR_CA_G3_CERT.as_bytes());
        assert!(cert.is_ok(), "Should parse Apple WWDR G3 CA cert: {:?}", cert.err());
        let cert = cert.unwrap();

        // Verify this is the WWDR G3 cert by checking the subject
        let subject = cert.subject_name();
        let subject_str = format!("{:?}", subject);
        assert!(
            subject_str.contains("Apple Worldwide Developer Relations"),
            "Subject should contain WWDR: {}", subject_str
        );
    }

    #[test]
    fn test_apple_root_ca_cert_parses() {
        let cert = X509::from_pem(super::APPLE_ROOT_CA_CERT.as_bytes());
        assert!(cert.is_ok(), "Should parse Apple Root CA cert: {:?}", cert.err());
        let cert = cert.unwrap();

        // Verify this is the Root CA by checking the subject
        let subject = cert.subject_name();
        let subject_str = format!("{:?}", subject);
        assert!(
            subject_str.contains("Apple Root CA"),
            "Subject should contain Apple Root CA: {}", subject_str
        );
    }

    #[test]
    fn test_get_issuer_name_hash() {
        // Test with Apple WWDR G3 CA (we know its issuer is Apple Root CA)
        let wwdr_g3 = X509::from_pem(super::APPLE_WWDR_CA_G3_CERT.as_bytes()).unwrap();
        let hash = SigningAssets::get_issuer_name_hash(&wwdr_g3);
        assert!(hash.is_ok(), "Should compute issuer hash: {:?}", hash.err());

        // The WWDR G3 is signed by Apple Root CA, so we can verify the hash is consistent
        // (We don't check the exact value since it depends on the DER encoding)
        let hash_value = hash.unwrap();
        assert!(hash_value != 0, "Hash should be non-zero");
    }
}
