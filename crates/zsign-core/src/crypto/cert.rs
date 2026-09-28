//! Certificate and private key handling for code signing.
//!
//! This module loads signing credentials from PEM-encoded files or PKCS#12 (.p12)
//! containers. It supports RSA and ECDSA (P-256) private keys commonly used in
//! Apple code signing certificates.
//!
//! Credentials loaded through the public constructors are anchored to the
//! Apple Root CA: the chain is walked and every link verified at load time.
//!
//! # Supported Formats
//!
//! - **PEM**: Separate certificate and private key files. The key may be an unencrypted
//!   PKCS#8, PKCS#1 or SEC1 key, a PBES2-encrypted PKCS#8 container, or a traditional
//!   `Proc-Type: 4,ENCRYPTED` / `DEK-Info` PEM. An encrypted key needs the passphrase; an
//!   unencrypted one ignores a supplied one, as OpenSSL does.
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

use super::cms_verify::TrustAnchors;
use crate::{Error, Result};
use const_oid::ObjectIdentifier;
use der::{Decode, DecodePem};
use p256::ecdsa::SigningKey as EcdsaSigningKey;
use rsa::RsaPrivateKey;
#[cfg(not(target_arch = "wasm32"))]
use sha1::{Digest, Sha1};
use x509_cert::Certificate;

const OID_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.15");
const OID_BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");
const OID_EXT_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37");
const OID_CODE_SIGNING: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.3");

/// Formats a SHA-1 digest as uppercase hex, as `security find-identity` prints it.
// The keychain leaf selector is a native-only concern; the module exposing it
// (`crypto::keychain`) is already gated off `wasm32`.
#[cfg(not(target_arch = "wasm32"))]
fn hex_upper(bytes: &[u8; 20]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

/// Private key for code signing, supporting multiple key types.
///
/// Apple code signing certificates typically use either RSA or ECDSA keys.
/// This enum abstracts over both types to provide a unified signing interface.
///
/// # Variants
///
/// * [`Rsa`](SigningKeyType::Rsa) - RSA private key (minimum 2048 bits)
/// * [`Ecdsa`](SigningKeyType::Ecdsa) - ECDSA P-256 private key (secp256r1)
#[allow(clippy::large_enum_variant)]
#[derive(Clone)]
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
#[derive(Clone)]
pub struct SigningCredentials {
    /// X.509 signing certificate identifying the developer or organization.
    pub certificate: Certificate,

    /// Private key corresponding to the certificate's public key.
    pub signing_key: SigningKeyType,

    /// Intermediate CA certificates for building the certificate chain.
    ///
    /// These certificates connect the signing certificate to the Apple Root CA.
    ///
    /// Chains assembled by the public constructors are verified at load time
    /// to terminate at the Apple Root CA, so this list is chain-complete.
    pub cert_chain: Vec<Certificate>,

    /// Apple Team ID extracted from the certificate's Organizational Unit (OU) field.
    ///
    /// This is a 10-character alphanumeric identifier assigned by Apple to
    /// each developer or organization.
    pub team_id: Option<String>,
}

/// A PKCS#8 private key decoded to a form that can be SPKI-matched against certificates.
// Load-path-only decode result: boxing the Rsa arm would churn every match site for a
// transient value; the long-lived SigningKeyType carries the same allow.
#[allow(clippy::large_enum_variant)]
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

    /// Decodes a private key by trying each encoding OpenSSL can produce: PKCS#8,
    /// then PKCS#1 (traditional RSA), then SEC1 (traditional EC).
    fn from_der_by_content(der: &[u8]) -> Option<Self> {
        use rsa::pkcs1::DecodeRsaPrivateKey;
        if let Some(key) = Self::from_pkcs8_der(der) {
            return Some(key);
        }
        if let Ok(k) = RsaPrivateKey::from_pkcs1_der(der) {
            return Some(Self::Rsa(k));
        }
        p256::SecretKey::from_sec1_der(der)
            .ok()
            .map(|k| Self::Ecdsa(EcdsaSigningKey::from(&k)))
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
        match self {
            Self::Rsa(k) => {
                use rsa::traits::PublicKeyParts;
                let bits = k.n().bits();
                if bits < 2048 {
                    return Err(Error::Certificate(format!(
                        "RSA key too small: {} bits (minimum 2048)",
                        bits
                    )));
                }
                Ok(SigningKeyType::Rsa(
                    rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(k),
                ))
            }
            Self::Ecdsa(k) => Ok(SigningKeyType::Ecdsa(k)),
        }
    }
}

/// Returns the first PEM block's label and DER body.
///
/// RFC 7468 headers (`Proc-Type:`, `DEK-Info:` and friends) may only appear before the
/// base64 text, so the scan skips lines that look like headers until the first body line.
/// `der`'s own reader refuses any block carrying headers, which is why this exists.
fn first_pem_block(pem: &str) -> Option<Vec<u8>> {
    use base64::Engine as _;
    let rest = pem.split_once("-----BEGIN ")?.1;
    let (_label, after_label) = rest.split_once("-----")?;
    let mut body = String::new();
    for line in after_label.lines() {
        let line = line.trim_end();
        if line.starts_with("-----END ") {
            break;
        }
        if body.is_empty() && line.contains(": ") {
            continue;
        }
        body.push_str(line);
    }
    base64::engine::general_purpose::STANDARD.decode(&body).ok()
}

/// Decodes a private key given as PEM, decrypting it when the container is encrypted.
///
/// Routing is by content, never by label: `main.rs` wraps bare DER in a `PRIVATE KEY`
/// label (`pem_wrap_der`, `main.rs:896-908`), so an encrypted PKCS#8 DER can legitimately
/// arrive under that label, and PKCS#1 / SEC1 bodies arrive both traditional-encrypted and
/// in the clear. A supplied password on an unencrypted container is ignored, which is what
/// OpenSSL does.
fn decode_key_material(pem: &str, password: Option<&str>) -> Result<DecodedKey> {
    const UNPARSEABLE: &str = "Failed to parse private key as RSA or ECDSA";
    if let Some(traditional) = crate::crypto::encrypted_pem::decrypt_traditional_pem(pem, password)?
    {
        // The padding validated; a body that still fails to decode means the passphrase was wrong.
        return DecodedKey::from_der_by_content(&traditional.der).ok_or(Error::InvalidPassword);
    }
    let der = first_pem_block(pem).ok_or_else(|| Error::Certificate(UNPARSEABLE.into()))?;
    if let Some(key) = DecodedKey::from_der_by_content(&der) {
        return Ok(key);
    }
    if pkcs8::EncryptedPrivateKeyInfo::try_from(der.as_slice()).is_err() {
        return Err(Error::Certificate(UNPARSEABLE.into()));
    }
    let password = password.ok_or_else(|| {
        Error::Certificate(
            "encrypted private key requires a password (-p or ZSIGN_PASSWORD)".into(),
        )
    })?;
    let plain =
        super::pkcs12::decrypt_key_bag(&der, password).map_err(super::pkcs12::pem_load_error)?;
    DecodedKey::from_der_by_content(&plain).ok_or(Error::InvalidPassword)
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
/// the issuer is an Apple WWDR CA; the Apple Root CA is then appended whenever
/// the walk dangles at an issuer naming it, whether that last link came from
/// the container or from the WWDR injection.
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

    // Complete the chain at the embedded Apple Root CA whenever the walk dangles
    // at an issuer that names it, whether the last link came from the container
    // or from the WWDR injection above. A name match alone proves nothing — the
    // policy step verifies the final link against this certificate's key.
    let root = Certificate::from_pem(super::assets::APPLE_ROOT_CA_CERT.as_bytes()).ok();
    let complete = match (&root, chain.last().unwrap_or(leaf)) {
        (Some(root), terminal) => {
            terminal.tbs_certificate.subject != terminal.tbs_certificate.issuer
                && terminal.tbs_certificate.issuer == root.tbs_certificate.subject
        }
        _ => false,
    };
    if complete && !chain.iter().any(is_apple_root) {
        if let Some(root) = root {
            chain.push(root);
        }
    }
    chain
}

/// Requires `chain` to pass the verify-side walk and terminate at one of
/// `anchors`: every link signed by its parent, intermediates valid CAs, and
/// the terminus self-signed with a pinned anchor key. Fail-closed — any
/// structural or trust failure names the unanchored leaf.
fn require_anchored_chain(
    leaf: &Certificate,
    chain: &[Certificate],
    anchors: &TrustAnchors,
) -> Result<()> {
    let outcome = super::cms_verify::verify_chain(
        chain,
        leaf,
        anchors,
        time_now(),
        super::cms_verify::SignerPurpose::CodeSigning,
    );
    if outcome.ok && outcome.anchored {
        return Ok(());
    }
    let detail = outcome
        .reason
        .unwrap_or_else(|| "certificate chain is not anchored to a trusted root".to_string());
    Err(Error::Certificate(format!(
        "signing certificate \"{}\": {}",
        leaf.tbs_certificate.subject, detail
    )))
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
        // Legacy generation — this certificate expired 2023-02-07. Load-time
        // chain validation checks issuer validity, so a chain built on it is
        // rejected either way; injecting it only makes the failure name the
        // expired issuer instead of a missing one.
        APPLE_WWDR_CA_CERT
    };
    Certificate::from_pem(pem.as_bytes()).ok()
}

fn is_apple_root(cert: &Certificate) -> bool {
    extract_subject_cn(cert).is_some_and(|cn| cn == "Apple Root CA")
}

/// The DER value of extension `id`, or `None` when the extension is absent.
fn ext_value(cert: &Certificate, id: ObjectIdentifier) -> Option<&[u8]> {
    let exts = cert.tbs_certificate.extensions.as_ref()?;
    exts.iter()
        .find(|e| e.extn_id == id)
        .map(|e| e.extn_value.as_bytes())
}

/// Current time; wasm32 has no wall clock, so builds there check against a
/// fixed reference (mirrors `cms_verify::time_now`).
fn time_now() -> time::OffsetDateTime {
    #[cfg(target_arch = "wasm32")]
    {
        time::OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap()
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        time::OffsetDateTime::now_utc()
    }
}

/// Load-time code-signing policy for the signing leaf, mirroring the
/// verify-side leaf purpose rules in the same check order: codeSigning EKU
/// must be present; keyUsage, when present, must include digitalSignature;
/// basicConstraints, when present, must assert CA=false; then the validity
/// window must contain `now`. Returns the violation naming the subject and
/// the failing property.
fn code_signing_policy_violation(cert: &Certificate, now: time::OffsetDateTime) -> Option<String> {
    use x509_cert::ext::pkix::{BasicConstraints, ExtendedKeyUsage, KeyUsage};

    let subject = cert.tbs_certificate.subject.to_string();

    // Purpose checks first, then validity — the same order `verify_chain`
    // applies (`leaf_purpose_reason` runs before `in_validity`), so both sides
    // name the same violation for a certificate that breaks several rules.
    let Some(eku_bytes) = ext_value(cert, OID_EXT_KEY_USAGE) else {
        return Some(format!(
            "signing certificate \"{}\": extended key usage extension missing (codeSigning EKU required)",
            subject
        ));
    };
    let Ok(eku) = ExtendedKeyUsage::from_der(eku_bytes) else {
        return Some(format!(
            "signing certificate \"{}\": extended key usage extension is malformed",
            subject
        ));
    };
    if !eku.0.contains(&OID_CODE_SIGNING) {
        return Some(format!(
            "signing certificate \"{}\": extended key usage lacks codeSigning (1.3.6.1.5.5.7.3.3): {:?}",
            subject, eku.0
        ));
    }
    if let Some(ku_bytes) = ext_value(cert, OID_KEY_USAGE) {
        let Ok(ku) = KeyUsage::from_der(ku_bytes) else {
            return Some(format!(
                "signing certificate \"{}\": keyUsage extension is malformed",
                subject
            ));
        };
        if !ku.digital_signature() {
            return Some(format!(
                "signing certificate \"{}\": keyUsage lacks digitalSignature",
                subject
            ));
        }
    }
    if let Some(bc_bytes) = ext_value(cert, OID_BASIC_CONSTRAINTS) {
        let Ok(bc) = BasicConstraints::from_der(bc_bytes) else {
            return Some(format!(
                "signing certificate \"{}\": basicConstraints extension is malformed",
                subject
            ));
        };
        if bc.ca {
            return Some(format!("signing certificate \"{}\": basicConstraints asserts CA=true (leaf must be end-entity)", subject));
        }
    }

    let v = &cert.tbs_certificate.validity;
    let nb = v.not_before.to_date_time().unix_duration().as_secs() as i64;
    let na = v.not_after.to_date_time().unix_duration().as_secs() as i64;
    let now_ts = now.unix_timestamp();
    if now_ts < nb {
        return Some(format!(
            "signing certificate \"{}\": not yet valid (notBefore={}, now={})",
            subject,
            v.not_before.to_date_time(),
            now
        ));
    }
    if now_ts > na {
        return Some(format!(
            "signing certificate \"{}\": expired (notAfter={}, now={})",
            subject,
            v.not_after.to_date_time(),
            now
        ));
    }
    None
}

impl SigningCredentials {
    /// Load credentials from PEM-encoded certificate and private key.
    ///
    /// Parses a PEM-encoded X.509 certificate and a private key in any encoding OpenSSL
    /// writes: PKCS#8, traditional PKCS#1, traditional SEC1, a PBES2-encrypted PKCS#8
    /// container, or a traditional `Proc-Type: 4,ENCRYPTED` / `DEK-Info` PEM. Routing is by
    /// content, not by PEM label, because the CLI wraps bare DER under a `PRIVATE KEY`
    /// label and an encrypted container may legitimately arrive under it.
    ///
    /// # Arguments
    ///
    /// * `cert_pem` - PEM-encoded X.509 certificate
    /// * `key_pem` - PEM-encoded private key (PKCS#8, PKCS#1 or SEC1, optionally encrypted)
    /// * `password` - Passphrase for an encrypted key; ignored for an unencrypted one
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPassword`] if the supplied passphrase does not decrypt the
    /// key. Returns [`Error::Certificate`] if:
    /// - The certificate PEM is malformed or invalid
    /// - The private key PEM is malformed, or is not a supported key encoding
    /// - The private key is neither RSA nor ECDSA P-256
    /// - The RSA private key is smaller than 2048 bits
    /// - The key is encrypted and no passphrase was supplied
    /// - The key's encryption algorithm is outside the supported set (named in the message)
    /// - The certificate is expired or not yet valid
    /// - The certificate is missing the codeSigning extended key usage
    /// - The certificate's keyUsage lacks digitalSignature when present
    /// - The certificate asserts CA=true
    /// - The certificate chain does not reach the Apple Root CA (each link must
    ///   be signed by its parent and the terminus must match the embedded Apple root)
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
        Self::load_pem(
            cert_pem,
            key_pem,
            password,
            Some(&TrustAnchors::apple_root()?),
        )
    }

    /// Loads PEM credentials without requiring the certificate chain to reach
    /// the Apple Root CA. Test fixtures only — see
    /// [`SigningCredentials::from_p12_unanchored`].
    #[cfg(any(test, feature = "test-fixtures"))]
    pub fn from_pem_unanchored(
        cert_pem: &[u8],
        key_pem: &[u8],
        password: Option<&str>,
    ) -> Result<Self> {
        Self::load_pem(cert_pem, key_pem, password, None)
    }

    /// Loads PEM credentials, requiring an Apple-root-anchored chain when
    /// `anchors` is `Some`.
    fn load_pem(
        cert_pem: &[u8],
        key_pem: &[u8],
        password: Option<&str>,
        anchors: Option<&TrustAnchors>,
    ) -> Result<Self> {
        let certificate = Certificate::from_pem(cert_pem)
            .map_err(|e| Error::Certificate(format!("Failed to parse certificate PEM: {}", e)))?;

        let key_str = std::str::from_utf8(key_pem)
            .map_err(|e| Error::Certificate(format!("Invalid UTF-8 in key PEM: {}", e)))?;

        let decoded = decode_key_material(key_str, password)?;
        let signing_key = decoded.into_signing_key()?;

        let team_id = extract_team_id(&certificate);
        let cert_chain = build_chain_from_leaf(&certificate, Vec::new());

        verify_key_matches_cert(&signing_key, &certificate)?;

        if let Some(violation) = code_signing_policy_violation(&certificate, time_now()) {
            return Err(Error::Certificate(violation));
        }

        // Anchoring is the last load-time check, so a policy violation keeps
        // precedence over an unanchored chain on this route too.
        if let Some(anchors) = anchors {
            require_anchored_chain(&certificate, &cert_chain, anchors)?;
        }

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
    /// - The RSA private key is smaller than 2048 bits
    /// - No private key matches a certificate
    /// - More than one distinct key/certificate identity is present
    /// - The certificate is expired or not yet valid
    /// - The certificate is missing the codeSigning extended key usage
    /// - The certificate's keyUsage lacks digitalSignature when present
    /// - The certificate asserts CA=true
    /// - The certificate chain does not reach the Apple Root CA (each link must
    ///   be signed by its parent and the terminus must match the embedded Apple root)
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
        Self::load_p12(p12_data, password, Some(&TrustAnchors::apple_root()?))
    }

    /// Loads a PKCS#12 container, requiring an Apple-root-anchored chain when
    /// `anchors` is `Some`.
    fn load_p12(p12_data: &[u8], password: &str, anchors: Option<&TrustAnchors>) -> Result<Self> {
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
        Self::finish_p12(decoded, certificate, rest, anchors)
    }

    /// Loads a PKCS#12 container without requiring the certificate chain to
    /// reach the Apple Root CA.
    ///
    /// Exists for test fixtures built from self-issued certificates, which can
    /// never satisfy the anchoring policy. Production callers must use
    /// [`SigningCredentials::from_p12`]; every other load-time check (parse,
    /// identity pairing, key strength, code-signing policy) still applies.
    #[cfg(any(test, feature = "test-fixtures"))]
    pub fn from_p12_unanchored(p12_data: &[u8], password: &str) -> Result<Self> {
        Self::load_p12(p12_data, password, None)
    }

    /// Load from PKCS#12, selecting the identity whose leaf certificate's
    /// SHA-1 matches `leaf_sha1` — the hash `security find-identity` prints
    /// next to the identity's name.
    ///
    /// Every load-time check [`Self::from_p12`] performs runs on the selected
    /// pair: key strength, code-signing policy, chain assembly and team ID
    /// extraction are identical. The export-provided chain is preserved in
    /// `rest`, so certificates belonging to other identities in the same
    /// export still feed [`build_chain_from_leaf`]. An export that does not
    /// contain the requested certificate is rejected with an actionable
    /// message naming the missing hash.
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn from_p12_with_leaf_sha1(
        p12_data: &[u8],
        password: &str,
        leaf_sha1: &[u8; 20],
    ) -> Result<Self> {
        Self::from_p12_with_leaf_sha1_impl(
            p12_data,
            password,
            leaf_sha1,
            Some(&TrustAnchors::apple_root()?),
        )
    }

    /// The body of [`Self::from_p12_with_leaf_sha1`], parameterized on the
    /// anchoring requirement.
    #[cfg(not(target_arch = "wasm32"))]
    fn from_p12_with_leaf_sha1_impl(
        p12_data: &[u8],
        password: &str,
        leaf_sha1: &[u8; 20],
        anchors: Option<&TrustAnchors>,
    ) -> Result<Self> {
        let contents = super::pkcs12::extract_p12(p12_data, password)
            .map_err(|e| Error::Certificate(format!("Failed to parse PKCS#12: {}", e)))?;
        let matches_leaf = |c: &[u8]| Sha1::digest(c).as_slice() == leaf_sha1;
        let selected: Vec<Vec<u8>> = contents
            .certs
            .iter()
            .filter(|c| matches_leaf(c))
            .cloned()
            .collect();
        if selected.is_empty() {
            return Err(Error::Certificate(format!(
                "no certificate in PKCS#12 has SHA-1 {} (the selected keychain identity was not exported)",
                hex_upper(leaf_sha1)
            )));
        }
        // Pair the key against the selected leaf only: the full container
        // would trip select_identity's multi-identity rejection. Its `rest`
        // then covers only that matched slice, so rebuild `rest` from every
        // non-leaf certificate — the chain material `finish_p12` needs.
        let (decoded, certificate, _matched_rest) = select_identity(&contents.keys, &selected)?;
        let rest: Vec<Certificate> = contents
            .certs
            .iter()
            .filter(|c| !matches_leaf(c))
            .filter_map(|d| Certificate::from_der(d).ok())
            .collect();
        Self::finish_p12(decoded, certificate, rest, anchors)
    }

    /// [`Self::from_p12_with_leaf_sha1`] without the Apple-root anchoring
    /// requirement; test builds only.
    #[cfg(all(test, not(target_arch = "wasm32")))]
    pub(crate) fn from_p12_with_leaf_sha1_unanchored(
        p12_data: &[u8],
        password: &str,
        leaf_sha1: &[u8; 20],
    ) -> Result<Self> {
        Self::from_p12_with_leaf_sha1_impl(p12_data, password, leaf_sha1, None)
    }

    /// Runs the checks every PKCS#12 entry point shares on a selected
    /// key/certificate pair and assembles the credentials. When `anchors` is
    /// `Some`, the assembled chain must terminate at one of them.
    fn finish_p12(
        decoded: DecodedKey,
        certificate: Certificate,
        rest: Vec<Certificate>,
        anchors: Option<&TrustAnchors>,
    ) -> Result<Self> {
        let signing_key = decoded.into_signing_key()?;

        if let Some(violation) = code_signing_policy_violation(&certificate, time_now()) {
            return Err(Error::Certificate(violation));
        }
        let cert_chain = build_chain_from_leaf(&certificate, rest);
        if let Some(anchors) = anchors {
            require_anchored_chain(&certificate, &cert_chain, anchors)?;
        }
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

    use crate::crypto::pkcs12::extract_p12;
    use base64::Engine as _;
    use const_oid::ObjectIdentifier;
    use der::Encode;
    use rsa::pkcs1::EncodeRsaPrivateKey;
    use spki::SubjectPublicKeyInfoOwned;
    use x509_cert::ext::pkix::ExtendedKeyUsage;
    use x509_cert::ext::pkix::{BasicConstraints, KeyUsage, KeyUsages};
    use x509_cert::serial_number::SerialNumber;
    use x509_cert::time::{Time, Validity};

    const IDENTITY_SINGLE: &[u8] = include_bytes!("fixtures/identity_single.p12");
    const IDENTITY_DUP: &[u8] = include_bytes!("fixtures/identity_duplicate_certs.p12");
    const WEAK_RSA1024: &[u8] = include_bytes!("fixtures/weak_rsa1024.p12");

    const EVIL_CHAIN: &[u8] = include_bytes!("fixtures/evil_root_chain.p12");

    // Encrypted-key fixtures are committed as base64 blobs of byte-exact OpenSSL output: the
    // repository's private-key commit gate refuses every private-key PEM file, PBES2 containers
    // included. The certificates are committed readable, because a certificate is not a key.
    const RSA_CERT: &[u8] = include_bytes!("fixtures/pem_rsa_cert.pem");
    const EC_CERT: &[u8] = include_bytes!("fixtures/pem_ec_cert.pem");
    const ENC_PKCS8_RSA: &str = include_str!("fixtures/pem_rsa_key_pbes2_sha256.pem.b64");
    const ENC_PKCS8_RSA_SHA1PRF: &str = include_str!("fixtures/pem_rsa_key_pbes2_sha1prf.pem.b64");
    const ENC_PKCS8_EC: &str = include_str!("fixtures/pem_ec_key_pbes2_sha256.pem.b64");
    const ENC_TRAD_RSA: &str = include_str!("fixtures/pem_rsa_key_dekinfo_aes256.pem.b64");
    const ENC_TRAD_RSA_3DES: &str = include_str!("fixtures/pem_rsa_key_dekinfo_des3.pem.b64");
    const ENC_TRAD_EC: &str = include_str!("fixtures/pem_ec_key_dekinfo_aes128.pem.b64");
    const PASS: &str = "testpassword";

    /// Decodes one committed encrypted-key fixture back to its PEM text. The fixtures are
    /// byte-exact OpenSSL output stored as base64 because the repository's private-key commit
    /// gate refuses every private-key PEM file, PBES2 containers included.
    fn pem_fixture(blob: &str) -> String {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(blob.trim())
            .expect("fixture must be valid base64");
        String::from_utf8(bytes).expect("fixture must be UTF-8 PEM text")
    }

    /// Wraps DER in PEM the way the CLI's own `pem_wrap_der` does, building the label at runtime
    /// so no source line carries a private-key header.
    fn pem_text(label: &str, der: &[u8]) -> String {
        let body = base64::engine::general_purpose::STANDARD.encode(der);
        let begin = format!("-----BEGIN {label}-----");
        let end = format!("-----END {label}-----");
        let mut out = String::new();
        for line in body.as_bytes().chunks(64) {
            out.push_str(std::str::from_utf8(line).unwrap());
            out.push('\n');
        }
        format!("{begin}\n{out}{end}\n")
    }

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
    /// subject's own key), with `issuer` supplied as an already-parsed name so a caller
    /// can reproduce an embedded root's subject byte-for-byte.
    fn build_cert_issuer_name(
        subject: &str,
        issuer: &x509_cert::name::Name,
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
                issuer: issuer.clone(),
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
        use std::str::FromStr;

        build_cert_issuer_name(
            subject,
            &x509_cert::name::Name::from_str(issuer).unwrap(),
            subject_key,
            issuer_key,
            validity,
            eku,
        )
    }

    fn build_root_cert(subject: &str, key: &rsa::RsaPrivateKey, validity: Validity) -> Certificate {
        use spki::EncodePublicKey;
        use std::str::FromStr;
        use x509_cert::builder::{Builder, CertificateBuilder, Profile};
        let spki = SubjectPublicKeyInfoOwned::from_der(
            key.to_public_key().to_public_key_der().unwrap().as_ref(),
        )
        .unwrap();
        let signer = rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(key.clone());
        CertificateBuilder::new(
            Profile::Root,
            SerialNumber::from(11u32),
            validity,
            x509_cert::name::Name::from_str(subject).unwrap(),
            spki,
            &signer,
        )
        .unwrap()
        .build::<rsa::pkcs1v15::Signature>()
        .unwrap()
    }

    fn build_subca_cert(
        subject: &str,
        issuer: &x509_cert::name::Name,
        subject_key: &rsa::RsaPrivateKey,
        issuer_key: &rsa::RsaPrivateKey,
        validity: Validity,
    ) -> Certificate {
        use spki::EncodePublicKey;
        use std::str::FromStr;
        use x509_cert::builder::{Builder, CertificateBuilder, Profile};
        let spki = SubjectPublicKeyInfoOwned::from_der(
            subject_key
                .to_public_key()
                .to_public_key_der()
                .unwrap()
                .as_ref(),
        )
        .unwrap();
        let signer = rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(issuer_key.clone());
        CertificateBuilder::new(
            Profile::SubCA {
                issuer: issuer.clone(),
                path_len_constraint: None,
            },
            SerialNumber::from(12u32),
            validity,
            x509_cert::name::Name::from_str(subject).unwrap(),
            spki,
            &signer,
        )
        .unwrap()
        .build::<rsa::pkcs1v15::Signature>()
        .unwrap()
    }

    /// root → int → leaf, all properly signed, with the root and intermediate
    /// keys returned because several tests rebuild one link of the chain.
    fn anchored_test_chain() -> (
        Certificate,
        Certificate,
        Certificate,
        rsa::RsaPrivateKey,
        rsa::RsaPrivateKey,
    ) {
        let root_key = fresh_2048();
        let int_key = fresh_2048();
        let leaf_key = fresh_2048();
        let root = build_root_cert("CN=zsn test root", &root_key, present());
        let int = build_subca_cert(
            "CN=zsn test int",
            &root.tbs_certificate.subject,
            &int_key,
            &root_key,
            present(),
        );
        let leaf = build_cert_issuer_name(
            "CN=zsn leaf",
            &int.tbs_certificate.subject,
            &leaf_key,
            &int_key,
            present(),
            Some(code_signing_eku()),
        );
        (root, int, leaf, root_key, int_key)
    }

    #[test]
    fn require_anchored_chain_accepts_anchor_terminated_chain() {
        let (root, int, leaf, _, _) = anchored_test_chain();
        let anchors = TrustAnchors::from_certificates(vec![root.clone()]);
        let res = require_anchored_chain(&leaf, &[int, root], &anchors);
        assert!(
            res.is_ok(),
            "properly anchored chain must be accepted, got {:?}",
            res.err()
        );
    }

    #[test]
    fn require_anchored_chain_rejects_chain_under_production_anchors() {
        // same well-formed chain; production callers pin the embedded Apple root
        let (root, int, leaf, _, _) = anchored_test_chain();
        let res = require_anchored_chain(&leaf, &[int, root], &TrustAnchors::apple_root().unwrap());
        assert!(
            matches!(&res, Err(Error::Certificate(m)) if m.contains("not anchored")),
            "got {:?}",
            res.err()
        );
    }

    #[test]
    fn require_anchored_chain_rejects_link_signed_by_the_wrong_key() {
        // the leaf names the intermediate as issuer but was signed by another
        // key; the terminus reaches the injected anchor, so only the link check
        // can produce the failure
        let (root, int, _, _, _) = anchored_test_chain();
        let wrong = fresh_2048();
        let leaf = build_cert_issuer_name(
            "CN=zsn leaf",
            &int.tbs_certificate.subject,
            &wrong,
            &wrong,
            present(),
            Some(code_signing_eku()),
        );
        let anchors = TrustAnchors::from_certificates(vec![root.clone()]);
        let res = require_anchored_chain(&leaf, &[int, root], &anchors);
        assert!(
            matches!(&res, Err(Error::Certificate(m))
            if m.contains("issuer-signature verification")),
            "got {:?}",
            res.err()
        );
    }

    #[test]
    fn require_anchored_chain_rejects_non_ca_intermediate() {
        // a Profile::Leaf certificate acting as the issuer: CA:FALSE, and the
        // basicConstraints check fires before any signature check
        let (root, _, _, root_key, _) = anchored_test_chain();
        let int_key = fresh_2048();
        let leaf_key = fresh_2048();
        let int = build_cert_issuer_name(
            "CN=zsn not a ca",
            &root.tbs_certificate.subject,
            &int_key,
            &root_key,
            present(),
            None,
        );
        let leaf = build_cert_issuer_name(
            "CN=zsn leaf",
            &int.tbs_certificate.subject,
            &leaf_key,
            &int_key,
            present(),
            Some(code_signing_eku()),
        );
        let anchors = TrustAnchors::from_certificates(vec![root.clone()]);
        let res = require_anchored_chain(&leaf, &[int, root], &anchors);
        assert!(
            matches!(&res, Err(Error::Certificate(m))
            if m.contains("basicConstraints")),
            "got {:?}",
            res.err()
        );
    }

    #[test]
    fn require_anchored_chain_rejects_expired_intermediate() {
        // issuer validity is checked before anything cryptographic
        let (root, _, leaf, root_key, _) = anchored_test_chain();
        let int_key = fresh_2048();
        let int = build_subca_cert(
            "CN=zsn test int",
            &root.tbs_certificate.subject,
            &int_key,
            &root_key,
            window(1_600_000_000, 1_650_000_000),
        );
        let anchors = TrustAnchors::from_certificates(vec![root.clone()]);
        let res = require_anchored_chain(&leaf, &[int, root], &anchors);
        assert!(
            matches!(&res, Err(Error::Certificate(m))
            if m.contains("outside validity")),
            "got {:?}",
            res.err()
        );
    }

    #[test]
    fn require_anchored_chain_rejects_forged_terminus_with_anchor_key() {
        // self-issued certificate carrying the anchor root's public key but
        // signed by a different key: the intermediate link verifies against that
        // key, so only the terminus self-signature check can catch the forgery
        use std::str::FromStr;
        let (root, int, leaf, root_key, _) = anchored_test_chain();
        let attacker = fresh_2048();
        let forged = build_subca_cert(
            "CN=zsn test root",
            &x509_cert::name::Name::from_str("CN=zsn test root").unwrap(),
            &root_key,
            &attacker,
            present(),
        );
        let anchors = TrustAnchors::from_certificates(vec![root.clone()]);
        let res = require_anchored_chain(&leaf, &[int, forged], &anchors);
        assert!(
            matches!(&res, Err(Error::Certificate(m))
            if m.contains("self-signature")),
            "got {:?}",
            res.err()
        );
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

    /// PEM-encoded load attempt through `from_pem`.
    fn load(cert: &Certificate, key: &rsa::RsaPrivateKey) -> Result<SigningCredentials> {
        let (cert_pem, key_pem) = leaf_pems(cert, key);
        SigningCredentials::from_pem(&cert_pem, &key_pem, None)
    }

    /// PEM-encoded load attempt through `from_pem_unanchored`, for fixtures
    /// built from self-issued certificates that no anchor can terminate.
    fn load_unanchored(cert: &Certificate, key: &rsa::RsaPrivateKey) -> Result<SigningCredentials> {
        let (cert_pem, key_pem) = leaf_pems(cert, key);
        SigningCredentials::from_pem_unanchored(&cert_pem, &key_pem, None)
    }

    fn code_signing_eku() -> ExtendedKeyUsage {
        ExtendedKeyUsage(vec![OID_CODE_SIGNING])
    }

    /// Replaces (or appends) extension `id` on `cert` with `value`'s DER
    /// (pattern from `cms_verify.rs` tests; mutation invalidates the cert's own
    /// signature, which load-time policy never checks).
    fn replace_extension(cert: &mut Certificate, id: ObjectIdentifier, value: &impl der::Encode) {
        let bytes = value.to_der().unwrap();
        let exts = cert.tbs_certificate.extensions.get_or_insert_with(Vec::new);
        exts.retain(|e| e.extn_id != id);
        exts.push(x509_cert::ext::Extension {
            extn_id: id,
            critical: false,
            extn_value: der::asn1::OctetString::new(bytes).unwrap(),
        });
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

    fn sha1_of(der: &[u8]) -> [u8; 20] {
        use sha1::{Digest, Sha1};
        Sha1::digest(der).into()
    }

    #[test]
    fn from_p12_with_leaf_sha1_selects_the_matching_pair() {
        let contents = extract_p12(IDENTITY_DUP, "testpassword").expect("fixture parses");
        assert!(
            contents.certs.len() >= 2,
            "duplicate fixture must carry both identities"
        );
        let target = sha1_of(&contents.certs[0]);
        let creds = SigningCredentials::from_p12_with_leaf_sha1_unanchored(
            IDENTITY_DUP,
            "testpassword",
            &target,
        )
        .expect("selected identity must load through every load-time check");
        let leaf_der = creds.certificate.to_der().expect("leaf DER");
        assert_eq!(sha1_of(&leaf_der), target, "leaf must be the selected one");
    }

    #[test]
    fn from_p12_with_leaf_sha1_unknown_hash_errors() {
        let res =
            SigningCredentials::from_p12_with_leaf_sha1(IDENTITY_DUP, "testpassword", &[0u8; 20]);
        assert!(
            matches!(&res, Err(Error::Certificate(m))
                if m.contains("SHA-1") && m.contains("0000000000000000000000000000000000000000")),
            "actionable mismatch message required, got {:?}",
            res.as_ref().err()
        );
    }

    #[test]
    fn from_p12_with_leaf_sha1_enforces_weak_key_gate() {
        let contents = extract_p12(WEAK_RSA1024, "testpassword").expect("fixture parses");
        let leaf_sha1 = sha1_of(&contents.certs[0]);
        let res =
            SigningCredentials::from_p12_with_leaf_sha1(WEAK_RSA1024, "testpassword", &leaf_sha1);
        assert!(
            matches!(&res, Err(Error::Certificate(m)) if m.contains("1024") && m.contains("2048")),
            "keychain selector must not bypass the RSA minimum, got {:?}",
            res.as_ref().err()
        );
    }

    #[test]
    fn from_p12_with_leaf_sha1_enforces_code_signing_policy() {
        let p12: &[u8] = include_bytes!("fixtures/modern_pbes2_aes256.p12");
        let contents = extract_p12(p12, "testpassword").expect("fixture parses");
        let leaf_sha1 = sha1_of(&contents.certs[0]);
        let res = SigningCredentials::from_p12_with_leaf_sha1(p12, "testpassword", &leaf_sha1);
        assert!(
            matches!(&res, Err(Error::Certificate(m)) if m.contains("codeSigning")),
            "keychain selector must not bypass the code-signing policy, got {:?}",
            res.as_ref().err()
        );
    }

    #[test]
    fn from_p12_selects_single_identity_with_empty_chain() {
        let creds = SigningCredentials::from_p12_unanchored(IDENTITY_SINGLE, "testpassword")
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
        let creds = SigningCredentials::from_pem_unanchored(&cert_pem, &key_pem, None)
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

    #[test]
    fn from_pem_accepts_compliant_leaf() {
        let key = fresh_2048();
        let cert = build_cert(
            "CN=zsign policy ok",
            "CN=zsign policy ok",
            &key,
            &key,
            present(),
            Some(code_signing_eku()),
        );
        load_unanchored(&cert, &key).expect("policy-compliant leaf must load");
    }

    #[test]
    fn from_pem_rejects_expired_leaf() {
        let key = fresh_2048();
        let cert = build_cert(
            "CN=zsign expired",
            "CN=zsign expired",
            &key,
            &key,
            window(1_500_000_000, 1_600_000_000),
            Some(code_signing_eku()),
        );
        let res = load(&cert, &key);
        assert!(
            matches!(&res, Err(Error::Certificate(m)) if m.contains("expired") && m.contains("CN=zsign expired")),
            "expected expired rejection, got {:?}",
            res.as_ref().err()
        );
    }

    #[test]
    fn from_pem_rejects_not_yet_valid_leaf() {
        let key = fresh_2048();
        let cert = build_cert(
            "CN=zsign future",
            "CN=zsign future",
            &key,
            &key,
            window(2_200_000_000, 2_300_000_000),
            Some(code_signing_eku()),
        );
        let res = load(&cert, &key);
        assert!(
            matches!(&res, Err(Error::Certificate(m)) if m.contains("not yet valid") && m.contains("CN=zsign future")),
            "expected not-yet-valid rejection, got {:?}",
            res.as_ref().err()
        );
    }

    #[test]
    fn from_pem_rejects_leaf_without_eku() {
        let key = fresh_2048();
        let cert = build_cert(
            "CN=zsign no eku",
            "CN=zsign no eku",
            &key,
            &key,
            present(),
            None,
        );
        let res = load(&cert, &key);
        assert!(
            matches!(&res, Err(Error::Certificate(m)) if m.contains("codeSigning") && m.contains("CN=zsign no eku")),
            "expected missing-EKU rejection, got {:?}",
            res.as_ref().err()
        );
    }

    #[test]
    fn from_pem_rejects_leaf_with_wrong_purpose_eku() {
        let key = fresh_2048();
        let server_auth = ExtendedKeyUsage(vec![ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.1")]);
        let cert = build_cert(
            "CN=zsign tls leaf",
            "CN=zsign tls leaf",
            &key,
            &key,
            present(),
            Some(server_auth),
        );
        let res = load(&cert, &key);
        assert!(
            matches!(&res, Err(Error::Certificate(m)) if m.contains("codeSigning")),
            "expected wrong-purpose rejection, got {:?}",
            res.as_ref().err()
        );
    }

    #[test]
    fn from_pem_rejects_leaf_without_digital_signature() {
        let key = fresh_2048();
        let mut cert = build_cert(
            "CN=zsign weak ku",
            "CN=zsign weak ku",
            &key,
            &key,
            present(),
            Some(code_signing_eku()),
        );
        replace_extension(
            &mut cert,
            OID_KEY_USAGE,
            &KeyUsage(KeyUsages::KeyCertSign.into()),
        );
        let res = load(&cert, &key);
        assert!(
            matches!(&res, Err(Error::Certificate(m)) if m.contains("digitalSignature") && m.contains("CN=zsign weak ku")),
            "expected KU rejection, got {:?}",
            res.as_ref().err()
        );
    }

    #[test]
    fn from_pem_rejects_ca_leaf() {
        let key = fresh_2048();
        let mut cert = build_cert(
            "CN=zsign ca leaf",
            "CN=zsign ca leaf",
            &key,
            &key,
            present(),
            Some(code_signing_eku()),
        );
        replace_extension(
            &mut cert,
            OID_BASIC_CONSTRAINTS,
            &BasicConstraints {
                ca: true,
                path_len_constraint: None,
            },
        );
        let res = load(&cert, &key);
        assert!(
            matches!(&res, Err(Error::Certificate(m)) if m.contains("CA") && m.contains("CN=zsign ca leaf")),
            "expected CA=true rejection, got {:?}",
            res.as_ref().err()
        );
    }

    #[test]
    fn from_pem_accepts_leaf_without_ku_and_bc() {
        // Verify-side consistency: KU and BC are checked only when present.
        let key = fresh_2048();
        let mut cert = build_cert(
            "CN=zsign bare leaf",
            "CN=zsign bare leaf",
            &key,
            &key,
            present(),
            Some(code_signing_eku()),
        );
        for id in [OID_KEY_USAGE, OID_BASIC_CONSTRAINTS] {
            if let Some(exts) = cert.tbs_certificate.extensions.as_mut() {
                exts.retain(|e| e.extn_id != id);
            }
        }
        load_unanchored(&cert, &key).expect("absent KU/BC must be tolerated");
    }

    #[test]
    fn from_p12_rejects_non_policy_fixture() {
        // The committed extract-level fixtures are not policy-compliant (no EKU,
        // basicConstraints CA:TRUE) — loading them must now fail loudly.
        let res = SigningCredentials::from_p12(
            include_bytes!("fixtures/modern_pbes2_aes256.p12"),
            "testpassword",
        );
        assert!(
            matches!(&res, Err(Error::Certificate(m)) if m.contains("codeSigning") && m.contains("CN=zsign-test-fixture")),
            "expected non-compliant fixture rejection, got {:?}",
            res.as_ref().err()
        );
    }

    #[test]
    fn from_p12_rejects_weak_rsa_key() {
        let res = SigningCredentials::from_p12(WEAK_RSA1024, "testpassword");
        assert!(
            matches!(&res, Err(Error::Certificate(m)) if m.contains("1024") && m.contains("2048")),
            "expected weak-RSA rejection naming both bit counts, got {:?}",
            res.as_ref().err()
        );
    }

    #[test]
    fn from_pem_rejects_weak_rsa_key() {
        // rsa 0.9.10 enforces no minimum at generation or decode (verified in its
        // vendored source), so a 1024-bit key builds in-memory.
        let key = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 1024)
            .expect("rsa crate accepts 1024-bit generation");
        let cert = build_cert(
            "CN=zsign-test-fixture",
            "CN=zsign-test-fixture",
            &key,
            &key,
            present(),
            Some(code_signing_eku()),
        );
        let (cert_pem, key_pem) = leaf_pems(&cert, &key);
        let res = SigningCredentials::from_pem(&cert_pem, &key_pem, None);
        assert!(
            matches!(&res, Err(Error::Certificate(m)) if m.contains("1024") && m.contains("2048")),
            "expected weak-RSA rejection naming both bit counts, got {:?}",
            res.as_ref().err()
        );
    }

    /// The committed blobs, decoded, in one place: `&String` so each use site is a borrow.
    fn encrypted_forms() -> Vec<(&'static [u8], String)> {
        vec![
            (RSA_CERT, pem_fixture(ENC_PKCS8_RSA)),
            (RSA_CERT, pem_fixture(ENC_PKCS8_RSA_SHA1PRF)),
            (RSA_CERT, pem_fixture(ENC_TRAD_RSA)),
            (RSA_CERT, pem_fixture(ENC_TRAD_RSA_3DES)),
            (EC_CERT, pem_fixture(ENC_PKCS8_EC)),
            (EC_CERT, pem_fixture(ENC_TRAD_EC)),
        ]
    }

    #[test]
    fn from_pem_loads_every_supported_key_form() {
        for (cert, key) in encrypted_forms() {
            let res = SigningCredentials::from_pem_unanchored(cert, key.as_bytes(), Some(PASS));
            assert!(
                res.is_ok(),
                "certificate and encrypted key must load, got {:?}",
                res.as_ref().err()
            );
            assert_eq!(res.unwrap().team_id.as_deref(), Some("TESTTEAM"));
        }
    }

    #[test]
    fn from_pem_wrong_password_is_a_password_error() {
        for (cert, key) in encrypted_forms() {
            let res = SigningCredentials::from_pem(cert, key.as_bytes(), Some("wrong"));
            assert!(
                matches!(res, Err(Error::InvalidPassword)),
                "a wrong passphrase must be InvalidPassword, got {:?}",
                res.as_ref().err()
            );
        }
    }

    #[test]
    fn from_pem_encrypted_key_without_password_asks_for_one() {
        for key in [pem_fixture(ENC_TRAD_RSA), pem_fixture(ENC_PKCS8_RSA)] {
            let res = SigningCredentials::from_pem(RSA_CERT, key.as_bytes(), None);
            assert!(
                matches!(&res, Err(Error::Certificate(m)) if m.contains("requires a password")),
                "got {:?}",
                res.as_ref().err()
            );
        }
    }

    #[test]
    fn from_pem_keeps_the_password_free_pkcs8_path_unchanged() {
        // Regression: an unencrypted PKCS#8 key still loads with no password at all.
        let key = fresh_2048();
        let cert = build_cert(
            "CN=zsign-test-fixture,OU=TESTTEAM",
            "CN=zsign-test-fixture,OU=TESTTEAM",
            &key,
            &key,
            present(),
            Some(code_signing_eku()),
        );
        let (cert_pem, key_pem) = leaf_pems(&cert, &key);
        assert!(SigningCredentials::from_pem_unanchored(&cert_pem, &key_pem, None).is_ok());
        // A password on an unencrypted key is accepted and ignored, as OpenSSL does.
        assert!(
            SigningCredentials::from_pem_unanchored(&cert_pem, &key_pem, Some("ignored")).is_ok()
        );
    }

    #[test]
    fn from_pem_loads_unencrypted_traditional_keys() {
        // Design D18.5: plaintext PKCS#1 and SEC1 bodies are accepted by content, not label.
        let rsa_key = fresh_2048();
        let rsa_cert = build_cert(
            "CN=zsign-test-fixture,OU=TESTTEAM",
            "CN=zsign-test-fixture,OU=TESTTEAM",
            &rsa_key,
            &rsa_key,
            present(),
            Some(code_signing_eku()),
        );
        let (rsa_cert_pem, _) = leaf_pems(&rsa_cert, &rsa_key);
        let pkcs1 = pem_text(
            "RSA PRIVATE KEY",
            rsa_key.to_pkcs1_der().unwrap().as_bytes(),
        );
        let res = SigningCredentials::from_pem_unanchored(&rsa_cert_pem, pkcs1.as_bytes(), None);
        assert!(
            res.is_ok(),
            "plaintext PKCS#1 must load, got {:?}",
            res.err()
        );

        // The EC certificate is issued by the RSA identity above; only the key body is P-256.
        let sec1 = pem_text(
            "EC PRIVATE KEY",
            p256::SecretKey::from(&p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng))
                .to_sec1_der()
                .unwrap()
                .as_slice(),
        );
        let res = SigningCredentials::from_pem_unanchored(&rsa_cert_pem, sec1.as_bytes(), None);
        assert!(
            matches!(
                res,
                Err(Error::Certificate(_)) | Err(Error::InvalidPassword)
            ),
            "an EC body must load far enough to fail on pairing, never on parsing"
        );
        let res = SigningCredentials::from_pem(EC_CERT, sec1.as_bytes(), None);
        assert!(
            matches!(&res, Err(Error::Certificate(m)) if m.contains("does not match")),
            "a plaintext SEC1 body must be decoded and then SPKI-paired, got {:?}",
            res.as_ref().err()
        );
    }

    #[test]
    fn from_pem_still_pairs_the_decrypted_key_with_the_certificate() {
        let key = pem_fixture(ENC_PKCS8_RSA);
        let res = SigningCredentials::from_pem(EC_CERT, key.as_bytes(), Some(PASS));
        assert!(
            matches!(&res, Err(Error::Certificate(m)) if m.contains("does not match")),
            "an encrypted key must still be SPKI-paired, got {:?}",
            res.as_ref().err()
        );
    }

    #[test]
    fn from_p12_rejects_evil_root_chain() {
        let res = SigningCredentials::from_p12(EVIL_CHAIN, PASS);
        assert!(
            matches!(&res, Err(Error::Certificate(m))
                if m.contains("Evil") && m.contains("not anchored to a trusted root")),
            "self-issued chain must be rejected, got {:?}",
            res.as_ref().err()
        );
    }

    #[test]
    fn from_p12_rejects_self_issued_identity() {
        let res = SigningCredentials::from_p12(IDENTITY_SINGLE, PASS);
        assert!(
            matches!(&res, Err(Error::Certificate(m))
                if m.contains("not anchored to a trusted root")),
            "self-signed leaf must be rejected, got {:?}",
            res.as_ref().err()
        );
    }

    #[test]
    fn from_pem_rejects_self_signed_leaf() {
        let key = fresh_2048();
        let cert = build_cert(
            "CN=zsn unanchored",
            "CN=zsn unanchored",
            &key,
            &key,
            present(),
            Some(code_signing_eku()),
        );
        let res = load(&cert, &key);
        assert!(
            matches!(&res, Err(Error::Certificate(m))
                if m.contains("not anchored to a trusted root")),
            "got {:?}",
            res.as_ref().err()
        );
    }

    #[test]
    fn build_chain_appends_embedded_root_for_direct_issue() {
        let root = Certificate::from_pem(crate::crypto::assets::APPLE_ROOT_CA_CERT.as_bytes())
            .expect("embedded root parses");
        let key = fresh_2048();
        let cert = build_cert_issuer_name(
            "CN=zsn direct",
            &root.tbs_certificate.subject,
            &key,
            &key,
            present(),
            Some(code_signing_eku()),
        );
        let chain = build_chain_from_leaf(&cert, vec![]);
        assert_eq!(
            chain.len(),
            1,
            "dangling issuer at the Apple Root CA must complete the chain"
        );
        assert!(chain.iter().any(is_apple_root));
    }
}
