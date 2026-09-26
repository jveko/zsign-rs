//! Shared test utilities (test-only build).

use x509_cert::builder::{Builder, CertificateBuilder, Profile};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::Validity;

/// Self-issued RSA-2048 credentials (`Profile::Leaf`, codeSigning EKU) with
/// `team_id=Some("TESTTEAM")`.
pub(crate) fn test_credentials() -> crate::SigningCredentials {
    use rsa::pkcs1v15::SigningKey as RsaSigningKey;
    use rsa::RsaPrivateKey;
    use sha2::Sha256;
    use spki::der::Decode;
    use spki::{EncodePublicKey, SubjectPublicKeyInfoOwned};
    use std::str::FromStr;
    use std::time::Duration;

    let mut rng = rand::thread_rng();
    let rsa_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let signing_key = RsaSigningKey::<Sha256>::new(rsa_key.clone());

    let subject = Name::from_str("CN=zsign test,OU=TESTTEAM").unwrap();
    let serial = SerialNumber::from(7u32);
    let validity = Validity::from_now(Duration::from_secs(3600)).unwrap();
    let pub_key_der = rsa_key.to_public_key().to_public_key_der().unwrap();
    let pub_key = SubjectPublicKeyInfoOwned::from_der(pub_key_der.as_ref()).unwrap();

    let mut builder = CertificateBuilder::new(
        Profile::Leaf {
            issuer: subject.clone(),
            enable_key_agreement: false,
            enable_key_encipherment: false,
        },
        serial,
        validity,
        subject,
        pub_key,
        &signing_key,
    )
    .unwrap();
    builder
        .add_extension(&x509_cert::ext::pkix::ExtendedKeyUsage(vec![
            spki::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.3"),
        ]))
        .unwrap();
    let cert = builder.build::<rsa::pkcs1v15::Signature>().unwrap();

    crate::SigningCredentials {
        certificate: cert,
        signing_key: zsign_core::crypto::SigningKeyType::Rsa(RsaSigningKey::<Sha256>::new(rsa_key)),
        cert_chain: vec![],
        team_id: Some("TESTTEAM".to_string()),
    }
}
