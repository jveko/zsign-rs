//! Shared test utilities (test-only build).

use x509_cert::builder::{Builder, CertificateBuilder, Profile};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::Validity;

/// Minimal thin-arm64 Mach-O fixture bytes (see crates/zsign/src/ipa/fixtures/).
pub(crate) fn minimal_macho() -> Vec<u8> {
    include_bytes!("ipa/fixtures/minimal_macho.bin").to_vec()
}

/// minimal_macho() with an injected LC_ENCRYPTION_INFO_64 (cryptid=1, cryptsize=0x1000).
pub(crate) fn minimal_macho_encrypted() -> Vec<u8> {
    let mut data = minimal_macho();
    let ncmds = u32::from_le_bytes(data[16..20].try_into().unwrap());
    let sizeofcmds = u32::from_le_bytes(data[20..24].try_into().unwrap());
    data[16..20].copy_from_slice(&(ncmds + 1).to_le_bytes());
    data[20..24].copy_from_slice(&(sizeofcmds + 24).to_le_bytes());
    let off = 32 + sizeofcmds as usize;
    let lc: [u32; 6] = [0x2c, 24, 0x1000, 0x1000, 1, 0];
    for (i, v) in lc.iter().enumerate() {
        data[off + i * 4..off + i * 4 + 4].copy_from_slice(&v.to_le_bytes());
    }
    data
}

/// Self-signed RSA-2048 credentials with `team_id=Some("TESTTEAM")`.
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

    crate::SigningCredentials {
        certificate: cert,
        signing_key: zsign_core::crypto::SigningKeyType::Rsa(RsaSigningKey::<Sha256>::new(rsa_key)),
        cert_chain: vec![],
        team_id: Some("TESTTEAM".to_string()),
    }
}
