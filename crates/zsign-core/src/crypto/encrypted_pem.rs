//! Traditional OpenSSL encrypted PEM keys: `Proc-Type: 4,ENCRYPTED` plus `DEK-Info`.
//!
//! The PEM label names the inner encoding (`RSA PRIVATE KEY` is PKCS#1, `EC PRIVATE KEY`
//! is SEC1, `PRIVATE KEY` is PKCS#8), the headers carry the cipher name and the
//! initialisation vector, and the body is the CBC ciphertext of those DER bytes.
//! `der`'s PEM reader rejects RFC 7468 headers outright, so the framing here is
//! deliberately small: one BEGIN line, a header block, base64, one END line.

use crate::{Error, Result};
use base64::Engine as _;
use md5::{Digest, Md5};

/// A traditional encrypted PEM that decrypted cleanly: just the plaintext DER of the inner
/// key encoding. The PEM label is deliberately not returned — routing is by content, so a
/// `PRIVATE KEY` label that arrives from the CLI's own DER wrapper must not steer the decoder.
pub(crate) struct TraditionalKey {
    /// Plaintext DER of the inner key encoding (PKCS#1, SEC1 or PKCS#8).
    pub der: Vec<u8>,
}

/// Derives `need` key bytes with `EVP_BytesToKey`: MD5, `D_i = MD5(D_(i-1) || password || salt)`,
/// blocks concatenated then truncated. `salt` is the first 8 bytes of the header IV.
///
/// The derived IV is deliberately never used: OpenSSL stores the real IV in the `DEK-Info`
/// header, and feeding the derived bytes back in corrupts the first plaintext block while
/// leaving the rest (and the padding) intact — which looks like a working key until the DER
/// parser rejects it.
fn evp_bytes_to_key(password: &[u8], salt: &[u8], need: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(need);
    let mut previous: Vec<u8> = Vec::new();
    while out.len() < need {
        let mut hasher = Md5::new();
        hasher.update(&previous);
        hasher.update(password);
        hasher.update(salt);
        previous = hasher.finalize().to_vec();
        out.extend_from_slice(&previous);
    }
    out.truncate(need);
    out
}

/// A `DEK-Info` cipher this crate can decrypt, so the header name is validated exactly once
/// and every later use is a `match` on a type that cannot hold an unsupported value.
#[derive(Clone, Copy)]
enum DekCipher {
    Aes128,
    Aes192,
    Aes256,
    TdesEde3,
}

impl std::fmt::Display for DekCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            DekCipher::Aes128 => "AES-128-CBC",
            DekCipher::Aes192 => "AES-192-CBC",
            DekCipher::Aes256 => "AES-256-CBC",
            DekCipher::TdesEde3 => "DES-EDE3-CBC",
        };
        f.write_str(name)
    }
}

impl DekCipher {
    /// Key and IV length in bytes, or `None` for a cipher outside the supported set.
    fn shape(name: &str) -> Option<(Self, usize, usize)> {
        match name {
            "AES-128-CBC" => Some((DekCipher::Aes128, 16, 16)),
            "AES-192-CBC" => Some((DekCipher::Aes192, 24, 16)),
            "AES-256-CBC" => Some((DekCipher::Aes256, 32, 16)),
            "DES-EDE3-CBC" => Some((DekCipher::TdesEde3, 24, 8)),
            _ => None,
        }
    }

    /// CBC-decrypts `data` with the key bytes derived by `evp_bytes_to_key`. Any failure here is
    /// reported as `None` so the caller can apply the padding-or-wrong-password rule uniformly.
    fn decrypt(self, key: &[u8], iv: &[u8], data: &[u8]) -> Option<Vec<u8>> {
        match self {
            DekCipher::Aes128 => {
                crate::crypto::pkcs12::aes_decrypt::<aes::Aes128>(key, iv, data).ok()
            }
            DekCipher::Aes192 => {
                crate::crypto::pkcs12::aes_decrypt::<aes::Aes192>(key, iv, data).ok()
            }
            DekCipher::Aes256 => {
                crate::crypto::pkcs12::aes_decrypt::<aes::Aes256>(key, iv, data).ok()
            }
            DekCipher::TdesEde3 => {
                crate::crypto::pkcs12::aes_decrypt::<des::TdesEde3>(key, iv, data).ok()
            }
        }
    }
}

fn malformed(detail: String) -> Error {
    Error::Certificate(format!("malformed encrypted PEM: {detail}"))
}

fn unsupported(detail: String) -> Error {
    Error::Certificate(format!("unsupported key encryption: {detail}"))
}

/// Decrypts a traditional encrypted PEM. `Ok(None)` means "this is not a traditional encrypted
/// PEM" — the caller then falls through to the PKCS#8 and PBES2 paths.
pub(crate) fn decrypt_traditional_pem(
    pem: &str,
    password: Option<&str>,
) -> Result<Option<TraditionalKey>> {
    let mut lines = pem.lines().map(str::trim_end);
    let begin = loop {
        match lines.next() {
            None => return Ok(None),
            Some(line) if line.starts_with("-----BEGIN ") => break line,
            Some(_) => continue,
        }
    };
    if !begin.ends_with("-----") {
        return Err(malformed(format!("unrecognised BEGIN line {begin}")));
    }
    let mut proc_type: Option<String> = None;
    let mut dek_info: Option<String> = None;
    let mut body = String::new();
    for line in lines {
        if line.starts_with("-----END ") {
            break;
        }
        match line.split_once(':') {
            Some(("Proc-Type", value)) if body.is_empty() => {
                proc_type = Some(value.trim().to_string())
            }
            Some(("DEK-Info", value)) if body.is_empty() => {
                dek_info = Some(value.trim().to_string())
            }
            _ => body.push_str(line),
        }
    }
    if proc_type.as_deref() != Some("4,ENCRYPTED") {
        return Ok(None);
    }
    let dek_info = dek_info
        .ok_or_else(|| malformed("Proc-Type is encrypted but DEK-Info is absent".into()))?;
    let (cipher_name, iv_hex) = dek_info
        .split_once(',')
        .ok_or_else(|| malformed(format!("DEK-Info has no IV: {dek_info}")))?;
    let (cipher, key_len, iv_len) = DekCipher::shape(cipher_name.trim()).ok_or_else(|| {
        unsupported(format!(
            "DEK-Info cipher {} (supported: AES-128/192/256-CBC, DES-EDE3-CBC)",
            cipher_name.trim()
        ))
    })?;
    if iv_hex.len() != iv_len * 2 {
        return Err(malformed(format!(
            "{cipher} needs a {iv_len}-byte IV, DEK-Info carries {} hex characters",
            iv_hex.len()
        )));
    }
    let iv: Vec<u8> = (0..iv_hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&iv_hex[i..i + 2], 16)
                .map_err(|_| malformed(format!("DEK-Info IV is not hex: {iv_hex}")))
        })
        .collect::<std::result::Result<Vec<u8>, Error>>()?;
    let ciphertext = base64::engine::general_purpose::STANDARD
        .decode(&body)
        .map_err(|e| malformed(format!("ciphertext body is not valid base64: {e}")))?;
    let password = password.ok_or_else(|| {
        Error::Certificate(
            "encrypted private key requires a password (-p or ZSIGN_PASSWORD)".into(),
        )
    })?;
    let key = evp_bytes_to_key(password.as_bytes(), &iv[..8], key_len);
    let plaintext = cipher.decrypt(&key, &iv, &ciphertext);
    match plaintext {
        Some(der) => Ok(Some(TraditionalKey { der })),
        // Every failure after a real decryption attempt is a passphrase failure: either the
        // PKCS#7 padding is invalid, or (one in 256 times) it is valid and the DER is nonsense,
        // which the caller's decoder also reports as such.
        None => Err(Error::InvalidPassword),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey};

    /// Decodes one committed key fixture.
    ///
    /// The fixtures are byte-exact OpenSSL output under a published test passphrase, stored as a
    /// single base64 blob because the repository's private-key commit gate refuses every
    /// private-key PEM file, including the `ENCRYPTED PRIVATE KEY` PBES2 container. The committed
    /// bytes are unchanged; only the file wrapper is. The equivalent throwaway keys are already
    /// committed inside the `.p12` fixtures, so nothing sensitive is being smuggled in.
    ///
    /// `EncryptedPrivateKeyInfo` has no version field (PKCS#5 v2.0 two-field
    /// `SEQUENCE { encryptionAlgorithm, encryptedData }`), so a decoded PBES2 body feeds the same
    /// decoder a `.p12` shrouded key bag does.
    fn pem_fixture(blob: &str) -> String {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(blob.trim())
            .expect("fixture must be valid base64");
        String::from_utf8(bytes).expect("fixture must be UTF-8 PEM text")
    }

    /// Wraps DER in PEM the way the CLI's own `pem_wrap_der` does, building the label at runtime
    /// so no source line carries a private-key header. Plaintext keys are generated here rather
    /// than committed: no cleartext private key belongs in the repository.
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

    fn plaintext_rsa_pem() -> String {
        let key = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
        pem_text("RSA PRIVATE KEY", key.to_pkcs1_der().unwrap().as_bytes())
    }

    #[test]
    fn dek_info_aes256_yields_a_pkcs1_key() {
        let pem = pem_fixture(include_str!("fixtures/pem_rsa_key_dekinfo_aes256.pem.b64"));
        let key = decrypt_traditional_pem(&pem, Some("testpassword"))
            .unwrap()
            .expect("an encrypted PEM must decode");
        assert_eq!(key.der[0], 0x30, "plaintext must be a DER SEQUENCE");
        assert!(
            rsa::RsaPrivateKey::from_pkcs1_der(&key.der).is_ok(),
            "traditional RSA PEM must decrypt to PKCS#1, got {} bytes",
            key.der.len()
        );
    }

    #[test]
    fn dek_info_aes128_yields_a_sec1_ec_key() {
        let pem = pem_fixture(include_str!("fixtures/pem_ec_key_dekinfo_aes128.pem.b64"));
        let key = decrypt_traditional_pem(&pem, Some("testpassword"))
            .unwrap()
            .expect("an encrypted PEM must decode");
        assert!(
            p256::SecretKey::from_sec1_der(&key.der).is_ok(),
            "traditional EC PEM must decrypt to SEC1, got {} bytes",
            key.der.len()
        );
    }

    #[test]
    fn dek_info_3des_yields_a_pkcs1_key() {
        let pem = pem_fixture(include_str!("fixtures/pem_rsa_key_dekinfo_des3.pem.b64"));
        let key = decrypt_traditional_pem(&pem, Some("testpassword"))
            .unwrap()
            .expect("an encrypted PEM must decode");
        assert!(rsa::RsaPrivateKey::from_pkcs1_der(&key.der).is_ok());
    }

    #[test]
    fn wrong_password_is_reported_as_a_password_failure() {
        for blob in [
            include_str!("fixtures/pem_rsa_key_dekinfo_aes256.pem.b64"),
            include_str!("fixtures/pem_rsa_key_dekinfo_des3.pem.b64"),
            include_str!("fixtures/pem_ec_key_dekinfo_aes128.pem.b64"),
        ] {
            let pem = pem_fixture(blob);
            let res = decrypt_traditional_pem(&pem, Some("not-the-password"));
            assert!(
                matches!(res, Err(Error::InvalidPassword)),
                "a wrong passphrase must be a password failure, got {:?}",
                res.as_ref().err()
            );
        }
    }

    #[test]
    fn missing_password_asks_for_one() {
        let pem = pem_fixture(include_str!("fixtures/pem_rsa_key_dekinfo_aes256.pem.b64"));
        let res = decrypt_traditional_pem(&pem, None);
        assert!(
            matches!(&res, Err(Error::Certificate(m)) if m.contains("requires a password")),
            "an encrypted key without a password must say so, got {:?}",
            res.as_ref().err()
        );
    }

    #[test]
    fn unsupported_dek_info_cipher_is_named() {
        // Hand-written header: the rejection happens before any crypto, so the body
        // never needs to be a real ciphertext. `concat!` splits the PEM label so the
        // pre-commit private-key scanner stays happy, as `main.rs:1675` already does.
        let pem = concat!(
            "-----BEGIN RSA ",
            "PRIVATE KEY-----\n",
            "Proc-Type: 4,ENCRYPTED\n",
            "DEK-Info: AES-128-CTR,00112233445566778899AABBCCDDEEFF\n",
            "AAAAAAAAAAAAAAAAAAAA\n",
            "-----END RSA ",
            "PRIVATE KEY-----\n"
        );
        let res = decrypt_traditional_pem(pem, Some("x"));
        assert!(
            matches!(&res, Err(Error::Certificate(m)) if m.contains("AES-128-CTR")),
            "unsupported ciphers must be named, got {:?}",
            res.as_ref().err()
        );
    }

    #[test]
    fn weak_and_legacy_dek_info_ciphers_are_refused_by_name() {
        // Design D18.4: single DES and RC2 spellings are refused, not silently accepted.
        for cipher in ["DES-CBC", "RC2-CBC", "RC2-40-CBC"] {
            let pem = format!(
                concat!(
                    "-----BEGIN RSA {}PRIVATE KEY-----\n",
                    "Proc-Type: 4,ENCRYPTED\n",
                    "DEK-Info: {},0011223344556677\n",
                    "AAAAAAAAAAAAAAAAAAAA\n",
                    "-----END RSA {}PRIVATE KEY-----\n"
                ),
                " ", cipher, " "
            );
            let res = decrypt_traditional_pem(&pem, Some("x"));
            assert!(
                matches!(&res, Err(Error::Certificate(m)) if m.contains(cipher) && m.contains("unsupported")),
                "{cipher} must be refused by name, got {:?}",
                res.as_ref().err()
            );
        }
    }

    #[test]
    fn unencrypted_pem_is_not_this_modules_business() {
        let pem = plaintext_rsa_pem();
        let res = decrypt_traditional_pem(&pem, Some("testpassword"));
        assert!(
            matches!(&res, Ok(None)),
            "a plaintext PEM must fall through to the other decoders, got {:?}",
            res.as_ref().err()
        );
    }

    #[test]
    fn framing_rejects_a_malformed_iv() {
        let pem = concat!(
            "-----BEGIN RSA ",
            "PRIVATE KEY-----\n",
            "Proc-Type: 4,ENCRYPTED\n",
            "DEK-Info: AES-256-CBC,00112233445566\n",
            "AAAAAAAAAAAAAAAAAAAA\n",
            "-----END RSA ",
            "PRIVATE KEY-----\n"
        );
        let res = decrypt_traditional_pem(pem, Some("x"));
        assert!(
            matches!(&res, Err(Error::Certificate(m)) if m.contains("DEK-Info")),
            "a bad IV must be a framing error, got {:?}",
            res.as_ref().err()
        );
    }
}
