//! Self-contained PKCS#12 (PFX) parsing and decryption.
//!
//! Implements the subset of [RFC 7292] needed to extract private keys and
//! certificates from `.p12` / `.pfx` credential files:
//!
//! - PBES1 with SHA-1 (Apple Keychain and OpenSSL ≤ 1.1 exports):
//!   RC2-40, RC2-128, 2-key and 3-key Triple-DES
//! - PBES2 with PBKDF2 and AES-128/192/256-CBC (OpenSSL 3 default)
//! - MAC integrity verification with HMAC-SHA1 or HMAC-SHA256
//!
//! Only pure-Rust crypto primitives are used, so this module compiles for
//! `wasm32-unknown-unknown` unchanged. Parsing is deterministic; no OS
//! randomness is required.
//!
//! [RFC 7292]: https://www.rfc-editor.org/rfc/rfc7292

use aes::{Aes128, Aes192, Aes256};
use const_oid::ObjectIdentifier;
use des::{TdesEde2, TdesEde3};
use digest::core_api::BlockSizeUser;
use digest::{Digest, OutputSizeUser};
use hmac::{Mac, SimpleHmac};
use pbkdf2::pbkdf2_hmac;
use rc2::cipher::{Block, BlockDecrypt, KeyInit};
use rc2::Rc2;
use sha1::Sha1;
use sha2::Sha256;
use std::fmt;

/// Object identifiers used by PKCS#12 structures.
mod oid {
    use const_oid::ObjectIdentifier;

    pub const DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");
    pub const ENCRYPTED_DATA: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.6");
    pub const PBE_RC2_40: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.12.1.6");
    pub const PBE_RC2_128: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.12.1.5");
    pub const PBE_3DES: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.12.1.3");
    pub const PBE_2DES: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.12.1.4");
    pub const PBES2: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.5.13");
    pub const PBKDF2: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.5.12");
    pub const AES_128_CBC: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.2");
    pub const AES_192_CBC: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.22");
    pub const AES_256_CBC: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.42");
    pub const SHA1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.14.3.2.26");
    pub const SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
    pub const HMAC_SHA1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.2.7");
    pub const HMAC_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.2.9");
    pub const KEY_BAG: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.12.10.1.2");
    pub const CERT_BAG: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.12.10.1.3");
    pub const X509_CERT: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.22.1");
}

/// PKCS#12 extraction failure.
#[derive(Debug, Clone)]
pub(crate) enum P12Error {
    /// Malformed ASN.1/DER structure.
    Der(String),
    /// MAC verification failed: wrong password or corrupted file.
    Mac,
    /// A password-derived key could not decrypt a layer.
    Decrypt(String),
    /// Unsupported algorithm or structure.
    Unsupported(String),
}

impl fmt::Display for P12Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            P12Error::Der(msg) => write!(f, "malformed PKCS#12: {msg}"),
            P12Error::Mac => write!(f, "invalid PKCS#12 password (MAC mismatch)"),
            P12Error::Decrypt(msg) => write!(f, "PKCS#12 decryption failed: {msg}"),
            P12Error::Unsupported(msg) => write!(f, "unsupported PKCS#12: {msg}"),
        }
    }
}

type Result<T, E = P12Error> = std::result::Result<T, E>;

/// Contents extracted from a PKCS#12 file: DER-encoded private keys and
/// certificates.
pub(crate) struct P12Contents {
    pub keys: Vec<Vec<u8>>,
    pub certs: Vec<Vec<u8>>,
}

/// Extract private keys and certificates from a `.p12` / `.pfx` file.
///
/// The password is used only during parsing and is not retained.
pub(crate) fn extract_p12(data: &[u8], password: &str) -> Result<P12Contents> {
    // PFX ::= SEQUENCE { version INTEGER, authSafe ContentInfo,
    //                    macData MacData OPTIONAL }
    let mut outer = DerReader::new(data);
    let pfx = outer.read_sequence()?;
    let mut reader = DerReader::new(pfx);

    let _version = reader.read_integer_u32()?;
    let auth_safe = reader.read_sequence()?;
    let mac_data = if reader.remaining() > 0 {
        Some(MacData::parse(&mut reader)?)
    } else {
        None
    };

    let auth_contents = decrypt_content_info(auth_safe, password)?;

    if let Some(mac) = &mac_data {
        if !verify_mac(mac, &auth_contents, password)? {
            return Err(P12Error::Mac);
        }
    }

    // auth_contents is the AuthenticatedSafe: SEQUENCE OF ContentInfo.
    // Each ContentInfo's content holds a SafeContents (SEQUENCE OF SafeBag),
    // either plain or inside an encryptedData layer.
    let mut contents = DerReader::new(&auth_contents);
    let ci_list = contents.read_sequence()?;

    let mut keys = Vec::new();
    let mut certs = Vec::new();
    let mut ci_reader = DerReader::new(ci_list);
    while ci_reader.remaining() > 0 {
        let ci = ci_reader.read_sequence()?;
        let safe_contents = decrypt_content_info(ci, password)?;
        collect_bags(&safe_contents, password, &mut keys, &mut certs)?;
    }

    Ok(P12Contents { keys, certs })
}

/// Minimum and maximum PBKDF iteration counts accepted from untrusted input.
const MIN_ITERATIONS: u32 = 1;
const MAX_ITERATIONS: u32 = 10_000_000;

/// Minimal DER reader for the subset of ASN.1 used by PKCS#12.
///
/// Handles definite-length encodings only, which is what PKCS#12 producers
/// emit.
struct DerReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> DerReader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn read_byte(&mut self) -> Result<u8> {
        let b = *self
            .buf
            .get(self.pos)
            .ok_or_else(|| P12Error::Der("unexpected end of data".into()))?;
        self.pos += 1;
        Ok(b)
    }

    /// Peeks the next tag byte without advancing.
    fn peek_tag(&self) -> Option<u8> {
        self.buf.get(self.pos).copied()
    }

    /// Reads a definite-length TLV and returns its tag and value slice.
    fn read_tlv(&mut self) -> Result<(u8, &'a [u8])> {
        let tag = self.read_byte()?;
        let len = self.read_len()?;
        if self.remaining() < len {
            return Err(P12Error::Der("value length exceeds input".into()));
        }
        let value = &self.buf[self.pos..self.pos + len];
        self.pos += len;
        Ok((tag, value))
    }

    /// Reads a definite BER length (short or long form).
    fn read_len(&mut self) -> Result<usize> {
        let first = self.read_byte()?;
        if first & 0x80 == 0 {
            return Ok(first as usize);
        }
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 4 {
            return Err(P12Error::Der(
                "indefinite or oversized length encoding".into(),
            ));
        }
        let mut len = 0usize;
        for _ in 0..n {
            len = (len << 8) | (self.read_byte()? as usize);
        }
        Ok(len)
    }

    fn expect_tag(&mut self, expected: u8, what: &str) -> Result<&'a [u8]> {
        let (tag, value) = self.read_tlv()?;
        if tag != expected {
            return Err(P12Error::Der(format!(
                "expected {what} (tag 0x{expected:02x}), found 0x{tag:02x}"
            )));
        }
        Ok(value)
    }

    fn read_sequence(&mut self) -> Result<&'a [u8]> {
        self.expect_tag(0x30, "SEQUENCE")
    }

    fn read_octet_string(&mut self) -> Result<&'a [u8]> {
        self.expect_tag(0x04, "OCTET STRING")
    }

    /// Reads an OCTET STRING that may be encoded as `[0] IMPLICIT`
    /// (tag 0x80), as used for RFC 5652 `encryptedContent`.
    fn read_octet_string_or_implicit(&mut self) -> Result<&'a [u8]> {
        let (tag, value) = self.read_tlv()?;
        if tag == 0x04 || tag == 0x80 {
            Ok(value)
        } else {
            Err(P12Error::Der(format!(
                "expected OCTET STRING (tag 0x04 or 0x80), found 0x{tag:02x}"
            )))
        }
    }

    fn read_oid(&mut self) -> Result<ObjectIdentifier> {
        let value = self.expect_tag(0x06, "OBJECT IDENTIFIER")?;
        ObjectIdentifier::from_bytes(value).map_err(|e| P12Error::Der(format!("bad OID: {e}")))
    }

    fn read_integer_u32(&mut self) -> Result<u32> {
        let value = self.expect_tag(0x02, "INTEGER")?;
        if value.is_empty() || value.len() > 4 || value[0] & 0x80 != 0 {
            return Err(P12Error::Der("invalid INTEGER value".into()));
        }
        Ok(value.iter().fold(0u32, |acc, b| (acc << 8) | *b as u32))
    }

    /// Reads a `[tag_no] EXPLICIT` context-specific value, returning the
    /// inner TLV bytes (tag byte included).
    fn read_explicit(&mut self, tag_no: u8) -> Result<&'a [u8]> {
        let tag = self.read_byte()?;
        if tag != 0xa0 | tag_no {
            return Err(P12Error::Der(format!(
                "expected [{}] EXPLICIT (0x{:02x}), found 0x{tag:02x}",
                tag_no,
                0xa0 | tag_no
            )));
        }
        let len = self.read_len()?;
        if self.remaining() < len {
            return Err(P12Error::Der("value length exceeds input".into()));
        }
        let value = &self.buf[self.pos..self.pos + len];
        self.pos += len;
        Ok(value)
    }

    /// Reads any TLV, returning the value slice.
    fn read_any(&mut self) -> Result<&'a [u8]> {
        Ok(self.read_tlv()?.1)
    }
}

/// ContentInfo ::= SEQUENCE { contentType OBJECT IDENTIFIER,
///                             content [0] EXPLICIT ANY }
struct ContentInfo<'a> {
    oid: ObjectIdentifier,
    /// Inner TLV bytes of the `[0] EXPLICIT` content.
    inner: &'a [u8],
}

impl<'a> ContentInfo<'a> {
    /// Parses a ContentInfo from its decoded SEQUENCE value.
    fn parse(value: &'a [u8]) -> Result<Self> {
        let mut inner_reader = DerReader::new(value);
        let oid = inner_reader.read_oid()?;
        let inner = inner_reader.read_explicit(0)?;
        Ok(Self { oid, inner })
    }
}

/// Decrypts (or unwraps) a ContentInfo into its plaintext contents.
///
/// `data` ContentInfos carry an OCTET STRING payload; `encryptedData`
/// content infos carry an EncryptedData structure that is decrypted with
/// the password-derived key.
fn decrypt_content_info(ci_der: &[u8], password: &str) -> Result<Vec<u8>> {
    let ci = ContentInfo::parse(ci_der)?;
    if ci.oid == oid::DATA {
        let octets = DerReader::new(ci.inner).read_octet_string()?;
        return Ok(octets.to_vec());
    }
    if ci.oid == oid::ENCRYPTED_DATA {
        return decrypt_encrypted_data(ci.inner, password);
    }
    Err(P12Error::Unsupported(format!(
        "content type {ci_oid}",
        ci_oid = ci.oid
    )))
}

/// EncryptedData ::= SEQUENCE { version INTEGER,
///                               encryptedContentInfo SEQUENCE {
///                                 contentType OBJECT IDENTIFIER,
///                                 contentEncryptionAlgorithm AlgorithmIdentifier,
///                                 encryptedContent OCTET STRING } }
fn decrypt_encrypted_data(inner: &[u8], password: &str) -> Result<Vec<u8>> {
    let mut reader = DerReader::new(inner);
    let encrypted_data = reader.read_sequence()?;
    let mut ed_reader = DerReader::new(encrypted_data);
    let _version = ed_reader.read_integer_u32()?;
    let eci = ed_reader.read_sequence()?;
    let mut eci_reader = DerReader::new(eci);
    let _content_type = eci_reader.read_oid()?;
    let algorithm = AlgorithmId::parse(&mut eci_reader)?;
    let encrypted = eci_reader.read_octet_string_or_implicit()?;
    decrypt_with_algorithm(&algorithm, encrypted, password)
}

/// AlgorithmIdentifier ::= SEQUENCE { algorithm OBJECT IDENTIFIER,
///                                     parameters ANY OPTIONAL }
struct AlgorithmId<'a> {
    oid: ObjectIdentifier,
    params: Option<&'a [u8]>,
}

impl<'a> AlgorithmId<'a> {
    fn parse(reader: &mut DerReader<'a>) -> Result<Self> {
        let seq = reader.read_sequence()?;
        let mut inner = DerReader::new(seq);
        let oid = inner.read_oid()?;
        let params = if inner.remaining() > 0 {
            Some(inner.read_any()?)
        } else {
            None
        };
        Ok(Self { oid, params })
    }
}

/// PBEParameter ::= SEQUENCE { salt OCTET STRING, iterations INTEGER }
struct PbeParameter<'a> {
    salt: &'a [u8],
    iterations: u32,
}

impl<'a> PbeParameter<'a> {
    /// Parses PBEParameter from its decoded SEQUENCE value.
    fn parse(value: &'a [u8]) -> Result<Self> {
        let mut inner = DerReader::new(value);
        let salt = inner.read_octet_string()?;
        let iterations = inner.read_integer_u32()?;
        validate_iterations(iterations)?;
        Ok(Self { salt, iterations })
    }
}

fn validate_iterations(iterations: u32) -> Result<()> {
    if !(MIN_ITERATIONS..=MAX_ITERATIONS).contains(&iterations) {
        return Err(P12Error::Der(format!(
            "out-of-range PBKDF iteration count {iterations}"
        )));
    }
    Ok(())
}

/// Decrypts an encrypted payload with a PBES1 or PBES2 algorithm
/// identifier.
fn decrypt_with_algorithm(
    algorithm: &AlgorithmId<'_>,
    data: &[u8],
    password: &str,
) -> Result<Vec<u8>> {
    let params = algorithm
        .params
        .ok_or_else(|| P12Error::Der("algorithm parameters missing".into()))?;

    if algorithm.oid == oid::PBES2 {
        // PBES2 params carry the PBKDF2 and scheme algorithm identifiers,
        // and use the raw password bytes (no BMPString conversion).
        return pbes2_decrypt(params, data, password);
    }

    let pbe = PbeParameter::parse(params)?;
    let bmp = bmp_string(password);

    if algorithm.oid == oid::PBE_RC2_40 {
        return pbes1_decrypt::<Rc2>(
            &bmp,
            &pbe,
            data,
            5,
            |key| Some(Rc2::new_with_eff_key_len(key, 40)),
            P12Error::Decrypt("RC2-40".into()),
        );
    }
    if algorithm.oid == oid::PBE_RC2_128 {
        return pbes1_decrypt::<Rc2>(
            &bmp,
            &pbe,
            data,
            16,
            |key| Some(Rc2::new_with_eff_key_len(key, 128)),
            P12Error::Decrypt("RC2-128".into()),
        );
    }
    if algorithm.oid == oid::PBE_3DES {
        return pbes1_decrypt::<TdesEde3>(
            &bmp,
            &pbe,
            data,
            24,
            |key| TdesEde3::new_from_slice(key).ok(),
            P12Error::Decrypt("3-key Triple-DES".into()),
        );
    }
    if algorithm.oid == oid::PBE_2DES {
        return pbes1_decrypt::<TdesEde2>(
            &bmp,
            &pbe,
            data,
            16,
            |key| TdesEde2::new_from_slice(key).ok(),
            P12Error::Decrypt("2-key Triple-DES".into()),
        );
    }

    Err(P12Error::Unsupported(format!(
        "encryption algorithm {oid}",
        oid = algorithm.oid
    )))
}

/// PBES1 (PKCS#12 KDF over SHA-1 + CBC block cipher).
///
/// Key and IV are derived with KDF ids 1 and 2; the block cipher is
/// constructed from the derived key by `make_cipher`.
fn pbes1_decrypt<C>(
    password: &[u8],
    pbe: &PbeParameter<'_>,
    data: &[u8],
    key_len: usize,
    make_cipher: impl FnOnce(&[u8]) -> Option<C>,
    label: P12Error,
) -> Result<Vec<u8>>
where
    C: BlockDecrypt,
{
    let key = pkcs12_kdf::<Sha1>(password, pbe.salt, pbe.iterations, 1, key_len)?;
    let iv = pkcs12_kdf::<Sha1>(password, pbe.salt, pbe.iterations, 2, 8)?;
    let cipher = make_cipher(&key).ok_or_else(|| label.clone())?;
    cbc_decrypt(&cipher, &iv, data).ok_or(label)
}

/// PBES2 ::= SEQUENCE { keyDerivationFunc PBKDF2-params,
///                       encryptionScheme AlgorithmIdentifier }
fn pbes2_decrypt(params: &[u8], data: &[u8], password: &str) -> Result<Vec<u8>> {
    // `params` is the decoded SEQUENCE value: two AlgorithmIdentifiers.
    let mut inner = DerReader::new(params);

    let kdf = AlgorithmId::parse(&mut inner)?;
    let scheme = AlgorithmId::parse(&mut inner)?;

    if kdf.oid != oid::PBKDF2 {
        return Err(P12Error::Unsupported(format!(
            "key derivation function {oid}",
            oid = kdf.oid
        )));
    }

    let pbkdf2_params = kdf
        .params
        .ok_or_else(|| P12Error::Der("PBKDF2 parameters missing".into()))?;
    let salt = Pbkdf2Parameter::parse(pbkdf2_params)?;

    let (key_len, iv) = match scheme.oid {
        oid::AES_128_CBC => (16, aes_cbc_iv(&scheme)?),
        oid::AES_192_CBC => (24, aes_cbc_iv(&scheme)?),
        oid::AES_256_CBC => (32, aes_cbc_iv(&scheme)?),
        _ => {
            return Err(P12Error::Unsupported(format!(
                "PBES2 encryption scheme {oid}",
                oid = scheme.oid
            )))
        }
    };

    let mut key = vec![0u8; key_len];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt.salt, salt.iterations, &mut key);

    let plaintext = match key_len {
        16 => aes_decrypt::<Aes128>(&key, iv, data)?,
        24 => aes_decrypt::<Aes192>(&key, iv, data)?,
        32 => aes_decrypt::<Aes256>(&key, iv, data)?,
        _ => unreachable!(),
    };
    Ok(plaintext)
}

/// PBKDF2-params ::= SEQUENCE { salt OCTET STRING,
///                               iterationCount INTEGER,
///                               keyLength INTEGER OPTIONAL,
///                               prf AlgorithmIdentifier DEFAULT
///                                 hmacSHA1 }
struct Pbkdf2Parameter<'a> {
    salt: &'a [u8],
    iterations: u32,
}

impl<'a> Pbkdf2Parameter<'a> {
    /// Parses PBKDF2-params from its decoded SEQUENCE value.
    fn parse(value: &'a [u8]) -> Result<Self> {
        let mut inner = DerReader::new(value);
        let salt = inner.read_octet_string()?;
        let iterations = inner.read_integer_u32()?;
        validate_iterations(iterations)?;

        // keyLength (if present) precedes the optional PRF. It is only
        // read when actually an INTEGER, so a PRF-only layout is handled.
        if inner.peek_tag() == Some(0x02) {
            let _key_length = inner.read_integer_u32()?;
        }
        if inner.remaining() > 0 {
            let _prf = AlgorithmId::parse(&mut inner)?;
        }

        Ok(Self { salt, iterations })
    }
}

/// Extracts the 16-byte IV from an AES-CBC algorithm identifier.
fn aes_cbc_iv<'a>(scheme: &AlgorithmId<'a>) -> Result<&'a [u8]> {
    // The AES-CBC parameters are the decoded OCTET STRING value: the raw IV.
    let iv = scheme
        .params
        .ok_or_else(|| P12Error::Der("AES-CBC IV missing".into()))?;
    if iv.len() != 16 {
        return Err(P12Error::Der("AES-CBC IV must be 16 bytes".into()));
    }
    Ok(iv)
}

fn aes_decrypt<C>(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>>
where
    C: BlockDecrypt + KeyInit,
{
    let cipher = C::new_from_slice(key)
        .map_err(|_| P12Error::Decrypt(format!("invalid AES key length {}", key.len())))?;
    cbc_decrypt(&cipher, iv, data).ok_or_else(|| P12Error::Decrypt("AES-CBC".into()))
}

/// CBC decryption with PKCS#7 padding removal, generic over block cipher.
fn cbc_decrypt<C>(cipher: &C, iv: &[u8], data: &[u8]) -> Option<Vec<u8>>
where
    C: BlockDecrypt,
{
    let block_size = std::mem::size_of::<Block<C>>();
    if block_size == 0 || data.len() < block_size || !data.len().is_multiple_of(block_size) {
        return None;
    }
    if iv.len() < block_size {
        return None;
    }

    let mut previous = iv[..block_size].to_vec();
    let mut out = Vec::with_capacity(data.len());

    for chunk in data.chunks_exact(block_size) {
        let mut block = Block::<C>::default();
        block.copy_from_slice(chunk);
        cipher.decrypt_block(&mut block);
        for (byte, prev) in block.iter_mut().zip(previous.iter()) {
            *byte ^= prev;
        }
        previous.copy_from_slice(chunk);
        out.extend_from_slice(&block);
    }

    if !unpad_pkcs7(&mut out, block_size) {
        return None;
    }
    Some(out)
}

/// Removes PKCS#7 padding, returning `false` if the padding is invalid.
fn unpad_pkcs7(data: &mut Vec<u8>, block_size: usize) -> bool {
    let Some(&last) = data.last() else {
        return false;
    };
    let pad = last as usize;
    if pad == 0 || pad > block_size || data.len() < pad {
        return false;
    }
    if data[data.len() - pad..].iter().any(|&b| b as usize != pad) {
        return false;
    }
    data.truncate(data.len() - pad);
    true
}

/// MacData ::= SEQUENCE { mac DigestInfo, macSalt OCTET STRING,
///                        iterations INTEGER }
struct MacData<'a> {
    digest_algorithm: ObjectIdentifier,
    digest: &'a [u8],
    salt: &'a [u8],
    iterations: u32,
}

impl<'a> MacData<'a> {
    fn parse(reader: &mut DerReader<'a>) -> Result<Self> {
        let seq = reader.read_sequence()?;
        let mut inner = DerReader::new(seq);

        // DigestInfo ::= SEQUENCE { digestAlgorithm AlgorithmIdentifier,
        //                            digest OCTET STRING }
        let digest_info = inner.read_sequence()?;
        let mut di = DerReader::new(digest_info);
        let algorithm = AlgorithmId::parse(&mut di)?;
        let digest = di.read_octet_string()?;

        let salt = inner.read_octet_string()?;
        let iterations = inner.read_integer_u32()?;
        validate_iterations(iterations)?;

        Ok(Self {
            digest_algorithm: algorithm.oid,
            digest,
            salt,
            iterations,
        })
    }
}

/// Verifies the PKCS#12 MAC over the decrypted authSafe contents.
///
/// The MAC key is derived with the PKCS#12 KDF (id 3) using the MAC's
/// digest algorithm; the MAC itself is HMAC with that digest.
fn verify_mac(mac: &MacData<'_>, contents: &[u8], password: &str) -> Result<bool> {
    let bmp = bmp_string(password);
    let valid = match mac.digest_algorithm {
        oid::SHA1 | oid::HMAC_SHA1 => {
            let key = pkcs12_kdf::<Sha1>(&bmp, mac.salt, mac.iterations, 3, 20)?;
            hmac_verify::<Sha1>(&key, contents, mac.digest)
        }
        oid::SHA256 | oid::HMAC_SHA256 => {
            let key = pkcs12_kdf::<Sha256>(&bmp, mac.salt, mac.iterations, 3, 32)?;
            hmac_verify::<Sha256>(&key, contents, mac.digest)
        }
        _ => {
            return Err(P12Error::Unsupported(format!(
                "MAC digest algorithm {oid}",
                oid = mac.digest_algorithm
            )))
        }
    };
    Ok(valid)
}

fn hmac_verify<D>(key: &[u8], data: &[u8], expected: &[u8]) -> bool
where
    D: Digest + BlockSizeUser<BlockSize = digest::consts::U64>,
{
    <SimpleHmac<D> as digest::KeyInit>::new_from_slice(key)
        .map(|mut mac| {
            mac.update(data);
            mac.verify_slice(expected).is_ok()
        })
        .unwrap_or(false)
}

/// Walks SafeContents, decrypting key bags and collecting certificates.
///
/// SafeContents ::= SEQUENCE OF SafeBag
fn collect_bags(
    bytes: &[u8],
    password: &str,
    keys: &mut Vec<Vec<u8>>,
    certs: &mut Vec<Vec<u8>>,
) -> Result<()> {
    let mut reader = DerReader::new(bytes);
    let safe_contents = reader.read_sequence()?;
    let mut bags = DerReader::new(safe_contents);
    while bags.remaining() > 0 {
        let bag_der = bags.read_sequence()?;

        // SafeBag ::= SEQUENCE { bagId OBJECT IDENTIFIER,
        //                         bagValue [0] EXPLICIT ANY,
        //                         bagAttributes SET OF Attribute OPTIONAL }
        let mut bag = DerReader::new(bag_der);
        let bag_id = bag.read_oid()?;
        let value = bag.read_explicit(0)?;
        let _attributes = if bag.remaining() > 0 {
            Some(bag.read_any()?)
        } else {
            None
        };

        if bag_id == oid::KEY_BAG {
            keys.push(decrypt_key_bag(value, password)?);
        } else if bag_id == oid::CERT_BAG {
            certs.push(parse_cert_bag(value)?);
        }
        // Other bag types (CRL, secret, safeContents) carry nothing the
        // signer needs and are skipped.
    }
    Ok(())
}

/// pkcs8ShroudedKeyBag ::= EncryptedPrivateKeyInfo
fn decrypt_key_bag(value: &[u8], password: &str) -> Result<Vec<u8>> {
    let mut reader = DerReader::new(value);
    let epki = reader.read_sequence()?;
    let mut inner = DerReader::new(epki);
    let algorithm = AlgorithmId::parse(&mut inner)?;
    let encrypted = inner.read_octet_string()?;
    decrypt_with_algorithm(&algorithm, encrypted, password)
}

/// certBag ::= SEQUENCE { certId OBJECT IDENTIFIER,
///                        certValue [0] EXPLICIT OCTET STRING }
fn parse_cert_bag(value: &[u8]) -> Result<Vec<u8>> {
    let mut reader = DerReader::new(value);
    let cert_bag = reader.read_sequence()?;
    let mut inner = DerReader::new(cert_bag);
    let cert_id = inner.read_oid()?;
    if cert_id != oid::X509_CERT {
        return Err(P12Error::Unsupported(format!(
            "certificate type {oid}",
            oid = cert_id
        )));
    }
    let octets = inner.read_explicit(0)?;
    Ok(DerReader::new(octets).read_octet_string()?.to_vec())
}

/// Converts a password to the PKCS#12 BMPString form: UTF-16BE with a
/// trailing NUL code unit.
fn bmp_string(password: &str) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(password.len() * 2 + 2);
    for unit in password.encode_utf16() {
        bytes.push((unit >> 8) as u8);
        bytes.push((unit & 0xff) as u8);
    }
    bytes.extend_from_slice(&[0x00, 0x00]);
    bytes
}

/// Pads `data` to a multiple of `v` bytes by repetition (RFC 7292 §B.2).
fn pad_to_v(data: &[u8], v: usize) -> Vec<u8> {
    let len = data.len().div_ceil(v) * v;
    data.iter().copied().cycle().take(len).collect()
}

/// PKCS#12 key derivation function (RFC 7292 §B.2).
///
/// Derives `size` key bytes from `password`/`salt` for a given KDF `id`
/// (1 = encryption key, 2 = IV, 3 = MAC key). Only digests with a 64-byte
/// block size (SHA-1, SHA-256) are supported.
fn pkcs12_kdf<D>(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    id: u8,
    size: usize,
) -> Result<Vec<u8>>
where
    D: Digest + BlockSizeUser<BlockSize = digest::consts::U64> + Clone + Default,
{
    const V: usize = 64;
    let u = <D as OutputSizeUser>::output_size();

    let d = [id; V];
    let mut i = pad_to_v(salt, V);
    i.extend_from_slice(&pad_to_v(password, V));

    let mut out = Vec::with_capacity(size.div_ceil(u) * u);
    for _ in 0..size.div_ceil(u) {
        // A = HASH^iterations(D || I)
        let mut h = D::default();
        h.update(d);
        h.update(&i);
        let mut a = h.finalize();
        for _ in 1..iterations {
            let mut h = D::default();
            h.update(&a);
            a = h.finalize();
        }
        out.extend_from_slice(&a);

        // I = (I + B + 1) mod 2^(V*8): B is repeated over the whole I, a
        // carry starts at each V-byte boundary, and the +1 is applied per
        // boundary (RFC 7292 §B.2; verified against OpenSSL-produced files).
        let b = pad_to_v(&a, V);
        let mut carry = 1u16;
        for k in (0..i.len()).rev() {
            if k % V == V - 1 {
                carry = 1;
            }
            let sum = i[k] as u16 + b[k % V] as u16 + carry;
            i[k] = (sum & 0xff) as u8;
            carry = sum >> 8;
        }
    }

    out.truncate(size);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::Decode;
    use pkcs8::DecodePrivateKey;
    use rsa::traits::PublicKeyParts;
    use rsa::RsaPrivateKey;
    use x509_cert::Certificate;

    const LEGACY: &[u8] = include_bytes!("fixtures/legacy_rc2_3des.p12");
    const MODERN: &[u8] = include_bytes!("fixtures/modern_pbes2_aes256.p12");
    const LEGACY_3DES: &[u8] = include_bytes!("fixtures/legacy_3des_only.p12");
    const LEGACY_RC2_128: &[u8] = include_bytes!("fixtures/legacy_rc2_128.p12");
    const LEGACY_2DES: &[u8] = include_bytes!("fixtures/legacy_2des.p12");
    const MODERN_AES128: &[u8] = include_bytes!("fixtures/modern_aes128.p12");
    const MODERN_AES192: &[u8] = include_bytes!("fixtures/modern_aes192.p12");
    const MODERN_SHA1_MAC: &[u8] = include_bytes!("fixtures/modern_sha1_mac.p12");
    const EMPTY_PASSWORD: &[u8] = include_bytes!("fixtures/empty_password.p12");

    /// Every PKCS#12 encryption scheme the extractor supports, as produced
    /// by OpenSSL 3 (throwaway keys, CN=zsign-test-fixture).
    const VARIANTS: &[(&str, &[u8], &str)] = &[
        ("legacy rc2-40 + 3des", LEGACY, "testpassword"),
        ("legacy 3des only", LEGACY_3DES, "testpassword"),
        ("legacy rc2-128", LEGACY_RC2_128, "testpassword"),
        ("legacy 2des", LEGACY_2DES, "testpassword"),
        ("pbes2 aes-256", MODERN, "testpassword"),
        ("pbes2 aes-128", MODERN_AES128, "testpassword"),
        ("pbes2 aes-192", MODERN_AES192, "testpassword"),
        ("pbes2 aes-256 + sha1 mac", MODERN_SHA1_MAC, "testpassword"),
        ("legacy empty password", EMPTY_PASSWORD, ""),
    ];

    /// Asserts that the bag's private key matches the bag's certificate.
    fn assert_key_matches_cert(key_der: &[u8], cert_der: &[u8]) {
        use der::Encode;
        use pkcs8::DecodePublicKey;
        use rsa::RsaPublicKey;

        let key = RsaPrivateKey::from_pkcs8_der(key_der).expect("key must parse");
        let cert = Certificate::from_der(cert_der).expect("cert must parse");
        let key_pub = RsaPublicKey::from(&key);
        let spki_der = cert
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .expect("spki must encode");
        let cert_pub = RsaPublicKey::from_public_key_der(&spki_der).expect("spki must be an rsa key");
        assert_eq!(key_pub.n(), cert_pub.n(), "key and certificate modulus differ");
        assert_eq!(key_pub.e(), cert_pub.e(), "key and certificate exponent differ");
    }

    #[test]
    fn extracts_key_and_cert_from_all_supported_variants() {
        for (name, fixture, password) in VARIANTS {
            let contents = extract_p12(fixture, password)
                .unwrap_or_else(|e| panic!("{name} should parse: {e}"));
            assert_eq!(contents.keys.len(), 1, "{name}: one key expected");
            assert_eq!(contents.certs.len(), 1, "{name}: one cert expected");
            assert_key_matches_cert(&contents.keys[0], &contents.certs[0]);
        }
    }

    #[test]
    fn wrong_password_is_rejected_for_every_variant() {
        for (name, fixture, _) in VARIANTS {
            let wrong = if name.contains("empty password") { "x" } else { "wrong" };
            assert!(
                matches!(extract_p12(fixture, wrong), Err(P12Error::Mac)),
                "{name}: wrong password must fail the MAC check"
            );
        }
    }

    #[test]
    fn extracts_key_and_cert_from_legacy_p12() {
        let contents = extract_p12(LEGACY, "testpassword").expect("legacy p12 should parse");
        assert_eq!(contents.keys.len(), 1);
        assert_eq!(contents.certs.len(), 1);

        let rsa_key = RsaPrivateKey::from_pkcs8_der(&contents.keys[0])
            .expect("key must be a PKCS#8 RSA private key");
        assert_eq!(rsa_key.n().bits(), 2048);

        let cert = Certificate::from_der(&contents.certs[0]).expect("cert must parse");
        assert_eq!(
            cert.tbs_certificate.subject.to_string(),
            "CN=zsign-test-fixture"
        );
    }

    #[test]
    fn extracts_key_and_cert_from_modern_p12() {
        let contents = extract_p12(MODERN, "testpassword").expect("modern p12 should parse");
        assert_eq!(contents.keys.len(), 1);
        assert_eq!(contents.certs.len(), 1);

        let rsa_key = RsaPrivateKey::from_pkcs8_der(&contents.keys[0])
            .expect("key must be a PKCS#8 RSA private key");
        assert_eq!(rsa_key.n().bits(), 2048);

        let cert = Certificate::from_der(&contents.certs[0]).expect("cert must parse");
        assert_eq!(
            cert.tbs_certificate.subject.to_string(),
            "CN=zsign-test-fixture"
        );
    }

    #[test]
    fn wrong_password_is_rejected_for_both_schemes() {
        assert!(matches!(extract_p12(LEGACY, "wrong"), Err(P12Error::Mac)));
        assert!(matches!(extract_p12(MODERN, "wrong"), Err(P12Error::Mac)));
    }

    #[test]
    fn truncated_input_is_rejected() {
        assert!(extract_p12(&LEGACY[..40], "testpassword").is_err());
        assert!(extract_p12(b"", "testpassword").is_err());
    }

    #[test]
    fn kdf_matches_independently_computed_vectors() {
        // RFC 7292 §B.2 known-answer vectors. The third vector derives a
        // 24-byte key and exercises the two-block I-update path.
        let key = pkcs12_kdf::<Sha1>(b"password", b"salt", 1, 1, 20).unwrap();
        assert_eq!(
            key,
            [
                0xd7, 0xa5, 0xd2, 0xcb, 0xfe, 0x03, 0x39, 0xc3, 0xef, 0xe6, 0xf5, 0x95, 0xe4, 0x0e,
                0x7b, 0xad, 0xbe, 0x65, 0xfb, 0x33
            ]
        );

        let salt = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let pw = bmp_string("testpassword");
        let mac_key = pkcs12_kdf::<Sha1>(&pw, &salt, 2048, 3, 20).unwrap();
        assert_eq!(
            mac_key,
            [
                0xe2, 0xe4, 0xfb, 0x32, 0x2c, 0x47, 0x24, 0x83, 0xf5, 0x3c, 0x0e, 0x19, 0x49, 0x67,
                0x20, 0xed, 0x4b, 0xf9, 0xe2, 0x3d
            ]
        );

        let enc_key = pkcs12_kdf::<Sha1>(&pw, &salt, 2048, 1, 24).unwrap();
        assert_eq!(
            enc_key,
            [
                0x52, 0x4c, 0xed, 0x8d, 0xa1, 0x17, 0x67, 0xb3, 0x6e, 0xff, 0x05, 0x09, 0x7b, 0x2d,
                0x7c, 0x0f, 0x65, 0x83, 0xa2, 0xb9, 0xc8, 0x25, 0x0b, 0x0e
            ]
        );
    }

    #[test]
    fn bmp_string_encodes_utf16be_with_nul() {
        assert_eq!(
            bmp_string("WSF"),
            vec![0x00, 0x57, 0x00, 0x53, 0x00, 0x46, 0x00, 0x00]
        );
        assert_eq!(bmp_string(""), vec![0x00, 0x00]);
        // Non-ASCII passwords round-trip through encode_utf16.
        assert_eq!(
            bmp_string("päss"),
            vec![0x00, 0x70, 0x00, 0xe4, 0x00, 0x73, 0x00, 0x73, 0x00, 0x00]
        );
    }
}
