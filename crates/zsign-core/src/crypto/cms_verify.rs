//! Real CMS (PKCS#7) signature verification for Apple code signatures.
//!
//! The [`cms`](https://crates.io/crates/cms) crate is signer-only (0.2.x has no
//! verification API), so this module hand-parses the `SignedData` structure on
//! the same pure-Rust `der`/`rsa`/`p256` stack used for signing. It validates,
//! in the same order Apple's verifier does:
//!
//! 1. **Message digest**: the `messageDigest` signed attribute must equal the
//!    digest of the signed content (the CodeDirectory bytes).
//! 2. **Signed content type**: the signed `contentType` attribute must occur
//!    exactly once and contain `id-data`.
//! 3. **Apple CDHash attributes**: the `1.2.840.113635.100.9.1` plist and
//!    `1.2.840.113635.100.9.2` sequence must carry this CodeDirectory's actual
//!    cdhash (truncated-20 for v1, full 32 bytes for v2).
//! 4. **Signature**: the signerInfo signature must verify over the DER encoding
//!    of the `signedAttrs` field as-is (the CMS rule: the `[0]`-tagged SET OF
//!    Attribute is the signed message, not a re-encoded copy).
//! 5. **Signer binding**: the signerInfo issuer+serial must identify a
//!    certificate in the embedded set, and the chain must be structurally
//!    valid (each certificate signed by its issuer and within its validity
//!    window).
//! 6. **X.509 purpose enforcement**: the leaf must carry codeSigning EKU and
//!    end-entity constraints; each climbed issuer must satisfy CA constraints.
//! 7. **Trust anchoring**: the chain must terminate at a certificate in the
//!    explicit trust-anchor set ([`TrustAnchors::apple_root`] by default).
//! 8. **SKI SignerInfo resolution**: a signer identified by its
//!    `subjectKeyIdentifier` must match a certificate in the embedded set.
//!
//! This module proves integrity, Apple-attribute binding, chain structure, and
//! anchoring to an explicit trust-anchor set — [`TrustAnchors::apple_root`]
//! by default; revocation remains a device concern.
//!
//! # Examples
//!
//! ```ignore
//! use zsign_core::crypto::cms_verify::verify_code_signature;
//!
//! let report = verify_code_signature(&cms_blob, &cd_bytes, None, &cd_sha256)?;
//! assert!(report.valid);
//! ```

use crate::{Error, Result};
use const_oid::ObjectIdentifier;
use der::asn1::{AnyRef, OctetStringRef};
use der::Tagged;
use der::{Decode, DecodePem, Encode, Reader, SliceReader, Tag, TagNumber};
use pkcs8::DecodePublicKey;
use sha2::{Digest, Sha256};

/// signedData content type: `1.2.840.113549.1.7.2`
const OID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
/// id-data content type: `1.2.840.113549.1.7.1`
const OID_ID_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");
/// contentType attribute: `1.2.840.113549.1.9.3`
const OID_CONTENT_TYPE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");
/// messageDigest attribute: `1.2.840.113549.1.9.4`
const OID_MESSAGE_DIGEST: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");
/// signingTime attribute: `1.2.840.113549.1.9.5`
#[allow(dead_code)]
const OID_SIGNING_TIME: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.5");
/// Apple CDHash v1 attribute: `1.2.840.113635.100.9.1`
const OID_APPLE_CDHASH_V1: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113635.100.9.1");
/// Apple CDHash v2 attribute: `1.2.840.113635.100.9.2`
const OID_APPLE_CDHASH_V2: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113635.100.9.2");
/// SHA-256: `2.16.840.1.101.3.4.2.1`
const OID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
/// rsaEncryption: `1.2.840.113549.1.1.1`
const OID_RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
/// sha1WithRSAEncryption: `1.2.840.113549.1.1.5`
const OID_SHA1_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.5");
/// sha256WithRSAEncryption: `1.2.840.113549.1.1.11`
const OID_SHA256_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
/// sha384WithRSAEncryption: `1.2.840.113549.1.1.12`
const OID_SHA384_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12");
/// sha512WithRSAEncryption: `1.2.840.113549.1.1.13`
const OID_SHA512_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13");
/// ecdsa-with-SHA256: `1.2.840.10045.4.3.2`
const OID_ECDSA_WITH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
/// id-ecPublicKey: `1.2.840.10045.2.1`
const OID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
/// SubjectKeyIdentifier extension: `2.5.29.14`
const OID_SUBJECT_KEY_IDENTIFIER: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.14");
/// keyUsage extension: `2.5.29.15`
const OID_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.15");
/// basicConstraints extension: `2.5.29.19`
const OID_BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");
/// extended key usage extension: `2.5.29.37`
const OID_EXT_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37");
/// codeSigning EKU: `1.3.6.1.5.5.7.3.3`
const OID_CODE_SIGNING: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.3");

/// Normalizes BER indefinite-length encodings to definite-length DER.
///
/// Apple's own toolchains occasionally emit CMS structures with BER
/// indefinite lengths (observed in `/bin/ls` on Intel macOS runners), which
/// strict DER parsers reject. This rewrites every indefinite-length constructed
/// TLV into its definite-length form, leaving already-definite bytes untouched.
/// `EOC` (0x00 0x00) closes the innermost indefinite frame.
pub fn normalize_ber_lengths(input: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0usize;
    while i < input.len() {
        let (bytes, consumed) = write_norm(input, i)?;
        out.extend_from_slice(&bytes);
        i += consumed;
    }
    Ok(out)
}

/// Serializes one TLV (and its children) starting at `i`, returning the
/// normalized bytes and the number of input bytes consumed.
fn write_norm(input: &[u8], mut i: usize) -> Result<(std::vec::Vec<u8>, usize)> {
    let start = i;
    let tag = *input
        .get(i)
        .ok_or_else(|| Error::Verification("truncated TLV tag".into()))?;
    i += 1;
    let l0 = *input
        .get(i)
        .ok_or_else(|| Error::Verification("truncated TLV length".into()))?;
    i += 1;

    let constructed = tag & 0x20 != 0;

    // Indefinite length (BER): content runs until the EOC at this frame level.
    if l0 == 0x80 {
        if !constructed {
            return Err(Error::Verification(
                "indefinite length on a primitive TLV".into(),
            ));
        }
        let mut content = Vec::new();
        loop {
            let (b, n) = {
                let rest = &input[i..];
                if rest.len() >= 2 && rest[0] == 0 && rest[1] == 0 {
                    break; // EOC
                }
                write_norm(input, i)?
            };
            content.extend_from_slice(&b);
            i += n;
        }
        i += 2; // consume EOC
        let mut out = Vec::with_capacity(2 + len_len(content.len()) + content.len());
        out.push(tag);
        write_len(&mut out, content.len());
        out.extend_from_slice(&content);
        return Ok((out, i - start));
    }

    // Definite length.
    let len = if l0 < 0x80 {
        l0 as usize
    } else {
        let count = (l0 & 0x7f) as usize;
        if count == 0 || count > 8 {
            return Err(Error::Verification("malformed long-form length".into()));
        }
        let bytes = input
            .get(i..i + count)
            .ok_or_else(|| Error::Verification("truncated long-form length".into()))?;
        i += count;
        let mut v = 0usize;
        for b in bytes {
            v = v
                .checked_mul(256)
                .and_then(|v| v.checked_add(*b as usize))
                .ok_or_else(|| Error::Verification("length overflow".into()))?;
        }
        v
    };
    let content_end = i
        .checked_add(len)
        .ok_or_else(|| Error::Verification("content overrun".into()))?;
    let content = input
        .get(i..content_end)
        .ok_or_else(|| Error::Verification("truncated TLV content".into()))?;

    let mut out = Vec::with_capacity(2 + (content_end - start));
    out.push(tag);
    write_len(&mut out, len);
    if constructed {
        let mut j = 0usize;
        while j < content.len() {
            let (child, n) = write_norm(content, j)?;
            out.extend_from_slice(&child);
            j += n;
        }
        if j != content.len() {
            return Err(Error::Verification(
                "child TLVs do not span the constructed content".into(),
            ));
        }
    } else {
        out.extend_from_slice(content);
    }
    Ok((out, content_end - start))
}

/// Number of bytes a definite length of `v` needs in its minimal encoding.
fn len_len(v: usize) -> usize {
    if v < 0x80 {
        1
    } else {
        1 + (usize::BITS as usize - v.leading_zeros() as usize).div_ceil(8)
    }
}

/// Appends the definite-length header bytes for `v` (short or minimal long form).
fn write_len(out: &mut Vec<u8>, v: usize) {
    if v < 0x80 {
        out.push(v as u8);
    } else {
        let n = len_len(v) - 1;
        out.push(0x80 | n as u8);
        for k in (0..n).rev() {
            out.push((v >> (8 * k)) as u8);
        }
    }
}

/// Result of a CMS verification attempt.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CmsVerifyReport {
    /// True when the signature cryptographically verifies and the Apple
    /// attributes bind this exact CodeDirectory.
    pub valid: bool,
    /// Whether no CMS signature was present (ad-hoc signing).
    pub no_signature: bool,
    /// The signer certificate's subject common name, when found.
    pub signer_subject: Option<String>,
    /// The signer certificate's serial number (hex), when found.
    pub signer_serial: Option<String>,
    /// Whether the `messageDigest` attribute matched the content digest.
    pub message_digest_ok: bool,
    /// Whether the Apple CDHash v1 attribute matched the CodeDirectory.
    pub cdhash_v1_ok: bool,
    /// Whether the Apple CDHash v2 attribute matched the CodeDirectory.
    pub cdhash_v2_ok: bool,
    /// Whether the signature verified over the signed attributes.
    pub signature_ok: bool,
    /// Whether the signer certificate's chain is structurally valid
    /// (issuer-signed, in-validity, leaf EKU when present).
    pub chain_ok: bool,
    /// Whether the chain terminates at a verified trust anchor.
    pub anchored: bool,
    /// Why the chain check failed, when it did.
    pub chain_reason: Option<String>,
    /// Certificate subjects from leaf to anchor.
    pub chain: Vec<String>,
    /// Non-fatal observations (e.g. unsupported attributes).
    pub warnings: Vec<String>,
    /// Fatal verification failures.
    pub errors: Vec<String>,
}

/// Verifies a code-signing CMS blob over `content` (the CodeDirectory bytes).
///
/// `cms_blob` is the raw signature slot blob including its 8-byte
/// `CSMAGIC_BLOBWRAPPER` header. `cd_sha1` is `Some` only for dual
/// SHA-1+SHA-256 output; `cd_sha256` is always the full 32-byte digest.
/// The default trust-anchor set is [`TrustAnchors::apple_root`]; use
/// [`verify_code_signature_with_anchors`] to supply a different policy.
///
/// # Errors
///
/// Returns [`Error::Verification`] when the blob is not a well-formed CMS
/// structure; integrity failures are reported in the returned report (with
/// `valid == false`) rather than as hard errors.
pub fn verify_code_signature(
    cms_blob: &[u8],
    content: &[u8],
    cd_sha1: Option<&[u8; 20]>,
    cd_sha256: &[u8; 32],
) -> Result<CmsVerifyReport> {
    verify_code_signature_with_anchors(
        cms_blob,
        content,
        cd_sha1,
        cd_sha256,
        &TrustAnchors::apple_root()?,
    )
}

/// Like [`verify_code_signature`], but against an explicit anchor set.
///
/// Tests inject their own root here; production callers that need a custom
/// trust policy pass their store. The default entry point uses
/// [`TrustAnchors::apple_root`].
pub fn verify_code_signature_with_anchors(
    cms_blob: &[u8],
    content: &[u8],
    cd_sha1: Option<&[u8; 20]>,
    cd_sha256: &[u8; 32],
    anchors: &TrustAnchors,
) -> Result<CmsVerifyReport> {
    let cms = strip_blob_wrapper(cms_blob)?;
    // Some Apple-produced binaries use BER indefinite lengths; normalize to
    // strict DER before parsing (no-op on already-definite input).
    let cms = normalize_ber_lengths(cms)?;
    verify_signed_data(&cms, content, cd_sha1, cd_sha256, anchors)
}

/// Builds a verification report for an ad-hoc signature (no CMS present).
pub fn adhoc_report() -> CmsVerifyReport {
    CmsVerifyReport {
        no_signature: true,
        valid: true,
        ..CmsVerifyReport::default()
    }
}

/// Certificates whose public keys are trusted as chain termini.
///
/// A chain must terminate at a certificate that either matches one of these
/// anchors (embedded self-signed root) or whose missing issuer names one
/// (unembedded root); otherwise verification fails as unanchored.
#[derive(Debug, Clone, Default)]
pub struct TrustAnchors {
    roots: Vec<x509_cert::Certificate>,
}

impl TrustAnchors {
    /// Wraps the given certificates as trust anchors.
    pub fn from_certificates(roots: Vec<x509_cert::Certificate>) -> Self {
        Self { roots }
    }

    /// The Apple Root CA embedded in [`crate::crypto::assets`].
    ///
    /// This is the default anchor set for [`verify_code_signature`].
    pub fn apple_root() -> Result<Self> {
        let cert =
            x509_cert::Certificate::from_pem(crate::crypto::assets::APPLE_ROOT_CA_CERT.as_bytes())
                .map_err(|e| {
                    Error::Verification(format!(
                        "embedded Apple root CA certificate is invalid: {e}"
                    ))
                })?;
        Ok(Self { roots: vec![cert] })
    }

    /// Whether an anchor's DER-encoded SubjectPublicKeyInfo equals `spki_der`.
    fn contains_spki(&self, spki_der: &[u8]) -> bool {
        self.roots.iter().any(|r| {
            r.tbs_certificate
                .subject_public_key_info
                .to_der()
                .map(|d| d.as_slice() == spki_der)
                .unwrap_or(false)
        })
    }

    /// The anchor whose subject equals `name` (issuer lookup for unembedded roots).
    fn find_by_subject(&self, name: &x509_cert::name::Name) -> Option<&x509_cert::Certificate> {
        self.roots
            .iter()
            .find(|r| r.tbs_certificate.subject == *name)
    }
}

fn strip_blob_wrapper(blob: &[u8]) -> Result<&[u8]> {
    if blob.len() < 8 {
        return Err(Error::Verification(
            "CMS slot blob too short for header".into(),
        ));
    }
    // CSMAGIC_BLOBWRAPPER = 0xfade0b01
    if blob[0..4] != 0xfade_0b01u32.to_be_bytes() {
        return Err(Error::Verification(
            "CMS slot blob has wrong magic (not a blob wrapper)".into(),
        ));
    }
    let len = u32::from_be_bytes(blob[4..8].try_into().unwrap()) as usize;
    if len < 8 || len > blob.len() {
        return Err(Error::Verification(format!(
            "CMS blob wrapper length {len} out of range (blob {} bytes)",
            blob.len()
        )));
    }
    Ok(&blob[8..len])
}

/// Creates a reader with a contextual verification error.
fn reader<'a>(bytes: &'a [u8], ctx: &str) -> Result<SliceReader<'a>> {
    SliceReader::new(bytes).map_err(|e| Error::Verification(format!("{ctx}: {e}")))
}

/// The raw signed attributes (the `[0]`-tagged SET OF Attribute field), plus
/// the parsed attribute values we care about.
struct SignedAttrs<'a> {
    content_type_count: usize,
    content_types: Vec<ObjectIdentifier>,
    message_digest: Option<&'a [u8]>,
    cdhash_v1_plist: Option<&'a [u8]>,
    cdhash_v2_der: Option<&'a [u8]>,
}

/// Parses a signedAttrs `[0]` field's content into the attributes we need.
fn parse_signed_attrs(content: &[u8]) -> Result<SignedAttrs<'_>> {
    let mut r = reader(content, "malformed signedAttrs")?;
    let mut content_type_count = 0;
    let mut content_types = Vec::new();
    let mut message_digest = None;
    let mut cdhash_v1_plist = None;
    let mut cdhash_v2_der = None;
    while !r.is_finished() {
        let attr = AnyRef::decode(&mut r)
            .map_err(|e| Error::Verification(format!("malformed signed attribute: {e}")))?;
        if attr.tag() != Tag::Sequence {
            return Err(Error::Verification(
                "signed attribute is not a SEQUENCE".into(),
            ));
        }
        let mut ar = reader(attr.value(), "malformed attribute body")?;
        let oid = ObjectIdentifier::decode(&mut ar)
            .map_err(|e| Error::Verification(format!("malformed attribute OID: {e}")))?;
        let values = AnyRef::decode(&mut ar)
            .map_err(|e| Error::Verification(format!("malformed attribute values: {e}")))?;
        if values.tag() != Tag::Set {
            return Err(Error::Verification("attribute values are not a SET".into()));
        }
        // First value of the SET.
        let vbytes = values.value();
        if oid == OID_CONTENT_TYPE {
            // RFC 5652 §5.3/§11.1: exactly one value. Delimit every complete TLV
            // in the SET first, then strict-decode each TLV as an OID — so a value
            // after a non-OID or malformed one is still counted and can never
            // evade duplicate detection.
            let mut vr = reader(vbytes, "malformed contentType value")?;
            while !vr.is_finished() {
                content_type_count += 1;
                let start = usize::try_from(vr.position()).unwrap_or(0);
                if AnyRef::decode(&mut vr).is_err() {
                    // Not delimitable (truncated length): the broken value is
                    // counted above and nothing can follow a length error.
                    break;
                }
                let end = usize::try_from(vr.position()).unwrap_or(0);
                if let Some(tlv) = vbytes.get(start..end) {
                    if let Ok(ct) = ObjectIdentifier::from_der(tlv) {
                        content_types.push(ct);
                    }
                }
            }
            continue;
        }
        let mut vr = reader(vbytes, "malformed attribute value")?;
        let vstart = usize::try_from(vr.position()).unwrap_or(0);
        let value = match AnyRef::decode(&mut vr) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let vend = usize::try_from(vr.position()).unwrap_or(0);

        if oid == OID_MESSAGE_DIGEST {
            if value.tag() == Tag::OctetString {
                message_digest = Some(value.value());
            }
        } else if oid == OID_APPLE_CDHASH_V1 {
            if value.tag() == Tag::OctetString {
                cdhash_v1_plist = Some(value.value());
            }
        } else if oid == OID_APPLE_CDHASH_V2 && value.tag() == Tag::Sequence {
            // Keep the full SEQUENCE TLV (the value is the raw DER sequence).
            cdhash_v2_der = vbytes.get(vstart..vend);
        }
    }

    Ok(SignedAttrs {
        content_type_count,
        content_types,
        message_digest,
        cdhash_v1_plist,
        cdhash_v2_der,
    })
}

/// RFC 5652 §5.3/§11.1: exactly one signed `contentType` value; §5.6: its
/// value must equal the encapsulated content type (id-data, required
/// separately below). `count` is every value delimited, `decoded` the subset
/// that strict-decoded as OIDs.
fn content_type_reason(count: usize, decoded: &[ObjectIdentifier]) -> Option<String> {
    match count {
        0 => Some("signed contentType attribute missing".into()),
        1 => match decoded.first() {
            Some(only) if *only == OID_ID_DATA => None,
            Some(only) => Some(format!(
                "signed contentType attribute is {only} (expected id-data)"
            )),
            None => Some("signed contentType attribute is malformed".into()),
        },
        _ => Some("duplicate signed contentType attribute".into()),
    }
}

/// Attaches SignedData-level errors to the report on every `Ok` exit so
/// an early return inside the SignerInfo loop can never drop them.
fn seal(mut report: CmsVerifyReport, mut global_errors: Vec<String>) -> Result<CmsVerifyReport> {
    if !global_errors.is_empty() {
        global_errors.append(&mut report.errors);
        report.errors = global_errors;
    }
    Ok(report)
}

/// `[0]`-constructed context tag.
const TAG_CTX0: Tag = Tag::ContextSpecific {
    constructed: true,
    number: TagNumber::new(0),
};
/// `[1]`-constructed context tag.
const TAG_CTX1: Tag = Tag::ContextSpecific {
    constructed: true,
    number: TagNumber::new(1),
};

fn verify_signed_data(
    cms: &[u8],
    content: &[u8],
    cd_sha1: Option<&[u8; 20]>,
    cd_sha256: &[u8; 32],
    anchors: &TrustAnchors,
) -> Result<CmsVerifyReport> {
    let mut report = CmsVerifyReport::default();
    let mut global_errors: Vec<String> = Vec::new();

    let mut r = reader(cms, "malformed ContentInfo")?;
    // ContentInfo ::= SEQUENCE { contentType OID, [0] EXPLICIT SignedData }
    let ci = AnyRef::decode(&mut r)
        .map_err(|e| Error::Verification(format!("malformed ContentInfo: {e}")))?;
    if ci.tag() != Tag::Sequence {
        return Err(Error::Verification("ContentInfo is not a SEQUENCE".into()));
    }
    let mut cir = reader(ci.value(), "malformed ContentInfo body")?;
    let content_type = ObjectIdentifier::decode(&mut cir)
        .map_err(|e| Error::Verification(format!("malformed contentType: {e}")))?;
    if content_type != OID_SIGNED_DATA {
        return Err(Error::Verification(format!(
            "not a signedData CMS (contentType {content_type})"
        )));
    }
    let sd_wrap = AnyRef::decode(&mut cir)
        .map_err(|e| Error::Verification(format!("malformed SignedData wrapper: {e}")))?;
    if sd_wrap.tag() != TAG_CTX0 {
        return Err(Error::Verification(
            "SignedData is not in [0] EXPLICIT wrapper".into(),
        ));
    }

    // SignedData ::= SEQUENCE { version, digestAlgorithms, encapContentInfo,
    //                [0] certificates?, signerInfos }
    let mut sr = reader(sd_wrap.value(), "malformed SignedData")?;
    let sd = AnyRef::decode(&mut sr)
        .map_err(|e| Error::Verification(format!("malformed SignedData: {e}")))?;
    if sd.tag() != Tag::Sequence {
        return Err(Error::Verification("SignedData is not a SEQUENCE".into()));
    }
    let mut sdr = reader(sd.value(), "malformed SignedData body")?;

    // version
    let _version = u32::decode(&mut sdr)
        .map_err(|e| Error::Verification(format!("malformed SignedData version: {e}")))?;

    // digestAlgorithms SET
    let _digest_algs = AnyRef::decode(&mut sdr)
        .map_err(|e| Error::Verification(format!("malformed digestAlgorithms: {e}")))?;

    // encapContentInfo SEQUENCE { eContentType, [0] eContent? }
    let encap = AnyRef::decode(&mut sdr)
        .map_err(|e| Error::Verification(format!("malformed encapContentInfo: {e}")))?;
    if encap.tag() != Tag::Sequence {
        return Err(Error::Verification(
            "encapContentInfo is not a SEQUENCE".into(),
        ));
    }
    let mut encap_r = reader(encap.value(), "malformed encapContentInfo body")?;
    let econtent_type = ObjectIdentifier::decode(&mut encap_r)
        .map_err(|e| Error::Verification(format!("malformed eContentType: {e}")))?;
    if econtent_type != OID_ID_DATA {
        global_errors.push(format!(
            "encapContentInfo eContentType is {econtent_type} (expected id-data)"
        ));
    }
    // Skip an optional [0] eContent if present (detached signatures omit it).
    if !encap_r.is_finished() {
        let _ = AnyRef::decode(&mut encap_r);
    }

    // Optional [0] IMPLICIT certificates, then signerInfos SET.
    let mut certs: Vec<x509_cert::Certificate> = Vec::new();
    let mut signer_infos_raw: Vec<&[u8]> = Vec::new();
    let mut saw_certificates = false;
    while !sdr.is_finished() {
        let next = AnyRef::decode(&mut sdr)
            .map_err(|e| Error::Verification(format!("malformed SignedData tail: {e}")))?;
        match next.tag() {
            TAG_CTX0 if !saw_certificates => {
                saw_certificates = true;
                // IMPLICIT SET OF Certificate: concatenated DER certs.
                let cert_data = next.value();
                let mut cr = reader(cert_data, "malformed certificates")?;
                while !cr.is_finished() {
                    let start = usize::try_from(cr.position()).unwrap_or(0);
                    let cert_any = AnyRef::decode(&mut cr).map_err(|e| {
                        Error::Verification(format!("malformed embedded certificate: {e}"))
                    })?;
                    let end = usize::try_from(cr.position()).unwrap_or(0);
                    // Each element is a CertificateChoices choice; the common
                    // `certificate` alternative is [0]-tagged (IMPLICIT) with
                    // the raw X.509 DER inside. Some builders emit a bare
                    // SEQUENCE; in that case the full element TLV is the cert.
                    let derived: &[u8] = match cert_any.tag() {
                        TAG_CTX0 => cert_any.value(),
                        Tag::Sequence => cert_data.get(start..end).unwrap_or_default(),
                        _ => {
                            return Err(Error::Verification(
                                "unexpected CertificateChoices tag".into(),
                            ))
                        }
                    };
                    let cert = x509_cert::Certificate::from_der(derived).map_err(|e| {
                        Error::Verification(format!("malformed X.509 certificate: {e}"))
                    })?;
                    certs.push(cert);
                }
            }
            TAG_CTX1 => { /* CRLs — ignored */ }
            Tag::Set => {
                // signerInfos SET OF SignerInfo
                let mut sir = reader(next.value(), "malformed signerInfos")?;
                while !sir.is_finished() {
                    let si_any = AnyRef::decode(&mut sir)
                        .map_err(|e| Error::Verification(format!("malformed SignerInfo: {e}")))?;
                    if si_any.tag() != Tag::Sequence {
                        return Err(Error::Verification("SignerInfo is not a SEQUENCE".into()));
                    }
                    signer_infos_raw.push(si_any.value());
                }
            }
            _ => {
                return Err(Error::Verification(format!(
                    "unexpected SignedData field (tag {:?})",
                    next.tag()
                )))
            }
        }
    }

    if signer_infos_raw.is_empty() {
        report.errors.push("no SignerInfo present".into());
        return seal(report, global_errors);
    }

    // Verify each SignerInfo; the report reflects the best (valid) one.
    for si_raw in &signer_infos_raw {
        let mut si_r = reader(si_raw, "malformed SignerInfo")?;
        let _si_version = u32::decode(&mut si_r)
            .map_err(|e| Error::Verification(format!("malformed SignerInfo version: {e}")))?;

        // sid: issuerAndSerialNumber SEQUENCE or [0] subjectKeyIdentifier.
        let sid = AnyRef::decode(&mut si_r)
            .map_err(|e| Error::Verification(format!("malformed signer id: {e}")))?;
        let sid_body = sid.value();
        let mut ski_cert: Option<&x509_cert::Certificate> = None;
        let mut issuer_der: &[u8] = &[];
        let mut serial_der: &[u8] = &[];
        match sid.tag() {
            Tag::Sequence => {
                let mut sidr = reader(sid_body, "malformed issuerAndSerialNumber")?;
                let ib = usize::try_from(sidr.position()).unwrap_or(0);
                let _issuer_any = AnyRef::decode(&mut sidr)
                    .map_err(|e| Error::Verification(format!("malformed issuer: {e}")))?;
                let ie = usize::try_from(sidr.position()).unwrap_or(0);
                let sb = usize::try_from(sidr.position()).unwrap_or(0);
                let _serial_any = AnyRef::decode(&mut sidr)
                    .map_err(|e| Error::Verification(format!("malformed serial: {e}")))?;
                let se = usize::try_from(sidr.position()).unwrap_or(0);
                issuer_der = sid_body.get(ib..ie).unwrap_or_default();
                serial_der = sid_body.get(sb..se).unwrap_or_default();
            }
            // cms 0.2.3 encodes the SKI sid as an IMPLICIT *primitive* [0] OCTET
            // STRING (der-derive default); tolerate a constructed wrapper too — its
            // value is then the inner OCTET STRING TLV rather than the raw key id.
            Tag::ContextSpecific {
                number,
                constructed,
            } if number == TagNumber::new(0) => {
                let key_id: Option<Vec<u8>> = if constructed {
                    der::asn1::OctetString::from_der(sid_body)
                        .ok()
                        .map(|o| o.as_bytes().to_vec())
                } else {
                    Some(sid_body.to_vec())
                };
                let resolved = key_id
                    .as_deref()
                    .and_then(|kid| find_cert_by_ski(&certs, kid));
                match resolved {
                    Some(c) => ski_cert = Some(c),
                    None => {
                        // Never leave the report invalid-with-empty-errors: record why
                        // this SignerInfo was unusable and move to the next one.
                        if report.errors.is_empty() {
                            report.errors.push(
                                "signer subjectKeyIdentifier does not match any embedded certificate"
                                    .into(),
                            );
                        }
                        continue;
                    }
                }
            }
            other => {
                return Err(Error::Verification(format!(
                    "unexpected signer id tag {other:?}"
                )))
            }
        };

        // digestAlgorithm
        let dig_alg = AnyRef::decode(&mut si_r)
            .map_err(|e| Error::Verification(format!("malformed digestAlgorithm: {e}")))?;
        let dig_oid = {
            let mut dar = reader(dig_alg.value(), "malformed digestAlgorithm body")?;
            ObjectIdentifier::decode(&mut dar)
                .map_err(|e| Error::Verification(format!("malformed digest OID: {e}")))?
        };
        if dig_oid != OID_SHA256 {
            report.errors.push(format!(
                "unsupported digest algorithm {dig_oid} (only SHA-256 is supported)"
            ));
            return seal(report, global_errors);
        }

        // signedAttrs [0] — capture raw bytes (the signed message).
        let attrs_start = usize::try_from(si_r.position()).unwrap_or(0);
        let attrs_any = AnyRef::decode(&mut si_r)
            .map_err(|e| Error::Verification(format!("malformed signedAttrs: {e}")))?;
        if attrs_any.tag() != TAG_CTX0 {
            return Err(Error::Verification("signedAttrs is not [0]-tagged".into()));
        }
        let attrs_end = usize::try_from(si_r.position()).unwrap_or(0);
        let attrs_raw = &si_raw[attrs_start..attrs_end];
        let attrs = parse_signed_attrs(attrs_any.value())?;

        // signatureAlgorithm + signature
        let sig_alg = AnyRef::decode(&mut si_r)
            .map_err(|e| Error::Verification(format!("malformed signatureAlgorithm: {e}")))?;
        let sig_oid = {
            let mut sar = reader(sig_alg.value(), "malformed signatureAlgorithm body")?;
            ObjectIdentifier::decode(&mut sar)
                .map_err(|e| Error::Verification(format!("malformed signature OID: {e}")))?
        };
        let sig_any = AnyRef::decode(&mut si_r)
            .map_err(|e| Error::Verification(format!("malformed signature: {e}")))?;
        if sig_any.tag() != Tag::OctetString {
            return Err(Error::Verification(
                "signature is not an OCTET STRING".into(),
            ));
        }
        let signature = sig_any.value();

        // Locate the signing certificate by resolved SKI or issuer+serial.
        let signer_cert = match ski_cert {
            Some(c) => Some(c),
            None => certs.iter().find(|c| {
                c.tbs_certificate
                    .issuer
                    .to_der()
                    .map(|d| d.as_slice() == issuer_der)
                    .unwrap_or(false)
                    && c.tbs_certificate
                        .serial_number
                        .to_der()
                        .map(|d| d.as_slice() == serial_der)
                        .unwrap_or(false)
            }),
        };

        let Some(cert) = signer_cert else {
            report
                .errors
                .push("signing certificate not found in embedded set".into());
            return seal(report, global_errors);
        };

        let cn = cert.tbs_certificate.subject.to_string();
        report.signer_subject = Some(cn.clone());
        report.signer_serial = cert
            .tbs_certificate
            .serial_number
            .to_der()
            .ok()
            .map(|d| hex(&d));

        // 1. messageDigest attribute == SHA-256(content)
        let digest = Sha256::digest(content);
        let md_ok = attrs
            .message_digest
            .map(|md| md == digest.as_slice())
            .unwrap_or(false);
        report.message_digest_ok = md_ok;

        // 2. Apple CDHash attributes bind this CodeDirectory.
        let v1_ok = attrs
            .cdhash_v1_plist
            .map(|p| cdhash_v1_matches(p, cd_sha1, cd_sha256))
            .unwrap_or(false);
        report.cdhash_v1_ok = v1_ok;
        let v2_ok = attrs
            .cdhash_v2_der
            .map(|d| cdhash_v2_matches(d, cd_sha256))
            .unwrap_or(false);
        report.cdhash_v2_ok = v2_ok;

        // 3. Signature over the raw signedAttrs bytes.
        let sig_ok = verify_signer_signature(cert, sig_oid, attrs_raw, signature);
        report.signature_ok = sig_ok;

        // 4. Chain structure and trust anchoring.
        let outcome = verify_chain(&certs, cert, anchors);
        report.chain_ok = outcome.ok;
        report.anchored = outcome.anchored;
        report.chain = outcome.subjects;
        report.chain_reason = outcome.reason.clone();
        for w in outcome.warnings {
            if !report.warnings.contains(&w) {
                report.warnings.push(w);
            }
        }

        let mut errors = Vec::new();
        if !md_ok {
            errors.push("messageDigest attribute does not match the signed content".into());
        }
        if !v1_ok {
            errors.push("Apple CDHash v1 attribute does not match the CodeDirectory".into());
        }
        if !v2_ok {
            errors.push("Apple CDHash v2 attribute does not match the CodeDirectory".into());
        }
        if !sig_ok {
            errors.push("signature does not verify over the signed attributes".into());
        }
        if !outcome.ok {
            errors.push(
                report
                    .chain_reason
                    .clone()
                    .unwrap_or_else(|| "certificate chain is not structurally valid".into()),
            );
        } else if !outcome.anchored {
            errors.push("certificate chain is not anchored to a trusted root".into());
        }
        if let Some(reason) = content_type_reason(attrs.content_type_count, &attrs.content_types) {
            errors.push(reason);
        }

        if errors.is_empty() {
            if global_errors.is_empty() {
                report.valid = true;
                report.errors.clear();
            }
            // No-op when globals are empty; otherwise the structural errors
            // land first and keep `valid` false.
            return seal(report, global_errors);
        }
        if report.errors.is_empty() {
            report.errors = errors;
        }
    }

    seal(report, global_errors)
}

/// Checks the Apple CDHash v1 plist attribute (a plist with a `cdhashes`
/// array of data values). Modern sha256-only output carries a single
/// truncated-SHA-256 entry; legacy dual output carries SHA-1 then truncated
/// SHA-256.
fn cdhash_v1_matches(plist_bytes: &[u8], cd_sha1: Option<&[u8; 20]>, cd_sha256: &[u8; 32]) -> bool {
    let Ok(value) = plist::from_bytes::<plist::Value>(plist_bytes) else {
        return false;
    };
    let Some(dict) = value.as_dictionary() else {
        return false;
    };
    let Some(arr) = dict.get("cdhashes").and_then(|v| v.as_array()) else {
        return false;
    };
    let truncated: &[u8] = &cd_sha256[..20];
    match (cd_sha1, arr.as_slice()) {
        (None, [single]) => single.as_data().map(|d| d == truncated).unwrap_or(false),
        (Some(sha1), [first, second]) => {
            first.as_data().map(|d| d == &sha1[..]).unwrap_or(false)
                && second.as_data().map(|d| d == truncated).unwrap_or(false)
        }
        _ => false,
    }
}

/// Checks the Apple CDHash v2 attribute: a DER SEQUENCE { SHA-256 OID,
/// OCTET STRING } carrying the full 32-byte cdhash.
fn cdhash_v2_matches(der: &[u8], cd_sha256: &[u8; 32]) -> bool {
    let Ok(mut r) = reader(der, "malformed CDHash v2") else {
        return false;
    };
    let seq = match AnyRef::decode(&mut r) {
        Ok(seq) if seq.tag() == Tag::Sequence => seq,
        _ => return false,
    };
    let Ok(mut sr) = reader(seq.value(), "malformed CDHash v2 body") else {
        return false;
    };
    let Ok(oid) = ObjectIdentifier::decode(&mut sr) else {
        return false;
    };
    if oid != OID_SHA256 {
        return false;
    }
    let Ok(hash) = OctetStringRef::decode(&mut sr) else {
        return false;
    };
    hash.as_bytes() == cd_sha256
}

/// Verifies the signerInfo signature over the signed attributes with the
/// signing certificate's public key.
fn verify_signer_signature(
    cert: &x509_cert::Certificate,
    sig_oid: ObjectIdentifier,
    signed_attrs_raw: &[u8],
    signature: &[u8],
) -> bool {
    use signature::Verifier;

    let spki = &cert.tbs_certificate.subject_public_key_info;
    let alg = spki.algorithm.oid;

    // Signed attributes are transported as [0] IMPLICIT, but the signature may
    // cover either that form or the plain SET form (the cms builder signs the
    // SET encoding; Apple's verifier accepts the signature over either). Try
    // both.
    let mut candidates: Vec<&[u8]> = vec![signed_attrs_raw];
    let set_form;
    if signed_attrs_raw.first() == Some(&0xA0) {
        set_form = {
            let mut v = signed_attrs_raw.to_vec();
            v[0] = 0x31; // SET OF tag
            v
        };
        candidates.push(&set_form);
    }

    // Dispatch on signatureAlgorithm; RSA can be rsaEncryption (with the
    // digest OID carrying SHA-256) or sha256WithRSAEncryption directly.
    let rsa_sig = sig_oid == OID_SHA256_WITH_RSA || sig_oid == OID_RSA_ENCRYPTION;
    let ecdsa_sig = sig_oid == OID_ECDSA_WITH_SHA256;

    for msg in candidates {
        let ok = if rsa_sig && alg == OID_RSA_ENCRYPTION {
            let Ok(pk_der) = spki.to_der() else {
                return false;
            };
            let Ok(pub_key) = rsa::RsaPublicKey::from_public_key_der(&pk_der) else {
                return false;
            };
            let Ok(sig) = rsa::pkcs1v15::Signature::try_from(signature) else {
                return false;
            };
            rsa::pkcs1v15::VerifyingKey::<Sha256>::new(pub_key)
                .verify(msg, &sig)
                .is_ok()
        } else if ecdsa_sig && alg == OID_EC_PUBLIC_KEY {
            let Ok(pk_der) = spki.to_der() else {
                return false;
            };
            let Ok(vk) = p256::ecdsa::VerifyingKey::from_public_key_der(&pk_der) else {
                return false;
            };
            let Ok(sig) = p256::ecdsa::Signature::from_slice(signature) else {
                return false;
            };
            vk.verify(msg, &sig).is_ok()
        } else {
            return false;
        };
        if ok {
            return true;
        }
    }
    false
}

/// The result of walking a certificate chain toward a trust anchor.
struct ChainOutcome {
    /// Structural + cryptographic checks passed (every link verified).
    ok: bool,
    /// The terminus was matched against the trust anchors.
    anchored: bool,
    /// Certificate subjects, leaf first.
    subjects: Vec<String>,
    /// Why `ok` is false, when it is.
    reason: Option<String>,
    /// Non-fatal observations (SHA-1 signatures — added by queue item 5).
    warnings: Vec<String>,
}

/// Walks the embedded certificate set from `leaf` toward a trust anchor,
/// enforcing leaf and issuer purpose constraints, then verifying each
/// certificate's signature with its issuer's public key and validity window.
fn verify_chain(
    certs: &[x509_cert::Certificate],
    leaf: &x509_cert::Certificate,
    anchors: &TrustAnchors,
) -> ChainOutcome {
    let mut names = vec![leaf.tbs_certificate.subject.to_string()];
    let mut warnings: Vec<String> = Vec::new();
    let mut current = leaf;
    let now = time_now();

    if let Some(reason) = leaf_purpose_reason(leaf) {
        return ChainOutcome {
            ok: false,
            anchored: false,
            subjects: names,
            reason: Some(reason),
            warnings,
        };
    }
    if !in_validity(leaf, now) {
        let v = &leaf.tbs_certificate.validity;
        return ChainOutcome {
            ok: false,
            anchored: false,
            subjects: names,
            reason: Some(format!(
                "leaf outside validity (not_before={}, not_after={})",
                fmt_time(&v.not_before),
                fmt_time(&v.not_after)
            )),
            warnings,
        };
    }

    for depth in 0..=certs.len() {
        let self_signed = current.tbs_certificate.subject == current.tbs_certificate.issuer;

        // Find the issuer: a certificate whose subject equals our issuer.
        let parent = certs
            .iter()
            .find(|c| c.tbs_certificate.subject == current.tbs_certificate.issuer);

        match parent {
            Some(p) if !std::ptr::eq(p, current) => {
                if !in_validity(p, now) {
                    let v = &p.tbs_certificate.validity;
                    return ChainOutcome {
                        ok: false,
                        anchored: false,
                        subjects: names,
                        reason: Some(format!(
                            "issuer outside validity (not_before={}, not_after={})",
                            fmt_time(&v.not_before),
                            fmt_time(&v.not_after)
                        )),
                        warnings,
                    };
                }
                if let Some(reason) = issuer_ca_reason(p, names.len().saturating_sub(1)) {
                    return ChainOutcome {
                        ok: false,
                        anchored: false,
                        subjects: names,
                        reason: Some(reason),
                        warnings,
                    };
                }
                if !verify_cert_signature(current, p) {
                    return ChainOutcome {
                        ok: false,
                        anchored: false,
                        subjects: names,
                        reason: Some(format!(
                            "certificate at depth {depth} fails issuer-signature verification"
                        )),
                        warnings,
                    };
                }
                names.push(p.tbs_certificate.subject.to_string());
                current = p;
                continue;
            }
            _ => {
                if self_signed {
                    if !verify_cert_signature(current, current) {
                        return ChainOutcome {
                            ok: false,
                            anchored: false,
                            subjects: names,
                            reason: Some(format!(
                                "self-signed certificate at depth {depth} fails self-signature verification"
                            )),
                            warnings,
                        };
                    }
                    let spki_der = current
                        .tbs_certificate
                        .subject_public_key_info
                        .to_der()
                        .map(|d| d.to_vec())
                        .unwrap_or_default();
                    if anchors.contains_spki(&spki_der) {
                        return ChainOutcome {
                            ok: true,
                            anchored: true,
                            subjects: names,
                            reason: None,
                            warnings,
                        };
                    }
                    // Structure complete, trust not granted — `valid` is gated on `anchored`.
                    return ChainOutcome {
                        ok: true,
                        anchored: false,
                        subjects: names,
                        reason: None,
                        warnings,
                    };
                }
                // Chain runs out: try the trust anchors for the missing issuer before failing.
                let missing = current.tbs_certificate.issuer.clone();
                if let Some(anchor) = anchors.find_by_subject(&missing) {
                    if verify_cert_signature(current, anchor) {
                        names.push(anchor.tbs_certificate.subject.to_string());
                        return ChainOutcome {
                            ok: true,
                            anchored: true,
                            subjects: names,
                            reason: None,
                            warnings,
                        };
                    }
                    return ChainOutcome {
                        ok: false,
                        anchored: false,
                        subjects: names,
                        reason: Some(format!(
                            "certificate at depth {depth} fails trust-anchor signature verification"
                        )),
                        warnings,
                    };
                }
                return ChainOutcome {
                    ok: false,
                    anchored: false,
                    subjects: names,
                    reason: Some(format!(
                        "issuer \"{missing}\" not present in the embedded set or trust anchors"
                    )),
                    warnings,
                };
            }
        }
    }
    ChainOutcome {
        ok: false,
        anchored: false,
        subjects: names,
        reason: Some("chain longer than the embedded certificate set".into()),
        warnings,
    }
}

fn fmt_time(t: &x509_cert::time::Time) -> String {
    format!("{}", t.to_date_time().unix_duration().as_secs())
}

/// Verifies `child`'s signature with `issuer`'s public key.
fn verify_cert_signature(child: &x509_cert::Certificate, issuer: &x509_cert::Certificate) -> bool {
    use signature::Verifier;
    let Ok(tbs) = child.tbs_certificate.to_der() else {
        return false;
    };
    let sig_bytes = child.signature.raw_bytes().to_vec();
    let spki = &issuer.tbs_certificate.subject_public_key_info;
    let alg = spki.algorithm.oid;
    let sig_alg = child.signature_algorithm.oid;

    let Ok(pk_der) = spki.to_der() else {
        return false;
    };
    if alg == OID_RSA_ENCRYPTION {
        let Ok(pub_key) = rsa::RsaPublicKey::from_public_key_der(&pk_der) else {
            return false;
        };
        let Ok(sig) = rsa::pkcs1v15::Signature::try_from(sig_bytes.as_slice()) else {
            return false;
        };
        // The digest comes from the certificate's own signature algorithm:
        // Apple's older intermediates still sign with SHA-1.
        if sig_alg == OID_SHA1_WITH_RSA {
            return rsa::pkcs1v15::VerifyingKey::<sha1::Sha1>::new(pub_key)
                .verify(&tbs, &sig)
                .is_ok();
        }
        if sig_alg == OID_SHA384_WITH_RSA {
            return rsa::pkcs1v15::VerifyingKey::<sha2::Sha384>::new(pub_key)
                .verify(&tbs, &sig)
                .is_ok();
        }
        if sig_alg == OID_SHA512_WITH_RSA {
            return rsa::pkcs1v15::VerifyingKey::<sha2::Sha512>::new(pub_key)
                .verify(&tbs, &sig)
                .is_ok();
        }
        // Default (and by far the most common): SHA-256.
        rsa::pkcs1v15::VerifyingKey::<Sha256>::new(pub_key)
            .verify(&tbs, &sig)
            .is_ok()
    } else if alg == OID_EC_PUBLIC_KEY {
        let Ok(vk) = p256::ecdsa::VerifyingKey::from_public_key_der(&pk_der) else {
            return false;
        };
        let Ok(sig) = p256::ecdsa::Signature::from_slice(&sig_bytes) else {
            return false;
        };
        vk.verify(&tbs, &sig).is_ok()
    } else {
        false
    }
}
/// The DER value of extension `id`, or `None` when the extension is absent.
fn ext_value<'a>(cert: &'a x509_cert::Certificate, id: ObjectIdentifier) -> Option<&'a [u8]> {
    let exts = cert.tbs_certificate.extensions.as_ref()?;
    exts.iter()
        .find(|e| e.extn_id == id)
        .map(|e| e.extn_value.as_bytes())
}

/// Finds the embedded certificate whose SubjectKeyIdentifier equals `key_id`.
///
/// Malformed SKI extensions are skipped; `None` means the SignerInfo cannot
/// be resolved and must be rejected with a fatal report error.
fn find_cert_by_ski<'a>(
    certs: &'a [x509_cert::Certificate],
    key_id: &[u8],
) -> Option<&'a x509_cert::Certificate> {
    use der::Decode;
    certs.iter().find(|c| {
        let Some(bytes) = ext_value(c, OID_SUBJECT_KEY_IDENTIFIER) else {
            return false;
        };
        der::asn1::OctetString::from_der(bytes)
            .map(|ski| ski.as_bytes() == key_id)
            .unwrap_or(false)
    })
}

/// End-entity purpose constraints; applied unconditionally to the leaf.
fn leaf_purpose_reason(leaf: &x509_cert::Certificate) -> Option<String> {
    use x509_cert::ext::pkix::{BasicConstraints, ExtendedKeyUsage, KeyUsage};
    let Some(eku_bytes) = ext_value(leaf, OID_EXT_KEY_USAGE) else {
        return Some("leaf lacks codeSigning EKU extension".into());
    };
    let Ok(eku) = ExtendedKeyUsage::from_der(eku_bytes) else {
        return Some("leaf EKU extension is malformed".into());
    };
    if !eku.0.contains(&OID_CODE_SIGNING) {
        return Some(format!("leaf EKU lacks codeSigning: {:?}", eku.0));
    }
    if let Some(ku_bytes) = ext_value(leaf, OID_KEY_USAGE) {
        let Ok(ku) = KeyUsage::from_der(ku_bytes) else {
            return Some("leaf keyUsage extension is malformed".into());
        };
        if !ku.digital_signature() {
            return Some("leaf keyUsage lacks digitalSignature".into());
        }
    }
    if let Some(bc_bytes) = ext_value(leaf, OID_BASIC_CONSTRAINTS) {
        let Ok(bc) = BasicConstraints::from_der(bc_bytes) else {
            return Some("leaf basicConstraints extension is malformed".into());
        };
        if bc.ca {
            return Some("leaf basicConstraints asserts CA".into());
        }
    }
    None
}

/// CA constraints for a certificate used to issue another.
fn issuer_ca_reason(issuer: &x509_cert::Certificate, cas_below: usize) -> Option<String> {
    use x509_cert::ext::pkix::{BasicConstraints, KeyUsage};
    let Some(bc_bytes) = ext_value(issuer, OID_BASIC_CONSTRAINTS) else {
        return Some("issuer lacks basicConstraints extension".into());
    };
    let Ok(bc) = BasicConstraints::from_der(bc_bytes) else {
        return Some("issuer basicConstraints extension is malformed".into());
    };
    if !bc.ca {
        return Some("issuer basicConstraints is not CA".into());
    }
    if let Some(path_len) = bc.path_len_constraint {
        if cas_below > path_len as usize {
            return Some(format!(
                "issuer pathLen constraint violated ({cas_below} CA certificates below, pathLen {path_len})"
            ));
        }
    }
    if let Some(ku_bytes) = ext_value(issuer, OID_KEY_USAGE) {
        let Ok(ku) = KeyUsage::from_der(ku_bytes) else {
            return Some("issuer keyUsage extension is malformed".into());
        };
        if !ku.key_cert_sign() {
            return Some("issuer keyUsage lacks keyCertSign".into());
        }
    }
    None
}

fn in_validity(cert: &x509_cert::Certificate, now: time::OffsetDateTime) -> bool {
    let v = &cert.tbs_certificate.validity;
    let nb = v.not_before.to_date_time().unix_duration().as_secs() as i64;
    let na = v.not_after.to_date_time().unix_duration().as_secs() as i64;
    let now = now.unix_timestamp();
    nb <= now && now <= na
}

fn time_now() -> time::OffsetDateTime {
    // WASM builds have no reliable wall clock; a fixed reference keeps the
    // module compiling on wasm32 while native builds get real validity checks.
    #[cfg(target_arch = "wasm32")]
    {
        time::OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap()
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        time::OffsetDateTime::now_utc()
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::crypto::cert::SigningKeyType;
    use crate::crypto::cms::sign_code_directory;
    use crate::crypto::SigningCredentials;
    use sha2::Sha256;
    use spki::{EncodePublicKey, SubjectPublicKeyInfoOwned};
    use std::str::FromStr;
    use std::time::Duration;
    use x509_cert::builder::{Builder, CertificateBuilder, Profile};
    use x509_cert::ext::pkix::{BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages};
    use x509_cert::name::Name;
    use x509_cert::serial_number::SerialNumber;
    use x509_cert::time::Validity;

    fn rsa_credentials() -> (SigningCredentials, rsa::RsaPrivateKey) {
        let mut rng = rand::thread_rng();
        let key = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let signing_key = rsa::pkcs1v15::SigningKey::<Sha256>::new(key.clone());
        let subject = Name::from_str("CN=zsign verify test").unwrap();
        let serial = SerialNumber::from(42u32);
        let validity = Validity::from_now(Duration::from_secs(3600)).unwrap();
        let pub_der = key.to_public_key().to_public_key_der().unwrap();
        let pub_key = SubjectPublicKeyInfoOwned::from_der(pub_der.as_ref()).unwrap();
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
            .add_extension(&ExtendedKeyUsage(vec![OID_CODE_SIGNING]))
            .unwrap();
        let cert = builder.build::<rsa::pkcs1v15::Signature>().unwrap();
        (
            SigningCredentials {
                certificate: cert,
                signing_key: SigningKeyType::Rsa(signing_key),
                cert_chain: vec![],
                team_id: None,
            },
            key,
        )
    }

    fn anchors_for(creds: &SigningCredentials) -> TrustAnchors {
        TrustAnchors::from_certificates(vec![creds.certificate.clone()])
    }

    fn wrap(cms: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + cms.len());
        out.extend_from_slice(&0xfade_0b01u32.to_be_bytes());
        out.extend_from_slice(&((8 + cms.len()) as u32).to_be_bytes());
        out.extend_from_slice(cms);
        out
    }

    #[test]
    fn round_trip_rsa_signs_and_verifies() {
        let (creds, _key) = rsa_credentials();
        let content: &[u8] = b"the code directory bytes";
        let cd_sha256: [u8; 32] = Sha256::digest(content).into();
        let cms = sign_code_directory(content, &creds, None, &cd_sha256).unwrap();
        let report = verify_code_signature_with_anchors(
            &wrap(&cms),
            content,
            None,
            &cd_sha256,
            &anchors_for(&creds),
        )
        .unwrap();
        assert!(report.valid, "errors: {:?}", report.errors);
        assert!(report.signature_ok);
        assert!(report.message_digest_ok);
        assert!(report.cdhash_v1_ok);
        assert!(report.cdhash_v2_ok);
        assert!(report.chain_ok);
        assert!(report.anchored);
        assert_eq!(
            report.signer_subject.as_deref(),
            Some("CN=zsign verify test")
        );
    }

    #[test]
    fn tampered_content_fails_digest() {
        let (creds, _key) = rsa_credentials();
        let content: &[u8] = b"the code directory bytes";
        let cd_sha256: [u8; 32] = Sha256::digest(content).into();
        let cms = sign_code_directory(content, &creds, None, &cd_sha256).unwrap();
        let tampered: &[u8] = b"the code directory bytes!";
        let report = verify_code_signature_with_anchors(
            &wrap(&cms),
            tampered,
            None,
            &cd_sha256,
            &anchors_for(&creds),
        )
        .unwrap();
        assert!(!report.valid);
        assert!(!report.message_digest_ok);
    }

    #[test]
    fn tampered_signature_fails_crypto() {
        let (creds, _key) = rsa_credentials();
        let content: &[u8] = b"the code directory bytes";
        let cd_sha256: [u8; 32] = Sha256::digest(content).into();
        let cms = sign_code_directory(content, &creds, None, &cd_sha256).unwrap();
        let mut wrapped = wrap(&cms);
        // Flip a bit near the end of the CMS (inside the signature value).
        let n = wrapped.len();
        wrapped[n - 1] ^= 0x01;
        let report = verify_code_signature_with_anchors(
            &wrapped,
            content,
            None,
            &cd_sha256,
            &anchors_for(&creds),
        )
        .unwrap();
        assert!(!report.valid);
        assert!(!report.signature_ok);
    }

    #[test]
    fn wrong_cdhash_fails_binding() {
        let (creds, _key) = rsa_credentials();
        let content: &[u8] = b"the code directory bytes";
        let cd_sha256: [u8; 32] = Sha256::digest(content).into();
        let cms = sign_code_directory(content, &creds, None, &cd_sha256).unwrap();
        let other: [u8; 32] = [0xEE; 32];
        let report = verify_code_signature_with_anchors(
            &wrap(&cms),
            content,
            None,
            &other,
            &anchors_for(&creds),
        )
        .unwrap();
        assert!(!report.valid);
        assert!(!report.cdhash_v1_ok);
        assert!(!report.cdhash_v2_ok);
    }

    /// Re-encodes a DER blob with every constructed TLV switched to BER
    /// indefinite-length form (used to exercise the normalization path).
    fn to_indefinite(input: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut i = 0usize;
        while i < input.len() {
            let tag = input[i];
            i += 1;
            let l0 = input[i];
            i += 1;
            let constructed = tag & 0x20 != 0;
            let len = if l0 < 0x80 {
                l0 as usize
            } else {
                let count = (l0 & 0x7f) as usize;
                let mut v = 0usize;
                for b in &input[i..i + count] {
                    v = v * 256 + *b as usize;
                }
                i += count;
                v
            };
            let content = &input[i..i + len];
            i += len;

            if !constructed {
                // Primitive: copy tag + original length bytes + content.
                let len_bytes = if l0 < 0x80 {
                    1
                } else {
                    1 + (l0 & 0x7f) as usize
                };
                out.push(tag);
                out.extend_from_slice(&input[i - len - len_bytes..i - len]);
                out.extend_from_slice(content);
                continue;
            }
            // Constructed: rewrite as indefinite.
            out.push(tag);
            out.push(0x80);
            out.extend_from_slice(&to_indefinite(content));
            out.extend_from_slice(&[0x00, 0x00]);
        }
        out
    }

    #[test]
    fn normalizes_ber_indefinite_lengths() {
        // Short-form definite original: the BER form must fold back to it.
        let der = b"\x30\x03\x02\x01\x01".to_vec();
        let indefinite = to_indefinite(&der);
        assert_eq!(indefinite, b"\x30\x80\x02\x01\x01\x00\x00");
        assert_eq!(normalize_ber_lengths(&indefinite).unwrap(), der);
    }

    #[test]
    fn normalize_is_noop_on_definite_input() {
        let der = b"\x30\x03\x02\x01\x01\x04\x02\xaa\xbb".to_vec();
        assert_eq!(normalize_ber_lengths(&der).unwrap(), der);
    }

    #[test]
    fn ber_indefinite_cms_verifies() {
        let (creds, _key) = rsa_credentials();
        let content: &[u8] = b"the code directory bytes";
        let cd_sha256: [u8; 32] = Sha256::digest(content).into();
        let cms = sign_code_directory(content, &creds, None, &cd_sha256).unwrap();
        // Wrap the CMS (ContentInfo, SignedData, etc.) in indefinite form.
        let indefinite = to_indefinite(&cms);
        assert_ne!(indefinite, cms, "re-encode must differ");
        let report = verify_code_signature_with_anchors(
            &wrap(&indefinite),
            content,
            None,
            &cd_sha256,
            &anchors_for(&creds),
        )
        .unwrap();
        assert!(
            report.valid,
            "BER-indefinite CMS must verify after normalization: {:?}",
            report.errors
        );
    }

    /// A CA signed with SHA-1 (Apple's older intermediates) must still chain.
    #[test]
    fn chain_accepts_sha1_signed_intermediate() {
        use std::str::FromStr;
        use x509_cert::builder::{Builder, CertificateBuilder, Profile};
        use x509_cert::name::Name;
        use x509_cert::serial_number::SerialNumber;
        use x509_cert::time::Validity;

        let mut rng = rand::thread_rng();
        let root_key = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let root_signing = rsa::pkcs1v15::SigningKey::<sha1::Sha1>::new(root_key.clone());
        let root_subject = Name::from_str("CN=zsign sha1 root").unwrap();
        let root_serial = SerialNumber::from(1u32);
        let root_validity = Validity::from_now(Duration::from_secs(3600)).unwrap();
        let root_pub_der = root_key.to_public_key().to_public_key_der().unwrap();
        let root_pub = SubjectPublicKeyInfoOwned::from_der(root_pub_der.as_ref()).unwrap();
        let root = CertificateBuilder::new(
            Profile::Root,
            root_serial,
            root_validity,
            root_subject.clone(),
            root_pub,
            &root_signing,
        )
        .unwrap()
        .build::<rsa::pkcs1v15::Signature>()
        .unwrap();

        // Leaf signed by the SHA-1 root (the leaf's own key only provides the
        // public half used in the certificate).
        let leaf_key = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let leaf_subject = Name::from_str("CN=zsign sha1 leaf").unwrap();
        let leaf_serial = SerialNumber::from(2u32);
        let leaf_validity = Validity::from_now(Duration::from_secs(3600)).unwrap();
        let leaf_pub_der = leaf_key.to_public_key().to_public_key_der().unwrap();
        let leaf_pub = SubjectPublicKeyInfoOwned::from_der(leaf_pub_der.as_ref()).unwrap();
        let mut leaf_builder = CertificateBuilder::new(
            // End-entity signed by the SHA-1 root.
            Profile::Leaf {
                issuer: root_subject.clone(),
                enable_key_agreement: false,
                enable_key_encipherment: false,
            },
            leaf_serial,
            leaf_validity,
            leaf_subject,
            leaf_pub,
            &root_signing,
        )
        .unwrap();
        leaf_builder
            .add_extension(&ExtendedKeyUsage(vec![OID_CODE_SIGNING]))
            .unwrap();
        let leaf = leaf_builder.build::<rsa::pkcs1v15::Signature>().unwrap();

        let outcome = verify_chain(
            &[root.clone(), leaf.clone()],
            &leaf,
            &TrustAnchors::from_certificates(vec![root.clone()]),
        );
        assert!(
            outcome.ok,
            "SHA-1-signed intermediate must chain: {:?}",
            outcome.reason
        );
        assert!(outcome.anchored);
    }

    #[test]
    fn rejects_non_cms() {
        assert!(verify_code_signature(&wrap(b"not a cms"), b"x", None, &[0u8; 32]).is_err());
    }

    #[test]
    fn rejects_wrong_wrapper_magic() {
        let blob = vec![0u8; 16];
        assert!(verify_code_signature(&blob, b"x", None, &[0u8; 32]).is_err());
    }

    fn build_rsa_root(
        cn: &str,
    ) -> (
        rsa::RsaPrivateKey,
        x509_cert::Certificate,
        rsa::pkcs1v15::SigningKey<Sha256>,
    ) {
        let key = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
        let signing_key = rsa::pkcs1v15::SigningKey::<Sha256>::new(key.clone());
        let subject = Name::from_str(cn).unwrap();
        let pub_key = SubjectPublicKeyInfoOwned::from_der(
            key.to_public_key().to_public_key_der().unwrap().as_ref(),
        )
        .unwrap();
        let cert = CertificateBuilder::new(
            Profile::Root,
            SerialNumber::from(9u32),
            Validity::from_now(Duration::from_secs(3600)).unwrap(),
            subject,
            pub_key,
            &signing_key,
        )
        .unwrap()
        .build::<rsa::pkcs1v15::Signature>()
        .unwrap();
        (key, cert, signing_key)
    }

    fn chain_with(root: &x509_cert::Certificate, leaf: &x509_cert::Certificate) -> ChainOutcome {
        verify_chain(
            &[root.clone(), leaf.clone()],
            leaf,
            &TrustAnchors::from_certificates(vec![root.clone()]),
        )
    }

    /// Builds `Profile::Leaf` signed by `root_signing`, optionally adding EKU.
    fn build_leaf(
        cn: &str,
        issuer: &x509_cert::name::Name,
        root_signing: &rsa::pkcs1v15::SigningKey<Sha256>,
        eku: Option<x509_cert::ext::pkix::ExtendedKeyUsage>,
    ) -> (rsa::RsaPrivateKey, x509_cert::Certificate) {
        let key = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
        let pub_key = SubjectPublicKeyInfoOwned::from_der(
            key.to_public_key().to_public_key_der().unwrap().as_ref(),
        )
        .unwrap();
        let mut b = CertificateBuilder::new(
            Profile::Leaf {
                issuer: issuer.clone(),
                enable_key_agreement: false,
                enable_key_encipherment: false,
            },
            SerialNumber::from(3u32),
            Validity::from_now(Duration::from_secs(3600)).unwrap(),
            Name::from_str(cn).unwrap(),
            pub_key,
            root_signing,
        )
        .unwrap();
        if let Some(eku) = &eku {
            b.add_extension(eku).unwrap();
        }
        let cert = b.build::<rsa::pkcs1v15::Signature>().unwrap();
        (key, cert)
    }

    #[test]
    fn leaf_without_eku_fails_purpose() {
        let (_k, root, root_signing) = build_rsa_root("CN=zsign purpose root");
        let (_lk, leaf) = build_leaf(
            "CN=zsign no eku leaf",
            &root.tbs_certificate.subject,
            &root_signing,
            None,
        );
        let outcome = chain_with(&root, &leaf);
        assert!(!outcome.ok);
        assert!(outcome
            .reason
            .as_deref()
            .unwrap_or_default()
            .contains("leaf lacks codeSigning EKU"));
    }

    #[test]
    fn leaf_wrong_purpose_eku_fails() {
        let (_k, root, root_signing) = build_rsa_root("CN=zsign purpose root");
        let (_lk, leaf) = build_leaf(
            "CN=zsign tls leaf",
            &root.tbs_certificate.subject,
            &root_signing,
            Some(ExtendedKeyUsage(vec![ObjectIdentifier::new_unwrap(
                "1.3.6.1.5.5.7.3.1", // serverAuth — a purpose that is not codeSigning
            )])),
        );
        let outcome = chain_with(&root, &leaf);
        assert!(!outcome.ok);
        assert!(outcome
            .reason
            .as_deref()
            .unwrap_or_default()
            .contains("leaf EKU lacks codeSigning"));
    }

    #[test]
    fn leaf_with_code_signing_eku_chains() {
        let (_k, root, root_signing) = build_rsa_root("CN=zsign purpose root");
        let (_lk, leaf) = build_leaf(
            "CN=zsign good leaf",
            &root.tbs_certificate.subject,
            &root_signing,
            Some(ExtendedKeyUsage(vec![OID_CODE_SIGNING])),
        );
        let outcome = chain_with(&root, &leaf);
        assert!(outcome.ok, "{:?}", outcome.reason);
        assert!(outcome.anchored);
    }

    #[test]
    fn self_signed_leaf_still_needs_code_signing_eku() {
        // D5 has no self-signed carve-out: a self-signed signer is still the leaf
        // of its own chain and must pass the leaf purpose rules.
        let (_k, self_signed, _s) = build_rsa_root("CN=zsign bare self-signed");
        let outcome = verify_chain(
            &[self_signed.clone()],
            &self_signed,
            &TrustAnchors::from_certificates(vec![self_signed.clone()]),
        );
        assert!(!outcome.ok);
        assert!(outcome
            .reason
            .as_deref()
            .unwrap_or_default()
            .contains("leaf lacks codeSigning EKU"));
    }

    #[test]
    fn attacker_self_signed_resign_is_invalid() {
        let (victim, _k1) = rsa_credentials();
        let (attacker, _k2) = rsa_credentials();
        let content: &[u8] = b"the code directory bytes";
        let cd_sha256: [u8; 32] = Sha256::digest(content).into();
        // The attacker re-signs the same CodeDirectory (same CDHash binding)
        // with a fresh self-signed certificate that nobody trusts.
        let cms = sign_code_directory(content, &attacker, None, &cd_sha256).unwrap();
        let report = verify_code_signature_with_anchors(
            &wrap(&cms),
            content,
            None,
            &cd_sha256,
            &anchors_for(&victim),
        )
        .unwrap();
        assert!(
            !report.valid,
            "attacker re-sign must not verify: {:?}",
            report.errors
        );
        assert!(!report.errors.is_empty());
        assert!(!report.anchored);
    }

    #[test]
    fn chain_missing_issuer_is_invalid() {
        // leaf issued by `root`, but only the leaf gets embedded (cert_chain empty);
        // the anchors available at verification time are an UNRELATED root.
        let (unrelated, _uk) = rsa_credentials();
        let (_root_key, root, root_signer) = build_rsa_root("CN=zsign missing issuer root");
        let leaf_key = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
        let leaf_signing = rsa::pkcs1v15::SigningKey::<Sha256>::new(leaf_key.clone());
        let leaf_subject = Name::from_str("CN=zsign missing issuer leaf").unwrap();
        let mut leaf_builder = CertificateBuilder::new(
            Profile::Leaf {
                issuer: root.tbs_certificate.subject.clone(),
                enable_key_agreement: false,
                enable_key_encipherment: false,
            },
            SerialNumber::from(7u32),
            Validity::from_now(Duration::from_secs(3600)).unwrap(),
            leaf_subject,
            SubjectPublicKeyInfoOwned::from_der(
                leaf_key
                    .to_public_key()
                    .to_public_key_der()
                    .unwrap()
                    .as_ref(),
            )
            .unwrap(),
            &root_signer,
        )
        .unwrap();
        leaf_builder
            .add_extension(&ExtendedKeyUsage(vec![OID_CODE_SIGNING]))
            .unwrap();
        let leaf = leaf_builder.build::<rsa::pkcs1v15::Signature>().unwrap();
        let creds = SigningCredentials {
            certificate: leaf,
            signing_key: SigningKeyType::Rsa(leaf_signing),
            cert_chain: vec![],
            team_id: None,
        };
        let content: &[u8] = b"the code directory bytes";
        let cd_sha256: [u8; 32] = Sha256::digest(content).into();
        let cms = sign_code_directory(content, &creds, None, &cd_sha256).unwrap();
        let report = verify_code_signature_with_anchors(
            &wrap(&cms),
            content,
            None,
            &cd_sha256,
            &anchors_for(&unrelated),
        )
        .unwrap();
        assert!(
            !report.valid,
            "unanchored missing-issuer chain: {:?}",
            report.errors
        );
        assert!(!report.errors.is_empty());
        assert!(report
            .errors
            .iter()
            .any(|e| e.contains("not present in the embedded set or trust anchors")));
    }

    #[test]
    fn unanchored_structural_chain_is_invalid() {
        let (creds, _k) = rsa_credentials();
        let content: &[u8] = b"the code directory bytes";
        let cd_sha256: [u8; 32] = Sha256::digest(content).into();
        let cms = sign_code_directory(content, &creds, None, &cd_sha256).unwrap();
        // Default anchors = Apple Root CA: this self-signed test root is not one.
        let report = verify_code_signature(&wrap(&cms), content, None, &cd_sha256).unwrap();
        assert!(
            !report.valid,
            "structural-but-unanchored chain must be invalid"
        );
        assert!(
            report.chain_ok,
            "structure itself is fine: {:?}",
            report.chain_reason
        );
        assert!(!report.anchored);
    }
    /// Self-issued `Profile::SubCA` acting as the chain root (subject == issuer).
    fn build_subca(
        cn: &str,
        path_len: Option<u8>,
    ) -> (x509_cert::Certificate, rsa::pkcs1v15::SigningKey<Sha256>) {
        let key = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
        let signing_key = rsa::pkcs1v15::SigningKey::<Sha256>::new(key.clone());
        let subject = Name::from_str(cn).unwrap();
        let pub_key = SubjectPublicKeyInfoOwned::from_der(
            key.to_public_key().to_public_key_der().unwrap().as_ref(),
        )
        .unwrap();
        let cert = CertificateBuilder::new(
            Profile::SubCA {
                issuer: subject.clone(),
                path_len_constraint: path_len,
            },
            SerialNumber::from(11u32),
            Validity::from_now(Duration::from_secs(3600)).unwrap(),
            subject,
            pub_key,
            &signing_key,
        )
        .unwrap()
        .build::<rsa::pkcs1v15::Signature>()
        .unwrap();
        (cert, signing_key)
    }

    /// `Profile::SubCA` issued by `issuer`, no pathLen constraint.
    fn build_subca_issued_by(
        cn: &str,
        issuer: &x509_cert::name::Name,
        issuer_signing: &rsa::pkcs1v15::SigningKey<Sha256>,
    ) -> (x509_cert::Certificate, rsa::pkcs1v15::SigningKey<Sha256>) {
        let key = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
        let signing_key = rsa::pkcs1v15::SigningKey::<Sha256>::new(key.clone());
        let pub_key = SubjectPublicKeyInfoOwned::from_der(
            key.to_public_key().to_public_key_der().unwrap().as_ref(),
        )
        .unwrap();
        let cert = CertificateBuilder::new(
            Profile::SubCA {
                issuer: issuer.clone(),
                path_len_constraint: None,
            },
            SerialNumber::from(12u32),
            Validity::from_now(Duration::from_secs(3600)).unwrap(),
            Name::from_str(cn).unwrap(),
            pub_key,
            issuer_signing,
        )
        .unwrap()
        .build::<rsa::pkcs1v15::Signature>()
        .unwrap();
        (cert, signing_key)
    }

    /// Replaces (or appends) extension `id` on `cert` with `value`'s DER.
    ///
    /// Mutation invalidates the mutated certificate's own signature; every
    /// fixture below only exercises checks that run before any verification of
    /// that certificate's signature (leaf purpose checks first, issuer CA checks
    /// before the child-signature check).
    fn replace_extension(
        cert: &mut x509_cert::Certificate,
        id: ObjectIdentifier,
        value: &impl der::Encode,
    ) {
        let bytes = value.to_der().unwrap();
        // x509_cert::ext::Extensions is a plain Vec<Extension>.
        let exts = cert.tbs_certificate.extensions.get_or_insert_with(Vec::new);
        exts.retain(|e| e.extn_id != id);
        exts.push(x509_cert::ext::Extension {
            extn_id: id,
            critical: false,
            extn_value: der::asn1::OctetString::new(bytes).unwrap(),
        });
    }

    #[test]
    fn issuer_without_ca_bit_fails() {
        let (_k, root, root_signing) = build_rsa_root("CN=zsign seed root");
        // A Profile::Leaf certificate carries basicConstraints CA=false; using it
        // to issue another certificate must be rejected before any signature check.
        let (issuer_key, issuer_like) = build_leaf(
            "CN=zsign not a ca",
            &root.tbs_certificate.subject,
            &root_signing,
            None,
        );
        let issuer_signing = rsa::pkcs1v15::SigningKey::<Sha256>::new(issuer_key);
        let (_lk, leaf) = build_leaf(
            "CN=zsign child leaf",
            &issuer_like.tbs_certificate.subject,
            &issuer_signing,
            Some(ExtendedKeyUsage(vec![OID_CODE_SIGNING])),
        );
        let outcome = verify_chain(
            &[issuer_like.clone(), leaf.clone()],
            &leaf,
            &TrustAnchors::from_certificates(vec![issuer_like.clone()]),
        );
        assert!(!outcome.ok);
        assert!(outcome
            .reason
            .as_deref()
            .unwrap_or_default()
            .contains("issuer basicConstraints"));
    }

    #[test]
    fn issuer_key_usage_without_key_cert_sign_fails() {
        let (_k, mut root, root_signing) = build_rsa_root("CN=zsign ku issuer root");
        // Root profile KU is keyCertSign|cRLSign; flip it to digitalSignature only.
        replace_extension(
            &mut root,
            OID_KEY_USAGE,
            &KeyUsage(KeyUsages::DigitalSignature.into()),
        );
        let (_lk, leaf) = build_leaf(
            "CN=zsign ku issuer leaf",
            &root.tbs_certificate.subject,
            &root_signing,
            Some(ExtendedKeyUsage(vec![OID_CODE_SIGNING])),
        );
        let outcome = chain_with(&root, &leaf);
        assert!(!outcome.ok);
        assert!(outcome
            .reason
            .as_deref()
            .unwrap_or_default()
            .contains("keyUsage lacks keyCertSign"));
    }

    #[test]
    fn parent_path_len_violation_fails() {
        // subca: self-issued Profile::SubCA with pathLen 0, one CA (int) below it.
        let (subca, subca_signing) = build_subca("CN=zsign pathlen subca", Some(0));
        let (int, int_signing) = build_subca_issued_by(
            "CN=zsign pathlen int",
            &subca.tbs_certificate.subject,
            &subca_signing,
        );
        let (_lk, leaf) = build_leaf(
            "CN=zsign pathlen leaf",
            &int.tbs_certificate.subject,
            &int_signing,
            Some(ExtendedKeyUsage(vec![OID_CODE_SIGNING])),
        );
        let outcome = verify_chain(
            &[leaf.clone(), int.clone(), subca.clone()],
            &leaf,
            &TrustAnchors::from_certificates(vec![subca.clone()]),
        );
        assert!(!outcome.ok);
        assert!(outcome
            .reason
            .as_deref()
            .unwrap_or_default()
            .contains("pathLen"));
    }

    #[test]
    fn leaf_without_digital_signature_fails() {
        let (_k, root, root_signing) = build_rsa_root("CN=zsign weak ku root");
        let (_lk, mut leaf) = build_leaf(
            "CN=zsign weak ku leaf",
            &root.tbs_certificate.subject,
            &root_signing,
            Some(ExtendedKeyUsage(vec![OID_CODE_SIGNING])),
        );
        replace_extension(
            &mut leaf,
            OID_KEY_USAGE,
            &KeyUsage(KeyUsages::KeyCertSign.into()),
        );
        let outcome = chain_with(&root, &leaf);
        assert!(!outcome.ok);
        assert!(outcome
            .reason
            .as_deref()
            .unwrap_or_default()
            .contains("leaf keyUsage lacks digitalSignature"));
    }

    #[test]
    fn leaf_asserting_ca_fails() {
        let (_k, root, root_signing) = build_rsa_root("CN=zsign bc root");
        let (_lk, mut leaf) = build_leaf(
            "CN=zsign ca leaf",
            &root.tbs_certificate.subject,
            &root_signing,
            Some(ExtendedKeyUsage(vec![OID_CODE_SIGNING])),
        );
        replace_extension(
            &mut leaf,
            OID_BASIC_CONSTRAINTS,
            &BasicConstraints {
                ca: true,
                path_len_constraint: None,
            },
        );
        let outcome = chain_with(&root, &leaf);
        assert!(!outcome.ok);
        assert!(outcome
            .reason
            .as_deref()
            .unwrap_or_default()
            .contains("leaf basicConstraints asserts CA"));
    }

    #[test]
    fn malformed_leaf_eku_fails() {
        let (_k, root, root_signing) = build_rsa_root("CN=zsign bad eku root");
        let (_lk, mut leaf) = build_leaf(
            "CN=zsign bad eku leaf",
            &root.tbs_certificate.subject,
            &root_signing,
            Some(ExtendedKeyUsage(vec![OID_CODE_SIGNING])),
        );
        // `replace_extension` stores the argument's DER inside `extn_value`, so
        // the extension value becomes the OCTET STRING TLV `04 02 05 00` — not a
        // DER SEQUENCE of OIDs, hence a malformed EKU.
        replace_extension(
            &mut leaf,
            OID_EXT_KEY_USAGE,
            &der::asn1::OctetString::new(b"\x05\x00").unwrap(),
        );
        let outcome = chain_with(&root, &leaf);
        assert!(!outcome.ok);
        assert!(outcome
            .reason
            .as_deref()
            .unwrap_or_default()
            .contains("leaf EKU extension is malformed"));
    }
    /// The SubjectKeyIdentifier key id of `cert` (Profile::Root fixtures always
    /// carry the extension).
    fn ski_of(cert: &x509_cert::Certificate) -> Vec<u8> {
        use der::Decode;
        let bytes = ext_value(cert, OID_SUBJECT_KEY_IDENTIFIER).expect("fixture must have SKI");
        // The extension value is the DER of SubjectKeyIdentifier, itself an
        // OCTET STRING over the raw key id.
        der::asn1::OctetString::from_der(bytes)
            .unwrap()
            .as_bytes()
            .to_vec()
    }

    /// tag byte + minimal DER length (module's own `write_len`) + body.
    fn der_tlv(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        write_len(&mut out, body.len());
        out.extend_from_slice(body);
        out
    }

    /// An Attribute SEQUENCE { OID, SET { value } } for parser-level fixtures.
    fn attr_tlv(oid: ObjectIdentifier, value_tlv: &[u8]) -> Vec<u8> {
        use der::Encode;
        let mut body = oid.to_der().unwrap();
        body.extend_from_slice(&der_tlv(0x31, value_tlv)); // SET OF
        der_tlv(0x30, &body)
    }

    #[test]
    fn signed_content_type_must_be_single_id_data() {
        assert!(content_type_reason(0, &[])
            .unwrap_or_default()
            .contains("missing"));
        assert_eq!(content_type_reason(1, &[OID_ID_DATA]), None);
        assert!(content_type_reason(2, &[OID_ID_DATA, OID_ID_DATA])
            .unwrap_or_default()
            .contains("duplicate"));
        let other = ObjectIdentifier::new_unwrap("1.2.840.113635.100.9.1");
        assert!(content_type_reason(1, &[other])
            .unwrap_or_default()
            .contains("expected id-data"));
        // One occurrence whose value did not decode: malformed, not "missing".
        assert!(content_type_reason(1, &[])
            .unwrap_or_default()
            .contains("malformed"));
    }

    #[test]
    fn duplicate_signed_content_type_attributes_are_counted() {
        use der::Encode;
        let id_data = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1")
            .to_der()
            .unwrap();
        let mut body = attr_tlv(OID_CONTENT_TYPE, &id_data);
        body.extend_from_slice(&attr_tlv(OID_CONTENT_TYPE, &id_data));
        let attrs = parse_signed_attrs(&body).unwrap();
        assert_eq!(attrs.content_type_count, 2);
        let reason =
            content_type_reason(attrs.content_type_count, &attrs.content_types).unwrap_or_default();
        assert!(reason.contains("duplicate"), "{reason}");
    }

    #[test]
    fn extra_malformed_content_type_value_is_counted() {
        use der::Encode;
        let mut value = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1")
            .to_der()
            .unwrap();
        value.extend_from_slice(&[0x05, 0x00]); // malformed second value (NULL)
        let body = attr_tlv(OID_CONTENT_TYPE, &value);
        let attrs = parse_signed_attrs(&body).unwrap();
        // A valid id-data first value plus a malformed extra must never read as
        // "exactly one".
        assert_eq!(attrs.content_type_count, 2);
        let reason =
            content_type_reason(attrs.content_type_count, &attrs.content_types).unwrap_or_default();
        assert!(reason.contains("duplicate"), "{reason}");
    }

    #[test]
    fn malformed_middle_value_does_not_hide_trailing_value() {
        use der::Encode;
        let id_data = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1")
            .to_der()
            .unwrap();
        let other = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2")
            .to_der()
            .unwrap();
        let mut value = id_data;
        value.extend_from_slice(&[0x05, 0x00]); // malformed middle value (NULL)
        value.extend_from_slice(&other); // valid trailing value behind it
        let body = attr_tlv(OID_CONTENT_TYPE, &value);
        let attrs = parse_signed_attrs(&body).unwrap();
        // TLV-boundary counting: the trailing value must not escape the count
        // just because an earlier value failed OID decoding.
        assert_eq!(attrs.content_type_count, 3);
        let reason =
            content_type_reason(attrs.content_type_count, &attrs.content_types).unwrap_or_default();
        assert!(reason.contains("duplicate"), "{reason}");
    }

    /// Re-encodes the raw CMS with the first SignerInfo's sid swapped for
    /// `new_sid` (a complete TLV). Assumes the single-SignerInfo output of
    /// `sign_code_directory` (asserted below).
    fn replace_first_sid(cms: &[u8], new_sid: &[u8]) -> Vec<u8> {
        // ContentInfo ::= SEQUENCE { contentType OID, [0] EXPLICIT SignedData }
        let ci = AnyRef::from_der(cms).unwrap();
        assert_eq!(ci.tag(), Tag::Sequence);
        let ci_body = ci.value();
        let mut ci_r = SliceReader::new(ci_body).unwrap();
        let _oid = AnyRef::decode(&mut ci_r).unwrap();
        let oid_end = usize::try_from(ci_r.position()).unwrap();
        let wrap = AnyRef::decode(&mut ci_r).unwrap();
        assert_eq!(wrap.tag(), TAG_CTX0);
        let wrap_tlv = &ci_body[oid_end..]; // [0] wrapper TLV (last field)
                                            // [0] is EXPLICIT: its value carries the full SignedData TLV (`30 …`),
                                            // so the SEQUENCE must be decoded before its fields can be iterated.
        let sd_tlv = wrap.value();
        let sd_seq = AnyRef::from_der(sd_tlv).expect("SignedData SEQUENCE inside [0]");
        assert_eq!(sd_seq.tag(), Tag::Sequence);
        let sd_body_src = sd_seq.value();

        // SignedData fields; signerInfos SET is the LAST one (digestAlgorithms is
        // also a SET — select by position, never by tag, or it gets dropped).
        let mut sd_r = SliceReader::new(sd_body_src).unwrap();
        let mut fields: Vec<&[u8]> = Vec::new(); // version, digestAlgs, encap, certs, set
        while !sd_r.is_finished() {
            let start = usize::try_from(sd_r.position()).unwrap();
            let _field = AnyRef::decode(&mut sd_r).unwrap();
            let end = usize::try_from(sd_r.position()).unwrap();
            fields.push(&sd_body_src[start..end]);
        }
        let set_tlv = fields.pop().expect("SignedData fields required");
        assert_eq!(
            AnyRef::from_der(set_tlv).unwrap().tag(),
            Tag::Set,
            "signerInfos SET must be the last SignedData field"
        );
        let fixed: Vec<&[u8]> = fields;

        // SignerInfo: replace the sid (the field after version).
        let set_any = AnyRef::from_der(set_tlv).unwrap();
        let si_list = set_any.value();
        let mut set_r = SliceReader::new(si_list).unwrap();
        let si_any = AnyRef::decode(&mut set_r).unwrap();
        assert_eq!(si_any.tag(), Tag::Sequence);
        assert!(set_r.is_finished(), "fixture assumes a single SignerInfo");
        let si_body = si_any.value();
        // RFC 5652 §5.3: a subjectKeyIdentifier sid requires SignerInfo version 3,
        // and one v3 SignerInfo forces SignedData version 3. Both are `INTEGER 1`
        // today — bump each with a one-byte patch so lengths never change.
        assert_eq!(
            &si_body[..3],
            &[0x02, 0x01, 0x01],
            "SignerInfo.version assumed INTEGER 1"
        );
        let mut si_body = si_body.to_vec();
        si_body[2] = 0x03;
        let mut si_r = SliceReader::new(&si_body).unwrap();
        let _version = AnyRef::decode(&mut si_r).unwrap();
        let sid_start = usize::try_from(si_r.position()).unwrap();
        let _sid = AnyRef::decode(&mut si_r).unwrap();
        let sid_end = usize::try_from(si_r.position()).unwrap();
        let mut new_si_body = Vec::new();
        new_si_body.extend_from_slice(&si_body[..sid_start]);
        new_si_body.extend_from_slice(new_sid);
        new_si_body.extend_from_slice(&si_body[sid_end..]);

        // Rebuild bottom-up: SignerInfo → SET → SignedData → [0] → ContentInfo.
        let new_si = der_tlv(si_list[0], &new_si_body);
        let new_set = der_tlv(set_tlv[0], &new_si);
        let mut sd_body = Vec::new();
        for (i, f) in fixed.iter().enumerate() {
            if i == 0 {
                assert_eq!(
                    *f,
                    &[0x02, 0x01, 0x01],
                    "SignedData.version assumed INTEGER 1"
                );
                sd_body.extend_from_slice(&[0x02, 0x01, 0x03]);
            } else {
                sd_body.extend_from_slice(f);
            }
        }
        sd_body.extend_from_slice(&new_set);
        let new_sd = der_tlv(sd_tlv[0], &sd_body);
        let new_wrap = der_tlv(wrap_tlv[0], &new_sd);
        let mut ci2 = Vec::new();
        ci2.extend_from_slice(&ci_body[..oid_end]);
        ci2.extend_from_slice(&new_wrap);
        der_tlv(cms[0], &ci2)
    }

    #[test]
    fn ski_signer_resolves_end_to_end() {
        let (creds, _k) = rsa_credentials();
        let content: &[u8] = b"the code directory bytes";
        let cd_sha256: [u8; 32] = Sha256::digest(content).into();
        let cms = sign_code_directory(content, &creds, None, &cd_sha256).unwrap();

        let key_id = ski_of(&creds.certificate);
        let mut sid = vec![0x80u8, key_id.len() as u8];
        sid.extend_from_slice(&key_id);
        let spliced = replace_first_sid(&cms, &sid);

        let report = verify_code_signature_with_anchors(
            &wrap(&spliced),
            content,
            None,
            &cd_sha256,
            &anchors_for(&creds),
        )
        .unwrap();
        assert!(report.valid, "SKI signer must resolve: {:?}", report.errors);
        assert_eq!(
            report.signer_subject.as_deref(),
            Some("CN=zsign verify test")
        );
    }

    #[test]
    fn ski_signer_with_unknown_key_id_is_fatal() {
        let (creds, _k) = rsa_credentials();
        let content: &[u8] = b"the code directory bytes";
        let cd_sha256: [u8; 32] = Sha256::digest(content).into();
        let cms = sign_code_directory(content, &creds, None, &cd_sha256).unwrap();

        let real = ski_of(&creds.certificate);
        let wrong = vec![0x5Au8; real.len()];
        let mut sid = vec![0x80u8, wrong.len() as u8];
        sid.extend_from_slice(&wrong);
        let spliced = replace_first_sid(&cms, &sid);

        let report = verify_code_signature_with_anchors(
            &wrap(&spliced),
            content,
            None,
            &cd_sha256,
            &anchors_for(&creds),
        )
        .unwrap();
        assert!(!report.valid);
        assert!(!report.errors.is_empty());
        assert!(report
            .errors
            .iter()
            .any(|e| e.contains("subjectKeyIdentifier")));
    }
    #[test]
    fn ski_resolves_to_matching_certificate() {
        let (_ka, cert_a, _sa) = build_rsa_root("CN=zsign ski a");
        let (_kb, cert_b, _sb) = build_rsa_root("CN=zsign ski b");
        let key_id = ski_of(&cert_a);
        let certs = [cert_b.clone(), cert_a.clone()];
        let found =
            find_cert_by_ski(&certs, &key_id).expect("key id must resolve to its own certificate");
        assert_eq!(
            found.tbs_certificate.subject,
            cert_a.tbs_certificate.subject
        );
    }

    #[test]
    fn ski_unknown_key_id_finds_nothing() {
        let (_ka, cert_a, _sa) = build_rsa_root("CN=zsign ski solo");
        let mut wrong = ski_of(&cert_a);
        let last = wrong.len() - 1;
        wrong[last] ^= 0xFF;
        assert!(find_cert_by_ski(&[cert_a.clone()], &wrong).is_none());
    }

    #[test]
    fn ski_malformed_extension_is_skipped() {
        let (_ka, mut cert_a, _sa) = build_rsa_root("CN=zsign ski bad");
        // Extension value that is not an OCTET STRING: strict decode fails and
        // the certificate must be skipped, not panic.
        replace_extension(&mut cert_a, OID_SUBJECT_KEY_IDENTIFIER, &der::asn1::Null);
        assert!(find_cert_by_ski(&[cert_a.clone()], b"any key id").is_none());
    }
    #[test]
    fn global_econtent_type_error_beats_clean_signer() {
        let (creds, _k) = rsa_credentials();
        let content: &[u8] = b"the code directory bytes";
        let cd_sha256: [u8; 32] = Sha256::digest(content).into();
        let cms = sign_code_directory(content, &creds, None, &cd_sha256).unwrap();

        // encapContentInfo.eContentType is the first id-data OID TLV in the CMS:
        // everything preceding it (ContentInfo's signedData OID `…1.7.2`, the
        // version INTEGER, digestAlgorithms' SHA-256 OID) shares no bytes with
        // the 11-byte pattern — which includes the OID's own `06 09` header, so
        // a mid-TLV match cannot start — while the signedAttrs copy of id-data
        // and the CDHash payload live much later. Patch the trailing arc 1 → 2:
        // id-data becomes id-signedData, same DER length, and the field is
        // outside signedAttrs, so every per-signer check stays green. (A wrong
        // landing would fail the `encapContentInfo` assertion below loudly.)
        let id_data: &[u8] = &[
            0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01,
        ];
        let pos = cms
            .windows(id_data.len())
            .position(|w| w == id_data)
            .expect("id-data OID must be present");
        let mut patched = cms.clone();
        patched[pos + id_data.len() - 1] = 0x02;

        let report = verify_code_signature_with_anchors(
            &wrap(&patched),
            content,
            None,
            &cd_sha256,
            &anchors_for(&creds),
        )
        .unwrap();
        assert!(
            report.signature_ok,
            "unsigned field must not break the signature"
        );
        assert!(!report.valid, "global error must block a clean signer");
        assert_eq!(
            report.errors.len(),
            1,
            "clean signer must not clear or mask the global error: {:?}",
            report.errors
        );
        assert!(report.errors[0].contains("encapContentInfo eContentType"));
    }
}
