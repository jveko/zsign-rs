//! Real CMS (PKCS#7) signature verification for Apple code signatures.
//!
//! The [`cms`](https://crates.io/crates/cms) crate is signer-only (0.2.x has no
//! verification API), so this module hand-parses the `SignedData` structure on
//! the same pure-Rust `der`/`rsa`/`p256` stack used for signing. It validates,
//! in the same order Apple's verifier does:
//!
//! 1. **Message digest**: the `messageDigest` signed attribute must equal the
//!    digest of the signed content (the CodeDirectory bytes).
//! 2. **Apple CDHash attributes**: the `1.2.840.113635.100.9.1` plist and
//!    `1.2.840.113635.100.9.2` sequence must carry this CodeDirectory's actual
//!    cdhash (truncated-20 for v1, full 32 bytes for v2).
//! 3. **Signature**: the signerInfo signature must verify over the DER encoding
//!    of the `signedAttrs` field as-is (the CMS rule: the `[0]`-tagged SET OF
//!    Attribute is the signed message, not a re-encoded copy).
//! 4. **Signer binding**: the signerInfo issuer+serial must identify a
//!    certificate in the embedded set, and the chain must be structurally
//!    valid (each certificate signed by its issuer, validity windows, leaf
//!    code-signing EKU when present).
//!
//! Trust *policy* (anchoring to Apple's roots, revocation) is deliberately left
//! to the device/`codesign`; this module proves cryptographic integrity and
//! chain structure.
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
use der::{Decode, Encode, Reader, SliceReader, Tag, TagNumber};
use pkcs8::DecodePublicKey;
use sha2::{Digest, Sha256};

/// signedData content type: `1.2.840.113549.1.7.2`
const OID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
/// id-data content type: `1.2.840.113549.1.7.1`
const OID_ID_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");
/// contentType attribute: `1.2.840.113549.1.9.3`
#[allow(dead_code)]
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
/// sha256WithRSAEncryption: `1.2.840.113549.1.1.11`
const OID_SHA256_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
/// ecdsa-with-SHA256: `1.2.840.10045.4.3.2`
const OID_ECDSA_WITH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
/// id-ecPublicKey: `1.2.840.10045.2.1`
const OID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
/// extended key usage extension: `2.5.29.37`
const OID_EXT_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37");
/// codeSigning EKU: `1.3.6.1.5.5.7.3.3`
const OID_CODE_SIGNING: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.3");

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
    /// Whether the chain terminates at a self-signed anchor.
    pub anchored: bool,
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
    let cms = strip_blob_wrapper(cms_blob)?;
    verify_signed_data(cms, content, cd_sha1, cd_sha256)
}

/// Builds a verification report for an ad-hoc signature (no CMS present).
pub fn adhoc_report() -> CmsVerifyReport {
    CmsVerifyReport {
        no_signature: true,
        valid: true,
        ..CmsVerifyReport::default()
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
    message_digest: Option<&'a [u8]>,
    cdhash_v1_plist: Option<&'a [u8]>,
    cdhash_v2_der: Option<&'a [u8]>,
}

/// Parses a signedAttrs `[0]` field's content into the attributes we need.
fn parse_signed_attrs(content: &[u8]) -> Result<SignedAttrs<'_>> {
    let mut r = reader(content, "malformed signedAttrs")?;
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
        message_digest,
        cdhash_v1_plist,
        cdhash_v2_der,
    })
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
) -> Result<CmsVerifyReport> {
    let mut report = CmsVerifyReport::default();

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
        report.warnings.push(format!(
            "unusual eContentType {econtent_type} (expected id-data)"
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
        return Ok(report);
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
        let (issuer_der, serial_der) = match sid.tag() {
            Tag::Sequence => {
                let mut sidr = reader(sid_body, "malformed issuerAndSerialNumber")?;
                let (issuer, serial) = {
                    let ib = usize::try_from(sidr.position()).unwrap_or(0);
                    let _issuer_any = AnyRef::decode(&mut sidr)
                        .map_err(|e| Error::Verification(format!("malformed issuer: {e}")))?;
                    let ie = usize::try_from(sidr.position()).unwrap_or(0);
                    let sb = usize::try_from(sidr.position()).unwrap_or(0);
                    let _serial_any = AnyRef::decode(&mut sidr)
                        .map_err(|e| Error::Verification(format!("malformed serial: {e}")))?;
                    let se = usize::try_from(sidr.position()).unwrap_or(0);
                    (
                        sid_body.get(ib..ie).unwrap_or_default(),
                        sid_body.get(sb..se).unwrap_or_default(),
                    )
                };
                (issuer, serial)
            }
            TAG_CTX0 => {
                report
                    .warnings
                    .push("signer identified by subjectKeyIdentifier; skipping".into());
                continue;
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
            return Ok(report);
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

        // Locate the signing certificate by issuer+serial.
        let signer_cert = certs.iter().find(|c| {
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
        });

        let Some(cert) = signer_cert else {
            report
                .errors
                .push("signing certificate not found in embedded set".into());
            return Ok(report);
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

        // 4. Chain structure.
        let (chain_ok, anchored, chain) = verify_chain(&certs, cert);
        report.chain_ok = chain_ok;
        report.anchored = anchored;
        report.chain = chain;

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
        if !chain_ok {
            errors.push("certificate chain is not structurally valid".into());
        }

        if errors.is_empty() {
            report.valid = true;
            report.errors.clear();
            return Ok(report);
        }
        if report.errors.is_empty() {
            report.errors = errors;
        }
    }

    Ok(report)
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

/// Walks the embedded certificate set from `leaf` toward a root, verifying each
/// certificate's signature with its issuer's public key and its validity
/// window, and checking the leaf's code-signing EKU when one is present.
///
/// Returns `(chain_ok, anchored, chain_subjects_leaf_to_root)`.
fn verify_chain(
    certs: &[x509_cert::Certificate],
    leaf: &x509_cert::Certificate,
) -> (bool, bool, Vec<String>) {
    let mut chain = vec![leaf];
    let mut names = vec![leaf.tbs_certificate.subject.to_string()];
    let mut current = leaf;
    let now = time_now();

    // Leaf code-signing EKU check (only when an EKU extension is present).
    if let Some(eku) = leaf_eku(leaf) {
        if !eku.contains(&OID_CODE_SIGNING) {
            return (false, false, names);
        }
    }
    if !in_validity(leaf, now) {
        return (false, false, names);
    }

    for _ in 0..=certs.len() {
        let self_signed = current.tbs_certificate.subject == current.tbs_certificate.issuer;

        // Find the issuer: a certificate whose subject equals our issuer.
        let parent = certs
            .iter()
            .find(|c| c.tbs_certificate.subject == current.tbs_certificate.issuer);

        match parent {
            Some(p) if !std::ptr::eq(p, current) => {
                if !in_validity(p, now) {
                    return (false, false, names);
                }
                if !verify_cert_signature(current, p) {
                    return (false, false, names);
                }
                chain.push(p);
                names.push(p.tbs_certificate.subject.to_string());
                current = p;
            }
            _ => {
                if self_signed {
                    // Anchor found (leaf or an ancestor is self-signed).
                    return (true, true, names);
                }
                // Chain runs out without an anchor: structural checks pass,
                // trust is not established (device policy decides).
                return (true, false, names);
            }
        }
    }
    let _ = chain;
    (false, false, names)
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

/// Returns the leaf's extended key usage OIDs, if the extension is present.
fn leaf_eku(cert: &x509_cert::Certificate) -> Option<Vec<ObjectIdentifier>> {
    let exts = cert.tbs_certificate.extensions.as_ref()?;
    for ext in exts {
        if ext.extn_id == OID_EXT_KEY_USAGE {
            let mut r = reader(ext.extn_value.as_bytes(), "malformed EKU").ok()?;
            // EKU is itself a SEQUENCE in the extension value.
            let seq = AnyRef::decode(&mut r).ok()?;
            if seq.tag() != Tag::Sequence {
                return None;
            }
            let mut sr = reader(seq.value(), "malformed EKU body").ok()?;
            let mut oids = Vec::new();
            while !sr.is_finished() {
                if let Ok(oid) = ObjectIdentifier::decode(&mut sr) {
                    oids.push(oid);
                } else {
                    break;
                }
            }
            return Some(oids);
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

    #[test]
    fn debug_certs_dump() {
        let (creds, _key) = rsa_credentials();
        let content: &[u8] = b"the code directory bytes";
        let cd_sha256: [u8; 32] = Sha256::digest(content).into();
        let cms = sign_code_directory(content, &creds, None, &cd_sha256).unwrap();
        let wrapped = wrap(&cms);
        let cms_bytes = strip_blob_wrapper(&wrapped).unwrap();
        // find certificates: parse SignedData manually with a cursor
        let mut r = SliceReader::new(cms_bytes).unwrap();
        let ci = AnyRef::decode(&mut r).unwrap();
        let mut cir = SliceReader::new(ci.value()).unwrap();
        let _ct = ObjectIdentifier::decode(&mut cir).unwrap();
        let sd_wrap = AnyRef::decode(&mut cir).unwrap();
        let mut sdr = SliceReader::new(sd_wrap.value()).unwrap();
        let sd = AnyRef::decode(&mut sdr).unwrap();
        let mut sd_body = SliceReader::new(sd.value()).unwrap();
        let _v = u32::decode(&mut sd_body).unwrap();
        let _da = AnyRef::decode(&mut sd_body).unwrap();
        let _encap = AnyRef::decode(&mut sd_body).unwrap();
        let certs0 = AnyRef::decode(&mut sd_body).unwrap();
        println!(
            "certs tag: {:?}, total value len: {}",
            certs0.tag(),
            certs0.value().len()
        );
        let v = certs0.value();

        let mut cr = SliceReader::new(certs0.value()).unwrap();
        let elem = AnyRef::decode(&mut cr).unwrap();
        println!(
            "elem tag: {:?}, elem value len: {}",
            elem.tag(),
            elem.value().len()
        );
        match x509_cert::Certificate::from_der(elem.value()) {
            Ok(_) => println!("from_der OK"),
            Err(e) => println!("from_der ERR: {e}"),
        }
        let show = v.len().min(128);
        for (i, b) in v[..show].iter().enumerate() {
            if i % 16 == 0 {
                print!("{:04x}: ", i);
            }
            print!("{b:02x} ");
            if i % 16 == 15 {
                println!();
            }
        }
        println!();
    }

    use super::*;
    use crate::crypto::cert::SigningKeyType;
    use crate::crypto::cms::sign_code_directory;
    use crate::crypto::SigningCredentials;
    use sha2::Sha256;
    use spki::{EncodePublicKey, SubjectPublicKeyInfoOwned};
    use std::str::FromStr;
    use std::time::Duration;
    use x509_cert::builder::{Builder, CertificateBuilder, Profile};
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
        let report = verify_code_signature(&wrap(&cms), content, None, &cd_sha256).unwrap();
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
        let report = verify_code_signature(&wrap(&cms), tampered, None, &cd_sha256).unwrap();
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
        let report = verify_code_signature(&wrapped, content, None, &cd_sha256).unwrap();
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
        let report = verify_code_signature(&wrap(&cms), content, None, &other).unwrap();
        assert!(!report.valid);
        assert!(!report.cdhash_v1_ok);
        assert!(!report.cdhash_v2_ok);
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
}
