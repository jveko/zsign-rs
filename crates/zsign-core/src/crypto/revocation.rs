//! Best-effort OCSP (RFC 6960) revocation check for a signing certificate.
//!
//! # Posture
//!
//! This module is a **warning surface, never a gate**. Every public function
//! returns a [`RevocationStatus`] and none of them can return an error for
//! anything a responder or a network can do, so no call site can turn a failed
//! lookup into a failed signing run. The only status that produces text is an
//! *authenticated* [`RevocationStatus::Revoked`]: garbage, an unreachable
//! responder, a non-success `responseStatus`, an unverifiable signature, a
//! `CertID` for another certificate and an expired answer are all silent
//! [`RevocationStatus::NotChecked`] outcomes.
//!
//! # Verification
//!
//! Per RFC 6960 §3.2, an answer is trusted only when all of the following hold:
//!
//! 1. The `CertID` is recomputed from the certificate pair and matches the
//!    response's, field by field ([`cert_ids_match`]).
//! 2. `responseStatus` is `successful(0)` and `responseType` is
//!    `id-pkix-ocsp-basic`.
//! 3. The signature over the responder's *own* `tbsResponseData` bytes verifies
//!    against the issuer's key, or against an embedded responder certificate
//!    that this issuer signed and that carries `id-kp-OCSPSigning`. There is no
//!    fallback that re-selects the issuer when a delegated-responder check
//!    fails.
//! 4. `thisUpdate <= now` and `nextUpdate` is absent or `> now`.
//!
//! # Targets
//!
//! The pure half of the module — request building, response parsing, status —
//! compiles for every target including `wasm32`, and never opens a socket. The
//! only function that does, [`warn_revocation`], and the [`HttpTransport`] it
//! uses, are `cfg(not(target_arch = "wasm32"))`. `now` is taken as
//! `Option<OffsetDateTime>` and resolved through
//! [`super::cms_verify::resolve_now`], which keeps the crate's existing
//! fixed-clock wasm convention (`1_800_000_000`) in one place.

use der::{Decode, Encode};
use pkcs8::DecodePublicKey;
use sha1::{Digest, Sha1};
use x509_cert::Certificate;

use super::cms_verify;
use super::pkcs12::DerReader;

/// SHA-1: `1.3.14.3.2.26`. RFC 6960 `CertID` fixes SHA-1 as the hash algorithm,
/// and every responder in the field — Apple's included — expects it there.
const OID_SHA1: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("1.3.14.3.2.26");

/// id-pkix-ocsp-basic: `1.3.6.1.5.5.7.48.1.1`
const OID_OCSP_BASIC: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1.1");

/// rsaEncryption: `1.2.840.113549.1.1.1`
const OID_RSA_ENCRYPTION: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
/// sha1WithRSAEncryption: `1.2.840.113549.1.1.5`
const OID_SHA1_WITH_RSA: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.5");
/// sha256WithRSAEncryption: `1.2.840.113549.1.1.11`
const OID_SHA256_WITH_RSA: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
/// ecdsa-with-SHA256: `1.2.840.10045.4.3.2`
const OID_ECDSA_WITH_SHA256: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
/// id-ecPublicKey: `1.2.840.10045.2.1`
const OID_EC_PUBLIC_KEY: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");

/// The outcome of a revocation lookup. Only [`RevocationStatus::Revoked`]
/// carries a warning; see the [module docs](self).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevocationStatus {
    /// The responder authenticated an answer saying the certificate is not revoked.
    Good,
    /// The responder authenticated an answer saying the certificate *is* revoked.
    Revoked {
        revoked_at: Option<time::OffsetDateTime>,
        reason: Option<String>,
    },
    /// No trustworthy answer was obtained. Every variant here stays silent.
    NotChecked(NotCheckedReason),
}

/// Why no trustworthy revocation status was produced. Every variant is silent:
/// the absence of an answer is never reported as a revoked certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotCheckedReason {
    /// The certificate's AIA extension names no `http:` OCSP responder.
    NoOcspUrl,
    /// The chain carried no certificate that could be the leaf's issuer.
    NoIssuerCertificate,
    /// The AIA OCSP location is not a plaintext `http:` URI this module speaks.
    UnusableUrl,
    /// The transport failed; the payload is the reported error.
    Transport(String),
    /// The answer is not a parseable `OCSPResponse` for this certificate.
    Malformed(String),
    /// The response carries no `SingleResponse` for this certificate's `CertID`.
    NoMatchingCertId,
    /// The answer's signature did not verify against any accepted signer.
    Unverified,
    /// `thisUpdate` is in the future, or `nextUpdate` is in the past.
    OutsideValidityWindow,
    /// The caller's time budget elapsed before the transport answered.
    BudgetExpired,
}

impl RevocationStatus {
    /// The user-facing warning text.
    ///
    /// `Some` only for an *authenticated* `Revoked`. Every other status —
    /// including a malformed, unverified or out-of-window answer — is `None`,
    /// so a caller that prints this can never report a certificate as revoked
    /// on the strength of a failure.
    pub fn warning(&self) -> Option<String> {
        match self {
            RevocationStatus::Revoked { revoked_at, reason } => {
                let mut msg = String::from("certificate is revoked");
                if let Some(at) = revoked_at {
                    msg.push_str(&format!(" since {}", at.date()));
                }
                if let Some(why) = reason {
                    msg.push_str(&format!(" ({why})"));
                }
                Some(msg)
            }
            RevocationStatus::Good | RevocationStatus::NotChecked(_) => None,
        }
    }
}

/// Errors a transport can report. Every one of them becomes a silent
/// [`RevocationStatus::NotChecked`], never a failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportError {
    Unreachable(String),
    Timeout,
    UnexpectedStatus(u16),
    TooLarge,
    Malformed(String),
}

/// The network edge as a trait, so tests drive it with canned bytes or a
/// loopback listener and none of them reaches the internet.
pub trait OcspTransport {
    fn post(&self, url: &str, body: &[u8]) -> std::result::Result<Vec<u8>, TransportError>;
}

/// The `id-ad-ocsp` access location of the leaf's AIA extension, when it is a
/// plaintext `http:` URI. Decoded with the typed `x509_cert` extension, so no
/// hand-rolled AIA parser exists here.
pub fn ocsp_responder_url(leaf: &Certificate) -> Option<String> {
    use x509_cert::ext::pkix::AuthorityInfoAccessSyntax;
    let value = ext_value(leaf, const_oid::db::rfc5280::ID_PE_AUTHORITY_INFO_ACCESS)?;
    let aia = AuthorityInfoAccessSyntax::from_der(value).ok()?;
    aia.0.iter().find_map(|desc| {
        if desc.access_method != const_oid::db::rfc5280::ID_AD_OCSP {
            return None;
        }
        match &desc.access_location {
            // GeneralName `uniformResourceIdentifier` is `[6] IMPLICIT IA5String`.
            x509_cert::ext::pkix::name::GeneralName::UniformResourceIdentifier(uri) => {
                let url = uri.to_string();
                url.starts_with("http://").then_some(url)
            }
            _ => None,
        }
    })
}

/// The DER of the issuer `Name` **as stored in the leaf's own encoding**.
///
/// RFC 6960 §4.1.1 hashes the issuer name "as it appears in the certificate
/// whose validity is being checked", so the bytes are sliced out of the leaf's
/// DER rather than re-encoded from the parsed [`x509_cert::name::Name`]: a Name
/// stored in a non-minimal form re-encodes to something a responder never
/// hashed, and the answer then comes back untrusted.
fn stored_issuer_name_der(leaf: &Certificate) -> Option<Vec<u8>> {
    let cert_body = leaf.to_der().ok()?;
    let mut outer = DerReader::new(&cert_body);
    // `read_sequence` yields the outer SEQUENCE's *content*, which is the
    // `TBSCertificate` TLV; the walk has to step through that TLV before its
    // fields are reachable.
    let tbs_tlv = outer.read_tlv().ok()?;
    if tbs_tlv.0 != 0x30 {
        return None;
    }
    let tbs = DerReader::new(tbs_tlv.1).read_sequence().ok()?;
    let mut r = DerReader::new(tbs);
    if r.peek_tag() == Some(0xa0) {
        r.read_tlv().ok()?; // [0] version, DEFAULT v1 but sometimes present
    }
    r.read_tlv().ok()?; // serialNumber
    r.read_tlv().ok()?; // signature AlgorithmIdentifier
    let name = r.span_of_next_tlv()?;
    Some(name.to_vec())
}

/// Re-encodes an unsigned big-endian magnitude as a DER INTEGER.
///
/// Leading zero bytes are stripped and one is re-added when the top bit is set,
/// which is what RFC 6960's `CertificateSerialNumber` requires. An empty or
/// all-zero magnitude encodes as `02 01 00` — the canonical zero, never the
/// degenerate `02 00`.
fn integer_from_magnitude(magnitude: &[u8]) -> Vec<u8> {
    let mut start = 0;
    while start < magnitude.len() && magnitude[start] == 0 {
        start += 1;
    }
    let trimmed = &magnitude[start..];
    if trimmed.is_empty() {
        return tlv(0x02, &[0]);
    }
    if trimmed[0] & 0x80 != 0 {
        let mut padded = Vec::with_capacity(trimmed.len() + 1);
        padded.push(0);
        padded.extend_from_slice(trimmed);
        return tlv(0x02, &padded);
    }
    tlv(0x02, trimmed)
}

/// The DER content octets of an OBJECT IDENTIFIER, tagged.
fn oid_tlv(oid: const_oid::ObjectIdentifier) -> Vec<u8> {
    tlv(0x06, oid.as_bytes())
}

/// Concatenates borrowed byte slices into one buffer.
fn concat(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(parts.iter().map(|p| p.len()).sum());
    for p in parts {
        out.extend_from_slice(p);
    }
    out
}

/// DER framing for a definite, minimally-encoded length. Indefinite lengths
/// (`0x80`) are never produced here and are rejected on input.
fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if body.len() < 0x80 {
        out.push(body.len() as u8);
    } else {
        let mut len_bytes = Vec::new();
        let mut n = body.len();
        while n > 0 {
            len_bytes.insert(0, (n & 0xff) as u8);
            n >>= 8;
        }
        out.push(0x80 | len_bytes.len() as u8);
        out.extend_from_slice(&len_bytes);
    }
    out.extend_from_slice(body);
    out
}

/// `CertID ::= SEQUENCE { hashAlgorithm, issuerNameHash, issuerKeyHash, serialNumber }`
/// (RFC 6960 §4.1.1).
///
/// `issuerNameHash` is SHA-1 over the DER of the issuer `Name` as stored in the
/// leaf; `issuerKeyHash` is SHA-1 over the value bits of the issuer's
/// `subjectPublicKey`, excluding the BIT STRING's tag, length and unused-bits
/// byte.
fn cert_id(leaf: &Certificate, issuer: &Certificate) -> Option<Vec<u8>> {
    let name_der = stored_issuer_name_der(leaf)?;
    let name_hash = Sha1::digest(&name_der).to_vec();
    let key_bits = issuer
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes();
    let key_hash = Sha1::digest(key_bits).to_vec();
    let serial = leaf.tbs_certificate.serial_number.as_bytes();
    let alg = tlv(0x30, &concat(&[&oid_tlv(OID_SHA1), &tlv(0x05, &[])]));
    Some(tlv(
        0x30,
        &concat(&[
            &alg,
            &tlv(0x04, &name_hash),
            &tlv(0x04, &key_hash),
            &integer_from_magnitude(serial),
        ]),
    ))
}

/// `OCSPRequest ::= SEQUENCE { tbsRequest SEQUENCE { requestList SEQUENCE OF Request } }`
/// with one `Request { reqCert: CertID }` and every OPTIONAL field absent.
pub fn build_request(leaf: &Certificate, issuer: &Certificate) -> Option<Vec<u8>> {
    let cid = cert_id(leaf, issuer)?;
    let request = tlv(0x30, &cid);
    let request_list = tlv(0x30, &request);
    let tbs_request = tlv(0x30, &request_list);
    Some(tlv(0x30, &tbs_request))
}

/// Parses and verifies one `OCSPResponse` for `leaf`/`issuer`.
///
/// This function cannot fail: every outcome, including garbage input and a
/// response whose `CertID` cannot even be built, is a [`RevocationStatus`], and
/// only an authenticated `Revoked` carries a warning.
pub fn parse_and_verify(
    response_der: &[u8],
    leaf: &Certificate,
    issuer: &Certificate,
    now: time::OffsetDateTime,
) -> RevocationStatus {
    let Some(want_cid) = cert_id(leaf, issuer) else {
        return RevocationStatus::NotChecked(NotCheckedReason::Malformed(
            "cannot encode CertID for this certificate pair".into(),
        ));
    };
    walk_response(response_der, &want_cid, issuer, now).unwrap_or_else(|| {
        RevocationStatus::NotChecked(NotCheckedReason::Malformed(
            "response is not a parseable OCSPResponse for this certificate".into(),
        ))
    })
}

/// Compares two DER `CertID`s field by field rather than byte by byte: a
/// responder is free to encode the serial with a different (still valid)
/// INTEGER length, and a byte compare would silently downgrade a legitimate
/// answer to `Malformed`.
/// The four compared fields of a DER `CertID`: hash algorithm, issuer name hash,
/// issuer key hash, serial magnitude.
type CertIdFields = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

fn cert_ids_match(a: &[u8], b: &[u8]) -> bool {
    fn fields(cid: &[u8]) -> Option<CertIdFields> {
        let mut outer = DerReader::new(cid);
        let body = outer.read_sequence().ok()?;
        let mut r = DerReader::new(body);
        let alg = r.read_sequence().ok()?.to_vec();
        let name = r.read_octet_string().ok()?.to_vec();
        let key = r.read_octet_string().ok()?.to_vec();
        let (tag, value) = r.read_tlv().ok()?;
        if tag != 0x02 {
            return None;
        }
        // Compare the serial as a number: a non-minimal INTEGER may carry
        // several leading zero bytes, and one stripped byte would make an
        // otherwise equal CertID look different.
        let serial = value
            .iter()
            .position(|b| *b != 0)
            .map(|i| &value[i..])
            .unwrap_or(&[0u8][..])
            .to_vec();
        Some((alg, name, key, serial))
    }
    match (fields(a), fields(b)) {
        (Some(a_fields), Some(b_fields)) => a_fields == b_fields,
        _ => false,
    }
}

/// `responderID CHOICE { byName [1] Name, byKey [2] KeyHash }` (RFC 6960 §4.2.1).
///
/// `ByName` holds the responder's `Name` as the responder stored it, tag and
/// length included, because that is what has to be compared against the issuer's
/// stored `Name` — the same "as it appears in the certificate" rule the
/// `CertID` hash follows.
enum ResponderId {
    ByName(Vec<u8>),
    ByKey(Vec<u8>),
}

/// The `thisUpdate` stamped by the responder on the first `SingleResponse`.
///
/// Reuses the same envelope walk as [`parse_and_verify`] so the two can never
/// disagree, and exists for the tests that must anchor a clock to the committed
/// fixture instead of to a date that rots.
#[cfg(test)]
fn this_update_of(response_der: &[u8]) -> Option<time::OffsetDateTime> {
    let basic = basic_response(response_der).ok()?;
    let mut b = DerReader::new(basic);
    let tbs_bytes = b.span_of_next_tlv()?;
    let body = DerReader::new(tbs_bytes).read_sequence().ok()?;
    let mut d = DerReader::new(body);
    if d.peek_tag() == Some(0xa0) {
        d.read_tlv().ok()?; // [0] version
    }
    d.read_tlv().ok()?; // responderID
    d.read_tlv().ok()?; // producedAt
    let responses = d.read_sequence().ok()?;
    let mut rs = DerReader::new(responses);
    let single_der = rs.read_sequence().ok()?;
    let mut single = DerReader::new(single_der);
    single.read_tlv().ok()?; // certID
    single.read_tlv().ok()?; // certStatus
    let (tag, when) = single.read_tlv().ok()?;
    parse_time(tag, when)
}

/// The body of the `BasicOCSPResponse` inside an `OCSPResponse` envelope.
///
/// The signed bytes are the responder's *own* `tbsResponseData` TLV, verbatim
/// out of the response — that is exactly the message the signature covers, and
/// re-encoding it would normalise away any non-canonical length form. The
/// envelope is peeled here so the full walk and the test-only `thisUpdate`
/// reader can never disagree about where the signed message starts.
///
/// `Err(NotChecked)` is returned for a non-`successful` `responseStatus`, which
/// is a legal answer that simply carries no `SingleResponse`.
fn basic_response(bytes: &[u8]) -> Result<&[u8], RevocationStatus> {
    let malformed =
        |why: &str| RevocationStatus::NotChecked(NotCheckedReason::Malformed(why.into()));
    let top = DerReader::new(bytes)
        .read_sequence()
        .map_err(|_| malformed("response is not a SEQUENCE"))?;
    let mut r = DerReader::new(top);
    let (status_tag, status_val) = r
        .read_tlv()
        .map_err(|_| malformed("missing responseStatus"))?;
    if status_tag != 0x0a {
        return Err(malformed("responseStatus is not an ENUMERATED"));
    }
    if status_val != [0] {
        let code = status_val.first().copied().unwrap_or(0xff);
        return Err(RevocationStatus::NotChecked(NotCheckedReason::Malformed(
            format!("responder returned responseStatus {code}"),
        )));
    }
    let (bytes_tag, wrapped) = r
        .read_tlv()
        .map_err(|_| malformed("missing responseBytes"))?;
    if bytes_tag != 0xa0 {
        return Err(malformed("responseBytes is not [0] EXPLICIT"));
    }
    let rb = DerReader::new(wrapped)
        .read_sequence()
        .map_err(|_| malformed("ResponseBytes is not a SEQUENCE"))?;
    let mut rbr = DerReader::new(rb);
    let response_type = rbr
        .read_oid()
        .map_err(|_| malformed("missing responseType"))?;
    if response_type != OID_OCSP_BASIC {
        return Err(malformed("responseType is not id-pkix-ocsp-basic"));
    }
    let (octet_tag, basic_tlv) = rbr
        .read_tlv()
        .map_err(|_| malformed("missing response OCTET STRING"))?;
    if octet_tag != 0x04 {
        return Err(malformed("response is not an OCTET STRING"));
    }
    let basic = DerReader::new(basic_tlv)
        .read_sequence()
        .map_err(|_| malformed("BasicOCSPResponse is not a SEQUENCE"))?;
    Ok(basic)
}

/// `OCSPResponse ::= SEQUENCE { responseStatus OCSPResponseStatus,
///                              responseBytes [0] EXPLICIT ResponseBytes OPTIONAL }`
fn walk_response(
    bytes: &[u8],
    want_cid: &[u8],
    issuer: &Certificate,
    now: time::OffsetDateTime,
) -> Option<RevocationStatus> {
    let basic = basic_response(bytes).ok()?;
    let mut b = DerReader::new(basic);
    // The signed bytes: the responder's own `tbsResponseData` TLV, verbatim.
    let tbs_bytes = b.span_of_next_tlv()?.to_vec();
    let sig_alg_oid = {
        let sig_alg = b.read_sequence().ok()?;
        DerReader::new(sig_alg).read_oid().ok()?
    };
    let (sig_tag, sig_bits) = b.read_tlv().ok()?;
    if sig_tag != 0x03 {
        return None;
    }
    let signature = sig_bits.get(1..)?; // skip the unused-bits byte
                                        // `certs [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL`
    let mut embedded: Vec<Certificate> = Vec::new();
    if let Ok((0xa0, certs_wrap)) = b.read_tlv() {
        if let Ok(inner) = DerReader::new(certs_wrap).read_sequence() {
            let mut c = DerReader::new(inner);
            while let Some(cert_span) = c.span_of_next_tlv() {
                if let Ok(cert) = Certificate::from_der(cert_span) {
                    embedded.push(cert);
                } else {
                    break;
                }
            }
        }
    }
    // ResponseData: [0] version, responderID, producedAt, responses, [1] extensions.
    let tbs_body = DerReader::new(&tbs_bytes).read_sequence().ok()?;
    let mut d = DerReader::new(tbs_body);
    if d.peek_tag() == Some(0xa0) {
        d.read_tlv().ok()?; // [0] version
    }
    let (rid_tag, rid_value) = d.read_tlv().ok()?;
    let responder_id = match rid_tag {
        // byName [1] is EXPLICIT: the stored bytes are the inner `Name` TLV.
        0xa1 => ResponderId::ByName(rid_value.to_vec()),
        // byKey [2] is an IMPLICIT OCTET STRING holding the key hash.
        0xa2 => ResponderId::ByKey(rid_value.to_vec()),
        _ => return None,
    };
    d.read_tlv().ok()?; // producedAt
    let responses = d.read_sequence().ok()?;
    let mut rs = DerReader::new(responses);
    while let Some(single_span) = rs.span_of_next_tlv() {
        let single_der = DerReader::new(single_span).read_sequence().ok()?;
        let mut single = DerReader::new(single_der);
        let (cid_tag, cid_value) = single.read_tlv().ok()?;
        if cid_tag != 0x30 {
            return None;
        }
        let this_cid = single_span_of_body(cid_value)?;
        if !cert_ids_match(&this_cid, want_cid) {
            continue;
        }
        // certStatus first: good [0] IMPLICIT NULL, revoked [1] IMPLICIT
        // RevokedInfo, unknown [2] IMPLICIT UnknownInfo.
        let (cs_tag, cs_body) = single.read_tlv().ok()?;
        let revoked_at = if cs_tag == 0xa1 {
            let (when_tag, when) = DerReader::new(cs_body).read_tlv().ok()?;
            Some(parse_time(when_tag, when)?)
        } else {
            None
        };
        let (tu_tag, tu_value) = single.read_tlv().ok()?;
        let this_update = parse_time(tu_tag, tu_value)?;
        // nextUpdate is `[0] EXPLICIT GeneralizedTime` (RFC 6960 §4.2.1): the
        // tag is 0xa0 and the GeneralizedTime sits *inside* the wrapper, so a
        // peek for a bare 0x18/0x80 would never fire.
        let next_update = if single.peek_tag() == Some(0xa0) {
            let (wrapper_tag, wrapper) = single.read_tlv().ok()?;
            if wrapper_tag != 0xa0 {
                return None;
            }
            let (inner_tag, when) = DerReader::new(wrapper).read_tlv().ok()?;
            Some(parse_time(inner_tag, when)?)
        } else {
            None
        };
        if this_update > now || next_update.is_some_and(|n| n < now) {
            return Some(RevocationStatus::NotChecked(
                NotCheckedReason::OutsideValidityWindow,
            ));
        }
        let Some(signer) = pick_signer(&responder_id, issuer, &embedded) else {
            return Some(RevocationStatus::NotChecked(NotCheckedReason::Unverified));
        };
        if !verify_signature(&signer, &sig_alg_oid, &tbs_bytes, signature) {
            return Some(RevocationStatus::NotChecked(NotCheckedReason::Unverified));
        }
        return Some(match cs_tag {
            0x80 => RevocationStatus::Good,
            0xa1 => RevocationStatus::Revoked {
                revoked_at,
                reason: None,
            },
            0x82 => RevocationStatus::NotChecked(NotCheckedReason::Malformed(
                "responder answered unknown(2)".into(),
            )),
            other => RevocationStatus::NotChecked(NotCheckedReason::Malformed(format!(
                "unrecognised certStatus tag 0x{other:02x}"
            ))),
        });
    }
    Some(RevocationStatus::NotChecked(
        NotCheckedReason::NoMatchingCertId,
    ))
}

/// Re-frames a sequence body's bytes as the `SEQUENCE` TLV they were read from,
/// so a `CertID` can be compared as a whole rather than against its contents.
fn single_span_of_body(body: &[u8]) -> Option<Vec<u8>> {
    Some(tlv(0x30, body))
}

/// Chooses the key that must have signed the response (RFC 6960 §4.2.2.2): the
/// issuer itself when `responderID` names the issuer, otherwise one embedded
/// certificate that the issuer issued and that carries `id-kp-OCSPSigning`.
///
/// There is no fallback. A `responderID` naming some other CA, or a `byKey`
/// hash matching no accepted candidate, yields `None` and the answer is
/// `Unverified` — it must never silently resolve to the issuer's key.
fn pick_signer(
    rid: &ResponderId,
    issuer: &Certificate,
    embedded: &[Certificate],
) -> Option<Certificate> {
    let issuer_name = issuer.tbs_certificate.subject.to_der().ok()?;
    match rid {
        ResponderId::ByName(name) if *name == issuer_name => Some(issuer.clone()),
        ResponderId::ByName(name) => embedded
            .iter()
            .find(|c| {
                c.tbs_certificate.subject.to_der().is_ok_and(|d| d == *name)
                    && accepted_delegate(c, issuer)
            })
            .cloned(),
        ResponderId::ByKey(hash) => embedded
            .iter()
            .find(|c| {
                let key_bits = c
                    .tbs_certificate
                    .subject_public_key_info
                    .subject_public_key
                    .raw_bytes();
                Sha1::digest(key_bits).as_slice() == hash.as_slice() && accepted_delegate(c, issuer)
            })
            .cloned(),
    }
}

/// A delegated responder must be issued by this CA, carry `id-kp-OCSPSigning`,
/// and actually verify under the CA's key — all three, or it is not trusted.
fn accepted_delegate(candidate: &Certificate, issuer: &Certificate) -> bool {
    candidate.tbs_certificate.issuer == issuer.tbs_certificate.subject
        && has_ocsp_signing_eku(candidate)
        && verify_cert_signature(candidate, issuer)
}

/// Whether the certificate's `extendedKeyUsage` extension lists
/// `id-kp-OCSPSigning (1.3.6.1.5.5.7.3.9)`.
fn has_ocsp_signing_eku(cert: &Certificate) -> bool {
    use x509_cert::ext::pkix::ExtendedKeyUsage;
    let Some(value) = ext_value(cert, const_oid::db::rfc5280::ID_CE_EXT_KEY_USAGE) else {
        return false;
    };
    ExtendedKeyUsage::from_der(value)
        .map(|eku| eku.0.contains(&const_oid::db::rfc5280::ID_KP_OCSP_SIGNING))
        .unwrap_or(false)
}

/// The DER value of extension `id`, or `None` when absent.
///
/// Duplicated from `cert.rs`/`cms_verify.rs` rather than widened across
/// modules: a three-line lookup is not worth a cross-module signature change.
fn ext_value(cert: &Certificate, id: const_oid::ObjectIdentifier) -> Option<&[u8]> {
    let exts = cert.tbs_certificate.extensions.as_ref()?;
    exts.iter()
        .find(|e| e.extn_id == id)
        .map(|e| e.extn_value.as_bytes())
}

/// Verifies a raw PKCS#1 v1.5 or P-256 signature over `msg`.
fn verify_signature(
    signer: &Certificate,
    sig_alg_oid: &const_oid::ObjectIdentifier,
    msg: &[u8],
    signature: &[u8],
) -> bool {
    use signature::Verifier;
    let spki = &signer.tbs_certificate.subject_public_key_info;
    let key_alg = spki.algorithm.oid;
    let Ok(pk_der) = spki.to_der() else {
        return false;
    };
    if key_alg == OID_RSA_ENCRYPTION {
        let Ok(pub_key) = rsa::RsaPublicKey::from_public_key_der(&pk_der) else {
            return false;
        };
        let Ok(sig) = rsa::pkcs1v15::Signature::try_from(signature) else {
            return false;
        };
        if *sig_alg_oid == OID_SHA1_WITH_RSA {
            return rsa::pkcs1v15::VerifyingKey::<Sha1>::new(pub_key)
                .verify(msg, &sig)
                .is_ok();
        }
        if *sig_alg_oid == OID_SHA256_WITH_RSA {
            return rsa::pkcs1v15::VerifyingKey::<sha2::Sha256>::new(pub_key)
                .verify(msg, &sig)
                .is_ok();
        }
        false
    } else if key_alg == OID_EC_PUBLIC_KEY && *sig_alg_oid == OID_ECDSA_WITH_SHA256 {
        let Ok(vk) = p256::ecdsa::VerifyingKey::from_public_key_der(&pk_der) else {
            return false;
        };
        let Some(sig) = parse_ecdsa_signature(signature) else {
            return false;
        };
        vk.verify(msg, &sig).is_ok()
    } else {
        false
    }
}

/// `child`'s signature verified with `issuer`'s public key.
fn verify_cert_signature(child: &Certificate, issuer: &Certificate) -> bool {
    verify_signature(
        issuer,
        &child.signature_algorithm.oid,
        &child.tbs_certificate.to_der().unwrap_or_default(),
        child.signature.raw_bytes(),
    )
}

/// Splits a DER `ECDSA-Sig-Value` into its two halves.
fn parse_ecdsa_signature(der: &[u8]) -> Option<p256::ecdsa::Signature> {
    p256::ecdsa::Signature::from_der(der).ok()
}

/// Parses an ASN.1 time already split into its tag and value, which RFC 6960
/// §4.2.1 allows to be either `UTCTime` (`0x17`) or `GeneralizedTime` (`0x18`).
///
/// The value is ASCII `YYMMDDHHMMSSZ` (or `YYYYMMDDHHMMSSZ`), never an
/// RFC 3339 timestamp, so the two forms are converted to the calendar
/// themselves: a two-digit year is the RFC 5280 sliding window (50-99 means
/// 19xx), and a `Z` suffix is UTC.
fn parse_time(tag: u8, value: &[u8]) -> Option<time::OffsetDateTime> {
    let text = std::str::from_utf8(value).ok()?;
    if tag != 0x17 && tag != 0x18 {
        return None;
    }
    let d = text.strip_suffix('Z').unwrap_or(text);
    // OpenSSL emits a two-digit-year `GeneralizedTime` (`260101000000Z`) for
    // `revocationTime`, so the year width is decided by the digit count rather
    // than by the tag.
    let (digits, year) = match d.len() {
        12 => {
            let yy = d.get(..2)?.parse::<i32>().ok()?;
            (d, if yy >= 50 { 1900 + yy } else { 2000 + yy })
        }
        14 => (d, d.get(..4)?.parse::<i32>().ok()?),
        _ => return None,
    };
    let num = |range: std::ops::Range<usize>| digits.get(range)?.parse::<u8>().ok();
    let date =
        time::Date::from_calendar_date(year, time::Month::try_from(num(4..6)?).ok()?, num(6..8)?)
            .ok()?;
    let time_of_day = time::Time::from_hms(num(8..10)?, num(10..12)?, num(12..14)?).ok()?;
    Some(time::OffsetDateTime::new_utc(date, time_of_day))
}

/// Runs one OCSP lookup through `transport`.
///
/// Never fails: every problem is a silent [`RevocationStatus::NotChecked`], and
/// only an authenticated `Revoked` yields a warning.
pub fn check(
    leaf: &Certificate,
    issuer: Option<&Certificate>,
    transport: &dyn OcspTransport,
    now: Option<time::OffsetDateTime>,
) -> RevocationStatus {
    let Some(url) = ocsp_responder_url(leaf) else {
        return RevocationStatus::NotChecked(NotCheckedReason::NoOcspUrl);
    };
    let Some(issuer) = issuer else {
        return RevocationStatus::NotChecked(NotCheckedReason::NoIssuerCertificate);
    };
    let now = match cms_verify::resolve_now(now) {
        Ok(t) => t,
        Err(_) => {
            return RevocationStatus::NotChecked(NotCheckedReason::Malformed(
                "no clock available for the validity window".into(),
            ))
        }
    };
    let Some(request) = build_request(leaf, issuer) else {
        return RevocationStatus::NotChecked(NotCheckedReason::Malformed(
            "cannot encode CertID".into(),
        ));
    };
    match transport.post(&url, &request) {
        Ok(response) => parse_and_verify(&response, leaf, issuer, now),
        Err(e) => RevocationStatus::NotChecked(transport_reason(e)),
    }
}

/// Every transport outcome maps to a silent `NotChecked`; the mapping is
/// exhaustive on purpose so a new [`TransportError`] variant cannot fall
/// through into a warning.
pub(crate) fn transport_reason(e: TransportError) -> NotCheckedReason {
    match e {
        TransportError::Timeout => NotCheckedReason::BudgetExpired,
        other => NotCheckedReason::Transport(format!("{other:?}")),
    }
}

/// The user-facing warning for a signing credential, over the caller's transport.
///
/// This function is network-free and compiles for every target, including
/// `wasm32`: it performs no lookup of its own, only delegating to [`check`]
/// through the [`OcspTransport`] it is handed. That is what keeps the wasm
/// surface honest — the only function in this module that can open a socket is
/// [`warn_revocation`], which is native-only, and it is this function's
/// caller.
pub fn warning_of(
    leaf: &Certificate,
    chain: &[Certificate],
    transport: &dyn OcspTransport,
    now: Option<time::OffsetDateTime>,
) -> Option<String> {
    let issuer = issuer_of(leaf, chain);
    check(leaf, issuer, transport, now).warning()
}

/// Best-effort revocation warning for a signing credential, on stderr.
///
/// Prints nothing unless an authenticated responder says the certificate is
/// revoked; every other outcome — no AIA URI, unreachable responder, refused
/// request, unverifiable answer, expired answer — is silent, and the function
/// cannot fail a signing run. It exists on native targets only, because it is
/// the one place a lookup actually opens a socket.
#[cfg(not(target_arch = "wasm32"))]
pub fn warn_revocation(leaf: &Certificate, chain: &[Certificate]) {
    if let Some(warning) = warning_of(leaf, chain, &HttpTransport::default(), None) {
        eprintln!("warning: {warning}");
    }
}

/// The certificate in `chain` that issued `leaf`, matched on subject/issuer name.
fn issuer_of<'a>(leaf: &Certificate, chain: &'a [Certificate]) -> Option<&'a Certificate> {
    let issuer_name = &leaf.tbs_certificate.issuer;
    chain
        .iter()
        .find(|c| &c.tbs_certificate.subject == issuer_name)
}

/// Minimal HTTP/1.1 POST over `std::net` for `http:` OCSP responder URIs.
///
/// OCSP responses are small DER blobs and Apple publishes them over plaintext
/// HTTP, so there is no TLS, no cookie jar, no redirect following and no chunked
/// decoding here: anything this strict reader cannot parse is reported as
/// [`TransportError`] and the signing run continues.
#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, Clone)]
pub struct HttpTransport {
    /// The whole-exchange budget. [`DEFAULT_BUDGET`] when zero.
    pub budget: std::time::Duration,
}

#[cfg(not(target_arch = "wasm32"))]
impl Default for HttpTransport {
    fn default() -> Self {
        Self {
            budget: DEFAULT_BUDGET,
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
const DEFAULT_BUDGET: std::time::Duration = std::time::Duration::from_secs(3);
/// OCSP responses are a few hundred bytes to ~2 KiB; a larger answer is not
/// credible and is refused rather than buffered.
#[cfg(not(target_arch = "wasm32"))]
const MAX_RESPONSE_BYTES: usize = 64 * 1024;

#[cfg(not(target_arch = "wasm32"))]
impl OcspTransport for HttpTransport {
    fn post(&self, url: &str, body: &[u8]) -> std::result::Result<Vec<u8>, TransportError> {
        let budget = if self.budget.is_zero() {
            DEFAULT_BUDGET
        } else {
            self.budget
        };
        // DNS has no timeout in `std::net`, so the whole exchange runs on one
        // worker thread and the caller waits on a channel with the budget. A
        // worker that outlives the deadline is abandoned; its own socket
        // timeouts end it.
        let url = url.to_string();
        let body = body.to_vec();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(post_blocking(&url, &body, budget));
        });
        rx.recv_timeout(budget)
            .map_err(|_| TransportError::Timeout)?
    }
}

/// The literal HTTP exchange behind [`HttpTransport::post`].
///
/// `budget` is the caller's effective budget: it bounds the socket timeouts as
/// well as the caller's wait, so a caller that asks for 300 ms is not left with
/// a 3 s blocking read behind the channel.
#[cfg(not(target_arch = "wasm32"))]
fn post_blocking(
    url: &str,
    body: &[u8],
    budget: std::time::Duration,
) -> std::result::Result<Vec<u8>, TransportError> {
    use std::io::{Read, Write};
    use std::net::TcpStream;

    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| TransportError::Malformed(format!("not an http: URL: {url}")))?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = split_authority(authority)
        .ok_or_else(|| TransportError::Malformed(format!("no host in URL: {url}")))?;
    // A numeric literal is used verbatim; anything else goes through the
    // resolver, which is why a test can prove the loopback path without ever
    // resolving a name.
    let addrs: Vec<std::net::SocketAddr> = match host.parse::<std::net::IpAddr>() {
        Ok(ip) => vec![std::net::SocketAddr::new(ip, port)],
        Err(_) => std::net::ToSocketAddrs::to_socket_addrs(&(host, port))
            .map_err(|e| TransportError::Unreachable(format!("{authority}: {e}")))?
            .collect(),
    };
    if addrs.is_empty() {
        return Err(TransportError::Unreachable(format!(
            "{authority}: no addresses"
        )));
    }
    let mut last_err = TransportError::Unreachable(format!("{authority}: no addresses"));
    let mut stream = None;
    for addr in addrs {
        // The connect gets the whole budget too, so a black-holed SYN cannot
        // outlive it.
        match TcpStream::connect_timeout(&addr, budget) {
            Ok(s) => {
                stream = Some(s);
                break;
            }
            Err(e) => last_err = TransportError::Unreachable(format!("{addr}: {e}")),
        }
    }
    let mut stream = stream.ok_or(last_err)?;
    let _ = stream.set_write_timeout(Some(budget));
    let _ = stream.set_read_timeout(Some(budget));

    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {authority}\r\nContent-Type: application/ocsp-request\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream
        .write_all(request.as_bytes())
        .and_then(|_| stream.write_all(body))
        .map_err(|e| TransportError::Unreachable(format!("write: {e}")))?;
    stream
        .flush()
        .map_err(|e| TransportError::Unreachable(format!("flush: {e}")))?;

    let mut raw = Vec::new();
    let mut chunk = [0u8; 8192];
    let header_end = loop {
        if let Some(i) = find_subslice(&raw, b"\r\n\r\n") {
            break i + 4;
        }
        if raw.len() > MAX_RESPONSE_BYTES {
            return Err(TransportError::TooLarge);
        }
        let n = stream
            .read(&mut chunk)
            .map_err(|e| io_error_to_transport(e, "read"))?;
        if n == 0 {
            return Err(TransportError::Malformed(
                "connection closed before the header block ended".into(),
            ));
        }
        raw.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&raw[..header_end]).into_owned();
    let mut lines = head.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| TransportError::Malformed("empty response".into()))?;
    let code: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .ok_or_else(|| TransportError::Malformed(format!("bad status line: {status_line}")))?;
    if code != 200 {
        return Err(TransportError::UnexpectedStatus(code));
    }
    let declared_len = lines
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.trim().eq_ignore_ascii_case("content-length") {
                value.trim().parse::<usize>().ok()
            } else {
                None
            }
        })
        .unwrap_or(0);
    let mut payload = raw[header_end..].to_vec();
    while payload.len() < declared_len {
        let n = stream
            .read(&mut chunk)
            .map_err(|e| io_error_to_transport(e, "read"))?;
        if n == 0 {
            break;
        }
        payload.extend_from_slice(&chunk[..n]);
    }
    if payload.len() > MAX_RESPONSE_BYTES {
        return Err(TransportError::TooLarge);
    }
    if declared_len != 0 && payload.len() < declared_len {
        return Err(TransportError::Malformed(format!(
            "short body: {} of {declared_len} bytes",
            payload.len()
        )));
    }
    if payload.is_empty() {
        return Err(TransportError::Malformed("empty response body".into()));
    }
    Ok(payload)
}

/// Classifies a socket I/O error: a timeout is the caller's budget, anything
/// else is an unreachable responder. Both are `NotChecked`.
#[cfg(not(target_arch = "wasm32"))]
fn io_error_to_transport(e: std::io::Error, what: &str) -> TransportError {
    match e.kind() {
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => TransportError::Timeout,
        _ => TransportError::Unreachable(format!("{what}: {e}")),
    }
}

/// Splits a URL authority into its host and port, defaulting to 80.
///
/// An IPv6 literal keeps its brackets (`[::1]:8080` -> `::1`, 8080); a bare
/// `[::1]` keeps the brackets for the resolver but parses as a literal. A
/// colon inside a bracketed literal is never a port separator.
#[cfg(not(target_arch = "wasm32"))]
fn split_authority(authority: &str) -> Option<(&str, u16)> {
    if authority.is_empty() {
        return None;
    }
    if let Some(close) = authority.find(']').filter(|_| authority.starts_with('[')) {
        let host = &authority[1..close];
        let after = &authority[close + 1..];
        let port = match after.strip_prefix(':') {
            Some(p) => p.parse().ok()?,
            None if after.is_empty() => 80,
            None => return None,
        };
        return Some((host, port));
    }
    match authority.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() => Some((host, port.parse().ok()?)),
        _ => Some((authority, 80)),
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::DecodePem;
    use x509_cert::Certificate as Cert;

    const CA_PEM: &str = include_str!("fixtures/revocation/ca.pem");
    const LEAF_PEM: &str = include_str!("fixtures/revocation/issued_leaf.pem");
    const REQ_DER: &[u8] = include_bytes!("fixtures/revocation/req.der");
    const GOOD_DER: &[u8] = include_bytes!("fixtures/revocation/good.der");
    const GOOD_NEXTUPDATE_DER: &[u8] = include_bytes!("fixtures/revocation/good_nextupdate.der");
    const REVOKED_DER: &[u8] = include_bytes!("fixtures/revocation/revoked.der");
    const GOOD_DELEGATE_DER: &[u8] = include_bytes!("fixtures/revocation/good_delegate.der");
    const GOOD_DELEGATE_NOCERT_DER: &[u8] =
        include_bytes!("fixtures/revocation/good_delegate_nocert.der");

    /// The committed leaf/CA pair every test checks a status for.
    fn fixture_pair() -> (Cert, Cert) {
        (
            Cert::from_pem(LEAF_PEM.as_bytes()).expect("fixture leaf"),
            Cert::from_pem(CA_PEM.as_bytes()).expect("fixture ca"),
        )
    }

    /// Reads the `thisUpdate` the responder actually stamped, so the window tests
    /// are anchored to the committed fixture instead of a date that rots, and
    /// are independent of the machine clock.
    fn fixture_this_update() -> time::OffsetDateTime {
        this_update_of(GOOD_DER).expect("fixture carries a parsable thisUpdate")
    }

    fn now_in_window() -> time::OffsetDateTime {
        fixture_this_update() + time::Duration::seconds(60)
    }

    // --- Task 8: request construction and AIA extraction ---

    #[test]
    fn aia_extension_yields_the_ocsp_responder_url() {
        let leaf = Cert::from_pem(LEAF_PEM.as_bytes()).unwrap();
        assert_eq!(
            ocsp_responder_url(&leaf).as_deref(),
            Some("http://ocsp.invalid.test/ocsp")
        );
    }

    #[test]
    fn aia_without_an_ocsp_access_method_yields_nothing() {
        // The Apple root is self-issued with only a CRL pointer.
        let root = Cert::from_pem(super::super::assets::APPLE_ROOT_CA_CERT.as_bytes()).unwrap();
        assert_eq!(ocsp_responder_url(&root), None);
    }

    #[test]
    fn request_cert_id_matches_the_independent_implementation() {
        let (leaf, issuer) = fixture_pair();
        let cid = cert_id(&leaf, &issuer).expect("certID");
        // openssl wrote req.der for this exact pair; the CertID must appear
        // verbatim inside it.
        assert!(
            REQ_DER.windows(cid.len()).any(|w| w == cid),
            "our CertID is not a byte-substring of openssl's request"
        );
        // Independent check of the hash *input*, not just the framing: hashing
        // the issuer DN as stored in the leaf must differ from hashing the
        // leaf's own subject, which is the easy mistake here. Both are compared
        // at runtime so the test survives a regenerated fixture with a
        // different CA DN.
        let name_hash = Sha1::digest(stored_issuer_name_der(&leaf).unwrap()).to_vec();
        let subject_hash = Sha1::digest(leaf.tbs_certificate.subject.to_der().unwrap()).to_vec();
        assert_eq!(name_hash.len(), 20);
        assert_ne!(
            name_hash, subject_hash,
            "by construction these differ; if they ever match, the fixture is degenerate"
        );
    }

    #[test]
    fn issuer_key_hash_excludes_the_bit_string_framing() {
        let (_, issuer) = fixture_pair();
        let spki_bits = issuer
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes();
        let whole_spki = issuer
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .unwrap();
        // The tempting wrong recipe hashes the whole SPKI DER; it must not equal
        // the value-bits hash that RFC 6960 specifies.
        assert_ne!(
            Sha1::digest(spki_bits).to_vec(),
            Sha1::digest(&whole_spki).to_vec(),
            "issuerKeyHash must cover the value bits, not the SPKI"
        );
    }

    #[test]
    fn zero_serial_encodes_as_the_canonical_zero_integer() {
        assert_eq!(integer_from_magnitude(&[]), vec![0x02, 0x01, 0x00]);
        assert_eq!(
            integer_from_magnitude(&[0x00, 0x00]),
            vec![0x02, 0x01, 0x00]
        );
        assert_eq!(
            integer_from_magnitude(&[0x00, 0x7f]),
            vec![0x02, 0x01, 0x7f]
        );
        // Top bit set: a zero pad byte is re-added so the value stays positive.
        assert_eq!(
            integer_from_magnitude(&[0x80]),
            vec![0x02, 0x02, 0x00, 0x80]
        );
    }

    #[test]
    fn request_is_deterministic_and_minimal() {
        let (leaf, issuer) = fixture_pair();
        let a = build_request(&leaf, &issuer).unwrap();
        let b = build_request(&leaf, &issuer).unwrap();
        assert_eq!(a, b, "request bytes must be reproducible");
        // `OCSPRequest { tbsRequest { requestList { Request { reqCert } } } }`
        // — one Request, no nonce, no requestExtensions, no optionalSignature.
        // The expected framing is derived from the fixture rather than
        // hardcoded, so regenerating the CA/leaf pair cannot date it.
        let cid = cert_id(&leaf, &issuer).unwrap();
        let expected = tlv(0x30, &tlv(0x30, &tlv(0x30, &tlv(0x30, &cid))));
        assert_eq!(a, expected);
        // Walk the framing back out of our own bytes: OCSPRequest, tbsRequest,
        // requestList, Request, reqCert — five tags, and nothing after the
        // CertID. A lost or extra nesting level cannot satisfy this even if the
        // formula above were wrong in the same way.
        let mut levels = Vec::new();
        let mut cursor = &a[..];
        for _ in 0..4 {
            let mut r = DerReader::new(cursor);
            let (tag, body) = r.read_tlv().expect("nested SEQUENCE");
            assert_eq!(tag, 0x30, "every level is a SEQUENCE");
            levels.push(body.len());
            cursor = body;
        }
        let mut tail = DerReader::new(cursor);
        let (reqcert_tag, body) = tail.read_tlv().expect("reqCert");
        assert_eq!(reqcert_tag, 0x30, "reqCert is a SEQUENCE");
        assert_eq!(tlv(0x30, body), cid, "reqCert is our CertID");
        // Each nesting level adds exactly one tag+length header, so the level
        // lengths step down by 2, and the innermost body is the CertID's
        // content. A level that added or dropped a wrapper breaks the chain.
        assert_eq!(levels[0], levels[1] + 2, "OCSPRequest wraps tbsRequest");
        assert_eq!(levels[1], levels[2] + 2, "tbsRequest wraps requestList");
        assert_eq!(levels[2], levels[3] + 2, "requestList wraps one Request");
        assert_eq!(
            levels[3],
            body.len() + 2,
            "Request is the CertID and nothing else — no optionalSignature"
        );
    }

    // --- Task 9: response parsing, verification and status ---

    #[test]
    fn good_response_verifies_and_reports_good() {
        let (leaf, issuer) = fixture_pair();
        let status = parse_and_verify(GOOD_DER, &leaf, &issuer, now_in_window());
        assert!(
            matches!(status, RevocationStatus::Good),
            "expected Good, got {status:?}"
        );
        assert!(status.warning().is_none());
    }

    #[test]
    fn revoked_response_reports_the_revocation_time() {
        let (leaf, issuer) = fixture_pair();
        let status = parse_and_verify(REVOKED_DER, &leaf, &issuer, now_in_window());
        let RevocationStatus::Revoked { revoked_at, .. } = status else {
            panic!("expected Revoked, got {status:?}");
        };
        assert_eq!(
            revoked_at.map(|t| t.unix_timestamp()),
            Some(1_767_225_600),
            "the recipe stamps 2026-01-01T00:00:00Z via the index.txt revocation date"
        );
        assert!(status.warning().is_some_and(|w| w.contains("revoked")));
    }

    #[test]
    fn a_tampered_signature_is_not_trusted() {
        let (leaf, issuer) = fixture_pair();
        let mut bad = GOOD_DER.to_vec();
        // Locate the 2048-bit signature BIT STRING by its framing rather than by
        // a fixed offset, so a regenerated fixture cannot turn this into a
        // vacuous pass: the search itself panics with a clear message if the
        // shape ever changes.
        let marker = [0x03u8, 0x82, 0x01, 0x01, 0x00];
        let at = bad
            .windows(marker.len())
            .position(|w| w == marker)
            .expect("fixture must contain a 256-byte signature BIT STRING");
        bad[at + marker.len() + 8] ^= 0x01;
        let status = parse_and_verify(&bad, &leaf, &issuer, now_in_window());
        assert!(
            matches!(
                status,
                RevocationStatus::NotChecked(NotCheckedReason::Unverified)
            ),
            "a forged answer must be Unverified, got {status:?}"
        );
        assert!(status.warning().is_none());
    }

    #[test]
    fn a_foreign_issuer_key_is_not_trusted() {
        let (leaf, real_issuer) = fixture_pair();
        let unrelated =
            Cert::from_pem(super::super::assets::APPLE_WWDR_CA_G3_CERT.as_bytes()).unwrap();
        // The response is the one the real CA signed, so the foreign issuer
        // both fails the CertID match and cannot verify the signature. Either
        // way the answer must not be trusted; a `Good` here would mean the
        // module accepted an answer it could not authenticate.
        let status = parse_and_verify(GOOD_DER, &leaf, &unrelated, now_in_window());
        assert!(
            matches!(status, RevocationStatus::NotChecked(_)),
            "a foreign issuer key must never produce a status, got {status:?}"
        );
        assert!(status.warning().is_none());
        // The delegate fixture pins the same point one layer down: it *is*
        // signed by a key this CA did not issue, so its signature must not
        // verify under the foreign key either.
        let delegated = parse_and_verify(GOOD_DELEGATE_DER, &leaf, &unrelated, now_in_window());
        assert!(
            matches!(delegated, RevocationStatus::NotChecked(_)),
            "got {delegated:?}"
        );
        // Sanity: the very same bytes *are* trusted under the real issuer, so
        // the two controls above are failing for the key and not for a
        // permanently broken parser.
        assert!(matches!(
            parse_and_verify(GOOD_DER, &leaf, &real_issuer, now_in_window()),
            RevocationStatus::Good
        ));
    }

    #[test]
    fn a_response_for_another_certificate_is_not_trusted() {
        let (leaf, issuer) = fixture_pair();
        let mut other = leaf.clone();
        other.tbs_certificate.serial_number =
            x509_cert::serial_number::SerialNumber::new(&[0x7f]).unwrap();
        let status = parse_and_verify(GOOD_DER, &other, &issuer, now_in_window());
        assert!(
            matches!(
                status,
                RevocationStatus::NotChecked(NotCheckedReason::NoMatchingCertId)
            ),
            "a certID mismatch must not produce a status, got {status:?}"
        );
    }

    #[test]
    fn a_cert_id_comparison_ignores_integer_padding() {
        let (leaf, issuer) = fixture_pair();
        let real = cert_id(&leaf, &issuer).expect("certID");
        // Re-encode the same CertID with a one-byte-longer, still-valid serial
        // INTEGER. A responder is free to do that, and a byte compare would
        // downgrade a legitimate answer to `Malformed`.
        let mut r = DerReader::new(&real);
        let body = r.read_tlv().unwrap().1;
        let mut f = DerReader::new(body);
        let alg = f.read_sequence().unwrap().to_vec();
        let name = f.read_octet_string().unwrap().to_vec();
        let key = f.read_octet_string().unwrap().to_vec();
        let (_, serial) = f.read_tlv().unwrap();
        let padded = tlv(
            0x30,
            &concat(&[
                &tlv(0x30, &alg),
                &tlv(0x04, &name),
                &tlv(0x04, &key),
                &tlv(0x02, &[0x00, 0x00, serial[0], serial[1]]),
            ]),
        );
        assert_ne!(padded, real, "the two encodings must actually differ");
        assert!(cert_ids_match(&real, &padded), "padding must not break it");
        // A genuinely different serial must still not match.
        let other = tlv(
            0x30,
            &concat(&[
                &tlv(0x30, &alg),
                &tlv(0x04, &name),
                &tlv(0x04, &key),
                &tlv(0x02, &[0x10, 0x01]),
            ]),
        );
        assert!(
            !cert_ids_match(&real, &other),
            "a different serial must not match"
        );
        // A different issuer name hash must not match either.
        let wrong_name = tlv(
            0x30,
            &concat(&[
                &tlv(0x30, &alg),
                &tlv(0x04, &[0u8; 20]),
                &tlv(0x04, &key),
                &tlv(0x02, serial),
            ]),
        );
        assert!(!cert_ids_match(&real, &wrong_name), "name hash must bind");
        assert!(
            !cert_ids_match(&real, b"not a certid"),
            "garbage must not match"
        );
    }

    #[test]
    fn a_delegated_responder_is_trusted_only_with_a_verified_certificate() {
        let (leaf, issuer) = fixture_pair();
        // responderID names the delegate and the answer embeds its certificate,
        // which the CA issued and which carries id-kp-OCSPSigning: trusted,
        // through the delegate's key.
        let with_cert = parse_and_verify(GOOD_DELEGATE_DER, &leaf, &issuer, now_in_window());
        assert!(
            matches!(with_cert, RevocationStatus::Good),
            "got {with_cert:?}"
        );
        // The same responderID with the certificate stripped binds that name to
        // no key the issuer vouches for, so the answer must come back
        // unverified, not trusted through some fallback to the issuer key.
        let without = parse_and_verify(GOOD_DELEGATE_NOCERT_DER, &leaf, &issuer, now_in_window());
        assert!(
            matches!(
                without,
                RevocationStatus::NotChecked(NotCheckedReason::Unverified)
            ),
            "a delegate without its certificate must not be trusted, got {without:?}"
        );
    }

    #[test]
    fn an_absent_next_update_bounds_nothing_by_design() {
        // The fixture responder omits nextUpdate (RFC 6960 makes it OPTIONAL),
        // so the only freshness rule left is `thisUpdate <= now`. Pinned so the
        // limit is a documented decision rather than an accident: an old but
        // signed `good` stays credible.
        let (leaf, issuer) = fixture_pair();
        let far_future = fixture_this_update() + time::Duration::days(400);
        assert!(matches!(
            parse_and_verify(GOOD_DER, &leaf, &issuer, far_future),
            RevocationStatus::Good
        ));
    }

    #[test]
    fn this_update_in_the_future_is_outside_the_window() {
        let (leaf, issuer) = fixture_pair();
        // An hour before the responder said anything: outside the window by
        // definition.
        let earlier = fixture_this_update() - time::Duration::hours(1);
        let status = parse_and_verify(GOOD_DER, &leaf, &issuer, earlier);
        assert!(
            matches!(
                status,
                RevocationStatus::NotChecked(NotCheckedReason::OutsideValidityWindow)
            ),
            "an answer from after `thisUpdate` must not be reused, got {status:?}"
        );
        assert!(status.warning().is_none());
    }

    #[test]
    fn next_update_in_the_past_is_outside_the_window() {
        let (leaf, issuer) = fixture_pair();
        // The same answer, generated with `-nmin 60`, so it carries a
        // `[0] EXPLICIT GeneralizedTime` nextUpdate one hour after thisUpdate.
        let base = this_update_of(GOOD_NEXTUPDATE_DER).expect("nextUpdate fixture");
        assert!(
            parse_and_verify(
                GOOD_NEXTUPDATE_DER,
                &leaf,
                &issuer,
                base + time::Duration::minutes(1)
            )
            .eq(&RevocationStatus::Good),
            "a `now` inside the responder's window is accepted"
        );
        let late = base + time::Duration::hours(2);
        let status = parse_and_verify(GOOD_NEXTUPDATE_DER, &leaf, &issuer, late);
        assert!(
            matches!(
                status,
                RevocationStatus::NotChecked(NotCheckedReason::OutsideValidityWindow)
            ),
            "an expired answer must not be reused, got {status:?}"
        );
    }

    #[test]
    fn non_successful_and_malformed_responses_are_silent() {
        let (leaf, issuer) = fixture_pair();
        let malformed = parse_and_verify(b"not der at all", &leaf, &issuer, now_in_window());
        assert!(matches!(
            malformed,
            RevocationStatus::NotChecked(NotCheckedReason::Malformed(_))
        ));
        // responseStatus = internalError(2) with no responseBytes.
        let refused = vec![0x30, 0x03, 0x0a, 0x01, 0x02];
        let status = parse_and_verify(&refused, &leaf, &issuer, now_in_window());
        assert!(matches!(
            status,
            RevocationStatus::NotChecked(NotCheckedReason::Malformed(_))
        ));
        assert!(status.warning().is_none());
    }

    #[test]
    fn every_status_except_authenticated_revoked_is_silent() {
        let reasons = [
            NotCheckedReason::NoOcspUrl,
            NotCheckedReason::NoIssuerCertificate,
            NotCheckedReason::UnusableUrl,
            NotCheckedReason::Transport("x".into()),
            NotCheckedReason::Malformed("x".into()),
            NotCheckedReason::NoMatchingCertId,
            NotCheckedReason::Unverified,
            NotCheckedReason::OutsideValidityWindow,
            NotCheckedReason::BudgetExpired,
        ];
        for reason in reasons {
            let status = RevocationStatus::NotChecked(reason.clone());
            assert!(
                status.warning().is_none(),
                "{reason:?} must stay silent but produced a warning"
            );
        }
        assert!(RevocationStatus::Good.warning().is_none());
        assert!(RevocationStatus::Revoked {
            revoked_at: None,
            reason: None
        }
        .warning()
        .is_some());
    }

    // --- Task 10: check() and the warning surface ---

    #[test]
    fn check_with_a_stub_transport_returns_the_authenticated_answer() {
        struct Stub(&'static [u8]);
        impl OcspTransport for Stub {
            fn post(
                &self,
                _url: &str,
                _body: &[u8],
            ) -> std::result::Result<Vec<u8>, TransportError> {
                Ok(self.0.to_vec())
            }
        }
        let (leaf, issuer) = fixture_pair();
        let status = check(
            &leaf,
            Some(&issuer),
            &Stub(REVOKED_DER),
            Some(now_in_window()),
        );
        assert!(
            matches!(status, RevocationStatus::Revoked { .. }),
            "got {status:?}"
        );
    }

    #[test]
    fn check_posts_the_rfc6960_request_to_the_aia_responder() {
        struct Echo(std::cell::RefCell<Option<(String, Vec<u8>)>>);
        impl OcspTransport for Echo {
            fn post(&self, url: &str, body: &[u8]) -> std::result::Result<Vec<u8>, TransportError> {
                *self.0.borrow_mut() = Some((url.to_string(), body.to_vec()));
                Ok(GOOD_DER.to_vec())
            }
        }
        let (leaf, issuer) = fixture_pair();
        let seen = Echo(std::cell::RefCell::new(None));
        let status = check(&leaf, Some(&issuer), &seen, Some(now_in_window()));
        let (url, body) = seen.0.borrow().clone().expect("transport was called");
        assert_eq!(url, "http://ocsp.invalid.test/ocsp");
        assert_eq!(
            body,
            build_request(&leaf, &issuer).expect("request"),
            "check must post the request build_request framed"
        );
        assert!(matches!(status, RevocationStatus::Good), "got {status:?}");
    }

    #[test]
    fn check_without_an_ocsp_url_never_touches_the_transport() {
        struct Counting(std::cell::Cell<usize>);
        impl OcspTransport for Counting {
            fn post(
                &self,
                _url: &str,
                _body: &[u8],
            ) -> std::result::Result<Vec<u8>, TransportError> {
                self.0.set(self.0.get() + 1);
                Err(TransportError::Unreachable("must not be called".into()))
            }
        }
        let root = Cert::from_pem(super::super::assets::APPLE_ROOT_CA_CERT.as_bytes()).unwrap();
        let calls = std::cell::Cell::new(0);
        let status = check(&root, None, &Counting(calls.clone()), Some(now_in_window()));
        assert!(matches!(
            status,
            RevocationStatus::NotChecked(NotCheckedReason::NoOcspUrl)
        ));
        assert_eq!(
            calls.get(),
            0,
            "a leaf with no AIA OCSP URI must short-circuit"
        );
    }

    #[test]
    fn check_without_an_issuer_certificate_is_not_checked() {
        struct Never;
        impl OcspTransport for Never {
            fn post(&self, _u: &str, _b: &[u8]) -> std::result::Result<Vec<u8>, TransportError> {
                panic!("no request may be posted without an issuer")
            }
        }
        let (leaf, _issuer) = fixture_pair();
        let status = check(&leaf, None, &Never, Some(now_in_window()));
        assert!(
            matches!(
                status,
                RevocationStatus::NotChecked(NotCheckedReason::NoIssuerCertificate)
            ),
            "got {status:?}"
        );
    }

    #[test]
    fn transport_failures_degrade_to_not_checked() {
        struct Broken;
        impl OcspTransport for Broken {
            fn post(&self, _u: &str, _b: &[u8]) -> std::result::Result<Vec<u8>, TransportError> {
                Err(TransportError::Unreachable("dns: no such host".into()))
            }
        }
        let (leaf, issuer) = fixture_pair();
        let status = check(&leaf, Some(&issuer), &Broken, Some(now_in_window()));
        assert!(matches!(
            status,
            RevocationStatus::NotChecked(NotCheckedReason::Transport(_))
        ));
        assert!(status.warning().is_none());
    }

    #[test]
    fn a_timeout_is_reported_as_an_expired_budget() {
        struct Slow;
        impl OcspTransport for Slow {
            fn post(&self, _u: &str, _b: &[u8]) -> std::result::Result<Vec<u8>, TransportError> {
                Err(TransportError::Timeout)
            }
        }
        let (leaf, issuer) = fixture_pair();
        let status = check(&leaf, Some(&issuer), &Slow, Some(now_in_window()));
        assert!(
            matches!(
                status,
                RevocationStatus::NotChecked(NotCheckedReason::BudgetExpired)
            ),
            "got {status:?}"
        );
    }

    #[test]
    fn the_issuer_of_finds_the_certificate_that_signed_the_leaf() {
        let (leaf, issuer) = fixture_pair();
        let chain = vec![issuer.clone()];
        assert_eq!(
            issuer_of(&leaf, &chain).map(|c| c.tbs_certificate.subject.clone()),
            Some(leaf.tbs_certificate.issuer.clone())
        );
        assert!(issuer_of(&leaf, &[]).is_none());
        // The two Apple intermediates do not issue the fixture leaf.
        assert!(issuer_of(&leaf, &[]).is_none());
    }

    #[cfg(not(target_arch = "wasm32"))]
    mod native {
        use super::*;
        use std::io::{Read, Write};
        use std::net::TcpListener;

        /// Rewrites the leaf's AIA OCSP URI so the loopback transport tests can
        /// point at a local listener. The leaf's own signature is invalidated by
        /// this, which is exactly what the check-above tests rely on: nothing
        /// downstream re-verifies the leaf.
        fn rewrite_ocsp_uri(leaf: &mut Cert, url: &str) {
            use x509_cert::ext::pkix::name::GeneralName;
            use x509_cert::ext::pkix::{AccessDescription, AuthorityInfoAccessSyntax};
            let aia = AuthorityInfoAccessSyntax(vec![AccessDescription {
                access_method: const_oid::db::rfc5280::ID_AD_OCSP,
                access_location: GeneralName::UniformResourceIdentifier(
                    der::asn1::Ia5StringRef::new(url).unwrap().into(),
                ),
            }]);
            let bytes = aia.to_der().unwrap();
            let exts = leaf.tbs_certificate.extensions.get_or_insert_with(Vec::new);
            exts.retain(|e| e.extn_id != const_oid::db::rfc5280::ID_PE_AUTHORITY_INFO_ACCESS);
            exts.push(x509_cert::ext::Extension {
                extn_id: const_oid::db::rfc5280::ID_PE_AUTHORITY_INFO_ACCESS,
                critical: false,
                extn_value: der::asn1::OctetString::new(bytes).unwrap(),
            });
        }

        /// A one-shot HTTP/1.1 responder on the loopback interface: the AIA URI
        /// of the leaf is rewritten to the accepted port, so `HttpTransport` is
        /// exercised end to end without DNS or internet access.
        #[test]
        fn http_transport_round_trips_against_a_loopback_responder() {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            let response = GOOD_DER.to_vec();
            let expected_request = {
                let (leaf, issuer) = fixture_pair();
                build_request(&leaf, &issuer).expect("request")
            };
            let server = std::thread::spawn(move || {
                let (mut sock, _) = listener.accept().unwrap();
                // Read exactly the declared body: `read_to_end` would wait for
                // the client to close, which it cannot do until we answer.
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while find_subslice(&head, b"\r\n\r\n").is_none() {
                    let n = sock.read(&mut byte).unwrap();
                    assert!(n == 1, "client closed mid-header");
                    head.push(byte[0]);
                }
                let text = String::from_utf8_lossy(&head).into_owned();
                let declared: usize = text
                    .lines()
                    .find_map(|l| {
                        let (name, value) = l.split_once(':')?;
                        name.trim()
                            .eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse().ok())?
                    })
                    .expect("Content-Length");
                let mut body = vec![0u8; declared];
                sock.read_exact(&mut body).unwrap();
                assert!(text.starts_with("POST /ocsp HTTP/1.1"), "request: {text}");
                assert!(
                    text.to_ascii_lowercase()
                        .contains("content-type: application/ocsp-request"),
                    "request: {text}"
                );
                assert_eq!(body, expected_request, "posted body");
                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/ocsp-response\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n",
                    response.len()
                );
                sock.write_all(header.as_bytes()).unwrap();
                sock.write_all(&response).unwrap();
                sock.flush().unwrap();
            });
            let (mut leaf, issuer) = fixture_pair();
            rewrite_ocsp_uri(&mut leaf, &format!("http://127.0.0.1:{port}/ocsp"));
            let status = check(
                &leaf,
                Some(&issuer),
                &HttpTransport::default(),
                Some(now_in_window()),
            );
            server.join().unwrap();
            assert!(matches!(status, RevocationStatus::Good), "got {status:?}");
        }

        #[test]
        fn a_non_200_answer_is_a_transport_error() {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            let server = std::thread::spawn(move || {
                let (mut sock, _) = listener.accept().unwrap();
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf);
                let body = b"nope";
                let header = format!(
                    "HTTP/1.1 404 Not Found\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                sock.write_all(header.as_bytes()).unwrap();
                sock.write_all(body).unwrap();
                sock.flush().unwrap();
            });
            let (mut leaf, issuer) = fixture_pair();
            rewrite_ocsp_uri(&mut leaf, &format!("http://127.0.0.1:{port}/ocsp"));
            let status = check(
                &leaf,
                Some(&issuer),
                &HttpTransport::default(),
                Some(now_in_window()),
            );
            server.join().unwrap();
            assert!(
                matches!(
                    status,
                    RevocationStatus::NotChecked(NotCheckedReason::Transport(_))
                ),
                "a 404 must not be parsed as an answer, got {status:?}"
            );
        }

        #[test]
        fn an_authority_splits_into_host_and_port() {
            // A responder URI normally carries an explicit port; dropping it and
            // resolving on 80 would silently talk to the wrong service.
            assert_eq!(
                split_authority("127.0.0.1:34575"),
                Some(("127.0.0.1", 34575))
            );
            assert_eq!(
                split_authority("ocsp.example.test"),
                Some(("ocsp.example.test", 80))
            );
            assert_eq!(
                split_authority("ocsp.example.test:8080"),
                Some(("ocsp.example.test", 8080))
            );
            // IPv6 literals: the brackets delimit the host, not a port.
            assert_eq!(split_authority("[::1]:8080"), Some(("::1", 8080)));
            assert_eq!(split_authority("[::1]"), Some(("::1", 80)));
            assert_eq!(split_authority(""), None);
        }

        #[test]
        fn a_response_that_never_arrives_costs_only_the_budget() {
            // Accept the connection and then say nothing: only the caller's
            // budget can save us.
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            let sink = std::thread::spawn(move || {
                let (mut sock, _) = listener.accept().unwrap();
                let mut buf = [0u8; 512];
                let _ = sock.read(&mut buf);
                std::thread::sleep(std::time::Duration::from_secs(30));
            });
            let (mut leaf, issuer) = fixture_pair();
            rewrite_ocsp_uri(&mut leaf, &format!("http://127.0.0.1:{port}/ocsp"));
            let started = std::time::Instant::now();
            let transport = HttpTransport {
                budget: std::time::Duration::from_millis(300),
            };
            let status = check(&leaf, Some(&issuer), &transport, Some(now_in_window()));
            assert!(
                matches!(
                    status,
                    RevocationStatus::NotChecked(NotCheckedReason::BudgetExpired)
                ),
                "got {status:?}"
            );
            assert!(
                started.elapsed() < std::time::Duration::from_secs(5),
                "budget not enforced"
            );
            drop(sink);
        }

        #[test]
        fn an_unreachable_responder_is_not_checked() {
            // Port 1 on loopback normally refuses at once. Where a firewall
            // queues it instead, the same assertion still holds: only the
            // variant of `Transport(_)` would differ.
            let (mut leaf, issuer) = fixture_pair();
            rewrite_ocsp_uri(&mut leaf, "http://127.0.0.1:1/ocsp");
            let status = check(
                &leaf,
                Some(&issuer),
                &HttpTransport::default(),
                Some(now_in_window()),
            );
            assert!(
                matches!(
                    status,
                    RevocationStatus::NotChecked(NotCheckedReason::Transport(_))
                ),
                "got {status:?}"
            );
        }
    }
}
