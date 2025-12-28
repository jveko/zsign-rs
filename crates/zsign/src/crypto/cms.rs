//! Safe wrapper for CMS signing with Apple custom attributes

use crate::{Error, Result};
use openssl::pkey::{PKeyRef, Private};
use openssl::x509::{X509, X509Ref};
use openssl_sys::{
    ASN1_OBJECT_free, BIO, BIO_new, BIO_new_mem_buf, BIO_s_mem, CMS_ContentInfo,
    CMS_ContentInfo_free, EVP_sha256, OBJ_txt2obj, X509 as X509_sys, EVP_PKEY,
};
use std::ffi::c_int;
use std::ptr;

use super::assets::{
    APPLE_ROOT_CA_CERT, APPLE_WWDR_CA_CERT, APPLE_WWDR_CA_G3_CERT,
    APPLE_WWDR_ISSUER_HASH, APPLE_WWDR_G3_ISSUER_HASH,
};
use super::cms_ffi::{
    CMS_SignerInfo, CMS_add1_signer, CMS_final, CMS_sign,
    CMS_signed_add1_attr_by_OBJ, CMS_add1_cert,
    APPLE_CDHASH_V2_OID,
};

// Use the constants from cms_ffi to avoid ambiguity
use super::cms_ffi::{CMS_BINARY, CMS_DETACHED, CMS_NOSMIMECAP, CMS_PARTIAL};

// BIO functions that need to be declared
extern "C" {
    fn BIO_free(a: *mut BIO) -> c_int;
    fn BIO_ctrl(bp: *mut BIO, cmd: c_int, larg: isize, parg: *mut std::ffi::c_void) -> isize;
    fn i2d_CMS_bio(bio: *mut BIO, cms: *mut CMS_ContentInfo) -> c_int;
}

// BIO_CTRL constants
const BIO_CTRL_RESET: c_int = 1;
const BIO_CTRL_INFO: c_int = 3;

// Helper functions for BIO operations
unsafe fn bio_reset(bio: *mut BIO) -> c_int {
    BIO_ctrl(bio, BIO_CTRL_RESET, 0, ptr::null_mut()) as c_int
}

unsafe fn bio_get_mem_data(bio: *mut BIO, pp: *mut *mut u8) -> isize {
    BIO_ctrl(bio, BIO_CTRL_INFO, 0, pp as *mut std::ffi::c_void)
}

/// Get raw X509 pointer from X509Ref
///
/// # Safety
/// The returned pointer is only valid as long as the X509Ref is valid.
unsafe fn x509_as_ptr(x509: &X509Ref) -> *mut X509_sys {
    // X509Ref contains a reference to the underlying X509 structure
    // We need to cast through the reference to get the raw pointer
    x509 as *const X509Ref as *const X509_sys as *mut X509_sys
}

/// Get raw EVP_PKEY pointer from PKeyRef
///
/// # Safety
/// The returned pointer is only valid as long as the PKeyRef is valid.
unsafe fn pkey_as_ptr(pkey: &PKeyRef<Private>) -> *mut EVP_PKEY {
    pkey as *const PKeyRef<Private> as *const EVP_PKEY as *mut EVP_PKEY
}

/// Get the Apple CA certificates for the CMS signature chain.
///
/// Returns a vector containing:
/// 1. The appropriate Apple WWDR CA (based on the signing certificate's issuer hash)
/// 2. The Apple Root CA
///
/// This matches the behavior of C++ zsign which hardcodes these certificates
/// and adds them to the CMS signature chain automatically.
fn get_apple_ca_chain(cert: &X509Ref) -> Result<Vec<X509>> {
    // Use OpenSSL's X509_issuer_name_hash directly to match C++ zsign
    extern "C" {
        fn X509_issuer_name_hash(x: *const openssl_sys::X509) -> std::ffi::c_ulong;
    }

    let issuer_hash = unsafe {
        X509_issuer_name_hash(x509_as_ptr(cert))
    } as u32;

    // Select the appropriate WWDR certificate based on issuer hash
    let wwdr_cert = if issuer_hash == APPLE_WWDR_ISSUER_HASH {
        X509::from_pem(APPLE_WWDR_CA_CERT.as_bytes())
    } else if issuer_hash == APPLE_WWDR_G3_ISSUER_HASH {
        X509::from_pem(APPLE_WWDR_CA_G3_CERT.as_bytes())
    } else {
        // Unknown issuer - this may be a self-signed or ad-hoc certificate
        // In this case, skip adding Apple CA chain (same as C++ zsign behavior)
        return Ok(Vec::new());
    }.map_err(|e| Error::Signing(format!("Failed to parse Apple WWDR CA: {}", e)))?;

    let root_cert = X509::from_pem(APPLE_ROOT_CA_CERT.as_bytes())
        .map_err(|e| Error::Signing(format!("Failed to parse Apple Root CA: {}", e)))?;

    Ok(vec![wwdr_cert, root_cert])
}

/// Generate CMS signature with Apple CDHash attributes
///
/// # Arguments
///
/// * `data` - The data to sign (CodeDirectory blob)
/// * `cert` - The signing certificate
/// * `pkey` - The private key
/// * `cert_chain` - Optional certificate chain (intermediate CAs)
/// * `cdhash_sha1` - SHA-1 CDHash for Apple attribute
/// * `cdhash_sha256` - SHA-256 CDHash for Apple attribute
///
/// # Apple CA Chain
///
/// This function automatically adds the Apple WWDR and Root CA certificates
/// to the CMS signature chain, matching the behavior of C++ zsign. The
/// appropriate WWDR CA is selected based on the signing certificate's issuer.
pub fn sign_with_apple_attrs(
    data: &[u8],
    cert: &X509Ref,
    pkey: &PKeyRef<Private>,
    cert_chain: &[X509],
    cdhash_sha1: &[u8; 20],
    cdhash_sha256: &[u8; 32],
) -> Result<Vec<u8>> {
    // Get Apple CA chain (WWDR + Root CA) based on the signing certificate's issuer
    let apple_ca_chain = get_apple_ca_chain(cert)?;

    unsafe {
        // Create BIO for data
        let bio = BIO_new_mem_buf(data.as_ptr() as *const _, data.len() as c_int);
        if bio.is_null() {
            return Err(Error::Signing("Failed to create BIO".into()));
        }

        // Create CMS with PARTIAL flag to add attributes later
        // With CMS_PARTIAL, we use CMS_add1_cert to add certificates explicitly
        // (the cert stack passed to CMS_sign doesn't work with PARTIAL flag)
        let flags = CMS_PARTIAL | CMS_DETACHED | CMS_BINARY | CMS_NOSMIMECAP;
        let cms = CMS_sign(
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(), // Don't use cert stack with CMS_PARTIAL
            ptr::null_mut(),
            flags,
        );
        if cms.is_null() {
            BIO_free(bio);
            return Err(Error::Signing("CMS_sign failed".into()));
        }

        // Add signer with SHA256
        let cert_ptr = x509_as_ptr(cert);
        let pkey_ptr = pkey_as_ptr(pkey);

        let signer_info = CMS_add1_signer(cms, cert_ptr, pkey_ptr, EVP_sha256(), flags);
        if signer_info.is_null() {
            CMS_ContentInfo_free(cms);
            BIO_free(bio);
            return Err(Error::Signing("CMS_add1_signer failed".into()));
        }

        // Add certificates to CMS using CMS_add1_cert
        // This is required when using CMS_PARTIAL flag
        // Order: Apple CA chain first (WWDR + Root), then signing cert
        
        // Add Apple CA chain (WWDR CA + Root CA)
        for apple_cert in &apple_ca_chain {
            let apple_cert_ptr = x509_as_ptr(apple_cert.as_ref());
            if CMS_add1_cert(cms, apple_cert_ptr) != 1 {
                CMS_ContentInfo_free(cms);
                BIO_free(bio);
                return Err(Error::Signing("Failed to add Apple CA to CMS".into()));
            }
        }

        // Add user-provided certificate chain (intermediate CAs)
        for chain_cert in cert_chain {
            let chain_cert_ptr = x509_as_ptr(chain_cert.as_ref());
            if CMS_add1_cert(cms, chain_cert_ptr) != 1 {
                CMS_ContentInfo_free(cms);
                BIO_free(bio);
                return Err(Error::Signing("Failed to add cert chain to CMS".into()));
            }
        }

        // Add the signing certificate itself
        // CMS_add1_signer adds the cert to signerInfos but NOT to the certificates field
        if CMS_add1_cert(cms, cert_ptr) != 1 {
            CMS_ContentInfo_free(cms);
            BIO_free(bio);
            return Err(Error::Signing("Failed to add signing cert to CMS".into()));
        }

        // Add Apple CDHash v1 attribute (OID 1.2.840.113635.100.9.1)
        // This contains the plist with cdhashes array
        let cdhash_plist = build_cdhash_plist(cdhash_sha1, cdhash_sha256);
        add_apple_attribute(signer_info, super::cms_ffi::APPLE_CDHASH_OID, &cdhash_plist)?;

        // Add Apple CDHash v2 attribute (OID 1.2.840.113635.100.9.2)
        // This contains a SEQUENCE with AlgorithmIdentifier + hash
        let cdhash_v2_value = build_cdhash_v2_attribute(cdhash_sha256);
        add_apple_attribute_sequence(signer_info, APPLE_CDHASH_V2_OID, &cdhash_v2_value)?;

        // Finalize CMS
        bio_reset(bio);
        if CMS_final(cms, bio, ptr::null_mut(), flags) != 1 {
            CMS_ContentInfo_free(cms);
            BIO_free(bio);
            return Err(Error::Signing("CMS_final failed".into()));
        }

        // Serialize to DER
        let out_bio = BIO_new(BIO_s_mem());
        if out_bio.is_null() {
            CMS_ContentInfo_free(cms);
            BIO_free(bio);
            return Err(Error::Signing("Failed to create output BIO".into()));
        }

        if i2d_CMS_bio(out_bio, cms) != 1 {
            CMS_ContentInfo_free(cms);
            BIO_free(bio);
            BIO_free(out_bio);
            return Err(Error::Signing("Failed to serialize CMS".into()));
        }

        // Read DER data
        let mut buf_ptr: *mut u8 = ptr::null_mut();
        let len = bio_get_mem_data(out_bio, &mut buf_ptr);
        let der = std::slice::from_raw_parts(buf_ptr, len as usize).to_vec();

        // Cleanup
        CMS_ContentInfo_free(cms);
        BIO_free(bio);
        BIO_free(out_bio);

        Ok(der)
    }
}

/// Build CDHash plist for Apple attribute
///
/// Creates an XML plist with a "cdhashes" array containing SHA-1 and SHA-256 CDHashes.
/// Both hashes are 20 bytes (SHA-256 is truncated to match SHA-1 length).
/// This is used for the Apple CDHash v1 attribute (OID 1.2.840.113635.100.9.1).
pub fn build_cdhash_plist(sha1: &[u8; 20], sha256: &[u8; 32]) -> Vec<u8> {
    use plist::{Dictionary, Value};

    let mut dict = Dictionary::new();
    dict.insert(
        "cdhashes".to_string(),
        Value::Array(vec![
            // SHA-1 CDHash (20 bytes)
            Value::Data(sha1.to_vec()),
            // SHA-256 CDHash truncated to 20 bytes (matches zsign behavior)
            Value::Data(sha256[..20].to_vec()),
        ]),
    );

    let mut buf = Vec::new();
    plist::to_writer_xml(&mut buf, &Value::Dictionary(dict))
        .expect("plist serialization failed");
    // Add trailing newline to match C++ zsign behavior
    // C++ zsign json.cpp:3263: m_strdoc += "</plist>" + m_line; (m_line = "\n")
    buf.push(b'\n');
    buf
}

/// Build the CDHash v2 attribute value.
///
/// This creates a DER-encoded SEQUENCE containing:
/// - OBJECT IDENTIFIER for SHA-256 (2.16.840.1.101.3.4.2.1)
/// - OCTET STRING containing the 32-byte SHA-256 CDHash
///
/// Format: SEQUENCE { OBJECT sha256, OCTET STRING hash }
/// This matches the format used by Apple's codesign and zsign.
fn build_cdhash_v2_attribute(cdhash_sha256: &[u8; 32]) -> Vec<u8> {
    // SHA-256 OID: 2.16.840.1.101.3.4.2.1
    // DER encoded: 60 86 48 01 65 03 04 02 01
    let sha256_oid: [u8; 9] = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
    
    // Build OBJECT IDENTIFIER for sha256
    let mut oid = Vec::new();
    oid.push(0x06); // OBJECT IDENTIFIER tag
    oid.push(sha256_oid.len() as u8);
    oid.extend_from_slice(&sha256_oid);
    
    // Build OCTET STRING with CDHash
    let mut hash_octet = Vec::new();
    hash_octet.push(0x04); // OCTET STRING tag
    hash_octet.push(cdhash_sha256.len() as u8);
    hash_octet.extend_from_slice(cdhash_sha256);
    
    // Wrap both in outer SEQUENCE: SEQUENCE { OBJECT, OCTET STRING }
    let inner_len = oid.len() + hash_octet.len();
    let mut result = Vec::new();
    result.push(0x30); // SEQUENCE tag
    result.push(inner_len as u8);
    result.extend_from_slice(&oid);
    result.extend_from_slice(&hash_octet);
    
    result
}

/// Add Apple custom attribute to signer info as OCTET STRING
///
/// Helper function to add attributes with custom OIDs to the CMS signer info.
/// Used for Apple-specific code signing attributes like CDHash.
unsafe fn add_apple_attribute(
    signer_info: *mut CMS_SignerInfo,
    oid: &str,
    data: &[u8],
) -> Result<()> {
    // Create ASN1_OBJECT from OID string
    let oid_cstr =
        std::ffi::CString::new(oid).map_err(|_| Error::Signing("Invalid OID string".into()))?;

    let obj = OBJ_txt2obj(oid_cstr.as_ptr(), 1);
    if obj.is_null() {
        return Err(Error::Signing(format!("Failed to create OID: {}", oid)));
    }

    // V_ASN1_OCTET_STRING = 4
    let ret = CMS_signed_add1_attr_by_OBJ(
        signer_info,
        obj,
        4, // V_ASN1_OCTET_STRING
        data.as_ptr() as *const _,
        data.len() as i32,
    );

    ASN1_OBJECT_free(obj);

    if ret != 1 {
        return Err(Error::Signing("Failed to add Apple attribute".into()));
    }
    Ok(())
}

/// Add Apple custom attribute to signer info as SEQUENCE
///
/// This is used for CDHash v2 which requires a pre-encoded SEQUENCE value.
unsafe fn add_apple_attribute_sequence(
    signer_info: *mut CMS_SignerInfo,
    oid: &str,
    data: &[u8],
) -> Result<()> {
    let oid_cstr =
        std::ffi::CString::new(oid).map_err(|_| Error::Signing("Invalid OID string".into()))?;

    let obj = OBJ_txt2obj(oid_cstr.as_ptr(), 1);
    if obj.is_null() {
        return Err(Error::Signing(format!("Failed to create OID: {}", oid)));
    }

    // V_ASN1_SEQUENCE = 16
    let ret = CMS_signed_add1_attr_by_OBJ(
        signer_info,
        obj,
        16, // V_ASN1_SEQUENCE
        data.as_ptr() as *const _,
        data.len() as i32,
    );

    ASN1_OBJECT_free(obj);

    if ret != 1 {
        return Err(Error::Signing("Failed to add Apple SEQUENCE attribute".into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_cdhash_plist() {
        let sha1 = [0u8; 20];
        let sha256 = [0u8; 32];
        let plist = build_cdhash_plist(&sha1, &sha256);

        assert!(!plist.is_empty());
        let plist_str = String::from_utf8_lossy(&plist);
        assert!(plist_str.contains("cdhashes"));
        assert!(plist_str.contains("<array>"));
        assert!(plist_str.contains("<data>"));
    }

    #[test]
    fn test_build_cdhash_plist_with_real_hashes() {
        // Test with actual hash values
        let sha1: [u8; 20] = [
            0x2f, 0xd4, 0xe1, 0xc6, 0x7a, 0x2d, 0x28, 0xfc, 0xed, 0x84, 0x9e, 0xe1, 0xbb, 0x76,
            0xe7, 0x39, 0x1b, 0x93, 0xeb, 0x12,
        ];
        let sha256: [u8; 32] = [
            0xd7, 0xa8, 0xfb, 0xb3, 0x07, 0xd7, 0x80, 0x94, 0x69, 0xca, 0x9a, 0xbc, 0xb0, 0x08,
            0x2e, 0x4f, 0x8d, 0x56, 0x51, 0xe4, 0x6d, 0x3c, 0xdb, 0x76, 0x2d, 0x02, 0xd0, 0xbf,
            0x37, 0xc9, 0xe5, 0x92,
        ];

        let plist = build_cdhash_plist(&sha1, &sha256);

        // Parse the plist back to verify structure
        let parsed: plist::Value = plist::from_bytes(&plist).unwrap();
        let dict = parsed.as_dictionary().unwrap();
        let cdhashes = dict.get("cdhashes").unwrap().as_array().unwrap();

        assert_eq!(cdhashes.len(), 2);
        assert_eq!(cdhashes[0].as_data().unwrap(), sha1);
        // SHA-256 is truncated to 20 bytes in the plist (matches zsign behavior)
        assert_eq!(cdhashes[1].as_data().unwrap(), &sha256[..20]);
    }
}
