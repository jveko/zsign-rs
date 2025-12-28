//! Raw FFI bindings for OpenSSL CMS functions not exposed by rust-openssl

use openssl_sys::*;
use std::ffi::{c_int, c_uint, c_void};

// CMS_SignerInfo is opaque - we only need pointer
#[repr(C)]
pub struct CMS_SignerInfo {
    _private: [u8; 0],
}

// Stack of CMS_SignerInfo
#[repr(C)]
pub struct stack_st_CMS_SignerInfo {
    _private: [u8; 0],
}

// CMS flags (defined here to ensure correct values for our use case)
pub const CMS_PARTIAL: u32 = 0x4000;
pub const CMS_DETACHED: u32 = 0x40;
pub const CMS_BINARY: u32 = 0x80;
pub const CMS_NOSMIMECAP: u32 = 0x200;

extern "C" {
    pub fn CMS_sign(
        signcert: *mut X509,
        pkey: *mut EVP_PKEY,
        certs: *mut stack_st_X509,
        data: *mut BIO,
        flags: c_uint,
    ) -> *mut CMS_ContentInfo;

    pub fn CMS_add1_signer(
        cms: *mut CMS_ContentInfo,
        signer: *mut X509,
        pk: *mut EVP_PKEY,
        md: *const EVP_MD,
        flags: c_uint,
    ) -> *mut CMS_SignerInfo;

    pub fn CMS_final(
        cms: *mut CMS_ContentInfo,
        data: *mut BIO,
        dcont: *mut BIO,
        flags: c_uint,
    ) -> c_int;

    pub fn CMS_get0_SignerInfos(cms: *mut CMS_ContentInfo) -> *mut stack_st_CMS_SignerInfo;

    pub fn CMS_signed_add1_attr_by_OBJ(
        si: *mut CMS_SignerInfo,
        obj: *const ASN1_OBJECT,
        type_: c_int,
        bytes: *const c_void,
        len: c_int,
    ) -> c_int;

    pub fn sk_CMS_SignerInfo_num(sk: *const stack_st_CMS_SignerInfo) -> c_int;

    pub fn sk_CMS_SignerInfo_value(
        sk: *const stack_st_CMS_SignerInfo,
        idx: c_int,
    ) -> *mut CMS_SignerInfo;

    // Add certificate to CMS
    pub fn CMS_add1_cert(cms: *mut CMS_ContentInfo, cert: *mut X509) -> c_int;

    // Sign signer info (sets signatureAlgorithm properly)
    pub fn CMS_SignerInfo_sign(si: *mut CMS_SignerInfo) -> c_int;

    // STACK_OF(X509) functions for building certificate chains
    // These are needed to pass certs to CMS_sign() like C++ zsign does
    // In OpenSSL 3, sk_X509_* are macros that wrap OPENSSL_sk_* functions
    #[link_name = "OPENSSL_sk_new_null"]
    pub fn sk_X509_new_null() -> *mut stack_st_X509;
    #[link_name = "OPENSSL_sk_push"]
    pub fn sk_X509_push(sk: *mut stack_st_X509, x509: *mut X509) -> c_int;
    #[link_name = "OPENSSL_sk_free"]
    pub fn sk_X509_free(sk: *mut stack_st_X509);
}

// Apple OIDs for code signing
pub const APPLE_CDHASH_OID: &str = "1.2.840.113635.100.9.1";
pub const APPLE_CDHASH_V2_OID: &str = "1.2.840.113635.100.9.2";
