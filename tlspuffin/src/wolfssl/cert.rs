use std::ptr;

use wolfssl_sys as wolf;

use crate::{
    static_certs::{CERT, PRIVATE_KEY},
    wolfssl::{bio::MemBioSlice, error::ErrorStack},
};

pub struct X509;

impl X509 {}

pub unsafe fn parse_rsa_key() -> Result<*mut wolf::WOLFSSL_EVP_PKEY, ErrorStack> {
    let bio = MemBioSlice::new(PRIVATE_KEY.as_bytes())?;
    // Read pem from bio
    let rsa = wolf::wolfSSL_PEM_read_bio_RSAPrivateKey(
        bio.as_ptr(),
        ptr::null_mut(),
        None,
        ptr::null_mut(),
    );

    let evp = wolf::wolfSSL_EVP_PKEY_new();
    wolf::wolfSSL_EVP_PKEY_assign_RSA(evp, rsa as *mut _);
    Ok(evp)
}
pub unsafe fn parse_cert() -> Result<*mut wolf::WOLFSSL_X509, ErrorStack> {
    let bio = MemBioSlice::new(CERT.as_bytes())?;

    let cert =
        wolf::wolfSSL_PEM_read_bio_X509(bio.as_ptr(), ptr::null_mut(), None, ptr::null_mut());
    Ok(cert)
}
