use foreign_types::foreign_type;
use wolfssl_sys as wolf;

use crate::wolfssl::{bio::MemBioSlice, error::ErrorStack, util::cvt_p};

foreign_type! {
    pub unsafe type X509: Sync + Send {
        type CType = wolf::WOLFSSL_X509;
        fn drop = wolf::wolfSSL_X509_free;
    }
}

impl X509 {
    pub fn from_pem(pem: &[u8]) -> Result<X509, ErrorStack> {
        unsafe {
            let bio = MemBioSlice::new(pem)?;
            cvt_p(wolf::wolfSSL_PEM_read_bio_X509(
                bio.as_ptr(),
                ::std::ptr::null_mut(),
                None,
                ::std::ptr::null_mut(),
            ))
            .map(|p| ::foreign_types::ForeignType::from_ptr(p))
        }
    }
}
