use foreign_types::foreign_type;
use wolfssl_sys as wolf;

use crate::{bio::MemBioSlice, error::ErrorStack, pkey::Private, util::cvt_p};

foreign_type! {
    pub unsafe type Rsa<T>: Sync + Send {
        type CType = wolf::WOLFSSL_RSA;
        type PhantomData = T;
        fn drop = wolf::wolfSSL_RSA_free;
    }
}

impl Rsa<Private> {
    pub fn private_key_from_pem(pem: &[u8]) -> Result<Rsa<Private>, ErrorStack> {
        unsafe {
            let bio = MemBioSlice::new(pem)?;
            cvt_p(wolf::wolfSSL_PEM_read_bio_RSAPrivateKey(
                bio.as_ptr(),
                ::std::ptr::null_mut(),
                None,
                ::std::ptr::null_mut(),
            ))
            .map(|p| ::foreign_types::ForeignType::from_ptr(p))
        }
    }
}
