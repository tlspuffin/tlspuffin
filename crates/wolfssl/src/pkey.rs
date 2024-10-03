use std::mem;

use foreign_types::{foreign_type, ForeignType};
use wolfssl_sys as wolf;

use crate::error::ErrorStack;
use crate::rsa::Rsa;
use crate::util::{cvt, cvt_p};

/// A tag type indicating that a key only has public components.
pub enum Public {}

/// A tag type indicating that a key has private components.
pub enum Private {}

/// A trait indicating that a key has public components.
pub unsafe trait HasPublic {}

unsafe impl HasPublic for Public {}

unsafe impl<T> HasPublic for T where T: HasPrivate {}

/// A trait indicating that a key has private components.
pub unsafe trait HasPrivate {}

unsafe impl HasPrivate for Private {}

foreign_type! {
    pub unsafe type PKey<T>: Sync + Send {
        type CType = wolf::WOLFSSL_EVP_PKEY;
        type PhantomData = T;
        fn drop = wolf::wolfSSL_EVP_PKEY_free;
    }
}

impl PKey<Private> {
    /// Creates a new `PKey` containing an RSA key.
    ///
    /// This corresponds to [`EVP_PKEY_assign_RSA`].
    ///
    /// [`EVP_PKEY_assign_RSA`]: https://www.openssl.org/docs/man1.1.0/crypto/EVP_PKEY_assign_RSA.html
    pub fn from_rsa(rsa: Rsa<Private>) -> Result<PKey<Private>, ErrorStack> {
        unsafe {
            let evp = cvt_p(wolf::wolfSSL_EVP_PKEY_new())?;
            let pkey = PKey::from_ptr(evp);

            cvt(wolf::wolfSSL_EVP_PKEY_assign_RSA(
                pkey.0.as_ptr(),
                rsa.as_ptr() as *mut _,
            ))?;
            mem::forget(rsa);
            Ok(pkey)
        }
    }
}
