use std::io::{ErrorKind, Read, Write};
use std::marker::PhantomData;
use std::mem::ManuallyDrop;
use std::os::raw::c_int;

use openssl::error::ErrorStack;
use openssl::ssl::{SslContextBuilder, SslVersion};
use openssl::{
    asn1::Asn1Time,
    bn::{BigNum, MsbOption},
    hash::MessageDigest,
    pkey::{PKey, PKeyRef, Private},
    version::version,
    x509::{
        extension::{BasicConstraints, KeyUsage, SubjectKeyIdentifier},
        X509NameBuilder, X509Ref, X509,
    },
};

use crate::agent::TLSVersion;
use crate::error::Error;
use crate::io::MemoryStream;
use crate::openssl_binding::static_rsa_cert;
use wolfssl_sys as wolf;

// Ssl: a pointer to a Wolfssl pointer
pub struct Ssl(*mut wolfssl_sys::WOLFSSL);
impl Ssl {
    #[inline]
    unsafe fn from_ptr(ptr: *mut wolf::WOLFSSL) -> Ssl {
        Ssl(ptr)
    }

    #[inline]
    fn as_ptr(&self) -> *mut wolf::WOLFSSL {
        self.0
    }
}
impl Drop for Ssl {
    #[inline]
    fn drop(&mut self) {
        unsafe { wolf::wolfSSL_free(self.0) }
    }
}
/// A TLS session over a stream.
pub struct SslStream<S> {
    ssl: ManuallyDrop<Ssl>,
    method: ManuallyDrop<wolf::WOLFSSL_BIO_METHOD>,
    _p: PhantomData<S>,
}
impl<S: Read + Write> SslStream<S> {
    /// Creates a new `SslStream`.
    ///
    /// This function performs no IO; the stream will not have performed any part of the handshake
    /// with the peer. If the `Ssl` was configured with [`SslRef::set_connect_state`] or
    /// [`SslRef::set_accept_state`], the handshake can be performed automatically during the first
    /// call to read or write. Otherwise the `connect` and `accept` methods can be used to
    /// explicitly perform the handshake.
    ///
    /// This corresponds to [`SSL_set_bio`].
    ///
    /// [`SSL_set_bio`]: https://www.openssl.org/docs/manmaster/man3/SSL_set_bio.html
    pub fn new(ssl: Ssl, stream: S) -> Result<Self, ErrorStack> {
        todo!()
        /* [TODO] Currently failing attempt:
            let (bio, method) = wolf::wolfSSL_BIO_new(stream)?;
        unsafe {
            wolf::wolfSSL_set_bio(ssl.as_ptr(), bio, bio);
        }
        Ok(SslStream {
            ssl: ManuallyDrop::new(ssl),
            method: ManuallyDrop::new(method),
            _p: PhantomData,
        })
        */
    }
}
/*  [TODO] Copied pasted from openssl_binding:
pub fn create_openssl_client(
    stream: MemoryStream,
    tls_version: &TLSVersion,
) -> Result<SslStream<MemoryStream>, ErrorStack> {
    let mut ctx_builder = SslContext::builder(SslMethod::tls())?;
    // Not sure whether we want this disabled or enabled: https://gitlab.inria.fr/mammann/tlspuffin/-/issues/26
    // The tests become simpler if disabled to maybe that's what we want. Lets leave it default
    // for now.
    // https://wiki.openssl.org/index.php/TLS1.3#Middlebox_Compatibility_Mode
    #[cfg(feature = "openssl111")]
    ctx_builder.clear_options(SslOptions::ENABLE_MIDDLEBOX_COMPAT);

    set_max_protocol_version(&mut ctx_builder, tls_version)?;

    // Disallow EXPORT in client
    ctx_builder.set_cipher_list("ALL:!EXPORT:!LOW:!aNULL:!eNULL:!SSLv2")?;

    let mut ssl = Ssl::new(&ctx_builder.build())?;
    ssl.set_connect_state();

    SslStream::new(ssl, stream)
}
 */

pub fn create_client(
    stream: MemoryStream,
    tls_version: &TLSVersion,
) -> Result<SslStream<MemoryStream>, ErrorStack> {
    todo!()
}

pub fn create_server(
    stream: MemoryStream,
    cert: &X509Ref,
    key: &PKeyRef<Private>,
    tls_version: &TLSVersion,
) -> Result<SslStream<MemoryStream>, ErrorStack> {
    todo!()
}