use std::any::Any;
use std::ffi::CString;
use std::io;
use std::io::{ErrorKind, Read, Write};
use std::marker::PhantomData;
use std::mem::ManuallyDrop;
use std::os::raw::{c_char, c_int, c_void};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::slice;

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
use crate::wolfssl_bio::*;
use wolfssl_sys as wolf;

/// WolfSSL library initialization (done only once statically)
pub fn init() {
    use std::ptr;
    use std::sync::Once;

    // explicitly initialize to work around https://github.com/openssl/openssl/issues/3505
    static INIT: Once = Once::new();
    let init_options = wolf::OPENSSL_INIT_LOAD_SSL_STRINGS;

    INIT.call_once(|| unsafe {
        wolf::wolfSSL_OPENSSL_init_ssl(init_options as u64, ptr::null_mut());
    })
}

/// Ssl: a struct of a Wolfssl pointer with pointer handling as methods
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
    method: ManuallyDrop<BioMethod>,
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
        let (bio, method) = bio_new(stream)?;
        unsafe {
            wolf::wolfSSL_set_bio(ssl.as_ptr(), bio, bio);
        }
        Ok(SslStream {
            ssl: ManuallyDrop::new(ssl),
            method: ManuallyDrop::new(method),
            _p: PhantomData,
        })
    }
/*
    pub fn get_mut(&mut self) -> &mut S {
        unsafe {
            let bio = wolf::wolfSSL_get_rbio(self.ssl);
            bio::get_mut(bio)
        }
    }
*/
}

unsafe fn set_max_protocol_version(
    ctx: *mut wolf::WOLFSSL_CTX,
    tls_version: &TLSVersion,
) -> Result<(), ErrorStack> {
    unsafe {
        match tls_version {
            TLSVersion::V1_3 => {
                #[cfg(feature = "openssl111")]
                wolf::wolfSSL_CTX_set_max_proto_version(ctx, wolf::TLS1_3_VERSION as i32);
                // do nothing as the maximum available TLS version is 1.3
                Ok(())
            }
            TLSVersion::V1_2 => {
                wolf::wolfSSL_CTX_set_max_proto_version(ctx, wolf::TLS1_2_VERSION as i32);
                Ok(())
            }
            TLSVersion::Unknown => Ok(()),
        }?;
    }
    Ok(())
}

pub fn create_client(
    stream: MemoryStream,
    tls_version: &TLSVersion,
) -> Result<SslStream<MemoryStream>, ErrorStack> {
    unsafe {
        //// Global WolfSSL lib initialization
        init();

        //// Context builder
        wolf::wolfSSL_Init();
        let ctx: *mut wolf::WOLFSSL_CTX = wolf::wolfSSL_CTX_new(wolf::wolfTLSv1_3_client_method());
        // Disallow EXPORT in client
        let cipher_list = CString::new("ALL:!EXPORT:!LOW:!aNULL:!eNULL:!SSLv2").unwrap();
        wolf::wolfSSL_CTX_set_cipher_list(ctx, cipher_list.as_ptr() as *const _); //

        //// SSL pointer builder
        let ssl: Ssl = Ssl::from_ptr(wolf::wolfSSL_new(ctx));
        wolf::wolfSSL_set_connect_state(ssl.as_ptr());

        //// Stream builder
        let ssl_stream = SslStream::new(ssl, stream)?;
        Ok(ssl_stream)
    }
}

pub fn create_server(
    stream: MemoryStream,
    cert: &X509Ref,
    key: &PKeyRef<Private>,
    tls_version: &TLSVersion,
) -> Result<SslStream<MemoryStream>, ErrorStack> {
    unsafe {
        //// Global WolfSSL lib initialization
        init();

        //// Context builder
        wolf::wolfSSL_Init();
        let ctx: *mut wolf::WOLFSSL_CTX = wolf::wolfSSL_CTX_new(wolf::wolfTLSv1_3_client_method());
        // Disallow EXPORT in client
        let cipher_list = CString::new("ALL:!EXPORT:!LOW:!aNULL:!eNULL:!SSLv2").unwrap();
        wolf::wolfSSL_CTX_set_cipher_list(ctx, cipher_list.as_ptr() as *const _);
        // Set the static keys
        wolf::wolfSSL_CTX_use_certificate(ctx, cert as *const _ as *mut _);
        wolf::wolfSSL_CTX_use_PrivateKey(ctx, key as *const _ as *mut _);

        //// SSL pointer builder
        let ssl: Ssl = Ssl::from_ptr(wolf::wolfSSL_new(ctx));
        wolf::wolfSSL_set_accept_state(ssl.as_ptr());

        //// Stream builder
        let ssl_stream = SslStream::new(ssl, stream)?;
        Ok(ssl_stream)
    }
}
