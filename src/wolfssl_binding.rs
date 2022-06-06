use itertools::Itertools;
use std::any::Any;
use std::cmp;
use std::ffi::{CStr, CString};
use std::io;
use std::io::{ErrorKind, Read, Write};
use std::marker::PhantomData;
use std::mem::ManuallyDrop;
use std::os::raw::{c_char, c_int, c_void};
use std::panic;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::slice;
use std::str;

use openssl::error::ErrorStack;
use openssl::ssl::{SslContextBuilder, SslVersion};
use openssl::{
    asn1::Asn1Time,
    bn::{BigNum, MsbOption},
    hash::MessageDigest,
    pkey::{PKey, PKeyRef, Private},
    x509::{
        extension::{BasicConstraints, KeyUsage, SubjectKeyIdentifier},
        X509NameBuilder, X509Ref, X509,
    },
};

use crate::agent::TLSVersion;
use crate::error::Error;
use crate::io::MemoryStream;
use crate::wolfssl_bio as bio;
use crate::{openssl_binding, wolfssl_binding};
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
    pub unsafe fn from_ptr(ptr: *mut wolf::WOLFSSL) -> Ssl {
        Ssl(ptr)
    }

    #[inline]
    pub fn as_ptr(&self) -> *mut wolf::WOLFSSL {
        self.0
    }

    fn read(&mut self, buf: &mut [u8]) -> c_int {
        let len = cmp::min(c_int::max_value() as usize, buf.len()) as c_int;
        unsafe { wolf::wolfSSL_read(self.as_ptr(), buf.as_ptr() as *mut c_void, len) }
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
    pub(crate) ssl: ManuallyDrop<Ssl>,
    method: ManuallyDrop<bio::BioMethod>,
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
        let (bio, method) = bio::bio_new(stream)?;
        unsafe {
            wolf::wolfSSL_set_bio(ssl.as_ptr(), bio, bio);
        }
        Ok(SslStream {
            ssl: ManuallyDrop::new(ssl),
            method: ManuallyDrop::new(method),
            _p: PhantomData,
        })
    }
    /// Returns a mutable reference to the underlying stream.
    ///
    /// # Warning
    ///
    /// It is inadvisable to read from or write to the underlying stream as it
    /// will most likely corrupt the SSL session.
    pub fn get_mut(&mut self) -> &mut S {
        unsafe {
            let bio = wolf::wolfSSL_SSL_get_rbio(self.ssl.as_ptr());
            bio::get_mut(bio)
        }
    }

    /// Returns a longer string describing the state of the session.
    ///
    /// This corresponds to [`SSL_state_string_long`].
    ///
    /// [`SSL_state_string_long`]: https://www.openssl.org/docs/man1.1.0/ssl/SSL_state_string_long.html
    pub fn state_string_long(&self) -> &'static str {
        let state = unsafe {
            let ptr = wolf::wolfSSL_state_string_long(self.ssl.as_ptr());
            CStr::from_ptr(ptr as *const _)
        };

        str::from_utf8(state.to_bytes()).unwrap()
    }

    /// Returns a shared reference to the `Ssl` object associated with this stream.
    pub fn ssl(&self) -> &Ssl {
        &self.ssl
    }

    /// Like `read`, but returns an `ssl::Error` rather than an `io::Error`.
    ///
    /// It is particularly useful with a nonblocking socket, where the error value will identify if
    /// OpenSSL is waiting on read or write readiness.
    ///
    /// This corresponds to [`SSL_read`].
    ///
    /// [`SSL_read`]: https://www.openssl.org/docs/manmaster/man3/SSL_read.html
    pub fn ssl_read(&mut self, buf: &mut [u8]) -> Result<usize, openssl::ssl::Error> {
        // The interpretation of the return code here is a little odd with a
        // zero-length write. OpenSSL will likely correctly report back to us
        // that it read zero bytes, but zero is also the sentinel for "error".
        // To avoid that confusion short-circuit that logic and return quickly
        // if `buf` has a length of zero.
        if buf.is_empty() {
            return Ok(0);
        }

        let ret = self.ssl.read(buf);
        if ret > 0 {
            Ok(ret as usize)
        } else {
            Err(self.make_error(ret))
        }
    }

    fn get_raw_rbio(&self) -> *mut bio::BIO {
        unsafe { wolf::wolfSSL_SSL_get_rbio(self.ssl.as_ptr()) }
    }

    fn get_bio_error(&mut self) -> Option<io::Error> {
        unsafe { bio::take_error::<S>(wolf::wolfSSL_SSL_get_rbio(self.ssl.as_ptr())) }
    }

    fn check_panic(&mut self) {
        if let Some(err) = unsafe { bio::take_panic::<S>(self.get_raw_rbio()) } {
            panic::resume_unwind(err)
        }
    }

    fn get_error(&self, ret: c_int) -> openssl::ssl::ErrorCode {
        unsafe {
            openssl::ssl::ErrorCode::from_raw(wolf::wolfSSL_get_error(self.ssl.as_ptr(), ret))
        }
    }

    fn make_error(&mut self, ret: c_int) -> openssl::ssl::Error {
        use openssl::ssl;

        self.check_panic();

        let code = self.get_error(ret);

        let cause = match code {
            // Impossible to use InnerError here ...
            _ => None,
        };

        openssl::ssl::Error { code, cause }
    }

    /// Initiates the handshake.
    ///
    /// This will fail if `set_accept_state` or `set_connect_state` was not called first.
    ///
    /// This corresponds to [`SSL_do_handshake`].
    ///
    /// [`SSL_do_handshake`]: https://www.openssl.org/docs/manmaster/man3/SSL_do_handshake.html
    pub fn do_handshake(&mut self) -> Result<(), openssl::ssl::Error> {
        let ret = unsafe { wolf::wolfSSL_SSL_do_handshake(self.ssl.as_ptr()) };
        if ret > 0 {
            Ok(())
        } else {
            Err(self.make_error(ret))
        }
    }

    pub fn clear(&mut self) -> u32 {
        unsafe { wolf::wolfSSL_clear(self.ssl.as_ptr()) as u32 }
    }

    /// The text variant of the version number and the release date. For example, "OpenSSL 0.9.5a 1 Apr 2000".
    pub fn version(&self) -> &'static str {
        unsafe {
            CStr::from_ptr(wolf::wolfSSL_lib_version())
                .to_str()
                .unwrap()
        }
    }
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
pub fn do_handshake(stream: &mut SslStream<MemoryStream>) -> Result<(), Error> {
    if stream.state_string_long() == "SSL negotiation finished successfully" {
        // todo improve this case
        let mut vec: Vec<u8> = Vec::from([1; 128]);

        if let Err(error) = stream.ssl_read(&mut vec) {
            openssl_binding::log_io_error(&error)?;
            openssl_binding::log_ssl_error(&error)?;
        } else {
            // Reading succeeded
        }
    } else if let Err(error) = stream.do_handshake() {
        openssl_binding::log_io_error(&error)?;
        openssl_binding::log_ssl_error(&error)?;
    } else {
        // Handshake is done
    }

    Ok(())
}

#[test]
fn test_wolf_version() {
    init();

    let memory_stream = MemoryStream::new();
    let ssl_stream = create_client(memory_stream, &TLSVersion::V1_3).unwrap();

    println!("{}", ssl_stream.version());
    assert!(ssl_stream.version().contains("5.2.0"));
}

#[test]
fn test_wolf_get_bio_error() {
    init();

    let memory_stream = MemoryStream::new();
    let mut ssl_stream = create_client(memory_stream, &TLSVersion::V1_3).unwrap();
    let error = ssl_stream.get_bio_error();  // SEGFAULT HERE, search for [test_wolf_get_bio] [SEGFAULT]

    println!("Error: {:?}", error);
}
