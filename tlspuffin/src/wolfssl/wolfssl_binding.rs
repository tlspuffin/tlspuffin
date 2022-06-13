use std::{
    cmp,
    ffi::{CStr, CString},
    io,
    io::{ErrorKind, Read, Write},
    marker::PhantomData,
    mem::ManuallyDrop,
    os::raw::{c_int, c_void},
    panic, ptr, str,
};

use wolfssl_sys as wolf;

use super::{error::ErrorStack, wolfssl_bio as bio};
use crate::{
    agent::TLSVersion,
    error::Error,
    io::MemoryStream,
    static_certs::{CERT, PRIVATE_KEY},
    wolfssl::{
        error::{ErrorCode, InnerError, SslError},
        wolfssl_bio::MemBioSlice,
    },
};

/// WolfSSL library initialization (done only once statically)
pub fn init(debug: bool) {
    use std::{ptr, sync::Once};

    // explicitly initialize to work around https://github.com/openssl/openssl/issues/3505
    static INIT: Once = Once::new();
    let init_options = wolf::OPENSSL_INIT_LOAD_SSL_STRINGS;

    INIT.call_once(|| unsafe {
        if debug {
            wolf::wolfSSL_Debugging_ON();
        }
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
    /// FIXME: This function of wolfSSL currently does not work with TLS 1.3
    pub fn state_string_long(&self) -> &'static str {
        let state = unsafe {
            let state_ptr = wolf::wolfSSL_state_string_long(self.ssl.as_ptr());

            if state_ptr.is_null() {
                return "Unknown State";
            }

            CStr::from_ptr(state_ptr as *const _)
        };

        let string = str::from_utf8(state.to_bytes()).unwrap();

        string
    }

    pub fn is_handshake_done(&self) -> bool {
        (unsafe { wolf::wolfSSL_is_init_finished(self.ssl.as_ptr()) }) > 0
    }

    pub fn handshake_state(&self) -> &'static str {
        let state = unsafe { (*self.ssl.as_ptr()).options.handShakeState };

        // WARNING: The following names have been taken from wolfssl/internal.h. They can become out of date.
        match state as u32 {
            wolf::states_NULL_STATE => "NULL_STATE",
            wolf::states_SERVER_HELLOVERIFYREQUEST_COMPLETE => "SERVER_HELLOVERIFYREQUEST_COMPLETE",
            wolf::states_SERVER_HELLO_RETRY_REQUEST_COMPLETE => {
                "SERVER_HELLO_RETRY_REQUEST_COMPLETE"
            }
            wolf::states_SERVER_HELLO_COMPLETE => "SERVER_HELLO_COMPLETE",
            wolf::states_SERVER_ENCRYPTED_EXTENSIONS_COMPLETE => {
                "SERVER_ENCRYPTED_EXTENSIONS_COMPLETE"
            }
            wolf::states_SERVER_CERT_COMPLETE => "SERVER_CERT_COMPLETE",
            wolf::states_SERVER_CERT_VERIFY_COMPLETE => "SERVER_CERT_VERIFY_COMPLETE",
            wolf::states_SERVER_KEYEXCHANGE_COMPLETE => "SERVER_KEYEXCHANGE_COMPLETE",
            wolf::states_SERVER_HELLODONE_COMPLETE => "SERVER_HELLODONE_COMPLETE",
            wolf::states_SERVER_CHANGECIPHERSPEC_COMPLETE => "SERVER_CHANGECIPHERSPEC_COMPLETE",
            wolf::states_SERVER_FINISHED_COMPLETE => "SERVER_FINISHED_COMPLETE",
            wolf::states_CLIENT_HELLO_RETRY => "CLIENT_HELLO_RETRY",
            wolf::states_CLIENT_HELLO_COMPLETE => "CLIENT_HELLO_COMPLETE",
            wolf::states_CLIENT_KEYEXCHANGE_COMPLETE => "CLIENT_KEYEXCHANGE_COMPLETE",
            wolf::states_CLIENT_CHANGECIPHERSPEC_COMPLETE => "CLIENT_CHANGECIPHERSPEC_COMPLETE",
            wolf::states_CLIENT_FINISHED_COMPLETE => "CLIENT_FINISHED_COMPLETE",
            wolf::states_HANDSHAKE_DONE => "HANDSHAKE_DONE",
            _ => "Unknown",
        }
    }

    pub fn accept_state(&self, tls_version: TLSVersion) -> &'static str {
        let state = unsafe { (*self.ssl.as_ptr()).options.acceptState };

        // WARNING: The following names have been taken from wolfssl/internal.h. They can become out of date.
        match tls_version {
            TLSVersion::V1_3 => match state as u32 {
                wolf::AcceptStateTls13_TLS13_ACCEPT_BEGIN => "TLS13_ACCEPT_BEGIN",
                wolf::AcceptStateTls13_TLS13_ACCEPT_BEGIN_RENEG => "TLS13_ACCEPT_BEGIN_RENEG",
                wolf::AcceptStateTls13_TLS13_ACCEPT_CLIENT_HELLO_DONE => {
                    "TLS13_ACCEPT_CLIENT_HELLO_DONE"
                }
                wolf::AcceptStateTls13_TLS13_ACCEPT_HELLO_RETRY_REQUEST_DONE => {
                    "TLS13_ACCEPT_HELLO_RETRY_REQUEST_DONE"
                }
                wolf::AcceptStateTls13_TLS13_ACCEPT_FIRST_REPLY_DONE => {
                    "TLS13_ACCEPT_FIRST_REPLY_DONE"
                }
                wolf::AcceptStateTls13_TLS13_ACCEPT_SECOND_REPLY_DONE => {
                    "TLS13_ACCEPT_SECOND_REPLY_DONE"
                }
                wolf::AcceptStateTls13_TLS13_SERVER_HELLO_SENT => "TLS13_SERVER_HELLO_SENT",
                wolf::AcceptStateTls13_TLS13_ACCEPT_THIRD_REPLY_DONE => {
                    "TLS13_ACCEPT_THIRD_REPLY_DONE"
                }
                wolf::AcceptStateTls13_TLS13_SERVER_EXTENSIONS_SENT => {
                    "TLS13_SERVER_EXTENSIONS_SENT"
                }
                wolf::AcceptStateTls13_TLS13_CERT_REQ_SENT => "TLS13_CERT_REQ_SENT",
                wolf::AcceptStateTls13_TLS13_CERT_SENT => "TLS13_CERT_SENT",
                wolf::AcceptStateTls13_TLS13_CERT_VERIFY_SENT => "TLS13_CERT_VERIFY_SENT",
                wolf::AcceptStateTls13_TLS13_ACCEPT_FINISHED_SENT => "TLS13_ACCEPT_FINISHED_SENT",
                wolf::AcceptStateTls13_TLS13_PRE_TICKET_SENT => "TLS13_PRE_TICKET_SENT",
                wolf::AcceptStateTls13_TLS13_ACCEPT_FINISHED_DONE => "TLS13_ACCEPT_FINISHED_DONE",
                wolf::AcceptStateTls13_TLS13_TICKET_SENT => "TLS13_TICKET_SENT",
                _ => "Unknown",
            },
            TLSVersion::Unknown | TLSVersion::V1_2 => match state as u32 {
                wolf::AcceptState_ACCEPT_BEGIN => "ACCEPT_BEGIN",
                wolf::AcceptState_ACCEPT_BEGIN_RENEG => "ACCEPT_BEGIN_RENEG",
                wolf::AcceptState_ACCEPT_CLIENT_HELLO_DONE => "ACCEPT_CLIENT_HELLO_DONE",
                wolf::AcceptState_ACCEPT_HELLO_RETRY_REQUEST_DONE => {
                    "ACCEPT_HELLO_RETRY_REQUEST_DONE"
                }
                wolf::AcceptState_ACCEPT_FIRST_REPLY_DONE => "ACCEPT_FIRST_REPLY_DONE",
                wolf::AcceptState_SERVER_HELLO_SENT => "SERVER_HELLO_SENT",
                wolf::AcceptState_CERT_SENT => "CERT_SENT",
                wolf::AcceptState_CERT_VERIFY_SENT => "CERT_VERIFY_SENT",
                wolf::AcceptState_CERT_STATUS_SENT => "CERT_STATUS_SENT",
                wolf::AcceptState_KEY_EXCHANGE_SENT => "KEY_EXCHANGE_SENT",
                wolf::AcceptState_CERT_REQ_SENT => "CERT_REQ_SENT",
                wolf::AcceptState_SERVER_HELLO_DONE => "SERVER_HELLO_DONE",
                wolf::AcceptState_ACCEPT_SECOND_REPLY_DONE => "ACCEPT_SECOND_REPLY_DONE",
                wolf::AcceptState_TICKET_SENT => "TICKET_SENT",
                wolf::AcceptState_CHANGE_CIPHER_SENT => "CHANGE_CIPHER_SENT",
                wolf::AcceptState_ACCEPT_FINISHED_DONE => "ACCEPT_FINISHED_DONE",
                wolf::AcceptState_ACCEPT_THIRD_REPLY_DONE => "ACCEPT_THIRD_REPLY_DONE",
                _ => "Unknown",
            },
        }
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
    pub fn ssl_read(&mut self, buf: &mut [u8]) -> Result<usize, SslError> {
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

    fn get_error(&self, ret: c_int) -> ErrorCode {
        unsafe { ErrorCode::from_raw(wolf::wolfSSL_get_error(self.ssl.as_ptr(), ret)) }
    }

    fn make_error(&mut self, ret: c_int) -> SslError {
        self.check_panic();

        let code = self.get_error(ret);

        let cause = match code {
            ErrorCode::SSL => Some(InnerError::Ssl(ErrorStack::get())),
            ErrorCode::SYSCALL => {
                let errs = ErrorStack::get();
                if errs.errors().is_empty() {
                    self.get_bio_error().map(InnerError::Io)
                } else {
                    Some(InnerError::Ssl(errs))
                }
            }
            ErrorCode::ZERO_RETURN => None,
            ErrorCode::WANT_READ | ErrorCode::WANT_WRITE => {
                self.get_bio_error().map(InnerError::Io)
            }
            _ => Some(InnerError::Ssl(ErrorStack::get())), // FIXME
        };

        SslError { code, cause }
    }

    /// Initiates the handshake.
    ///
    /// This will fail if `set_accept_state` or `set_connect_state` was not called first.
    ///
    /// This corresponds to [`SSL_do_handshake`].
    ///
    /// [`SSL_do_handshake`]: https://www.openssl.org/docs/manmaster/man3/SSL_do_handshake.html
    pub fn do_handshake(&mut self) -> Result<(), SslError> {
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
}

/// The text variant of the version number and the release date. For example, "OpenSSL 0.9.5a 1 Apr 2000".
pub unsafe fn wolfssl_version() -> &'static str {
    CStr::from_ptr(wolf::wolfSSL_lib_version())
        .to_str()
        .unwrap()
}

pub fn create_client(
    stream: MemoryStream,
    tls_version: &TLSVersion,
) -> Result<SslStream<MemoryStream>, SslError> {
    unsafe {
        //// Global WolfSSL lib initialization
        init(false);

        //// Context builder
        wolf::wolfSSL_Init();

        let ctx: *mut wolf::WOLFSSL_CTX = match tls_version {
            TLSVersion::V1_3 => wolf::wolfSSL_CTX_new(wolf::wolfTLSv1_3_client_method()),
            TLSVersion::V1_2 => wolf::wolfSSL_CTX_new(wolf::wolfTLSv1_2_client_method()),
            TLSVersion::Unknown => panic!("Unknown tls version"),
        };

        // Disallow EXPORT in client
        let cipher_list = CString::new("ALL:!EXPORT:!LOW:!aNULL:!eNULL:!SSLv2").unwrap();
        wolf::wolfSSL_CTX_set_cipher_list(ctx, cipher_list.as_ptr() as *const _); //

        // Disable certificate verify FIXME: Why is this not needed in OpenSSL?
        wolf::wolfSSL_CTX_set_verify(ctx, wolf::WOLFSSL_VERIFY_NONE, None);

        //// SSL pointer builder
        let ssl: Ssl = Ssl::from_ptr(wolf::wolfSSL_new(ctx));

        // Force session ticket because `seed_successfull12` expects it. FIXME: add new tests for this
        wolf::wolfSSL_UseSessionTicket(ssl.as_ptr());

        wolf::wolfSSL_set_connect_state(ssl.as_ptr());

        //// Stream builder
        let ssl_stream = SslStream::new(ssl, stream)?;
        Ok(ssl_stream)
    }
}

pub fn create_server(
    stream: MemoryStream,
    tls_version: &TLSVersion,
) -> Result<SslStream<MemoryStream>, SslError> {
    unsafe {
        //// Global WolfSSL lib initialization
        init(false);

        //// Context builder
        wolf::wolfSSL_Init();

        let ctx: *mut wolf::WOLFSSL_CTX = match tls_version {
            TLSVersion::V1_3 => wolf::wolfSSL_CTX_new(wolf::wolfTLSv1_3_server_method()),
            TLSVersion::V1_2 => wolf::wolfSSL_CTX_new(wolf::wolfTLSv1_2_server_method()),
            TLSVersion::Unknown => panic!("Unknown tls version"),
        };

        // Disallow EXPORT in client
        let cipher_list = CString::new("ALL:!EXPORT:!LOW:!aNULL:!eNULL:!SSLv2").unwrap();
        wolf::wolfSSL_CTX_set_cipher_list(ctx, cipher_list.as_ptr() as *const _);

        let bio = MemBioSlice::new(PRIVATE_KEY.as_bytes())?;
        // Read pem from bio
        let rsa = wolf::wolfSSL_PEM_read_bio_RSAPrivateKey(
            bio.as_ptr(),
            ptr::null_mut(),
            None,
            ptr::null_mut(),
        );
        let bio = MemBioSlice::new(CERT.as_bytes())?;
        // FIXME: We are passing here an RSA *, is that fine?
        let cert =
            wolf::wolfSSL_PEM_read_bio_X509(bio.as_ptr(), ptr::null_mut(), None, ptr::null_mut());

        let evp = wolf::wolfSSL_EVP_PKEY_new();
        wolf::wolfSSL_EVP_PKEY_assign_RSA(evp, rsa as *mut _);

        // Set the static keys
        wolf::wolfSSL_CTX_use_certificate(ctx, cert as *const _ as *mut _);
        wolf::wolfSSL_CTX_use_PrivateKey(ctx, evp as *const _ as *mut _);

        //// SSL pointer builder
        let ssl: Ssl = Ssl::from_ptr(wolf::wolfSSL_new(ctx));
        wolf::wolfSSL_set_accept_state(ssl.as_ptr());

        //// Stream builder
        let ssl_stream = SslStream::new(ssl, stream)?;
        Ok(ssl_stream)
    }
}

pub fn log_io_error(error: &SslError) -> Result<(), Error> {
    if let Some(io_error) = error.io_error() {
        match io_error.kind() {
            ErrorKind::WouldBlock => {
                // Not actually an error, we just reached the end of the stream, thrown in MemoryStream
                // trace!("Would have blocked but the underlying stream is non-blocking!");
                Ok(())
            }
            _ => Err(Error::IO(format!("Unexpected IO Error: {}", io_error))),
        }
    } else {
        Ok(())
    }
}

pub fn log_ssl_error(error: &SslError) -> Result<(), Error> {
    if let Some(ssl_error) = error.ssl_error() {
        // OpenSSL threw an error, that means that there should be an Alert message in the
        // outbound channel
        Err(Error::OpenSSL(ssl_error.to_string()))
    } else {
        Ok(())
    }
}

pub fn do_handshake(stream: &mut SslStream<MemoryStream>) -> Result<(), Error> {
    if stream.is_handshake_done() {
        // todo improve this case
        let mut vec: Vec<u8> = Vec::from([1; 128]);

        if let Err(error) = stream.ssl_read(&mut vec) {
            log_io_error(&error)?;
            log_ssl_error(&error)?;
        } else {
            // Reading succeeded
        }
    } else if let Err(error) = stream.do_handshake() {
        log_io_error(&error)?;
        log_ssl_error(&error)?;
    } else {
        // Handshake is done
    }

    Ok(())
}
