use std::{
    any::{Any, TypeId},
    cmp,
    collections::HashMap,
    ffi::{CStr, CString},
    io,
    io::{Read, Write},
    marker::PhantomData,
    mem::ManuallyDrop,
    panic, ptr,
    ptr::NonNull,
    sync::{Arc, Mutex, Once},
};

use bitflags::bitflags;
use foreign_types::{foreign_type, ForeignType, ForeignTypeRef};
use libc::{c_int, c_long, c_void};
use wolfssl_sys as wolf;

use crate::{
    agent::TLSVersion,
    wolfssl::{
        bio,
        callbacks::{msg_callback, ExtraUserDataRegistry, UserData},
        dummy_callbacks::{SSL_connect_ex, SSL_connect_timeout_ex},
        error::{Error, ErrorCode, ErrorStack, InnerError, SslError},
        pkey::{HasPrivate, PKeyRef},
        util::{cvt, cvt_n, cvt_p},
        x509::X509Ref,
    },
};

bitflags! {
    /// Options controlling the behavior of certificate verification.
    pub struct SslVerifyMode: i32 {
        /// Verifies that the peer's certificate is trusted.
        ///
        /// On the server side, this will cause OpenSSL to request a certificate from the client.
        const PEER = wolf::WOLFSSL_VERIFY_PEER;

        /// Disables verification of the peer's certificate.
        ///
        /// On the server side, this will cause OpenSSL to not request a certificate from the
        /// client. On the client side, the certificate will be checked for validity, but the
        /// negotiation will continue regardless of the result of that check.
        const NONE = wolf::WOLFSSL_VERIFY_NONE;

        /// On the server side, abort the handshake if the client did not send a certificate.
        ///
        /// This should be paired with `SSL_VERIFY_PEER`. It has no effect on the client side.
        const FAIL_IF_NO_PEER_CERT = wolf::WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT;
    }
}

#[derive(Copy, Clone)]
pub struct SslMethod(*mut wolf::WOLFSSL_METHOD);

impl SslMethod {
    pub fn tls_client_13() -> SslMethod {
        unsafe { SslMethod(wolf::wolfTLSv1_3_client_method()) }
    }

    pub fn tls_client_12() -> SslMethod {
        unsafe { SslMethod(wolf::wolfTLSv1_2_client_method()) }
    }

    pub fn tls_server_13() -> SslMethod {
        unsafe { SslMethod(wolf::wolfTLSv1_3_server_method()) }
    }

    pub fn tls_server_12() -> SslMethod {
        unsafe { SslMethod(wolf::wolfTLSv1_2_server_method()) }
    }

    pub unsafe fn from_ptr(ptr: *mut wolf::WOLFSSL_METHOD) -> SslMethod {
        SslMethod(ptr)
    }

    #[allow(clippy::trivially_copy_pass_by_ref)]
    pub fn as_ptr(&self) -> *mut wolf::WOLFSSL_METHOD {
        self.0
    }
}

foreign_type! {
    pub unsafe type SslContext: Sync + Send {
        type CType = wolfssl_sys::WOLFSSL_CTX;
        fn drop = wolfssl_sys::wolfSSL_CTX_free;
    }
}

impl SslContext {
    pub fn new(method: SslMethod) -> Result<Self, ErrorStack> {
        unsafe {
            init(false);
            let ctx = cvt_p(wolf::wolfSSL_CTX_new(method.as_ptr()))?;

            Ok(Self::from_ptr(ctx))
        }
    }
}

impl SslContextRef {
    /// Sets the list of supported ciphers for protocols before TLSv1.3.
    ///
    /// The `set_ciphersuites` method controls the cipher suites for TLSv1.3.
    ///
    /// See [`ciphers`] for details on the format.
    ///
    /// This corresponds to [`SSL_CTX_set_cipher_list`].
    ///
    /// [`ciphers`]: https://www.openssl.org/docs/man1.1.0/apps/ciphers.html
    /// [`SSL_CTX_set_cipher_list`]: https://www.openssl.org/docs/manmaster/man3/SSL_CTX_set_cipher_list.html
    pub fn set_cipher_list(&mut self, cipher_list: &str) -> Result<(), ErrorStack> {
        let cipher_list = CString::new(cipher_list).unwrap();
        unsafe {
            cvt(wolf::wolfSSL_CTX_set_cipher_list(
                self.as_ptr(),
                cipher_list.as_ptr() as *const _,
            ))
            .map(|_| ())
        }
    }

    /// Sets the leaf certificate.
    ///
    /// Use `add_extra_chain_cert` to add the remainder of the certificate chain.
    ///
    /// This corresponds to [`SSL_CTX_use_certificate`].
    ///
    /// [`SSL_CTX_use_certificate`]: https://www.openssl.org/docs/man1.0.2/ssl/SSL_CTX_use_certificate_file.html
    pub fn set_certificate(&mut self, cert: &X509Ref) -> Result<(), ErrorStack> {
        unsafe {
            cvt(wolf::wolfSSL_CTX_use_certificate(self.as_ptr(), cert.as_ptr()) as c_int)
                .map(|_| ())
        }
    }

    /// Sets the private key.
    ///
    /// This corresponds to [`SSL_CTX_use_PrivateKey`].
    ///
    /// [`SSL_CTX_use_PrivateKey`]: https://www.openssl.org/docs/man1.0.2/ssl/SSL_CTX_use_PrivateKey_file.html
    pub fn set_private_key<T>(&mut self, key: &PKeyRef<T>) -> Result<(), ErrorStack>
    where
        T: HasPrivate,
    {
        unsafe {
            cvt(wolf::wolfSSL_CTX_use_PrivateKey(
                self.as_ptr(),
                key.as_ptr(),
            ))
            .map(|_| ())
        }
    }

    /// Configures the certificate verification method for new connections.
    ///
    /// This corresponds to [`SSL_CTX_set_verify`].
    ///
    /// [`SSL_CTX_set_verify`]: https://www.openssl.org/docs/man1.1.0/ssl/SSL_CTX_set_verify.html
    pub fn set_verify(&mut self, mode: SslVerifyMode) {
        unsafe {
            wolf::wolfSSL_CTX_set_verify(self.as_ptr(), mode.bits as c_int, None);
        }
    }

    pub fn set_num_tickets(&mut self, n: u64) {
        unsafe {
            wolf::wolfSSL_CTX_set_num_tickets(self.as_ptr(), n);
        }
    }
}

/// WolfSSL library initialization (done only once statically)
pub fn init(debug: bool) {
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

foreign_type! {
    pub unsafe type Ssl: Sync + Send {
        type CType = wolfssl_sys::WOLFSSL;
        fn drop = wolfssl_sys::wolfSSL_free;
    }
}

impl Ssl {
    pub fn new(ctx: &SslContextRef) -> Result<Ssl, ErrorStack> {
        unsafe {
            let ptr = cvt_p(wolf::wolfSSL_new(ctx.as_ptr()))?;
            let mut ssl = Ssl::from_ptr(ptr);

            ssl.set_ex_data(0, ExtraUserDataRegistry::new()); // FIXME: make sure 0 is not reused

            Ok(ssl)
        }
    }
}

impl SslRef {
    fn read(&mut self, buf: &mut [u8]) -> c_int {
        let len = cmp::min(c_int::max_value() as usize, buf.len()) as c_int;
        unsafe { wolf::wolfSSL_read(self.as_ptr(), buf.as_ptr() as *mut _, len) }
    }

    /// Sets the extra data at the specified index.
    ///
    /// This can be used to provide data to callbacks registered with the context. Use the
    /// `Ssl::new_ex_index` method to create an `Index`.
    ///
    /// This corresponds to [`SSL_set_ex_data`].
    ///
    /// [`SSL_set_ex_data`]: https://www.openssl.org/docs/manmaster/man3/SSL_set_ex_data.html
    pub fn set_ex_data<T>(&mut self, index: i32, data: T) {
        unsafe {
            let data = Box::new(data);
            wolf::wolfSSL_set_ex_data(self.as_ptr(), index, Box::into_raw(data) as *mut c_void);
        }
    }

    /// Returns a reference to the extra data at the specified index.
    ///
    /// This corresponds to [`SSL_get_ex_data`].
    ///
    /// [`SSL_get_ex_data`]: https://www.openssl.org/docs/manmaster/man3/SSL_set_ex_data.html
    pub fn ex_data<T>(&self, index: i32) -> Option<&mut T> {
        unsafe {
            let data = wolf::wolfSSL_get_ex_data(self.as_ptr(), index);
            if data.is_null() {
                None
            } else {
                Some(&mut *(data as *mut T))
            }
        }
    }

    pub fn drop_ex_data<T>(&self, index: i32) {
        unsafe {
            let data = wolf::wolfSSL_get_ex_data(self.as_ptr(), index);
            if !data.is_null() {
                Box::<T>::from_raw(data as *mut T);
            }
        }
    }

    pub fn set_user_data<T: 'static>(&self, value: T) {
        let registry: &mut ExtraUserDataRegistry =
            self.ex_data(0).expect("unable to find user data registry");
        registry.user_data.insert(
            TypeId::of::<T>(),
            UserData {
                data: Box::new(value),
            },
        );
    }

    pub fn get_user_data<T: 'static>(&self) -> Option<&T> {
        let registry: &mut ExtraUserDataRegistry =
            self.ex_data(0).expect("unable to find user data registry");
        registry
            .user_data
            .get(&TypeId::of::<T>())
            .and_then(|data| data.data.downcast_ref())
    }

    pub fn set_msg_callback<F>(&mut self, callback: F)
    where
        F: Fn(&mut SslRef) + 'static,
    {
        // Requires WOLFSSL_CALLBACKS (FIXME: or OPENSSL_EXTRA??)
        unsafe {
            self.set_user_data(callback);
            wolf::wolfSSL_set_msg_callback(self.as_ptr(), Some(msg_callback::<F>));
        }
    }

    /// Configure as an outgoing stream from a client.
    ///
    /// This corresponds to [`SSL_set_connect_state`].
    ///
    /// [`SSL_set_connect_state`]: https://www.openssl.org/docs/manmaster/man3/SSL_set_connect_state.html
    pub fn set_connect_state(&mut self) {
        unsafe { wolf::wolfSSL_set_connect_state(self.as_ptr()) }
    }

    /// Configure as an incoming stream to a server.
    ///
    /// This corresponds to [`SSL_set_accept_state`].
    ///
    /// [`SSL_set_accept_state`]: https://www.openssl.org/docs/manmaster/man3/SSL_set_accept_state.html
    pub fn set_accept_state(&mut self) {
        unsafe { wolf::wolfSSL_set_accept_state(self.as_ptr()) }
    }

    pub fn use_session_ticket(&mut self) {
        unsafe {
            wolf::wolfSSL_UseSessionTicket(self.as_ptr());
        }
    }

    pub fn handshake_state(&self) -> &'static str {
        let state = unsafe { (*self.as_ptr()).options.handShakeState };

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
        let state = unsafe { (*self.as_ptr()).options.acceptState };

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
}

/// A TLS session over a stream.
pub struct SslStream<S> {
    ssl: ManuallyDrop<Ssl>,
    method: ManuallyDrop<bio::BioMethod>,
    _p: PhantomData<S>,
}

impl<S> Drop for SslStream<S> {
    fn drop(&mut self) {
        // ssl holds a reference to method internally so it has to drop first
        unsafe {
            self.ssl.drop_ex_data::<ExtraUserDataRegistry>(0);

            ManuallyDrop::drop(&mut self.ssl);
            ManuallyDrop::drop(&mut self.method);
        }
    }
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

        let string = std::str::from_utf8(state.to_bytes()).unwrap();

        string
    }

    pub fn is_handshake_done(&self) -> bool {
        (unsafe { wolf::wolfSSL_is_init_finished(self.ssl.as_ptr()) }) > 0
    }

    /// Returns a shared reference to the `Ssl` object associated with this stream.
    pub fn ssl(&self) -> &Ssl {
        &self.ssl
    }

    pub fn ssl_mut(&mut self) -> &mut Ssl {
        &mut self.ssl
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
        let ret = unsafe {
            //wolf::wolfSSL_SSL_do_handshake(self.ssl.as_ptr())
            wolf::wolfSSL_accept_ex(
                self.ssl.as_ptr(),
                Some(SSL_connect_ex),
                Some(SSL_connect_timeout_ex),
                wolf::WOLFSSL_TIMEVAL {
                    tv_sec: 5,
                    tv_usec: 0,
                },
            )
        };
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
