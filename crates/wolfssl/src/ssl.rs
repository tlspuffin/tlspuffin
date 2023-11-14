use std::{
    cell::{Ref, RefMut},
    cmp,
    ffi::{CStr, CString},
    io,
    io::{Read, Write},
    marker::PhantomData,
    mem::ManuallyDrop,
    panic, ptr,
    sync::Once,
};

use bitflags::bitflags;
use foreign_types::{foreign_type, ForeignType, ForeignTypeRef};
use libc::{c_int, c_uchar, c_void};
use log::LevelFilter;
use wolfssl_sys as wolf;

use crate::{
    bio,
    callbacks::{ctx_msg_callback, ssl_msg_callback, ExtraUserDataRegistry},
    error::{ErrorCode, ErrorStack, InnerError, SslError},
    util::{cvt, cvt_p},
    x509::X509Ref,
    TLSVersion,
};

const EXTRA_USER_DATA_REGISTRY_INDEX: i32 = 0;

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

pub unsafe fn drop_ssl_context(ctx: *mut wolf::WOLFSSL_CTX) {
    SslContextRef::from_ptr(ctx)
        .drop_ex_data::<ExtraUserDataRegistry>(EXTRA_USER_DATA_REGISTRY_INDEX);

    wolfssl_sys::wolfSSL_CTX_free(ctx);
}

foreign_type! {
    pub unsafe type SslContext: Sync + Send {
        type CType = wolfssl_sys::WOLFSSL_CTX;
        fn drop = drop_ssl_context;
    }
}

impl SslContext {
    pub fn new(method: SslMethod) -> Result<Self, ErrorStack> {
        unsafe {
            init(log::max_level() >= LevelFilter::Trace);
            let ptr = cvt_p(wolf::wolfSSL_CTX_new(method.as_ptr()))?;
            let mut ctx = Self::from_ptr(ptr);
            ctx.set_ex_data(EXTRA_USER_DATA_REGISTRY_INDEX, ExtraUserDataRegistry::new());
            Ok(ctx)
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

    /// This function loads a certificate to use for verifying a peer when performing a TLS/SSL handshake. The peer certificate sent during the handshake is compared by using the SKID when available and the signature. If these two things do not match then any loaded CAs are used. Is the same functionality as wolfSSL_CTX_trust_peer_cert except is from a buffer instead of a file. Feature is enabled by defining the macro WOLFSSL_TRUST_PEER_CERT Please see the examples for proper usage.
    ///
    /// This corresponds to [`wolfSSL_CTX_load_verify_buffer`].
    /// [`wolfSSL_CTX_load_verify_buffer`]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__CertsKeys.html#function-wolfssl_ctx_load_verify_buffer
    pub fn load_verify_buffer(&self, cert: &[u8]) -> Result<(), ErrorStack> {
        unsafe {
            unsafe {
                cvt(wolf::wolfSSL_CTX_load_verify_buffer(
                    self.as_ptr(),
                    cert.as_ptr() as *const u8,
                    cert.len() as i64,
                    wolf::WOLFSSL_FILETYPE_PEM,
                ))
                .map(|_| ())
            }
        }
    }

    /// Returns a reference to the extra data at the specified index.
    ///
    /// This corresponds to [`SSL_CTX_get_ex_data`].
    ///
    /// [`SSL_CTX_get_ex_data`]: https://www.openssl.org/docs/manmaster/man3/SSL_CTX_get_ex_data.html
    pub fn ex_data<T>(&self, index: i32) -> Option<&T> {
        unsafe {
            let data = wolf::wolfSSL_CTX_get_ex_data(self.as_ptr(), index);
            if data.is_null() {
                None
            } else {
                Some(&*(data as *const T))
            }
        }
    }

    /// Sets the extra data at the specified index.
    ///
    /// This can be used to provide data to callbacks registered with the context. Use the
    /// `SslContext::new_ex_index` method to create an `Index`.
    ///
    /// This corresponds to [`SSL_CTX_set_ex_data`].
    ///
    /// [`SSL_CTX_set_ex_data`]: https://www.openssl.org/docs/man1.0.2/ssl/SSL_CTX_set_ex_data.html
    pub fn set_ex_data<T>(&mut self, index: i32, data: T) {
        unsafe {
            let data = Box::into_raw(Box::new(data)) as *mut c_void;
            wolf::wolfSSL_CTX_set_ex_data(self.as_ptr(), index, data);
        }
    }

    pub fn drop_ex_data<T>(&self, index: i32) {
        unsafe {
            let data = wolf::wolfSSL_CTX_get_ex_data(self.as_ptr(), index);
            if !data.is_null() {
                Box::<T>::from_raw(data as *mut T);
            }
        }
    }

    pub fn get_user_data<T: 'static>(&self) -> Option<Ref<T>> {
        let registry: &ExtraUserDataRegistry =
            self.ex_data(0).expect("unable to find user data registry");
        registry.get::<T>()
    }

    pub fn get_user_data_mut<T: 'static>(&self) -> Option<RefMut<T>> {
        let registry: &ExtraUserDataRegistry =
            self.ex_data(0).expect("unable to find user data registry");
        registry.get_mut()
    }

    pub fn set_user_data<T: 'static>(&self, value: T) {
        let registry: &ExtraUserDataRegistry =
            self.ex_data(0).expect("unable to find user data registry");
        registry.set(value);
    }

    #[cfg(not(feature = "wolfssl430"))]
    pub fn set_msg_callback<F>(&mut self, callback: F) -> Result<(), ErrorStack>
    where
        F: Fn(&mut SslRef, i32, u8, bool) + 'static,
    {
        // Requires WOLFSSL_CALLBACKS (FIXME: or OPENSSL_EXTRA??)
        unsafe {
            self.set_user_data(callback);
            cvt(wolf::wolfSSL_CTX_set_msg_callback(
                self.as_ptr(),
                Some(ctx_msg_callback::<F>),
            ))
            .map(|_| ())
        }
    }

    pub fn disable_session_cache(&mut self) -> Result<(), ErrorStack> {
        unsafe {
            cvt(wolfssl_sys::wolfSSL_CTX_set_session_cache_mode(
                self.as_ptr(),
                wolfssl_sys::WOLFSSL_SESS_CACHE_OFF.into(),
            ) as i32)
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
    #[cfg(not(feature = "wolfssl430"))]
    pub fn set_private_key<T>(&mut self, key: &crate::pkey::PKeyRef<T>) -> Result<(), ErrorStack>
    where
        T: crate::pkey::HasPrivate,
    {
        unsafe {
            cvt(wolf::wolfSSL_CTX_use_PrivateKey(
                self.as_ptr(),
                key.as_ptr(),
            ))
            .map(|_| ())
        }
    }

    #[cfg(feature = "wolfssl430")]
    pub fn set_private_key_pem(&mut self, key: &[u8]) -> Result<(), ErrorStack> {
        unsafe {
            cvt(wolf::wolfSSL_CTX_use_PrivateKey_buffer(
                self.as_ptr(),
                key.as_ptr() as *const u8,
                key.len() as i64,
                wolf::WOLFSSL_FILETYPE_PEM,
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

    #[cfg(not(feature = "wolfssl430"))]
    pub fn set_num_tickets(&mut self, n: u64) -> Result<(), ErrorStack> {
        unsafe { cvt(wolf::wolfSSL_CTX_set_num_tickets(self.as_ptr(), n)).map(|_| ()) }
    }
}

/// WolfSSL library initialization (done only once statically)
pub fn init(debug: bool) {
    // explicitly initialize to work around https://github.com/openssl/openssl/issues/3505
    static INIT: Once = Once::new();

    INIT.call_once(|| unsafe {
        if debug {
            wolf::wolfSSL_Debugging_ON();
        }
        wolf::wolfSSL_Init();
    })
}

pub unsafe fn drop_ssl(ssl: *mut wolf::WOLFSSL) {
    SslRef::from_ptr(ssl).drop_ex_data::<ExtraUserDataRegistry>(EXTRA_USER_DATA_REGISTRY_INDEX);

    wolfssl_sys::wolfSSL_free(ssl);
}

foreign_type! {
    pub unsafe type Ssl: Sync + Send {
        type CType = wolfssl_sys::WOLFSSL;
        fn drop = drop_ssl;
    }
}

impl Ssl {
    pub fn new(ctx: &SslContextRef) -> Result<Ssl, ErrorStack> {
        unsafe {
            let ptr = cvt_p(wolf::wolfSSL_new(ctx.as_ptr()))?;
            let mut ssl = Ssl::from_ptr(ptr);

            ssl.set_ex_data(EXTRA_USER_DATA_REGISTRY_INDEX, ExtraUserDataRegistry::new());

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
    pub fn ex_data<T>(&self, index: i32) -> Option<&T> {
        unsafe {
            let data = wolf::wolfSSL_get_ex_data(self.as_ptr(), index);
            if data.is_null() {
                None
            } else {
                Some(&*(data as *mut T))
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
        let registry: &ExtraUserDataRegistry =
            self.ex_data(0).expect("unable to find user data registry");
        registry.set::<T>(value)
    }

    pub fn get_user_data<T: 'static>(&self) -> Option<Ref<T>> {
        let registry: &ExtraUserDataRegistry =
            self.ex_data(0).expect("unable to find user data registry");
        registry.get::<T>()
    }

    pub fn get_user_data_mut<T: 'static>(&self) -> Option<RefMut<T>> {
        let registry: &ExtraUserDataRegistry =
            self.ex_data(0).expect("unable to find user data registry");
        registry.get_mut::<T>()
    }

    pub fn set_msg_callback<F>(&mut self, callback: F) -> Result<(), ErrorStack>
    where
        F: Fn(&mut SslRef, i32, u8, bool) + 'static,
    {
        // Requires WOLFSSL_CALLBACKS (FIXME: or OPENSSL_EXTRA??)
        unsafe {
            self.set_user_data(callback);
            cvt(wolf::wolfSSL_set_msg_callback(
                self.as_ptr(),
                Some(ssl_msg_callback::<F>),
            ))
            .map(|_| ())
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

    pub fn server_state(&self) -> u32 {
        unsafe { (*self.as_ptr()).options.serverState as u32 }
    }

    pub fn server_state_str(&self) -> &'static str {
        let state = unsafe { (*self.as_ptr()).options.serverState };

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
            #[cfg(not(feature = "wolfssl430"))]
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

    pub fn get_peer_certificate(&self) -> Option<Vec<u8>> {
        unsafe {
            let cert = wolf::wolfSSL_get_peer_certificate(self.as_ptr());

            if !cert.is_null() {
                let mut buffer: *mut c_uchar = ptr::null_mut();

                let cert_buffer = if let Ok(length) = cvt(wolf::wolfSSL_i2d_X509(cert, &mut buffer))
                {
                    let vec = Vec::from(std::slice::from_raw_parts(buffer, length as usize));
                    if !buffer.is_null() {
                        wolfssl_sys::wolfSSL_Free(buffer as *mut c_void);
                    }
                    Some(vec)
                } else {
                    None
                };

                wolfssl_sys::wolfSSL_X509_free(cert);

                cert_buffer
            } else {
                None
            }
        }
    }

    pub fn get_accept_state(&self) -> u32 {
        unsafe { (*self.as_ptr()).options.acceptState as u32 }
    }

    pub fn accept_state_str(&self, tls_version: TLSVersion) -> &'static str {
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
            TLSVersion::V1_2 => match state as u32 {
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
        unsafe {
            // ssl holds a reference to method internally so it has to drop first
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
    /// Currently unsupported with TLS 1.3.
    ///
    /// This corresponds to [`SSL_state_string_long`].
    ///
    /// [`SSL_state_string_long`]: https://www.openssl.org/docs/man1.1.0/ssl/SSL_state_string_long.html
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
            // Other errors are not ignored but regarded as SSL related errors
            _ => Some(InnerError::Ssl(ErrorStack::get())),
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
        pub unsafe extern "C" fn SSL_connect_timeout_ex(_info: *mut wolf::TimeoutInfo) -> i32 {
            0
        }

        pub unsafe extern "C" fn SSL_connect_ex(_info: *mut wolf::HandShakeInfo) -> i32 {
            0
        }

        #[cfg(feature = "wolfssl430")]
        type WolfTimeval = wolf::Timeval;

        #[cfg(not(feature = "wolfssl430"))]
        type WolfTimeval = wolf::WOLFSSL_TIMEVAL;

        let ret = unsafe {
            //wolf::wolfSSL_SSL_do_handshake(self.ssl.as_ptr())
            wolf::wolfSSL_accept_ex(
                self.ssl.as_ptr(),
                Some(SSL_connect_ex),
                Some(SSL_connect_timeout_ex),
                WolfTimeval {
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
