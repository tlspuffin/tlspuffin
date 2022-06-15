use std::{
    borrow::BorrowMut,
    cell::{RefCell, RefMut},
    cmp,
    ffi::{CStr, CString},
    io,
    io::{ErrorKind, Read, Write},
    marker::PhantomData,
    mem,
    mem::ManuallyDrop,
    os::raw::{c_int, c_void},
    panic, ptr,
    rc::Rc,
    str,
    sync::Once,
};

use libafl::inputs::bytes;
use libc::{c_char, c_ulong};
use log::info;
use security_claims::register::Claimer;
use wolfssl_sys as wolf;

use super::{error::ErrorStack, wolfssl_bio as bio};
use crate::{
    agent::{AgentName, TLSVersion},
    error::Error,
    io::MemoryStream,
    static_certs::{CERT, PRIVATE_KEY},
    trace::VecClaimer,
    wolfssl::{
        error::{ErrorCode, InnerError, SslError},
        wolfssl_bio::MemBioSlice,
    },
};

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

    pub fn handshake_state(&self) -> &'static str {
        let state = unsafe { (*self.0).options.handShakeState };

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
        let state = unsafe { (*self.0).options.acceptState };

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
impl Drop for Ssl {
    #[inline]
    fn drop(&mut self) {
        // unsafe { wolf::wolfSSL_free(self.0) }
    }
}

/// A TLS session over a stream.
pub struct SslStream<S> {
    ssl: ManuallyDrop<Ssl>,
    vec_claimer: Rc<RefCell<VecClaimer>>,
    pub agent_name: AgentName,
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
    pub fn new(
        ssl: Ssl,
        stream: S,
        agent_name: AgentName,
        vec_claimer: Rc<RefCell<VecClaimer>>,
    ) -> Result<Self, ErrorStack> {
        let (bio, method) = bio::bio_new(stream)?;
        unsafe {
            wolf::wolfSSL_set_bio(ssl.as_ptr(), bio, bio);
        }
        Ok(SslStream {
            agent_name,
            vec_claimer,
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
        let ret = unsafe {
            //wolf::wolfSSL_SSL_do_handshake(self.ssl.as_ptr())
            wolf::wolfSSL_accept_ex(
                self.ssl.as_ptr(),
                Some(SSL_connect_ex),
                None,
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

/// The text variant of the version number and the release date. For example, "OpenSSL 0.9.5a 1 Apr 2000".
pub unsafe fn wolfssl_version() -> &'static str {
    CStr::from_ptr(wolf::wolfSSL_lib_version())
        .to_str()
        .unwrap()
}

pub fn create_client(
    stream: MemoryStream,
    tls_version: &TLSVersion,
    claimer: Rc<RefCell<VecClaimer>>,
    agent_name: AgentName,
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

        // Force requesting session ticket because `seed_successfull12` expects it. FIXME: add new tests for this
        wolf::wolfSSL_UseSessionTicket(ssl.as_ptr());

        wolf::wolfSSL_set_connect_state(ssl.as_ptr());

        //// Stream builder
        let ssl_stream = SslStream::new(ssl, stream, agent_name, claimer)?;
        Ok(ssl_stream)
    }
}

unsafe extern "C" fn SSL_info(ssl: *const wolf::WOLFSSL, a: c_int, b: c_int) {
    info!(
        "SSL_info {:?}",
        Ssl::from_ptr(ssl as *mut wolf::WOLFSSL).accept_state(TLSVersion::V1_3)
    );
}

unsafe extern "C" fn SSL_finished(
    ssl: *mut wolf::WOLFSSL,
    a: *const u8,
    b: *const u8,
    c: *mut u8,
    d: *mut c_void,
) -> i32 {
    info!(
        "SSL_finished {:?}",
        Ssl::from_ptr(ssl as *mut wolf::WOLFSSL).accept_state(TLSVersion::V1_3)
    );
    0
}
unsafe extern "C" fn SSL_keylog13(
    ssl: *mut wolf::WOLFSSL,
    a: c_int,
    b: *const u8,
    d: c_int,
    c: *mut c_void,
) -> i32 {
    /*match a as u32 {
        wolf::Tls13Secret_CLIENT_EARLY_TRAFFIC_SECRET => {
            info!("Tls13Secret_CLIENT_EARLY_TRAFFIC_SECRET");
        }
        wolf::Tls13Secret_CLIENT_HANDSHAKE_TRAFFIC_SECRET => {
            info!("Tls13Secret_CLIENT_HANDSHAKE_TRAFFIC_SECRET");
        }
        wolf::Tls13Secret_SERVER_HANDSHAKE_TRAFFIC_SECRET => {
            info!("Tls13Secret_SERVER_HANDSHAKE_TRAFFIC_SECRET");
        }
        wolf::Tls13Secret_CLIENT_TRAFFIC_SECRET => {
            info!("Tls13Secret_CLIENT_TRAFFIC_SECRET");
        }
        wolf::Tls13Secret_SERVER_TRAFFIC_SECRET => {
            info!("Tls13Secret_SERVER_TRAFFIC_SECRET");
        }
        wolf::Tls13Secret_EARLY_EXPORTER_SECRET => {
            info!("Tls13Secret_EARLY_EXPORTER_SECRET");
        }
        wolf::Tls13Secret_EXPORTER_SECRET => {
            info!("Tls13Secret_EXPORTER_SECRET");
        }
        _ => {}
    };*/
    info!(
        "SSL_keylog13 {:?}",
        Ssl::from_ptr(ssl as *mut wolf::WOLFSSL).accept_state(TLSVersion::V1_3)
    );

    0
}
unsafe extern "C" fn SSL_keylog(ssl: *const wolf::WOLFSSL, a: c_int, b: c_int) {
    info!(
        "SSL_keylog {:?}",
        Ssl::from_ptr(ssl as *mut wolf::WOLFSSL).accept_state(TLSVersion::V1_3)
    );
}

unsafe fn check_transcript(ssl: *mut wolf::WOLFSSL, claimer: &mut Claimer) {
    let hashes = (*ssl).hsHashes;

    if hashes.is_null() {
        return;
    }

    let mut sha256 = (*hashes).hashSha256;

    let mut hash: [u8; 32] = [0; 32];
    wolf::wc_Sha256GetHash(&mut sha256 as *mut wolf::wc_Sha256, hash.as_mut_ptr());

    let mut target: [u8; 64] = [0; 64];
    target[..32].clone_from_slice(&hash);

    let state = unsafe { (*ssl).options.acceptState };

    // WARNING: The following names have been taken from wolfssl/internal.h. They can become out of date.
    match state as u32 {
        wolf::AcceptStateTls13_TLS13_ACCEPT_SECOND_REPLY_DONE => claimer(security_claims::Claim {
            typ: security_claims::ClaimType::CLAIM_TRANSCRIPT_CH_SH,
            transcript: security_claims::ClaimTranscript {
                length: 32,
                data: target,
            },
            ..security_claims::Claim::default()
        }),
        wolf::AcceptStateTls13_TLS13_CERT_VERIFY_SENT => claimer(security_claims::Claim {
            typ: security_claims::ClaimType::CLAIM_TRANSCRIPT_CH_SERVER_FIN,
            transcript: security_claims::ClaimTranscript {
                length: 32,
                data: target,
            },
            ..security_claims::Claim::default()
        }),
        // FIXME
        wolf::AcceptStateTls13_TLS13_TICKET_SENT => claimer(security_claims::Claim {
            typ: security_claims::ClaimType::CLAIM_TRANSCRIPT_CH_CLIENT_FIN,
            transcript: security_claims::ClaimTranscript {
                length: 32,
                data: target,
            },
            ..security_claims::Claim::default()
        }),
        _ => {}
    };

    info!(
        "SSL_Msg_Cb {:?}",
        Ssl::from_ptr(ssl as *mut wolf::WOLFSSL).accept_state(TLSVersion::V1_3),
    );
}

unsafe extern "C" fn SSL_Msg_Cb(
    write_p: c_int,
    version: c_int,
    content_type: c_int,
    buf: *const c_void,
    len: c_ulong,
    ssl: *mut wolf::WOLFSSL,
    arg: *mut c_void,
) {
    let claimer: &mut Box<Claimer> = unsafe { mem::transmute(arg) };
    check_transcript(ssl, claimer);

    info!(
        "SSL_Msg_Cb {:?}",
        Ssl::from_ptr(ssl as *mut wolf::WOLFSSL).accept_state(TLSVersion::V1_3),
    );
}

unsafe extern "C" fn SSL_connect_ex(arg1: *mut wolf::HandShakeInfo) -> i32 {
    info!("SSL_connect_ex");
    1
}

pub fn create_server(
    stream: MemoryStream,
    tls_version: &TLSVersion,
    claimer: Rc<RefCell<VecClaimer>>,
    agent_name: AgentName,
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

        //wolf::wolfSSL_CTX_set_keylog_callback(ctx, Some(SSL_keylog));
        //wolf::wolfSSL_CTX_set_info_callback(ctx, Some(SSL_info));
        //wolf::wolfSSL_CTX_SetTlsFinishedCb(ctx, Some(SSL_finished));

        wolf::wolfSSL_CTX_set_num_tickets(ctx, 2); // We expect two tickets like in OpenSSL

        //// SSL pointer builder
        let ssl: Ssl = Ssl::from_ptr(wolf::wolfSSL_new(ctx));
        // Requires WOLFSSL_CALLBACKS
        wolf::wolfSSL_set_msg_callback(ssl.as_ptr(), Some(SSL_Msg_Cb));

        let rc = claimer.clone();

        let cb: Box<Box<Claimer>> = Box::new(Box::new(move |claim: security_claims::Claim| {
            let mut ref_mut = (*claimer).borrow_mut();
            ref_mut.claim(agent_name, claim);
        }));
        let x = Box::into_raw(cb) as *mut _;
        wolf::wolfSSL_set_msg_callback_arg(
            ssl.as_ptr(),
            x, // FIXME: memory leak
        );

        wolf::wolfSSL_set_tls13_secret_cb(ssl.as_ptr(), Some(SSL_keylog13), ptr::null_mut());

        wolf::wolfSSL_set_accept_state(ssl.as_ptr());

        //// Stream builder

        let ssl_stream = SslStream::new(ssl, stream, agent_name, rc)?;
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
    info!(
        "do_handshake {:?}",
        stream.ssl.accept_state(TLSVersion::V1_3)
    );

    unsafe {
        let rc = stream.vec_claimer.clone();
        let name = stream.agent_name;
        check_transcript(
            stream.ssl.as_ptr(),
            &mut move |claim: security_claims::Claim| {
                info!("check_transcript|do_handshake {}", claim);

                let mut ref_mut = (*rc).borrow_mut();

                ref_mut.claim(name, claim);
            },
        )
    }

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
