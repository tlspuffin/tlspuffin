#![allow(non_snake_case)]

use std::{
    cell::RefCell,
    ffi::CString,
    io::{ErrorKind, Read, Write},
    ptr,
    rc::Rc,
};

use foreign_types::ForeignType;
use rustls::msgs::message::OpaqueMessage;
use security_claims::register::Claimer;

use crate::{
    agent::{AgentName, PutName, TLSVersion},
    error::Error,
    io::{MemoryStream, MessageResult, Stream},
    put::{Config, Put},
    put_registry::{Factory, WOLFSSL520},
    trace::VecClaimer,
    wolfssl,
    wolfssl::{
        cert::{parse_cert, parse_rsa_key},
        error::{ErrorStack, SslError},
        ssl::{Ssl, SslContext, SslMethod, SslStream, SslVerifyMode},
        version::version,
    },
};

mod bio;
mod callbacks;
mod cert;
mod dummy_callbacks;
mod error;
mod ssl;
mod transcript;
mod util;
mod version;

pub fn new_wolfssl_factory() -> Box<dyn Factory> {
    struct WolfSSLFactory;
    impl Factory for WolfSSLFactory {
        fn create(&self, config: Config) -> Box<dyn Put> {
            Box::new(WolfSSL::new(config).unwrap())
        }

        fn put_name(&self) -> PutName {
            WOLFSSL520
        }

        fn put_version(&self) -> &'static str {
            WolfSSL::version()
        }

        fn make_deterministic(&self) {
            WolfSSL::make_deterministic()
        }
    }

    Box::new(WolfSSLFactory)
}

impl From<ErrorStack> for Error {
    fn from(err: ErrorStack) -> Self {
        Error::OpenSSL(err.to_string())
    }
}

pub struct WolfSSL {
    stream: SslStream<MemoryStream>,
}

impl Stream for WolfSSL {
    fn add_to_inbound(&mut self, result: &OpaqueMessage) {
        let raw_stream = self.stream.get_mut();
        raw_stream.add_to_inbound(result)
    }

    fn take_message_from_outbound(&mut self) -> Result<Option<MessageResult>, Error> {
        self.stream.get_mut().take_message_from_outbound()
    }
}

impl Read for WolfSSL {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.stream.get_mut().read(buf)
    }
}

impl Write for WolfSSL {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.stream.get_mut().write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.get_mut().flush()
    }
}

impl Drop for WolfSSL {
    fn drop(&mut self) {
        #[cfg(feature = "claims")]
        unsafe {
            self.deregister_claimer();
        }
    }
}

impl Put for WolfSSL {
    fn new(config: Config) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let ssl = if config.server {
            //let (cert, pkey) = openssl_binding::generate_cert();
            // FIXME: let (cert, pkey) = static_rsa_cert()?;

            Self::create_server(config.tls_version)?
        } else {
            Self::create_client(config.tls_version)?
        };

        let stream = SslStream::new(ssl, MemoryStream::new())?;

        #[cfg(not(feature = "claims"))]
        let wolfssl = WolfSSL { stream };

        #[cfg(feature = "claims")]
        let wolfssl = {
            let mut stream = WolfSSL { stream };
            stream.register_claimer(config.claimer, config.agent_name);
            stream
        };
        Ok(wolfssl)
    }

    fn progress(&mut self) -> Result<(), Error> {
        /*    unsafe {
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
        }*/

        if self.is_state_successful() {
            // Trigger another read
            let mut vec: Vec<u8> = Vec::from([1; 128]);
            let maybe_error: MaybeError = self.stream.ssl_read(&mut vec).into();
            maybe_error.into()
        } else {
            let maybe_error: MaybeError = self.stream.do_handshake().into();
            maybe_error.into()
        }
    }

    fn reset(&mut self) -> Result<(), Error> {
        self.stream.clear();
        Ok(())
    }

    #[cfg(feature = "claims")]
    fn register_claimer(&mut self, claimer: Rc<RefCell<VecClaimer>>, agent_name: AgentName) {
        unsafe {
            /*security_claims::register_claimer(
                self.stream.ssl().as_ptr().cast(),
                move |claim: security_claims::Claim| {
                    (*claimer).borrow_mut().claim(agent_name, claim)
                },
            );*/
        }
    }

    #[cfg(feature = "claims")]
    fn deregister_claimer(&mut self) {
        unsafe {
            //security_claims::deregister_claimer(self.stream.ssl().as_ptr().cast());
        }
    }

    #[allow(unused_variables)]
    fn change_agent_name(&mut self, claimer: Rc<RefCell<VecClaimer>>, agent_name: AgentName) {
        #[cfg(feature = "claims")]
        unsafe {
            //self.deregister_claimer();
            // FIXME
            /*            self.stream.agent_name = agent_name;
            let cb: Box<Box<Claimer>> = Box::new(Box::new(move |claim: security_claims::Claim| {
                let mut ref_mut = (*claimer).borrow_mut();
                ref_mut.claim(agent_name, claim);
            }));
            let x = Box::into_raw(cb) as *mut _;
            wolfssl_sys::wolfSSL_set_msg_callback_arg(
                self.stream.ssl().as_ptr(),
                x, // FIXME: memory leak
            );*/

            //self.register_claimer(claimer, agent_name)
        }
    }

    fn describe_state(&self) -> &'static str {
        // Very useful for nonblocking according to docs:
        // https://www.openssl.org/docs/manmaster/man3/SSL_state_string.html
        // When using nonblocking sockets, the function call performing the handshake may return
        // with SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE condition,
        // so that SSL_state_string[_long]() may be called.
        self.stream.state_string_long()
    }

    fn version() -> &'static str {
        unsafe { version() }
    }

    fn make_deterministic() {
        // TODO
    }

    fn is_state_successful(&self) -> bool {
        self.stream.is_handshake_done()
    }
}

impl WolfSSL {
    pub fn create_client(tls_version: TLSVersion) -> Result<Ssl, ErrorStack> {
        let mut ctx = match tls_version {
            TLSVersion::V1_3 => SslContext::new(SslMethod::tls_client_13())?,
            TLSVersion::V1_2 => SslContext::new(SslMethod::tls_client_12())?,
            TLSVersion::Unknown => panic!("Unknown tls version"),
        };

        // Disallow EXPORT in client
        ctx.set_cipher_list("ALL:!EXPORT:!LOW:!aNULL:!eNULL:!SSLv2")?;
        // Disable certificate verify FIXME: Why is this not needed in OpenSSL?
        ctx.set_verify(SslVerifyMode::NONE);

        let mut ssl: Ssl = Ssl::new(&ctx)?;
        ssl.set_connect_state();

        // Force requesting session ticket because `seed_successfull12` expects it. FIXME: add new tests for this
        ssl.use_session_ticket();

        Ok(ssl)
    }

    pub fn create_server(tls_version: TLSVersion) -> Result<Ssl, ErrorStack> {
        let mut ctx = match tls_version {
            TLSVersion::V1_3 => SslContext::new(SslMethod::tls_server_13())?,
            TLSVersion::V1_2 => SslContext::new(SslMethod::tls_server_12())?,
            TLSVersion::Unknown => panic!("Unknown tls version"),
        };

        //wolf::wolfSSL_CTX_set_session_cache_mode(ctx, wolf::WOLFSSL_SESS_CACHE_OFF.into());

        // Disallow EXPORT in server
        ctx.set_cipher_list("ALL:!EXPORT:!LOW:!aNULL:!eNULL:!SSLv2")?;

        // FIXME Set the static keys
        unsafe {
            wolfssl_sys::wolfSSL_CTX_use_certificate(
                ctx.as_ptr(),
                parse_cert()? as *const _ as *mut _,
            );
            wolfssl_sys::wolfSSL_CTX_use_PrivateKey(
                ctx.as_ptr(),
                parse_rsa_key()? as *const _ as *mut _,
            );
        }

        // TODO: Callbacks for experiements
        //wolf::wolfSSL_CTX_set_keylog_callback(ctx, Some(SSL_keylog));
        //wolf::wolfSSL_CTX_set_info_callback(ctx, Some(SSL_info));
        //wolf::wolfSSL_CTX_SetTlsFinishedCb(ctx, Some(SSL_finished));
        //wolf::wolfSSL_set_tls13_secret_cb(ssl.as_ptr(), Some(SSL_keylog13), ptr::null_mut());

        // We expect two tickets like in OpenSSL
        ctx.set_num_tickets(2);

        //// SSL pointer builder
        let mut ssl: Ssl = Ssl::new(&ctx)?;

        ssl.set_accept_state();

        // Requires WOLFSSL_CALLBACKS
        /*TODO: wolf::wolfSSL_set_msg_callback(ssl.as_ptr(), Some(SSL_Msg_Cb));

        let claimer = claimer.clone();
        let cb: Box<Box<Claimer>> = Box::new(Box::new(move |claim: security_claims::Claim| {
            let mut claimer = (*claimer).borrow_mut();
            claimer.claim(agent_name, claim);
        }));
        // FIXME: memory leak
        wolf::wolfSSL_set_msg_callback_arg(ssl.as_ptr(), Box::into_raw(cb) as *mut _);*/

        Ok(ssl)
    }
}

pub enum MaybeError {
    Ok,
    Err(Error),
}

impl<T> From<Result<T, SslError>> for MaybeError {
    fn from(result: Result<T, SslError>) -> Self {
        if let Err(ssl_error) = result {
            if let Some(io_error) = ssl_error.io_error() {
                match io_error.kind() {
                    ErrorKind::WouldBlock => {
                        // Not actually an error, we just reached the end of the stream, thrown in MemoryStream
                        // trace!("Would have blocked but the underlying stream is non-blocking!");
                        MaybeError::Ok
                    }
                    _ => MaybeError::Err(Error::IO(format!("Unexpected IO Error: {}", io_error))),
                }
            } else if let Some(ssl_error) = ssl_error.ssl_error() {
                // OpenSSL threw an error, that means that there should be an Alert message in the
                // outbound channel
                MaybeError::Err(Error::OpenSSL(ssl_error.to_string()))
            } else {
                MaybeError::Ok
            }
        } else {
            MaybeError::Ok
        }
    }
}

impl Into<Result<(), Error>> for MaybeError {
    fn into(self) -> Result<(), Error> {
        match self {
            MaybeError::Ok => Ok(()),
            MaybeError::Err(err) => Err(err),
        }
    }
}
