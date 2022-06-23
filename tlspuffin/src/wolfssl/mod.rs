#![allow(non_snake_case)]

use std::{
    cell::RefCell,
    io::{ErrorKind, Read, Write},
    rc::Rc,
};

use foreign_types::{ForeignType, ForeignTypeRef};
use rustls::msgs::message::OpaqueMessage;

use crate::{
    agent::{AgentName, TLSVersion},
    error::Error,
    io::{MemoryStream, MessageResult, Stream},
    put::{Put, PutConfig, PutName},
    put_registry::{Factory, WOLFSSL520},
    static_certs::{CERT, PRIVATE_KEY},
    trace::ClaimList,
    wolfssl::{
        error::{ErrorStack, SslError},
        pkey::PKey,
        ssl::{Ssl, SslContext, SslMethod, SslRef, SslStream, SslVerifyMode},
        transcript::claim_transcript,
        version::version,
        x509::X509,
    },
};

mod bio;
mod callbacks;
mod dummy_callbacks;
mod error;
mod pkey;
mod rsa;
mod ssl;
mod transcript;
mod util;
mod version;
mod x509;

pub fn new_wolfssl_factory() -> Box<dyn Factory> {
    struct WolfSSLFactory;
    impl Factory for WolfSSLFactory {
        fn create(&self, agent_name: AgentName, config: PutConfig) -> Box<dyn Put> {
            Box::new(WolfSSL::new(agent_name, config).unwrap())
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
    config: PutConfig,
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

impl Drop for WolfSSL {
    fn drop(&mut self) {
        #[cfg(feature = "claims")]
        unsafe {
            self.deregister_claimer();
        }
    }
}

impl Put for WolfSSL {
    fn new(agent_name: AgentName, config: PutConfig) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let ssl = if config.server {
            //let (cert, pkey) = openssl_binding::generate_cert();
            // FIXME: let (cert, pkey) = static_rsa_cert()?;

            let mut ssl = Self::create_server(config.tls_version)?;
            let claimer = config.claims.clone();
            // FIXME: Improve code here -> deduplicate
            ssl.set_msg_callback(move |ssl: &mut SslRef| unsafe {
                let claimer = claimer.clone();
                let mut fn_claimer = move |claim: security_claims::Claim| {
                    let mut claimer = (*claimer).borrow_mut();
                    claimer.claim(agent_name, claim);
                };
                claim_transcript(ssl.as_ptr(), &mut fn_claimer);
            });

            ssl
        } else {
            Self::create_client(config.tls_version)?
        };

        let stream = SslStream::new(ssl, MemoryStream::new())?;

        let mut wolfssl = WolfSSL {
            stream,
            config: config.clone(),
        };

        #[cfg(feature = "claims")]
        stream.register_claimer(config.claims, config.agent_name);
        Ok(wolfssl)
    }

    fn progress(&mut self, agent_name: &AgentName) -> Result<(), Error> {
        unsafe {
            // FIXME: Improve code here -> deduplicate
            let claimer = self.config.claims.clone();
            let agent_name = *agent_name;
            claim_transcript(
                self.stream.ssl().as_ptr(),
                &mut move |claim: security_claims::Claim| {
                    (*claimer).borrow_mut().claim(agent_name, claim);
                },
            )
        }

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
    fn register_claimer(&mut self, claims: Rc<RefCell<ClaimList>>, agent_name: AgentName) {
        unsafe {
            security_claims::register_claimer(
                self.stream.ssl().as_ptr().cast(),
                move |claim: security_claims::Claim| {
                    (*claims).borrow_mut().claim(agent_name, claim)
                },
            );
        }
    }

    #[cfg(feature = "claims")]
    fn deregister_claimer(&mut self) {
        unsafe {
            security_claims::deregister_claimer(self.stream.ssl().as_ptr().cast());
        }
    }

    #[allow(unused_variables)]
    fn rename_agent(&mut self, claims: Rc<RefCell<ClaimList>>, agent_name: AgentName) {
        #[cfg(feature = "claims")]
        {
            self.deregister_claimer();
            self.register_claimer(claims.clone(), agent_name);
        }

        unsafe {
            // FIXME
            self.config.claims = claims.clone();
            //self.config.agent_name = agent_name;
            // FIXME: Improve code here -> deduplicate
            let claimer = claims;
            self.stream
                .ssl_mut()
                .set_msg_callback(move |ssl: &mut SslRef| unsafe {
                    let claimer = claimer.clone();
                    let mut fn_claimer = move |claim: security_claims::Claim| {
                        let mut claimer = (*claimer).borrow_mut();
                        claimer.claim(agent_name, claim);
                    };
                    claim_transcript(ssl.as_ptr(), &mut fn_claimer);
                });
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
        };

        // Mitigates "2. Misuse of sessions of different TLS versions (1.2, 1.3) from the session cache"
        ctx.disable_session_cache()?;

        // Disallow EXPORT in server
        ctx.set_cipher_list("ALL:!EXPORT:!LOW:!aNULL:!eNULL:!SSLv2")?;

        let cert = X509::from_pem(CERT.as_bytes())?;
        ctx.set_certificate(cert.as_ref())?;

        let rsa = crate::wolfssl::rsa::Rsa::private_key_from_pem(PRIVATE_KEY.as_bytes())?;
        let pkey = PKey::from_rsa(rsa)?;
        ctx.set_private_key(pkey.as_ref())?;

        // TODO: Callbacks for experiements
        //wolf::wolfSSL_CTX_set_keylog_callback(ctx, Some(SSL_keylog));
        //wolf::wolfSSL_CTX_set_info_callback(ctx, Some(SSL_info));
        //wolf::wolfSSL_CTX_SetTlsFinishedCb(ctx, Some(SSL_finished));
        //wolf::wolfSSL_set_tls13_secret_cb(ssl.as_ptr(), Some(SSL_keylog13), ptr::null_mut());

        // We expect two tickets like in OpenSSL
        ctx.set_num_tickets(2)?;

        //// SSL pointer builder
        let mut ssl: Ssl = Ssl::new(&ctx)?;

        ssl.set_accept_state();
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
