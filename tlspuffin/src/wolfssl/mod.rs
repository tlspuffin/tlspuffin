#![allow(non_snake_case)]

use std::{
    borrow::Borrow,
    cell::RefCell,
    ffi::{CStr, CString},
    io::{ErrorKind, Read, Write},
    ops::Deref,
    rc::Rc,
};

use foreign_types::{ForeignType, ForeignTypeRef};
use rustls::msgs::message::OpaqueMessage;

use crate::{
    agent::{AgentDescriptor, AgentName, TLSVersion},
    error::Error,
    io::{MemoryStream, MessageResult, Stream},
    put::{Put, PutConfig, PutName},
    put_registry::{Factory, WOLFSSL520_PUT},
    static_certs::{CERT, PRIVATE_KEY},
    wolfssl::{
        error::{ErrorStack, SslError},
        ssl::{Ssl, SslContext, SslContextRef, SslMethod, SslRef, SslStream, SslVerifyMode},
        transcript::claim_transcript,
        version::version,
        x509::X509,
    },
};

mod bio;
mod callbacks;
// TODO: remove: mod dummy_callbacks;
mod error;
#[cfg(not(feature = "wolfssl430"))]
mod pkey;
#[cfg(not(feature = "wolfssl430"))]
mod rsa;
mod ssl;
mod transcript;
mod util;
mod version;
mod x509;

pub fn new_wolfssl_factory() -> Box<dyn Factory> {
    struct WolfSSLFactory;
    impl Factory for WolfSSLFactory {
        fn create(
            &self,
            agent: &AgentDescriptor,
            config: PutConfig,
        ) -> Result<Box<dyn Put>, Error> {
            Ok(Box::new(WolfSSL::new(agent, config)?))
        }

        fn put_name(&self) -> PutName {
            WOLFSSL520_PUT
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
    ctx: SslContext,
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

impl WolfSSL {
    fn new_stream(
        ctx: &SslContextRef,
        config: &PutConfig,
    ) -> Result<SslStream<MemoryStream>, Error> {
        let ssl = if config.server {
            Self::create_server(ctx)?
        } else {
            Self::create_client(ctx)?
        };

        Ok(SslStream::new(ssl, MemoryStream::new())?)
    }
}

impl Put for WolfSSL {
    fn new(agent: &AgentDescriptor, config: PutConfig) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let mut ctx = if config.server {
            Self::create_server_ctx(config.tls_version)?
        } else {
            Self::create_client_ctx(config.tls_version)?
        };

        let agent_name = agent.name;
        ctx.set_msg_callback(
            config.claim_closure(move |context: &mut SslRef, claims| unsafe {
                claim_transcript(context, agent_name, claims);
            }),
        );

        let stream = Self::new_stream(&ctx, &config)?;

        let mut wolfssl = WolfSSL {
            ctx,
            stream,
            config: config.clone(),
        };

        #[cfg(feature = "claims")]
        stream.register_claimer(config.claims, config.agent_name);
        Ok(wolfssl)
    }

    fn progress(&mut self, agent_name: &AgentName) -> Result<(), Error> {
        claim_transcript(
            self.stream.ssl_mut().as_mut(),
            *agent_name,
            &mut self.config.claims.deref_borrow_mut(),
        );

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

    fn reset(&mut self, agent_name: AgentName) -> Result<(), Error> {
        self.stream = Self::new_stream(&self.ctx, &self.config)?;
        //self.stream.clear();
        Ok(())
    }

    fn config(&self) -> &PutConfig {
        &self.config
    }

    #[cfg(feature = "claims")]
    fn register_claimer(&mut self, agent_name: AgentName) {
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
    fn rename_agent(&mut self, agent_name: AgentName) {
        #[cfg(feature = "claims")]
        {
            self.deregister_claimer();
            self.register_claimer(agent_name);
        }

        self.ctx.set_msg_callback(self.config.claim_closure(
            move |context: &mut SslRef, claims| unsafe {
                claim_transcript(context, agent_name, claims);
            },
        ));
    }

    fn describe_state(&self) -> &'static str {
        // Very useful for nonblocking according to docs:
        // https://www.openssl.org/docs/manmaster/man3/SSL_state_string.html
        // When using nonblocking sockets, the function call performing the handshake may return
        // with SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE condition,
        // so that SSL_state_string[_long]() may be called.
        self.stream.state_string_long()
    }

    fn is_state_successful(&self) -> bool {
        self.stream.is_handshake_done()
    }

    fn version() -> &'static str {
        unsafe { version() }
    }

    fn make_deterministic() {
        // TODO
    }
}

impl WolfSSL {
    pub fn create_client_ctx(tls_version: TLSVersion) -> Result<SslContext, ErrorStack> {
        let mut ctx = match tls_version {
            TLSVersion::V1_3 => SslContext::new(SslMethod::tls_client_13())?,
            TLSVersion::V1_2 => SslContext::new(SslMethod::tls_client_12())?,
        };

        ctx.disable_session_cache()?;

        // Disallow EXPORT in client
        ctx.set_cipher_list("ALL:!EXPORT:!LOW:!aNULL:!eNULL:!SSLv2")?;
        // Disable certificate verify FIXME: Why is this not needed in OpenSSL?
        ctx.set_verify(SslVerifyMode::NONE);

        Ok(ctx)
    }

    pub fn create_client(ctx: &SslContextRef) -> Result<Ssl, ErrorStack> {
        let mut ssl: Ssl = Ssl::new(&ctx)?;
        ssl.set_connect_state();

        // Force requesting session ticket because `seed_successfull12` expects it. FIXME: add new tests for this
        ssl.use_session_ticket();

        Ok(ssl)
    }

    pub fn create_server_ctx(tls_version: TLSVersion) -> Result<SslContext, ErrorStack> {
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

        #[cfg(not(feature = "wolfssl430"))]
        {
            let rsa = crate::wolfssl::rsa::Rsa::private_key_from_pem(PRIVATE_KEY.as_bytes())?;
            let pkey = crate::wolfssl::pkey::PKey::from_rsa(rsa)?;
            ctx.set_private_key(pkey.as_ref())?;
        }
        #[cfg(feature = "wolfssl430")]
        {
            ctx.set_private_key_pem(PRIVATE_KEY.as_bytes())?;
        }

        // Callbacks for experiements
        //wolf::wolfSSL_CTX_set_keylog_callback(ctx, Some(SSL_keylog));
        //wolf::wolfSSL_CTX_set_info_callback(ctx, Some(SSL_info));
        //wolf::wolfSSL_CTX_SetTlsFinishedCb(ctx, Some(SSL_finished));
        //wolf::wolfSSL_set_tls13_secret_cb(ssl.as_ptr(), Some(SSL_keylog13), ptr::null_mut());

        // We expect two tickets like in OpenSSL
        #[cfg(not(feature = "wolfssl430"))]
        ctx.set_num_tickets(2)?;
        Ok(ctx)
    }

    pub fn create_server(ctx: &SslContextRef) -> Result<Ssl, ErrorStack> {
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
                        // debug!("Would have blocked but the underlying stream is non-blocking!");
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
