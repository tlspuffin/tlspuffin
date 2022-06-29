use std::{cell::RefCell, io, io::ErrorKind, rc::Rc};

use openssl::{
    error::ErrorStack,
    pkey::{PKeyRef, Private},
    ssl::{Ssl, SslContext, SslMethod, SslStream, SslVerifyMode},
    x509::X509Ref,
};
use rustls::msgs::message::OpaqueMessage;

use crate::{
    agent::{AgentName, TLSVersion},
    error::Error,
    io::{MemoryStream, MessageResult, Stream},
    openssl::util::{set_max_protocol_version, static_rsa_cert},
    put::{Put, PutConfig, PutName},
    put_registry::{Factory, OPENSSL111_PUT},
    trace::ClaimList,
};

#[cfg(feature = "deterministic")]
mod deterministic;
mod util;

/*
   Change openssl version:
   cargo clean -p openssl-src
   cd openssl-src/openssl
   git checkout OpenSSL_1_1_1j
*/

pub fn new_openssl_factory() -> Box<dyn Factory> {
    struct OpenSSLFactory;
    impl Factory for OpenSSLFactory {
        fn create(&self, agent_name: AgentName, config: PutConfig) -> Result<Box<dyn Put>, Error> {
            Ok(Box::new(OpenSSL::new(agent_name, config)?))
        }

        fn put_name(&self) -> PutName {
            OPENSSL111_PUT
        }

        fn put_version(&self) -> &'static str {
            OpenSSL::version()
        }

        fn make_deterministic(&self) {
            OpenSSL::make_deterministic()
        }
    }

    Box::new(OpenSSLFactory)
}

impl From<ErrorStack> for Error {
    fn from(err: ErrorStack) -> Self {
        Error::OpenSSL(err.to_string())
    }
}

pub struct OpenSSL {
    stream: SslStream<MemoryStream>,
}

impl Drop for OpenSSL {
    fn drop(&mut self) {
        #[cfg(feature = "claims")]
        self.deregister_claimer();
    }
}

impl Stream for OpenSSL {
    fn add_to_inbound(&mut self, result: &OpaqueMessage) {
        self.stream.get_mut().add_to_inbound(result)
    }

    fn take_message_from_outbound(&mut self) -> Result<Option<MessageResult>, Error> {
        self.stream.get_mut().take_message_from_outbound()
    }
}

impl Put for OpenSSL {
    fn new(agent_name: AgentName, config: PutConfig) -> Result<OpenSSL, Error> {
        let ssl = if config.server {
            Self::create_server(config.tls_version)?
        } else {
            Self::create_client(config.tls_version)?
        };

        let stream = SslStream::new(ssl, MemoryStream::new())?;

        let mut openssl = OpenSSL { stream };

        #[cfg(feature = "claims")]
        openssl.register_claimer(config.claims, agent_name);

        Ok(openssl)
    }

    fn progress(&mut self, _agent_name: &AgentName) -> Result<(), Error> {
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
        self.stream.clear();
        Ok(())
    }

    #[cfg(feature = "claims")]
    fn register_claimer(&mut self, claims: Rc<RefCell<ClaimList>>, agent_name: AgentName) {
        unsafe {
            use foreign_types_shared::ForeignTypeRef;
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
            use foreign_types_shared::ForeignTypeRef;
            security_claims::deregister_claimer(self.stream.ssl().as_ptr().cast());
        }
    }

    #[allow(unused_variables)]
    fn rename_agent(&mut self, claims: Rc<RefCell<ClaimList>>, agent_name: AgentName) {
        #[cfg(feature = "claims")]
        {
            self.deregister_claimer();
            self.register_claimer(claims, agent_name)
        }
    }

    fn describe_state(&self) -> &'static str {
        // Very useful for nonblocking according to docs:
        // https://www.openssl.org/docs/manmaster/man3/SSL_state_string.html
        // When using nonblocking sockets, the function call performing the handshake may return
        // with SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE condition,
        // so that SSL_state_string[_long]() may be called.
        self.stream.ssl().state_string_long()
    }

    fn is_state_successful(&self) -> bool {
        self.describe_state()
            .contains("SSL negotiation finished successfully")
    }

    fn version() -> &'static str {
        openssl::version::version()
    }

    fn make_deterministic() {
        #[cfg(all(feature = "deterministic", feature = "openssl111"))]
        deterministic::set_openssl_deterministic();
        #[cfg(not(feature = "openssl111"))]
        log::warn!("Unable to make PUT determinisitic!");
    }
}

impl OpenSSL {
    fn create_server(tls_version: TLSVersion) -> Result<Ssl, ErrorStack> {
        let mut ctx_builder = SslContext::builder(SslMethod::tls())?;

        //let (cert, pkey) = openssl_binding::generate_cert();
        let (cert, key) = static_rsa_cert()?;
        ctx_builder.set_certificate(&cert)?;
        ctx_builder.set_private_key(&key)?;

        #[cfg(feature = "openssl111")]
        ctx_builder.clear_options(openssl::ssl::SslOptions::ENABLE_MIDDLEBOX_COMPAT);

        #[cfg(feature = "openssl111")]
        ctx_builder.set_options(openssl::ssl::SslOptions::ALLOW_NO_DHE_KEX);

        set_max_protocol_version(&mut ctx_builder, tls_version)?;

        #[cfg(any(feature = "openssl101f", feature = "openssl102u"))]
        {
            ctx_builder.set_tmp_ecdh(
                &openssl::ec::EcKey::from_curve_name(openssl::nid::Nid::SECP384R1)?.as_ref(),
            )?;

            ctx_builder.set_tmp_rsa(&openssl::rsa::Rsa::generate(512)?)?;
        }

        // Allow EXPORT in server
        ctx_builder.set_cipher_list("ALL:EXPORT:!LOW:!aNULL:!eNULL:!SSLv2")?;

        let mut ssl = Ssl::new(&ctx_builder.build())?;
        ssl.set_accept_state();

        Ok(ssl)
    }

    fn create_client(tls_version: TLSVersion) -> Result<Ssl, ErrorStack> {
        let mut ctx_builder = SslContext::builder(SslMethod::tls())?;
        // Not sure whether we want this disabled or enabled: https://github.com/tlspuffin/tlspuffin/issues/67
        // The tests become simpler if disabled to maybe that's what we want. Lets leave it default
        // for now.
        // https://wiki.openssl.org/index.php/TLS1.3#Middlebox_Compatibility_Mode
        #[cfg(feature = "openssl111")]
        ctx_builder.clear_options(openssl::ssl::SslOptions::ENABLE_MIDDLEBOX_COMPAT);

        set_max_protocol_version(&mut ctx_builder, tls_version)?;

        // Disallow EXPORT in client
        ctx_builder.set_cipher_list("ALL:!EXPORT:!LOW:!aNULL:!eNULL:!SSLv2")?;

        ctx_builder.set_verify(SslVerifyMode::NONE);

        let mut ssl = Ssl::new(&ctx_builder.build())?;
        ssl.set_connect_state();

        Ok(ssl)
    }
}

pub enum MaybeError {
    Ok,
    Err(Error),
}

impl<T> From<Result<T, openssl::ssl::Error>> for MaybeError {
    fn from(result: Result<T, openssl::ssl::Error>) -> Self {
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
