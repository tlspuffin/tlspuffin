use std::io::ErrorKind;

use openssl::error::ErrorStack;
use openssl::ssl::{Ssl, SslContext, SslContextRef, SslMethod, SslStream, SslVerifyMode};
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::X509;
use puffin::agent::{AgentDescriptor, AgentName};
use puffin::algebra::ConcreteMessage;
use puffin::error::Error;
use puffin::put::Put;
use puffin::stream::{MemoryStream, Stream};
use util::{set_max_protocol_version, static_rsa_cert};

use crate::protocol::{AgentType, OpaqueMessageFlight, TLSDescriptorConfig, TLSProtocolBehavior};
use crate::put::TlsPutConfig;
use crate::static_certs::{ALICE_CERT, ALICE_PRIVATE_KEY, BOB_CERT, BOB_PRIVATE_KEY, EVE_CERT};

mod bindings;
mod deterministic;
mod util;

pub struct RustPut {
    stream: SslStream<MemoryStream>,
    ctx: SslContext,
    config: TlsPutConfig,
}

impl Drop for RustPut {
    fn drop(&mut self) {
        self.deregister_claimer();
    }
}

impl Stream<TLSProtocolBehavior> for RustPut {
    fn add_to_inbound(&mut self, result: &ConcreteMessage) {
        <MemoryStream as Stream<TLSProtocolBehavior>>::add_to_inbound(self.stream.get_mut(), result)
    }

    fn take_message_from_outbound(&mut self) -> Result<Option<OpaqueMessageFlight>, Error> {
        let memory_stream = self.stream.get_mut();
        //memory_stream.take_message_from_outbound()

        <MemoryStream as Stream<TLSProtocolBehavior>>::take_message_from_outbound(memory_stream)
    }
}

impl Put<TLSProtocolBehavior> for RustPut {
    fn progress(&mut self) -> Result<(), Error> {
        let result = if self.is_state_successful() {
            // Trigger another read
            let mut vec: Vec<u8> = Vec::from([1; 128]);
            let maybe_error: MaybeError = self.stream.ssl_read(&mut vec).into();
            maybe_error.into()
        } else {
            let maybe_error: MaybeError = self.stream.do_handshake().into();
            maybe_error.into()
        };

        result
    }

    fn reset(&mut self, new_name: AgentName) -> Result<(), Error> {
        self.config.descriptor.name = new_name;

        self.deregister_claimer();

        if self.config.use_clear {
            bindings::clear(self.stream.ssl());
        } else {
            self.stream = Self::new_stream(&self.ctx, &self.config).map_err(|err| {
                Error::Put(format!("OpenSSL error during stream creation: {}", err))
            })?;
        }

        self.register_claimer();

        Ok(())
    }

    fn descriptor(&self) -> &AgentDescriptor<TLSDescriptorConfig> {
        &self.config.descriptor
    }

    fn describe_state(&self) -> String {
        // Very useful for nonblocking according to docs:
        // https://www.openssl.org/docs/manmaster/man3/SSL_state_string.html
        // When using nonblocking sockets, the function call performing the handshake may return
        // with SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE condition,
        // so that SSL_state_string[_long]() may be called.
        self.stream.ssl().state_string_long().to_owned()
    }

    fn is_state_successful(&self) -> bool {
        self.describe_state()
            .contains("SSL negotiation finished successfully")
    }

    fn shutdown(&mut self) -> String {
        panic!("Unsupported with OpenSSL PUT")
    }

    fn version() -> String {
        openssl::version::version().to_string()
    }
}

impl RustPut {
    pub fn new(config: TlsPutConfig) -> Result<Self, Error> {
        Self::new_agent(config)
            .map_err(|err| Error::Put(format!("Failed to create agent: {}", err)))
    }

    fn new_agent(config: TlsPutConfig) -> Result<RustPut, ErrorStack> {
        let agent_descriptor = &config.descriptor;
        #[allow(unused_mut)]
        let mut ctx = match agent_descriptor.protocol_config.typ {
            AgentType::Server => Self::create_server_ctx(agent_descriptor)?,
            AgentType::Client => Self::create_client_ctx(agent_descriptor)?,
        };

        let stream = Self::new_stream(&ctx, &config)?;

        #[allow(unused_mut)]
        let mut openssl = RustPut {
            config,
            ctx,
            stream,
        };

        openssl.register_claimer();

        Ok(openssl)
    }

    fn new_stream(
        ctx: &SslContextRef,
        config: &TlsPutConfig,
    ) -> Result<SslStream<MemoryStream>, ErrorStack> {
        let ssl = match config.descriptor.protocol_config.typ {
            AgentType::Server => Self::create_server(ctx)?,
            AgentType::Client => Self::create_client(ctx)?,
        };

        Ok(SslStream::new(ssl, MemoryStream::new())?)
    }

    fn create_server_ctx(
        descriptor: &AgentDescriptor<TLSDescriptorConfig>,
    ) -> Result<SslContext, ErrorStack> {
        let mut ctx_builder = SslContext::builder(SslMethod::tls())?;

        let (cert, key) = static_rsa_cert(ALICE_PRIVATE_KEY.0.as_bytes(), ALICE_CERT.0.as_bytes())?;
        ctx_builder.set_certificate(&cert)?;
        ctx_builder.set_private_key(&key)?;

        #[cfg(any(feature = "openssl111-binding", feature = "libressl-binding"))]
        if let Some(groups) = &descriptor.protocol_config.groups {
            ctx_builder.set_groups_list(groups)?;
        }

        if descriptor.protocol_config.client_authentication {
            let mut store = X509StoreBuilder::new()?;
            store.add_cert(X509::from_pem(BOB_CERT.0.as_bytes())?)?;
            store.add_cert(X509::from_pem(EVE_CERT.0.as_bytes())?)?;
            let store = store.build();

            ctx_builder.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
            ctx_builder.set_cert_store(store);
        } else {
            ctx_builder.set_verify(SslVerifyMode::NONE);
        }

        #[cfg(feature = "openssl111-binding")]
        ctx_builder.clear_options(openssl::ssl::SslOptions::ENABLE_MIDDLEBOX_COMPAT);

        #[cfg(feature = "openssl111-binding")]
        bindings::set_allow_no_dhe_kex(&mut ctx_builder);

        set_max_protocol_version(&mut ctx_builder, descriptor.protocol_config.tls_version)?;

        #[cfg(any(feature = "openssl101-binding", feature = "openssl102-binding"))]
        {
            ctx_builder.set_tmp_ecdh(
                &openssl::ec::EcKey::from_curve_name(openssl::nid::Nid::SECP384R1)?.as_ref(),
            )?;

            bindings::set_tmp_rsa(&ctx_builder, &openssl::rsa::Rsa::generate(512)?)?;
        }

        // Allow EXPORT in server
        ctx_builder.set_cipher_list("ALL:EXPORT:!LOW:!aNULL:!eNULL:!SSLv2")?;

        Ok(ctx_builder.build())
    }

    fn create_server(ctx: &SslContextRef) -> Result<Ssl, ErrorStack> {
        let mut ssl = Ssl::new(&ctx)?;

        ssl.set_accept_state();
        Ok(ssl)
    }

    fn create_client_ctx(
        descriptor: &AgentDescriptor<TLSDescriptorConfig>,
    ) -> Result<SslContext, ErrorStack> {
        let mut ctx_builder = SslContext::builder(SslMethod::tls())?;
        // Not sure whether we want this disabled or enabled: https://github.com/tlspuffin/tlspuffin/issues/67
        // The tests become simpler if disabled to maybe that's what we want. Lets leave it default
        // for now.
        // https://wiki.openssl.org/index.php/TLS1.3#Middlebox_Compatibility_Mode
        #[cfg(feature = "openssl111-binding")]
        ctx_builder.clear_options(openssl::ssl::SslOptions::ENABLE_MIDDLEBOX_COMPAT);

        set_max_protocol_version(&mut ctx_builder, descriptor.protocol_config.tls_version)?;

        #[cfg(any(feature = "openssl111-binding", feature = "libressl-binding"))]
        if let Some(groups) = &descriptor.protocol_config.groups {
            ctx_builder.set_groups_list(groups)?;
        }

        // Disallow EXPORT in client
        ctx_builder.set_cipher_list("ALL:!EXPORT:!LOW:!aNULL:!eNULL:!SSLv2")?;

        ctx_builder.set_verify(SslVerifyMode::NONE);

        if descriptor.protocol_config.client_authentication {
            let (cert, key) = static_rsa_cert(BOB_PRIVATE_KEY.0.as_bytes(), BOB_CERT.0.as_bytes())?;
            ctx_builder.set_certificate(&cert)?;
            ctx_builder.set_private_key(&key)?;
        }

        if descriptor.protocol_config.server_authentication {
            ctx_builder.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);

            let mut store = X509StoreBuilder::new()?;
            store.add_cert(X509::from_pem(ALICE_CERT.0.as_bytes())?)?;
            store.add_cert(X509::from_pem(EVE_CERT.0.as_bytes())?)?;
            let store = store.build();

            ctx_builder.set_cert_store(store);
        } else {
            ctx_builder.set_verify(SslVerifyMode::NONE);
        }

        Ok(ctx_builder.build())
    }

    pub fn create_client(ctx: &SslContextRef) -> Result<Ssl, ErrorStack> {
        let mut ssl: Ssl = Ssl::new(&ctx)?;
        ssl.set_connect_state();

        Ok(ssl)
    }

    fn register_claimer(&mut self) {
        unsafe {
            use foreign_types_openssl::ForeignTypeRef;

            use crate::claims::claims_helpers;

            let agent_name = self.config.descriptor.name;
            let claims = self.config.claims.clone();
            let protocol_version = self.config.descriptor.protocol_config.tls_version;
            let origin = self.config.descriptor.protocol_config.typ;

            security_claims::register_claimer(
                self.stream.ssl().as_ptr().cast(),
                move |claim: security_claims::Claim| {
                    if let Some(data) = claims_helpers::to_claim_data(protocol_version, claim) {
                        claims
                            .deref_borrow_mut()
                            .claim_sized(crate::claims::TlsClaim {
                                agent_name,
                                origin,
                                protocol_version,
                                data,
                            })
                    }
                },
            );
        }
    }

    fn deregister_claimer(&mut self) {
        unsafe {
            use foreign_types_openssl::ForeignTypeRef;
            security_claims::deregister_claimer(self.stream.ssl().as_ptr().cast());
        }
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
                        // Not actually an error, we just reached the end of the stream, thrown in
                        // MemoryStream
                        MaybeError::Ok
                    }
                    _ => MaybeError::Err(Error::IO(format!("Unexpected IO Error: {}", io_error))),
                }
            } else if let Some(ssl_error) = ssl_error.ssl_error() {
                // OpenSSL threw an error, that means that there should be an Alert message in the
                // outbound channel
                MaybeError::Err(Error::Put(ssl_error.to_string()))
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
