use std::{cell::RefCell, io::ErrorKind, rc::Rc};

use log::debug;
use openssl::{
    error::ErrorStack,
    ssl::{Ssl, SslContext, SslContextRef, SslMethod, SslStream, SslVerifyMode},
    x509::{store::X509StoreBuilder, X509},
};
use puffin::{
    agent::{AgentDescriptor, AgentName, AgentType},
    error::Error,
    protocol::MessageResult,
    put::{Put, PutName},
    put_registry::{Factory, PutKind},
    stream::{MemoryStream, Stream},
    trace::TraceContext,
    VERSION_STR,
};

use crate::{
    openssl::util::{set_max_protocol_version, static_rsa_cert},
    protocol::{OpaqueMessageFlight, TLSProtocolBehavior},
    put::TlsPutConfig,
    put_registry::OPENSSL111_PUT,
    static_certs::{ALICE_CERT, ALICE_PRIVATE_KEY, BOB_CERT, BOB_PRIVATE_KEY, EVE_CERT},
    tls::rustls::msgs::{
        deframer::MessageDeframer,
        message::{Message, OpaqueMessage},
    },
};

mod bindings;
#[cfg(feature = "deterministic")]
mod deterministic;
mod util;

pub fn new_openssl_factory() -> Box<dyn Factory<TLSProtocolBehavior>> {
    struct OpenSSLFactory;
    impl Factory<TLSProtocolBehavior> for OpenSSLFactory {
        fn create(
            &self,
            context: &TraceContext<TLSProtocolBehavior>,
            agent_descriptor: &AgentDescriptor,
        ) -> Result<Box<dyn Put<TLSProtocolBehavior>>, Error> {
            let put_descriptor = context.put_descriptor(agent_descriptor);

            let options = &put_descriptor.options;

            let use_clear = options
                .get_option("use_clear")
                .map(|value| value.parse().unwrap_or(false))
                .unwrap_or(false);

            let config = TlsPutConfig {
                descriptor: agent_descriptor.clone(),
                claims: context.claims().clone(),
                authenticate_peer: agent_descriptor.typ == AgentType::Client
                    && agent_descriptor.server_authentication
                    || agent_descriptor.typ == AgentType::Server
                        && agent_descriptor.client_authentication,
                extract_deferred: Rc::new(RefCell::new(None)),
                use_clear,
            };
            Ok(Box::new(OpenSSL::new(config).map_err(|err| {
                Error::Put(format!("Failed to create client/server: {}", err))
            })?))
        }

        fn kind(&self) -> PutKind {
            PutKind::Rust
        }

        fn name(&self) -> PutName {
            OPENSSL111_PUT
        }

        fn versions(&self) -> Vec<(String, String)> {
            let openssl_shortname = if cfg!(feature = "openssl101f") {
                "openssl101f"
            } else if cfg!(feature = "openssl102u") {
                "openssl102u"
            } else if cfg!(feature = "openssl111") {
                "openssl111k"
            } else if cfg!(feature = "openssl111j") {
                "openssl111j"
            } else if cfg!(feature = "openssl111u") {
                "openssl111u"
            } else if cfg!(feature = "openssl312") {
                "openssl312"
            } else if cfg!(feature = "libressl") {
                "libressl333"
            } else {
                "unknown"
            };

            vec![
                (
                    "harness".to_string(),
                    format!("{} ({})", OPENSSL111_PUT, VERSION_STR),
                ),
                (
                    "library".to_string(),
                    format!("openssl ({} / {})", openssl_shortname, OpenSSL::version()),
                ),
            ]
        }

        fn determinism_set_reseed(&self) {
            debug!("[Determinism] set and reseed");
            #[cfg(feature = "deterministic")]
            {
                deterministic::rng_set();
                deterministic::rng_reseed();
            }
        }

        fn determinism_reseed(&self) {
            debug!("[Determinism] reseed");
            #[cfg(feature = "deterministic")]
            deterministic::rng_reseed();
        }

        fn clone_factory(&self) -> Box<dyn Factory<TLSProtocolBehavior>> {
            Box::new(OpenSSLFactory)
        }
    }

    Box::new(OpenSSLFactory)
}

pub struct OpenSSL {
    stream: SslStream<MemoryStream<MessageDeframer>>,
    ctx: SslContext,
    config: TlsPutConfig,
}

impl Drop for OpenSSL {
    fn drop(&mut self) {
        #[cfg(feature = "claims")]
        self.deregister_claimer();
    }
}

impl Stream<Message, OpaqueMessage, OpaqueMessageFlight> for OpenSSL {
    fn add_to_inbound(&mut self, result: &OpaqueMessageFlight) {
        <MemoryStream<MessageDeframer> as Stream<Message, OpaqueMessage, OpaqueMessageFlight>>::add_to_inbound(
            self.stream.get_mut(),
            result,
        )
    }

    fn take_message_from_outbound(
        &mut self,
    ) -> Result<Option<MessageResult<Message, OpaqueMessage>>, Error> {
        let memory_stream = self.stream.get_mut();
        //memory_stream.take_message_from_outbound()

        <MemoryStream<MessageDeframer> as Stream<Message, OpaqueMessage, OpaqueMessageFlight>>::take_message_from_outbound(memory_stream)
    }
}

impl Put<TLSProtocolBehavior> for OpenSSL {
    fn progress(&mut self, _agent_name: &AgentName) -> Result<(), Error> {
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

    fn reset(&mut self, _agent_name: AgentName) -> Result<(), Error> {
        if self.config.use_clear {
            bindings::clear(self.stream.ssl());
        } else {
            self.stream = Self::new_stream(&self.ctx, &self.config).map_err(|err| {
                Error::Put(format!("OpenSSL error during stream creation: {}", err))
            })?;

            // FIXME don't force-register a new claimer on reset
            //
            //    Because OpenSSL vendor libraries crash when no claimer is
            //    registered (#253), we are forced to register a new one on
            //    reset. This should be removed once this bug is fixed.
            //
            //    See the WolfSSL module for comparison.
            #[cfg(feature = "claims")]
            self.register_claimer(self.config.descriptor.name);
        }

        Ok(())
    }

    fn descriptor(&self) -> &AgentDescriptor {
        &self.config.descriptor
    }

    #[cfg(feature = "claims")]
    fn register_claimer(&mut self, agent_name: AgentName) {
        unsafe {
            use foreign_types_openssl::ForeignTypeRef;

            let claims = self.config.claims.clone();
            let protocol_version = self.config.descriptor.tls_version;
            let origin = self.config.descriptor.typ;

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

    #[cfg(feature = "claims")]
    fn deregister_claimer(&mut self) {
        unsafe {
            use foreign_types_openssl::ForeignTypeRef;
            security_claims::deregister_claimer(self.stream.ssl().as_ptr().cast());
        }
    }

    #[allow(unused_variables)]
    fn rename_agent(&mut self, agent_name: AgentName) -> Result<(), Error> {
        #[cfg(feature = "claims")]
        {
            self.deregister_claimer();
            self.register_claimer(agent_name);
        }
        Ok(())
    }

    fn describe_state(&self) -> &str {
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

    fn determinism_reseed(&mut self) -> Result<(), Error> {
        #[cfg(feature = "deterministic")]
        {
            deterministic::rng_reseed();
            Ok(())
        }
        #[cfg(not(feature = "deterministic"))]
        {
            Err(Error::Agent(
                "Unable to make OpenSSL deterministic!".to_string(),
            ))
        }
    }

    fn shutdown(&mut self) -> String {
        panic!("Unsupported with OpenSSL PUT")
    }

    fn version() -> String {
        openssl::version::version().to_string()
    }
}

impl OpenSSL {
    fn new(config: TlsPutConfig) -> Result<OpenSSL, ErrorStack> {
        let agent_descriptor = &config.descriptor;
        #[allow(unused_mut)]
        let mut ctx = match agent_descriptor.typ {
            AgentType::Server => Self::create_server_ctx(agent_descriptor)?,
            AgentType::Client => Self::create_client_ctx(agent_descriptor)?,
        };

        let stream = Self::new_stream(&ctx, &config)?;

        #[cfg(feature = "claims")]
        let agent_name = agent_descriptor.name;

        #[allow(unused_mut)]
        let mut openssl = OpenSSL {
            config,
            ctx,
            stream,
        };

        #[cfg(feature = "claims")]
        openssl.register_claimer(agent_name);

        Ok(openssl)
    }

    fn new_stream(
        ctx: &SslContextRef,
        config: &TlsPutConfig,
    ) -> Result<SslStream<MemoryStream<MessageDeframer>>, ErrorStack> {
        let ssl = match config.descriptor.typ {
            AgentType::Server => Self::create_server(ctx)?,
            AgentType::Client => Self::create_client(ctx)?,
        };

        Ok(SslStream::new(
            ssl,
            MemoryStream::new(MessageDeframer::new()),
        )?)
    }

    fn create_server_ctx(descriptor: &AgentDescriptor) -> Result<SslContext, ErrorStack> {
        let mut ctx_builder = SslContext::builder(SslMethod::tls())?;

        let (cert, key) = static_rsa_cert(ALICE_PRIVATE_KEY.0.as_bytes(), ALICE_CERT.0.as_bytes())?;
        ctx_builder.set_certificate(&cert)?;
        ctx_builder.set_private_key(&key)?;

        if descriptor.client_authentication {
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

        set_max_protocol_version(&mut ctx_builder, descriptor.tls_version)?;

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

    fn create_client_ctx(descriptor: &AgentDescriptor) -> Result<SslContext, ErrorStack> {
        let mut ctx_builder = SslContext::builder(SslMethod::tls())?;
        // Not sure whether we want this disabled or enabled: https://github.com/tlspuffin/tlspuffin/issues/67
        // The tests become simpler if disabled to maybe that's what we want. Lets leave it default
        // for now.
        // https://wiki.openssl.org/index.php/TLS1.3#Middlebox_Compatibility_Mode
        #[cfg(feature = "openssl111-binding")]
        ctx_builder.clear_options(openssl::ssl::SslOptions::ENABLE_MIDDLEBOX_COMPAT);

        set_max_protocol_version(&mut ctx_builder, descriptor.tls_version)?;

        // Disallow EXPORT in client
        ctx_builder.set_cipher_list("ALL:!EXPORT:!LOW:!aNULL:!eNULL:!SSLv2")?;

        ctx_builder.set_verify(SslVerifyMode::NONE);

        if descriptor.client_authentication {
            let (cert, key) = static_rsa_cert(BOB_PRIVATE_KEY.0.as_bytes(), BOB_CERT.0.as_bytes())?;
            ctx_builder.set_certificate(&cert)?;
            ctx_builder.set_private_key(&key)?;
        }

        if descriptor.server_authentication {
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

#[cfg(feature = "claims")]
mod claims_helpers {
    use puffin::agent::TLSVersion;
    use smallvec::SmallVec;

    use crate::claims::{
        ClaimData, ClaimDataMessage, ClaimDataTranscript, Finished, TlsTranscript,
        TranscriptCertificate, TranscriptClientFinished, TranscriptClientHello,
        TranscriptPartialClientHello, TranscriptServerFinished, TranscriptServerHello,
    };

    pub fn to_claim_data(
        protocol_version: TLSVersion,
        claim: security_claims::Claim,
    ) -> Option<ClaimData> {
        match claim.typ {
            // Transcripts
            security_claims::ClaimType::CLAIM_TRANSCRIPT_CH => Some(ClaimData::Transcript(
                ClaimDataTranscript::ClientHello(TranscriptClientHello(TlsTranscript(
                    claim.transcript.data,
                    claim.transcript.length,
                ))),
            )),
            security_claims::ClaimType::CLAIM_TRANSCRIPT_PARTIAL_CH => Some(ClaimData::Transcript(
                ClaimDataTranscript::PartialClientHello(TranscriptPartialClientHello(
                    TlsTranscript(claim.transcript.data, claim.transcript.length),
                )),
            )),
            security_claims::ClaimType::CLAIM_TRANSCRIPT_CH_SH => Some(ClaimData::Transcript(
                ClaimDataTranscript::ServerHello(TranscriptServerHello(TlsTranscript(
                    claim.transcript.data,
                    claim.transcript.length,
                ))),
            )),
            security_claims::ClaimType::CLAIM_TRANSCRIPT_CH_SERVER_FIN => {
                Some(ClaimData::Transcript(ClaimDataTranscript::ServerFinished(
                    TranscriptServerFinished(TlsTranscript(
                        claim.transcript.data,
                        claim.transcript.length,
                    )),
                )))
            }
            security_claims::ClaimType::CLAIM_TRANSCRIPT_CH_CLIENT_FIN => {
                Some(ClaimData::Transcript(ClaimDataTranscript::ClientFinished(
                    TranscriptClientFinished(TlsTranscript(
                        claim.transcript.data,
                        claim.transcript.length,
                    )),
                )))
            }
            security_claims::ClaimType::CLAIM_TRANSCRIPT_CH_CERT => Some(ClaimData::Transcript(
                ClaimDataTranscript::Certificate(TranscriptCertificate(TlsTranscript(
                    claim.transcript.data,
                    claim.transcript.length,
                ))),
            )),
            // Messages
            // Transcripts in these messages are not up-to-date. They get updated after the Message has
            // been processed
            security_claims::ClaimType::CLAIM_FINISHED => {
                Some(ClaimData::Message(ClaimDataMessage::Finished(Finished {
                    outbound: claim.write > 0,
                    client_random: SmallVec::from(claim.client_random.data),
                    server_random: SmallVec::from(claim.server_random.data),
                    session_id: SmallVec::from_slice(
                        &claim.session_id.data[..claim.session_id.length as usize],
                    ),
                    authenticate_peer: false,             // FIXME
                    peer_certificate: Default::default(), // FIXME
                    master_secret: match protocol_version {
                        TLSVersion::V1_3 => SmallVec::from_slice(&claim.master_secret.secret),
                        TLSVersion::V1_2 => SmallVec::from_slice(&claim.master_secret_12.secret),
                    },
                    chosen_cipher: claim.chosen_cipher.data,
                    available_ciphers: SmallVec::from_iter(
                        claim.available_ciphers.ciphers[..claim.available_ciphers.length as usize]
                            .iter()
                            .map(|cipher| cipher.data),
                    ),
                    signature_algorithm: claim.signature_algorithm,
                    peer_signature_algorithm: claim.peer_signature_algorithm,
                })))
            }
            security_claims::ClaimType::CLAIM_CLIENT_HELLO => None,
            security_claims::ClaimType::CLAIM_CCS => None,
            security_claims::ClaimType::CLAIM_END_OF_EARLY_DATA => None,
            security_claims::ClaimType::CLAIM_CERTIFICATE => None,
            security_claims::ClaimType::CLAIM_KEY_EXCHANGE => None,
            // FIXME it is weird that this returns the correct transcript
            security_claims::ClaimType::CLAIM_CERTIFICATE_VERIFY => {
                if claim.write == 0 {
                    Some(ClaimData::Transcript(ClaimDataTranscript::ServerFinished(
                        TranscriptServerFinished(TlsTranscript(
                            claim.transcript.data,
                            claim.transcript.length,
                        )),
                    )))
                } else {
                    None
                }
            }
            security_claims::ClaimType::CLAIM_KEY_UPDATE => None,
            security_claims::ClaimType::CLAIM_HELLO_REQUEST => None,
            security_claims::ClaimType::CLAIM_SERVER_HELLO => None,
            security_claims::ClaimType::CLAIM_CERTIFICATE_REQUEST => None,
            security_claims::ClaimType::CLAIM_SERVER_DONE => None,
            security_claims::ClaimType::CLAIM_SESSION_TICKET => None,
            security_claims::ClaimType::CLAIM_CERTIFICATE_STATUS => None,
            security_claims::ClaimType::CLAIM_EARLY_DATA => None,
            security_claims::ClaimType::CLAIM_ENCRYPTED_EXTENSIONS => None,
            _ => None,
        }
    }
}
