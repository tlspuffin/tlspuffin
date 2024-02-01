use std::{cell::RefCell, io::ErrorKind, rc::Rc};

use foreign_types::ForeignTypeRef;
use log::debug;

use boring::{
    error::ErrorStack,
    ex_data::Index,
    ssl::{Ssl, SslContext, SslMethod, SslRef, SslStream, SslVerifyMode},
    x509::{store::X509StoreBuilder, X509},
};
use log::info;
use puffin::{
    agent::{AgentDescriptor, AgentName, AgentType, TLSVersion},
    error::Error,
    protocol::MessageResult,
    put::{Put, PutName},
    put_registry::Factory,
    stream::{MemoryStream, Stream},
    trace::TraceContext,
};
use smallvec::SmallVec;

use boringssl_sys::ssl_st;

use crate::{
    boringssl::util::{set_max_protocol_version, static_rsa_cert},
    claims::{
        ClaimData, ClaimDataMessage, ClaimDataTranscript, Finished, TlsClaim, TlsTranscript,
        TranscriptCertificate, TranscriptClientFinished, TranscriptClientHello,
        TranscriptPartialClientHello, TranscriptServerFinished, TranscriptServerHello,
    },
    protocol::TLSProtocolBehavior,
    put::TlsPutConfig,
    put_registry::BORINGSSL_PUT,
    static_certs::{ALICE_CERT, ALICE_PRIVATE_KEY, BOB_CERT, BOB_PRIVATE_KEY, EVE_CERT},
    tls::rustls::msgs::{
        deframer::MessageDeframer,
        message::{Message, OpaqueMessage},
    },
};

#[cfg(feature = "deterministic")]
mod deterministic;
mod transcript;
mod util;

use std::ops::Deref;
use transcript::extract_current_transcript;

pub fn new_boringssl_factory() -> Box<dyn Factory<TLSProtocolBehavior>> {
    struct BoringSSLFactory;
    impl Factory<TLSProtocolBehavior> for BoringSSLFactory {
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

            // FIXME: Add non-clear method like in wolfssl
            if !use_clear {
                info!("OpenSSL put does not support clearing mode")
            }

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
            Ok(Box::new(BoringSSL::new(config).map_err(|err| {
                Error::Put(format!("Failed to create client/server: {}", err))
            })?))
        }

        fn name(&self) -> PutName {
            BORINGSSL_PUT
        }

        fn determinism_set_reseed(&self) -> () {
            debug!("[Determinism] BoringSSL set (already done at compile time) and reseed RAND");
            deterministic::reset_rand();
        }

        fn determinism_reseed(&self) -> () {
            debug!("[Determinism] reseed BoringSSL");
            deterministic::reset_rand();
        }

        fn version(&self) -> String {
            BoringSSL::version()
        }
    }

    Box::new(BoringSSLFactory)
}

pub struct BoringSSL {
    stream: SslStream<MemoryStream<MessageDeframer>>,
    config: TlsPutConfig,
}

impl Drop for BoringSSL {
    fn drop(&mut self) {
        #[cfg(feature = "claims")]
        self.deregister_claimer();
    }
}

impl Stream<Message, OpaqueMessage> for BoringSSL {
    fn add_to_inbound(&mut self, result: &OpaqueMessage) {
        <MemoryStream<MessageDeframer> as Stream<Message, OpaqueMessage>>::add_to_inbound(
            self.stream.get_mut(),
            result,
        )
    }

    fn take_message_from_outbound(
        &mut self,
    ) -> Result<Option<MessageResult<Message, OpaqueMessage>>, Error> {
        let memory_stream = self.stream.get_mut();
        //memory_stream.take_message_from_outbound()

        MemoryStream::take_message_from_outbound(memory_stream)
    }
}

fn _to_claim_data(
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
            ClaimDataTranscript::PartialClientHello(TranscriptPartialClientHello(TlsTranscript(
                claim.transcript.data,
                claim.transcript.length,
            ))),
        )),
        security_claims::ClaimType::CLAIM_TRANSCRIPT_CH_SH => Some(ClaimData::Transcript(
            ClaimDataTranscript::ServerHello(TranscriptServerHello(TlsTranscript(
                claim.transcript.data,
                claim.transcript.length,
            ))),
        )),
        security_claims::ClaimType::CLAIM_TRANSCRIPT_CH_SERVER_FIN => Some(ClaimData::Transcript(
            ClaimDataTranscript::ServerFinished(TranscriptServerFinished(TlsTranscript(
                claim.transcript.data,
                claim.transcript.length,
            ))),
        )),
        security_claims::ClaimType::CLAIM_TRANSCRIPT_CH_CLIENT_FIN => Some(ClaimData::Transcript(
            ClaimDataTranscript::ClientFinished(TranscriptClientFinished(TlsTranscript(
                claim.transcript.data,
                claim.transcript.length,
            ))),
        )),
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

impl Put<TLSProtocolBehavior> for BoringSSL {
    fn progress(&mut self, agent_name: &AgentName) -> Result<(), Error> {
        let result = if self.is_state_successful() {
            // Trigger another read
            let mut vec: Vec<u8> = Vec::from([1; 128]);
            let maybe_error: MaybeError = self.stream.ssl_read(&mut vec).into();
            maybe_error.into()
        } else {
            let maybe_error: MaybeError = self.stream.do_handshake().into();
            maybe_error.into()
        };

        self.set_info_callback(Self::create_info_callback(agent_name.clone(), &self.config))
            .expect("Failed to set info_callback to extract transcript");

        result
    }

    fn reset(&mut self, _agent_name: AgentName) -> Result<(), Error> {
        self.stream.ssl_mut().clear();
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
                    if let Some(data) = to_claim_data(protocol_version, claim) {
                        claims.deref_borrow_mut().claim_sized(TlsClaim {
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
            Ok(())
        }
        #[cfg(not(feature = "deterministic"))]
        {
            Err(Error::Agent(
                "Unable to make BoringSSL deterministic!".to_string(),
            ))
        }
    }

    fn shutdown(&mut self) -> String {
        panic!("Unsupported with OpenSSL PUT")
    }

    fn version() -> String {
        boring::version::version().to_string()
    }
}

impl BoringSSL {
    fn new(config: TlsPutConfig) -> Result<BoringSSL, ErrorStack> {
        let agent_descriptor = &config.descriptor;
        let ssl = match agent_descriptor.typ {
            AgentType::Server => Self::create_server(agent_descriptor)?,
            AgentType::Client => Self::create_client(agent_descriptor)?,
        };

        let stream = SslStream::new(ssl, MemoryStream::new(MessageDeframer::new()))?;

        #[cfg(feature = "claims")]
        let agent_name = agent_descriptor.name;

        let mut boringssl = BoringSSL { config, stream };

        #[cfg(feature = "claims")]
        boringssl.register_claimer(agent_name);

        // boringssl.set_info_callback(Self::create_info_callback(agent_name, &boringssl.config));

        Ok(boringssl)
    }

    fn create_server(descriptor: &AgentDescriptor) -> Result<Ssl, ErrorStack> {
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

        set_max_protocol_version(&mut ctx_builder, descriptor.tls_version)?;

        // Allow EXPORT in server
        ctx_builder.set_cipher_list("ALL:EXPORT:!LOW:!aNULL:!eNULL:!SSLv2")?;

        let mut ssl = Ssl::new(&ctx_builder.build())?;
        ssl.set_accept_state();

        Ok(ssl)
    }

    fn create_client(descriptor: &AgentDescriptor) -> Result<Ssl, ErrorStack> {
        let mut ctx_builder = SslContext::builder(SslMethod::tls())?;
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

        let mut ssl = Ssl::new(&ctx_builder.build())?;
        ssl.set_connect_state();

        Ok(ssl)
    }

    /// Set the info_callback of BoringSSL
    ///
    /// Here we use a intermediate callback, `boring_info_callback`, to call the
    /// `callback` function `callback` is stored in the boringssl ex_data to be
    /// retrieved and executed by `boring_info_callback`
    fn set_info_callback<F>(&mut self, callback: F) -> Result<(), ErrorStack>
    where
        F: Fn(&mut SslRef, i32) + 'static,
    {
        unsafe {
            let ssl = self.stream.ssl_mut();
            ssl.set_ex_data(Index::from_raw(0), callback);
            let ssl_ptr = ssl.as_ptr();
            boringssl_sys::SSL_set_info_callback(ssl_ptr, Some(boring_info_callback::<F>));

            Ok(())
        }
    }

    /// This callback gets the actual hash transcript of the SSL handshake and
    /// add it to the claims
    fn create_info_callback(
        agent_name: AgentName,
        config: &TlsPutConfig,
    ) -> impl Fn(&mut SslRef, i32) {
        let origin = config.descriptor.typ;
        let protocol_version = config.descriptor.tls_version;
        let claims = config.claims.clone();

        move |ssl: &mut SslRef, _info_type: i32| {
            if let Some((transcript, status)) = extract_current_transcript(ssl) {
                let claim = match status.as_str() {
                    "TLS 1.3 server read_client_finished" => Some(ClaimData::Transcript(
                        ClaimDataTranscript::ClientFinished(TranscriptClientFinished(transcript)),
                    )),
                    "TLS 1.3 server done" => Some(ClaimData::Transcript(
                        ClaimDataTranscript::ServerFinished(TranscriptServerFinished(transcript)),
                    )),
                    _ => None,
                };

                if let Some(data) = claim {
                    claims.deref_borrow_mut().claim_sized(TlsClaim {
                        agent_name,
                        origin,
                        protocol_version,
                        data,
                    });
                }
            }
        }
    }
}

pub enum MaybeError {
    Ok,
    Err(Error),
}

/// This callback uses boringssl ex_data to get a pointer to the real callback
/// and to execute it.
///
/// This allows to use a closure as a callback since `SSL_set_info_callback`
/// accepts only `unsafe extern "C"` functions
pub unsafe extern "C" fn boring_info_callback<F>(ssl: *const ssl_st, info_type: i32, _value: i32)
where
    F: Fn(&mut SslRef, i32) + 'static,
{
    let ssl = SslRef::from_ptr_mut(ssl as *mut ssl_st);

    // Getting the callback from ex_data index 0
    let callback = {
        let callback = ssl
            .ex_data::<F>(Index::from_raw(0))
            .expect("BUG: missing info_callback");

        callback.deref() as *const F
    };

    (*callback)(ssl, info_type);
}

impl<T> From<Result<T, boring::ssl::Error>> for MaybeError {
    fn from(result: Result<T, boring::ssl::Error>) -> Self {
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
