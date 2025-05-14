#![allow(non_snake_case)]

use std::io::ErrorKind;
use std::ops::Deref;

use foreign_types::ForeignType;
use puffin::agent::{AgentDescriptor, AgentName};
use puffin::algebra::dynamic_function::TypeShape;
use puffin::algebra::ConcreteMessage;
use puffin::error::Error;
use puffin::put::Put;
use puffin::stream::{MemoryStream, Stream};
use smallvec::SmallVec;
use transcript::extract_current_transcript;
use wolfssl::error::{ErrorStack, SslError};
use wolfssl::ssl::{Ssl, SslContext, SslContextRef, SslMethod, SslRef, SslStream, SslVerifyMode};
use wolfssl::version::version;
use wolfssl::x509::X509;

use crate::claims::{
    ClaimData, ClaimDataMessage, ClaimDataTranscript, Finished, TlsClaim, TranscriptCertificate,
    TranscriptClientFinished, TranscriptServerFinished, TranscriptServerHello,
};
use crate::protocol::{
    AgentType, OpaqueMessageFlight, TLSDescriptorConfig, TLSProtocolBehavior, TLSProtocolTypes,
    TLSVersion,
};
use crate::put::TlsPutConfig;
use crate::static_certs::{ALICE_CERT, ALICE_PRIVATE_KEY, BOB_CERT, BOB_PRIVATE_KEY, EVE_CERT};
use crate::tls::rustls::msgs::enums::HandshakeType;

mod transcript;

pub struct WolfSSLErrorStack(pub ErrorStack);

impl From<ErrorStack> for WolfSSLErrorStack {
    fn from(err: ErrorStack) -> Self {
        WolfSSLErrorStack(err)
    }
}

impl From<WolfSSLErrorStack> for Error {
    fn from(err: WolfSSLErrorStack) -> Self {
        Error::Put(err.0.to_string())
    }
}

pub struct RustPut {
    stream: SslStream<MemoryStream>,
    ctx: SslContext,
    config: TlsPutConfig,
}

impl Stream<TLSProtocolBehavior> for RustPut {
    fn add_to_inbound(&mut self, result: &ConcreteMessage) {
        <MemoryStream as Stream<TLSProtocolBehavior>>::add_to_inbound(self.stream.get_mut(), result)
    }

    fn take_message_from_outbound(&mut self) -> Result<Option<OpaqueMessageFlight>, Error> {
        let raw_stream = self.stream.get_mut();
        <MemoryStream as Stream<TLSProtocolBehavior>>::take_message_from_outbound(raw_stream)
    }
}

impl Drop for RustPut {
    fn drop(&mut self) {
        self.deregister_claimer();
    }
}

impl RustPut {
    pub fn new(config: TlsPutConfig) -> Result<Self, Error> {
        Self::new_agent(config)
            .map_err(|err| Error::Put(format!("Failed to create agent: {}", err.0.to_string())))
    }

    fn new_agent(config: TlsPutConfig) -> Result<Self, WolfSSLErrorStack> {
        let agent_descriptor = &config.descriptor;
        #[allow(unused_mut)]
        let mut ctx = match agent_descriptor.protocol_config.typ {
            AgentType::Server => Self::create_server_ctx(agent_descriptor)?,
            AgentType::Client => Self::create_client_ctx(agent_descriptor)?,
        };

        let stream = Self::new_stream(&mut ctx, &config)?;

        #[allow(unused_mut)]
        let mut wolfssl = RustPut {
            ctx,
            stream,
            config: config.clone(),
        };

        wolfssl.register_claimer();
        Ok(wolfssl)
    }

    fn new_stream(
        ctx: &mut SslContextRef,
        config: &TlsPutConfig,
    ) -> Result<SslStream<MemoryStream>, WolfSSLErrorStack> {
        #[cfg(not(feature = "wolfssl430"))]
        ctx.set_msg_callback(Self::create_msg_callback(config.descriptor.name, &config))
            .expect("Failed to set msg_callback to extract transcript");

        let ssl = match config.descriptor.protocol_config.typ {
            AgentType::Server => Self::create_server(ctx)?,
            AgentType::Client => Self::create_client(ctx)?,
        };

        #[allow(unused_mut)]
        let mut stream = SslStream::new(ssl, MemoryStream::new())?;

        #[cfg(feature = "wolfssl430")]
        stream
            .ssl_mut()
            .set_msg_callback(Self::create_msg_callback(config.descriptor.name, &config))
            .expect("Failed to set msg_callback to extract transcript");

        Ok(stream)
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

        self.deferred_transcript_extraction();

        result
    }

    fn reset(&mut self, new_name: AgentName) -> Result<(), Error> {
        self.config.descriptor.name = new_name;
        self.deregister_claimer();

        if self.config.use_clear {
            self.stream.clear();
        } else {
            self.stream = Self::new_stream(&mut self.ctx, &self.config)?;
        }

        self.register_claimer();

        Ok(())
    }

    fn describe_state(&self) -> String {
        // Very useful for nonblocking according to docs:
        // https://www.openssl.org/docs/manmaster/man3/SSL_state_string.html
        // When using nonblocking sockets, the function call performing the handshake may return
        // with SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE condition,
        // so that SSL_state_string[_long]() may be called.
        self.stream.state_string_long().to_owned()
    }

    fn is_state_successful(&self) -> bool {
        self.stream.is_handshake_done()
    }

    fn version() -> String {
        unsafe { version().to_string() }
    }

    fn shutdown(&mut self) -> String {
        panic!("Unsupported with WolfSSL PUT")
    }

    fn descriptor(&self) -> &AgentDescriptor<TLSDescriptorConfig> {
        &self.config.descriptor
    }
}

impl RustPut {
    pub fn create_client_ctx(
        descriptor: &AgentDescriptor<TLSDescriptorConfig>,
    ) -> Result<SslContext, WolfSSLErrorStack> {
        let mut ctx = match descriptor.protocol_config.tls_version {
            TLSVersion::V1_3 => SslContext::new(SslMethod::tls_client_13())?,
            TLSVersion::V1_2 => SslContext::new(SslMethod::tls_client_12())?,
        };

        ctx.disable_session_cache()?;

        if descriptor.protocol_config.client_authentication {
            let cert = X509::from_pem(BOB_CERT.0.as_bytes())?;
            ctx.set_certificate(cert.as_ref())?;

            #[cfg(not(feature = "wolfssl430"))]
            {
                let rsa = wolfssl::rsa::Rsa::private_key_from_pem(BOB_PRIVATE_KEY.0.as_bytes())?;
                let pkey = wolfssl::pkey::PKey::from_rsa(rsa)?;
                ctx.set_private_key(pkey.as_ref())?;
            }
            #[cfg(feature = "wolfssl430")]
            {
                ctx.set_private_key_pem(BOB_PRIVATE_KEY.0.as_bytes())?;
            }
        }

        if descriptor.protocol_config.server_authentication {
            ctx.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
            ctx.load_verify_buffer(ALICE_CERT.0.as_bytes())?;
            ctx.load_verify_buffer(EVE_CERT.0.as_bytes())?;
        } else {
            // Disable certificate verify
            ctx.set_verify(SslVerifyMode::NONE);
        }

        // Disallow EXPORT in client
        ctx.set_cipher_list(&descriptor.protocol_config.cipher_string)?;

        if let Some(groups) = &descriptor.protocol_config.groups {
            ctx.set_groups(groups)?;
        }

        Ok(ctx)
    }

    pub fn create_client(ctx: &SslContextRef) -> Result<Ssl, WolfSSLErrorStack> {
        let mut ssl: Ssl = Ssl::new(&ctx)?;
        ssl.set_connect_state();

        // Force requesting session ticket because `seed_successfull12` expects it.
        ssl.use_session_ticket();

        Ok(ssl)
    }

    pub fn create_server_ctx(
        descriptor: &AgentDescriptor<TLSDescriptorConfig>,
    ) -> Result<SslContext, WolfSSLErrorStack> {
        let mut ctx = match descriptor.protocol_config.tls_version {
            TLSVersion::V1_3 => SslContext::new(SslMethod::tls_server_13())?,
            TLSVersion::V1_2 => SslContext::new(SslMethod::tls_server_12())?,
        };

        // Mitigates "2. Misuse of sessions of different TLS versions (1.2, 1.3) from the session
        // cache"
        ctx.disable_session_cache()?;

        // Disallow EXPORT in server
        ctx.set_cipher_list(&descriptor.protocol_config.cipher_string)?;

        if let Some(groups) = &descriptor.protocol_config.groups {
            ctx.set_groups(groups)?;
        }

        let cert = X509::from_pem(ALICE_CERT.0.as_bytes())?;
        ctx.set_certificate(cert.as_ref())?;

        #[cfg(not(feature = "wolfssl430"))]
        {
            let rsa = wolfssl::rsa::Rsa::private_key_from_pem(ALICE_PRIVATE_KEY.0.as_bytes())?;
            let pkey = wolfssl::pkey::PKey::from_rsa(rsa)?;
            ctx.set_private_key(pkey.as_ref())?;
        }
        #[cfg(feature = "wolfssl430")]
        {
            ctx.set_private_key_pem(ALICE_PRIVATE_KEY.0.as_bytes())?;
        }

        if descriptor.protocol_config.client_authentication {
            ctx.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
            ctx.load_verify_buffer(BOB_CERT.0.as_bytes())?;
            ctx.load_verify_buffer(EVE_CERT.0.as_bytes())?;
        } else {
            ctx.set_verify(SslVerifyMode::NONE);
        }

        // We expect two tickets like in OpenSSL
        #[cfg(not(feature = "wolfssl430"))]
        ctx.set_num_tickets(2)?;
        Ok(ctx)
    }

    pub fn create_server(ctx: &SslContextRef) -> Result<Ssl, WolfSSLErrorStack> {
        //// SSL pointer builder
        let mut ssl: Ssl = Ssl::new(&ctx)?;

        ssl.set_accept_state();
        Ok(ssl)
    }

    fn deferred_transcript_extraction(&self) {
        let config = &self.config;
        if let Some(type_shape) = self.config.extract_deferred.deref().borrow_mut().take() {
            if let Some(transcript) = extract_current_transcript(self.stream.ssl()) {
                let CERT_SHAPE: TypeShape<TLSProtocolTypes> =
                    TypeShape::<TLSProtocolTypes>::of::<TranscriptCertificate>();
                let FINISHED_SHAPE: TypeShape<TLSProtocolTypes> =
                    TypeShape::<TLSProtocolTypes>::of::<TranscriptServerFinished>();
                let CLIENT_SHAPE: TypeShape<TLSProtocolTypes> =
                    TypeShape::<TLSProtocolTypes>::of::<TranscriptClientFinished>();

                let data = if type_shape == CERT_SHAPE {
                    Some(ClaimData::Transcript(ClaimDataTranscript::Certificate(
                        TranscriptCertificate(transcript),
                    )))
                } else if type_shape == FINISHED_SHAPE {
                    Some(ClaimData::Transcript(ClaimDataTranscript::ServerFinished(
                        TranscriptServerFinished(transcript),
                    )))
                } else if type_shape == CLIENT_SHAPE {
                    Some(ClaimData::Transcript(ClaimDataTranscript::ClientFinished(
                        TranscriptClientFinished(transcript),
                    )))
                } else {
                    None
                };

                if let Some(data) = data {
                    config.claims.deref_borrow_mut().claim_sized(TlsClaim {
                        agent_name: self.config.descriptor.name,
                        origin: config.descriptor.protocol_config.typ,
                        protocol_version: config.descriptor.protocol_config.tls_version,
                        data,
                    });
                }
            }
        }
    }

    fn register_claimer(&mut self) {
        unsafe {
            use crate::claims::claims_helpers;

            let agent_name = self.config.descriptor.name;
            let claims = self.config.claims.clone();
            let protocol_version = self.config.descriptor.protocol_config.tls_version;
            let origin = self.config.descriptor.protocol_config.typ;

            security_claims::register_claimer(
                self.stream.ssl().as_ptr().cast(),
                move |claim: security_claims::Claim| {
                    if let Some(data) = claims_helpers::to_claim_data(protocol_version, claim) {
                        claims.deref_borrow_mut().claim_sized(TlsClaim {
                            agent_name,
                            origin,
                            protocol_version,
                            data,
                        });
                    }
                },
            );
        }
    }

    fn deregister_claimer(&mut self) {
        unsafe {
            security_claims::deregister_claimer(self.stream.ssl().as_ptr().cast());
        }
    }

    fn create_msg_callback(
        agent_name: AgentName,
        config: &TlsPutConfig,
    ) -> impl Fn(&mut SslRef, i32, u8, bool) {
        let origin = config.descriptor.protocol_config.typ;
        let protocol_version = config.descriptor.protocol_config.tls_version;
        let claims = config.claims.clone();
        let extract_transcript = config.extract_deferred.clone();
        let authenticate_peer = config.authenticate_peer;

        move |context: &mut SslRef, content_type: i32, first_byte: u8, outbound: bool| {
            let typ = if content_type == 22 {
                HandshakeType::from(first_byte)
            } else {
                HandshakeType::Unknown(0)
            };

            if !outbound {
                match typ {
                    HandshakeType::Certificate => {
                        // Extract ClientHello..ServerFinished..Certificate transcript
                        // at the end of the message flight
                        *extract_transcript.deref().borrow_mut() =
                            Some(TypeShape::of::<TranscriptCertificate>());
                    }
                    HandshakeType::CertificateVerify => {
                        // Extract ClientHello..ServerFinished..CertificateVerify transcript
                        // at the end of the message flight
                        *extract_transcript.deref().borrow_mut() =
                            Some(TypeShape::of::<TranscriptServerFinished>());
                    }
                    HandshakeType::Finished => {
                        claims.deref_borrow_mut().claim_sized(TlsClaim {
                            agent_name,
                            origin,
                            protocol_version,
                            data: ClaimData::Message(ClaimDataMessage::Finished(Finished {
                                outbound,
                                client_random: context.client_random().into(),
                                server_random: context.server_random().into(),
                                session_id: Default::default(), // TODO
                                authenticate_peer,
                                peer_certificate: context
                                    .get_peer_certificate()
                                    .map(|cert| SmallVec::from_vec(cert))
                                    .unwrap_or_else(|| SmallVec::new()),
                                master_secret: Default::default(), // TODO
                                chosen_cipher: context.current_cipher() as u16,
                                available_ciphers: Default::default(), // TODO
                                signature_algorithm: 0,                // TODO
                                peer_signature_algorithm: 0,           // TODO
                            })),
                        });

                        // Extract ClientHello..ClientFinished transcript
                        // at the end of the message flight
                        *extract_transcript.deref().borrow_mut() =
                            Some(TypeShape::of::<TranscriptClientFinished>());
                    }
                    _ => {}
                }
            }

            // type only work correctly for inbound messages
            if let Some(transcript) = extract_current_transcript(context) {
                let claim = match context.server_state() {
                    wolfssl_sys::states_SERVER_HELLO_COMPLETE => {
                        // Extract ClientHello..ServerFinished transcript at the end of the message
                        // flight
                        *extract_transcript.deref().borrow_mut() =
                            Some(TypeShape::of::<TranscriptServerFinished>());

                        // Extract ClientHello..ServerHello transcript in-flight
                        Some(ClaimData::Transcript(ClaimDataTranscript::ServerHello(
                            TranscriptServerHello(transcript),
                        )))
                    }
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

impl<T> From<Result<T, SslError>> for MaybeError {
    fn from(result: Result<T, SslError>) -> Self {
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
