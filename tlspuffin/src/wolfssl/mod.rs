#![allow(non_snake_case)]

use std::{
    borrow::{Borrow, BorrowMut},
    cell::RefCell,
    ffi::{CStr, CString},
    io::{ErrorKind, Read, Write},
    mem::MaybeUninit,
    ops::Deref,
    os::raw::{c_uchar, c_void},
    rc::Rc,
};

use foreign_types::{ForeignType, ForeignTypeRef};
use puffin::{
    agent::{AgentDescriptor, AgentName, AgentType, TLSVersion},
    algebra::dynamic_function::TypeShape,
    error::Error,
    io::{MemoryStream, MessageResult, Stream},
    put::{Put, PutName},
    put_registry::Factory,
    trace::TraceContext,
};
use smallvec::SmallVec;

use crate::{
    claims::{
        ClaimData, ClaimDataMessage, ClaimDataTranscript, Finished, TlsClaim,
        TranscriptCertificate, TranscriptClientFinished, TranscriptClientHello,
        TranscriptServerFinished, TranscriptServerHello,
    },
    put::TlsPutConfig,
    put_registry::{TLSProtocolBehavior, WOLFSSL520_PUT},
    static_certs::{ALICE_CERT, ALICE_PRIVATE_KEY, BOB_CERT, BOB_PRIVATE_KEY, EVE_CERT},
    tls::rustls::msgs::{
        enums::HandshakeType,
        message::{Message, OpaqueMessage},
    },
    wolfssl::{
        bio::{MemBio, MemBioSlice},
        error::{ErrorStack, SslError},
        ssl::{Ssl, SslContext, SslContextRef, SslMethod, SslRef, SslStream, SslVerifyMode},
        transcript::extract_current_transcript,
        util::{cvt, cvt_n, cvt_p},
        version::version,
        x509::X509,
    },
};

mod bio;
mod callbacks;
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

pub fn new_wolfssl_factory() -> Box<dyn Factory<TLSProtocolBehavior>> {
    struct WolfSSLFactory;
    impl Factory<TLSProtocolBehavior> for WolfSSLFactory {
        fn create(
            &self,
            context: &TraceContext<TLSProtocolBehavior>,
            agent_descriptor: &AgentDescriptor,
        ) -> Result<Box<dyn Put<TLSProtocolBehavior>>, Error> {
            let config = TlsPutConfig {
                descriptor: agent_descriptor.clone(),
                claims: context.claims().clone(),
                authenticate_peer: agent_descriptor.typ == AgentType::Client
                    && agent_descriptor.server_authentication
                    || agent_descriptor.typ == AgentType::Server
                        && agent_descriptor.client_authentication,
                extract_deferred: Rc::new(RefCell::new(None)),
            };

            Ok(Box::new(WolfSSL::new(config)?))
        }

        fn name(&self) -> PutName {
            WOLFSSL520_PUT
        }

        fn version(&self) -> &'static str {
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
    stream: SslStream<MemoryStream<TLSProtocolBehavior>>,
    config: TlsPutConfig,
}

impl Stream<TLSProtocolBehavior> for WolfSSL {
    fn add_to_inbound(&mut self, result: &OpaqueMessage) {
        let raw_stream = self.stream.get_mut();
        raw_stream.add_to_inbound(result)
    }

    fn take_message_from_outbound(
        &mut self,
    ) -> Result<Option<MessageResult<Message, OpaqueMessage>>, Error> {
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
    fn new(config: TlsPutConfig) -> Result<Self, Error> {
        let agent_descriptor = &config.descriptor;
        let mut ctx = match agent_descriptor.typ {
            AgentType::Server => Self::create_server_ctx(agent_descriptor)?,
            AgentType::Client => Self::create_client_ctx(agent_descriptor)?,
        };

        #[cfg(not(feature = "wolfssl430"))]
        ctx.set_msg_callback(Self::create_msg_callback(agent_descriptor.name, &config))?;

        let mut stream = Self::new_stream(&ctx, &config)?;

        #[cfg(feature = "wolfssl430")]
        stream
            .ssl_mut()
            .set_msg_callback(Self::create_msg_callback(agent_descriptor.name, &config))?;

        let mut wolfssl = WolfSSL {
            ctx,
            stream,
            config: config.clone(),
        };

        #[cfg(feature = "claims")]
        stream.register_claimer(config.claims, config.agent_name);
        Ok(wolfssl)
    }

    fn new_stream(
        ctx: &SslContextRef,
        config: &TlsPutConfig,
    ) -> Result<SslStream<MemoryStream<TLSProtocolBehavior>>, Error> {
        let ssl = match config.descriptor.typ {
            AgentType::Server => Self::create_server(ctx)?,
            AgentType::Client => Self::create_client(ctx)?,
        };

        Ok(SslStream::new(ssl, MemoryStream::new())?)
    }
}

impl Put<TLSProtocolBehavior> for WolfSSL {
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

        self.deferred_transcript_extraction(agent_name);

        result
    }

    fn reset(&mut self, agent_name: AgentName) -> Result<(), Error> {
        self.stream = Self::new_stream(&self.ctx, &self.config)?;
        //self.stream.clear();
        Ok(())
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
    fn rename_agent(&mut self, agent_name: AgentName) -> Result<(), Error> {
        #[cfg(feature = "claims")]
        {
            self.deregister_claimer();
            self.register_claimer(agent_name);
        }

        #[cfg(not(feature = "wolfssl430"))]
        self.ctx
            .set_msg_callback(Self::create_msg_callback(agent_name, &self.config))?;

        #[cfg(feature = "wolfssl430")]
        self.stream
            .ssl_mut()
            .set_msg_callback(Self::create_msg_callback(agent_name, &self.config))?;

        Ok(())
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

    fn shutdown(&mut self) -> String {
        panic!("Unsupported with WolfSSL PUT")
    }

    fn descriptor(&self) -> &AgentDescriptor {
        &self.config.descriptor
    }
}

impl WolfSSL {
    pub fn create_client_ctx(descriptor: &AgentDescriptor) -> Result<SslContext, ErrorStack> {
        let mut ctx = match descriptor.tls_version {
            TLSVersion::V1_3 => SslContext::new(SslMethod::tls_client_13())?,
            TLSVersion::V1_2 => SslContext::new(SslMethod::tls_client_12())?,
        };

        ctx.disable_session_cache()?;

        if descriptor.client_authentication {
            let cert = X509::from_pem(BOB_CERT.0.as_bytes())?;
            ctx.set_certificate(cert.as_ref())?;

            #[cfg(not(feature = "wolfssl430"))]
            {
                let rsa = crate::wolfssl::rsa::Rsa::private_key_from_pem(
                    crate::static_certs::BOB_PRIVATE_KEY.0.as_bytes(),
                )?;
                let pkey = crate::wolfssl::pkey::PKey::from_rsa(rsa)?;
                ctx.set_private_key(pkey.as_ref())?;
            }
            #[cfg(feature = "wolfssl430")]
            {
                ctx.set_private_key_pem(BOB_PRIVATE_KEY.0.as_bytes())?;
            }
        }

        if descriptor.server_authentication {
            ctx.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
            ctx.load_verify_buffer(ALICE_CERT.0.as_bytes())?;
            ctx.load_verify_buffer(EVE_CERT.0.as_bytes())?;
        } else {
            // Disable certificate verify
            ctx.set_verify(SslVerifyMode::NONE);
        }

        // Disallow EXPORT in client
        ctx.set_cipher_list("ALL:!EXPORT:!LOW:!aNULL:!eNULL:!SSLv2")?;

        Ok(ctx)
    }

    pub fn create_client(ctx: &SslContextRef) -> Result<Ssl, ErrorStack> {
        let mut ssl: Ssl = Ssl::new(&ctx)?;
        ssl.set_connect_state();

        // Force requesting session ticket because `seed_successfull12` expects it.
        ssl.use_session_ticket();

        Ok(ssl)
    }

    pub fn create_server_ctx(descriptor: &AgentDescriptor) -> Result<SslContext, ErrorStack> {
        let mut ctx = match descriptor.tls_version {
            TLSVersion::V1_3 => SslContext::new(SslMethod::tls_server_13())?,
            TLSVersion::V1_2 => SslContext::new(SslMethod::tls_server_12())?,
        };

        // Mitigates "2. Misuse of sessions of different TLS versions (1.2, 1.3) from the session cache"
        ctx.disable_session_cache()?;

        // Disallow EXPORT in server
        ctx.set_cipher_list("ALL:!EXPORT:!LOW:!aNULL:!eNULL:!SSLv2")?;

        let cert = X509::from_pem(ALICE_CERT.0.as_bytes())?;
        ctx.set_certificate(cert.as_ref())?;

        #[cfg(not(feature = "wolfssl430"))]
        {
            let rsa =
                crate::wolfssl::rsa::Rsa::private_key_from_pem(ALICE_PRIVATE_KEY.0.as_bytes())?;
            let pkey = crate::wolfssl::pkey::PKey::from_rsa(rsa)?;
            ctx.set_private_key(pkey.as_ref())?;
        }
        #[cfg(feature = "wolfssl430")]
        {
            ctx.set_private_key_pem(ALICE_PRIVATE_KEY.0.as_bytes())?;
        }

        if descriptor.client_authentication {
            ctx.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
            ctx.load_verify_buffer(BOB_CERT.0.as_bytes())?;
            ctx.load_verify_buffer(EVE_CERT.0.as_bytes())?;
        } else {
            ctx.set_verify(SslVerifyMode::NONE);
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

    fn deferred_transcript_extraction(&self, agent_name: &AgentName) {
        let config = &self.config;
        if let Some(type_shape) = self.config.extract_deferred.deref().borrow_mut().take() {
            if let Some(transcript) = extract_current_transcript(self.stream.ssl()) {
                let CERT_SHAPE: TypeShape = TypeShape::of::<TranscriptCertificate>();
                let FINISHED_SHAPE: TypeShape = TypeShape::of::<TranscriptServerFinished>();
                let CLIENT_SHAPE: TypeShape = TypeShape::of::<TranscriptClientFinished>();

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
                        agent_name: *agent_name,
                        origin: config.descriptor.typ,
                        protocol_version: config.descriptor.tls_version,
                        data,
                    });
                }
            }
        }
    }

    fn create_msg_callback(
        agent_name: AgentName,
        config: &TlsPutConfig,
    ) -> impl Fn(&mut SslRef, HandshakeType, bool) {
        let origin = config.descriptor.typ;
        let protocol_version = config.descriptor.tls_version;
        let claims = config.claims.clone();
        let extract_transcript = config.extract_deferred.clone();
        let authenticate_peer = config.authenticate_peer;

        move |context: &mut SslRef, typ: HandshakeType, outbound: bool| unsafe {
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
                                client_random: Default::default(), // TODO
                                server_random: Default::default(), // TODO
                                session_id: Default::default(),    // TODO
                                authenticate_peer,
                                peer_certificate: context
                                    .get_peer_certificate()
                                    .unwrap_or_else(|| SmallVec::new()),
                                master_secret: Default::default(), // TODO
                                chosen_cipher: 0,                  // TODO
                                available_ciphers: Default::default(), // TODO
                                signature_algorithm: 0,            // TODO
                                peer_signature_algorithm: 0,       // TODO
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
                        // Extract ClientHello..ServerFinished transcript at the end of the message flight
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
