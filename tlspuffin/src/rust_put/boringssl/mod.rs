use core::ffi::c_void;
use std::io::ErrorKind;

use boring::error::ErrorStack;
use boring::ex_data::Index;
use boring::ssl::{Ssl, SslContext, SslMethod, SslOptions, SslRef, SslStream, SslVerifyMode};
use boring::x509::store::X509StoreBuilder;
use boring::x509::X509;
use boringssl_sys::ssl_st;
use foreign_types::ForeignTypeRef;
use puffin::agent::{AgentDescriptor, AgentName};
use puffin::error::Error;
use puffin::put::Put;
use puffin::stream::{MemoryStream, Stream};
use smallvec::SmallVec;
use util::{set_max_protocol_version, static_rsa_cert};

use crate::claims::{
    ClaimData, ClaimDataMessage, ClaimDataTranscript, Finished, TlsClaim, TranscriptCertificate,
    TranscriptClientFinished, TranscriptServerFinished, TranscriptServerHello,
};
use crate::protocol::{
    AgentType, OpaqueMessageFlight, TLSDescriptorConfig, TLSProtocolBehavior, TLSVersion,
};
use crate::put::TlsPutConfig;
use crate::static_certs::{ALICE_CERT, ALICE_PRIVATE_KEY, BOB_CERT, BOB_PRIVATE_KEY, EVE_CERT};

mod transcript;
mod util;

use std::ops::Deref;

use puffin::algebra::ConcreteMessage;
use transcript::extract_current_transcript;

pub struct RustPut {
    stream: SslStream<MemoryStream>,
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

    fn descriptor(&self) -> &AgentDescriptor<TLSDescriptorConfig> {
        &self.config.descriptor
    }

    fn reset(&mut self, new_name: AgentName) -> Result<(), Error> {
        self.config.descriptor.name = new_name;
        self.deregister_claimer();
        self.stream.ssl_mut().clear();
        self.register_claimer();
        Ok(())
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
        boring::version::version().to_string()
    }
}

impl RustPut {
    pub fn new(config: TlsPutConfig) -> Result<Self, Error> {
        // FIXME: Add non-clear method like in wolfssl
        if !config.use_clear {
            log::info!("BoringSSL PUT does not support clearing mode")
        }

        Self::new_agent(config)
            .map_err(|err| Error::Put(format!("Failed to create agent: {}", err)))
    }

    fn new_agent(config: TlsPutConfig) -> Result<Self, ErrorStack> {
        let agent_descriptor = &config.descriptor;
        let ssl = match agent_descriptor.protocol_config.typ {
            AgentType::Server => Self::create_server(agent_descriptor)?,
            AgentType::Client => Self::create_client(agent_descriptor)?,
        };

        let stream = SslStream::new(ssl, MemoryStream::new())?;
        let mut boringssl = RustPut { config, stream };

        boringssl.register_claimer();
        Ok(boringssl)
    }

    fn create_server(descriptor: &AgentDescriptor<TLSDescriptorConfig>) -> Result<Ssl, ErrorStack> {
        let mut ctx_builder = SslContext::builder(SslMethod::tls())?;

        let (cert, key) = static_rsa_cert(ALICE_PRIVATE_KEY.0.as_bytes(), ALICE_CERT.0.as_bytes())?;
        ctx_builder.set_certificate(&cert)?;
        ctx_builder.set_private_key(&key)?;

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

        set_max_protocol_version(&mut ctx_builder, descriptor.protocol_config.tls_version)?;

        match descriptor.protocol_config.tls_version {
            TLSVersion::V1_3 => {
                ctx_builder.set_cipher_list(&descriptor.protocol_config.cipher_string_tls13)?;
            }
            TLSVersion::V1_2 => {
                ctx_builder.set_cipher_list(&descriptor.protocol_config.cipher_string_tls12)?;
            }
        }

        if let Some(groups) = &descriptor.protocol_config.groups {
            ctx_builder.set_groups(groups)?;
        }

        let mut ssl = Ssl::new(&ctx_builder.build())?;
        ssl.set_accept_state();

        Ok(ssl)
    }

    fn create_client(descriptor: &AgentDescriptor<TLSDescriptorConfig>) -> Result<Ssl, ErrorStack> {
        let mut ctx_builder = SslContext::builder(SslMethod::tls())?;
        set_max_protocol_version(&mut ctx_builder, descriptor.protocol_config.tls_version)?;

        match descriptor.protocol_config.tls_version {
            TLSVersion::V1_3 => {
                ctx_builder.set_cipher_list(&descriptor.protocol_config.cipher_string_tls13)?;
            }
            TLSVersion::V1_2 => {
                ctx_builder.set_cipher_list(&descriptor.protocol_config.cipher_string_tls12)?;
            }
        }

        if let Some(groups) = &descriptor.protocol_config.groups {
            ctx_builder.set_groups(groups)?;
        }

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

        let mut ssl = Ssl::new(&ctx_builder.build())?;
        ssl.set_connect_state();

        Ok(ssl)
    }

    fn register_claimer(&mut self) {
        self.set_msg_callback(Self::create_msg_callback(&self.config))
            .expect("Failed to set msg_callback to extract transcript");
    }

    fn deregister_claimer(&mut self) {
        // TODO implement deregister_claimer for BoringSSL
    }

    /// Set the msg_callback of BoringSSL
    ///
    /// Here we use a intermediate callback, `boring_msg_callback`, to call the
    /// `callback` function `callback` is stored in the boringssl ex_data to be
    /// retrieved and executed by `boring_msg_callback`
    fn set_msg_callback<F>(&mut self, callback: F) -> Result<(), ErrorStack>
    where
        F: Fn(&mut SslRef, i32) + 'static,
    {
        unsafe {
            let ssl = self.stream.ssl_mut();
            ssl.set_ex_data(Index::from_raw(0), callback);
            let ssl_ptr = ssl.as_ptr();
            boringssl_sys::SSL_set_msg_callback(ssl_ptr, Some(boring_msg_callback::<F>));

            Ok(())
        }
    }

    /// This callback gets the actual hash transcript of the SSL handshake and
    /// add it to the claims
    fn create_msg_callback(config: &TlsPutConfig) -> impl Fn(&mut SslRef, i32) {
        let agent_name = config.descriptor.name;
        let origin = config.descriptor.protocol_config.typ;
        let protocol_version = config.descriptor.protocol_config.tls_version;
        let claims = config.claims.clone();
        let authenticate_peer = config.authenticate_peer;

        move |ssl: &mut SslRef, info_type: i32| {
            log::trace!(
                "BORING MSG CALLBACK : {} -- {}",
                ssl.state_string_long(),
                info_type
            );

            let claim = match (ssl.state_string_long(), info_type) {
                ("TLS 1.3 server read_client_finished", 256) => extract_current_transcript(ssl)
                    .map_or(None, |t| {
                        Some(ClaimData::Transcript(ClaimDataTranscript::ClientFinished(
                            TranscriptClientFinished(t),
                        )))
                    }),
                ("TLS 1.3 server send_server_hello", 256) => extract_current_transcript(ssl)
                    .map_or(None, |t| {
                        Some(ClaimData::Transcript(ClaimDataTranscript::ServerHello(
                            TranscriptServerHello(t),
                        )))
                    }),
                ("TLS 1.3 server send_server_finished", 256) => extract_current_transcript(ssl)
                    .map_or(None, |t| {
                        Some(ClaimData::Transcript(ClaimDataTranscript::ServerFinished(
                            TranscriptServerFinished(t),
                        )))
                    }),
                ("TLS 1.3 server read_client_certificate", 256) => extract_current_transcript(ssl)
                    .map_or(None, |t| {
                        Some(ClaimData::Transcript(ClaimDataTranscript::Certificate(
                            TranscriptCertificate(t),
                        )))
                    }),
                ("TLS 1.3 server read_client_finished", 22) => {
                    Some(Self::get_finished_claim(ssl, false, authenticate_peer))
                }
                ("TLS 1.3 client complete_second_flight", 22) => {
                    Some(Self::get_finished_claim(ssl, true, authenticate_peer))
                }
                _ => None,
            };

            if let Some(data) = claim {
                claims.deref_borrow_mut().claim_sized(TlsClaim {
                    agent_name,
                    origin,
                    protocol_version,
                    data,
                    step: None,
                });
            }
        }
    }

    fn get_finished_claim(ssl: &mut SslRef, outbound: bool, authenticate_peer: bool) -> ClaimData {
        let mut client_random = vec![0u8; 32];
        let mut server_random = vec![0u8; 32];
        ssl.client_random(client_random.as_mut_slice());
        ssl.server_random(server_random.as_mut_slice());

        let cipher = ssl.current_cipher().unwrap();
        let cipher_id = cipher.cipher_id();

        let session = ssl.session().unwrap();

        let session_id: SmallVec<[u8; 32]> = session.id().into();

        let mut master_secret = vec![0u8; 32];
        session.master_key(master_secret.as_mut_slice());

        let peer_certificate = ssl
            .peer_certificate()
            .map_or(vec![], |x| x.to_der().unwrap());

        ClaimData::Message(ClaimDataMessage::Finished(Finished {
            outbound,
            client_random: client_random.into(),
            server_random: server_random.into(),
            session_id,
            authenticate_peer,
            peer_certificate: peer_certificate.into(),
            master_secret: master_secret.into(),
            chosen_cipher: cipher_id as u16,
            available_ciphers: Default::default(), // TODO
            signature_algorithm: 0,                // TODO
            peer_signature_algorithm: 0,           // TODO
            early_secret: Default::default(),      // TODO
            handshake_secret: Default::default(),  // TODO
        }))
    }
}

pub enum MaybeError {
    Ok,
    Err(Error),
}

/// This callback uses boringssl ex_data to get a pointer to the real callback
/// and to execute it.
///
/// This allows to use a closure as a callback since `SSL_set_msg_callback`
/// accepts only `unsafe extern "C"` functions
pub unsafe extern "C" fn boring_msg_callback<F>(
    _write_p: i32,
    _version: i32,
    content_type: i32,
    _buf: *const c_void,
    _len: usize,
    ssl: *mut ssl_st,
    _arg: *mut c_void,
) where
    F: Fn(&mut SslRef, i32) + 'static,
{
    let ssl = SslRef::from_ptr_mut(ssl);

    // Getting the callback from ex_data index 0
    let callback = {
        let callback = ssl
            .ex_data::<F>(Index::from_raw(0))
            .expect("BUG: missing info_callback");

        callback.deref() as *const F
    };

    (*callback)(ssl, content_type);
}

impl<T> From<Result<T, boring::ssl::Error>> for MaybeError {
    fn from(result: Result<T, boring::ssl::Error>) -> Self {
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
