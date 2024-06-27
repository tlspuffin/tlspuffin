use core::ffi::c_void;
use std::{cell::RefCell, io::ErrorKind, rc::Rc};

use boring::{
    error::ErrorStack,
    ex_data::Index,
    ssl::{Ssl, SslContext, SslMethod, SslRef, SslStream, SslVerifyMode},
    x509::{store::X509StoreBuilder, X509},
};
use boringssl_sys::ssl_st;
use foreign_types::ForeignTypeRef;
use puffin::{
    agent::{AgentDescriptor, AgentName, AgentType},
    error::Error,
    put::{Put, PutName},
    put_registry::{Factory, PutKind},
    stream::{MemoryStream, Stream},
    trace::TraceContext,
    VERSION_STR,
};

use crate::{
    claims::{
        ClaimData, ClaimDataTranscript, TlsClaim, TranscriptCertificate, TranscriptClientFinished,
        TranscriptServerFinished, TranscriptServerHello,
    },
    protocol::{OpaqueMessageFlight, TLSProtocolBehavior},
    put::TlsPutConfig,
    put_registry::BORINGSSL_PUT,
    query::TlsQueryMatcher,
    static_certs::{ALICE_CERT, ALICE_PRIVATE_KEY, BOB_CERT, BOB_PRIVATE_KEY, EVE_CERT},
    tls::rustls::msgs::message::{Message, OpaqueMessage},
};

mod bindings;
mod deterministic;
mod transcript;

use std::ops::Deref;

use transcript::extract_current_transcript;

pub fn new_boringssl_factory() -> Box<dyn Factory<TLSProtocolBehavior>> {
    #[derive(Clone)]
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
                log::info!("BoringSSL put does not support clearing mode")
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

        fn kind(&self) -> PutKind {
            PutKind::Rust
        }

        fn name(&self) -> PutName {
            BORINGSSL_PUT
        }

        fn versions(&self) -> Vec<(String, String)> {
            let boringssl_shortname = if cfg!(feature = "boringssl202311") {
                "boringssl202311"
            } else if cfg!(feature = "boringssl202403") {
                "boringssl202403"
            } else if cfg!(feature = "boringsslmaster") {
                "master"
            } else {
                "unknown"
            };

            vec![
                (
                    "harness".to_string(),
                    format!("{} ({})", BORINGSSL_PUT, VERSION_STR),
                ),
                (
                    "library".to_string(),
                    format!(
                        "boringssl ({} / {})",
                        boringssl_shortname,
                        BoringSSL::version()
                    ),
                ),
            ]
        }

        fn rng_reseed(&self) {
            log::debug!("[RNG] reseed ({})", self.name());
            deterministic::rng_reseed();
        }

        fn clone_factory(&self) -> Box<dyn Factory<TLSProtocolBehavior>> {
            Box::new(self.clone())
        }
    }

    Box::new(BoringSSLFactory)
}

pub struct BoringSSL {
    stream: SslStream<MemoryStream>,
    config: TlsPutConfig,
}

impl Drop for BoringSSL {
    fn drop(&mut self) {
        self.deregister_claimer();
    }
}

impl Stream<TlsQueryMatcher, Message, OpaqueMessage, OpaqueMessageFlight> for BoringSSL {
    fn add_to_inbound(&mut self, result: &OpaqueMessageFlight) {
        <MemoryStream as Stream<
            TlsQueryMatcher,
            Message,
            OpaqueMessage,
            OpaqueMessageFlight,
        >>::add_to_inbound(self.stream.get_mut(), result)
    }

    fn take_message_from_outbound(&mut self) -> Result<Option<OpaqueMessageFlight>, Error> {
        let memory_stream = self.stream.get_mut();

        <MemoryStream as Stream<
            TlsQueryMatcher,
            Message,
            OpaqueMessage,
            OpaqueMessageFlight,
        >>::take_message_from_outbound(memory_stream)
    }
}

impl Put<TLSProtocolBehavior> for BoringSSL {
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
        self.stream.ssl_mut().clear();
        self.register_claimer();
        Ok(())
    }

    fn descriptor(&self) -> &AgentDescriptor {
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
        panic!("Unsupported with BoringSSL PUT")
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
        let stream = SslStream::new(ssl, MemoryStream::new())?;
        let mut boringssl = BoringSSL { config, stream };

        boringssl.register_claimer();
        Ok(boringssl)
    }

    fn create_server(descriptor: &AgentDescriptor) -> Result<Ssl, ErrorStack> {
        let mut ctx_builder = SslContext::builder(SslMethod::tls())?;

        let (cert, key) =
            bindings::static_rsa_cert(ALICE_PRIVATE_KEY.0.as_bytes(), ALICE_CERT.0.as_bytes())?;
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

        bindings::set_max_protocol_version(&mut ctx_builder, descriptor.tls_version)?;

        // Allow EXPORT in server
        ctx_builder.set_cipher_list("ALL:EXPORT:!LOW:!aNULL:!eNULL:!SSLv2")?;

        let mut ssl = Ssl::new(&ctx_builder.build())?;
        ssl.set_accept_state();

        Ok(ssl)
    }

    fn create_client(descriptor: &AgentDescriptor) -> Result<Ssl, ErrorStack> {
        let mut ctx_builder = SslContext::builder(SslMethod::tls())?;
        bindings::set_max_protocol_version(&mut ctx_builder, descriptor.tls_version)?;

        // Disallow EXPORT in client
        ctx_builder.set_cipher_list("ALL:!EXPORT:!LOW:!aNULL:!eNULL:!SSLv2")?;

        ctx_builder.set_verify(SslVerifyMode::NONE);

        if descriptor.client_authentication {
            let (cert, key) =
                bindings::static_rsa_cert(BOB_PRIVATE_KEY.0.as_bytes(), BOB_CERT.0.as_bytes())?;
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
        let origin = config.descriptor.typ;
        let protocol_version = config.descriptor.tls_version;
        let claims = config.claims.clone();

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
                        // Not actually an error, we just reached the end of the stream, thrown in MemoryStream
                        // log::debug!("Would have blocked but the underlying stream is non-blocking!");
                        MaybeError::Ok
                    }
                    _ => MaybeError::Err(Error::IO(format!("Unexpected IO Error: {}", io_error))),
                }
            } else if let Some(ssl_error) = ssl_error.ssl_error() {
                // BoringSSL threw an error, that means that there should be an Alert message in the
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
