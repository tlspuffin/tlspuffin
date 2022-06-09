use std::{cell::RefCell, io, rc::Rc};

use foreign_types_shared::ForeignTypeRef;
use openssl::error::ErrorStack;
use rustls::msgs::message::OpaqueMessage;
use security_claims::{deregister_claimer, register_claimer};

use crate::{
    agent::{AgentName, PutName},
    concretize::{Config, Factory, Put, OPENSSL111},
    error::Error,
    io::{MemoryStream, MessageResult, Stream},
    openssl::{openssl_binding::openssl_version, static_keys::static_rsa_cert},
    trace::VecClaimer,
};

mod openssl_binding;
mod static_keys;

pub fn new_openssl_factory() -> Box<dyn Factory> {
    struct OpenSSLFactory;
    impl Factory for OpenSSLFactory {
        fn create(&self, config: Config) -> Box<dyn Put> {
            Box::new(OpenSSL::new(config).unwrap())
        }

        fn put_name(&self) -> PutName {
            OPENSSL111
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

impl From<openssl::error::ErrorStack> for Error {
    fn from(err: ErrorStack) -> Self {
        Error::OpenSSL(err.to_string())
    }
}

pub struct OpenSSL {
    stream: openssl::ssl::SslStream<MemoryStream>,
}

impl Drop for OpenSSL {
    fn drop(&mut self) {
        #[cfg(feature = "claims")]
        OpenSSL::deregister_claimer(self);
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

impl io::Read for OpenSSL {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.stream.get_mut().read(buf)
    }
}

impl io::Write for OpenSSL {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.stream.get_mut().write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.get_mut().flush()
    }
}

impl Put for OpenSSL {
    fn new(config: Config) -> Result<OpenSSL, Error> {
        let memory_stream = MemoryStream::new();
        let stream = if config.server {
            //let (cert, pkey) = openssl_binding::generate_cert();
            let (cert, pkey) = static_rsa_cert()?;
            openssl_binding::create_openssl_server(
                memory_stream,
                &cert,
                &pkey,
                &config.tls_version,
            )?
        } else {
            openssl_binding::create_openssl_client(memory_stream, &config.tls_version)?
        };

        let mut stream = OpenSSL { stream };
        OpenSSL::register_claimer(&mut stream, config.claimer, config.agent_name);
        Ok(stream)
    }

    fn progress(&mut self) -> Result<(), Error> {
        openssl_binding::do_handshake(&mut self.stream)
    }

    fn reset(&mut self) -> Result<(), Error> {
        self.stream.clear();
        Ok(())
    }

    fn register_claimer(&mut self, claimer: Rc<RefCell<VecClaimer>>, agent_name: AgentName) {
        #[cfg(feature = "claims")]
        unsafe {
            use security_claims::Claim;
            register_claimer(self.stream.ssl().as_ptr().cast(), move |claim: Claim| {
                (*claimer).borrow_mut().claim(agent_name, claim)
            });
        }
    }

    fn deregister_claimer(&mut self) {
        #[cfg(feature = "claims")]
        unsafe {
            deregister_claimer(self.stream.ssl().as_ptr().cast());
        }
    }

    fn change_agent_name(&mut self, claimer: Rc<RefCell<VecClaimer>>, agent_name: AgentName) {
        OpenSSL::deregister_claimer(self);
        OpenSSL::register_claimer(self, claimer, agent_name)
    }

    fn describe_state(&self) -> &'static str {
        // Very useful for nonblocking according to docs:
        // https://www.openssl.org/docs/manmaster/man3/SSL_state_string.html
        // When using nonblocking sockets, the function call performing the handshake may return
        // with SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE condition,
        // so that SSL_state_string[_long]() may be called.
        self.stream.ssl().state_string_long()
    }

    fn version() -> &'static str {
        openssl_version()
    }

    fn make_deterministic() {
        openssl_binding::make_deterministic();
    }
}
