#![allow(non_snake_case)]

use std::{
    cell::RefCell,
    io::{Read, Write},
    rc::Rc,
};

use rustls::msgs::message::OpaqueMessage;

use self::wolfssl_binding::wolfssl_version;
use crate::{
    agent::{AgentName, PutName},
    concretize::{Config, Put},
    error::Error,
    io::{MemoryStream, MessageResult, Stream},
    registry::{Factory, WOLFSSL520},
    trace::VecClaimer,
    wolfssl::error::SslError,
};

mod error;
mod util;
mod wolfssl_binding;
mod wolfssl_bio;

pub fn new_wolfssl_factory() -> Box<dyn Factory> {
    struct WolfSSLFactory;
    impl Factory for WolfSSLFactory {
        fn create(&self, config: Config) -> Box<dyn Put> {
            Box::new(WolfSSL::new(config).unwrap())
        }

        fn put_name(&self) -> PutName {
            WOLFSSL520
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

impl From<SslError> for Error {
    fn from(err: SslError) -> Self {
        Error::OpenSSL(err.to_string())
    }
}

pub struct WolfSSL {
    stream: wolfssl_binding::SslStream<MemoryStream>,
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

impl Read for WolfSSL {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.stream.get_mut().read(buf)
    }
}

impl Write for WolfSSL {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.stream.get_mut().write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.get_mut().flush()
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

impl Put for WolfSSL {
    fn new(c: Config) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let memory_stream = MemoryStream::new();
        let stream = if c.server {
            // we reuse static data obtained through the OpenSSL PUT, which is OK
            // FIXME: let (cert, pkey) = openssl_binding::static_rsa_cert()?;
            wolfssl_binding::create_server(memory_stream, &c.tls_version)?
        } else {
            wolfssl_binding::create_client(memory_stream, &c.tls_version)?
        };

        let wolfssl = WolfSSL { stream };
        #[cfg(feature = "claims")]
        unsafe {
            wolfssl.register_claimer(c.claimer, c.agent_name);
        }
        Ok(wolfssl)
    }

    fn progress(&mut self) -> Result<(), Error> {
        wolfssl_binding::do_handshake(&mut self.stream)?;
        Ok(())
    }

    fn reset(&mut self) -> Result<(), Error> {
        self.stream.clear();
        Ok(())
    }

    #[cfg(feature = "claims")]
    fn register_claimer(&mut self, claimer: Rc<RefCell<VecClaimer>>, agent_name: AgentName) {
        unsafe {
            security_claims::register_claimer(
                self.stream.ssl.as_ptr().cast(),
                move |claim: Claim| (*claimer).borrow_mut().claim(agent_name, claim),
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
    fn change_agent_name(&mut self, claimer: Rc<RefCell<VecClaimer>>, agent_name: AgentName) {
        #[cfg(feature = "claims")]
        unsafe {
            self.deregister_claimer();
            self.register_claimer(claimer, agent_name)
        }
    }

    fn describe_state(&self) -> &'static str {
        // Very useful for nonblocking according to docs:
        // https://www.openssl.org/docs/manmaster/man3/SSL_state_string.html
        // When using nonblocking sockets, the function call performing the handshake may return
        // with SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE condition,
        // so that SSL_state_string[_long]() may be called.
        self.stream.state_string_long()
    }

    fn version() -> &'static str {
        unsafe { wolfssl_version() }
    }

    fn make_deterministic() {
        // TODO
    }

    fn is_state_successful(&self) -> bool {
        self.stream.is_handshake_done()
    }
}
