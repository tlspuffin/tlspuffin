//! Generic [`PUT`] trait defining an interface with a TLS library with which we can:
//! - [`new`] create a client (or server) new initial state + bind buffers
//! - [`progress`] makes a state progress (interacting with the buffers)
//!
//! And specific implementations of PUT for the different PUTs.
use crate::agent::{AgentName, TLSVersion};
use crate::error::Error;
use crate::io::MessageResult;
use crate::io::{MemoryStream, Stream};
use crate::openssl_binding::openssl_version;
use crate::trace::VecClaimer;
#[cfg(feature = "wolfssl")]
use crate::wolfssl_binding;
use crate::{io, openssl_binding};
use foreign_types_shared::ForeignTypeRef;
use rustls::msgs::message::OpaqueMessage;
use security_claims::{deregister_claimer, register_claimer, Claim};
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::io::{Read, Write};
use std::rc::Rc;

/// Stream, Read, Write traits below are with respect to this content type // [TODO:PUT] how one can make this precise in the type (Without modifing those traits specs?)
pub type Bts<'a> = &'a [u8];

/// Static configuration for creating a new agent state for the PUT
pub struct Config {
    pub tls_version: TLSVersion,
    /// Whether the agent which holds this descriptor is a server.
    pub server: bool,
    ///
    pub agent_name: AgentName,
    ///
    pub claimer: Rc<RefCell<VecClaimer>>,
}

#[derive(Debug, Copy, Clone, Deserialize, Serialize, Eq, PartialEq)]
pub enum PUTType {
    OpenSSL,
    #[cfg(feature = "wolfssl")]
    WolfSSL,
}
pub trait PUT: Stream + Drop {
    /// Create a new agent state for the PUT + set up buffers/BIOs
    fn new(c: Config) -> Result<Self, Error>
    where
        Self: Sized;
    /// Process incoming buffer, internal progress, can fill in output buffer
    fn progress(&mut self) -> Result<(), Error>;
    /// In-place reset of the state
    fn reset(&mut self) -> Result<(), Error>;
    /// Register a new claim for agent_name
    fn register_claimer(&mut self, claimer: Rc<RefCell<VecClaimer>>, agent_name: AgentName);
    /// Remove all claims in self
    fn deregister_claimer(&mut self) -> ();
    /// Change the agent name and the claimer of self
    fn change_agent_name(&mut self, claimer: Rc<RefCell<VecClaimer>>, agent_name: AgentName);
    /// Returns a textual representation of the state in which self is
    fn describe_state(&self) -> &'static str;
    /// Returns a textual representation of the version of the PUT used by self
    fn version(&self) -> &'static str;
    /// Make the PUT used by self determimistic in the future by making its PRNG "deterministic"
    fn make_deterministic(&self) -> ();
}

pub fn put_version() -> &'static str {
    let c = Config {
        tls_version: TLSVersion::V1_3,
        server: false,
        agent_name: AgentName::new(),
        claimer: Rc::new(RefCell::new(VecClaimer::new())),
    };
    let put: Box<dyn PUT> = Box::new(OpenSSL::new(c).expect("Failed to create a put instance"));

    put.as_ref().version()
}

pub fn put_make_deterministic() -> () {
    let c = Config {
        tls_version: TLSVersion::V1_3,
        server: false,
        agent_name: AgentName::new(),
        claimer: Rc::new(RefCell::new(VecClaimer::new())),
    };
    let put: Box<dyn PUT> = Box::new(OpenSSL::new(c).expect("Failed to create a put instance"));

/*        #[cfg(feature = "wolfssl")]
        Box::new(crate::concretize::wolfssl::WolfSSL::new(c).expect("Failed to create a put instance"))
*/
    put.as_ref().make_deterministic()
}

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////// OpenSSL specific-state
////////////////////////////////////////////////////////////////////////////////////////////////////

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

impl Read for OpenSSL {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.stream.get_mut().read(buf)
    }
}

impl Write for OpenSSL {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.stream.get_mut().write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.get_mut().flush()
    }
}

impl PUT for OpenSSL {
    fn new(c: Config) -> Result<OpenSSL, Error> {
        let memory_stream = MemoryStream::new();
        let stream = if c.server {
            //let (cert, pkey) = openssl_binding::generate_cert();
            let (cert, pkey) = openssl_binding::static_rsa_cert()?;
            openssl_binding::create_openssl_server(memory_stream, &cert, &pkey, &c.tls_version)?
        } else {
            openssl_binding::create_openssl_client(memory_stream, &c.tls_version)?
        };

        let mut stream = OpenSSL { stream };
        OpenSSL::register_claimer(&mut stream, c.claimer, c.agent_name);
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
        register_claimer(self.stream.ssl().as_ptr().cast(), move |claim: Claim| {
            (*claimer).borrow_mut().claim(agent_name, claim)
        });
    }

    fn deregister_claimer(&mut self) -> () {
        #[cfg(feature = "claims")]
        deregister_claimer(self.stream.ssl().as_ptr().cast());
    }

    fn change_agent_name(self: &mut Self, claimer: Rc<RefCell<VecClaimer>>, agent_name: AgentName) {
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

    fn version(&self) -> &'static str {
        openssl_version()
    }

    fn make_deterministic(&self) -> () {
        openssl_binding::make_deterministic();
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////// WolfSSL specific-state
////////////////////////////////////////////////////////////////////////////////////////////////////
#[cfg(feature = "wolfssl")]
pub mod wolfssl {
    use std::cell::RefCell;
    use std::io::{Read, Write};
    use std::rc::Rc;
    use rustls::msgs::message::OpaqueMessage;
    use security_claims::{deregister_claimer, register_claimer};
    use crate::error::Error;
    use crate::io::{MemoryStream, MessageResult, Stream};
    use crate::{openssl_binding, wolfssl_binding};
    use crate::agent::AgentName;
    use crate::concretize::{Config, PUT};
    use crate::trace::VecClaimer;
    use security_claims::Claim;

    pub struct WolfSSL {
        stream: wolfssl_binding::SslStream<MemoryStream>,
    }

    impl Stream for WolfSSL {
        fn add_to_inbound(&mut self, result: &OpaqueMessage) {
            let a = self.stream.get_mut();
            a.add_to_inbound(result)  // SEGFAULT: here a = NULL when we execute the first input, which triggers add_to_inbound here! Somehow, bio initialization fails !
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
            WolfSSL::deregister_claimer(self);
        }
    }

    impl PUT for WolfSSL {
        fn new(c: Config) -> Result<Self, Error>
            where
                Self: Sized, {
            let memory_stream = MemoryStream::new();
            let stream = if c.server {
                // we reuse static data obtained through the OpenSSL PUT, which is OK
                let (cert, pkey) = openssl_binding::static_rsa_cert()?;
                wolfssl_binding::create_server(memory_stream, &cert, &pkey, &c.tls_version)?
            } else {
                wolfssl_binding::create_client(memory_stream, &c.tls_version)?
            };

            let mut stream = WolfSSL { stream };
            WolfSSL::register_claimer(&mut stream, c.claimer, c.agent_name);
            Ok(stream)
        }

        fn progress(&mut self) -> Result<(), Error> {
            wolfssl_binding::do_handshake(&mut self.stream)
        }

        fn reset(&mut self) -> Result<(), Error> {
            self.stream.clear();
            Ok(())
        }

        fn register_claimer(&mut self, claimer: Rc<RefCell<VecClaimer>>, agent_name: AgentName) {
            #[cfg(feature = "claims")]
            register_claimer(self.stream.ssl.as_ptr().cast(), move |claim: Claim| {
                (*claimer).borrow_mut().claim(agent_name, claim)
            });
        }

        fn deregister_claimer(&mut self) -> () {
            #[cfg(feature = "claims")]
            deregister_claimer(self.stream.ssl().as_ptr().cast());
        }

        fn change_agent_name(&mut self, claimer: Rc<RefCell<VecClaimer>>, agent_name: AgentName) {
            WolfSSL::deregister_claimer(self);
            WolfSSL::register_claimer(self, claimer, agent_name)
        }

        fn describe_state(&self) -> &'static str {
            // Very useful for nonblocking according to docs:
            // https://www.openssl.org/docs/manmaster/man3/SSL_state_string.html
            // When using nonblocking sockets, the function call performing the handshake may return
            // with SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE condition,
            // so that SSL_state_string[_long]() may be called.
            self.stream.state_string_long()
        }

        fn version(&self) -> &'static str {
            self.stream.version()
        }

        fn make_deterministic(&self) -> () {
            () // TODO
        }
    }
}