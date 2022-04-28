//! Generic [`PUT`] trait defining an interface with a TLS library with which we can:
//! - [`new`] create a client (or server) new initial state + bind buffers
//! - [`progress`] makes a state progress (interacting with the buffers)
//!
//! And specific implementations of PUT for the different PUTs.
use std::cell::RefCell;
use crate::io::MessageResult;
use crate::{io, openssl_binding};
use openssl::ssl::SslStream;
use rustls::msgs::message::OpaqueMessage;
use std::io::{Read, Write};
use std::rc::Rc;
use foreign_types_shared::ForeignTypeRef;
use security_claims::{deregister_claimer, register_claimer, Claim};
use crate::agent::{AgentName, TLSVersion};
use crate::error::Error;
use crate::io::{MemoryStream, Stream};
use crate::trace::VecClaimer;

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

pub trait PUT: Stream + Drop {
    /// An agent state for the PUT
    type State;

    /// Create a new agent state for the PUT + set up buffers/BIOs
    fn new(c: Config) -> Result<<Self as PUT>::State, Error>;
    /// Process incoming buffer, internal progress, can fill in output buffer
    fn progress(s: &mut <Self as PUT>::State) -> Result<(), Error>;
    /// In-place reset of the state
    fn reset(s: &mut <Self as PUT>::State) -> Result<(), Error>;
    ///
    fn register_claimer(s: &mut <Self as PUT>::State, claimer: Rc<RefCell<VecClaimer>>, agent_name: AgentName);
    ///
    fn deregister_claimer(s: &mut <Self as PUT>::State) -> ();
}

impl OpenSSL {
    pub fn change_agent_name(self: &mut Self, claimer: Rc<RefCell<VecClaimer>>, agent_name: AgentName) {
        OpenSSL::deregister_claimer(self);
        OpenSSL::register_claimer(self,claimer, agent_name)
    }
}

// TODO: find a way to conditionally define the specific instantiation we shall use like
// pub type PUTState = if cfg!(openssl) then OpenSSL else WolfSSL;

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////// OpenSSL specific-state
////////////////////////////////////////////////////////////////////////////////////////////////////

pub struct OpenSSL {
    stream: SslStream<MemoryStream>,
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
    type State = OpenSSL;

    fn new(c: Config) -> Result<OpenSSL, Error> {
        // [TODO::PUT] will replace io::PUTState::new
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

    fn progress(s: &mut <Self as PUT>::State) -> Result<(), Error> {
        let stream = &mut s.stream;
        openssl_binding::do_handshake(stream)
    }

    fn reset(s: &mut <Self as PUT>::State) -> Result<(), Error> {
        s.stream.clear();
        Ok(())
    }

    fn register_claimer(s: &mut <Self as PUT>::State, claimer: Rc<RefCell<VecClaimer>>, agent_name: AgentName) {
        #[cfg(feature = "claims")]
        register_claimer(
            s.stream.ssl().as_ptr().cast(),
            move |claim: Claim| (*claimer).borrow_mut().claim(agent_name, claim),
        );
    }

    fn deregister_claimer(s: &mut <Self as PUT>::State) -> () {
        #[cfg(feature = "claims")]
        deregister_claimer(s.stream.ssl().as_ptr().cast());
    }
}

impl OpenSSL {
    pub fn describe_state(&self) -> &'static str {
        // Very useful for nonblocking according to docs:
        // https://www.openssl.org/docs/manmaster/man3/SSL_state_string.html
        // When using nonblocking sockets, the function call performing the handshake may return
        // with SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE condition,
        // so that SSL_state_string[_long]() may be called.
        self.stream.ssl().state_string_long()
    }
}
////////////////////////////////////////////////////////////////////////////////////////////////////
////////////// WolfSSL specific-state
////////////////////////////////////////////////////////////////////////////////////////////////////

pub struct WolfSSL {
    // [TODO::PUT]
}

impl Stream for WolfSSL {
    fn add_to_inbound(&mut self, result: &OpaqueMessage) {
        todo!()
    }

    fn take_message_from_outbound(&mut self) -> Result<Option<MessageResult>, Error> {
        todo!()
    }
}

impl Read for WolfSSL {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        todo!()
    }
}

impl Write for WolfSSL {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        todo!()
    }

    fn flush(&mut self) -> std::io::Result<()> {
        todo!()
    }
}

impl Drop for WolfSSL {
    fn drop(&mut self) {
        todo!()
    }
}

impl PUT for WolfSSL {
    type State = WolfSSL;

    fn new(c: Config) -> Result<<Self as PUT>::State, Error> {
        todo!()
    }

    fn progress(s: &mut <Self as PUT>::State) -> Result<(), Error> {
        todo!()
    }

    fn reset(s: &mut <Self as PUT>::State) -> Result<(), Error> {
        todo!()
    }

    fn register_claimer(s: &mut <Self as PUT>::State, claimer: Rc<RefCell<VecClaimer>>, agent_name: AgentName) {
        todo!()
    }

    fn deregister_claimer(s: &mut <Self as PUT>::State) -> () {
        todo!()
    }
}

impl WolfSSL {
    pub fn change_agent_name(self: &mut Self, claimer: Rc<RefCell<VecClaimer>>, agent_name: AgentName) {
        todo!()
    }
}