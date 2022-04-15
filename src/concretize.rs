//! Generic [`PUT`] trait defining an interface with a TLS library with which we can:
//! - [`new`] create a client (or server) new initial state + bind buffers
//! - [`progress`] makes a state progress (interacting with the buffers)
//!
//! And specific implementations of PUT for the different PUTs.
use std::io::{Read, Write};
use openssl::ssl::SslStream;
use rustls::msgs::message::OpaqueMessage;
use tlspuffin::agent::TLSVersion;
use tlspuffin::error::Error;
use tlspuffin::io::{MemoryStream, Stream};
use crate::io::MessageResult;
use crate::openssl_binding;

/// Stream, Read, Write traits below are with respect to this content type // [TODO:PUT] how one can make this precise in the type (Without modifing those traits specs?)
pub type Bts<'a> = &'a[u8];

/// Static configuration for creating a new agent state for the PUT
pub struct Config {
    pub tls_version: TLSVersion,
    /// Whether the agent which holds this descriptor is a server.
    pub server: bool,
}

pub trait PUT: Stream + Drop {
    /// An agent state for the PUT // [TODO::PUT] will become the current PUTState
    type State;

    /// Create a new agent state for the PUT + set up buffers/BIOs
    fn new (c: Config) -> Result<<Self as PUT>::State,Error>;
    /// Process incoming buffer, internal progress, can fill in output buffer
    fn progress (s: &mut<Self as PUT>::State) -> Result<(),Error>;
    /// In-place reset of the state
    fn reset(s: &mut<Self as PUT>::State) -> Result<(),Error>;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////// OpenSSL specific-state
////////////////////////////////////////////////////////////////////////////////////////////////////

pub struct OpenSSL {
    stream: SslStream<MemoryStream>,
}

impl Stream for OpenSSL {
    fn add_to_inbound(&mut self, result: &OpaqueMessage) {
        todo!()
    }

    fn take_message_from_outbound(&mut self) -> Result<Option<MessageResult>, Error> {
        todo!()
    }
}

impl Read for OpenSSL {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        todo!()
    }
}

impl Write for OpenSSL {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        todo!()
    }

    fn flush(&mut self) -> std::io::Result<()> {
        todo!()
    }
}

impl Drop for OpenSSL {
    fn drop(&mut self) {
        todo!()
    }
}

impl PUT for OpenSSL {
    type State = OpenSSL;

    fn new(c: Config) -> Result<OpenSSL, Error> { // [TODO::PUT] will replace io::PUTState::new
        let memory_stream = MemoryStream::new();
        let stream = if c.server {
            //let (cert, pkey) = openssl_binding::generate_cert();
            let (cert, pkey) = openssl_binding::static_rsa_cert()?;
            openssl_binding::create_openssl_server(memory_stream, &cert, &pkey, &c.tls_version)?
        } else {
            openssl_binding::create_openssl_client(memory_stream, &c.tls_version)?
        };

        let mut stream = OpenSSL { stream };
        Ok(stream)
    }

    fn progress(s: &mut<Self as PUT>::State) -> Result<(), Error> {
        let stream = &mut s.stream;
        openssl_binding::do_handshake(stream)
    }

    fn reset(s: &mut <Self as PUT>::State) -> () {
        OK(s.stream.clear())
    }
}


////////////////////////////////////////////////////////////////////////////////////////////////////
////////////// WolfSSL specific-state
////////////////////////////////////////////////////////////////////////////////////////////////////

pub struct WolfSSLState {
    // [TODO::PUT]
}

impl PUT for WolfSSLState {
    type State = WolfSSLState;

}
