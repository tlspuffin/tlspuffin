//! Generic [`PUT`] trait defining an interface with a TLS library with which we can:
//! - [`new`] create a client (or server) new initial state + bind buffers
//! - [`progress`] makes a state progress (interacting with the buffers)
//!
//! And specific implementations of PUT for the different PUTs.
use tlspuffin::agent::TLSVersion;
use tlspuffin::error::Error;
use tlspuffin::io::Stream;

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
    fn new (c: Config) -> Result<PUT::State,Error>;
    /// Process incoming buffer, internal progress, can fill in output buffer
    fn progress (&self) -> Result<(),Error>;
    /// In-place reset of the state
    fn reset(&self) -> Result<(),Error>;
}