//! Generic [`PUT`] trait defining an interface with a TLS library with which we can:
//! - [`new`] create a client (or server) new initial state + bind buffers
//! - [`progress`] makes a state progress (interacting with the buffers)
//!
//! And specific implementations of PUT for the different PUTs.
use tlspuffin::agent::TLSVersion;
use tlspuffin::error::Error;
use tlspuffin::io::Stream;

/// An agent state for the PUT // [TODO::PUT] will become the current PUTState
pub struct State {}

/// Static configuration for creating a new agent state for the PUT
pub struct Config {
    pub tls_version: TLSVersion,
    /// Whether the agent which holds this descriptor is a server.
    pub server: bool,
}

pub trait PUT: Stream + Drop {
    /// Create a new agent state for the PUT + set up buffers/BIOs
    fn new (c: Config) -> Result<State,Error>;
    /// Process incoming buffer, internal progress, can fill in output buffer
    fn progress (&self) -> Result<(),Error>;
    /// In-place reset of the state
    fn reset(&self) -> Result<(),Error>;
}