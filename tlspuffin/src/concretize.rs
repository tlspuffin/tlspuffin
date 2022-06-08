//! Generic [`PUT`] trait defining an interface with a TLS library with which we can:
//! - [`new`] create a client (or server) new initial state + bind buffers
//! - [`progress`] makes a state progress (interacting with the buffers)
//!
//! And specific implementations of PUT for the different PUTs.
use crate::agent::{AgentName, PutName, TLSVersion};
use crate::error::Error;
use crate::io::MessageResult;
use crate::io::{MemoryStream, Stream};
use crate::trace::VecClaimer;
use rustls::msgs::message::OpaqueMessage;
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::io::{Read, Write};
use std::rc::Rc;

pub struct PutRegistry<const N: usize>([fn() -> Box<dyn Factory>; N]);

impl<const N: usize> PutRegistry<N> {
    pub fn versions(&self) -> String {
        let mut put_versions: String = "".to_owned();
        for func in self.0 {
            let factory = func();

            let name = factory.put_name();
            let version = factory.put_version();
            put_versions.push_str(format!("{:?}: {}", name, version).as_str());
        }
        put_versions
    }
    pub fn make_deterministic(&self) {
        for func in self.0 {
            let factory = func();
            factory.make_deterministic();
        }
    }

    pub fn find_factory(&self, put_name: PutName) -> Option<Box<dyn Factory>> {
        self.0
            .iter()
            .map(|func| func())
            .find(|factory: &Box<dyn Factory>| factory.put_name() == put_name)
    }
}

pub const OPENSSL111: PutName = PutName(['O', 'P', 'E', 'N', 'S', 'S', 'L', '1', '1', '1']);

const N_REGISTERED: usize = 0 + if cfg!(feature = "openssl") { 1 } else { 0 };
pub const PUT_REGISTRY: PutRegistry<N_REGISTERED> = PutRegistry([
    #[cfg(feature = "openssl")]
    crate::openssl::new_openssl_factory,
]);

pub trait Factory {
    fn create(&self, config: Config) -> Box<dyn Put>;
    fn put_name(&self) -> PutName;
    fn put_version(&self) -> &'static str;
    fn make_deterministic(&self);
}

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

pub trait Put: Stream + Drop + 'static {
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
    fn deregister_claimer(&mut self);
    /// Change the agent name and the claimer of self
    fn change_agent_name(&mut self, claimer: Rc<RefCell<VecClaimer>>, agent_name: AgentName);
    /// Returns a textual representation of the state in which self is
    fn describe_state(&self) -> &'static str;
    /// Returns a textual representation of the version of the PUT used by self
    fn version() -> &'static str
    where
        Self: Sized;
    /// Make the PUT used by self determimistic in the future by making its PRNG "deterministic"
    fn make_deterministic()
    where
        Self: Sized;
}
