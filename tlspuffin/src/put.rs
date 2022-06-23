//! Generic [`PUT`] trait defining an interface with a TLS library with which we can:
//! - [`new`] create a client (or server) new initial state + bind buffers
//! - [`progress`] makes a state progress (interacting with the buffers)
//!
//! And specific implementations of PUT for the different PUTs.
use std::{cell::RefCell, fmt::Debug, hash::Hash, rc::Rc};

use serde::{Deserialize, Serialize};

use crate::{
    agent::{AgentName, TLSVersion},
    error::Error,
    io::Stream,
    put_registry::DUMMY_PUT,
    trace::ClaimList,
};

#[derive(Debug, Copy, Clone, Deserialize, Serialize, Eq, PartialEq, Hash)]
pub struct PutName(pub [char; 10]);

impl Default for PutName {
    fn default() -> Self {
        DUMMY_PUT
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, Eq, PartialEq, Hash, Default)]
pub struct PutDescriptor {
    // FIXME: Rename?
    pub name: PutName,
    pub options: Vec<(String, String)>,
}

/// Static configuration for creating a new agent state for the PUT
#[derive(Clone)]
pub struct PutConfig {
    pub descriptor: PutDescriptor,
    pub server: bool,
    pub tls_version: TLSVersion,
    pub claims: Rc<RefCell<ClaimList>>,
}

impl PutConfig {
    pub fn get_option(&self, key: &str) -> Option<&str> {
        self.descriptor
            .options
            .iter()
            .find(|(found_key, _value)| -> bool { found_key == key })
            .map(|(_key, value)| value.as_str())
    }
}

pub trait Put: Stream + Drop + 'static {
    /// Create a new agent state for the PUT + set up buffers/BIOs
    fn new(agent_name: AgentName, config: PutConfig) -> Result<Self, Error>
    where
        Self: Sized;
    /// Process incoming buffer, internal progress, can fill in output buffer
    fn progress(&mut self, agent_name: &AgentName) -> Result<(), Error>;
    /// In-place reset of the state
    fn reset(&mut self) -> Result<(), Error>;
    /// Register a new claim for agent_name
    #[cfg(feature = "claims")]
    fn register_claimer(&mut self, claims: Rc<RefCell<ClaimList>>, agent_name: AgentName);
    /// Remove all claims in self
    #[cfg(feature = "claims")]
    fn deregister_claimer(&mut self);
    /// Change the agent name and the claimer of self
    fn rename_agent(&mut self, claims: Rc<RefCell<ClaimList>>, agent_name: AgentName);
    /// Returns a textual representation of the state in which self is
    fn describe_state(&self) -> &'static str;
    /// Checks whether the Put is in a good state
    fn is_state_successful(&self) -> bool;
    /// Returns a textual representation of the version of the PUT used by self
    fn version() -> &'static str
    where
        Self: Sized;
    /// Make the PUT used by self determimistic in the future by making its PRNG "deterministic"
    fn make_deterministic()
    where
        Self: Sized;
}
