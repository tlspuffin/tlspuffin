use std::fmt;
use std::hash::Hash;

use serde::{Deserialize, Serialize};

use crate::agent::{AgentDescriptor, AgentName};
use crate::error::Error;
use crate::protocol::ProtocolBehavior;
use crate::put_registry::DUMMY_PUT;
use crate::stream::Stream;

#[derive(Debug, Copy, Clone, Deserialize, Serialize, Eq, PartialEq, Hash)]
pub struct PutName(pub [char; 10]);

impl Default for PutName {
    fn default() -> Self {
        DUMMY_PUT
    }
}

impl fmt::Display for PutName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", String::from_iter(self.0))
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, Eq, PartialEq, Hash, Default)]
pub struct PutOptions {
    options: Vec<(String, String)>,
}

impl PutOptions {
    pub fn new(options: Vec<(String, String)>) -> Self {
        Self { options }
    }

    pub fn from_slice_vec(options: Vec<(&str, &str)>) -> Self {
        Self {
            options: Vec::from_iter(
                options
                    .iter()
                    .map(|(key, value)| (key.to_string(), value.to_string())),
            ),
        }
    }
}

impl PutOptions {
    pub fn get_option(&self, key: &str) -> Option<&str> {
        self.options
            .iter()
            .find(|(found_key, _value)| -> bool { found_key == key })
            .map(|(_key, value)| value.as_str())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, Eq, PartialEq, Hash, Default)]
pub struct PutDescriptor {
    pub name: PutName,
    pub options: PutOptions,
}

/// Generic trait used to define the interface with a concrete library
/// implementing the protocol.
pub trait Put<PB: ProtocolBehavior>:
    Stream<
        PB::Matcher,
        PB::ProtocolMessage,
        PB::OpaqueProtocolMessage,
        PB::OpaqueProtocolMessageFlight,
    > + 'static
{
    /// Process incoming buffer, internal progress, can fill in the output buffer
    fn progress(&mut self, agent_name: &AgentName) -> Result<(), Error>;

    /// In-place reset of the state
    fn reset(&mut self, agent_name: AgentName) -> Result<(), Error>;

    fn descriptor(&self) -> &AgentDescriptor;

    /// Register a new claim for agent_name
    #[cfg(feature = "claims")]
    fn register_claimer(&mut self, agent_name: AgentName);

    /// Remove all claims in self
    #[cfg(feature = "claims")]
    fn deregister_claimer(&mut self);

    /// Propagate agent changes to the PUT
    fn rename_agent(&mut self, agent_name: AgentName) -> Result<(), Error>;

    /// Returns a textual representation of the state in which self is
    fn describe_state(&self) -> &str;

    /// Checks whether the Put is in a good state
    fn is_state_successful(&self) -> bool;

    /// Make the PUT used by self deterministic in the future by making its PRNG "deterministic"
    /// Now subsumed by Factory-level functions to reseed globally: `determinism_reseed`
    fn determinism_reseed(&mut self) -> Result<(), Error>;

    /// checks whether a agent is reusable with the descriptor
    fn is_reusable_with(&self, other: &AgentDescriptor) -> bool {
        let agent_descriptor = self.descriptor();
        agent_descriptor.typ == other.typ && agent_descriptor.tls_version == other.tls_version
    }

    /// Shut down the PUT by consuming it and returning a string that summarizes the execution.
    fn shutdown(&mut self) -> String;

    /// Returns a textual representation of the version of the PUT used by self
    fn version() -> String
    where
        Self: Sized;
}
