use std::{
    fmt::{Debug, Display, Formatter},
    hash::Hash,
};

use serde::{Deserialize, Serialize};

use crate::{
    agent::{AgentDescriptor, AgentName},
    error::Error,
    protocol::ProtocolBehavior,
    put_registry::DUMMY_PUT,
    stream::Stream,
};

#[derive(Debug, Copy, Clone, Deserialize, Serialize, Eq, PartialEq, Hash)]
pub struct PutName(pub [char; 10]);

impl Default for PutName {
    fn default() -> Self {
        DUMMY_PUT
    }
}

impl Display for PutName {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
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
    fn progress(&mut self) -> Result<(), Error>;

    /// In-place reset of the state
    fn reset(&mut self, new_name: AgentName) -> Result<(), Error>;

    fn descriptor(&self) -> &AgentDescriptor;

    /// Returns a textual representation of the state in which self is
    fn describe_state(&self) -> String;

    /// Checks whether the Put is in a good state
    fn is_state_successful(&self) -> bool;

    /// Shut down the PUT by consuming it and returning a string that summarizes the execution.
    fn shutdown(&mut self) -> String;

    /// Returns a textual representation of the version of the PUT used by self
    fn version() -> String
    where
        Self: Sized;
}
