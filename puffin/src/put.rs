use std::hash::Hash;

use serde::{Deserialize, Serialize};

use crate::agent::{AgentDescriptor, AgentName};
use crate::error::Error;
use crate::protocol::{ProtocolBehavior, ProtocolTypes};
use crate::stream::Stream;

#[derive(Debug, Clone, Deserialize, Serialize, Eq, PartialEq, Hash, Default)]
pub struct PutOptions {
    options: Vec<(String, String)>,
}

impl PutOptions {
    #[must_use]
    pub const fn new(options: Vec<(String, String)>) -> Self {
        Self { options }
    }
}

impl PutOptions {
    #[must_use]
    pub fn get_option(&self, key: &str) -> Option<&str> {
        self.options
            .iter()
            .find(|(found_key, _value)| -> bool { found_key == key })
            .map(|(_key, value)| value.as_str())
    }
}

impl<S> From<Vec<(S, S)>> for PutOptions
where
    S: Into<String>,
{
    fn from(value: Vec<(S, S)>) -> Self {
        Self {
            options: value
                .into_iter()
                .map(|(key, value)| (key.into(), value.into()))
                .collect(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, Eq, PartialEq, Hash, Default)]
pub struct PutDescriptor {
    pub factory: String,
    pub options: PutOptions,
}

impl PutDescriptor {
    pub fn new(factory: impl Into<String>, options: impl Into<PutOptions>) -> Self {
        Self {
            factory: factory.into(),
            options: options.into(),
        }
    }
}

impl<S> From<S> for PutDescriptor
where
    S: Into<String>,
{
    fn from(name: S) -> Self {
        Self::new(name, PutOptions::default())
    }
}

/// Generic trait used to define the interface with a concrete library
/// implementing the protocol.
pub trait Put<PB: ProtocolBehavior>: Stream<PB> + 'static {
    /// Process incoming buffer, internal progress, can fill in the output buffer
    fn progress(&mut self) -> Result<(), Error>;

    /// In-place reset of the state
    fn reset(&mut self, new_name: AgentName) -> Result<(), Error>;

    fn descriptor(
        &self,
    ) -> &AgentDescriptor<<<PB as ProtocolBehavior>::ProtocolTypes as ProtocolTypes>::PUTConfig>;

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
