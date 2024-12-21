//! [`Agent`]s represent communication participants like Alice, Bob or Eve.
//!
//! Note that attackers are usually not represented by these [`Agent`]s but instead through a recipe
//! term (see [`crate::trace::InputAction`]).
//!
//! Each [`Agent`] has an *inbound* and an *outbound* channel (see [`crate::stream`])

use core::fmt;
use std::fmt::Debug;
use std::hash::Hash;

use comparable::Comparable;
use serde::{Deserialize, Serialize};

use crate::algebra::ConcreteMessage;
use crate::error::Error;
use crate::protocol::{ProtocolBehavior, ProtocolTypes};
use crate::put::Put;
use crate::stream::Stream;

/// Copyable reference to an [`Agent`]. It identifies exactly one agent.
#[derive(
    Serialize, Deserialize, Copy, Clone, Debug, Eq, PartialEq, Hash, Comparable, Ord, PartialOrd,
)]
pub struct AgentName(u8);

impl AgentName {
    #[must_use]
    pub const fn new() -> Self {
        const FIRST: AgentName = AgentName(0u8);
        FIRST
    }

    #[must_use]
    pub const fn next(&self) -> Self {
        Self(self.0 + 1)
    }

    #[must_use]
    pub const fn first() -> Self {
        Self::new()
    }
}

impl Default for AgentName {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for AgentName {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<AgentName> for u8 {
    fn from(value: AgentName) -> Self {
        value.0
    }
}

/// Contains the protocol specific configuration of an agent
pub trait ProtocolDescriptorConfig:
    Default + Debug + Clone + Serialize + Hash + for<'a> Deserialize<'a>
{
    /// Indicates wheter a agent is reusable, ie. it's configuration is compatible with the new
    /// agent to spawn
    fn is_reusable_with(&self, other: &Self) -> bool;
}

/// [`AgentDescriptor`]s act like a blueprint to spawn [`Agent`]s with a corresponding server or
/// client role and a specific TLs version. Essentially they are an [`Agent`] without a stream.
///
/// The difference between an [`AgentDescriptor`] and a [`crate::put::PutDescriptor`] is that
/// values of the [`AgentDescriptor`] are required for seed traces to succeed. They are the same for
/// every invocation of the seed. Values in the [`crate::put::PutDescriptor`] are supposed to
/// differ between invocations.
#[derive(Debug, Clone, Deserialize, Serialize, Eq, PartialEq, Hash)]
#[serde(bound = "C: ProtocolDescriptorConfig")]
pub struct AgentDescriptor<C: ProtocolDescriptorConfig> {
    pub name: AgentName,

    /// Contains the protocol specific configuration of the Agent
    pub protocol_config: C,
}

impl<C: ProtocolDescriptorConfig> AgentDescriptor<C> {
    pub fn from_config(name: AgentName, put_config: C) -> Self {
        Self {
            name,
            protocol_config: put_config,
        }
    }

    pub fn from_name(name: AgentName) -> Self {
        Self {
            name,
            protocol_config: C::default(),
        }
    }
}

impl<C: ProtocolDescriptorConfig> Default for AgentDescriptor<C> {
    fn default() -> Self {
        Self {
            name: AgentName::first(),
            protocol_config: C::default(),
        }
    }
}

/// An [`Agent`] holds a non-cloneable reference to a Stream.
pub struct Agent<PB: ProtocolBehavior> {
    descriptor:
        AgentDescriptor<<<PB as ProtocolBehavior>::ProtocolTypes as ProtocolTypes>::PUTConfig>,
    put: Box<dyn Put<PB>>,
}

impl<PB: ProtocolBehavior> fmt::Debug for Agent<PB> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Agent")
            .field("descriptor", &self.descriptor)
            .field("put", &self.put.describe_state())
            .finish()
    }
}

impl<PB: ProtocolBehavior> PartialEq for Agent<PB> {
    fn eq(&self, other: &Self) -> bool {
        self.descriptor.name.eq(&other.descriptor.name)
            && self.put.describe_state() == other.put.describe_state()
    }
}

impl<PB: ProtocolBehavior> Agent<PB> {
    #[must_use]
    pub fn new(
        descriptor: AgentDescriptor<<PB::ProtocolTypes as ProtocolTypes>::PUTConfig>,
        put: Box<dyn Put<PB>>,
    ) -> Self {
        Self { descriptor, put }
    }

    pub fn progress(&mut self) -> Result<(), Error> {
        self.put.progress()
    }

    pub fn reset(&mut self, new_name: AgentName) -> Result<(), Error> {
        self.descriptor.name = new_name;
        self.put.reset(new_name)
    }

    /// Shut down the agent by consuming it and returning a string that summarizes the execution.
    pub fn shutdown(&mut self) -> String {
        self.put.shutdown()
    }

    /// Checks whether the agent is in a good state.
    #[must_use]
    pub fn is_state_successful(&self) -> bool {
        self.put.is_state_successful()
    }

    /// Checks whether the agent is reusable with the descriptor.
    #[must_use]
    pub fn is_reusable_with(
        &self,
        other: &AgentDescriptor<<PB::ProtocolTypes as ProtocolTypes>::PUTConfig>,
    ) -> bool {
        self.descriptor
            .protocol_config
            .is_reusable_with(&other.protocol_config)
    }

    #[must_use]
    pub const fn name(&self) -> AgentName {
        self.descriptor.name
    }

    #[must_use]
    pub fn put(&self) -> &dyn Put<PB> {
        self.put.as_ref()
    }

    pub fn put_mut(&mut self) -> &mut dyn Put<PB> {
        self.put.as_mut()
    }
}

impl<PB: ProtocolBehavior> Stream<PB> for Agent<PB> {
    fn add_to_inbound(&mut self, message: &ConcreteMessage) {
        self.put.add_to_inbound(message);
    }

    fn take_message_from_outbound(
        &mut self,
    ) -> Result<Option<PB::OpaqueProtocolMessageFlight>, Error> {
        self.put.take_message_from_outbound()
    }
}
