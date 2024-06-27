//! [`Agent`]s represent communication participants like Alice, Bob or Eve. Attackers are usually
//! not represented by these [`Agent`]s.
//! Attackers are represented through a recipe term (see [`crate::trace::InputAction`]).
//!
//! Each [`Agent`] has an *inbound* and an *outbound* channel (see [`crate::stream`])

use core::fmt;
use std::fmt::{Debug, Formatter};

use serde::{Deserialize, Serialize};

use crate::{error::Error, protocol::ProtocolBehavior, put::Put, stream::Stream};

/// Copyable reference to an [`Agent`]. It identifies exactly one agent.
#[derive(Serialize, Deserialize, Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct AgentName(u8);

impl From<AgentName> for u8 {
    fn from(val: AgentName) -> Self {
        val.0
    }
}

#[derive(Serialize, Deserialize, Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum AgentType {
    Server,
    Client,
}

impl AgentName {
    pub const fn new() -> Self {
        const FIRST: AgentName = AgentName(0u8);
        FIRST
    }

    pub const fn next(&self) -> Self {
        AgentName(self.0 + 1)
    }

    pub const fn first() -> Self {
        AgentName::new()
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

/// AgentDescriptors act like a blueprint to spawn [`Agent`]s with a corresponding server or
/// client role and a specific TLs version. Essentially they are an [`Agent`] without a stream.
///
/// The difference between an [`AgentDescriptor`] and a [`crate::put_registry::PutDescriptor`] is
/// that values of the [`AgentDescriptor`] are required for seed traces to succeed. They are the
/// same for every invocation of the seed. Values in the [`crate::put_registry::PutDescriptor`] are
/// supposed to differ between invocations.
#[derive(Debug, Clone, Deserialize, Serialize, Eq, PartialEq, Hash)]
pub struct AgentDescriptor {
    pub name: AgentName,
    pub tls_version: TLSVersion,
    /// Whether the agent which holds this descriptor is a server.
    pub typ: AgentType,
    /// Whether we want to try to reuse a previous agent. This is needed for TLS session resumption
    /// as openssl agents rotate ticket keys if they are recreated.
    pub try_reuse: bool,
    /// If agent is a server:
    ///   Make client auth. a requirement.
    /// If agent is a client:
    ///   Send a static certificate.
    ///
    /// Default: false
    pub client_authentication: bool,
    /// If agent is a server:
    ///   No effect, servers always send certificates in TLS.
    /// If agent is a client:
    ///   Make server auth. a requirement.
    ///
    /// Default: true
    pub server_authentication: bool,
}

impl Default for AgentDescriptor {
    fn default() -> Self {
        Self {
            name: AgentName::first(),
            tls_version: TLSVersion::V1_3,
            typ: AgentType::Server,
            try_reuse: false,
            client_authentication: false,
            server_authentication: true,
        }
    }
}

impl AgentDescriptor {
    pub fn new_server(name: AgentName, tls_version: TLSVersion) -> Self {
        Self {
            name,
            tls_version,
            typ: AgentType::Server,
            ..AgentDescriptor::default()
        }
    }

    pub fn new_client(name: AgentName, tls_version: TLSVersion) -> Self {
        Self {
            name,
            tls_version,
            typ: AgentType::Client,
            ..AgentDescriptor::default()
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub enum TLSVersion {
    V1_3,
    V1_2,
}

/// An [`Agent`] holds a non-cloneable reference to a Stream.
pub struct Agent<PB: ProtocolBehavior> {
    descriptor: AgentDescriptor,
    put: Box<dyn Put<PB>>,
}

impl<PB: ProtocolBehavior> Debug for Agent<PB> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
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
    pub fn new(descriptor: &AgentDescriptor, put: Box<dyn Put<PB>>) -> Self {
        Self {
            descriptor: descriptor.clone(),
            put,
        }
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
    pub fn is_state_successful(&self) -> bool {
        self.put.is_state_successful()
    }

    /// Checks whether the agent is reusable with the descriptor.
    pub fn is_reusable_with(&self, other: &AgentDescriptor) -> bool {
        self.descriptor.typ == other.typ && self.descriptor.tls_version == other.tls_version
    }

    pub fn name(&self) -> AgentName {
        self.descriptor.name
    }
}

impl<PB: ProtocolBehavior>
    Stream<
        PB::Matcher,
        PB::ProtocolMessage,
        PB::OpaqueProtocolMessage,
        PB::OpaqueProtocolMessageFlight,
    > for Agent<PB>
{
    fn add_to_inbound(&mut self, message_flight: &PB::OpaqueProtocolMessageFlight) {
        self.put.add_to_inbound(message_flight)
    }

    fn take_message_from_outbound(
        &mut self,
    ) -> Result<Option<PB::OpaqueProtocolMessageFlight>, Error> {
        self.put.take_message_from_outbound()
    }
}
