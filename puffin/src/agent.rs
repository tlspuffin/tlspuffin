//! [`Agent`]s represent communication participants like Alice, Bob or Eve. Attackers are usually
//! not represented by these [`Agent`]s.
//! Attackers are represented through a recipe term (see [`InputAction`]).
//!
//! Each [`Agent`] has an *inbound* and an *outbound channel* (see [`crate::io`])

use core::fmt;
use std::fmt::{Debug, Formatter};

use serde::{Deserialize, Serialize};

use crate::{
    error::Error,
    protocol::ProtocolBehavior,
    put::{Put, PutDescriptor},
    trace::TraceContext,
};

/// Copyable reference to an [`Agent`]. It identifies exactly one agent.
#[derive(Serialize, Deserialize, Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct AgentName(u8);

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
/// The difference between an [`AgentDescriptor`] and a [`PutDescriptor`] is that values of
/// the [`AgentDescriptor`] are required for seed traces to succeed. They are the same for every
/// invocation of the seed. Values in the [`PutDescriptor`] are supposed to differ between
/// invocations.
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
    pub fn new_reusable_server(name: AgentName, tls_version: TLSVersion) -> Self {
        Self {
            name,
            tls_version,
            typ: AgentType::Server,
            try_reuse: true,
            ..AgentDescriptor::default()
        }
    }

    pub fn new_reusable_client(name: AgentName, tls_version: TLSVersion) -> Self {
        Self {
            name,
            tls_version,
            typ: AgentType::Client,
            try_reuse: true,
            ..AgentDescriptor::default()
        }
    }

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
    name: AgentName,

    put: Box<dyn Put<PB>>,
    put_descriptor: PutDescriptor,
}

impl<PB: ProtocolBehavior> Debug for Agent<PB> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Agent")
            .field("name", &self.name)
            .field("put", &self.put.describe_state())
            .field("put_descriptor", &self.put_descriptor)
            .finish()
    }
}

impl<PB: ProtocolBehavior> PartialEq for Agent<PB> {
    fn eq(&self, other: &Self) -> bool {
        self.name.eq(&other.name)
            && self.put.describe_state() == other.put.describe_state()
            && self.put_descriptor.eq(&other.put_descriptor)
    }
}

impl<PB: ProtocolBehavior> Agent<PB> {
    pub fn new(
        context: &TraceContext<PB>,
        agent_descriptor: &AgentDescriptor,
    ) -> Result<Self, Error> {
        let put_descriptor = context.put_descriptor(agent_descriptor);

        let factory = context
            .put_registry()
            .find_factory(put_descriptor.name)
            .ok_or_else(|| {
                Error::Agent(format!(
                    "unable to find PUT {} factory in binary",
                    &put_descriptor.name
                ))
            })?;

        let stream = factory.create(context, agent_descriptor)?;
        let agent = Agent {
            name: agent_descriptor.name,
            put: stream,
            put_descriptor,
        };

        Ok(agent)
    }

    pub fn descriptor(&self) -> &PutDescriptor {
        &self.put_descriptor
    }

    pub fn rename(&mut self, new_name: AgentName) -> Result<(), Error> {
        self.name = new_name;
        self.put.rename_agent(new_name)
    }

    pub fn reset(&mut self, agent_name: AgentName) -> Result<(), Error> {
        self.put.reset(agent_name)
    }

    pub fn name(&self) -> AgentName {
        self.name
    }

    pub fn put(&self) -> &dyn Put<PB> {
        self.put.as_ref()
    }

    pub fn put_mut(&mut self) -> &mut dyn Put<PB> {
        self.put.as_mut()
    }
}
