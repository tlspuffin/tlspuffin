//! [`Agent`]s represent communication participants like Alice, Bob or Eve. Attackers are usually
//! not represented by these [`Agent`]s.
//! Attackers are represented through a recipe term (see [`InputAction`]).
//!
//! Each [`Agent`] has an *inbound* and an *outbound channel* (see [`crate::io`])

use core::fmt;
use std::{
    borrow::Borrow,
    cell::{Ref, RefCell},
    ops::Deref,
    rc::Rc,
};

use serde::{Deserialize, Serialize};

use crate::{
    error::Error,
    put::{Put, PutConfig, PutDescriptor},
    put_registry::PUT_REGISTRY,
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
    pub fn next(&self) -> AgentName {
        AgentName(self.0 + 1)
    }

    pub fn new() -> AgentName {
        const FIRST: AgentName = AgentName(0u8);
        FIRST
    }

    pub fn first() -> AgentName {
        AgentName::new()
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
    pub put_descriptor: PutDescriptor,
    pub tls_version: TLSVersion,
    /// Whether the agent which holds this descriptor is a server.
    pub typ: AgentType,
    /// Whether we want to try to reuse a previous agent. This is needed for TLS session resumption
    /// as openssl agents rotate ticket keys if they are recreated.
    pub try_reuse: bool,
    pub client_authentication: bool,
}

impl Default for AgentDescriptor {
    fn default() -> Self {
        Self {
            name: AgentName::first(),
            put_descriptor: PutDescriptor::default(),
            tls_version: TLSVersion::V1_3,
            typ: AgentType::Server,
            try_reuse: false,
            client_authentication: false,
        }
    }
}

impl AgentDescriptor {
    pub fn new_reusable_server(
        name: AgentName,
        tls_version: TLSVersion,
        put_descriptor: PutDescriptor,
    ) -> Self {
        Self {
            name,
            tls_version,
            typ: AgentType::Server,
            try_reuse: true,
            put_descriptor,
            ..AgentDescriptor::default()
        }
    }

    pub fn new_reusable_client(
        name: AgentName,
        tls_version: TLSVersion,
        put_descriptor: PutDescriptor,
    ) -> Self {
        Self {
            name,
            tls_version,
            typ: AgentType::Client,
            try_reuse: true,
            put_descriptor,
            ..AgentDescriptor::default()
        }
    }

    pub fn new_server(
        name: AgentName,
        tls_version: TLSVersion,
        put_descriptor: PutDescriptor,
    ) -> Self {
        Self {
            name,
            tls_version,
            typ: AgentType::Server,
            put_descriptor,
            ..AgentDescriptor::default()
        }
    }

    pub fn new_client(
        name: AgentName,
        tls_version: TLSVersion,
        put_descriptor: PutDescriptor,
    ) -> Self {
        Self {
            name,
            tls_version,
            typ: AgentType::Client,
            put_descriptor,
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
pub struct Agent {
    pub name: AgentName,
    pub typ: AgentType,
    pub put: Box<dyn Put>,
}

impl Agent {
    pub fn new(context: &TraceContext, descriptor: &AgentDescriptor) -> Result<Self, Error> {
        let factory = PUT_REGISTRY
            .find_factory(descriptor.put_descriptor.name)
            .ok_or_else(|| Error::Agent("unable to find PUT factory in binary".to_string()))?;
        let config = PutConfig {
            descriptor: descriptor.put_descriptor.clone(),
            typ: descriptor.typ,
            tls_version: descriptor.tls_version,
            claims: context.claims().clone(),
        };

        let mut stream = factory.create(&descriptor, config)?;
        let agent = Agent {
            name: descriptor.name,
            typ: descriptor.typ,
            put: stream,
        };

        Ok(agent)
    }

    pub fn rename(&mut self, new_name: AgentName) -> Result<(), Error> {
        self.name = new_name;
        self.put.rename_agent(new_name)
    }

    pub fn reset(&mut self, agent_name: AgentName) -> Result<(), Error> {
        self.put.reset(agent_name)
    }
}
