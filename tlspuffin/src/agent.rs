//! [`Agent`]s represent communication participants like Alice, Bob or Eve. Attackers are usually
//! not represented by these [`Agent`]s.
//! Attackers are represented through a recipe term (see [`InputAction`]).
//!
//! Each [`Agent`] has an *inbound* and an *outbound channel* (see [`crate::io`])

use core::fmt;
use std::{cell::RefCell, rc::Rc};

use serde::{Deserialize, Serialize};

use crate::{
    error::Error,
    put::{Config, Put},
    put_registry::PUT_REGISTRY,
    trace::ClaimList,
};

/// Copyable reference to an [`Agent`]. It identifies exactly one agent.
#[derive(Serialize, Deserialize, Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct AgentName(u8);

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

#[derive(Debug, Copy, Clone, Deserialize, Serialize, Eq, PartialEq, Hash)]
pub struct PutName(pub [char; 10]);

/// AgentDescriptors act like a blueprint to spawn [`Agent`]s with a corresponding server or
/// client role and a specific TLs version. Essentially they are an [`Agent`] without a stream.
#[derive(Debug, Copy, Clone, Deserialize, Serialize, Eq, PartialEq, Hash)]
pub struct AgentDescriptor {
    pub name: AgentName,
    pub put_name: PutName,
    pub tls_version: TLSVersion,
    /// Whether the agent which holds this descriptor is a server.
    pub server: bool,
    /// Whether we want to try to reuse a previous agent. This is needed for TLS session resumption
    /// as openssl agents rotate ticket keys if they are recreated.
    pub try_reuse: bool,
}

impl AgentDescriptor {
    /// checks whether a agent with this descriptor is reusable with the other descriptor
    pub fn is_reusable_with(&self, other: &AgentDescriptor) -> bool {
        self.server == other.server && self.tls_version == other.tls_version
    }

    pub fn new_reusable_server(
        name: AgentName,
        tls_version: TLSVersion,
        put_name: PutName,
    ) -> Self {
        Self {
            name,
            tls_version,
            server: true,
            try_reuse: true,
            put_name,
        }
    }

    pub fn new_reusable_client(
        name: AgentName,
        tls_version: TLSVersion,
        put_name: PutName,
    ) -> Self {
        Self {
            name,
            tls_version,
            server: true,
            try_reuse: true,
            put_name,
        }
    }

    pub fn new_server(name: AgentName, tls_version: TLSVersion, put_name: PutName) -> Self {
        Self {
            name,
            tls_version,
            server: true,
            try_reuse: false,
            put_name,
        }
    }

    pub fn new_client(name: AgentName, tls_version: TLSVersion, put_name: PutName) -> Self {
        Self {
            name,
            tls_version,
            server: false,
            try_reuse: false,
            put_name,
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub enum TLSVersion {
    V1_3,
    V1_2,
    Unknown,
}

impl From<i32> for TLSVersion {
    fn from(value: i32) -> Self {
        match value {
            0x303 => TLSVersion::V1_2,
            0x304 => TLSVersion::V1_3,
            _ => TLSVersion::Unknown,
        }
    }
}

/// An [`Agent`] holds a non-cloneable reference to a Stream.
pub struct Agent {
    pub descriptor: AgentDescriptor,
    pub stream: Box<dyn Put>,
}

impl Agent {
    pub fn new(
        descriptor: &AgentDescriptor,
        claims: Rc<RefCell<ClaimList>>,
    ) -> Result<Self, Error> {
        let config = Config {
            descriptor: *descriptor,
            claims,
        };

        let factory = PUT_REGISTRY
            .find_factory(descriptor.put_name)
            .ok_or_else(|| Error::Agent("unable to find PUT factory in binary".to_string()))?;
        let stream = factory.create(config);
        let agent = Agent {
            descriptor: *descriptor,
            stream,
        };

        Ok(agent)
    }

    pub fn rename(&mut self, claims: Rc<RefCell<ClaimList>>, new_name: AgentName) {
        self.descriptor.name = new_name;
        self.stream.rename_agent(claims, new_name);
    }

    pub fn reset(&mut self) -> Result<(), Error> {
        self.stream.reset()
    }
}
