//! [`Agent`]s represent communication participants like Alice, Bob or Eve. Attackers are usually
//! not represented by these [`Agent`]s.
//! Attackers are represented through a recipe term (see [`InputAction`]).
//!
//! Each [`Agent`] has an *inbound* and an *outbound channel* (see [`crate::io`])

use crate::error::Error;
use crate::io::PUTState;
use core::fmt;
use serde::{Deserialize, Serialize};

use crate::trace::VecClaimer;
use std::cell::RefCell;
use std::rc::Rc;
use rustls::msgs::enums::ProtocolVersion::TLSv1_2;
use crate::agent::TLSVersion::Unknown;

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

/// AgentDescriptors act like a blueprint to spawn [`Agent`]s with a corresponding server or
/// client role and a specific TLs version. Essentially they are an [`Agent`] without a stream.
#[derive(Debug, Copy, Clone, Deserialize, Serialize, Eq, PartialEq)]
pub struct AgentDescriptor {
    pub name: AgentName,
    pub tls_version: TLSVersion,
    /// Whether the agent which holds this descriptor is a server.
    pub server: bool,
    /// Whether we want to try to reuse a previous agent. This is needed for TLS session resumption
    /// as openssl agents rotate ticket keys if they are recreated.
    pub try_reuse: bool
    // [TODO::PUT] consider add a `PUTDescriptor` field that will be used to know how to instantiate
    // a new state
}

impl AgentDescriptor {
    /// checks whether a agent with this descriptor is reusable with the other descriptor
    pub fn is_reusable_with(&self, other: &AgentDescriptor) -> bool {
        return self.server == other.server && self.tls_version == other.tls_version;
    }

    pub fn new_reusable_server(name: AgentName, tls_version: TLSVersion) -> Self {
        Self {
            name,
            tls_version,
            server: true,
            try_reuse: true
        }
    }

    pub fn new_reusable_client(name: AgentName, tls_version: TLSVersion) -> Self {
        Self {
            name,
            tls_version,
            server: true,
            try_reuse: true
        }
    }

    pub fn new_server(name: AgentName, tls_version: TLSVersion) -> Self {
        Self {
            name,
            tls_version,
            server: true,
            try_reuse: false
        }
    }

    pub fn new_client(name: AgentName, tls_version: TLSVersion) -> Self {
        Self {
            name,
            tls_version,
            server: false,
            try_reuse: false
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub enum TLSVersion {
    V1_3,
    V1_2,
    Unknown,
}

impl From<i32> for TLSVersion  {
    fn from(value: i32) -> Self {
       match value {
           0x303 => TLSVersion::V1_2,
           0x304 => TLSVersion::V1_3,
           _ => TLSVersion::Unknown
       }
    }
}

/// An [`Agent`] holds a non-cloneable reference to a Stream.
pub struct Agent {
    pub descriptor: AgentDescriptor,
    pub stream: PUTState,
}

impl Agent {
    pub fn new(
        descriptor: &AgentDescriptor,
        claimer: Rc<RefCell<VecClaimer>>,
    ) -> Result<Self, Error> {
        let openssl_stream = PUTState::new(
            descriptor.server,
            &descriptor.tls_version,
            descriptor.name,
            claimer,
        )?;

        let agent = Self::from_stream(descriptor, openssl_stream);

        Ok(agent)
    }

    pub fn rename(&mut self, claimer: Rc<RefCell<VecClaimer>>, new_name: AgentName) {
        self.descriptor.name = new_name;
        self.stream.change_agent_name(claimer, new_name);
    }

    pub fn reset(&mut self) {
        self.stream.reset();
    }

    fn from_stream(descriptor: &AgentDescriptor, stream: PUTState) -> Agent {
        Agent {
            descriptor: *descriptor,
            stream,
        }
    }
}
