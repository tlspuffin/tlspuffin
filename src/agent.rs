//! [`Agent`]s represent communication participants like Alice, Bob or Eve. Attackers are usually
//! not represented by these [`Agent`]s.
//! Attackers are represented through a recipe term (see [`InputAction`]).
//!
//! Each [`Agent`] has an *inbound* and an *outbound channel* (see [`crate::io`])

use crate::error::Error;
use crate::io::OpenSSLStream;
use core::fmt;
use serde::{Deserialize, Serialize};

use crate::trace::VecClaimer;
use std::cell::RefCell;
use std::rc::Rc;

/// Copyable reference to an [`Agent`]. LH: I assume this injectively identifies agents.
#[derive(Serialize, Deserialize, Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct AgentName(u8);

impl AgentName {
    pub fn next(&self) -> AgentName {
        AgentName(self.0 + 1)
    }

    pub fn first() -> AgentName {
        const FIRST: AgentName = AgentName(0u8);
        FIRST
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
    pub server: bool,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub enum TLSVersion {
    V1_3,
    V1_2,
}

/// An [`Agent`] holds a non-cloneable reference to a Stream.
pub struct Agent {
    pub descriptor: AgentDescriptor,
    pub stream: OpenSSLStream,
}

impl Agent {
    pub fn new_openssl(
        descriptor: &AgentDescriptor,
        claimer: Rc<RefCell<VecClaimer>>,
    ) -> Result<Self, Error> {
        let openssl_stream = OpenSSLStream::new(
            descriptor.server,
            &descriptor.tls_version,
            descriptor.name,
            claimer,
        )?;

        let agent = Self::from_stream(descriptor, openssl_stream);

        Ok(agent)
    }

    pub fn reset(&mut self) {
        self.stream.reset();
    }

    fn from_stream(descriptor: &AgentDescriptor, stream: OpenSSLStream) -> Agent {
        Agent {
            descriptor: *descriptor,
            stream,
        }
    }
}
