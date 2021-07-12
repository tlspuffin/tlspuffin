//! [`Agent`]s represent communication participants like Alice, Bob or Eve. Attackers are usually
//! not represented by these [`Agent`]s.
//! Attackers are represented through a recipe term (see [`InputAction`]).
//!
//! Each [`Agent`] has an *inbound* and an *outbound channel* (see [`crate::io`])

use core::fmt;
use serde::{Deserialize, Serialize};
use crate::io::{OpenSSLStream, Stream};
use crate::error::Error;
use security_claims::{Claim, ClaimType};
use security_claims::register::Claimer;
use std::rc::Rc;
use std::cell::RefCell;

/// Copyable reference to an [`Agent`]
#[derive(Serialize, Deserialize, Copy, Clone, Debug, Eq)]
pub struct AgentName(u8);

impl AgentName {
    pub fn next(&self) -> AgentName {
        AgentName(self.0 + 1)
    }

    pub fn first() -> AgentName {
        FIRST
    }
}

const FIRST: AgentName = AgentName(0u8);

impl fmt::Display for AgentName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl PartialEq for AgentName {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

/// AgentDescriptors act like a blueprint to spawn [`Agent`]s with a corresponding server or
/// client role and a specific TLs version. Essentially they are an [`Agent`] without a stream.
#[derive(Debug, Copy, Clone, Deserialize, Serialize)]
pub struct AgentDescriptor {
    pub name: AgentName,
    pub tls_version: TLSVersion,
    pub server: bool,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum TLSVersion {
    V1_3,
    V1_2,
}

pub struct VecClaimer {
    pub claims: Vec<Claim>
}

impl VecClaimer {
    pub fn new() -> Self {
        Self {
            claims: vec![]
        }
    }

    pub fn claim(&mut self, claim: Claim) {
        self.claims.push(claim);
    }
}

/// An [`Agent`] holds a non-cloneable reference to a Stream.
pub struct Agent {
    pub descriptor: AgentDescriptor,
    pub stream: OpenSSLStream,
    pub claimer: Rc<RefCell<VecClaimer>>,
}

impl Agent {
    pub fn new_openssl(descriptor: &AgentDescriptor) -> Result<Self, Error> {
        let claimer = Rc::new(RefCell::new(VecClaimer::new()));

        let openssl_stream = OpenSSLStream::new(
            descriptor.server,
            &descriptor.tls_version,
            claimer.clone()
        )?;

        let mut agent = Self::from_stream(
            descriptor,
            openssl_stream,
            claimer
        );

        Ok(agent)
    }


    fn from_stream(descriptor: &AgentDescriptor, stream: OpenSSLStream, claimer: Rc<RefCell<VecClaimer>>) -> Agent {
        Agent { descriptor: *descriptor, stream, claimer }
    }
}
