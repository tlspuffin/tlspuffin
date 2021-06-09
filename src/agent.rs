use core::fmt;

use serde::{Deserialize, Serialize};

use crate::io::{OpenSSLStream, Stream};
use crate::error::Error;

#[derive(Serialize, Deserialize, Copy, Clone, Debug)]
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

pub struct Agent {
    pub descriptor: AgentDescriptor,
    pub stream: Box<dyn Stream>,
}

impl Agent {
    pub fn new_openssl(descriptor: &AgentDescriptor) -> Result<Self, Error> {
        let openssl_stream = OpenSSLStream::new(
            descriptor.server,
            &descriptor.tls_version,
        )?;
        Ok(Self::from_stream(
            descriptor,
            Box::new(openssl_stream),
        ))
    }

    pub fn from_stream(descriptor: &AgentDescriptor, stream: Box<dyn Stream>) -> Agent {
        Agent { descriptor: *descriptor, stream }
    }
}
