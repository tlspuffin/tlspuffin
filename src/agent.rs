use core::fmt;

use rand::random;

use crate::io::{MemoryStream, OpenSSLStream, Stream};

#[derive(Copy, Clone)]
pub struct AgentName(u128);

impl fmt::Display for AgentName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0.to_ne_bytes()))
    }
}

impl PartialEq for AgentName {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

pub struct Agent {
    pub name: AgentName,
    pub stream: Box<dyn Stream>,
}

impl Agent {
    pub fn new() -> Self {
        Self::from_stream(Box::new(MemoryStream::new()))
    }

    pub fn from_stream(stream: Box<dyn Stream>) -> Agent {
        Agent {
            name: AgentName(random()),
            stream,
        }
    }

    pub fn new_openssl() -> Self {
        Self::from_stream(Box::new(OpenSSLStream::new()))
    }
}

pub const NO_AGENT: AgentName = AgentName(u128::min_value());
