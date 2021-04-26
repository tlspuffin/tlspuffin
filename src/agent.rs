use core::fmt;

use rand::random;

use crate::io::{MemoryStream, OpenSSLStream, Stream};

#[derive(Copy, Clone)]
pub struct AgentName(u128); // TODO make u128 private again

impl AgentName {
    pub fn random() -> AgentName {
        AgentName(random())
    }

    pub fn none() -> AgentName {
        AgentName(0u128)
    }
}

pub const NONE: AgentName = AgentName(0u128);

impl fmt::Display for AgentName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut encoded = hex::encode(self.0.to_ne_bytes());
        encoded.truncate(8); // only display first 4 byte
        write!(f, "{}", encoded)
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

    pub fn new_openssl(server: bool) -> Self {
        Self::from_stream(Box::new(OpenSSLStream::new(server)))
    }

    pub fn from_stream(stream: Box<dyn Stream>) -> Agent {
        Agent {
            name: AgentName::random(),
            stream,
        }
    }
}
