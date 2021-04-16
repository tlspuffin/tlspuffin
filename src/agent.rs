use rand::random;

use crate::io::MemoryStream;

#[derive(Debug, Copy, Clone)]
pub struct AgentName(u128);

impl PartialEq for AgentName {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

pub struct Agent {
    pub name: AgentName,
    pub stream: MemoryStream,
}

impl Agent {
    pub fn new() -> Self {
        Self::from_stream(MemoryStream::new())
    }

    pub fn from_stream(stream: MemoryStream) -> Agent {
        Agent {
            name: AgentName(random()),
            stream,
        }
    }
}

pub const NO_AGENT: AgentName = AgentName(u128::min_value());
