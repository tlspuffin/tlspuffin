use std::any::TypeId;

use comparable::Comparable;
use extractable_macro::Extractable;
use puffin::agent::ProtocolDescriptorConfig;
use puffin::algebra::signature::Signature;
use puffin::codec;
use puffin::codec::{Codec, Reader, VecCodecWoSize};
use puffin::error::Error;
use puffin::protocol::{
    EvaluatedTerm, OpaqueProtocolMessageFlight, ProtocolBehavior, ProtocolMessage,
    ProtocolMessageDeframer, ProtocolMessageFlight, ProtocolTypes,
};
use puffin::put::PutDescriptor;
use puffin::trace::Trace;
use serde::{Deserialize, Serialize};

use crate::claim::SshClaim;
use crate::query::SshQueryMatcher;
use crate::ssh::deframe::SshMessageDeframer;
use crate::ssh::message::{RawSshMessage, SshMessage};
use crate::ssh::SSH_SIGNATURE;
use crate::violation::SshSecurityViolationPolicy;

#[derive(Debug, Clone, Extractable, Comparable)]
#[extractable(SshProtocolTypes)]
pub struct SshMessageFlight {
    pub messages: Vec<SshMessage>,
}

impl VecCodecWoSize for SshMessage {}
impl codec::Codec for SshMessageFlight {
    fn encode(&self, bytes: &mut Vec<u8>) {
        for msg in &self.messages {
            msg.encode(bytes);
        }
    }

    fn read(reader: &mut codec::Reader) -> Option<Self> {
        let mut flight = Vec::new();

        while let Some(msg) = SshMessage::read(reader) {
            flight.push(msg);
        }
        Some(SshMessageFlight { messages: flight })
    }
}

impl ProtocolMessageFlight<SshProtocolTypes, SshMessage, RawSshMessage, RawSshMessageFlight>
    for SshMessageFlight
{
    fn new() -> Self {
        Self { messages: vec![] }
    }

    fn push(&mut self, msg: SshMessage) {
        self.messages.push(msg);
    }

    fn debug(&self, info: &str) {
        log::debug!("{}: {:?}", info, self);
    }
}

impl From<SshMessage> for SshMessageFlight {
    fn from(value: SshMessage) -> Self {
        Self {
            messages: vec![value],
        }
    }
}

#[derive(Debug, Clone, Extractable, Comparable)]
#[extractable(SshProtocolTypes)]
pub struct RawSshMessageFlight {
    pub messages: Vec<RawSshMessage>,
}

impl VecCodecWoSize for RawSshMessage {}

impl OpaqueProtocolMessageFlight<SshProtocolTypes, RawSshMessage> for RawSshMessageFlight {
    fn new() -> Self {
        Self { messages: vec![] }
    }

    fn push(&mut self, msg: RawSshMessage) {
        self.messages.push(msg);
    }

    fn debug(&self, info: &str) {
        log::debug!("{}: {:?}", info, self);
    }
}

impl TryFrom<RawSshMessageFlight> for SshMessageFlight {
    type Error = ();

    fn try_from(value: RawSshMessageFlight) -> Result<Self, Self::Error> {
        let flight = Self {
            messages: value
                .messages
                .iter()
                .filter_map(|m| (*m).clone().try_into().ok())
                .collect(),
        };

        if flight.messages.is_empty() {
            Err(())
        } else {
            Ok(flight)
        }
    }
}

impl Codec for RawSshMessageFlight {
    fn encode(&self, bytes: &mut Vec<u8>) {
        for msg in &self.messages {
            msg.encode(bytes);
        }
    }

    fn read(reader: &mut Reader) -> Option<Self> {
        let mut deframer = SshMessageDeframer::new();
        let mut flight = Self::new();

        let _ = deframer.read(&mut reader.rest());
        while let Some(msg) = deframer.pop_frame() {
            flight.push(msg);
        }

        Some(flight)
    }
}

impl From<SshMessageFlight> for RawSshMessageFlight {
    fn from(value: SshMessageFlight) -> Self {
        Self {
            messages: value.messages.iter().map(|m| m.create_opaque()).collect(),
        }
    }
}

impl From<RawSshMessage> for RawSshMessageFlight {
    fn from(value: RawSshMessage) -> Self {
        Self {
            messages: vec![value],
        }
    }
}

#[derive(Serialize, Deserialize, Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum AgentType {
    Server,
    Client,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub struct SshDescriptorConfig {
    /// Whether the agent which holds this descriptor is a server.
    pub typ: AgentType,
    /// Whether we want to try to reuse a previous agent.
    pub try_reuse: bool,
}

impl ProtocolDescriptorConfig for SshDescriptorConfig {
    fn is_reusable_with(&self, other: &Self) -> bool {
        self.typ == other.typ
    }
}

impl Default for SshDescriptorConfig {
    fn default() -> Self {
        Self {
            typ: AgentType::Server,
            try_reuse: false,
        }
    }
}

#[derive(Clone, Debug, Hash, Serialize, Deserialize)]
pub struct SshProtocolTypes;
impl ProtocolTypes for SshProtocolTypes {
    type Matcher = SshQueryMatcher;
    type PUTConfig = SshDescriptorConfig;

    fn signature() -> &'static Signature<Self> {
        &SSH_SIGNATURE
    }

    fn differential_fuzzing_blacklist() -> Option<Vec<std::any::TypeId>> {
        None
    }

    fn differential_fuzzing_whitelist() -> Option<Vec<std::any::TypeId>> {
        None
    }

    fn differential_fuzzing_terms_to_eval() -> Vec<puffin::algebra::Term<Self>> {
        vec![]
    }

    fn differential_fuzzing_claims_blacklist() -> Option<Vec<TypeId>> {
        None
    }
}

impl std::fmt::Display for SshProtocolTypes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "")
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct SshProtocolBehavior {}

impl ProtocolBehavior for SshProtocolBehavior {
    type Claim = SshClaim;
    type OpaqueProtocolMessage = RawSshMessage;
    type OpaqueProtocolMessageFlight = RawSshMessageFlight;
    type ProtocolMessage = SshMessage;
    type ProtocolMessageFlight = SshMessageFlight;
    type ProtocolTypes = SshProtocolTypes;
    type SecurityViolationPolicy = SshSecurityViolationPolicy;

    fn create_corpus(_put: PutDescriptor) -> Vec<(Trace<Self::ProtocolTypes>, &'static str)> {
        vec![] // TODO
    }

    fn try_read_bytes(
        _bitstring: &[u8],
        _ty: TypeId,
    ) -> Result<Box<dyn EvaluatedTerm<Self::ProtocolTypes>>, Error> {
        todo!()
    }
}
