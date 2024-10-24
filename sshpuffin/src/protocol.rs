use std::any::TypeId;

use puffin::algebra::signature::Signature;
use puffin::algebra::ConcreteMessage;
use puffin::codec;
use puffin::codec::{Codec, Reader};
use puffin::error::Error;
use puffin::protocol::{
    EvaluatedTerm, OpaqueProtocolMessageFlight, ProtocolBehavior, ProtocolMessage,
    ProtocolMessageDeframer, ProtocolMessageFlight, ProtocolTypes,
};
use puffin::trace::{Knowledge, Source, Trace};
use serde::{Deserialize, Serialize};

use crate::claim::SshClaim;
use crate::query::SshQueryMatcher;
use crate::ssh::deframe::SshMessageDeframer;
use crate::ssh::message::{RawSshMessage, SshMessage};
use crate::ssh::SSH_SIGNATURE;
use crate::violation::SshSecurityViolationPolicy;

#[derive(Debug, Clone)]
pub struct SshMessageFlight {
    pub messages: Vec<SshMessage>,
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

impl EvaluatedTerm<SshProtocolTypes> for SshMessageFlight {
    fn extract_knowledge<'a>(
        &'a self,
        knowledges: &mut Vec<Knowledge<'a, SshProtocolTypes>>,
        matcher: Option<<SshProtocolTypes as ProtocolTypes>::Matcher>,
        source: &'a Source,
    ) -> Result<(), Error> {
        knowledges.push(Knowledge {
            source,
            matcher,
            data: self,
        });
        for msg in &self.messages {
            msg.extract_knowledge(knowledges, matcher, source)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct RawSshMessageFlight {
    pub messages: Vec<RawSshMessage>,
}

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

impl EvaluatedTerm<SshProtocolTypes> for RawSshMessageFlight {
    fn extract_knowledge<'a>(
        &'a self,
        knowledges: &mut Vec<Knowledge<'a, SshProtocolTypes>>,
        matcher: Option<<SshProtocolTypes as ProtocolTypes>::Matcher>,
        source: &'a Source,
    ) -> Result<(), Error> {
        knowledges.push(Knowledge {
            source,
            matcher,
            data: self,
        });
        for msg in &self.messages {
            msg.extract_knowledge(knowledges, matcher, source)?;
        }
        Ok(())
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

#[derive(Clone, Debug, Hash, Serialize, Deserialize)]
pub struct SshProtocolTypes;
impl ProtocolTypes for SshProtocolTypes {
    type Matcher = SshQueryMatcher;

    fn signature() -> &'static Signature<Self> {
        &SSH_SIGNATURE
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

    fn create_corpus() -> Vec<(Trace<Self::ProtocolTypes>, &'static str)> {
        vec![] // TODO
    }

    fn any_get_encoding(
        message: &dyn EvaluatedTerm<Self::ProtocolTypes>,
    ) -> Result<ConcreteMessage, Error> {
        match message
            .as_any()
            .downcast_ref::<SshMessage>()
            .map(|b| codec::Encode::get_encoding(&b.create_opaque()))
        {
            Some(cm) => Ok(cm),
            None => message
                .as_any()
                .downcast_ref::<RawSshMessage>()
                .map(|b| codec::Encode::get_encoding(b))
                .ok_or(Error::Term(
                    "[any_get_encoding] Unable to encode (Raw)SshMessage".to_string(),
                )),
        }
    }

    fn try_read_bytes(
        bitstring: &[u8],
        ty: TypeId,
    ) -> Result<Box<dyn EvaluatedTerm<Self::ProtocolTypes>>, Error> {
        todo!()
    }
}
