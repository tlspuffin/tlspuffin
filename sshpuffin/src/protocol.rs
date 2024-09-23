use log::debug;
use puffin::{
    algebra::signature::Signature,
    codec::{Codec, Reader},
    error::Error,
    protocol::{
        ExtractKnowledge, OpaqueProtocolMessageFlight, ProtocolBehavior, ProtocolMessage,
        ProtocolMessageDeframer, ProtocolMessageFlight,
    },
    trace::{Knowledge, Source, Trace},
};

use crate::{
    claim::SshClaim,
    query::SshQueryMatcher,
    ssh::{
        deframe::SshMessageDeframer,
        message::{RawSshMessage, SshMessage},
        SSH_SIGNATURE,
    },
    violation::SshSecurityViolationPolicy,
};

#[derive(Debug, Clone)]
pub struct SshMessageFlight {
    pub messages: Vec<SshMessage>,
}

impl ProtocolMessageFlight<SshQueryMatcher, SshMessage, RawSshMessage, RawSshMessageFlight>
    for SshMessageFlight
{
    fn new() -> Self {
        Self { messages: vec![] }
    }

    fn push(&mut self, msg: SshMessage) {
        self.messages.push(msg);
    }

    fn debug(&self, info: &str) {
        debug!("{}: {:?}", info, self);
    }
}

impl From<SshMessage> for SshMessageFlight {
    fn from(value: SshMessage) -> Self {
        Self {
            messages: vec![value],
        }
    }
}

impl ExtractKnowledge<SshQueryMatcher> for SshMessageFlight {
    fn extract_knowledge<'a>(
        &'a self,
        knowledges: &mut Vec<Knowledge<'a, SshQueryMatcher>>,
        matcher: Option<SshQueryMatcher>,
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

impl OpaqueProtocolMessageFlight<SshQueryMatcher, RawSshMessage> for RawSshMessageFlight {
    fn new() -> Self {
        Self { messages: vec![] }
    }

    fn push(&mut self, msg: RawSshMessage) {
        self.messages.push(msg);
    }

    fn debug(&self, info: &str) {
        debug!("{}: {:?}", info, self);
    }
}

impl ExtractKnowledge<SshQueryMatcher> for RawSshMessageFlight {
    fn extract_knowledge<'a>(
        &'a self,
        knowledges: &mut Vec<Knowledge<'a, SshQueryMatcher>>,
        matcher: Option<SshQueryMatcher>,
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

        if flight.messages.len() == 0 {
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

#[derive(Clone, Debug, PartialEq)]
pub struct SshProtocolBehavior {}

impl ProtocolBehavior for SshProtocolBehavior {
    type Claim = SshClaim;
    type SecurityViolationPolicy = SshSecurityViolationPolicy;
    type ProtocolMessage = SshMessage;
    type OpaqueProtocolMessage = RawSshMessage;
    type Matcher = SshQueryMatcher;
    type ProtocolMessageFlight = SshMessageFlight;
    type OpaqueProtocolMessageFlight = RawSshMessageFlight;

    fn signature() -> &'static Signature {
        &SSH_SIGNATURE
    }

    fn create_corpus() -> Vec<(Trace<Self::Matcher>, &'static str)> {
        vec![] // TODO
    }
}
