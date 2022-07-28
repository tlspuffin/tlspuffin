use std::io::Read;

use puffin::{
    algebra::{signature::Signature, AnyMatcher},
    error::Error,
    io::MessageResult,
    protocol::{Message, MessageDeframer, OpaqueMessage, ProtocolBehavior},
    put_registry::PutRegistry,
    trace::Trace,
    variable_data::VariableData,
};

use crate::{
    claim::SshClaim,
    ssh::{russh::client::Msg, SSH_SIGNATURE},
    violation::SshSecurityViolationPolicy,
    SSH_PUT_REGISTRY,
};

impl Message<Msg> for Msg {
    fn create_opaque(&self) -> Msg {
        todo!()
    }

    fn debug(&self, info: &str) {
        todo!()
    }
}

impl OpaqueMessage<Msg> for Msg {
    fn encode(&self) -> Vec<u8> {
        todo!()
    }

    fn into_message(self) -> Result<Msg, Error> {
        todo!()
    }

    fn debug(&self, info: &str) {
        todo!()
    }
}

pub struct SshMessageDeframer {}

impl MessageDeframer<Msg, Msg> for SshMessageDeframer {
    fn new() -> Self {
        todo!()
    }

    fn pop_frame(&mut self) -> Option<Msg> {
        todo!()
    }

    fn encode(&self) -> Vec<u8> {
        todo!()
    }

    fn read(&mut self, rd: &mut dyn Read) -> std::io::Result<usize> {
        todo!()
    }
}

#[derive(Clone)]
pub struct SshProtocolBehavior {}

impl ProtocolBehavior for SshProtocolBehavior {
    type Claim = SshClaim;
    type SecurityViolationPolicy = SshSecurityViolationPolicy;
    type Message = Msg;
    type OpaqueMessage = Msg;
    type MessageDeframer = SshMessageDeframer;
    type Matcher = AnyMatcher;

    fn signature() -> &'static Signature {
        &SSH_SIGNATURE
    }

    fn registry() -> &'static PutRegistry<Self>
    where
        Self: Sized,
    {
        &SSH_PUT_REGISTRY
    }

    fn create_corpus() -> Vec<(Trace<Self::Matcher>, &'static str)> {
        vec![] // TODO
    }

    fn extract_query_matcher(
        message_result: &MessageResult<Self::Message, Self::OpaqueMessage>,
    ) -> Self::Matcher {
        todo!()
    }

    fn extract_knowledge(message: &Self::Message) -> Result<Vec<Box<dyn VariableData>>, Error> {
        todo!()
    }
}
