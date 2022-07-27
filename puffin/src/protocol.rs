use std::fmt::Debug;

use crate::{
    algebra::{signature::Signature, Matcher},
    claims::{Claim, SecurityViolationPolicy},
    error::Error,
    io::MessageResult,
    put_registry::PutRegistry,
    trace::Trace,
    variable_data::VariableData,
};

pub trait Message<O: OpaqueMessage<Self>>: Clone + Debug {
    fn create_opaque(&self) -> O;
    fn debug(&self, info: &str);
}

pub trait OpaqueMessage<M: Message<Self>>: Clone + Debug {
    fn encode(&self) -> Vec<u8>;
    fn into_message(self) -> Result<M, Error>;
    fn debug(&self, info: &str);
}

pub trait MessageDeframer<M: Message<O>, O: OpaqueMessage<M>> {
    fn new() -> Self;
    fn pop_frame(&mut self) -> Option<O>;
    fn encode(&self) -> Vec<u8>;
    fn read(&mut self, rd: &mut dyn std::io::Read) -> std::io::Result<usize>;
}

pub trait ProtocolBehavior: 'static {
    type Claim: Claim;
    type SecurityViolationPolicy: SecurityViolationPolicy<Self::Claim>;

    type Message: Message<Self::OpaqueMessage>;
    type OpaqueMessage: OpaqueMessage<Self::Message>;
    type MessageDeframer: MessageDeframer<Self::Message, Self::OpaqueMessage>;

    type Matcher: Matcher;

    fn extract_knowledge(message: &Self::Message) -> Result<Vec<Box<dyn VariableData>>, Error>;

    fn signature() -> &'static Signature;

    fn registry() -> &'static PutRegistry<Self>
    where
        Self: Sized;

    fn create_corpus() -> Vec<(Trace<Self::Matcher>, &'static str)>;

    fn extract_query_matcher(
        message_result: &MessageResult<Self::Message, Self::OpaqueMessage>,
    ) -> Self::Matcher;
}
