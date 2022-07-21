use std::{
    fmt::{Debug, Display},
    slice::Iter,
};

use crate::{
    agent::{AgentDescriptor, AgentName},
    algebra::signature::Signature,
    claims::{ClaimTrait, Policy},
    error::Error,
    io,
    io::MessageResult,
    put::{Put, PutDescriptor, PutName},
    trace::{QueryMatcher, Trace, TraceContext},
    variable_data::VariableData,
};

pub const DUMMY_PUT: PutName = PutName(['D', 'U', 'M', 'Y', 'Y', 'D', 'U', 'M', 'M', 'Y']);

pub trait PutRegistry<PB> {
    fn version_strings(&self) -> Vec<String>;
    fn make_deterministic(&self);
    fn find_factory(&self, put_name: PutName) -> Option<Box<dyn Factory<PB>>>;
}

pub trait Message<O: OpaqueMessage<Self>>: Clone + Debug {
    fn create_opaque(&self) -> O;
}

pub trait OpaqueMessage<M: Message<Self>>: Clone + Debug {
    fn encode(&self) -> Vec<u8>;

    fn into_message(self) -> Result<M, Error>;
}

pub trait MessageDeframer<M: Message<O>, O: OpaqueMessage<M>> {
    fn new() -> Self;
    fn pop_frame(&mut self) -> Option<O>;
    fn encode(&self) -> Vec<u8>;
    fn read(&mut self, rd: &mut dyn std::io::Read) -> std::io::Result<usize>;
}

pub trait ProtocolBehavior: 'static {
    type Claim: ClaimTrait;
    type Message: Message<Self::OpaqueMessage>;
    type OpaqueMessage: OpaqueMessage<Self::Message>;
    type MessageDeframer: MessageDeframer<Self::Message, Self::OpaqueMessage>;
    type QueryMatcher: QueryMatcher;

    fn policy() -> Policy<Self::Claim>;

    fn extract_knowledge(message: &Self::Message) -> Result<Vec<Box<dyn VariableData>>, Error>;

    fn signature() -> &'static Signature;

    fn create_corpus() -> Vec<(Trace<Self::QueryMatcher>, &'static str)>;
    fn new_registry() -> &'static dyn PutRegistry<Self>;

    fn to_query_matcher(
        message_result: &MessageResult<Self::Message, Self::OpaqueMessage>,
    ) -> Self::QueryMatcher;
}

pub trait Factory<PB: ProtocolBehavior> {
    fn create(
        &self,
        context: &TraceContext<PB>,
        agent_descriptor: &AgentDescriptor,
    ) -> Result<Box<dyn Put<PB>>, Error>;
    fn put_name(&self) -> PutName;
    fn put_version(&self) -> &'static str;
    fn make_deterministic(&self);
}
