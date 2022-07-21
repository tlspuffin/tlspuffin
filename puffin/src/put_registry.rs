use std::fmt::{Debug, Display};

use crate::{
    agent::{AgentDescriptor, AgentName},
    algebra::signature::Signature,
    claims::{ClaimTrait, Policy},
    error::Error,
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

pub trait Message<O: OpaqueMessage>: Clone + Debug {
    fn create_opaque(&self) -> O;
}

pub trait OpaqueMessage: Clone + Debug {
    fn encode(&self) -> Vec<u8>;
}

pub trait ProtocolBehavior: 'static {
    type Claim: ClaimTrait;
    type Message: Message<Self::OpaqueMessage>;
    type OpaqueMessage: OpaqueMessage;
    type QueryMatcher: QueryMatcher;

    fn policy() -> Policy<Self::Claim>;

    fn extract_knowledge(message: &Self::Message) -> Result<Vec<Box<dyn VariableData>>, Error>;

    fn signature() -> &'static Signature;

    fn create_corpus() -> Vec<(Trace<Self::QueryMatcher>, &'static str)>;
    fn new_registry() -> &'static dyn PutRegistry<Self>;
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
