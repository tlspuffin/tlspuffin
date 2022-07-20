use rustls::msgs::message::Message;

use crate::{
    agent::{AgentDescriptor, AgentName},
    algebra::signature::Signature,
    claims::{ClaimTrait, Policy},
    error::Error,
    put::{Put, PutDescriptor, PutName},
    trace::{Trace, TraceContext},
    variable_data::VariableData,
};

pub const DUMMY_PUT: PutName = PutName(['D', 'U', 'M', 'Y', 'Y', 'D', 'U', 'M', 'M', 'Y']);

pub trait PutRegistry<PB> {
    fn version_strings(&self) -> Vec<String>;
    fn make_deterministic(&self);
    fn find_factory(&self, put_name: PutName) -> Option<Box<dyn Factory<PB>>>;
}

pub trait ProtocolBehavior {
    type Claim: ClaimTrait;

    fn policy() -> Policy<Self::Claim>;

    fn extract_knowledge(message: &Message) -> Result<Vec<Box<dyn VariableData>>, Error>;

    fn signature() -> &'static Signature;

    fn create_corpus() -> Vec<(Trace, &'static str)>;
    fn new_registry() -> &'static dyn PutRegistry<Self>;
}

pub trait Factory<PB: ProtocolBehavior> {
    fn create(
        &self,
        context: &TraceContext<PB>,
        agent_descriptor: &AgentDescriptor,
    ) -> Result<Box<dyn Put>, Error>;
    fn put_name(&self) -> PutName;
    fn put_version(&self) -> &'static str;
    fn make_deterministic(&self);
}
