use std::{
    fmt::{Debug, Display},
    slice::Iter,
};

use crate::{
    agent::{AgentDescriptor, AgentName},
    algebra::{signature::Signature, QueryMatcher},
    claims::{Claim, Policy},
    error::Error,
    io,
    io::MessageResult,
    protocol::ProtocolBehavior,
    put::{Put, PutDescriptor, PutName},
    trace::{Trace, TraceContext},
    variable_data::VariableData,
};

pub const DUMMY_PUT: PutName = PutName(['D', 'U', 'M', 'Y', 'Y', 'D', 'U', 'M', 'M', 'Y']);

pub struct PutRegistry<PB: 'static> {
    pub factories: &'static [fn() -> Box<dyn Factory<PB>>],
}

impl<PB: ProtocolBehavior> PutRegistry<PB> {
    pub fn version_strings(&self) -> Vec<String> {
        let mut put_versions = Vec::new();
        for func in self.factories {
            let factory = func();

            let name = factory.put_name();
            let version = factory.put_version();
            put_versions.push(format!("{}: {}", name, version));
        }
        put_versions
    }

    pub fn make_deterministic(&self) {
        for func in self.factories {
            let factory = func();
            factory.make_deterministic();
        }
    }

    pub fn find_factory(&self, put_name: PutName) -> Option<Box<dyn Factory<PB>>> {
        self.factories
            .iter()
            .map(|func| func())
            .find(|factory: &Box<dyn Factory<PB>>| factory.put_name() == put_name)
    }
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
