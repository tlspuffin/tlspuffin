use rustls::msgs::message::Message;

use crate::{
    agent::{AgentDescriptor, AgentName},
    algebra::signature::Signature,
    claims::{ClaimTrait, Policy},
    error::Error,
    put::{Put, PutConfig, PutDescriptor, PutName},
    trace::Trace,
    variable_data::VariableData,
};

pub const DUMMY_PUT: PutName = PutName(['D', 'U', 'M', 'Y', 'Y', 'D', 'U', 'M', 'M', 'Y']);

pub struct PutRegistry(pub &'static [fn() -> Box<dyn Factory>]);

impl PutRegistry {}

impl PutRegistry {
    pub fn policy(&self) -> Policy<Box<dyn ClaimTrait>> {
        todo!()
    }

    pub fn extract_knowledge(
        &self,
        message: &Message,
    ) -> Result<Vec<Box<dyn VariableData>>, Error> {
        todo!()
    }

    pub fn signature(&self) -> &'static Signature {
        todo!()
    }

    pub fn create_corpus(&self) -> Vec<(Trace, &str)> {
        todo!()
    }

    pub fn version_strings(&self) -> Vec<String> {
        let mut put_versions = Vec::new();
        for func in self.0 {
            let factory = func();

            let name = factory.put_name();
            let version = factory.put_version();
            put_versions.push(format!("{}: {}", name, version));
        }
        put_versions
    }

    pub fn make_deterministic(&self) {
        for func in self.0 {
            let factory = func();
            factory.make_deterministic();
        }
    }

    pub fn find_factory(&self, put_name: PutName) -> Option<Box<dyn Factory>> {
        self.0
            .iter()
            .map(|func| func())
            .find(|factory: &Box<dyn Factory>| factory.put_name() == put_name)
    }
}

pub trait Factory {
    fn create(&self, agent: &AgentDescriptor, config: PutConfig) -> Result<Box<dyn Put>, Error>;
    fn put_name(&self) -> PutName;
    fn put_version(&self) -> &'static str;
    fn make_deterministic(&self);
}
