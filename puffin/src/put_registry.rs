use crate::{
    agent::{AgentDescriptor, AgentName},
    error::Error,
    put::{Put, PutConfig, PutDescriptor, PutName},
};

pub struct PutRegistry(&'static [fn() -> Box<dyn Factory>]);

impl PutRegistry {
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

pub const CURRENT_PUT_NAME: PutName = {
    cfg_if::cfg_if! {
        if #[cfg(feature = "openssl-binding")] {
            OPENSSL111_PUT
        } else if #[cfg(feature = "wolfssl-binding")] {
            WOLFSSL520_PUT
        } else {
            DUMMY_PUT
        }
    }
};

pub fn current_put() -> PutDescriptor {
    PutDescriptor {
        name: CURRENT_PUT_NAME,
        ..PutDescriptor::default()
    }
}
