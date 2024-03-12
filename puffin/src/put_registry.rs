use std::fmt::{Debug, Formatter};

use log::debug;

use crate::{
    agent::AgentDescriptor,
    error::Error,
    protocol::ProtocolBehavior,
    put::{Put, PutName},
    trace::TraceContext,
};

pub const DUMMY_PUT: PutName = PutName(['D', 'U', 'M', 'Y', 'Y', 'D', 'U', 'M', 'M', 'Y']);

/// Registry for [Factories](Factory). An instance of this is usually defined statically and then
/// used throughout the fuzzer.
#[derive(PartialEq)]
pub struct PutRegistry<PB: 'static> {
    pub factories: &'static [fn() -> Box<dyn Factory<PB>>],
    pub default: fn() -> Box<dyn Factory<PB>>,
}

impl<PB: ProtocolBehavior + 'static> Debug for PutRegistry<PB> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PutRegistry (default only)")
            .field("default", &(self.default)().name())
            .finish()
    }
}

impl<PB: ProtocolBehavior> PutRegistry<PB> {
    pub fn version_strings(&self) -> Vec<String> {
        let mut put_versions = Vec::new();
        for func in self.factories {
            let factory = func();

            let name = factory.name();
            let version = factory.version();
            put_versions.push(format!("{}: {}", name, version));
        }
        put_versions
    }

    pub fn default_factory(&self) -> Box<dyn Factory<PB>> {
        (self.default)()
    }

    pub fn find_factory(&self, put_name: PutName) -> Option<Box<dyn Factory<PB>>> {
        self.factories
            .iter()
            .map(|func| func())
            .find(|factory: &Box<dyn Factory<PB>>| factory.name() == put_name)
    }

    /// To be called at the beginning of all fuzzing campaigns!
    pub fn determinism_set_reseed_all_factories(&self) -> () {
        debug!("== Set and reseed all ({}):", self.factories.len());
        for func in self.factories {
            func().determinism_set_reseed();
        }
    }

    pub fn determinism_reseed_all_factories(&self) -> () {
        debug!("== Reseed all ({}):", self.factories.len());
        for func in self.factories {
            func().determinism_reseed();
        }
    }
}

/// Factory for instantiating programs-under-test.
pub trait Factory<PB: ProtocolBehavior> {
    fn create(
        &self,
        context: &TraceContext<PB>,
        agent_descriptor: &AgentDescriptor,
    ) -> Result<Box<dyn Put<PB>>, Error>;
    fn name(&self) -> PutName;
    fn version(&self) -> String;

    fn determinism_set_reseed(&self) -> ();

    fn determinism_reseed(&self) -> ();
}
