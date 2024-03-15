use std::fmt;

use crate::{
    agent::AgentDescriptor,
    error::Error,
    protocol::ProtocolBehavior,
    put::{Put, PutName},
    trace::TraceContext,
};

pub type LibraryId = String;
pub type HarnessId = PutName;

pub const DUMMY_PUT: PutName = PutName(['D', 'U', 'M', 'Y', 'Y', 'D', 'U', 'M', 'M', 'Y']);

#[derive(PartialEq, Eq, Clone)]
pub struct PutId {
    pub harness: HarnessId,
    pub library: LibraryId,
}

impl fmt::Display for PutId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "(harness={}, library={})", self.harness, self.library)
    }
}

/// Registry for [Factories](Factory). An instance of this is usually defined statically and then
/// used throughout the fuzzer.
pub struct PutRegistry<PB> {
    factories: Vec<fn() -> Box<dyn Factory<PB>>>,
    default_put: PutId,
}

impl<PB: ProtocolBehavior> PutRegistry<PB> {
    pub fn new(factories: &[fn() -> Box<dyn Factory<PB>>], default: PutId) -> Self {
        let result = Self {
            factories: factories.to_vec(),
            default_put: default,
        };

        result
            .find_id(&result.default_put)
            .unwrap_or_else(|| panic!("default PUT {} is not in registry", &result.default_put));

        result
    }

    pub fn version_strings(&self) -> Vec<String> {
        let mut put_versions = Vec::new();
        for func in &self.factories {
            let factory = func();

            let name = factory.name();
            let version = factory.version();
            put_versions.push(format!("{}: {}", name, version));
        }
        put_versions
    }

    pub fn default(&self) -> Box<dyn Factory<PB>> {
        self.find_id(&self.default_put).unwrap()
    }

    pub fn find_id(&self, id: &PutId) -> Option<Box<dyn Factory<PB>>> {
        self.factories
            .iter()
            .map(|f| f())
            .find(|factory| factory.id() == id.clone())
    }

    pub fn search<'a, P>(&'a self, predicate: P) -> impl Iterator<Item = Box<dyn Factory<PB>>> + 'a
    where
        P: Fn(&PutId) -> bool + 'a,
    {
        self.factories
            .iter()
            .map(|f| f())
            .filter(move |factory| predicate(&factory.id()))
    }
}

impl<PB: ProtocolBehavior> Clone for PutRegistry<PB> {
    fn clone(&self) -> Self {
        Self::new(&self.factories, self.default_put.clone())
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

    fn library(&self) -> LibraryId;

    fn version(&self) -> String;

    fn id(&self) -> PutId {
        PutId {
            harness: self.name(),
            library: self.library(),
        }
    }
}
