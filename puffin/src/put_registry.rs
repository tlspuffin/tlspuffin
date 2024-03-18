use std::fmt::{self, Debug, Formatter};

use log::debug;

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
    factories: Vec<Box<dyn Factory<PB>>>,
    default_put: PutId,
}

impl<PB: ProtocolBehavior> PartialEq for PutRegistry<PB> {
    fn eq(&self, other: &Self) -> bool {
        self.default_put == other.default_put
            && self
                .factories
                .iter()
                .zip(other.factories.iter())
                .all(|(a, b)| a.id() == b.id())
    }
}

impl<PB: ProtocolBehavior> Debug for PutRegistry<PB> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PutRegistry (default only)")
            .field("default", &self.default().name())
            .finish()
    }
}

impl<PB: ProtocolBehavior> PutRegistry<PB> {
    pub fn new(factories: Vec<Box<dyn Factory<PB>>>, default: PutId) -> Self {
        let result = Self {
            factories,
            default_put: default,
        };

        result
            .find_id(&result.default_put)
            .unwrap_or_else(|| panic!("default PUT {} is not in registry", &result.default_put));

        result
    }

    pub fn version_strings(&self) -> Vec<String> {
        let mut put_versions = Vec::new();
        for factory in &self.factories {
            let name = factory.name();
            let version = factory.version();
            put_versions.push(format!("{}: {}", name, version));
        }
        put_versions
    }

    pub fn default(&self) -> &dyn Factory<PB> {
        self.find_id(&self.default_put).unwrap()
    }

    pub fn find_id(&self, id: &PutId) -> Option<&dyn Factory<PB>> {
        self.factories
            .iter()
            .map(|f| f.to_owned().as_ref())
            .find(|factory| factory.id() == id.clone())
    }

    pub fn search<'a, P>(&'a self, predicate: P) -> impl Iterator<Item = &dyn Factory<PB>> + 'a
    where
        P: Fn(&PutId) -> bool + 'a,
    {
        self.factories
            .iter()
            .map(|f| f.as_ref())
            .filter(move |factory| predicate(&factory.id()))
    }

    /// To be called at the beginning of all fuzzing campaigns!
    pub fn determinism_set_reseed_all_factories(&self) {
        debug!("== Set and reseed all ({}):", self.factories.len());
        for factory in self.factories.iter() {
            factory.determinism_set_reseed();
        }
    }

    pub fn determinism_reseed_all_factories(&self) {
        debug!("== Reseed all ({}):", self.factories.len());
        for factory in self.factories.iter() {
            factory.determinism_reseed();
        }
    }
}

impl<PB: ProtocolBehavior> Clone for PutRegistry<PB> {
    fn clone(&self) -> Self {
        Self::new(
            self.factories
                .iter()
                .map(|f| f.clone_factory())
                .collect::<Vec<_>>(),
            self.default_put.clone(),
        )
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

    fn determinism_set_reseed(&self);
    fn determinism_reseed(&self);

    fn id(&self) -> PutId {
        PutId {
            harness: self.name(),
            library: self.library(),
        }
    }

    fn clone_factory(&self) -> Box<dyn Factory<PB>>;
}
