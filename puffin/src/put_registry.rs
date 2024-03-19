use std::collections::HashMap;

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
pub struct PutRegistry<PB> {
    factories: HashMap<String, Box<dyn Factory<PB>>>,
    default_put: String,
}

impl<PB: ProtocolBehavior> PutRegistry<PB> {
    pub fn new<SI, I, S>(puts: I, default: S) -> Self
    where
        SI: Into<String>,
        I: IntoIterator<Item = (SI, Box<dyn Factory<PB>>)>,
        S: Into<String>,
    {
        let result = Self {
            factories: puts
                .into_iter()
                .map(|(id, f)| (Into::<String>::into(id), f))
                .collect(),
            default_put: default.into(),
        };

        // check that the default PUT is actually in the registry
        let _ = result.find_by_id(&result.default_put);

        result
    }

    pub fn default(&self) -> &dyn Factory<PB> {
        self.find_by_id(&self.default_put)
            .unwrap_or_else(|| panic!("default PUT {} is not in registry", &self.default_put))
    }

    pub fn puts(&self) -> impl Iterator<Item = (&str, &dyn Factory<PB>)> {
        self.factories
            .iter()
            .map(|(n, f)| (n.as_str(), f.to_owned().as_ref()))
    }

    pub fn find_by_id<S: AsRef<str>>(&self, id: S) -> Option<&dyn Factory<PB>> {
        self.factories
            .get(id.as_ref())
            .map(|f| f.to_owned().as_ref())
    }
}

impl<PB: ProtocolBehavior> Clone for PutRegistry<PB> {
    fn clone(&self) -> Self {
        Self::new(
            self.factories
                .iter()
                .map(|(n, f)| (n.clone(), f.clone_factory())),
            self.default_put.clone(),
        )
    }
}

#[derive(Debug)]
pub enum PutKind {
    CPUT,
    Rust,
}

/// Factory for instantiating programs-under-test.
pub trait Factory<PB: ProtocolBehavior> {
    fn create(
        &self,
        context: &TraceContext<PB>,
        agent_descriptor: &AgentDescriptor,
    ) -> Result<Box<dyn Put<PB>>, Error>;

    fn kind(&self) -> PutKind;
    fn name(&self) -> PutName;
    fn versions(&self) -> Vec<(String, String)>;

    fn clone_factory(&self) -> Box<dyn Factory<PB>>;
}
