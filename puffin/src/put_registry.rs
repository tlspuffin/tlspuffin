use std::{
    collections::HashMap,
    fmt::{Debug, Formatter},
};

use itertools::Itertools;

use crate::{
    agent::AgentDescriptor,
    error::Error,
    protocol::ProtocolBehavior,
    put::{Put, PutOptions},
    trace::TraceContext,
};

// FIXME TCP_PUT should be defined in the tlspuffin package
//
//     The TCP PUT is specific to TLS and is therefore defined in the `tlspuffin` package. However,
//     we expose it here in `puffin` so that the generic CLI is able to provide the `tcp` command.
//
//     Once we factor out the `tcp` command, we can move this definition into `tlspuffin`.
pub const TCP_PUT: &str = "rust-put-tcp";

/// Registry for [Factories](Factory). An instance of this is usually defined statically and then
/// used throughout the fuzzer.
pub struct PutRegistry<PB> {
    factories: HashMap<String, Box<dyn Factory<PB>>>,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Default)]
pub struct PutDescriptor {
    pub factory: String,
    pub options: PutOptions,
}

impl<PB: ProtocolBehavior> PartialEq for PutRegistry<PB> {
    fn eq(&self, other: &Self) -> bool {
        self.factories.len() == other.factories.len()
            && self
                .factories
                .keys()
                .all(|id| other.factories.contains_key(id))
    }
}

impl<PB: ProtocolBehavior> Debug for PutRegistry<PB> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("PutRegistry(")?;
        f.debug_list()
            .entries(self.factories.keys().sorted())
            .finish()?;
        f.write_str(")")?;
        Ok(())
    }
}

impl<PB: ProtocolBehavior> PutRegistry<PB> {
    pub fn new<I>(puts: I) -> Self
    where
        I: IntoIterator<Item = Box<dyn Factory<PB>>>,
    {
        Self {
            factories: puts.into_iter().map(|f| (f.name(), f)).collect(),
        }
    }

    // FIXME remove PutRegistry::default() once compile-time PUT definitions are removed
    pub fn default(&self) -> &dyn Factory<PB> {
        // grab the first non-TCP PUT if any, else the TCP PUT
        self.puts()
            .find(|p| p.name() != TCP_PUT)
            .unwrap_or_else(|| self.find_by_id(TCP_PUT).expect("PUT registry is empty"))
    }

    pub fn puts(&self) -> impl Iterator<Item = &dyn Factory<PB>> {
        self.factories.values().map(|f| f.to_owned().as_ref())
    }

    pub fn find_by_id<S: AsRef<str>>(&self, id: S) -> Option<&dyn Factory<PB>> {
        self.factories
            .get(id.as_ref())
            .map(|f| f.to_owned().as_ref())
    }

    pub fn determinism_reseed_all_factories(&self) {
        log::debug!("== [RNG] reseed all PUT factories");
        for (_, factory) in self.factories.iter() {
            factory.rng_reseed();
        }
    }
}

impl<PB: ProtocolBehavior> Clone for PutRegistry<PB> {
    fn clone(&self) -> Self {
        Self::new(self.factories.values().map(|f| f.clone_factory()))
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
    fn name(&self) -> String;
    fn versions(&self) -> Vec<(String, String)>;

    fn supports(&self, capability: &str) -> bool;

    fn clone_factory(&self) -> Box<dyn Factory<PB>>;

    fn rng_reseed(&self) {
        log::debug!("[RNG] reseed failed ({}): not supported", self.name());
    }
}
