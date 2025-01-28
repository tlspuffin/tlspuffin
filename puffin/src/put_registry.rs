use std::collections::HashMap;
use std::fmt;

use crate::agent::AgentDescriptor;
use crate::claims::GlobalClaimList;
use crate::error::Error;
use crate::protocol::{ProtocolBehavior, ProtocolTypes};
use crate::put::{Put, PutOptions};

// FIXME TCP_PUT should be defined in the tlspuffin package
//
//     The TCP PUT is specific to TLS and is therefore defined in the `tlspuffin` package. However,
//     we expose it here in `puffin` so that the generic CLI is able to provide the `tcp` command.
//
//     Once we factor out the `tcp` command, we can move this definition into `tlspuffin`.
pub const TCP_PUT: &str = "tcp";

/// Registry for [Factories](Factory). An instance of this is usually defined statically and then
/// used throughout the fuzzer.
pub struct PutRegistry<PB> {
    factories: HashMap<String, Box<dyn Factory<PB>>>,
    default_put: String,
}

impl<PB> PutRegistry<PB> {
    pub fn set_default(&mut self, name: &str) -> Result<(), String> {
        if self.factories.get(name).is_none() {
            return Err(format!("PUT {} not found in registry", name));
        }
        self.default_put = String::from(name);
        Ok(())
    }

    pub fn default_put_name(&self) -> &str {
        &self.default_put
    }
}

impl<PB: ProtocolBehavior> PartialEq for PutRegistry<PB> {
    fn eq(&self, other: &Self) -> bool {
        self.default_put == other.default_put
            && self.factories.len() == other.factories.len()
            && self
                .factories
                .keys()
                .all(|id| other.factories.contains_key(id))
    }
}

impl<PB: ProtocolBehavior> fmt::Debug for PutRegistry<PB> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PutRegistry (default only)")
            .field("default", &self.default().name())
            .finish()
    }
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

    #[must_use]
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

    pub fn determinism_reseed_all_factories(&self) {
        log::debug!("[RNG] reseed all PUT factories");
        for factory in self.factories.values() {
            factory.rng_reseed();
        }
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

/// Factory for instantiating programs-under-test.
pub trait Factory<PB: ProtocolBehavior> {
    fn create(
        &self,
        agent_descriptor: &AgentDescriptor<
            <<PB as ProtocolBehavior>::ProtocolTypes as ProtocolTypes>::PUTConfig,
        >,
        claims: &GlobalClaimList<PB::Claim>,
        options: &PutOptions,
    ) -> Result<Box<dyn Put<PB>>, Error>;

    fn name(&self) -> String;
    fn versions(&self) -> Vec<(String, String)>;

    fn supports(&self, capability: &str) -> bool;

    fn clone_factory(&self) -> Box<dyn Factory<PB>>;

    fn rng_reseed(&self) {
        log::debug!("[RNG] reseed failed ({}): not supported", self.name());
    }
}
