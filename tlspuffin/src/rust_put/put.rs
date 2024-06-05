use puffin::agent::AgentDescriptor;
use puffin::claims::GlobalClaimList;
use puffin::error::Error;
use puffin::protocol::ProtocolBehavior;
use puffin::put::{Put, PutOptions};
use puffin::put_registry::Factory;

use crate::protocol::TLSProtocolBehavior;
use crate::put::TlsPutConfig;
use crate::rust_put::RustPut;

#[derive(Debug, Clone)]
pub struct RustFactory {
    name: String,
    harness_version: String,
    library_version: String,
}

impl RustFactory {
    pub fn new(
        name: impl Into<String>,
        harness_version: impl Into<String>,
        library_version: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            harness_version: harness_version.into(),
            library_version: library_version.into(),
        }
    }
}

impl Factory<TLSProtocolBehavior> for RustFactory {
    fn create(
        &self,
        agent_descriptor: &AgentDescriptor,
        claims: &GlobalClaimList<<TLSProtocolBehavior as ProtocolBehavior>::Claim>,
        options: &PutOptions,
    ) -> Result<Box<dyn Put<TLSProtocolBehavior>>, Error> {
        Ok(Box::new(RustPut::new(TlsPutConfig::new(
            agent_descriptor,
            claims,
            options,
        ))?))
    }

    fn name(&self) -> String {
        self.name.clone()
    }

    fn versions(&self) -> Vec<(String, String)> {
        vec![
            ("harness".to_string(), self.harness_version.clone()),
            ("library".to_string(), self.library_version.clone()),
        ]
    }

    fn rng_reseed(&self) {
        log::debug!("[RNG] reseed ({})", self.name());
        crate::rust_put::rand::rng_reseed();
    }

    fn clone_factory(&self) -> Box<dyn Factory<TLSProtocolBehavior>> {
        Box::new(self.clone())
    }
}
