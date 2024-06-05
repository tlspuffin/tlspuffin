use std::cell::RefCell;
use std::collections::HashSet;
use std::rc::Rc;

use puffin::agent::{AgentDescriptor, AgentType};
use puffin::algebra::dynamic_function::TypeShape;
use puffin::claims::GlobalClaimList;
use puffin::error::Error;
use puffin::protocol::ProtocolBehavior;
use puffin::put::{Put, PutOptions};
use puffin::put_registry::Factory;

use crate::claims::TlsClaim;
use crate::protocol::{TLSProtocolBehavior, TLSProtocolTypes};
use crate::put_registry::bindings::TLS_PUT_INTERFACE;

/// Static configuration for creating a new agent state for the PUT
#[derive(Clone, Debug)]
pub struct TlsPutConfig {
    pub descriptor: AgentDescriptor,
    pub claims: GlobalClaimList<TlsClaim>,
    pub authenticate_peer: bool,
    pub extract_deferred: Rc<RefCell<Option<TypeShape<TLSProtocolTypes>>>>,
    pub use_clear: bool,
}

impl TlsPutConfig {
    pub fn new(
        agent_descriptor: &AgentDescriptor,
        claims: &GlobalClaimList<<TLSProtocolBehavior as ProtocolBehavior>::Claim>,
        options: &PutOptions,
    ) -> TlsPutConfig {
        let use_clear = options
            .get_option("use_clear")
            .map(|value| value.parse().unwrap_or(false))
            .unwrap_or(false);

        TlsPutConfig {
            descriptor: agent_descriptor.clone(),
            claims: claims.clone(),
            authenticate_peer: agent_descriptor.typ == AgentType::Client
                && agent_descriptor.server_authentication
                || agent_descriptor.typ == AgentType::Server
                    && agent_descriptor.client_authentication,
            extract_deferred: Rc::new(RefCell::new(None)),
            use_clear,
        }
    }
}

#[derive(Clone, Debug)]
pub struct CPut {
    name: String,
    harness_version: String,
    library_version: String,
    capabilities: HashSet<String>,
    interface: TLS_PUT_INTERFACE,
}

impl CPut {
    pub fn new(
        name: impl Into<String>,
        harness_version: impl Into<String>,
        library_version: impl Into<String>,
        capabilities: HashSet<String>,
        interface: TLS_PUT_INTERFACE,
    ) -> Self {
        Self {
            name: name.into(),
            harness_version: harness_version.into(),
            library_version: library_version.into(),
            capabilities,
            interface,
        }
    }
}

impl Factory<TLSProtocolBehavior> for CPut {
    fn create(
        &self,
        _agent_descriptor: &AgentDescriptor,
        _claims: &GlobalClaimList<<TLSProtocolBehavior as ProtocolBehavior>::Claim>,
        _options: &PutOptions,
    ) -> Result<Box<dyn Put<TLSProtocolBehavior>>, Error> {
        todo!()
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
        if self.interface.rng_reseed.is_none() {
            log::debug!("[RNG] reseed failed ({}): not supported", self.name());
            return;
        }

        const DEFAULT_SEED: [u8; 8] = 42u64.to_le().to_ne_bytes();

        log::debug!("[RNG] reseed ({})", self.name());
        unsafe {
            (self.interface.rng_reseed.unwrap())(DEFAULT_SEED.as_ptr(), DEFAULT_SEED.len());
        }
    }

    fn supports(&self, capability: &str) -> bool {
        self.capabilities.contains(capability)
    }

    fn clone_factory(&self) -> Box<dyn Factory<TLSProtocolBehavior>> {
        Box::new(self.clone())
    }
}
