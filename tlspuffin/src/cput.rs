use std::{cell::RefCell, rc::Rc};

use puffin::{
    agent::AgentType, error::Error, put::Put, put_registry::Factory, stream::Stream, VERSION_STR,
};
use tls_harness::{CPutHarness, CPutLibrary, C_PUT_INTERFACE};

use crate::{
    protocol::{OpaqueMessageFlight, TLSProtocolBehavior},
    put::TlsPutConfig,
    query::TlsQueryMatcher,
    tls::rustls::msgs::message::{Message, OpaqueMessage},
};

pub fn new_factory(
    harness: CPutHarness,
    library: CPutLibrary,
    interface: C_PUT_INTERFACE,
) -> Box<dyn Factory<TLSProtocolBehavior>> {
    Box::new(TlsCPut {
        harness,
        library,
        interface,
    })
}

#[derive(Clone)]
struct TlsCPut {
    harness: CPutHarness,
    library: CPutLibrary,
    interface: C_PUT_INTERFACE,
}

impl Factory<TLSProtocolBehavior> for TlsCPut {
    fn create(
        &self,
        context: &puffin::trace::TraceContext<TLSProtocolBehavior>,
        agent_descriptor: &puffin::agent::AgentDescriptor,
    ) -> Result<Box<dyn puffin::put::Put<TLSProtocolBehavior>>, puffin::error::Error> {
        let put_descriptor = context.put_descriptor(agent_descriptor);
        let options = &put_descriptor.options;

        let use_clear = options
            .get_option("use_clear")
            .map(|value| value.parse().unwrap_or(false))
            .unwrap_or(false);

        let config = TlsPutConfig {
            descriptor: agent_descriptor.clone(),
            claims: context.claims().clone(),
            authenticate_peer: agent_descriptor.typ == AgentType::Client
                && agent_descriptor.server_authentication
                || agent_descriptor.typ == AgentType::Server
                    && agent_descriptor.client_authentication,
            extract_deferred: Rc::new(RefCell::new(None)),
            use_clear,
        };

        Ok(Box::new(TlsCAgent::new(config).map_err(|err| {
            Error::Put(format!("Failed to create client/server: {}", err))
        })?))
    }

    fn kind(&self) -> puffin::put_registry::PutKind {
        puffin::put_registry::PutKind::CPUT
    }

    fn name(&self) -> String {
        self.library.config_name.to_string()
    }

    fn versions(&self) -> Vec<(String, String)> {
        vec![
            (
                "harness".to_owned(),
                format!("{} ({})", self.harness.name, VERSION_STR),
            ),
            (
                "library".to_owned(),
                format!(
                    "{} ({} / {})",
                    self.library.config_name, self.library.version, self.library.config_hash
                ),
            ),
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
        self.harness.capabilities.contains(capability)
    }

    fn clone_factory(&self) -> Box<dyn Factory<TLSProtocolBehavior>> {
        Box::new(self.clone())
    }
}

struct TlsCAgent {
    config: TlsPutConfig,
}

impl TlsCAgent {
    fn new(config: TlsPutConfig) -> Result<Self, Error> {
        Ok(Self { config })
    }
}

impl Put<TLSProtocolBehavior> for TlsCAgent {
    fn progress(&mut self) -> Result<(), Error> {
        todo!()
    }

    fn reset(&mut self, new_name: puffin::agent::AgentName) -> Result<(), Error> {
        self.config.descriptor.name = new_name;
        todo!()
    }

    fn descriptor(&self) -> &puffin::agent::AgentDescriptor {
        todo!()
    }

    fn describe_state(&self) -> String {
        todo!()
    }

    fn is_state_successful(&self) -> bool {
        todo!()
    }

    fn shutdown(&mut self) -> String {
        todo!()
    }

    fn version() -> String
    where
        Self: Sized,
    {
        todo!()
    }
}

impl Stream<TlsQueryMatcher, Message, OpaqueMessage, OpaqueMessageFlight> for TlsCAgent {
    fn add_to_inbound(&mut self, message_flight: &OpaqueMessageFlight) {
        let _ = message_flight;
        todo!()
    }

    fn take_message_from_outbound(&mut self) -> Result<Option<OpaqueMessageFlight>, Error> {
        todo!()
    }
}
