use puffin::{put_registry::Factory, VERSION_STR};
use tls_harness::{CPutHarness, CPutLibrary, C_PUT_TYPE};

use crate::protocol::TLSProtocolBehavior;

pub fn new_factory(
    harness: CPutHarness,
    library: CPutLibrary,
    cput: &'static C_PUT_TYPE,
) -> Box<dyn Factory<TLSProtocolBehavior>> {
    Box::new(TlsCPut {
        harness,
        library,
        c_data: cput,
    })
}

struct TlsCPut {
    harness: CPutHarness,
    library: CPutLibrary,

    c_data: &'static C_PUT_TYPE,
}

impl Factory<TLSProtocolBehavior> for TlsCPut {
    fn create(
        &self,
        _agent_descriptor: &puffin::agent::AgentDescriptor,
        _claims: &puffin::claims::GlobalClaimList<
            <TLSProtocolBehavior as puffin::protocol::ProtocolBehavior>::Claim,
        >,
        _options: &puffin::put::PutOptions,
    ) -> Result<Box<dyn puffin::put::Put<TLSProtocolBehavior>>, puffin::error::Error> {
        todo!()
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
                    self.library.name, self.library.version, self.library.config_hash
                ),
            ),
        ]
    }

    fn supports(&self, _capability: &str) -> bool {
        false
    }

    fn determinism_reseed(&self) {
        if !self.supports_deterministic_rng() {
            log::error!(
                "[Determinism] C PUT {} has no support for deterministic RNG",
                self.library.config_name
            );
            return;
        }

        const DEFAULT_SEED: [u8; 8] = 42u64.to_le().to_ne_bytes();

        unsafe {
            (self.c_data.deterministic_rng_reseed.unwrap())(
                DEFAULT_SEED.as_ptr(),
                DEFAULT_SEED.len(),
            );
        }
    }

    fn clone_factory(&self) -> Box<dyn Factory<TLSProtocolBehavior>> {
        Box::new(TlsCPut {
            harness: self.harness.clone(),
            library: self.library.clone(),
            c_data: self.c_data,
        })
    }
}

impl TlsCPut {
    fn supports_deterministic_rng(&self) -> bool {
        self.c_data.deterministic_rng_reseed.is_some()
    }
}
