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
        context: &puffin::trace::TraceContext<TLSProtocolBehavior>,
        agent_descriptor: &puffin::agent::AgentDescriptor,
    ) -> Result<Box<dyn puffin::put::Put<TLSProtocolBehavior>>, puffin::error::Error> {
        let _ = context;
        let _ = agent_descriptor;
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

    fn determinism_set_reseed(&self) {
        if !self.supports_deterministic_rng() {
            log::error!(
                "[Determinism] C PUT {} has no support for deterministic RNG",
                self.library.config_name
            );
            return;
        }

        unsafe {
            (self.c_data.deterministic_rng_set.unwrap())();
        }

        self.determinism_reseed();
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
        self.c_data.deterministic_rng_set.is_some()
            && self.c_data.deterministic_rng_reseed.is_some()
    }
}
