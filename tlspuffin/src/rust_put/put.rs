use std::collections::HashSet;

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

    fn supports(&self, capability: &str) -> bool {
        let capabilities: HashSet<&str> = vec![
            #[cfg(feature = "openssl-binding")]
            "openssl_binding",
            #[cfg(feature = "libressl-binding")]
            "libressl_binding",
            #[cfg(feature = "wolfssl-binding")]
            "wolfssl_binding",
            #[cfg(feature = "boringssl-binding")]
            "boringssl_binding",
            #[cfg(feature = "tls12")]
            "tls12",
            #[cfg(feature = "tls13")]
            "tls13",
            #[cfg(feature = "tls12-session-resumption")]
            "tls12_session_resumption",
            #[cfg(feature = "tls13-session-resumption")]
            "tls13_session_resumption",
            #[cfg(feature = "openssl111-binding")]
            "openssl111_binding",
            #[cfg(feature = "openssl102-binding")]
            "openssl102_binding",
            #[cfg(feature = "openssl101-binding")]
            "openssl101_binding",
            #[cfg(feature = "transcript-extraction")]
            "transcript_extraction",
            #[cfg(feature = "client-authentication-transcript-extraction")]
            "client_authentication_transcript_extraction",
        ]
        .into_iter()
        .collect();

        capabilities.contains(capability)
    }

    fn rng_reseed(&self) {
        log::debug!("[RNG] reseed ({})", self.name());
        crate::rust_put::rand::rng_reseed();
    }

    fn clone_factory(&self) -> Box<dyn Factory<TLSProtocolBehavior>> {
        Box::new(self.clone())
    }
}
