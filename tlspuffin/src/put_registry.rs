use puffin::{
    agent::{AgentDescriptor, AgentName},
    algebra::signature::Signature,
    claims::Policy,
    error::Error,
    put::{Put, PutDescriptor, PutName},
    put_registry::{Factory, ProtocolBehavior, PutRegistry},
    trace::Trace,
    variable_data::VariableData,
};
use rustls::msgs::message::Message;

use crate::{
    claims::TlsClaim,
    extraction::extract_knowledge,
    tls::{seeds::create_corpus, violation::is_violation, TLS_SIGNATURE},
};

#[derive(Clone)]
pub struct TLSProtocolBehavior;

impl ProtocolBehavior for TLSProtocolBehavior {
    type Claim = TlsClaim;

    fn policy() -> Policy<Self::Claim> {
        Policy { func: is_violation }
    }

    fn extract_knowledge(message: &Message) -> Result<Vec<Box<dyn VariableData>>, Error> {
        extract_knowledge(message)
    }

    fn signature() -> &'static Signature {
        &TLS_SIGNATURE
    }

    fn create_corpus() -> Vec<(Trace, &'static str)> {
        create_corpus()
    }

    fn new_registry() -> &'static dyn PutRegistry<Self> {
        todo!()
    }
}

pub struct TlsPutRegistry {
    pub factories: &'static [fn() -> Box<dyn Factory<TLSProtocolBehavior>>],
}

impl PutRegistry<TLSProtocolBehavior> for TlsPutRegistry {
    fn version_strings(&self) -> Vec<String> {
        let mut put_versions = Vec::new();
        for func in self.factories {
            let factory = func();

            let name = factory.put_name();
            let version = factory.put_version();
            put_versions.push(format!("{}: {}", name, version));
        }
        put_versions
    }

    fn make_deterministic(&self) {
        for func in self.factories {
            let factory = func();
            factory.make_deterministic();
        }
    }

    fn find_factory(&self, put_name: PutName) -> Option<Box<dyn Factory<TLSProtocolBehavior>>> {
        self.factories
            .iter()
            .map(|func| func())
            .find(|factory: &Box<dyn Factory<TLSProtocolBehavior>>| factory.put_name() == put_name)
    }
}

pub const OPENSSL111_PUT: PutName = PutName(['O', 'P', 'E', 'N', 'S', 'S', 'L', '1', '1', '1']);
pub const WOLFSSL520_PUT: PutName = PutName(['W', 'O', 'L', 'F', 'S', 'S', 'L', '5', '2', '0']);
pub const TCP_CLIENT_PUT: PutName = PutName(['T', 'C', 'P', 'C', 'L', 'I', 'E', 'N', 'T', '_']);
pub const TCP_SERVER_PUT: PutName = PutName(['T', 'C', 'P', 'S', 'E', 'R', 'V', 'E', 'R', '_']);

pub const PUT_REGISTRY: TlsPutRegistry = TlsPutRegistry {
    factories: &[
        crate::tcp::new_tcp_client_factory,
        crate::tcp::new_tcp_server_factory,
        #[cfg(feature = "openssl-binding")]
        crate::openssl::new_openssl_factory,
        #[cfg(feature = "wolfssl-binding")]
        crate::wolfssl::new_wolfssl_factory,
    ],
};

pub const CURRENT_PUT_NAME: PutName = {
    cfg_if::cfg_if! {
        if #[cfg(feature = "openssl-binding")] {
            OPENSSL111_PUT
        } else if #[cfg(feature = "wolfssl-binding")] {
            WOLFSSL520_PUT
        } else {
            DUMMY_PUT
        }
    }
};

pub fn current_put() -> PutDescriptor {
    PutDescriptor {
        name: CURRENT_PUT_NAME,
        ..PutDescriptor::default()
    }
}
