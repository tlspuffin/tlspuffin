use std::collections::HashMap;

use crate::{
    agent::AgentName,
    put::{Put, PutConfig, PutDescriptor, PutName},
};

pub struct PutRegistry(&'static [fn() -> Box<dyn Factory>]);

impl PutRegistry {
    pub fn versions(&self) -> String {
        let mut put_versions: String = "".to_owned();
        for func in self.0 {
            let factory = func();

            let name = factory.put_name();
            let version = factory.put_version();
            put_versions.push_str(format!("{:?}: {}", name, version).as_str());
        }
        put_versions
    }

    pub fn make_deterministic(&self) {
        for func in self.0 {
            let factory = func();
            factory.make_deterministic();
        }
    }

    pub fn find_factory(&self, put_name: PutName) -> Option<Box<dyn Factory>> {
        self.0
            .iter()
            .map(|func| func())
            .find(|factory: &Box<dyn Factory>| factory.put_name() == put_name)
    }
}

pub const DUMMY_PUT: PutName = PutName(['D', 'U', 'M', 'Y', 'Y', 'D', 'U', 'M', 'M', 'Y']);
pub const OPENSSL111: PutName = PutName(['O', 'P', 'E', 'N', 'S', 'S', 'L', '1', '1', '1']);
pub const WOLFSSL520: PutName = PutName(['W', 'O', 'L', 'F', 'S', 'S', 'L', '5', '2', '0']);
pub const TCP: PutName = PutName(['T', 'C', 'P', 'T', 'C', 'P', 'T', 'C', 'P', 'T']);

pub const PUT_REGISTRY: PutRegistry = PutRegistry(&[
    crate::tcp::new_tcp_factory,
    #[cfg(feature = "openssl-binding")]
    crate::openssl::new_openssl_factory,
    #[cfg(feature = "wolfssl-binding")]
    crate::wolfssl::new_wolfssl_factory,
]);

pub trait Factory {
    fn create(&self, agent_name: AgentName, config: PutConfig) -> Box<dyn Put>;
    fn put_name(&self) -> PutName;
    fn put_version(&self) -> &'static str;
    fn make_deterministic(&self);
}

pub const CURRENT_PUT_NAME: PutName = {
    cfg_if::cfg_if! {
        if #[cfg(feature = "openssl-binding")] {
            OPENSSL111
        } else if #[cfg(feature = "wolfssl-binding")] {
            WOLFSSL520
        } else {
            TCP
        }
    }
};

pub fn current_put() -> PutDescriptor {
    PutDescriptor {
        name: CURRENT_PUT_NAME,
        ..PutDescriptor::default()
    }
}
