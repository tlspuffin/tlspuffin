use crate::{
    agent::PutName,
    concretize::{Config, Put},
};

pub struct PutRegistry<const N: usize>([fn() -> Box<dyn Factory>; N]);

impl<const N: usize> PutRegistry<N> {
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
pub const WOLFSSL510: PutName = PutName(['W', 'O', 'L', 'F', 'S', 'S', 'L', '5', '2', '0']);

const N_REGISTERED: usize = 0 + if cfg!(feature = "openssl-binding") {
    1 + if cfg!(feature = "wolfssl-binding") {
        1
    } else {
        0
    }
} else if cfg!(feature = "wolfssl-binding") {
    1
} else {
    0
};
pub const PUT_REGISTRY: PutRegistry<N_REGISTERED> = PutRegistry([
    #[cfg(feature = "openssl-binding")]
    crate::openssl::new_openssl_factory,
    #[cfg(feature = "wolfssl-binding")]
    crate::wolfssl::new_wolfssl_factory,
]);

pub trait Factory {
    fn create(&self, config: Config) -> Box<dyn Put>;
    fn put_name(&self) -> PutName;
    fn put_version(&self) -> &'static str;
    fn make_deterministic(&self);
}
