use crate::{protocol::TLSProtocolBehavior, put_registry::C_PUT};

use puffin::{
    agent::AgentDescriptor, error::Error, put::Put, put::PutName, put_registry::Factory,
    trace::TraceContext,
};

pub fn new_cput_openssl_factory() -> Box<dyn Factory<TLSProtocolBehavior>> {
    struct CPUTOpenSSLFactory;
    impl Factory<TLSProtocolBehavior> for CPUTOpenSSLFactory {
        fn create(
            &self,
            context: &TraceContext<TLSProtocolBehavior>,
            agent_descriptor: &AgentDescriptor,
        ) -> Result<Box<dyn Put<TLSProtocolBehavior>>, Error> {
            Err(Error::Agent("C OpenSSL agent not implemented".to_string()))
        }

        fn name(&self) -> PutName {
            C_PUT
        }

        fn version(&self) -> String {
            "0.0.1".to_string()
        }
    }

    Box::new(CPUTOpenSSLFactory)
}

#[cfg(test)]
mod tests {
    use super::new_cput_openssl_factory;

    #[test]
    fn create_cput_openssl_factory() {
        new_cput_openssl_factory();
        return;
    }
}
