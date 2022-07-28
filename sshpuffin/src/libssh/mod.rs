use puffin::{
    agent::AgentDescriptor,
    error::Error,
    put::{Put, PutName},
    put_registry::Factory,
    trace::TraceContext,
};

use crate::{protocol::SshProtocolBehavior, put_registry::LIBSSH_PUT};

mod libssh_sys;

pub fn new_libssh_factory() -> Box<dyn Factory<SshProtocolBehavior>> {
    struct OpenSSLFactory;
    impl Factory<SshProtocolBehavior> for OpenSSLFactory {
        fn create(
            &self,
            context: &TraceContext<SshProtocolBehavior>,
            agent_descriptor: &AgentDescriptor,
        ) -> Result<Box<dyn Put<SshProtocolBehavior>>, Error> {
            todo!()
        }

        fn put_name(&self) -> PutName {
            LIBSSH_PUT
        }

        fn put_version(&self) -> &'static str {
            todo!()
        }

        fn make_deterministic(&self) {
            todo!()
        }
    }

    Box::new(OpenSSLFactory)
}
