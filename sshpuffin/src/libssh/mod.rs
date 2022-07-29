use std::{
    io::Write,
    os::unix::net::{SocketAddr, UnixListener, UnixStream},
};

use puffin::{
    agent::{AgentDescriptor, AgentName},
    error::Error,
    io::{MessageResult, Stream},
    protocol::OpaqueMessage,
    put::{Put, PutName},
    put_registry::Factory,
    trace::TraceContext,
};
use tokio::io::AsyncWriteExt;

use crate::{protocol::SshProtocolBehavior, put_registry::LIBSSH_PUT, ssh::russh::client::Msg};

mod ssh;

pub fn new_libssh_factory() -> Box<dyn Factory<SshProtocolBehavior>> {
    struct LibSSLFactory;
    impl Factory<SshProtocolBehavior> for LibSSLFactory {
        fn create(
            &self,
            context: &TraceContext<SshProtocolBehavior>,
            agent_descriptor: &AgentDescriptor,
        ) -> Result<Box<dyn Put<SshProtocolBehavior>>, Error> {
            let addr = SocketAddr::from_abstract_namespace(b"\0socket").unwrap();
            let listener = UnixListener::bind_addr(&addr).unwrap();
            listener.set_nonblocking(true).unwrap();

            let mut client_stream = UnixStream::connect_addr(&addr).unwrap();
            client_stream.set_nonblocking(false).unwrap();
            let server_stream = listener.incoming().next().unwrap().unwrap();

            Ok(Box::new(LibSSL {
                client_stream,
                server_stream,
            }))
        }

        fn put_name(&self) -> PutName {
            LIBSSH_PUT
        }

        fn put_version(&self) -> &'static str {
            LibSSL::version()
        }

        fn make_deterministic(&self) {
            LibSSL::make_deterministic()
        }
    }

    Box::new(LibSSLFactory)
}

pub struct LibSSL {
    server_stream: UnixStream,
    client_stream: UnixStream,
}

impl LibSSL {}

impl Stream<SshProtocolBehavior> for LibSSL {
    fn add_to_inbound(&mut self, result: &Msg) {
        self.server_stream.write_all(&result.encode()).unwrap();
    }

    fn take_message_from_outbound(&mut self) -> Result<Option<MessageResult<Msg, Msg>>, Error> {
        todo!()
    }
}

impl Put<SshProtocolBehavior> for LibSSL {
    fn progress(&mut self, agent_name: &AgentName) -> Result<(), Error> {
        todo!()
    }

    fn reset(&mut self, agent_name: AgentName) -> Result<(), Error> {
        todo!()
    }

    fn descriptor(&self) -> &AgentDescriptor {
        todo!()
    }

    #[cfg(feature = "claims")]
    fn register_claimer(&mut self, agent_name: AgentName) {
        todo!()
    }

    #[cfg(feature = "claims")]
    fn deregister_claimer(&mut self) {
        todo!()
    }

    fn rename_agent(&mut self, agent_name: AgentName) -> Result<(), Error> {
        todo!()
    }

    fn describe_state(&self) -> &str {
        todo!()
    }

    fn is_state_successful(&self) -> bool {
        todo!()
    }

    fn version() -> &'static str
    where
        Self: Sized,
    {
        "Unknown"
    }

    fn make_deterministic()
    where
        Self: Sized,
    {
        todo!()
    }

    fn shutdown(&mut self) -> String {
        todo!()
    }
}
