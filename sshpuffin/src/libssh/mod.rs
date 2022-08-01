use std::{
    ffi::c_int,
    io::{ErrorKind, Read, Write},
    os::unix::{
        io::{IntoRawFd, RawFd},
        net::{SocketAddr, UnixListener, UnixStream},
    },
    thread,
    time::Duration,
};

use log::{debug, error, info};
use puffin::{
    agent::{AgentDescriptor, AgentName, AgentType},
    codec::Codec,
    error::Error,
    io::{MessageResult, Stream},
    protocol::OpaqueMessage,
    put::{Put, PutName},
    put_registry::Factory,
    trace::TraceContext,
};
use tokio::io::AsyncWriteExt;

use crate::{
    libssh::ssh::{
        SessionOption, SshAuthResult, SshBind, SshBindOption, SshRequest, SshResult, SshSession,
    },
    protocol::SshProtocolBehavior,
    put_registry::LIBSSH_PUT,
    ssh::{
        deframe::SshMessageDeframer,
        message::{RawMessage, SshMessage},
    },
};

pub mod ssh;

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

            let mut fuzz_stream = UnixStream::connect_addr(&addr).unwrap();
            fuzz_stream.set_nonblocking(true).unwrap();

            let put_stream = listener.incoming().next().unwrap().unwrap();
            put_stream.set_nonblocking(true).unwrap();

            let mut session = SshSession::new().unwrap();
            session.set_blocking(false);
            session
                .set_options_int(SessionOption::PROCESS_CONFIG, 0)
                .unwrap();

            let put_fd = put_stream.into_raw_fd();

            match &agent_descriptor.typ {
                AgentType::Server => {
                    let mut bind = SshBind::new().unwrap();

                    bind.set_options_str(
                        SshBindOption::RSAKEY,
                        "/home/max/projects/tlspuffin/ssh_host_rsa_key",
                    )
                    .unwrap();
                    bind.set_blocking(false);

                    bind.accept_fd(&session, put_fd).unwrap();
                }
                AgentType::Client => {
                    session
                        .set_options_str(SessionOption::HOST, "dummy")
                        .unwrap();
                    session.set_options_int(SessionOption::FD, put_fd).unwrap();
                }
            }

            Ok(Box::new(LibSSL {
                fuzz_stream,
                put_fd,
                agent_descriptor: agent_descriptor.clone(),
                session,
                deframer: SshMessageDeframer::default(),
                state: PutState::ExchangingKeys,
            }))
        }

        fn name(&self) -> PutName {
            LIBSSH_PUT
        }

        fn version(&self) -> String {
            LibSSL::version()
        }

        fn make_deterministic(&self) {
            LibSSL::make_deterministic()
        }
    }

    Box::new(LibSSLFactory)
}

#[derive(PartialEq)]
enum PutState {
    ExchangingKeys,
    Authenticating,
    Done,
}

pub struct LibSSL {
    fuzz_stream: UnixStream,
    agent_descriptor: AgentDescriptor,
    session: SshSession,
    deframer: SshMessageDeframer,

    state: PutState,
    put_fd: RawFd,
}

impl LibSSL {}

impl Stream<SshProtocolBehavior> for LibSSL {
    fn add_to_inbound(&mut self, result: &RawMessage) {
        let mut buffer = Vec::new();
        Codec::encode(result, &mut buffer);
        self.fuzz_stream.write_all(&mut buffer).unwrap();
    }

    fn take_message_from_outbound(
        &mut self,
    ) -> Result<
        Option<MessageResult<super::ssh::message::SshMessage, super::ssh::message::RawMessage>>,
        Error,
    > {
        /*self.session.blocking_flush(Duration::from_secs(10)).unwrap();*/

        /*        let mut buffer: Vec<u8> = Vec::with_capacity(256);

        match self.fuzz_stream.read_to_end(&mut buffer) {
            Ok(_) => {}
            Err(err) => match err.kind() {
                ErrorKind::WouldBlock => {}
                _ => {
                    panic!("{}", err)
                }
            },
        }*/

        // Retry to read if no more frames in the deframer buffer
        let opaque_message = loop {
            if let Some(opaque_message) = self.deframer.frames.pop_front() {
                break Some(opaque_message);
            } else {
                match self.deframer.read(&mut self.fuzz_stream) {
                    Ok(v) => {
                        if v == 0 {
                            break None;
                        }
                    }
                    Err(err) => match err.kind() {
                        ErrorKind::WouldBlock => {
                            // This is not a hard error. It just means we will should read again from
                            // the TCPStream in the next steps.
                            break None;
                        }
                        _ => return Err(err.into()),
                    },
                }
            }
        };

        if let Some(opaque_message) = opaque_message {
            let message = match SshMessage::try_from(&opaque_message) {
                Ok(message) => Some(message),
                Err(err) => {
                    error!("Failed to decode message! This means we maybe need to remove logical checks from rustls! {}", err);
                    None
                }
            };

            Ok(Some(MessageResult(message, opaque_message)))
        } else {
            // no message to return
            Ok(None)
        }
    }
}

impl Put<SshProtocolBehavior> for LibSSL {
    fn progress(&mut self, agent_name: &AgentName) -> Result<(), Error> {
        let session = &mut self.session;
        match &self.agent_descriptor.typ {
            AgentType::Server => match &self.state {
                PutState::ExchangingKeys => {
                    if let Ok(kex) = session.handle_key_exchange() {
                        if kex == SshResult::Ok {
                            self.state = PutState::Authenticating;
                        }
                    }
                }
                PutState::Authenticating => {
                    if let Some(mut message) = session.get_message() {
                        match message.typ().unwrap() {
                            Some(SshRequest::REQUEST_AUTH) => {
                                message.auth_reply_success(0).unwrap();
                                self.state = PutState::Done;
                            }
                            _ => {
                                message.reply_default().unwrap();
                            }
                        }
                    }
                }
                PutState::Done => {}
            },
            AgentType::Client => match &self.state {
                PutState::ExchangingKeys => {
                    if let Ok(kex) = session.connect() {
                        if kex == SshResult::Ok {
                            self.state = PutState::Authenticating;
                        }
                    }
                }
                PutState::Authenticating => {
                    if let Ok(auth) = session.userauth_password(None, "test") {
                        if auth == SshAuthResult::Success {
                            self.state = PutState::Done;
                        }
                    }
                }
                PutState::Done => {}
            },
        }

        Ok(())
    }

    fn reset(&mut self, agent_name: AgentName) -> Result<(), Error> {
        panic!("Not supported")
    }

    fn descriptor(&self) -> &AgentDescriptor {
        &self.agent_descriptor
    }

    #[cfg(feature = "claims")]
    fn register_claimer(&mut self, agent_name: AgentName) {
        panic!("Not supported")
    }

    #[cfg(feature = "claims")]
    fn deregister_claimer(&mut self) {
        panic!("Not supported")
    }

    fn rename_agent(&mut self, agent_name: AgentName) -> Result<(), Error> {
        panic!("Not supported")
    }

    fn describe_state(&self) -> &str {
        match self.state {
            PutState::ExchangingKeys => "ExchangingKeys",
            PutState::Authenticating => "Authenticating",
            PutState::Done => "Done",
        }
    }

    fn is_state_successful(&self) -> bool {
        self.state == PutState::Done
    }

    fn version() -> String
    where
        Self: Sized,
    {
        ssh::version()
    }

    fn make_deterministic()
    where
        Self: Sized,
    {
        panic!("Not supported")
    }

    fn shutdown(&mut self) -> String {
        panic!("Not supported")
    }
}
