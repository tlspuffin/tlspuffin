// FIXME stabilize sshpuffin and reactivate the dead_code lint
//
//     Currently sshpuffin contains many functions that are unused but will be
//     necessary for the full implementation. To avoid the many unhelpful
//     warning messages, we deactivate the dead_code lint globally in this
//     module.
//
//     Once the necessary features and API of sshpuffin are more stable, we
//     should reactivate the dead_code lint, as it provides valuable insights.
#![allow(dead_code)]

use std::fs;
use std::io::{Read, Write};
use std::os::unix::io::{IntoRawFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};

use puffin::agent::{AgentDescriptor, AgentName, AgentType};
use puffin::algebra::ConcreteMessage;
use puffin::claims::GlobalClaimList;
use puffin::codec::Codec;
use puffin::error::Error;
use puffin::put::{Put, PutOptions};
use puffin::put_registry::Factory;
use puffin::stream::Stream;

use crate::libssh::ssh::{
    SessionOption, SessionState, SshAuthResult, SshBind, SshBindOption, SshKey, SshRequest,
    SshResult, SshSession,
};
use crate::protocol::{RawSshMessageFlight, SshProtocolBehavior};
use crate::put_registry::LIBSSH_RUST_PUT;

pub mod ssh;

const OPENSSH_RSA_PRIVATE_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
";

pub fn new_libssh_factory() -> Box<dyn Factory<SshProtocolBehavior>> {
    struct LibSSLFactory;
    impl Factory<SshProtocolBehavior> for LibSSLFactory {
        fn create(
            &self,
            agent_descriptor: &AgentDescriptor,
            _claims: &GlobalClaimList<
                <SshProtocolBehavior as puffin::protocol::ProtocolBehavior>::Claim,
            >,
            _options: &PutOptions,
        ) -> Result<Box<dyn Put<SshProtocolBehavior>>, Error> {
            // FIXME: Switch to UDS with stabilization in Rust 1.70
            //let addr = SocketAddr::from_abstract_namespace(b"\0socket").unwrap();
            //let listener = UnixListener::bind_addr(&addr).unwrap();
            let path = format!("socket_{}", agent_descriptor.name);
            let listener = UnixListener::bind(&path).unwrap();
            listener.set_nonblocking(true).unwrap();

            // FIXME: Switch to UDS with stabilization in Rust 1.70
            // let mut fuzz_stream = UnixStream::connect_addr(&addr).unwrap();
            let fuzz_stream = UnixStream::connect(&path).unwrap();

            // Unlink directly as we have the addresses now
            fs::remove_file(&path).unwrap();

            fuzz_stream.set_nonblocking(true).unwrap();

            let put_stream = listener.incoming().next().unwrap().unwrap();
            put_stream.set_nonblocking(true).unwrap();

            let mut session = SshSession::new().unwrap();
            session.set_blocking(false);
            session
                .set_options_int(SessionOption::SSH_OPTIONS_PROCESS_CONFIG, 0)
                .unwrap();

            let put_fd = put_stream.into_raw_fd();

            match &agent_descriptor.typ {
                AgentType::Server => {
                    let mut bind = SshBind::new().unwrap();

                    let key = SshKey::from_base64(OPENSSH_RSA_PRIVATE_KEY).unwrap();
                    bind.set_options_key(SshBindOption::SSH_BIND_OPTIONS_IMPORT_KEY, key)
                        .unwrap();
                    bind.set_blocking(false);

                    bind.accept_fd(&session, put_fd).unwrap();
                }
                AgentType::Client => {
                    session
                        .set_options_str(SessionOption::SSH_OPTIONS_HOST, "dummy")
                        .unwrap();
                    session
                        .set_options_int(SessionOption::SSH_OPTIONS_FD, put_fd)
                        .unwrap();
                }
            }

            Ok(Box::new(LibSSL {
                fuzz_stream,
                put_fd,
                agent_descriptor: agent_descriptor.clone(),
                session,
                state: PutState::ExchangingKeys,
            }))
        }

        fn name(&self) -> String {
            String::from(LIBSSH_RUST_PUT)
        }

        fn versions(&self) -> Vec<(String, String)> {
            vec![
                (
                    "harness".to_string(),
                    format!(
                        "{} {}",
                        LIBSSH_RUST_PUT,
                        puffin_build::puffin::full_version()
                    ),
                ),
                (
                    "library".to_string(),
                    format!("libssh ({} / {})", "libssh0104", LibSSL::version()),
                ),
            ]
        }

        fn clone_factory(&self) -> Box<dyn Factory<SshProtocolBehavior>> {
            Box::new(LibSSLFactory)
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

    state: PutState,
    put_fd: RawFd,
}

impl LibSSL {}

impl Stream<SshProtocolBehavior> for LibSSL {
    fn add_to_inbound(&mut self, message: &ConcreteMessage) {
        self.fuzz_stream.write_all(message).unwrap();
    }

    fn take_message_from_outbound(&mut self) -> Result<Option<RawSshMessageFlight>, Error> {
        let mut buf = vec![];
        let _ = self.fuzz_stream.read_to_end(&mut buf);

        Ok(RawSshMessageFlight::read_bytes(&buf))
    }
}

impl Put<SshProtocolBehavior> for LibSSL {
    fn progress(&mut self) -> Result<(), Error> {
        let session = &mut self.session;
        match &self.agent_descriptor.typ {
            AgentType::Server => match &self.state {
                PutState::ExchangingKeys => match session.handle_key_exchange() {
                    Ok(kex) => {
                        if kex == SshResult::Ok {
                            self.state = PutState::Authenticating;
                        }
                    }
                    Err(err) => {
                        panic!("{}", err)
                    }
                },
                PutState::Authenticating => {
                    if let Some(mut message) = session.get_message() {
                        match message.typ().unwrap() {
                            Some(SshRequest::SSH_REQUEST_AUTH) => {
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
                PutState::ExchangingKeys => match session.connect() {
                    Ok(kex) => {
                        if kex == SshResult::Ok {
                            self.state = PutState::Authenticating;
                        }
                    }
                    Err(err) => {
                        panic!("{}", err)
                    }
                },
                PutState::Authenticating => match session.userauth_password(None, "test") {
                    Ok(auth) => {
                        if auth == SshAuthResult::Success {
                            self.state = PutState::Done;
                        }
                    }
                    Err(err) => {
                        panic!("{}", err)
                    }
                },
                PutState::Done => {}
            },
        }

        Ok(())
    }

    fn reset(&mut self, _new_name: AgentName) -> Result<(), Error> {
        panic!("Not supported")
    }

    fn descriptor(&self) -> &AgentDescriptor {
        &self.agent_descriptor
    }

    fn describe_state(&self) -> String {
        // TODO: We can use internal state
        match self.state {
            PutState::ExchangingKeys => "ExchangingKeys",
            PutState::Authenticating => "Authenticating",
            PutState::Done => "Done",
        }
        .to_owned()
    }

    fn is_state_successful(&self) -> bool {
        //self.state == PutState::Done
        self.session.session_state() == SessionState::SSH_SESSION_STATE_AUTHENTICATED
    }

    fn version() -> String
    where
        Self: Sized,
    {
        ssh::version()
    }

    fn shutdown(&mut self) -> String {
        panic!("Not supported")
    }
}
