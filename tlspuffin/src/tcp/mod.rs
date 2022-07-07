use std::{
    cell::RefCell,
    io,
    io::{ErrorKind, Read, Write},
    net::{AddrParseError, IpAddr, SocketAddr, TcpStream, ToSocketAddrs},
    rc::Rc,
    str::FromStr,
    thread,
    time::Duration,
};

use log::error;
use rustls::msgs::{
    deframer::MessageDeframer,
    message::{Message, OpaqueMessage},
};

use crate::{
    agent::{AgentDescriptor, AgentName},
    error::Error,
    io::{MessageResult, Stream},
    put::{Put, PutConfig, PutName},
    put_registry::{Factory, TCP_PUT},
};

pub fn new_tcp_factory() -> Box<dyn Factory> {
    struct OpenSSLFactory;
    impl Factory for OpenSSLFactory {
        fn create(
            &self,
            agent: &AgentDescriptor,
            config: PutConfig,
        ) -> Result<Box<dyn Put>, Error> {
            Ok(Box::new(TcpPut::new(agent, config)?))
        }

        fn put_name(&self) -> PutName {
            TCP_PUT
        }

        fn put_version(&self) -> &'static str {
            TcpPut::version()
        }

        fn make_deterministic(&self) {
            TcpPut::make_deterministic()
        }
    }

    Box::new(OpenSSLFactory)
}

impl From<AddrParseError> for Error {
    fn from(err: AddrParseError) -> Self {
        Error::IO(err.to_string())
    }
}

/// A PUT which is backed by a TCP stream to a server.
/// In order to use this start an OpenSSL server like this:
///
/// ```bash
/// openssl s_server -key key.pem -cert cert.pem -accept 44330 -msg -debug -state
/// ```
pub struct TcpPut {
    stream: TcpStream,
    deframer: MessageDeframer,
    config: PutConfig,
}

impl TcpPut {
    fn new_stream<A: ToSocketAddrs>(addr: A) -> io::Result<TcpStream> {
        let mut tries = 3;
        let stream = loop {
            if let Ok(stream) = TcpStream::connect(&addr) {
                // We are waiting 1 second for a response of the PUT behind the TCP socket.
                // If we are expecting data from it and this timeout is reached, then we assume that
                // no more will follow.
                stream.set_read_timeout(Some(Duration::from_millis(500)))?;
                stream.set_nodelay(true)?;
                break Some(stream);
            }

            tries -= 1;

            if tries == 0 {
                break None;
            }

            thread::sleep(Duration::from_millis(500));
        };

        stream.ok_or(io::Error::new(
            ErrorKind::NotConnected,
            "TcpPut failed to connect",
        ))
    }
}

impl Stream for TcpPut {
    fn add_to_inbound(&mut self, opaque_message: &OpaqueMessage) {
        self.stream
            .write_all(&mut opaque_message.clone().encode())
            .unwrap();
        self.stream.flush().unwrap()
    }

    fn take_message_from_outbound(&mut self) -> Result<Option<MessageResult>, Error> {
        // Retry to read if no more frames in the deframer buffer
        let opaque_message = loop {
            if let Some(opaque_message) = self.deframer.frames.pop_front() {
                break Some(opaque_message);
            } else if let Err(e) = self.deframer.read(&mut self.stream) {
                match e.kind() {
                    ErrorKind::WouldBlock => {
                        // This is not a hard error. It just means we will should read again from
                        // the TCPStream in the next steps.
                        break None;
                    }
                    _ => return Err(e.into()),
                }
            }
        };

        if let Some(opaque_message) = opaque_message {
            let message = match Message::try_from(opaque_message.clone().into_plain_message()) {
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

impl Drop for TcpPut {
    fn drop(&mut self) {}
}

impl Put for TcpPut {
    fn new(_agent: &AgentDescriptor, config: PutConfig) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let host = config.get_option("host").unwrap_or("127.0.0.1");
        let port = config
            .get_option("port")
            .and_then(|value| u16::from_str(value).ok())
            .expect("Failed to parse port option");

        let stream = Self::new_stream(SocketAddr::new(IpAddr::from_str(host)?, port))?;

        Ok(Self {
            stream,
            deframer: Default::default(),
            config,
        })
    }

    fn progress(&mut self, _agent_name: &AgentName) -> Result<(), Error> {
        Ok(())
    }

    fn reset(&mut self, _agent_name: AgentName) -> Result<(), Error> {
        let address = self.stream.peer_addr()?;
        self.stream = Self::new_stream(address)?;
        Ok(())
    }

    fn config(&self) -> &PutConfig {
        &self.config
    }

    #[cfg(feature = "claims")]
    fn register_claimer(&mut self, _agent_name: AgentName) {
        panic!("Claims are not supported with TcpPut")
    }

    #[cfg(feature = "claims")]
    fn deregister_claimer(&mut self) {
        panic!("Claims are not supported with TcpPut")
    }

    fn rename_agent(&mut self, _agent_name: AgentName) -> Result<(), Error> {
        Ok(())
    }

    fn describe_state(&self) -> &'static str {
        panic!("Can not describe the state with TcpPut")
    }

    fn is_state_successful(&self) -> bool {
        false
    }

    fn version() -> &'static str
    where
        Self: Sized,
    {
        "Undefined"
    }

    fn make_deterministic()
    where
        Self: Sized,
    {
    }
}

#[cfg(test)]
mod tests {
    use std::{
        ffi::OsStr,
        io::{stderr, Read, Write},
        process::{Child, Command, Stdio},
    };

    use log::info;
    use tempfile::{tempdir, TempDir};
    use test_log::test;

    use crate::{
        put::PutDescriptor,
        put_registry::TCP_PUT,
        tls::seeds::{seed_client_attacker_full, seed_session_resumption_dhe_full, SeedHelper},
    };

    struct OpenSSLServer {
        child: Option<Child>,
        temp_dir: TempDir,
    }

    impl OpenSSLServer {
        pub fn new(port: u16) -> Self {
            Self::wait_and_print(Self::execute_command(["version"]));

            let temp_dir = tempdir().unwrap();

            let key = temp_dir.path().join("key.pem");
            let key_path = key.as_os_str().to_str().unwrap();
            let cert = temp_dir.path().join("cert.pem");
            let cert_path = cert.as_os_str().to_str().unwrap();

            Self::wait_and_print(Self::execute_command([
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-keyout",
                key_path,
                "-out",
                cert_path,
                "-days",
                "365",
                "-nodes",
                "-subj",
                "/C=US/ST=New Sweden/L=Stockholm/O=.../OU=.../CN=.../emailAddress=...",
            ]));

            Self {
                child: Some(Self::execute_command([
                    "s_server",
                    "-accept",
                    &port.to_string(),
                    "-msg",
                    "-state",
                    "-key",
                    key_path,
                    "-cert",
                    cert_path,
                ])),
                temp_dir,
            }
        }

        fn wait_and_print(child: Child) {
            let output = child.wait_with_output().expect("failed to wait on child");
            info!("--- stderr");
            info!("{}", std::str::from_utf8(&output.stderr).unwrap());
            info!("--- stderr");
            info!("--- stdout");
            info!("{}", std::str::from_utf8(&output.stdout).unwrap());
            info!("--- stdout");
        }

        fn execute_command<I, S>(args: I) -> Child
        where
            I: IntoIterator<Item = S>,
            S: AsRef<OsStr>,
        {
            Command::new("openssl")
                .args(args)
                .stdin(Stdio::piped()) // This line is super important! Else the OpenSSL server immediately stops
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("failed to execute process")
        }
    }

    impl Drop for OpenSSLServer {
        fn drop(&mut self) {
            if let Some(mut child) = self.child.take() {
                child.kill().expect("failed to stop server");

                Self::wait_and_print(child)
            }
        }
    }

    #[test]
    fn test_tcp_put_session_resumption_dhe_full() {
        let port = 44330;
        let _guard = OpenSSLServer::new(port);

        let put = PutDescriptor {
            name: TCP_PUT,
            options: vec![("port".to_owned(), port.to_string())],
        };

        let trace = seed_session_resumption_dhe_full.build_trace_with_put(put);
        trace.execute_default();
    }

    #[test]
    fn test_tcp_put_seed_client_attacker_full() {
        let port = 44331;
        let _guard = OpenSSLServer::new(port);

        let put = PutDescriptor {
            name: TCP_PUT,
            options: vec![("port".to_owned(), port.to_string())],
        };

        let trace = seed_client_attacker_full.build_trace_with_put(put);
        trace.execute_default();
    }
}
