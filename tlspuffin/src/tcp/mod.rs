use std::{
    cell::RefCell,
    io,
    io::{ErrorKind, Read, Write},
    net::{AddrParseError, IpAddr, SocketAddr, TcpStream, ToSocketAddrs},
    rc::Rc,
    str::FromStr,
    time::Duration,
};

use log::error;
use rustls::msgs::{
    deframer::MessageDeframer,
    message::{Message, OpaqueMessage},
};

use crate::{
    agent::{AgentName, PutName},
    error::Error,
    io::{MessageResult, Stream},
    put::{Config, Put},
    put_registry::{Factory, OPENSSL111, TCP},
    trace::VecClaimer,
};

pub fn new_tcp_factory() -> Box<dyn Factory> {
    struct OpenSSLFactory;
    impl Factory for OpenSSLFactory {
        fn create(&self, config: Config) -> Box<dyn Put> {
            Box::new(TcpPut::new(config).unwrap())
        }

        fn put_name(&self) -> PutName {
            TCP
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
    outbound_buffer: io::Cursor<Vec<u8>>,
    deframer: MessageDeframer,
}

impl TcpPut {
    fn new_stream<A: ToSocketAddrs>(addr: A) -> io::Result<TcpStream> {
        let stream = TcpStream::connect(addr)?;
        stream.set_read_timeout(Some(Duration::from_millis(500)))?;
        Ok(stream)
    }
}

impl Stream for TcpPut {
    fn add_to_inbound(&mut self, opaque_message: &OpaqueMessage) {
        self.stream
            .write_all(&mut opaque_message.clone().encode())
            .unwrap();
    }

    fn take_message_from_outbound(&mut self) -> Result<Option<MessageResult>, Error> {
        let mut first_message = self.deframer.frames.pop_front();

        // Retry to read if no more frames in the deframer buffer
        if first_message.is_none() {
            if let Err(e) = self.deframer.read(&mut self.stream) {
                let kind = e.kind();
                match kind {
                    ErrorKind::WouldBlock => {
                        // This is not a hard error. It just means we will should read again from
                        // the TCPStream in the next steps.
                    }
                    _ => return Err(e.into()),
                }
            }
            first_message = self.deframer.frames.pop_front()
        }

        if let Some(opaque_message) = first_message {
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

impl Read for TcpPut {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.stream.read(buf)
    }
}

impl Write for TcpPut {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.stream.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

impl Drop for TcpPut {
    fn drop(&mut self) {}
}

impl Put for TcpPut {
    fn new(_config: Config) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let mut stream = Self::new_stream(SocketAddr::new(IpAddr::from_str("127.0.0.1")?, 44330))?;

        Ok(Self {
            stream,
            outbound_buffer: io::Cursor::new(Vec::new()),
            deframer: Default::default(),
        })
    }

    fn progress(&mut self) -> Result<(), Error> {
        Ok(())
    }

    fn reset(&mut self) -> Result<(), Error> {
        let address = self.stream.peer_addr()?;
        self.stream = Self::new_stream(address)?;
        Ok(())
    }

    #[cfg(feature = "claims")]
    fn register_claimer(&mut self, claimer: Rc<RefCell<VecClaimer>>, agent_name: AgentName) {
        panic!("Claims are not supported with TcpPut")
    }

    #[cfg(feature = "claims")]
    fn deregister_claimer(&mut self) {
        panic!("Claims are not supported with TcpPut")
    }

    fn change_agent_name(&mut self, claimer: Rc<RefCell<VecClaimer>>, agent_name: AgentName) {}

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
        fs::File,
        path::{Path, PathBuf},
        process::{Child, Command, Stdio},
    };

    use tempfile::{tempdir, TempDir};

    use crate::{
        agent::AgentName,
        put_registry::TCP,
        tls::seeds::{seed_client_attacker_full, seed_session_resumption_dhe_full},
        trace::TraceContext,
    };

    struct OpenSSLServer {
        child: Child,
        tmp: TempDir,
    }

    impl OpenSSLServer {
        pub fn new(port: u16) -> Self {
            let dir = tempdir().unwrap();
            let key = dir.path().join("key.pem");
            let cert = dir.path().join("cert.pem");
            let output = Command::new("openssl")
                .arg("req")
                .arg("-x509")
                .arg("-newkey")
                .arg("rsa:2048")
                .arg("-keyout")
                .arg(key.as_path().to_str().unwrap())
                .arg("-out")
                .arg(cert.as_path().to_str().unwrap())
                .arg("-days")
                .arg("365")
                .arg("-nodes")
                .arg("-subj")
                .arg("/C=US/ST=New Sweden/L=Stockholm/O=.../OU=.../CN=.../emailAddress=...")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("failed to generate certs")
                .wait()
                .expect("failed to wait on child");

            Self {
                child: Command::new("openssl")
                    .arg("s_server")
                    .arg("-accept")
                    .arg(port.to_string())
                    .arg("-key")
                    .arg(key.as_path().to_str().unwrap())
                    .arg("-cert")
                    .arg(cert.as_path().to_str().unwrap())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .expect("failed to execute process"),
                tmp: dir,
            }
        }
    }

    impl Drop for OpenSSLServer {
        fn drop(&mut self) {
            self.child.kill().expect("failed to stop server");
        }
    }

    fn start_openssl_server() {}

    #[test]
    fn test_tcp_put_session_resumption_dhe_full() {
        let _guard = OpenSSLServer::new(44330);

        let mut ctx = TraceContext::new();
        let initial_server = AgentName::first();
        let server = initial_server.next();
        let trace = seed_session_resumption_dhe_full(initial_server, server, TCP);

        trace.execute(&mut ctx).unwrap();
    }

    #[test]
    #[ignore]
    fn test_tcp_put_seed_client_attacker_full() {
        let _guard = OpenSSLServer::new(44330);

        let mut ctx = TraceContext::new();
        let server = AgentName::first();
        let (trace, ..) = seed_client_attacker_full(server, TCP);

        trace.execute(&mut ctx).unwrap();
    }
}
