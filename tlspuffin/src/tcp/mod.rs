use std::{
    any::Any,
    cell::RefCell,
    ffi::OsStr,
    io,
    io::{ErrorKind, Read, Write},
    net::{AddrParseError, IpAddr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs},
    ops::DerefMut,
    process::{Child, Command, Stdio},
    rc::Rc,
    str::FromStr,
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

use log::{error, info};
use rustls::msgs::{
    deframer::MessageDeframer,
    message::{Message, OpaqueMessage},
};

use crate::{
    agent::{AgentDescriptor, AgentName},
    error::Error,
    io::{MessageResult, Stream},
    put::{Put, PutConfig, PutName},
    put_registry::{Factory, TCP_CLIENT_PUT, TCP_SERVER_PUT},
};

pub fn new_tcp_client_factory() -> Box<dyn Factory> {
    struct TCPFactory;
    impl Factory for TCPFactory {
        fn create(
            &self,
            agent: &AgentDescriptor,
            config: PutConfig,
        ) -> Result<Box<dyn Put>, Error> {
            let args = config.get_option("args").unwrap();
            let prog = config.get_option("prog").unwrap();
            let process = Box::new(TLSProcess::new(&prog, &args));

            let mut client = TcpClientPut::new(agent, config)?;
            client.drop_together(process);
            Ok(Box::new(client))
        }

        fn put_name(&self) -> PutName {
            TCP_CLIENT_PUT
        }

        fn put_version(&self) -> &'static str {
            TcpClientPut::version()
        }

        fn make_deterministic(&self) {
            TcpClientPut::make_deterministic()
        }
    }

    Box::new(TCPFactory)
}

pub fn new_tcp_server_factory() -> Box<dyn Factory> {
    struct TCPFactory;
    impl Factory for TCPFactory {
        fn create(
            &self,
            agent: &AgentDescriptor,
            config: PutConfig,
        ) -> Result<Box<dyn Put>, Error> {
            let args = config.get_option("args").unwrap().to_string();
            let prog = config.get_option("prog").unwrap().to_string();
            let mut server = TcpServerPut::new(agent, config)?;

            thread::sleep(Duration::from_millis(1000));

            server.drop_together(Box::new(TLSProcess::new(&prog, &args)));

            thread::sleep(Duration::from_millis(1000));

            Ok(Box::new(server))
        }

        fn put_name(&self) -> PutName {
            TCP_SERVER_PUT
        }

        fn put_version(&self) -> &'static str {
            TcpServerPut::version()
        }

        fn make_deterministic(&self) {
            TcpServerPut::make_deterministic()
        }
    }

    Box::new(TCPFactory)
}

impl From<AddrParseError> for Error {
    fn from(err: AddrParseError) -> Self {
        Error::IO(err.to_string())
    }
}

pub trait TcpPut {
    fn deframer_mut(&mut self) -> &mut MessageDeframer;

    fn write_to_stream(&mut self, buf: &[u8]) -> io::Result<()>;

    fn read_to_deframer(&mut self) -> io::Result<usize>;

    fn config(&self) -> &PutConfig;

    fn new_from_config(config: PutConfig) -> Result<Self, Error>
    where
        Self: Sized;

    fn reset(&mut self, _agent_name: AgentName) -> Result<(), Error>;
}

/// A PUT which is backed by a TCP stream to a server.
/// In order to use this start an OpenSSL server like this:
///
/// ```bash
/// openssl s_server -key key.pem -cert cert.pem -accept 44330 -msg -debug -state
/// ```
pub struct TcpClientPut {
    stream: TcpStream,
    deframer: MessageDeframer,
    config: PutConfig,
    drops: Vec<Box<dyn Any>>,
}

impl TcpPut for TcpClientPut {
    fn deframer_mut(&mut self) -> &mut MessageDeframer {
        &mut self.deframer
    }

    fn write_to_stream(&mut self, mut buf: &[u8]) -> io::Result<()> {
        self.stream.write_all(buf)?;
        self.stream.flush()
    }

    fn read_to_deframer(&mut self) -> io::Result<usize> {
        self.deframer.read(&mut self.stream)
    }

    fn config(&self) -> &PutConfig {
        &self.config
    }

    fn new_from_config(config: PutConfig) -> Result<Self, Error> {
        let stream = Self::new_stream(addr_from_config(&config)?)?;

        Ok(Self {
            stream,
            deframer: Default::default(),
            config,
            drops: vec![],
        })
    }

    fn reset(&mut self, _agent_name: AgentName) -> Result<(), Error> {
        let address = self.stream.peer_addr()?;
        self.stream = Self::new_stream(address)?;
        Ok(())
    }
}

impl TcpClientPut {
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
            "TcpClientPut failed to connect",
        ))
    }
}

pub struct TcpServerPut {
    stream: Arc<Mutex<Option<(TcpStream, TcpListener)>>>,
    deframer: MessageDeframer,
    config: PutConfig,
    drops: Vec<Box<dyn Any>>,
}

impl TcpServerPut {
    pub fn drop_together(&mut self, drop: Box<dyn Any>) {
        self.drops.push(drop);
    }
}

impl TcpClientPut {
    pub fn drop_together(&mut self, drop: Box<dyn Any>) {
        self.drops.push(drop);
    }
}

impl TcpPut for TcpServerPut {
    fn deframer_mut(&mut self) -> &mut MessageDeframer {
        &mut self.deframer
    }

    fn write_to_stream(&mut self, mut buf: &[u8]) -> io::Result<()> {
        if let Ok(mut stream) = self.stream.lock() {
            stream.as_mut().unwrap().0.write_all(buf)?;
            stream.as_mut().unwrap().0.flush()?;
            Ok(())
        } else {
            unreachable!();
        }
    }

    fn read_to_deframer(&mut self) -> io::Result<usize> {
        if let Ok(mut stream) = self.stream.lock() {
            self.deframer.read(&mut stream.as_mut().unwrap().0)
        } else {
            unreachable!();
        }
    }

    fn config(&self) -> &PutConfig {
        &self.config
    }

    fn new_from_config(config: PutConfig) -> Result<Self, Error> {
        /*        let listener = TcpListener::bind(&addr)?;

        for mut new_stream in listener.incoming() {
            let stream = new_stream?;
            // We are waiting 1 second for a response of the PUT behind the TCP socket.
            // If we are expecting data from it and this timeout is reached, then we assume that
            // no more will follow.
            stream.set_read_timeout(Some(Duration::from_millis(500)))?;
            stream.set_nodelay(true)?;
            println!("Connection established!");
            return Ok(stream);
        }

        Err(io::Error::new(ErrorKind::AlreadyExists, "wups"))*/

        let stream = Arc::new(Mutex::new(None));
        let stream2 = stream.clone();
        let addr = addr_from_config(&config)?;

        thread::spawn(move || {
            let listener = TcpListener::bind(&addr).unwrap();

            for mut new_stream in listener.incoming() {
                let stream = new_stream.unwrap();
                // We are waiting 1 second for a response of the PUT behind the TCP socket.
                // If we are expecting data from it and this timeout is reached, then we assume that
                // no more will follow.
                stream
                    .set_read_timeout(Some(Duration::from_millis(500)))
                    .unwrap();
                stream.set_nodelay(true).unwrap();
                println!("Connection established!");

                if let Ok(mut stream2) = stream2.lock() {
                    *stream2.deref_mut() = Some((stream, listener));
                    return;
                }
            }

            println!("donw");
        });

        Ok(Self {
            stream,
            deframer: Default::default(),
            config,
            drops: vec![],
        })
    }

    fn reset(&mut self, _agent_name: AgentName) -> Result<(), Error> {
        unreachable!()
    }
}

impl<P> Stream for P
where
    P: TcpPut,
{
    fn add_to_inbound(&mut self, opaque_message: &OpaqueMessage) {
        self.write_to_stream(&mut opaque_message.clone().encode())
            .unwrap();
    }

    fn take_message_from_outbound(&mut self) -> Result<Option<MessageResult>, Error> {
        // Retry to read if no more frames in the deframer buffer
        let opaque_message = loop {
            if let Some(opaque_message) = self.deframer_mut().frames.pop_front() {
                break Some(opaque_message);
            } else {
                match self.read_to_deframer() {
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

impl Drop for TcpClientPut {
    fn drop(&mut self) {
        println!("test")
    }
}
impl Drop for TcpServerPut {
    fn drop(&mut self) {
        println!("test")
    }
}

fn addr_from_config(config: &PutConfig) -> Result<SocketAddr, AddrParseError> {
    let host = config.get_option("host").unwrap_or("127.0.0.1");
    let port = config
        .get_option("port")
        .and_then(|value| u16::from_str(value).ok())
        .expect("Failed to parse port option");

    Ok(SocketAddr::new(IpAddr::from_str(host)?, port))
}

impl<P: 'static> Put for P
where
    P: TcpPut + Stream + Drop,
{
    fn new(_agent: &AgentDescriptor, config: PutConfig) -> Result<Self, Error>
    where
        Self: Sized,
    {
        Self::new_from_config(config)
    }

    fn progress(&mut self, _agent_name: &AgentName) -> Result<(), Error> {
        Ok(())
    }

    fn reset(&mut self, agent_name: AgentName) -> Result<(), Error> {
        self.reset(agent_name)
    }

    fn config(&self) -> &PutConfig {
        &self.config()
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

struct TLSProcess {
    child: Option<Child>,
}

impl TLSProcess {
    pub fn new(prog: &str, args: &str) -> Self {
        wait_and_print(execute_command(prog, ["version"]));

        Self {
            child: Some(execute_command(prog, args.split(" "))),
        }
    }
}

impl Drop for TLSProcess {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            child.kill().expect("failed to stop server");

            wait_and_print(child)
        }
    }
}

fn wait_and_print(child: Child) {
    let output = child.wait_with_output().expect("failed to wait on child");
    info!("--- stderr");
    let err = std::str::from_utf8(&output.stderr).unwrap();
    info!("{}", err);
    info!("--- stderr");
    info!("--- stdout");
    let out = std::str::from_utf8(&output.stdout).unwrap();
    info!("{}", out);
    info!("--- stdout");
}

fn execute_command<I, S>(prog: &str, args: I) -> Child
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    Command::new(prog)
        .args(args)
        .stdin(Stdio::piped()) // This line is super important! Else the OpenSSL server immediately stops
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to execute process")
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
        put_registry::{TCP_CLIENT_PUT, TCP_SERVER_PUT},
        tcp::{execute_command, wait_and_print},
        tls::seeds::{
            seed_client_attacker_full, seed_session_resumption_dhe_full, seed_successful12,
            SeedHelper,
        },
    };

    /*    #[test]
        fn test_tcp_put_session_resumption_dhe_full() {
            let port = 44330;
            let _guard = CLIAgent::new(port);

            let put = PutDescriptor {
                name: TCP_CLIENT_PUT,
                options: vec![("port".to_owned(), port.to_string())],
            };

            let trace = seed_session_resumption_dhe_full.build_trace_with_puts(&[put]);
            trace.execute_default();
        }

        #[test]
        fn test_tcp_put_seed_client_attacker_full() {
            let port = 44331;
            let _guard = CLIAgent::new(port);

            let put = PutDescriptor {
                name: TCP_CLIENT_PUT,
                options: vec![("port".to_owned(), port.to_string())],
            };

            let trace = seed_client_attacker_full.build_trace_with_puts(&[put]);
            trace.execute_default();
        }
    */
    #[test]
    fn test_tcp_put_seed_successful() {
        let temp_dir = tempdir().unwrap();

        let key = temp_dir.path().join("key.pem");
        let key_path = key.as_os_str().to_str().unwrap();
        let cert = temp_dir.path().join("cert.pem");
        let cert_path = cert.as_os_str().to_str().unwrap();

        wait_and_print(execute_command(
            "openssl",
            [
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
            ],
        ));

        let port = 44332;

        let server = PutDescriptor {
            name: TCP_CLIENT_PUT,
            options: vec![
                ("port".to_owned(), port.to_string()),
                ("prog".to_owned(), "openssl".to_string()),
                (
                    "args".to_owned(),
                    [
                        "s_server",
                        "-accept",
                        &port.to_string(),
                        "-msg",
                        "-state",
                        "-key",
                        key_path,
                        "-cert",
                        cert_path,
                        "-no_tls1_3",
                    ]
                    .join(" "),
                ),
            ],
        };

        let port = 55333;

        let openssl_client = [
            "s_client",
            "-connect",
            &format!("{}:{}", "127.0.0.1", port),
            "-msg",
            "-state",
            "-no_tls1_3",
        ];

        let wolfssl_client = ["-h", "127.0.0.1", "-p", &port.to_string(), "-x", "-d"];
        let client = PutDescriptor {
            name: TCP_SERVER_PUT,
            options: vec![
                ("port".to_owned(), port.to_string()),
                (
                    "prog".to_string(),
                    "/home/max/projects/wolfssl/build/examples/client/client".to_string(),
                ),
                ("args".to_owned(), wolfssl_client.join(" ")),
            ],
        };

        for i in 0..2 {
            let trace = seed_successful12.build_trace_with_puts(&[client.clone(), server.clone()]);
            let context = trace.execute_default();
        }
    }
}
