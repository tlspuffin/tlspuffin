use std::{
    any::Any,
    cell::RefCell,
    ffi::OsStr,
    io,
    io::{ErrorKind, Read, Write},
    net::{AddrParseError, IpAddr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs},
    ops::DerefMut,
    path::Path,
    process::{Child, Command, Stdio},
    rc::Rc,
    str::FromStr,
    sync::{mpsc, mpsc::channel, Arc, Mutex},
    thread,
    time::Duration,
};

use log::{error, info};
use puffin::{
    agent::{AgentDescriptor, AgentName, TLSVersion},
    error::Error,
    io::{MessageResult, Stream},
    put::{Put, PutConfig, PutName},
    put_registry::Factory,
};
use rustls::msgs::{
    deframer::MessageDeframer,
    message::{Message, OpaqueMessage},
};

use crate::put_registry::{TCP_CLIENT_PUT, TCP_SERVER_PUT};

pub fn new_tcp_client_factory() -> Box<dyn Factory> {
    struct TCPFactory;
    impl Factory for TCPFactory {
        fn create(
            &self,
            agent: &AgentDescriptor,
            config: PutConfig,
        ) -> Result<Box<dyn Put>, Error> {
            let options = &config.descriptor.options;
            let args = options
                .get_option("args")
                .ok_or_else(|| Error::Agent("Unable to find args".to_string()))?;
            let prog = options
                .get_option("prog")
                .ok_or_else(|| Error::Agent("Unable to find prog".to_string()))?;
            let cwd = options
                .get_option("cwd")
                .map(|cwd| Some(cwd))
                .unwrap_or_default();

            let process = TLSProcess::new(&prog, &args, cwd);

            let mut client = TcpClientPut::new(agent, config)?;
            client.set_process(process);
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
            let options = &config.descriptor.options;
            let args = options
                .get_option("args")
                .ok_or_else(|| Error::Agent("Unable to find args".to_string()))?
                .to_owned();
            let prog = options
                .get_option("prog")
                .ok_or_else(|| Error::Agent("Unable to find prog".to_string()))?
                .to_owned();
            let cwd = options
                .get_option("cwd")
                .map(|cwd| Some(cwd.to_owned()))
                .unwrap_or_default();
            let mut server = TcpServerPut::new(agent, config)?;

            server.set_process(TLSProcess::new(&prog, &args, cwd.as_ref()));

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

trait TcpPut {
    fn deframer_mut(&mut self) -> &mut MessageDeframer;

    fn write_to_stream(&mut self, buf: &[u8]) -> io::Result<()>;

    fn read_to_deframer(&mut self) -> io::Result<usize>;
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
    process: Option<TLSProcess>,
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
}

impl TcpClientPut {
    fn new_stream<A: ToSocketAddrs>(addr: A) -> io::Result<TcpStream> {
        let mut tries = 3;
        let stream = loop {
            if let Ok(stream) = TcpStream::connect(&addr) {
                // We are waiting 500ms for a response of the PUT behind the TCP socket.
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

    pub fn set_process(&mut self, process: TLSProcess) {
        self.process = Some(process)
    }
}

pub struct TcpServerPut {
    stream: Option<(TcpStream, TcpListener)>,
    stream_receiver: mpsc::Receiver<(TcpStream, TcpListener)>,
    deframer: MessageDeframer,
    config: PutConfig,
    process: Option<TLSProcess>,
}

impl TcpServerPut {
    pub fn set_process(&mut self, process: TLSProcess) {
        self.process = Some(process)
    }

    pub fn receive_stream(&mut self) {
        if self.stream.is_some() {
            return;
        }

        if let Ok(tuple) = self.stream_receiver.recv_timeout(Duration::from_secs(10)) {
            self.stream = Some(tuple);
        } else {
            panic!("Unstable to get stream to client!")
        }
    }
}

impl TcpPut for TcpServerPut {
    fn deframer_mut(&mut self) -> &mut MessageDeframer {
        &mut self.deframer
    }

    fn write_to_stream(&mut self, mut buf: &[u8]) -> io::Result<()> {
        self.receive_stream();
        let stream = &mut self.stream.as_mut().unwrap().0;
        stream.write_all(buf)?;
        stream.flush()?;
        Ok(())
    }

    fn read_to_deframer(&mut self) -> io::Result<usize> {
        self.receive_stream();
        let stream = &mut self.stream.as_mut().unwrap().0;
        self.deframer.read(stream)
    }
}

impl Stream for TcpServerPut {
    fn add_to_inbound(&mut self, opaque_message: &OpaqueMessage) {
        self.write_to_stream(&mut opaque_message.clone().encode())
            .unwrap();
    }

    fn take_message_from_outbound(&mut self) -> Result<Option<MessageResult>, Error> {
        take_message_from_outbound(self)
    }
}

impl Stream for TcpClientPut {
    fn add_to_inbound(&mut self, opaque_message: &OpaqueMessage) {
        self.write_to_stream(&mut opaque_message.clone().encode())
            .unwrap();
    }

    fn take_message_from_outbound(&mut self) -> Result<Option<MessageResult>, Error> {
        take_message_from_outbound(self)
    }
}

fn take_message_from_outbound<P: TcpPut>(put: &mut P) -> Result<Option<MessageResult>, Error> {
    // Retry to read if no more frames in the deframer buffer
    let opaque_message = loop {
        if let Some(opaque_message) = put.deframer_mut().frames.pop_front() {
            break Some(opaque_message);
        } else {
            match put.read_to_deframer() {
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

impl Drop for TcpClientPut {
    fn drop(&mut self) {}
}

impl Drop for TcpServerPut {
    fn drop(&mut self) {}
}

fn addr_from_config(config: &PutConfig) -> Result<SocketAddr, AddrParseError> {
    let options = &config.descriptor.options;
    let host = options.get_option("host").unwrap_or("127.0.0.1");
    let port = options
        .get_option("port")
        .and_then(|value| u16::from_str(value).ok())
        .expect("Failed to parse port option");

    Ok(SocketAddr::new(IpAddr::from_str(host)?, port))
}

impl Put for TcpServerPut {
    fn new(_agent: &AgentDescriptor, config: PutConfig) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let (sender, stream_receiver) = channel();
        let addr = addr_from_config(&config).map_err(|err| Error::OpenSSL(err.to_string()))?;

        thread::spawn(move || {
            let listener = TcpListener::bind(&addr).unwrap();

            if let Some(new_stream) = listener.incoming().next() {
                let stream = new_stream.unwrap();
                // We are waiting 500ms for a response of the PUT behind the TCP socket.
                // If we are expecting data from it and this timeout is reached, then we assume that
                // no more will follow.
                stream
                    .set_read_timeout(Some(Duration::from_millis(500)))
                    .unwrap();
                stream.set_nodelay(true).unwrap();
                sender.send((stream, listener)).unwrap();
            }
        });

        Ok(Self {
            stream: None,
            stream_receiver,
            deframer: Default::default(),
            config,
            process: None,
        })
    }

    fn progress(&mut self, _agent_name: &AgentName) -> Result<(), Error> {
        Ok(())
    }

    fn reset(&mut self, agent_name: AgentName) -> Result<(), Error> {
        panic!("Not supported")
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

    fn describe_state(&self) -> &str {
        panic!("Not supported")
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

    fn shutdown(&mut self) -> String {
        self.process.as_mut().unwrap().shutdown().unwrap()
    }
}

impl Put for TcpClientPut {
    fn new(_agent: &AgentDescriptor, config: PutConfig) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let addr = addr_from_config(&config).map_err(|err| Error::OpenSSL(err.to_string()))?;
        let stream = Self::new_stream(addr)?;

        Ok(Self {
            stream,
            deframer: Default::default(),
            config,
            process: None,
        })
    }

    fn progress(&mut self, _agent_name: &AgentName) -> Result<(), Error> {
        Ok(())
    }

    fn reset(&mut self, agent_name: AgentName) -> Result<(), Error> {
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

    fn describe_state(&self) -> &str {
        panic!("Not supported")
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

    fn shutdown(&mut self) -> String {
        self.process.as_mut().unwrap().shutdown().unwrap()
    }
}

pub struct TLSProcess {
    child: Option<Child>,
    output: Option<String>,
}

impl TLSProcess {
    pub fn new<P: AsRef<Path>>(prog: &str, args: &str, cwd: Option<P>) -> Self {
        Self {
            child: Some(execute_command(prog, args.split(" "), cwd)),
            output: None,
        }
    }

    pub fn shutdown(&mut self) -> Option<String> {
        if let Some(mut child) = self.child.take() {
            child.kill().expect("failed to stop process");

            Some(collect_output(child))
        } else {
            None
        }
    }
}

impl Drop for TLSProcess {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn collect_output(child: Child) -> String {
    let output = child.wait_with_output().expect("failed to wait on child");
    let mut complete = "--- start stderr\n".to_string();

    complete.push_str(std::str::from_utf8(&output.stderr).unwrap());
    complete.push_str("\n--- end stderr\n");
    complete.push_str("--- start stdout\n");
    complete.push_str(std::str::from_utf8(&output.stdout).unwrap());
    complete.push_str("\n--- end stdout\n");

    complete
}

fn execute_command<I, S, P: AsRef<Path>>(prog: &str, args: I, cwd: Option<P>) -> Child
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut cmd = Command::new(prog);

    if let Some(cwd) = cwd {
        cmd.current_dir(cwd);
    }

    cmd.args(args)
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
    use puffin::{
        agent::{AgentName, TLSVersion},
        put::{PutDescriptor, PutOptions},
    };
    use tempfile::{tempdir, TempDir};
    use test_log::test;

    use crate::{
        put_registry::{PUT_REGISTRY, TCP_CLIENT_PUT, TCP_SERVER_PUT},
        tcp::{collect_output, execute_command, TLSProcess},
        tls::seeds::{
            seed_client_attacker_full, seed_session_resumption_dhe_full, seed_successful12,
            seed_successful12_with_tickets, SeedHelper,
        },
    };

    const OPENSSL_PROG: &'static str = "openssl";

    /// In case `temp_dir` is set this acts as a guard. Dropping it makes it invalid.
    struct ParametersGuard {
        port: u16,
        prog: String,
        args: String,
        cwd: Option<String>,
        temp_dir: Option<TempDir>,
    }

    impl ParametersGuard {
        fn build_options(&self) -> PutOptions {
            let port = self.port.to_string();
            let mut options: Vec<(&str, &str)> =
                vec![("port", &port), ("prog", &self.prog), ("args", &self.args)];
            if let Some(cwd) = &self.cwd {
                options.push(("cwd", cwd));
            }
            PutOptions::new(options)
        }
    }

    fn gen_certificate() -> (String, String, TempDir) {
        let temp_dir = tempdir().unwrap();

        let key = temp_dir.path().join("key.pem");
        let key_path = key.as_os_str().to_str().unwrap();
        let cert = temp_dir.path().join("cert.pem");
        let cert_path = cert.as_os_str().to_str().unwrap();

        let openssl_gen_cert_args = [
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
        ];

        info!(
            "{}",
            collect_output(execute_command::<_, _, &str>(
                OPENSSL_PROG,
                openssl_gen_cert_args,
                None,
            ))
        );

        (key_path.to_owned(), cert_path.to_owned(), temp_dir)
    }

    fn wolfssl_client(port: u16, version: TLSVersion) -> ParametersGuard {
        let (key, cert, temp_dir) = gen_certificate();

        let port_string = port.to_string();
        let mut args = vec!["-h", "127.0.0.1", "-p", &port_string, "-x", "-d"];
        let prog = "./examples/client/client";
        let cwd = "/home/max/projects/wolfssl";

        match version {
            TLSVersion::V1_3 => {
                args.push("-v");
                args.push("4");
            }
            TLSVersion::V1_2 => {
                args.push("-v");
                args.push("3");
            }
        }

        ParametersGuard {
            port,
            prog: prog.to_owned(),
            args: args.join(" "),
            cwd: Some(cwd.to_owned()),
            temp_dir: None,
        }
    }

    fn wolfssl_server(port: u16) -> ParametersGuard {
        let (key, cert, temp_dir) = gen_certificate();

        let port_string = port.to_string();
        let mut args = vec!["-p", &port_string, "-x", "-d"];
        let prog = "./examples/server/server";
        let cwd = "/home/max/projects/wolfssl";

        ParametersGuard {
            port,
            prog: prog.to_owned(),
            args: args.join(" "),
            cwd: Some(cwd.to_owned()),
            temp_dir: None,
        }
    }

    fn openssl_server(port: u16, version: TLSVersion) -> ParametersGuard {
        let (key, cert, temp_dir) = gen_certificate();

        let port_string = port.to_string();
        let mut args = vec![
            "s_server",
            "-accept",
            &port_string,
            "-msg",
            "-state",
            "-key",
            &key,
            "-cert",
            &cert,
        ];

        match version {
            TLSVersion::V1_3 => {
                args.push("-tls1_3");
            }
            TLSVersion::V1_2 => {
                args.push("-tls1_2");
            }
        }

        ParametersGuard {
            port,
            prog: OPENSSL_PROG.to_owned(),
            args: args.join(" "),
            cwd: None,
            temp_dir: Some(temp_dir),
        }
    }

    fn openssl_client(port: u16, version: TLSVersion) -> ParametersGuard {
        let connect = format!("{}:{}", "127.0.0.1", port);
        let mut args = vec!["s_client", "-connect", &connect, "-msg", "-state"];

        match version {
            TLSVersion::V1_3 => {
                args.push("-tls1_3");
            }
            TLSVersion::V1_2 => {
                args.push("-tls1_2");
            }
        }

        ParametersGuard {
            port,
            prog: OPENSSL_PROG.to_owned(),
            args: args.join(" "),
            cwd: None,
            temp_dir: None,
        }
    }

    #[test]
    fn test_openssl_session_resumption_dhe_full() {
        let port = 44330;
        let guard = openssl_server(port, TLSVersion::V1_3);
        let put = PutDescriptor {
            name: TCP_CLIENT_PUT,
            options: guard.build_options(),
        };

        let trace = seed_session_resumption_dhe_full.build_trace_with_puts(&[put.clone(), put]);
        trace.execute_default(&PUT_REGISTRY);

        let mut context = trace.execute_default(&PUT_REGISTRY);

        let server = AgentName::first().next();
        let shutdown = context.find_agent_mut(server).unwrap().put.shutdown();
        info!("{}", shutdown);
        assert!(shutdown.contains("Reused session-id"));
    }

    #[test]
    fn test_openssl_seed_client_attacker_full() {
        let port = 44331;

        let guard = openssl_server(port, TLSVersion::V1_3);
        let put = PutDescriptor {
            name: TCP_CLIENT_PUT,
            options: guard.build_options(),
        };

        let trace = seed_client_attacker_full.build_trace_with_puts(&[put]);
        let mut context = trace.execute_default(&PUT_REGISTRY);

        let server = AgentName::first();
        let shutdown = context.find_agent_mut(server).unwrap().put.shutdown();
        info!("{}", shutdown);
        assert!(shutdown.contains("BEGIN SSL SESSION PARAMETERS"));
        assert!(!shutdown.contains("Reused session-id"));
    }

    #[test]
    fn test_openssl_openssl_seed_successful12() {
        let port = 44332;

        let server_guard = openssl_server(port, TLSVersion::V1_2);
        let server = PutDescriptor {
            name: TCP_CLIENT_PUT,
            options: server_guard.build_options(),
        };

        let port = 55333;

        let client_guard = openssl_client(port, TLSVersion::V1_2);
        let client = PutDescriptor {
            name: TCP_SERVER_PUT,
            options: client_guard.build_options(),
        };

        let trace =
            seed_successful12_with_tickets.build_trace_with_puts(&[client.clone(), server.clone()]);
        let mut context = trace.execute_default(&PUT_REGISTRY);

        let client = AgentName::first();
        let shutdown = context.find_agent_mut(client).unwrap().put.shutdown();
        info!("{}", shutdown);
        assert!(shutdown.contains("Timeout   : 7200 (sec)"));

        let server = client.next();
        let shutdown = context.find_agent_mut(server).unwrap().put.shutdown();
        info!("{}", shutdown);
        assert!(shutdown.contains("BEGIN SSL SESSION PARAMETERS"));
    }

    #[test]
    #[ignore] // wolfssl example server and client are not available in CI
    fn test_wolfssl_openssl_seed_successful12() {
        let port = 44336;

        let server_guard = openssl_server(port, TLSVersion::V1_2);
        let server = PutDescriptor {
            name: TCP_CLIENT_PUT,
            options: server_guard.build_options(),
        };

        let port = 55337;

        let client_guard = wolfssl_client(port, TLSVersion::V1_2);
        let client = PutDescriptor {
            name: TCP_SERVER_PUT,
            options: client_guard.build_options(),
        };

        let trace =
            seed_successful12_with_tickets.build_trace_with_puts(&[client.clone(), server.clone()]);
        let mut context = trace.execute_default(&PUT_REGISTRY);

        let client = AgentName::first();
        let shutdown = context.find_agent_mut(client).unwrap().put.shutdown();
        info!("{}", shutdown);
        assert!(!shutdown.contains("fail"));

        let server = client.next();
        let shutdown = context.find_agent_mut(server).unwrap().put.shutdown();
        info!("{}", shutdown);
        assert!(shutdown.contains("BEGIN SSL SESSION PARAMETERS"));
    }
}
