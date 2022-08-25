/// PUT over TCP: any TLS-spewaking library can be plugged in through a TCP channel
/// Two libraries are ready to be tested: openssl and wolfssl
/// For openssl: an executable "openssl" must be in the path.
/// For wolfssl: a folder wolfssl corresponding to the wolf ssl git repository must be at the root
/// of this repository and the executable examples/server/server and examples/client/client must
/// be built.
/// When the flag fixed-port is enabled, the user should open its own client and server instances on
/// port 5000 for the server and 5001 for the client (TODO: find a 'retry' mode).

use std::{
    ffi::OsStr,
    io,
    io::{ErrorKind, Read, Write},
    net::{AddrParseError, IpAddr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs},
    path::Path,
    process::{Child, Command, Stdio},
    str::FromStr,
    sync::{mpsc, mpsc::channel},
    thread,
    time::Duration,
};
use std::fmt::Debug;

use log::{error, info};
use puffin::{
    agent::{AgentDescriptor, AgentName, AgentType, TLSVersion},
    error::Error,
    protocol::MessageResult,
    put::{Put, PutDescriptor, PutName},
    put_registry::Factory,
    stream::Stream,
    trace::TraceContext,
};

use crate::{
    protocol::TLSProtocolBehavior,
    put_registry::TCP_PUT,
    tls::rustls::msgs::{
        deframer::MessageDeframer,
        message::{Message, OpaqueMessage},
    },
};

pub fn new_tcp_factory() -> Box<dyn Factory<TLSProtocolBehavior>> {
    struct TCPFactory;
    impl Factory<TLSProtocolBehavior> for TCPFactory {
        fn create(
            &self,
            context: &TraceContext<TLSProtocolBehavior>,
            agent_descriptor: &AgentDescriptor,
        ) -> Result<Box<dyn Put<TLSProtocolBehavior>>, Error> {
            let put_descriptor = context.put_descriptor(agent_descriptor);

            let options = &put_descriptor.options;

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

            if agent_descriptor.typ == AgentType::Client {
                // TODO [LH] Weird, is there a typo in the conditional (I expected the converse)
                let mut server = TcpServerPut::new(agent_descriptor, &put_descriptor)?;
                server.set_process(TLSProcess::new(&prog, &args, cwd.as_ref()));
                Ok(Box::new(server))
            } else {
                let process = TLSProcess::new(&prog, &args, cwd);
                let mut client = TcpClientPut::new(agent_descriptor, &put_descriptor)?;
                client.set_process(process);
                Ok(Box::new(client))
            }
        }

        fn name(&self) -> PutName {
            TCP_PUT
        }

        fn version(&self) -> String {
            TcpClientPut::version()
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
    agent_descriptor: AgentDescriptor,
    process: Option<TLSProcess>,
}

impl TcpPut for TcpClientPut {
    fn deframer_mut(&mut self) -> &mut MessageDeframer {
        &mut self.deframer
    }

    fn write_to_stream(&mut self, buf: &[u8]) -> io::Result<()> {
        self.stream.write_all(buf)?;
        self.stream.flush()
    }

    fn read_to_deframer(&mut self) -> io::Result<usize> {
        self.deframer.read(&mut self.stream)
    }
}

impl TcpClientPut {
    fn new(
        agent_descriptor: &AgentDescriptor,
        put_descriptor: &PutDescriptor,
    ) -> Result<Self, Error> {
        let addr =
            if true { //cfg!(feature = "fixed-port") {
                addr_from_config(put_descriptor).map_err(|err| Error::Put(err.to_string()))?
            } else {
                let host = &put_descriptor.options.get_option("host").unwrap_or("127.0.0.1");
                SocketAddr::new(IpAddr::from_str(host).unwrap(), 5001)
            };

        let stream = Self::new_stream(addr)?;

        Ok(Self {
            stream,
            deframer: Default::default(),
            agent_descriptor: agent_descriptor.clone(),
            process: None,
        })
    }

    fn new_stream<A: ToSocketAddrs>(addr: A) -> io::Result<TcpStream> {
        let mut tries = 10;
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
    agent_descriptor: AgentDescriptor,
    process: Option<TLSProcess>,
}

impl TcpServerPut {
    fn new(
        agent_descriptor: &AgentDescriptor,
        put_descriptor: &PutDescriptor,
    ) -> Result<Self, Error> {
        let (sender, stream_receiver) = channel();
        let addr =
            if cfg!(not(feature = "fixed-port")) {
                addr_from_config(put_descriptor).map_err(|err| Error::Put(err.to_string()))?
            } else {
                let host = &put_descriptor.options.get_option("host").unwrap_or("127.0.0.1");
                SocketAddr::new(IpAddr::from_str(host).unwrap(), 5000)
            };

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
            agent_descriptor: agent_descriptor.clone(),
            process: None,
        })
    }

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
            panic!("Unable to get stream to client!")
        }
    }
}

impl TcpPut for TcpServerPut {
    fn deframer_mut(&mut self) -> &mut MessageDeframer {
        &mut self.deframer
    }

    fn write_to_stream(&mut self, buf: &[u8]) -> io::Result<()> {
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

impl Stream<Message, OpaqueMessage> for TcpServerPut {
    fn add_to_inbound(&mut self, opaque_message: &OpaqueMessage) {
        self.write_to_stream(&mut opaque_message.clone().encode())
            .unwrap();
    }

    fn take_message_from_outbound(
        &mut self,
    ) -> Result<Option<MessageResult<Message, OpaqueMessage>>, Error> {
        take_message_from_outbound(self)
    }
}

impl Stream<Message, OpaqueMessage> for TcpClientPut {
    fn add_to_inbound(&mut self, opaque_message: &OpaqueMessage) {
        self.write_to_stream(&mut opaque_message.clone().encode())
            .unwrap();
    }

    fn take_message_from_outbound(
        &mut self,
    ) -> Result<Option<MessageResult<Message, OpaqueMessage>>, Error> {
        take_message_from_outbound(self)
    }
}

fn take_message_from_outbound<P: TcpPut>(
    put: &mut P,
) -> Result<Option<MessageResult<Message, OpaqueMessage>>, Error> {
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

fn addr_from_config(put_descriptor: &PutDescriptor) -> Result<SocketAddr, AddrParseError> {
    let options = &put_descriptor.options;
    let host = options.get_option("host").unwrap_or("127.0.0.1");
    let port =
        options
        .get_option("port")
        .and_then(|value| u16::from_str(value).ok())
        .expect("Failed to parse port option");

    Ok(SocketAddr::new(IpAddr::from_str(host)?, port))
}

impl Put<TLSProtocolBehavior> for TcpServerPut {
    fn progress(&mut self, _agent_name: &AgentName) -> Result<(), Error> {
        Ok(())
    }

    fn reset(&mut self, _agent_name: AgentName) -> Result<(), Error> {
        panic!("Not supported")
    }

    fn descriptor(&self) -> &AgentDescriptor {
        &self.agent_descriptor
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

    fn set_deterministic(&mut self) -> Result<(), puffin::error::Error> {
        Err(Error::Agent(
            "Unable to make TCP PUT deterministic!".to_string(),
        ))
    }

    fn shutdown(&mut self) -> String {
        self.process.as_mut().unwrap().shutdown().unwrap()
    }

    fn version() -> String
    where
        Self: Sized,
    {
        "Undefined".to_string()
    }
}

impl Put<TLSProtocolBehavior> for TcpClientPut {
    fn progress(&mut self, _agent_name: &AgentName) -> Result<(), Error> {
        Ok(())
    }

    fn reset(&mut self, _agent_name: AgentName) -> Result<(), Error> {
        let address = self.stream.peer_addr()?;
        self.stream = Self::new_stream(address)?;
        Ok(())
    }

    fn descriptor(&self) -> &AgentDescriptor {
        &self.agent_descriptor
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

    fn set_deterministic(&mut self) -> Result<(), puffin::error::Error> {
        Err(Error::Agent(
            "Unable to make TCP PUT deterministic!".to_string(),
        ))
    }

    fn shutdown(&mut self) -> String {
        self.process.as_mut().unwrap().shutdown().unwrap()
    }

    fn version() -> String
    where
        Self: Sized,
    {
        "Undefined".to_string()
    }
}

pub struct TLSProcess {
    child: Option<Child>,
    output: Option<String>,
}

impl TLSProcess {
    pub fn new<P: AsRef<Path> + Debug>(prog: &str, args: &str, cwd: Option<P>) -> Self {
        Self {
            child: Some(execute_command(prog, args.split(' '), cwd)),
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

fn execute_command<I, S, P: AsRef<Path> + Debug>(prog: &str, args: I, cwd: Option<P>) -> Child
where
    I: IntoIterator<Item = S> + Debug,
    S: AsRef<OsStr>,
{
    let mut cmd = Command::new(prog);

    info!("About to execute: {:?} from {:?} with args {:?}", &cmd, &cwd, &args);

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
    use std::env;
    use log::info;
    use puffin::{
        agent::{AgentName, TLSVersion},
        put::{PutDescriptor, PutOptions},
    };
    use tempfile::{tempdir, TempDir};
    use test_log::test;

    use crate::{
        put_registry::{TCP_PUT, TLS_PUT_REGISTRY},
        tcp::{collect_output, execute_command},
        tls::seeds::{
            seed_client_attacker_full, seed_session_resumption_dhe_full,
            seed_successful12_with_tickets, SeedHelper,
        },
    };

    const OPENSSL_PROG: &str = "openssl";

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
        let (_key, _cert, _temp_dir) = gen_certificate();

        let port_string = port.to_string();
        let mut args = vec!["-h", "127.0.0.1", "-p", &port_string, "-x", "-d", "-v4"];
        let prog = "./examples/client/client";
        let mut cwd = env::current_dir().unwrap();
        cwd.push("../wolfssl");

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
            cwd: Some(cwd.to_str().unwrap().to_owned()),
            temp_dir: None,
        }
    }

    fn wolfssl_server(port: u16) -> ParametersGuard {
        let (_key, _cert, _temp_dir) = gen_certificate();

        let port_string = port.to_string();
        let args = vec!["-p", &port_string, "-x", "-d", "-v4"];
        let prog = "./examples/server/server";
        let mut cwd = env::current_dir().unwrap();
        cwd.push("../wolfssl");

        ParametersGuard {
            port,
            prog: prog.to_owned(),
            args: args.join(" "),
            cwd: Some(cwd.to_str().unwrap().to_owned()),
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
            name: TCP_PUT,
            options: guard.build_options(),
        };

        let trace = seed_session_resumption_dhe_full.build_trace();
        let initial_server = trace.prior_traces[0].descriptors[0].name;
        let server = trace.descriptors[0].name;
        let mut context = trace.execute_with_puts(
            &TLS_PUT_REGISTRY,
            &[(initial_server, put.clone()), (server, put)],
        );

        let server = AgentName::first().next();
        let shutdown = context.find_agent_mut(server).unwrap().put_mut().shutdown();
        info!("{}", shutdown);
        assert!(shutdown.contains("Reused session-id"));
    }

    #[test]
    fn test_openssl_seed_client_attacker_full() {
        let port = 44331;

        let guard = openssl_server(port, TLSVersion::V1_3);
        let put = PutDescriptor {
            name: TCP_PUT,
            options: guard.build_options(),
        };

        let trace = seed_client_attacker_full.build_trace();
        let server = trace.descriptors[0].name;
        let mut context = trace.execute_with_puts(&TLS_PUT_REGISTRY, &[(server, put)]);

        let server = AgentName::first();
        let shutdown = context.find_agent_mut(server).unwrap().put_mut().shutdown();
        info!("{}", shutdown);
        assert!(shutdown.contains("BEGIN SSL SESSION PARAMETERS"));
        assert!(!shutdown.contains("Reused session-id"));
    }

    #[test]
    fn test_openssl_openssl_seed_successful12() {
        let port = 44332;

        let server_guard = openssl_server(port, TLSVersion::V1_2);
        let server = PutDescriptor {
            name: TCP_PUT,
            options: server_guard.build_options(),
        };

        let port = 55333;

        let client_guard = openssl_client(port, TLSVersion::V1_2);
        let client = PutDescriptor {
            name: TCP_PUT,
            options: client_guard.build_options(),
        };

        let trace = seed_successful12_with_tickets.build_trace();
        let descriptors = &trace.descriptors;
        let client_name = descriptors[0].name;
        let server_name = descriptors[1].name;
        let mut context = trace.execute_with_puts(
            &TLS_PUT_REGISTRY,
            &[(client_name, client.clone()), (server_name, server.clone())],
        );

        let client = AgentName::first();
        let shutdown = context.find_agent_mut(client).unwrap().put_mut().shutdown();
        info!("{}", shutdown);
        assert!(shutdown.contains("Timeout   : 7200 (sec)"));

        let server = client.next();
        let shutdown = context.find_agent_mut(server).unwrap().put_mut().shutdown();
        info!("{}", shutdown);
        assert!(shutdown.contains("BEGIN SSL SESSION PARAMETERS"));
    }

    use std::io::prelude::*;
    use std::fs::File;
    use puffin::algebra::set_deserialize_signature;
    use puffin::libafl::inputs::Input;
    use puffin::trace::Trace;
    use crate::query::TlsQueryMatcher;
    use crate::tls::TLS_SIGNATURE;

    #[test]
    fn test_wolfssl_openssl_seed_successful12() {
        let port = 44336;

        let server_guard = wolfssl_server(port);
        let server = PutDescriptor {
            name: TCP_PUT,
            options: server_guard.build_options(),
        };

            let client_guard = wolfssl_client(port, TLSVersion::V1_2);
            let client = PutDescriptor {
                name: TCP_PUT,
                options: client_guard.build_options(),
            };

            let trace = seed_successful12_with_tickets.build_trace();
            let descriptors = &trace.descriptors;
            let client_name = descriptors[0].name;
            let server_name = descriptors[1].name;
            let mut context = trace.execute_with_puts(
                &TLS_PUT_REGISTRY,
                &[(client_name, client.clone()), (server_name, server.clone())],
            );

            let client = AgentName::first();
            let shutdown = context.find_agent_mut(client).unwrap().put_mut().shutdown();
            info!("{}", shutdown);
            assert!(!shutdown.contains("fail"));

            let server = client.next();
            let shutdown = context.find_agent_mut(server).unwrap().put_mut().shutdown();

        info!("{}", shutdown);
    }

    #[test]
    fn test_wolfssl_buffer_under_read_client() {
        // To test this and find the buffer overflow you need to enable CALLBACKS functions.
        // For example, do the following at the root fo this repo prior to executing this test:
        // $ git clone --branch debug_buffer_overflow git@github.com:tlspuffin/wolfssl.git
        // $ cd wolfssl; ./autogen.sh; ./configure --enable-all CFLAGS='-DWOLFSSL_CALLBACKS -fsanitize=address'; make; cd ..
        // and that's all.
        let port = 44336;

        let server_guard = wolfssl_server(port);
        let server = PutDescriptor {
            name: TCP_PUT,
            options: server_guard.build_options(),
        };

        let client_guard = wolfssl_client(port, TLSVersion::V1_3);
        let client = PutDescriptor {
            name: TCP_PUT,
            options: client_guard.build_options(),
        };

        set_deserialize_signature(&TLS_SIGNATURE).expect("TODO: panic message");

        // Read trace file
        let mut path = env::current_dir().unwrap();
        path.push("../TRACES/HEAP_BUFFER_UNDER_READ_2022-08-23-114149-Wolfssl540_BUFFER-0_4.trace-16");
        // AGENTNAME 0 and 1 --> OK if only 0 still bug ?
        info!("Accessing trace file at {}",path.display());
        let mut trace = Trace::<TlsQueryMatcher>::from_file(path).unwrap();
        info!("Trace descriptors: {:#?}", trace.descriptors);
        info!("Trace steps: {:#?}", trace.steps);
        info!("Trace prior steps: {:#?}\n           -------------------\n", trace.prior_traces);

        // Try to minimize the trace
       let trace = Trace {
            steps: vec![trace.steps[0].clone()],
            descriptors: vec![trace.descriptors[0].clone()],
            ..trace
          // prior_traces: vec![],
        };

        let descriptors = &trace.descriptors;
        let client_name = descriptors[0].name;
      //  let server_name = descriptors[1].name;
        let mut context = trace.execute_with_puts(
            &TLS_PUT_REGISTRY,
            &[(client_name, client.clone())], //, (server_name, server.clone())],  // Use en empty array here instead to not change the PUT
        );

        let server = AgentName::first();
        let shutdown = context.find_agent_mut(server).unwrap().put.shutdown();
        info!("{}", shutdown);
    }
}