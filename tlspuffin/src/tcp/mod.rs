use std::ffi::OsStr;
use std::io::{self, ErrorKind, Read, Write};
use std::net::{AddrParseError, IpAddr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::str::FromStr;
use std::sync::mpsc::{self, channel};
use std::thread;
use std::time::Duration;

use puffin::agent::{AgentDescriptor, AgentName, AgentType};
use puffin::algebra::ConcreteMessage;
use puffin::claims::GlobalClaimList;
use puffin::codec::Codec;
use puffin::error::Error;
use puffin::protocol::ProtocolBehavior;
use puffin::put::{Put, PutOptions};
use puffin::put_registry::{Factory, PutKind, TCP_PUT};
use puffin::stream::Stream;
use puffin::VERSION_STR;

use crate::protocol::{OpaqueMessageFlight, TLSProtocolBehavior};

pub fn new_tcp_factory() -> Box<dyn Factory<TLSProtocolBehavior>> {
    struct TCPFactory;
    impl Factory<TLSProtocolBehavior> for TCPFactory {
        fn create(
            &self,
            agent_descriptor: &AgentDescriptor,
            _claims: &GlobalClaimList<<TLSProtocolBehavior as ProtocolBehavior>::Claim>,
            options: &PutOptions,
        ) -> Result<Box<dyn Put<TLSProtocolBehavior>>, Error> {
            if options.get_option("args").is_some() {
                log::info!("Trace contains TCP running information we shall reuse.");
                let args = options
                    .get_option("args")
                    .ok_or_else(|| {
                        Error::Agent(format!("{} // {:?}", "Unable to find args", options))
                    })?
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
                    let mut server = TcpServerPut::new(agent_descriptor, options)?;
                    server.set_process(TLSProcess::new(&prog, &args, cwd.as_ref()));
                    Ok(Box::new(server))
                } else {
                    let process = TLSProcess::new(&prog, &args, cwd);
                    let mut client = TcpClientPut::new(agent_descriptor, options)?;
                    client.set_process(process);
                    Ok(Box::new(client))
                }
            } else {
                log::info!("Trace contains no TCP running information so we fall back to external TCP client and servers.");
                if agent_descriptor.typ == AgentType::Client {
                    let server = TcpServerPut::new(agent_descriptor, options)?;
                    Ok(Box::new(server))
                } else {
                    let client = TcpClientPut::new(agent_descriptor, options)?;
                    Ok(Box::new(client))
                }
            }
        }

        fn kind(&self) -> PutKind {
            PutKind::Rust
        }

        fn name(&self) -> String {
            String::from(TCP_PUT)
        }

        fn versions(&self) -> Vec<(String, String)> {
            vec![(
                "harness".to_string(),
                format!("{} ({})", TCP_PUT, VERSION_STR),
            )]
        }

        fn clone_factory(&self) -> Box<dyn Factory<TLSProtocolBehavior>> {
            Box::new(TCPFactory)
        }
    }

    Box::new(TCPFactory)
}

trait TcpPut {
    fn write_to_stream(&mut self, buf: &[u8]) -> io::Result<()>;

    fn read_to_flight(&mut self) -> Result<Option<OpaqueMessageFlight>, Error>;
}

/// A PUT which is backed by a TCP stream to a server.
/// In order to use this start an OpenSSL server like this:
///
/// ```bash
/// openssl s_server -key key.pem -cert cert.pem -accept 44330 -msg -debug -state
/// ```
pub struct TcpClientPut {
    stream: TcpStream,
    agent_descriptor: AgentDescriptor,
    process: Option<TLSProcess>,
}

impl TcpPut for TcpClientPut {
    fn write_to_stream(&mut self, buf: &[u8]) -> io::Result<()> {
        self.stream.write_all(buf)?;
        self.stream.flush()
    }

    fn read_to_flight(&mut self) -> Result<Option<OpaqueMessageFlight>, Error> {
        let mut buf = vec![];
        let _ = self.stream.read_to_end(&mut buf);
        let flight = OpaqueMessageFlight::read_bytes(&buf);
        Ok(flight)
    }
}

impl TcpClientPut {
    fn new(agent_descriptor: &AgentDescriptor, options: &PutOptions) -> Result<Self, Error> {
        let addr = addr_from_config(options).map_err(|err| Error::Put(err.to_string()))?;
        let stream = Self::new_stream(addr)?;

        Ok(Self {
            stream,
            agent_descriptor: agent_descriptor.clone(),
            process: None,
        })
    }

    fn new_stream<A: ToSocketAddrs>(addr: A) -> io::Result<TcpStream> {
        let mut tries = 500;
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

            thread::sleep(Duration::from_millis(100));
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
    agent_descriptor: AgentDescriptor,
    process: Option<TLSProcess>,
}

impl TcpServerPut {
    fn new(agent_descriptor: &AgentDescriptor, options: &PutOptions) -> Result<Self, Error> {
        let (sender, stream_receiver) = channel();
        let addr = addr_from_config(options).map_err(|err| Error::Put(err.to_string()))?;

        let listener = TcpListener::bind(addr).unwrap();

        thread::spawn(move || {
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

        if let Ok(tuple) = self.stream_receiver.recv_timeout(Duration::from_secs(60)) {
            self.stream = Some(tuple);
        } else {
            panic!("Unable to get stream to client!")
        }
    }
}

impl TcpPut for TcpServerPut {
    fn write_to_stream(&mut self, buf: &[u8]) -> io::Result<()> {
        self.receive_stream();
        let stream = &mut self.stream.as_mut().unwrap().0;
        stream.write_all(buf)?;
        stream.flush()?;
        Ok(())
    }

    fn read_to_flight(&mut self) -> Result<Option<OpaqueMessageFlight>, Error> {
        self.receive_stream();
        let mut buf = vec![];
        let _ = self.stream.as_mut().unwrap().0.read_to_end(&mut buf);
        let flight = OpaqueMessageFlight::read_bytes(&buf);
        Ok(flight)
    }
}

impl Stream<TLSProtocolBehavior> for TcpServerPut {
    fn add_to_inbound(&mut self, message: &ConcreteMessage) {
        self.write_to_stream(message).unwrap();
    }

    fn take_message_from_outbound(&mut self) -> Result<Option<OpaqueMessageFlight>, Error> {
        take_message_from_outbound(self)
    }
}

impl Stream<TLSProtocolBehavior> for TcpClientPut {
    fn add_to_inbound(&mut self, message: &ConcreteMessage) {
        self.write_to_stream(message).unwrap();
    }

    fn take_message_from_outbound(&mut self) -> Result<Option<OpaqueMessageFlight>, Error> {
        take_message_from_outbound(self)
    }
}

fn take_message_from_outbound<P: TcpPut>(
    put: &mut P,
) -> Result<Option<OpaqueMessageFlight>, Error> {
    put.read_to_flight()
}

fn addr_from_config(options: &PutOptions) -> Result<SocketAddr, AddrParseError> {
    let host = options.get_option("host").unwrap_or("127.0.0.1");
    let port = options
        .get_option("port")
        .and_then(|value| u16::from_str(value).ok())
        .unwrap_or_else(|| {
            let port = 44338;
            log::warn!(
                "Failed to parse port option (maybe you executed a trace that was not produced in \
            TCP mode?). We anyway fall back to port {port}."
            );
            port
        });

    Ok(SocketAddr::new(IpAddr::from_str(host)?, port))
}

impl Put<TLSProtocolBehavior> for TcpServerPut {
    fn progress(&mut self) -> Result<(), Error> {
        Ok(())
    }

    fn reset(&mut self, _new_name: AgentName) -> Result<(), Error> {
        panic!("Not supported")
    }

    fn descriptor(&self) -> &AgentDescriptor {
        &self.agent_descriptor
    }

    fn describe_state(&self) -> &str {
        panic!("Not supported")
    }

    fn is_state_successful(&self) -> bool {
        false
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
    fn progress(&mut self) -> Result<(), Error> {
        Ok(())
    }

    fn reset(&mut self, new_name: AgentName) -> Result<(), Error> {
        self.agent_descriptor.name = new_name;
        let address = self.stream.peer_addr()?;
        self.stream = Self::new_stream(address)?;
        Ok(())
    }

    fn descriptor(&self) -> &AgentDescriptor {
        &self.agent_descriptor
    }

    fn describe_state(&self) -> &str {
        panic!("Not supported")
    }

    fn is_state_successful(&self) -> bool {
        false
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
    pub fn new<P: AsRef<Path>>(prog: &str, args: &str, cwd: Option<P>) -> Self {
        Self {
            child: Some(execute_command(prog, args.split(' '), cwd)),
            output: None,
        }
    }

    pub fn shutdown(&mut self) -> Option<String> {
        self.output = if let Some(mut child) = self.child.take() {
            child.kill().expect("failed to stop process");

            Some(collect_output(child))
        } else {
            None
        };

        self.output.clone()
    }
}

impl Drop for TLSProcess {
    fn drop(&mut self) {
        if let Some(output) = self.shutdown() {
            println!(
                "TLSProcess was not shutdown manually. Output of the process: {}",
                output
            );
        }
    }
}

pub fn collect_output(child: Child) -> String {
    let output = child.wait_with_output().expect("failed to wait on child");
    let mut complete = "--- start stderr\n".to_string();

    complete.push_str(std::str::from_utf8(&output.stderr).unwrap());
    complete.push_str("\n--- end stderr\n");
    complete.push_str("--- start stdout\n");
    complete.push_str(std::str::from_utf8(&output.stdout).unwrap());
    complete.push_str("\n--- end stdout\n");

    complete
}

pub fn execute_command<I, S, P: AsRef<Path>>(prog: &str, args: I, cwd: Option<P>) -> Child
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
    use puffin::agent::TLSVersion;
    use puffin::execution::{Runner, TraceRunner};
    use puffin::put::PutDescriptor;
    use puffin::put_registry::TCP_PUT;
    use puffin::trace::Spawner;

    #[allow(unused_imports)]
    use crate::{test_utils::prelude::*, tls::seeds::*};

    #[test_log::test]
    fn test_openssl_session_resumption_dhe_full() {
        let port = 44330;
        let guard = openssl_server(port, TLSVersion::V1_3);
        let trace = seed_session_resumption_dhe_full.build_trace();
        let server = trace.descriptors[0].name;
        let runner = default_runner_for(PutDescriptor::new(TCP_PUT, guard.build_options()));

        let mut context = runner.execute(trace).unwrap();

        let shutdown = context.find_agent_mut(server).unwrap().shutdown();
        log::info!("{}", shutdown);
        assert!(shutdown.contains("Reused session-id"));
    }

    #[test_log::test]
    fn test_openssl_seed_client_attacker_full() {
        let port = 44331;
        let guard = openssl_server(port, TLSVersion::V1_3);
        let runner = default_runner_for(PutDescriptor::new(TCP_PUT, guard.build_options()));
        let trace = seed_client_attacker_full.build_trace();
        let server = trace.descriptors[0].name;

        let mut context = runner.execute(trace).unwrap();

        let shutdown = context.find_agent_mut(server).unwrap().shutdown();
        log::info!("{}", shutdown);
        assert!(shutdown.contains("BEGIN SSL SESSION PARAMETERS"));
        assert!(!shutdown.contains("Reused session-id"));
    }

    #[test_log::test]
    fn test_openssl_openssl_seed_successful12() {
        let trace = seed_successful12_with_tickets.build_trace();

        let server_port = 44332;
        let server_agent = trace.descriptors[1].name;
        let server_guard = openssl_server(server_port, TLSVersion::V1_2);
        let server = PutDescriptor::new(TCP_PUT, server_guard.build_options());

        let client_port = 44333;
        let client_agent = trace.descriptors[0].name;
        let client_guard = openssl_client(client_port, TLSVersion::V1_2);
        let client = PutDescriptor::new(TCP_PUT, client_guard.build_options());

        let put_registry = tls_registry();
        let runner = Runner::new(
            put_registry.clone(),
            Spawner::new(put_registry)
                .with_mapping(&[(client_agent, client), (server_agent, server)]),
        );

        let mut context = runner.execute(trace).unwrap();

        let shutdown = context.find_agent_mut(client_agent).unwrap().shutdown();
        log::info!("{}", shutdown);
        assert!(shutdown.contains("Timeout   : 7200 (sec)"));

        let shutdown = context.find_agent_mut(server_agent).unwrap().shutdown();
        log::info!("{}", shutdown);
        assert!(shutdown.contains("BEGIN SSL SESSION PARAMETERS"));
    }

    #[test_log::test]
    #[ignore] // wolfssl example server and client are not available in CI
    fn test_wolfssl_openssl_seed_successful12() {
        let trace = seed_successful12_with_tickets.build_trace();

        let server_port = 44334;
        let server_agent = trace.descriptors[1].name;
        let server_guard = openssl_server(server_port, TLSVersion::V1_2);
        let server = PutDescriptor::new(TCP_PUT, server_guard.build_options());

        let client_port = 44335;
        let client_agent = trace.descriptors[0].name;
        let client_guard = wolfssl_client(client_port, TLSVersion::V1_2, None);
        let client = PutDescriptor::new(TCP_PUT, client_guard.build_options());

        let put_registry = tls_registry();
        let runner = Runner::new(
            put_registry.clone(),
            Spawner::new(put_registry)
                .with_mapping(&[(client_agent, client), (server_agent, server)]),
        );

        let mut context = runner.execute(trace).unwrap();

        let shutdown = context.find_agent_mut(client_agent).unwrap().shutdown();
        log::info!("{}", shutdown);
        assert!(!shutdown.contains("fail"));

        let shutdown = context.find_agent_mut(server_agent).unwrap().shutdown();
        log::info!("{}", shutdown);
        assert!(shutdown.contains("BEGIN SSL SESSION PARAMETERS"));
    }
}
