use std::collections::HashMap;
use std::ffi::OsStr;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Shutdown, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

use opcua::puffin::messages::{MessageFlight, MAX_WIRE_SIZE};
use opcua::puffin::types::{AgentType, ApplicationConfig};
use puffin::agent::{AgentDescriptor, AgentName};
use puffin::algebra::ConcreteMessage;
use puffin::claims::GlobalClaimList;
use puffin::codec::Codec;
use puffin::error::Error;
use puffin::protocol::OpaqueProtocolMessageFlight;
use puffin::put::{Put, PutOptions};
use puffin::put_registry::{Factory, TCP_PUT};
use puffin::stream::Stream;

use crate::claims::OpcuaClaim;
use crate::protocol::OpcuaProtocolBehavior;

struct Agent {
    application: AgentDescriptor<ApplicationConfig>,
    port: u16,
    fuzz_streams: HashMap<u8, TcpStream>,
    _process: Option<OpcuaProcess>,
}

impl Agent {}

impl Stream<OpcuaProtocolBehavior> for Agent {
    fn add_to_inbound(&mut self, message: &ConcreteMessage) {
        // `message` is an unconstrained Vec<u8> that bit-level mutation can shrink (even to empty),
        // so guard before indexing: we need the 1-byte connexion id plus the 3-byte UA-TCP type
        // prefix. Indexing a shorter message would panic in the harness and be misreported as a
        // crash finding.
        if message.len() < 4 {
            log::warn!(
                "TCP\t| Dropping too-short message ({} bytes, need >= 4)",
                message.len()
            );
            return;
        }
        let id = message[0];
        let maybe_stream = match self.fuzz_streams.get_mut(&id) {
            Some(fs) => Some(fs),
            None => {
                if let Ok(new_stream) = TcpStream::connect((Ipv4Addr::LOCALHOST, self.port)) {
                    let _ = new_stream.set_read_timeout(Some(Duration::from_millis(1000)));
                    let _ = new_stream.set_nodelay(true);
                    self.fuzz_streams.insert(id, new_stream);
                    self.fuzz_streams.get_mut(&id)
                } else {
                    None
                }
            }
        };
        let mut closed = false;
        if let Some(fuzz_stream) = maybe_stream {
            // Try to send the message.
            fuzz_stream
                .write_all(&message[1..])
                .map_err(|e| log::warn!("TCP {}\t| Error while trying to send bytes: {}!", id, e))
                .ok();

            // UA TCP closes the connection if a CLO message is sent
            const CLOSE_SECURE_CHANNEL_MESSAGE: &'static [u8; 3] = b"CLO";
            if &message[1..4] == CLOSE_SECURE_CHANNEL_MESSAGE {
                log::warn!(
                    "TCP {}\t| Close connection, {} bytes",
                    id,
                    message.len() - 1
                );
                let _ = fuzz_stream.shutdown(Shutdown::Both);
                closed = true;
            } else {
                log::warn!("TCP {id}\t| Add message, {} bytes", message.len() - 1);
                fuzz_stream
                    .flush()
                    .map_err(|e| log::warn!("Error while trying to flush the TCP stream: {}!", e))
                    .ok();
            }
        } else {
            log::error!("TCP {id}\t| Failed to connect to localhost:{}", self.port);
        };
        // Drop a shut-down stream so a later message with the same connection id opens a fresh
        // connection instead of reusing the closed socket (writes to which would be silently lost).
        if closed {
            self.fuzz_streams.remove(&id);
        }
    }

    fn take_message_from_outbound(
        &mut self,
        output_flight: &mut Option<MessageFlight>,
    ) -> Result<(), Error> {
        let mut result = MessageFlight::new();
        for (id, fuzz_stream) in self.fuzz_streams.iter_mut() {
            // A single read() is not guaranteed to return exactly one UA-TCP frame (TCP may split
            // one frame across reads or coalesce several), so accumulate before framing. To avoid
            // idling a full read-timeout per connection once a response has arrived, the first read
            // uses the socket's configured (long) timeout to wait for the response, then subsequent
            // reads drain any coalesced frames under a short deadline. The full buffer is then
            // deframed at once (the framer prepends the conn id and length-frames internally).
            const DRAIN_TIMEOUT: Duration = Duration::from_millis(20);
            const DEFAULT_TIMEOUT: Duration = Duration::from_millis(1000);
            let mut acc: Vec<u8> = Vec::new();
            let mut chunk = vec![0u8; MAX_WIRE_SIZE];
            let mut first = true;
            loop {
                match fuzz_stream.read(&mut chunk) {
                    Ok(0) => break, // EOF
                    Ok(n) => {
                        acc.extend_from_slice(&chunk[..n]);
                        if acc.len() >= MAX_WIRE_SIZE {
                            break; // bound accumulation to one wire buffer
                        }
                        if first {
                            first = false;
                            let _ = fuzz_stream.set_read_timeout(Some(DRAIN_TIMEOUT));
                        }
                    }
                    // timeout / no more data ready => the flight is complete
                    Err(ref e)
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            || e.kind() == std::io::ErrorKind::TimedOut =>
                    {
                        break
                    }
                    Err(_) => break,
                }
            }
            // Restore the default timeout for later add/take cycles on this stream.
            if !first {
                let _ = fuzz_stream.set_read_timeout(Some(DEFAULT_TIMEOUT));
            }
            if acc.is_empty() {
                continue;
            }
            let mut framed = Vec::with_capacity(acc.len() + 1);
            framed.push(*id);
            framed.extend_from_slice(&acc);
            if let Some(flight) = MessageFlight::read_bytes(&framed) {
                result.merge(flight)
            } else {
                // Framing/decoding failure is a codec error, not a security violation: returning
                // SecurityClaim here would be recorded by the harness as a (false) objective.
                return Err(Error::Codec("Invalid UA TCP message!".to_string()));
            }
        }
        *output_flight = Some(result);
        Ok(())
    }
}

impl Put<OpcuaProtocolBehavior> for Agent {
    fn progress(&mut self) -> Result<(), Error> {
        Ok(())
    }

    fn reset(&mut self, _new_name: AgentName) -> Result<(), Error> {
        Ok(())
    }

    fn descriptor(&self) -> &AgentDescriptor<ApplicationConfig> {
        &self.application
    }

    fn describe_state(&self) -> String {
        "unimplemented!".to_string()
    }

    fn is_state_successful(&self) -> bool {
        true
    }

    fn version() -> String {
        "1.0".to_string()
    }

    fn shutdown(&mut self) -> String {
        for fuzz_stream in self.fuzz_streams.values() {
            let _ = fuzz_stream.shutdown(Shutdown::Both);
        }
        "TCP\t| All streams shut down!".to_string()
    }
}

#[derive(Debug, Clone)]
struct OpcTcpFactory {}

impl Factory<OpcuaProtocolBehavior> for OpcTcpFactory {
    fn create(
        &self,
        application: &AgentDescriptor<ApplicationConfig>,
        _claims: &GlobalClaimList<OpcuaClaim>,
        options: &PutOptions,
    ) -> Result<Box<dyn Put<OpcuaProtocolBehavior>>, Error> {
        let host = Ipv4Addr::LOCALHOST;
        let port = if let Some(port_arg) = options.get_option("port") {
            port_arg
                .parse::<u16>()
                .map_err(|e| Error::Put(format!("Invalid port number {port_arg:?}: {e}")))?
        } else {
            /* Only for --put tcp */
            match application.protocol_config.kind {
                AgentType::Server => 4840,
                AgentType::Client => 4841,
            }
        };

        // 1. Start the OPC UA Server:
        let process = if options.get_option("prog").is_some() {
            let prog = options.get_option("prog").unwrap();
            let args = options.get_option("args").unwrap_or("");
            let cwd = options.get_option("cwd");
            match application.protocol_config.kind {
                AgentType::Client => Some(OpcuaProcess::new(prog, args, cwd)),
                AgentType::Server => Some(OpcuaProcess::new(prog, args, cwd)),
            }
        } else {
            if options.get_option("port").is_some() {
                match application.protocol_config.kind {
                    AgentType::Client => {
                        Some(OpcuaProcess::new(
                            "./vendor/open62541/build/bin/examples/client_connect",
                            &("-username peter -password peter123 ".to_owned() +
                            "-cert crates/opcua-mapper/lib/src/puffin/assets/alice_cert.der " +
                            "-key crates/opcua-mapper/lib/src/puffin/assets/alice_key.der " +
                            "-securityMode 2 -securityPolicy http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256 " +
                            &format!("-reverse opc.tcp://localhost:{} ", port)),
                            Some("."))) },
                    AgentType::Server => {
                        Some(OpcuaProcess::new(
                            "./vendor/open62541/build/bin/examples/ci_server",
                            &(format!("{} ", port) +
                            "crates/opcua-mapper/lib/src/puffin/assets/bob_cert.pem " +
                            "crates/opcua-mapper/lib/src/puffin/assets/bob_key.pem"),
                            Some("."))) }
                }
            } else {
                /* Only for --put tcp: call of an external server on default port */
                None
            }
        };

        // 2. Connect to the TCP server listening on localhost:port
        match application.protocol_config.kind {
            AgentType::Server | AgentType::Client => {
                let fuzz_stream = TcpStream::connect((host, port)).map_err(|e| {
                    log::warn!(
                        "TCP\t| Failed to connect to server at {}:{}: {}",
                        host,
                        port,
                        e
                    );
                    Error::IO(e.to_string())
                })?;
                log::warn!("TCP 1\t| Connected to server at {}:{}", host, port);

                fuzz_stream
                    .set_read_timeout(Some(Duration::from_millis(1000)))
                    .map_err(|e| Error::IO(e.to_string()))?;
                fuzz_stream
                    .set_nodelay(true)
                    .map_err(|e| Error::IO(e.to_string()))?;

                Ok(Box::new(Agent {
                    application: application.clone(),
                    port,
                    fuzz_streams: HashMap::from([(1, fuzz_stream)]),
                    _process: process,
                }))
            }
        }
    }

    fn name(&self) -> String {
        String::from(TCP_PUT)
    }

    fn versions(&self) -> Vec<(String, String)> {
        vec![("harness".to_string(), "1.1".to_string())]
    }

    fn supports(&self, _capability: &str) -> bool {
        false
    }

    fn clone_factory(&self) -> Box<dyn Factory<OpcuaProtocolBehavior>> {
        Box::new(self.clone())
    }
}

pub fn new_opcua_factory() -> Box<dyn Factory<OpcuaProtocolBehavior>> {
    Box::new(OpcTcpFactory {})
}

// The OPC UA application process launcher.
// Manually create a new process launcher for each target.

pub struct OpcuaProcess {
    child: Option<Child>,
    output: Option<String>,
}

impl OpcuaProcess {
    pub fn new<P: AsRef<Path>>(prog: &str, args: &str, cwd: Option<P>) -> Self {
        let child = Self {
            child: Some(execute_command(prog, args.split(' '), cwd)),
            output: None,
        };
        thread::sleep(Duration::from_millis(500));
        child
    }

    pub fn shutdown(&mut self) -> Option<String> {
        self.output = if let Some(mut child) = self.child.take() {
            // Do NOT panic here: shutdown() runs from Drop, so a panic while the thread is already
            // unwinding from another error would be a double-panic and abort the whole fuzzer. The
            // child may already have exited (e.g. it crashed natively), which makes kill() fail --
            // that is expected during teardown, so just log it.
            if let Err(e) = child.kill() {
                log::debug!("OPC UA process already stopped (kill failed: {e})");
            }
            collect_output(child)
        } else {
            None
        };

        self.output.clone()
    }
}

impl Drop for OpcuaProcess {
    fn drop(&mut self) {
        if let Some(output) = self.shutdown() {
            println!(
                "OPC UA Process was not shutdown manually. Output:\n{}",
                output
            );
        }
    }
}

pub fn collect_output(child: Child) -> Option<String> {
    // Called from the teardown path (via Drop): never panic. Return None if the child output
    // cannot be collected, and lossily decode bytes rather than unwrap()-ing on non-UTF-8.
    let output = match child.wait_with_output() {
        Ok(o) => o,
        Err(e) => {
            log::debug!("could not wait on OPC UA child: {e}");
            return None;
        }
    };
    let mut complete = "--- start stderr\n".to_string();
    complete.push_str(&String::from_utf8_lossy(&output.stderr));
    complete.push_str("\n--- end stderr\n");
    complete.push_str("--- start stdout\n");
    complete.push_str(&String::from_utf8_lossy(&output.stdout));
    complete.push_str("\n--- end stdout\n");

    Some(complete)
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
        .stdin(Stdio::piped()) // needed!
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to execute OPC UA application process")
}
