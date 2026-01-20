use std::ffi::OsStr;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Shutdown, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

use puffin::agent::{AgentDescriptor, AgentName};
use puffin::algebra::ConcreteMessage;
use puffin::claims::GlobalClaimList;
use puffin::codec::Codec;
use puffin::error::Error;
use puffin::put::{Put, PutOptions};
use puffin::put_registry::{Factory, TCP_PUT};
use puffin::stream::Stream;

use opcua::puffin::messages::{MAX_WIRE_SIZE, MessageFlight};
use opcua::puffin::types::{AgentType, ApplicationConfig};

use crate::claims::OpcuaClaim;
use crate::protocol::OpcuaProtocolBehavior;

struct Agent {
    application: AgentDescriptor<ApplicationConfig>,
    fuzz_stream: TcpStream,
    _process: Option<OpcuaProcess>,
}

impl Agent {}

impl Stream<OpcuaProtocolBehavior> for Agent {
    fn add_to_inbound(&mut self, message: &ConcreteMessage) {
        log::warn!("Add message, {} bytes", message.len());
        self.fuzz_stream.write_all(message).map_err(|e| log::warn!("TCP: error while trying to send bytes: {}!", e)).ok();
        self.fuzz_stream.flush().map_err(|e| log::warn!("Error while trying to flush the TCP stream: {}!", e)).ok();
    }

    fn take_message_from_outbound(&mut self) -> Result<Option<MessageFlight>, Error> {
        let mut buf = vec![0; MAX_WIRE_SIZE];
        let size = self.fuzz_stream.read(&mut buf).map_err(|e| {
            log::error!("TCP: error while trying to take bytes: {}!", e);
            Error::Put("TCP: error while trying to take bytes!".to_string())
        })?;
        Ok(MessageFlight::read_bytes(&buf[0..size]))
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
        if let Err(e) = self.fuzz_stream.shutdown(Shutdown::Both){
            log::warn!("Error at TCP stream shut down: {e}");
            format!("Error at TCP stream shut down: {e}")
        } else {
            "TCP stream shut down!".to_string()
        }
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
        let port =
            if let Some(port_arg) = options.get_option("port") {
                u16::from_str_radix(port_arg, 10).expect("Invalid port number")
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
                AgentType::Client => {
                    Some(OpcuaProcess::new(prog, args, cwd)) },
                AgentType::Server => {
                    Some(OpcuaProcess::new(prog, args, cwd)) },
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
                let fuzz_stream = TcpStream::connect((host, port))
                .map_err(|e| {
                    log::warn!("Failed to connect to TCP server at {}:{}: {}", host, port, e);
                    Error::IO(e.to_string())
                })?;
                log::warn!("Connected to TCP server at {}:{}", host, port);

                fuzz_stream.set_read_timeout(Some(Duration::from_millis(1000)))
                    .map_err(|e| { Error::IO(e.to_string()) })?;
                fuzz_stream.set_nodelay(true)
                    .map_err(|e| { Error::IO(e.to_string()) })?;

                Ok(Box::new(Agent{
                    application: application.clone(),
                    fuzz_stream,
                    _process: process,
                }))
            }
        }
    }

    fn name(&self) -> String {String::from(TCP_PUT)}

    fn versions(&self) -> Vec<(String, String)>{
        vec![
            ("harness".to_string(), "1.0".to_string()),
        ]
    }

    fn supports(&self, _capability: &str) -> bool {false}

    fn clone_factory(&self) -> Box<dyn Factory<OpcuaProtocolBehavior>>{
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
            child.kill().expect("failed to stop process");

            Some(collect_output(child))
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
        .stdin(Stdio::piped()) // needed!
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to execute OPC UA application process")
}