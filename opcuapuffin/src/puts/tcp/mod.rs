use std::io::{Read, Write};
use std::net::{Ipv4Addr, Shutdown, TcpStream};
use std::time::Duration;

use puffin::agent::{AgentDescriptor, AgentName};
use puffin::algebra::ConcreteMessage;
use puffin::claims::GlobalClaimList;
use puffin::codec::Codec;
use puffin::error::Error;
use puffin::put::{Put, PutOptions};
use puffin::put_registry::Factory;
use puffin::stream::Stream;

use opcua::puffin::messages::{MAX_WIRE_SIZE, MessageFlight};
use opcua::puffin::types::{AgentType, ApplicationConfig};

use crate::claims::OpcuaClaim;
use crate::protocol::OpcuaProtocolBehavior;
use crate::put_registry::OPC_TCP;

struct Agent {
    application: AgentDescriptor<ApplicationConfig>,
    fuzz_stream: TcpStream,
}

impl Agent {}

impl Stream<OpcuaProtocolBehavior> for Agent {
    fn add_to_inbound(&mut self, message: &ConcreteMessage) {
        log::warn!("Added a new message to the PUT of size {}", message.len());
        self.fuzz_stream.write_all(message).map_err(|e| log::warn!("Error while trying to put bytes in the PUT: {}!", e)).ok();
        self.fuzz_stream.flush().map_err(|e| log::warn!("Error while trying to flush the PUT: {}!", e)).ok();
    }

    fn take_message_from_outbound(&mut self) -> Result<Option<MessageFlight>, Error> {
        let mut buf = vec![];
        buf.resize(MAX_WIRE_SIZE, 0);
        let size = self.fuzz_stream.read(&mut buf).map_err(|e| {
            log::warn!("Error while trying to take bytes from the PUT: {}!", e);
            Error::Put("Error while trying to take bytes from the PUT!".to_string())
        })?;
        log::warn!("Took {size} bytes from the PUT");
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
        _options: &PutOptions,
    ) -> Result<Box<dyn Put<OpcuaProtocolBehavior>>, Error> {

        let host = Ipv4Addr::LOCALHOST;
        let port = match application.protocol_config.kind {
            AgentType::Server => 4840,
            AgentType::Client => 4841,
        };

        match application.protocol_config.kind {
            AgentType::Server | AgentType::Client => {
                // 2. connect to the TCP server listening on localhost:port
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
                }))
            }
        }
    }

    fn name(&self) -> String {String::from(OPC_TCP)}

    fn versions(&self) -> Vec<(String, String)>{
        vec![
            ("harness".to_string(), "1.0".to_string()),
            ("library".to_string(), "???".to_string()),
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
