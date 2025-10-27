use std::collections::HashSet;
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
use opcua::puffin::types::OpcuaDescriptorConfig;
use opcua::puffin::static_certs::{BOB_CERTIFICATE, BOB_PRIVATE_KEY};

use crate::claims::OpcuaClaim;
use crate::protocol::OpcuaProtocolBehavior;
use crate::put_registry::OPEN62541;

mod raw;

struct Agent {
    agent_descriptor: AgentDescriptor<OpcuaDescriptorConfig>,
    _capabilities: HashSet<String>,
    _claims: GlobalClaimList<OpcuaClaim>,
    fuzz_stream: TcpStream,
    _certificate: &'static [u8], //DER
    _private_key: &'static [u8], //DER
    //...
}

impl Agent {}

impl Stream<OpcuaProtocolBehavior> for Agent {
    fn add_to_inbound(&mut self, message: &ConcreteMessage) {
        log::warn!("Added a new message to the PUT");
        self.fuzz_stream.write_all(message).unwrap();
        self.fuzz_stream.flush().unwrap();
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

    fn descriptor(&self) -> &AgentDescriptor<OpcuaDescriptorConfig> {
        &self.agent_descriptor
    }

    fn describe_state(&self) -> String {
        "unimplemented!".to_string()
    }

    fn is_state_successful(&self) -> bool {
        unimplemented!("Put for Agent")
    }

    fn version() -> String {
        "unimplemented!".to_string()
    }

    fn shutdown(&mut self) -> String {
        self.fuzz_stream.shutdown(Shutdown::Both).unwrap();
        "TCP stream shut down!".to_string()
    }
}

struct Open62541Factory {}

    impl Factory<OpcuaProtocolBehavior> for Open62541Factory {
        fn create(
            &self,
            agent_descriptor: &AgentDescriptor<OpcuaDescriptorConfig>,
            claims: &GlobalClaimList<OpcuaClaim>,
            _options: &PutOptions,
        ) -> Result<Box<dyn Put<OpcuaProtocolBehavior>>, Error> {

            let host = Ipv4Addr::LOCALHOST;
            let port = 4840;

            // 1. create a server listening on localhost:port:

            // 2. connect to the server:
            let fuzz_stream = TcpStream::connect((host, port))
                .map_err(|e| {
                    log::warn!("Failed to connect to OPC UA server at {}:{}: {}", host, port, e);
                    Error::IO(e.to_string())
                })?;
            log::warn!("Connected to OPC UA server at {}:{}", host, port);

            fuzz_stream.set_read_timeout(Some(Duration::from_millis(500)))
                 .map_err(|e| { Error::IO(e.to_string()) })?;
            fuzz_stream.set_nodelay(true)
                 .map_err(|e| { Error::IO(e.to_string()) })?;

            Ok(Box::new(Agent{
                agent_descriptor: agent_descriptor.clone(),
                _capabilities: HashSet::new(),
                _claims: claims.clone(),
                fuzz_stream,
                _certificate: BOB_CERTIFICATE.1,
                _private_key: BOB_PRIVATE_KEY.1
            }))
        }

        fn name(&self) -> String {String::from(OPEN62541)}

        fn versions(&self) -> Vec<(String, String)>{
            vec![
                ("harness".to_string(), "0.0".to_string()),
                ("library".to_string(), "1.5".to_string()),
            ]
        }

        fn supports(&self, _capability: &str) -> bool {false}

        fn clone_factory(&self) -> Box<dyn Factory<OpcuaProtocolBehavior>>{
            Box::new(Open62541Factory {})
        }

    }

pub fn new_opcua_factory() -> Box<dyn Factory<OpcuaProtocolBehavior>> {
    Box::new(Open62541Factory {})
}
