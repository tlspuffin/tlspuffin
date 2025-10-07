use std::collections::HashSet;
//use std::fs;
use std::io::{Read, Write};
//use std::os::unix::io::{IntoRawFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};

use puffin::agent::{AgentDescriptor, AgentName};
use puffin::algebra::ConcreteMessage;
use puffin::claims::GlobalClaimList;
use puffin::codec::Codec;
use puffin::error::Error;
use puffin::put::{Put, PutOptions};
use puffin::put_registry::Factory;
use puffin::stream::Stream;

use opcua::puffin::types::OpcuaDescriptorConfig;
use opcua::puffin::messages::MessageFlight;

use crate::claims::OpcuaClaim;
use crate::protocol::OpcuaProtocolBehavior;
use crate::put_registry::OPEN62541;

mod raw;

struct Agent {
    agent_descriptor: AgentDescriptor<OpcuaDescriptorConfig>,
    capabilities: HashSet<String>,
    claims: GlobalClaimList<OpcuaClaim>,
    fuzz_stream: UnixStream,
    //...
}

impl Agent {}

impl Stream<OpcuaProtocolBehavior> for Agent {
    fn add_to_inbound(&mut self, message: &ConcreteMessage) {
        self.fuzz_stream.write_all(message).unwrap();
    }

    fn take_message_from_outbound(&mut self) -> Result<Option<MessageFlight>, Error> {
        let mut buf = vec![];
        let _ = self.fuzz_stream.read_to_end(&mut buf);
        Ok(MessageFlight::read_bytes(&buf))
    }
}

impl Put<OpcuaProtocolBehavior> for Agent {
    fn progress(&mut self) -> Result<(), Error> {
        unimplemented!("Put for Agent")
    }

    fn reset(&mut self, _new_name: AgentName) -> Result<(), Error> {
        unimplemented!("Put for Agent")
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
        unimplemented!("Put for Agent")
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

            let path = format!("socket_{}", agent_descriptor.name);
            let fuzz_stream = UnixStream::connect(path).unwrap();

            Ok(Box::new(Agent{
                agent_descriptor: agent_descriptor.clone(),
                capabilities: HashSet::new(),
                claims: claims.clone(),
                fuzz_stream
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
