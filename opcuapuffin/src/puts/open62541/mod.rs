use std::collections::HashSet;

use puffin::agent::{AgentDescriptor, AgentName};
use puffin::algebra::ConcreteMessage;
use puffin::claims::GlobalClaimList;
use puffin::error::Error;
use puffin::put::{Put, PutOptions};
use puffin::put_registry::Factory;
use puffin::stream::{MemoryStream, Stream};

use opcua::puffin::messages::MessageFlight;
use opcua::puffin::types::{AgentType, OpcuaDescriptorConfig};

use crate::claims::OpcuaClaim;
use crate::protocol::OpcuaProtocolBehavior;
use crate::put_registry::OPEN62541;

mod raw;

struct Agent {
    agent_descriptor: AgentDescriptor<OpcuaDescriptorConfig>,
    _capabilities: HashSet<String>,
    _claims: GlobalClaimList<OpcuaClaim>,
    fuzz_stream: MemoryStream
}

impl Agent {}

impl Stream<OpcuaProtocolBehavior> for Agent {
    fn add_to_inbound(&mut self, message: &ConcreteMessage) {
        log::warn!("Added a new message to the PUT of size {}", message.len());
        <MemoryStream as Stream<OpcuaProtocolBehavior>>::add_to_inbound(&mut self.fuzz_stream, message);
    }

    fn take_message_from_outbound(&mut self) -> Result<Option<MessageFlight>, Error> {
        <MemoryStream as Stream<OpcuaProtocolBehavior>>::take_message_from_outbound(&mut self.fuzz_stream)
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
        true
    }

    fn version() -> String {
        "unimplemented!".to_string()
    }

    fn shutdown(&mut self) -> String {
        "Memory stream to open62541 is shut down!".to_string()
    }
}

#[derive(Clone)]
struct Open62541Factory {}

impl Factory<OpcuaProtocolBehavior> for Open62541Factory {
    fn create(
        &self,
        agent_descriptor: &AgentDescriptor<OpcuaDescriptorConfig>,
        claims: &GlobalClaimList<OpcuaClaim>,
        _options: &PutOptions,
    ) -> Result<Box<dyn Put<OpcuaProtocolBehavior>>, Error> {

        match agent_descriptor.protocol_config.kind {
            AgentType::Server | AgentType::Client => {

                Ok(Box::new(Agent{
                    agent_descriptor: agent_descriptor.clone(),
                    _capabilities: HashSet::new(),
                    _claims: claims.clone(),
                    fuzz_stream: MemoryStream::new()
                }))
            },
            _ => unimplemented!()
        }
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
        Box::new(self.clone())
    }

}

pub fn new_opcua_factory() -> Box<dyn Factory<OpcuaProtocolBehavior>> {
    Box::new(Open62541Factory {})
}
