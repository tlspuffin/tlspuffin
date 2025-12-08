use std::collections::{BTreeMap, HashSet};

use puffin::agent::{AgentDescriptor, AgentName};
use puffin::algebra::ConcreteMessage;
use puffin::claims::GlobalClaimList;
use puffin::error::Error;
use puffin::put::{Put, PutOptions};
use puffin::put_registry::Factory;
use puffin::stream::{MemoryStream, Stream};

use opcua::puffin::messages::MessageFlight;
use opcua::puffin::types::{AgentType, ApplicationConfig};

use crate::claims::OpcuaClaim;
use crate::protocol::OpcuaProtocolBehavior;
use crate::put_registry::OPEN62541;
use crate::puts::opcua_sys::{AGENT, AGENT_INTERFACE, APPLICATION_DESCRIPTOR,
    OPCUA_AGENT_ROLE, OPCUA_PUT_INTERFACE, VOID_STORE, version_of,
    ALICE_CERTIFICATE, ALICE_PRIVATE_KEY, BOB_CERTIFICATE, BOB_PRIVATE_KEY};

mod raw;

// An agent is a virtual TCP channel that is used by the fuzzer to communicate
// with an OPC UA application instantiated in the library open62541.
struct Agent {
    application: AgentDescriptor<ApplicationConfig>,
    _capabilities: HashSet<String>,
    _claims: GlobalClaimList<OpcuaClaim>,
    fuzz_stream: MemoryStream,
    c_agent: AGENT,
    c_agent_interface: AGENT_INTERFACE
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
        if let Some(agent_progress) = self.c_agent_interface.progress {
            unsafe { agent_progress(self.c_agent) };
            Ok(())
        } else {
            Err(Error::Put("Open62541 Agent: progress unavailable!".to_string()))
        }
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
        "unimplemented!".to_string()
    }

    fn shutdown(&mut self) -> String {
        format!("Open62541 agent: {} is shutting down", self.application.name)
    }
}

impl Drop for Agent {
    fn drop(&mut self) {
        if let Some(destroy) = self.c_agent_interface.destroy {
            unsafe { destroy(self.c_agent) }
    }}
}

// We only insert applications, we never remove them so taking references is ok.
struct Open62541State {
    pub applications: BTreeMap<u8, APPLICATION_DESCRIPTOR>
}
static mut PUT_STATE: Open62541State = Open62541State {
    applications: BTreeMap::new()
};

#[derive(Clone)]
struct Open62541Factory {
    put_interface: OPCUA_PUT_INTERFACE,
}

impl Factory<OpcuaProtocolBehavior> for Open62541Factory {

    // Creates an Agent, viewed as an object implementing the trait Put,
    // and hence manipulable by puffin.
    fn create(
        &self,
        application: &AgentDescriptor<ApplicationConfig>,
        claims: &GlobalClaimList<OpcuaClaim>,
        _options: &PutOptions,
    ) -> Result<Box<dyn Put<OpcuaProtocolBehavior>>, Error> {

        let id = u8::from(application.name);
        unsafe {
            let c_application_descriptor: &APPLICATION_DESCRIPTOR =
                PUT_STATE.applications.entry(id).or_insert_with( | | {
                    let descriptor =
                    match application.protocol_config.kind{
                        AgentType::Client => APPLICATION_DESCRIPTOR {
                            id,
                            role: OPCUA_AGENT_ROLE::CLIENT,
                            version: version_of(application.protocol_config.version),
                            cert: &ALICE_CERTIFICATE,
                            pkey: &ALICE_PRIVATE_KEY,
                            store: &VOID_STORE,
                            store_length: 0,
                        },
                        AgentType::Server => APPLICATION_DESCRIPTOR {
                            id,
                            role: OPCUA_AGENT_ROLE::SERVER,
                            version: version_of(application.protocol_config.version),
                            cert: &BOB_CERTIFICATE,
                            pkey: &BOB_PRIVATE_KEY,
                            store: &VOID_STORE,
                            store_length: 0,
                        }
                    };
                    //let _result = raw::open62541_start_application(&descriptor);
                    descriptor});

            if let Some(create_agent) = self.put_interface.create {
                Ok(Box::new(Agent{
                    application: application.clone(),
                    _capabilities: HashSet::new(),
                    _claims: claims.clone(),
                    fuzz_stream: MemoryStream::new(),
                    c_agent: create_agent(c_application_descriptor),
                    c_agent_interface: self.put_interface.agent_interface
                }))
            } else {
                Err(Error::Put("Open62541 Factory: create Agent unavailable!".to_string()))
            }
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
    unsafe {
        Box::new(Open62541Factory {
            put_interface: raw::open62541(),
        })
    }
}
