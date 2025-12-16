use std::collections::HashSet;
use std::ffi::CStr;

use puffin::agent::{AgentDescriptor, AgentName};
use puffin::algebra::ConcreteMessage;
use puffin::claims::GlobalClaimList;
use puffin::error::Error;
use puffin::put::{Put, PutOptions};
use puffin::put_registry::Factory;
use puffin::stream::Stream;

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
#[derive(Debug)]
struct Agent {
    application: AgentDescriptor<ApplicationConfig>,
    _capabilities: HashSet<String>,
    _claims: GlobalClaimList<OpcuaClaim>,
    c_agent: AGENT,
    c_agent_interface: AGENT_INTERFACE
}

impl Agent {}

impl Stream<OpcuaProtocolBehavior> for Agent {
    fn add_to_inbound(&mut self, message: &ConcreteMessage) {
        log::error!("Add to imbound, agent: {:?}", &self);
        log::error!("Open62541 Agent: try to add {} bytes!", message.len());
        if let Some(c_add_inbound) = self.c_agent_interface.add_inbound {
            unsafe {
                let mut written: usize = 0;
                c_add_inbound(self.c_agent, message.as_ptr(), message.len(), &mut written);
                if message.len() != written {
                    log::error!("Open62541 Agent: added to inbound only {} bytes out of {}!",
                                written, message.len());
                } else {
                    log::warn!("Added a new message to the PUT of size {}", message.len());
                }}
        } else {
            log::error!("Open62541 Agent: add_inbound unavailable!")
        }
    }

    fn take_message_from_outbound(&mut self) -> Result<Option<MessageFlight>, Error> {
        if let Some(c_take_outbound) = self.c_agent_interface.take_outbound {
            Err(Error::Put("Open62541 Agent: take_outbound unavailable!".to_string()))
        } else {
            Err(Error::Put("Open62541 Agent: take_outbound unavailable!".to_string()))
        }

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
            let c_application_descriptor: APPLICATION_DESCRIPTOR =
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

            if let Some(create_agent) = self.put_interface.create {
                Ok(Box::new(Agent{
                    application: application.clone(),
                    _capabilities: HashSet::new(),
                    _claims: claims.clone(),
                    c_agent: create_agent(&c_application_descriptor),
                    c_agent_interface: self.put_interface.agent_interface
                }))
            } else {
                Err(Error::Put("Open62541 Factory: create Agent unavailable!".to_string()))
            }
        }
    }

    fn name(&self) -> String {String::from(OPEN62541)}

    fn versions(&self) -> Vec<(String, String)>{
        let put_version =
            if let Some(get_put_version) = self.put_interface.version {
                let cstr = unsafe { CStr::from_ptr(get_put_version()) };
                Some(cstr.to_string_lossy().into_owned())
            } else {
                None
            };
        let library_version = match put_version {
            Some(version) => version,
            None => "unavailable!".to_string()
        };
        vec![
            ("harness".to_string(), "0.0".to_string()),
            ("library".to_string(), library_version),
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
