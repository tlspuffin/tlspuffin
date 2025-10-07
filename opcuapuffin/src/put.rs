/// This is the generic Rust interface to all OPCUA stacks with an interface in C.
use std::collections::HashSet;
use std::io::Read;

use puffin::agent::AgentDescriptor;
use puffin::claims::GlobalClaimList;
use puffin::error::Error;
use puffin::harness::{to_string, CError};
use puffin::protocol::{OpaqueProtocolMessageFlight, ProtocolBehavior};
use puffin::put::{Put, PutOptions};
use puffin::put_registry::Factory;
use puffin::stream::Stream;

use opcua::puffin::types::OpcuaDescriptorConfig;

use crate::claims::OpcuaClaim;
use crate::protocol::OpcuaProtocolBehavior;
use crate::static_certs::{ALICE_PRIVATE_KEY_AND_CERTIFICATE, BOB_PRIVATE_KEY_AND_CERTIFICATE};

/// Static configuration for creating a new agent state for the PUT
#[derive(Clone, Debug)]
pub struct OpcuaPutConfig {
    pub descriptor: AgentDescriptor<OpcuaDescriptorConfig>,
    pub claims: GlobalClaimList<OpcuaClaim>,
}

impl OpcuaPutConfig {
    pub fn new(
        agent_descriptor: &AgentDescriptor<OpcuaDescriptorConfig>,
        claims: GlobalClaimList<OpcuaClaim>,
        _options: &PutOptions
    ) -> OpcuaPutConfig {
        OpcuaPutConfig{
            descriptor: agent_descriptor.clone(),
            claims: claims.clone(),
            // extract options.
        }
    }
}





