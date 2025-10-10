/// This is the generic Rust interface to all OPCUA stacks with an interface in C.

use puffin::agent::AgentDescriptor;
use puffin::claims::GlobalClaimList;
use puffin::put::PutOptions;

use opcua::puffin::types::OpcuaDescriptorConfig;

use crate::claims::OpcuaClaim;

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





