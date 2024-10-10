use std::cell::RefCell;
use std::rc::Rc;

use puffin::agent::{AgentDescriptor, AgentType};
use puffin::algebra::dynamic_function::TypeShape;
use puffin::claims::GlobalClaimList;
use puffin::protocol::ProtocolBehavior;
use puffin::put::PutOptions;

use crate::claims::TlsClaim;
use crate::protocol::{TLSProtocolBehavior, TLSProtocolTypes};

/// Static configuration for creating a new agent state for the PUT
#[derive(Clone)]
pub struct TlsPutConfig {
    pub descriptor: AgentDescriptor,
    pub claims: GlobalClaimList<TLSProtocolTypes, TlsClaim>,
    pub authenticate_peer: bool,
    pub extract_deferred: Rc<RefCell<Option<TypeShape<TLSProtocolTypes>>>>,
    pub use_clear: bool,
}

impl TlsPutConfig {
    pub fn new(
        agent_descriptor: &AgentDescriptor,
        claims: &GlobalClaimList<
            TLSProtocolTypes,
            <TLSProtocolBehavior as ProtocolBehavior>::Claim,
        >,
        options: &PutOptions,
    ) -> TlsPutConfig {
        let use_clear = options
            .get_option("use_clear")
            .map(|value| value.parse().unwrap_or(false))
            .unwrap_or(false);

        TlsPutConfig {
            descriptor: agent_descriptor.clone(),
            claims: claims.clone(),
            authenticate_peer: agent_descriptor.typ == AgentType::Client
                && agent_descriptor.server_authentication
                || agent_descriptor.typ == AgentType::Server
                    && agent_descriptor.client_authentication,
            extract_deferred: Rc::new(RefCell::new(None)),
            use_clear,
        }
    }
}
