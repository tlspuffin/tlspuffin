use std::cell::RefCell;
use std::rc::Rc;

use puffin::agent::AgentDescriptor;
use puffin::algebra::dynamic_function::TypeShape;
use puffin::claims::GlobalClaimList;

use crate::claims::TlsClaim;

/// Static configuration for creating a new agent state for the PUT
#[derive(Clone)]
pub struct TlsPutConfig {
    pub descriptor: AgentDescriptor,
    pub claims: GlobalClaimList<TlsClaim>,
    pub authenticate_peer: bool,
    pub extract_deferred: Rc<RefCell<Option<TypeShape>>>,
    pub use_clear: bool,
}
