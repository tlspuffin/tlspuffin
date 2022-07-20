use std::{
    any::{Any, TypeId},
    cell::{Ref, RefCell, RefMut},
    fmt::Debug,
    ops::Deref,
    rc::Rc,
    slice::Iter,
};

use itertools::Itertools;
use log::{debug, trace};

use crate::{agent::AgentName, algebra::dynamic_function::TypeShape, variable_data::VariableData};

pub trait ClaimTrait: VariableData {
    fn agent_name(&self) -> AgentName;
    fn id(&self) -> TypeShape;
}

impl Clone for Box<dyn ClaimTrait> {
    fn clone(&self) -> Self {
        todo!()
    }
}

impl ClaimTrait for Box<dyn ClaimTrait> {
    fn agent_name(&self) -> AgentName {
        self.agent_name()
    }

    fn id(&self) -> TypeShape {
        self.id()
    }
}

pub struct Policy<C: ClaimTrait> {
    pub func: fn(claims: &[C]) -> Option<&'static str>,
}

pub trait CheckViolation<C: ClaimTrait> {
    fn check_violation(&self, policy: Policy<C>) -> Option<&'static str>;
}

#[derive(Clone, Debug)]
pub struct ClaimList<C: ClaimTrait> {
    claims: Vec<C>,
}

impl<C: ClaimTrait> CheckViolation<C> for ClaimList<C> {
    fn check_violation(&self, policy: Policy<C>) -> Option<&'static str> {
        (policy.func)(&self.claims)
    }
}

impl<C: ClaimTrait> ClaimList<C> {
    pub fn iter(&self) -> Iter<'_, C> {
        self.claims.iter()
    }

    /// finds the last claim matching `type`
    pub fn find_last_claim_by_type<T: 'static>(&self, agent_name: AgentName) -> Option<&C> {
        self.find_last_claim(agent_name, TypeShape::of::<T>())
    }

    pub fn find_last_claim(&self, agent_name: AgentName, shape: TypeShape) -> Option<&C> {
        self.claims
            .iter()
            .rev()
            .find(|claim| claim.id() == shape && claim.agent_name() == agent_name)
    }

    pub fn slice(&self) -> &[C] {
        &self.claims
    }
}

impl<C: ClaimTrait> ClaimList<C> {
    pub fn log(&self) {
        debug!(
            "New Claims: {}",
            &self
                .claims
                .iter()
                .map(|claim| format!("{}", claim.type_name()))
                .join(", ")
        );
        for claim in &self.claims {
            trace!("{:?}", claim);
        }
    }
}

impl<C: ClaimTrait> From<Vec<C>> for ClaimList<C> {
    fn from(claims: Vec<C>) -> Self {
        Self { claims }
    }
}

impl<C: ClaimTrait> ClaimList<C> {
    pub fn new() -> Self {
        Self { claims: vec![] }
    }

    pub fn claim_sized(&mut self, claim: C) {
        self.claims.push(claim);
    }
}

#[derive(Clone)]
pub struct GlobalClaimList<C: ClaimTrait> {
    claims: Rc<RefCell<ClaimList<C>>>,
}

impl<C: ClaimTrait> GlobalClaimList<C> {
    pub fn new() -> Self {
        Self {
            claims: Rc::new(RefCell::new(ClaimList::new())),
        }
    }

    pub fn deref_borrow(&self) -> Ref<'_, ClaimList<C>> {
        self.claims.deref().borrow()
    }

    pub fn deref_borrow_mut(&self) -> RefMut<'_, ClaimList<C>> {
        self.claims.deref().borrow_mut()
    }
}
