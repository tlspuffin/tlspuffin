use std::{
    any::Any,
    cell::{Ref, RefCell, RefMut},
    fmt::Debug,
    ops::Deref,
    rc::Rc,
    slice::Iter,
};

use itertools::Itertools;
use log::{debug, trace};

use crate::{agent::AgentName, algebra::dynamic_function::TypeShape, variable_data::VariableData};

pub trait Claim: VariableData {
    fn agent_name(&self) -> AgentName;
    fn id(&self) -> TypeShape;
    fn inner(&self) -> Box<dyn Any>;
}

pub trait SecurityViolationPolicy<C: Claim> {
    fn check_violation(claims: &[C]) -> Option<&'static str>;
}

#[derive(Clone, Debug)]
pub struct ClaimList<C: Claim> {
    claims: Vec<C>,
}

impl<C: Claim> ClaimList<C> {
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

impl<C: Claim> ClaimList<C> {
    pub fn log(&self) {
        // TODO: skip logging completely during fuzzing -> more performance
        debug!(
            "New Claims: {}",
            &self
                .claims
                .iter()
                .map(|claim| claim.type_name().to_string())
                .join(", ")
        );
        for claim in &self.claims {
            trace!("{:?}", claim);
        }
    }
}

impl<C: Claim> From<Vec<C>> for ClaimList<C> {
    fn from(claims: Vec<C>) -> Self {
        Self { claims }
    }
}

impl<C: Claim> ClaimList<C> {
    pub fn new() -> Self {
        Self { claims: vec![] }
    }

    pub fn claim_sized(&mut self, claim: C) {
        self.claims.push(claim);
    }
}

#[derive(Clone)]
pub struct GlobalClaimList<C: Claim> {
    claims: Rc<RefCell<ClaimList<C>>>,
}

impl<C: Claim> GlobalClaimList<C> {
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
