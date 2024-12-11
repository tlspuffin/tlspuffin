use std::cell::{Ref, RefCell, RefMut};
use std::fmt::Debug;
use std::ops::Deref;
use std::rc::Rc;
use std::slice::Iter;

use itertools::Itertools;

use crate::agent::AgentName;
use crate::algebra::dynamic_function::TypeShape;
use crate::protocol::{EvaluatedTerm, ProtocolTypes};

pub trait Claim: EvaluatedTerm<Self::PT> + Debug {
    type PT: ProtocolTypes;

    fn agent_name(&self) -> AgentName;
    fn id(&self) -> TypeShape<Self::PT>;
    fn inner(&self) -> Box<dyn EvaluatedTerm<Self::PT>>;
}

pub trait SecurityViolationPolicy {
    type C: Claim;

    fn check_violation(claims: &[Self::C]) -> Option<&'static str>;
}

#[derive(Default, Clone, Debug, PartialEq)]
pub struct ClaimList<C: Claim> {
    claims: Vec<C>,
}

impl<C: Claim> ClaimList<C> {
    pub fn iter(&self) -> Iter<'_, C> {
        self.claims.iter()
    }

    /// finds the last claim matching `type`
    #[must_use]
    pub fn find_last_claim_by_type<T: 'static>(&self, agent_name: AgentName) -> Option<&C> {
        self.find_last_claim(agent_name, TypeShape::<C::PT>::of::<T>())
    }

    #[must_use]
    pub fn find_last_claim(&self, agent_name: AgentName, shape: TypeShape<C::PT>) -> Option<&C> {
        self.claims
            .iter()
            .rev()
            .find(|claim| claim.id() == shape && claim.agent_name() == agent_name)
    }

    #[must_use]
    pub fn slice(&self) -> &[C] {
        &self.claims
    }
}

impl<C: Claim> ClaimList<C> {
    pub fn log(&self) {
        // TODO: skip logging completely during fuzzing -> more performance
        log::debug!(
            "New Claims: {}",
            &self
                .claims
                .iter()
                .map(|claim| claim.type_name().to_string())
                .join(", ")
        );
        for claim in &self.claims {
            log::trace!("{:?}", claim);
        }
    }
}

impl<C: Claim> From<Vec<C>> for ClaimList<C> {
    fn from(claims: Vec<C>) -> Self {
        Self { claims }
    }
}

impl<C: Claim> ClaimList<C> {
    #[must_use]
    pub const fn new() -> Self {
        Self { claims: vec![] }
    }

    pub fn claim_sized(&mut self, claim: C) {
        self.claims.push(claim);
    }
}

#[derive(Default, Clone, PartialEq, Debug)]
pub struct GlobalClaimList<C: Claim> {
    claims: Rc<RefCell<ClaimList<C>>>,
}

impl<C: Claim> GlobalClaimList<C> {
    #[must_use]
    pub fn new() -> Self {
        Self {
            claims: Rc::new(RefCell::new(ClaimList::new())),
        }
    }

    #[must_use]
    pub fn deref_borrow(&self) -> Ref<'_, ClaimList<C>> {
        self.claims.deref().borrow()
    }

    #[must_use]
    pub fn deref_borrow_mut(&self) -> RefMut<'_, ClaimList<C>> {
        self.claims.deref().borrow_mut()
    }
}
