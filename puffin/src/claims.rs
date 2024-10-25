use std::cell::{Ref, RefCell, RefMut};
use std::fmt::Debug;
use std::marker::PhantomData;
use std::ops::Deref;
use std::rc::Rc;
use std::slice::Iter;

use itertools::Itertools;

use crate::agent::AgentName;
use crate::algebra::dynamic_function::TypeShape;
use crate::protocol::{EvaluatedTerm, ProtocolTypes};
use crate::variable_data::VariableData;

pub trait Claim<PT: ProtocolTypes>: EvaluatedTerm<PT> + VariableData<PT> + Debug {
    fn agent_name(&self) -> AgentName;
    fn id(&self) -> TypeShape<PT>;
    fn inner(&self) -> Box<dyn EvaluatedTerm<PT>>;
}

pub trait SecurityViolationPolicy<PT: ProtocolTypes, C: Claim<PT>> {
    fn check_violation(claims: &[C]) -> Option<&'static str>;
}

#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub struct ClaimList<PT: ProtocolTypes, C: Claim<PT>> {
    claims: Vec<C>,
    phantom: PhantomData<PT>,
}

impl<PT: ProtocolTypes, C: Claim<PT>> ClaimList<PT, C> {
    pub fn iter(&self) -> Iter<'_, C> {
        self.claims.iter()
    }

    /// finds the last claim matching `type`
    #[must_use]
    pub fn find_last_claim_by_type<T: 'static>(&self, agent_name: AgentName) -> Option<&C> {
        self.find_last_claim(agent_name, TypeShape::<PT>::of::<T>())
    }

    #[must_use]
    pub fn find_last_claim(&self, agent_name: AgentName, shape: TypeShape<PT>) -> Option<&C> {
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

impl<PT: ProtocolTypes, C: Claim<PT>> ClaimList<PT, C> {
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

impl<PT: ProtocolTypes, C: Claim<PT>> From<Vec<C>> for ClaimList<PT, C> {
    fn from(claims: Vec<C>) -> Self {
        Self {
            claims,
            phantom: PhantomData,
        }
    }
}

impl<PT: ProtocolTypes, C: Claim<PT>> ClaimList<PT, C> {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            claims: vec![],
            phantom: PhantomData,
        }
    }

    pub fn claim_sized(&mut self, claim: C) {
        self.claims.push(claim);
    }
}

#[derive(Default, Clone, PartialEq, Eq, Debug)]
pub struct GlobalClaimList<PT: ProtocolTypes, C: Claim<PT>> {
    claims: Rc<RefCell<ClaimList<PT, C>>>,
}

impl<PT: ProtocolTypes, C: Claim<PT>> GlobalClaimList<PT, C> {
    #[must_use]
    pub fn new() -> Self {
        Self {
            claims: Rc::new(RefCell::new(ClaimList::new())),
        }
    }

    #[must_use]
    pub fn deref_borrow(&self) -> Ref<'_, ClaimList<PT, C>> {
        self.claims.deref().borrow()
    }

    #[must_use]
    pub fn deref_borrow_mut(&self) -> RefMut<'_, ClaimList<PT, C>> {
        self.claims.deref().borrow_mut()
    }
}
