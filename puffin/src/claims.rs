use std::any::TypeId;
use std::cell::{Ref, RefCell, RefMut};
use std::collections::HashMap;
use std::fmt::Debug;
use std::ops::Deref;
use std::rc::Rc;
use std::slice::{Iter, IterMut};

use anyhow::Result;
use comparable::Comparable;
use itertools::Itertools;

use crate::agent::AgentName;
use crate::algebra::dynamic_function::TypeShape;
use crate::differential::TraceDifference;
use crate::protocol::{EvaluatedTerm, ProtocolTypes};
use crate::trace::StepNumber;

pub trait Claim: EvaluatedTerm<Self::PT> + Debug + Comparable + PartialEq {
    type PT: ProtocolTypes;

    fn agent_name(&self) -> AgentName;
    fn id(&self) -> TypeShape<Self::PT>;
    fn inner(&self) -> Box<dyn EvaluatedTerm<Self::PT>>;
    fn set_step(&mut self, step: Option<StepNumber>);
    fn get_step(&self) -> Option<StepNumber>;
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

    pub fn iter_mut(&mut self) -> IterMut<'_, C> {
        self.claims.iter_mut()
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

fn filter_claims<C: Claim>(claim: &C, blacklist: &Option<Vec<TypeId>>) -> bool {
    if let Some(b) = blacklist {
        if b.iter().any(|x| *x == claim.id().into()) {
            return false;
        }
    }

    true
}

impl<C: Claim> ClaimList<C> {
    #[must_use]
    pub const fn new() -> Self {
        Self { claims: vec![] }
    }

    pub fn claim_sized(&mut self, mut claim: C) {
        claim.set_step(None);
        self.claims.push(claim);
    }

    pub fn compare(&self, other: &Self) -> Result<(), Vec<TraceDifference>> {
        let blacklist = <C::PT as ProtocolTypes>::differential_fuzzing_claims_blacklist();

        let mut self_claims_filtered = HashMap::<AgentName, Vec<&C>>::new();
        self.claims
            .iter()
            .filter(|x| filter_claims(*x, &blacklist))
            .map(|c| {
                self_claims_filtered
                    .entry(c.agent_name())
                    .or_insert(vec![])
                    .push(c)
            })
            .count();

        let mut other_claims_filtered = HashMap::<AgentName, Vec<&C>>::new();
        other
            .claims
            .iter()
            .filter(|x| filter_claims(*x, &blacklist))
            .map(|c| {
                other_claims_filtered
                    .entry(c.agent_name())
                    .or_insert(vec![])
                    .push(c)
            })
            .count();

        self_claims_filtered = self_claims_filtered
            .into_iter()
            .map(|(k, v)| {
                (
                    k,
                    v.into_iter()
                        .dedup_by(|x, y| x.comparison(y) == comparable::Changed::Unchanged)
                        .collect(),
                )
            })
            .collect();

        other_claims_filtered = other_claims_filtered
            .into_iter()
            .map(|(k, v)| {
                (
                    k,
                    v.into_iter()
                        .dedup_by(|x, y| x.comparison(y) == comparable::Changed::Unchanged)
                        .collect(),
                )
            })
            .collect();

        let diffs = self_claims_filtered.comparison(&other_claims_filtered);
        match diffs {
            comparable::Changed::Unchanged => Ok(()),
            comparable::Changed::Changed(changes) => {
                Err(vec![TraceDifference::Claims(format!("{:#?}", changes))])
            }
        }
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

    pub fn compare(&self, other: &Self) -> Result<(), Vec<TraceDifference>> {
        self.claims.borrow().compare(&other.claims.borrow())
    }
}
