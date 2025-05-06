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
use crate::differential::{ClaimDiff, TraceDifference};
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

        let mut self_claims_filtered: HashMap<AgentName, Vec<&C>> = self
            .claims
            .iter()
            .filter(|x| filter_claims(*x, &blacklist))
            .fold(HashMap::new(), |mut acc, c| {
                acc.entry(c.agent_name()).or_insert(vec![]).push(c);
                acc
            });

        let mut other_claims_filtered: HashMap<AgentName, Vec<&C>> = other
            .claims
            .iter()
            .filter(|x| filter_claims(*x, &blacklist))
            .fold(HashMap::new(), |mut acc, c| {
                acc.entry(c.agent_name()).or_insert(vec![]).push(c);
                acc
            });

        self_claims_filtered.iter_mut().for_each(|(_, v)| {
            v.dedup_by(|x, y| x.comparison(y) == comparable::Changed::Unchanged)
        });

        other_claims_filtered.iter_mut().for_each(|(_, v)| {
            v.dedup_by(|x, y| x.comparison(y) == comparable::Changed::Unchanged)
        });

        log::trace!("Comparing claim lists");

        let mut keys: Vec<_> = self_claims_filtered
            .keys()
            .into_iter()
            .chain(other_claims_filtered.keys().into_iter())
            .collect();
        keys.sort();

        let mut diffs = vec![];

        for k in keys.iter().dedup() {
            let empty = vec![];
            let s = self_claims_filtered.get(k).unwrap_or(&empty);
            let o = other_claims_filtered.get(k).unwrap_or(&empty);

            for i in 0..usize::max(s.len(), o.len()) {
                match (s.get(i), o.get(i)) {
                    (None, Some(b)) => {
                        diffs.push(TraceDifference::Claims(ClaimDiff::DifferentTypes {
                            agent: b.agent_name().into(),
                            index: i,
                            first_type: "()".into(),
                            second_type: b.inner().type_name().into(),
                        }))
                    }
                    (Some(a), None) => {
                        diffs.push(TraceDifference::Claims(ClaimDiff::DifferentTypes {
                            agent: a.agent_name().into(),
                            index: i,
                            first_type: a.inner().type_name().into(),
                            second_type: "()".into(),
                        }))
                    }
                    (Some(a), Some(b)) => match a.comparison(b) {
                        comparable::Changed::Changed(changes) => {
                            diffs.push(TraceDifference::Claims(ClaimDiff::InnerDifference {
                                agent: a.agent_name().into(),
                                index: i,
                                diff: format!("{:?}", changes),
                            }))
                        }
                        comparable::Changed::Unchanged => (),
                    },
                    _ => (),
                }
            }
        }

        if diffs.len() > 0 {
            Err(diffs)
        } else {
            Ok(())
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
