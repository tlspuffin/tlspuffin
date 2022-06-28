use std::{
    cell::{Ref, RefCell, RefMut},
    ops::Deref,
    rc::Rc,
    slice::Iter,
};

use itertools::Itertools;
use log::{debug, trace};
use security_claims::{Claim, ClaimType};

use crate::agent::AgentName;

#[derive(Clone, Debug)]
pub struct ClaimList {
    claims: Vec<(AgentName, Claim)>,
}

impl ClaimList {
    pub fn iter(&self) -> Iter<'_, (AgentName, Claim)> {
        self.claims.iter()
    }

    /// finds the last claim matching `type`
    pub fn find_last_claim(&self, typ: ClaimType) -> Option<&(AgentName, Claim)> {
        self.claims.iter().find(|(_name, claim)| claim.typ == typ)
    }

    pub fn slice(&self) -> &[(AgentName, Claim)] {
        &self.claims
    }

    pub fn log(&self) {
        debug!(
            "New Claims: {}",
            &self
                .claims
                .iter()
                .map(|(name, claim)| format!("{name}: {}", claim.typ))
                .join(", ")
        );
        for (name, claim) in &self.claims {
            trace!("{}: {}", name, claim);
        }
    }
}

impl From<Vec<(AgentName, Claim)>> for ClaimList {
    fn from(claims: Vec<(AgentName, Claim)>) -> Self {
        Self { claims }
    }
}

/// Claims filters by [`AgentName`]
pub struct ByAgentClaimList {
    claims: ClaimList,
}

impl ByAgentClaimList {
    pub fn new(claims: &ClaimList, agent_name: AgentName) -> Option<Self> {
        let filtered = claims
            .iter()
            .filter(|(name, _claim)| agent_name == *name)
            .cloned()
            .rev()
            .collect::<Vec<_>>();
        if filtered.is_empty() {
            None
        } else {
            Some(Self {
                claims: filtered.into(),
            })
        }
    }

    /// finds the last claim matching `type`
    pub fn find_last_claim(&self, typ: ClaimType) -> Option<&(AgentName, Claim)> {
        self.claims.iter().find(|(_name, claim)| claim.typ == typ)
    }
}

impl ClaimList {
    pub fn new() -> Self {
        Self { claims: vec![] }
    }

    pub fn claim(&mut self, name: AgentName, claim: Claim) {
        self.claims.push((name, claim));
    }
}

#[derive(Clone)]
pub struct GlobalClaimList {
    claims: Rc<RefCell<ClaimList>>,
}

impl GlobalClaimList {
    pub fn new() -> Self {
        Self {
            claims: Rc::new(RefCell::new(ClaimList::new())),
        }
    }

    pub fn deref_borrow(&self) -> Ref<'_, ClaimList> {
        self.claims.deref().borrow()
    }

    pub fn deref_borrow_mut(&self) -> RefMut<'_, ClaimList> {
        self.claims.deref().borrow_mut()
    }
}
