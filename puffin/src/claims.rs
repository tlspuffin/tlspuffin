use std::any::TypeId;
use std::cell::{Ref, RefCell, RefMut};
use std::collections::HashMap;
use std::fmt::Debug;
use std::ops::Deref;
use std::rc::Rc;
use std::slice::{Iter, IterMut};

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

    /// Canonical projection of this claim for the protocol-agnostic
    /// claim-trajectory coverage feedback (see `DY_CLAIM_COVERAGE_FEEDBACK.md`).
    /// `Some(key)` opts this claim into coverage; `None` (default) opts out, so
    /// the feedback is inert until a protocol implements it.
    ///
    /// Implementors MUST omit per-execution-random fields (nonces, ephemeral
    /// keys, session ids, MAC tags, timestamps) and bucket unbounded counters,
    /// so two semantically-equal conversation states collapse to one key —
    /// otherwise every run is "novel" and the feedback degenerates to
    /// always-true. The induced equivalence (`a ≡ b ⇔ equal keys`) is the
    /// protocol's comparison function over claims.
    fn coverage_key(&self) -> Option<u64> {
        None
    }
}

/// Size of the synthetic claim-trajectory coverage map (power of two). Indexed
/// by hashed claim states and adjacent claim transitions.
pub const CLAIM_COVERAGE_MAP_SIZE: usize = 1 << 16;

/// Per-process claim-trajectory coverage map, mirroring the sancov edge map: an
/// `Observer` reads it post-execution and a `MaxMapFeedback` rewards novel
/// cells. Single fuzzing thread per process (Launcher forks), so a process-local
/// `static mut` is sound, exactly as for `EDGES_MAP`.
pub static mut CLAIM_COVERAGE_MAP: [u8; CLAIM_COVERAGE_MAP_SIZE] = [0; CLAIM_COVERAGE_MAP_SIZE];

#[inline]
fn claim_cov_mix(mut x: u64) -> u64 {
    // splitmix64 finalizer — spreads small/structured keys across the map.
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}

/// OR-write the claim-trajectory coverage of one execution into
/// [`CLAIM_COVERAGE_MAP`]: one cell per claim *state* and one per adjacent,
/// ordered claim *transition*. Protocol-blind — it only consumes each claim's
/// [`Claim::coverage_key`]. The map is reset by the observer's `pre_exec`, so
/// this only sets bits. Called from the executor on every run (incl. aborted
/// ones, capturing partial trajectories).
pub fn record_claim_coverage<C: Claim>(claims: &[C]) {
    let map = unsafe { &mut *core::ptr::addr_of_mut!(CLAIM_COVERAGE_MAP) };
    let mut prev: Option<u64> = None;
    for c in claims {
        let Some(k) = c.coverage_key() else {
            continue;
        };
        // Presence-only (set to 1, not increment): a DY conversation state hit
        // N times is not "more novel" than hit once. With hit-count semantics
        // the feedback retained inputs for new hit-count *buckets* of the same
        // state, inflating the corpus with noise (A/B finding); presence makes
        // retention reflect genuinely new states / transitions only.
        let s = (claim_cov_mix(k) as usize) & (CLAIM_COVERAGE_MAP_SIZE - 1);
        map[s] = 1;
        if let Some(p) = prev {
            let t = (claim_cov_mix(p.rotate_left(1) ^ claim_cov_mix(k)) as usize)
                & (CLAIM_COVERAGE_MAP_SIZE - 1);
            map[t] = 1;
        }
        prev = Some(k);
    }
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

    /// compares two claim lists and returns a list of differences
    pub fn compare(&self, other: &Self) -> Result<(), Vec<TraceDifference>> {
        let blacklist = <C::PT as ProtocolTypes>::differential_fuzzing_claims_blacklist();

        // filter out claims that are in the blacklist and group them by agent
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

        // deduplicate similar adjacent claims, keeping the order
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

        // for each agent, compare the claims of both lists and find differences in types and inner
        // values
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
