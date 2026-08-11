//! What the executions put in the knowledge store, so that mutators can draw queries that have a
//! chance of being answered instead of guessing a source, a matcher and a counter.
//!
//! The pool is a thread-local hint, written by the executions of a fuzzing client and read by its
//! mutators: it is not part of the corpus, and a stale or empty pool only costs mutations.

use std::any::{Any, TypeId};
use std::cell::RefCell;
use std::collections::HashMap;

use libafl::corpus::CorpusId;
use libafl::schedulers::Scheduler;
use libafl_bolts::tuples::MatchName;
use libafl_bolts::Error;

use crate::protocol::ProtocolTypes;
use crate::trace::Source;

/// A `(source, matcher)` combination under which knowledge of some type was observed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation<PT: ProtocolTypes> {
    pub source: Source,
    pub matcher: Option<PT::Matcher>,
    /// Largest `counter` (exclusive) a query may use and still be answered.
    pub multiplicity: u16,
    /// First step whose recipe can read this knowledge, i.e. one past the step that produced it;
    /// `0` for a prior trace or a precomputation. A query placed earlier reads an empty store.
    pub available_from: usize,
}

/// The knowledge combinations observed so far, indexed by the type of the knowledge.
#[derive(Debug)]
pub struct ObservedKnowledge<PT: ProtocolTypes> {
    by_type: HashMap<TypeId, Vec<Observation<PT>>>,
}

impl<PT: ProtocolTypes> Default for ObservedKnowledge<PT> {
    fn default() -> Self {
        Self::new()
    }
}

impl<PT: ProtocolTypes> ObservedKnowledge<PT> {
    #[must_use]
    pub fn new() -> Self {
        Self {
            by_type: HashMap::new(),
        }
    }

    /// Merges in the knowledge of a *single* execution, one item per value it holds.
    ///
    /// Both fields are merged with a maximum across executions: a counter is bounded by what one
    /// execution offers at once, and the latest step the knowledge was seen to appear at is the
    /// one a query is sure to be after. Matchers are only `PartialEq`, hence the linear lookup.
    pub fn record(
        &mut self,
        observations: impl Iterator<Item = (TypeId, Source, Option<PT::Matcher>, usize)>,
    ) {
        let mut execution: HashMap<TypeId, Vec<Observation<PT>>> = HashMap::new();
        for (typ, source, matcher, available_from) in observations {
            let entries = execution.entry(typ).or_default();
            match entries
                .iter_mut()
                .find(|entry| entry.source == source && entry.matcher == matcher)
            {
                Some(entry) => {
                    entry.multiplicity = entry.multiplicity.saturating_add(1);
                    entry.available_from = entry.available_from.min(available_from);
                }
                None => entries.push(Observation {
                    source,
                    matcher,
                    multiplicity: 1,
                    available_from,
                }),
            }
        }

        for (typ, observations) in execution {
            let entries = self.by_type.entry(typ).or_default();
            for observation in observations {
                match entries.iter_mut().find(|entry| {
                    entry.source == observation.source && entry.matcher == observation.matcher
                }) {
                    Some(entry) => {
                        entry.multiplicity = entry.multiplicity.max(observation.multiplicity);
                        entry.available_from = entry.available_from.max(observation.available_from);
                    }
                    None => entries.push(observation),
                }
            }
        }
    }

    /// The combinations under which knowledge of type `typ` was observed, if any ever was.
    #[must_use]
    pub fn observations(&self, typ: TypeId) -> Option<&[Observation<PT>]> {
        self.by_type.get(&typ).map(Vec::as_slice)
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_type.is_empty()
    }
}

/// The pools of a fuzzing client: what every execution taught (`union`), what the execution of
/// each corpus entry taught (`by_corpus`), and what the last execution taught but has not been
/// attributed yet (`staging`, committed by [`Pools::commit`] once the corpus id is known).
#[derive(Debug)]
pub struct Pools<PT: ProtocolTypes> {
    union: ObservedKnowledge<PT>,
    by_corpus: HashMap<CorpusId, ObservedKnowledge<PT>>,
    staging: ObservedKnowledge<PT>,
}

impl<PT: ProtocolTypes> Pools<PT> {
    #[must_use]
    pub fn new() -> Self {
        Self {
            union: ObservedKnowledge::new(),
            by_corpus: HashMap::new(),
            staging: ObservedKnowledge::new(),
        }
    }

    /// Records the knowledge of one execution, into the union and into the staging pool.
    pub fn record(
        &mut self,
        observations: impl Iterator<Item = (TypeId, Source, Option<PT::Matcher>, usize)>,
    ) {
        let observations: Vec<_> = observations.collect();
        self.union.record(observations.iter().cloned());
        self.staging = ObservedKnowledge::new();
        self.staging.record(observations.into_iter());
    }

    /// Attributes the staged knowledge to the corpus entry the executed input became, if any.
    ///
    /// An entry added without an execution of its own — a seed loaded from disk — is left without
    /// a pool rather than given an empty one, so that it keeps falling back to the union.
    pub fn commit(&mut self, id: Option<CorpusId>) {
        let staged = std::mem::replace(&mut self.staging, ObservedKnowledge::new());
        if let (Some(id), false) = (id, staged.is_empty()) {
            self.by_corpus.insert(id, staged);
        }
    }

    /// What `id`'s own execution taught. Entries with no pool of their own — the seeds, which
    /// never went through a mutation, and the evicted ones — fall back to the union pool; an entry
    /// that *has* one does not, or it would borrow the knowledge of other traces for every type it
    /// happens not to produce.
    #[must_use]
    pub fn observations(&self, id: Option<CorpusId>, typ: TypeId) -> Option<&[Observation<PT>]> {
        match id.and_then(|id| self.by_corpus.get(&id)) {
            Some(observed) => observed.observations(typ),
            None => self.union.observations(typ),
        }
    }
}

impl<PT: ProtocolTypes> Default for Pools<PT> {
    fn default() -> Self {
        Self::new()
    }
}

thread_local! {
    /// Type-erased, because the pools are reached from contexts that do not carry `PT`.
    static OBSERVED: RefCell<Option<Box<dyn Any>>> = const { RefCell::new(None) };
}

/// Runs `f` on this thread's pools, creating empty ones on first use. A binary fuzzes a single
/// protocol, so pools of another `PT` are replaced rather than misread.
pub fn with_observed_knowledge<PT: ProtocolTypes, R>(f: impl FnOnce(&mut Pools<PT>) -> R) -> R {
    OBSERVED.with(|cell| {
        let mut slot = cell.borrow_mut();
        if !slot.as_ref().is_some_and(|pool| pool.is::<Pools<PT>>()) {
            *slot = Some(Box::new(Pools::<PT>::new()));
        }
        f(slot
            .as_mut()
            .and_then(|pool| pool.downcast_mut::<Pools<PT>>())
            .expect("the pools were just made to hold a Pools<PT>"))
    })
}

/// Empties this thread's pools. Only useful to keep tests independent.
pub fn clear_observed_knowledge<PT: ProtocolTypes>() {
    with_observed_knowledge::<PT, _>(|pools| *pools = Pools::new());
}

/// Attributes the knowledge of the execution that just happened to the corpus entry it produced:
/// `on_add` is the first moment its [`CorpusId`] is known.
#[derive(Debug)]
pub struct AttributingScheduler<PT: ProtocolTypes, SCH> {
    inner: SCH,
    phantom: std::marker::PhantomData<PT>,
}

impl<PT: ProtocolTypes, SCH> AttributingScheduler<PT, SCH> {
    pub fn new(inner: SCH) -> Self {
        Self {
            inner,
            phantom: std::marker::PhantomData,
        }
    }
}

impl<PT: ProtocolTypes, SCH, I, S> Scheduler<I, S> for AttributingScheduler<PT, SCH>
where
    SCH: Scheduler<I, S>,
{
    fn on_add(&mut self, state: &mut S, id: CorpusId) -> Result<(), Error> {
        with_observed_knowledge::<PT, _>(|pools| pools.commit(Some(id)));
        self.inner.on_add(state, id)
    }

    fn on_evaluation<OT>(&mut self, state: &mut S, input: &I, observers: &OT) -> Result<(), Error>
    where
        OT: MatchName,
    {
        self.inner.on_evaluation(state, input, observers)
    }

    fn next(&mut self, state: &mut S) -> Result<CorpusId, Error> {
        self.inner.next(state)
    }

    fn set_current_scheduled(
        &mut self,
        state: &mut S,
        next_id: Option<CorpusId>,
    ) -> Result<(), Error> {
        self.inner.set_current_scheduled(state, next_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::AgentName;
    use crate::algebra::test_signature::TestProtocolTypes;
    use crate::algebra::AnyMatcher;

    fn observation(
        typ: TypeId,
        available_from: usize,
    ) -> (TypeId, Source, Option<AnyMatcher>, usize) {
        (typ, Source::Agent(AgentName::first()), None, available_from)
    }

    /// What an entry's own execution taught is kept apart from what the others did, and an entry
    /// that never went through a mutation still sees the union.
    #[test_log::test]
    fn pools_attribute_knowledge_to_the_entry_that_produced_it() {
        let mine = TypeId::of::<u8>();
        let others = TypeId::of::<u16>();
        let id = CorpusId::from(7_usize);

        let mut pools = Pools::<TestProtocolTypes>::new();
        pools.record([observation(others, 1)].into_iter());
        pools.commit(Some(CorpusId::from(1_usize)));
        pools.record([observation(mine, 2)].into_iter());
        pools.commit(Some(id));

        assert!(pools.observations(Some(id), mine).is_some());
        assert!(
            pools.observations(Some(id), others).is_none(),
            "the entry never produced that type, another one did"
        );
        assert!(
            pools.observations(None, others).is_some(),
            "without an entry the union answers"
        );
    }

    /// Knowledge staged by an execution that was not kept belongs to no entry.
    #[test_log::test]
    fn pools_drop_the_knowledge_of_a_discarded_execution() {
        let typ = TypeId::of::<u8>();
        let mut pools = Pools::<TestProtocolTypes>::new();
        pools.record([observation(typ, 0)].into_iter());
        pools.commit(None);
        pools.commit(Some(CorpusId::from(1_usize)));

        assert!(
            !pools.by_corpus.contains_key(&CorpusId::from(1_usize)),
            "an entry with nothing of its own is left to the union"
        );
        assert!(pools
            .observations(Some(CorpusId::from(1_usize)), typ)
            .is_some());
    }
}
