use std::borrow::Cow;
use std::collections::{HashMap, HashSet};

use libafl::common::HasMetadata;
use libafl::executors::ExitKind;
use libafl::feedbacks::{Feedback, StateInitializer};
use libafl::SerdeAny;
use libafl_bolts::prelude::MatchName;
use libafl_bolts::tuples::*;
use libafl_bolts::{Error, Named};
use serde::{Deserialize, Serialize};

use crate::fuzzer::feedback::semantic_edge_observer::SemanticEdgeObserver;
#[derive(Debug, Serialize, Deserialize, SerdeAny)]
pub struct SemanticEdgeMetadata {
    // key: edge_id, value: list of terms that reached this edge
    pub global_edges_terms: HashMap<u32, HashSet<String>>,
}

impl SemanticEdgeMetadata {
    pub fn new() -> Self {
        Self {
            global_edges_terms: HashMap::new(),
        }
    }
}

pub struct SemanticEdgeFeedback {
    observer_handle: Handle<SemanticEdgeObserver>,
}
// initialise hashmap with (edge, term) pairs from seeds
impl<S> StateInitializer<S> for SemanticEdgeFeedback
where
    S: HasMetadata,
{
    fn init_state(&mut self, state: &mut S) -> Result<(), Error> {
        if !state.has_metadata::<SemanticEdgeMetadata>() {
            state.add_metadata(SemanticEdgeMetadata::new());
        }
        Ok(())
    }
}
impl SemanticEdgeFeedback {
    /// Creates a new [`SemanticEdgeFeedback`] tied to the provided [`SemanticEdgeObserver`].
    pub fn new(observer: &SemanticEdgeObserver) -> Self {
        Self {
            observer_handle: observer.handle(),
        }
    }
}

impl Named for SemanticEdgeFeedback {
    fn name(&self) -> &Cow<'static, str> {
        self.observer_handle.name()
    }
}

impl<EM, I, OT, S> Feedback<EM, I, OT, S> for SemanticEdgeFeedback
where
    OT: MatchName,
    S: HasMetadata,
{
    fn is_interesting(
        &mut self,
        state: &mut S,
        _manager: &mut EM,
        _input: &I,
        observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error> {
        let Some(observer) = observers.get(&self.observer_handle) else {
            return Err(Error::illegal_state(
                "Observer referenced by SemanticEdgeFeedback is not found in observers given to the fuzzer",
            ));
        };
        let metadata = state
            .metadata_mut::<SemanticEdgeMetadata>()
            .map_err(|_| Error::illegal_state("SemanticEdgeMetadata missing in State"))?;

        let mut is_interesting = false;

        for (edge, term) in &observer.semantic_edges {
            let entry = metadata
                .global_edges_terms
                .entry(*edge)
                .or_insert_with(HashSet::new);
            // if we can add the couple to the hashmap, it is a new one
            if entry.insert(term.clone()) {
                log::debug!("New semantic edge cover found: {}{}",edge, term);
                is_interesting = true;
            }
        }
        Ok(is_interesting)
    }
}
