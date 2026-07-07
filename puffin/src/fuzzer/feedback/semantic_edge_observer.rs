use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::HashSet;

use libafl::common::HasMetadata;
use libafl::executors::ExitKind;
use libafl::observers::Observer;
use libafl_bolts::{Error, Named};
use serde::{Deserialize, Serialize};
use crate::fuzzer::stats_stage::EDGE_COVERED;
use libafl::SerdeAny;

thread_local! {
    // Keep pairs (ID_edge, term) discovered during trace execution
    pub static CAPTURED_SEMANTIC_EDGES: RefCell<Vec<(u32, String)>> = RefCell::new(Vec::new());
}
#[derive(Debug, Serialize, Deserialize, SerdeAny)]
pub struct GlobalEdgeHistoryMetadata {
    pub seen_edges: HashSet<u32>,
}

impl GlobalEdgeHistoryMetadata {
    pub fn new() -> Self {
        Self {
            seen_edges: HashSet::new(),
        }
    }
}
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SemanticEdgeObserver {
    name: Cow<'static, str>,
    pub semantic_edges: Vec<(u32, String)>,
}

impl SemanticEdgeObserver {
    pub fn new(name: &'static str) -> Self {
        Self {
            name: Cow::Borrowed(name),
            semantic_edges: Vec::new(),
        }
    }
}

impl<I, S> Observer<I, S> for SemanticEdgeObserver where
    S: HasMetadata,
    {
    fn pre_exec(&mut self, state: &mut S, _input: &I) -> Result<(), Error> {
        self.semantic_edges.clear();
        CAPTURED_SEMANTIC_EDGES.with(|s| s.borrow_mut().clear());
        Ok(())
    }

    fn post_exec(
        &mut self,
        state: &mut S,
        _input: &I,
        _exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        CAPTURED_SEMANTIC_EDGES.with(|s| {
            self.semantic_edges = s.borrow().clone();
        });
        let metadata = state.metadata_or_insert_with::<GlobalEdgeHistoryMetadata>(GlobalEdgeHistoryMetadata::new);

        for &(edge, _) in &self.semantic_edges {
            if metadata.seen_edges.insert(edge) {
                EDGE_COVERED.increment();
            }
        }
        Ok(())
    }
}

impl Named for SemanticEdgeObserver {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}
