use std::borrow::Cow;
use std::collections::HashSet;

use libafl::executors::ExitKind;
use libafl::feedbacks::{Feedback, StateInitializer};
use libafl_bolts::prelude::MatchName;
use libafl_bolts::tuples::*;
use libafl_bolts::{Error, Named};

use crate::fuzzer::feedback::term_observer::TermObserver;
/// Feedback that monitors structural or symbolic terms extracted from the protocol
pub struct TermFeedback {
    /// Persistent global memory storing all DY terms discovered
    global_knowledge_memory: HashSet<String>,
    observer_handle: Handle<TermObserver>,
    name: Cow<'static, str>,
}

impl<S> StateInitializer<S> for TermFeedback {}

impl TermFeedback {
    /// Creates a new [`TermFeedback`] associated with the given [`TermObserver`].
    pub fn new(observer: &TermObserver) -> Self {
        Self {
            global_knowledge_memory: HashSet::new(),
            observer_handle: observer.handle(),
            name: Cow::Borrowed("term_feedback"),
        }
    }
}

impl Named for TermFeedback {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<EM, I, OT, S> Feedback<EM, I, OT, S> for TermFeedback
where
    OT: MatchName,
{
    fn is_interesting(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _input: &I,
        observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error> {
        let Some(observer) = observers.get(&self.observer_handle) else {
            return Err(Error::illegal_state(
                "Observer referenced by TermFeedback is not found in observers given to the fuzzer",
            ));
        };
        let mut found_new_term = false;

        for term_signature in &observer.discovered_terms {
            if !self.global_knowledge_memory.contains(term_signature) {
                log::debug!("New term found: {}", term_signature);
                // Add discovered term to the global knowledge
                self.global_knowledge_memory.insert(term_signature.clone());
                found_new_term = true;
            }
        }
        Ok(found_new_term)
    }
}
