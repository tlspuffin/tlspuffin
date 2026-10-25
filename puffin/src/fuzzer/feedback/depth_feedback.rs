use std::borrow::Cow;
use std::collections::HashMap;

use libafl::executors::ExitKind;
use libafl::feedbacks::{Feedback, StateInitializer};
use libafl_bolts::prelude::MatchName;
use libafl_bolts::tuples::*;
use libafl_bolts::{Error, Named};
use serde::{Deserialize, Serialize};

use crate::fuzzer::feedback::term_observer::TermObserver;

#[derive(Serialize, Deserialize, Debug, Clone)]
/// Feedback that tracks the maximal syntactic depth of symbolic terms.
pub struct DepthFeedback {
    observer_handle: Handle<TermObserver>,
    /// Highest term tree depth achieved across all past fuzzing generations.
    pub max_depth_by_context: HashMap<String, usize>,
    name: Cow<'static, str>,
}

impl<S> StateInitializer<S> for DepthFeedback {}

impl DepthFeedback {
    /// Creates a new [`DepthFeedback`] tied to the provided [`TermObserver`].
    pub fn new(observer: &TermObserver) -> Self {
        Self {
            observer_handle: observer.handle(),
            max_depth_by_context: HashMap::new(),
            name: Cow::Borrowed("depth_feedback"),
        }
    }
}

impl Named for DepthFeedback {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<EM, I, OT, S> Feedback<EM, I, OT, S> for DepthFeedback
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
                "Observer referenced by DepthFeedback is not found in observers given to the fuzzer",
            ));
        };
        let mut is_interesting = false;
        // Check if we reach new depth for this message type
        for (context, depth) in &observer.terms_with_depths {
            let current_max = self
                .max_depth_by_context
                .entry(context.clone())
                .or_insert(0);
            if *depth > *current_max {
                *current_max = *depth;
                is_interesting = true;
            }
        }

        Ok(is_interesting)
    }
}
