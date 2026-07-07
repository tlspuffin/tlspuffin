use std::borrow::Cow;

use libafl::executors::ExitKind;
use libafl::feedbacks::{Feedback, StateInitializer};
use libafl_bolts::prelude::MatchName;
use libafl_bolts::tuples::*;
use libafl_bolts::{Error, Named};
use serde::{Deserialize, Serialize};

use crate::fuzzer::feedback::term_observer::TermObserver;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DepthFeedback {
    observer_handle: Handle<TermObserver>,
    pub max_history_depth: usize,
    name: Cow<'static, str>,
}

impl<S> StateInitializer<S> for DepthFeedback {}

impl DepthFeedback {
    pub fn new(observer: &TermObserver) -> Self {
        Self {
            observer_handle: observer.handle(),
            max_history_depth: 0,
            name: Cow::Borrowed("depth_feedback"),
        }
    }
}

impl Named for DepthFeedback {
    fn name(&self) -> &Cow<'static, str> {
        &self.name()
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

        if observer.max_depth > self.max_history_depth {
            // log::info!("Nouvelle profondeur syntaxique atteinte : {} (ancienne: {})",
            // observer.max_depth, self.max_history_depth);

            self.max_history_depth = observer.max_depth;
            return Ok(true);
        }

        Ok(false)
    }
}
