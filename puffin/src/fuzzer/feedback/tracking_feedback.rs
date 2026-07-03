use std::borrow::Cow;

use libafl::common::HasNamedMetadata;
use libafl::corpus::Testcase;
use libafl::executors::ExitKind;
use libafl::feedbacks::{Feedback, StateInitializer};
use libafl::SerdeAny;
use libafl_bolts::{Error, Named};
use serde::{Deserialize, Serialize};

use crate::fuzzer::stats_stage::{
    HIT_FDB_CLAIM, HIT_FDB_CLAIM_PROFILE,HIT_FDB_SEM_EDGE,HIT_FDB_TERM,
};

#[derive(Debug, Serialize, Deserialize, SerdeAny)]
pub struct FeedbackStatsMetadata {
    pub total_evaluated: u64,
    pub total_interesting: u64,
}

impl FeedbackStatsMetadata {
    pub fn new() -> Self {
        Self {
            total_evaluated: 0,
            total_interesting: 0,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TrackingFeedbackWrapper<F> {
    pub inner: F,
}

impl<F> TrackingFeedbackWrapper<F> {
    pub fn new(feedback: F) -> Self {
        Self { inner: feedback }
    }
}

impl<F> Named for TrackingFeedbackWrapper<F>
where
    F: Named,
{
    fn name(&self) -> &Cow<'static, str> {
        self.inner.name()
    }
}

impl<F, S> StateInitializer<S> for TrackingFeedbackWrapper<F>
where
    F: StateInitializer<S> + Named,
    S: HasNamedMetadata,
{
    fn init_state(&mut self, state: &mut S) -> Result<(), Error> {
        self.inner.init_state(state)?;

        let name = self.inner.name().to_string();

        if !state.has_named_metadata::<FeedbackStatsMetadata>(&name) {
            state.add_named_metadata(&name, FeedbackStatsMetadata::new());
        }
        Ok(())
    }
}

impl<EM, F, I, OT, S> Feedback<EM, I, OT, S> for TrackingFeedbackWrapper<F>
where
    F: Feedback<EM, I, OT, S>,
    S: HasNamedMetadata,
{
    fn is_interesting(
        &mut self,
        state: &mut S,
        manager: &mut EM,
        input: &I,
        observers: &OT,
        exit_kind: &ExitKind,
    ) -> Result<bool, Error> {
        let name = self.inner.name().to_string();
        let is_interesting = self
            .inner
            .is_interesting(state, manager, input, observers, exit_kind)?;

        let stats = state.named_metadata_mut::<FeedbackStatsMetadata>(&name)?;

        stats.total_evaluated += 1;

        if is_interesting {
            stats.total_interesting += 1;
        }
        if stats.total_evaluated % 10000 == 0 {
            let percentage = stats.total_interesting as f64 / stats.total_evaluated as f64 * 100.0;
            log::info!(
                "[STATS: {}] Evaluated: {} | Hit rate: {:.4}%",
                name,
                stats.total_evaluated,
                percentage
            );
        }

        // Increment hit stats
        if is_interesting {
            match name.as_str() {
                "claim_feedback" => HIT_FDB_CLAIM.increment(),
                "profile_feedback" => HIT_FDB_CLAIM_PROFILE.increment(),
                "term_observer" => HIT_FDB_TERM.increment(),
                "semantic_edge_observer" => HIT_FDB_SEM_EDGE.increment(),
                _ => {}
            }
        }

        Ok(is_interesting)
    }

    fn append_metadata(
        &mut self,
        state: &mut S,
        manager: &mut EM,
        observers: &OT,
        testcase: &mut Testcase<I>,
    ) -> Result<(), Error> {
        self.inner
            .append_metadata(state, manager, observers, testcase)
    }
}
