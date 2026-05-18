use std::borrow::Cow;
use std::cell::Cell;
use std::default::Default;

use libafl::corpus::{Corpus, CorpusId, Testcase};
use libafl::events::EventFirer;
use libafl::executors::ExitKind;
use libafl::feedbacks::{Feedback, StateInitializer};
use libafl::observers::ObserversTuple;
use libafl::prelude::{HasMaxSize, HasRand};
use libafl::state::HasCorpus;
use libafl_bolts::{Error, Named};
use serde::{Deserialize, Serialize};

use crate::fuzzer::stats_stage::DUPLICATES;
use crate::protocol::ProtocolTypes;
use crate::trace::Trace;

thread_local! {
    pub static FAIL_AT_STEP: Cell<Option<usize>> = const { Cell::new(None) };
    pub static OBJECTIVE_TRIGGERED: Cell<bool> = const { Cell::new(false) };
    pub static OBJECTIVE_HASH: Cell<Option<u64>> = const { Cell::new(None)};
}

/// Feedback that triggers when the harness sets [`OBJECTIVE_TRIGGERED`] to `true`.
///
/// Used to record security-claim violations and differential differences as objectives
/// without crashing the process (avoids the restart + serialization overhead of abort()).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ObjectiveFeedback {
    seen_objectives: std::collections::HashSet<(CorpusId, u64)>,
}

impl ObjectiveFeedback {
    pub fn new() -> Self {
        Self {
            seen_objectives: std::collections::HashSet::new(),
        }
    }
}

impl Named for ObjectiveFeedback {
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("ObjectiveFeedback")
    }
}

impl<S> StateInitializer<S> for ObjectiveFeedback {
    fn init_state(&mut self, _state: &mut S) -> Result<(), Error> {
        Ok(())
    }
}

impl<EM, I, OT, S> Feedback<EM, I, OT, S> for ObjectiveFeedback
where
    OT: ObserversTuple<I, S>,
    EM: EventFirer<I, S>,
    S: HasCorpus<I>,
{
    /// An objective is interesting if the harness has set the `OBJECTIVE_TRIGGERED` flag to true,
    /// and if the associated hash (if any) has not been seen before for the current corpus file.
    /// If no hash is set, we treat it as interesting to avoid losing objectives when the harness
    /// doesn't provide a hash.
    fn is_interesting(
        &mut self,
        state: &mut S,
        _: &mut EM,
        _: &I,
        _: &OT,
        _: &ExitKind,
    ) -> Result<bool, Error> {
        if OBJECTIVE_TRIGGERED.get() {
            match OBJECTIVE_HASH.get() {
                Some(hash) => {
                    let current_idx = state.corpus().current();

                    if current_idx.is_none() {
                        return Ok(true); // Could not get current corpus file index so we keep the
                                         // objective
                    }

                    // Only interesting if this hash hasn't been seen before for this corpus file
                    if self.seen_objectives.insert((current_idx.unwrap(), hash)) {
                        return Ok(true);
                    } else {
                        DUPLICATES.increment();
                        return Ok(false); // duplicate — already in corpus
                    }
                }
                None => return Ok(true), // no hash set, always treat as interesting
            }
        }
        Ok(false)
    }

    fn is_interesting_introspection(
        &mut self,
        s: &mut S,
        em: &mut EM,
        i: &I,
        ot: &OT,
        ek: &ExitKind,
    ) -> Result<bool, Error> {
        self.is_interesting(s, em, i, ot, ek)
    }
}

/// Custom feedback for minimizing traces after execution and prior to adding them to the corpus.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MinimizingFeedback<SC, PT>
where
    SC: HasRand + HasMaxSize,
    PT: ProtocolTypes + 'static,
{
    enabled: bool,
    pub(crate) phantom: std::marker::PhantomData<(SC, PT)>,
}

impl<SC, PT> MinimizingFeedback<SC, PT>
where
    SC: HasRand + HasMaxSize,
    PT: ProtocolTypes + 'static,
{
    pub fn new(with_truncation: bool) -> Self {
        Self {
            enabled: with_truncation,
            phantom: Default::default(),
        }
    }
}
impl<SC, PT> Named for MinimizingFeedback<SC, PT>
where
    SC: HasRand + HasMaxSize,
    PT: ProtocolTypes + 'static,
{
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("MinimizingFeedback")
    }
}

impl<SC, PT> StateInitializer<SC> for MinimizingFeedback<SC, PT>
where
    SC: HasRand + HasMaxSize,
    PT: ProtocolTypes + 'static,
{
    fn init_state(&mut self, _state: &mut SC) -> Result<(), Error> {
        Ok(())
    }
}

impl<EM, OT, SC, PT> Feedback<EM, Trace<PT>, OT, SC> for MinimizingFeedback<SC, PT>
where
    SC: HasRand + HasMaxSize,
    PT: ProtocolTypes + 'static,
    EM: EventFirer<Trace<PT>, SC>,
    OT: ObserversTuple<Trace<PT>, SC>,
{
    fn is_interesting(
        &mut self,
        _: &mut SC,
        _: &mut EM,
        _: &Trace<PT>,
        _: &OT,
        _: &ExitKind,
    ) -> Result<bool, Error> {
        Ok(false)
    }

    fn is_interesting_introspection(
        &mut self,
        _: &mut SC,
        _: &mut EM,
        _: &Trace<PT>,
        _: &OT,
        _: &ExitKind,
    ) -> Result<bool, Error> {
        Ok(false)
    }

    /// Append to the testcase the generated metadata in case of a new corpus item
    fn append_metadata(
        &mut self,
        _state: &mut SC,
        _manager: &mut EM,
        _observers: &OT,
        testcase: &mut Testcase<Trace<PT>>,
    ) -> Result<(), Error> {
        if self.enabled {
            let possibly_failed_at_step = FAIL_AT_STEP.get();
            let input_trace = testcase
                .input_mut()
                .as_mut()
                .expect("[MinimizingFeedback::append_metadata] Expected input to be a Trace<PT>");
            if let Some(failed_at_step) = possibly_failed_at_step {
                if input_trace.steps.len() >= 2 && failed_at_step <= input_trace.steps.len() - 2 {
                    // not fully executing the last step is OK if the last very step failed
                    // If the execution failed at the last step, we set the value to None
                    log::trace!("[b:trace len={}/size={}/{failed_at_step}] [MinimizingFeedback::append_metadata] Truncate.", input_trace.steps.len(), input_trace.size());
                    input_trace.truncate_at_step(failed_at_step + 1); // +1 because we want to
                                                                      // include
                                                                      // the step that failed
                } else {
                    log::trace!("[b:trace len={}/size={}/{failed_at_step}] [MinimizingFeedback::append_metadata] No trunc.",input_trace.steps.len(), input_trace.size());
                }
            } else {
                panic!(
                    "[MinimizingFeedback::append_metadata] no failed step found, not truncating trace"
                );
            }
        }
        Ok(())
    }
}
