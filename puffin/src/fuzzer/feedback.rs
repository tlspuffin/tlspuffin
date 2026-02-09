use std::borrow::Cow;
use std::cell::Cell;
use std::default::Default;

use libafl::corpus::Testcase;
use libafl::events::EventFirer;
use libafl::executors::ExitKind;
use libafl::feedbacks::Feedback;
use libafl::feedbacks::StateInitializer;
use libafl::observers::ObserversTuple;
use libafl::prelude::{Corpus, HasCorpus, HasMaxSize, HasRand, StdState};
use libafl_bolts::{Error, Named};
use serde::{Deserialize, Serialize};

use crate::protocol::ProtocolTypes;
use crate::trace::Trace;

// A global (or thread-local) mutable variable that your harness will update.
// Now it holds an Option<usize>.
thread_local! {
    pub static FAIL_AT_STEP: Cell<Option<usize>> = const { Cell::new(None) };
}

/// Custom feedback for minimizing traces after execution and prior to adding them to the corpus.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MinimizingFeedback<SC, PT>
where
    SC: HasRand + HasMaxSize,
    PT: ProtocolTypes + 'static
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
    ) -> Result<(), Error>
    {
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
