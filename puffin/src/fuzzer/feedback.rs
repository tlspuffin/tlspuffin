use std::default::Default;

use libafl::corpus::Testcase;
use libafl::events::EventFirer;
use libafl::executors::ExitKind;
use libafl::feedbacks::Feedback;
use libafl::inputs::UsesInput;
use libafl::observers::ObserversTuple;
use libafl::prelude::{HasCorpus, HasMaxSize, HasRand, State};
use libafl_bolts::{Error, Named};
use serde::{Deserialize, Serialize};

use crate::protocol::ProtocolTypes;
use crate::trace::Trace;

/// Custom feedback for minimizing traces after execution and prior to adding them to the corpus.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MinimizingFeedback<SC, PT>
where
    SC: HasCorpus + HasRand + HasMaxSize + UsesInput<Input = Trace<PT>> + State,
    PT: ProtocolTypes + 'static,
{
    pub(crate) phantom: std::marker::PhantomData<SC>,
}

impl<SC, PT> MinimizingFeedback<SC, PT>
where
    SC: HasCorpus + HasRand + HasMaxSize + UsesInput<Input = Trace<PT>> + State,
    PT: ProtocolTypes + 'static,
{
    pub fn new() -> Self {
        Self {
            phantom: Default::default(),
        }
    }
}
impl<SC, PT> Named for MinimizingFeedback<SC, PT>
where
    SC: HasCorpus + HasRand + HasMaxSize + UsesInput<Input = Trace<PT>> + State,
    PT: ProtocolTypes + 'static,
{
    fn name(&self) -> &str {
        "MinimizingFeedback"
    }
}

impl<SC, PT> Feedback<SC> for MinimizingFeedback<SC, PT>
where
    SC: HasCorpus + HasRand + HasMaxSize + UsesInput<Input = Trace<PT>> + State,
    PT: ProtocolTypes + 'static,
{
    fn is_interesting<EM, OT>(
        &mut self,
        _: &mut SC,
        _: &mut EM,
        _: &Trace<PT>,
        _: &OT,
        _: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<State = SC>,
        OT: ObserversTuple<SC>,
    {
        Ok(false)
    }

    fn is_interesting_introspection<EM, OT>(
        &mut self,
        _: &mut SC,
        _: &mut EM,
        _: &SC::Input,
        _: &OT,
        _: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<State = SC>,
        OT: ObserversTuple<SC>,
    {
        Ok(false)
    }

    fn append_metadata<OT>(
        &mut self,
        state: &mut SC,
        observers: &OT,
        testcase: &mut Testcase<Trace<PT>>,
    ) -> Result<(), Error>
    where
        OT: ObserversTuple<SC>,
    {
        todo!();
        // let observer_failed_at_step = observers
        //     .match_name::<OT>("failed_at_step")
        //     .expect("A MinimizingFeedback needs an observer");
        //
        // let input_trace = testcase
        //     .input_mut()
        //     .as_mut()
        //     .expect("Expected input to be a Trace<PT>");
        // if let Some(failed_at_step) = observer_failed_at_step {
        //     input_trace
        //         .truncate_at(failed_at_step)
        //         .map_err(|e| Error::illegal_state(format!(
        //             "Failed to truncate trace at step {}: {}",
        //             failed_at_step, e
        //         )))?;
        // }
        // Ok(())
    }

    fn discard_metadata(&mut self, _state: &mut SC, _input: &SC::Input) -> Result<(), Error> {
        todo!()
    }
}
