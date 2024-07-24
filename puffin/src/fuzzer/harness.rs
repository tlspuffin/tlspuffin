use libafl::executors::ExitKind;
use rand::Rng;

use crate::error::Error;
use crate::execution::{Runner, TraceRunner};
use crate::fuzzer::stats_stage::*;
use crate::protocol::ProtocolBehavior;
use crate::put_registry::PutRegistry;
use crate::trace::{Action, Spawner, Trace};

pub fn harness<PB: ProtocolBehavior + 'static>(
    put_registry: &PutRegistry<PB>,
    input: &Trace<PB::Matcher>,
) -> ExitKind {
    let runner = Runner::new(put_registry.clone(), Spawner::new(put_registry.clone()));

    TRACE_LENGTH.update(input.steps.len());

    for step in &input.steps {
        match &step.action {
            Action::Input(input) => {
                TERM_SIZE.update(input.recipe.size());
            }
            Action::Output(_) => {}
        }
    }

    if let Err(err) = runner.execute(input) {
        match &err {
            Error::Fn(_) => FN_ERROR.increment(),
            Error::Term(_e) => TERM.increment(),
            Error::Put(_) => PUT.increment(),
            Error::IO(_) => IO.increment(),
            Error::Agent(_) => AGENT.increment(),
            Error::Stream(_) => STREAM.increment(),
            Error::Extraction() => EXTRACTION.increment(),
            Error::SecurityClaim(msg) => {
                log::warn!("{}", msg);
                std::process::abort()
            }
        }

        log::trace!("{}", err);
    }

    ExitKind::Ok
}

#[allow(unused)]
pub fn dummy_harness<PB: ProtocolBehavior + 'static>(_input: &Trace<PB::Matcher>) -> ExitKind {
    let mut rng = rand::thread_rng();

    let n1 = rng.gen_range(0..10);
    log::info!("Run {}", n1);
    if n1 <= 5 {
        return ExitKind::Timeout;
    }
    ExitKind::Ok // Everything other than Ok is recorded in the crash corpus
}
